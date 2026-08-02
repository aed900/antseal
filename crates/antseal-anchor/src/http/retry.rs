//! Retry classification (A3; decision D90 §6.3).
//!
//! # Why retry is not one policy
//!
//! A calendar submission is a network **write**: A13 POSTs `anchor_digest`
//! and the calendar returns a pending attestation. Re-submitting the same
//! digest yields a *second* pending attestation from that calendar, which
//! would make A13's Accept row 1 ("two calendars → one `.ots` containing two
//! pending attestations") observe three. A TSA POST is cryptographically
//! safe to repeat, but A10 records hard rate limits (Sectigo ~15 s spacing,
//! SwissSign ~10/day — `tasks/A.md`), so three attempts burn 30 % of
//! SwissSign's daily quota on one failure.
//!
//! The dividing line is therefore **whether the request bytes reached the
//! server**, and it is decidable rather than guessed: the substrate's error
//! classes are built from `ureq`'s phase-typed errors, so "the connection was
//! never made" and "the response never came back" are different variants
//! rather than one `Io`.
//!
//! What is *not* decidable is the phase name on its own. A `Timeout(X)` means
//! "X's deadline expired first", not "we were in phase X", and `ureq` checks
//! each phase's predecessors alongside it — so `Timeout(SendRequest)` can and
//! does arrive while awaiting a response to a fully delivered request. The
//! placement of every phase is therefore derived from `ureq`'s predecessor
//! graph in [`super::timeout_phase`], not from its name, and only two phases
//! come out pre-send. Getting that backwards is what makes a substrate
//! double-submit.
//!
//! Two consequences worth stating because they are easy to get backwards:
//!
//! - The failure direction of [`Idempotency::AtMostOnceAfterSend`] is a
//!   **missed** stamp, never a duplicated one. A calendar that processes a
//!   request and then dies before its first response byte presents as a
//!   receive-phase timeout and is not retried. That is the correct
//!   direction: A13 already tolerates a per-calendar failure ("≥ 1 success ⇒
//!   a pending OTS anchor exists") and has no mechanism at all for
//!   tolerating a duplicate.
//! - Backoff is **deterministic and un-jittered**
//!   ([`HTTP_BACKOFF`](super::HTTP_BACKOFF)). We contact two to five *named*
//!   endpoints, never a fleet, so thundering-herd is not our failure mode;
//!   determinism keeps the timeout tests exact and keeps an RNG out of the
//!   retry path.

use super::AnchorHttpError;

/// Whether a request may be re-sent after it might already have been
/// delivered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Idempotency {
    /// Repeating the request is free of side effects at the server. A14's
    /// upgrade GET, A16's esplora GET, A17's `eth_getTransactionReceipt` (a
    /// POST by transport, a read by semantics).
    SafeToRepeat,
    /// Repeating the request after it may have been delivered would create a
    /// second server-side effect. A13's calendar submit and A10's TSA POST:
    /// pre-send failures are still retried, ambiguous ones are not.
    AtMostOnceAfterSend,
}

/// What the substrate does with a failed attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RetryVerdict {
    /// Try again, if the attempt budget allows.
    Retry,
    /// Return this failure to the caller. Covers both of D90's right-hand
    /// columns — "stop" (the request may have been delivered) and "never"
    /// (the failure is deterministic and a retry would reproduce it). The
    /// distinction between them is visible in the error variant, and
    /// collapsing it here is deliberate: the loop's only question is whether
    /// to go round again.
    Stop,
}

/// Decide whether `error` may be retried under `idempotency`.
///
/// This is D90 §6.3's table. Its left-hand column — which `ureq` outcome
/// becomes which class — is applied one layer up, where the `ureq::Error` is
/// mapped to an [`AnchorHttpError`]; the two halves are separated so that
/// this half is a pure function over a constructible type and can be tested
/// exhaustively without a socket.
///
/// The match is deliberately **wildcard-free**: adding a variant to
/// [`AnchorHttpError`] must not silently inherit a retry policy.
#[must_use]
pub fn classify(error: &AnchorHttpError, idempotency: Idempotency) -> RetryVerdict {
    // "The request certainly did not reach the server" — safe to retry
    // whatever the idempotency class is.
    const PRE_SEND: RetryVerdict = RetryVerdict::Retry;
    // "It might have." Retry only when repeating is free.
    let ambiguous = match idempotency {
        Idempotency::SafeToRepeat => RetryVerdict::Retry,
        Idempotency::AtMostOnceAfterSend => RetryVerdict::Stop,
    };

    match error {
        // Deterministic: the next attempt reproduces this exact outcome, and
        // for the endpoint arms it never even reaches a socket.
        AnchorHttpError::InvalidEndpoint { .. }
        | AnchorHttpError::TlsRequired { .. }
        | AnchorHttpError::Redirected { .. }
        | AnchorHttpError::OversizeBody { .. }
        | AnchorHttpError::MalformedResponse { .. } => RetryVerdict::Stop,

        // Pre-send: DNS, TCP and TLS all failed before a request byte was
        // written, so nothing can have been actioned server-side.
        // `SendTimeout` belongs here **because of how narrowly it is
        // minted**: only `ureq`'s `Resolve` and `Connect` phases reach it,
        // and those are the only two the predecessor graph proves cannot
        // fire while a delivered request is outstanding
        // (`super::timeout_phase`). The send-*named* phases are ambiguous
        // and land below; that is not an oversight.
        AnchorHttpError::Resolve { .. }
        | AnchorHttpError::Connect { .. }
        | AnchorHttpError::Tls { .. }
        | AnchorHttpError::SendTimeout { .. } => PRE_SEND,

        // Ambiguous: the request was (or may have been) written and no
        // response came back. `Transport` is D90's "any other `Error::Io`"
        // row and lands here for the same reason.
        AnchorHttpError::ReceiveTimeout { .. } | AnchorHttpError::Transport { .. } => ambiguous,

        // A complete response arrived, so the request certainly *was*
        // delivered — but a 429/503 is the server saying it declined to act
        // on it, which is as good as never having received it.
        AnchorHttpError::Status { status, .. } => match *status {
            429 | 503 => RetryVerdict::Retry,
            500..=599 => ambiguous,
            _ => RetryVerdict::Stop,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::super::{AnchorHttpError, HttpClient, HttpMethod, HttpPolicy, HttpRequest};
    use super::*;
    use crate::http::endpoint::{Endpoint, TlsPolicy};
    use crate::testing::stub::{StubReply, StubScript, StubServer};
    use std::net::TcpListener;
    use std::time::Duration;

    fn endpoint(url: &str) -> String {
        url.to_owned()
    }

    /// Every arm of the error enum, under both idempotency classes, against
    /// D90 §6.3's table read directly. This is the half of the table that a
    /// stub server cannot exercise cheaply — a real `HostNotFound` needs DNS,
    /// a real 503 needs a server — so it is asserted here as a pure function
    /// and the loop tests below prove the loop *uses* it.
    #[test]
    fn the_classifier_reproduces_d90_table_6_3() {
        use Idempotency::{AtMostOnceAfterSend as Once, SafeToRepeat as Safe};
        use RetryVerdict::{Retry, Stop};

        let cases: &[(AnchorHttpError, RetryVerdict, RetryVerdict)] = &[
            // ── deterministic: never, under either class ──────────────────
            (
                AnchorHttpError::InvalidEndpoint {
                    endpoint: endpoint("x"),
                    reason: "no scheme",
                },
                Stop,
                Stop,
            ),
            (
                AnchorHttpError::TlsRequired {
                    endpoint: endpoint("http://e.example"),
                },
                Stop,
                Stop,
            ),
            (
                AnchorHttpError::Redirected {
                    endpoint: endpoint("http://e.example"),
                    status: 302,
                    location: Some("http://elsewhere.example".into()),
                },
                Stop,
                Stop,
            ),
            (
                AnchorHttpError::OversizeBody {
                    endpoint: endpoint("http://e.example"),
                    cap_bytes: 1024,
                },
                Stop,
                Stop,
            ),
            (
                AnchorHttpError::MalformedResponse {
                    endpoint: endpoint("http://e.example"),
                    detail: "bad chunked framing".into(),
                },
                Stop,
                Stop,
            ),
            // ── pre-send: retry under both ────────────────────────────────
            (
                AnchorHttpError::Resolve {
                    endpoint: endpoint("http://e.example"),
                    attempts: 3,
                },
                Retry,
                Retry,
            ),
            (
                AnchorHttpError::Connect {
                    endpoint: endpoint("http://e.example"),
                    attempts: 3,
                    detail: "Connection refused".into(),
                },
                Retry,
                Retry,
            ),
            (
                AnchorHttpError::Tls {
                    endpoint: endpoint("https://e.example"),
                    detail: "unknown issuer".into(),
                },
                Retry,
                Retry,
            ),
            (
                AnchorHttpError::SendTimeout {
                    endpoint: endpoint("http://e.example"),
                    phase: "connect",
                },
                Retry,
                Retry,
            ),
            // ── ambiguous: the split that stops A13 double-submitting ─────
            (
                AnchorHttpError::ReceiveTimeout {
                    endpoint: endpoint("http://e.example"),
                    phase: "recv-response",
                },
                Retry,
                Stop,
            ),
            (
                AnchorHttpError::Transport {
                    endpoint: endpoint("http://e.example"),
                    detail: "connection reset".into(),
                },
                Retry,
                Stop,
            ),
            // ── status-coded ──────────────────────────────────────────────
            (status(429), Retry, Retry),
            (status(503), Retry, Retry),
            (status(500), Retry, Stop),
            (status(502), Retry, Stop),
            (status(599), Retry, Stop),
            (status(400), Stop, Stop),
            (status(404), Stop, Stop),
            (status(418), Stop, Stop),
            (status(451), Stop, Stop),
            (status(200), Stop, Stop),
        ];

        for (error, safe, once) in cases {
            assert_eq!(classify(error, Safe), *safe, "SafeToRepeat: {error:?}");
            assert_eq!(
                classify(error, Once),
                *once,
                "AtMostOnceAfterSend: {error:?}"
            );
        }
    }

    fn status(status: u16) -> AnchorHttpError {
        AnchorHttpError::Status {
            endpoint: endpoint("http://e.example"),
            status,
            body: Vec::new(),
        }
    }

    fn policy(max_attempts: u32) -> HttpPolicy {
        let mut policy = HttpPolicy::seal();
        policy.max_attempts = max_attempts;
        policy.timeouts = super::super::HttpTimeouts::within(1_000);
        policy
    }

    fn post<'a>(endpoint: &'a Endpoint, idempotency: Idempotency) -> HttpRequest<'a> {
        HttpRequest {
            endpoint,
            method: HttpMethod::Post,
            content_type: Some("application/timestamp-query"),
            accept: None,
            body: b"\x30\x03\x02\x01\x00",
            receive_cap_bytes: 4096,
            idempotency,
        }
    }

    /// D90's `post_is_not_retried_after_the_request_was_delivered`.
    ///
    /// The stub reads the whole request and then stalls, so the failure is a
    /// receive-phase timeout — the ambiguous class. Under
    /// `AtMostOnceAfterSend` the server must see the request exactly **once**;
    /// a substrate that retried every transport error would leave three
    /// pending attestations at a calendar that answered slowly.
    #[test]
    fn post_is_not_retried_after_the_request_was_delivered() {
        let server = StubServer::spawn(
            StubScript::new().always(StubReply::StallBeforeHeaders(Duration::from_secs(30))),
        );
        let endpoint = Endpoint::parse(&server.base_url(), TlsPolicy::Optional).expect("stub url");
        let client = HttpClient::new(policy(3));

        let err = client
            .send(&post(&endpoint, Idempotency::AtMostOnceAfterSend))
            .expect_err("the stub never answers");
        assert!(
            matches!(err, AnchorHttpError::ReceiveTimeout { .. }),
            "{err:?}"
        );
        assert_eq!(
            server.requests().len(),
            1,
            "a delivered POST must never be re-sent"
        );
    }

    /// The other side of the same coin, and the reason the previous test is
    /// not vacuous: with `SafeToRepeat` the identical failure IS retried, so
    /// the count of 1 above is the idempotency class doing work and not the
    /// retry loop being broken.
    #[test]
    fn the_same_failure_is_retried_when_repeating_is_safe() {
        let server = StubServer::spawn(
            StubScript::new().always(StubReply::StallBeforeHeaders(Duration::from_secs(30))),
        );
        let endpoint = Endpoint::parse(&server.base_url(), TlsPolicy::Optional).expect("stub url");
        let client = HttpClient::new(policy(3));

        let err = client
            .send(&post(&endpoint, Idempotency::SafeToRepeat))
            .expect_err("the stub never answers");
        assert!(
            matches!(err, AnchorHttpError::ReceiveTimeout { .. }),
            "{err:?}"
        );
        assert_eq!(
            server.requests().len(),
            3,
            "SafeToRepeat exhausts the budget"
        );
    }

    /// A genuine **pre-send** failure — nothing is listening on the port — is
    /// retried under both classes, and the attempt count in the error is the
    /// real one rather than a constant: the same call under a one-attempt
    /// policy reports 1.
    #[test]
    fn a_pre_send_failure_is_retried_up_to_the_attempt_limit() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        drop(listener);
        let url = format!("http://{addr}/");
        let endpoint = Endpoint::parse(&url, TlsPolicy::Optional).expect("dead port url");

        for (attempts, expected) in [(3u32, 3u32), (1, 1)] {
            let client = HttpClient::new(policy(attempts));
            let err = client
                .send(&post(&endpoint, Idempotency::AtMostOnceAfterSend))
                .expect_err("nothing is listening");
            match err {
                AnchorHttpError::Connect {
                    attempts: reported, ..
                } => assert_eq!(reported, expected),
                other => panic!("expected Connect, got {other:?}"),
            }
        }
    }

    /// D90's `get_is_retried_on_pre_send_failure_and_succeeds`, in the one
    /// shape a single stub server can hold deterministically: two `503`s
    /// (the server declining, which D90's table retries under BOTH classes)
    /// and then a 200. Proves the loop returns a later attempt's success
    /// rather than the first attempt's failure.
    #[test]
    fn a_declined_request_is_retried_and_a_later_attempt_succeeds() {
        let server = StubServer::spawn(
            StubScript::new()
                .then(StubReply::body(503, b"busy".to_vec()))
                .then(StubReply::body(503, b"busy".to_vec()))
                .then(StubReply::body(200, b"anchored".to_vec())),
        );
        let endpoint = Endpoint::parse(&server.base_url(), TlsPolicy::Optional).expect("stub url");
        let client = HttpClient::new(policy(3));

        let response = client
            .send(&post(&endpoint, Idempotency::AtMostOnceAfterSend))
            .expect("the third attempt succeeds");
        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"anchored");
        assert_eq!(server.requests().len(), 3);
    }

    /// D90's `deterministic_failures_are_never_retried`. A 4xx or an
    /// oversize body entering the retry loop would burn a TSA's rate limit
    /// on an outcome that cannot change.
    #[test]
    fn deterministic_failures_are_never_retried() {
        for (reply, expect_oversize) in [
            (StubReply::body(400, b"bad request".to_vec()), false),
            (StubReply::body(404, b"Not found".to_vec()), false),
            (StubReply::body(200, vec![0x5A; 64]), true),
        ] {
            let server = StubServer::spawn(StubScript::new().always(reply));
            let endpoint =
                Endpoint::parse(&server.base_url(), TlsPolicy::Optional).expect("stub url");
            let client = HttpClient::new(policy(3));
            let mut request = post(&endpoint, Idempotency::SafeToRepeat);
            if expect_oversize {
                request.receive_cap_bytes = 8;
            }

            let err = client.send(&request).expect_err("deterministic failure");
            if expect_oversize {
                assert!(
                    matches!(err, AnchorHttpError::OversizeBody { .. }),
                    "{err:?}"
                );
            } else {
                assert!(matches!(err, AnchorHttpError::Status { .. }), "{err:?}");
            }
            assert_eq!(
                server.requests().len(),
                1,
                "a deterministic failure must be tried exactly once: {err:?}"
            );
        }
    }
}
