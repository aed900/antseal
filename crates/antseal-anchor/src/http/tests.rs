//! D90's verification obligations for the substrate.
//!
//! Every one runs in the **default** lane (`cargo test --workspace
//! --locked`), against a loopback stub, with no network access — which is
//! also why D90 refused to gate this crate's HTTP half behind a feature: none
//! of these would be compiled by any required CI context if it had.

use super::endpoint::{Endpoint, TlsPolicy};
use super::retry::Idempotency;
use super::*;
use crate::testing::stub::{StubReply, StubScript, StubServer};
use std::time::{Duration, Instant};

/// The substrate is shared across scoped threads for endpoint independence,
/// so this must hold. A compile-time assertion rather than a test body: if it
/// ever stops holding, `endpoints_run_concurrently_not_sequentially` would
/// fail to compile with a much less obvious message.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<HttpClient>();
    assert_send_sync::<AnchorHttpError>();
};

/// The production ladder, scaled to a 1 s global: recv-body 400 ms,
/// recv-response 500 ms, send-body 600 ms, send-request 700 ms, connect
/// 800 ms, resolve 900 ms. Same *shape* as `standard()`, so a phase test that
/// passes here is a statement about the shipped configuration.
fn fast_policy(max_attempts: u32) -> HttpPolicy {
    HttpPolicy {
        timeouts: HttpTimeouts::within(1_000),
        max_attempts,
        tls: TlsPolicy::Optional,
    }
}

fn get<'a>(endpoint: &'a Endpoint, receive_cap_bytes: u64) -> HttpRequest<'a> {
    HttpRequest {
        endpoint,
        method: HttpMethod::Get,
        content_type: None,
        accept: None,
        body: &[],
        receive_cap_bytes,
        idempotency: Idempotency::SafeToRepeat,
    }
}

fn post<'a>(endpoint: &'a Endpoint, receive_cap_bytes: u64) -> HttpRequest<'a> {
    HttpRequest {
        endpoint,
        method: HttpMethod::Post,
        content_type: Some("application/timestamp-query"),
        accept: Some("application/timestamp-reply"),
        body: b"\x30\x03\x02\x01\x00",
        receive_cap_bytes,
        idempotency: Idempotency::AtMostOnceAfterSend,
    }
}

fn loopback(server: &StubServer) -> Endpoint {
    Endpoint::parse(&server.base_url(), TlsPolicy::Optional).expect("the stub binds 127.0.0.1")
}

// ─── The receive ceiling, and the off-by-one A28 must not inherit ───────────

/// D90's headline obligation. **A small synthetic cap on purpose**: at
/// `MAX_TSA_TOKEN_BYTES` each half of this assertion moves a megabyte, which
/// is exactly the kind of slowness that gets a test "optimised" into a
/// one-sided check — and the side that would survive is the one a literal
/// `.limit(cap)` already passes.
///
/// Under `.limit(cap)` instead of `.limit(cap + 1)` the FIRST half fails: a
/// body of exactly `cap` bytes is rejected, which is A28's `≤` silently
/// having become `<`.
#[test]
fn receive_cap_accepts_exactly_the_ceiling_and_rejects_one_more() {
    const CAP: u64 = 1_024;

    let at_ceiling =
        StubServer::spawn(StubScript::new().always(StubReply::body(200, vec![0x5A; CAP as usize])));
    let endpoint = loopback(&at_ceiling);
    let client = HttpClient::new(fast_policy(1));
    let response = client
        .send(&get(&endpoint, CAP))
        .expect("a body of exactly the ceiling is admissible");
    assert_eq!(response.body.len(), CAP as usize);

    let over = StubServer::spawn(
        StubScript::new().always(StubReply::body(200, vec![0x5A; CAP as usize + 1])),
    );
    let endpoint = loopback(&over);
    let err = client
        .send(&get(&endpoint, CAP))
        .expect_err("one byte more is not");
    match err {
        AnchorHttpError::OversizeBody { cap_bytes, .. } => assert_eq!(cap_bytes, CAP),
        other => panic!("expected OversizeBody, got {other:?}"),
    }
}

/// The cap is a **streaming** ceiling, not a post-hoc length check: the stub
/// announces a 64 MiB body and streams, and the call must fail having caused
/// only a bounded number of bytes to be written.
///
/// The bound asserted is deliberately loose (1 MiB against an announced
/// 64 MiB): the kernel's socket buffers absorb some writes the client never
/// reads, so a tight bound would be flaky while a loose one is still three
/// orders of magnitude away from "buffered the whole thing".
#[test]
fn receive_cap_is_enforced_before_the_body_is_buffered() {
    const CAP: u64 = 4 * 1024;
    const ANNOUNCED: u64 = 64 * 1024 * 1024;

    let server = StubServer::spawn(StubScript::new().always(StubReply::StreamUntilClosed {
        status: 200,
        content_length: ANNOUNCED,
        chunk_len: 16 * 1024,
        stop_after_bytes: ANNOUNCED,
    }));
    let endpoint = loopback(&server);
    let client = HttpClient::new(fast_policy(1));

    let err = client
        .send(&get(&endpoint, CAP))
        .expect_err("64 MiB against a 4 KiB ceiling");
    assert!(
        matches!(err, AnchorHttpError::OversizeBody { .. }),
        "{err:?}"
    );
    let written = server.bytes_written();
    assert!(
        written < 1024 * 1024,
        "the stub wrote {written} bytes of an announced {ANNOUNCED}: the ceiling is not \
         being applied while streaming"
    );
}

/// A28's derived constraints, as compile-time facts rather than prose. The
/// strict inequality on the OTS side is the point: equality *is* the
/// conflation of a per-reply cap with the merged-artifact cap.
#[test]
fn the_ots_response_cap_is_not_the_merged_artifact_cap() {
    const { assert!(OTS_CALENDAR_RESPONSE_CAP_BYTES < antseal_core::codec::caps::MAX_OTS_BYTES) };
    assert_eq!(
        TSA_RESPONSE_CAP_BYTES,
        antseal_core::codec::caps::MAX_TSA_TOKEN_BYTES,
        "one TSA response IS one embedded token — this relation is an identity, not a bound"
    );
    assert_eq!(OTS_CALENDAR_RESPONSE_CAP_BYTES, 65_536);
}

/// D37 permits 256 transfers in one transaction, which makes a 188 328-byte
/// receipt. At the draft's 64 KiB this would truncate at 89 logs — A17
/// failing on exactly the large seals it exists to corroborate, and failing
/// as `OversizeBody`, which reads as an endpoint problem.
#[test]
fn the_rpc_cap_admits_a_maximum_size_arbitrum_receipt() {
    const { assert!(RPC_RESPONSE_CAP_BYTES >= D37_MAX_RECEIPT_BYTES) };

    let server = StubServer::spawn(StubScript::new().always(StubReply::body(
        200,
        vec![0x7B; D37_MAX_RECEIPT_BYTES as usize],
    )));
    let endpoint = loopback(&server);
    let client = HttpClient::new(fast_policy(1));
    let response = client
        .send(&get(&endpoint, RPC_RESPONSE_CAP_BYTES))
        .expect("D37's worst-case receipt must fit under the RPC cap");
    assert_eq!(response.body.len(), D37_MAX_RECEIPT_BYTES as usize);
}

// ─── Timeouts ───────────────────────────────────────────────────────────────

/// Each phase must name itself. A global-only timeout cannot say which phase
/// stalled, so it cannot say whether the request reached the server — and the
/// whole idempotency split turns on that.
///
/// All three stubs are loopback; none sends a packet off this host. (D90
/// suggested an unroutable `192.0.2.1` for the connect phase; a stub that
/// accepts and never reads produces a send-phase stall instead, with no
/// outbound traffic and no dependence on how this host routes TEST-NET-1.)
///
/// Note which *variant* each produces: only `resolve` and `connect` are
/// pre-send, so all three of these are `ReceiveTimeout`. That is not a bug in
/// the test — see [`timeout_phase`].
#[test]
fn each_timeout_phase_reports_its_own_phase() {
    let mut seen: Vec<&'static str> = Vec::new();
    let client = HttpClient::new(fast_policy(1));

    // (a) headers never arrive → the response phase.
    let stalled = StubServer::spawn(
        StubScript::new().always(StubReply::StallBeforeHeaders(Duration::from_secs(30))),
    );
    let endpoint = loopback(&stalled);
    match client.send(&get(&endpoint, 4096)) {
        Err(AnchorHttpError::ReceiveTimeout { phase, .. }) => seen.push(phase),
        other => panic!("expected ReceiveTimeout, got {other:?}"),
    }

    // (b) headers arrive, body does not → the body phase.
    let stalled = StubServer::spawn(
        StubScript::new().always(StubReply::StallAfterHeaders(Duration::from_secs(30))),
    );
    let endpoint = loopback(&stalled);
    match client.send(&get(&endpoint, 4096)) {
        Err(AnchorHttpError::ReceiveTimeout { phase, .. }) => seen.push(phase),
        other => panic!("expected ReceiveTimeout, got {other:?}"),
    }

    // (c) the peer never reads → a send phase. A body larger than the socket
    // buffers is what makes the client's own write block.
    let deaf = StubServer::spawn(
        StubScript::new().always(StubReply::AcceptWithoutReading(Duration::from_secs(30))),
    );
    let endpoint = loopback(&deaf);
    let body = vec![0x5A; 48 * 1024 * 1024];
    let request = HttpRequest {
        endpoint: &endpoint,
        method: HttpMethod::Post,
        content_type: Some("application/octet-stream"),
        accept: None,
        body: &body,
        receive_cap_bytes: 4096,
        idempotency: Idempotency::AtMostOnceAfterSend,
    };
    match client.send(&request) {
        Err(AnchorHttpError::ReceiveTimeout { phase, .. }) => seen.push(phase),
        other => panic!("expected a send-phase ReceiveTimeout, got {other:?}"),
    }

    assert_eq!(seen.len(), 3);
    let mut distinct = seen.clone();
    distinct.sort_unstable();
    distinct.dedup();
    assert_eq!(
        distinct.len(),
        3,
        "phases must be distinguishable, got {seen:?} — a flat ladder reports the \
         same earlier phase every time, and a global-only timeout reports `global` \
         three times"
    );
    assert!(
        !seen.contains(&"global"),
        "a per-phase deadline must fire before the global backstop: {seen:?}"
    );
}

/// The ladder invariant, stated as the inequality chain `ureq`'s predecessor
/// graph requires. Flattening it (or restoring D90's increasing table) makes
/// the *reported phase* wrong; the classification stays safe because of
/// [`timeout_phase`], but the error messages start naming a phase the
/// connection was not in.
#[test]
fn the_timeout_ladder_is_strictly_decreasing() {
    for timeouts in [
        HttpTimeouts::standard(),
        HttpTimeouts::opportunistic(),
        HttpTimeouts::within(1_000),
    ] {
        let rungs = [
            ("global", timeouts.global),
            ("resolve", timeouts.resolve),
            ("connect", timeouts.connect),
            ("send_request", timeouts.send_request),
            ("send_body", timeouts.send_body),
            ("recv_response", timeouts.recv_response),
            ("recv_body", timeouts.recv_body),
        ];
        for pair in rungs.windows(2) {
            assert!(
                pair[0].1 > pair[1].1,
                "{} ({:?}) must exceed {} ({:?}): ureq checks a phase's predecessors \
                 alongside the current phase and reports the EARLIEST deadline",
                pair[0].0,
                pair[0].1,
                pair[1].0,
                pair[1].1
            );
        }
    }

    // Capacity, not just ordering. The worst cases D90 measured against the
    // real M2 endpoints on 2026-08-02 must fit inside the rung that governs
    // them, in BOTH profiles — a ladder that decreases beautifully and times
    // out on a healthy calendar is worse than no ladder.
    const WORST_TLS_HANDSHAKE: Duration = Duration::from_millis(1_047);
    const WORST_TIME_TO_FIRST_BYTE: Duration = Duration::from_millis(1_772);

    let standard = HttpTimeouts::standard();
    assert_eq!(standard.global, HTTP_TIMEOUT_GLOBAL);
    assert!(standard.connect > WORST_TLS_HANDSHAKE);
    assert!(standard.recv_response > WORST_TIME_TO_FIRST_BYTE);

    let opportunistic = HttpTimeouts::opportunistic();
    assert!(opportunistic.connect >= HTTP_OPPORTUNISTIC_CONNECT);
    assert!(opportunistic.connect > WORST_TLS_HANDSHAKE);
    assert!(
        opportunistic.recv_response > WORST_TIME_TO_FIRST_BYTE,
        "the 3 s opportunistic profile must still admit the slowest calendar D90 \
         measured ({WORST_TIME_TO_FIRST_BYTE:?} TTFB), or A15 reports every healthy \
         upgrade poll as a failure"
    );
    assert!(opportunistic.global <= Duration::from_secs(3));
}

/// The safety property, executed under a **deliberately wrong** ladder.
///
/// This is D90's table verbatim, scaled to milliseconds: send-request 4,
/// recv-response 8 — increasing across exactly the boundary that matters. It
/// makes `ureq` report `Timeout(SendRequest)` for a request the stub has
/// already read in full, which is what a live run produced before this was
/// found. The assertion is that the request is **still** sent only once:
/// `timeout_phase`'s conservative placement, not the constant table, is what
/// stops A13 double-submitting.
///
/// Delete either half and this test fails: flatten the classification and the
/// count becomes 3; the ladder alone would not save it, because the ladder is
/// wrong here on purpose.
#[test]
fn a_delivered_request_is_never_classified_pre_send_even_under_a_wrong_ladder() {
    let d90_table = HttpTimeouts {
        global: Duration::from_millis(1_000),
        resolve: Duration::from_millis(300),
        connect: Duration::from_millis(400),
        send_request: Duration::from_millis(400),
        send_body: Duration::from_millis(400),
        recv_response: Duration::from_millis(800),
        recv_body: Duration::from_millis(800),
    };
    let server = StubServer::spawn(
        StubScript::new().always(StubReply::StallBeforeHeaders(Duration::from_secs(30))),
    );
    let endpoint = loopback(&server);
    let client = HttpClient::new(HttpPolicy {
        timeouts: d90_table,
        max_attempts: 3,
        tls: TlsPolicy::Optional,
    });

    let err = client
        .send(&post(&endpoint, 4096))
        .expect_err("the stub never answers");
    // The misattribution really does happen under this table — this
    // assertion is what makes the test non-vacuous.
    assert!(
        matches!(&err, AnchorHttpError::ReceiveTimeout { phase, .. } if *phase == "send-request"),
        "expected the misattributed send-request phase this table produces, got {err:?}"
    );
    assert_eq!(
        server.requests().len(),
        1,
        "a delivered calendar POST was re-sent: the phase name was trusted over the \
         delivery graph, and A13 now has two pending attestations"
    );
}

/// The phase table itself, exhaustively — including the two `ureq` phases a
/// stub cannot produce (`Global`, `PerCall`) and the classification that
/// matters most about them: they are **ambiguous**, because they fire only
/// when no single phase did.
#[test]
fn every_timeout_phase_is_named_and_placed() {
    let expected: &[(ureq::Timeout, &str, bool)] = &[
        (ureq::Timeout::Resolve, "resolve", true),
        (ureq::Timeout::Connect, "connect", true),
        // Ambiguous despite the names: both can be reported while awaiting a
        // response to a fully delivered request (see `timeout_phase`).
        (ureq::Timeout::SendRequest, "send-request", false),
        (ureq::Timeout::SendBody, "send-body", false),
        (ureq::Timeout::RecvResponse, "recv-response", false),
        (ureq::Timeout::RecvBody, "recv-body", false),
        (ureq::Timeout::Global, "global", false),
        (ureq::Timeout::PerCall, "per-call", false),
    ];
    let mut names = Vec::new();
    for (phase, name, pre_send) in expected {
        match timeout_phase(*phase) {
            TimeoutSide::PreSend(got) => {
                assert!(*pre_send, "{phase:?} must not be pre-send");
                assert_eq!(got, *name);
                names.push(got);
            }
            TimeoutSide::Ambiguous(got) => {
                assert!(!*pre_send, "{phase:?} must be pre-send");
                assert_eq!(got, *name);
                names.push(got);
            }
        }
    }
    names.sort_unstable();
    names.dedup();
    assert_eq!(names.len(), expected.len(), "phase names must be distinct");
}

// ─── Redirects, statuses, bodies ────────────────────────────────────────────

/// `max_redirects(0)` does **not** error — it returns the 3xx, with an empty
/// body. A client that only asked "did I get a response" would hand that
/// empty buffer to the DER parser. The classification is ours.
///
/// This test is also the guard on A16's independence: two endpoints that both
/// redirect to a common origin are one endpoint wearing two names, and "both
/// must succeed and agree" becomes a tautology that still reports agreement.
#[test]
fn a_redirect_is_an_error_not_a_response() {
    let server = StubServer::spawn(StubScript::new().always(StubReply::Redirect {
        status: 302,
        location: "http://127.0.0.1:1/elsewhere".to_owned(),
    }));
    let endpoint = loopback(&server);
    let client = HttpClient::new(fast_policy(3));

    let err = client
        .send(&post(&endpoint, 4096))
        .expect_err("a 3xx must never be handed back as a response");
    match err {
        AnchorHttpError::Redirected {
            status, location, ..
        } => {
            assert_eq!(status, 302);
            assert_eq!(location.as_deref(), Some("http://127.0.0.1:1/elsewhere"));
        }
        other => panic!("expected Redirected, got {other:?}"),
    }
    assert_eq!(
        server.requests().len(),
        1,
        "a redirect is deterministic and must not be retried"
    );
}

/// A non-2xx failure **carries its body**. A14's upgrade discriminator is
/// three-way and body-separated — `200` + attestation, `404` + pending text,
/// `404` + not-found text — so a substrate that collapsed this to a status
/// code would make A14 unimplementable on top of it.
///
/// Both 404 bodies are asserted, and asserted to *differ*: a one-sided test
/// that only checked `status == 404` would pass under exactly the defect this
/// exists to prevent.
#[test]
fn a_non_2xx_response_carries_its_body() {
    const PENDING: &[u8] = b"Pending confirmation in Bitcoin blockchain";
    const NOT_FOUND: &[u8] = b"Not found";
    assert_eq!(PENDING.len(), 42);

    let mut bodies = Vec::new();
    for expected in [PENDING, NOT_FOUND] {
        let server =
            StubServer::spawn(StubScript::new().always(StubReply::body(404, expected.to_vec())));
        let endpoint = loopback(&server);
        let client = HttpClient::new(fast_policy(1));
        match client.send(&get(&endpoint, 4096)).expect_err("404") {
            AnchorHttpError::Status { status, body, .. } => {
                assert_eq!(status, 404);
                assert_eq!(body, expected);
                bodies.push(body);
            }
            other => panic!("expected Status, got {other:?}"),
        }
    }
    assert_ne!(
        bodies[0], bodies[1],
        "the two 404s must be distinguishable by body — that is the whole discriminator"
    );
}

/// An over-long *error* body is truncated evidence, not a failed request: the
/// call must still report the status. If this arm inherited an artifact cap,
/// a 500 with a megabyte of HTML would become `OversizeBody` and the status
/// would be lost.
#[test]
fn a_non_2xx_body_is_capped_independently_of_the_artifact_cap() {
    let server =
        StubServer::spawn(StubScript::new().always(StubReply::body(500, vec![b'x'; 64 * 1024])));
    let endpoint = loopback(&server);
    let client = HttpClient::new(fast_policy(1));

    match client
        .send(&get(&endpoint, RPC_RESPONSE_CAP_BYTES))
        .expect_err("500")
    {
        AnchorHttpError::Status { status, body, .. } => {
            assert_eq!(status, 500);
            assert!(
                body.len() as u64 <= HTTP_ERROR_BODY_CAP_BYTES,
                "carried {} bytes, cap is {HTTP_ERROR_BODY_CAP_BYTES}",
                body.len()
            );
            assert_eq!(body.len() as u64, HTTP_ERROR_BODY_CAP_BYTES);
        }
        other => panic!("expected Status (truncated), got {other:?}"),
    }
}

/// Adversary-controlled framing must produce a typed error, never a panic and
/// never a body the caller might trust. Three shapes: a lying
/// `Content-Length`, a body that stops early, and a status line that is not
/// HTTP at all.
#[test]
fn malformed_framing_is_a_typed_error() {
    let cases: [(&str, Vec<u8>); 3] = [
        (
            "content-length lies high",
            b"HTTP/1.1 200 OK\r\nContent-Length: 4096\r\nConnection: close\r\n\r\nshort".to_vec(),
        ),
        ("no status line", b"not http at all\r\n\r\n".to_vec()),
        (
            "header block never terminates",
            b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n".to_vec(),
        ),
    ];

    for (what, bytes) in cases {
        let server = StubServer::spawn(StubScript::new().always(StubReply::Raw(bytes)));
        let endpoint = loopback(&server);
        let client = HttpClient::new(fast_policy(1));
        let outcome = client.send(&get(&endpoint, 4096));
        let err = match outcome {
            Err(err) => err,
            Ok(response) => panic!("{what}: malformed framing yielded a response: {response:?}"),
        };
        // The class must be a transport/parse failure. `Status` or
        // `OversizeBody` here would mean the broken response was parsed far
        // enough to be believed, which is the outcome this test exists to
        // exclude — and a panic would be worse still.
        assert!(
            matches!(
                err,
                AnchorHttpError::MalformedResponse { .. }
                    | AnchorHttpError::Transport { .. }
                    | AnchorHttpError::ReceiveTimeout { .. }
            ),
            "{what}: expected a transport/parse class, got {err:?}"
        );
    }
}

// ─── Every error class ──────────────────────────────────────────────────────

/// A3's Accept row 1 asks for a test of **each error class**. Several of them
/// cannot be produced from a loopback stub without contacting something real
/// — a `HostNotFound` needs DNS, a `Tls` needs a hostile certificate — so the
/// mapping itself is asserted here as a pure function over constructed `ureq`
/// outcomes. This is D90 §6.3's **left-hand** column; `retry::classify` is the
/// right-hand one, and the stub tests prove the pipeline uses both.
///
/// Two entries encode findings that a doc comment would have got wrong:
/// a refused connection arrives as `Io(ConnectionRefused)` rather than as
/// `ConnectionFailed`, and `BodyExceedsLimit` is documented as a *send*-side
/// error while `limit.rs` raises it on receive.
#[test]
fn every_ureq_outcome_maps_to_its_own_error_class() {
    use std::io::{Error as IoError, ErrorKind};

    let endpoint = Endpoint::parse("http://127.0.0.1:9/x", TlsPolicy::Optional).expect("endpoint");
    let request = get(&endpoint, 4_096);
    let classify = |error: ureq::Error| map_error(&request, 2, &error);

    macro_rules! assert_class {
        ($error:expr, $pattern:pat) => {{
            let mapped = classify($error);
            assert!(
                matches!(mapped, $pattern),
                "{} mapped to {mapped:?}",
                stringify!($error)
            );
            mapped
        }};
    }

    // Pre-send — retried under both idempotency classes.
    assert_class!(ureq::Error::HostNotFound, AnchorHttpError::Resolve { .. });
    assert_class!(
        ureq::Error::ConnectionFailed,
        AnchorHttpError::Connect { .. }
    );
    for kind in [
        ErrorKind::ConnectionRefused,
        ErrorKind::HostUnreachable,
        ErrorKind::NetworkUnreachable,
    ] {
        assert_class!(
            ureq::Error::Io(IoError::from(kind)),
            AnchorHttpError::Connect { .. }
        );
    }
    assert_class!(
        ureq::Error::Timeout(ureq::Timeout::Resolve),
        AnchorHttpError::SendTimeout { .. }
    );
    assert_class!(
        ureq::Error::Timeout(ureq::Timeout::Connect),
        AnchorHttpError::SendTimeout { .. }
    );

    // Ambiguous — never retried when repeating would double-submit.
    for phase in [
        ureq::Timeout::SendRequest,
        ureq::Timeout::SendBody,
        ureq::Timeout::RecvResponse,
        ureq::Timeout::RecvBody,
        ureq::Timeout::Global,
        ureq::Timeout::PerCall,
    ] {
        assert_class!(
            ureq::Error::Timeout(phase),
            AnchorHttpError::ReceiveTimeout { .. }
        );
    }
    // "any other Io" — D90's ambiguous row.
    for kind in [
        ErrorKind::ConnectionReset,
        ErrorKind::UnexpectedEof,
        ErrorKind::BrokenPipe,
        ErrorKind::TimedOut,
    ] {
        assert_class!(
            ureq::Error::Io(IoError::from(kind)),
            AnchorHttpError::Transport { .. }
        );
    }

    // TLS — its own class so a stale `webpki-roots` snapshot triages in one
    // step instead of reading like an attack.
    assert_class!(
        ureq::Error::Tls("unknown issuer"),
        AnchorHttpError::Tls { .. }
    );
    assert_class!(ureq::Error::TlsRequired, AnchorHttpError::Tls { .. });

    // Deterministic.
    let oversize = assert_class!(
        ureq::Error::BodyExceedsLimit(99),
        AnchorHttpError::OversizeBody { .. }
    );
    match oversize {
        AnchorHttpError::OversizeBody { cap_bytes, .. } => assert_eq!(
            cap_bytes, 4_096,
            "the cap reported must be the caller's TRUE ceiling, not ureq's `limit` argument"
        ),
        other => panic!("{other:?}"),
    }
    assert_class!(
        ureq::Error::BadUri("nope".to_owned()),
        AnchorHttpError::InvalidEndpoint { .. }
    );
    assert_class!(
        ureq::Error::RequireHttpsOnly("http://x/".to_owned()),
        AnchorHttpError::TlsRequired { .. }
    );
    assert_class!(
        ureq::Error::LargeResponseHeader(70_000, 16_384),
        AnchorHttpError::MalformedResponse { .. }
    );
    assert_class!(
        ureq::Error::TooManyRedirects,
        AnchorHttpError::MalformedResponse { .. }
    );
    assert_class!(
        ureq::Error::RedirectFailed,
        AnchorHttpError::MalformedResponse { .. }
    );

    // `http_status_as_error(false)` means this cannot happen; if it ever
    // does, the setting was lost and A14's body-carrying discriminator went
    // with it, so it must be loud rather than a plausible bodyless `Status`.
    let lost = assert_class!(
        ureq::Error::StatusCode(404),
        AnchorHttpError::MalformedResponse { .. }
    );
    assert!(
        lost.to_string().contains("http_status_as_error"),
        "the message must name the lost setting: {lost}"
    );

    // Every arm carries the endpoint URL, and only the URL.
    for error in [
        classify(ureq::Error::HostNotFound),
        classify(ureq::Error::Io(IoError::from(ErrorKind::ConnectionReset))),
        classify(ureq::Error::Tls("x")),
    ] {
        assert!(
            error.to_string().contains("http://127.0.0.1:9/x"),
            "{error}"
        );
    }
}

/// Every byte in a non-2xx body is adversary-controlled, and the error is
/// rendered to a terminal. `Status`'s `Display` therefore reports the body's
/// **length** and never its content — so a calendar answering `404` with ANSI
/// escapes, a fake prompt or a `\r` overwrite cannot paint the user's screen.
/// The bytes are still carried in the field, where A14's matcher reads them.
#[test]
fn a_hostile_error_body_is_never_rendered_into_the_message() {
    let hostile = b"\x1b[2J\x1b[1;31mFATAL: seal verified\x1b[0m\r\n\x07".to_vec();
    let error = AnchorHttpError::Status {
        endpoint: "http://calendar.example/timestamp".to_owned(),
        status: 404,
        body: hostile.clone(),
    };
    let rendered = error.to_string();
    assert!(
        !rendered.contains('\x1b') && !rendered.contains('\r') && !rendered.contains('\x07'),
        "control bytes reached the rendered message: {rendered:?}"
    );
    assert!(!rendered.contains("FATAL"), "{rendered:?}");
    assert!(rendered.contains(&format!("{} body byte(s)", hostile.len())));
    // …and the bytes are still there for the consumer that needs them.
    match error {
        AnchorHttpError::Status { body, .. } => assert_eq!(body, hostile),
        other => panic!("{other:?}"),
    }
}

/// The two endpoint-validation failures reach the transport error type with
/// **identical text**, so a user sees the same sentence whether the URL was
/// refused at config load or at send time. Asserted rather than asserted-in-a-
/// comment: two independently written `#[error]` strings drift.
#[test]
fn endpoint_errors_convert_with_identical_text() {
    let cases = [
        EndpointError::Invalid {
            endpoint: "ftp://x.example/".to_owned(),
            reason: "scheme must be http or https",
        },
        EndpointError::TlsRequired {
            endpoint: "http://esplora.example/api".to_owned(),
        },
    ];
    for endpoint_error in cases {
        let expected = endpoint_error.to_string();
        let converted: AnchorHttpError = endpoint_error.into();
        assert_eq!(converted.to_string(), expected);
        assert!(matches!(
            converted,
            AnchorHttpError::InvalidEndpoint { .. } | AnchorHttpError::TlsRequired { .. }
        ));
    }
}

// ─── Transport policy (A49) ─────────────────────────────────────────────────

/// The counterweight to A49: a later "hardening" pass that made the substrate
/// TLS-only would silently kill DigiCert, whose timestamp service has no port
/// 443 at all.
#[test]
fn plain_http_is_permitted_under_the_optional_policy() {
    let server = StubServer::spawn(StubScript::new().always(StubReply::body(200, b"ok".to_vec())));
    let endpoint = loopback(&server);
    let client = HttpClient::new(fast_policy(1));
    let response = client
        .send(&post(&endpoint, 4096))
        .expect("plain http POST");
    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"ok");
}

/// A49's structural half: the profile carries the transport requirement, so
/// an A16/A17 call site cannot obtain a permissive client by forgetting a
/// parameter. Asserted in both directions — a `verify()` client refuses a
/// public plain-HTTP endpoint, and a `seal()` client accepts it.
#[test]
fn the_verify_profile_requires_tls_and_the_seal_profile_does_not() {
    assert_eq!(HttpPolicy::verify().tls, TlsPolicy::RequiredExceptLoopback);
    assert_eq!(HttpPolicy::seal().tls, TlsPolicy::Optional);
    assert_eq!(HttpPolicy::opportunistic().tls, TlsPolicy::Optional);

    let permissive =
        Endpoint::parse("http://esplora.example/api", TlsPolicy::Optional).expect("Optional");
    let verifier = HttpClient::new(HttpPolicy::verify());
    let err = verifier
        .send(&get(&permissive, 4096))
        .expect_err("the verify client must refuse plain http to a public host");
    assert!(
        matches!(err, AnchorHttpError::TlsRequired { .. }),
        "{err:?}"
    );

    // And the refusal happens before any socket work: the host above does not
    // exist, so a substrate that dialled first would report a DNS failure.
    assert!(
        err.to_string().contains("must be https"),
        "the failure must name the transport rule, not a DNS accident: {err}"
    );
}

/// A16/A17's stub suites must keep working under the strict policy, or A49
/// would be a rule that makes its own Accept rows untestable.
#[test]
fn the_strict_policy_still_admits_a_loopback_stub() {
    let server = StubServer::spawn(StubScript::new().always(StubReply::body(200, b"80".to_vec())));
    let endpoint = Endpoint::parse(&server.base_url(), TlsPolicy::RequiredExceptLoopback)
        .expect("a loopback IP literal is exempt");
    let client = HttpClient::new(HttpPolicy {
        timeouts: HttpTimeouts::within(1_000),
        max_attempts: 1,
        tls: TlsPolicy::RequiredExceptLoopback,
    });
    let response = client
        .send(&get(&endpoint, 4096))
        .expect("loopback is exempt");
    assert_eq!(response.body, b"80");
}

// ─── The agent's own configuration ──────────────────────────────────────────

/// Each of these settings is either a measured decision or a defence against
/// an `ureq` default. Asserting them on the built agent is cheap and catches
/// a dropped builder line that no behavioural test happens to cover.
#[test]
fn the_agent_is_configured_exactly_as_d90_specifies() {
    let client = HttpClient::new(HttpPolicy::seal());
    let config = client.agent.config();

    assert!(
        config.proxy().is_none(),
        "ureq's DEFAULT reads HTTP_PROXY/ALL_PROXY — which would route both halves of \
         A16's must-agree pair through one intermediary"
    );
    assert_eq!(config.max_redirects(), 0);
    assert!(
        !config.http_status_as_error(),
        "we classify statuses, not ureq"
    );
    assert!(!config.https_only(), "per-request, from TlsPolicy");
    assert_eq!(
        config.max_response_header_size(),
        HTTP_MAX_RESPONSE_HEADER_BYTES
    );
    assert!(matches!(
        config.accept_encoding(),
        ureq::config::AutoHeaderValue::None
    ));
    assert_eq!(config.timeouts().global, Some(HTTP_TIMEOUT_GLOBAL));
    assert_eq!(config.timeouts().connect, Some(HTTP_TIMEOUT_CONNECT));
    assert_eq!(config.timeouts().recv_body, Some(HTTP_TIMEOUT_RECV_BODY));
}

/// On the wire, not in the config: our own user-agent (never `ureq/3.3.0`,
/// which would tell an observer of a plain-HTTP DigiCert request exactly
/// which client bugs to aim at) and no `Accept-Encoding` at all (a streaming
/// byte ceiling on a compressed body bounds the wrong number).
///
/// **Measured limitation, recorded rather than glossed.** Deleting the
/// `.accept_encoding(AutoHeaderValue::None)` builder line does *not* make
/// this test fail: with `default-features = false` the `gzip` feature is off,
/// so `ureq` negotiates no encoding either way. The builder line is a defence
/// against a future feature-default change, and the assertion that can fail
/// on its removal is the one in
/// [`the_agent_is_configured_exactly_as_d90_specifies`] (red direction
/// executed). The user-agent half of this test *does* fail on its own
/// mutation.
#[test]
fn the_client_sends_our_user_agent_and_no_accept_encoding() {
    let server = StubServer::spawn(StubScript::new().always(StubReply::body(200, b"ok".to_vec())));
    let endpoint = loopback(&server);
    let client = HttpClient::new(fast_policy(1));
    client.send(&post(&endpoint, 4096)).expect("POST");

    let requests = server.requests();
    let raw = String::from_utf8_lossy(requests.first().expect("one request")).to_ascii_lowercase();
    assert!(raw.contains("user-agent: antseal/"), "{raw}");
    assert!(
        !raw.contains("ureq/"),
        "the default user-agent leaked: {raw}"
    );
    assert!(!raw.contains("accept-encoding"), "{raw}");
    assert!(
        raw.contains("content-type: application/timestamp-query"),
        "{raw}"
    );
    assert!(raw.contains("accept: application/timestamp-reply"), "{raw}");
}

// ─── The proxy default: the most dangerous of the three ─────────────────────

/// `ureq::Config::default()` sets `proxy: Proxy::try_from_env()`. Left alone
/// it would route **both** halves of A16's must-agree pair through one
/// on-path intermediary — two endpoints wearing one origin, agreeing
/// perfectly, on whatever that intermediary chose to say. No agreement test
/// could catch it, because the results really would agree.
///
/// Environment variables cannot be set in-process (`std::env::set_var` is
/// `unsafe` in edition 2024, and this workspace denies `unsafe_code`), so the
/// request is made by a **child process** started with the proxy variables
/// set. The load-bearing assertions are the parent's connection counts: the
/// proxy stub must see nothing and the real endpoint must see exactly one
/// request. A child that silently ran no test at all fails them.
#[test]
fn the_agent_never_takes_a_proxy_from_the_environment() {
    let proxy =
        StubServer::spawn(StubScript::new().always(StubReply::body(200, b"PROXY".to_vec())));
    let target =
        StubServer::spawn(StubScript::new().always(StubReply::body(200, b"TARGET".to_vec())));

    let exe = std::env::current_exe().expect("the test binary's own path");
    let output = std::process::Command::new(exe)
        .args([
            "--exact",
            "http::tests::proxy_environment_child",
            "--ignored",
            "--nocapture",
        ])
        .env("ALL_PROXY", proxy.base_url())
        .env("HTTP_PROXY", proxy.base_url())
        .env("http_proxy", proxy.base_url())
        .env("HTTPS_PROXY", proxy.base_url())
        .env("ANTSEAL_STUB_TARGET", target.base_url())
        .env_remove("NO_PROXY")
        .env_remove("no_proxy")
        .output()
        .expect("spawn the child test process");

    assert!(
        output.status.success(),
        "child failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        proxy.connections(),
        0,
        "the ambient proxy was consulted — .proxy(None) is not in force"
    );
    assert_eq!(
        target.connections(),
        1,
        "the request must have reached the endpoint itself"
    );
}

/// The child half of [`the_agent_never_takes_a_proxy_from_the_environment`].
/// Ignored so it never runs in the ordinary pass; it is meaningless without
/// the environment its parent supplies, and says so by failing loudly rather
/// than skipping.
#[test]
#[ignore = "driven as a subprocess by the_agent_never_takes_a_proxy_from_the_environment"]
fn proxy_environment_child() {
    let target = std::env::var("ANTSEAL_STUB_TARGET")
        .expect("ANTSEAL_STUB_TARGET: this test is only meaningful as its parent's child");
    let endpoint = Endpoint::parse(&target, TlsPolicy::Optional).expect("stub url");
    let client = HttpClient::new(fast_policy(1));
    let response = client
        .send(&get(&endpoint, 4096))
        .expect("the request must reach the endpoint, not the proxy");
    assert_eq!(
        response.body, b"TARGET",
        "answered by the proxy stub instead of the endpoint"
    );
}

// ─── Independence across endpoints ──────────────────────────────────────────

/// A10's "one TSA's failure never aborts **or delays** the others", A16's
/// pair, A13's per-calendar independence: all of it comes from
/// `std::thread::scope`, not from a runtime.
///
/// The second assertion is the non-vacuous half. A sequential implementation
/// that happened to query the fast endpoint first would pass a wall-clock
/// check on its own.
#[test]
fn endpoints_run_concurrently_not_sequentially() {
    let slow = StubServer::spawn(
        StubScript::new().always(StubReply::StallBeforeHeaders(Duration::from_millis(1_500))),
    );
    let fast = StubServer::spawn(StubScript::new().always(StubReply::body(200, b"fast".to_vec())));
    let slow_endpoint = loopback(&slow);
    let fast_endpoint = loopback(&fast);

    let client = HttpClient::new(HttpPolicy {
        timeouts: HttpTimeouts::standard(),
        max_attempts: 1,
        tls: TlsPolicy::Optional,
    });

    let started = Instant::now();
    let mut elapsed: Vec<(&str, Duration)> = std::thread::scope(|scope| {
        let handles: Vec<_> = [("slow", &slow_endpoint), ("fast", &fast_endpoint)]
            .into_iter()
            .map(|(name, endpoint)| {
                let client = &client;
                scope.spawn(move || {
                    let at = Instant::now();
                    let outcome = client.send(&get(endpoint, 4096));
                    assert!(outcome.is_ok(), "{name}: {outcome:?}");
                    (name, at.elapsed())
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|handle| handle.join().expect("stub thread"))
            .collect()
    });
    let wall = started.elapsed();

    elapsed.sort_by_key(|(_, taken)| *taken);
    assert!(
        wall < Duration::from_millis(2_400),
        "sequential execution: {wall:?} for a 1.5 s endpoint plus a fast one"
    );
    let (name, taken) = elapsed[0];
    assert_eq!(name, "fast");
    assert!(
        taken < Duration::from_millis(900),
        "the fast endpoint waited {taken:?} on the slow one"
    );
}
