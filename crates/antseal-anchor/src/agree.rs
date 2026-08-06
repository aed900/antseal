//! The must-agree two-endpoint primitive (task **A16**).
//!
//! Two independent endpoints are asked the same question. Their replies are
//! **unsigned** — an esplora header and a JSON-RPC receipt carry no signature
//! antseal can check — so the only integrity control available is that two
//! parties who should not be able to coordinate said the same thing. This
//! module is where "they said the same thing" is decided, and where the three
//! ways it can fail are kept apart.
//!
//! # Agreement is over an **extracted value**, never over response bytes
//!
//! D90 §6.9(a) ships **no** comparison helper in the HTTP substrate, and that
//! ruling is not contradicted here. What it forbids is a
//! `must_agree(a: &[u8], b: &[u8])` over *response bodies*: the two Arbitrum
//! RPCs D55 ruled in return different JSON for the same receipt, so a byte
//! comparator would report "a lying endpoint" for two honest ones on every
//! call. Measured twice, on two networks:
//!
//! - arbitrum-sepolia (D55 §3, reproduced 2026-08-03): one endpoint's result
//!   carries `timeboosted`, the other's `blobGasUsed`; zero differing shared
//!   keys; the extracted tuple identical;
//! - arbitrum-one (2026-08-03): the result key sets are *identical* and the
//!   bodies **still** differ, because the two order the JSON-RPC envelope
//!   differently — `{"jsonrpc",…,"id",…}` against `{"id",…,"jsonrpc",…}`.
//!
//! [`must_agree`] therefore compares `T`, a value the **consumer** extracted,
//! and never a `&[u8]` it went and fetched. For A16's esplora pair `T` is the
//! 80 raw header bytes, and byte equality *is* the extraction — an esplora
//! header is a fixed-width object with no representational freedom. That is
//! the reading under which A16's "byte-identical" and A17's "agree on
//! blockNumber and blockHash" are both correct, and **the reason A16's rule
//! must not be generalised.**
//!
//! # What this primitive does not establish
//!
//! Endpoint **independence**, which is the property the whole design rests
//! on, is not something code can check. [`EndpointPair`] refuses the one
//! shape that is decidable and would silently make agreement vacuous — two
//! URLs on one origin — and D90 already refuses the runtime version of the
//! same collapse by never following a redirect. Beyond that:
//!
//! - two distinct hostnames resolving to one machine,
//! - two services behind one CDN or one on-path intermediary,
//! - two operators who are the same person,
//!
//! are all indistinguishable from here. `.proxy(None)` (D90 §6.5) removes the
//! one instance the process controls; the rest is the operator's choice of
//! endpoints, which is why the defaults are a *reviewed decision* (D54/D55)
//! rather than a configuration convenience.
//!
//! # Concurrency
//!
//! [`fetch_and_agree`] runs the two endpoints on [`std::thread::scope`], so a
//! slow or dead endpoint delays the pair by its own timeout and not by twice
//! it. Task A51 will hoist one shared fan-out for A10/A13/A16/A17; when it
//! lands, only [`fetch_and_agree`] changes — [`must_agree`] is a pure
//! function over two already-collected results and is where every outcome
//! test in this crate points.

use crate::http::{AnchorHttpError, Endpoint, HttpClient};

/// A reply that could not be turned into a comparable value.
///
/// Two arms, because they fail at different layers and a caller that
/// collapsed them would lose the distinction between "the endpoint did not
/// answer" and "the endpoint answered something that is not what this API
/// returns" — the second being a far stronger signal about the endpoint.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum EndpointFailure {
    /// The request itself failed: transport, timeout, non-2xx, over-cap.
    #[error(transparent)]
    Http(#[from] AnchorHttpError),
    /// A 2xx arrived and its body was not usable.
    ///
    /// `reason` is a `&'static str` rather than a formatted message on
    /// purpose: every reason is a named case in the consumer's extractor, so
    /// a test can assert on the exact one, and no adversary-controlled bytes
    /// can reach a log line through it.
    #[error("{endpoint}: the reply was not usable ({reason})")]
    Payload {
        /// The endpoint URL.
        endpoint: String,
        /// Which shape rule the body broke.
        reason: &'static str,
    },
    /// The endpoint answered, correctly, about a **different chain**
    /// (A17's `eth_chainId` guard; D55 §3).
    ///
    /// A third class rather than a [`Self::Payload`] with a formatted reason,
    /// and the reason is D55's own requirement that the mismatch report
    /// "names the expected and reported ids": a `&'static str` cannot carry
    /// them, and a `String` detail would be a channel for endpoint-controlled
    /// bytes. Two `u64`s are neither. It also *is* a distinct condition —
    /// not "no answer" and not "unusable answer" but "an answer about the
    /// wrong question", which is the shape a mistyped or hostile endpoint
    /// override produces.
    #[error("{endpoint}: serving chain id {reported}, expected {expected}")]
    WrongChain {
        /// The endpoint URL.
        endpoint: String,
        /// The chain id this network requires.
        expected: u64,
        /// The chain id the endpoint reported.
        reported: u64,
    },
}

impl EndpointFailure {
    /// The endpoint this failure is about.
    #[must_use]
    pub fn endpoint(&self) -> &str {
        match self {
            Self::Payload { endpoint, .. } | Self::WrongChain { endpoint, .. } => endpoint,
            Self::Http(error) => http_endpoint(error),
        }
    }

    /// A payload failure for `endpoint`.
    #[must_use]
    pub fn payload(endpoint: &Endpoint, reason: &'static str) -> Self {
        Self::Payload {
            endpoint: endpoint.url().to_owned(),
            reason,
        }
    }
}

/// Every [`AnchorHttpError`] arm carries the endpoint; this reads it back out
/// without the enum having to grow an accessor in A3's file.
///
/// **Wildcard-free**, the same discipline `http::retry::classify` applies for
/// the same reason: a new error arm must be given an endpoint deliberately,
/// not inherit the empty string and quietly drop an endpoint from a
/// degradation report. (`AnchorHttpError` is `#[non_exhaustive]`, but that
/// only binds other crates — this one is where the enum lives.)
fn http_endpoint(error: &AnchorHttpError) -> &str {
    match error {
        AnchorHttpError::InvalidEndpoint { endpoint, .. }
        | AnchorHttpError::TlsRequired { endpoint }
        | AnchorHttpError::Resolve { endpoint, .. }
        | AnchorHttpError::Connect { endpoint, .. }
        | AnchorHttpError::Tls { endpoint, .. }
        | AnchorHttpError::SendTimeout { endpoint, .. }
        | AnchorHttpError::ReceiveTimeout { endpoint, .. }
        | AnchorHttpError::Status { endpoint, .. }
        | AnchorHttpError::Redirected { endpoint, .. }
        | AnchorHttpError::OversizeBody { endpoint, .. }
        | AnchorHttpError::MalformedResponse { endpoint, .. }
        | AnchorHttpError::RealNetworkDenied { endpoint, .. }
        | AnchorHttpError::Transport { endpoint, .. } => endpoint,
    }
}

/// The outcome of asking two endpoints one question.
///
/// Three arms, and the two failures are **not** interchangeable:
/// [`Self::Unavailable`] is advisory and retryable (an endpoint was down),
/// while [`Self::Disagreed`] is alarming — it means one of two endpoints that
/// should not be able to coordinate is wrong or lying, and R's M3
/// endpoint-disagreement rendering exists for exactly that.
///
/// `T` is what the consumer extracted, so `Agreed(T)` carries the value both
/// endpoints stood behind and nothing else.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Agreement<T> {
    /// Both endpoints answered and their extracted values are equal.
    Agreed(T),
    /// Both endpoints answered and their extracted values differ. Both are
    /// carried: a renderer that showed only one would be choosing a winner,
    /// which is precisely the judgement this outcome refuses to make.
    Disagreed {
        /// What the first endpoint said.
        first: T,
        /// What the second endpoint said.
        second: T,
    },
    /// At least one endpoint could not be turned into a value. Carries one
    /// or two failures — never zero.
    Unavailable {
        /// Per-endpoint failures, in endpoint order.
        failures: Vec<EndpointFailure>,
    },
}

impl<T> Agreement<T> {
    /// The agreed value, if the endpoints agreed.
    #[must_use]
    pub const fn agreed(&self) -> Option<&T> {
        match self {
            Self::Agreed(value) => Some(value),
            _ => None,
        }
    }

    /// How many endpoints failed: 0, 1 or 2.
    #[must_use]
    pub fn failed(&self) -> usize {
        match self {
            Self::Unavailable { failures } => failures.len(),
            _ => 0,
        }
    }
}

/// Decide agreement over two already-collected results.
///
/// A pure function, and deliberately separate from [`fetch_and_agree`]: every
/// outcome — including the ones a live pair almost never produces — is then
/// reachable in a test without a socket, a clock or a scheduler.
///
/// Precedence is **failure first**: if either endpoint failed, the result is
/// [`Agreement::Unavailable`] and no comparison happens. One endpoint's answer
/// is not evidence; A16's whole premise is that a single endpoint is not
/// trusted, so "one succeeded, so use its value" would quietly delete the
/// property.
pub fn must_agree<T: PartialEq>(outcomes: [Result<T, EndpointFailure>; 2]) -> Agreement<T> {
    let [first, second] = outcomes;
    match (first, second) {
        (Ok(first), Ok(second)) => {
            if first == second {
                Agreement::Agreed(first)
            } else {
                Agreement::Disagreed { first, second }
            }
        }
        (Err(first), Err(second)) => Agreement::Unavailable {
            failures: vec![first, second],
        },
        (Err(only), Ok(_)) | (Ok(_), Err(only)) => Agreement::Unavailable {
            failures: vec![only],
        },
    }
}

/// Two endpoints that are not the same origin.
///
/// Construction is the only way to get one, so a caller cannot accidentally
/// pass the same endpoint twice and receive a confident `Agreed`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointPair {
    first: Endpoint,
    second: Endpoint,
}

/// A pair that cannot provide what a must-agree pair is for.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PairError {
    /// Both URLs name one origin.
    #[error(
        "{first} and {second} are the same origin ({origin}): a must-agree pair \
         of one endpoint agrees with itself and proves nothing"
    )]
    SameOrigin {
        /// The first URL, as supplied.
        first: String,
        /// The second URL, as supplied.
        second: String,
        /// The origin they share.
        origin: String,
    },
}

impl EndpointPair {
    /// Pair two endpoints.
    ///
    /// # Errors
    ///
    /// [`PairError::SameOrigin`] when the two URLs resolve to one
    /// `scheme://host:port`. This is refused rather than warned about: the
    /// failure mode is not a broken query but a *successful* one that reports
    /// agreement between an endpoint and itself, which is indistinguishable
    /// from real corroboration at every layer above.
    pub fn new(first: Endpoint, second: Endpoint) -> Result<Self, PairError> {
        if first.origin() == second.origin() {
            return Err(PairError::SameOrigin {
                first: first.url().to_owned(),
                second: second.url().to_owned(),
                origin: first.origin().to_owned(),
            });
        }
        Ok(Self { first, second })
    }

    /// The first endpoint.
    #[must_use]
    pub const fn first(&self) -> &Endpoint {
        &self.first
    }

    /// The second endpoint.
    #[must_use]
    pub const fn second(&self) -> &Endpoint {
        &self.second
    }
}

/// Ask both endpoints concurrently and decide agreement.
///
/// `extract` is run per endpoint and owns everything endpoint-specific: which
/// requests to issue, and how to turn the replies into the comparable value.
/// It never sees the other endpoint's result, which is what keeps one
/// endpoint from choosing the other's question — A16's esplora pair resolves
/// height → hash → header entirely within one endpoint for that reason.
pub fn fetch_and_agree<T, F>(client: &HttpClient, pair: &EndpointPair, extract: F) -> Agreement<T>
where
    T: PartialEq + Send,
    F: Fn(&HttpClient, &Endpoint) -> Result<T, EndpointFailure> + Sync,
{
    let (first, second) = std::thread::scope(|scope| {
        let first = scope.spawn(|| extract(client, pair.first()));
        let second = extract(client, pair.second());
        // A panic inside the extractor is a bug in this crate, not an
        // endpoint failure, and must not be laundered into `Unavailable` —
        // that would make a broken parser look like a down endpoint.
        let first = match first.join() {
            Ok(result) => result,
            Err(panic) => std::panic::resume_unwind(panic),
        };
        (first, second)
    });
    must_agree([first, second])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::TlsPolicy;

    fn endpoint(url: &str) -> Endpoint {
        Endpoint::parse(url, TlsPolicy::Optional).expect("test url")
    }

    fn http_failure(url: &str) -> EndpointFailure {
        EndpointFailure::Http(AnchorHttpError::Connect {
            endpoint: url.to_owned(),
            attempts: 3,
            detail: "Connection refused".into(),
        })
    }

    /// The three outcomes, over the full 3×3 grid of (ok/err) × (ok/err) plus
    /// the equal/unequal split. **This is the test that makes disagreement
    /// legible**: a primitive fed only agreeing endpoints has not been tested,
    /// and the failure mode of the thing being tested is that it reports
    /// `Agreed` when it should not.
    #[test]
    fn every_outcome_is_reachable_and_distinct() {
        assert_eq!(must_agree([Ok(7), Ok(7)]), Agreement::Agreed(7));
        assert_eq!(
            must_agree([Ok(7), Ok(8)]),
            Agreement::Disagreed {
                first: 7,
                second: 8
            }
        );
        // Order is preserved: `first` is the first endpoint's value, always.
        assert_eq!(
            must_agree([Ok(8), Ok(7)]),
            Agreement::Disagreed {
                first: 8,
                second: 7
            }
        );

        let a = http_failure("http://a.example");
        let b = http_failure("http://b.example");

        match must_agree([Err(a.clone()), Ok(7)]) {
            Agreement::Unavailable { failures } => {
                assert_eq!(failures, vec![a.clone()]);
            }
            other => panic!("one down must be Unavailable, got {other:?}"),
        }
        match must_agree([Ok(7), Err(b.clone())]) {
            Agreement::Unavailable { failures } => assert_eq!(failures, vec![b.clone()]),
            other => panic!("one down must be Unavailable, got {other:?}"),
        }
        match must_agree::<u32>([Err(a.clone()), Err(b.clone())]) {
            Agreement::Unavailable { failures } => assert_eq!(failures, vec![a, b]),
            other => panic!("both down must be Unavailable, got {other:?}"),
        }
    }

    /// The rule that makes the primitive worth having: **one endpoint's
    /// answer is never the answer.** An implementation that fell back to the
    /// surviving endpoint would pass every agreement test and every
    /// disagreement test, and would have silently reduced the pair to one
    /// trusted endpoint.
    #[test]
    fn a_surviving_endpoint_is_never_promoted_to_the_result() {
        let outcome = must_agree([Ok(0xabcd_u32), Err(http_failure("http://down.example"))]);
        assert_eq!(outcome.agreed(), None);
        assert_eq!(outcome.failed(), 1);
        assert!(
            matches!(outcome, Agreement::Unavailable { .. }),
            "{outcome:?}"
        );
    }

    /// Failure takes precedence over comparison, so a caller can never see
    /// `Disagreed` built from one real value and one default.
    #[test]
    fn failure_precedes_comparison() {
        for outcome in [
            must_agree([Err(http_failure("http://a.example")), Ok(1)]),
            must_agree([Ok(1), Err(http_failure("http://b.example"))]),
        ] {
            assert!(matches!(outcome, Agreement::Unavailable { .. }));
        }
    }

    /// A pair of one endpoint is refused at construction.
    ///
    /// Both directions: the two real A16 defaults must pair, or the check
    /// would be a check that rejects everything.
    #[test]
    fn a_pair_that_is_one_origin_is_refused() {
        for (a, b) in [
            ("https://example.org/api", "https://example.org/api"),
            // Same origin, different path — the shape a copy-paste override
            // produces.
            ("https://example.org/api/x", "https://example.org/api/y"),
            // Same origin, spelled differently.
            ("https://Example.ORG/api", "https://example.org:443/api"),
        ] {
            let err = EndpointPair::new(endpoint(a), endpoint(b))
                .map(|_| "wrongly paired")
                .expect_err(a);
            assert!(matches!(err, PairError::SameOrigin { .. }), "{err:?}");
            assert!(
                err.to_string().contains("proves nothing"),
                "the message must say why: {err}"
            );
        }

        EndpointPair::new(
            endpoint("https://blockstream.info/api"),
            endpoint("https://mempool.space/api"),
        )
        .expect("the two real A16 defaults are distinct origins");
    }

    /// `EndpointFailure::endpoint` reads the URL back out of either arm, so a
    /// degradation report can name every endpoint that failed (D54's
    /// `every_failed_endpoint_appears_in_the_degradation_report` shape).
    #[test]
    fn a_failure_names_its_own_endpoint() {
        assert_eq!(
            http_failure("http://a.example").endpoint(),
            "http://a.example"
        );
        assert_eq!(
            EndpointFailure::payload(&endpoint("http://b.example"), "not 80 bytes").endpoint(),
            "http://b.example"
        );
    }
}
