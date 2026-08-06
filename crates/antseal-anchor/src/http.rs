//! The anchor HTTP substrate (task **A3**; decision
//! [D90](../../../docs/decisions/D90-anchor-http-substrate.md)).
//!
//! Every byte an adversary controls enters this process through this module,
//! before any parser of ours has seen it. Its job is to bound that — in time,
//! in size, in transport and in the number of times a write is repeated — and
//! to hand the rest of the crate a typed failure rather than a surprise.
//!
//! # Blocking, with no runtime created, borrowed or required
//!
//! `antseal-anchor` creates **no** async runtime, borrows none, and requires
//! no async context. [`AnchorGate::run`](crate::gate::AnchorGate::run) keeps
//! its frozen `async fn` signature and its body blocks: a blocking body
//! inside an `async fn` returns `Poll::Ready` on the first poll, which D90
//! measured rather than argued (probe 6: *"polls to completion = 1"* under
//! the noop-waker executor `gate.rs` already uses). That is what makes
//! A15/U24 — an opportunistic upgrade attempt on *every* CLI invocation, in
//! builds where `tokio` is not compiled in at all — implementable, and it is
//! why the client is `ureq` rather than anything that needs a reactor.
//!
//! Independence across endpoints (A10's "one TSA's failure never aborts or
//! **delays** the others", A16's must-agree pair) comes from
//! [`std::thread::scope`], not from a runtime; [`HttpClient`] is `Send +
//! Sync` and is meant to be shared across scoped threads.
//!
//! One residual coupling, recorded because its failure mode is a hang with no
//! local cause: blocking inside `rt.block_on` is safe **only because**
//! `antseal-cli`'s `runtime()` builds a `new_multi_thread` runtime, so
//! ant-core's spawned tasks progress on worker threads while the calling
//! thread sits on a socket. On a `new_current_thread` runtime they would
//! starve. Q84 owns asserting that invariant on the other side of the seam
//! (D90 §3.3).
//!
//! # Three `ureq` behaviours that no documentation states
//!
//! Each was found by executed probe, each is a defect if the obvious thing is
//! assumed, and each is pinned by a named test here so an `ureq` bump goes
//! red rather than quiet:
//!
//! 1. **`.limit(N)` accepts at most `N − 1` bytes.** `LimitReader` errors as
//!    soon as its allowance is exhausted rather than returning `Ok(0)`, so a
//!    literal `.limit(MAX_TSA_TOKEN_BYTES)` would reject a token of exactly
//!    `MAX_TSA_TOKEN_BYTES` — a token that *is* embeddable — silently turning
//!    A28's `≤` into `<`. The compensation lives in [`read_limit`] and
//!    nowhere else, so every caller's `receive_cap_bytes` is the true
//!    ceiling and means it.
//! 2. **`max_redirects(0)` returns the 3xx rather than erroring.**
//!    `Config::max_redirects_do_error()` is `max_redirects > 0 &&
//!    max_redirects_will_error`, which zero can never satisfy. A client that
//!    only asked "did I get a response" would hand an empty body to the DER
//!    parser, so the 3xx classification is **ours**
//!    ([`AnchorHttpError::Redirected`]).
//! 3. **`Config::default()` reads `HTTP_PROXY`/`ALL_PROXY` from the
//!    environment.** This is the dangerous one. It would route *both* halves
//!    of A16's must-agree pair through one on-path intermediary — two
//!    endpoints wearing one origin, agreeing perfectly, on whatever that
//!    intermediary chose to say — which is precisely the independence the
//!    must-agree design exists to provide. The agent sets `.proxy(None)`
//!    unconditionally. If a proxy is ever wanted it becomes an explicit
//!    field in U4's config under its own recorded decision, never an ambient
//!    default.
//!
//! # What this module deliberately does not provide (D90 §6.9)
//!
//! - **No response-comparison helper.** Agreement is never over response
//!   bytes: the two ruled-in Arbitrum RPCs return *different JSON key sets*
//!   for the same receipt while the values A17 compares are identical, so a
//!   generic `must_agree(&[u8], &[u8])` would report "a lying endpoint" for
//!   two honest ones on every call. Agreement is defined per source, by the
//!   consumer, over an extracted value.
//! - **No liveness or health probe.** An endpoint that answers
//!   `eth_blockNumber` in 0.75 s can still reject the only query A17 makes
//!   (`"Archive requests require a personal token"`, measured), so a probe on
//!   a cheap method converts an authorization failure into an endorsement.
//!   Probe with the method the caller actually issues, against a real
//!   argument, or do not probe.
//! - **No browser reachability claim.** This crate is never compiled to
//!   wasm32: the verifier page performs its own fetches in JS and feeds
//!   results to WASM-safe core through A2's `OnlineEvidence`.

pub mod endpoint;
pub mod offline;
pub mod retry;

use std::io::Read as _;
use std::time::Duration;

pub use endpoint::{Endpoint, EndpointError, TlsPolicy};
pub use retry::{Idempotency, RetryVerdict, classify};

// ─── Timeouts (D90 §6.2) ────────────────────────────────────────────────────

/// Per-attempt wall-clock backstop. A3 proposed ~10 s; confirmed against
/// measured round trips (slowest real endpoint 1.996 s, 2026-08-02) — 5× the
/// worst observed, with the largest single component (a 1.047 s TLS
/// handshake) an order of magnitude inside it. `Timeout(Global)` is
/// classified **ambiguous** because it cannot name a phase, and by
/// construction it only fires when no single phase did.
pub const HTTP_TIMEOUT_GLOBAL_MILLIS: u64 = 10_000;
/// See [`HTTP_TIMEOUT_GLOBAL_MILLIS`].
pub const HTTP_TIMEOUT_GLOBAL: Duration = Duration::from_millis(HTTP_TIMEOUT_GLOBAL_MILLIS);
/// The per-phase rungs of [`HttpTimeouts::standard`]. **Strictly decreasing**
/// — see [`HttpTimeouts::within`] for why that ordering is a correctness
/// requirement and not a taste.
pub const HTTP_TIMEOUT_RESOLVE: Duration = HttpTimeouts::standard().resolve;
/// See [`HTTP_TIMEOUT_RESOLVE`].
pub const HTTP_TIMEOUT_CONNECT: Duration = HttpTimeouts::standard().connect;
/// See [`HTTP_TIMEOUT_RESOLVE`].
pub const HTTP_TIMEOUT_SEND_REQUEST: Duration = HttpTimeouts::standard().send_request;
/// See [`HTTP_TIMEOUT_RESOLVE`].
pub const HTTP_TIMEOUT_SEND_BODY: Duration = HttpTimeouts::standard().send_body;
/// See [`HTTP_TIMEOUT_RESOLVE`].
pub const HTTP_TIMEOUT_RECV_RESPONSE: Duration = HttpTimeouts::standard().recv_response;
/// See [`HTTP_TIMEOUT_RESOLVE`].
pub const HTTP_TIMEOUT_RECV_BODY: Duration = HttpTimeouts::standard().recv_body;

/// 1 initial attempt + 2 retries. Worst case per endpoint under
/// [`HttpPolicy::seal`]: 3 × 10 s + 0.8 s = **30.8 s**, which is a
/// PER-ENDPOINT bound only because endpoints run on [`std::thread::scope`].
pub const HTTP_MAX_ATTEMPTS: u32 = 3;
/// Deterministic and un-jittered: two to five named endpoints is not a
/// fleet, and an RNG in the retry path would make the timeout tests
/// approximate. Index `n` is the pause *after* attempt `n + 1` failed; a
/// budget larger than this array reuses the last value.
pub const HTTP_BACKOFF: [Duration; 2] = [Duration::from_millis(200), Duration::from_millis(600)];

/// A15/U24's hook fires on EVERY CLI invocation and must never delay the
/// host command: one attempt, no backoff. (A finding A15/U24 must act on
/// rather than a rule this module can impose: at 3 s per calendar even a
/// single attempt is user-visible, so "never delays the host command" is
/// only achievable if the hook runs **after** the host command's output is
/// flushed. A pre-output hook cannot satisfy that wording at any timeout
/// this substrate can offer.)
pub const HTTP_OPPORTUNISTIC_GLOBAL_MILLIS: u64 = 3_000;
/// See [`HTTP_OPPORTUNISTIC_GLOBAL_MILLIS`].
pub const HTTP_OPPORTUNISTIC_GLOBAL: Duration =
    Duration::from_millis(HTTP_OPPORTUNISTIC_GLOBAL_MILLIS);
/// The connect allowance D90 specified for the opportunistic profile. It is
/// **a floor on the rung, not the rung itself**: the phase budgets have to
/// form a strictly decreasing ladder (see [`HttpTimeouts::within`]), so
/// connect gets 80 % of the 3 s global — 2.4 s — which is more than this and
/// therefore satisfies D90's intent. Asserted, so a future narrowing of the
/// ladder cannot silently drop below it.
pub const HTTP_OPPORTUNISTIC_CONNECT: Duration = Duration::from_millis(1_500);
/// See [`HTTP_OPPORTUNISTIC_GLOBAL_MILLIS`].
pub const HTTP_OPPORTUNISTIC_ATTEMPTS: u32 = 1;

/// Honest identification to volunteer calendars and commercial TSAs with
/// abuse controls. Replaces `ureq`'s default `ureq/3.3.0`, which would tell
/// an observer of a plain-HTTP DigiCert request exactly which HTTP-client
/// bugs to aim at.
pub const HTTP_USER_AGENT: &str = concat!("antseal/", env!("CARGO_PKG_VERSION"));
/// Bounded before any body is read. `ureq`'s own default is 64 KiB.
pub const HTTP_MAX_RESPONSE_HEADER_BYTES: usize = 16 * 1024;

/// The ceiling on a body carried inside [`AnchorHttpError::Status`].
/// Deliberately far smaller than any artifact cap: the bodies this exists to
/// preserve are *discriminators* (A14's three-way upgrade state is a 404
/// **body**, the largest observed being 42 bytes), never anchor artifacts, so
/// this must not be able to approach `MAX_TSA_TOKEN_BYTES`/`MAX_OTS_BYTES`.
pub const HTTP_ERROR_BODY_CAP_BYTES: u64 = 4 * 1024;

// ─── Receive-side ceilings (D90 §6.8) ───────────────────────────────────────
//
// The substrate applies the `+ 1` that ureq's `LimitReader` requires (see
// `read_limit`); every constant below is the TRUE ceiling, and a call site
// passing one means exactly it.
//
// These are **per-HTTP-reply** ceilings. They are a different quantity from
// the artifact caps in `antseal_core::codec::caps`, which bound what a bundle
// may *embed*, and the two coincide in exactly one case (the TSA one, below)
// for a reason that is stated there rather than assumed.

/// A single TSA `TimeStampResp` **is** the artifact that gets embedded — one
/// response, one token — so here the receive cap and the embed cap are the
/// same quantity, and A28's `receive_cap <= MAX_TSA_TOKEN_BYTES` becomes an
/// identity rather than an assertion that can drift. Consumed by name from
/// `antseal_core::codec::caps`, never redefined (D84 §5).
pub const TSA_RESPONSE_CAP_BYTES: u64 = antseal_core::codec::caps::MAX_TSA_TOKEN_BYTES;

/// **A calendar's per-response body is NOT the embedded artifact**, and this
/// constant must not be confused with `MAX_OTS_BYTES`.
///
/// `MAX_OTS_BYTES` = 1 MiB caps the *merged* `.ots` that goes into the
/// bundle — every calendar, every upgrade, accumulated. This caps **one HTTP
/// reply from one calendar**. Measured across 18 real calendar responses
/// (2026-08-02): the **largest was 220 bytes**. 64 KiB is a 298× margin over
/// that and leaves room for an upgraded attestation's Bitcoin merkle path;
/// 1 MiB would have frozen a ceiling **4 766×** above anything observed, and
/// under F4's raise-only rule a too-high cap can never be walked back while a
/// too-low one costs a follow-up commit. A28's separate merge-side cap is the
/// one that carries `merge_cap <= MAX_OTS_BYTES`.
pub const OTS_CALENDAR_RESPONSE_CAP_BYTES: u64 = 65_536;

/// Advisory online evidence, not an embeddable artifact — no F4 registry row
/// (D84's F1–F4 govern anchor artifacts; an esplora reply is neither), so
/// this is freely adjustable network-path policy. It bounds a reply whose
/// payload is 160 hex characters.
pub const ESPLORA_RESPONSE_CAP_BYTES: u64 = 16 * 1024;

/// Sized from this project's own payment shape, not from a round number.
///
/// D37 permits **256 transfers in one transaction**; a measured Arbitrum
/// receipt log is 731 B, so the largest receipt A17 must be able to read is
/// 256 × 731 = 187 136 B of logs plus a ~1 192 B envelope = **188 328 B**. A
/// 64 KiB cap would truncate at **89 logs** — i.e. A17 would fail on exactly
/// the large seals it exists to corroborate, and it would fail as
/// `OversizeBody`, which reads as an endpoint problem and would be attributed
/// to one. 512 KiB is 2.78× the D37-maximum receipt, absorbs the key-set
/// variance between endpoints, and costs at most 1 MiB resident across a
/// must-agree pair.
pub const RPC_RESPONSE_CAP_BYTES: u64 = 512 * 1024;

/// The largest Arbitrum receipt A17 must be able to read, at D37's
/// 256-transfer maximum. Pinned as a constant so the arithmetic behind
/// [`RPC_RESPONSE_CAP_BYTES`] survives even if the test that streams a body
/// this size is later shrunk for speed.
pub const D37_MAX_RECEIPT_BYTES: u64 = 188_328;

const _: () = {
    // Strict inequality, because equality *is* the conflation §6.8 forbids:
    // a calendar reply and the merged artifact are different quantities.
    assert!(OTS_CALENDAR_RESPONSE_CAP_BYTES < antseal_core::codec::caps::MAX_OTS_BYTES);
    // A28's derived constraint, as an identity on the TSA side.
    assert!(TSA_RESPONSE_CAP_BYTES == antseal_core::codec::caps::MAX_TSA_TOKEN_BYTES);
    // The cap A17 depends on admits the largest receipt D37 permits.
    assert!(RPC_RESPONSE_CAP_BYTES >= D37_MAX_RECEIPT_BYTES);
    // D90's opportunistic connect allowance is a floor on the rung.
    assert!(
        HttpTimeouts::opportunistic().connect.as_millis() >= HTTP_OPPORTUNISTIC_CONNECT.as_millis()
    );
};

/// The value to hand `ureq`'s `.limit()` for a **true** ceiling of
/// `true_ceiling` bytes.
///
/// `ureq`'s `LimitReader::read` errors as soon as its allowance is exhausted
/// instead of returning `Ok(0)`, so `read_to_end` never observes the clean
/// end of an exactly-at-the-limit body. Executed through the real API
/// (D90 probe 2):
///
/// ```text
/// PROBE 2 body=1023 limit=1024 -> ok=true
/// PROBE 2 body=1024 limit=1024 -> ok=false
/// PROBE 2 body=1024 limit=1025 -> ok=true
/// ```
///
/// **This is the only place the `+ 1` appears.** Duplicating it doubles the
/// ceiling; dropping it turns every `≤` in A28 into `<`.
#[must_use]
const fn read_limit(true_ceiling: u64) -> u64 {
    true_ceiling.saturating_add(1)
}

// ─── Policy ─────────────────────────────────────────────────────────────────

/// Per-phase timeouts. All values are strictly inside
/// [`HttpTimeouts::global`] so a stall names its own phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HttpTimeouts {
    /// Wall-clock backstop for one attempt.
    pub global: Duration,
    /// DNS.
    pub resolve: Duration,
    /// TCP (and, for https, the TLS handshake).
    pub connect: Duration,
    /// Writing the request head.
    pub send_request: Duration,
    /// Writing the request body.
    pub send_body: Duration,
    /// Awaiting the response head.
    pub recv_response: Duration,
    /// Reading the response body.
    pub recv_body: Duration,
}

impl HttpTimeouts {
    /// A **strictly decreasing** ladder of phase budgets inside a global of
    /// `global_millis`: resolve 90 %, connect 80 %, send-request 70 %,
    /// send-body 60 %, recv-response 50 %, recv-body 40 %.
    ///
    /// # Why the ordering is a correctness requirement
    ///
    /// **Found by executing D90's own constant table, 2026-08-02.** `ureq`
    /// does not evaluate one deadline per phase. `CallTimings::next_timeout`
    /// (`ureq-3.3.0/src/timings.rs:157-176`) takes the **minimum** over the
    /// current phase *and its immediate predecessors* — and it records a
    /// phase's timestamp when that phase **ends**
    /// (`record_time`, `src/run.rs:430`, `:528`, `:588`), so a predecessor's
    /// clock starts running at the moment the next phase begins. The
    /// predecessor graph is `RecvBody ← RecvResponse ← {SendRequest,
    /// SendBody} ← Connect ← Resolve`.
    ///
    /// The consequence: while we sit in `RecvResponse`, `SendRequest`'s
    /// deadline is also live, and if `send_request < recv_response` **it
    /// expires first and `ureq` reports `Timeout(SendRequest)` for a request
    /// the server has already received in full.**
    ///
    /// D90's table (resolve 3 s, connect 4 s, send-request 4 s, send-body
    /// 4 s, recv-response 8 s, recv-body 8 s) is increasing across exactly
    /// that boundary, and executing it against a stub that reads the request
    /// and then stalls produced:
    ///
    /// ```text
    /// SendTimeout { endpoint: "http://127.0.0.1:39199", phase: "send-request" }
    /// ```
    ///
    /// — a *delivered* POST classified pre-send, hence retried, hence a
    /// second pending attestation at the calendar. That is precisely the
    /// double-submission A13's Accept row 1 depends on never happening.
    ///
    /// Two independent fixes are applied, and both are asserted:
    /// this ladder (so the reported phase is the phase we are in), and
    /// [`timeout_phase`]'s conservative placement (so the *classification* is
    /// safe even if a future editor flattens the ladder).
    #[must_use]
    pub const fn within(global_millis: u64) -> Self {
        Self {
            global: Duration::from_millis(global_millis),
            resolve: Duration::from_millis(global_millis * 9 / 10),
            connect: Duration::from_millis(global_millis * 8 / 10),
            send_request: Duration::from_millis(global_millis * 7 / 10),
            send_body: Duration::from_millis(global_millis * 6 / 10),
            recv_response: Duration::from_millis(global_millis * 5 / 10),
            recv_body: Duration::from_millis(global_millis * 4 / 10),
        }
    }

    /// The measured default: a 10 s global with the ladder inside it —
    /// resolve 9 s, connect 8 s, send-request 7 s, send-body 6 s,
    /// recv-response 5 s, recv-body 4 s.
    ///
    /// Every rung has room for the worst case measured against the real M2
    /// endpoints on 2026-08-02: the slowest TLS handshake was 1.047 s against
    /// an 8 s connect budget, and the slowest time-to-first-byte was 1.772 s
    /// against a 5 s recv-response budget. Each rung is an **idle** timeout —
    /// `ureq` recomputes the current phase's deadline from `now` on every
    /// poll — so the only total bound is the global.
    #[must_use]
    pub const fn standard() -> Self {
        Self::within(HTTP_TIMEOUT_GLOBAL_MILLIS)
    }

    /// A15/U24's profile: a 3 s global, so an opportunistic poll can never
    /// delay a CLI command by more than that.
    ///
    /// **Not** [`Self::within`]'s ten-percent ladder, and the reason is
    /// arithmetic rather than taste. `within(3_000)` would put recv-response
    /// at 1.5 s, and the slowest calendar D90 measured
    /// (`alice.btc.calendar.opentimestamps.org`) answers at a
    /// time-to-first-byte of **1.772 s** — so the profile would time out on a
    /// healthy endpoint and A15 would report every upgrade poll as a failure.
    /// The rungs are therefore packed at 100 ms intervals just under the
    /// global: still strictly decreasing (which is what keeps the phase names
    /// honest), but leaving 2.5 s for the response instead of 1.5 s. Tight
    /// gaps cost only *name precision* — a stall may be attributed to the
    /// phase before it — never safety, because the pre-send/ambiguous split
    /// comes from [`timeout_phase`]'s graph and not from the gaps.
    #[must_use]
    pub const fn opportunistic() -> Self {
        Self {
            global: HTTP_OPPORTUNISTIC_GLOBAL,
            resolve: Duration::from_millis(2_900),
            connect: Duration::from_millis(2_800),
            send_request: Duration::from_millis(2_700),
            send_body: Duration::from_millis(2_600),
            recv_response: Duration::from_millis(2_500),
            recv_body: Duration::from_millis(2_400),
        }
    }
}

/// How one family of anchor calls is executed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HttpPolicy {
    /// Per-phase deadlines.
    pub timeouts: HttpTimeouts,
    /// Total attempts, initial included. `0` and `1` both mean a single
    /// attempt — the first one is always made, because a policy that
    /// performed no request at all would report a network failure for a
    /// request that never happened.
    pub max_attempts: u32,
    /// Whether the endpoints of this family must be reached over TLS. Set by
    /// the profile, never by the call site — see [`HttpPolicy::verify`].
    pub tls: TlsPolicy,
}

impl HttpPolicy {
    /// A10 (TSA POSTs) and A13 (calendar submits) — the pre-pay gate.
    ///
    /// [`TlsPolicy::Optional`] because RFC 3161 tokens are signed and
    /// nonce-bound, and because `timestamp.digicert.com` has no port 443 at
    /// all (measured): a TLS-only substrate could not reach one of the
    /// spec's two default TSAs.
    #[must_use]
    pub const fn seal() -> Self {
        Self {
            timeouts: HttpTimeouts::standard(),
            max_attempts: HTTP_MAX_ATTEMPTS,
            tls: TlsPolicy::Optional,
        }
    }

    /// A16 (esplora) and A17 (Arbitrum RPC) — `verify --online`.
    ///
    /// [`TlsPolicy::RequiredExceptLoopback`], and this is **task A49's
    /// structural half**: these two families' replies are unsigned and are
    /// trusted only because two independent endpoints agree, so transport
    /// security is their only integrity control. Because the profile carries
    /// the policy, an A16/A17 call site cannot obtain a permissive client by
    /// forgetting a parameter — it would have to build one deliberately.
    #[must_use]
    pub const fn verify() -> Self {
        Self {
            timeouts: HttpTimeouts::standard(),
            max_attempts: HTTP_MAX_ATTEMPTS,
            tls: TlsPolicy::RequiredExceptLoopback,
        }
    }

    /// A15/U24's opportunistic upgrade poll: one attempt, 3 s, no backoff.
    #[must_use]
    pub const fn opportunistic() -> Self {
        Self {
            timeouts: HttpTimeouts::opportunistic(),
            max_attempts: HTTP_OPPORTUNISTIC_ATTEMPTS,
            tls: TlsPolicy::Optional,
        }
    }
}

// ─── Request / response ─────────────────────────────────────────────────────

/// The two methods the anchor clients use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HttpMethod {
    /// A14's upgrade poll, A16's esplora reads.
    Get,
    /// A10's TSA request, A13's calendar submit, A17's JSON-RPC call.
    Post,
}

/// One anchor request.
#[derive(Debug, Clone)]
pub struct HttpRequest<'a> {
    /// Where to send it. Already parsed and transport-checked.
    pub endpoint: &'a Endpoint,
    /// Method.
    pub method: HttpMethod,
    /// `Content-Type` for the request body, when there is one.
    pub content_type: Option<&'a str>,
    /// `Accept`, when the endpoint cares.
    pub accept: Option<&'a str>,
    /// The request body. Empty for [`HttpMethod::Get`]. Held by reference so
    /// a retry re-sends the identical bytes.
    pub body: &'a [u8],
    /// The **true** ceiling on the response body, in bytes: a body of exactly
    /// this size is accepted and one byte more is not. The `+ 1` `ureq`
    /// requires is applied inside the substrate ([`read_limit`]).
    pub receive_cap_bytes: u64,
    /// Whether this request may be re-sent after it might already have been
    /// delivered.
    pub idempotency: Idempotency,
}

/// A successful (2xx) anchor response.
///
/// Non-2xx never arrives here: it is [`AnchorHttpError::Status`], body and
/// all. Keeping it in the error arm rather than returning an `HttpResponse`
/// for every status is deliberate — it preserves A10's "HTTP failure ⇒
/// distinct outcome" for free, and it makes it structurally impossible for a
/// caller to hand a 500's body to the DER parser by forgetting a check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    /// The 2xx status code.
    pub status: u16,
    /// The body, at most `receive_cap_bytes` long.
    pub body: Vec<u8>,
}

// ─── Errors ─────────────────────────────────────────────────────────────────

/// An anchor request failed, with the endpoint URL and a failure class.
///
/// It deliberately has **no `code()`**: the error-code contract
/// (`docs/testing/error-code-contract.md` §1) governs errors a *verifier* can
/// surface, and an acquisition failure never appears in a `.sealproof`
/// verdict. It reaches a user through `CliError`'s existing classes.
///
/// The `endpoint` field carries a URL only. Calendar upgrade URLs embed a
/// commitment derived from `anchor_digest` — public manifest-identity data,
/// never `W`, a unit key or a salt — so project rule 6 is satisfied by
/// construction and the field needs no redaction.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum AnchorHttpError {
    /// The URL is not usable as an endpoint.
    #[error("{endpoint}: not a usable endpoint URL ({reason})")]
    InvalidEndpoint {
        /// The URL as supplied.
        endpoint: String,
        /// Which structural rule it broke.
        reason: &'static str,
    },
    /// Plain HTTP where the transport is the only integrity control (A49).
    #[error("{endpoint}: this endpoint must be https (only loopback literals are exempt)")]
    TlsRequired {
        /// The URL as supplied.
        endpoint: String,
    },
    /// DNS never produced an address.
    #[error("{endpoint}: DNS resolution failed after {attempts} attempt(s)")]
    Resolve {
        /// The endpoint URL.
        endpoint: String,
        /// How many attempts were made.
        attempts: u32,
    },
    /// No connection was established.
    #[error("{endpoint}: connection failed after {attempts} attempt(s): {detail}")]
    Connect {
        /// The endpoint URL.
        endpoint: String,
        /// How many attempts were made.
        attempts: u32,
        /// The underlying reason, as the transport reported it.
        detail: String,
    },
    /// The TLS handshake failed. Named explicitly so that a stale
    /// `webpki-roots` snapshot — a *liveness* failure that otherwise reads
    /// like an attack — triages in one step.
    #[error("{endpoint}: TLS handshake failed: {detail}")]
    Tls {
        /// The endpoint URL.
        endpoint: String,
        /// The underlying reason.
        detail: String,
    },
    /// A timeout that `ureq`'s own predecessor graph proves fired before any
    /// request byte could have been actioned by the server, so a retry cannot
    /// duplicate anything. See [`timeout_phase`] for why only two phases
    /// qualify.
    #[error("{endpoint}: timed out before the request could be sent ({phase})")]
    SendTimeout {
        /// The endpoint URL.
        endpoint: String,
        /// Which phase: `resolve` or `connect`.
        phase: &'static str,
    },
    /// A timeout that may have fired after the request was delivered in full.
    /// Covers the send phases too, and deliberately — see [`timeout_phase`].
    #[error("{endpoint}: timed out ({phase}); the request may have been delivered")]
    ReceiveTimeout {
        /// The endpoint URL.
        endpoint: String,
        /// Which phase: `send-request`, `send-body`, `recv-response`,
        /// `recv-body`, `global`, `per-call`.
        phase: &'static str,
    },
    /// A complete response arrived with a non-2xx status.
    ///
    /// **The body is carried, not discarded.** A14's upgrade discriminator is
    /// three-way and body-separated — `200` + attestation, `404` + *pending*
    /// text, `404` + *not found* text — and the two 404s are indistinguishable
    /// by status alone, so a substrate that collapsed this arm to a status
    /// code would make A14 unimplementable on top of it. Bounded by
    /// [`HTTP_ERROR_BODY_CAP_BYTES`], **not** by the request's own
    /// `receive_cap_bytes`, and truncated rather than refused: an over-long
    /// error body is best-effort evidence, not a failed request.
    ///
    /// Caution inherited from the measurement: the two 404 bodies differ in
    /// length between calendars (9 vs 10 bytes — one has a trailing newline),
    /// so any matcher built on this must compare **trimmed content**, never
    /// length and never a byte-exact literal.
    #[error("{endpoint}: HTTP {status} ({} body byte(s))", body.len())]
    Status {
        /// The endpoint URL.
        endpoint: String,
        /// The status code.
        status: u16,
        /// The response body, truncated to [`HTTP_ERROR_BODY_CAP_BYTES`].
        body: Vec<u8>,
    },
    /// A 3xx. Endpoints are pinned URLs and redirects are never followed:
    /// on a 301/302 `ureq` would rewrite our POST to a GET and drop the DER
    /// body, a moved endpoint should be a loud error a human reads, and —
    /// decisively — two endpoints that both redirect to a common origin are
    /// one endpoint wearing two names, under which A16's "both must succeed
    /// and agree" becomes a tautology that still reports agreement.
    #[error(
        "{endpoint}: HTTP {status} redirect to {location:?} — endpoints are pinned and redirects are never followed"
    )]
    Redirected {
        /// The endpoint URL.
        endpoint: String,
        /// The 3xx status code.
        status: u16,
        /// The `Location` header, if the response carried a usable one.
        location: Option<String>,
    },
    /// The response body exceeded the caller's true ceiling. Enforced while
    /// streaming, so nothing over-sized is ever allocated.
    #[error("{endpoint}: response exceeds the {cap_bytes}-byte receive ceiling")]
    OversizeBody {
        /// The endpoint URL.
        endpoint: String,
        /// The true ceiling that was exceeded.
        cap_bytes: u64,
    },
    /// The response was not valid HTTP.
    #[error("{endpoint}: malformed HTTP response: {detail}")]
    MalformedResponse {
        /// The endpoint URL.
        endpoint: String,
        /// The underlying reason.
        detail: String,
    },
    /// Refused by the no-real-anchor-network policy (task **Q16**) before
    /// any address was resolved. **No socket was opened.**
    ///
    /// Only a loopback IP literal may be dialled while the gate is armed;
    /// see [`offline`] for the two arms and
    /// `docs/testing/anchor-ci-policy.md` for the policy this enforces.
    #[error(
        "{endpoint}: refused by the no-real-anchor-network policy ({reason}); \
         only loopback IP literals may be dialled here — see \
         docs/testing/anchor-ci-policy.md"
    )]
    RealNetworkDenied {
        /// The endpoint URL that was refused.
        endpoint: String,
        /// Which arm of [`offline::decide`] armed the gate.
        reason: &'static str,
    },
    /// Any other transport failure. Treated as *ambiguous* by the retry
    /// classifier — it is D90's "any other `Error::Io`" row.
    #[error("{endpoint}: transport failure: {detail}")]
    Transport {
        /// The endpoint URL.
        endpoint: String,
        /// The underlying reason.
        detail: String,
    },
}

impl From<EndpointError> for AnchorHttpError {
    fn from(error: EndpointError) -> Self {
        match error {
            EndpointError::Invalid { endpoint, reason } => {
                Self::InvalidEndpoint { endpoint, reason }
            }
            EndpointError::TlsRequired { endpoint } => Self::TlsRequired { endpoint },
        }
    }
}

// ─── The client ─────────────────────────────────────────────────────────────

/// The one configured HTTP client of this crate.
///
/// No call site may construct a bare `ureq::Agent`: every setting on it
/// ([`HttpClient::new`]) is either a measured decision or a defence against
/// an `ureq` default, and an agent built anywhere else would silently have
/// the defaults back — most dangerously the ambient proxy.
#[derive(Debug, Clone)]
pub struct HttpClient {
    agent: ureq::Agent,
    policy: HttpPolicy,
}

impl HttpClient {
    /// Build the agent, once, with exactly this configuration.
    #[must_use]
    pub fn new(policy: HttpPolicy) -> Self {
        let config = ureq::Agent::config_builder()
            .timeout_global(Some(policy.timeouts.global))
            .timeout_resolve(Some(policy.timeouts.resolve))
            .timeout_connect(Some(policy.timeouts.connect))
            .timeout_send_request(Some(policy.timeouts.send_request))
            .timeout_send_body(Some(policy.timeouts.send_body))
            .timeout_recv_response(Some(policy.timeouts.recv_response))
            .timeout_recv_body(Some(policy.timeouts.recv_body))
            // Redirects are refused, not followed — and because
            // `max_redirects(0)` RETURNS the 3xx rather than erroring, the
            // classification is ours (module docs, item 2).
            .max_redirects(0)
            // We classify statuses ourselves: `ureq`'s own status-as-error
            // discards the body, which is A14's discriminator.
            .http_status_as_error(false)
            // NOT the default. `Config::default()` reads HTTP_PROXY/ALL_PROXY
            // and would collapse A16's must-agree pair onto one origin
            // (module docs, item 3).
            .proxy(None)
            // Per-request instead, from `TlsPolicy` — `https_only` cannot
            // express the loopback carve-out A24's stubs need.
            .https_only(false)
            // A streaming byte ceiling on a *compressed* body bounds the
            // wrong number. `default-features = false` already drops gzip;
            // this closes the path rather than reasoning about it.
            .accept_encoding(ureq::config::AutoHeaderValue::None)
            .user_agent(HTTP_USER_AGENT)
            .max_response_header_size(HTTP_MAX_RESPONSE_HEADER_BYTES)
            .build();
        Self {
            agent: config.into(),
            policy,
        }
    }

    /// The policy this client was built with.
    #[must_use]
    pub const fn policy(&self) -> &HttpPolicy {
        &self.policy
    }

    /// Send `request`, retrying according to [`retry::classify`].
    ///
    /// # Errors
    ///
    /// [`AnchorHttpError`], carrying the endpoint URL and the failure class.
    /// A non-2xx response is an error *with its body*
    /// ([`AnchorHttpError::Status`]).
    pub fn send(&self, request: &HttpRequest<'_>) -> Result<HttpResponse, AnchorHttpError> {
        // Second enforcement point (A49): an `Endpoint` parsed permissively
        // still cannot be sent through a client whose family requires TLS.
        self.policy.tls.admits(request.endpoint)?;

        let mut attempt: u32 = 0;
        loop {
            attempt = attempt.saturating_add(1);
            let error = match self.attempt(request, attempt) {
                Ok(response) => return Ok(response),
                Err(error) => error,
            };
            if attempt >= self.policy.max_attempts
                || retry::classify(&error, request.idempotency) == RetryVerdict::Stop
            {
                return Err(error);
            }
            let index = usize::try_from(attempt - 1).unwrap_or(usize::MAX);
            let pause = HTTP_BACKOFF
                .get(index)
                .or_else(|| HTTP_BACKOFF.last())
                .copied()
                .unwrap_or(Duration::ZERO);
            std::thread::sleep(pause);
        }
    }

    /// One attempt. No retry logic, no sleeping.
    fn attempt(
        &self,
        request: &HttpRequest<'_>,
        attempt: u32,
    ) -> Result<HttpResponse, AnchorHttpError> {
        let url = request.endpoint.url();

        // Q16's no-real-anchor-network gate. It sits HERE — in the one
        // function of this workspace that hands a URL to `ureq` — rather
        // than in `send`, so that any future caller of `attempt` inherits it
        // without having to remember to. Refusal precedes resolution, so an
        // armed gate emits no DNS query, no TCP connection and no TLS
        // handshake. `offline` explains why the `cfg(test)` arm has no off
        // switch.
        if !request.endpoint.is_loopback_literal()
            && let Some(reason) = offline::deny_reason()
        {
            return Err(AnchorHttpError::RealNetworkDenied {
                endpoint: url.to_owned(),
                reason,
            });
        }

        let sent = match request.method {
            HttpMethod::Get => {
                let mut builder = self.agent.get(url);
                if let Some(value) = request.content_type {
                    builder = builder.header("Content-Type", value);
                }
                if let Some(value) = request.accept {
                    builder = builder.header("Accept", value);
                }
                builder.call()
            }
            HttpMethod::Post => {
                let mut builder = self.agent.post(url);
                if let Some(value) = request.content_type {
                    builder = builder.header("Content-Type", value);
                }
                if let Some(value) = request.accept {
                    builder = builder.header("Accept", value);
                }
                builder.send(request.body)
            }
        };

        let mut response = sent.map_err(|error| map_error(request, attempt, &error))?;
        let status = response.status().as_u16();

        if (300..400).contains(&status) {
            // The body is never read: a redirect is refused on its status
            // line, so a 3xx carrying a gigabyte cannot make us allocate one.
            let location = response
                .headers()
                .get("location")
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned);
            return Err(AnchorHttpError::Redirected {
                endpoint: url.to_owned(),
                status,
                location,
            });
        }

        if !(200..300).contains(&status) {
            // Deliberately NOT the success path's shape. `.limit()` errors,
            // it does not truncate, and a 500 with a 1 MiB body must still
            // produce `Status` rather than `OversizeBody` — so the read goes
            // through `Read::take`, which stops cleanly at the ceiling. The
            // `.limit()` here can never trip; it is belt to `take`'s braces.
            // Best-effort by design: a read failure yields a short body,
            // never an error that hides the status.
            let mut evidence = Vec::new();
            let _ = response
                .body_mut()
                .with_config()
                .limit(read_limit(HTTP_ERROR_BODY_CAP_BYTES))
                .reader()
                .take(HTTP_ERROR_BODY_CAP_BYTES)
                .read_to_end(&mut evidence);
            return Err(AnchorHttpError::Status {
                endpoint: url.to_owned(),
                status,
                body: evidence,
            });
        }

        let body = response
            .body_mut()
            .with_config()
            .limit(read_limit(request.receive_cap_bytes))
            .read_to_vec()
            .map_err(|error| map_error(request, attempt, &error))?;
        Ok(HttpResponse { status, body })
    }
}

/// D90 §6.3's left-hand column: which `ureq` outcome is which class.
///
/// Two of these mappings are counter-intuitive and were established by probe
/// rather than by reading doc comments:
///
/// - a refused connection arrives as `Error::Io(ConnectionRefused)`, not as
///   `Error::ConnectionFailed` (whose doc comment suggests otherwise), so the
///   pre-send class is read off `io::ErrorKind`. An implementation matching
///   only on `ConnectionFailed` would have written a retry rule that never
///   fires;
/// - `Error::BodyExceedsLimit` is **overloaded** — its own doc comment
///   describes the *send* side ("a send body … is larger than the
///   `content-length` header") while `limit.rs` raises it for the receive
///   side. We always send bodies of known length, so a send-side occurrence
///   is a programming error; the variant maps to the receive-side class.
fn map_error(request: &HttpRequest<'_>, attempt: u32, error: &ureq::Error) -> AnchorHttpError {
    let endpoint = request.endpoint.url().to_owned();
    let detail = error.to_string();
    match error {
        ureq::Error::HostNotFound => AnchorHttpError::Resolve {
            endpoint,
            attempts: attempt,
        },
        ureq::Error::ConnectionFailed => AnchorHttpError::Connect {
            endpoint,
            attempts: attempt,
            detail,
        },
        ureq::Error::Io(io) => match io.kind() {
            std::io::ErrorKind::ConnectionRefused
            | std::io::ErrorKind::HostUnreachable
            | std::io::ErrorKind::NetworkUnreachable => AnchorHttpError::Connect {
                endpoint,
                attempts: attempt,
                detail,
            },
            _ => AnchorHttpError::Transport { endpoint, detail },
        },
        ureq::Error::Timeout(phase) => match timeout_phase(*phase) {
            TimeoutSide::PreSend(phase) => AnchorHttpError::SendTimeout { endpoint, phase },
            TimeoutSide::Ambiguous(phase) => AnchorHttpError::ReceiveTimeout { endpoint, phase },
        },
        ureq::Error::Tls(_) | ureq::Error::TlsRequired | ureq::Error::Pem(_) => {
            AnchorHttpError::Tls { endpoint, detail }
        }
        ureq::Error::Rustls(_) => AnchorHttpError::Tls { endpoint, detail },
        ureq::Error::BodyExceedsLimit(_) => AnchorHttpError::OversizeBody {
            endpoint,
            cap_bytes: request.receive_cap_bytes,
        },
        ureq::Error::BadUri(_) => AnchorHttpError::InvalidEndpoint {
            endpoint,
            reason: "the HTTP client rejected the URI",
        },
        ureq::Error::RequireHttpsOnly(_) => AnchorHttpError::TlsRequired { endpoint },
        ureq::Error::Protocol(_)
        | ureq::Error::Http(_)
        | ureq::Error::LargeResponseHeader(_, _) => {
            AnchorHttpError::MalformedResponse { endpoint, detail }
        }
        // `StatusCode` cannot reach us — the agent sets
        // `http_status_as_error(false)`, asserted in
        // `the_agent_is_configured_exactly_as_d90_specifies`. If it ever
        // does, the configuration was lost and A14's body-carrying
        // discriminator went with it, so this is loud rather than a
        // plausible-looking `Status` with an empty body.
        ureq::Error::StatusCode(status) => AnchorHttpError::MalformedResponse {
            endpoint,
            detail: format!(
                "the client reported HTTP {status} as an error: the agent's \
                     http_status_as_error(false) setting was lost, and with it the \
                     non-2xx response body"
            ),
        },
        // Redirects are configured off, so these are unreachable; they are
        // mapped rather than ignored so a configuration regression still
        // produces a typed, non-retryable failure.
        ureq::Error::RedirectFailed | ureq::Error::TooManyRedirects => {
            AnchorHttpError::MalformedResponse { endpoint, detail }
        }
        _ => AnchorHttpError::Transport { endpoint, detail },
    }
}

/// Which side of the delivery boundary a `ureq` timeout phase sits on.
enum TimeoutSide {
    /// The request certainly had not been written yet.
    PreSend(&'static str),
    /// It may have been.
    Ambiguous(&'static str),
}

/// Name each `ureq` timeout phase, and place it relative to delivery.
///
/// # This placement is derived from `ureq`'s predecessor graph, not from the
/// phase names
///
/// A `Timeout(X)` does **not** mean "we were in phase X". It means "X's
/// deadline was the first to expire", and `next_timeout` checks the current
/// phase *plus its immediate predecessors*
/// (`ureq-3.3.0/src/timings.rs:63-68, 157-176`). So each phase can be
/// reported from any phase that lists it as a predecessor:
///
/// | reported | can be reported while in | request delivered? |
/// | --- | --- | --- |
/// | `Resolve`      | Resolve, Connect                       | no |
/// | `Connect`      | Connect, SendRequest                   | no — a partial request head is not actionable |
/// | `SendRequest`  | SendRequest, Await100, SendBody, **RecvResponse** | **unknown** |
/// | `SendBody`     | SendBody, **RecvResponse**             | **unknown** |
/// | `RecvResponse` | RecvResponse, RecvBody                 | yes |
/// | `RecvBody`     | RecvBody                               | yes |
///
/// `SendRequest` and `SendBody` are therefore **ambiguous**, however
/// send-shaped their names are: both can fire while awaiting a response to a
/// request the server already has in full. D90 §6.3's table places them in
/// the pre-send row, which — executed — retried a delivered calendar POST.
/// They are placed conservatively here, so the "never double-submit"
/// property holds no matter what the timeout constants are later changed to.
/// The cost is the safe one: a genuine send stall on an `AtMostOnceAfterSend`
/// request is not retried, i.e. a **missed** stamp rather than a duplicated
/// one, which is the direction A13 can already tolerate.
///
/// `Global` and `PerCall` are ambiguous for the reason D90 gives: they cannot
/// name a phase and they only fire when no single phase did.
fn timeout_phase(phase: ureq::Timeout) -> TimeoutSide {
    match phase {
        ureq::Timeout::Resolve => TimeoutSide::PreSend("resolve"),
        ureq::Timeout::Connect => TimeoutSide::PreSend("connect"),
        ureq::Timeout::SendRequest => TimeoutSide::Ambiguous("send-request"),
        ureq::Timeout::SendBody => TimeoutSide::Ambiguous("send-body"),
        ureq::Timeout::RecvResponse => TimeoutSide::Ambiguous("recv-response"),
        ureq::Timeout::RecvBody => TimeoutSide::Ambiguous("recv-body"),
        ureq::Timeout::Global => TimeoutSide::Ambiguous("global"),
        ureq::Timeout::PerCall => TimeoutSide::Ambiguous("per-call"),
        // `Await100` is documented as never escaping ureq, and the enum is
        // `#[non_exhaustive]`: anything unrecognised is treated as ambiguous,
        // which is the direction that cannot double-submit.
        _ => TimeoutSide::Ambiguous("unspecified"),
    }
}

#[cfg(test)]
mod tests;
