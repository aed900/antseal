//! The RFC 3161 TSA capture client (task **A10**; decisions D59, D60, D90),
//! plus the TSA-identity observable task **A31** ruled in.
//!
//! # Only a token that verifies in core counts
//!
//! A20's gate is the last check before irreversible spending, and its rule is
//! *≥ 1 verified TSA token or abort*. **Verified means verified in
//! `antseal-core`** — not `HTTP 200`, not `PKIStatus: granted`, not "the DER
//! parsed". Every capture below runs the full offline pipeline the eventual
//! bundle recipient will run:
//!
//! 1. [`antseal_core::anchor::tsa::verify_token`] (A8, stage T2) with the
//!    **expected nonce supplied** — the one path in the project where the
//!    comparison is reachable at all (D59 §1);
//! 2. [`antseal_core::anchor::chain::validate_token_chain`] (A9, stage T3)
//!    against the **pinned** root store;
//! 3. the resulting state must be headline-eligible.
//!
//! A token that fails any step is recorded as a failure with its own class
//! and contributes nothing to the gate. Nothing here re-implements a check:
//! this module builds requests, sends bytes, and calls core.
//!
//! # Where a nonce mismatch fires, exactly
//!
//! Inside [`capture_one`] → [`capture_from_tsas`] →
//! `submit_anchors` → [`AnchorGate::run`](crate::gate::AnchorGate::run),
//! which the seal pipeline invokes **after consent and strictly before
//! `pay`**. So a mismatched nonce subtracts that endpoint from the verified
//! count while the seal is still free; if it subtracts the last one, the gate
//! aborts with zero money spent. It is a payment-relevant outcome that can
//! never be a payment-*loss* outcome, because it cannot be reached after the
//! payment call.
//!
//! # No local clock decides anything (A32)
//!
//! The capture host that produced every committed fixture ran **129 s slow**
//! (D60/D59, measured against three unrelated hosts' HTTP `Date` headers
//! within one second of each other). The obvious sanity check — *"a timestamp
//! cannot be from the future, so reject if `gen_time > fetch_date`"* —
//! rejects every token in `testdata/anchors/A25-bootstrap/`, and would reject
//! real tokens on any user machine whose clock is behind by more than the
//! TSA's response latency.
//!
//! So: `fetch_date` is recorded as **provenance metadata and nothing else**,
//! and the chain is evaluated at `verify_at = genTime` — the token's own
//! statement — rather than at a locally-read instant. Two consequences worth
//! being explicit about:
//!
//! - the pre-payment gate's verdict does not depend on the host clock at all,
//!   which is the strongest available form of A32's rule;
//! - nothing is weakened by it. The alternative, `verify_at = now`, can only
//!   move a capture from `proven` to
//!   `valid-at-stamping-cert-since-expired` — both headline-eligible, both
//!   counting — because `verify_at` is one-sided and has no path to `invalid`
//!   (see [`antseal_core::anchor::chain`]).
//!
//! [`tests::a_fetch_date_before_gen_time_still_captures`] is the regression
//! test, driven by a real committed token.
//!
//! # One request per endpoint, concurrently
//!
//! `std::thread::scope`, mirroring [`crate::ots::submit::submit_to_calendars`]
//! — A10's *"one TSA's failure never aborts **or delays** the others"*. A51
//! will hoist one shared fan-out for A10/A13/A16/A17; when it lands only the
//! block in [`capture_from_tsas`] changes.
//!
//! # Minimum-interval caveats (Sectigo ~15 s, SwissSign ~10/day)
//!
//! Within one seal each *distinct* endpoint is contacted exactly once, so no
//! spacing rule can be violated by this stage — provided the list really is
//! distinct, which is why [`effective_tsa_urls`] deduplicates rather than
//! trusting the config to. Honouring a spacing rule **across** invocations
//! needs a persisted last-contact time, which is vault state this crate does
//! not have; recorded as owed work (U49) rather than faked here.

use std::time::{Duration, Instant};

use antseal_core::anchor::chain::{ChainFault, ChainVerdict, validate_token_chain};
use antseal_core::anchor::error::AnchorError;
use antseal_core::anchor::model::TsaCaptureRecord;
use antseal_core::anchor::request::{
    TSA_REQUEST_NONCE_LEN, build_timestamp_req, canonical_request_nonce,
};
use antseal_core::anchor::roots::TsaRootStore;
use antseal_core::anchor::tsa::{TsaSignerIdentity, verify_token};
use antseal_core::verify::report::AnchorState;

use crate::http::{
    AnchorHttpError, Endpoint, HttpClient, HttpMethod, HttpRequest, Idempotency,
    TSA_RESPONSE_CAP_BYTES, TlsPolicy,
};
use crate::nonce::{NonceUnavailable, draw_request_nonce};

/// The spec's two default TSAs (MVP-SPEC.md line 109, A10's `Do`).
///
/// DigiCert is **plain HTTP and must stay that way**: `timestamp.digicert.com`
/// has no port 443 at all (measured 2026-08-02T19:35:51Z, D90 §6.6), and
/// RFC 3161 tokens are signed and nonce-bound, so transport buys them nothing.
/// The asymmetry with esplora/RPC — where HTTPS is mandatory because the
/// replies are unsigned — is task A49's, enforced by the [`TlsPolicy`] the
/// [`crate::http::HttpPolicy::seal`] profile carries.
pub const DEFAULT_TSA_URLS: [&str; 2] =
    ["https://freetsa.org/tsr", "http://timestamp.digicert.com"];

/// The RFC 3161 request media type (RFC 3161 §3.4).
pub const TSA_REQUEST_CONTENT_TYPE: &str = "application/timestamp-query";

/// The RFC 3161 response media type, sent as `Accept`.
pub const TSA_RESPONSE_CONTENT_TYPE: &str = "application/timestamp-reply";

/// The effective TSA list: a config override replaces the defaults
/// **wholesale** (U26's semantics, matching [`crate::ots::calendars`]), an
/// absent or empty override falls back to [`DEFAULT_TSA_URLS`], and the
/// result is **deduplicated**.
///
/// Deduplication is not tidiness. Two identical entries would have this stage
/// send two requests to one TSA inside one second, which is exactly what the
/// documented spacing caveats forbid (Sectigo ~15 s), and would report two
/// verified tokens where a user holds one piece of evidence. A31 catches the
/// second half after the fact by counting signer certificates; this stops the
/// first half from happening.
///
/// The comparison is exact-string, deliberately: two spellings of one URL are
/// two endpoints as far as this list is concerned, and the *authoritative*
/// collapse is A31's, made on what the TSAs actually signed.
#[must_use]
pub fn effective_tsa_urls(config: Option<&[String]>) -> Vec<String> {
    let source: Vec<String> = match config {
        Some(list) if !list.is_empty() => list.to_vec(),
        _ => DEFAULT_TSA_URLS
            .iter()
            .map(|url| (*url).to_owned())
            .collect(),
    };
    let mut out: Vec<String> = Vec::with_capacity(source.len());
    for url in source {
        if !out.contains(&url) {
            out.push(url);
        }
    }
    out
}

/// Why one TSA contributed nothing toward the gate.
///
/// Four classes, because A10's Accept requires them to be distinguishable and
/// because they call for four different responses: a transport failure is
/// retryable and may be transient; a non-granted status is the TSA declining,
/// with its own reason; an unverifiable token is that TSA misbehaving *or*
/// something on the wire rewriting it; and an untrusted chain is a
/// well-formed token this build cannot anchor to a pinned root, which is a
/// configuration or root-store fact rather than an incident.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TsaFailure {
    /// Transport, timeout, non-2xx, redirect, over-cap. Carries the endpoint
    /// URL. The over-cap arm is A28's embeddability limit
    /// ([`TSA_RESPONSE_CAP_BYTES`] `== MAX_TSA_TOKEN_BYTES`): a token too
    /// large to embed is a seal that anchors and then cannot be revealed, so
    /// it is refused here rather than stored.
    #[error(transparent)]
    Http(#[from] AnchorHttpError),
    /// A well-formed `TimeStampResp` whose `PKIStatus` is not granted — the
    /// TSA declined. Distinct from [`TsaFailure::Token`] because the artifact
    /// is fine and the *answer* is no.
    #[error("{endpoint}: the TSA declined the request ({source})")]
    NotGranted {
        /// The TSA endpoint URL.
        endpoint: String,
        /// Core's typed status error, carrying the `PKIStatus` value.
        source: AnchorError,
    },
    /// A granted response that does not verify: malformed DER, a broken CMS
    /// signature, a `messageImprint` for another digest, a **nonce that does
    /// not match the one sent**, a rejected algorithm.
    ///
    /// A10's *"a granted-but-unverifiable token counts as a failure"*.
    #[error("{endpoint}: the token does not verify ({source})")]
    Token {
        /// The TSA endpoint URL.
        endpoint: String,
        /// Core's typed verification error, carrying its stable `anchor-`
        /// code.
        source: AnchorError,
    },
    /// The token verifies but its certificate chain does not reach a pinned
    /// root in a headline-eligible state — `internally-consistent-only`, or
    /// `invalid` with a named chain fault.
    ///
    /// It contributes **nothing** to the gate: MVP-SPEC.md line 137's
    /// property is that a gate-passing seal holds at least one anchor that
    /// renders with an independently proven time offline, and neither of
    /// these does.
    #[error("{endpoint}: the token verifies but does not chain to a pinned root ({state:?}{})",
        match fault { Some(f) => format!(", {}", f.code()), None => String::new() })]
    Untrusted {
        /// The TSA endpoint URL.
        endpoint: String,
        /// The state A9 reached.
        state: AnchorState,
        /// The chain fault, present exactly when `state` is `Invalid`.
        fault: Option<ChainFault>,
    },
}

impl TsaFailure {
    /// A one-word class name for the degradation report (the
    /// [`crate::ots::submit::CalendarFailure::class`] precedent).
    #[must_use]
    pub const fn class(&self) -> &'static str {
        match self {
            Self::Http(_) => "http",
            Self::NotGranted { .. } => "not-granted",
            Self::Token { .. } => "unverifiable",
            Self::Untrusted { .. } => "untrusted-chain",
        }
    }
}

/// One fully verified token, as captured.
///
/// Constructed **only** by [`capture_one`], and only after core has verified
/// the token and validated its chain to a pinned root — so the existence of
/// this value is the evidence A20's gate counts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TsaCapture {
    /// The endpoint this token came from, verbatim as configured.
    pub endpoint: String,
    /// The `TimeStampResp` exactly as received. This is what the vault
    /// stores and what F embeds in the bundle (registry §7.9 key 1 accepts
    /// the response shape; A36).
    pub token: Vec<u8>,
    /// The vault record U9 persists (A2's type): digest, endpoint, the nonce
    /// as sent, and the fetch date.
    pub record: TsaCaptureRecord,
    /// **Which TSA signed it** (A31) — the signer certificate's
    /// `(issuer, serialNumber)`. Two captures with equal identities are one
    /// anchor however many endpoints produced them.
    pub identity: TsaSignerIdentity,
    /// The token's `genTime`, POSIX seconds. Never compared to a clock.
    pub gen_time_unix: u64,
    /// The headline-eligible state A9 reached at `verify_at = genTime`.
    pub state: AnchorState,
    /// The pinned root the chain closed at.
    pub root_label: Option<&'static str>,
    /// The root-store version that produced the verdict (A6/A26).
    pub root_store_version: u32,
}

/// One TSA attempt, successful or not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TsaAttempt {
    /// The endpoint, verbatim as configured.
    pub endpoint: String,
    /// How long this endpoint's own exchange took. Recorded per endpoint so
    /// the concurrency guarantee is *observable* and not merely asserted.
    pub elapsed: Duration,
    /// The outcome.
    pub outcome: Result<TsaCapture, TsaFailure>,
}

/// Everything the TSA capture stage produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TsaCaptureStage {
    /// The digest every token stamps.
    pub anchor_digest: [u8; 32],
    /// Per-endpoint attempts, in the order the endpoints were given.
    pub attempts: Vec<TsaAttempt>,
}

impl TsaCaptureStage {
    /// The fully verified captures.
    pub fn verified(&self) -> impl Iterator<Item = &TsaCapture> {
        self.attempts
            .iter()
            .filter_map(|attempt| attempt.outcome.as_ref().ok())
    }

    /// How many endpoints produced a fully verified token.
    #[must_use]
    pub fn verified_count(&self) -> usize {
        self.verified().count()
    }

    /// How many **distinct TSAs** those tokens came from (**A31**).
    ///
    /// This is the number that describes the evidence. `verified_count` is
    /// the number of endpoints that answered, and the two differ whenever one
    /// TSA is reachable under two names — which is not hypothetical:
    /// `timestamp.entrust.net` is served by Sectigo, measured byte-identical
    /// (D60, 2026-08-02).
    #[must_use]
    pub fn distinct_tsas(&self) -> usize {
        let mut seen: Vec<&TsaSignerIdentity> = Vec::new();
        for capture in self.verified() {
            if !seen.contains(&&capture.identity) {
                seen.push(&capture.identity);
            }
        }
        seen.len()
    }

    /// Groups of endpoints that turned out to be **one** TSA, largest group
    /// first is not promised — order follows first appearance. Only groups of
    /// two or more are returned, so an ordinary seal yields an empty vector.
    #[must_use]
    pub fn collapsed_endpoints(&self) -> Vec<(String, Vec<String>)> {
        let mut groups: Vec<(&TsaSignerIdentity, Vec<String>)> = Vec::new();
        for capture in self.verified() {
            match groups
                .iter_mut()
                .find(|(identity, _)| *identity == &capture.identity)
            {
                Some((_, endpoints)) => endpoints.push(capture.endpoint.clone()),
                None => groups.push((&capture.identity, vec![capture.endpoint.clone()])),
            }
        }
        groups
            .into_iter()
            .filter(|(_, endpoints)| endpoints.len() > 1)
            .map(|(identity, endpoints)| (identity.label(), endpoints))
            .collect()
    }

    /// One line per failed endpoint — **the URL verbatim**, its failure
    /// class, the underlying message, and its elapsed time — plus one line
    /// per collapsed TSA group (A31).
    ///
    /// Verbatim is the requirement and not a preference: a summarising
    /// "1 TSA failed" is what this exists to make impossible, because the
    /// operator's next action is to look at *that URL*.
    #[must_use]
    pub fn degradation_report(&self) -> Vec<String> {
        let mut lines: Vec<String> = self
            .attempts
            .iter()
            .filter_map(|attempt| {
                attempt.outcome.as_ref().err().map(|failure| {
                    format!(
                        "{} [{}] {} ({} ms)",
                        attempt.endpoint,
                        failure.class(),
                        failure,
                        attempt.elapsed.as_millis()
                    )
                })
            })
            .collect();
        for (label, endpoints) in self.collapsed_endpoints() {
            lines.push(format!(
                "{} [one-tsa-two-endpoints] {} serve the same signer certificate ({label}) \
                 and count as ONE anchor, not {}",
                endpoints.join(" + "),
                endpoints.join(" and "),
                endpoints.len()
            ));
        }
        lines
    }
}

/// Capture a token from every endpoint in `endpoints`, concurrently.
///
/// `fetch_date` is the caller's POSIX-second reading, recorded as provenance
/// on every capture record. It is **not** a validity input (A32): no outcome
/// below is reachable from its value.
///
/// # Errors
///
/// [`NonceUnavailable`] if the OS CSPRNG fails. Every nonce is drawn **before
/// any request is sent**, so this failure mode is all-or-nothing: a machine
/// that cannot produce randomness sends no timestamp request at all rather
/// than sending some with fresh nonces and some with whatever a fallback
/// produced.
pub fn capture_from_tsas(
    client: &HttpClient,
    anchor_digest: &[u8; 32],
    endpoints: &[String],
    store: &TsaRootStore,
    fetch_date: u64,
) -> Result<TsaCaptureStage, NonceUnavailable> {
    let nonces: Vec<[u8; TSA_REQUEST_NONCE_LEN]> = endpoints
        .iter()
        .map(|_| draw_request_nonce())
        .collect::<Result<_, _>>()?;

    let attempts: Vec<TsaAttempt> = std::thread::scope(|scope| {
        let handles: Vec<_> = endpoints
            .iter()
            .zip(&nonces)
            .map(|(endpoint, nonce)| {
                scope.spawn(move || {
                    let started = Instant::now();
                    let outcome =
                        capture_one(client, anchor_digest, endpoint, nonce, store, fetch_date);
                    TsaAttempt {
                        endpoint: endpoint.clone(),
                        elapsed: started.elapsed(),
                        outcome,
                    }
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|handle| match handle.join() {
                Ok(attempt) => attempt,
                // A panic here is a bug in this crate, never an endpoint
                // failure: laundering it into a `TsaFailure` would make a
                // broken verifier look like a dead TSA.
                Err(panic) => std::panic::resume_unwind(panic),
            })
            .collect()
    });

    Ok(TsaCaptureStage {
        anchor_digest: *anchor_digest,
        attempts,
    })
}

/// One TSA: build the request, POST it, and verify the reply in core.
///
/// The nonce arrives as a parameter rather than being drawn here, for the
/// same reason [`build_timestamp_req`] takes one (D59 §4): it makes this
/// function deterministic, so a test can drive it against a **recorded real
/// token** whose nonce is a fixed committed value.
///
/// # Errors
///
/// [`TsaFailure`], one class per A10 Accept row.
pub fn capture_one(
    client: &HttpClient,
    anchor_digest: &[u8; 32],
    endpoint: &str,
    nonce: &[u8; TSA_REQUEST_NONCE_LEN],
    store: &TsaRootStore,
    fetch_date: u64,
) -> Result<TsaCapture, TsaFailure> {
    // `TlsPolicy::Optional` — the RFC 3161 family's profile (D90 §6.6, A49).
    let parsed = Endpoint::parse(endpoint, TlsPolicy::Optional)
        .map_err(|error| TsaFailure::Http(error.into()))?;

    let body = build_timestamp_req(anchor_digest, nonce);
    let request = HttpRequest {
        endpoint: &parsed,
        method: HttpMethod::Post,
        content_type: Some(TSA_REQUEST_CONTENT_TYPE),
        accept: Some(TSA_RESPONSE_CONTENT_TYPE),
        body: &body,
        // A28: `== MAX_TSA_TOKEN_BYTES`, so a token that could not afterwards
        // be embedded is refused at capture rather than at reveal.
        receive_cap_bytes: TSA_RESPONSE_CAP_BYTES,
        // A TSA mints a signed token and charges it against a rate limit, so
        // a request that may already have been delivered must not be re-sent.
        // D90's placement is derived from ureq's predecessor graph, not from
        // phase names — the finding that a naive ladder retried a *delivered*
        // POST is exactly this hazard.
        idempotency: Idempotency::AtMostOnceAfterSend,
    };
    let token = client.send(&request).map_err(TsaFailure::Http)?.body;

    // T2 — A8, with the expected nonce supplied. This is the only call site in
    // the project that passes `Some`.
    //
    // **The comparison operand is the CANONICAL form, not the drawn bytes.**
    // `check_nonce` compares the token's DER INTEGER *content octets* with
    // whatever is handed to it, byte for byte — it normalises nothing, and it
    // must not, since normalising an adversary's encoding is how a strict-DER
    // parser stops being one. The drawn value is 8 raw bytes; what goes on the
    // wire and what the TSA echoes is `canonical_request_nonce`, which prepends
    // `0x00` when the top bit is set and strips leading zeroes otherwise. The
    // two forms differ for **half of all draws**, so passing `nonce` here would
    // reject roughly every second real token as `anchor-tsa-nonce-mismatch` and
    // abort the seal before payment. Not a money-loss defect — the gate fails
    // closed — but a product that works half the time.
    //
    // The committed FreeTSA fixture cannot catch it (its nonce is `0x4C…`, top
    // bit clear, so both forms coincide); the Sectigo fixture (`0xE4…`) can, and
    // `tests::the_nonce_operand_is_the_canonical_der_form_not_the_drawn_bytes`
    // drives both.
    let expected_nonce = canonical_request_nonce(nonce);
    let verified = verify_token(&token, anchor_digest, Some(&expected_nonce)).map_err(
        |source| match source {
            AnchorError::StatusNotGranted { .. } => TsaFailure::NotGranted {
                endpoint: endpoint.to_owned(),
                source,
            },
            other => TsaFailure::Token {
                endpoint: endpoint.to_owned(),
                source: other,
            },
        },
    )?;

    // T3 — A9, at the token's own `genTime`. See the module docs for why the
    // local clock is not the verification time here.
    let gen_time_unix = verified.gen_time_unix();
    let verdict: ChainVerdict = validate_token_chain(&verified, &[], store, gen_time_unix);
    if !verdict.headline_eligible() {
        return Err(TsaFailure::Untrusted {
            endpoint: endpoint.to_owned(),
            state: verdict.state(),
            fault: verdict.fault(),
        });
    }

    let identity = verified
        .signer_identity()
        .map_err(|source| TsaFailure::Token {
            endpoint: endpoint.to_owned(),
            source,
        })?;

    Ok(TsaCapture {
        endpoint: endpoint.to_owned(),
        token,
        record: TsaCaptureRecord {
            anchor_digest: *anchor_digest,
            endpoint: endpoint.to_owned(),
            request_nonce: *nonce,
            fetch_date,
        },
        identity,
        gen_time_unix,
        state: verdict.state(),
        root_label: verdict.anchor_label(),
        root_store_version: verdict.root_store_version(),
    })
}

#[cfg(test)]
#[path = "tsa/tests.rs"]
mod tests;
