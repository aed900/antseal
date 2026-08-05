//! The anchor submission orchestrator and the **minimum-anchor seal gate**
//! (task **A20**; decisions D54 §3, D59, D90; interface locus D34).
//!
//! # This is the last check before irreversible spending
//!
//! The seal pipeline's order is `consent → anchor gate → pay`
//! (`antseal_cli::pipeline::resume::consent_anchor_pay`, MVP-SPEC.md line 34,
//! S12's fault barriers). Everything before `pay` is free to fail; `pay` is
//! not. So the rule this module implements is the one that decides whether
//! money moves at all:
//!
//! > **Proceed iff at least one TSA token passed full core verification.
//! > Otherwise abort — before any payment.**
//!
//! "Passed full core verification" is not "HTTP 200", not "`PKIStatus:
//! granted`", and not "the CMS signature checked out". It is
//! [`crate::tsa::TsaCapture`], a value that can only exist after A8's token
//! verification *and* A9's path validation to a **pinned** root reached a
//! headline-eligible state. A `.sealproof` whose only TSA anchor renders
//! `internally-consistent-only` carries no independently proven time, and
//! MVP-SPEC.md line 137's guarantee — a normal seal never renders UNANCHORED
//! offline — would be false for it.
//!
//! # OTS never gates, and never fails silently
//!
//! D54 §3: at seal time an OTS anchor is `pending`, `pending` is not
//! headline-eligible, so gating a paid irreversible seal on it would trade a
//! permanent cost for zero evidentiary gain. Total OTS failure produces a
//! degradation report naming every failed endpoint verbatim and proceeds.
//!
//! # Order: OTS first, then TSA
//!
//! MVP-SPEC.md line 34's own order, and it is not arbitrary. The OTS submits
//! are the ones that can be re-issued later at no cost if the gate then
//! aborts; a TSA capture consumes a rate-limited request whose spacing
//! caveats are real (Sectigo ~15 s). Doing the abortable-and-cheap half first
//! keeps a failed gate from having burned the scarcer resource.
//!
//! # `--no-anchor` and `--force-degraded`
//!
//! - `--no-anchor` skips submission entirely and produces
//!   [`AnchorSubmissionOutcome::Empty`] — and is **refused on a permanent
//!   network**, here as the third and innermost of three layers (U13's CLI
//!   check, S13's library check, this one). A gate cannot be bypassed by
//!   driving the library directly.
//! - `--force-degraded` converts the abort into proceed-with-degradation. It
//!   never *adds* evidence and never suppresses a report line; it only
//!   changes an abort into a loud proceed.
//!
//! # Why this crate does not learn what network it is on
//!
//! Network identity is S5's (`antseal_net::NetworkId`), and `antseal-anchor`
//! has no reason to know arbitrum-one from arbitrum-sepolia. The gate needs
//! exactly one bit — *is this a permanent, paid seal* — so it takes
//! [`NetworkClass`] and the caller maps. Anything finer would be a second
//! place where network identity is defined.

use antseal_core::anchor::roots::TsaRootStore;

use crate::gate::{
    AnchorEndpointFailure, AnchorGate, AnchorGateError, AnchorStage, AnchorSubmissionOutcome,
};
use crate::http::HttpClient;
use crate::nonce::NonceUnavailable;
use crate::ots::calendars::effective_calendars;
use crate::ots::submit::{OtsSubmission, OtsSubmitOutcome, submit_to_calendars};
use crate::tsa::{TsaCaptureStage, capture_from_tsas, effective_tsa_urls};

/// The endpoints one seal's anchor stage will contact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorEndpoints {
    /// RFC 3161 TSAs (A10). Deduplicated by [`effective_tsa_urls`].
    pub tsa_urls: Vec<String>,
    /// OpenTimestamps calendars (A13).
    pub ots_calendars: Vec<String>,
}

impl AnchorEndpoints {
    /// The built-in defaults for both families.
    #[must_use]
    pub fn defaults() -> Self {
        Self::from_config(None, None)
    }

    /// Apply U4/U26's config overrides. An absent or empty override falls
    /// back to that family's defaults; a present one replaces them wholesale.
    #[must_use]
    pub fn from_config(tsa_urls: Option<&[String]>, ots_calendars: Option<&[String]>) -> Self {
        Self {
            tsa_urls: effective_tsa_urls(tsa_urls),
            ots_calendars: effective_calendars(ots_calendars),
        }
    }
}

/// Everything one seal's anchor stage produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorSubmission {
    /// The digest every anchor commits.
    pub anchor_digest: [u8; 32],
    /// The OTS half (A13). Never gates.
    pub ots: OtsSubmission,
    /// The TSA half (A10). The gate reads only this.
    pub tsa: TsaCaptureStage,
}

impl AnchorSubmission {
    /// How many TSA endpoints produced a token that passed **full core
    /// verification**. This is the number the gate compares against 1.
    #[must_use]
    pub fn verified_tsa_count(&self) -> usize {
        self.tsa.verified_count()
    }

    /// How many **distinct TSAs** those tokens came from (A31).
    ///
    /// Always `<= verified_tsa_count`, and strictly less whenever one TSA
    /// answered on two endpoints. The gate's threshold is unchanged by this
    /// number — A31 is explicit that it changes reporting and any future ≥2
    /// policy, not today's abort rule — but every report that describes the
    /// evidence must use it, because "2 anchors" and "2 endpoints" are
    /// different claims.
    #[must_use]
    pub fn distinct_tsas(&self) -> usize {
        self.tsa.distinct_tsas()
    }

    /// Whether this seal is degraded in any way a report must say out loud:
    /// a failed endpoint anywhere, fewer than D54's two distinct calendars,
    /// or two endpoints that collapsed to one TSA.
    #[must_use]
    pub fn is_degraded(&self) -> bool {
        !self.degradation_report().is_empty()
            || self.ots.outcome() != OtsSubmitOutcome::Complete
            || self.verified_tsa_count() == 0
    }

    /// Every per-endpoint failure, typed, in stage order (OTS then TSA).
    #[must_use]
    pub fn endpoint_failures(&self) -> Vec<AnchorEndpointFailure> {
        let ots = self.ots.attempts.iter().filter_map(|attempt| {
            attempt
                .outcome
                .as_ref()
                .err()
                .map(|failure| AnchorEndpointFailure {
                    stage: AnchorStage::Ots,
                    endpoint: attempt.calendar.clone(),
                    class: failure.class(),
                    detail: failure.to_string(),
                    elapsed_millis: attempt.elapsed.as_millis(),
                })
        });
        let tsa = self.tsa.attempts.iter().filter_map(|attempt| {
            attempt
                .outcome
                .as_ref()
                .err()
                .map(|failure| AnchorEndpointFailure {
                    stage: AnchorStage::Tsa,
                    endpoint: attempt.endpoint.clone(),
                    class: failure.class(),
                    detail: failure.to_string(),
                    elapsed_millis: attempt.elapsed.as_millis(),
                })
        });
        ots.chain(tsa).collect()
    }

    /// The human-readable degradation report: every failed endpoint verbatim
    /// from both halves, plus A31's collapse lines, plus the counts.
    ///
    /// Empty exactly when nothing needs saying.
    #[must_use]
    pub fn degradation_report(&self) -> Vec<String> {
        let mut lines: Vec<String> = self
            .ots
            .degradation_report()
            .into_iter()
            .map(|line| format!("{} {line}", AnchorStage::Ots.label()))
            .collect();
        lines.extend(
            self.tsa
                .degradation_report()
                .into_iter()
                .map(|line| format!("{} {line}", AnchorStage::Tsa.label())),
        );
        if !lines.is_empty() {
            let verified = self.verified_tsa_count();
            let distinct = self.distinct_tsas();
            lines.push(format!(
                "tsa: {verified} verified token(s) from {distinct} distinct TSA(s); \
                 ots: {} distinct calendar(s)",
                self.ots.distinct_calendars()
            ));
        }
        lines
    }
}

/// Whether a seal on this network is permanent and paid for.
///
/// One bit, by design — see the module docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NetworkClass {
    /// arbitrum-one: real money, permanent storage. `--no-anchor` is refused.
    Permanent,
    /// devnet or a testnet: `--no-anchor` is a legitimate dev shortcut.
    Development,
}

/// The seal-shaping flags the gate reads (U22 wires them).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SealGateFlags {
    /// `--no-anchor`: skip submission entirely (dev only).
    pub no_anchor: bool,
    /// `--force-degraded`: proceed even with zero verified TSA tokens.
    pub force_degraded: bool,
}

/// What the gate decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealGateDecision {
    /// At least one TSA token verified. `degraded` says whether the report
    /// still has something to say out loud.
    Proceed {
        /// Whether anything in the stage needs reporting loudly.
        degraded: bool,
    },
    /// Zero verified TSA tokens, but `--force-degraded` was given. The seal
    /// proceeds and its anchor set is recorded as degraded.
    ProceedDegraded,
    /// `--no-anchor` on a development network: the empty anchor set.
    SkipUnanchored,
}

/// **The pure gate decision.** No I/O, no clock, no allocation beyond the
/// failure list it copies into an abort.
///
/// `submission` is `None` exactly when no submission was attempted — the
/// `--no-anchor` path, or a caller that could not get that far. Treating
/// `None` as "zero verified tokens" is deliberate: the failure direction of
/// this function must be *refuse*, so an absent submission can never be a
/// reason to proceed.
///
/// # Errors
///
/// - [`AnchorGateError::NoAnchorOnPermanentNetwork`] — checked **first**, and
///   before anything else can turn it into a proceed.
/// - [`AnchorGateError::MinimumAnchor`] — zero verified tokens without
///   `--force-degraded`, carrying every per-endpoint failure verbatim.
pub fn evaluate_seal_gate(
    submission: Option<&AnchorSubmission>,
    flags: SealGateFlags,
    network: NetworkClass,
) -> Result<SealGateDecision, AnchorGateError> {
    if flags.no_anchor {
        // Rule 1, and first: `--force-degraded` must not be able to buy a
        // mainnet seal with the anchor gate bypassed. Ordering these two the
        // other way round would let it.
        if network == NetworkClass::Permanent {
            return Err(AnchorGateError::NoAnchorOnPermanentNetwork);
        }
        return Ok(SealGateDecision::SkipUnanchored);
    }

    let verified = submission.map_or(0, AnchorSubmission::verified_tsa_count);
    if verified >= MIN_VERIFIED_TSA_TOKENS {
        return Ok(SealGateDecision::Proceed {
            degraded: submission.is_some_and(AnchorSubmission::is_degraded),
        });
    }
    if flags.force_degraded {
        return Ok(SealGateDecision::ProceedDegraded);
    }
    Err(AnchorGateError::MinimumAnchor {
        attempted: submission.map_or(0, |s| s.tsa.attempts.len()),
        failures: submission
            .map(AnchorSubmission::endpoint_failures)
            .unwrap_or_default(),
    })
}

/// The minimum-anchor threshold (MVP-SPEC.md lines 19, 34, 137).
///
/// **One**, and A31 does not change it: two endpoints collapsing to one TSA
/// still clears a threshold of one. The constant is named so that a future
/// ≥2 policy is a one-line change *and* so that a reader can see the gate is
/// counting [`AnchorSubmission::verified_tsa_count`] rather than
/// `attempts.len()` — registry §8's obligation (A40) applied at the only
/// place it can currently bite.
pub const MIN_VERIFIED_TSA_TOKENS: usize = 1;

/// Run both halves of the anchor stage: OTS calendar submits first, then TSA
/// captures (MVP-SPEC.md line 34's order).
///
/// # Errors
///
/// [`NonceUnavailable`] if the OS CSPRNG fails — no TSA request is sent at
/// all in that case. The OTS half has already run and its result is
/// discarded, which is correct: a pending `.ots` for a seal that will now
/// abort costs the calendars nothing and commits this project to nothing.
pub fn submit_anchors(
    client: &HttpClient,
    anchor_digest: &[u8; 32],
    endpoints: &AnchorEndpoints,
    store: &TsaRootStore,
    fetch_date: u64,
) -> Result<AnchorSubmission, NonceUnavailable> {
    let ots = submit_to_calendars(client, anchor_digest, &endpoints.ots_calendars);
    let tsa = capture_from_tsas(
        client,
        anchor_digest,
        &endpoints.tsa_urls,
        store,
        fetch_date,
    )?;
    Ok(AnchorSubmission {
        anchor_digest: *anchor_digest,
        ots,
        tsa,
    })
}

/// The real pre-pay anchor gate (A20) behind A1's frozen interface.
///
/// Injected by the seal pipeline in place of
/// [`NoAnchorGate`](crate::gate::NoAnchorGate). Holds the flags rather than
/// taking them per call, because [`AnchorGate::run`]'s signature is frozen —
/// `anchor_digest` and nothing else.
#[derive(Debug, Clone)]
pub struct SubmitAnchorGate<'a> {
    client: &'a HttpClient,
    endpoints: &'a AnchorEndpoints,
    store: &'a TsaRootStore,
    flags: SealGateFlags,
    network: NetworkClass,
    fetch_date: Option<u64>,
}

impl<'a> SubmitAnchorGate<'a> {
    /// Build the gate. `store` is [`TsaRootStore::pinned`] in every
    /// production path; the parameter exists so A24's injected test store can
    /// drive the same code (A6's Accept).
    #[must_use]
    pub const fn new(
        client: &'a HttpClient,
        endpoints: &'a AnchorEndpoints,
        store: &'a TsaRootStore,
        flags: SealGateFlags,
        network: NetworkClass,
    ) -> Self {
        Self {
            client,
            endpoints,
            store,
            flags,
            network,
            fetch_date: None,
        }
    }

    /// Pin the `fetch_date` recorded on every capture instead of reading the
    /// host clock.
    ///
    /// Safe to expose, and the reason is A32: `fetch_date` is provenance
    /// metadata that gates no outcome anywhere, so no verdict can be changed
    /// by overriding it. That is also why the override is *needed* — a
    /// deterministic test must be able to fix it, and a value that could
    /// change a verdict would make such a test a lie.
    #[must_use]
    pub const fn with_fetch_date(mut self, fetch_date: u64) -> Self {
        self.fetch_date = Some(fetch_date);
        self
    }

    /// POSIX seconds, saturating at 0 before the epoch. Recorded, never
    /// compared (A32).
    fn now_unix(&self) -> u64 {
        self.fetch_date.unwrap_or_else(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |since| since.as_secs())
        })
    }
}

impl AnchorGate for SubmitAnchorGate<'_> {
    async fn run(
        &self,
        anchor_digest: [u8; 32],
    ) -> Result<AnchorSubmissionOutcome, AnchorGateError> {
        if self.flags.no_anchor {
            // The pipeline skips the gate entirely under `--no-anchor`
            // (`run_anchor_gate`), so arriving here with the flag set means a
            // caller drove the gate directly. Evaluate the rule anyway — the
            // mainnet refusal must not be reachable around — and submit
            // nothing either way.
            evaluate_seal_gate(None, self.flags, self.network)?;
            return Ok(AnchorSubmissionOutcome::Empty);
        }

        let submission = submit_anchors(
            self.client,
            &anchor_digest,
            self.endpoints,
            self.store,
            self.now_unix(),
        )?;
        evaluate_seal_gate(Some(&submission), self.flags, self.network)?;
        Ok(AnchorSubmissionOutcome::Submitted(Box::new(submission)))
    }
}

#[cfg(test)]
#[path = "submit/tests.rs"]
mod tests;
