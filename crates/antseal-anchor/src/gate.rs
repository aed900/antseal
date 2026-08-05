//! The pre-pay **anchor gate** interface and the M1 zero-anchor seal
//! contract (task A1; interface locus per D34 Decision 2: defined on the
//! A side, consumed by the `antseal_cli` pipeline library).
//!
//! # The zero-anchor seal contract (M1, normative)
//!
//! With `--no-anchor` (dev-only; MVP-SPEC.md line 149) the
//! anchor-submission step is a **no-op producing an empty anchor set**:
//!
//! - no OTS calendar submission, no TSA request, no anchor policy — the
//!   gate is [`NoAnchorGate`] and performs zero network I/O (S13's
//!   accept asserts no submission call ever happens in this mode);
//! - the seal is representable in every format as **UNANCHORED**: the
//!   manifest/bundle anchor sections are empty (F13's
//!   `empty-anchor-unanchored` golden vector is exactly this shape);
//! - at verify time every anchor slot evaluates `absent`, and the
//!   aggregate has **zero headline-eligible anchors** —
//!   `antseal_core::verify::aggregate` (A1's core half) reports it
//!   `is_unanchored()`, which the M1 E2E consumes (spec line 154).
//!
//! # The mainnet rejection rule (MUST — the contract U wires)
//!
//! **`--no-anchor` combined with `--network arbitrum-one` MUST be
//! rejected before any anchor submission, quote, or payment.** A
//! permanent, paid-for mainnet seal must never be mintable with the
//! anchor gate bypassed. Enforcement is layered and owned elsewhere —
//! this crate states the rule but cannot enforce it (network identity is
//! S5's; CLI flags are U's):
//!
//! - **CLI level**: U13's `seal` wiring rejects the combination
//!   (U-domain test; cross-referenced by A1's accept);
//! - **pipeline level, defense in depth**: S13 rejects it inside the
//!   library pipeline with a distinct error and zero network side
//!   effects, so the CLI check cannot be bypassed by driving the
//!   library directly (S13's accept row).
//!
//! # Gate ordering (S12)
//!
//! The pipeline runs the gate **strictly before `pay`**: consent → the
//! anchor gate → `pay`. A gate failure aborts the seal with **zero money
//! spent** — every cheap failable step precedes the one irreversible
//! paid step (MVP-SPEC.md line 34's order; S12's fault barriers assert
//! it). Pipeline tests drive the abort path with a test double of
//! [`AnchorGate`] returning [`AnchorGateError`].
//!
//! # What arrives at M2 (deliberately absent here)
//!
//! A20 implements the real gate behind this same interface — OTS
//! submissions first, then TSA captures, then the pure decision
//! `evaluate_seal_gate`: proceed iff ≥ 1 TSA token passed full core
//! verification, `--force-degraded` converting the abort into
//! proceed-with-degradation — and A2 models the artifact/capture types
//! in `antseal-core`. [`AnchorSubmissionOutcome`] is `#[non_exhaustive]`
//! precisely so A20 can add the populated arm without breaking the M1
//! consumers, and building any of that machinery now is out of A1's
//! scope by instruction.
//!
//! # What arrived at M2 (task A20)
//!
//! [`crate::submit`] holds the orchestrator and the pure decision
//! [`evaluate_seal_gate`](crate::submit::evaluate_seal_gate);
//! [`SubmitAnchorGate`](crate::submit::SubmitAnchorGate) is the real
//! implementation of this interface. The types this module gained for it are
//! [`AnchorSubmissionOutcome::Submitted`], the three new
//! [`AnchorGateError`] arms, and [`AnchorEndpointFailure`].

use crate::submit::AnchorSubmission;

/// What the anchor-submission step produced.
///
/// M1 (A1): only the empty outcome exists — the `--no-anchor` seal.
/// M2 (A20/A2) adds the populated arm carrying real artifacts and the
/// degradation report; the enum is `#[non_exhaustive]` for exactly that
/// growth.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AnchorSubmissionOutcome {
    /// The `--no-anchor` **empty anchor set** (A1): no submission was
    /// attempted, there is nothing to persist to the vault, the
    /// manifest/bundle anchor sections stay empty, and every verify-side
    /// anchor slot evaluates `absent` — the UNANCHORED aggregate.
    Empty,
    /// A20's populated arm: anchors were submitted and the gate let the seal
    /// proceed. Boxed because the submission carries whole tokens and a
    /// merged `.ots`, and the `Empty` arm must stay free.
    Submitted(Box<AnchorSubmission>),
}

impl AnchorSubmissionOutcome {
    /// Whether this outcome carries no anchors at all.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        matches!(self, Self::Empty)
    }

    /// The submission, when there was one.
    #[must_use]
    pub const fn submission(&self) -> Option<&AnchorSubmission> {
        match self {
            Self::Empty => None,
            Self::Submitted(submission) => Some(submission),
        }
    }
}

/// Which half of the anchor stage an endpoint failure came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AnchorStage {
    /// An OpenTimestamps calendar submit (A13).
    Ots,
    /// An RFC 3161 TSA capture (A10).
    Tsa,
}

impl AnchorStage {
    /// The label used in the abort error and the degradation report.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Ots => "ots",
            Self::Tsa => "tsa",
        }
    }
}

/// One endpoint's failure, as it appears **verbatim** in A20's typed abort
/// error and in the degradation report.
///
/// `class` is not restated here — it comes from the underlying typed error's
/// own `class()` method ([`crate::tsa::TsaFailure::class`],
/// [`crate::ots::submit::CalendarFailure::class`]), so a new failure variant
/// cannot acquire a wrong label by being forgotten in a second table. `detail`
/// is the typed error's `Display`, which is what makes "verbatim" checkable:
/// the endpoint URL is inside it as well as beside it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorEndpointFailure {
    /// Which half of the stage.
    pub stage: AnchorStage,
    /// The endpoint URL, exactly as configured.
    pub endpoint: String,
    /// The failure class, from the typed error.
    pub class: &'static str,
    /// The typed error's own message.
    pub detail: String,
    /// How long this endpoint's exchange took.
    pub elapsed_millis: u128,
}

impl core::fmt::Display for AnchorEndpointFailure {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{} {} [{}] {} ({} ms)",
            self.stage.label(),
            self.endpoint,
            self.class,
            self.detail,
            self.elapsed_millis
        )
    }
}

/// The pre-pay anchor gate refused the seal.
///
/// Constructible today so S12's pipeline tests can drive the abort path
/// with a failing gate double; `#[non_exhaustive]` so A20 (M2) can add
/// structured per-endpoint failure data without breaking matches.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum AnchorGateError {
    /// The minimum-anchor policy was not met and the seal must abort —
    /// before any payment (S12 ordering). Kept from M1 as the free-form
    /// arm the pipeline's own test doubles construct; A20's real gate emits
    /// [`AnchorGateError::MinimumAnchor`], which carries the failures.
    #[error("anchor gate refused the seal: {detail}")]
    PolicyNotMet {
        /// Human-readable summary of why the gate refused.
        detail: String,
    },
    /// **A20's abort.** Zero TSA endpoints produced a token that verified in
    /// core, and `--force-degraded` was not given. Every per-endpoint failure
    /// is carried verbatim, because the operator's next action is to look at
    /// *those URLs*.
    #[error(
        "the minimum-anchor policy was not met: 0 of {attempted} TSA endpoint(s) \
         produced a verified token, so nothing was paid for.\n{}\n\
         Re-run when an endpoint recovers, or pass --force-degraded to seal with a \
         loudly recorded degraded anchor set.",
        failures.iter().map(ToString::to_string).collect::<Vec<_>>().join("\n")
    )]
    MinimumAnchor {
        /// How many TSA endpoints were attempted.
        attempted: usize,
        /// Every endpoint failure from both halves of the stage, in stage
        /// order (OTS first, then TSA), each verbatim.
        failures: Vec<AnchorEndpointFailure>,
    },
    /// `--no-anchor` on a permanent (paid, mainnet) network. The rule is
    /// stated in this module's docs and enforced at the CLI (U13) and library
    /// (S13) layers before a gate is even chosen; this arm is the third,
    /// innermost layer, so driving the gate directly cannot bypass it.
    #[error(
        "--no-anchor cannot be used on a permanent network: a paid, permanent seal \
         must never be mintable with the anchor gate bypassed"
    )]
    NoAnchorOnPermanentNetwork,
    /// The OS CSPRNG is unavailable, so no timestamp request could be built.
    ///
    /// Its own arm, and deliberately: "this machine cannot produce randomness"
    /// must never be triaged as "the TSAs are down". No request was sent.
    #[error(transparent)]
    Entropy(#[from] crate::nonce::NonceUnavailable),
}

/// The injected pre-pay anchor-gate step (D34 Decision 2: defined here
/// on the A side; `antseal_cli`'s pipeline consumes it generically and
/// `antseal-anchor` never learns the pipeline exists).
///
/// `anchor_digest` is the manifest-identity digest the anchors bind —
/// SHA-256 over the **full manifest bytes, signatures included**
/// (MVP-SPEC.md line 75), taken by value: 32 bytes, no secret material.
///
/// # Contract
///
/// - Runs strictly **before** `pay`; `Err` aborts the seal with zero
///   money spent (module docs).
/// - `Ok(outcome)` hands the pipeline whatever was anchored;
///   [`AnchorSubmissionOutcome::Empty`] is the `--no-anchor` path and
///   must involve **no** submission I/O.
///
/// # `async fn` / object safety (same argument as
/// `antseal_net::StorageBackend`)
///
/// Native `async fn` (the M2 gate performs network submissions), so the
/// trait is not dyn-compatible; the single consumer is generic over the
/// injected gate, futures need no `Send` bound (the pipeline awaits
/// them inline). Widening either is a deliberate A-domain event.
#[allow(async_fn_in_trait)] // dyn-compatibility deliberately traded away; rationale above.
pub trait AnchorGate {
    /// Run the pre-pay anchor step for the seal whose `anchor_digest`
    /// is given.
    ///
    /// # Errors
    ///
    /// [`AnchorGateError`] — the seal must abort before any payment.
    async fn run(
        &self,
        anchor_digest: [u8; 32],
    ) -> Result<AnchorSubmissionOutcome, AnchorGateError>;
}

/// The `--no-anchor` skip gate (A1): a no-op producing the empty anchor
/// set. Performs no submission, no I/O, and cannot fail.
///
/// **Never inject this on `arbitrum-one`** — the mainnet rejection rule
/// (module docs) must have already fired at the CLI (U13) and pipeline
/// (S13) layers before a gate is even chosen.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NoAnchorGate;

impl AnchorGate for NoAnchorGate {
    async fn run(
        &self,
        _anchor_digest: [u8; 32],
    ) -> Result<AnchorSubmissionOutcome, AnchorGateError> {
        Ok(AnchorSubmissionOutcome::Empty)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;
    use std::pin::pin;
    use std::task::{Context, Poll, Waker};

    /// Minimal std-only executor (same hand-rolled shape the S2 note
    /// sanctions for `antseal-net`; this crate has no dep edge to reuse
    /// it from there, and no runtime dep is wanted before M2 needs one).
    fn block_on<F: Future>(future: F) -> F::Output {
        let mut context = Context::from_waker(Waker::noop());
        let mut future = pin!(future);
        loop {
            match future.as_mut().poll(&mut context) {
                Poll::Ready(output) => return output,
                Poll::Pending => std::thread::yield_now(),
            }
        }
    }

    #[test]
    fn no_anchor_gate_is_a_noop_producing_the_empty_set() {
        let outcome = block_on(NoAnchorGate.run([0xA5; 32])).expect("skip gate cannot fail");
        assert_eq!(outcome, AnchorSubmissionOutcome::Empty);
        assert!(outcome.is_empty());
    }

    /// The abort path is drivable through the trait — the shape S12's
    /// pipeline tests rely on for "anchor-gate failure aborts before
    /// pay with no EVM tx".
    #[test]
    fn a_refusing_gate_double_surfaces_the_typed_abort() {
        struct RefusingGate;
        impl AnchorGate for RefusingGate {
            async fn run(
                &self,
                _anchor_digest: [u8; 32],
            ) -> Result<AnchorSubmissionOutcome, AnchorGateError> {
                Err(AnchorGateError::PolicyNotMet {
                    detail: "0 TSA tokens verified".into(),
                })
            }
        }
        let err = block_on(RefusingGate.run([0; 32])).expect_err("gate refuses");
        match &err {
            AnchorGateError::PolicyNotMet { detail } => {
                assert_eq!(detail, "0 TSA tokens verified");
            }
            other => panic!("the M1 double must keep emitting the M1 arm: {other:?}"),
        }
        assert!(err.to_string().contains("refused the seal"));
    }
}
