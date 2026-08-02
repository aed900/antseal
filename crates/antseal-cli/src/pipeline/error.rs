//! The pipeline's typed failure set, and the fault-injection barriers the
//! kill/resume matrices drive it through.
//!
//! # Why a pipeline error type at all
//!
//! [`CliError`] is the *exit-code* surface (U2's frozen table): many
//! distinct pipeline failures deliberately share one code, because a user
//! remedies them the same way. The pipeline needs the opposite —
//! per-failure-class distinctness so S13's "distinct error", S11's
//! abandon/proofs-expired states, and S16's matrix can each assert the
//! exact thing that happened. [`SealError`] is that type; the
//! `From<SealError> for CliError` conversion is the one place the
//! many-to-one collapse happens, and it mints **no new exit class**.

use antseal_anchor::AnchorGateError;
use antseal_core::crypto::error::CryptoError;
use antseal_core::manifest::ManifestError;
use antseal_net::{MAX_CHUNK_SIZE, StorageError};

use super::journal::{JournalError, StagedBytesUnavailable};
use crate::error::{CliError, ConsentOutcome, ResumeSafetyReason};

/// A named step boundary of the seal pipeline.
///
/// Every barrier is a point at which a real process can die, and each is
/// individually reachable in tests through a [`BarrierHook`] — that is what
/// makes S16's mock matrix and S18's devnet matrix able to kill
/// *deterministically* rather than by timing.
///
/// The variants are in **execution order**. (S12's accept row lists the
/// same set unordered; the normative sequence is the one in S12's `Do`:
/// staged bytes are journaled before the quote, not after.)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Barrier {
    /// Plan validation passed: the argument checks and D32's per-blob
    /// chunk-cap check are done and nothing has been written, submitted,
    /// or quoted.
    PostPlanValidation,
    /// Every staged blob and the plan record are durable — the
    /// journal-before-anything-irreversible barrier.
    PostStagingJournal,
    /// `quote_batch` returned. **This is D49's truncation barrier**:
    /// `--dry-run` is the pipeline stopped exactly here, not a parallel
    /// mode.
    PostQuote,
    /// The consent hook returned an affirmative answer and the consent
    /// record is journaled.
    PostConsent,
    /// The anchor gate returned (or was skipped in `--no-anchor` mode).
    /// After this point a failure is no longer free.
    PostAnchor,
    /// `pay` returned and the receipt is **not yet journaled** — the one
    /// window where money has moved and nothing records it.
    ///
    /// In production this window is empty: with the default
    /// [`NoBarriers`] hook nothing at all executes between `pay`'s return
    /// and the journal write, so the barrier compiles to a call that
    /// cannot fail. It exists as a *named* point so S16 can assert the
    /// window is exactly one statement wide instead of taking it on
    /// trust.
    PostPayPreReceiptJournal,
    /// The receipt is durable and `finalize_batch` has not been called —
    /// the crash window the whole pay/finalize split exists for. Resume
    /// from here never pays again.
    PostReceiptJournalPreFinalize,
    /// `finalize_batch` returned `Ok` and the work is **not yet marked
    /// complete**. Resume from here re-finalizes idempotently.
    ///
    /// This is the half of "mid-finalize" the pipeline owns. The other
    /// half — dying after `k` of `n` blobs were stored, *inside* one
    /// `finalize_batch` call — is not the pipeline's to subdivide; it is
    /// `MockBackend`'s `AfterStoringK(k)` fault on the mock side and a
    /// real SIGKILL on the devnet side (S18).
    PostFinalizePreComplete,
}

impl Barrier {
    /// Every barrier, in execution order (the exhaustiveness anchor S16's
    /// "one test per barrier" row counts against).
    pub const ALL: [Self; 8] = [
        Self::PostPlanValidation,
        Self::PostStagingJournal,
        Self::PostQuote,
        Self::PostConsent,
        Self::PostAnchor,
        Self::PostPayPreReceiptJournal,
        Self::PostReceiptJournalPreFinalize,
        Self::PostFinalizePreComplete,
    ];

    /// Stable kebab identifier for diagnostics and test names.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::PostPlanValidation => "post-plan-validation",
            Self::PostStagingJournal => "post-staging-journal",
            Self::PostQuote => "post-quote",
            Self::PostConsent => "post-consent",
            Self::PostAnchor => "post-anchor",
            Self::PostPayPreReceiptJournal => "post-pay-pre-receipt-journal",
            Self::PostReceiptJournalPreFinalize => "post-receipt-journal-pre-finalize",
            Self::PostFinalizePreComplete => "post-finalize-pre-complete",
        }
    }

    /// Whether money has already moved when this barrier is reached — the
    /// property S16's no-double-pay rows partition on.
    #[must_use]
    pub const fn is_post_pay(self) -> bool {
        matches!(
            self,
            Self::PostPayPreReceiptJournal
                | Self::PostReceiptJournalPreFinalize
                | Self::PostFinalizePreComplete
        )
    }
}

/// The injected kill switch the fault matrices drive.
///
/// Production injects [`NoBarriers`], whose implementation is a `const`
/// `Ok(())` — the barriers cost nothing when nobody is killing anything.
pub trait BarrierHook {
    /// Called as the pipeline crosses `barrier`. Returning `Err` aborts
    /// the invocation exactly there, leaving whatever the barrier's
    /// contract says is durable.
    ///
    /// # Errors
    ///
    /// [`SealError::KilledAtBarrier`] in the test harnesses; production
    /// never errors.
    fn at(&self, barrier: Barrier) -> Result<(), SealError>;
}

/// The production barrier hook: nothing is ever injected.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NoBarriers;

impl BarrierHook for NoBarriers {
    fn at(&self, _barrier: Barrier) -> Result<(), SealError> {
        Ok(())
    }
}

/// Everything the seal pipeline can fail with — one variant per failure
/// class the design distinguishes.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SealError {
    /// **S13's defense-in-depth guard**: `--no-anchor` was combined with
    /// `arbitrum-one`. Refused before any quote, anchor submission or
    /// payment — so no permanent, paid-for mainnet seal can ever be minted
    /// with the anchor gate bypassed, even by a caller driving the library
    /// directly past U13's CLI check.
    #[error(
        "--no-anchor cannot be used on arbitrum-one: a permanent, paid-for mainnet seal must \
         never be minted with the anchor gate bypassed (nothing was quoted, anchored, paid, or \
         uploaded); use --network devnet or arbitrum-sepolia for zero-anchor development seals"
    )]
    NoAnchorOnMainnet,

    /// **D32's plan-time cap**, checked before consent, before the anchor
    /// gate and before `quote_batch` — because the client would otherwise
    /// quote and *pay* for a chunk the network cannot store.
    #[error(
        "a blob of this work would be {projected_len} bytes, over the {MAX_CHUNK_SIZE}-byte \
         Autonomi chunk limit ({subject}){}: nothing was quoted, anchored, paid, or uploaded",
        if *.split_hint {
            " — pass `--split blank-lines` to divide this text file into paragraph units"
        } else {
            " — files this large are not supported in v1"
        }
    )]
    BlobExceedsChunkCap {
        /// Which blob (`file 2, unit 7` / `the encrypted manifest`).
        subject: String,
        /// Projected ciphertext length in bytes.
        projected_len: u64,
        /// Whether `--split` could fix it (an over-cap *text* file).
        split_hint: bool,
    },

    /// The work names no files at all.
    #[error("a seal needs at least one file")]
    EmptyWork,

    /// The consent gate did not produce an affirmative answer. **D36 rule
    /// 3**: on a resume this leaves the work `incomplete` — declining is
    /// never abandonment, and no state transition is written.
    #[error("{}", CliError::ConsentNotObtained { reason: *.0 })]
    ConsentDeclined(ConsentOutcome),

    /// The pre-pay anchor gate refused the seal — aborted with **zero
    /// money spent** (S12's ordering guarantee).
    #[error(transparent)]
    AnchorGate(#[from] AnchorGateError),

    /// **D37 Decision 6 / D36 rule 2**: the journaled payment proofs have
    /// outlived the ~24 h node-side validity window. The payment is
    /// stranded; completing the seal needs a fresh, separately consented
    /// payment. Surfaced distinctly so it can never happen silently.
    #[error(
        "this seal's payment proofs have expired (the ~24 h node-side window has passed), so \
         the storers reject them: completing it requires a new, separately consented payment — \
         the already-spent ANT is not recoverable"
    )]
    ProofsExpired,

    /// The staged bytes are unavailable: the seal is **abandoned**, any
    /// payment forfeited, and a fresh seal must start with a new `seal_id`
    /// and freshly drawn nonces (S11; the journaled nonce table is never
    /// reused).
    #[error("{0}")]
    StagedBytes(StagedBytesUnavailable),

    /// The work is in a state this operation cannot act on (resuming a
    /// complete work, finalizing an abandoned one).
    #[error("this work is {state} and cannot be resumed")]
    NotResumable {
        /// The work's current state, by name.
        state: &'static str,
    },

    /// A resume found no journaled plan — the work never finished staging,
    /// so there is nothing to re-upload.
    #[error("this work has no journaled seal plan; nothing was staged to resume from")]
    NothingStaged,

    /// A fault barrier fired (test harnesses only; never in production,
    /// where [`NoBarriers`] cannot fail).
    #[error("pipeline killed at the {} barrier (fault injection)", .0.name())]
    KilledAtBarrier(Barrier),

    /// The storage backend failed.
    #[error(transparent)]
    Storage(#[from] StorageError),

    /// The journal failed.
    #[error(transparent)]
    Journal(#[from] JournalError),

    /// A crypto primitive failed (RNG failure, essentially).
    #[error(transparent)]
    Crypto(#[from] CryptoError),

    /// The manifest could not be built or encoded.
    #[error(transparent)]
    Manifest(#[from] ManifestError),

    /// The consent hook itself failed (no channel, TTY error) — distinct
    /// from a decline.
    #[error(transparent)]
    Consent(Box<CliError>),
}

impl From<StagedBytesUnavailable> for SealError {
    fn from(reason: StagedBytesUnavailable) -> Self {
        SealError::StagedBytes(reason)
    }
}

impl From<SealError> for CliError {
    fn from(err: SealError) -> Self {
        match err {
            // Plan-validation failures are argument problems: every
            // offending input is named, pre-consent, pre-anchor, pre-quote.
            SealError::NoAnchorOnMainnet
            | SealError::BlobExceedsChunkCap { .. }
            | SealError::EmptyWork => CliError::InvalidSealArgument {
                problems: vec![err.to_string()],
            },
            SealError::ConsentDeclined(reason) => CliError::ConsentNotObtained { reason },
            SealError::AnchorGate(_) => CliError::AnchorGateAbort,
            // Both are "resume cannot safely proceed" — one exit code,
            // distinguishing messages (the U2 table's own pattern).
            SealError::StagedBytes(_) => CliError::ResumeSafetyAbort {
                reason: ResumeSafetyReason::StagedBytesMissing,
            },
            SealError::ProofsExpired
            | SealError::NotResumable { .. }
            | SealError::NothingStaged => CliError::Usage {
                message: err.to_string(),
            },
            SealError::KilledAtBarrier(_) => CliError::Internal {
                detail: err.to_string(),
            },
            SealError::Storage(inner) => storage_to_cli(inner),
            SealError::Journal(inner) => inner.into(),
            SealError::Crypto(inner) => CliError::Internal {
                detail: inner.to_string(),
            },
            SealError::Manifest(inner) => CliError::Internal {
                detail: inner.to_string(),
            },
            SealError::Consent(inner) => *inner,
        }
    }
}

/// The storage boundary's classes mapped onto U2's exit codes. The two
/// shortfalls stay distinct all the way to the exit code — the user
/// remedies them differently (acquire ANT vs bridge ETH), which is why the
/// spec separates them at all.
fn storage_to_cli(err: StorageError) -> CliError {
    match err {
        StorageError::InsufficientAnt {
            required_atto,
            available_atto,
        } => CliError::InsufficientAntToken {
            required_atto,
            available_atto,
        },
        StorageError::InsufficientGas {
            required_wei,
            available_wei,
        } => CliError::InsufficientEthGas {
            required_wei,
            available_wei,
        },
        StorageError::ProofsExpired => CliError::Usage {
            message: SealError::ProofsExpired.to_string(),
        },
        other => CliError::NetworkFailure {
            detail: other.to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ErrorClass;

    #[test]
    fn barrier_names_are_unique_and_ordered() {
        let mut names: Vec<&str> = Barrier::ALL.iter().map(|b| b.name()).collect();
        let count = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), count, "barrier names must be unique");
        assert_eq!(count, 8, "S12 names eight step boundaries");
    }

    /// The post-pay partition S16's no-double-pay rows depend on.
    #[test]
    fn exactly_the_three_post_pay_barriers_are_post_pay() {
        let post_pay: Vec<&str> = Barrier::ALL
            .iter()
            .filter(|b| b.is_post_pay())
            .map(|b| b.name())
            .collect();
        assert_eq!(
            post_pay,
            vec![
                "post-pay-pre-receipt-journal",
                "post-receipt-journal-pre-finalize",
                "post-finalize-pre-complete"
            ]
        );
    }

    /// The pipeline mints **no new exit class**: every `SealError` lands on
    /// a class that already existed in U2's frozen table.
    #[test]
    fn every_seal_error_maps_onto_an_existing_exit_class() {
        let samples = [
            SealError::NoAnchorOnMainnet,
            SealError::BlobExceedsChunkCap {
                subject: "file 0, unit 0".to_owned(),
                projected_len: 5_000_000,
                split_hint: true,
            },
            SealError::EmptyWork,
            SealError::ConsentDeclined(ConsentOutcome::Declined),
            SealError::AnchorGate(AnchorGateError::PolicyNotMet {
                detail: "0 TSA tokens".to_owned(),
            }),
            SealError::ProofsExpired,
            SealError::StagedBytes(StagedBytesUnavailable::Missing),
            SealError::NotResumable { state: "complete" },
            SealError::NothingStaged,
            SealError::KilledAtBarrier(Barrier::PostQuote),
            SealError::Storage(StorageError::InsufficientAnt {
                required_atto: 10,
                available_atto: 1,
            }),
            SealError::Storage(StorageError::InsufficientGas {
                required_wei: 10,
                available_wei: 1,
            }),
            SealError::Storage(StorageError::Network {
                reason: "unreachable".to_owned(),
            }),
        ];
        for err in samples {
            let rendered = err.to_string();
            let cli: CliError = err.into();
            assert!(ErrorClass::ALL.contains(&cli.class()));
            assert!(!rendered.is_empty());
        }
    }

    /// The two shortfalls must never collapse into one another (the spec
    /// separates them because the remedies differ).
    #[test]
    fn the_two_shortfalls_stay_distinct_to_the_exit_code() {
        let ant: CliError = SealError::Storage(StorageError::InsufficientAnt {
            required_atto: 10,
            available_atto: 1,
        })
        .into();
        let gas: CliError = SealError::Storage(StorageError::InsufficientGas {
            required_wei: 10,
            available_wei: 1,
        })
        .into();
        assert_eq!(ant.class(), ErrorClass::InsufficientAntToken);
        assert_eq!(gas.class(), ErrorClass::InsufficientEthGas);
        assert_ne!(ant.exit_code(), gas.exit_code());
    }

    /// S13's guard is a *distinct* error, not a generic usage failure, and
    /// its message says nothing was spent.
    #[test]
    fn the_mainnet_no_anchor_guard_is_distinct_and_says_nothing_was_spent() {
        let rendered = SealError::NoAnchorOnMainnet.to_string();
        assert!(rendered.contains("--no-anchor"));
        assert!(rendered.contains("arbitrum-one"));
        assert!(rendered.contains("nothing was quoted, anchored, paid, or uploaded"));
    }

    /// D32's over-cap message names `--split` for a text file and does not
    /// for a binary one.
    #[test]
    fn the_over_cap_message_names_split_only_for_text() {
        let text = SealError::BlobExceedsChunkCap {
            subject: "file 0, unit 0".to_owned(),
            projected_len: 5_000_000,
            split_hint: true,
        }
        .to_string();
        assert!(text.contains("--split blank-lines"));

        let binary = SealError::BlobExceedsChunkCap {
            subject: "file 1, unit 3".to_owned(),
            projected_len: 5_000_000,
            split_hint: false,
        }
        .to_string();
        assert!(!binary.contains("--split"));
        assert!(binary.contains("not supported in v1"));
    }
}
