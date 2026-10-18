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
    /// money spent** (S12's ordering guarantee). It carries the refused
    /// work's seal-id beside the gate's own error (D194), because the CLI
    /// message names the command that discards that work.
    #[error(transparent)]
    AnchorGate(GateRefusal),

    // `ProofsExpired` lived here from S11 until **D147/U81**. Nothing ever
    // constructed it — the reachable expiry is
    // `StorageError::ProofsExpired`, which `resume` intercepts once
    // (`resume.rs:274`) and otherwise hands to `storage_to_cli` — and its
    // sentence was borrowed by that mapping purely for its text, which is
    // how the one message in the product containing *"the already-spent ANT
    // is not recoverable"* came to exit 2. D147 R3 moved the sentence to
    // `CliError::PaymentProofsExpired` (code 29) and R4 removed the variant,
    // on this crate's own precedent for `AnchorStageUnavailable`
    // (`crate::error`, the comment where it stood): *"an error nothing can
    // produce is a claim about the product that no test can falsify."*
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

    /// **S37 (D186)**: money moved and the vault could not record what it
    /// bought. The most recent receipt capture of this payment did not
    /// become durable, and then either `pay` failed mid-sequence or the
    /// post-`pay` receipt write failed too. A re-run would buy again
    /// whatever the vault does not show as paid, which is why this is never
    /// `payment-stranded` (28), whose re-run is safe.
    ///
    /// Built only by `consent_anchor_pay`, from
    /// [`SealJournal::receipts_unrecorded`](super::journal::SealJournal::receipts_unrecorded).
    #[error(
        "{}",
        CliError::PaymentUnrecorded {
            landed_tx_count: *.landed_tx_count,
            fault: ToString::to_string(.fault),
            detail: Clone::clone(.detail),
        }
    )]
    PaymentUnrecorded {
        /// Sub-batch transactions this payment landed.
        landed_tx_count: usize,
        /// Why the most recent capture did not become durable (paths and
        /// I/O classes only, never receipt content).
        fault: super::receipt_sink::ReceiptSinkFault,
        /// What failed after it: the storage layer's stranded-payment
        /// reason, or the post-`pay` receipt write's own error.
        detail: String,
    },

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

/// A refusal of the pre-pay anchor gate, with the work it refused (D194).
///
/// The gate knows nothing of works, so its error ([`AnchorGateError`]) cannot
/// name one. The pipeline does, and pairs the two where it calls the gate
/// (`resume.rs`'s `run_anchor_gate`). The seal-id is what the CLI's abort
/// message hands to `antseal abandon` (D185): an identifier every resume
/// message already prints, not a secret.
#[derive(Debug, thiserror::Error)]
#[error("{error}")]
pub struct GateRefusal {
    /// The refused work, which is left staged.
    pub seal_id: antseal_core::crypto::secrets::SealId,
    /// The gate's own refusal, unchanged.
    pub error: AnchorGateError,
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
            SealError::AnchorGate(refusal) => CliError::AnchorGateAbort {
                failures: gate_refusal_lines(&refusal.error),
                seal_id: crate::status::hex_seal(&refusal.seal_id),
            },
            // Both are "resume cannot safely proceed" — one exit code,
            // distinguishing messages (the U2 table's own pattern).
            SealError::StagedBytes(_) => CliError::ResumeSafetyAbort {
                reason: ResumeSafetyReason::StagedBytesMissing,
            },
            SealError::NotResumable { .. } | SealError::NothingStaged => CliError::Usage {
                message: err.to_string(),
            },
            SealError::KilledAtBarrier(_) => CliError::Internal {
                detail: err.to_string(),
            },
            SealError::Storage(inner) => storage_to_cli(inner),
            SealError::PaymentUnrecorded {
                landed_tx_count,
                fault,
                detail,
            } => CliError::PaymentUnrecorded {
                landed_tx_count,
                fault: fault.to_string(),
                detail,
            },
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

/// `TsaFailure::Untrusted`'s class (`antseal-anchor`'s `tsa.rs`), compared by
/// value because the anchor crate exports no constant for it;
/// `the_untrusted_chain_class_is_the_tsa_failures_own` pins the two equal.
const UNTRUSTED_CHAIN: &str = "untrusted-chain";

/// What an `untrusted-chain` entry adds (D194 R1): that endpoint answered,
/// so "wait for it" is advice that would never work.
const NEVER_COUNTS: &str = "a token that does not chain to a root antseal pins never counts \
                            toward the gate (docs/user/timestamp-authorities.md §1)";

/// **U97 (D194 R1)**: what the abort message says failed. There is one entry
/// per failed endpoint, each in the gate's own verbatim form
/// (`{stage} {endpoint} [{class}] {detail} ({ms} ms)`, `gate.rs`), so its
/// class is named and a TSA trust state appears by its frozen name.
///
/// The gate's other arms carry no endpoint list, so their own sentence is
/// the one entry.
fn gate_refusal_lines(error: &AnchorGateError) -> Vec<String> {
    match error {
        AnchorGateError::MinimumAnchor {
            attempted,
            failures,
        } => {
            if failures.is_empty() {
                return vec![format!(
                    "0 of {attempted} TSA endpoint(s) produced a verified token"
                )];
            }
            failures
                .iter()
                .map(|failure| {
                    if failure.class == UNTRUSTED_CHAIN {
                        format!("{failure} — {NEVER_COUNTS}")
                    } else {
                        failure.to_string()
                    }
                })
                .collect()
        }
        other => vec![other.to_string()],
    }
}

/// The storage boundary's classes mapped onto U2's exit codes.
///
/// The distinction this map exists to keep is **four-way**, not two-way
/// (**D147**). Two of the four are the shortfalls found *before* anything is
/// paid — `insufficient-ant-token` (20) and `insufficient-eth-gas` (21) —
/// which stay distinct all the way to the exit code because the user
/// remedies them differently (acquire ANT vs bridge ETH). The other two are
/// the outcomes where money has **already moved**: `payment-stranded` (28)
/// and `payment-proofs-expired` (29). Everything else here is the transient
/// class (23), which is the one a caller is right to retry — and that is
/// exactly why 28 and 29 must never wear it.
///
/// The third money-moved class, `payment-unrecorded` (37, D186), is not
/// minted here: whether the receipt is durable is the journal's knowledge,
/// not the storage error's, so `consent_anchor_pay` decides it and builds
/// [`SealError::PaymentUnrecorded`] before a stranded payment reaches this
/// map.
fn storage_to_cli(err: StorageError) -> CliError {
    // D147: wildcard-free, the discipline `antseal_net::live::fetch_failure_class`
    // already applies to this enum. `StorageError` is not `#[non_exhaustive]`, so a
    // tenth variant is `error[E0004]` here rather than a silent exit 23 — which is
    // how `StrandedPayment` came to share a code with a peer timeout.
    //
    // Every transport arm below binds the WHOLE error and renders it with
    // `to_string()`, exactly as the catch-all did. Destructuring to
    // `{ reason }` and forwarding `reason` alone would look equivalent and is
    // not: it drops each variant's own `#[error(...)]` prefix, so
    // "quote collection failed: <r>" would silently become "<r>" in four
    // shipped messages. `the_transport_arms_keep_the_storage_errors_own_prefix`
    // is the guard.
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
        // D147 R2: money moved. The sentence the catch-all already forwarded
        // was right; only the two-word prefix and the machine identity behind
        // it were wrong.
        StorageError::StrandedPayment {
            landed_tx_count,
            reason,
        } => CliError::PaymentStranded {
            landed_tx_count,
            detail: reason,
        },
        // D147 R3: money moved, and completing the seal costs a second,
        // separately consented payment. Exited 2 — clap's own parse-error
        // code — until this class existed.
        StorageError::ProofsExpired => CliError::PaymentProofsExpired,
        // quoting precedes consent and payment: no money is at risk, retry is right.
        err @ StorageError::Quote { .. } => CliError::NetworkFailure {
            detail: err.to_string(),
        },
        // by its own definition, "before any transaction landed" — nothing moved.
        err @ StorageError::Payment { .. } => CliError::NetworkFailure {
            detail: err.to_string(),
        },
        // finalize issues no payment and is idempotent with the journaled receipt.
        err @ StorageError::Finalize { .. } => CliError::NetworkFailure {
            detail: err.to_string(),
        },
        // transport by definition; this is the class 23 is named for.
        err @ StorageError::Network { .. } => CliError::NetworkFailure {
            detail: err.to_string(),
        },
        // D147 §1.3: unreachable from this pipeline — `NotFound` is produced only
        // by `get_data`, which the seal/resume pipeline never calls, and whose three
        // callers stringify at the call site. Written out rather than left to a
        // wildcard so the day someone wires a fetch into this pipeline is a
        // deliberate review, not a silent inheritance. Rendered through
        // `to_string()` like the rest, so the address text has exactly one spelling.
        err @ StorageError::NotFound { .. } => CliError::NetworkFailure {
            detail: err.to_string(),
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

    /// The conversion mints **no exit class of its own**: every `SealError`
    /// lands on a class of U2's table, which grows only by a decision
    /// (D147's 28 and 29, D186's 37).
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
            SealError::AnchorGate(GateRefusal {
                seal_id: antseal_core::crypto::secrets::SealId::from_bytes([0x5E; 16]),
                error: AnchorGateError::PolicyNotMet {
                    detail: "0 TSA tokens".to_owned(),
                },
            }),
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
            // D147's two money-moved classes. They replace the sample that
            // used to be `SealError::ProofsExpired` — a variant nothing
            // constructed, so the row proved only that a dead type mapped
            // somewhere.
            SealError::Storage(StorageError::StrandedPayment {
                landed_tx_count: 1,
                reason: "a payment sub-batch transaction reverted on-chain".to_owned(),
            }),
            SealError::Storage(StorageError::ProofsExpired),
            // D186's third money-moved class.
            SealError::PaymentUnrecorded {
                landed_tx_count: 1,
                fault: crate::pipeline::receipt_sink::ReceiptSinkFault::Encode,
                detail: "a payment sub-batch transaction reverted on-chain".to_owned(),
            },
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

    /// **D147 R5's guard.** Making `storage_to_cli` wildcard-free replaced one
    /// `other => … other.to_string()` arm with five named ones, and the
    /// obvious spelling of those arms — `StorageError::Quote { reason } => …
    /// detail: reason` — compiles just as happily while silently dropping
    /// each variant's own `#[error(...)]` prefix. That would turn
    /// *"quote collection failed: r"* into *"r"* in four shipped messages and
    /// nothing else in the suite would notice: the display snapshot's
    /// `network-failure` exemplars are built from `CliError::NetworkFailure`
    /// directly and never travel through this function.
    ///
    /// So the rendering is asserted **against the storage error's own
    /// `Display`**, which R11 forbids rewording — one string, written once,
    /// compared where it is consumed.
    #[test]
    fn the_transport_arms_keep_the_storage_errors_own_prefix() {
        let transport = [
            StorageError::Quote {
                reason: "r".to_owned(),
            },
            StorageError::Payment {
                reason: "r".to_owned(),
            },
            StorageError::Finalize {
                reason: "r".to_owned(),
            },
            StorageError::Network {
                reason: "r".to_owned(),
            },
            StorageError::NotFound {
                address: antseal_net::Address::from([0xaa; 32]),
            },
        ];
        assert_eq!(transport.len(), 5, "D147 R6 rules exactly five arms at 23");
        for err in transport {
            let storage_rendering = err.to_string();
            // Cannot pass vacuously: the storage rendering must carry a
            // prefix of its own to lose, and the two halves must differ.
            assert!(
                storage_rendering.contains(": ") || storage_rendering.contains(" at "),
                "{storage_rendering}: no prefix for this test to protect"
            );
            let cli: CliError = SealError::Storage(err).into();
            assert_eq!(cli.class(), ErrorClass::NetworkFailure);
            assert_eq!(
                cli.to_string(),
                format!("network failure: {storage_rendering}"),
                "an arm dropped the storage error's own `#[error(...)]` prefix"
            );
        }
    }

    /// **D147**: the two outcomes where ANT has already left the wallet are
    /// each their own class, and neither is the transient one a caller
    /// retries. Asserted at this seam as well as at the exit code
    /// (`tests/seal_matrix.rs`), because this `From` impl is the only route
    /// from the storage boundary to a code.
    #[test]
    fn the_two_money_moved_errors_never_wear_the_transient_class() {
        let stranded: CliError = SealError::Storage(StorageError::StrandedPayment {
            landed_tx_count: 2,
            reason: "a payment sub-batch transaction reverted on-chain".to_owned(),
        })
        .into();
        let expired: CliError = SealError::Storage(StorageError::ProofsExpired).into();

        assert_eq!(stranded.class(), ErrorClass::PaymentStranded);
        assert_eq!(stranded.exit_code(), 28);
        assert_eq!(expired.class(), ErrorClass::PaymentProofsExpired);
        assert_eq!(expired.exit_code(), 29);

        let transient = ErrorClass::NetworkFailure.exit_code();
        assert_ne!(stranded.exit_code(), transient, "23 is the retry-me code");
        assert_ne!(expired.exit_code(), transient, "23 is the retry-me code");
        // 2 is clap's own parse-error code, which is where `ProofsExpired`
        // used to land: a wrapper cannot tell that from a typo.
        assert_ne!(expired.exit_code(), ErrorClass::Usage.exit_code());
    }

    /// **D186**: a payment the vault could not record is the third
    /// money-moved class, and it is none of the codes a wrapper might act on
    /// blindly — not 28 (whose re-run is safe), not 23 (retry), not 4 (an
    /// I/O error that never mentions money). Its message carries both facts
    /// the class exists for: the count that landed, and why the record
    /// failed.
    #[test]
    fn an_unrecorded_payment_is_its_own_money_moved_class() {
        let fault = crate::pipeline::receipt_sink::ReceiptSinkFault::Write {
            detail: "work store I/O failure at /v/store/works/w/receipt: disk full".to_owned(),
        };
        let cli: CliError = SealError::PaymentUnrecorded {
            landed_tx_count: 3,
            fault: fault.clone(),
            detail: "a payment sub-batch transaction reverted on-chain".to_owned(),
        }
        .into();

        assert_eq!(cli.class(), ErrorClass::PaymentUnrecorded);
        assert_eq!(cli.exit_code(), 37);
        for blind in [
            ErrorClass::PaymentStranded,
            ErrorClass::NetworkFailure,
            ErrorClass::IoError,
        ] {
            assert_ne!(cli.exit_code(), blind.exit_code(), "{}", blind.name());
        }
        let message = cli.to_string();
        assert!(
            message.contains(" 3 sub-batch transaction(s) landed"),
            "{message}"
        );
        assert!(message.contains(&format!("({fault})")), "{message}");
        assert!(message.contains("instead of passing --yes"), "{message}");
    }

    /// The CLI recognises an `untrusted-chain` entry by the class string the
    /// anchor crate's own `TsaFailure::class` returns. This pins the two
    /// equal, so a respelled class cannot silently drop the "never counts"
    /// note.
    #[test]
    fn the_untrusted_chain_class_is_the_tsa_failures_own() {
        let failure = antseal_anchor::tsa::TsaFailure::Untrusted {
            endpoint: "http://127.0.0.1:1/".to_owned(),
            state: antseal_core::verify::report::AnchorState::InternallyConsistentOnly,
            fault: None,
        };
        assert_eq!(failure.class(), UNTRUSTED_CHAIN);
    }

    /// **U97 (D194 R1)** at the conversion: every failed endpoint is named
    /// with its class, the trust state appears by its frozen name, only the
    /// `untrusted-chain` entry carries the "never counts" note, and the way
    /// forward names this work's seal-id. Built from the anchor crate's real
    /// failure values, as `submit.rs` builds them.
    #[test]
    fn a_gate_refusal_names_each_failed_endpoint_and_the_staged_work() {
        use antseal_anchor::gate::{AnchorEndpointFailure, AnchorStage};
        use antseal_anchor::tsa::TsaFailure;

        let entry = |endpoint: &str, failure: TsaFailure| AnchorEndpointFailure {
            stage: AnchorStage::Tsa,
            endpoint: endpoint.to_owned(),
            class: failure.class(),
            detail: failure.to_string(),
            elapsed_millis: 7,
        };
        let down = "http://127.0.0.1:1/";
        let unpinned = "http://127.0.0.1:2/";
        let failures = vec![
            entry(
                down,
                TsaFailure::Http(antseal_anchor::AnchorHttpError::Status {
                    endpoint: down.to_owned(),
                    status: 503,
                    body: b"offline".to_vec(),
                }),
            ),
            entry(
                unpinned,
                TsaFailure::Untrusted {
                    endpoint: unpinned.to_owned(),
                    state: antseal_core::verify::report::AnchorState::InternallyConsistentOnly,
                    fault: None,
                },
            ),
        ];
        assert_eq!(failures.len(), 2, "anti-vacuity: two endpoints failed");
        let cli: CliError = SealError::AnchorGate(GateRefusal {
            seal_id: antseal_core::crypto::secrets::SealId::from_bytes([0xB7; 16]),
            error: AnchorGateError::MinimumAnchor {
                attempted: 2,
                failures,
            },
        })
        .into();

        assert_eq!(cli.class(), ErrorClass::AnchorGateAbort);
        assert_eq!(cli.exit_code(), 22);
        let message = cli.to_string();
        assert!(!message.contains('\n'), "single-line: {message}");
        assert!(message.contains(&format!("tsa {down} [http]")), "{message}");
        assert!(
            message.contains(&format!("tsa {unpinned} [untrusted-chain]")),
            "{message}"
        );
        assert!(
            message.contains("(internally-consistent-only)"),
            "{message}"
        );
        assert!(!message.contains("InternallyConsistentOnly"), "{message}");
        assert_eq!(
            message.matches(NEVER_COUNTS).count(),
            1,
            "only the untrusted-chain entry says it never counts: {message}"
        );
        assert!(
            message.contains(&format!("`antseal abandon {}`", "b7".repeat(16))),
            "{message}"
        );
    }
}
