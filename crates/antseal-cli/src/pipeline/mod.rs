//! The seal orchestration layer (D34) — the pipeline, its journal, and the
//! interfaces it is written over.
//!
//! Per `docs/decisions/D34-seal-pipeline-placement.md` this module tree is
//! the **orchestration home**: the seal journal and its state machine (S10),
//! the seal pipeline (S12), resume (S11), restore (S14) and — at M3 — the
//! reveal flow. It is library code inside `antseal-cli`'s `[lib]` target so
//! the M1 E2E drives sealing through library APIs (MVP-SPEC.md line 154),
//! never by spawning the binary.
//!
//! # Interface directions (D34 Decision 2, frozen)
//!
//! | interface | defined in | implemented by |
//! | --- | --- | --- |
//! | `antseal_net::StorageBackend` | `antseal-net` (S2) | S6's ant-core adapter; `MockBackend` |
//! | `antseal_anchor::AnchorGate` | `antseal-anchor` (A1) | `NoAnchorGate`; A20's real gate (M2); test doubles |
//! | [`journal::SealJournal`] | **here** | [`vault_journal::VaultJournal`] over U9's record store; test doubles |
//! | `ConsentHook` | **here** (S12) | U14's interactive gate; test doubles |
//!
//! `antseal-core` and `antseal-net` never learn the journal or the consent
//! hook exist; the pipeline is generic over every one of them and uses no
//! `dyn` (both upstream traits are `async fn` traits and therefore not
//! dyn-compatible — a deliberate trade recorded on each).

pub mod consent;
pub mod error;
pub mod journal;
pub mod receipt_sink;
pub mod restore;
pub mod resume;
pub mod seal;
pub mod vault_journal;

pub use consent::{ConsentDecision, ConsentHook, ConsentRequest, consent_record};
pub use error::{Barrier, BarrierHook, NoBarriers, SealError};
pub use journal::{
    BlobSlot, JournalError, MANIFEST_BLOB_ENTRY, NONCE_LEN, PLAN_ENTRY, RecordedIdentity,
    SEAL_JOURNAL_VERSION, STATE_ENTRY, SealJournal, SealPlan, SealState, StagedBlob,
    StagedBytesUnavailable, UNIT_ENTRY_BASE, WorkIdentity, check_staged_integrity,
    verify_all_staged,
};
pub use receipt_sink::{ReceiptSinkFault, VaultReceiptSink};
pub use restore::{
    BlobOrigin, ByteSource, FailedFile, FailureKind, FileError, FileOutcome, ManifestSource,
    RestoreEngine, RestoreError, RestoreReport, VerifiedFile, hex32,
};
pub use resume::{Pipeline, SealOutcome, canonical_order};
pub use seal::{
    AEAD_TAG_LEN, DryRunReport, SealFile, SealRequest, SealResult, projected_ciphertext_len,
};
pub use vault_journal::VaultJournal;
