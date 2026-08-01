//! Autonomi storage boundary for antseal (MVP-SPEC.md lines 60–69).
//!
//! This crate owns the batch-first [`StorageBackend`] trait —
//!
//! ```text
//! quote_batch(&[Blob])                       -> CostQuote
//! pay(&CostQuote)                            -> PaymentReceipt
//! finalize_batch(&PaymentReceipt, &[Blob])   -> Vec<Address>     // idempotent; resumable
//! get_data(Address)                          -> Bytes
//! ```
//!
//! — its types, its error taxonomy, the `MockBackend` all tests run on
//! (S3, behind the non-default `test-util` feature), and, from S6, the
//! one-file `ant-core` adapter.
//!
//! # The churn-isolation boundary (normative)
//!
//! **All Autonomi storage network use goes through [`StorageBackend`]**;
//! the `ant-core = "=0.5.0"` pin and its weekly-churning API surface are
//! contained in one adapter impl file (S6/S20). **Anchor network I/O —
//! OTS calendar, TSA HTTP, esplora, two-endpoint Arbitrum-receipt
//! *confirmation* — is explicitly out of scope for this crate** and lives
//! in `antseal-anchor`. The **payment RPC is in scope** (D33): submitting
//! payment txs, awaiting their receipts (block-number capture inside
//! `pay()`), and the `eth_getTransactionReceipt` backfill all ride the
//! S5-configured payment endpoint — that is driving the payment, not
//! anchor evidence. CI's dependency-graph check proves only this crate
//! depends on `ant-core` and that no anchor-evidence client code or deps
//! appear here (S2 accept, D33-scoped).
//!
//! # Design anchors
//!
//! - **D32** — blob = exactly one chunk; `Address` = BLAKE3-256 of the
//!   ciphertext; hard [`MAX_CHUNK_SIZE`] cap enforced by [`Blob`]'s
//!   constructor; `get_data` ↦ `chunk_get`; no data-map path in v1.
//! - **D33** — block numbers are captured inside `pay()` from its awaited
//!   tx receipts; enrichment retries idempotently and never gates
//!   finalize.
//! - **D37** — `pay()` emits ⌈non-zero-transfers/256⌉ **sequential** txs,
//!   journaled per sub-batch; the receipt's core is the quote→tx map plus
//!   per-blob `proof_bytes`; post-pay resume is time-boxed (~24 h) with a
//!   distinct proofs-expired state.
//! - **Evidence validity never depends on Autonomi availability**: this
//!   crate stores and fetches ciphertext; it plays no part in offline
//!   bundle verification.
//!
//! This crate is **not** WASM: it never enters `antseal-core`'s or the
//! verifier page's dependency graph.

pub mod address;
pub mod backend;
pub mod blob;
pub mod error;
pub mod quote;
pub mod receipt;

pub use address::Address;
pub use backend::StorageBackend;
pub use blob::{Blob, BlobExceedsChunkCap, MAX_CHUNK_SIZE};
pub use error::StorageError;
pub use quote::{
    BlobCost, BlobQuote, CostQuote, EncodedPeerId, PeerQuote, QuoteHash, QuotePaymentEntry,
    QuotePreimage, RewardsAddress, TxHash,
};
pub use receipt::{BlobPaymentRecord, GasSummary, PaymentReceipt, TxRecord, TxStatus};
