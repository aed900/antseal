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
//! anchor evidence. CI's dependency-graph check proves this is the only
//! **product** crate depending on `ant-core` (the never-published
//! devnet-launcher holds the other, feature-gated edge) and that no
//! anchor-evidence client code or deps appear here (S2 accept,
//! D33-scoped).
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
//! # Network selection and the `ant-backend` feature split (S5)
//!
//! [`NetworkConfig`] maps the three network identities — `arbitrum-one`
//! (default), `arbitrum-sepolia` (chain 421614 — **Arbitrum** Sepolia,
//! NOT Ethereum Sepolia), `devnet` (run-scoped local environment) — to
//! chain id, payment contracts, RPC endpoint and bootstrap peers, as
//! **pure data in the default feature set** (no ant-core), so U's config
//! wiring never pays for the backend graph. The heavy half — conversion
//! to upstream's `EvmNetwork`, `WalletKey::evm_wallet`, and from S6 the
//! real backend — lives in [`evm`] behind the non-default
//! **`ant-backend`** feature:
//!
//! ```text
//! cargo test -p antseal-net                          # pure half only
//! cargo test -p antseal-net --features ant-backend   # + the EVM stack
//! ```
//!
//! **The wallet light half is NOT behind that feature** (D89, 2026-08-02):
//! [`wallet`] owns secp256k1 keygen, the D44 import predicate, address
//! derivation and EIP-55 rendering over a direct exact-pinned `k256`
//! (`arithmetic` only) + `sha3`, and [`backend`] owns [`BalanceReport`],
//! [`PreflightReport`] and the pure shortfall rule [`preflight`]. U11's
//! `init` and U14's consent gate are therefore compiled, linted and
//! asserted by the **required** default-feature CI lanes, which is the
//! coverage property D89 Evidence 3 measured and bought; the nine packages
//! it costs the default graph add **zero** to the feature graphs.
//! `wallet.rs` is deliberately **not** on the S6 upstream-use allowlist,
//! so the `dep-graph` lane itself enforces that the light half never names
//! `ant_core::`/`ant_protocol::`.
//!
//! This crate is **not** WASM: it never enters `antseal-core`'s or the
//! verifier page's dependency graph.

pub mod address;
// The ONE ant-core adapter impl file (S6) — the churn-containment unit the
// StorageBackend boundary exists for. Same non-default feature as `evm`.
#[cfg(feature = "ant-backend")]
pub mod ant_backend;
pub mod backend;
pub mod blob;
pub mod error;
// The EVM half of S5 (network→EvmNetwork conversion + wallet key ops),
// behind the NON-DEFAULT `ant-backend` feature — the containment boundary
// that keeps the ~600-package ant-core graph out of every default build
// (see the feature comment in Cargo.toml). S6's adapter extends the same
// feature.
#[cfg(feature = "ant-backend")]
pub mod evm;
// The `--live` persistence primitive (S15) — rides `StorageBackend` only,
// so it is in the DEFAULT feature set and tests on `MockBackend`.
pub mod live;
pub mod network;
pub mod quote;
pub mod receipt;
// The wallet LIGHT half (D89): secp256k1 keygen, D44 import validation,
// address derivation, EIP-55 — DEFAULT feature set, over `k256`
// (arithmetic only) + `sha3`, naming no upstream crate. Deliberately kept
// OFF the S6 containment allowlist so that stays machine-checked.
pub mod wallet;

// Test-support surface (S3): `MockBackend` + the std-only `block_on`
// executor, exported across the crate boundary for `antseal_cli`'s
// pipeline tests (D34's forced sub-finding). Non-default feature; zero
// optional deps — see the feature comment in Cargo.toml.
#[cfg(feature = "test-util")]
pub mod test_util;

pub use address::Address;
#[cfg(feature = "ant-backend")]
pub use ant_backend::{AntCoreBackend, CaptureHook};
pub use backend::{BalanceReport, PreflightReport, StorageBackend, preflight};
pub use blob::{Blob, BlobExceedsChunkCap, MAX_CHUNK_SIZE};
pub use error::StorageError;
pub use live::manifest::{
    LiveCheckError, LiveCheckReport, LiveCheckRow, LiveSubject, LiveVerdict, StorageRecord,
    UnitKindTag, blob_outcome, live_check, live_inputs, records_from_manifest, subject_label,
};
pub use live::{
    BlobPersistence, FetchFailureClass, PersistenceOutcome, PersistenceReport, PersistenceSummary,
    check_persistence, fetch_failure_class,
};
pub use network::{
    DevnetEnv, DevnetEnvError, EvmAddress20, EvmAddressParseError, NetworkConfig,
    NetworkConfigError, NetworkId,
};
pub use quote::{
    BlobCost, BlobQuote, CostQuote, EncodedPeerId, PeerQuote, QuoteHash, QuotePaymentEntry,
    QuotePreimage, RewardsAddress, TxHash,
};
pub use receipt::{
    BlobPaymentRecord, GasSummary, JournalReceipt, PaymentReceipt, RECEIPT_JOURNAL_VERSION,
    ReceiptFormatError, TxRecord, TxStatus,
};
pub use wallet::{WalletImportError, WalletKey, WalletOpsError, checksummed};
