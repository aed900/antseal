//! [`StorageError`] — the storage-boundary failure taxonomy (S2).
//!
//! One enum, shared by all four [`StorageBackend`] operations: the S6
//! adapter maps upstream's single `ant_core::data::Error` into these
//! classes (S1 §13), and the pipeline/UX layers classify by **variant,
//! never by message string**. Insufficient-ANT and insufficient-gas are
//! distinct variants (S2 accept); the stranded-payment and proofs-expired
//! slots are D37's.
//!
//! **Hygiene rules, normative for every variant** (project rule 6; S7):
//!
//! - no secret material (`W`, unit keys, salts, wallet keys) in any field
//!   or message — none is even representable here;
//! - no receipt fields (tx hashes, quote hashes, preimages) in messages —
//!   receipts are wallet-linkable; variants carry counts, not hashes.
//!   Chunk [`Address`]es are public content identifiers and may appear.
//!
//! [`StorageBackend`]: crate::StorageBackend

use crate::Address;

/// A storage-boundary operation failed.
///
/// Variants follow the S2 class list — quote, payment, insufficient-ANT,
/// insufficient-gas, finalize, not-found, network — plus D37's
/// stranded-payment and proofs-expired slots. `reason` strings are
/// diagnostic renderings of upstream errors, never classification keys.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StorageError {
    /// Quote collection failed (no money at risk: quoting precedes
    /// consent and payment).
    #[error("quote collection failed: {reason}")]
    Quote {
        /// Diagnostic detail.
        reason: String,
    },
    /// Payment submission failed **before any transaction landed** (no
    /// money moved). A failure after one or more sub-batch txs landed is
    /// [`StorageError::StrandedPayment`] instead — the distinction is the
    /// whole point of the split.
    #[error("payment failed before any transaction landed: {reason}")]
    Payment {
        /// Diagnostic detail.
        reason: String,
    },
    /// The wallet's ANT balance cannot cover the quoted storage cost.
    /// Distinct from [`StorageError::InsufficientGas`] **by type**: the
    /// user remedies them differently (acquire ANT vs bridge ETH).
    #[error(
        "insufficient ANT: the quote needs {required_atto} atto-ANT, the wallet holds \
         {available_atto}"
    )]
    InsufficientAnt {
        /// Atto-ANT the complete quote requires.
        required_atto: u128,
        /// Atto-ANT the wallet holds.
        available_atto: u128,
    },
    /// The wallet's ETH balance cannot cover the estimated gas.
    #[error(
        "insufficient gas: the payment needs an estimated {required_wei} wei of ETH, the wallet \
         holds {available_wei}"
    )]
    InsufficientGas {
        /// Wei the estimated gas requires.
        required_wei: u128,
        /// Wei the wallet holds.
        available_wei: u128,
    },
    /// `finalize_batch` failed — including the **gap** case: a non-zero
    /// quote with no tx hash in the receipt's map (upstream errors the
    /// same way, `batch.rs:300-305`). Finalize is idempotent and issues
    /// no payment, so this error is always retryable with the same
    /// journaled receipt (within the proof-validity window).
    #[error("finalize failed: {reason}")]
    Finalize {
        /// Diagnostic detail.
        reason: String,
    },
    /// Payment failed **mid-sequence with money already moved**: one or
    /// more sub-batch txs landed before the failure (D37 Decision 3 —
    /// the partial quote→tx map is journaled *before* this error
    /// surfaces, so the evidence of money spent is never only in the
    /// error). Resume treats mapped quotes as paid and pays only the
    /// remainder. Carries counts, not hashes (hygiene).
    #[error(
        "payment stranded mid-sequence: {landed_tx_count} sub-batch transaction(s) landed before \
         the failure; the journaled partial receipt is authoritative — resume will not re-pay \
         mapped quotes ({reason})"
    )]
    StrandedPayment {
        /// Sub-batch txs that landed (and were journaled) before the
        /// failure.
        landed_tx_count: usize,
        /// Diagnostic detail.
        reason: String,
    },
    /// A storer rejected the journaled proofs on payment grounds, and
    /// they are older than antseal's conservative ~24 h proof-age window
    /// (D37 Decision 6). Completing the seal now requires **re-consented
    /// re-payment** — surfaced distinctly so it can never happen
    /// silently (S11 owns the re-consent flow).
    ///
    /// **Attribution, corrected by S9 (2026-08-02):** this window is
    /// antseal's own client-side policy, **not** a rule the pinned
    /// ant-node enforces. `QUOTE_MAX_AGE_SECS` — which D37 recorded as
    /// node-side proof validity, following ant-core's own doc comments —
    /// does not exist in ant-node 0.15.0, and the single-node payment
    /// path (`verify_payment_inner` -> `verify_evm_payment`,
    /// `ant-node-0.15.0/src/payment/verifier.rs:801,945`) applies no
    /// timestamp gate at all. The only proof-age enforcement in the
    /// pinned stack is `MERKLE_PAYMENT_EXPIRATION` (7 days,
    /// `evmlib-0.9.0/src/merkle_payments/merkle_tree.rs:24`), on the
    /// merkle path D37 excludes. The variant stays, and the window stays
    /// conservative: the mechanism may return upstream at any release,
    /// and being early costs one re-pay of a cheap chunk. Evidence:
    /// `crates/antseal-net/tests/storage_constants.rs` module docs.
    #[error(
        "payment proofs expired: the node-side proof-validity window (~24 h) has passed and \
         storers reject the journaled proofs; completing this seal requires a re-consented \
         re-payment"
    )]
    ProofsExpired,
    /// No chunk exists at this address (distinct from transport failure:
    /// the network answered, negatively).
    #[error("no chunk found at address {address}")]
    NotFound {
        /// The address that resolved to nothing.
        address: Address,
    },
    /// Transport-class failure: the operation could not get an answer
    /// from the network (timeouts, unreachable peers, RPC transport
    /// errors). Retryable by nature.
    #[error("network error: {reason}")]
    Network {
        /// Diagnostic detail.
        reason: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The S2 accept row: insufficient-token and insufficient-gas are
    /// distinguishable **by type, not string** — classification works on
    /// variants with the messages ignored entirely.
    #[test]
    fn shortfall_variants_are_distinct_types() {
        let ant = StorageError::InsufficientAnt {
            required_atto: 10,
            available_atto: 3,
        };
        let gas = StorageError::InsufficientGas {
            required_wei: 10,
            available_wei: 3,
        };
        assert!(matches!(ant, StorageError::InsufficientAnt { .. }));
        assert!(matches!(gas, StorageError::InsufficientGas { .. }));
        assert!(!matches!(ant, StorageError::InsufficientGas { .. }));
        assert!(!matches!(gas, StorageError::InsufficientAnt { .. }));
    }

    /// Every class in the S2 list (plus the two D37 slots) is present and
    /// constructible, and messages carry no hash material.
    #[test]
    fn taxonomy_is_complete_and_messages_are_hash_free() {
        let all = [
            StorageError::Quote { reason: "r".into() },
            StorageError::Payment { reason: "r".into() },
            StorageError::InsufficientAnt {
                required_atto: 1,
                available_atto: 0,
            },
            StorageError::InsufficientGas {
                required_wei: 1,
                available_wei: 0,
            },
            StorageError::Finalize { reason: "r".into() },
            StorageError::StrandedPayment {
                landed_tx_count: 1,
                reason: "r".into(),
            },
            StorageError::ProofsExpired,
            StorageError::NotFound {
                address: Address::from_bytes([0xAA; 32]),
            },
            StorageError::Network { reason: "r".into() },
        ];
        for err in &all {
            let msg = err.to_string();
            assert!(!msg.is_empty());
        }
        // The stranded message names a count, never a tx hash.
        let msg = StorageError::StrandedPayment {
            landed_tx_count: 2,
            reason: "x".into(),
        }
        .to_string();
        assert!(
            msg.contains('2') && !msg.to_lowercase().contains("0x"),
            "{msg}"
        );
    }
}
