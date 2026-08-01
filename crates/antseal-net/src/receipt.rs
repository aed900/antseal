//! [`PaymentReceipt`] — the journaled proof-reconstruction record
//! (skeleton; contents finalized in S7 per decision D37).
//!
//! **The receipt is a proof-reconstruction record, not a hash list**
//! (D37): to complete a seal after a crash between `pay` and
//! `finalize_batch` *without re-paying*, the journal must be able to
//! rebuild, for every blob, a proof the network accepts — which needs the
//! per-blob quote preimages and the quote→tx association (upstream
//! `finalize_batch_payment` consumes a `HashMap<QuoteHash, TxHash>` and
//! errors on any missing entry,
//! `ant-core-0.5.0/src/data/client/batch.rs:300-305,337-343`), or the
//! finished `proof_bytes` themselves (upstream's own resume cache
//! persists exactly `(address, proof_bytes)`, `cached_single.rs`
//! module docs). A flat `Vec<TxHash>` retains neither — the register's
//! original shape, overturned by D37.
//!
//! # Skeleton status (S2) and how S7 extends it
//!
//! The **map-shaped core** frozen here is D37 Decision 4: per-blob
//! records, the deterministic quote→tx `BTreeMap`, per-tx enrichment
//! slots. S7 finalizes contents *additively* — deterministic serde for
//! vault persistence, the capture-consistency checks against upstream's
//! `deserialize_proof`, richer gas fields — without reshaping what exists
//! here. These are in-process types, not wire formats: growing them is a
//! compile-visible workspace event, and the vault's serialized layout is
//! S7's to version.
//!
//! # Time-boxed usability (D37 Decision 6)
//!
//! A journaled receipt is PUT-usable only within the node-side proof
//! validity window (`QUOTE_MAX_AGE_SECS`, ~24 h — node policy, pinned by
//! S9). After it, storers reject the proofs even though the receipt is
//! intact: that is the distinct [`StorageError::ProofsExpired`] state,
//! and completing the seal then requires re-consented re-payment, never a
//! silent one.
//!
//! [`StorageError::ProofsExpired`]: crate::StorageError::ProofsExpired

use std::collections::BTreeMap;

use crate::Address;
use crate::quote::{PeerQuote, QuoteHash, QuotePaymentEntry, TxHash};

/// Everything one blob needs to be stored (or re-stored on resume)
/// **without any new payment** — D37 Decision 4's per-blob record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobPaymentRecord {
    /// The blob's chunk address.
    pub address: Address,
    /// The payment ledger lines for this blob — carried flat (beyond D37's
    /// minimum) because `finalize_batch` must check *per blob* that every
    /// non-zero line's `quote_hash` is covered by [`PaymentReceipt::tx_map`]
    /// (the upstream gap check, `batch.rs:300-305`), and the per-tx
    /// [`TxRecord::quote_hashes`] sets cannot answer "which quotes belong
    /// to this blob".
    pub payments: Vec<QuotePaymentEntry>,
    /// Full signed quote preimages from the quoting peers.
    pub peer_quotes: Vec<PeerQuote>,
    /// ADR-0004 opaque commitment sidecars, verbatim.
    pub commitment_sidecars: Vec<Vec<u8>>,
    /// The store-ready proof, opaque **upstream-versioned** bytes (tag
    /// byte + rmp-serde `PaymentProof`,
    /// `ant-protocol-2.3.0/src/payment/proof.rs:17-99`). Built via the
    /// pure `finalize_batch_payment` the moment the last needed tx hash
    /// exists (D37), so the journaled receipt is store-ready with no live
    /// `PreparedChunk`. Never parsed by this crate; S7's capture-
    /// consistency test parses it via upstream's own `deserialize_proof`.
    pub proof_bytes: Vec<u8>,
}

/// Landing status of one payment sub-batch transaction.
///
/// The reverted arm was added at S6 (the extension the skeleton
/// anticipated): the awaited-receipt flow observes `status == false`
/// directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxStatus {
    /// Submitted; landing not yet observed (the journal-first record —
    /// the hash is durable even if the receipt await is interrupted,
    /// D33 Decision 2). Backfill resolves it to one of the other arms.
    Submitted,
    /// The awaited transaction receipt reports the tx mined successfully.
    Confirmed,
    /// The awaited transaction receipt reports the tx mined but
    /// **reverted** (S6): gas was spent, **no ANT moved**, and the
    /// sub-batch's quotes are deliberately NOT in the quote→tx map (they
    /// are unpaid). The record is journaled as evidence of the gas spend.
    Reverted,
}

/// One sub-batch transaction's journal record — exactly D37 Decision 2's
/// `{tx_hash, block_number, status, quote_hash set}`, journaled **before
/// the next sub-batch is submitted**.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxRecord {
    /// The sub-batch's EVM transaction hash.
    pub tx_hash: TxHash,
    /// Block number — the D33 **enrichment slot**: filled from the very
    /// receipt `pay()` awaits in the primary flow; `None` when the read
    /// failed, backfilled idempotently by later invocations via
    /// `eth_getTransactionReceipt` over the payment RPC. Enrichment never
    /// gates finalize.
    pub block_number: Option<u64>,
    /// Landing status.
    pub status: TxStatus,
    /// The quote hashes this tx paid (its ≤256-transfer sub-batch).
    pub quote_hashes: Vec<QuoteHash>,
}

/// Gas summary for the whole payment (skeleton).
///
/// Upstream's `GasInfo` carries `estimated_gas`, `gas_with_buffer`, fee
/// caps, `actual_gas_used`, `effective_gas_price`
/// (`evmlib-0.9.0/src/retry.rs:15-30`) — S7 adds what the vault record
/// needs; the one field every path already has is the total.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GasSummary {
    /// Total gas cost in wei (upstream `gas_cost_wei: u128`).
    pub gas_cost_wei: u128,
}

/// The journaled payment record for one seal — D37 Decision 4's shape.
///
/// The spec's four element classes are all present or slotted: tx
/// **hashes** ([`TxRecord::tx_hash`], plural under multi-tx), **block
/// number** slots ([`TxRecord::block_number`], D33), **quote preimages**
/// ([`BlobPaymentRecord::peer_quotes`]), and **`proof_bytes`**
/// ([`BlobPaymentRecord::proof_bytes`]) — everything the v1.1
/// receipt-verification chain needs, captured from day one so no reseal
/// is ever required (MVP-SPEC.md lines 69/110).
///
/// **Hygiene (S7, normative here too): no field of this type may appear
/// in logs or error messages** — receipts are wallet-linkable on a public
/// chain. The hash newtypes have no `Display` and prefix-only `Debug` for
/// exactly this reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaymentReceipt {
    /// Per-blob proof-reconstruction records, in quote/blob order.
    /// Already-stored blobs (zero-cost quote lines) have nothing to pay
    /// or prove and carry no record.
    pub blobs: Vec<BlobPaymentRecord>,
    /// The payment-wide **quote→tx map** — what `finalize_batch_payment`
    /// consumes; complete over every non-zero quote or finalize fails
    /// with a gap error. `BTreeMap` for deterministic encoding (D37).
    pub tx_map: BTreeMap<QuoteHash, TxHash>,
    /// Per-tx records in **submission order** (D37 sequential
    /// sub-batches: ⌈non-zero-transfers/256⌉ txs; one tx in the common
    /// ≤256-blob case).
    pub txs: Vec<TxRecord>,
    /// Total storage cost paid, atto-ANT.
    pub storage_cost_atto: u128,
    /// Gas summary.
    pub gas: GasSummary,
}

impl PaymentReceipt {
    /// Whether every non-zero payment line of every blob record is
    /// covered by the quote→tx map — the receipt-side statement of the
    /// upstream gap rule (`batch.rs:300-305`): a receipt failing this
    /// cannot finalize and signals journal corruption or a truncated
    /// capture.
    #[must_use]
    pub fn covers_all_paid_quotes(&self) -> bool {
        self.blobs.iter().all(|record| {
            record
                .payments
                .iter()
                .filter(|line| line.amount_atto > 0)
                .all(|line| self.tx_map.contains_key(&line.quote_hash))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quote::RewardsAddress;

    fn line(quote_hash: QuoteHash, amount_atto: u128) -> QuotePaymentEntry {
        QuotePaymentEntry {
            quote_hash,
            rewards_address: RewardsAddress::from_bytes([0; 20]),
            amount_atto,
            price_atto: amount_atto / 3,
        }
    }

    #[test]
    fn coverage_check_flags_a_gap_and_ignores_zero_lines() {
        let paid = QuoteHash::from_bytes([1; 32]);
        let unpaid = QuoteHash::from_bytes([2; 32]);
        let zero = QuoteHash::from_bytes([3; 32]);
        let mut receipt = PaymentReceipt {
            blobs: vec![BlobPaymentRecord {
                address: Address::from_bytes([9; 32]),
                payments: vec![line(paid, 300), line(zero, 0)],
                peer_quotes: Vec::new(),
                commitment_sidecars: Vec::new(),
                proof_bytes: Vec::new(),
            }],
            tx_map: BTreeMap::from([(paid, TxHash::from_bytes([8; 32]))]),
            txs: Vec::new(),
            storage_cost_atto: 300,
            gas: GasSummary {
                gas_cost_wei: 21_000,
            },
        };
        // Complete: the non-zero line is mapped; the zero line needs no tx.
        assert!(receipt.covers_all_paid_quotes());

        // A gap: a non-zero line whose quote is not in the map.
        receipt.blobs[0].payments.push(line(unpaid, 300));
        assert!(!receipt.covers_all_paid_quotes());
    }
}
