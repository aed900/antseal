//! [`PaymentReceipt`] — the journaled proof-reconstruction record
//! (contents finalized at S7 per decision D37).
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
//! # Serialization contract (S7 — the U9 opaque-slot format)
//!
//! The **map-shaped core** frozen here is D37 Decision 4: per-blob
//! records, the deterministic quote→tx `BTreeMap`, per-tx enrichment
//! slots. At S7 every receipt/quote type carries `serde` derives, and the
//! journaled at-rest shape is the [`JournalReceipt`] envelope:
//!
//! - **codec-agnostic**: the vault's byte codec is U9's choice; this
//!   module defines the *data model* — struct **field order is part of
//!   the format** (serde emits declaration order; reordering fields is a
//!   format change and takes a version bump), enums are externally
//!   tagged by variant name, byte arrays are plain sequences, and the
//!   quote→tx map serializes as an **ordered pair list**
//!   ([`tx_map_pairs`]) so codecs without byte-string map keys (JSON
//!   included) encode it losslessly — `BTreeMap` iteration makes the
//!   order deterministic, and duplicate keys are rejected on parse
//!   (defensive: a duplicate can only mean journal corruption);
//! - **versioned**: [`JournalReceipt::seal`] stamps
//!   [`RECEIPT_JOURNAL_VERSION`]; [`JournalReceipt::open`] refuses
//!   unknown versions with a typed error instead of misreading a future
//!   layout. Prefer additive slots + a version bump over reshaping.
//!
//! Determinism: encoding the same receipt twice through any
//! deterministic serde codec yields identical bytes (no HashMap
//! anywhere, no floats, no non-deterministic field). The unit tests
//! prove it through the exact-pinned `serde_json` as the evidence codec.
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
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PaymentReceipt {
    /// Per-blob proof-reconstruction records, in quote/blob order.
    /// Already-stored blobs (zero-cost quote lines) have nothing to pay
    /// or prove and carry no record.
    pub blobs: Vec<BlobPaymentRecord>,
    /// The payment-wide **quote→tx map** — what `finalize_batch_payment`
    /// consumes; complete over every non-zero quote or finalize fails
    /// with a gap error. `BTreeMap` for deterministic encoding (D37);
    /// serialized as an ordered pair list (`tx_map_pairs`) so the format
    /// survives codecs without byte-array map keys (JSON included), with
    /// duplicate keys rejected on parse.
    #[serde(with = "tx_map_pairs")]
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

/// The at-rest journal format version this build writes.
///
/// v1 = the S7 data model (module docs). Bump on any reshaping of the
/// receipt/quote types or their serde attributes; [`JournalReceipt::open`]
/// refuses anything else.
pub const RECEIPT_JOURNAL_VERSION: u16 = 1;

/// The versioned at-rest envelope for a journaled [`PaymentReceipt`] —
/// what U9's vault record stores in its opaque receipt slot.
///
/// Fields are private on purpose: the only way in is
/// [`JournalReceipt::seal`] (stamps the current version) and the only way
/// out is [`JournalReceipt::open`] (validates it) — a parser cannot
/// accidentally skip the version check.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct JournalReceipt {
    /// Format version tag — serialized FIRST (field order is format).
    version: u16,
    /// The receipt payload.
    receipt: PaymentReceipt,
}

impl JournalReceipt {
    /// Wrap a receipt for journaling, stamped with
    /// [`RECEIPT_JOURNAL_VERSION`].
    #[must_use]
    pub fn seal(receipt: PaymentReceipt) -> Self {
        Self {
            version: RECEIPT_JOURNAL_VERSION,
            receipt,
        }
    }

    /// Unwrap a parsed envelope, refusing unknown format versions
    /// (defensive parse: a future layout must never be misread as v1).
    ///
    /// # Errors
    ///
    /// [`ReceiptFormatError::UnknownVersion`] for any version this build
    /// does not write.
    pub fn open(self) -> Result<PaymentReceipt, ReceiptFormatError> {
        if self.version != RECEIPT_JOURNAL_VERSION {
            return Err(ReceiptFormatError::UnknownVersion {
                found: self.version,
                supported: RECEIPT_JOURNAL_VERSION,
            });
        }
        Ok(self.receipt)
    }

    /// The envelope's version tag (readable without opening — lets a
    /// caller render "written by a newer antseal" before failing).
    #[must_use]
    pub const fn version(&self) -> u16 {
        self.version
    }
}

/// A journaled receipt envelope could not be accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ReceiptFormatError {
    /// The envelope's version tag is not one this build reads.
    #[error(
        "journaled receipt has format version {found}, this build supports {supported} — \
         written by a different antseal version"
    )]
    UnknownVersion {
        /// The tag found in the envelope.
        found: u16,
        /// The version this build reads/writes.
        supported: u16,
    },
}

/// Serde codec for [`PaymentReceipt::tx_map`]: an **ordered pair list**
/// instead of a native map (module docs — byte-array map keys do not
/// survive every codec; JSON is the pinned counter-example). Order is
/// `BTreeMap`'s key order (deterministic); duplicates are a parse error.
mod tx_map_pairs {
    use std::collections::BTreeMap;

    use serde::de::Error as _;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use crate::quote::{QuoteHash, TxHash};

    pub fn serialize<S: Serializer>(
        map: &BTreeMap<QuoteHash, TxHash>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let pairs: Vec<(&QuoteHash, &TxHash)> = map.iter().collect();
        pairs.serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<BTreeMap<QuoteHash, TxHash>, D::Error> {
        let pairs: Vec<(QuoteHash, TxHash)> = Vec::deserialize(deserializer)?;
        let mut map = BTreeMap::new();
        for (quote_hash, tx_hash) in pairs {
            if map.insert(quote_hash, tx_hash).is_some() {
                return Err(D::Error::custom(
                    "duplicate quote hash in the journaled quote→tx map — corrupt journal",
                ));
            }
        }
        Ok(map)
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

    /// Drive the mock twin with a forced sub-batch cap to mint a REAL
    /// multi-tx receipt shape (S7 accept: ≥ 2 sub-batches) — 5 blobs at
    /// cap 2 ⇒ 3 sequential txs.
    fn multi_tx_receipt() -> PaymentReceipt {
        use crate::StorageBackend;
        use crate::test_util::{MockBackend, block_on};
        let mock = MockBackend::new().with_max_transfers_per_tx(2);
        let blobs: Vec<crate::Blob> = (1u8..=5)
            .map(|fill| crate::Blob::new(vec![fill; 64]).expect("under cap"))
            .collect();
        let quote = block_on(mock.quote_batch(&blobs)).expect("quote");
        block_on(mock.pay(&quote)).expect("pay")
    }

    #[test]
    fn multi_tx_receipt_serde_round_trips_with_no_field_loss() {
        let receipt = multi_tx_receipt();
        assert_eq!(receipt.txs.len(), 3, "the multi-tx shape under test");
        assert_eq!(receipt.tx_map.len(), 5, "every quote mapped across txs");

        let envelope = JournalReceipt::seal(receipt.clone());
        let bytes = serde_json::to_vec(&envelope).expect("encodes");
        let parsed: JournalReceipt = serde_json::from_slice(&bytes).expect("decodes");
        let reopened = parsed.open().expect("current version opens");
        // Field-for-field equality IS the no-field-loss proof: every
        // element class (per-blob triple incl. proof_bytes + sidecars,
        // quote→tx map, per-tx block-number slots, gas, totals) is part
        // of PartialEq.
        assert_eq!(reopened, receipt);

        // The map really covers every quote of every tx.
        for tx in &receipt.txs {
            for quote_hash in &tx.quote_hashes {
                assert_eq!(receipt.tx_map.get(quote_hash), Some(&tx.tx_hash));
            }
        }
    }

    #[test]
    fn journal_encoding_is_deterministic() {
        // Same receipt, two encodes: byte-identical. Two identically
        // driven mocks: byte-identical journals (no HashMap, no clock,
        // no RNG anywhere in the model).
        let a = JournalReceipt::seal(multi_tx_receipt());
        let b = JournalReceipt::seal(multi_tx_receipt());
        let bytes_a1 = serde_json::to_vec(&a).expect("encodes");
        let bytes_a2 = serde_json::to_vec(&a).expect("encodes");
        let bytes_b = serde_json::to_vec(&b).expect("encodes");
        assert_eq!(bytes_a1, bytes_a2);
        assert_eq!(bytes_a1, bytes_b);
    }

    #[test]
    fn unknown_journal_version_is_a_typed_refusal() {
        let envelope = JournalReceipt::seal(multi_tx_receipt());
        let mut value = serde_json::to_value(&envelope).expect("encodes");
        // A future format: version 2 with whatever payload — must be
        // refused at open(), never misread.
        value["version"] = serde_json::json!(2);
        let parsed: JournalReceipt = serde_json::from_value(value).expect("envelope parses");
        assert_eq!(parsed.version(), 2);
        let err = parsed.open().expect_err("unknown version refused");
        assert_eq!(
            err,
            ReceiptFormatError::UnknownVersion {
                found: 2,
                supported: RECEIPT_JOURNAL_VERSION,
            }
        );
        // And the version tag serializes FIRST (field order is format).
        let text = serde_json::to_string(&envelope).expect("encodes");
        assert!(
            text.starts_with("{\"version\":1,"),
            "version leads the envelope: {}",
            &text[..40.min(text.len())]
        );
    }

    #[test]
    fn duplicate_tx_map_keys_are_rejected_on_parse() {
        let receipt = multi_tx_receipt();
        let mut value = serde_json::to_value(&receipt).expect("encodes");
        let pairs = value["tx_map"].as_array().expect("pair list").clone();
        let mut doubled = pairs.clone();
        doubled.push(pairs[0].clone());
        value["tx_map"] = serde_json::Value::Array(doubled);
        let err = serde_json::from_value::<PaymentReceipt>(value).expect_err("duplicate refused");
        assert!(
            err.to_string().contains("duplicate quote hash"),
            "typed duplicate rejection: {err}"
        );
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
