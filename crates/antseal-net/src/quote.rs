//! [`CostQuote`] and its constituents — the priced plan for one seal's
//! full blob set, carrying the quote preimages the receipt must persist.
//!
//! Shapes mirror the pinned upstream types 1:1 in antseal-native form
//! (`docs/research/S1-ant-core-api-survey.md` §3; verified against
//! `ant-core-0.5.0` / `evmlib-0.9.0` / `ant-protocol-2.3.0` sources), so
//! S6's adapter maps field-for-field and S7's receipt can persist the full
//! preimages the v1.1 verification chain re-derives
//! (`QuoteHash = Keccak-256(bytes_for_sig ‖ pub_key ‖ signature)`,
//! `evmlib-0.9.0/src/data_payments.rs:130-135`).
//!
//! Amount representation: upstream `Amount = U256`. Here amounts are
//! `u128` **atto-ANT** (and gas in `u128` wei) — vastly above any real
//! total (`u128::MAX` atto ≈ 3.4e20 ANT) and clean for the S8 preflight
//! arithmetic. S6's adapter converts checked; an upstream value over
//! `u128::MAX` is a quote-class error there, never a truncation.

use crate::Address;

/// A 32-byte quote hash — upstream `QuoteHash = FixedBytes<32>`,
/// Keccak-256 over the signed quote bytes plus the node's key and
/// signature (`evmlib-0.9.0/src/common.rs:12,15`,
/// `data_payments.rs:130-135`).
///
/// This is the key of the receipt's quote→tx map — the exact identifier
/// `finalize_batch_payment` consumes (D37). Ordered so the map can be a
/// deterministic `BTreeMap`. `Debug` prints a hex prefix only and there
/// is deliberately no `Display`: quote hashes are receipt material and
/// must not drift into logs or error messages (S7 hygiene).
#[derive(
    Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub struct QuoteHash([u8; 32]);

impl QuoteHash {
    /// Construct from exactly-sized bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrow the raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl core::fmt::Debug for QuoteHash {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        debug_hex_prefix(f, "QuoteHash", &self.0)
    }
}

/// A 32-byte EVM transaction hash (upstream `TxHash`).
///
/// Receipt material: `Debug` prints a hex prefix only, no `Display`
/// (wallet-linkability hygiene, S7 — a tx hash identifies the paying
/// wallet on a public chain).
#[derive(
    Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub struct TxHash([u8; 32]);

impl TxHash {
    /// Construct from exactly-sized bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrow the raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl core::fmt::Debug for TxHash {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        debug_hex_prefix(f, "TxHash", &self.0)
    }
}

/// A node's 20-byte EVM rewards address (upstream `RewardsAddress` =
/// alloy `Address`, `evmlib-0.9.0/src/common.rs:11`).
#[derive(
    Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub struct RewardsAddress([u8; 20]);

impl RewardsAddress {
    /// Construct from exactly-sized bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 20]) -> Self {
        Self(bytes)
    }

    /// Borrow the raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 20] {
        &self.0
    }
}

impl core::fmt::Debug for RewardsAddress {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        debug_hex_prefix(f, "RewardsAddress", &self.0)
    }
}

/// A quoting node's 32-byte encoded peer id — raw
/// BLAKE3(ML-DSA-65 public key) upstream
/// (`evmlib-0.9.0/src/data_payments.rs:21-25`).
#[derive(
    Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub struct EncodedPeerId([u8; 32]);

impl EncodedPeerId {
    /// Construct from exactly-sized bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrow the raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl core::fmt::Debug for EncodedPeerId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        debug_hex_prefix(f, "EncodedPeerId", &self.0)
    }
}

fn debug_hex_prefix(
    f: &mut core::fmt::Formatter<'_>,
    name: &str,
    bytes: &[u8],
) -> core::fmt::Result {
    write!(f, "{name}(")?;
    for byte in bytes.iter().take(4) {
        write!(f, "{byte:02x}")?;
    }
    write!(f, "\u{2026})")
}

/// One node's full signed quote — the **preimage** the receipt persists
/// (mirror of `evmlib-0.9.0/src/data_payments.rs:75-115` `PaymentQuote`;
/// field-by-field per S1 §3).
///
/// The v1.1 receipt-verification chain re-derives
/// `QuoteHash = Keccak-256(bytes_for_sig ‖ pub_key ‖ signature)` from
/// exactly these fields, which is why the flat struct travels in the
/// [`CostQuote`] and again in the `PaymentReceipt` (D37 Decision 4:
/// redundancy with the opaque `proof_bytes` accepted — the flat fields
/// are what the chain and `--json` consumers read).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct QuotePreimage {
    /// The quoted chunk address (upstream `content: XorName`).
    pub content: Address,
    /// Quote timestamp as Unix seconds (upstream `SystemTime`, signed as
    /// u64-LE unix seconds).
    pub timestamp_unix_secs: u64,
    /// The node's asked price in atto-ANT (upstream `price: Amount`).
    pub price_atto: u128,
    /// The node's EVM payout address.
    pub rewards_address: RewardsAddress,
    /// The node's ML-DSA-65 public key (variable-length upstream bytes).
    pub node_pub_key: Vec<u8>,
    /// The node's ML-DSA-65 signature over `bytes_for_sig`.
    pub node_signature: Vec<u8>,
    /// ADR-0004 committed key count (serde-default tail field upstream).
    pub committed_key_count: u32,
    /// ADR-0004 commitment pin (serde-default tail field upstream).
    pub commitment_pin: Option<[u8; 32]>,
}

/// One `(peer, quote)` pair — upstream `peer_quotes:
/// Vec<(EncodedPeerId, PaymentQuote)>`, the material `proof_bytes` are
/// built from (`ant-core-0.5.0/src/data/client/batch.rs:291-331`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PeerQuote {
    /// The quoting node.
    pub peer_id: EncodedPeerId,
    /// Its signed quote preimage.
    pub quote: QuotePreimage,
}

/// One payment ledger line — mirror of upstream `QuotePaymentInfo`
/// (`ant-protocol-2.3.0/src/payment/single_node.rs:43-53`).
///
/// Upstream sorts a blob's quotes by price and pays the **median quote 3×
/// its price, every other amount zero**
/// (`SINGLE_NODE_PAYMENT_MULTIPLIER = 3`,
/// `ant-core-0.5.0/src/data/client/batch.rs:59-95`,
/// `payment.rs:17`) — so a blob contributes exactly one non-zero
/// transfer, and D37's 256-transfers-per-tx cap is a 256-**blobs**-per-tx
/// cap.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct QuotePaymentEntry {
    /// The quote this line pays (key into the receipt's quote→tx map).
    pub quote_hash: QuoteHash,
    /// Transfer destination (the node's payout address).
    pub rewards_address: RewardsAddress,
    /// Amount actually transferred, atto-ANT (0 for non-median quotes).
    pub amount_atto: u128,
    /// The node's asked price, atto-ANT.
    pub price_atto: u128,
}

/// What storing one blob costs.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum BlobCost {
    /// The network already holds this chunk — a **zero-cost line**:
    /// upstream `prepare_chunk_payment` returns `Ok(None)` when
    /// `CLOSE_GROUP_MAJORITY` peers report stored
    /// (`ant-core-0.5.0/src/data/client/batch.rs:361-368`; D32 evidence
    /// row 11). No quotes exist, nothing is paid, and `finalize_batch`
    /// skips the blob — the idempotency primitive the pay/finalize split
    /// relies on.
    AlreadyStored,
    /// The chunk must be paid for and stored.
    Priced {
        /// The payment ledger (one non-zero line per blob; see
        /// [`QuotePaymentEntry`]).
        payments: Vec<QuotePaymentEntry>,
        /// Full signed preimages from the quoting peers — journal
        /// material for the receipt (D37).
        peer_quotes: Vec<PeerQuote>,
        /// ADR-0004 opaque commitment sidecars, carried verbatim
        /// (upstream `Vec<Vec<u8>>`; never parsed by antseal).
        commitment_sidecars: Vec<Vec<u8>>,
    },
}

/// One blob's line in the quote.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BlobQuote {
    /// The blob's chunk address (BLAKE3-256 of its bytes, D32; computed
    /// by the backend — upstream derives it inside
    /// `prepare_chunk_payment`).
    pub address: Address,
    /// What storing it costs.
    pub cost: BlobCost,
}

/// The complete priced plan for one `quote_batch` call: per-blob quote
/// lines with full preimages, the total ANT, and the gas estimate.
///
/// **Completeness contract (S8)**: the quote handed to the consent step
/// covers *every* blob that will be finalized — all unit ciphertexts,
/// raw mirrors, and the encrypted manifest — so no post-consent payment
/// ever exceeds it. Blob order is the caller's `&[Blob]` order.
///
/// A quote is a **single-use spend authorization input**: a journaled
/// quote is never paid (D36) — resume always re-quotes and re-consents,
/// and `pay` takes the exact quote object consent affirmed.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CostQuote {
    /// Per-blob lines, in the order of the quoted `&[Blob]` slice.
    pub blobs: Vec<BlobQuote>,
    /// Total storage cost, atto-ANT — the sum of every payment line's
    /// `amount_atto` (already-stored lines contribute 0).
    pub total_ant_atto: u128,
    /// Estimated gas for the batch payment tx(s), wei.
    pub gas_estimate_wei: u128,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_newtypes_round_trip_and_order() {
        let a = QuoteHash::from_bytes([1; 32]);
        let b = QuoteHash::from_bytes([2; 32]);
        assert!(a < b, "byte-wise ordering for deterministic maps");
        assert_eq!(a.as_bytes(), &[1; 32]);
        assert_eq!(TxHash::from_bytes([7; 32]).as_bytes(), &[7; 32]);
        assert_eq!(RewardsAddress::from_bytes([9; 20]).as_bytes(), &[9; 20]);
        assert_eq!(EncodedPeerId::from_bytes([3; 32]).as_bytes(), &[3; 32]);
    }

    #[test]
    fn debug_leaks_only_a_prefix() {
        let tx = TxHash::from_bytes([0xCD; 32]);
        assert_eq!(format!("{tx:?}"), "TxHash(cdcdcdcd\u{2026})");
        let qh = QuoteHash::from_bytes([0x0F; 32]);
        assert_eq!(format!("{qh:?}"), "QuoteHash(0f0f0f0f\u{2026})");
    }
}
