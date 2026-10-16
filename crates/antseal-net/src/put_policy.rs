//! The verdict on a blob's failed store round (S43, D179): was the payment
//! proof refused — so completing the seal needs a new, separately consented
//! payment — or does finalize simply run again, paying nothing?
//!
//! # The rule (D179 R1–R3)
//!
//! - **A payment-class reply is one target's decline.** `PaymentFailed` and
//!   `PaymentRequired` are what one storer answered, and nothing more: the
//!   round continues to the next target and stops only when a majority
//!   ([`PutTally::majority`]) has stored or the targets run out. That is
//!   upstream's own close-group policy — *"skip this peer, do not re-quote"*
//!   (`ant-core-0.5.0/src/data/client/chunk.rs:36-79`) — and it is why one
//!   hostile target can no longer end the round.
//! - **[`PutVerdict::ProofsExpired`] needs both of:**
//!   1. the declines **alone** make the majority unreachable: the targets that
//!      did not decline — stored, or failed for any other reason — are fewer
//!      than the majority, and the declines are themselves at least a
//!      majority ([`PutTally::declines_are_decisive`]); with upstream's seven
//!      targets that is four or more declines;
//!   2. the payment is more than [`PROOF_VALIDITY_WINDOW_SECS`] old by the
//!      **block timestamp** of the transaction that paid for the blob
//!      ([`payment_outlived_window`]).
//! - **Everything else is [`PutVerdict::Retry`]**: a typed finalize failure,
//!   which resume answers by finalizing again and paying nothing.
//!
//! # Why the block's time, and never the quote's
//!
//! A quote's `timestamp_unix_secs` is the quoting peer's own signed field, and
//! the client never checks it (`S43`'s defect): judged by the oldest quote
//! timestamp, one hostile quoting peer could make a minute-old payment look a
//! day old. The block timestamp is the chain's, and no storage peer writes
//! it. It is needed only on the rare path where the declines are decisive, so
//! the adapter reads it only there, through the journaled receipt's
//! quote→tx map ([`paying_txs`]) and the payment RPC it already holds. A time
//! that cannot be read counts as **not** expired ([`payment_time`]): a failed
//! read costs a retry, never a payment.
//!
//! The age is measured against this machine's clock. A clock set more than a
//! day ahead makes a refused proof look expired early; the cost is the same
//! as any early guess — one re-payment the user must consent to.
//!
//! # What this does not stop (D179 R6)
//!
//! A hostile close-group **majority** can still decline every PUT, and once
//! the payment is a day old by the chain's clock it can put the user in front
//! of one re-payment consent per invocation (`--yes` consents in advance). A
//! minority can do neither: its declines are never decisive.
//!
//! # Why the window is antseal's own
//!
//! No pinned node rejects a proof on age: `QUOTE_MAX_AGE_SECS` does not exist
//! in `ant-node` 0.15.0, and its single-node payment path reads no timestamp
//! (D37's 2026-08-02 correction; `tests/storage_constants.rs` module docs).
//! The window is a client policy that decides only when a refused proof is
//! old enough to justify asking for a new payment.
//!
//! # Containment
//!
//! Pure, and in the default graph, so the required default-feature lanes
//! compile and test the decision. The adapter (`ant_backend.rs`, feature
//! `ant-backend`) only maps each upstream reply to a [`PutReply`] and supplies
//! the block time (D179 R4).

use crate::quote::TxHash;
use crate::receipt::{BlobPaymentRecord, PaymentReceipt};

/// antseal's proof-age window (~24 h, D37 Decision 6): a refused payment proof
/// is treated as expired only when its payment is **more** than this old by
/// its block time (strictly greater: a payment exactly this old is not
/// expired).
///
/// Its value mirrors ant-core's client-side cache policy
/// (`CACHED_PROOF_MAX_AGE_SECS = 24 * 60 * 60`,
/// `ant-core-0.5.0/src/data/client/batch.rs:1051-1058`) and is **not** a rule
/// the pinned nodes enforce (module docs).
pub const PROOF_VALIDITY_WINDOW_SECS: u64 = 24 * 60 * 60;

/// One PUT target's answer, as the policy reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PutReply {
    /// The target stored the chunk, or reported that it already held it.
    Stored,
    /// A payment-class refusal — `PaymentFailed` or `PaymentRequired`: this
    /// target declined the payment proof.
    Declined,
    /// Any other failure: an unreachable peer, a timeout, a full node, any
    /// other remote rejection.
    Failed,
}

/// The running count of one blob's store round.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PutTally {
    majority: usize,
    stored: usize,
    declined: usize,
    failed: usize,
}

impl PutTally {
    /// An empty tally for a round that is done once `majority` targets stored
    /// (the adapter passes upstream's `CLOSE_GROUP_MAJORITY`, 4 of 7). A
    /// majority of zero is read as one: no round is done before anything
    /// stored.
    #[must_use]
    pub const fn new(majority: usize) -> Self {
        Self {
            majority: if majority == 0 { 1 } else { majority },
            stored: 0,
            declined: 0,
            failed: 0,
        }
    }

    /// Count one target's answer.
    pub fn record(&mut self, reply: PutReply) {
        let slot = match reply {
            PutReply::Stored => &mut self.stored,
            PutReply::Declined => &mut self.declined,
            PutReply::Failed => &mut self.failed,
        };
        *slot = slot.saturating_add(1);
    }

    /// How many stores complete the round.
    #[must_use]
    pub const fn majority(&self) -> usize {
        self.majority
    }

    /// Targets that stored.
    #[must_use]
    pub const fn stored(&self) -> usize {
        self.stored
    }

    /// Targets that declined the payment proof.
    #[must_use]
    pub const fn declined(&self) -> usize {
        self.declined
    }

    /// Targets that failed for any reason other than payment.
    #[must_use]
    pub const fn failed(&self) -> usize {
        self.failed
    }

    /// Whether a majority stored: the round is done, and the blob is stored.
    #[must_use]
    pub const fn majority_stored(&self) -> bool {
        self.stored >= self.majority
    }

    /// Whether the declines **alone** made the majority unreachable (D179
    /// R2): the targets that did not decline are fewer than the majority —
    /// so even had every one of them stored, the round would still fall
    /// short — and the declines are at least a majority themselves, so a
    /// minority of targets can never be decisive however few targets there
    /// were.
    ///
    /// Meaningful once the targets have run out; before that, untried targets
    /// could still store.
    #[must_use]
    pub const fn declines_are_decisive(&self) -> bool {
        self.declined >= self.majority && self.stored.saturating_add(self.failed) < self.majority
    }
}

/// What a store round that has run out of targets (or reached its majority)
/// comes to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PutVerdict {
    /// A majority stored.
    Stored,
    /// A majority declined the payment proof, and the payment is more than
    /// [`PROOF_VALIDITY_WINDOW_SECS`] old by its block time: completing the
    /// seal needs a new, separately consented payment.
    ProofsExpired,
    /// Short of a majority for any other reason, or with a payment too young
    /// (or of unreadable age) to call expired: finalize again, paying
    /// nothing.
    Retry,
}

/// The verdict on a finished round (D179 R1–R3).
///
/// `paid_at_unix_secs` is the block timestamp of the payment ([`payment_time`]);
/// the adapter reads it only when [`PutTally::declines_are_decisive`] holds,
/// and passes `None` otherwise — which this function does not rely on: an age
/// alone never makes a round expired.
#[must_use]
pub fn verdict(tally: &PutTally, paid_at_unix_secs: Option<u64>, now_unix_secs: u64) -> PutVerdict {
    if tally.majority_stored() {
        return PutVerdict::Stored;
    }
    let expired =
        paid_at_unix_secs.is_some_and(|paid_at| payment_outlived_window(paid_at, now_unix_secs));
    if tally.declines_are_decisive() && expired {
        PutVerdict::ProofsExpired
    } else {
        PutVerdict::Retry
    }
}

/// Whether a payment made at `paid_at_unix_secs` is **more** than
/// [`PROOF_VALIDITY_WINDOW_SECS`] old at `now_unix_secs`. A payment time in
/// the future (clock skew) is age zero, never expired.
#[must_use]
pub const fn payment_outlived_window(paid_at_unix_secs: u64, now_unix_secs: u64) -> bool {
    now_unix_secs.saturating_sub(paid_at_unix_secs) > PROOF_VALIDITY_WINDOW_SECS
}

/// One transaction that paid for a blob, as the journaled receipt records it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PayingTx {
    /// The payment transaction's hash.
    pub tx_hash: TxHash,
    /// The receipt's block-number slot (D33 Decision 2). `None` when the
    /// journal never learned it — the adapter then asks the chain.
    pub block_number: Option<u64>,
}

/// The transactions that paid for `record`'s blob: each non-zero payment line,
/// through the receipt's quote→tx map, to its per-tx record. In the order of
/// the blob's payment lines, each transaction once.
///
/// A mapped hash with no per-tx record (a truncated journal) is still
/// returned, with no block number, so the adapter can ask the chain. A line
/// the map does not cover contributes nothing; `finalize_batch` refuses such a
/// receipt before any PUT (`PaymentReceipt::covers_all_paid_quotes`).
#[must_use]
pub fn paying_txs(receipt: &PaymentReceipt, record: &BlobPaymentRecord) -> Vec<PayingTx> {
    let mut paying: Vec<PayingTx> = Vec::new();
    for line in record.payments.iter().filter(|line| line.amount_atto > 0) {
        let Some(tx_hash) = receipt.tx_map.get(&line.quote_hash) else {
            continue;
        };
        if paying.iter().any(|seen| seen.tx_hash == *tx_hash) {
            continue;
        }
        let block_number = receipt
            .txs
            .iter()
            .find(|tx| tx.tx_hash == *tx_hash)
            .and_then(|tx| tx.block_number);
        paying.push(PayingTx {
            tx_hash: *tx_hash,
            block_number,
        });
    }
    paying
}

/// When a blob was paid for, from the block times of its paying transactions
/// ([`paying_txs`]): the **latest** of them — the youngest payment, so its
/// age is never overstated — or `None` when there is none or any one of them
/// could not be read. `None` is never expired (D179 R3).
#[must_use]
pub fn payment_time(block_times: &[Option<u64>]) -> Option<u64> {
    let mut latest: Option<u64> = None;
    for time in block_times {
        let time = (*time)?;
        latest = Some(latest.map_or(time, |seen| seen.max(time)));
    }
    latest
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::Address;
    use crate::quote::{QuoteHash, QuotePaymentEntry, RewardsAddress};
    use crate::receipt::{GasSummary, TxRecord, TxStatus};

    /// A fixed clock: every age below is relative to it.
    const NOW: u64 = 1_900_000_000;
    const HOUR: u64 = 60 * 60;
    /// Upstream's close-group majority at the pin (4 of 7), linked to
    /// `ant_protocol::CLOSE_GROUP_MAJORITY` by the feature build's
    /// `absence_needs_a_unanimous_majority_sized_sample`.
    const MAJORITY: usize = 4;

    /// A finished round of `stored` stores, `declined` declines and `failed`
    /// other failures.
    fn round(stored: usize, declined: usize, failed: usize) -> PutTally {
        let mut tally = PutTally::new(MAJORITY);
        for (reply, count) in [
            (PutReply::Stored, stored),
            (PutReply::Declined, declined),
            (PutReply::Failed, failed),
        ] {
            for _ in 0..count {
                tally.record(reply);
            }
        }
        assert_eq!(
            (tally.stored(), tally.declined(), tally.failed()),
            (stored, declined, failed),
            "the tally counts what it was told"
        );
        tally
    }

    /// **S43 B1.** One hostile decline among seven targets, the other six
    /// willing: the round stores at the fourth store, and nothing about the
    /// decline is decisive whatever the payment's age.
    #[test]
    fn s43_b1_one_decline_and_a_majority_of_stores_is_stored() {
        let tally = round(4, 1, 0);
        assert!(tally.majority_stored());
        assert!(!tally.declines_are_decisive());
        for paid_at in [Some(NOW - HOUR), Some(NOW - 72 * HOUR), None] {
            assert_eq!(
                verdict(&tally, paid_at, NOW),
                PutVerdict::Stored,
                "one hostile decline is one target's answer (S43 B1), paid_at={paid_at:?}"
            );
        }
    }

    /// **S43 B2.** Every target declines, but the payment is an hour old by
    /// its block time: not expired, whatever the quotes' own timestamps said —
    /// they are not an input at all.
    #[test]
    fn s43_b2_a_young_payment_is_never_expired_however_many_declined() {
        let tally = round(0, 7, 0);
        assert!(tally.declines_are_decisive());
        assert_eq!(
            verdict(&tally, Some(NOW - HOUR), NOW),
            PutVerdict::Retry,
            "a hostile majority expired a payment at 1 h chain age (S43 R3)"
        );
    }

    /// **S43 B3.** Two declines and five dial failures, payment a day and an
    /// hour old: the declines are not what made the majority unreachable, so
    /// re-paying would buy nothing a retry does not.
    #[test]
    fn s43_b3_declines_that_are_not_decisive_never_re_pay() {
        let tally = round(0, 2, 5);
        assert!(
            !tally.declines_are_decisive(),
            "2 declines of 7 are not decisive"
        );
        assert_eq!(
            verdict(&tally, Some(NOW - 25 * HOUR), NOW),
            PutVerdict::Retry,
            "declines not decisive, yet re-pay (S43 R2)"
        );
    }

    /// **S43 B4, the positive row.** Four declines and three stores, the
    /// payment a day and an hour old by its block time: the one shape that
    /// re-pays.
    #[test]
    fn s43_b4_a_declining_majority_over_an_old_payment_is_expired() {
        let tally = round(3, 4, 0);
        assert!(tally.declines_are_decisive());
        assert_eq!(
            verdict(&tally, Some(NOW - 25 * HOUR), NOW),
            PutVerdict::ProofsExpired
        );
        // Every target declining is the same verdict.
        assert_eq!(
            verdict(&round(0, 7, 0), Some(NOW - 25 * HOUR), NOW),
            PutVerdict::ProofsExpired
        );
    }

    /// **S43 B5.** A payment time that could not be read is never expired.
    #[test]
    fn s43_b5_an_unreadable_block_time_never_re_pays() {
        let tally = round(0, 7, 0);
        assert_eq!(
            verdict(&tally, None, NOW),
            PutVerdict::Retry,
            "unreadable block time re-pays (S43 R3)"
        );
        assert_eq!(payment_time(&[]), None, "no paying transaction");
        assert_eq!(
            payment_time(&[Some(NOW - 30 * HOUR), None]),
            None,
            "one unreadable paying transaction makes the whole time unreadable"
        );
    }

    /// **S43 B6.** The boundary: a payment exactly 24 h old is not expired;
    /// one second more is.
    #[test]
    fn s43_b6_exactly_the_window_is_not_expired_one_second_more_is() {
        let tally = round(0, 7, 0);
        let exactly = NOW - PROOF_VALIDITY_WINDOW_SECS;
        assert!(
            !payment_outlived_window(exactly, NOW),
            "exactly 24 h counted expired (S43 B6)"
        );
        assert_eq!(
            verdict(&tally, Some(exactly), NOW),
            PutVerdict::Retry,
            "exactly 24 h counted expired"
        );
        assert!(
            payment_outlived_window(exactly - 1, NOW),
            "24 h and one second is not expired (S43 B6)"
        );
        assert_eq!(
            verdict(&tally, Some(exactly - 1), NOW),
            PutVerdict::ProofsExpired
        );
        assert_eq!(PROOF_VALIDITY_WINDOW_SECS, 86_400);
        // A payment time ahead of the clock is age zero.
        assert!(!payment_outlived_window(NOW + HOUR, NOW));
    }

    /// The decisive predicate at every split of seven targets: declines are
    /// decisive exactly when four or more of seven declined, and a minority
    /// is never decisive however few targets there were.
    #[test]
    fn s43_declines_are_decisive_exactly_from_a_majority_of_seven() {
        for declined in 0..=7 {
            for stored in 0..=(7 - declined) {
                let failed = 7 - declined - stored;
                let tally = round(stored, declined, failed);
                assert_eq!(
                    tally.declines_are_decisive(),
                    declined >= MAJORITY,
                    "stored={stored} declined={declined} failed={failed}"
                );
            }
        }
        // Fewer targets than a close group: three declines of five make a
        // majority unreachable, but three is a minority of the close group —
        // never decisive.
        assert!(!round(0, 3, 2).declines_are_decisive());
        assert!(!round(0, 3, 0).declines_are_decisive());
        // A majority of zero is read as one.
        assert_eq!(PutTally::new(0).majority(), 1);
        assert!(!PutTally::new(0).majority_stored());
    }

    // ── paying_txs / payment_time ────────────────────────────────────────

    fn line(quote: u8, amount_atto: u128) -> QuotePaymentEntry {
        QuotePaymentEntry {
            quote_hash: QuoteHash::from_bytes([quote; 32]),
            rewards_address: RewardsAddress::from_bytes([0x33; 20]),
            amount_atto,
            price_atto: amount_atto,
        }
    }

    fn record(payments: Vec<QuotePaymentEntry>) -> BlobPaymentRecord {
        BlobPaymentRecord {
            address: Address::from_bytes([0x5A; 32]),
            payments,
            peer_quotes: Vec::new(),
            commitment_sidecars: Vec::new(),
            proof_bytes: vec![0x01],
        }
    }

    fn tx(byte: u8, block_number: Option<u64>) -> TxRecord {
        TxRecord {
            tx_hash: TxHash::from_bytes([byte; 32]),
            block_number,
            status: TxStatus::Confirmed,
            quote_hashes: Vec::new(),
        }
    }

    fn receipt(map: &[(u8, u8)], txs: Vec<TxRecord>) -> PaymentReceipt {
        PaymentReceipt {
            blobs: Vec::new(),
            tx_map: map
                .iter()
                .map(|(quote, tx)| {
                    (
                        QuoteHash::from_bytes([*quote; 32]),
                        TxHash::from_bytes([*tx; 32]),
                    )
                })
                .collect::<BTreeMap<_, _>>(),
            txs,
            storage_cost_atto: 0,
            gas: GasSummary { gas_cost_wei: 0 },
        }
    }

    /// The blob's paying transaction is found through the quote→tx map, with
    /// the block number its per-tx record holds; zero-amount lines and lines
    /// of other blobs contribute nothing.
    #[test]
    fn s43_the_paying_tx_is_found_through_the_quote_to_tx_map() {
        let receipt = receipt(
            &[(0xA1, 0x71), (0xB2, 0x72)],
            vec![tx(0x71, Some(1_234)), tx(0x72, None)],
        );
        let blob = record(vec![line(0xA0, 0), line(0xA1, 300), line(0xA2, 0)]);
        assert_eq!(
            paying_txs(&receipt, &blob),
            [PayingTx {
                tx_hash: TxHash::from_bytes([0x71; 32]),
                block_number: Some(1_234),
            }]
        );
    }

    /// A journal-first record with no block number yet, a mapped hash with no
    /// per-tx record, and two lines paid by one transaction.
    #[test]
    fn s43_unknown_block_numbers_are_left_for_the_chain_and_each_tx_counts_once() {
        let receipt = receipt(
            &[(0xA1, 0x72), (0xA2, 0x72), (0xA3, 0x7F)],
            vec![tx(0x72, None)],
        );
        let blob = record(vec![line(0xA1, 1), line(0xA2, 2), line(0xA3, 3)]);
        assert_eq!(
            paying_txs(&receipt, &blob),
            [
                PayingTx {
                    tx_hash: TxHash::from_bytes([0x72; 32]),
                    block_number: None,
                },
                PayingTx {
                    tx_hash: TxHash::from_bytes([0x7F; 32]),
                    block_number: None,
                },
            ]
        );
        // A line the map does not cover is not a paying transaction.
        let unmapped = record(vec![line(0xEE, 5)]);
        assert!(paying_txs(&receipt, &unmapped).is_empty());
    }

    /// The payment time is the youngest paying block, so an age is never
    /// overstated.
    #[test]
    fn s43_the_payment_time_is_the_latest_paying_block() {
        assert_eq!(
            payment_time(&[Some(NOW - 30 * HOUR)]),
            Some(NOW - 30 * HOUR)
        );
        assert_eq!(
            payment_time(&[
                Some(NOW - 30 * HOUR),
                Some(NOW - HOUR),
                Some(NOW - 50 * HOUR)
            ]),
            Some(NOW - HOUR)
        );
    }
}
