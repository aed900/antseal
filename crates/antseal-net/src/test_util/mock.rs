//! [`MockBackend`] — the deterministic in-memory [`StorageBackend`] with
//! fault injection and call-order logging (task S3).
//!
//! # Fidelity to the surveyed upstream (S1; mirrored per the S3 note)
//!
//! | Behavior | Upstream fact mirrored |
//! |---|---|
//! | already-stored blobs quote as zero-cost [`BlobCost::AlreadyStored`] lines and are never paid or re-stored | `prepare_chunk_payment` → `Ok(None)` (`ant-core-0.5.0/src/data/client/batch.rs:361-368`) |
//! | per blob: quotes sorted by price, the **median paid 3× its price, all others zero** | `batch.rs:59-95`; `SINGLE_NODE_PAYMENT_MULTIPLIER = 3` (`payment.rs:17`) |
//! | pay filters zero-amount entries, then splits into sub-batches of ≤ [`MockBackend::with_max_transfers_per_tx`] (default 256), **one tx per sub-batch, sequential** | `evmlib-0.9.0/src/wallet.rs:432-460`; `MAX_TRANSFERS_PER_TRANSACTION = 256` (`payment_vault/mod.rs:11`); D37 Decision 2 |
//! | finalize errors on any non-zero quote missing from the quote→tx map | `batch.rs:300-305` |
//! | finalize skips already-stored addresses, stores the rest, issues no payment | the pay/finalize split contract (spec line 69) |
//! | re-paying an already-paid quote hash moves money **again** (recorded in [`MockBackend::double_paid`]) — nothing on-chain dedupes; only correct resume logic prevents it | D37 Decision 3/5 |
//!
//! # Determinism
//!
//! The mock never reads a clock or an RNG. Synthetic material (quote
//! hashes, tx hashes, peer ids, prices, block numbers, preimage
//! timestamps) derives from internal counters and blob bytes via a
//! non-cryptographic digest, so two identically-driven mocks produce
//! byte-identical quotes, receipts, and call logs — and re-quoting mints
//! **fresh** quote hashes (a per-call round counter), exactly as
//! upstream's timestamped quotes do, which is what makes the D36
//! "a journaled quote is never paid" tests meaningful.
//!
//! # Addresses — the one stand-in, and its S4 seam
//!
//! The real address rule is BLAKE3-256 of the blob bytes (D32), owned by
//! S4's `compute_storage_address` in `antseal-core` — **not yet landed**
//! when S3 executed. The mock therefore takes an injectable address
//! function ([`MockBackend::with_address_fn`]); its default is a
//! deterministic non-cryptographic stand-in that is NOT the network rule.
//! Pipeline tests that compare manifest-recorded addresses against
//! backend-returned ones must inject S4's function (task S21 flips the
//! default to it once S4 lands, deleting the stand-in).
//!
//! # Faults
//!
//! One-shot, armed via [`MockBackend::arm_fault`], covering every
//! S16/S18 kill point reachable at the backend boundary: after-quote,
//! after-pay-before-store, between sub-batch txs (D37), after storing k
//! of n, during get_data, and per-method network errors. Per-sub-batch
//! *journal-hook* mechanics (the S6/S7 pay design) are deliberately not
//! simulated here — the mock exposes the stranded state and per-tx
//! records those tasks build their capture timing on.
//!
//! [`StorageBackend`]: crate::StorageBackend
//! [`BlobCost::AlreadyStored`]: crate::BlobCost::AlreadyStored

use std::collections::BTreeMap;
use std::sync::Mutex;

use crate::quote::{
    BlobCost, BlobQuote, CostQuote, EncodedPeerId, PeerQuote, QuoteHash, QuotePaymentEntry,
    QuotePreimage, RewardsAddress, TxHash,
};
use crate::receipt::{BlobPaymentRecord, GasSummary, PaymentReceipt, TxRecord, TxStatus};
use crate::{Address, Blob, StorageBackend, StorageError};

/// Default sub-batch cap: upstream `MAX_TRANSFERS_PER_TRANSACTION = 256`
/// (`evmlib-0.9.0/src/contract/payment_vault/mod.rs:11`). One non-zero
/// transfer per blob (median-×3 rule) ⇒ 256 blobs per tx.
pub const DEFAULT_MAX_TRANSFERS_PER_TX: usize = 256;

/// The four [`StorageBackend`] operations, as call-log identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    /// `quote_batch`.
    QuoteBatch,
    /// `pay`.
    Pay,
    /// `finalize_batch`.
    FinalizeBatch,
    /// `get_data`.
    GetData,
}

/// One armed, one-shot fault. Each fires the first time execution
/// reaches its named point, then disarms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fault {
    /// `quote_batch` completes its quote computation, then the response
    /// is lost: returns [`StorageError::Network`], no state change.
    AfterQuote,
    /// `pay` lands **every** sub-batch tx (money moved, internal paid
    /// state updated), then fails before the caller can see the receipt
    /// — the post-pay/pre-receipt-journal crash window. Returns
    /// [`StorageError::StrandedPayment`].
    AfterPayBeforeStore,
    /// `pay` lands exactly `k` sub-batch txs, then fails **between
    /// sub-batches** (the D37 mid-sequence kill point). Returns
    /// [`StorageError::StrandedPayment`] with `landed_tx_count = k`.
    /// Never fires if the payment needs ≤ `k` txs (stays armed).
    AfterSubBatches(usize),
    /// `finalize_batch` stores exactly `k` blobs, then aborts before the
    /// next store — the partial-store kill point. Skipped
    /// (already-stored) blobs do not count toward `k`. Never fires if
    /// fewer than `k + 1` stores are needed (stays armed).
    AfterStoringK(usize),
    /// `get_data` fails with [`StorageError::Network`] before reading
    /// the store.
    DuringGetData,
    /// The named method fails with [`StorageError::Network`] on entry,
    /// before any state change.
    NetworkOn(Method),
}

/// One call-log entry. The record's position in
/// [`MockBackend::call_log`] is its global sequence number.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallRecord {
    /// Which operation was invoked.
    pub method: Method,
    /// Deterministic digest of the call's arguments — equal args ⇒ equal
    /// digest, so tests can assert "finalize was retried with the same
    /// receipt/blobs" without holding the args themselves.
    pub args_digest: [u8; 32],
}

#[derive(Default)]
struct Inner {
    store: BTreeMap<Address, Vec<u8>>,
    /// Total store *writes* ever performed (never decremented; skips do
    /// not count) — the idempotency counter.
    store_events: u64,
    paid: BTreeMap<QuoteHash, TxHash>,
    double_paid: Vec<QuoteHash>,
    quote_rounds: u64,
    tx_counter: u64,
    log: Vec<CallRecord>,
    faults: Vec<Fault>,
}

/// The in-memory [`StorageBackend`] all storage-touching tests run on.
///
/// See the module docs for the fidelity table, determinism guarantees,
/// the address-function seam, and the fault set. All state sits behind a
/// `Mutex`, so `&self` methods compose with the trait's `&self` receivers
/// and the mock can be shared by reference within a test.
pub struct MockBackend {
    address_fn: fn(&[u8]) -> Address,
    max_transfers_per_tx: usize,
    base_price_atto: u128,
    inner: Mutex<Inner>,
}

impl Default for MockBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl MockBackend {
    /// A mock with the default (stand-in) address function, the upstream
    /// 256-transfer sub-batch cap, and a base price of 100 atto-ANT.
    #[must_use]
    pub fn new() -> Self {
        Self {
            address_fn: standin_address,
            max_transfers_per_tx: DEFAULT_MAX_TRANSFERS_PER_TX,
            base_price_atto: 100,
            inner: Mutex::new(Inner::default()),
        }
    }

    /// Replace the blob→address function (module docs: inject S4's
    /// `compute_storage_address` wherever manifest-recorded addresses
    /// must agree with backend-returned ones).
    #[must_use]
    pub fn with_address_fn(mut self, address_fn: fn(&[u8]) -> Address) -> Self {
        self.address_fn = address_fn;
        self
    }

    /// Force a smaller sub-batch cap so multi-tx payments are testable
    /// with small batches (S7/S16: "mock-forced sub-batch size"). Values
    /// below 1 are clamped to 1.
    #[must_use]
    pub fn with_max_transfers_per_tx(mut self, cap: usize) -> Self {
        self.max_transfers_per_tx = cap.max(1);
        self
    }

    /// Change the deterministic base price (atto-ANT) quotes derive from.
    #[must_use]
    pub fn with_base_price(mut self, base_price_atto: u128) -> Self {
        self.base_price_atto = base_price_atto;
        self
    }

    /// Arm a one-shot [`Fault`]. Multiple faults may be armed; each fires
    /// independently at its own point.
    pub fn arm_fault(&self, fault: Fault) {
        self.lock().faults.push(fault);
    }

    /// Number of armed (not yet fired) faults.
    #[must_use]
    pub fn armed_faults(&self) -> usize {
        self.lock().faults.len()
    }

    /// Simulate a chunk some third party already paid for and stored:
    /// seeds the store directly (no payment, no log entry) and returns
    /// its address. Subsequent quotes for the same bytes come back as
    /// zero-cost [`BlobCost::AlreadyStored`] lines.
    pub fn preload_third_party(&self, bytes: &[u8]) -> Address {
        let address = (self.address_fn)(bytes);
        let mut inner = self.lock();
        inner.store.entry(address).or_insert_with(|| bytes.to_vec());
        address
    }

    /// Whether a chunk exists at `address`.
    #[must_use]
    pub fn contains(&self, address: Address) -> bool {
        self.lock().store.contains_key(&address)
    }

    /// The stored bytes at `address`, if any.
    #[must_use]
    pub fn stored(&self, address: Address) -> Option<Vec<u8>> {
        self.lock().store.get(&address).cloned()
    }

    /// Number of distinct chunks currently stored.
    #[must_use]
    pub fn stored_count(&self) -> usize {
        self.lock().store.len()
    }

    /// Total store **writes** ever performed (skips excluded) — the
    /// idempotency counter: a re-finalize that stores nothing leaves it
    /// unchanged.
    #[must_use]
    pub fn store_events(&self) -> u64 {
        self.lock().store_events
    }

    /// Total payment sub-batch transactions ever landed.
    #[must_use]
    pub fn payment_tx_count(&self) -> u64 {
        self.lock().tx_counter
    }

    /// Snapshot of the cumulative quote→tx paid map.
    #[must_use]
    pub fn paid_map(&self) -> BTreeMap<QuoteHash, TxHash> {
        self.lock().paid.clone()
    }

    /// Quote hashes that were paid **more than once** — money moved
    /// twice. A correct pipeline/resume never produces any; tests assert
    /// this is empty.
    #[must_use]
    pub fn double_paid(&self) -> Vec<QuoteHash> {
        self.lock().double_paid.clone()
    }

    /// The full call log, in invocation order.
    #[must_use]
    pub fn call_log(&self) -> Vec<CallRecord> {
        self.lock().log.clone()
    }

    /// How many times `method` was invoked (fault-failed calls count:
    /// the call happened).
    #[must_use]
    pub fn calls(&self, method: Method) -> usize {
        self.lock()
            .log
            .iter()
            .filter(|r| r.method == method)
            .count()
    }

    /// Global sequence index of the first `method` invocation, if any —
    /// the primitive ordering assertions are built from.
    #[must_use]
    pub fn first_index_of(&self, method: Method) -> Option<usize> {
        self.lock().log.iter().position(|r| r.method == method)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().expect("MockBackend state mutex poisoned")
    }

    /// Consume the first armed fault matching `predicate`, if any.
    fn take_fault(inner: &mut Inner, predicate: impl Fn(Fault) -> bool) -> Option<Fault> {
        let position = inner.faults.iter().position(|&f| predicate(f))?;
        Some(inner.faults.remove(position))
    }

    fn network_fault(inner: &mut Inner, method: Method, label: &str) -> Option<StorageError> {
        Self::take_fault(inner, |f| f == Fault::NetworkOn(method)).map(|_| StorageError::Network {
            reason: format!("injected network fault: {label}"),
        })
    }
}

impl StorageBackend for MockBackend {
    async fn quote_batch(&self, blobs: &[Blob]) -> Result<CostQuote, StorageError> {
        let mut inner = self.lock();
        let args: Vec<&[u8]> = blobs.iter().map(Blob::as_bytes).collect();
        let digest = mock_digest_tagged(b"log-quote_batch", &args);
        inner.log.push(CallRecord {
            method: Method::QuoteBatch,
            args_digest: digest,
        });
        if let Some(err) = Self::network_fault(&mut inner, Method::QuoteBatch, "quote_batch") {
            return Err(err);
        }

        inner.quote_rounds += 1;
        let round = inner.quote_rounds;

        let mut lines = Vec::with_capacity(blobs.len());
        let mut total_ant_atto: u128 = 0;
        let mut priced_blobs: u128 = 0;
        for blob in blobs {
            let address = (self.address_fn)(blob.as_bytes());
            let cost = if inner.store.contains_key(&address) {
                // Zero-cost already-stored line (upstream `Ok(None)`).
                BlobCost::AlreadyStored
            } else {
                priced_blobs += 1;
                let (payments, peer_quotes, amount) =
                    self.synthesize_quotes(round, address, blob.len());
                total_ant_atto = total_ant_atto.saturating_add(amount);
                BlobCost::Priced {
                    payments,
                    peer_quotes,
                    commitment_sidecars: Vec::new(),
                }
            };
            lines.push(BlobQuote { address, cost });
        }

        if Self::take_fault(&mut inner, |f| f == Fault::AfterQuote).is_some() {
            return Err(StorageError::Network {
                reason: "injected fault: after-quote (quote computed, response lost)".into(),
            });
        }

        Ok(CostQuote {
            blobs: lines,
            total_ant_atto,
            // Deterministic, arbitrary gas model: a flat base plus a
            // per-priced-blob increment.
            gas_estimate_wei: 21_000_u128.saturating_add(priced_blobs.saturating_mul(1_000)),
        })
    }

    async fn pay(&self, quote: &CostQuote) -> Result<PaymentReceipt, StorageError> {
        let mut inner = self.lock();
        let digest = pay_args_digest(quote);
        inner.log.push(CallRecord {
            method: Method::Pay,
            args_digest: digest,
        });
        if let Some(err) = Self::network_fault(&mut inner, Method::Pay, "pay") {
            return Err(err);
        }

        // Zero-amount entries are filtered before sub-batching — the
        // evmlib `pay_for_quotes` semantics (wallet.rs:432-460).
        let mut transfers: Vec<QuoteHash> = Vec::new();
        for line in &quote.blobs {
            if let BlobCost::Priced { payments, .. } = &line.cost {
                transfers.extend(
                    payments
                        .iter()
                        .filter(|p| p.amount_atto > 0)
                        .map(|p| p.quote_hash),
                );
            }
        }

        // Sequential sub-batches of ≤ cap transfers, one tx each (D37).
        let sub_batches: Vec<&[QuoteHash]> = transfers.chunks(self.max_transfers_per_tx).collect();
        let stop_after = Self::take_fault(&mut inner, |f| matches!(f, Fault::AfterSubBatches(_)))
            .and_then(|f| match f {
                Fault::AfterSubBatches(k) if k < sub_batches.len() => Some(k),
                // Fewer txs than k: the fault cannot fire; re-arm it.
                Fault::AfterSubBatches(_) => {
                    inner.faults.push(f);
                    None
                }
                _ => None,
            });

        let mut txs = Vec::with_capacity(sub_batches.len());
        for (index, sub_batch) in sub_batches.iter().enumerate() {
            if stop_after == Some(index) {
                return Err(StorageError::StrandedPayment {
                    landed_tx_count: index,
                    reason: "injected fault: killed between payment sub-batch txs".into(),
                });
            }
            inner.tx_counter += 1;
            let tx_hash = TxHash::from_bytes(mock_digest_tagged(
                b"mock-tx",
                &[&inner.tx_counter.to_le_bytes()],
            ));
            for quote_hash in *sub_batch {
                if inner.paid.insert(*quote_hash, tx_hash).is_some() {
                    inner.double_paid.push(*quote_hash);
                }
            }
            txs.push(TxRecord {
                tx_hash,
                // "Landed instantly": the block number is available from
                // the awaited receipt (D33's primary-flow shape).
                block_number: Some(1_000_000 + inner.tx_counter),
                status: TxStatus::Confirmed,
                quote_hashes: sub_batch.to_vec(),
            });
        }

        let tx_map: BTreeMap<QuoteHash, TxHash> = txs
            .iter()
            .flat_map(|tx| tx.quote_hashes.iter().map(|qh| (*qh, tx.tx_hash)))
            .collect();

        let blobs = quote
            .blobs
            .iter()
            .filter_map(|line| match &line.cost {
                BlobCost::AlreadyStored => None,
                BlobCost::Priced {
                    payments,
                    peer_quotes,
                    commitment_sidecars,
                } => {
                    Some(BlobPaymentRecord {
                        address: line.address,
                        payments: payments.clone(),
                        peer_quotes: peer_quotes.clone(),
                        commitment_sidecars: commitment_sidecars.clone(),
                        // Clearly-synthetic opaque bytes: NOT upstream's
                        // tag+rmp encoding, never parseable by
                        // `deserialize_proof` (S7's capture-consistency
                        // test runs on the real adapter, not this mock).
                        proof_bytes: synthetic_proof_bytes(line.address, &tx_map),
                    })
                }
            })
            .collect();

        let receipt = PaymentReceipt {
            blobs,
            tx_map,
            txs,
            storage_cost_atto: quote.total_ant_atto,
            gas: GasSummary {
                gas_cost_wei: quote.gas_estimate_wei,
            },
        };

        if Self::take_fault(&mut inner, |f| f == Fault::AfterPayBeforeStore).is_some() {
            return Err(StorageError::StrandedPayment {
                landed_tx_count: receipt.txs.len(),
                reason:
                    "injected fault: after-pay-before-store (txs landed, receipt lost pre-journal)"
                        .into(),
            });
        }

        Ok(receipt)
    }

    async fn finalize_batch(
        &self,
        receipt: &PaymentReceipt,
        blobs: &[Blob],
    ) -> Result<Vec<Address>, StorageError> {
        let mut inner = self.lock();
        let digest = finalize_args_digest(receipt, blobs);
        inner.log.push(CallRecord {
            method: Method::FinalizeBatch,
            args_digest: digest,
        });
        if let Some(err) = Self::network_fault(&mut inner, Method::FinalizeBatch, "finalize_batch")
        {
            return Err(err);
        }

        let mut addresses = Vec::with_capacity(blobs.len());
        let mut stored_this_call: usize = 0;
        for blob in blobs {
            let address = (self.address_fn)(blob.as_bytes());
            addresses.push(address);

            // Idempotency: already-stored addresses are skipped — whether
            // stored by an earlier finalize, a partial store, or a third
            // party. No payment check applies to a skip.
            if inner.store.contains_key(&address) {
                continue;
            }

            // Not stored: the receipt must cover it — per-blob record
            // present and every non-zero line mapped to a tx (the
            // upstream gap rule, batch.rs:300-305).
            let record = receipt
                .blobs
                .iter()
                .find(|r| r.address == address)
                .ok_or_else(|| StorageError::Finalize {
                    reason: format!("no payment record for unstored blob at address {address}"),
                })?;
            if let Some(gap) = record
                .payments
                .iter()
                .find(|p| p.amount_atto > 0 && !receipt.tx_map.contains_key(&p.quote_hash))
            {
                // Count-only detail: quote hashes stay out of messages.
                let _ = gap;
                return Err(StorageError::Finalize {
                    reason: format!(
                        "quote→tx map gap for blob at address {address}: a non-zero quote has no \
                         tx hash"
                    ),
                });
            }

            // The after-storing-k-of-n kill point: k stores done, the
            // (k+1)-th is about to happen — abort instead.
            if let Some(Fault::AfterStoringK(_)) = Self::take_fault(
                &mut inner,
                |f| matches!(f, Fault::AfterStoringK(k) if k == stored_this_call),
            ) {
                return Err(StorageError::Network {
                    reason: format!(
                        "injected fault: aborted after storing {stored_this_call} blob(s)"
                    ),
                });
            }

            inner.store.insert(address, blob.as_bytes().to_vec());
            inner.store_events += 1;
            stored_this_call += 1;
        }

        Ok(addresses)
    }

    async fn get_data(&self, address: Address) -> Result<Vec<u8>, StorageError> {
        let mut inner = self.lock();
        let digest = mock_digest_tagged(b"log-get_data", &[address.as_bytes()]);
        inner.log.push(CallRecord {
            method: Method::GetData,
            args_digest: digest,
        });
        if let Some(err) = Self::network_fault(&mut inner, Method::GetData, "get_data") {
            return Err(err);
        }
        if Self::take_fault(&mut inner, |f| f == Fault::DuringGetData).is_some() {
            return Err(StorageError::Network {
                reason: "injected fault: during-get_data".into(),
            });
        }
        inner
            .store
            .get(&address)
            .cloned()
            .ok_or(StorageError::NotFound { address })
    }
}

impl MockBackend {
    /// Three synthetic peer quotes per blob, prices `p`, `p+1`, `p+2`
    /// (already price-sorted); the median (index 1) is paid 3× its
    /// price, the others zero — the upstream single-node payment shape.
    /// Returns `(payment lines, peer quotes, paid amount)`.
    fn synthesize_quotes(
        &self,
        round: u64,
        address: Address,
        blob_len: usize,
    ) -> (Vec<QuotePaymentEntry>, Vec<PeerQuote>, u128) {
        let base = self.base_price_atto.saturating_add(blob_len as u128);
        let mut payments = Vec::with_capacity(3);
        let mut peer_quotes = Vec::with_capacity(3);
        let mut paid_amount: u128 = 0;
        for peer_index in 0u8..3 {
            let price_atto = base.saturating_add(u128::from(peer_index));
            let amount_atto = if peer_index == 1 {
                paid_amount = price_atto.saturating_mul(3);
                paid_amount
            } else {
                0
            };
            let quote_hash = QuoteHash::from_bytes(mock_digest_tagged(
                b"mock-quote",
                &[&round.to_le_bytes(), address.as_bytes(), &[peer_index]],
            ));
            let peer_id = EncodedPeerId::from_bytes(mock_digest_tagged(
                b"mock-peer",
                &[address.as_bytes(), &[peer_index]],
            ));
            let rewards_address = {
                let digest =
                    mock_digest_tagged(b"mock-rewards", &[address.as_bytes(), &[peer_index]]);
                let mut bytes = [0u8; 20];
                bytes.copy_from_slice(&digest[..20]);
                RewardsAddress::from_bytes(bytes)
            };
            payments.push(QuotePaymentEntry {
                quote_hash,
                rewards_address,
                amount_atto,
                price_atto,
            });
            peer_quotes.push(PeerQuote {
                peer_id,
                quote: QuotePreimage {
                    content: address,
                    // Deterministic fake clock: the quote round. The mock
                    // never reads wall time.
                    timestamp_unix_secs: round,
                    price_atto,
                    rewards_address,
                    node_pub_key: mock_digest_tagged(b"mock-node-key", &[peer_id.as_bytes()])
                        .to_vec(),
                    node_signature: mock_digest_tagged(b"mock-node-sig", &[peer_id.as_bytes()])
                        .to_vec(),
                    committed_key_count: 0,
                    commitment_pin: None,
                },
            });
        }
        (payments, peer_quotes, paid_amount)
    }
}

/// Deterministic argument digest for a `pay` call: the quote's totals and
/// every (address, quote-hash, amount) line.
fn pay_args_digest(quote: &CostQuote) -> [u8; 32] {
    let mut parts: Vec<Vec<u8>> = vec![
        quote.total_ant_atto.to_le_bytes().to_vec(),
        quote.gas_estimate_wei.to_le_bytes().to_vec(),
    ];
    for line in &quote.blobs {
        parts.push(line.address.as_bytes().to_vec());
        if let BlobCost::Priced { payments, .. } = &line.cost {
            for p in payments {
                parts.push(p.quote_hash.as_bytes().to_vec());
                parts.push(p.amount_atto.to_le_bytes().to_vec());
            }
        }
    }
    let views: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
    mock_digest_tagged(b"log-pay", &views)
}

/// Deterministic argument digest for a `finalize_batch` call: the
/// receipt's tx hashes plus every blob's bytes.
fn finalize_args_digest(receipt: &PaymentReceipt, blobs: &[Blob]) -> [u8; 32] {
    let mut parts: Vec<Vec<u8>> = receipt
        .txs
        .iter()
        .map(|tx| tx.tx_hash.as_bytes().to_vec())
        .collect();
    for blob in blobs {
        parts.push(blob.as_bytes().to_vec());
    }
    let views: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
    mock_digest_tagged(b"log-finalize_batch", &views)
}

/// Clearly-synthetic opaque proof bytes (marker-prefixed; not upstream's
/// tag+rmp encoding).
fn synthetic_proof_bytes(address: Address, tx_map: &BTreeMap<QuoteHash, TxHash>) -> Vec<u8> {
    let tx_bytes: Vec<&[u8]> = tx_map.values().map(|tx| tx.as_bytes().as_slice()).collect();
    let mut parts: Vec<&[u8]> = vec![address.as_bytes()];
    parts.extend(tx_bytes);
    let digest = mock_digest_tagged(b"mock-proof", &parts);
    let mut bytes = b"ANTSEAL-MOCK-PROOF\x00".to_vec();
    bytes.extend_from_slice(&digest);
    bytes
}

/// The default blob→address stand-in (module docs): deterministic and
/// well-dispersed but **non-cryptographic and NOT the network's
/// BLAKE3-256 rule** — S21 replaces it with S4's
/// `compute_storage_address` as the default.
fn standin_address(bytes: &[u8]) -> Address {
    Address::from_bytes(mock_digest_tagged(b"mock-address", &[bytes]))
}

/// 32-byte deterministic digest: four FNV-1a-64 lanes with distinct
/// seeds over length-framed parts, finalized with a 64-bit mix. Test
/// infrastructure only — never a security boundary.
fn mock_digest_tagged(tag: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;
    fn absorb(data: &[u8], h: &mut u64) {
        for &byte in data {
            *h = (*h ^ u64::from(byte)).wrapping_mul(FNV_PRIME);
        }
    }
    let mut out = [0u8; 32];
    for lane in 0u64..4 {
        let mut h = FNV_OFFSET ^ lane.wrapping_mul(0x9e37_79b9_7f4a_7c15);
        absorb(&(tag.len() as u64).to_le_bytes(), &mut h);
        absorb(tag, &mut h);
        for part in parts {
            absorb(&(part.len() as u64).to_le_bytes(), &mut h);
            absorb(part, &mut h);
        }
        h ^= h >> 33;
        h = h.wrapping_mul(0xff51_afd7_ed55_8ccd);
        h ^= h >> 33;
        out[usize::try_from(lane).expect("lane < 4") * 8..][..8].copy_from_slice(&h.to_le_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::block_on;

    fn blobs(specs: &[(u8, usize)]) -> Vec<Blob> {
        specs
            .iter()
            .map(|&(fill, len)| Blob::new(vec![fill; len]).expect("test blob under cap"))
            .collect()
    }

    #[test]
    fn happy_path_round_trips_and_logs_in_order() {
        let mock = MockBackend::new();
        let batch = blobs(&[(1, 300), (2, 700), (3, 42)]);

        let quote = block_on(mock.quote_batch(&batch)).expect("quote");
        assert_eq!(quote.blobs.len(), 3);
        // Median-×3 totals: per blob 3 × (base + len + 1).
        let expected: u128 = [300u128, 700, 42]
            .iter()
            .map(|len| (100 + len + 1) * 3)
            .sum();
        assert_eq!(quote.total_ant_atto, expected);

        let receipt = block_on(mock.pay(&quote)).expect("pay");
        assert!(receipt.covers_all_paid_quotes());
        assert_eq!(receipt.txs.len(), 1, "3 transfers fit one sub-batch");
        assert_eq!(receipt.tx_map.len(), 3, "one non-zero quote per blob");
        assert_eq!(receipt.storage_cost_atto, quote.total_ant_atto);
        assert!(
            receipt.txs[0].block_number.is_some(),
            "D33 slot filled on landing"
        );

        let addresses = block_on(mock.finalize_batch(&receipt, &batch)).expect("finalize");
        assert_eq!(addresses.len(), 3);
        assert_eq!(mock.stored_count(), 3);
        for (blob, address) in batch.iter().zip(&addresses) {
            let fetched = block_on(mock.get_data(*address)).expect("stored");
            assert_eq!(fetched, blob.as_bytes());
        }

        // The ordering primitive, consumed here (S3 accept): quote
        // strictly precedes pay, pay strictly precedes finalize.
        let quote_at = mock.first_index_of(Method::QuoteBatch).expect("quoted");
        let pay_at = mock.first_index_of(Method::Pay).expect("paid");
        let finalize_at = mock
            .first_index_of(Method::FinalizeBatch)
            .expect("finalized");
        assert!(
            quote_at < pay_at && pay_at < finalize_at,
            "pipeline order via call log"
        );
    }

    #[test]
    fn already_stored_by_third_party_quotes_zero_and_is_never_paid_or_restored() {
        let mock = MockBackend::new();
        let batch = blobs(&[(7, 100), (8, 200)]);
        let preloaded = mock.preload_third_party(batch[0].as_bytes());

        let quote = block_on(mock.quote_batch(&batch)).expect("quote");
        assert!(matches!(quote.blobs[0].cost, BlobCost::AlreadyStored));
        assert!(matches!(quote.blobs[1].cost, BlobCost::Priced { .. }));
        assert_eq!(
            quote.total_ant_atto,
            (100 + 200 + 1) * 3,
            "only the unstored blob costs"
        );

        let receipt = block_on(mock.pay(&quote)).expect("pay");
        assert_eq!(
            receipt.blobs.len(),
            1,
            "no payment record for the already-stored blob"
        );
        assert_eq!(receipt.tx_map.len(), 1);

        let store_events_before = mock.store_events();
        let addresses = block_on(mock.finalize_batch(&receipt, &batch)).expect("finalize");
        assert_eq!(addresses[0], preloaded);
        assert_eq!(
            mock.store_events(),
            store_events_before + 1,
            "only the new blob was written"
        );
        assert_eq!(
            block_on(mock.get_data(preloaded)).expect("served"),
            batch[0].as_bytes()
        );
    }

    #[test]
    fn finalize_is_idempotent_and_partial_store_resumes_without_new_payment() {
        let mock = MockBackend::new();
        let batch = blobs(&[(1, 10), (2, 20), (3, 30)]);
        let quote = block_on(mock.quote_batch(&batch)).expect("quote");
        let receipt = block_on(mock.pay(&quote)).expect("pay");

        // Kill after storing 1 of 3.
        mock.arm_fault(Fault::AfterStoringK(1));
        let err = block_on(mock.finalize_batch(&receipt, &batch)).expect_err("injected abort");
        assert!(matches!(err, StorageError::Network { .. }));
        assert_eq!(mock.stored_count(), 1);
        assert_eq!(mock.store_events(), 1);

        // Resume: same receipt, same blobs — stores only the missing two.
        let first = block_on(mock.finalize_batch(&receipt, &batch)).expect("resumed finalize");
        assert_eq!(mock.stored_count(), 3);
        assert_eq!(mock.store_events(), 3, "nothing stored twice");

        // Double finalize: same address vector back, zero new writes,
        // and pay was never re-invoked (call log).
        let second = block_on(mock.finalize_batch(&receipt, &batch)).expect("re-finalize");
        assert_eq!(first, second);
        assert_eq!(mock.store_events(), 3);
        assert_eq!(mock.calls(Method::Pay), 1, "pay never called twice");
        assert_eq!(mock.payment_tx_count(), 1);
        assert!(mock.double_paid().is_empty());
    }

    #[test]
    fn forced_sub_batch_size_yields_sequential_multi_tx_receipts() {
        let mock = MockBackend::new().with_max_transfers_per_tx(2);
        let batch = blobs(&[(1, 1), (2, 2), (3, 3), (4, 4), (5, 5)]);
        let quote = block_on(mock.quote_batch(&batch)).expect("quote");
        let receipt = block_on(mock.pay(&quote)).expect("pay");

        assert_eq!(receipt.txs.len(), 3, "ceil(5 transfers / 2 per tx)");
        assert_eq!(receipt.tx_map.len(), 5, "every non-zero quote mapped");
        assert!(receipt.covers_all_paid_quotes());
        // Sub-batches partition the transfer list in order: 2 + 2 + 1.
        let sizes: Vec<usize> = receipt.txs.iter().map(|tx| tx.quote_hashes.len()).collect();
        assert_eq!(sizes, vec![2, 2, 1]);
        // Block numbers are strictly increasing — sequential landing.
        let blocks: Vec<u64> = receipt
            .txs
            .iter()
            .map(|tx| tx.block_number.expect("landed"))
            .collect();
        assert!(blocks.windows(2).all(|w| w[0] < w[1]));
        // Every tx's quotes map to that tx.
        for tx in &receipt.txs {
            for qh in &tx.quote_hashes {
                assert_eq!(receipt.tx_map.get(qh), Some(&tx.tx_hash));
            }
        }
    }

    #[test]
    fn kill_between_sub_batches_strands_exactly_k_txs() {
        let mock = MockBackend::new().with_max_transfers_per_tx(2);
        let batch = blobs(&[(1, 1), (2, 2), (3, 3), (4, 4), (5, 5)]);
        let quote = block_on(mock.quote_batch(&batch)).expect("quote");

        mock.arm_fault(Fault::AfterSubBatches(1));
        let err = block_on(mock.pay(&quote)).expect_err("mid-sequence kill");
        match err {
            StorageError::StrandedPayment {
                landed_tx_count, ..
            } => {
                assert_eq!(landed_tx_count, 1);
            }
            other => panic!("expected StrandedPayment, got {other:?}"),
        }
        assert_eq!(mock.payment_tx_count(), 1, "exactly one sub-batch landed");
        assert_eq!(
            mock.paid_map().len(),
            2,
            "the first sub-batch's two quotes are paid"
        );
    }

    #[test]
    fn after_pay_before_store_moves_money_but_loses_the_receipt() {
        let mock = MockBackend::new();
        let batch = blobs(&[(9, 50)]);
        let quote = block_on(mock.quote_batch(&batch)).expect("quote");

        mock.arm_fault(Fault::AfterPayBeforeStore);
        let err = block_on(mock.pay(&quote)).expect_err("receipt lost");
        assert!(matches!(
            err,
            StorageError::StrandedPayment {
                landed_tx_count: 1,
                ..
            }
        ));
        assert_eq!(mock.payment_tx_count(), 1, "money moved");
        assert_eq!(mock.stored_count(), 0, "nothing stored");

        // A D36-correct retry re-quotes (fresh hashes) and re-pays: no
        // double payment of any single quote hash is recorded.
        let requote = block_on(mock.quote_batch(&batch)).expect("re-quote");
        let receipt = block_on(mock.pay(&requote)).expect("re-pay");
        assert!(
            mock.double_paid().is_empty(),
            "fresh quote hashes, no per-quote double pay"
        );
        assert_eq!(mock.payment_tx_count(), 2);
        block_on(mock.finalize_batch(&receipt, &batch)).expect("finalize");
        assert_eq!(mock.stored_count(), 1);
    }

    #[test]
    fn paying_the_same_quote_object_twice_is_detected() {
        let mock = MockBackend::new();
        let batch = blobs(&[(4, 10)]);
        let quote = block_on(mock.quote_batch(&batch)).expect("quote");
        block_on(mock.pay(&quote)).expect("first pay");
        block_on(mock.pay(&quote)).expect("incorrect second pay of the same quote");
        assert_eq!(
            mock.double_paid().len(),
            1,
            "the same quote hash paid twice is recorded"
        );
    }

    #[test]
    fn quote_and_get_data_faults_are_one_shot() {
        let mock = MockBackend::new();
        let batch = blobs(&[(1, 5)]);

        mock.arm_fault(Fault::AfterQuote);
        let err = block_on(mock.quote_batch(&batch)).expect_err("after-quote fault");
        assert!(matches!(err, StorageError::Network { .. }));
        let quote = block_on(mock.quote_batch(&batch)).expect("fault disarmed");

        mock.arm_fault(Fault::NetworkOn(Method::Pay));
        let err = block_on(mock.pay(&quote)).expect_err("network fault on pay");
        assert!(matches!(err, StorageError::Network { .. }));
        assert_eq!(
            mock.payment_tx_count(),
            0,
            "network fault fires before side effects"
        );
        let receipt = block_on(mock.pay(&quote)).expect("pay after disarm");
        let addresses = block_on(mock.finalize_batch(&receipt, &batch)).expect("finalize");

        mock.arm_fault(Fault::DuringGetData);
        let err = block_on(mock.get_data(addresses[0])).expect_err("get_data fault");
        assert!(matches!(err, StorageError::Network { .. }));
        let bytes = block_on(mock.get_data(addresses[0])).expect("served after disarm");
        assert_eq!(bytes, batch[0].as_bytes());
        assert_eq!(mock.armed_faults(), 0, "every fault consumed");
    }

    #[test]
    fn get_data_distinguishes_not_found_from_network() {
        let mock = MockBackend::new();
        let missing = Address::from_bytes([0x55; 32]);
        let err = block_on(mock.get_data(missing)).expect_err("nothing stored");
        assert_eq!(err, StorageError::NotFound { address: missing });
    }

    #[test]
    fn tx_map_gap_is_a_distinct_finalize_error() {
        let mock = MockBackend::new();
        let batch = blobs(&[(6, 60)]);
        let quote = block_on(mock.quote_batch(&batch)).expect("quote");
        let mut receipt = block_on(mock.pay(&quote)).expect("pay");
        receipt.tx_map.clear(); // hand-tampered: the gap
        let err = block_on(mock.finalize_batch(&receipt, &batch)).expect_err("gap");
        assert!(matches!(err, StorageError::Finalize { .. }));
        assert_eq!(mock.stored_count(), 0, "gap detected before any store");
    }

    #[test]
    fn identically_driven_mocks_are_byte_identical() {
        let drive = |mock: &MockBackend| {
            let batch = blobs(&[(1, 11), (2, 22)]);
            let quote = block_on(mock.quote_batch(&batch)).expect("quote");
            let receipt = block_on(mock.pay(&quote)).expect("pay");
            let addresses = block_on(mock.finalize_batch(&receipt, &batch)).expect("finalize");
            (quote, receipt, addresses, mock.call_log())
        };
        let (q1, r1, a1, l1) = drive(&MockBackend::new());
        let (q2, r2, a2, l2) = drive(&MockBackend::new());
        assert_eq!(q1, q2);
        assert_eq!(r1, r2);
        assert_eq!(a1, a2);
        assert_eq!(l1, l2, "call log (methods + args digests) is deterministic");
    }

    #[test]
    fn args_digests_distinguish_different_calls_and_match_repeats() {
        let mock = MockBackend::new();
        let batch_a = blobs(&[(1, 5)]);
        let batch_b = blobs(&[(2, 5)]);
        block_on(mock.quote_batch(&batch_a)).expect("quote a");
        block_on(mock.quote_batch(&batch_a)).expect("quote a again");
        block_on(mock.quote_batch(&batch_b)).expect("quote b");
        let log = mock.call_log();
        assert_eq!(
            log[0].args_digest, log[1].args_digest,
            "same args, same digest"
        );
        assert_ne!(
            log[0].args_digest, log[2].args_digest,
            "different args, different digest"
        );
    }
}
