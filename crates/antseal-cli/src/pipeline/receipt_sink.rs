//! [`VaultReceiptSink`] — D37 Decision 7's durable per-sub-batch receipt
//! write, and the one encoder both writers of the receipt record share.
//!
//! # What this closes (S31)
//!
//! D37 Decision 2 says `pay()` journals each sub-batch's record **before
//! submitting the next**, so a crash mid-sequence loses at most the tx
//! currently in flight. U36 built the seam that expresses the timing —
//! `SealBackend::connect` takes a `ReceiptSink` and installs the hook
//! itself — but until S31 no sink wrote anything durable: `ReadOnly` drops
//! the receipt, the rest were test doubles, and the only durable write was
//! the pipeline's own `put_receipt` *after* `pay` returned. So a crash
//! between sub-batch txs lost every receipt so far.
//!
//! # Why the write happens here and not on the pipeline's side
//!
//! The obvious alternative — a channel the pipeline drains between
//! sub-batches — cannot work, and the reason is worth stating where the
//! code is. antseal-net's hook (`CaptureHook`) is a **synchronous** call
//! made inline from `pay`'s own body, while the pipeline's future is
//! suspended at `backend.pay(quote).await` **in the same task**. A channel
//! `send` returns immediately and nobody can dequeue it: the only code that
//! could is the caller currently blocked inside the call that fired the
//! hook. Draining under `select!` gets polled only when `pay` yields, and
//! its next yield is *inside* `send_transaction` for the following
//! sub-batch — so the write would land after the next submission, which is
//! precisely the ordering D37 forbids. (Full argument: D37's
//! "Amendment — 2026-08-02 (S31)".)
//!
//! So [`VaultReceiptSink::capture`] performs U9's atomic + fsync'd write
//! **inline** and returns whether it became durable: the adapter's loop
//! submits the next sub-batch only after a durable capture (S46).
//!
//! # The three properties the shape had to keep
//!
//! - **Secret lifetime (U6/U9).** The sink holds an [`Arc`] of the
//!   *existing* [`UnlockedVault`], never a copy of the vault key.
//!   `UnlockedVault` stays `!Clone`; there is still exactly one `VaultKey`
//!   in the process and it still zeroizes on its single drop.
//! - **U5's single-writer lock.** This sink **never acquires it**. U5
//!   refuses a same-process double-acquire by design (two open file
//!   descriptions), so a sink that tried would deadlock the command against
//!   itself. The command's existing hold covers these writes.
//! - **S10 keeps journal ownership.** The sink writes the *receipt record
//!   and nothing else* — no state transitions, no plan, no staging. Which
//!   work it writes to is supplied by the pipeline through
//!   [`SealJournal::arm_receipts`](super::journal::SealJournal::arm_receipts),
//!   called immediately before `pay` on every path that can pay.
//!
//! # Panics
//!
//! It must not, ever. `capture` runs between two transactions on the far
//! side of money having moved, so every failure is recorded and logged,
//! never propagated — in two slots that answer different questions.
//! [`VaultReceiptSink::fault`] keeps the *first* failure, for diagnosis.
//! [`VaultReceiptSink::unrecorded`] says whether the *most recent* capture
//! of the current payment became durable, and that is what the pipeline
//! reads to tell a stranded payment it can finish (exit 28) from one whose
//! receipt the vault could not record (exit 37, S37/D186).

use std::sync::{Arc, Mutex};

use antseal_core::crypto::secrets::SealId;
use antseal_net::{CaptureOutcome, JournalReceipt, PaymentReceipt};

use super::journal::JournalError;
use crate::rng::OsEntropy;
use crate::vault::session::UnlockedVault;
use crate::vault::store::WorkStore;

/// Encode a receipt into the versioned at-rest envelope U9's record slot
/// stores.
///
/// **One encoder, two writers.** Both the pipeline's
/// [`VaultJournal::put_receipt`](super::vault_journal::VaultJournal) and
/// this module's sink write the same record; a second hand-rolled encoding
/// is exactly how the two would drift into disagreement over what a
/// journaled receipt is.
///
/// # Errors
///
/// [`JournalError::Encode`] — the only reachable class (the envelope is
/// plain serde data).
pub(super) fn encode_receipt(receipt: &PaymentReceipt) -> Result<Vec<u8>, JournalError> {
    let envelope = JournalReceipt::seal(receipt.clone());
    serde_json::to_vec(&envelope).map_err(|_| JournalError::Encode)
}

/// The inverse of [`encode_receipt`] — kept beside it so the pair cannot
/// be changed one-sidedly.
///
/// # Errors
///
/// [`JournalError::Corrupt`] for malformed bytes or an unsupported
/// envelope version. Adversarial input reaches this only through a vault
/// record that already passed its AEAD, but it is parsed defensively
/// regardless.
pub(super) fn decode_receipt(bytes: &[u8]) -> Result<PaymentReceipt, JournalError> {
    let envelope: JournalReceipt = serde_json::from_slice(bytes)
        .map_err(|_| super::journal::corrupt("journaled receipt is malformed"))?;
    envelope
        .open()
        .map_err(|_| super::journal::corrupt("journaled receipt carries an unsupported version"))
}

/// The journaled [`PaymentReceipt`], read straight from U9's store — the
/// `recorded_state`/`recorded_plan` shape for the receipt slot (`status`,
/// U23).
///
/// Same reason as [`recorded_plan`](super::journal::recorded_plan): a
/// read-only command needs the record, not a `SealJournal`, and minting one
/// would arm a receipt sink nobody writes through on a path that never pays.
///
/// `None` means *not paid yet* — the same state
/// [`SealJournal::receipt`](super::journal::SealJournal::receipt) reports,
/// and never an error.
///
/// # Errors
///
/// Store-level failures, and [`JournalError::Corrupt`] for a record that is
/// present but unreadable.
pub fn recorded_receipt(
    store: &WorkStore<'_>,
    seal_id: &SealId,
) -> Result<Option<PaymentReceipt>, JournalError> {
    match store.get_receipt(seal_id)? {
        Some(bytes) => decode_receipt(bytes.as_bytes()).map(Some),
        None => Ok(None),
    }
}

/// Fold a freshly-paid receipt into records a previous invocation already
/// bought and the network still honours.
///
/// Ordering is `prior` first, then `fresh` — deterministic given
/// deterministic inputs, and the direction that matters: `finalize_batch`
/// resolves a blob by scanning for the first matching address, so a merge
/// that put `fresh` first could shadow a prior record. It never can here
/// (the two sets are disjoint by construction — `fresh` pays only what
/// `prior` did not cover), but the order is the cheap guarantee rather
/// than the argument.
///
/// `storage_cost_atto` and the gas summary are sums: what this seal has
/// cost in total, across however many invocations paid for it.
///
/// **Correct at every capture, not just the last.** D37's hook delivers
/// the cumulative receipt-so-far *of the current `pay`*, so folding a
/// fixed, disjoint `prior` into it is idempotent: capture `k` produces
/// `prior + (sub-batches 1..=k)`, which is exactly what a crash after
/// capture `k` should leave on disk.
pub(super) fn merge_receipts(prior: PaymentReceipt, fresh: PaymentReceipt) -> PaymentReceipt {
    let mut merged = prior;
    merged.blobs.extend(fresh.blobs);
    merged.tx_map.extend(fresh.tx_map);
    merged.txs.extend(fresh.txs);
    merged.storage_cost_atto = merged
        .storage_cost_atto
        .saturating_add(fresh.storage_cost_atto);
    merged.gas.gas_cost_wei = merged
        .gas
        .gas_cost_wei
        .saturating_add(fresh.gas.gas_cost_wei);
    merged
}

/// Why a capture did not become durable.
///
/// Carries no receipt content and no key material — a fault is a
/// diagnosis, and the record it failed to write is the sensitive part.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiptSinkFault {
    /// A receipt arrived before any work was named. Structurally
    /// unreachable through the pipeline (it arms on every paying path);
    /// reachable if a caller wires a sink into a backend and then pays
    /// through something that is not the pipeline.
    NotArmed,
    /// The sink was re-armed to a **different** work while it already had
    /// one. One command seals one work at a time; this is a wiring bug.
    /// The new target wins, so the receipt in flight is still written.
    Rearmed,
    /// The durable write failed. `detail` is the store's own message
    /// (paths and I/O classes — never record contents).
    Write {
        /// The store's rendering of the failure.
        detail: String,
    },
    /// The receipt could not be encoded into its at-rest envelope.
    Encode,
}

impl std::fmt::Display for ReceiptSinkFault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotArmed => f.write_str(
                "a payment receipt arrived before the sink was told which work it belongs to",
            ),
            Self::Rearmed => {
                f.write_str("the receipt sink was re-armed to a different work mid-payment")
            }
            Self::Write { detail } => write!(f, "the receipt could not be journaled: {detail}"),
            Self::Encode => f.write_str("the receipt could not be encoded for the journal"),
        }
    }
}

/// The mutable half, behind one lock.
///
/// One `Mutex` rather than several: a capture is arm-check → encode →
/// write → bookkeeping, and those must not interleave with an `arm` from
/// another thread. In practice there is no contention at all — `pay`'s
/// sub-batch loop is sequential and the pipeline is suspended inside it —
/// but antseal-net's hook type requires a `Sync` sink, so the lock is what
/// makes that requirement honest rather than assumed.
struct SinkState {
    target: Option<SealId>,
    /// Records an **earlier** invocation already paid for, which every
    /// capture of the current `pay` must be folded into before it is
    /// written. Without this, a remainder payment's first capture would
    /// overwrite the durable partial the previous crash left, and a second
    /// crash would strand everything the first one had bought — the exact
    /// hazard this sink exists to remove, one invocation deeper.
    prior: Option<PaymentReceipt>,
    writes: usize,
    fault: Option<ReceiptSinkFault>,
    /// **S37 (D186 R1)**: why the most recent capture of the current
    /// payment did not become durable — `None` when it did, or when this
    /// payment has made no capture yet.
    ///
    /// Not `fault`, which is first-fault-wins and so answers a different
    /// question. Captures are cumulative (each writes the whole
    /// receipt-so-far), so a failed capture is *healed* by any later
    /// durable one, and only the latest says whether the vault holds what
    /// was bought. Reading `fault` instead would call a healed payment
    /// unrecorded. Since S46 (D198) the adapter's loop makes no capture after
    /// a not-durable one, so no `pay` produces that heal any more; the rule
    /// stays, because it is what the predicate means.
    unrecorded: Option<ReceiptSinkFault>,
    /// The test seam (D186): fail this many upcoming writes, so a
    /// fail-then-heal sequence can be scripted without a broken disk.
    #[cfg(test)]
    fail_next_writes: usize,
    rng: OsEntropy,
}

impl SinkState {
    /// First fault wins: the earliest failure is the one that explains the
    /// rest, and a later success must not erase it.
    fn note(&mut self, fault: ReceiptSinkFault) {
        tracing::error!(fault = %fault, "D37 per-sub-batch receipt capture failed");
        if self.fault.is_none() {
            self.fault = Some(fault);
        }
    }

    /// A capture that did not become durable. It sets the S37 predicate as
    /// well as the diagnostic slot. Only the three capture outcomes come
    /// here (`NotArmed`, `Encode`, `Write`) and never `Rearmed`, which
    /// re-targets and still writes (D186 R1). It returns the verdict
    /// `capture` answers (S46), so the answer and the predicate cannot part.
    fn not_durable(&mut self, fault: ReceiptSinkFault) -> CaptureOutcome {
        self.unrecorded = Some(fault.clone());
        self.note(fault);
        CaptureOutcome::NotDurable
    }

    /// A capture that reached the disk. It clears the S37 predicate: the
    /// receipt it wrote is cumulative, so it covers whatever an earlier
    /// failed capture of this payment had dropped. It returns the verdict
    /// `capture` answers (S46).
    fn durable(&mut self) -> CaptureOutcome {
        self.writes += 1;
        self.unrecorded = None;
        CaptureOutcome::Durable
    }
}

/// A [`ReceiptSink`](crate::backend::ReceiptSink) that journals each
/// sub-batch receipt durably, inside `pay`.
///
/// Construct one per command, hand it to `SealBackend::connect`, and
/// attach the same handle to the [`VaultJournal`] the pipeline runs over
/// (see
/// [`VaultJournal::with_receipt_sink`](super::vault_journal::VaultJournal::with_receipt_sink))
/// so the pipeline can arm it.
pub struct VaultReceiptSink {
    vault: Arc<UnlockedVault>,
    state: Mutex<SinkState>,
}

impl std::fmt::Debug for VaultReceiptSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (armed, writes, faulted) = match self.state.lock() {
            Ok(state) => (state.target.is_some(), state.writes, state.fault.is_some()),
            Err(poisoned) => {
                let state = poisoned.into_inner();
                (state.target.is_some(), state.writes, state.fault.is_some())
            }
        };
        f.debug_struct("VaultReceiptSink")
            .field("armed", &armed)
            .field("writes", &writes)
            .field("faulted", &faulted)
            .finish_non_exhaustive()
    }
}

impl VaultReceiptSink {
    /// Open a sink over the command's already-unlocked vault.
    ///
    /// The `Arc` shares the one `UnlockedVault`; it does not copy the key
    /// (`UnlockedVault` is deliberately `!Clone`). Drop the sink with the
    /// command and the vault key zeroizes exactly once, as before.
    #[must_use]
    pub fn new(vault: Arc<UnlockedVault>) -> Arc<Self> {
        Arc::new(Self {
            vault,
            state: Mutex::new(SinkState {
                target: None,
                prior: None,
                writes: 0,
                fault: None,
                unrecorded: None,
                #[cfg(test)]
                fail_next_writes: 0,
                rng: OsEntropy,
            }),
        })
    }

    /// Name the work whose receipts this sink is about to write, and the
    /// already-durable records every write must preserve.
    ///
    /// The pipeline calls this immediately before **every** `pay`, so on
    /// the production path it cannot be forgotten. `prior` is `Some` only
    /// on the unpaid-remainder path, where an earlier invocation's
    /// payments are on disk and this `pay` covers the rest; it is `None`
    /// for a fresh seal and — deliberately — for the proofs-expired
    /// re-payment, where the old records are what is being replaced.
    ///
    /// Re-arming the same work is silent and simply refreshes `prior`
    /// (one command can pay twice for one work: the remainder, then a
    /// proofs-expired retry). Re-arming a *different* work records
    /// [`ReceiptSinkFault::Rearmed`] and re-targets — losing the write in
    /// flight would be strictly worse than recording the wiring bug.
    ///
    /// Arming also resets [`Self::unrecorded`], because it marks the start
    /// of a payment that has made no capture yet. One invocation can pay
    /// twice — a fresh or remainder `pay`, then the proofs-expired
    /// re-payment (`resume.rs`) — and the first payment's last capture says
    /// nothing about the second: its receipt was made durable afterwards by
    /// the pipeline's own `put_receipt`, which this sink never sees.
    pub fn arm(&self, seal_id: &SealId, prior: Option<&PaymentReceipt>) {
        let mut state = self.lock();
        if state.target.is_some_and(|current| current != *seal_id) {
            state.note(ReceiptSinkFault::Rearmed);
        }
        state.target = Some(*seal_id);
        state.prior = prior.cloned();
        state.unrecorded = None;
    }

    /// How many receipts reached the disk. One per landed sub-batch on a
    /// multi-tx payment.
    #[must_use]
    pub fn writes(&self) -> usize {
        self.lock().writes
    }

    /// The first fault recorded, if any. `None` means every capture this
    /// sink saw is durable.
    #[must_use]
    pub fn fault(&self) -> Option<ReceiptSinkFault> {
        self.lock().fault.clone()
    }

    /// **S37's predicate (D186 R1)**: why the most recent capture of the
    /// current payment did not become durable, or `None` when it did — or
    /// when this payment has made no capture yet.
    ///
    /// This, not [`Self::fault`], is what the pipeline reads when a payment
    /// fails mid-sequence or its final receipt write fails. `Some` means the
    /// vault may not hold a record of what was bought, so a re-run would buy
    /// it again (exit 37); `None` means the receipt-so-far is on disk and a
    /// stranded payment is finishable (exit 28).
    #[must_use]
    pub fn unrecorded(&self) -> Option<ReceiptSinkFault> {
        self.lock().unrecorded.clone()
    }

    /// The test seam (D186): make the next `n` writes fail, recorded
    /// exactly as a failed store write is.
    #[cfg(test)]
    pub(crate) fn fail_next_writes(&self, n: usize) {
        self.lock().fail_next_writes = n;
    }

    /// Journal the receipt-so-far, synchronously, and say whether it became
    /// durable.
    ///
    /// This is the whole point: when it returns [`CaptureOutcome::Durable`],
    /// the record is on disk (U9's `put_receipt` is atomic and fsync'd), and
    /// the adapter's loop has not yet submitted the next sub-batch. When it
    /// returns [`CaptureOutcome::NotDurable`] — the failure is then in
    /// [`Self::unrecorded`] and [`Self::fault`] — that loop submits no further
    /// sub-batch and fails with `StrandedPayment` (S46), so at most one
    /// sub-batch is paid without a record; after the last sub-batch it stops
    /// nothing, and the pipeline's own write is the second chance (D186 R3).
    /// The answer is the S37 predicate's: `Durable` exactly where this
    /// capture cleared [`Self::unrecorded`], `NotDurable` where it set it.
    ///
    /// Later, more complete receipts overwrite earlier partial ones — the
    /// same idempotence
    /// [`SealJournal::put_receipt`](super::journal::SealJournal::put_receipt)
    /// documents, which is also how the pipeline's own post-`pay` write
    /// supersedes the last capture.
    pub fn capture(&self, receipt: &PaymentReceipt) -> CaptureOutcome {
        let mut state = self.lock();
        let Some(seal_id) = state.target else {
            return state.not_durable(ReceiptSinkFault::NotArmed);
        };
        // Never write less than what is already durable: on a remainder
        // payment the receipt-so-far covers only this round's sub-batches,
        // and writing it bare would erase the prior round's records.
        let record = match &state.prior {
            Some(prior) => merge_receipts(prior.clone(), receipt.clone()),
            None => receipt.clone(),
        };
        let bytes = match encode_receipt(&record) {
            Ok(bytes) => bytes,
            Err(_) => return state.not_durable(ReceiptSinkFault::Encode),
        };
        #[cfg(test)]
        {
            if state.fail_next_writes > 0 {
                state.fail_next_writes -= 1;
                return state.not_durable(ReceiptSinkFault::Write {
                    detail: "injected write failure (test seam)".to_owned(),
                });
            }
        }
        let store = WorkStore::new(self.vault.as_ref());
        match store.put_receipt(&seal_id, &bytes, &mut state.rng) {
            Ok(()) => state.durable(),
            Err(err) => state.not_durable(ReceiptSinkFault::Write {
                detail: err.to_string(),
            }),
        }
    }

    /// Poisoning is not a failure mode worth propagating here: the only
    /// code under this lock is I/O and bookkeeping, and a poisoned lock
    /// after a panic elsewhere must not stop a landed payment from being
    /// recorded.
    fn lock(&self) -> std::sync::MutexGuard<'_, SinkState> {
        match self.state.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use antseal_core::crypto::secrets::{MasterSecret, SealId};
    use antseal_net::{CaptureOutcome, GasSummary, PaymentReceipt};

    use super::{ReceiptSinkFault, VaultReceiptSink};
    use crate::pipeline::journal::{SealJournal, WorkIdentity};
    use crate::pipeline::vault_journal::VaultJournal;
    use crate::vault::kdf::KdfSelection;
    use crate::vault::layout::VaultLayout;
    use crate::vault::session::{UnlockedVault, create_vault, unlock_vault};
    use crate::vault::store::{SealShapingFlags, WorkStore};

    /// The sink must satisfy antseal-net's `CaptureHook` bounds without the
    /// `ant-backend` feature being on — if this ever stops holding, the
    /// gated `impl ReceiptSink for VaultReceiptSink` in `backend.rs` stops
    /// compiling in a lane no required gate runs.
    const fn _bounds_hold<T: Send + Sync + 'static>() {}
    const _: () = _bounds_hold::<VaultReceiptSink>();

    /// NON-SECRET test passphrase.
    fn passphrase() -> antseal_core::crypto::secrets::SecretBuf {
        antseal_core::crypto::secrets::SecretBuf::new(b"receipt-sink-test-passphrase".to_vec())
    }

    struct Fixture {
        _dir: std::path::PathBuf,
        vault: Arc<UnlockedVault>,
        seal_id: SealId,
    }

    impl Fixture {
        fn new(tag: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "antseal-s31-{tag}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_nanos())
            ));
            std::fs::create_dir_all(&dir).expect("mk fixture dir");
            let layout = VaultLayout::at(dir.join("vault"));
            let mut rng = crate::rng::OsEntropy;
            create_vault(&layout, &passphrase(), KdfSelection::Argon2id, &mut rng)
                .expect("create vault");
            let vault = Arc::new(unlock_vault(&layout, &passphrase()).expect("unlock"));

            let seal_id = SealId::generate(&mut rng).expect("seal id");
            let w = MasterSecret::generate(&mut rng).expect("W");
            let journal = VaultJournal::new(WorkStore::new(vault.as_ref()), &mut rng);
            journal
                .begin(&WorkIdentity {
                    seal_id,
                    w: w.secret_ref(),
                    network: "devnet".to_owned(),
                    degraded: false,
                    unanchored: true,
                    input_paths_as_given: vec!["a.txt".to_owned()],
                    input_paths_absolute: vec!["/w/a.txt".to_owned()],
                    shaping: SealShapingFlags::default(),
                })
                .expect("begin");

            Self {
                _dir: dir,
                vault,
                seal_id,
            }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self._dir);
        }
    }

    /// A minimal blob record tagged by its `proof_bytes` so merge order is
    /// readable in an assertion. NON-SECRET: a one-byte tag.
    fn blob_record(tag: u8) -> antseal_net::BlobPaymentRecord {
        antseal_net::BlobPaymentRecord {
            address: antseal_net::Address::from([tag; 32]),
            payments: Vec::new(),
            peer_quotes: Vec::new(),
            commitment_sidecars: Vec::new(),
            proof_bytes: vec![tag],
        }
    }

    fn receipt(cost: u128) -> PaymentReceipt {
        PaymentReceipt {
            blobs: Vec::new(),
            tx_map: std::collections::BTreeMap::new(),
            txs: Vec::new(),
            storage_cost_atto: cost,
            gas: GasSummary { gas_cost_wei: 0 },
        }
    }

    /// The property the whole task exists for: when `capture` **returns**,
    /// the receipt is readable from a *different* store session — i.e. it
    /// is on disk, not in the sink. A `SIGKILL` one instruction later
    /// changes nothing.
    #[test]
    fn a_capture_is_durable_by_the_time_it_returns() {
        let fx = Fixture::new("durable");
        let sink = VaultReceiptSink::new(Arc::clone(&fx.vault));
        sink.arm(&fx.seal_id, None);

        let mut rng = crate::rng::OsEntropy;
        let reader = VaultJournal::new(WorkStore::new(fx.vault.as_ref()), &mut rng);
        assert!(
            reader.receipt(&fx.seal_id).expect("read").is_none(),
            "nothing is journaled before the first capture"
        );

        assert_eq!(
            sink.capture(&receipt(4_242)),
            CaptureOutcome::Durable,
            "a durable write answers Durable (S46)"
        );

        let read_back = reader
            .receipt(&fx.seal_id)
            .expect("read")
            .expect("the capture is durable the instant it returns");
        assert_eq!(read_back.storage_cost_atto, 4_242);
        assert_eq!(sink.writes(), 1);
        assert_eq!(sink.fault(), None);
        assert_eq!(
            sink.unrecorded(),
            None,
            "a durable capture leaves nothing unrecorded"
        );
    }

    /// D37's hook delivers the cumulative receipt-so-far once per
    /// sub-batch, so successive captures must supersede rather than
    /// accumulate — and the last one wins.
    #[test]
    fn later_captures_supersede_earlier_partial_ones() {
        let fx = Fixture::new("supersede");
        let sink = VaultReceiptSink::new(Arc::clone(&fx.vault));
        sink.arm(&fx.seal_id, None);
        for cost in [10_u128, 20, 30] {
            sink.capture(&receipt(cost));
        }

        let mut rng = crate::rng::OsEntropy;
        let reader = VaultJournal::new(WorkStore::new(fx.vault.as_ref()), &mut rng);
        assert_eq!(
            reader
                .receipt(&fx.seal_id)
                .expect("read")
                .expect("journaled")
                .storage_cost_atto,
            30
        );
        assert_eq!(sink.writes(), 3, "one durable write per sub-batch");
    }

    /// **Armed with a prior, every capture writes the merge.** A remainder
    /// payment's receipt-so-far covers only that round; written bare it
    /// would erase the records the previous crash had already paid for.
    /// This is the property the double-crash row in `resume.rs` depends on,
    /// isolated to one call.
    #[test]
    fn a_capture_never_writes_less_than_the_prior_it_was_armed_with() {
        let fx = Fixture::new("prior");
        let sink = VaultReceiptSink::new(Arc::clone(&fx.vault));

        let mut prior = receipt(100);
        prior.blobs.push(blob_record(1));
        sink.arm(&fx.seal_id, Some(&prior));

        // The current `pay`'s first capture: one blob of its own.
        let mut so_far = receipt(40);
        so_far.blobs.push(blob_record(2));
        sink.capture(&so_far);

        let mut rng = crate::rng::OsEntropy;
        let reader = VaultJournal::new(WorkStore::new(fx.vault.as_ref()), &mut rng);
        let written = reader
            .receipt(&fx.seal_id)
            .expect("read")
            .expect("journaled");
        assert_eq!(
            written
                .blobs
                .iter()
                .map(|b| b.proof_bytes[0])
                .collect::<Vec<_>>(),
            vec![1, 2],
            "the prior must survive, and must come first"
        );
        assert_eq!(written.storage_cost_atto, 140, "the costs add up");

        // The second capture carries sub-batches 1..=2 cumulatively, so the
        // fold must NOT double-count the first.
        let mut so_far2 = receipt(75);
        so_far2.blobs.push(blob_record(2));
        so_far2.blobs.push(blob_record(3));
        sink.capture(&so_far2);
        let written = reader
            .receipt(&fx.seal_id)
            .expect("read")
            .expect("journaled");
        assert_eq!(
            written
                .blobs
                .iter()
                .map(|b| b.proof_bytes[0])
                .collect::<Vec<_>>(),
            vec![1, 2, 3],
            "a later capture supersedes the earlier one rather than accumulating on top of it"
        );
        assert_eq!(written.storage_cost_atto, 175);
    }

    /// The red direction of the arming contract: an unarmed sink drops the
    /// receipt (it has no work to write it to) and **says so**. Without
    /// this the failure would be silent, which is the S27 shape all over
    /// again.
    #[test]
    fn an_unarmed_capture_is_recorded_as_a_fault_not_swallowed() {
        let fx = Fixture::new("unarmed");
        let sink = VaultReceiptSink::new(Arc::clone(&fx.vault));

        assert_eq!(
            sink.capture(&receipt(1)),
            CaptureOutcome::NotDurable,
            "a dropped receipt answers NotDurable (S46)"
        );

        assert_eq!(sink.writes(), 0);
        assert_eq!(sink.fault(), Some(ReceiptSinkFault::NotArmed));
        assert_eq!(
            sink.unrecorded(),
            Some(ReceiptSinkFault::NotArmed),
            "a dropped receipt is an unrecorded one (D186 R1)"
        );
        let mut rng = crate::rng::OsEntropy;
        let reader = VaultJournal::new(WorkStore::new(fx.vault.as_ref()), &mut rng);
        assert!(reader.receipt(&fx.seal_id).expect("read").is_none());
    }

    /// Re-arming to the same work is silent; re-arming to a different one
    /// is a recorded wiring bug that still writes.
    #[test]
    fn rearming_to_another_work_is_a_recorded_fault_and_still_writes() {
        let fx = Fixture::new("rearm");
        let sink = VaultReceiptSink::new(Arc::clone(&fx.vault));
        sink.arm(&fx.seal_id, None);
        sink.arm(&fx.seal_id, None);
        assert_eq!(sink.fault(), None, "re-arming the same work is a no-op");

        let other = SealId::generate(&mut crate::rng::OsEntropy).expect("seal id");
        sink.arm(&other, None);
        assert_eq!(sink.fault(), Some(ReceiptSinkFault::Rearmed));
        assert_eq!(
            sink.unrecorded(),
            None,
            "a re-arm still writes, so it alone never makes a receipt unrecorded (D186 R1)"
        );
    }

    /// A write failure must be recorded rather than panicking: `capture`
    /// runs between two transactions, on the far side of money having
    /// moved. Provoked by arming at a work that was never created, which
    /// is the store's `WorkNotFound` path.
    #[test]
    fn a_failed_write_records_a_fault_and_never_panics() {
        let fx = Fixture::new("writefail");
        let sink = VaultReceiptSink::new(Arc::clone(&fx.vault));
        let mut rng = crate::rng::OsEntropy;
        let ghost = SealId::generate(&mut rng).expect("seal id");
        sink.arm(&ghost, None);

        assert_eq!(
            sink.capture(&receipt(9)),
            CaptureOutcome::NotDurable,
            "a failed write answers NotDurable (S46)"
        );

        assert_eq!(sink.writes(), 0);
        match sink.fault() {
            Some(ReceiptSinkFault::Write { detail }) => {
                assert!(!detail.is_empty(), "the fault names the failure");
            }
            other => panic!("expected a Write fault, got {other:?}"),
        }
        // The real store failure — not only the test seam — sets S37's
        // predicate, and to the same fault.
        assert_eq!(sink.unrecorded(), sink.fault());
    }

    /// **S37's predicate (D186 R1)** follows the *latest* capture, while
    /// `fault()` keeps the *first*. Captures are cumulative, so a later
    /// durable capture heals an earlier failed one, and only the latest
    /// says whether the vault holds what was bought.
    #[test]
    fn the_predicate_follows_the_latest_capture_and_the_fault_keeps_the_first() {
        let fx = Fixture::new("latest");
        let sink = VaultReceiptSink::new(Arc::clone(&fx.vault));
        sink.arm(&fx.seal_id, None);
        let mut rng = crate::rng::OsEntropy;
        let reader = VaultJournal::new(WorkStore::new(fx.vault.as_ref()), &mut rng);
        let durable_cost = || {
            reader
                .receipt(&fx.seal_id)
                .expect("read")
                .map(|receipt| receipt.storage_cost_atto)
        };

        sink.fail_next_writes(1);
        assert_eq!(
            sink.capture(&receipt(10)),
            CaptureOutcome::NotDurable,
            "an injected write failure answers NotDurable (S46)"
        );
        let first = sink.unrecorded().expect("the failed capture is unrecorded");
        assert!(matches!(first, ReceiptSinkFault::Write { .. }), "{first:?}");
        assert_eq!(
            durable_cost(),
            None,
            "positive control: nothing reached the disk"
        );

        assert_eq!(
            sink.capture(&receipt(20)),
            CaptureOutcome::Durable,
            "the healing write answers Durable (S46)"
        );
        assert_eq!(
            sink.unrecorded(),
            None,
            "a later durable capture heals the failed one"
        );
        assert_eq!(
            sink.fault(),
            Some(first.clone()),
            "the first fault is kept for diagnosis"
        );
        assert_eq!(durable_cost(), Some(20));

        sink.fail_next_writes(1);
        assert_eq!(
            sink.capture(&receipt(30)),
            CaptureOutcome::NotDurable,
            "the second injected failure answers NotDurable (S46)"
        );
        assert_eq!(
            sink.unrecorded(),
            Some(first),
            "the latest capture failed again"
        );
        assert_eq!(
            durable_cost(),
            Some(20),
            "positive control: the disk still holds the healed receipt, not the latest"
        );
        assert_eq!(
            sink.writes(),
            1,
            "exactly one capture of three became durable"
        );
    }

    /// Arming starts a payment that has made no capture yet, so it clears
    /// the predicate. One invocation can pay twice (a fresh or remainder
    /// `pay`, then the proofs-expired re-payment), and the first payment's
    /// last capture says nothing about the second.
    #[test]
    fn arming_starts_a_payment_with_no_unrecorded_capture() {
        let fx = Fixture::new("rearm-clears");
        let sink = VaultReceiptSink::new(Arc::clone(&fx.vault));
        sink.arm(&fx.seal_id, None);
        sink.fail_next_writes(1);
        sink.capture(&receipt(5));
        assert!(
            sink.unrecorded().is_some(),
            "positive control: the capture failed"
        );

        sink.arm(&fx.seal_id, None);
        assert_eq!(
            sink.unrecorded(),
            None,
            "a new payment starts with nothing unrecorded"
        );
        assert!(
            sink.fault().is_some(),
            "the diagnostic slot still keeps the failure"
        );
    }

    /// The vault key's lifetime is unchanged by the `Arc`: once the sink
    /// is dropped the fixture's handle is the only owner again, so the
    /// single `VaultKey` zeroizes on the single drop U6 designed for.
    #[test]
    fn the_sink_holds_no_extra_vault_beyond_its_own_lifetime() {
        let fx = Fixture::new("lifetime");
        assert_eq!(Arc::strong_count(&fx.vault), 1);
        let sink = VaultReceiptSink::new(Arc::clone(&fx.vault));
        assert_eq!(Arc::strong_count(&fx.vault), 2);
        drop(sink);
        assert_eq!(
            Arc::strong_count(&fx.vault),
            1,
            "the sink leaked a vault handle — the key would outlive the command"
        );
    }
}
