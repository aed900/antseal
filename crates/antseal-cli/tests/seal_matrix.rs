//! S16: the mock-level pipeline invariant matrix — one row per
//! fault-injection barrier, the D36/D37/D49 rows the decisions demand, and
//! a property test over arbitrary kill/resume interleavings.
//!
//! **Every assertion reads the mock's call log, its payment counter, or the
//! journal — never timing.** The mock is deterministic (no clock, no RNG),
//! so a row that fails here fails identically on every machine, which is
//! what makes this the cheap mirror of S18's devnet matrix rather than a
//! flaky approximation of it.
//!
//! One Argon2id vault is unlocked per test (the matrices run dozens of
//! pipeline invocations); works are keyed by distinct fixture seal ids.
//!
//! NON-SECRET: every fixture value is documented in `common`.

mod common;

use std::cell::{Cell, RefCell};
use std::sync::Arc;

use antseal_cli::error::ConsentOutcome;
use antseal_cli::pipeline::{
    Barrier, BlobSlot, NoBarriers, Pipeline, SealError, SealFile, SealJournal, SealPlan,
    SealRequest, SealResult, SealState, StagedBlob, UNIT_ENTRY_BASE, VaultJournal,
    VaultReceiptSink, WorkIdentity,
};
use antseal_cli::vault::session::UnlockedVault;
use antseal_cli::vault::store::{SealShapingFlags, WorkStore};
use antseal_core::content::{FileFlags, SplitMode};
use antseal_core::crypto::material::MasterSecretRef;
use antseal_core::crypto::secrets::SealId;
use antseal_core::crypto::sig_policy::SigPolicy;
use antseal_core::storage::compute_storage_address;
use antseal_core::test_util::proptest;
use antseal_core::test_util::proptest::prelude::*;
use antseal_net::test_util::{Fault, Method, MockBackend, block_on};
use antseal_net::{
    Address, Blob, CostQuote, NetworkId, PaymentReceipt, StorageBackend, StorageError,
};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

use common::{
    FIXTURE_W, IsolatedVault, KillAt, RecordingBackend, RecordingGate, ScriptedConsent as Consent,
    TraceBarriers, fixture_manifest_envelope, fixture_seal_id, journal_over, shared_vault,
};

const TEXT: &[u8] = b"one paragraph\r\n\r\ntwo paragraph\r\n";
const BINARY: &[u8] = &[0xFF, 0xFE, 0x01, 0x02];

fn seal_rng(seed: u8) -> ChaCha20Rng {
    ChaCha20Rng::from_seed([seed; 32])
}

fn files() -> Vec<SealFile<'static>> {
    vec![
        SealFile {
            path_as_given: "a.txt",
            path_absolute: "/w/a.txt",
            bytes: TEXT,
            flags: FileFlags::new().with_split(SplitMode::BlankLines),
        },
        SealFile {
            path_as_given: "b.bin",
            path_absolute: "/w/b.bin",
            bytes: BINARY,
            flags: FileFlags::new(),
        },
    ]
}

fn request<'a>(files: &'a [SealFile<'a>]) -> SealRequest<'a> {
    SealRequest {
        files,
        title: "matrix".to_owned(),
        claimed_time_unix_secs: 1_800_000_000,
        app_version: "antseal-test/1".to_owned(),
        network: NetworkId::Devnet,
        no_anchor: false,
        degraded: false,
        dry_run: false,
        sig_policy: SigPolicy::hybrid(),
        shaping: SealShapingFlags::default(),
    }
}

/// A backend that fires D37's capture hook **inside** `pay`, into the real
/// [`VaultReceiptSink`], before returning — which is what production does
/// once `SealBackend::connect` installs the hook (S31) and
/// `SealSession` supplies the sink (S36).
///
/// This is what makes the post-pay/pre-receipt-journal window empty. Its
/// absence is not a theoretical concern: the paired test below shows a kill
/// in that window double-pays without it.
///
/// `crash_after_blobs` is the mid-sequence case. `Some(k)` pays only the
/// first `k` blob lines through the inner mock — really moving the money and
/// really sub-batching it at the configured cap — captures the receipt
/// covering them, and *then* fails with [`StorageError::StrandedPayment`].
/// That is a crash **between** sub-batch txs, modelled the only way the mock
/// allows: `Fault::AfterSubBatches` fires *instead of* paying and has no
/// hook, so it can produce the error but not the durable partial receipt
/// that is the thing under test.
///
/// **Why the real sink and not a hand-rolled `put_receipt` (S31's report).**
/// The previous version called `journal.put_receipt` itself and only on the
/// success path, so the mid-sequence fault propagated with nothing durable —
/// which was an accurate model of the tree *before* S31 and stopped being
/// one the moment the sink landed. A double that models a mechanism which no
/// longer exists still passes, and quietly asserts the wrong number.
struct CapturingBackend<'a> {
    inner: &'a MockBackend,
    sink: Arc<VaultReceiptSink>,
    crash_after_blobs: Option<usize>,
    armed: Cell<bool>,
    captures: RefCell<usize>,
}

impl<'a> CapturingBackend<'a> {
    fn new(inner: &'a MockBackend, sink: &Arc<VaultReceiptSink>) -> Self {
        Self {
            inner,
            sink: Arc::clone(sink),
            crash_after_blobs: None,
            armed: Cell::new(false),
            captures: RefCell::new(0),
        }
    }

    /// Crash between sub-batch txs, once, after `blobs` blob lines are paid.
    fn crashing_after(inner: &'a MockBackend, sink: &Arc<VaultReceiptSink>, blobs: usize) -> Self {
        Self {
            crash_after_blobs: Some(blobs),
            armed: Cell::new(true),
            ..Self::new(inner, sink)
        }
    }
}

impl StorageBackend for CapturingBackend<'_> {
    async fn quote_batch(&self, blobs: &[Blob]) -> Result<CostQuote, StorageError> {
        self.inner.quote_batch(blobs).await
    }

    async fn pay(&self, quote: &CostQuote) -> Result<PaymentReceipt, StorageError> {
        if let (Some(landed), true) = (self.crash_after_blobs, self.armed.replace(false)) {
            let lines: Vec<antseal_net::BlobQuote> =
                quote.blobs.iter().take(landed).cloned().collect();
            let total: u128 = lines
                .iter()
                .map(|line| match &line.cost {
                    antseal_net::BlobCost::AlreadyStored => 0,
                    antseal_net::BlobCost::Priced { payments, .. } => {
                        payments.iter().map(|p| p.amount_atto).sum()
                    }
                })
                .sum();
            let partial = self
                .inner
                .pay(&CostQuote {
                    blobs: lines,
                    total_ant_atto: total,
                    gas_estimate_wei: 0,
                })
                .await?;
            // The hook, doing its one job: the receipt-so-far is on disk
            // before upstream's loop could submit the next sub-batch.
            self.sink.capture(&partial);
            *self.captures.borrow_mut() += 1;
            return Err(StorageError::StrandedPayment {
                landed_tx_count: partial.txs.len(),
                reason: "test: killed between payment sub-batch txs".into(),
            });
        }
        let receipt = self.inner.pay(quote).await?;
        // The last sub-batch's capture: durable before the caller can be
        // interrupted.
        self.sink.capture(&receipt);
        *self.captures.borrow_mut() += 1;
        Ok(receipt)
    }

    async fn finalize_batch(
        &self,
        receipt: &PaymentReceipt,
        blobs: &[Blob],
    ) -> Result<Vec<Address>, StorageError> {
        self.inner.finalize_batch(receipt, blobs).await
    }

    async fn get_data(&self, address: Address) -> Result<Vec<u8>, StorageError> {
        self.inner.get_data(address).await
    }

    async fn balances(&self) -> Result<antseal_net::BalanceReport, StorageError> {
        self.inner.balances().await
    }
}

/// [`journal_over`], plus S31's durable receipt sink attached — i.e. the
/// pairing `SealSession` builds for the real `seal` command (S36), in the
/// shape this suite's per-invocation helper already uses.
///
/// A fresh session per call, so every durability claim still crosses a real
/// close/reopen rather than a live cache.
fn paying_journal_over<T>(
    vault: &Arc<UnlockedVault>,
    sink: &Arc<VaultReceiptSink>,
    body: impl FnOnce(&VaultJournal<'_, ChaCha20Rng>) -> T,
) -> T {
    let mut rng = common::rng();
    let journal =
        VaultJournal::new(WorkStore::new(vault), &mut rng).with_receipt_sink(Arc::clone(sink));
    body(&journal)
}

// ─────────────────────────────────────────────────────────────────────
// Hand-staged works (for the post-pay rows, whose seal_id must be known
// before the invocation that is killed)
// ─────────────────────────────────────────────────────────────────────

const UNIT_COUNT: u64 = 2;

fn identity(seal_id: SealId) -> WorkIdentity<'static> {
    static W: [u8; 32] = FIXTURE_W;
    WorkIdentity {
        w: MasterSecretRef::from_bytes(&W),
        seal_id,
        network: "devnet".to_owned(),
        unanchored: false,
        degraded: false,
        input_paths_as_given: vec!["a.txt".to_owned()],
        input_paths_absolute: vec!["/w/a.txt".to_owned()],
        shaping: SealShapingFlags::default(),
    }
}

fn staged_blob(slot: BlobSlot, fill: u8, len: usize) -> StagedBlob {
    let ciphertext = vec![fill; len];
    let address = compute_storage_address(&ciphertext).expect("under the cap");
    let mut nonce = [0u8; 24];
    nonce[0] = fill;
    StagedBlob {
        slot,
        nonce,
        address,
        ciphertext,
    }
}

fn staged_set() -> Vec<StagedBlob> {
    vec![
        staged_blob(BlobSlot::Unit { unit_id: 0 }, 0x10, 256),
        staged_blob(BlobSlot::Unit { unit_id: 1 }, 0x11, 384),
        staged_blob(BlobSlot::EncryptedManifest, 0x12, 128),
    ]
}

fn stage(vault: &UnlockedVault, seal_id: SealId, state: SealState) {
    journal_over(vault, |journal| {
        journal.begin(&identity(seal_id)).expect("begin");
        for blob in &staged_set() {
            journal.put_staged(&seal_id, blob).expect("stage");
        }
        journal
            .put_plan(
                &seal_id,
                &SealPlan {
                    unit_count: UNIT_COUNT,
                    manifest_bytes: Some(fixture_manifest_envelope()),
                },
            )
            .expect("plan");
        for step in [
            SealState::Anchored,
            SealState::Paid,
            SealState::Finalizing,
            SealState::Complete,
        ] {
            if journal.state(&seal_id).expect("state") == state {
                break;
            }
            journal.set_state(&seal_id, step).expect("advance");
        }
    });
}

// ─────────────────────────────────────────────────────────────────────
// One row per barrier
// ─────────────────────────────────────────────────────────────────────

/// **Barrier `post-plan-validation`**: the work does not exist yet — the
/// first durable write comes after this point — so there is nothing to
/// resume and nothing was spent.
#[test]
fn barrier_post_plan_validation_leaves_no_work_at_all() {
    let vault = IsolatedVault::create("barrier-plan");
    let files = files();
    let mock = MockBackend::new();
    let gate = RecordingGate::new();
    let consent = Consent::always_yes();
    let kill = KillAt::new(Barrier::PostPlanValidation);

    let before = vault.fingerprint();
    vault.with_journal(|journal| {
        let pipeline = Pipeline::new(&mock, &gate, journal, &consent, &kill);
        assert!(matches!(
            block_on(pipeline.seal(&request(&files), &mut seal_rng(40))),
            Err(SealError::KilledAtBarrier(Barrier::PostPlanValidation))
        ));
    });
    assert_eq!(before, vault.fingerprint(), "nothing durable yet");
    assert_eq!(mock.call_log().len(), 0);
    assert_eq!(mock.payment_tx_count(), 0);
}

/// **Barriers `post-staging-journal`, `post-quote`, `post-consent`,
/// `post-anchor`**: killed pre-pay ⇒ resume completes the seal with
/// **exactly one** payment and byte-identical re-uploads.
#[test]
fn every_pre_pay_barrier_resumes_to_exactly_one_payment() {
    // Its own vault: this row *enumerates* the store to find the work the
    // killed invocation left behind, and enumeration walks every work
    // directory. A neighbour test mid-`begin()` (directory created, meta
    // not yet written) would surface as a spurious `WorkNotFound` —
    // production serialises those writes behind the U5 single-writer lock,
    // parallel test threads do not.
    let isolated = IsolatedVault::create("pre-pay-barriers");
    let vault = isolated.unlock();
    for (seed, barrier, expected_state) in [
        (41u8, Barrier::PostStagingJournal, SealState::Staged),
        (42, Barrier::PostQuote, SealState::Staged),
        (43, Barrier::PostConsent, SealState::Staged),
        (44, Barrier::PostAnchor, SealState::Anchored),
    ] {
        let files = files();
        let mock = MockBackend::new();
        let backend = RecordingBackend::new(&mock);
        let gate = RecordingGate::new();
        let consent = Consent::always_yes();
        let kill = KillAt::new(barrier);

        // Invocation 1: killed.
        let killed_at = journal_over(&vault, |journal| {
            let pipeline = Pipeline::new(&backend, &gate, journal, &consent, &kill);
            match block_on(pipeline.seal(&request(&files), &mut seal_rng(seed))) {
                Err(SealError::KilledAtBarrier(b)) => b,
                other => panic!("{}: expected a kill, got {other:?}", barrier.name()),
            }
        });
        assert_eq!(killed_at, barrier);
        assert_eq!(mock.payment_tx_count(), 0, "{}: pre-pay", barrier.name());

        // Find the work the killed invocation left behind.
        let seal_id = journal_over(&vault, |journal| {
            let mut candidates = journal.incomplete_works().expect("enumerate");
            candidates.retain(|(_, state)| *state == expected_state);
            let (seal_id, state) = *candidates.last().expect("a resumable work");
            assert_eq!(state, expected_state, "{}", barrier.name());
            seal_id
        });

        // Invocation 2: resume.
        journal_over(&vault, |journal| {
            let pipeline = Pipeline::new(&backend, &gate, journal, &consent, &NoBarriers);
            block_on(pipeline.resume(&seal_id)).expect("resume completes");
            assert_eq!(journal.state(&seal_id).expect("state"), SealState::Complete);
        });

        assert_eq!(
            mock.payment_tx_count(),
            1,
            "{}: exactly one payment across kill+resume",
            barrier.name()
        );
        assert!(
            mock.double_paid().is_empty(),
            "{}: no quote hash paid twice",
            barrier.name()
        );
        assert_eq!(mock.stored_count(), 5, "{}", barrier.name());
    }
}

/// **Barrier `post-pay-pre-receipt-journal`** — the row that has to be
/// argued rather than merely run.
///
/// The window is empty in production *because the backend journals each
/// sub-batch receipt inside `pay` before returning* (D37 Decision 2). Both
/// halves are asserted here: with the capture hook a kill in the window
/// costs exactly one payment; **without it, the same kill double-pays**.
/// The second half is why the hook is a requirement and not an
/// optimisation.
#[test]
fn barrier_post_pay_is_atomic_only_because_of_the_capture_hook() {
    let vault = Arc::new(shared_vault().unlock());

    // (a) With the capture hook: survivable.
    let with_hook = fixture_seal_id(60);
    stage(&vault, with_hook, SealState::Anchored);
    let mock = MockBackend::new();
    let sink = VaultReceiptSink::new(Arc::clone(&vault));
    let gate = RecordingGate::new();
    let consent = Consent::always_yes();
    let kill = KillAt::new(Barrier::PostPayPreReceiptJournal);
    paying_journal_over(&vault, &sink, |journal| {
        let backend = CapturingBackend::new(&mock, &sink);
        let pipeline = Pipeline::new(&backend, &gate, journal, &consent, &kill);
        assert!(matches!(
            block_on(pipeline.resume(&with_hook)),
            Err(SealError::KilledAtBarrier(
                Barrier::PostPayPreReceiptJournal
            ))
        ));
        assert!(
            journal.receipt(&with_hook).expect("read").is_some(),
            "the hook made the receipt durable before the kill"
        );
    });
    journal_over(&vault, |journal| {
        let pipeline = Pipeline::new(&mock, &gate, journal, &consent, &NoBarriers);
        block_on(pipeline.resume(&with_hook)).expect("resume finalizes");
    });
    assert_eq!(mock.payment_tx_count(), 1, "exactly one payment");
    assert!(mock.double_paid().is_empty());

    // (b) Without it: the window is real, and the resume pays again.
    let no_hook = fixture_seal_id(61);
    stage(&vault, no_hook, SealState::Anchored);
    let mock = MockBackend::new();
    let kill = KillAt::new(Barrier::PostPayPreReceiptJournal);
    journal_over(&vault, |journal| {
        let pipeline = Pipeline::new(&mock, &gate, journal, &consent, &kill);
        assert!(block_on(pipeline.resume(&no_hook)).is_err());
        assert!(
            journal.receipt(&no_hook).expect("read").is_none(),
            "no hook, no journaled receipt"
        );
    });
    journal_over(&vault, |journal| {
        let pipeline = Pipeline::new(&mock, &gate, journal, &consent, &NoBarriers);
        block_on(pipeline.resume(&no_hook)).expect("resume");
    });
    assert_eq!(
        mock.payment_tx_count(),
        2,
        "without the capture hook the window costs a second payment — \
         this is what installing it prevents (S27)"
    );
}

/// **Barrier `post-receipt-journal-pre-finalize`**: resume finalizes only
/// — `pay` is never invoked when a receipt is journaled.
#[test]
fn barrier_post_receipt_journal_resumes_finalize_only() {
    let vault = shared_vault().unlock();
    let seal_id = fixture_seal_id(62);
    stage(&vault, seal_id, SealState::Anchored);

    let mock = MockBackend::new();
    let backend = RecordingBackend::new(&mock);
    let gate = RecordingGate::new();
    let consent = Consent::always_yes();
    let kill = KillAt::new(Barrier::PostReceiptJournalPreFinalize);

    journal_over(&vault, |journal| {
        let pipeline = Pipeline::new(&backend, &gate, journal, &consent, &kill);
        assert!(block_on(pipeline.resume(&seal_id)).is_err());
        assert_eq!(journal.state(&seal_id).expect("state"), SealState::Paid);
    });
    let (quotes, pays, consents) = (backend.quote_calls(), backend.pay_calls(), consent.calls());

    journal_over(&vault, |journal| {
        let pipeline = Pipeline::new(&backend, &gate, journal, &consent, &NoBarriers);
        let outcome = block_on(pipeline.resume(&seal_id)).expect("finalize-only");
        assert!(!outcome.paid_here);
    });
    assert_eq!(backend.quote_calls(), quotes, "no re-quote");
    assert_eq!(consent.calls(), consents, "no consent prompt");
    assert_eq!(backend.pay_calls(), pays, "pay never repeated");
    assert_eq!(mock.payment_tx_count(), 1);

    // Receipt-journal-before-finalize, read from the call log: the only
    // `pay` precedes the only `finalize_batch`.
    let log = mock.call_log();
    let pay_at = log.iter().position(|c| c.method == Method::Pay);
    let fin_at = log.iter().position(|c| c.method == Method::FinalizeBatch);
    assert!(pay_at < fin_at, "pay precedes finalize");
}

/// **Barrier `post-finalize-pre-complete`**: finalize succeeded, the
/// completion tag did not land. Resume re-finalizes idempotently — no new
/// payment, and no blob stored twice.
#[test]
fn barrier_post_finalize_resumes_idempotently() {
    let vault = shared_vault().unlock();
    let seal_id = fixture_seal_id(63);
    stage(&vault, seal_id, SealState::Anchored);

    let mock = MockBackend::new();
    let gate = RecordingGate::new();
    let consent = Consent::always_yes();
    let kill = KillAt::new(Barrier::PostFinalizePreComplete);

    journal_over(&vault, |journal| {
        let pipeline = Pipeline::new(&mock, &gate, journal, &consent, &kill);
        assert!(block_on(pipeline.resume(&seal_id)).is_err());
        assert_eq!(
            journal.state(&seal_id).expect("state"),
            SealState::Finalizing
        );
    });
    assert_eq!(mock.stored_count(), 3);
    assert_eq!(mock.store_events(), 3);

    journal_over(&vault, |journal| {
        let pipeline = Pipeline::new(&mock, &gate, journal, &consent, &NoBarriers);
        block_on(pipeline.resume(&seal_id)).expect("resume completes");
        assert_eq!(journal.state(&seal_id).expect("state"), SealState::Complete);
    });
    assert_eq!(mock.payment_tx_count(), 1, "no second payment");
    assert_eq!(
        mock.store_events(),
        3,
        "already-stored blobs are skipped, never re-written"
    );
}

/// Partial store inside one `finalize_batch` (the other half of
/// "mid-finalize"): resume stores exactly the remainder.
#[test]
fn a_partial_store_resumes_to_exactly_the_remainder() {
    let vault = shared_vault().unlock();
    let seal_id = fixture_seal_id(64);
    stage(&vault, seal_id, SealState::Anchored);

    let mock = MockBackend::new();
    let gate = RecordingGate::new();
    let consent = Consent::always_yes();
    mock.arm_fault(Fault::AfterStoringK(1));

    journal_over(&vault, |journal| {
        let pipeline = Pipeline::new(&mock, &gate, journal, &consent, &NoBarriers);
        assert!(block_on(pipeline.resume(&seal_id)).is_err());
    });
    assert_eq!(mock.stored_count(), 1);

    journal_over(&vault, |journal| {
        let pipeline = Pipeline::new(&mock, &gate, journal, &consent, &NoBarriers);
        block_on(pipeline.resume(&seal_id)).expect("resume");
    });
    assert_eq!(mock.stored_count(), 3);
    assert_eq!(mock.store_events(), 3, "one write per blob, ever");
    assert_eq!(mock.payment_tx_count(), 1);
}

/// Abandon-on-missing-staged-bytes: the terminal branch of the matrix.
#[test]
fn missing_staged_bytes_abandon_without_a_backend_call() {
    let vault = shared_vault().unlock();
    let seal_id = fixture_seal_id(65);
    stage(&vault, seal_id, SealState::Anchored);
    journal_over(&vault, |journal| {
        journal
            .store()
            .delete_journal_entry(&seal_id, UNIT_ENTRY_BASE)
            .expect("delete");
    });

    let mock = MockBackend::new();
    let gate = RecordingGate::new();
    let consent = Consent::always_yes();
    journal_over(&vault, |journal| {
        let pipeline = Pipeline::new(&mock, &gate, journal, &consent, &NoBarriers);
        assert!(matches!(
            block_on(pipeline.resume(&seal_id)),
            Err(SealError::StagedBytes(_))
        ));
        assert_eq!(
            journal.state(&seal_id).expect("state"),
            SealState::Abandoned
        );
    });
    assert_eq!(mock.call_log().len(), 0);
    assert_eq!(mock.payment_tx_count(), 0);
}

// ─────────────────────────────────────────────────────────────────────
// D37: the multi-tx sub-batch row
// ─────────────────────────────────────────────────────────────────────

/// **D37 row**: with a sub-batch cap forcing ≥ 2 transactions, a kill
/// *between* sub-batch txs resumes to **exactly one tx per sub-batch**,
/// with the quote→tx map complete and no sub-batch ever re-paid.
///
/// # What this row used to claim, and why the number changed (S31 → S36)
///
/// It asserted **three** transactions for a two-sub-batch work, with the
/// comment "the resumed invocation re-quotes, so its two sub-batches are new
/// quote hashes — what must never happen is paying a hash twice". That was
/// the honest reading when it was written: the double modelled the capture
/// hook by journaling from the *success* path only, so a mid-sequence fault
/// propagated with nothing durable, the resume found no receipt, and it
/// correctly re-bought the whole work. The row's name was a statement of
/// intent, not of fact.
///
/// S31 landed the sink that makes the name true, and S36 attached it to the
/// command, so the model is now the production one: the receipt-so-far is on
/// disk before the next submission, the resume buys only the blobs that
/// receipt does not cover, and the count is **two** — one transaction per
/// sub-batch, which is what the function is called. Renaming it to match the
/// weaker claim was the alternative and was rejected: "no hash is paid
/// twice" is already asserted below and is a strictly weaker property (it
/// holds in the pre-S31 tree, where the user pays for the same *blobs*
/// twice under fresh hashes), so a rename would have preserved a name for a
/// guarantee nothing needed and quietly dropped the one D37 actually makes.
#[test]
fn a_kill_between_sub_batch_txs_pays_each_sub_batch_exactly_once() {
    // The sink is `'static`, so the vault it writes through is shared by
    // `Arc` — the same pairing `SealSession` builds for a real `seal`.
    let vault = Arc::new(shared_vault().unlock());
    let seal_id = fixture_seal_id(66);
    stage(&vault, seal_id, SealState::Anchored);

    // Three blobs, two transfers per tx ⇒ two sub-batches.
    let mock = MockBackend::new().with_max_transfers_per_tx(2);
    let sink = VaultReceiptSink::new(Arc::clone(&vault));
    let gate = RecordingGate::new();
    let consent = Consent::always_yes();

    // Kill after the first sub-batch lands (D37's mid-sequence point), with
    // the hook journaling what it bought from inside `pay`.
    paying_journal_over(&vault, &sink, |journal| {
        let backend = CapturingBackend::crashing_after(&mock, &sink, 2);
        let pipeline = Pipeline::new(&backend, &gate, journal, &consent, &NoBarriers);
        match block_on(pipeline.resume(&seal_id)) {
            Err(SealError::Storage(StorageError::StrandedPayment {
                landed_tx_count, ..
            })) => assert_eq!(landed_tx_count, 1),
            other => panic!("expected a stranded payment, got {other:?}"),
        }
        // The property the whole row rests on: durable *before* the crash,
        // not written by the resume afterwards.
        assert_eq!(
            journal
                .receipt(&seal_id)
                .expect("read")
                .expect("the sink journaled the receipt-so-far from inside pay")
                .blobs
                .len(),
            2,
            "the partial receipt must cover exactly the sub-batch that landed"
        );
    });
    assert_eq!(mock.payment_tx_count(), 1, "one sub-batch landed");
    assert_eq!(sink.fault(), None);

    // Resume: the remaining sub-batch is paid, and only that one.
    paying_journal_over(&vault, &sink, |journal| {
        let backend = CapturingBackend::new(&mock, &sink);
        let pipeline = Pipeline::new(&backend, &gate, journal, &consent, &NoBarriers);
        block_on(pipeline.resume(&seal_id)).expect("resume completes");
        assert_eq!(journal.state(&seal_id).expect("state"), SealState::Complete);
    });

    assert_eq!(
        mock.payment_tx_count(),
        2,
        "one transaction per sub-batch across the crash: the resume bought the sub-batch nobody \
         had paid for and nothing else. Three would mean it re-bought the landed one under a \
         fresh quote hash — money the user spends twice for blobs they already own"
    );
    assert_eq!(
        mock.paid_map().len(),
        3,
        "exactly one paying quote per blob, across both invocations"
    );
    assert!(
        mock.double_paid().is_empty(),
        "no quote hash was ever paid twice"
    );
    assert_eq!(mock.stored_count(), 3);
    // The map is complete over the receipt that actually finalized, and it
    // still carries the dead invocation's transaction.
    paying_journal_over(&vault, &sink, |journal| {
        let receipt = journal.receipt(&seal_id).expect("read").expect("present");
        assert!(receipt.covers_all_paid_quotes(), "quote→tx map complete");
        assert_eq!(
            receipt.txs.len(),
            2,
            "the merged receipt carries both invocations' transactions, not just the resume's"
        );
        assert_eq!(receipt.blobs.len(), 3, "every blob has a payment record");
    });
}

// ─────────────────────────────────────────────────────────────────────
// D36: the four rows
// ─────────────────────────────────────────────────────────────────────

/// **D36 (i)+(ii)+(iii)**: a resumed invocation performs `quote_batch`
/// before `pay`; the consent-hook call sits between them in the same
/// invocation; and `pay`'s quote argument is identity-equal to that
/// `quote_batch` return.
#[test]
fn d36_row_i_ii_iii_quote_then_consent_then_pay_with_one_quote_object() {
    let vault = shared_vault().unlock();
    let seal_id = fixture_seal_id(67);
    stage(&vault, seal_id, SealState::Anchored);

    let mock = MockBackend::new();
    let backend = RecordingBackend::new(&mock);
    let gate = RecordingGate::new();
    let consent = Consent::always_yes();

    journal_over(&vault, |journal| {
        let pipeline = Pipeline::new(&backend, &gate, journal, &consent, &NoBarriers);
        block_on(pipeline.resume(&seal_id)).expect("resume");
    });

    // (i) quote before pay, from the call log.
    let log = mock.call_log();
    let quote_at = log
        .iter()
        .position(|c| c.method == Method::QuoteBatch)
        .expect("quote");
    let pay_at = log
        .iter()
        .position(|c| c.method == Method::Pay)
        .expect("pay");
    assert!(quote_at < pay_at);

    // (ii) exactly one consent, in this invocation, between them.
    assert_eq!(consent.calls(), 1);
    let shown = consent.last().expect("a request");
    assert!(shown.resume);

    // (iii) identity: what was quoted == what was shown == what was paid.
    let quoted = backend.last_quote().expect("a quote");
    assert_eq!(shown.quote, quoted);
    assert_eq!(backend.last_paid_quote().expect("paid"), quoted);
}

/// **D36 (iv)**: consent-decline on resume ⇒ no `pay`, no state
/// transition. The work stays incomplete; it is never abandoned.
#[test]
fn d36_row_iv_decline_leaves_no_payment_and_no_transition() {
    let vault = shared_vault().unlock();
    let seal_id = fixture_seal_id(68);
    stage(&vault, seal_id, SealState::Anchored);

    let mock = MockBackend::new();
    let gate = RecordingGate::new();
    let consent = Consent::always_declines();

    journal_over(&vault, |journal| {
        let pipeline = Pipeline::new(&mock, &gate, journal, &consent, &NoBarriers);
        assert!(matches!(
            block_on(pipeline.resume(&seal_id)),
            Err(SealError::ConsentDeclined(ConsentOutcome::Declined))
        ));
        assert_eq!(
            journal.state(&seal_id).expect("state"),
            SealState::Anchored,
            "no transition on a decline"
        );
        assert!(journal.receipt(&seal_id).expect("read").is_none());
    });
    assert_eq!(mock.payment_tx_count(), 0);
    assert_eq!(mock.calls(Method::Pay), 0);
}

/// A journaled quote is never paid: the resumed invocation's quote is a
/// *fresh* object (the mock mints new quote hashes per round), so a
/// pipeline that cached one would be visible here.
#[test]
fn a_journaled_quote_is_never_the_one_that_gets_paid() {
    let vault = shared_vault().unlock();
    let seal_id = fixture_seal_id(69);
    stage(&vault, seal_id, SealState::Anchored);

    let mock = MockBackend::new();
    let backend = RecordingBackend::new(&mock);
    let gate = RecordingGate::new();

    // A first, declined attempt — its quote is now "the old quote".
    let declining = Consent::always_declines();
    journal_over(&vault, |journal| {
        let pipeline = Pipeline::new(&backend, &gate, journal, &declining, &NoBarriers);
        assert!(block_on(pipeline.resume(&seal_id)).is_err());
    });
    let old_quote = backend.last_quote().expect("first quote");

    // The second attempt must quote afresh and pay *that*.
    let consent = Consent::always_yes();
    journal_over(&vault, |journal| {
        let pipeline = Pipeline::new(&backend, &gate, journal, &consent, &NoBarriers);
        block_on(pipeline.resume(&seal_id)).expect("resume");
    });
    let paid = backend.last_paid_quote().expect("paid");
    assert_ne!(paid, old_quote, "the stale quote was not paid");
    assert_eq!(
        paid,
        backend.last_quote().expect("fresh"),
        "the fresh one was"
    );
}

// ─────────────────────────────────────────────────────────────────────
// D49: the dry-run row
// ─────────────────────────────────────────────────────────────────────

/// **D49 row**: `--dry-run` performs zero journal writes and exactly one
/// backend call (`quote_batch`) — the journal-before-backend invariant is
/// scoped to the paid path, and the mode is asserted rather than exempted.
#[test]
fn d49_row_dry_run_writes_nothing_and_calls_quote_only() {
    let vault = IsolatedVault::create("matrix-dry-run");
    let files = files();
    let mock = MockBackend::new();
    let gate = RecordingGate::new();
    let consent = Consent::always_yes();
    let barriers = TraceBarriers::new();

    let before = vault.fingerprint();
    vault.with_journal(|journal| {
        let mut req = request(&files);
        req.dry_run = true;
        let pipeline = Pipeline::new(&mock, &gate, journal, &consent, &barriers);
        assert!(matches!(
            block_on(pipeline.seal(&req, &mut seal_rng(45))),
            Ok(SealResult::DryRun(_))
        ));
    });

    assert_eq!(before, vault.fingerprint(), "zero journal writes");
    assert_eq!(
        mock.call_log().iter().map(|c| c.method).collect::<Vec<_>>(),
        vec![Method::QuoteBatch],
        "exactly one backend call class"
    );
    assert_eq!(gate.calls(), 0);
    assert_eq!(consent.calls(), 0);
    assert_eq!(mock.payment_tx_count(), 0);
    assert_eq!(mock.stored_count(), 0);
    assert_eq!(barriers.crossed().last(), Some(&Barrier::PostQuote));
}

// ─────────────────────────────────────────────────────────────────────
// The property test
// ─────────────────────────────────────────────────────────────────────

/// **S16's property**: whatever the interleaving of kills and resumes, a
/// work ends `complete` or `abandoned` — never mid-flight, never
/// double-paid, and never re-encrypted.
///
/// "Never re-encrypted" is enforced structurally rather than sampled: the
/// resume path has no access to `W` at all, so the encryptor is
/// unreachable from it. What the property samples is the part that *is*
/// sampleable — the state machine's reachability and the payment count.
///
/// Seeds are explicit and the mock is deterministic, so a failure here
/// reproduces exactly; a shrunk counterexample would be committed as a
/// regression fixture (none found).
#[test]
fn any_interleaving_of_kills_and_resumes_terminates_without_double_paying() {
    let vault = Arc::new(shared_vault().unlock());
    let barriers = [
        Barrier::PostStagingJournal,
        Barrier::PostQuote,
        Barrier::PostConsent,
        Barrier::PostAnchor,
        Barrier::PostReceiptJournalPreFinalize,
        Barrier::PostFinalizePreComplete,
    ];

    let mut runner = proptest::test_runner::TestRunner::new(ProptestConfig {
        cases: 24,
        failure_persistence: None,
        ..ProptestConfig::default()
    });
    let strategy = proptest::collection::vec(0usize..barriers.len(), 1..5);

    let counter = RefCell::new(0u8);
    runner
        .run(&strategy, |kill_order| {
            let tag = {
                let mut c = counter.borrow_mut();
                *c = c.wrapping_add(1);
                *c
            };
            let seal_id = fixture_seal_id(100u8.wrapping_add(tag));
            stage(&vault, seal_id, SealState::Anchored);

            let mock = MockBackend::new();
            let sink = VaultReceiptSink::new(Arc::clone(&vault));
            let gate = RecordingGate::new();
            let consent = Consent::always_yes();

            for index in &kill_order {
                let kill = KillAt::new(barriers[*index]);
                paying_journal_over(&vault, &sink, |journal| {
                    let backend = CapturingBackend::new(&mock, &sink);
                    let pipeline = Pipeline::new(&backend, &gate, journal, &consent, &kill);
                    // Either it was killed, or the barrier was already
                    // behind this invocation and the seal completed.
                    let _ = block_on(pipeline.resume(&seal_id));
                });
                let state = journal_over(&vault, |journal| journal.state(&seal_id).expect("state"));
                if state.is_terminal() {
                    break;
                }
            }

            // Drive it to a terminal state.
            for _ in 0..8 {
                let state = journal_over(&vault, |journal| journal.state(&seal_id).expect("state"));
                if state.is_terminal() {
                    break;
                }
                let no_barriers = NoBarriers;
                paying_journal_over(&vault, &sink, |journal| {
                    let backend = CapturingBackend::new(&mock, &sink);
                    let pipeline = Pipeline::new(&backend, &gate, journal, &consent, &no_barriers);
                    let _ = block_on(pipeline.resume(&seal_id));
                });
            }

            let state = journal_over(&vault, |journal| journal.state(&seal_id).expect("state"));
            prop_assert!(
                state.is_terminal(),
                "kills {kill_order:?} left the work {}",
                state.name()
            );
            prop_assert!(
                mock.double_paid().is_empty(),
                "kills {kill_order:?} paid a quote hash twice"
            );
            if state == SealState::Complete {
                prop_assert_eq!(mock.stored_count(), 3);
                prop_assert_eq!(mock.store_events(), 3);
            }
            Ok(())
        })
        .expect("no interleaving violates the invariants");
}
