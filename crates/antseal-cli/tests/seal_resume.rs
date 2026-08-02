//! S11 acceptance suite: resume from every kill point, the unconditional
//! re-quote/re-consent rule (D36), the proofs-expired state (D37), and the
//! abandon guard that exists so a journaled nonce is never handed back to
//! the encryptor.
//!
//! Works are staged by hand here rather than by S12's `seal()`, on purpose:
//! resume's guarantees must hold against *the journal*, whatever produced
//! it, and independent staging keeps this suite from co-failing with the
//! code it is meant to hold to account. S16 exercises seal→kill→resume as
//! one flow.
//!
//! NON-SECRET: every fixture value is documented in `common`.

mod common;

use antseal_cli::error::ConsentOutcome;
use antseal_cli::pipeline::{
    Barrier, BlobSlot, NoBarriers, Pipeline, SealError, SealJournal, SealPlan, SealState,
    StagedBlob, StagedBytesUnavailable, UNIT_ENTRY_BASE, WorkIdentity,
};
use antseal_cli::vault::store::{ConsentChannel, SealShapingFlags};
use antseal_core::crypto::material::MasterSecretRef;
use antseal_core::crypto::secrets::SealId;
use antseal_core::storage::compute_storage_address;
use antseal_net::test_util::{Fault, Method, MockBackend, block_on};
use antseal_net::{StorageBackend, StorageError};

use common::{
    FIXTURE_W, KillAt, RecordingBackend, RecordingGate, ScriptedConsent, TraceBarriers,
    fixture_manifest_envelope, fixture_seal_id, with_journal,
};

/// Two units plus the encrypted manifest — the smallest work with a real
/// blob set.
const UNIT_COUNT: u64 = 2;

fn identity(seal_id: SealId, unanchored: bool) -> WorkIdentity<'static> {
    static W: [u8; 32] = FIXTURE_W;
    WorkIdentity {
        w: MasterSecretRef::from_bytes(&W),
        seal_id,
        network: "devnet".to_owned(),
        unanchored,
        degraded: false,
        input_paths_as_given: vec!["a.txt".to_owned()],
        input_paths_absolute: vec!["/tmp/a.txt".to_owned()],
        shaping: SealShapingFlags::default(),
    }
}

fn staged(slot: BlobSlot, fill: u8, len: usize) -> StagedBlob {
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

fn staged_blobs() -> Vec<StagedBlob> {
    vec![
        staged(BlobSlot::Unit { unit_id: 0 }, 0xA0, 512),
        staged(BlobSlot::Unit { unit_id: 1 }, 0xA1, 768),
        staged(BlobSlot::EncryptedManifest, 0xF0, 256),
    ]
}

/// Journal a work into `state`, staged and planned exactly as S12's
/// staging phase leaves it.
fn stage_work(seal_id: SealId, state: SealState, unanchored: bool) {
    with_journal(|journal| {
        journal
            .begin(&identity(seal_id, unanchored))
            .expect("begin");
        for blob in &staged_blobs() {
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
        assert_eq!(journal.state(&seal_id).expect("state"), state);
    });
}

// ─────────────────────────────────────────────────────────────────────
// Kill-point resumes (S11 accept row 1)
// ─────────────────────────────────────────────────────────────────────

/// **Pre-anchor kill**: resume re-runs the anchor submission, then
/// continues through the full money path.
#[test]
fn a_pre_anchor_kill_resumes_by_re_running_the_gate() {
    let seal_id = fixture_seal_id(1);
    stage_work(seal_id, SealState::Staged, false);

    let mock = MockBackend::new();
    let backend = RecordingBackend::new(&mock);
    let gate = RecordingGate::new();
    let consent = ScriptedConsent::always_yes();
    let barriers = TraceBarriers::new();

    let outcome = with_journal(|journal| {
        let pipeline = Pipeline::new(&backend, &gate, journal, &consent, &barriers);
        block_on(pipeline.resume(&seal_id)).expect("resume completes")
    });

    assert_eq!(gate.calls(), 1, "the anchor step re-ran exactly once");
    assert_eq!(backend.quote_calls(), 1);
    assert_eq!(backend.pay_calls(), 1);
    assert_eq!(outcome.addresses.len(), 3);
    assert!(outcome.paid_here);
    with_journal(|journal| {
        assert_eq!(journal.state(&seal_id).expect("state"), SealState::Complete);
    });
}

/// **Post-anchor / pre-pay kill**: resume re-quotes, re-consents, pays,
/// finalizes — and never re-runs the anchor step (nothing anchored is
/// touched, D36 rule 6).
#[test]
fn a_pre_pay_kill_re_quotes_and_re_consents_without_re_anchoring() {
    let seal_id = fixture_seal_id(2);
    stage_work(seal_id, SealState::Anchored, false);

    let mock = MockBackend::new();
    let backend = RecordingBackend::new(&mock);
    let gate = RecordingGate::new();
    let consent = ScriptedConsent::always_yes();

    with_journal(|journal| {
        let pipeline = Pipeline::new(&backend, &gate, journal, &consent, &NoBarriers);
        block_on(pipeline.resume(&seal_id)).expect("resume completes");
    });

    assert_eq!(gate.calls(), 0, "anchors made before the kill stay valid");
    assert_eq!(backend.quote_calls(), 1, "always re-quote (D36 rule 1)");
    assert_eq!(consent.calls(), 1, "always re-consent (D36 rule 2)");
    assert!(consent.last().expect("a consent request").resume);
    assert_eq!(mock.payment_tx_count(), 1);
}

/// **Post-pay / pre-finalize kill**: finalize only. No quote, no consent
/// prompt, no payment — the vacuous case of D36 rule 2, and the reason the
/// pay/finalize split exists.
#[test]
fn a_post_pay_kill_finalizes_without_quoting_consenting_or_paying() {
    let seal_id = fixture_seal_id(3);
    stage_work(seal_id, SealState::Anchored, false);

    let mock = MockBackend::new();
    let backend = RecordingBackend::new(&mock);
    let gate = RecordingGate::new();
    let consent = ScriptedConsent::always_yes();

    // First invocation: pay, then die before finalize.
    let kill = KillAt::new(Barrier::PostReceiptJournalPreFinalize);
    with_journal(|journal| {
        let pipeline = Pipeline::new(&backend, &gate, journal, &consent, &kill);
        let err = block_on(pipeline.resume(&seal_id)).expect_err("killed");
        assert!(matches!(err, SealError::KilledAtBarrier(_)));
    });
    with_journal(|journal| {
        assert_eq!(journal.state(&seal_id).expect("state"), SealState::Paid);
        assert!(journal.receipt(&seal_id).expect("read").is_some());
    });

    let quotes_before = backend.quote_calls();
    let pays_before = backend.pay_calls();
    let consents_before = consent.calls();

    // Second invocation: finalize only.
    with_journal(|journal| {
        let pipeline = Pipeline::new(&backend, &gate, journal, &consent, &NoBarriers);
        let outcome = block_on(pipeline.resume(&seal_id)).expect("finalize-only resume");
        assert!(!outcome.paid_here, "no money moved in this invocation");
    });

    assert_eq!(backend.quote_calls(), quotes_before, "no re-quote");
    assert_eq!(consent.calls(), consents_before, "no consent prompt");
    assert_eq!(backend.pay_calls(), pays_before, "pay never called again");
    assert_eq!(mock.payment_tx_count(), 1, "exactly one payment, ever");
    assert!(mock.double_paid().is_empty());
}

/// **Mid-finalize kill**: `finalize_batch` stored some blobs and died.
/// Resume calls it again with the same receipt — idempotent, no payment,
/// and every blob ends up stored exactly once.
#[test]
fn a_mid_finalize_kill_resumes_idempotently_with_no_new_payment() {
    let seal_id = fixture_seal_id(4);
    stage_work(seal_id, SealState::Anchored, false);

    let mock = MockBackend::new();
    let backend = RecordingBackend::new(&mock);
    let gate = RecordingGate::new();
    let consent = ScriptedConsent::always_yes();

    // The backend-level mid-finalize kill: two of three blobs stored.
    mock.arm_fault(Fault::AfterStoringK(2));
    with_journal(|journal| {
        let pipeline = Pipeline::new(&backend, &gate, journal, &consent, &NoBarriers);
        let err = block_on(pipeline.resume(&seal_id)).expect_err("finalize aborts");
        assert!(matches!(err, SealError::Storage(_)));
    });
    assert_eq!(mock.stored_count(), 2, "a partial store");

    with_journal(|journal| {
        assert_eq!(
            journal.state(&seal_id).expect("state"),
            SealState::Finalizing
        );
        let pipeline = Pipeline::new(&backend, &gate, journal, &consent, &NoBarriers);
        block_on(pipeline.resume(&seal_id)).expect("finalize retry completes");
    });

    assert_eq!(mock.stored_count(), 3, "every blob stored");
    assert_eq!(
        mock.store_events(),
        3,
        "already-stored blobs are skipped, never re-written"
    );
    assert_eq!(mock.payment_tx_count(), 1, "finalize issues no payment");
    assert_eq!(backend.pay_calls(), 1);
}

/// **S11 accept**: the bytes uploaded on resume are the journaled staged
/// bytes, byte for byte — the source tree is never read, so mutating it
/// has no effect (asserted here by there being no source at all: the
/// pipeline has no path to one).
#[test]
fn resume_uploads_exactly_the_journaled_staged_bytes() {
    let seal_id = fixture_seal_id(5);
    stage_work(seal_id, SealState::Anchored, false);

    let mock = MockBackend::new();
    let backend = RecordingBackend::new(&mock);
    let gate = RecordingGate::new();
    let consent = ScriptedConsent::always_yes();

    with_journal(|journal| {
        let pipeline = Pipeline::new(&backend, &gate, journal, &consent, &NoBarriers);
        block_on(pipeline.resume(&seal_id)).expect("resume");
    });

    let uploaded = backend.uploaded.borrow();
    let sent = uploaded.last().expect("one finalize call");
    let expected: Vec<Vec<u8>> = staged_blobs().into_iter().map(|b| b.ciphertext).collect();
    assert_eq!(sent, &expected, "uploaded bytes == staged bytes");

    // And what the network holds equals what was staged.
    for blob in staged_blobs() {
        let fetched = block_on(mock.get_data(blob.address.into())).expect("stored");
        assert_eq!(fetched, blob.ciphertext);
    }
}

// ─────────────────────────────────────────────────────────────────────
// D36: re-quote, re-consent, pay-argument identity, decline ≠ abandon
// ─────────────────────────────────────────────────────────────────────

/// **D36 (iii)**: the quote handed to `pay` is identity-equal to the one
/// `quote_batch` returned in the same invocation and the one consent was
/// rendered against. The mock mints fresh quote hashes per round, so a
/// stale or re-fetched quote would be visibly different.
#[test]
fn pay_receives_exactly_the_quote_consent_affirmed() {
    let seal_id = fixture_seal_id(6);
    stage_work(seal_id, SealState::Anchored, false);

    let mock = MockBackend::new();
    let backend = RecordingBackend::new(&mock);
    let gate = RecordingGate::new();
    let consent = ScriptedConsent::always_yes();

    with_journal(|journal| {
        let pipeline = Pipeline::new(&backend, &gate, journal, &consent, &NoBarriers);
        block_on(pipeline.resume(&seal_id)).expect("resume");
    });

    let quoted = backend.last_quote().expect("a quote");
    let shown = consent.last().expect("a consent request").quote;
    let paid = backend.last_paid_quote().expect("a payment");
    assert_eq!(shown, quoted, "consent saw the fresh quote");
    assert_eq!(paid, quoted, "pay received that same quote object");

    // Ordering, from the mock's own log: quote → pay, in that order.
    let log = mock.call_log();
    let quote_at = log
        .iter()
        .position(|c| c.method == Method::QuoteBatch)
        .expect("a quote call");
    let pay_at = log
        .iter()
        .position(|c| c.method == Method::Pay)
        .expect("a pay call");
    assert!(quote_at < pay_at, "quote_batch precedes pay");
}

/// **D36 rule 3**: declining leaves the work `incomplete` — no `pay`, no
/// state transition, no state loss. Declining is not abandonment.
#[test]
fn declining_the_re_consent_leaves_the_work_incomplete_never_abandoned() {
    let seal_id = fixture_seal_id(7);
    stage_work(seal_id, SealState::Anchored, false);

    let mock = MockBackend::new();
    let backend = RecordingBackend::new(&mock);
    let gate = RecordingGate::new();
    let consent = ScriptedConsent::always_declines();

    with_journal(|journal| {
        let pipeline = Pipeline::new(&backend, &gate, journal, &consent, &NoBarriers);
        match block_on(pipeline.resume(&seal_id)) {
            Err(SealError::ConsentDeclined(ConsentOutcome::Declined)) => {}
            other => panic!("expected a decline, got {other:?}"),
        }
    });

    assert_eq!(backend.pay_calls(), 0, "no payment on a decline");
    assert_eq!(mock.payment_tx_count(), 0);
    with_journal(|journal| {
        assert_eq!(
            journal.state(&seal_id).expect("state"),
            SealState::Anchored,
            "the work stays exactly where it was"
        );
        assert!(journal.state(&seal_id).expect("state").is_incomplete());
    });

    // And it is still resumable afterwards, at whatever the market quotes.
    let consent = ScriptedConsent::always_yes();
    with_journal(|journal| {
        let pipeline = Pipeline::new(&backend, &gate, journal, &consent, &NoBarriers);
        block_on(pipeline.resume(&seal_id)).expect("resumable after a decline");
    });
    assert_eq!(mock.payment_tx_count(), 1);
}

/// **D36 rule 4**: the re-consent render is given the prior journaled
/// consent, so it can show that the price moved. Display only — nothing
/// gates on it.
#[test]
fn the_re_consent_render_receives_the_prior_consent_record() {
    let seal_id = fixture_seal_id(8);
    stage_work(seal_id, SealState::Anchored, false);

    let mock = MockBackend::new();
    let backend = RecordingBackend::new(&mock);
    let gate = RecordingGate::new();

    // First attempt declines *after* the consent record would exist only
    // if one had been granted — so seed one explicitly, as the original
    // pre-kill invocation would have.
    with_journal(|journal| {
        journal
            .put_consent(
                &seal_id,
                antseal_cli::vault::store::ConsentRecord {
                    total_ant_atto: 999,
                    gas_estimate_wei: 111,
                    consent_time_unix_secs: 1_700_000_000,
                    channel: ConsentChannel::Interactive,
                },
            )
            .expect("seed prior consent");
    });

    let consent = ScriptedConsent::always_yes();
    with_journal(|journal| {
        let pipeline = Pipeline::new(&backend, &gate, journal, &consent, &NoBarriers);
        block_on(pipeline.resume(&seal_id)).expect("resume");
    });

    let seen = consent.last().expect("a consent request");
    assert!(seen.had_prior, "the prior consent record was offered");
    assert!(seen.resume);
    assert!(!seen.proofs_expired);

    // The journaled record is now the fresh one (latest wins).
    with_journal(|journal| {
        let record = journal.consent(&seal_id).expect("read").expect("present");
        assert_ne!(record.total_ant_atto, 999);
        assert_eq!(record.channel, ConsentChannel::YesFlag);
    });
}

// ─────────────────────────────────────────────────────────────────────
// D37: the proofs-expired state
// ─────────────────────────────────────────────────────────────────────

/// **D37 / S11 accept**: an expired-proof resume surfaces the state
/// distinctly and requires a fresh consent before any re-payment — it is
/// never silent, and the consent render is told the previous spend is
/// stranded.
#[test]
fn expired_proofs_require_a_fresh_consent_before_re_payment() {
    let seal_id = fixture_seal_id(9);
    stage_work(seal_id, SealState::Paid, false);
    // A journaled receipt is the precondition of the post-pay path.
    let mock = MockBackend::new();
    let backend = ExpiringOnce::new(&mock);
    let gate = RecordingGate::new();
    let consent = ScriptedConsent::always_yes();

    with_journal(|journal| {
        journal
            .put_receipt(&seal_id, &block_on(seed_receipt(&mock)))
            .expect("seed receipt");
        let pipeline = Pipeline::new(&backend, &gate, journal, &consent, &NoBarriers);
        block_on(pipeline.resume(&seal_id)).expect("re-payment completes the seal");
    });

    let seen = consent.last().expect("a consent request");
    assert!(
        seen.proofs_expired,
        "the render is told the prior payment is stranded"
    );
    assert_eq!(consent.calls(), 1, "exactly one fresh consent");
    with_journal(|journal| {
        assert_eq!(journal.state(&seal_id).expect("state"), SealState::Complete);
    });
}

/// Declining the proofs-expired re-consent leaves the work incomplete —
/// the same D36 rule 3, applied to the stranded case.
#[test]
fn declining_the_proofs_expired_consent_leaves_the_work_incomplete() {
    let seal_id = fixture_seal_id(10);
    stage_work(seal_id, SealState::Paid, false);
    let mock = MockBackend::new();
    let backend = ExpiringOnce::new(&mock);
    let gate = RecordingGate::new();
    let consent = ScriptedConsent::always_declines();

    with_journal(|journal| {
        journal
            .put_receipt(&seal_id, &block_on(seed_receipt(&mock)))
            .expect("seed receipt");
        let pipeline = Pipeline::new(&backend, &gate, journal, &consent, &NoBarriers);
        match block_on(pipeline.resume(&seal_id)) {
            Err(SealError::ConsentDeclined(_)) => {}
            other => panic!("expected a decline, got {other:?}"),
        }
    });
    with_journal(|journal| {
        assert!(journal.state(&seal_id).expect("state").is_incomplete());
    });
}

// ─────────────────────────────────────────────────────────────────────
// The abandon guard (S11 accept row 3)
// ─────────────────────────────────────────────────────────────────────

/// **S11 accept**: with staged bytes deleted, resume returns the distinct
/// abandoned error, marks the state, and never reaches the network — so no
/// encryption can possibly run with a journaled nonce, because resume has
/// no encryption path and no `W` at all.
#[test]
fn deleted_staged_bytes_abandon_the_seal_without_touching_the_network() {
    let seal_id = fixture_seal_id(11);
    stage_work(seal_id, SealState::Anchored, false);
    with_journal(|journal| {
        journal
            .store()
            .delete_journal_entry(&seal_id, UNIT_ENTRY_BASE + 1)
            .expect("delete a staged unit");
    });

    let mock = MockBackend::new();
    let backend = RecordingBackend::new(&mock);
    let gate = RecordingGate::new();
    let consent = ScriptedConsent::always_yes();

    with_journal(|journal| {
        let pipeline = Pipeline::new(&backend, &gate, journal, &consent, &NoBarriers);
        match block_on(pipeline.resume(&seal_id)) {
            Err(SealError::StagedBytes(StagedBytesUnavailable::Missing)) => {}
            other => panic!("expected the abandon error, got {other:?}"),
        }
        assert_eq!(
            journal.state(&seal_id).expect("state"),
            SealState::Abandoned
        );
    });

    assert_eq!(mock.call_log().len(), 0, "no backend call was made");
    assert_eq!(gate.calls(), 0);
    assert_eq!(consent.calls(), 0);
}

/// Corrupted staged bytes abandon too: the S4 address recompute is what
/// catches a flipped bit that authentication alone would not.
#[test]
fn corrupted_staged_bytes_abandon_via_the_address_recompute() {
    let seal_id = fixture_seal_id(12);
    stage_work(seal_id, SealState::Anchored, false);
    with_journal(|journal| {
        // Re-journal one unit with bytes that no longer hash to its
        // recorded address (the record itself stays authentic).
        let mut blob = journal
            .staged(&seal_id, BlobSlot::Unit { unit_id: 0 })
            .expect("staged");
        blob.ciphertext[7] ^= 0x01;
        journal.put_staged(&seal_id, &blob).expect("re-journal");
    });

    let mock = MockBackend::new();
    let gate = RecordingGate::new();
    let consent = ScriptedConsent::always_yes();
    with_journal(|journal| {
        let pipeline = Pipeline::new(&mock, &gate, journal, &consent, &NoBarriers);
        match block_on(pipeline.resume(&seal_id)) {
            Err(SealError::StagedBytes(StagedBytesUnavailable::AddressMismatch)) => {}
            other => panic!("expected an integrity abandon, got {other:?}"),
        }
        assert_eq!(
            journal.state(&seal_id).expect("state"),
            SealState::Abandoned
        );
    });
    assert_eq!(mock.call_log().len(), 0);
}

/// Terminal works are refused, in both directions.
#[test]
fn terminal_works_are_not_resumable() {
    for (tag, state) in [(13u8, SealState::Complete), (14, SealState::Abandoned)] {
        let seal_id = fixture_seal_id(tag);
        stage_work(seal_id, SealState::Anchored, false);
        with_journal(|journal| {
            if state == SealState::Abandoned {
                journal
                    .set_state(&seal_id, SealState::Abandoned)
                    .expect("abandon");
            } else {
                for step in [SealState::Paid, SealState::Finalizing, SealState::Complete] {
                    journal.set_state(&seal_id, step).expect("advance");
                }
            }
        });

        let mock = MockBackend::new();
        let gate = RecordingGate::new();
        let consent = ScriptedConsent::always_yes();
        with_journal(|journal| {
            let pipeline = Pipeline::new(&mock, &gate, journal, &consent, &NoBarriers);
            match block_on(pipeline.resume(&seal_id)) {
                Err(SealError::NotResumable { state: got }) => assert_eq!(got, state.name()),
                other => panic!("expected NotResumable, got {other:?}"),
            }
        });
        assert_eq!(mock.call_log().len(), 0);
    }
}

/// An anchor-gate refusal on a pre-anchor resume aborts with zero money
/// spent — the cheap-before-irreversible ordering, on the resume path too.
#[test]
fn an_anchor_gate_refusal_aborts_a_resume_before_any_payment() {
    let seal_id = fixture_seal_id(15);
    stage_work(seal_id, SealState::Staged, false);

    let mock = MockBackend::new();
    let gate = RecordingGate::refusing();
    let consent = ScriptedConsent::always_yes();
    with_journal(|journal| {
        let pipeline = Pipeline::new(&mock, &gate, journal, &consent, &NoBarriers);
        assert!(matches!(
            block_on(pipeline.resume(&seal_id)),
            Err(SealError::AnchorGate(_))
        ));
    });

    assert_eq!(gate.calls(), 1);
    assert_eq!(mock.payment_tx_count(), 0, "no EVM tx");
    // The quote precedes the gate (consent is rendered against it, and
    // consent precedes anchoring) — so a quote call is expected. What must
    // not have happened is anything irreversible.
    assert_eq!(
        mock.call_log().iter().map(|c| c.method).collect::<Vec<_>>(),
        vec![Method::QuoteBatch],
        "the read-only quote, and nothing else"
    );
    assert_eq!(mock.calls(Method::Pay), 0);
    assert_eq!(mock.calls(Method::FinalizeBatch), 0);
    assert_eq!(mock.stored_count(), 0);
    with_journal(|journal| {
        assert_eq!(journal.state(&seal_id).expect("state"), SealState::Staged);
    });
}

/// **S13, resume side**: an unanchored work never calls the gate on
/// resume either — not even a real, submitting gate double.
#[test]
fn an_unanchored_work_never_calls_the_gate_on_resume() {
    let seal_id = fixture_seal_id(16);
    stage_work(seal_id, SealState::Staged, true);

    let mock = MockBackend::new();
    let gate = RecordingGate::refusing();
    let consent = ScriptedConsent::always_yes();
    with_journal(|journal| {
        let pipeline = Pipeline::new(&mock, &gate, journal, &consent, &NoBarriers);
        block_on(pipeline.resume(&seal_id)).expect("unanchored resume completes");
    });
    assert_eq!(
        gate.calls(),
        0,
        "a refusing gate cannot refuse what is never called"
    );
}

// ─────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────

/// A receipt for the work's blob set, obtained the way the pipeline would.
async fn seed_receipt(mock: &MockBackend) -> antseal_net::PaymentReceipt {
    let blobs: Vec<antseal_net::Blob> = staged_blobs()
        .into_iter()
        .map(|b| antseal_net::Blob::new(b.ciphertext).expect("under the cap"))
        .collect();
    let quote = mock.quote_batch(&blobs).await.expect("quote");
    mock.pay(&quote).await.expect("pay")
}

/// A backend whose **first** `finalize_batch` reports expired proofs (D37's
/// ~24 h window), and which behaves normally afterwards. The mock cannot
/// simulate node-side proof age, so the window is modelled at the boundary
/// where it is actually observed.
struct ExpiringOnce<'m> {
    inner: &'m MockBackend,
    armed: std::cell::Cell<bool>,
}

impl<'m> ExpiringOnce<'m> {
    fn new(inner: &'m MockBackend) -> Self {
        Self {
            inner,
            armed: std::cell::Cell::new(true),
        }
    }
}

impl StorageBackend for ExpiringOnce<'_> {
    async fn quote_batch(
        &self,
        blobs: &[antseal_net::Blob],
    ) -> Result<antseal_net::CostQuote, StorageError> {
        self.inner.quote_batch(blobs).await
    }

    async fn pay(
        &self,
        quote: &antseal_net::CostQuote,
    ) -> Result<antseal_net::PaymentReceipt, StorageError> {
        self.inner.pay(quote).await
    }

    async fn finalize_batch(
        &self,
        receipt: &antseal_net::PaymentReceipt,
        blobs: &[antseal_net::Blob],
    ) -> Result<Vec<antseal_net::Address>, StorageError> {
        if self.armed.replace(false) {
            return Err(StorageError::ProofsExpired);
        }
        self.inner.finalize_batch(receipt, blobs).await
    }

    async fn get_data(&self, address: antseal_net::Address) -> Result<Vec<u8>, StorageError> {
        self.inner.get_data(address).await
    }

    async fn balances(&self) -> Result<antseal_net::BalanceReport, StorageError> {
        self.inner.balances().await
    }
}
