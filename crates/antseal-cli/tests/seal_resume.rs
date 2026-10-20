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

/// **S43 Accept 2 (B7, D179 R2).** Since S43 the adapter answers a refused
/// proof over a payment that is not a day old by its block time — and any
/// shortfall the declines did not decide — with a retryable `Finalize` error
/// (exit 23), never `ProofsExpired`. Resume must meet that by finalizing
/// again: no re-quote, no consent prompt, and no second payment, in the
/// invocation that failed or in the one that finishes.
#[test]
fn a_retryable_finalize_failure_resumes_without_paying_again() {
    let seal_id = fixture_seal_id(17);
    stage_work(seal_id, SealState::Paid, false);
    let mock = MockBackend::new();
    let backend = FinalizeFailsOnce::new(&mock);
    let gate = RecordingGate::new();
    let consent = ScriptedConsent::always_yes();

    let first = with_journal(|journal| {
        journal
            .put_receipt(&seal_id, &block_on(seed_receipt(&mock)))
            .expect("seed receipt");
        let pipeline = Pipeline::new(&backend, &gate, journal, &consent, &NoBarriers);
        block_on(pipeline.resume(&seal_id))
    });
    assert_eq!(
        mock.payment_tx_count(),
        1,
        "resume paid again ({} payment txs) after a retryable finalize (S43 B7)",
        mock.payment_tx_count()
    );
    assert_eq!(consent.calls(), 0, "a retry asks for no consent");
    match first {
        Err(SealError::Storage(StorageError::Finalize { .. })) => {}
        other => panic!("a retryable finalize failure surfaces as itself: {other:?}"),
    }
    with_journal(|journal| {
        assert!(
            journal.state(&seal_id).expect("state").is_incomplete(),
            "the work stays incomplete, never abandoned"
        );
    });

    let outcome = with_journal(|journal| {
        let pipeline = Pipeline::new(&backend, &gate, journal, &consent, &NoBarriers);
        block_on(pipeline.resume(&seal_id)).expect("the retry completes the seal")
    });
    assert!(!outcome.paid_here, "no money moved in this invocation");
    assert_eq!(outcome.paid_atto, 0, "nothing paid here");
    assert_eq!(mock.payment_tx_count(), 1, "exactly one payment, ever");
    assert_eq!(consent.calls(), 0, "no consent prompt in either invocation");
    assert!(mock.double_paid().is_empty());
    with_journal(|journal| {
        assert_eq!(journal.state(&seal_id).expect("state"), SealState::Complete);
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

/// A backend whose **first** `finalize_batch` reports expired proofs, and
/// which behaves normally afterwards. Since S43 the adapter returns
/// `ProofsExpired` only when a majority of the storing peers refused the proof
/// and the payment is more than 24 hours old by its block time
/// (`antseal_net::put_policy`); the mock models neither peers nor blocks, so
/// the verdict is modelled at the boundary where the pipeline observes it.
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

/// A backend whose **first** `finalize_batch` fails with the retryable
/// `Finalize` error S43's adapter returns for a refusal that is not decisive,
/// or one over a payment younger than a day — and which behaves normally
/// afterwards.
struct FinalizeFailsOnce<'m> {
    inner: &'m MockBackend,
    armed: std::cell::Cell<bool>,
}

impl<'m> FinalizeFailsOnce<'m> {
    fn new(inner: &'m MockBackend) -> Self {
        Self {
            inner,
            armed: std::cell::Cell::new(true),
        }
    }
}

impl StorageBackend for FinalizeFailsOnce<'_> {
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
            return Err(StorageError::Finalize {
                reason: "7 of 7 storing peers refused the payment proof, but the payment is not \
                         more than 24 hours old by its block time"
                    .to_owned(),
            });
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

// ─────────────────────────────────────────────────────────────────────
// D210 (U114 + U115): the plan, `list` and `abandon` over a post-pay or
// stranded payment, held against what the next resume asks
// ─────────────────────────────────────────────────────────────────────

/// **D210** (U114, U115): what the resume plan, `list` and `antseal
/// abandon` say about a work whose tag and money do not tell the same story,
/// read against what that work's next resume actually asks for.
///
/// Each work lives in a vault of its own: `detect` and `list` read every
/// work in the vault, and the shared one holds every other test's.
mod d210 {
    use super::*;

    use std::cell::Cell;
    use std::sync::Arc;

    use antseal_cli::error::ErrorClass;
    use antseal_cli::listing::{ResumeClock, WorkListing};
    use antseal_cli::pipeline::journal::JournalError;
    use antseal_cli::pipeline::receipt_sink::recorded_receipt;
    use antseal_cli::pipeline::{VaultJournal, VaultReceiptSink};
    use antseal_cli::seal_resume::{ResumeDecision, abandon_pre_pay, detect, resume_plan_lines};
    use antseal_cli::vault::session::UnlockedVault;
    use antseal_cli::vault::store::WorkStore;
    use antseal_net::{
        Blob, BlobCost, BlobQuote, CaptureOutcome, CostQuote, GasSummary, NetworkId,
        PaymentReceipt, QuoteHash, TxHash, TxRecord, TxStatus,
    };

    use crate::common::{IsolatedVault, SeenConsent, journal_over, rng};

    /// Words that promise a resume will not charge. Every work below is one
    /// whose next resume asks to pay, so none may appear in its plan (U114).
    const NO_CHARGE_PROMISES: [&str; 4] = [
        "no further payment",
        "already paid for",
        "PAID",
        "upload only",
    ];

    fn hex(seal_id: &SealId) -> String {
        seal_id
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    /// The staged blobs as the backend sees them, in canonical order.
    fn blobs() -> Vec<Blob> {
        staged_blobs()
            .into_iter()
            .map(|blob| Blob::new(blob.ciphertext).expect("under the cap"))
            .collect()
    }

    /// [`stage_work`]'s walk — `begin`, every staged blob, the plan, then
    /// `set_state` up the S10 machine — over this test's own vault.
    fn stage(vault: &UnlockedVault, seal_id: SealId, state: SealState) {
        journal_over(vault, |journal| {
            journal.begin(&identity(seal_id, false)).expect("begin");
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
            for step in [SealState::Anchored, SealState::Paid] {
                if journal.state(&seal_id).expect("state") == state {
                    break;
                }
                journal.set_state(&seal_id, step).expect("advance");
            }
            assert_eq!(journal.state(&seal_id).expect("state"), state);
        });
    }

    fn tag(vault: &UnlockedVault, seal_id: &SealId) -> SealState {
        journal_over(vault, |journal| journal.state(seal_id).expect("tag"))
    }

    fn journaled_receipt(vault: &UnlockedVault, seal_id: &SealId) -> Option<PaymentReceipt> {
        recorded_receipt(&WorkStore::new(vault), seal_id).expect("the receipt reads")
    }

    /// The plan `seal --dry-run` prints for the one work in `vault`:
    /// `run_seal`'s own two reads, in its order (`seal_run.rs`) — D45
    /// detection over the recorded identity, then [`resume_plan_lines`] over
    /// the receipt `recorded_receipt` reads.
    fn plan_of(vault: &UnlockedVault) -> Vec<String> {
        let store = WorkStore::new(vault);
        let recorded = identity(fixture_seal_id(0), false);
        let decision = detect(
            &store,
            NetworkId::Devnet,
            &recorded.input_paths_absolute,
            &recorded.shaping,
        )
        .expect("detection reads the vault");
        let ResumeDecision::Resume(candidate) = decision else {
            panic!("the recorded command exact-matches its own work: {decision:?}");
        };
        let receipt = recorded_receipt(&store, &candidate.seal_id).expect("the receipt reads");
        resume_plan_lines(&candidate, receipt.as_ref())
    }

    /// `list`'s money note for the one unfinished work in `vault`: the line
    /// just above its `resume with:` line.
    fn list_note(vault: &UnlockedVault) -> String {
        let lines = WorkListing::gather(&WorkStore::new(vault))
            .expect("list reads the vault")
            .render();
        let commands: Vec<usize> = lines
            .iter()
            .enumerate()
            .filter(|(_, line)| line.starts_with("  resume with: "))
            .map(|(at, _)| at)
            .collect();
        assert_eq!(
            commands.len(),
            1,
            "one unfinished work:\n{}",
            lines.join("\n")
        );
        assert!(commands[0] > 0, "{}", lines.join("\n"));
        lines[commands[0] - 1].clone()
    }

    /// `antseal abandon`'s engine on the work, which rule 2 must refuse: the
    /// refusal as the user reads it.
    fn refusal(vault: &UnlockedVault, seal_id: &SealId) -> String {
        let store = WorkStore::new(vault);
        let err = journal_over(vault, |journal| abandon_pre_pay(&store, journal, seal_id))
            .expect_err("rule 2 refuses the work");
        assert_eq!(err.class(), ErrorClass::Usage, "{err}");
        err.to_string()
    }

    /// What the work's next resume asks for, with nothing paid: the one
    /// consent request a declining gate is shown (D36 rule 3 leaves the
    /// work where it was).
    fn next_ask<B: StorageBackend>(
        vault: &UnlockedVault,
        backend: &B,
        seal_id: &SealId,
    ) -> SeenConsent {
        let consent = ScriptedConsent::always_declines();
        let gate = RecordingGate::new();
        let outcome = journal_over(vault, |journal| {
            let pipeline = Pipeline::new(backend, &gate, journal, &consent, &NoBarriers);
            block_on(pipeline.resume(seal_id))
        });
        match outcome {
            Err(SealError::ConsentDeclined(_)) => {}
            other => panic!("the resume asks before it pays, and is declined: {other:?}"),
        }
        assert_eq!(consent.calls(), 1, "one consent request");
        consent.last().expect("the request")
    }

    /// How many of the request's quote lines cost something.
    fn priced(seen: &SeenConsent) -> usize {
        seen.quote
            .blobs
            .iter()
            .filter(|line| matches!(line.cost, BlobCost::Priced { .. }))
            .count()
    }

    /// `list`'s proof clock, as the plan indents its lines.
    fn clock_line() -> String {
        format!("    {}", ResumeClock::TimeBoxed.note())
    }

    /// The plan claims nothing its next resume contradicts: no word of it
    /// promises that the resume will not charge (U114).
    fn assert_promises_no_free_finish(plan: &[String], asked: &SeenConsent) {
        let text = plan.join("\n");
        for promise in NO_CHARGE_PROMISES {
            assert!(
                !text.contains(promise),
                "the plan promised no further payment ({promise:?}) while the resume asked for \
                 {} blob(s), {} of them priced:\n{text}",
                asked.blob_count,
                priced(asked)
            );
        }
    }

    /// Rule 2's RECEIPT clause, as a refusal of `seal_id` reads: what the
    /// vault records, and a way forward the work's next resume keeps — it
    /// asks first, buys only what the receipt does not cover, and past the
    /// proof clock buys again.
    fn assert_receipt_clause(text: &str, seal_id: &SealId) {
        let opening = format!(
            "usage error: a payment is recorded for work {} — its payment receipt maps quotes to \
             transactions. ",
            hex(seal_id)
        );
        assert!(text.starts_with(&opening), "{text}");
        for clause in [
            "which asks before any payment and pays only for what the receipt does not cover",
            "and after that finishing it costs a second payment",
        ] {
            assert!(text.contains(clause), "missing {clause:?}:\n{text}");
        }
    }

    /// The pipeline makes the work's first payment and is killed before its
    /// upload (`PostReceiptJournalPreFinalize`): the receipt and the `Paid`
    /// tag are the pipeline's own writes.
    fn paid_by_the_pipeline(vault: &UnlockedVault, mock: &MockBackend, seal_id: &SealId) {
        let consent = ScriptedConsent::always_yes();
        let gate = RecordingGate::new();
        let kill = KillAt::new(Barrier::PostReceiptJournalPreFinalize);
        let outcome = journal_over(vault, |journal| {
            let pipeline = Pipeline::new(mock, &gate, journal, &consent, &kill);
            block_on(pipeline.resume(seal_id))
        });
        match outcome {
            Err(SealError::KilledAtBarrier(_)) => {}
            other => panic!("killed once the receipt was journaled: {other:?}"),
        }
        assert_eq!(tag(vault, seal_id), SealState::Paid);
        let paid = journaled_receipt(vault, seal_id).expect("journaled");
        assert_eq!(paid.blobs.len(), 3, "control: one record per staged blob");
    }

    /// A backend over [`MockBackend`] for D210's pipeline-built shapes. Its
    /// first `finalize_batch` reports expired proofs when `expire` is set
    /// (the verdict [`ExpiringOnce`] models), and its first `pay` lands only
    /// the first quote line — journaled through the REAL durable sink, as
    /// the adapter journals each landed sub-batch from inside `pay` (D37
    /// Decision 7) — and then strands (exit 28, S46). Every later call is
    /// the mock's.
    struct StrandsAfterOneLine<'m> {
        inner: &'m MockBackend,
        sink: Arc<VaultReceiptSink>,
        expire: Cell<bool>,
        strand: Cell<bool>,
    }

    impl StorageBackend for StrandsAfterOneLine<'_> {
        async fn quote_batch(&self, blobs: &[Blob]) -> Result<CostQuote, StorageError> {
            self.inner.quote_batch(blobs).await
        }

        async fn pay(&self, quote: &CostQuote) -> Result<PaymentReceipt, StorageError> {
            if !self.strand.replace(false) {
                return self.inner.pay(quote).await;
            }
            let first: Vec<BlobQuote> = quote.blobs.iter().take(1).cloned().collect();
            let total_ant_atto: u128 = first
                .iter()
                .map(|line| match &line.cost {
                    BlobCost::AlreadyStored => 0,
                    BlobCost::Priced { payments, .. } => {
                        payments.iter().map(|payment| payment.amount_atto).sum()
                    }
                })
                .sum();
            let landed = self
                .inner
                .pay(&CostQuote {
                    blobs: first,
                    total_ant_atto,
                    gas_estimate_wei: 0,
                })
                .await?;
            assert_eq!(
                self.sink.capture(&landed),
                CaptureOutcome::Durable,
                "the landed sub-batch is journaled before the strand"
            );
            Err(StorageError::StrandedPayment {
                landed_tx_count: landed.txs.len(),
                reason: "the second sub-batch failed (test double)".to_owned(),
            })
        }

        async fn finalize_batch(
            &self,
            receipt: &PaymentReceipt,
            blobs: &[Blob],
        ) -> Result<Vec<antseal_net::Address>, StorageError> {
            if self.expire.replace(false) {
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

    /// One consented resume of `seal_id` through [`StrandsAfterOneLine`], with
    /// D37's durable sink wired into the journal as the binary wires it
    /// (`VaultJournal::with_receipt_sink`). It strands; the work's tag is
    /// returned.
    fn strand_once(
        vault: &Arc<UnlockedVault>,
        mock: &MockBackend,
        seal_id: &SealId,
        expire: bool,
    ) -> SealState {
        let sink = VaultReceiptSink::new(Arc::clone(vault));
        let backend = StrandsAfterOneLine {
            inner: mock,
            sink: Arc::clone(&sink),
            expire: Cell::new(expire),
            strand: Cell::new(true),
        };
        let consent = ScriptedConsent::always_yes();
        let gate = RecordingGate::new();
        let mut r = rng();
        let journal = VaultJournal::new(WorkStore::new(vault), &mut r).with_receipt_sink(sink);
        let outcome = {
            let pipeline = Pipeline::new(&backend, &gate, &journal, &consent, &NoBarriers);
            block_on(pipeline.resume(seal_id))
        };
        match outcome {
            Err(SealError::Storage(StorageError::StrandedPayment { .. })) => {}
            other => panic!("the payment strands after its first sub-batch (exit 28): {other:?}"),
        }
        assert_eq!(
            consent.calls(),
            1,
            "one consent, for the payment that stranded"
        );
        assert_eq!(
            consent.last().expect("the request").proofs_expired,
            expire,
            "control: the consent was the expected kind"
        );
        let capture = journaled_receipt(vault, seal_id).expect("the sink's capture");
        assert_eq!(
            capture.blobs.len(),
            1,
            "control: the landed sub-batch covers one of the three blobs"
        );
        tag(vault, seal_id)
    }

    /// D204 §1.4's capture, NON-SECRET synthetic bytes: what a build before
    /// S50 journaled for a first sub-batch that reverted — a receipt that
    /// maps no quote and moved no ANT.
    fn revert_only_receipt() -> PaymentReceipt {
        PaymentReceipt {
            blobs: Vec::new(),
            tx_map: std::collections::BTreeMap::new(),
            txs: vec![TxRecord {
                tx_hash: TxHash::from_bytes([0xD7; 32]),
                block_number: Some(43),
                status: TxStatus::Reverted,
                quote_hashes: vec![QuoteHash::from_bytes([0xD8; 32])],
            }],
            storage_cost_atto: 0,
            gas: GasSummary {
                gas_cost_wei: 21_000,
            },
        }
    }

    /// **G-U114-1 — legacy case 1.** `Paid` over the capture a build before
    /// S50 journaled for a first sub-batch that reverted (a receipt that maps
    /// no quote), the tag as the repair before D203 M5 wrote it — both
    /// planted with their production writers (`set_state` up the machine,
    /// `put_receipt`). No payment is recorded and the next resume asks to
    /// buy every blob, so the plan says exactly that, carries no proof clock
    /// (`list` puts the work on the re-quote clock too), and abandon's
    /// refusal claims no payment.
    ///
    /// Red at ab7226f: "PAID — the payment receipt is journaled" / "upload
    /// only (no further payment)" / "This seal is already paid for. …".
    #[test]
    fn u114_case_1_a_paid_tag_over_a_receipt_that_maps_nothing_is_not_called_paid() {
        let iso = IsolatedVault::create("d210-case-1");
        let vault = iso.unlock();
        let seal_id = fixture_seal_id(0xD1);
        stage(&vault, seal_id, SealState::Paid);
        journal_over(&vault, |journal| {
            journal
                .put_receipt(&seal_id, &revert_only_receipt())
                .expect("the pre-S50 capture");
        });

        let plan = plan_of(&vault);
        let mock = MockBackend::new();
        let next = next_ask(&vault, &mock, &seal_id);
        assert_eq!(
            (next.blob_count, priced(&next), next.proofs_expired),
            (3, 3, false),
            "control: the resume buys every blob"
        );
        assert_promises_no_free_finish(&plan, &next);
        assert_eq!(
            &plan[1..],
            &[
                "    staged:    past its payment step, but no payment is recorded".to_owned(),
                "    remaining: pay, if anything is priced, then upload".to_owned(),
            ][..],
            "the plan claims a payment the vault does not record:\n{plan:#?}"
        );
        assert_eq!(
            list_note(&vault),
            format!("  {}", ResumeClock::ReQuote.note())
        );
        let text = refusal(&vault, &seal_id);
        assert!(
            !text.contains("a payment is recorded") && !text.contains("been paid for"),
            "rule 2's state clause claims a payment the vault does not record:\n{text}"
        );
    }

    /// **G-U114-2 — legacy case 2.** `Paid` over a partial payment whose
    /// remainder was declined (the repair before D203 M5 tagged it first):
    /// a payment IS recorded and the rest is owed, so the plan says a payment
    /// is recorded, that the rest is paid if any is owed, and closes on the
    /// proof clock — and the next resume asks for exactly the two blobs the
    /// partial did not buy.
    ///
    /// Red at ab7226f: the same three post-pay lines as case 1.
    #[test]
    fn u114_case_2_a_paid_tag_over_a_partial_payment_says_the_rest_is_owed() {
        let iso = IsolatedVault::create("d210-case-2");
        let vault = iso.unlock();
        let seal_id = fixture_seal_id(0xD2);
        stage(&vault, seal_id, SealState::Paid);
        let mock = MockBackend::new();
        let partial = block_on(async {
            let quote = mock.quote_batch(&blobs()[..1]).await.expect("quote");
            mock.pay(&quote).await.expect("pay")
        });
        journal_over(&vault, |journal| {
            journal
                .put_receipt(&seal_id, &partial)
                .expect("the partial capture");
        });

        let plan = plan_of(&vault);
        let next = next_ask(&vault, &mock, &seal_id);
        assert_eq!(
            (next.blob_count, priced(&next), next.proofs_expired),
            (2, 2, false),
            "control: the resume buys the remainder"
        );
        assert_promises_no_free_finish(&plan, &next);
        assert_eq!(
            &plan[1..],
            &[
                "    staged:    a payment is recorded; the upload has not started".to_owned(),
                "    remaining: pay the rest, if any, then upload".to_owned(),
                clock_line(),
            ][..],
            "{plan:#?}"
        );
        assert_receipt_clause(&refusal(&vault, &seal_id), &seal_id);
    }

    /// **G-U114-X, shape X-A — reachable at HEAD.** Built by the pipeline end
    /// to end: the first payment (killed before its upload), then a resume
    /// whose upload meets expired proofs and whose fresh consent is
    /// DECLINED (D36 rule 3) — `Finalizing` over a payment whose proofs no
    /// longer buy anything. The next resume asks to buy every blob again,
    /// so the plan may not call the work paid; it says a payment is recorded
    /// and closes on the proof clock that names the second payment.
    ///
    /// Red at ab7226f: "PAID — upload was interrupted part-way" / "resume the
    /// upload (no further payment)" / "This seal is already paid for. …".
    #[test]
    fn u114_x_a_a_declined_expired_proof_re_consent_is_not_called_paid() {
        let iso = IsolatedVault::create("d210-x-a");
        let vault = iso.unlock();
        let seal_id = fixture_seal_id(0xD3);
        stage(&vault, seal_id, SealState::Anchored);
        let mock = MockBackend::new();
        paid_by_the_pipeline(&vault, &mock, &seal_id);
        let declined = next_ask(&vault, &ExpiringOnce::new(&mock), &seal_id);
        assert!(
            declined.proofs_expired,
            "control: the expired-proof re-consent"
        );
        assert_eq!(tag(&vault, &seal_id), SealState::Finalizing);

        let plan = plan_of(&vault);
        // The proofs are still expired: the next resume asks again.
        let next = next_ask(&vault, &ExpiringOnce::new(&mock), &seal_id);
        assert_eq!(
            (next.blob_count, priced(&next), next.proofs_expired),
            (3, 3, true),
            "control: the next resume buys every blob again"
        );
        assert_promises_no_free_finish(&plan, &next);
        assert_eq!(
            &plan[1..],
            &[
                "    staged:    a payment is recorded; the upload was interrupted".to_owned(),
                "    remaining: pay the rest, if any, then resume the upload".to_owned(),
                clock_line(),
            ][..],
            "{plan:#?}"
        );
        assert_receipt_clause(&refusal(&vault, &seal_id), &seal_id);
    }

    /// **G-U114-X, shape X-B — reachable at HEAD.** Built by the pipeline: the
    /// first payment (killed before its upload), then a resume whose upload
    /// meets expired proofs and whose consented RE-PAYMENT strands after its
    /// first sub-batch (exit 28) — `Finalizing` over the durable sink's
    /// capture of that one sub-batch. The next resume asks for the two blobs
    /// the re-payment did not reach, so the plan says the rest is owed.
    ///
    /// Red at ab7226f: the same three lines as X-A.
    #[test]
    fn u114_x_b_a_stranded_expired_proof_re_payment_is_not_called_paid() {
        let iso = IsolatedVault::create("d210-x-b");
        let vault = Arc::new(iso.unlock());
        let seal_id = fixture_seal_id(0xD4);
        stage(&vault, seal_id, SealState::Anchored);
        let mock = MockBackend::new();
        paid_by_the_pipeline(&vault, &mock, &seal_id);
        assert_eq!(
            strand_once(&vault, &mock, &seal_id, true),
            SealState::Finalizing
        );

        let plan = plan_of(&vault);
        let next = next_ask(&vault, &mock, &seal_id);
        assert_eq!(
            (next.blob_count, priced(&next), next.proofs_expired),
            (2, 2, false),
            "control: the next resume buys what the re-payment did not reach"
        );
        assert_promises_no_free_finish(&plan, &next);
        assert_eq!(
            &plan[1..],
            &[
                "    staged:    a payment is recorded; the upload was interrupted".to_owned(),
                "    remaining: pay the rest, if any, then resume the upload".to_owned(),
                clock_line(),
            ][..],
            "{plan:#?}"
        );
        assert_receipt_clause(&refusal(&vault, &seal_id), &seal_id);
    }

    /// **G-U115-1.** A first payment that stranded after one sub-batch (exit
    /// 28; the tag stays `Anchored` over the sink's capture) is partly paid:
    /// rule 2 refuses it by what its receipt records and claims no more —
    /// never "has already been paid for", nor "forfeit … permanently" — and
    /// its way forward is what the re-run does: it asks first, and only for
    /// the two blobs the receipt does not cover.
    ///
    /// Red at ab7226f: "work … has already been paid for — a payment receipt
    /// is journaled for it. Abandoning it would forfeit that payment
    /// permanently …".
    #[test]
    fn u115_abandon_refuses_a_partly_paid_work_by_what_its_receipt_records() {
        let iso = IsolatedVault::create("d210-u115-1");
        let vault = Arc::new(iso.unlock());
        let seal_id = fixture_seal_id(0xD5);
        stage(&vault, seal_id, SealState::Anchored);
        let mock = MockBackend::new();
        assert_eq!(
            strand_once(&vault, &mock, &seal_id, false),
            SealState::Anchored
        );

        let text = refusal(&vault, &seal_id);
        let opening = format!(
            "usage error: a payment is recorded for work {} — its payment receipt maps quotes to \
             transactions. ",
            hex(&seal_id)
        );
        assert!(text.starts_with(&opening), "{text}");
        for overstated in [
            "has already been paid for",
            "forfeit that payment permanently",
            "no quote the receipt already maps is paid again",
        ] {
            assert!(
                !text.contains(overstated),
                "rule 2 says more than the receipt records ({overstated:?}):\n{text}"
            );
        }
        let clauses = [
            "Abandoning it would give that payment up for good, and antseal will not do that on \
             request.",
            "Finish it instead by re-running `antseal seal a.txt",
            "which asks before any payment and pays only for what the receipt does not cover",
            "but its payment proofs stay usable for uploading only about a day, and after that \
             finishing it costs a second payment",
        ];
        for clause in clauses {
            assert!(text.contains(clause), "missing {clause:?}:\n{text}");
        }
        let next = next_ask(&vault, &mock, &seal_id);
        assert_eq!(
            (next.blob_count, priced(&next)),
            (2, 2),
            "control: the re-run asks, and only for what the receipt does not cover"
        );
    }

    /// **G-U115-2.** The same stranded work: the plan's last line and
    /// `list`'s note are ONE sentence, `ResumeClock::TimeBoxed.note()` — so
    /// the two surfaces cannot drift — and the stranded (`Anchored`) arm
    /// carries it.
    ///
    /// Red at ab7226f: the stranded plan had three lines and no clock, while
    /// `list` printed "RESUME PROMPTLY …" for the same work.
    #[test]
    fn u115_the_plans_proof_clock_is_the_sentence_list_prints() {
        let iso = IsolatedVault::create("d210-u115-2");
        let vault = Arc::new(iso.unlock());
        let seal_id = fixture_seal_id(0xD6);
        stage(&vault, seal_id, SealState::Anchored);
        let mock = MockBackend::new();
        assert_eq!(
            strand_once(&vault, &mock, &seal_id, false),
            SealState::Anchored
        );

        let plan = plan_of(&vault);
        let note = list_note(&vault);
        let clock = ResumeClock::TimeBoxed.note();
        assert_eq!(
            (
                plan.last().and_then(|line| line.strip_prefix("    ")),
                note.strip_prefix("  ")
            ),
            (Some(clock), Some(clock)),
            "the plan's proof clock and list's note for the same work drifted apart:\nplan: \
             {plan:#?}\nlist: {note}"
        );
        assert_eq!(plan.len(), 4, "{plan:#?}");
        assert_eq!(
            &plan[1..3],
            &[
                "    staged:    staged and past its anchor step; a payment is recorded".to_owned(),
                "    remaining: pay the rest, if any, then upload".to_owned(),
            ][..]
        );
    }

    /// **G-U115-3.** Rule 2's STATE clause — a post-pay tag, no payment
    /// recorded — claims no payment. Over legacy case 1 (a receipt that maps
    /// nothing) its way forward is the re-run, which quotes and asks first.
    /// Over a post-pay tag with no receipt at all — no writer leaves one, the
    /// payment step journals the receipt before it moves the tag — the
    /// resume stops at the missing receipt (measured here), so the refusal
    /// offers no re-run it cannot keep, and the plan says the same.
    ///
    /// Red at ab7226f: "work … has already been paid for — a payment receipt
    /// is journaled for it" over both, where no payment is recorded.
    #[test]
    fn u115_a_post_pay_tag_with_no_payment_recorded_is_refused_without_claiming_one() {
        let maps_nothing = IsolatedVault::create("d210-u115-3-revert");
        let no_receipt = IsolatedVault::create("d210-u115-3-none");
        let shapes = [
            (maps_nothing.unlock(), fixture_seal_id(0xD7), true),
            (no_receipt.unlock(), fixture_seal_id(0xD8), false),
        ];
        for (vault, seal_id, with_receipt) in &shapes {
            stage(vault, *seal_id, SealState::Paid);
            if *with_receipt {
                journal_over(vault, |journal| {
                    journal
                        .put_receipt(seal_id, &revert_only_receipt())
                        .expect("the pre-S50 capture");
                });
            }
            let text = refusal(vault, seal_id);
            let opening = format!(
                "usage error: work {} is past its payment step (the journal records `paid`), but \
                 no payment is recorded for it, and antseal does not abandon a work in that state \
                 on request. ",
                hex(seal_id)
            );
            assert!(text.starts_with(&opening), "{text}");
            for claim in [
                "a payment is recorded",
                "been paid for",
                "forfeit",
                "give that payment up",
            ] {
                assert!(
                    !text.contains(claim),
                    "the state clause claims a payment the vault does not record ({claim:?}):\n{text}"
                );
            }
            let forward = if *with_receipt {
                "Finish it instead by re-running `antseal seal a.txt --network devnet`, which quotes \
                 whatever is not yet stored and asks before any payment"
            } else {
                "Its journal holds no payment receipt, so re-running `antseal seal a.txt --network \
                 devnet` cannot finish it either: a resume past the payment step needs that receipt"
            };
            assert!(text.ends_with(forward), "{text}");
        }

        // The fact the no-receipt words rest on: the resume stops at its
        // receipt read, before any backend call — and the plan says so.
        let (vault, seal_id, _) = &shapes[1];
        let mock = MockBackend::new();
        let consent = ScriptedConsent::always_yes();
        let gate = RecordingGate::new();
        let outcome = journal_over(vault, |journal| {
            let pipeline = Pipeline::new(&mock, &gate, journal, &consent, &NoBarriers);
            block_on(pipeline.resume(seal_id))
        });
        match outcome {
            Err(SealError::Journal(JournalError::Corrupt { .. })) => {}
            other => panic!("a post-pay work with no receipt cannot be resumed: {other:?}"),
        }
        assert_eq!(mock.call_log().len(), 0, "no backend call");
        assert_eq!(consent.calls(), 0, "nothing asked");
        assert_eq!(
            &plan_of(vault)[1..],
            &[
                "    staged:    past its payment step, but no payment receipt is journaled"
                    .to_owned(),
                "    remaining: none — resuming fails without that receipt".to_owned(),
            ][..]
        );
    }
}

// ─────────────────────────────────────────────────────────────────────
// D209 (S53, S55): an expired-proof re-payment keeps what the work paid
// ─────────────────────────────────────────────────────────────────────

/// **D209 (S53, S55)**: an expired-proof re-payment carries forward what the
/// work has paid — every total, the records this run paid for, and every
/// mapping no record uses — and re-buys only the rest. Each row runs in a
/// vault of its own, because `list` reads every work in the vault it is
/// pointed at, and every paid state is one a production writer leaves: the
/// pipeline itself, or the receipt the durable sink journals for a first
/// sub-batch (`put_receipt` of what `MockBackend::pay` returned).
mod d209 {
    use super::*;

    use std::cell::{Cell, RefCell};
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::Arc;

    use antseal_cli::listing::WorkListing;
    use antseal_cli::pipeline::{VaultJournal, VaultReceiptSink};
    use antseal_cli::vault::store::WorkStore;
    use antseal_net::{
        Address, Blob, BlobCost, BlobQuote, CostQuote, PaymentReceipt, PaymentTxState, TxHash,
        TxStatus,
    };

    use crate::common::{IsolatedVault, rng};

    /// `stage_work`, into a vault of the row's own.
    fn stage_in(iso: &IsolatedVault, seal_id: SealId, state: SealState) {
        iso.with_journal(|journal| {
            journal.begin(&identity(seal_id, false)).expect("begin");
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
            for step in [SealState::Anchored, SealState::Paid] {
                if journal.state(&seal_id).expect("state") == state {
                    break;
                }
                journal.set_state(&seal_id, step).expect("advance");
            }
            assert_eq!(journal.state(&seal_id).expect("state"), state);
        });
    }

    fn net_blobs() -> Vec<Blob> {
        staged_blobs()
            .into_iter()
            .map(|b| Blob::new(b.ciphertext).expect("under the cap"))
            .collect()
    }

    fn address_of(blob: &Blob) -> Address {
        Address::from(compute_storage_address(blob.as_bytes()).expect("under the cap"))
    }

    /// The addresses a quote prices (an `AlreadyStored` line is not bought).
    fn priced(quote: &CostQuote) -> BTreeSet<Address> {
        quote
            .blobs
            .iter()
            .filter(|line| matches!(line.cost, BlobCost::Priced { .. }))
            .map(|line| line.address)
            .collect()
    }

    /// The first `count` staged blobs bought through the mock in one
    /// payment — the receipt the durable sink journals for a first
    /// sub-batch that landed.
    fn bought(mock: &MockBackend, count: usize) -> PaymentReceipt {
        block_on(async {
            let quote = mock
                .quote_batch(&net_blobs()[..count])
                .await
                .expect("quote");
            mock.pay(&quote).await.expect("pay")
        })
    }

    fn txs_of(receipt: &PaymentReceipt) -> BTreeSet<TxHash> {
        receipt.txs.iter().map(|tx| tx.tx_hash).collect()
    }

    /// A journal over the row's vault, with the durable sink attached — the
    /// pairing `SealSession` builds for `seal`.
    fn sink_journal<T>(
        vault: &Arc<antseal_cli::vault::session::UnlockedVault>,
        sink: &Arc<VaultReceiptSink>,
        body: impl FnOnce(&VaultJournal<'_, rand_chacha::ChaCha20Rng>) -> T,
    ) -> T {
        let mut rng = rng();
        let journal =
            VaultJournal::new(WorkStore::new(vault), &mut rng).with_receipt_sink(Arc::clone(sink));
        body(&journal)
    }

    /// The work's cost as `complete()` recorded it, and its receipt.
    fn recorded(iso: &IsolatedVault, seal_id: &SealId) -> (Option<u128>, PaymentReceipt) {
        iso.with_journal(|journal| {
            assert_eq!(journal.state(seal_id).expect("state"), SealState::Complete);
            (
                journal
                    .recorded_identity(seal_id)
                    .expect("identity")
                    .cost_atto,
                journal.receipt(seal_id).expect("read").expect("present"),
            )
        })
    }

    /// `list`'s cost lines for the vault's one work.
    fn list_cost_lines(iso: &IsolatedVault) -> Vec<String> {
        let vault = iso.unlock();
        WorkListing::gather(&WorkStore::new(&vault))
            .expect("list")
            .render()
            .into_iter()
            .map(|line| line.trim().to_owned())
            .filter(|line| line.starts_with("cost:"))
            .collect()
    }

    /// A backend whose next `finalize_batch`, once armed, stores the first
    /// `store_first` blobs under the receipt it is handed and then reports
    /// expired proofs — a work partly stored before its proofs aged out, as
    /// the adapter's blob-by-blob store returns at the first decisive
    /// refusal — and which behaves normally otherwise. It tallies every atto
    /// its `pay` moved (the mock's receipt cost is the quote total it paid).
    struct ExpiringAfterStoring<'m> {
        inner: &'m MockBackend,
        store_first: usize,
        armed: Cell<bool>,
        spent_atto: Cell<u128>,
    }

    impl<'m> ExpiringAfterStoring<'m> {
        fn new(inner: &'m MockBackend, store_first: usize) -> Self {
            Self {
                inner,
                store_first,
                armed: Cell::new(false),
                spent_atto: Cell::new(0),
            }
        }
    }

    impl StorageBackend for ExpiringAfterStoring<'_> {
        async fn quote_batch(&self, blobs: &[Blob]) -> Result<CostQuote, StorageError> {
            self.inner.quote_batch(blobs).await
        }

        async fn pay(&self, quote: &CostQuote) -> Result<PaymentReceipt, StorageError> {
            let receipt = self.inner.pay(quote).await?;
            self.spent_atto
                .set(self.spent_atto.get() + receipt.storage_cost_atto);
            Ok(receipt)
        }

        async fn finalize_batch(
            &self,
            receipt: &PaymentReceipt,
            blobs: &[Blob],
        ) -> Result<Vec<Address>, StorageError> {
            if self.armed.replace(false) {
                if self.store_first > 0 {
                    self.inner
                        .finalize_batch(receipt, &blobs[..self.store_first])
                        .await?;
                }
                return Err(StorageError::ProofsExpired);
            }
            self.inner.finalize_batch(receipt, blobs).await
        }

        async fn get_data(&self, address: Address) -> Result<Vec<u8>, StorageError> {
            self.inner.get_data(address).await
        }

        async fn balances(&self) -> Result<antseal_net::BalanceReport, StorageError> {
            self.inner.balances().await
        }

        async fn payment_tx_state(&self, tx_hash: &TxHash) -> PaymentTxState {
            self.inner.payment_tx_state(tx_hash).await
        }
    }

    /// D179's verdict, modelled per PAYMENT, which `ExpiringOnce` cannot
    /// express: `finalize_batch` refuses a blob as expired when its record's
    /// paying transaction is in `expired`, and stores every other blob, one
    /// at a time through the mock. `pay` counts the priced lines it receives
    /// per blob ADDRESS — what `double_paid()` cannot see, since a re-quote
    /// mints fresh quote hashes — and, when `strand` names a payment by its
    /// index, lands only that payment's first lines, captures them through
    /// the real sink as the adapter's hook does, and strands.
    struct PerTxExpiry<'m> {
        inner: &'m MockBackend,
        expired: BTreeSet<TxHash>,
        paid: RefCell<BTreeMap<Address, usize>>,
        pays: Cell<usize>,
        /// `(payment index, blob lines that land, the sink)`.
        strand: Option<(usize, usize, Arc<VaultReceiptSink>)>,
    }

    impl<'m> PerTxExpiry<'m> {
        fn new(inner: &'m MockBackend, expired: BTreeSet<TxHash>) -> Self {
            Self {
                inner,
                expired,
                paid: RefCell::new(BTreeMap::new()),
                pays: Cell::new(0),
                strand: None,
            }
        }

        fn max_pays_per_address(&self) -> usize {
            self.paid.borrow().values().copied().max().unwrap_or(0)
        }
    }

    impl StorageBackend for PerTxExpiry<'_> {
        async fn quote_batch(&self, blobs: &[Blob]) -> Result<CostQuote, StorageError> {
            self.inner.quote_batch(blobs).await
        }

        async fn pay(&self, quote: &CostQuote) -> Result<PaymentReceipt, StorageError> {
            let index = self.pays.get();
            self.pays.set(index + 1);
            let stranding = self.strand.as_ref().filter(|(at, ..)| *at == index);
            let lines: Vec<BlobQuote> = match stranding {
                Some((_, landed, _)) => quote.blobs.iter().take(*landed).cloned().collect(),
                None => quote.blobs.clone(),
            };
            for line in &lines {
                if matches!(line.cost, BlobCost::Priced { .. }) {
                    *self.paid.borrow_mut().entry(line.address).or_insert(0) += 1;
                }
            }
            let receipt = match stranding {
                Some(_) => {
                    let total = lines
                        .iter()
                        .map(|line| match &line.cost {
                            BlobCost::AlreadyStored => 0,
                            BlobCost::Priced { payments, .. } => {
                                payments.iter().map(|p| p.amount_atto).sum()
                            }
                        })
                        .sum();
                    self.inner
                        .pay(&CostQuote {
                            blobs: lines,
                            total_ant_atto: total,
                            gas_estimate_wei: 0,
                        })
                        .await?
                }
                None => self.inner.pay(quote).await?,
            };
            if let Some((_, _, sink)) = &self.strand {
                // The hook, doing its one job inside `pay`.
                sink.capture(&receipt);
            }
            if stranding.is_some() {
                return Err(StorageError::StrandedPayment {
                    landed_tx_count: receipt.txs.len(),
                    reason: "test: the re-payment stranded after its first sub-batch".into(),
                });
            }
            Ok(receipt)
        }

        async fn finalize_batch(
            &self,
            receipt: &PaymentReceipt,
            blobs: &[Blob],
        ) -> Result<Vec<Address>, StorageError> {
            let mut addresses = Vec::with_capacity(blobs.len());
            for blob in blobs {
                let address = address_of(blob);
                addresses.push(address);
                if self.inner.contains(address) {
                    continue;
                }
                if let Some(record) = receipt.blobs.iter().find(|r| r.address == address) {
                    let stale = record
                        .payments
                        .iter()
                        .filter(|line| line.amount_atto > 0)
                        .any(|line| {
                            receipt
                                .tx_map
                                .get(&line.quote_hash)
                                .is_some_and(|tx| self.expired.contains(tx))
                        });
                    if stale {
                        return Err(StorageError::ProofsExpired);
                    }
                }
                self.inner
                    .finalize_batch(receipt, std::slice::from_ref(blob))
                    .await?;
            }
            Ok(addresses)
        }

        async fn get_data(&self, address: Address) -> Result<Vec<u8>, StorageError> {
            self.inner.get_data(address).await
        }

        async fn balances(&self) -> Result<antseal_net::BalanceReport, StorageError> {
            self.inner.balances().await
        }

        async fn payment_tx_state(&self, tx_hash: &TxHash) -> PaymentTxState {
            self.inner.payment_tx_state(tx_hash).await
        }
    }

    /// **G-S53a, S53's Accept, through the expired-proof seam.** A paid work
    /// stores one blob, then its proofs expire, and the resume re-pays what is
    /// not stored. The vault records BOTH payments — in the receipt, in the
    /// meta cost `complete()` writes and in `list`'s cost line — while the
    /// receipt holds only the replacement's records (D37) and the run report
    /// only the replacement's spend.
    ///
    /// The `Paid` state is the pipeline's own: the first payment is journaled
    /// by `consent_anchor_pay`, and that run is killed before finalize.
    ///
    /// Red at ab7226f: "cost Some(3678), expected Some(9195): the expired
    /// payment was forgotten (S53)".
    #[test]
    fn s53_an_expired_re_payment_records_both_payments_where_list_reads_them() {
        let iso = IsolatedVault::create("d209-s53a");
        let seal_id = fixture_seal_id(0x53);
        stage_in(&iso, seal_id, SealState::Anchored);
        let mock = MockBackend::new();
        let backend = ExpiringAfterStoring::new(&mock, 1);
        let gate = RecordingGate::new();
        let consent = ScriptedConsent::always_yes();

        let kill = KillAt::new(Barrier::PostReceiptJournalPreFinalize);
        iso.with_journal(|journal| {
            let pipeline = Pipeline::new(&backend, &gate, journal, &consent, &kill);
            match block_on(pipeline.resume(&seal_id)) {
                Err(SealError::KilledAtBarrier(Barrier::PostReceiptJournalPreFinalize)) => {}
                other => panic!("expected the kill after the receipt journal, got {other:?}"),
            }
        });
        let expired = iso.with_journal(|journal| {
            assert_eq!(journal.state(&seal_id).expect("state"), SealState::Paid);
            journal.receipt(&seal_id).expect("read").expect("journaled")
        });
        let first = backend.spent_atto.get();
        assert_eq!(expired.storage_cost_atto, first);
        assert_eq!(
            expired.blobs.len(),
            3,
            "the first payment bought every blob"
        );

        backend.armed.set(true);
        let outcome = iso.with_journal(|journal| {
            let pipeline = Pipeline::new(&backend, &gate, journal, &consent, &NoBarriers);
            block_on(pipeline.resume(&seal_id)).expect("the re-payment completes the seal")
        });
        let second = backend.spent_atto.get() - first;
        assert_eq!(
            consent.calls(),
            2,
            "the first payment's consent, then the re-payment's"
        );
        let seen = consent.last().expect("the re-payment asked");
        assert!(
            seen.proofs_expired,
            "the re-consent was the proofs-expired one"
        );
        assert_eq!(
            (seen.blob_count, priced(&seen.quote).len()),
            (3, 2),
            "blob 0 was stored before the expiry, so the re-quote prices the other two"
        );
        assert!(
            0 < second && second < first,
            "anti-vacuity: C2 ({second}) is below C1 ({first}), so no total can pass for either"
        );
        let total = first + second;
        assert_eq!(
            outcome.paid_atto, second,
            "outcome.paid_atto {}: the run report claims money an earlier run paid (expected {second})",
            outcome.paid_atto
        );
        assert!(outcome.paid_here);

        let (cost, receipt) = recorded(&iso, &seal_id);
        assert_eq!(
            cost,
            Some(total),
            "cost {cost:?}, expected Some({total}): the expired payment was forgotten (S53)"
        );
        assert_eq!(receipt.storage_cost_atto, total, "the receipt's total");
        assert!(
            receipt.blobs.len() == 2
                && expired
                    .tx_map
                    .keys()
                    .all(|q| !receipt.tx_map.contains_key(q))
                && expired
                    .txs
                    .iter()
                    .all(|old| receipt.txs.iter().all(|tx| tx.tx_hash != old.tx_hash)),
            "a replaced record survived into the receipt (D37: never merge expired records): \
             {} records, {} mappings, {} txs",
            receipt.blobs.len(),
            receipt.tx_map.len(),
            receipt.txs.len()
        );
        assert!(receipt.covers_all_paid_quotes(), "quote→tx map complete");
        assert_eq!(
            list_cost_lines(&iso),
            vec![format!("cost: {total} atto-ANT")],
            "list must show the work's total"
        );
    }

    /// **G-S53b: a remainder, then an expiry, in one run.** A stranded first
    /// sub-batch (blob 0, journaled as the sink captures it) is resumed: the
    /// run pays the remainder, its finalize meets the partial's expired
    /// proof, and the arm re-pays. The vault records all three payments; the
    /// run report the two this run made.
    ///
    /// Red at ab7226f: "cost Some(5517), expected Some(11034): the expired
    /// payment was forgotten (S53)".
    #[test]
    fn s53_a_remainder_then_an_expiry_in_one_run_records_every_payment() {
        let iso = IsolatedVault::create("d209-s53b");
        let seal_id = fixture_seal_id(0x5B);
        stage_in(&iso, seal_id, SealState::Anchored);
        let mock = MockBackend::new();
        let partial = bought(&mock, 1);
        assert!(
            partial.storage_cost_atto > 0,
            "anti-vacuity: the partial cost something"
        );
        iso.with_journal(|journal| {
            journal
                .put_receipt(&seal_id, &partial)
                .expect("the sink's capture of the first sub-batch")
        });

        let backend = ExpiringAfterStoring::new(&mock, 0);
        backend.armed.set(true);
        let gate = RecordingGate::new();
        let consent = ScriptedConsent::always_yes();
        let outcome = iso.with_journal(|journal| {
            let pipeline = Pipeline::new(&backend, &gate, journal, &consent, &NoBarriers);
            block_on(pipeline.resume(&seal_id)).expect("the run completes the seal")
        });

        let seen = consent.seen.borrow();
        assert_eq!(
            seen.len(),
            2,
            "the remainder's consent, then the re-payment's"
        );
        assert!(!seen[0].proofs_expired && seen[1].proofs_expired);
        let (remainder, replacement) = (seen[0].quote.total_ant_atto, seen[1].quote.total_ant_atto);
        assert_eq!(
            backend.spent_atto.get(),
            remainder + replacement,
            "the run paid exactly the two quotes it was granted"
        );
        assert_eq!(
            outcome.paid_atto,
            remainder + replacement,
            "outcome.paid_atto {}: the run report is this run's spend",
            outcome.paid_atto
        );
        let total = partial.storage_cost_atto + remainder + replacement;
        let (cost, receipt) = recorded(&iso, &seal_id);
        assert_eq!(
            cost,
            Some(total),
            "cost {cost:?}, expected Some({total}): the expired payment was forgotten (S53)"
        );
        assert_eq!(receipt.storage_cost_atto, total, "the receipt's total");
        assert!(
            partial
                .tx_map
                .keys()
                .all(|q| !receipt.tx_map.contains_key(q)),
            "a replaced record survived into the receipt (D37: never merge expired records)"
        );
        assert_eq!(
            list_cost_lines(&iso),
            vec![format!("cost: {total} atto-ANT")],
            "list must show the work's total"
        );
    }

    /// **S55's Accept (D209 R7, row A's T1 shape): a remainder this run paid
    /// for is never bought again when an older payment expires in the same
    /// run.** A stranded first sub-batch (unit 0, paid by transaction P) is
    /// resumed; the run pays the remainder (unit 1 and the manifest), and
    /// finalize meets unit 0's proof, refused because P is expired. The arm
    /// keeps this run's records and re-quotes only unit 0: one consent over
    /// exactly the blobs outside them (`keep ∩ candidates = ∅`), each
    /// address paid at most once in the run — counted per ADDRESS, which
    /// `double_paid()` cannot see — and the recorded cost is every payment
    /// the work made, with this run's transactions kept in the receipt.
    ///
    /// Red at ab7226f: the re-consent prices all three blobs, unit 1 and the
    /// manifest are paid twice in one run, and the vault records 5517 of the
    /// 11 034 spent (P2 §6.2: max pays per address 2).
    #[test]
    fn s55_a_remainder_paid_in_this_run_is_never_bought_again_when_an_older_payment_expires() {
        let iso = IsolatedVault::create("d209-s55-t1");
        let seal_id = fixture_seal_id(0x55);
        stage_in(&iso, seal_id, SealState::Anchored);
        let mock = MockBackend::new();
        let partial = bought(&mock, 1);
        iso.with_journal(|journal| {
            journal
                .put_receipt(&seal_id, &partial)
                .expect("the sink's capture of the first sub-batch")
        });
        let backend = PerTxExpiry::new(&mock, txs_of(&partial));
        let gate = RecordingGate::new();
        let consent = ScriptedConsent::always_yes();
        let outcome = iso.with_journal(|journal| {
            let pipeline = Pipeline::new(&backend, &gate, journal, &consent, &NoBarriers);
            block_on(pipeline.resume(&seal_id)).expect("the run completes the seal")
        });

        let blobs = net_blobs();
        let seen = consent.seen.borrow();
        assert_eq!(
            seen.len(),
            2,
            "the remainder's consent, then the re-payment's"
        );
        assert!(!seen[0].proofs_expired && seen[1].proofs_expired);
        let (this_run, replaced) = (priced(&seen[0].quote), priced(&seen[1].quote));
        assert_eq!(
            this_run,
            [address_of(&blobs[1]), address_of(&blobs[2])]
                .into_iter()
                .collect(),
            "the remainder buys unit 1 and the manifest"
        );
        assert!(
            this_run.is_disjoint(&replaced),
            "keep ∩ candidates must be empty: the re-quote priced {} blob(s) this run had just \
             paid for",
            this_run.intersection(&replaced).count()
        );
        assert_eq!(
            replaced,
            std::iter::once(address_of(&blobs[0])).collect(),
            "only the blob whose payment expired is bought again"
        );
        let max = backend.max_pays_per_address();
        assert_eq!(
            max, 1,
            "max pays of one address in this run = {max}: a blob paid for minutes ago was \
             bought again (S55)"
        );
        assert_eq!(
            backend.paid.borrow().len(),
            3,
            "every blob was paid in this run"
        );

        let spent_here = seen[0].quote.total_ant_atto + seen[1].quote.total_ant_atto;
        assert_eq!(outcome.paid_atto, spent_here, "the run report");
        let total = partial.storage_cost_atto + spent_here;
        let (cost, receipt) = recorded(&iso, &seal_id);
        assert_eq!(
            cost,
            Some(total),
            "cost {cost:?}, expected Some({total}): not what the work spent"
        );
        assert_eq!(receipt.blobs.len(), 3, "a record per blob");
        assert!(
            receipt.txs.iter().all(|tx| !partial.txs.contains(tx)),
            "the expired transaction paid only the replaced record, so it goes"
        );
        assert_eq!(
            receipt.txs.len(),
            2,
            "this run's two transactions: the remainder's and the replacement's"
        );
        assert!(receipt.covers_all_paid_quotes());
    }

    /// **S55 (D209 R6): a mapping no record uses survives the expired arm.**
    /// A first payment of two sub-batches whose second landing no run saw is
    /// journaled the way builds before S54 journaled it: unit 1's quote
    /// mapped to the unobserved transaction U, with no record (D208 R10's
    /// legacy shape; the mock really mined U). The resume pays the remainder,
    /// unit 0's proof is refused because its transaction expired, and the arm
    /// replaces that record — but U's mapping and transaction are carried,
    /// because only the chain can say what U paid for.
    ///
    /// Red with the records-free carry (`spent_only`) and at ab7226f (`prior:
    /// None`): both drop U's mapping and transaction (P2 §6.7, T3).
    #[test]
    fn s55_a_mapping_no_record_uses_survives_the_expired_arm() {
        let iso = IsolatedVault::create("d209-s55-t3");
        let seal_id = fixture_seal_id(0x56);
        stage_in(&iso, seal_id, SealState::Anchored);
        let mock = MockBackend::new().with_max_transfers_per_tx(1);
        mock.arm_fault(Fault::Unobserved {
            sub_batch: 1,
            chain: TxStatus::Confirmed,
        });
        let mut first = bought(&mock, 2);
        assert_eq!(mock.armed_faults(), 0, "the unobserved fault fired");
        assert_eq!(
            first.txs.len(),
            2,
            "unit 0 landed, unit 1's landing unobserved"
        );
        assert_eq!(first.txs[1].status, TxStatus::Submitted);
        let unobserved = first.txs[1].tx_hash;
        // The legacy capture: no record for the unobserved sub-batch, and the
        // cost of the records it holds.
        let unit1 = address_of(&net_blobs()[1]);
        first.blobs.retain(|record| record.address != unit1);
        first.storage_cost_atto = first
            .blobs
            .iter()
            .flat_map(|record| record.payments.iter())
            .map(|line| line.amount_atto)
            .sum();
        let orphan: Vec<_> = first
            .tx_map
            .iter()
            .filter(|(_, tx)| **tx == unobserved)
            .map(|(quote, _)| *quote)
            .collect();
        assert_eq!(orphan.len(), 1, "anti-vacuity: one record-less mapping");
        iso.with_journal(|journal| {
            journal
                .put_receipt(&seal_id, &first)
                .expect("the sink's capture")
        });

        let expired: BTreeSet<TxHash> = std::iter::once(first.txs[0].tx_hash).collect();
        let backend = PerTxExpiry::new(&mock, expired);
        let gate = RecordingGate::new();
        let consent = ScriptedConsent::always_yes();
        iso.with_journal(|journal| {
            let pipeline = Pipeline::new(&backend, &gate, journal, &consent, &NoBarriers);
            block_on(pipeline.resume(&seal_id)).expect("the run completes the seal")
        });
        assert_eq!(consent.calls(), 2, "the remainder, then the re-payment");
        assert!(consent.last().expect("asked").proofs_expired);
        assert_eq!(
            backend.max_pays_per_address(),
            1,
            "no blob bought twice in the run"
        );

        let (_, receipt) = recorded(&iso, &seal_id);
        assert_eq!(
            (
                receipt.tx_map.get(&orphan[0]) == Some(&unobserved),
                receipt.txs.iter().any(|tx| tx.tx_hash == unobserved),
            ),
            (true, true),
            "the record-less mapping and its transaction must survive the expired arm \
             (D209 R6): only the chain can say what U paid for"
        );
        assert!(
            receipt
                .txs
                .iter()
                .all(|tx| tx.tx_hash != first.txs[0].tx_hash),
            "the expired transaction paid only the replaced record, so it goes"
        );
    }

    /// **S55 with a strand (D209 R6): every capture of the re-payment is the
    /// carry plus the receipt-so-far.** The first payment (units 0 and 1, one
    /// transaction each) has expired; the resume pays the remainder (the
    /// manifest), finalize meets unit 0's refused proof, and the re-payment
    /// of units 0 and 1 strands after its first sub-batch. The durable
    /// capture keeps the manifest's record — this run's, carried — beside
    /// the landed sub-batch, under the work's cumulative cost; the next run
    /// buys unit 1 alone. Armed with no records, the capture would drop the
    /// manifest's record, and the next run would buy the manifest a second
    /// time.
    #[test]
    fn s55_a_stranded_re_payment_keeps_this_runs_records_on_disk() {
        let iso = IsolatedVault::create("d209-s55-strand");
        let vault = Arc::new(iso.unlock());
        let seal_id = fixture_seal_id(0x57);
        stage_in(&iso, seal_id, SealState::Anchored);
        let mock = MockBackend::new().with_max_transfers_per_tx(1);
        let first = bought(&mock, 2);
        assert_eq!(first.txs.len(), 2, "one transaction per blob");
        iso.with_journal(|journal| {
            journal
                .put_receipt(&seal_id, &first)
                .expect("the sink's capture")
        });

        let sink = VaultReceiptSink::new(Arc::clone(&vault));
        let mut backend = PerTxExpiry::new(&mock, txs_of(&first));
        // Payment 0 is the remainder; payment 1, the re-payment, lands one
        // blob and strands.
        backend.strand = Some((1, 1, Arc::clone(&sink)));
        let gate = RecordingGate::new();
        let consent = ScriptedConsent::always_yes();
        let err = sink_journal(&vault, &sink, |journal| {
            let pipeline = Pipeline::new(&backend, &gate, journal, &consent, &NoBarriers);
            block_on(pipeline.resume(&seal_id)).expect_err("the re-payment strands")
        });
        assert!(
            matches!(
                err,
                SealError::Storage(StorageError::StrandedPayment {
                    landed_tx_count: 1,
                    ..
                })
            ),
            "{err:?}"
        );
        assert_eq!(sink.fault(), None, "every capture was durable");
        let manifest = address_of(&net_blobs()[2]);
        let seen = consent.seen.borrow().clone();
        assert_eq!(seen.len(), 2, "the remainder, then the re-payment");
        assert!(
            !priced(&seen[1].quote).contains(&manifest),
            "the re-payment must not price the manifest this run just bought"
        );
        let on_disk =
            iso.with_journal(|journal| journal.receipt(&seal_id).expect("read").expect("present"));
        let addresses: BTreeSet<Address> = on_disk.blobs.iter().map(|r| r.address).collect();
        assert!(
            addresses.contains(&manifest),
            "the strand's capture dropped the record this run had just paid for: {} record(s)",
            addresses.len()
        );
        assert_eq!(
            addresses.len(),
            2,
            "the manifest's and the landed sub-batch's"
        );
        let spent_before_strand: u128 = first.storage_cost_atto + seen[0].quote.total_ant_atto;
        assert!(
            on_disk.storage_cost_atto > spent_before_strand,
            "the capture carries every total plus what landed: {} vs {spent_before_strand}",
            on_disk.storage_cost_atto
        );

        // The next run buys what is left — unit 1 — and nothing else.
        let healthy = PerTxExpiry::new(&mock, BTreeSet::new());
        sink_journal(&vault, &sink, |journal| {
            let pipeline = Pipeline::new(&healthy, &gate, journal, &consent, &NoBarriers);
            block_on(pipeline.resume(&seal_id)).expect("the next run completes the seal")
        });
        assert_eq!(
            healthy.paid.borrow().keys().copied().collect::<Vec<_>>(),
            vec![address_of(&net_blobs()[1])],
            "the next run buys unit 1 alone"
        );
        assert_eq!(
            backend.paid.borrow().get(&manifest),
            Some(&1),
            "the manifest was bought once"
        );
        let (cost, _) = recorded(&iso, &seal_id);
        let spent = first.storage_cost_atto
            + seen[0].quote.total_ant_atto
            + (on_disk.storage_cost_atto - spent_before_strand)
            + consent.last().expect("asked").quote.total_ant_atto;
        assert_eq!(cost, Some(spent), "the recorded cost is everything spent");
    }
}

// ─────────────────────────────────────────────────────────────────────
// D208 (S54): the resume asks the chain before it buys around a payment
// whose landing no run saw
// ─────────────────────────────────────────────────────────────────────

/// **D208 R9 (S54)**: a payment transaction whose landing no run observed is
/// journaled `Submitted`, its quotes mapped and — since R5 — its blobs'
/// records built over its hash. Before the resume buys anything it asks the
/// chain about it: landed and confirmed, the records stand; reverted or
/// never mined, the transaction's mappings, records and cost are pruned and
/// the blobs bought again, with its record kept as evidence; still held, or
/// not answerable, the run refuses having paid nothing (exit 23).
///
/// Money is counted per ADDRESS from the quotes the mock really paid on its
/// chain — `double_paid()` cannot see a blob bought twice under two quote
/// rounds. Every state is a production writer's: the first run strands
/// through the pipeline, its capture journaled by the real sink from inside
/// `pay`, as the adapter's hook does.
mod d208 {
    use super::*;

    use std::cell::RefCell;
    use std::collections::BTreeMap;
    use std::sync::Arc;

    use antseal_cli::error::CliError;
    use antseal_cli::pipeline::{SealOutcome, VaultJournal, VaultReceiptSink};
    use antseal_cli::vault::session::UnlockedVault;
    use antseal_cli::vault::store::WorkStore;
    use antseal_net::{
        Address, Blob, BlobCost, CostQuote, PaymentReceipt, PaymentTxState, QuoteHash, TxHash,
        TxStatus,
    };

    use crate::common::{IsolatedVault, rng};

    fn stage_in(iso: &IsolatedVault, seal_id: SealId) {
        iso.with_journal(|journal| {
            journal.begin(&identity(seal_id, false)).expect("begin");
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
            journal
                .set_state(&seal_id, SealState::Anchored)
                .expect("anchored");
        });
    }

    fn addresses() -> Vec<Address> {
        staged_blobs()
            .iter()
            .map(|blob| {
                let bytes = Blob::new(blob.ciphertext.clone()).expect("under the cap");
                Address::from(compute_storage_address(bytes.as_bytes()).expect("cap"))
            })
            .collect()
    }

    fn sink_journal<T>(
        vault: &Arc<UnlockedVault>,
        sink: &Arc<VaultReceiptSink>,
        body: impl FnOnce(&VaultJournal<'_, rand_chacha::ChaCha20Rng>) -> T,
    ) -> T {
        let mut rng = rng();
        let journal =
            VaultJournal::new(WorkStore::new(vault), &mut rng).with_receipt_sink(Arc::clone(sink));
        body(&journal)
    }

    /// The adapter as D208 R5 builds it, over the mock: `pay` returns what
    /// the mock lands; when the mock reports a sub-batch whose landing was
    /// not observed (`Fault::Unobserved`), this double does what the
    /// adapter does there — the capture is journaled through the real sink
    /// from inside `pay`, and the payment strands with the landed count. It
    /// remembers which blob every paying quote was for, so money that really
    /// moved can be counted per address, and forwards `payment_tx_state` to
    /// the mock's chain.
    struct Adapter<'m> {
        inner: &'m MockBackend,
        sink: Arc<VaultReceiptSink>,
        owner: RefCell<BTreeMap<QuoteHash, Address>>,
    }

    impl<'m> Adapter<'m> {
        fn new(inner: &'m MockBackend, sink: &Arc<VaultReceiptSink>) -> Self {
            Self {
                inner,
                sink: Arc::clone(sink),
                owner: RefCell::new(BTreeMap::new()),
            }
        }

        /// How many paying quotes the mock's chain really paid, per blob.
        fn paid_per_address(&self) -> BTreeMap<Address, usize> {
            let owner = self.owner.borrow();
            let mut paid = BTreeMap::new();
            for quote in self.inner.paid_map().keys() {
                if let Some(address) = owner.get(quote) {
                    *paid.entry(*address).or_insert(0) += 1;
                }
            }
            paid
        }
    }

    impl StorageBackend for Adapter<'_> {
        async fn quote_batch(&self, blobs: &[Blob]) -> Result<CostQuote, StorageError> {
            self.inner.quote_batch(blobs).await
        }

        async fn pay(&self, quote: &CostQuote) -> Result<PaymentReceipt, StorageError> {
            for line in &quote.blobs {
                if let BlobCost::Priced { payments, .. } = &line.cost {
                    for payment in payments.iter().filter(|p| p.amount_atto > 0) {
                        self.owner
                            .borrow_mut()
                            .insert(payment.quote_hash, line.address);
                    }
                }
            }
            let receipt = self.inner.pay(quote).await?;
            self.sink.capture(&receipt);
            if receipt
                .txs
                .iter()
                .any(|tx| tx.status == TxStatus::Submitted)
            {
                return Err(StorageError::StrandedPayment {
                    landed_tx_count: receipt
                        .txs
                        .iter()
                        .filter(|tx| tx.status == TxStatus::Confirmed)
                        .count(),
                    reason: "test: a sub-batch's landing was not observed".into(),
                });
            }
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

        async fn payment_tx_state(&self, tx_hash: &TxHash) -> PaymentTxState {
            self.inner.payment_tx_state(tx_hash).await
        }
    }

    /// One work, one mock, one sink: the first run pays with the mock's
    /// unobserved fault armed and strands; what the vault then holds.
    struct Unobserved<'m> {
        iso: IsolatedVault,
        vault: Arc<UnlockedVault>,
        sink: Arc<VaultReceiptSink>,
        seal_id: SealId,
        adapter: Adapter<'m>,
        /// The capture the first run left.
        capture: PaymentReceipt,
        /// The transaction whose landing was not observed.
        unobserved: TxHash,
    }

    impl<'m> Unobserved<'m> {
        fn strand(
            tag: &str,
            seal_id: SealId,
            mock: &'m MockBackend,
            sub_batch: usize,
            chain: TxStatus,
        ) -> Self {
            let iso = IsolatedVault::create(tag);
            let vault = Arc::new(iso.unlock());
            stage_in(&iso, seal_id);
            let sink = VaultReceiptSink::new(Arc::clone(&vault));
            let adapter = Adapter::new(mock, &sink);
            mock.arm_fault(Fault::Unobserved { sub_batch, chain });
            let gate = RecordingGate::new();
            let consent = ScriptedConsent::always_yes();
            let err = sink_journal(&vault, &sink, |journal| {
                let pipeline = Pipeline::new(&adapter, &gate, journal, &consent, &NoBarriers);
                block_on(pipeline.resume(&seal_id)).expect_err("the payment strands")
            });
            assert!(
                matches!(
                    err,
                    SealError::Storage(StorageError::StrandedPayment { landed_tx_count, .. })
                        if landed_tx_count == sub_batch
                ),
                "{err:?}"
            );
            assert_eq!(mock.armed_faults(), 0, "the unobserved fault fired");
            assert_eq!(sink.fault(), None, "the capture is durable");
            let capture = iso.with_journal(|journal| {
                journal.receipt(&seal_id).expect("read").expect("captured")
            });
            let unobserved = capture
                .txs
                .iter()
                .find(|tx| tx.status == TxStatus::Submitted)
                .expect("the unobserved transaction is journaled Submitted")
                .tx_hash;
            assert!(
                capture.tx_map.values().any(|tx| *tx == unobserved),
                "its quotes are mapped"
            );
            Self {
                iso,
                vault,
                sink,
                seal_id,
                adapter,
                capture,
                unobserved,
            }
        }

        /// The next run, over the same chain.
        fn resume(&self, consent: &ScriptedConsent) -> Result<SealOutcome, SealError> {
            let gate = RecordingGate::new();
            sink_journal(&self.vault, &self.sink, |journal| {
                let pipeline = Pipeline::new(&self.adapter, &gate, journal, consent, &NoBarriers);
                block_on(pipeline.resume(&self.seal_id))
            })
        }

        fn receipt(&self) -> PaymentReceipt {
            self.iso.with_journal(|journal| {
                journal
                    .receipt(&self.seal_id)
                    .expect("read")
                    .expect("present")
            })
        }

        fn state(&self) -> SealState {
            self.iso
                .with_journal(|journal| journal.state(&self.seal_id).expect("state"))
        }

        fn recorded_cost(&self) -> Option<u128> {
            self.iso.with_journal(|journal| {
                journal
                    .recorded_identity(&self.seal_id)
                    .expect("identity")
                    .cost_atto
            })
        }
    }

    fn evidence<'r>(
        receipt: &'r PaymentReceipt,
        tx_hash: &TxHash,
    ) -> Option<&'r antseal_net::TxRecord> {
        receipt.txs.iter().find(|tx| tx.tx_hash == *tx_hash)
    }

    /// **Landed (D208 R9).** The unobserved transaction was mined and paid:
    /// the resume reads its receipt, marks it `Confirmed` with its block, and
    /// finishes over the records the capture built — no consent asked, no
    /// blob bought a second time.
    ///
    /// Without the resolution step the work still finishes here (R5's
    /// records cover its blobs whatever runs), but its record stays
    /// `Submitted` with no block: that clause is the one a skipped
    /// resolution reddens.
    #[test]
    fn a_landing_nobody_saw_is_confirmed_by_the_chain_and_never_bought_again() {
        let mock = MockBackend::new();
        let work = Unobserved::strand(
            "d208-landed",
            fixture_seal_id(0x81),
            &mock,
            0,
            TxStatus::Confirmed,
        );
        let consent = ScriptedConsent::always_yes();
        let outcome = work.resume(&consent).expect("the resume finishes the seal");

        assert_eq!(consent.calls(), 0, "a landed payment asks for nothing");
        assert!(!outcome.paid_here, "no money moved in the resume");
        assert_eq!(work.state(), SealState::Complete);
        let paid = work.adapter.paid_per_address();
        assert_eq!(paid.len(), 3, "every blob was paid for");
        assert!(
            paid.values().all(|count| *count == 1),
            "each blob paid exactly once, per address: {paid:?}"
        );
        let receipt = work.receipt();
        let record = evidence(&receipt, &work.unobserved).expect("kept");
        assert_eq!(
            (record.status, record.block_number.is_some()),
            (TxStatus::Confirmed, true),
            "the chain's answer was not written back: a landed transaction is Confirmed with \
             its block"
        );
        assert_eq!(
            work.recorded_cost(),
            Some(work.capture.storage_cost_atto),
            "the cost is the landed payment's"
        );
    }

    /// **Absent (D208 R9, D209 R5).** The unobserved transaction never
    /// reached the chain (receipt null, by-hash null). Its mappings, the
    /// records built over it and their cost are pruned; its record is kept,
    /// unmapped, as evidence that it was sent; and the resume re-quotes and
    /// asks for exactly those blobs — through the remainder arm, never the
    /// pre-pay arm, which would have erased that record. The cost recorded
    /// is what actually moved, and no blob is paid twice.
    #[test]
    fn a_payment_the_chain_never_saw_is_pruned_kept_as_evidence_and_bought_again() {
        let mock = MockBackend::new();
        let work = Unobserved::strand(
            "d208-absent",
            fixture_seal_id(0x82),
            &mock,
            0,
            TxStatus::Submitted,
        );
        assert!(
            work.capture.storage_cost_atto > 0,
            "anti-vacuity: the capture priced its records"
        );
        assert_eq!(mock.payment_tx_count(), 0, "nothing reached the chain");
        let consent = ScriptedConsent::always_yes();
        let outcome = work.resume(&consent).expect("the resume finishes the seal");

        assert_eq!(
            consent.calls(),
            1,
            "the pruned blobs must be re-quoted and asked for ({} consent call(s))",
            consent.calls()
        );
        let asked = consent.last().expect("asked");
        assert_eq!(
            (asked.blob_count, asked.proofs_expired),
            (3, false),
            "the remainder over every pruned blob"
        );
        assert_eq!(work.state(), SealState::Complete);
        let paid = work.adapter.paid_per_address();
        assert_eq!(
            paid.keys().copied().collect::<Vec<_>>(),
            {
                let mut all = addresses();
                all.sort();
                all
            },
            "every blob paid on chain"
        );
        assert!(
            paid.values().all(|count| *count == 1),
            "each blob paid exactly once, per address: {paid:?}"
        );
        let receipt = work.receipt();
        let kept = evidence(&receipt, &work.unobserved)
            .expect("the never-mined transaction's record is kept as evidence");
        assert_eq!(kept.status, TxStatus::Submitted);
        assert!(
            receipt.tx_map.values().all(|tx| *tx != work.unobserved),
            "and it maps nothing"
        );
        assert_eq!(
            work.recorded_cost(),
            Some(asked.quote.total_ant_atto),
            "the cost recorded is what moved: only the resume's payment"
        );
        assert_eq!(outcome.paid_atto, asked.quote.total_ant_atto);
    }

    /// **Reverted (D208 R9).** The unobserved transaction was mined and
    /// reverted: it moved no ANT. As for an absent one, its mappings,
    /// records and cost are pruned and its blobs bought again — and its
    /// record is kept as `Reverted`, with its block.
    #[test]
    fn a_payment_that_reverted_is_pruned_kept_as_reverted_and_bought_again() {
        let mock = MockBackend::new();
        let work = Unobserved::strand(
            "d208-reverted",
            fixture_seal_id(0x83),
            &mock,
            0,
            TxStatus::Reverted,
        );
        let consent = ScriptedConsent::always_yes();
        work.resume(&consent).expect("the resume finishes the seal");

        assert_eq!(
            consent.calls(),
            1,
            "the pruned blobs must be re-quoted and asked for ({} consent call(s))",
            consent.calls()
        );
        let asked = consent.last().expect("asked");
        assert_eq!(asked.blob_count, 3);
        let paid = work.adapter.paid_per_address();
        assert_eq!(paid.len(), 3);
        assert!(
            paid.values().all(|count| *count == 1),
            "each blob paid exactly once, per address: {paid:?}"
        );
        let receipt = work.receipt();
        let kept = evidence(&receipt, &work.unobserved)
            .expect("the reverted transaction's record is kept as evidence");
        assert_eq!(
            (kept.status, kept.block_number.is_some()),
            (TxStatus::Reverted, true),
            "kept as Reverted, with its block"
        );
        assert!(receipt.tx_map.values().all(|tx| *tx != work.unobserved));
        assert_eq!(work.recorded_cost(), Some(asked.quote.total_ant_atto));
    }

    /// **Absent after a landed sub-batch (D208 R9, D209 R5).** The first of
    /// three one-blob sub-batches landed and was observed; the second's
    /// landing was not, and it never reached the chain; the third was never
    /// sent. Pruning removes only the second's share — the first stays
    /// mapped and recorded — so the remainder buys the second and third
    /// blobs, and the work's cost is the first payment plus the remainder.
    #[test]
    fn pruning_an_absent_second_sub_batch_keeps_the_first_and_its_cost() {
        let mock = MockBackend::new().with_max_transfers_per_tx(1);
        let work = Unobserved::strand(
            "d208-absent-2nd",
            fixture_seal_id(0x84),
            &mock,
            1,
            TxStatus::Submitted,
        );
        let blobs = addresses();
        assert_eq!(
            (work.capture.blobs.len(), work.capture.txs.len()),
            (2, 2),
            "fixture: one landed record, one unobserved"
        );
        let first_share: u128 = work.capture.blobs[0]
            .payments
            .iter()
            .map(|line| line.amount_atto)
            .sum();
        assert!(first_share > 0 && first_share < work.capture.storage_cost_atto);

        let consent = ScriptedConsent::always_yes();
        work.resume(&consent).expect("the resume finishes the seal");
        assert_eq!(
            consent.calls(),
            1,
            "the pruned blob and the one never sent must be re-quoted and asked for ({} \
             consent call(s))",
            consent.calls()
        );
        let asked = consent.last().expect("asked");
        assert_eq!(
            asked
                .quote
                .blobs
                .iter()
                .map(|line| line.address)
                .collect::<Vec<_>>(),
            vec![blobs[1], blobs[2]],
            "the remainder buys exactly the pruned blob and the one never sent"
        );
        let paid = work.adapter.paid_per_address();
        assert!(
            paid.values().all(|count| *count == 1) && paid.len() == 3,
            "each blob paid exactly once, per address: {paid:?}"
        );
        assert_eq!(
            work.recorded_cost(),
            Some(first_share + asked.quote.total_ant_atto),
            "the pruned share left the total; the landed one stayed"
        );
    }

    /// **Pending (D208 R9).** The payment RPC still holds the unobserved
    /// transaction, unmined: it may yet pay for its blobs. Buying around it
    /// could pay twice, so the run refuses — exit 23, before any consent and
    /// with nothing paid — and leaves the receipt as it was.
    #[test]
    fn a_payment_still_held_by_the_rpc_refuses_the_run_and_pays_nothing() {
        let mock = MockBackend::new();
        let work = Unobserved::strand(
            "d208-pending",
            fixture_seal_id(0x85),
            &mock,
            0,
            TxStatus::Submitted,
        );
        mock.arm_fault(Fault::PaymentTxHeld);
        let consent = ScriptedConsent::always_yes();
        let err = work
            .resume(&consent)
            .expect_err("a held payment refuses the run");
        let cli: CliError = err.into();
        assert_eq!(
            cli.exit_code(),
            23,
            "a held transaction must refuse the run as retryable: {cli}"
        );
        let message = cli.to_string();
        assert!(message.contains("not mined yet"), "{message}");
        assert!(
            message.contains("nothing was paid in this run"),
            "{message}"
        );
        assert_eq!(consent.calls(), 0, "no consent asked");
        assert_eq!(mock.payment_tx_count(), 0, "nothing paid");
        assert_eq!(work.receipt(), work.capture, "the receipt is untouched");
        assert!(work.state().is_incomplete());
    }

    /// **Unaskable (D208 R9).** The chain cannot be asked: nothing is known
    /// about the unobserved transaction, so nothing may be bought around it.
    /// The run refuses — exit 23, no consent, nothing paid — naming why.
    #[test]
    fn a_payment_the_chain_cannot_be_asked_about_refuses_the_run_and_pays_nothing() {
        let mock = MockBackend::new();
        let work = Unobserved::strand(
            "d208-unaskable",
            fixture_seal_id(0x86),
            &mock,
            0,
            TxStatus::Confirmed,
        );
        let mined = mock.payment_tx_count();
        mock.arm_fault(Fault::NetworkOn(Method::PaymentTxState));
        let consent = ScriptedConsent::always_yes();
        let err = work
            .resume(&consent)
            .expect_err("an unaskable chain refuses the run");
        let cli: CliError = err.into();
        assert_eq!(cli.exit_code(), 23, "{cli}");
        let message = cli.to_string();
        assert!(
            message.contains("could not check whether the earlier payment transaction was mined"),
            "{message}"
        );
        assert!(
            message.contains("nothing was paid in this run"),
            "{message}"
        );
        assert_eq!(consent.calls(), 0, "no consent asked");
        assert_eq!(mock.payment_tx_count(), mined, "nothing paid");
        assert_eq!(work.receipt(), work.capture, "the receipt is untouched");
    }

    /// **Recorded residue (D208 R10), asserted as residue, not as a red.** A
    /// capture written before this wave mapped an unobserved transaction's
    /// quotes but built NO records. The chain shows the transaction landed,
    /// and the resume marks it so — but with no record and no prepared
    /// chunk, its blobs cannot be finalized without buying them again, so
    /// each is paid twice. Developer vaults only (nothing is released, Q31);
    /// a fix would turn this assertion around deliberately.
    #[test]
    fn residue_a_legacy_record_less_landing_is_still_bought_again() {
        let mock = MockBackend::new();
        let iso = IsolatedVault::create("d208-legacy");
        let vault = Arc::new(iso.unlock());
        let seal_id = fixture_seal_id(0x87);
        stage_in(&iso, seal_id);
        let sink = VaultReceiptSink::new(Arc::clone(&vault));
        let adapter = Adapter::new(&mock, &sink);
        mock.arm_fault(Fault::Unobserved {
            sub_batch: 0,
            chain: TxStatus::Confirmed,
        });
        let mut legacy = block_on(async {
            let blobs: Vec<Blob> = staged_blobs()
                .into_iter()
                .map(|b| Blob::new(b.ciphertext).expect("cap"))
                .collect();
            let quote = adapter.quote_batch(&blobs).await.expect("quote");
            adapter
                .inner
                .pay(&quote)
                .await
                .expect("the unobserved shape")
        });
        // Record which blob each paying quote was for, as `pay` would have.
        for record in &legacy.blobs {
            for line in &record.payments {
                adapter
                    .owner
                    .borrow_mut()
                    .insert(line.quote_hash, record.address);
            }
        }
        legacy.blobs.clear();
        legacy.storage_cost_atto = 0;
        let unobserved = legacy.txs[0].tx_hash;
        iso.with_journal(|journal| {
            journal
                .put_receipt(&seal_id, &legacy)
                .expect("the legacy capture")
        });

        let consent = ScriptedConsent::always_yes();
        let gate = RecordingGate::new();
        sink_journal(&vault, &sink, |journal| {
            let pipeline = Pipeline::new(&adapter, &gate, journal, &consent, &NoBarriers);
            block_on(pipeline.resume(&seal_id)).expect("the resume finishes the seal")
        });
        let paid = adapter.paid_per_address();
        assert_eq!(
            paid.values().copied().collect::<Vec<_>>(),
            vec![2, 2, 2],
            "D208 R10 residue: a legacy record-less landing is bought again (if this \
             changed, the residue was fixed — update D208 R10 and this row together)"
        );
        let receipt =
            iso.with_journal(|journal| journal.receipt(&seal_id).expect("read").expect("present"));
        assert_eq!(
            evidence(&receipt, &unobserved).map(|tx| tx.status),
            Some(TxStatus::Confirmed),
            "the chain's answer is still written back"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────
// U120 (D209 R8): the consent screen's Upload line over a real remainder
// and a real partial proofs-expired re-consent
// ─────────────────────────────────────────────────────────────────────

/// **U120** (D209 R8): the counts the consent gate receives when the
/// pipeline itself asks for a remainder or a partial proofs-expired
/// re-payment, and the Upload line the production screen makes of them.
///
/// `consent_anchor_pay` reads the whole seal's blob count from the journaled
/// plan; the renderer's own tests (`seal_consent.rs`) hand it a made-up
/// request. Here every request comes from `Pipeline::resume`, over a first
/// payment the pipeline itself made and stranded (its first sub-batch
/// captured through D37's REAL durable sink, as the adapter journals one),
/// and every screen is the one `seal` prints — [`SealConsent::report_for`]
/// and `ConsentReport::render` — handed the very request the gate was asked
/// with.
///
/// Each work lives in a vault of its own, with the durable sink wired into
/// the journal as the binary wires it.
mod u120 {
    use super::*;

    use std::cell::RefCell;
    use std::sync::Arc;

    use antseal_cli::error::CliError;
    use antseal_cli::pipeline::{
        ConsentDecision, ConsentHook, ConsentRequest, SealOutcome, VaultJournal, VaultReceiptSink,
    };
    use antseal_cli::seal_consent::{ConsentPrompt, SealConsent};
    use antseal_cli::seal_plan::{PlannedFile, SealPlan as InvocationPlan};
    use antseal_cli::vault::session::UnlockedVault;
    use antseal_cli::vault::store::WorkStore;
    use antseal_core::content::FileFlags;
    use antseal_net::{
        Address, BalanceReport, Blob, BlobCost, BlobQuote, CaptureOutcome, CostQuote, NetworkId,
        PaymentReceipt, PaymentTxState, TxHash,
    };

    use crate::common::{IsolatedVault, SeenConsent, journal_over, rng};

    /// The Upload line of a quote over the whole seal — unchanged by U120.
    fn whole_seal_line(n: usize) -> String {
        format!("  Upload:      {n} blob(s) — every encrypted unit plus the encrypted manifest")
    }

    /// The Upload line of a quote over `k` of the seal's `n` blobs (D209 R8).
    fn share_line(k: usize, n: usize) -> String {
        format!("  Upload:      {k} of the seal's {n} blob(s) — the others are already paid for")
    }

    /// The invocation the screen describes: the input `identity` names.
    fn invocation() -> InvocationPlan {
        InvocationPlan {
            files: vec![PlannedFile {
                as_given: "a.txt".to_owned(),
                absolute: "/tmp/a.txt".to_owned(),
                size: 11,
                flags: FileFlags::new(),
            }],
            shaping: SealShapingFlags::default(),
            network: NetworkId::Devnet,
            dry_run: false,
            yes: true,
        }
    }

    /// The screen is rendered here, never asked: the script answers.
    struct NeverAsked;

    impl ConsentPrompt for NeverAsked {
        fn ask(&mut self) -> Result<bool, CliError> {
            panic!("the screen double renders; the script answers")
        }
    }

    /// The suites' recording consent double with the production screen
    /// beside it: each request is rendered by [`SealConsent::report_for`] and
    /// `ConsentReport::render` at the moment the gate is asked, then answered
    /// — and recorded as a [`SeenConsent`] — by the script.
    struct Screened<'p> {
        script: ScriptedConsent,
        screen: SealConsent<'p, NeverAsked>,
        screens: RefCell<Vec<Vec<String>>>,
    }

    impl<'p> Screened<'p> {
        fn new(prompt: &'p mut NeverAsked, balances: BalanceReport) -> Self {
            Self {
                script: ScriptedConsent::always_yes(),
                screen: SealConsent::new(
                    &invocation(),
                    balances,
                    Vec::new(),
                    true,
                    false,
                    false,
                    1_800_000_000,
                    prompt,
                ),
                screens: RefCell::new(Vec::new()),
            }
        }

        fn seen(&self) -> Vec<SeenConsent> {
            self.script.seen.borrow().clone()
        }

        /// The one line of screen `index` that starts with `prefix`.
        fn line(&self, index: usize, prefix: &str) -> String {
            let screens = self.screens.borrow();
            let screen = screens.get(index).expect("a screen per consent");
            let lines: Vec<String> = screen
                .iter()
                .filter(|line| line.starts_with(prefix))
                .cloned()
                .collect();
            assert_eq!(
                lines.len(),
                1,
                "exactly one {prefix:?} line on screen {index}: {screen:#?}"
            );
            lines.into_iter().next().unwrap_or_default()
        }
    }

    impl ConsentHook for Screened<'_> {
        fn confirm(&self, request: &ConsentRequest<'_>) -> Result<ConsentDecision, CliError> {
            self.screens
                .borrow_mut()
                .push(self.screen.report_for(request).render());
            self.script.confirm(request)
        }
    }

    /// The adapter's stranded first payment: `pay` lands only the quote's
    /// first line — journaled through the REAL durable sink from inside
    /// `pay`, as the adapter journals each landed sub-batch (D37 Decision 7)
    /// — and then strands (exit 28). Everything else is the mock's.
    struct StrandsAfterFirstLine<'m> {
        inner: &'m MockBackend,
        sink: Arc<VaultReceiptSink>,
    }

    impl StorageBackend for StrandsAfterFirstLine<'_> {
        async fn quote_batch(&self, blobs: &[Blob]) -> Result<CostQuote, StorageError> {
            self.inner.quote_batch(blobs).await
        }

        async fn pay(&self, quote: &CostQuote) -> Result<PaymentReceipt, StorageError> {
            let first: Vec<BlobQuote> = quote.blobs.iter().take(1).cloned().collect();
            let total_ant_atto: u128 = first
                .iter()
                .map(|line| match &line.cost {
                    BlobCost::AlreadyStored => 0,
                    BlobCost::Priced { payments, .. } => {
                        payments.iter().map(|payment| payment.amount_atto).sum()
                    }
                })
                .sum();
            let landed = self
                .inner
                .pay(&CostQuote {
                    blobs: first,
                    total_ant_atto,
                    gas_estimate_wei: 0,
                })
                .await?;
            assert_eq!(
                self.sink.capture(&landed),
                CaptureOutcome::Durable,
                "the landed sub-batch is journaled before the strand"
            );
            Err(StorageError::StrandedPayment {
                landed_tx_count: landed.txs.len(),
                reason: "the second sub-batch failed (test double)".to_owned(),
            })
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

        async fn balances(&self) -> Result<BalanceReport, StorageError> {
            self.inner.balances().await
        }

        async fn payment_tx_state(&self, tx_hash: &TxHash) -> PaymentTxState {
            self.inner.payment_tx_state(tx_hash).await
        }
    }

    /// A work staged and planned as S12's staging phase leaves it, and not
    /// yet anchored: its first payment is the one a fresh seal makes.
    fn stage(vault: &UnlockedVault, seal_id: SealId) {
        journal_over(vault, |journal| {
            journal.begin(&identity(seal_id, false)).expect("begin");
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
            assert_eq!(journal.state(&seal_id).expect("state"), SealState::Staged);
        });
    }

    /// One resume of `seal_id`, with D37's durable sink wired into the
    /// journal as the binary wires it (`VaultJournal::with_receipt_sink`).
    fn run_resume<B: StorageBackend>(
        vault: &UnlockedVault,
        sink: &Arc<VaultReceiptSink>,
        backend: &B,
        consent: &Screened<'_>,
        seal_id: &SealId,
    ) -> Result<SealOutcome, SealError> {
        let mut r = rng();
        let journal =
            VaultJournal::new(WorkStore::new(vault), &mut r).with_receipt_sink(Arc::clone(sink));
        let gate = RecordingGate::new();
        let pipeline = Pipeline::new(backend, &gate, &journal, consent, &NoBarriers);
        block_on(pipeline.resume(seal_id))
    }

    /// The pipeline's first payment, over the whole seal, strands after its
    /// first sub-batch: the work keeps a durable receipt for one blob of the
    /// three, and its tag stays pre-pay. Returns that receipt.
    fn strand_the_first_payment(
        vault: &UnlockedVault,
        sink: &Arc<VaultReceiptSink>,
        mock: &MockBackend,
        consent: &Screened<'_>,
        seal_id: &SealId,
    ) -> PaymentReceipt {
        let backend = StrandsAfterFirstLine {
            inner: mock,
            sink: Arc::clone(sink),
        };
        match run_resume(vault, sink, &backend, consent, seal_id) {
            Err(SealError::Storage(StorageError::StrandedPayment { .. })) => {}
            other => panic!("the first payment strands after one sub-batch (exit 28): {other:?}"),
        }
        let capture = journal_over(vault, |journal| {
            assert_eq!(
                journal.state(seal_id).expect("state"),
                SealState::Anchored,
                "control: the strand leaves the work pre-pay"
            );
            journal
                .receipt(seal_id)
                .expect("read")
                .expect("the sink's capture")
        });
        assert_eq!(
            capture.blobs.len(),
            1,
            "control: the landed sub-batch covers one of the three blobs"
        );
        capture
    }

    /// **U120's Accept, the remainder — and a full first payment as before.**
    /// The pipeline's own first payment, quoted over every blob, strands
    /// after one sub-batch; the resume asks for the rest. The gate receives
    /// the remainder's count AND the seal's, and the production screen says
    /// the remainder is that share of the seal, while the first payment's
    /// screen keeps the words it had before U120.
    #[test]
    fn u120_a_remainder_consent_is_shown_as_its_share_of_the_seal() {
        let iso = IsolatedVault::create("u120-remainder");
        let vault = Arc::new(iso.unlock());
        let seal_id = fixture_seal_id(0xC1);
        stage(&vault, seal_id);
        let n = staged_blobs().len();
        assert_eq!(n, 3, "control: two units and the encrypted manifest");
        let mock = MockBackend::new();
        let sink = VaultReceiptSink::new(Arc::clone(&vault));
        let mut prompt = NeverAsked;
        let consent = Screened::new(&mut prompt, block_on(mock.balances()).expect("balances"));

        let partial = strand_the_first_payment(&vault, &sink, &mock, &consent, &seal_id);
        let outcome = run_resume(&vault, &sink, &mock, &consent, &seal_id)
            .expect("the resume pays the rest and completes the seal");
        assert!(
            outcome.paid_here && outcome.addresses.len() == n,
            "control: the resume paid and stored every blob"
        );

        let seen = consent.seen();
        assert_eq!(
            seen.len(),
            2,
            "the first payment's consent, then the remainder's"
        );
        assert_eq!(consent.screens.borrow().len(), 2, "one screen per consent");
        let (first, remainder) = (&seen[0], &seen[1]);
        assert!(
            !first.proofs_expired && !remainder.proofs_expired,
            "control: nothing expired in this flow"
        );

        // A full first payment: a quote over every blob, printed as before.
        assert_eq!(
            first.quote.blobs.len(),
            n,
            "control: the first quote covers the seal"
        );
        assert_eq!(
            (first.blob_count, first.work_blob_count),
            (n, n),
            "the first payment's request: (blob_count, work_blob_count)"
        );
        assert_eq!(
            consent.line(0, "  Upload:"),
            whole_seal_line(n),
            "a whole-seal quote prints as it did before U120"
        );

        // The remainder: K of the seal's N.
        let k = n - partial.blobs.len();
        assert_eq!(
            remainder.quote.blobs.len(),
            k,
            "control: the remainder quotes only the blobs the capture does not cover"
        );
        assert!(
            0 < k && k < n,
            "anti-vacuity: the remainder is a strict share of the seal (k {k}, n {n})"
        );
        assert_eq!(
            (remainder.blob_count, remainder.work_blob_count),
            (k, n),
            "the remainder's request: (blob_count, work_blob_count) — the gate must receive the \
             seal's count beside the quote's (U120)"
        );
        assert_eq!(
            consent.line(1, "  Upload:"),
            share_line(k, n),
            "the remainder's Upload line must name its share of the seal (U120)"
        );
    }

    /// **U120's Accept, the partial proofs-expired re-consent (S55's shape,
    /// D209 R7).** The pipeline's stranded first payment is resumed: the run
    /// pays the remainder, then finalize meets the older payment's expired
    /// proofs (`ExpiringOnce`: the verdict where the pipeline observes it).
    /// The arm keeps the records this run bought and re-quotes only the
    /// rest, so the proofs-expired request is a strict share of the seal —
    /// and the screen says so, on the Upload line and in the WARNING's count
    /// of what this run keeps.
    #[test]
    fn u120_a_partial_expired_re_consent_is_shown_as_its_share_of_the_seal() {
        let iso = IsolatedVault::create("u120-expired");
        let vault = Arc::new(iso.unlock());
        let seal_id = fixture_seal_id(0xC2);
        stage(&vault, seal_id);
        let n = staged_blobs().len();
        let mock = MockBackend::new();
        let sink = VaultReceiptSink::new(Arc::clone(&vault));
        let mut prompt = NeverAsked;
        let consent = Screened::new(&mut prompt, block_on(mock.balances()).expect("balances"));

        let partial = strand_the_first_payment(&vault, &sink, &mock, &consent, &seal_id);
        let expiring = ExpiringOnce::new(&mock);
        let outcome = run_resume(&vault, &sink, &expiring, &consent, &seal_id)
            .expect("the run pays the remainder, re-pays the expired share, completes the seal");
        assert!(
            outcome.paid_here && outcome.addresses.len() == n,
            "control: the run paid and stored every blob"
        );

        let seen = consent.seen();
        assert_eq!(
            seen.len(),
            3,
            "the first payment's consent, the remainder's, then the re-payment's"
        );
        assert_eq!(consent.screens.borrow().len(), 3, "one screen per consent");
        let (remainder, expired) = (&seen[1], &seen[2]);
        assert!(
            !remainder.proofs_expired && expired.proofs_expired,
            "control: the third consent is the proofs-expired one"
        );
        let paid_this_run = remainder.quote.blobs.len();
        assert_eq!(
            paid_this_run,
            n - partial.blobs.len(),
            "control: the run's remainder bought every blob the capture did not cover"
        );
        let k = n - paid_this_run;
        assert_eq!(
            expired.quote.blobs.len(),
            k,
            "control: the re-quote covers only the blobs this run did not buy (S55)"
        );
        let priced = expired
            .quote
            .blobs
            .iter()
            .filter(|line| matches!(line.cost, BlobCost::Priced { .. }))
            .count();
        assert_eq!(priced, k, "control: no re-quoted blob is stored yet");
        assert!(
            0 < k && k < n,
            "anti-vacuity: the re-payment is a strict share of the seal (k {k}, n {n})"
        );

        assert_eq!(
            (expired.blob_count, expired.work_blob_count),
            (k, n),
            "the proofs-expired request: (blob_count, work_blob_count) — the gate must receive \
             the seal's count beside the quote's (U120)"
        );
        assert_eq!(
            consent.line(2, "  Upload:"),
            share_line(k, n),
            "the proofs-expired Upload line must name its share of the seal (U120)"
        );
        let warning = consent.line(2, "  WARNING: a majority");
        assert!(
            warning.contains(&format!(
                "payment for the {priced} blob(s) priced here is stranded"
            )),
            "the WARNING counts what the re-payment replaces: {warning}"
        );
        assert!(
            warning.contains(&format!(
                "while the {paid_this_run} blob(s) paid for in this run keep their payment"
            )),
            "the WARNING counts what this run keeps (D209 R8): {warning}"
        );
    }
}
