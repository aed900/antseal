//! S10 acceptance suite: the seal journal — staged ciphertext bytes made
//! durable before payment, the state machine, and the ordering rules the
//! pipeline may not violate.
//!
//! The suite drives the **production** [`VaultJournal`] over a real
//! encrypted vault (one Argon2id vault, created once): S10's guarantees are
//! filesystem facts, and a pure in-memory double would assert none of them.
//! The pipeline-level ordering assertions against `MockBackend` are S12/S16's.
//!
//! NON-SECRET: every `W`, passphrase, path, and ciphertext byte here is a
//! documented fixture (project rule 6 — no real secret material, and none
//! of these values ever reaches a log or an error).

use std::path::PathBuf;
use std::sync::OnceLock;

use antseal_anchor::ots::AppliedUpgrade;
use antseal_cli::error::{CliError, ErrorClass};
use antseal_cli::pipeline::{
    AnchorArtifact, ArtifactKind, BlobSlot, JournalError, MANIFEST_BLOB_ENTRY, NONCE_LEN, OTS_SLOT,
    PLAN_ENTRY, STATE_ENTRY, SealJournal, SealPlan, SealState, StagedBlob, StagedBytesUnavailable,
    StoredAnchors, UNIT_ENTRY_BASE, VaultJournal, WorkIdentity, apply_upgrade,
    check_staged_integrity, tsa_slot, verify_all_staged,
};
use antseal_cli::vault::kdf::KdfSelection;
use antseal_cli::vault::layout::VaultLayout;
use antseal_cli::vault::session::{UnlockedVault, create_vault, unlock_vault};
use antseal_cli::vault::store::{
    ConsentChannel, ConsentRecord, SealShapingFlags, WorkState, WorkStore,
};
use antseal_core::bundle::schema::OtsUpgrade;
use antseal_core::codec::encode_item;
use antseal_core::crypto::material::MasterSecretRef;
use antseal_core::crypto::secrets::{SealId, SecretBuf};
use antseal_core::storage::compute_storage_address;
use antseal_net::quote::{QuoteHash, TxHash};
use antseal_net::receipt::{GasSummary, PaymentReceipt, TxRecord, TxStatus};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

// ─────────────────────────────────────────────────────────────────────
// Scaffolding
// ─────────────────────────────────────────────────────────────────────

const TEST_RNG_SEED: [u8; 32] = [0x51u8; 32];
const FIXTURE_PASSPHRASE: &[u8] = b"seal journal fixture passphrase";
/// NON-SECRET fixture master secret (never a real key; house convention).
const FIXTURE_W: [u8; 32] = [0x5A; 32];

fn passphrase() -> SecretBuf {
    SecretBuf::new(FIXTURE_PASSPHRASE.to_vec())
}

fn rng() -> ChaCha20Rng {
    ChaCha20Rng::from_seed(TEST_RNG_SEED)
}

struct SharedVault {
    #[allow(dead_code)]
    root: PathBuf,
    layout: VaultLayout,
}

impl SharedVault {
    fn unlock(&self) -> UnlockedVault {
        unlock_vault(&self.layout, &passphrase()).expect("unlock shared vault")
    }
}

fn shared_vault() -> &'static SharedVault {
    static VAULT: OnceLock<SharedVault> = OnceLock::new();
    VAULT.get_or_init(|| {
        let root = std::env::temp_dir().join(format!(
            "antseal-cli-journal-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).expect("mk root");
        let layout = VaultLayout::at(root.join("vault"));
        create_vault(&layout, &passphrase(), KdfSelection::Argon2id, &mut rng())
            .expect("create shared vault");
        SharedVault { root, layout }
    })
}

/// A distinct fixture seal id per call site (tests own disjoint works).
fn fixture_seal_id(tag: u8) -> SealId {
    let mut bytes = [tag; 16];
    bytes[0] = 0x5E;
    bytes[1] = tag;
    SealId::from_bytes(bytes)
}

fn identity(seal_id: SealId) -> WorkIdentity<'static> {
    static W: [u8; 32] = FIXTURE_W;
    WorkIdentity {
        w: MasterSecretRef::from_bytes(&W),
        seal_id,
        network: "devnet".to_owned(),
        unanchored: true,
        degraded: false,
        input_paths_as_given: vec!["notes.txt".to_owned()],
        input_paths_absolute: vec!["/tmp/notes.txt".to_owned()],
        shaping: SealShapingFlags::default(),
    }
}

/// A staged blob whose journaled address is the real S4/D32 address of its
/// bytes — the shape every honest staging step produces.
fn staged(slot: BlobSlot, ciphertext: Vec<u8>) -> StagedBlob {
    let address = compute_storage_address(&ciphertext).expect("fixture blob is under the cap");
    let mut nonce = [0u8; NONCE_LEN];
    // Distinct per slot so a swapped record is detectable in the assertions.
    nonce[0] = match slot {
        BlobSlot::EncryptedManifest => 0xFF,
        BlobSlot::Unit { unit_id } => u8::try_from(unit_id % 251).unwrap_or(0),
    };
    StagedBlob {
        slot,
        nonce,
        address,
        ciphertext,
    }
}

fn unit(unit_id: u64, fill: u8, len: usize) -> StagedBlob {
    staged(BlobSlot::Unit { unit_id }, vec![fill; len])
}

/// A minimal but structurally complete receipt (one sub-batch tx).
fn receipt(cost_atto: u128) -> PaymentReceipt {
    let quote = QuoteHash::from_bytes([0x11; 32]);
    let tx = TxHash::from_bytes([0x22; 32]);
    PaymentReceipt {
        blobs: Vec::new(),
        tx_map: [(quote, tx)].into_iter().collect(),
        txs: vec![TxRecord {
            tx_hash: tx,
            block_number: Some(42),
            status: TxStatus::Confirmed,
            quote_hashes: vec![quote],
        }],
        storage_cost_atto: cost_atto,
        gas: GasSummary { gas_cost_wei: 7 },
    }
}

/// Run `body` with a freshly-unlocked vault and a journal over it — the
/// "reopen the vault" shape every durability assertion needs.
fn with_journal<T>(body: impl FnOnce(&VaultJournal<'_, ChaCha20Rng>) -> T) -> T {
    let vault = shared_vault().unlock();
    let mut rng = rng();
    let journal = VaultJournal::new(WorkStore::new(&vault), &mut rng);
    body(&journal)
}

// ─────────────────────────────────────────────────────────────────────
// Round trip and integrity (S10 accept rows 2 and 4)
// ─────────────────────────────────────────────────────────────────────

/// **S10 accept**: journal round-trip restores byte-identical staged
/// ciphertexts — across a vault close/reopen, not just in one process.
#[test]
fn staged_ciphertexts_round_trip_byte_identically_across_a_reopen() {
    let seal_id = fixture_seal_id(1);
    let blobs = vec![
        unit(0, 0xA1, 1024),
        unit(1, 0xB2, 4096),
        staged(BlobSlot::EncryptedManifest, vec![0xC3; 777]),
    ];

    with_journal(|journal| {
        journal.begin(&identity(seal_id)).expect("begin");
        for blob in &blobs {
            journal.put_staged(&seal_id, blob).expect("put staged");
        }
    });

    // A completely new vault session — the bytes came off disk.
    with_journal(|journal| {
        for expected in &blobs {
            let got = journal.staged(&seal_id, expected.slot).expect("read back");
            assert_eq!(&got, expected, "staged record must round-trip exactly");
            assert_eq!(
                got.ciphertext, expected.ciphertext,
                "staged ciphertext must be byte-identical"
            );
        }
    });
}

/// **S10 accept**: the staged-bytes integrity check (recompute the address
/// via S4, compare to the journaled target) detects corruption and
/// classifies the work as staged-bytes-unavailable.
#[test]
fn corrupted_staged_bytes_classify_as_staged_bytes_unavailable() {
    let mut blob = unit(0, 0x33, 512);
    check_staged_integrity(&blob).expect("pristine staged bytes verify");

    // One flipped bit anywhere in the ciphertext.
    blob.ciphertext[100] ^= 0x08;
    assert_eq!(
        check_staged_integrity(&blob),
        Err(StagedBytesUnavailable::AddressMismatch)
    );

    // Truncation is caught by the same check.
    let mut truncated = unit(1, 0x44, 512);
    truncated.ciphertext.truncate(511);
    assert_eq!(
        check_staged_integrity(&truncated),
        Err(StagedBytesUnavailable::AddressMismatch)
    );

    // And so is a swapped target address.
    let mut swapped = unit(2, 0x55, 64);
    swapped.address = unit(3, 0x66, 64).address;
    assert_eq!(
        check_staged_integrity(&swapped),
        Err(StagedBytesUnavailable::AddressMismatch)
    );
}

/// A deleted journal entry is the abandon trigger S11 keys on, and it
/// surfaces as the distinct staged-bytes-unavailable class — not as a
/// generic I/O or not-found error.
#[test]
fn a_missing_staged_entry_is_the_distinct_unavailable_class() {
    let seal_id = fixture_seal_id(2);
    with_journal(|journal| {
        journal.begin(&identity(seal_id)).expect("begin");
        journal
            .put_staged(&seal_id, &unit(0, 0x77, 128))
            .expect("put staged");
        journal
            .put_staged(&seal_id, &unit(1, 0x88, 128))
            .expect("put staged");
        journal
            .put_plan(
                &seal_id,
                &SealPlan {
                    unit_count: 2,
                    manifest_bytes: None,
                },
            )
            .expect("plan");
        verify_all_staged(journal, &seal_id).expect("all staged bytes verify");

        // Simulate the disk loss S11 abandons on.
        journal
            .store()
            .delete_journal_entry(&seal_id, UNIT_ENTRY_BASE + 1)
            .expect("delete");

        match journal.staged(&seal_id, BlobSlot::Unit { unit_id: 1 }) {
            Err(JournalError::StagedBytes(StagedBytesUnavailable::Missing)) => {}
            other => panic!("expected Missing, got {other:?}"),
        }
        // And the whole-work sweep reports it too.
        assert!(matches!(
            verify_all_staged(journal, &seal_id),
            Err(JournalError::StagedBytes(_))
        ));
    });
}

/// Every staged-bytes failure maps onto the resume-safety-abort exit class
/// — one operational meaning (abandon), several diagnoses.
#[test]
fn staged_bytes_failures_map_to_the_resume_safety_abort_class() {
    for reason in [
        StagedBytesUnavailable::Missing,
        StagedBytesUnavailable::AddressMismatch,
        StagedBytesUnavailable::ExceedsChunkCap,
        StagedBytesUnavailable::Corrupt,
    ] {
        let err: CliError = JournalError::StagedBytes(reason).into();
        assert_eq!(err.class(), ErrorClass::ResumeSafetyAbort);
        assert!(!err.to_string().is_empty());
    }
}

// ─────────────────────────────────────────────────────────────────────
// Ordering and the state machine (S10 accept rows 1 and 3)
// ─────────────────────────────────────────────────────────────────────

/// **S10 accept (ordering, journal side)**: the state machine refuses to
/// reach `Paid` before `Anchored`, and `Anchored` before the staged bytes
/// have been journaled at `Staged`. The pipeline cannot call `pay` on a
/// work the journal will not advance.
#[test]
fn the_state_machine_refuses_to_skip_a_barrier() {
    let seal_id = fixture_seal_id(3);
    with_journal(|journal| {
        journal.begin(&identity(seal_id)).expect("begin");
        assert_eq!(journal.state(&seal_id).expect("state"), SealState::Staged);

        // Straight to Paid: refused, no write.
        match journal.set_state(&seal_id, SealState::Paid) {
            Err(JournalError::IllegalTransition { from, to }) => {
                assert_eq!(from, SealState::Staged);
                assert_eq!(to, SealState::Paid);
            }
            other => panic!("expected IllegalTransition, got {other:?}"),
        }
        assert_eq!(journal.state(&seal_id).expect("state"), SealState::Staged);

        // Straight to Complete: refused too.
        assert!(matches!(
            journal.set_state(&seal_id, SealState::Complete),
            Err(JournalError::IllegalTransition { .. })
        ));

        // The legal walk.
        for state in [
            SealState::Anchored,
            SealState::Paid,
            SealState::Finalizing,
            SealState::Complete,
        ] {
            journal.set_state(&seal_id, state).expect("legal advance");
            assert_eq!(journal.state(&seal_id).expect("state"), state);
        }

        // Terminal: nothing leaves Complete, in either direction.
        assert!(matches!(
            journal.set_state(&seal_id, SealState::Finalizing),
            Err(JournalError::IllegalTransition { .. })
        ));
        assert!(matches!(
            journal.set_state(&seal_id, SealState::Abandoned),
            Err(JournalError::IllegalTransition { .. })
        ));
    });
}

/// Re-writing the state a transition already reached is a no-op, not an
/// error: a crash between the durable write and the caller's return is
/// indistinguishable from never having written, so every transition must
/// be replayable.
#[test]
fn transitions_are_idempotent() {
    let seal_id = fixture_seal_id(4);
    with_journal(|journal| {
        journal.begin(&identity(seal_id)).expect("begin");
        journal
            .set_state(&seal_id, SealState::Anchored)
            .expect("advance");
        journal
            .set_state(&seal_id, SealState::Anchored)
            .expect("replay is a no-op");
        assert_eq!(journal.state(&seal_id).expect("state"), SealState::Anchored);
    });
}

/// **D43**: the `complete` transition is a state-tag write — same bytes, no
/// move, no copy. After it, every staged blob is still readable
/// byte-identically (now under the *cache* contract), and U9's coarse
/// mirror reads `Complete`.
#[test]
fn completing_reclassifies_without_moving_a_byte() {
    let seal_id = fixture_seal_id(5);
    let blob = unit(0, 0x99, 2048);

    with_journal(|journal| {
        journal.begin(&identity(seal_id)).expect("begin");
        journal.put_staged(&seal_id, &blob).expect("put staged");
        let before = std::fs::read(
            shared_vault()
                .layout
                .works_dir()
                .join(hex_dir(&seal_id))
                .join("journal")
                .join((UNIT_ENTRY_BASE).to_string()),
        )
        .expect("staged entry file exists");

        for state in [
            SealState::Anchored,
            SealState::Paid,
            SealState::Finalizing,
            SealState::Complete,
        ] {
            journal.set_state(&seal_id, state).expect("advance");
        }

        let after = std::fs::read(
            shared_vault()
                .layout
                .works_dir()
                .join(hex_dir(&seal_id))
                .join("journal")
                .join((UNIT_ENTRY_BASE).to_string()),
        )
        .expect("staged entry file still exists");
        assert_eq!(
            before, after,
            "D43: reclassification moves no byte of the staged record"
        );

        assert_eq!(
            journal.staged(&seal_id, blob.slot).expect("still readable"),
            blob
        );
        assert_eq!(
            journal.store().load_meta(&seal_id).expect("meta").state,
            WorkState::Complete,
            "the coarse mirror follows the fine tag"
        );
    });
}

/// The coarse [`WorkState`] mirror U9 records tracks every fine
/// transition, so `list`/`status`/D45's resume scan never decrypt a
/// journal entry to know where a work stands.
#[test]
fn the_coarse_mirror_tracks_every_fine_transition() {
    let seal_id = fixture_seal_id(6);
    with_journal(|journal| {
        journal.begin(&identity(seal_id)).expect("begin");
        for (state, mirror) in [
            (SealState::Staged, WorkState::IncompletePrePay),
            (SealState::Anchored, WorkState::IncompletePrePay),
            (SealState::Paid, WorkState::IncompletePostPay),
            (SealState::Finalizing, WorkState::IncompletePostPay),
            (SealState::Complete, WorkState::Complete),
        ] {
            journal.set_state(&seal_id, state).expect("advance");
            assert_eq!(
                journal.store().load_meta(&seal_id).expect("meta").state,
                mirror,
                "{} must mirror as {mirror:?}",
                state.name()
            );
        }
    });
}

/// The abandon path is reachable from every non-terminal state and is
/// itself terminal (S11's safety outcome).
#[test]
fn abandon_is_reachable_from_every_live_state_and_is_terminal() {
    for (tag, walk) in [
        (10u8, vec![]),
        (11, vec![SealState::Anchored]),
        (12, vec![SealState::Anchored, SealState::Paid]),
        (
            13,
            vec![SealState::Anchored, SealState::Paid, SealState::Finalizing],
        ),
    ] {
        let seal_id = fixture_seal_id(tag);
        with_journal(|journal| {
            journal.begin(&identity(seal_id)).expect("begin");
            for state in walk {
                journal.set_state(&seal_id, state).expect("advance");
            }
            journal
                .set_state(&seal_id, SealState::Abandoned)
                .expect("abandon is always reachable");
            assert_eq!(
                journal.store().load_meta(&seal_id).expect("meta").state,
                WorkState::Abandoned
            );
            assert!(matches!(
                journal.set_state(&seal_id, SealState::Complete),
                Err(JournalError::IllegalTransition { .. })
            ));
        });
    }
}

// ─────────────────────────────────────────────────────────────────────
// Receipt, consent, manifest, enumeration
// ─────────────────────────────────────────────────────────────────────

/// **S10 accept**: the receipt is durable the instant it is journaled — a
/// fresh vault session reads it back, which is what "before any finalize
/// call" means across a crash. `None` (not paid) is a state, not an error.
#[test]
fn the_receipt_survives_a_reopen_and_absence_is_a_state() {
    let seal_id = fixture_seal_id(7);
    with_journal(|journal| {
        journal.begin(&identity(seal_id)).expect("begin");
        assert!(
            journal.receipt(&seal_id).expect("read").is_none(),
            "not paid yet is None, never an error"
        );
        journal
            .put_receipt(&seal_id, &receipt(123_456))
            .expect("journal receipt");
    });

    with_journal(|journal| {
        let got = journal
            .receipt(&seal_id)
            .expect("read")
            .expect("receipt is durable across a reopen");
        assert_eq!(got, receipt(123_456));
        assert_eq!(got.storage_cost_atto, 123_456);
    });
}

/// **D36**: the consent record is journaled at every affirmative consent —
/// a display-only baseline for the next resume render, overwritten by the
/// latest consent.
#[test]
fn the_consent_record_is_journaled_and_overwritten_by_the_latest() {
    let seal_id = fixture_seal_id(8);
    let first = ConsentRecord {
        total_ant_atto: 1_000,
        gas_estimate_wei: 21_000,
        consent_time_unix_secs: 1_700_000_000,
        channel: ConsentChannel::Interactive,
    };
    let second = ConsentRecord {
        total_ant_atto: 1_500,
        gas_estimate_wei: 23_000,
        consent_time_unix_secs: 1_700_000_900,
        channel: ConsentChannel::YesFlag,
    };
    with_journal(|journal| {
        journal.begin(&identity(seal_id)).expect("begin");
        assert!(journal.consent(&seal_id).expect("read").is_none());
        journal.put_consent(&seal_id, first).expect("consent 1");
        assert_eq!(journal.consent(&seal_id).expect("read"), Some(first));
        journal.put_consent(&seal_id, second).expect("consent 2");
        assert_eq!(journal.consent(&seal_id).expect("read"), Some(second));
    });
}

/// The built plaintext manifest is journaled with the seal id, and comes
/// back byte-identically — resume never rebuilds or re-signs it (S11).
#[test]
fn the_plaintext_manifest_round_trips() {
    let seal_id = fixture_seal_id(9);
    let manifest = (0u16..600).map(|i| (i % 256) as u8).collect::<Vec<u8>>();
    with_journal(|journal| {
        journal.begin(&identity(seal_id)).expect("begin");
        assert!(journal.plan(&seal_id).expect("read").is_none());
        assert!(journal.manifest(&seal_id).expect("read").is_none());
        // Staging finishes first: the plan records the expected blob count
        // before the manifest exists.
        journal
            .put_plan(
                &seal_id,
                &SealPlan {
                    unit_count: 4,
                    manifest_bytes: None,
                },
            )
            .expect("staging plan");
        assert!(journal.manifest(&seal_id).expect("read").is_none());
        journal
            .put_plan(
                &seal_id,
                &SealPlan {
                    unit_count: 4,
                    manifest_bytes: Some(manifest.clone()),
                },
            )
            .expect("journal manifest");
    });
    with_journal(|journal| {
        assert_eq!(
            journal.manifest(&seal_id).expect("read"),
            Some(manifest.clone())
        );
        assert_eq!(
            journal.plan(&seal_id).expect("read"),
            Some(SealPlan {
                unit_count: 4,
                manifest_bytes: Some(manifest),
            })
        );
    });
}

/// **Canonical blob order**: units ascending by `unit_id`, encrypted
/// manifest last — derived from the entry-key namespace, never stored
/// twice, and independent of the order the blobs were journaled in.
#[test]
fn staged_slots_come_back_in_canonical_blob_order() {
    let seal_id = fixture_seal_id(14);
    with_journal(|journal| {
        journal.begin(&identity(seal_id)).expect("begin");
        // Journal them in a deliberately scrambled order.
        journal
            .put_staged(&seal_id, &staged(BlobSlot::EncryptedManifest, vec![1; 16]))
            .expect("put");
        for unit_id in [3u64, 0, 2, 1] {
            journal
                .put_staged(&seal_id, &unit(unit_id, 0x10 + unit_id as u8, 32))
                .expect("put");
        }
        assert_eq!(
            journal.staged_slots(&seal_id).expect("slots"),
            vec![
                BlobSlot::Unit { unit_id: 0 },
                BlobSlot::Unit { unit_id: 1 },
                BlobSlot::Unit { unit_id: 2 },
                BlobSlot::Unit { unit_id: 3 },
                BlobSlot::EncryptedManifest,
            ]
        );
    });
}

/// The reserved non-blob entries (state, plan) never appear as staged
/// slots — the namespace split is real, not a convention.
#[test]
fn reserved_entries_are_not_staged_slots() {
    assert_eq!(BlobSlot::from_entry_key(STATE_ENTRY), None);
    assert_eq!(BlobSlot::from_entry_key(PLAN_ENTRY), None);
    assert_eq!(
        BlobSlot::from_entry_key(MANIFEST_BLOB_ENTRY),
        Some(BlobSlot::EncryptedManifest)
    );

    let seal_id = fixture_seal_id(15);
    with_journal(|journal| {
        journal.begin(&identity(seal_id)).expect("begin");
        journal
            .put_plan(
                &seal_id,
                &SealPlan {
                    unit_count: 0,
                    manifest_bytes: Some(b"manifest".to_vec()),
                },
            )
            .expect("plan");
        journal
            .set_state(&seal_id, SealState::Anchored)
            .expect("state write");
        assert!(
            journal.staged_slots(&seal_id).expect("slots").is_empty(),
            "state and plan records are not staged blobs"
        );
    });
}

/// **S10 accept**: incomplete works are enumerable through a library API —
/// with their fine state, and without decrypting a single staged blob body.
///
/// # This row is deliberately on the shared vault (D106 §7)
///
/// It is the tree's **only** witness that a whole-store scan is *total*
/// under real concurrent mutation: 27 tests run in parallel against one
/// vault while `begin`, `set_state` and `put_anchor` execute, so the
/// enumeration below is racing genuine writers. Its assertions are
/// membership-only over ids it owns, so a neighbour's work appearing or
/// vanishing cannot make it wrong — what made it fail historically was the
/// **scan erroring**, not the scan's contents (U66/S34/S38, three
/// recordings of one defect).
///
/// So a red here means `list_works` or `incomplete_works` stopped being
/// total. It does **not** mean the test is flaky, and moving it to an
/// isolated vault would trade a real signal for a permanently green vacuum
/// (D100 R10.2). The rows below it plant on-disk state and therefore do
/// own private vaults — a plant races siblings, a read does not.
#[test]
fn incomplete_works_are_enumerable_with_their_state() {
    let live = fixture_seal_id(16);
    let done = fixture_seal_id(17);
    let gone = fixture_seal_id(18);
    with_journal(|journal| {
        journal.begin(&identity(live)).expect("begin");
        journal
            .set_state(&live, SealState::Anchored)
            .expect("advance");

        journal.begin(&identity(done)).expect("begin");
        for state in [
            SealState::Anchored,
            SealState::Paid,
            SealState::Finalizing,
            SealState::Complete,
        ] {
            journal.set_state(&done, state).expect("advance");
        }

        journal.begin(&identity(gone)).expect("begin");
        journal
            .set_state(&gone, SealState::Abandoned)
            .expect("abandon");

        let incomplete = journal.incomplete_works().expect("enumerate");
        assert!(
            incomplete.contains(&(live, Some(SealState::Anchored))),
            "the live work is a resume candidate"
        );
        assert!(
            !incomplete.iter().any(|(id, _)| *id == done),
            "a complete work is never a resume candidate"
        );
        assert!(
            !incomplete.iter().any(|(id, _)| *id == gone),
            "an abandoned work is never a resume candidate"
        );
    });
}

/// **D106 R4**: `begin` is `create_work` **then**
/// `put_journal_entry(STATE_ENTRY)`, so between them a work has its `meta`
/// record and no fine state tag. That is a work in progress, not a corrupt
/// one — and `incomplete_works` was the only reader in the tree that said
/// otherwise, failing the **whole enumeration** with
/// `Corrupt { detail: "work has no journal state record" }`.
///
/// Production has always tolerated it: `list` reads the fine tag through
/// `recorded_state`, which maps an absent record to `Ok(None)` (U19 note 2,
/// pinned by `a_work_without_its_fine_state_record_still_lists`), and falls
/// back to U9's coarse mirror. This row makes the enumeration agree.
///
/// `SealJournal::state` is deliberately **not** changed: its other callers
/// are `set_state` and the seal pipeline, which run under the U5 lock, and
/// a state machine that cannot read the current state must not advance.
///
/// The window is reconstructed on disk rather than raced for —
/// `delete_journal_entry(STATE_ENTRY)` leaves exactly the bytes `begin`
/// leaves between its two writes. Private vault: this row **plants**, and a
/// plant races the shared vault's parallel enumerations.
#[test]
fn a_work_begun_but_not_yet_state_tagged_is_in_progress_not_corrupt() {
    let root = std::env::temp_dir().join(format!(
        "antseal-cli-journal-d106-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ));
    std::fs::create_dir_all(&root).expect("mk root");
    let layout = VaultLayout::at(root.join("vault"));
    let unlocked = create_vault(&layout, &passphrase(), KdfSelection::Argon2id, &mut rng())
        .expect("create private vault");
    let mut journal_rng = rng();
    let journal = VaultJournal::new(WorkStore::new(&unlocked), &mut journal_rng);
    let store = WorkStore::new(&unlocked);

    let mid_begin = fixture_seal_id(24);
    journal.begin(&identity(mid_begin)).expect("begin");
    assert!(
        store
            .delete_journal_entry(&mid_begin, STATE_ENTRY)
            .expect("delete"),
        "the fine tag was there to delete"
    );

    let incomplete = journal
        .incomplete_works()
        .expect("a work mid-`begin` is not a corrupt vault");
    assert!(
        incomplete.contains(&(mid_begin, None)),
        "no fine tag is a state, and U9's coarse mirror filters it in: {incomplete:?}"
    );

    // The fine tag is still preferred wherever it exists, so nothing
    // outside this window changes: `set_state`'s mirror-lags-by-one-barrier
    // ordering keeps deciding membership by the authoritative record.
    let tagged = fixture_seal_id(25);
    journal.begin(&identity(tagged)).expect("begin");
    journal
        .set_state(&tagged, SealState::Anchored)
        .expect("advance");
    let incomplete = journal.incomplete_works().expect("enumerate");
    assert!(incomplete.contains(&(tagged, Some(SealState::Anchored))));

    let _ = std::fs::remove_dir_all(&root);
}

// ─────────────────────────────────────────────────────────────────────
// Hygiene (S10 accept row 4, second half)
// ─────────────────────────────────────────────────────────────────────

/// **S10 accept**: no plaintext unit bytes, `W`, `k_u` or salts appear in
/// the journal area beyond what the spec mandates — and every journal file
/// is ciphertext, so even the mandated bytes are not readable on disk.
#[test]
fn journal_files_are_ciphertext_and_leak_no_plaintext() {
    let seal_id = fixture_seal_id(19);
    // Distinctive fixture bytes we then hunt for on disk.
    let plaintext_marker: &[u8] = b"PLAINTEXT-UNIT-MARKER-DO-NOT-LEAK";
    let mut ciphertext = vec![0x5C; 256];
    ciphertext[..plaintext_marker.len()].copy_from_slice(plaintext_marker);
    let blob = staged(BlobSlot::Unit { unit_id: 0 }, ciphertext);

    with_journal(|journal| {
        journal.begin(&identity(seal_id)).expect("begin");
        journal.put_staged(&seal_id, &blob).expect("put staged");
        journal
            .put_plan(
                &seal_id,
                &SealPlan {
                    unit_count: 1,
                    manifest_bytes: Some(b"manifest".to_vec()),
                },
            )
            .expect("plan");
        journal.put_receipt(&seal_id, &receipt(9)).expect("receipt");
    });

    let work_dir = shared_vault().layout.works_dir().join(hex_dir(&seal_id));
    let mut files = 0usize;
    for path in walk(&work_dir) {
        let bytes = std::fs::read(&path).expect("read record file");
        files += 1;
        assert!(
            !contains(&bytes, plaintext_marker),
            "record {} exposes staged bytes in the clear",
            path.display()
        );
        assert!(
            !contains(&bytes, &FIXTURE_W),
            "record {} exposes W in the clear",
            path.display()
        );
        assert!(
            !contains(&bytes, FIXTURE_PASSPHRASE),
            "record {} exposes the passphrase",
            path.display()
        );
    }
    assert!(
        files >= 4,
        "expected meta + state + plan + staged + receipt"
    );
}

/// Error renderings never carry record content — a malformed journal must
/// not become an oracle for the bytes it held.
#[test]
fn journal_errors_carry_no_record_bytes() {
    let secret_shaped = vec![0xDE, 0xAD, 0xBE, 0xEF];
    let mut record = staged(BlobSlot::Unit { unit_id: 0 }, secret_shaped.clone())
        .encode()
        .expect("encodes");
    // Corrupt the envelope so decode fails on adversarial-looking bytes.
    let last = record.len() - 1;
    record[last] ^= 0xFF;
    let rendered = match StagedBlob::decode(&record) {
        Err(err) => err.to_string(),
        Ok(_) => String::new(),
    };
    assert!(
        !rendered.contains("dead") && !rendered.contains("DEAD") && !rendered.contains("beef"),
        "error rendering leaked record bytes: {rendered}"
    );
}

// ─────────────────────────────────────────────────────────────────────
// The anchor slots: U47's reader, and D97/D99's single write site
//
// These run over the real encrypted store because every claim here is a
// filesystem fact — that `list_anchors` really does sort lexically, that a
// slot really does survive a close/reopen, that one `put_anchor` really is
// one atomic replacement. The ordering and refusal rules are unit-tested in
// `src/pipeline/anchors/tests.rs` against the same code path.
// ─────────────────────────────────────────────────────────────────────

/// A synthetic 80-byte block header (NON-SECRET, patterned so an off-by-one
/// splice is visible in a failure dump).
fn fixture_block_header() -> [u8; 80] {
    let mut bytes = [0u8; 80];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = 0xB0u8.wrapping_add(u8::try_from(index % 16).expect("small"));
    }
    bytes
}

/// The pending `.ots` record a seal leaves in [`OTS_SLOT`].
fn pending_ots(fetch_date: u64) -> AnchorArtifact {
    AnchorArtifact {
        kind: ArtifactKind::OtsPending,
        endpoint: String::new(),
        fetch_date,
        bytes: vec![0x00, 0x4F, 0x54, 0x53, 0x01, 0x02],
        upgrade: None,
    }
}

fn tsa_token(index: usize) -> AnchorArtifact {
    AnchorArtifact {
        kind: ArtifactKind::TsaToken,
        endpoint: format!("http://127.0.0.1:1/tsr/{index}"),
        fetch_date: 1_800_000_000 + index as u64,
        bytes: vec![0x30, 0x82, u8::try_from(index).expect("small fixture")],
        upgrade: None,
    }
}

/// **U47 Accept**: a record written by the seal path round-trips through the
/// shared reader — across a vault close/reopen, so the bytes came off disk.
///
/// This is the one property the task was written for: `pipeline/anchors.rs`
/// wrote these slots and *nothing read them back except a test*, so `status`
/// and `reveal` were each about to grow their own decoder.
#[test]
fn anchor_slots_written_by_the_seal_path_round_trip_through_the_shared_reader() {
    let seal_id = fixture_seal_id(0x40);
    let written = vec![
        (OTS_SLOT.to_owned(), pending_ots(1_800_000_000)),
        (tsa_slot(0), tsa_token(0)),
        (tsa_slot(1), tsa_token(1)),
    ];

    with_journal(|journal| {
        journal.begin(&identity(seal_id)).expect("begin");
        // Exactly the call the seal/resume anchor loop makes.
        for (slot, artifact) in &written {
            journal
                .put_anchor(&seal_id, slot, &artifact.encode().expect("encodes"))
                .expect("put anchor");
        }
    });

    let vault = shared_vault().unlock();
    let store = WorkStore::new(&vault);
    let stored_anchors = StoredAnchors::read(&store, &seal_id).expect("read anchors");
    let anchors = stored_anchors.require_intact().expect("read anchors");
    assert_eq!(anchors.all(), written.as_slice(), "record and slot both");
    assert_eq!(anchors.ots().len(), 1);
    assert_eq!(anchors.tsa().len(), 2);
    assert_eq!(anchors.ots_slot(0), Some(OTS_SLOT));
}

/// **The numeric re-sort, crossing the real `list_anchors`.**
///
/// `list_anchors` is a `read_dir` + `sort_unstable`, so it hands back
/// `tsa-10` before `tsa-2`. The upgrade engine indexes anchors positionally,
/// so passing the directory order through would mis-pair an applied upgrade
/// the first time a work had eleven TSA captures. Twelve here — the existing
/// `tests/anchor_stage.rs` fixture has one and cannot see it.
#[test]
fn the_reader_repairs_the_lexical_slot_order_a_real_listing_produces() {
    let seal_id = fixture_seal_id(0x41);
    with_journal(|journal| {
        journal.begin(&identity(seal_id)).expect("begin");
        journal
            .put_anchor(
                &seal_id,
                OTS_SLOT,
                &pending_ots(1_800_000_000).encode().expect("encodes"),
            )
            .expect("put anchor");
        for index in 0..12 {
            journal
                .put_anchor(
                    &seal_id,
                    &tsa_slot(index),
                    &tsa_token(index).encode().expect("encodes"),
                )
                .expect("put anchor");
        }
    });

    let vault = shared_vault().unlock();
    let store = WorkStore::new(&vault);

    // The premise, measured rather than assumed: this is what the store hands
    // over, and it is wrong for the engine.
    let listed = store.list_anchors(&seal_id).expect("list");
    assert_eq!(
        listed.iter().position(|s| s == "tsa-10"),
        Some(3),
        "the store really does sort lexically: {listed:?}"
    );
    assert!(
        listed.iter().position(|s| s == "tsa-10") < listed.iter().position(|s| s == "tsa-2"),
        "the bug the reader owes a repair for: {listed:?}"
    );

    let stored_anchors = StoredAnchors::read(&store, &seal_id).expect("read anchors");

    let anchors = stored_anchors.require_intact().expect("read anchors");
    let order: Vec<&str> = anchors
        .all()
        .iter()
        .map(|(slot, _)| slot.as_str())
        .collect();
    assert_eq!(
        order,
        vec![
            "ots-pending",
            "tsa-0",
            "tsa-1",
            "tsa-2",
            "tsa-3",
            "tsa-4",
            "tsa-5",
            "tsa-6",
            "tsa-7",
            "tsa-8",
            "tsa-9",
            "tsa-10",
            "tsa-11",
        ],
        "OTS first, then TSA by parsed index"
    );
    // Each record travelled with its own slot, not merely its name.
    for (index, (_, artifact)) in anchors.tsa().iter().enumerate() {
        assert_eq!(artifact, &tsa_token(index));
    }
}

/// A work that never anchored has no `anchors/` directory at all. That is a
/// state — `--no-anchor` seals and works killed before the gate both have
/// one — and it reads as empty rather than erroring.
#[test]
fn a_work_with_no_anchor_directory_reads_as_empty_not_as_a_failure() {
    let seal_id = fixture_seal_id(0x42);
    with_journal(|journal| {
        journal.begin(&identity(seal_id)).expect("begin");
    });

    let vault = shared_vault().unlock();
    let store = WorkStore::new(&vault);
    let stored_anchors =
        StoredAnchors::read(&store, &seal_id).expect("no anchors is not a failure");
    let anchors = stored_anchors
        .require_intact()
        .expect("no anchors is not a failure");
    assert!(anchors.is_empty());
    assert_eq!(anchors.len(), 0);
}

/// **U47 Accept**: an unknown version is refused **by name**, not skipped and
/// not conflated with damage.
///
/// "Upgrade antseal" and "your vault is damaged" are different sentences, and
/// only one of them is the user's fault. The record below is substituted on
/// disk through the store's own writer, so it is a genuine future record
/// inside a genuine AEAD rather than a decoder called directly.
///
/// Re-pointed at the **evidence door** by D100 R10.1, with every assertion
/// standing verbatim — `ErrorClass::VaultNewerVersion` included. That is the
/// check that R2's restructure is a relocation of a policy and not a change
/// to one: D100 R1 keeps `NewerRecord` a distinct damage reason, so this row
/// constrains the design rather than fighting it.
#[test]
fn a_newer_anchor_record_refuses_by_name_through_the_evidence_door() {
    let seal_id = fixture_seal_id(0x43);
    let future_version = u64::from(antseal_cli::pipeline::SEAL_JOURNAL_VERSION) + 1;
    let body = encode_item(|e| e.map(|m| m.entry(0, |e| e.u64(0)))).expect("encodes");
    let future = encode_item(|e| {
        e.array(|a| {
            a.item(|e| e.u64(future_version))?;
            a.item(|e| e.bytes(&body))
        })
    })
    .expect("encodes");

    with_journal(|journal| {
        journal.begin(&identity(seal_id)).expect("begin");
        journal
            .put_anchor(&seal_id, OTS_SLOT, &future)
            .expect("put anchor");
    });

    let vault = shared_vault().unlock();
    let store = WorkStore::new(&vault);
    let stored = StoredAnchors::read(&store, &seal_id).expect("the read itself succeeds");
    match stored.require_intact() {
        Err(JournalError::NewerRecord { found }) => assert_eq!(found, future_version),
        other => panic!("a newer record must refuse as newer, got {other:?}"),
    }
    // And it keeps the class the whole way to the exit code, rather than
    // collapsing into the vault-auth sentence.
    let err: CliError = stored.require_intact().expect_err("newer").into();
    assert_eq!(err.class(), ErrorClass::VaultNewerVersion);

    // **D100 R1**: through the reporting door the same record is a datum
    // whose reason is `newer-record` and not `undecodable` — the distinction
    // "upgrade antseal" rests on, carried all the way to `--json`.
    let (intact, damaged) = stored.intact_and_damaged();
    assert!(intact.is_empty());
    assert_eq!(damaged.len(), 1);
    assert_eq!(damaged[0].slot, OTS_SLOT);
    assert_eq!(damaged[0].reason.name(), "newer-record");
    assert_eq!(damaged[0].reason.format_version(), Some(future_version));
}

/// One unreadable slot means the **evidence door** refuses — never a partial
/// picture through it.
///
/// A caller handed nine of ten artifacts would render a verdict about
/// evidence it does not have. D100 R2 keeps that rule and makes it a type:
/// the refusal moved from `read` to `require_intact`, the error is
/// byte-identical, and the assertion below is unchanged from before D100.
/// Its counterpart is the row after this one, which takes the other door.
#[test]
fn one_unreadable_slot_refuses_at_the_evidence_door() {
    let seal_id = fixture_seal_id(0x44);
    with_journal(|journal| {
        journal.begin(&identity(seal_id)).expect("begin");
        journal
            .put_anchor(
                &seal_id,
                OTS_SLOT,
                &pending_ots(1_800_000_000).encode().expect("encodes"),
            )
            .expect("put anchor");
        // A structurally impossible record in the second slot: a TSA slot
        // holding an OTS-kind artifact.
        journal
            .put_anchor(
                &seal_id,
                &tsa_slot(0),
                &pending_ots(1_800_000_001).encode().expect("encodes"),
            )
            .expect("put anchor");
    });

    let vault = shared_vault().unlock();
    let store = WorkStore::new(&vault);
    let stored = StoredAnchors::read(&store, &seal_id).expect("the read itself succeeds");
    match stored.require_intact() {
        Err(JournalError::Corrupt { detail }) => {
            assert_eq!(detail, "anchor slot family disagrees with the record kind");
        }
        other => panic!("a partial picture was returned: {other:?}"),
    }

    // **D100 R2, the counterpart**: the reporting door hands back the
    // survivor *and* the damage, together — which is the whole reason `list`
    // can now say "1 of 2" rather than "damaged" (§2(b)).
    let (intact, damaged) = stored.intact_and_damaged();
    assert_eq!(
        intact.len(),
        1,
        "the good OTS slot survives the bad TSA one"
    );
    assert_eq!(intact.ots_slot(0), Some(OTS_SLOT));
    assert_eq!(stored.total_slots(), 2);
    assert_eq!(damaged.len(), 1);
    assert_eq!(damaged[0].slot, tsa_slot(0));
    assert_eq!(damaged[0].reason.name(), "undecodable");
    assert_eq!(
        damaged[0].reason.detail(),
        "anchor slot family disagrees with the record kind",
        "the damaged slot carries the decoder's own message, verbatim (R10.5)"
    );
    assert_eq!(damaged[0].reason.format_version(), None);
}

/// **D97 §3 + D99 R10: the upgrade lands in one record, through one write.**
///
/// Every fact D97's ruling turns on, asserted against the disk: the slot name
/// does not change, the slot *set* does not change, the artifact bytes are
/// replaced, the group arrives with them, key 2 still carries the original
/// submission's date and key 6 carries the header fetch's (R4/R5).
#[test]
fn applying_an_upgrade_replaces_one_record_and_keeps_the_submission_fetch_date() {
    let seal_id = fixture_seal_id(0x45);
    let submission_date = 1_800_000_000;
    let header_fetch_date = 1_800_090_000;
    let prior = pending_ots(submission_date);

    with_journal(|journal| {
        journal.begin(&identity(seal_id)).expect("begin");
        journal
            .put_anchor(&seal_id, OTS_SLOT, &prior.encode().expect("encodes"))
            .expect("put anchor");
        journal
            .put_anchor(
                &seal_id,
                &tsa_slot(0),
                &tsa_token(0).encode().expect("encodes"),
            )
            .expect("put anchor");
    });

    let applied = AppliedUpgrade {
        work_id: [0x7A; 32],
        anchor_index: 0,
        artifact: vec![0x00, 0x4F, 0x54, 0x53, 0xFF, 0xEE, 0xDD],
        upgrade: Some(OtsUpgrade::new(
            870_123,
            fixture_block_header(),
            header_fetch_date,
        )),
    };

    let vault = shared_vault().unlock();
    let store = WorkStore::new(&vault);
    let stored_anchors = StoredAnchors::read(&store, &seal_id).expect("read");
    let anchors = stored_anchors.require_intact().expect("read");
    // R10: the slot comes from the ordered list this very read produced,
    // never from a fresh listing.
    let (slot, read_prior) = anchors
        .ots_entry(applied.anchor_index)
        .expect("the report names an anchor this work has");
    assert_eq!(read_prior, &prior);

    let mut write_rng = ChaCha20Rng::from_seed([0x99; 32]);
    apply_upgrade(&store, &seal_id, slot, read_prior, &applied, &mut write_rng)
        .expect("the upgrade applies");

    // Re-open: the write is on disk, not in a cache.
    let vault = shared_vault().unlock();
    let store = WorkStore::new(&vault);
    let stored_after = StoredAnchors::read(&store, &seal_id).expect("read back");
    let after = stored_after.require_intact().expect("read back");

    // The slot SET is unchanged — D97 R7's whole point. An `ots-upgrade`
    // slot would have published the anchor state to anyone with filesystem
    // read access; there is no new name and no new file.
    assert_eq!(
        store.list_anchors(&seal_id).expect("list"),
        vec![OTS_SLOT.to_owned(), tsa_slot(0)],
        "the upgrade must not mint a slot"
    );

    let (_, upgraded) = &after.ots()[0];
    assert_eq!(upgraded.bytes, applied.artifact, "the .ots bytes advanced");
    let group = upgraded.upgrade.as_ref().expect("the group rode along");
    assert_eq!(group.block_height(), 870_123);
    assert_eq!(group.block_header(), &fixture_block_header());
    assert_eq!(
        group.fetch_date(),
        header_fetch_date,
        "key 6 is pinned from the engine's parameter (R5), never a clock"
    );
    assert_eq!(
        upgraded.fetch_date, submission_date,
        "key 2 must still be the ORIGINAL submission's date (R4)"
    );
    // The TSA half is untouched: one record was replaced, not the area.
    assert_eq!(after.tsa(), &[(tsa_slot(0), tsa_token(0))]);
}

/// **D97 R6**: an upgraded artifact with no group is refused, never written.
///
/// It would be strictly worse than the pending artifact it replaced —
/// `pending` (O5) becomes `internally-consistent-only` (O9), the work stops
/// being nagged (`NagState::AttestedOnly`), and `--online` is structurally
/// unable to rescue it because `agreed` is derived from the group. The engine
/// cannot produce this today (`changed ⟹ upgrade.is_some()`), which is a
/// control-flow property and not a type property — so the write site refuses
/// rather than trusts.
#[test]
fn an_upgrade_with_no_group_is_refused_and_writes_nothing() {
    let seal_id = fixture_seal_id(0x46);
    let prior = pending_ots(1_800_000_000);
    with_journal(|journal| {
        journal.begin(&identity(seal_id)).expect("begin");
        journal
            .put_anchor(&seal_id, OTS_SLOT, &prior.encode().expect("encodes"))
            .expect("put anchor");
    });

    let groupless = AppliedUpgrade {
        work_id: [0x7A; 32],
        anchor_index: 0,
        artifact: vec![0x00, 0x4F, 0x54, 0x53, 0xFF],
        upgrade: None,
    };

    let vault = shared_vault().unlock();
    let store = WorkStore::new(&vault);
    let mut write_rng = ChaCha20Rng::from_seed([0x9A; 32]);
    match apply_upgrade(
        &store,
        &seal_id,
        OTS_SLOT,
        &prior,
        &groupless,
        &mut write_rng,
    ) {
        Err(JournalError::IllegalAnchorWrite { detail }) => assert_eq!(
            detail,
            "an OTS upgrade arrived without its block-header group"
        ),
        other => panic!("a groupless upgrade was not refused: {other:?}"),
    }

    // Nothing was written: the pending artifact is exactly as it was.
    let stored_after = StoredAnchors::read(&store, &seal_id).expect("read back");
    let after = stored_after.require_intact().expect("read back");
    assert_eq!(after.ots(), &[(OTS_SLOT.to_owned(), prior)]);
}

/// **D99 R3: compare-and-set.** `prior` is load-bearing, not advisory.
///
/// The engine polls *unlocked* — the U5 lock is never held across network
/// I/O — so between the read that computed a transition and the write that
/// applies it, a resume may have rewritten `ots-pending` from a **fresh**
/// submission. Writing anyway would pair a genuinely upgraded `.ots` with a
/// previous submission's artifact, which is D97 §2 K2's false
/// `anchor-ots-header-uncommitted` verdict on an honest work.
#[test]
fn an_upgrade_computed_against_a_stale_record_is_discarded_not_written() {
    let seal_id = fixture_seal_id(0x47);
    let stale = pending_ots(1_800_000_000);
    let fresh = AnchorArtifact {
        // What a resume writes: new bytes, and a new submission date.
        bytes: vec![0x00, 0x4F, 0x54, 0x53, 0xAA, 0xBB],
        ..pending_ots(1_800_050_000)
    };

    with_journal(|journal| {
        journal.begin(&identity(seal_id)).expect("begin");
        journal
            .put_anchor(&seal_id, OTS_SLOT, &stale.encode().expect("encodes"))
            .expect("put anchor");
    });

    let applied = AppliedUpgrade {
        work_id: [0x7A; 32],
        anchor_index: 0,
        artifact: vec![0x00, 0x4F, 0x54, 0x53, 0xFF, 0xEE],
        upgrade: Some(OtsUpgrade::new(
            870_123,
            fixture_block_header(),
            1_800_090_000,
        )),
    };

    // …the interleaving: another process rewrites the slot after the read.
    with_journal(|journal| {
        journal
            .put_anchor(&seal_id, OTS_SLOT, &fresh.encode().expect("encodes"))
            .expect("the resume rewrites the slot");
    });

    let vault = shared_vault().unlock();
    let store = WorkStore::new(&vault);
    let mut write_rng = ChaCha20Rng::from_seed([0x9B; 32]);
    assert!(
        matches!(
            apply_upgrade(&store, &seal_id, OTS_SLOT, &stale, &applied, &mut write_rng),
            Err(JournalError::AnchorSlotMoved)
        ),
        "a transition computed against a superseded record must be discarded"
    );

    // The fresh record survives untouched — in particular it did NOT acquire
    // the stale transition's group, which is the state that renders `invalid`.
    let stored_after = StoredAnchors::read(&store, &seal_id).expect("read back");
    let after = stored_after.require_intact().expect("read back");
    assert_eq!(after.ots(), &[(OTS_SLOT.to_owned(), fresh)]);

    // And re-reading first makes the same transition applicable again, so the
    // refusal is a discard-and-recompute rather than a dead end.
    let stored_current = StoredAnchors::read(&store, &seal_id).expect("read");
    let current = stored_current.require_intact().expect("read");
    let (slot, prior) = current.ots_entry(0).expect("one OTS anchor");
    apply_upgrade(&store, &seal_id, slot, prior, &applied, &mut write_rng)
        .expect("the recomputed transition applies");
}

/// The compare-and-set is over the **whole record**, not just the `.ots`
/// bytes: a slot whose key 2 moved is a slot whose submission moved, and
/// carrying that fetch date forward (D97 R4) would attribute one
/// submission's provenance to another's.
#[test]
fn the_compare_and_set_catches_a_record_that_moved_only_in_its_fetch_date() {
    let seal_id = fixture_seal_id(0x48);
    let prior = pending_ots(1_800_000_000);
    // Same `.ots` bytes, different submission date.
    let moved = pending_ots(1_800_050_000);
    assert_eq!(prior.bytes, moved.bytes, "the fixture isolates key 2");

    with_journal(|journal| {
        journal.begin(&identity(seal_id)).expect("begin");
        journal
            .put_anchor(&seal_id, OTS_SLOT, &moved.encode().expect("encodes"))
            .expect("put anchor");
    });

    let applied = AppliedUpgrade {
        work_id: [0x7A; 32],
        anchor_index: 0,
        artifact: vec![0x00, 0x4F, 0x54, 0x53, 0xFF],
        upgrade: Some(OtsUpgrade::new(
            870_123,
            fixture_block_header(),
            1_800_090_000,
        )),
    };

    let vault = shared_vault().unlock();
    let store = WorkStore::new(&vault);
    let mut write_rng = ChaCha20Rng::from_seed([0x9C; 32]);
    assert!(
        matches!(
            apply_upgrade(&store, &seal_id, OTS_SLOT, &prior, &applied, &mut write_rng),
            Err(JournalError::AnchorSlotMoved)
        ),
        "a record that moved only in key 2 must still fail the compare-and-set"
    );
}

/// **D97 R3 / D99 R10: the write sites of an anchor slot, enumerated.**
///
/// The single-write-site rule is the whole of the atomicity argument — one
/// `put_anchor` replaces one whole record in one atomic rename, which is what
/// makes D79's *"recorded together or not at all"* a property of the
/// filesystem instead of a property of a comment. It is otherwise only a
/// comment, so it is asserted here as **data**: the exact set, by file, with
/// each file's role named. A new site reddens this by appearing in the diff
/// of a `Vec`, and cannot be waved through as "still about two".
///
/// # D97 R3 is wrong about the count, and was wrong before this change
///
/// R3 says *"a test … asserts there are exactly two (the seal/resume loop and
/// this one)"*. Measured, there are **four** textual call sites, and two of
/// the four are neither of R3's:
///
/// - `vault_journal.rs` is the `SealJournal::put_anchor` **trait impl**
///   forwarding to the store. It is the plumbing the seal/resume site travels
///   through, not a second decision to write.
/// - `vault/export.rs` is **D47's import**, which reinstalls exported anchor
///   slots verbatim. It writes bytes it never authored and never inspects —
///   D97 §1.3 records this path itself (*"Export/import carry anchor slots
///   opaquely"*) and still wrote "exactly two".
///
/// Both spellings of the call are counted, because `apply_upgrade` reaches
/// the store directly (U24's hook has no journal, D99 R10): a scan for
/// `journal.put_anchor` alone would report half the rule and pass.
#[test]
fn the_anchor_slot_write_sites_are_exactly_the_enumerated_four() {
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut sites: Vec<String> = Vec::new();
    let mut visited = 0usize;
    for path in walk(&src) {
        if path.extension().is_none_or(|e| e != "rs") {
            continue;
        }
        visited += 1;
        let text = std::fs::read_to_string(&path).expect("read source");
        for line in text.lines() {
            let line = line.trim();
            // A definition is not a call site, and neither is prose about one.
            if line.starts_with("//") || line.contains("fn put_anchor") {
                continue;
            }
            if line.contains(".put_anchor(") {
                sites.push(
                    path.file_name()
                        .expect("named")
                        .to_string_lossy()
                        .into_owned(),
                );
            }
        }
    }
    sites.sort();
    assert!(
        visited > 20,
        "the scan visited only {visited} sources — it is not looking where it thinks"
    );
    assert_eq!(
        sites,
        vec![
            // `apply_upgrade` — the ONLY path that may record an upgrade
            // group (D97 R3, reaching the store directly per D99 R10).
            "anchors.rs".to_owned(),
            // The seal/resume anchor loop — the only path that may record a
            // fresh submission's artifacts.
            "resume.rs".to_owned(),
            // D47's import: reinstalls exported slots verbatim, authors none.
            "export.rs".to_owned(),
            // The `SealJournal::put_anchor` trait impl, forwarding to the
            // store. Plumbing, not a decision to write.
            "vault_journal.rs".to_owned(),
        ]
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>(),
        "an anchor slot is written from exactly these four places, of which \
         exactly TWO author anchor records: the seal/resume loop and \
         `pipeline::anchors::apply_upgrade`. A fifth site — or a third \
         authoring one — breaks D97's atomicity argument, because the group \
         can then outlive the artifact it was written with."
    );
}

// ─────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────

fn hex_dir(seal_id: &SealId) -> String {
    let mut out = String::with_capacity(32);
    for byte in seal_id.as_bytes() {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn walk(dir: &std::path::Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            out.extend(walk(&path));
        } else {
            out.push(path);
        }
    }
    out
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}
