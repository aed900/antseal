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

use antseal_cli::error::{CliError, ErrorClass};
use antseal_cli::pipeline::{
    BlobSlot, JournalError, MANIFEST_BLOB_ENTRY, NONCE_LEN, PLAN_ENTRY, STATE_ENTRY, SealJournal,
    SealPlan, SealState, StagedBlob, StagedBytesUnavailable, UNIT_ENTRY_BASE, VaultJournal,
    WorkIdentity, check_staged_integrity, verify_all_staged,
};
use antseal_cli::vault::kdf::KdfSelection;
use antseal_cli::vault::layout::VaultLayout;
use antseal_cli::vault::session::{UnlockedVault, create_vault, unlock_vault};
use antseal_cli::vault::store::{
    ConsentChannel, ConsentRecord, SealShapingFlags, WorkState, WorkStore,
};
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
            incomplete.contains(&(live, SealState::Anchored)),
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
