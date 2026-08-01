//! U9 acceptance suite: the per-work record store — versioned round trips
//! over the fixture state set, receipt-write durability across a reopen,
//! the D42 file-level splice matrix (the test U5 deferred), the journal
//! area API, and enumeration that never touches journal bodies.
//!
//! One Argon2id vault is created once (`OnceLock`); every test owns its
//! works by distinct fixture seal ids, so the suite pays the KDF once.
//!
//! NON-SECRET: every `W`, path, and amount here is a documented fixture.

use std::path::PathBuf;
use std::sync::OnceLock;

use antseal_cli::error::{CliError, ErrorClass};
use antseal_cli::vault::kdf::KdfSelection;
use antseal_cli::vault::layout::VaultLayout;
use antseal_cli::vault::session::{UnlockedVault, create_vault, unlock_vault};
use antseal_cli::vault::store::{
    ConsentChannel, ConsentRecord, SealShapingFlags, StoreError, WORK_RECORD_VERSION, WorkRecord,
    WorkState, WorkStore, utf8_paths,
};
use antseal_core::crypto::secrets::{MasterSecret, SealId, SecretBuf};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

// ─────────────────────────────────────────────────────────────────────
// Scaffolding
// ─────────────────────────────────────────────────────────────────────

const TEST_RNG_SEED: [u8; 32] = [0x42u8; 32];
const FIXTURE_PASSPHRASE: &[u8] = b"correct horse battery staple fixture";

fn passphrase() -> SecretBuf {
    SecretBuf::new(FIXTURE_PASSPHRASE.to_vec())
}

fn rng() -> ChaCha20Rng {
    ChaCha20Rng::from_seed(TEST_RNG_SEED)
}

struct SharedVault {
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
            "antseal-cli-store-shared-{}-{}",
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
    bytes[0] = 0xF0;
    bytes[1] = tag;
    SealId::from_bytes(bytes)
}

/// A representative record: consent + invocation identity + optional
/// fields populated per `state`.
fn fixture_record(tag: u8, state: WorkState, degraded: bool, unanchored: bool) -> WorkRecord {
    let paid = !matches!(state, WorkState::IncompletePrePay);
    WorkRecord {
        w: MasterSecret::from_bytes([tag; 32]),
        seal_id: fixture_seal_id(tag),
        network: "devnet".to_owned(),
        state,
        degraded,
        unanchored,
        input_paths_as_given: vec!["notes.md".to_owned(), "./sub/../essay.txt".to_owned()],
        input_paths_absolute: vec![
            "/home/fixture/notes.md".to_owned(),
            "/home/fixture/essay.txt".to_owned(),
        ],
        shaping: SealShapingFlags {
            title: Some("fixture title".to_owned()),
            split_blank_lines: true,
            force_text: false,
            no_fine_tree: vec!["*.bin".to_owned()],
            no_anchor: unanchored,
            force_degraded: degraded,
        },
        work_id: paid.then_some([0xAB; 32]),
        cost_atto: paid.then_some(1_234_567_890_123_456_789_012_345_678_u128),
        consent: paid.then_some(ConsentRecord {
            total_ant_atto: 1_234_567_890_123_456_789_012_345_678_u128,
            gas_estimate_wei: 21_000_000_000_000_u128,
            consent_time_unix_secs: 1_785_600_000,
            channel: ConsentChannel::Interactive,
        }),
    }
}

/// Field-wise equality (`WorkRecord` is deliberately not `PartialEq`:
/// `W` comparisons must be explicit).
fn assert_records_equal(a: &WorkRecord, b: &WorkRecord) {
    assert_eq!(a.w.secret_ref().as_bytes(), b.w.secret_ref().as_bytes());
    assert_eq!(a.seal_id, b.seal_id);
    assert_eq!(a.network, b.network);
    assert_eq!(a.state, b.state);
    assert_eq!(a.degraded, b.degraded);
    assert_eq!(a.unanchored, b.unanchored);
    assert_eq!(a.input_paths_as_given, b.input_paths_as_given);
    assert_eq!(a.input_paths_absolute, b.input_paths_absolute);
    assert_eq!(a.shaping, b.shaping);
    assert_eq!(a.work_id, b.work_id);
    assert_eq!(a.cost_atto, b.cost_atto);
    assert_eq!(a.consent, b.consent);
}

fn cli_class(err: StoreError) -> ErrorClass {
    CliError::from(err).class()
}

// ─────────────────────────────────────────────────────────────────────
// Versioned round trips over the fixture state set (U9 Accept)
// ─────────────────────────────────────────────────────────────────────

/// Every Accept-named work shape — complete, incomplete-pre-pay,
/// incomplete-post-pay, degraded, UNANCHORED — survives create → fresh
/// unlock → load, consent record and invocation identity included.
#[test]
fn fixture_states_round_trip_across_reopen() {
    let vault = shared_vault();
    let fixtures = [
        fixture_record(0x01, WorkState::Complete, false, false),
        fixture_record(0x02, WorkState::IncompletePrePay, false, false),
        fixture_record(0x03, WorkState::IncompletePostPay, false, false),
        fixture_record(0x04, WorkState::Complete, true, false), // degraded
        fixture_record(0x05, WorkState::Complete, false, true), // UNANCHORED
    ];
    {
        let unlocked = vault.unlock();
        let store = WorkStore::new(&unlocked);
        let mut rng = rng();
        for record in &fixtures {
            store.create_work(record, &mut rng).expect("create");
        }
    }
    // A fresh unlock — nothing may depend on in-memory state.
    let unlocked = vault.unlock();
    let store = WorkStore::new(&unlocked);
    for record in &fixtures {
        let loaded = store.load_meta(&record.seal_id).expect("load");
        assert_records_equal(record, &loaded);
    }
}

/// The incomplete → filled-in lifecycle: work_id, cost, and the D36
/// consent record land later via `store_meta`, and the update persists.
#[test]
fn meta_updates_persist() {
    let vault = shared_vault();
    let unlocked = vault.unlock();
    let store = WorkStore::new(&unlocked);
    let mut rng = rng();

    let mut record = fixture_record(0x06, WorkState::IncompletePrePay, false, false);
    record.work_id = None;
    record.cost_atto = None;
    record.consent = None;
    store.create_work(&record, &mut rng).expect("create");

    record.work_id = Some([0x66; 32]);
    record.cost_atto = Some(42);
    record.consent = Some(ConsentRecord {
        total_ant_atto: 42,
        gas_estimate_wei: 7,
        consent_time_unix_secs: 1_785_600_001,
        channel: ConsentChannel::YesFlag,
    });
    store.store_meta(&record, &mut rng).expect("update");

    let loaded = store.load_meta(&record.seal_id).expect("reload");
    assert_records_equal(&record, &loaded);
}

/// State transitions via the API, including the D43 reclassification:
/// `mark_complete` is a state-tag write — journal bytes untouched (same
/// file, same ciphertext), class derived from the tag.
#[test]
fn set_state_and_mark_complete_reclassify_without_touching_journal_bytes() {
    let vault = shared_vault();
    let unlocked = vault.unlock();
    let store = WorkStore::new(&unlocked);
    let mut rng = rng();

    let record = fixture_record(0x07, WorkState::IncompletePostPay, false, false);
    let id = record.seal_id;
    store.create_work(&record, &mut rng).expect("create");
    store
        .put_journal_entry(&id, 0, b"staged-bytes-fixture", &mut rng)
        .expect("journal");

    // Bytes on disk before and after the transition are identical.
    let dir = unlocked.layout().works_dir();
    let entry_path = std::fs::read_dir(&dir)
        .expect("read works dir")
        .filter_map(Result::ok)
        .map(|e| e.path())
        .find(|p| {
            p.file_name()
                .is_some_and(|n| n.to_string_lossy().starts_with("f007"))
        })
        .expect("work dir exists")
        .join("journal")
        .join("0");
    let before = std::fs::read(&entry_path).expect("journal bytes before");

    store.mark_complete(&id, &mut rng).expect("mark complete");

    let after = std::fs::read(&entry_path).expect("journal bytes after");
    assert_eq!(
        before, after,
        "D43: reclassification is a tag write, same bytes"
    );
    let loaded = store.load_meta(&id).expect("reload");
    assert_eq!(loaded.state, WorkState::Complete);

    // And the tag is what D43's contracts key on: journal-class before,
    // cache-class after (the split itself is enforced by U12's export and
    // R16's readers — the store carries the tag).
    store
        .set_state(&id, WorkState::IncompletePostPay, &mut rng)
        .expect("state can move under S10's machine");
}

// ─────────────────────────────────────────────────────────────────────
// Receipt durability (U9 Accept — feeds S's no-double-pay E2E)
// ─────────────────────────────────────────────────────────────────────

/// The receipt write API returns ⇒ the receipt is durable: a fresh
/// process image (simulated by dropping every handle and re-unlocking
/// from disk) reads it back byte-identically. The torn-write windows
/// below the API are covered by the U5 kill matrix on `atomic_write`,
/// which this write is one call to.
#[test]
fn receipt_survives_reopen_byte_identically() {
    let vault = shared_vault();
    let receipt_fixture: Vec<u8> = (0u8..=255).cycle().take(4096).collect();
    let id = fixture_seal_id(0x08);
    {
        let unlocked = vault.unlock();
        let store = WorkStore::new(&unlocked);
        let mut rng = rng();
        let record = fixture_record(0x08, WorkState::IncompletePrePay, false, false);
        store.create_work(&record, &mut rng).expect("create");
        assert!(store.get_receipt(&id).expect("no receipt yet").is_none());
        store
            .put_receipt(&id, &receipt_fixture, &mut rng)
            .expect("journal the receipt");
        // Everything dropped here: handles, keys, store.
    }
    let unlocked = vault.unlock();
    let store = WorkStore::new(&unlocked);
    let read_back = store
        .get_receipt(&id)
        .expect("read receipt")
        .expect("receipt present after reopen");
    assert_eq!(read_back.as_bytes(), receipt_fixture.as_slice());
}

// ─────────────────────────────────────────────────────────────────────
// The D42 splice matrix, file level (the test U5 deferred to U9)
// ─────────────────────────────────────────────────────────────────────

/// Swapping two works' encrypted record files — meta ↔ meta, a journal
/// entry across works, a journal entry across entry keys, a receipt into
/// a meta slot, an anchor across slots — always fails authentication.
#[test]
fn spliced_record_files_fail_authentication() {
    let vault = shared_vault();
    let unlocked = vault.unlock();
    let store = WorkStore::new(&unlocked);
    let mut rng = rng();

    let a = fixture_record(0x0A, WorkState::IncompletePostPay, false, false);
    let b = fixture_record(0x0B, WorkState::IncompletePostPay, false, false);
    let (id_a, id_b) = (a.seal_id, b.seal_id);
    store.create_work(&a, &mut rng).expect("create A");
    store.create_work(&b, &mut rng).expect("create B");
    store
        .put_journal_entry(&id_a, 0, b"A staged unit 0", &mut rng)
        .expect("A journal 0");
    store
        .put_journal_entry(&id_b, 0, b"B staged unit 0", &mut rng)
        .expect("B journal 0");
    store
        .put_receipt(&id_a, b"A receipt bytes", &mut rng)
        .expect("A receipt");
    store
        .put_anchor(&id_a, "ots-pending", b"A ots bytes", &mut rng)
        .expect("A anchor");

    let dir_of = |tag: &str| {
        std::fs::read_dir(unlocked.layout().works_dir())
            .expect("read works dir")
            .filter_map(Result::ok)
            .map(|e| e.path())
            .find(|p| {
                p.file_name()
                    .is_some_and(|n| n.to_string_lossy().starts_with(tag))
            })
            .expect("work dir")
    };
    let dir_a = dir_of("f00a");
    let dir_b = dir_of("f00b");

    // Meta of B into A's slot.
    std::fs::copy(dir_b.join("meta"), dir_a.join("meta")).expect("splice meta");
    assert_eq!(
        cli_class(store.load_meta(&id_a).expect_err("spliced meta")),
        ErrorClass::VaultAuthFailure
    );
    // Repair A's meta for the rest of the matrix.
    store.store_meta(&a, &mut rng).expect("repair A meta");

    // Journal entry across works: B/journal/0 into A/journal/0.
    std::fs::copy(dir_b.join("journal/0"), dir_a.join("journal/0")).expect("splice journal");
    assert_eq!(
        cli_class(
            store
                .get_journal_entry(&id_a, 0)
                .expect_err("cross-work journal splice")
        ),
        ErrorClass::VaultAuthFailure
    );

    // Journal entry across entry keys: B/journal/0 as B/journal/1.
    std::fs::copy(dir_b.join("journal/0"), dir_b.join("journal/1")).expect("splice entry key");
    assert_eq!(
        cli_class(
            store
                .get_journal_entry(&id_b, 1)
                .expect_err("cross-entry splice")
        ),
        ErrorClass::VaultAuthFailure
    );
    // The un-spliced original still opens (the matrix is falsifiable).
    assert_eq!(
        store
            .get_journal_entry(&id_b, 0)
            .expect("intact entry")
            .expect("present")
            .as_bytes(),
        b"B staged unit 0"
    );

    // Record-class confusion: A's receipt into A's meta slot.
    std::fs::copy(dir_a.join("receipt"), dir_a.join("meta")).expect("splice class");
    assert_eq!(
        cli_class(store.load_meta(&id_a).expect_err("class splice")),
        ErrorClass::VaultAuthFailure
    );
    store.store_meta(&a, &mut rng).expect("repair A meta again");

    // Anchor across slots: ots-pending as tsa-0.
    std::fs::copy(
        dir_a.join("anchors/ots-pending"),
        dir_a.join("anchors/tsa-0"),
    )
    .expect("splice anchor slot");
    assert_eq!(
        cli_class(
            store
                .get_anchor(&id_a, "tsa-0")
                .expect_err("anchor slot splice")
        ),
        ErrorClass::VaultAuthFailure
    );
    assert_eq!(
        store
            .get_anchor(&id_a, "ots-pending")
            .expect("intact anchor")
            .expect("present")
            .as_bytes(),
        b"A ots bytes"
    );
}

// ─────────────────────────────────────────────────────────────────────
// Journal area API + enumeration discipline
// ─────────────────────────────────────────────────────────────────────

/// put/get/list/delete over the journal area; list is canonical-decimal
/// strict and skips inert temp residue.
#[test]
fn journal_area_put_get_list_delete() {
    let vault = shared_vault();
    let unlocked = vault.unlock();
    let store = WorkStore::new(&unlocked);
    let mut rng = rng();

    let record = fixture_record(0x0C, WorkState::IncompletePrePay, false, false);
    let id = record.seal_id;
    store.create_work(&record, &mut rng).expect("create");

    for entry in [3u64, 0, 12] {
        store
            .put_journal_entry(&id, entry, format!("unit-{entry}").as_bytes(), &mut rng)
            .expect("put");
    }
    assert_eq!(
        store.list_journal_entries(&id).expect("list"),
        vec![0, 3, 12]
    );
    assert_eq!(
        store
            .get_journal_entry(&id, 3)
            .expect("get")
            .expect("present")
            .as_bytes(),
        b"unit-3"
    );
    assert!(
        store
            .get_journal_entry(&id, 99)
            .expect("absent is None")
            .is_none()
    );

    // Overwrite is a fresh nonce, same slot (resume re-writes are legal).
    store
        .put_journal_entry(&id, 0, b"unit-0-rewritten", &mut rng)
        .expect("overwrite");
    assert_eq!(
        store
            .get_journal_entry(&id, 0)
            .expect("get")
            .expect("present")
            .as_bytes(),
        b"unit-0-rewritten"
    );

    assert!(store.delete_journal_entry(&id, 3).expect("delete"));
    assert!(!store.delete_journal_entry(&id, 3).expect("idempotent"));
    assert_eq!(store.list_journal_entries(&id).expect("list"), vec![0, 12]);

    // Inert temp residue (the fs.rs dotfile shape) is skipped…
    let journal_dir = std::fs::read_dir(unlocked.layout().works_dir())
        .expect("read works dir")
        .filter_map(Result::ok)
        .map(|e| e.path())
        .find(|p| {
            p.file_name()
                .is_some_and(|n| n.to_string_lossy().starts_with("f00c"))
        })
        .expect("work dir")
        .join("journal");
    std::fs::write(journal_dir.join(".0.tmp.999.1"), b"residue").expect("plant residue");
    assert_eq!(store.list_journal_entries(&id).expect("list"), vec![0, 12]);

    // …but a non-canonical name is loud, never silently skipped
    // ("007" would alias entry 7 onto a second file).
    std::fs::write(journal_dir.join("007"), b"alias").expect("plant alias");
    let err = store.list_journal_entries(&id).expect_err("alien entry");
    assert!(matches!(err, StoreError::AlienEntry { .. }), "{err:?}");
    assert_eq!(cli_class(err), ErrorClass::VaultAuthFailure);
}

/// Enumeration reads no record bodies: every journal entry and receipt
/// of every work can be flipped to garbage on disk and `list_works` +
/// `load_meta` still answer — the list/status path never decrypts
/// content-scale bytes (U9 Accept: enumerable without decrypting all
/// bodies).
#[test]
fn enumeration_never_touches_journal_bodies() {
    let vault = shared_vault();
    let unlocked = vault.unlock();
    let store = WorkStore::new(&unlocked);
    let mut rng = rng();

    let record = fixture_record(0x0D, WorkState::IncompletePostPay, false, false);
    let id = record.seal_id;
    store.create_work(&record, &mut rng).expect("create");
    store
        .put_journal_entry(&id, 0, b"content-scale staged bytes", &mut rng)
        .expect("journal");
    store
        .put_receipt(&id, b"receipt bytes", &mut rng)
        .expect("receipt");

    // Corrupt the content-scale records on disk.
    let work_dir = std::fs::read_dir(unlocked.layout().works_dir())
        .expect("read works dir")
        .filter_map(Result::ok)
        .map(|e| e.path())
        .find(|p| {
            p.file_name()
                .is_some_and(|n| n.to_string_lossy().starts_with("f00d"))
        })
        .expect("work dir");
    std::fs::write(work_dir.join("journal/0"), b"garbage").expect("corrupt journal");
    std::fs::write(work_dir.join("receipt"), b"garbage").expect("corrupt receipt");

    // Enumeration and meta reads are untouched.
    let ids = store.list_works().expect("list");
    assert!(ids.contains(&id));
    let loaded = store.load_meta(&id).expect("meta decrypts fine");
    assert_eq!(loaded.state, WorkState::IncompletePostPay);

    // Reading the corrupted bodies IS loud — corruption is detected
    // exactly where the bytes are used.
    assert_eq!(
        cli_class(
            store
                .get_journal_entry(&id, 0)
                .expect_err("corrupt journal")
        ),
        ErrorClass::VaultAuthFailure
    );
}

// ─────────────────────────────────────────────────────────────────────
// Edges: unknown works, double create, future versions, alien entries
// ─────────────────────────────────────────────────────────────────────

#[test]
fn unknown_work_and_double_create_are_typed() {
    let vault = shared_vault();
    let unlocked = vault.unlock();
    let store = WorkStore::new(&unlocked);
    let mut rng = rng();

    let ghost = fixture_seal_id(0xE0);
    let err = store.load_meta(&ghost).expect_err("unknown work");
    assert!(matches!(err, StoreError::WorkNotFound));
    assert_eq!(cli_class(err), ErrorClass::Usage);
    assert!(matches!(
        store.put_journal_entry(&ghost, 0, b"x", &mut rng),
        Err(StoreError::WorkNotFound)
    ));
    assert!(matches!(
        store.put_receipt(&ghost, b"x", &mut rng),
        Err(StoreError::WorkNotFound)
    ));

    let record = fixture_record(0x0E, WorkState::IncompletePrePay, false, false);
    store.create_work(&record, &mut rng).expect("create");
    let again = fixture_record(0x0E, WorkState::IncompletePrePay, false, false);
    let err = store
        .create_work(&again, &mut rng)
        .expect_err("double create");
    assert!(matches!(err, StoreError::AlreadyExists));
    assert_eq!(cli_class(err), ErrorClass::Internal);
}

/// A meta record written by a newer schema version is refused distinctly
/// (its body is never parsed), mapping to the vault-newer-version class.
#[test]
fn future_meta_version_is_refused_distinctly() {
    use antseal_cli::vault::cipher::RecordIdentity;
    use antseal_core::codec::encode_item;

    let vault = shared_vault();
    let unlocked = vault.unlock();
    let store = WorkStore::new(&unlocked);
    let mut rng = rng();

    let record = fixture_record(0x0F, WorkState::IncompletePrePay, false, false);
    let id = record.seal_id;
    store.create_work(&record, &mut rng).expect("create");

    // Craft a valid AEAD blob for this slot whose plaintext claims
    // schema version WORK_RECORD_VERSION + 1.
    let future = encode_item(|e| {
        e.array(|a| {
            a.item(|e| e.u64(u64::from(WORK_RECORD_VERSION) + 1))?;
            a.item(|e| e.bytes(b"opaque future body"))
        })
    })
    .expect("craft future record");
    let blob = unlocked
        .seal_record(RecordIdentity::WorkMeta { seal_id: &id }, &future, &mut rng)
        .expect("seal future record");
    let work_dir = std::fs::read_dir(unlocked.layout().works_dir())
        .expect("read works dir")
        .filter_map(Result::ok)
        .map(|e| e.path())
        .find(|p| {
            p.file_name()
                .is_some_and(|n| n.to_string_lossy().starts_with("f00f"))
        })
        .expect("work dir");
    antseal_cli::vault::fs::atomic_write(&work_dir.join("meta"), &blob).expect("install");

    let err = store.load_meta(&id).expect_err("future version");
    assert!(matches!(err, StoreError::NewerRecord { found } if found == 2));
    assert_eq!(cli_class(err), ErrorClass::VaultNewerVersion);
}

/// An alien file in the works directory is loud (a corrupted or
/// hand-edited store must never be silently skipped over). Owns a
/// private vault: planting the alien in the shared one would race the
/// parallel tests' enumerations.
#[test]
fn alien_entries_in_the_works_dir_are_loud() {
    let root = std::env::temp_dir().join(format!(
        "antseal-cli-store-alien-{}-{}",
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
    let store = WorkStore::new(&unlocked);

    let alien = unlocked.layout().works_dir().join("not-a-work");
    std::fs::write(&alien, b"alien").expect("plant alien");
    let err = store.list_works().expect_err("alien entry");
    assert!(matches!(err, StoreError::AlienEntry { .. }));
    let _ = std::fs::remove_dir_all(&root);
}

/// Non-UTF-8 paths are refused at record-construction time with the D46
/// invalid-argument class (recorded v1 limitation).
#[cfg(unix)]
#[test]
fn non_utf8_paths_are_refused() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    let good = PathBuf::from("/home/fixture/notes.md");
    let bad = PathBuf::from(OsString::from_vec(vec![0x2F, 0xFF, 0xFE]));
    let err = utf8_paths(&[good.clone(), bad]).expect_err("non-UTF-8");
    assert!(matches!(err, StoreError::NonUtf8Path));
    assert_eq!(cli_class(err), ErrorClass::InvalidSealArgument);
    assert_eq!(
        utf8_paths(&[good]).expect("utf8 ok"),
        vec!["/home/fixture/notes.md".to_owned()]
    );
}

/// Golden vector for the v1 meta-record plaintext encoding (house rule:
/// every new versioned format pins exact bytes). The fixture is the
/// fully-populated `Complete` record — every field present, both
/// sub-maps, all optionals. Byte drift here is a vault-format break:
/// existing vaults would stop decoding.
#[test]
fn meta_record_golden_vector() {
    let record = fixture_record(0x01, WorkState::Complete, false, false);
    let encoded = record.encode().expect("encode");
    let hex: String = encoded.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(hex, META_GOLDEN_HEX, "v1 meta-record golden vector drifted");
    // And the golden bytes decode back to the fixture (both directions).
    let decoded = WorkRecord::decode(&encoded).expect("decode");
    assert_records_equal(&record, &decoded);
}

/// The pinned v1 encoding of `fixture_record(0x01, Complete, false,
/// false)` (regenerate deliberately by reading the test failure output
/// after a REVIEWED schema change — never silently). Layout: envelope
/// `[1, body]`; body map keys 0..=11 — W(32) · seal_id(16) · "devnet" ·
/// state 3 · flags 0/0 · both path lists · shaping sub-map · work_id(32)
/// · cost bstr16 · consent sub-map.
const META_GOLDEN_HEX: &str = "8201590117ac0058200101010101010101010101010101010101010101010101\
                               0101010101010101010150f00101010101010101010101010101010246646576\
                               6e65740303040005000682486e6f7465732e6d64522e2f7375622f2e2e2f6573\
                               7361792e7478740782562f686f6d652f666978747572652f6e6f7465732e6d64\
                               572f686f6d652f666978747572652f65737361792e74787408a6004d66697874\
                               757265207469746c65010102000381452a2e62696e04000500095820abababab\
                               abababababababababababababababababababababababababababab0a500000\
                               000003fd35eb6d797a91be38f34e0ba400500000000003fd35eb6d797a91be38\
                               f34e0150000000000000000000001319718a5000021a6a6e18000300";

/// Suite-level cleanup marker: the shared vault directory is temp-space;
/// leak tolerance is the same as the other suites (best-effort OS temp
/// cleanup). This "test" exists to document that choice loudly.
#[test]
fn zz_shared_vault_lives_in_temp_space() {
    let vault = shared_vault();
    assert!(vault.root.starts_with(std::env::temp_dir()));
}
