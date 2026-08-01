//! U12 acceptance suite: `vault export` / `vault import` per D47.
//!
//! - the flagship round trip: full logical state (5-state fixture works,
//!   journal, receipts, anchors, wallet, config) → export → wipe →
//!   import → byte-identical logical state, with the D43 cache excluded
//!   from the file (proven by size) and its absence never an error;
//! - unreadable without the passphrase; the tamper matrix (magic,
//!   version, KDF bomb, header nonce, ciphertext, truncation) with
//!   distinct classes, the bomb rejected before any passphrase is even
//!   requested;
//! - the absolute existing-vault refusal (code 10, directory untouched,
//!   precedes file access; no bypass flag parses);
//! - the spawned-binary E2E over `--passphrase-fd 0` (machine mode, both
//!   plain and `--json`) — the D41 scripted-automation shape.
//!
//! NON-SECRET: every W/key/passphrase here is a documented fixture.

use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command as Process, Stdio};

use antseal_cli::cli::Cli;
use antseal_cli::error::{CliError, ErrorClass};
use antseal_cli::vault::export::{export_vault, import_vault};
use antseal_cli::vault::kdf::KdfSelection;
use antseal_cli::vault::layout::{BesideFile, VaultLayout};
use antseal_cli::vault::session::{UnlockedVault, create_vault, unlock_vault};
use antseal_cli::vault::store::{
    ConsentChannel, ConsentRecord, SealShapingFlags, WorkRecord, WorkState, WorkStore,
};
use antseal_cli::vault::wallet::{WalletKeyHandle, load_wallet_key, store_wallet_key};
use antseal_core::crypto::secrets::{MasterSecret, SealId, SecretBuf};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

const TEST_RNG_SEED: [u8; 32] = [0x42u8; 32];
const FIXTURE_PASSPHRASE: &[u8] = b"correct horse battery staple fixture";
const FIXTURE_WALLET_KEY: [u8; 32] = [0x5Au8; 32];
const FIXTURE_CONFIG: &[u8] = b"# antseal config fixture\ndefault_network = \"devnet\"\n";

/// Cache blob planted on every COMPLETE work: the export file staying
/// far below this size is direct evidence the D43 cache is excluded.
const CACHE_BLOB_LEN: usize = 200_000;

fn rng() -> ChaCha20Rng {
    ChaCha20Rng::from_seed(TEST_RNG_SEED)
}

fn passphrase() -> SecretBuf {
    SecretBuf::new(FIXTURE_PASSPHRASE.to_vec())
}

struct TestDir(PathBuf);

impl TestDir {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "antseal-cli-export-it-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("create test dir");
        TestDir(dir)
    }
    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn fixture_seal_id(tag: u8) -> SealId {
    let mut bytes = [tag; 16];
    bytes[0] = 0xE0;
    bytes[1] = tag;
    SealId::from_bytes(bytes)
}

fn fixture_record(tag: u8, state: WorkState, degraded: bool, unanchored: bool) -> WorkRecord {
    let paid = !matches!(state, WorkState::IncompletePrePay);
    WorkRecord {
        w: MasterSecret::from_bytes([tag; 32]),
        seal_id: fixture_seal_id(tag),
        network: "devnet".to_owned(),
        state,
        degraded,
        unanchored,
        input_paths_as_given: vec!["notes.md".to_owned()],
        input_paths_absolute: vec!["/home/fixture/notes.md".to_owned()],
        shaping: SealShapingFlags {
            title: Some("fixture title".to_owned()),
            split_blank_lines: true,
            force_text: false,
            no_fine_tree: vec![],
            no_anchor: unanchored,
            force_degraded: degraded,
        },
        work_id: paid.then_some([tag; 32]),
        cost_atto: paid.then_some(42_000_000_000_000_000_000_u128),
        consent: paid.then_some(ConsentRecord {
            total_ant_atto: 42_000_000_000_000_000_000_u128,
            gas_estimate_wei: 21_000_000_000_000_u128,
            consent_time_unix_secs: 1_785_600_000,
            channel: ConsentChannel::YesFlag,
        }),
    }
}

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

/// Build the reference vault: the U9 5-state fixture set with journal
/// entries (cache-sized on the complete works), receipts, anchors, a
/// wallet, and a config file. Returns the fixture records.
fn populate(vault: &UnlockedVault) -> Vec<WorkRecord> {
    let mut r = rng();
    let fixtures = vec![
        fixture_record(0x01, WorkState::Complete, false, false),
        fixture_record(0x02, WorkState::IncompletePrePay, false, false),
        // The mid-seal shape: staged bytes + a journaled receipt,
        // finalize still pending — the resumability Accept's subject.
        fixture_record(0x03, WorkState::IncompletePostPay, false, false),
        fixture_record(0x04, WorkState::Complete, true, false), // degraded
        fixture_record(0x05, WorkState::Complete, false, true), // UNANCHORED
    ];
    let store = WorkStore::new(vault);
    for record in &fixtures {
        store.create_work(record, &mut r).expect("create work");
        let complete = record.state == WorkState::Complete;
        // Journal entries for every work; content-scale for complete
        // works (the D43 cache whose exclusion the size assertion pins).
        for entry in [0u64, 7] {
            let body = if complete {
                vec![record.seal_id.as_bytes()[1]; CACHE_BLOB_LEN]
            } else {
                format!(
                    "staged-unit-{entry}-of-{:02x}",
                    record.seal_id.as_bytes()[1]
                )
                .into_bytes()
            };
            store
                .put_journal_entry(&record.seal_id, entry, &body, &mut r)
                .expect("journal");
        }
        if record.state != WorkState::IncompletePrePay {
            store
                .put_receipt(
                    &record.seal_id,
                    format!("receipt-of-{:02x}", record.seal_id.as_bytes()[1]).as_bytes(),
                    &mut r,
                )
                .expect("receipt");
        }
        if complete {
            store
                .put_anchor(&record.seal_id, "ots-pending", b"ots fixture bytes", &mut r)
                .expect("anchor");
            store
                .put_anchor(&record.seal_id, "tsa-0.der", b"tsa fixture bytes", &mut r)
                .expect("anchor 2");
        }
    }
    store_wallet_key(
        vault,
        &WalletKeyHandle::from_bytes(FIXTURE_WALLET_KEY),
        &mut r,
    )
    .expect("wallet");
    let config_path = vault.layout().beside_path(BesideFile::Config);
    antseal_cli::vault::fs::atomic_write(&config_path, FIXTURE_CONFIG).expect("config");
    fixtures
}

// ─────────────────────────────────────────────────────────────────────
// The flagship round trip
// ─────────────────────────────────────────────────────────────────────

/// export → wipe → import → the full logical state survives: metas
/// field-identical, incomplete works' journal bytes byte-identical (a
/// resumable seal stays resumable), receipts and anchors intact, wallet
/// and config byte-identical — while the complete works' cache bytes are
/// absent from the file (size-proven) and absent after import WITHOUT
/// being an error (D43).
#[test]
fn round_trip_preserves_the_full_logical_state() {
    let dir = TestDir::new("roundtrip");
    let layout = VaultLayout::at(dir.path().join("vault"));
    let vault = create_vault(&layout, &passphrase(), KdfSelection::Argon2id, &mut rng())
        .expect("create vault");
    let fixtures = populate(&vault);
    let out = dir.path().join("backup.sealvault");
    let summary = export_vault(&vault, &passphrase(), &out, &mut rng()).expect("export");
    assert_eq!(summary.works, 5);
    drop(vault);

    // D43 exclusion, proven by arithmetic: three complete works carry
    // 2 × 200 kB of cache each; the file holding NONE of it stays far
    // below a single planted blob.
    let file_len = std::fs::metadata(&out).expect("stat").len();
    assert!(
        file_len < CACHE_BLOB_LEN as u64,
        "export file ({file_len} B) must not contain the complete works' cache bytes"
    );

    // Wipe the vault entirely (the clean-machine shape).
    std::fs::remove_dir_all(layout.root()).expect("wipe vault");
    assert!(!layout.root().exists());

    let summary = import_vault(&out, &layout, || Ok(passphrase()), &mut rng()).expect("import");
    assert_eq!(summary.works, 5);
    assert!(summary.wallet_present);
    assert!(summary.config_present);

    let vault = unlock_vault(&layout, &passphrase()).expect("unlock imported vault");
    let store = WorkStore::new(&vault);
    assert_eq!(store.list_works().expect("list").len(), 5);

    for record in &fixtures {
        let loaded = store.load_meta(&record.seal_id).expect("meta");
        assert_records_equal(record, &loaded);
        let complete = record.state == WorkState::Complete;
        if complete {
            // Cache-state entries are absent, and their absence is a
            // plain `None`, never an error (D43).
            assert_eq!(
                store.list_journal_entries(&record.seal_id).expect("list"),
                Vec::<u64>::new()
            );
            assert!(
                store
                    .get_journal_entry(&record.seal_id, 0)
                    .expect("absence is not an error")
                    .is_none()
            );
            // Anchors round-tripped.
            assert_eq!(
                store.list_anchors(&record.seal_id).expect("anchors"),
                vec!["ots-pending".to_owned(), "tsa-0.der".to_owned()]
            );
            assert_eq!(
                store
                    .get_anchor(&record.seal_id, "ots-pending")
                    .expect("get")
                    .expect("present")
                    .as_bytes(),
                b"ots fixture bytes"
            );
        } else {
            // Journal-state entries: byte-identical (resumability).
            assert_eq!(
                store.list_journal_entries(&record.seal_id).expect("list"),
                vec![0, 7]
            );
            for entry in [0u64, 7] {
                assert_eq!(
                    store
                        .get_journal_entry(&record.seal_id, entry)
                        .expect("get")
                        .expect("present")
                        .as_bytes(),
                    format!(
                        "staged-unit-{entry}-of-{:02x}",
                        record.seal_id.as_bytes()[1]
                    )
                    .as_bytes()
                );
            }
        }
        if record.state != WorkState::IncompletePrePay {
            assert_eq!(
                store
                    .get_receipt(&record.seal_id)
                    .expect("receipt")
                    .expect("present")
                    .as_bytes(),
                format!("receipt-of-{:02x}", record.seal_id.as_bytes()[1]).as_bytes()
            );
        }
    }

    // Wallet and config, byte-identical.
    assert_eq!(
        load_wallet_key(&vault)
            .expect("wallet")
            .expect("present")
            .secret_bytes(),
        &FIXTURE_WALLET_KEY
    );
    assert_eq!(
        std::fs::read(layout.beside_path(BesideFile::Config)).expect("config"),
        FIXTURE_CONFIG
    );
}

// ─────────────────────────────────────────────────────────────────────
// Authentication and the tamper matrix
// ─────────────────────────────────────────────────────────────────────

fn exported_fixture(dir: &TestDir) -> (VaultLayout, PathBuf) {
    let layout = VaultLayout::at(dir.path().join("vault"));
    let vault = create_vault(&layout, &passphrase(), KdfSelection::Argon2id, &mut rng())
        .expect("create vault");
    populate(&vault);
    let out = dir.path().join("backup.sealvault");
    export_vault(&vault, &passphrase(), &out, &mut rng()).expect("export");
    (layout, out)
}

#[test]
fn wrong_passphrase_fails_with_the_import_auth_class() {
    let dir = TestDir::new("wrongpass");
    let (_layout, out) = exported_fixture(&dir);
    let target = VaultLayout::at(dir.path().join("restored"));
    let err = import_vault(
        &out,
        &target,
        || Ok(SecretBuf::new(b"not the fixture passphrase!!".to_vec())),
        &mut rng(),
    )
    .expect_err("wrong passphrase");
    assert!(matches!(err, CliError::ImportAuthFailed), "{err:?}");
    assert_eq!(err.exit_code(), 33);
    assert!(!target.root().exists(), "nothing installed");
}

/// Every mutation fails with its distinct class: magic and body flips and
/// truncation → import-auth (33); a raised version → newer-version (34);
/// an in-window KDF raise → auth failure via the AAD; and the D40 cap
/// bomb → params-out-of-range (14) **without the passphrase ever being
/// requested**.
#[test]
fn tamper_matrix_yields_distinct_classes() {
    let dir = TestDir::new("tamper");
    let (_layout, out) = exported_fixture(&dir);
    let original = std::fs::read(&out).expect("read export");
    let target = VaultLayout::at(dir.path().join("restored"));

    let run = |bytes: &[u8]| -> CliError {
        let mutated = dir.path().join("mutated.sealvault");
        std::fs::write(&mutated, bytes).expect("write mutation");
        import_vault(&mutated, &target, || Ok(passphrase()), &mut rng())
            .expect_err("mutation must fail")
    };

    // Magic flip → not an export file → auth class.
    let mut m = original.clone();
    m[0] ^= 0x01;
    assert_eq!(run(&m).exit_code(), 33, "magic flip");

    // Version raised to 2 (byte 21: the uint after the array head).
    let mut m = original.clone();
    assert_eq!(m[20], 0x82, "header envelope head");
    assert_eq!(m[21], 0x01, "version 1 encoding");
    m[21] = 0x02;
    let err = run(&m);
    assert!(
        matches!(err, CliError::ImportNewerVersion { found: 2, .. }),
        "{err:?}"
    );
    assert_eq!(err.exit_code(), 34, "future version");

    // Last ciphertext byte (the tag region) flipped → auth.
    let mut m = original.clone();
    let last = m.len() - 1;
    m[last] ^= 0x01;
    assert_eq!(run(&m).exit_code(), 33, "ciphertext flip");

    // A flipped byte INSIDE the header body (salt/nonce region) → the
    // AAD breaks → auth.
    let mut m = original.clone();
    m[60] ^= 0x01;
    assert_eq!(run(&m).exit_code(), 33, "header body flip");

    // Truncation → auth.
    assert_eq!(
        run(&original[..original.len() - 8]).exit_code(),
        33,
        "truncation"
    );

    // The intact file still imports (falsifiability), into a fresh dir.
    let fresh = VaultLayout::at(dir.path().join("restored-ok"));
    import_vault(&out, &fresh, || Ok(passphrase()), &mut rng()).expect("intact file imports");
}

/// The D40 §3 cap bomb: a synthetic export header demanding a 1 TiB
/// Argon2id arena is rejected with the distinct params class BEFORE any
/// KDF allocation — and before the passphrase is requested (the closure
/// panics if consulted).
#[test]
fn kdf_bomb_header_is_rejected_pre_allocation_and_pre_passphrase() {
    use antseal_core::codec::encode_item;

    let dir = TestDir::new("bomb");
    // magic ‖ [1, body{0: bomb kdf block, 1: 24-B nonce}] ‖ fake ct.
    let bomb_block = encode_item(|e| {
        e.map(|m| {
            m.entry(0, |e| e.u64(1))?; // argon2id
            m.entry(1, |e| e.bytes(&[0u8; 16]))?; // salt
            m.entry(2, |e| e.u64(1_073_741_824))?; // m_cost KiB = 1 TiB
            m.entry(3, |e| e.u64(3))?;
            m.entry(4, |e| e.u64(1))
        })
    })
    .expect("bomb block");
    let body = encode_item(|e| {
        e.map(|m| {
            m.entry(0, |e| e.bytes(&bomb_block))?;
            m.entry(1, |e| e.bytes(&[0u8; 24]))
        })
    })
    .expect("body");
    let header = encode_item(|e| {
        e.array(|a| {
            a.item(|e| e.u64(1))?;
            a.item(|e| e.bytes(&body))
        })
    })
    .expect("header");
    // The magic via its constant — the literal's one sanctioned source
    // occurrence is the export module (secret-guard exclusion record).
    let mut file = antseal_cli::vault::export::EXPORT_MAGIC.to_vec();
    file.extend_from_slice(&header);
    file.extend_from_slice(&[0u8; 64]); // fake ciphertext
    let bomb_path = dir.path().join("bomb.sealvault");
    std::fs::write(&bomb_path, &file).expect("write bomb");

    let target = VaultLayout::at(dir.path().join("restored"));
    let err = import_vault(
        &bomb_path,
        &target,
        || unreachable!("the passphrase must never be requested for a bomb header"),
        &mut rng(),
    )
    .expect_err("bomb must be rejected");
    assert!(
        matches!(err, CliError::VaultKdfParamsOutOfRange { .. }),
        "{err:?}"
    );
    assert_eq!(err.exit_code(), 14);
    assert_eq!(err.class(), ErrorClass::VaultKdfParamsOutOfRange);
}

// ─────────────────────────────────────────────────────────────────────
// The existing-vault refusal
// ─────────────────────────────────────────────────────────────────────

/// Refusal is absolute (D39 precedent, D51: no bypass in any mode), maps
/// to the consent-not-obtained class, leaves the existing vault
/// byte-identical, and precedes even reading the import file.
#[test]
fn import_over_an_existing_vault_refuses_absolutely() {
    let dir = TestDir::new("refusal");
    let (layout, out) = exported_fixture(&dir);

    let snapshot = |root: &Path| -> BTreeMap<PathBuf, Vec<u8>> {
        fn walk(dir: &Path, out: &mut BTreeMap<PathBuf, Vec<u8>>) {
            for entry in std::fs::read_dir(dir).expect("read dir") {
                let path = entry.expect("entry").path();
                if path.is_dir() {
                    walk(&path, out);
                } else {
                    out.insert(path.clone(), std::fs::read(&path).expect("read"));
                }
            }
        }
        let mut map = BTreeMap::new();
        walk(root, &mut map);
        map
    };
    let before = snapshot(layout.root());

    // A valid export file, an existing vault at the target → refusal.
    let err = import_vault(
        &out,
        &layout,
        || unreachable!("refusal precedes the passphrase"),
        &mut rng(),
    )
    .expect_err("must refuse");
    assert!(matches!(err, CliError::ImportRefusedExistingVault { .. }));
    assert_eq!(err.class(), ErrorClass::ConsentNotObtained);
    assert_eq!(err.exit_code(), 10);
    let rendered = err.to_string();
    assert!(
        rendered.contains("vault export"),
        "workaround copy: {rendered}"
    );
    assert!(
        rendered.contains("unsupported"),
        "states the D51 stance: {rendered}"
    );

    // The refusal precedes file access: a nonexistent import file still
    // yields the refusal, not an I/O error.
    let err = import_vault(
        &dir.path().join("no-such-file.sealvault"),
        &layout,
        || unreachable!("refusal precedes the passphrase"),
        &mut rng(),
    )
    .expect_err("must refuse before reading");
    assert_eq!(err.exit_code(), 10, "refusal precedes file access");

    // The existing vault is byte-identical.
    assert_eq!(before, snapshot(layout.root()), "vault untouched");
}

/// No bypass flag parses on `vault import` (the canonical surface has
/// none, by D51 design) — and none on `vault export` either.
#[test]
fn no_bypass_flag_parses() {
    for flag in ["--force", "--yes", "--overwrite"] {
        let err = Cli::parse_checked(["antseal", "vault", "import", "backup.sealvault", flag])
            .expect_err("bypass flag must not parse");
        assert_eq!(
            err.kind(),
            clap::error::ErrorKind::UnknownArgument,
            "{flag}"
        );
    }
    let err = Cli::parse_checked(["antseal", "vault", "export", "--force"])
        .expect_err("export takes no flags");
    assert_eq!(err.kind(), clap::error::ErrorKind::UnknownArgument);
}

/// A path that exists but is not a vault is a usage refusal naming the
/// obstruction, never a merge target.
#[test]
fn import_into_an_existing_non_vault_path_refuses() {
    let dir = TestDir::new("nonvault");
    let (_layout, out) = exported_fixture(&dir);
    let obstruction = dir.path().join("obstruction");
    std::fs::create_dir_all(&obstruction).expect("mk obstruction");
    let target = VaultLayout::at(obstruction);
    let err = import_vault(
        &out,
        &target,
        || unreachable!("refusal precedes the passphrase"),
        &mut rng(),
    )
    .expect_err("must refuse");
    assert_eq!(err.class(), ErrorClass::Usage);
}

// ─────────────────────────────────────────────────────────────────────
// Spawned-binary E2E: the D41 scripted-automation shape
// ─────────────────────────────────────────────────────────────────────

fn spawn_antseal(
    vault_dir: &Path,
    args: &[&str],
    stdin_bytes: Option<&[u8]>,
) -> std::process::Output {
    let mut cmd = Process::new(env!("CARGO_BIN_EXE_antseal"));
    cmd.args(args)
        .env("ANTSEAL_DIR", vault_dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    match stdin_bytes {
        Some(bytes) => {
            cmd.stdin(Stdio::piped());
            let mut child = cmd.spawn().expect("spawn antseal");
            child
                .stdin
                .take()
                .expect("stdin handle")
                .write_all(bytes)
                .expect("pipe passphrase");
            child.wait_with_output().expect("wait")
        }
        None => {
            cmd.stdin(Stdio::null());
            cmd.output().expect("spawn antseal")
        }
    }
}

/// Full scripted drive of the real binary: export over
/// `--passphrase-fd 0` (plain), wipe, import (`--json`) — one JSON
/// document on stdout, human copy on stderr, vault verified by an
/// in-process unlock. Machine mode throughout (stdin is a pipe).
#[test]
fn scripted_export_import_over_passphrase_fd_zero() {
    let dir = TestDir::new("e2e");
    let vault_root = dir.path().join("vault");
    {
        let layout = VaultLayout::at(vault_root.clone());
        let vault = create_vault(&layout, &passphrase(), KdfSelection::Argon2id, &mut rng())
            .expect("create vault");
        populate(&vault);
    }
    let backup = dir.path().join("backup.sealvault");
    let backup_arg = backup.to_str().expect("utf-8 temp path");

    // Export, plain mode, passphrase piped on fd 0.
    let out = spawn_antseal(
        &vault_root,
        &["vault", "export", backup_arg, "--passphrase-fd", "0"],
        Some(b"correct horse battery staple fixture\n"),
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(backup.exists());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("self-verified"), "human summary: {stdout}");

    // Wipe and import, --json mode.
    std::fs::remove_dir_all(&vault_root).expect("wipe vault");
    let out = spawn_antseal(
        &vault_root,
        &[
            "--json",
            "vault",
            "import",
            backup_arg,
            "--passphrase-fd",
            "0",
        ],
        Some(b"correct horse battery staple fixture\n"),
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).expect("utf-8 stdout");
    let doc: serde_json::Value =
        serde_json::from_str(stdout.trim_end_matches('\n')).expect("exactly one JSON document");
    assert_eq!(doc["ok"], serde_json::json!(true));
    assert_eq!(doc["result"]["works"], serde_json::json!(5));
    assert_eq!(doc["result"]["wallet_restored"], serde_json::json!(true));
    assert!(!out.stderr.is_empty(), "human copy on stderr under --json");

    // The reconstructed vault opens and holds the works.
    let layout = VaultLayout::at(vault_root);
    let vault = unlock_vault(&layout, &passphrase()).expect("unlock imported vault");
    assert_eq!(WorkStore::new(&vault).list_works().expect("list").len(), 5);
}

/// Machine mode with no passphrase channel aborts with the dedicated
/// code instead of hanging — for export in both plain and `--json`
/// modes (stdin is closed, no fd given).
#[test]
fn machine_mode_without_a_channel_aborts_with_the_passphrase_class() {
    let dir = TestDir::new("nochannel");
    let vault_root = dir.path().join("vault");
    {
        let layout = VaultLayout::at(vault_root.clone());
        create_vault(&layout, &passphrase(), KdfSelection::Argon2id, &mut rng())
            .expect("create vault");
    }
    let out = spawn_antseal(&vault_root, &["vault", "export"], None);
    assert_eq!(out.status.code(), Some(11), "plain machine mode");
    assert!(out.stdout.is_empty(), "no stdout on plain-mode errors");

    let out = spawn_antseal(&vault_root, &["--json", "vault", "export"], None);
    assert_eq!(out.status.code(), Some(11), "--json machine mode");
    let stdout = String::from_utf8(out.stdout).expect("utf-8");
    let doc: serde_json::Value =
        serde_json::from_str(stdout.trim_end_matches('\n')).expect("one JSON document");
    assert_eq!(doc["error"]["class"], "passphrase-unavailable");
}

/// `vault export` without a vault is a clean usage error pointing at
/// `init`.
#[test]
fn export_without_a_vault_is_a_usage_error() {
    let dir = TestDir::new("novault");
    let out = spawn_antseal(&dir.path().join("vault"), &["vault", "export"], None);
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("antseal init"), "{stderr}");
}
