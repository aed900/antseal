//! U20 acceptance suite: D48's output-directory policy, the three-state
//! collision matrix, and the per-file verification report.
//!
//! Every row drives the real command path —
//! [`antseal_cli::restore_out::run_restore`] over a `MockBackend` and a
//! real vault — so what is asserted is a genuine seal → wipe → restore
//! round trip, not a simulation of one. The devnet leg is S17's.
//!
//! NON-SECRET: every fixture byte string is documented in `common`.

mod common;

use std::path::{Path, PathBuf};

use antseal_cli::error::ErrorClass;
use antseal_cli::pipeline::VaultJournal;
use antseal_cli::pipeline::journal::{MANIFEST_BLOB_ENTRY, PLAN_ENTRY};
use antseal_cli::pipeline::{
    ByteSource, NoBarriers, Pipeline, SealFile, SealRequest, SealResult, hex32,
};
use antseal_cli::restore_out::{
    FileStatus, RestoreOutput, default_output_dir, reroot, run_restore,
};
use antseal_cli::vault::session::UnlockedVault;
use antseal_cli::vault::store::{SealShapingFlags, WorkStore};
use antseal_core::content::{FileFlags, SplitMode};
use antseal_core::crypto::secrets::SealId;
use antseal_core::crypto::sig_policy::SigPolicy;
use antseal_net::NetworkId;
use antseal_net::test_util::{MockBackend, block_on};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

use common::{IsolatedVault, RecordingGate, ScriptedConsent};

/// BOM + CRLF + NFD: carries a raw mirror, so restoring it exercises the
/// exact-original-bytes path D48 §3 makes the comparison basis.
const CRLF_BOM_NFD: &[u8] = "\u{FEFF}caf\u{65}\u{301} notes\r\n\r\nsecond para\r\n".as_bytes();
const BINARY: &[u8] = &[0x00, 0x01, 0x02, 0xFF, 0xFE, 0x7F, 0x80, 0x00, 0x42];
const SPLIT_TEXT: &[u8] = b"alpha one\n\nbeta two\n\ngamma three\n";

/// A scratch directory that removes itself.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "antseal-u20-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        std::fs::create_dir_all(&path).expect("mk scratch");
        Self(path)
    }

    fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn files(paths: [&'static str; 3]) -> Vec<SealFile<'static>> {
    vec![
        SealFile {
            path_as_given: paths[0],
            path_absolute: "/w/notes.txt",
            bytes: CRLF_BOM_NFD,
            flags: FileFlags::new(),
        },
        SealFile {
            path_as_given: paths[1],
            path_absolute: "/w/data/blob.bin",
            bytes: BINARY,
            flags: FileFlags::new(),
        },
        SealFile {
            path_as_given: paths[2],
            path_absolute: "/w/split.txt",
            bytes: SPLIT_TEXT,
            flags: FileFlags::new().with_split(SplitMode::BlankLines),
        },
    ]
}

/// Seal the fixture work into `mock` and return its printed work id.
fn seal_fixture(mock: &MockBackend, vault: &UnlockedVault, paths: [&'static str; 3]) -> String {
    let files = files(paths);
    let mut journal_rng = ChaCha20Rng::from_seed([0x20; 32]);
    let journal = VaultJournal::new(WorkStore::new(vault), &mut journal_rng);
    let gate = RecordingGate::new();
    let consent = ScriptedConsent::always_yes();
    let pipeline = Pipeline::new(mock, &gate, &journal, &consent, &NoBarriers);
    let request = SealRequest {
        files: &files,
        title: "u20 fixture".to_owned(),
        claimed_time_unix_secs: 1_800_000_000,
        app_version: "antseal-test/1".to_owned(),
        network: NetworkId::Devnet,
        no_anchor: false,
        degraded: false,
        dry_run: false,
        sig_policy: SigPolicy::hybrid(),
        shaping: SealShapingFlags::default(),
    };
    let result = block_on(pipeline.seal(&request, &mut ChaCha20Rng::from_seed([0x21; 32])))
        .expect("the fixture seals");
    match result {
        SealResult::Sealed(outcome) => hex32(&outcome.work_id),
        SealResult::DryRun(_) => unreachable!("not a dry run"),
    }
}

fn restore_into(
    mock: &MockBackend,
    vault: &UnlockedVault,
    work_id: &str,
    dir: &Path,
) -> RestoreOutput {
    let store = WorkStore::new(vault);
    block_on(run_restore(mock, &store, work_id, Some(dir))).expect("the run completes")
}

fn status_of(out: &RestoreOutput, recorded: &str) -> FileStatus {
    out.files
        .iter()
        .find(|f| f.recorded_path == recorded)
        .unwrap_or_else(|| panic!("{recorded} has a row"))
        .status
}

// ─────────────────────────────────────────────────────────────────────
// U20 Accept row 1: seal → wipe → restore, then an idempotent re-run
// ─────────────────────────────────────────────────────────────────────

/// **U20 accept**: restore reproduces byte-identical files (raw bytes via
/// the raw mirror where one exists), and an immediate re-run reports every
/// file already-restored and exits 0 — convergent, and never destructive.
#[test]
fn restore_reproduces_the_originals_and_a_re_run_is_a_no_op() {
    let scratch = Scratch::new("roundtrip");
    let mock = MockBackend::new();
    let vault = IsolatedVault::create("u20-roundtrip");
    let unlocked = vault.unlock();
    let work_id = seal_fixture(
        &mock,
        &unlocked,
        ["notes.txt", "data/blob.bin", "split.txt"],
    );

    let dir = scratch.join("out");
    let first = restore_into(&mock, &unlocked, &work_id, &dir);
    assert!(first.into_error().is_none(), "a clean run exits 0");
    assert_eq!(first.files.len(), 3);
    for file in &first.files {
        assert_eq!(file.status, FileStatus::Restored, "{}", file.recorded_path);
    }

    // The bytes on disk are the originals, subdirectory and all.
    assert_eq!(
        std::fs::read(dir.join("notes.txt")).expect("read"),
        CRLF_BOM_NFD
    );
    assert_eq!(
        std::fs::read(dir.join("data/blob.bin")).expect("read"),
        BINARY
    );
    assert_eq!(
        std::fs::read(dir.join("split.txt")).expect("read"),
        SPLIT_TEXT
    );
    assert_eq!(
        first
            .files
            .iter()
            .find(|f| f.recorded_path == "notes.txt")
            .expect("row")
            .source,
        Some(ByteSource::RawMirror),
        "the mirror is what makes the BOM and CRLF survive"
    );

    // No temp residue survives a successful run (D48 §4).
    let residue: Vec<_> = std::fs::read_dir(&dir)
        .expect("read dir")
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().starts_with('.'))
        .collect();
    assert!(residue.is_empty(), "temp files are renamed away, not left");

    // Idempotent re-run: everything confirmed, nothing rewritten, exit 0.
    let mtime = std::fs::metadata(dir.join("notes.txt"))
        .and_then(|m| m.modified())
        .expect("mtime");
    let second = restore_into(&mock, &unlocked, &work_id, &dir);
    assert!(second.into_error().is_none(), "a converged re-run exits 0");
    for file in &second.files {
        assert_eq!(
            file.status,
            FileStatus::AlreadyRestored,
            "{}",
            file.recorded_path
        );
    }
    assert_eq!(
        std::fs::metadata(dir.join("notes.txt"))
            .and_then(|m| m.modified())
            .expect("mtime"),
        mtime,
        "an already-restored file is not rewritten (no mtime churn)"
    );
}

// ─────────────────────────────────────────────────────────────────────
// U20 Accept row 2: D48's three-state collision matrix
// ─────────────────────────────────────────────────────────────────────

/// **U20 accept, the three-state matrix**: absent → written; identical →
/// already-restored (success); differing → refused-overwrite with the
/// file untouched and a severity-ordered nonzero exit.
#[test]
fn the_three_target_states_behave_exactly_as_d48_says() {
    let scratch = Scratch::new("matrix");
    let mock = MockBackend::new();
    let vault = IsolatedVault::create("u20-matrix");
    let unlocked = vault.unlock();
    let work_id = seal_fixture(
        &mock,
        &unlocked,
        ["notes.txt", "data/blob.bin", "split.txt"],
    );

    let dir = scratch.join("out");
    std::fs::create_dir_all(dir.join("data")).expect("mk");
    // identical: exactly the bytes restore would write (the raw-mirror
    // rendition — the comparison basis D48 §3 names).
    std::fs::write(dir.join("notes.txt"), CRLF_BOM_NFD).expect("plant identical");
    // differing: one byte off.
    let mine = b"my own work, please do not eat".to_vec();
    std::fs::write(dir.join("split.txt"), &mine).expect("plant differing");
    // absent: data/blob.bin

    let out = restore_into(&mock, &unlocked, &work_id, &dir);
    assert_eq!(status_of(&out, "notes.txt"), FileStatus::AlreadyRestored);
    assert_eq!(status_of(&out, "data/blob.bin"), FileStatus::Restored);
    assert_eq!(status_of(&out, "split.txt"), FileStatus::RefusedOverwrite);

    assert_eq!(
        std::fs::read(dir.join("split.txt")).expect("read"),
        mine,
        "a differing file is left EXACTLY as it was"
    );
    assert_eq!(
        std::fs::read(dir.join("data/blob.bin")).expect("read"),
        BINARY
    );

    let err = out.into_error().expect("a non-success class is present");
    assert_eq!(err.class(), ErrorClass::RefusedOverwrite);
    assert_eq!(err.exit_code(), 30);

    // Moving the conflicting file aside and re-running converges.
    std::fs::remove_file(dir.join("split.txt")).expect("move aside");
    let again = restore_into(&mock, &unlocked, &work_id, &dir);
    assert!(again.into_error().is_none(), "the run converges");
    assert_eq!(status_of(&again, "split.txt"), FileStatus::Restored);
}

/// A directory sitting where a file belongs is a collision like any
/// other: refused, never cleared.
#[test]
fn a_directory_in_the_way_is_refused_not_removed() {
    let scratch = Scratch::new("dir-collision");
    let mock = MockBackend::new();
    let vault = IsolatedVault::create("u20-dircol");
    let unlocked = vault.unlock();
    let work_id = seal_fixture(
        &mock,
        &unlocked,
        ["notes.txt", "data/blob.bin", "split.txt"],
    );

    let dir = scratch.join("out");
    std::fs::create_dir_all(dir.join("notes.txt/inner")).expect("plant a directory");

    let out = restore_into(&mock, &unlocked, &work_id, &dir);
    assert_eq!(status_of(&out, "notes.txt"), FileStatus::RefusedOverwrite);
    assert!(dir.join("notes.txt/inner").is_dir(), "left alone");
    assert_eq!(
        out.into_error().expect("nonzero").class(),
        ErrorClass::RefusedOverwrite
    );
}

// ─────────────────────────────────────────────────────────────────────
// U20 Accept row 3: the lexical re-rooting rule
// ─────────────────────────────────────────────────────────────────────

/// **U20 accept**: absolute recorded paths re-root safely under `-o`,
/// and `..`-bearing ones are refused as a distinct malformed-record
/// error — with nothing written.
#[test]
fn absolute_paths_re_root_and_dot_dot_paths_are_refused() {
    let scratch = Scratch::new("reroot");
    let mock = MockBackend::new();
    let vault = IsolatedVault::create("u20-reroot");
    let unlocked = vault.unlock();

    // An absolute recorded path: the root is stripped, the rest kept.
    let work_id = seal_fixture(
        &mock,
        &unlocked,
        ["/etc/notes.txt", "data/blob.bin", "split.txt"],
    );
    let dir = scratch.join("abs");
    let out = restore_into(&mock, &unlocked, &work_id, &dir);
    assert_eq!(status_of(&out, "/etc/notes.txt"), FileStatus::Restored);
    assert_eq!(
        std::fs::read(dir.join("etc/notes.txt")).expect("read"),
        CRLF_BOM_NFD,
        "contained under -o, at the recorded shape"
    );

    // A `..`-bearing recorded path aborts the run before any write.
    let escaping = IsolatedVault::create("u20-escape");
    let escaping_unlocked = escaping.unlock();
    let escape_mock = MockBackend::new();
    let escape_id = seal_fixture(
        &escape_mock,
        &escaping_unlocked,
        ["../escape.txt", "data/blob.bin", "split.txt"],
    );
    let escape_dir = scratch.join("escape");
    let store = WorkStore::new(&escaping_unlocked);
    let err = block_on(run_restore(
        &escape_mock,
        &store,
        &escape_id,
        Some(&escape_dir),
    ))
    .expect_err("a `..` recorded path is refused");
    assert_eq!(err.class(), ErrorClass::MalformedRestoreRecord);
    assert!(
        !escape_dir.exists(),
        "the refusal precedes even the output directory's creation"
    );
    assert!(!scratch.join("escape.txt").exists(), "nothing escaped");

    // And the pure lexical rule, exercised directly.
    assert_eq!(
        reroot(Path::new("/out"), "a/./b//c.txt").expect("cleaned"),
        PathBuf::from("/out/a/b/c.txt")
    );
    assert_eq!(
        reroot(Path::new("/out"), "../x")
            .expect_err("escape")
            .class(),
        ErrorClass::MalformedRestoreRecord
    );
}

/// Two recorded paths that map to one target abort the whole run
/// **before** anything is written — no half-ordering is both
/// deterministic and safe (D48 §2).
#[test]
fn an_intra_work_collision_aborts_pre_write() {
    let scratch = Scratch::new("collide");
    let mock = MockBackend::new();
    let vault = IsolatedVault::create("u20-collide");
    let unlocked = vault.unlock();
    // `/w/notes.txt` and `w/notes.txt` re-root to the same target.
    let work_id = seal_fixture(
        &mock,
        &unlocked,
        ["/w/notes.txt", "w/notes.txt", "split.txt"],
    );

    let dir = scratch.join("out");
    let store = WorkStore::new(&unlocked);
    let err = block_on(run_restore(&mock, &store, &work_id, Some(&dir)))
        .expect_err("the collision is refused");
    assert_eq!(err.class(), ErrorClass::MalformedRestoreRecord);
    assert!(err.to_string().contains("both restore to"));
    assert!(!dir.exists(), "not one byte was written");
}

// ─────────────────────────────────────────────────────────────────────
// U20 Accept row 4: verification failures, exit classes, `--json`
// ─────────────────────────────────────────────────────────────────────

/// **U20 accept**: a fetch that cannot be satisfied is a per-file row in
/// the transient class, the file is never written, and the run exits with
/// that class — while its neighbours still restore.
#[test]
fn an_unfetchable_file_is_never_written_and_sets_the_exit_class() {
    let scratch = Scratch::new("unfetchable");
    let mock = MockBackend::new();
    let vault = IsolatedVault::create("u20-unfetchable");
    let unlocked = vault.unlock();
    let work_id = seal_fixture(
        &mock,
        &unlocked,
        ["notes.txt", "data/blob.bin", "split.txt"],
    );

    // Empty network + no cache = nothing to fetch, for every file.
    {
        let store = WorkStore::new(&unlocked);
        let seal_id = only_work(&store);
        for entry in store.list_journal_entries(&seal_id).expect("entries") {
            if entry >= MANIFEST_BLOB_ENTRY {
                store.delete_journal_entry(&seal_id, entry).expect("delete");
            }
        }
    }

    let dir = scratch.join("out");
    let store = WorkStore::new(&unlocked);
    // The manifest still comes from the vault's plaintext copy, so the
    // run reaches the per-unit fetches and reports them one by one.
    let out = block_on(run_restore(
        &MockBackend::new(),
        &store,
        &work_id,
        Some(&dir),
    ))
    .expect("the run completes");
    for file in &out.files {
        assert_eq!(
            file.status,
            FileStatus::FetchFailed,
            "{}",
            file.recorded_path
        );
        assert!(file.bytes.is_none(), "no bytes to write");
        assert!(!file.target.exists(), "nothing was written");
    }
    let err = out.into_error().expect("nonzero");
    assert_eq!(err.class(), ErrorClass::NetworkFailure);
    assert_eq!(err.exit_code(), 23);
}

/// **U20 accept**: when classes mix, the reported one follows D48 §6's
/// fixed severity — evidence beats local conflict beats transient.
#[test]
fn the_exit_class_is_the_most_severe_present() {
    use antseal_cli::pipeline::{FailedFile, FileError, FileOutcome, ManifestSource, VerifiedFile};

    let scratch = Scratch::new("severity");
    let dir = scratch.join("out");
    let report = antseal_cli::pipeline::RestoreReport {
        seal_id: SealId::from_bytes([0x7A; 16]),
        work_id: [0x7B; 32],
        network: "devnet".to_owned(),
        unanchored: false,
        manifest_source: ManifestSource::VaultCopy,
        files: vec![
            FileOutcome::Verified(VerifiedFile {
                file_id: 0,
                recorded_path: "ok.txt".to_owned(),
                bytes: b"fine".to_vec(),
                source: ByteSource::Canonical,
                from_network: 1,
                from_cache: 0,
            }),
            FileOutcome::Failed(FailedFile {
                file_id: 1,
                recorded_path: "gone.txt".to_owned(),
                error: FileError::Unfetchable {
                    unit_id: 1,
                    detail: "network".to_owned(),
                },
            }),
            FileOutcome::Failed(FailedFile {
                file_id: 2,
                recorded_path: "bad.txt".to_owned(),
                error: FileError::CommitmentMismatch {
                    subject: "the canonical bytes",
                },
            }),
        ],
    };

    let out = antseal_cli::restore_out::write_verified(&report, &dir).expect("policy applies");
    assert_eq!(status_of(&out, "ok.txt"), FileStatus::Restored);
    assert_eq!(status_of(&out, "gone.txt"), FileStatus::FetchFailed);
    assert_eq!(status_of(&out, "bad.txt"), FileStatus::VerificationFailed);
    assert!(
        !dir.join("bad.txt").exists(),
        "verification-failed is never written"
    );
    assert!(!dir.join("gone.txt").exists());

    let err = out.into_error().expect("nonzero");
    assert_eq!(
        err.class(),
        ErrorClass::RestoreVerificationFailed,
        "evidence outranks the transient class"
    );
    assert_eq!(err.exit_code(), 35);

    // With the verification row removed, the transient one reports.
    let out = RestoreOutput {
        files: out
            .files
            .into_iter()
            .filter(|f| f.recorded_path != "bad.txt")
            .collect(),
        ..out
    };
    assert_eq!(
        out.into_error().expect("nonzero").class(),
        ErrorClass::NetworkFailure
    );
}

/// The registered `--json` shape: per-file status array with every
/// documented key, plus the counts a script gates on.
#[test]
fn the_json_document_carries_per_file_status() {
    let scratch = Scratch::new("json");
    let mock = MockBackend::new();
    let vault = IsolatedVault::create("u20-json");
    let unlocked = vault.unlock();
    let work_id = seal_fixture(
        &mock,
        &unlocked,
        ["notes.txt", "data/blob.bin", "split.txt"],
    );

    let dir = scratch.join("out");
    std::fs::create_dir_all(&dir).expect("mk");
    std::fs::write(dir.join("split.txt"), b"mine").expect("plant a conflict");

    let out = restore_into(&mock, &unlocked, &work_id, &dir);
    let doc = out.json();

    assert_eq!(doc["work_id"], serde_json::json!(work_id));
    assert_eq!(doc["manifest_source"], serde_json::json!("vault-copy"));
    let files = doc["files"].as_array().expect("files array");
    assert_eq!(files.len(), 3);
    for row in files {
        for key in [
            "file_id",
            "recorded_path",
            "target",
            "status",
            "detail",
            "bytes",
            "source",
        ] {
            assert!(row.get(key).is_some(), "row missing {key}: {row}");
        }
    }
    let notes = files
        .iter()
        .find(|r| r["recorded_path"] == serde_json::json!("notes.txt"))
        .expect("notes row");
    assert_eq!(notes["status"], serde_json::json!("restored"));
    assert_eq!(notes["source"], serde_json::json!("raw-mirror"));

    let refused = files
        .iter()
        .find(|r| r["recorded_path"] == serde_json::json!("split.txt"))
        .expect("split row");
    assert_eq!(refused["status"], serde_json::json!("refused-overwrite"));
    assert_eq!(doc["counts"]["refused-overwrite"], serde_json::json!(1));
    assert_eq!(doc["counts"]["restored"], serde_json::json!(2));
    assert_eq!(doc["counts"]["verification-failed"], serde_json::json!(0));

    // The human render says the same thing in words.
    let rendered = out.render().join("\n");
    assert!(rendered.contains("Restored 2 of 3 file(s)"));
    assert!(rendered.contains("refused-overwrite"));
    assert!(rendered.contains("move them aside"));
    assert!(
        rendered.contains("exact original bytes"),
        "the mirror is named"
    );
}

// ─────────────────────────────────────────────────────────────────────
// Defaults and refusals
// ─────────────────────────────────────────────────────────────────────

/// The default output directory is work-scoped, so it is collision-free
/// across works and a re-run of the same work lands in the same place.
#[test]
fn the_default_output_directory_is_work_scoped() {
    let printed = "ab".repeat(32);
    assert_eq!(
        default_output_dir(&[0xAB; 32]),
        PathBuf::from(format!("antseal-restore-{printed}"))
    );
}

/// An unknown work id is a clean error before anything is created.
#[test]
fn an_unknown_work_id_fails_cleanly() {
    let scratch = Scratch::new("unknown");
    let mock = MockBackend::new();
    let vault = IsolatedVault::create("u20-unknown");
    let unlocked = vault.unlock();
    let _ = seal_fixture(
        &mock,
        &unlocked,
        ["notes.txt", "data/blob.bin", "split.txt"],
    );
    let store = WorkStore::new(&unlocked);

    let dir = scratch.join("out");
    let err = block_on(run_restore(&mock, &store, &"cd".repeat(32), Some(&dir)))
        .expect_err("no such work");
    assert_eq!(err.class(), ErrorClass::Usage);
    assert!(
        !dir.exists(),
        "nothing created for a work that does not exist"
    );

    let err = block_on(run_restore(&mock, &store, "not-a-work-id", Some(&dir)))
        .expect_err("not an id at all");
    assert_eq!(err.class(), ErrorClass::Usage);
}

/// A work whose manifest cannot be located stops before the output
/// directory exists — the D48 malformed-record class, and the shape a
/// `vault import`ed complete work currently has (S29).
#[test]
fn an_unresolvable_manifest_stops_before_any_output() {
    let scratch = Scratch::new("nomanifest");
    let mock = MockBackend::new();
    let vault = IsolatedVault::create("u20-nomanifest");
    let unlocked = vault.unlock();
    let work_id = seal_fixture(
        &mock,
        &unlocked,
        ["notes.txt", "data/blob.bin", "split.txt"],
    );

    let store = WorkStore::new(&unlocked);
    let seal_id = only_work(&store);
    store
        .delete_journal_entry(&seal_id, PLAN_ENTRY)
        .expect("drop plan");
    store
        .delete_journal_entry(&seal_id, MANIFEST_BLOB_ENTRY)
        .expect("drop locator");

    let dir = scratch.join("out");
    let err = block_on(run_restore(&mock, &store, &work_id, Some(&dir)))
        .expect_err("no manifest, no restore");
    assert_eq!(err.class(), ErrorClass::MalformedRestoreRecord);
    assert!(!dir.exists());
}

/// The only work in a fixture vault.
fn only_work(store: &WorkStore<'_>) -> SealId {
    let works = store.list_works().expect("list");
    assert_eq!(works.len(), 1, "the fixture vault holds one work");
    works[0]
}
