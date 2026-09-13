//! U20 acceptance suite: D48's output-directory policy, the three-state
//! collision matrix, and the per-file verification report.
//!
//! Every library row drives the real command path —
//! [`antseal_cli::restore_out::run_restore`] over a `MockBackend` and a
//! real vault — so what is asserted is a genuine seal → wipe → restore
//! round trip, not a simulation of one. The devnet leg is S17's.
//!
//! The **handler** rows at the end (D170 §2 R3/R4, U74, U90) spawn the
//! binary instead, because the handlers are `pub(crate)` and build their own
//! backend: what they prove is which build answers what, in which order, and
//! that a build with a backend degrades an unreachable network rather than
//! refusing. None of them needs a devnet — the network they cannot reach is a
//! loopback port nothing listens on — and the devnet rows are
//! `tests/e2e_restore.rs`'s.
//!
//! NON-SECRET: every fixture byte string is documented in `common`.

mod common;

#[path = "common/spawn.rs"]
mod spawn;

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::Stdio;

use antseal_cli::backend::{ReadOnlyBackend, degrade};
use antseal_cli::error::ErrorClass;
use antseal_cli::pipeline::VaultJournal;
use antseal_cli::pipeline::journal::{MANIFEST_BLOB_ENTRY, PLAN_ENTRY, UNIT_ENTRY_BASE};
use antseal_cli::pipeline::{
    ByteSource, ManifestSource, NoBarriers, Pipeline, SealFile, SealRequest, SealResult, hex32,
};
use antseal_cli::restore_out::{
    FileStatus, RestoreOutput, default_output_dir, reroot, run_restore,
};
use antseal_cli::vault::session::UnlockedVault;
use antseal_cli::vault::store::{SealShapingFlags, WorkStore};
use antseal_core::content::{FileFlags, SplitMode};
use antseal_core::crypto::secrets::SealId;
use antseal_core::crypto::sig_policy::SigPolicy;
use antseal_net::test_util::{Fault, Method, MockBackend, block_on};
use antseal_net::{
    Address, BalanceReport, Blob, CostQuote, GasSummary, NetworkId, PaymentReceipt, StorageBackend,
    StorageError,
};
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
    assert!(first.exit_class().is_none(), "a clean run exits 0");
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
    assert!(second.exit_class().is_none(), "a converged re-run exits 0");
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

    let class = out.exit_class().expect("a non-success class is present");
    assert_eq!(class, ErrorClass::RefusedOverwrite);
    assert_eq!(class.exit_code(), 30);

    // Moving the conflicting file aside and re-running converges.
    std::fs::remove_file(dir.join("split.txt")).expect("move aside");
    let again = restore_into(&mock, &unlocked, &work_id, &dir);
    assert!(again.exit_class().is_none(), "the run converges");
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
        out.exit_class().expect("nonzero"),
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
    let class = out.exit_class().expect("nonzero");
    assert_eq!(class, ErrorClass::NetworkFailure);
    assert_eq!(class.exit_code(), 23);
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

    let class = out.exit_class().expect("nonzero");
    assert_eq!(
        class,
        ErrorClass::RestoreVerificationFailed,
        "evidence outranks the transient class"
    );
    assert_eq!(class.exit_code(), 35);

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
        out.exit_class().expect("nonzero"),
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

// ─────────────────────────────────────────────────────────────────────
// D170 §2 R1/R2 — the read-only backend over a network it cannot reach
// ─────────────────────────────────────────────────────────────────────

/// The connection failure the connect-failed arm hands to `degrade`. A
/// fixture string, so a row can prove the per-file failure carries it.
const FAILED_CONNECTION: &str = "fixture: no bootstrap peer answered";

/// The two shapes an unreachable network takes at a read-only command's
/// seam, which the command must treat identically.
///
/// - **`ConnectFailed`** — the connection attempt fails, and `degrade` hands
///   the command an unreachable backend whose every call fails (D170 §2 R2 as
///   ruled).
/// - **`EveryFetchFails`** — the connection **succeeds** and every fetch then
///   fails in the network class. Measured 2026-09-13 on a live devnet, this is
///   what ant-core 0.5.0 actually does for a dead or empty bootstrap: the
///   client connects `Ok` and the network surfaces per fetch — as the network
///   class only since the adapter stopped reporting an unreachable network as
///   `NotFound`.
#[derive(Clone, Copy, Debug)]
enum Unreachable {
    ConnectFailed,
    EveryFetchFails,
}

impl Unreachable {
    const BOTH: [Self; 2] = [Self::ConnectFailed, Self::EveryFetchFails];

    /// The backend a read-only command holds in this shape. In the
    /// every-fetch arm `network` is armed with exactly `fetches` network-class
    /// faults, so each expected fetch fails and any extra fetch would reach
    /// the store and be visible in the count.
    fn backend(
        self,
        network: &std::sync::Arc<MockBackend>,
        fetches: usize,
    ) -> ReadOnlyBackend<SharedMock> {
        match self {
            Self::ConnectFailed => degrade(
                "restore",
                Err(StorageError::Network {
                    reason: FAILED_CONNECTION.to_owned(),
                }),
            ),
            Self::EveryFetchFails => {
                for _ in 0..fetches {
                    network.arm_fault(Fault::NetworkOn(Method::GetData));
                }
                degrade("restore", Ok(SharedMock(std::sync::Arc::clone(network))))
            }
        }
    }

    /// How many fetches failed: the unreachable backend's own counter, or
    /// the connected network's `get_data` calls since `before` — every armed
    /// fault having fired.
    fn failed_fetches(
        self,
        backend: &ReadOnlyBackend<SharedMock>,
        network: &MockBackend,
        before: usize,
    ) -> usize {
        match self {
            Self::ConnectFailed => backend
                .degraded()
                .expect("a failed connection degrades to the unreachable backend")
                .calls(),
            Self::EveryFetchFails => {
                assert!(
                    backend.degraded().is_none(),
                    "a connection that succeeded is not degraded"
                );
                assert_eq!(
                    network.armed_faults(),
                    0,
                    "every armed fault fired: every fetch failed in the network class"
                );
                network.calls(Method::GetData) - before
            }
        }
    }

    /// The text every failed row carries in this shape.
    const fn reason(self) -> &'static str {
        match self {
            Self::ConnectFailed => FAILED_CONNECTION,
            Self::EveryFetchFails => "injected network fault: get_data",
        }
    }
}

/// How many per-unit D43 cache copies the fixture vault holds.
fn unit_cache_entries(store: &WorkStore<'_>) -> usize {
    let seal_id = only_work(store);
    store
        .list_journal_entries(&seal_id)
        .expect("entries")
        .into_iter()
        .filter(|entry| *entry >= UNIT_ENTRY_BASE)
        .count()
}

/// **D170 §2 R2 / U90's Accept, first half — an unreachable network does not
/// end `restore`.** In both shapes every unit is asked of the network first,
/// every ask fails in the network class, and D43 §5's verified-cache fallback
/// serves each one: a fully cached work restores byte-identical and exits 0.
///
/// The fetch count is what separates this from a restore that never asked the
/// network at all — the two write the same files — so it is asserted exactly,
/// against the number of cache copies the seal retained. The every-fetch arm
/// runs over the very network that sealed the work, which still holds every
/// chunk: a fetch that escaped its fault would succeed and move the count.
#[test]
fn an_unreachable_network_degrades_and_a_fully_cached_work_still_restores() {
    let scratch = Scratch::new("degraded-cached");
    let network = std::sync::Arc::new(MockBackend::new());
    let vault = IsolatedVault::create("u90-degraded-cached");
    let unlocked = vault.unlock();
    let work_id = seal_fixture(
        &network,
        &unlocked,
        ["notes.txt", "data/blob.bin", "split.txt"],
    );
    let store = WorkStore::new(&unlocked);
    let cached_units = unit_cache_entries(&store);
    assert!(
        cached_units >= 3,
        "the seal retained a D43 cache copy of every unit, at least one per file: {cached_units}"
    );

    for shape in Unreachable::BOTH {
        let before = network.calls(Method::GetData);
        let backend = shape.backend(&network, cached_units);
        let dir = scratch.join(&format!("out-{shape:?}"));
        let out = block_on(run_restore(&backend, &store, &work_id, Some(&dir)))
            .unwrap_or_else(|error| panic!("{shape:?}: the restore must still complete: {error}"));

        assert!(
            out.exit_class().is_none(),
            "{shape:?}: every file came from a verified copy, so the run exits 0: {:?}",
            out.counts()
        );
        assert_eq!(out.files.len(), 3, "{shape:?}");
        for file in &out.files {
            assert_eq!(
                file.status,
                FileStatus::Restored,
                "{shape:?}: {}: {:?}",
                file.recorded_path,
                file.detail
            );
        }
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
            out.manifest_source,
            ManifestSource::VaultCopy,
            "{shape:?}: the manifest needed no fetch, so the network was asked only for units"
        );
        assert_eq!(
            shape.failed_fetches(&backend, &network, before),
            cached_units,
            "{shape:?}: network-first (D43 §5) — every unit was asked of the network, and failed, \
             before its verified cache copy was used"
        );
    }
}

/// **D170 §2 R2 / U90's Accept, second half — with nothing cached, an
/// unreachable network yields a result document, not a refusal.** In both
/// shapes every file is `fetch-failed`, each row carries the network-class
/// reason (never the build-has-no-backend sentence, never the absence
/// sentence, never a verification failure), nothing is written, and the run
/// folds to the transient network class by D48 §6.
#[test]
fn an_unreachable_network_with_no_cache_reports_every_file_fetch_failed() {
    let scratch = Scratch::new("degraded-uncached");
    let network = std::sync::Arc::new(MockBackend::new());
    let vault = IsolatedVault::create("u90-degraded-uncached");
    let unlocked = vault.unlock();
    let work_id = seal_fixture(
        &network,
        &unlocked,
        ["notes.txt", "data/blob.bin", "split.txt"],
    );
    let store = WorkStore::new(&unlocked);
    {
        let seal_id = only_work(&store);
        for entry in store.list_journal_entries(&seal_id).expect("entries") {
            if entry >= MANIFEST_BLOB_ENTRY {
                store.delete_journal_entry(&seal_id, entry).expect("delete");
            }
        }
    }
    assert_eq!(unit_cache_entries(&store), 0, "no verified copy remains");

    for shape in Unreachable::BOTH {
        let before = network.calls(Method::GetData);
        let backend = shape.backend(&network, 3);
        let dir = scratch.join(&format!("out-{shape:?}"));
        let out =
            block_on(run_restore(&backend, &store, &work_id, Some(&dir))).unwrap_or_else(|error| {
                panic!("{shape:?}: a result document, never a whole-run refusal: {error}")
            });

        assert_eq!(out.files.len(), 3, "{shape:?}");
        for file in &out.files {
            assert_eq!(
                file.status,
                FileStatus::FetchFailed,
                "{shape:?}: {}: {:?}",
                file.recorded_path,
                file.detail
            );
            let detail = file.detail.as_deref().expect("a fetch-failed row says why");
            assert!(
                detail.contains(shape.reason()),
                "{shape:?}: the row carries the network-class reason: {detail}"
            );
            assert!(
                !detail.contains("ant-backend") && !detail.contains("has no data at this address"),
                "{shape:?}: neither the no-backend sentence nor the absence sentence: {detail}"
            );
            assert!(file.bytes.is_none(), "no bytes to write");
            assert!(!file.target.exists(), "nothing was written");
        }
        let class = out.exit_class().expect("a failing row sets a class");
        assert_eq!(class, ErrorClass::NetworkFailure, "{shape:?}");
        assert_eq!(
            out.json()["counts"]["fetch-failed"],
            serde_json::json!(3),
            "{shape:?}"
        );
        assert_eq!(
            shape.failed_fetches(&backend, &network, before),
            3,
            "{shape:?}: one failed fetch per file — each file stops at its first unit that cannot \
             be obtained"
        );
    }
}

/// `MockBackend` behind an `Arc`, so a row can read its call log after
/// `degrade` has taken ownership of the backend it wraps.
struct SharedMock(std::sync::Arc<MockBackend>);

impl StorageBackend for SharedMock {
    async fn quote_batch(&self, blobs: &[Blob]) -> Result<CostQuote, StorageError> {
        self.0.quote_batch(blobs).await
    }

    async fn pay(&self, quote: &CostQuote) -> Result<PaymentReceipt, StorageError> {
        self.0.pay(quote).await
    }

    async fn finalize_batch(
        &self,
        receipt: &PaymentReceipt,
        blobs: &[Blob],
    ) -> Result<Vec<Address>, StorageError> {
        self.0.finalize_batch(receipt, blobs).await
    }

    async fn get_data(&self, address: Address) -> Result<Vec<u8>, StorageError> {
        self.0.get_data(address).await
    }

    async fn balances(&self) -> Result<BalanceReport, StorageError> {
        self.0.balances().await
    }
}

/// **D170 §2 R1, the CLI's own layer — read-only is a property of the
/// wrapper.** Around a backend that **can** quote, pay, store and read a
/// wallet, a `ReadOnlyBackend` delegates the fetch and refuses the other four
/// itself, each in its trait contract's class, without a single one of them
/// reaching the inner backend.
#[test]
fn the_read_only_backend_delegates_fetches_and_refuses_everything_that_could_pay() {
    const CHUNK: &[u8] = b"u90 fixture: a chunk already on the network";

    let inner = std::sync::Arc::new(MockBackend::new());
    let address = inner.preload_third_party(CHUNK);
    let backend = degrade(
        "restore",
        Ok::<_, StorageError>(SharedMock(std::sync::Arc::clone(&inner))),
    );
    assert!(
        backend.degraded().is_none(),
        "a connection that succeeded is not degraded"
    );

    assert_eq!(
        block_on(backend.get_data(address)).expect("the fetch is delegated"),
        CHUNK
    );

    let blob = Blob::new(b"u90 fixture: bytes that would cost money".to_vec()).expect("under cap");
    // A real quote and a receipt-shaped value, both from outside the wrapper,
    // so every refused call is one the inner backend could have accepted.
    let quote = block_on(MockBackend::new().quote_batch(std::slice::from_ref(&blob)))
        .expect("a foreign mock quotes");
    let receipt = PaymentReceipt {
        blobs: Vec::new(),
        tx_map: std::collections::BTreeMap::new(),
        txs: Vec::new(),
        storage_cost_atto: 0,
        gas: GasSummary { gas_cost_wei: 0 },
    };

    let refused = block_on(backend.quote_batch(std::slice::from_ref(&blob)))
        .expect_err("a read-only backend must refuse to quote");
    assert!(matches!(refused, StorageError::Quote { .. }), "{refused:?}");
    let refused =
        block_on(backend.pay(&quote)).expect_err("a read-only backend must refuse to pay");
    assert!(
        matches!(refused, StorageError::Payment { .. }),
        "{refused:?}"
    );
    let refused = block_on(backend.finalize_batch(&receipt, std::slice::from_ref(&blob)))
        .expect_err("a read-only backend must refuse to store");
    assert!(
        matches!(refused, StorageError::Finalize { .. }),
        "{refused:?}"
    );
    let refused =
        block_on(backend.balances()).expect_err("a read-only backend must refuse a wallet read");
    assert!(
        matches!(refused, StorageError::Network { .. }),
        "{refused:?}"
    );

    for (method, expected) in [
        (Method::GetData, 1),
        (Method::QuoteBatch, 0),
        (Method::Pay, 0),
        (Method::FinalizeBatch, 0),
        (Method::Balances, 0),
    ] {
        assert_eq!(
            inner.calls(method),
            expected,
            "{method:?} reached the wrapped backend {} time(s); a read-only backend delegates \
             the fetch and nothing else",
            inner.calls(method)
        );
    }
    assert_eq!(inner.payment_tx_count(), 0, "no money moved");
    assert_eq!(inner.store_events(), 0, "nothing was stored");
}

// ─────────────────────────────────────────────────────────────────────
// D170 §2 R3/R4, U74, U90 — the `restore` handler, through the binary
// ─────────────────────────────────────────────────────────────────────

/// What a spawned `antseal` answered.
struct Spawned {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

impl Spawned {
    /// The one `--json` document on stdout.
    fn document(&self) -> serde_json::Value {
        serde_json::from_str(self.stdout.trim_end_matches('\n')).unwrap_or_else(|error| {
            panic!(
                "stdout is not one JSON document ({error}).\nstdout:\n{}\nstderr:\n{}",
                self.stdout, self.stderr
            )
        })
    }
}

/// The two traces these rows read: D42's hook says whether the invocation
/// unlocked a vault — the process-level witness of *before the vault* and
/// *after the passphrase* — and the read-only construction says whether a
/// connection was attempted at all.
const HANDLER_LOG: &str = "antseal_cli::upgrade_hook=debug,antseal_cli::backend=debug";

/// `connect_read_only`'s one trace, emitted inside its future — so only when
/// a connection is actually attempted.
const READER_CONNECT_TRACE: &str = "connecting the read-only reader";

/// Spawn `antseal <args>` over the vault at `vault_root`, from `cwd`, with the
/// fixture passphrase on stdin and `devnet_env` as the only devnet definition
/// it can see (`None` strips any the developer's shell exported).
///
/// A write failure on stdin is ignored on purpose: a build that refuses
/// before reading the passphrase exits first and closes the pipe, which is the
/// command doing its job rather than the harness failing.
fn spawn_over(vault_root: &Path, cwd: &Path, args: &[&str], devnet_env: Option<&Path>) -> Spawned {
    let mut command = spawn::antseal();
    command
        .args(args)
        .env("ANTSEAL_DIR", vault_root)
        .env("RUST_LOG", HANDLER_LOG)
        .current_dir(cwd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    match devnet_env {
        Some(path) => {
            command.env("ANTSEAL_DEVNET_ENV", path);
        }
        None => {
            command.env_remove("ANTSEAL_DEVNET_ENV");
        }
    }
    let mut child = command.spawn().expect("spawn antseal");
    let _ = child
        .stdin
        .as_mut()
        .expect("stdin is piped")
        .write_all(common::FIXTURE_PASSPHRASE);
    drop(child.stdin.take());
    let out = child.wait_with_output().expect("wait for antseal");
    Spawned {
        code: out.status.code(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

/// A devnet definition that reaches **nothing**: its one bootstrap peer is a
/// loopback UDP port bound and released a moment ago, and its payment RPC a
/// loopback TCP port likewise — D170 §2 R7's negative-control shape, with no
/// devnet anywhere. A reader dials the bootstrap and nothing else; the RPC is
/// there only because the export format requires one.
///
/// NON-SECRET: no key line at all (a walletless export), and the two contract
/// addresses are Anvil's well-known deterministic deployments.
fn dead_devnet_export(dir: &Path) -> PathBuf {
    let udp = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind a loopback probe socket");
    let bootstrap = udp.local_addr().expect("the probe's address");
    drop(udp);
    let tcp = std::net::TcpListener::bind("127.0.0.1:0").expect("bind a loopback probe listener");
    let rpc_port = tcp.local_addr().expect("the probe's address").port();
    drop(tcp);
    let text = format!(
        "# antseal devnet environment: a dead one, for a negative control\n\
         ANTSEAL_DEVNET_RPC_URL='http://127.0.0.1:{rpc_port}/'\n\
         ANTSEAL_DEVNET_CHAIN_ID='31337'\n\
         ANTSEAL_DEVNET_TOKEN_ADDRESS='0x5FbDB2315678afecb367f032d93F642f64180aa3'\n\
         ANTSEAL_DEVNET_PAYMENT_VAULT_ADDRESS='0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512'\n\
         ANTSEAL_DEVNET_BOOTSTRAP='{bootstrap}'\n\
         ANTSEAL_DEVNET_NODE_COUNT='1'\n\
         ANTSEAL_DEVNET_BASE_PORT='{port}'\n\
         ANTSEAL_DEVNET_DATA_DIR='{data}'\n\
         ANTSEAL_DEVNET_PID='{pid}'\n",
        port = bootstrap.port(),
        data = dir.display(),
        pid = std::process::id(),
    );
    let path = dir.join("dead-devnet.env");
    std::fs::write(&path, text).expect("write the dead devnet export");
    path
}

/// A vault holding the three-file fixture work, sealed on `devnet` with every
/// D43 cache copy retained — the shape U74 names: a work that could be
/// restored without a network, if a build were allowed to.
fn fully_cached_fixture(tag: &str) -> (IsolatedVault, String) {
    let mock = MockBackend::new();
    let vault = IsolatedVault::create(tag);
    let work_id = {
        let unlocked = vault.unlock();
        let work_id = seal_fixture(
            &mock,
            &unlocked,
            ["notes.txt", "data/blob.bin", "split.txt"],
        );
        let cached = unit_cache_entries(&WorkStore::new(&unlocked));
        assert!(
            cached >= 3,
            "the fixture must be fully cached, or U74's question does not arise: {cached}"
        );
        work_id
    };
    (vault, work_id)
}

/// **U74, answered by D170 §2 R4 — and U90's degrade — through the spawned
/// binary, per build.** The same fully cached work, the same argv:
///
/// - **A build with no backend refuses, before the vault.** Exit 23 with the
///   no-backend refusal byte-for-byte, nothing written, and D42's hook reports
///   no unlocked vault — so no passphrase was ever read. A cache that could
///   serve every byte does not change the answer: `restore` is
///   network-normative (D43 §5), and a build that cannot attempt the network
///   has no restore to give.
/// - **A build with one restores it with no reachable peer.** Its only
///   network is a dead loopback port, so every unit is asked of the network,
///   fails in the network class, and is served from its verified cache copy:
///   exit 0, byte-identical originals, the vault unlocked, a connection
///   attempted.
///
/// Selected by a runtime read of `BackendArm::THIS_BUILD` rather than `#[cfg]`
/// (U73's shape), so both expectations compile into both builds.
#[test]
fn a_fully_cached_restore_answers_per_build() {
    use antseal_cli::backend::{BackendArm, unavailable_arm};
    use antseal_cli::upgrade_hook::{HOOK_ARMED, HOOK_NOT_ARMED};

    let scratch = Scratch::new("u74-per-build");
    let (vault, work_id) = fully_cached_fixture("u74-per-build");
    let dead = dead_devnet_export(&scratch.0);
    let out_dir = scratch.join("restored");
    let out_arg = out_dir.to_str().expect("a utf-8 scratch path").to_owned();

    let run = spawn_over(
        vault.layout.root(),
        &scratch.0,
        &[
            "--json",
            "--passphrase-fd",
            "0",
            "restore",
            &work_id,
            "-o",
            &out_arg,
        ],
        Some(&dead),
    );
    let document = run.document();

    match BackendArm::THIS_BUILD {
        BackendArm::NotCompiled => {
            assert_eq!(
                run.code,
                Some(23),
                "U74: a build with no backend refuses `restore` even for a fully cached work \
                 (D170 §2 R4). stderr:\n{}",
                run.stderr
            );
            assert_eq!(document["ok"], serde_json::json!(false), "{document}");
            assert_eq!(
                document["error"],
                unavailable_arm("restore", BackendArm::NotCompiled).error_object(),
                "the refusal is the no-backend seam's, unchanged"
            );
            assert!(
                run.stderr.contains(HOOK_NOT_ARMED) && !run.stderr.contains(HOOK_ARMED),
                "the refusal lands BEFORE the vault: no vault was unlocked, so no passphrase \
                 was read. stderr:\n{}",
                run.stderr
            );
            assert!(
                !run.stderr.contains(READER_CONNECT_TRACE),
                "a build with no backend attempts no connection"
            );
            assert!(!out_dir.exists(), "a refused restore writes nothing");
        }
        BackendArm::Compiled => {
            assert_eq!(
                run.code,
                Some(0),
                "U90: a build with a backend restores a fully cached work with no reachable \
                 peer (D170 §2 R2). stderr:\n{}",
                run.stderr
            );
            assert_eq!(document["ok"], serde_json::json!(true), "{document}");
            assert_eq!(
                document["result"]["counts"]["restored"],
                serde_json::json!(3),
                "{document}"
            );
            assert_eq!(
                std::fs::read(out_dir.join("notes.txt")).expect("read"),
                CRLF_BOM_NFD
            );
            assert_eq!(
                std::fs::read(out_dir.join("data/blob.bin")).expect("read"),
                BINARY
            );
            assert_eq!(
                std::fs::read(out_dir.join("split.txt")).expect("read"),
                SPLIT_TEXT
            );
            assert!(
                run.stderr.contains(HOOK_ARMED),
                "this build opens the vault first (U73's precedent). stderr:\n{}",
                run.stderr
            );
            assert!(
                run.stderr.contains(READER_CONNECT_TRACE),
                "the network was asked — network-first — before each verified copy was used. \
                 stderr:\n{}",
                run.stderr
            );
        }
    }
}

/// **U73's shape for `restore`**: into a `HOME` with no vault, the two builds
/// answer differently, and each answer is the right one.
///
/// - **No backend: 23**, the seam refusal, because that arm refuses before
///   the vault is even looked for.
/// - **A backend: 2**, `open_layout`'s *"no vault exists"* usage refusal —
///   verified in code rather than assumed: the feature arm's first line is
///   `open_layout()?`, whose missing-header branch is `CliError::Usage`, and
///   nothing before it can fail on this argv.
///
/// Neither build creates `~/.antseal`.
#[test]
fn restore_into_a_vault_less_home_answers_per_build() {
    use antseal_cli::backend::{BackendArm, unavailable_arm};

    let home = Scratch::new("vault-less-home");
    let out = spawn::antseal()
        .args([
            "--json",
            "restore",
            &"a1".repeat(32),
            "--passphrase-fd",
            "0",
        ])
        .env("HOME", &home.0)
        .env_remove("ANTSEAL_DIR")
        .env_remove("ANTSEAL_DEVNET_ENV")
        .env_remove("RUST_LOG")
        .current_dir(&home.0)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn antseal");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let document: serde_json::Value =
        serde_json::from_str(stdout.trim_end_matches('\n')).expect("one JSON document");

    match BackendArm::THIS_BUILD {
        BackendArm::NotCompiled => {
            assert_eq!(out.status.code(), Some(23), "{document}");
            assert_eq!(
                document["error"],
                unavailable_arm("restore", BackendArm::NotCompiled).error_object()
            );
        }
        BackendArm::Compiled => {
            assert_eq!(out.status.code(), Some(2), "{document}");
            assert_eq!(document["error"]["class"], serde_json::json!("usage"));
            let message = document["error"]["message"].as_str().expect("a message");
            assert!(
                message.contains("no vault exists"),
                "the feature build meets the missing vault first: {message}"
            );
        }
    }
    assert!(
        !home.0.join(".antseal").exists(),
        "a refused restore must never create the vault directory"
    );
}

/// **U90's `Accept`, the uncached half, through the binary (D170 §2 R2 as
/// corrected, D48 §6).** With no verified copy left and a network it cannot
/// reach, a build with a backend returns a **result document** at the
/// network-failure code — `ok: true`, every file a `fetch-failed` row, nothing
/// written — and never the unavailable refusal. Each row's reason is the
/// network class's: not the no-backend sentence, and not the absence sentence
/// an unreachable network must never be reported as (D170 §2 R12).
#[cfg(feature = "ant-backend")]
#[test]
fn an_uncached_work_over_an_unreachable_network_is_a_result_document_at_exit_23() {
    use antseal_cli::upgrade_hook::HOOK_ARMED;

    let scratch = Scratch::new("u90-uncached-binary");
    let (vault, work_id) = fully_cached_fixture("u90-uncached-binary");
    {
        let unlocked = vault.unlock();
        let store = WorkStore::new(&unlocked);
        let seal_id = only_work(&store);
        for entry in store.list_journal_entries(&seal_id).expect("entries") {
            if entry >= MANIFEST_BLOB_ENTRY {
                store.delete_journal_entry(&seal_id, entry).expect("delete");
            }
        }
        assert_eq!(unit_cache_entries(&store), 0, "no verified copy remains");
    }
    let dead = dead_devnet_export(&scratch.0);
    let out_dir = scratch.join("restored");
    let out_arg = out_dir.to_str().expect("a utf-8 scratch path").to_owned();

    let run = spawn_over(
        vault.layout.root(),
        &scratch.0,
        &[
            "--json",
            "--passphrase-fd",
            "0",
            "restore",
            &work_id,
            "-o",
            &out_arg,
        ],
        Some(&dead),
    );
    let document = run.document();

    assert_eq!(
        run.code,
        Some(23),
        "D48 §6: every file fetch-failed, so the run exits in the network-failure class. \
         stderr:\n{}",
        run.stderr
    );
    assert_eq!(
        document["ok"],
        serde_json::json!(true),
        "a result document, never the unavailable refusal: {document}"
    );
    assert_eq!(
        document["result"]["counts"]["fetch-failed"],
        serde_json::json!(3),
        "{document}"
    );
    let files = document["result"]["files"]
        .as_array()
        .expect("the per-file array");
    assert_eq!(files.len(), 3, "{document}");
    for file in files {
        assert_eq!(file["status"], serde_json::json!("fetch-failed"), "{file}");
        let detail = file["detail"]
            .as_str()
            .expect("a fetch-failed row says why");
        assert!(
            detail.contains("could not be fetched from the network"),
            "the row is the engine's fetch failure: {detail}"
        );
        for forbidden in ["has no data at this address", "ant-backend", "compiled in"] {
            assert!(
                !detail.contains(forbidden),
                "an unreachable network is reported in the network class — neither as absence \
                 nor as a missing backend (`{forbidden}`): {detail}"
            );
        }
        let target = PathBuf::from(file["target"].as_str().expect("a target"));
        assert!(
            !target.exists(),
            "nothing was written: {}",
            target.display()
        );
    }
    assert!(
        run.stderr.contains(HOOK_ARMED) && run.stderr.contains(READER_CONNECT_TRACE),
        "the vault was opened and the network was asked. stderr:\n{}",
        run.stderr
    );
}

/// **D170 §2 R3 — the work's own network, and the two refusals it moves after
/// the passphrase.** Over a `devnet` work, in a build with a backend:
///
/// 1. `--network arbitrum-one` names a network the work was not sealed on:
///    a **usage error (2)**, never a silent override, naming both networks.
/// 2. No devnet definition in sight: a **usage error (2)** naming
///    `ANTSEAL_DEVNET_ENV`. For `restore` alone this lands **after the
///    passphrase** — the definition depends on the network the vault records
///    — and the hook's armed trace is the process-level proof that the vault
///    had been unlocked when it did.
///
/// Neither run attempts a connection or writes a file: both refusals are
/// answerable from the unlocked record alone.
#[cfg(feature = "ant-backend")]
#[test]
fn the_works_own_network_is_used_and_both_network_refusals_follow_the_passphrase() {
    use antseal_cli::upgrade_hook::HOOK_ARMED;

    let scratch = Scratch::new("r3-network");
    let (vault, work_id) = fully_cached_fixture("r3-network");
    let dead = dead_devnet_export(&scratch.0);
    let out_dir = scratch.join("restored");
    let out_arg = out_dir.to_str().expect("a utf-8 scratch path").to_owned();

    let mismatched = spawn_over(
        vault.layout.root(),
        &scratch.0,
        &[
            "--json",
            "--network",
            "arbitrum-one",
            "--passphrase-fd",
            "0",
            "restore",
            &work_id,
            "-o",
            &out_arg,
        ],
        Some(&dead),
    );
    let undefined = spawn_over(
        vault.layout.root(),
        &scratch.0,
        &[
            "--json",
            "--passphrase-fd",
            "0",
            "restore",
            &work_id,
            "-o",
            &out_arg,
        ],
        None,
    );

    for (label, run, must_name) in [
        (
            "an explicit --network that is not the work's",
            &mismatched,
            ["sealed on `devnet`", "--network arbitrum-one"],
        ),
        (
            "a devnet work with no devnet definition",
            &undefined,
            ["ANTSEAL_DEVNET_ENV", "devnet"],
        ),
    ] {
        assert_eq!(run.code, Some(2), "{label}: stderr:\n{}", run.stderr);
        let document = run.document();
        assert_eq!(
            document["error"]["class"],
            serde_json::json!("usage"),
            "{label}: {document}"
        );
        let message = document["error"]["message"]
            .as_str()
            .expect("a message")
            .to_owned();
        for fragment in must_name {
            assert!(
                message.contains(fragment),
                "{label}: the refusal names `{fragment}`: {message}"
            );
        }
        assert!(
            run.stderr.contains(HOOK_ARMED),
            "{label}: refused AFTER the passphrase — the vault had been unlocked. stderr:\n{}",
            run.stderr
        );
        assert!(
            !run.stderr.contains(READER_CONNECT_TRACE),
            "{label}: refused BEFORE any connection. stderr:\n{}",
            run.stderr
        );
        assert!(!out_dir.exists(), "{label}: nothing was written");
    }
}

/// The only work in a fixture vault.
fn only_work(store: &WorkStore<'_>) -> SealId {
    let works = store.list_works().expect("list");
    assert_eq!(works.len(), 1, "the fixture vault holds one work");
    works[0]
}
