//! **S19 — the M1 clean-tree restore drill.**
//!
//! The milestone's capability proof: seal a work on a live devnet, take a
//! `vault export`, then reconstruct the user's files **on a clean machine**
//! from that backup plus the network, and nothing else.
//!
//! Run by `scripts/e2e-devnet.sh` (registry row S19). Locally:
//!
//! ```text
//! scripts/devnet/local-up --nodes 14
//! ANTSEAL_DEVNET_ENV=$PWD/.devnet/env \
//!     cargo test -p antseal-cli --features ant-backend --test e2e_restore -- --nocapture
//! scripts/devnet/local-down
//! ```
//!
//! # "A clean machine" is a real process, not a mutated environment
//!
//! S19 asks for a fresh HOME/config dir, an empty working tree, no staged
//! data and no source files. Setting `HOME` in-process is not available:
//! `std::env::set_var` is `unsafe` in edition 2024 and `unsafe_code` is
//! denied workspace-wide — and it would be a weak simulation anyway, since
//! the rest of the process keeps every path it had already resolved.
//!
//! So the restore half runs in **this test binary re-executed** with
//! `env_clear()`, a fresh `HOME`, a fresh `XDG_CONFIG_HOME`, an empty
//! working directory, and exactly three inbound facts: where the backup
//! file is, where to import it, and where the devnet is. That process has
//! no way to reach the sealing vault (deleted), the staged ciphertexts
//! (never exported) or the source bytes — it is not told the run tag, so it
//! cannot even recompute the fixtures. Everything it produces must have
//! come from the backup or the wire.
//!
//! The parent holds the originals out of band and does the byte comparison.
//!
//! # The S29 dependency
//!
//! This suite was blocked until S29: `vault export` applied D43 §3's cache
//! exclusion to the whole journal area, so a complete work lost the
//! encrypted manifest's `{address, nonce}` locator and became unfindable on
//! a content-addressed network. The fix scoped the exclusion to staged
//! **unit** blobs, so entries 0-2 survive and the units do not. This suite
//! asserts both halves of that directly: the imported journal carries
//! exactly `[STATE, PLAN, MANIFEST_BLOB]`, and every restored file reports
//! `from_cache == 0` — the units really came off the wire.
//!
//! # D170 — the same capability through the spawned binary
//!
//! The S19 rows above drive the library (`RestoreEngine` over
//! `SealBackend::connect`), which is all any process could reach while
//! `commands::restore` refused in every build. The `devnet_d170_…` rows below
//! drive the **release-feature binary** the user runs instead, over the
//! handlers D170 wired: `restore` byte-identical and then idempotent,
//! `vault import` then `restore` on a clean home, and `reveal` →
//! `verify --live --json` reporting the manifest row persisted, beside a
//! negative control whose only network is a dead loopback port. Sealing still
//! happens in-process — it is the precondition, not the subject — and every
//! assertion about restoring, revealing or verifying is read off a process's
//! exit code and its one `--json` document.
//!
//! NON-SECRET: every fixture byte string is documented and run-tagged; `W`
//! never leaves the vault, and the backup is an encrypted export.

#![cfg(feature = "ant-backend")]

mod common;

#[path = "common/spawn.rs"]
mod spawn;

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Instant;

use antseal_cli::backend::{SealBackend, runtime};
use antseal_cli::pipeline::{
    MANIFEST_BLOB_ENTRY, ManifestSource, NoBarriers, PLAN_ENTRY, Pipeline, RestoreEngine,
    STATE_ENTRY, SealFile, SealRequest, SealResult, UNIT_ENTRY_BASE, VaultJournal,
};
use antseal_cli::vault::export::{export_vault, import_vault};
use antseal_cli::vault::kdf::KdfSelection;
use antseal_cli::vault::layout::VaultLayout;
use antseal_cli::vault::session::{create_vault, unlock_vault};
use antseal_cli::vault::store::{SealShapingFlags, WorkStore};
use antseal_core::content::{FileFlags, SplitMode};
use antseal_core::crypto::sig_policy::SigPolicy;
use antseal_net::{NetworkConfig, NetworkId, WalletKey};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

use common::devnet::{CapturedReceipts, gate, run_seed, run_tag, serial};
use common::{RecordingGate, ScriptedConsent, passphrase, rng};

// ─────────────────────────────────────────────────────────────────────
// Clean-machine child protocol
// ─────────────────────────────────────────────────────────────────────

const CHILD_ENV: &str = "ANTSEAL_S19_CHILD";
const BACKUP_ENV: &str = "ANTSEAL_S19_BACKUP";
const IMPORT_ENV: &str = "ANTSEAL_S19_IMPORT";
const OUT_ENV: &str = "ANTSEAL_S19_OUT";

/// Import the backup, then restore — the whole clean-machine flow.
const SCENARIO_IMPORT_RESTORE: &str = "import-restore";
/// Skip the import and try to restore anyway — the negative control.
const SCENARIO_NO_VAULT: &str = "no-vault";

// ─────────────────────────────────────────────────────────────────────
// Fixtures — the three shapes S19 names
// ─────────────────────────────────────────────────────────────────────

/// Text whose raw bytes differ from its canonical rendition in three
/// independent ways at once: a UTF-8 BOM, CRLF endings, and an NFD
/// sequence (`e` + U+0301) that NFC folds to `é`. It therefore carries a
/// **raw mirror**, and restoring it byte-identically has to go through
/// that mirror rather than through the canonical bytes.
fn crlf_bom_text() -> Vec<u8> {
    let mut bytes = vec![0xEF, 0xBB, 0xBF];
    bytes.extend_from_slice(format!("clean tree {}\r\n", run_tag()).as_bytes());
    bytes.extend_from_slice("cafe\u{0301} line\r\n".as_bytes());
    bytes
}

/// LF/NFC/BOM-free text with blank-line paragraphs — several units under
/// `--split blank-lines`.
fn multi_unit_text() -> Vec<u8> {
    format!(
        "para one for {tag}\n\npara two\n\npara three\n\npara four\n",
        tag = run_tag()
    )
    .into_bytes()
}

/// Non-UTF-8 bytes — no canonicalization, no mirror.
fn binary_blob() -> Vec<u8> {
    let mut bytes = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0xFF];
    bytes.extend_from_slice(&run_seed("s19-binary"));
    bytes
}

struct Originals {
    crlf: Vec<u8>,
    multi: Vec<u8>,
    binary: Vec<u8>,
}

impl Originals {
    fn new() -> Self {
        Self {
            crlf: crlf_bom_text(),
            multi: multi_unit_text(),
            binary: binary_blob(),
        }
    }

    fn files(&self) -> Vec<SealFile<'_>> {
        vec![
            SealFile {
                path_as_given: "notes.txt",
                path_absolute: "/w/notes.txt",
                bytes: &self.crlf,
                flags: FileFlags::new(),
            },
            SealFile {
                path_as_given: "chapters/long.txt",
                path_absolute: "/w/chapters/long.txt",
                bytes: &self.multi,
                flags: FileFlags::new().with_split(SplitMode::BlankLines),
            },
            SealFile {
                path_as_given: "data/blob.bin",
                path_absolute: "/w/data/blob.bin",
                bytes: &self.binary,
                flags: FileFlags::new(),
            },
        ]
    }

    fn expected(&self, path: &str) -> &[u8] {
        match path {
            "notes.txt" => &self.crlf,
            "chapters/long.txt" => &self.multi,
            "data/blob.bin" => &self.binary,
            other => panic!("no original recorded for {other}"),
        }
    }
}

fn request<'a>(files: &'a [SealFile<'a>]) -> SealRequest<'a> {
    SealRequest {
        files,
        title: format!("S19 {}", run_tag()),
        claimed_time_unix_secs: 1_800_000_000,
        app_version: "antseal-m1-gate/1".to_owned(),
        network: NetworkId::Devnet,
        no_anchor: true,
        degraded: false,
        dry_run: false,
        sig_policy: SigPolicy::hybrid(),
        shaping: SealShapingFlags::default(),
    }
}

// ─────────────────────────────────────────────────────────────────────
// The clean machine
// ─────────────────────────────────────────────────────────────────────

/// Re-execute this binary as a clean machine and wait for it to finish.
///
/// `env_clear()` is the substance of the claim: the child inherits nothing
/// — not `HOME`, not `XDG_CONFIG_HOME`, not the run tag, not even the
/// parent's working directory. It is then given back exactly what a real
/// clean machine would have: a home, a shell `PATH`, the devnet's address,
/// and the backup file the user carried over.
fn run_clean_machine(
    scenario: &str,
    home: &Path,
    cwd: &Path,
    backup: &Path,
    import_to: &Path,
    out: &Path,
) -> std::process::Output {
    let exe = std::env::current_exe().expect("the test binary's own path");
    let devnet_env =
        std::env::var_os("ANTSEAL_DEVNET_ENV").expect("the gate already checked this is set");
    let mut command = std::process::Command::new(exe);
    command
        .args([
            "--exact",
            "clean_machine_child",
            "--nocapture",
            "--test-threads=1",
        ])
        .env_clear()
        // Q16 / D99 R4.1. `env_clear()` is the ONE operation that defeats the
        // environment arm of the no-real-anchor-network gate, and it defeats
        // it even in CI, where the workflow arms the variable workflow-wide:
        // the parent inherits it and this child is then handed an empty
        // environment. Nothing else in the harness can notice — a disarmed
        // gate reaches the network and every assertion still passes, which is
        // Q16 §2's recorded failure exactly. So the clean machine is given the
        // arming back explicitly, and `check-anchor-net.py` R4 refuses an
        // `env_clear()` in a test source that does not re-arm.
        .env(spawn::NO_REAL_ANCHOR_NETWORK, "1")
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_DATA_HOME", home.join("data"))
        .env("TMPDIR", home.join("tmp"))
        .env("ANTSEAL_DEVNET_ENV", devnet_env)
        .env(CHILD_ENV, scenario)
        .env(BACKUP_ENV, backup)
        .env(IMPORT_ENV, import_to)
        .env(OUT_ENV, out)
        .current_dir(cwd);
    command.output().expect("run the clean machine")
}

/// The clean-machine body. A no-op unless spawned as one.
#[test]
fn clean_machine_child() {
    let Some(scenario) = std::env::var_os(CHILD_ENV) else {
        return;
    };
    let scenario = scenario.to_string_lossy().into_owned();
    let backup = PathBuf::from(std::env::var_os(BACKUP_ENV).expect("backup path"));
    let import_to = PathBuf::from(std::env::var_os(IMPORT_ENV).expect("import path"));
    let out = PathBuf::from(std::env::var_os(OUT_ENV).expect("output path"));
    std::fs::create_dir_all(&out).expect("mk output dir");

    let layout = VaultLayout::at(import_to);

    if scenario == SCENARIO_NO_VAULT {
        // The negative control: no import, so there is no vault to unlock.
        // The failure must be about the missing vault, in words a user can
        // act on — not a panic, not a generic I/O error.
        match unlock_vault(&layout, &passphrase()) {
            Ok(_) => panic!("a vault was unlocked on a machine that has none"),
            Err(error) => {
                std::fs::write(out.join("no-vault-error.txt"), error.to_string())
                    .expect("record the error");
                eprintln!("clean machine: no vault -> {error}");
                return;
            }
        }
    }
    assert_eq!(scenario, SCENARIO_IMPORT_RESTORE, "unknown scenario");

    // 1. Import the carried-over backup. This is the ONLY local state this
    //    machine is given.
    import_vault(&backup, &layout, || Ok(passphrase()), &mut rng()).expect("import the backup");
    let unlocked = unlock_vault(&layout, &passphrase()).expect("unlock the imported vault");
    let store = WorkStore::new(&unlocked);

    let works = store.list_works().expect("enumerate works");
    assert_eq!(works.len(), 1, "the backup carried exactly one work");
    let seal_id = works[0];

    // 2. The S29 invariant, checked on the imported side: the record-scale
    //    head survived and the staged unit ciphertexts did not. If entry 2
    //    (the encrypted manifest's {address, nonce}) were missing, the
    //    manifest would be unfindable and the restore below could not run
    //    at all — that was the blocker.
    let entries = store.list_journal_entries(&seal_id).expect("entries");
    assert_eq!(
        entries,
        vec![STATE_ENTRY, PLAN_ENTRY, MANIFEST_BLOB_ENTRY],
        "an imported complete work must carry its record-scale head and nothing else"
    );
    assert!(
        store
            .get_journal_entry(&seal_id, UNIT_ENTRY_BASE)
            .expect("read")
            .is_none(),
        "a staged unit ciphertext survived the export — the restore below would not need the \
         network"
    );

    // 3. Restore: backup + network, nothing else.
    let Some((config, _env, key)) = gate() else {
        panic!("the clean machine was started without a live devnet");
    };
    let sink = CapturedReceipts::new();
    let rt = runtime().expect("runtime");
    let report = rt.block_on(async {
        let backend = SealBackend::connect(&config, &key, sink.clone())
            .await
            .expect("the clean machine reaches the devnet");
        RestoreEngine::new(&backend, &store)
            .restore(&seal_id)
            .await
            .expect("restore from the imported vault")
    });

    assert_eq!(sink.fired(), 0, "a restore must never pay");

    // 4. Hand the bytes back to the parent, which holds the originals.
    let mut summary = String::new();
    for file in report.verified() {
        let path = out.join(format!("{}.bin", file.file_id));
        std::fs::write(&path, &file.bytes).expect("write restored bytes");
        summary.push_str(&format!(
            "{}|{}|{}|{}\n",
            file.file_id, file.recorded_path, file.from_cache, file.from_network
        ));
    }
    let failed: Vec<String> = report
        .failed()
        .map(|f| format!("{}:{:?}", f.recorded_path, f.error))
        .collect();
    std::fs::write(out.join("summary.txt"), summary).expect("write summary");
    std::fs::write(out.join("failed.txt"), failed.join("\n")).expect("write failures");
    std::fs::write(
        out.join("manifest-source.txt"),
        format!("{:?}", report.manifest_source),
    )
    .expect("write manifest source");
    eprintln!(
        "clean machine: restored {} file(s), manifest from {:?}, {} failed",
        report.files.len(),
        report.manifest_source,
        failed.len()
    );
}

/// Parse the child's summary into `(file_id, path, from_cache, from_network)`.
fn read_summary(out: &Path) -> Vec<(u64, String, usize, usize)> {
    let text = std::fs::read_to_string(out.join("summary.txt")).expect("the child wrote a summary");
    text.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            let cols: Vec<&str> = line.split('|').collect();
            assert_eq!(cols.len(), 4, "malformed summary row {line:?}");
            (
                cols[0].parse().expect("file id"),
                cols[1].to_owned(),
                cols[2].parse().expect("from_cache"),
                cols[3].parse().expect("from_network"),
            )
        })
        .collect()
}

// ─────────────────────────────────────────────────────────────────────
// S19 accept rows 1 and 2
// ─────────────────────────────────────────────────────────────────────

/// **S19 accept rows 1 and 2**: a work sealed on the devnet is restored
/// byte-identically on a clean machine that has only the vault export and
/// the network — CRLF/BOM/NFD text through its raw mirror, a binary file,
/// and a multi-unit `--split` file.
#[test]
fn a_clean_machine_restores_from_the_vault_backup_and_the_network() {
    let _guard = serial();
    let Some((config, env, key)) = gate() else {
        return;
    };
    eprintln!(
        "S19: run tag {}, {} nodes, chain {}",
        run_tag(),
        env.node_count(),
        env.chain_id()
    );

    let originals = Originals::new();
    let files = originals.files();

    // The sealing machine.
    let stage = std::env::temp_dir().join(format!("antseal-s19-{}", run_tag()));
    let sealing_root = stage.join("sealing-machine");
    std::fs::create_dir_all(&sealing_root).expect("mk sealing root");
    let sealing_layout = VaultLayout::at(sealing_root.join("vault"));
    create_vault(
        &sealing_layout,
        &passphrase(),
        KdfSelection::Argon2id,
        &mut rng(),
    )
    .expect("create the sealing vault");

    let started = Instant::now();
    let (work_id, backup) = {
        let unlocked = unlock_vault(&sealing_layout, &passphrase()).expect("unlock");
        let mut journal_rng = ChaCha20Rng::from_seed(run_seed("s19-journal"));
        let journal = VaultJournal::new(WorkStore::new(&unlocked), &mut journal_rng);
        let sink = CapturedReceipts::new();
        let gate_double = RecordingGate::new();
        let consent = ScriptedConsent::always_yes();

        let rt = runtime().expect("runtime");
        let outcome = rt.block_on(async {
            let backend = SealBackend::connect(&config, &key, sink.clone())
                .await
                .expect("connect");
            let pipeline = Pipeline::new(&backend, &gate_double, &journal, &consent, &NoBarriers);
            let SealResult::Sealed(outcome) = pipeline
                .seal(
                    &request(&files),
                    &mut ChaCha20Rng::from_seed(run_seed("s19-seal")),
                )
                .await
                .expect("the three-file work seals")
            else {
                panic!("expected Sealed");
            };
            outcome
        });

        // The backup the user carries to the new machine. It lives outside
        // both machines' trees, as a USB stick would.
        let backup = stage.join("carried.sealvault");
        export_vault(&unlocked, &passphrase(), &backup, &mut rng()).expect("vault export");
        (outcome.work_id, backup)
    };

    // Simulate the clean machine: the sealing vault is destroyed outright,
    // so nothing local survives except the backup file.
    std::fs::remove_dir_all(&sealing_root).expect("wipe the sealing machine");
    assert!(
        !sealing_root.exists(),
        "the sealing machine's state must be gone"
    );

    let clean_home = stage.join("clean-machine/home");
    let clean_cwd = stage.join("clean-machine/empty-tree");
    let out = stage.join("clean-machine/restored");
    for dir in [&clean_home, &clean_cwd, &out] {
        std::fs::create_dir_all(dir).expect("mk clean-machine dir");
    }
    std::fs::create_dir_all(clean_home.join("tmp")).expect("mk child tmp");
    assert!(
        std::fs::read_dir(&clean_cwd)
            .expect("read the empty tree")
            .next()
            .is_none(),
        "the clean machine's working tree must start empty"
    );

    let output = run_clean_machine(
        SCENARIO_IMPORT_RESTORE,
        &clean_home,
        &clean_cwd,
        &backup,
        &clean_home.join("vault"),
        &out,
    );
    assert!(
        output.status.success(),
        "the clean machine failed:\n--- stdout ---\n{}\n--- stderr ---\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    // The working tree stayed empty: restore returns bytes, it does not
    // write files (that is U20's job, D48 §2).
    assert!(
        std::fs::read_dir(&clean_cwd)
            .expect("read the empty tree")
            .next()
            .is_none(),
        "the clean machine wrote into its working tree"
    );

    let failures =
        std::fs::read_to_string(out.join("failed.txt")).expect("the child recorded failures");
    assert!(
        failures.trim().is_empty(),
        "files failed to restore on the clean machine: {failures}"
    );
    let manifest_source = std::fs::read_to_string(out.join("manifest-source.txt"))
        .expect("the child recorded the manifest source");
    assert_eq!(
        manifest_source,
        format!("{:?}", ManifestSource::VaultCopy),
        "the imported backup should carry the plaintext manifest (entry 1)"
    );

    // Byte-identical, all three shapes.
    let rows = read_summary(&out);
    assert_eq!(rows.len(), 3, "three files restored, got {}", rows.len());
    for (file_id, path, from_cache, from_network) in &rows {
        let restored =
            std::fs::read(out.join(format!("{file_id}.bin"))).expect("read restored bytes");
        assert_eq!(
            restored,
            originals.expected(path),
            "{path} did not restore byte-identically on the clean machine"
        );
        // The S29 fix's own assertion: the units came off the wire, not
        // from a cache the export should never have carried.
        assert_eq!(
            *from_cache, 0,
            "{path} used a cached unit — the export was not lean, and this drill proved nothing \
             about the network"
        );
        assert!(
            *from_network > 0,
            "{path} produced no unit from the network"
        );
    }

    // The BOM, the CRLF endings and the NFD sequence all survived — the
    // raw mirror did its job.
    let crlf_row = rows
        .iter()
        .find(|(_, path, _, _)| path == "notes.txt")
        .expect("notes.txt restored");
    let crlf = std::fs::read(out.join(format!("{}.bin", crlf_row.0))).expect("read");
    assert!(
        crlf.starts_with(&[0xEF, 0xBB, 0xBF]) && crlf.windows(2).any(|w| w == b"\r\n"),
        "the BOM and CRLF endings did not survive the clean-machine round trip"
    );
    assert!(
        crlf.windows(2).any(|w| w == [0x65, 0xCC]),
        "the NFD sequence was normalized away — the raw mirror was not used"
    );

    let multi = rows
        .iter()
        .find(|(_, path, _, _)| path == "chapters/long.txt")
        .expect("multi-unit file restored");
    assert!(
        multi.3 >= 4,
        "the --split file should have produced several units, got {}",
        multi.3
    );

    eprintln!(
        "S19 OK: work {} sealed, exported, sealing machine wiped, restored on a clean machine \
         from backup+network alone ({} files, {} units off the wire, 0 from cache), {:.1}s",
        antseal_cli::pipeline::hex32(&work_id),
        rows.len(),
        rows.iter().map(|r| r.3).sum::<usize>(),
        started.elapsed().as_secs_f64()
    );
}

// ─────────────────────────────────────────────────────────────────────
// S19 accept row 3 — the negative control
// ─────────────────────────────────────────────────────────────────────

/// **S19 accept row 3**: the same clean machine, run again with **no
/// vault**, fails with a clear no-vault error.
///
/// This is what stops row 1 from being a tautology: if the flow succeeded
/// without the backup, the backup was never what made it work.
#[test]
fn a_clean_machine_without_the_vault_fails_with_a_clear_no_vault_error() {
    let _guard = serial();
    if gate().is_none() {
        return;
    }

    let stage = std::env::temp_dir().join(format!("antseal-s19-negative-{}", run_tag()));
    let clean_home = stage.join("home");
    let clean_cwd = stage.join("empty-tree");
    let out = stage.join("out");
    for dir in [&clean_home, &clean_cwd, &out] {
        std::fs::create_dir_all(dir).expect("mk dir");
    }
    std::fs::create_dir_all(clean_home.join("tmp")).expect("mk child tmp");

    let output = run_clean_machine(
        SCENARIO_NO_VAULT,
        &clean_home,
        &clean_cwd,
        &stage.join("there-is-no-backup.sealvault"),
        &clean_home.join("vault"),
        &out,
    );
    assert!(
        output.status.success(),
        "the negative-control child crashed instead of reporting a clean failure:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let message = std::fs::read_to_string(out.join("no-vault-error.txt"))
        .expect("the child recorded the refusal");
    let lowered = message.to_lowercase();
    assert!(
        lowered.contains("vault"),
        "the refusal does not mention the vault, so a user cannot act on it: {message}"
    );
    assert!(
        lowered.contains("not")
            || lowered.contains("no ")
            || lowered.contains("missing")
            || lowered.contains("absent"),
        "the refusal does not say the vault is absent: {message}"
    );
    // It must not be a generic I/O splat.
    assert!(
        !lowered.contains("os error 2") || lowered.contains("vault"),
        "the refusal is a bare ENOENT with no explanation: {message}"
    );
    eprintln!("S19 negative control OK: no vault -> {}", message.trim());
}

// ─────────────────────────────────────────────────────────────────────
// D170 §2 R8 — the wired handlers, through the spawned binary
// ─────────────────────────────────────────────────────────────────────

/// Create a vault at `layout` and seal [`Originals`] into it on the live
/// devnet, keeping every D43 cache copy. Returns the work id.
///
/// In-process on purpose: sealing is these rows' precondition, not their
/// subject, and `seal`'s own binary path is `tests/seal_command.rs`'s.
fn seal_on_devnet(
    layout: &VaultLayout,
    config: &NetworkConfig,
    key: &WalletKey,
    originals: &Originals,
    label: &str,
) -> [u8; 32] {
    create_vault(layout, &passphrase(), KdfSelection::Argon2id, &mut rng())
        .expect("create the sealing vault");
    let unlocked = unlock_vault(layout, &passphrase()).expect("unlock");
    let mut journal_rng = ChaCha20Rng::from_seed(run_seed(&format!("{label}-journal")));
    let journal = VaultJournal::new(WorkStore::new(&unlocked), &mut journal_rng);
    let sink = CapturedReceipts::new();
    let gate_double = RecordingGate::new();
    let consent = ScriptedConsent::always_yes();
    let files = originals.files();
    let rt = runtime().expect("runtime");
    rt.block_on(async {
        let backend = SealBackend::connect(config, key, sink.clone())
            .await
            .expect("connect");
        let pipeline = Pipeline::new(&backend, &gate_double, &journal, &consent, &NoBarriers);
        let SealResult::Sealed(outcome) = pipeline
            .seal(
                &request(&files),
                &mut ChaCha20Rng::from_seed(run_seed(&format!("{label}-seal"))),
            )
            .await
            .expect("the three-file work seals")
        else {
            panic!("expected Sealed");
        };
        outcome.work_id
    })
}

/// What a spawned `antseal` answered.
struct Answer {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

impl Answer {
    /// The one `--json` document on stdout, or a panic that shows both
    /// streams.
    fn document(&self) -> serde_json::Value {
        serde_json::from_str(self.stdout.trim_end_matches('\n')).unwrap_or_else(|error| {
            panic!(
                "stdout is not one JSON document ({error}).\nstdout:\n{}\nstderr:\n{}",
                self.stdout, self.stderr
            )
        })
    }

    /// Both streams, for an assertion message.
    fn streams(&self) -> String {
        format!("stdout:\n{}\nstderr:\n{}", self.stdout, self.stderr)
    }
}

/// Where a spawned invocation finds its vault.
enum VaultAt<'a> {
    /// `ANTSEAL_DIR` names it.
    Dir(&'a Path),
    /// A fresh `HOME` holds it at `~/.antseal`, and `ANTSEAL_DIR` is unset.
    Home(&'a Path),
}

/// Spawn the release-feature binary: its vault at `vault`, `cwd` as its
/// working directory, `devnet_env` as the only devnet definition it can see,
/// and — when `passphrase_on_stdin` — the fixture passphrase on fd 0.
fn antseal_on_devnet(
    vault: VaultAt<'_>,
    cwd: &Path,
    args: &[&str],
    devnet_env: Option<&Path>,
    passphrase_on_stdin: bool,
) -> Answer {
    let mut command = spawn::antseal();
    command
        .args(args)
        .current_dir(cwd)
        .env_remove("RUST_LOG")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    match vault {
        VaultAt::Dir(dir) => {
            command.env("ANTSEAL_DIR", dir);
        }
        VaultAt::Home(home) => {
            command.env("HOME", home).env_remove("ANTSEAL_DIR");
        }
    }
    match devnet_env {
        Some(path) => {
            command.env("ANTSEAL_DEVNET_ENV", path);
        }
        None => {
            command.env_remove("ANTSEAL_DEVNET_ENV");
        }
    }
    command.stdin(if passphrase_on_stdin {
        Stdio::piped()
    } else {
        Stdio::null()
    });
    let mut child = command.spawn().expect("spawn antseal");
    if passphrase_on_stdin {
        // Ignored on purpose: a command that refuses before reading closes
        // the pipe first, and that is the command doing its job.
        let _ = child
            .stdin
            .as_mut()
            .expect("stdin is piped")
            .write_all(common::FIXTURE_PASSPHRASE);
        drop(child.stdin.take());
    }
    let out = child.wait_with_output().expect("wait for antseal");
    Answer {
        code: out.status.code(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

/// The live devnet's export path — already proven readable by `gate()`.
fn devnet_export() -> PathBuf {
    PathBuf::from(std::env::var_os("ANTSEAL_DEVNET_ENV").expect("the gate checked this is set"))
}

/// A devnet definition that reaches **nothing**: one bootstrap peer on a
/// loopback UDP port bound and released a moment ago — D170 §2 R7's
/// negative-control export. Written from scratch rather than copied from the
/// live export, so no key line is ever duplicated into a scratch file.
///
/// NON-SECRET: a walletless export; Anvil's well-known contract addresses.
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

/// Assert every original sits byte-identical under `root`, at its recorded
/// path.
fn assert_originals_under(root: &Path, originals: &Originals, venue: &str) {
    for path in ["notes.txt", "chapters/long.txt", "data/blob.bin"] {
        let restored = std::fs::read(root.join(path))
            .unwrap_or_else(|error| panic!("{venue}: {path} was not restored: {error}"));
        assert_eq!(
            restored,
            originals.expected(path),
            "{venue}: {path} did not restore byte-identically"
        );
    }
}

/// **U90 `Accept` row 1 (D170 §2 R8): a spawned `restore` on a devnet-sealed
/// work writes byte-identical originals, and a second run reports every file
/// already restored with exit 0.**
///
/// The network is made the **only** source before the binary runs: every
/// D43 unit copy **and** the vault's plaintext manifest copy are deleted, so
/// a successful run must have fetched the manifest by its journaled locator
/// and every unit off the wire, through the wallet-less reader — the
/// `manifest_source: "network"` member reads that back. The work records
/// `devnet` while the invocation's default network is `arbitrum-one`, so the
/// first run is also D170 §2 R3's witness that the work's own network is the
/// one used; the re-run names `--network devnet` explicitly, the accepted
/// form of the flag.
#[test]
fn devnet_d170_a_spawned_restore_is_byte_identical_and_a_re_run_is_already_restored() {
    let _guard = serial();
    let Some((config, _env, key)) = gate() else {
        return;
    };
    let originals = Originals::new();
    let stage = std::env::temp_dir().join(format!("antseal-d170-td1-{}", run_tag()));
    std::fs::create_dir_all(&stage).expect("mk stage");
    let layout = VaultLayout::at(stage.join("vault"));
    let work_id = antseal_cli::pipeline::hex32(&seal_on_devnet(
        &layout, &config, &key, &originals, "d170-td1",
    ));

    // The network, and nothing else.
    {
        let unlocked = unlock_vault(&layout, &passphrase()).expect("unlock");
        let store = WorkStore::new(&unlocked);
        let works = store.list_works().expect("list");
        assert_eq!(works.len(), 1, "one work");
        let mut deleted = 0usize;
        for entry in store.list_journal_entries(&works[0]).expect("entries") {
            if entry == PLAN_ENTRY || entry >= UNIT_ENTRY_BASE {
                store
                    .delete_journal_entry(&works[0], entry)
                    .expect("delete");
                deleted += 1;
            }
        }
        assert!(
            deleted >= 4,
            "the plaintext manifest and at least three unit copies were removed: {deleted}"
        );
        assert_eq!(
            store.list_journal_entries(&works[0]).expect("entries"),
            vec![STATE_ENTRY, MANIFEST_BLOB_ENTRY],
            "only the state and the encrypted manifest's locator remain"
        );
    }

    let out = stage.join("restored");
    let out_arg = out.to_str().expect("a utf-8 stage path").to_owned();
    let first = antseal_on_devnet(
        VaultAt::Dir(layout.root()),
        &stage,
        &[
            "--json",
            "--passphrase-fd",
            "0",
            "restore",
            &work_id,
            "-o",
            &out_arg,
        ],
        Some(&devnet_export()),
        true,
    );
    assert_eq!(
        first.code,
        Some(0),
        "the release-feature binary restores a devnet-sealed work.\n{}",
        first.streams()
    );
    let document = first.document();
    assert_eq!(document["ok"], serde_json::json!(true), "{document}");
    assert_eq!(
        document["result"]["manifest_source"],
        serde_json::json!("network"),
        "the manifest came off the wire: {document}"
    );
    assert_eq!(
        document["result"]["counts"]["restored"],
        serde_json::json!(3),
        "{document}"
    );
    assert_originals_under(&out, &originals, "the first run");

    let again = antseal_on_devnet(
        VaultAt::Dir(layout.root()),
        &stage,
        &[
            "--json",
            "--network",
            "devnet",
            "--passphrase-fd",
            "0",
            "restore",
            &work_id,
            "-o",
            &out_arg,
        ],
        Some(&devnet_export()),
        true,
    );
    assert_eq!(
        again.code,
        Some(0),
        "D48 §3: a re-run confirms and exits 0.\n{}",
        again.streams()
    );
    let document = again.document();
    assert_eq!(
        document["result"]["counts"]["already-restored"],
        serde_json::json!(3),
        "every file already restored: {document}"
    );
    assert_eq!(
        document["result"]["counts"]["restored"],
        serde_json::json!(0),
        "and nothing rewritten: {document}"
    );
    assert_originals_under(&out, &originals, "the re-run");

    let _ = std::fs::remove_dir_all(&stage);
    eprintln!(
        "D170 T-D1 OK: work {work_id} restored by the binary from the network, then confirmed"
    );
}

/// **U90 `Accept` row 2 (D170 §2 R8): a spawned `vault import`, then a
/// spawned `restore`, on a clean home, restores byte-identical originals.**
///
/// The sealing machine is wiped after its export, so the clean home holds
/// exactly what a user carries: the backup file. The imported vault holds no
/// unit copy (S29's lean export, asserted by S19 above), so every unit comes
/// off the wire; the restore writes to the default output directory under
/// the working directory, and `ANTSEAL_DIR` is unset so the vault is found
/// where a user's would be — `~/.antseal`.
#[test]
fn devnet_d170_a_spawned_vault_import_then_restore_on_a_clean_home_is_byte_identical() {
    let _guard = serial();
    let Some((config, _env, key)) = gate() else {
        return;
    };
    let originals = Originals::new();
    let stage = std::env::temp_dir().join(format!("antseal-d170-td2-{}", run_tag()));
    let sealing = stage.join("sealing-machine");
    std::fs::create_dir_all(&sealing).expect("mk sealing machine");
    let sealing_layout = VaultLayout::at(sealing.join("vault"));
    let work = seal_on_devnet(&sealing_layout, &config, &key, &originals, "d170-td2");
    let work_id = antseal_cli::pipeline::hex32(&work);
    let backup = stage.join("carried.sealvault");
    {
        let unlocked = unlock_vault(&sealing_layout, &passphrase()).expect("unlock");
        export_vault(&unlocked, &passphrase(), &backup, &mut rng()).expect("vault export");
    }
    std::fs::remove_dir_all(&sealing).expect("wipe the sealing machine");

    let home = stage.join("clean-home");
    let cwd = home.join("empty-tree");
    std::fs::create_dir_all(&cwd).expect("mk the clean home");
    let backup_arg = backup.to_str().expect("a utf-8 stage path").to_owned();

    let imported = antseal_on_devnet(
        VaultAt::Home(&home),
        &cwd,
        &[
            "--json",
            "--passphrase-fd",
            "0",
            "vault",
            "import",
            &backup_arg,
        ],
        None,
        true,
    );
    assert_eq!(
        imported.code,
        Some(0),
        "the clean home imports the carried backup.\n{}",
        imported.streams()
    );
    assert!(
        home.join(".antseal").is_dir(),
        "the import landed at the clean home's default vault path"
    );

    let restored = antseal_on_devnet(
        VaultAt::Home(&home),
        &cwd,
        &["--json", "--passphrase-fd", "0", "restore", &work_id],
        Some(&devnet_export()),
        true,
    );
    assert_eq!(
        restored.code,
        Some(0),
        "the clean home restores from the backup and the network.\n{}",
        restored.streams()
    );
    let document = restored.document();
    assert_eq!(
        document["result"]["counts"]["restored"],
        serde_json::json!(3),
        "{document}"
    );
    let default_dir = cwd.join(format!("antseal-restore-{work_id}"));
    assert_eq!(
        document["result"]["output_dir"],
        serde_json::json!(format!("antseal-restore-{work_id}")),
        "D48 §1's default, work-scoped, under the working directory: {document}"
    );
    assert_originals_under(&default_dir, &originals, "the clean home");

    let _ = std::fs::remove_dir_all(&stage);
    eprintln!("D170 T-D2 OK: work {work_id} imported and restored by the binary on a clean home");
}

/// **U75's restated `Accept` and R81 `Accept` row 1's binary half (D170
/// §2 R7): a spawned `reveal`, then `verify --live --json`, reports the
/// manifest row and every unit persisted — with a dead-bootstrap negative
/// control yielding an Inconclusive live section at the same exit code.**
///
/// The exit code is compared with the same bundle's **offline** `verify`, so
/// "the live layer reaches no exit code" (D69 §3 R6) is read off three
/// processes rather than assumed. The divergent manifest row stays proven at
/// the library route (`tests/verify_live_manifest.rs`): a real network never
/// serves `Different` through this adapter (R79).
#[test]
fn devnet_d170_reveal_then_verify_live_is_persisted_and_a_dead_network_inconclusive() {
    const MANIFEST_SUBJECT: &str = "encrypted manifest";

    let _guard = serial();
    let Some((config, _env, key)) = gate() else {
        return;
    };
    let originals = Originals::new();
    let stage = std::env::temp_dir().join(format!("antseal-d170-td3-{}", run_tag()));
    std::fs::create_dir_all(&stage).expect("mk stage");
    let layout = VaultLayout::at(stage.join("vault"));
    let work_id = antseal_cli::pipeline::hex32(&seal_on_devnet(
        &layout, &config, &key, &originals, "d170-td3",
    ));

    let bundle = stage.join("whole-work.sealproof");
    let bundle_arg = bundle.to_str().expect("a utf-8 stage path").to_owned();
    let revealed = antseal_on_devnet(
        VaultAt::Dir(layout.root()),
        &stage,
        &[
            "--json",
            "--passphrase-fd",
            "0",
            "reveal",
            &work_id,
            "--all",
            "--yes",
            "-o",
            &bundle_arg,
        ],
        Some(&devnet_export()),
        true,
    );
    assert_eq!(
        revealed.code,
        Some(0),
        "the binary reveals the cached work.\n{}",
        revealed.streams()
    );
    assert!(bundle.is_file(), "the bundle was written");
    let units = &revealed.document()["result"]["units"];
    assert_eq!(
        units["from_network"],
        serde_json::json!(0),
        "reveal still serves a cached work from its cache (U72; U91 wires the rest): {units}"
    );

    let offline = antseal_on_devnet(
        VaultAt::Dir(&stage.join("no-vault-here")),
        &stage,
        &["--json", "verify", &bundle_arg],
        None,
        false,
    );
    let offline_code = offline.code;
    assert_eq!(
        offline.document()["ok"],
        serde_json::json!(true),
        "the revealed bundle verifies offline.\n{}",
        offline.streams()
    );

    let live = antseal_on_devnet(
        VaultAt::Dir(&stage.join("no-vault-here")),
        &stage,
        &[
            "--json",
            "--network",
            "devnet",
            "verify",
            &bundle_arg,
            "--live",
        ],
        Some(&devnet_export()),
        false,
    );
    assert_eq!(
        live.code,
        offline_code,
        "the live layer reaches no exit code (D69 §3 R6).\n{}",
        live.streams()
    );
    let document = live.document();
    let section = &document["result"]["live"];
    assert_eq!(
        section["verdict"],
        serde_json::json!("all-persisted"),
        "a live devnet holds every blob this work stored: {section}"
    );
    let checked = section["counts"]["checked"].as_u64().expect("a count");
    assert!(
        checked >= 2,
        "units and the manifest were asked about: {section}"
    );
    assert_eq!(
        section["counts"]["identical"],
        serde_json::json!(checked),
        "{section}"
    );
    let rows = section["rows"].as_array().expect("the live rows");
    let manifest_rows: Vec<&serde_json::Value> = rows
        .iter()
        .filter(|row| row["subject"] == MANIFEST_SUBJECT)
        .collect();
    assert_eq!(
        manifest_rows.len(),
        1,
        "exactly one manifest row (R81): {section}"
    );
    assert_eq!(
        manifest_rows[0]["outcome"],
        serde_json::json!("identical"),
        "R81 row 1 through the binary: the encrypted manifest is persisted: {section}"
    );

    // ── the negative control: a network nothing answers on ───────────────
    let dead = dead_devnet_export(&stage);
    let control = antseal_on_devnet(
        VaultAt::Dir(&stage.join("no-vault-here")),
        &stage,
        &[
            "--json",
            "--network",
            "devnet",
            "verify",
            &bundle_arg,
            "--live",
        ],
        Some(&dead),
        false,
    );
    assert_eq!(
        control.code,
        offline_code,
        "an unreachable network moves no exit code either.\n{}",
        control.streams()
    );
    let document = control.document();
    let section = &document["result"]["live"];
    assert_eq!(
        section["verdict"],
        serde_json::json!("inconclusive"),
        "a dead bootstrap is Inconclusive: {section}"
    );
    assert_eq!(
        section["counts"]["fetch_failed"], section["counts"]["checked"],
        "every row is a fetch failure: {section}"
    );
    assert_eq!(
        section["counts"]["not_found"],
        serde_json::json!(0),
        "and not one is reported absent — an unreachable network is never absence \
         (D170 §2 R12): {section}"
    );

    let _ = std::fs::remove_dir_all(&stage);
    eprintln!(
        "D170 T-D3 OK: work {work_id} revealed; verify --live all-persisted ({checked} subjects) \
         and Inconclusive over a dead bootstrap, both at exit {offline_code:?}"
    );
}
