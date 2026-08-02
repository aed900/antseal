//! U3 acceptance suite: the abort-not-hang harness and the one-document
//! contract, driven against the REAL binary for every command of the
//! frozen surface × machine-mode flag combinations, under a watchdog —
//! plus the committed envelope fixtures (the schema registry's teeth).
//!
//! NON-SECRET: fixture passphrases and paths only.

use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::process::{Command as Process, Stdio};
use std::time::{Duration, Instant};

use antseal_cli::machine::{ALL_COMMAND_NAMES, MINIMAL_ARGV, all_specs};
use antseal_cli::vault::kdf::KdfSelection;
use antseal_cli::vault::layout::VaultLayout;
use antseal_cli::vault::session::create_vault;
use antseal_core::crypto::secrets::SecretBuf;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

/// Watchdog budget per spawned command. Generous (2-core CI, debug
/// build) — a machine-mode command that has not exited in two minutes is
/// hanging on input that can never come, which is exactly the regression
/// this harness exists to catch.
const WATCHDOG: Duration = Duration::from_secs(120);

struct TestDir(PathBuf);

impl TestDir {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "antseal-cli-machine-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("create test dir");
        TestDir(dir)
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct Captured {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

/// Spawn the binary with stdin closed (machine mode by construction) and
/// a real watchdog: a child that outlives the budget is killed and the
/// test fails loudly — abort-not-HANG is the assertion, so the harness
/// must be able to lose.
fn spawn_watched(vault_dir: &Path, args: &[&str]) -> Captured {
    let mut child = Process::new(env!("CARGO_BIN_EXE_antseal"))
        .args(args)
        .env("ANTSEAL_DIR", vault_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn antseal");

    // Drain the pipes on threads so a chatty child can never block on a
    // full pipe while we poll.
    let mut stdout_pipe = child.stdout.take().expect("stdout pipe");
    let mut stderr_pipe = child.stderr.take().expect("stderr pipe");
    let out_thread = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stdout_pipe.read_to_end(&mut buf);
        buf
    });
    let err_thread = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stderr_pipe.read_to_end(&mut buf);
        buf
    });

    let deadline = Instant::now() + WATCHDOG;
    let code = loop {
        match child.try_wait().expect("try_wait") {
            Some(status) => break status.code(),
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("HANG: {args:?} did not exit within {WATCHDOG:?} in machine mode");
            }
            None => std::thread::sleep(Duration::from_millis(25)),
        }
    };
    let stdout = String::from_utf8(out_thread.join().expect("stdout thread")).expect("utf-8");
    let stderr = String::from_utf8(err_thread.join().expect("stderr thread")).expect("utf-8");
    Captured {
        code,
        stdout,
        stderr,
    }
}

/// A vault fixture so the real handlers reach their machine-mode gates.
fn fixture_vault(dir: &TestDir) -> PathBuf {
    let root = dir.0.join("vault");
    let layout = VaultLayout::at(root.clone());
    create_vault(
        &layout,
        &SecretBuf::new(b"correct horse battery staple fixture".to_vec()),
        KdfSelection::Argon2id,
        &mut ChaCha20Rng::from_seed([0x42u8; 32]),
    )
    .expect("create fixture vault");
    root
}

/// What each command must do TODAY in machine mode with no channels
/// supplied: the typed abort class (stub commands: not-implemented;
/// export and `list`: passphrase-unavailable — they must unlock the
/// fixture vault and machine mode never prompts; import over the fixture
/// vault: the refusal → consent-not-obtained). Extends as handlers land.
fn expected_class(name: &str) -> (i32, &'static str) {
    match name {
        "vault export" | "list" => (11, "passphrase-unavailable"),
        "vault import" => (10, "consent-not-obtained"),
        // U11's handler refuses over the fixture vault, absolutely and
        // before it would ask for anything (D39 Decision 4) — so the
        // machine-mode abort it exhibits here is the usage class, not
        // passphrase-unavailable. The refusal is first for a reason:
        // overwriting a vault destroys every sealed work's keys.
        "init" => (2, "usage"),
        // U20's handler refuses at the backend seam before it would ask
        // for a passphrase — a build with no network cannot restore, and
        // collecting a secret first would be rude as well as pointless.
        "restore" => (23, "network-failure"),
        // U13's handler validates the plan FIRST, before the seam, the
        // vault and any secret. The minimal argv names `x.txt`, which
        // does not exist, so what it exhibits here is D46 rule 4's
        // ordinary I/O class — and that is the point: an argument problem
        // is answerable without a network, a vault or a passphrase.
        "seal" => (4, "io-error"),
        _ => (3, "not-implemented"),
    }
}

/// The harness: every command × {plain, --json} × closed stdin. Asserts
/// abort-not-hang with the right class, stdout purity in both modes, and
/// valid envelopes under --json.
#[test]
fn every_command_aborts_not_hangs_in_machine_mode() {
    let dir = TestDir::new("harness");
    let vault_root = fixture_vault(&dir);

    for (argv, name) in MINIMAL_ARGV.iter().zip(ALL_COMMAND_NAMES) {
        let args: Vec<&str> = argv[1..].to_vec(); // strip the "antseal" argv[0]
        let (want_code, want_class) = expected_class(name);

        // Plain mode: typed abort, empty stdout.
        let plain = spawn_watched(&vault_root, &args);
        assert_eq!(
            plain.code,
            Some(want_code),
            "{name} plain: {}",
            plain.stderr
        );
        assert!(
            plain.stdout.is_empty(),
            "{name} plain mode must write no stdout on error; got {:?}",
            plain.stdout
        );
        assert!(!plain.stderr.is_empty(), "{name}: human copy on stderr");

        // --json mode: same code, exactly one envelope on stdout.
        let mut json_args = vec!["--json"];
        json_args.extend(&args);
        let json = spawn_watched(&vault_root, &json_args);
        assert_eq!(json.code, Some(want_code), "{name} --json: {}", json.stderr);
        let doc: serde_json::Value = serde_json::from_str(json.stdout.trim_end_matches('\n'))
            .unwrap_or_else(|e| panic!("{name}: stdout is not one JSON document: {e}"));
        assert_eq!(doc["v"], serde_json::json!(1), "{name}");
        assert_eq!(doc["command"], serde_json::json!(name), "{name}");
        assert_eq!(doc["network"], serde_json::json!("arbitrum-one"), "{name}");
        assert_eq!(doc["ok"], serde_json::json!(false), "{name}");
        assert_eq!(
            doc["error"]["class"],
            serde_json::json!(want_class),
            "{name}"
        );
        assert_eq!(
            doc["error"]["exit_code"],
            serde_json::json!(want_code),
            "{name}"
        );
        assert!(
            doc["error"]["message"].is_string(),
            "{name}: message present"
        );
        // Zero stray stdout bytes beyond the one document.
        assert_eq!(
            json.stdout.trim_end_matches('\n').lines().count(),
            1,
            "{name}: exactly one stdout line"
        );
    }
}

/// The success side of the contract: a real handler under --json puts
/// exactly one success envelope on stdout with its registered result
/// shape (vault export, driven over the fd channel).
#[test]
fn success_envelope_carries_the_registered_result_shape() {
    let dir = TestDir::new("success");
    let vault_root = fixture_vault(&dir);
    let backup = dir.0.join("backup.sealvault");

    let mut child = Process::new(env!("CARGO_BIN_EXE_antseal"))
        .args([
            "--json",
            "vault",
            "export",
            backup.to_str().expect("utf-8 path"),
            "--passphrase-fd",
            "0",
        ])
        .env("ANTSEAL_DIR", &vault_root)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn antseal");
    use std::io::Write as _;
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(b"correct horse battery staple fixture\n")
        .expect("pipe passphrase");
    let out = child.wait_with_output().expect("wait");
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).expect("utf-8");
    let doc: serde_json::Value =
        serde_json::from_str(stdout.trim_end_matches('\n')).expect("one JSON document");
    assert_eq!(doc["v"], serde_json::json!(1));
    assert_eq!(doc["command"], serde_json::json!("vault export"));
    assert_eq!(doc["ok"], serde_json::json!(true));
    assert_eq!(doc["result"]["self_verified"], serde_json::json!(true));
    assert!(doc["result"]["works"].is_u64());
    assert!(!out.stderr.is_empty(), "human summary on stderr");
}

/// Unparseable argv with a literal `--json` token still yields one JSON
/// document (the best-effort envelope, command/network null); without
/// the token, stdout stays clap's silence.
#[test]
fn unparseable_argv_honors_the_json_token() {
    let dir = TestDir::new("badargv");
    let with_json = spawn_watched(&dir.0, &["--json", "frobnicate"]);
    assert_eq!(with_json.code, Some(2));
    let doc: serde_json::Value = serde_json::from_str(with_json.stdout.trim_end_matches('\n'))
        .expect("one JSON document on the --json bad-argv path");
    assert_eq!(doc["ok"], serde_json::json!(false));
    assert_eq!(doc["command"], serde_json::Value::Null);
    assert_eq!(doc["error"]["class"], serde_json::json!("usage"));
    assert_eq!(doc["error"]["exit_code"], serde_json::json!(2));

    let without = spawn_watched(&dir.0, &["frobnicate"]);
    assert_eq!(without.code, Some(2));
    assert!(without.stdout.is_empty(), "no JSON without the token");
}

/// `--help` stays an intrinsic text surface (documented envelope
/// exemption), even beside `--json`.
#[test]
fn help_is_exempt_from_the_envelope_contract() {
    let dir = TestDir::new("help");
    let out = spawn_watched(&dir.0, &["--json", "--help"]);
    assert_eq!(out.code, Some(0));
    assert!(
        out.stdout.contains("Usage:"),
        "help text on stdout, not an envelope"
    );
}

// ─────────────────────────────────────────────────────────────────────
// The committed envelope fixtures (schema registry)
// ─────────────────────────────────────────────────────────────────────

/// Render the fixture document: for every command, the machine-mode
/// error envelope it exhibits today (deterministic exemplar errors), and
/// for the real handlers their success-envelope example. Committed at
/// `tests/snapshots/json-envelopes.txt`; regenerate deliberately with
/// `ANTSEAL_BLESS=1` and justify the diff — envelope drift is a
/// machine-interface event.
fn render_fixture() -> String {
    use antseal_cli::error::{CliError, Milestone, PassphraseFailure};
    use antseal_cli::machine::{error_envelope, success_envelope};

    let mut out = String::new();
    for name in ALL_COMMAND_NAMES {
        let err = match name {
            "vault export" => CliError::PassphraseUnavailable {
                reason: PassphraseFailure::NoChannel,
            },
            "vault import" => CliError::ImportRefusedExistingVault {
                vault_dir: PathBuf::from("/home/user/.antseal"),
            },
            // A real handler that must unlock the vault: in machine mode
            // without a channel, that is where it stops (U19).
            "list" => CliError::PassphraseUnavailable {
                reason: PassphraseFailure::NoChannel,
            },
            // U20's handler is complete; the storage-backend construction
            // seam it reaches is U36's, shared with `seal`. Rendered by
            // the real producer — a hand-copied string here went stale the
            // first time the message changed, and a fixture that documents
            // text no build emits is worse than none (U19's rule).
            "restore" => antseal_cli::backend::unavailable("restore"),
            // U11's handler is complete. Its registered error exemplar is
            // the D39 absolute refusal — the one a user actually hits —
            // rendered by the real producer rather than hand-copied
            // (U19's rule).
            "init" => antseal_cli::init::existing_vault_refusal(Path::new("/home/user/.antseal")),
            // U13's handler is complete. Its registered exemplar is the
            // M1 anchor-stage gate — the refusal a user who types plain
            // `antseal seal notes.txt` today actually gets, and the one
            // that disappears when U22 lands at M2.
            "seal" => CliError::AnchorStageUnavailable,
            "status" => CliError::NotImplemented {
                command: "status",
                milestone: Milestone::M2,
            },
            _ => CliError::NotImplemented {
                command: match name {
                    "show" => "show",
                    "reveal" => "reveal",
                    _ => "verify",
                },
                milestone: Milestone::M3,
            },
        };
        out.push_str(&format!(
            "[{name}] error\n{}\n",
            error_envelope(name, "arbitrum-one", &err)
        ));
    }
    // Success examples for the commands with real handlers today.
    //
    // `list`'s is rendered by the real U19 renderer over a fixture
    // listing rather than hand-written, so the registered fixture cannot
    // drift from the shape the command actually emits.
    out.push_str(&format!(
        "[init] result\n{}\n",
        success_envelope("init", "arbitrum-one", fixture_init_report().json())
    ));
    out.push_str(&format!(
        "[list] result\n{}\n",
        success_envelope("list", "arbitrum-one", fixture_listing().json())
    ));
    // U13's, rendered by `SealReport::json` — the real producer, so the
    // registered document cannot drift from the command's own output.
    out.push_str(&format!(
        "[seal] result\n{}\n",
        success_envelope("seal", "arbitrum-one", fixture_seal_report().json())
    ));
    // U16's two `--dry-run` documents. Both are rendered by
    // `SealCommandResult::json` — the real producer — and both are
    // registered because a consumer has to branch on them: the truncated
    // rehearsal carries a quote, and the D45 §5 rehearsal over a resumable
    // work deliberately carries none (`quoted: false`). Headers keep the
    // `[seal]` key so the shape test's command-field check still applies.
    out.push_str(&format!(
        "[seal] result (--dry-run)\n{}\n",
        success_envelope("seal", "arbitrum-one", fixture_dry_run().json())
    ));
    out.push_str(&format!(
        "[seal] result (--dry-run over a resumable work)\n{}\n",
        success_envelope("seal", "arbitrum-one", fixture_dry_run_resume().json())
    ));
    out.push_str(&format!(
        "[restore] result\n{}\n",
        success_envelope("restore", "arbitrum-one", fixture_restore().json())
    ));
    out.push_str(&format!(
        "[vault export] result\n{}\n",
        success_envelope(
            "vault export",
            "arbitrum-one",
            serde_json::json!({
                "file": "/home/user/antseal-vault-export-20260801-160000.sealvault",
                "works": 5, "bytes": 4096, "self_verified": true,
            })
        )
    ));
    out.push_str(&format!(
        "[vault import] result\n{}\n",
        success_envelope(
            "vault import",
            "arbitrum-one",
            serde_json::json!({
                "vault_dir": "/home/user/.antseal",
                "works": 5, "wallet_restored": true, "config_restored": true,
            })
        )
    ));
    out
}

/// A completed `seal`, rendered by U13's own report type. The cost is a
/// real-shaped atto-ANT value (18 decimals — past what a JSON number
/// survives, which is why the field is a decimal string).
fn fixture_seal_report() -> antseal_cli::seal_run::SealReport {
    antseal_cli::seal_run::SealReport {
        work_id: [0xA1; 32],
        seal_id: antseal_core::crypto::secrets::SealId::from_bytes([0xE1; 16]),
        cost_atto: 4_200_000_000_000_000_000,
        paid_here: true,
        blob_count: 4,
        resumed: false,
        unanchored: false,
        network: "arbitrum-one".to_owned(),
    }
}

/// D49's truncated rehearsal, built by the **real** U14 gate over a
/// fixture plan and rendered by U16's own result type — so the registered
/// document cannot drift from what the command emits (three prior lanes
/// found hand-copied strings had already gone stale).
///
/// The plan deliberately earns all three U15 warnings — a title, a
/// `--no-fine-tree` match, and a file over
/// `FINE_TREE_ESTIMATE_THRESHOLD_BYTES` — because the `warnings` array is
/// the field a consumer branches on, and a fixture that only ever showed
/// it empty would document nothing about its shape.
///
/// The balances are larger than the quote on purpose: a shortfall exits
/// before any document is produced, so the funded case is the only one
/// this envelope can exhibit.
///
/// NON-SECRET: the wallet is a repeated byte pattern, unmistakably not a
/// real account.
fn fixture_dry_run() -> antseal_cli::seal_run::SealCommandResult {
    use antseal_cli::pipeline::ConsentRequest;
    use antseal_cli::seal_consent::{ConsentPrompt, SealConsent};
    use antseal_cli::seal_plan::{PlannedFile, SealPlan};
    use antseal_cli::seal_run::SealCommandResult;
    use antseal_cli::seal_warnings::FINE_TREE_ESTIMATE_THRESHOLD_BYTES;
    use antseal_cli::vault::store::SealShapingFlags;
    use antseal_core::content::FileFlags;
    use antseal_core::crypto::secrets::SealId;
    use antseal_net::network::EvmAddress20;
    use antseal_net::{BalanceReport, CostQuote};

    struct NeverAsked;
    impl ConsentPrompt for NeverAsked {
        fn ask(&mut self) -> Result<bool, antseal_cli::error::CliError> {
            panic!("a fixture render must never prompt");
        }
    }

    let plan = SealPlan {
        files: vec![
            PlannedFile {
                as_given: "notes.txt".to_owned(),
                absolute: "/home/user/work/notes.txt".to_owned(),
                size: 27,
                flags: FileFlags::new(),
            },
            PlannedFile {
                as_given: "data/blob.bin".to_owned(),
                absolute: "/home/user/work/data/blob.bin".to_owned(),
                size: FINE_TREE_ESTIMATE_THRESHOLD_BYTES,
                flags: FileFlags::new().with_no_fine_tree(),
            },
            PlannedFile {
                as_given: "scan.tiff".to_owned(),
                absolute: "/home/user/work/scan.tiff".to_owned(),
                size: FINE_TREE_ESTIMATE_THRESHOLD_BYTES,
                flags: FileFlags::new(),
            },
        ],
        shaping: SealShapingFlags {
            title: Some("thesis draft".to_owned()),
            no_fine_tree: vec!["*.bin".to_owned()],
            no_anchor: true,
            ..SealShapingFlags::default()
        },
        network: antseal_net::NetworkId::ArbitrumOne,
        dry_run: true,
        yes: false,
    };
    let quote = CostQuote {
        blobs: Vec::new(),
        total_ant_atto: 4_200_000_000_000_000_000,
        gas_estimate_wei: 21_000_000_000_000,
    };
    let mut prompt = NeverAsked;
    let gate = SealConsent::new(
        &plan,
        BalanceReport {
            wallet: EvmAddress20::from_bytes([0x5A; 20]),
            ant_atto: 9_000_000_000_000_000_000,
            gas_wei: 1_000_000_000_000_000,
        },
        Vec::new(),
        false,
        true,
        true,
        1_798_762_000,
        &mut prompt,
    );
    let mut report = gate.report_for(&ConsentRequest {
        seal_id: SealId::from_bytes([0xE1; 16]),
        quote: &quote,
        blob_count: 5,
        prior: None,
        resume: false,
        proofs_expired: false,
    });
    report.dry_run = true;
    SealCommandResult::DryRun(Box::new(report))
}

/// D45 §5's rehearsal over a resumable work: the plan and nothing else.
/// Registered separately because it is a **different shape** — no quote,
/// no balances, `quoted: false` — and a consumer that assumed the
/// document above would break on it.
fn fixture_dry_run_resume() -> antseal_cli::seal_run::SealCommandResult {
    use antseal_cli::pipeline::journal::SealState;
    use antseal_cli::seal_resume::{ResumeCandidate, resume_plan_lines};
    use antseal_cli::seal_run::SealCommandResult;
    use antseal_cli::vault::store::{SealShapingFlags, WorkState};
    use antseal_core::crypto::secrets::SealId;

    // Built through the real `resume_plan_lines` renderer rather than a
    // hand-written array: three prior lanes found hand-copied strings had
    // drifted from what the command emits.
    SealCommandResult::ResumePlan(resume_plan_lines(&ResumeCandidate {
        seal_id: SealId::from_bytes([0xE4; 16]),
        absolute_paths: vec!["/home/user/work/big.bin".to_owned()],
        as_given_paths: vec!["big.bin".to_owned()],
        shaping: SealShapingFlags {
            no_anchor: true,
            ..SealShapingFlags::default()
        },
        network: "arbitrum-one".to_owned(),
        state: WorkState::IncompletePostPay,
        journal_state: Some(SealState::Paid),
    }))
}

/// A completed `init`, rendered by U11's own report type so the
/// registered document cannot drift from what the command emits. The
/// address is the secp256k1 generator's — a published public constant,
/// unmistakably not a real wallet — and there is deliberately no key
/// material in the shape at all.
fn fixture_init_report() -> antseal_cli::init::InitReport {
    use antseal_cli::init::InitReport;
    use antseal_net::NetworkId;

    InitReport {
        address: "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf".to_owned(),
        network: NetworkId::ArbitrumOne,
        vault_dir: PathBuf::from("/home/user/.antseal"),
        wallet_source: "generate",
        kdf: "argon2id",
        asked: Vec::new(),
    }
}

/// A two-row listing covering the shapes a consumer must handle: a
/// finished work with a cost, and an unfinished one carrying the D45
/// resume hint, the D37 clock, and U25's reserved slot.
fn fixture_listing() -> antseal_cli::listing::WorkListing {
    use antseal_cli::listing::{ResumeClock, ResumeHint, WorkListing, WorkRow};
    use antseal_cli::pipeline::journal::SealState;
    use antseal_cli::vault::store::WorkState;
    use antseal_core::crypto::secrets::SealId;

    WorkListing {
        works: vec![
            WorkRow {
                work_id: Some([0xA1; 32]),
                seal_id: SealId::from_bytes([0xE1; 16]),
                title: Some("thesis draft".to_owned()),
                sealed_at_unix_secs: Some(1_798_762_000),
                network: "arbitrum-one".to_owned(),
                state: WorkState::Complete,
                fine_state: Some(SealState::Complete),
                unanchored: false,
                degraded: false,
                cost_atto: Some(4_200_000_000_000_000_000),
                resume: None,
                pending_anchors: None,
            },
            WorkRow {
                work_id: Some([0xA4; 32]),
                seal_id: SealId::from_bytes([0xE4; 16]),
                title: None,
                sealed_at_unix_secs: Some(1_798_761_800),
                network: "devnet".to_owned(),
                state: WorkState::IncompletePostPay,
                fine_state: Some(SealState::Paid),
                unanchored: true,
                degraded: false,
                cost_atto: Some(1_000_000_000_000_000_000),
                resume: Some(ResumeHint {
                    invocation: "antseal seal big.bin --no-anchor --network devnet".to_owned(),
                    clock: ResumeClock::TimeBoxed,
                }),
                pending_anchors: None,
            },
        ],
    }
}

/// A restore run covering the statuses a consumer must branch on: one
/// written, one confirmed identical, one refused, one that never verified
/// (D48 §3's rows, and U20's registered per-file status array).
fn fixture_restore() -> antseal_cli::restore_out::RestoreOutput {
    use antseal_cli::pipeline::{ByteSource, ManifestSource};
    use antseal_cli::restore_out::{FileReport, FileStatus, RestoreOutput};

    let dir = PathBuf::from(format!("antseal-restore-{}", "a1".repeat(32)));
    RestoreOutput {
        work_id: [0xA1; 32],
        output_dir: dir.clone(),
        manifest_source: ManifestSource::Network,
        files: vec![
            FileReport {
                file_id: 0,
                recorded_path: "notes.txt".to_owned(),
                target: dir.join("notes.txt"),
                status: FileStatus::Restored,
                detail: None,
                bytes: Some(27),
                source: Some(ByteSource::RawMirror),
            },
            FileReport {
                file_id: 1,
                recorded_path: "data/blob.bin".to_owned(),
                target: dir.join("data/blob.bin"),
                status: FileStatus::AlreadyRestored,
                detail: None,
                bytes: Some(9),
                source: Some(ByteSource::Raw),
            },
            FileReport {
                file_id: 2,
                recorded_path: "draft.txt".to_owned(),
                target: dir.join("draft.txt"),
                status: FileStatus::RefusedOverwrite,
                detail: Some(
                    "a different file already exists here and was left exactly as it was"
                        .to_owned(),
                ),
                bytes: Some(31),
                source: Some(ByteSource::Canonical),
            },
            FileReport {
                file_id: 3,
                recorded_path: "tampered.txt".to_owned(),
                target: dir.join("tampered.txt"),
                status: FileStatus::VerificationFailed,
                detail: Some(
                    "the canonical bytes of this file do not match the commitment the manifest \
                     records"
                        .to_owned(),
                ),
                bytes: None,
                source: None,
            },
        ],
    }
}

#[test]
fn envelope_fixtures_match_the_committed_snapshot() {
    let rendered = render_fixture();
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/snapshots/json-envelopes.txt");
    if std::env::var_os("ANTSEAL_BLESS").is_some() {
        std::fs::write(&path, &rendered).expect("write blessed snapshot");
        return;
    }
    let committed = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "missing committed envelope fixture at {}: {e}\n(generate once with \
             ANTSEAL_BLESS=1 and review the diff)",
            path.display()
        )
    });
    assert!(
        committed == rendered,
        "the JSON envelope drifted from the committed fixture {} — machine-interface \
         changes are reviewed, versioned events (regenerate with ANTSEAL_BLESS=1)",
        path.display()
    );
}

/// The shape test over the committed fixture: every command has a
/// registered entry, every envelope carries exactly the v1 keys, every
/// error object exactly the U2 keys.
#[test]
fn every_command_has_a_registered_fixture_with_the_v1_shape() {
    let rendered = render_fixture();
    let mut seen = Vec::new();
    let mut lines = rendered.lines();
    while let Some(header) = lines.next() {
        let name = header
            .strip_prefix('[')
            .and_then(|h| h.split(']').next())
            .expect("fixture header");
        let doc: serde_json::Value =
            serde_json::from_str(lines.next().expect("fixture body")).expect("fixture parses");
        let obj = doc.as_object().expect("envelope is an object");
        let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect();
        keys.sort_unstable();
        if doc["ok"] == serde_json::json!(false) {
            assert_eq!(keys, ["command", "error", "network", "ok", "v"], "{name}");
            let err = doc["error"].as_object().expect("error object");
            let mut ekeys: Vec<&str> = err.keys().map(String::as_str).collect();
            ekeys.sort_unstable();
            assert_eq!(ekeys, ["class", "exit_code", "message"], "{name}");
        } else {
            assert_eq!(keys, ["command", "network", "ok", "result", "v"], "{name}");
        }
        assert_eq!(doc["command"], serde_json::json!(name), "{name}");
        seen.push(name.to_owned());
    }
    for name in ALL_COMMAND_NAMES {
        assert!(
            seen.iter().any(|s| s == name),
            "{name} lacks a registered fixture — a command cannot ship without one"
        );
    }
}

/// The prompt-class registry is complete and its declared channels are
/// real (the in-module tests pin the table; this pins the harness's own
/// dependency on it so registry and harness cannot drift apart).
#[test]
fn registry_and_harness_enumerate_the_same_surface() {
    assert_eq!(all_specs().len(), MINIMAL_ARGV.len());
    for (spec, name) in all_specs().iter().zip(ALL_COMMAND_NAMES) {
        assert_eq!(spec.name, name);
    }
}
