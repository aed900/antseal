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
/// export: passphrase-unavailable; import over the fixture vault: the
/// refusal → consent-not-obtained). Extends as handlers land.
fn expected_class(name: &str) -> (i32, &'static str) {
    match name {
        "vault export" => (11, "passphrase-unavailable"),
        "vault import" => (10, "consent-not-obtained"),
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
            "init" | "seal" | "list" | "restore" => CliError::NotImplemented {
                command: match name {
                    "init" => "init",
                    "seal" => "seal",
                    "list" => "list",
                    _ => "restore",
                },
                milestone: Milestone::M1,
            },
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
