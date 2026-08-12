//! U3 acceptance suite: the abort-not-hang harness and the one-document
//! contract, driven against the REAL binary for every command of the
//! frozen surface × machine-mode flag combinations, under a watchdog —
//! plus the committed envelope fixtures (the schema registry's teeth).
//!
//! NON-SECRET: fixture passphrases and paths only.

#[path = "common/spawn.rs"]
mod spawn;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::process::Stdio;
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
    let mut child = spawn::antseal()
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
/// export, `list` and `status`: passphrase-unavailable — they must unlock
/// the fixture vault and machine mode never prompts; import over the
/// fixture vault: the refusal → consent-not-obtained). Extends as handlers
/// land.
fn expected_class(name: &str) -> (i32, &'static str) {
    match name {
        // U23's handler joined this arm rather than gaining one of its
        // own: `status` reads the vault and nothing else, so it stops
        // exactly where `list` and `vault export` stop, for the reason
        // they stop there. **U27's `show` joined it for the same reason**
        // — it reads the vault and, by construction, nothing else (it
        // holds no backend at all, D67 §1 j), so machine mode with no
        // passphrase channel stops it at the same gate.
        "vault export" | "list" | "status" | "show" => (11, "passphrase-unavailable"),
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
        // **U28/U29's `reveal` joined it at the same seam**: unlike `show`,
        // which holds no backend at all (D67 §1 j), a reveal may have to
        // fetch a ciphertext this vault no longer caches, so it stops where
        // `restore` stops — before the passphrase and before U29's
        // irreversible-disclosure screen could be painted.
        "restore" | "reveal" => (23, "network-failure"),
        // U13's handler validates the plan FIRST, before the seam, the
        // vault and any secret. The minimal argv names `x.txt`, which
        // does not exist, so what it exhibits here is D46 rule 4's
        // ordinary I/O class — and that is the point: an argument problem
        // is answerable without a network, a vault or a passphrase.
        // U30's handler needs no vault and never prompts, so what it
        // exhibits under the minimal argv is the same shape `seal` does:
        // the bundle path it was given does not exist, which is D46 rule
        // 4's ordinary I/O class. **This arm was `not-implemented` (3)
        // until U30**, which was the last stub of the frozen surface — no
        // build can emit that class for any command now, and the wildcard
        // is gone with it so a new subcommand must state its own row here.
        "seal" | "verify" => (4, "io-error"),
        other => panic!("{other} has no registered machine-mode expectation"),
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

    let mut child = spawn::antseal()
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
    use antseal_cli::error::{CliError, PassphraseFailure};
    use antseal_cli::machine::{error_envelope, success_envelope, success_envelope_raw};

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
            // U13's handler is complete and U22 wired its anchor stage, so
            // the M1 "anchoring arrives in M2" exemplar is gone. What a
            // plain `antseal seal notes.txt` meets in a default-feature
            // build is the same storage-backend seam `restore` reaches
            // (U36's, shared) — rendered by the real producer rather than
            // hand-copied, per U19's rule.
            "seal" => antseal_cli::backend::unavailable("seal"),
            // U28's flow and U29's consent gate are complete, so the
            // not-implemented exemplar this row carried is gone: what a
            // default-feature build actually meets is `restore`'s seam,
            // rendered by the real producer rather than hand-copied (U19's
            // rule).
            "reveal" => antseal_cli::backend::unavailable("reveal"),
            // U23's handler is complete. Like `list`, it must unlock the
            // vault, so in machine mode without a channel that is exactly
            // where it stops — rendered by the real producer rather than
            // hand-copied (U19's rule).
            "status" => CliError::PassphraseUnavailable {
                reason: PassphraseFailure::NoChannel,
            },
            // U27's handler is complete and reaches no backend at all, so
            // like `list` and `status` it stops at the passphrase gate.
            "show" => CliError::PassphraseUnavailable {
                reason: PassphraseFailure::NoChannel,
            },
            // U30's handler is complete, and it was the LAST stub of the
            // frozen surface — so the not-implemented envelope this row
            // carried for five milestones is gone, and no build can emit
            // one for any command. `verify` needs no vault and never
            // prompts, so its registered refusal is a verdict one: D69's
            // `verify-bundle-rejected` (40), rendered by the real producer
            // over a genuinely tampered bundle rather than hand-copied
            // (U19's rule). It is the shape a consumer branches on — one
            // class for every rejection code, with the specific code in the
            // freely-rewordable message.
            _ => verify_rejection(),
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
    // U27's, rendered by `WorkUnits::json` — the real producer. The
    // registered document is the shape a `reveal --units` chooser branches
    // on: the per-unit `selectable` flag (spec line 92's rule, machine
    // form), the byte-range in its own committed domain, and the D67 §3 R6
    // snippet **value** — form, raw window, truncation, provenance — with
    // the absent arm as an explicit `null` rather than a missing key.
    out.push_str(&format!(
        "[show] result\n{}\n",
        success_envelope("show", "arbitrum-one", fixture_show().json())
    ));
    // U23's, rendered by `WorkStatus::json` — the real producer. The
    // registered document is the shape a consumer branches on: a per-anchor
    // `state` from A18's seven frozen names, `headline_eligible` beside it,
    // the source's verified/claimed bit, and the receipt in its **own**
    // field rather than as an anchor (D98 rider 4).
    out.push_str(&format!(
        "[status] result\n{}\n",
        success_envelope("status", "arbitrum-one", fixture_status().json())
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
    // U28's, rendered by `RevealReport::json` — the real producer. The
    // registered document is what a `reveal --json` caller branches on: the
    // resolved bundle path (always present, and identical in every mode —
    // D68 §3 R5), the disclosed unit ids, the receipt opt-in as a boolean,
    // and the one canonical verifier URL (D62 §3 R8) so a wrapper never
    // hard-codes an address of its own. The exemplar is a `--units`
    // selection that PROMOTED its file to a full reveal, pulling the raw
    // mirror in with it (D70) — a `--all` document would show the fields
    // without showing the case a chooser has to notice.
    out.push_str(&format!(
        "[reveal] result\n{}\n",
        success_envelope("reveal", "arbitrum-one", fixture_reveal().json())
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
    // U30's, rendered by `VerifyRun::json` — the real producer — and wrapped
    // by `success_envelope_raw`, because D65 §5 carries `result.report`
    // BYTE-VERBATIM and `success_envelope`'s `serde_json::Value` parameter
    // cannot express that (a `Value` round trip alphabetizes the report's
    // keys and destroys D29 rule 1's declaration order).
    //
    // The registered document is what a `verify --json` consumer branches
    // on: the four always-present members (`report`, `overlay`, `live`,
    // `verdict` — `null` where the mode was off, never omitted), and D69's
    // verdict datum carrying the rung's stable name beside the exit code
    // the process reports. The exemplar is an UNANCHORED bundle, which is
    // the **nonzero-exit success envelope** — the shape nothing in the tree
    // exercised before U30 and the one D69 §3 R1's third arm exists to make
    // possible.
    out.push_str(&format!(
        "[verify] result\n{}\n",
        success_envelope_raw("verify", "arbitrum-one", &fixture_verify())
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

/// The tampered bundle `verify`'s registered refusal is produced from —
/// R6's constructor with one manifest `canon_commit` bit flipped, which is a
/// tamper-matrix row.
fn tampered_bundle() -> Vec<u8> {
    use antseal_core::test_util::bundle_fixtures::{Selection, Tweak, build_tweaked, shapes};
    let mut tweak = Tweak::none();
    tweak.corrupt_canon_commit = Some(0);
    build_tweaked(
        &shapes::single_text_with_mirror(),
        &Selection::all(1),
        &tweak,
    )
    .bytes
}

/// `verify`'s registered error, from the real producer.
fn verify_rejection() -> antseal_cli::error::CliError {
    use antseal_core::verify::VerifyOptions;
    use antseal_core::verify::orchestration::VerifyModes;
    match antseal_cli::verify_out::run_verify(
        &tampered_bundle(),
        &VerifyOptions::new(),
        VerifyModes::OFFLINE,
        &antseal_cli::verify_host::CollectedInputs::none(),
    ) {
        Ok(_) => panic!("the tampered fixture must not verify"),
        Err(error) => error,
    }
}

/// `verify`'s registered `result` document, from the real producer: an
/// UNANCHORED bundle, so the envelope is a **success at a nonzero exit**.
fn fixture_verify() -> String {
    use antseal_core::test_util::bundle_fixtures::{Selection, build, shapes};
    use antseal_core::verify::VerifyOptions;
    use antseal_core::verify::orchestration::VerifyModes;
    let bundle = build(&shapes::single_text_with_mirror(), &Selection::all(1)).bytes;
    let run = antseal_cli::verify_out::run_verify(
        &bundle,
        &VerifyOptions::new(),
        VerifyModes::OFFLINE,
        &antseal_cli::verify_host::CollectedInputs::none(),
    )
    .expect("the R6 fixture verifies");
    assert_eq!(run.exit_code(), 43, "the exemplar is the UNANCHORED rung");
    run.json().expect("the result document renders")
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
        // U22: the registered exemplar shows a **degraded** anchor stage —
        // one TSA verified, one failed, both calendars pending. That is the
        // shape a consumer has to branch on; an all-green stage would
        // document the fields without documenting the per-endpoint failure
        // arm, which is the only reason they are structured rather than a
        // count. The two counts are deliberately different quantities and
        // separately named (`verified_tsa_tokens` is A20's gate input;
        // `distinct_calendar_routes` is D54 §3's upgrade-route liveness) —
        // neither is a count of independent attesting parties (D92 §5.6).
        anchors: Some(antseal_cli::pipeline::AnchorSummary {
            endpoints: vec![
                antseal_cli::pipeline::AnchorEndpointOutcome {
                    stage: antseal_anchor::gate::AnchorStage::Ots,
                    endpoint: "https://alice.example/calendar".to_owned(),
                    failure_class: None,
                    detail: None,
                },
                antseal_cli::pipeline::AnchorEndpointOutcome {
                    stage: antseal_anchor::gate::AnchorStage::Ots,
                    endpoint: "https://bob.example/calendar".to_owned(),
                    failure_class: None,
                    detail: None,
                },
                antseal_cli::pipeline::AnchorEndpointOutcome {
                    stage: antseal_anchor::gate::AnchorStage::Tsa,
                    endpoint: "https://tsa-one.example/tsr".to_owned(),
                    failure_class: None,
                    detail: None,
                },
                antseal_cli::pipeline::AnchorEndpointOutcome {
                    stage: antseal_anchor::gate::AnchorStage::Tsa,
                    endpoint: "http://tsa-two.example".to_owned(),
                    failure_class: Some("http"),
                    detail: Some("http://tsa-two.example: HTTP 503 (26 bytes of body)".to_owned()),
                },
            ],
            verified_tsa_tokens: 1,
            distinct_calendar_routes: 2,
            degraded: true,
            degradation: vec![
                "tsa http://tsa-two.example [http] http://tsa-two.example: HTTP 503 \
                 (26 bytes of body) (12 ms)"
                    .to_owned(),
                "tsa: 1 verified token(s) from 1 distinct TSA(s); ots: 2 distinct calendar(s)"
                    .to_owned(),
            ],
        }),
        degraded: true,
        network: "arbitrum-one".to_owned(),
        // U18: the registered exemplar shows the nag ON, because that is
        // the shape a consumer has to notice — a first seal in a vault
        // with no recorded backup. `false` would document the field
        // without documenting why it exists.
        export_nag: true,
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
        // U8: the registered exemplar shows the wrap DECLINED (D50's
        // default), because that is what the overwhelming majority of
        // documents look like; the keyfile shape is one nullable string.
        keyfile: None,
        asked: Vec::new(),
    }
}

/// The `status` result document: one work carrying both an OTS anchor that
/// cannot yet prove a time and a TSA anchor that can, plus the receipt.
///
/// Hand-built rather than gathered from a vault, because this suite is about
/// the **envelope** and an Argon2id derivation per fixture would buy nothing.
/// Every value below is a real one — the states come from A18's frozen set
/// and the source strings are the shapes the evaluators actually produce.
fn fixture_status() -> antseal_cli::status::WorkStatus {
    use antseal_cli::status::{AnchorRow, ReceiptRow, WorkStatus};
    use antseal_cli::vault::store::WorkState;
    use antseal_core::anchor::model::AnchorVerdict;
    use antseal_core::crypto::secrets::SealId;
    use antseal_core::verify::report::AnchorKind;

    WorkStatus {
        work_id: Some([0xA1; 32]),
        seal_id: SealId::from_bytes([0xE1; 16]),
        title: Some("thesis draft".to_owned()),
        network: "arbitrum-one".to_owned(),
        state: WorkState::Complete,
        degraded: false,
        anchors: vec![
            AnchorRow {
                slot: "ots-pending".to_owned(),
                verdict: AnchorVerdict::pending(
                    AnchorKind::Ots,
                    Some("https://calendar.example/alice".to_owned()),
                    None,
                ),
            },
            AnchorRow {
                slot: "tsa-0".to_owned(),
                verdict: AnchorVerdict::proven(
                    AnchorKind::Tsa,
                    1_785_000_000,
                    Some("CN=antseal mock TSA signer,O=antseal fixtures".to_owned()),
                    Some("1785600000".to_owned()),
                ),
            },
        ],
        // **D100 R6/§9(v)**: the two damage arrays of the `status` document,
        // spelled exactly as `list` spells its own — one fact, one shape,
        // across both commands. Present and empty on a healthy work: a key
        // that only appeared on damage would leave a damaged work looking
        // exactly like a clean one, and this is the registered document a
        // consumer branches on.
        unclassifiable: Vec::new(),
        damaged: Vec::new(),
        absent: Vec::new(),
        receipt: Some(ReceiptRow {
            transactions: 1,
            block_numbers: vec![377_262_147],
        }),
        upgrade: None,
    }
}

/// A `show` document covering every snippet shape a consumer must branch
/// on, over two files: a text unit with the exact **sealed bytes**, its
/// **raw mirror** (hex, truncated, `selectable: false` — spec line 92), a
/// unit whose snippet came from the **current file** and carries that
/// caveat, and a unit with **no** snippet at all, which rides as `null`
/// rather than as a missing key (D65 §7).
///
/// Hand-built rather than gathered from a vault, for the reason
/// [`fixture_status`] gives: this suite is about the envelope, and an
/// Argon2id derivation plus a full seal per fixture would buy nothing. The
/// *document* is still the real producer's — `WorkUnits::json` — so the
/// registered shape cannot drift from what the command emits.
///
/// NON-SECRET: repeated-byte ids and the same fixture prose the U27 suite
/// seals.
fn fixture_show() -> antseal_cli::show::WorkUnits {
    use antseal_cli::pipeline::ManifestSource;
    use antseal_cli::preview::{
        DisclosurePreview, FilePreview, PreviewRow, PreviewTotals, Snippet, SnippetProvenance,
        SnippetWindow,
    };
    use antseal_cli::show::{FileRow, WorkUnits};
    use antseal_cli::vault::store::WorkState;
    use antseal_core::crypto::secrets::SealId;
    use antseal_core::manifest::{ByteRange, DescriptorKind, FineTreeDomain, UnitKind};

    let row = |unit_id: u64,
               file_id: u64,
               path: &str,
               kind: UnitKind,
               start: u64,
               length: u64,
               snippet: Option<Snippet>| PreviewRow {
        unit_id,
        file_id,
        path: path.to_owned(),
        kind,
        range: ByteRange::new(start, length),
        size: length,
        // `show` selects every normal unit, so every file is fully
        // revealed under D28's predicate and every mirror rides — which is
        // exactly why the table is total over the manifest.
        file_fully_revealed: true,
        snippet,
    };

    WorkUnits {
        work_id: Some([0xA1; 32]),
        seal_id: SealId::from_bytes([0xE1; 16]),
        title: Some("thesis draft".to_owned()),
        network: "arbitrum-one".to_owned(),
        state: WorkState::Complete,
        // Never `network`: `show` holds no backend (D67 §1 j).
        manifest_source: ManifestSource::VaultCopy,
        files: vec![
            FileRow {
                file_id: 0,
                path: "notes.txt".to_owned(),
                kind: DescriptorKind::Text,
                offset_domain: FineTreeDomain::Canonical,
                fine_tree: true,
                size: 25,
                unicode_version: Some("unicode-17.0.0".to_owned()),
                raw_mirror_unit_id: Some(1),
            },
            FileRow {
                file_id: 1,
                path: "data/blob.bin".to_owned(),
                kind: DescriptorKind::Binary,
                offset_domain: FineTreeDomain::Raw,
                fine_tree: true,
                size: 4096,
                unicode_version: None,
                raw_mirror_unit_id: None,
            },
            FileRow {
                file_id: 2,
                path: "archive.tar".to_owned(),
                kind: DescriptorKind::Binary,
                offset_domain: FineTreeDomain::Raw,
                // `--no-fine-tree`: whole-file-reveal only, permanently
                // (spec lines 18/85), and single-unit by D24 — which is
                // why the shape below has exactly one unit.
                fine_tree: false,
                size: 8,
                unicode_version: None,
                raw_mirror_unit_id: None,
            },
        ],
        preview: DisclosurePreview {
            rows: vec![
                row(
                    0,
                    0,
                    "notes.txt",
                    UnitKind::Normal,
                    0,
                    25,
                    Some(Snippet {
                        window: SnippetWindow::Text("café notes\n\nsecond para\n".to_owned()),
                        truncated: false,
                        provenance: SnippetProvenance::SealedBytes,
                    }),
                ),
                row(
                    1,
                    0,
                    "notes.txt",
                    UnitKind::RawMirror,
                    0,
                    32,
                    Some(Snippet {
                        window: SnippetWindow::Hex(vec![
                            0xEF, 0xBB, 0xBF, 0x63, 0x61, 0x66, 0x65, 0xCC, 0x81, 0x20, 0x6E, 0x6F,
                            0x74, 0x65, 0x73, 0x0D,
                        ]),
                        truncated: true,
                        provenance: SnippetProvenance::SealedBytes,
                    }),
                ),
                row(
                    2,
                    1,
                    "data/blob.bin",
                    UnitKind::Normal,
                    0,
                    4096,
                    Some(Snippet {
                        window: SnippetWindow::Hex(vec![0x89, 0x50, 0x4E, 0x47]),
                        truncated: true,
                        provenance: SnippetProvenance::CurrentFile,
                    }),
                ),
                row(3, 2, "archive.tar", UnitKind::Normal, 0, 8, None),
            ],
            files: vec![
                FilePreview {
                    file_id: 0,
                    path: "notes.txt".to_owned(),
                    fully_revealed: true,
                    mirror_rides_along: true,
                },
                FilePreview {
                    file_id: 1,
                    path: "data/blob.bin".to_owned(),
                    fully_revealed: true,
                    mirror_rides_along: false,
                },
                FilePreview {
                    file_id: 2,
                    path: "archive.tar".to_owned(),
                    fully_revealed: true,
                    mirror_rides_along: false,
                },
            ],
            totals: PreviewTotals {
                units: 4,
                bytes: 25 + 32 + 4096 + 8,
                files_touched: 3,
                files_fully_revealed: 3,
                mirror_rides_along: true,
            },
        },
    }
}

/// A three-row listing covering the shapes a consumer must handle: a
/// finished work with a cost, an unfinished one carrying the D45 resume hint
/// and the D37 clock, and one holding an anchor slot that will not read.
///
/// U25's slot is no longer reserved, so every row carries a real
/// `(pending_anchors, nag)` pair rather than the two `null`s no gathered
/// listing produces: row 1 is the nagging class (pending OTS, nothing else
/// proving a time), row 2 the `--no-anchor` one, whose count is a counted
/// zero and not an absent measurement. `None` on both fields means "not
/// computable" and is exercised by `list`'s own suite, not here.
///
/// **Row 3 is D100 R10.3's**, and the reason it is spelled out here rather
/// than left to `list`'s suite is that this fixture hand-builds `WorkRow`
/// literals and **never calls `gather`** — so no behavioural change can reach
/// it. A new field makes it **fail to compile**, which forces an edit and
/// asserts nothing; without a row that actually carries damage,
/// `damaged_anchors` would ship unsnapshotted in the one document that is the
/// registered machine contract. It carries all three of R1's reasons, because
/// the reason is the field a consumer branches on.
fn fixture_listing() -> antseal_cli::listing::WorkListing {
    use antseal_anchor::ots::NagState;
    use antseal_cli::listing::{AnchorDamage, ResumeClock, ResumeHint, WorkListing, WorkRow};
    use antseal_cli::pipeline::anchors::{DamageReason, DamagedSlot};
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
                pending_anchors: Some(2),
                nag: Some(NagState::OnlyPendingOts),
                damaged_anchors: AnchorDamage::default(),
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
                pending_anchors: Some(0),
                nag: Some(NagState::Unanchored),
                damaged_anchors: AnchorDamage::default(),
            },
            WorkRow {
                work_id: Some([0xA7; 32]),
                seal_id: SealId::from_bytes([0xE7; 16]),
                title: Some("damaged anchors".to_owned()),
                sealed_at_unix_secs: Some(1_798_761_600),
                network: "arbitrum-one".to_owned(),
                state: WorkState::Complete,
                fine_state: Some(SealState::Complete),
                unanchored: false,
                degraded: false,
                cost_atto: Some(2_000_000_000_000_000_000),
                resume: None,
                // The nag class is **orthogonal** to the damage and is not
                // suppressed by it (D100 R4): this work does hold a
                // headline-eligible anchor, so `anchored` is true, and the
                // damaged array is what stops it being read as the whole
                // story. A consumer that branched on `nag` alone would call
                // this work clean.
                pending_anchors: Some(0),
                nag: Some(NagState::Anchored),
                damaged_anchors: AnchorDamage {
                    slots: vec![
                        DamagedSlot {
                            slot: "tsa-1".to_owned(),
                            reason: DamageReason::Undecodable {
                                detail: "anchor slot family disagrees with the record kind",
                            },
                        },
                        DamagedSlot {
                            slot: "tsa-2".to_owned(),
                            reason: DamageReason::NewerRecord { found: 3 },
                        },
                        DamagedSlot {
                            slot: "tsa-3".to_owned(),
                            reason: DamageReason::SlotMoved,
                        },
                    ],
                    total_slots: 4,
                },
            },
        ],
    }
}

/// A completed `reveal`, rendered by U28's own report type: a `--units 0`
/// selection over the fixture work, which completes notes.txt and so
/// promotes to a full reveal with its raw mirror riding along (D70), landed
/// at D68's default path with the receipt left out (the default — it exposes
/// the paying wallet).
fn fixture_reveal() -> antseal_cli::reveal_out::RevealReport {
    let work_id = [0xA1; 32];
    antseal_cli::reveal_out::RevealReport {
        work_id,
        bundle_path: antseal_cli::reveal_out::default_bundle_path(&work_id),
        bytes: 18_342,
        files_touched: 1,
        summary: antseal_cli::pipeline::RevealSummary {
            revealed_unit_ids: vec![0, 1],
            files_fully_revealed: vec![0],
            receipt_included: false,
            units_from_cache: 2,
            units_from_network: 0,
        },
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

/// D65 §5's carriage route cannot drift from the one nine commands use:
/// over **every registered success document**, the hand-assembled
/// `success_envelope_raw` and the `serde_json::json!`-built
/// `success_envelope` produce byte-identical envelopes.
///
/// `verify` is the only command whose result reaches stdout through the raw
/// constructor, and it does so because its `report` member must be
/// byte-verbatim. That is a claim about the *result*; this row is a claim
/// about the *wrapper*, and it is what stops a hand-built envelope from
/// quietly growing a different key order, a missing escape or a stray
/// space. Red against any drift, on nine real documents at once.
#[test]
fn the_raw_envelope_is_byte_identical_to_the_value_envelope() {
    use antseal_cli::machine::{success_envelope, success_envelope_raw};

    let rendered = render_fixture();
    let mut lines = rendered.lines();
    let mut checked = 0usize;
    while let Some(header) = lines.next() {
        let body = lines.next().expect("fixture body");
        let doc: serde_json::Value = serde_json::from_str(body).expect("fixture parses");
        if doc["ok"] != serde_json::json!(true) {
            continue;
        }
        let command = doc["command"].as_str().expect("a command");
        let network = doc["network"].as_str().expect("a network");
        let result = doc["result"].clone();
        assert_eq!(
            success_envelope_raw(command, network, &result.to_string()),
            success_envelope(command, network, result).to_string(),
            "{header}: the two envelope constructors disagree"
        );
        checked += 1;
    }
    assert!(
        checked >= 9,
        "only {checked} success documents were checked"
    );

    // The escaping half, which no fixture exercises: a command or network
    // carrying a quote or a backslash must not break the document.
    let hostile = "arb\"one\\";
    let raw = success_envelope_raw("verify", hostile, "null");
    let parsed: serde_json::Value = serde_json::from_str(&raw).expect("still one JSON document");
    assert_eq!(parsed["network"], serde_json::json!(hostile));
    assert!(parsed["result"].is_null());
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
