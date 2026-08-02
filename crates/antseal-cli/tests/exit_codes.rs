//! U2 acceptance suite: the exit-code scheme and the CLI error taxonomy.
//!
//! - the committed code↔class table is pinned literally (any drift is a
//!   deliberate, reviewed event);
//! - every `CliError` variant (and every reason of its reason enums) has
//!   an exemplar whose class, code, and `Display` are asserted — the
//!   Display strings against ONE committed snapshot,
//!   `tests/snapshots/cli-errors.display.txt` (regenerate deliberately
//!   with `ANTSEAL_BLESS=1 cargo test -p antseal-cli`);
//! - decision-mandated distinctions are pinned one test each
//!   (token ≠ gas, D51's class partition, D40's two KDF classes,
//!   D51 routing of the vault-import overwrite refusal);
//! - the binary is spawned to prove the `--json` error object is exactly
//!   one JSON document on stdout with the same exit code as plain mode
//!   (D51 invariant 2).
//!
//! Exemplar field values are non-secret by construction (paths the user
//! typed, counts, versions, amounts, short detail strings) — the same
//! discipline the error type itself enforces by carrying no secret-typed
//! fields (U21 starts here).

use std::collections::HashSet;
use std::path::PathBuf;
use std::process::Command as Process;

use antseal_cli::error::{
    CliError, ConsentOutcome, ErrorClass, Milestone, PassphraseFailure, ResumeSafetyReason,
};

// ─────────────────────────────────────────────────────────────────────
// The committed exit-code table
// ─────────────────────────────────────────────────────────────────────

/// The documented table (module docs of `antseal_cli::error`), literally.
const TABLE: [(ErrorClass, u8, &str); 28] = [
    (ErrorClass::Internal, 1, "internal"),
    (ErrorClass::Usage, 2, "usage"),
    (ErrorClass::NotImplemented, 3, "not-implemented"),
    (ErrorClass::IoError, 4, "io-error"),
    (ErrorClass::ConsentNotObtained, 10, "consent-not-obtained"),
    (
        ErrorClass::PassphraseUnavailable,
        11,
        "passphrase-unavailable",
    ),
    (ErrorClass::VaultAuthFailure, 12, "vault-auth-failure"),
    (ErrorClass::VaultKdfMemory, 13, "vault-kdf-memory"),
    (
        ErrorClass::VaultKdfParamsOutOfRange,
        14,
        "vault-kdf-params-out-of-range",
    ),
    (ErrorClass::VaultLockHeld, 15, "vault-lock-held"),
    (ErrorClass::VaultNewerVersion, 16, "vault-newer-version"),
    (ErrorClass::MalformedConfig, 17, "malformed-config"),
    (ErrorClass::VaultKeyfileMissing, 18, "vault-keyfile-missing"),
    (
        ErrorClass::VaultWrapModeUnsupported,
        19,
        "vault-wrap-mode-unsupported",
    ),
    (
        ErrorClass::InsufficientAntToken,
        20,
        "insufficient-ant-token",
    ),
    (ErrorClass::InsufficientEthGas, 21, "insufficient-eth-gas"),
    (ErrorClass::AnchorGateAbort, 22, "anchor-gate-abort"),
    (ErrorClass::NetworkFailure, 23, "network-failure"),
    (ErrorClass::ResumeSafetyAbort, 24, "resume-safety-abort"),
    (
        ErrorClass::ResumeOverlapNotExact,
        25,
        "resume-overlap-not-exact",
    ),
    (ErrorClass::ResumeFlagMismatch, 26, "resume-flag-mismatch"),
    (ErrorClass::InvalidSealArgument, 27, "invalid-seal-argument"),
    (ErrorClass::RefusedOverwrite, 30, "refused-overwrite"),
    (
        ErrorClass::MalformedRestoreRecord,
        31,
        "malformed-restore-record",
    ),
    (
        ErrorClass::ExportSelfVerifyFailed,
        32,
        "export-self-verify-failed",
    ),
    (ErrorClass::ImportAuthFailed, 33, "import-auth-failed"),
    (ErrorClass::ImportNewerVersion, 34, "import-newer-version"),
    (
        ErrorClass::RestoreVerificationFailed,
        35,
        "restore-verification-failed",
    ),
];

#[test]
fn the_exit_code_table_is_exactly_the_documented_one() {
    assert_eq!(ErrorClass::ALL.len(), TABLE.len(), "table and ALL agree");
    for (class, code, name) in TABLE {
        assert_eq!(class.exit_code(), code, "{name} code");
        assert_eq!(class.name(), name, "{name} identifier");
    }
    let all: HashSet<ErrorClass> = ErrorClass::ALL.into_iter().collect();
    assert_eq!(all.len(), ErrorClass::ALL.len(), "ALL lists no class twice");
    for (class, ..) in TABLE {
        assert!(all.contains(&class), "table row missing from ALL");
    }
}

#[test]
fn codes_are_nonzero_distinct_and_avoid_reserved_ranges() {
    let mut seen = HashSet::new();
    for class in ErrorClass::ALL {
        let code = class.exit_code();
        assert_ne!(code, 0, "{}: 0 is success", class.name());
        assert!(
            seen.insert(code),
            "{}: exit code {code} is not distinct",
            class.name()
        );
        assert!(
            !(40..=49).contains(&code),
            "{}: 40–49 are reserved for U30's verification-verdict classes",
            class.name()
        );
        assert!(
            code < 125,
            "{}: codes stay below shell/signal territory (125+)",
            class.name()
        );
    }
}

// ─────────────────────────────────────────────────────────────────────
// Exemplars: every variant, every reason
// ─────────────────────────────────────────────────────────────────────

/// One exemplar per variant, plus one per reason-enum value, labelled for
/// the snapshot. Field values are deliberately mundane and non-secret.
fn exemplars() -> Vec<(&'static str, CliError)> {
    vec![
        (
            "internal",
            CliError::Internal {
                detail: "journal write returned an impossible state".into(),
            },
        ),
        (
            "usage",
            CliError::Usage {
                message: "--wallet import requires --wallet-key-fd in machine mode".into(),
            },
        ),
        (
            "not-implemented-m2",
            CliError::NotImplemented {
                command: "status",
                milestone: Milestone::M2,
            },
        ),
        // U13's M1 gate: the anchor STAGE is what is missing, not the
        // command — same class and code as a stub, deliberately
        // different words (a user told `seal` is unimplemented goes
        // looking for a milestone that already arrived).
        ("anchor-stage-unavailable", CliError::AnchorStageUnavailable),
        (
            "not-implemented-m3",
            CliError::NotImplemented {
                command: "reveal",
                milestone: Milestone::M3,
            },
        ),
        (
            "io-error",
            CliError::Io {
                context: "reading ./notes.txt".into(),
                source: std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied"),
            },
        ),
        (
            "consent-declined",
            CliError::ConsentNotObtained {
                reason: ConsentOutcome::Declined,
            },
        ),
        (
            "consent-machine-mode",
            CliError::ConsentNotObtained {
                reason: ConsentOutcome::MachineModeWithoutYes,
            },
        ),
        (
            "import-refused-existing-vault",
            CliError::ImportRefusedExistingVault {
                vault_dir: PathBuf::from("/home/user/.antseal"),
            },
        ),
        (
            "passphrase-no-channel",
            CliError::PassphraseUnavailable {
                reason: PassphraseFailure::NoChannel,
            },
        ),
        (
            "passphrase-fd-read-failed",
            CliError::PassphraseUnavailable {
                reason: PassphraseFailure::FdReadFailed,
            },
        ),
        (
            "passphrase-fd-empty",
            CliError::PassphraseUnavailable {
                reason: PassphraseFailure::FdEmpty,
            },
        ),
        (
            "passphrase-fd-forbidden-byte",
            CliError::PassphraseUnavailable {
                reason: PassphraseFailure::FdForbiddenByte,
            },
        ),
        (
            "passphrase-fd-over-cap",
            CliError::PassphraseUnavailable {
                reason: PassphraseFailure::FdOverCap,
            },
        ),
        (
            "passphrase-prompt-empty",
            CliError::PassphraseUnavailable {
                reason: PassphraseFailure::PromptEmpty,
            },
        ),
        (
            "passphrase-prompt-failed",
            CliError::PassphraseUnavailable {
                reason: PassphraseFailure::PromptFailed,
            },
        ),
        (
            "passphrase-confirm-mismatch",
            CliError::PassphraseUnavailable {
                reason: PassphraseFailure::ConfirmMismatch,
            },
        ),
        ("vault-auth-failure", CliError::VaultAuthFailure),
        (
            "vault-kdf-memory",
            CliError::VaultKdfMemory { required_mib: 256 },
        ),
        (
            "vault-kdf-params-out-of-range",
            CliError::VaultKdfParamsOutOfRange {
                detail: "argon2id m_cost 1073741824 KiB exceeds the 4194304 KiB cap".into(),
            },
        ),
        (
            "vault-lock-held-with-pid",
            CliError::VaultLockHeld {
                lock_path: PathBuf::from("/home/user/.antseal/vault.lock"),
                holder_pid: Some(4242),
            },
        ),
        (
            "vault-lock-held-unknown-pid",
            CliError::VaultLockHeld {
                lock_path: PathBuf::from("/home/user/.antseal/vault.lock"),
                holder_pid: None,
            },
        ),
        (
            "vault-newer-version",
            CliError::VaultNewerVersion {
                found: 2,
                supported: 1,
            },
        ),
        (
            "malformed-config",
            CliError::MalformedConfig {
                path: PathBuf::from("/home/user/.antseal/config.toml"),
                line: 3,
                detail: "`default_network` must be one of arbitrum-one, arbitrum-sepolia, \
                         devnet (got `ropsten`)"
                    .into(),
            },
        ),
        (
            "insufficient-ant-token",
            CliError::InsufficientAntToken {
                required_atto: 1_500_000_000_000_000_000,
                available_atto: 20_000_000_000_000_000,
            },
        ),
        (
            "insufficient-eth-gas",
            CliError::InsufficientEthGas {
                required_wei: 90_000_000_000_000,
                available_wei: 1_000_000_000,
            },
        ),
        (
            "vault-keyfile-missing",
            CliError::VaultKeyfileMissing {
                path: PathBuf::from("/media/usb/antseal-keyfile.bin"),
                detail: "No such file or directory (os error 2)".into(),
            },
        ),
        (
            "vault-wrap-mode-unsupported",
            CliError::VaultWrapModeUnsupported {
                mode: 2,
                name: "os-keystore, reserved (D50)",
            },
        ),
        ("anchor-gate-abort", CliError::AnchorGateAbort),
        (
            "network-failure",
            CliError::NetworkFailure {
                detail: "quote_batch: no peers reachable".into(),
            },
        ),
        (
            "resume-source-changed",
            CliError::ResumeSafetyAbort {
                reason: ResumeSafetyReason::SourceChanged,
            },
        ),
        (
            "resume-staged-bytes-missing",
            CliError::ResumeSafetyAbort {
                reason: ResumeSafetyReason::StagedBytesMissing,
            },
        ),
        (
            "resume-overlap-not-exact",
            CliError::ResumeOverlapNotExact {
                detail: "2 of 3 paths match incomplete work a1b2c3".into(),
            },
        ),
        (
            "resume-flag-mismatch",
            CliError::ResumeFlagMismatch {
                detail: "incomplete work a1b2c3 was started without --split".into(),
            },
        ),
        (
            "invalid-seal-argument-one",
            CliError::InvalidSealArgument {
                problems: vec!["./src is a directory (seal takes files only)".into()],
            },
        ),
        (
            "invalid-seal-argument-many",
            CliError::InvalidSealArgument {
                problems: vec![
                    "./src is a directory (seal takes files only)".into(),
                    "./notes.txt appears twice".into(),
                ],
            },
        ),
        (
            "refused-overwrite",
            CliError::RefusedOverwrite { refused_files: 2 },
        ),
        (
            "malformed-restore-record",
            CliError::MalformedRestoreRecord {
                detail: "unit 3 names no target path".into(),
            },
        ),
        (
            "export-self-verify-failed",
            CliError::ExportSelfVerifyFailed,
        ),
        ("import-auth-failed", CliError::ImportAuthFailed),
        (
            "import-newer-version",
            CliError::ImportNewerVersion {
                found: 3,
                supported: 1,
            },
        ),
        (
            "restore-verification-failed",
            CliError::RestoreVerificationFailed {
                failed_files: 1,
                detail: "the canonical bytes of notes.txt".into(),
            },
        ),
    ]
}

#[test]
fn every_variant_maps_to_its_class_and_code() {
    for (label, err) in exemplars() {
        assert_eq!(
            err.exit_code(),
            err.class().exit_code(),
            "{label}: exit_code delegates to the class"
        );
    }
    // Spot-pins for the mappings decisions fixed:
    // D51 prompt-class table: the vault-import overwrite refusal IS the
    // consent-not-obtained class (declined ≡ unobtainable; no bypass).
    assert_eq!(
        CliError::ImportRefusedExistingVault {
            vault_dir: PathBuf::from("/tmp/v")
        }
        .class(),
        ErrorClass::ConsentNotObtained
    );
    // D51 invariant 4: the partition is distinct.
    let partition = [
        ErrorClass::ConsentNotObtained,
        ErrorClass::PassphraseUnavailable,
        ErrorClass::Usage,
        ErrorClass::VaultAuthFailure,
    ];
    let codes: HashSet<u8> = partition.iter().map(|c| c.exit_code()).collect();
    assert_eq!(codes.len(), partition.len(), "D51 partition distinctness");
    // D40: the two KDF classes are distinct from vault-auth and each other.
    assert_ne!(
        ErrorClass::VaultKdfMemory.exit_code(),
        ErrorClass::VaultAuthFailure.exit_code()
    );
    assert_ne!(
        ErrorClass::VaultKdfParamsOutOfRange.exit_code(),
        ErrorClass::VaultAuthFailure.exit_code()
    );
    assert_ne!(
        ErrorClass::VaultKdfMemory.exit_code(),
        ErrorClass::VaultKdfParamsOutOfRange.exit_code()
    );
}

#[test]
fn insufficient_token_and_gas_differ_in_code_and_message() {
    let token = CliError::InsufficientAntToken {
        required_atto: 10,
        available_atto: 1,
    };
    let gas = CliError::InsufficientEthGas {
        required_wei: 10,
        available_wei: 1,
    };
    assert_ne!(token.exit_code(), gas.exit_code());
    let (token_msg, gas_msg) = (token.to_string(), gas.to_string());
    assert_ne!(token_msg, gas_msg);
    assert!(token_msg.contains("ANT") && !token_msg.contains("gas"));
    assert!(gas_msg.contains("gas") && gas_msg.contains("ETH"));
}

// ─────────────────────────────────────────────────────────────────────
// Display snapshot (every message reviewed and frozen)
// ─────────────────────────────────────────────────────────────────────

fn render_displays() -> String {
    let mut out = String::new();
    for (label, err) in exemplars() {
        out.push_str(&format!(
            "[{label}] class={} code={}\n  {err}\n",
            err.class().name(),
            err.exit_code()
        ));
    }
    out
}

#[test]
fn display_output_matches_committed_snapshot() {
    let rendered = render_displays();
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/snapshots/cli-errors.display.txt");
    if std::env::var_os("ANTSEAL_BLESS").is_some() {
        std::fs::write(&path, &rendered).expect("write blessed snapshot");
        return;
    }
    let committed = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "missing committed error-display snapshot at {}: {e}\n\
             (generate once with ANTSEAL_BLESS=1 and review the diff)",
            path.display()
        )
    });
    assert!(
        committed == rendered,
        "error Display drifted from the committed snapshot {} — message \
         changes are reviewed events (regenerate with ANTSEAL_BLESS=1 and \
         justify the diff)",
        path.display()
    );
}

/// Messages carry no format-string leftovers and no newline (single-line
/// stderr discipline).
#[test]
fn display_output_is_single_line_and_fully_rendered() {
    for (label, err) in exemplars() {
        let msg = err.to_string();
        assert!(!msg.contains('\n'), "{label}: multi-line Display");
        assert!(!msg.contains("{}"), "{label}: unrendered placeholder");
        assert!(!msg.is_empty(), "{label}: empty Display");
    }
}

// ─────────────────────────────────────────────────────────────────────
// JSON error object (U2's shape, finalized by U3 as the envelope's
// inner `error` member)
// ─────────────────────────────────────────────────────────────────────

#[test]
fn json_error_object_carries_class_code_and_message() {
    for (label, err) in exemplars() {
        let v = err.error_object();
        assert_eq!(v["class"], err.class().name(), "{label}");
        assert_eq!(
            v["exit_code"],
            serde_json::json!(err.exit_code()),
            "{label}"
        );
        assert_eq!(v["message"], err.to_string().as_str(), "{label}");
        // And through the U3 envelope, unchanged (the finalization
        // claim, executed).
        let env = antseal_cli::machine::error_envelope("list", "arbitrum-one", &err);
        assert_eq!(env["ok"], serde_json::json!(false), "{label}");
        assert_eq!(
            env["error"], v,
            "{label}: envelope embeds the object verbatim"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────
// Binary wiring: --json stdout purity, identical codes in both modes
// ─────────────────────────────────────────────────────────────────────

#[test]
fn json_mode_emits_exactly_one_json_document_with_the_same_exit_code() {
    // `status` is the exemplar stub (M2); `list` played this role until
    // U19 gave it a real handler.
    let plain = Process::new(env!("CARGO_BIN_EXE_antseal"))
        .args(["status", "w1"])
        .output()
        .expect("spawn antseal");
    let json = Process::new(env!("CARGO_BIN_EXE_antseal"))
        .args(["--json", "status", "w1"])
        .output()
        .expect("spawn antseal");

    assert_eq!(plain.status.code(), json.status.code(), "D51: same code");
    assert_eq!(json.status.code(), Some(3), "not-implemented class code");

    // stdout parses as exactly one JSON document, no stray bytes — the
    // U3 envelope around U2's error object.
    let stdout = String::from_utf8(json.stdout).expect("utf-8 stdout");
    let doc: serde_json::Value =
        serde_json::from_str(stdout.trim_end_matches('\n')).expect("single JSON document");
    assert_eq!(doc["v"], serde_json::json!(1));
    assert_eq!(doc["command"], serde_json::json!("status"));
    assert_eq!(doc["ok"], serde_json::json!(false));
    assert_eq!(doc["error"]["class"], "not-implemented");
    assert_eq!(doc["error"]["exit_code"], serde_json::json!(3));

    // Human copy stays on stderr in both modes.
    assert!(!json.stderr.is_empty(), "human message on stderr");
    assert!(plain.stdout.is_empty(), "plain mode: no stdout for errors");
}
