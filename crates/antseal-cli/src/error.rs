//! CLI error taxonomy and the documented, stable exit-code scheme (U2).
//!
//! Every failure of a dispatched command is a [`CliError`]; every
//! `CliError` belongs to exactly one [`ErrorClass`]; every class has
//! exactly one exit code. `main_entry` maps deterministically — plain mode
//! prints `error: <Display>` on stderr, `--json` mode additionally emits
//! one structured error object on stdout (provisional shape until U3's
//! versioned envelope) — and the code is identical in both modes (D51
//! invariant 2).
//!
//! # The exit-code table (committed; unit-tested in `tests/exit_codes.rs`)
//!
//! | code | class | source |
//! |-----:|-------|--------|
//! | 0    | success | |
//! | 1    | `internal` | unexpected failure (bug class) |
//! | 2    | `usage` | argv/parse/cross-validation errors (clap's own convention, kept) |
//! | 3    | `not-implemented` | U1 frozen-surface stubs; message names the arriving milestone |
//! | 4    | `io-error` | ordinary filesystem I/O failure (D46 row 4's "ordinary I/O class") |
//! | 10   | `consent-not-obtained` | D51: declined ≡ unobtainable, one class; also machine-mode / declined `vault import` overwrite (D51 prompt-class table, "destructive confirm" row) |
//! | 11   | `passphrase-unavailable` | D41: no TTY and no `--passphrase-fd`; fd read failure / empty / forbidden bytes / over-cap |
//! | 12   | `vault-auth-failure` | bad passphrase, AAD-detected tamper, or corrupt store — one code insofar as safe (U6) |
//! | 13   | `vault-kdf-memory` | D40 §2: cannot allocate the KDF floor, at create AND unlock; no fallback exists |
//! | 14   | `vault-kdf-params-out-of-range` | D40 §3: pre-auth header caps, before any KDF allocation; also `vault import` headers (D47) |
//! | 15   | `vault-lock-held` | U5: another antseal process holds the single-writer lock |
//! | 16   | `vault-newer-version` | U5: vault header written by a newer antseal |
//! | 20   | `insufficient-ant-token` | distinct from gas by spec (core flow 1) |
//! | 21   | `insufficient-eth-gas` | distinct from token by spec (core flow 1) |
//! | 22   | `anchor-gate-abort` | zero TSA tokens and no `--force-degraded`; aborts pre-payment |
//! | 23   | `network-failure` | storage/anchor network I/O failure (transient class; D48 severity floor) |
//! | 24   | `resume-safety-abort` | spec line 145: changed source / missing staged bytes — never re-encrypts |
//! | 25   | `resume-overlap-not-exact` | D45 §2: input overlap with an incomplete work that is not an exact match |
//! | 26   | `resume-flag-mismatch` | D45 §2: same inputs, different seal-shaping flags |
//! | 27   | `invalid-seal-argument` | D46: directory / non-regular file / duplicate path, pre-consent |
//! | 30   | `refused-overwrite` | D48: restore found an existing, differing file (per-file; most-severe-class reporting) |
//! | 31   | `malformed-restore-record` | D48: a vault record that cannot drive a safe restore |
//! | 32   | `export-self-verify-failed` | D47: the written export failed its mandatory self-verify |
//! | 33   | `import-auth-failed` | D47: wrong passphrase or tampered/truncated export file |
//! | 34   | `import-newer-version` | D47: export written by a newer antseal |
//! | 40–49 | *reserved* | verification-verdict classes, finalized in U30 (M3) — do not mint here |
//!
//! Codes stay below 125 (126/127/128+n carry shell/signal meanings).
//! When one run hits several per-file classes, the reported class follows
//! D48 §6's fixed severity: verification-failed (40s, M3) >
//! `refused-overwrite` > fetch/network.
//!
//! # Secret hygiene (project rule 6; U21 discipline starts here)
//!
//! No variant carries secret material — no passphrase bytes, no key or
//! salt material, no fd contents, no vault record plaintext. Fields are
//! limited to: paths the user themself supplied or the vault directory
//! path, counts, versions, amounts, and short non-secret detail strings.
//! Authentication failures (`VaultAuthFailure`, `ImportAuthFailed`,
//! `PassphraseUnavailable`) are deliberately field-free or reason-enum
//! only, so their `Display` cannot interpolate input content even by
//! mistake. `tests/exit_codes.rs` snapshots every `Display`; the U21
//! harness later scans end-to-end output for planted sentinels.

use std::path::PathBuf;

use thiserror::Error;

/// Display helper: `" (pid N)"` when the lock holder's pid is known.
fn pid_suffix(pid: Option<u32>) -> String {
    pid.map(|p| format!(" (pid {p})")).unwrap_or_default()
}

/// Display helper: pluralizing `s`.
fn plural_s(n: usize) -> &'static str {
    if n == 1 { "" } else { "s" }
}

/// The milestone a stubbed command's real handler arrives with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Milestone {
    /// M1 — storage: seal/restore/vault handlers land within this milestone.
    M1,
    /// M2 — anchors.
    M2,
    /// M3 — reveal + verifier.
    M3,
}

impl std::fmt::Display for Milestone {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Milestone::M1 => "M1",
            Milestone::M2 => "M2",
            Milestone::M3 => "M3",
        })
    }
}

/// Why consent was not obtained (D51 invariant 3: the message
/// distinguishes, the exit code does not).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsentOutcome {
    /// An interactive prompt was answered "no".
    Declined,
    /// Machine mode (`--json`, non-TTY stdin, or stdin consumed by
    /// `--passphrase-fd 0`) without `--yes`: nothing prompts, ever.
    MachineModeWithoutYes,
}

impl ConsentOutcome {
    fn describe(self) -> &'static str {
        match self {
            ConsentOutcome::Declined => "consent declined: nothing was paid, anchored, or uploaded",
            ConsentOutcome::MachineModeWithoutYes => {
                "consent required but not obtainable: machine mode (--json, non-TTY stdin, \
                 or --passphrase-fd 0) never prompts — pass --yes to consent in advance; \
                 nothing was paid, anchored, or uploaded"
            }
        }
    }
}

/// Why the passphrase channel failed (D41 byte semantics). Reasons name
/// the failure class only — never any input byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PassphraseFailure {
    /// No TTY on stdin and no `--passphrase-fd` given.
    NoChannel,
    /// Reading the named fd failed.
    FdReadFailed,
    /// The fd yielded an empty passphrase (after the single trailing
    /// LF/CRLF strip).
    FdEmpty,
    /// The fd bytes contain interior NUL/LF/CR — not enterable at the
    /// prompt, so rejected for channel parity.
    FdForbiddenByte,
    /// The fd exceeded the 1 KiB read cap.
    FdOverCap,
}

impl PassphraseFailure {
    fn describe(self) -> &'static str {
        match self {
            PassphraseFailure::NoChannel => {
                "no TTY on stdin and no --passphrase-fd was given; supply the passphrase over \
                 a file descriptor, e.g. `printf '%s' \"$PASS\" | antseal … --passphrase-fd 0`"
            }
            PassphraseFailure::FdReadFailed => "reading the --passphrase-fd descriptor failed",
            PassphraseFailure::FdEmpty => "the --passphrase-fd input was empty",
            PassphraseFailure::FdForbiddenByte => {
                "the --passphrase-fd input contains interior NUL/LF/CR bytes, which the \
                 interactive prompt could never produce (channel parity, D41)"
            }
            PassphraseFailure::FdOverCap => {
                "the --passphrase-fd input exceeded the 1 KiB cap (D41)"
            }
        }
    }
}

/// Why a resume was refused as unsafe (spec line 145: resume never
/// re-encrypts — one exit code, distinguishing messages).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResumeSafetyReason {
    /// A source file no longer reproduces the anchored commitments;
    /// re-encrypting under the journaled nonce would be catastrophic
    /// `(k_u, nonce)` reuse.
    SourceChanged,
    /// The journaled staged ciphertext bytes are unavailable; the
    /// in-progress seal is abandoned rather than ever re-encrypted.
    StagedBytesMissing,
}

impl ResumeSafetyReason {
    fn describe(self) -> &'static str {
        match self {
            ResumeSafetyReason::SourceChanged => {
                "a source file changed since the interrupted seal: resume never re-encrypts \
                 (re-using a journaled nonce on new plaintext would break the encryption), so \
                 this seal is abandoned; re-run `antseal seal` to start a fresh one"
            }
            ResumeSafetyReason::StagedBytesMissing => {
                "the staged ciphertext bytes of the interrupted seal are missing from the \
                 vault: resume never re-encrypts, so this seal is abandoned; re-run \
                 `antseal seal` to start a fresh one (any payment already made is forfeited \
                 — the deliberate safety-over-cost choice)"
            }
        }
    }
}

/// One error class per exit code (the table above). `CliError` variants
/// map many-to-one onto classes where a decision says so.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorClass {
    Internal,
    Usage,
    NotImplemented,
    IoError,
    ConsentNotObtained,
    PassphraseUnavailable,
    VaultAuthFailure,
    VaultKdfMemory,
    VaultKdfParamsOutOfRange,
    VaultLockHeld,
    VaultNewerVersion,
    InsufficientAntToken,
    InsufficientEthGas,
    AnchorGateAbort,
    NetworkFailure,
    ResumeSafetyAbort,
    ResumeOverlapNotExact,
    ResumeFlagMismatch,
    InvalidSealArgument,
    RefusedOverwrite,
    MalformedRestoreRecord,
    ExportSelfVerifyFailed,
    ImportAuthFailed,
    ImportNewerVersion,
}

impl ErrorClass {
    /// Every class, for table tests. Grows only by deliberate review.
    pub const ALL: [ErrorClass; 24] = [
        ErrorClass::Internal,
        ErrorClass::Usage,
        ErrorClass::NotImplemented,
        ErrorClass::IoError,
        ErrorClass::ConsentNotObtained,
        ErrorClass::PassphraseUnavailable,
        ErrorClass::VaultAuthFailure,
        ErrorClass::VaultKdfMemory,
        ErrorClass::VaultKdfParamsOutOfRange,
        ErrorClass::VaultLockHeld,
        ErrorClass::VaultNewerVersion,
        ErrorClass::InsufficientAntToken,
        ErrorClass::InsufficientEthGas,
        ErrorClass::AnchorGateAbort,
        ErrorClass::NetworkFailure,
        ErrorClass::ResumeSafetyAbort,
        ErrorClass::ResumeOverlapNotExact,
        ErrorClass::ResumeFlagMismatch,
        ErrorClass::InvalidSealArgument,
        ErrorClass::RefusedOverwrite,
        ErrorClass::MalformedRestoreRecord,
        ErrorClass::ExportSelfVerifyFailed,
        ErrorClass::ImportAuthFailed,
        ErrorClass::ImportNewerVersion,
    ];

    /// The documented exit code (the table in the module docs).
    #[must_use]
    pub fn exit_code(self) -> u8 {
        match self {
            ErrorClass::Internal => 1,
            ErrorClass::Usage => 2,
            ErrorClass::NotImplemented => 3,
            ErrorClass::IoError => 4,
            ErrorClass::ConsentNotObtained => 10,
            ErrorClass::PassphraseUnavailable => 11,
            ErrorClass::VaultAuthFailure => 12,
            ErrorClass::VaultKdfMemory => 13,
            ErrorClass::VaultKdfParamsOutOfRange => 14,
            ErrorClass::VaultLockHeld => 15,
            ErrorClass::VaultNewerVersion => 16,
            ErrorClass::InsufficientAntToken => 20,
            ErrorClass::InsufficientEthGas => 21,
            ErrorClass::AnchorGateAbort => 22,
            ErrorClass::NetworkFailure => 23,
            ErrorClass::ResumeSafetyAbort => 24,
            ErrorClass::ResumeOverlapNotExact => 25,
            ErrorClass::ResumeFlagMismatch => 26,
            ErrorClass::InvalidSealArgument => 27,
            ErrorClass::RefusedOverwrite => 30,
            ErrorClass::MalformedRestoreRecord => 31,
            ErrorClass::ExportSelfVerifyFailed => 32,
            ErrorClass::ImportAuthFailed => 33,
            ErrorClass::ImportNewerVersion => 34,
        }
    }

    /// The stable kebab-case class identifier (JSON `error.class`; also
    /// the table's class column).
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            ErrorClass::Internal => "internal",
            ErrorClass::Usage => "usage",
            ErrorClass::NotImplemented => "not-implemented",
            ErrorClass::IoError => "io-error",
            ErrorClass::ConsentNotObtained => "consent-not-obtained",
            ErrorClass::PassphraseUnavailable => "passphrase-unavailable",
            ErrorClass::VaultAuthFailure => "vault-auth-failure",
            ErrorClass::VaultKdfMemory => "vault-kdf-memory",
            ErrorClass::VaultKdfParamsOutOfRange => "vault-kdf-params-out-of-range",
            ErrorClass::VaultLockHeld => "vault-lock-held",
            ErrorClass::VaultNewerVersion => "vault-newer-version",
            ErrorClass::InsufficientAntToken => "insufficient-ant-token",
            ErrorClass::InsufficientEthGas => "insufficient-eth-gas",
            ErrorClass::AnchorGateAbort => "anchor-gate-abort",
            ErrorClass::NetworkFailure => "network-failure",
            ErrorClass::ResumeSafetyAbort => "resume-safety-abort",
            ErrorClass::ResumeOverlapNotExact => "resume-overlap-not-exact",
            ErrorClass::ResumeFlagMismatch => "resume-flag-mismatch",
            ErrorClass::InvalidSealArgument => "invalid-seal-argument",
            ErrorClass::RefusedOverwrite => "refused-overwrite",
            ErrorClass::MalformedRestoreRecord => "malformed-restore-record",
            ErrorClass::ExportSelfVerifyFailed => "export-self-verify-failed",
            ErrorClass::ImportAuthFailed => "import-auth-failed",
            ErrorClass::ImportNewerVersion => "import-newer-version",
        }
    }
}

/// Top-level CLI error: one variant per user-distinguishable failure.
/// Wrapping `#[from]` impls for library-domain errors (C/G/S/A/R/F) land
/// with the commands that produce them (U13, U20, …) — the classes and
/// codes those wrappers map into are fixed here first.
#[derive(Debug, Error)]
pub enum CliError {
    /// Unexpected failure — a bug, not an input problem.
    #[error("internal error: {detail} (this is a bug in antseal — please report it)")]
    Internal { detail: String },

    /// Post-parse usage error (clap parse errors render through clap and
    /// share exit code 2 by construction).
    #[error("usage error: {message}")]
    Usage { message: String },

    /// The canonical surface is frozen from day one (U1); this command's
    /// handler has not landed yet.
    #[error(
        "`antseal {command}` is not implemented until {milestone}: the command surface is \
         frozen from day one so scripts written today keep parsing, and handlers land \
         milestone by milestone"
    )]
    NotImplemented {
        /// Space-joined command path, e.g. `"vault export"`.
        command: &'static str,
        /// When the real handler arrives.
        milestone: Milestone,
    },

    /// Ordinary filesystem I/O failure (D46 row 4's "ordinary I/O class").
    #[error("I/O error: {context}: {source}")]
    Io {
        /// What was being attempted (a path or short action, non-secret).
        context: String,
        #[source]
        source: std::io::Error,
    },

    /// D51: consent declined or unobtainable — one class, and nothing was
    /// paid or uploaded.
    #[error("{}", .reason.describe())]
    ConsentNotObtained { reason: ConsentOutcome },

    /// D51 prompt-class table, "destructive confirm" row: overwriting a
    /// vault destroys `W` for every work in it; the manual move/remove is
    /// the consent, and no bypass flag exists in v1.
    #[error(
        "refusing to import over the existing vault at {}: overwriting a vault \
         irreversibly destroys the reveal/restore keys of every work in it. Move or remove \
         that directory yourself first (after `antseal vault export` if you want its \
         contents) — scripted overwrite-import is deliberately unsupported (D51)",
        .vault_dir.display()
    )]
    ImportRefusedExistingVault { vault_dir: PathBuf },

    /// D41: the passphrase channel failed; the prompt-parity abort.
    #[error("passphrase unavailable: {}", .reason.describe())]
    PassphraseUnavailable { reason: PassphraseFailure },

    /// U6: bad passphrase, AAD-detected tamper, and corrupt store share
    /// one code insofar as distinguishing them is safe.
    #[error(
        "vault authentication failed: wrong passphrase, or the vault store or header has \
         been modified or corrupted"
    )]
    VaultAuthFailure,

    /// D40 §2: the machine cannot allocate the KDF's memory floor; no
    /// fallback exists, at create and at unlock alike.
    #[error(
        "cannot allocate the {required_mib} MiB this vault's key derivation requires: the \
         memory floor is a security parameter (a stolen vault decrypts permanent public \
         ciphertexts, forever) and antseal will not create or open a weaker vault; use a \
         machine with more allocatable memory (D40)"
    )]
    VaultKdfMemory { required_mib: u32 },

    /// D40 §3: pre-auth header caps — enforced before any KDF allocation,
    /// so a substituted header cannot be a resource bomb.
    #[error(
        "vault KDF parameters are outside the accepted range ({detail}): refusing to run \
         the KDF on an out-of-range header (D40 §3)"
    )]
    VaultKdfParamsOutOfRange { detail: String },

    /// U5: the single-writer lockfile is held by another live process.
    #[error(
        "another antseal process{} holds the vault lock at {}; retry when it finishes",
        pid_suffix(*.holder_pid),
        .lock_path.display()
    )]
    VaultLockHeld {
        lock_path: PathBuf,
        holder_pid: Option<u32>,
    },

    /// U5: the vault header names a format version this build predates.
    #[error(
        "this vault was created by a newer antseal (vault format v{found}; this build \
         supports up to v{supported}): upgrade antseal instead of downgrading the vault"
    )]
    VaultNewerVersion { found: u64, supported: u32 },

    /// Distinct from gas by spec (core flow 1): the ANT token balance
    /// cannot cover the quote.
    #[error(
        "insufficient ANT for this seal: the quote needs {required_atto} atto-ANT but the \
         wallet holds {available_atto}; fund the wallet with ANT and re-run (nothing was \
         paid or uploaded)"
    )]
    InsufficientAntToken {
        required_atto: u128,
        available_atto: u128,
    },

    /// Distinct from token by spec (core flow 1): the ETH balance cannot
    /// cover gas.
    #[error(
        "insufficient ETH for gas: the payment transaction needs about {required_wei} wei \
         but the wallet holds {available_wei}; fund the wallet with ETH for gas and re-run \
         (nothing was paid or uploaded)"
    )]
    InsufficientEthGas {
        required_wei: u128,
        available_wei: u128,
    },

    /// The ≥1-TSA-or-abort gate: aborting cheaply and reversibly before
    /// any payment.
    #[error(
        "no RFC 3161 timestamp token could be obtained, so the seal aborts before anything \
         is paid or uploaded (the anchor gate); re-run when a TSA is reachable, or pass \
         --force-degraded to proceed with a loudly recorded degraded anchor set"
    )]
    AnchorGateAbort,

    /// Storage/anchor network I/O failure (transient class).
    #[error("network failure: {detail}")]
    NetworkFailure { detail: String },

    /// Spec line 145: resume never re-encrypts.
    #[error("resume safety abort: {}", .reason.describe())]
    ResumeSafetyAbort { reason: ResumeSafetyReason },

    /// D45 §2: the invocation's inputs overlap an incomplete work without
    /// matching it exactly — refuse loudly rather than guess.
    #[error(
        "these inputs overlap an incomplete seal without matching it exactly ({detail}): \
         re-run with exactly the original path list to resume it, with a disjoint path \
         list to start a fresh seal, or abandon it first (D45)"
    )]
    ResumeOverlapNotExact { detail: String },

    /// D45 §2: same inputs, different seal-shaping flags.
    #[error(
        "these inputs match an incomplete seal but the seal-shaping flags differ \
         ({detail}): re-run with the original flags to resume, or abandon the incomplete \
         seal first (D45)"
    )]
    ResumeFlagMismatch { detail: String },

    /// D46: directory / non-regular file / duplicate path — every
    /// offending argument named, pre-consent.
    #[error(
        "invalid seal argument{}: {}",
        plural_s(.problems.len()),
        .problems.join("; ")
    )]
    InvalidSealArgument { problems: Vec<String> },

    /// D48: restore found existing files that differ from the sealed
    /// content and refused to touch them (per-file; the run continues).
    #[error(
        "restore refused to overwrite {refused_files} existing file(s) whose bytes differ \
         from the sealed content; the differing files are untouched — move them aside and \
         re-run to write the sealed versions (D48)"
    )]
    RefusedOverwrite { refused_files: usize },

    /// D48: a vault record that cannot drive a safe restore.
    #[error("malformed restore record: {detail} (the vault record cannot drive a safe restore)")]
    MalformedRestoreRecord { detail: String },

    /// D47: the mandatory post-write self-verification failed — the file
    /// on disk is not a usable backup.
    #[error(
        "the written vault export failed its mandatory self-verification: the file on disk \
         is NOT a usable backup — delete it and re-run `antseal vault export` (D47)"
    )]
    ExportSelfVerifyFailed,

    /// D47: wrong passphrase or a tampered/truncated export file — one
    /// class, deliberately, like vault authentication.
    #[error(
        "vault import authentication failed: wrong passphrase, or the export file has been \
         modified or truncated"
    )]
    ImportAuthFailed,

    /// D47: the export file names a format version this build predates.
    #[error(
        "this export file was written by a newer antseal (export format v{found}; this \
         build supports up to v{supported}): upgrade antseal to import it"
    )]
    ImportNewerVersion { found: u64, supported: u32 },
}

impl CliError {
    /// The class (and therefore exit code) of this error.
    #[must_use]
    pub fn class(&self) -> ErrorClass {
        match self {
            CliError::Internal { .. } => ErrorClass::Internal,
            CliError::Usage { .. } => ErrorClass::Usage,
            CliError::NotImplemented { .. } => ErrorClass::NotImplemented,
            CliError::Io { .. } => ErrorClass::IoError,
            // D51's prompt-class table maps the vault-import destructive
            // confirm into the consent class: declined ≡ unobtainable,
            // and the manual move/remove is the consent.
            CliError::ConsentNotObtained { .. } | CliError::ImportRefusedExistingVault { .. } => {
                ErrorClass::ConsentNotObtained
            }
            CliError::PassphraseUnavailable { .. } => ErrorClass::PassphraseUnavailable,
            CliError::VaultAuthFailure => ErrorClass::VaultAuthFailure,
            CliError::VaultKdfMemory { .. } => ErrorClass::VaultKdfMemory,
            CliError::VaultKdfParamsOutOfRange { .. } => ErrorClass::VaultKdfParamsOutOfRange,
            CliError::VaultLockHeld { .. } => ErrorClass::VaultLockHeld,
            CliError::VaultNewerVersion { .. } => ErrorClass::VaultNewerVersion,
            CliError::InsufficientAntToken { .. } => ErrorClass::InsufficientAntToken,
            CliError::InsufficientEthGas { .. } => ErrorClass::InsufficientEthGas,
            CliError::AnchorGateAbort => ErrorClass::AnchorGateAbort,
            CliError::NetworkFailure { .. } => ErrorClass::NetworkFailure,
            CliError::ResumeSafetyAbort { .. } => ErrorClass::ResumeSafetyAbort,
            CliError::ResumeOverlapNotExact { .. } => ErrorClass::ResumeOverlapNotExact,
            CliError::ResumeFlagMismatch { .. } => ErrorClass::ResumeFlagMismatch,
            CliError::InvalidSealArgument { .. } => ErrorClass::InvalidSealArgument,
            CliError::RefusedOverwrite { .. } => ErrorClass::RefusedOverwrite,
            CliError::MalformedRestoreRecord { .. } => ErrorClass::MalformedRestoreRecord,
            CliError::ExportSelfVerifyFailed => ErrorClass::ExportSelfVerifyFailed,
            CliError::ImportAuthFailed => ErrorClass::ImportAuthFailed,
            CliError::ImportNewerVersion { .. } => ErrorClass::ImportNewerVersion,
        }
    }

    /// The documented exit code for this error (never 0).
    #[must_use]
    pub fn exit_code(&self) -> u8 {
        self.class().exit_code()
    }

    /// The provisional `--json` error object (U2). U3's versioned
    /// envelope (`command`, `network`, `ok`, `result|error`) supersedes
    /// this shape; until then, machine mode still gets exactly one JSON
    /// document on stdout with a stable `error.class`.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "ok": false,
            "error": {
                "class": self.class().name(),
                "exit_code": self.exit_code(),
                "message": self.to_string(),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::ErrorClass;

    /// Exhaustive-match index: adding an `ErrorClass` variant fails this
    /// match at compile time, forcing `ALL` (asserted complete below), the
    /// module-doc table, and `tests/exit_codes.rs::TABLE` to be updated in
    /// the same change.
    fn class_index(class: ErrorClass) -> usize {
        match class {
            ErrorClass::Internal => 0,
            ErrorClass::Usage => 1,
            ErrorClass::NotImplemented => 2,
            ErrorClass::IoError => 3,
            ErrorClass::ConsentNotObtained => 4,
            ErrorClass::PassphraseUnavailable => 5,
            ErrorClass::VaultAuthFailure => 6,
            ErrorClass::VaultKdfMemory => 7,
            ErrorClass::VaultKdfParamsOutOfRange => 8,
            ErrorClass::VaultLockHeld => 9,
            ErrorClass::VaultNewerVersion => 10,
            ErrorClass::InsufficientAntToken => 11,
            ErrorClass::InsufficientEthGas => 12,
            ErrorClass::AnchorGateAbort => 13,
            ErrorClass::NetworkFailure => 14,
            ErrorClass::ResumeSafetyAbort => 15,
            ErrorClass::ResumeOverlapNotExact => 16,
            ErrorClass::ResumeFlagMismatch => 17,
            ErrorClass::InvalidSealArgument => 18,
            ErrorClass::RefusedOverwrite => 19,
            ErrorClass::MalformedRestoreRecord => 20,
            ErrorClass::ExportSelfVerifyFailed => 21,
            ErrorClass::ImportAuthFailed => 22,
            ErrorClass::ImportNewerVersion => 23,
        }
    }

    #[test]
    fn all_lists_every_class_exactly_once() {
        let mut seen = [false; ErrorClass::ALL.len()];
        for class in ErrorClass::ALL {
            let idx = class_index(class);
            assert!(!seen[idx], "{} listed twice in ALL", class.name());
            seen[idx] = true;
        }
        assert!(seen.iter().all(|&s| s), "ALL misses a class");
    }
}
