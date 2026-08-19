//! CLI error taxonomy and the documented, stable exit-code scheme (U2).
//!
//! Every failure of a dispatched command is a [`CliError`]; every
//! `CliError` belongs to exactly one [`ErrorClass`]; every class has
//! exactly one exit code. `main_entry` maps deterministically — plain mode
//! prints `error: <Display>` on stderr, `--json` mode additionally emits
//! exactly one U3 envelope on stdout (`crate::machine` owns the envelope;
//! this module owns the inner `error` object, U2's shape finalized) — and
//! the code is identical in both modes (D51 invariant 2).
//!
//! # The exit-code table (committed; unit-tested in `tests/exit_codes.rs`)
//!
//! | code | class | source |
//! |-----:|-------|--------|
//! | 0    | success | |
//! | 1    | `internal` | unexpected failure (bug class) |
//! | 2    | `usage` | argv/parse/cross-validation errors (clap's own convention, kept) |
//! | 3    | `not-implemented` | U1 frozen-surface stubs; message names the arriving milestone. (U13's M1 anchor-stage gate also mapped here until U22 wired the real stage and deleted it) |
//! | 4    | `io-error` | ordinary filesystem I/O failure (D46 row 4's "ordinary I/O class") |
//! | 10   | `consent-not-obtained` | D51: declined ≡ unobtainable, one class; also machine-mode / declined `vault import` overwrite (D51 prompt-class table, "destructive confirm" row) |
//! | 11   | `passphrase-unavailable` | D41: no TTY and no `--passphrase-fd`; fd read failure / empty / forbidden bytes / over-cap |
//! | 12   | `vault-auth-failure` | bad passphrase, AAD-detected tamper, or corrupt store — one code insofar as safe (U6) |
//! | 13   | `vault-kdf-memory` | D40 §2: cannot allocate the KDF floor, at create AND unlock; no fallback exists |
//! | 14   | `vault-kdf-params-out-of-range` | D40 §3: pre-auth header caps, before any KDF allocation; also `vault import` headers (D47) |
//! | 15   | `vault-lock-held` | U5: another antseal process holds the single-writer lock |
//! | 16   | `vault-newer-version` | U5: vault header written by a newer antseal |
//! | 17   | `malformed-config` | U4: `config.toml` present but unreadable — never silently ignored (missing = defaults) |
//! | 18   | `vault-keyfile-missing` | U8/D50 mode 1: the keyfile factor is absent, unreadable or the wrong size — NEVER the generic auth failure |
//! | 19   | `vault-wrap-mode-unsupported` | D50: the header names a registered wrap mode this build does not implement (mode 2, os-keystore) |
//! | 20   | `insufficient-ant-token` | distinct from gas by spec (core flow 1) |
//! | 21   | `insufficient-eth-gas` | distinct from token by spec (core flow 1) |
//! | 22   | `anchor-gate-abort` | zero TSA tokens and no `--force-degraded`; aborts pre-payment |
//! | 23   | `network-failure` | storage/anchor network I/O failure (transient class; D48 severity floor) |
//! | 24   | `resume-safety-abort` | spec line 145: changed source / missing staged bytes — never re-encrypts |
//! | 25   | `resume-overlap-not-exact` | D45 §2: input overlap with an incomplete work that is not an exact match |
//! | 26   | `resume-flag-mismatch` | D45 §2: same inputs, different seal-shaping flags |
//! | 27   | `invalid-seal-argument` | D46: directory / non-regular file / duplicate path, pre-consent |
//! | 28   | `payment-stranded` | D147: payment failed mid-sequence with money already moved — never the transient class; re-running `seal` finishes it and re-pays no quote the journaled receipt already maps |
//! | 29   | `payment-proofs-expired` | D147 / D37 Decision 6: the journaled proofs outlived the ~24 h window, so completing the seal costs a **second**, separately consented payment |
//! | 30   | `refused-overwrite` | D48: restore found an existing, differing file (per-file; most-severe-class reporting) |
//! | 31   | `malformed-restore-record` | D48: a vault record that cannot drive a safe restore |
//! | 32   | `export-self-verify-failed` | D47: the written export failed its mandatory self-verify |
//! | 33   | `import-auth-failed` | D47: wrong passphrase or tampered/truncated export file |
//! | 34   | `import-newer-version` | D47: export written by a newer antseal |
//! | 35   | `restore-verification-failed` | D48 §6: restore fetched bytes that did not open their manifest commitment; nothing written for those files |
//! | 36   | `reveal-inputs-unusable` | D69 §5 group 3: a manifest, vault record, ciphertext or anchor artifact disagrees with the manifest, so no bundle can be built — no argv change and no retry fixes it (reveal's sibling of 35) |
//! | 40   | `verify-bundle-rejected` | D69 §3 R2 `‡`: the `Err` arm of `verify_bundle` — tamper, forgery, malformation, over-cap and non-canonical bytes are **one** class; the specific `VerifyError::code()` rides in the message, never in the integer |
//! | 41   | `verify-anchor-refuted` | D69 §3 R2 rung 1: ≥1 anchor slot is `invalid` (MVP-SPEC.md line 134 — *"signature/op check fails"*), offline or by agreed online refutation |
//! | 42   | `verify-headline-divergence` | D69 §3 R2 rung 2: headline-eligible anchors disagree by strictly more than 48 h (MVP-SPEC.md line 137) |
//! | 43   | `verify-unanchored` | D69 §3 R2 rung 3: zero headline-eligible anchors — **deliberately nonzero and deliberately distinct**, so a caller who accepts undated bundles opts back in with one line |
//! | 44–49 | *reserved* | D69 §3 R9: a future storage-linkage rung (only if R6 is ever overturned), a `sig_policy` split, or report-v2 growth — **do not mint here** |
//!
//! # 28 and 29 are the money-moved pair (D147)
//!
//! Of the classes the storage boundary produces
//! ([`crate::pipeline::error`]'s `storage_to_cli`), 20 and 21 are
//! shortfalls found *before* anything is paid and 23 is the transient
//! class a caller is **right** to retry: all three leave the wallet
//! untouched by the failed attempt. 28 and 29 are the two where ANT has
//! already left it, and they are separate codes because the remedies
//! differ: 28 is finished by re-running `antseal seal` on the same inputs
//! (the journaled partial receipt is authoritative, so no mapped quote is
//! re-paid), while 29 needs a new, separately consented payment. A
//! wrapper that retries 23 the way it retries a peer timeout must not be
//! handed either of them.
//!
//! They are minted **inside** the seal/payment/resume band D69 §1(a)
//! surveyed and recorded free, not appended past 43 — the same placement
//! rule that put `restore-verification-failed` at 35 *"beside the other
//! restore classes"* rather than in the 40s. No assigned code moved and
//! 44–49 stays reserved (D134 §2 R3).
//!
//! # The three verdict rungs are not errors (D69 §3 R1's third arm)
//!
//! 41, 42 and 43 have **no [`CliError`] variant on purpose**. They are the
//! fold of a verification that *succeeded* — every commitment opened, a
//! report exists — so they ride on
//! [`Outcome::exit_class`](crate::commands::Outcome) and the run still emits
//! its `--json` **success** envelope. `ok` means *a result document is
//! present*, never *the exit code is 0*
//! ([`crate::machine`]). Only 40 is an error: `verify_bundle` returned
//! `Err`, and D27 §4 means no report exists to carry.
//!
//! [`ErrorClass::for_rung`] is the one mapping from D69's rung to this
//! table; the rung's own name is `antseal-core`'s, so the two spellings are
//! asserted equal rather than typed twice.
//!
//! Codes stay below 125 (126/127/128+n carry shell/signal meanings).
//! When one run hits several per-file classes, the reported class follows
//! D48 §6's fixed severity: `restore-verification-failed` >
//! `refused-overwrite` > fetch/network. That order is implemented as an
//! explicit rank ([`crate::pipeline::restore::FailureKind`] and U20's
//! severity fold), never as a comparison of numeric codes — which is why
//! restore's verification class can live at 35 without disturbing the
//! 40–49 band. U2's table originally predicted this class would be minted
//! in the 40s by U30; U20 needs it at M1, and it is a *restore* outcome
//! rather than a bundle verdict, so it sits beside the other restore
//! classes (30, 31) and the reserved band stays intact for U30.
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

use antseal_core::verify::rung::VerdictExitRung;
use thiserror::Error;

/// Display helper: `" (pid N)"` when the lock holder's pid is known.
fn pid_suffix(pid: Option<u32>) -> String {
    pid.map(|p| format!(" (pid {p})")).unwrap_or_default()
}

/// Display helper: `":<line>"` when a config line is known (0 = a
/// whole-file problem, no fragment).
fn line_suffix(line: usize) -> String {
    if line == 0 {
        String::new()
    } else {
        format!(":{line}")
    }
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
    /// The message, for both of this class's gates.
    ///
    /// **The tail names every consequence a declined consent avoided**, and
    /// it lists four rather than three because this class has two consumers,
    /// not one: U14's permanence gate (nothing was paid, anchored or
    /// uploaded) and **U29's irreversible-disclosure gate** (nothing was
    /// disclosed — no bundle was written, and no whole-file commitment was
    /// opened). A user who has just declined a `reveal` needs to be told
    /// about the disclosure, not only about a payment their command was
    /// never going to make; the seal-only tail was true for them but silent
    /// on the one thing they were deciding.
    fn describe(self) -> &'static str {
        match self {
            ConsentOutcome::Declined => {
                "consent declined: nothing was paid, anchored, uploaded, or disclosed"
            }
            ConsentOutcome::MachineModeWithoutYes => {
                "consent required but not obtainable: machine mode (--json, non-TTY stdin, \
                 or --passphrase-fd 0) never prompts — pass --yes to consent in advance; \
                 nothing was paid, anchored, uploaded, or disclosed"
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
    /// The interactive prompt returned an empty passphrase (parity with
    /// the fd channel's empty rejection, U7).
    PromptEmpty,
    /// Reading from the terminal failed (EOF at the prompt, a TTY error).
    PromptFailed,
    /// Create-time confirmation did not match the first entry (the
    /// double-entry exists to catch typos; only the prompt path has it —
    /// fd input is not typed, D41 §5).
    ConfirmMismatch,
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
            PassphraseFailure::PromptEmpty => "the passphrase entered at the prompt was empty",
            PassphraseFailure::PromptFailed => "reading the passphrase from the terminal failed",
            PassphraseFailure::ConfirmMismatch => {
                "the confirmation did not match the passphrase; nothing was created — re-run \
                 and enter the same passphrase twice"
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
    ///
    /// # Unreachable by construction on the resume path, deliberately
    ///
    /// Nothing constructs this variant, and that is the *stronger*
    /// outcome rather than a gap. U17 asked for an abort when a source
    /// file changed; S11 implemented something better — resume never
    /// opens a source file at all (`RecordedIdentity` carries no `W`, and
    /// the re-upload is of the journaled staged ciphertexts), so a
    /// changed source is not a hazard to abort on but a non-event: S18
    /// case (3) proves a resume with edited sources restores the
    /// **original** bytes. There is no abort because the wrong thing
    /// cannot happen.
    ///
    /// The variant is kept rather than deleted: it is the frozen class
    /// for any future path that *does* read plaintext against a journaled
    /// nonce (a re-stage or repair feature would need exactly this
    /// refusal), and its `Display` states the rule that makes such a path
    /// illegal. Whether to keep it or shrink the error universe by one is
    /// recorded as **U42**.
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
            // U17 fixes the exact wording this abort owes the user: what
            // was lost, that losing it was chosen, and what a fresh seal
            // will and will not reuse. "Start a fresh one" alone left the
            // reader to wonder whether the new seal reuses the old keys —
            // which is the one thing it must never do.
            ResumeSafetyReason::StagedBytesMissing => {
                "the staged ciphertext bytes of the interrupted seal are missing from the \
                 vault: resume never re-encrypts, so this seal is abandoned; re-run \
                 `antseal seal` to start a fresh one, which draws a NEW seal_id and freshly \
                 generated nonces and therefore produces a different work-id (any payment \
                 already made is forfeited — the deliberate safety-over-cost choice: a \
                 reused (k_u, nonce) pair would destroy the confidentiality of everything \
                 encrypted under it)"
            }
        }
    }
}

/// One error class per exit code (the table above). `CliError` variants
/// map many-to-one onto classes where a decision says so — and D69's three
/// verdict rungs map onto classes with **no variant at all**, because they
/// are the outcome of a run that produced a report (see the module docs).
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
    MalformedConfig,
    VaultKeyfileMissing,
    VaultWrapModeUnsupported,
    InsufficientAntToken,
    InsufficientEthGas,
    AnchorGateAbort,
    NetworkFailure,
    ResumeSafetyAbort,
    ResumeOverlapNotExact,
    ResumeFlagMismatch,
    InvalidSealArgument,
    PaymentStranded,
    PaymentProofsExpired,
    RefusedOverwrite,
    MalformedRestoreRecord,
    ExportSelfVerifyFailed,
    ImportAuthFailed,
    ImportNewerVersion,
    RestoreVerificationFailed,
    RevealInputsUnusable,
    VerifyBundleRejected,
    VerifyAnchorRefuted,
    VerifyHeadlineDivergence,
    VerifyUnanchored,
}

impl ErrorClass {
    /// Every class, for table tests. Grows only by deliberate review.
    pub const ALL: [ErrorClass; 35] = [
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
        ErrorClass::PaymentStranded,
        ErrorClass::PaymentProofsExpired,
        ErrorClass::RefusedOverwrite,
        ErrorClass::MalformedRestoreRecord,
        ErrorClass::ExportSelfVerifyFailed,
        ErrorClass::ImportAuthFailed,
        ErrorClass::ImportNewerVersion,
        ErrorClass::MalformedConfig,
        ErrorClass::VaultKeyfileMissing,
        ErrorClass::VaultWrapModeUnsupported,
        ErrorClass::RestoreVerificationFailed,
        ErrorClass::RevealInputsUnusable,
        ErrorClass::VerifyBundleRejected,
        ErrorClass::VerifyAnchorRefuted,
        ErrorClass::VerifyHeadlineDivergence,
        ErrorClass::VerifyUnanchored,
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
            ErrorClass::MalformedConfig => 17,
            ErrorClass::VaultKeyfileMissing => 18,
            ErrorClass::VaultWrapModeUnsupported => 19,
            ErrorClass::InsufficientAntToken => 20,
            ErrorClass::InsufficientEthGas => 21,
            ErrorClass::AnchorGateAbort => 22,
            ErrorClass::NetworkFailure => 23,
            ErrorClass::ResumeSafetyAbort => 24,
            ErrorClass::ResumeOverlapNotExact => 25,
            ErrorClass::ResumeFlagMismatch => 26,
            ErrorClass::InvalidSealArgument => 27,
            // D147: the two money-moved classes, taking the first two
            // free codes of the seal/payment/resume band (D69 §1(a)
            // recorded 28 and 29 free) rather than appending past 43 —
            // the placement rule `restore-verification-failed` (35) and
            // `reveal-inputs-unusable` (36) already set.
            ErrorClass::PaymentStranded => 28,
            ErrorClass::PaymentProofsExpired => 29,
            ErrorClass::RefusedOverwrite => 30,
            ErrorClass::MalformedRestoreRecord => 31,
            ErrorClass::ExportSelfVerifyFailed => 32,
            ErrorClass::ImportAuthFailed => 33,
            ErrorClass::ImportNewerVersion => 34,
            ErrorClass::RestoreVerificationFailed => 35,
            // D69 §5: the first free code after restore's band, and
            // deliberately OUTSIDE the reserved 40–49 — a reveal failure is
            // not a bundle-verification verdict and the band's own wording
            // forbids borrowing it.
            ErrorClass::RevealInputsUnusable => 36,
            // D69 §3 R2's verdict band. The **numeric** order runs opposite
            // to the severity rank (41 is the worst rung and 43 the mildest),
            // which is exactly why the ladder is
            // `VerdictExitRung`'s `Ord` derive and never a comparison of
            // these integers.
            ErrorClass::VerifyBundleRejected => 40,
            ErrorClass::VerifyAnchorRefuted => 41,
            ErrorClass::VerifyHeadlineDivergence => 42,
            ErrorClass::VerifyUnanchored => 43,
        }
    }

    /// The class D69's severity rung maps onto — the **one** place a rung
    /// becomes an integer (D69 §3 R1: *"exactly one code table in the
    /// product"*, and §3 R7's "the CLI has no second route to a verdict
    /// code").
    ///
    /// Wildcard-free, so a fourth rung in `antseal-core` fails to compile
    /// here rather than silently taking one of these three codes. The rung's
    /// stable name is core's, and
    /// `the_rung_classes_carry_the_cores_own_names` asserts the two
    /// spellings are equal — the names are not typed twice by hand and
    /// checked by eye.
    #[must_use]
    pub const fn for_rung(rung: VerdictExitRung) -> Self {
        match rung {
            VerdictExitRung::AnchorRefuted => ErrorClass::VerifyAnchorRefuted,
            VerdictExitRung::HeadlineDivergence => ErrorClass::VerifyHeadlineDivergence,
            VerdictExitRung::Unanchored => ErrorClass::VerifyUnanchored,
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
            ErrorClass::MalformedConfig => "malformed-config",
            ErrorClass::VaultKeyfileMissing => "vault-keyfile-missing",
            ErrorClass::VaultWrapModeUnsupported => "vault-wrap-mode-unsupported",
            ErrorClass::InsufficientAntToken => "insufficient-ant-token",
            ErrorClass::InsufficientEthGas => "insufficient-eth-gas",
            ErrorClass::AnchorGateAbort => "anchor-gate-abort",
            ErrorClass::NetworkFailure => "network-failure",
            ErrorClass::ResumeSafetyAbort => "resume-safety-abort",
            ErrorClass::ResumeOverlapNotExact => "resume-overlap-not-exact",
            ErrorClass::ResumeFlagMismatch => "resume-flag-mismatch",
            ErrorClass::InvalidSealArgument => "invalid-seal-argument",
            ErrorClass::PaymentStranded => "payment-stranded",
            ErrorClass::PaymentProofsExpired => "payment-proofs-expired",
            ErrorClass::RefusedOverwrite => "refused-overwrite",
            ErrorClass::MalformedRestoreRecord => "malformed-restore-record",
            ErrorClass::ExportSelfVerifyFailed => "export-self-verify-failed",
            ErrorClass::ImportAuthFailed => "import-auth-failed",
            ErrorClass::ImportNewerVersion => "import-newer-version",
            ErrorClass::RestoreVerificationFailed => "restore-verification-failed",
            ErrorClass::RevealInputsUnusable => "reveal-inputs-unusable",
            // D69 §3 R8. The `verify-` stem is reserved against the
            // verifier's *rejection-code* namespace by the same rule —
            // `docs/testing/error-code-contract.md` §2 rules the two
            // namespaces disjoint, and `tests/namespace_disjointness.rs`
            // machine-checks it.
            ErrorClass::VerifyBundleRejected => "verify-bundle-rejected",
            ErrorClass::VerifyAnchorRefuted => "verify-anchor-refuted",
            ErrorClass::VerifyHeadlineDivergence => "verify-headline-divergence",
            ErrorClass::VerifyUnanchored => "verify-unanchored",
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

    // `AnchorStageUnavailable` lived here from U13 until U22. It was the M1
    // plan-validation refusal of every seal without `--no-anchor`, and its
    // message said "anchoring arrives in M2". U22 wired A20's real gate into
    // `seal_run`, so the sentence became false in a build that can anchor —
    // and a user-facing error stating something this build can do is the
    // failure class this project polices hardest. Removed rather than left
    // unconstructed: an error nothing can produce is a claim about the
    // product that no test can falsify. The refusal that replaces it is the
    // gate's own [`CliError::AnchorGateAbort`] (code 22), raised after
    // consent and before `pay`.
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
    ///
    /// The remedy names **no command**: this message is produced from
    /// `refuse_existing_target`'s `header.exists()` gate
    /// (`vault/export.rs:1208-1213`) with the header never decoded, so it
    /// cannot know whether `antseal vault export` would run for this vault
    /// — and moving the directory is the one instruction true for every
    /// wrap mode (D155 §2 R3).
    #[error(
        "refusing to import over the existing vault at {}: overwriting a vault \
         irreversibly destroys the reveal/restore keys of every work in it. Move that \
         directory aside yourself first — moving it keeps everything, and no antseal command \
         has to run first; delete it only when you are certain nothing in it matters. \
         Scripted overwrite-import is deliberately unsupported (D51)",
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

    /// U4: `config.toml` exists but cannot be honored — a hard, precise
    /// error on every command (silently dropped overrides are worse than
    /// a loud stop; a MISSING file is simply the defaults).
    #[error(
        "malformed config at {}{}: {detail} — fix or remove config.toml (docs/config.md \
         documents the accepted schema and subset); a config that cannot be read is never \
         silently ignored",
        .path.display(),
        line_suffix(*.line)
    )]
    MalformedConfig {
        path: PathBuf,
        /// 1-based line; 0 for whole-file problems.
        line: usize,
        detail: String,
    },

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

    /// **D147**: a payment failed mid-sequence with money already moved. Never
    /// the transient network class — a caller retrying this the way it retries a
    /// peer timeout spends against a wallet that has already paid.
    #[error(
        "payment stranded mid-sequence: {landed_tx_count} sub-batch transaction(s) landed \
         before the failure and the journaled partial receipt is authoritative — this is not \
         a transient network failure and money has already moved: re-run `antseal seal` with \
         the same files and the same seal-shaping flags to finish it, which re-pays no quote \
         the receipt already maps; `antseal list` prints the exact command ({detail})"
    )]
    PaymentStranded {
        /// Sub-batch txs that landed (and were journaled) before the failure.
        landed_tx_count: usize,
        /// The storage layer's own diagnostic rendering (already redacted at
        /// `ant_backend.rs`'s `redact_evm_error`).
        detail: String,
    },

    /// **D147**: D37 Decision 6's expired-proof stranded state. Its own text says
    /// "the already-spent ANT is not recoverable"; it exited 2 — clap's parse-error
    /// code — until this class existed.
    #[error(
        "this seal's payment proofs have expired (the ~24 h node-side window has passed), so \
         the storers reject them: completing it requires a new, separately consented payment — \
         the already-spent ANT is not recoverable"
    )]
    PaymentProofsExpired,

    /// Spec line 145: resume never re-encrypts.
    #[error("resume safety abort: {}", .reason.describe())]
    ResumeSafetyAbort { reason: ResumeSafetyReason },

    /// U8/D50 mode 1: the keyfile factor could not be obtained.
    ///
    /// **Never collapsed into [`Self::VaultAuthFailure`]**, which is U6's
    /// deliberate one-code collapse of "wrong passphrase / tampered
    /// header / corrupt store". That collapse exists because
    /// distinguishing those three would leak which secret-dependent step
    /// failed. A missing keyfile leaks nothing: the header already says
    /// mode 1, so an attacker holding the vault knows a keyfile is
    /// required. Telling a user whose USB stick is unplugged that their
    /// passphrase is wrong would send them to re-type, re-derive and
    /// eventually re-create — which destroys the vault.
    ///
    /// `detail` names the failure class only (absent, unreadable, wrong
    /// size) and never a byte of the file.
    #[error(
        "the vault's keyfile could not be read from {} ({detail}). This vault was created with a keyfile wrap (D50 mode 1), so the keyfile is required alongside the passphrase at every unlock. Point at it with ANTSEAL_KEYFILE=<path> if it has moved; without it the vault cannot be opened by anyone, including you",
        .path.display()
    )]
    VaultKeyfileMissing {
        /// Where the keyfile was looked for (a path the user supplied or
        /// the vault recorded — never secret).
        path: PathBuf,
        /// The failure class, never file content.
        detail: String,
    },

    /// D50: the header names a registered wrap mode this build does not
    /// implement — today only mode 2 (OS keystore), which is reserved so
    /// that a later implementation is purely additive.
    #[error(
        "this vault uses wrap mode {mode} ({name}), which this build does not implement. The mode is a registered id, not corruption: the vault is intact and a build that implements it will open it. Nothing was changed"
    )]
    VaultWrapModeUnsupported {
        /// The D50 registry id found in the header.
        mode: u8,
        /// Its registry name, so the message is readable without the spec.
        name: &'static str,
    },

    /// D45 §2: the invocation's inputs overlap an incomplete work without
    /// matching it exactly — refuse loudly rather than guess.
    ///
    /// The way-forward clause names only actions this build can actually
    /// perform. It used to end "or abandon it first", which was an
    /// instruction with no command behind it: the abandon **mechanism**
    /// exists ([`crate::seal_resume::abandon_pre_pay`]) but the surface
    /// token that would invoke it is D45's deliberately-deferred decision
    /// (U41). An error that tells a trapped user to do something
    /// impossible leaves them worse off than one that names the two exits
    /// that work.
    #[error(
        "these inputs overlap an incomplete seal without matching it exactly ({detail}): \
         re-run with exactly the original path list to resume it, or with a disjoint path \
         list to start a fresh seal — `antseal list` shows the incomplete seal and the \
         exact command that finishes it (D45)"
    )]
    ResumeOverlapNotExact { detail: String },

    /// D45 §2: same inputs, different seal-shaping flags.
    ///
    /// See [`Self::ResumeOverlapNotExact`] on why the way-forward clause
    /// no longer offers an abandon.
    #[error(
        "these inputs match an incomplete seal but the seal-shaping flags differ \
         ({detail}): re-run with the original flags to resume and finish it. This build \
         has no way to discard a staged work, so finishing it — or sealing a copy under a \
         different path — are the two ways forward; `antseal list` shows it (D45)"
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

    /// D48 §6's top-severity restore class: bytes arrived and did not
    /// open their manifest commitment. Nothing was written for the
    /// affected files (S14 returns no bytes for them at all).
    #[error(
        "restore could not verify {failed_files} file(s) against the manifest ({detail}); \
         nothing was written for them — the sealed evidence and the bytes on the network \
         disagree"
    )]
    RestoreVerificationFailed { failed_files: usize, detail: String },

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

    /// D68 §3 R7: `reveal`'s output path is occupied, so nothing was
    /// written.
    ///
    /// **Class, not number**: D68 fixes this at D48 §6's `refused-overwrite`
    /// rung — a local, user-fixable conflict, below evidence problems and
    /// above transient network ones — and leaves the numeric code to U2,
    /// which already has that rung at 30. Hence a distinct variant sharing
    /// [`ErrorClass::RefusedOverwrite`]: the message a bundle owes is not
    /// restore's (which counts files), and the two failures are the same
    /// *class* of problem with the same remedy.
    ///
    /// The way-forward clause names only what exists: move the file, or
    /// choose another path. There is deliberately no `--force` and no
    /// prompt (D48 §5 replaced that convention; a second prompt would
    /// dilute U29's irreversible-disclosure gate).
    #[error(
        "refusing to overwrite the existing {} — a proof bundle is never replaced: you may \
         already have sent this one, and rebuilding it can produce different bytes as its \
         anchors are upgraded. Move that file aside, or write this bundle elsewhere with -o \
         (D68)",
        .path.display()
    )]
    RefusedBundleOverwrite { path: PathBuf },

    /// D69 §5 group 3: something a bundle would have to embed disagrees
    /// with the manifest, so no bundle can be built.
    ///
    /// The reveal-side sibling of [`Self::RestoreVerificationFailed`]:
    /// bytes that do not hash to their recorded address, ciphertext that
    /// will not open, a manifest that does not decode or does not belong to
    /// this work, a vault record that cannot drive a reveal, an anchor
    /// artifact that cannot be embedded, or a builder refusal. **No argv
    /// change and no retry fixes any of them**, which is exactly what
    /// separates this class from `usage` (2) and `network-failure` (23).
    ///
    /// `detail` is the underlying typed error's own sentence: ids, states
    /// and failure classes — never key material, content bytes or receipt
    /// fields (R16's own discipline, carried through unchanged).
    #[error(
        "this work cannot produce a proof bundle: {detail} — no change of arguments and no \
         retry fixes this; the vault's records and the sealed evidence disagree"
    )]
    RevealInputsUnusable { detail: String },

    /// D69 §3 R2's `‡` row: `verify_bundle` returned `Err`, so **no report
    /// exists** (D27 §4 — *"a report exists only for a bundle that passed the
    /// evidence pipeline"*) and there is nothing to fold into a rung.
    ///
    /// **One class for all 248 rejection codes, deliberately.** Tamper,
    /// forgery, malformation, over-cap and non-canonical bytes are the same
    /// answer to a third party's question — *do not rely on this* — and the
    /// two namespaces are ruled disjoint
    /// (`docs/testing/error-code-contract.md` §2: an exit class is a
    /// **process outcome**, a code is a **rejection class**). So the specific
    /// `VerifyError::code()` rides in `code` and therefore in the message,
    /// where a human and a tamper-matrix row both read it, and never in the
    /// integer.
    ///
    /// `code` is `&'static str` because it comes from the frozen
    /// `VerifyError::code()` table, never from bundle bytes; `detail` is the
    /// typed error's own sentence, which carries stage names, counts and
    /// ids — never content bytes or key material.
    #[error("this bundle did not verify: {detail} [{code}]")]
    VerifyBundleRejected {
        /// The frozen rejection code from `VerifyError::code()`.
        code: &'static str,
        /// The typed error's own sentence.
        detail: String,
    },
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
            CliError::MalformedConfig { .. } => ErrorClass::MalformedConfig,
            CliError::VaultKeyfileMissing { .. } => ErrorClass::VaultKeyfileMissing,
            CliError::VaultWrapModeUnsupported { .. } => ErrorClass::VaultWrapModeUnsupported,
            CliError::InsufficientAntToken { .. } => ErrorClass::InsufficientAntToken,
            CliError::InsufficientEthGas { .. } => ErrorClass::InsufficientEthGas,
            CliError::AnchorGateAbort => ErrorClass::AnchorGateAbort,
            CliError::NetworkFailure { .. } => ErrorClass::NetworkFailure,
            CliError::PaymentStranded { .. } => ErrorClass::PaymentStranded,
            CliError::PaymentProofsExpired => ErrorClass::PaymentProofsExpired,
            CliError::ResumeSafetyAbort { .. } => ErrorClass::ResumeSafetyAbort,
            CliError::ResumeOverlapNotExact { .. } => ErrorClass::ResumeOverlapNotExact,
            CliError::ResumeFlagMismatch { .. } => ErrorClass::ResumeFlagMismatch,
            CliError::InvalidSealArgument { .. } => ErrorClass::InvalidSealArgument,
            // D68 §3 R7: one rung, two messages — restore counts files, a
            // reveal names the one path it refused.
            CliError::RefusedOverwrite { .. } | CliError::RefusedBundleOverwrite { .. } => {
                ErrorClass::RefusedOverwrite
            }
            CliError::RevealInputsUnusable { .. } => ErrorClass::RevealInputsUnusable,
            CliError::VerifyBundleRejected { .. } => ErrorClass::VerifyBundleRejected,
            CliError::MalformedRestoreRecord { .. } => ErrorClass::MalformedRestoreRecord,
            CliError::RestoreVerificationFailed { .. } => ErrorClass::RestoreVerificationFailed,
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

    /// The `--json` error object — the inner `error` member of the U3
    /// versioned envelope ([`crate::machine::error_envelope`]). The shape
    /// is U2's provisional one, **finalized unchanged** by U3: `class`
    /// (the stable kebab identifier), `exit_code`, `message`. Changing
    /// any of these three keys is a machine-interface event (the
    /// committed envelope fixtures pin them).
    #[must_use]
    pub fn error_object(&self) -> serde_json::Value {
        serde_json::json!({
            "class": self.class().name(),
            "exit_code": self.exit_code(),
            "message": self.to_string(),
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
            ErrorClass::MalformedConfig => 24,
            ErrorClass::VaultKeyfileMissing => 25,
            ErrorClass::VaultWrapModeUnsupported => 26,
            ErrorClass::RestoreVerificationFailed => 27,
            ErrorClass::RevealInputsUnusable => 28,
            ErrorClass::VerifyBundleRejected => 29,
            ErrorClass::VerifyAnchorRefuted => 30,
            ErrorClass::VerifyHeadlineDivergence => 31,
            ErrorClass::VerifyUnanchored => 32,
            ErrorClass::PaymentStranded => 33,
            ErrorClass::PaymentProofsExpired => 34,
        }
    }

    /// D69 §3 R8's names are `antseal-core`'s, and this crate must not spell
    /// a second copy of them: the rung → class mapping is asserted against
    /// [`VerdictExitRung::name`] rather than against a literal, so a rename
    /// on either side reddens instead of producing two surfaces that
    /// disagree (R27's parity gate compares CLI and page strings).
    #[test]
    fn the_rung_classes_carry_the_cores_own_names() {
        for rung in super::VerdictExitRung::ALL {
            assert_eq!(
                super::ErrorClass::for_rung(rung).name(),
                rung.name(),
                "the rung's name and its class's must be one string"
            );
        }
        // The mapping is injective: three rungs, three distinct codes, none
        // of them 0 and none of them 40 (which is the `Err` arm, not a rung).
        let codes: std::collections::HashSet<u8> = super::VerdictExitRung::ALL
            .into_iter()
            .map(|rung| super::ErrorClass::for_rung(rung).exit_code())
            .collect();
        assert_eq!(codes.len(), 3, "one code per rung");
        assert!(!codes.contains(&40), "40 is the Err arm, never a rung");
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
