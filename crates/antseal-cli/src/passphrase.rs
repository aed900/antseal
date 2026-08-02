//! Passphrase collection (U7): the no-echo prompt, the strength floor,
//! and the `--passphrase-fd` non-interactive channel — with D41's frozen
//! byte semantics and prompt parity.
//!
//! # The two channels (D41)
//!
//! - **`--passphrase-fd <n>`** (adopted channel; stdin is the degenerate
//!   `--passphrase-fd 0`): the secret transits a pipe or redirected file —
//!   never argv, never the environment (D41's measured
//!   `/proc/self/environ` rejection), never disk unless the caller put it
//!   there. Read by [`read_passphrase_fd`] with the frozen semantics
//!   below.
//! - **The interactive prompt**: no-echo TTY entry via the pinned
//!   `rpassword` (termios raw mode; restores the terminal on drop, panic
//!   included; prompt text goes to `/dev/tty`, never stdout — stdout
//!   stays reserved for command output). At create the prompt asks twice
//!   (typo channel); the fd path never confirms (piped input has no typo
//!   channel, D41 §5).
//!
//! # Frozen fd byte semantics (D41, verbatim)
//!
//! 1. read fd `n` to EOF, hard cap [`MAX_PASSPHRASE_FD_BYTES`] (1 KiB) on
//!    the **raw** bytes;
//! 2. strip **exactly one** trailing LF, or CRLF, if present;
//! 3. reject: empty result, and any remaining NUL/LF/CR byte (trailing
//!    included — none of these is enterable at a no-echo prompt, and
//!    parity beats permissiveness);
//! 4. otherwise the bytes are the passphrase **verbatim** — no other
//!    whitespace trimming and **no Unicode normalization** (normalizing
//!    would change KDF input for existing vaults; G's NFC machinery is
//!    for sealed content, never credentials).
//!
//! **Prompt parity**: the prompt yields the entered line minus the
//! terminating newline (and terminal editing), then passes the same
//! forbidden-byte validation — so a vault created via either channel
//! unlocks via either channel, tested cross-channel in this module.
//!
//! # The strength floor (U7's "choose and document the measure")
//!
//! **[`MIN_CREATE_PASSPHRASE_BYTES`] = 12 bytes, length only**, enforced
//! at vault *creation* on both channels (never at unlock — existing
//! vaults own their passphrases). Recorded choice: a byte-length floor is
//! deterministic, channel-parity-exact, and honest — it claims to stop
//! trivially short passphrases, not to measure strength. A zxcvbn-class
//! estimator was rejected for v1: a new scoring dependency plus
//! locale-sensitive judgments in exchange for a number users would
//! game, against a threat model (offline attack on a stolen vault,
//! MVP-SPEC.md line 143) where the real mitigations are the Argon2id
//! memory floor (D40) and passphrase length. Bytes, not characters, so
//! the measure is exactly what the KDF sees (documented at the prompt:
//! multi-byte UTF-8 counts by encoded length).
//!
//! # Machine mode (the D51 primitive U3 consumes)
//!
//! [`machine_mode`] = `--json` ∨ stdin is not a TTY ∨ stdin consumed by
//! `--passphrase-fd 0` — detected via stdin `isatty` only (`/dev/tty`
//! probing is rejected by D51). In machine mode nothing prompts, ever:
//! callers get the typed [`PassphraseFailure::NoChannel`] abort instead
//! of a hang. U3 builds the full interactivity framework on this
//! function; U7 ships the vault-side primitive.
//!
//! # Secret hygiene (U21 discipline)
//!
//! Passphrase bytes live in [`SecretBuf`] from the moment they exist:
//! the fd read pre-reserves its full capacity (no mid-read reallocation
//! strands a partial copy), every rejection path wipes the buffer before
//! returning, and error variants are field-free reason enums — no input
//! byte can appear in any message, log, or JSON object. The
//! `errors_never_carry_input` test drives every failure with a sentinel
//! and scans the rendered errors for it.

use std::io::{IsTerminal, Read};

use antseal_core::crypto::secrets::SecretBuf;
use zeroize::Zeroize;

use crate::error::{CliError, PassphraseFailure};

/// D41: hard cap on the raw bytes read from `--passphrase-fd` (a
/// documented U-constant, not format surface — the strength floor makes
/// longer inputs pointless and the cap bounds a hostile pipe).
pub const MAX_PASSPHRASE_FD_BYTES: usize = 1024;

/// The creation-time strength floor, in bytes (module docs: recorded
/// choice — length floor, channel-parity-exact; applies to `init` and to
/// any future import-to-new-passphrase, never to unlock).
pub const MIN_CREATE_PASSPHRASE_BYTES: usize = 12;

/// What the passphrase is for — decides whether the floor and the
/// create-time confirmation apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PassphrasePurpose {
    /// Unlocking an existing vault: no floor, no confirmation.
    Unlock,
    /// Creating a vault (or re-passphrasing at import): floor enforced on
    /// both channels; the prompt confirms, the fd path does not (D41 §5).
    Create,
}

/// Whether stdin is an interactive terminal — the ONLY TTY probe D51
/// permits (never `/dev/tty`).
#[must_use]
pub fn stdin_is_interactive() -> bool {
    std::io::stdin().is_terminal()
}

/// The D51 machine-mode determination over the real process state.
#[must_use]
pub fn machine_mode(json: bool, passphrase_fd: Option<u32>) -> bool {
    machine_mode_from(stdin_is_interactive(), json, passphrase_fd)
}

/// Pure machine-mode core (deterministically testable): machine mode =
/// `--json` ∨ non-TTY stdin ∨ stdin consumed by `--passphrase-fd 0`.
#[must_use]
pub fn machine_mode_from(stdin_is_tty: bool, json: bool, passphrase_fd: Option<u32>) -> bool {
    json || !stdin_is_tty || passphrase_fd == Some(0)
}

/// Collect the passphrase: fd channel when `--passphrase-fd` was given,
/// else the interactive prompt when stdin is a TTY, else the typed
/// no-channel abort (nothing ever hangs waiting for input that cannot
/// come — D51).
///
/// # Errors
///
/// [`CliError::PassphraseUnavailable`] with the precise
/// [`PassphraseFailure`] reason; [`CliError::Usage`] for a create-time
/// passphrase under the strength floor.
pub fn obtain_passphrase(
    purpose: PassphrasePurpose,
    passphrase_fd: Option<u32>,
) -> Result<SecretBuf, CliError> {
    match passphrase_fd {
        Some(fd) => {
            let secret = read_passphrase_fd(fd)?;
            // D41 §5: the fd path skips confirmation; the floor applies
            // unchanged.
            enforce_create_floor(purpose, &secret)?;
            Ok(secret)
        }
        None if stdin_is_interactive() => collect_from_prompt(purpose, &mut TtyPrompt),
        None => Err(CliError::PassphraseUnavailable {
            reason: PassphraseFailure::NoChannel,
        }),
    }
}

/// Read a passphrase from file descriptor `fd` with the frozen D41 byte
/// semantics (module docs).
///
/// fd 0 reads the process's stdin; any other fd is reached through
/// `/dev/fd/<n>` (POSIX; on Linux a procfs symlink, on macOS a devfs
/// node — both reopen the same open file description's object, which is
/// exactly how shell `<(…)` substitution works). Windows has no fd
/// namespace: the channel reports [`PassphraseFailure::FdReadFailed`]
/// there, recorded as a platform limit of the gpg-convention design.
///
/// # Errors
///
/// [`CliError::PassphraseUnavailable`] with reason
/// `FdReadFailed`/`FdOverCap`/`FdEmpty`/`FdForbiddenByte` per D41.
pub fn read_passphrase_fd(fd: u32) -> Result<SecretBuf, CliError> {
    read_secret_fd(fd).map_err(|reason| CliError::PassphraseUnavailable { reason })
}

/// The channel itself, one layer down: the frozen D41 byte semantics with
/// the failure returned as a bare [`PassphraseFailure`] rather than
/// wrapped in the passphrase error class.
///
/// Split out for U11's `--wallet-key-fd` (D39/D44): a wallet key is a
/// **different secret on a different channel**, so it must reuse these
/// exact bytes-and-newline rules while reporting its own error — reporting
/// a passphrase failure would send the user to the wrong flag. The byte
/// semantics are the shared part; the class is not.
///
/// # Errors
///
/// `FdReadFailed`/`FdOverCap`/`FdEmpty`/`FdForbiddenByte` per D41.
pub fn read_secret_fd(fd: u32) -> Result<SecretBuf, PassphraseFailure> {
    let fail = |reason| reason;

    // Pre-reserve the full cap so the growing read never reallocates —
    // a reallocation would strand an unwipeable partial copy.
    let mut raw: Vec<u8> = Vec::with_capacity(MAX_PASSPHRASE_FD_BYTES + 1);
    let read_result = if fd == 0 {
        std::io::stdin()
            .lock()
            .take((MAX_PASSPHRASE_FD_BYTES + 1) as u64)
            .read_to_end(&mut raw)
    } else {
        std::fs::File::open(format!("/dev/fd/{fd}")).and_then(|f| {
            f.take((MAX_PASSPHRASE_FD_BYTES + 1) as u64)
                .read_to_end(&mut raw)
        })
    };
    if let Err(_e) = read_result {
        raw.zeroize();
        return Err(fail(PassphraseFailure::FdReadFailed));
    }
    if raw.len() > MAX_PASSPHRASE_FD_BYTES {
        raw.zeroize();
        return Err(fail(PassphraseFailure::FdOverCap));
    }

    // Strip exactly one trailing LF or CRLF. `truncate` keeps the bytes
    // in the allocation; the same Vec moves into SecretBuf below, whose
    // drop wipes the full capacity — stripped bytes included.
    if raw.last() == Some(&b'\n') {
        raw.truncate(raw.len() - 1);
        if raw.last() == Some(&b'\r') {
            raw.truncate(raw.len() - 1);
        }
    }
    if raw.is_empty() {
        // (Nothing secret to wipe, but stay uniform.)
        raw.zeroize();
        return Err(fail(PassphraseFailure::FdEmpty));
    }
    if raw.iter().any(|b| matches!(b, 0x00 | b'\n' | b'\r')) {
        raw.zeroize();
        return Err(fail(PassphraseFailure::FdForbiddenByte));
    }
    Ok(SecretBuf::new(raw))
}

/// Enforce the creation-time floor (no-op at unlock).
///
/// # Errors
///
/// [`CliError::Usage`] naming the floor — never the input or its exact
/// length (passphrase length is guessing-relevant, so even the rejection
/// message only says "shorter than").
pub fn enforce_create_floor(
    purpose: PassphrasePurpose,
    secret: &SecretBuf,
) -> Result<(), CliError> {
    if purpose == PassphrasePurpose::Create && secret.len() < MIN_CREATE_PASSPHRASE_BYTES {
        return Err(CliError::Usage {
            message: format!(
                "the passphrase is shorter than the {MIN_CREATE_PASSPHRASE_BYTES}-byte minimum \
                 (bytes, not characters); this vault's contents are permanent, public \
                 ciphertexts once sealed — pick a long passphrase you can keep forever"
            ),
        });
    }
    Ok(())
}

/// The prompt seam: production reads the TTY through rpassword; unit
/// tests inject scripted entries. Kept crate-private — U11's wizard will
/// define its own interaction seam over this module's public functions.
pub(crate) trait SecretPrompt {
    /// Show `prompt` (never on stdout) and read one no-echo line, without
    /// its terminating newline.
    fn read_secret_line(&mut self, prompt: &str) -> std::io::Result<String>;
}

/// The production prompt: rpassword over `/dev/tty` (raw mode, echo off,
/// terminal restored on drop even under panic).
pub(crate) struct TtyPrompt;

impl SecretPrompt for TtyPrompt {
    fn read_secret_line(&mut self, prompt: &str) -> std::io::Result<String> {
        rpassword::prompt_password(prompt)
    }
}

/// Interactive collection: entry (+ confirmation at create), empty and
/// forbidden-byte rejection for parity, floor at create.
pub(crate) fn collect_from_prompt(
    purpose: PassphrasePurpose,
    prompt: &mut impl SecretPrompt,
) -> Result<SecretBuf, CliError> {
    let fail = |reason| CliError::PassphraseUnavailable { reason };
    let text = match purpose {
        PassphrasePurpose::Unlock => "Vault passphrase: ",
        PassphrasePurpose::Create => "New vault passphrase (12-byte minimum): ",
    };
    let first = read_prompt_line(prompt, text)?;
    if first.is_empty() {
        return Err(fail(PassphraseFailure::PromptEmpty));
    }
    enforce_create_floor(purpose, &first)?;
    if purpose == PassphrasePurpose::Create {
        let second = read_prompt_line(prompt, "Confirm passphrase: ")?;
        if first.as_bytes() != second.as_bytes() {
            return Err(fail(PassphraseFailure::ConfirmMismatch));
        }
        // `second` drops (and wipes) here; `first` is the value.
    }
    Ok(first)
}

/// One prompted line into a zeroizing buffer, with the parity
/// forbidden-byte check (interior NUL/LF/CR can reach us through exotic
/// terminals or injected readers; the prompt channel must accept exactly
/// the fd channel's byte space).
fn read_prompt_line(prompt: &mut impl SecretPrompt, text: &str) -> Result<SecretBuf, CliError> {
    let fail = |reason| CliError::PassphraseUnavailable { reason };
    let line = prompt
        .read_secret_line(text)
        .map_err(|_| fail(PassphraseFailure::PromptFailed))?;
    // Move, not copy: the String's buffer becomes the SecretBuf.
    let secret = SecretBuf::new(line.into_bytes());
    if secret
        .as_bytes()
        .iter()
        .any(|b| matches!(b, 0x00 | b'\n' | b'\r'))
    {
        return Err(fail(PassphraseFailure::FdForbiddenByte));
    }
    Ok(secret)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ErrorClass;
    use std::collections::VecDeque;

    /// Scripted prompt for the seam (each call pops one line).
    struct Scripted(VecDeque<Result<String, ()>>);

    impl Scripted {
        fn lines(lines: &[&str]) -> Self {
            Scripted(lines.iter().map(|l| Ok((*l).to_owned())).collect())
        }
    }

    impl SecretPrompt for Scripted {
        fn read_secret_line(&mut self, _prompt: &str) -> std::io::Result<String> {
            match self.0.pop_front() {
                Some(Ok(line)) => Ok(line),
                Some(Err(())) | None => Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "script exhausted",
                )),
            }
        }
    }

    fn reason_of(err: &CliError) -> PassphraseFailure {
        match err {
            CliError::PassphraseUnavailable { reason } => *reason,
            other => panic!("expected PassphraseUnavailable, got {other:?}"),
        }
    }

    #[test]
    fn create_prompts_twice_and_matching_confirmation_succeeds() {
        let mut prompt = Scripted::lines(&[
            "correct horse battery staple",
            "correct horse battery staple",
        ]);
        let secret =
            collect_from_prompt(PassphrasePurpose::Create, &mut prompt).expect("collected");
        assert_eq!(secret.as_bytes(), b"correct horse battery staple");
        assert!(prompt.0.is_empty(), "both scripted lines consumed");
    }

    #[test]
    fn create_confirmation_mismatch_is_typed() {
        let mut prompt = Scripted::lines(&[
            "correct horse battery staple",
            "correct horse battery stable",
        ]);
        let err =
            collect_from_prompt(PassphrasePurpose::Create, &mut prompt).expect_err("mismatch");
        assert_eq!(reason_of(&err), PassphraseFailure::ConfirmMismatch);
        assert_eq!(err.class(), ErrorClass::PassphraseUnavailable);
    }

    #[test]
    fn unlock_prompts_once_and_applies_no_floor() {
        let mut prompt = Scripted::lines(&["short"]);
        let secret =
            collect_from_prompt(PassphrasePurpose::Unlock, &mut prompt).expect("collected");
        assert_eq!(secret.as_bytes(), b"short");
    }

    #[test]
    fn create_floor_rejects_eleven_bytes_and_accepts_twelve() {
        let mut prompt = Scripted::lines(&["elevenchars"]);
        let err = collect_from_prompt(PassphrasePurpose::Create, &mut prompt).expect_err("floor");
        assert_eq!(err.class(), ErrorClass::Usage);
        assert!(err.to_string().contains("12-byte minimum"), "{err}");

        let mut prompt = Scripted::lines(&["twelve chars", "twelve chars"]);
        let secret = collect_from_prompt(PassphrasePurpose::Create, &mut prompt).expect("at floor");
        assert_eq!(secret.len(), 12);
    }

    #[test]
    fn prompt_empty_and_eof_are_typed() {
        let mut prompt = Scripted::lines(&[""]);
        let err = collect_from_prompt(PassphrasePurpose::Unlock, &mut prompt).expect_err("empty");
        assert_eq!(reason_of(&err), PassphraseFailure::PromptEmpty);

        let mut prompt = Scripted(VecDeque::new());
        let err = collect_from_prompt(PassphrasePurpose::Unlock, &mut prompt).expect_err("eof");
        assert_eq!(reason_of(&err), PassphraseFailure::PromptFailed);
    }

    /// Parity: an injected prompt line with interior control bytes is
    /// rejected exactly like the fd channel would reject it.
    #[test]
    fn prompt_forbidden_bytes_rejected_for_parity() {
        for bad in ["with\nnewline", "with\rreturn", "with\0nul"] {
            let mut prompt = Scripted::lines(&[bad]);
            let err = collect_from_prompt(PassphrasePurpose::Unlock, &mut prompt).expect_err(bad);
            assert_eq!(reason_of(&err), PassphraseFailure::FdForbiddenByte);
        }
    }

    /// The D41 prompt-parity rule, executed against a REAL vault: create
    /// with the prompt-collected buffer, unlock with the fd-collected one
    /// — same logical passphrase, both channels, one vault.
    #[test]
    fn prompt_and_fd_channels_unlock_the_same_vault() {
        use crate::vault::kdf::KdfSelection;
        use crate::vault::layout::VaultLayout;
        use crate::vault::session::{create_vault, unlock_vault};
        use rand_core::SeedableRng;

        // Prompt side: entry + confirmation.
        let mut prompt =
            Scripted::lines(&["parity fixture passphrase", "parity fixture passphrase"]);
        let via_prompt =
            collect_from_prompt(PassphrasePurpose::Create, &mut prompt).expect("prompt side");

        // fd side: the same logical passphrase as `printf '%s\n'` would
        // pipe it, via a real file descriptor.
        let dir = std::env::temp_dir().join(format!(
            "antseal-cli-parity-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("mk test dir");
        let secret_file = dir.join("pass-input");
        std::fs::write(&secret_file, b"parity fixture passphrase\n").expect("write input");
        let handle = std::fs::File::open(&secret_file).expect("open input");
        let fd = {
            use std::os::fd::AsRawFd;
            u32::try_from(handle.as_raw_fd()).expect("fd fits")
        };
        let via_fd = read_passphrase_fd(fd).expect("fd side");
        drop(handle);

        assert_eq!(
            via_prompt.as_bytes(),
            via_fd.as_bytes(),
            "channel parity at the byte level"
        );

        // And through the vault: create with one channel's output, unlock
        // with the other's.
        let layout = VaultLayout::at(dir.join("vault"));
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([0x42u8; 32]);
        create_vault(&layout, &via_prompt, KdfSelection::Argon2id, &mut rng)
            .expect("create via prompt-collected passphrase");
        unlock_vault(&layout, &via_fd).expect("unlock via fd-collected passphrase");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
