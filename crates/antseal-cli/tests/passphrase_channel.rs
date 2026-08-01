//! U7 acceptance suite: the `--passphrase-fd` channel's frozen D41 byte
//! semantics over real file descriptors (files AND pipes), the machine-
//! mode primitive, and the U21 sentinel discipline.
//!
//! Prompt-side behavior (confirmation, floor, parity against a real
//! vault) lives with the seam as unit tests in `src/passphrase.rs`; this
//! file exercises the public channel end to end.
//!
//! Unix-only: the fd channel reaches non-stdin descriptors through
//! `/dev/fd/<n>`, which Windows does not have — recorded as a platform
//! limit of the gpg-convention design (module docs of
//! `antseal_cli::passphrase`).
//!
//! NON-SECRET: every "passphrase" here is a documented fixture; the
//! sentinel exists precisely to prove it never surfaces.

#![cfg(unix)]

use std::io::Write;
use std::os::fd::AsRawFd;
use std::path::PathBuf;

use antseal_cli::error::{CliError, ErrorClass, PassphraseFailure};
use antseal_cli::passphrase::{
    MAX_PASSPHRASE_FD_BYTES, MIN_CREATE_PASSPHRASE_BYTES, PassphrasePurpose, enforce_create_floor,
    machine_mode_from, read_passphrase_fd,
};
use antseal_core::crypto::secrets::SecretBuf;

// ─────────────────────────────────────────────────────────────────────
// Scaffolding
// ─────────────────────────────────────────────────────────────────────

struct TestDir(PathBuf);

impl TestDir {
    fn new(tag: &str) -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "antseal-cli-pfd-{tag}-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
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

/// Run `read_passphrase_fd` over a real regular-file descriptor holding
/// `bytes` (the `--passphrase-fd 3 3<secret.file` shape).
fn via_file(tag: &str, bytes: &[u8]) -> Result<SecretBuf, CliError> {
    let dir = TestDir::new(tag);
    let path = dir.0.join("input");
    std::fs::write(&path, bytes).expect("write input");
    let handle = std::fs::File::open(&path).expect("open input");
    let fd = u32::try_from(handle.as_raw_fd()).expect("fd fits");
    let result = read_passphrase_fd(fd);
    drop(handle);
    result
}

/// Run `read_passphrase_fd` over a real PIPE read end (the
/// `printf '%s' "$PASS" | antseal …` shape): a child process writes the
/// bytes and closes, the test reads the child's stdout descriptor.
fn via_pipe(bytes: &[u8]) -> Result<SecretBuf, CliError> {
    let mut child = std::process::Command::new("sh")
        .arg("-c")
        // The bytes travel via the child's stdin -> cat -> its stdout
        // pipe, so no byte value needs shell quoting.
        .arg("cat")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("spawn cat");
    child
        .stdin
        .take()
        .expect("stdin handle")
        .write_all(bytes)
        .expect("feed pipe");
    // stdin dropped: the child copies and exits; the pipe read end holds
    // the buffered bytes + EOF.
    let stdout = child.stdout.take().expect("stdout handle");
    let fd = u32::try_from(stdout.as_raw_fd()).expect("fd fits");
    let result = read_passphrase_fd(fd);
    drop(stdout);
    let _ = child.wait();
    result
}

fn reason_of(err: &CliError) -> PassphraseFailure {
    match err {
        CliError::PassphraseUnavailable { reason } => *reason,
        other => panic!("expected PassphraseUnavailable, got {other:?}"),
    }
}

// ─────────────────────────────────────────────────────────────────────
// D41 byte semantics, file-descriptor variant
// ─────────────────────────────────────────────────────────────────────

/// The strip rule: exactly one trailing LF, or CRLF; nothing else.
#[test]
fn strips_exactly_one_trailing_newline() {
    let cases: [(&[u8], &[u8]); 4] = [
        (b"fixture pass\n", b"fixture pass"),
        (b"fixture pass\r\n", b"fixture pass"),
        (b"fixture pass", b"fixture pass"),
        // No trimming of any other whitespace: verbatim rule.
        (b"  spaced fixture  \n", b"  spaced fixture  "),
    ];
    for (input, expected) in cases {
        let secret = via_file("strip", input).expect("accepted");
        assert_eq!(secret.as_bytes(), expected, "input {input:?}");
    }
}

/// UTF-8 passes through verbatim: no Unicode normalization, ever (a
/// normalizing change would re-key existing vaults — D41 §4).
#[test]
fn utf8_bytes_are_verbatim() {
    let input = "p\u{00e4}ssw\u{00f6}rd-\u{00fc}nicode fixture\n";
    let secret = via_file("utf8", input.as_bytes()).expect("accepted");
    assert_eq!(secret.as_bytes(), input.trim_end_matches('\n').as_bytes());
}

/// Empty inputs (truly empty, or newline-only) abort with the dedicated
/// code.
#[test]
fn empty_inputs_are_rejected() {
    for input in [&b""[..], &b"\n"[..], &b"\r\n"[..]] {
        let err = via_file("empty", input).expect_err("must reject");
        assert_eq!(
            reason_of(&err),
            PassphraseFailure::FdEmpty,
            "input {input:?}"
        );
        assert_eq!(err.class(), ErrorClass::PassphraseUnavailable);
        assert_eq!(err.exit_code(), 11);
    }
}

/// Interior (and unstripped trailing) NUL/LF/CR reject for prompt parity.
#[test]
fn forbidden_bytes_are_rejected() {
    let cases: [&[u8]; 5] = [
        b"with\ninterior newline\n",
        b"with\rinterior return\n",
        b"with\0interior nul\n",
        // Two trailing newlines: one is stripped, the second is forbidden.
        b"fixture pass\n\n",
        // A lone trailing CR is not part of the strip rule.
        b"fixture pass\r",
    ];
    for input in cases {
        let err = via_file("forbidden", input).expect_err("must reject");
        assert_eq!(
            reason_of(&err),
            PassphraseFailure::FdForbiddenByte,
            "input {input:?}"
        );
    }
}

/// The 1 KiB cap applies to the RAW fd bytes, pre-strip.
#[test]
fn one_kib_cap_is_enforced_on_raw_bytes() {
    // Exactly at cap, no newline: accepted, verbatim.
    let at_cap = vec![b'a'; MAX_PASSPHRASE_FD_BYTES];
    let secret = via_file("cap", &at_cap).expect("at cap accepted");
    assert_eq!(secret.len(), MAX_PASSPHRASE_FD_BYTES);

    // At cap including the newline: accepted, stripped.
    let mut with_nl = vec![b'a'; MAX_PASSPHRASE_FD_BYTES - 1];
    with_nl.push(b'\n');
    let secret = via_file("cap-nl", &with_nl).expect("cap incl newline accepted");
    assert_eq!(secret.len(), MAX_PASSPHRASE_FD_BYTES - 1);

    // One raw byte over: rejected before any strip.
    let over = vec![b'a'; MAX_PASSPHRASE_FD_BYTES + 1];
    let err = via_file("cap-over", &over).expect_err("over cap");
    assert_eq!(reason_of(&err), PassphraseFailure::FdOverCap);

    // A cap-length passphrase plus its newline is over the raw cap too —
    // the cap is on fd bytes, not on the post-strip value (documented).
    let mut passphrase_at_cap_plus_nl = vec![b'a'; MAX_PASSPHRASE_FD_BYTES];
    passphrase_at_cap_plus_nl.push(b'\n');
    let err = via_file("cap-nl-over", &passphrase_at_cap_plus_nl).expect_err("over raw cap");
    assert_eq!(reason_of(&err), PassphraseFailure::FdOverCap);
}

/// A descriptor that does not exist fails with the read-failure reason
/// (also the recorded Windows behavior for every non-stdin fd).
#[test]
fn unreadable_fd_is_a_read_failure() {
    let err = read_passphrase_fd(987).expect_err("no such fd");
    assert_eq!(reason_of(&err), PassphraseFailure::FdReadFailed);
    assert_eq!(err.exit_code(), 11);
}

// ─────────────────────────────────────────────────────────────────────
// The pipe variant (the shape scripts and the S17–S19 harness use)
// ─────────────────────────────────────────────────────────────────────

/// The same semantics hold over a real pipe: verbatim value, one-newline
/// strip, forbidden-byte rejection.
#[test]
fn pipe_variant_matches_file_variant() {
    let secret = via_pipe(b"piped fixture passphrase\n").expect("accepted");
    assert_eq!(secret.as_bytes(), b"piped fixture passphrase");

    let secret = via_pipe(b"piped no newline").expect("accepted");
    assert_eq!(secret.as_bytes(), b"piped no newline");

    let err = via_pipe(b"piped\0nul\n").expect_err("forbidden");
    assert_eq!(reason_of(&err), PassphraseFailure::FdForbiddenByte);
}

// ─────────────────────────────────────────────────────────────────────
// Machine mode (the D51 primitive U3 consumes) and the floor
// ─────────────────────────────────────────────────────────────────────

/// The pure machine-mode truth table: `--json` ∨ non-TTY stdin ∨
/// `--passphrase-fd 0`.
#[test]
fn machine_mode_truth_table() {
    // (stdin_is_tty, json, passphrase_fd) → machine mode
    let cases = [
        ((true, false, None), false),
        ((true, true, None), true),
        ((false, false, None), true),
        ((true, false, Some(0)), true),
        ((true, false, Some(3)), false),
        ((false, true, Some(0)), true),
    ];
    for ((tty, json, fd), expected) in cases {
        assert_eq!(
            machine_mode_from(tty, json, fd),
            expected,
            "stdin_tty={tty} json={json} fd={fd:?}"
        );
    }
}

/// The floor applies at create only, on the byte length.
#[test]
fn create_floor_is_twelve_bytes_and_unlock_has_none() {
    let eleven = SecretBuf::new(b"elevenchars".to_vec());
    let twelve = SecretBuf::new(b"twelve chars".to_vec());
    assert_eq!(MIN_CREATE_PASSPHRASE_BYTES, 12);
    assert!(enforce_create_floor(PassphrasePurpose::Create, &eleven).is_err());
    assert!(enforce_create_floor(PassphrasePurpose::Create, &twelve).is_ok());
    assert!(enforce_create_floor(PassphrasePurpose::Unlock, &eleven).is_ok());

    // A multi-byte character counts by encoded length (bytes, not chars):
    // six ä's are twelve bytes.
    let six_umlauts = SecretBuf::new("\u{00e4}".repeat(6).into_bytes());
    assert_eq!(six_umlauts.len(), 12);
    assert!(enforce_create_floor(PassphrasePurpose::Create, &six_umlauts).is_ok());
}

// ─────────────────────────────────────────────────────────────────────
// U21 discipline: no passphrase bytes in any rendered error
// ─────────────────────────────────────────────────────────────────────

/// Every failure path is driven with a sentinel-bearing input; the
/// rendered error (Display, Debug, and the JSON object) must never
/// contain it. Structural backing: `PassphraseFailure` reasons are
/// field-free, so there is nothing to interpolate — this test keeps that
/// structural fact load-bearing.
#[test]
fn errors_never_carry_input() {
    const SENTINEL: &str = "SENTINEL-cc180ac0-passphrase";

    let failures: Vec<CliError> = vec![
        // Forbidden byte, sentinel on both sides of it.
        via_file(
            "sent-forbidden",
            format!("{SENTINEL}\n{SENTINEL}\n").as_bytes(),
        )
        .expect_err("forbidden"),
        // Over-cap, sentinel-repeated payload.
        via_file(
            "sent-cap",
            SENTINEL
                .repeat(1 + MAX_PASSPHRASE_FD_BYTES / SENTINEL.len())
                .as_bytes(),
        )
        .expect_err("over cap"),
        // Floor rejection over a sentinel-prefixed (11-byte) secret.
        enforce_create_floor(
            PassphrasePurpose::Create,
            &SecretBuf::new(b"SENTINEL-cc".to_vec()),
        )
        .expect_err("floor"),
    ];
    for err in failures {
        let display = err.to_string();
        let debug = format!("{err:?}");
        let json =
            antseal_cli::machine::error_envelope("vault export", "arbitrum-one", &err).to_string();
        for rendered in [&display, &debug, &json] {
            assert!(
                !rendered.contains("SENTINEL"),
                "sentinel leaked into a rendered error: {rendered}"
            );
        }
    }
}
