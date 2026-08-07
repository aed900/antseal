//! The one way this crate's tests construct the `antseal` binary
//! (**Q16**, decision [D99] R4.1).
//!
//! Include it with
//!
//! ```ignore
//! #[path = "common/spawn.rs"]
//! mod spawn;
//! ```
//!
//! rather than as a submodule of [`common`](super), so a suite that only
//! needs to spawn a process does not drag in the pipeline harness's
//! `MockBackend`, vault fixtures and Argon2id `OnceLock`.
//!
//! # The defect this closes
//!
//! Q16's gate has two arms (`crates/antseal-anchor/src/http/offline.rs`): a
//! `cfg(test)` arm the compiler arms and nobody can switch off, and the
//! `ANTSEAL_NO_REAL_ANCHOR_NETWORK` environment arm. The first one **does not
//! cover this crate**. `cfg!(test)` is evaluated in *antseal-anchor's own*
//! compilation, and when `antseal-cli`'s integration tests link
//! `antseal-anchor` they link its ordinary, non-`cfg(test)` build — so in
//! `crates/antseal-cli/tests/` only the environment arm exists.
//!
//! CI arms it workflow-wide (`.github/workflows/ci.yml`) and
//! `scripts/local-gate.sh` exports it, so both gating venues were covered.
//! A bare `cargo test -p antseal-cli` — what a contributor actually types —
//! armed nothing. Measured on 2026-08-06 with a probe compiled into this
//! directory and then removed:
//!
//! ```text
//! $ cargo test -p antseal-cli --test <probe> -- --nocapture
//! D99-PROBE env=None deny_reason=None
//! D99-PROBE send=Err(Status { endpoint: "https://freetsa.org/tsr", status: 403, … })
//! ```
//!
//! That second line is the part that matters, and it is not a prediction: the
//! probe **reached freetsa.org**. DNS resolved, TCP connected, TLS completed
//! and a real third-party server answered. The same probe with the variable
//! set returns `RealNetworkDenied` in 0.00 s, before any address is resolved.
//! So the exposure was live, not theoretical, and every suite here that
//! spawns the binary inherits whatever the developer's shell happened to
//! export.
//!
//! U24's opportunistic upgrade hook is what makes this urgent rather than
//! merely untidy. It fires on **every** vault-holding invocation, and its
//! calendar URIs come out of a stored `.ots` artifact rather than out of any
//! source text — so `anchor_stage.rs`'s
//! `no_test_source_names_a_live_anchor_endpoint` scanner, which is this
//! crate's existing defence, cannot see them at all. A42's allowlist admits
//! the real calendar hostnames by design. That is the Q16 §2 violation
//! verbatim, waiting to recur one crate over.
//!
//! # Why a test cannot simply arm its own process
//!
//! It is the obvious idea, it is unavailable, and it is unavailable twice
//! over. Both halves were confirmed by compiling them on 2026-08-06, not by
//! reading:
//!
//! ```text
//! std::env::set_var("ANTSEAL_NO_REAL_ANCHOR_NETWORK", "1");
//!   error[E0133]: call to unsafe function `set_var` is unsafe and requires
//!                 unsafe block                       ← edition 2024
//!
//! unsafe { std::env::set_var(…) };
//!   error: usage of an `unsafe` block                ← Cargo.toml,
//!                                        [workspace.lints.rust] unsafe_code = "deny"
//! ```
//!
//! And it would be racy across libtest's threads even if both were available:
//! the process environment is global, the tests are not. The same constraint
//! is recorded on the other side of the seam at
//! `crates/antseal-anchor/tests/no_real_network.rs`, as the reason *that*
//! test spawns a child process instead of setting a variable.
//!
//! **The consequence is a rule, and it is enforced rather than advised: no
//! test source may call [`antseal_cli::main_entry`].** An in-process entry
//! cannot be armed, so an in-process entry that dials calendars cannot be
//! made safe — the venue has to stay closed rather than be made careful.
//! `scripts/check-anchor-net.py` R4 refuses both a `main_entry` call in a
//! test source and a bare `CARGO_BIN_EXE_antseal` outside this file.
//!
//! [D99]: ../../../../docs/decisions/D99-upgrade-hook-placement-and-test-seam.md

#![allow(dead_code)] // a suite uses the command, the path, or both

/// Q16's environment arm. Named here rather than spelled inline so the helper
/// and `antseal_anchor::http::offline::NO_REAL_NETWORK_ENV` cannot drift into
/// two different strings that both look right.
pub const NO_REAL_ANCHOR_NETWORK: &str = "ANTSEAL_NO_REAL_ANCHOR_NETWORK";

/// The `antseal` binary, with Q16's gate **armed**.
///
/// Every construction site in `crates/antseal-cli/tests/` goes through here.
/// Nothing else may name `CARGO_BIN_EXE_antseal`; `check-anchor-net.py` R4
/// enforces that, with planted faults proving it can fail.
///
/// Deliberately minimal: it sets the one variable and nothing else. Suites
/// clear `RUST_LOG`, `ANTSEAL_DIR` and the rest for their own reasons, and a
/// helper that also had opinions about those would be a helper suites started
/// working around.
#[must_use]
pub fn antseal() -> std::process::Command {
    let mut command = std::process::Command::new(antseal_exe());
    // Q16 / D99 R4.1. `docs/testing/anchor-ci-policy.md` §3.1. Removing this
    // line is measured to let the suite reach live calendars and TSAs — see
    // the module docs for the probe output.
    command.env(NO_REAL_ANCHOR_NETWORK, "1");
    command
}

/// The binary's path, for a suite that needs to *recognise* the process
/// rather than start it.
///
/// `secret_hygiene.rs` waits for `/proc/<pid>/cmdline` to name the binary, to
/// be sure it is reading the child after `execve` rather than the test binary
/// between `fork` and `execve`. It needs the path, not a `Command` — and
/// giving it this accessor is what lets R4's rule stay a flat "only this file
/// names `CARGO_BIN_EXE_antseal`" with no exemption list. A rule with an
/// exemption list is a rule the next caller adds itself to.
#[must_use]
pub fn antseal_exe() -> &'static str {
    env!("CARGO_BIN_EXE_antseal")
}
