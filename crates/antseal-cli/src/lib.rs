//! `antseal_cli` — the orchestration layer of the antseal CLI (D34).
//!
//! Per docs/decisions/D34-seal-pipeline-placement.md this library target is
//! where the seal pipeline (S12), the journal state machine (S10), resume
//! (S11), restore (S14) and — at M3 — the reveal flow live, written over
//! injected backend/gate/journal/consent interfaces so the M1 E2E drives
//! sealing via library APIs, never by spawning the binary. The binary
//! (`src/main.rs`) is a thin argv→[`main_entry`] driver.
//!
//! Interface-direction rules (D34 §2): the pipeline consumes
//! `antseal_net::StorageBackend` generically (trait and types stay in
//! `antseal-net`); the anchor-gate contract is defined on the A side and
//! consumed here; the consent-hook and `SealJournal` interfaces are defined
//! in this library and implemented by the interactive layer, the vault
//! store, and test doubles. `antseal-core`/`antseal-net` never learn any of
//! them exist.
//!
//! **Stability**: this library's API is NOT a stability-committed interface
//! — it exists for the binary and the workspace's own harnesses. Whether it
//! ever publishes (and freezes) is D72's open M4 decision (D34, residual
//! risk 4). Consume it from outside this workspace at your own risk.

pub mod cli;
pub mod error;
mod run;

use std::process::ExitCode;

// Intentional dependency edge (P5): the CLI is a thin shell over
// antseal-core; real consumption begins with the pipeline (U13).
use antseal_core as _;

/// Full CLI entry: parse, dispatch, and map every outcome to its
/// documented exit code. Testable — it never calls `process::exit`.
///
/// Exit codes at U1 (the full U2 table extends this): 0 success (also
/// `--help`/`--version`, clap's convention), 2 usage error, and the
/// [`error::CliError::exit_code`] values for dispatched failures.
pub fn main_entry<I, T>(args: I) -> ExitCode
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    let cli = match cli::Cli::parse_checked(args) {
        Ok(cli) => cli,
        Err(clap_err) => {
            // `print` writes help/version to stdout and usage errors to
            // stderr; `exit_code` is 0 for the former, 2 for the latter —
            // clap's own convention, kept as the documented usage code.
            let code = clap_err.exit_code();
            let _ = clap_err.print();
            return ExitCode::from(u8::try_from(code).unwrap_or(1));
        }
    };
    match run::run(&cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::from(err.exit_code())
        }
    }
}

/// Install the process-global tracing subscriber: stderr only, env-filter
/// driven (`RUST_LOG`). stdout stays reserved for command output — under
/// `--json` it must carry exactly one JSON document (D51), so logs may
/// never race onto it. Called once by the binary; library tests install
/// nothing.
pub fn init_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();
}
