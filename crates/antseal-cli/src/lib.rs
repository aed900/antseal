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

pub mod backend;
pub mod cli;
mod commands;
pub mod config;
pub mod error;
pub mod init;
pub mod listing;
pub mod machine;
pub mod passphrase;
pub mod pipeline;
pub mod restore_out;
pub mod rng;
mod run;
pub mod seal_consent;
pub mod seal_plan;
pub mod seal_resume;
pub mod seal_run;
pub mod seal_warnings;
pub mod vault;

use std::process::ExitCode;

// Intentional dependency edge (P5): the CLI is a thin shell over
// antseal-core; real consumption begins with the pipeline (U13).
use antseal_core as _;

/// Full CLI entry: parse, dispatch, and map every outcome to its
/// documented exit code (the U2 table in [`error`]). Testable — it never
/// calls `process::exit`.
///
/// The machine-output contract lives in [`machine`] (U3): under `--json`,
/// stdout carries exactly one versioned envelope per invocation — success
/// or failure — with the same exit code as plain mode; every human byte
/// goes to stderr. clap-level outcomes keep clap's convention:
/// help/version render on stdout with code 0 (the documented intrinsic
/// exemption), and unparseable argv exits 2 with clap's message on
/// stderr — plus a best-effort null-command envelope on stdout when the
/// literal `--json` token is present in argv (the parse that failed is
/// the only intent source there; see [`machine::argv_requests_json`]).
pub fn main_entry<I, T>(args: I) -> ExitCode
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    let args: Vec<std::ffi::OsString> = args.into_iter().map(Into::into).collect();
    let json_token = machine::argv_requests_json(&args);
    let cli = match cli::Cli::parse_checked(args) {
        Ok(cli) => cli,
        Err(clap_err) => {
            use clap::error::ErrorKind;
            let intrinsic = matches!(
                clap_err.kind(),
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
            );
            let code = clap_err.exit_code();
            let rendered = clap_err.render().to_string();
            let _ = clap_err.print();
            if json_token && !intrinsic {
                println!("{}", machine::unparseable_argv_envelope(&rendered));
            }
            return ExitCode::from(u8::try_from(code).unwrap_or(1));
        }
    };
    let command = machine::command_name(&cli.command);
    let fail = |network: &str, err: &error::CliError| -> ExitCode {
        eprintln!("error: {err}");
        if cli.globals.json {
            println!("{}", machine::error_envelope(command, network, err));
        }
        ExitCode::from(err.exit_code())
    };

    // The config file (U4): missing = defaults; malformed = a hard error
    // for every command (its `network` field falls back to
    // flag-or-built-in — the config that would have supplied the middle
    // layer is exactly what failed). Unknown-key warnings go to stderr,
    // never stdout.
    let config = match config::load() {
        Ok(config) => config,
        Err(err) => {
            let network = cli
                .globals
                .network
                .map_or(antseal_net::NetworkId::default().as_str(), |n| n.as_str());
            return fail(network, &err);
        }
    };
    for warning in &config.warnings {
        eprintln!("warning: {warning}");
    }
    // flag > config > built-in default (U4's precedence rule).
    let network = config::effective_network(cli.globals.network, &config).as_str();

    match run::run(&cli) {
        Ok(outcome) => {
            if cli.globals.json {
                println!(
                    "{}",
                    machine::success_envelope(command, network, outcome.json)
                );
            }
            ExitCode::SUCCESS
        }
        Err(err) => fail(network, &err),
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
