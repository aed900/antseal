//! `antseal_cli` — the orchestration layer of the antseal CLI (D34).
//!
//! Per docs/decisions/D34-seal-pipeline-placement.md this library target is
//! where the seal pipeline (S12), the journal state machine (S10), resume
//! (S11), restore (S14) and the reveal flow (R16) live, written over
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
pub mod brand;
pub mod cli;
mod commands;
pub mod config;
// U89: `ANTSEAL_DEVNET_ENV` -> `NetworkConfig`, with the three outcomes the
// old `.ok()` collapsed into one kept apart. Deliberately NOT behind
// `ant-backend`: `DevnetEnv`/`NetworkConfig` are antseal-net's pure half, so
// the decision table compiles and is tested in the default feature set even
// though its only callers sit behind the feature.
// Its only PRODUCTION callers (`commands::seal_over_backend`,
// `backend::payment_rpc`) are behind the feature, so in the default lane the
// items are reachable only from their own unit tests. The allow is scoped to
// exactly that build: under `ant-backend` dead code here is still an error.
#[cfg_attr(not(feature = "ant-backend"), allow(dead_code))]
pub(crate) mod devnet_env;
pub mod error;
pub mod init;
pub mod listing;
pub mod machine;
pub mod passphrase;
pub mod pipeline;
pub mod preview;
pub mod redaction_out;
pub mod restore_out;
pub mod reveal_consent;
pub mod reveal_out;
pub mod rng;
mod run;
pub mod seal_consent;
pub mod seal_plan;
pub mod seal_resume;
pub mod seal_run;
pub mod seal_session;
pub mod seal_warnings;
pub mod show;
pub mod status;
pub mod upgrade_hook;
pub mod vault;
pub mod verify_host;
pub mod verify_out;

use std::process::ExitCode;

// Intentional dependency edge (P5): the CLI is a thin shell over
// antseal-core; real consumption begins with the pipeline (U13).
use antseal_core as _;

/// Full CLI entry: parse, dispatch, and map every outcome to its
/// documented exit code (the U2 table in [`error`]).
///
/// **Testable through the binary, and only through the binary** (D99 R4.2).
/// It never calls `process::exit`, which is what the original claim meant and
/// which still holds — but that claim was always narrower than it read. This
/// entry consumes the *process* environment (`config::load` →
/// `VaultLayout::resolve`), so its behaviour is a property of the process it
/// runs in, and it was only ever safely callable in-process for
/// argv→exit-code mapping with no vault.
///
/// U24's opportunistic upgrade hook removes even that: the entry will dial
/// OTS calendars after dispatch. A test **cannot** arm Q16's gate for its own
/// process — `std::env::set_var` is `unsafe` in edition 2024 and
/// `[workspace.lints.rust]` denies `unsafe_code` (both confirmed by
/// compiling them) — so an in-process call cannot be made safe, only avoided.
/// **No test source may call this function**; spawn the binary through
/// `crates/antseal-cli/tests/common/spawn.rs`, which arms the gate.
/// `scripts/check-anchor-net.py` R4 enforces both halves.
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

    // U24's slot (D99 R1/R2): owned here, threaded through dispatch, filled by
    // whichever handler unlocks — through the one expression that both unlocks
    // and arms, so no handler can hold a vault the hook never sees.
    let vault_slot = upgrade_hook::VaultSlot::default();
    // D69 §3 R1's THREE arms. `Ok` no longer implies exit 0: a verdict
    // command folds its anchor set into a severity rung and reports it in
    // the process code **while still emitting its result document**, because
    // `ok` means "a result document is present", not "the exit code is 0"
    // (maintainer-confirmed 2026-08-12; `ENVELOPE_VERSION` unchanged).
    //
    // The code is computed on both sides of the `--json` branch, never
    // inside it — D51 invariant 2: plain and machine runs exit identically.
    let code = match run::run(&cli, &vault_slot) {
        Ok(outcome) => {
            if cli.globals.json {
                match outcome.json {
                    commands::MachineResult::Value(json) => {
                        println!("{}", machine::success_envelope(command, network, json));
                    }
                    // D65 §5: `verify`'s report member is byte-verbatim, so
                    // its result never becomes a `serde_json::Value` — the
                    // parse is where D29 rule 1's declaration order is lost.
                    commands::MachineResult::Raw(result) => {
                        println!(
                            "{}",
                            machine::success_envelope_raw(command, network, &result)
                        );
                    }
                }
            }
            ExitCode::from(outcome.exit_class.map_or(0, error::ErrorClass::exit_code))
        }
        Err(err) => fail(network, &err),
    };
    // D42 + A15 + D99 R1: after the answer, never before it — this is the only
    // point that is post-output in *both* plain and `--json` mode; after the
    // host command's `VaultLock` has been released, so the hook can take its
    // own (the lock is a try-lock and would otherwise refuse itself); and after
    // `code` is a value, so no hook outcome can reach the exit status. The
    // pre-dispatch error returns above are deliberately untouched: no command
    // was dispatched, no vault was held, so there is nothing to arm and nothing
    // to upgrade.
    upgrade_hook::run_after_output(&vault_slot, &config, network);
    code
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
