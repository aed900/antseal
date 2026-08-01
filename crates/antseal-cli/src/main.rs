//! `antseal` binary — a thin driver over the `antseal_cli` library (D34):
//! install the stderr-only tracing subscriber, then hand argv to
//! [`antseal_cli::main_entry`]. All parsing, dispatch, and exit-code policy
//! live in the library so tests and the M1 E2E drive the same code paths.

use std::process::ExitCode;

fn main() -> ExitCode {
    antseal_cli::init_tracing();
    antseal_cli::main_entry(std::env::args_os())
}
