//! Command dispatch. Every canonical command routes through here; until its
//! real handler lands, a command returns the typed not-implemented error
//! for its milestone (U1) — never a panic, never silence.
//!
//! Arrival map (tasks/U.md milestones): `init` U11, `seal` U13, `list`
//! U19, `restore` U20, `vault export|import` U12 — all M1; `status` U23 —
//! M2; `show` U27, `reveal` U28, `verify` U30 — M3.

use crate::cli::{Cli, Command, VaultCommand};
use crate::error::{CliError, Milestone};

/// Dispatch a parsed invocation.
///
/// # Errors
///
/// Every stubbed command returns [`CliError::NotImplemented`] naming the
/// milestone its handler arrives with.
pub fn run(cli: &Cli) -> Result<(), CliError> {
    tracing::debug!(network = ?cli.globals.network, json = cli.globals.json, "dispatch");
    let (command, milestone) = match &cli.command {
        Command::Init(_) => ("init", Milestone::M1),
        Command::Seal(_) => ("seal", Milestone::M1),
        Command::List => ("list", Milestone::M1),
        Command::Show { .. } => ("show", Milestone::M3),
        Command::Status { .. } => ("status", Milestone::M2),
        Command::Restore { .. } => ("restore", Milestone::M1),
        Command::Reveal(_) => ("reveal", Milestone::M3),
        Command::Verify { .. } => ("verify", Milestone::M3),
        Command::Vault { command } => match command {
            VaultCommand::Export { .. } => ("vault export", Milestone::M1),
            VaultCommand::Import { .. } => ("vault import", Milestone::M1),
        },
    };
    Err(CliError::NotImplemented { command, milestone })
}
