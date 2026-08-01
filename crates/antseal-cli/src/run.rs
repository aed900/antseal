//! Command dispatch. Every canonical command routes through here; until
//! its real handler lands, a command returns the typed not-implemented
//! error for its milestone (U1) — never a panic, never silence.
//!
//! Arrival map (tasks/U.md milestones): `init` U11, `seal` U13, `list`
//! U19, `restore` U20 — M1 pending; **`vault export|import` — U12,
//! LANDED**; `status` U23 — M2; `show` U27, `reveal` U28, `verify` U30 —
//! M3.

use crate::cli::{Cli, Command, VaultCommand};
use crate::commands::{self, Outcome};
use crate::error::{CliError, Milestone};

/// Dispatch a parsed invocation.
///
/// # Errors
///
/// Every stubbed command returns [`CliError::NotImplemented`] naming the
/// milestone its handler arrives with; real handlers return their own
/// typed classes.
pub(crate) fn run(cli: &Cli) -> Result<Outcome, CliError> {
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
            VaultCommand::Export { file } => {
                return commands::vault_export(&cli.globals, file.as_deref());
            }
            VaultCommand::Import { file } => {
                return commands::vault_import(&cli.globals, file);
            }
        },
    };
    Err(CliError::NotImplemented { command, milestone })
}
