//! Command dispatch. Every canonical command routes through here; until
//! its real handler lands, a command returns the typed not-implemented
//! error for its milestone (U1) — never a panic, never silence.
//!
//! Arrival map (tasks/U.md milestones): **`init` — U11, LANDED**;
//! `seal` U13 — M1 pending;
//! **`list` — U19, LANDED**; **`restore` — U20, LANDED** (its
//! policy and report are complete; the storage-backend construction seam
//! it reaches is U36's, shared with `seal`); **`vault export|import` —
//! U12, LANDED**; `status` U23 — M2; `show` U27, `reveal` U28, `verify`
//! U30 — M3.

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
        Command::Init(args) => return commands::init(&cli.globals, args),
        Command::Seal(_) => ("seal", Milestone::M1),
        Command::List => return commands::list(&cli.globals),
        Command::Show { .. } => ("show", Milestone::M3),
        Command::Status { .. } => ("status", Milestone::M2),
        Command::Restore { work_id, output } => {
            return commands::restore(&cli.globals, work_id, output.as_deref());
        }
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
