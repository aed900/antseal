//! Command dispatch. Every canonical command routes through here; until
//! its real handler lands, a command returns the typed not-implemented
//! error for its milestone (U1) — never a panic, never silence.
//!
//! Arrival map (tasks/U.md milestones): **`init` — U11, LANDED**;
//! **`seal` — U13, LANDED** (plan validation, D45 resume detection and
//! the U14 consent gate are complete and drive the pipeline over any
//! `StorageBackend`; the live path shares `restore`'s U36 seam);
//! **`list` — U19, LANDED**; **`restore` — U20, LANDED** (its
//! policy and report are complete; the storage-backend construction seam
//! it reaches is U36's, shared with `seal`); **`vault export|import` —
//! U12, LANDED**; **`status` — U23, LANDED** (per-anchor states through
//! A18's evaluators, and `--upgrade`'s calendar poll); `show` U27,
//! `reveal` U28, `verify` U30 — M3.

use crate::cli::{Cli, Command, VaultCommand};
use crate::commands::{self, Outcome};
use crate::error::{CliError, Milestone};
use crate::upgrade_hook::VaultSlot;

/// Dispatch a parsed invocation.
///
/// `slot` is the dispatcher-owned home for whatever unlocked vault the
/// dispatched command opens (D99 R2). It is threaded to **every** handler,
/// including the ones that never fill it, so a handler that holds no vault
/// says so in its own signature (`_slot`) rather than by being absent from a
/// list somewhere else. Filling it is not a step any handler performs: the one
/// expression that unlocks — `vault::session::unlock_for_command` — is the one
/// expression that arms.
///
/// # Errors
///
/// Every stubbed command returns [`CliError::NotImplemented`] naming the
/// milestone its handler arrives with; real handlers return their own
/// typed classes.
pub(crate) fn run(cli: &Cli, slot: &VaultSlot) -> Result<Outcome, CliError> {
    tracing::debug!(network = ?cli.globals.network, json = cli.globals.json, "dispatch");
    let (command, milestone) = match &cli.command {
        Command::Init(args) => return commands::init(&cli.globals, args, slot),
        Command::Seal(args) => return commands::seal(&cli.globals, args, slot),
        Command::List => return commands::list(&cli.globals, slot),
        Command::Show { .. } => ("show", Milestone::M3),
        Command::Status { work_id, upgrade } => {
            return commands::status(&cli.globals, work_id, *upgrade, slot);
        }
        Command::Restore { work_id, output } => {
            return commands::restore(&cli.globals, work_id, output.as_deref(), slot);
        }
        Command::Reveal(_) => ("reveal", Milestone::M3),
        Command::Verify { .. } => ("verify", Milestone::M3),
        Command::Vault { command } => match command {
            VaultCommand::Export { file } => {
                return commands::vault_export(&cli.globals, file.as_deref(), slot);
            }
            VaultCommand::Import { file } => {
                return commands::vault_import(&cli.globals, file, slot);
            }
        },
    };
    Err(CliError::NotImplemented { command, milestone })
}
