//! Command dispatch. Every canonical command routes through here — never a
//! panic, never silence. **Every arm is a real handler as of U30**: the
//! typed not-implemented refusal U1 introduced for later-milestone commands
//! has no dispatch arm left.
//!
//! Arrival map (tasks/U.md milestones): **`init` — U11, LANDED**;
//! **`seal` — U13, LANDED** (plan validation, D45 resume detection and
//! the U14 consent gate are complete and drive the pipeline over any
//! `StorageBackend`; the live path shares `restore`'s U36 seam);
//! **`list` — U19, LANDED**; **`restore` — U20, LANDED** (its
//! policy and report are complete; the storage-backend construction seam
//! it reaches is U36's, shared with `seal`); **`vault export|import` —
//! U12, LANDED**; **`status` — U23, LANDED** (per-anchor states through
//! A18's evaluators, and `--upgrade`'s calendar poll); **`show` — U27,
//! LANDED** (every unit of a work with its D67 snippet, sourced from the
//! D43 cache or the current file — it reaches no backend at all);
//! **`verify` — U30, LANDED** (the last handler of the frozen surface:
//! R21's orchestration behind D69's exit-code fold, D65's byte-verbatim
//! `--json` carriage, and D128's always-on storage-linkage section — it
//! needs no vault and never prompts).
//!
//! **`reveal` — U28/U29, LANDED.** [`crate::reveal_out::run_reveal`]
//! resolves `-o`/D68's default, refuses an occupied target *before*
//! anything is fetched or consented to, renders U29's
//! irreversible-disclosure screen through
//! [`crate::reveal_consent::DisclosureConsent`] — the confirmation spec
//! line 36 requires, with `--yes` and D51's machine-mode matrix — then
//! drives R16's `prepare → build`, writes with `create_new(true)` and
//! renders the run (bundle path + the canonical verifier URL).
//!
//! Its handler stops where `restore`'s stops, and for the same reason:
//! `reveal` fetches any ciphertext this vault no longer caches, so it needs
//! the **storage-backend construction seam**, and a build without one
//! refuses there rather than collecting a passphrase, rendering a
//! disclosure screen and then refusing. Everything above that seam is
//! complete and is driven end to end over a `StorageBackend`
//! (`tests/reveal_output.rs`, `tests/reveal_consent.rs`) — U20's recorded
//! shape, with U20's outstanding wiring.

use crate::cli::{Cli, Command, VaultCommand};
use crate::commands::{self, Outcome};
use crate::error::CliError;
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
/// Every handler returns its own typed classes. **No arm returns
/// [`CliError::NotImplemented`] any more**: `verify` was the last stub of
/// the frozen surface, so the milestone-shaped refusal U1 introduced is
/// now unreachable from dispatch — the variant survives for the type's own
/// exhaustive matches and for a future surface addition, not for a command
/// that exists.
pub(crate) fn run(cli: &Cli, slot: &VaultSlot) -> Result<Outcome, CliError> {
    tracing::debug!(network = ?cli.globals.network, json = cli.globals.json, "dispatch");
    match &cli.command {
        Command::Init(args) => commands::init(&cli.globals, args, slot),
        Command::Seal(args) => commands::seal(&cli.globals, args, slot),
        Command::List => commands::list(&cli.globals, slot),
        Command::Show { work_id } => commands::show(&cli.globals, work_id, slot),
        Command::Status { work_id, upgrade } => {
            commands::status(&cli.globals, work_id, *upgrade, slot)
        }
        Command::Restore { work_id, output } => {
            commands::restore(&cli.globals, work_id, output.as_deref(), slot)
        }
        Command::Reveal(args) => commands::reveal(&cli.globals, args, slot),
        Command::Verify {
            bundle,
            online,
            live,
        } => commands::verify(&cli.globals, bundle, *online, *live, slot),
        Command::Vault { command } => match command {
            VaultCommand::Export { file } => {
                commands::vault_export(&cli.globals, file.as_deref(), slot)
            }
            VaultCommand::Import { file } => commands::vault_import(&cli.globals, file, slot),
        },
    }
}
