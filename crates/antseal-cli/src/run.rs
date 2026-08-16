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
//! **U72 moved its stopping point.** It used to stop where `restore` stops
//! — at the storage-backend construction seam, unconditionally, at entry —
//! on the reasoning that a reveal may have to fetch a ciphertext this vault
//! no longer caches. R16's gathering is cache-first by D43's ruling, so that
//! reasoning is right about *may* and wrong about *must*: a work whose
//! retained cache is intact discloses with **zero** network access, and the
//! entry refusal made the default build refuse on bytes already on the
//! user's own disk. The handler now unlocks like `show`, `list` and
//! `status`, holds [`crate::backend::VaultLocalBackend`] (a backend that
//! serves nothing and says why), and refuses only at the point a fetch is
//! genuinely required — which R16's `prepare → build` split already places
//! before the consent gate, exactly where D68 §3 R8 wants it. A partial
//! cache refuses the **whole** reveal there rather than disclosing the
//! cached subset. `tests/reveal_vault_local.rs` measures all of it at the
//! seam.
//!
//! What a build *with* the feature does not yet have is its own live wiring
//! on top of U36's seam, so a cache miss refuses there too — with the other
//! arm's sentence. That is `restore`'s outstanding wiring, in `reveal`'s
//! shape.

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
