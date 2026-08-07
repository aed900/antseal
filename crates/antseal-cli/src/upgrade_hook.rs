//! **U24 — the opportunistic OpenTimestamps upgrade hook**: the pass that
//! runs at the end of *every* invocation and drives whatever pending
//! attestations it can afford to a Bitcoin attestation.
//!
//! MVP-SPEC.md line 35 (`list` nags and the background upgrade), 108 (the
//! anchoring machinery), 182 (the risk this reduces). The ruling that placed
//! it is `docs/decisions/D99-upgrade-hook-placement-and-test-seam.md`; the
//! record it writes is D97's; the engine it drives is A15's.
//!
//! # Where this runs, and why nowhere else works
//!
//! [`run_after_output`] is called from exactly one place —
//! [`crate::main_entry`], after the exit code is a value and after every byte
//! of output has been written (D99 R1). That position is **forced three
//! times**, not chosen:
//!
//! 1. it is the only point that is post-output in *both* plain and `--json`
//!    mode — handlers print through `Ui::line` before returning, and the one
//!    machine document is printed by `main_entry` afterwards;
//! 2. it is the only point at which the host command's U5 `VaultLock` has been
//!    released. `init` and `vault export` hold theirs across their handlers,
//!    and [`VaultLock::acquire`] is a **try-lock** that refuses a second
//!    acquisition even inside one process — a hook that ran any earlier would
//!    refuse itself;
//! 3. the exit code is already computed, so nothing here can perturb U2's
//!    table. That is structural: there is no expression in scope through which
//!    a hook outcome could reach the exit status.
//!
//! D42's rule is that the hook runs **iff** the dispatching command already
//! holds an unlocked vault handle. No point that sees all ten subcommands
//! holds one (`run::run` takes a `&Cli`; every handler unlocks for itself; and
//! `UnlockedVault` is deliberately `!Clone`), so the handle is *moved up*
//! into a [`VaultSlot`] the dispatcher owns, through the single expression
//! [`unlock_for_command`](crate::vault::session::unlock_for_command). A
//! command that never unlocked leaves the slot empty and this is a silent
//! no-op: it never unlocks, never prompts, and never creates `~/.antseal`.
//!
//! # Everything here is silent, and that is a ruling
//!
//! Every failure is a **skip**, traced at `debug` on this module's own target
//! (`antseal_cli::upgrade_hook`), naming the work and the reason (D99 R6).
//! Never `warn`: a warning on every invocation for a condition the user cannot
//! act on is a nag, and `status <work-id>` is the command that must report a
//! corrupt or future-versioned anchor record loudly, because that is a command
//! the user ran *about that work*.
//!
//! **Nothing reaches stdout**, on three independent counts: the engine prints
//! nothing by construction, [`crate::init_tracing`] binds the subscriber to
//! stderr, and this runs after the single `--json` document is already
//! written — so even a stray byte would be *after* the document rather than
//! inside it.
//!
//! # What it costs
//!
//! One pass is bounded by [`UpgradeBudget::opportunistic`] — 3 s of wall clock
//! and 4 polls — plus at most one in-flight call, so the achievable bound on
//! *lateness of exit* is about 6 s. A human never sees it: the answer is
//! already printed and the shell prompt is the only thing waiting. A **script**
//! sees all of it, because `$(antseal list --json)` waits for process exit;
//! that residual is recorded in D99 §8 and its remedy is U58's config key.

use std::cell::RefCell;
use std::sync::Arc;
use std::time::Instant;

use antseal_anchor::http::{HttpClient, HttpPolicy};
use antseal_anchor::ots::{PendingWork, UpgradeBudget, UpgradeReport, upgrade_pending};
use antseal_core::crypto::secrets::SealId;

use crate::config::Config;
use crate::error::CliError;
use crate::rng::OsEntropy;
use crate::status::{UpgradeConfig, hex_seal, pending_work, persist_upgrades};
use crate::vault::layout::BesideFile;
use crate::vault::lock::VaultLock;
use crate::vault::session::UnlockedVault;
use crate::vault::store::{WorkState, WorkStore};

/// The line every invocation emits when the dispatched command handed up an
/// unlocked vault handle — D42's positive arm.
///
/// A `const` rather than a literal because it is an **assertion surface**:
/// D99's rewritten Accept row 4 enumerates every subcommand against the real
/// binary's debug trace and reads exactly these two sentences to decide which
/// arm each one took. A test that spelled them out itself would go green on
/// the day the hook stopped running and the message stopped being emitted.
pub const HOOK_ARMED: &str = "opportunistic OTS upgrade hook: armed";

/// The line every invocation emits when it did not (D42's negative arm: a
/// silent no-op, never a prompt, never a vault creation).
pub const HOOK_NOT_ARMED: &str =
    "opportunistic OTS upgrade hook: not armed — this invocation holds no unlocked vault";

/// The handle a vault-holding command moves up to the dispatcher.
///
/// `RefCell<Option<Arc<UnlockedVault>>>` and nothing more. It is owned by
/// [`main_entry`](crate::main_entry), borrowed by `run::run` and threaded to
/// every handler, and the **only** way to fill it is
/// [`unlock_for_command`](crate::vault::session::unlock_for_command), which
/// unlocks and arms in one expression — so a handler cannot end up holding a
/// vault it forgot to arm. The other half of that guarantee is a scan: no
/// production source outside `vault/session.rs` and `vault/export.rs` may name
/// `unlock_vault`, asserted by
/// `the_unlock_primitives_are_named_in_exactly_two_production_files`.
///
/// # The cost, recorded rather than hidden
///
/// The vault key's lifetime is extended past the handler's return, to the end
/// of `main_entry`. It is a **move**, not a copy — `UnlockedVault` stays
/// `!Clone`, so there is still exactly one `VaultKey` in the process and it
/// still zeroizes on its single drop — and the key was alive for the whole
/// command already. But `seal_session.rs`'s
/// `a_session_holds_exactly_two_handles_to_one_vault` used to say a third
/// handle *"would mean something outlives the command holding the vault key"*.
/// Under D99 §2.2 something does, on purpose, bounded by this hook's budget;
/// that doc comment is amended rather than quietly outlived.
#[derive(Debug, Default)]
pub struct VaultSlot(RefCell<Option<Arc<UnlockedVault>>>);

impl VaultSlot {
    /// Store the handle and hand a clone back to the unlocking command.
    ///
    /// Crate-private on purpose: the public door is `unlock_for_command`, and
    /// an arming that did not unlock in the same expression would be a way to
    /// arm the hook with a vault some *other* code path opened.
    pub(crate) fn arm(&self, vault: Arc<UnlockedVault>) -> Arc<UnlockedVault> {
        let handed = Arc::clone(&vault);
        *self.0.borrow_mut() = Some(vault);
        handed
    }

    /// Take the handle out, leaving the slot empty.
    ///
    /// Taken rather than borrowed so the hook owns the last reference for the
    /// duration of its pass and drops it — with the key — before `main_entry`
    /// returns.
    fn take(&self) -> Option<Arc<UnlockedVault>> {
        self.0.borrow_mut().take()
    }
}

/// How a hook pass polls one work's pending attestations.
///
/// A boxed closure rather than a hard call to [`upgrade_pending`], and that is
/// the whole test seam (D99 R4.4/R5): production closes over
/// [`upgrade_pending`], whose resolver is A42's real allowlist; a test closes
/// over `upgrade_pending_with` and a `127.0.0.1:0` stub. A42's allowlist
/// requires `https`, a bare host and no port, so a loopback stub can *never*
/// be admitted through the production resolver — which is correct, and which
/// is exactly why this seam has to exist for U24's Accept row 1 to be
/// executable at all.
///
/// The budget is a **parameter** rather than something the closure closes
/// over, because the invocation's budget has to be spent across every work the
/// pass visits: the engine's own clock restarts on each call, so a vault of
/// fifty works would otherwise pay fifty budgets.
pub type PollStep<'a> = Box<dyn Fn(&[PendingWork], UpgradeBudget) -> UpgradeReport + 'a>;

/// Everything one hook pass needs that it does not decide for itself.
pub struct HookContext<'a> {
    /// The handle the dispatched command armed.
    vault: &'a UnlockedVault,
    /// What one whole invocation may spend, across every work it visits.
    budget: UpgradeBudget,
    /// This pass's single clock read, POSIX seconds UTC. It is both the
    /// `fetch_date` a recorded upgrade group carries (D97 R5 — never read from
    /// a clock at the write site) and R9's rotation seed.
    fetch_date: u64,
    /// Poll one work's pending attestations within the budget given.
    poll: PollStep<'a>,
}

impl std::fmt::Debug for HookContext<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HookContext")
            .field("budget", &self.budget)
            .field("fetch_date", &self.fetch_date)
            .finish_non_exhaustive()
    }
}

impl<'a> HookContext<'a> {
    /// The production context — **the only construction here that may reach a
    /// real endpoint** (D99 R4.4).
    ///
    /// Named in `tests/anchor_stage.rs`'s `DEFAULT_LIST_ROUTES`, so no test
    /// source in this crate may spell it, for the reason `common/mod.rs`
    /// already records about `AnchorStageConfig`: a defaulted endpoint field
    /// is how a test reaches a live service by omission. Every test builds its
    /// context through [`Self::with_poll`] over loopback stubs.
    ///
    /// D99 R4.4 spells this `production(&Config, NetworkId)`. The network is
    /// deliberately **not** carried into the context: OTS anchors to Bitcoin
    /// and the calendars and esplora pair are the same whichever EVM chain
    /// paid, so a network field here would gate nothing. It is recorded in
    /// [`run_after_output`]'s trace instead, where it is invocation context
    /// for a reader of `RUST_LOG` rather than a parameter pretending to decide
    /// something.
    ///
    /// # Errors
    ///
    /// [`CliError::Usage`] when `[verify] bitcoin_endpoints` does not name
    /// exactly two parseable, distinct-origin endpoints. The caller turns that
    /// into a skip: a hook that cannot confirm a block header must not run,
    /// and it must not fail the command that carried it either.
    pub fn production(
        vault: &'a UnlockedVault,
        config: &Config,
        fetch_date: u64,
    ) -> Result<Self, CliError> {
        let upgrade = UpgradeConfig::from_config(config);
        // Built once, before any work is visited, so a malformed endpoint
        // configuration is one skip rather than one per work.
        let pair = upgrade.pair()?;
        let client = HttpClient::new(HttpPolicy::opportunistic());
        Ok(Self {
            vault,
            budget: UpgradeBudget::opportunistic(),
            fetch_date,
            poll: Box::new(move |works, budget| {
                upgrade_pending(
                    &client,
                    &pair,
                    works,
                    &upgrade.calendars,
                    budget,
                    fetch_date,
                )
            }),
        })
    }

    /// A context whose poll step the caller supplies.
    ///
    /// Not a bypass of anything: A42's invariant is a property of the
    /// *resolver* — no poll is issued against a URI read out of a stored
    /// artifact without `classify_upgrade_uri` having run — and the production
    /// resolver is untouched. What this admits is a resolver the caller
    /// supplies, and `scripts/check-anchor-net.py` R5 plus
    /// `the_test_seam_has_no_production_call_sites` are what keep the only
    /// callers tests.
    #[must_use]
    pub fn with_poll(
        vault: &'a UnlockedVault,
        budget: UpgradeBudget,
        fetch_date: u64,
        poll: PollStep<'a>,
    ) -> Self {
        Self {
            vault,
            budget,
            fetch_date,
            poll,
        }
    }
}

/// What one hook pass did.
///
/// Returned as **data** so the suite can assert on a pass without reading
/// stderr; [`run_after_output`] discards it. Nothing here is rendered to a
/// user, and there is no `Result` anywhere on this path for a future edit to
/// propagate into the host command's exit status.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HookPass {
    /// The candidate works, in the rotated order they were visited (R9). The
    /// first element is the one this invocation started on.
    pub order: Vec<SealId>,
    /// Works whose anchors were actually handed to the engine.
    pub considered: usize,
    /// Works that never became candidates: R7's state filter, and work records
    /// that could not be read at all.
    pub excluded: usize,
    /// Candidates the pass could not use, for one of D99 R6's reasons — an
    /// unreadable anchor set, no OTS artifact, a failed persist. Counted apart
    /// from [`Self::excluded`] because "this work was not eligible" and "this
    /// work was eligible and unusable" are different facts, and only the
    /// second one may be worth a `status <work-id>`.
    pub skipped: usize,
    /// Calendar polls issued across the whole pass.
    pub polls: usize,
    /// Transitions persisted.
    pub applied: usize,
    /// Transitions discarded because the slot moved under them — benign, and
    /// recomputed next invocation.
    pub declined: usize,
    /// Whether the pass stopped because the invocation's budget ran out.
    pub budget_exhausted: bool,
    /// Whether it stopped because another process holds the single-writer
    /// lock. Never an error, never surfaced: polls are idempotent.
    pub lock_contended: bool,
}

/// The hook. Called from [`main_entry`](crate::main_entry) and from nowhere
/// else (D99 R1).
///
/// Returns `()` and takes no `Result`, so there is no error for a future edit
/// to propagate — the same guarantee `upgrade_pending` gives one layer down,
/// applied at the CLI boundary.
///
/// `network` is the invocation's **effective** network (flag > config >
/// default, already resolved by the caller), recorded in the trace so a reader
/// of `RUST_LOG` can correlate the pass with the command that carried it. It
/// gates nothing here.
pub fn run_after_output(slot: &VaultSlot, config: &Config, network: &str) {
    let Some(vault) = slot.take() else {
        tracing::debug!(network, "{HOOK_NOT_ARMED}");
        return;
    };
    tracing::debug!(network, "{HOOK_ARMED}");

    let ctx = match HookContext::production(&vault, config, crate::commands::now_unix_secs()) {
        Ok(ctx) => ctx,
        Err(error) => {
            tracing::debug!(
                %error,
                "skipped: no usable endpoint configuration for the upgrade pass"
            );
            return;
        }
    };
    let pass = run_with(&ctx);
    tracing::debug!(
        considered = pass.considered,
        excluded = pass.excluded,
        skipped = pass.skipped,
        polls = pass.polls,
        applied = pass.applied,
        declined = pass.declined,
        budget_exhausted = pass.budget_exhausted,
        lock_contended = pass.lock_contended,
        "opportunistic OTS upgrade hook: pass complete"
    );
}

/// One pass over the armed vault: choose, rotate, poll, persist.
///
/// # Which works (R7)
///
/// [`WorkState::Complete`] only. An incomplete work is a D45 resume candidate
/// whose `ots-pending` slot the next resume rewrites wholesale from a *fresh*
/// submission, so upgrading it spends the budget on nothing at best and
/// manufactures D97 §1's `invalid` / `anchor-ots-header-uncommitted` pairing at
/// worst. `Abandoned` works are skipped for the budget reason alone. This is
/// the **hook's** restriction and not the engine's: `status --upgrade` is
/// synchronous, user-requested and single-work, and does not share it.
///
/// # Where it starts (R9)
///
/// `list_works` is a stable ascending byte order, the engine returns at the
/// first budget exhaustion, and `max_polls` is 4 — so without a rotation the
/// first work by seal-id order consumes every invocation's budget until it
/// upgrades, and a commitment a calendar answers `NotFound` for consumes it
/// **permanently**, starving every work behind it for the life of the vault.
/// The pass therefore starts at `fetch_date % n` and wraps. No persisted
/// state, no write on a read-only command, and deterministic under a pinned
/// `fetch_date` so the rotation is assertable. This *bounds* starvation rather
/// than removing it; removing it needs a remembered `NotFound`, which is U57.
///
/// # The lock (R3)
///
/// Polling happens **unlocked**. The single-writer lock exists to serialize
/// writers, and holding it across a calendar round-trip would block every
/// concurrent `seal` for the whole budget — which an opportunistic pass has no
/// right to do. The lock is taken only once there is a transition to write,
/// released before the next work's polling, and a contended lock is a silent
/// `debug` line and the end of the pass. The window that opens between the
/// poll and the write is closed by `apply_upgrade`'s compare-and-set, not by
/// hope.
#[must_use]
pub fn run_with(ctx: &HookContext<'_>) -> HookPass {
    let mut pass = HookPass::default();
    let store = WorkStore::new(ctx.vault);

    let works = match store.list_works() {
        Ok(works) => works,
        Err(error) => {
            tracing::debug!(%error, "skipped: the work store could not be listed");
            return pass;
        }
    };

    let mut candidates = Vec::with_capacity(works.len());
    for seal_id in works {
        match store.load_meta(&seal_id) {
            Ok(record) if record.state == WorkState::Complete => candidates.push(seal_id),
            Ok(record) => {
                pass.excluded += 1;
                tracing::debug!(
                    work = %hex_seal(&seal_id),
                    state = ?record.state,
                    "skipped: only completed works are upgraded opportunistically (R7)"
                );
            }
            Err(error) => {
                // R6: a newer build's record, a corrupt one, a failed AEAD.
                // Each is a skip, and `status <work-id>` is what says so out
                // loud.
                pass.excluded += 1;
                tracing::debug!(
                    work = %hex_seal(&seal_id),
                    %error,
                    "skipped: the work record could not be read"
                );
            }
        }
    }
    if candidates.is_empty() {
        tracing::debug!("no completed work in this vault to consider");
        return pass;
    }

    // R9. `usize::try_from` cannot fail — the modulus is a `usize` cast to
    // `u64` — but the fallible spelling is what keeps this total on a 32-bit
    // target rather than relying on the cast.
    let start = usize::try_from(ctx.fetch_date % candidates.len() as u64).unwrap_or(0);
    let order: Vec<SealId> = candidates[start..]
        .iter()
        .chain(&candidates[..start])
        .copied()
        .collect();

    let started = Instant::now();
    for seal_id in &order {
        let elapsed = started.elapsed();
        if pass.polls >= ctx.budget.max_polls || elapsed >= ctx.budget.total {
            // The invocation's budget, not this work's: the engine's own
            // `Instant` restarts on every call, so the remaining budget has to
            // be computed here or a vault of fifty works would pay fifty
            // budgets.
            pass.budget_exhausted = true;
            tracing::debug!(
                polls = pass.polls,
                "the invocation's upgrade budget is spent; the rest wait for the next one"
            );
            break;
        }

        let (stored, work) = match pending_work(&store, seal_id) {
            Ok(pair) => pair,
            Err(error) => {
                // R6: `NewerRecord` on the plan record, an enumeration
                // failure, tamper. **Not** an `AnchorArtifact::decode`
                // refusal any more — D100 R5 makes that a per-slot datum, so
                // it arrives through the `None` arm below with the rest of
                // the work still readable.
                pass.skipped += 1;
                tracing::debug!(
                    work = %hex_seal(seal_id),
                    %error,
                    "skipped: this work's anchors could not be read"
                );
                continue;
            }
        };
        let Some(work) = work else {
            // Three reasons reach here and D99 R6 lists all three as skips:
            // no OTS artifact at all, no readable one (every `ots-pending`
            // record damaged), and no recoverable `anchor_digest` because the
            // journaled manifest is gone. Named together rather than under
            // the first one's sentence, which would be false for the other
            // two.
            pass.skipped += 1;
            tracing::debug!(
                work = %hex_seal(seal_id),
                damaged_slots = stored.damaged().len(),
                "skipped: nothing pollable — no readable OTS artifact, or no anchor digest to \
                 poll it against"
            );
            continue;
        };

        let remaining = UpgradeBudget {
            total: ctx.budget.total.saturating_sub(elapsed),
            max_polls: ctx.budget.max_polls - pass.polls,
        };
        let report = (ctx.poll)(std::slice::from_ref(&work), remaining);
        pass.considered += 1;
        pass.polls += report.polls;
        pass.budget_exhausted |= report.budget_exhausted;
        for note in &report.notes {
            tracing::debug!(work = %hex_seal(seal_id), note = %note, "upgrade note");
        }
        if report.is_empty() {
            continue;
        }

        // R3, in order: something to persist, then the lock, then the write,
        // then the lock goes away again before the next work is polled.
        let lock = match VaultLock::acquire(&ctx.vault.layout().beside_path(BesideFile::Lockfile)) {
            Ok(lock) => lock,
            Err(error) => {
                pass.lock_contended = true;
                tracing::debug!(
                    %error,
                    "declined: another process holds the vault lock; the transitions are \
                     discarded and recomputed on the next invocation"
                );
                break;
            }
        };
        match persist_upgrades(&store, seal_id, &stored, &report, &mut OsEntropy) {
            Ok(outcome) => {
                pass.applied += outcome.applied;
                pass.declined += outcome.declined;
                tracing::debug!(
                    work = %hex_seal(seal_id),
                    applied = outcome.applied,
                    declined = outcome.declined,
                    "persisted"
                );
            }
            Err(error) => {
                pass.skipped += 1;
                tracing::debug!(
                    work = %hex_seal(seal_id),
                    %error,
                    "skipped: the computed upgrade could not be persisted"
                );
            }
        }
        drop(lock);
    }
    pass.order = order;
    pass
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two trace sentences are the enumeration test's only handle on which
    /// arm an invocation took, so they must stay distinguishable by a
    /// substring search: one must not be a prefix of the other, or a
    /// not-armed run would satisfy an "armed" assertion.
    #[test]
    fn the_two_trace_arms_cannot_be_mistaken_for_each_other() {
        assert!(!HOOK_NOT_ARMED.contains(HOOK_ARMED));
        assert!(!HOOK_ARMED.contains(HOOK_NOT_ARMED));
        assert_ne!(HOOK_ARMED, HOOK_NOT_ARMED);
    }

    /// An empty slot is the D42 no-op, and taking from it is not an error.
    #[test]
    fn an_unarmed_slot_yields_nothing() {
        let slot = VaultSlot::default();
        assert!(slot.take().is_none());
        // Idempotent: a second take after the hook already ran is still empty,
        // so a future double call cannot run two passes over one handle.
        assert!(slot.take().is_none());
    }
}
