//! Real command handlers (U12 first: `vault export` / `vault import`).
//!
//! Handlers return an [`Outcome`] whose `json` value is the command's
//! machine-result document; `main_entry` prints it under `--json`
//! (provisional `{"ok": true, "result": …}` shape until U3's versioned
//! envelope wraps it). Human copy goes through [`Ui`]: stdout in plain
//! mode, stderr under `--json` — stdout stays reserved for the one JSON
//! document (D51 invariant 2).
//!
//! # Machine mode at the passphrase seam (D51, via the ε primitive)
//!
//! [`collect_passphrase`] is the U12-scope seam U3 will fold into its
//! framework: `--passphrase-fd` always wins; otherwise machine mode
//! (`--json` ∨ non-TTY stdin ∨ fd 0 — [`crate::passphrase::machine_mode`])
//! aborts with the typed passphrase-unavailable code instead of ever
//! prompting — the `--json`-with-a-real-TTY case included, which the
//! bare `obtain_passphrase` gate (stdin-isatty only) cannot see on its
//! own.

use std::path::{Path, PathBuf};

use antseal_core::crypto::secrets::SecretBuf;

use crate::cli::GlobalArgs;
use crate::error::{CliError, PassphraseFailure};
use crate::passphrase::{PassphrasePurpose, obtain_passphrase};
use crate::rng::OsEntropy;
use crate::upgrade_hook::VaultSlot;
use crate::vault::export::{EXPORT_FILE_EXTENSION, export_vault, import_vault};
use crate::vault::layout::{BesideFile, VaultLayout};
use crate::vault::lock::VaultLock;
use crate::vault::session::unlock_for_command;
use crate::vault::store::WorkStore;

/// A successfully-handled command: the machine-result document (printed
/// on stdout under `--json`; U3's envelope wraps it), and D69's **third
/// arm**.
///
/// # The third arm (D69 §3 R1)
///
/// `main_entry` had exactly two arms until M3 — `Ok → 0 + ok:true + result`
/// and `Err(CliError) → code + ok:false + error` — so *any* nonzero exit
/// emitted **no result document at all**. That is fine for a failure and
/// wrong for a verdict: `verify` folds a set of independently-stated anchor
/// states into a severity rung, and a bundle whose every commitment opened
/// still has a full report to hand over even when the rung is
/// `verify-unanchored`.
///
/// So [`Self::exit_class`] carries an optional class that sets the process
/// code **while the success envelope is still emitted**. `ok` means *a
/// result document is present*, never *the exit code is 0*
/// (maintainer-confirmed 2026-08-12; `ENVELOPE_VERSION` stays 1). D51
/// invariant 2 is preserved because the code is computed before the mode
/// branch.
///
/// `Option<ErrorClass>` rather than a fresh enum, deliberately: there is
/// exactly **one** code table in the product, with one `exit_code()` and one
/// `name()`, and U2 keeps ownership of the identifiers.
///
/// `restore` is the second consumer (U69, D69 §6.1) — a reviewer must not
/// "fix" this by making `ok` follow the exit code again.
pub(crate) struct Outcome {
    /// The command's machine-result document.
    pub json: MachineResult,
    /// The class whose code the process exits with, or `None` for 0.
    pub exit_class: Option<crate::error::ErrorClass>,
}

/// How a command's `result` document reaches stdout.
///
/// Two variants because D65 §5 forbids one of them for `verify`: routing the
/// report through `serde_json::Value` alphabetizes its keys (`Map` is a
/// `BTreeMap` in this build) and destroys D29 rule 1's declaration order,
/// and `success_envelope`'s only signature takes a `Value`. Nine commands
/// build a `Value` and are unaffected; `verify` renders its whole `result`
/// through serde on typed values and hands over the text.
pub(crate) enum MachineResult {
    /// A `serde_json::Value`, wrapped by [`crate::machine::success_envelope`].
    Value(serde_json::Value),
    /// A pre-rendered `result` document, spliced verbatim by
    /// [`crate::machine::success_envelope_raw`].
    Raw(String),
}

impl Outcome {
    /// The ordinary outcome: a `Value` result at exit 0.
    pub(crate) const fn value(json: serde_json::Value) -> Self {
        Self {
            json: MachineResult::Value(json),
            exit_class: None,
        }
    }

    /// A pre-rendered result, with D69's rung class when the run folded one.
    pub(crate) const fn raw(result: String, exit_class: Option<crate::error::ErrorClass>) -> Self {
        Self {
            json: MachineResult::Raw(result),
            exit_class,
        }
    }
}

/// Human-copy channel selector: plain mode prints to stdout; under
/// `--json`, everything human moves to stderr (D51 invariant 1/2).
struct Ui {
    json: bool,
}

impl Ui {
    fn line(&self, text: &str) {
        if self.json {
            eprintln!("{text}");
        } else {
            println!("{text}");
        }
    }
}

/// Collect the vault passphrase under the D51 machine-mode rule.
/// `purpose` is `Unlock` for both export and import — the passphrase
/// already exists; no strength floor, no confirmation. Machine mode
/// arrives from [`crate::machine::machine_mode_for`] — the single
/// detection point (D51) — never from a local isatty probe.
fn collect_passphrase(
    globals: &GlobalArgs,
    purpose: PassphrasePurpose,
) -> Result<SecretBuf, CliError> {
    if globals.passphrase_fd.is_none() && crate::machine::machine_mode_for(globals) {
        return Err(CliError::PassphraseUnavailable {
            reason: PassphraseFailure::NoChannel,
        });
    }
    obtain_passphrase(purpose, globals.passphrase_fd)
}

/// Resolve the vault layout, refusing early (and readably) when no vault
/// exists yet — the same shape every vault-reading command needs.
fn open_layout() -> Result<VaultLayout, CliError> {
    let layout = VaultLayout::resolve().map_err(|e| CliError::Usage {
        message: e.to_string(),
    })?;
    if !layout.beside_path(BesideFile::Header).exists() {
        return Err(CliError::Usage {
            message: format!(
                "no vault exists at {} — run `antseal init` first",
                layout.root().display()
            ),
        });
    }
    Ok(layout)
}

/// `init` (U11; wizard, copy and vault construction in [`crate::init`]).
///
/// The handler is deliberately thin: it resolves the layout, holds the
/// U5 single-writer lock across the whole creation, and renders. Every
/// decision — the D39 order, the D40 KDF question, the D44 import
/// classes, the D51 machine-mode rule — lives in [`crate::init::run_init`]
/// so it is drivable in-process without a pty.
pub(crate) fn init(
    globals: &GlobalArgs,
    args: &crate::cli::InitArgs,
    // D99 R2 / D42's corrected consequence: `init` does NOT arm. `run_init`
    // consumes the `UnlockedVault` `create_vault` produced and drops it
    // inside, so this handler holds no handle at the dispatch layer — and a
    // vault created moments ago has nothing to upgrade anyway.
    _slot: &VaultSlot,
) -> Result<Outcome, CliError> {
    let ui = Ui { json: globals.json };
    let layout = VaultLayout::resolve().map_err(|e| CliError::Usage {
        message: e.to_string(),
    })?;

    // The lock lives beside the AEAD and needs the directory to exist;
    // creating it is idempotent and leaves nothing behind if `init`
    // refuses (an empty `~/.antseal/` is not a vault — the header is).
    std::fs::create_dir_all(layout.root()).map_err(|source| CliError::Io {
        context: format!("creating {}", layout.root().display()),
        source,
    })?;
    let _lock =
        VaultLock::acquire(&layout.beside_path(BesideFile::Lockfile)).map_err(CliError::from)?;

    let report = crate::init::run_init(
        &layout,
        args,
        globals.passphrase_fd,
        crate::machine::machine_mode_for(globals),
        crate::init::init_network(globals),
        &mut crate::init::TtyInitPrompt,
        &mut OsEntropy,
    )?;

    for line in report.render() {
        ui.line(&line);
    }
    Ok(Outcome::value(report.json()))
}

/// `seal <PATH>…` (U13; plan validation in [`crate::seal_plan`], resume
/// detection in [`crate::seal_resume`], the consent gate in
/// [`crate::seal_consent`], the orchestration in [`crate::seal_run`]).
///
/// # The order of refusals, and why it is this one
///
/// Plan validation runs **first**, before the backend seam, before the
/// vault is opened and before any passphrase is collected. Every D46
/// problem, the `--no-anchor` × `arbitrum-one` refusal and the M1
/// anchor-stage gate are answerable from argv and `stat` alone, and a
/// build that cannot reach the network should not be the reason a user
/// never learns that one of their arguments is a directory. (`restore`
/// reaches its seam first because it has no argument validation to do —
/// the shared rule is "the cheapest thing that can say no goes first",
/// not "the seam goes first".)
///
/// # U73: what a **valid** plan meets next differs by build, and that is
/// the correct answer
///
/// Past plan validation the two `seal_over_backend` arms diverge, and a
/// spawned-binary test asserted the default build's answer for both:
/// `seal a.txt --network devnet` into a vault-less `HOME` exits **23** on
/// the default build (the seam has no adapter) and **2** under
/// `--features ant-backend` (`open_layout` finds no vault). Nothing had
/// ever seen the second, because `heavy-features` is local-only by Q153.
/// U73 ruled the divergence **correct** and made the test arm-aware, on
/// four witnesses:
///
/// 1. **U72**, hours older and the same shape. Moving `reveal`'s entry
///    refusal to the seam left `open_layout` *first* and paid the cost out
///    loud — *"the vault is the only place the work, its cache and its
///    keys live, so there is nothing to decide before it is open"*. A
///    `seal` that probed the seam ahead of the vault would contradict the
///    ordering its sibling had just been given.
/// 2. **The rule in the paragraph above.** `open_layout` is one `stat`;
///    the wired seam is a tokio runtime, a wallet-key read out of an
///    unlocked vault and a connect. Vault-first *is* cheapest-first, and
///    it is the order `list`, `show`, `status` and (since U72) `reveal`
///    already keep.
/// 3. **This build has no true seam sentence for `seal`.**
///    [`BackendArm::Compiled`]'s message says the command *"does not
///    construct one yet"* — false here since U13 wired it — so satisfying
///    the old assertion would have meant printing a falsehood.
/// 4. **D89**, which settles the general form: *"a default build of
///    antseal is an inspect-and-verify build"* is *"already true and
///    already shipped"*. The two builds are capability-divergent **by
///    design**, so when the next thing a command needs is the network,
///    answering differently is the design working rather than a defect.
///
/// # The two records that look like precedent and are not
///
/// **D48 §6 and D69 §3 R3** are one rule, not two — D69 calls its rung
/// rank *"D48 §6's severity fold, extended"* — and that rule is
/// *most-severe-wins over facts established **together** in one run*
/// (several per-file restore failures; several anchor slots). These two
/// refusals are **sequential gates**: `open_layout` fails and the seam is
/// never reached, so no second fact is ever established and there is
/// nothing to fold. Note also that *"the cheapest thing that can say no
/// goes first"* is this comment's own rule and appears in no decision
/// record — witness 2 is code-local, and is offered as such.
///
/// **D65** partitions the `--json` schema by *stability over time* for one
/// build; it rules on no cross-build question. Nothing here disturbs it
/// anyway: both refusals are ordinary `CliError`s already in D69's
/// committed table (`usage` 2, `network-failure` 23) with class and code
/// agreeing, so no tier-B key moves and no tier-A member is touched.
///
/// One correction U73 owes R82, whose Accept read *"only the
/// `error.message` string of the feature-ON arm is in scope"*: for `seal`
/// the **exit code** diverges between the builds as well, not just the
/// message. R82's own change did not cause that and its scope note is
/// right about itself — but as a description of the two builds it is
/// incomplete, and this is the row that measured it.
///
/// [`BackendArm::Compiled`]: crate::backend::BackendArm::Compiled
pub(crate) fn seal(
    globals: &GlobalArgs,
    args: &crate::cli::SealArgs,
    slot: &VaultSlot,
) -> Result<Outcome, CliError> {
    // Loaded ONCE here and used for both answers it holds: the effective
    // network, and U26's TSA-list override for the anchor stage. Loading it
    // twice would be two chances for one invocation to run on two configs.
    // A malformed file has already hard-failed before dispatch, and this is
    // still ahead of plan validation — so U26's "a malformed TSA URL is a
    // config error before any pipeline work" holds twice over.
    let config = crate::config::load()?;
    let network = crate::config::effective_network(globals.network, &config);
    let cwd = std::env::current_dir().map_err(|source| CliError::Io {
        context: "resolving the current directory to absolutize the seal arguments".to_owned(),
        source,
    })?;
    let plan = crate::seal_plan::build_plan(args, network, &cwd)?;
    seal_over_backend(globals, &plan, &config, slot)
}

// `effective_network(globals)` used to sit here, loading the config a
// second time to answer one question. U26 needs a second answer out of the
// same file (the TSA-list override), so `seal` now loads it once and reads
// both — which is also the stronger property: one invocation cannot run
// with its network resolved from one read of the file and its endpoints
// from another. `main_entry`'s own load, for the U3 envelope's `network`
// field, is unchanged; a malformed config hard-fails there, before dispatch.

/// The storage-backend half of `seal`, reached only after the whole plan
/// has been validated.
#[cfg(not(feature = "ant-backend"))]
fn seal_over_backend(
    _globals: &GlobalArgs,
    _plan: &crate::seal_plan::SealPlan,
    _config: &crate::config::Config,
    // The vault is never opened on this build, so nothing is ever armed —
    // which is the honest reading of D42's rule and not an exemption from it.
    _slot: &VaultSlot,
) -> Result<Outcome, CliError> {
    Err(crate::backend::unavailable("seal"))
}

/// The live path: unlock, connect, run the pipeline, render.
///
/// Every step is ordered so the expensive and the secret come last: the
/// plan is already validated when this is entered, the vault lock is taken
/// before the passphrase (a second antseal mid-seal should not first ask
/// for a secret), and the network connection is made only once the wallet
/// key is in hand.
#[cfg(feature = "ant-backend")]
fn seal_over_backend(
    globals: &GlobalArgs,
    plan: &crate::seal_plan::SealPlan,
    config: &crate::config::Config,
    slot: &VaultSlot,
) -> Result<Outcome, CliError> {
    use std::sync::Arc;

    use antseal_net::NetworkConfig;

    use crate::backend::{ReceiptSink, SealBackend, runtime, wallet_key};
    use crate::seal_consent::TtyConsentPrompt;
    use crate::seal_run::{AnchorStageConfig, SealContext, run_seal};
    use crate::seal_session::SealSession;
    use crate::vault::wallet::{load_wallet_key, no_wallet_key_refusal};

    let ui = Ui { json: globals.json };
    // **U73 ruled this line stays first.** It is why this build answers
    // `seal` into a vault-less HOME with "no vault exists" (2) where the
    // default build answers with the seam refusal (23) — a divergence the
    // spawned-binary suite now asserts per arm rather than assuming away.
    // The full argument is on `seal` above; the short form is that this is
    // one `stat`, the seam below is a runtime plus a connect, and the
    // cheapest thing that can say no goes first.
    let layout = open_layout()?;
    let _lock =
        VaultLock::acquire(&layout.beside_path(BesideFile::Lockfile)).map_err(CliError::from)?;

    // The network definition BEFORE the passphrase: a devnet with no
    // exported environment cannot be sealed to, and finding that out
    // after typing a passphrase is the rudeness U20 named.
    // Named distinctly from the `config: &crate::config::Config` parameter above.
    // It was `config` and SHADOWED the parameter, which silently pointed U22's
    // `AnchorStageConfig::from_config` at the wrong type — a tier-2-only compile
    // error no default-features gate could see (Q112).
    let net_config = NetworkConfig::select(plan.network, devnet_env().as_ref()).map_err(|e| {
        CliError::Usage {
            message: format!(
                "{e} — export ANTSEAL_DEVNET_ENV pointing at a running devnet's .devnet/env \
                 (scripts/devnet/local-up), or seal to --network arbitrum-sepolia"
            ),
        }
    })?;

    let passphrase = collect_passphrase(globals, PassphrasePurpose::Unlock)?;
    // S36: the vault is unlocked straight into a `SealSession`, which is
    // what pairs it with D37's durable receipt sink. `seal` is a paying
    // command, and a paying command that built a bare journal would put the
    // tree back where it was before S31 — the capture hook fires, nothing
    // durable happens, and a crash between sub-batch txs buys the landed
    // sub-batches a second time. The session takes an `Arc` share rather than
    // the value (D99 R2 — `unlock_for_command` keeps one for the hook), and
    // `UnlockedVault` is still `!Clone`, so this is still the one
    // `UnlockedVault` and the one `VaultKey` in the process.
    let session = SealSession::open(unlock_for_command(&layout, &passphrase, slot)?);
    // D155 §2 R4: the message has one public author in `vault::wallet`,
    // because nothing in this private module can be reached by a test and
    // the old copy's remedy — restore from a `vault export` backup — was
    // unfollowable for every wrap mode (the vault is unlocked here, so
    // `vault import` refuses over it, always).
    let handle =
        load_wallet_key(session.vault())?.ok_or_else(|| no_wallet_key_refusal(layout.root()))?;
    let key = wallet_key(&handle)?;

    let ctx = SealContext {
        machine_mode: crate::machine::machine_mode_for(globals),
        to_stderr: globals.json,
        now_unix_secs: now_unix_secs(),
        app_version: format!("antseal/{}", env!("CARGO_PKG_VERSION")),
        // U22/U26. This is the ONLY production construction of the anchor
        // stage's endpoint set, and it is the only one that may name the
        // built-in defaults.
        anchors: AnchorStageConfig::from_config(config),
    };
    let rt = runtime()?;
    let result = rt.block_on(async {
        // The same object on both sides: the backend fires it from inside
        // `pay`, and the pipeline arms it with the drawn `seal_id` through
        // the session's journal. `seal_session.rs`'s scan is what keeps a
        // future edit from minting a second one here.
        let backend = SealBackend::connect(
            &net_config,
            &key,
            session.receipts() as Arc<dyn ReceiptSink>,
        )
        .await?;
        run_seal(
            &backend,
            &session,
            plan,
            &mut TtyConsentPrompt,
            &ctx,
            &mut OsEntropy,
            &mut OsEntropy,
        )
        .await
    })?;

    for line in result.render() {
        ui.line(&line);
    }
    Ok(Outcome::value(result.json()))
}

/// The devnet's exported environment, when one is present.
///
/// The devnet has no built-in definition anywhere by design (S5): its
/// contract addresses are minted by the Anvil run that created it, so the
/// only truthful source is the file that run wrote.
/// `pub(crate)` since U67: [`crate::backend::payment_rpc`] resolves the same
/// devnet definition when it opens a session for D33's block-number
/// backfill, and a second reader of `ANTSEAL_DEVNET_ENV` is a second chance
/// for one invocation to run against two devnets.
#[cfg(feature = "ant-backend")]
pub(crate) fn devnet_env() -> Option<antseal_net::DevnetEnv> {
    let path = std::env::var_os("ANTSEAL_DEVNET_ENV")?;
    let text = std::fs::read_to_string(path).ok()?;
    antseal_net::DevnetEnv::from_env_file(&text).ok()
}

/// `list` (U19).
///
/// Read-only, and deliberately **not** under the U5 single-writer lock:
/// that lock exists to serialize writers, and making `list` wait on a
/// running seal would turn the one command you reach for when something
/// looks wrong into the one command that hangs. The cost is that a listing
/// taken during a seal may show that work mid-transition — which is
/// exactly what it is.
pub(crate) fn list(globals: &GlobalArgs, slot: &VaultSlot) -> Result<Outcome, CliError> {
    let ui = Ui { json: globals.json };
    let layout = open_layout()?;
    let passphrase = collect_passphrase(globals, PassphrasePurpose::Unlock)?;
    let vault = unlock_for_command(&layout, &passphrase, slot)?;

    let listing = crate::listing::WorkListing::gather(&WorkStore::new(&vault))?;
    for line in listing.render() {
        ui.line(&line);
    }
    Ok(Outcome::value(listing.json()))
}

/// `show <WORK-ID>` (U27; the gather, the D43 snippet ladder and the
/// rendering are [`crate::show`]).
///
/// Read-only, and — like `list` and `status` — deliberately **not** under
/// the U5 single-writer lock: the command a user reaches for to decide what
/// to reveal must not be the command that hangs behind a running seal. It
/// touches no backend at all (D67 §1 j): every snippet comes from the D43
/// cache or from the user's own current file, and neither can reach the
/// network.
pub(crate) fn show(
    globals: &GlobalArgs,
    work_id: &str,
    slot: &VaultSlot,
) -> Result<Outcome, CliError> {
    let ui = Ui { json: globals.json };
    let layout = open_layout()?;
    let passphrase = collect_passphrase(globals, PassphrasePurpose::Unlock)?;
    let vault = unlock_for_command(&layout, &passphrase, slot)?;
    let store = WorkStore::new(&vault);

    let seal_id = crate::pipeline::restore::resolve_work_id(&store, work_id)?;
    let units = crate::show::WorkUnits::gather(&store, &seal_id)?;

    for line in units.render() {
        ui.line(&line);
    }
    Ok(Outcome::value(units.json()))
}

/// `status <WORK-ID> [--upgrade]` (U23; the evaluation and rendering are
/// [`crate::status`], the ruling is D98).
///
/// Read-only by default and — like `list` — deliberately **not** under the
/// U5 single-writer lock: the command you reach for when something looks
/// wrong must not be the command that hangs behind a running seal.
///
/// `--upgrade` writes, and its lock discipline is D99 R3's: poll unlocked
/// (the lock exists to serialize writers, and holding it for a calendar
/// round-trip would block every concurrent `seal` for up to two minutes),
/// then take it only when there is something to persist. The window that
/// opens is closed by `apply_upgrade`'s compare-and-set, not by hope.
///
/// The clock is read **once** and used for both jobs (D98 rider 2c): the
/// verification time every anchor is evaluated at, and — through the engine's
/// parameter — the `fetch_date` a recorded upgrade group carries (D97 R5). A
/// second read could straddle a certificate expiry inside one output.
pub(crate) fn status(
    globals: &GlobalArgs,
    work_id: &str,
    upgrade: bool,
    slot: &VaultSlot,
) -> Result<Outcome, CliError> {
    let ui = Ui { json: globals.json };
    let layout = open_layout()?;
    let passphrase = collect_passphrase(globals, PassphrasePurpose::Unlock)?;
    let vault = unlock_for_command(&layout, &passphrase, slot)?;
    let store = WorkStore::new(&vault);

    let now = now_unix_secs();
    let seal_id = crate::pipeline::restore::resolve_work_id(&store, work_id)?;

    let mut applied = None;
    if upgrade {
        let config = crate::config::load()?;
        let upgrade_config = crate::status::UpgradeConfig::from_config(&config);
        let (stored, report) =
            crate::status::poll_upgrades(&store, &seal_id, &upgrade_config, now)?;
        applied = Some(if report.is_empty() {
            crate::status::UpgradeOutcome::of_report(&report)
        } else {
            let _lock = VaultLock::acquire(&layout.beside_path(BesideFile::Lockfile))
                .map_err(CliError::from)?;
            crate::status::persist_upgrades(&store, &seal_id, &stored, &report, &mut OsEntropy)?
        });
    }

    // ── U67: D33's block-number backfill, hosted here ──────────────────
    //
    // WHY THE SLOT CAN BE `None`, AND WHAT RE-FILLS IT. `TxRecord::block_number`
    // is D33's enrichment slot: the payment landed but the receipt read did
    // not (an interrupted await, an RPC blip, a crash in the post-pay window).
    // The tx *hash* is the load-bearing capture and is always journaled, so
    // the number is re-derivable from it forever — which is why D33 Decision 2
    // lets enrichment be lazy and says *"every subsequent invocation retries
    // idempotently"*. Until U67 nothing in the product performed that retry:
    // `backfill_block_numbers` existed with no caller outside a devnet test,
    // and a work whose enrichment failed once could never embed its receipt
    // in a `.sealproof` again (registry §7.10 key 1 is required, so R16
    // refuses `--include-receipt` with `ReceiptBlockNumberUnknown`). **This
    // line is that retry.** Delete it and the refusal becomes permanent again;
    // `the_block_number_backfill_has_exactly_one_production_caller` in
    // `tests/receipt_backfill.rs` is what makes that a red rather than a
    // rediscovery.
    //
    // WHY HERE. `status` is the only command that renders the block number at
    // all, so the repair sits beside the display of the thing repaired, and —
    // like `--upgrade`'s persist just above, and for the same reason — it runs
    // *before* the gather, so one `status <id>` both closes the gap and shows
    // it closed. The full argument, including why U67's own "natural" host
    // (the A15/U24 hook) was measured and refused, is on the function.
    //
    // WHAT IT COSTS AND WHAT IT CANNOT DO. It returns no `Result` and no error
    // — there is no expression here through which it could reach `status`'s
    // exit code or a byte of its output (D33: enrichment never gates; U24:
    // never delay, never fail, never prompt). It opens nothing unless an empty
    // slot is actually found, so a healthy work pays one already-cached record
    // read and a default build pays only that. Because this sits *before* the
    // gather it can delay the **answer**, not merely the exit — a stricter
    // position than U24's post-output hook — so the network legs carry a hard
    // deadline (`backend.rs`'s `PAYMENT_RPC_BUDGET`, 10 s each), and a timeout is
    // the same silent skip every other failure is.
    let _backfill = crate::pipeline::receipt_backfill::enrich_recorded_receipt(&vault, &seal_id);

    // Gathered *after* the write, so one `--upgrade` run renders the state it
    // just produced rather than the state it started from — which is also
    // what makes U23's "a re-run shows the new state" a check of durability
    // rather than of ordering.
    let mut status = crate::status::WorkStatus::gather(
        &store,
        &seal_id,
        crate::status::StatusContext::new(now),
    )?;
    status.upgrade = applied;

    for line in status.render() {
        ui.line(&line);
    }
    Ok(Outcome::value(status.json()))
}

/// `restore <WORK-ID> [-o DIR]` (U20; policy and engine in
/// [`crate::restore_out`] and [`crate::pipeline::restore`]).
///
/// The backend seam is reached **first**, before the vault is opened and
/// before any passphrase is asked for: a build that cannot reach the
/// network should say so rather than collect a secret and then refuse.
pub(crate) fn restore(
    _globals: &GlobalArgs,
    _work_id: &str,
    _output: Option<&Path>,
    // U20's live path unlocks through `unlock_for_command` like every other
    // vault-holding command; this build refuses at the backend seam first, so
    // nothing is ever armed.
    _slot: &VaultSlot,
) -> Result<Outcome, CliError> {
    Err(crate::backend::unavailable("restore"))
}

/// `reveal <WORK-ID> (--all | --units …) [-o FILE] [--include-receipt]
/// [--yes]` (U28's flow in [`crate::reveal_out`], U29's
/// irreversible-disclosure gate in [`crate::reveal_consent`]).
///
/// # U72: the backend seam is **not** reached first any more
///
/// This handler used to return `backend::unavailable("reveal")`
/// unconditionally, at entry — `restore`'s order, on the reasoning that a
/// reveal may have to fetch a ciphertext this vault no longer caches. That
/// reasoning is right about *may* and wrong about *must*. R16's gathering
/// is cache-first by D43's ruling, so a work whose retained cache is intact
/// is disclosable with zero network access, and the entry refusal made the
/// default build refuse on bytes already on the user's own disk.
///
/// U72's ruling, argued in full on [`crate::backend::VaultLocalBackend`]:
/// the handler resolves, unlocks, prepares and gathers as far as it can,
/// and the refusal lands at the point a fetch is genuinely required. A
/// partial cache refuses the **whole** reveal there rather than disclosing
/// the cached subset, and — because R16 gathers inside `prepare` and
/// [`crate::reveal_out::run_reveal`] gates on `prepare`'s result — that
/// refusal is automatically *before* the consent gate, which is where D68
/// §3 R8 wants it and what D68's own "nobody consents to a disclosure that
/// cannot be written" implies for one that cannot be gathered.
///
/// The passphrase is therefore collected before the disclosure can be
/// known to be possible, which is a real cost and the ordering `show`,
/// `list` and `status` already pay: the vault is the only place the work,
/// its cache and its keys live, so there is nothing to decide before it is
/// open. What has *not* changed is that nothing irreversible happens before
/// the gate: the output path is resolved and a collision refused first (D68
/// §3 R8), and the gate is asked only when a bundle could actually be
/// produced.
///
/// # The consent gate's one production call site (U71)
///
/// The `consent` argument [`crate::reveal_out::run_reveal`] takes is an
/// arbitrary closure, so `|_| Ok(())` compiles and is a *different command*
/// — one that writes irreversibly-disclosed plaintext without asking. This
/// is the only production expression in the crate that supplies it, it
/// supplies [`DisclosureConsent::gate`], and
/// `the_reveal_consent_gate_has_exactly_one_production_caller` in
/// `tests/reveal_consent.rs` holds both facts as a red-capable source
/// assertion.
pub(crate) fn reveal(
    globals: &GlobalArgs,
    args: &crate::cli::RevealArgs,
    slot: &VaultSlot,
) -> Result<Outcome, CliError> {
    use crate::reveal_consent::{DisclosureConsent, TtyDisclosurePrompt};

    let ui = Ui { json: globals.json };
    let layout = open_layout()?;
    let passphrase = collect_passphrase(globals, PassphrasePurpose::Unlock)?;
    let vault = unlock_for_command(&layout, &passphrase, slot)?;
    let store = WorkStore::new(&vault);

    // U29's gate, assembled from the invocation's own context: D51's single
    // machine-mode detection point, and the same stream selector every
    // human line in this handler uses.
    let mut prompt = TtyDisclosurePrompt;
    let gate = DisclosureConsent::new(
        args.yes,
        crate::machine::machine_mode_for(globals),
        globals.json,
        &mut prompt,
    );

    // U72: a backend that serves nothing and says why, rather than no
    // reveal at all. Its refusal is what a genuinely-required fetch meets.
    let backend = crate::backend::VaultLocalBackend::new("reveal");
    let report = crate::backend::block_on_vault_local(crate::reveal_out::run_reveal(
        &backend,
        &store,
        args,
        gate.gate(),
    ))??;

    for line in report.render() {
        ui.line(&line);
    }
    Ok(Outcome::value(report.json()))
}

/// `verify <BUNDLE> [--online] [--live]` (U30; the run, its rendering and
/// its `--json` document are [`crate::verify_out`], the network hosts are
/// [`crate::verify_host`], the rulings are D69/D65/D128).
///
/// **No vault, and it never prompts** — the frozen help says so and this
/// handler proves it: nothing here resolves a layout, collects a passphrase
/// or touches [`VaultSlot`]. `verify` is the third party's command
/// (MVP-SPEC.md line 38), and a third party has no vault to open.
///
/// # Order of operations, and why `--live` refuses first
///
/// `--live` needs the storage-backend construction seam (U36's, shared with
/// `seal`/`restore`/`reveal`). A build without one cannot attempt the check
/// at all, so it refuses **before verification** in the transient network
/// class (23) — D69 §3 R6's one carve-out, and a *process* outcome rather
/// than a verdict. A build that *can* fetch behaves the other way entirely:
/// the offline verdict renders in full, the live section reports R11's own
/// `Inconclusive`, and the exit code is still the evidence verdict's.
///
/// `--online` probes before the run because R21's host seam is a pure
/// accessor over already-collected data. A bundle that will not even decode
/// is not probed — there is nothing to ask about — and the rejection its
/// verification produces is the authoritative one.
pub(crate) fn verify(
    globals: &GlobalArgs,
    bundle_path: &Path,
    online: bool,
    live: bool,
    // D99 R2: `verify` opens no vault, so it never arms the upgrade hook.
    _slot: &VaultSlot,
) -> Result<Outcome, CliError> {
    use antseal_core::verify::VerifyOptions;
    use antseal_core::verify::orchestration::VerifyModes;

    let ui = Ui { json: globals.json };

    // D69 §3 R2's non-verdict row: a bundle file that is missing or
    // unreadable is `io-error` (4), not a verdict — nothing was verified.
    let bytes = std::fs::read(bundle_path).map_err(|source| CliError::Io {
        context: format!("reading {}", bundle_path.display()),
        source,
    })?;

    if live {
        // The seam, before any verification (D69 §3 R6). A default build
        // compiles no storage backend at all; the message names the actual
        // cause rather than implying an outage.
        return Err(crate::backend::unavailable("verify"));
    }

    let mut modes = VerifyModes::OFFLINE;
    let mut host = crate::verify_host::CollectedInputs::none();
    if online {
        modes = modes.with_online();
        let config = crate::config::load()?;
        let network = crate::config::effective_network(globals.network, &config);
        if let Some(endpoints) = crate::verify_host::endpoints_from_config(&config, network)? {
            let client =
                antseal_anchor::http::HttpClient::new(antseal_anchor::http::HttpPolicy::verify());
            if let Ok(decoded) = antseal_core::bundle::BundleV1::decode(&bytes) {
                host = host.with_online(crate::verify_host::probe_online(
                    &client, &decoded, &endpoints, network,
                ));
            }
        }
    }

    // The clock is read once for the whole run: a verification that read the
    // time twice could straddle a certificate expiry inside one output
    // (`status`'s own rule, for the same reason).
    let options = VerifyOptions::new().with_verify_at_unix(now_unix_secs());
    let run = crate::verify_out::run_verify(&bytes, &options, modes, &host)?;

    for line in run.render() {
        ui.line(&line);
    }

    // D69 §3 R1's third arm: the rung sets the process code and the success
    // envelope is still emitted, because `ok` means "a result document is
    // present". D65 §5's carriage: the result is text, so `report` reaches
    // stdout byte-for-byte as `to_canonical_json()` produced it.
    Ok(Outcome::raw(run.json()?, run.exit_class()))
}

/// `vault export [FILE]` (U12; format and engine in
/// [`crate::vault::export`]).
pub(crate) fn vault_export(
    globals: &GlobalArgs,
    file: Option<&Path>,
    slot: &VaultSlot,
) -> Result<Outcome, CliError> {
    let ui = Ui { json: globals.json };
    let layout = open_layout()?;

    // The single-writer lock for the whole snapshot: export reads many
    // record files and must not interleave with a concurrent writer.
    let _lock =
        VaultLock::acquire(&layout.beside_path(BesideFile::Lockfile)).map_err(CliError::from)?;

    let passphrase = collect_passphrase(globals, PassphrasePurpose::Unlock)?;
    // The unlock IS the passphrase proof D47 requires before that same
    // passphrase becomes the backup's only key.
    let vault = unlock_for_command(&layout, &passphrase, slot)?;

    let out_path = match file {
        Some(path) => path.to_path_buf(),
        None => PathBuf::from(default_export_name(now_unix_secs())),
    };
    let summary = export_vault(&vault, &passphrase, &out_path, &mut OsEntropy)?;
    // U18/U34: record the export **after** the file is written and
    // self-verified, never before — the flag that stops the nag must mean
    // "a backup exists", and a bookkeeping write that ran first would
    // silence the nag for an export that then failed.
    crate::vault::bookkeeping::record_export(&vault, now_unix_secs(), &mut OsEntropy)?;

    ui.line(&format!(
        "Exported {} work record(s) to {} ({} bytes; self-verified by a full re-read \
         and decrypt).",
        summary.works,
        summary.path.display(),
        summary.bytes,
    ));
    ui.line(
        "Treat this file like the vault itself: whoever holds it and the passphrase \
         holds the keys to every sealed work, forever.",
    );

    Ok(Outcome::value(serde_json::json!({
        "file": summary.path.display().to_string(),
        "works": summary.works,
        "bytes": summary.bytes,
        "self_verified": true,
    })))
}

/// `vault import <FILE>` (U12).
pub(crate) fn vault_import(
    globals: &GlobalArgs,
    file: &Path,
    // D99 R2 / D42's corrected consequence: `vault import` does NOT arm.
    // Its only unlock is the self-verification inside `import_vault`, which
    // never leaves that function — so there is no handle here to move up, and
    // manufacturing one would cost a second ~1 s Argon2id derivation for a
    // vault the user's next command will unlock properly.
    _slot: &VaultSlot,
) -> Result<Outcome, CliError> {
    let ui = Ui { json: globals.json };
    let layout = VaultLayout::resolve().map_err(|e| CliError::Usage {
        message: e.to_string(),
    })?;

    // The passphrase is collected lazily, only after the file's pre-auth
    // header checks pass (garbage never prompts); the machine-mode rule
    // applies at that point exactly as it would up front.
    let summary = import_vault(
        file,
        &layout,
        || collect_passphrase(globals, PassphrasePurpose::Unlock),
        &mut OsEntropy,
    )?;

    ui.line(&format!(
        "Imported {} work record(s) into {} (validated in memory, installed \
         atomically, verified by a fresh unlock).",
        summary.works,
        summary.vault_dir.display(),
    ));
    if summary.wallet_present {
        ui.line("The wallet key was restored.");
    }
    if summary.config_present {
        ui.line("config.toml was restored.");
    }

    Ok(Outcome::value(serde_json::json!({
        "vault_dir": summary.vault_dir.display().to_string(),
        "works": summary.works,
        "wallet_restored": summary.wallet_present,
        "config_restored": summary.config_present,
    })))
}

/// This invocation's clock read, POSIX seconds UTC. Shared with U24's hook,
/// which reads it once for its own pass (the rotation seed and the
/// `fetch_date` a recorded upgrade group carries).
pub(crate) fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Default export file name (D47 leaves naming to U12): timestamped so
/// repeated exports never silently replace an earlier backup —
/// `antseal-vault-export-YYYYMMDD-HHMMSS.sealvault` (UTC), in the
/// current directory. The extension is advisory; identification is by
/// magic.
fn default_export_name(unix_secs: u64) -> String {
    let (y, mo, d, h, mi, s) = civil_utc(unix_secs);
    format!("antseal-vault-export-{y:04}{mo:02}{d:02}-{h:02}{mi:02}{s:02}.{EXPORT_FILE_EXTENSION}")
}

/// Unix seconds → UTC civil date-time (Howard Hinnant's `civil_from_days`
/// algorithm; std has no calendar and a chrono-class dependency for one
/// filename is not warranted). Valid for the whole unix era.
#[allow(clippy::many_single_char_names)]
pub(crate) fn civil_utc(unix_secs: u64) -> (i64, u32, u32, u32, u32, u32) {
    let days = (unix_secs / 86_400) as i64;
    let rem = unix_secs % 86_400;
    let (h, mi, s) = (
        (rem / 3600) as u32,
        ((rem % 3600) / 60) as u32,
        (rem % 60) as u32,
    );
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = u32::try_from(doy - (153 * mp + 2) / 5 + 1).unwrap_or(1);
    let m = u32::try_from(if mp < 10 { mp + 3 } else { mp - 9 }).unwrap_or(1);
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d, h, mi, s)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pinned against `date -u` (2026-08-01): the epoch, a leap-day
    /// midday, and the current-era value used in fixtures.
    #[test]
    fn civil_utc_matches_known_dates() {
        assert_eq!(civil_utc(0), (1970, 1, 1, 0, 0, 0));
        assert_eq!(civil_utc(951_825_661), (2000, 2, 29, 12, 1, 1));
        assert_eq!(civil_utc(1_785_600_000), (2026, 8, 1, 16, 0, 0));
    }

    #[test]
    fn default_export_name_is_timestamped_and_extension_advisory() {
        assert_eq!(
            default_export_name(1_785_600_000),
            "antseal-vault-export-20260801-160000.sealvault"
        );
    }
}
