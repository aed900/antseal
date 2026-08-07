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
/// on stdout under `--json`; U3's envelope wraps it).
pub(crate) struct Outcome {
    pub json: serde_json::Value,
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
    Ok(Outcome {
        json: report.json(),
    })
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
    use crate::vault::wallet::load_wallet_key;

    let ui = Ui { json: globals.json };
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
    let handle = load_wallet_key(session.vault())?.ok_or_else(|| CliError::Usage {
        message: "this vault holds no wallet key, so it cannot pay for a seal — it was \
                  created by an older build, or the wallet record was removed. Restore from a \
                  `antseal vault export` backup"
            .to_owned(),
    })?;
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
    Ok(Outcome {
        json: result.json(),
    })
}

/// The devnet's exported environment, when one is present.
///
/// The devnet has no built-in definition anywhere by design (S5): its
/// contract addresses are minted by the Anvil run that created it, so the
/// only truthful source is the file that run wrote.
#[cfg(feature = "ant-backend")]
fn devnet_env() -> Option<antseal_net::DevnetEnv> {
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
    Ok(Outcome {
        json: listing.json(),
    })
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
    Ok(Outcome {
        json: status.json(),
    })
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

    Ok(Outcome {
        json: serde_json::json!({
            "file": summary.path.display().to_string(),
            "works": summary.works,
            "bytes": summary.bytes,
            "self_verified": true,
        }),
    })
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

    Ok(Outcome {
        json: serde_json::json!({
            "vault_dir": summary.vault_dir.display().to_string(),
            "works": summary.works,
            "wallet_restored": summary.wallet_present,
            "config_restored": summary.config_present,
        }),
    })
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
