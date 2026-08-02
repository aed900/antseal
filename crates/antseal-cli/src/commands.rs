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
use crate::vault::export::{EXPORT_FILE_EXTENSION, export_vault, import_vault};
use crate::vault::layout::{BesideFile, VaultLayout};
use crate::vault::lock::VaultLock;
use crate::vault::session::unlock_vault;
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
pub(crate) fn init(globals: &GlobalArgs, args: &crate::cli::InitArgs) -> Result<Outcome, CliError> {
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
pub(crate) fn seal(globals: &GlobalArgs, args: &crate::cli::SealArgs) -> Result<Outcome, CliError> {
    let network = effective_network(globals)?;
    let cwd = std::env::current_dir().map_err(|source| CliError::Io {
        context: "resolving the current directory to absolutize the seal arguments".to_owned(),
        source,
    })?;
    let plan = crate::seal_plan::build_plan(args, network, &cwd)?;
    seal_over_backend(globals, &plan)
}

/// The network the invocation actually runs on: flag > config > built-in
/// default (U4's precedence).
///
/// `config::load()` runs a second time here — `main_entry` already loaded
/// it to fill the U3 envelope's `network` field but does not pass the
/// resolution down, and a handler that guessed instead would be a second
/// answer to a question U4 settled. A malformed config has already hard-
/// failed before dispatch, so the reload can only agree.
fn effective_network(globals: &GlobalArgs) -> Result<antseal_net::NetworkId, CliError> {
    Ok(crate::config::effective_network(
        globals.network,
        &crate::config::load()?,
    ))
}

/// The storage-backend half of `seal`, reached only after the whole plan
/// has been validated.
#[cfg(not(feature = "ant-backend"))]
fn seal_over_backend(
    _globals: &GlobalArgs,
    _plan: &crate::seal_plan::SealPlan,
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
) -> Result<Outcome, CliError> {
    use std::sync::Arc;

    use antseal_net::NetworkConfig;

    use crate::backend::{SealBackend, runtime, wallet_key};
    use crate::seal_consent::TtyConsentPrompt;
    use crate::seal_run::{SealContext, SealReceipts, run_seal};
    use crate::vault::wallet::load_wallet_key;

    let ui = Ui { json: globals.json };
    let layout = open_layout()?;
    let _lock =
        VaultLock::acquire(&layout.beside_path(BesideFile::Lockfile)).map_err(CliError::from)?;

    // The network definition BEFORE the passphrase: a devnet with no
    // exported environment cannot be sealed to, and finding that out
    // after typing a passphrase is the rudeness U20 named.
    let config = NetworkConfig::select(plan.network, devnet_env().as_ref()).map_err(|e| {
        CliError::Usage {
            message: format!(
                "{e} — export ANTSEAL_DEVNET_ENV pointing at a running devnet's .devnet/env \
                 (scripts/devnet/local-up), or seal to --network arbitrum-sepolia"
            ),
        }
    })?;

    let passphrase = collect_passphrase(globals, PassphrasePurpose::Unlock)?;
    let vault = unlock_vault(&layout, &passphrase)?;
    let handle = load_wallet_key(&vault)?.ok_or_else(|| CliError::Usage {
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
    };
    let receipts = SealReceipts::new();
    let rt = runtime()?;
    let result = rt.block_on(async {
        let backend = SealBackend::connect(&config, &key, Arc::clone(&receipts) as Arc<_>).await?;
        run_seal(
            &backend,
            &vault,
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
pub(crate) fn list(globals: &GlobalArgs) -> Result<Outcome, CliError> {
    let ui = Ui { json: globals.json };
    let layout = open_layout()?;
    let passphrase = collect_passphrase(globals, PassphrasePurpose::Unlock)?;
    let vault = unlock_vault(&layout, &passphrase)?;

    let listing = crate::listing::WorkListing::gather(&WorkStore::new(&vault))?;
    for line in listing.render() {
        ui.line(&line);
    }
    Ok(Outcome {
        json: listing.json(),
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
) -> Result<Outcome, CliError> {
    Err(crate::backend::unavailable("restore"))
}

/// `vault export [FILE]` (U12; format and engine in
/// [`crate::vault::export`]).
pub(crate) fn vault_export(globals: &GlobalArgs, file: Option<&Path>) -> Result<Outcome, CliError> {
    let ui = Ui { json: globals.json };
    let layout = open_layout()?;

    // The single-writer lock for the whole snapshot: export reads many
    // record files and must not interleave with a concurrent writer.
    let _lock =
        VaultLock::acquire(&layout.beside_path(BesideFile::Lockfile)).map_err(CliError::from)?;

    let passphrase = collect_passphrase(globals, PassphrasePurpose::Unlock)?;
    // The unlock IS the passphrase proof D47 requires before that same
    // passphrase becomes the backup's only key.
    let vault = unlock_vault(&layout, &passphrase)?;

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
pub(crate) fn vault_import(globals: &GlobalArgs, file: &Path) -> Result<Outcome, CliError> {
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

fn now_unix_secs() -> u64 {
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
