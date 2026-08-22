//! The `devnet`-feature implementation: drive `ant_core::data::LocalDevnet`
//! (pinned `=0.5.0`) with our own `DevnetConfig` instead of running the
//! upstream `start-local-devnet` example verbatim — and, since P22,
//! `ant_node::devnet::Devnet` directly for the Arbitrum-Sepolia mode.
//!
//! Why not the example (P16 memo §6): it hardcodes `DevnetConfig::default()`
//! — 25 nodes, the flake zone on this 2-core host — and writes the manifest
//! (which embeds the funded Anvil dev key) into the SHARED
//! `~/.local/share/ant/`, coupling us to any other ant tooling on the
//! machine. We run 14 nodes by default (upstream's own e2e parity count),
//! keep every artifact under a repo-local gitignored directory, and handle
//! SIGTERM so `scripts/devnet/local-down` gets a clean, residue-free stop.
//!
//! Lifetime model: in local mode `LocalDevnet` holds the `Testnet` (Anvil
//! child process) — dropping it kills Anvil — and the nodes are tokio tasks
//! of THIS process. In Sepolia mode there is no Anvil at all; the nodes are
//! still tokio tasks of this process. Either way the launcher process is the
//! devnet: `local-down` = SIGTERM this pid (from the pidfile we write),
//! nothing else to hunt down.
//!
//! ## P22: why Sepolia mode does not go through `LocalDevnet`
//!
//! P22's brief was "set `DevnetConfig.evm_network =
//! Some(EvmNetwork::ArbitrumSepoliaTest)` and skip the Anvil requirement".
//! `DevnetConfig` does carry that field (`ant-node-0.15.0/src/devnet.rs:167`)
//! — but `LocalDevnet::start` **cannot** be asked to use it. Its first act is
//! `Testnet::new()`, an unconditional Anvil spawn, and it then *overwrites*
//! whatever the caller set:
//!
//! ```text
//! ant-core-0.5.0/src/node/devnet.rs
//!   :44   let testnet = Testnet::new().await …   // Anvil, unconditionally
//!   :54   config.evm_network = Some(network.clone());   // clobbers ours
//! ```
//!
//! So skipping the `PATH` check alone would only move the failure: Anvil
//! would still be spawned (or the spawn would fail two layers down, which is
//! exactly what `assert_anvil_on_path` exists to prevent). Upstream hit the
//! same wall and answered it the same way — its own
//! `ant-core-0.5.0/examples/start-devnet-sepolia.rs` bypasses `LocalDevnet`
//! and drives `ant_node::devnet::Devnet` directly, writing the manifest by
//! hand. This module does the same, behind one enum, so the local path keeps
//! using upstream's wrapper (and upstream's manifest serialization) byte for
//! byte and only the Sepolia arm is new code.

use std::error::Error;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant, SystemTime};

use ant_core::data::{EvmNetwork, LocalDevnet};
use ant_node::devnet::{Devnet, DevnetConfig};

use crate::export::{EnvExport, ManifestExport, NetworkMode};

/// Node-count bounds. 5 is upstream's `minimal()` smoke preset — already
/// below `CLOSE_GROUP_SIZE = 7`, living on the degraded-quorum floors; below
/// that nothing meaningful stabilizes. 25 is upstream's full default and the
/// measured flake zone on 2 cores (memo §7) — allowed for parity runs,
/// nothing larger (the default `base_port` randomization reserves exactly a
/// 25-port margin).
const MIN_NODES: usize = 5;
const MAX_NODES: usize = 25;
const DEFAULT_NODES: usize = 14;

struct Options {
    network: NetworkMode,
    nodes: usize,
    dir: PathBuf,
    stabilization_secs: Option<u64>,
    node_logs: bool,
}

/// Entry point behind the feature; `main` delegates here.
pub fn run() -> ExitCode {
    let options = match parse_options() {
        Ok(options) => options,
        Err(message) => {
            eprintln!("devnet-launcher: {message}");
            eprintln!(
                "usage: devnet-launcher [--network local|arbitrum-sepolia] [--nodes N] [--dir PATH]"
            );
            return ExitCode::from(2);
        }
    };
    match boot(options) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("devnet-launcher: FAILED: {error}");
            ExitCode::FAILURE
        }
    }
}

fn parse_options() -> Result<Options, String> {
    let mut nodes = env_parse("ANTSEAL_DEVNET_NODES")?.unwrap_or(DEFAULT_NODES);
    let mut dir = std::env::var_os("ANTSEAL_DEVNET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(".devnet"));
    // The default is `local` and there is deliberately no environment
    // override for it: `--nodes`/`--dir` have one because harnesses tune
    // them, but a devnet silently booting against a different CHAIN because
    // a variable was left exported is not a knob anyone wants. The mode is
    // named at the call site or it is local.
    let mut network = NetworkMode::default();

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--network" => {
                let value = args.next().ok_or("--network needs a value")?;
                network = NetworkMode::parse(&value)?;
            }
            "--nodes" | "-n" => {
                let value = args.next().ok_or("--nodes needs a value")?;
                nodes = value
                    .parse::<usize>()
                    .map_err(|_| format!("--nodes: not a number: {value}"))?;
            }
            "--dir" => dir = PathBuf::from(args.next().ok_or("--dir needs a value")?),
            "--help" | "-h" => {
                return Err(
                    "boots the P16 local devnet (--network local, the default) or the P17 \
                     Arbitrum-Sepolia devnet (--network arbitrum-sepolia); see \
                     docs/devnet/local-devnet.md and docs/devnet/sepolia-devnet.md"
                        .into(),
                );
            }
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    if !(MIN_NODES..=MAX_NODES).contains(&nodes) {
        return Err(format!(
            "--nodes {nodes} is outside {MIN_NODES}..={MAX_NODES} (5 = smoke preset, \
             14 = default/e2e parity, 25 = upstream-default parity; memo §3)"
        ));
    }
    Ok(Options {
        network,
        nodes,
        dir,
        stabilization_secs: env_parse::<u64>("ANTSEAL_DEVNET_STABILIZATION_SECS")?,
        node_logs: std::env::var("ANTSEAL_DEVNET_NODE_LOGS").is_ok_and(|v| v == "1"),
    })
}

fn env_parse<T: std::str::FromStr>(name: &str) -> Result<Option<T>, String> {
    match std::env::var(name) {
        Ok(value) => value
            .parse::<T>()
            .map(Some)
            .map_err(|_| format!("{name}: not a number: {value}")),
        Err(_) => Ok(None),
    }
}

/// The upstream presets carry stabilization timeouts tuned to their sizes
/// (5 → 30 s, 10 → 60 s, default → 120 s); anything non-preset takes the
/// full default timeout. `data_dir`, logging and the env override are then
/// applied uniformly — `cleanup_data_dir` stays `true`, so a clean shutdown
/// removes the node stores without our help.
///
/// `evm_network` is the P22 seam and is set here for both modes, in one
/// place: `Some(ArbitrumSepoliaTest)` selects the real chain-421614
/// contracts, and `None` is what every upstream preset already carries, so
/// the local path is unchanged (and `LocalDevnet::start` overwrites it with
/// Anvil's `Custom` network regardless — see the module docs).
fn build_config(options: &Options, data_dir: PathBuf) -> DevnetConfig {
    let mut config = match options.nodes {
        5 => DevnetConfig::minimal(),
        10 => DevnetConfig::small(),
        n => DevnetConfig {
            node_count: n,
            ..DevnetConfig::default()
        },
    };
    config.data_dir = data_dir;
    config.enable_node_logging = options.node_logs;
    if let Some(secs) = options.stabilization_secs {
        config.stabilization_timeout = Duration::from_secs(secs);
    }
    config.evm_network = match options.network {
        NetworkMode::Local => None,
        NetworkMode::ArbitrumSepolia => Some(EvmNetwork::ArbitrumSepoliaTest),
    };
    config
}

/// `Testnet::new` spawns `anvil` via alloy's node bindings with no explicit
/// path — it MUST be on `PATH`. Check up front so the failure names the fix
/// instead of surfacing as an opaque spawn error two layers down.
///
/// Only the local mode reaches this: a Sepolia devnet spawns no Anvil, so
/// requiring the binary would refuse a boot that needs nothing from it
/// (docs/devnet/sepolia-devnet.md, Host requirements: "**No `anvil`**").
fn assert_anvil_on_path() -> Result<(), String> {
    let path = std::env::var_os("PATH").unwrap_or_default();
    let found = std::env::split_paths(&path).any(|p| p.join("anvil").is_file());
    if found {
        return Ok(());
    }
    Err(
        "`anvil` is not on PATH. Foundry installs it at ~/.foundry/bin/anvil \
         (scripts/devnet/local-up appends that automatically; a bare binary run \
         needs `export PATH=\"$HOME/.foundry/bin:$PATH\"`). No anvil at all? \
         Install foundry — see docs/devnet/local-devnet.md, Host requirements."
            .into(),
    )
}

/// Refuse to double-boot: a live pid in the pidfile means a devnet is already
/// running (its Anvil child and node ports would collide with ours in spirit
/// even when the OS-random ports differ — one devnet per checkout is the
/// contract `local-up`/`local-down` manage, across BOTH modes). A dead pid is
/// a stale file from a SIGKILL; say so and continue.
fn check_pidfile(pidfile: &Path) -> Result<(), String> {
    let Ok(raw) = std::fs::read_to_string(pidfile) else {
        return Ok(());
    };
    let pid = raw.trim();
    if !pid.is_empty() && Path::new(&format!("/proc/{pid}")).exists() {
        return Err(format!(
            "a devnet launcher is already running (pid {pid}, from {}). \
             Run scripts/devnet/local-down first.",
            pidfile.display()
        ));
    }
    eprintln!(
        "removing stale pidfile {} (pid {pid} is gone)",
        pidfile.display()
    );
    let _ = std::fs::remove_file(pidfile);
    Ok(())
}

fn boot(options: Options) -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    if options.network.spawns_anvil() {
        assert_anvil_on_path()?;
    }

    let dir = absolutize(&options.dir)?;
    std::fs::create_dir_all(&dir)?;
    let pidfile = dir.join("launcher.pid");
    let manifest_path = dir.join("manifest.json");
    let env_path = dir.join("env");
    check_pidfile(&pidfile)?;
    std::fs::write(&pidfile, format!("{}\n", std::process::id()))?;

    let network = options.network;
    let config = build_config(&options, dir.join("data"));
    if network == NetworkMode::ArbitrumSepolia {
        // The banner P17 requires: the wrong-Sepolia mistake is expensive
        // and silent, so the mode names itself before anything starts.
        println!(
            "devnet-launcher: network=arbitrum-sepolia chain_id={} \
             (Arbitrum Sepolia — NOT Ethereum Sepolia, 11155111); no Anvil, \
             no wallet in the export",
            network.chain_id()
        );
    }
    println!(
        "devnet-launcher: booting {} nodes (bootstrap {}, stabilization timeout {:?}) under {}",
        config.node_count,
        config.bootstrap_count,
        config.stabilization_timeout,
        dir.display()
    );

    // Upstream's example shape: multi-thread runtime with 8 MiB worker
    // stacks — the PQC handshake paths in the node stack want deep stacks.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_stack_size(8 * 1024 * 1024)
        .build()?;

    let result = runtime.block_on(run_devnet(network, &manifest_path, &env_path, config));

    // Whatever happened, the exported surface must not outlive the devnet:
    // a stale manifest/env pointing at dead ports is exactly the kind of
    // residue `local-down` promises not to leave.
    for stale in [&manifest_path, &env_path, &pidfile] {
        let _ = std::fs::remove_file(stale);
    }
    result
}

/// A booted devnet, in whichever shape its mode required.
///
/// The variants are not interchangeable upstream types — `LocalDevnet` owns
/// an Anvil `Testnet` and a manifest; `Devnet` owns neither — so everything
/// the export needs is read through this enum, and each accessor documents
/// which upstream field it reads. The local arm reads exactly the fields the
/// pre-P22 code read, from exactly the same places, which is what makes the
/// local export byte-identical rather than merely similar.
enum RunningDevnet {
    /// `--network local`: upstream's Anvil-backed wrapper.
    ///
    /// Both variants are boxed: an enum is always the size of its largest
    /// variant, and these are ~976 bytes (`LocalDevnet`, which owns the
    /// Anvil `Testnet` and a whole manifest) against ~280 (`Devnet`).
    /// Boxing one only moves which variant is the outlier, so box both —
    /// two pointers, one allocation, once per process.
    Local(Box<LocalDevnet>),
    /// `--network arbitrum-sepolia`: `ant_node`'s devnet, driven directly.
    Sepolia(Box<Devnet>),
}

/// The EVM half of the export: which chain, which contracts, and — only
/// where one exists — which wallet.
struct EvmSurface {
    /// EVM JSON-RPC endpoint.
    rpc_url: String,
    /// AutonomiNetworkToken address.
    token_address: String,
    /// PaymentVault address.
    payment_vault_address: String,
    /// The funded wallet key. **`None` in Sepolia mode** — that is the
    /// mode's defining property, not a missing value.
    wallet_private_key: Option<String>,
}

impl RunningDevnet {
    fn node_count(&self) -> usize {
        match self {
            Self::Local(devnet) => devnet.manifest().node_count,
            Self::Sepolia(devnet) => devnet.config().node_count,
        }
    }

    fn base_port(&self) -> u16 {
        match self {
            Self::Local(devnet) => devnet.manifest().base_port,
            Self::Sepolia(devnet) => devnet.config().base_port,
        }
    }

    fn data_dir(&self) -> String {
        match self {
            Self::Local(devnet) => devnet.manifest().data_dir.display().to_string(),
            Self::Sepolia(devnet) => devnet.config().data_dir.display().to_string(),
        }
    }

    /// Node socket addresses for `Client::connect`.
    fn bootstrap_socket_addrs(&self) -> Vec<String> {
        match self {
            Self::Local(devnet) => devnet
                .bootstrap_addrs()
                .iter()
                .map(std::string::ToString::to_string)
                .collect(),
            Self::Sepolia(devnet) => devnet
                .bootstrap_addrs()
                .iter()
                .filter_map(ant_node::core::MultiAddr::socket_addr)
                .map(|addr| addr.to_string())
                .collect(),
        }
    }

    /// The EVM half of the export: RPC endpoint, both contract addresses,
    /// and the wallet key **only** where one exists.
    ///
    /// Local: read out of the manifest upstream built from the live Anvil
    /// instance. Sepolia: read off `EvmNetwork::ArbitrumSepoliaTest`, i.e.
    /// evmlib's own pinned constants (`evmlib-0.9.0/src/lib.rs:58-75`) —
    /// never re-typed here, so they cannot drift from the chain the nodes
    /// actually verify against.
    fn evm_surface(&self) -> Result<EvmSurface, Box<dyn Error>> {
        match self {
            Self::Local(devnet) => {
                let evm = devnet
                    .manifest()
                    .evm
                    .as_ref()
                    .ok_or("LocalDevnet manifest unexpectedly carries no EVM section")?;
                Ok(EvmSurface {
                    rpc_url: evm.rpc_url.clone(),
                    token_address: evm.payment_token_address.clone(),
                    payment_vault_address: evm.payment_vault_address.clone(),
                    wallet_private_key: Some(evm.wallet_private_key.clone()),
                })
            }
            Self::Sepolia(devnet) => {
                let network = devnet.config().evm_network.as_ref().ok_or(format!(
                    "Sepolia devnet booted with no EVM network configured: it must be \
                     ArbitrumSepoliaTest (chain {}). Upstream's `None` default means the nodes \
                     verify payments against Arbitrum One — MAINNET",
                    NetworkMode::ARBITRUM_SEPOLIA_CHAIN_ID
                ))?;
                if !matches!(network, EvmNetwork::ArbitrumSepoliaTest) {
                    return Err(format!(
                        "Sepolia devnet booted against the wrong EVM network: {network}, not \
                         ArbitrumSepoliaTest (chain {})",
                        NetworkMode::ARBITRUM_SEPOLIA_CHAIN_ID
                    )
                    .into());
                }
                Ok(EvmSurface {
                    rpc_url: network.rpc_url().to_string(),
                    token_address: network.payment_token_address().to_string(),
                    payment_vault_address: network.payment_vault_address().to_string(),
                    wallet_private_key: None,
                })
            }
        }
    }

    /// Bootstrap multiaddrs, for the JSON manifest's `bootstrap` field.
    fn bootstrap_multiaddrs(&self) -> Vec<String> {
        match self {
            Self::Local(devnet) => devnet
                .manifest()
                .bootstrap
                .iter()
                .map(std::string::ToString::to_string)
                .collect(),
            Self::Sepolia(devnet) => devnet
                .bootstrap_addrs()
                .iter()
                .map(std::string::ToString::to_string)
                .collect(),
        }
    }

    /// Write the JSON manifest.
    ///
    /// Local mode delegates to upstream's own serializer, so the P16
    /// manifest keeps upstream's exact bytes and cannot drift from
    /// `DevnetManifest`. Sepolia mode has no such helper — and
    /// `devnet-launcher` declares no `serde_json` edge — so it renders the
    /// same shape itself, exactly as upstream's own Sepolia example does.
    async fn write_manifest(&self, path: &Path) -> Result<(), Box<dyn Error>> {
        match self {
            Self::Local(devnet) => {
                devnet
                    .write_manifest(path)
                    .await
                    .map_err(|e| format!("manifest write failed: {e}"))?;
            }
            Self::Sepolia(_) => {
                let evm = self.evm_surface()?;
                debug_assert!(
                    evm.wallet_private_key.is_none(),
                    "a Sepolia devnet has no wallet"
                );
                let manifest = ManifestExport {
                    base_port: self.base_port(),
                    node_count: self.node_count(),
                    bootstrap: self.bootstrap_multiaddrs(),
                    data_dir: self.data_dir(),
                    created_at: unix_seconds(),
                    rpc_url: evm.rpc_url,
                    payment_token_address: evm.token_address,
                    payment_vault_address: evm.payment_vault_address,
                };
                std::fs::write(path, manifest.render_json())
                    .map_err(|e| format!("manifest write failed: {e}"))?;
            }
        }
        Ok(())
    }

    async fn shutdown(&mut self) -> Result<(), String> {
        match self {
            Self::Local(devnet) => devnet
                .shutdown()
                .await
                .map_err(|e| format!("devnet shutdown failed: {e}")),
            Self::Sepolia(devnet) => devnet
                .shutdown()
                .await
                .map_err(|e| format!("devnet shutdown failed: {e}")),
        }
    }
}

/// Upstream writes Unix seconds as opaque text in `created_at`; match it.
fn unix_seconds() -> String {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .to_string()
}

async fn run_devnet(
    network: NetworkMode,
    manifest_path: &Path,
    env_path: &Path,
    config: DevnetConfig,
) -> Result<(), Box<dyn Error>> {
    // The signal streams exist BEFORE the boot starts. Until a handler is
    // installed, SIGTERM's default disposition kills the process outright —
    // destructors skipped — and boot takes up to the stabilization timeout:
    // a `local-down` issued in that window would orphan the Anvil child.
    // With the streams armed, an early SIGTERM/SIGINT instead cancels the
    // `start` future (dropping the partially-built Testnet kills Anvil; the
    // runtime drop in `boot` reaps any already-spawned node tasks). The node
    // data dir can survive that abort path — `local-reset` clears it, and
    // the runbook says so.
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;

    let boot_started = Instant::now();
    let mut devnet = tokio::select! {
        result = start(network, config) => result?,
        _ = sigterm.recv() => {
            println!("devnet-launcher: SIGTERM during boot — aborting");
            return Err("aborted by SIGTERM during boot (partial node data may remain; scripts/devnet/local-reset clears it)".into());
        }
        result = tokio::signal::ctrl_c() => {
            result?;
            println!("devnet-launcher: SIGINT during boot — aborting");
            return Err("aborted by SIGINT during boot (partial node data may remain; scripts/devnet/local-reset clears it)".into());
        }
    };
    let boot_secs = boot_started.elapsed().as_secs_f64();

    let outcome = export_and_wait(
        network,
        &devnet,
        &mut sigterm,
        manifest_path,
        env_path,
        boot_secs,
    )
    .await;

    // Shutdown runs on BOTH paths — the export failing must still stop the
    // nodes and let `cleanup_data_dir` remove the stores.
    let shutdown = devnet.shutdown().await;
    println!("devnet-launcher: STOPPED");
    outcome.and(shutdown.map_err(Into::into))
}

/// Boot the devnet its mode asks for.
///
/// Local goes through upstream's `LocalDevnet` (Anvil + nodes + manifest, in
/// one call). Sepolia drives `ant_node::devnet::Devnet` directly — two calls,
/// no Anvil — because `LocalDevnet` cannot be told not to start one (module
/// docs).
async fn start(
    network: NetworkMode,
    config: DevnetConfig,
) -> Result<RunningDevnet, Box<dyn Error>> {
    match network {
        NetworkMode::Local => {
            let devnet = LocalDevnet::start(config)
                .await
                .map_err(|e| format!("devnet failed to start: {e}"))?;
            Ok(RunningDevnet::Local(Box::new(devnet)))
        }
        NetworkMode::ArbitrumSepolia => {
            let mut devnet = Devnet::new(config)
                .await
                .map_err(|e| format!("devnet failed to start: {e}"))?;
            devnet
                .start()
                .await
                .map_err(|e| format!("devnet failed to start: {e}"))?;
            Ok(RunningDevnet::Sepolia(Box::new(devnet)))
        }
    }
}

async fn export_and_wait(
    network: NetworkMode,
    devnet: &RunningDevnet,
    sigterm: &mut tokio::signal::unix::Signal,
    manifest_path: &Path,
    env_path: &Path,
    boot_secs: f64,
) -> Result<(), Box<dyn Error>> {
    devnet.write_manifest(manifest_path).await?;
    let rpc_url = write_env_file(network, devnet, env_path)?;

    // The READY line is the machine-readable "up" signal `local-up` tails
    // for; the manifest file appearing is the durable one it polls for.
    println!(
        "devnet-launcher: READY nodes={} boot_secs={:.1} rpc={} manifest={}",
        devnet.node_count(),
        boot_secs,
        rpc_url,
        manifest_path.display()
    );

    tokio::select! {
        _ = sigterm.recv() => println!("devnet-launcher: SIGTERM — shutting down"),
        result = tokio::signal::ctrl_c() => {
            result?;
            println!("devnet-launcher: SIGINT — shutting down");
        }
    }
    Ok(())
}

/// The flat, sourceable side of the export, for shell consumers (the JSON
/// manifest is the full-fidelity side). Returns the RPC URL, for the READY
/// line. The rendering itself is [`crate::export::EnvExport::render`] —
/// pure, and tested in the default-feature lane.
///
/// `ANTSEAL_DEVNET_CHAIN_ID` is the mode's chain id: Anvil's default 31337
/// locally (evmlib's `Testnet` starts Anvil without overriding it), 421614
/// in Sepolia mode. The boot-evidence procedure re-verifies it against
/// `eth_chainId` (runbook, Boot evidence).
fn write_env_file(
    network: NetworkMode,
    devnet: &RunningDevnet,
    env_path: &Path,
) -> Result<String, Box<dyn Error>> {
    let evm = devnet.evm_surface()?;

    let bootstrap = devnet.bootstrap_socket_addrs();
    if bootstrap.is_empty() {
        // An export with no reachable peer is not an export a consumer can
        // use — `DevnetEnv` rejects it too. Fail here, where the message can
        // name the devnet, rather than at whoever sources the file.
        return Err("devnet exported no bootstrap socket addresses".into());
    }

    let export = EnvExport {
        network,
        rpc_url: evm.rpc_url.clone(),
        token_address: evm.token_address,
        payment_vault_address: evm.payment_vault_address,
        wallet_private_key: evm.wallet_private_key,
        bootstrap,
        node_count: devnet.node_count(),
        base_port: devnet.base_port(),
        data_dir: devnet.data_dir(),
        pid: std::process::id(),
    };
    let text = export.render();

    // The wallet-key rule, enforced at the moment of writing rather than
    // trusted: ten keys locally, nine in Sepolia mode, and in Sepolia mode
    // nothing wallet-shaped at all. A release-active check, not a
    // debug_assert — this is the line between "no key on disk" and a real
    // Sepolia secret in a file.
    let expected_keys = if network.exports_wallet_key() {
        EnvExport::KEYS.len()
    } else {
        EnvExport::KEYS.len() - 1
    };
    let actual_keys = text.lines().filter(|line| line.contains('=')).count();
    if actual_keys != expected_keys {
        return Err(format!(
            "refusing to write the {network} environment export: it carries {actual_keys} keys, \
             not the {expected_keys} this mode defines"
        )
        .into());
    }
    if !network.exports_wallet_key() && text.contains("WALLET") {
        return Err(format!(
            "refusing to write the {network} environment export: it carries a wallet key, which \
             this mode must never write to a file"
        )
        .into());
    }

    std::fs::write(env_path, text)?;
    Ok(evm.rpc_url)
}

fn absolutize(path: &Path) -> Result<PathBuf, Box<dyn Error>> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(std::env::current_dir()?.join(path))
    }
}
