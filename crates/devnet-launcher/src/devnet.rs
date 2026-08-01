//! The `devnet`-feature implementation: drive `ant_core::data::LocalDevnet`
//! (pinned `=0.5.0`) with our own `DevnetConfig` instead of running the
//! upstream `start-local-devnet` example verbatim.
//!
//! Why not the example (P16 memo §6): it hardcodes `DevnetConfig::default()`
//! — 25 nodes, the flake zone on this 2-core host — and writes the manifest
//! (which embeds the funded Anvil dev key) into the SHARED
//! `~/.local/share/ant/`, coupling us to any other ant tooling on the
//! machine. We run 14 nodes by default (upstream's own e2e parity count),
//! keep every artifact under a repo-local gitignored directory, and handle
//! SIGTERM so `scripts/devnet/local-down` gets a clean, residue-free stop.
//!
//! Lifetime model: `LocalDevnet` holds the `Testnet` (Anvil child process) —
//! dropping it kills Anvil, and the nodes are tokio tasks of THIS process.
//! So the launcher process is the devnet: `local-down` = SIGTERM this pid
//! (from the pidfile we write), nothing else to hunt down.

use std::error::Error;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use ant_core::data::LocalDevnet;
use ant_node::devnet::DevnetConfig;

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
            eprintln!("usage: devnet-launcher [--nodes N] [--dir PATH]");
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

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--nodes" | "-n" => {
                let value = args.next().ok_or("--nodes needs a value")?;
                nodes = value
                    .parse::<usize>()
                    .map_err(|_| format!("--nodes: not a number: {value}"))?;
            }
            "--dir" => dir = PathBuf::from(args.next().ok_or("--dir needs a value")?),
            "--help" | "-h" => {
                return Err("boots the P16 local devnet; see docs/devnet/local-devnet.md".into());
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
        nodes,
        dir,
        stabilization_secs: env_parse("ANTSEAL_DEVNET_STABILIZATION_SECS")?.map(|s: u64| s),
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
fn build_config(options: &Options, data_dir: PathBuf) -> DevnetConfig {
    let mut config = match options.nodes {
        n if n == 5 => DevnetConfig::minimal(),
        n if n == 10 => DevnetConfig::small(),
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
    config
}

/// `Testnet::new` spawns `anvil` via alloy's node bindings with no explicit
/// path — it MUST be on `PATH`. Check up front so the failure names the fix
/// instead of surfacing as an opaque spawn error two layers down.
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
/// contract `local-up`/`local-down` manage). A dead pid is a stale file from
/// a SIGKILL; say so and continue.
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

    assert_anvil_on_path()?;

    let dir = absolutize(&options.dir)?;
    std::fs::create_dir_all(&dir)?;
    let pidfile = dir.join("launcher.pid");
    let manifest_path = dir.join("manifest.json");
    let env_path = dir.join("env");
    check_pidfile(&pidfile)?;
    std::fs::write(&pidfile, format!("{}\n", std::process::id()))?;

    let config = build_config(&options, dir.join("data"));
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

    let result = runtime.block_on(run_devnet(&manifest_path, &env_path, config));

    // Whatever happened, the exported surface must not outlive the devnet:
    // a stale manifest/env pointing at dead ports is exactly the kind of
    // residue `local-down` promises not to leave.
    for stale in [&manifest_path, &env_path, &pidfile] {
        let _ = std::fs::remove_file(stale);
    }
    result
}

async fn run_devnet(
    manifest_path: &Path,
    env_path: &Path,
    config: DevnetConfig,
) -> Result<(), Box<dyn Error>> {
    let boot_started = Instant::now();
    let mut devnet = LocalDevnet::start(config)
        .await
        .map_err(|e| format!("devnet failed to start: {e}"))?;
    let boot_secs = boot_started.elapsed().as_secs_f64();

    let outcome = export_and_wait(&devnet, manifest_path, env_path, boot_secs).await;

    // Shutdown runs on BOTH paths — the export failing must still stop the
    // nodes and let `cleanup_data_dir` remove the stores.
    let shutdown = devnet
        .shutdown()
        .await
        .map_err(|e| format!("devnet shutdown failed: {e}"));
    println!("devnet-launcher: STOPPED");
    outcome.and(shutdown.map_err(Into::into))
}

async fn export_and_wait(
    devnet: &LocalDevnet,
    manifest_path: &Path,
    env_path: &Path,
    boot_secs: f64,
) -> Result<(), Box<dyn Error>> {
    devnet
        .write_manifest(manifest_path)
        .await
        .map_err(|e| format!("manifest write failed: {e}"))?;
    write_env_file(devnet, env_path)?;

    // The READY line is the machine-readable "up" signal `local-up` tails
    // for; the manifest file appearing is the durable one it polls for.
    println!(
        "devnet-launcher: READY nodes={} boot_secs={:.1} rpc={} manifest={}",
        devnet.manifest().node_count,
        boot_secs,
        devnet
            .manifest()
            .evm
            .as_ref()
            .map_or("<none>", |evm| evm.rpc_url.as_str()),
        manifest_path.display()
    );

    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
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
/// manifest is the full-fidelity side). Values are single-quoted; nothing a
/// devnet produces can contain a single quote (ports, hex, local paths).
///
/// `ANTSEAL_DEVNET_CHAIN_ID` is Anvil's default chain id 31337 — evmlib's
/// `Testnet` starts Anvil without overriding it. The boot-evidence procedure
/// re-verifies it against `eth_chainId` (runbook, Boot evidence).
fn write_env_file(devnet: &LocalDevnet, env_path: &Path) -> Result<(), Box<dyn Error>> {
    let manifest = devnet.manifest();
    let evm = manifest
        .evm
        .as_ref()
        .ok_or("LocalDevnet manifest unexpectedly carries no EVM section")?;
    let bootstrap = devnet
        .bootstrap_addrs()
        .iter()
        .map(std::string::ToString::to_string)
        .collect::<Vec<_>>()
        .join(",");

    let mut env = String::new();
    let mut push = |key: &str, value: &str| {
        env.push_str(key);
        env.push_str("='");
        env.push_str(value);
        env.push_str("'\n");
    };
    push("ANTSEAL_DEVNET_RPC_URL", &evm.rpc_url);
    push("ANTSEAL_DEVNET_CHAIN_ID", "31337");
    push("ANTSEAL_DEVNET_TOKEN_ADDRESS", &evm.payment_token_address);
    push(
        "ANTSEAL_DEVNET_PAYMENT_VAULT_ADDRESS",
        &evm.payment_vault_address,
    );
    // The funded wallet: Anvil dev account 0 — the token deployer, holding
    // the entire premined supply. A WELL-KNOWN PUBLIC CONSTANT, never a
    // secret; it still lives only under the gitignored `.devnet/`.
    push("ANTSEAL_DEVNET_WALLET_PRIVATE_KEY", &evm.wallet_private_key);
    push("ANTSEAL_DEVNET_BOOTSTRAP", &bootstrap);
    push(
        "ANTSEAL_DEVNET_NODE_COUNT",
        &manifest.node_count.to_string(),
    );
    push("ANTSEAL_DEVNET_BASE_PORT", &manifest.base_port.to_string());
    push(
        "ANTSEAL_DEVNET_DATA_DIR",
        &manifest.data_dir.display().to_string(),
    );
    push("ANTSEAL_DEVNET_PID", &std::process::id().to_string());

    std::fs::write(env_path, env)?;
    Ok(())
}

fn absolutize(path: &Path) -> Result<PathBuf, Box<dyn Error>> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(std::env::current_dir()?.join(path))
    }
}
