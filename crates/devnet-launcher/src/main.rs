//! devnet-launcher — the P16 local devnet environment, and (P22) the P17
//! Arbitrum-Sepolia one.
//!
//! `--network local` (the default): boots a local Autonomi devnet — Anvil as
//! a subprocess (fresh chain, both payment contracts deployed per run, supply
//! premined to Anvil dev account 0) plus N in-process node tasks (LMDB
//! stores, per-node ML-DSA identity — no docker, no `antnode` binary).
//!
//! `--network arbitrum-sepolia` (P22): the same N in-process nodes, but
//! verifying payments against **the real deployed Arbitrum Sepolia
//! contracts** on chain 421614. No Anvil, no per-run deploy, and no wallet
//! in the export — a Sepolia key is a real secret and never reaches a file.
//!
//! Either way the environment surface is exported as a machine-readable
//! manifest + flat env file under the repo-local, gitignored `.devnet/`
//! directory, and the process then stays alive until SIGTERM/SIGINT — so the
//! process IS the devnet's lifetime (in local mode, dropping the embedded
//! `Testnet` kills Anvil too).
//!
//! Run through `scripts/devnet/local-up` or `scripts/devnet/sepolia-up`
//! (release build, `devnet` feature). The runbooks are
//! `docs/devnet/local-devnet.md` and `docs/devnet/sepolia-devnet.md`; the
//! feasibility evidence is `docs/research/P16-devnet-feasibility.md`.

#[cfg(feature = "devnet")]
mod devnet;

/// The export rendering and the `--network` value type.
///
/// Feature-independent on purpose (see the module docs): it exists so the
/// cheap default `cargo test -p devnet-launcher` lane can police the export
/// format without building the 736-package ant-node graph. In a default
/// build nothing *calls* it — only its own tests do — so the unused-code
/// lint would otherwise fire on the module whose whole point is being
/// testable there.
#[cfg_attr(not(feature = "devnet"), allow(dead_code))]
mod export;

#[cfg(feature = "devnet")]
fn main() -> std::process::ExitCode {
    devnet::run()
}

/// The featureless stub: default `--workspace` builds compile exactly this,
/// and none of the ant-node graph. Exit 2 mirrors the CLI's usage-error
/// class so a script mistake (running the default-feature binary) is loud
/// and distinct.
#[cfg(not(feature = "devnet"))]
fn main() -> std::process::ExitCode {
    eprintln!(
        "devnet-launcher was built WITHOUT the `devnet` feature; the \
         ant-core/ant-node graph is not compiled into this binary."
    );
    eprintln!("Use scripts/devnet/local-up, or directly:");
    eprintln!("    cargo run --release -p devnet-launcher --features devnet");
    std::process::ExitCode::from(2)
}
