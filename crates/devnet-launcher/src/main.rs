//! devnet-launcher — the P16 local devnet environment.
//!
//! Boots a local Autonomi devnet: Anvil as a subprocess (fresh chain, both
//! payment contracts deployed per run, supply premined to Anvil dev account
//! 0) plus N in-process node tasks (LMDB stores, per-node ML-DSA identity —
//! no docker, no `antnode` binary). Exports the environment surface as a
//! machine-readable manifest + flat env file under the repo-local, gitignored
//! `.devnet/` directory, then stays alive until SIGTERM/SIGINT — dropping the
//! embedded `Testnet` kills Anvil, so the process IS the devnet's lifetime.
//!
//! Run through `scripts/devnet/local-up` (release build, `devnet` feature).
//! The runbook is `docs/devnet/local-devnet.md`; the feasibility evidence is
//! `docs/research/P16-devnet-feasibility.md`.

#[cfg(feature = "devnet")]
mod devnet;

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
