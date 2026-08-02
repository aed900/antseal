//! The CLI's storage-backend construction seam.
//!
//! Every network-touching command (`seal`, `restore`, `status --upgrade`,
//! `verify --live`) needs the same three things assembled in the same
//! order: U4's resolved [`NetworkConfig`], U10's vault-held wallet key,
//! and an async runtime to drive S6's `AntCoreBackend` on. That assembly
//! is one job with one right answer, so it lives here rather than being
//! re-derived per command.
//!
//! # Status: declared, not yet built (U36)
//!
//! The pieces exist in three places and have never been joined:
//!
//! - S6's `AntCoreBackend::connect(&NetworkConfig, &WalletKey)` is behind
//!   the non-default `ant-backend` feature (S22's gate policy), so a
//!   default build has no production backend compiled in at all;
//! - it is an `async fn` over ant-core's tokio-driven client, and
//!   `antseal-cli` deliberately declares no async runtime — the
//!   dependency lane checks that the *normal* graph stays free of
//!   async/network crates;
//! - the wallet handle is U10's, and D37's per-sub-batch capture hook
//!   **must** be installed on the constructed backend or a crash in the
//!   post-pay window costs a second payment (S16 asserts both
//!   directions; S27 records that nothing forces it yet).
//!
//! Joining them is a dependency-policy event (an optional runtime),
//! a feature-gating decision, and the hook obligation from S27 — all of
//! which belong to U13/S17's construction path, which needs this exact
//! function for `seal`. **U36** records it. Until it lands, every command
//! that reaches this seam refuses with a specific, actionable message
//! rather than pretending the network is merely down.
//!
//! What is *not* blocked on it: `restore`'s whole policy half runs over
//! any [`StorageBackend`](antseal_net::StorageBackend) —
//! [`crate::restore_out::run_restore`] is generic and is driven end to end
//! in the test suites, which is also how D34 says the M1 E2E drives the
//! pipeline (library APIs, never a spawned binary).
//!
//! [`NetworkConfig`]: antseal_net::NetworkConfig

use crate::error::CliError;

/// The refusal a command gets when it needs the network and this build
/// cannot reach it.
///
/// Deliberately **not** the not-implemented class: the command itself is
/// implemented, and saying otherwise would send a user looking for a
/// milestone that has already arrived. It is reported in the transient
/// network class (D48 §6's floor), because from the caller's side that is
/// what it is — no bytes can be fetched — and the message names the
/// actual cause instead of implying an outage.
#[must_use]
pub(crate) fn unavailable(command: &str) -> CliError {
    CliError::NetworkFailure {
        detail: format!(
            "`{command}` needs a live Autonomi connection, and this build has no storage backend \
             compiled in (the `ant-backend` feature is off by default). The command itself is \
             complete — its network seam is wired together with `seal` (U13/S17, tracked as U36)"
        ),
    }
}
