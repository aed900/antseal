//! Arbitrum receipt confirmation — advisory supporting evidence, never an
//! anchor (task **A17**; decisions D33, D55).
//!
//! The boundary D33 drew: `antseal-net::pay()` **captures** the receipt (the
//! block number is a field of the very transaction receipt `pay()` must await
//! anyway, over the payment RPC), and this module only **re-confirms** it at
//! verify time, over a separate pair of endpoints, as advisory overlay data.
//! Nothing here captures or backfills a receipt field.

pub mod confirm;
pub mod endpoints;

pub use confirm::{ArbitrumConfirmation, confirm_arbitrum_tx, project};
pub use endpoints::{
    ARBITRUM_ONE_RESERVE_RPCS_CLI_ONLY, ARBITRUM_ONE_VERIFY_RPCS, ARBITRUM_SEPOLIA_VERIFY_RPCS,
    expected_chain_id, verify_rpcs,
};
