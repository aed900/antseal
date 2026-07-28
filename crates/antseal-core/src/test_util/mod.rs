//! Shared test infrastructure (Q2/Q3/Q4/Q5).
//!
//! # Two feature tiers (P14)
//!
//! - **`test-vectors`** — the WASM-safe subset: [`vectors`] and
//!   [`TEST_MASTER_SECRET_W`]. I/O-free, allocation-only, activates **zero**
//!   optional dependencies, and therefore compiles for
//!   `wasm32-unknown-unknown` and leaves the `core-dep-graph` lane's verdict
//!   untouched. This is what the Q5 native↔WASM bit-match harness enables.
//! - **`test-util`** — `test-vectors` plus the proptest-bearing residents
//!   ([`strategies`], [`tamper`]) and the `proptest` re-export. Native
//!   test targets only.
//!
//! Residents:
//!
//! - [`strategies`] — the shared proptest strategies and the deterministic
//!   [`proptest` config builder](strategies::proptest_config) every
//!   component domain (F/C/G/S/A/R) uses instead of redefining its own
//!   (conventions: `docs/testing/proptest-conventions.md`).
//! - [`tamper`] — the tamper-matrix harness (Q7): row model, the
//!   distinct-outcome and no-panic assertions, and the row-addition
//!   procedure every domain (F15/C17/G19/A21/R7) registers rows through.
//!   Error-code contract: `docs/testing/error-code-contract.md`.
//! - [`vectors`] — the golden-vector envelope schema, validation, kind
//!   dispatch, and execution (schema doc: `testdata/vectors/README.md`).
//!   Deliberately WASM-safe (parses/executes **bytes**; zero I/O) so the
//!   Q5 native↔WASM bit-match lane reuses the identical execution path —
//!   only file discovery lives in the native runner test.
//!
//! # Consuming this module
//!
//! ```toml
//! [dev-dependencies]
//! antseal-core = { workspace = true, features = ["test-util"] }
//! ```
//!
//! A consumer that only needs the WASM-safe subset (the Q5 bit-match
//! harness) asks for `features = ["test-vectors"]` instead — the only
//! feature of this crate a *normal* dependency edge may enable.
//!
//! **Never** enable `test-util` from a normal dependency edge: it activates
//! test-only dependencies (proptest) that are neither WASM-safe nor part of
//! the audited normal dependency graph. proptest itself is re-exported
//! below — consumers write
//! `use antseal_core::test_util::proptest::prelude::*;` and never declare
//! their own proptest, so exactly one lockfile-frozen version serves the
//! whole workspace.

#[cfg(feature = "test-util")]
pub mod strategies;
#[cfg(feature = "test-util")]
pub mod tamper;
pub mod vectors;

/// The one pinned proptest the whole workspace tests with (Q3): component
/// crates use this re-export instead of declaring the dependency, so the
/// version cannot skew between domains.
#[cfg(feature = "test-util")]
pub use proptest;

/// The **documented fixed test seed** of the secret-material convention
/// (`testdata/README.md`; project rule 6): the NON-SECRET byte pattern
/// `0x00 0x01 … 0x1f` standing in for a master secret `W` wherever
/// committed fixtures need one. Every committed fixture secret is this
/// value or is deterministically derived from it — never real vault or
/// wallet material. The golden-vector executor enforces it
/// ([`vectors`], kind `hkdf-labels`).
pub const TEST_MASTER_SECRET_W: [u8; 32] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
];
