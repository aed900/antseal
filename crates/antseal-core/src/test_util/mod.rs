//! Shared test infrastructure (Q2/Q3/Q4/Q5).
//!
//! # Two feature tiers (P14)
//!
//! - **`test-vectors`** — the WASM-safe subset: [`vectors`],
//!   [`TEST_MASTER_SECRET_W`], the deterministic [`fixture_rng`], and R6's
//!   [`bundle_fixtures`] constructor. I/O-free, allocation-only, activates
//!   **zero** optional dependencies, and therefore compiles for
//!   `wasm32-unknown-unknown` and leaves the `core-dep-graph` lane's verdict
//!   untouched. This is what the Q5 native↔WASM bit-match harness enables,
//!   and what the `wasm32-core-tests` lane's dev-dependency edge turns on.
//! - **`test-util`** — `test-vectors` plus the proptest-bearing residents
//!   ([`strategies`], [`tamper`]) and the `proptest` re-export, together
//!   with the harness slices built on them ([`tamper_rows_crypto`],
//!   [`tamper_rows_structural`]). Native test targets only.
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
//! - [`tamper_rows_crypto`] — C's own registry slice for that harness
//!   (C17): the M0 crypto tamper rows, plus the mutation helpers R7's
//!   bundle-level fixtures reuse.
//! - [`tamper_rows_fine_tree`] — G's registry slice (G19): the two
//!   fine-tree rows (`fine-root-binding-failed`,
//!   `fine-root-over-broad-cover`), plus the **single** over-broad-cover
//!   construction helper the R lane consumes rather than duplicating.
//! - [`tamper_rows_structural`] — R's registry slice (R7): the M0
//!   structural rows, mutated from [`bundle_fixtures`] works and driven
//!   through `verify_bundle` wherever the mutation is reachable there.
//! - [`bundle_fixtures`] — R6's seeded, deterministic constructor for valid
//!   works and `.sealproof` bundles of every M0 shape. The substrate R7–R10
//!   mutate and R9's golden vectors pin; the M3 production builder (R13)
//!   absorbs it under a parity test.
//! - [`fixture_rng`] — the deterministic fixture randomness source, for the
//!   APIs (unit AEAD) that draw their own nonces by design.
//! - [`vectors`] — the golden-vector envelope schema, validation, kind
//!   dispatch, and execution (schema doc: `testdata/vectors/README.md`).
//!   Deliberately WASM-safe (parses/executes **bytes**; zero I/O) so the
//!   Q5 native↔WASM bit-match lane reuses the identical execution path —
//!   only file discovery lives in the native runner test.
//! - [`vectors_cbor_diag`] — the **diagnostic sidecar** renderer the
//!   `manifest` and `bundle` kinds share (F12): one canonical CBOR item,
//!   rendered structurally as JSON. It is the artifact F14's independent
//!   CBOR implementation compares against, so its rendering rules are a
//!   contract, not an implementation detail.
//! - [`vectors_manifest`] — the `manifest` vector kind (F12): the committed
//!   manifest bytes, their two-layer diagnostic sidecars, and the
//!   `work_id`/`anchor_digest` each hashes to — which is also where F7's
//!   deferred committed-digest artifact lands.
//! - [`vectors_bundle`] — the `bundle` vector kind (F13): the committed
//!   `.sealproof` bytes, their **three**-layer diagnostic sidecars and the
//!   reveal structure each discloses — including the empty-anchor
//!   (UNANCHORED) bundle, a named M0 milestone artifact.
//! - [`vectors_fine_tree`] — the `fine-tree` vector kind (G15): the
//!   fine-tree/GGM golden vectors, whose reason for existing is to pin
//!   **MSB-first** GGM leaf indexing at the unbalanced `n = 6` case
//!   (MVP-SPEC.md lines 96, 169), and the regenerator
//!   `tests/fine_tree_vectors.rs` diffs the committed document against.
//! - [`vectors_report`] — the `report` vector kind (R9): canonical bundles
//!   mapped to the **expected serialized `VerificationReport`** for every M0
//!   shape (MVP-SPEC.md lines 153, 167, 169), byte-pinned in the D29
//!   encoding. Its cases name R6 [`bundle_fixtures::shapes`] handles, which
//!   both lanes build in-process — that is what makes the native↔WASM
//!   bit-match over report bytes possible at all. Regenerator:
//!   `tests/report_vectors.rs`.
//! - [`vectors_sig_reject`] — the `sig-reject` vector kind (C15): the
//!   committed per-algorithm signature reject-vector suites and their
//!   executor, which routes every case through C14's full verification
//!   path.
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

pub mod bundle_fixtures;
pub mod fixture_rng;
#[cfg(feature = "test-util")]
pub mod strategies;
#[cfg(feature = "test-util")]
pub mod tamper;
#[cfg(feature = "test-util")]
pub mod tamper_rows_crypto;
#[cfg(feature = "test-util")]
pub mod tamper_rows_fine_tree;
#[cfg(feature = "test-util")]
pub mod tamper_rows_structural;
pub mod vectors;
pub mod vectors_bundle;
pub mod vectors_cbor_diag;
pub mod vectors_fine_tree;
pub mod vectors_manifest;
pub mod vectors_report;
pub mod vectors_sig_reject;

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

/// A **second** fixture secret, deliberately different from
/// [`TEST_MASTER_SECRET_W`] yet still derived from it:
///
/// ```text
/// W' = SHA-256(label ‖ TEST_MASTER_SECRET_W)
/// ```
///
/// Wrong-key evidence — a signature by another author, a unit encrypted
/// under another `W` — needs a secret that is genuinely *not* the fixture
/// one. Inventing a fresh 32-byte literal would breach the secret-material
/// convention's "every fixture secret is the documented seed or
/// deterministically derived from it" (`testdata/README.md`); deriving one
/// per `label` keeps the provenance obvious, keeps distinct uses from
/// colliding, and stays reproducible by any implementation reading this
/// formula.
///
/// The label is a domain separator, not a secret: it appears verbatim in
/// test source and in fixture READMEs.
#[must_use]
pub fn alternate_test_secret(label: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(label);
    hasher.update(TEST_MASTER_SECRET_W);
    hasher.finalize().into()
}
