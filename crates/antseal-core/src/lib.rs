//! Pure logic for antseal. **WASM-safe by construction**: no I/O and no
//! `tokio` (nor any other async runtime, network, or filesystem crate) may
//! ever enter this crate's *normal* dependency graph — it must always compile
//! for `wasm32-unknown-unknown`. CI enforces both properties from the stub
//! stage (`.github/workflows/ci.yml`, lanes `wasm32-core` and
//! `core-dep-graph`).
//!
//! What will live here (MVP-SPEC.md, Architecture): canonicalization, crypto,
//! manifest + bundle formats, and FULL verification — including all anchor
//! verification: RFC 3161 `TimeStampResp`/`TSTInfo` parse + verify against a
//! pinned TSA root store, `.ots` parse + op execution + embedded-header
//! check, and deterministic Autonomi address recomputation — BLAKE3-256 of
//! the ciphertext bytes ([`storage`]; decisions D32/D35 record the deviation
//! from the spec's "via `self_encryption`" phrasing, which names a mechanism
//! ant-core 0.5.0's chunk-level storage model does not use). Verification
//! must succeed fully offline, and the WASM build must bit-match native
//! verification.

pub mod anchor;
pub mod builder;
pub mod bundle;
pub mod canon;
pub mod codec;
pub mod content;
pub mod crypto;
// Q52 — the frozen error-code universe (D30). A test-only module, and
// deliberately *inside* the crate rather than under `tests/`: five of the
// eight per-domain exemplar enumerators it collects from are `#[cfg(test)]
// pub(crate)`, and widening them to `pub` so an integration test could reach
// them would put a test-support surface into the crate's public API to buy
// nothing. Native-only — it reads a committed file.
#[cfg(all(test, not(target_arch = "wasm32")))]
mod error_universe;
pub mod format;
pub mod manifest;
pub mod storage;
// `test-util` implies `test-vectors` (see Cargo.toml), so gating the module
// on the smaller feature admits both surfaces; the proptest-bearing
// residents are gated inside.
#[cfg(feature = "test-vectors")]
pub mod test_util;
pub mod verify;

/// Crate version as compiled in (pre-M0 scaffold marker).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use core::sync::atomic::{AtomicU64, Ordering};

    /// Trivial stub test so `cargo test` exercises antseal-core from day one.
    #[test]
    fn version_matches_scaffold() {
        assert_eq!(super::VERSION, "0.0.0");
    }

    // ── wasm32 execution witness (P14) ──────────────────────────────────
    //
    // `wasm32-unknown-unknown` has no stdio: libtest's report is written to
    // a sink that discards it, so the ONLY signals the `wasm32-core-tests`
    // runner (`scripts/wasm-test-runner.mjs`) can observe are "`main`
    // returned 0" (all tests passed) and "the module trapped" (a test
    // failed — panics abort on this target). Neither distinguishes *all
    // tests passed* from *zero tests ran*, so the runner would be silently
    // vacuous if the test binary ever lost its tests.
    //
    // This witness closes that hole per run. The test below writes an
    // 8-byte pattern into a zero-initialised static, i.e. into WASM linear
    // memory; the runner scans the exported `memory` **before** calling
    // `main` (the pattern must be ABSENT — proving it is not a data-section
    // literal) and again **after** (it must be PRESENT — proving this test
    // body actually executed). See docs/wasm-toolchain.md.
    //
    // The pattern is assembled at run time from two `u32` halves precisely
    // so that the full 8-byte sequence exists nowhere in the module image:
    // constant-promotion of either half can only ever place 4 of the 8
    // bytes, so a pre-`main` hit is a real finding, never an artefact.

    /// Low half of the witness pattern (little-endian bytes `4D 41 57 30`).
    const WITNESS_LO: u32 = 0x3057_414D;
    /// High half of the witness pattern (little-endian bytes `4C 41 4E 31`).
    const WITNESS_HI: u32 = 0x314E_414C;

    /// Zero-initialised (`.bss`) — the pattern reaches linear memory only by
    /// executing [`wasm_lane_execution_witness`].
    static EXECUTION_WITNESS: AtomicU64 = AtomicU64::new(0);

    /// Writes the witness pattern the wasm32 test runner scans for.
    ///
    /// Runs on every target; only the wasm32 runner reads the result. On
    /// native targets it is an ordinary (trivially passing) unit test.
    #[test]
    fn wasm_lane_execution_witness() {
        let pattern = u64::from(WITNESS_LO) | (u64::from(WITNESS_HI) << 32);
        EXECUTION_WITNESS.store(pattern, Ordering::SeqCst);
        assert_eq!(EXECUTION_WITNESS.load(Ordering::SeqCst), pattern);
    }
}
