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
//! check, and deterministic Autonomi address recomputation via
//! `self_encryption`. Verification must succeed fully offline, and the WASM
//! build must bit-match native verification.

pub mod canon;

/// Crate version as compiled in (pre-M0 scaffold marker).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    /// Trivial stub test so `cargo test` exercises antseal-core from day one.
    #[test]
    fn version_matches_scaffold() {
        assert_eq!(super::VERSION, "0.0.0");
    }
}
