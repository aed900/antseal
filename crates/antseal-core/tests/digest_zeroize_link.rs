//! C24/D88, layer 1 — the **compile-time** half of the `sha2/zeroize` guard.
//!
//! # If you are here because of `error[E0432]: unresolved import`
//!
//! Someone removed the `zeroize` feature from the `sha2` pin in the workspace
//! `Cargo.toml`. Put it back:
//!
//! ```toml
//! sha2 = { version = "=0.11.0", default-features = false, features = ["zeroize"] }
//! ```
//!
//! That feature is not cosmetic. Measured on this exact pin
//! (`tests/zeroization_residue.rs`), without it:
//!
//! - a dropped `Hkdf<Sha256>` leaves **114 of 144 bytes** of PRK-keyed HMAC
//!   state readable — `W`-equivalent for that work: every unit key, every
//!   salt, the fine seed and both signing seeds;
//! - the HKDF extract context leaves the master secret **`W` recoverable
//!   verbatim** from its uncompressed block buffer;
//! - every `content::ggm::child_seed` call strands its **parent GGM seed** in
//!   a dropped hasher, and a leaked ancestor seed opens leaves a reveal
//!   deliberately withheld.
//!
//! That is a live contradiction of MVP-SPEC.md line 143. Removing the feature
//! is a version bump under `docs/dependency-policy.md` §4, never a drive-by.
//! Records: `docs/decisions/D88-hkdf-hmac-zeroization.md`,
//! `docs/zeroization-audit.md` R1.
//!
//! # Why this is its own test binary
//!
//! The import below *is* the assertion, so losing the feature is a build
//! failure rather than a test failure. That is the loudest possible signal
//! and the cheapest possible check — but a compile error aborts every test in
//! the same target, which would bury the explanatory runtime assertions in
//! `tests/feature_pins.rs` and the residue measurements in
//! `tests/zeroization_residue.rs` under a compiler message that never
//! mentions `W`. Keeping this on its own leaves those two able to run and
//! report.
//!
//! # What it does and does not prove
//!
//! `digest` re-exports the `zeroize` crate under `#[cfg(feature = "zeroize")]`
//! and `sha2` re-exports `digest`, so this import resolves only when
//! `digest/zeroize` is active — which `sha2/zeroize` forwards, and which in
//! turn forwards `block-buffer/zeroize`. So a green build here proves
//! **`BlockBuffer` has its wiping `Drop`**: the buffer that holds `W` and the
//! GGM parent seed.
//!
//! It does **not** prove `sha2`'s own feature is on. `hmac/zeroize` forwards
//! `digest/zeroize` too, so a future edit could satisfy this file while
//! `Sha256VarCore`'s `Drop` — the SHA-256 **chaining state** — stopped being
//! compiled. `feature_pins.rs` (declaration) and `zeroization_residue.rs`
//! (behaviour) close that gap. Three layers, none redundant.

#![cfg(not(target_arch = "wasm32"))]

use sha2::digest::zeroize::Zeroize;

/// The import above is the real assertion. This exercises it so the item is
/// unambiguously *used*, and confirms the re-exported trait is the working
/// one rather than an empty stub.
#[test]
fn digest_reexports_a_working_zeroize() {
    let mut witness = [0xAAu8; 8];
    witness.zeroize();
    assert_eq!(
        witness, [0u8; 8],
        "digest's re-exported Zeroize must actually wipe — if this ever fails, \
         the guard above has become decorative"
    );
}
