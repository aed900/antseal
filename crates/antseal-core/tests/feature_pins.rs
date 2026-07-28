//! C24/D88 — the guard that `sha2`'s `zeroize` feature cannot be dropped
//! silently.
//!
//! `docs/zeroization-audit.md` R1 is resolved by a **feature**, not by code:
//! `sha2 = { ..., features = ["zeroize"] }`. A future dependency edit that
//! drops that one word silently restores recoverable `W` and GGM-seed residue
//! in dropped hashers (measured before/after in
//! `tests/zeroization_residue.rs`). Nothing about the source tree changes when
//! it happens, so nothing about the source tree can be trusted to notice.
//!
//! # Three layers, because no single one is sufficient
//!
//! D88 §7 states the property has "**no** compile-time detector". That is too
//! strong — one exists (layer 1, in `tests/digest_zeroize_link.rs`), but it
//! is only *half* a detector, and the half it misses is the half
//! `crypto.rs::zeroization_sweep` also misses:
//!
//! 1. **Compile-time** — `tests/digest_zeroize_link.rs`. `digest` re-exports
//!    the `zeroize` crate under `#[cfg(feature = "zeroize")]` and `sha2`
//!    re-exports `digest`, so naming `sha2::digest::zeroize` does not compile
//!    unless `digest/zeroize` is on. That covers `BlockBuffer`'s `Drop` — the
//!    buffer holding `W` verbatim and the GGM parent seed.
//!
//!    **What it cannot see:** `digest/zeroize` is also forwarded by
//!    `hmac/zeroize`. If a future edit dropped `sha2`'s feature while
//!    something else kept `digest/zeroize` alive, that check would still pass
//!    while `Sha256VarCore`'s own `Drop` — the SHA-256 **chaining state** —
//!    silently stopped being compiled. Necessary, not sufficient.
//!
//! 2. **Declaration** — this file. Assert the workspace pin itself still says
//!    what it must. This is the layer that catches exactly the case layer 1
//!    misses, and its failure message names the consequence and the fix.
//!
//!    It lives in a **separate test binary from layer 1 on purpose**: layer 1
//!    fails as `error[E0432]: unresolved import`, which would abort
//!    compilation of anything sharing its target and bury this file's
//!    explanation under a compiler error that says nothing about `W`.
//!
//! 3. **Behaviour** — `tests/zeroization_residue.rs`. The only layer that
//!    proves bytes are actually wiped rather than that a feature is nominally
//!    enabled, and the only one that would survive an upstream change of
//!    mechanism. It deliberately does **not** import `sha2::digest::zeroize`,
//!    so that dropping the feature makes it go *red with residue counts*
//!    rather than fail to build.
//!
//! Native only: this file reads the workspace manifest from disk, and
//! `wasm32-unknown-unknown` has no filesystem (P14, `docs/wasm-toolchain.md`).

#![cfg(not(target_arch = "wasm32"))]

use std::fs;
use std::path::PathBuf;

/// The workspace root manifest — the single version-declaration point
/// (`docs/dependency-policy.md` §2).
fn workspace_manifest() -> String {
    let path: PathBuf = [env!("CARGO_MANIFEST_DIR"), "..", "..", "Cargo.toml"]
        .iter()
        .collect();
    fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read the workspace manifest {}: {e}", path.display()))
}

/// The single `sha2 = ...` declaration line from `[workspace.dependencies]`.
fn sha2_pin_line(manifest: &str) -> &str {
    let mut lines = manifest
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("sha2 ="));
    let line = lines
        .next()
        .expect("no `sha2 = ...` line in the workspace manifest — has the pin been renamed?");
    assert!(
        lines.next().is_none(),
        "more than one `sha2 = ...` line in the workspace manifest; \
         the exact-pin class requires a single declaration point \
         (docs/dependency-policy.md §2)"
    );
    line
}

/// Layer 2 — declaration. The workspace pin still enables `zeroize`, still
/// pins the exact version, and still disables default features.
///
/// This is the layer that catches `sha2`'s own feature being dropped while
/// some other crate keeps `digest/zeroize` alive — the case layer 1 is blind
/// to, and the case in which `Sha256VarCore`'s chaining-state `Drop` silently
/// stops being compiled.
#[test]
fn sha2_pin_declares_the_zeroize_feature() {
    let manifest = workspace_manifest();
    let line = sha2_pin_line(&manifest);

    assert!(
        line.contains("\"zeroize\""),
        "the sha2 workspace pin no longer enables the `zeroize` feature.\n\
         found: {line}\n\
         expected: sha2 = {{ version = \"=0.11.0\", default-features = false, \
         features = [\"zeroize\"] }}\n\n\
         This is not a style nit. Without that feature a dropped Hkdf<Sha256> \
         leaves 114 of 144 bytes of PRK-keyed HMAC state readable, the HKDF \
         extract context leaves the master secret W recoverable VERBATIM, and \
         every content::ggm::child_seed call strands its parent GGM seed in a \
         dropped hasher — a live contradiction of MVP-SPEC.md line 143.\n\
         See docs/decisions/D88-hkdf-hmac-zeroization.md and \
         docs/zeroization-audit.md R1. Removing it is a version bump under \
         docs/dependency-policy.md §4, never a drive-by."
    );
    assert!(
        line.contains("\"=0.11.0\""),
        "the sha2 pin is no longer exactly =0.11.0 — every residue and cost \
         number in D88 was measured against that version.\nfound: {line}"
    );
    assert!(
        line.contains("default-features = false"),
        "the sha2 pin no longer disables default features; `alloc`/`oid` \
         would re-enter the wasm32 surface.\nfound: {line}"
    );
}

/// `hmac`'s own `zeroize` feature stays **off**, per D88 §4.
///
/// It adds nothing once `sha2/zeroize` is on (measured: identical residue
/// with and without it), and an inert feature is a maintenance claim that has
/// to be re-defended at every bump. If a future edit turns it on, that should
/// be a decision with a reason, not drift — this test is where the reason
/// gets written down.
#[test]
fn hmac_pin_does_not_enable_zeroize() {
    let manifest = workspace_manifest();
    let line = manifest
        .lines()
        .map(str::trim)
        .find(|line| line.starts_with("hmac ="))
        .expect("no `hmac = ...` line in the workspace manifest");

    assert!(
        !line.contains("zeroize"),
        "the hmac pin now enables `zeroize`. D88 §2 measured that it adds \
         nothing once sha2/zeroize is on. If this is deliberate, amend D88 \
         and this test together.\nfound: {line}"
    );
}
