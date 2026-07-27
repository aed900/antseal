//! Native execution of the C11 probe suite.
//!
//! `selfcheck()` carries every behavioral invariant as one bitmask so that
//! the native run and the wasm run (run-wasm.mjs) assert the identical set.
//! On failure, the per-bit breakdown below names the failing probe.

use sig_probe::{EXPECTED_SELFCHECK, selfcheck};

const BIT_NAMES: [&str; 27] = [
    "mldsa: verify_with_context(ctx) ok",
    "mldsa: wrong ctx rejected",
    "mldsa: empty ctx rejected",
    "mldsa: sign_deterministic is deterministic",
    "mldsa: decode rejects duplicate hint indices (CVE-2026-24850 guard)",
    "mldsa: decode rejects hint count > omega",
    "mldsa: decode rejects nonzero hint padding",
    "mldsa: decode rejects decreasing hint cuts",
    "mldsa: decode rejects z coefficient at gamma1 (norm bound)",
    "mldsa: c_tilde bitflip decodes but fails verify (layering)",
    "fips204: verify(ctx) ok",
    "fips204: wrong ctx rejected",
    "fips204: pk bytes == ml-dsa pk bytes (cross-impl KeyGen)",
    "fips204: sig bytes == ml-dsa sig bytes (cross-impl deterministic sign)",
    "fips204: duplicate hint indices rejected (folded into verify=false)",
    "dalek2: verify_strict ok",
    "dalek2: S+L maul parses but verify AND verify_strict reject",
    "dalek2: small-order R rejected by verify_strict",
    "dalek2: small-order A parses (ZIP-215), is_weak, verify_strict rejects",
    "dalek2: non-canonical A (y=p) ACCEPTED at parse (documented gap)",
    "dalek3: verify_strict ok",
    "dalek3: S+L maul parses but verify AND verify_strict reject",
    "dalek3: small-order R rejected by verify_strict",
    "dalek3: small-order A parses (ZIP-215), is_weak, verify_strict rejects",
    "dalek3: non-canonical A (y=p) ACCEPTED at parse (documented gap)",
    "cross-version: dalek2 sig bytes == dalek3 sig bytes",
    "cross-version: dalek2 pk == dalek3 pk",
];

#[test]
fn all_probe_invariants_hold() {
    let bits = selfcheck();
    if bits != EXPECTED_SELFCHECK {
        let mut failed = Vec::new();
        for (i, name) in BIT_NAMES.iter().enumerate() {
            if bits & (1 << i) == 0 {
                failed.push(format!("bit {i}: {name}"));
            }
        }
        panic!(
            "selfcheck = {bits:#010x}, expected {EXPECTED_SELFCHECK:#010x}; failed probes:\n  {}",
            failed.join("\n  ")
        );
    }
}
