# D13 — `ed25519-dalek` pin: 3.0.0 over the 2.x line

- **Status: RESOLVED** (recommended by the C11 probe; accepted at wave-2
  integration review — evidence is probe-executed and source-diffed)
- **Date: 2026-07-27**

## Context

The hybrid author signature's Ed25519 half (MVP-SPEC.md line 97) requires
RFC 8032 `verify_strict` semantics — reject non-canonical `S ≥ L`, reject
small-order/non-canonical `R`/`A` — as a conformance requirement for every
verifier, and the crate sits permanently in the frozen verifier trust
base. The spec left "2.x vs the three-week-old 3.0.0" to an M0 decision
(tasks P11/C11). Execution-time facts (crates.io, 2026-07-27): newest 2.x
is **2.2.0** (2025-07-09); **3.0.0** published 2026-07-06 after a
year-long pre/rc series (3.0.0-pre.0 on 2025-07-09; rc.1 2026-06-18).

## Evidence

C11 probe (`probes/sig-probe/`, both versions in one graph via package
rename; full report:
[docs/research/C11-signature-probe.md](../research/C11-signature-probe.md) §4-5):

- **Strict-verification semantics are identical** in both versions,
  source-diffed and probe-executed: `S ≥ L` rejected in every verify path
  via `Scalar::from_canonical_bytes` (src/signature.rs:87-96 in both);
  small-order `R` and `A` rejected by `verify_strict`; non-canonical `R`
  rejected by the recompute-and-byte-compare design. Probe bits 15-24
  pass identically for both.
- **Byte-identical outputs**: same seed ⇒ identical pk and identical
  signature bytes across 2.2.0 and 3.0.0 (probe bits 25-26) — the pin
  choice moves no vector, ever.
- **Shared gaps** (version-independent, closed by C12's pre-validation
  layer): signature parse is infallible (S checked only at verify, with
  an opaque error) and `VerifyingKey::from_bytes` is ZIP-215 (accepts
  non-canonical `A` encodings; curve25519-dalek#626).
- **Stack coherence**: 3.0.0 = curve25519-dalek 5.0.0, ed25519 3,
  `signature` **3** (the trait major `ml-dsa =0.1.1` uses), sha2 **0.11**
  (our exact pin), rand_core 0.10/getrandom **0.4** (ml-dsa's line);
  MSRV 1.85 / edition 2024 (workspace: 1.92 / 2024). Choosing 2.2.0
  instead demonstrably doubles the crypto stack (probe lock: sha2
  0.10.9+0.11.0, signature 2.2.0+3.0.0, ed25519 2.2.3+3.0.0,
  crypto-common 0.1.7+0.2.2) and makes C14 orchestrate across two
  incompatible `signature` trait majors.
- **RUSTSEC/osv.dev**: both candidates clean (RUSTSEC-2022-0093 ended at
  2.0.0; curve25519-dalek's RUSTSEC-2024-0344 fixed in 4.1.3, and 5.0.0
  unaffected).
- wasm32-unknown-unknown: both build **and execute** in the probe wasm
  module with bit-identical output to native; no getrandom needed
  (`rand_core` feature off — keys derive from `W`).

## Decision

**Pin `ed25519-dalek = "=3.0.0"`** (exact-pin class; declaration-only in
`[workspace.dependencies]` until C12 consumes it).

Rationale in one paragraph: the strict-verification behavior we freeze on
is probe-proven identical between the candidates — so the deciding factor
is the trust-base shape, and 3.0.0 is the only choice that gives one
RustCrypto generation across the whole signature stack (signature 3 +
sha2 0.11 + getrandom 0.4, all shared with `ml-dsa =0.1.1` and the
existing workspace pins) instead of two parallel ones frozen forever. The
three-week age is mitigated by the year of pre/rc releases behind it, by
the verification core being byte-for-byte behavior-compatible with the
long-deployed 2.x code (probe bits 15-26), by the exact pin + P13
advisory watch, and by a clean escape hatch: 2.2.0 is byte-compatible, so
a forced downgrade would move no vectors.

Consumption shape (C12): `default-features = false, features = ["alloc",
"zeroize"]`; never `legacy_compatibility` (weakens the S check); `fast`
(precomputed tables, speed vs ~wasm-size) is C12's call. C12 adds the
pre-validation layer for parse-time S-range and `A`/`R` encoding
canonicality (report §9).

## Consequences

- Root `[workspace.dependencies]`: `ed25519-dalek = "=3.0.0"`
  (declaration-only; root Cargo.lock unchanged until C12).
- `docs/dependency-policy.md` §1 row updated; bumps follow §4.
- P14's getrandom audit table: dalek 3.0.0 sits on the 0.4 line (only if
  `rand_core` is ever enabled; the M0 build pulls no getrandom at all).
- C12 requirements recorded in the probe report §9 (S-range pre-check,
  A-canonicality pre-check, feature hygiene).
