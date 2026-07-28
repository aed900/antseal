# D14 — ML-DSA-65 crate: primary `ml-dsa =0.1.1`, fallback `fips204 =0.4.6`, Ed25519-only fallback not shipped

- **Status: RESOLVED** (recommended by the C11 probe; accepted at wave-2
  integration review — wasm32 executed bit-match, canonical rejection
  source-verified, fips204 cross-implementation byte-equality)
- **Date: 2026-07-27**

## Context

The PQC half of the hybrid author signature (MVP-SPEC.md line 97) named
`ml-dsa = "=0.1.1"` (pre-1.0, unaudited, 2026 advisories) as primary and
`fips204 = "=0.4.6"` (dormant since 2024-12) as fallback, contingent on
the M0 WASM probe (line 153) — with a reserved-slot
`sig_policy = [ed25519]` fallback if both fail (lines 97, 183). Task C11
ran the probe; task P12 lands the pins with the advisory assessment.

## Evidence

C11 probe (`probes/sig-probe/`; full report:
[docs/research/C11-signature-probe.md](../research/C11-signature-probe.md)):

- `ml-dsa =0.1.1` is the newest published version (2026-06-05, not
  yanked); `#![no_std]`, `unsafe_code = "forbid"`, RustCrypto signature-3
  generation. Deterministic keygen from 32-byte xi
  (`SigningKey::from_seed`, FIPS 204 Algorithm 6), first-class FIPS-204
  `ctx` on sign and verify, and — decisive for the spec's canonical-
  verification requirement — **complete canonical rejection at
  `Signature::decode`**: z norm bound, strict hint-index increase, hint
  count ≤ ω, zero padding, monotonic cuts (source cites in report §2.3;
  probe bits 4-9), cleanly layered so decode-failure vs verify-failure
  maps onto `NonCanonicalSignature` vs `SignatureInvalid` with **no C13
  pre-validation layer needed**.
- **wasm32 probe PASSED with executed bit-match**: built for
  wasm32-unknown-unknown with zero getrandom in the graph, executed in
  node, all 27 invariants held and the 10714-byte output transcript was
  SHA-256-identical to native
  (`92354c8d75efdc6dfd26cea301243e35ba0776753c61127846b77c8a3cffa298`).
- `fips204 =0.4.6`: seed keygen + ctx + deterministic signing via
  `try_sign_with_seed(&[0;32], …)` all present; **byte-identical pk and
  deterministic-signature output vs ml-dsa for the same xi** (probe bits
  12-13) — a cross-implementation check of KeyGen/Sign and proof that a
  fallback swap moves no format bytes. Its bool-only verify API folds
  decode and verification failures, so activating it would require a C13
  canonicality pre-validation layer (report §3). No advisories on record.

Advisory assessment (P12; the spec's "two Jan-2026 advisories" plus a
third; all details report §6):

1. **RUSTSEC-2025-0144 / CVE-2026-22705 / GHSA-hcp2-x6j4-29j7** — timing
   side-channel in Decompose during signing (patched ≥ 0.1.0-rc.3).
   Applicability: signing is local-CLI with per-work keys, no networked
   signing oracle; verification is public-data only. Patched in the pin;
   residual accepted.
2. **CVE-2026-24850 / GHSA-5x2r-hc65-25f9** — verification accepted
   duplicate hint indices (malleability; patched ≥ rc.4). Squarely our
   canonical-verification threat class; the pin has the strict `<` fix
   (hint.rs:149), probe bit 4 guards it permanently, C15 commits reject
   vectors.
3. **GHSA-h37v-hp6w-2pp8** — UseHint off-by-two at r0 = 0 (valid
   signatures could fail verification; patched rc.5). For antseal a
   false-"tampered" correctness bug, not a forgery; fixed in the pin and
   cross-checked by the fips204 byte-equality probe.

All three are fixed by 0.1.1. **Tracking gap**: only №1 has a RUSTSEC ID
(advisory-db `crates/ml-dsa/` holds exactly one file; osv.dev confirms
№2/№3 are GHSA-only as of 2026-07-27) — P13's lane must watch GHSA/osv.dev
in addition to the RUSTSEC DB, and its deny.toml justifications must cite
all three IDs.

## Decision

**Primary ML-DSA crate: `ml-dsa = "=0.1.1"`.** **Fallback:
`fips204 = "=0.4.6"`, pinned and probe-covered but consumed by no crate.**
**The Ed25519-only `sig_policy = [ed25519]` fallback does NOT ship** — its
trigger (ML-DSA failing the M0 WASM probe) did not fire; v1 seals sign
hybrid `[ed25519, ml-dsa-65]` as specced. The slot stays reserved in the
format and C14 still exercises the Ed25519-only path in CI (format
insurance, per C14's accept list), but no shipping seal uses it.

Rationale in one paragraph: the probe removed the only contingency that
would have demoted `ml-dsa` — it not only compiles for wasm32 but
executes there with byte-identical output to native, needs no RNG plumbing
at all in our deterministic profile, enforces the full FIPS 204 canonical
signature encoding at decode (the property the spec's strict-verification
line exists for, and the property advisory №2 shows this crate class can
silently lose — hence the probe's standing regression bits), and its three
2026 advisories are all patched in the pinned version with a written
applicability assessment. `fips204` earns the fallback seat — dormant but
advisory-clean, API-complete for our profile, and byte-compatible with the
primary so a swap is a dependency change, not a format event.

**Fallback trigger (normative for this decision):** the fips204 path
activates only if a defect or advisory lands against `ml-dsa` that (a)
breaks soundness of signing, canonical verification, or the wasm32
bit-match under our exact pin, and (b) cannot be resolved by a
dependency-policy §4 reviewed bump. The Ed25519-only policy activates only
if BOTH ML-DSA implementations are simultaneously unusable by that
standard — format unchanged, slot reserved. Either activation is a new
decision entry here, never a drive-by.

## Consequences

- Root `[workspace.dependencies]`: `ml-dsa = "=0.1.1"`,
  `fips204 = "=0.4.6"` (both declaration-only until C13; root Cargo.lock
  unchanged). Consumption shapes documented inline and in report §2.4/§3.
- `docs/dependency-policy.md` §1 rows filled; bumps follow §4 (for
  `ml-dsa`, any bump re-runs the probe and must keep probe bits 4-9 and
  the fips204 cross-equality green).
- C13: no canonicality pre-validation layer against the primary; call
  `sign_deterministic`/`verify_with_context` (never the empty-ctx trait
  impls); enable the non-default `zeroize` feature; zeroize the xi buffer
  caller-side. If fips204 ever activates, add the pre-validation layer of
  report §3/§9.
- P13/Q10: track all three advisory IDs; add a GHSA/osv.dev source beside
  RUSTSEC (coverage gap above).
- D15 (hedged vs deterministic signing) stays open; C11's inputs are
  recorded in report §8 — the pinned crate defaults to deterministic
  (rnd = 0^32), hedged sits behind `rand_core`+getrandom-0.4, verification
  and the wasm verifier surface are unaffected either way, and
  deterministic signatures are cross-implementation byte-identical (C16
  vector shape).

## Addendum — 2026-07-28: `fips204` moves from declaration-only to a dev-dependency (Q11/D31)

D31 consequence 4 requires this to be recorded rather than landed silently:
it is a change to a **consumption shape this decision fixed**, and a later
reader must not mistake it for the fallback having been activated.

**It has not been.** `ml-dsa =0.1.1` remains the primary and the only
implementation antseal ships. The fallback trigger above is unchanged and
untripped.

### What changed

| | before | after |
| --- | --- | --- |
| root `[workspace.dependencies]` | `fips204 = "=0.4.6"` | `fips204 = { version = "=0.4.6", default-features = false, features = ["ml-dsa-65"] }` |
| consumed by | no crate | `antseal-core` `[dev-dependencies]`, native-only |
| consumed where | — | `crates/antseal-core/tests/mldsa_fallback_equivalence.rs` |

The feature shape is now written down as **exactly the consumption shape this
record already documented** for the triggered case (no `default-rng`;
deterministic signing via `try_sign_with_seed`), so the equivalence test
exercises the shape a real swap would ship rather than a convenient
approximation.

### Why the "pinned-unconsumed" property survives

This record's Consequences say `fips204` is "pinned and probe-covered but
consumed by no crate", and the `core-dep-graph` lane depends on antseal-core's
*normal* graph staying I/O-free and predictable. A `[dev-dependencies]` edge is
not a consumed runtime dependency: it never enters `cargo tree -e normal`, and
nothing it pulls can reach a shipped artifact.

Verified at landing by cargo-tree diff:

```
cargo tree -p antseal-core -e normal --prefix none --locked
```

is **byte-identical** before and after, 102 lines, and `fips204` does not
appear in it. The `core-dep-graph` lane is unperturbed.

### What did change: `Cargo.lock`

Twelve packages are added, all dev-only and all reachable only through
`fips204`: `fips204 0.4.6` itself plus the RustCrypto 0.10-generation stack it
builds on — `sha2 0.10.9`, `sha3 0.10.9`, `digest 0.10.7`, `crypto-common
0.1.7`, `block-buffer 0.10.4`, `generic-array 0.14.7`, `keccak 0.1.6`,
`rand_core 0.6.4`, `cpufeatures 0.2.17`, `version_check 0.9.5`,
`zeroize_derive 1.5.0`. No package was removed and no existing version moved.

**This adds duplicate-version pairs** (`sha2` 0.10.9 beside our pinned
=0.11.0, `crypto-common` 0.1.7 beside 0.2.2, `rand_core` 0.6.4 beside the
0.9 line). `deny.toml` sets `multiple-versions = "warn"`, so the lane warns
rather than fails, which is the correct verdict here: the duplicates are
confined to the dev graph and cannot ship. If that setting is ever tightened
to `deny`, this is the entry that explains the exemption these pairs need.

### The distinction that matters, restated

D31 §4a settles the register's long-open question about whether an
`ml-dsa`↔`fips204` comparison counts as the independent cross-check. **It does
not.** Both crates are Rust, both implement FIPS 204, both come from the same
small community: their agreement is **T2** and cannot detect a shared
misreading of FIPS 204. The independent cross-check for ML-DSA-65 is NIST ACVP
(`crates/antseal-core/tests/acvp_ml_dsa.rs`, tier **T0**, 115 cases, zero
disagreements at the freeze commit).

So the new test is evidence for **this record's fallback claim and nothing
else**, and it says so in its own module docs. The two must never be conflated
in a freeze report, and `docs/testing/cross-check.md` labels them separately.
