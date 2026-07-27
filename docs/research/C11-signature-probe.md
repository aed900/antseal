# C11 — M0 signature-crate probe report

Task C11 (tasks/C.md); spec basis: author signature (MVP-SPEC.md line 97),
M0 milestone (line 153), PQC-crate-maturity risk (line 183). Executed
2026-07-27 on toolchain 1.92.0 (x86_64-unknown-linux-gnu) + node v24.12.0.
Probe harness: `probes/sig-probe/` (standalone crate, own committed
`Cargo.lock`). Decisions fed: [D13](../decisions/D13-ed25519-dalek-pin.md),
[D14](../decisions/D14-mldsa-crate.md); D15 inputs recorded (§8).

Method: upstream-verification by design — every claim below was checked
against the published crate bytes for the pinned versions (crates.io
package downloads, extracted and read; file:line citations refer to those
packages) and/or executed in the probe. Nothing here is from memory of the
APIs.

## 1. Execution-time crate landscape (crates.io API, 2026-07-27)

| crate | pinned | newest today | published | notes |
| --- | --- | --- | --- | --- |
| `ml-dsa` | `=0.1.1` | 0.1.1 | 2026-06-05 | first stable after an rc series (rc.0 2025-09-13 … rc.11 2026-05-10, 0.1.0 2026-05-17); repo RustCrypto/signatures; not yanked |
| `fips204` | `=0.4.6` | 0.4.6 | 2024-12-22 | dormant since 2024-12 exactly as the spec records; repo integritychain/fips204 |
| `ed25519-dalek` | decided `=3.0.0` | 3.0.0 | 2026-07-06 | 3 weeks old at decision time, after a 1-year pre/rc series (3.0.0-pre.0 2025-07-09, rc.1 2026-06-18); newest 2.x is **2.2.0** (2025-07-09) |

Stay-or-bump per P12: both spec pins are the newest published versions —
**stay** is trivially the decision for `ml-dsa`/`fips204`; `ed25519-dalek`
is a fresh decision (D13), not a bump.

## 2. `ml-dsa = "=0.1.1"` (primary candidate) — source findings

Package facts: `#![no_std]` (src/lib.rs:1), `unsafe_code = "forbid"`
(Cargo.toml lints), MSRV 1.85, edition 2024. Deps: `crypto-common 0.2`,
`ctutils 0.4`, `hybrid-array 0.4`, `module-lattice 0.2.3`, `shake 0.1`,
`signature 3`, optional `zeroize 1.8.1`, optional `pkcs8 0.11`/`const-oid
0.10`. Default features `alloc, getrandom, pkcs8` — **`zeroize` is NOT
default and must be enabled explicitly**.

### 2.1 Deterministic keygen from a 32-byte seed xi

- `pub type Seed = B32` — "ML-DSA seeds are signing (private) keys …
  the preferred serialization" (src/lib.rs:91-93).
- `SigningKey::<P>::from_seed(xi: &Seed)` implements FIPS 204
  **Algorithm 6 `ML-DSA.KeyGen_internal`** (src/signing.rs:51-91: derives
  rho/rho'/K via SHAKE over `xi ‖ K ‖ L`, expands A_hat/s1/s2, power2round).
  `to_seed()/as_seed()` round the seed back (src/signing.rs:100-117).
- Sizes asserted by the crate's own test and by our probe: sk 4032 / pk
  **1952** / sig **3309** for ML-DSA-65 (src/lib.rs:262-279) — matches
  C13's schema constants.

### 2.2 FIPS-204 `ctx` parameter — YES, first-class

- Sign: `ExpandedSigningKey::sign_deterministic(M, ctx) -> Result<…>`
  (src/signing.rs:428-430 → 440-447); `ctx.len() > 255` is an `Err`
  (src/signing.rs:441-443).
- Verify: `VerifyingKey::verify_with_context(M, ctx, sig) -> bool` =
  **Algorithm 3 `ML-DSA.Verify`** (src/verifying.rs:130-133);
  `ctx.len() > 255` returns false (src/verifying.rs:140-143).
- The M′ construction is the spec's non-prehashed domain separation:
  `MuBuilder::new` absorbs `tr ‖ 0x00 ‖ len(ctx) ‖ ctx` before the message
  (src/lib.rs:157-168) — i.e. `M′ = IntegerToBytes(0,1) ‖
  IntegerToBytes(|ctx|,1) ‖ ctx ‖ M`. Probe bits 0-2 confirm ctx binding
  (verify passes with `"antseal-manifest-v1"`, fails with a different ctx
  and with the empty ctx).
- The `Signer`/`MultipartSigner` trait impls sign with the **empty ctx**
  (src/signing.rs:181-195) — C13 must call `sign_deterministic`
  explicitly, never the trait method.

### 2.3 Canonical rejection at decode — YES, complete, with layering

`Signature::decode` (Algorithm 27 sigDecode, src/lib.rs:113-127) returns
`Option`; `TryFrom<&[u8]>` (src/lib.rs:130-137) adds the exact-length
check. Rejection conditions, each exercised by a probe bit:

| condition | source | probe bit |
| --- | --- | --- |
| `‖z‖∞ ≥ γ1 − β` (eager: FIPS 204 puts this in Verify step 13; the crate rejects at decode) | src/lib.rs:122-124 | 8 |
| duplicate hint indices in a polynomial segment (strict `<`; **this is the CVE-2026-24850 fix** — the vulnerable rc.2 used `<=`) | src/hint.rs:148-151 | 4 |
| hint count above ω (cut byte > ω = 55 for -65) | src/hint.rs:137 | 5 |
| nonzero index bytes after the last cut (zero-padding rule, Alg 21 steps 16-18) | src/hint.rs:138 | 6 |
| decreasing cumulative cuts | src/hint.rs:136 | 7 |
| wrong length | src/lib.rs:130-137 (`EncodedSignature::try_from`) | (compile-shape) |

There are **no other signature-encoding degrees of freedom**: `c_tilde`
is 48 opaque hash bytes (all values legal; equality-checked in verify),
and the 20-bit z packing is a bijection onto `[−γ1+1, γ1]`, so canonical
enforcement = the norm bound + hint rules above. Conclusion for C13:
**no pre-validation layer is needed for canonicality** — the crate itself
enforces the full FIPS 204 canonical-encoding rule at decode.

Layering (probe bit 9): a bit-flipped `c_tilde` **decodes fine and fails
only at verify** — so C13 gets its two distinct errors naturally:
`decode → None/Err` ⇒ `NonCanonicalSignature{mldsa65}` and
`verify_with_context → false` ⇒ `SignatureInvalid{mldsa65}`. Remaining
C13 nuance (not a gap): `decode`'s `Option` carries no reason and folds
wrong-length with non-canonical; if C15's vectors want finer attribution
(length vs hint vs z), C13 can pre-check length (3309) and, optionally,
re-derive the reason for diagnostics — the verdict-relevant distinction
(non-canonical vs invalid) needs nothing extra.

`verify_internal`/`raw_verify_mu` (src/verifying.rs:94-128) then performs
Algorithm 8 over the decoded (hence already-validated) signature: UseHint
reconstruction and `c_tilde` equality.

### 2.4 Signing modes (D15 inputs) and RNG surface

- `sign_deterministic` = FIPS 204 Algorithm 2 **deterministic variant**:
  `rnd = B32::default()` (32 zero bytes, src/signing.rs:435-438 →
  raw_sign_mu). The `Signer` trait impl is the same mode (empty ctx).
- Hedged signing exists as `sign_randomized`/`sign_mu_randomized` behind
  the `rand_core` feature (src/signing.rs:376-420) — takes an external
  `TryCryptoRng`.
- Verification is mode-agnostic (rnd never appears in Verify).
- With `default-features = false, features = ["alloc", "zeroize"]` the
  crate needs **no RNG at all**: probe `Cargo.lock` contains **zero
  `getrandom` entries**. If a future decision enables `getrandom`, the
  chain is `crypto-common 0.2.2 → getrandom 0.4 (sys_rng)` (verified in
  the crypto-common 0.2.2 manifest) — the `wasm_js`+RUSTFLAGS recipe line.

### 2.5 Zeroization

`SigningKey::drop` zeroizes the seed (src/signing.rs:222-228);
`ExpandedSigningKey::drop` zeroizes rho, K, tr, s1, s2, t0 and the NTT
forms (src/signing.rs:644-659); both implement `ZeroizeOnDrop`
(src/signing.rs:230-231, 661-662) — **only with the `zeroize` feature
on**, which the probe asserts at compile time (`assert_zeroize_on_drop`).
C13's own xi handling (HKDF output buffer) still needs C-side zeroizing;
the crate clones the seed into the key (src/signing.rs:87), so the
caller's copy is the caller's job.

### 2.6 Test corpus shipped by the crate

The package runs Wycheproof vectors (tests/wycheproof.rs) and property
tests; the ACVP JSON files are excluded from the package but exercised in
the upstream repo's CI. C16 should still commit our own ACVP/KAT-derived
vectors per C15/C16 scope.

## 3. `fips204 = "=0.4.6"` (fallback candidate) — source findings

Package facts: no_std-capable, MSRV 1.70, edition 2021. Deps:
`rand_core 0.6.4` (non-optional, but backend-less without features),
`sha2 0.10.8`, `sha3 0.10.2`, `zeroize` (non-optional, with derive).
Features: default = `default-rng` (= `rand_core/getrandom` → the
**getrandom-0.2 line**) + all three parameter sets; per-set features
(`ml-dsa-65`) allow a minimal build.

- **Seed keygen**: `KG::keygen_from_seed(xi: &[u8; 32]) -> (PublicKey,
  PrivateKey)` (src/traits.rs:104-113) — no RNG.
- **ctx support**: `try_sign(&self, message, ctx)` /
  `verify(&self, message, &sig, ctx)` (src/traits.rs:156, 356); ctx > 255
  errors/fails.
- **Deterministic signing**: `try_sign_with_seed(&self, seed, message,
  ctx)` feeds `rnd` from a `DummyRng { data: seed }`
  (src/traits.rs:228-231, 309-326); passing `&[0u8; 32]` is exactly the
  FIPS 204 deterministic variant. **Probe-proven byte-compatible with
  ml-dsa**: same xi ⇒ identical pk bytes (bit 12) and identical
  deterministic signature bytes (bit 13) — a genuine cross-implementation
  check of both KeyGen and Sign, and the reason a fallback swap would
  need no re-derivation or format change.
- **Canonical rejection**: `sig_decode` (Algorithm 27,
  src/encodings.rs:292-329) calls `hint_bit_unpack` — a line-by-line
  Algorithm 21 transcription including step 4 (cut < index or > ω → ⊥,
  src/conversion.rs:356-361), step 9 (non-strictly-increasing indices →
  ⊥, src/conversion.rs:372-377) and steps 16-18 (nonzero padding → ⊥,
  src/conversion.rs:394-405). The z bound is enforced as spec-located:
  Verify step 13 `‖z‖∞ < γ1 − β` (src/ml_dsa.rs:433-436).
- **Limitation vs ml-dsa**: the public `Signature` type is a raw
  `[u8; 3309]` (src/lib.rs:255) and `verify` returns plain `bool` —
  decode failure (src/ml_dsa.rs:367-372) and verification failure are
  indistinguishable (probe bit 14). If the fallback ever activates, C13
  must add a **pre-validation layer** (length + hint-rule + z-bound
  re-check over the raw bytes) to keep `NonCanonicalSignature` vs
  `SignatureInvalid` distinct. With the primary crate this layer is not
  needed (§2.3).
- RUSTSEC/osv.dev: **no advisories** for fips204 (osv.dev query
  2026-07-27 returned none).

## 4. `ed25519-dalek` 2.2.0 vs 3.0.0 — source findings

Both versions share the same verification core (diff-checked on the
published packages):

- **S ≥ L rejected in every verification path** — `check_scalar` uses
  `Scalar::from_canonical_bytes` (src/signature.rs:87-96, identical in
  both) and runs during `InternalSignature::try_from` at the start of
  `verify`, `verify_strict`, and the ph variants. **NOT at signature
  parse time**: `ed25519::Signature::from_bytes(&[u8; 64])` is
  *infallible by type* (any 64 bytes parse; probe bits 16/21 construct
  the `s+L` maul through it), and the dalek error out of a failed verify
  is opaque (`signature::Error`) — so C12's distinct
  `NonCanonicalSignature{ed25519}` needs its **own S-range pre-check**
  over bytes 32..64 before calling the crate. Feeds D16 exactly as C12
  anticipated.
- **`legacy_compatibility` feature weakens check_scalar to the 3-high-bits
  check** (src/signature.rs:65-86) — it must never be enabled; the C12
  manifest entry should not expose it.
- **verify_strict** (2.2.0 src/verifying.rs:357-380; 3.0.0
  src/verifying.rs:367-390; bodies identical): canonical-S via
  check_scalar, R decompression, **small-order R and small-order A
  rejection** (`is_small_order` on both), then recomputes R and
  **byte-compares the canonical compression against the provided R
  bytes** — which also rejects every **non-canonically encoded R**
  (RCompute doc, 2.2.0 src/verifying.rs:490-493: "all our verification
  functions do not accept non-canonically encoded R values"). Probe bits
  15/17/20/22 exercise accept/reject.
- **Known gap (both versions): non-canonical A.**
  `VerifyingKey::from_bytes` documents: "Verifies the point is valid
  under **ZIP-215** rules. RFC 8032 / NIST point validation criteria are
  currently unsupported (curve25519-dalek#626)" (2.2.0
  src/verifying.rs:130-132; same in 3.0.0). Probe bits 19/24: the
  y-encoding `p` (≡ 0 mod p, non-canonical) is **accepted** and the key
  keeps its non-canonical byte identity. verify_strict never re-checks
  A's encoding canonicality. → **C12 pre-validation layer must add the
  A-canonicality check** (decompress → recompress → byte-compare against
  the manifest-supplied pubkey bytes) to meet the spec's "reject
  small-order/**non-canonical** `R`/`A`" conformance line. (Small-order
  A *is* rejected by verify_strict — probe bits 18/23 — and in antseal a
  mauled pubkey also breaks the signed body, but cross-verifier
  conformance requires the explicit check.)
- **Zeroization**: `SigningKey: ZeroizeOnDrop` behind the `zeroize`
  feature in both (3.0.0 src/signing.rs:725-726); compile-asserted in the
  probe.
- **Determinism / cross-version byte equality**: probe bits 25/26 — same
  seed ⇒ identical pk and identical signature bytes across 2.2.0 and
  3.0.0 (RFC 8032 determinism), so a later 2.x↔3.x migration cannot move
  any committed vector.

Version-line differences (3.0.0 CHANGELOG + manifests):

| | 2.2.0 | 3.0.0 |
| --- | --- | --- |
| curve25519-dalek | 4 (locked 4.1.3 in probe) | 5.0.0 |
| ed25519 / signature | 2.2.3 / 2.x | 3.0.0 / **3** (same major as ml-dsa) |
| sha2 | 0.10 (locked 0.10.9) | **0.11** (= our exact pin line) |
| rand_core (optional) | 0.6.4 → getrandom **0.2** | 0.10 → getrandom **0.4** (changelog: "Upgrade getrandom dependency to v0.4") |
| MSRV / edition | 1.81 / 2021 | 1.85 / 2024 (workspace is 1.92 / 2024) |
| std feature | yes (default) | removed (core Error) |

RUSTSEC/osv.dev (2026-07-27): `ed25519-dalek` — only RUSTSEC-2022-0093 /
CVE-2022-50237 (double pubkey signing oracle), fixed ≥ 2.0.0 — both
candidates clean. `curve25519-dalek` — RUSTSEC-2024-0344 / CVE-2024-58262
(Scalar sub timing), fixed 4.1.3 — probe locked exactly 4.1.3 for the 2.x
side; 5.0.0 unaffected. Nothing against 3.0.0 or curve25519-dalek 5.

**Dual-stack cost of choosing 2.2.0** (visible in the probe lock, which
contains both): sha2 0.10.9+0.11.0, signature 2.2.0+3.0.0, ed25519
2.2.3+3.0.0, crypto-common 0.1.7+0.2.2, curve25519-dalek 4.1.3+5.0.0 —
i.e. two parallel RustCrypto generations inside the permanently-frozen
verifier trust base, plus duplicate-version exceptions in P13's deny.toml,
plus C14 orchestrating across two incompatible `signature` trait majors.
Choosing 3.0.0 collapses all of it into the one generation the rest of
the workspace already pins. → D13.

## 5. Probe harness and results

`probes/sig-probe/`: standalone crate (empty `[workspace]`), committed
`Cargo.lock`, both dalek majors via package rename, no RNG features
anywhere. 27 behavioral invariants in one `selfcheck()` bitmask (see
`tests/probe.rs` for the per-bit names) + a 10714-byte deterministic
transcript `mldsa_pk ‖ mldsa_sig ‖ fips204_pk ‖ fips204_sig ‖ d2_pk ‖
d2_sig ‖ d3_pk ‖ d3_sig` over fixed fixture seeds, the frozen ctx
`"antseal-manifest-v1"`, and the C12 Ed25519 pre-image `ctx ‖ 0x00 ‖ body`.

Results (2026-07-27):

- **native**: 27/27 pass; transcript SHA-256
  `92354c8d75efdc6dfd26cea301243e35ba0776753c61127846b77c8a3cffa298`
  (pinned as a golden in `tests/transcript.rs`).
- **wasm32-unknown-unknown**: builds with **no getrandom recipe** (no
  getrandom in the graph at all) and — because the module ends up with
  zero imports — was **executed** in node v24 via plain
  `WebAssembly.instantiate` (`run-wasm.mjs`): selfcheck `0x07ffffff`
  (27/27) and **byte-identical transcript** (same SHA-256). This is a
  real executed native↔wasm bit-match, not compile-level evidence — the
  C3-style "defer execution to P14/Q5" rider is NOT needed for C11.
  P14/Q5 still owns the durable CI harness (wasm-bindgen-test + headless
  runner) for antseal-core's own test suite.
- wasm size datum: 257,971 B for all four crates in one module
  (`opt-level = "s"`, no lto tuning) — comfortably within the verifier
  page budget; the shipping build carries one dalek + one ML-DSA impl.

## 6. Advisory assessment (P12/(b); IDs named)

GitHub security advisories on RustCrypto/signatures list **three** against
`ml-dsa` (all published Jan 2026; cross-checked via osv.dev):

1. **GHSA-hcp2-x6j4-29j7 = CVE-2026-22705 = RUSTSEC-2025-0144** —
   "Timing side-channel in ML-DSA decomposition" (RUSTSEC date
   2025-12-12; GHSA published 2026-01-09). Variable-time hardware
   division on secret-derived values in `decompose` during **signing**.
   Patched ≥ 0.1.0-rc.3 (Barrett reduction; `use_hint` is now
   constant-time selection, src/hint.rs:20-44). *Applicability to our
   profile*: signing happens locally in the CLI with per-work keys — no
   networked signing oracle exists, and an attacker who can take precise
   timing measurements on the sealer's own machine is outside our threat
   model's containment anyway; verification touches public data only.
   **Patched in our pin; residual risk accepted and documented.**
2. **GHSA-5x2r-hc65-25f9 = CVE-2026-24850** — "Signature Verification
   Accepts Signatures with Repeated Hint Indices" (published 2026-01-27).
   A `<` → `<=` regression in exactly the canonical-hint rule the spec's
   "canonical ML-DSA (hint bounds)" line exists for; enables signature
   malleability (multiple byte encodings verify) — directly against our
   SUF-CMA/anti-malleability requirement. Affected ≤ rc.3, patched ≥
   rc.4. **Patched in our pin (strict `<` verified at src/hint.rs:149);
   probe bit 4 is a standing regression guard; C15 commits reject
   vectors.**
3. **GHSA-h37v-hp6w-2pp8** (no CVE, no RUSTSEC ID) — "UseHint off by two
   when r0 = 0" (published 2026-01-31). FIPS 204 Algorithm 40 compliance
   bug: valid signatures could fail verification on an edge case — for
   antseal that is a false "tampered" verdict on an honest bundle, an
   integrity-verdict-correctness issue rather than a forgery. Affected ≤
   rc.4, patched rc.5. **Patched in our pin (r0 = 0 takes the decrement
   branch, src/hint.rs:34-36; upstream regression test
   src/hint.rs:241-250); our fips204 cross-check (probe bit 13) would
   surface any sign-side re-regression as a byte mismatch.**

The spec's "two Jan-2026 advisories" (lines 97/183) maps to №2+№3 (the
two January-*dated* ones; №1 is December-dated in RUSTSEC and
January-published as a GHSA). All three predate and are fixed by the
pinned 0.1.1 (2026-06-05).

**Tracking gap for P13/Q10**: as of 2026-07-27 only №1 has a RUSTSEC ID —
the RUSTSEC advisory-db `crates/ml-dsa/` directory contains exactly
`RUSTSEC-2025-0144.md`, and osv.dev shows №2/№3 as GHSA-only. A
cargo-audit/cargo-deny lane fed by the RUSTSEC DB alone would have shown
one of three. P13 must include a GHSA/osv.dev source (e.g. `osv-scanner`
or a GHSA query) alongside RUSTSEC, and the deny.toml justification
entries should cite all three IDs above.

## 7. getrandom audit rows (handoff to P14)

With the recommended feature selections **nothing pulls getrandom** (the
signature stack is RNG-free: keygen from HKDF-derived seeds, deterministic
ML-DSA signing, deterministic Ed25519). If RNG features are ever enabled:

| crate + feature | chain | getrandom line | recipe |
| --- | --- | --- | --- |
| `ml-dsa` `getrandom` | crypto-common 0.2.2 → getrandom `0.4` (`sys_rng`) | 0.4 | `wasm_js` feature + `--cfg getrandom_backend="wasm_js"` |
| `ed25519-dalek 3.0.0` `rand_core` | rand_core 0.10 → getrandom `0.4` | 0.4 | same |
| `ed25519-dalek 2.2.0` `rand_core` | rand_core 0.6.4 → getrandom `0.2` | 0.2 | feature `js` |
| `fips204` `default-rng` | rand_core 0.6.4 → getrandom `0.2` | 0.2 | feature `js` |

(The 3.0.0 choice keeps any future RNG need on the single 0.4 line.)

## 8. D15 inputs (hedged vs deterministic signing mode — no resolution here)

- The pinned crate defaults to **deterministic** (trait impls and
  `sign_deterministic`, rnd = 0^32); hedged exists behind `rand_core`.
- Deterministic mode: C16 golden signature vectors are exactly
  reproducible, and — probe bit 13 — **portable across independent
  implementations** (fips204 produces the identical bytes), i.e. vectors
  survive even a fallback swap. No RNG in the signing path (the wasm
  verifier never signs regardless).
- Hedged mode: FIPS 204 §3.4's default recommendation (fault/side-channel
  hedge); would make C16 sign-side vectors non-reproducible (verify-side
  vectors unaffected) and adds a getrandom-0.4 requirement to the CLI
  (native only — irrelevant to the wasm surface).
- Verification is identical either way; the manifest format carries no
  trace of the mode.

## 9. Gaps enumerated for C12/C13 (pre-validation layers)

1. **C12 / Ed25519 — S-range pre-check**: `Signature::from_bytes` is
   infallible and dalek's verify errors are opaque; C12 checks
   `s = bytes[32..64] < L` itself to emit `NonCanonicalSignature{ed25519}`
   distinctly from `SignatureInvalid{ed25519}` (D16 evidence).
2. **C12 / Ed25519 — A-canonicality pre-check**: dalek accepts
   non-canonical pubkey encodings (ZIP-215, §4); C12 adds decompress →
   recompress → byte-compare on the manifest pubkey (and may reuse the
   same check on R for a distinct non-canonical-R error before dalek's
   fold-into-Verify rejection).
3. **C12 — feature hygiene**: never enable `legacy_compatibility`; keep
   `zeroize` on (not default-off here — it IS a default feature of dalek,
   but the pin entry states it explicitly).
4. **C13 / ml-dsa — no canonicality pre-validation needed** (§2.3); C13
   maps `decode` failure → `NonCanonicalSignature{mldsa65}`, `verify` false
   → `SignatureInvalid{mldsa65}`; pre-check length 3309 for a cleaner
   wrong-length error if desired; must call `sign_deterministic`/
   `verify_with_context` (never the empty-ctx trait impls); must enable
   the non-default `zeroize` feature and zeroize the xi buffer C-side.
5. **C13 / fips204 (only if fallback activates)** — full canonicality
   pre-validation required (bool-only API, §3).
6. **P13** — advisory lane must watch GHSA/osv.dev in addition to RUSTSEC
   (§6 coverage gap).
