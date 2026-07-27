# Dependency pin governance (P7)

Normative policy for every dependency of the antseal workspace. Rationale:
antseal produces permanent, versioned formats (manifests, bundles, `.ots`
material, ciphertext addresses) whose bytes must stay verifiable forever,
while several upstream crates release weekly-to-biweekly (ant-core) or are
pre-1.0 and unaudited (ml-dsa). A silently moved dependency version is a
format or consensus incident, not a chore. (MVP-SPEC.md: Key external
dependency; Risks — ant-core churn, PQC crate maturity.)

## 1. The exact-pin class

Every **format-, crypto-, or network-consensus-affecting** dependency MUST
be pinned with an exact `=x.y.z` requirement. Known members (each lands in
the workspace with its owning task; the pin rule binds from the moment it
lands):

| Dependency | Why exact-pinned | Deciding task |
| --- | --- | --- |
| `ant-core` (spec pin `=0.5.0`, re-verified at M0 start) | storage/payment surface; network consensus | P9 |
| deterministic-CBOR encoder (candidate `minicbor`) | every hashed/signed byte flows through it | P10 (joint with F) |
| `ed25519-dalek` (2.x vs 3.0.0 decision) | signature format + strict-verification semantics | P11 (C sign-off) |
| `ml-dsa` (spec pin `=0.1.1`; pre-1.0, unaudited) | PQC signature format | P12 |
| `fips204` (spec pin `=0.4.6`; fallback impl) | PQC signature fallback | P12 |
| `opentimestamps` (spec pin `=0.2.0`) | `.ots` wire format. **Scope: wire-format codec only** — the calendar HTTP client is in-house (antseal-anchor); no networking surface of the crate may be used | P18 (A) |
| `self_encryption` | deterministic ciphertext-address recomputation; **must equal the exact version ant-core's graph locks** — skew breaks the storage-linkage layer | P15 |
| AEAD/HKDF/SHA-2 stack (XChaCha20-Poly1305, HKDF-SHA256, `sha2`; exact crates nominated by C at M0) | ciphertext format + key derivation | C |
| Unicode/NFC data crate (nominated by G at M0; its Unicode data version is frozen into manifests) | canonicalization output bytes | G |
| Argon2/scrypt (vault KDF) | vault format | U/C |
| `zeroize` | secret-hygiene behavior | C |

**This list grows — it is a floor, not a ceiling.** G nominates the
Unicode/NFC crate (with its exact Unicode data version) at M0, and C
nominates the concrete AEAD/HKDF/SHA-2 crates at M0. Any new dependency
whose output bytes end up hashed, signed, stored, or paid for joins the
class in the same PR that introduces it.

Dependencies outside the class (e.g. `thiserror`, `clap`, `tracing`) may use
caret requirements, but their *resolved* versions are still frozen by the
committed `Cargo.lock` (§3).

## 2. Single declaration point

ALL version requirements live in **`[workspace.dependencies]`** in the root
`Cargo.toml` and nowhere else. Member crates reference dependencies
exclusively via `<dep>.workspace = true` — a member `Cargo.toml` never
carries a version string. The whole pin surface is reviewable in one place,
and an off-policy version cannot hide in a crate manifest.

## 3. Lockfile discipline

`Cargo.lock` is committed. Every CI lane that resolves dependencies runs
with `--locked`, so lockfile drift — or a manifest change without its
lockfile update — fails CI loudly. Local builds behave the same: if cargo
wants to touch the lockfile unprompted, a manifest and the lock are out of
sync; fix the commit rather than letting resolution float.

## 4. Version bumps are deliberate, reviewed events

Upstream cadence is weekly-to-biweekly; ours is not. **No drive-by bumps.**
`cargo update` sweeps, auto-bump bots, and bumping "while in the area" are
all off-policy (the weekly upstream check, P19, produces a *report*, never a
bump). A bump is its own PR containing only the bump and its direct
fallout, with this checklist completed in the PR description:

- [ ] Upstream changelog / release notes / commit delta reviewed; behavior
      and format changes written up
- [ ] RUSTSEC check for the new version (advisory lane must be green; new
      advisories get a written applicability assessment)
- [ ] Golden-vector re-run: every committed vector still verifies
      byte-exact (M0 onward). A vector change is a format event — it is
      justified explicitly, never regenerated silently
- [ ] For `ant-core`: devnet E2E green (local devnet, P16; Sepolia-mode
      where payment surfaces changed, P17), and the locked
      `self_encryption` version re-recorded — the two move only in lockstep
      (P15)
- [ ] For toolchain bumps: [toolchain.md](toolchain.md) procedure —
      `rust-toolchain.toml`, `rust-version`, `clippy.toml` move together in
      one commit

## 5. Toolchain and dev-tools under the same rules

- The Rust toolchain is pinned exactly in `rust-toolchain.toml`
  ([toolchain.md](toolchain.md)); MSRV = the pin; bumps follow §4.
- Dev-tools whose output or verdict the project depends on are exact-pinned
  wherever they are installed (CI workflows, scripts, docs):
  **wasm-pack**, **wasm-bindgen-cli** (must equal the `wasm-bindgen` crate
  pin — a mismatch breaks the build), **cargo-deny** (its verdict gates
  merges; P13 pins the CI version). The M3 reproducible wasm build makes
  the wasm-pack/wasm-bindgen versions format-provenance-relevant, exactly
  like the toolchain itself.

## Enforcement & cross-references

- CI (P8): `--locked` in every resolving lane; the `core-dep-graph` lane
  guards antseal-core's dependency purity.
- cargo-deny advisory lane, per-PR + weekly schedule (P13, M0).
- Weekly upstream-bump check: report-only, human-reviewed PR required for
  any pin change (P19).
- PR process: [../CONTRIBUTING.md](../CONTRIBUTING.md) — its checklist
  routes every version-touching PR through §4.
- [toolchain.md](toolchain.md) — the toolchain pin governed by §5.
