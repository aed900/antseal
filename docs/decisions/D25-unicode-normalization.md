# D25 — Unicode/NFC normalization: crate, exact data-version pin, multi-version retention

- **Status: RESOLVED**
- **Date: 2026-07-27**

## Context

Canonicalization (MVP-SPEC.md lines 81–83) NFC-normalizes every text file,
and NFC output depends on the Unicode data version, so the exact version is
frozen per seal, recorded in the per-file canonicalization descriptor, and
the matching normalization table must ship in `antseal-core` and stay
available **forever** under the format-stability policy (line 123): a
verifier recomputing canonicalization (the raw-mirror check, line 121)
applies the *descriptor-recorded* version, never "latest", or aging honest
bundles false-positive as tampered. M0 requires the pinned Unicode/NFC
version (line 153). The crate is in the exact-pin class
([`docs/dependency-policy.md`](../dependency-policy.md) §1: "Unicode/NFC
data crate (nominated by G at M0); its Unicode data version is frozen into
manifests"). Task G1; this record resolves open decision D25.

Candidates evaluated: `unicode-normalization` (unicode-rs) vs ICU4X
`icu_normalizer` with compiled data.

## Evidence (all retrieved 2026-07-27, ~17:55Z–18:25Z)

**Reference point**: Unicode 17.0.0 released **2025-09-09** and is the
current version of the Unicode Standard ("2025 September 9", "This version
supersedes all previous versions" — unicode.org/versions/Unicode17.0.0).
Unicode releases annually in September; no 18.0 exists yet.

**`unicode-normalization`** (repo: github.com/unicode-rs/unicode-normalization):

- Newest release **0.1.25**, published to crates.io **2025-10-30**
  (crates.io API; previous: 0.1.24 on 2024-09-17). ~509 M downloads.
- **Shipped Unicode data version verified from the published crate bytes**
  (cargo-registry copy, checksum-verified by cargo at fetch time):
  `unicode-normalization-0.1.25/src/tables.rs:18` reads
  `pub const UNICODE_VERSION: (u8, u8, u8) = (17, 0, 0);`
  Corroborated by the upstream commit log: "Update Unicode to version
  17.0.0" (commit `01f4bd6`, 2025-09-11 — two days after the Unicode 17.0
  release) precedes "Release 0.1.25" (commit `7ae3eb0`, 2025-10-30).
  For comparison, 0.1.24 shipped 16.0.0 ("Update Unicode to version
  16.0.0, bump to 0.1.24", commit `fdfe8e0`, 2024-09-13). The GitHub
  project publishes no Releases entries; the commit log + the
  `UNICODE_VERSION` constant are the authoritative mapping.
- Dependency graph: **3 packages total** — itself + `tinyvec` (features
  `alloc`) + `tinyvec_macros`. `no_std`-capable (`default = ["std"]`),
  MSRV 1.36 (≤ our 1.92 pin), no I/O, no build script, pure table lookup:
  deterministic by construction. Crate root carries
  `#![deny(missing_docs, unsafe_code)]` with three narrow
  `#[allow(unsafe_code)]` sites (Hangul-arithmetic
  `char::from_u32_unchecked` on values proven in range) — small, auditable.
- RUSTSEC: **no advisories** (rustsec.org/packages/unicode-normalization
  returns 404; the site publishes a page per crate iff advisories exist —
  convention verified against `time`, which has a page).
- wasm32 size probe (this machine, toolchain 1.92.0, cdylib calling NFC,
  `opt-level = "s"`, `lto = true`, release): **139,672 B** vs a 1,798 B
  no-dep baseline → **~138 KB delta**.

**`icu_normalizer` (ICU4X)** (repo: github.com/unicode-org/icu4x):

- Newest release **2.2.0**, published **2026-04-01** (crates.io API;
  2.1.x on 2025-10-28, 2.0.0 on 2025-05-07). Compiled data lives in the
  separate `icu_normalizer_data` crate (2.2.0, 2026-04-01).
- Shipped data version, from the published data-crate bytes
  (`icu_normalizer_data-2.2.0/README.md`): "This data was generated with
  CLDR version 48.2.0, ICU version **release-78.1rc**" — ICU 78/CLDR 48
  implement Unicode 17.0 (chained inference; also note the data derives
  from an ICU release *candidate*). The icu4x CHANGELOG/release notes for
  icu@2.1.0 state "update to CLDR 48" and list normalizer work incl. "Make
  the normalizer work with new Unicode 16 normalization behaviors" —
  i.e. upstream **changed engine code to accommodate new Unicode data**,
  evidence that engine and data versions are behaviorally coupled.
- **No runtime constant exposes the data's Unicode version** — the mapping
  is provenance documentation, not machine-assertable in our tests.
- Dependency graph: ~20 runtime crates (icu_collections, icu_provider,
  icu_locale_core, zerovec, zerotrie, yoke, zerofrom, potential_utf,
  tinystr, litemap, writeable, utf8_iter, utf16_iter, write16, smallvec,
  stable_deref_trait, …) plus a proc-macro stack (syn, quote, proc-macro2,
  synstructure, displaydoc, derive crates) — ~27 packages. The zerovec/yoke
  layer is heavily (if competently) `unsafe`. Very actively maintained
  (Unicode-consortium project). RUSTSEC: no advisories (same 404 check).
- wasm32 size probe (identical setup): **96,734 B** → **~95 KB delta**.
  ICU4X's zerovec data layout is genuinely smaller (~43 KB less).

## Decision

**Winner: `unicode-normalization`, pinned `=0.1.25`, shipping Unicode data
version 17.0.0.** The frozen descriptor version string is
**`unicode-17.0.0`** (the only string v1 registers; format
`unicode-<major>.<minor>.<patch>` of `UNICODE_VERSION`).

The crate-release → Unicode-data-version mapping (`0.1.25` → `17.0.0`) is
**machine-asserted in `antseal-core` tests** against the crate's public
`UNICODE_VERSION` constant, so any future pin bump that silently changes
the shipped data version fails CI instead of silently changing canonical
bytes.

Why not ICU4X, despite its ~43 KB smaller wasm footprint and first-class
data-provider versioning:

1. **Auditability of the freeze.** `unicode-normalization` is a fused
   engine+tables artifact: pinning `=0.1.25` freezes, in one small crate,
   exactly the code+data that produce M0 canonical bytes — nothing can
   drift. ICU4X splits a *moving* engine from versioned data, and upstream
   demonstrably changes engine code for new Unicode behaviors (2.1's
   "new Unicode 16 normalization behaviors" fix), so "old data under a
   newer engine yields identical bytes" is plausible but not contractual —
   every engine bump would become a re-verification event for *all*
   retained versions, and icu data-format stability is only promised
   within a semver major anyway (the freeze problem returns at icu 3.x).
2. **Machine-checkable mapping.** `UNICODE_VERSION` lets tests enforce the
   decision-doc mapping forever; ICU4X offers only README provenance (from
   an ICU RC build, at that).
3. **Supply-chain / pin surface.** 3 packages, MSRV 1.36, near-zero
   `unsafe`, vs ~27 packages with a large `unsafe` core — all sitting in
   the verifier trust base. The exact-pin class gains one crate instead of
   two-plus.

The ~43 KB wasm penalty is accepted; both candidates are deterministic,
I/O-free, `wasm32-unknown-unknown`-clean (both probes compiled and were
measured on that target), and RUSTSEC-clean.

## Multi-version retention architecture

Verifiers apply exactly the descriptor-recorded version, never "latest"
(spec line 83). Future Unicode versions are **added**; shipped tables are
**never removed or altered** (spec line 123). Concretely:

- `antseal-core::canon::unicode` holds a **version-dispatch registry**:
  descriptor string → normalizer implementation. v1 registers exactly
  `unicode-17.0.0` → `unicode-normalization =0.1.25`. Any unregistered
  string resolves to the distinct `UnknownUnicodeVersion` error (a
  malformed/newer-than-this-build bundle renders "needs a newer verifier",
  never a false "tampered").
- **The pin never moves onto different data.** All upstream releases live
  in the single `0.1.x` semver range, so cargo can resolve only one per
  graph; upstream data bumps (as 0.1.24→0.1.25 was) therefore CANNOT be
  taken as in-place pin bumps once `unicode-17.0.0` seals exist. A bump of
  `=0.1.25` is permitted only if `UNICODE_VERSION` still equals
  `(17, 0, 0)` (the mapping test enforces this) and the dependency-policy
  §4 checklist passes (golden vectors byte-identical).
- **Adding Unicode N (N ≥ 18)**: vendor the newer upstream release into
  the workspace as a distinctly named crate (e.g.
  `antseal-nfc-data-18`, sources copied verbatim from the upstream
  release; MIT/Apache-2.0 + Unicode-3.0 licensing permits this), pin it
  exactly, and register `unicode-18.0.0` alongside — the `unicode-17.0.0`
  entry and its crate stay byte-identical forever. Additive cost: one
  ~140 KB wasm table-set per retained version (measured above; accepted —
  Unicode revs annually, and we adopt new versions deliberately, not
  automatically).
- **Retention obligation (normative; ties into the Q27 format-stability
  policy doc):** every version string ever emitted into a sealed
  manifest's descriptor remains registered, with byte-identical behavior,
  in every future `antseal-core` release (CLI and page alike). Removing,
  renaming, or altering a registered table is a format break and is
  forbidden. The G3 corpus golden outputs police behavior per version in
  CI indefinitely.

## Consequences

- Root `[workspace.dependencies]`: `unicode-normalization = "=0.1.25"`
  (exact-pin class); `antseal-core` consumes it via `workspace = true`.
- `crates/antseal-core/src/canon/unicode.rs` implements the registry
  (`UnicodeVersion`, `UnicodeVersionError::UnknownUnicodeVersion`) and the
  registry-routed NFC entry point; G2's `canonicalize_v` pipeline
  (BOM/EOL/detection) builds on it; G4's descriptor records
  `UnicodeVersion::CURRENT.as_str()` at seal time; G3 commits the corpus
  golden bytes produced by these tables.
- The mapping test (`UNICODE_VERSION == (17, 0, 0)`, descriptor string
  `unicode-17.0.0`) is the standing tripwire for any future pin motion.
