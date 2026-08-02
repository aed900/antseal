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
| `ant-node` — **pinned `=0.15.0` 2026-08-01 (P16; memo docs/research/P16-devnet-feasibility.md §5)**: the in-process devnet node stack behind ant-core's `devnet` feature. ant-core 0.5.0's own caret `0.15.0` requirement is deterministic today only by accident (no other 0.15.x published; 0.16.0 is outside the caret) — the exact pin closes the 0.15.1 window before it opens. Consumed ONLY by the never-published `devnet-launcher` behind its non-default `devnet` feature, never by a product crate; must stay inside ant-core's own requirement, so it moves only within an ant-core bump review (§4) | network consensus: node-side storage/replication/payment-verification behavior defines what the devnet accepts — the S17–S19 E2E evidence runs on exactly this stack | P16 — landed |
| `ant-protocol` — **pinned `=2.3.0` 2026-08-01 (S6)**: the wire-protocol crate ant-core itself depends on, taken as a direct edge because the S6 adapter needs surfaces ant-core does not re-export — `QuoteHash`/`TxHash`/`Amount`, `payment::deserialize_single_node_proof` (the S7 capture-consistency parse of the receipt's `proof_bytes`), `evm::contract::payment_vault` (per-sub-batch `payForQuotes` calldata + `MAX_TRANSFERS_PER_TRANSACTION = 256`, the D37 cap), `CLOSE_GROUP_MAJORITY`. Its own header names it "the single version-pin point" and prohibits a downstream evmlib dep (lib.rs:75-92) — honored: no evmlib line exists. =2.3.0 is exactly what ant-core 0.5.0 resolves in Cargo.lock (2.3.1 exists and is deliberately not taken). **Lockstep: moves ONLY inside an ant-core bump review (§4), never alone.** Consumed by antseal-net behind the non-default `ant-backend` feature | storage/payment wire surface; the receipt's `proof_bytes` encoding (tag + rmp) is this crate's format | S6 — landed |
| `alloy` — **pinned `=1.8.3` 2026-08-01 (S6; D33 Decision 4)**: the EVM `Provider` trait + Ethereum tx/receipt types for the external-signer flow `pay()` drives itself — each ≤256-transfer sub-batch tx submitted and its receipt awaited in-band (the D33 block-number capture source). evmlib exposes its concrete provider (`Wallet::to_provider()`) but re-exports no trait, so the trait import is unavoidably direct. =1.8.3 is what evmlib 0.9.0's caret `1.0.32` resolves in Cargo.lock; the declared features are a strict subset of evmlib's activation set, so the line adds zero packages/features to the resolved graph. **Lockstep: moves only with an evmlib move inside an ant-core bump review (§4)** | payment-tx submission + receipt capture (tx hashes/block numbers journaled into the permanent vault record) | S6 (D33) — landed |
| `bytes` — **pinned `=1.12.1` 2026-08-01 (S6)**: `prepare_chunk_payment` consumes and `DataChunk.content` carries `bytes::Bytes`; the adapter must construct the type. Exact-pinned to the version the ant-core graph already locks (zero packages added); moves only within an ant-core bump review (§4). Not format-affecting by itself — pinned for lockstep hygiene with the storage surface it feeds | storage-payload container type of the pinned upstream API | S6 — landed |
| `minicbor` (pinned `=2.3.0`, decision D7) | every hashed/signed byte flows through it | P10 (joint with F) — landed |
| `ed25519-dalek` — **pinned `=3.0.0` 2026-07-27 ([D13](decisions/D13-ed25519-dalek-pin.md); C11 probe)**: verify_strict semantics probe-proven identical to 2.2.0 (byte-identical keys/sigs), chosen for the unified signature-3/sha2-0.11/getrandom-0.4 stack shared with `ml-dsa`; ZIP-215 pubkey-parse gap closed by C12's pre-validation layer | signature format + strict-verification semantics | P11 (C sign-off) — landed (declaration-only until C12) |
| `ml-dsa` — **pinned `=0.1.1` 2026-07-27 ([D14](decisions/D14-mldsa-crate.md); C11 probe)**: primary ML-DSA-65; pre-1.0, unaudited; all three 2026 advisories patched in 0.1.1 (only CVE-2026-22705 has a RUSTSEC ID — P13 must watch GHSA/osv.dev, not RUSTSEC alone); wasm32 probe passed with executed native↔wasm bit-match | PQC signature format | P12 — landed (declaration-only until C13) |
| `fips204` — **pinned `=0.4.6` 2026-07-27 ([D14](decisions/D14-mldsa-crate.md))**: fallback impl, dormant since 2024-12 (accepted for a fallback); probe-proven byte-identical keygen + deterministic sign vs `ml-dsa`, so activation needs no re-derivation; normally consumed by no crate | PQC signature fallback | P12 — landed (declaration-only) |
| `opentimestamps` (spec pin `=0.2.0`) | `.ots` wire format. **Scope: wire-format codec only** — the calendar HTTP client is in-house (antseal-anchor); no networking surface of the crate may be used | P18 (A) |
| `blake3` — **pinned `=1.8.5` 2026-08-01 (P15; decision [D35](decisions/D35-self-encryption-dependency-mode.md))**: current stable on crates.io, and the same version ant-core 0.5.0's packaged lock records — matching is tidy, **not** load-bearing: BLAKE3 is a fixed function, and the golden vectors, not the crate version, are the determinism authority, so this pin has **no lockstep semantics** with ant-core bumps. `default-features = false` (drops `std`, the only default feature): the normal graph is pure no_std Rust (arrayref/arrayvec/cfg-if/constant_time_eq — no getrandom, no rand, no I/O, no threads); `rayon` (nondeterministic thread pool), `mmap` (I/O) and `wasm32_simd` deliberately OFF. P15 probe 2026-08-01: wasm32-unknown-unknown build passes on the pinned toolchain, and the official BLAKE3-team spec vectors match on both the x86 asm path and `pure`. Declaration-only until S4 consumes it | storage-address recomputation: S4's `compute_storage_address` and the M3 storage-linkage layer recompute ant-protocol's `compute_address` = BLAKE3-256 of the blob bytes (network consensus) | P15 (D35) — landed (declaration-only until S4) |
| AEAD/HKDF/SHA-2 stack — **HKDF/SHA-2 part nominated 2026-07-27 (C1–C4): `sha2 = "=0.11.0"`, `hkdf = "=0.13.0"`, `hmac = "=0.13.0"`** (current stable verified on crates.io; RUSTSEC clean — sha2's only advisory RUSTSEC-2021-0100 affects 0.9.7 only, hkdf/hmac have none; `hmac` is hkdf's HMAC layer, also the tests' RFC 5869 reference). **XChaCha20-Poly1305 part nominated 2026-07-27 (C9): `chacha20poly1305 = "=0.11.0"`** (current stable, same RustCrypto generation as the sha2 0.11/hkdf 0.13 pins; RUSTSEC — no advisories on record). Every permanent unit/manifest ciphertext byte comes out of it. Features `alloc` + `zeroize` only; **default features OFF so `getrandom` never enters antseal-core** (injected-RNG-only policy, C5/C9; wasm recipe is P14's). Underlying `aead`/`chacha20`/`poly1305`/`cipher` versions frozen by Cargo.lock (§3) | ciphertext format + key derivation | C |
| Unicode/NFC data crate — **nominated 2026-07-27 (G1): `unicode-normalization = "=0.1.25"`, shipping Unicode data 17.0.0 behind the frozen descriptor string `unicode-17.0.0`** ([D25](decisions/D25-unicode-normalization.md)); the data version is frozen into manifests, and every shipped table is retained forever | canonicalization output bytes | G |
| Argon2/scrypt (vault KDF) — **pinned 2026-08-01 (U6; decision [D40](decisions/D40-vault-kdf-selection.md)): `argon2 = "=0.6.0-rc.8"` (default-features off — no `alloc`, we allocate the arena fallibly ourselves per D40 §2; no `getrandom`/`password-hash` — parameters live in the AAD-bound vault header, never PHC strings; `zeroize` ON), `blake2 = "=0.11.0-rc.6"` (argon2's hash core, declared directly SOLELY to force its `zeroize` feature — argon2's own `zeroize` does not forward it, and blake2's wiping `Drop` on the BLAKE2b chaining state is gated on blake2's own feature: without this line every Argon2id H0 leaves 65 bytes of passphrase-derived state in dropped hashers, measured; the hmac-declaration precedent), `scrypt = "=0.12.0"` (default-features off; resolves onto the exact `sha2 =0.11.0` pin incl. the D88 zeroize drop-glue — no second digest generation; honest limit recorded: scrypt's internal 1 GiB B/V buffers have no wiping story, password-derived only).** Re-verified current at pin time per D40's clause: argon2 0.6.0 final is NOT out, rc.8 is newest — rc discipline as for ml-dsa (exact pin + RUSTSEC/GHSA watch). RUSTSEC check 2026-08-01: no advisories on record for argon2/blake2/scrypt at these versions. Guards: RFC 9106 §5.3 + RFC 7914 §12 known-answer vectors (`crates/antseal-cli/tests/vault_encryption.rs` — KDF output bytes are vault-format bytes) and the D88-style blake2 residue probe + manifest-declaration check (`crates/antseal-cli/tests/kdf_residue.rs`, red-direction proven 2026-08-01). The blake2 `zeroize` feature is **load-bearing** exactly like sha2's (treat removal as a §4 version bump) | vault format + passphrase-residue hygiene | U6 (D40) — landed |
| `getrandom` — **pinned `=0.4.3` 2026-08-01 (U6)**: the CLI's OS-CSPRNG backend — vault KDF salts and record nonces are drawn from it (antseal-core stays injected-RNG-only by construction, C5; the CLI is the sanctioned production caller). 0.4.3 = the version the locked graph already records (the ed25519-dalek/ml-dsa getrandom-0.4 line — no second generation added to the product graph). RUSTSEC 2026-08-01: no advisories on record for 0.4.x | secret-generation surface (same family as the rand_core row) | U6 — landed |
| `rpassword` — **pinned `=7.5.4` 2026-08-01 (U7; channel decision [D41](decisions/D41-noninteractive-passphrase-channel.md))**: the no-echo terminal prompt — the rawest secret-path input surface in the product (the passphrase transits its buffers before any type of ours can wrap it), exact-pinned on the `zeroize`-row precedent though it affects no format byte. Mechanism argued at U7: no-echo needs termios, which std does not expose; the alternatives were this small vetted crate (+`rtoolbox`; libc already in the graph via getrandom, rtoolbox's serde/serde_json resolve onto the existing exact pins) or first-party libc `unsafe` under the workspace deny. Reviewed at pin: SafeString line-buffer wiping, termios restored on drop (panic included), prompt writes to `/dev/tty` never stdout; the returned String is moved straight into C5's `SecretBuf`. Machine mode never reaches it (D51). RUSTSEC 2026-08-01: no advisories on record | secret-path input surface | U7 (D41) — landed |
| `zeroize` — **pinned `=1.9.0` 2026-07-27 (C5)** (current stable on crates.io; RUSTSEC — no advisories on record). Wiping semantics for `W`, unit/manifest keys, salts, seeds, and passphrase buffers (`MasterSecret`/`SecretBuf`/material newtypes; C5/C21). Features: `alloc` only (Vec-backed `SecretBuf`); the `derive` feature is deliberately NOT enabled — impls are manual, keeping syn/proc-macro out of antseal-core's graph | secret-hygiene behavior | C (C5) |
| `subtle` — **pinned `=2.6.1` 2026-07-27 (C6)** (current stable; 2.6.0 yanked; RUSTSEC — no advisories on record). Constant-time equality for every verdict-bearing commitment-digest comparison over adversarial bundles (MVP-SPEC.md line 121/168 checks); comparison semantics are consensus-relevant. `default-features = false` (drops `std`/`i128`; wasm-lean) | verdict-bearing comparison semantics | C (C6) |
| `rand_core` — **pinned `=0.10.1` 2026-07-27 (C5)** (current stable; RUSTSEC-2019-0035 and RUSTSEC-2021-0023 affect only <0.4.2 / 0.6.0–0.6.1). The injected-CSPRNG **trait contract** of every generation/nonce path (`MasterSecret`/`SealId` generation, C9 nonce drawing): trait-surface changes alter the public API and test determinism, hence exact-pinned. 0.10 is a pure trait crate — zero deps, zero features — so it structurally cannot pull `getrandom` into antseal-core (0.10 renamed 0.6's `CryptoRngCore` to `CryptoRng`/`TryCryptoRng`; we bound on `TryCryptoRng` and map failures to `CryptoError::RngFailure`) | injected-RNG API contract | C (C5/C9) |
| `serde` + `serde_json` (pinned `=1.0.229` / `=1.0.151` at R1) | the serialized `VerificationReport` is the R9/Q4/Q5 native↔WASM bit-match vector byte format, retained forever — serializer output drift is a silent vector break ([D29](decisions/D29-report-byte-format.md)) | R1 |

**Note on the AEAD/HKDF/SHA-2 stack row.** `sha2`'s **`zeroize` feature is
load-bearing** (D88): dropping it silently restores recoverable `W` and
GGM-seed residue in dropped hashers. Treat feature removal as a version bump
under §4, and note that the compile-time `ZeroizeOnDrop` assertions in
`crypto.rs::zeroization_sweep` do **not** catch it — the wipe is drop glue,
not a trait bound.

Three separate guards exist instead (C24), and none is redundant:

| guard | file | catches |
| --- | --- | --- |
| compile-time | `crates/antseal-core/tests/digest_zeroize_link.rs` | `digest/zeroize` off ⇒ `sha2::digest::zeroize` does not resolve ⇒ build fails. Proves `BlockBuffer`'s wiping `Drop` exists — the buffer holding `W` and the GGM parent seed. **Blind to** `sha2`'s own feature: `hmac/zeroize` forwards `digest/zeroize` too. |
| declaration | `crates/antseal-core/tests/feature_pins.rs` | the pin line itself losing `features = ["zeroize"]` — exactly the case above is blind to, i.e. `Sha256VarCore`'s chaining-state `Drop` silently vanishing. |
| behaviour | `crates/antseal-core/tests/zeroization_residue.rs` | bytes actually surviving a drop. The only layer that would outlive an upstream change of mechanism. |

The stack's other feature selections are ordinary consumption shape; this one
is a security property whose failure mode is silent, which is why it is
called out here rather than left in the row.

**`self_encryption` is prohibited, not pinned (P15, decision
[D35](decisions/D35-self-encryption-dependency-mode.md)).** Until 2026-08-01
this table carried a `self_encryption` row ("must equal the exact version
ant-core's graph locks"). D35 dissolved the need: under D32's
blob-=-one-chunk model the storage address is BLAKE3-256 of the ciphertext
bytes, so no antseal crate uses `self_encryption` for anything — and three
independent grounds (GPL-3.0 with no linking exception; mandatory
tokio/tempfile/rayon/rand deps; wasm32-hostile) disqualify it from ever
becoming a dependency. The rule is therefore a **prohibition**:
`self_encryption` must never be a *direct* dependency of any antseal crate —
it remains a transitive, never-invoked-by-us dependency inside ant-core's
graph, linked only into net/cli binaries (D6's distribution note stands).
Enforced on every run by `scripts/ci-lanes.sh dep-graph` (declared-manifest
scan plus, once the crate is in the locked graph, a resolved-graph
immediate-parent check). The old move-only-in-lockstep clause is **retired**:
the transitive version simply follows ant-core's lock and is *recorded*,
never pinned by us, at every ant-core bump (§4 checklist; S20's survey).
The `blake3` row above is D35's replacement primitive and deliberately has
no lockstep semantics of its own.

**The devnet era's containment is asserted, not conventional (P20,
2026-08-02).** P16's lockfile event resolved `ant-node` and the whole EVM
stack into `Cargo.lock`, and a lock entry is not a compile — locks cover
every member feature. `scripts/ci-lanes.sh dep-graph` therefore carries
**one containment story in three rules**, all in that single lane so a
reviewer sees them together:

1. **The default `--workspace` graph reaches none of `ant-node`,
   `ant-core`, `ant-protocol`, `evmlib`, `alloy`.** Every edge to them is
   behind `devnet-launcher/devnet` or `antseal-net/ant-backend`, both
   non-default by decision (D33, D35, D52). Measured at P20: 120 packages
   by default, 475 with `devnet-launcher/devnet` — a single non-optional
   edge added in review would move ~355 packages into every contributor's
   build and every CI lane, and nothing else would notice.
2. **`self_encryption` is a direct dependency of nothing of ours** — the
   prohibition above, declared-manifest scan plus resolved-parent check,
   both halves now with their own planted-fake self-test.
3. **`alloy` moves only with the `evmlib` that ant-core's graph locks.**
   D44 defines the accepted wallet/payment set as "what the pinned
   evmlib/alloy parse accepts", and `antseal-net` holds a direct `alloy`
   edge (evmlib re-exports no `Provider` trait), so two independent things
   name `alloy` and independent drift would silently fork that set.
   `Cargo.lock` already encodes the property: a dependency entry is
   version-**qualified** (`"alloy 1.7.0"`) if and only if the package
   resolves to more than one version, so `evmlib` listing a bare `"alloy"`
   is the lock's own statement that there is one alloy and both of us are
   on it. The lane checks that, the whole `alloy-*` family being
   single-versioned, and that the recorded `=` pin literal equals what is
   resolved.

Each rule runs its detector against a planted violation **before** the
verdict, the pattern the `secret-guard` lane established; rule 1's
self-test uses the real graph with the feature flipped on rather than a
planted string.

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
      where payment surfaces changed, P17), and the `self_encryption`
      version its graph locks re-recorded — recorded, never pinned: no
      antseal crate may depend on it directly (D35 prohibition, P15; the
      old move-only-in-lockstep clause is retired)
- [ ] For toolchain bumps: [toolchain.md](toolchain.md) procedure —
      `rust-toolchain.toml`, `rust-version`, `clippy.toml` move together in
      one commit

## 5. Toolchain and dev-tools under the same rules

- The Rust toolchain is pinned exactly in `rust-toolchain.toml`
  ([toolchain.md](toolchain.md)); MSRV = the pin; bumps follow §4.
- Dev-tools whose output or verdict the project depends on are exact-pinned
  wherever they are installed (CI workflows, scripts, docs):
  **wasm-pack**, **wasm-bindgen-cli** (must equal the `wasm-bindgen` crate
  pin — a mismatch breaks the build; **neither is installed yet**: P14's
  wasm32 test-execution and bit-match lanes use no wasm-bindgen at all, and
  pinning one now would pre-empt D18 — the equality rule is enforced from
  the moment either pin appears by `scripts/wasm-toolchain-audit.sh`, CI
  lane `wasm32-core-tests`; rationale in
  [wasm-toolchain.md](wasm-toolchain.md) §4), **cargo-deny `=0.19.8`** (its verdict
  gates merges; pinned at P13 per [D19](decisions/D19-advisory-lane.md) —
  installed with `cargo install cargo-deny --version 0.19.8 --locked` in
  both the per-PR `audit-deny` job and the weekly `advisory-cron`
  workflow, and the same version is what "run cargo-deny locally" means),
  **Python `cbor2` `==6.1.3`** (the D12 independent CBOR cross-check the
  M0 golden-vector freeze gate depends on — never enters any Rust
  dependency tree; the `the_cbor2_pin_is_exact_and_dev_tool_only` test
  refuses to let its name appear in a manifest). F14 landed the pin as
  `requirements-crosscheck.txt` (pip `--require-hashes`, D31): a SHA-256 per
  artifact PyPI publishes for 6.1.3, from which — on a machine with no pip —
  `scripts/cross-check.sh --setup` fetches and verifies a wheel into a cache
  **outside the repo**
  (`${XDG_CACHE_HOME:-~/.cache}/antseal/cbor2-6.1.3`). Two facts that
  shaped that: cbor2 6.x is a compiled **Rust/PyO3** extension with no
  pure-Python fallback (so a source install would want a Rust toolchain and
  dev headers), and a wheel is a zip — so the setup step needs no `pip`,
  no `ensurepip` and no root, **cargo-fuzz `=0.13.2`** (its verdict
  gates merges via the `fuzz-smoke` lane; pinned at Q9 — installed with
  `cargo install cargo-fuzz --version 0.13.2 --locked` in both the per-PR
  `fuzz-smoke` job and the scheduled `fuzz-nightly` workflow, and
  `scripts/fuzz.sh` **refuses to run** on any other version rather than
  silently producing a verdict from an unreviewed tool).
  The M3 reproducible wasm build makes the
  wasm-pack/wasm-bindgen versions format-provenance-relevant, exactly like
  the toolchain itself.
- **A second, dated toolchain pin exists for fuzzing only**:
  `fuzz/rust-toolchain.toml` (`nightly-2026-01-26` at Q9). cargo-fuzz needs
  nightly for `-Z sanitizer` and libFuzzer instrumentation, and the
  workspace pin — which is the MSRV — must not move for that. rustup
  resolves toolchain files from the invocation directory upward and
  `scripts/fuzz.sh` runs cargo from `fuzz/`, so the nightly governs fuzzing
  and nothing else (`fuzz/` is not an ancestor of `crates/`). It is a
  **date**, not a floating `nightly`, for the reason this whole section
  exists: a floating channel would make "the fuzzer found nothing" a
  statement about whatever compiler CI downloaded that morning. Bumps
  follow §4.

## Enforcement & cross-references

- CI (P8): `--locked` in every resolving lane; the `core-dep-graph` lane
  guards antseal-core's dependency purity.
- CI (P14): the `wasm32-core-tests` lane runs
  `scripts/wasm-toolchain-audit.sh`, which enforces the getrandom recipe on
  every wasm32 build graph and the wasm-bindgen crate↔CLI pin equality of §5
  ([wasm-toolchain.md](wasm-toolchain.md)).
- cargo-deny advisory lane, per-PR + weekly schedule (P13, M0).
- CI (Q9): the `fuzz-smoke` lane installs cargo-fuzz at the §5 pin and the
  fuzzing nightly from `fuzz/rust-toolchain.toml`; neither version literal
  is hardcoded in a workflow. `fuzz/Cargo.lock` is committed and separate
  from the workspace lockfile — the fuzz crate carries an empty
  `[workspace]` table, so `libfuzzer-sys`/`arbitrary`/`cc` structurally
  cannot reach the audited graph (`docs/testing/fuzzing.md`).
- Weekly upstream-bump check: report-only, human-reviewed PR required for
  any pin change (P19).
- PR process: [../CONTRIBUTING.md](../CONTRIBUTING.md) — its checklist
  routes every version-touching PR through §4.
- [toolchain.md](toolchain.md) — the toolchain pin governed by §5.
