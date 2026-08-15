# WASM toolchain: getrandom recipe, wasm32 test execution, bit-match lane (P14/Q5)

Normative for everything that compiles or runs on `wasm32-unknown-unknown`.
Spec basis: **MVP-SPEC.md line 153** (M0 — "WASM probe with exact getrandom
recipe … **wasm32 build in CI from day one**") and **lines 167/169** ("the
WASM build must bit-match native verification"). Tasks: `tasks/P.md` **P14**,
`tasks/Q.md` **Q5**.

Companions: [toolchain.md](toolchain.md) (the compiler pin),
[dependency-policy.md](dependency-policy.md) (§2 single declaration point,
§5 dev-tool pins), [ci-verification.md](ci-verification.md) (lane evidence +
branch-protection payload), `docs/research/C11-signature-probe.md` (the
executed native↔wasm bit-match this lane's technique descends from).

---

## 1. The lanes

| Lane | Command | Asserts |
| --- | --- | --- |
| `wasm32-core` | `cargo build -p antseal-core --target wasm32-unknown-unknown --locked` | antseal-core still *compiles* for the verifier's target |
| `wasm32-core-tests` | `cargo test -p antseal-core --lib --target wasm32-unknown-unknown --locked` then `./scripts/wasm-toolchain-audit.sh` | antseal-core's unit tests *execute* on that target; the getrandom recipe and the wasm-bindgen pin equality hold |
| `wasm-bitmatch` | `./scripts/wasm-bitmatch.sh` | every committed golden vector produces **byte-identical** output natively and under wasm32 (**Q5** — §6) |

The first two lanes land with **P14**; `wasm-bitmatch` with **Q5**, built on
the same runner technique.

All three take the toolchain exclusively from `rust-toolchain.toml`, whose
`targets` list already contains `wasm32-unknown-unknown`.

## 2. How wasm32 tests actually execute (no wasm-bindgen, no browser)

A Rust **libtest** binary built for `wasm32-unknown-unknown`:

- has **zero imports** — no JS glue, no WASI, no getrandom backend;
- exports `main` and `memory`.

So `WebAssembly.instantiate(bytes, {})` runs it, and `main(0, 0)` runs the
suite. `scripts/wasm-test-runner.mjs` does exactly that and is wired as
cargo's runner for the target in `.cargo/config.toml`, which is why plain
`cargo test --target wasm32-unknown-unknown` works instead of failing to exec
a `.wasm`.

This is the same technique the **C11** signature probe used to get an
executed (not compile-level) native↔wasm byte match on the pinned signature
crates — `docs/research/C11-signature-probe.md` §5.

**[D18, 2026-08-12] Scope of the zero-import property.** It is a property of
the **test** and **bit-match** modules — the two built here — and it does
**not** extend to the shipped verifier-page module. That module carries a
`#[wasm_bindgen]` surface, and one exported function measurably yields **4**
imports (D18 §1 e), so the page's module necessarily has an import table and
is governed instead by **D18 §5 R7's allow-list**: the imports must be exactly
the wasm-bindgen runtime shim set, every name matched against a committed
pattern. The property changes from *"asserts nothing"* to *"asserts exactly
this list"*, which is why the two runners here can keep refusing any import
(`scripts/wasm-test-runner.mjs`, `scripts/wasm-bitmatch.mjs`) without that
refusal ever reaching the page.

### What the runner can and cannot observe

`wasm32-unknown-unknown` has **no stdio**: `std` sends stdout to a sink, so
libtest's report is unreadable. Panics **abort** on this target (no unwinding
runtime), and `std::process::exit` is unsupported, so a failing test tears
the module down. The two observable outcomes are therefore:

| Outcome | Meaning |
| --- | --- |
| `main` returns `0` | every test passed |
| the module traps (`unreachable`) | a test failed — the runner **names it**, see below |

Neither distinguishes *all tests passed* from *zero tests ran*. That hole is
closed per run by the **execution witness**: `antseal_core::tests::`
`wasm_lane_execution_witness` writes an 8-byte pattern into a
zero-initialised static, i.e. into linear memory. The runner scans the
exported `memory` **before** `main` (the pattern must be absent — proving it
is not a data-section literal) and **after** (it must be present — proving
the test body ran). The pattern is assembled at run time from two `u32`
halves precisely so no 8-byte copy of it can exist in the module image.

The runner also refuses a module that has **any** import: an import means the
binary is no longer the self-contained artifact this lane promises.

#### Naming the failing test (R41)

Until R41 the entire diagnosis on a red lane was `the test binary trapped:
unreachable` — no test name, no assertion, no message. That is how R32's
fourth coupled site hid: `EXPECTED_CANONICAL_JSON` in `verify/mod.rs` was
enforced by nothing else, passed every other lane, and failed here as a bare
trap.

**Linear memory survives the trap**, and the program has already written two
things into it — no import, no JS glue, and nothing added to the crate:

1. **libtest's progress line.** libtest writes `test <name> ... ` before
   invoking a test body and `ok\n` after it. `stdout` here is a discarding
   sink *behind std's line buffer*, so the newline that would flush the line
   never arrives and the buffer still holds the line for the test that was
   running when the module aborted.
2. **The default panic hook's record**: `panicked at <file>:<line>:<col>:`
   followed by the payload — the assertion, its message, and `left`/`right`.

The runner reads both out of the exported `memory` after catching the trap.
The filter that makes this sound is the exported **`__heap_base`** global:
every test name and the panic hook's own format string are static literals in
the data section, so without it the scan would report decoys and could name
the wrong test. Matches below `__heap_base` are therefore discarded, and when
the scan finds zero or more than one candidate the runner **says so** rather
than guessing — a diagnostic that can be silently wrong is worse than none.

Measured on a deliberately failing build of `antseal-core`'s lib tests:
exactly one progress line above `__heap_base`, one panic record above it,
three static decoys correctly below it. Output shape:

```
panicked at crates/antseal-core/src/lib.rs:88:9:
assertion `left == right` failed: R41 probe: deliberate failure
  left: 1
 right: 2
::error::wasm32 test runner: test `tests::zzz_r41_probe_deliberate_failure` FAILED (module trapped: unreachable)
```

Nothing here changes what executes: the real `#[test]` functions run through
the real libtest `main`, the module still has zero imports (asserted per run),
and D18 stays open — no wasm-bindgen, no crate-type change, no JS shipped
with the product.

### Which tests run on wasm32

`--lib` only: integration tests under `crates/antseal-core/tests/` read the
filesystem (vector discovery, the UTF-8 corpus) and are native by
construction; Q5's harness covers the vector *execution* path on wasm32
instead.

Within the lib, the `test-util`/`test-vectors` feature split decides
membership (`crates/antseal-core/Cargo.toml`):

```
native  dev-dep -> antseal-core features = ["test-util"]     311 unit tests
wasm32  dev-dep -> antseal-core features = ["test-vectors"]  286 unit tests
```

The 25 native-only tests are, exactly:

- **17 property tests** in `proptest!` blocks (canon/pipeline, content/{ggm,
  unit, descriptor}, crypto/{hkdf, padding}), plus their strategy helpers.
  `proptest` is not WASM-safe — it pulls `rusty-fork` (process spawning) and
  `tempfile` (getrandom) — so the wasm32 dev-dep edge excludes it and the
  blocks carry `#[cfg(feature = "test-util")]`. Property tests are
  generative and platform-independent; the wasm32 lane exists to execute the
  *deterministic* tests on the verifier's real target.
- **7 tests** inside `test_util::{strategies, tamper}`, which live in the
  `test-util` tier for the same reason.
- **1 source-scanning test**, `crypto::domain::tests::`
  `no_other_module_hardcodes_domain_tag_bytes`, which reads the crate's own
  `src/` tree at run time. `wasm32-unknown-unknown` has no filesystem, so it
  carries `#[cfg(not(target_arch = "wasm32"))]`.

Everything else — every canonicalization, commitment, HKDF, AEAD, GGM,
manifest-codec, signature and verification unit test — runs on both.

### The two feature tiers

| Feature | Contents | Optional deps activated | May a *normal* dependency edge enable it? |
| --- | --- | --- | --- |
| `test-vectors` | `test_util::vectors` (golden-vector envelope executor), `TEST_MASTER_SECRET_W`, `manifest::fixtures`, the `FileSalt` vector-generation byte accessor | **none** | **yes** — this is what makes Q5's harness possible |
| `test-util` | `test-vectors` + `test_util::{strategies, tamper}` + the `proptest` re-export | `proptest` | never |

`test-vectors` activating **zero** optional dependencies is the load-bearing
property: it means turning it on cannot change `antseal-core`'s dependency
graph, so the `core-dep-graph` lane's verdict and the `wasm32-core` build are
unaffected no matter who enables it (verified: `cargo tree -p antseal-core -e
normal` is identical with and without the feature).

## 3. The getrandom recipe

The spec mandates both halves of the recipe simultaneously, because a mixed
workspace can carry both getrandom lines:

| getrandom line | feature knob | `--cfg` knob |
| --- | --- | --- |
| 0.1 / 0.2 | `js` | — |
| 0.3 / 0.4 | `wasm_js` | `--cfg getrandom_backend="wasm_js"` |

**Where each knob lives:**

- The **`--cfg`** half is in `.cargo/config.toml` under
  `[target.wasm32-unknown-unknown] rustflags` — set now, so it is already in
  place on the day a getrandom-bearing dependency arrives. An unused `--cfg`
  is inert.
- The **feature** half can only live on a dependency edge, so it goes in the
  manifest of whichever crate first pulls getrandom into a wasm32 build, with
  the version declared (as always) only in the root
  `[workspace.dependencies]` (dependency-policy §2):

  ```toml
  [target.'cfg(target_arch = "wasm32")'.dependencies]
  getrandom = { workspace = true, features = ["wasm_js"] }   # or ["js"] on the 0.2 line
  ```

**Today no wasm32 build graph pulls getrandom at all**, so no feature knob
exists yet. Rather than leave that as prose that can rot,
`scripts/wasm-toolchain-audit.sh` enforces it: it walks the wasm32 graphs and
fails, naming the crate and printing the stanza above, the moment a getrandom
appears without its knob.

### Audit table — which dependency sits on which line

Verified 2026-07-28 against the crates' published manifests and the committed
`Cargo.lock`. "Status" is about **our** consumption shape.

| Dependency | Feature that would pull getrandom | Chain | Line | Status here |
| --- | --- | --- | --- | --- |
| `ml-dsa =0.1.1` | `getrandom` (a **default** feature) | `crypto-common 0.2.2 → getrandom 0.4 (sys_rng)` | 0.4 | **OFF** — `default-features = false`; keygen is from the HKDF-derived seed ξ and signing is `sign_deterministic` |
| `chacha20poly1305 =0.11.0` | `getrandom` (a **default** feature) | `aead 0.6.1 → crypto-common 0.2.2 → getrandom 0.4` | 0.4 | **OFF** — `default-features = false`; nonces come from an injected `TryCryptoRng` (C9) |
| `ed25519-dalek =3.0.0` | `rand_core` | `rand_core 0.10` — **no getrandom** (see correction below) | — | OFF anyway; keys derive from `W` |
| `rand_core =0.10.1` | — | zero dependencies, zero features | — | consumed; structurally cannot pull getrandom |
| `fips204 =0.4.6` | `default-rng` (a **default** feature) | `rand_core 0.6.4 → getrandom 0.2` | 0.2 | declaration-only fallback, consumed by no crate; if ever activated use `default-features = false, features = ["ml-dsa-65"]` |
| `proptest 1.11.0` (dev) | unconditional | `rand 0.9 → rand_core 0.9.5 → getrandom 0.3.4` and `tempfile 3.27 → getrandom 0.4.3` | 0.3 **and** 0.4 | native test targets only — excluded from wasm32 by the dev-dependency target split |
| `self_encryption` (P15, M1) | not yet in the graph | — | — | when it lands, re-run the audit; P15's accept already requires a green wasm32 build |

Both getrandom entries in `Cargo.lock` (0.3.4 and 0.4.3) therefore trace to
`proptest` alone.

> **Correction to `docs/research/C11-signature-probe.md` §7.** That table
> lists `ed25519-dalek 3.0.0` + `rand_core` as reaching `getrandom 0.4` via
> `rand_core 0.10`. `rand_core 0.10.1`'s published manifest has **no
> dependencies and no features** at all, and dalek 3.0.0 takes it with
> `default-features = false`; the `getrandom 0.4 (sys_rng)` in dalek's
> manifest is a **dev**-dependency, which never reaches a downstream
> consumer. Enabling dalek's `rand_core` feature would therefore *not* pull
> getrandom. Nothing downstream of that row changes — the feature is off
> either way, and D13's "single getrandom-0.4 line" argument still holds via
> `ml-dsa`/`chacha20poly1305`.

## 4. wasm-pack / wasm-bindgen: the M0 no-pin arrangement, and the pins D18 ruled

*(Retitled 2026-08-12 by **D18**. This section was headed **"wasm-pack /
wasm-bindgen: deliberately not pinned yet"**; that title and the three reasons
below stay verbatim as the historical record of the M0 arrangement, and the
dated closing note is what changed.)*

`docs/dependency-policy.md` §5 requires **wasm-pack** and
**wasm-bindgen-cli** to be exact-pinned *wherever they are installed*, with
the CLI version **equal** to the `wasm-bindgen` crate pin.

Neither is installed anywhere in this repo, and no crate depends on
`wasm-bindgen`. That is a deliberate choice, not an omission:

1. The M0 requirement is **wasm32 test execution and a native↔WASM
   bit-match**, and both are met without wasm-bindgen (§2, §6) — the modules
   involved have zero imports, so the JS-glue generator would add nothing.
2. Pinning `wasm-bindgen` now would pre-empt **D18** (whether the shipped
   wasm-bindgen surface is feature-gated inside `antseal-core` or lives in a
   thin wrapper crate), which is **not due until M3**, and R22's
   reproducible-build pin.
3. The CLI↔crate equality constraint cannot be meaningfully verified while
   neither side exists.

So the *check* lands now and the *pins* land with D18/R22:
`scripts/wasm-toolchain-audit.sh` reports `N/A` while both are absent, and
starts enforcing equality the moment either appears — with no further wiring.
This is the same "allowed-empty, later required" idiom as Q1's mount-point
lanes.

**What the M0 arrangement does NOT commit:** no `crate-type` change to
`antseal-core`, no `wasm-bindgen` dependency, no `#[wasm_bindgen]` export
anywhere, no wrapper crate carrying a JS surface. D18 remains entirely free.

**[D18, 2026-08-12] Reason 2 is discharged.** D18 rules the surface location —
a new workspace member `crates/antseal-wasm`, target-gated `wasm-bindgen`,
closed export list — so the pin no longer pre-empts anything.
`wasm-bindgen = "=0.2.126"` (the version `Cargo.lock` already carries via the
ant-core subtree) and an equal `wasm-bindgen-cli` land **with R22**, in one
commit; `wasm-pack`'s own version is a maintainer install decision.

That last sentence is now answered, and both tools are installed on the
maintainer's machine at exact versions (2026-08-12):

```sh
cargo install wasm-bindgen-cli --locked --version 0.2.126
cargo install wasm-pack        --locked --version 0.15.0
```

`0.2.126` and **not** the newest CLI (0.2.127), because D18 rules the CLI pin
**equal** to the crate pin and the committed lock carries `wasm-bindgen
0.2.126`; `wasm-pack 0.15.0` is crates.io's `max_stable_version` as queried
2026-08-12. `docs/dependency-policy.md` §5's *"exact-pinned wherever
installed"* is therefore satisfied on this machine. Reason 3 is discharged
with them: the CLI↔crate equality now has both sides, and
`scripts/wasm-toolchain-audit.sh` moves off `N/A` the moment the **committed**
half lands — the single-line `[workspace.dependencies]` entry plus the CI/script
install line, which are one atomic edit because the audit is green only while
both are absent.

Two build-time hazards stay open and are **R22's first act to measure, not to
assume** (D18 §7 P5): whether the installed `wasm-pack`'s release path fetches
its own `wasm-bindgen-cli` when one is not on `PATH`, and whether it runs a
downloaded `binaryen`/`wasm-opt`. Either would breach D63 §5 R5's *"no network
access during the build"* fence and §5's pin-wherever-installed rule, and
`wasm-opt` is named nowhere else in this repository.

**§4's final paragraph above — "What the M0 arrangement does NOT commit" —
remains true of `antseal-core` PERMANENTLY, not merely until M3.** D18 §5 R10
makes *"no `crate-type` change, no `wasm-bindgen` dependency, no
`#[wasm_bindgen]` export in `antseal-core`"* the **ruling** rather than the
deferral. What is no longer true is only the last clause: D18 is no longer
free, and the wrapper crate carrying the JS surface is exactly what ships —
above core, never inside it.

### 4.1 Path remapping: why the shipped module carries no builder path (R25/R83)

**[2026-08-15, R25 Accept row 1.]** The tool pins above fix *which programs*
run. This subsection fixes the other half of a reproducible build: which
*machine* they ran on must not be visible in the output.

**What was wrong, measured on two runners at `08c074c`.** GitHub Actions
produced a 1 853 735 B module; this machine produced 1 853 543 B. The cause was
the builder's absolute `$CARGO_HOME` — `/home/runner/.cargo/registry` against
`/home/deb/.cargo/registry` — embedded **52 times** in each artifact, in the
`#[track_caller]`/panic-location strings of registry dependencies
(`crypto-bigint` 17, `der` 5, `ml-dsa` 4, …). Base64-expanded into D129's
single-file page, the module delta is the whole of the page delta.

**Two counts D63 §7 rule 1 leads a reader to expect are wrong for this
artifact, and both were re-measured here.** §1 (j)'s *300 checkout-path* and
*1 274 registry* occurrences were taken on the **debug** `wasm_bitmatch.wasm`.
On the **release** module `scripts/wasm-pack-build.sh` ships, the registry
count is **52** and the checkout-path count is **zero** — cargo already hands
the crate being built a relative path, so `crates/antseal-core/src/…` is what
appears. The workspace root is remapped anyway: it costs nothing today and is
exactly what starts leaking if any profile turns debuginfo back on.

**The mechanism.** `scripts/wasm-pack-build.sh` derives both prefixes from the
environment doing the building and passes them on the one `wasm-pack` command:

```
CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUSTFLAGS=
    "--remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}/registry=/cargo/registry
     --remap-path-prefix=<workspace root>=/antseal"
```

Nothing is hard-coded — that is the property under test — and the physically
resolved form of each root is added when a symlink makes it differ.

**Why that channel and not the three obvious ones.** Measured on cargo 1.92.0:

| channel | result |
| --- | --- |
| `RUSTFLAGS` / `CARGO_ENCODED_RUSTFLAGS` | **REPLACES** the whole rustflags selection — `.cargo/config.toml`'s getrandom `--cfg` (§3) silently disappears. Measured cfg count: 0. |
| `--config 'target.cfg(target_arch="wasm32").rustflags=[…]'` | **also replaces it.** The cargo book's *"all matching `target.*` entries joined together"* does not survive a `--config` override. Measured cfg count: 0. This is the one that looks safe and is not. |
| `[profile.release] trim-paths = "all"` | derives both remaps by itself and is **not stabilized**: cargo 1.92.0 refuses it in `Cargo.toml` and in `.cargo/config.toml` alike — *"feature `trim-paths` is required … not stabilized in this version of Cargo"*. Nightly is not this toolchain. |
| `CARGO_TARGET_<TRIPLE>_RUSTFLAGS` | **MERGES** with the config file's entry for the same target — the getrandom `--cfg` survives beside both remaps in one `rustc` invocation. **Adopted.** |

The replacement values are `trim-paths`'s own (`/cargo/registry`), so adopting
it once it stabilizes would not move the published footer digest.

**Why the flags are NOT in `.cargo/config.toml`.** D18 §10's rider warned that
config-level flags are per **target**, so they would move `wasm_bitmatch.wasm`'s
bytes too (§6), and asked R25 to verify rather than assume. Verified by not
touching that input at all: scoping to the invocation leaves the wasm32 **debug**
cache (the `wasm32-core-tests` lane and Q5's bit-match) and the entire **native**
cache seeing no flag change. The cost is one wasm32-release rebuild, measured at
**57 s** on the 2-core host.

Two rebuild figures, measured here because **R83** needs them for the gate's
budget: `wasm-pack-build.sh --build-only` costs **1 m 08 s** cold and
**19.2 s** warm with no source change (cargo itself 1.2 s of that; the rest is
`wasm-bindgen` and the out-dir rewrite). An always-rebuild arm for
`scripts/verifier-page-build.sh` prices at the warm figure on the common path.

**Whitespace is refused, not tolerated.** Cargo splits
`CARGO_TARGET_*_RUSTFLAGS` on spaces and offers no encoded form for the
per-target key, so a build path containing whitespace would be truncated into a
half-remapped artifact. The script dies naming the path instead.

**`--locked` is passed and separately verified, because passing it does not
work.** D63 §5 R5 (i) rules the build *"invoke `wasm-pack` … with `--locked`"*.
Measured in a scratch copy of the tree, with `Cargo.lock` deleted:

| invocation | exit | lock recreated |
| --- | --- | --- |
| `cargo build --target wasm32-unknown-unknown --release --locked` | **101** — *"the lock file … needs to be updated but `--locked` was passed"* | no |
| `wasm-pack build … -- --locked` | **0** | **yes** |

Extra options *do* reach cargo — a bogus one is rejected — so the flag is not
being dropped. **`wasm-pack` runs `cargo metadata` before the build**, that call
re-resolves and writes `Cargo.lock`, and the `--locked` build then trivially
agrees with the lock it just regenerated. In the probe the re-resolution picked
`thiserror 2.0.20` where the committed lock names `2.0.19` — a different
dependency graph, silently, which is precisely what Accept row 1 forbids.

The flag is passed anyway (it binds the build step and, measured, does not move
the digest), and the property it was meant to buy is asserted directly:
`scripts/wasm-pack-build.sh` records `sha256(Cargo.lock)` before and after the
build and fails naming the `cargo metadata` mechanism if it moved. **D63 §5
R5 (i)'s named mechanism is therefore necessary but not sufficient, and this is
the correction it needs.**

**The enforcement, and its planted fault.** `--check` and `--build-only` scan
the module *and* the glue for `$repo`, `$CARGO_HOME`, `/home/`, `/Users/` and
`/root/`, and print the count of remapped placeholders (printed, not asserted:
a dependency that stopped emitting paths is not a defect). `--self-test`'s
**third** planted fault appends the builder's `$CARGO_HOME` to a copy of the
real module and requires the scan to go red on its own message.

**The evidence for Accept row 1** (2026-08-15, all at `08c074c`):

| build | checkout path | `CARGO_HOME` | remap | SHA-256 |
| --- | --- | --- | --- | --- |
| baseline | `/home/deb/Documents/code0` (25 ch) | `/home/deb/.cargo` | on | `baee3fc9…22a3` |
| second runner, path only | scratchpad, 122 ch | `/home/deb/.cargo` | on | `baee3fc9…22a3` |
| second runner, both roots | scratchpad, 122 ch | scratchpad | on | `baee3fc9…22a3` |
| control | scratchpad, 122 ch | `/home/deb/.cargo` | **off** | `e7b722ff…d4c4` |

The three remapped builds are **byte-identical**, module and glue. The control
reproduces the pre-change in-tree artifact **exactly**, from a checkout path
97 characters longer.

That control settles one half of the disjunct D132 §1 (f) and R83 left open —
*"either the committed artifact is not from HEAD, or the build is not
reproducible from source alone"*. **The second disjunct is refuted**: at
`08c074c` the module is reproducible from source alone, on two checkout paths,
to the byte. Which leaves the first as the explanation of R83's 14 066 B — a
stale artifact — and is why R83's own mechanism, not this subsection, is what
closes it.

Sizes: module 1 853 543 B → **1 853 031 B**; page 2 517 081 B → **2 516 397 B**,
the 684 B being exactly the base64 expansion of the module's 512 B. The
per-occurrence arithmetic does not close exactly in either direction and is not
relied on: 52 × (25 − 15) predicts 520 B against 512 B measured, and the
two-runner delta first reported as *entirely* path length predicts 52 × 3 =
156 B against 192 B measured. The residual is data-section and offset encoding.
**The claim rests on the byte-identity above, not on the arithmetic** — which is
the point of measuring two runners rather than counting characters.

**The footer digest this moves** (D63 §5 R2 — untruncated, 64 ungrouped
lowercase hex), and the page it is injected into:

```
module  baee3fc9125a04429232dcb8510985b570bb682f81cc1f54ef54f8dab54522a3   1 853 031 B
page    5d4703a2920546b18114f3e8dcd23b509e33b00665602f4574793cba5ee1dbc8   2 516 397 B
```

A deployed page built before this change carries the old digest and will not
match a fresh build until it is redeployed. That is expected: the number is a
function of the module, and the module changed on purpose.

**Not measured, and therefore not claimed.** The three builds shared a locale,
a `TZ`, a `HOME`, a user and a host. The axes proven independent are the
checkout path and `$CARGO_HOME`; the rest of D63 §7 rule 2's list
(timestamps aside — three builds minutes apart agreeing rules those out at
second granularity) is untested here.

## 5. ML-DSA / fips204 on wasm32 — the C-facing probe result (P14 accept)

Input to C's `sig_policy = [ed25519]` fallback decision:

- **`ml-dsa =0.1.1` compiles for wasm32 inside `antseal-core`** (lane
  `wasm32-core`) and **its C13 unit tests execute and pass on wasm32** (lane
  `wasm32-core-tests`) — deterministic keygen from ξ, `sign_deterministic`,
  `verify_with_context`, and the canonical-rejection paths, on the real
  target, in-crate.
- This strictly strengthens C11's standalone-probe evidence (27/27
  invariants and a byte-identical transcript under wasm32).
- **Verdict: GO on the hybrid `sig_policy`. The `[ed25519]`-only fallback is
  not invoked.** `fips204` stays declaration-only; C11's probe covers it, and
  nothing on the wasm32 path depends on it.

## 6. The native↔WASM bit-match contract (Q5)

See `crates/wasm-bitmatch/README.md` for the harness and
[ci-verification.md](ci-verification.md) for the recorded evidence. In brief:

- The harness embeds every committed vector under `testdata/vectors/` at
  build time (its `build.rs` walks the tree — **no hardcoded lists**, and
  `cargo::rerun-if-changed` keeps it fresh), executes each through the exact
  `antseal_core::test_util::vectors` path the Q4 native runner uses, and
  serialises the results into a **transcript**.
- The transcript is compact JSON built under the **D29** determinism rules
  (declaration-order fields, no maps, no floats, no conditional presence,
  lowercase hex) — D29 is *recommended*, not frozen; Q14 freezes it.
- The lane produces the transcript twice — once from the native binary, once
  from the wasm32 module executed in node — and requires the two byte
  strings, and their SHA-256, to be **identical**.
- Adding a vector requires no change to the harness, the runner, or CI.
- The lane **self-tests first, every run** (`--self-test`): an injected
  wasm32-only divergence must turn the comparison red before a green
  comparison is trusted — the `secret-guard` idiom.

Substance of the comparison: each entry carries the vector's
**recomputed digest** (`VectorSummary::recomputed_digest`), a SHA-256 over
every byte the executor recomputed — length-prefixed and domain-separated.
That is Q5's "report bytes **plus recomputed digests**": a platform
divergence anywhere in the recomputation changes the digest even where it
would not (yet) flip a pass/fail verdict. Today that covers **C3's HKDF
label vectors** — the standing C3 rider to join this harness — and every
kind registered later flows in with no harness change, which is what the M2
exit criterion (anchor verification with golden vectors and a wasm32 build)
needs.

## 7. Running everything locally

```sh
cargo build -p antseal-core --target wasm32-unknown-unknown --locked   # wasm32-core
./scripts/wasm-tests.sh                                                # wasm32-core-tests
./scripts/wasm-tests.sh --self-test                                    #   its planted fault
./scripts/wasm-bitmatch.sh --self-test                                 #   its planted fault
./scripts/wasm-bitmatch.sh                                             # wasm-bitmatch
```

Since **Q125** and **Q128**, `scripts/local-gate.sh` runs both execution lanes
for you when the diff selects them — `wasm32-tests` and `wasm-bitmatch`, each
with its own `--needs-run` predicate, forced by `ANTSEAL_GATE_WASM=1/0` and
`ANTSEAL_GATE_BITMATCH=1/0` respectively. The two predicates are **asymmetric
on purpose**: a change under `testdata/vectors/` selects `wasm-bitmatch` and
not `wasm32-tests`, because `crates/wasm-bitmatch/build.rs` walks that tree and
the PQC unit suite reads no vector; a change under `crates/antseal-core/`
selects both. That is asserted, not just written down —
`./scripts/wasm-bitmatch.sh --trigger-self-test` reads the other script's
trigger list and fails if the two stop disagreeing about vectors or stop
agreeing about `antseal-core`.

`scripts/wasm-tests.sh` is what CI runs, so the lane's shell is executed
locally before it is pushed (Q43). It wraps the two steps the lane used to
spell inline — `cargo test -p antseal-core --lib --target
wasm32-unknown-unknown --locked` and `./scripts/wasm-toolchain-audit.sh`.

Requirements: the pinned toolchain (which already installs the wasm32
target) and **node ≥ 18**. Node is the wasm *host*, not a build tool — it
contributes no byte to any published artifact, so it is not exact-pinned the
way wasm-pack/wasm-bindgen are; the runners assert the floor and log the
version.

`cargo test --target wasm32-unknown-unknown` may be run from anywhere: cargo
sets the runner's working directory to the **package** root, which is why
`.cargo/config.toml` spells the runner path `../../scripts/…`.

libtest arguments (filters, `--nocapture`, …) are **not** forwarded on
wasm32: argv does not exist on this target. The runner rejects them loudly
rather than silently ignoring them — filter natively instead.

## 8. Red-lane evidence (test-of-the-test)

Every guard in this lane has been shown to go red. Executed 2026-07-28 on
toolchain 1.92.0 / node v24.12.0; recorded in
[ci-verification.md](ci-verification.md).

| Guard | Probe | Observed |
| --- | --- | --- |
| a failing wasm32 unit test | temporarily broke `version_matches_scaffold` | lane red: `the test binary trapped: unreachable` |
| **the failure names its test** (R41) | `./scripts/wasm-tests.sh --self-test` — builds a throwaway crate outside the repo with one passing and one failing `#[test]`, and asserts the runner names the failing one, does **not** name the passing one, prints the assertion message, and reports no data-section decoy | self-test green; and red under each of three planted faults — diagnostic lost (`0 libtest progress lines … cannot be named with certainty`), attribution wrong (`named a test that PASSED`), `__heap_base` filter dropped (`reported a data-section decoy`) |
| non-vacuity (zero tests ran) | temporarily perturbed the witness pattern | lane red: `main() returned 0 but the execution witness is absent — the suite ran ZERO tests` |
| getrandom recipe | `ANTSEAL_WASM_AUDIT_TARGET=x86_64-unknown-linux-gnu ./scripts/wasm-toolchain-audit.sh` — puts proptest's getrandom 0.3/0.4 into the audited graph | exit 1, both lines named, missing `wasm_js` feature and missing `--cfg` both reported |
| bit-match divergence | `./scripts/wasm-bitmatch.sh --self-test` — rebuilds only the wasm32 side with an injected platform divergence (reversed entry order + uppercased hex digests) | lane red, first differing byte and both contexts printed; the script inverts the exit code, so this is a **permanent per-run** guard, not a one-off |

The `ANTSEAL_WASM_AUDIT_TARGET` override exists **only** for that probe; it
is a documented, re-runnable self-test, not a production knob.
