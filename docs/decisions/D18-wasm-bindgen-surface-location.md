# D18 — wasm-bindgen surface location: the shipped artifact is a package, not a feature

- **Status: RESOLVED — the surface is a NEW WORKSPACE MEMBER,
  `crates/antseal-wasm` (`crate-type = ["cdylib", "rlib"]`,
  `publish = false`), whose `wasm-bindgen` edge is TARGET-GATED to
  `cfg(target_arch = "wasm32")` and whose public JS surface is a CLOSED
  export list of at most four entries returning the report's canonical BYTES, never a
  structured JS object. `antseal-core` gains no feature, no dependency, no
  `crate-type` change and no `#[wasm_bindgen]` attribute — so
  `core-dep-graph`, `gate-features --check-partition`, `wasm32-core`,
  `wasm32-core-tests` and `wasm-bitmatch` are all untouched BY CONSTRUCTION,
  not by re-testing. `wasm-bindgen` is pinned `=0.2.126` — the version the
  committed `Cargo.lock` already carries — and R22's "no I/O inside the WASM
  module" becomes STRUCTURAL through two mechanical checks that ride existing
  jobs: a reviewed-set assertion over the new package's wasm32 normal graph,
  and an ALLOW-LIST over the built module's import table.** The register's
  **dichotomy is overturned as a framing**: its two arms are not comparable
  objects — one is a package and the other is a feature — and every single
  downstream consumer of this decision addresses the shipped artifact **by
  package** (`wasm-pack`'s invocation target, D63's "the deployed `.wasm`",
  R25's `SHA256SUMS`, F29's profile, `[profile.release.package.*]`, a
  `cargo tree -p` lane, R27's parity gate). A feature is not an artifact. The
  **"thin wrapper crate" arm survives ON MEASUREMENT** as a *location*, and
  what sharpened it is four things the framing did not contain: the
  wasm-bindgen edge is **target-gated** (so the native gate never compiles
  it), the crate lives under **`crates/`** and not `verifier-web/` (measured:
  `.cargo/config.toml`'s runner path hard-codes a two-level package depth),
  the crate **name is a build-reproducibility input** (measured: the crate
  name appears 23× inside its own artifact), and the arm the register did not
  name — **target-gated-without-a-feature inside `antseal-core`** — is the
  one that would have looked cleanest and is killed outright, because a
  single `#[wasm_bindgen]` function produces **4 imports** and the
  `wasm32-core-tests` runner refuses any module with an import.
- **Date: 2026-08-12** (wave 18 Act 1b, D18 planning lane; briefed to overturn
  the dichotomy and its arms. The framing dies on the package-vs-feature
  asymmetry; one in-core variant dies on `core-dep-graph`'s measured
  blindness plus `gate-features`'s tier partition; the other dies on a
  measured import count; one arm nobody supplied — a raw C ABI with no
  wasm-bindgen at all, already proven in this tree — is refused on R22's own
  Accept row rather than on taste; and one argument this lane expected to
  make, that `#[wasm_bindgen]` breaks the workspace's `unsafe_code = "deny"`,
  was **measured and is false**, so it is recorded as refuted rather than
  quietly dropped.)
- **Owning tasks: R22** (builds the surface; its `Do` already says *"thin
  wasm-bindgen crate"*), **P14** (landed the toolchain and deliberately left
  this free), **R25/D63** (consumes the artifact identity and the pins),
  **R23** (loads the module), **F29** (the profile gap, scoped in §5 R9),
  **P5** (the scaffold row whose `Notes` said the layout must preclude
  neither arm), **P15/Q74** (owns the `core-dep-graph` idiom this extends).
- **Amends**: `tasks/R.md` R22 (`Notes`), `tasks/P.md` P5 (`Notes`) and the
  `Open decisions (P)` bullet, `docs/wasm-toolchain.md` §4,
  `docs/dependency-policy.md` §5, `docs/decisions/D63…` §7 rule 1's
  precondition list — all quoted in §11, the registrar's to apply.
  **Supersedes**: nothing. **Corrects**: nothing in code; one refuted
  hypothesis of this lane's own is recorded in §3.4 so nobody re-derives it.

---

## 1. What was measured

**(a) `core-dep-graph`'s reviewed-set check runs on DEFAULT FEATURES, so a
feature-gated dependency is invisible to it. Measured, not reasoned.**

The command is one line, `scripts/ci-lanes.sh:314`:

```sh
tree="$(cargo tree -p antseal-core -e normal --target all --prefix none --locked)"
```

No `--features`, no `--all-features`. `antseal-core` already carries an
optional dependency behind a non-default feature (`proptest`, activated by
`test-util`, `crates/antseal-core/Cargo.toml:36`), so the property is directly
testable on today's tree:

```
$ cargo tree -p antseal-core -e normal --target all --prefix none --locked \
    | sed 's/ .*//' | sort -u | wc -l
84
$ cargo tree -p antseal-core -e normal --target all --prefix none --locked \
    | grep -c "^proptest"
0
$ cargo tree -p antseal-core -e normal --target all --prefix none --locked \
    --features test-util | grep -cE "^(proptest|getrandom|rand |tempfile|rusty-fork)"
7
```

Seven packages the lane's reviewed set does not contain are one `--features`
flag away and the lane never looks. **A `wasm-bindgen` dependency inside
`antseal-core`, optional and feature-gated, therefore violates neither layer
of this lane** — not the decided-prohibition denylist
(`scripts/ci-lanes.sh:286`, which names async/network/RNG crates and no
codegen crate) and not the set equality (`:501-513`). It passes **silently**,
which is worse than failing, because the lane's own violation message states
what the set is for (`scripts/ci-lanes.sh:503`):

> `::error::Q74 violation: package(s) entered antseal-core NORMAL dependency
> graph without review. **This graph ships as the verifier page WASM** and
> MVP-SPEC.md lines 47-53 require it to do no I/O; that property is argued per
> entry by a human, not detected by this lane.`

Under a feature-gated in-core surface the sentence stops being true of what
the lane measures: the graph that ships would be `default + wasm`, and the
lane would go on green about `default`.

**(b) The same lane's scope note already states the containment principle
that decides this decision.** `scripts/ci-lanes.sh:249-254`:

> `* -p antseal-core, NOT the workspace. Edges added to antseal-net or
> antseal-anchor — A3's ureq, for instance — cannot reach this set, **because
> those crates sit ABOVE core**.`

That is the house's existing answer to "a product crate needs a dependency
`antseal-core` must not have": put the crate above core. A wasm-bindgen
surface is exactly that shape.

**(c) `--target all` means TARGET-gating is visible to the lane even though
FEATURE-gating is not.** The reviewed set contains `libc` and `fiat-crypto`
annotated *"absent on x86_64 and wasm32"* (`scripts/ci-lanes.sh:345`, `:436`)
— they are in the set only because `--target all` over-reports on purpose
(`:246-248`). This asymmetry creates the arm the register never named, and §3.3
kills it on a different measurement.

**(d) A new feature on `antseal-core` is not free: it must be classified by
`gate-features.sh --check-partition`, and both available classifications are
wrong.** The guard enumerates every declared feature of every member
(`scripts/gate-features.sh:108-126`) and requires the computed LIGHT union to
equal a literal in `scripts/local-gate.sh:207`. Today:

```
$ ./scripts/gate-features.sh --check-partition
OK: 7 declared feature(s); tier 1 compiles
[antseal-anchor/test-util,antseal-core/test-util,antseal-core/test-vectors,antseal-net/test-util],
tier 2 compiles [antseal-cli/ant-backend,antseal-net/ant-backend,devnet-launcher/devnet]
```

An unclassified feature is a hard red with a named message
(`scripts/gate-features.sh:165` — *"feature(s) NO tier compiles"*). So an
`antseal-core/wasm` feature must go somewhere, and:

- **LIGHT** puts it into `cargo clippy --workspace --all-targets --features
  "$GATE_LIGHT_FEATURES"` and `cargo test --workspace --features …`
  (`scripts/local-gate.sh:222-223`). Those are **host-target, whole-workspace**
  commands, so wasm-bindgen would be compiled into `antseal-cli`'s test
  binaries by feature unification — the gate would test a configuration
  nobody ships, which is the exact failure `gate-features.sh`'s own header
  warns about (`:26-31`: *"`--all-features` compiles the UNION of features,
  which is not the same as compiling each feature configuration — workspace
  feature unification can hide a package that does not build with only its own
  feature enabled, **which is the shape a consumer actually gets**"*).
- **HEAVY** puts it behind `HEAVY_TRIGGER_PATHS`
  (`scripts/gate-features.sh:98-106`), a **storage-touching** path list. A
  change to the wasm surface touches none of them, so the surface would be
  compiled by **no tier that runs** — the precise defect that already bit once
  and is recorded at the fix site (`scripts/local-gate.sh:202-207`:
  `antseal-anchor/test-util` *"landed the feature and did not classify it, so
  no tier compiled A24's stub servers"*).

A **crate** declares no feature and perturbs the partition not at all.

**(e) A wasm-bindgen export makes the module gain imports, and two lanes
refuse any import.** Measured on a minimal probe built offline outside the
repo (a four-line crate, `wasm-bindgen =0.2.126`, one `#[wasm_bindgen] pub fn
verify(bundle_bytes: &[u8]) -> u32`):

```
import count: 4
   __wbindgen_placeholder__.__wbindgen_describe (function)
   __wbindgen_externref_xform__.__wbindgen_externref_table_grow (function)
   __wbindgen_externref_xform__.__wbindgen_externref_table_set_null (function)
   __wbindgen_placeholder__.__wbg___wbindgen_throw_344f42d3211c4765 (function)
export count: 73
```

Both wasm runners in this repo hard-fail on a non-empty import list —
`scripts/wasm-test-runner.mjs:156-160` (*"the test binary has imports, so it
is no longer self-contained"*) and `scripts/wasm-bitmatch.mjs:51-55`. This is
the measurement that kills §3.3's arm and, in its positive form, is what §5 R7
turns into the structural enforcement of *"No I/O inside the WASM module"*.

**(f) The precedent for a separate crate is already committed, was built for
exactly this reason, and says so in its own manifest.**
`crates/wasm-bitmatch/Cargo.toml:3-11`:

> `NOT A PRODUCT CRATE. The MVP-SPEC Architecture tree lists four antseal-*
> crates plus verifier-web/ and testdata/; this is test infrastructure, never
> published (publish = false), never depended on by any product crate, and
> deliberately NOT named antseal-* so it cannot be mistaken for one. **It
> exists because the bit-match needs a wasm artifact with a custom export, and
> putting that export in antseal-core would edge into decision D18**
> (wasm-bindgen surface location, not due until M3). Nothing here uses
> wasm-bindgen: the exports are a raw C ABI over two integers.`
>
> `**It IS a workspace member — that is the point.** A bit-match between two
> builds resolved from different lockfiles would be meaningless, so this crate
> must share the single root Cargo.lock and the exact same pinned dependency
> versions as every native build.`

Its `crate-type` is `["cdylib", "rlib"]` (`:30`) with the reason written
beside it, and the crate's own module doc restates the D18 abstention
(`crates/wasm-bitmatch/src/lib.rs:38-43`). So the workspace already runs a
cdylib member producing a wasm32 artifact alongside native binaries and tests,
and the membership argument for it applies to the shipped page **with more
force**, since R22's Accept row 2 demands byte-identical reports against
native.

**(g) Text written before this decision already says "crate", three times, in
three domains.**

- `tasks/R.md:273` (R22 `Do`): *"Create the thin wasm-bindgen **crate**/exports
  over `antseal-core`"*.
- `tasks/R.md:694` (R's cross-domain expectations of P): *"P: workspace
  scaffolding for `verifier-web/` and **the wasm-bindgen crate**"*.
- `docs/decisions/D87-bitmatch-vector-carriage.md:433`: *"the M3 verifier page
  is a **separate wasm-bindgen build**, D18"*.

Three independent rows, none of them this decision's, already read the surface
as a build unit of its own. That is a measured convergence, and §2 shows it is
also the only reading under which the downstream consumers have a referent.

**(h) `.cargo/config.toml` hard-codes a two-level package depth, so the crate
cannot live at `verifier-web/`.** `.cargo/config.toml:6-11`:

> `NOTE ON CWD: cargo executes a test binary — and therefore its runner — with
> the current directory set to the **package root** … Hence the ../../ in the
> runner path below: **every wasm32-tested package lives two levels below the
> workspace root** (crates/<pkg>/, per the MVP-SPEC Architecture tree), so the
> relative path is stable for all of them`

`runner = ["node", "../../scripts/wasm-test-runner.mjs"]` (`:29`). A package
rooted at `verifier-web/` is **one** level down, so the runner path would
resolve outside the repository. There is exactly one `.cargo/config.toml` in
the tree and exactly one `[target.wasm32-unknown-unknown]` table in it.

**(i) That same singleton forbids `wasm-bindgen-test`.** The `runner` key is
per **target**, not per package, and P14 already owns it. `TODO.md:98` records
that the zero-import libtest runner was *"chosen over wasm-bindgen-test
because it runs the real `#[test]` fns, needs no wasm-bindgen pin, and **leaves
D18 free** (no crate-type change, no JS surface, nothing committed)"* — a
deviation from P14's own `Do`, which had said *"wire wasm-bindgen-test with a
headless runner"* (`tasks/P.md:166`). Adopting `wasm-bindgen-test` at R22
would require replacing that runner for the whole target and would take
`wasm32-core-tests` down with it. Two other rows still carry the pre-deviation
wording as an *"or equivalent"* (`tasks/A.md:270`, `tasks/Q.md:57`); both are
already satisfied by the harness that exists.

**(j) The `wasm-bindgen` version is not a free choice: `0.2.126` is already in
the committed lockfile.** `Cargo.lock:7476-7478`:

```
name = "wasm-bindgen"
version = "0.2.126"
source = "registry+https://github.com/rust-lang/crates.io-index"
```

with `js-sys 0.3.103` (`:4040-4042`) beside it. The reverse-dependency set in
the lock is `chrono`, `getrandom`, `iana-time-zone`, `js-sys`, `reqwest`,
`uuid`, `wasm-bindgen-futures`, `wasm-streams`, `wasmtimer`, `web-sys`,
`web-time` — i.e. the ant-core/ant-node subtree, all of it behind the
non-default `ant-backend`/`devnet` features (`cargo tree -i wasm-bindgen` on
the default graph answers *"did not match any packages"*, which is the
converse half of the same fact). **A lock is one resolution for the whole
workspace including all member features**, so an exact `wasm-bindgen` pin is a
constraint shared with the upstream payment stack. §7 rules the pin and
records the coupling.

**(k) A minimal `#[wasm_bindgen]` surface adds exactly six unreviewed
packages to a normal graph — measured, offline.** `cargo tree -e normal` over
the probe:

| package | already in `antseal-core`'s reviewed set? |
| --- | --- |
| `wasm-bindgen v0.2.126` | no |
| `wasm-bindgen-macro v0.2.126` (proc-macro) | no |
| `wasm-bindgen-macro-support v0.2.126` | no |
| `wasm-bindgen-shared v0.2.126` | no |
| `bumpalo v3.20.3` | no |
| `once_cell v1.21.4` | no |
| `cfg-if`, `proc-macro2`, `quote`, `syn`, `unicode-ident` | **yes** (`scripts/ci-lanes.sh:343`, `:461-464`) |

`rustversion` compiles but is a **build**-dependency and so never enters
`-e normal`, which is the edge kind both `core-dep-graph` and §5 R6's new rule
use. Six names is a reviewable number; §5 R6 requires each to be argued at the
site, in the Q74 style.

**(l) The crate name is inside the artifact, so naming is a reproducibility
input and not a cosmetic choice.** D63 §1 (k) measured that changing only the
output filename changes the artifact hash. Confirmed here first-hand on the
probe's own wasm32 debug artifact:

```
$ grep -a -o "wbprobe" .../wbprobe.wasm | wc -l
23
```

`wasm-pack` derives the emitted filename from the package name
(`<name_underscored>_bg.wasm`), and D63 §5 R2 makes that file's SHA-256 the
footer's displayed value. So the package name is a byte-level input to the
number the page publishes about itself: it must be chosen once, here, and
frozen.

**(m) The workspace's `unsafe_code = "deny"` is NOT tripped by
`#[wasm_bindgen]` — this lane's expected argument, measured and refuted.**
`Cargo.toml:627` denies `unsafe_code` workspace-wide with a documented
per-crate opt-out, and wasm-bindgen 0.2.126's codegen emits `pub unsafe extern
"C-unwind" fn` shims and `unsafe { … }` blocks into the consuming crate
(`wasm-bindgen-macro-support-0.2.126/src/codegen.rs:1014`, `:317`, `:519`,
`:586`, `:629`, `:2476`) and carries **zero** `allow(unsafe_code)` of its own
(grep over the whole crate: no hits). The probe nevertheless built green with
`unsafe_code = "deny"` active, and the lint was proven live by a planted fault
in the same crate:

```
$ (planted:  pub fn planted() -> u8 { unsafe { *(&42u8 as *const u8) } })
error: usage of an `unsafe` block
---selftest-exit=101---
```

So the lint fires on hand-written `unsafe` and not on the macro expansion. **No
crate-root `#![allow(unsafe_code)]` is needed by either arm**, and any future
record that reaches for this argument should stop here. (`wasm-bitmatch`'s
`#[allow(unsafe_code)]` at `src/lib.rs:277` is for its own hand-written
`unsafe(no_mangle)`, which is a different thing.)

**(n) Neither tool is installed, and the reproducible-build preconditions
D63 named are still absent.**

```
$ which wasm-pack wasm-bindgen wasm-opt
exit=1                                  # no output
$ rustc --version
rustc 1.92.0 (ded5c06cf 2025-12-08)
```

`scripts/wasm-toolchain-audit.sh:159-163` prints `N/A` and starts enforcing
crate↔CLI equality the moment either side appears, with no further wiring
(`docs/dependency-policy.md:263-300` §5; `docs/wasm-toolchain.md` §4).
`--release` still appears in CI and scripts in exactly two places, both
`cargo build --release -p devnet-launcher` (`scripts/devnet/local-up:70`,
`scripts/devnet/sepolia-up:117`), and the root manifest declares ten
`[profile.dev.package.*]` stanzas (`Cargo.toml:651-670`) — confirming both
halves of D63 §10 (i) against F29's row text, which is already ledgered and is
not re-minted here.

---

## 2. The framing, overturned: the two arms are not the same kind of thing

The register asks *feature-gated in core* **vs** *thin wrapper crate*, as if
these were two placements of one object. They are not. One is a **feature**;
the other is a **package**. Cargo, this repository's CI, and this decision's
downstream consumers all address the shipped WASM artifact **by package**, and
none of them can address a feature:

| the consumer | what it needs to name | package-scoped? |
| --- | --- | --- |
| `wasm-pack build <dir>` | a package directory | **yes** — its only argument |
| **D63 §5 R2** — "SHA-256 of the deployed `.wasm`" | one artifact with one filename | **yes** — the name comes from the package (§1 l) |
| **D63 §5 R4** — `SHA256SUMS` over the served closure | the built file set | **yes** |
| **F29** — "the page ships a release build" | a profile scoped to the shipped code | **yes** — `[profile.release.package.<name>]`; there is no per-feature profile |
| a dependency-graph lane | `cargo tree -p <pkg>` | **yes** — `-p` takes a package |
| **R27/Q19** — footer version parity | one module's exported identity | **yes** |
| `docs/dependency-policy.md` §2 | one declaration point per version | package manifests |

A feature is a *compilation switch*; an artifact is a *package output*. The
question the register asked has no symmetric answer because only one of its
arms produces a thing the rest of the system can point at. Once that is seen,
the wrapper arm is not "the winner of a close comparison" — it is the only arm
that answers the question, and the remaining work is deciding **which**
package, **where**, under **what edge shape**, with **what surface**. Those
four are §5's job and are where this record's substance is; the arm choice
itself is decided by §1's measurements before taste enters.

The same reframing pays for something nobody asked for. Because the artifact
is a package, `[profile.release.package.antseal-wasm]` can tune the shipped
codegen **without moving `antseal-core`'s native release codegen** — the idiom
the root manifest already uses ten times for `[profile.dev.package.*]`
(`Cargo.toml:651-670`). Under any in-core arm, the page's profile and the
CLI's linked-library profile are the same package's, and F29's question would
have no scope to be answered in.

---

## 3. The arms, taken to measurement

### 3.1 Feature-gated inside `antseal-core` — **refused**

- **It makes `core-dep-graph` stop describing the graph that ships** (§1 a).
  The lane runs on default features; the shipped configuration would be
  `default + wasm`; the lane's own violation text says the set it guards *"ships
  as the verifier page WASM"* (`scripts/ci-lanes.sh:503`). The failure is
  silent, which is the direction this project refuses everywhere: the lane
  would keep printing `OK: antseal-core normal graph is exactly the 84
  reviewed package(s)` about a configuration nobody deploys.
- **It forces a `gate-features` tier and both tiers are wrong** (§1 d) — LIGHT
  compiles wasm-bindgen into every host-target workspace test by feature
  unification; HEAVY compiles it only when a **storage** path changes, i.e.
  never for a wasm-surface change, which is the coverage hole the partition
  guard exists to prevent and has already caught once.
- **It puts a JS ABI inside the crate whose manifest says it must not have
  one.** `crates/antseal-core/Cargo.toml:39-41`: *"This crate must stay
  WASM-safe: no I/O, async-runtime, or network crates may enter its normal
  dependency graph (CI lane `core-dep-graph`)."* `wasm-bindgen` is the gateway
  crate for JS capability; `js-sys`/`web-sys` are the crates through which
  `fetch` becomes reachable. Under this arm, prohibiting them becomes a *new
  rule about `antseal-core`*; under §5's ruling it is a property of a
  single-purpose package that has no other job.
- **It requires `crate-type = ["cdylib", "rlib"]` on the product library**, so
  every `cargo build -p antseal-core` — native and wasm32 — additionally links
  a dynamic artifact nothing consumes, and `wasm-pack` would be pointed at
  `crates/antseal-core`, generating npm identity (`package.json`, `*.d.ts`,
  a `pkg/` directory) **for the core library**.
- Not refused on: `unsafe_code`. That argument is measured false (§1 m).

### 3.2 A thin wrapper crate — **SURVIVES ON MEASUREMENT**, and here is exactly what sharpened it

The arm survives because every objection above is answered by construction
rather than by a new check: `antseal-core` is not edited, so `core-dep-graph`
keeps measuring the graph it names, the feature partition keeps its seven
features, and the wasm32 lanes keep their zero-import property. The precedent
is committed and reasoned (§1 f), and three rows already assume it (§1 g).

Four things sharpened it, none of which the register's phrase "thin wrapper
crate" contains:

1. **The `wasm-bindgen` edge is target-gated**, not unconditional, so the
   native `cargo clippy/test --workspace` gate never compiles it (§5 R3). The
   probe compiles for the host in 12.1 s producing `libwbprobe.so` +
   `libwbprobe.rlib`, which is a real cost paid on every gate run for nothing;
   target-gating removes it, using the manifest idiom `antseal-core` already
   uses twice (`crates/antseal-core/Cargo.toml`, the two
   `[target.'cfg(…target_arch = "wasm32")'.dev-dependencies]` tables).
2. **It lives under `crates/`, not `verifier-web/`** — measured on
   `.cargo/config.toml:6-11`'s two-level runner-path invariant (§1 h), which
   would silently break for a package rooted one level down.
3. **Its name is frozen here**, because the name is inside the artifact whose
   digest the footer publishes (§1 l).
4. **"Thin" is given a closed definition** (§5 R4/R5) instead of being an
   adjective: a fixed list of exports, no `js-sys`, no `web-sys`, no async, and
   report **bytes** rather than a structured JS value — the last inherited
   from D29's own Consequences, quoted verbatim inside D65 §5: *"R21/U30 reuse
   `to_canonical_json()` for `--json`; **R22 returns the same bytes through
   wasm-bindgen** — one serialization path everywhere, so the bit-match
   contract covers the user-facing output too."*

### 3.3 The arm the register did not name: target-gated in core, no feature — **refused, on a measurement**

This variant is genuinely attractive and would have been the strongest in-core
shape: put `wasm-bindgen` under `[target.'cfg(target_arch = "wasm32")'.dependencies]`
in `antseal-core` with **no feature at all**. It fixes §3.1's worst problem —
`--target all` means `core-dep-graph` **would** see it (§1 c) and go red until
the six names of §1 (k) are reviewed in — and it needs no `gate-features`
tier, because it declares no feature.

It is killed by one number. With no feature to switch it off, the
`#[wasm_bindgen]` items compile into **every** wasm32 build of the crate,
including the libtest binary that `wasm32-core-tests` executes. A single
`#[wasm_bindgen]` function yields **4 imports** (§1 e), and the runner refuses
any module with an import (`scripts/wasm-test-runner.mjs:156-160`). The lane
goes red on its own harness, and the zero-import property — which is not
decoration but the thing that makes `WebAssembly.instantiate(bytes, {})` a
complete execution story with no JS glue (`docs/wasm-toolchain.md` §2) —
would have to be abandoned to ship the page. Recorded because it is the arm a
future reader will reach for after seeing §3.1's `--target all` observation,
and because the reason it fails is not visible from the manifest.

### 3.4 One argument this lane expected to make and could not

That `#[wasm_bindgen]` collides with `unsafe_code = "deny"` and so belongs in a
crate that can carry the opt-out. **Measured false** (§1 m), including a
planted-fault check proving the lint was live. It is written down because it is
plausible, because the codegen really does emit `unsafe` items into the
consuming crate, and because a record that only lists its surviving arguments
teaches the next reader to trust an argument that does not hold.

---

## 4. Two more arms nobody supplied

### 4.1 No wasm-bindgen at all — a raw C ABI, the `wasm-bitmatch` technique — **refused**

The strongest unsupplied arm, and the only one already **proven in this tree**:
`crates/wasm-bitmatch` ships a wasm32 cdylib with a raw C ABI over integers,
zero imports and zero JS glue, and its transcript is compared byte-for-byte
against native every run. Extending that to the page means exporting
`verify_ptr()/verify_len()` and having page JS read the report out of linear
memory. It would add **zero** dependencies, keep the zero-import assertion
usable unchanged, and eliminate the entire pin question (§7).

Refused on R22's own Accept row, not on taste:

> `Panic hook installed; malformed input returns a typed JS error object, never
> an unhandled trap` (`tasks/R.md:277`)

Both halves need JS glue. On `wasm32-unknown-unknown` panics **abort** with no
unwinding runtime and there is no stdio (`docs/wasm-toolchain.md` §2), so a
zero-import module cannot deliver a panic message to the host at all — which is
precisely why R41 had to reconstruct failures by scanning linear memory after a
trap, a diagnostic technique that is right for a CI harness and wrong for a
product surface. A "typed JS error object" is a JS value constructed across the
boundary, which is the boundary wasm-bindgen exists to be. And spec line 137
names the tool — *"No framework, no build beyond `wasm-pack`"* — while line 56
describes `verifier-web/` as *"plain HTML/JS + antseal-core compiled via
wasm-bindgen"*; a hand-rolled ABI would diverge from two frozen sentences to
save six reviewable packages.

Recorded, because it is the right answer to a different question: if the page
ever needs a second, minimal, glue-free entry point, the technique is proven
next door.

### 4.2 `verifier-web/` becomes the Cargo package — **refused**

Superficially elegant: the spec tree already names `verifier-web/`, so making
it the package root would add no directory and would leave `wasm-pack`'s
output beside the `index.html` that loads it. Refused on three measurements:

- **The runner-path invariant** (§1 h) — a package one level below the root
  breaks `.cargo/config.toml:29`.
- **D63 §5 R5's fence** requires the committed template to be *"a valid,
  loadable page on its own"* and the built artifact to differ from it by one
  token; a directory that is simultaneously the package root, the committed
  template's home and `wasm-pack`'s `pkg/` output directory makes
  "committed" versus "built" a matter of `.gitignore` discipline rather than
  of directory identity, and D63 §5 R4 additionally requires byproducts to be
  **deleted** before the sums are computed.
- **The spec calls it a static page** (line 56, quoted above) and P5's `Do`
  scaffolds it as a *"static-page stub"* (`tasks/P.md:60`).

**So `verifier-web/` does NOT become a workspace member.** That is half of
D63 §10 (iv)'s open question answered; the other half — what CI does with the
directory, and where R25's injector/drift tests live — stays with R23/R25,
where D63 left it. Its one live reference remains the R18 ban scan root in
`crates/antseal-core/tests/verdict_wording.rs` (the `root.join("verifier-web")`
entry in that file's source-scan root list; cited without a line number because
that file is being edited by a live implementation lane as this is written, so
D63 §1 (g)'s `:710` and any number quoted today would both be stale).

---

## 5. The ruling

Ten rules. "The module" = the `.wasm` file `wasm-pack` emits and the browser
loads. "The surface" = the set of `#[wasm_bindgen]` items.

**R1 — Home: a new workspace member, `crates/antseal-wasm`.** A product crate
(so `antseal-*`, unlike `wasm-bitmatch`), `publish = false` for M3 — the
artifact ships as a hosted page, not as a crate, and nothing requires a
registry release; Q31/D5's release-time naming question is untouched. It is a
**workspace member** for the reason `wasm-bitmatch`'s manifest already gives
(`crates/wasm-bitmatch/Cargo.toml:12-16`): a byte-comparison between two
builds resolved from different lockfiles would be meaningless, and R22's
Accept row 2 is exactly such a comparison. **The name is frozen by this
record** and may not be changed by an implementation lane, because it is a
byte-level input to the artifact whose digest D63 §5 R2 publishes (§1 l).

**R2 — `crate-type = ["cdylib", "rlib"]`.** `cdylib` is what
`wasm-pack`/`wasm-bindgen` require; `rlib` follows the committed precedent and
its recorded reason (`crates/wasm-bitmatch/Cargo.toml:28-30`) — it keeps native
unit tests and any future in-workspace consumer possible at no measured cost.
**`antseal-core`'s `crate-type` does not change and gains no `[lib]` section.**

**R3 — The `wasm-bindgen` edge is TARGET-GATED, never feature-gated.**

```toml
[target.'cfg(target_arch = "wasm32")'.dependencies]
wasm-bindgen = { workspace = true }
```

with the version declared **only** in the root `[workspace.dependencies]`
(`docs/dependency-policy.md` §2) and `default-features = false, features =
["std"]` there — equal to today's default set (`default = ["std"]`, measured
in `wasm-bindgen-0.2.126/Cargo.toml`) and immune to a future default-set
change. Consequences, each deliberate:

- The native `cargo clippy --workspace --all-targets` / `cargo test
  --workspace` gate compiles **no** wasm-bindgen (§3.2 (1)).
- The `#[wasm_bindgen]` items carry `#[cfg(target_arch = "wasm32")]`, so the
  crate still compiles for the host as an ordinary empty-ish library and the
  gate keeps type-checking whatever non-boundary code it holds.
- `P20 rule 1`'s default `--workspace` graph (`cargo tree --workspace -e
  normal,build,dev`, host target — `scripts/ci-lanes.sh:651`) is unmoved, so
  its printed count stays at 162 and no evidence line moves.
- **No feature is declared by this crate**, so `gate-features.sh
  --check-partition` stays at seven features and neither tier list changes.

**Prohibited outright, as decided prohibitions in the §5 R6 sense**: `js-sys`,
`web-sys`, `wasm-bindgen-futures`, `web-time`, `getrandom`, and any HTTP,
async-runtime or storage crate. `js-sys`/`web-sys` are the crates through
which host capability — `fetch`, `XMLHttpRequest`, `localStorage`, `Date` —
becomes reachable from Rust; refusing them is what makes R22's *"No I/O inside
the WASM module"* a property of the graph rather than of a reviewer's
attention.

**R4 — The public JS surface is a CLOSED list of at most four entries.** Nothing else
may be exported, and additions are a decision, not a code change:

1. `verify(bundle_bytes: &[u8]) -> JsValue` — offline verification of a
   `.sealproof`, returning the report.
2. an **online-evidence entry** taking pre-fetched endpoint responses supplied
   by page JS and returning the overlay, feeding A's WASM-safe
   must-agree/header-match core (`tasks/R.md:273`; D66's fetch shape is the
   page's, never the module's).
3. **build info** — `antseal-core` version, supported format versions, source
   commit. **D63 §5 R3 depends on this existing**: the footer renders these
   from the module's export and never from injected HTML, and R27/Q19 assert
   the rendered version equals it (the mixed-deploy detector). This entry is
   therefore load-bearing, not convenience. Whether it is one function
   returning a struct or three functions is R22's; the **class** is what this
   rule closes.
4. **D69's rung/verdict-class datum, conditionally** — `tasks/R.md:266`
   requires it to live in core *"so R22's page can state the same rung and
   R27's parity gate has something to compare"*, and JS can reach a Rust
   function only through an export. So: **if the rung is a field of the report
   bytes, the list is three entries and no fourth export exists**; if it is not,
   this fourth entry supplies it. Which of the two is D69/R21's to say, not
   this record's — what is ruled here is that the page gets the rung from the
   module and never recomputes it in JS.

Plus a panic hook installed at module init. **No self-hash entry point may
exist** — D63 §11.3 already writes that into R22's `Notes`, and R1's closed
list is what makes it enforceable rather than remembered.

**R5 — The module returns report BYTES, never a structured JS value.** The
`JsValue` R22's `Do` names is a JS **string** (or `Uint8Array`) carrying
`to_canonical_json()`'s bytes verbatim — not a JS object built by
`serde_wasm_bindgen`, `JsValue::from_serde`, or any path that re-serializes.
The reason is measured and already recorded twice: D29's Consequences (quoted
in D65 §5) require *"one serialization path everywhere, so the bit-match
contract covers the user-facing output too"*, and D65 refuses routing the
report through `serde_json::Value` because a round trip alphabetizes keys and
destroys D29 rule 1's declaration order. `wasm-bindgen`'s `serde-serialize`
feature is **prohibited** by R3 for the same reason. Page JS may `JSON.parse`
the string for layout; what it must never receive is a report that was
serialized twice.

**R6 — A reviewed-set rule over the SHIPPED configuration, in the Q74 idiom,
riding an existing job.** Add to `scripts/ci-lanes.sh`'s dep-graph lane:

```sh
cargo tree -p antseal-wasm -e normal --target wasm32-unknown-unknown --prefix none --locked
```

asserted **equal** to `antseal-core`'s reviewed set ∪ the six names measured in
§1 (k) — `wasm-bindgen`, `wasm-bindgen-macro`, `wasm-bindgen-macro-support`,
`wasm-bindgen-shared`, `bumpalo`, `once_cell` — each with the per-entry I/O
argument the lane demands, plus a layer-1 denylist carrying R3's prohibited
names so `js-sys` fails with a diagnosis instead of as "an unreviewed
package". Both directions (unreviewed arrival **and** stale entry), the
self-test-first discipline, and the anti-vacuity root check are copied from the
existing rule, not reinvented. **The target is `wasm32-unknown-unknown`, not
`--target all`**, because unlike `antseal-core` this package ships to exactly
one target and the over-reporting `--target all` buys nothing here.

**R7 — An IMPORT ALLOW-LIST over the built module: the structural half of "no
I/O".** R6 is decidable from the graph; this is decidable from the artifact,
and the two together are what make R22's `Do` sentence enforced rather than
reviewed. The existing zero-import assertion generalises: the shipped module's
import table must be **exactly** the wasm-bindgen runtime shim set, with every
name matched against a committed pattern. The measurement that makes this
sound is §1 (e): a module's imports are precisely the host functions it can
call, they are generated only from declared `extern` bindings, and a `fetch`
or `Date.now` capability cannot enter without appearing there by name. The
check runs on the artifact `wasm-pack` emits, so an R25 build or an R26 deploy
cannot introduce a capability unseen — the same "runs against the built
artifact" discipline R23's CSP Accept row already uses.

**R8 — No new required CI context.** R6 rides `core-dep-graph` (which already
bootstraps the toolchain and runs `cargo tree`) and R7 rides `wasm-bitmatch`
(which already builds a wasm32 artifact and instantiates it in node). The
required-context count stays at **19** (Q78/Q81). This is a ruling, not a
suggestion: CI minutes are a stated constraint and neither check needs a
runner of its own.

**R9 — The `--release` question, split so that neither half is unowned.**

- **D18/R22 own the boundary comparison at the shipped profile.** R22's Accept
  row 2 — *"R9 golden vectors verified through the JS boundary produce reports
  byte-identical to native"* — is executed against **the artifact `wasm-pack`
  emits**, i.e. the release build the page ships, not a debug convenience
  build. That is not an addition to R22: it is what "through the JS boundary"
  already means once the boundary has an artifact. It puts the shipped codegen
  path under comparison for the first time.
- **F29 keeps its own question**, narrowed: whether the **Q5 vector
  bit-match** (`scripts/wasm-bitmatch.sh`, debug on both sides today) gains a
  second pass at the shipped profile. F29's `Accept` already names *"D18/R22
  landing"* as the natural trigger (`tasks/F.md:408`); this record **is** that
  trigger, and it hands F29 the thing it lacked — a package the profile can be
  scoped to, via `[profile.release.package.antseal-wasm]` (§2).
- F29's row text is stale in one clause (`no [profile.*]`) and correct in the
  other (`no --release in CI`), both re-measured in §1 (n); already ledgered by
  D63 §10 (i) and not re-minted here.

**R10 — What this decision does NOT change.** `antseal-core`: no feature, no
dependency, no `crate-type`, no `#[wasm_bindgen]`, no `[lib]` section, no
manifest edit of any kind. `.cargo/config.toml`: unchanged — the wasm32
`runner` stays P14's, and **`wasm-bindgen-test` is not adopted** (§1 i); R22's
*"module loads in node and browser tests"* is satisfied by node scripts over
the `wasm-pack` output (the `scripts/wasm-bitmatch.mjs` precedent) and by
R27's playwright job. `verifier-web/` does not become a member (§4.2). No
registry key, error code, HKDF label, domain tag, golden vector or wording
snapshot moves: **zero frozen bytes**.

---

## 6. Refused shapes

| shape | refused on |
| --- | --- |
| feature-gated `wasm-bindgen` inside `antseal-core` | `core-dep-graph` runs on default features and would go **silently** green about a configuration nobody ships (§1 a, measured with `proptest`); forces a `gate-features` tier and both are wrong (§1 d) |
| target-gated `wasm-bindgen` inside `antseal-core`, no feature | the libtest binary gains the surface's imports and `wasm32-core-tests`' runner refuses any import — 4 imports measured from one exported fn (§1 e, §3.3) |
| the register's framing that these are two placements of one object | a feature is a compilation switch, an artifact is a package output; seven downstream consumers address the artifact by package and none can address a feature (§2) |
| raw C ABI, no wasm-bindgen (the `wasm-bitmatch` technique) | R22 Accept row 3's panic hook + typed JS error object need glue, and panics abort with no stdio on this target; spec lines 137/56 name wasm-bindgen and `wasm-pack` (§4.1) |
| `verifier-web/` as the Cargo package root | `.cargo/config.toml:6-11`'s two-level runner-path invariant; D63 §5 R4/R5's committed-template-vs-built-output separation (§4.2, §1 h) |
| adopting `wasm-bindgen-test` | `runner` is per **target**, there is one `[target.wasm32-unknown-unknown]` table, and P14 owns it; replacing it takes `wasm32-core-tests` down (§1 i) |
| `js-sys` / `web-sys` / `wasm-bindgen-futures` / `web-time` in the surface's graph | they are the crates through which host capability becomes reachable; refusing them is what makes "no I/O inside the WASM module" a graph property (§5 R3) |
| returning a structured JS object (`serde_wasm_bindgen`, `serde-serialize`) | a second serialization path; D29's Consequences and D65 §5 both require the wasm boundary to return `to_canonical_json()`'s bytes so the bit-match covers user-facing output (§5 R5) |
| a self-hash entry point on the module | D63 §5 R1 forbids page-side hash computation outright; R4's closed export list makes it unbuildable rather than merely forbidden |
| `#![allow(unsafe_code)]` anywhere for this surface | measured unnecessary — the lint does not fire on the macro expansion, proven with a planted fault (§1 m) |
| a new required CI context for either new check | both ride existing jobs that already have the toolchain and the artifact; 19 stays 19 (§5 R8) |
| `--target all` for the new package's dep-graph rule | it ships to exactly one target; over-reporting buys nothing and would admit names no build contains (§5 R6) |

---

## 7. The pins that land with this decision

`docs/dependency-policy.md` §5 requires `wasm-pack` and `wasm-bindgen-cli`
exact-pinned *wherever installed*, with the CLI equal to the `wasm-bindgen`
crate pin. R22 Accept row 1 (*"`wasm-pack build` succeeds with the pinned
toolchain"*) cannot be satisfied against a pin that does not exist, so the pins
are ruled here to the extent measurement allows and handed over explicitly
where it does not.

**P1 — The crate pin is `wasm-bindgen = "=0.2.126"`, and it is not a free
choice.** `Cargo.lock:7476-7478` already carries exactly that version (§1 j).
An exact pin at any other value is a constraint the upstream payment stack's
requirements must also satisfy, and a conflict surfaces as a resolution
failure rather than a duplicate — which is the right failure direction and a
real coupling. Declared in the root `[workspace.dependencies]` only (§2 of the
policy), which is also the only place `scripts/wasm-toolchain-audit.sh:151-152`
looks.

**P2 — The pin must be a SINGLE-LINE entry containing `"=0.2.126"`.** The
audit's extractor is a line grep — `grep -E '^wasm-bindgen\b' Cargo.toml` then
`sed -nE 's/.*"=([0-9]+\.[0-9]+\.[0-9]+)".*/\1/p'` — so a multi-line table
entry would yield an empty `crate_pin` while a CLI pin exists, and the check
would report the wrong diagnosis. Instrument-shaped and recorded so R22 does
not trip it.

**P3 — Crate pin and CLI install line land in the SAME commit.** The audit is
green (`N/A`) only while **both** sides are absent
(`scripts/wasm-toolchain-audit.sh:159-163`); either alone is a hard error with
its own message (`:164-169`). So the `[workspace.dependencies]` entry and the
`cargo install wasm-bindgen-cli --version 0.2.126 --locked` line in CI/scripts
are one atomic edit. No wiring is needed beyond that.

**P4 — `wasm-pack`'s own version is a MAINTAINER INSTALL decision this lane
cannot measure.** It is not installed (§1 n) and querying the registry is a
network action this lane has no consent for. What is ruled: whatever version is
chosen is exact-pinned wherever it is installed (§5 of the policy), and it is
recorded in the same commit as P1/P3, because — per D63 §7 rule 1 — *"the tool
list **is** part of the build's identity"*.

**P5 — Two build-time hazards to verify at R22 execution, flagged not
asserted.** `wasm-pack`'s release path is understood to (i) fetch a matching
`wasm-bindgen-cli` binary when one is not already on `PATH`, and (ii) run
`wasm-opt` from a downloaded `binaryen`. Either would breach **D63 §5 R5**'s
*"no network access during the build"* fence and §5's pin-wherever-installed
rule, and `wasm-opt`/`binaryen` is named **nowhere** in this repository (D63
§1 i, re-verified: `which wasm-opt` empty). **R22's first act is to measure
what the installed `wasm-pack` actually does and record it**, then either
pre-install both binaries at pinned versions so nothing is fetched, or disable
the optimizer. This is stated as a hazard because it was not measurable here,
not as a finding.

**P6 — The pin is now jointly owned with the upstream bump procedure.**
Because `wasm-bindgen 0.2.126` is reached by `reqwest`/`chrono`/`uuid`/
`getrandom`/`wasmtimer`/`web-time` inside the ant-core subtree (§1 j), an
ant-core bump can raise the floor above our exact pin and fail the resolve.
**S20's bump procedure must name `wasm-bindgen` as a coupled pin** — the same
shape as P20 rule 3's alloy↔evmlib lockstep, and cheap to record now versus
expensive to diagnose at a bump.

---

## 8. What R22 must implement (verbatim for the implementation lane)

1. **Create `crates/antseal-wasm`** per §5 R1–R3: workspace member,
   `publish = false`, `crate-type = ["cdylib", "rlib"]`, `[lints] workspace =
   true`, `wasm-bindgen` declared **only** under
   `[target.'cfg(target_arch = "wasm32")'.dependencies]` with the version in
   the root table. **Do not edit `crates/antseal-core/Cargo.toml`.**
2. **Land the pins as one commit** per §7 P1–P4, and run
   `./scripts/wasm-toolchain-audit.sh` before and after to see `N/A` become
   `OK    wasm-bindgen crate and CLI both pinned at 0.2.126`.
3. **Implement the §5 R4 exports and nothing else**, returning report
   **bytes** (§5 R5). The build-info export is D63 §5 R3's dependency and must
   carry `antseal-core`'s version, the supported format versions, and the
   source commit.
4. **Land both structural checks** (§5 R6, R7) on **existing** jobs (§5 R8),
   each with a planted fault proving it goes red before its green verdict is
   trusted — the house discipline, and specifically: R6's fault is a planted
   `js-sys` line reported by name; R7's is a planted extra import.
5. **Execute Accept row 2 at the shipped profile** (§5 R9) and record which
   profile the artifact came from in `docs/ci-verification.md`, so F29's
   remaining question is asked against a measured baseline.
6. **Add the new crate to the two wasm trigger lists** —
   `WASM_TRIGGER_PATHS` (`scripts/wasm-tests.sh:119-127`) is unaffected by
   design (the new crate is not `antseal-core`), but
   `BITMATCH_TRIGGER_PATHS` (`scripts/wasm-bitmatch.sh:139-147`) gains
   `crates/antseal-wasm/` if R7 rides that job. `wasm-bitmatch.sh
   --trigger-self-test` compares the two lists and must stay green.
7. **Do not adopt `wasm-bindgen-test`** (§5 R10). Node/browser loading is
   scripted over the `wasm-pack` output.

---

## 9. Spec conformance

- **Line 56** (*"`verifier-web/` — static page: plain HTML/JS + `antseal-core`
  compiled via wasm-bindgen"*) is honoured in substance: the shipped module
  **is** `antseal-core` compiled through the wasm-bindgen toolchain; the
  wrapper contributes a boundary and no verification logic (line 127's *"all
  verification, anchors included"* stays in core, and R23's page JS does
  *"layout only"*, `tasks/R.md:273`). `verifier-web/` remains the static page
  the line calls it (§4.2).
- **Line 137** (*"No framework, no build beyond `wasm-pack`"*) is held: this
  decision adds a Cargo package, not a build system, and `wasm-pack` remains
  the only build tool named. D63 §5 R5's closed operation list is untouched.
- **Line 153** (*"wasm32 build in CI from day one"*) and **lines 167/169**
  (*"the WASM build must bit-match native verification"*) are strengthened, not
  disturbed: the existing lanes keep their zero-import property because
  `antseal-core` is not edited (§5 R10), and §5 R9 adds the first comparison of
  the **shipped** codegen path.
- **One recorded divergence, flagged rather than taken quietly.** The
  Architecture tree (lines 44–58) lists **four** `crates/antseal-*` entries,
  and P5's Accept says *"Tree matches spec lines 44–58 exactly"*
  (`tasks/P.md:62`). `crates/antseal-wasm` is a fifth. The workspace has
  already grown two non-tree members (`wasm-bitmatch`, `devnet-launcher`), both
  justified as non-product and deliberately not `antseal-*`
  (`crates/wasm-bitmatch/Cargo.toml:3-11`) — this one **is** a product crate,
  so that escape does not apply. It is a one-line tree divergence, it is
  recorded here rather than absorbed, and §11.5 hands the registrar the choice
  between a one-line spec amendment at M4's doc pass and a standing recorded
  deviation. **No spec edit is made by this record.**

---

## 10. Residual risk (of the decision taken)

- **The module has imports, permanently, and that is a real loss.** Today every
  wasm artifact in this repo is self-contained and provable so in one line of
  JS. The shipped page's module will not be, because a typed error object and
  a panic hook require a host. §5 R7 converts the lost invariant into a weaker
  but checkable one — an allow-list instead of an empty set — and that is the
  honest description: **the property changes from "asserts nothing" to "asserts
  exactly this list"**, and the list must be reviewed on every change like any
  other allow-list in this project.
- **The glue JS is outside both checks.** R6 covers the Rust graph and R7 the
  wasm module; the `wasm-bindgen`-generated `.js` is neither. It is covered by
  D63 §5 R4's `SHA256SUMS` over the served closure and by R23's Accept that no
  external resource is fetched — not by anything in this record. Stated so
  nobody reads R6+R7 as covering the whole artifact set.
- **The reproducible build remains unproven and its tool chain incomplete.**
  D63 §9 says this already; D18 discharges one of its four named preconditions
  (this decision) and rules a second (the `wasm-bindgen` pin). Two remain
  outside this record: `--remap-path-prefix` for the workspace root and
  `$CARGO_HOME/registry`, and an optimizer either pinned or disabled. Note that
  the remap flags live in `.cargo/config.toml`'s `[target.wasm32-unknown-unknown]
  rustflags`, which is **target-scoped and applies to every wasm32 build** —
  including the bit-match and unit-test lanes. That is arm-neutral (it would be
  true under either register arm) and it is R25's to land, but it means the
  remap will move the bytes of `wasm_bitmatch.wasm` too; the Q5 lane compares
  transcripts rather than module bytes, so no lane should go red, and R25
  should verify that rather than assume it.
- **Six new packages enter a shipped graph.** `bumpalo` and `once_cell` are
  allocation and lazy-init helpers with no I/O, and the four wasm-bindgen
  crates are the boundary itself; each still needs its per-entry argument at
  the R6 site, because the whole point of the Q74 idiom is that the argument is
  made once by the human who admits the name.
- **`publish = false` is a deferral, not a decision about distribution.** If a
  downstream ever wants the bindings as a crate, that is a Q31/M4 question
  along with D5's bare-name question; nothing here forecloses it.

---

## 11. Discovered work — described, not registered

No ids are minted here.

**(i) `tasks/A.md:270` and `tasks/Q.md:57` still say "wasm-bindgen-test (or
equivalent)".** Both predate P14's deviation, both are satisfied by the
harness that exists, and §5 R10 now forbids adopting the named tool. Doc-prose
staleness with a live prohibition behind it — **ledger material**, and worth a
bracketed correction on both rows when either is next touched.

**(ii) `tasks/P.md:166` (P14's `Do`) still instructs "Install and exact-pin
wasm-pack and wasm-bindgen-cli … and wire wasm-bindgen-test".** P14 is ✅ and
`TODO.md:98` records the deviation and its reasoning, but the row's own `Do`
was never annotated. A reader arriving at P14 today is told to do three things
this project decided not to do. **Ledger material**; §11.3 supplies the note.

**(iii) The `core-dep-graph` lane's headline in `ci.yml` is broader than the
lane.** `.github/workflows/ci.yml:211-214` says *"antseal-core's NORMAL
dependency graph must never gain an async runtime, network, or I/O crate"*,
which is the overclaim `scripts/ci-lanes.sh:202-234` explicitly narrowed and
documented at length. The narrowing never reached the workflow's own comment.
Harmless today; it becomes misleading the moment a second dep-graph rule (R6)
lands beside it under the same job name. **Ledger material.**

**(iv) `verifier-web/` gains a partial answer and keeps an open half.** §4.2
rules it does **not** become a Cargo member. D63 §10 (iv)'s remaining question
— what CI does with the directory, and where R25's injector and drift tests
live — is untouched and stays with R23/R25. Recorded so the two halves are not
confused for one another.

**(v) A pre-existing hazard this lane hit and repaired in passing: none.**
`scripts/check-traceability.py` carries **zero** `D18` literals (verified:
`grep -c "D18" scripts/check-traceability.py` → `0`), so Q184's
derive-from-the-staged-tree retarget did what it claimed and resolving D18
does not disarm the self-test case Q184 was written about. Recorded because
Q184's own entry warns that it would, and a future reader deserves the
measurement rather than the warning.

---

## 12. Quoted entry notes (registrar's to apply)

### 12.1 `tasks/P.md` — `Open decisions (P)`, replace the wasm-bindgen bullet

> - wasm-bindgen surface location — feature-gated exports inside
>   `antseal-core` vs a thin wrapper crate; partially blocks P14 (test
>   harness), finally blocks R's M3 page build (R22); decide by M0, final by
>   M3. — **[2026-08-12]** RESOLVED (**D18**): a **new workspace member**,
>   `crates/antseal-wasm` (`cdylib`+`rlib`, `publish = false`), with the
>   `wasm-bindgen` edge **target-gated** to `cfg(target_arch = "wasm32")` and a
>   **closed** JS surface (at most four exports) returning canonical report
>   **bytes**.
>   `antseal-core` gains nothing — no feature, no dependency, no `crate-type`
>   change — so `core-dep-graph`, `gate-features --check-partition`,
>   `wasm32-core`, `wasm32-core-tests` and `wasm-bitmatch` are untouched by
>   construction. The **dichotomy is overturned as a framing** (a feature is
>   not an artifact; every downstream consumer addresses the shipped `.wasm`
>   **by package**), while the wrapper arm **survives ON MEASUREMENT**:
>   `core-dep-graph` runs on default features and so cannot see a feature-gated
>   edge at all, and the target-gated-in-core variant dies because one
>   `#[wasm_bindgen]` fn yields 4 imports and the wasm32 test runner refuses
>   any import. `wasm-bindgen = "=0.2.126"` (the version the lock already
>   carries), CLI equal, both landing in one commit
>   (docs/decisions/D18-wasm-bindgen-surface-location.md).

### 12.2 `tasks/P.md` P5 — replace the `Notes` line

> - Notes: Where wasm-bindgen bindings live was ruled 2026-08-12 by **D18**
>   (docs/decisions/D18-wasm-bindgen-surface-location.md): a **new workspace
>   member `crates/antseal-wasm`**, not a feature on `antseal-core` and not a
>   package rooted at `verifier-web/` — the latter refused on
>   `.cargo/config.toml`'s two-level runner-path invariant. **`verifier-web/`
>   stays a static-page directory and does not become a Cargo member.** This
>   scaffold row's *"must not preclude either"* is discharged: it precluded
>   neither, and the arm chosen needs no scaffold change. One recorded
>   divergence: the crate is a **fifth** `crates/antseal-*` entry against this
>   row's *"Tree matches spec lines 44–58 exactly"* Accept — flagged in D18 §9,
>   no spec edit made.

### 12.3 `tasks/P.md` P14 — append to `Notes`

> - Notes: **[D18, 2026-08-12]** This row's `Do` still reads *"Install and
>   exact-pin wasm-pack and wasm-bindgen-cli … and wire wasm-bindgen-test"*;
>   the execution deviated on all three and `TODO.md`'s completion line records
>   why. D18 ratifies the deviation and makes one half of it permanent:
>   **`wasm-bindgen-test` is not adopted**, because `.cargo/config.toml`'s
>   `runner` key is per **target**, there is one
>   `[target.wasm32-unknown-unknown]` table, and this row owns it — replacing
>   it would take `wasm32-core-tests` down. The pins this row deferred land
>   with **R22**: `wasm-bindgen = "=0.2.126"` (the lock's own version) in the
>   root `[workspace.dependencies]` as a **single-line** entry, plus a
>   `wasm-bindgen-cli --version 0.2.126` install line, **in the same commit** —
>   `scripts/wasm-toolchain-audit.sh` is green only while both are absent.

### 12.4 `tasks/R.md` R22 — append a second `Notes` paragraph

> - Notes: **[D18, 2026-08-12]** Surface location ruled
>   (docs/decisions/D18-wasm-bindgen-surface-location.md): a **new workspace
>   member `crates/antseal-wasm`** — `crate-type = ["cdylib", "rlib"]`,
>   `publish = false`, name **frozen** because it is the artifact's filename
>   and therefore a byte-level input to D63's published digest — with
>   `wasm-bindgen` declared **only** under
>   `[target.'cfg(target_arch = "wasm32")'.dependencies]` (version in the root
>   table, `default-features = false, features = ["std"]`). **`antseal-core` is
>   not edited at all.** The JS surface is **closed at four**:
>   `verify(bundle_bytes)`, the pre-fetched online-evidence entry, the build
>   info D63 §5 R3 depends on, and — only if D69's rung is not already a field
>   of the report bytes — the rung; plus a panic hook. It
>   returns **`to_canonical_json()`'s bytes** as a JS string — never a
>   structured value, never `serde-wasm-bindgen`, never wasm-bindgen's
>   `serde-serialize` feature — because D29's Consequences and D65 §5 both
>   require one serialization path so the bit-match covers user-facing output.
>   `js-sys`, `web-sys`, `wasm-bindgen-futures`, `web-time` and `getrandom` are
>   **decided prohibitions**: refusing them is what makes this row's *"No I/O
>   inside the WASM module"* a graph property. Two structural checks land with
>   this row and **ride existing jobs** (19 required contexts stays 19): a Q74-
>   style reviewed-set assertion over `cargo tree -p antseal-wasm -e normal
>   --target wasm32-unknown-unknown` (= core's set ∪ six measured names:
>   `wasm-bindgen`, `-macro`, `-macro-support`, `-shared`, `bumpalo`,
>   `once_cell`), and an **import allow-list** over the built module — a
>   `#[wasm_bindgen]` fn yields 4 imports, so the zero-import assertion
>   generalises rather than disappears. **`wasm-bindgen-test` is not adopted.**
>   Accept row 1's pins: `=0.2.126`, matching the lock, CLI equal, one commit.
>   Accept row 2 runs at the **shipped (release) profile**, which is what puts
>   the page's codegen path under comparison for the first time — F29 keeps
>   only the question of a second *vector* pass, and now has
>   `[profile.release.package.antseal-wasm]` to scope it with.

### 12.5 `docs/wasm-toolchain.md` §4 — retitle and rewrite the closing paragraphs

> The section title *"wasm-pack / wasm-bindgen: deliberately not pinned yet"*
> and its three reasons stay as the historical record of the M0 arrangement,
> with a dated closing note: **[D18, 2026-08-12] Reason 2 is discharged.**
> D18 rules the surface location — a new workspace member
> `crates/antseal-wasm`, target-gated `wasm-bindgen`, closed export list — so
> the pin no longer pre-empts anything. `wasm-bindgen = "=0.2.126"` (the
> version `Cargo.lock` already carries via the ant-core subtree) and an equal
> `wasm-bindgen-cli` land **with R22**, in one commit; `wasm-pack`'s own
> version is a maintainer install decision. §4's final paragraph — *"What the
> M0 arrangement does NOT commit"* — remains true of `antseal-core`
> **permanently**, not merely until M3: D18 §5 R10 makes "no `crate-type`
> change, no `wasm-bindgen` dependency, no `#[wasm_bindgen]` export in
> `antseal-core`" the ruling rather than the deferral. Add a line to §2: the
> zero-import property is a property of the **test and bit-match** modules and
> does **not** extend to the shipped page module, which necessarily has
> imports and is governed instead by D18 §5 R7's allow-list.

### 12.6 `docs/dependency-policy.md` §5 — replace the parenthetical

> **wasm-pack**, **wasm-bindgen-cli** (must equal the `wasm-bindgen` crate pin
> — a mismatch breaks the build). **[D18, 2026-08-12]** The deliberate
> no-pin state ends with R22: the crate pin is **`=0.2.126`**, which is the
> version the committed `Cargo.lock` already resolves through the ant-core
> subtree, so it is **coupled to the upstream stack** — an ant-core bump that
> raises the floor above it fails the resolve, and **S20's bump procedure must
> name `wasm-bindgen` as a coupled pin** (the alloy↔evmlib lockstep shape).
> The crate pin must be a **single-line** `[workspace.dependencies]` entry
> containing `"=0.2.126"`, because `scripts/wasm-toolchain-audit.sh`'s
> extractor is a line grep; and the crate pin and the CLI install line must
> land in the **same commit**, because the audit is green only while both are
> absent.

---

## Registrar's edit set

**This lane wrote one file: this one.** Everything below is instruction.

1. `TODO.md` decision register, the **D18** line (`TODO.md:802` at time of
   writing) → the resolved form supplied in this lane's closing report.
   *Note for the registrar*: `TODO.md:98` (P14's completion line) and
   `TODO.md:129` (F29's row) both mention D18's open state in prose; neither
   is the register row and neither needs editing, but a first-occurrence
   replacement over the whole file will hit line 98 first — anchor the edit.
2. `docs/decisions/README.md` → one index row for this record, in ascending id
   order, status/date from this record's own `- **Status`/`- **Date` lines
   (D119 RULING 1/3).
3. `tasks/P.md` — the `Open decisions (P)` bullet per §12.1; P5 gains §12.2;
   P14 gains §12.3.
4. `tasks/R.md` — R22 gains §12.4 as a **second** `Notes` paragraph beside
   D63's (do not replace D63's; they compose).
5. `docs/wasm-toolchain.md` §4 per §12.5 (and the §2 rider it names);
   `docs/dependency-policy.md` §5 per §12.6.
6. `docs/decisions/D63-…md` §7 rule 1 — the precondition list opens with
   *"**D18** ruled"*; strike that item and cite this record. The other three
   preconditions (`wasm-pack`/CLI pins, `--remap-path-prefix`, optimizer) stand,
   with the pin half now specified by §7 here.
7. `docs/instrument-ledger.md` → §11 (i), (ii) and (iii). §11 (iv) and (v) are
   observations, not findings; record at the registrar's discretion.
8. **Hand §9's spec-tree divergence to the maintainer track**: a fifth
   `crates/antseal-*` entry against MVP-SPEC lines 44–58 and P5's Accept —
   either a one-line spec amendment at M4's doc pass or a standing recorded
   deviation. **No spec edit is made here.**
9. **No edits** to `MVP-SPEC.md`, the frozen registry, `wording.rs`, any
   snapshot, any code, or any fixture are requested by this ruling. **Zero
   frozen bytes.**

---

## Outcome

The register asked where the wasm-bindgen attributes should live and offered
two homes. The measurements say the question was mis-shaped: one candidate is a
package and the other is a compilation switch, and everything downstream of
this decision — `wasm-pack`'s only argument, the digest D63 puts in the footer,
the sums R25 publishes, the profile F29 asks about, the graph a lane can walk,
the parity R27 compares — can name a package and cannot name a feature. A
feature is not an artifact.

Having seen that, the arms still had to be measured, and they failed in
instructive and different ways. Feature-gating inside `antseal-core` fails
**silently**: the lane whose error message says *"this graph ships as the
verifier page WASM"* runs on default features, so it would have gone on
printing `84 reviewed packages` about a configuration nobody deploys — proven
on today's tree with `proptest`, an optional dependency the lane already cannot
see. The variant nobody named — target-gating inside core, which fixes exactly
that blindness because the lane runs `--target all` — fails **loudly and
immediately**: one exported function produces four imports, and both wasm
runners in this repository refuse a module with any import. And the arm with
the most elegance, a raw C ABI with no wasm-bindgen at all, is already proven
next door in `wasm-bitmatch` and still cannot deliver the typed JS error and
the panic hook R22's own Accept row demands, because panics on this target
abort into a target with no stdio.

What the wrapper arm needed was not a defence but a definition. "Thin" is now
a closed list of at most four exports that return the report's canonical bytes and
nothing structured; the dependency edge is target-gated so the native gate
never compiles it; the crate sits under `crates/` because a runner path
two levels up says so; its name is frozen because the name is 23 bytes inside
its own artifact and therefore inside the digest the page publishes about
itself. And the sentence in R22 that would otherwise have been enforced by
review — *"No I/O inside the WASM module"* — becomes two mechanical checks
that ride jobs which already exist: what the graph may contain, and what the
built module may import. The second one is the honest heir to the zero-import
property this decision spends: the shipped page cannot keep an empty import
table, but it can keep an enumerated one, and an enumerated import table is a
complete statement of everything the module can ask the browser to do.
