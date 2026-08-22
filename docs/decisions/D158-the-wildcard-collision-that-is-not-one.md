# D158 — There is no collision. cargo-deny already exempts all nine of the dev edges, the fix is one line each and never touches the workspace table, and the row's "unavoidable" came from a single false comment at `Cargo.toml:62-63` that propagated into D72 and back out into the row

- **Status: RESOLVED. The lean is OVERTURNED ON TWO OF ITS FOUR CLAUSES AND
  CONFIRMED ON THE OTHER TWO. The brief's four corrections are all CONFIRMED,
  one of them with an off-by-one, and THREE MORE were found.** The lean was
  *"D72 §2 R8 already decides it: record the intent, fix the §2 R5
  misattribution, leave the dev-deps alone, and close the row."*
  - **CONFIRMED: record the intent, and fix the misattribution.** The sentence
    the row quotes twice is verbatim at `D72:562`, under the heading `### §2 R8`
    at `:560`. `§2 R5` (`:506`) is the GitHub-Releases channel ruling and says
    nothing about crates.io beyond a parenthetical (§1.10).
  - **CONFIRMED, and it is the ruling's centre: leave the nine edges alone.**
    But **not** for the lean's reason. They are left because three *further*
    publish blockers are unfixed (§1.9), because `cargo package --workspace`
    may already make the row's headline false and nobody has run it (§1.8.3),
    and because a planner barred from `cargo` cannot prove a manifest edit
    works. Not because the fix is hard — the fix is **nine single-line edits**
    and it is written out in full at §2 R4 so the next lane does not re-derive
    it.
  - **OVERTURNED: the row is NOT closed.** D72 §2 R8 discharges **Accept row 1
    and nothing else**. §2 R8's own disposition sets a **review date — the first
    release after M4** — and D72 §5.1 says *"§5.1's task must be done first"* if
    a real publish is ever wanted. Ticking Q241 now deletes the only row
    carrying that cost into the review date D72 itself set (§2 R1).
  - **OVERTURNED ON ITS FRAMING: there is no collision, and the row's own
    closing sentence is false on both halves.** cargo-deny 0.19.8 exempts a
    wildcard path dep when the krate is private **or the edge is a
    dev-dependency** (`src/bans.rs:984-989`), `deny.toml:81` already sets
    `allow-wildcard-paths = true`, and **all nine edges are
    `DependencyKind::Development`**. Measured on a synthetic workspace and
    fault-planted: with the flag on, only the *normal* public edge reds; with it
    off, all three crates red (§1.3). The row ends *"the fix lands on the
    workspace table, which is what makes the collision unavoidable"* — the fix
    does **not** land on the workspace table (it lands on nine per-crate lines,
    §1.5) and the collision does **not** exist.
  - **The false sentence has exactly one home, and it is not a decision
    record.** `Cargo.toml:62-63` — *"the cargo-deny bans lane (P13, deny.toml)
    rejects wildcard requirements workspace-wide, path deps included"* — is
    false against the pinned checker. `deny.toml:77-79` states the **opposite
    and correct** thing, and `D19:51-53` is also correct. D72 §1.6 and §5.1 took
    the `Cargo.toml` comment at its word without running the counterfactual, and
    the row inherited it from D72. **One comment turned an XS row into an M row
    and gave a decision record a false premise** (§1.6).
  - **NEW, and it kills the row's "only route" claim: `scripts/reserve-crates.sh`
    is structurally incapable of seeing this.** Its `cargo publish --dry-run` at
    `:191` runs on a **synthesized six-line placeholder** built by
    `make_placeholder()` into `$(mktemp -d)`, with **zero dependencies** — never
    on `crates/antseal-*`. The tree already records the proof: P2's runbook
    (`docs/naming/P2-crates-reservation-runbook.md:109`) says *"`cargo publish
    --dry-run`: **green for all five**"* on the same day `-p antseal-core` exits
    101. **Nothing in this tree can see the failure — not CI, not by hand**
    (§1.7).
  - **NEW: the count is nine, not seven or eight.** The brief's eighth
    (`antseal-core/Cargo.toml:153`, `test-vectors`, in the `cfg(wasm32)` dev-dep
    table) is confirmed. A **ninth** exists at `antseal-wasm/Cargo.toml:113`,
    exempt from the packaging problem only because that crate carries
    `publish = false` (`:49`) — but it is the same idiom and a fix that changes
    eight and leaves one splits the house pattern (§1.2, §2 R4).
  - **NEW: the version bump is answered, and the answer is worse than "no".**
    For the two **self**-edges the requirement is `=<the crate's own version>`
    resolved against the registry, and cargo requires that same requirement to
    be satisfied by the local copy — so it is **forced** to equal a version that
    is by definition not yet published. **No number fixes it. It is
    unconditional, not a `0.0.0` artefact** (§1.8). Accept row 4 is answered
    here, not owed.
  - **NEW: three further publish blockers, and only one is on any row.**
    `0.0.0` is burned; **no `description` exists on any crate or in
    `[workspace.package]`**, which is a hard `cargo publish` error, and D72
    §1.6 expected it *"at M4/Q29"* — Q29 ticked 2026-08-17 having landed
    `license` only, so that expectation died with its owning row; and the
    multi-package `cargo package` mode has never been run here (§1.9).
  - **No checker is minted, on measured yield.** The "nothing may publish" form
    returns **6 findings over `scripts/` + `.github/`, all 6 false positives**,
    and **0 hits in `.github/`** — green-by-construction. The packaging check
    D72 §6 actually asked for **cannot be added while it is red**, which makes
    Accept row 2 and "leave the edges alone" mutually exclusive as written
    (§1.11, §2 R7).
- **Date: 2026-08-22**
- **Owning task: Q241.** Rulings touch `TODO.md`'s Q241 row, `tasks/Q.md`'s Q241
  entry (`:2977-2990`), and `Cargo.toml:60-63`. **No new id is assigned and no
  row is minted** — §2 R11 states why, and §4 states what the registrar lands.
- **What it blocks: nothing.** Measured: `grep -rn "Q241"` over `TODO.md`,
  `tasks/`, `docs/` and `scripts/` returns five hits — the row itself
  (`TODO.md:837`), its entry (`tasks/Q.md:2977`), a wave note (`TODO.md:91`), a
  wave brief (`docs/waves/wave-26-brief.md:21`), and one **consumer annotation**
  (`tasks/Q.md:3149`, *"relevant to Q241 (the publish blocker)"*). **No `after`
  run anywhere names Q241.** It is a leaf, and every ruling below is therefore
  safe against the cycle class D154 measured.
- Related: **D72 §2 R8** (the ruling that discharges Accept row 1 — *not* §2 R5),
  **§2 R5** (what the row actually cited), **§1.6** (`PKG_CORE_EXIT=101`, and the
  false premise it inherited), **§5 item 1** (*"the fix collides with P13's
  wildcard ban"* — the same false premise, and the source of *"must be done
  first"*), **§6 item 1** (the registration: size **S**, and the instrument it
  named); **D19 §advisory-lane `:51-53`** (correct, and mis-cited by the row);
  **D141 §2 R1** (Q31 performs no release execution — why the `after Q31` term
  cannot mean what it looks like); **D154 §2 R1** (the strike-plus-annotation
  instrument), **§2 R10** (rule 7's four-surfaces test, applied at §2 R5),
  **§2 R11** (mint nothing); **D125 / TODO.md rule 8** (why §2 R9's findings go
  to the ledger without ids); **TODO.md rule 7** (the authority for §2 R5).

---

## 1. What was measured

**Provenance.** Measured 2026-08-22 against the **working tree**, not `HEAD`.
`git status --porcelain` at the start of this lane reported `TODO.md`,
`tasks/Q.md`, `docs/signing/key-custody.md` and
`docs/signing/maintainer-key-procedure.md` as modified-uncommitted. **Re-read at
the close of this lane, `crates/antseal-core/Cargo.toml` had become dirty under a
concurrent lane** — U76 appending a `[[bin]] metric-vault-fp` with
`required-features = ["test-util"]` **after `:154`**. Re-measured after that
change: the two edges this record cites in that file are still at **`:135`** and
**`:153`**, unmoved, because the insertion is at the end of the file. `deny.toml`,
the other four manifests and `docs/decisions/D72-…` are clean. The new `[[bin]]`
does not change any ruling here — a bin whose `required-features` are unmet is
shipped in the tarball and not built — but it is a **third** consumer of
`test-util` inside a publishable crate, and §2 R4's fix table is keyed to exact
old strings as well as line numbers for exactly this reason. **No `cargo build`,
`cargo test`, `cargo package` or `cargo publish` was run by this lane** — the
build lock is held by other lanes and this record is explicit at §3 about which
claims are therefore deductions rather than executions. The two cargo-deny runs
below are on **synthetic workspaces in the scratchpad**, with
`CARGO_TARGET_DIR` set outside the project; nothing in `/home/deb/Documents/code0`
was written except this file.

**All locators in the brief were re-measured. All are correct except one count
word**, corrected at §1.4.

### 1.1 The registry index: five placeholders, no features, none yanked

`~/.cargo/registry/index/index.crates.io-1949cf8c6b5b557f/.cache/an/ts/` holds
exactly five entries, one per reserved name. Each carries a single version:

```
{"name":"antseal",       "vers":"0.0.0","deps":[],"features":{},"yanked":false,"pubtime":"2026-08-11T13:48:44Z"}
{"name":"antseal-core",  "vers":"0.0.0","deps":[],"features":{},"yanked":false,"pubtime":"2026-08-11T13:49:17Z"}
{"name":"antseal-net",   "vers":"0.0.0","deps":[],"features":{},"yanked":false,"pubtime":"2026-08-11T13:50:23Z"}
{"name":"antseal-anchor","vers":"0.0.0","deps":[],"features":{},"yanked":false,"pubtime":"2026-08-11T13:49:50Z"}
{"name":"antseal-cli",   "vers":"0.0.0","deps":[],"features":{},"yanked":false,"pubtime":"2026-08-11T13:50:57Z"}
```

`"features":{}` on all five is the whole cause, and `"deps":[]` is §1.7's
evidence: these were packaged from `reserve-crates.sh`'s synthesized manifests,
which declare no dependencies at all, not from the workspace crates. **The cause
is confirmed with no cargo run.** The `=0.0.0` requirement arrives from
`Cargo.toml:64` (`antseal-core`), `:70` (`antseal-net`), `:76`
(`antseal-anchor`); there is **no `antseal-cli` entry** in
`[workspace.dependencies]`, because nothing depends on it.

### 1.2 The edges: nine, not seven. The row's list is a filter artefact

The row filters on `features = ["test-util"]`, which is why it stops at seven.
The complete set of `[dev-dependencies]`-class edges on an `antseal*` crate that
inherit `[workspace.dependencies]`:

| # | file:line | dep | feature | table | on a publishable crate? |
|---|---|---|---|---|---|
| 1 | `crates/antseal-core/Cargo.toml:135` | `antseal-core` **(self)** | `test-util` | `[target.'cfg(not(target_arch = "wasm32"))'.dev-dependencies]` | yes |
| 2 | `crates/antseal-core/Cargo.toml:153` | `antseal-core` **(self)** | `test-vectors` | `[target.'cfg(target_arch = "wasm32")'.dev-dependencies]` | **yes — the eighth** |
| 3 | `crates/antseal-net/Cargo.toml:117` | `antseal-net` **(self)** | `test-util` | `[dev-dependencies]` | yes |
| 4 | `crates/antseal-net/Cargo.toml:122` | `antseal-core` | `test-util` | `[dev-dependencies]` | yes |
| 5 | `crates/antseal-anchor/Cargo.toml:64` | `antseal-core` | `test-util` | `[dev-dependencies]` | yes |
| 6 | `crates/antseal-cli/Cargo.toml:126` | `antseal-net` | `test-util` | `[dev-dependencies]` | yes |
| 7 | `crates/antseal-cli/Cargo.toml:132` | `antseal-core` | `test-util` | `[dev-dependencies]` | yes |
| 8 | `crates/antseal-cli/Cargo.toml:139` | `antseal-anchor` | `test-util` | `[dev-dependencies]` | yes |
| 9 | `crates/antseal-wasm/Cargo.toml:113` | `antseal-core` | `test-vectors` | `[dev-dependencies]` | **no — `publish = false` at `:49`** |

**The brief's eighth is confirmed and a ninth is added here.** Both extra edges
request `test-vectors`, not `test-util`, which is exactly why both escaped every
grep this row has been re-measured with — including D72's.

Edge 2 is not cosmetic: it sits on a **publishable** crate, it is a **self**-edge,
and a `cfg`-gated dev-dep is still resolved when packaging, because the packaged
`Cargo.lock` covers every target. It fails for the same reason edge 1 does, with
`test-vectors` in place of `test-util`.

Edge 9 is exempt from the packaging problem for one reason only — `cargo package`
is never run on a `publish = false` crate — and is *not* exempt from the idiom.
`antseal-wasm/Cargo.toml:102-104` states why the edge is a **dev** edge in the
first place: *"dev-dependencies are a different edge kind from `-e normal`, so
the R6 dep-graph rule's set is unaffected and the fixture catalogue never reaches
the shipped page module."*

**Every one of the four publishable crates is affected**, which makes the row's
headline true: `antseal-core` (self), `antseal-net` (self + core), `antseal-anchor`
(core), `antseal-cli` (net + core + anchor).

### 1.3 cargo-deny 0.19.8 exempts every one of the nine — read, then measured, then fault-planted

The pinned checker is `cargo-deny 0.19.8` (`.github/workflows/ci.yml:729`,
`cargo install cargo-deny --version 0.19.8 --locked`; `~/.cargo/bin/cargo-deny
--version` → `cargo-deny 0.19.8`). Its source was extracted from
`~/.cargo/registry/cache/index.crates.io-*/cargo-deny-0.19.8.crate`.
`src/bans.rs:977-990`:

```rust
for mdep in manifest.deps(false) {
    if mdep.dep.req != VersionReq::STAR {
        continue;
    }

    // Wildcards are allowed for path or git dependencies, if the krate
    // is private, or it's only a dev-dependency
    if allow_wildcard_paths
        && !mdep.krate.is_registry()
        && (is_private
            || mdep.dep.kind == DependencyKind::Development)
    {
        continue;
    }
```

`is_private` is `krate.is_private(&[])` at `:973` — `publish`-derived. `deny.toml`
sets `wildcards = "deny"` at `:80` and **`allow-wildcard-paths = true` at `:81`**.

**Measured, not inferred.** A three-member synthetic workspace was built in the
scratchpad: `wca` (public; one **normal** wildcard path dep on `wcb`; one
**self dev** wildcard), `wcb` (public; one **dev** wildcard on `wca`), `wcp`
(`publish = false`; one **normal** wildcard on `wcb`), with a `deny.toml` whose
`[bans]` mirrors the project's three fields. `cargo-deny --offline check bans`:

```
error[wildcard]: found 2 wildcard dependencies for crate 'wca'. allow-wildcard-paths
is enabled, but does not apply to public crates as crates.io disallows path dependencies.
  ┌─ …/wc/wca/Cargo.toml:8:17
8 │ wcb.workspace = true
  │                 ━━━━ wildcard dependency
bans FAILED
REAL_EXIT=2
```

**One crate flagged, one edge inside it, and it is the normal one.** `wca`'s own
self **dev** edge is not flagged. `wcb` — whose only wildcard is a dev edge — is
not flagged at all. `wcp` — a private crate with a **normal** wildcard — is not
flagged at all. (The *"2"* in the message counts diagnostic **labels**: cargo-deny
pushes a second label pointing at the workspace declaration for each offending
dep.)

**The fault plant.** `allow-wildcard-paths` flipped to `false`, same tree, same
command:

```
error[wildcard]: found 4 wildcard dependencies for crate 'wca'
error[wildcard]: found 2 wildcard dependencies for crate 'wcb'
error[wildcard]: found 1 wildcard dependency for crate 'wcp'
bans FAILED
REAL_EXIT=2
```

Three crates, up from one; `wca` 2 labels → 4; the dev-only crate and the
private crate both appear. **So the check sees all four wildcards and the
exemption is what silences three of them** — its silence in the first run is a
measurement, not a blind spot. Flag restored to `true` afterwards.

### 1.4 What *would* red is the normal edges — and that is what the workspace-table version is actually for

The normal edges inheriting `[workspace.dependencies]`:

| file:line | dep | crate is | reds if the workspace version is dropped? |
|---|---|---|---|
| `crates/antseal-net/Cargo.toml:68` | `antseal-core` | public | **yes** |
| `crates/antseal-anchor/Cargo.toml:26` | `antseal-core` | public | **yes** |
| `crates/antseal-anchor/Cargo.toml:35` | `antseal-net` | public | **yes** |
| `crates/antseal-cli/Cargo.toml:53` | `antseal-core` | public | **yes** |
| `crates/antseal-cli/Cargo.toml:57` | `antseal-anchor` | public | **yes** |
| `crates/antseal-cli/Cargo.toml:63` | `antseal-net` | public | **yes** |
| `crates/antseal-wasm/Cargo.toml:65` | `antseal-core` | **private** | no — `is_private` |

**Correction to the brief, and it is an off-by-one in a count word, not in a
locator.** The brief says *"the **seven** normal edges … (`antseal-net:68`,
`antseal-anchor:26,35`, `antseal-cli:53,57,63`)"* and then gives the reason the
seventh is different. There are seven such edges; **six** of them would red. The
six it lists are the six, and they are correct.

So: **the version on the workspace table is load-bearing, and it stays.** What is
not load-bearing is the version *inherited onto the nine dev lines*, which is
where the packaging failure comes from and which no rule requires.

### 1.5 The arm nobody listed, measured green: declare the path on the dev line

A second synthetic workspace: `[workspace.dependencies]` **keeps**
`version = "=0.0.0"` on both entries (so the normal edge is not a wildcard at
all), while the dev lines are written directly, including one in a
`[target.'cfg(target_arch = "wasm32")'.dev-dependencies]` table to mirror edges
1, 2 and 9:

```toml
[dependencies]
wcb.workspace = true                                   # normal: keeps "=0.0.0"

[dev-dependencies]
wca = { path = ".", features = ["tu"] }                # self dev, no version

[target.'cfg(target_arch = "wasm32")'.dev-dependencies]
wcb = { path = "../wcb", features = ["tu"] }           # cfg-gated dev, no version
```

`cargo-deny --offline check bans` → **`bans ok`, `REAL_EXIT=0`.** Fault-planted
the same way: with `allow-wildcard-paths = false` the same tree gives
`error[wildcard]: found 2 wildcard dependencies for crate 'wca'`, `REAL_EXIT=2`.
**So the checker does see both dev lines — the `cfg`-gated one included — and
classifies both as `DependencyKind::Development`.** The green is an exemption,
not an oversight.

The packaging half of this arm is documented rather than executed by this lane.
Two independent statements, plus the project's own:

- Cargo Book, *Specifying Dependencies*: **"When a package is published, only
  dev-dependencies that specify a `version` will be included in the published
  crate."**
- `cargo package(1)` for the pinned toolchain
  (`~/.rustup/toolchains/1.92.0-x86_64-unknown-linux-gnu/share/doc/rust/html/cargo/commands/cargo-package.html`):
  *"Path dependencies are not allowed unless they have a version key. Cargo will
  ignore the `path` key for dependencies in published packages. **dev-dependencies
  do not have this restriction.**"*
- **D72 §5.1 already says it**: *"Dropping the version makes the dev-dep a bare
  path dep (which cargo strips at package time, unblocking the publish)"*. D72
  had the mechanism right and only the consequence wrong.

Two arms were considered and are refused. **(g) Move the version down onto the
six normal lines and leave the workspace table version-less** — symmetric, works
for both checks, and breaks `Cargo.toml:52-54`'s *"SINGLE version-declaration
point … declared HERE and only here"* in six places instead of zero. **(j) A
second `[workspace.dependencies]` key aliasing the same crate without a version**
— preserves the single declaration point but renames the extern crate at every
`use` site. Neither beats the per-line form, which declares **no version at all**
and therefore moves no version-declaration point.

### 1.6 `Cargo.toml:62-63` is the false sentence, and it has exactly one home

```
60  # Internal path dep. The explicit `version` (matching the crate's own,
61  # pre-publish 0.0.0) exists so the requirement is never cargo's implicit
62  # `*`: the cargo-deny bans lane (P13, deny.toml) rejects wildcard
63  # requirements workspace-wide, path deps included.
64  antseal-core = { path = "crates/antseal-core", version = "=0.0.0" }
```

*"workspace-wide, path deps included"* is false against the pinned checker for
dev edges and for private crates (§1.3). Its two neighbours are **correct**:

- `deny.toml:77-79` — *"No wildcard version requirements — **except cargo's
  implicit `*` on version-less internal path dependencies** (`antseal-core =
  { path = … }`), which is the workspace-internal norm (versions land at first
  publish)."*
- `D19:51-53` — *"`wildcards = "deny"` **with `allow-wildcard-paths = true`**;
  internal path deps carry an explicit `version` in `[workspace.dependencies]`
  so no implicit `*` exists."*

**So `deny.toml` and D19 both record the exemption, and only `Cargo.toml` denies
it.** The row cites `D19:51-53` as a co-author of the collision; D19 says the
opposite.

**The propagation is traceable in three hops.** `Cargo.toml:62-63` → D72 §1.6
(*"`Cargo.toml:49-52` records that it exists so P13's `deny.toml` wildcard ban is
satisfied for path deps. **Fixing publishability and satisfying the wildcard ban
pull in opposite directions***", `D72:362-365`) → D72 §5.1 (*"the fix collides
with P13's wildcard ban … and trips `deny.toml`'s wildcard rejection"*,
`D72:730-737`) → the row. **At no hop did anyone run the checker against the
counterfactual.** The row is the only one of the four to have doubted it in
writing — *"`deny.toml:81` already sets `allow-wildcard-paths = true`, so that
arm deserves re-measuring rather than assuming"* — and then closed with the
opposite conclusion anyway: *"which is what makes the collision unavoidable"*.

### 1.7 `scripts/reserve-crates.sh` cannot see this, and the tree already records the green that proves it

The row and its entry both say the script is *"the only route that would see
it"*. Measured:

`scripts/reserve-crates.sh:92-110`, `make_placeholder()`, writes a **fresh
six-line manifest** into `$(mktemp -d)/$name` (`:138`, `:177-178`):

```toml
[package]
name = "$name"
version = "$VERSION"
edition = "2021"
description = "$DESCRIPTION"
license = "$LICENSE"
repository = "$REPOSITORY"
```

— **no `[dependencies]`, no `[dev-dependencies]`, no workspace** — and `:191`
runs `cargo publish --dry-run` inside *that* directory. It never opens
`crates/antseal-*/Cargo.toml`.

The tree records the consequence. `docs/naming/P2-crates-reservation-runbook.md:109`:
*"`cargo publish --dry-run`: **green for all five** placeholder crates."*
`D72:322-336`: `cargo publish --dry-run -p antseal-core --allow-dirty` →
`PKG_CORE_EXIT=101`. **Same command, opposite verdicts, because they have
different subjects** — which is also why §1.1's index entries show `"deps":[]`.

`grep -rn "cargo publish\|cargo package"` over `scripts/` and `.github/` returns
**6 hits, all in `reserve-crates.sh` (`:13`, `:14`, `:45`, `:182`, `:190`,
`:191`), and 0 in `.github/`**. So the true statement is stronger than the row's:
**nothing in this tree can observe the failure, in CI or by hand.** The only
observation ever made was D72's lane typing the command ad hoc.

### 1.8 The version-bump question, answered

Accept row 4 demands *"measurement, not inference"*. This lane is barred from
`cargo`; what follows is deduction from the **measured index** at §1.1 plus the
pinned toolchain's documented resolution rules, which is strictly stronger than
the *"plausible-sounding guess"* the row's `Do` warns against, and is marked at
§3 as what it is.

**1.8.1 — the two self-edges. No number fixes it; the failure is unconditional.**
The workspace entry's version is `=<the crate's own version>` by the tree's own
discipline (`Cargo.toml:60-61`, *"matching the crate's own, pre-publish 0.0.0"*).
It is forced there, not merely conventional: with both `path` and `version`, the
requirement is checked against the local copy, so a workspace entry reading
`=0.1.0` while `crates/antseal-core` is at `0.2.0` fails **locally**, before any
publish. At package time cargo drops the `path` and resolves `=<V>` against the
registry:

- `V = 0.0.0` → the index has `0.0.0`, `"features":{}` → *"depends on
  `antseal-core` with feature `test-util` but `antseal-core` does not have that
  feature"* (`D72:329-331`, exit 101).
- `V = 0.1.0`, or any future number → the index has no such version → *"failed to
  select a version"*. To put `0.1.0` on the index you must package it. **Circular
  by construction.**

The only escapes are to relax `=` to a range that an already-published version
with the feature satisfies — which contradicts `Cargo.toml:55-56`'s exact-pin
rule and would build the crate's own tests against a stale published copy of
itself — or to remove the version from the dev line, which is §1.5.

**1.8.2 — the six cross-edges. Fixable by ordering, not by a number.** Once
`antseal-core 0.1.0` **carrying `test-util`** is on the index, `=0.1.0 +
test-util` resolves. But `antseal-core` cannot be published at all while its own
self-edge stands (1.8.1). **The two self-edges gate the whole family.**

**1.8.3 — the arm this record will not close, and the reason the edges are not
touched today.** cargo 1.92.0 supports packaging inter-dependent workspace
members in one invocation. `cargo package(1)`, `--registry`: *"if we are
packaging multiple inter-dependent crates, lock-files will be generated under the
assumption that dependencies will be published to this registry"* — cargo builds
a temporary local registry overlaying the packages being produced. **Every
measurement this row rests on used the single-package form**: D72 §1.6's
reproducer is `-p antseal-core`, and D72 §6 item 1 names `cargo package
--no-verify -p antseal-core --allow-dirty`. **Whether the overlay also satisfies a
crate's dev-dependency on *itself* has never been run here.** If it does, the
row's headline is an artefact of the invocation and the nine edits are churn.
This is §2 R3's first measurement and it is ordered **before** any manifest edit.

### 1.9 Three further publish blockers, and only one of them is on any row

1. **`0.0.0` is burned.** `D72:342-343`, blocker 1: *"The next publish of any of
   the five must be a higher version."* Recorded, still true, on no row.
2. **No `description` anywhere.** `grep -n "^description\|^repository\|^homepage\|^documentation\|^readme\|^keywords\|^categories"` over
   `Cargo.toml` and all seven `crates/*/Cargo.toml` returns **zero hits**.
   `[workspace.package]` (`Cargo.toml:34-49`) carries exactly `edition`,
   `rust-version` and `license`; every publishable crate inherits
   `edition.workspace`, `rust-version.workspace`, `license.workspace` and
   nothing else. `cargo publish` **hard-errors** on a missing `description`.
   D72 §1.6 blocker 2 read *"Exactly as D6 predicted — they land at M4/Q29"*;
   **Q29 ticked 2026-08-17 (`TODO.md:826`) with three Accept clauses, none of
   which mentions `description` or `repository`.** The expectation died with its
   owning row and nothing inherited it.
3. **The multi-package packaging mode has never been run** (§1.8.3).

Blocker 1 is on no row. Blocker 2 is on no row and its presumed owner is closed.
Blocker 3 is not in any record before this one. **Ticking Q241 today would leave
all three homeless** — which is the concrete form of §2 R1's objection to closing
it.

### 1.10 The row's citation defects: the brief's fourth, plus two more

- **CONFIRMED (the brief's item 4).** `tasks/Q.md:2986` (Accept row 1) and the
  `Do` line's arm (d) both cite *"D72 **§2 R5**'s 'no `antseal*` crate is
  published to crates.io as part of the M4 release'"*. That sentence is verbatim
  at **`D72:562`**, three lines under the heading `### §2 R8 — crates.io: no real
  publish at M4…` at `:560`. `### §2 R5` is at `:506` and rules the **channel**
  (GitHub Releases, single authoritative source); its only crates.io words are a
  parenthetical, *"no `cargo install` path at M4 (which §2 R8 forecloses
  anyway)"* — **§2 R5 defers to §2 R8, which is the reverse of the row's
  reading.**
- **NEW.** `tasks/Q.md:2982` and `TODO.md:837` cite *"registered as discovered
  work by **D72 §6** (`:730-737`, `:757-762`)"*. `:730-737` is **§5 item 1**
  (`## 5. What this ruling owes` is at `:728`); `## 6. Discovered work` begins at
  `:755` and item 1 runs `:757-763`. The second range is right; the first is §5
  labelled as §6.
- **NEW.** `tasks/Q.md:2983` cites `docs/decisions/D19-advisory-lane.md:51-53`
  as co-author of the collision. Re-read (§1.6), that passage records
  `allow-wildcard-paths = true` and is evidence **against** the row.
- **Size.** D72 §6 item 1 registered this as **size S**; the row and entry read
  **M** (`TODO.md:837`, `tasks/Q.md:2979`).

### 1.11 Checker yield, measured

**Candidate A — "nothing may run `cargo package`/`cargo publish` outside an
allowlist".** Measured over `scripts/` + `.github/`: **6 findings, 0 true.** All
six are `reserve-crates.sh`, which packages synthesized placeholders — exactly
what P2 was for and what D72 §2 R8's disposition explicitly keeps. Precision
**0/6**. The inverse form, *"assert `.github/` runs no publish"*, is **green with
zero subjects today** and stays green if a release workflow is added under a
different spelling: green-by-construction, the class this project has now found
in four instruments (`TODO.md:97`, D151 §2 R10's T1/T6, D152 §2 R9, Q252). **Both
forms refused.**

**Candidate B — a manifest lint asserting the nine dev lines carry no inherited
version.** Subject set is exactly the nine rows of §1.2's table; false positives
over the real tree **0**; plantable (restore `workspace = true` on any one).
Refused anyway: it is a **textual proxy for a behaviour that has a direct
executable check**, and a proxy that can pass while the behaviour fails is worth
less than nothing here.

**Candidate C — `cargo package --no-verify` over the four publishable crates, as
a gate lane.** This is the instrument D72 §6 item 1 actually asked for (*"should
add a `cargo package --no-verify` smoke check so the answer cannot silently
rot"*). It can go red — it is red **today**, measured at `D72:337`
(`NOVERIFY_EXIT=101`). **And that is precisely why it cannot be added today: a
check that is red on arrival cannot join a gate.** Its admissibility is
conditional on the fix. Deferred with the fix, not refused — §2 R7.

---

## 2. RULING

### §2 R1 — `Q241` is discharged **in part**, by **D72 §2 R8** and not by §2 R5. The row is AMENDED and stays OPEN; it is not closed

D72 §2 R8 (`D72:560-599`) rules *"No `antseal*` crate is published to crates.io as
part of the M4 release"* on four independent grounds, reason 1 being this very
failure. That discharges **Accept row 1 via its second branch** and nothing else.

**It does not close the row, for three measured reasons.**

1. **§2 R8 sets its own review date and names this row as the entry cost.** Its
   disposition paragraph: *"A review date is set: the first release after M4. At
   that point either a real version ships … or the placeholders are re-justified
   deliberately."* and *"If a real publish is ever wanted, §1.6's blockers are the
   entry cost and **§5.1's task must be done first**."* Q241 **is** §5.1's task.
   Ticking it deletes the only row carrying that cost into the review date the
   same ruling created.
2. **Three blockers would be left homeless** (§1.9), one of them — the absent
   `description` — a hard `cargo publish` error whose presumed owner (Q29) closed
   without it.
3. **Accept row 1's second branch is not satisfiable as written today.** It
   requires the dev-dep *"left as-is **with its reason**"*, and the reason on file
   (`Cargo.toml:62-63`) is false (§1.6). The branch becomes satisfiable only once
   §2 R6 lands.

**Exact text for the registrar to splice** into `tasks/Q.md:2986` and into the
`TODO.md:837` row's Notes (compose nothing; this is the whole insert):

> **Accept row 1 is MET via its second branch, 2026-08-22 (D158 §2 R1).** The
> intent is recorded: **no `antseal*` crate is published to crates.io as part of
> the M4 release**, ruled at **D72 §2 R8** — *not* §2 R5, which is the
> GitHub-Releases channel ruling and defers to §2 R8 on crates.io. The nine
> `[dev-dependencies]` edges are left in place; their reason is recorded at
> `Cargo.toml:60-63` as corrected by D158 §2 R6, and the fix that discharges
> them is written out at D158 §2 R4. **The row stays open** as the entry cost of
> §2 R8's own review date (*"the first release after M4"*, D72 §2 R8), which
> D72 §5.1 requires be paid *"first"*.

### §2 R2 — The row's central framing is FALSE. There is no collision, and the row's closing sentence is wrong on both halves

`deny.toml:81` sets `allow-wildcard-paths = true`; cargo-deny 0.19.8
(`src/bans.rs:984-989`) exempts a wildcard path dep when the krate is private
**or the edge is `DependencyKind::Development`**; **all nine edges are
development edges** (§1.2), including the two in `cfg`-gated tables, measured at
§1.5. The row's *"correction to the handover"* — *"no dev-dep line carries a
literal `version =`, so the fix lands on the workspace table, which is what makes
the collision unavoidable"* — is false twice over: the fix lands on **nine
per-crate lines**, and there is no collision to be unavoidable about.

What a version-less workspace table *would* red is the **six** normal edges on
public crates (§1.4). **So the workspace table's `version = "=0.0.0"` is
load-bearing and is not touched by any ruling here.**

### §2 R3 — Before any manifest edit, run the invocation nobody has run

D72's reproducer and D72 §6's named instrument are both **single-package**
(`-p antseal-core`). cargo 1.92 packages inter-dependent workspace members
through a temporary local-registry overlay (§1.8.3). **First measurement, ordered
`before` §2 R4:**

```
cargo package --no-verify --allow-dirty \
  -p antseal-core -p antseal-net -p antseal-anchor -p antseal-cli
```

Record the exit code **read back out of a file**, never from the harness's own
notification, and record the message, not just the code. If it is green today,
the row's headline is an artefact of the invocation, §2 R4 becomes churn, and
this record is amended by dated addendum. If it is red — the expected outcome,
since D72 measured red on the single-package form — §2 R4 stands unchanged.

### §2 R4 — Disposition of the nine edges: LEFT IN PLACE, with the fix written out in full so it is never re-derived

**Not fixed in this wave.** Three reasons, in order of weight: §2 R3's
measurement is unrun and may make the edit unnecessary; three other publish
blockers stand (§1.9) so the edit buys none of a publish; and this record's
author is barred from `cargo` and will not order a manifest change whose effect
it cannot measure, in a wave whose only witness is a local gate on a contended
build lock. **Re-homed to no parking-lot row** — the v1.1 parking lot
(`TODO.md:1090`) is for *out-of-MVP-scope* obligations, and this is an in-scope
release blocker deferred by ruling. It stays on Q241, which is a leaf and blocks
nothing.

**The fix, in full, for whoever pays the entry cost.** Nine lines, no workspace-
table change, no `deny.toml` change:

| file:line | from | to |
|---|---|---|
| `antseal-core/Cargo.toml:135` | `antseal-core = { workspace = true, features = ["test-util"] }` | `antseal-core = { path = ".", features = ["test-util"] }` |
| `antseal-core/Cargo.toml:153` | `antseal-core = { workspace = true, features = ["test-vectors"] }` | `antseal-core = { path = ".", features = ["test-vectors"] }` |
| `antseal-net/Cargo.toml:117` | `antseal-net = { workspace = true, features = ["test-util"] }` | `antseal-net = { path = ".", features = ["test-util"] }` |
| `antseal-net/Cargo.toml:122` | `antseal-core = { workspace = true, features = ["test-util"] }` | `antseal-core = { path = "../antseal-core", features = ["test-util"] }` |
| `antseal-anchor/Cargo.toml:64` | `antseal-core = { workspace = true, features = ["test-util"] }` | `antseal-core = { path = "../antseal-core", features = ["test-util"] }` |
| `antseal-cli/Cargo.toml:126` | `antseal-net = { workspace = true, features = ["test-util"] }` | `antseal-net = { path = "../antseal-net", features = ["test-util"] }` |
| `antseal-cli/Cargo.toml:132` | `antseal-core = { workspace = true, features = ["test-util"] }` | `antseal-core = { path = "../antseal-core", features = ["test-util"] }` |
| `antseal-cli/Cargo.toml:139` | `antseal-anchor = { workspace = true, features = ["test-util"] }` | `antseal-anchor = { path = "../antseal-anchor", features = ["test-util"] }` |
| `antseal-wasm/Cargo.toml:113` | `antseal-core = { workspace = true, features = ["test-vectors"] }` | `antseal-core = { path = "../antseal-core", features = ["test-vectors"] }` |

**All nine, not eight.** The ninth is exempt from the packaging failure only
because `antseal-wasm` carries `publish = false`; it is the same idiom, and a
tree in which eight lines take one form and one takes another teaches the next
lane the wrong half. If a future lane prefers minimality it must annotate
`antseal-wasm/Cargo.toml:113` with why it differs — silence is not an option.

**The proof the fix owes, red-before/green-after, in this order:**
1. `cargo package --no-verify --allow-dirty -p …` on all four → **red**, exit
   101, message quoted (this is §2 R3's run).
2. Apply the nine edits. `cargo package --no-verify --allow-dirty -p …` →
   **green**.
3. `./scripts/ci-lanes.sh audit-deny` → **green**, with the fault plant: flip
   `deny.toml:81` to `false`, confirm it reds naming the dev lines, restore.
   `touch` the manifests after any restore — a `cp -p` restore preserves mtime
   and cargo will not rebuild.
4. Confirm `Cargo.lock` is unchanged, or record what changed and why.

**Fallback if step 2 does not go green**: arm (a) from the row's own `Do` — move
`test-util`/`test-vectors` into a separate `publish = false` helper crate,
removing the self-edges entirely. Do not reach for arm (c) (bootstrap a real
version onto the registry) or arm (d) (`publish = false` on the four): (c) is
foreclosed by D72 §2 R8 reasons 2 and 3, and (d) states more than D72 ruled and
contradicts §2 R8's review date.

### §2 R5 — Two `after` terms are STRUCK. Neither survives rule 7's own test, and one of them was manufactured by a rewording

`TODO.md:837` reads `— after P13/D19, P2, Q31`. Rule 7's test (D154 §2 R10):
*name the clause of Q241's `Accept` that cannot be written until Y is `[x]`*.

- **`P13/D19` — STRUCK.** The Accept clause it would serve is row 3
  (`deny.toml`'s wildcard rule). `deny.toml` exists, is landed and is green;
  P13's open residue is *"first scheduled-run evidence + D19 red-lane demo
  (maintainer deferred)"* (`TODO.md:138`), which touches nothing this row
  measures. Replace with the annotation `P13/D19 (the rule this row measures
  against — consumer, not a dep)`.
- **`Q31` — STRUCK.** It serves Accept row 2 only, and Accept row 2 is the
  **registrar's rewording** of D72 §6 item 1, which asked for *"a `cargo package
  --no-verify` smoke check"* — an **instrument**, naming no lane and no release
  workflow. The rewording into *"whatever CI lane owns the release runs the
  packaging check"* is what created the Q31 edge. With Accept row 2 restored to
  D72's scope (§2 R7), no clause needs Q31 `[x]`. Note also D141 §2 R1: **Q31
  performs no release execution** — its `Do` publishes a draft and its Accept
  row 1 is a dry-run tag — so it is not the row a real publish would hang off in
  any case.
- **`P2` — KEPT.** It is a true predecessor: the published `0.0.0` placeholders
  are what the resolver finds, and without them the failure has a different
  shape.

**The real ordering is not a row and must not be written as one.** Q241's work
is due **before the first crates.io publish**, which is D72 §2 R8's review date
(*"the first release after M4"*), not before any checkbox. Under rule 7 that is
an `Accept`/venue condition, D154 §1.8's fourth surface — record it in Notes,
never as an `after`, and never as an inverted edge.

**No cycle is created.** Nothing in the tracker is `after Q241` (see *What it
blocks*), so striking two terms from a leaf changes no other row's availability.

### §2 R6 — `Cargo.toml:60-63` IS corrected, in this wave, and here is the replacement text

This is the one edit that is not deferred. It is the defect that manufactured the
row's framing, it propagated into a resolved decision record, and every day it
stands the next lane re-derives the same wrong conclusion. Replace `Cargo.toml:60-63`
verbatim with:

```toml
# Internal path dep. The explicit `version` (matching the crate's own,
# pre-publish 0.0.0) exists for the SEVEN NORMAL edges that inherit this
# entry: cargo-deny's `wildcards = "deny"` (deny.toml:80) reds an implicit
# `*` on a path dep of a PUBLIC crate, and six of those seven are public
# (antseal-wasm's is exempt via `publish = false`). It is NOT needed by the
# nine `[dev-dependencies]` edges that also inherit it — `allow-wildcard-paths`
# (deny.toml:81) exempts every dev edge and every private crate
# (cargo-deny 0.19.8, src/bans.rs:984-989, measured D158 §1.3). Those nine
# inherit it anyway, and THAT is what makes all four publishable crates
# unpackageable: D158 §2 R4 / Q241.
```

**The sentence being deleted is *"the cargo-deny bans lane (P13, deny.toml)
rejects wildcard requirements workspace-wide, path deps included"*, and it is
false.** `deny.toml:77-79` and `D19:51-53` both already say the true thing; this
brings the third site into line with them.

### §2 R7 — The four Accept rows, per row

Vocabulary per D140 §2 R1, D143 §2 R5, D148 §2 R10.

- **Accept row 1 — MET (second branch), 2026-08-22.** Text at §2 R1. The
  citation is corrected `§2 R5` → **`§2 R8`** in the same act, on both the row
  and the `Do` line's arm (d).
- **Accept row 2 — AMENDED, not met.** As written (*"Whatever CI lane owns the
  release runs the packaging check"*) it is **unsatisfiable while the nine edges
  stand**, because the check it demands is red on arrival and a red check cannot
  join a gate — which makes it mutually exclusive with Accept row 1's second
  branch, the branch this record takes. It also over-reads its source: D72 §6
  item 1 asked for *"a `cargo package --no-verify` smoke check"*, naming an
  instrument, not a lane. Replacement text for `tasks/Q.md:2987`:

  > **AMENDED 2026-08-22 (D158 §2 R7).** The reproducer and the exact nine-line
  > fix are recorded where the next lane will find them (D158 §1.8, §2 R4), and
  > the smoke check D72 §6 item 1 asked for lands **with** the fix, never before
  > it: a check that is red on arrival cannot join a gate. Until then the class
  > is invisible **by ruling, with the reason written down**, which is a
  > different state from the invisible-by-accident this row was minted for.
  > **Correction carried in the same act**: `scripts/reserve-crates.sh:191` is
  > *not* a route that could see it — it packages a synthesized placeholder with
  > no dependencies (`make_placeholder()`, `:92-110`), which is why
  > `docs/naming/P2-crates-reservation-runbook.md:109` records it **green for
  > all five** on the same day `-p antseal-core` exits 101. **Nothing in this
  > tree can see the failure, in CI or by hand.**

- **Accept row 3 — MET, 2026-08-22.** `deny.toml`'s wildcard rule is **unmoved**
  and no ruling here moves it; it was never in tension with the fix (§1.3, §2
  R2). The recorded reason it is unmoved is §2 R6's replacement comment.
- **Accept row 4 — MET, 2026-08-22, and the answer is NO.** §1.8: for the two
  self-edges the failure is **unconditional and circular** — the requirement is
  forced to `=<the crate's own version>`, which is by definition not on the
  registry when the crate is packaged, so no bump ever fixes it; for the six
  cross-edges it is fixable only by publish **ordering**, which the two
  self-edges gate. **This is deduction from the measured index at §1.1 plus the
  pinned toolchain's documented rules, not an execution** — §3 says so plainly,
  and §2 R3's run is what converts it.

**A fifth Accept row is added**, because §1.9's blockers otherwise have no home:

> - The three publish blockers that are **not** the dev-dep are named on this
>   row so the first publish does not rediscover them one at a time: `0.0.0` is
>   burned (D72 §1.6 blocker 1); **no `description` exists on any crate or in
>   `[workspace.package]`**, a hard `cargo publish` error that D72 §1.6 blocker
>   2 expected *"at M4/Q29"* and that **Q29 ticked without** (D158 §1.9); and
>   the multi-package `cargo package` mode has never been run here (D158 §1.8.3,
>   §2 R3).

### §2 R8 — Size: **XS**, and D72 §6 item 1 already said S

The row and entry read `M` (`TODO.md:837`, `tasks/Q.md:2979`); D72 §6 item 1
registered it **S**. The `M` was sized against building the fix *and* the CI
lane. With the fix deferred by §2 R4 and the lane refused by §1.11, the residue
is one comment block, the row/entry text, and a ledger line. **XS**, which is
live vocabulary in this tracker (138 rows carry it).

### §2 R9 — Three findings go to `docs/instrument-ledger.md` with no id, per rule 8

All three have the verification apparatus or decision prose as their subject.

1. **`tasks/Q.md:2982` / `TODO.md:837` cite `D72:730-737` as "§6"; it is §5 item
   1** (`## 5.` at `D72:728`, `## 6.` at `:755`, item 1 at `:757-763`).
2. **`tasks/Q.md:2983` cites `D19:51-53` as co-author of the collision; that
   passage records `allow-wildcard-paths = true` and is evidence against it.**
3. **D72 §2 R8 reason 4's *"`cargo install antseal` would also be an unsigned
   acquisition path"* does not describe this tree.** No workspace member is named
   `antseal`; the reserved crates.io name `antseal` maps to no crate, and the
   binary called `antseal` is produced by `antseal-cli`
   (`crates/antseal-cli/Cargo.toml:20`). `cargo install antseal` today installs
   the empty placeholder. The reasoning survives — a second acquisition path is
   still refused — but the mechanism named is not the live one, and the naming
   gap belongs to whoever pays §2 R8's review date.

### §2 R10 — Nothing mechanical is minted. Both refusals are on measured yield

§1.11: candidate A **6 findings / 0 true**, and its inverse green with zero
subjects; candidate B a textual proxy for a behaviour with a direct check;
candidate C (the one D72 asked for) admissible only **after** the fix and
therefore deferred **with** it, not refused. Precedent: D154 refused two cycle
checkers on 4/0 and 62/1, and D141 §2 R7 refused one before that. **The fault
that would prove candidate C can redden is named in advance** — restore
`{ workspace = true, features = ["test-util"] }` on
`crates/antseal-core/Cargo.toml:135` and require the message *"depends on
`antseal-core` with feature `test-util` but `antseal-core` does not have that
feature"*, not merely a nonzero exit, since a crash exits nonzero too.

### §2 R11 — No row is minted and no id is assigned

Rule 8: every finding this record makes is either a ruling on an existing row
(Q241), a correction to a comment (`Cargo.toml`), or instrument-class prose
(§2 R9). The one thing that looks like new work — the absent `description` — is
**not** minted as a row: it is a clause of the publish this record has just ruled
does not happen, and it lands on Q241's new fifth Accept row, which is the row
that carries the entry cost. Minting a second row for it would put a second owner
on one gate.

---

## 3. What this record does NOT settle, stated plainly

- **It did not run `cargo`.** `cargo package`, `cargo publish`, `cargo build` and
  `cargo test` were all barred for this lane. Every packaging claim above is
  either (a) quoted from D72 §1.6's measured run, (b) deduced from the measured
  registry index at §1.1 plus the pinned toolchain's own documentation, or (c)
  explicitly ordered as a measurement at §2 R3. **§2 R4's fix is not proven to
  work by this record** — it is proven not to trip cargo-deny (§1.5, measured and
  fault-planted) and documented to be stripped by cargo at package time (§1.5,
  three sources). The green half of red-before/green-after is owed by whoever
  applies it, and the fallback is named.
- **Whether `cargo package --workspace` already succeeds is unknown** (§1.8.3).
  It is the single measurement that could make §2 R4 unnecessary, and it is
  ordered first for exactly that reason.
- **The cargo-deny measurements are on synthetic workspaces, not on this tree.**
  They had to be: the real tree has no wildcard requirement anywhere, so a run
  against it proves nothing about the counterfactual. The synthetic workspaces
  reproduce the shape edge-for-edge, including a `cfg`-gated dev-dep table, and
  both were fault-planted.
- **`Cargo.lock` behaviour under §2 R4's edit is not measured.** No version
  requirement appears in a lockfile and the resolved package is the same path
  crate, so no change is expected; step 4 of §2 R4's proof exists because
  "expected" is not "measured".

---

## 4. Edit list — per file, with the timing word

Timing words are load-bearing. `with` = same act; `before` = strictly earlier,
same wave; `after` = requires the other to be complete. **Collapsing `with` or
`before` into `after` invents a dependency** — the defect D154 traced to four
phantom cycles.

**Registrar (single-writer on `TODO.md` and `tasks/*.md`):**

1. `tasks/Q.md:2986` — splice §2 R1's block verbatim onto Accept row 1. **with**
   edit 2.
2. `tasks/Q.md:2987` — replace with §2 R7's Accept-row-2 replacement text.
   **with** edit 1.
3. `tasks/Q.md:2988` — append `**MET 2026-08-22 (D158 §2 R7)**: unmoved; the
   recorded reason is Cargo.toml:60-63 as corrected by D158 §2 R6.` **with** 1-2.
4. `tasks/Q.md:2989` — append §2 R7's Accept-row-4 verdict (**NO**, with the §1.8
   pointer). **with** 1-3.
5. `tasks/Q.md` after `:2989` — add §2 R7's **fifth** Accept row. **with** 1-4.
6. `tasks/Q.md:2979` — `Size: M` → `Size: XS`, citing D158 §2 R8 and D72 §6 item
   1's `S`. **with** 1-5.
7. `tasks/Q.md:2980` — `Deps`: strike `P13/D19` and `Q31` per §2 R5, keep `P2`,
   add the two annotations and the non-row ordering sentence. **with** 1-6.
8. `tasks/Q.md:2983` — correct *"whose reason is written … in
   `docs/decisions/D19-advisory-lane.md:51-53`"* (§2 R9 item 2) and the
   *"only route that would [see it]"* sentence (§2 R7's correction). **with** 1-7.
9. `tasks/Q.md:2984` — arm (d): `D72 §2 R5` → `D72 §2 R8`. **with** 1-8.
10. `TODO.md:837` — headline `(M)` → `(XS)`; strike the two `after` terms per §2
    R5; replace the closing *"correction to the handover"* sentence with §2 R2's
    finding; add the §2 R1 Notes text. **with** 1-9, and **after** edit 11 has
    been decided so the row's pointer to the corrected comment is not written
    before the comment exists.
11. `Cargo.toml:60-63` — §2 R6's replacement comment. **This is the one edit that
    is not deferred**, and it is **before** edit 10. *(Cargo.toml is outside the
    registrar's usual scope — assign it to whichever lane holds the manifest
    write scope this wave, and never to two lanes at once.)*
12. `docs/decisions/README.md` — one register row for D158. **with** 1-11.
13. `docs/instrument-ledger.md` — §2 R9's three findings, one dated line each.
    **with** 1-12.

**Deferred, owned by whoever pays D72 §2 R8's review date — ordered `before` the
first crates.io publish and after nothing:**

14. §2 R3's multi-package `cargo package --no-verify` measurement. **before** 15.
15. §2 R4's nine manifest lines, with its four-step red-before/green-after proof.
    **after** 14, and **with** 16.
16. Candidate C added as a gate lane, with the §2 R10 fault plant. **with** 15,
    never **before** it.

**Explicitly NOT edited by anything here:** `deny.toml` (§2 R7 Accept row 3 — the
rule is unmoved), `Cargo.toml:64/70/76` (§2 R2 — the workspace-table version is
load-bearing for the six normal public edges), and `docs/decisions/D72-…`, whose
§1.6/§5.1 false premise is corrected **by citation from this record**, not by
editing a resolved record.
