# `fuzz/` — cargo-fuzz targets

Registered targets:

| target | owner | what it drives |
| --- | --- | --- |
| `verify_bundle` | R10 | `antseal_core::verify::verify_bundle` over arbitrary bytes and structure-aware mutations of valid R6 bundles |

F17 (manifest/bundle CBOR decoders) and A23 (TimeStampResp, `.ots`) add
their targets here as they land.

## What R10 built, and what Q9 still owns

R10's task text says the fuzz jobs are Q9's (`tasks/R.md` R10 deps: "Q: fuzz
jobs in CI (Q9)"), so this directory contains **the target and nothing
else**. Everything below is Q9's to wire, listed explicitly so none of it
is discovered late:

1. **A nightly toolchain pin.** `rust-toolchain.toml` pins stable 1.92.0,
   and cargo-fuzz needs nightly for `-Z sanitizer` and libFuzzer
   instrumentation. Q8's CI comment already anticipates this — "cargo-fuzz
   needs its own nightly-toolchain pin, independent of the workspace pin"
   (`.github/workflows/ci.yml`). **Until that pin exists, `cargo fuzz run`
   does not work in this repo**, which is why R10's invariant is *also*
   asserted by the ordinary test suite (below).
2. **The `cargo-fuzz` tool itself**, plus a decision on pinning its version
   the way other tooling is pinned (`docs/dependency-policy.md`).
3. **The two CI lanes** Q9's task text describes: a per-PR `fuzz-smoke` with
   a fixed budget (≈90 s/target) and a scheduled nightly long run with
   corpus persistence.
4. **Corpus management** — minimization cadence, committed minimized
   corpora, and the crash-triage workflow (a crash is release-blocking, and
   its input becomes a committed regression case).

### Two dependencies, flagged

`libfuzzer-sys` and its transitive `arbitrary`/`cc` subtree are **new
third-party dependencies**, and `docs/dependency-policy.md` makes that a
deliberate reviewed event. Two things contain the blast radius:

- `fuzz/Cargo.toml` carries an empty `[workspace]` table, cargo-fuzz's
  standard detach idiom, so this crate has its **own** lockfile and nothing
  here enters the workspace `Cargo.lock` or the audited normal dependency
  graph;
- the target itself uses **neither** crate's API beyond `fuzz_target!`. The
  driver takes raw entropy rather than an `Arbitrary` impl, so
  `antseal-core` gains no fuzzing dependency and the engine stays testable
  from the ordinary suite.

`fuzz/Cargo.lock` **is committed**, following the `probes/*` precedent
(root `.gitignore`: "their `Cargo.lock` files ARE committed (reproducible
probes) — only build output is ignored"). It was resolved and type-checked
on the pinned **stable** toolchain — `cargo check` succeeds there, only the
instrumented build needs nightly — so the pins are reviewable now rather
than at whatever version Q9's first nightly run happens to resolve.

## Seeding the corpus

The seed corpus is generated, not committed: valid R6 bundles of every M0
shape plus R7/R8's tamper fixtures, from
`antseal_core::test_util::bundle_mutators::seed_corpus()`. Materialize it
with a one-liner from the workspace root once nightly is available:

```
cargo fuzz run verify_bundle -- -runs=0            # build only
# then write seeds/ from seed_corpus() — see Q9's corpus tooling
```

Seeding matters more than usual here: a mutation of an *already invalid*
bundle reaches error paths a mutation of a valid one reaches only by
accident — the second failure inside a stage that has already found one.

## The half that runs today

R10's Accept requires the no-panic property in the **normal test suite**,
not only under fuzzing, and that half is live now:
`crates/antseal-core/tests/verify_fuzz.rs`. It drives the identical engine,
so the two halves cannot disagree about what a mutation is, and the
mutators are exercised on every CI build rather than only when someone
fuzzes.

That suite also pins the two regions of a bundle whose mutation legitimately
still verifies at M0 — the storage record (spec line 119: storage is the
product's bonus, not its proof) and the anchor artifacts (the M0 anchor
stage is a stub until R12) — as an **equality**, so a crash-free fuzz run is
not mistaken for "everything is authenticated".
