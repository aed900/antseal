# Property-testing conventions (Q3)

Normative for every property test in the workspace, all component domains
(F/C/G/S/A/R). Spec basis: Verification "(M0) Unit/property tests per
crate" (MVP-SPEC.md line 167); working principle "determinism".

## 1. The pinned proptest

Exactly **one proptest** serves the whole workspace: workspace requirement
`proptest = "1"` (root `Cargo.toml`), **resolved version `1.11.0` frozen by
the committed `Cargo.lock`** (dependency-policy §3; recorded here at Q3).
proptest is deliberately *outside* the exact-pin class of
[dependency-policy §1](../dependency-policy.md) — it is test
infrastructure whose output is never hashed, signed, stored, or paid for —
but its resolved version still only moves through the §4 deliberate-bump
procedure like every locked dependency.

**Component crates never declare proptest.** It reaches test code
exclusively through `antseal-core`'s `test-util` feature, which activates
proptest as an optional dependency and re-exports it:

```toml
# any crate's Cargo.toml
[dev-dependencies]
antseal-core = { workspace = true, features = ["test-util"] }
```

```rust
use antseal_core::test_util::proptest::prelude::*;
use antseal_core::test_util::strategies;
```

One declaration point means the version can never skew between domains.
(`antseal-core` itself consumes the same surface via a self
dev-dependency.) **Never** enable `test-util` on a normal dependency edge:
it pulls non-WASM-safe test deps, and the `wasm32-core`/`core-dep-graph`
lanes audit the default graph.

## 2. Shared strategies

Home: **`antseal_core::test_util::strategies`** (feature `test-util`) — the
one place work/file/unit/byte-range generators live, so structural
invariants are generated identically everywhere and never redefined per
crate (Q3 accept). First residents:

- `proptest_config(seed)` — the project config builder (§3);
- `unit_tiling(max_units, max_unit_len)` — work-shaped unit tilings:
  sorted, non-overlapping, contiguous ranges exactly tiling
  `[0, total_size)`, plus the empty-work case (one empty unit), per the
  MVP-SPEC.md line 121/78 invariants.

Worked example consuming both (strategy-contract property + real
crate-code property): `crates/antseal-core/tests/proptest_example.rs`.
Grow this module (new generators for manifests, files, byte ranges, GGM
shapes …) instead of writing local ones; a strategy used by two crates
belongs here by definition.

## 3. Determinism and seeding

Every `proptest!` block sets the project config with a **fixed RNG seed**:

```rust
proptest! {
    #![proptest_config(strategies::proptest_config(0x5EED_0007))]
    // ...
}
```

- The seed is an arbitrary per-block constant chosen at authoring time
  (distinct across blocks so exploration is not correlated; any literal is
  fine — stability is what matters, not the value).
- Fixed seeding makes every CI run reproduce exactly (a red lane on a
  runner reproduces byte-for-byte locally) and keeps case generation
  OS-independent. The exploration lost to a fixed seed is recovered by
  raising case counts in CI (§4) — a longer deterministic sequence — and
  by the committed regressions files (§5).
- `proptest_config` starts from `ProptestConfig::default()`, so proptest's
  own environment overrides keep working (§4); only the seed is forced.
- Tests with a spec-mandated case floor (e.g. C3's ≥ 10 000 injectivity
  cases) additionally hardcode `cases` on top of the builder:
  `ProptestConfig { cases: 10_000, ..strategies::proptest_config(SEED) }`.
  **This does not survive `PROPTEST_CASES`** — see the correction in §4
  before relying on a floor.
  (The pre-Q3 block in `src/crypto/hkdf.rs` already has these semantics —
  fixed seed + hardcoded floor over the default base — and C may fold it
  onto the builder whenever that file is next touched.)

## 4. Case counts per environment (env var)

Case counts are tuned via proptest's native **`PROPTEST_CASES`**
environment variable (honoured by `ProptestConfig::default()`, hence by
the §3 builder):

| Environment | Cases | Where set |
| --- | --- | --- |
| Local development | 256 (proptest default) | nothing to set |
| CI `test` lane | **1024** | `env: PROPTEST_CASES` on the `test` job, `.github/workflows/ci.yml` |
| Deep local soak (optional) | e.g. `PROPTEST_CASES=100000 cargo test` | ad hoc |

> **Correction (found at C18, 2026-07-28).** This section previously said
> that a hardcoded `cases` value overrides `PROPTEST_CASES`. **The opposite
> is true**, and it matters.
>
> The `proptest!` macro re-applies the environment on top of whatever
> config it is handed — `sugar.rs` wraps every config in
> `contextualize_config($config)` before building the runner — so
> `PROPTEST_CASES` wins over an explicit `cases` field. Measured on
> proptest 1.11.0: a block declaring `cases: 48` runs 48 cases with no env
> var set, 16 with `PROPTEST_CASES=16`, and 256 with `PROPTEST_CASES=256`.
>
> Consequences to be aware of, and to fix in the owning tasks:
>
> - **Spec floors are not currently enforced.** C3's ≥10 000-case
>   injectivity floor (`src/crypto/hkdf.rs`, `cases: 10_000`) runs **1024**
>   cases in the CI `test` lane, not 10 000. C8's `cases: 2048` likewise
>   drops to 1024. A floor has to be expressed as
>   `cases: max(10_000, ProptestConfig::default().cases)` — or the lane has
>   to stop setting the variable — for the floor to actually hold.
> - **A ceiling cannot be expressed in the config at all.** An expensive
>   block (e.g. C18's hybrid ML-DSA property) cannot cap its own case count;
>   the only levers are per-case cost and the lane's env var.
> - The comment on the `PROPTEST_CASES` env in `.github/workflows/ci.yml`
>   repeats the same incorrect claim and should be corrected with the C3
>   fix.
>
> Setting `cases` is still worthwhile: it is the value used for local runs
> and anywhere the variable is unset.

## 5. Regressions files: committed and never deleted

proptest persists every found failure as a seed line under
`proptest-regressions/` next to the failing test's source (crate-relative;
e.g. `crates/antseal-core/proptest-regressions/…`). Policy:

**Integration tests (`tests/`) must name the file explicitly.** proptest's
default persistence walks *up* from the test's source file looking for a
directory containing `lib.rs`/`main.rs`. That works for `#[cfg(test)]`
blocks inside `src/`, but a test in `tests/` has no such ancestor: the
lookup fails, proptest prints

```text
proptest: FileFailurePersistence::SourceParallel set, but failed to find lib.rs or main.rs
```

and — having no source file configured either — **persists nothing**. A
failure found in CI would then be unreproducible locally, silently
defeating this whole section. Use the explicit-path variant instead:

```rust
proptest! {
    #![proptest_config(strategies::integration_test_config(
        0x5EED_0007,
        "proptest-regressions/<test-file-stem>.txt",
    ))]
    // ...
}
```

The path is relative to the package root (`cargo test`'s working
directory), so it lands exactly where `SourceParallel` would have put an
in-`src` test's file. Suites inside `src/` keep using `proptest_config` —
the default persistence is correct there. (Found and fixed at C18, which
was the first substantial `tests/` property suite; `tests/proptest_example.rs`
was converted at the same time.)

- **Commit every `proptest-regressions/` file** in the PR that first
  produces it. They are regression tests, not noise; persisted seeds re-run
  *first* on every subsequent execution, in every environment, before
  random generation.
- **Never delete or edit an entry** — not on refactors, not when the test
  moves (move the file with it), not when the failure "can't happen
  anymore". Removing one deletes a regression test. This mirrors the
  golden-vector retention rule (append-only evidence).
- Never add these paths to `.gitignore`.

## 6. Shrinking and timeouts

- **Shrinking**: proptest defaults (`max_shrink_iters` et al.) — do not
  lower them; a poorly-shrunk failure is still reproducible via the
  persisted seed. Strategies in `test_util::strategies` should prefer
  built-in combinators (`prop_map` over ad-hoc `Just` trees) so shrinking
  stays effective.
- **Timeouts**: no per-case `timeout` by default (deterministic pure
  functions don't hang; the CI job-level timeout is the backstop). A test
  that genuinely needs one sets it explicitly in its block with a comment.
- **Forking**: off (default). `fork = true` would break WASM portability
  of test code and hide panics from the harness; crash-class inputs belong
  to the fuzz lanes (Q9), not property tests.

## 7. Naming

Property tests follow normal test naming **minus the reserved cross-OS
markers**: never use `corpus_` or `vector_` in a property-test name — those
select the G3/Q4 cross-OS suites (CONTRIBUTING.md, "Cross-OS suite
naming"), and property tests are not byte-stability suites.
