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

Hardcoded `cases` values (spec floors, §3) override the env var by
proptest semantics — that is intended.

## 5. Regressions files: committed and never deleted

proptest persists every found failure as a seed line under
`proptest-regressions/` next to the failing test's source (crate-relative;
e.g. `crates/antseal-core/proptest-regressions/…`). Policy:

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
