# D138 — Path-filtering docs-only pushes, moving the billed cross-OS arms to weekly, and the guard that makes both self-enforcing

- **Status: RESOLVED. The maintainer's DIRECTION is confirmed and implemented; the
  obvious MECHANISM for it is overturned twice, both times on a measurement taken
  in this repository.** The instruction was *"path-filter docs-only pushes and
  move cross-OS to weekly"*. The direction stands and is built. What does not
  stand is (a) the shape the brief and every prior note assumed — a `paths-ignore`
  on the single `ci.yml`, which would have skipped `traceability` on exactly the
  pushes whose contents that lane reads — and (b) the *scope* of "docs":
  **`docs/**` and even `docs/decisions/**` are UNEXCLUDABLE**, because
  `docs/decisions/D18-wasm-bindgen-surface-location.md` carries
  `wasm-bindgen-cli --version 0.2.126` on **lines 752 and 976**, and
  `scripts/wasm-toolchain-audit.sh:161-162` greps `.github/workflows scripts docs`
  for exactly that literal to assert CLI/crate pin equality inside `ci.yml`'s
  `wasm32-core-tests` job. Two lines of a decision record are live CI inputs. The
  exclusion is therefore **three entries**, not a tree, and the smallness is the
  finding.
- **A third premise of the brief is overturned as arithmetic**, not as design: the
  quoted saving of *"~1 375 min/month"* (≈800 docs + ≈575 cross-OS) assumes
  **~25 pushes/month**. The observed cadence over 2026-08-01→16 is **32 pushes in
  15.00 days = 64/month**, and over the whole 36-run history **55/month**. Priced
  at the observed cadence the saving is **~2 450 weighted min/month**, roughly
  **1.8×** the brief's figure. The uncertainty is entirely in the cadence, and
  this record says so rather than presenting one number.
- **Date: 2026-08-16**
- **Owning task: Q239.**
- Related: D61 (the fuzz lane's minutes ceiling and the only prior bill in the
  tree), D124/Q182 (`traceability`'s cargo-free property, and the RULING that a
  static read of `run:` text is the wrong observable for a property of a process
  tree — the same trap this record hit in a new suit), D135 (the whole-repository
  bill of 3 154–3 324 weighted min for 2026-08-01→15, and the exhaustion this
  responds to), D136 (the page lane), Q43 (`scripts/check-ci-shell.py`), Q78 (the
  whole-allowance accounting, still open), Q153/D116 (a lane that never runs on
  the remote is not evidence).

---

## 1. The measurement

### 1.1 What a push costs

Per-job wall time from run **31873411737** (2026-08-15, the last fully green
`ci` push run), with GitHub's platform multipliers applied:

| job | wall | × | weighted min |
|---|---|---|---|
| `test` | 31 m 58 s | 1 | 32.0 |
| `cross-os-macos` | **1 m 19 s** | **10** | **13.2** |
| `fuzz-smoke` | 11 m 09 s | 1 | 11.2 |
| `cross-os-windows` | **4 m 51 s** | **2** | **9.7** |
| `wasm32-core-tests` | 3 m 40 s | 1 | 3.7 |
| `cross-check` | 2 m 13 s | 1 | 2.2 |
| `cross-os-linux` | 2 m 15 s | 1 | 2.2 |
| `wasm-bitmatch` | 1 m 49 s | 1 | 1.8 |
| `golden-vectors` | 1 m 41 s | 1 | 1.7 |
| `tamper-matrix` | 1 m 32 s | 1 | 1.5 |
| `clippy` | 1 m 04 s | 1 | 1.1 |
| `vector-freeze` / `format-freeze` | 36 s / 34 s | 1 | 0.6 / 0.6 |
| `wasm32-core` / `audit-deny` / `core-dep-graph` | 32 s / 31 s / 27 s | 1 | 0.5 each |
| `fmt` | 24 s | 1 | 0.4 |
| `traceability` | 19 s | 1 | 0.3 |
| `secret-guard` | 6 s | 1 | 0.1 |
| **total** | | | **83.8** |

**The multiplier is the whole story for the two arms that move.** macOS is the
*fastest* of the three cross-OS arms in real time and the most expensive by a
factor of six. Together the two are **22.9 weighted min — 88 % of the cross-OS
lane and 27 % of the whole per-push bill.**

**A correction to the table's basis, recorded because it changes the number in
the safe direction.** These are *raw wall × multiplier*. GitHub bills each job
**rounded up to the whole minute** before applying the multiplier, which for this
matrix is **100 billed minutes** against 83.8 raw — **+19 %**, because 12 of the
19 jobs are under two minutes. Everything below is priced on the **raw** basis,
which understates both the bill and the saving. On the billed basis the saving is
~3 000 min/month rather than ~2 450.

### 1.2 How many pushes are docs-only

35 consecutive push ranges (36 `ci` push runs, `event: push`, 2026-07-27 →
2026-08-16), each range diffed with `git diff --name-only <prev> <this>`:

- **10 of 35 (29 %) touched no code at all.** Every one of them touched
  `TODO.md`, `tasks/`, or `docs/` — files this repository's own docs treat as
  "docs" and which the naive fix would have excluded.
- Under the exclusion this record actually rules, **9 of the 35 would be skipped**
  (ranges 5, 10, 11, 13, 17, 21, 23, 25, 26). The tenth — range 35, `b253ae8..10ddee1`
  — touches `docs/decisions/D135-*.md` and correctly still runs, per §2 R2.

### 1.3 What a `concurrency` block would save: nothing

Checked, because it is the standard next suggestion. Across the same 35
consecutive pairs, exactly **one** run was still in flight when its successor
started (run 2 → run 3, 2026-07-28, before the measurement window). A
`concurrency` group with `cancel-in-progress` would have cancelled **1 run in 35**
and its saving is inside the noise. **No `concurrency` block is added**, and this
paragraph is the measurement so the idea is not re-proposed.

---

## 2. The ruling

### §2 R1 — The `push` trigger of `ci.yml` is filtered. `pull_request` is not, and never will be.

```yaml
on:
  pull_request:
  push:
    branches: [main]
    paths-ignore:
      - TODO.md
      - tasks/**
      - docs/ci-verification.md
```

**The asymmetry is the ruling, not an implementation detail.** A required status
context whose workflow is skipped by path filtering **never reports at all** —
GitHub leaves the check pending rather than reading "the workflow was filtered
out" as "the check passed" — so a filtered `pull_request:` hangs every protected
pull request for ever. Branch protection is not enabled today and every `ci` run
on record is `event: push`, so the trap would not fire now; **it must not be
built in against the day it does.** Filtering `push` alone has no such failure
mode: a push has nothing to gate.

`scripts/check-ci-paths.py` **R2** fails if a `paths`/`paths-ignore` key ever
appears under `pull_request:` in **any** workflow in the directory.

### §2 R2 — The exclusion is three entries, and `docs/**` is refused on evidence

| excluded | why it is safe | why it is worth it |
|---|---|---|
| `TODO.md` | read only by `scripts/check-traceability.py`, which runs on `ci-always.yml` | 8 of the 10 docs-only pushes |
| `tasks/**` | same reader, same workflow | 1 of the 10 |
| `docs/ci-verification.md` | **opened** by no program; cited in three comments (`scripts/local-gate.sh:62,130`, `scripts/wasm-tests.sh:6`). It *is* inside the `docs` grep root of `scripts/wasm-toolchain-audit.sh`, so its safety is **content-conditional and re-checked every push by R4c**, not asserted once here | 5 of the 10 |

**REFUSED, with the reader that refuses it:**

- **`docs/decisions/**`** — `docs/decisions/D18-wasm-bindgen-surface-location.md`
  lines **752** and **976** contain `wasm-bindgen-cli --version 0.2.126`, and
  `scripts/wasm-toolchain-audit.sh:161-162` greps `docs` for that literal to
  assert the CLI pin equals the crate pin, inside `wasm32-core-tests`. This is
  **content-conditional**: the directory is not a read surface, *a matching line
  in it* is. R4c re-runs the grep against every excluded file on every push, so
  the day a decision record grows such a line the lane goes red **on that commit**
  instead of silently opening a hole.
- **`docs/format/**`** — `crates/antseal-core/tests/format_registry_freeze.rs:93-99`,
  `format_freeze.rs:69`, `scripts/format-freeze.sh:69-70`, and six
  `include_str!("…/docs/format/anchor-artifact-limits.md")` sites in
  `antseal-core/src/anchor/{caps.rs,ots/limits.rs}`.
- **`docs/testing/error-code-contract.md`** — `crates/antseal-core/src/error_universe.rs:775`.
- **`docs/testing/cbor-cross-check.md`** — `crates/antseal-core/tests/cbor_crosscheck_contract.rs:100,131`.
- **`docs/security-assumptions.md`, `docs/threat-model.md`, `docs/zeroization-audit.md`**
  — `crates/antseal-core/tests/security_assumptions_drift.rs:45,47,72`.
- **`docs/dependency-policy.md`** — `crates/antseal-core/tests/feature_pins.rs:185`.
- **`docs/research/C11-signature-probe.md`** — `feature_pins.rs:502`.
- **`MVP-SPEC.md`** — `crates/antseal-wasm/tests/page_template.rs:153`,
  `crates/antseal-core/tests/tamper_completeness/mod.rs:86`,
  `crates/antseal-core/src/anchor/model.rs:1630`.
- **`README.md`, `CONTRIBUTING.md`, `CHANGELOG.md`, `.gitattributes`,
  `.gitignore`, `requirements-crosscheck.txt`, `deny.toml`** — all read at
  runtime by something; the full inventory is in Q239's Notes.

### §2 R3 — The cheap checkers move to an unfiltered workflow. This is the correctness half.

`.github/workflows/ci-always.yml` (new) carries `traceability` and `secret-guard`,
**byte-identical job ids and `name:` values**, on `pull_request:` and an
**unfiltered** `push:`.

They had to move because **a GitHub path filter is workflow-level: there is no
per-job `paths:`.** And they had to move rather than being left behind, because
`traceability`'s inputs **are** the excluded files: it reads `TODO.md`, every
`tasks/*.md` and every `docs/decisions/D*.md`. **A docs-only push is that lane's
busiest case, not its emptiest.** A blanket `paths-ignore` on the one workflow
would have skipped the single check that most needed to run — a strictly worse
state than no filter at all. R6 of the checker fails if either context stops
being produced by a workflow whose `push` is unfiltered.

### §2 R4 — `paths` and `paths-ignore` are NOT complements. The mirrored-workflow shape is refused.

The tempting design is two mirrored workflows — `ci.yml` on `paths-ignore: [D]`
and a twin on `paths: [D]` — so that exactly one fires and no job ever moves
between files. **It cannot work.** Both filters quantify **existentially** over
the changed set: `paths-ignore: [D]` runs iff *some* changed file is outside `D`;
`paths: [D]` runs iff *some* changed file is inside `D`. A push touching one doc
and one source file satisfies **both**, both workflows fire, and every shared
context is produced **twice** — two check runs of one name that branch protection
cannot tell apart. R3's duplicate-producer check exists so this shape cannot be
rebuilt by accident.

### §2 R5 — `cross-os-macos` and `cross-os-windows` move to weekly; the Linux arm stays per-push

`.github/workflows/cross-os-extended.yml` (new) carries the two billed arms on
`schedule: "53 4 * * 0"` (Sunday 04:53 UTC, colliding with no existing cron),
`workflow_dispatch:`, and — **deliberately** — `pull_request:`. There is **no
`push:`**, and that absence is the entire saving.

`pull_request:` is present for the R1 reason: these are required contexts, and a
required context whose workflow never starts hangs a protected PR. Keeping it
means all 19 contexts still report on a pull request exactly as before.

**What it costs, stated plainly.** This repository is pushed to directly, so the
per-push run *was* these arms' only gate. Their coverage drops from **every push
to weekly plus every pull request**, and an OS-conditional divergence introduced
on a Monday can sit undetected until Sunday. The class narrowed is specifically
the OS-conditional one — `size_of` differences, path separators, line endings,
filesystem case-sensitivity — and this project has been bitten by exactly that
class before (Q125's `size_of::<x509_cert::Certificate>()`, on wasm32 rather than
macOS, which cost a CI red at `6f69e1a`). **This is a real trade, not a free
saving.** It is recorded in `scripts/local-gate.sh`'s header, which is the file a
contributor reads before a push.

The weekly cadence costs **22.9 × 4.33 = ~99 weighted min/month**, netted off
below. `scripts/ci-lanes.sh fuzz-budget` prices only `fuzz-nightly.yml` and does
not see this file; that gap belongs to **Q78**.

### §2 R6 — The context set stays at 19, and nothing about branch protection changes

| workflow | contexts |
|---|---|
| `ci.yml` | `fmt` `clippy` `test` `wasm32-core` `wasm32-core-tests` `core-dep-graph` `cross-os-linux` `golden-vectors` `cross-check` `vector-freeze` `format-freeze` `wasm-bitmatch` `tamper-matrix` `fuzz-smoke` `audit-deny` — **15** |
| `ci-always.yml` | `traceability` `secret-guard` — **2** |
| `cross-os-extended.yml` | `cross-os-macos` `cross-os-windows` — **2** |

**19 on `pull_request`, each produced exactly once. 17 on `push`.** Jobs *moved*;
none was added, removed or renamed. The branch-protection payload in
`docs/ci-verification.md` is **unchanged** and needs no external action.
`check-ci-paths.py` R3 asserts both event-sets against a frozen constant and
fails on any context produced twice, missing, or unregistered.

### §2 R7 — The filter is guarded by a committed checker, in the gate and in CI

`scripts/check-ci-paths.py`, two steps of `ci-always.yml`'s `traceability` job and
two lanes of `scripts/local-gate.sh`. **Zero new required-status contexts.**

Its placement is load-bearing rather than thrifty: it rides on the **unfiltered**
workflow, so it runs on every push **including the docs-only ones the filter
exists to skip**. On `ci.yml` it would have been skipped by exactly the pushes it
polices — a check that cannot run on its own subject.

---

## 3. Why a checker at all: a path filter is an assertion that cannot fail

Every other guard in this repository fails loudly when its subject drifts. A
`paths-ignore` **has no failure mode**. When it is wrong the job simply does not
run, and the absence of a red is indistinguishable from a green — it fails
*silently, in the direction of running less*, which is the one direction nothing
downstream can observe. It is a perfect breeding ground for this project's
dominant defect class, and nothing already in the tree could see it.

The checker's rules, each with a planted fault in `--self-test`:

| rule | what it asserts |
|---|---|
| **R1** | `DOCS_ONLY` in the checker is byte-equal, and in order, to `ci.yml`'s `paths-ignore`. One definition, mirrored once — the `BOUNDARY_COPIES` idiom of `check-traceability.py`, not two lists and a comment. |
| **R2** | no `pull_request` path filter anywhere; a filtered `push` uses `paths-ignore`, never `paths` (§2 R4). |
| **R3** | the per-event context sets equal the frozen 19 / 17, with no context produced twice. |
| **R4a** | no whole-string path literal, on a non-comment line, in anything `ci.yml` runs, resolves into the exclusion. |
| **R4b** | `include_str!`/`include_bytes!`, resolved against the source file. |
| **R4c** | no excluded file's **content** matches a registered `grep -r` surface's pattern — the D18 class. |
| **R4e** | every `scripts/x` edge out of a script `ci.yml` runs is classified as followed or unreached, with a reason, both directions stale-checked. |
| **R5** | every pattern matches ≥1 file; the exclusion matches neither nothing nor everything; every file it matches has a `.md` suffix, so a `.py` dropped into `tasks/` reds instead of becoming code no lane compiles. |
| **R6** | `traceability` and `secret-guard` are produced by an unfiltered `push`. |

**Two things the checker's own construction had to learn the hard way, both
recorded at the code so they are not undone:**

1. **The reader set cannot be closed blindly.** The first version followed every
   `scripts/x` reference transitively, dragged `scripts/check-traceability.py`
   into `ci.yml`'s reader set through `scripts/ci-lanes.sh` — a nine-lane
   dispatcher that `ci.yml` calls with seven subcommands, none of them
   `traceability` — and since that file opens `TODO.md` fourteen times, **every
   exclusion became unprovable.** This is D124 RULING 2's trap in a new suit:
   reading one level into a multi-lane callee attributes every lane's behaviour
   to every lane. Fixed by classifying all 26 edges explicitly, with a rule that
   an unclassified edge is a hard failure.
2. **`--self-test` failed on its first complete run, and the failure was real.**
   The arm "exclude `MVP-SPEC.md`, which `ci.yml`'s `test` reads" stayed
   **GREEN**, because both readers spell the path as an offset from
   `CARGO_MANIFEST_DIR` (`.join("../../MVP-SPEC.md")` and
   `concat!(env!("CARGO_MANIFEST_DIR"), "/../../MVP-SPEC.md")`) while the resolver
   anchored on the source file's directory. It resolved the first to
   `crates/MVP-SPEC.md` and the second to an absolute path, and matched neither.
   **The check reported green over a genuine read.** That is the best evidence
   available that the arms were not fitted to the check, and the fix
   (`crate_root()`) carries the story.

### 3.1 What this does NOT protect against

Stated here and at the code, because a guard whose limits are unwritten gets
trusted past them:

1. **A read whose path is computed and never appears as a literal** —
   `root.join("TO" + "DO.md")`, a repo-wide `**/*.md` walk, a path assembled from
   a variable. R4a reads string literals; it does not execute the program.
   `tasks/**` is defensible today because R5 pins the suffix set and the
   directory has one shape.
2. **A read by a third-party `uses:` action** rather than by a committed script.
   The reader set derives from `run:` blocks, which Q43 guarantees are script
   calls; `uses:` steps are opaque. None reads repo docs today.
3. **Semantic dependence without a read** — a test asserting a number a human
   keeps in step with a sentence in an excluded file. Nothing mechanical sees it.
4. **The filter being too narrow.** Every rule guards against excluding too much;
   excluding too little only costs minutes and is not an error.
5. **GitHub's actual matching.** The checker models a documented subset of the
   glob syntax and **refuses** the rest (`!`, `[`, `{`, `+`, `?`) rather than
   guessing — a mis-modelled negation would report a filter that reads one way
   here and another way to GitHub. It does not observe what GitHub did with a
   push.
6. **The coverage this ruling deliberately gives up**: macOS and Windows for up
   to seven days (§2 R5), and every `ci.yml` lane on a push that touches only the
   three excluded paths. The second is the point; the first is the price.

---

## 4. The saving

Basis: the §1.1 per-run costs (raw wall × multiplier), the window
**2026-08-01T11:12Z → 2026-08-16T11:16Z = 15.00 days, 32 `ci` push runs**, of
which **9 would be skipped** and 23 would still run.

| | weighted min |
|---|---|
| a code push, today | 83.8 |
| a code push, after | **61.0** (= 83.8 − 22.9 + 0.14 for the new guard) |
| a docs push, after | **0.54** (`traceability` + `secret-guard` + the guard) |

Marginal, **in this order** (the order matters — applied the other way round the
two shares swap):

- **docs filter first:** 9 × (83.94 − 0.54) = **751 min per window → ~1 500/month**
- **cross-OS on top:** 23 × 22.9 = 527 per window → 1 053/month, **less** the
  weekly add-back of 99 → **~954/month**
- **total ≈ 2 450 weighted min/month**, taking the monthly `ci`-push bill from
  ~5 360 to ~2 900 against a 3 000 allowance.

**What it assumes, and where it can be wrong:**

1. **The cadence.** 32 pushes / 15.00 days = 64/month; the whole 36-run history
   gives 55/month. The brief's ~1 375 corresponds to ~25/month. **Halve the
   cadence and halve the saving** — this is the dominant uncertainty and it is
   not reducible from here.
2. **That every skipped run would have executed its full matrix.** 13 of the 32
   runs in the window concluded `failure`, and a fast failure bills less, so the
   *before* figure is an **upper bound**. D135's independently measured
   whole-repository bill for 2026-08-01→15 — **3 154 weighted min over 538
   dispatched jobs**, re-measured at **3 324** — is the reality check, and the
   2 678 this record attributes to `ci` pushes alone sits sensibly inside it.
3. **The raw basis.** GitHub rounds each job up to the whole minute: 100 billed
   min per full run against 83.8 raw. On that basis the saving is
   **~3 000/month**. Pricing on the lower number is the conservative direction.
4. **That the guard's own cost is 0.14 min.** Measured: `--self-test`
   8.12/7.97/7.96 s and the check 0.59/0.57/0.58 s on a 2-core host, 2026-08-16.
5. **Not verified from GitHub's own counter.** `GET /users/aed900/settings/billing/actions`
   returns 404 — the token still lacks the `user` scope, exactly as D135 and
   `docs/ci-verification.md:1697` record. Every figure here is derived from the
   Actions API's per-job timestamps, not from the biller.

---

## 5. What this ruling owes

1. **`docs/ci-verification.md`** — its context table and branch-protection
   payload still describe three workflows and one `cross-os` matrix. The
   *contents* of the payload are unchanged (19 contexts, same names), but the
   **provenance** of four of them has moved between files and the runbook should
   say so. Not done here: that file is outside this lane's write scope, and it is
   itself one of the three excluded paths.
2. **`CONTRIBUTING.md`'s "CI lanes" table** (line 38 names the three `cross-os`
   contexts) — same reason.
3. **Q78** still owns the whole-allowance accounting. `fuzz-budget` prices one
   lane; `cross-os-extended.yml` is now a second scheduled workflow it does not
   see.
4. **A remote witness.** No lane here has run on the remote. Q43's rule — *a lane
   that has never run on the remote is not evidence* — applies in full, and the
   allowance is exhausted, so it cannot be discharged today. The first push after
   the limit is raised is the witness, and the observable is specific: **a push
   touching only `TODO.md` must produce exactly two check runs** (`traceability`,
   `secret-guard`) **and no `ci` run at all.**
