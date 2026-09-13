# D168 — the reproducibility comparison is **raised to a required push context** as an **unfiltered** workflow on push to `main` and every pull request; the pre-priced filtered shape is **unbuildable on this repository's own checker** and is advised against by GitHub; and D135 §3 R6's budget precondition is **restated as a falsifiable predicate** rather than declared trivially met

- **Status: RESOLVED. The lean fell clause by clause, and one clause fell hardest
  — on the house rule against assertions that cannot fail.**
  - **"Standard runners bill $0 on a public repository" SURVIVES** three checks
    that could have falsified it: GitHub's billing documentation, visibility
    `public`, and a census of every `runs-on` label (22 `ubuntu-latest`, 1
    `macos-latest`, 1 `windows-latest` — all standard). §1.1.
  - **"`billable` = 0 after the flip is the decisive measurement" FALLS on its
    premise.** The timing endpoint reads `UBUNTU.total_ms: 0` on pre-flip
    **private** run `33808001048`, which executed 8–15 steps per job on an
    assigned runner. The field is 0 either way, so it cannot fail — D135 §1.3
    recorded the same in August. §1.1.
  - **"D135 §3 R6's precondition is trivially met" FALLS.** A precondition that is
    trivially met is an assertion that cannot fail. §2 R2 restates it as three
    measured conjuncts with named reopen triggers.
  - **"D135 §10 R2's filtered separate workflow is still the right lane" is
    UNBUILDABLE AS RULED.** D164's recorded shape, constructed in memory and run
    through `scripts/check-ci-paths.py`'s own `check()`, goes red on **R1, R2
    and R3, each by its own message** — rules that landed in `a9007e5` on
    2026-08-16, eleven days before D164 recorded the shape as passing. GitHub's
    documentation says the same thing from the other side: *avoid requiring
    workflows that can be skipped*, because a path-filtered required check stays
    **Pending**. §1.3.
  - **The comparator has never run on a hosted runner.** Only two `pages` runs
    exist and both predate it. So `Q238` cannot tick on agent work alone. §1.4.
- **Date: 2026-09-13**
- Owner rows: **`Q238`** (stays OPEN until a hosted run reports the new context;
  its `Do` and `Accept` are amended by §2 R4), **`Q265`** (arming — unchanged by
  this record except that the payload it regenerates now carries **20**
  contexts), **`R25`** (its `Accept` row 1 re-cited at the new tier), **`R86`**
  (annotated).
- Related: **D135** §1.1 (the bill method), §1.3 (`billable` reads 0), §1.5/§4 R7
  (the commit stamp), §3 R1 (the deploy-gated tier this raises), §3 R6 (raise
  only by decision), §10 R2 (the pre-priced filtered arm this refuses);
  **D138** (push path filters on `ci.yml` and the context split); **D164** §1.4
  and §2 R6 (the filtered shape and the never-reported-context problem it named);
  **D165** (the owner of tag `R8` in `check-ci-paths.py`); **D166** (a workflow
  lands with its witness named).

## 0. What was measured against

`HEAD` `ef5f6d9`, public repository, read-only `gh api` GETs, and in-memory
fixtures passed to `check()` through its `extra_workflows` parameter with module
constants patched in memory only — the tree was byte-unchanged (planning lane C,
wave 35). Documentation quotes arrived through a paraphrasing fetch tool and are
marked as such where they carry weight.

## 1. What was measured

### 1.1 The bill, the D135 §1.1 way

Every run, every job rounded up to the whole minute, platform factors ×1/×2/×10,
jobs with no runner excluded:

| window | jobs | weighted (rounded up) | split |
|---|---|---|---|
| 2026-09-01T00:00Z → the flip, private | 64 | **596** | ci 244, fuzz 192, cross-os 86, devnet 60, ci-always 9, advisory 5 |
| the flip → 2026-09-13T00:25Z, public | 32 | **111** | CodeQL 50, ci 55, ci-always 6 |

The flip instant is bounded to (18:30:50Z, 20:34:41Z] on 2026-09-12 by the last
pre-flip `ci` run and the first `CodeQL Setup` run. **The budget premise had
stopped binding before the flip** (≈1 500 weighted minutes a month against
Pro's 3 000), and on a public repository the included-minutes inequality has
**no referent**: GitHub bills standard hosted runners in public repositories at
zero. The proxy figure stays recordable; it no longer fails.

### 1.2 The comparison stays meaningful although the module moves per commit

`scripts/wasm-pack-build.sh` stamps `git rev-parse HEAD` into the module, so the
published digest changes on every commit, documentation-only ones included.
`scripts/reproducible-build.sh --compare` resolves `HEAD` **once** and both
environments build that same commit, so **two environments at one commit** is
still a falsifiable claim. What no path filter can express is that `HEAD` itself
is an input — which is one more reason the filtered shape cannot describe its
own trigger.

### 1.3 The four shapes, through the checker that would judge them

| fixture | rules red |
|---|---|
| D164 shape as specified (`push: paths:` + unfiltered PR, in `REQUIRED_CONTEXTS` and `PUSH_EXEMPT`) | **R1, R2, R3** |
| the same with `paths-ignore` | R1, R3 |
| `paths:` without `PUSH_EXEMPT` | R1, R2 |
| unfiltered push(`main`) + PR, registered in `MUST_RUN_ON_EVERY_PUSH` — **arm (iii)** | **green** |
| arm (iii) gains `paths-ignore` | R1, R6 |
| arm (iii) loses its push trigger | R3, R6 |
| a job-level `if:` skip | green — **the checker cannot see it** |

A complete filter — one covering every file the tool-pin greps read, which is all
of `docs/`, `scripts/` and `.github/workflows/` — would still have run on **18 of
24** real push ranges (75 %), saving one free run in four. The `PUSH_EXEMPT`
precedent (`cross-os-extended.yml`) is a workflow with **no** push trigger, not a
filtered one.

### 1.4 The comparator's hosted history

`pages` has exactly two runs and both predate R86's comparison step, so the
comparison has **never executed on a hosted runner**. Its first hosted execution
will be either the first push carrying this lane or the next consented `pages`
dispatch, whichever comes first.

## 2. RULING

### §2 R1 — Arm (iii): an unfiltered workflow, required on push

A new `.github/workflows/reproducible-build.yml`: `on: push: branches: [main]` and
`pull_request`, **no path filter**, no job-level `if:`, no `concurrency`;
workflow-level `permissions: contents: read` and
`ANTSEAL_NO_REAL_ANCHOR_NETWORK: "1"`; one job whose id and `name:` are
`reproducible-build` (A9's greps select on `repro`); steps: pinned checkout,
toolchain, pinned rust-cache, `./scripts/wasm-tools-provision.sh`, **an explicit
`./scripts/wasm-pack-build.sh --build-only` before the comparison** (because
`prepare()` skips build A when an artifact already exists, and a restored cache
could supply a stale one — the hazard `verifier-page.yml` already documents), then
`./scripts/reproducible-build.sh --compare`. The context joins
`REQUIRED_CONTEXTS` (**19 → 20**) and `MUST_RUN_ON_EVERY_PUSH`. **Refused**: arm
(i), filtered (§1.3); arm (ii), an always-running job that short-circuits to
success — a skip that reports success is this project's dominant defect class and
its input set is content-dependent; arm (iv), the same job inside `ci-always.yml` —
no checker difference, and it mixes a cargo lane into the cheap workflow.

### §2 R2 — D135 §3 R6's precondition, restated so it can fail

The raise holds while **all three** conjuncts hold: (a) repository visibility is
`public`; (b) every `runs-on` label in `.github/workflows/` is a standard
GitHub-hosted label; (c) the D135 §1.1 proxy figure is recorded with its window
and command (§1.1 above). **Reopen triggers**, any one of which returns this tier
to a decision: visibility changes; a non-standard or larger runner label appears;
a billing read shows Actions charges. No checker is minted for (b): the census
found **0 true positives across 24 labels**, measured yield zero — the census is
recorded here instead.

### §2 R3 — The deploy gate stays

`pages.yml`'s comparison is **not** removed: the served artifact is only ever
checked there, and the push tier checks the tree, not the deploy.

### §2 R4 — `Q238`'s `Do` and `Accept` are amended, never deleted

`Do`'s mandate of a workflow-level `on: push: paths:` filter is **superseded** by
§2 R1 with this record cited. `Accept` rows 4 (a filter self-test) and 5 (the
filter input-set test) are **struck as moot** under an unfiltered lane — their
concern moves to §2 R5's decay arms. The `Accept` clause naming rule **`R8`** is
**restated**: tag `R8` belongs to D165's depth rule, so the clause now names the
`MUST_RUN_ON_EVERY_PUSH` registration and its decay arms. `Accept` row 1 (the bill
re-measured and recorded) is met by §1.1; row 2 (under the allowance) is met by
§2 R2's restated predicate; row 3 (a required status context with the count moved
in the same act) is met **locally** by the registration and **witnessed** only
when a hosted run reports the context — `Q265` arms it.

### §2 R5 — Checker changes, each with its decay arm

In `scripts/check-ci-paths.py`: `MUST_RUN_ON_EVERY_PUSH` becomes a mapping from
context to its **own** reason, so R6's message stops hard-coding the docs-lane
reason for every member; R3's message names `PUSH_EXEMPT` when a context is
required but exempt, instead of calling it unregistered. Self-test arms use
in-memory `extra_workflows` only and assert **whole finding sets**: arm (iii) green;
`+ paths-ignore` exactly `{R1, R6}`; push trigger removed exactly `{R3, R6}`; the
`PUSH_EXEMPT` mis-registration message contains `PUSH_EXEMPT`.

## 3. Fault plants

The four arms in §2 R5, judged by message, with arm (iii) as the green control.
Owed at the hosted witness, a **human read** rather than a checker (runs expire):
the run log's `the commit both builds stamp:` line, `build B: N s`, the
`reproducible across environments: …` line with the shared digest, the `A path=… CARGO_HOME=…`
and `B path=… CARGO_HOME=…` lines, and `two-environment comparison: N s`, plus build A's
duration from its own step — copied verbatim into `Q238`'s Notes. **Corrected before this
record landed, by the implementing lane:** as first written this named a `build A: …` line,
which the script prints only on a red path, so a green run would never have produced it.
**Refused with yield zero**: a rule refusing job-level `if:` on required contexts
(0 such `if:` across 8 workflows), and D164's proposed `R8` (tag taken; the
existing R1/R2/R3 already refuse its shape).

## 4. What this record does NOT decide

- **What "required" binds.** With one admin who pushes directly and zero pull
  requests ever, classic protection with `enforce_admins: false` and a ruleset
  with an admin bypass both constrain nobody, while a ruleset with no bypass
  rejects every direct push. That is the maintainer's to rule, at `Q265`.
- `Q78`'s re-cut of the fuzz budget constants, which this record's §1.1 makes
  measurable but does not rule.
- The live page, whose embedded module is stamped with a commit that no longer
  exists — minted as its own row, because no push-tier lane can repair a deploy.

## 5. Edit list — per write scope, with the lane named before this record was written

### W1 (the CI lane)
- New `.github/workflows/reproducible-build.yml` per §2 R1, with its pinned
  `uses:` rows reflected in `.github/action-pins.tsv` invocation counts.
- `scripts/check-ci-paths.py` per §2 R1 and §2 R5.
- `scripts/reproducible-build.sh`: header and `REPRO_TIER` to the push tier.
- `.github/workflows/pages.yml`: header prose that describes the tier.
- `docs/ci-verification.md`: A9, C2's regenerated payload (**20**), and every prose
  site stating 19 required contexts.

### Registrar — `TODO.md`, `tasks/{Q,R}.md`, `docs/decisions/README.md`, `docs/instrument-ledger.md`
- `Q238` per §2 R4; `R25` `Accept` row 1 re-cited; `R86` annotated; `Q265`'s
  payload count.
- `docs/instrument-ledger.md`: D164 §1.4's false *"pure in-memory"* certificate for
  `check-ci-paths.py --self-test` (it rewrites tracked files and has since
  `a9007e5`); D164's shape table recording "passes" for a shape that goes red; the
  `billable` field that cannot fail; run records and check runs past retention
  becoming deletable, which makes every cited run id an expiring pointer.
- Index row and register row for this record.

## Closing — this record is not consent

It authorises no push, no dispatch and no branch-protection or ruleset write. The
lane lands locally; its first hosted run is the witness, and that run needs a
consented push.
