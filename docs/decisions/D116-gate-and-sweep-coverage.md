# D116 — Q133, Q141, Q140: three places the gate and the sweeps are blind, and what each blindness actually is

- **Status: RESOLVED — all three rows execute, and all three of their headline
  numbers are wrong.** **Q133's** widening is *not* free: D109 §6.4 cmd 8
  measured the decision-resolution half and never measured the **Q58
  line-citation half**, which turns the lane **RED** on the first run — and the
  reason is not the `D77000` fixture the row names (that one is silent, exactly
  as claimed) but a second literal, `registry-v1.md:1097`, sixteen lines away.
  The self-exclusion is therefore **load-bearing**, not hygiene. **Q141's**
  *"measured cost ~4 s"* is wrong by an order of magnitude: `cross-check.sh
  --self-test` costs **46.4 / 55.7 s** here, tripling the gate's cross-check
  block — the 4 s figure belongs to `crosscheck_cbor.py --self-test` alone,
  measured here at **0.10 s**. The lane still lands, on a better argument than
  the row's: those 46 s buy planted faults on **six** surfaces, not one.
  **Q140** reproduces exactly as written and then exceeds its own scope in two
  directions: the row names **one** walker where the tree has **two** with the
  identical fatal rule (`vector_runner.rs`, which is CI's `golden-vectors`
  context), and the trigger is **not** *"runs or imports"* — running the
  checker creates nothing; only an **import** does, which is why no fix on the
  producer side has a producer to fix.
- **And the general measurement the brief asked for found the shape a third and
  fourth time, in the direction nobody has looked.** Q125, Q128 and Q141 are all
  *"CI runs it, the gate does not"*. The complete diff (§5) shows **five gate
  lanes with no CI counterpart at all** — the entire S22 feature-partition
  mechanism (`--self-test`, `--check-partition`, `--heavy`), the Q128 trigger
  self-test, and `e2e-devnet.sh --self-test`, whose cron sibling runs the lane
  **bare**. That is `docs/ci-verification.md`'s own rule — *"a lane that has
  never run on the remote is not evidence"* — violated by five lanes, with
  nothing saying so, while the gate header enumerates only the other direction.
  Plus one substantive undeclared argument divergence: the gate's `test` lane
  runs proptest at **256** cases where CI runs **1024**.
- **Date: 2026-08-10** (M2 wave 12 planning round)
- **Owning tasks: Q133, Q141, Q140** (all three closed by their rulings)
- **Amends**: `TODO.md`'s **Q133** row (the widening is not free; the named
  reason for the self-exclusion is the wrong literal), **Q141** row (*"~4 s"*),
  **Q140** row (*"`build.rs:175`"* is one of two sites; *"runs or imports"*);
  **`docs/decisions/D109-task-id-traceability-scope.md` §6.4 cmd 8 and §8 (i)**
  (cmd 8 measured one of the two failure modes `check_decisions()` has);
  **`scripts/local-gate.sh`'s header** (three undeclared divergence classes).
  **Supersedes**: nothing. **Binds against**: Q4/Q5's discovery contract
  (`testdata/vectors/README.md`), D87, D109 §3.3, D112 R1, Q43's
  never-run-on-the-remote rule, Q125/Q128's trigger contract.

---
- `docs/decisions/README.md` — this decision's index row. **Applied 2026-08-11**, executing [D119](D119-decision-index-identity-and-the-index-row-sections.md) §5 step 4; the former `## Index row` section is demoted to this line under D119 RULING 4, and RULING 6 puts the row in the act that commits the record.

## The problem, in one sentence

Three checks are believed to cover ground they do not: the decision sweep does
not read the gate scripts, the local gate does not run the half of the
cross-check that selects, and the vector walk treats a git-ignored dropping as
a build-breaking defect — and measuring each one turns up something larger than
the row.

---

## 1. What was measured

Everything below was executed on 2026-08-10, first against the working tree
(HEAD `5fbc48d` plus wave 12's uncommitted work) and then **re-executed against
that same state once it was committed as `d23dccc`**. Both planting experiments
reproduce byte-identically at `d23dccc`; every line anchor cited here
(`local-gate.sh:313`, `check-traceability.py:487`, `:1229`, `:1245`,
`build.rs:175`) was re-verified at that commit. Commands and verdicts are in §7.

*Recorded because it bears on the evidence's independence:* a full
`scripts/local-gate.sh` run was in flight on this tree during the first round of
planting. It finished **green — every lane PASS, exit 0, 2430 tests, zero
reds** — so the plants did not reach it; and the second round was run after
`d23dccc` was committed, on a quiet tree. Neither set of figures is
contaminated, and both were taken twice.

### 1.1 Q133 — D109 §6.4 cmd 8 measured one of the two things `check_decisions()` can fail on, and the other one is red

`check_decisions()` (`scripts/check-traceability.py:520-586`) raises **two**
distinct failure classes from **one** sweep of `DECISION_SCAN` ×
`DECISION_SUFFIXES`:

| # | class | source | trigger |
| --- | --- | --- | --- |
| 1 | Q57 — a cited `D<n>` that resolves to no record, no registered home, no open row | `:551-552`, judged at `:557-568` | bounded by `n > max(allocated) → skip` |
| 2 | Q58 — a citation of the frozen wire registry **by line number** | `:554-555`, judged at `:570-576` | regex `registry-v1\.(?:md\|json):\d+`, **no bound at all** |

D109 §6.4 cmd 8 records *"`scripts/` + `.github/` added to the **decision**
sweep → **0** new unresolved decisions — the widening in §8 (i) is free"*.
Re-measured here, that sentence is **true and incomplete**: it is a statement
about class 1 only. Class 2 has no ceiling, no allocation bound and no
suppression register, and it fires immediately.

Run against today's tree, with the real `check_decisions()` executed unmodified
except for the two constants (§7 cmd 3):

```
--- A0 today (control)
    scan=['crates', 'docs/format', 'docs/testing'] suffixes=['.json', '.md', '.py', '.rs']
    FAILURES: 0
    [decisions] ok — 100 distinct decisions cited, all resolve (94 have records, 5 homed
    elsewhere, 13 still open in the register); no line-number citations into the registry

--- A1 one constant: DECISION_SCAN := TASK_SCAN, no self-exclusion
    scan=['crates', 'docs/format', 'docs/testing', 'scripts']
    suffixes=['.json', '.md', '.mjs', '.py', '.rs', '.sh']
    FAILURES: 1
      * decisions: scripts/check-traceability.py: registry-v1.md:1097 cites the frozen wire
        registry by LINE NUMBER. Cite the section instead (e.g. `registry §7.14 key 1`): the
        registry is frozen, its line numbers are not, and a rotted pointer is silent

--- A2 D109 cmd 8 literal: + scripts/ + .github/ over .sh .mjs .yml .py
    FAILURES: 1   (the same one)

--- A3 one constant + self-exclusion
    FAILURES: 0   [decisions] ok — 100 distinct decisions cited …

--- A4 D109 cmd 8 + self-exclusion
    FAILURES: 0   [decisions] ok — 101 distinct decisions cited …
```

**So the widening is free only if the self-exclusion lands in the same
change** — which the row and D109 §8 (i) both require, for a reason that turns
out to be the wrong one.

### 1.2 `D77000` is real, is silent, and is **not** why the self-exclusion is needed

`D77000` is a **self-test fixture**, at `scripts/check-traceability.py:1229`:

```python
            (
                "decisions",
                "crates/antseal-core/src/bundle/error.rs",
                lambda t: t.replace("D78", "D77000", 1),
                "green",
            ),
```

It is the **green** arm of the decision check's own bound: the self-test stages
a scratch tree, rewrites a real `D78` citation in a real source file to
`D77000`, and requires the lane to **stay green** — because 77000 is above
`max(allocated)` and therefore not an allocated id at all. That is the
`D800`-Unicode-surrogate rule (`:507-509`) proven from the tree rather than
asserted.

The literal lives in `scripts/check-traceability.py`, which `check_decisions()`
does not read today because `scripts/` is not in `DECISION_SCAN`. The row and
D109 §8 (i) both say the self-exclusion is needed *"because this file carries
the literal `D77000` as a self-test fixture, skipped today only because 77000
exceeds the ceiling"*.

**Measured: that is exactly right about `D77000` and it is not the reason.**
`D77000` stays silent under every widening arm above — the ceiling holds, which
is the fixture working as designed. What actually goes red is **sixteen lines
further down**, at `:1245`:

```python
            (
                "decisions",
                "docs/testing/error-code-contract.md",
                lambda t: t + "\n\nSee `docs/format/registry-v1.md:1097` for the rule.\n",
                "red",
            ),
```

— the **red** arm of the Q58 half, whose whole job is to carry a
line-number citation as a literal. Class 2 has no ceiling to hide behind, so the
moment `scripts/` joins the scan, the checker reports **its own test fixture**
as a defect in the tree.

This is the same lesson as A21 in project memory, one function over: the reason
a shared input needs a guard is rarely the reason the analysis names. The
self-exclusion is **mandatory and load-bearing**, and the code comment that goes
with it must name `registry-v1.md:1097`, not `D77000`, or the next lane will
delete the exclusion after checking the wrong literal.

`grep -rn 'registry-v1\.\(md\|json\):[0-9]' scripts/ .github/` returns **exactly
one hit**, that one. There is no second landmine.

### 1.3 The counterfactual, planted and executed in both directions

The Accept requires *"a planted `D<n>` in a `.sh` under `scripts/` turns the
lane red"*. Executed as a four-point counterfactual on a staged copy of the
tree (§7 cmds 5–8), because making a `D<n>` **unresolvable** requires deleting
its record, which must not happen in the real tree:

| step | tree state | constants | verdict |
| --- | --- | --- | --- |
| control | staged copy, untouched | today's | **green** — 100 cited, all resolve |
| 1 | `docs/decisions/D19-advisory-lane.md` deleted; `scripts/zzz-d116-probe.sh` added citing *"per decision D19"* | today's | **GREEN — the hole** |
| 2 | same tree | proposed (`scripts/` + `.sh`/`.mjs` + self-exclusion) | **RED**, naming the file |
| 3 | probe `.sh` deleted | proposed | **green** |
| 4 | `D19` record restored | proposed | **green** |

Step 2's exact output:

```
::error::check-traceability [decisions] D19 is cited as normative
(scripts/zzz-d116-probe.sh) but has no record, no registered home in
DECISIONS_HOMED_ELSEWHERE, and no open entry in TODO.md's register
```

**`D19` was chosen by computation, not by taste**: it is one of only two
decisions (`D19`, `D109`) that are recorded, closed, and cited in **zero**
files of today's scan surface, so deleting its record cannot make some *other*
site fire and contaminate the counterfactual.

And on the **real** tree, where no `D<n>` can be made unresolvable (§1.4), the
same surface was proven read via class 2 (§7 cmd 9): a throwaway
`scripts/zzz-d116-probe.sh` carrying a line-number citation is **green today**
and **red under the proposed constants**, naming the planted file. The probe was
deleted and `git status --short` re-verified at 21 entries — identical to the
21 present when this lane started.

### 1.4 The D namespace is 100 % dense **and** 100 % resolvable, which decides how the new self-test case must be written

Measured over `TODO.md` + `docs/decisions/` + `DECISIONS_HOMED_ELSEWHERE`
(§7 cmd 4):

```
max allocated: 112 | allocated: 112 | open: 13 | records: 94
would-fail ids <= max: []
holes in allocation 1..max: []
```

94 records + 5 homed + 13 open = **112**, with **zero** holes in `1..112`. D109
§1.4 measured *"D1–D108, zero holes"*; four decisions later it is still exact.

Two consequences the implementing lane must not rediscover:

1. **No single-file transform can plant a class-1 red.** The self-test harness
   applies one `(check, path, mutate, expect)` tuple to **one** file
   (`:1394-1420`), and there is no `D<n>` whose mere citation fails. Making one
   fail needs a *second* edit (delete a record, or flip a checkbox), which the
   harness cannot express. The existing class-1 red case (`:1232-1241`) works
   only because it mutates `TODO.md` itself and lets an **existing** citation
   in `crates/wasm-bitmatch` do the naming — so it does not pin the `scripts/`
   surface.
2. **The `.sh`-surface case must therefore be a class-2 case**, which *is* a
   one-file transform and is guaranteed red. This is not a compromise: it is
   the same sweep, the same `DECISION_SCAN` loop, the same file list. If the
   suffix set or the scan root ever narrows back, the case goes green and the
   lane says so — which is exactly what case (b) does for `--task-citations`
   at `:1302-1307`.

### 1.5 Q140 — reproduced, with the real error text, and it is worse than the row says

`testdata/vectors/v1/__pycache__/` created with a genuine `.pyc`
(`py_compile.compile('testdata/vectors/v1/crosscheck_cbor.py')`), then
`cargo check -p wasm-bitmatch --locked` (§7 cmd 11):

```
error: failed to run custom build command for `wasm-bitmatch v0.0.0`
Caused by:
  process didn't exit successfully: `…/build-script-build` (exit status: 101)
  --- stderr
  thread 'main' (373087) panicked at crates/wasm-bitmatch/build.rs:175:13:
  /home/deb/Documents/code0/testdata/vectors/v1/__pycache__/crosscheck_cbor.cpython-311.pyc:
  unclassifiable file under vectors/v1/ — every file must be a vector (*.json) or a
  documented auxiliary (README.md, *.py, FROZEN.sha256, INDEX.json); nothing is silently
  skipped (Q4/Q5)
```

`cargo check --workspace --locked` fails identically (**rc 101**), so *"hard-fail
the entire workspace build"* is exact.

**Three findings the row does not have.**

**(a) There are two walkers with the identical fatal rule, not one.**
`crates/antseal-core/tests/vector_runner.rs:74-108` is the Q4 runner and carries
the same closed classification, worded almost identically. With the same
`__pycache__` present (§7 cmd 12):

```
---- vector_runner_discovers_and_executes_every_committed_vector stdout ----
thread '…' panicked at crates/antseal-core/tests/vector_runner.rs:142:73:
…/testdata/vectors/v1/__pycache__/crosscheck_cbor.cpython-311.pyc: unclassifiable file
under vectors/v1/ — … nothing is silently skipped (Q4)
test result: FAILED. 7 passed; 1 failed
```

That test is the substance of CI's **`golden-vectors`** required context
(`ci-lanes.sh:791`, `cargo test -p antseal-core -- vector_`), of the
**`cross-os`** matrix (`:782`, the `vector_` filter on all three OSes), and of
the `test` lane. **A fix to `build.rs` alone leaves four required contexts still
brickable by a `.pyc`.**

> **Predicate added 2026-08-11 under `Q196`. The finding above is
> byte-unchanged and is neither struck nor replaced, because it is not wrong**
> — see *"Correction — the section numbers in the Amendment above, and what
> §1.5(a)'s 'two walkers' counts, 2026-08-11"* below for the routing under
> D117 §2.3. What this figure counts is **walks carrying the identical closed
> classification rule**, not walks over the tree. Q157's later census counts a
> different predicate — *walk sites* of every class — and finds **twelve**, of
> which exactly **two** are `closed`: these two. The twelve does not supersede
> the two; it confirms it and re-denominates it. Both figures are true today,
> and a sentence that carries only the number invites the reading that one
> replaces the other, which `tasks/Q.md`'s `Q196` row is the measured instance
> of.
>
> **This finding was not measured under `cargo test`'s fail-fast.** It was
> reached by reading `vector_runner.rs`'s classification and confirmed by two
> commands that name their targets — §7 cmd 11's `cargo check` and §7 cmd 12's
> single-target `cargo test --test vector_runner`, whose own transcript above
> (`7 passed; 1 failed`) shows the target counted to completion. `--no-fail-fast`
> would have changed nothing here.

**(b) A third walker over the same tree is naturally immune, and the reason is
the rule shape.** `vector_freeze.rs`'s `collect_json` (`:273-297`) filters
**positively** for `.json` instead of asserting a closed classification, so it
recurses into `__pycache__` and finds nothing to say. With the `.pyc` planted,
`cargo test -p antseal-core --test vector_freeze --test vector_index` is **19
passed / 3 passed** and `./scripts/vector-freeze.sh` prints **`vector-freeze:
GREEN`**. `crosscheck_cbor.py`'s `discover()` (`:505`,
`VERSION_DIR.rglob("*.json")`) is immune for the same reason. So the tree
already contains the tolerant shape; the two fatal walkers are the outliers.

**(c) The class is wider than Python bytecode.** `.gitignore` also declares
`*.swp` expected (`:50`). Planted (§7 cmd 13):

```
thread 'main' panicked at crates/wasm-bitmatch/build.rs:175:13:
/home/deb/Documents/code0/testdata/vectors/v1/.crosscheck_cbor.py.swp: unclassifiable file
under vectors/v1/ — …
```

**Editing `crosscheck_cbor.py` in vim bricks the workspace build for as long as
the editor is open.** A `__pycache__`-shaped fix does not touch this.

### 1.6 Q140 — the row's trigger is wrong, and that is what kills the producer-side fix

The row says the directory *"returns whenever anyone **runs or imports**
`crosscheck_cbor.py` without `-B`"*. Measured, in a staged copy so the real
tree was never dirtied (§7 cmd 14):

```
--- run the checker directly (no -B) ---
rc=0
(after direct run: NONE)
--- import it as a module (no -B) ---
rc=0
(after import: __pycache__)   crosscheck_cbor.cpython-311.pyc
```

**Running it creates nothing.** CPython writes `__pycache__` for *imported*
modules, never for the `__main__` script. And the tree's only automated
invocation — `scripts/cross-check.sh:122`, `"$python" "${path}" --check` — is a
direct run.

So the producers are: a developer's `import`, an editor's language server, a
REPL, a `pytest` collection, a future Rust test that shells out to
`python3 -c "import crosscheck_cbor"`, and — for `.swp` — vim. **There is no
invocation in this repository to add `-B` to.** That is not an argument about
elegance; it is the observation that the producer-side fix has no producer.

### 1.7 Q141 — the cost figure is wrong by an order of magnitude, and the wrong figure is a real one from the wrong subject

> **Signpost added 2026-08-11 under `Q196`; nothing in this section is
> corrected.** This section is Q141's **cost** figure and nothing else. If you
> arrived here looking for a finding about directory **walks**: the *"two
> walkers"* finding is **§1.5(a)**, the two naturally immune walks are
> **§1.5(b)**, and the discovered-work item that became `Q157` is **§9 item 5**.
> Two live documents send a reader to this section for a walk finding and
> neither citation resolves — the Amendment below (*"§1.7's extra directory
> walks as `Q157`"*) and `tasks/Q.md`'s `Q196` row (*"D116 §1.7 concluding
> Q140's radius was 'two walkers'"*). See the correction section at the end of
> this document. §9 item 8 cites this section correctly, for the cost figure.

Three timed runs (§7 cmd 15):

| command | wall |
| --- | --- |
| `./scripts/cross-check.sh --self-test` | **55.66 s**, then **46.41 s** |
| `./scripts/cross-check.sh --check` | 24.63 s, then 22.48 s |
| `python3 testdata/vectors/v1/crosscheck_cbor.py --self-test` | **0.10 s** |

The row (from D112 §8.5) says *"The self-test costs ~4 s locally"*. Neither
number is 4 s. The figure is closest in spirit to the **0.10 s** one — the
CBOR checker alone, the only surface the 2026-08-09 incident touched — and the
flag the gate would actually add is the **46 s** one, because
`cross-check.sh --self-test` stages a copy of `testdata/` and plants faults on
**six** surfaces (`crosscheck-provenance.py`, `reference.py`'s own T0 anchors,
the hkdf/crypto/fine-tree generators, the UTF-8 corpus, the CBOR checker,
`crosscheck-report.py`).

The gate's cross-check block goes from ~23 s to **~70–80 s**. The ruling does
not change — but the *argument* does, and for the better: 46 s does not buy one
lane's non-vacuity, it buys **six surfaces' planted faults**, five of which no
local lane has ever exercised.

The row's other premises hold exactly. `scripts/local-gate.sh:313` runs
`--check` and never `--self-test`; `.github/workflows/ci.yml:382-385` runs them
as separate steps; and D112's Amendments record both live self-test defects
(planting inside the `try`; a bare `StopIteration` past `main`'s handler)
reproducing at `5fbc48d` — **both invisible to `--check` by construction**.

### 1.8 The general measurement — the shape found twice more, in the direction nobody has looked

The gate header (`local-gate.sh:5-37`) is an honest artifact and its ten
entries are, item by item, correct. But it answers only one question — *what
does CI run that I do not?* — and the complete diff (§5) shows the other
direction is where the undeclared gaps are.

**Five gate lanes have no counterpart in any workflow.** `grep -rc
'gate-features' .github/` returns **0 hits**:

| gate lane | CI counterpart |
| --- | --- |
| `scripts/gate-features.sh --self-test` | **none** |
| `scripts/gate-features.sh --check-partition` | **none** |
| `scripts/gate-features.sh --heavy` (S22 tier 2) | **none** |
| `scripts/wasm-bitmatch.sh --trigger-self-test` (Q128) | **none** |
| `scripts/e2e-devnet.sh --self-test` (D52) | **none** — `devnet-e2e-cron.yml:119` runs `./scripts/e2e-devnet.sh` **bare**, the lane without its self-test |

The last one is **Q141's exact shape, inverted**: one venue runs `--self-test`
and not the lane, the other runs the lane and not `--self-test`, and neither
says so. And the S22 rows mean the **HEAVY features are compiled by zero CI
lanes** — `HEAVY_FEATURES` is `antseal-cli/ant-backend`,
`antseal-net/ant-backend`, `devnet-launcher/devnet`, and `ci-lanes.sh
dep-graph` positively *asserts* the default `--workspace` graph does not reach
them (`:644-656`). So the only machine that ever compiles them is a
contributor's, when the diff triggers it.

This matters because `docs/ci-verification.md` states the governing rule in the
opposite direction and the gate's own comment quotes it (`local-gate.sh:259-261`):
*"a lane that never runs locally is not evidence either (Q43's rule, in its
local dual)"*. The dual of the dual is unwritten: **five lanes have never run
on the remote.**

### 1.9 The one substantive argument divergence the header does not carry

`.github/workflows/ci.yml:152` sets `PROPTEST_CASES: "1024"` on the `test` job.
`grep -c 'PROPTEST' scripts/local-gate.sh` returns **0**, so the gate runs
proptest's default — **256** cases (`docs/testing/proptest-conventions.md`
§4's own table). **A green local `test` lane has explored one quarter of the
input space CI will.** `docs/ci-verification.md:342` and the conventions doc
both record the CI value; neither the gate header nor its `test` line says the
gate does not reproduce it, and the header is the artifact a contributor reads
when deciding whether a green gate is enough.

The other four argument divergences were measured and are **not** substantive,
which is worth recording so nobody re-opens them:

| divergence | measured verdict |
| --- | --- |
| CI `cargo fmt --check` vs gate `cargo fmt --all -- --check` | **identical**: both emit the same **101** files, `diff` clean. The root manifest is virtual, so `workspace_default_members == workspace_members == 6` |
| CI `cargo clippy --all-targets` vs gate `--workspace --all-targets --features LIGHT` | `--workspace` is a no-op for the same reason; the LIGHT features are already unified through dev-dependency self-edges (`antseal-core/Cargo.toml:134`, `antseal-cli/Cargo.toml:138`) |
| CI `cargo test --workspace` (default) vs gate `--features LIGHT` | **identical test selection: 2440 = 2440** via `-- --list`. The explicit LIGHT line is belt-and-braces today; it stops being redundant the moment a feature is declared that no dev-dep edge enables, which is precisely what `--check-partition` exists to notice |
| CI `./scripts/wasm-bitmatch.sh` (bare) vs gate `--check` | **identical**: `wasm-bitmatch.sh:407` is `""\|--check) cmd_lane 0` — one branch |

And one deliberate divergence that is declared in code but not in the header:
the gate omits `--require` on `cross-check.sh`, so a machine without `cbor2`
gets a visible `SKIP` where CI gets a hard failure (`local-gate.sh:309-312`
says why; the header does not repeat it).

---

## 2. The options, and what kills each

### Q133

**(a) Widen `DECISION_SCAN` and leave the self-exclusion for later — refused.**
It is the only arm that is *measurably* red on the first run (§1.1 A1/A2). The
lane would go red on its own fixture, and the obvious repair — deleting or
rewording the fixture — destroys the Q58 red case.

**(b) Two constants with a comment saying why they differ — refused.** There is
no *why*. The scan sets would be `["crates","docs/format","docs/testing"]` and
`["crates","docs/format","docs/testing","scripts"]`, and the only honest comment
is *"these are the same, one is stale"*. D112's whole subject was a rule written
twice held in step by a comment; installing a second instance of that shape one
file over, in the same wave, is not available.

**(c) Add `.github/` and `.yml` too, as D109 cmd 8 literally measured —
refused for now, and it is close.** It is green (§1.1 A4) and adds one new
resolvable citation. But the workflows are already covered by a purpose-built
checker (`scripts/check-ci-shell.py`, which enumerates every `run:` block in
**all three** workflows), the `.yml` suffix would drag the whole `.github/`
tree into a sweep tuned for prose and code, and `TASK_SCAN` — the constant this
becomes — does not include it either, so adding it here re-creates the
asymmetry from the other side. Named in §9 as its own question with the
measurement already done.

**(d) One constant, `scripts/` in, self-exclusion in the same change — the
ruling.** §3 R-Q133.

### Q141

**(a) Add `--self-test` to the gate's cross-check block — the ruling**, with
the cost restated honestly and the ordering the rest of the gate already uses.

**(b) Run only `crosscheck_cbor.py --self-test` (0.10 s) — refused.** It is the
surface the incident touched, and choosing it would repeat the incident's own
error one level up: picking the half you happen to be thinking about. Five other
surfaces have planted faults that no local lane has ever fired, and
`cross-check.sh --self-test` is the only thing that fires them. Also, the gate
would then invoke the Python checker directly, bypassing the `--setup`/exit-2
provisioning contract that `cross-check.sh` owns.

**(c) Leave it and sharpen the header instead — refused.** The header already
says the `--self-test` half is CI-only. It said so through the 2026-08-09
incident, and the incident happened anyway. A sentence that has already failed
to prevent the thing it describes is not the instrument.

### Q140

**(a) Fix it in `.gitignore` — refused outright.** The two rules disagree and
`.gitignore` is the one that is right. Its own comment records that *"one such
file reached a commit during the wave-7 freeze before this rule existed"*, and
un-ignoring `__pycache__/` under a directory whose entire point is
byte-for-byte freezing would invite bytecode into `FROZEN.sha256`'s
neighbourhood.

**(b) Fix it at the producer (`-B`, `PYTHONDONTWRITEBYTECODE`,
`sys.dont_write_bytecode`) — refused, on §1.6.** Running the checker creates
nothing; only an import does, and the repo contains no import to flag. The
producers are humans and editors. It would also be a fix that must be
*complete* to work: one un-flagged `import` anywhere reinstates the brick. And
it does nothing at all for `.swp` (§1.5c).

**(c) Skip `__pycache__` only when the name matches exactly **and** every file
under it is `.pyc` — refused.** It makes a directory's classification depend on
its contents, so a stray `.json` saved into `__pycache__` by accident flips the
whole directory from ignorable to fatal with a message about the wrong thing;
`.pyo`, `.nbi`/`.nbc` (numba) and future CPython artifacts each need a new
clause; and it still leaves `.swp`, `.idea/`, `.vscode/` fatal. It buys nothing
over (d) that Q4/Q5's intent needs, because a `.pyc` is not a candidate vector
under any rule.

**(d) One shared, explicitly-named ignorable classifier used by **both** fatal
walkers, derived from `.gitignore` by an assertion — the ruling.** §3 R-Q140.

---

## 3. Ruling

**R-Q133. One constant, and the self-exclusion in the same commit, named for
the literal that actually fires.** `DECISION_SCAN`/`DECISION_SUFFIXES` and
`TASK_SCAN`/`TASK_SUFFIXES` collapse into **one pair of constants** used by both
sweeps; `check_decisions()` adopts `TASK_SCAN_SELF`'s self-exclusion **and**
`sweep_task_surfaces()`'s `{"target","node_modules","__pycache__"}` prune. The
comment on the exclusion names **`registry-v1.md:1097` at `:1245`** as the
literal that turns the lane red, and records `D77000` as the fixture that is
correctly silent — because the next reader will check the named one.

**R-Q141. The gate runs `cross-check.sh --self-test` before
`cross-check.sh --check`**, on the same exit-0/2/other contract, through **one**
shared invocation helper rather than two copies of the `case $?` block. The
cost recorded in the comment is the measured **46.4 / 55.7 s**, labelled as a
two-run sample on this host, in the idiom `local-gate.sh:179-195` already uses
for Q128's figures — never *"~4 s"*.

**R-Q140. `__pycache__` is pruned and the git-ignored droppings are classified
ignorable, in one classifier shared by both fatal walkers, checked against
`.gitignore`.** Q4/Q5's intent is protected by what is *unchanged*: every
`*.json` is still discovered, executed and counted; every unclassifiable file
that is **not** on the ignorable list is still fatal; and the "zero vectors
discovered" panic is untouched, so a rule that accidentally swallowed the tree
still fails the build.

**R-D. The three rows' headline figures are amended** (§1.1, §1.5, §1.6, §1.7),
and `local-gate.sh`'s header gains the three undeclared divergence classes
(§1.8, §1.9) as a second short list: *what this gate runs that CI does not*.

---

## 4. Riders — normative, cite by number

### R1 — The single scan constant (Q133)

`scripts/check-traceability.py`'s two constant pairs become one pair, placed
where `DECISION_SCAN` is today, with both consumers pointed at it:

```python
# Where BOTH sweeps look. Normative surfaces only — TODO.md is the register
# itself and tasks/*.md are working notes, so neither is a citation site.
# `scripts/` is in because the gate is committed code and a dangling pointer
# there is as normative as one in `crates/`; it is the surface that hid `A71`
# in `scripts/fuzz.sh:98-103` from the task half and every `D<n>` in
# `scripts/*.sh` from the decision half (D116 §1.1).
# `docs/decisions/` is deliberately OUT — D109 §3.3: a record's job includes
# PROPOSING work the orchestrator may number, renumber or decline, and
# sweeping it fails 13 rows for ids that D92 and D93 merely proposed. It is
# also where THIS document's captured evidence lives, which contains a
# `registry-v1.md:<n>` literal on purpose (D116 §1.3).
# `.github/` is deliberately OUT and it is a close call — see D116 §2 (c).
CITATION_SCAN = ["crates", "docs/format", "docs/testing", "scripts"]
CITATION_SUFFIXES = {".rs", ".md", ".json", ".py", ".sh", ".mjs"}

# This file names task AND decision ids as literals in its registers and plants
# them in `--self-test`. Sweeping it reports its own fixtures.
#
# NOT because of `D77000` (`:1229`), which is the GREEN arm of the ceiling rule
# and stays silent under every widening — measured, D116 §1.2. The literal that
# actually turns the lane red is `docs/format/registry-v1.md:1097` at `:1245`,
# the RED arm of the Q58 line-citation check, which has no ceiling, no
# allocation bound and no suppression register. Check that one before ever
# deciding this exclusion is unnecessary.
CITATION_SCAN_SELF = "scripts/check-traceability.py"
```

`DECISION_SCAN`, `DECISION_SUFFIXES`, `TASK_SCAN`, `TASK_SUFFIXES` and
`TASK_SCAN_SELF` are **deleted**, not aliased: an alias is a second name for
one thing and the next reader has to prove they are equal.

### R2 — `check_decisions()`'s loop body reaches parity (Q133)

At `:537-555`, the two lines that differ from `sweep_task_surfaces()`:

```python
        for path in base.rglob("*"):
            if not path.is_file() or path.suffix not in CITATION_SUFFIXES:
                continue
            if {"target", "node_modules", "__pycache__"} & set(path.parts):
                continue
            rel = str(path.relative_to(ROOT))
            if rel == CITATION_SCAN_SELF:
                continue
```

The `__pycache__` prune is not cosmetic parity: `scripts/__pycache__/` exists in
this tree today (`check-anchor-net.cpython-311.pyc`), and while `.pyc` is not in
the suffix set, the two sweeps having different prune sets after being given one
scan set is exactly the divergence R1 exists to end.

### R3 — The `[decisions] ok` line reports the files it swept (Q133)

`check_task_citations` already prints *"across 352 files"*; `check_decisions`
prints no such number, so a scan silently narrowing back to three roots is
invisible in a green log. The ok line at `:581-586` gains the count, in the
sibling's wording, computed from the same loop.

### R4 — The new self-test case, and why it is a class-2 case (Q133)

One case appended to the list at `:1226`, in the idiom of case (b) at
`:1302-1307`:

```python
            # The `scripts/` surface really is swept by the DECISION half too.
            # Without this case, R1's widening is unproven and a later edit
            # could narrow CITATION_SCAN back to the three doc/code roots with
            # nothing noticing — which is the state that hid every `D<n>` in
            # `scripts/*.sh` until D116.
            #
            # It plants the Q58 line-citation rather than an unresolvable
            # `D<n>` DELIBERATELY, and the reason is measured (D116 §1.4):
            # D1–D112 is dense with ZERO holes and every id resolves, so no
            # single-file mutation can make a `D<n>` citation fail — and this
            # harness applies exactly one mutation to exactly one file. The
            # Q58 half needs no allocation to fail, and it exercises the SAME
            # sweep, the same suffix set and the same file list.
            (
                "decisions",
                "scripts/fuzz.sh",
                lambda t: t + "\n# key layout: docs/format/registry-v1.md:1097\n",
                "red",
            ),
```

`scripts/fuzz.sh` is the target for the same reason case (b) uses it: it is the
file whose real `A71` citation proved the surface matters.

**Do not "improve" this into a class-1 case by adding a hole to the D
namespace.** The density is a property of the register, not a deficiency.

### R5 — The gate's cross-check block (Q141)

`local-gate.sh:305-322` becomes one helper and two calls. The helper is
required, not stylistic: the block is bespoke *because* of the exit-2 SKIP
contract, and copying it would put that contract in two places in the same file
— D112 R1's lesson, one script over.

```bash
# F14 — the independent cross-check (decision D31; contract:
# docs/testing/cbor-cross-check.md). Not a cargo lane: its whole value is that
# it shares no code with the crate it checks.
#
# SELF-TEST FIRST, like format-freeze, features, ci-lanes and vector-freeze.
# Q141, and the reason is a measured incident rather than symmetry: on
# 2026-08-09 the CBOR checker's scope rule was written twice, `run` was
# narrowed and `self_test` was not, and the tree was GREEN under `--check` and
# RED under `--self-test`. CI runs them as separate steps and only the second
# one selects, so CI saw it and THIS GATE STRUCTURALLY COULD NOT. Q130's three
# new instruments — the swept subject set, the computed fault counts, the
# non-vacuity CheckFailure — are all invisible to `--check` for the same
# reason: `--check` verifies committed bytes, `--self-test` verifies that the
# checker can still fail.
#
# COST, measured here 2026-08-10, two runs on this 2-core host: `--self-test`
# 55.66 s then 46.41 s; `--check` 24.63 s then 22.48 s. So this block roughly
# triples, to ~70-80 s. Two samples, one host, one day — the weaker kind of
# figure, and it says so (the provenance rule in the wasm-bitmatch block
# above). It is NOT the "~4 s" that reached TODO.md: that figure belongs to
# `crosscheck_cbor.py --self-test` alone, which is 0.10 s. The 46 s buys
# planted faults on SIX surfaces (provenance, reference.py's T0 anchors, the
# generators, the UTF-8 corpus, the CBOR checker, the report checker), five of
# which no other local lane exercises at all.
#
# Exit 2 means the dev tool is not provisioned on THIS machine. That is a
# visible SKIP locally, with the one-line fix printed — and a hard FAILURE in
# CI, where the `cross-check` lane passes --require so a freeze-gate input can
# never go quietly missing.
crosscheck_lane() {
  local label="$1"; shift
  local out; out=$(scripts/cross-check.sh "$@" 2>&1); local rc=$?
  case $rc in
    0) printf '  %-16s PASS  (%s)\n' "$label" \
         "$(printf '%s' "$out" | tail -1 | cut -c1-90)" ;;
    2) printf '  %-16s SKIP  (cbor2 not provisioned — scripts/cross-check.sh --setup)\n' \
         "$label" ;;
    *) printf '  %-16s FAIL\n' "$label"
       printf '%s\n' "$out" | tail -25
       fail=1 ;;
  esac
}
crosscheck_lane cross-check-st --self-test
crosscheck_lane cross-check    --check
```

The label stays within the `%-16s` field. The self-test inherits the exit-2 SKIP
by construction, which is correct: on a machine without `cbor2` neither half can
run, and one SKIP line per half is the honest report.

### R6 — The gate header (Q141, and §1.8/§1.9)

Two edits.

The `cross-check` entry in the existing list loses the `--self-test` half (the
gate now runs it) and keeps `cbor-drift-guard`, with the measured note that
`cbor-drift-guard` is `cargo test -p antseal-core --all-features --test
cbor_crosscheck_contract`, that `antseal-core` declares only `test-util` and
`test-vectors`, that both are LIGHT, and that the gate's `test` lane therefore
already runs that target at the same feature set — so the residual gap is the
lane's *identity*, not its coverage.

And a **second short list** is added under the first, because the header today
answers only one of the two questions a reader has:

```
# And what a green run of this script asserts that CI DOES NOT (the other
# direction, and the one nothing has recorded until D116 §1.8):
#
#   gate-features --self-test        no CI job runs scripts/gate-features.sh
#   gate-features --check-partition  at all. S22's whole partition mechanism —
#   heavy-features                   including tier 2 — is local-only, and the
#                                    HEAVY features (antseal-cli/ant-backend,
#                                    antseal-net/ant-backend,
#                                    devnet-launcher/devnet) are compiled by
#                                    ZERO CI lanes; `ci-lanes.sh dep-graph`
#                                    positively asserts the default graph does
#                                    not reach them.
#   bitmatch-trigger                 Q128's trigger self-test: local-only.
#   e2e-selftest                     devnet-e2e-cron.yml runs
#                                    `./scripts/e2e-devnet.sh` BARE — the lane
#                                    without its self-test. Q141's shape,
#                                    inverted.
#
# That is Q43's rule pointing the other way — "a lane that has never run on
# the remote is not evidence" (docs/ci-verification.md) — and these five have
# not. Recorded, not fixed: moving them is a required-context change.
#
#   PROPTEST_CASES                   ci.yml sets 1024 on the `test` job; this
#                                    script sets nothing, so the `test` lane
#                                    below runs proptest's default of 256. A
#                                    green `test` here has explored a QUARTER
#                                    of the cases CI will
#                                    (docs/testing/proptest-conventions.md §4).
```

### R7 — The ignorable classifier (Q140)

One function, written once and **shared** by `crates/wasm-bitmatch/build.rs` and
`crates/antseal-core/tests/vector_runner.rs`. They are in different crates and a
build script cannot import a test module, so "shared" here means **one text, one
list, and a test that fails if the two copies diverge** — the same technique
`cbor_crosscheck_contract.rs` uses on the Python checker and that
`wasm-bitmatch.sh --trigger-self-test` arm 4 uses across two shell scripts.

```rust
/// Names the discovery walk must ignore rather than classify.
///
/// Q4/Q5 say nothing under `vectors/v<n>/` is SILENTLY skipped, and that rule
/// is unchanged: every `*.json` is still discovered, executed and counted, and
/// every file that is neither a vector, nor a documented auxiliary, nor on
/// this list is still a hard failure naming the path.
///
/// What this list adds is the distinction Q4/Q5 never had to draw, because in
/// 2026-07 nobody had yet run a Python import inside the vector tree: a file
/// the REPOSITORY ITSELF declares is not part of the tree is not an
/// unclassifiable vector, it is not a vector at all. `.gitignore` is where
/// that declaration lives, and `__pycache__/` has been in it since the wave-7
/// freeze — so before D116 the tree carried two rules that disagreed about
/// whether the same directory was expected, and the build-breaking one won.
///
/// Measured (D116 §1.5): a `.pyc` here failed `cargo check --workspace` with
/// exit 101, and so did `vector_runner`, which is CI's `golden-vectors`,
/// `cross-os` and `test` contexts. A vim swap file did the same, so editing
/// `crosscheck_cbor.py` bricked the workspace build for as long as the editor
/// was open.
///
/// `vector_freeze.rs`'s `collect_json` needs no such list because it filters
/// POSITIVELY for `.json` instead of asserting a closed classification, and is
/// green through all of the above — the tolerant shape was already in the tree.
const IGNORED_DIRS: &[&str] = &["__pycache__", ".idea", ".vscode"];
const IGNORED_SUFFIXES: &[&str] = &[".pyc", ".pyo", ".pyd", ".swp", ".swo"];
const IGNORED_NAMES: &[&str] = &[".DS_Store"];
```

**Directories are pruned, not walked** — an ignored directory's *contents* are
never classified, which is what makes the rule independent of what CPython
decides to put in there next. In both walkers, in `walk_version_dir`:

```rust
        if entry.is_dir() {
            if IGNORED_DIRS.contains(&name.as_str()) {
                continue;                 // pruned, not recursed (D116 R7)
            }
            walk_version_dir(&entry, version, found);
            continue;
        }
```

and, in the file arm, immediately before the fatal `assert!`/`Err`:

```rust
        if IGNORED_NAMES.contains(&name.as_str())
            || IGNORED_SUFFIXES.iter().any(|s| name.ends_with(s))
        {
            continue;
        }
```

Note the ordering: **after** the `*.json` arm, so an ignorable rule can never
swallow a vector, and after `INDEX.json`.

`walk_root` is **not** changed. Its directory rule is `v<integer>` only, and a
`__pycache__` directly under `vectors/` should stay fatal: nothing imports a
module from there, and loosening the top level would let a whole stray tree in.

### R8 — What keeps the two rules from disagreeing again (Q140)

Two instruments, because the row's own diagnosis — *"two rules in the tree
disagree"* — is only closed by making one **derive** from the other.

**(a) The two copies must be byte-identical.** A new test in
`crates/wasm-bitmatch/tests/bitmatch.rs`, beside the existing
discovery-agreement test, reads both source files and asserts the three
constant blocks match. The existing agreement test
(`bitmatch.rs:60-70`) **cannot** catch this class: it compares the *result sets*
of two successful walks, and a `build.rs` panic happens strictly before any test
in that crate runs. Say so in the new test's doc comment.

**(b) `.gitignore` is the authority, and a test says so.** A test in
`antseal-core/tests/vector_runner.rs` reads `.gitignore`, takes every pattern
that could match a file or directory **name** under `testdata/vectors/`
(ignoring anchored, path-bearing and negated patterns), and requires each to be
covered by `IGNORED_DIRS`/`IGNORED_SUFFIXES`/`IGNORED_NAMES`. Failure text names
the pattern and the file it would brick:

```
.gitignore declares `{pattern}` expected anywhere in the tree, but the vector
discovery walk would classify a matching file under testdata/vectors/v<n>/ as
unclassifiable and FAIL THE BUILD. Two rules that disagree about whether a file
is expected is the Q140 defect; add it to IGNORED_* (D116 R7) or exclude the
pattern here with the reason.
```

Do **not** invert this into "derive the list from `.gitignore` at build time":
a build script must not depend on `.gitignore` being present (it is not in a
`cargo package` tarball), and glob semantics are more than this walk needs. The
assertion is the coupling; the list stays explicit.

**(c) Tests-of-the-test, each shown red before green**, in the scratch-tree
idiom `vector_runner.rs` already uses for
`vector_runner_fails_loudly_on_unclassifiable_file`: a `.pyc` inside
`__pycache__/` (green), a `.pyc` **not** inside `__pycache__/` (green — the
suffix rule), a `.swp` (green), a stray `.txt` (**still red** — the fatal arm
survives), a `.json` inside `__pycache__/` (green **and not embedded** — pruning
means a vector hidden in an ignored directory is invisible, which is the correct
and slightly surprising consequence, so it is pinned), and `__pycache__`
directly under `vectors/` (**still red** — `walk_root` unchanged).

---

## 5. The complete local-gate ↔ CI divergence table

Every check-bearing `run:` step in `.github/workflows/ci.yml` (rustup, checkout,
cache, `node --version`, `pip install` and `cargo install` steps excluded), and
every lane in `scripts/local-gate.sh`. **17 jobs → 19 required contexts; 25 CI
check-steps; 12 gate lanes plus 3 trigger-conditional ones.**

### 5.1 CI → gate

| # | CI job | step | gate lane | verdict |
| --- | --- | --- | --- | --- |
| 1 | `fmt` | `cargo fmt --check` | `fmt` (`--all -- --check`) | args differ, **measured identical** (101 files, `diff` clean) |
| 2 | `clippy` | `cargo clippy --all-targets --locked -- -D warnings` | `clippy` (`--workspace --features LIGHT`) | args differ, **measured equivalent** (§1.9) |
| 3 | `test` | `cargo test --workspace --locked`, `PROPTEST_CASES=1024` | `test` (`--features LIGHT`, **no env**) | **DIVERGENT — 256 vs 1024 cases. Undeclared** |
| 4 | `wasm32-core` | `cargo build -p antseal-core --target wasm32…` | `wasm32-build` | same |
| 5 | `wasm32-core-tests` | `wasm-tests.sh --self-test` | `wasm32-selftest`, unconditional | same |
| 6 | `wasm32-core-tests` | `wasm-tests.sh --check` | `wasm32-tests`, **diff-triggered** | conditional (Q125, declared) |
| 7 | `core-dep-graph` | `ci-lanes.sh dep-graph` | — | **absent** (declared) |
| 8 | `cross-os` ×3 | `bash ci-lanes.sh cross-os` | — | **absent** (declared; the Linux leg genuinely is covered in substance by `test` — its empty-selection case is a `::notice`, not an error) |
| 9 | `golden-vectors` | `ci-lanes.sh golden-vectors` | — | **absent** (declared) |
| 10 | `cross-check` | `cross-check.sh --self-test --require` | — | **absent — Q141** (declared, cost misstated) |
| 11 | `cross-check` | `cross-check.sh --check --require` | `cross-check` (**no `--require`**) | args differ, deliberate (exit 2 = SKIP); in code, not the header |
| 12 | `cross-check` | `ci-lanes.sh cbor-drift-guard` | — | **absent** (declared) — but its target is run by the gate's `test` lane at the same feature set (§1.9) |
| 13 | `vector-freeze` | `vector-freeze.sh --self-test` | — | **absent** (declared) |
| 14 | `vector-freeze` | `vector-freeze.sh` | — | **absent** (declared) |
| 15 | `format-freeze` | `format-freeze.sh --self-test` | `format-freeze` | same |
| 16 | `format-freeze` | `format-freeze.sh` | `format-freeze` | same |
| 17 | `wasm-bitmatch` | `wasm-bitmatch.sh --self-test` | `bitmatch-inject`, trigger-conditional | conditional (Q128, declared) |
| 18 | `wasm-bitmatch` | `wasm-bitmatch.sh` (bare) | `wasm-bitmatch` (`--check`), trigger-conditional | args differ, **measured identical** (one branch); conditional (declared) |
| 19 | `tamper-matrix` | `ci-lanes.sh --self-test` | `ci-lanes` | same |
| 20 | `tamper-matrix` | `ci-lanes.sh tamper-matrix` | — | **absent** (declared) |
| 21 | `fuzz-smoke` | `fuzz.sh lint` | — | **absent** (declared as one line for four steps) |
| 22 | `fuzz-smoke` | `fuzz.sh build` | — | **absent** |
| 23 | `fuzz-smoke` | `fuzz.sh selftest` | — | **absent** |
| 24 | `fuzz-smoke` | `fuzz.sh smoke 90` | — | **absent** |
| 25 | `audit-deny` | `ci-lanes.sh audit-deny` | — | **absent** (declared) |
| 26 | `secret-guard` | `ci-lanes.sh secret-guard` | — | **absent** (declared) |
| 27 | `traceability` | `ci-lanes.sh traceability` | `traceability` | same |
| 28 | `traceability` | `ci-lanes.sh ci-shell` | `ci-shell` | same |
| 29 | `traceability` | `ci-lanes.sh fuzz-budget` | `fuzz-budget` | same |
| 30 | `traceability` | `ci-lanes.sh anchor-net-policy` | `anchor-net` | same |

### 5.2 gate → CI (the direction nothing records)

| # | gate lane | CI counterpart | verdict |
| --- | --- | --- | --- |
| 31 | `bitmatch-trigger` — `wasm-bitmatch.sh --trigger-self-test` | **none** | **gate-only. Undeclared** |
| 32 | `features` — `gate-features.sh --self-test` | **none** | **gate-only. Undeclared** |
| 33 | `features` — `gate-features.sh --check-partition` | **none** | **gate-only. Undeclared** |
| 34 | `heavy-features` — `gate-features.sh --heavy` | **none**; the HEAVY features are compiled by zero CI lanes | **gate-only. Undeclared** |
| 35 | `e2e-selftest` — `e2e-devnet.sh --self-test` | **none**; `devnet-e2e-cron.yml:119` runs the lane **bare** | **gate-only, and Q141 inverted. Undeclared** |
| — | `e2e-devnet` (opt-in) | `devnet-e2e-cron.yml` (scheduled, not a PR context) | declared |
| — | `wasm-tests.sh --needs-run` / `wasm-bitmatch.sh --needs-run` | n/a — triggers | n/a |
| — | `export ANTSEAL_NO_REAL_ANCHOR_NETWORK=1` | `ci.yml:109`, workflow-level | present both sides ✓ |

### 5.3 Summary

**35 comparison points. 30 CI check-steps, of which 15 have no gate counterpart
(14 declared in the header) and 5 differ in arguments (1 substantively). 5 gate
lanes have no CI counterpart, none of them declared anywhere.** The gate
header's list has **ten** entries and is correct item-for-item; the divergence
classes it does not carry are **three**: `PROPTEST_CASES` (§1.9), the five
gate-only lanes (§1.8), and `--require` (in code, not the header).

---

## 6. Ordering, lane boundaries, and the commands that prove each fix

### 6.1 File contention

| file | Q133 | Q141 | Q140 | other open rows |
| --- | --- | --- | --- | --- |
| `scripts/check-traceability.py` | **yes** | — | — | **Q145** (the resolved-decision-with-a-ticked-owner join) lives in this file |
| `scripts/local-gate.sh` | — | **yes** | — | — |
| `crates/wasm-bitmatch/build.rs` | — | — | **yes** | — |
| `crates/antseal-core/tests/vector_runner.rs` | — | — | **yes** | — |
| `crates/wasm-bitmatch/tests/bitmatch.rs` | — | — | **yes** (R8a) | — |

**The three rows touch five files and share none.** They may run as three
parallel lanes, in any order, in the same wave.

### 6.2 The one real ordering constraint

**Q133 before Q145.** Both edit `scripts/check-traceability.py`; Q133 deletes
five module-level constants and rewrites `check_decisions()`'s loop body, and
Q145 adds a sixth check that reads the register `check_decisions()` already
parses. Running Q145 first means rebasing it onto R1's constant rename. If they
must be concurrent, Q145 takes `check_decisions()`'s *helpers*
(`allocated_decision_ids`, `open_decision_ids`) and must not touch the sweep
loop or the constants.

**Q140 before any lane that runs the full gate.** Its bug is a *build* failure
in a workspace member, so while it is open, any lane that imports the CBOR
checker or leaves an editor open on a file under `testdata/vectors/v1/` cannot
run `cargo` at all. It is XS and unblocks everyone; run it first in the wave.

**No constraint between Q141 and the other two.** Q141's own verification runs
the gate, so it is more pleasant after Q140, not dependent on it.

### 6.3 Proof commands, per row

**Q133 — the fix works:**
```
python3 scripts/check-traceability.py --decisions
python3 scripts/check-traceability.py --self-test
python3 scripts/check-traceability.py
```
Green, and the `[decisions] ok` line must now report a **file count** (R3) that
is larger than the task half's 352 minus the self-exclusion is not the test —
the test is that the number is printed at all and that R4's case is red.

**Q133 — would have caught the original:** R4's case, run in isolation, plus
the real-tree probe re-executed:
```
printf '#!/usr/bin/env bash\n# key layout: docs/format/registry-v1.md:1097\nexit 0\n' > scripts/zzz-probe.sh
python3 scripts/check-traceability.py --decisions      # MUST be rc 1, naming scripts/zzz-probe.sh
rm scripts/zzz-probe.sh
python3 scripts/check-traceability.py --decisions      # MUST be rc 0
```
Measured at planning time: rc 0 / rc 1 / rc 0 across today's and the proposed
constants (§1.3, §7 cmd 9). The `A71` shape itself — a `D<n>` with no record
cited only from a `.sh` — is proven on the staged tree (§1.3), because the real
tree has no unresolvable `D<n>` to plant.

**Q141 — the fix works:**
```
scripts/local-gate.sh
```
Two lines where there was one: `cross-check-st PASS` then `cross-check PASS`,
and the block's wall time roughly triples.

**Q141 — would have caught the original:** weaken the checker so that
`--check` cannot notice and `--self-test` must, then run the gate:
```
# in a staged copy of the tree, make check_case() accept a length it should reject
scripts/cross-check.sh --check      # rc 0 — the committed vectors are still correct
scripts/cross-check.sh --self-test  # rc 1 — a planted fault now survives
scripts/local-gate.sh               # cross-check-st FAIL
```
This is the incident's *class* — a checker that has stopped checking — and it is
guaranteed red by construction, where reconstructing the 2026-08-09 selector bug
is not: Q130's `the_cbor_scope_predicate_is_written_exactly_once` now makes the
two-copy state unwritable, which is the point. Record the reconstruction as the
second, historical instance and the weakening as the standing proof.

**Q140 — the fix works:**
```
python3 -c "import py_compile; py_compile.compile('testdata/vectors/v1/crosscheck_cbor.py')"
touch testdata/vectors/v1/.crosscheck_cbor.py.swp
cargo check --workspace --locked                                   # MUST be rc 0
cargo test -p antseal-core --test vector_runner --locked            # MUST be rc 0
rm -rf testdata/vectors/v1/__pycache__ testdata/vectors/v1/.crosscheck_cbor.py.swp
```

**Q140 — would have caught the original:** the same two commands at the parent
commit, which are the ones executed here (§7 cmds 11–13) and returned **rc 101**
and **1 failed** with the verbatim text in §1.5. Plus R8's tests-of-the-test,
each shown red before green — in particular the stray-`.txt` case, which is what
proves the fatal arm survived the change.

---

## 7. Commands run for this decision, with verdicts

| # | command | verdict |
| --- | --- | --- |
| 1 | `python3 scripts/check-traceability.py` | **rc 0** — all five checks green; decisions: 100 cited, 94 records, 5 homed, 13 open |
| 2 | `grep -rn 'registry-v1\.\(md\|json\):[0-9]' scripts/ .github/` | exactly **one** hit: `scripts/check-traceability.py:1245` |
| 3 | real `check_decisions()` re-executed over 5 constant arms | §1.1's table — A1/A2 **red**, A3/A4 **green** |
| 4 | allocation census over `TODO.md` + `docs/decisions/` | max **112**, **112** allocated, **0** holes, **0** ids that would fail |
| 5–8 | staged-tree counterfactual: record deleted + `.sh` citation planted | today's constants **GREEN** (the hole); proposed **RED** naming the file; probe deleted **green**; record restored **green** |
| 9 | real-tree probe `scripts/zzz-d116-probe.sh`, planted then deleted | today's **rc 0**; proposed **rc 1** naming it; after deletion **rc 0**. `git status --short` = 21 entries, unchanged |
| 10 | `cargo check -p wasm-bitmatch --locked` (control) | **rc 0**, `Finished dev profile in 34.68s` |
| 11 | same, with `testdata/vectors/v1/__pycache__/*.pyc` present | **rc 101**, `build.rs:175` panic (verbatim, §1.5); `cargo check --workspace --locked` **rc 101** identically |
| 12 | `cargo test -p antseal-core --test vector_runner --locked`, same state | **1 failed**, `vector_runner.rs:142:73` panic (verbatim, §1.5a) |
| 13 | `.crosscheck_cbor.py.swp` planted; `cargo check -p wasm-bitmatch` | **rc 101** naming the swap file |
| 14 | `vector_freeze` + `vector_index` tests and `./scripts/vector-freeze.sh`, same state | **19 passed / 3 passed**, `vector-freeze: GREEN` — immune |
| 15 | direct run vs import of `crosscheck_cbor.py`, in a staged copy | run → **no** `__pycache__`; import → `__pycache__/crosscheck_cbor.cpython-311.pyc` |
| 16 | cleanup, then `cargo check -p wasm-bitmatch --locked` | **rc 0**; `find testdata/vectors -name '__pycache__' -o -name '*.swp'` → empty |
| 17 | `cross-check.sh --self-test` ×2 / `--check` ×2 / `crosscheck_cbor.py --self-test` | **55.66 s, 46.41 s** / 24.63 s, 22.48 s / **0.10 s**; all green |
| 18 | `cargo test --workspace --locked -- --list` vs the same with LIGHT features | **2440** and **2440** |
| 19 | `cargo fmt --check -v` vs `cargo fmt --all --check -v` | **101** files each, `diff` clean |
| 20 | `cargo metadata --no-deps` | `workspace_members` **6** = `workspace_default_members` **6**; `antseal-core` declares only `test-util`, `test-vectors` |
| 21 | `grep -rc 'gate-features' .github/` | **0 hits** |
| 22 | every `run:` line across all four workflows, enumerated | §5's table; `e2e-devnet.sh` appears once, **bare**, at `devnet-e2e-cron.yml:119` |
| 23 | `grep -c 'PROPTEST' scripts/local-gate.sh` | **0** |
| 24 | cmds 9–11 **re-executed at `d23dccc`** | identical: probe green/red/green; `cargo check -p wasm-bitmatch` **rc 0 → rc 101 → rc 0**, same `build.rs:175:13` text |

`git status --short` was 21 entries before this lane began and 21 after the
first round. After wave 12 was committed as `d23dccc` and the plants re-run, it
shows seven files modified by three concurrent implementation lanes (untouched
here) and four untracked decision documents, of which this is one. No throwaway
file survived either round: `find testdata/vectors -name '__pycache__' -o -name
'*.swp' -o -name '*.pyc'` is empty and `scripts/zzz*` does not exist.

---

## 8. What this does not do

- **It does not add `.github/` or `.yml` to the citation sweep.** Measured
  green (§1.1 A4, +1 resolvable citation); refused for now on §2 (c) and named
  in §9 with the measurement already banked.
- **It does not move any gate-only lane into CI.** Five lanes have never run on
  the remote (§1.8); each would be a **new required status context**, which is
  a branch-protection change and therefore an external act. R6 records the gap
  where the reader is; §9 names the question.
- **It does not set `PROPTEST_CASES` in the local gate.** Raising it to 1024
  would quadruple the longest lane in the gate for a property the CI run will
  check anyway. R6 makes the shortfall visible; whether to add a
  `ANTSEAL_GATE_PROPTEST` escape hatch is §9's.
- **It does not correct `crypto/manifest-aead.json`, touch any vector, or move
  any frozen byte.** Q140 changes classification only; the embedded set,
  `EMBEDDED_BYTES_BY_VERSION` and the D87 ceiling are unaffected because
  `__pycache__` never contributed a `.json`.
- **It does not make the Q4/Q5 rule laxer for anything that could be a
  vector.** The ignorable list is checked *after* the `*.json` arm, and R8(c)
  keeps a stray `.txt` fatal.
- **It does not rule on Q145's design**, only on its ordering against Q133
  (§6.2).

---

## 9. Discovered work — described, not numbered

*(The wave owner allocates and registers. No id is minted here.)*

1. **Five local-gate lanes have never run on the remote, and the project has a
   written rule against exactly that.** — M2 · S · deps: Q125, Q128, Q43.
   `gate-features.sh --self-test`, `--check-partition`, `--heavy`,
   `wasm-bitmatch.sh --trigger-self-test`, `e2e-devnet.sh --self-test`.
   `docs/ci-verification.md` says *"a lane that has never run on the remote is
   not evidence"* and `local-gate.sh:259-261` quotes its local dual; nothing
   states the dual of the dual. The cheap three (`--check-partition`,
   `--trigger-self-test`, `e2e-devnet.sh --self-test`) are seconds and need no
   cargo, so they could ride as **steps of the existing `traceability` job** —
   the precedent `ci-shell`, `fuzz-budget` and `anchor-net-policy` already set,
   costing **zero** new required contexts. `--heavy` cannot ride anywhere and is
   a separate question.
2. **`devnet-e2e-cron.yml:119` runs `./scripts/e2e-devnet.sh` without its
   `--self-test`** — the only venue that runs the devnet lane at all runs it
   with its test-of-the-test disabled, while the local gate runs the
   test-of-the-test and (by default) not the lane. Neither venue runs both.
   Q141's shape exactly, inverted, in a scheduled workflow.
3. **The local gate runs proptest at 256 cases where CI runs 1024**, undeclared
   in the gate header (§1.9). Beyond R6's disclosure, decide whether an
   `ANTSEAL_GATE_PROPTEST=1024` opt-in belongs beside `ANTSEAL_GATE_WASM`,
   `_BITMATCH`, `_HEAVY` and `_E2E`, which are the same shape.
4. **Adding `.github/` + `.yml` to the citation sweep is measured green (+1
   resolvable citation) and was deliberately not taken** (§2 (c)). The
   counter-argument is `check-ci-shell.py`'s existing coverage and `TASK_SCAN`'s
   matching omission. Whoever takes it must move **both** halves, or R1's single
   constant re-splits.
5. **`vector_index.rs`'s `read_frozen` and `vector_freeze.rs`'s `collect_json`
   are a second and third walk of the same tree with a third and fourth
   classification rule.** D112 §8 item 2 already named `read_frozen` as an
   undeclared second parser of `FROZEN.sha256`; this decision adds that
   `collect_json` is a *positive-filter* walker and is therefore immune to Q140
   by accident rather than by decision. Worth one comment each recording which
   shape they are and why, so the next person who adds a walker picks the
   tolerant one deliberately.
6. **`crates/wasm-bitmatch/tests/bitmatch.rs`'s discovery-agreement test cannot
   see a classification-rule divergence**, because a `build.rs` panic precedes
   every test in that crate (§R8a). It compares result sets, not rules. The
   general shape — *a cross-check that can only run when the thing it checks
   already succeeded* — is worth a sweep of the other agreement tests in the
   tree.
7. **`#! kind`'s `since` token and `INDEX.json`'s per-vector `task` are two
   registers of task ids that no sweep reads.** D112 §8 item 4 measured the
   first. Now that `TASK_SCAN` is becoming `CITATION_SCAN` (R1), note that
   `testdata/` is in **neither** — which is also what kills D109 R7 bullet 3's
   `S310` — so thirteen directive task ids plus one per vector are parsed,
   stored, and checked against nothing.
8. **The `--self-test` cost figures in `TODO.md` and D112 §8.5 came from a
   different subject than the flag they describe** (§1.7: 4 s claimed, 0.10 s
   for the checker, 46 s for the lane). Both documents state the figure without
   naming what was timed. The generalisation — a measurement recorded without
   its subject is a measurement that will be applied to the wrong thing — is
   worth a line in the provenance convention `local-gate.sh:179-195` already
   established for exactly this reason.

---

## Outcome

**RESOLVED, 2026-08-10.** All three rows execute and all three headline numbers
are wrong. **Q133**: D109 §6.4 cmd 8 measured the decision-*resolution* half of
`check_decisions()` and never measured the **Q58 line-citation half**, which has
no ceiling and no suppression register — the widening turns the lane **red on
its first run**, and the literal responsible is not the `D77000` the row names
(that one is correctly silent, as claimed) but `registry-v1.md:1097` sixteen
lines away, so the self-exclusion is load-bearing and its comment must name the
right literal. One constant, not two, because a rule written twice and held in
step by a comment is the defect the previous wave spent itself on. The `.sh`
surface is proven by planting, in both directions, on a staged tree and on the
real one; the new self-test case must be a **class-2** case because D1–D112 is
**100 % dense and 100 % resolvable**, so no single-file mutation can make a
`D<n>` fail and the harness applies exactly one. **Q141**: the fix stands, the
cost does not — `cross-check.sh --self-test` is **46.4 / 55.7 s**, not ~4 s;
the 4 s belongs to the CBOR checker alone, which is **0.10 s**. It lands on a
better argument than the row's: it fires planted faults on **six** surfaces,
five of which no local lane has ever exercised. **Q140** reproduces verbatim
and is larger than its row twice over: **two** walkers carry the fatal rule, not
one — `vector_runner.rs` is CI's `golden-vectors`, `cross-os` and `test`
contexts — and the trigger is **import, never run**, which kills the
producer-side fix outright because the repository contains no import to flag.
The class is wider than Python too: a vim swap file bricks the workspace build
for as long as the editor is open. The tree already holds the tolerant shape in
`collect_json`, which filters positively for `.json` and is green through all of
it. **And the general measurement found the shape twice more, pointing the other
way**: five gate lanes — the entire S22 partition mechanism, Q128's trigger
self-test, and `e2e-devnet.sh --self-test`, whose cron sibling runs the lane
bare — have **no CI counterpart at all**, which is `docs/ci-verification.md`'s
own *"a lane that has never run on the remote is not evidence"* violated five
times with nothing recording it, while the gate header enumerates only the
opposite direction. Plus one substantive undeclared argument gap: **256 proptest
cases locally against CI's 1024**. Four other argument divergences were measured
and are **not** substantive — `fmt` (101 files each, `diff` clean), `clippy`
(the root manifest is virtual, so `--workspace` is a no-op), `test` (**2440 =
2440** with and without the LIGHT features, which are already unified through
dev-dependency self-edges), and `wasm-bitmatch` (bare and `--check` are one
branch) — and are recorded so nobody re-opens them.

---
## Amendment — there is a second landmine, 2026-08-10

**Recorded, not applied. The body above is byte-unchanged**, per D115 §3.7 and
`Q122`; this is D84's appended-correction mechanism.

**§1.2's closing sentence — *"There is no second landmine"* — was true when
measured and false by the time this decision's own riders landed.** It rested on
`grep -rn 'registry-v1\.\(md\|json\):[0-9]' scripts/ .github/` returning
exactly one hit, the `registry-v1.md:1097` literal carried by the Q58 RED case.
R4 added a new self-test case carrying a second such literal, so the
self-exclusion at `CITATION_SCAN_SELF` now covers **strictly more** than the
record that mandated it. The implementing lane recorded this in the code where
the next reader will meet it, which is the right home: the comment above
`CITATION_SCAN_SELF` now reads *"D116 §1.2 found one such literal; R4's new case
adds a second, so the exclusion covers strictly more than the record that
mandated it."*

**This does not weaken §1.2 — it strengthens it.** The section's operative
finding is that the self-exclusion is *mandatory* and that the comment must name
the literal that actually fires, *"or the next lane will delete the exclusion
after checking the wrong literal"*. A second literal makes that instruction more
necessary, not less, and the landed comment names the class rather than a count.

**RULINGS on Q133, Q141 and Q140 all stand**, and all three rows closed
2026-08-10 on this record's reasoning. The five never-remote gate lanes (§1.4),
the bare cron invocation (§1.4) and the undeclared proptest divergence (§1.5)
are registered as `Q153`, `Q154` and `Q155`; §1.7's extra directory walks as
`Q157` — **narrowed**, because `vector_index.rs`'s `read_frozen` is not a walk
but a second parser of `FROZEN.sha256`, which is `Q142`'s subject — and its
build-gated cross-check as `Q158`. §2's cost-figure lesson is `Q160`.

---

## Correction — the section numbers in the Amendment above, and what §1.5(a)'s "two walkers" counts, 2026-08-11

**Authority** (D117 §2.2.3): `Q196`, *"Blast radius measured under fail-fast is
a lower bound reported as a radius"*, wave-15 implementing lane. **This
correction lands in a commit separate from its subject.** D116 landed as
`1c702d4` in wave 13 and its Amendment on 2026-08-10; this section is written
in wave 15, so it is a diff against a published record and not a same-commit
amendment (D117 §2.1(c)).

**Epoch** (D117 §2.5): every figure below was measured on 2026-08-11 against
the working tree at `1f82da1` plus ten concurrent wave-15 lanes. No concurrent
lane owns this document. `tasks/Q.md` **is** concurrently owned, and its `Q196`
row is quoted below as it stood when this lane read it.

**What moved in the body**: two **additive dated notes**, one at the end of
§1.5(a) and one at the head of §1.7. Nothing is struck, nothing is replaced,
nothing is deleted, and no section, rule, ruling or rider identifier moves
(D117 §2.4.1). No new ruling is introduced (D117 §2.7).

### (1) What is wrong: five section citations in the Amendment above

Quoted verbatim, from *"Amendment — there is a second landmine, 2026-08-10"*:

> The five never-remote gate lanes (§1.4), the bare cron invocation (§1.4) and
> the undeclared proptest divergence (§1.5) are registered as `Q153`, `Q154`
> and `Q155`; §1.7's extra directory walks as `Q157` … §2's cost-figure lesson
> is `Q160`.

Measured by reading every cited heading in this document's body against the
subject the Amendment attaches to it:

| the Amendment cites | for | where the subject actually is | what the cited section actually holds |
| --- | --- | --- | --- |
| §1.4 | the five never-remote gate lanes | **§1.8** | the D-namespace density census |
| §1.4 | the bare cron invocation | **§1.8** | *(same)* |
| §1.5 | the undeclared proptest divergence | **§1.9** | Q140 reproduced, with the real error text |
| §1.7 | the extra directory walks | **§1.5(b)**, registered from **§9 item 5** | Q141's cost figure |
| §2 | the cost-figure lesson | **§1.7** | the options, and what kills each |

**None of the five resolves.** The body's numbering is the stable one, and it
is corroborated twice inside this same document: **§9 item 3 cites `(§1.9)` for
the proptest divergence and §9 item 8 cites `(§1.7)` for the cost figures**,
both correct. The Amendment is the outlier.

**Which defect this is** (D117 §2.5.4): **wrong when written**, not *went
stale*. The body was never renumbered — §2.4.1 forbids it, this file has one
commit in `git log`, and the subjects themselves have not moved — so these
citations never resolved against any published state of the document.

**Routing, and why the correction is applied at the destination rather than at
the source.** A cross-reference is a D117 §2.3(a) **REPLACE** case by name.
It is recorded here and deliberately **not** applied to the Amendment's text:

- The same mis-citation is live in `tasks/Q.md` and in `TODO.md`, neither of
  which this lane owns. Repairing only the Amendment would still leave a reader
  arriving from the `Q196` row at §1.7 with nothing to tell them they are in
  the wrong section. **The dated signpost at the head of §1.7 catches every
  arrival, from all three sources**, which a source-side replacement does not.
- Replacing text *inside an appended amendment*, rather than inside the argued
  body, is not a case D117 §2.2 contemplates — its placement rule governs
  where correction sections go, not how one amendment corrects another. This
  lane declines to improvise a form for it.

**Registered for the owning wave as discovered work**, described and not
numbered, rather than left silent.

### (2) §1.5(a)'s "two walkers": routed under D117 §2.3, and NOT struck

`Q196`'s `Accept` asks for this figure to be annotated as superseded. Applying
D117 §2.3 here, and recording the reasoning as the row requires:

§2.3's test — *"would a lane act on this sentence?"* — forks between **(a)
REPLACE** and **(b) STRIKE**. Both arms assert that the sentence is **wrong**;
§2.2's limit on a correction is explicit: *"A correction states what is
false."* So the prior question is whether anything in §1.5(a) is false.
**Measured, nothing is.**

- §1.5(a) claims that **two** walks carry the *identical fatal closed
  classification rule*. Read against `crates/antseal-core/tests/vector_walk/mod.rs`,
  the Q157 census: of its twelve registered sites, exactly two carry class
  `closed` — `wasm-bitmatch/build.rs`'s `walk_version_dir` and
  `antseal-core/tests/vector_runner.rs`'s `walk_version_dir`. **The same two.**
- §1.5(b) already found two further walks over the same tree and called them
  immune, and §1.5's closing sentence already says *"the two fatal walkers are
  the outliers"*. §1.5 therefore never claimed that only two walks exist; it
  counted the ones carrying the rule under repair.
- The census's own text confirms rather than corrects it: *"Q140 found two
  walks over the committed vector tree carrying the same closed classification
  rule"*, and its class column keeps `closed` at exactly two.

**Therefore neither arm of §2.3 applies.** REPLACE would substitute a correct
sentence for a correct sentence; STRIKE would assert that a true measurement
was mistaken and would falsify the record that §2.1(a)'s non-erasure principle
exists to protect. What the sentence lacks is its **predicate** — an
under-specification, not an error — and the instrument for that is an
**additive dated note that leaves the text standing**, which is what §1.5(a)
now carries. That note is not a §2.3(d) marker and does not use its `~~`
form, because nothing is struck; this paragraph is the record of why a new
shape was used rather than one of the two sanctioned ones.

### (3) The `Q196` premises that sent a reader here, refuted in three parts

`tasks/Q.md`'s `Q196` states, and `TODO.md`'s row repeats: *"a plausible
mechanism for **D116 §1.7** concluding Q140's radius was 'two walkers' when
Q157's later census found twelve walk sites"*. The row flags its own causal
claim as a hypothesis. It does not hold, in three separable ways:

1. **Wrong section.** The finding is §1.5(a). §1.7 is Q141's cost figure. The
   likeliest provenance is the Amendment's own *"§1.7's extra directory
   walks"*, corrected in (1) above — stated as the most probable route, not as
   proven.
2. **Not measured under fail-fast.** §7's own log is decisive: the finding came
   from **reading** `vector_runner.rs`'s classification, and was confirmed by
   **cmd 11** (`cargo check -p wasm-bitmatch --locked`, which runs no test at
   all and which `--no-fail-fast` cannot reach — `cargo test` has no
   `--keep-going`) and **cmd 12** (`cargo test -p antseal-core --test
   vector_runner --locked`, a single named target). §1.5(a)'s own transcript
   reports `7 passed; 1 failed`, which is the whole target counted to
   completion — libtest never stops at the first failure, and cargo's
   `--no-fail-fast` governs *executables*, not tests within one. The flag would
   have changed nothing about this figure.
3. **Not superseded.** Per (2): twelve and two count different predicates and
   are both true at this epoch.

**What the row is right about, and it is the part worth keeping**: a recorded
figure that does not name what produced it attaches itself to whatever the
reader is thinking about. `Q196` is itself the measured instance — the missing
detail here was **what was counted**, not *what was allowed to stop*, which is
`Q160`'s generalisation arriving one measurement earlier than the row placed
it. The convention the row asks for is written at
`docs/ci-verification.md`, *"A blast radius measured under fail-fast is a lower
bound, not a radius"*, and it requires **both** the command and the predicate
for exactly this reason.

### (4) The count, stated per D117 §2.5

1. **The original figure, with its section**: §1.5(a), *"There are two walkers
   with the identical fatal rule, not one."*
2. **The new figure**: unchanged — **two**.
3. **The predicate, in words, and how it was measured**: *walks over
   `testdata/vectors/` whose classification is closed, i.e. that fail on any
   file they cannot classify.* Measured by reading the class column of
   `VECTOR_TREE_WALKS`' census in
   `crates/antseal-core/tests/vector_walk/mod.rs`, which registers twelve sites
   and marks exactly two `closed`; `tests/vector_walk_census.rs` holds that
   table to the tree.
4. **Which defect this is**: **neither**. The figure was correct when written
   and is correct now. What is added is the predicate it always counted.
5. **Whether the conclusion resting on the count survives**: **yes, and it
   widens.** R7 and R8 put one shared list behind both closed walkers; Q157
   then found that the *prune* half of that list is needed by every recursive
   walk, closed or positive, and extended it to seven. That is R8's own
   derive-one-rule-from-the-other principle applied further out, not a
   correction of it.

**No tie-break is needed** (D117 §2.5): the two figures do not conflict, and
both have a reproducible source.

### (5) What stands

**RULINGS on Q133, Q141 and Q140 all stand, and every rider R1–R8 stands
unchanged.** Every error corrected here is a **pointer**, not a finding: the
Amendment's five section numbers misdirect a reader and change nothing about
what this document measured or ruled. §1.5(a)'s figure is confirmed by the
later census rather than superseded by it, so the argument for R7 and R8 is
strengthened, not weakened. Nothing in §1.7's cost measurement is touched.
