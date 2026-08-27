# D163 — neither term is clerical: `after Q34` on `Q35` is a **missing split**, not a mis-typed word, and `after Q1` on `Q30`/`Q31` is **discharged clause-wise and NOT struck**, because Q1's branch-protection clause is live, sequenced behind the flip, and owned by nobody

- **Status: RESOLVED. The lean is OVERTURNED on both halves, and they fall differently.**
  - **(A) falls ON ITS PREMISE.** `after Q34` is not a typo. It was written into
    `TODO.md`'s ordering run **and** `tasks/Q.md`'s `Deps` line in the **same
    founding commit `0efdeee`**, beside an `Accept` conjunct — *"progress
    reviewed weekly **post-release**"* — that genuinely runs `Q34 → Q35`.
    `before Q34` is therefore not a repair but a **false claim in the opposite
    direction**. The row has carried two opposite timings for 219 rows'
    worth of history; the defect is a **missing split**. The lean's
    *direction* (make `Q35` available) survives; its *instrument* does not. §1.1–§1.3.
  - **(B) falls ON ITS PREMISE, and its remedy is under-scoped by five rows.**
    The lean invokes D156 §2 R6 as authority to *strike* — and D156 §2 R6's own
    words are *"the `Q30` term is **DISCHARGED** under D156 §2 R1, and
    **deliberately NOT struck**"*. Rule 7 as amended by that record says repair
    *"never by deletion"*. Measured, the term is not on two rows: **15 rows
    carry `Q1` as an `after` term — 8 ticked, 7 open** (`Q56`, `A30`, `Q16`,
    `Q19`, `Q30`, `Q31`, `Q238`). §1.4.
  - **The branch-protection clause is NOT vestigial, and that is the finding
    under (B).** `docs/ci-verification.md` forbids arming it *in this sitting*
    in its own words — *"Do not add a required status context in this
    sitting"* — and names the precondition: **one green run on `main`**, which
    the exhausted Actions allowance blocks and which only the flip restores.
    The clause is **live, sequenced behind `Q65`, and about to become
    executable for the first time**. §1.6.
  - **Exactly one open row's `Accept` consumes it, and it is not `Q30` or
    `Q31`.** `Q238` `Accept` row 3: *"The promoted job is a **required status
    context** on `main`"*. Walked clause by clause, **none of `Q30`'s three or
    `Q31`'s six `Accept` rows names a required status or branch protection** —
    `Q31` row 5's read-back is `actions/permissions`, a different endpoint. §1.5.
  - **One correction to the brief that sent this record.** It frames both terms
    as *"on the M4 ship path"*. Measured: **zero rows carry `Q35` as an `after`
    term.** `Q35` blocks nothing. `Q31` blocks `Q32`, `Q34` and `Q241`; `Q30`
    blocks `Q31` and `Q32`. (B) is the ship path; (A) is a permanently
    untickable row. §1.3.
- **Date: 2026-08-22**
- Owner rows: **`Q35`** (split), **`Q30`**/**`Q31`** (terms annotated), **`Q1`**
  (residue routed). This record ticks nothing.
- Related: **D156 §2 R1** (what `after X` requires — amended here by §2 R1),
  **§2 R2** (a residue needs a named owner), **§2 R6** (the `Q30`-on-`Q31`
  precedent the lean misquotes), **§2 R7** (`P17`'s residue routed to `Q258` —
  the template §2 R4 reuses), **§2 R11** (ordering runs carry `before` and
  `with`; exemplars by row id, not line number); **D141 §2 R8** (the 403s are
  gone; `main` is unprotected, `rulesets` `200 []`); **D154 §2 R5** (narrowed
  `U76` against `Q35` — read here for what it does *not* say); **D161 §2 R7**
  (the budget half: free runners only after the flip, and *"no required status
  context may be added on the strength of that expectation"*); **D73 §7 items
  1, 6, 7** (`Q35`'s amendments and its instrument); **D125 / rule 8** (why §2 R9
  mints no row).

---

## 0. What was measured against

Read in full: `TODO.md` rule 7 (including its D141 §2 R7, D154 §2 R10 and
D156 §2 R1/R2/R11 annotations) and rule 8; `TODO.md`'s rows `Q1`, `Q30`, `Q31`,
`Q32`, `Q34`, `Q35`, `Q56`, `Q71`, `Q238`, `Q244`, `U32`, `U76`, `A30`;
`tasks/Q.md`'s `### Q1`, `### Q22`, `### Q30`, `### Q31`, `### Q35`, `### Q238`
entries (`Do`, every `Accept` row, every `Notes` block); `D156` §2 R1, R2, R6,
R7; `D161` §2 R7; `D73` §7 items 1, 6, 7; `docs/ci-verification.md`'s C2 block;
`MVP-SPEC.md`'s M4 bullet.

Measured at source on **2026-08-22** by script or by `git`, not quoted from a
record. **No network command was run, no GitHub API write was attempted, no
build was started, and neither `local-gate.sh` nor any `--self-test` was
invoked.** Every exit status below was read back out of a file.

---

## 1. What was measured

### 1.1 `after Q34` and `Deps: Q22, Q34` were written in the same founding commit

```
$ git log -S 'after Q22,Q34' --oneline -- TODO.md
0efdeee P4: task tracker (219 tasks, 9-domain decomposition) + project agent
$ git log -S 'Deps: Q22, Q34' --oneline -- tasks/Q.md
0efdeee P4: task tracker (219 tasks, 9-domain decomposition) + project agent
REAL_EXIT=0
```

The term is **original** and has never been edited. It appears in two files, in
one authoring act, in the commit rule 7 itself names as the origin of the list.
A word mis-typed once is a typo; the same word written into the authoritative
ordering run *and* the detail `Deps` line, in the same commit, beside an
`Accept` clause that agrees with it, is **intent**.

### 1.2 The row carries both timings in its own text, and neither is wrong

`tasks/Q.md`'s `### Q35`:

| surface | timing it states | direction |
| --- | --- | --- |
| `Do` | *"Write the plan **before release**"* | `Q35 → Q34` |
| `Accept` row 1 | *"Plan + tracking artifact committed **pre-release**"* | `Q35 → Q34` |
| `Accept` row 2, conjunct 1 | *"First outreach batch **scheduled**"* | pre-release |
| `Accept` row 2, conjunct 2 | *"progress reviewed weekly **post-release**"* | **`Q34 → Q35`** |
| `Notes` | *"Execution is **post-release**/continuous; the plan is the M4 deliverable"* | **both, named as both** |
| ordering run / `Deps` | `after Q22,Q34` | `Q34 → Q35` |

Apply rule 7's edge test — *name the clause of X's `Accept` that cannot be
written until Y's `Do` has landed*. For `Q35` against `Q34` the answer is
**`Accept` row 2's second conjunct**, and it is a real answer. So `after Q34` is
a **well-formed edge for part of this row and a false edge for the rest of it**.
No single ordering word can express that; rewording it in either direction
publishes a falsehood.

**D154 §2 R5 does not say otherwise, and this is the field-that-carries-the-claim
trap.** Its sentence is *"Both `Accept` rows … are satisfiable **with X2 never
yet run**"* — a ruling about **`U76`/X2**, not about the release. Read as
*"both `Accept` rows are satisfiable before the ship"* it answers a question it
was never asked, and conjunct 2 falsifies that reading on its face.

### 1.3 `Q35` blocks nothing, and `docs/success-metric.md` has never existed

```
rows with Q35 as an after-term: 0            (script parse of all 857 checkbox rows)
$ git log --all --oneline -- docs/success-metric.md | wc -l
0                                            REAL_EXIT=0
$ ls -la docs/success-metric.md
ls: cannot access 'docs/success-metric.md': No such file or directory
```

Exactly **two** rows name the file: `Q35` (`TODO.md:861`, its creator) and the
ticked `U76` (`:896`). D73 §7 item 7's words are *"Every number in
`docs/success-metric.md` is, today, zero — and the file does not exist. **The
first thing this ruling owes is its own instrument**"*. `Q22`, `Q35`'s only
other `after` term, is **`[x]`**. So the instrument half is unblocked by
everything except the word this record is ruling on.

### 1.4 Fifteen rows carry `Q1` as an `after` term, seven of them open

Parsed per rule 7 + D156 §2 R11 (runs terminate on `before`, `with`, `—`, `·`,
`✅`, `**[`), over all 857 checkbox rows in `TODO.md`:

| | rows |
| --- | --- |
| **ticked** behind `Q1` (8) | `Q2` `Q4` `Q5` `Q7` `Q9` `Q43` `Q15` `Q244` |
| **open** behind `Q1` (7) | `Q56` `A30` `Q16` `Q19` **`Q30`** **`Q31`** `Q238` |

The ticked count is **8**, which is exactly what D156 §1.3 asserts
(*"eight of them behind `Q1`"*) — an independent confirmation of the parse, and
the discriminator that caught the parser's one false positive (`Q190:731`,
where the run `after Q176: "…"` is quoted prose, not an edge).

**Two of the seven open rows carry `Q1` in a form a literal `grep "after Q1"`
cannot see**: `A30` (`— after A5,Q1`) and `Q238` (`— after R86, D135 §3 R6 +
§10 R2, Q1;`). A remedy scoped to `Q30` and `Q31` leaves **five** open rows
carrying the term.

### 1.5 Walked clause by clause: neither `Q30` nor `Q31` consumes branch protection

| row | `Accept` clauses | any clause requiring a **required status** / branch protection? |
| --- | ---: | --- |
| `Q30` | 3 | **none** — key published ≥2 places; clean-machine verify; sums+signatures produced by the pipeline |
| `Q31` | 6 | **none** — row 5's verification is `gh api repos/aed900/antseal/actions/permissions`, a **different endpoint** from `branches/main/protection` |
| **`Q238`** | 7 | **row 3: YES** — *"The promoted job is a **required status context** on `main`"* |

What `Q30` and `Q31` actually consume from `Q1`'s `Do` is the CI **matrix** and
the workflow files its lane mount points created — all landed, and `Q244` (also
`after Q1`, also ticked) pinned all 57 `uses:` invocations across them.

### 1.6 The branch-protection clause is live, and its own runbook forbids arming it now

`Q1`'s `Do` sentence 5 — *"Configure branch protection so all lanes are
required statuses"* — and `Accept` row 1's second half — *"and **are required
to merge**"* — have not landed. `docs/ci-verification.md`'s C2 block records:

```
$ gh api repos/aed900/antseal/rulesets
[]                                                     # REAL_EXIT=0
$ gh api repos/aed900/antseal/branches/main/protection
{"message":"Branch not protected", …, "status":"404"}  # REAL_EXIT=1
```

and, in the same block, the sentence that decides this record:

> **"Do not add a required status context in this sitting.** A required context
> that has never reported green on `main` blocks the next push, including the
> maintainer's own — and the hosted CI has refused every job since wave 20 on an
> exhausted Actions allowance, so *no* context has a recent green."

So the sequence is **measured, not argued**: *flip (`Q65`) → free standard
runners (D161 §2 R7's budget half) → one green run on `main` → required
contexts (`Q1`'s clause, `Q238`'s `Accept` row 3) → the ship*. A clause sitting
one step from becoming executable for the first time is the opposite of
vestigial. D161 §2 R7's rider binds here verbatim: **no required status context
may be added on the strength of that expectation.**

### 1.7 D156 §2 R1 is under-specified for a multi-clause `Do`, and its own evidence proves it

R1's literal text is *"If X's `Do` has **not** landed, the term is live and the
successor does not tick — whatever X's box says."* `Q1`'s `Do` has **not**
landed, in full. Read literally, the eight ticks R1 cites as its own proof are
eight defects and four passed milestone gates were wrong — which R1 itself says
*"no evidence supports"*.

The register has therefore always read the `Do` **clause-wise**, and D156 says
so everywhere except in R1's sentence: §2 R7 discharges `P17` *"for `Q32`'s
scripting"* and holds it live for `Accept` row 1; §2 R8 discharges `R26` *"for
writing"* and holds it *"live for verifying"*. §2 R1 supplies the missing
sentence rather than inventing a rule.

### 1.8 Two stale premises found in passing, both about the same 403

- **`Q71` (`TODO.md:460`)**: *"nothing can enforce it (**branch protection
  403s**, D52 E1)"*. D141 §2 R8 measured that premise false on 2026-08-18.
- **`Q238` `Accept` row 3's parenthetical**: *"branch protection is
  plan-blocked on this account — `docs/ci-verification.md`, 'Branch protection
  is BLOCKED BY PLAN'"*. Same dead premise, on a live M4 `Accept` clause, and
  it is the clause §1.5 identifies as the one real consumer.
- **A seventh locator drift**: D156 §2 R7 routes `P17`'s residue to *"the
  **Maintainer actions** block at `TODO.md:98`"*. Measured, that block is at
  **`TODO.md:99`**; line 98 is the wave-26 registration line. §2 R4 names the
  block by its heading text, per D156 §2 R11's own lesson.

---

## 2. RULING

### §2 R1 — `after X` is discharged **clause-wise** when X's `Do` carries more than one clause

Amending **D156 §2 R1**, whose text this supplies rather than contradicts:

> Where X's `Do` states more than one clause, an `after X` term is discharged
> **against the clause the successor consumes**. To discharge it, name that
> clause, name the artifact it promised, and show the artifact in the tree. An
> unlanded clause of X that **no** clause of the successor's `Accept` requires
> does **not** hold the successor. An unlanded clause that some clause of the
> successor's `Accept` **does** require keeps the term live for that clause
> alone, and the successor's lane writes which is which in the act that ticks
> it.

The test is unchanged and is rule 7's: **name the clause of the successor's
`Accept` that cannot be written until that clause of X's `Do` has landed.** If
you cannot name one, the clause is not this successor's dependency.

This is a statement of what the register has done since `0efdeee` (§1.7), and it
is **not a licence to discharge in bulk**: it is discharged per row, per clause,
by reading, and §2 R3 refuses to apply it to rows this record did not read.

### §2 R2 — `Q30`'s and `Q31`'s `after Q1` terms are **DISCHARGED and ANNOTATED — not struck**

The clause each consumes is `Q1`'s CI matrix and its lane mount points; it
landed (14 contexts green on run 30309407509, now 19 required contexts, all 57
`uses:` pinned by `Q244`). The clause each does **not** consume is branch
protection — measured across all nine `Accept` rows (§1.5).

The term **stays in the run**, exactly as D156 §2 R6 kept the `Q30` term on
`Q31`, because the workflow files are real predecessors and a future reader must
see why an OPEN row satisfied it. **Striking is refused** on rule 7's own words
(*repair "never by deletion"*; strike is permitted only *"if the verifier's own
`Accept` already carries the obligation"* — `Q1`'s `Accept` row 1 carries it and
`Q1` is open, so the precondition for striking is **absent**).

`Q30` and `Q31` are therefore **available to lane work today**, which is the
lean's direction reached by the opposite instrument.

### §2 R3 — The other five open rows behind `Q1` are **NOT discharged here**, and `Q238`'s term is **LIVE**

- **`Q238` — LIVE.** Its `Accept` row 3 requires a required status context on
  `main`, i.e. `Q1`'s unlanded clause. This is the one true `after Q1` edge in
  the open set, and it must not be struck.
- **`Q56`, `A30`, `Q16`, `Q19` — untouched.** This record did not read their
  `Accept` rows and does not discharge what it did not measure. They are named
  so the next survey does not rediscover them, and each is a one-lane reading
  under §2 R1.

### §2 R4 — `Q1`'s branch-protection clause is a **residue with no owner**, and it is routed exactly as `P17`'s was

Under D156 §2 R2 a residue needs a named owner. This one has none: it is an
external GitHub API write that no agent may take, and `Q1`'s own row calls its
status *"unmeasured, not plan-blocked"*.

- **Routed to `Q258`** — the row D153 §2 R9 minted for precisely this class
  (*"maintainer-only acts have no row of their own, so a readiness survey can
  find them only by reading another row's Notes"*) — **and** to the
  **Maintainer actions** block (named by heading, not line; §1.8).
- **Its ordering, written as a `before` deadline and NOT as a new `after`
  edge** (D156 §2 R8's discipline: collapsing `before` to `after` invents
  dependencies and manufactured wave 27's phantom cycles):
  **after `Q65`'s flip and one green run on `main`; before `Q34`.**
- **`Q1` does not tick on this record**, and its `⛔` status line is **kept and
  corrected**, not removed: the block is real, its stated reason is stale, and
  its true reason is §1.6's sequence.
- **No agent arms it, and nothing here is consent.** D161 §2 R7's rider is
  restated: no required status context may be added on the expectation of free
  runners. The expectation is not a measurement.

### §2 R5 — `after Q34` on `Q35` is **NOT a typo**; `before Q34` is **REFUSED**

Founding commit, two files, one act (§1.1), beside an `Accept` conjunct that
agrees with it (§1.2). Rewriting it to `before Q34` would assert that a
**post-release** weekly review is a **pre-release** deadline — a false claim
manufactured by a repair. Striking it outright is refused for the same reason
§2 R2 refuses striking: `Q34`'s `Accept` does not carry the weekly review, so
striking would leave an **unowned residue**, which D156 §2 R2 forbids.

### §2 R6 — `Q35` is **SPLIT**. The defect is a missing split, 219 rows old

- **`Q35` keeps the pre-ship instrument half.** Its ordering run becomes
  **`— after Q22, before Q34`** — one run carrying both words, precedented at
  `U78` (`— after U11/U18, before U32`) under D156 §2 R11.
- **A new M4 row carries the post-ship execution half**, ordering run
  **`— after Q34`**, id assigned by the registrar at registration.

### §2 R7 — The clause allocation, so no clause is lost in the split

| clause | goes to | why |
| --- | --- | --- |
| `Do`'s *"Write the plan before release"*; recruitment, onboarding, no-telemetry method | **`Q35`** | its own `Do` says *before release* |
| `docs/success-metric.md` created with D73 §4 R7's shape + header, **every number zero** | **`Q35`** | D73 §7 item 7: *"the first thing this ruling owes is its own instrument"* |
| `Accept` row 1 entire (*plan + artifact committed pre-release; definition verbatim*) | **`Q35`** | D73 §7 item 1: satisfied by D73 §1 and R4 |
| `Accept` row 2 conjunct 1 (*first outreach batch **scheduled***) | **`Q35`** | scheduling is not shipping |
| the **X7 planted-fault run** and its header record | **`Q35`** | D73 §7 item 6 names `Q35` its owner; executable as soon as the instrument exists (D154 §2 R5: not a precondition of creating the file) |
| `Accept` row 2 conjunct 2 (*progress reviewed weekly **post-release***) | **new row** | the only clause `after Q34` was ever true of |
| executing the first outreach batch; the weekly cadence until ≥10 | **new row** | `Notes`: *"Execution is post-release/continuous"* |
| **declaring the count met** | **new row**, gated on `U76`'s `metric-vault-fp` + X2 fired + the X7 record | D73 §7 item 6: *"a concrete pre-condition of declaring the count met"* |

The new row is **bounded and tickable** — the cadence ends at ≥10 completions
or at a recorded abandonment — so it does **not** belong in the Continuous
section (6 rows, all `[ ]` by design). `Q35` becomes tickable for the first
time; it is currently untickable in **both** directions, which no reword fixes.

### §2 R8 — **No checker is minted**, and three candidates are refused with their measured counts

| candidate | measured on the tree today | verdict |
| --- | --- | --- |
| *a row names T in its `after` run and says `before T` on the same line* | **8 hits** over 857 rows (`R5` `R32` `S36` `U43` `Q78` `Q167` `Q22` `U77`) — every one legitimate under D156 §2 R11 — and **0 true positives**: `Q35`'s row says `after Q22,Q34` and the string `before`/`pre-release` **appears nowhere on it** | **REFUSED — it cannot detect the defect it was designed for**, and its whole yield is false positives |
| *parse the `after` graph and verify it acyclic* | rule 7 already says *"nothing has ever parsed an `after` list"*, D141 §2 R7 **struck** the claim and **refused the checker under rule 8**; D156's own first parser produced **7 phantom edges** | **REFUSED — already refused, and the parser is the thing that needs a checker** |
| *flag an `after X` term where X's `Do` has not landed* | **mechanism-unbuildable**: *"`Do` has landed"* is a reading of prose against the tree, not a machine predicate; §2 R1 makes it a per-clause judgement | **REFUSED — no plantable fault exists, so no arm could redden** |

Recorded so the refusal is not read as laziness: the false-positive count for
candidate 1 is **8 of 8**, and it is exactly this project's dominant defect
class inverted — a check that is loud and blind at once.

### §2 R9 — The two stale 403 premises are corrected at source; neither mints a row

`Q71`'s parenthetical and `Q238`'s `Accept` row 3 parenthetical both rest on the
plan-403 that D141 §2 R8 measured gone. `Q71`'s is a **problem statement**, so
under rule 8 it is an instrument finding and takes a ledger line, not a row.
`Q238`'s sits inside a **live `Accept` clause on the ship path** — the one
clause §1.5 identifies as branch protection's real consumer — so it is corrected
in place, with §1.6's sequence written in as its true blocker.

---

## 3. What this record does NOT settle

- It does **not** discharge `after Q1` on `Q56`, `A30`, `Q16` or `Q19`. Those
  four are named, not ruled; §2 R1 is the instrument, one lane-reading each.
- It does **not** rule on `Q238`'s own ordering. That row carries `before the
  repository goes public` in its headline and `joint with Q65` in its `Accept`
  row 3 — **two different timing words for one obligation**, the same shape as
  `Q35`. Worse, §1.6's sequence puts the required-context promotion **after**
  the flip while the headline puts it **before**. That is a genuine ordering
  contradiction on a live M4 row and it needs its own decision.
- It does **not** arm branch protection, authorise arming it, or constitute
  consent for any external action. It does not authorise the flip.
- It does **not** create `docs/success-metric.md`. §2 R6/R7 say who does and when.
- It does **not** tick `Q1`, `Q30`, `Q31` or `Q35`, and it takes no position on
  whether `Q30`'s or `Q31`'s remaining `Accept` clauses are now reachable —
  D156 §2 R6 already answered that for `Q31` and this record only removes a
  false blocker.
- It **cannot** verify the GitHub-side state itself: §1.6's figures are read
  from `docs/ci-verification.md`'s recorded C2 capture, not re-measured, because
  no network command was run.

---

## 4. Edit list — per file, with the timing word

Ordering words below are rule 7's. Nothing here is an external action.

### `TODO.md`

1. **`Q35`'s row (`:861`)** — replace the ordering run `— after Q22,Q34` with
   **`— after Q22, before Q34`**, and append the §2 R5/R6 annotation naming the
   split and the new row's id. **with** edit 2.
2. **A new M4 row is minted**, id assigned by the registrar, carrying §2 R7's
   right-hand column and the ordering run **`— after Q34`**. **with** edit 1 —
   the two are one act, because landing edit 1 alone orphans conjunct 2.
3. **`Q30`'s row (`:856`)** — append the §2 R2 annotation: the `after Q1` term
   is **DISCHARGED (CI matrix + mount points landed), not struck**; branch
   protection is named as a clause this row's `Accept` does not consume.
   **with** edit 4.
4. **`Q31`'s row (`:857`)** — the same annotation, adding that row 5's read-back
   is `actions/permissions` and **not** `branches/main/protection`. **with**
   edit 3.
5. **`Q1`'s row (`:333`)** — append §2 R4: the `Do`'s clause 5 and `Accept` row
   1's *"required to merge"* half are a **residue routed to `Q258` and to the
   Maintainer actions block**; deadline **after `Q65` + one green run on `main`,
   before `Q34`**; the `⛔` is kept and its stale reason corrected. **after**
   edits 3–4.
6. **`Q238`'s row (`:863`)** — record §2 R3 (its `after Q1` term is **LIVE**,
   and it is the only open row whose `Accept` consumes the clause) and §2 R9's
   correction of the *plan-blocked* premise. **after** edit 5.
7. **`Q258`'s row (`:899`)** — add `Q1`'s branch-protection clause to the
   maintainer-act set it carries, with its §2 R4 deadline. **with** edit 5.
8. **The Maintainer actions block** (`## Current focus`, the line beginning
   *"**Maintainer actions** (all external)"* — **named by heading, not by line
   number**, per §1.8) — add the clause as a numbered entry, marked **not
   takeable in this sitting** with `docs/ci-verification.md`'s own sentence
   quoted. **with** edit 7.
9. **The M4 heading count and the register totals** — **recount by script**,
   never increment, after edit 2 lands. **after** every edit above.

### `tasks/Q.md`

10. **`### Q35`** — `Deps:` becomes `Q22` alone; `Do` keeps *"Write the plan
    before release"*; `Accept` row 2 keeps **only** *"First outreach batch
    scheduled"*; a `Notes` block records the split, the `0efdeee` measurement,
    and that D154 §2 R5's sentence is about **X2**, not about the release.
    **with** `TODO.md` edit 1.
11. **A new `### <new id>` entry** — `Milestone: M4`, `Deps: Q35, Q34, U76`,
    carrying §2 R7's right-hand column verbatim, with the ≥10 termination
    condition stated so the row is bounded. **with** `TODO.md` edit 2.
12. **`### Q30`, `### Q31`** — mirror the §2 R2 annotation into `Notes`.
    **after** `TODO.md` edits 3–4.
13. **`### Q1`** — a `Notes` block recording §2 R4: which clause of the `Do`
    landed, which did not, who owns the residue, and §1.6's sequence.
    **with** `TODO.md` edit 5.
14. **`### Q238`** — replace `Accept` row 3's parenthetical with §1.6's measured
    sequence; the clause itself is unchanged. **after** `TODO.md` edit 6.

### `docs/decisions/README.md`

15. **The `D163` index row.** **Registrar's edit, not a lane's** — this record
    does not write it.

### `docs/instrument-ledger.md`

16. **One line** for `Q71`'s stale *"branch protection 403s"* premise (rule 8:
    a problem statement about the apparatus takes no row), and **one line** for
    D156 §2 R7's `TODO.md:98` locator drift, now `:99` — the **seventh** of its
    class. **after** the `TODO.md` edits.

### Nothing else

No script is added or changed (§2 R8). No workflow is touched. No file under
`crates/`, `testdata/` or `.github/` is in this record's edit list, so **no
build, no golden vector and no tamper-matrix row is affected**, and the
`wasm32-unknown-unknown` surface is untouched.
