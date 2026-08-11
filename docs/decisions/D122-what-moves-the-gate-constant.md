# D122 — Q183: what moves `CURRENT_MILESTONE`, and why no check compares it to the Current-focus block

- **Status: RESOLVED — the bump belongs to the milestone-gate row, and the
  reason nothing bumped it is that three of the six gates have no row.** The
  row offers two shapes and leans to (b), a check against `TODO.md`'s
  Current-focus block. **Shape (b) is refused on a measurement: as worded it
  demands the value D118 §5 refused.** The block declares `M2` (*"Phase: M2 —
  Anchors, IN PROGRESS"*); the constant is `M1` and is correct; an equality
  check would be **red today against a correct constant**, and a lane obeying it
  would push the constant to the `M2` that forces `V7.1` into
  `ACCEPTED_NON_COVERED` and mutes it at the very review meant to read it.
  **Shape (a) is adopted, and its precondition — that a document a milestone
  review is run from exists — is satisfied, contrary to the row's own sweep.**
  It is `TODO.md` rule 4, *"Milestone gates"*, which already enumerates the acts
  that follow a passing gate, already says *"the gate, not the task count, is
  the exit criterion"*, and omits the constant. The row's sweep returned that
  file and filed it as a tracker.
  **The deeper finding is that the bump had no owner because the review had no
  row.** Only two of the six milestone gates are task rows — `Q14` executed
  M0's, `Q34` executes M4's. **M1, M2 and M3 have none.** The two data points
  that exist correlate exactly: M0's review was a row whose closing note records
  *"traceability all 16 M0 rows `covered`"* and the constant was right at the
  freeze; M1's review was an unrostered act and the constant went stale for
  eight days. The bump was never forgotten by a person — it was never assigned
  to anything.
  **No check is added.** A gate cannot parameterise itself from its own
  subject: deriving the constant from the matrix makes the status gate
  **provably unable to fail**, and deriving it from task rows is refuted by
  measurement — **M1's gate passed on 2026-08-02 and eleven of M1's
  seventy-one rows are still unchecked today**, most of them work discovered
  after the gate passed, so a passed milestone accretes rows forever.
- **Date: 2026-08-11** (wave 15, D122 lane, briefed to overturn shape (b) — it
  is overturned, and so are two of the four alternatives the brief supplied.)

---

## 1. What was measured

**(a) The constant, and its comment.** `scripts/check-traceability.py:259` reads
`CURRENT_MILESTONE = "M1"`. Its comment block (`:238-258`) already carries
D118's semantics — *"It names the last milestone whose review has PASSED, not
the one being built"* — and a dated move record, *"M0 -> M1 on 2026-08-10 (Q165
/ D118)"*. **The instance is closed; the class is open.** The comment's own
opening sentence contradicts its third paragraph: it begins *"The milestone
under review"*, which is the reading D118 §5 needed three measurements to
refute.

**(b) The gate figures, confirmed exactly.**

```
$ python3 scripts/check-traceability.py --matrix --milestone M0
[matrix] ok — 34 rows over 34 spec bullets, 97 references resolved (M0=16, M1=6,
M2=5, M3=4, M4=3); status gate: all 16 row(s) at or before M0 read 'covered'

$ python3 scripts/check-traceability.py --matrix
[matrix] ok — … status gate: all 22 row(s) at or before M1 read 'covered'
```

16 and 22, as the row states.

**(c) The phrase occurs at three in-code sites, not two, and the third is
user-facing.** The row counts *"two normative sites"* plus Q51's entry.
Measured:

| site | text |
| --- | --- |
| `scripts/check-traceability.py:239` | *"The milestone under review. **This is the line a milestone review bumps.**"* |
| `scripts/check-traceability.py:1206-1208` | argparse `--milestone` help — *"milestone under review … the constant a milestone review bumps"*, **printed by `--help`** |
| `docs/testing/verification-matrix.md:51-52` | *"the constant `CURRENT_MILESTONE` in that script — **the line a milestone review bumps.**"* |
| `tasks/Q.md:751` (Q51's entry) | *"The constant is the line a milestone review bumps"* |

**(d) The row's four-file sweep is wrong in both directions, and its error is
the load-bearing one.** Q183 says *"the only files that mention it at all are
the checker, the matrix, D118 and the Q14 freeze-gate plan"*. Measured at
`1c702d4` (wave 13, before D118 and Q183 existed):

```
$ git grep -l "milestone review" 1c702d4
TODO.md
docs/format/Q14-freeze-gate-plan.md
docs/testing/verification-matrix.md
scripts/check-traceability.py
tasks/Q.md
```

**Five files, and D118 is not among them** — it did not yet exist, so it cannot
have been in the sweep that discovered the row. `TODO.md` and `tasks/Q.md`
**were**, and both were dropped. Today the same sweep returns seven.

**(e) The document a milestone review is run from exists, was in the sweep's own
output, and was misfiled.** `TODO.md:29`, rule 4 of *"How to use this list (the
adaptive protocol)"*:

> **Milestone gates**: a milestone is done only when its gate checklist passes —
> the gate, not the task count, is the exit criterion. Run the gate, record
> evidence, then move the Current-focus block forward.

That is a milestone-review procedure. It names the exit criterion, it enumerates
the closing acts in order, and it omits the constant. The per-milestone gate
clause lists live in the same file as `Gate:` lines at `TODO.md:63` (pre-M0),
`:291` (M1), `:378` (M2), `:653` (M3).

**(f) Three of six gates are not rows.** Searching for the rows that execute a
gate returns exactly three, covering two milestones:

```
$ grep -nE "Execute the M[0-4]|Script the M[0-4]" TODO.md
283:- [x] **Q14** (S) Execute the M0 format-freeze gate; annotated `format-v1-freeze` tag …
697:- [ ] **Q32** (L) Script the M4 gate: Sepolia E2E + clean-machine procedure + disk-loss drill …
699:- [ ] **Q34** (M) Execute the M4 gate: mainnet smoke seal, clean-machine verify, drill, SHIP …
```

A broader sweep of every checkbox row whose text mentions a gate adds none.
**M1, M2 and M3 have a declared gate and no row that executes it.** `Q14`'s
closing note ends with *"traceability all 16 M0 rows `covered`"* — the one
milestone whose review was a row is the one whose constant was correct at the
end of it.

**(g) M1 passed with eleven rows open, and that number is not shrinking.**

```
$ awk 'NR>289 && NR<376 && /^- \[ \]/' TODO.md | wc -l
11
$ awk 'NR>289 && NR<376 && /^- \[x\]/' TODO.md | wc -l
60
```

The eleven are `P22`, `S37`, `S30`, `S24`, `S25`, `S26`, `U39`, `U41`, `U42`,
`U43`, `Q71`. Most were **discovered after** M1's gate passed on 2026-08-02 and
filed to the milestone that owns them.

**(h) The Current-focus Phase line, over every commit that has touched
`TODO.md`.** Grouping the first `> **Phase:` line of each revision:

| revisions | grammar |
| --- | --- |
| 79 | `Phase: M0 COMPLETE — the format-v1-freeze tag exists.` |
| 30 | `Phase: M2 — Anchors, IN PROGRESS.` |
| 9 | `Phase: M1 COMPLETE — the storage milestone's gate passes …` |
| 16 | `Phase: M0 — wave N executed <date>` (six distinct variants, waves 1–6) |
| 2 | `Phase: pre-M0 — …` (**no milestone token at all**) |

**(i) `"under review"` has spread to nine sites**, including the runtime failure
message at `:390` — *"…but `M1` is under review and every row at or before it
must read 'covered'"* — and the parameter name `under_review` (`:325`, `:332`,
`:334`, `:336`, `:339`, `:352`). A reader who trips that failure today is told
M1 is under review. M1's review finished on 2026-08-02.

---

## 2. Shape (a) — a review-checklist item

The row states shape (a)'s precondition honestly and then guesses wrong about
it. §1 (e) settles it: **the checklist exists.** It is not a runbook in
`docs/`, which is what the sweep looked for and why it was missed — it is rule 4
of the working-rules block at the top of the file every lane opens first, and it
already lists the two acts that follow a passing gate.

So shape (a) is not *"add a checklist item to a checklist nobody has written"*.
It is **add the third act to a three-act list that already has two** — a
one-clause edit to a live, followed procedure.

The objection to shape (a) is the row's own `Accept`: *"a mechanism that is not
memory"*. A sentence in a working-rules block is memory-assisted. §5 answers
that objection: the `Accept` also permits *"refused by a checklist item"*, and
the enforcement the project already uses for every other obligation is a row's
`Accept` — a row cannot be checked off without satisfying it. That is what makes
the bump an obligation rather than a recollection, and it is why the missing
gate rows matter more than the missing sentence.

---

## 3. Shape (b) — compare the constant to the Current-focus block

**Refused, on three grounds, the first of which is fatal by itself.**

**(a) As worded, it demands the value D118 §5 refused.** The row asks for *"a
check comparing `CURRENT_MILESTONE` against the milestone `TODO.md`'s
Current-focus block declares"*. The block declares `M2`. The constant is `M1`.
D118 §5 established with three measurements that `M1` is correct and `M2` is
wrong — there is no M2 review to be under; `M2` would force `V7.1` into
`ACCEPTED_NON_COVERED`, a register reserved for *"a milestone shipping with a
known hole"*, and then mute it at the M2 review itself. **A literal shape-(b)
check is red today against a correct constant**, and a lane resolving that red
in the direction the check points undoes D118. *The fix for an invisible gap
cannot be a register that hides it* — and it cannot be a check that argues for
one either.

**(b) The off-by-one is not a constant offset. It flips on a free-text word.**
The obvious repair is to compare against the *predecessor* of the declared
milestone. §1 (h) shows why that is not a repair. A regex over the token after
`Phase:` extracts `M0` from both `M0 COMPLETE` — where the constant should equal
the token — and `M0 — wave 3 executed` — where the constant should be the
predecessor, and there is no predecessor because the project was inside M0.
**The same captured token carries the constant's value in one grammar and its
successor in another**, and the only disambiguator is whether the next word is
`COMPLETE`. Two revisions carry no milestone token at all. Of the five grammars
this line has used, a predecessor rule is correct for two and wrong for three.

**(c) It promotes the block that has twice eaten a self-test mutation.** The row
names this cost and the brief sharpens it. It is real, but it is third here:
shape (b) fails on arithmetic before it fails on genre.

**What survives from shape (b):** the *observation* underneath it — that the
project keeps a register of which milestone it is in and nothing reads it — is
correct. It is just that the register is prose, means two different things in
the same field, and is one ahead of the constant by design.

---

## 4. Shape (c) — derive it from a machine-shaped source that already exists

The brief proposes three candidates. All three fail, and the second fails on a
measurement rather than an argument.

**The `Gate:` clause lines in `TODO.md`.** These say what each gate *requires*,
not which gates have *passed*. Four of six milestones have one; M0's and M4's do
not. Wrong question, incomplete coverage.

**The per-row `Milestone:` fields in `tasks/*.md`.** This is the derivation
*"milestone Mₙ has passed when all of Mₙ's rows are done"*. §1 (g) refutes it:
**M1's gate passed on 2026-08-02 and eleven of its seventy-one rows are
unchecked today, eight days later.** The check would never have fired for M1 at
all. Worse, it is monotonically unfixable — most of the eleven are work
*discovered after* the gate passed and filed to the milestone that owns it, so a
passed milestone gains rows indefinitely and the condition gets further from
true over time, not closer. `TODO.md` rule 4 says this itself, in the sentence
the row did not read: *"the gate, not the task count, is the exit criterion."*

**A dedicated one-line datum file.** This is the constant, in a second file,
still written by hand — with the two now able to disagree. It adds a drift
surface and removes none. Refused.

---

## 5. Shape (d) — delete the constant and derive the gate's scope from the matrix

The brief asks whether a hand-maintained current-milestone value is needed at
all. **It is, and the reason is a two-line proof rather than a preference.**

Let `CURRENT_MILESTONE := max{ Mᵢ : every row at or before Mᵢ reads 'covered' }`.
Then, by construction, every row at or before `CURRENT_MILESTONE` reads
`covered` — which is exactly the predicate `check_matrix`'s status gate tests.
**The gate passes unconditionally.** The only failure left in that arm is the
vacuity guard at `:446`. A stale `gap` row would simply lower the derived
milestone and stay green, which is Finding 1 restored in full and Q51 undone.

**A gate cannot parameterise itself from its own subject.** The constant's whole
value is that it is the one input to the status gate that is *not* derived from
what the gate checks — an independent assertion about the world that the data
can then contradict. That is also the general answer to §4: every proposal to
make the constant automatic either reads an artefact the gate checks (vacuous)
or an artefact nobody checks (narrative). **There is no third source, because
the event the constant records — a review passing — is not written down anywhere
else in this project.** The constant *is* the project's only machine-readable
record of which reviews have passed.

That reframes the defect. It was never that the value is hand-maintained. It is
that **the act that writes it is not on anyone's list.**

---

## 6. The ruling

1. **`CURRENT_MILESTONE` stays a hand-maintained constant, and stays the last
   milestone whose review has PASSED** (D118 §5, unchanged and now cited at the
   constant rather than restated).
2. **The bump is an act of the milestone-gate row**, alongside recording the
   evidence and moving the Current-focus block. `TODO.md` rule 4 gains it as the
   third of three closing acts.
3. **Every milestone gate is a task row, and three are missing.** `Q14` was M0's
   and `Q34` is M4's; M1's, M2's and M3's do not exist. Registering M2's and
   M3's is what converts the bump from a sentence into an `Accept` clause that a
   row cannot be checked off without — the project's existing enforcement
   mechanism, not a new one. **This is described in §10 and numbered by the
   orchestrator, not here.**
4. **No check is added comparing the constant to the Current-focus block, now or
   later**, and the constant's comment records that refusal with its reason, so
   the next lane that has this idea meets the measurement instead of repeating
   the work. **This project already has the house form for exactly that**, one
   file over: `CITATION_SCAN`'s comment block records a reason for each of its
   deliberate exclusions — `docs/decisions/` is out on D109 §3.3, `.github/` on
   D116 §2 (c) — and the row covering the third, unreasoned exclusion states the
   principle in one line: *"an exclusion with a reason is a decision; an
   exclusion with no reason is an accident that has not cost anything yet."*
   A **refused check** is the same object as an excluded scan root, and it earns
   the same treatment: written at the constant, with its measurement, in the
   shape the neighbouring exclusions already use.
5. **The constant's comment stops asserting a procedure that does not exist**,
   and so do the other three sites — including the argparse help, which prints
   the claim to users, and the runtime failure message, which tells readers a
   finished review is in progress.

**Why this and not a check:** the row's `Accept` asks for *"a mechanism that is
not memory"*, and offers *"caught by a check **or** refused by a checklist
item"*. §3–§5 exhaust the checks: every one is either red against a correct
constant, or vacuous, or reading prose whose meaning inverts on a word. What is
left is the second arm — and the honest form of it is not a sentence asking
someone to remember, but a row whose `Accept` contains the bump, because that is
how this project already makes every other obligation non-optional.

---

## 7. Edit set

**This lane wrote one file: this one.** Everything below is instruction.
- `docs/decisions/README.md` — this decision's index row. **Applied 2026-08-11**, executing [D119](D119-decision-index-identity-and-the-index-row-sections.md) §5 step 4; the former `## Index row` section is demoted to this line under D119 RULING 4, and RULING 6 puts the row in the act that commits the record.

### 7.1 `scripts/check-traceability.py` — **do not edit this wave**

Two other wave-15 lanes are in this file (Q184's fixture sweep, and the lane
ruling on `--self-test` staging). These edits belong to whichever lane holds the
file after them, or to a follow-up.

**(a) Replace the comment's opening sentence at `:239`.** Current:

```
# The milestone under review. **This is the line a milestone review bumps.**
```

Replacement:

```
# The last milestone whose review has PASSED — not the one being built, and
# not "the milestone under review", which is the reading that sent Q165 to M2
# (D118 §5). **What moves it is the milestone-gate row for the milestone that
# just passed**: TODO.md rule 4 lists the acts that close a passing gate and
# this is one of them. Q14 was M0's gate row; Q34 is M4's.
#
# Nothing compares this line to TODO.md's Current-focus block, and D122
# refuses such a check on measurement, not taste: the block names the
# milestone IN PROGRESS ("M2" today) where this names the last one PASSED
# ("M1"), so equality is red against a correct constant; and across this
# project's history that line has used five grammars, in which the same token
# position means the current milestone in three and the finished one in two.
```

**(b) `:1206-1208`, the `--milestone` help — it is printed by `--help`.**
Replace *"milestone under review for the --matrix status gate"* with *"last
milestone whose review has passed; the --matrix status gate requires every row
at or before it to read 'covered'"*, and the parenthetical *"the constant a
milestone review bumps"* with *"moved by the milestone-gate row for the
milestone that just passed — TODO.md rule 4"*.

**(c) `:390`, the status-gate failure message.** The fragment reading
`… but {under_review} is under review and every row at or …` states something
false to every reader who trips it. Replace with `… but {under_review}'s review
has passed and every row at or …`.

**(d) Optional, and a merge hazard this wave:** rename the parameter
`under_review` → `gated_through` at `:325`, `:332`, `:334`, `:336`, `:339`,
`:352`. Cosmetic — it changes no printed output beyond (c) — and safely
deferrable. It is listed because *"under review"* is where the M2 misreading
came from, and the name keeps regenerating it.

### 7.2 `docs/testing/verification-matrix.md` — *"How the gate uses this"*, final bullet (`:49-57`)

Replace *"— **the line a milestone review bumps.**"* with:

> **It names the last milestone whose review has passed, and what moves it is
> that milestone's own gate row** (`Q14` did it for M0; `Q34` will for M4) —
> `TODO.md` rule 4. It is deliberately **one behind** `TODO.md`'s Current-focus
> block, which names the milestone in progress: nothing compares the two, and
> D122 rules that nothing should.

**Warning to the implementing lane, and it is not decorative.** This file
carries the two `--self-test` status-gate fixtures. Both mutate a matrix table
row's status cell by a **first-occurrence `str.replace` scoped to this file**,
and the fixture's own comment already records the governing rule — *"Any
status-gate fixture must be pinned to a row that outlives the constant it is
testing against."* The replacement prose must not reproduce that table row's
text in any form, and no new prose anywhere above the table may either. This is
the failure that went to CI twice in wave 14. Describe the cell; never quote it.

### 7.3 `TODO.md:29`, rule 4

Current:

> 4. **Milestone gates**: a milestone is done only when its gate checklist
>    passes — the gate, not the task count, is the exit criterion. Run the gate,
>    record evidence, then move the Current-focus block forward.

Replacement:

> 4. **Milestone gates**: a milestone is done only when its gate checklist
>    passes — the gate, not the task count, is the exit criterion. **Each gate
>    is a task row** (`Q14` executed M0's; `Q34` executes M4's), and its
>    `Accept` carries all three closing acts: record the evidence, **bump
>    `CURRENT_MILESTONE` in `scripts/check-traceability.py` to the milestone
>    that just passed**, and move the Current-focus block forward. The constant
>    **lags the Current-focus block by exactly one** — it names the milestone
>    last *passed*, the block names the one *in progress*. Nothing compares them
>    and nothing should (D118 §5, D122).

**This edit and the gate-row registrations in §10 must land in the same act.**
Rule 4 as replaced says *"each gate is a task row"*, and for M2 and M3 that is
not yet true. Landing the sentence alone would put a second normative statement
of a procedure that does not exist into the tree — which is the exact defect
this decision was opened to end, reproduced by its own fix.

### 7.4 `tasks/Q.md:751`, Q51's entry — a **dated correction**, not a rewrite

The sentence *"The constant is the line a milestone review bumps"* is the third
statement of the fiction. Per D117, what is forbidden is silence, not change:
append a dated correction rather than editing the claim away —

> *— corrected 2026-08-11 (D122): what bumps it is the milestone-gate row for
> the milestone that just passed. No procedure did, which is Q183, and Q51's
> gate was correct and unarmed for eight days as a result.*

**Measured for the implementing lane:** `tasks/Q.md`'s `FREEZE-BOUNDARY` block
runs `:180-214`. Line 751 is well outside it, so this edit does not touch frozen
bytes — but re-run `--freeze-boundary` regardless, because Q49 exists.

### 7.5 `TODO.md:627` and `tasks/Q.md` Q183

Mark resolved with the §9 status line, and record in Q183's entry that its
four-file sweep was measured wrong in both directions and that the checklist it
supposed missing is rule 4 of the file the sweep already returned.

---

## 8. Commands run, with verdicts

| command | verdict |
| --- | --- |
| `python3 scripts/check-traceability.py --matrix --milestone M0` | `[matrix] ok — … all 16 row(s) at or before M0 read 'covered'` |
| `python3 scripts/check-traceability.py --matrix` | `[matrix] ok — … all 22 row(s) at or before M1 read 'covered'` |
| `python3 scripts/check-traceability.py` (flagless) | `check-traceability: ok (freeze-boundary, matrix, decisions, task-citations, task-entries, decision-owners)` — six lanes, whole output read, no failure lines |
| `python3 scripts/check-traceability.py --self-test` (before this file existed) | **34** `self-test: ok — …` lines, no failure line; whole output read from the top |
| `python3 scripts/check-traceability.py --self-test` (with this file) | **transient crash, not a check failure, and not this lane's** — `ValueError: too many values to unpack (expected 3)` at `:1698`. Diagnosed by its message and proved content-independent: the helper's signature is `-> tuple[int, str, str, str]` and returns four values unconditionally, while the call site unpacked three, so it crashed on **any** tree regardless of what this lane added. `git diff` shows both the signature and the call site inside the concurrent lane's uncommitted `+334/−10` edit to this script; the file's mtime is **later** than this document's. The lane finished the edit and the mismatch is gone. |
| `python3 scripts/check-traceability.py --self-test` (re-run, script consistent) | **28** `self-test: ok — …` lines, **no failure line anywhere**, output read whole and from the top — failures print **first**, so the tail alone is not a verdict |
| `python3 scripts/check-traceability.py --check` | **no such flag** — `error: unrecognized arguments: --check`. The ordinary run is flagless, exactly as the constant's own comment says. |
| `git grep -l "milestone review" 1c702d4` | five files; D118 absent, `TODO.md` and `tasks/Q.md` present |
| `grep -nE "Execute the M[0-4]\|Script the M[0-4]" TODO.md` | three rows, two milestones: `Q14`, `Q32`, `Q34` |

**Two caveats on the verdicts above, both stated rather than smoothed.** First,
the self-test's case count moved **34 → 28** between the two green runs. That is
the concurrent lane restructuring the harness mid-wave, not a lane going quiet:
both runs are green and neither count is this lane's to explain. **`--self-test`
should be re-run at integration, after that edit settles.** Second, **this
document's own citations were checked by hand, not by the gate**:
`docs/decisions/` is outside `CITATION_SCAN` by deliberate exclusion on D109
§3.3, so no check reads the D- and task-ids in this file. Every one was resolved
manually against `TODO.md` and `tasks/*.md` before this was written.

---

## 9. Status line for `TODO.md`'s Q183 row

> ✅ 2026-08-11 — **RULED by D122: the bump belongs to the milestone-gate row,
> and shape (b) is refused because as worded it demands the `M2` that D118 §5
> refused** — the Current-focus block names the milestone *in progress* where
> the constant names the last one *passed*, so equality is red against a correct
> constant, and across five grammars of that line the same token means the
> current milestone in three and the finished one in two. **The row's four-file
> sweep is wrong in both directions**: measured at `1c702d4` it returns five
> files, D118 absent (it did not exist) and `TODO.md` and `tasks/Q.md` dropped —
> **and `TODO.md` is the checklist the row supposed missing**, rule 4 already
> naming the exit criterion and the closing acts and omitting only the constant.
> **The real defect is that the bump had no owner because the review had no
> row**: only `Q14` (M0) and `Q34` (M4) execute a gate, M1/M2/M3 have none, and
> the one milestone whose review was a row is the one whose constant was right
> at the end of it. **No check is added** — deriving the constant from the
> matrix makes the status gate provably unable to fail, and deriving it from
> task counts is refuted by measurement (M1 passed 2026-08-02 with **11 of 71**
> rows still open today, most discovered after the gate). Four sites lose the
> fiction, including the argparse help that prints it and the failure message
> that calls a finished review current

---

## 10. Discovered work — described, not registered

No ids are minted here.

**(i) M1's, M2's and M3's gate-execution rows do not exist.** M0's was `Q14` and
M4's is `Q34`; the other three milestones have a declared `Gate:` clause list
and nothing that executes it. This is the finding under the finding — §6 (3) —
and M2's is live work, not hygiene: M2's review is the next one, and it is
currently owned by nobody. §7.3's rule-4 edit is blocked on at least M2's and
M3's existing.

**(ii) D118's own fix created a second, unchecked statement of the constant's
value.** `docs/testing/verification-matrix.md:31-32` now reads *"M1's review has
happened and M1 is gated from 2026-08-10"*. That is the constant's value written
a second time, in prose, with nothing comparing them — a fresh instance of the
class this decision closes, introduced by the change that closed it. It rots the
moment M2's review bumps the constant. Either it becomes an act of the M2 gate
row alongside the bump, or it should be reduced to something the checker
verifies.

**(iii) `"under review"` is a defect vector, not a wording preference.** It sits
at nine sites including the parameter name and one user-facing failure message,
and it is provably where the M2 misreading came from: Q165's `Accept` implied
`M2` and D118 §5 spent three measurements undoing it. §7.1 (d) defers the rename
because of this wave's contention. It should not be deferred twice.

**(iv) The row's sweep failed in a way worth generalising.** It grepped for a
phrase, got five files, and classified `TODO.md` and `tasks/Q.md` as trackers
rather than reading them — so a procedure sitting in the results was reported
absent, and the row was written around a hole that was not there. This is the
same shape as D118's *"the answer sat in `TODO.md`'s own rows; nobody had
looked"*. A sweep that returns the tracker files needs a rule about reading
them, because in this project the trackers **are** the procedure documents.

---

## Outcome

The constant was already correct when this row was opened; what was missing was
anything that would keep it so. Four sites said a milestone review bumps it and
no milestone review had ever been asked to, because for three of the six
milestones a review is not a thing anyone is assigned to do.

The row's preferred fix would have made it worse. Comparing the constant to the
Current-focus block is red today against a value D118 established over three
measurements, and the obvious repair — compare against the predecessor — is
correct for two of the five grammars that line has actually used and wrong for
three. Neither of the automatic alternatives survives either: one makes the gate
unable to fail, and the other never fires, because a milestone that has passed
keeps collecting rows.

**What is left is the thing the project already does everywhere else.** The
bump becomes a clause of an `Accept`, on a row that has to exist because the
review has to be done by someone. And the comment at the constant stops
describing a procedure and starts naming one.
