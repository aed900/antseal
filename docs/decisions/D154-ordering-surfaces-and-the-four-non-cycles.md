# D154 — None of the four is a cycle. The `after` graph holds zero, the four "cycles" it *does* report are four different parser artefacts, and the live defect is that D141 §2 R5 and §2 R6 were transcribed into `TODO.md` with their timing words dropped

- **Status: RESOLVED. The lean is OVERTURNED ON ITS PREMISE, HALF CONFIRMED IN
  DIRECTION FOR TWO OF THE FOUR, AND OVERTURNED OUTRIGHT ON BOTH OF ITS
  AVAILABILITY CLAIMS.** The lean was *"All four are real cycles; strike the
  backwards edge in each and U76/Q28 become available."*
  - **Not one of the four is a cycle in the authoritative order.** A cycle needs
    two edges. Defect 1 has **one** `after` edge and one `Accept` clause;
    defect 2 has **one** `after` edge written twice on two surfaces of the same
    row; defect 3 has **zero** — it exists on no `after` list at all; defect 4
    is one edge and no second edge was ever alleged. Measured over the whole
    tracker: **838 rows, 1 393 `after` edges, four 2-cycles — and none of them
    is any of the four** (§1.1).
  - **The four cycles the parser *does* report are four false positives from
    four different causes**, and one of them is the token rule 7 names as its
    own example. A cycle checker over `after` runs therefore has, on today's
    tree, precision **0/4** and recall **0/4** against the defects actually in
    front of us (§1.1, §1.11). D141 §2 R7 refused to mint one a wave ago; this
    record finds three further reasons and refuses it again.
  - **Direction survives for two of the four, and the replacement the lean never
    named is `with`/`before`, never an inverted `after`.** Inverting defect 1 —
    writing `Q65 after Q254` — is not merely wrong, it is **measured to create
    one 2-cycle and three 3-cycles**, because Q242/Q243/Q244 are each recorded
    `after Q65` and Q254 is `after` all three (§1.2). That is D141's own
    experiment shape landing on a second pair.
  - **The real defect is a transcription defect, and it is upstream of three of
    the four.** D141 §2 R5's four `TODO.md` edits **were never made** — the
    corrections landed in `tasks/Q.md` and were skipped on the surface rule 7
    calls authoritative (§1.3). And D141 §2 R6 prescribed the new row's `Deps`
    with timing words attached — `Q65 (this row IS Q65's execution half),
    Q242 (with), Q243 (before), Q244 (before)` — and **the two terms whose word
    was not `after` were both transcribed as `after`** (§1.4).
  - **`U76` becomes available: CONFIRMED.** Its other four predecessors are all
    `[x]` (§1.6). But the edge is not struck because it is half of a cycle — it
    is struck because it **contradicts the record that minted the row**: D73 §7
    item 2 orders the tool *"before Q35's **first submission**"*, and the
    register wrote `after Q35`. The replacement is `before Q35's first
    submission`, and `Q35 after U76` must **not** be written (§1.5).
  - **`Q28` becomes available: OVERTURNED, and the stake stated for defect 4 is
    false.** Q28 is `after Q20–Q27` and **Q22 is `[ ]`** (`TODO.md:811`). The
    `U31` edge decides nothing about Q28's reachability, and it is not
    unsatisfiable in any case: it was **discharged on 2026-08-16**, and Q20's
    own tick note wrote the reading down (§1.8, §1.9).
  - **An edge that can never be satisfied does exist — and it is not the one the
    survey named.** `Q254 after Q242` requires a row whose `Accept` can only
    read true *"in the same window as the visibility change"* to be `[x]` before
    a checklist whose own `Accept` is *"committed **before** the flip"*
    (§1.10). `after U31` is satisfiable; `after Q242` is not.
- **Date: 2026-08-19**
- **Owning task: Q254** (the row whose ordering this record repairs, and the one
  it makes available). Rulings touch `TODO.md`'s Q65, Q242, Q243, Q244, Q254,
  Q28, Q35, U32 and U76 rows and rule 7; `tasks/Q.md` Q28's `Deps`, Q35's Notes,
  Q65's `Accept` row 3 and Q254's `Deps`; `tasks/U.md` U32's `Deps` and U76's
  `Deps`/Notes; and `docs/instrument-ledger.md`. **No new id is assigned here and
  no row is minted** — §5 states what the registrar lands and §2 R11 states why
  nothing is minted.
- **What it blocks:** `Q254` (unblocked by this record), `U76` (unblocked by this
  record), and the readability of the M4 ship path for the next readiness
  survey — which under the register as it stands today reads two ticked rows
  (`Q243`, `Q244`) as sitting behind an open predecessor (`Q65`).
- Related: **D141 §2 R5** (the four `TODO.md` edits never made), **§2 R6** (the
  `Deps` prescription whose timing words were dropped), **§2 R7** (rule 7's
  *"(verified acyclic)"* struck; no checker minted), **§6** (*"Known limits"* —
  its parser reads only `after` runs); **D150 §1.8** (the `Accept`-clause
  surface D141 never enumerated), **§2 R1** (the strike-plus-consumer
  instrument, and the mirror-image warning this record checks itself against),
  **§2 R2** (the consumer annotation's house form); **D73 §4 R5/R7** (X2, X7 and
  the tracking file's header block), **§7 item 2** (*"before Q35's first
  submission"* — the ordering the register inverted), **§7 item 6** (what X7 is
  actually a precondition of), **§7 item 1** (*"`tasks/` is outside this lane's
  write scope"*); **D134 §4 item 1** (U77's nomination, whose own successor-as-
  predecessor clause was corrected in wave 26); **TODO.md rule 7** (the
  authority for every ruling below) and **rule 8** (why §2 R11 mints nothing).

---

## 1. What was measured

**Provenance of every line number below.** Measured 2026-08-19 against the
**working tree**, not `HEAD`: `git status --porcelain` reports `TODO.md`,
`tasks/Q.md`, `docs/signing/key-custody.md` and
`docs/signing/maintainer-key-procedure.md` as modified-uncommitted. Every edit in
§5 is therefore keyed to a **row id and an exact old string** as well as a line
number, so it survives a locator drifting under another lane — the discipline
`docs/instrument-ledger.md:196` argues for after rule 7's own two cited locators
went stale within one wave of being written.

**All fourteen locators the brief supplied were re-measured and all fourteen are
correct** — `TODO.md:845/824/859/817/856/869/803`, `tasks/Q.md:3231/978/3237/500`,
`tasks/U.md:1074/534/521`. This is recorded because the counts in this project
have drifted four separate times and a lane is right to distrust them, and
because **this lane's own first reading was the wrong one**: an early pass
printed `TODO.md:843-847` and reported *"`:845` is Q257, not Q254"* from the head
of the range. `:843` is Q257 and `:845` is Q254. **What was wrong in the brief is
the characterisation, not a single locator** — and correcting a good citation
from a neighbouring line is the failure this project has already recorded twice.

### 1.1 The authoritative `after` graph: 838 rows, 1 393 edges, four 2-cycles — and all four are artefacts

A parser was written for this record (scratchpad only; nothing committed, nothing
minted — §2 R11). It reads `— after …` runs from `TODO.md` checkbox lines,
expands en-dash ranges (`Q20–Q27`, `U1–U30`), drops `~~struck~~` spans, and stops
each run at the first `—`, `·`, `✅` or `**[`.

```
rows parsed          : 838
after-edges parsed   : 1393
2-cycles in after graph: 4  [('A5','A8'), ('R11','S15'), ('R89','R92'), ('U13','U14')]
non-trivial SCCs (any length): 4  (the same four pairs)
```

**838 reconciles exactly** with the register's own count: `grep -c` gives **686**
task checkbox rows and **152** decision rows; the 687th task row is
`~~**P18**~~` at `TODO.md:431`, which carries no checkbox and is correctly not
matched. Independently, **687** rows carry a `- Deps:` line in `tasks/*.md`.

**The parser is not vacuous.** A fault was planted on a scratch copy — `,U76`
appended to Q35's run at `TODO.md:824` — and the scan moved from 1 393 to
**1 394** edges and from four 2-cycles to **five**, the new one being
`('Q35','U76')`. The evidence is that delta and the named pair, not an exit code.
So the parser can see an M4 2-cycle between exactly the two rows the brief
alleges one for, and its silence on all four defects is a measurement.

**All four reported 2-cycles are false positives, from four different causes:**

| pair | the run that produced the phantom edge | what it actually is |
|---|---|---|
| A5 / A8 | `A5 — after A2 + D-A8 pins` | `A8` lifted out of the **decision id `D-A8`**. A tokeniser artefact. |
| R11 / S15 | `S15 — after S6 (R11 consumes)` | an **inline consumer annotation** inside the run — rule 7's first clause, written in the ordering position. |
| U13 / U14 | `U14 — after U2,U3,U13(interface) + S8` | `U13(interface)` — **rule 7's own literal example** of an annotated mention that is *"excused only by reading, not by a checker"*. |
| R89 / R92 | R89's row contains a **second** `— after ` that begins a prose sentence: *"— after R79 no adversary byte could reach a display line…"* | prose swallowed as an ordering run; `R92` lifted from *"those are **R92**, not a residue note"*. |

`TODO.md:1188` already records the U13⇄U14 shape as deliberate: the v1.1 pass
*"U13⇄U14 and eight consumer-reference cycles annotated (Deps-discipline rule 7
added)"*. The tracker has been carrying annotated consumer cycles as a matter of
policy for a year, and the only mechanism anyone has proposed for finding real
ones cannot tell them apart from a hyphenated decision id.

### 1.2 Defect 1 is one `after` edge and one `Accept` clause, and inverting the edge creates four cycles

Measured runs:

- `Q254` (`TODO.md:845`): `— after Q65,Q242,Q243,Q244`
- `Q65` (`TODO.md:825`): `— after Q22,Q28,Q27` — **it does not name Q254.**
- `tasks/Q.md:3231`: `- Deps: after Q65 (the publish-scope decision this sequences), Q242, Q243, Q244; consumes D141 §2 R6`

The other direction is `tasks/Q.md:978`, Q65's `Accept` **row 3** (third
top-level bullet under `- Accept:`, after the decision-record row and the
machine-path row):

> *"Executed **before** any visibility change, and the ordering stated where the
> visibility change would be made (the `docs/ci-verification.md` runbook)."*

That is an `Accept` clause, not an edge — **D150 §1.8's fourth surface** exactly.
So: one edge, one tickability condition. Not a cycle.

**Inverting the edge is measured to be forbidden.** `Q242 — after Q65, …`,
`Q243 — after Q65, Q2`, `Q244 — after Q1, Q65, Q31` (`TODO.md:830`, `:831`,
`:832`). Writing `Q65 after Q254` therefore creates `Q65→Q254→Q65` **and**
`Q65→Q242→Q254→Q65`, `Q65→Q243→Q254→Q65`, `Q65→Q244→Q254→Q65`. This is D141's
own finding on a second pair — *"inverting Q244 **creates**
`Q31→Q65→Q244→Q31`"*.

**One conjunct of Accept row 3 is already satisfied in the tree**, and it is
recorded here so nobody concludes nothing is written: the scrub-before-flip
ordering is stated at `docs/ci-verification.md:1191-1193` (*"**This triggers
Q65** … which must be executed *before* the visibility change, never after. Do
not take this option for a CI reason without taking Q65 first"*) and again at
`:1277` (*"which triggers **Q65 first**, never after"*). Neither sits inside the
section headed *"## Maintainer runbook (remote steps, in this exact order)"*
(`:216`), whose six steps are token refresh, push, first green run, wasm-guard
probe, branch protection and actionlint — **the visibility flip is not one of
them**. The *ordered flip procedure* is genuinely absent, and it is Q254's
deliverable, which Q254's own `Do` states: *"the venue Q65's own Accept row 3
names"*.

### 1.3 D141 §2 R5's four `TODO.md` edits were never made — and the same rulings did land in `tasks/Q.md`

D141 §2 R5 is titled *"Q243's edge is INVERTED. Q242's is NOT; it takes the
tracker's existing `with/before` form. Q244's is inverted and its Q31 edge is
re-homed"*, and names **the registrar** as who. It prescribes four `TODO.md`
edits. Measured today:

| R5 clause | prescribed `TODO.md` text | actual `TODO.md` text | landed? |
|---|---|---|---|
| (a) Q243 | `after Q2 · **before Q65** (D141 §2 R5)` | `— after Q65, Q2` (`:831`) | **no** |
| (b) Q242 | `after Q21/Q23,Q22 · **with/before Q65**` | `— after Q65, Q21/Q23, Q22` (`:830`) | **no** |
| (c) Q244 | `after Q1 · **before Q65** (D141 §2 R5(c))` | `— after Q1, Q65, Q31` (`:832`) | **no** |
| (a)+(c) | *"Add `Q243` … Add `Q244` to Q65's `after:` list"* | `— after Q22,Q28,Q27` (`:825`) | **no** |

`grep -n "before Q65\|with/before" TODO.md` returns **no hit on any of lines
830–832 or 825**. The same grep over `tasks/Q.md` returns **three hits**, all
landed and all dated:

- `tasks/Q.md:2994` — `- Deps: **with/before Q65** — *not* \`after\` *(corrected 2026-08-18 by D141 §2 R5(b) …)*`
- `tasks/Q.md:3009` — `- Deps: **before Q65** — *inverted 2026-08-18 by D141 §2 R5(a) …*`
- `tasks/Q.md:3024` — `- Deps: after Q1 (the CI skeleton); **before Q65** — *inverted 2026-08-18 by D141 §2 R5(c) …*`

**The ruling was executed on the detail surface and skipped on the authoritative
one.** This is the exact mirror of wave 24's follow-up finding (`dc0bac8`, *"the
rulings were recorded where status lives, not where the protocol says detail
lives"*): here they were recorded where detail lives and not where the build
order lives.

**The behaviour already followed the corrected reading.** `Q243` and `Q244` are
both `[x]` (`TODO.md:831`, `:832`) while the row they are recorded as `after` —
`Q65` — is `[ ]` (`:825`). Two ticked rows currently sit behind an open
predecessor on the authoritative surface. That is not a tick discipline failure;
it is the register disagreeing with itself, and the half that is wrong is the
half D141 §2 R5 already told the registrar to change.

### 1.4 D141 §2 R6 attached a timing word to each `Deps` term; the two that were not `after` were transcribed as `after`

D141 §2 R6, verbatim, prescribing the new row (Q254):

> `Deps: Q65 (this row IS Q65's execution half), Q242 (with), Q243 (before), Q244 (before)`

Four terms, three timing words, one identity statement:

| term | R6's word | what the registrar wrote | faithful? |
|---|---|---|---|
| `Q65` | **none** — *"this row IS Q65's execution half"*, a partition of one body of work | `after Q65` | **no** — a partition became a precedence |
| `Q242` | `(with)` | `after Q242` | **no** |
| `Q243` | `(before)` | `after Q243` | yes (Q243 precedes) |
| `Q244` | `(before)` | `after Q244` | yes (Q244 precedes) |

R6's own `Accept` for the row is *"the checklist is committed **before** the
flip"*, and its rationale is *"the irreversible act deserves an artefact that
exists **before** it and is auditable **after** it"*. Both halves of the flip's
paperwork — Q65's decision and Q254's checklist — are pre-flip. Neither needs the
other to be `[x]`; both need the other's content, in one act. That is what
`with` means and what rule 7's second scope correction blesses: *"this rule's
*ordering* vocabulary is **wider than `after`** — `with`/`before` already sit in
the ordering position"*.

**Everything Q254 needs from Q65 already exists as a written record.** Q254's
`Do` cites *"Q65 finding 4"*, which is written in Q65's **entry**
(`tasks/Q.md`, finding 4, *"The four at-the-flip GitHub settings, folded in
here rather than minted as rows"*), not in the decision record Q65 owes. This is
**D141 §2 R3's test** — the one D150 correctly refused to transfer to Q30
because *"a key is not a record"* — applied to a case where the operand **is** a
record, and returning yes.

### 1.5 Defect 2 is one edge, written twice on the same row, and inverted against the record that minted it

Measured:

- `U76` (`TODO.md:859`): `— after U23/U28, D29, D65, D73 §4 R5, Q35`
- `tasks/U.md:1074`: `- Deps: after U23/U28 (…), D29 (…), D65 (…), D73 §4 R5 (…), Q35 (the row that cannot run its own instrument without it)`
- `Q35` (`TODO.md:824`): `— after Q22,Q34` — **it does not name U76.**

So the "two `after` lists running the other way" are **two copies of one edge on
one row**, not two edges. A 2-cycle needs a second row to carry the return edge,
and Q35 does not.

**The edge is inverted against D73, the record that minted U76.** D73 §7 item 2,
verbatim:

> *"**This is real work and deserves a row** — describe it as "a maintainer-side
> distinctness tool that extracts `pubkeys` from a submitted bundle for D73 §4 R5
> X2", M4, **before Q35's first submission**."*

`after Q35` is the opposite of `before Q35's first submission`. And the `Deps`
gloss attached to the term says so in the row's own words — *"Q35 (**the row that
cannot run its own instrument without it**)"* — a **consumer** description filed
under `after`, which is precisely what rule 7's first clause forbids.

**The reverse edge must not be written either.** D73 scopes the precondition to
*"Q35's **first submission**"* (§7 item 2) and to *"declaring the count met"*
(§7 item 6: *"The R5 X7 planted-fault run is a concrete pre-condition of
declaring the count met, and it has an owner (Q35)"*). Q35's two `Accept` rows
are *"Plan + tracking artifact committed pre-release; completion definition
matches the spec metric verbatim"* and *"First outreach batch **scheduled**;
progress reviewed weekly post-release"*. **Neither needs X2 to have fired**, and
D73 §7 item 7 says the file should be created now with every number at zero
(*"The first thing this ruling owes is its own instrument"*). Q35's own Notes
partition the row the same way: *"Execution is post-release/continuous; the plan
is the M4 deliverable."*

So `Q35 after U76` would be **wrong on the merits**, quite apart from being the
mirror-image edge D150 §2 R1 forbids. The correct form is `before Q35's first
submission`, and the tracker already carries that exact shape: `U38 — after U1;
before U11's wizard half` (`TODO.md:414`), alongside `R33 — after R8, before
Q14` (`:269`) and `U84 — before U32`.

**Consequence for the two prose sites.** `TODO.md:824`'s *"**Blocked in fact, not
only in `after:`**"* and `tasks/Q.md:619`'s *"A blocker this row does not list in
its `after:`"* are **over-broad against D73's own scoping**: what is blocked is
the first submission and the declaration of the count, not the row's `Accept`.
Both are narrowed in §2 R5 rather than deleted — the underlying finding is
correct and worth keeping.

### 1.6 U76's remaining predecessors are all `[x]`, so the row becomes available — with one `Accept` clause the executing lane cannot discharge

`U23` `[x]` (`:561`), `U28` `[x]` (`:788`), `D29` `[x]` (`:908`), `D65` `[x]`
(`:1009`), `D73` `[x]` (`:1029`). With `Q35` struck, U76's run is fully
satisfied. (`R5` also appears in a naive parse of the run — lifted out of the
citation `D73 §4 R5`. It is a citation, not an edge; noted so the registrar does
not "fix" it.)

**The `Do` holds a choice, not a blocker.** U76's `Do` requires *"Decide
explicitly between (a) a `test-util`/dev binary or an `xtask`-shaped helper …
and (b) a real `show` field … **(a) is the lean and (b) must not be taken by
accident**"*. This does **not** need a planning round, because D73 already
constrained it in two places: §6 item 7 (*"it is a **tooling** question, not a
format one. D29's report is frozen and this record proposes no change to it"*)
and §7 item 2 (*"A small maintainer-side tool over the library accessor is
enough; a `show --json` field would also do but touches a stability surface
(D65) for a use case that is not a user's"*). Arm (a) is executable in lane.
**Arm (b) is not**: it moves D29's frozen table and lands a key in D65's tier, so
a lane that wants (b) stops and says *this is a decision*.

**One `Accept` row is not the executing lane's to discharge.** U76 `Accept`
row 4 is *"**Q35's entry** cites the route by name"* — an edit to `tasks/Q.md`.
D73 §7 item 1 states the constraint for its own lane in so many words
(*"(Registrar's edit, not this lane's — `tasks/` is outside the write scope.)"*)
and Q65's `Accept` row 5 carries the same note (*"armed by the orchestrator,
since the lane that resolved it may not edit `tasks/*.md`"*). So U76's row 4 must
be **armed in the ticking act**, not attempted by the lane. Flagged in §2 R6 so
the row is not reported "4 of 5 met" by a lane that had no route to the fifth.

### 1.7 Defect 3 exists on no authoritative surface at all

- `Q28` (`TODO.md:817`): `— after Q20–Q27 + U31/R25` — **no U32.**
- `U32` (`TODO.md:856`): `— after U1–U30` — **no Q28.**
- `tasks/Q.md:500`: `- Deps: Q20, Q21–Q27; U: final CLI strings (U31/U32); R: final page copy + footer (R23/R25)`
- `tasks/U.md:534`: `- Deps: U1–U30, U21, U31; Q: docs cross-check + release/CI gates (Q28/Q31); S/Q: clean-machine + disk-loss drill execution (Q32)`

The pair exists **only** across two `Deps` lines. Under rule 7 the `after` lists
are the authoritative build order, and they carry no edge in either direction.
There is nothing to strike.

**Applying the dependency test (§2 R10) in both directions returns "no" both
times.** Q28's three `Accept` rows are *"Lint green repo-wide including extracted
CLI/page strings"*, *"Exactly one canonical URL value found by grep across all
surfaces"* and *"Signed-off audit checklist committed; violations fixed before
Q34 release"*. The first needs U31's catalog and the Q20 lint — both landed. None
needs U32 `[x]`. U32's four `Accept` rows name exit-code and JSON schema docs, a
schema-freeze check, the hygiene harness, drill feedback and the `--help`
snapshot; none needs Q28 `[x]`. The staleness worry — that U32 later rewrites
copy Q28 signed off — is absorbed by **U32's own `Do`**, which already says
*"run the final positioning + secret-hygiene audits (U21/U31 extended over
M2/M3 surfaces: status, show, reveal, verify)"*.

So both mentions are consumer/interface references and rule 7's first clause
already prescribes the remedy: annotate. **Neither goes into an `after` list.**

**But U32 is not therefore available, and the register does not say why.** U1–U30
are **all `[x]`** (measured: the not-ticked set is empty), so U32's authoritative
run is fully satisfied and reads as unblocked. Wave 26's survey called it
*"dep-blocked on `Q28`/`Q31`/`Q32`/`U31`"* — a verdict taken from the `Deps`
line, i.e. from the non-authoritative surface, and correct in outcome for the
wrong reason. **Q32 is a true dependency by the test**: U32's `Accept` row 3
includes *"drill feedback items closed"*, and the drills are Q32's
(`Q32 — Script the M4 gate: Sepolia E2E + clean-machine procedure + disk-loss
drill`, `[ ]` at `:821`). Q32 is already named in U32's `Deps`; it is missing
from the authoritative list. §2 R8 promotes it — bookkeeping under rule 7, not a
new decision.

### 1.8 `after <continuous row>` is an idiom the register already reads correctly, and Q20's tick note wrote the reading down

Six rows carry `- Milestone: continuous`: **Q10, Q36, S20, P19, R28, U31**. In
1 393 edges, exactly **three** point at one of them:

```
U31 -> Q20  (Q20 is [x])
U31 -> Q28  (Q28 is [ ])
S20 -> S25
```

Four of the six continuous rows have **zero** successors. So the "defect" is
three edges out of 1 393, and one of the three has already been ticked through.

**Q20's tick note states the rule, at the tick.** `TODO.md:803`, ticked
2026-08-16, ends:

> *"Shared with **U31**, which stays open as the continuous conformance
> obligation; **Q28** owns the full-corpus audit"*

And its clause is `Positioning-copy style guide + repo-wide lint (**with U31**)
— after R18 + U31` — the same pair carries **both** `with U31` and `after U31` in
one line, and U31's own row carries `(with Q20)`. The shared deliverable landed
(`docs/positioning-copy-style.md`; `scripts/check-copy-style.py`, flagless run
exit 0, both `copy-style-selftest` and `copy-style` green in the gate); the
continuous obligation stayed open, as designed by rule 6.

**So `after <continuous>` is an edge to the lane's instrument, not to its
checkbox.** It can never be discharged by a `[x]` and was never meant to be. Q20
is the precedent that **legitimises** the idiom, not the exception that proves a
bug — the brief's alternative, confirmed. What is missing is not a fix but a
*statement*: the reading lives in one row's tick note and in nobody's rule.

**Q28's `U31` edge is therefore discharged, and has been since 2026-08-16.**

### 1.9 Defect 4's stated stake is false: Q22 decides Q28's reachability, not U31

Q28's run expands to `Q20, Q21, Q22, Q23, Q24, Q25, Q26, Q27, R25, U31`. States:
Q20 `[x]`, Q21 `[x]`, **Q22 `[ ]` (`TODO.md:811`)**, Q23 `[x]`, Q24 `[x]`,
Q25 `[x]`, Q26 `[x]`, Q27 `[x]`, R25 `[x]`, U31 `[ ]`-by-design-and-discharged.

Q28 is blocked by **Q22**, and D150 §1.8 established that Q22 *"cannot tick, on
its own `Accept` rather than on any edge"* — two of its four `Accept` rows are
verified by successors (row 2 by Q34, row 3 by Q28). Whether `after U31` is a
completion edge or a lane-green edge changes nothing about Q28.

### 1.10 The edge that genuinely cannot be satisfied is `Q254 after Q242`

Q242's `Accept` row 2 (`tasks/Q.md`, Q242): *"Private vulnerability reporting is
**enabled**, verified by the API returning enabled rather than 404, **in the same
window as the visibility change**."* D141 §2 R5(b) states the consequence:
*"`before Q65` is unsatisfiable by construction"*. Q242's row records the
mechanism: `PUT repos/aed900/antseal/private-vulnerability-reporting` returns
**404** because the feature is public-repository-only.

Q254's `Accept`, from D141 §2 R6: *"the checklist is committed **before** the
flip"*.

So `Q254 after Q242` requires a row that can only close **at or after** the flip
to be `[x]` before a row that must be complete **before** the flip. That is the
brief's *"one edge that can never be satisfied"* — correctly identified as a
class, misidentified as `Q28 after U31`. D141 §2 R6 had already written the right
word: `Q242 (with)`.

### 1.11 What three candidate checkers would actually yield

Measured over the working tree:

| candidate check | what it parses | findings today | of those, on open rows | true positives |
|---|---|---|---|---|
| **cycle scan** over `after` runs | `TODO.md` runs only | **4** | — | **0** (§1.1: four artefacts, four causes) |
| **`Deps` ⊆ `after`, else annotate** (rule 7 clause 1, mechanised) | `tasks/*.md` `Deps` + `TODO.md` runs | **290 rows / 573 ids** | 98 rows | unknown, and unreachable: it would need 573 annotations written before it could ever go green |
| **`Accept` names a transitive successor** (D150 §1.8's shape) | `tasks/*.md` `Accept` bullets + the `after` graph | **62** | **6** | 1 (`Q22 → Q28, Q34`, already found and already ruled by D150) |

The six open findings of the third check are `Q1 → Q4,Q5,Q7,Q9`;
`Q22 → Q28,Q34`; `Q28 → Q34`; `Q31 → Q244,Q255`; `R92 → R89`; `U32 → U78,U84`.
Most are benign — `Q28 → Q34` is a **deadline** (*"violations fixed before Q34
release"*), `U32 → U78,U84` is U32 **ratifying** two snapshots, which is a
consumer relation the wave-25 registrar wrote deliberately.

**And the one check with a tolerable yield still misses the defect that raised
the question.** Q65's `Accept` row 3 names a **file**
(`docs/ci-verification.md`), not a row id, so no id-matching check can see it.
Defect 1 is invisible to all three candidates; defects 2 and 4 are invisible to
all three; defect 3 is visible only to the 290-finding one.

---

## 2. Ruling

### R1 — D141 §2 R5's four `TODO.md` edits are EXECUTED NOW, verbatim as that record wrote them. **Who: the registrar.**

This re-decides nothing. It executes a resolved ruling on the surface it named.
Text for each row's ordering run; the rest of every row is untouched.

- `TODO.md` **Q243** (`:831`): `— after Q65, Q2` becomes
  `— after Q2 · **before Q65** (D141 §2 R5(a), executed 2026-08-19 by D154 §2 R1 — the edit was ruled 2026-08-18 and landed only in `tasks/Q.md:3009`)`
- `TODO.md` **Q244** (`:832`): `— after Q1, Q65, Q31` becomes
  `— after Q1 · **before Q65** (D141 §2 R5(c), executed 2026-08-19 by D154 §2 R1; the `Q31` term is re-homed onto Q31's own `Accept`, landed at `tasks/Q.md:547`)`
- `TODO.md` **Q242** (`:830`): `— after Q65, Q21/Q23, Q22` becomes
  `— after Q21/Q23,Q22 · **with/before Q65** (D141 §2 R5(b), executed 2026-08-19 by D154 §2 R1 — CO-TIMED, never `after`: `Accept` row 2 requires the API to read *enabled* in the same window as the visibility change, so `before Q65` is unsatisfiable by construction)`
- `TODO.md` **Q65** (`:825`): `— after Q22,Q28,Q27` becomes
  `— after Q22,Q28,Q27,Q243,Q244` *(D141 §2 R5(a)+(c) both order these two added; executed 2026-08-19 by D154 §2 R1. Both are `[x]`, so this changes no availability — it makes the order say what was ruled.)*
  **Q65 gains no `after` entry for Q242** — D141 §2 R5(b) forbids it explicitly; the co-timing is recorded on Q65's `Do` as an at-the-flip item.

**Verification, and it is not an exit code.** After the edits,
`grep -n 'before Q65\|with/before' TODO.md` must return **three** hits on the
Q242/Q243/Q244 rows and `grep -c '^- \[.\] \*\*Q6[45]\*\*'`-adjacent inspection
must show `Q243,Q244` present in Q65's run. Then re-run the §1.1 scan: the
2-cycle set must still be exactly the four artefact pairs, and **not** contain
any of `Q65`, `Q242`, `Q243`, `Q244`, `Q254`.

### R2 — Q254's `Q65` and `Q242` terms take D141 §2 R6's own timing words. **Who: the registrar.**

- `TODO.md` **Q254** (`:845`): `— after Q65,Q242,Q243,Q244` becomes
  `— after Q243,Q244 · **with Q65** · **with Q242**`
- `tasks/Q.md:3231`: `- Deps: after Q65 (the publish-scope decision this sequences), Q242, Q243, Q244; consumes D141 §2 R6` becomes:

  > `- Deps: after Q243, Q244; **with Q65**, **with Q242** — *(timing words restored 2026-08-19 by D154 §2 R1/R2 from D141 §2 R6's own prescription, which reads `Q65 (this row IS Q65's execution half), Q242 (with), Q243 (before), Q244 (before)`.)* **`Q65` is a partition, not a predecessor**: R6 gave it no timing word because this row IS Q65's execution half, and everything this row needs from Q65 already exists as a written record — Q65 finding 4, in Q65's own entry. **`Q242` is co-timed**: its `Accept` row 2 can only read true "in the same window as the visibility change", while this row's `Accept` is "the checklist is committed **before** the flip", so `after Q242` was an edge that could never be satisfied in the window this row needs. **Do not write `Q65 after Q254`** — measured 2026-08-19, it creates `Q65→Q254→Q65` plus three 3-cycles through Q242/Q243/Q244, each of which is recorded `after Q65`; this is D141's own `Q31→Q65→Q244→Q31` shape on a second pair. `~~after Q65~~`, `~~after Q242~~` — **STRUCK 2026-08-19 by D154 §2 R2**; consumes D141 §2 R6.`

**Effect: Q254 becomes available.** After R1 and R2 its run is `after Q243,Q244`,
both `[x]`. Its inputs exist: `SECURITY.md` (9 690 B) is landed, Q243 and Q244
are done, Q65 finding 4 is written, and D61 §9 is a record.

### R3 — Q65's `Accept` row 3 records which half is already discharged and which half Q254 writes. **Who: the registrar.**

`tasks/Q.md:978` keeps its text and gains a bracketed clause after it:

> **[D154 §2 R3, 2026-08-19 — this clause has two conjuncts with two different
> owners, and reading it as one is what produced an apparent deadlock with
> Q254.]** The **scrub-before-flip ordering** is already stated, measured
> 2026-08-19 at `docs/ci-verification.md:1191-1193` (*"which must be executed
> *before* the visibility change, never after"*) and `:1277`. The **ordered flip
> procedure** — which steps, in which order, each with the command that reads
> back its own result — is **Q254's deliverable**, in the same venue, and Q254 is
> **co-timed with this row** (`with Q65`, D154 §2 R2), not after it. This row
> ticks with Q254's checklist landing in the same act. **Do not write
> `Q65 after Q254`** to express it: measured, that creates a 2-cycle and three
> 3-cycles (D154 §1.2).

### R4 — U76's `Q35` edge is STRUCK on both surfaces and replaced with `before Q35's first submission`. **Who: the registrar.**

- `TODO.md` **U76** (`:859`): `— after U23/U28, D29, D65, D73 §4 R5, Q35` becomes
  `— after U23/U28, D29, D65, D73 §4 R5 · **before Q35's first submission** (D154 §2 R4)`
- `tasks/U.md:1074`: replace `Q35 (the row that cannot run its own instrument
  without it)` with:

  > `~~Q35 (the row that cannot run its own instrument without it)~~ — **STRUCK 2026-08-19 by D154 §2 R4.** The gloss was a **consumer** description filed under `after`, and the edge was **inverted against the record that minted this row**: D73 §7 item 2 orders the tool *"M4, **before Q35's first submission**"*. The correct form is `before Q35's first submission` (the `before X's <sub-part>` idiom already in the tracker at `TODO.md:414`, `U38 — after U1; before U11's wizard half`). **Do not write `Q35 after U76` either** — it would be the mirror-image edge D150 §2 R1 forbids, and it is wrong on the merits: Q35's two `Accept` rows are the committed plan and a scheduled first outreach batch, and D73 §7 items 2 and 6 scope the precondition to Q35's *first submission* and to *declaring the count met*, both of which are post-tick continuous execution. `R5` also appears in a naive parse of this run — it is the citation `D73 §4 R5`, not an edge; do not "fix" it.`

**Effect: U76 becomes available.** U23, U28, D29, D65, D73 are all `[x]`.

### R5 — Q35's two "blocked in fact" statements are NARROWED to what D73 blocks, not deleted. **Who: the registrar.**

The finding is right and the scope is not. Both sites keep their measurement and
gain the scoping sentence.

- `TODO.md` **Q35** (`:824`): `**Blocked in fact, not only in `after:`**` becomes
  `**A real precondition, and it binds the metric rather than this row's `Accept`** *(narrowed 2026-08-19 by D154 §2 R5)*`
- `tasks/Q.md:619`, appended to that Notes block:

  > **[D154 §2 R5, 2026-08-19 — narrowed, not withdrawn.]** What U76 blocks is
  > **Q35's first submission** (D73 §7 item 2) and **declaring the count met**
  > (D73 §7 item 6, *"a concrete pre-condition of declaring the count met"*),
  > not this row's `Accept`. Both `Accept` rows — the committed plan and tracking
  > artifact, and a **scheduled** first outreach batch — are satisfiable with
  > X2 never yet run, and D73 §7 item 7 asks for the file to be created **now**
  > with every number at zero (*"the first thing this ruling owes is its own
  > instrument"*). The X7 planted-fault record is a **header field** of
  > `docs/success-metric.md` that is filled when the run happens (D73 §4 R5), not
  > a precondition of creating the file. `U76` is therefore recorded on U76's own
  > row as `before Q35's first submission` and **not** as `Q35 after U76`.

### R6 — U76's `Accept` row 4 is flagged as a registrar-executed clause. **Who: the registrar.**

Append to `tasks/U.md` U76's Notes:

> **[D154 §2 R6, 2026-08-19.]** `Accept` row 4 — *"Q35's entry cites the route by
> name"* — is an edit to `tasks/Q.md`, which the executing lane may not make;
> D73 §7 item 1 states the constraint for its own lane (*"Registrar's edit, not
> this lane's — `tasks/` is outside the write scope"*) and Q65's `Accept` row 5
> carries the same note. It is **armed in the ticking act**, like D61 §9's
> clause. A lane reporting "four of five met" has not failed row 4; it had no
> route to it. Separately, the `Do`'s (a)/(b) choice needs **no planning round
> for arm (a)** — D73 §6 item 7 already ruled it *"a **tooling** question, not a
> format one"* with D29 frozen — but **arm (b) is a decision**: it moves D29's
> frozen `show` table and lands a key in D65's tier, so a lane that wants (b)
> stops and says so.

### R7 — Q28 ↔ U32: both `Deps` mentions are annotated; **no `after` edge is written in either direction**. **Who: the registrar.**

There is nothing to strike — neither `after` list carries the pair (§1.7). Rule 7
clause 1 is applied to both `Deps` lines.

- `tasks/Q.md:500`: `- Deps: Q20, Q21–Q27; U: final CLI strings (U31/U32); R: final page copy + footer (R23/R25)` becomes:

  > `- Deps: Q20, Q21–Q27; U: the extracted string catalog and its lint (**U31** — a true predecessor, discharged, see D154 §2 R9), **U32 (interface, not a dep — D154 §2 R7)**; R: final page copy + footer (R23/R25). **U32 is named here as the surface this row's audit should stay true against, not as a predecessor**: none of this row's three `Accept` rows needs U32 `[x]`, and the staleness U32 could introduce is absorbed by U32's own `Do`, which re-runs the positioning and hygiene audits over every surface it changes. Measured 2026-08-19: neither this row's `after` list nor U32's carries the other, so the apparent 2-cycle existed only across two `Deps` lines and on no authoritative surface. **Do not write `Q28 after U32` or `U32 after Q28`.**`

- `tasks/U.md:534`: replace `Q: docs cross-check + release/CI gates (Q28/Q31)` with:

  > `Q: **Q28 (consumer, not a dep — D154 §2 R7)** — Q28 consumes this row's frozen strings; nothing in this row's `Accept` needs Q28 `[x]`, and listing a consumer here is what rule 7 clause 1 forbids. Q31 (release/CI gates — see D154 §4, routed). **This annotation does not make this row available**: its true remaining predecessor is **Q32**, promoted into the authoritative `after` list by D154 §2 R8.`

### R8 — U32's already-recorded `Q32` term is promoted into the authoritative `after` list. **Who: the registrar.**

Bookkeeping under rule 7, not a new decision: `Q32` is already in U32's `Deps`
(`tasks/U.md:534`, *"S/Q: clean-machine + disk-loss drill execution (Q32)"*), it
passes the dependency test — U32's `Accept` row 3 contains *"drill feedback items
closed"* and the drills are Q32's — and it is absent from the authoritative
surface.

- `TODO.md` **U32** (`:856`): `— after U1–U30` becomes
  `— after U1–U30, **Q32** (D154 §2 R8 — already in this row's `Deps`; promoted to the authoritative list because `Accept` row 3's *"drill feedback items closed"* cannot be written before the drills run)`

Measured: `Q32`'s own run is `Q22,Q30,Q31 + P17,S19,U12,R26,A25` and does not
contain `U32`, so this creates no cycle. **U1–U30 are all `[x]`; without this
edge U32 reads as available and is not.**

### R9 — Q28's `U31` edge STANDS, with its discharge written into the row. **Who: the registrar.**

No strike, no inversion, no consumer annotation. The edge is well formed and was
satisfied on 2026-08-16.

- `TODO.md` **Q28** (`:817`), appended to the row:
  `· **[D154 §2 R9, 2026-08-19: the `U31` term is DISCHARGED, not unsatisfiable.]** `after <continuous row>` is an edge to the lane's **instrument**, not to its checkbox — a `Milestone: continuous` row never ticks by design (rule 6) and was never meant to. U31's shared deliverable landed with **Q20** on 2026-08-16 (`docs/positioning-copy-style.md`; `scripts/check-copy-style.py`, flagless run exit 0), and Q20's own tick note states the reading: *"Shared with **U31**, which stays open as the continuous conformance obligation; **Q28** owns the full-corpus audit"*. **This row's live blocker is `Q22`** (`[ ]`), which D150 §1.8 shows cannot tick on its own `Accept`; the `U31` term decides nothing about this row's reachability.`

### R10 — The rule that distinguishes the four surfaces, and rule 7 gains one sentence. **Who: the registrar** (rule 7 text and the ledger line).

**Four surfaces carry ordering information, and only one of them is an edge.**

| surface | what it is | force |
|---|---|---|
| the `TODO.md` checkbox ordering run (`after` / `with` / `before`) | the authoritative build order (rule 7) | binding; the only surface a graph parse sees |
| a `tasks/*.md` `- Deps:` line | true predecessors **plus** annotated consumer/interface mentions (rule 7 clause 1) | detail; loses to the checkbox run on disagreement |
| an `- Accept:` clause naming another row, venue or artifact | a **tickability** condition | binding on the row's own tick, and **invisible to every ordering surface** (D150 §1.8) |
| Notes prose (*"blocked in fact"*, *"consumer"*, *"this row IS X's execution half"*) | narrative | **never** an edge |

**The test. Apply it in one direction at a time, and name a clause or drop the
claim.**

> **Name the clause of X's `Accept` that cannot be written until Y is `[x]`.**
>
> 1. **You can name one → dependency.** It belongs in X's `after` run **and** in
>    X's `Deps` line, and nowhere else.
> 2. **You cannot, and instead Y reads or edits X's output, or Y's own procedure
>    acts on X's file → consumer.** Notes, or an explicit *"consumer, not a dep"*
>    annotation. **Never** an `after` edge in either direction — writing the
>    reverse to "fix" it is how the mirror-image cycle gets written
>    (D150 §2 R1).
> 3. **The clause you named is in X's own `Accept` and it names Y as its verifier
>    or venue → not an ordering edge at all.** X cannot tick without Y and no
>    `after` edge can say so. Three instruments exist and all three are already
>    in the tree: **re-home** the clause onto Y's `Accept` (D141 §2 R5(c)),
>    **narrow** it in writing (D141 §2 R4), or **co-time** the pair with `with`
>    (D141 §2 R5(b), D154 §2 R2). **Do not invert an `after` edge to express it.**
> 4. **Both must land in one wave but neither's `Accept` needs the other `[x]`
>    → co-timing, `with`.** It is inside rule 7's vocabulary and **invisible to
>    any `after`-only parse**, so it must be written in both rows' Notes as well
>    as in the run.

**Two corollaries, one per defect class this record found:**

- **A parenthetical in a decision record's `Deps:` prescription is a timing word,
  and a term with no timing word is not `after`.** D141 §2 R6 wrote
  `Q65 (this row IS Q65's execution half), Q242 (with), Q243 (before),
  Q244 (before)`; both terms whose word was not a precedence became `after`
  (§1.4). Registrars: transcribe the word; where a term has none, it is a
  partition or an identity statement — ask before writing `after`.
- **An edge to a `Milestone: continuous` row targets the lane's instrument, not
  its checkbox.** It is discharged when the shared deliverable lands and green;
  it can never be discharged by a `[x]`. Three such edges exist (§1.8); Q20 has
  already been ticked through one.

**Rule 7 gains one sentence**, after *"Read the lists as authoritative and as
**unverified**"*:

> **[D154 §2 R10, 2026-08-19]** Four surfaces carry ordering information and only
> the runs here are edges: a `tasks/*.md` `Deps` line is detail, an `Accept`
> clause naming another row as its **verifier or venue** is a *tickability*
> condition that no `after` edge can express (D150 §1.8), and Notes prose is
> never an edge. The test for an edge is: **name the clause of X's `Accept` that
> cannot be written until Y is `[x]`** — if you cannot, it is a consumer or a
> co-timing, and the fix is an annotation or `with`, **never an inverted
> `after`**. An `after` term naming a `Milestone: continuous` row points at that
> lane's **instrument**, not at a checkbox that by design never ticks; it is
> discharged when the instrument lands and is green (precedent: `Q20`, ticked
> 2026-08-16 through `after U31`, with the reading recorded in its own tick
> note).

### R11 — No cycle checker is minted. No row. One ledger line. **Who: the registrar.**

Rule 8 governs and the promotion test is not met: nothing in this record was
blocked by the absence of a checker — all four defects were found by reading, and
the general rule is now written down. **D141 §2 R7 already refused to mint one a
wave ago**; this record finds three further reasons and does not reverse it.

**Refused, with the measurement (§1.11):**

1. **A cycle scan over `after` runs** — today it reports **four** findings and
   **all four are false positives**, from four different causes, one of them
   being `U13(interface)`, the token rule 7 names as its own example of a
   mention *"excused only by reading, not by a checker"*. Precision 0/4, recall
   0/4 against the four defects in front of us. A checker whose entire current
   yield is noise is a checker that trains readers to ignore it.
2. **`Deps` ⊆ `after`, else annotate** — **290 rows / 573 ids** on day one
   (98 rows open). It would need 573 annotations written before it could ever go
   green: D144's unsatisfiable-`Accept` class, in a lint.
3. **`Accept` names a transitive successor** (D150 §1.8's shape) — **62**
   findings, **6** on open rows, of which **1** is real and already ruled. And it
   **misses defect 1**, because Q65's `Accept` row 3 names a *file*, not a row id.

**Ledger line** (`docs/instrument-ledger.md`, house format):

> `2026-08-19 · D154's lane (wave 27) · **The tracker's only proposed ordering checker reports four cycles today and all four are parser artefacts — a decision id (`D-A8`), an inline consumer annotation (`(R11 consumes)`), rule 7's own example token (`U13(interface)`) and a prose sentence beginning "— after".** Measured over 838 rows / 1 393 `after` edges. Two further candidates were measured and refused: `Deps ⊆ after` yields **290 rows / 573 ids** on day one, and `Accept`-names-a-successor yields **62** (6 open, 1 real) and still misses the defect that raised the question, because Q65's `Accept` row 3 names a **file** rather than a row id. **No checker is minted; D141 §2 R7's refusal stands.** Separately measured and repaired by D154 §2 R1: **D141 §2 R5's four `TODO.md` edits were never executed** — the same corrections landed in `tasks/Q.md:2994/3009/3024` — so `Q243` and `Q244` are both `[x]` while the authoritative order records them `after` an open `Q65` · TODO.md rule 7 · D141 §2 R5/R7 · D154`

### R12 — What stops a later reader restoring the struck edges, and the mirror-cycle check. **Who: the registrar** (the annotations are already specified above).

**Every strike in this record uses D150 §2 R1's instrument**: the term is left
visible under `~~strike-through~~` with a dated citation, and the Notes carry an
explicit *"do not write the reverse either"* sentence naming the measured
consequence. A term that is deleted invites re-derivation; a term that is struck
in place with its reason attached does not.

**Mirror-cycle check, run explicitly, one strike at a time:**

| struck | reverse edge | would it be a cycle? | written? |
|---|---|---|---|
| `Q254 after Q65` | `Q65 after Q254` | **yes** — 1× 2-cycle + 3× 3-cycle via Q242/Q243/Q244 (§1.2) | **forbidden**, in Q254's `Deps` and Q65's `Accept` row 3 |
| `Q254 after Q242` | `Q242 after Q254` | no, but wrong: Q242 closes only at the flip | not written; `with Q242` instead |
| `U76 after Q35` | `Q35 after U76` | no (after the strike), but wrong on the merits — D73 scopes the precondition to Q35's first submission (§1.5) | **forbidden**, in U76's `Deps` |
| `Q242/Q243/Q244 after Q65` | `Q65 after Q243,Q244` | **no** — and it is exactly what D141 §2 R5 ordered; landed by R1 | **written** |
| Q28 ↔ U32 | — | nothing struck; no edge existed | both directions forbidden in both `Deps` lines |

**Whole-graph re-measurement with every edit in this record applied**, on a
scratch copy: **838 rows, 1 388 edges** (−7 removed, +2 added — arithmetic
reconciles exactly), **four 2-cycles, the same four artefact pairs**. No ruling
in this record creates a cycle of any length.

---

## 3. What was refused and why

1. **Refused: "all four are cycles, strike the backwards edge in each."** A cycle
   needs two edges and none of the four has two. Three of the four are collisions
   between the authoritative order and **three different** non-authoritative
   surfaces — an `Accept` clause (defect 1), Notes prose (defect 2), two `Deps`
   lines (defect 3) — and the fourth is a single well-formed edge (defect 4).
   Treating them uniformly is what produced the deadlock reading in the first
   place.
2. **Refused: inverting Q254's `Q65` edge.** Measured to create one 2-cycle and
   three 3-cycles (§1.2). The lean's own instrument would have written the very
   defect it was assembled to remove — D141's `Q31→Q65→Q244→Q31` result,
   reproduced on a second pair.
3. **Refused: `Q35 after U76`.** It is not a cycle after the strike, so it *looks*
   safe; it is wrong on the merits. D73 §7 items 2 and 6 scope the precondition
   to Q35's **first submission** and to **declaring the count met**, and neither
   of Q35's two `Accept` rows needs X2 to have fired (§1.5). Writing it would
   block an M4 plan deliverable on a post-release instrument.
4. **Refused: treating `after U31` as a defect.** Three such edges exist in
   1 393; four of the six continuous rows have zero successors; Q20 has already
   been ticked through one and **wrote the reading down in its own tick note**.
   The brief's alternative is right: Q20 legitimises the idiom. What was missing
   is a statement of it, and R10 supplies it.
5. **Refused: any of the three checkers**, on measured yield (§1.11, §2 R11), and
   because rule 8's promotion test — *"blocks an acceptance on the ship path"* —
   is not met by anything in this record.
6. **Refused: minting any row.** Every repair here is an edit to an existing row's
   ordering, `Deps` or Notes, plus one rule-7 sentence and one ledger line. No
   finding here changes what a user's seal or verify does.
7. **Refused: rewriting Q35's and U76's "blocked in fact" prose out of the
   register.** The measurement behind it is correct and hard-won (no shipped
   binary prints `pubkeys`); only its scope was wrong. R5 narrows both sites and
   keeps the finding.
8. **Refused: silently correcting the brief's two stale locators.** `TODO.md:845`
   is Q257 in the tree as measured, and the four "2-cycles" are four different
   artefacts. Both are recorded in §1 rather than fixed in passing — counts in
   this project have drifted four times, once inside the sentence promising they
   had not.

---

## 4. Routed, not ruled

1. **`Q34` does not name `U32` in its `after` run.** Measured: `Q34 — after
   Q13,Q21,Q28,Q31–Q33,**Q65**`. The M4 ship gate does not list the CLI release
   freeze as a predecessor, and neither does `Q32`. Whether that is deliberate
   (U32 freezes *for* the release Q34 ships, i.e. a consumer relation) or an
   omission of the §2 R10 kind is a question this record measured and did not
   rule — it is outside the four pairs it was given. **Next planning round.**
2. **`U32 after Q31`.** U32's `Deps` names Q31 and its `Accept` row 1 reads
   *"exit-code and JSON schema docs **shipped with the release**"*, which is
   Q31's workflow. Unlike `Q32` (§2 R8), this does not pass the test cleanly —
   the docs can exist before the workflow ships them — so it is **not** promoted
   here. **Next planning round.**
3. **`Q254 after Q243, Q244` may be over-strict for the same reason `after Q65`
   was.** D141 §2 R6's `Do` lists Q243 and Q244 as *items inside the checklist*
   (*"Q243 landed; Q244's pins landed … **then** the flip"*), and a checklist can
   name a step before the step runs. Both are `[x]`, so nothing is blocked today
   and this record leaves the terms standing rather than widening its own scope.
   Recorded so a later reader knows it was seen.
4. **The register currently shows two ticked rows behind an open predecessor**
   (`Q243`, `Q244` after `Q65`). §2 R1 repairs it. If any *other* ticked row sits
   behind an open predecessor, nothing has looked — a whole-tracker sweep of that
   invariant is one line of the §1.1 parser and was **not** run for this record,
   because it is a different question from the one asked. **Worth one wave's
   attention; it is instrument-class and takes no row.**
5. **Q35's own run is `after Q22,Q34`** while its `Accept` row 1 requires the
   plan *"committed **pre-release**"* and Q34 is the row that **ships** the
   release. The row is split-natured (its Notes say *"Execution is
   post-release/continuous; the plan is the M4 deliverable"*) and the `after Q34`
   term fits the run half while contradicting the plan half. Not ruled: it is a
   fifth pair, not one of the four, and it needs D73 §4 R8 read alongside it.

---

## 5. Registrar's edit set

Twelve edits, five files, no source, no row, no id. Every target is given as
**row id + exact old string** as well as a line number, because four files are
modified-uncommitted and locators may drift under another lane.

**`TODO.md`**

1. **Q65** (`:825`) — in the ordering run, `— after Q22,Q28,Q27` → `— after Q22,Q28,Q27,Q243,Q244`, per §2 R1.
2. **Q242** (`:830`) — `— after Q65, Q21/Q23, Q22` → the `with/before Q65` form in §2 R1.
3. **Q243** (`:831`) — `— after Q65, Q2` → the `before Q65` form in §2 R1.
4. **Q244** (`:832`) — `— after Q1, Q65, Q31` → the `before Q65` form in §2 R1.
5. **Q254** (`:845`) — `— after Q65,Q242,Q243,Q244` → `— after Q243,Q244 · **with Q65** · **with Q242**`, per §2 R2.
6. **U76** (`:859`) — `— after U23/U28, D29, D65, D73 §4 R5, Q35` → `— after U23/U28, D29, D65, D73 §4 R5 · **before Q35's first submission** (D154 §2 R4)`, per §2 R4.
7. **U32** (`:856`) — `— after U1–U30` → the form in §2 R8 adding `Q32`.
8. **Q35** (`:824`) — the phrase `**Blocked in fact, not only in `after:`**` → the narrowed phrase in §2 R5.
9. **Q28** (`:817`) — append the §2 R9 discharge clause.
10. **rule 7** (`:36`) — append the §2 R10 sentence after *"Read the lists as authoritative and as **unverified**"*.

**`tasks/Q.md`** — Q254's `Deps` (`:3231`, §2 R2); Q65's `Accept` row 3
(`:978`, §2 R3); Q35's Notes block (`:619`, §2 R5); Q28's `Deps` (`:500`, §2 R7).

**`tasks/U.md`** — U76's `Deps` (`:1074`, §2 R4) and Notes (§2 R6); U32's `Deps`
(`:534`, §2 R7).

**`docs/instrument-ledger.md`** — the §2 R11 line.

**`docs/decisions/README.md`** and the decision register — one index row and one
register row for **D154**, in the same commit that lands this file, per rule 3 as
amended by D142 §2 R4 (an id gets one of its three homes in the allocating
commit).

**Post-edit verification, and none of it is an exit code.**

- `grep -n 'before Q65\|with/before' TODO.md` → **three** hits, on the Q242, Q243 and Q244 rows.
- `grep -n '^- \[.\] \*\*Q254\*\*' TODO.md` → no live `Q65` and no live `Q242` in the ordering run; both struck terms visible in `tasks/Q.md:3231`.
- `grep -n '^- \[.\] \*\*U76\*\*' TODO.md` → no live `Q35` in the ordering run.
- Re-run the §1.1 parse: expect **838 rows, 1 388 edges, four 2-cycles**, and the pair set must be exactly `('A5','A8')`, `('R11','S15')`, `('R89','R92')`, `('U13','U14')`. **Any fifth pair is a red**, and the plant in §1.1 shows the scan can produce one.
- `python3 scripts/check-traceability.py` (**flagless — that IS the check; the script has no `--check` flag**) → 8 of 8 ok, including `[decisions]` and `[decision-owners]`, which stay green only if D154's index row and register row land in the same act as this file.

**Availability delta this record produces, stated plainly so the next readiness
survey does not re-derive it:** **`Q254` and `U76` become available**;
**`Q28` does not** (blocked by `Q22`); **`U32` does not** (blocked by `Q32`,
newly written into its run — before §2 R8 it read as available and was not).
