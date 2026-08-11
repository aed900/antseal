# D107 — Q126: what the F4 registry's §6 changelog is for, and why it has never recorded anything

- **Status: RESOLVED — §6 STAYS, its obligation MOVES OFF "lowering" and onto
  *any change to a limit's recorded value*, and Q126 is amended in both its
  premise and its Accept.** The register's lean — **(b) delete §6 and move the
  lowering note into the `lowered` cell** — is **refused**, and recon's fastest
  dismissal, (c) *keep §6 and make its obligation testable*, is **refused too**,
  on a ground recon never reached. Neither side measured the thing that decides
  it: **§6's obligation is attached to the branch F4 makes nearly impossible and
  is absent from the branch F4 makes routine.** A lowering is a format-version
  event whose window D104 §2.1 closes at first release and whose only proposed
  exercise D104 §3 rules **empty**; a raise is *"always available and never
  expires"* (D104 §10) with 16 384 of measured headroom. §6 is obliged to record
  the first and forbidden to record the second. That is why its positive arm is
  empty: **it is aimed at the wrong branch**, and both (b) and (c) argue about
  how hard to enforce an aim that is wrong. **And the branch that will actually
  happen has a written procedure that is already broken against a committed
  test**: §5's *"a raise is recorded by appending the new value and its date to
  the `initial value` cell"*, executed literally, makes
  `ots_limits_match_the_f4_registry` (`limits.rs:264-278`) go red — its needle
  is `| \`{name}\` | A11 | {value} |`, a row prefix that requires the value cell
  to hold one bare value and nothing else. Nobody has noticed because no raise
  has happened. **Q126's own premise is false**: zero of the eight
  document-changing commits owed a §6 entry — all eight `lowered` cells read
  `never` and no diff has ever written anything else — so the *"100 % miss
  rate"* measures misses against an obligation of **zero**. **And Q126's Accept
  clause 2 is met on arrival and always was**: *"has this ever been lowered?"*
  is answered by eight cells in one table, at a glance, with no diff at all, and
  seven of the eight rows are pinned to their constants by name, owner and
  value. §6 was never the answer to that question; it carries only the *why*.
- **Date: 2026-08-09** (M2 wave 10 planning round; briefed with a lean toward
  deleting §6, and §6 is kept)
- **Owning tasks: Q126** (the ruling; closed by it), **A27** (the document and
  its Update rule), **A11** (the seven rows and the cross-check), **A42** (the
  eighth row, which §8 measures is pinned by nothing)
- **Amends**: **`tasks/Q.md` Q126** — its Problem statement (the miss rate is
  against an obligation of zero), its `Do` (the disjunction is resolved, and
  neither arm as written is the ruling) and its **Accept** (clause 2 is met on
  arrival; clause 1's *"owes"* is given a definition); **`TODO.md:555`**, which
  carries the same false premise; **`docs/format/anchor-artifact-limits.md`
  §5's Update rule** (`:331-338`) and **§6** (`:343-351`);
  **`docs/decisions/D104-max-ots-depth-lowering-window.md:462`**, whose
  suggested repair — *"deleting §6 and moving the lowering note into the
  `lowered` cell itself"* — is refused by §2(b), and **`:467-469`**, whose
  conditioning clause on the open lowering window is **discharged**.
  **Supersedes**: nothing. **Binds against**: D84 F4, D102 §5/§5a, D104 §2/§3/§5/§10,
  A27's Update rule, Q14, Q27, Q64, Q125.

---

## The problem, in one sentence

Q126 says the F4 registry's §6 changelog has a 100 % miss rate across seven
commits; measured, it has a 100 % miss rate against an obligation that has
never once been incurred, and the obligation it does carry is pointed at the
one event F4 makes nearly impossible.

---

## 1. What was measured

Read from the tree at `a68d9ea`. No `cargo` command was run (§7); the ruling
rests on the document's own text, on `git log`, and on reading two committed
test needles.

### 1.1 The obligation has never fired, so the miss rate is against zero

`git log --oneline 1620543..HEAD -- docs/format/anchor-artifact-limits.md`
returns **seven** commits (`6f69e1a`, `5f758de`, `a053272`, `49df1e9`,
`ead5db6`, `63640a0`, `3d47363`), eight counting `1620543`'s creation. Against
those, the §5 Update rule (`:331-338`) charges a §6 entry on **one trigger
only**:

> *"`lowered` starts at `never` and is the only cell that may change; changing
> it away from `never` is a **format-version event** requiring the full freeze
> procedure (Q27, mirroring Q14) and **a dated note in §6 saying which release
> lowered it and why**. A raise is recorded by appending the new value and its
> date to the `initial value` cell…"*

A raise goes to the `initial value` cell, **explicitly not to §6**. Row
addition carries no §6 duty at all. So the only §6 obligation is a lowering.

Measured, over the whole history of the file: **all eight `lowered` cells read
`never`** (eight `| never |` occurrences against eight §5 rows), and
`git log -p --follow` over the file produces **no added or removed line that
writes anything else into that column** — the only `lowered`-bearing diff lines
are the rule text itself, the table header, and F4's own prose. **Zero of the
eight commits owed a §6 entry.**

Q126's *"it has never been used"* is true and **its inference is not**: a
section that has never been used because its trigger has never fired is not a
section with a miss rate. It is an unused notebook. §5 of D104 said *"worse than
an omission"*; on this measurement it is not an omission at all.

### 1.2 Q126's Accept clause 2 is met on arrival, and §6 was never its answer

Q126's Accept (`tasks/Q.md:1543`) ends: *"either way the question 'has this ever
been lowered?' is answerable without reading seven diffs."*

It already is, and always has been. The `lowered` column is in the same table as
the values, eight cells, all reading `never`. Reading it costs one glance and
zero diffs. And it is not merely prose: `ots_limits_match_the_f4_registry`
(`limits.rs:264-278`) asserts, for each of the seven A11 constants, that §5
contains the literal row prefix `| \`{name}\` | A11 | {value} |`, so a constant
that moved without its row moving is a red test. The table cannot have silently
drifted from the code.

**What §6 carries that no cell carries is the *why*.** That is a real thing and
it is the reason §6 survives §2(b) — but it is not what Accept clause 2 asks
for, and clause 2 required no work on the day it was written.

### 1.3 The Update rule contradicts itself, and has been falsified three ways

Within one sentence pair at `:334-336`:

> *"`lowered` … **is the only cell that may change**"* … *"A raise is recorded
> by **appending** the new value and its date to the **`initial value` cell**."*

The second clause is a change to a cell the first clause says may not change.
And the tree has falsified the first clause twice more since:

| falsifier | where |
| --- | --- |
| D102 added an entire **eighth column**, `structural cost`, to every row | `:219`, `:276-330` |
| **D104 §4** rules that A48 rewrites the `MAX_OTS_DEPTH` row's `measured against` **and** `margin` cells | `D104…md:409-427`; row at `:222` |

This matters directly to the lean: recon's (b) is a proposal about the grammar
of the `lowered` cell, and the sentence that governs that cell has been wrong
since the day after it was written.

### 1.4 The obligation is on the branch F4 makes rarest and off the branch it makes routine

This is the finding that decides D107, and neither the brief nor recon reached
it.

| branch | F4's treatment | expected occurrence | §6 duty today |
| --- | --- | --- | --- |
| **lowering** | format-version event; window closes at first release (**D104 §2.1**); the only proposed exercise is **empty**, not declined — every admissible cap costs identical bytes (**D104 §3.1-§3.4**) | ≈ 0 | **required** |
| **raise** | *"always available under F4 and **never expires**"* (**D104 §10**); measured headroom 4 096 green, 16 384 green (`limits.rs:195-197`, D102 §3.2) | the expected case | **forbidden** — routed to the `initial value` cell instead |

So: §6 is obliged to record an event that will probably never occur, and is
told **not** to record the event F4 exists to permit. **That is the whole
explanation of the empty positive arm**, and it is the thing both options in
Q126's `Do` argue past. (b) deletes the section because the aim is empty. (c)
enforces the aim harder. Neither moves the aim.

### 1.5 The raise procedure, executed literally, breaks a committed test

`ots_limits_match_the_f4_registry` builds its needle as
`format!("| \`{name}\` | A11 | {} |", format_underscored(*value))`
(`limits.rs:268`), i.e. **`| \`MAX_OTS_OPS\` | A11 | 4_096 |`** — a `contains`
over cells 0-2 that requires the value cell to hold **one bare value and a
closing pipe**.

Now execute §5's raise procedure on `MAX_OTS_OPS`: *"appending the new value and
its date to the `initial value` cell"* gives a cell reading, say,
`4_096 (2026-08-02), 8_192 (2026-09-01)`. The needle for the new constant,
`| \`MAX_OTS_OPS\` | A11 | 8_192 |`, is **not present** — no `|` follows
`8_192`. The needle for the old constant is absent too. The test goes red, and
its message (*"the constant and its F4 registry row have drifted"*) names a
cause that is false: nothing drifted; the document told the lane to write a cell
shape the pin cannot read.

**The one procedure F4 expects anyone to use is broken against the one test that
pins this table to the code, and it is invisible because nobody has used it.**
That is a sharper defect than the one Q126 names, it lives in the same paragraph,
and it is fixed in the same edit (R2).

### 1.6 What is editable, and what nothing reaches

| fact | where |
| --- | --- |
| `anchor-artifact-limits.md` is **not** frozen — the freeze policy's `required_name_prefix` is `registry-v`, and the doc comment excludes this file **by name** as *"about the format, not the format"* | `crates/antseal-core/tests/format_freeze.rs:65-74` |
| §1 and §2 **are** pinned byte-for-byte across three files by `check-traceability.py --freeze-boundary` | `scripts/check-traceability.py:47-63`; markers at `anchor-artifact-limits.md:115` and `:149` |
| **§5 and §6 sit outside those markers** (`:212` and `:343`), so nothing in this record's edit set is a freeze-boundary event | computed from the marker positions |
| Two needles reach the file from code, both `contains`, both `include_str!`: the row-prefix pin and the structural-cost pin | `limits.rs:265`, `:297` |
| **No needle touches §6**; the row-prefix needle constrains **cells 0-2 only**, so cells 3-7 are unconstrained prose | read at `limits.rs:268`, `:299-323` |
| A §5 cell can already carry a paragraph — `MAX_OTS_CALENDAR_RESPONSE_BYTES`'s `measured against` cell is ~60 words | `:228` |

---

## 2. The options, and what kills each

### (a) Write the seven retrospective entries — refused, and recorded so it stays refused

Q126's own `Do` (`tasks/Q.md:1542`) and D104 §5 both forbid it: *"a changelog
composed by lanes that did not make the edits is fabricated provenance."*
Unchanged here. §1.1 adds a second reason: **six of the seven commits changed no
limit's value at all**, so retrospective entries would record editorial edits in
a section whose whole subject is limit values.

### (b) Delete §6 and move the lowering note into the `lowered` cell — the lean. Four kills.

**K1 — the analogy is misapplied, and the tree's own answer to it is the
opposite one.** Q125's and Q128's anti-pattern is *a checker that cannot go
red*: a lane reports `PASS`, a reader infers coverage, and there is none. The
harm is **false assurance from a green signal**. §6 emits no signal. No lane
reads it, it asserts nothing, and it cannot be green. Deleting a *place to
write* because nothing has been written there is not the act Q125 performed —
and what Q125 actually did with a guard whose positive arm was empty was
**supply the arm**: `wasm32-tests --self-test` plants change-sets in both
directions, *"the positive arm pinned to `anchor/caps.rs` **by name**"*
(`tasks/Q.md`, Q125's DONE note). The precedent recon cites rules against recon.

**K2 — it destroys auditability for the branch that will happen and preserves it
for the branch that will not.** A `lowered` cell is written **only by a
lowering**. So under (b), the day `MAX_OTS_OPS` is raised — the event D104 §10
calls always-available and never-expiring — there is no cell that can carry
*why*, because the raise never touches `lowered`, and the section that could
have has been deleted. (b) optimises the registry for the event §1.4 measures
at ≈ 0.

**K3 — the grammar is available and it does not help.** Answering the brief's
question directly, so nobody re-derives it: a `lowered` cell **can** truthfully
carry date + release + reason. Cells 3-7 are unconstrained (§1.6), the document
already carries a 60-word cell (`:228`), and the only mechanical limit is that
the text must contain no `|`. A working grammar would be
`` `2026-09-01` · v0.4.0 · <one clause of reason> ``. **The option still fails
on K2**, which is not about whether the cell can hold the words.

**K4 — it dangles a ratified record, for zero measured benefit.** Deleting §6
strands **D104:302** (*"§6 owes a dated note"*, inside §2.2's cost list),
**:454**, **:462**, **:467-469**, **:533** and D104's Index row at **:645**, plus
`TODO.md:555` and `tasks/Q.md:1541-1544`. Each is an amendment a wave owner must
apply by hand, and what is bought is the removal of nine lines that cost nothing
to keep.

### (c) Keep §6, enforce the lowering obligation, planted change-set for the positive arm — refused, and NOT for vacuity

The brief is right that this is not vacuous: a planted fixture supplies the
positive arm, exactly as Q125's self-test does, and *"an instrument with a
planted change-set is not a guard with an empty positive arm"* is a correct
sentence. Recon dismissed it too fast and for the wrong reason.

**It fails on aim, not on vacuity.** It buys a table parser, a fixture pair and
a place in the gate, in order to enforce a duty that §1.4 measures will
plausibly never be discharged — while leaving §1.5's broken raise procedure and
the unrecordable raise-reason exactly where they are. An instrument whose only
lifetime exerciser is its own fixture is a test of the test, and this project
has a name for what that produces: **A104** — *"a planted fault passed green in
a brand-new suite until the row was widened."* Widen the row.

### (d) Widen the obligation to any change of a limit's recorded value — **the ruling**

---

## 3. Ruling

**§6 stays. Its obligation moves off *lowering* and onto *any change to a
limit's recorded value*, which is the class the registry exists to record and
the only class F4 expects to occur. The `initial value` column becomes `value`
and carries exactly one bare current value — which repairs §1.5's broken raise
procedure and keeps `limits.rs:265`'s existing needle exact — with the history
and the reason moving into §6, where a reason can be a sentence. §6 is retitled
so its scope stops promising a document history it was never asked to keep, and
the document's editorial history is named as `git log`, which is where D104 §1.2
already found it. One checker lands, in `limits.rs`'s existing test module beside
the two cross-checks that already `include_str!` the same document: §5's
value-recording cells and §6's entries must agree **in both directions**, with
planted fixture strings supplying both arms. Q126's Problem statement and Accept
are amended. No limit's value changes; no constant moves.**

What carries it, in one line: **a changelog with an empty positive arm is not
always a guard to delete or a guard to enforce — sometimes it is a guard aimed
at the wrong branch, and the repair is to move the aim.**

And what makes it cheap rather than merely correct: after R2 the checker is a
pure function of two strings, so it runs in the existing `--lib` test module
with no script, no gate wiring, no temp files and no diff awareness, and its
positive arm is four committed fixture strings rather than a hypothetical future
commit.

---

## 4. Riders — normative, cite by number

### R1 — The obligation, exactly, and what it deliberately excludes

**A commit may not change a limit's recorded value in §5 without adding a §6
entry naming that limit.** "Recorded value" means the `value` cell or the
`lowered` cell, and nothing else.

**Excluded, deliberately, each with its reason:**

| change | §6 duty | why |
| --- | --- | --- |
| **adding a row** (A5's three DER rows, A110; A28's two) | none | the row's own `date set` cell is the record; a §6 entry would say the same thing twice |
| correcting `measured against`, `margin` or `structural cost` | none | these are things learned **about an unchanged limit**. D104 §4 hands A48 a batch of exactly this; a duty here is the theatre D104 §5 refuses |
| editorial edits to prose, headings, notes | none | see R6 |

**The line, stated so it is not re-derived: §6 records what a limit *is*, never
what we have learned about it.**

### R2 — The column and the two grammars, exact

**R2.1 — `initial value` → `value`.** The cell carries **exactly one bare
value**, always the current one. This is not cosmetic: it is what keeps
`limits.rs:268`'s needle (`| \`{name}\` | A11 | {value} |`) exact through a
raise, and §1.5 measures that the procedure it replaces breaks that needle on
first use. The header is not needled by anything (`limits.rs` matches rows, not
the header; `check-traceability.py`'s markers close at `:149`), so the rename is
free.

**R2.2 — `lowered` keeps its grammar**: `never`, or `` `YYYY-MM-DD` ``. No
reason, no release — those go to §6, which is the point of keeping it.

**R2.3 — the §6 entry grammar**, one line per change, newest last:

```
- **YYYY-MM-DD** — `LIMIT_NAME` raised|lowered `N` → `M` (owner task or decision,
  release or `pre-release`) — why, in one clause.
```

The three fields the checker reads are the **date**, the **backticked limit
name**, and the word **`raised`** or **`lowered`**. Everything after the em dash
is free prose the checker does not parse — deliberately, because `622f5fe`'s
lesson holds here too: pinning prose pins editorial wording rather than facts.

**R2.4 — the existing 2026-07-28 entry is kept**, re-headed as the log's zero
point (*"table created; no limit's value has changed since"*), and is exempt from
R2.3's grammar by naming no limit. It is what makes the log's emptiness a
**true statement** rather than an absence.

### R3 — §6's title and scope

`## 6. Changelog` → **`## 6. Limit-change log`**, with one scope sentence
immediately under it:

> This log records **changes to a limit's recorded value in §5**, and nothing
> else. It is not a history of this document: that is
> `git log -- docs/format/anchor-artifact-limits.md`, which is where D104 §1.2
> read it. An empty log below the creation entry means no limit's value has
> changed since the table was set — which is a fact, not an omission.

**Why the retitle is load-bearing and not decoration.** A section titled
*"Changelog"* holding one entry reading *"document created"* tells a reader the
document has not changed since 2026-07-28. It has changed **seven times**
(§1.1), one of them adding a whole section and a whole column. And this document
has **already injured a careful reader through exactly that gap**: D104 §1.2
records a read-only recon lane concluding that A27's Update rule was written ten
days later by the D102 lane, *"a provenance corruption with a measured victim"*.
A "Changelog" that stops at creation **confirms** that reading rather than
correcting it. Retitling costs one line and removes the false promise; keeping
the title and honouring it would install the per-edit duty R6 refuses.

### R4 — The checker, and why it is not the instrument (c) would have built

**Home:** `crates/antseal-core/src/anchor/ots/limits.rs`, inside the existing
`mod tests`, on the `include_str!` already there. One document, one place its
checks live; splitting them across a second crate's test surface is how a third
lane writes a fourth checker. Being in `--lib` costs the `wasm32-core-tests`
lane a target-independent string comparison, which is free.

**The invariant, both directions:**

- **Forward.** For every §5 row: if the `value` cell is not a single bare value
  **or** the `lowered` cell is not `never`, §6 must hold at least one entry
  whose backticked limit name is that row's. *Today: zero rows trigger.*
- **Reverse.** Every §6 entry naming a limit must name a limit that has a §5
  row, and that row must corroborate it — `lowered` ≠ `never` for a `lowered`
  entry, `value` ≠ the original for a `raised` entry. *This is D104 §5's
  fabricated-provenance arm made mechanical:* a lane cannot write *"we lowered
  X"* into §6 unless the table says so.

**Anti-vacuity, and this is the answer to the brief's question.** The checker is
a pure function of two `&str`s, so **both arms are exercised by committed
fixture strings in the same module** — no temp files, no script, no gate wiring,
no diff awareness:

| fixture | expectation |
| --- | --- |
| a row whose `value` cell shows a raise, §6 silent | violation, naming the limit |
| a row whose `lowered` cell is a date, §6 silent | violation, naming the limit |
| a §6 entry naming a limit whose row shows no change | violation (fabricated provenance) |
| a §6 entry naming a limit with **no §5 row** | violation |
| **the tree's own document** | no violation |

The last row is the only one that reads the real file. The other four are
strings, which is why this is ~110 lines rather than a lint with a self-test
harness.

**And one free second enforcement, recorded because it is worth knowing:** with
R2.1's single-bare-value grammar, `ots_limits_match_the_f4_registry`'s existing
needle becomes a *second* guard on the same rule — a lane that reverts to the old
"append to the cell" procedure reddens the row-prefix pin immediately, in a test
written a wave before this decision.

### R5 — Q126's Accept, amended with its reason

**Clause 2** — *"the question 'has this ever been lowered?' is answerable
without reading seven diffs"* — is **met on arrival and always was** (§1.2):
eight cells in one table, zero diffs, seven of them pinned to their constants.
Recorded as met rather than left to be re-satisfied, because a row that closes by
delivering something the tree already had is how the next audit concludes the row
did nothing.

**Clause 1** — *"a document-changing commit that owes a §6 entry cannot land
without one"* — is **kept and given a definition**: *owes* means R1's
value-change, and R4 makes it mechanical. A commit that changes a recorded value
without its entry is red in `cargo test`.

**The disjunct** — *"or §6 does not exist and the `lowered` cell carries the
history"* — is **struck**, on §2(b) K2: that arm is auditable for lowerings and
silent for raises, and raises are the case.

### R6 — What is deliberately NOT imposed

**No per-edit changelog duty.** Widening R1 from "a limit's value changed" to
"this file changed" would produce entries reading *"typo"* and *"reworded §3"*,
which is D104 §5's fabricated provenance one shade lighter and is unenforceable
without a diff-aware lint. The document's editorial history has a keeper already
and R3 names it.

### R7 — Ordering

**One commit.** The Update-rule repair (R1/R2) and the checker (R4) land
together: a checker asserting a grammar the document does not yet state asserts
nothing, and a grammar with no checker is how §5 acquired a raise procedure that
breaks a test nobody ran against it.

---

## 5. Edit set

| file | edit | rider |
| --- | --- | --- |
| `docs/format/anchor-artifact-limits.md:219` (§5 table header) | `initial value` → `value` | R2.1 |
| `docs/format/anchor-artifact-limits.md:221-228` (the eight rows) | no cell content changes — every `value` cell already holds one bare value and every `lowered` cell already reads `never`. **Recorded as a no-op so the implementing lane does not go looking for one.** | R2.1 |
| `docs/format/anchor-artifact-limits.md:331-338` (Update rule) | rewritten: the §6 duty is R1's value-change (both directions), the raise clause's *"append to the cell"* is **deleted** as breaking `limits.rs:268` (§1.5), the self-contradicting *"is the only cell that may change"* is **deleted** as falsified three ways (§1.3), and R2.2/R2.3's grammars are stated | R1, R2 |
| `docs/format/anchor-artifact-limits.md:343` (§6 heading) | `## 6. Changelog` → `## 6. Limit-change log`, + R3's scope sentence | R3 |
| `docs/format/anchor-artifact-limits.md:345-351` (the one entry) | re-headed as the log's zero point; **no retrospective entries added** | R2.4, §2(a) |
| `crates/antseal-core/src/anchor/ots/limits.rs`, `mod tests` | the checker + its four planted fixtures + the real-document case | R4 |
| `tasks/Q.md` Q126 | Problem statement corrected (miss rate against an obligation of zero); `Do` replaced by the ruling; **Accept** amended per R5 | R5 |
| `TODO.md:555` | Q126's row follows `tasks/Q.md` | R5 |
| `docs/decisions/D104…md:462` | rider: the suggested repair *"deleting §6 and moving the lowering note into the `lowered` cell itself"* is **refused** by D107 §2(b) K2 — a `lowered` cell is written only by a lowering, so it cannot carry a raise's reason. D104's ruling is untouched | §2(b) |
| `docs/decisions/D104…md:467-469` | rider: the clause *"a future lowering may not be recorded into an inert §6 — whoever exercises the window closes Q126 first"* is **discharged**. Under D107 §6 is not inert: its obligation is mechanical (R4) and its emptiness is a true statement (R3). The window D104 §2.1 leaves open is no longer conditioned on this row | R3, R4 |
| `docs/decisions/D104…md:302` | **unchanged.** *"§6 owes a dated note"* survives verbatim: under R1 a lowering still owes one | — |
| `docs/decisions/README.md` | this decision's index row — **applied 2026-08-11** under [D119](D119-decision-index-identity-and-the-index-row-sections.md) RULING 4, which demotes the former `## Index row` section to this row | — |

**Zero limit values move. Zero constants move. Zero wire bytes. Zero
format-version events. Nothing inside the `FREEZE-BOUNDARY` markers
(`:115-149`) is touched.**

---

## 6. Instruments

One test, five cases, in `limits.rs`'s existing `mod tests`:

- `the_limit_change_log_agrees_with_the_registry_rows` — forward and reverse
  (R4), over the real document.
- Four planted-fixture cases (R4's table), each asserting the checker returns a
  violation **naming the limit**, so a message that names the wrong row is a red
  test rather than a confusing one.

**Run the planted cases before trusting the green one.** R4's fixture set is the
whole positive arm; if a fixture passes the checker, the checker is not checking.
This is A104's rule and Q125's practice.

**No new lane, no gate wiring, no script.** Recorded explicitly because Q126's
`Do` proposed *"a lint of the `--freeze-boundary` shape"* and D104 §5 repeated
it: that shape exists to keep **three copies of one text** byte-identical
(`check-traceability.py:47-63`), and there is only one copy of §5 and §6. Reusing
it here would install machinery for a problem that is not this one.

---

## 7. What this does not do

- **It does not change any limit's value.** `MAX_OTS_DEPTH` is 1 024 before and
  after, and D104 §3's refusal is untouched.
- **It does not close D104's lowering window** (D104 §2.1). It removes the
  condition D104 §5 attached to exercising it.
- **It does not write retrospective entries**, and §2(a) records the second
  reason as well as D104's: six of the seven commits changed no limit's value.
- **It does not impose a per-edit changelog duty** (R6).
- **It does not touch the `margin` column's cross-check gap** — that is A112/A113,
  registered by D104 §7 — **nor the wasm32 asymmetry**, which is A106's (D104 §6),
  **nor the §5a heading capture**, also A106's (D104 §1.2). D107's edit set and
  A106's do not overlap; if they land in one wave the §5a boundary repair should
  land first, because it moves the line numbers under §5.
- **It does not add the rows A5 and A28 still owe** (A110, `:323-329`,
  `:340-341`). When they arrive they take a `value` cell and a `lowered` cell and
  inherit R1 with no further judgement.
- **It does not run `cargo`.** The two needles were read, not executed; §1.5's
  claim is a substring argument over `limits.rs:268`'s `format!` and is checkable
  by eye. The implementing lane confirms it by planting the append-shaped cell
  and watching `ots_limits_match_the_f4_registry` go red — **that is worth doing
  once**, because it is the only evidence that §1.5 is a defect rather than a
  reading.

---

## 8. Discovered work — described, not numbered

*(The wave owner allocates and registers; per the Q85 rule, including the item
cited only in prose.)*

**(i) §5's eighth row is pinned to nothing.** — M2 · XS · deps: A42, A11.
`ots_limits_match_the_f4_registry` needles seven rows and asserts
`ALL.len() == 7` *"D58 §9.1 sets seven — update deliberately"* (`limits.rs:278`).
The eighth row, A42's `MAX_OTS_CALENDAR_RESPONSE_BYTES` (`:228`), is **not one of
them**: its constant lives in `antseal-anchor` (`ots/mod.rs:99`) with a `const`
assert at 65 536 (`:107`) that never looks at the registry. So the one row D54 §7
added after the cross-check was written is the one row a silent edit would not
redden — the same shape as D104 §4's finding about the `margin` column, one
column over. Accept: the A42 row is pinned to its constant by the same
name-owner-value needle, from whichever crate can see both, or the reason it
cannot is recorded at `limits.rs:278` beside the `ALL.len() == 7` assertion.

**(ii) The `owner` cell is prose.** — M2 · XS · deps: (i). The needle hardcodes
the literal `A11`, so it happens to pin seven owners; nothing checks that an
`owner` cell names a task that exists. Small, and worth folding into (i) rather
than carrying separately.

---

## Outcome

**RESOLVED, 2026-08-09.** §6 **stays**, and both sides of Q126's `Do` are
refused. Recon's lean — delete §6, move the note into the `lowered` cell — dies
on **K2**: a `lowered` cell is written only by a lowering, so (b) preserves
auditability for the event D104 §3 rules **empty** and destroys it for the event
D104 §10 calls always-available; and on **K1**, because Q125's own precedent for
a guard with an empty positive arm was to **supply the arm**, not delete the
guard. The dismissed option (c) is refused too, and not for vacuity — the brief
is right that a planted change-set is a real positive arm — but for **aim**: it
enforces the branch that will not happen. **The obligation moves.** §6 records
**any change to a limit's recorded value**, the `initial value` column becomes
`value` carrying one bare current value, and the raise's history and reason move
into §6 where a reason can be a sentence. That repair is forced independently of
Q126 by a defect nobody had reported: **§5's written raise procedure —
*"appending the new value and its date to the `initial value` cell"* — breaks
`ots_limits_match_the_f4_registry` on first use**, because its needle
`| \`{name}\` | A11 | {value} |` requires the value cell to hold one bare value.
**Q126's premise is false** (zero of eight commits owed an entry; all eight
`lowered` cells read `never` and no diff has ever written otherwise) and **its
Accept clause 2 is met on arrival** (the `lowered` column answers *"has this ever
been lowered?"* at a glance, with no diff). The real defect is the one Q126 does
not name: a section titled **Changelog** holding one *"document created"* entry
tells a reader a seven-times-changed document has not changed — the exact
misreading D104 §1.2 measured a recon lane making about this file. Retitled
**Limit-change log**, with `git log` named as the editorial history. One checker,
five cases, four of them planted fixture strings, in the test module that already
`include_str!`s the document. **Zero limit values move.** D104 §5's clause
conditioning the open lowering window on this row is **discharged**; D104 §2.2's
*"§6 owes a dated note"* survives verbatim.
