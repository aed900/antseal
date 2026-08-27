# D162 — D158 is not a one-off and no checker was ever the mechanism: its thirteen edits are one `with`-chained act whose ordering root sits in a write scope no lane held, the one item that escaped escaped by *violating* the chain, and the same wave left a second record half-executed on a row that is already ticked

- **Status: RESOLVED. The lean is OVERTURNED ON ITS PREMISE, and the
  orchestrator's own hypothesis is FALSIFIED with counts.** The lean was
  *"D158's unexecuted edit list is a one-off oversight from wave 28. Execute
  edits 1–11 and 13 and move on. No decision is needed, no checker is warranted,
  and nothing general follows."*
  - **OVERTURNED: it is not a one-off, and the cohort is the unit.** Wave 28
    (`bebc850`) resolved **five** records in one commit — D156, D157, D158,
    D159, D160. **Three of the five did not fully execute in that wave**: D158
    (nothing but its index row), D159 (executed a wave late, by hand), D160
    (registrar half landed only where a checker sat). Waves 26 and 27 resolved
    **three** records each and executed all six. Wave 29 resolved one and
    executed it. §1.2.
  - **FALSIFIED: "rulings land iff a checker forces them."** `docs/instrument-ledger.md`
    is read by **no checker** (§1.3), and **15 of the 16** records whose edit set
    names it landed their ledger line anyway. Under the hypothesis that rate
    would be near zero. §1.3.
  - **The hypothesis's own counter-example is inside D160, one paragraph wide.**
    §5.3 opens *"**Mandatory, not optional.** `check_decision_owners` reds when…"*
    and then asks for **two** things: that `U88`'s row name `D160` (checked) and
    that its false headline be replaced **verbatim** (unchecked). The checked
    half landed. The unchecked half did not. `check-traceability.py` is **9 of 9
    ok, `REAL_EXIT=0`** today with the false headline standing on a `- [x]` row.
    §1.4.
  - **What actually failed is D158's own edit list.** Items 1–13 are one
    `with`-chained act. Item 10 is `with` 1–9 **and `after` item 11**; item 11 is
    `Cargo.toml`, which the list itself removes from the registrar's scope and
    assigns to *"whichever lane holds the manifest write scope this wave"* — a
    lane wave 28 never dispatched. Under D156's `with` = same act, **the chain is
    one indivisible act whose ordering root had no owner, so it could not
    start.** §1.5.
  - **Edit 12 did not "land because a checker forced it" — it landed by
    *breaking* the chain.** It is written `**with** 1-11`. It executed alone.
    `decision-index` reddens without it, so the checker's real effect was to
    force a **`with`-chain violation**, which is the opposite of the mechanism
    the lean's hypothesis proposes. §1.5.
  - **CONFIRMED, and it is the only surviving clause: the edits are owed.** But
    not as written — the line numbers have drifted **+10** in `tasks/Q.md`
    (§1.6), and item 10's `after` term must be struck before any lane reads it.
- **Date: 2026-08-22**
- Owner row: **`Q241`** (D158's edits) and **`U88`** (D160's shortfall). This
  record **ticks neither**. D158 §2 R1 rules `Q241` *amended and OPEN*; `U88` is
  already `- [x]` and its residue is instrument-class under rule 8.
- Related: **D158** (the unexecuted edit list); **D159 §2 R1** (the floor-guard
  discipline this record's new check adopts); **D160 §5.3** (the in-record
  natural experiment); **D156 §2 R1–R3/R9** (`with` semantics; the residue-marker
  retraction obligation this record enforces); **D154 §2 R10** (collapsing `with`
  into `after` invents a dependency — the defect D158 wrote down and then
  committed in its own item 10); **D161 §2 R6** (the refusal-with-counts
  precedent this record follows twice); **D142 §2 R4** (rule 3, allocation —
  the rule this record distinguishes execution from).

---

## 0. What was measured against

Read in full before anything was written: `docs/decisions/D158-…md` (§2 R1–R11
and all sixteen items of §4), the edit-set sections of **all 48** records that
carry one, `docs/decisions/D161-…md` (house format), `TODO.md`'s *How to use
this list* rules 1–8, `Q241`'s and `U88`'s rows and `tasks/*.md` entries,
`scripts/check-traceability.py`'s check roster, and `docs/instrument-ledger.md`.

Every count below comes from a command that was run, and the command is quoted
with it. Exit codes are read from a file. No file in the tree was modified: the
fault plants in §1.8 ran against copies staged under the session scratchpad.
`scripts/local-gate.sh`, `--self-test` and any build over ~2 minutes were not
run; none of this record's claims needs one.

---

## 1. What was measured

### 1.1 The population: 48 of 155 records carry an edit set — 31.0 %

```
grep -ln -E '^#+ .*([Ee]dit list|[Ee]dit set)' docs/decisions/D*.md | wc -l   → 48
ls docs/decisions/D*.md | wc -l                                              → 155
```

A broader pattern (`|What changes|Edits|What to edit`) returns **49**; the
forty-ninth is `### §2 R5 — The complete edit set…`, a ruling heading inside §2
rather than a section, and is excluded. The house name is **"Edit set"** in
twelve spellings; **D158 is the only record using "Edit list — per file, with
the timing word"**, which is why the orchestrator's brief and the tree disagree
on the term.

**A mechanical screen over all 48 was attempted and is REFUSED as a
measurement**, reported here so nobody re-derives it. Extracting every file path
named in each edit set and asking whether that file mentions the record's id
gives **450 targets, 159 flagged, 46 of 48 records with ≥1 flag**. The false
positives dominate: the bare token `README.md` matches inside every
`docs/decisions/README.md`, and code files never cite decision ids at all. On
the eleven records hand-verified in §1.2 the screen flagged roughly thirty
targets where the truth is **two** records. **A 35 % flag rate on a corpus whose
true rate is under 5 % is not a check; it is noise with a threshold.**

### 1.2 Full census of the recent tail — the gap is a cohort effect, not a one-off

Every record introduced in waves 26–29 was hand-verified against distinctive
verbatim strings from its own edit set (`grep -cF`), not against the screen.
Introducing commit per record from `git log --diff-filter=A -1 -- <path>`.

| wave | commit | records resolved | fully executed in-wave | shortfall |
| --- | --- | ---: | ---: | --- |
| 26 | `28afe38` | D150, D151, D152 | **3 / 3** | — |
| 27 | `5c8d1ca` | D153, D154, D155 | **3 / 3** | — |
| 28 | `bebc850` | D156, D157, **D158**, **D159**, **D160** | **2 / 5** | D158 (all), D159 (late), D160 (partial) |
| 29 | `c2709ea` | D161 *(no edit set)* | n/a | — |

Probes that returned green, each one a distinct verbatim string: D153's two
ledger findings, its D71 and D150 addenda; D154's `with/before Q65` (1),
`before Q65` (5), `with Q65` (2) rewrites; D155's *"ruled by D155"* on `TODO.md`,
five ledger findings, five `tasks/U.md` hits, the D39 addendum; D156's minted
`TICKED_WITH_RESIDUE` row (present in **both** `TODO.md` and `tasks/Q.md`), its
*phantom*-edge ledger line, the rule-7 exemplar replacement; D157's *"Which act
releases what"* table, its D153 banner at line 3, its two ledger lines.

**The discriminator is not age and not subject matter — it is how many records
one wave's registrar had to execute serially.** Three is survivable; five is
not. The lean's "one-off oversight" reading predicts a random single failure;
what is measured is **60 % of one cohort and 0 % of the neighbouring three**.

### 1.3 The checker hypothesis fails on the ledger, 15–1

`docs/instrument-ledger.md` is read by **nothing**:

```
grep -rn "instrument-ledger" scripts/ .github/     → 5 hits
```

— four are comments or prose inside `check-traceability.py` and
`verify-release.sh`, and the fifth is `check-copy-style.py:121`'s
language-register map, which classifies the file's **prose style**, never its
content. No check parses a ledger line.

Of the **16** records whose edit set names the ledger, **15 carry at least one
ledger line attributed to them** and exactly one does not:

```
D18 9 · D62 4 · D63 6 · D129 8 · D131 5 · D150 2 · D151 3 · D152 2
D153 2 · D154 1 · D155 4 · D156 3 · D157 2 · D158 0 ← · D159 4 · D160 1
```

(Attribution measured as a ledger line whose *finder* field names the id:
`^- .*·[^·]*\bD<n>\b[^·]*·`. `any mention` differs from `attributed` on only two
records, D154 and D155, where a later line cites them in passing — so the
attributed form is the precise one and is what §2 R6 adopts.)

**If rulings landed only where a checker forces them, this column would be
near-zero. It is 15 of 16.** The hypothesis is false in its "only if" direction.
Its "if" direction survives — `decision-index` is satisfied on **48 of 48**
records — but that direction is the trivial half: it says a check that reddens
gets fixed, which was never in doubt.

### 1.4 D160's §5.3 is a controlled experiment the register has not read

One paragraph asks for two edits, one checked and one not.

- **Checked half — LANDED.** `TODO.md:906`'s `U88` row names `D160` four times,
  and `check_decision_owners` prints `ok — 7 per-ruling owner assignment(s) …
  every one named by the row it assigns`.
- **Unchecked half — NOT LANDED.** §5.3(a) orders the headline replaced
  **verbatim** with *"Where the keyfile class learns its backup route at the two
  class-blind existing-vault refusals — answered `no pointer`, and the premise
  was false."* `grep -cF` → **0**. The row still opens *"The honest reword left
  one vault class with no backup route mentioned anywhere in `init` or
  `import`."* — and the **same line's own closing note** says that headline was
  *"false six times over"*. The row asserts a claim and refutes it, 4 000
  characters apart, with the box ticked.
- **§5.4 items 1–2 — NOT LANDED.** `tasks/U.md:1267` still reads *"### U88 — The
  honest reword leaves one vault class with no backup route named anywhere"*,
  and the U88 entry span (`:1267–:1281`) mentions **`D160` zero times**
  (`grep -c` → 0). The two locator corrections (`init.rs:655-663`,
  `init.rs:368-388`) are absent.

D160's implementing half **did** land — `bookkeeping.rs:401,410,433` carry R7's
rustdoc and R8's identity pin, and the row reports R9's four verdicts. So the
failure is not "the lane never ran"; it is that **the registrar's chain stopped
exactly where the checker's reach stopped.**

Full checker state today, read from a file, `--self-test` not run:

```
python3 scripts/check-traceability.py ; echo $? > /tmp/ct.rc   → REAL_EXIT=0
check-traceability: ok (freeze-boundary, matrix, decisions, task-citations,
task-entries, decision-owners, decision-index, machine-paths, doc-links)
```

### 1.5 The real mechanism: a `with`-chain whose ordering root had no owner

D158 §4's own timing words, quoted:

| item | target | timing as written |
| ---: | --- | --- |
| 1–9 | `tasks/Q.md` | mutually **`with`** |
| 10 | `TODO.md:837` | **`with`** 1–9, **and `after` edit 11 has been decided** |
| 11 | `Cargo.toml:60-63` | **`before`** 10 · *"assign it to whichever lane holds the manifest write scope this wave, and never to two lanes at once"* |
| 12 | `docs/decisions/README.md` | **`with`** 1–11 |
| 13 | `docs/instrument-ledger.md` | **`with`** 1–12 |

D158's own preamble states the semantics: *"`with` = same act."* So items 1–13
are **one act**, and that act is `after` an item the registrar may not perform
and that no lane was given. `bebc850`'s file list contains
`crates/antseal-core/Cargo.toml` and **not** the workspace root `Cargo.toml`:
the manifest lane was never dispatched, so the root of the chain never
resolved, so nothing downstream of it could execute.

**And D158 wrote the lesson it then broke.** Its §4 preamble: *"**Collapsing
`with` or `before` into `after` invents a dependency** — the defect D154 traced
to four phantom cycles."* Item 11 is declared `before` 10, and item 10 restates
it as `after` 11. The invented dependency is one line below the warning against
it.

Item 12's escape confirms the reading. It is written `with` 1–11 and executed
**alone**, because `decision-index` reddens without it. That is not a checker
causing execution; it is a checker causing a **chain violation** — the registrar
peeled one item out of an act it could not otherwise perform.

### 1.6 D158's locators have drifted +10, and one of them is misdescribed

`tasks/Q.md` measured today against D158 §4's cited lines:

| D158 §4 says | field | today |
| --- | --- | ---: |
| `:2979` | `Size: M` | **`:2989`** |
| `:2980` | `Deps:` | **`:2990`** |
| `:2983` | `Problem:` | **`:2993`** |
| `:2984` | `Do:` (arm (d)) | **`:2994`** |
| `:2986`–`:2989` | `Accept` rows 1–4 | **`:2996`–`:2999`** |
| — | `Notes:` | **`:3000`** |

`### Q241` now begins at `:2987`. **A lane executing item 6 at `:2979` edits
another row's `Accept` bullet.**

Separately: the brief describes item 9 as *"`D72 §2 R5` → `D72 §2 R8` in Accept
row 1"*. It is not. Item 9 targets **arm (d) of the `Do:` line** (`:2994`
today). Accept row 1 also carries `D72 §2 R5`, but that site is consumed by item
1's wholesale replacement. Both were measured; both are unlanded.

Per-item state, re-verified at source and not inherited:

| item | landed? | evidence |
| ---: | --- | --- |
| 1–5 | **no** | `Accept` still has **4** rows; row 1 is the original |
| 6 | **no** | `:2989` still `Size: M` |
| 7 | **no** | `Deps` still carries `P13/D19` **and** `Q31` |
| 8 | **no** | `Problem`'s two clauses unedited |
| 9 | **no** | `Do:` arm (d) still `D72 §2 R5` |
| 10 | **partial** | `(M)` stands; both `after` terms stand; *"correction to the handover"* sentence stands. A `[D158 RULED …]` block **was appended** — the §2 R1 Notes half only |
| 11 | **no** | `Cargo.toml:60-63` still reads *"…rejects wildcard requirements workspace-wide, path deps included"* — the sentence D158 §2 R6 calls **false** |
| 12 | **yes** | `docs/decisions/README.md:176` |
| 13 | **no** | `grep -c D158 docs/instrument-ledger.md` → **0** |

### 1.7 Two further live defects the sweep surfaced

**(a) `Q249`'s `OWED` marker was never retracted.** `TODO.md:876` carries both
*"`[D159 RULED 2026-08-22 … the check is OWED and is the next act on this
row.]`"* **and** *"✅ 2026-08-22 — **D159 §2 R1/R2/R5 EXECUTED**"*, unstruck
(`grep -c '~~\[D159 RULED'` → 0). Protocol rule 1 clause (b) — *"The marker is
retracted in the act that discharges the residue"* — is breached on the only
row that has ever used this marker form. It is the same class D156 §2 R9
retracted four `🟡` glyphs for, ten days stale, and it recurred inside the very
wave that read D156.

**(b) Three surfaces disagree on `Q241`'s size.** `TODO.md:1096`'s decision
register says *"Row shrinks to **XS**"*; `TODO.md:866` says `(M)`;
`tasks/Q.md:2989` says `Size: M`. Nothing compares a register row's claim
against the row it describes.

### 1.8 The one checker candidate that survives, with its yield measured on history

Candidate: **for every record whose edit-set section names
`docs/instrument-ledger.md`, the ledger must carry at least one line attributed
to that record's id.** Run against four historical trees via `git show`, and
against the worktree:

| tree | wave close | subject | findings |
| --- | --- | ---: | --- |
| `28afe38` | 26 | 8 | **0** |
| `5c8d1ca` | 27 | 11 | **0** |
| `bebc850` | 28 | 16 | **2 — D158, D159** |
| `c2709ea` | 29 | 16 | **1 — D158** |
| worktree | today | 16 | **1 — D158** |

**This is not a check that is green because nothing could redden it.** It was
green on two trees and red on three, and both of its wave-28 findings were
**independently confirmed unexecuted by later hand investigation** — D159 by
wave 29's hunt, D158 by this record. **It would have named D159 a full wave
before the register found it by reading.** False positives across all five
trees and 67 record-tree observations: **0**.

**Fault plants, run on copies staged in the session scratchpad; the tree was not
modified.** Baseline on the copy: RED, 1 finding (D158), `REAL_EXIT=1`.

| plant | expected | observed |
| --- | --- | --- |
| delete D157's ledger lines | RED 2 | **RED 2, naming D157 and D158**, `REAL_EXIT=1` |
| empty the ledger entirely | RED 16 (whole subject) | **RED 16**, `REAL_EXIT=1` |
| **green control** — restore, add one synthetic `D158` line | GREEN 0 | **GREEN 0**, `REAL_EXIT=0` |

The green control is the load-bearing arm: it proves the standing red is caused
by the **absence of D158's line specifically**, not by anything else in the
file. A red-only plant would not have shown that.

**The vacuity trap is the heading regex**, exactly as D159 §2 R1 found for
`doc-links`' glob: if `'^#+ .*([Ee]dit list|[Ee]dit set)'` ever stops matching,
the subject falls to 0 and the check passes forever. **The subject count must be
asserted against a floor, not merely iterated.**

**What the check does NOT see, stated so it is not over-read.** It is a
**sentinel, not a coverage test**. It is blind to D160's §5.3(a) and §5.4
misses, to every `tasks/*.md` edit, and to item 11. Its justification is
positional and measured: in the twelve records written in the current house
style the ledger item sits at **58 %–88 %** through the edit set — never first —
so its absence is evidence that **the chain stopped**, which is the failure mode
§1.5 identifies. That is a correlation this record measured, not a guarantee,
and §3 says what it therefore cannot promise.

### 1.9 What the protocol already says, and where the hole is

Rule 3 (D142 §2 R4) governs **allocation**: *"A decision id, once allocated,
gets one of the three homes in the same commit that allocates it."* It is
enforced citation-independently by `check_decisions`, and it works — 161
allocated ids, 0 holes.

Rule 1 clause (a)/(b) (D156 §2 R1–R3) governs **residue**: a ticked row's
residue must name a live owner, and the marker retracts in the discharging act.
It is enforced by nothing, and §1.7(a) is a live breach.

**Nothing in rules 1–8 says a resolved record's edit set is executed at all.**
D160 §5.3(c) states the principle in passing — *"D141's lesson is that a
*resolved* ruling is not an *executed* one"* — in a record whose own edit set
then went partly unexecuted. The principle is on record as an aside and binds
nothing.

---

## 2. RULING

### §2 R1 — The lean falls on its premise. D158 is the third of three in one cohort, and the cohort is the unit of failure

Wave 28 resolved five records and executed two. Waves 26 and 27 resolved three
each and executed six of six. Wave 29 resolved one and executed it (§1.2).
**Any wave resolving more than three records carries an execution shortfall
risk, and the wave brief must name the executing lane for every record's edit
set before the records are written, not after.** This is a finding about wave
shape, not about D158's author.

### §2 R2 — The checker-forces-execution hypothesis is FALSIFIED, 15–1, and its own counter-example is inside D160

`docs/instrument-ledger.md` is read by no checker, and 15 of 16 records landed
their ledger item anyway (§1.3). The converse direction — a checker that reddens
gets satisfied — holds at 48 of 48 and is the trivial half. D160 §5.3 asks for a
checked edit and an unchecked edit in one paragraph, calls both *"Mandatory"*,
and only the checked one landed (§1.4). **A checker is sufficient to force an
edit and is not necessary; treating it as necessary would licence the conclusion
that unchecked rulings need not be executed, which is false on the measurement.**

### §2 R3 — The mechanism is D158's own edit list: one `with`-chained act whose ordering root sat in a write scope no lane held

Items 1–13 are `with`-chained into a single act (D158's own preamble: *"`with` =
same act"*). Item 10 is `after` item 11; item 11 is `Cargo.toml`, expressly
outside the registrar's scope and assigned to a manifest lane wave 28 never
dispatched. **The chain could not start.** Item 12's solo landing is a
`with`-chain **violation** forced by `decision-index`, not evidence that
checkers cause execution (§1.5).

### §2 R4 — Item 10's `after` term on item 11 is STRUCK. Item 11 is INDEPENDENT

D158 §4's own preamble forbids exactly this: *"Collapsing `with` or `before`
into `after` invents a dependency."* Item 11 is declared `before` 10 and then
re-declared `after` by item 10 — the invented dependency is one line below the
warning. **Item 11 executes independently, by one lane, in the same wave.
Items 1–10, 12 and 13 are the registrar's and wait on nothing.** The stated
reason for the original coupling — *"so the row's pointer to the corrected
comment is not written before the comment exists"* — is satisfied by both
landing in the same wave's commit, which is what `with` already meant.

### §2 R5 — D158's line-number locators are STALE by +10 and are REPLACED by row-id-plus-quoted-string form

`### Q241` moved from `:2977` to `:2987` (§1.6). **No lane may execute D158 §4
by line number.** §4 below restates every target as *field name + quoted old
string*, with today's line as a convenience only. This is D154's own rule —
*"Every target is given as row id + exact old string as well as a line number,
because … locators may drift under another lane"* — which D158 did not adopt.

### §2 R6 — ONE checker is MINTED: `decision-ledger-debt`, a tenth check in `check-traceability.py`, with a floor

**What it parses.** Each `docs/decisions/D*.md`; the section matched by
`^#+ .*([Ee]dit list|[Ee]dit set)` up to the next `^#{1,2} ` heading; whether
that section names `docs/instrument-ledger.md`; and whether the ledger carries a
line matching `^- .*·[^·]*\bD<n>\b[^·]*·`.

**Measured yield.** Today **1** (D158), 0 false positives. Historically: wave 26
**0/8**, wave 27 **0/11**, wave 28 **2/16** (D158, D159 — both later confirmed
unexecuted by independent hand investigation), wave 29 **1/16** (§1.8). It would
have named D159 one wave before the register found it by reading.

**Measured false positives.** **0**, across 67 record-tree observations on five
trees.

**Planted faults, all executed on copies (§1.8).** Delete D157's ledger lines →
RED 2 naming D157; empty the ledger → RED 16; **green control**, add one
synthetic D158 line → GREEN 0.

**Mandatory vacuity guard.** The check **must assert `subject >= 16`** and print
the subject count, per D159 §2 R1's floor discipline. A heading-regex drift
yields subject 0 and a vacuous pass, and that is this project's dominant defect
class. **The floor is 16, not an equality**: re-measured at this registration
the subject is already **18**, because two wave-30 records (this one and `D163`,
written concurrently by another lane) carry ledger-naming edit sets.

**The mid-act window is expected and is not a defect.** Like `decision-index`,
this check reds on a record that exists before its edits land — measured at this
registration: `subject=18 findings=3`, naming `D158`, `D162` and `D163`. Two of
the three are wave 30's own records mid-act, and they go green when §4 items 13
and 14 land. D119 RULING 6 governs; the registrar closes the window at wave end.
**A lane must not "fix" this by narrowing the subject.**

**Sequencing, and it is the point.** The check is built and demonstrated **RED
naming D158 on the unfixed tree** *before* the registrar lands D158 item 13.
That is a measured yield on a live subject, not a plant. The registrar's ledger
line then turns it **GREEN**. Red-before / green-after, on real data.

### §2 R7 — TWO checkers are REFUSED, with counts

| candidate | measured | verdict |
| --- | --- | --- |
| *"every file named in an edit set mentions the record's id"* | **450 targets, 159 flagged, 46 of 48 records flagged**; hand-verified true rate on 11 records ≈ **2** | **REFUSED** — a 35 % flag rate against a <5 % true rate is noise with a threshold, and it would train lanes to ignore it |
| *"every resolved record's edit set is executed"* | **not parseable** — items are prose carrying verbatim quotes; nothing decides execution mechanically without a per-item machine form | **REFUSED** — inventing that format is a change no measurement here supports, and D161 §2 R6's rule applies: *a decision is not made checkable by wrapping a constant in a script* |

### §2 R8 — D160 is a SECOND live gap and is wave-30 work: §5.3(a) and §5.4 items 1–2

`TODO.md:906` is `- [x]` and carries a headline its own governing record calls
false, refuted 4 000 characters later in the same line. `tasks/U.md`'s `U88`
entry does not name `D160` at all. **These execute in wave 30.** `U88` is **not
untickable** — D160 §5.3(c)'s tick condition (lane lands R7/R8, reports R9's
four verdicts) is satisfied and measured at `bookkeeping.rs:401,410,433`. The
box stays `- [x]`; the prose is corrected under it.

### §2 R9 — `Q249`'s `OWED` marker is RETRACTED, per protocol rule 1 clause (b), which it currently breaches

The marker and its own `EXECUTED` note stand side by side, unstruck (§1.7(a)).
Retract by striking the bracketed marker, not by deleting it — D117's discipline
for a dated record of what was true then.

### §2 R10 — Executing D158's edits does NOT tick `Q241`, and its size resolves to **XS** on all three surfaces

D158 §2 R1 rules the row *amended and OPEN*; D158 §2 R3's unrun
`cargo package --workspace` and §1.9's three further publish blockers stand.
The register row at `TODO.md:1096` already says **XS**; the two surfaces that
say `M` are the stale ones (§1.7(b)). **No surface changes to `M`; two change to
`XS`.**

### §2 R11 — A protocol rule IS owed, it belongs in rule 3, and it is one sentence

Rule 3 governs **allocation**; nothing governs **execution** (§1.9). Append to
rule 3:

> **[D162 §2 R11, 2026-08-22]** A resolved decision record's edit set is
> **executed in the same commit that resolves it**, or the shortfall is written
> onto the owning row as a live debt naming **an owner and a timing word** —
> the same two things rule 1 clause (a) requires of a residue. *Resolved is not
> executed*: three of wave 28's five records shipped a ruling whose edits had
> not been made, and one of them was found only two waves later. Where an edit
> set spans **more than one write scope**, the wave brief names the lane for
> each scope **before** the record is written; an item assigned to *"whichever
> lane holds"* a scope is assigned to nobody.

**No general execution checker accompanies it** (§2 R7). The
`decision-ledger-debt` sentinel is the only mechanical enforcement, and §3 says
plainly what it does not cover.

### §2 R12 — No task row is minted

Under rule 8 every finding here is instrument-class — decision-document prose,
stale locators, tracker drift, checker honesty — and none blocks an acceptance
on the ship path that is not **already owned by an open row**: D158's edits by
`Q241`, the protocol sentence by this record, D160's shortfall by a `[x]` row
whose residue is ledger-bound. §4 item 13 sends four findings to
`docs/instrument-ledger.md` with no id, per rule 8 and per D158 §2 R11's own
precedent.

---

## 3. What this record does NOT settle

1. **It does not measure the unexecuted-item count across all 48 records.** It
   measures the **population** (48 of 155, §1.1) and hand-verifies the
   **wave-26-to-29 tail in full** (11 records, §1.2). The 37 older records are
   covered only by the screen that §1.1 **refuses as a measurement**. What is
   claimed is the cohort finding, not a tree-wide total. Anyone wanting that
   total must hand-verify 37 records, and this record does not pretend to have.
2. **`decision-ledger-debt` is a sentinel, not a coverage test** (§1.8). It is
   blind to `tasks/*.md` edits, to `Cargo.toml`, and to both of D160's live
   misses. Its positional justification (58 %–88 % through the edit set) is a
   measured correlation over twelve records and **may not hold for a record that
   puts its ledger item first** — D63 puts it at 3 %. It will pass a chain that
   stopped after the ledger item.
3. **It does not rule that five records per wave is forbidden**, only that the
   shortfall correlates with it and that the brief must name executing lanes per
   write scope. The causal claim is one cohort wide.
4. **It does not run `cargo`.** D158 §2 R3's *"run `cargo package --workspace`
   before any manifest edit"* is unrun and stays unrun; item 11 corrects a
   **comment** and touches no dependency edge, so it does not trip that
   ordering. D158 §4 items 14–16 stay deferred to the first crates.io publish
   and this record does not move them.
5. **It does not tick `Q241` or reopen `U88`**, and it authorises no external
   action of any kind.
6. **It does not audit whether the 15 landed ledger lines say what their records
   asked them to say** — only that a line attributed to the record exists. A
   wrong ledger line passes.

---

## 4. Edit list — per file, with the timing word

Timing words are literal, per D156 and D154 §2 R10. `with` = same act; `before` =
strictly earlier, same wave; `after` = requires the other complete. **Every
target below is given as field + quoted old string. Line numbers are a
convenience and have already drifted once (§1.6) — if the quoted string is not
at the line, trust the string.**

**Write scopes are disjoint and are declared here so two lanes never collide:**
registrar → `TODO.md`, `tasks/*.md`, `docs/instrument-ledger.md`,
`docs/decisions/README.md`. Manifest lane → `Cargo.toml` **only**. Checker lane
→ `scripts/check-traceability.py` **only**.

### Manifest lane — exactly one lane, `Cargo.toml` only

1. `Cargo.toml`, the `antseal-core` comment block (today `:60-63`, old string
   *"exists so the requirement is never cargo's implicit `*`: the cargo-deny
   bans lane (P13, deny.toml) rejects wildcard requirements workspace-wide, path
   deps included."*) — replace with **D158 §2 R6**'s eleven-line TOML block
   verbatim. This is **D158 item 11**, and its `after`/`before` coupling to item
   10 is **STRUCK by §2 R4**: it is **independent**. Touch nothing else in the
   file; `Cargo.toml:64/70/76` stay (D158 §2 R2).

### Checker lane — `scripts/check-traceability.py` only

2. Add the tenth check `decision-ledger-debt` per **§2 R6**: parse each
   `docs/decisions/D*.md`, take the section matched by
   `^#+ .*([Ee]dit list|[Ee]dit set)` to the next `^#{1,2} ` heading, and where
   that section names `docs/instrument-ledger.md`, require a ledger line
   matching `^- .*·[^·]*\bD<n>\b[^·]*·`. **Assert and print `subject >= 16`.**
   Update the module docstring's *"Nine checks live here"* → **"Ten"** and its
   flag table **in the same edit** — D159 §2 R1 found that number stale before.
   **`before` item 13**, so the check is seen RED naming D158 on the unfixed
   tree; record that red's message as the yield.
3. Add `--self-test` arms for it per §2 R6's plants: one RED (subject present,
   ledger line absent — subject **constructed**, not the live D158), one RED
   (empty ledger → whole subject), one **GREEN control** (line present), and one
   guard arm asserting the check **reds when `subject` falls below the floor**.
   **`with` item 2.**

### Registrar — `TODO.md`, `tasks/*.md`, `docs/instrument-ledger.md`, `docs/decisions/README.md`

D158's own items, renumbered and re-anchored. **Items 4–12 are one act (`with`),
and that act no longer waits on anything (§2 R4).**

4. `tasks/Q.md`, `### Q241` → `Accept` row 1 (*"`cargo package` (not merely
   `--dry-run`) succeeds …"*) — replace with **D158 §2 R1**'s block verbatim.
   *(D158 item 1.)* **with** 5–12.
5. `tasks/Q.md` `Q241` `Accept` rows 2, 3, 4 — replace/append per **D158 §2 R7**:
   row 2 its replacement text; row 3 append *"**MET 2026-08-22 (D158 §2 R7)**:
   unmoved; the recorded reason is `Cargo.toml:60-63` as corrected by D158 §2
   R6."*; row 4 append §2 R7's verdict (**NO**, with the §1.8 pointer).
   *(D158 items 2–4.)* **with** 4, 6–12.
6. `tasks/Q.md` `Q241` — add **D158 §2 R7**'s **fifth** `Accept` row after row 4.
   The entry has **4** rows today; it must have **5**. *(D158 item 5.)*
   **with** 4–5, 7–12.
7. `tasks/Q.md` `Q241` `- Size: M` → `- Size: XS`, citing **D158 §2 R8** and
   D72 §6 item 1's `S`. *(D158 item 6.)* **with** 4–6, 8–12.
8. `tasks/Q.md` `Q241` `- Deps:` — strike `P13/D19` and `Q31` per **D158 §2 R5**,
   keep `P2`, add its two annotations and its non-row ordering sentence.
   *(D158 item 7.)* **with** 4–7, 9–12.
9. `tasks/Q.md` `Q241` `- Problem:` — correct *"whose reason is written … in
   `docs/decisions/D19-advisory-lane.md:51-53`"* per **D158 §2 R9 item 2**, and
   the *"The only route that would is …"* sentence per **§2 R7**'s correction.
   *(D158 item 8.)* **with** 4–8, 10–12.
10. `tasks/Q.md` `Q241` `- Do:` **arm (d)** — `D72 §2 R5` → `D72 §2 R8`. **This
    is the `Do:` line, not `Accept` row 1** (§1.6). *(D158 item 9.)*
    **with** 4–9, 11–12.
11. `TODO.md` `Q241` row — headline `**Q241** (M)` → `**Q241** (XS)` (§2 R10);
    strike the two `after` terms per **D158 §2 R5**; **replace** (not append) the
    sentence *"correction to the handover: **no dev-dep line carries a literal
    `version =`**, so the fix lands on the workspace table, which is what makes
    the collision unavoidable"* with **D158 §2 R2**'s finding. The existing
    `[D158 RULED …]` block is D158 §2 R1's Notes half and **stays**. *(D158 item
    10, with §2 R4's `after` term struck.)* **with** 4–10, 12.
12. `TODO.md` decision register row for `D158` (`:1096`) — no change; it already
    says **XS**, and §2 R10 makes the other two surfaces agree with it.
    Recorded here so no lane "corrects" it downward. **with** 4–11.
13. `docs/instrument-ledger.md` — **D158 §2 R9**'s three findings, one dated line
    each, attributed `· D158's lane (wave 28) ·`. *(D158 item 13.)* **after**
    item 2 has been seen RED naming D158, so the check's yield is measured on a
    live subject before it is discharged.
14. `docs/instrument-ledger.md` — **four** further dated lines from this record,
    no id, per rule 8: (a) *a resolved ruling's edit set went unexecuted for two
    waves because its `with`-chain's ordering root sat in a write scope no lane
    held (D162 §1.5)*; (b) *a record's `Mandatory, not optional` edit landed only
    on the half a checker could see, in the same paragraph (D162 §1.4)*; (c) *a
    decision record's own line-number locators drifted +10 before any lane read
    them, and D154's row-id-plus-string form was available and not used (D162
    §1.6)*; (d) *`Q249` carries an `OWED` marker and its own `EXECUTED` note on
    one line, unstruck — rule 1 clause (b) breached in the wave that read D156
    (D162 §1.7a)*. **with** 13.
15. `TODO.md:876` `Q249` row — **strike** (`~~…~~`, never delete) the
    `**[D159 RULED 2026-08-22 … the check is OWED and is the next act on this
    row.]**` marker, with a one-line dated reason citing **D162 §2 R9** and
    protocol rule 1 clause (b). The `✅ 2026-08-22 — D159 §2 R1/R2/R5 EXECUTED`
    note stays. **independent** of 4–14.
16. `TODO.md:906` `U88` row — **D160 §5.3(a)** verbatim: replace the headline
    *"The honest reword left one vault class with no backup route mentioned
    anywhere in `init` or `import`."* and the *"That is honest. It is also
    **silent**… "* → *"…move a directory aside."* passage with §5.3(a)'s two
    quoted replacements. The box stays `- [x]` (§2 R8). **independent** of 4–15.
17. `tasks/U.md:1267` `### U88` — **D160 §5.4 items 1 and 2**: the title
    replacement, §5.3(a)'s `Problem` replacement, and the two locator
    corrections (`init.rs:655-663`, `standing_warnings` `init.rs:368-388` with
    selection at `:377-381`). **with** 16.
18. `TODO.md` protocol rule 3 — append **§2 R11**'s paragraph verbatim, after
    the D142 §2 R4 block. **independent**.
19. `TODO.md` decision register — the `D162` row, ticked, naming `Q241` and
    `U88`. **with** 20.
20. `docs/decisions/README.md` — one index row for **D162**, in ascending id
    order, `RESOLVED` / `2026-08-22` copied from this record's own
    `- **Status`/`- **Date` lines. **Registrar holds this file; this record does
    not write it.** **with** 19, and rule 3 makes both one act with the commit
    that lands this file.
21. `TODO.md` header counts — **recount by script**
    (`python3 scripts/check-traceability.py`, flagless — that run *is* the
    check; there is no `--check` flag, and `--self-test` stages a full tree copy
    and is banned mid-wave). **Never increment**; the header has drifted six
    times. **after** 19–20.

### Post-edit verification, and none of it is an exit code

- `python3 scripts/check-traceability.py` → **10 of 10 ok**, with
  `[decision-ledger-debt]` printing its subject count and **`subject >= 16`**
  satisfied, and `[decisions]`/`[decision-index]` green only if items 19 and 20
  landed together.
- `sed -n '/^### Q241/,/^### Q242/p' tasks/Q.md | grep -c '^  - '` → **5**
  `Accept` rows, not 4.
- `grep -c 'Size: XS' tasks/Q.md` up by one; `grep -n '^- Size' ` on the `Q241`
  span → `XS`. `grep -c '\*\*Q241\*\* (M)' TODO.md` → **0**.
- `grep -c 'path deps included' Cargo.toml` → **0**;
  `grep -c 'allow-wildcard-paths' Cargo.toml` → **1**.
- `grep -c D158 docs/instrument-ledger.md` → **≥ 3**, each line attributed
  `· D158's lane`.
- `grep -c 'no backup route mentioned anywhere' TODO.md tasks/U.md` → **0 0**.
- The **D158 red is recorded as a message, not an exit status**: item 2's first
  run must print the finding naming `D158` and the ledger, and that message —
  not `REAL_EXIT` — is the evidence, read back from a file.

**Explicitly NOT edited by anything here:** `deny.toml` (D158 §2 R7 Accept row 3
— unmoved), `Cargo.toml:64/70/76` (D158 §2 R2 — load-bearing for the six normal
public edges), `docs/decisions/D158-…md` and `docs/decisions/D160-…md` bodies
(D117 — resolved records are corrected by citation, not by editing), any Rust
source, any snapshot, and `docs/decisions/D159-…md`. **D158 §4 items 14–16 stay
deferred** to the first crates.io publish and are not touched. **No row is
minted and no id is assigned** (§2 R12).
