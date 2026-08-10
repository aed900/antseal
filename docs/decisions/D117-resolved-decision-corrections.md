# D117 — Q122: whether a resolved decision's body takes dated corrections, and what happens to the sentence that is wrong

- **Status: RESOLVED — a resolved decision's body **does** take dated
  corrections, and the arm the register was briefed to defend does not exist.
  The lean survives; every reason given for it is wrong.** The row cites *"D84
  §2's dated-corrections mechanism"*; §2 is *"Why introducing these limits at M2
  cannot break line 123"* and holds none. The entry corrects that and stops one
  step short: D84's two corrections used **two incompatible mechanisms** — the
  first **deleted three lines of the resolved body** (`5994365`, +27/−3), the
  second was a **pure append** that left its subject standing (`3d47363`,
  +37/−0) — and three wave-13 amendments cite the second as *"the
  appended-correction mechanism D84 established"*, which is false of the first.
  **The rule was already written, on the lean's side, in the third sentence of
  the file the row cites for a different reason**: `docs/decisions/README.md`
  opens *"A decision is changed by editing its file with a new dated entry,
  **never by silently rewriting history**"* — the prohibition is on **silence**,
  not on change, and it predates Q122 by eleven days. Neither the row nor the
  entry mentions it.
  **The other arm is not the conservative arm; it is unimplementable three
  times over.** (1) *"The register row"* is **three** rows: `TODO.md`'s
  register (**116 rows, complete, machine-read**), `docs/decisions/README.md`
  (**69 rows, 29 records missing — D53–D61 and D97–D116 — and read by
  zero scripts**), and each document's own `## Index row` section (**33 carry
  one; 27 of the 33 have never been applied to README**). (2) On Q122's own
  forcing case **the register row is inside the body** — D95's row is verbatim
  in `README.md:81`, `TODO.md:788` **and `D95:349`** — so *"move only the row"*
  requires the body edit it forbids. (3) *"Bodies are immutable"* would reverse
  an executed practice **30 instances deep**: of 48 commits that modified an
  already-committed `docs/decisions/D*.md`, **28 deleted body lines** (132 lines
  total, 2026-07-27 → 2026-08-10), and at the parent commit the file read
  `Status: RESOLVED` in **30 of 34** (commit, file) pairs. Nine resolved
  decisions carry a **`Amendments / Corrections (orchestrator applies at
  source)`** section whose contents are instructions to *replace* and even
  *delete* text inside other resolved decisions — D93 §13.3 ordered a ground
  **deleted** from D56 and it was.
  **Accept bullet 3's count case was solved one wave before four lanes declared
  the opposite rule, and nobody registered it.** `7bc746b` (wave 11) edited
  **resolved** D98's rider 3c from *"**Three** predicates"* to *"**Four**"* in
  place, with an inline dated attribution (*"Extended from three to four by D108
  R2 (Q129, 2026-08-09)"*) and an explicit **"This rider is not renumbered"**
  clause naming the six citation sites that must keep resolving. That is the
  mechanism, already executed and already right.
  **Wave 13's four "amendments" never amended a committed body.** Measured on
  `1c702d4`: D113 **880/0**, D114 **899/0**, D115 **873/0**, D116 **1209/0** —
  all four files were *created* by that commit, amendment included; D109's
  amendment likewise rode `d23dccc`, which created D109 (**1041/0**). So *"the
  body above is byte-unchanged"* is true only of a body git never held. The
  restraint was real as practice and **vacuous as evidence**.
  **The binary the row poses is the wrong axis.** Five in-place forms are
  already executed in this tree and none is normative. What decides the form is
  not *where* the correction goes but **what kind of sentence is wrong**: a
  sentence a lane would act on is **replaced**; a measurement, census, argument
  or rationale is **struck and left standing**. §2 rules six rules; §6 executes
  one correction under them.
  **A fifth parked correction exists that Q122's row does not name, and it is
  the one that proves the cost.** `D94:554-555` still reads *"three of A22's
  four Accept rows"*; A22 has three. **D101 §2.2 and D103 §7.2 RULING 6a each
  ordered it corrected at source and neither was executed**, because
  `tasks/Q.md:1407` asserts a contrary rule — *"a ruled record is immutable; the
  drift is recorded here"* — which is registered nowhere, cites nothing, and
  contradicts `README.md`'s opening. That sentence is the arm this decision was
  charged to build, found in the wild, and it has already cost two ignored
  rulings.
- **Date: 2026-08-10** (M2 wave 14 planning round; briefed to **overturn** the
  row's lean that resolved bodies take dated corrections, and returning it
  confirmed on a measurement the row does not contain, with the row, its entry,
  D84's characterisation, three wave-13 amendments and the register itself all
  falsified on the way)
- **Owning tasks: Q122** (the ruling), **D109** (§8 (iii), corrected in §6 under
  this rule), **Q167** (which lands under §5.1), **Q151** (D114 §7's marker,
  §5.2), **Q134**/**Q135** (which cite D109 §8 (iii)–(iv)), **A108** (whose
  parked D101 §3.4 correction is unblocked, §5.3)
- **Amends**: nothing in `tasks/*.md` — this decision proposes rows, it does not
  write them.
  **Supersedes**: nothing.
  **Corrects**: **D109 §8 (iii)**, executed in this commit under §2 — the
  correction D115 §3.7 declined and named `Q122` as its blocker.
  **Binds against**: `docs/decisions/README.md`'s opening paragraph, D84's two
  correction sections, D93 §13 and D56 §1 ground 3 / §5, D94 §9a, D98 rider 3c,
  D101 §2.2, D103 §7.2 RULING 6a, D108 §3 (frozen text is refused at the body
  and goes to the errata file), D109 §3.3 (`docs/decisions/` is out of
  `CITATION_SCAN`), D115 §3.2/§3.5/§3.7/§3.8, `scripts/check-traceability.py`'s
  `check_decisions()` and `allocated_decision_ids()`.

---

## The problem, in one sentence

A lane that measures a resolved decision and finds it wrong has two written
rules to choose between — `docs/decisions/README.md`'s *"changed by editing its
file with a new dated entry"* and `tasks/Q.md:1407`'s *"a ruled record is
immutable"* — neither of which cites the other, and the choice has already
decided whether two rulings were executed or ignored.

---

## 1. What was measured

Every command below was executed on this host on **2026-08-10** against the
working tree at `95fcee0`. Where a document disagrees with a measurement, the
measurement is recorded as the fact.

### 1.1 The row is wrong about D84, and the entry that corrects it stops one step short

The row (`TODO.md`, Q122) says *"D84 §2 already has a dated-corrections
mechanism that would fit."*

```
$ grep -n '^#\{1,4\} ' docs/decisions/D84-anchor-artifact-limits-permanence.md
...
78:## 2. Why introducing these limits at M2 cannot break line 123
...
353:## Correction — 2026-07-28 (A27 implementation)
374:### Correction to the correction — 2026-07-28 (M0 wave 7)
```

§2 is a permanence argument and contains no correction machinery. `tasks/Q.md`'s
Q122 entry already records this and re-points at the two trailing sections. That
much is right, and the entry's conclusion — *"D84 corrected its own resolved body
**twice**, so the practice already exists without a rule"* — is right.

**What neither the row nor the entry noticed is that the two corrections are not
one mechanism.** Measured from the history:

```
$ git show 5994365 --numstat --format='' -- docs/decisions/D84-*.md
27      3       docs/decisions/D84-anchor-artifact-limits-permanence.md
$ git show 3d47363 --numstat --format='' -- docs/decisions/D84-*.md
37      0       docs/decisions/D84-anchor-artifact-limits-permanence.md
```

- **Correction 1 (`5994365`, 2026-07-28)** *replaced the wrong text in the
  body*. Rule F4 went from `full freeze procedure (Q19).` to
  `full freeze procedure (**Q27** — see the 2026-07-28 correction below).`, and
  Consequences item 3 likewise; then a dated section was appended quoting the
  original error verbatim. Three body lines were deleted. The parent's `Status:`
  read `RESOLVED`.
- **Correction 2 (`3d47363`, 2026-07-28)** *appended only*. Its subject — the
  first correction's *"three sites"* and *"correcting it here corrects it
  everywhere"* — was left standing in the body, and is still standing today.

**And that difference has already misled readers.** D113's and D114's wave-13
amendments both describe the precedent as *"the appended-correction mechanism
`D84` established"* / *"D84's appended-correction mechanism, **not a body
edit**"*. That is a correct reading of correction 2 and a false statement about
correction 1, which is the one that established the practice. The append-only
half was quoted; the replace half was not read. **This is the failure mode the
append-only arm produces**, demonstrated on its own founding document.

### 1.2 *"The register row"* is three rows, and the one the row names is 29 records behind and read by nothing

`docs/decisions/README.md:1-5` opens:

> Numbered records of project-shaping decisions. One file per decision;
> statuses here mirror the files. A decision is changed by editing its file
> with a new dated entry, never by silently rewriting history.

```
$ ls docs/decisions/D*.md | wc -l
98
$ grep -c '^| \[D' docs/decisions/README.md
69
$ comm -13 <(grep -o '^| \[D[0-9]*' docs/decisions/README.md | grep -o 'D[0-9]*' | sort -u) \
           <(ls docs/decisions/D*.md | sed 's#.*/\(D[0-9]*\)-.*#\1#' | sort -u)
D100 D101 D102 D103 D104 D105 D106 D107 D108 D109 D110 D111 D112 D113 D114
D115 D116 D53 D54 D55 D56 D57 D58 D59 D60 D61 D97 D98 D99      (29 ids)
```

The missing set is **not** only D97–D116 as reported: it also contains **D53–D61**,
nine records from M2's first planning round, absent since `6e23622`
(**2026-08-02**, eight days). Zero README rows point at a file that does not
exist, so the register is purely **incomplete**, never dangling — which is the
failure mode that never raises.

```
$ git log -1 --format='%h %ad %s' --date=short -- docs/decisions/README.md
d82f72e 2026-08-06 A21: the M2 tamper matrix completes, ...
$ git grep -n "decisions/README" -- scripts/ .github/ | wc -l
0
```

The last commit to touch it was not a register update, and **no script and no CI
workflow reads it**. The machine-read register is `TODO.md`'s:

```
$ grep -cE '^- \[[ x]\] \*\*D[0-9]+\*\*' TODO.md
116
$ comm -13 <(grep -oE '^- \[[ x]\] \*\*D[0-9]+\*\*' TODO.md | grep -oE 'D[0-9]+' | sort -u) \
           <(ls docs/decisions/D*.md | sed 's#.*/\(D[0-9]*\)-.*#\1#' | sort -u)
                                                        (empty — nothing missing)
```

116 rows, 116 distinct ids, **zero decision files missing**, and
`check_decisions()` bounds every `D<n>` citation against it via
`allocated_decision_ids()` (`scripts/check-traceability.py:568`).

A third register exists inside the documents:

```
$ grep -l '^## Index row' docs/decisions/D*.md | wc -l
33
$ for f in $(grep -l '^## Index row' docs/decisions/D*.md); do
    id=$(basename $f | sed 's/\(D[0-9]*\)-.*/\1/')
    grep -q "^| \[$id\]" docs/decisions/README.md || echo $id; done | wc -l
27
```

**27 of the 33 `## Index row (orchestrator applies at merge)` sections have
never been applied.** They are unexecuted instructions sitting inside resolved
bodies.

**Consequence for the arm.** *"Only the register row moves"* names an act with
three possible targets: a complete machine-read list, a 29-records-behind list
nothing reads, and 33 in-body copies of which 27 were never merged. An arm whose
mechanism is already 29 records behind is not the safe arm merely because it
edits nothing.

### 1.3 On Q122's own forcing case, the register row is inside the body

```
$ git grep -n "is_verified" | grep -c .
21
$ grep -n '^## Index row' docs/decisions/D95-*.md
347:## Index row (orchestrator applies at merge)
```

D95's register row exists verbatim in **three** places: `docs/decisions/README.md:81`
(the applied copy), `TODO.md:788` (the register copy), and
`D95-sealer-recorded-anchor-metadata-in-the-report.md:349` — **inside D95's own
body**, under `## Index row` at `:347`. All three carry the stale
`is_verified` figure.

So on the exact case Q122 was filed over, *"only the register row moves"*
requires editing (a) a file nothing reads, (b) the tracker, and (c) **the
resolved body it forbids editing**. The arm contradicts itself on its own
forcing case. It cannot be executed as stated.

### 1.4 *"Bodies are immutable history"* is not the status quo — it would reverse 30 executed instances

```
$ git log --diff-filter=M --format='%H' -- 'docs/decisions/D*.md' | wc -l
48
$ ... (per-commit numstat, deletions > 0) ...
28
$ git log --diff-filter=M --numstat --format='' -- 'docs/decisions/D*.md' | awk '{s+=$2} END{print s}'
132
```

48 commits modified an already-committed decision file; **28 of them deleted at
least one line**; **132 body lines** have been deleted, spanning **2026-07-27 to
2026-08-10**. Resolving the file's `Status:` at each mutation's *parent* commit:

| status at parent | (commit, file) pairs |
| --- | --- |
| `RESOLVED` | **30** |
| `OPEN` | 2 (D83, D1) |
| `RECOMMENDED` | 2 (D13, D14) |
| resolved, different field spelling | 1 (D98 — `- **Status**: Resolved 2026-08-06`) |

The project names the practice in its own commit subjects: *"Amend D90 with what
executing it falsified"* (`6efb0d7`), *"Amend D61 and D58 where implementation
contradicted them"* (`f6ff43c`), *"Correct the two-day claim **at source** in
three places"* (`49df1e9`), *"Merge the root-store lane's corrections **at
source**"* (`ad46895`), *"docs: amend D83, R36/R37 and G24 **at source**"*
(`69e76a5`).

**And the practice is institutional, not incidental.** Nine resolved decisions
carry a section whose entire content is instructions to edit other documents'
bodies — D53 §11, D56 §11, D60 §9, D91 §11, D92 §10.4, D93 §13, D94 §9, D97 §6,
D100 §6, all spelled *"orchestrator applies at source"*. Their instructions
target resolved decisions by name:

- **D94 §9a**: *"**Replace**, in `docs/decisions/D84-…md:245-251` (inside the §7
  blockquote…)"* — a replace inside D84's **freeze-boundary** block. Executed at
  `5f758de` (D84 +21/−12); `D84:260` now carries the replacement text.
- **D93 §13.1**: *"**Replace the O3–O9 block**"* in D56, with a prescribed dated
  attribution above it. Executed; `D56:271` now reads *"**Amended 2026-08-06 by
  [D93](…) §4/§5.** As first written this list placed **O4 above O6 and O7**,
  which…"*.
- **D93 §13.3**: *"**D56 §1, ground 3 — delete it.**"* Executed at `D56:84-95`,
  as a **strike with a dated attribution and the reason kept**:
  `3. ~~**The tamper matrix is already committed to it.** …~~ — **DELETED
  2026-08-06 by [D93](…) §4.3. This ground was never available.** …`
- **D91 §11.1-2**: amend D58 §10.4's count and D56 §5's rule O2.
- **D100 §6.5**: *"`docs/decisions/D97-…md` §2 K1 — **append** the rider drafted
  in §5"*.

The immutable-body arm is therefore not the conservative reading of this
project's practice. It is a proposal to reverse nine documents' worth of
standing instructions and thirty executed edits.

### 1.5 The rule already exists, and it is on the lean's side

`docs/decisions/README.md:3-5`, unchanged since the register was created:

> **A decision is changed by editing its file with a new dated entry, never by
> silently rewriting history.**

Three properties of that sentence decide Q122 without further argument:

1. It rules **for** body corrections. *"Changed by editing its file"* is the act
   the row asks about.
2. Its prohibition is on **silence**, not on change. *"Never by silently
   rewriting"* forbids an unmarked edit, which is precisely the harm the
   immutable-body arm is reaching for.
3. It requires **a new dated entry** — the correction section — as the vehicle.

Q122's row cites this exact file, at `:81`, for the stale `is_verified` figure,
and does not cite its opening. The row asks a question its own cited file
answered eleven days earlier.

### 1.6 Five in-place forms are already executed, and none of them is normative

```
$ grep -n '^#\{1,4\} .*\(Correction\|Amendment\|Erratum\|Addendum\)' docs/decisions/*.md | wc -l
… 38 documents carry at least one
```

At least **thirteen** distinct heading spellings are in use, and they name
**three semantically different acts**:

| act | example | count |
| --- | --- | --- |
| (α) post-resolution correction of **this** document's body | `## Correction — 2026-07-28 (A27 implementation)` (D84); `## Amendment from F30 (2026-07-28, M0 wave 7) — …` (D10, ×4); `## Amendment — the owner-field census is wrong…, 2026-08-10` (D113) | ~24 documents |
| (β) instructions to edit **other** documents at source | `## 9. Amendments (orchestrator applies at source)` (D94); `## 11. Corrections to existing prose (orchestrator applies at source)` (D53/D56/D91) | 9 documents |
| (γ) corrections to the **register row that framed** the decision, written at authoring time | `## The register's framing, corrected` + `### Correction 1 — …` (D59, D61, D74, D75, D89) | 5 documents |

**This is D113 §1.2's four-spellings finding, one namespace over and at three
times the scale** — three different acts sharing two words, with no normative
form, in the document class whose job is to be evidence. Registered as
discovered work in §8.

The five in-place dispositions already executed in the tree:

| # | form | executed at | subject |
| --- | --- | --- | --- |
| 1 | **strike + dated attribution + reason kept** | `D56:84-95` (2026-08-06, D93 §4.3) | a withdrawn ground |
| 2 | **replace + dated attribution block above ("As first written…")** | `D56:271` (2026-08-06, D93 §4/§5) | a normative rule order |
| 3 | **replace + inline pointer to a trailing dated section** | `D84:166`, `:327` (2026-07-28, A27) | a cross-reference a lane would follow |
| 4 | **in-place count change + inline dated attribution + explicit no-renumber clause** | D98 rider 3c (`7bc746b`, wave 11) | a count |
| 5 | **pure append, body untouched** | `D84:374` (2026-07-28); D109/D113/D114/D115/D116's amendment sections | a falsified measurement |

All five are defensible. None was ruled. Q122 exists because nobody wrote down
which applies when.

### 1.7 Wave 13's four amendments never amended a committed body

```
$ git show 1c702d4 --numstat --format='' -- docs/decisions/
880  0  docs/decisions/D113-orphaned-decision-owner.md
899  0  docs/decisions/D114-line-123-citation-authority.md
873  0  docs/decisions/D115-entryless-row-reconstruction.md
1209 0  docs/decisions/D116-gate-and-sweep-coverage.md
$ git log --numstat --format='COMMIT %h' -- docs/decisions/D109-task-id-traceability-scope.md
COMMIT d23dccc
1041 0  docs/decisions/D109-task-id-traceability-scope.md
```

All four wave-13 documents were **created** by `1c702d4`, amendment sections
included; D109's `## Amendment — A117 became a real row` rode `d23dccc`, which
created D109. So each amendment's central claim — *"Recorded, not applied. The
body above is byte-unchanged"* — is true of a body git never held in any earlier
state. A reader running `git log -p` sees **one** authorship event and cannot
tell the amendment from the text it amends.

The restraint those lanes exercised was real and correct as *practice*. As
*evidence* it is vacuous, and this matters because the evidentiary value is the
entire argument for append-only. **The only real diffs against a committed
resolved body are D84's two and the wave-11 D98 edit** — and two of those three
replaced text.

**Consequence, ruled in §2.1(c):** a correction is only evidence if it lands in a
commit distinct from the text it corrects. Where it cannot (the correcting lane
and the authoring lane are the same wave), the correction section says so.

### 1.8 The count case was solved in wave 11, in place, and nobody registered it

```
$ git show '7bc746b^:docs/decisions/D98-status-anchor-state-vocabulary.md' | grep -n Status | head -1
3:- **Status**: Resolved 2026-08-06
$ git show 7bc746b --numstat --format='' -- docs/decisions/D98-*.md
29      1       docs/decisions/D98-status-anchor-state-vocabulary.md
```

The single deleted line is rider 3c's opening. The diff:

```
-3c. **Three predicates currently share the word UNANCHORED and must not be
+3c. **Four predicates currently share the word UNANCHORED and must not be
+**Extended from three to four by D108 R2** (Q129, 2026-08-09), which found the
+fourth in frozen normative text. …
+**This rider is not renumbered**: it stays 3c with four rows, so every existing
+citation of "D98 rider 3c" — `listing.rs`, `engine.rs`, `status.rs`,
+`status_command.rs`, Q120, Q129 — keeps resolving.
```

A **count** in a **resolved** body, corrected **in place**, with the amending
authority, its task and its date beside the number, the new domain stated as a
table, and the identifier explicitly pinned with its six citation sites named.
That is Accept bullet 3's case, answered, one wave before four lanes recorded
the opposite rule as though no precedent existed. §2.5 generalises it.

### 1.9 A correction's line numbers go stale faster than the claim it corrects

`tasks/R.md:797` is the correction to Q122's forcing case, written **2026-08-07**:

> `crates/antseal-cli/src/status.rs:594` (`fn source_label`) chooses between
> *"verified by this run"* and … and `status.rs:610` emits
> `"verified": source.is_verified()` in the `--json` envelope.

```
$ git grep -n "is_verified" -- '*.rs'
crates/antseal-cli/src/status.rs:44        (doc comment; R.md says :43)
crates/antseal-cli/src/status.rs:717       (fn source_label; R.md says :594)
crates/antseal-cli/src/status.rs:733       (--json "verified"; R.md says :610)
crates/antseal-cli/src/status/tests.rs:356 (R.md says :354)
crates/antseal-cli/src/status/tests.rs:382 (R.md says :380)
crates/antseal-core/src/anchor/model.rs:636
crates/antseal-core/src/anchor/model.rs:1255
crates/antseal-core/src/anchor/verdicts/tests.rs:1235
                                                     → 8 hits, exactly as claimed
```

The **figure** is right. **All five of its locators are wrong**, two of them by
123 lines, three days after they were written. The claim they corrected took a
full wave to go stale; the correction took three days. D115's own amendment
found the same shape from an unrelated instance and called it *"the argument for
extending the no-line-number rule beyond the frozen registry, made by the tree
rather than argued"* (registered as `Q169`). §2.6 makes it a rule.

Section citations are the stable alternative, and their volume is why:

```
$ git grep -oE 'D[0-9]+ ?§[0-9]+' -- '*.md' '*.rs' '*.py' '*.sh' | wc -l
2938
$ git grep -ohE 'D[0-9]+ ?§' … | grep -oE 'D[0-9]+' | sort -u | wc -l
63
$ git grep -onE 'D[0-9]+[-a-z0-9]*\.md:[0-9]+|\bD[0-9]+:[0-9]+' -- '*.md' | wc -l
82
```

**2938 section citations across 63 decisions** against **82 line citations**.
Renumbering a section is a 2938-wide blast radius; that is why §2.4 makes
section identifiers immovable rather than merely discouraged.

### 1.10 The immutable-body arm exists in the tree, unregistered, and has already cost two rulings

`tasks/Q.md:1407`, in Q109's entry:

> **`D94:554-555` still reads *"three of A22's four Accept rows"* and is not
> corrected — **a ruled record is immutable**; the drift is recorded here.**

Measured today, `D94:554-555` still reads *"…which are three of / A22's four
Accept rows."*, and A22 has **three** Accept rows. Two resolved decisions ordered
it fixed:

- **D101 §2.2 / §7**: *"And amend `tasks/Q.md:1373`, `TODO.md:529` and
  `D94:554-555` to 'three of A22's…'"* (`D101:249`, and its edit-set table at
  `:859`).
- **D103 §7.2 RULING 6a**: the same instruction, re-issued (`D103:634`, `:851`).

Neither was executed. A lane applied `tasks/Q.md:1407`'s rule instead — a rule
that is registered nowhere, cites no authority, and contradicts
`docs/decisions/README.md`'s opening sentence.

**This is the strongest single fact in this decision.** Q122's row lists four
stale sites and misses the fifth, which is the only one where the immutable-body
arm was actually applied and the only one where the cost is already paid: two
rulings ignored, and a wrong count still cited by line number in five places.

---

## 2. The ruling

### 2.1 A resolved decision's body takes dated corrections

**RULING 1.** A resolved decision's body **may and must** take dated
corrections. What is forbidden is a **silent** change. This ratifies
`docs/decisions/README.md`'s opening sentence, D84's two corrections, D93's
executed instructions against D56, the wave-11 D98 edit and the nine
*"orchestrator applies at source"* sections, and it **refuses**
`tasks/Q.md:1407`'s *"a ruled record is immutable"*, which §5.4 corrects.

Three sub-rules follow immediately.

**(a) A correction never replaces the record of what was believed.** Whether the
wrong text is struck or replaced, the original wording survives **verbatim** —
at the site if struck, in the correction section if replaced. A correction that
leaves no way to read the original sentence is a rewrite and is refused.

**(b) The register row is not a substitute.** Moving a register row alone is
never a discharge of a body error, for the three reasons measured in §1.2–§1.3:
there are three registers, one is 29 records behind and read by nothing, and one
lives inside the body.

**(c) A correction is evidence only if it is separable from its subject.** Where
the correction lands in a different commit from the text it corrects, nothing
more is needed. Where it cannot — the authoring lane and the correcting lane are
the same wave, as in §1.7 — the correction section **states that**, in one
sentence, so no future reader mistakes a same-commit amendment for a diff
against a published record.

### 2.2 RULING 2 — the correction section

Every correction is recorded in a **dated section appended to the document**,
and that section is the **single home** of the new fact.

- **Placement**: after `## Outcome` and after `## Index row`, in date order.
  Never inserted into the argued body. Never renumbered.
- **Heading form**, normative from this decision forward:
  `## Correction — <the clause that is wrong, in words>, <YYYY-MM-DD>`
  Use `## Amendment — …` only when the change *adds* a ruling rather than
  correcting a statement. Do not use `Erratum`, `Addendum`, `Postscript`, or
  the bare `(orchestrator applies at source)` heading — that spelling is
  reserved for act (β), instructions against **other** files (§1.6).
- **Required content**, in this order:
  1. the corrected sentence **quoted verbatim**, with its section identifier;
  2. the measured fact, with **the command that measured it and its output**;
  3. the **authority** — the task or decision id and the lane that found it —
     and whether the correction lands in a commit separate from its subject
     (§2.1(c));
  4. **which rulings still stand**, stated explicitly and in the direction the
     error moves them. D113's amendment does this correctly (*"Every error above
     runs in the direction that strengthens the refusal … RULINGS 1 and 2
     stand"*) and it is the model.
- **What it may not contain**: a new ruling. A correction states what is false.
  A change of decision needs a new decision.

### 2.3 RULING 3 — what happens to the sentence that is wrong

The row poses this as one question. It is two, and the answer turns on **what
kind of sentence is wrong**.

> **The test: would a lane act on this sentence?**

**(a) If yes — REPLACE.** Rules, constants, table rows, cross-references, edit
sets, prescribed text: anything a reader would execute. A rule left visibly
wrong is a rule somebody executes anyway, and the strike is not load-bearing at
the moment of execution. The replacement carries an inline dated marker; the
original wording is quoted verbatim in the correction section. Precedents: D84's
rule F4 (`5994365`), D56 §5's rule order (`D56:271`), D94 §9a's replacement of
D84 §7's row.

**(b) If no — STRIKE, and leave it standing.** Measurements, censuses,
arguments, rationales, discovered-work descriptions, anything already executed:
the sentence's value *is* the record of what was believed. Strike it with `~~ ~~`
and put a dated marker immediately after. Precedent: `D56:84-95`.

**(c) The marker carries at most one scalar.** A struck or replaced span may
carry the corrected **value** inline when that value is a single count, id or
name; anything longer is a pointer to the correction section and nothing else.
Rationale, measured: two homes for one value is the defect this tracker keeps
finding (`Q166`; D115 §3.2 rules it for `Size`), and §1.1 is what happens when
an argument lives in two places and only one is read.

**(d) Marker form**, normative:

```
~~<the wrong text>~~ — **Corrected <YYYY-MM-DD> by [D<n>](D<n>-slug.md) §<s>**;
see "Correction — <clause>, <YYYY-MM-DD>" below.
```

with `DELETED` in place of `Corrected` when the claim is withdrawn rather than
restated (`D56:84`'s executed form).

**(e) A correction is never applied by a lane that did not measure it.** If a
lane finds an error in a document it is not executing, it records the finding in
its own report and the correction is made by the owning wave. §1.10 is what
happens when an instruction to correct is issued by one document and executed by
nobody.

### 2.4 RULING 4 — three things that never move

1. **Section, rule, ruling and rider identifiers.** `§8 (iii)`, `RULING 3c`,
   `rider 1c`, `F4`, `O4` stay where they are, whatever happens to their text.
   Measured justification: **2938** `D<n> §<n>` citations across **63**
   decisions (§1.9). D98's *"This rider is not renumbered"* clause is the
   executed precedent and its shape — **name the citing sites** — is required
   whenever a correction changes the content of an identified unit.
2. **Text inside a drift-checked marker block.** D84 §7's `FREEZE-BOUNDARY`
   block is compared byte-for-byte across two files by
   `check-traceability.py --freeze-boundary`. A correction inside such a block
   is not a body edit; it is a **two-file byte-identical replacement in one
   commit**, exactly as D94 §9a specified it, and `--freeze-boundary` must be
   green in the same commit.
3. **Frozen normative text.** Anything covered by `testdata/vectors/v1/FROZEN.sha256`
   or the frozen registry is **refused at the body** and goes to
   `docs/format/frozen-registry-errata.md` per D108 §3. This decision does not
   reopen that.

### 2.5 RULING 5 — when the correction and the original disagree about a count

Both known instances are counts, and a count is what goes stale silently
because it records a measurement without recording what was measured. A count
correction states **five** things; one that omits any of them is not a
correction:

1. **the original figure, quoted**, with its section;
2. **the new figure**;
3. **the predicate, in words, and the command that produced the new figure** —
   never a bare number. *"8 hits"* is not a correction; *"8 hits over
   `git grep -n is_verified -- '*.rs'`, of which 2 are production"* is. Measured
   justification: Q122's own row says the stale figure is live in *"four
   documents"* and is wrong in both directions (§4) precisely because it counted
   *documents* and never wrote the predicate down;
4. **which of two defects it is** — *wrong when written* or *went stale* —
   because they have different consequences. *Wrong when written* impugns the
   argument that rests on the number (D113 §1.2's `55`, measured 41). *Went
   stale* impugns the practice of writing bare counts and nothing else (D95's
   `3`, correct on 2026-08-06, stale on 2026-08-07; D109 §8 (iii)'s `thirteen`,
   correct when written and stale within the wave);
5. **whether the conclusion resting on the count survives**, stated in the
   direction the error moves it.

**Tie-break, for when the two figures cannot be reconciled**: the figure with a
reproducible command wins, and the other is struck. If neither has one, both are
struck and the correction says the value is unmeasured — three independent
counts of one corpus producing three answers is exactly what D113's amendment
found, and recording a fourth guess would have been worse than recording none.

**Epoch rule.** A count over a mutable corpus is meaningless without the commit
it was taken at. A corrected count therefore names its epoch — `at 5fbc48d` — or
is expressed as a command a reader can re-run. §6's character-range correction
is written this way and is reproducible today only because of it.

### 2.6 RULING 6 — no line numbers in a correction

A correction cites by **section, heading, symbol, marker or test name — never by
line number**. This extends `docs/format/`'s existing no-line-number rule (which
`check-traceability.py --decisions` enforces for the registry) to
`docs/decisions/` and `tasks/` **as a convention**, not as a check: `check_decisions()`
sweeps `CITATION_SCAN = ["crates", "docs/format", "docs/testing", "scripts"]`
and `docs/decisions/` is deliberately outside it (D109 §3.3), so there is
nothing to extend mechanically without re-opening that exclusion.

Measured justification is §1.9: the correction's own locators went stale in
three days while the claim they corrected took a wave. Where a line number is
genuinely the only handle, it is written **with its epoch** — `` `status.rs:717`
at `95fcee0` `` — so a reader knows to re-measure rather than trusting it.

### 2.7 What a correction may not do

- It may not **renumber** anything (§2.4).
- It may not **delete** the original wording from the record (§2.1(a)).
- It may not introduce a **new ruling** (§2.2).
- It may not be applied by a lane that did not measure it (§2.3(e)).
- It may not silently change a **frozen** byte (§2.4.3).

---

## 3. The arm this decision was charged to build, and the three measurements that kill it

The brief asked for the strongest case that only the register row moves and
bodies are immutable history. It is a good case and it is worth recording in
full, because two of its three premises are true.

**Premise 1 — decisions are evidence, and the reasoning is the product.** True,
and this decision ratifies it: §2.1(a) makes the original wording survive every
correction, which the append-only arm secures and which a naive replace does
not. **This premise does not require immutability; it requires non-erasure**,
and §2.3(b) gives it the stronger form — strike-in-place beats append, because
the reader arrives at §4, not at the end of the file.

**Premise 2 — citation stability.** True, and measured: 2938 section citations
across 63 decisions (§1.9). D109's own amendment states the reason correctly:
*"renumbering a resolved decision's prose breaks every citation into it."* **This
premise argues for RULING 4, not for immutability** — it constrains identifiers,
which nothing in a text correction needs to touch.

**Premise 3 — the register row is the cheap, safe place.** **False, three times
over**, and this is what decides it:

1. **There is no single register row.** Three registers, one 29 records behind
   and read by zero scripts, one complete and machine-read, one duplicated into
   33 bodies of which 27 were never applied (§1.2).
2. **The register row is inside the body** on Q122's own forcing case (§1.3), so
   the arm requires the act it forbids.
3. **Register rows are copies of the body's own summary**, so an arm that
   corrects only the row creates the divergence it exists to prevent: after a
   row-only correction, `README.md:81`, `TODO.md:788` and `D95:349` say one
   thing and `D95` §4 and §7 say another, in the same repository, about the same
   number.

**And the arm has been tried.** §1.10: `tasks/Q.md:1407` applied it, in those
words, and the result was two resolved decisions' instructions ignored and a
count still wrong three days later. The arm's cost is not hypothetical; it is
the only part of this question with a measured price.

**What the lean's own stated reason gets wrong.** The row says D84 §2 has a
mechanism that fits. §2 has nothing, the mechanism is two mechanisms, and they
disagree about exactly the thing Accept bullet 1 asks (§1.1). So **the lean
survives and its stated reason does not.** What saved it is §1.4 — 30 executed
resolved-body edits, nine standing at-source instruction sections, and a
delete-a-ground order that was carried out — together with §1.5, the rule
already written in the register's own opening. The lean did not survive on D84.
It survived on the git history and on a sentence nobody had read.

---

## 4. Scope: the stale `is_verified` sites — a follow-on, with the domain re-measured here

**Accept bullet 2 requires this decision to say whether the four stale sites are
in scope of Q122 or of a follow-on. They are a FOLLOW-ON.** The reason is a
measurement, not a preference, and the row's own domain is wrong in both
directions.

**The row says**: *"the same stale figure is now live in **four** documents —
D95 §4 and its register row, `docs/decisions/README.md:81`, D98:240, and
TODO.md:470 and :704."*

**Measured 2026-08-10** (`git grep -n is_verified`), the stale-figure sites are:

| # | site | text | named by the row? |
| --- | --- | --- | --- |
| 1 | `D95` §4 | *"Repo-wide, `is_verified` has **three** hits — its own definition and two tests"* | yes |
| 2 | `D95` §7 *Measured vs. assumed* | *"`is_verified`: 3 repo-wide hits, all definition-or-test"* | **no** |
| 3 | `D95` `## Index row` | the register row, inside the body | not as such |
| 4 | `docs/decisions/README.md:81` | the applied copy of row 3 | yes |
| 5 | `TODO.md` (D95's register row) | the register copy of row 3 | as `:704` |
| 6 | `D98` §"what was measured" | *"`is_verified` re-measured: **3 repo-wide hits**"* | yes |

**Six statements in four files**, of which **three are the same register row in
three homes**. And one site the row calls stale is **not**: `TODO.md`'s R74 row
(the row's `:470`) already carries its own dated in-place correction — *"This
row's `is_verified` has 3 repo-wide hits, all definition-or-test is measurably
wrong: there are 8, two of them production"*. **Both of the row's `TODO.md` line
numbers have moved** (`:470` → `:494`, `:704` → `:788`); `README.md:81` and
`D98:240` still hold. A seventh site of a different class exists at `D98`
§1b — *"`is_verified` gains its first non-test caller"*, a prediction that has
since come true; predictions are not corrected, they are discharged, and that is
out of scope here.

**Why a follow-on.** Three of the six are one register row in three homes, and
one of those homes is `docs/decisions/README.md`, which is missing **29 records**
(§1.2). Correcting a word in a register that is 29 rows short — and would be the
only edit that file has received since 2026-08-06 — repairs the symptom and
certifies the wreck. The follow-on must first answer whether `README.md` is a
register or dead weight, because that decides whether the row is corrected in
three places or in two. **That is a question about the register, not about
whether bodies take corrections**, and Q122's Accept asks this decision to *say
which*, not to do it.

**What the follow-on inherits, so it does not re-derive it**: the six sites
above; the classification under §2.3 (all six are **measurements**, therefore
**strike**, not replace); the count rule §2.5 (the figure went **stale**, it was
not wrong when written — D95's `3` was correct on 2026-08-06 and the two
production callers landed at U23 in wave 8 under D98 rider 1c); the predicate
and command (`git grep -n "is_verified" -- '*.rs'` → 8, of which
`status.rs`'s `source_label` and the `--json` `"verified"` key are production);
and **the requirement that `tasks/R.md`'s existing correction be re-cited by
symbol**, because all five of its line numbers are stale (§1.9).

---

## 5. The rest of the parked set, and which arm each lands under

### 5.1 Q167 — D115 §3.5 vs §4: **lands under §2.3(a), REPLACE**

`Q167`'s `Notes` gate it on Q122 explicitly, and its two branches are stated: *"If
Q122 rules that a dated amendment is permitted, this is one amendment and one
sentence; if it rules that only the register row moves, the ratification lands in
the register row and the body's contradiction stands with a pointer to it."*

**It is the first branch.** D115 §3.5 states a *"exact form"* and a placement that
a lane executes — `Q135` will execute it twenty more times. Under §2.3's test the
answer is unambiguous: a lane would act on this sentence, so it is **replaced**,
not struck. The correcting lane:

1. replaces §3.5's *"immediately after `Accept`"* with §4's placement (after
   `Notes`), carrying the inline dated marker of §2.3(d);
2. quotes §3.5's original wording verbatim in a
   `## Correction — the provenance bullet's placement, <date>` section, with
   the measurement that decides it (all twelve entries lane C wrote place the
   bullet after `Notes`; the tree is consistent and the ruling was not);
3. does **not** renumber §3.5 or §4 (RULING 4) — D115 §3.5 is cited by `Q167`'s
   own row and entry;
4. states that D115's existing `## Amendment — the document contradicts itself…`
   section recorded this and did not apply it, and that §2.1(c) applies: D115's
   body and its amendment share one commit (`1c702d4`).

The next lane executes it; this decision does not, because the brief reserved it.

### 5.2 D114 §7 bullet 2 — `DECISION_SCAN`/`TASK_SCAN`: **lands under §2.3(b), STRIKE**

The bullet describes deleted constants as live. Measured:

```
$ grep -nE '^CITATION_SCAN|^CITATION_SUFFIXES|^CITATION_SCAN_SELF' scripts/check-traceability.py
506:CITATION_SCAN = ["crates", "docs/format", "docs/testing", "scripts"]
507:CITATION_SUFFIXES = {".rs", ".md", ".json", ".py", ".sh", ".mjs"}
527:CITATION_SCAN_SELF = "scripts/check-traceability.py"
```

`DECISION_SCAN`, `DECISION_SUFFIXES`, `TASK_SCAN`, `TASK_SUFFIXES` and
`TASK_SCAN_SELF` were deleted by Q133 (2026-08-10), not aliased. D114's own
amendment already records this and registers `Q176`/`Q151`; what is missing is
the **marker at §7**, which §2.3(b) now permits — the bullet is a description of
a scan surface, nobody executes it, and its **third clause is still true**, so
the strike is partial and the true clause stays unstruck. Owner: `Q151`, whose
`Notes` already name this as blocked on Q122; it is unblocked.

**Note for that lane, and it is a trap**: `D109`'s body names the deleted
constants **13 times**, including prescribed code blocks at R2/R3. Those are a
**record of what was proposed**, not a description of the present, and under
§2.3(b) they are **not** corrected — striking them would falsify the record of
what D109 specified. `check-traceability.py:662-663` names the same constants as
deleted, correctly. This is exactly the present-vs-past distinction `Q151`'s `Do`
says it must solve before writing a check, and D109 is the counterexample that
proves the check cannot be *"every backticked identifier must resolve"*.

### 5.3 D101 §3.4 — A108's parked blast-radius correction: **unblocked; §2.3(b), STRIKE**

A108's entry parks it: *"**Correcting D101 §3.4's body is blocked by Q122** …
Until Q122 rules, the correction lives here and in the A26 bullet. Do not
silently edit D101."* It is unblocked. §3.4's claim is a **measurement** (a
signer-DN rendering change moves two frozen files, one hatched and one not);
A108's entry measured **one** file, unhatched. Under §2.3(b) it is struck with a
dated marker, and the correction section carries A108's measurement with its
command. §2.5 does not apply — this is a set membership claim, not a count over a
mutable corpus, and it was **wrong when written**, which the correction states.
Owner: `A108`, whose `Accept` already requires the corrected sentence.

### 5.4 `D94:554-555` and `tasks/Q.md:1407` — the instance the row missed

§1.10. Two resolved decisions ordered `D94:554-555` corrected; neither
instruction was executed; the reason given is `tasks/Q.md:1407`'s *"a ruled
record is immutable"*, which RULING 1 now refuses. Under §2.3 the D94 sentence is
a **measurement** and is **struck**, and D103 §7.2 RULING 6a's own instruction —
*drop the count rather than correct it*, because A22's Accept is now numbered
1–4 — is what the correction applies. `tasks/Q.md:1407`'s sentence is itself
corrected in the same act: the claim *"a ruled record is immutable"* is false and
is the reason two rulings went unexecuted. **This is not registered anywhere and
is the most consequential unregistered item this decision found.**

### 5.5 D109 §8 (iii) — executed here, §6

---

## 6. The exercise: D109 §8 (iii), corrected in this commit

Accept bullet 4 requires one real correction, *"so the mechanism is exercised
rather than described. An unexercised procedure is the shape D94 §4 already
found blind once."* The chosen subject is **D109 §8 (iii)**, for four reasons:
it is the correction **D115 §3.7 explicitly declined**, naming Q122 as its
blocker and calling it *"the sharpest possible demonstration that Q122 is real
work"*; it carries **both** of the classes this decision must handle — a count
and an attribution; its Accept has already been executed (Q134 closed
2026-08-10), so it is unambiguously a **record**, which exercises §2.3(b) rather
than the easier replace path; and it is cited by four live documents, which
exercises RULING 4.

**Classification under §2.3:** §8 (iii) is a discovered-work description whose
work is done. Nobody will act on it. → **STRIKE**, with scalar corrections inline
per §2.3(c).

**Five claims are wrong, and each is measured below.**

**(1) The count.** *"Thirteen open rows"* → **twelve**. `Q130` drained at wave
12's bookkeeping. **Went stale**, not wrong when written.

**(2) Membership.** The list names `Q130`, which had left.

**(3) The character range.** *"386–2 193 characters"* → **386–1 735**; 2 193 was
`Q130`'s. **Went stale by the same event as (1)** — the range was inherited from
the same sentence and not re-measured when the count was. Reproduced here, with
its epoch, per §2.5:

```
$ git show 5fbc48d:TODO.md > /tmp/todo.md
$ for id in A72 A74 A76 A105 A108 Q88 Q89 Q122 Q123 R60 R76 U39; do
    grep -E "^- \[[ x]\] \*\*$id\*\*" /tmp/todo.md | head -1 | tr -d '\n' | wc -m; done | sort -n | sed -n '1p;$p'
386
1735
$ grep -E '^- \[[ x]\] \*\*Q130\*\*' /tmp/todo.md | tr -d '\n' | wc -m
2193
```

Note `wc -m`, not `wc -c`: the rows carry em-dashes and typographic quotes, and
`wc -c` gives 392–1748 / 2217. A count without its command is not reproducible,
which is RULING 5(3) demonstrated on this decision's own exercise.

**(4) The routing reason for A105 and A108 — an attribution, and wrong when
written.**

```
$ git grep -n "second-hand in three places that disagreed"
TODO.md:464:  … **A106** … the row was defined second-hand in three places that disagreed …
```

The phrase is **A106's**, in A106's own closing text. No Current-focus sentence
says it of A105 or A108. D109 §2 (b) attributes it to A106 correctly; §8 (iii)
misattributes it, and Q134's row and entry inherited the error from §8 (iii). The
conclusion the false premise supports is wrong too: by the `Do`/`Accept` measure
D115 §1.4 applied, **A108 is better specified than `A72`, `A74` and `R60`**,
which §8 (iii) routes to the lint lane.

**(5) The reformat claim, and the Accept's atomicity clause.** *"substantially a
reformat rather than an invention"* is **3 of 12, not 10 of 2** — only `Q123`,
`R76` and `U39` carry both a `Do` and an `Accept` — so **nine of twelve needed an
`Accept` authored**, which §2 (b) of the same document forbids a lint lane to do
silently. And *"deleting a register line and adding an entry are the same
commit"* is true **per row** and false **per batch**: D115 §3.8 measured 10-of-12
green on `--task-entries`, the no-flag run and `--self-test`, with either half of
one row's drain red.

**Which rulings stand (RULING 2, required content 4).** All of them. Every error
runs in the direction that *strengthens* §8 (iii)'s conclusion — the set is
smaller, the rows are shorter, and **more** of them needed authorship rather than
reformatting, so the case for routing this away from a lint lane is stronger than
the record makes it, not weaker. §2 (b)'s prohibition is untouched, and (iii)'s
split from (iv) stands.

**Identifier discipline (RULING 4).** `(iii)` is **not renumbered**. It is cited
by `TODO.md`'s Q134 row (*"discovered by D109 §8(iii)"*), `tasks/Q.md`'s Q134
entry, D115's front matter (`Corrects:`), and D115 §1.4 and §3.7.

**Separability (§2.1(c)).** This correction lands in a commit distinct from
`d23dccc`, which created D109. It is the first correction in this project's
history to satisfy §2.1(c) by construction rather than by accident.

**What landed**: strike markers and inline scalars at D109 §8 (iii); one pointer
sentence closing the bullet; and
`## Correction — §8 (iii)'s census, reformat claim, routing reason and atomicity
clause, 2026-08-10` appended after the existing `## Amendment — A117 became a
real row` section, in date order.

---

## 7. What this decision does not do

- **It does not add a check.** `docs/decisions/` is outside `CITATION_SCAN`
  (D109 §3.3) for a reason D109 measured — including it fails 13 rows for ids a
  decision merely *proposes* — and this decision does not reopen that. Every
  rule here is a convention enforced by review. §8 records what a check would
  have to solve first.
- **It does not correct the six `is_verified` sites** (§4), `Q167` (§5.1),
  D114 §7 (§5.2), D101 §3.4 (§5.3) or `D94:554-555` (§5.4). Each has an owner
  and a stated arm.
- **It does not touch `TODO.md`** — the orchestrator owns it — and it mints no
  task ids. §8's discoveries are prose with evidence.
- **It does not move a frozen byte.** `check-traceability.py --freeze-boundary`
  is green before and after (§9).
- **It does not rule on the `## Index row` backlog** (27 unapplied, §1.2). That
  is a register question and §8 records it.

**Residual risks.**

1. **The heading form is a convention with no enforcement**, and §1.6 measured
   thirteen spellings already in the tree. This decision does not retrofit them;
   a future lane that does must not renumber, and must preserve the (α)/(β)/(γ)
   distinction rather than unifying three acts under one word.
2. **§2.3's test is a judgement call at the margin.** A discovered-work bullet
   whose Accept is *not* yet executed is a sentence a lane would act on, and
   therefore a replace. §8 (iv) of D109 is exactly that case today and is
   deliberately left alone: its eight rows are undrained.
3. **§2.1(c) cannot be satisfied retroactively** for D109/D113/D114/D115/D116's
   existing amendments. They stay as they are, with §1.7 as the record of what
   their claim actually means.

---

## 8. Discovered work — described, not numbered

*(The wave owner allocates and registers. No id is minted here.)*

**(i) `docs/decisions/README.md` is 29 records behind, read by nothing, and
declares a property it does not have.** — M2 · S. Its opening says *"statuses
here mirror the files"*; it carries 69 of 98, missing **D53–D61** (since
2026-08-02) and **D97–D116**. `git grep "decisions/README" -- scripts/ .github/`
→ **0**. Decide whether it is a register — in which case the 29 rows land and a
check compares it against `TODO.md`'s complete one — or whether it is superseded
by `TODO.md`'s register and should say so in its opening rather than claiming to
mirror. **This gates §4**, because three of the six stale `is_verified` sites are
one row living in this file, `TODO.md` and `D95`'s body. Accept: the file either
carries every `D*.md` or states that it does not and why, and the claim
*"statuses here mirror the files"* is true or gone.

**(ii) 27 of 33 `## Index row (orchestrator applies at merge)` sections were
never applied.** — M2 · S. They are unexecuted instructions inside resolved
bodies, indistinguishable from applied ones. Sibling of (i) and of `Q145`'s
class — a pointer whose target nothing verifies. Accept: either applied, or the
heading states the row is the document's proposal and not a claim about the
register.

**(iii) `tasks/Q.md:1407` asserts *"a ruled record is immutable"*, registered
nowhere, and it has already suppressed two rulings.** — M2 · S. §1.10. D101 §2.2
and D103 §7.2 RULING 6a both ordered `D94:554-555` corrected; neither ran. The
sentence contradicts `docs/decisions/README.md`'s opening and is now refused by
D117 RULING 1. **This is the highest-value item in this list**, because it is the
only measured instance where the immutable-body arm was applied and its cost is
already paid. Accept: `D94:554-555` is struck under §2.3(b) with D103 RULING 6a's
prescribed disposition (drop the count), and `tasks/Q.md:1407`'s rule sentence is
corrected in the same act.

**(iv) Three different acts share the words "Amendment" and "Correction", in
thirteen spellings, across 38 documents.** — M2 · S. §1.6: (α) correcting this
document, (β) instructing edits to *other* documents (*"orchestrator applies at
source"*, 9 documents), (γ) correcting the register row that framed the decision
at authoring time (5 documents). A reader — or a future check — cannot tell (α)
from (β) by its heading, and (β) sections are **instructions that may or may not
have been executed**, which is (ii)'s defect one section over. This is D113
§1.2's four-spellings finding in a second namespace. Accept: the three acts have
three distinct heading forms, and (β) sections carry an executed/not-executed
marker.

**(v) A "correction" whose subject is a *prediction* has no defined
disposition.** — M3 · XS. `D98` §1b's *"`is_verified` gains its first non-test
caller"* was a forecast; it came true at U23. It is neither stale nor wrong, and
striking it would be false. The class needs a **discharge** note, not a
correction, and nothing says so. Found while measuring §4's domain.

**(vi) Five of the correcting document's own line citations went stale in three
days.** — M2 · XS, and it is the measured form of `Q169`'s argument.
`tasks/R.md`'s `is_verified` correction cites `status.rs:594`/`:610`; measured
`:717`/`:733`. **A no-line-number convention that covers `docs/format/` should
cover corrections everywhere**, because a correction is read later than the text
it corrects, by definition. Overlaps `Q169`; file as its extension rather than a
new class.

---

## 9. Commands run for this decision, with verdicts

| # | command | verdict |
| --- | --- | --- |
| 1 | `grep -n '^#\{1,4\} ' docs/decisions/D84-*.md` | §2 is the permanence argument; corrections at `:353`, `:374` — **row falsified** |
| 2 | `git show 5994365 --numstat --format='' -- docs/decisions/D84-*.md` | **27 / 3** — correction 1 deleted body lines |
| 3 | `git show 3d47363 --numstat --format='' -- docs/decisions/D84-*.md` | **37 / 0** — correction 2 was pure append |
| 4 | `ls docs/decisions/D*.md \| wc -l` ; `grep -c '^\| \[D' docs/decisions/README.md` | **98** vs **69** |
| 5 | `comm -13 <(README ids) <(file ids)` | **29** missing: D53–D61, D97–D116 |
| 6 | `git grep -n "decisions/README" -- scripts/ .github/` | **0 hits** |
| 7 | `grep -cE '^- \[[ x]\] \*\*D[0-9]+\*\*' TODO.md` ; `comm -13` | **116 rows**, **0** files missing |
| 8 | `grep -l '^## Index row' docs/decisions/D*.md \| wc -l`, then README membership | **33** carry one; **27** never applied |
| 9 | `git log --diff-filter=M … \| wc -l`; per-commit deletion census | **48** modifying commits, **28** with deletions, **132** lines |
| 10 | `git show <c>^:<file> \| grep 'Status'` over all 34 (commit, file) pairs | **30 RESOLVED**, 2 OPEN, 2 RECOMMENDED |
| 11 | `git show 1c702d4 --numstat --format='' -- docs/decisions/` | D113 **880/0**, D114 **899/0**, D115 **873/0**, D116 **1209/0** — all created |
| 12 | `git log --numstat -- docs/decisions/D109-*.md` | **1041/0** at `d23dccc` — created |
| 13 | `git show '7bc746b^:…D98…' \| grep Status`; `git show 7bc746b --numstat` | `Resolved 2026-08-06`; **29 / 1** — a resolved-body count edit |
| 14 | `git grep -n "is_verified" -- '*.rs' \| wc -l` | **8** — R74's correction's figure holds |
| 15 | `sed -n '705,740p' crates/antseal-cli/src/status.rs` | `source_label` at `:716-722`, `is_verified()` at `:717`, `--json` key at `:733` — **all five of `tasks/R.md`'s locators stale** |
| 16 | `git grep -oE 'D[0-9]+ ?§[0-9]+' … \| wc -l` | **2938** section citations across **63** decisions |
| 17 | `git grep -onE 'D[0-9]+…\.md:[0-9]+\|\bD[0-9]+:[0-9]+' -- '*.md' \| wc -l` | **82** line citations into decisions |
| 18 | `sed -n '552,557p' docs/decisions/D94-*.md` | still reads *"three of A22's four Accept rows"* — **uncorrected** |
| 19 | `git grep -n "second-hand in three places that disagreed"` | the phrase is **A106's** (`TODO.md:464`) |
| 20 | `git show 5fbc48d:TODO.md` + `wc -m` over the twelve | **386–1735**; `Q130` = **2193** — D115's range reproduced |
| 21 | `grep -nE '^CITATION_SCAN\|^CITATION_SUFFIXES\|^CITATION_SCAN_SELF' scripts/check-traceability.py` | `:506`, `:507`, `:527` — the old names are gone |
| 22 | `python3 scripts/check-traceability.py` (before the §6 edit) | **ok** — 6 checks green |
| 23 | `python3 scripts/check-traceability.py` (after the §6 edit) | **ok** — 6 checks green, unchanged |
| 24 | `python3 scripts/check-traceability.py --self-test` (after) | **ok** |

No `cargo` command was run: nothing under `crates/` was read for behaviour and
nothing was edited there. Zero frozen bytes moved —
`[freeze-boundary] ok — 2 copies identical to D84 §7 (2175 bytes)` before and
after.

---

## Index row (orchestrator applies at merge)

| [D117](D117-resolved-decision-corrections.md) | Q122 — does a resolved decision's body take dated corrections, or does only the register row move? — **BODIES TAKE DATED CORRECTIONS; the lean survives and every reason given for it is wrong.** The row cites *"D84 §2's mechanism"*: §2 is the permanence argument and holds none; the mechanism is D84's two trailing sections, and **they are two incompatible mechanisms** — the first **deleted three body lines** (`5994365`, +27/−3), the second was a **pure append** (`3d47363`, +37/−0) — which three wave-13 amendments then cite as *"the appended-correction mechanism D84 established"*, false of the first. **The rule was already written, on the lean's side, in the third sentence of the file the row cites for something else**: `docs/decisions/README.md` opens *"A decision is changed by editing its file with a new dated entry, never by **silently** rewriting history"* — the prohibition is on silence, not change. **The other arm is unimplementable three times over**: *"the register row"* is **three** rows (`TODO.md`'s **116, complete, machine-read**; `README.md`'s **69 — 29 records missing, D53–D61 and D97–D116, and read by zero scripts**; **33** in-body `## Index row` sections of which **27 were never applied**); on Q122's own forcing case **the row is inside the body** (D95's row is verbatim at `README.md:81`, `TODO.md:788` *and* `D95:349`); and *"bodies are immutable"* would reverse **30 executed resolved-body edits** — of 48 modifying commits **28 deleted lines**, 132 in total, and nine decisions carry standing *"orchestrator applies at source"* sections, one of which (**D93 §13.3**) ordered a ground **deleted** from D56 and it was. **Accept bullet 3's count case was solved in wave 11 and nobody registered it**: `7bc746b` edited resolved D98's rider 3c *"Three"* → *"Four"* in place, with an inline dated attribution and an explicit **"This rider is not renumbered"** clause naming its six citation sites. **Wave 13's four amendments never amended a committed body** — `1c702d4` **created** all four files (880/0, 899/0, 873/0, 1209/0), so *"the body above is byte-unchanged"* is vacuous as evidence. Ruled: six rules — the correction is a **dated appended section** that is the single home of the new fact and quotes the original verbatim; the wrong sentence is **REPLACED if a lane would act on it** and **STRUCK and left standing if it is a measurement, census or argument**; the marker carries **at most one scalar**; **section, ruling and rider identifiers never move** (**2938** `D<n> §<n>` citations across **63** decisions); a **count** correction states the original, the new figure, **the predicate and the command**, whether it was *wrong when written* or *went stale*, and whether the conclusion survives, with its **epoch**; and a correction **never cites a line number** — measured: `tasks/R.md`'s `is_verified` correction has the right figure and **all five locators stale in three days**. **Scope: the `is_verified` sites are a FOLLOW-ON**, and the row's domain is wrong both ways — **six** statements in four files, three of them one register row in three homes, one named site (`TODO.md`'s R74 row) **already corrected**, and both of the row's `TODO.md` line numbers moved. **`Q167` lands under REPLACE**, D114 §7 and D101 §3.4 under STRIKE. **A fifth parked correction the row never named**: `D94:554-555` still reads *"three of A22's four Accept rows"*; **D101 §2.2 and D103 §7.2 RULING 6a each ordered it corrected and neither ran**, because `tasks/Q.md:1407` asserts *"a ruled record is immutable"* — registered nowhere, citing nothing, contradicting README's opening, and now refused. **Exercised**: D109 §8 (iii) corrected under STRIKE — five wrong claims (count 13→12, `Q130`'s membership, range 386–2 193→**386–1 735** at `5fbc48d`, A106's history misattributed to A105/A108, and per-batch atomicity), `(iii)` not renumbered, every ruling standing. Zero frozen bytes, no `cargo` run, traceability green before and after | RESOLVED (Q122 executes) | 2026-08-10 |
