# D119 — Q180 + Q186: what `docs/decisions/README.md` is, and what the in-body `Index row` sections mean

- **Status: RESOLVED — the file is the decision directory's FRONT PAGE, not a
  third register; its opening claim is made TRUE by a check whose domain is the
  files on disk; and the 37 in-body index-row sections are DEMOTED into the edit
  sets they always belonged to, because the event their heading names has never
  once occurred.** Q180 offers two arms and forbids doing both. **Both arms are
  refused, and the reason is a defect neither row contains.** Measured today,
  the index and `TODO.md`'s register both record **D29** as *FROZEN 2026-07-28
  at Q14*; **D29's own record still reads `RECOMMENDED (R1)`, dated
  2026-07-27**, and says in its own Status line that until Q14 the format may
  change. The authoritative document is the stale one. Landing Q180's 29
  missing rows leaves that wrong; rewriting the opening to call the table *"a
  curated selection"* leaves it wrong **and licenses it**. Q180's inference —
  *"No row in the table lacks a file, so the drift is one-directional: the
  index only ever falls behind"* — is **invalid and false**: row/file
  *presence* is one-directional, but *status* runs the other way, and it got
  there deliberately (the 2026-07-31 audit updated the row and never touched
  the record; D29's file has not been modified since `5494e9f`).
  **The two artefacts have different domains, which is why neither supersedes
  the other.** `TODO.md`'s Decision register is the register: **118 rows,
  D1–D118, dense, zero duplicates**, machine-read as the allocation bound by
  `check_decisions()`, and it carries **18 ids that have no file** — five homed
  in `DECISIONS_HOMED_ELSEWHERE`, **13 still open** for decisions not yet
  written. Its domain is the **id space**. The index's domain is the **records
  that exist**. A check over the first would be red on 47 ids, 13 of them for
  documents nobody has written; a check over the second is red on 29 today and
  costs **0.03 s**.
  **Deletion is refused on measurement, not taste.** The file's prose is
  load-bearing and cited: **D117's central ruling turns on its third
  sentence** (*"never by **silently** rewriting history"* — the prohibition is
  on silence, not change), and `docs/security-assumptions.md` cites *"the
  `docs/decisions/README.md` convention"* by name. The table is not a duplicate
  of the register either — median text similarity over the 71 shared ids is
  **0.25**.
  **Q186's mechanism did not decay; it never ran as described.** The heading says
  *orchestrator applies at merge*. This project performed **83 merges, the last
  on 2026-08-05** (`8a6cd96`), and has committed **31 times since, all direct to
  main**. Of the eight applied rows in the 35-set, **zero were applied at a
  merge**: D92–D95, D117 and D118 landed their row **in the same commit as their
  own file**, and D90/D91 were swept in four days late. So Q186's *"the mechanism
  last worked for a six-record block in August"* is wrong in its premise — there
  was never a merge-time mechanism to stop working.
  **Q186's re-heading arm is refused, and so is its factual basis — including
  the claim that makes its census trustworthy.** It asserts *"Exactly one
  spelling, exactly one occurrence per file, so the count is not a parsing
  artefact."* **The count is a parsing artefact**: D86 §10 and D87 §8 carry
  `## <n>. Register row (for docs/decisions/README.md, added at merge)` — the
  same act, a second spelling, and **numbered**, so those two cannot be removed
  without moving a section identifier D117 forbids moving. It is **37 documents
  in two spellings**, not 35 in one. Its description of the artefact is wrong
  three further ways: *"a fenced, ready-to-paste"* row is **one of the 35**
  (D90); **D111's section holds no table row at all**, only a differently-shaped
  backticked one-liner; and **D118's carries a column header and separator** to
  strip. Re-heading them as *proposals* would preserve 37 hand-written
  duplicates of data the check now derives, and install the silent-rot shape one
  level up. It also does not satisfy its own Accept: the same instruction exists
  in the `Index note` prose of D27/D28/D29/D86/D87, as an edit-set line in D106
  and D113, and in **D8 §E5's still-open `- [ ]` checkbox ordering rows for D8,
  D78 and D79, all three of which have been in the index for two weeks**.
  **What the sections get right is preserved.** D86's and D87's own `Index note`
  states the rationale — the index is *"(which other planners are editing
  concurrently)"* — so the hand-off exists because several planners share one
  working tree, which is as true today as it was then. The mechanism solves a
  real problem and names the wrong event; the ruling keeps the first and drops
  the second.
  **Two rows the backfill cannot copy.** Q186 says the missing rows *"have
  mostly already been written"*. Measured: of the 29 missing, **27** carry a
  pre-written row and **D101 and D114 carry none at all** — neither row names
  them, and an implementing lane that treats the job as pure copying will be two
  rows short with nothing telling it so.
- **Date: 2026-08-11** — wave 15, D119 lane. Briefed with the lean *"either the
  index becomes a real register with a check, or its opening sentence stops
  claiming to mirror the files — do not do both"* (Q180) and *"the cheaper, more
  durable half is to re-head the sections as proposals"* (Q186), and briefed to
  overturn both. Both are overturned, and so is the framing they share: the file
  was never a register, so *"become a real register"* and *"admit you are not
  one"* were never the available moves.
- **Owning tasks: Q180 and Q186**, adjudicated together as the rows require
  (*"neither should be executed without the other in view"*). **Consumes**:
  D117 (correction form), D109 §3.3 (the `docs/decisions/` sweep exclusion),
  D116 (sweep parity), Q188 (the heading-family retrofit), Q181 (the unswept
  root-of-`docs` files). **Binds against**: `docs/decisions/README.md`'s opening
  paragraph, `TODO.md`'s Decision register, `scripts/check-traceability.py`.
  **Supersedes**: nothing.

---

## The problem, in one sentence

`docs/decisions/README.md` opens by claiming a property it does not have, and 37
decision documents carry a top-level section claiming an event that has never
happened — and because the two rows that registered these read them as *a
backlog* and *a heading*, both proposed fixes leave the one measured wrong
status standing.

---

## 1. What was measured

**Epoch.** Every figure below was re-derived on 2026-08-11 against the committed
tree at **`1f82da1`** — 100 tracked decision records, 71 index rows. Where a
row's figure has moved since it was filed, both are shown.

The epoch has to be stated because it moved *during this lane*. Five wave-15
planning lanes are writing concurrently into one working tree; by the time this
document was finished the tree held **104** decision files and **39** `Index row`
sections, with D122, D123 and D124 landing alongside D119 and three existing
records modified under other lanes. That is not noise — **it is the ruling's
strongest single piece of evidence**: every decision written adds one missing row
and one unapplied section, mechanically, with nothing to stop it. Wave 15 alone
widens Q180's gap by at least six. A backlog that grows once per decision is not
a backlog; it is a missing check.

### 1.1 The index against the records

```
$ ls docs/decisions/ | grep -c '^D[0-9]'
100
$ grep -c '^| \[D[0-9]' docs/decisions/README.md
71
```

Set difference, sorted numerically (the naive `comm` over a `sort -n` stream
reports garbage — `comm` needs lexical order, and doing it wrong produced a
first draft claiming D117 and D118 were simultaneously present and absent):

```
files with no index row (29):
  53 54 55 56 57 58 59 60 61 97 98 99 100 101 102 103 104 105 106 107
  108 109 110 111 112 113 114 115 116
index rows with no file: 0
index rows whose link target does not exist: 0
index table in ascending id order: yes
```

Q180 was filed at **69 of 98**; it is **71 of 100** today, D117 and D118 having
been applied at wave-14 bookkeeping. The two bands are unchanged: **D53–D61**
(files created 2026-08-02, `6e23622`) and **D97–D116**.

### 1.2 Nothing reads it — confirmed, and it is not the whole story

```
$ git grep -n "decisions/README" -- scripts/ .github/
$ echo $?
1
```

Zero hits from any instrument. But the file is heavily *cited* — 17 files, led
by **D117 (23 occurrences)**, `TODO.md` (7), `tasks/Q.md` (7), `D8` (4), `D113`
(3), and one each in `tasks/R.md` and `docs/security-assumptions.md`. Those
citations split cleanly into two classes, and the split is the ruling in
miniature:

- **Dependencies on the prose** — another document's rule rests on a sentence
  here. D117 (its central ruling), D91 (*"convention (`docs/decisions/README.md`:
  …)"*), `docs/security-assumptions.md` (*"(`docs/decisions/README.md`
  convention)"*), and the Q122/Q187 narrative in `TODO.md` and `tasks/Q.md`.
- **Instructions to edit the table** — D8 §E5, D106, D113, D85, D115, and the
  `Index note` lines in D27/D28/D29/D86/D87.

**No document anywhere depends on the table's content.** Everything that binds,
binds to the paragraphs; everything that touches the table is telling someone to
change it. That is what a front page looks like, and it is not what a register
looks like.

### 1.3 The mirror claim, tested on the rows that ARE present

The opening says *"statuses here mirror the files"*. Comparing each of the 71
rows' status and date cells against its record's `- **Status`/`- **Date` lines:

```
rows compared: 71
records with no parseable Status line: 0
records with no parseable Date line:   1  (D96)
leading-status-token divergences:      1  (D29)
date divergences:                      1  (D29)

  D29  index : RESOLVED (FROZEN at Q14 as report v1; `REPORT_VERSION = 1`, R32; …)  2026-07-28
       record: RECOMMENDED (R1) — final freeze belongs to Q4/Q5 vector schema …     2026-07-27
```

`TODO.md`'s register agrees with the index: *"**FROZEN 2026-07-28 at Q14** as
report **v1**"*. The record is alone and it is wrong. History says how:

```
$ git log --oneline -- docs/decisions/D29-report-byte-format.md
5494e9f R1: VerificationReport model + VerifyError taxonomy … (resolves D27; D29 recommended)
```

One commit, ever. The row was corrected in `dfe7071` (the 2026-07-31 audit
sweep, whose own `TODO.md` note records *"D29's README row updated RECOMMENDED
→ FROZEN"*). **The index was fixed and the record was not.** D29's Status line
still tells a reader *"Until Q14 this format may change"* about a format frozen
fourteen days ago.

### 1.4 The register, and why its domain is different

```
$ grep -c '^- \[.\] \*\*D[0-9]' TODO.md
118          (distinct ids: 118 — D1..D118, dense, no duplicates)
ids in the register with no file: 18
  homed in DECISIONS_HOMED_ELSEWHERE:  11 12 16 17 30
  still open (`- [ ]`, no document):   18 62 63 64 65 66 67 68 69 70 71 72 73
ids with a file but no register row: 0
ids with an index row but no register row: 0
```

Thirteen register ids are decisions that **do not exist yet**. Any check written
as *"every id in the register has an index row"* — the obvious phrasing, and the
one Q180's `Do` gestures at — is red on **47** ids and demands rows for
documents nobody has written. The correct domain is the glob, not the register.

### 1.5 The sections — 37, in two spellings, not 35 in one

Q186 states *"Exactly one spelling, exactly one occurrence per file, so the
count is not a parsing artefact."* **The count is a parsing artefact.** Grepping
for the act rather than for one phrasing:

```
$ git grep -h '^#\+ .*\([Ii]ndex row\|Register row\)' -- docs/decisions/ | sort | uniq -c
     35 ## Index row (orchestrator applies at merge)
      1 ## 10. Register row (for `docs/decisions/README.md`, added at merge)   [D86]
      1 ## 8. Register row (for `docs/decisions/README.md`, added at merge)    [D87]
```

**Thirty-seven documents carry a top-level section whose whole content is a row
for the index, under two heading spellings.** The 35 are unnumbered, so removing
them moves no identifier. **D86's and D87's are numbered sections**, so D117's
*"section, ruling and rider identifiers never move"* **is** engaged for those
two and they are handled differently in §5. Both are applied, so the applied
count is **10 of 37**; the unapplied count is unchanged at **27**, which is why
the error was invisible.

Within the 35:

```
$ git grep -c '^## Index row' -- docs/decisions/ | awk -F: '{print $2}' | sort | uniq -c
     35 1
```

One occurrence per file, never numbered.

```
of the 35:  applied (row now in the index):   8   D90 D91 D92 D93 D94 D95 D117 D118
            not applied:                     27   D53–D61 D97–D100 D102–D113 D115 D116
            fenced:                           1   D90
            carrying a header + separator:    1   D118
            containing no table row at all:   1   D111
            well-formed single self-row:     34
plus the two numbered `Register row` sections: D86 D87 — both applied,
  both fenced (so a fence-keyed harvest over all 37 returns 3, not 35)
missing from the index with NO pre-written row: 2  D101 D114
of the 35, also naming the index inside an Edit set / Consequences
  section (i.e. already carrying the demoted form):  2  D106 D113
```

Q186 was filed at *"six applied, twenty-nine not"* and self-corrected to 27 of
35 after wave 14 applied D117's and D118's. **Eight and 27** is the figure
today. D111's section is worth seeing, because it is the clearest evidence that
these are not a uniform mechanism — under the identical heading it carries a
single backticked line in a shape the index has never used, with em-dashes where
the table uses pipes.

### 1.6 The event the heading names

```
$ git log --merges --oneline | wc -l
83
$ git log --merges -1 --format='%h %ad %s' --date=short
8a6cd96 2026-08-05 Merge A18/A19/A39/A40: the anchor verdict state machine …
$ git log --oneline 8a6cd96..HEAD | wc -l
31
```

For each applied row, the commit that added the record versus the commit that
added its row:

```
D90   file 6e23622 2026-08-02   row 6ce5301 2026-08-06
D91   file 761817c 2026-08-02   row 6ce5301 2026-08-06
D92   file 6ce5301 2026-08-06   row 6ce5301 2026-08-06
D93   file 6ce5301 2026-08-06   row 6ce5301 2026-08-06
D94   file a053272 2026-08-06   row a053272 2026-08-06
D95   file 5f758de 2026-08-06   row 5f758de 2026-08-06
D117  file 360ea2a 2026-08-10   row 360ea2a 2026-08-10
D118  file 360ea2a 2026-08-10   row 360ea2a 2026-08-10
```

**Not one of them was applied at a merge.** Six landed row-and-record in a single
commit; two were swept in later. The heading has never described what happened.

**But the sections are not pointless, and the reason is written down.** D86's and
D87's `Index note` states it: the index *"(which other planners are editing
concurrently) gains its row at merge"*. The rationale was never branch topology —
it is that **several planners run against one working tree and cannot safely
write one shared file**, which is exactly as true today as it was then. So the
mechanism solves a real problem and names the wrong event. That distinction
decides RULING 4: the hand-off is kept, the false event-claim is not.

### 1.7 What the table is, if not a duplicate

Comparing each index summary against its `TODO.md` register entry, normalised
and diffed:

```
rows compared: 71   median similarity 0.25   mean 0.29
  >= 0.80 (near-duplicate):  2   (D94, D95 — written in the same act)
  0.50–0.80:                 9
  < 0.50:                   60
total index summary bytes 48 176   matching register bytes 75 185
```

The register is the long-form narrative; the index is a terse annotated
listing (D2's summary is 38 bytes against the register's 336). They are
different artefacts serving different readers, which is why "supersede" was
never available.

### 1.8 What a check would cost

A prototype, run in the scratchpad against the live tree:

```
candidate A (row-for-every-record, link resolves, ascending order): 29 findings
candidate B (status token and date mirror the record):               3 findings
                                                     wall = 0.03 s
```

Roughly 35 lines. Cost is not the obstacle, and *"measure, do not assume"* here
returns the unglamorous answer: it is free.

### 1.9 Source availability for a generated table (checked, and rejected)

```
files with a parseable `# D<n> — title` H1:  100 / 100
files with a `- **Status` line:              100 / 100  (98 house spelling, 2 `- **Status**:`)
files with a `- **Date` line:                 98 / 100  (D96, D98 lack one)
```

Mechanically, a generator is viable after four line-level normalisations. It is
rejected in §5.3 for a reason that only shows up once D29 is on the table.

---

## 2. Both readings, attacked

### 2.1 Q180 arm (a) — "it becomes a register and a check lands"

Refused as stated, adopted in substance with two corrections.

- **"Register" is the wrong word and it imports the wrong domain.** A register
  allocates; `TODO.md`'s does, and legitimately holds 13 ids with no document.
  An index describes what exists. Calling the file a register invites the
  47-finding check of §1.4.
- **Landing 29 rows does not make the opening sentence true.** D29 is present
  and divergent. The arm's own Accept — *"the file either carries a row for
  every `D*.md` … the claim is true or gone"* — is satisfiable while the claim
  stays false, because the Accept only quantifies over presence.

### 2.2 Q180 arm (b) — "the opening says it is a curated selection"

Refused outright, and it is the more dangerous arm. It converts a detected
defect into documented policy: once the file disclaims mirroring, D29's
contradiction becomes conforming behaviour, and the next reader who notices the
record and the register disagree has a sentence telling them not to care. The
one thing the file measurably does right — being correct about D29's status
where the record is wrong — is the thing this arm would license away.

### 2.3 The brief's arm — "delete it, or reduce it to a pointer"

Refused on measurement. Deleting the file deletes:

- the third sentence on which **D117's entire ruling rests**, and which predates
  Q122 by eleven days;
- the *Evidence convention* paragraph, the sole surviving provenance note for
  the pre-M0 naming and pin research memo (retrieval window and sources), which
  exists in no other file;
- the page GitHub renders at the `docs/decisions/` directory URL, which is where
  a reader arriving at 100 files actually lands.

Reducing it to a pointer keeps the prose and drops the table. That is coherent —
it is the only refused option that is not *wrong* — but it trades a 0.03 s check
for the loss of the project's only scannable per-decision listing, and §1.7 shows
the table is not recoverable from the register by reading it differently.

### 2.4 Q186 arm — "re-head them as proposals"

Refused on four counts.

1. **It preserves 37 hand-written duplicates.** Once the index is checked, a
   hand-written row in a body is a second copy of a fact the check already
   guarantees. A proposal that is permanently unapplied and permanently
   unfalsifiable is the silent-rot shape one level up.
2. **It does not satisfy its own Accept.** *"No section in `docs/decisions/`
   asserts that an edit was applied when it was not"* — the same assertion lives
   in the `Index note` prose of D27, D28, D29, D86 and D87 (*"the index … gains
   its row at merge"*), and in **D8 §E5's open `- [ ]` checkbox**, which orders
   rows for D8, D78 and D79 that have all been present since 2026-07-28/07-31.
   Re-heading the 37 touches none of these.
3. **Its premise is wrong.** *"The mechanism last worked for a six-record block
   in August and has not worked since"* — §1.6 shows it never worked *as
   described*. What worked was people writing the row into the index in the same
   commit as the record. That practice needs a check, not a heading.
4. **Its description of the artefact is wrong in four particulars** (§1.5): one
   fenced section, not 35; one section with no row at all; one carrying a header
   to strip; and *"exactly one spelling"* is two, missing D86's and D87's
   numbered `Register row` sections entirely. A lane briefed on *"fenced,
   ready-to-paste, one spelling"* will write a fence-keyed extractor, harvest
   exactly one row, and never look at D86 or D87.

### 2.5 The interaction the rows name

Correct, and it is arithmetic: applying a row moves Q180's missing-count down
and Q186's unapplied-count down together. Verified — the wave-14 bookkeeping
that applied D117 and D118 moved 69→71 and 6→8 in one act. The rows are right
that they cannot be executed apart. They are wrong that applying is the
expensive half: **the expensive half is D29**, which is in neither row's scope.

---

## 3. Ruling

**RULING 1 — the file's identity.** `docs/decisions/README.md` is the decision
directory's **front page**: normative convention prose plus a complete index of
the records that exist. It is **not** a register, does not allocate, and never
carries an id without a file. `TODO.md`'s Decision register is the project's
sole decision register and remains the allocation bound for `check_decisions()`.
The three artefacts have three domains — the register holds the **id space**,
the index holds the **files on disk**, the record holds the **decision** — and
each is authoritative over its own.

**RULING 2 — the record is authoritative for status.** Where a record, the
index and the register disagree about a decision's status, the **record**
decides, and the other two are corrected to it. Where the record is the stale
one — as with D29 — the record is corrected first, under D117's form, and only
then does the index follow. This is what makes RULING 3's check meaningful
rather than a demand that two documents agree about nothing in particular.

**RULING 3 — the opening claim is made true, by a check, over the glob.** The
opening paragraph stays and is made precise: it names `TODO.md`'s register as
the register, states that this file indexes the records that exist, and names
the check that holds it. A new `decision-index` check in
`scripts/check-traceability.py` asserts, over `docs/decisions/D*.md`:

  (a) every record has exactly one index row;
  (b) every index row's link resolves to an existing file;
  (c) rows are in ascending id order;
  (d) each row's status token and date equal the record's `- **Status`/`- **Date`
      lines.

Its domain is **the glob, never `TODO.md`'s register id space** (§1.4). Q180's
*"do not do both"* is refused as a false exclusion: making a sentence precise
**and** true is one act, not two. What Q180 rightly forbids — landing the rows
while also disclaiming the property — is not what happens here.

**RULING 4 — the 37 sections are demoted, not re-headed and not kept.** They are
edit instructions against exactly one file, wearing a top-level heading that
names an event that has never occurred. They are not a distinct act and get no
distinct heading. **The hand-off they provide is real and is kept**: several
planners share one working tree and cannot write one shared file, which is why
the row must be handed over rather than applied by its author (§1.6). What is
dropped is the claim that a merge applies it. Each document's section becomes
**one line inside that document's existing edit set**, in the form every other
cross-file instruction in the house already uses — and which **D106 and D113
already carry**, alongside their section, so the demoted form is not a new
invention but the one two documents chose independently. D86's and D87's
sections are **numbered**, so their content is emptied and their heading
rewritten **in place, keeping the section number**, under D117's rule that
identifiers never move.

**RULING 5 — the heading family belongs to Q188, not here.** The two spellings
ruled on here are **two more members** of the family Q188 inventories, which
already holds its `(β)` *"orchestrator applies at source"* sections (seven, in
D53, D56, D91, D93, D94, D97, D100) and does not name either. Nor does it name
the `Index note` prose form (five, in D27, D28, D29, D86, D87). That is **four
spellings of one act across 40 documents**, against Q186's *"exactly one"* and
Q188's *"eight documents"*. This decision hands all of them to Q188 and mints no
heading form of its own — because *"a convention adopted by imitation produces a
family of spellings"* is Q188's own finding, and solving it twice in two lanes is
how the fifth spelling gets born.

**RULING 6 — where the row is written from now on.** A decision's index row is
written by the lane that authors the record, **in that record's edit set**, and
is applied to `docs/decisions/README.md` **by the act that commits the record** —
in the same commit, which is what has happened for every decision since D92
(§1.6). The check's contract is on committed state, so a wave's bookkeeping act
— which lands both halves together — is green by construction, and a bookkeeping
that forgets is red. **The check must not be read as an obligation on a
concurrent planner**, who cannot write the shared file; it is an obligation on
the act that commits.

---

## 4. Why not the alternatives

### 4.1 Why not delete or reduce to a pointer

§2.3. The prose is cited by a resolved decision's central ruling and by a
normative document; the *Evidence convention* paragraph has no other home; the
table is not recoverable from the register (§1.7); and the page is what GitHub
renders at the directory URL. Deletion also strands the 37 sections in a worse
state than either row describes — instructions pointing at a file that no longer
has the thing they instruct.

### 4.2 Why not "curated selection"

§2.2. It documents the D29 defect as policy.

### 4.3 Why not generate the table

This is the option the measurement in §1.9 makes tempting and the measurement in
§1.3 kills. All 100 records carry a parseable H1 and Status line; a generator
would make *"statuses here mirror the files"* true by construction and retire the
29-row backlog forever. **But generation makes the record authoritative
mechanically, and for D29 the record is the stale one** — so the first
regeneration would silently overwrite a correct 2026-07-31 audit finding with
`RECOMMENDED`, reverting a frozen format decision's recorded status and
producing a green check over a wrong table. A generator is safe only *after*
every record's status is right, which is RULING 2's work; it is not a substitute
for it. It would also discard the 48 KB of hand-written summaries in favour of
H1 titles, which is a real loss and a separate question. Recorded here as
deliberately declined, with its precondition named, so that a future lane
proposing it does not have to rediscover why the order matters.

### 4.4 Why the check is not "one more instrument nobody needs"

Because it catches a class `TODO.md`'s register structurally cannot: the
register's domain is the id space, so it is *correct* while carrying 13 ids with
no document, and it says nothing at all about whether a record that exists is
indexed or whether its status is transcribed right. The measured evidence that
the class is real is that D117 §1.2 had to spend a measurement establishing
which of three registers was authoritative before it could rule — and that cost
is what produced Q180 and Q186 in the first place. Cost of the instrument:
0.03 s, ~35 lines, red today on 32 findings.

---

## 5. Edit set

Exactly what a later implementing lane does, file by file. **The order matters
and is not the file order**: step 1 must precede step 4, or the check is green
over a wrong status.

**1. `docs/decisions/D29-report-byte-format.md` — correct the record's status
(RULING 2).** This is the load-bearing step and it is in neither Q180's nor
Q186's scope. Under D117 RULING 2's **REPLACE** arm, because a lane reading
*"Until Q14 this format may change"* would act on it:
   - replace the `- **Status:` block with the frozen status, matching the wording
     `TODO.md`'s register already carries (frozen 2026-07-28 at Q14, report v1,
     `REPORT_VERSION = 1`, bumped at R32);
   - correct the `- **Date:` line to the freeze date;
   - append a dated correction section in D117's form —
     `## Correction — <clause>, 2026-08-11` — quoting the superseded Status and
     Date lines **verbatim**, naming Q14 as the event, naming `dfe7071` as the
     commit that corrected the index and not the record, and stating that the
     record was wrong from 2026-07-28 rather than having gone stale.
   - Move no section, ruling or rider identifier.

**2. `docs/decisions/D96-*.md` and `docs/decisions/D98-*.md` — normalise the two
status-block spellings.** D96 uses `- **Status**:` and carries no `- **Date`
line at all; D98 carries no `- **Date` line. Bring both to the house form
(`- **Status: …**` / `- **Date: YYYY-MM-DD**`), taking the dates from their
`TODO.md` register entries. Four lines total. Do this before step 4 or the check
is red on parse failures rather than on content.

**3. `docs/decisions/README.md` — the opening paragraph.** Replace the second
sentence. It must (i) name `TODO.md`'s Decision register as the project's
register and this file as an index of the records that exist, (ii) state that
every record has a row and that each row's status and date are the record's, and
(iii) name the `decision-index` check as what holds it. **Keep the third
sentence byte-for-byte** — D117's ruling cites it, and it is the one sentence in
the file nothing has ever falsified. Keep the *Evidence convention* paragraph
unchanged.

**4. `docs/decisions/README.md` — backfill 29 rows.** The table is in ascending
id order; insert accordingly.
   - **27 rows are harvestable** from the sections listed in §1.5. Harvest by
     locating the heading and taking the line that begins with a pipe followed
     by a bracketed id link — **not** by looking for a fence: only D90's is
     fenced, and a fence-keyed extractor returns one row.
   - **D118's section carries a column header and a separator line**; take the
     data row only.
   - **D111's section contains no table row.** Compose its row from the record's
     H1, `- **Status` and `- **Date` lines.
   - **D101 and D114 have no section at all** (neither Q180 nor Q186 says so).
     Compose both rows the same way.
   - Rows for D53–D61 carry statuses written when those records landed
     2026-08-02; verify each against its record's current Status line before
     pasting, since step 4 is exactly where a stale harvested status would be
     laundered into the index.

**5. `scripts/check-traceability.py` — add the `decision-index` check.**
   - New function beside `check_decisions()`; register it in `CHECKS`; add its
     flag; extend the module docstring's check list.
   - Assertions (a)–(d) of RULING 3. Domain: `(ROOT / DECISION_DIR).glob("D*.md")`.
     **Do not read `allocated_decision_ids()`** — comment the reason at the
     function, with the measured figure: 18 register ids have no file, 13 of them
     open, so the register's id space is the wrong domain and a check written
     over it is red on 47.
   - The green message reports the row count and the record count, so a check
     that silently narrowed its glob is visible in a green log (D116 R3's rule).
   - This does **not** reopen D109 §3.3: the check reads H1/Status/Date/table
     structure, never citations, and `docs/decisions/` stays out of
     `CITATION_SCAN`. Say so at the function.
   - **Self-test cases — three, and one hazard.** RED on a removed index row;
     RED on a status cell diverged from its record; GREEN control. The harness
     copies the tree and mutates a literal, and **34 decision bodies contain a
     line of exactly the index-row shape** — so a first-occurrence replacement
     can land in a decision body instead of the index. Target
     `docs/decisions/README.md` by path and assert the pre-image is present in
     that file before mutating. Verify each case by the **message** it prints,
     not by exit code.

**6. The 37 decision documents — demote the sections (RULING 4).**
   - **The 35 unnumbered `Index row` sections**: delete the section and add one
     line to that document's existing edit set naming `docs/decisions/README.md`
     and the index row, with whatever executed marker Q188 settles on. **D106 and
     D113 already carry such a line** and get no second one. No identifier moves
     — the heading is never numbered (§1.5).
   - **D86's `## 10.` and D87's `## 8.` `Register row` sections**: these are
     **numbered**. Do **not** delete them. Empty the content and rewrite the
     heading in place, **keeping the section number**, under D117's rule that
     section identifiers never move. Both rows are already applied, so the
     replacement records that fact rather than an instruction.
   - **This document's own section is one of the 37** — it carries the current
     spelling under this decision's brief, and the orchestrator re-heads or
     demotes it with the rest.

**7. `TODO.md` — close both rows.** Q180 and Q186 close together; status text in
§8 of the report this lane returns. Add D119 to the Decision register and its
row to the index in the same act (RULING 6).

**8. Do NOT do in this act:** D8 §E5's checkbox, the five `Index note` prose
sites, and Q188's heading-form retrofit. All three are described in §7 and
belong to rows the orchestrator numbers.

---
- `docs/decisions/README.md` — this decision's index row. **Applied 2026-08-11**, executing [D119](D119-decision-index-identity-and-the-index-row-sections.md) §5 step 4; the former `## Index row` section is demoted to this line under D119 RULING 4, and RULING 6 puts the row in the act that commits the record.

## 6. Commands run, with verdicts

| # | Command | Verdict |
|---|---|---|
| 1 | `ls docs/decisions/ \| grep -c '^D[0-9]'` | **100** records (Q180 filed at 98) |
| 2 | `grep -c '^\| \[D[0-9]' docs/decisions/README.md` | **71** rows (Q180 filed at 69) |
| 3 | set difference, files − rows | **29**: D53–D61, D97–D116 — bands confirmed |
| 4 | set difference, rows − files | **0**; and 0 rows link to a missing file |
| 5 | `git grep -n "decisions/README" -- scripts/ .github/` | **no output, exit 1** — confirmed |
| 6 | `git grep -c '^## Index row' -- docs/decisions/` | **35 files, one occurrence each, never numbered** |
| 6b | `git grep -h '^#\+ .*\([Ii]ndex row\|Register row\)' -- docs/decisions/` | **two** spellings over **37** files — D86 `## 10.` and D87 `## 8.` are numbered `Register row` sections Q186's census misses |
| 7 | heading set ∩ index rows | **8 of 35 applied**, **27 not** (Q186 filed at 6/29); **10 of 37** counting D86/D87 |
| 8 | missing-from-index minus heading-bearing | **D101, D114** — 2 rows with no source, in neither row |
| 9 | fence / header / row-shape census over the 35 | **1 fenced (D90)**, 1 with header+separator (D118), 1 with no row (D111) |
| 9b | of the 35, naming the index inside an Edit set / Consequences section | **2 — D106, D113** already carry the demoted form |
| 10 | status+date of all 71 rows vs their records | **D29 diverges in both**; D96 has no parseable Date |
| 11 | `git log --oneline -- …D29-report-byte-format.md` | **one commit ever**; row corrected in `dfe7071`, record never |
| 12 | `grep '^- \[.\] \*\*D29\*\*' TODO.md` | register says **FROZEN 2026-07-28 at Q14** — record is alone |
| 13 | `git log --merges \| wc -l`; last merge; commits since | **83**; `8a6cd96` 2026-08-05; **31**, all direct to main |
| 14 | file-add vs row-add commit for the 8 applied | **0 applied at a merge**; 6 same-commit, D90/D91 swept 4 days late |
| 15 | `TODO.md` register census | **118 rows, D1–D118, dense, 0 dupes**; **18 fileless** (5 homed, 13 open) |
| 16 | index summary vs register entry similarity, 71 ids | median **0.25** — not a duplicate |
| 17 | H1/Status/Date parseability over 100 records | 100 / 100 / **98** (D96, D98) |
| 18 | prototype check, live tree | **29 + 3 findings, wall 0.03 s** |
| 19 | `python3 scripts/check-traceability.py --check` | **`error: unrecognized arguments: --check`, exit 2** — the flag does not exist |
| 20 | `python3 scripts/check-traceability.py` | **`check-traceability: ok (freeze-boundary, matrix, decisions, task-citations, task-entries, decision-owners)`**, exit 0 |
| 21 | `python3 scripts/check-traceability.py --self-test` | **28 `self-test: ok — …` lines, no failures**, exit 0 |

Verdicts 20 and 21 were read whole, failures-first; neither printed a failure
line. Verdict 19 is reported by its message: the briefed invocation is not a
valid flag, and the full-check form takes no flags at all.

---

## 7. What this does not do

- **Does not reopen D109 §3.3.** `docs/decisions/` stays outside `CITATION_SCAN`.
  The new check reads structure, never citations.
- **Does not touch `TODO.md`'s register, its parse, `allocated_decision_ids()`,
  `open_decision_ids()` or `DECISIONS_HOMED_ELSEWHERE`.**
- **Does not settle the `(β)` heading form or its executed marker.** That is
  Q188's, and RULING 5 hands it two more spellings rather than inventing another.
- **Does not move any section, ruling or rider identifier.** The removed heading
  is unnumbered in all 35 files; D86's and D87's numbered sections are rewritten
  in place with their numbers kept, precisely so that nothing moves.
- **Does not touch frozen bytes, wire registry surface, vectors, error codes, or
  any file under `crates/`.** No `cargo` invocation is required by any step.
- **Does not make the index a register.** It never allocates and never carries a
  row without a file.
- **Does not generate the table** — §4.3 records that as declined, with its
  precondition.
- **Does not add a navigation link to the index** from any human entry point;
  that is described in §8 below as discovered, not ordered.

---

## 8. Discovered work — described, not registered

No ids are minted here. Each item is a problem, a proposed `Do`, a proposed
`Accept`, and where it was verified.

**(i) `D8 §E5` is an open checkbox over finished work — a false *unexecuted*
marker.** *Problem*: D8's edit set carries `- [ ] **E5.** *(docs)*
`docs/decisions/README.md` gains rows for **D8**, **D78** and **D79**`, still
unticked. All three rows have been in the index since 2026-07-28/07-31
(`8ba845d` *"promote D78 and D79 to records, index D8"*). Q186's complaint is
that a reader cannot tell an executed instruction from an unexecuted one; this is
the inverse and the more misleading direction — a marker positively asserting the
work is outstanding. *Proposed Do*: tick it, or strike it under D117's STRIKE arm
with the executing commit named. *Proposed Accept*: no open checkbox anywhere in
`docs/decisions/` orders an edit already present in the tree, and the sweep that
establishes this is recorded. *Verified*: the checkbox state, and three matching
rows in the index, 2026-08-11.

**(ii) Q188's family is at least four spellings over 40 documents, not the eight
its inventory names.** *Problem*: Q188 inventories `(β)` at *"eight documents"*.
Measured: **seven** documents carry a `(β)` *"applies at source"* heading (D53,
D56, D91, D93, D94, D97, D100); **35** carry `## Index row (orchestrator applies
at merge)`; **two** carry a numbered `Register row (… added at merge)` heading
(D86 §10, D87 §8); and **five** carry the `Index note` prose form (D27, D28, D29,
D86, D87). D119 rules the disposition of the last three groups but deliberately
mints no heading form (RULING 5), so the retrofit still needs one owner.
*Proposed Do*: widen Q188's retrofit domain to the measured census and state the
spelling count in the file that fixes the form, as Q188's own Accept already
requires. *Proposed Accept*: the retrofit's stated spelling count matches a
re-measurement taken after it lands, and no sixth spelling exists.
*Verified*: the four heading/prose censuses above, run over `docs/decisions/`,
2026-08-11.

**(iii) Nothing points a reader at the index.** *Problem*: root `README.md`,
`CONTRIBUTING.md` and `docs/threat-model.md` link to the `docs/decisions/`
*directory* or to individual records; none links to the index. If the index is
worth keeping — and RULING 1 says it is — the absence of any inbound link is why
its 15-day drift cost nothing and was noticed by nobody. *Proposed Do*: one link
from the contributor-facing document, wherever decisions are first mentioned.
*Proposed Accept*: at least one normative document links to the index, and the
link resolves under whatever check owns link resolution. *Verified*: `git grep -n
"docs/decisions" -- README.md CONTRIBUTING.md docs/*.md`, 2026-08-11.

**(iv) A normative convention is cited from an unswept file, about an unswept
file.** *Problem*: `docs/security-assumptions.md` cites *"the
`docs/decisions/README.md` convention"* as binding on how a frozen claim is
changed. Both files are outside `CITATION_SCAN` — the target under D109 §3.3,
the citing file as one of Q181's nine root-of-`docs` `.md` files. Nothing would
notice if either side moved. *Proposed Do*: fold as a measured instance into
Q181's disposition of the nine, rather than as its own row. *Proposed Accept*:
Q181's ruling names this citation among the consequences it weighed. *Verified*:
the citation text and `CITATION_SCAN`'s membership, 2026-08-11.

**(v) The index-row shape is ambient in `docs/decisions/`, which is a trap for
the new check's self-test.** *Problem*: **36 decision bodies** contain a line of
exactly the shape the index table uses (34 of the 35 — D111 has none — plus D86
and D87). A self-test mutation that replaces the first occurrence of such a
literal across a copied tree can land in a decision body rather than in the
index, producing a case that goes red for the wrong reason — the shape that has
already cost this project two CI reds. *Proposed Do*: require path-targeted
mutation with a pre-image assertion for any fixture in this class, stated once
where fixtures are defined rather than per case. *Proposed Accept*: every case in
the new check's fixture set names its target file, and a deliberately mistargeted
case fails to construct rather than passing vacuously. *Verified*: `git grep -c
'^| \[D[0-9]' -- docs/decisions/` less the index itself, 2026-08-11 — **36 files,
36 lines**, over tracked files only. The figure is **37** with this document, and
falls as §5 step 6 empties the sections, so the fixture must not depend on it.

---

## Outcome

Q180 and Q186 close together, as they required. The file is ruled to be what it
has always actually been — the decision directory's front page, not a third
register — and its one false sentence is repaired by making it true rather than
by retracting it, because the retraction would have licensed the defect that
made the question worth asking. The 37 sections are demoted into the edit sets
they belonged to, on the finding that the event their heading names has occurred
zero times in 83 merges.

Four things this lane found that neither row contains, in descending order of
cost: **D29's record contradicts both registers about a frozen format decision,
and has for fourteen days**; **D101 and D114 have no pre-written row**, so the
backfill is 27 copies and 2 compositions rather than the pure copy job Q186
describes; **the sections are 37 in two spellings, not 35 in one**, and two of
them are numbered, so the disposition is not uniform; and **the mechanism never
applied a row at a merge**, so *"restore it"* and *"re-head it"* were both
answers about an event that never happened — while the concurrency problem the
sections actually solve is still live and is preserved. The first of these is
why the Edit set is ordered rather than listed.

Zero frozen bytes. No `cargo` invocation. Traceability green before, by message,
on all six checks and all 28 self-test cases.
