# D115 — Q134: what a `tasks/*.md` entry must contain when the row is its only source, and the two entries a lint lane may not write

- **Status: RESOLVED — the entryless set is confirmed exactly, and both of the
  row's characterisations of it are refused on a measurement.** The census is
  the row's: **20** rows without entries, **12 open** and **8 done**, the twelve
  named exactly, `Q130` confirmed drained. Nothing about the *set* is wrong.
  What is wrong is everything the row says *about* the set.
  **Premise "substantially a reformat, except two" is false in both direction
  and membership.** Measured row by row against the two fields that make an
  entry usable: **3** of the twelve carry both a `Do` and an `Accept`
  (`Q123`, `R76`, `U39`); **5** carry a `Do` and no `Accept`; **4** carry
  neither. So **9 of 12 need an acceptance criterion authored**, not
  transcribed, and **4 need the `Do` authored as well** — the split is 3/9, not
  10/2.
  **Premise "the Current-focus block describes A105 and A108 as reconstructed
  from disagreeing sources" is FALSE.** No such sentence exists. The phrase
  belongs to **A106** (`TODO.md:462`, A106's own closing text: *"the row was
  defined second-hand in three places that disagreed"*). D109 §2 (b) attributes
  it correctly to A106; **D109 §8 (iii) misattributes it to A105 and A108**, and
  Q134's row and its `tasks/Q.md` entry both inherit the error. The
  Current-focus block says only *"A105 and A108 need their domain owner, not a
  lint lane"* — a conclusion with no stated reason.
  **And the conclusion the false premise supports is also wrong about
  membership**: by the `Do`/`Accept` measure **A108 is better specified than
  four rows the row calls reformats** — it carries an explicit, located
  imperative — while `A72`, `A74` and `R60` sit in the same "neither" bucket as
  `A105` and are routed to the lint lane.
  **Premise "twelve entries and twelve deleted register lines in the same
  commit" is stronger than the checker requires, and the lane-boundary
  conclusion drawn from it is wrong.** Executed against a full copy of the tree:
  a partial drain of **10 of 12** is **green** on `--task-entries`, on the
  no-flag run and on `--self-test`. Atomicity is **per row**, not per batch —
  each row's entry and its register line must move together, and both
  half-drains were shown red. **The twelve can be split across lanes and
  commits.**
  **Premise "386–2 193 characters" is stale**: 2 193 is `Q130`'s row at
  `5fbc48d`, and `Q130` is the one that left. The twelve run **386–1 735**. The
  row corrected *thirteen → twelve* and did not re-measure the range it
  inherited from the same sentence.
  **A105 and A108 are reconstructed in §4** as paste-ready entries, every path,
  line number and claim in them checked against the tree — which found that
  **A108's own row is factually wrong about the frozen file set**: a signer-DN
  rendering change would move **one** frozen file, not two, and it is the one
  **without** the hatch. **A108's manifest half has already landed.**
- **Date: 2026-08-11** (M2 wave 13 planning round; briefed to confirm a twelve-row
  reformat and rule on entry provenance, and rules that nine of the twelve are
  authorship, that the two singled out were singled out for a reason that does
  not exist, and that the batch the brief treats as indivisible is divisible)
- **Owning tasks: Q134** (the ruling; its `Problem`, `Do` and `Accept` are all
  amended), **A105** and **A108** (reconstructed in full in §4), **Q135** (the
  atomicity ruling applies to it unchanged), **Q85** (the check this drains)
- **Amends**: **`TODO.md`'s Q134 row** and **`tasks/Q.md`'s Q134 entry**
  (`Problem`'s character range and its "reformat except two" claim; `Do`'s
  routing instruction; `Accept`'s same-commit clause). **Proposes** the two
  entries in §4 for `tasks/A.md`.
  **Supersedes**: nothing.
  **Corrects**: **D109 §8 (iii)**'s attribution of A106's history to A105 and
  A108 — subject to Q122, which is the open row asking whether a resolved
  decision's body may take a dated correction at all (§3.7).
  **Binds against**: `TODO.md`'s "How to use this list" protocol rules 1 and 2,
  `check_task_entries()` and `ROWS_PENDING_ENTRY`'s three staleness rules,
  D109 §3.5, `scripts/ci-lanes.sh:822-829` (`lane_traceability`),
  `scripts/local-gate.sh:262`, `docs/testing/verification-matrix.md`'s status
  gate, D101 §4.3 RULING 3b/3c, D94's three-class event vocabulary.

---

## The problem, in one sentence

Twelve rows have no detail entry, and the instruction to fix them assumes the
row text *is* the entry minus formatting — but an entry's load-bearing field is
its `Accept`, nine of the twelve rows do not have one, and an `Accept` written
by someone who did not execute the task is the exact defect Q134 exists to
close.

---

## 1. What was measured

Read from the working tree at `5fbc48d` + wave 12's uncommitted work, 2026-08-11.
Every figure came from a command run here; none is quoted from the brief or from
the row. Commands and verdicts are in §6.

### 1.1 The set is exactly the row's — this premise is confirmed, not overturned

An independent census (not the checker: my own row/entry parser, §6 command 2)
over `TODO.md` and `tasks/*.md`:

| | count |
|---|---|
| rows | 521 |
| entries | 501 |
| **rows with no entry** | **20** |
| entries with no row | **0** |
| duplicate entries | **0** |
| misfiled entries | **0** |

The 20 split **12 open / 8 done** and are, exactly:

- **open (12)** — `A72`, `A74`, `A76`, `A105`, `A108`, `Q88`, `Q89`, `Q122`,
  `Q123`, `R60`, `R76`, `U39`
- **done (8)** — `Q124`, `S27`, `S29`, `S34`, `U36`, `U37`, `U38`, `U40`

That is the row's twelve, character for character, and Q135's eight. **`Q130`
is confirmed drained** — it has an entry and is absent from the register.
`ROWS_PENDING_ENTRY` holds exactly these 20 and the checker is green:

```
[task-entries] ok — 521 rows (520 live + 1 struck) against 501 entries;
20 registered in ROWS_PENDING_ENTRY, 0 unexplained; no entry without a row,
no duplicate, none misfiled
```

The brief asked for a headline if the set differed in any direction. **It does
not.** D109's entry half is behaving exactly as specified, the register has
shrunk by exactly the one row that was drained, and no row added since
`BACKLOG_FROZEN_ON` lacks an entry — including `Q134` and `Q135` themselves,
which both have entries. This is the one premise in the row that survives
contact with the tree, and it is worth saying plainly because the rest do not.

### 1.2 The character range is stale, and stale in a diagnostic way

| id | chars (worktree) |
|---|---|
| `Q89` | 386 |
| `A76` | 407 |
| `A74` | 426 |
| `A72` | 472 |
| `R76` | 489 |
| `A108` | 494 |
| `Q88` | 502 |
| `A105` | 545 |
| `Q123` | 604 |
| `R60` | 718 |
| `Q122` | 723 |
| `U39` | 1 735 |

**386–1 735.** The row says 386–2 193. Measured at `5fbc48d`, `Q130`'s row is
**2 193 characters** — it is the maximum, and it is the row that left. D109
§8 (iii) measured thirteen; Q134's row corrected the *count* to twelve in the
same sentence that kept the *range* for thirteen.

This is small and it is the tell: the row was edited by someone who re-derived
one number in a sentence and carried the other. That is this project's dominant
defect class, sitting inside the row whose whole subject is text carried from
one place to another without re-derivation.

### 1.3 Nine of the twelve rows do not contain an `Accept`

This is the finding that refuses the brief's lean.

An entry's shape is not a matter of taste — it is measurable. Across all **501**
entries:

| field | present | share |
|---|---|---|
| `Milestone` | 501 | **100 %** |
| `Size` | 501 | **100 %** |
| `Deps` | 501 | **100 %** |
| `Do` | 501 | **100 %** |
| `Accept` | 501 | **100 %** |
| `Spec` | 373 | 74 % |
| `Notes` | 342 | 68 % |
| `Discovered by` | 228 | 45 % |
| `Problem` | 107 | 21 % |

Five fields are **exceptionless**. `Accept` is one of them, and it is the field
a lane actually executes against — the A22 failure Q134 keeps citing was a lane
running against a *superseded Accept*, not a superseded problem statement.

So the question "is this row substantially a reformat?" reduces to: **does the
row supply a `Do` and an `Accept`?** Classified against two explicit tests —

- **`Do` present** = an imperative naming a change and where it goes.
- **`Accept` present** = an observable condition under which the task is done
  (a test that reddens, a state of a named file, a check that passes).

| id | size | `Do` in row? | `Accept` in row? | class | what must be authored |
|---|---|---|---|---|---|
| `U39` | S | **yes** — *"Add a cheap compile-only lane (`cargo check -p antseal-cli --features ant-backend --all-targets` …) to `scripts/ci-lanes.sh` and the local gate"* | **yes** — *"and prove it red against the exact fault this found"*, and the row names the fault twice | **transcription** | nothing |
| `R76` | XS | **yes** — *"One-line cross-reference"*, doc named, target named (`R74`) | entailed by the `Do` | **transcription** | nothing |
| `Q123` | S | **yes** — *"The capture script must refuse to finish without all four provenance fields"* | entailed — the refusal is the observable | **transcription** | nothing |
| `A76` | S | **yes** — *"decide whether the engine selects the earliest committing height, and price the extra header fetch"* | no | **Accept authored** | what "priced" means; whether the decision or the implementation closes it |
| `A108` | S | **yes** — *"Name, in the freeze manifest's prose and in A26's `Do`, the three events …"*, both locations named | no, **and the three events are not enumerated in the row** | **Accept authored** | §4.2 |
| `Q88` | S | **yes** — *"Ratify or tighten"*, plus the instrument gap (*"no same-root-different-signer fixture"*) | no | **Accept authored** | whether ratifying alone closes it, or a fixture is required |
| `Q89` | S | **yes** in substance — *"Keep … from being conflated … unless the datum names diverge"* | no | **Accept authored** | which surface must change, given `R18/R61` own the wording |
| `Q122` | S | **yes** — *"Rule whether the body of a resolved decision gets dated corrections"* | no | **Accept authored** | whether the four stale sites are in scope or a follow-on |
| `A72` | S | **partial** — *"Reconcile the two disagreeing TSA identity notions"*; direction hinted (*"the seal-side number … over-counts"*), choice not made | no | **`Do` + `Accept` authored** | which notion is canonical — a ruling |
| `A74` | XS | **no** — a defect statement only; the fix could be the doc or the gate | no | **`Do` + `Accept` authored** | doc-fix vs gate-fix |
| `R60` | S | **no** — *"Options: count work (iterations) …; serialize …; or widen …"*, a menu of three with no choice | no | **`Do` + `Accept` authored** | which of three |
| `A105` | XS | **no** — defect + rationale only | no | **`Do` + `Accept` authored** | §4.1 |

**3 transcriptions. 5 need an authored `Accept`. 4 need an authored `Do` and
`Accept`.** The row's 10/2 is wrong in magnitude — nine, not two, require
judgment — and wrong in membership: `A108` carries a located imperative that
`A72`, `A74` and `R60` do not.

### 1.4 The reason A105 and A108 were singled out does not exist

Q134's row: *"**except A105 and A108**, which the Current-focus block describes
as reconstructed from disagreeing sources"*.

Grepped: `TODO.md` contains the words `disagree`, `second-hand` and
`reconstructed` at fifteen lines. **None of them is in the Current-focus block
and none of them is about A105 or A108.** The Current-focus block's only
sentence on the subject (`TODO.md:49`) reads, in full:

> *"**Q134** (M, the twelve open rows with no detail entry — Q85's dangerous
> half, and the reason A22 ran against a superseded Accept for two days; A105
> and A108 need their domain owner, not a lint lane)"*

— a conclusion with no reason attached. The phrase the row quotes is **A106's**,
at `TODO.md:462`:

> *"**`tasks/A.md` had no `### A106` entry at all** … and the row was defined
> second-hand in three places that disagreed (`tasks/A.md:1191` …,
> `tasks/Q.md:1544` …, `TODO.md:462`)"*

The chain of custody is traceable and it has exactly one break:

1. **D109 §2 (b)** — correct: *"the exact failure the Current-focus block
   records for **A106**, 'defined second-hand in three places that disagreed
   about its scope'"*.
2. **D109 §8 (iii)** — the break: *"**A105 and A108** are the two the
   Current-focus block describes as having been reconstructed from disagreeing
   sources"*.
3. **`TODO.md`'s Q134 row** and **`tasks/Q.md`'s Q134 entry** — both inherit it.

Q134's row states A106's history correctly one clause earlier (*"how A106 was
defined second-hand in three disagreeing places"*) and then attributes the same
history to two other ids in the next. The two statements are in the same
sentence.

**What this does not overturn**: A105 and A108 genuinely do need archaeology —
§4 is four hours of it. The conclusion is right. Its stated reason is invented,
its membership is wrong, and it is the *only* reason offered, so a lane reading
the row cannot tell which rows are actually hard. §1.3's table can.

### 1.5 Atomicity is per row and the checker was made to say so

Prototyped against a **full copy of the tree** (27 MB, everything but `.git` and
`target/`), verified green on `--task-entries`, on the no-flag run and on
`--self-test` before any mutation. Draining = appending `### <ID> — …` to
`tasks/<d>.md` and deleting that id's `ROWS_PENDING_ENTRY` line.

| # | scenario | `--task-entries` | `--self-test` | no-flag |
|---|---|---|---|---|
| F1 | drain **10 of 12**, entries + register lines together | **green** | **green** | **green** |
| F2 | drain **1 of 12** (`A72`) together | **green** | **green** | — |
| F3 | entry written, register line **kept** | **RED** — *"ROWS_PENDING_ENTRY registers A72 … but tasks/A.md now defines `### A72 — `. Drop the entry"* | — | — |
| F4 | register line deleted, entry **not** written | **RED** — *"TODO.md row A72 has no `### A72 — ` entry in tasks/A.md"* | — | — |
| F5 | drain **all 12 open**, 8 done remain | **green** | **green** | — |
| F6 | drain **all 20**, register left empty | **green** | **RED** — `AssertionError: self-test: ROWS_PENDING_ENTRY is empty, so case (k) cannot show the staleness rule bites` | — |

Three things follow, and only the first is in the row:

1. **Each row is atomic.** F3 and F4 are the two halves of one row's drain and
   both are red. The row's *"the two edits cannot be separated even by
   accident"* is true — **of a row**.
2. **The batch is not atomic.** F1 and F2 are green. There is no count
   assertion anywhere: `ROWS_PENDING_ENTRY` is a plain dict, D109 §6.2
   deliberately declined to pin its contents (*"a test that pinned the 21 ids
   would … convert draining from a deletion into a two-file edit"*), and nothing
   else reads its length. **Ten of twelve leaves the lane green.**
3. **The empty-register trap is Q135's, not Q134's, and only `--self-test`
   sees it.** F6 shows `--task-entries` alone stays *green* on an empty
   register; the guard lives in the self-test. Both `lane_traceability`
   (`scripts/ci-lanes.sh:822-829`) and the local gate
   (`scripts/local-gate.sh:262`, which calls `ci-lanes.sh traceability`) run
   `--self-test` first, so both would catch it — but a lane that ran only
   `python3 scripts/check-traceability.py --task-entries` would not.

### 1.6 `Spec` is optional, and may cite something other than the spec

373 of 501 entries carry `Spec`. The 128 that do not are not a domain
accident — they concentrate in the tooling domains (`Q` 54/123 absent, `A`
31/90, `U` 20/59) and are absent from the format domains entirely (`C` 0/29,
`G` 0/29). And of the 373 present, **17 cite no spec line at all**:

- `A36` → `Format registry §7.9`
- `A52` → ``docs/testing/error-code-contract.md`` §2, §4a; D91 §7.1, §8
- `A63` → `D58 §9.5, §13.1`
- `F51` → `D23 clause 3; registry §7.3 key 6`
- `Q67` → `D28, D74`

So the field is **optional and its value is an authority, not necessarily a
spec line**. That is the measured answer to "what if the row gives no `Spec`
reference", and it means the honest options are *omit* or *cite what the row
names* — never invent a line.

### 1.7 A landmine directly under A108's `Spec` line

`MVP-SPEC.md` line **123** is the obvious citation for *"a frozen anchor vector
cannot legally move"*. It is the wrong one, and the tree already knows it:
**Q132** closed four sites that cited line 123 for byte-immutability, and
**Q148** is open over **nine more**. Line 123 reads *"every **released**
manifest/bundle format version remains verifiable …"* — a **compatibility** rule
conditioned on *released*, and D104 §1.5 confirms nothing has been released. The
freeze's authority is **Q6's own act** for vectors, **Q14's** for the format
registry.

A108 writes a bullet about exactly this subject. §4.2's `Spec` line therefore
cites **line 109** (the RFC 3161 / pinned-root-store bullet, which is A26's
own) and the decisions, and §4.2's `Notes` names the trap so the bullet does not
become Q148's tenth site.

---

## 2. The options for the entry-authoring rule, and what kills each

### (a) Transcribe the row and stop — the brief's lean

Killed by §1.3. For nine of twelve there is nothing in the row to put under
`Accept`, and `Accept` is a 501/501 field. Transcription produces either an
entry with a missing mandatory field, or — worse, and this is what actually
happens — an `Accept` invented in the moment by whoever is typing, with nothing
recording that it was invented. That is A22's failure mode with the serial
numbers filed off.

### (b) Let the entry's `Accept` be authored freely by the drain lane

Killed by D109 §2 (b), which this decision agrees with: *"writing a `Do`/`Accept`
for a row you did not execute is defining the task second-hand"*. An authored
`Accept` that reads like a transcribed one is a **forged provenance**, and the
tree refuses forged provenance elsewhere on principle — Q126's entry: *"a
changelog composed by lanes that did not make the edits is fabricated
provenance, which this project refuses elsewhere"*; Q123's row: *"hashing the
files today would prove nothing about what arrived over the wire while looking
exactly like the field §4 asks for"*.

### (c) Leave the nine unentered until each row's owner runs it

Killed by circularity. The entry exists so that the lane that runs the row has a
`Do`/`Accept` to run against; deferring the entry to that lane means the entry
is written by the person who no longer needs it, and the hazard Q134 names —
*a lane opens `tasks/A.md` and improvises* — is exactly as live as before. It
also cannot be reconciled with the register, which fails a row with no entry
whether or not someone intends to write one later.

### (d) Write the entry, and make the authored `Accept` **say that it is
authored**, with a decision-shaped `Do` where the row states options and makes
no choice — **the ruling**

---

## 3. Ruling — what an entry must contain when the row is its only source

### 3.1 The five mandatory fields are mandatory, and there is no sixth

`Milestone`, `Size`, `Deps`, `Do`, `Accept`, in that order, at the top of the
entry — the shape 501 of 501 entries already have. `Problem`, `Spec`,
`Discovered by` and `Notes` are optional and follow the house ordering seen in
recent entries (`Milestone`, `Size`, `Deps`, `Spec`, `Discovered by`, `Problem`,
`Do`, `Accept`, `Notes`).

### 3.2 `Milestone` and `Size` are transcribed from the row and never re-estimated

Both appear in the row *and* the entry. Two homes for one value is this
project's most-found defect, so the entry carries the row's value **verbatim**.
A re-estimate goes in `Notes` as a dated observation and does **not** change the
field. (§4.2 does exactly this: A108's row says `S`, the measured remainder is
`XS`, the field stays `S`.)

### 3.3 `Deps` is transcribed from the row's `after:` clause, which is authoritative

Protocol rule 7: *"the `after:` lists on the checkbox lines here are the
authoritative build order"*. Where the row has no `after:` (`R60`, `Q122`), the
entry reads `Deps: none` rather than inventing one.

### 3.4 `Spec`: omit it, or cite the authority the row already names

Per §1.6. Three rules, in order:

1. If the row names a spec line, transcribe it.
2. If the row names a decision, a registry section or a doc section, cite
   **that**, in the `A52`/`F51`/`Q67` form. It is a `Spec` value in 17 existing
   entries.
3. If the row names nothing, **omit the field**. 128 entries do. Do **not**
   derive a spec line by inference and present it as the row's.

Where a spec line is derived rather than transcribed, the derivation is stated
where it is made — §4.1 cites line 173 and says in the same breath that it comes
through matrix row `V7.2`, not through the row.

### 3.5 The provenance line — required, and this is its exact form

**Every entry authored under Q134 or Q135 carries a dated, bolded top-level
bullet, immediately after `Accept`, naming the source and separating what was
transcribed from what was authored.** The house form for a dated provenance
statement already exists and is used throughout `tasks/*.md` — a bolded, dated
sentence as a top-level `- ` bullet (*"**Scope corrected 2026-08-09 by the
wave-10 recon; still open.**"*, *"**Accept row 2 amended 2026-08-09 by D101 §4.4
(RULING 3d).**"*, *"**RULED 2026-08-09 by D103 RULING 8**"*). This follows it:

```
- **Entry authored <YYYY-MM-DD> under Q134 from `TODO.md`'s <ID> row alone —
  no other source existed.** Transcribed from the row: <fields>. **Authored
  here, not transcribed: <fields>** — the row states <what it states> and names
  no acceptance criterion. <the basis on which the criterion was chosen>.
```

Three rules bind it:

- **It names the row by ID and date, never by line number.** `TODO.md` line
  numbers move on every wave; the ID cannot, because protocol rule 1 forbids
  renumbering. The verification matrix's own header states the same principle —
  *"References are by name, never by line number"* — for the same reason.
- **It must be possible to read the entry and know which sentences nobody
  verified.** An entry authored from a row must not read as though it were
  derived from the spec, from code, or from an executed run. If the `Do` was
  invented, the bullet says the `Do` was invented.
- **It is deleted, not edited, when the task is executed** — at which point the
  executing lane's own dated correction replaces it, in the house form. A
  provenance note that outlives its uncertainty is the Q99 defect.

### 3.6 Where the row states options and makes no choice, the `Do` **is** the choice

`A72`, `A74` and `R60` name a defect and either offer a menu or offer nothing.
The entry does **not** pick one and present it as settled — it makes the
decision the task:

> `- Do: rule which of <the row's options> governs, and record the reason where
>   <the thing> is read.`
> `- Accept: the ruling is recorded with its reason; <the consequence the ruling
>   entails> lands with it; and <the instrument> is red before and green after.`

This is precedented and is not a dodge: `A107`'s `Do` is *"rule which instant a
vector's `fetch_date` carries"*, `Q122`'s row is itself decision-shaped, and
`A76`'s row already says *"decide whether"*. It keeps a ruling from being
smuggled into the tree through a task entry — which is D109 §2 (b)'s objection,
honoured rather than argued with.

### 3.7 One correction this decision may not make

§1.4 finds an error in **D109 §8 (iii)**, a **resolved** decision. Whether a
resolved decision's body may take a dated correction, or whether only its
register row moves, is **exactly `Q122`** — one of the twelve, still open, and
its row names D84 §2's dated-corrections mechanism as the candidate. So this
decision **records** the error here and does **not** edit D109. `Q122` is
therefore a *blocker on its own entry's provenance line*, which is worth
recording as the sharpest possible demonstration that `Q122` is real work.

### 3.8 Atomicity and lane boundaries — the operative answer

**Per row: indivisible.** Entry and register line in one commit (§1.5, F3/F4).

**Per batch: divisible.** Ten of twelve is green (F1), one of twelve is green
(F2). **Q134's Accept overstates the constraint** and the orchestrator must not
plan lane boundaries from it. Amend the Accept to:

> Accept: all twelve have `### <ID> — ` entries; **each entry and its own
> `ROWS_PENDING_ENTRY` line land in the same commit** — the staleness rule makes
> either half alone a failure, verified in both directions; and
> `check-traceability.py --task-entries` **and `--self-test`** are green at
> every commit.

**The real constraint is git, not the checker.** The twelve entries live in four
files (`tasks/A.md` ×5, `tasks/Q.md` ×4, `tasks/R.md` ×2, `tasks/U.md` ×1) but
all twelve register lines live in **one** — `scripts/check-traceability.py`. Two
concurrent lanes draining different domains will both edit
`ROWS_PENDING_ENTRY` and collide. So:

- **Splitting by domain across concurrent lanes is possible but costs a
  serialization point** on one file. Not worth it for twelve entries.
- **The recommendation is one lane**, and §4 removes the reason there were ever
  going to be two: `A105` and `A108` were routed separately because they needed
  a domain owner, and their archaeology is done here.
- **`Q135` inherits all of this unchanged**, with one addition: its last drained
  row empties the register, and F6 shows that `--task-entries` **stays green**
  on an empty register while `--self-test` raises. Q135's Accept must name
  `--self-test` explicitly, or the lane that drains the last row will see green
  and ship a self-test that cannot run.

---

## 4. A105 and A108, reconstructed

Both blocks below are **paste-ready**. Every path, line number, quotation,
constant and test name in them was checked against the working tree; the
verification commands are §6. Where a claim in the row turned out to be false,
the block says so rather than repeating it.

### 4.1 A105

**The archaeology.** A25's Accept row 2 reads, verbatim in `tasks/A.md`:
*"Both real TSA tokens reach `proven` against the pinned store."* The row's two
line citations are **exact at the working tree**:

- `crates/antseal-core/src/anchor/verdicts/tests.rs:1205-1208` —
  `assert_eq!(state_of(&tsa(FREETSA, TsaRootStore::pinned(), AFTER_CAPTURE)), AnchorState::Proven)`,
  under the comment *"Anti-vacuity: the unmutated capture passes T2 and is
  classified by its chain"*, inside
  `a_token_whose_cms_signature_fails_never_reaches_chain_classification` (`:1184`).
- `:1313-1316` — the same shape for `DIGICERT`, under *"Anti-vacuity: the same
  token with no intermediates is `proven`, so the rejection is about the
  certificate and not about the token"*, inside
  `a_malformed_bundle_intermediate_is_invalid_with_a5s_der_code` (`:1294`).

`tsa()` (`:179-183`) calls **`evaluate_tsa_artifact`**, so these are
**verdict-level** assertions — T1 parse, T2 CMS signature and T3 chain.

**Two things the row does not say, both of which change the task.**

1. **The chain half is already covered by named tests.** `chain.rs` has
   `real_digicert_token_reaches_proven_with_the_cross_cert_present` (`:1230`),
   `..._with_the_cross_cert_removed` (`:1244`) and
   `token_carrying_its_own_self_signed_root_still_reaches_proven` (`:1292`,
   which covers `freetsa` and `dfn`). They call `validate_token_chain` /
   `validate_chain`, **not** `evaluate_tsa_artifact`. The gap is the end-to-end
   verdict, not the chain — and without this the lane writes a redundant chain
   test and thinks it is done.
2. **The property already has a matrix row, and it reads `NONE`.**
   `docs/testing/verification-matrix.md:117`:

   `| V7.2 | 173 | Real FreeTSA (ECDSA P-384) and DigiCert tokens verified against the pinned roots | M2 | A25 + A7 | deferred | NONE at M0 | |`

   That is A25 Accept row 2 restated, spec line **173** (verified verbatim:
   *"**(M2) Anchor smoke tests**: … real FreeTSA (ECDSA P-384) and DigiCert
   tokens verified against the pinned roots …"*). `--matrix --milestone M2`
   names `V7.2` among **11** rows that must read `covered` at the M2 review, and
   `ACCEPTED_NON_COVERED` is `{}`. So "a reader looking for the property finds
   nothing" is literally true of the file built to answer that question, and
   `V7.2` is the fix's home.

**Proposed entry — paste into `tasks/A.md` in numeric order:**

```markdown
### A105 — A25 Accept row 2 is pinned only as the anti-vacuity arm of two tamper tests
- Milestone: M2
- Size: XS
- Deps: after A25
- Spec: Anchor smoke tests (MVP-SPEC.md line 173) — reached through the matrix row that already exists for this property, `docs/testing/verification-matrix.md` V7.2, whose `spec line` cell reads 173; the row itself cites no spec line.
- Discovered by: **the A25 lane** (2026-08-07), in the per-Accept-row adjudication recorded in A25's entry.
- Problem: A25's Accept row 2 — *"Both real TSA tokens reach `proven` against the pinned store"* — has **no test named for it**. Both assertions live as the *anti-vacuity arms* of tamper tests: `verdicts/tests.rs:1205-1208` (`FREETSA`, inside `a_token_whose_cms_signature_fails_never_reaches_chain_classification`) and `:1313-1316` (`DIGICERT`, inside `a_malformed_bundle_intermediate_is_invalid_with_a5s_der_code`). The pin is **real** — both go through `evaluate_tsa_artifact` against `TsaRootStore::pinned()` and the build reddens if either token stops reaching `proven` — but it is a side condition of tests named for something else, so a future tamper-test rewrite can drop an arm and take an M2 milestone criterion with it, silently. **The file built to answer "where is this tested?" says it is not**: matrix row `V7.2` (`docs/testing/verification-matrix.md:117`) restates Accept row 2 exactly, is owned by `A25 + A7` at M2, and its `tests / evidence` cell reads `NONE at M0` with status `deferred`.
- Do: give the property its own named home at the **verdict** level, and name it in `V7.2`. Do **not** write a chain-level test: `chain.rs` already names three — `real_digicert_token_reaches_proven_with_the_cross_cert_present` (`:1230`), `..._with_the_cross_cert_removed` (`:1244`) and `token_carrying_its_own_self_signed_root_still_reaches_proven` (`:1292`, freetsa + dfn) — and they call `validate_token_chain`/`validate_chain`, not `evaluate_tsa_artifact`, so they do not cover T1 or T2. Keep both anti-vacuity arms exactly where they are; they serve their own tests' non-vacuity and deleting them would weaken two tamper tests to buy nothing.
- Accept:
  - A test **named for the property** asserts that both real captures reach `AnchorState::Proven` through `evaluate_tsa_artifact` against `TsaRootStore::pinned()` at `AFTER_CAPTURE` — `FREETSA` (from `anchor::testing::tamper_rows`) and `DIGICERT` (`verdicts/tests.rs:59`), over the real 2026-08-02 tokens, not synthetic ones.
  - It is shown **red** by a planted fault before it is trusted — dropping a pinned root, or moving `verify_at` outside the chain's validity, must redden it. A test whose only evidence is that nothing broke is the shape this project keeps finding in other people's suites.
  - Both anti-vacuity arms at `:1205-1208` and `:1313-1316` are **still present and still asserting**, so the new test is an additional home and not a migration.
  - Matrix row `V7.2`'s `tests / evidence` cell names the new test **by name, never by line number**, and `python3 scripts/check-traceability.py --matrix` resolves it. Whether `V7.2`'s status may move `deferred` → `covered` depends on `A25`'s row-1 script, which is A25's, not this row's — if it may not, `V7.2`'s notes cell says which half is outstanding rather than leaving a blank, because the file's own header says a blank cell reads as covered.
- Notes: `V7.2` is one of **11** rows `--matrix --milestone M2` names as `deferred` at or before M2 (`V2.3`, `V3.5`, `V6.1`–`V6.6`, `V7.1`–`V7.3`), so this row does not by itself unblock the M2 matrix gate and must not be described as if it did. `ACCEPTED_NON_COVERED` is empty, so nothing is currently exempted. The lane runs `check-traceability.py` with no flags, and `--milestone` defaults to `CURRENT_MILESTONE`, which is **`"M0"`** (`scripts/check-traceability.py:241`) — so today's green says nothing whatever about the M2 review, and will not until that constant moves.
- **Entry authored 2026-08-11 under Q134 from `TODO.md`'s A105 row alone — no other source existed.** Transcribed from the row: `Size`, `Deps`, `Discovered by`, and the `Problem`'s first two sentences. **Authored here, not transcribed: the whole `Do` and the whole `Accept`** — the row states a defect and a rationale and names no acceptance criterion at all. The criterion was chosen by finding where the tree already asks this question and finding it unanswered (`V7.2`), rather than by inventing a test shape; the "do not write a chain-level test" clause and the eleven-row caveat are findings of that search and are **not** in the row. The two line citations and A25's Accept row 2 wording were re-verified against the working tree on 2026-08-11 and are exact.
```

### 4.2 A108

**The archaeology, and the row is wrong twice.**

**The three events** are D101 §4.3's table, verbatim:

| event | likelihood | today |
|---|---|---|
| A26 root **removal** (a compromised CA) | rare, and A26 already requires *"an explicit compatibility note"* for it | none proposed |
| a signer-DN **rendering** change (§3.4) | low | none proposed |
| a root append introducing a second valid path (§4.2) | low | measured absent |

**Claim 1 — *"one of the three is not a store event at all (a signer-DN
rendering change)"* — CONFIRMED.** D101 §3.4: *"a change to how a DN is
*rendered* is a verifier change, not a store change or a format change"*. It
matters because A26 is the **root-store** task, so two of the three events are
A26's subject and the third is not, and A108's deliverable is a bullet in A26's
`Do`.

**Claim 2 — *"after A22 it would move two frozen files, one with a hatch and one
without"* — FALSE at the working tree. It moves ONE, and it is the one without
the hatch.** Measured from the frozen bytes:

- `testdata/vectors/v1/anchor/anchor.json` renders signer DNs in
  `expect.cases[].source.identity` — `"ST=Bayern,C=DE,…,CN=www.freetsa.org,…"`
  and `"CN=DigiCert SHA256 RSA4096 Timestamp Responder 2025 1,O=DigiCert\, Inc.,C=US"`,
  both on `proven` cases. A rendering change moves it.
- `testdata/vectors/v1/report/verification-reports.json` carries **three**
  anchor verdicts, at `expect.cases[19].report.anchors[0..2]`, and **all three
  are `{"source": null, "state": "invalid", "verified_time_unix": null}`**.
  There is no rendered DN in the file to change.

The mechanism is D94's own ruling, working as designed: the report vectors'
anchor bytes stayed **synthetic** (D94 refused swapping in A25 material as a
FIXTURE EVENT for zero gain, *"when the meaningful home is the `anchor` kind
already reserved for A22"*), synthetic bytes render `invalid`, and an `invalid`
anchor carries no identity — asserted in code at `verdicts/tests.rs:1199`
(`assert_eq!(outcome.identity(), None)`) and witnessed again by
`anchor.json`'s own `ots-wrong-seal` case, which is `invalid` with
`source: null`.

The same reasoning covers the other two events: a root **removal** or a root
**append** cannot move an anchor that is already `invalid` before chain
classification. **All three events move exactly one frozen file —
`anchor/anchor.json` — and none of them moves a `report/` vector.** So the
asymmetry D101 §3.4 described as *"one with a hatch and one without"* is in fact
*"the only file that moves has no hatch"*, which makes D101's RULING 3c (name
it) more necessary, not less — while leaving RULING 3b (do not build the hatch
speculatively) untouched, since A108 names and does not build.

**The precondition is met and half the work is done.**
`testdata/vectors/v1/FROZEN.sha256:91` carries `#! kind anchor A22`, so anchor
vectors exist. And `:82-90` — the prose immediately above that directive —
**already carries the manifest half**, naming all three events and going beyond
RULING 3c by adding *"None is proposed, and the third is measured absent
(`chain.rs`'s five-token append test)"*. A26's own entry says so explicitly:
*"The manifest half has landed with A22 (`FROZEN.sha256`, the paragraph beside
`#! kind anchor A22`); this half has not."*

**So A108's remaining work is one bullet in A26's `Do`** — and A26 is a
**closed** row (`✅ 2026-08-03`). That is legitimate and precedented: A26's `Do`
already carries *"**Added 2026-08-09 (D101 §4.2, RULING 3a):**"*, and A26 is a
`continuous` process task. It must be said in the entry, because "edit a closed
task's `Do`" is otherwise the kind of instruction a lane refuses on sight.

**Proposed entry — paste into `tasks/A.md` in numeric order:**

```markdown
### A108 — Name the three events that could need D94's verdict-event hatch, in A26's `Do`
- Milestone: M2
- Size: S
- Deps: after A22 (D101)
- Spec: Anchoring — RFC 3161, the pinned TSA root store (MVP-SPEC.md line 109); D101 §4.3 RULING 3b/3c; D94 §2a's three-class event vocabulary.
- Discovered by: **D101** (2026-08-07), §4.3.
- Problem: a frozen `anchor` vector **cannot legally move**. `verdict_event_ok` refuses anything without `/report/` in its path as its first check (`scripts/vector-freeze.sh:98-99`), so D94's verdict-event escape does not reach the `anchor` kind. D101 §4.3 lists the only three events that could ever require one — an **A26 root removal** (a compromised CA), a **signer-DN rendering** change, and a **root append that gives a pinned token a second valid path** — and RULING 3b deliberately declined to build the hatch, on D94's own finding that *"an unexercised instrument goes blind"*. RULING 3c instead requires the three be **named** in two places, so the event discovers the gap rather than a red lane discovering it at merge. One of the three is **not a store event at all** — a DN *rendering* change is a verifier change (D101 §3.4) — which is why it sits oddly in a root-store task's `Do` and why naming it there is the point rather than an oversight.
- Do: add the bullet RULING 3c asks for to **A26's `Do`**, beside the RULING 3a bullet already there, naming all three events, saying which of them A26 itself can cause (removal, append) and which it cannot (rendering), and pointing at D101 §4.3 as the list's home and at `verdict_event_ok` as where a hatch would be extended if one of them is ever proposed. **The freeze-manifest half is already done** — `testdata/vectors/v1/FROZEN.sha256:82-90`, the paragraph beside `#! kind anchor A22`, landed with A22 and already names all three — so this row's remaining scope is the A26 bullet plus the correction below. A26 is a **closed** row; amending its `Do` is correct here and precedented in that same `Do` (*"Added 2026-08-09 (D101 §4.2, RULING 3a)"*), and A26's milestone line marks it `continuous` thereafter.
- Accept:
  - A26's `Do` carries the bullet, naming all three events and distinguishing the two A26 can cause from the one it cannot.
  - The bullet cites **D101 §4.3** by section and `scripts/vector-freeze.sh`'s `verdict_event_ok` by name — **never by line number**, because both move.
  - The bullet does **not** cite `MVP-SPEC.md` line 123 as the authority for the vector's immutability. Line 123 is the ***released*-conditioned compatibility rule**; the freeze's authority is **Q6's own act**. Q132 closed four sites that got this wrong and **Q148** is open over nine more — this bullet must not become the tenth.
  - The blast-radius sentence is corrected wherever this row's own correction lands (see `Notes`): **one** frozen file moves, not two, and it is the one **without** a hatch.
  - `scripts/vector-freeze.sh` is **not** modified and `verdict_event_ok` is **not** extended — D101 RULING 3b stands, and this row names rather than builds. Zero frozen bytes move.
- Notes:
  - **This row's own blast-radius claim is false and was measured false on 2026-08-11.** The row says a signer-DN rendering change *"would move two frozen files, one with a hatch and one without"*, following D101 §3.4. Measured: `testdata/vectors/v1/anchor/anchor.json` renders signer DNs in `expect.cases[].source.identity` for its two `proven` TSA cases, and `testdata/vectors/v1/report/verification-reports.json`'s three anchor verdicts (`expect.cases[19].report.anchors[0..2]`) are **all** `{"source": null, "state": "invalid", "verified_time_unix": null}`. The report vectors kept D94's synthetic bytes; synthetic bytes render `invalid`; an `invalid` anchor carries no identity (`verdicts/tests.rs:1199`, and `anchor.json`'s own `ots-wrong-seal` case). By the same mechanism a root removal and a root append cannot move an anchor that is already `invalid` before chain classification, so **all three events move exactly one frozen file and none moves a `report/` vector**. The asymmetry is not "one hatched, one not" — it is that **the only file that moves is unhatched**, which strengthens RULING 3c and leaves RULING 3b untouched.
  - **Correcting D101 §3.4's body is blocked by Q122**, which asks whether a *resolved* decision's body may take a dated correction or whether only its register row moves. Until Q122 rules, the correction lives here and in the A26 bullet. Do not silently edit D101.
  - **Size stays `S` as the row declares it.** Measured remainder after the manifest half landed is **XS** — one bullet plus the correction. Recorded, not applied: `Size` lives in the row and the entry both, and two homes disagreeing about one value is the defect class this tracker keeps finding.
- **Entry authored 2026-08-11 under Q134 from `TODO.md`'s A108 row, D101 §3.4/§4.3, A26's entry and the frozen files.** Transcribed from the row: `Size`, `Deps`, `Discovered by`, and the `Do`'s opening imperative. **Authored here: the whole `Accept`, the `Spec` line, and both `Notes` bullets** — the row names no acceptance criterion and does not enumerate the three events it asks to have named. The three events are D101 §4.3's table verbatim, not a reconstruction. The "manifest half already landed" finding comes from A26's own `Notes` and was confirmed against `testdata/vectors/v1/FROZEN.sha256:82-90`; the blast-radius correction is a measurement of the two frozen documents, made here for the first time.
```

---

## 5. Edit set

| file | change |
|---|---|
| `TODO.md` | Q134's row: character range `386–2 193` → `386–1 735`; *"substantially a reformat except A105 and A108"* → §1.3's 3/5/4 split; delete the false Current-focus attribution; Accept's *"in the same commit"* → §3.8's per-row wording. This decision's register line. |
| `tasks/Q.md` | Q134's entry: the same four corrections to `Problem`, `Do` and `Accept`. Q135's `Accept` gains `--self-test` (§1.5, F6). |
| `tasks/A.md` | **new**: §4.1's `A105` entry, §4.2's `A108` entry, in numeric order. |
| `tasks/A.md`, `tasks/Q.md`, `tasks/R.md`, `tasks/U.md` | the other ten entries, per §3. |
| `scripts/check-traceability.py` | twelve `ROWS_PENDING_ENTRY` lines deleted — **each in the commit that adds its own entry** (§3.8). No other change: no new check, no register rule, no constant. |
| `docs/decisions/D109-*.md` | **none** — §3.7. The §8 (iii) error is recorded here and its correction waits on Q122. |
| `docs/testing/verification-matrix.md` | **none in Q134's lane.** `V7.2` is A105's execution, not A105's entry. |
| `scripts/vector-freeze.sh`, `testdata/vectors/v1/**`, `docs/format/FROZEN.sha256` | **untouched.** Zero frozen bytes. |

---

## 6. Commands run for this decision, with verdicts

| # | command | verdict |
|---|---|---|
| 1 | `python3 scripts/check-traceability.py --task-entries` | **exit 0** — 521 rows (520 live + 1 struck), 501 entries, 20 registered, 0 unexplained |
| 2 | independent row/entry census (own parser, not the checker) | 20 rows without entries, **12 open / 8 done**, 0 entries without rows, 0 duplicates, 0 misfiled — identical to the register |
| 3 | row-length census at `HEAD` and at the working tree | twelve = **386–1 735**; thirteen incl. `Q130` = 386–**2 193** at `5fbc48d`, 386–**4 091** in the worktree |
| 4 | field census over all 501 entries | `Milestone`/`Size`/`Deps`/`Do`/`Accept` **501/501**; `Spec` 373; `Notes` 342; `Discovered by` 228; `Problem` 107 |
| 5 | `Spec`-value census | 356 of 373 cite a spec line; **17 cite a decision, registry section or doc**; 128 entries omit the field |
| 6 | full-tree copy → `--self-test`, no-flag run | both **green** before any mutation, so the drain scenarios are not measuring a broken baseline |
| 7 | drain scenarios **F1–F6** (§1.5) | 10/12 **green**; 1/12 **green**; both half-drains **red**; 12/12 **green**; 20/20 green on `--task-entries` and **red** on `--self-test` |
| 8 | `sed` at `verdicts/tests.rs:1195-1215`, `:1303-1320` | `:1205-1208` and `:1313-1316` are **exactly** the two `proven` assertions — the row's citations are correct |
| 9 | enclosing-`fn` resolution for both line ranges | `a_token_whose_cms_signature_fails_never_reaches_chain_classification` (`:1184`), `a_malformed_bundle_intermediate_is_invalid_with_a5s_der_code` (`:1294`) |
| 10 | `grep -rn 'fn .*proven'` over `crates/` | **three named chain-level tests exist** in `chain.rs` (`:1230`, `:1244`, `:1292`); **none** at the verdict level |
| 11 | `grep -n 'A25\|proven' docs/testing/verification-matrix.md` | `V7.2` at `:117`, `deferred`, `NONE at M0`, empty notes |
| 12 | `python3 scripts/check-traceability.py --matrix --milestone M2` | **exit 1, 11 rows** — `V2.3`, `V3.5`, `V6.1`–`V6.6`, `V7.1`, `V7.2`, `V7.3`; `ACCEPTED_NON_COVERED` is `{}` |
| 13 | `sed -n '173p' MVP-SPEC.md` | verbatim match for `V7.2`'s bullet |
| 14 | JSON walk of `report/verification-reports.json` | 3 anchors, **all** `state: "invalid"`, `source: null`, `verified_time_unix: null` |
| 15 | JSON walk of `anchor/anchor.json` | 7 cases; two `proven` TSA cases carry rendered signer DNs in `source.identity`; the one `invalid` case has `source: null` |
| 16 | `sed -n '74,100p' testdata/vectors/v1/FROZEN.sha256` | the RULING 3c paragraph is **present** at `:82-90` beside `#! kind anchor A22` (`:91`) |
| 17 | `grep -n 'verdict_event_ok' -A 12 scripts/vector-freeze.sh` | `:98-99` — refuses anything without `/report/` in the path, as its first check |
| 18 | `grep -n 'disagree\|second-hand\|reconstructed' TODO.md` | 15 hits, **none** in the Current-focus block, **none** about A105 or A108; the phrase is A106's at `:462` |
| 19 | `grep -n '\*\*Q148\*\*\|\*\*Q132\*\*' TODO.md` | line 123 is the *released*-conditioned compatibility rule; 4 sites closed by Q132, **9 open under Q148** |
| 20 | `sed -n '815,832p' scripts/ci-lanes.sh`; `grep -n traceab scripts/local-gate.sh` | `lane_traceability` runs `--self-test` then the no-flag run; the local gate reaches it via `ci-lanes.sh traceability` |

`cargo` was not run. Nothing in this decision changes Rust; §4.1's `Accept`
prescribes a test but does not write one.

---

## 7. What this does not do

- **It does not write the other ten entries.** §3 is the rule they follow and
  §1.3 says which of them need an authored `Accept`; the text is the drain
  lane's.
- **It does not rule A72, A74 or R60.** §3.6 makes their `Do` the ruling rather
  than guessing it. Three decision-shaped entries land, three decisions do not.
- **It does not correct D109 §8 (iii).** §3.7 — blocked on `Q122`, which is one
  of the twelve.
- **It does not correct D101 §3.4's "two frozen files".** Same blocker. The
  correction lives in §4.2's entry and in the A26 bullet.
- **It does not execute A105 or A108.** It writes their entries. `V7.2`'s status
  cell, the new verdict-level test and A26's bullet are the executing lane's.
- **It does not check that an entry is any good** — D109 §7's residual is
  untouched. `--task-entries` still only asks whether an entry exists, and an
  entry authored under §3.5 with a wrong `Accept` is exactly as invisible to it
  as a missing one is visible. The provenance line is the only mitigation and it
  is a convention, not a check (§8 (ii)).
- **It does not touch `Q135`** beyond §1.5's finding that its Accept needs
  `--self-test` named.

---

## 8. Discovered work — described, not registered

*(The wave owner allocates and registers. No id is minted here.)*

**(i) D109 §8 (iii) attributes A106's history to A105 and A108, and two live
documents have inherited it.** — M2 · XS · deps: Q122, Q134. §1.4. The claim
*"the Current-focus block describes A105 and A108 as reconstructed from
disagreeing sources"* is false — no such sentence exists, and the phrase is
A106's own row text at `TODO.md:462`. It is now in `TODO.md`'s Q134 row and
`tasks/Q.md`'s Q134 entry, both of which Q134's own lane will edit anyway.
Editing D109 itself is blocked on Q122. Accept: the two live copies are
corrected in Q134's lane; D109's body is corrected or its register row is
annotated, per whatever Q122 rules.

**(ii) Nothing distinguishes an entry authored from a row from an entry written
by the lane that executed the task.** — M3 · S · deps: Q134, Q135. §3.5 rules
that entries authored under Q134/Q135 carry a dated provenance bullet, and
nothing enforces it: `--task-entries` asks only whether a `### <ID> — ` heading
exists. Twenty entries will be written this way and the convention will be
invisible six weeks from now. The tractable form is narrow — an entry whose id
was in `ROWS_PENDING_ENTRY` must carry the bullet — and it has a natural death
date, since the register is drained by design, so it should probably be a
**one-shot check run at Q135's close** rather than a `CHECKS` entry that
outlives its subject. Accept: either the twenty entries are shown to carry the
bullet by something that ran, or the reason a convention was preferred to a
check is written where the convention is stated.

**(iii) `V7.2` is one of eleven matrix rows that will fail the M2 review, and
nothing has costed them.** — M2 · S · deps: Q13, Q51. §1.5 / command 12.
`--matrix --milestone M2` names `V2.3`, `V3.5`, `V6.1`–`V6.6`, `V7.1`, `V7.2`,
`V7.3` — including **six M1 rows** still reading `deferred` while M2 is the
current milestone, which by the file's own rule means M1 shipped with six
uncovered bullets or six stale rows. `ACCEPTED_NON_COVERED` is empty, so none of
them is an accepted hole. The lane runs the checker with no flags and
`--milestone` defaults to `CURRENT_MILESTONE`, so this is invisible until
someone types `--milestone M2`. Accept: each of the eleven is either covered,
re-dated, or registered in `ACCEPTED_NON_COVERED` with a written reason; and the
six M1 rows are separated from the five M2 ones, because a stale M1 row and a
genuinely uncovered M2 row are different findings.

**(iv) The report vectors' anchor slots are all `invalid`, so every anchor field
in `report/` is pinned at its null value.** — M3 · S · deps: A22, D94.
§4.2 / command 14. `expect.cases[19].report.anchors[0..2]` are the only anchor
verdicts in the `report` kind and all three read
`{"source": null, "state": "invalid", "verified_time_unix": null}`. That is
D94's deliberate choice and it is correct, but the consequence has not been
written down anywhere: **the `report` kind pins the D29 anchor surface only in
its degenerate case**, so a change to how `source`, `state` or
`verified_time_unix` renders on a *non-degenerate* anchor is invisible to every
`report/` vector and visible only to `anchor/`, which cannot legally move. The
two kinds together therefore have a blind spot neither has alone. Accept: the
blind spot is stated in `report/README.md` or in the D94 successor, naming which
kind pins which half; or a `report` case carrying a non-degenerate anchor is
proposed with its FIXTURE-EVENT cost priced.

**(v) `Size` and `Milestone` live in two places with no check.** — M3 · XS ·
deps: Q85. §3.2 rules that the entry transcribes the row, and nothing verifies
it. `--task-entries` compares *existence*, not content, and the row/entry pair
is the only place in the tracker where the same scalar is written twice by
different hands. Twenty entries about to be written from rows is exactly when
the two can diverge silently. Measured cost is unknown and should be measured
first: if today's 501 pairs already disagree anywhere, that is the finding.
Accept: either the pairs are checked, or the count of existing disagreements is
recorded so the next lane knows whether this is a real class or a hypothetical.

---

## Outcome

**RESOLVED, 2026-08-11.** The entryless set is **exactly** what Q134 says —
20 rows, **12 open / 8 done**, the twelve named correctly, `Q130` confirmed
drained, the register neither stale nor grown. Everything the row says *about*
that set is refused on a measurement. **"Substantially a reformat, except two"
is 3/9, not 10/2**: classified against the two fields an entry is executed
from, **3** rows carry both a `Do` and an `Accept` (`Q123`, `R76`, `U39`), **5**
carry a `Do` and no `Accept`, and **4** carry neither — so **nine of twelve need
an acceptance criterion authored**, and an authored `Accept` is precisely what
D109 §2 (b) refuses to let a lint lane write silently. **The reason A105 and
A108 were singled out does not exist**: no sentence in the Current-focus block
describes them as reconstructed from disagreeing sources; the phrase is
**A106's**, at `TODO.md:462`, and the misattribution enters at **D109
§8 (iii)** and is inherited by Q134's row and entry — which state A106's history
correctly one clause earlier. **And the membership is wrong too**: `A108`
carries a located imperative that `A72`, `A74` and `R60` do not, so the two
routed to a domain owner are not the two that most need one. **The batch is
divisible**: executed against a full tree copy, draining **10 of 12** is green
on `--task-entries`, on the no-flag run and on `--self-test`, while both halves
of a *single* row's drain are red — atomicity is **per row, not per batch**, the
Accept's *"in the same commit"* overstates the checker, and the real
lane-boundary constraint is that twelve register lines live in one file while
twelve entries live in four. **One lane is recommended anyway**, because §4 does
the archaeology that was the reason for two. **A105**'s two line citations
verify exactly, and two things the row does not say change the task: `chain.rs`
already names three chain-level `proven` tests, so the gap is the **verdict**
level; and the property already has a matrix row, `V7.2`, whose evidence cell
reads **`NONE at M0`** — the file built to answer "where is this tested?" says
it is not. **A108**'s manifest half **has already landed**
(`testdata/vectors/v1/FROZEN.sha256:82-90`, beside `#! kind anchor A22`), so its
remaining work is one bullet in the `Do` of a **closed** task; its "not a store
event" claim is confirmed; and its blast-radius claim is **false** — measured
from the frozen bytes, a signer-DN rendering change moves **one** file, not two,
because `report/`'s three anchor verdicts are all `invalid` with `source: null`,
and by the same mechanism **all three events move only `anchor/anchor.json`, the
one with no hatch**. That strengthens D101 RULING 3c and leaves RULING 3b
standing. The entry-provenance convention is a **dated, bolded top-level bullet
naming the row by ID and date, never by line number**, separating what was
transcribed from what was authored — the house form already used for dated
corrections — and where a row offers a menu and no choice, **the `Do` is to make
the choice**, so no ruling is smuggled into the tree through a task entry.
Correcting D109 §8 (iii) and D101 §3.4 is **blocked on `Q122`**, one of the
twelve, which is the sharpest available demonstration that `Q122` is real work.
Zero frozen bytes; no `cargo` run; no change to any check.

---

## Index row (orchestrator applies at merge)

| [D115](D115-entryless-row-reconstruction.md) | Q134 — what an entry must contain when the row is its only source — **the set is confirmed exactly and every claim about it is refused**. 20 entryless rows, **12 open / 8 done**, `Q130` confirmed drained, register neither stale nor grown. But **"substantially a reformat except two" is 3/9, not 10/2**: only `Q123`, `R76` and `U39` carry both a `Do` and an `Accept`; 5 carry a `Do` alone; 4 carry neither — **nine of twelve need an `Accept` authored**, which is exactly what D109 §2 (b) forbids a lint lane to do silently. **The reason A105/A108 were singled out does not exist** — no Current-focus sentence says it; the phrase *"defined second-hand in three places that disagreed"* is **A106's** (`TODO.md:462`), misattributed at **D109 §8 (iii)** and inherited by Q134's row and entry, which get A106 right one clause earlier. Membership is wrong too: **A108 is better specified than `A72`, `A74` and `R60`**. **Atomicity is per row, not per batch** — measured on a full tree copy: 10-of-12 drained is green on `--task-entries`, the no-flag run **and** `--self-test`, while both halves of one row's drain are red — so the twelve **can** be split; the real constraint is that twelve register lines share one file. **A105**: both cited line ranges verify exactly, but `chain.rs` already names three chain-level `proven` tests (the gap is the **verdict** level), and matrix row **`V7.2`** already exists for the property reading **`NONE at M0`**. **A108**: the **manifest half already landed** (`FROZEN.sha256:82-90`), leaving one bullet in a **closed** task's `Do`; and its *"two frozen files, one with a hatch and one without"* is **false** — `report/`'s three anchor verdicts are all `invalid` with `source: null`, so **all three events move only `anchor/anchor.json`, the file with no hatch**, which strengthens D101 RULING 3c. Provenance convention: a **dated bolded bullet naming the row by ID, never by line number**, separating transcribed from authored; where the row offers a menu, **the `Do` is the choice**. Correcting D109 §8 (iii) and D101 §3.4 is **blocked on `Q122`**, one of the twelve. Also found: `--matrix --milestone M2` names **11** deferred rows incl. **six M1 rows**; the `report` kind pins the anchor surface only in its degenerate case; `Size`/`Milestone` live in two places unchecked. Character range corrected **386–2 193 → 386–1 735** (2 193 was `Q130`'s, the row that left). Zero frozen bytes, no `cargo` run | RESOLVED (Q134 executes) | 2026-08-11 |


---

## Amendment — the document contradicts itself on the provenance bullet, 2026-08-10

**Recorded, not applied. The body above is byte-unchanged** — which this record
mandated for itself: §3.7 rules that correcting a resolved decision's body is
`Q122`'s question and that this decision *"records the error here and does not
edit"*. That rule now applies to this record's own errors, which is the sharpest
available demonstration that `Q122` is real work.

**§3.5 and §4 give two different placements for the provenance bullet.** §3.5
states its *"exact form"* as **immediately after `Accept`**; §4's two worked
blocks — the examples a lane implements from — place it **last, after `Notes`**.
Lane C followed §4 for all twelve entries, so the tree is consistent and the
ruling is not. **Follow §4**: the twelve entries in `tasks/{A,Q,R,U}.md` all
carry the bullet after `Notes`, verified by parsing each entry's field order,
and the four entries wave 13's bookkeeping authored follow them. Settling this
before `Q135` writes twenty more is `Q167`.

**§4.1 undercounts the `chain.rs` `proven` tests.** The record says `chain.rs`
*"already names three chain-level `proven` tests"*; the A105 entry written from
it names **four** over real tokens. The conclusion is unaffected — the gap is at
the **verdict** level either way — but the figure should not be quoted.

**§4.2's `scripts/vector-freeze.sh:98-99` is stale**, and was stale-adjacent
when written. `verdict_event_ok`'s `/report/` guard is now at `:114` with its
message at `:115-117`, in a function opening at `:103`; at `d23dccc` the guard
was at `:98`. This wave's own edits to that file moved everything +5. D101
§4.3's `:99-101` misses in the other direction, and a third instance survives at
D101 `:784`. Registered as `Q169` — and it is the argument for extending the
no-line-number rule beyond the frozen registry, made by the tree rather than
argued.

**§4.2's `D94 §2a` citation is CORRECT and the correction filed against it is
the thing that is wrong.** It was reported that this record, `D101` RULING 3c,
`scripts/vector-freeze.sh` and `testdata/vectors/v1/FROZEN.sha256` all cite §2a
for a table that is *"Ruling 4 in §2"*. Measured in
`D94-anchor-verdict-vector-re-emit.md`: `## 2.` opens at `:41`, `### 2a.` at
`:83`, Ruling 4 at `:99` with its three-class table at `:102-106`, and the next
`##` at `:115` — **the table is inside §2a**, which is the containing subsection,
and D94 itself cites bare `§2a` for it three times. All four citations stand.
What is false is `tasks/A.md:1278`, in the A108 entry written from this record,
which calls §2a *"the neighbouring subsection"*. Registered as `Q168`.

**The blocks in §4 carry a future date, 2026-08-11**, as does this record's own
`Index row`. The register line entered at wave 13's bookkeeping records
**2026-08-10**, the day the decision was made and executed.

**Every ruling in §3 stands**, including §3.2's rule that a re-estimate goes in
`Notes` without moving the field, which is what makes `Q166` writable.
