# D109 — Q85: the real scope of the task-ID traceability gap, and what its checker does about the backlog

- **Status: RESOLVED — Q85 is TWO checks, not one, under two flags; the
  citation half lands GREEN having found one real dangling pointer, and the
  entry half lands GREEN behind a date-locked, self-draining register of the
  21 rows that predate it.** The brief's lean — *mirror `check_decisions()`,
  "the same twenty lines pointed at the other kind of pointer"* (Q85's own
  Notes, `tasks/Q.md:1280`) — is **refused on a measurement**: the D namespace
  is **dense** (D1–D108, **zero** holes), and the task namespaces are **15–30 %
  holes** (**71** unallocated numbers inside `1..max` across the nine
  domains). `check_decisions()`'s `n > max(allocated)` bound is nearly free for
  a dense namespace and is a false-positive generator for a sparse one — every
  one of the three noise-and-genuine hits this check finds today lands in a
  hole, which is the mechanism, not a coincidence. The design therefore
  diverges from its sibling in three places, each measured.
  **Premise 1 of the brief is confirmed and is worse than stated**: Q85's
  Accept bullet 1 is not merely stale, it was **unsatisfiable the day it was
  written** — `A68` and `Q87`, two of the seven ids it requires the check to
  name, are cited in **zero** files anywhere under `crates/ docs/ scripts/
  fuzz/ verifier-web/ testdata/`, so no citation sweep could ever have named
  them. **Premise 4 is disproved in three places**: the sweep returns **20**
  ids, not 21 (`A71` is absent from it because it lives in `scripts/fuzz.sh`,
  a `.sh` file under a directory the decision half's `DECISION_SCAN` does not
  reach — a **second** hole, in the surface set, that the brief's own sweep
  found only by being wider than the code); `A0`/`C0`/`F0` are **not** "labels
  in `canon/pipeline.rs`" but **hex byte values** in UTF-8 comments (`C0`,
  `F0`, `A0` as lead and continuation bytes), which matters because a
  `n >= 1` floor kills them and a label register would not; and **`F64` is not
  genuine** — it is `Type::F64`, minicbor's IEEE-754 binary64 discriminant, so
  the bound "hiding" it is correct behaviour rather than a hole. **Premise 5 is
  confirmed and closed at zero cost**: the decision half does have the same
  hole (a newly minted, unregistered id is by definition above the ceiling),
  and a *marked-form-only* second tier above the ceiling catches it while
  reporting **zero** false positives on today's tree. **Premise 2 is confirmed
  exactly** — the 21 are the 21 — and project memory is **wrong** about S33 and
  S35: both have entries. **Premise 3 is confirmed with a correction that
  changes the fix**: `P18` needs **no exemption at all**; it needs the row
  regex to accept the struck form protocol rule 1 mandates, after which the
  count is 498 = 497 live + 1 struck = the header total, and *entries with no
  row* is **0**.
- **Date: 2026-08-10** (M2 wave 12 planning round; briefed to scope one check
  and rule on a 21-row backlog, and rules that the backlog is two backlogs of
  different kinds — 3 and 21 — which must not share a flag)
- **Owning tasks: Q85** (the ruling; its `Do` is rewritten and its Accept
  bullet 1 replaced), **Q66** (the self-test rule the fixtures obey),
  **Q57/Q58** (the decision half this diverges from, with reasons)
- **Amends**: **`tasks/Q.md` Q85's `Do`, `Accept` and `Notes`** (`:1264-1284`);
  **`TODO.md`'s Q85 row** (`:527`); **`scripts/check-traceability.py`** (module
  docstring, `CHECKS`, two new checks, two new self-test groups).
  **Supersedes**: nothing. **Binds against**: `TODO.md`'s "How to use this
  list" protocol rules 1 and 2, `check_decisions()`'s bound and
  `DECISIONS_HOMED_ELSEWHERE`, `check_matrix()`'s `ACCEPTED_NON_COVERED`
  staleness rules, Q66's derived-fixture rule, `scripts/ci-lanes.sh:822-828`
  (`lane_traceability`), `scripts/local-gate.sh:262`.

---

## The problem, in one sentence

Q85 asks for one mirrored check and the tree contains **two different defects
with two different backlogs** — 3 unresolved citations and 21 rows without
entries — and folding them into one flag would couple a half that can land
green to a half that cannot, which is how a lane gets switched off.

---

## 1. What was measured

Read from the tree at `5fbc48d`, 2026-08-10. Every figure below came from a
script I wrote and ran; none is quoted from the brief. Commands and verdicts
are in §6.4.

### 1.1 The row and entry grammars are exactly uniform — so both can be pinned hard

Rows in `TODO.md` take **two** shapes and only two:

| shape | count | example |
|---|---|---|
| `- [ ] **ID**` / `- [x] **ID**` | 497 | `TODO.md:527` |
| `- ~~**ID**` (struck, protocol rule 1) | 1 | `TODO.md:378`, `P18` |

497 + 1 = **498**, which equals the header's *"**498 tasks** today"* and the
sum of the domain table's nine counts, each of which I checked individually
against the actual rows: **all nine agree**. A census of every `- `-initial
line in `TODO.md` that bolds an id found **zero** lines in any third shape.

Entries in `tasks/*.md` take **one** shape: `### <ID> — <title>`. There are
**477** level-3 headings matching `^### [A-Z]\d+`, and **477** matching
`^### [A-Z]\d+ — ` — the em-dash form is universal, exceptionless. There are
**zero** level-3 headings in `tasks/*.md` that are not an id entry, **zero**
duplicate entries, and **zero** entries filed in the wrong domain's file.

This uniformity is what lets §4 specify exact regexes rather than tolerant
ones, and it is why the entry half can be a hard equality rather than a
heuristic.

### 1.2 The struck row is not an exception to handle — it is a shape to parse

`P18` is the tracker's one struck row. It has an entry (`tasks/P.md`) and a
row (`TODO.md:378`), and the row carries **no checkbox at all**:

> `- ~~**P18** (S) Pin `opentimestamps = "=0.2.0"` scoped codec-only; wasm32 viability check — after P7,P14~~ — **RETIRED 2026-08-02 by D58**…`

A checkbox-only regex reports `P18` as an *entry with no row* — a false
positive on the one row protocol rule 1 most wants preserved, and the reason
a grep of the P domain returns 26 where the header says 27. **With the struck
form parsed, `entries with no row` is 0** — the "known standing offset" is not
standing and not an offset; it is a regex bug in every ad-hoc script that has
measured this file, including the two that produced this brief.

This matters beyond `P18`: rule 1 says *"Never delete a task: strike it
through"*, so the struck shape is **protocol-mandated and will recur**. A
hardcoded `P18` exemption would go stale on the second retirement and would
have to be found by hand. Parsing the shape costs one alternation.

### 1.3 A sub-heading inside an entry is not a second entry

`tasks/Q.md:155` is `### Q14 — Run the M0 format-freeze gate with recorded
sign-off`; `tasks/Q.md:168` is `#### Q14 freeze checklist — normative rows`, a
level-4 sub-heading **of that same entry**, landed by Q37. It is the only
sub-heading of its kind in the tree, and it sits immediately above the
`FREEZE-BOUNDARY:BEGIN` marker at `:180` — i.e. adjacent to bytes that
`--freeze-boundary` compares. A detector keyed on `^#{2,4}` reports `Q14`
twice; a detector keyed on exactly `^### ` reports it once. **Sub-headings are
permitted and must be tolerated**; the level is the whole discriminator.

### 1.4 The decisive asymmetry: D is dense, the task domains are 15–30 % holes

This is the finding that refuses the brief's lean.

| domain | max allocated | rows | holes in `1..max` |
|---|---|---|---|
| **D** | 108 | 108 | **0** |
| A | 116 | 89 | 27 |
| Q | 132 | 112 | 20 |
| R | 76 | 64 | 12 |
| F | 53 | 49 | 4 |
| P | 30 | 27 | 3 |
| S | 38 | 35 | 3 |
| U | 66 | 64 | 2 |
| C | 29 | 29 | 0 |
| G | 29 | 29 | 0 |
| | | | **71 total** |

`check_decisions()`'s only bound is `n > max(allocated) → skip`. For a **dense**
namespace that bound is equivalent to *"n is allocated"*, so the decision half
has, by construction, almost no false-positive surface. For the task
namespaces it is **71 numbers wide**, and every unresolved hit the sweep
returns today lands in a hole:

- `A71` — a hole in A (A has 27 holes)
- `Q72` — a hole in Q (20 holes)
- `R46` — a hole in R (12 holes)

Q85's Notes call this *"the same twenty lines pointed at the other kind of
pointer"*. It is not. The bound that makes the sibling clean is the bound that
makes this one noisy, and the divergences in §3 are all downstream of this one
table.

### 1.5 The surface set has its own hole, and the one genuine finding is inside it

`DECISION_SCAN = ["crates", "docs/format", "docs/testing"]` with
`DECISION_SUFFIXES = {".rs", ".md", ".json", ".py"}`. Sweeping exactly that,
with the numeric bound applied per domain, returns **two** in-bound
unresolved task ids: `Q72` and `R46`.

`A71` is invisible to it, and `A71` is the only unambiguously genuine dangling
task pointer in the tree. It lives in `scripts/fuzz.sh:98` and `:103`:

> `# CAVEAT, recorded because it bounds what the anchor_token seeds buy (A71):`
> …
> `# a corpus of `real_imprint ‖ token` pairs would reach further and is A71.`

That is real, described, unregistered work — a fuzz-corpus improvement whose
scope is already written down in a committed script, pointing at an id no row
defines. It is missed **twice over**: `scripts/` is not in `DECISION_SCAN`, and
`.sh` is not in `DECISION_SUFFIXES`. The brief's wider sweep found it; the code
this decision is asked to mirror cannot.

Widening to `scripts/` costs nothing on the other side either: sweeping
`scripts/` and `.github/` for **decision** citations adds **zero** new
unresolved decisions (§8 (i)).

### 1.6 What the noise actually is — and why a numeric floor kills three quarters of it

The brief characterises `A0`/`C0`/`F0` as *"labels in `canon/pipeline.rs`"*.
They are not labels. They are **hex byte values in UTF-8 prose**:

- `crates/antseal-core/src/canon/pipeline.rs:655` — *"Overlong 2-byte encoding of '/': **C0** can never begin a valid…"*
- `:660` — *"Lead byte broken immediately: subparts are **F0** and 8C."*
- `:662` — *"Overlong 3-byte encoding: E0 requires **A0**..=BF next"*
- `crates/antseal-core/src/content/split.rs:328` — *"U+00A0 is two UTF-8 bytes (C2 **A0**)"*

No domain allocates id 0, so a **`n >= 1` floor** removes all three, and
removes every future hex byte ending in `0` of that form. The distinction
matters: a label register would have to name them one at a time forever.

The remainder, classified:

| token | where | class | killed by |
|---|---|---|---|
| `A0`, `C0`, `F0` | UTF-8 comments | hex bytes | `n >= 1` floor |
| `P384` | `anchor_real_tokens.rs` | NIST curve | ceiling (P max 30) |
| `U256` | `antseal-net` ×4 | EVM integer width | ceiling (U max 66) |
| `S310` | `crosscheck_cbor.py` | ruff `# noqa: S310` | ceiling (S max 38) |
| `F64` | `cbor_pin_eval.rs` | `Type::F64`, IEEE-754 | ceiling (F max 53) |
| `R46` | `roots/mod.rs`, `roots/PROVENANCE.md` | **CA root name** | **nothing numeric** |

`R46` is the hard case and the reason a register exists at all: *"Sectigo
Public Time Stamping Root R46"* is a certificate subject DN in a normative
source file, R has 12 holes, and 46 is one of them. No bound based on numbers
can distinguish it from a citation.

Note also `F64`'s neighbours: `Type::F16` and `Type::F32` appear in the same
file and **F16 and F32 are allocated rows**, so those two tokens resolve
silently today. The day F's ceiling passes 64 without `F64` itself being
minted — F already has holes at 45–48, so this is the normal case, not the
odd one — `Type::F64` becomes a tier-1 failure. That is a dated trap and §7
names it rather than leaving it to be discovered.

### 1.7 Q85's Accept bullet 1 was unsatisfiable when written, for two independent reasons

The brief says the seven ids now all have rows, so the criterion names a state
that no longer exists. True. But the stronger fact is that the criterion could
**never** have been met. Citation reach of the seven across
`crates/ docs/ scripts/ fuzz/ verifier-web/ testdata/`, counted by file:

| id | files citing it | of which `docs/decisions/` |
|---|---|---|
| A56 | 2 | 1 |
| A59 | 11 | 1 |
| A63 | 3 | 1 |
| A67 | 3 | 1 |
| A70 | 1 | 0 |
| **A68** | **0** | 0 |
| **Q87** | **0** | 0 |

`A68` and `Q87` are cited **nowhere**. Q85's `Do` asserts all seven were
*"cited in committed source and docs"*; for two of them that is false. A check
run against the pre-fix tree could have named at most **five**, and with
`docs/decisions/` excluded (§3.3) at most **two**. The replacement criterion is
R7.

### 1.8 What the two checks report on today's tree

Prototyped and run (§6.4, command 5):

**Citation half**, scanning `crates docs/format docs/testing scripts` over
`.rs .md .json .py .sh .mjs`, excluding the checker's own file, 352 files:

- **tier 1** (`1 <= n <= domain ceiling`, any occurrence) — **3**: `A71`, `Q72`, `R46`
- **tier 2** (`n > ceiling`, marked occurrence only) — **0**

**Entry half**: 498 rows, 477 entries, **21** rows with no entry, **0** entries
with no row, **0** duplicates, **0** misfiled. The 21 are exactly the brief's
list. Their split matters:

| | count | ids |
|---|---|---|
| **open** rows | **13** | A72, A74, A76, A105, A108, Q88, Q89, Q122, Q123, Q130, R60, R76, U39 |
| **done** rows | 8 | Q124, S27, S29, S34, U36, U37, U38, U40 |

The 13 open rows are the live hazard Q85 describes — *"a lane that opens
`tasks/A.md` to read its task's `Do`/`Accept` finds nothing and improvises"*.
The 8 done rows are archaeology; nobody will execute them. Their row texts run
1 617–4 044 characters and already carry the outcome inline.

### 1.9 Project memory is wrong about S33 and S35

Memory records *"`tasks/S.md` has none for S33/S34/S35"*. Measured: **S34** has
no entry; **S33 and S35 have entries**, and in fact have no rows either — 33
and 35 are holes in S. The note conflated "row without entry" with "number not
allocated". Only S34 belongs on the list.

---

## 2. The options, and what kills each

### (a) One check, one flag, mirroring `check_decisions()` — the brief's lean

Killed twice. **Structurally**, by §1.4: the sibling's bound is safe because D
is dense and unsafe here because the task domains are not, so a mirror is not a
mirror. **Operationally**, by the backlogs: the citation half can land green
today after three registrations, and the entry half cannot land green today
under any reading that does not involve writing 21 entries. Under one flag the
21 hold the 3 hostage, the lane lands red, and — the file's own sentence,
twice — *a lint with false positives is a lint people learn to ignore*. The
observable consequence would be `lane_traceability` red on every push, which
means `--task-citations` gets commented out along with everything else. Two
flags cost one dict entry.

### (b) Fix all 21 entries inside Q85's lane

Killed on **who is qualified**. Writing a `Do`/`Accept` for a row you did not
execute is *defining the task second-hand* — which is the exact failure the
Current-focus block records for A106, *"defined second-hand in three places
that disagreed about its scope"*. Q85's lane is a Python-lint lane; it has no
standing to reconstruct A105's or A108's anchor scope, and a wrong entry is
worse than a missing one because a missing entry is visibly missing. It is also
a size mismatch: Q85 is **S**, and 21 entries at 1 617–4 044 characters of
source row text apiece is **L**. Rejected as a whole, but **not** rejected in
part — §3.4 splits it.

### (c) Narrow the entry half to open rows only

Killed on **silence at the wrong moment**. It would land green today at 8
exemptions' worth of cost saved, but the rule *"a row must have an entry"*
would then be untrue of the tracker exactly when a done row is reopened or
cited by a later wave — which happened this wave: S34 and S38 were both read by
the D106 lane while closed. Worse, it makes the check's own predicate
state-dependent, so ticking a row would *remove* it from coverage. A gate that
gets weaker when work completes is backwards.

### (d) Land the entry half red, with the 21 as known failures

Killed by the brief's own sentence and by precedent: `traceability` is a
**required status context** (one of the 19), wired at
`scripts/ci-lanes.sh:1270` and `scripts/local-gate.sh:262`, and it runs
`check-traceability.py` with **no flags**, i.e. every entry in `CHECKS`. A new
check added to that dict is red in required CI from its first commit. There is
no "land it red and watch it" mode here.

### (e) A numeric-only bound, no register

Killed by `R46` (§1.6): a CA root name inside a hole, in `crates/`. No floor
and no ceiling separates it from a citation. Any design without a register
fails on the tree it is landing against.

### (f) Marked-form-only for *all* tiers

Attractive — it reports exactly one unresolved id on today's tree (`Q72`) and
zero noise. Killed on **coverage**, measured: of the 352 task ids cited in the
scan surfaces, **218 appear only in bare form**. The rule would see 38 % of
citations. Decisively, of the seven ids Q85 was written for, the marked rule
sees four, the bare rule sees five, and neither sees `A68` or `Q87` at all
(§1.7). Marked-form-only is right *above the ceiling*, where there is no
allocation evidence at all, and wrong below it, where there is.

### (g) Two checks, two flags; floor + ceiling + a path-scoped register below; marked-form-only above; the entry half behind a date-locked register — **the ruling**

---

## 3. Ruling

### 3.1 Two checks, two flags

`Q85` lands as **two** entries in `CHECKS`:

| flag | function | check label | question it answers |
|---|---|---|---|
| `--task-citations` | `check_task_citations` | `task-citations` | does an id cited in a normative surface have a row? |
| `--task-entries` | `check_task_entries` | `task-entries` | does a row in the tracker have a detail entry? |

They share no code path beyond `allocated_task_ids()`. The citation half reads
`TODO.md` + the scan surfaces; the entry half reads `TODO.md` + `tasks/*.md`
and **never** touches the scan surfaces. They are different questions with
different inputs and — the operative reason — **different backlogs that must be
able to fail independently**.

### 3.2 The bound is a floor, a ceiling, and a shape above the ceiling

Three rules, in order:

1. **Floor.** `n >= 1`. No domain allocates 0. Kills `A0`, `C0`, `F0` and every
   future hex byte of that shape.
2. **Tier 1 — at or below the ceiling.** For `1 <= n <= max allocated in that
   domain`: **any** occurrence is a citation. This is where allocation evidence
   exists, so bare mentions count. Residual noise is handled by
   `TASK_ID_NOT_A_CITATION` (§3.5), not by widening the bound.
3. **Tier 2 — above the ceiling.** For `n > max allocated in that domain`: only
   a **marked** occurrence counts — the id as the entire content of a backtick
   span (`` `A117` ``) or a bold span (`**A117**`). Above the ceiling there is
   no allocation evidence at all, so the citation must assert itself
   typographically.

Tier 2 is what closes premise 5's hole, and it closes it at **zero measured
cost**: 0 tier-2 failures on today's tree, with `F64`, `P384` and `U256` all
present above their ceilings and none of them ever written marked. Proven by
planting all three forms (§6.4, command 6): `` `A117` `` → seen, `**A117**` →
seen, bare `A117` → not seen.

**The blind spot, named.** A newly minted, unregistered id written **bare** and
above its domain's ceiling is not reported. This is deliberate: bare tokens
above the ceiling are where every curve name, integer width and lint code in
the tree lives. What covers it instead: (i) ids are conventionally written
marked in this codebase — 134 distinct ids appear marked in the scan surfaces;
(ii) the moment the domain's ceiling advances past that number for any reason,
the citation drops into tier 1 and fires; (iii) `--task-entries` catches the
same defect from the other side the instant a row is added. This paragraph is
required verbatim-in-substance as a comment in the code (§4, R2).

### 3.3 `docs/decisions/` is OUT of the citation sweep; `scripts/` is IN

**Out**, for the reason the decision half is already built that way —
`DECISION_SCAN` excludes `docs/decisions/` — and for a reason of its own: a
decision record's job includes **proposing** work that the orchestrator may
then number, renumber or decline. Measured cost of including it: **13**
tier-1 failures, 11 of them ids that `D92-proven-ots-anchor-identity.md` and
`D93-online-refutation-precedence.md` merely proposed (`A73`, `A75`, `A77`,
`A78`, `A79`, `A87`, `Q90`, `Q91`, `Q95`, `R62`, `R63`). Failing a lane for
those punishes the one document type whose purpose is to say *"a row is needed
for …"* — including this one, whose §8 does exactly that.

This leaves half of the wave-4 failure mode uncovered (an id minted in a brief
and cited only in a decision doc). What covers it instead: **`--task-entries`**
covers the tracker side completely, and a decision doc's proposals are read at
bookkeeping by the orchestrator, which is the process step that exists for it.
The residual, stated plainly: an id proposed in a decision record, never
numbered, and never cited outside `docs/decisions/` is invisible to both
checks. That is acceptable because nothing depends on it — no code, no test and
no other document points at it.

**In**: `scripts/` joins the scan, and `.sh` and `.mjs` join the suffixes.
`scripts/` holds the gate itself; a dangling task pointer there is as normative
as one in `crates/`. This is not symmetry for its own sake — it is where the
one genuine finding lives (§1.5).

`scripts/check-traceability.py` **excludes itself**. It must, because its own
registers name ids as string literals and its self-test plants ids, and a
self-swept checker would report its own fixtures. (The decision half is not
self-swept today only by accident: it does not scan `scripts/`, yet its
self-test literal `D77000` would already be skipped by the ceiling. Adding
`scripts/` to `DECISION_SCAN` — §8 (i) — must carry the same exclusion.)

### 3.4 The backlogs

**Citation half — backlog 3, drained to zero inside Q85's lane, lands GREEN.**

| id | disposition |
|---|---|
| `R46` | `TASK_ID_NOT_A_CITATION`, two paths — a CA subject DN, not a citation |
| `Q72` | `TASK_ID_NOT_A_CITATION`, one path — **mention, not use** |
| `A71` | **gets a row.** Not suppressed. |

`Q72` is the interesting one. `docs/testing/error-code-contract.md:215-219`
does not cite Q72 as work; it **documents that Q72 was never issued** —
*"`Q72` is named by neither, so D60 points a reader at nothing"* … *"A38 = Q80
= Q72 = the work this section is"*. A check that fails on the sentence
recording its own class of finding is absurd. The register entry says so.

`A71` is refused suppression on principle: it is real, described,
unregistered work (§1.5), and registering it as noise would make the check's
first run certify a dangling pointer instead of finding one. **The check must
earn its keep on its first run**, which is this project's pattern —
A113's checker found a wrong number on its first run, in a row nobody had
touched. The row is described in §8 (ii) for the orchestrator to number.

**Entry half — backlog 21, registered, drained by follow-up rows, lands GREEN.**

`ROWS_PENDING_ENTRY` is seeded with all 21 and **closed the same day**
(§3.5). It is drained by two follow-up rows, described in §8 (iii) and (iv):
the **13 open** rows first, because those are the live hazard, and the **8
done** rows separately and later, because they are archaeology. Splitting them
is the point: one is urgent M2 content work owned by the domains, the other is
a tidy-up that must not be allowed to delay the first.

### 3.5 What stops either register growing silently

Both registers carry the `ACCEPTED_NON_COVERED` idiom — *a stale entry is
itself a failure* — plus one mechanism each that makes growth an unmistakable
act.

`TASK_ID_NOT_A_CITATION` is keyed **`(id, path)`**, never by id alone. A
suppression in one file cannot mute a genuine citation of the same id in
another. Three failure rules: an entry matching no occurrence at its path is
stale and fails; an entry whose id has since gained a row is a lie and fails;
and — the growth brake — the key is a **path**, so silencing a new false
positive requires naming the exact file, which is reviewable in a diff in a way
that adding a bare id is not.

`ROWS_PENDING_ENTRY` is **date-locked**. Every value carries a registration
date, and the check fails any entry whose date is not `BACKLOG_FROZEN_ON =
"2026-08-10"`. The register is therefore **closed, not capped**: a 22nd entry
cannot be added without either dating it 2026-08-10 — a false statement in a
diff, next to a constant whose comment forbids it — or moving
`BACKLOG_FROZEN_ON`, which invalidates all 21 at once and cannot be done
quietly. A row added after 2026-08-10 without an entry is **a defect to fix,
not an exemption to grant**, and the failure message says exactly that.

---

## 4. Riders — normative, cite by number

Implementation-facing. No design freedom is intended below; where a name,
flag, path or message is given, it is the name, flag, path or message.

### R1 — Constants and parsing

Added to `scripts/check-traceability.py`, after `check_decisions()`:

```python
TASK_DOMAINS = "PFCGSARUQ"

# Where task citations are swept. Mirrors DECISION_SCAN and adds `scripts/`:
# the gate is committed code and a dangling task pointer there is as normative
# as one in `crates/`. docs/decisions/ is deliberately OUT — see D109 §3.3.
TASK_SCAN = ["crates", "docs/format", "docs/testing", "scripts"]
TASK_SUFFIXES = {".rs", ".md", ".json", ".py", ".sh", ".mjs"}

# This file names task ids as literals in its registers and plants them in
# `--self-test`. Sweeping it would report its own fixtures (D109 §3.3).
TASK_SCAN_SELF = "scripts/check-traceability.py"

# Both row shapes. `- ~~**P18**` carries NO checkbox: protocol rule 1 says a
# retired task is struck, never deleted, so this shape is mandated and will
# recur. A checkbox-only regex reports P18 as an entry with no row — the false
# positive on the one row the protocol most wants preserved (D109 §1.2).
TASK_ROW = re.compile(r"^- (?:\[[ xX]\]|~~)\s*\*\*([" + TASK_DOMAINS + r"])(\d+)\*\*", re.M)

# An entry is a level-3 heading, exactly. `tasks/Q.md:168`'s
# `#### Q14 freeze checklist` is a sub-heading OF the Q14 entry, not a second
# entry; sub-headings are permitted and `^#{2,4}` reports Q14 twice.
TASK_ENTRY = re.compile(r"^### ([" + TASK_DOMAINS + r"])(\d+) — ")

TASK_BARE = re.compile(r"\b([" + TASK_DOMAINS + r"])(\d{1,3})\b")
TASK_MARKED = re.compile(
    r"`([" + TASK_DOMAINS + r"])(\d{1,3})`|\*\*([" + TASK_DOMAINS + r"])(\d{1,3})\*\*"
)
```

Three helpers:

- `allocated_task_ids() -> dict[str, set[int]]` — every row in `TODO.md` via
  `TASK_ROW`, keyed by domain letter. **Must** total 498 today across both
  shapes; if it totals 0 for any reason the check fails with *"no task ids
  found in TODO.md's register — the bound is vacuous"*, mirroring
  `check_decisions()`.
- `task_id_ceiling(allocated) -> dict[str, int]` — `max()` per domain.
- `task_detail_entries() -> dict[str, list[tuple[str, int]]]` — every
  `TASK_ENTRY` match across `sorted((ROOT / "tasks").glob("*.md"))`, id → list
  of `(filename, line)`. A list, not a scalar, so duplicates are reportable.

### R2 — `check_task_citations(failures)`, check label `task-citations`

Sweep `TASK_SCAN` over `TASK_SUFFIXES`, skipping `target`, `node_modules`,
`__pycache__` and `TASK_SCAN_SELF`. Collect bare hits and marked hits as
`id -> set[relative path]`.

For each cited id not in `allocated`:

- `n < 1` → skip silently (the floor; hex bytes).
- `1 <= n <= ceiling[domain]` → **tier 1**. If `(id, path)` is in
  `TASK_ID_NOT_A_CITATION` for **every** path it was seen at, skip; otherwise
  fail for the unsuppressed paths.
- `n > ceiling[domain]` → **tier 2**, and only if the id appears in
  `marked_hits`. Bare-only above the ceiling is skipped.

The blind-spot comment of §3.3 goes immediately above the tier-2 branch, in
substance and with its three mitigations.

Failure messages, verbatim:

```
f"{tid} is cited ({where}) but has no row in TODO.md's register. Either the "
f"id was minted in a brief and never registered — add the row and its "
f"tasks/{domain}.md entry — or the token is not a task citation at all, in "
f"which case register it in TASK_ID_NOT_A_CITATION keyed by (id, path) with "
f"the reason."
```

```
f"{tid} is cited in marked form ({where}) and is above domain {domain}'s "
f"highest allocated number ({ceiling}), so no row for it can exist. That is "
f"what a freshly minted, never-registered id looks like. Add the row, or "
f"unmark the citation if it is not a task id."
```

Register staleness, both directions:

```
f"TASK_ID_NOT_A_CITATION registers ({tid}, {path}) as not-a-citation "
f"({reason}) but no occurrence of {tid} was swept there. Remove it — a stale "
f"suppression is how a lint decays into a permanent mute."
```

```
f"TASK_ID_NOT_A_CITATION suppresses {tid} at {path}, but {tid} now has a row "
f"in TODO.md. The suppression asserts something false about an allocated id; "
f"remove it and let the citation resolve."
```

Success line:

```
f"[{check}] ok — {n_ids} distinct task ids cited across {n_files} files, all "
f"resolve ({n_suppressed} registered as not-citations); no unregistered id "
f"cited in marked form above its domain ceiling"
```

The register, seeded exactly:

```python
# Tokens that match a task id and are not citations. Keyed by (id, PATH) so a
# suppression in one file can never mute a real citation of the same id
# elsewhere. A stale entry is itself a failure — see check_task_citations.
TASK_ID_NOT_A_CITATION: dict[tuple[str, str], str] = {
    ("R46", "crates/antseal-core/src/anchor/roots/mod.rs"):
        "'Sectigo Public Time Stamping Root R46' — a CA subject DN. 46 is a "
        "hole in R (R has 12), so no numeric bound can separate it.",
    ("R46", "crates/antseal-core/src/anchor/roots/PROVENANCE.md"):
        "Same DN, in the provenance table that records where the root came "
        "from.",
    ("Q72", "docs/testing/error-code-contract.md"):
        "Mention, not use: :215-219 RECORDS that Q72 was never issued — "
        "'Q72 is named by neither, so D60 points a reader at nothing' and "
        "'A38 = Q80 = Q72 = the work this section is'. Failing on the "
        "sentence that documents the defect is not the check working.",
}
```

### R3 — `check_task_entries(failures)`, check label `task-entries`

Reads `TODO.md` and `tasks/*.md` only. Five failure classes:

1. **Row with no entry**, unless registered:
```
f"TODO.md row {tid} has no `### {tid} — ` entry in tasks/{domain}.md. A lane "
f"that opens tasks/{domain}.md to read this task's Do/Accept finds nothing "
f"and improvises. Write the entry. ROWS_PENDING_ENTRY is closed "
f"({BACKLOG_FROZEN_ON}) and is not available for rows added since."
```
2. **Entry with no row** (in either shape):
```
f"tasks/{file}:{line} defines `### {tid} — ` but TODO.md has no row for "
f"{tid}, in either the checkbox form or the struck form `- ~~**{tid}**`. "
f"Statuses live only in TODO.md (protocol rule 1), so an entry with no row "
f"has no status and no milestone."
```
3. **Duplicate entries**:
```
f"{tid} has {count} `### {tid} — ` entries ({places}). An entry is the single "
f"home of a task's Do/Accept. A sub-heading inside an entry must be `#### `, "
f"not `### `."
```
4. **Misfiled entry**:
```
f"{tid}'s entry is in tasks/{file} but domain {domain} is homed in "
f"tasks/{domain}.md — one file per domain, per TODO.md's header table."
```
5. **Register staleness**, three rules — entry now exists; row no longer
   exists; date is not `BACKLOG_FROZEN_ON`:
```
f"ROWS_PENDING_ENTRY registers {tid} ({reason}) but tasks/{domain}.md now "
f"defines `### {tid} — `. Drop the entry — a stale exemption is how a gate "
f"decays into a permanent mute."
```
```
f"ROWS_PENDING_ENTRY registers {tid} but TODO.md has no row for it at all."
```
```
f"ROWS_PENDING_ENTRY entry {tid} is dated {date}, not {BACKLOG_FROZEN_ON}. "
f"This register was CLOSED on {BACKLOG_FROZEN_ON} and may only shrink: a row "
f"added since then that lacks its entry is a defect to fix, not an exemption "
f"to grant."
```

Anti-vacuity, mirroring `check_matrix`'s `gate_rows` guard: if
`allocated_task_ids()` yields 0 rows **or** `task_detail_entries()` yields 0
entries, fail with *"the entry check would be vacuous"*.

Success line:

```
f"[{check}] ok — {n_rows} rows ({n_live} live + {n_struck} struck) against "
f"{n_entries} entries; {n_pending} registered in ROWS_PENDING_ENTRY, 0 "
f"unexplained; no entry without a row, no duplicate, none misfiled"
```

The register:

```python
# CLOSED 2026-08-10 (D109 §3.5). These 21 rows predate --task-entries. The
# date is the lock: every value must carry BACKLOG_FROZEN_ON, so a 22nd entry
# cannot be added without either dating it falsely in a diff or moving the
# constant, which invalidates all 21 at once. It may only SHRINK. Drained by
# the two follow-up rows D109 §8 (iii) and (iv) describe.
BACKLOG_FROZEN_ON = "2026-08-10"
ROWS_PENDING_ENTRY: dict[str, tuple[str, str]] = {
    # --- open rows: the live hazard, drained first ---
    "A72":  (BACKLOG_FROZEN_ON, "open, M2 — TSA identity reconciliation"),
    "A74":  (BACKLOG_FROZEN_ON, "open, M2 — MIN_VERIFIED_TSA_TOKENS doc claim"),
    "A76":  (BACKLOG_FROZEN_ON, "open, M2 — recorded Bitcoin height is merge order"),
    "A105": (BACKLOG_FROZEN_ON, "open, M2 — A25 Accept row 2"),
    "A108": (BACKLOG_FROZEN_ON, "open, M2 — freeze-manifest events in A26's Do"),
    "Q88":  (BACKLOG_FROZEN_ON, "open, M2 — two signers under one root"),
    "Q89":  (BACKLOG_FROZEN_ON, "open, M2 — distinct calendars vs identities"),
    "Q122": (BACKLOG_FROZEN_ON, "open, M2 — dated corrections to resolved decisions"),
    "Q123": (BACKLOG_FROZEN_ON, "open, M2 — capture script provenance fields"),
    "Q130": (BACKLOG_FROZEN_ON, "open, M2 — cross-check scope by field-name sniff"),
    "R60":  (BACKLOG_FROZEN_ON, "open — R54's load-sensitive linear-time guard"),
    "R76":  (BACKLOG_FROZEN_ON, "open — AnchorResult::source doc mood"),
    "U39":  (BACKLOG_FROZEN_ON, "open — no lane type-checks --features ant-backend"),
    # --- done rows: archaeology, drained second ---
    "Q124": (BACKLOG_FROZEN_ON, "done — vectors README post-Q14 sentence"),
    "S27":  (BACKLOG_FROZEN_ON, "done — D37 per-sub-batch capture hook"),
    "S29":  (BACKLOG_FROZEN_ON, "done — imported complete work unrestorable"),
    "S34":  (BACKLOG_FROZEN_ON, "done — closed with U66 under D106"),
    "U36":  (BACKLOG_FROZEN_ON, "done — CLI storage-backend construction seam"),
    "U37":  (BACKLOG_FROZEN_ON, "done — init/consent gate in the default lane"),
    "U38":  (BACKLOG_FROZEN_ON, "done — D39 flag-supplied value not re-asked"),
    "U40":  (BACKLOG_FROZEN_ON, "done — durable receipt sink attached"),
}
```

### R4 — `CHECKS` and the module docstring

```python
CHECKS = {
    "freeze-boundary": check_freeze_boundary,
    "matrix": check_matrix,
    "decisions": check_decisions,
    "task-citations": check_task_citations,
    "task-entries": check_task_entries,
}
```

`main()` needs no change: `--task-citations` reaches
`args.task_citations` through the existing `name.replace("-", "_")`, and a
bare run selects all five. The docstring's list gains:

```
    --task-citations    Every task id cited in code, in a normative doc or in
                        a gate script resolves to a row in TODO.md's register
                        (Q85).
    --task-entries      Every row in TODO.md has a detail entry in
                        tasks/<domain>.md, and every entry has a row (Q85).
```

and the opening sentence *"Two checks live here"* becomes *"Five checks live
here"* — it already reads `Two` against three checks, which is its own small
instance of this project's dominant defect class and is corrected here.

### R5 — Q85's `Do` is rewritten

`tasks/Q.md:1264`'s `Do` currently asserts the seven ids were *"cited in
committed source and docs"*, which is false for `A68` and `Q87` (§1.7), and
prescribes *"the same twenty lines"*, which §1.4 refutes. It is replaced with
D109's §3 and §4 by reference: *"Implement D109 §4 R1–R4."* The `Notes`
sentence *"this is the same twenty lines pointed at the other kind of
pointer"* is replaced by *"D109 §1.4: the D namespace is dense and the task
namespaces are 71 holes wide, so the sibling's bound does not transfer."*

### R6 — `--milestone` is untouched

`check_task_citations` and `check_task_entries` take no milestone argument and
must not be added to `main()`'s special-casing of `matrix`. They are
milestone-independent by construction.

### R7 — Q85's Accept, replacing bullet 1

The stale bullet 1 (*"fails before the seven rows are added, naming all
seven"*) is deleted. The new Accept, executable against the tree at
`5fbc48d`:

1. **The citation half's before-state is recorded from a real run.** With
   `TASK_ID_NOT_A_CITATION` empty and before `A71` gains a row,
   `--task-citations` fails naming **exactly three** tier-1 ids and their
   paths: `A71` (`scripts/fuzz.sh`), `Q72`
   (`docs/testing/error-code-contract.md`), `R46`
   (`crates/antseal-core/src/anchor/roots/mod.rs`,
   `crates/antseal-core/src/anchor/roots/PROVENANCE.md`) — and **zero** tier-2
   ids. Both the red output and the green output after R2's register and
   `A71`'s row land are pasted into the commit message.
2. **The entry half's before-state likewise.** With `ROWS_PENDING_ENTRY`
   empty, `--task-entries` fails naming exactly the 21 of §1.8, and **zero**
   entries-without-rows — the second number is the one that proves the struck
   form is parsed, because a checkbox-only regex reports `P18`.
3. **The floor and ceiling are asserted, not observed.** A test asserts that
   `A0`, `C0`, `F0`, `P384`, `U256`, `S310` and `F64` are all present in the
   swept tree and none is reported.
4. **Tier 2 is proven in both directions** — R8's cases (c) and (d).
5. **`P18` is proven in both directions** — R8's case (h).
6. All self-test cases in R8 pass, and each mutation is derived from the
   file's current state per Q66 — no case may contain a literal task id.

### R8 — The self-test cases

Added to `self_test()`'s `cases` list, in its existing
`(check, file, mutation, expect)` shape. **Q66's rule is binding: not one of
these may hard-code a task id, a count or a line number.** Two helpers are
added beside `strip_marker`/`flip_tick`/`retick_upper`, both of which read the
scratch tree at fixture time:

```python
def first_hole(domain: str) -> str:
    """The lowest unallocated number in `domain`, read from the scratch tree."""

def above_ceiling(domain: str) -> str:
    """`domain` + (its highest allocated number + 1), read from the scratch tree."""
```

Both raise rather than return a literal if the tree yields nothing, so a
regex that stops matching makes the fixture fail loudly instead of vacuously.

| # | check | file | mutation | expect | what it pins |
|---|---|---|---|---|---|
| (a) | `task-citations` | `crates/antseal-core/src/anchor/mod.rs` | append `` // follow-up: `{first_hole("A")}` `` | **red** | tier 1 bites at all |
| (b) | `task-citations` | `scripts/fuzz.sh` | append `` # follow-up: `{first_hole("Q")}` `` | **red** | `scripts/` and `.sh` really are swept — without it the surface widening is unproven |
| (c) | `task-citations` | `crates/antseal-core/src/anchor/mod.rs` | append `` // follow-up: `{above_ceiling("A")}` `` | **red** | tier 2 — the newly-minted-id case, premise 5's hole |
| (d) | `task-citations` | `crates/antseal-core/src/anchor/mod.rs` | append `// follow-up: {above_ceiling("A")}` (**bare**) | **green** | the named blind spot is a decision. Widening tier 2 to bare turns this red and forces a re-decision — the idiom of the matrix's "later milestone at gap stays green" case |
| (e) | `task-citations` | `crates/antseal-core/src/anchor/roots/mod.rs` | replace the `R46` DN line with the same line minus ` R46` | **red** | the `TASK_ID_NOT_A_CITATION` entry is **not vacuous**: removing the token it names makes the entry stale, so green cannot be coming from "the file is not swept" |
| (f) | `task-entries` | the tasks file of the **first** row id that has an entry, computed | delete that `### <ID> — ` heading line | **red** | the entry half bites |
| (g) | `task-entries` | `TODO.md` | append a row `- [ ] **{above_ceiling("Q")}** (S) fixture` | **red** | a *new* row without an entry fails — the register is closed, not a blanket |
| (h) | `task-entries` | `TODO.md` | rewrite one **live** row that has an entry into the struck form `- ~~**ID**` … `~~` | **green** | the struck shape is parsed. A checkbox-only regex makes this row's entry an entry-with-no-row and it goes red — this is the case that pins §1.2 |
| (i) | `task-entries` | `tasks/<d>.md` | insert `#### <ID> — fixture sub-heading` inside an existing entry, id computed | **green** | sub-headings are tolerated. `^#{2,4}` makes this a duplicate and it goes red — pins §1.3 |
| (j) | `task-entries` | `tasks/<d>.md` | duplicate an existing `### <ID> — ` heading into a **different** domain file | **red** | duplicate **and** misfiled, one mutation |
| (k) | `task-entries` | `tasks/<d>.md` | add a `### <ID> — ` heading for the **first** id in `ROWS_PENDING_ENTRY`, computed by reading the register | **red** | register staleness — the exemption must die when the entry lands |

Cases (d), (h) and (i) are the three green arms, and each is load-bearing:
without them the tier-2 rule, the row grammar and the heading level could each
widen to something vacuous with nothing noticing. The existing self-test's
"a mutation that changed nothing makes its case vacuous" guard covers all
eleven for free.

---

## 5. Edit set

| file | change |
|---|---|
| `scripts/check-traceability.py` | R1–R4, R8. Docstring `Two`→`Five` and two new entries; `TASK_*` constants; `TASK_ID_NOT_A_CITATION` (3 entries); `BACKLOG_FROZEN_ON` + `ROWS_PENDING_ENTRY` (21 entries); `allocated_task_ids`, `task_id_ceiling`, `task_detail_entries`; `check_task_citations`; `check_task_entries`; two `CHECKS` entries; `first_hole`/`above_ceiling`; 11 cases |
| `tasks/Q.md` | R5, R7 — Q85's `Do`, `Accept` and `Notes` |
| `TODO.md` | Q85's row status text; the new row for `A71` (§8 (ii)); the two follow-up rows (§8 (iii), (iv)); this decision's register line |
| `scripts/ci-lanes.sh` | **none** — `lane_traceability` runs the script with no flags, so both checks join the lane by being in `CHECKS` |
| `.github/workflows/ci.yml` | **none** — same reason; no new required-status context, the set stays at 19 |

`docs/format/registry-v1.md`, `FROZEN.sha256` and every frozen artifact:
**untouched**. Nothing here reads or writes wire bytes.

---

## 6. Instruments

### 6.1 What is new

Two checks in a lane that already self-tests before it runs
(`scripts/ci-lanes.sh:822-828`: `--self-test` first, then the full run, with
the annotation *"a check stayed green over corrupted input, so a green run
below would prove nothing"*). Eleven new self-test cases, three of them green
arms that bound the rules from the other side.

### 6.2 What is deliberately NOT added

No test asserts the *contents* of `ROWS_PENDING_ENTRY` beyond its dates. A
test that pinned the 21 ids would have to be edited every time one is drained,
which converts draining from a deletion into a two-file edit — friction on
exactly the act the register exists to encourage.

### 6.3 The vacuity risk, named

`--task-entries` is green in two situations: the tracker is consistent, or the
sweep found nothing. The `n_rows == 0 or n_entries == 0` guard (R3) covers the
total failure. The partial failure — `TASK_ENTRY` silently stops matching a
renamed heading style — is covered by case (f), which deletes a heading the
fixture *found*, so it cannot pass if the finder is broken.

### 6.4 Commands run for this decision, with verdicts

| # | command | verdict |
|---|---|---|
| 1 | `python3 scripts/check-traceability.py --help` | 3 flags today: `--freeze-boundary --matrix --decisions`, plus `--milestone`, `--self-test` |
| 2 | `python3 scripts/check-traceability.py` | **exit 0.** freeze-boundary ok (2 copies, 2175 bytes); matrix ok (34 rows, 55 refs); decisions ok (97 cited, 90 records, 5 homed, 13 open) |
| 3 | row/entry census over `TODO.md` + `tasks/*.md` | 498 rows (497 live + 1 struck `P18`), 477 entries, **21** rows without entries, **0** entries without rows, **0** duplicates, **0** misfiled; all nine header-table counts correct |
| 4 | citation sweep at three breadths + gap census | 71 holes across the task domains, **0** in D; `DECISION_SCAN` mirror → 2 in-bound unresolved; wide sweep → 20 raw / 3 in-bound |
| 5 | prototype of both checks (`TASK_SCAN`, floor+ceiling+tier 2, self excluded) | 352 files; tier 1 = **A71, Q72, R46**; tier 2 = **0**; entry half = 21 / 0 / 0 / 0 |
| 6 | planted `` `A117` ``, `**A117**`, bare `A117` | marked forms seen, bare form not — tier 2 behaves as specified |
| 7 | `docs/decisions/` added to the citation scan | **+13** tier-1 failures (11 new), all ids the D92/D93 records merely proposed |
| 8 | `scripts/` + `.github/` added to the **decision** sweep | **0** new unresolved decisions — the widening in §8 (i) is free |
| 9 | citation reach of the wave-4 seven | `A68` and `Q87` cited in **0** files anywhere |
| 10 | `grep -c` for S33/S35 entries in `tasks/S.md` | both **present** — project memory is wrong |

`cargo` was not run. Nothing in this decision touches Rust.

---

## 7. What this does not do

- **It does not catch an id proposed only in a decision record.** §3.3, with
  the reason and what covers it instead.
- **It does not catch a bare, above-ceiling citation.** §3.2, with the three
  mitigations. Required as a code comment.
- **It leaves a dated trap at `F64`.** `Type::F64` is 11 above F's current
  ceiling of 53, and F already has holes at 45–48, so the day F's ceiling
  passes 64 without `F64` itself being minted, `crates/antseal-core/tests/cbor_pin_eval.rs`
  becomes a tier-1 failure. The fix when it happens is one
  `TASK_ID_NOT_A_CITATION` entry. It is named here so the next lane recognises
  it in two seconds instead of re-deriving it. `Type::F16` and `Type::F32` in
  the same file already resolve **silently** against real rows F16 and F32,
  which is harmless and is the same mechanism.
- **It does not check that a detail entry is any good** — only that it exists.
  An entry whose `Do` is stale (the A22 case Q85's row cites) is invisible to
  this and always was.
- **It does not verify the header table's counts**, though they are correct
  today. §8 (v).
- **It does not touch `check_decisions()`.** The surface hole it shares is
  §8 (i), separately, because widening a working lane is its own act.

---

## 8. Discovered work — described, not numbered

*(The wave owner allocates and registers. No id is minted here.)*

**(i) The decision half has the same surface hole, and closing it is free.**
— M2 · XS · deps: Q57, Q85. `DECISION_SCAN` omits `scripts/`, and
`DECISION_SUFFIXES` omits `.sh` and `.mjs`, so a decision cited in a gate
script resolves against nothing — the identical defect that hides `A71` from
the task half. Measured: adding `scripts/` and `.github/` over `.sh .mjs .yml
.py` yields **zero** new unresolved decisions, so this lands green on the
first run. It must adopt `TASK_SCAN_SELF`'s self-exclusion in the same change:
`scripts/check-traceability.py` contains the literal `D77000` as a self-test
fixture, which is skipped today only because 77000 exceeds the ceiling.
Accept: the two scan sets are one constant or two constants with a comment
saying why they differ; a planted `D<n>` citation in a `.sh` file under
`scripts/` turns the lane red.

**(ii) `scripts/fuzz.sh` describes real fuzz work and names it `A71`, which no
row defines.** — M2 · S · deps: Q9, Q17. `scripts/fuzz.sh:98-103` records that
`drive_anchor_token` takes its digest off the HEAD of the input, so a raw
`.tsr` seed is consumed 32 bytes short and cannot pass the imprint check on
the unmutated seed; it states that *"a corpus of `real_imprint ‖ token` pairs
would reach further and is A71"*. The work is specified; only the row is
missing. **The natural number is `A71` itself** — it is a free hole in A, the
citation is already committed in a gate script, and protocol rule 1 forbids
renumbering what is referenced elsewhere; but the allocation is the
orchestrator's call, not this decision's. **This must land in Q85's own lane**,
because it is the finding that makes `--task-citations` green, and R7 bullet 1
records the red-before-green.

**(iii) Thirteen open rows have no detail entry, and that is the live
hazard.** — M2 · M · deps: Q85. A72, A74, A76, A105, A108, Q88, Q89, Q122,
Q123, Q130, R60, R76, U39. Each has a row of 386–2 193 characters carrying its
size and often its `after:` deps, so the entry is substantially a reformat
rather than an invention — but **not for all of them**: A105 and A108 are the
two the Current-focus block describes as having been reconstructed from
disagreeing sources, and those two need their domain owner, not a lint lane.
Explicitly **not** folded into Q85 (§2 (b)): writing a `Do`/`Accept` for a row
you did not execute is defining the task second-hand, which is the defect Q85
exists to close. Accept: all thirteen have `### <ID> — ` entries and thirteen
`ROWS_PENDING_ENTRY` lines are deleted; the check stays green throughout,
because deleting a register line and adding an entry are the same commit.

**(iv) Eight closed rows have no detail entry.** — M3 · S · deps: Q85, (iii).
Q124, S27, S29, S34, U36, U37, U38, U40. Archaeology: nobody will execute
them, and their rows run 1 617–4 044 characters with the outcome inline, so
the entry is a transcription. Deliberately split from (iii) so it cannot delay
it. Accept: eight entries, eight register lines deleted, and
`ROWS_PENDING_ENTRY` is then **empty** — at which point the constant and
`BACKLOG_FROZEN_ON` should be deleted rather than left as an empty dict, since
an empty register with a 2026-08-10 lock invites a future lane to reopen it.

**(v) `TODO.md`'s own counts are prose asserting a fact about the tree, and
nothing verifies them.** — M3 · XS · deps: Q85. The header says *"**498 tasks**
today"* and *"**108 decisions D1–D108** of which **95 are resolved**"*, and the
domain table gives nine per-domain counts. All twelve numbers are **correct
today** — measured — which is precisely when to pin them, and the script's own
opening sentence describes this exact shape: *"something written down in prose
asserts a fact about the repository, and nothing else verifies it"*. **The
objection that must be answered first**: counts drift *by design* during a wave
and are reconciled at bookkeeping, so a hard check would be red for most of
every wave, and a check that is red by design is (d) again. The tractable form
is therefore **not** a `CHECKS` entry but a separate flag that bookkeeping runs
deliberately — `--counts`, excluded from the no-flag run — or an advisory
print. Decide which; do not add it to the required lane. Accept: either the
twelve numbers are checked under a flag the lane does not run, or the reason a
count check must stay advisory is recorded where the counts are written.

---

## Outcome

**RESOLVED, 2026-08-10.** Q85 is **two checks under two flags**,
`--task-citations` and `--task-entries`, and the brief's lean — mirror
`check_decisions()` — is refused on a measurement: **D1–D108 has zero holes and
the nine task domains have 71**, so the sibling's `n > max` bound is nearly
free for a dense namespace and is a 71-number-wide false-positive surface for
sparse ones. Every unresolved hit on today's tree lands in a hole, which is the
mechanism rather than a coincidence. The bound therefore becomes a **floor**
(`n >= 1`, killing `A0`/`C0`/`F0`, which are **hex bytes in UTF-8 comments**,
not labels), a **ceiling**, and — above the ceiling, where no allocation
evidence exists — **marked form only**, which closes premise 5's hole (a freshly
minted id is by definition above the ceiling) at **zero measured cost**: 0
tier-2 failures today, with `F64`, `P384` and `U256` all present and none ever
written marked. `docs/decisions/` is **out** of the sweep, as it already is for
decisions, because including it fails **13** rows for ids that D92 and D93
merely *proposed* — punishing the one document type whose job is to propose.
`scripts/` and `.sh`/`.mjs` are **in**, because that is where the single
genuine finding lives: **`scripts/fuzz.sh:98-103` describes real fuzz work and
names it `A71`, and no row defines it** — invisible to the code this was asked
to mirror, twice over. It gets a **row**, not a suppression, so the check earns
its keep on its first run. `R46` (a **Sectigo CA subject DN**) and `Q72` (a
**mention, not a use** — the sentence records that Q72 was never issued) go
into `TASK_ID_NOT_A_CITATION`, keyed by **(id, path)** so a suppression can
never mute the same id elsewhere, with stale entries failing in both
directions. **`P18` needs no exemption**: the false positive is a regex bug, not
a standing offset — protocol rule 1 mandates the struck shape `- ~~**P18**`,
which every ad-hoc script has failed to parse, and once parsed, 497 live + 1
struck = **498** = the header total and *entries with no row* is **0**. The 21
rows without entries are registered in a **date-locked** `ROWS_PENDING_ENTRY`
that is **closed, not capped** — a 22nd entry requires either a false date in a
diff or moving `BACKLOG_FROZEN_ON`, which invalidates all 21 at once — and is
drained by two follow-up rows split **13 open** (the live hazard, M2) from **8
done** (archaeology, M3), because writing a `Do`/`Accept` for a row you did not
execute is defining it second-hand, the very defect Q85 exists to close.
**Q85's Accept bullet 1 is replaced**, and not merely because it is stale: it
was **unsatisfiable the day it was written**, since `A68` and `Q87` — two of the
seven ids it requires the check to name — are cited in **zero** files anywhere
in the tree. Both checks land **green**, in a required lane that self-tests
first, behind **eleven** derived fixtures of which **three are green arms**
pinning the tier-2 blind spot, the struck-row shape and the `#### ` sub-heading
inside `Q14`'s entry. Zero frozen bytes; zero new required-status contexts; no
`cargo` command was run.

---

## Index row (orchestrator applies at merge)

| [D109](D109-task-id-traceability-scope.md) | Q85 — the real scope of the task-ID traceability gap — **two checks under two flags, both landing green; the mirror-`check_decisions()` lean is refused on a measurement.** **D1–D108 has zero holes; the nine task domains have 71**, so the sibling's `n > max(allocated)` bound is nearly free for a dense namespace and is a 71-number-wide false-positive surface for sparse ones — and all three of today's unresolved hits land in holes, which is the mechanism, not luck. The bound becomes a **floor** (`n >= 1` — `A0`/`C0`/`F0` are **hex bytes in UTF-8 comments**, not labels as recon had them), a **ceiling**, and **marked-form-only above the ceiling**, which closes the "a newly minted id is by definition above max" hole at **zero measured cost** (0 tier-2 failures, with `F64`, `P384`, `U256` all present and never written marked; `F64` is `Type::F64`, IEEE-754 — **not** the genuine id recon called it). Marked-form-only *everywhere* was measured and rejected: **218 of 352** cited ids appear bare only. `docs/decisions/` is **OUT**, as it already is for decisions — including it fails **13** rows for ids D92/D93 merely *proposed*, punishing the one document type whose job is to propose; `scripts/` + `.sh`/`.mjs` are **IN**, because the one genuine finding is there: **`scripts/fuzz.sh:98-103` specifies real fuzz work and names it `A71`, and no row defines it** — missed twice by the code this was asked to mirror (`scripts/` not in `DECISION_SCAN`, `.sh` not in its suffixes). `A71` gets a **row**, not a suppression, so the check earns its keep on its first run; `R46` (a **Sectigo CA subject DN** sitting in one of R's 12 holes) and `Q72` (**mention, not use** — the cited sentence *records* that Q72 was never issued) go into `TASK_ID_NOT_A_CITATION`, keyed **(id, path)** with stale entries failing both ways. **`P18` needs no exemption at all**: the "standing offset" is a **regex bug** every ad-hoc script has repeated — protocol rule 1 mandates the checkbox-less struck shape `- ~~**P18**`, and once parsed, 497 live + 1 struck = **498** = the header total and *entries with no row* = **0**. The 21 rows without entries go into a **date-locked, closed** `ROWS_PENDING_ENTRY` (a 22nd entry needs a false date in a diff or a constant move that invalidates all 21), drained by two rows split **13 open** (live hazard, M2) from **8 done** (archaeology, M3) — refused as Q85 lane work because writing a `Do`/`Accept` for a row you did not execute is defining it second-hand, the defect Q85 exists to close. **Accept bullet 1 was unsatisfiable the day it was written**, not merely stale: `A68` and `Q87`, two of its seven, are cited in **zero** files anywhere. Also found: the decision half shares the surface hole and closing it costs **zero** new failures; project memory is **wrong** that S33/S35 lack entries (both have them, and neither has a row); `TODO.md`'s twelve self-reported counts are all correct today and verified by nothing, but must stay **advisory** because counts drift by design mid-wave. Eleven derived self-test cases, **three green arms** pinning the tier-2 blind spot, the struck-row shape and `Q14`'s `#### ` sub-heading. Zero frozen bytes, zero new required contexts, no `cargo` run | RESOLVED (Q85 executes) | 2026-08-10 |

---

## Amendment — `A117` became a real row, 2026-08-10

This document uses **`A117`** as its worked example of an unallocated id — the
tier-2 marked-citation fixture, planted as `` `A117` ``, `**A117**` and bare
`A117` around §3.2 and §6.4. **At this wave's bookkeeping `A117` was allocated
to real work** (the two `A16-A17-live` esplora fixtures consumed by zero lines
of code, found by the A112 lane).

Nothing fails today: `docs/decisions/` is deliberately **out** of `TASK_SCAN`
(§3.3), so these plants are never swept. But the illustration now names real
and unrelated work, and **if the task sweep is ever widened to `docs/decisions/`
those plants become green citations of an esplora fixture task** rather than the
unallocated id the passage is about. Recorded rather than renumbered, because
renumbering a resolved decision's prose breaks every citation into it and the
plants are load-bearing to the argument. A future lane widening the sweep must
re-key this passage to an id that is still free at that time.

The same trap applies to any decision document that plants a fixture id: the id
is free when the document is written and may not be later. Registering the
example ids the way `TASK_ID_NOT_A_CITATION` registers real ones would close it.
