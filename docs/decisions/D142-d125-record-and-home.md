# D142 — D125's home, and the coverage property the `decisions` check has never asserted

- **Status: RESOLVED. The briefed lean — *"write `docs/decisions/D125-instrument-finding-triage.md` and the red goes away"* — is OVERTURNED, and it is overturned on provenance rather than on cost: `5a21ced` wrote `TODO.md`, `docs/instrument-ledger.md` and `docs/waves/wave-16-brief.md` and touched `docs/decisions/` not at all, and D125's own register row says in writing that the recordlessness was deliberate *"under its own rule"*.** D125 is registered in `DECISIONS_HOMED_ELSEWHERE`, not reconstructed as a record. **And the arm nobody listed is the one that carries the weight: the finding is not D125 at all — it is that `check_decisions` has never asserted the property its own prose claims to enforce.** The constant's comment says *"leaving a decision out of it is a failure"* and the entry for D17/D30 says *"a resolved decision with no home is exactly what the check exists to catch"*; measured, the check catches a **cited** resolved decision with no home, and is structurally silent about an uncited one. So the ruling is two edits in one act: **the home (R1) and a citation-independent coverage assertion (R2)** that reds on `allocated − recorded − homed − open ≠ ∅` no matter what any file cites, no matter which directories are swept. Writing the record alone would have closed one hole and left the class unguarded; homing alone would have been correct **by luck**, on a register that happens to have exactly one uncovered id today.
- **The premise that dies on measurement: D125 is not what blocks the next `CITATION_SCAN` widening.** Q253 reads *"the same move toward `docs/` or `docs/decisions/` reds a required context on contact"*. It does — and D125 is **1 finding against 47**. Admitting `docs/` fires **47 frozen-registry line-number citations** from the *same check* (`docs/threat-model.md`, `docs/decisions/README.md`, `D114`, `D98`, `D108`, `D73`, …); `docs/decisions/` alone fires **41**. Nothing in this record unblocks a widening, no row may claim that it does, and the 47 are recorded in §5 as work nobody owns.
- **The governance question, ruled: clean self-application, no exemption claimed, and one breach recorded.** Rule 8's operative sentence binds **task ids and rows** — *"takes no task ID and no row"*. A decision id is a different id space under a different protocol rule (rule 3), so **this record is not barred by rule 8 and needs no exemption**. Rule 8 **did** bind Q253, and by the ledger's own line-to-draw test (*"Does it change only what a checker says…? Ledger"*) plus its promotion criterion (*"only when it blocks an acceptance on the ship path"*, against Q253's own `Deps`: *"blocks nothing today"*), **Q253 was minted in breach of the rule it was minted to record**. The remedy is not to strike it — rule 8's own handling of instrument rows is *rows stand untouched*, and per-row adjudication is the meta-work the rule exists to prevent. Q253 stands, its minting is recorded here as a declared exception, and the binding consequence is forward-looking: **no second row. The whole edit set rides Q253.**
- **Date: 2026-08-18**
- **Owning task: Q253** (whose `Accept` rows 2 and 3 are amended here — see §2 R6). Written as prose and not as the anchored `**Owner: Q253**` form on purpose: `DECISION_OWNER` (`scripts/check-traceability.py:1178-1180`) matches that form at line start and `check_decision_owners` would then require Q253's `TODO.md` row to name D142 back, which it cannot until the registrar edits it. D140 sets this precedent with `- **Owning task: Q24**`.
- Related: **D125** (the subject — the starvation rule, ruled in session 2026-08-11, `5a21ced`), **Q57** (the general form: *does a cited decision resolve?*), **Q252** (the construct-don't-derive fixture rule this record inherits and must not break), **D109 §3.3** (`docs/decisions/` stays out of `CITATION_SCAN`), **D116 R1/R2/R3** (one scan pair, loop parity, the file count in the ok line), **D119 RULING 1/3/6** (the index's domain is the files on disk; the register allocates; the record and its index row are split across actors), **D123/Q190** (per-entry directory-vs-literal rule), **D138** (`traceability` now lives in the unfiltered `ci-always.yml` — a red here blocks every PR), **A134** (the retrospective-record class's provenance defect, still open), **D115 §4.1** (the twelve reconstructions this record refuses to make a thirteenth of).

---

## 1. The measurement

Everything below was re-derived from the checker's own accessors and the tree at `de71a09`. **Nothing is transcribed from Q253**; where the two disagree, §1.6 says so explicitly.

*Two lanes were writing this tree while these figures were taken, so each is a statement about the minute it was taken — the wave-23 rule, applied to this record. The figures that decide anything were re-measured at the close of the round and are unchanged: `allocated − recorded − homed − open = {125}` both times. The sweep's file count moved 451 → 452 under a sibling lane in the same window, which is why §1.2's ok line is quoted as measured rather than as it will read tomorrow.*

### 1.1 The arithmetic, from the accessors and not from the row

Computed by importing `scripts/check-traceability.py` and calling `allocated_decision_ids()` / `open_decision_ids()`, globbing `docs/decisions/D*.md` with the check's own `r"D(\d+)-"`, and reading `DECISIONS_HOMED_ELSEWHERE`:

```
allocated       : 140   min 1  max 140   gaps: []
recorded (files): 134             gaps: [11, 12, 16, 17, 30, 125]
homed elsewhere : 5     [11, 12, 16, 17, 30]
still open      : 0     []

allocated − recorded − homed − open  =  [125]
```

Three sanity directions, all empty: `recorded − allocated = []`, `homed − allocated = []`, `open − allocated = []`, and `recorded ∩ homed = []`. So **D125 is the sole uncovered id, and it is uncovered by set difference, not by subtraction.** Q253's `140 − 134 − 5` is arithmetically right and reaches the right answer; it is restated here as a set difference because that is the form R2 ships, and because a count is exactly the artefact this project has now watched go stale four times inside `TODO.md`'s own header.

`grep -cE '^\| \[D[0-9]+\]' docs/decisions/README.md` → **134**, matching the record count. The index carries no D125 row, which is correct: D119 RULING 1 makes the index's domain the files on disk.

### 1.2 The check is green, and its green line prints the numbers that prove the hole

`python3 scripts/check-traceability.py --decisions` → exit 0:

```
[decisions] ok — 132 distinct decisions cited across 451 files, all resolve
(134 have records, 5 homed elsewhere, 0 still open in the register); no
line-number citations into the registry
```

**134 + 5 + 0 = 139. The register allocates 140. The ok line prints three of the four numbers and never prints the fourth** (`scripts/check-traceability.py:798-810`), so the subtraction that finds D125 is available to a reader on every green run and is performed by nobody. That is the mechanism, stated at the site R2 edits.

### 1.3 Why it is green: the check's domain is citations, and D125 is uncited

The failing arm is `scripts/check-traceability.py:777-788` (Q253 cites `:776-787`; **:776 is a blank line and the arm's closing paren is :788** — off by one in both directions). It iterates `sorted(cited)`, skips `number > max(allocated)`, and reds anything not in `recorded ∪ DECISIONS_HOMED_ELSEWHERE ∪ still_open`. D125 is in none of the three sets and never enters the loop, because the sweep never sees it.

Sharpening it: **8 of the 140 allocated ids are mentioned by no swept file at all** — D113, D115, D119, D120, **D125**, D126, D134, D140. Seven of the eight hold records, so the silence costs nothing. **D125 is the only one of the eight with nothing behind the silence.** The check is not broken and is not lying about what it does; it is answering a narrower question than the constant's own prose claims for it (§1.5).

### 1.4 Every place D125 is mentioned, and in what form

Measured over the whole tree with the check's own `\bD(\d+)\b`, filtered to capture group `125`, excluding `target/`, `.git/`, `node_modules/`, `__pycache__/`. **Eight files, 38 capturable occurrences:**

| file | occurrences | marked | bare | reachable by a directory widening? |
| --- | ---: | ---: | ---: | --- |
| `TODO.md` | 15 | 3 | 12 | **no** — root file, and the constant's own header keeps `TODO.md` and `tasks/*.md` out by rule |
| `tasks/Q.md` | 14 | 3 | 11 | **no** — same rule; all 14 are inside Q253's own entry |
| `docs/instrument-ledger.md` | 3 | 1 | 2 | yes — `docs`, or as a literal entry |
| `docs/decisions/D126-a25-rerun-clause-and-row4-handoff.md` | 2 | 0 | 2 | yes — `docs` or `docs/decisions` (the latter refused by D109 §3.3) |
| `docs/ci-verification.md` | 1 | 0 | 1 | yes — `docs`, or as a literal entry |
| `docs/decisions/D73-external-completions-without-telemetry.md` | 1 | 0 | 1 | yes — as above |
| `docs/waves/wave-16-brief.md` | 1 | 0 | 1 | yes — `docs` or `docs/waves` |
| `testdata/anchors/A25-wave16-cycle/CAPTURE.log` | 1 | 0 | 1 | **no** — suffix `.log` is outside `CITATION_SUFFIXES`; reachable only by being named as a literal entry, which is unfiltered |

*Marked* = the id is the whole content of a backtick or bold span, checked per occurrence against the adjacent characters. **7 of 38 are marked, and not one of the 6 occurrences in the four `docs/` files is** — `D73`'s is `**D125/`docs/instrument-ledger.md`**`, a bold span whose content is not the id.

The three `testdata/acvp/*.json` fixtures hold 28 further `D125` **substrings** and **zero** capturable occurrences.

### 1.5 What the check's own prose claims, and does not do

`scripts/check-traceability.py:690-708`, at the constant:

> *"Each entry is the home, so 'no file' is a recorded fact rather than an omission. Adding to this list is a deliberate act; **leaving a decision out of it is a failure**."*

and inside it, for D17/D30:

> *"Closing the entries at the freeze removed their only home and turned this lane red, correctly: **a resolved decision with no home is exactly what the check exists to catch**."*

Both sentences are false of the tree as written. The check catches *a **cited** resolved decision with no home*. D125 has been the standing counterexample since 2026-08-11 and the prose has never been reddened by it — **a claim a document makes about itself with no instrument, which the file's own §7 header (`:1303-1304`) calls the shape every check in it exists to end.** That, and not D125's id, is this record's subject.

### 1.6 Which of Q253's figures survive, and which do not

**Confirmed exactly:** the arithmetic (`140 − 134 − 5`, D125 sole); that D125 is not recorded, not homed, not open; that the check is green solely because nothing swept mentions it; that `check_decisions` matches a bare token; that not one of the mention paths is in `CITATION_SCAN`; that `docs/user` was admitted this wave and `docs/` is one entry away; that D125 is the rule-8 starvation ruling recorded as a register row plus a protocol paragraph.

**Corrected:**

1. **Seven mention sites → EIGHT.** The omitted one is **`tasks/Q.md`**, at **14 occurrences** — the second-largest site in the tree, and it is Q253's own entry. The row corrects its minting brief for having missed `TODO.md` *"where the ruling is recorded"* and then misses the file where its own correction is written, by the same self-reference. Not a defect in the finding; a defect in a count taken before the act that changes it.
2. **`TODO.md` (5) → 15.** `tasks/Q.md` (unlisted) → 14. The other six per-file counts are exact.
3. **Locator `:776-787` → `:777-788`.**
4. **The asymmetry with the task-id check is stated backwards.** Q253: *"unlike the task-id check, which requires a citation to assert itself typographically, `check_decisions` matches a bare `\bD(\d+)\b`."* Measured, `check_task_citations` requires marked form **only above the domain's ceiling** (`:1049-1074`); **below the ceiling it reports bare tokens**, exactly as `check_decisions` does, and D125 is 15 below its ceiling. The two checks agree on the whole range this finding lives in. The real asymmetry is the opposite one the ledger already recorded on 2026-08-17: *above* the ceiling, decisions **discard** and tasks **report**.
5. **"Immune by regex accident rather than by design" overstates the ACVP fixtures.** A match needs a non-word character before `D` and after the digit run; inside a hex string every character is a word character, so the only hex string that could ever match is one that is *exactly* `"D125"`. Measured rather than argued: admitting `testdata` to `CITATION_SCAN` reads **62 more files and reports zero unresolved ids**. The immunity is structural for the whole fixture class. The one thing that *is* accidental is `07798DD125A2CEBB` inside `TODO.md:838` and `tasks/Q.md:3180` — the row quoting the hazard into the two files the constant deliberately does not sweep.
6. **The `Spec:` line cites a phrase that is not in the spec.** `tasks/Q.md:3171` reads *"Milestone M4 gate — 'traceability matrix 100 % green' (MVP-SPEC.md line 157)"*. `grep -n 'traceability' MVP-SPEC.md` returns **nothing**; MVP-SPEC.md:157 is the M4 bullet, whose CI clause is *"CI (fmt/clippy/test/wasm/fuzz)"*. The quoted phrase is real and lives at **`TODO.md:805`**, the M4 gate checklist. Registrar's correction, named in §5.

### 1.7 What actually happens the day `docs/` is admitted — and what happens to the self-test

Simulated read-only by re-running the sweep body over a patched scan list (no file was written, no tree was staged):

| scan | files read | unresolved decision ids | frozen-registry line citations |
| --- | ---: | --- | ---: |
| shipped `CITATION_SCAN` | 451 | — | 0 |
| `+ docs` | 636 | **D125** | **47** |
| `+ docs/decisions` | 586 | **D125** | **41** |
| `+ docs/waves` | 453 | **D125** | 0 |
| `+ docs/instrument-ledger.md` | 452 | **D125** | 0 |
| `+ docs/ci-verification.md` | 452 | **D125** | 0 |
| `+ testdata` | 513 | — | 0 |
| `+ TODO.md` | 452 | **D125** | 7 |
| `+ tasks` | 460 | **D125** | 4 |

And the state-independence measurement that decides R3. Simulating the coverage clause of R2 against the **existing** `decisions` self-test fixtures — the ones Q252 landed, which mint `max(allocated)+1` rather than searching the live register:

| staged tree | clause reports | arm verdict |
| --- | --- | --- |
| live tree, before R1 | `[125]` | flagless check RED |
| live tree, after R1 | `[]` | green |
| red case: append `- [x] **D141** …` to `TODO.md` | `[141]` | red — arm passes |
| green case: append `- [ ] **D141** …` to `TODO.md` | `[]` | green — findings unchanged, arm passes |

**The clause inherits Q252's fixture for free, and inherits its construction discipline with it**: the id is `max(allocated)+1`, which no amount of the register getting healthier can reach. But note what the same table shows: the red case *already* goes red through the citation half, so it does **not** pin the new clause independently. §2 R3 handles that honestly rather than asserting coverage the fixtures do not give.

### 1.8 Provenance: the recordlessness was executed, not overlooked

```
$ git show --stat --date=iso 5a21ced
5a21ceda88f1accefa414e5185b142009ba283d1 2026-08-11 10:17:54 +0100
D125: the backlog learns to starve, and the queue points back at the product

 TODO.md                     | 13 +++++++++----
 docs/instrument-ledger.md   | 23 +++++++++++++++++++++++
 docs/waves/wave-16-brief.md | 36 ++++++++++++++++++++++++++++++++++++
 3 files changed, 68 insertions(+), 4 deletions(-)
```

**`docs/decisions/` is not in that commit.** And `TODO.md:990`, the register row written by it, says so in words:

> *"the operative text lives in protocol rule 8 + `docs/instrument-ledger.md` + `docs/waves/wave-16-brief.md` rather than a decision doc — **deliberately, under its own rule**"*

The commit message is not a home: no check reads git history, and `recorded` is a glob over `docs/decisions/D*.md`. What exists on disk today are three homes — rule 8 (`TODO.md:37`, the normative text), the ledger it creates (`docs/instrument-ledger.md`, **153 entries** and live), and the wave brief that first executed it (`docs/waves/wave-16-brief.md:3`, *"Authority: D125 + `TODO.md` protocol rule 8"*). Every one of them is downstream of, or is, rule 8.

---

## 2. Rulings

### R1 — D125 is **homed**, not recorded. `scripts/check-traceability.py`, `DECISIONS_HOMED_ELSEWHERE`

Add a sixth entry, in id order after `30:`, with the reason at the site:

```python
    # D125 was ruled in session and given no record DELIBERATELY, which is a
    # fact on the record rather than an inference: `5a21ced` wrote TODO.md,
    # docs/instrument-ledger.md and docs/waves/wave-16-brief.md and touched
    # docs/decisions/ not at all, and the register row it wrote says "the
    # operative text lives in protocol rule 8 + docs/instrument-ledger.md +
    # docs/waves/wave-16-brief.md rather than a decision doc — deliberately,
    # under its own rule". This entry is where that fact becomes readable by
    # the check instead of only by a human reading TODO.md:990. The first
    # entry whose home is a section of TODO.md; see D142 §2 R1 for why that
    # is the honest home and not a shortcut.
    125: "TODO.md protocol rule 8 — the starvation rule's normative text — executed in docs/instrument-ledger.md; ruled in session 2026-08-11 (5a21ced), deliberately recordless",
```

**Who:** the lane that executes Q253. **Not** a planning lane, and not in this wave's parallel window without a declared write scope on that file.

**On the objection Q253 raises against this arm** — *"every existing entry points at a document, so pointing one at `TODO.md` makes the tracker its own authority, the shape rule 8 exists to avoid"*. Measured, the five entries point at: a research memo, a **decision record**, a research memo, `docs/format/registry-v1.md §6.2` **plus `crypto::sig_policy` in code**, and an error-code contract. So a two-part home is already precedented (entry 17), and one entry already points inside `docs/decisions/` itself. The objection's force is real but narrower than stated: what `TODO.md` holds here is not a *row* and not a *count* — it is **protocol rule 3's sibling, a normative paragraph that happens to share a file with the register**, and it is the only place rule 8 exists. Naming it is a true statement about where the authority is. The alternative puts a **second normative copy of rule 8** into the tree, and wave 23 alone measured four separate prose-copy drifts (`BOUNDARY_SOURCE`'s *"Both copies"*, the third freeze-boundary copy falsifying four statements at once, and two `TODO.md` header counts). **This entry adds zero copies.**

### R2 — `check_decisions` gains the coverage assertion it has always claimed. `scripts/check-traceability.py`, inside `check_decisions`

After `still_open` is computed and **before** the citation loop, using only names already in scope:

```python
    # The property the constant above claims for itself — "leaving a decision
    # out of it is a failure" — asserted independently of what anything
    # cites. Until D142 this check could only see an id a swept file
    # mentioned, so D125 sat allocated, unrecorded, unhomed and closed for
    # seven days while this lane printed ok; the three numbers on that ok
    # line sum to one less than the register allocates, and nothing
    # subtracted them. Set difference, never `len(a) - len(b) - len(c)`: the
    # counts are equal today and a count is the artefact this project keeps
    # watching go stale.
    for number in sorted(allocated - recorded - set(DECISIONS_HOMED_ELSEWHERE) - still_open):
        failures.add(
            check,
            f"D{number} is ALLOCATED in TODO.md's register and has no home: no "
            f"record under {DECISION_DIR}/, no entry in DECISIONS_HOMED_ELSEWHERE, "
            f"and no open row. Nothing needs to cite it for this to be wrong — "
            f"give it a record, or name its real home in the constant.",
        )
```

and the ok line (`:798-810`) reads back the number that proves it, rather than printing three of four:

```python
            f"[{check}] ok — every one of {len(allocated)} allocated decision ids "
            f"has a home ({len(recorded & allocated)} records, {homed} homed "
            f"elsewhere, {len(still_open)} still open); {len(in_bound)} distinct "
            f"decisions cited across {n_files} files, all resolve; no line-number "
            f"citations into the registry"
```

`--decisions`' help string gains the second clause: it no longer describes only cited ids.

**Constraints this satisfies, deliberately:** no new check name, no new flag, **no new required status context — the set stays at 19** (the standing constraint while the Actions allowance is exhausted). The failure message is worded so it can never be confused with the citation arm's in a log. **Who:** the same lane, the same commit as R1.

### R3 — Order, and the honest statement of what pins R2

**R1's line lands before R2's loop, in one commit.** Measured reason: `traceability` is a required context that now runs on every push from the unfiltered `ci-always.yml:109`, `lane_traceability` (`scripts/ci-lanes.sh:977-984`) runs `--self-test` **first and returns on its failure**, and R2 without R1 makes the flagless half red on D125 — the exact failure shape Q252 just repaired one arm over.

**What pins R2, stated as measured and not as hoped.** §1.7 shows the existing red case reports `D141` through the new clause and the existing green case stays silent, so the clause is exercised by fixtures that **construct** their subject. But the red case already reddens through the citation half, so it does not pin the new clause *alone*. The implementing lane therefore records, in Q253's Notes, two fault plants with their actual output text:

1. Delete the R2 loop, run `python3 scripts/check-traceability.py --self-test`, and record that **every arm still passes** — the honest statement that no arm pins this clause on its own. Restore.
2. Delete the `125:` entry from `DECISIONS_HOMED_ELSEWHERE`, run the flagless check, and record the new message **by its own text** and `REAL_EXIT=1` read back from a file. Restore, re-run, record exit 0.

**What the lane must NOT build:** a self-test arm that locates an uncovered id in the live tree. After R1 that set is empty by construction and the fixture would raise or go vacuous — Q252's defect, one check over, on the same day it was fixed. If an arm is ever added for this clause it must mint its subject above the register's ceiling, exactly as `plant_an_unrecorded_decision()` already does.

### R4 — The general rule, written where the next in-session ruling will be made. `TODO.md`, protocol rule 3

Q253's `Accept` row 3 requires the rule to live in the protocol section, not only in a record. Rule 3 today reads *"when a Decision-register entry (below) is resolved, check it, record the outcome + date inline, and update the blocked tasks' detail entries."* It gains one clause:

> …and **in the same commit, give the id one of the three homes the `decisions` check knows**: a record under `docs/decisions/`, an entry in `DECISIONS_HOMED_ELSEWHERE` naming the real home, or — while it is genuinely unresolved — an open row. A decision may legitimately be ruled in session with no record; it may not be left with no home. The check now says so (`check_decisions`, the allocated-with-no-home arm).

Two properties of that wording, both load-bearing: it does **not** require a record, so it does not retroactively condemn D125 or invent a rule the maintainer did not make; and it is **machine-read by R2**, so it is a rule with an instrument rather than a fourth prose claim about the register. **Who:** the registrar, in the same wave. It is not a new rule number — a rule 9 would be a governance change nobody asked for.

### R5 — No new task row. The edit set rides **Q253**

R1–R4 are four edits across three files and no new id is requested. Rule 8 refuses a task id to an instrument finding that blocks no ship-path acceptance, and this one blocks none (§3). Q253 already exists and already owns the subject.

*If the orchestrator overrules this and wants a separate row*, the row it needs is: **size XS; milestone M4; `Do` = R1 + R2 + R3's two fault plants in one commit; `Accept` = (a) `allocated − recorded − homed − open` is empty, computed by the check and not by the row, (b) both fault plants recorded with their literal output and `REAL_EXIT` read back from a file, (c) `./scripts/ci-lanes.sh traceability` exit 0 with the code read back from a file, (d) the `--decisions` help string and the ok line both name the new property; `Deps`: none** — and **the orchestrator assigns the id**. This record's position is that it should not.

### R6 — Q253's `Accept` is amended

- **Row 2 is superseded.** It reads *"a bare `D125` planted in a swept file is watched red by message before the fix and green after."* After R2, D125 needs no plant: it is red on the unmutated tree until R1 lands. The plant that carries meaning is R3's — remove the constant's entry, watch the new message. Row 2 becomes R3's two plants.
- **Row 4 is kept and tightened**: *"allocated − recorded − homed − open is empty"* stays, and is now **computed by the shipped check on every run** rather than re-derived by hand at close.
- Rows 1 and 3 stand: R1 is the recorded act naming the arm taken (this record is the "why the other was refused"), and R4 is the protocol sentence.
- **Who:** the registrar, or the Q253 lane in the act that ticks the row.

### R7 — What this record itself owes, and who owes it

Writing `docs/decisions/D142-d125-record-and-home.md` reddens `decision-index` until `docs/decisions/README.md` gains its row — D119 RULING 6 splits record and index row across actors, and the ledger records this mid-act window (2026-08-11 · Q208 lane) as routine rather than as a defect. **The registrar owes: the `- [x] **D142**` register row, and one index row at the table's tail in ascending id order whose status word and date are this file's `RESOLVED` / `2026-08-18`.** Neither file is in this lane's write scope and neither was touched.

---

## 3. What this refuses

**Arm A — write `docs/decisions/D125-instrument-finding-triage.md` — KILLED on four measurements.**

1. **Provenance (§1.8).** `5a21ced` created the ledger and the wave brief and did not touch `docs/decisions/`. The absence of a record is an executed choice with a diff to prove it.
2. **The register says so in writing.** `TODO.md:990` calls the recordlessness deliberate *"under its own rule"*. Writing the record overturns a dated maintainer choice on no new evidence — and this project's own rule is that a maintainer choice taken after a record resolves can delete its reasoning, never that a later lane may quietly reverse one.
3. **It joins a class whose provenance discipline is a live open defect.** D115 §4.1 reconstructed twelve entries retrospectively and **A134 is open** on the fact that A105's provenance is stated twice, circularly, with the two copies disagreeing about their own source and about the date. A thirteenth reconstruction, of a ruling made in a session nobody transcribed, minted while the class's rule is unruled, is the wrong order of operations.
4. **It is a second copy of a normative text.** Rule 8 is executed from `TODO.md`. A record either restates it — the drift class wave 23 measured four times — or it is a pointer file, which is `DECISIONS_HOMED_ELSEWHERE` in a more expensive shape, plus an index row, plus a status/date pair that must be kept in step by a check.

**The lean's premise that fixing D125 unblocks the next widening — REFUTED**, at 47:1 and 41:1 (§1.7). No row, record or ledger entry may state or imply it.

**"Give the decisions check the marked-form discipline the task-id check has" — refused, and refused because the analogy is wrong (§1.6 item 4).** The task-id check requires marked form **only above the ceiling**; below it, bare tokens are reported, which is where D125 lives. Adopting a marked-form rule for decisions would make **all six** `docs/` occurrences invisible — every one of them is bare — so it would *shrink* the check while appearing to harden it. Rejected as a straight weakening.

**A new check, a new flag, or a new job — refused** on the standing constraint: the Actions allowance is exhausted, hosted CI refuses every job, and no required context may be added meanwhile. R2 is an arm inside an existing check; 19 contexts stay 19.

**Putting the assertion in `check_decision_index` — refused by a prior ruling, not by preference.** D119 §7: that check *"does not touch `TODO.md`'s register, its parse, `allocated_decision_ids()`, `open_decision_ids()` or `DECISIONS_HOMED_ELSEWHERE`"*, and `:1312-1322` gives the reason — the index's domain is the files on disk, and importing the register's rules there makes an unwritten decision's missing row unfalsifiable.

**A `recorded − allocated` clause — refused, on a measurement taken on this very act.** A record file whose id the register never allocated is invisible to all seven checks, and that is a real gap (§5). It is not closed here because the counterexample is **live and doubled while this record was being written**: measured at 2026-08-18, `recorded − allocated = {141, 142}` — this record and a sibling planning lane's `D141-the-publish-flip-ordering.md`, both on disk, neither yet in the register, because the registrar files rows after the round. The clause would redden the gate on the record you are reading **and** on the one next to it, and on every future planning wave — converting D119's known, tolerated mid-act window into a hard red on the busiest hour of every wave.

**Striking Q253's row as a rule-8 breach — refused.** Rule 8's own handling of instrument rows is *rows stand untouched*; per-row adjudication is the meta-wave the rule exists to prevent; and the row holds the only written statement of the arithmetic. The breach is recorded, the row stands, and the consequence is that **no second row is minted** (R5).

**Widening `CITATION_SCAN` — not ruled here at all.** Out of scope in both directions: this record neither admits a directory nor forbids one. It removes exactly one of the 48 things that would fire if someone tried.

---

## 4. Falsifiers

Each of these, if it came out the other way, overturns a specific ruling.

1. **R1 dies if the recordlessness was an oversight.** `git show --stat 5a21ced` showing any `docs/decisions/` path, or `git log -S 'deliberately, under its own rule' -- TODO.md` dating that clause **later** than `5a21ced` — either would mean the register row rationalised an omission rather than recording a choice, and Arm A revives.
2. **R1 dies if a sixth entry breaks a live reader.** Measured: the only statements of the constant's size are `docs/decisions/D119-…md:24`, `:203` and `scripts/check-traceability.py:1312`, and all three are explicitly *"measured when D119 ruled"* — dated transcripts, not live claims. If any **live** count of that constant is found, it must be corrected in the same commit or R1 is a drift.
3. **R2 dies if a fourth legitimate state exists.** Construct one: an id that is allocated and correctly has no record, no home and no open row. If a wave finds one — an id withdrawn, retired or renumbered — R2 is wrong as written, and the repair is a **named fourth exemption set**, never a special case in the loop.
4. **R2/R3's coverage claim dies if the §1.7 simulation is wrong.** Run `--self-test` after the edit with the R2 loop deleted: if any arm *fails*, then an arm does pin the clause and R3's fault-plant mandate is unnecessary. Run it again with the loop present and the `125:` entry deleted: the flagless half must name D125 in the new message, not the citation one.
5. **R5 dies if Q253 blocks a ship-path acceptance.** The test is specific: does any row in the Current-focus queue carry an `Accept` clause requiring `CITATION_SCAN` to widen, or requiring the decision register to be fully homed? Measured today, none does, and Q253's own `Deps` says *"blocks nothing today"*. `TODO.md:805`'s *"traceability matrix 100 % green"* is the `--matrix` check and is green. **Re-measure at any promotion** — the answer changes the moment someone puts a widening on the ship path.
6. **The whole record dies if the arithmetic moves.** Re-derive from the accessors, never from this file: `allocated − recorded − homed − open` must be `{125}` before the edit and `∅` after. If it is neither, something landed between this record and its execution and the record must be re-read before it is executed.

**State-independence, said loudly.** R2 is correct on every register shape, not on this one: it reads the register's own allocation and the three exemption sets, and its finding is a set difference that is empty exactly when the property holds. It does not depend on which directories are swept, on which files mention D125, on the open set being non-empty, or on the register having exactly one hole. **R1, by contrast, is a fact about one id and is correct only for D125** — which is why R1 alone was refused as a complete answer, and why R4's protocol sentence and R2's arm are what keep the next in-session ruling from landing in the same position. The one place state-dependence could still enter is a future self-test arm for R2, and R3 forbids the shape that would introduce it: **construct the subject above the register's ceiling; never search the live tree for one.**

---

## 5. Found here, not this record's subject

1. **Q253's own figures need the registrar's correction** — eight mention sites not seven (`tasks/Q.md`, 14 occurrences, its own entry), `TODO.md` 15 not 5, the locator `:777-788` not `:776-787`, the task-id-check asymmetry stated backwards, and the ACVP "luck" claim overstated (§1.6). The row and entry are correct in every load-bearing respect and wrong in five countable ones; **that pattern — a finding right about the mechanism and wrong about the counts around it — is now the third consecutive wave.**
2. **`tasks/Q.md:3171` cites `MVP-SPEC.md` line 157 for a phrase that is not in the spec.** `grep -n 'traceability' MVP-SPEC.md` returns nothing; the phrase is at `TODO.md:805`. A `Spec:` line is what a lane opens the spec with, and this one sends the reader to a bullet about `CI (fmt/clippy/test/wasm/fuzz)`.
3. **47 frozen-registry line-number citations sit under `docs/`, owned by nobody** — 41 of them under `docs/decisions/` alone, including three in `docs/decisions/README.md` and two in `D114-line-123-citation-authority.md`, whose subject is line-number citation authority. Q58's rule is enforced only on the swept quarter of the tree. This is the real cost of any future widening and nothing tracks it. Ledger-class today; a row when a widening is actually proposed.
4. **`recorded − allocated` is asserted by nothing.** A record file under `docs/decisions/` whose id `TODO.md`'s register never allocated passes all seven checks: `check_decision_index` compares the index to the files and never to the register, and `check_decisions` reads the register only as a ceiling. Refused here for the measured reason in §3; recorded so the next lane does not conclude it is covered.
5. **The `decisions` ok line's file count and its resolve claim answer different questions.** `451 files` is honest about how much was read (D116 R3's purpose), but the sentence *"all resolve"* is scoped to those 451 files while reading as a statement about the register. R2's rewrite fixes the sentence; the general shape — a green log line whose subject is narrower than its grammar — is worth a sweep of the other six ok lines.
6. **`testdata/anchors/A25-wave16-cycle/CAPTURE.log` is the least reachable of the eight mention sites**, not merely an unlisted one: `.log` is outside `CITATION_SUFFIXES`, so no directory widening can ever read it — only a literal entry, which is unfiltered by D123's per-entry rule. Q253 lists it flat with the `docs/` sites, which overstates it in the opposite direction from item 5 of §1.6.
7. **Q253's own minting is a rule-8 breach** (§ the Status block). Recorded here, deliberately not remediated, and named so that the next lane counting promotions against the ledger's *"one promotion under rule 8"* line for wave 23 does not conclude the count was wrong: it was not — Q252's promotion was legitimate and Q253's was an undeclared exception.
