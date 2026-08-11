# D113 — Q145: how a resolved ruling survives its owner's closure, and what can actually see it

- **Status: RESOLVED — the proposed join is REFUSED on a measurement taken on
  its own two-row domain, and a keyed BACK-citation lands in its place under
  `--decision-owners`, hard-fail, with no exemption register.** Q145's design —
  *"a resolved decision naming an owner whose row is ticked, reported for a
  human to confirm the third [clause]"* — is refused three times over.
  **(i) The field it joins on is not a convention.** The string `Owner:` occurs
  **20 times in 94 decision documents**, spelled **five** ways; **2 of the 20**
  are D8 quoting a tail it is *deleting*, **2** name a domain letter rather than
  a task, and the anchored per-ruling form the row's premise assumes exists in
  **one document** — D104. The corpus's actual convention is the front-matter
  `- **Owning tasks:**` bullet (**55** of 94), which names a *set of related
  tasks*: D104's names six, including A27 *"the document, historically"* and A11
  *"the constant, which does not move"*. It is not an owner field.
  **(ii) Its precision is measured and it is fatal.** On the front-matter set
  the rule fires on **318** (decision, owner) pairs across **54** decisions; on
  every `Owner:` line in the corpus it fires on **42** pairs across **15**
  decisions; the true positives in both are **one**. Twelve ticked owners
  sampled by hand all carry substantive `✅` execution notes, which is the base
  rate the rule is up against. Worse than the ratio: **the rule has no green
  state.** Every decision that resolves with a closed owner adds a permanent
  line, so the population is monotonically non-decreasing and no lane can ever
  drain it — D109's `ROWS_PENDING_ENTRY` pattern cannot be transplanted because
  there is nothing to drain.
  **(iii) The ticked clause carries no information, and this is measured on the
  identical domain.** D104 assigns two rulings with the anchored form: §4 to
  **A48** (executed — the registry's `MAX_OTS_DEPTH` row now reads *"re-measured
  by A48 2026-08-10"* and `12.05x`) and §6 to **A106** (**not** executed —
  `limits.rs:361` still gates on `size_of::<usize>() == 8` and the structural-cost
  cell at `anchor-artifact-limits.md:222` contains zero occurrences of `24 576`).
  Both owners are ticked. **The proposed predicate fires on both and separates
  nothing: 1 of 2.** One fact separates them perfectly: **A48's row names D104
  and A106's row names no decision at all** — it is the only D104 owner whose
  row cites nothing, against A48 (D104/D107/D58), A63 (D103/D104), A109
  (D102/D104), A114 (D102/D104) and A121 (D104).
  **A premise of Q145 is falsified.** A106 did *not* close without a forwarding
  pointer — its row hands the residue on explicitly, *"filed as **A114**"*. What
  was lost at the handoff is the **decision id**, not the successor: A114's row
  at `5fbc48d` cites **D102** — as the *subject* of the defect (*"a D102 banner"*)
  — and never D104, and A114's `tasks/A.md` entry names no governing decision in
  its `Do`, `Accept` or `Notes` at all. So a check keyed on *"does the row cite
  some decision"* would have been **green** at the motivating instance. The
  citation must be **keyed to the assigning decision** or it proves nothing.
- **Date: 2026-08-10** (M2 wave 12 planning round; briefed to confirm a join
  over the register and the checkboxes, and refuses it on the measurement that
  the join's third column is prose in 94 files this script cannot parse)
- **Owning tasks: Q145** (the ruling; its `Do`, `Accept` and `Notes` are
  rewritten), **A121** (the instance, which this record does **not** execute),
  **Q85/D109** (the sibling checks this diverges from, with reasons),
  **Q141** (the venue defect this check's self-test inherits)
- **Amends**: **`TODO.md` Q145's row** (`:582`) and **`tasks/Q.md` Q145's entry**;
  **`TODO.md` A106's row** (`:462`), which gains the forwarding pointer;
  **`TODO.md`'s "How to use this list" protocol rule 3**, which gains the
  assignment clause; **`scripts/check-traceability.py`** (module docstring,
  `CHECKS`, one new check, three new self-test cases);
  **`docs/decisions/README.md`** (index row). **Supersedes**: nothing.
  **Binds against**: D109 (`check_task_citations`/`check_task_entries`, the
  `ROWS_PENDING_ENTRY` shape and its staleness rule, and §3.3's exclusion of
  `docs/decisions/` from `TASK_SCAN`), Q66's derived-fixture rule,
  `scripts/ci-lanes.sh:822-829` (`lane_traceability`), D104 §6 and §9.

---

## The problem, in one sentence

D104 §6 says *"**Owner: A106**"*, A106 closed on 2026-08-10 having excluded that
work, the ruling is still unexecuted today, and the question is whether any
mechanical rule can see that — given that A106 being ticked is the normal,
healthy state of 42 other owner assignments in the same corpus.

---

## 1. What was measured

Read from the working tree at `5fbc48d` + wave 12's uncommitted lane,
2026-08-10. Every figure below came from a script written for this round and
run against the real repository; the scripts are in the scratch directory and
the commands are quoted at each claim. Nothing here is quoted from the brief.

### 1.1 The register, and the corpus it points at

```
$ python3 -c '...' # count [x]/[ ] D-rows in TODO.md, count docs/decisions/D*.md
D register: 99 resolved [x], 13 open [ ], max=112
decision files on disk: 94
```

99 resolved decisions, 94 record files. That is the universe the proposed join
would range over.

### 1.2 The owner field is not a convention — it is five spellings, two of them traps

```
$ grep -rno 'Owner: [^*]*' docs/decisions/*.md          # 20 hits, 16 files
$ grep -rc  'Owning tasks' docs/decisions/*.md | grep -vc ':0'
55
```

Every one of the 20 `Owner:` hits, classified by reading it:

| form | count | docs | example |
| --- | --- | --- | --- |
| front-matter bullet, prose | 12 | D26, D32–D38, D52, D83, D89, D90 | `- **Owner: S2 (Blob/Address freeze); consumed by S4, S6, S9, S12, S14, R20**` |
| **anchored per-ruling, one id** | **2** | **D104 only** | `**Owner: A106**, whose class this is …` |
| inline parenthetical | 2 | D53 §11 items 1 and 7 | `Add the row in §7. (Owner: A38.)` |
| prose naming a **domain**, not a task | 2 | D92 §9 | `Size S. Owner: A domain, M2.` |
| **a quotation of a tail being DELETED** | **2** | D8 `:756`, `:1493` | `drop the "Owner: D8 with F8/F9/R" tail.` |

Two independent things fall out.

**The bare string has a 10 % false-positive rate before any join is attempted.**
D8's two hits are inside an *open correction list* — `- [ ] **C3.**` — instructing
a later lane to delete the very string a grep is matching. A rule that reads
`Owner:` unanchored reports `F8` and `F9` as owners of D8.

**The front-matter bullet cannot be parsed, and the failure is measured.** Taking
"the first task id after `Owner:`" over the 12 bullets yields **2 artifacts in
12**: D26 returns `G18` (its bullet is the last in the front matter, so a
fixed-width window runs past it into `## Context`), and D83 returns `Q14` from
`- **Owner: G (semantics + both checks) + F (registry wording); gate Q14**`,
where Q14 is the **gate**, not the owner. A 17 % parse-error rate on a 12-item
domain is not a field; it is prose.

**The corpus's real convention is a different field with different meaning.**
`- **Owning tasks:**` appears in 55 of 94 documents (27/55 for D1–D61, 13/22 for
D74–D95, **15/17 for D96–D112**). It is a *related-tasks* list, not an owner:

> `- **Owning tasks: A109** (the ruling; closed by it), **A11** (the constant,
> which does not move), **A48** …, **A63** …, **A106** …, **A27** (the document,
> historically …)

Six tasks, of which one is explicitly *"does not move"* and one is *"historically"*.
Joining on this field means joining on a bibliography.

**And 27 of 94 documents carry no owner field of any kind** (D1–D7, D9, D10,
D13–D15, D20–D25, D31, D75, D78–D80, D84, D88, and — modern — **D96, D98**).

> Q145's premise reads *"`check-traceability.py` already parses the register and
> the checkboxes, so it is a join over data it holds."* The register and the
> checkboxes it holds. **The third column of the join it does not hold, and
> cannot: it is prose in 94 files, spelled five ways, absent from 27 of them.**

### 1.3 The proposed rule's false-positive rate, run over the tree

The rule as written — *resolved decision, named owner, owner's row ticked* — run
at two scopes:

```
$ python3 scratchpad/m2_rules.py
RULE A: resolved decision + owner whose row is ticked
-- scope: section `Owner:` --
   FIRES on 42 (decision, owner) pairs across 15 decisions
   D8->F8, D8->F9, D32->S2, D32->S4, D32->S6, D32->S9, D32->S12, D32->S14,
   D33->S7, D33->S6, D34->S12, D34->S10, D34->U1, D34->U13, D35->P15, D35->S4,
   D36->S11, D36->U17, D36->U14, D37->S7, D37->S6, D38->P17, D52->Q15,
   D52->S17, D52->S18, D52->S19, D53->A38, D53->A40, D83->Q14, D89->U37,
   D89->U11, D90->A3, D90->A10, D90->A13, D90->A14, D90->A15, D90->A16,
   D90->A17, D90->A24, D92->U22, D104->A48, D104->A106
-- scope: front `Owning tasks:` --
   FIRES on 318 (decision, owner) pairs across 54 decisions
```

**True positives: one.** `D104->A106`. To establish the base rate rather than
assume it, twelve of the flagged owners were read by hand:

```
$ python3 -c '...'   # print each flagged owner's TODO.md row
P17  ticked=True has-✅-note=True  … ✅ 2026-08-02 — environment + runbook landed …
Q15  ticked=True has-✅-note=True  … ✅ 2026-08-02 — the D52 venue landed …
A3   ticked=True has-✅-note=True  … ✅ 2026-08-02 — `antseal-anchor` is the sole home …
S7 · S12 · S11 · S2 · U37 · A38 · A40 · P15 · Q14   — all ticked, all with ✅ notes
```

Twelve of twelve are owner-closed **and** ruling-executed. That is what the
rule reports 42 (or 318) times, once per run, for a human to read.

**The structural objection is larger than the ratio.** The report's population is
**monotonically non-decreasing**: a decision resolves once and stays resolved, an
owner ticks once and stays ticked. There is no edit that removes a line from
this report other than un-resolving a decision. **The check therefore has no
green state and no drain**, which is exactly the property `--task-entries` was
designed *not* to have: D109's `ROWS_PENDING_ENTRY` is *"CLOSED … it may only
SHRINK"*, and it shrinks because writing an entry removes a key. Nothing removes
a key here. A permanently red lane is a switched-off lane.

### 1.4 The decisive measurement: the ticked clause cannot separate D104 §4 from D104 §6

The two rulings sit in one document, in the identical syntax, with identically
ticked owners. One is executed and one is not.

```
$ grep -n 'A48 2026-08-10\|12\.05x' docs/format/anchor-artifact-limits.md   # §4
222: … re-measured by A48 2026-08-10 … | 12.05x | never | **40 960 B** = …

$ grep -n 'size_of::<usize>()' crates/antseal-core/src/anchor/ots/limits.rs   # §6
361:        if core::mem::size_of::<usize>() == 8 {
$ sed -n '222p' docs/format/anchor-artifact-limits.md | grep -c '24 576'
0
```

§4 is done: the `measured against` cell names A48's re-measurement and the margin
reads `12.05x`, exactly as D104 §4 ruled. §6 is not: the structural-cost cell
carries no wasm32 figure, and the test still has no 32-bit arm.

| predicate | D104 §4 → A48 (executed) | D104 §6 → A106 (**not**) | precision |
| --- | --- | --- | --- |
| Q145's: owner's row is ticked | **fires** | fires | **1 / 2** |
| back-citation: owner's row names D104 | silent | **fires** | **1 / 1** |

```
$ python3 -c '...'   # D-ids appearing in each D104 owner's TODO.md row
A27   ticked=True  D-citations: ['D10', 'D84']
A11   ticked=True  D-citations: ['D58']
A48   ticked=True  D-citations: ['D104', 'D107', 'D58']
A63   ticked=True  D-citations: ['D103', 'D104']
A109  ticked=True  D-citations: ['D102', 'D104']
A114  ticked=True  D-citations: ['D102', 'D104']
A121  ticked=False D-citations: ['D104']
A106  ticked=True  D-citations: []
```

**A106 is the only D104 owner whose row cites no decision whatsoever.** The
signal Q145 wanted was in the tracker the whole time, one column over from the
one it proposed to read.

### 1.5 The other two directions, measured against each other

The brief asked which direction has the smaller false-positive surface. Both
were run.

**Forward — every resolved decision must be cited by at least one task row:**

```
RULE C: resolved decision cited by NO task row at all
   FIRES on 4 of 99 resolved decisions:  D2, D3, D4, D76
   variant: no *unticked* row cites it -> 54 of 99
```

Four hits is the smallest surface of any candidate, and the rule is **structurally
blind to Q145**: D104 was cited by A48, A63, A109 and A114 the entire time the
§6 ruling sat orphaned. The unticked variant is unusable at 54.

**Backward — every named owner's row must cite the decision:**

```
RULE B (loose extraction, every id on the `Owner:` line)
   -- section `Owner:`      --  25 pairs across 12 decisions
   -- front `Owning tasks:` -- 268 pairs across 54 decisions
```

Loose, this is noise: most of the 25 are the *consumers* an owner line also
names (`consumed by S4, S6, S9, S12, S14, R20`). Restricted to the **principal**
owner — the first id after `Owner:` — the front-matter form yields 4 hits among
resolved decisions (D33→S7, D34→S12, D37→S7, D83→Q14), of which **D83→Q14 is the
parse artifact §1.2 measured**. Restricted to the **anchored per-ruling form**,
the domain is 2 and the hits are **1**.

> The direction is right and the *scope* is what decides the noise. The
> back-citation question is sharp; asking it of prose is not.

### 1.6 Where the chain actually broke — and the premise this falsifies

Q145 says A106 *"closed … with no forwarding pointer"*. Measured at `5fbc48d`,
that is **not what happened**:

```
$ git show HEAD:TODO.md | grep '^- \[x\] \*\*A106\*\*' | tail -c 200
… **explicitly NOT covered** and remains unowned — filed as **A114**
$ git show HEAD:TODO.md | grep '^- \[x\] \*\*A106\*\*' | grep -o '\bD[0-9]\+\b' | sort -u
(empty)
```

A106 left a *task* pointer and no *decision* pointer. And the pointer's target
did not recover it:

```
$ git show HEAD:TODO.md | grep '^- \[ \] \*\*A114\*\*' | grep -o '\bD[0-9]\+\b' | sort -u
D102
```

A114's row names D102 — as the **subject** of the defect (*"a D102 banner sits
above two A27 paragraphs"*), not as governance — and never names D104. Its
`tasks/A.md` entry at HEAD names D102 twice, in the same subject sense, and its
`Do`, `Accept` and `Notes` name **no governing decision at all**; its Notes close
*"this row exists so the fourth reader does not have to re-derive which is
authoritative"*, while the authoritative record went unnamed.

**Consequence for the design.** A check asking *"does this row cite any
decision?"* is **green** on A114 and green on A106's successor chain. The
assertion must be *"does this row cite **D104**"*, keyed to the assigning
decision. This is the same lesson D109 §1.5 learned about surfaces: the wrong
scope makes a real defect invisible while the check reports itself healthy.

### 1.7 Two more forms that must not be parsed, each with a measured trap

**RULING headings.** D104 §4 and §6 name their owners in the heading itself
(*"…: A48's, with A63 supplying the artifact"*, *"…and it is A106's"*), which
looks like a wider surface:

```
$ python3 scratchpad/m4_rulings.py
RULING headings in the corpus: 17
  ... that name at least one task id: 5   (in 3 documents)
D104 ['A48','A63']  ## 4. RULING 3 — … : A48's, with A63 supplying the artifact
D104 ['A106']       ## 6. RULING 5 — … and it is A106's
D105 ['R12','R20']  ## 2. RULING 1 — R20's storage-linkage …
D105 ['R12','R20']  ## 4. RULING 3 — … R12's *reasoning* has a flaw …
D110 ['R1']         ## 5. RULING 4 — §6 owes **no** entry, and D107 R1 says so
```

The last is a trap: **`D107 R1` is D107's Ruling 1, not task R1.** 1 artifact in
5 headings. Headings are refused.

**Section-keyed citation.** `tasks/A.md:1248` reads `- Deps: after A48 (D104 §4)`
and `tasks/Q.md:1539` reads `- Deps: after A27 (D104 §5)` — a good shape, and it
reveals the mechanism precisely: **a decision writes its pointers into the rows
it mints (A112, Q126, A121 all carry `(D104 §n)`) and never into rows that
already exist.** §6's owner A106 predated D104, so nothing was written into it.
The shape is also unmandated — 113 of 501 `Deps:` lines cite a decision (23 %) —
so it cannot be asserted, only encouraged.

---

## 2. RULING 1 — the ticked-owner join is REFUSED, and not on balance

Not "declined as noisy". **Refused, on three independent measurements, any one
of which is sufficient:**

1. **No domain.** The per-ruling owner field the join needs exists in **one of
   94** documents (§1.2). The field that exists in 55 is a related-tasks
   bibliography whose members include constants that *"do not move"*.
2. **No precision.** 1 of 42, or 1 of 318 (§1.3), against a hand-verified base
   rate of 12/12 owner-closed-and-executed.
3. **No information in the predicate.** On the identical two-assignment domain
   the ticked clause fires on the executed ruling and the unexecuted one alike
   (§1.4). It is not a weak signal; it is not a signal.

And a fourth, structural: **the report has no green state and no drain** (§1.3),
so D109's date-locked register cannot be transplanted onto it. A lane that is
red on 42 healthy rows every run is a lane someone deletes.

**Q145's `Do` is rewritten to this record's RULING 2. Its Accept bullet
requiring the ticked-owner report is deleted.**

---

## 3. RULING 2 — `--decision-owners`: the assigning decision's id must appear in the row it assigns to

**What the check asserts.** For every line in `docs/decisions/D<n>-*.md` matching
`^\*\*Owner: (<ID>)\*\*`, where `D<n>` is **resolved** in `TODO.md`'s register:

1. `<ID>` has a row in `TODO.md` (either shape — checkbox or struck), and
2. that row's text contains `D<n>` as a whole word.

**Flag:** `--decision-owners`, the sixth check in `scripts/check-traceability.py`.
It is picked up by `lane_traceability` automatically, which runs the script with
no arguments (`scripts/ci-lanes.sh:828`).

**Hard-fail, not advisory.** Advisory is the right call when the initial backlog
is large and the fix is other lanes' work. Here the backlog is **one line**, and
it is the defect the row exists to fix.

**Why the anchored form and nothing else.** §1.2 and §1.7 measure the cost of
every looser surface: unanchored `Owner:` reports D8's deletion instruction;
the front-matter bullet mis-parses 2 in 12; RULING headings mis-parse 1 in 5.
The anchored bold form is the only one that is unambiguously *one ruling
assigned to one registered task*. **Writing it becomes the author's part of the
bargain** — see RULING 4.

**Why the citation must be keyed.** §1.6: A114's row cites D102 and would satisfy
any "cites some decision" test while being blind to the decision that governs it.

**Why the closed row and not the successor.** A121's row cites D104 today, so a
rule satisfied by *any* row would be green at the motivating instance right now —
the exact failure D111 shipped in wave 12. The reader who lands on A106 must be
told there, in the row they are reading.

### 3.1 The check, verbatim — executed against the real repository

This block was pasted into a copy of `scripts/check-traceability.py`, registered
in `CHECKS`, and run. Its output is quoted in §3.2. No paraphrase.

```python
# ── check 6: a resolved ruling's owner is reachable from the row it names ────
# (Q145, ruled by D113)
#
# Q145 proposed a join over data this file already holds: resolved decision +
# owner whose row is ticked. D113 §2 refuses it on the identical two-assignment
# domain — D104 §4 (executed) and D104 §6 (not) — where the ticked clause fires
# on both and separates nothing. What separates them is the BACK-citation: A48's
# row names D104, A106's row names no decision at all.

DECISION_OWNER = re.compile(
    r"^\*\*Owner: ([" + TASK_DOMAINS + r"]\d{1,3})\*\*", re.M
)


def decision_owner_assignments() -> list[tuple[int, str, str, int]]:
    """`(decision number, owner id, filename, line)` per per-ruling assignment.

    Anchored and bold on purpose. The bare string `Owner:` occurs 20 times in
    the corpus and 2 of those are D8 quoting a tail it is DELETING; the
    front-matter `- **Owner: ...**` bullet is prose that names domains, gates
    and consumers as often as owners (D113 §1.2 measures 2 parse artifacts in
    12). This is the only form that is unambiguously one ruling assigned to one
    registered task, and D113 RULING 2 makes writing it the author's part.
    """
    found: list[tuple[int, str, str, int]] = []
    for path in sorted((ROOT / DECISION_DIR).glob("D*.md")):
        match = re.match(r"D(\d+)-", path.name)
        if not match:
            continue
        number = int(match.group(1))
        for line_no, line in enumerate(
            path.read_text(encoding="utf-8").splitlines(), 1
        ):
            hit = DECISION_OWNER.match(line)
            if hit:
                found.append((number, hit.group(1), path.name, line_no))
    return found


def row_text() -> dict[str, str]:
    """`id -> the whole TODO.md row`. `task_rows()` returns the struck flag and
    drops the text, and this check's question is about the text."""
    todo = (ROOT / "TODO.md").read_text(encoding="utf-8")
    found: dict[str, str] = {}
    for line in todo.splitlines():
        match = TASK_ROW.match(line)
        if match:
            found[match.group(1) + match.group(2)] = line
    return found


def check_decision_owners(failures: Failures) -> None:
    check = "decision-owners"

    allocated = allocated_decision_ids()
    if not allocated:
        failures.add(check, "no decision ids in TODO.md's register — the bound is vacuous")
        return
    resolved = allocated - open_decision_ids()
    rows = row_text()
    if not rows:
        failures.add(check, "TODO.md yielded no task rows — the check would be vacuous")
        return

    assignments = decision_owner_assignments()
    if not assignments:
        # The domain is small (D113 §1.2: one document today), so vacuity is
        # this check's likeliest failure and it must be loud, not green.
        failures.add(
            check,
            "no `**Owner: <ID>**` assignment exists in any decision document. Either the "
            "mandated form (D113 RULING 2) stopped being written or this regex stopped "
            "matching it; a check over an empty domain proves nothing.",
        )
        return

    checked = 0
    for number, owner, name, line_no in assignments:
        if number not in resolved:
            continue  # an unresolved decision has assigned nothing yet
        checked += 1
        if owner not in rows:
            failures.add(
                check,
                f"{name}:{line_no} assigns a ruling to {owner}, which has no row in "
                f"TODO.md's register. A ruling owned by an unregistered id is owned by "
                f"nobody. Add the row, or name an id that exists.",
            )
            continue
        if not re.search(rf"\bD{number}\b", rows[owner]):
            failures.add(
                check,
                f"{name}:{line_no} assigns a ruling to {owner}, and {owner}'s TODO.md row "
                f"never names D{number}. A lane that opens {owner}, or the row that succeeds "
                f"it, cannot learn that D{number} governs the work — which is how a resolved "
                f"ruling outlives its owner's closure unexecuted and unseen (Q145). Put "
                f"`D{number} §<n>` in {owner}'s row: if the ruling is done say so there, and "
                f"if it is not, the row must name the task carrying the remainder.",
            )

    if not failures:
        print(
            f"[{check}] ok — {checked} per-ruling owner assignment(s) in resolved "
            f"decisions, every one named by the row it assigns"
        )
```

Register it as `"decision-owners": check_decision_owners` in `CHECKS` and add the
line to the module docstring's table:

```
    --decision-owners   Every `**Owner: <ID>**` assignment in a RESOLVED
                        decision names a registered task whose TODO.md row
                        names that decision back (Q145).
```

### 3.2 It goes red at its own motivating instance, today

**This is the D111 test, and it passes.** Run against the working tree with
A121 registered but not landed:

```
$ python3 <copy>/scripts/check-traceability.py --decision-owners
::error::check-traceability [decision-owners] D104-max-ots-depth-lowering-window.md:514
  assigns a ruling to A106, and A106's TODO.md row never names D104. A lane that
  opens A106, or the row that succeeds it, cannot learn that D104 governs the
  work — which is how a resolved ruling outlives its owner's closure unexecuted
  and unseen (Q145). Put `D104 §<n>` in A106's row: …

check-traceability: FAILED with 1 problem(s).
exit=1
```

**One failure. Exactly the instance. Zero false positives across the whole
corpus.** D104 §4 → A48 — same document, same syntax, ticked owner — is silent,
because A48's row names D104.

And it goes green on the repair and on nothing else:

```
$ python3 - <<'EOF'   # insert the forwarding pointer into A106's row
re.sub(r"(^- \[x\] \*\*A106\*\* )",
       r"\1**Governed in part by D104 §6, whose remaining half is A121.** ", …)
EOF
$ python3 <copy>/scripts/check-traceability.py --decision-owners
[decision-owners] ok — 2 per-ruling owner assignment(s) in resolved decisions,
                  every one named by the row it assigns
exit=0
```

---

## 4. RULING 3 — no exemption register, and the one hit is fixed in the landing commit

D109 established the register pattern and this record deliberately does **not**
use it. Three reasons, in order:

1. **The backlog is one.** `ROWS_PENDING_ENTRY` exists because 21 rows could not
   be given entries in one commit. One sentence in one row can.
2. **D109 §3.4's own precedent forbids it.** `A71` was *"deliberately NOT put"*
   in `TASK_ID_NOT_A_CITATION` because *"registering it as noise would make this
   check's first run certify a dangling pointer instead of finding one"*. The
   single hit here **is** Q145's measured instance. Registering it would ship a
   check whose first act is to bless the defect it was written for.
3. **A register would make the self-test vacuous.** Measured: with the tree red
   at baseline, self-test fixture (i) produces **2** messages, one of them
   pre-existing, so a mutation that silently stopped working would still read
   "red". **The repair to A106's row must be in the same commit as the check**,
   or every red fixture is unfalsifiable.

**The repair, specified.** `TODO.md` A106's row gains a clause naming the
decision and the successor — for example *"**D104 §6 governs the remainder** —
the wasm32 cells and the 32-bit test arm; the unexecuted half is **A121**."*
This is not fabricated provenance: D104 §6 named A106 on 2026-08-09 and A106
closed on 2026-08-10 having excluded it. The row is being made to say what was
already true.

**If a future backlog ever exceeds one**, a register must follow D109's shape
exactly — keyed, every value carrying a `*_FROZEN_ON` constant, may only shrink,
and with a staleness rule that fails when a key is satisfied — or say why it
differs.

---

## 5. RULING 4 — the blind spot, named, and the protocol clause that bounds it

**Named plainly: a decision that assigns a ruling in prose is invisible to this
check.** If D104 §6 had read *"and it is A106's"* in the heading and nothing
else, `--decision-owners` would be green. The domain is **2 assignments in 1
document** today, and the check's value is therefore mostly prospective.

That is a real weakness and §1.2/§1.7 are the reason it is accepted rather than
fixed by widening: every looser surface was measured and every one mis-parses.
The blind spot is bounded from the other side instead, by making the form a
rule rather than a habit.

**`TODO.md`'s "How to use this list" protocol rule 3 gains one clause:**

> When a decision assigns part of its ruling to a task that **already has a
> row**, write the assignment as `**Owner: <ID>**` on its own line in that
> ruling's section, **and** add `D<n> §<k>` to that task's row. The second half
> is checked by `--decision-owners`; the first half is not checked by anything,
> which is why it is written down here. A decision that mints a *new* row
> carries the pointer already — `(D104 §4)`, `(D104 §5)`, `(D104 §6)` — and it
> is the pre-existing rows that get orphaned (D113 §1.7).

**What covers the residue.** (i) The form is one line and now has a stated
purpose. (ii) The vacuity guard fails loudly if the form stops being written, so
the convention cannot decay silently to zero. (iii) `--decision-owners`'s second
clause catches the adjacent defect — a ruling assigned to an id with no row at
all — for free, on the same parse.

**Q141 blocks the local half.** `scripts/ci-lanes.sh:824` runs `--self-test`
before `:828` runs the checks, but the local gate reaches this lane through
`scripts/local-gate.sh:262`'s `run traceability scripts/ci-lanes.sh traceability`
only; Q141 records that the local gate structurally cannot see the self-test
groups. **This check's three fixtures inherit that**, and the implementing lane
must say so in Q145's Notes rather than discover it later.

---

## 6. The self-test, and why each case exists

Q66's rule applies in full: **no case may hard-code a task id, a decision
number, a count or a line number.** Every value below is read from the scratch
tree at fixture time, and the helper raises rather than returning a literal when
the tree yields nothing.

```python
        def an_owner_assignment() -> tuple[int, str, str]:
            """`(decision number, owner id, decision filename)` for the first
            per-ruling assignment whose owned row ALREADY names the decision —
            so case (l)'s deletion is a real removal and not a no-op."""
            rows: dict[str, str] = {}
            for line in (tree / "TODO.md").read_text(encoding="utf-8").splitlines():
                match = TASK_ROW.match(line)
                if match:
                    rows[match.group(1) + match.group(2)] = line
            for path in sorted((tree / DECISION_DIR).glob("D*.md")):
                head = re.match(r"D(\d+)-", path.name)
                if not head:
                    continue
                number = int(head.group(1))
                for owner in DECISION_OWNER.findall(path.read_text(encoding="utf-8")):
                    if owner in rows and re.search(rf"\bD{number}\b", rows[owner]):
                        return number, owner, path.name
            raise AssertionError(
                "self-test: no per-ruling owner assignment has a back-citing row, so the "
                "decision-owners cases would be built from nothing"
            )

        owner_dnum, owner_id, owner_doc = an_owner_assignment()
        ghost_owner = above_ceiling(owner_id[0])
```

Three cases, appended to the existing `cases` list:

```python
            (
                # (l) red — the row stops naming the decision that assigned it.
                "decision-owners",
                "TODO.md",
                lambda t: re.sub(
                    r"^(- (?:\[[ xX]\]|~~)\s*\*\*" + owner_id + r"\*\*.*)$",
                    lambda m: re.sub(rf"\bD{owner_dnum}\b", "", m.group(1)),
                    t, count=1, flags=re.M,
                ),
                "red",
            ),
            (
                # (m) red — the assignment names an id that has no row at all.
                "decision-owners",
                f"{DECISION_DIR}/{owner_doc}",
                lambda t: t.replace(
                    f"**Owner: {owner_id}**", f"**Owner: {ghost_owner}**", 1
                ),
                "red",
            ),
            (
                # (n) green — the four prose `Owner:` shapes the corpus really
                # contains (§1.2) must not be parsed as assignments: the
                # front-matter bullet with a consumer list, D8's quotation of a
                # tail it is deleting, D92's domain-letter form, and an indented
                # bold form. Widening the regex turns this case red, which forces
                # a re-decision instead of a quiet edit.
                "decision-owners",
                f"{DECISION_DIR}/{owner_doc}",
                lambda t: t + (
                    f"\n- **Owner: {ghost_owner} (freeze); consumed by {ghost_owner}**\n"
                    f'and the trailing "Owner: {ghost_owner} with F8/F9/R" removed.\n'
                    f"Size S. Owner: A domain, M2 (before a report renders it).\n"
                    f"   **Owner: {ghost_owner}** (indented, so not an assignment)\n"
                ),
                "green",
            ),
```

Executed, against a copy of the real script and a copy of the real tree with the
A106 repair applied:

```
$ python3 <copy>/scripts/check-traceability.py --self-test
self-test: ok — decision-owners goes red when TODO.md is corrupted
self-test: ok — decision-owners goes red when docs/decisions/D104-…​.md is corrupted
self-test: ok — decision-owners stays green where it must, on docs/decisions/D104-…​.md
```

---

## 7. Kill criteria

This record is wrong, and must be reopened, if any of these is measured:

1. **A second document adopts the anchored `**Owner: <ID>**` form and the check
   fires on it as a false positive.** §1.4's 1/1 precision is measured on a
   domain of two. The first genuine false positive re-opens the scope question,
   and the answer is more likely to be a keyed suppression register of D109's
   shape than a weakening of the predicate.
2. **A ruling is orphaned in a document that uses the anchored form, and the
   check is green on it** — i.e. the owner's row cites the decision and the
   ruling is still unexecuted anyway. Then back-citation is necessary and not
   sufficient, and the sufficient half is a human review this record declines to
   automate.
3. **`- **Owning tasks:**` becomes a per-ruling owner field** with one id and a
   stated section. Its 15/17 adoption for D96–D112 would then make it the right
   surface and §1.2's refusal would be stale.
4. **The `Owner:` string count moves far from 20 without the anchored form
   growing** — that is the convention drifting to a sixth spelling, and §1.2's
   census must be retaken before the check is trusted.
5. **`ROWS_PENDING_ENTRY` is drained and the register deleted** (D109 §8 (iv)).
   §4's reasoning cites it as the live precedent for the shape; if it is gone,
   the shape must be re-argued from D109's text rather than from the constant.

---

## 8. Discovered work — named, not registered

*(No ids minted. The orchestrator allocates at bookkeeping — waves 8 and 10 each
had two planners mint the same number, and central assignment gave waves 11 and
12 zero collisions.)*

- **27 of 94 decision documents carry no owner field of any kind**, including two
  written this milestone (D96, D98), while `- **Owning tasks:**` is at 15/17 for
  D96–D112. A presence check on the front-matter field has a real domain and is a
  different instrument from this one — worth one row, and it is *not* what
  `--decision-owners` does.
- **Two owner-field spellings coexist with no rule about which**: `- **Owner:`
  (12 documents, all D26–D90) and `- **Owning tasks:` (55). A house-style
  consolidation in `docs/decisions/README.md`, plus one pass over the 12, would
  make §1.2's census stable.
- **`docs/decisions/D8-wire-registry-final.md` holds 7 open `- [ ] **C3.**`-style
  checkbox items inside a RESOLVED decision** (36 checkbox lines across the
  decision corpus). They are invisible to every tracker check, and one of them
  instructs a lane to delete the string `Owner:` — which is exactly the trap
  §1.2 measured. Either they are work with rows, or they should stop looking
  like tasks.
- **Four resolved decisions are cited by no task row at all**: D2, D3, D4 and
  **D76**. D2/D3/D4 are M0 infrastructure and plausibly need none; **D76 is a
  format decision (file-salt split)** and its absence from every row is worth one
  look, independent of any check.
- **The section-keyed citation shape `(D104 §4)` is good and unmandated** — 113
  of 501 `Deps:` lines in `tasks/*.md` cite a decision (23 %), and only a handful
  name the section. Mandating it in protocol rule 7 is cheap; asserting it is
  not, because most `Deps:` lines have no decision to name.
- **A114's `tasks/A.md` entry still names no governing decision** while D104 §6
  governed it. `--decision-owners` does not read `tasks/*.md`, so this is not
  fixed by the check; the A121 lane should repair the entry while it is there.
- **Q141 blocks this check's self-test locally**, as it blocks Q130's three. The
  ordering already in the Current-focus queue is right; this record adds one more
  instrument to the list of things the local gate cannot see.

---

## 9. Consequences — the exact edit set

| file | edit | § |
| --- | --- | --- |
| `scripts/check-traceability.py` | `DECISION_OWNER`, `decision_owner_assignments()`, `row_text()`, `check_decision_owners()` verbatim from §3.1; `CHECKS` gains `"decision-owners"`; module docstring gains the line | 3.1 |
| `scripts/check-traceability.py` (`self_test`) | `an_owner_assignment()` helper and cases (l), (m), (n) verbatim from §6 | 6 |
| `TODO.md` A106's row (`:462`) | gains the forwarding clause naming **D104 §6** and **A121** — **required in the same commit**, or every red fixture is unfalsifiable | 4 |
| `TODO.md` protocol rule 3 | gains the assignment clause from RULING 4 | 5 |
| `TODO.md` Q145's row (`:582`) | closed as RULED; the *"machine-readable half is the first two clauses"* design is recorded as refused with the 1/2 and 1/42 measurements | 2 |
| `tasks/Q.md` Q145's entry | `Do` → RULING 2; the ticked-owner Accept bullet deleted; Notes record the falsified premise (§1.6) and Q141's effect on the self-test | 2, 5 |
| `docs/decisions/README.md` | index row | — |

**Zero constants move. Zero wire bytes. Zero format-version events. Zero
vectors, digests or error codes touched. No production code is read or written
by the new check.**

---

## 10. What this record does not decide

- **Whether D104 §6's ruling is executed.** It is not (§1.4), and that is
  **A121's**, unchanged. This record makes the ruling *visible*; it does not
  land the two cells or the 32-bit arm.
- **Whether A106's row should have carried the pointer on 2026-08-10.** It is
  being added now because the fact is true, not as a claim about what the lane
  knew.
- **Whether every task entry should name its governing decision.** That is the
  `tasks/*.md` side, 501 `Deps:` lines wide, and it is a separate instrument
  (§8).
- **Whether the front-matter owner field should be consolidated.** Named in §8;
  §1.2 only measures that it cannot be parsed today.
- **Q134's twelve entry-less rows.** Adjacent — both are "a pointer exists and
  its target says nothing" — but Q134 is `tasks/*.md` coverage and is already
  first in the queue.

---

## Outcome

**RESOLVED, 2026-08-10.** Q145's proposed join is **refused**, on three
measurements taken against the tree rather than argued: the per-ruling owner
field it reads exists in **1 of 94** decision documents and the field that exists
in 55 is a related-tasks bibliography; the rule's precision is **1 of 42**
(or 1 of 318), against a hand-verified base rate of **12/12** owners who closed
*and* executed; and on the identical two-assignment domain **the ticked clause
fires on the executed ruling and the unexecuted one alike — 1 of 2 — so it is not
a weak signal but no signal**. Structurally it also has no green state and no
drain, so D109's register cannot be transplanted onto it. What lands instead is
the **keyed back-citation**: `--decision-owners`, hard-fail, asserting that a
resolved decision's `**Owner: <ID>**` assignment names a registered task whose
`TODO.md` row names that decision back. Run against the working tree it reports
**exactly one failure — D104 §6 → A106 — and zero false positives**, is silent on
D104 §4 → A48 in the same document with the same syntax and a ticked owner, and
goes green on the one-sentence repair. **One premise of Q145 is falsified**: A106
did leave a forwarding pointer — *"filed as **A114**"* — and what was dropped at
the handoff was the **decision id**, not the successor; A114's row cites D102 as
the *subject* of its defect and never D104, so a check keyed on *"cites some
decision"* would have been green at the motivating instance. The blind spot —
prose assignments — is named rather than papered over, bounded by a protocol
clause in `TODO.md` rule 3 and by a loud vacuity guard, and every wider surface
was measured and refused with its own artifact: unanchored `Owner:` reports D8's
*deletion instruction*, the front-matter bullet mis-parses 2 in 12, RULING
headings read **D107's Ruling 1 as task R1**.

---
## Amendment — the owner-field census is wrong in both directions, 2026-08-10

**Recorded, not applied. The body above is byte-unchanged**, per D115 §3.7:
whether a resolved decision's body may take a dated correction is `Q122`, still
open. This section is the appended-correction mechanism `D84` established and
`D109` used on 2026-08-10, which is a different act from editing the body.

**§1.2's census is wrong, and so is the re-measurement that corrected it.**
Measured at wave 13's bookkeeping, over `docs/decisions/*.md`:

| claim | source | measured |
| --- | --- | --- |
| corpus size | §1.2: **94** | **99** files (98 D-documents + `README.md`) |
| `- **Owning tasks:` | §1.2: **55** | **41** |
| no owner field at all | §1.2: **27**; lane D: **43** | **46** under §1.2's two spellings; **26** counting all four |
| owner-field spellings | §1.2: **two** | **four** |
| D96 / D98 carry no owner field | §1.2 | **false — both do** |

The four spellings are `- **Owner:` (12), `- **Owner**:` (2),
`- **Owning task:` (18, singular) and `- **Owning tasks:` (41). D96 and D98 use
the second, which a `- **Owner:` regex misses — which is almost certainly how
they came to be named as the counterexamples. **The disagreement is itself the
finding**: three independent counts of one corpus produced three answers because
no spelling is normative. That is now `Q162`, and the presence check §8 bullet 1
proposed is `Q161`, filed with the corrected domain rather than either estimate.

**§1.4's D8 figure is low by 24.** `docs/decisions/D8-wire-registry-final.md`
carries **31** open `- [ ]` items (A=2, B=10, C=7, D=7, E=5), not 7; 7 is the
`C` group alone. The 36-corpus-wide figure holds if it counts open **and**
checked (33 open, 3 checked). Registered as `Q163`.

**§5's *"Q141 blocks the local half"* is false.** `--self-test` runs inside
`ci-lanes.sh`'s `lane_traceability()`, which the local gate invokes, so the
local half was never blocked. This is why `tasks/Q.md`'s `Q145` entry does
**not** carry the caveat §7's edit set instructed: lane D falsified it before it
was written, and the instruction was correctly not followed.

**§1.6/§8's A114 claim is stale at `d23dccc`.**

**RULINGS 1 and 2 stand.** Every error above runs in the direction that
*strengthens* the refusal — a larger no-owner set and more spellings make the
prose column less machine-readable, not more — so the ticked-owner join is
refused on stronger ground than the record gives. **But §7's kill criteria 3 and
4 key on the wrong baselines** and must be re-derived from the figures above
before either is tested.

*Not verified at this bookkeeping, and recorded as unverified rather than as
fact: lane D's re-measurement of §1.3's front-matter precision (**177 pairs
across 38 decisions**, against §1.3's 318 across 54). Nobody should quote either
number until one of them is reproduced.*
