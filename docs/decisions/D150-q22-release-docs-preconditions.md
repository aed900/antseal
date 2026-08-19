# D150 — Q22's preconditions: the `Q30` edge falls, but D141 §2 R3's reasoning is not what fells it — and Q22 cannot tick this wave for a reason no `after:` edge can express

- **Status: RESOLVED. The lean is HALF CONFIRMED IN DIRECTION AND FULLY REFUTED
  IN MECHANISM, and its second half is OVERTURNED OUTRIGHT.** The lean was
  *"the `Q30` edge falls by D141 §2 R3's own reasoning, and Q22 can be written
  and ticked this wave."*
  - **D141 §2 R3's reasoning does NOT transfer to `Q30`, and the proof is that
    D141 ran this exact test itself and reached the opposite answer.** R3 struck
    the `Q31` edge because everything Q22 needed from Q31 already existed *as a
    record*. Applied to Q30 the same test returns a different verdict, and D141
    wrote the verdict down at `docs/decisions/D141-…:231-233`: *"**The one field
    Q22 genuinely cannot write before Q30** is that 56-character public key. Q30
    … lies on no cycle path, so this record leaves the `Q30` edge exactly as it
    is."* A key is not a record. It does not exist: `dig +short TXT antseal.org`
    returns **empty** and `minisign` is **not installed on this host**. Anyone
    who fells the `Q30` edge by quoting D141 §2 R3 is quoting the paragraph
    that preserves it.
  - **The arm nobody listed, and the one this record takes: the README's key
    line is not Q22's to write at all — it is Q30's own procedure acting on
    Q22's file.** `docs/signing/maintainer-key-procedure.md:167-174`, §5
    *"Publish the key in the other three places"*, step 1: **`README.md` — the
    56-character key, with a pointer to `verifying-a-release.md`**, performed
    *"After §1 and alongside §2"*. Q30 is a **consumer of Q22's install
    section**, in the same direction and with the same shape as
    `tasks/Q.md:524`'s *"Q31 is the **consumer** of the signing step"*. The edge
    falls — for the opposite reason to the one briefed. Writing it as recorded
    (`Q22 after Q30`) while §5 step 1's real dependence points the other way is
    one registrar note away from a 2-cycle that **nothing checks** (D141 §2 R7).
  - **"Q22 can be ticked this wave" is overturned on Q22's own `Accept`, not on
    any edge.** Row 2 is *"proven on a clean machine **during the Q34 gate**"*
    and row 3 is *"(**checked by Q28**)"* — two of four clauses are verified by
    successors, both open, and Q34 is now `after Q65` (D141 §2 R2). This project
    does not tick rows with unmet `Accept` rows: **Q30 itself is the live
    proof** — pipeline BUILT AND PROVEN, three `Accept` rows partly unmet, row
    still `- [ ]`.
- **The sharpest defect is in the instrument, and it is Q252's class exactly.**
  `check-copy-style.py --self-test`'s P7 arm *"a debt satisfied but not deleted
  from `OWED_PRESENCE`"* (`:789-799`) **derives its red from the live register
  being non-empty**. Q22's completion empties that register. Run against the
  real function with the register at `{}` and the arm's own mutation planted,
  P7 findings go **2 → 0**: the arm expects red, gets green, and **fails a
  required CI context and a local-gate lane**. A self-test fixture whose
  subject is state the project is driving to zero disarms itself — the wave-23
  finding (Q252), recurring in a different instrument, inside the one check
  that polices the front door.
- **A second ruling's stated verification cannot succeed.** D141 §2 R4 made the
  flip permissible when *"`grep 'registered debt' <(python3
  scripts/check-copy-style.py)` returns **zero** lines for `README.md`"*.
  Measured, that command returns **3** today and would return **1** after full
  discharge — never 0 — because the summary line at `:1012` itself contains the
  phrase (*"(P7, 2 registered debt(s) above)"*). The predicate is corrected in
  §2 R6 to an anchored form, measured at 2 today and 0 after discharge.
- **Date: 2026-08-18**
- **Owning task: Q22.** Rulings touch `TODO.md`'s Q22 and Q30 rows, `tasks/Q.md`
  Q22's `Deps`/`Do`/`Accept` and Q30's Notes, `scripts/check-copy-style.py`'s
  `OWED_PRESENCE` and one self-test arm, and `README.md`. **No new id is
  assigned here**; §5 describes what the registrar mints.
- **What it blocks:** Q65's narrowed `Q22` edge (D141 §2 R4) — and therefore
  Q31/Q34 through Q65 — plus Q28, which is `after Q20–Q27`.
- Related: **D141 §2 R3** (the instrument reused here and the paragraph that
  refutes the lean), **§2 R4** (the narrowing whose predicate is repaired),
  **§2 R7** (nothing checks the order for cycles); **D71 §2 R3** (the exact
  command), **§2 R5** (the README is a *pin*), **§2 R11** (what release
  documentation may not say); **D72 §2 R5/R6** (the channel, and the fact that
  it is **inoperative** today), **§3.1** (the `--passphrase-fd` obligation);
  **D139 §2 R6** (one writer of `check-copy-style.py`, once), **§2 R9** (the
  debts are Q22's and nobody else may delete them); **D140 §2 R5** (Q248, the
  README precedent, whose §1.8 premise D141 has since killed).

---

## 1. What was measured

Everything below was re-measured in this lane. Where a row, a record or the
brief disagrees with the tree, the tree is quoted and the source is corrected at
the site. Commands whose exit status matters were written to a file and the
status read back, per this project's harness rule.

### 1.1 Baseline and locators

`python3 scripts/check-traceability.py` (flagless — the check) at HEAD:
**green, all eight checks, `REAL_EXIT=0`**, reporting *"685 rows (684 live + 1
struck) against 685 entries"*, *"149 allocated decision ids … 0 still open"* and
*"143 index row(s) … against 143 record(s)"*.

`python3 scripts/check-copy-style.py` (flagless — the check; `--check` is not a
flag) at HEAD: **`REAL_EXIT=0`**, three lines, two of them registered debts.

Locators, re-measured because D141's have drifted by two lines since it was
written:

| row | line today | D141's citation |
| --- | --- | --- |
| Q22 | `TODO.md:810` | `:808` |
| Q28 | `TODO.md:816` | `:814` |
| Q30 | `TODO.md:818` | `:816` |
| Q65 | `TODO.md:824` | `:822` |
| Q22 entry | `tasks/Q.md:431` (`Deps` `:434`, `Do` `:436`, `Accept` `:438-441`) | `:434` |

`TODO.md:810` reads, verbatim in its ordering position: `— after Q20,Q30
~~,Q31~~`. `Q20` is `- [x]` (`TODO.md:802`, ✅ 2026-08-16). `Q30` is `- [ ]`.

### 1.2 The `Q30` edge, field by field: what Q22 needs and where it already exists

`tasks/Q.md:436` asks for *"install instructions including binary signature
verification (sha256sums + minisign/cosign steps)"*. Every operand of that
clause, and its status:

| operand | exists? | where |
| --- | --- | --- |
| the release channel | **ruled** | D72 §2 R5, `:506` — *"The channel is GitHub Releases, single authoritative source"* |
| the artifact target | **ruled** | D72 §2 R1, `:423` — `x86_64-unknown-linux-gnu`, *"the only one"* |
| the human verify command | **ruled, verbatim** | D71 §2 R3, `:407-434` |
| the expected trusted comment | **ruled, verbatim** | D71 §2 R3, `:425-429` |
| `SHA256SUMS` and the bulk check | **built** | D71 §2 R3 `:449-451`; `scripts/sign-release.sh` (Q30, wave 24) |
| the checking procedure, prose | **written** | `docs/signing/verifying-a-release.md`, 161 lines, Class **P** |
| **the 56-character public key** | **DOES NOT EXIST** | `dig +short TXT antseal.org` → empty; `command -v minisign` → not found; `docs/signing/maintainer-key-procedure.md:228-229` — *"**Not run:** every step in §1, §2 and §3 … **No project key exists**, no `TXT` record exists, and nothing has been anchored"* |

**Wave 24 is what changed the arithmetic, and no record has noticed.** Before
it, Q22 could not name `SHA256SUMS`, could not name the scripts, and had no
written procedure to point at. `TODO.md:818` now records the pipeline as *"BUILT
AND PROVEN"*. **Every row of that table except the last is discharged.** The
`Q30` edge has exactly one surviving operand, and it is a datum, not a document.

### 1.3 The finding D141 did not have: the README key line is Q30's act, not Q22's

`docs/signing/maintainer-key-procedure.md:167-177`, verbatim:

> ## 5. Publish the key in the other three places
>
> After §1 and alongside §2:
>
> 1. **`README.md`** — the 56-character key, with a pointer to
>    [`verifying-a-release.md`](verifying-a-release.md).
> 2. **The page footer at `https://antseal.org/`.**
> 3. **`minisign.pub` as a release asset**, with `minisign.pub.ots` beside it.
>
> All four locations change **in one act** whenever the key changes.

That document is Q30's, landed by Q30's lane in wave 24. **It assigns an edit to
`README.md` — Q22's file — as a step of Q30's own procedure, performed at the
moment the key exists.** Q22 does not consume the key; Q30 §5 step 1 *inserts*
it.

Two consequences, and they point the same way:

1. **The recorded edge is backwards.** Rule 7's second clause is the *"consumer,
   not a dep"* test, and the tree already applies it to this exact pair in the
   opposite direction: `tasks/Q.md:524`, Q30's own `Deps`, reads *"Q1 (**Q31 is
   the consumer of the signing step**)"*. §5 step 1 makes **Q30 a consumer of
   Q22's README section** by the same test.
2. **A future wave that records §5 step 1 as an ordering fact closes a
   2-cycle.** `Q22 after Q30` (recorded today) plus `Q30 after Q22` (what §5
   step 1 would justify) is a cycle, and D141 §2 R7 established that **nothing
   in this repository checks the recorded order for cycles** — the claim
   *"(verified acyclic)"* was struck as false. The cheapest defence is to have
   neither edge and to say why in both Notes. §2 R1 and §2 R2 do that.

**The independent reason the placeholder route is refused** is D71 §2 R5,
`:480-484`, which lists the four places the key is published and their worth:

| location | different control plane? | what it is for |
| --- | --- | --- |
| `https://antseal.org/` (page footer) **+ README** | **NO** | discovery and convenience; today the only *public* one |
| **`TXT` at `antseal.org`** | **YES** (Porkbun, not GitHub) | the pin that survives a GitHub compromise |

**The README is designated a pin.** `docs/signing/verifying-a-release.md` may
carry `RW<...56 characters...>` behind its *"Not yet published"* banner
(`:10-14`) because it is a *procedure* page and is not one of the four pins. A
placeholder written into a **pin** is a pin that does not pin, and it is written
into the file D71 §2 R5's own limitation 2 already flags as unreadable to
strangers today. §2 R3 refuses it.

### 1.4 What the install section may truthfully say today: three operands, all absent

This is the half the brief warned must not be waved through, and it is worse
than the key alone. Measured unauthenticated from this host, which is what a
stranger sees:

```
https://github.com/aed900/antseal           -> 404
https://github.com/aed900/antseal/releases  -> 404
https://antseal.org/                        -> 200
```

Against D71 §2 R3's mandated human form —

```
minisign -H -Vm antseal-x86_64-unknown-linux-gnu.tar.gz \
  -P RW<...56 characters...>
```

— **every operand is fictional today**: the artifact does not exist (`README.md:17`,
*"There is no release yet"*), the `.minisig` does not exist, the key does not
exist (§1.2), and the page a reader would be sent to for all three returns
**404**. D72 §2 R6's heading says it in the record's own words: **"R5 is
INOPERATIVE while the repository is private."**

**This is `U84`'s defect class at the front door.** `TODO.md:851`: `init` tells
keyfile users to *"Run `antseal vault export`"*, and `vault export` **refuses**
their vault — *"the one command `init` names to a keyfile user is the one command
that will not run for them"*. `U85` (`TODO.md:852`) is the same shape a second
time: *"The resume hint prints a command `seal` now refuses."* A README that
prints a verification command against a key that does not exist, on a page that
404s, is the third instance, on the most-read file a public repository has.

**And D141 §2 R3 does not license it.** R3 established that the channel is
*ruled*, which answers *"must Q31 have run?"* (no). It does not answer *"may the
README instruct a reader to visit it?"* — that question is D72 §2 R6's, and R6
is live. The two are not in conflict; they are about different things, and
conflating them is how the U84 sentence gets written.

### 1.5 `OWED_PRESENCE`: three facts, one of them new and load-bearing

Registered at `scripts/check-copy-style.py:192-203`; clause patterns at
`:256-266`; enforced at `:479-519`; domain `PRESENCE_SURFACES = ("README.md",)`
at `:256`.

**(a) A registered debt reddens nothing.** Re-measured, not transcribed: at
`:494-506` a missing clause that **is** registered appends to `notices`; only an
unregistered one becomes a `Finding`. Flagless run at HEAD prints two debts and
exits **`REAL_EXIT=0`**. D141 §1.8 measured the same and reported *"20
product-copy file(s)"*; today's line reads **26 files across 8 scan roots** —
a sixth instance of this tracker's count-drift class, and it is inside the
lint's own summary, not a row.

**(b) Writing the clauses without deleting the entries turns P7 RED.** Run
against the real `check_presence()` over a scratch root — today's `README.md`
plus a paragraph stating both clauses, the register untouched:

```
README-today    : 0 FINDING(S), 2 notice(s)
README+clauses  : 2 FINDING(S), 0 notice(s)
  RED: P7 README.md OWED_PRESENCE still carries 'compelled-disclosure'
       but the clause is now STATED. Delete the entry …
  RED: P7 README.md OWED_PRESENCE still carries 'limit-exclusive-possession'
       but the clause is now STATED. Delete the entry …
```

Verified **by message**, not by exit status. The clause-writing and the register
deletion are **one act**, and D139 §1.10's E10 measured the same property from
the other side.

**(c) THE NEW FINDING — deleting the entries disarms a self-test arm.** The
faults table carries exactly two P7 red arms:

| arm | `check-copy-style.py` | survives Q22? |
| --- | --- | --- |
| *"the seal-before-you-share line deleted from README"* | `:783-788` | **yes** — with an empty register the clause is unregistered, so `:496-504` fires |
| *"a debt satisfied but not deleted from `OWED_PRESENCE`"* | `:789-799` | **NO** |

The second arm appends to `README.md` a sentence stating both owed clauses and
requires **P7** to fire (`:44-45`: *"`expect` 'red' names the rule that must
fire"*). Its red comes from the loop at `:508-518` finding those keys in
`satisfied`. **With `OWED_PRESENCE == {}` that loop has nothing to iterate.**
Run against the real function, the arm's own mutation planted verbatim:

```
TODAY  register=2, arm planted    -> P7 findings: 2  RED  (arm passes)
AFTER Q22 register=0, arm planted -> P7 findings: 0  GREEN (arm FAILS — disarmed)
```

The arm does not go quietly green; it **fails**, in
`.github/workflows/ci.yml:815` and `scripts/local-gate.sh:469-470`. So the
failure is loud — but it is a failure of the wave that discharges Q22, not a
detection of anything, and the guard at `:508-518` is left with **no live
subject and no arm**.

The replacement is *constructed*, not *derived* — the technique the P8 arm at
`:800-807` already uses on `DOCS_CLASSIFICATION`. Register a debt for a clause
`README.md` **already states**, and the staleness guard fires with no live debt
anywhere:

```
ARM A (sbys deleted, register=0)  -> P7: 1  RED (survives)
      "does not state the required 'seal-before-you-share' clause …"
ARM B (constructed stale debt)    -> P7: 1  RED (armed)
      "OWED_PRESENCE still carries 'seal-before-you-share' but the clause
       is now STATED. Delete the entry (owed by SELF-TEST PLANT…"
```

**Why this is Q252 and not a new class.** Q252's traceability arm built its
fixture by *finding* a live open decision row, and wave 22 drained the open set
to zero. This arm builds its fixture by *finding* a live registered debt, and
Q22 drains that register to zero. Same shape, different instrument, and the
memory rule already exists: **construct, don't derive.**

### 1.6 D141 §2 R4's flip predicate cannot return zero

D141 §2 R4, `:458-460`: *"the flip is permitted when `grep 'registered debt'
<(python3 scripts/check-copy-style.py)` returns **zero** lines for
`README.md`."* Measured against the real output:

```
D141 R4's predicate  (grep 'registered debt')                  -> 3
anchored             (^check-copy-style: registered debt)      -> 2
surface-scoped       (registered debt — README.md:)            -> 2
```

The third match is the **summary line** itself: `:1012` interpolates
`len(OWED_PRESENCE)` into *"clauses (P7, 2 registered debt(s) above)"*. With the
register emptied that line reads *"(P7, **0** registered debt(s) above)"* — the
phrase is still present, so the count floors at **1**. **A ruling's own stated
verification cannot reach the value it demands.** The notices are printed at
`:1005` as `check-copy-style: registered debt — …`, so anchoring at line start
separates them; §2 R6 substitutes the anchored form and states its two values.

### 1.7 What Q22 actually still owes, itemised against the tree

`tasks/Q.md:436` `Do`, clause by clause, against `README.md` (69 lines) as it
stands:

| `Do` clause | state | measurement |
| --- | --- | --- |
| one-liner (spec line 24) | **PRESENT** | `README.md:3-5` reproduces `MVP-SPEC.md:24` |
| MVP-user framing (line 25) | **ABSENT** | `grep -ci` — `researcher` 0, `creator` 0, `practices` 0, `counterpart` 0 |
| quickstart `init → seal → status → reveal → verify` | **ABSENT** | `grep -c quickstart` / `Quickstart` → 0/0; `:13-15` names the nine subcommands and no flow |
| install instructions + signature verification | **ABSENT** | `grep -c` — `install`/`Install` 0/0, `minisign` 0, `sha256` 0 |
| zero-install verifier story + canonical URL | **PARTIAL** | URL present (`:12-13`, `:30`); `grep -ci drag` 0, `zero install` 0 — the *"counterparties need zero install"* framing (spec line 26) is not there |
| possession-not-authorship | **PRESENT** | `:7` — P7 `limit-authorship` HIT on `'NOT authorship'` |
| not a legal notary | **PRESENT** | `:9` |
| seal-before-you-share | **PRESENT** | `:8` — P7 HIT |
| **not exclusive possession** | **ABSENT** | P7 `limit-exclusive-possession` MISS — registered debt 1 |
| **compelled-disclosure note** | **ABSENT** | P7 `compelled-disclosure` MISS — registered debt 2 |
| title embedded in the plaintext manifest | **ABSENT** | `grep -c title` → 0 |
| structure metadata visible to recipients | **ABSENT** | not present |
| `--no-fine-tree` = permanently whole-file-reveal only | **ABSENT** | `grep -c no-fine-tree` → 0 |
| per-unit reveal now, byte-range in v1.1 | **ABSENT** | `grep -c byte-range` 0, `v1.1` 0 |
| **Link every other doc page** | **PARTIAL** | 8 links today (six `docs/user/`, `docs/threat-model.md`, `SECURITY.md`). **The entire `docs/signing/` subtree is unlinked** — and it is Class **P**, `check-copy-style.py:160-172`, on the merits that *"verifying-a-release.md is followed by a stranger holding only a download"* |

`Accept`, `tasks/Q.md:438-441`:

| row | state |
| --- | --- |
| 1 — *"All listed sections present; Q20 lint green"* | **NOT MET**, and the second half is **vacuous as written** — the lint is green *today*, with both clauses missing, because a registered debt reddens nothing (§1.5a). It becomes load-bearing only once the register entries are deleted. |
| 2 — *"proven on a clean machine **during the Q34 gate**"* | **DEFERRED BY CONSTRUCTION.** Q34 is open, is `after Q31–Q33` and now `after Q65` (D141 §2 R2), and its clause (b) requires *"zero repo-checkout resources"*. |
| 3 — *"Canonical URL identical to CLI/page usage (**checked by Q28**)"* | **VERIFIED BY A SUCCESSOR.** Q28 (`TODO.md:816`) is open and is `after Q20–Q27`. |
| 4 — *"`--passphrase-fd` is documented as what it is"* (D72 §3.1, `:634-637`) | **NOT MET**, and **its own premise is now false**: the clause asserts *"`README.md` contains the string 'passphrase' **zero times**"*; measured today, `grep -c passphrase README.md` → **2** (`:43`, `:45`) and `grep -o … | wc -l` → **2**. Both are Q248's `## Documentation` blurbs; `grep -c -- '--passphrase-fd' README.md` → **0**, so the obligation stands while the premise does not. |

**The doc-linking clause needs a definition and the tree already supplies one.**
`find docs -name '*.md'` returns **190** files, 145 of them decision records;
*"every other doc page"* cannot mean that set. The measurable reading is the
**Class P** partition at `check-copy-style.py:73-105` / `:115-183`: `README.md`,
`SECURITY.md`, `docs/positioning-copy-style.md`, `verifier-web/`,
`docs/signing/`, `docs/user/`. Against that set the README's residue is exactly
`docs/signing/` (plus `docs/threat-model.md`, Class E but already linked by
Q248). §2 R5 fixes the clause to that set.

**Nothing validates a README markdown link.** `crates/antseal-core/tests/doc_pointer_liveness.rs`
checks **rustdoc** pointers inside the crate; `check-traceability.py`'s eight
checks are freeze-boundary, matrix, decisions, task-citations, task-entries,
decision-owners, decision-index and machine-paths. A dead `docs/signing/…` link
in `README.md` would be caught by nobody. Stated so the implementer does not
assume coverage; **no instrument is minted here** (rule 8 / D125) and §4 routes it.

### 1.8 Why Q22 cannot tick, stated as a property rather than as a schedule

Two of Q22's four `Accept` rows are verified by successors — row 2 by **Q34**,
row 3 by **Q28**. D141 §1.7 read row 2 approvingly as *"the textbook rule-7
'consumer, not a dep' case"*, and for the **Q31** edge it was right. But a
consumer relation written into the row's **own `Accept`** is not a consumer
relation at all: **the row cannot tick without the successor.** Combined with
D141 §2 R2's new `Q34 after Q65` edge and the standing `Q65 after Q22`, the
recorded order now contains a closed loop of *tickability* —

```
Q34  after Q65        (D141 §2 R2, landed)
Q65  after Q22        (TODO.md:824, standing)
Q22  ticks only after Q34   (tasks/Q.md:439, its own Accept row 2)
```

— which D141's own experiment harness reports as **zero cycles**, because that
parser reads only `after` runs (`D141 §6`, *"Known limits"*). This is D141
falsifier 7 landing on a surface it did not enumerate: not a `before` edge, but
**an `Accept` clause naming a successor gate as its verifier**.

**What saves the ship path is D141 §2 R4 and only D141 §2 R4.** Q65 does not
need Q22 to *tick*; it needs the two clauses *written*, and R4 said so in
writing with a mechanical predicate — the predicate repaired at §2 R6. The
narrowing is not bookkeeping; it is the thing that keeps M4 from being blocked
on a row that cannot close before the gate it feeds.

### 1.9 Stale premises and unexecuted rulings found on the way

- **D140 §2 R1's ruled edit never landed.** It ordered `tasks/Q.md:454` (Q24's
  `Accept` row 1) replaced with two clauses. Q24's entry today
  (`tasks/Q.md` `### Q24`) still reads, unamended: *"Both pages exist and are
  linked from README and `init` output (U)"*, and the entry carries **no
  registrar Notes at all** — while `TODO.md:812` shows the row **`- [x]` ✅
  2026-08-17**. A row ticked against an `Accept` clause its own governing record
  had ordered rewritten, with the evidence living only on the checkbox line.
  The wave-24 follow-up class (`dc0bac8`), recurring.
- **Three sites still carry D140 §1.8's premise, which D141 killed.**
  `docs/decisions/D139-…:1072`, `docs/decisions/D140-…:360` and the register
  entries quoting them assert *"`TODO.md` puts Q22 after Q30/Q31, and Q65 is a
  precondition of Q31"*. D141 §2 R1 amended D72 §2 R6 so Q65 is **not** a
  precondition of Q31, and §2 R3 struck the Q31 edge. As *narration of what D140
  ruled* these remain accurate; as *live reasoning* they are dead. Routed, not
  ruled, in §4.
- **D141 §2 R3's own instruction was executed in only one half.** It ordered
  `tasks/Q.md:434`'s `Deps` to become *"Q30 (the 56-character public key — the
  one field this row cannot write without it; the command itself is D71 §2 R3)"*.
  The registrar landed the `Q31` strike and left the annotation reading
  **"Q30 (verification instructions)"**. §2 R2 supersedes it rather than
  restoring it, because §1.3 shows the intended text is itself wrong about the
  direction.
- **D141 §2 R4's narrowing DID land** — `tasks/Q.md` Q65 `Deps` (*"NARROWED IN
  WRITING 2026-08-18 by D141 §2 R4"*) and `TODO.md:824`. Checked rather than
  assumed: a literal grep for the record's proposed wording returns nothing, and
  the narrowing is present in a different form. Verify by property, not by string.

---

## 2. Ruling

### R1 — Q22's `after Q30` is STRUCK. Q30 becomes a **consumer** annotation, per rule 7's second clause — and the reason is §1.3, not D141 §2 R3

**Authority:** `docs/signing/maintainer-key-procedure.md:167-174` §5 step 1 —
Q30's own procedure performs the `README.md` key edit, *"After §1 and alongside
§2"*. Q22 does not consume the key; Q30 inserts it. Every other operand of
Q22's install clause exists as a ruled record or a wave-24 artefact (§1.2).

**Who: the registrar.**

- `TODO.md:810` — `— after Q20,Q30 ~~,Q31~~` becomes `— after Q20 ~~,Q30~~ ~~,Q31~~`,
  with a Notes clause in substance: *"**[D150 §2 R1, 2026-08-18: the `Q30` edge
  is STRUCK.]** Q30 is a **consumer**, not a dep. Every operand of this row's
  install clause is a ruled record or a wave-24 artefact — the channel (D72 §2
  R5), the target (D72 §2 R1), the command and the expected trusted comment
  (D71 §2 R3), `SHA256SUMS` and `scripts/{sign,verify}-release.sh` — except the
  56-character public key, and **that field is not this row's to write**:
  `docs/signing/maintainer-key-procedure.md:171-172` §5 step 1 assigns it to the
  maintainer's key act, acting on this row's file. **Do not write `Q30 after
  Q22` either** — the pair would be a 2-cycle and D141 §2 R7 established that
  nothing checks."*
- `tasks/Q.md:434` — replace `Q30 (verification instructions)` with
  `~~Q30 (verification instructions)~~ — **STRUCK 2026-08-18 by D150 §2 R1**`
  plus the same substance, and **supersede D141 §2 R3's unexecuted `Deps`
  rewrite explicitly** (§1.9), naming it so a later reader does not restore it.

**Verification:** `grep -n '^- \[.\] \*\*Q22\*\*' TODO.md` shows no live `Q30`
in the ordering run, and `python3 scripts/check-traceability.py` stays green
(`task-entries`, `task-citations`).

### R2 — Q30's entry records the §5-step-1 consumer relation, and both directions are forbidden as `after:` edges

**Who: the registrar**, in `tasks/Q.md` Q30's Notes (the entry, not the checkbox
line — the wave-24 follow-up's own lesson).

Text in substance: *"**[D150 §2 R1/R2, 2026-08-18.]** §5 step 1 of
`docs/signing/maintainer-key-procedure.md` edits `README.md`, which is **Q22's**
file. That makes this row a **consumer** of Q22's install section, in the same
direction as this entry's existing *'Q31 is the consumer of the signing step'*.
**Neither direction may be written as an `after:` edge**: `Q22 after Q30` was
struck by D150 §2 R1, and `Q30 after Q22` would close a 2-cycle with it that
nothing checks (D141 §2 R7). When the key act is taken, §5 step 1 inserts the
key into the anchor D150 §2 R3 requires Q22 to leave."*

### R3 — The README carries a NAMED EMPTY ANCHOR and NO key, NO placeholder and NO verification command. This is the rule that keeps the install section honest

**The rule, stated so it can be applied without rediscovering it:**

> **A command block in product copy is a promise that it runs.** Where an
> operand of that command does not exist — an artifact, a signature, a key, a
> reachable page — the block is not written at all. The page states what does
> not exist yet, names the one route that *does* work today, and points at the
> document that owns the procedure. **A placeholder is permitted in a
> *procedure*; it is refused in a *pin*.**

**Applied, and each half is measured:**

1. **No `minisign -H -Vm …` block in `README.md` today.** Every operand is
   absent and the page it would send a reader to returns **404** (§1.4). This is
   `U84`/`U85`'s class — an instruction the reader cannot execute — at the front
   door.
2. **No `RW<...56 characters...>` in `README.md`.** D71 §2 R5 `:482` designates
   the README a **pin**. `docs/signing/verifying-a-release.md:10-14` may carry
   the placeholder because it is a procedure page and is not one of the four
   pins.
3. **A named anchor is left where §5 step 1 will write.** An HTML comment pair
   in `README.md`, exactly:
   `<!-- BEGIN minisign-public-key (docs/signing/maintainer-key-procedure.md §5 step 1) -->`
   … `<!-- END minisign-public-key -->`, with one sentence between them stating
   that no key exists yet and pointing at
   [`docs/signing/verifying-a-release.md`](../signing/verifying-a-release.md).
   The marker idiom is the tree's own: `docs/threat-model.md`'s
   `<!-- BEGIN frozen-security-assumptions -->` pair is the stable locator that
   survived Q21's growth when line numbers did not (D139 §2 R4's addendum).
4. **The install section states today's truth**: building from source is the
   only route (`README.md:17-18` already says so); the channel *will be* GitHub
   Releases (D72 §2 R5) and **is inoperative while the repository is private**
   (D72 §2 R6); the checking procedure, the key and what a green result does and
   does not mean live in `docs/signing/verifying-a-release.md`.
5. **D71 §2 R11's four prohibitions bind this section verbatim** (`:653-664`):
   not *"verified"* alone as a verdict on the software; not *"revoked"*,
   *"expired"* or *"key rollover"*, as no such mechanism exists; **not any claim
   that the key in the README is independently verifiable while it is served
   from the same origin as the binary**; and no claim of legal or notarial
   effect.

**Verification, and it is not free-form.** Candidate copy was run through the
real lint functions before this ruling was written: `check_banned`,
`check_spellings` and `check_url` returned **0 findings**, and
`PRODUCT_URL.findall()` returned **`[]`** on a body containing
`https://github.com/aed900/antseal/releases` — the pattern
(`:253`) requires an `antseal.<tld>` **host**, so a GitHub path bearing the
product name is **not** a P6 trap. The implementer re-runs flagless
`python3 scripts/check-copy-style.py` and reports its output, per D139 §2 R6.

### R4 — The two `OWED_PRESENCE` clauses land NOW, and the register deletion and the clause text are ONE act

**Who: the Q22 lane.** Add a positioning paragraph to `README.md` that states
both owed clauses, and **in the same commit** delete both entries from
`scripts/check-copy-style.py:192-203`, leaving `OWED_PRESENCE` empty.

**Both halves are mandatory and each alone is red** (§1.5b, measured by
message). **`README.md:7-9` must not be reworded** — it carries three satisfied
P7 clauses and D140/Q248 already warned that an edit there can silently lose a
green one; the paragraph is an **addition**.

**The clause wording must satisfy P7 without tripping P3**, and the two rules
pull against each other: `AUTHORSHIP` (`:229-232`) bans `exclusive possession`,
while `DISCLAIMER` (`:238-242`) makes it lawful when `not|never|no|cannot|…`
appears **in the same sentence**. Measured against the real regexes, these
forms satisfy `limit-exclusive-possession` **and** carry their own disclaimer:
`not exclusive possession`, `no exclusive possession`, `not exclusively
possessed` — with or without `**` emphasis. **`It does not prove exclusive
possession.`** does **not** match the P7 pattern (the negation must be adjacent);
this is the trap that would cost a lane a cycle. For `compelled-disclosure`, the
pattern is `compelled|forced to reveal|coerc(e|ed|ion)`.

**Verification:** flagless `python3 scripts/check-copy-style.py`; `REAL_EXIT`
read back from a file; and the anchored predicate of §2 R6 returns **0**.

### R5 — Q22's *"Link every other doc page"* means the **Class P** set, and `docs/signing/` is the residue

**Who: the registrar**, in `tasks/Q.md:436`, as a parenthetical on the clause:
*"(**scoped by D150 §2 R5 to the Class P partition** — `check-copy-style.py:73-105`
/ `:115-183`: `SECURITY.md`, `docs/positioning-copy-style.md`, `docs/signing/`,
`docs/user/`, `verifier-web/` — plus `docs/threat-model.md`, already linked. It
does **not** mean all 190 `docs/**.md`, 145 of which are decision records.)"*

**Who: the Q22 lane**, in `README.md`'s `## Documentation` section: add
`docs/signing/verifying-a-release.md` (the stranger-facing page) and
`docs/signing/README.md` (the hub for the other two). **Nothing checks that a
README link resolves** (§1.7), so the lane verifies each added path with
`test -f` and says so in its return.

### R6 — D141 §2 R4's flip predicate is CORRECTED. It could never return the value it demanded

**Who: the registrar**, at the two sites carrying the narrowing —
`tasks/Q.md` Q65's `Deps` and `TODO.md:824` — by dated addendum, not rewrite:

> **[D150 §2 R6, 2026-08-18.]** D141 §2 R4's stated predicate — *"`grep
> 'registered debt' …` returns zero lines"* — **cannot return zero**: the
> lint's summary line at `scripts/check-copy-style.py:1012` interpolates
> `len(OWED_PRESENCE)` into the phrase *"N registered debt(s) above"*, so the
> count floors at 1. Measured today: **3**. The predicate is
> **`python3 scripts/check-copy-style.py | grep -c '^check-copy-style: registered debt'`**
> — **2 today, and 0 is the value that permits the flip.**

### R7 — The disarmed self-test arm is REPLACED with a constructed one, in the same commit that empties the register

**Who: the Q22 lane** — and, per D139 §2 R6, **it is the only writer of
`scripts/check-copy-style.py` in that wave**, and touches it once.

Replace the arm at `:789-799` (*"a debt satisfied but not deleted from
`OWED_PRESENCE`"*). Its mutation appends a README sentence and depends on the
live register being non-empty; §1.5c proves it goes green — and therefore
**fails** — the moment R4 lands. The replacement **constructs** its subject, the
way the P8 arm at `:800-807` already mutates `DOCS_CLASSIFICATION`:

- **mutation**: insert `("README.md", "seal-before-you-share")` into
  `OWED_PRESENCE` at module level — a clause `README.md` **already states**;
- **expect**: `"red"`, rule **P7**;
- **label**: *"a debt registered for a clause the surface already states — the
  staleness guard, armed without a live debt"*.

Measured: with the register empty and the constructed debt inserted, P7 fires
**1** finding, *"OWED_PRESENCE still carries 'seal-before-you-share' but the
clause is now STATED"*. The surviving arm at `:783-788` is unaffected — with an
empty register a deleted clause is *unregistered*, so `:496-504` fires instead
(measured: **1** P7 finding).

**The restore obligation is not optional.** `:208-209` already records that one
arm mutates a module-level register and that the restore must cover both the
file and the register, *"or the arms after it run against a"* mutated one. The
new arm is the second such; the lane verifies the arms that follow it still pass.

**Fault-plant requirement:** prove the new arm can fail, by removing the
`:508-518` staleness loop and observing the arm go green — verified **by the
arm's own message**, never by a nonzero exit.

### R8 — Q22's `Accept` rows 1 and 4 are AMENDED. One is vacuous; the other's premise is false

**Who: the registrar**, in `tasks/Q.md:438` and `:441`.

**(a) Row 1** — `All listed sections present; Q20 lint green` becomes:

> All listed sections present; **`scripts/check-copy-style.py` green with
> `OWED_PRESENCE` EMPTY** *(amended 2026-08-18 by D150 §2 R8 — "Q20 lint green"
> alone is an assertion that cannot fail: the lint is green **today**, with both
> required clauses missing, because a registered debt prints a notice and exits
> 0. The load-bearing predicate is D150 §2 R6's anchored grep returning **0**.)*

**(b) Row 4** — leave the obligation and **strike its false premise by dated
addendum**: the clause asserts *"`README.md` contains the string 'passphrase'
**zero times**"*; measured 2026-08-18, `grep -c passphrase README.md` → **2**
(`:43`, `:45`, both Q248's `## Documentation` blurbs), while
`grep -c -- '--passphrase-fd' README.md` → **0**. The D72 §3.1 obligation is
unchanged; the count that motivated it is not.

### R9 — This document cannot land alone, and it carries an `**Owner:**` assignment

**Who: the orchestrator.** Creating this file puts `check-traceability.py` red
until three things land in the same act:

1. **`docs/decisions/README.md`** gains a `| [D150](D150-q22-release-docs-preconditions.md) | … | RESOLVED | 2026-08-18 |`
   row in ascending id order. `check_decision_index` takes the glob
   `docs/decisions/D*.md` as its domain; today it reads **143 index rows against
   143 records**.
2. **`TODO.md`'s decision register** gains a `- [x] **D150**` row, in the shape
   of `:1038` (D149).
3. **Q22's `TODO.md` row must name `D150`.** This record writes the
   `**Owner: Q22**` form that D113 RULING 2 mandates, and
   `check_decision_owners` (`scripts/check-traceability.py:1524-1531`) fails a
   resolved decision whose owner's row *"never names D<number>"*. That is a
   third required edit, and it is deliberate: it is what stops a resolved ruling
   outliving its owner's closure unexecuted.

**Measured, not predicted — and the red arrives in TWO STAGES, which is the part
a registrar can be caught by.** Flagless `python3 scripts/check-traceability.py`
was **green at HEAD before this file was written** — eight checks, `REAL_EXIT=0`,
*"143 index row(s) against 143 record(s)"*. Re-run with only this file added, it
fails **by message** with exactly **one** problem:

```
::error::check-traceability [decision-index] docs/decisions/README.md: D150 has a
  record (D150-q22-release-docs-preconditions.md) and no row in the index. …
check-traceability: FAILED with 1 problem(s).              REAL_EXIT=1
```

The other seven stay green — **including `decision-owners`, which still reports
the same 3 assignments it reported before this file existed.** That is not the
check passing this record; it is the check **not yet seeing it**.
`allocated_decision_ids()` (`:729-731`) reads the ids out of **`TODO.md`'s
register**, and `check_decision_owners` skips any decision not in that set
(`:1513-1514`, *"an unresolved decision has assigned nothing yet"*). So the
`**Owner: Q22**` assignment is **dormant until edit 4 of §5 lands**, and the
moment it does, `decision-owners` starts demanding that `TODO.md:810` name
`D150`. **A registrar who lands the index row and the register row and stops
will get a red on the third edit, not on the first two.** Land all three in one
act.

**Owner: Q22**

---

## 3. What was refused and why

1. **"The `Q30` edge falls by D141 §2 R3's reasoning" — refused as a
   mechanism, though its conclusion survives.** R3's test is *does the
   successor produce a **record** this row merely quotes?* Applied to Q30 it
   returns **no** for the one operand that matters, and **D141 itself ran the
   test and wrote the answer down** (`:231-233`, *"the one field Q22 genuinely
   cannot write before Q30 … this record leaves the `Q30` edge exactly as it
   is"*). The edge falls on §1.3's finding — §5 step 1 makes Q30 the consumer —
   which D141 did not have, because
   `docs/signing/maintainer-key-procedure.md` was written by a parallel lane in
   the same wave.
2. **Keeping the `Q30` edge as recorded — refused.** It would block Q22 behind
   an **interactive maintainer act**: `minisign -G` prompts, `minisign` is not
   installed here, and `maintainer-key-procedure.md:228-229` records §1/§2/§3 as
   not run. No agent may take it (it is the project's long-lived signing key),
   and no row says so. Leaving the edge would park the head of the M4 ship path
   behind an act with no row and no owner-visible marker.
3. **Printing D71 §2 R3's command in `README.md` behind a "not yet published"
   banner — refused**, although `docs/signing/verifying-a-release.md:10-14` does
   exactly that and is green. The difference is measured, not aesthetic: D71 §2
   R5 `:482` designates **the README a pin**, and a placeholder in a pin is a
   pin that does not pin. The procedure page is not one of the four pins.
4. **Naming GitHub Releases as a place a reader may go today — refused.**
   Measured unauthenticated from this host: `https://github.com/aed900/antseal`
   and `/releases` both return **404**, and D72 §2 R6's own heading reads *"R5
   is INOPERATIVE while the repository is private."* The README may say what the
   channel **will be**; it may not issue an instruction whose target 404s. That
   is `U84`'s class, twice already in this tracker.
5. **Splitting Q22 — refused, again, and the refusal is D141 §2 R4's, not
   re-derived.** A split does not solve the ordering problem it is proposed for
   (two Q65→Q31 paths, Q22 on both, the second via `Q28 after Q22`), and it
   would mint a third row owning `README.md` after Q248 and Q22. The narrowing
   already landed at both sites; what it needed was a working predicate (§2 R6),
   not a row.
6. **Ticking Q22 this wave — refused on Q22's own `Accept`.** Rows 2 and 3 are
   verified by **Q34** and **Q28**, both open. The tree's own precedent is one
   row away: **Q30** is *"BUILT AND PROVEN"* and still `- [ ]`, because its
   `Accept` rows are partly unmet. Ticking Q22 would be a status claim its
   Accept contradicts.
7. **Minting an acyclicity checker, a README link checker, or a lint for the
   *"instruction a reader cannot execute"* class — all refused** under rule 8 /
   D125. Their subject is the apparatus; none blocks a ship-path acceptance;
   D141 §2 R7 refused the first of them eight hours ago on the same grounds. The
   findings and the measurements go to the ledger (§5) so a future instrument
   wave starts from working evidence.
8. **Rewriting D139 §1.8 / D140 §1.8 / D140 §2 R1's dead premise — refused as
   out of scope and as the wrong repair.** Those passages are accurate
   *narration of what was ruled*; the project's discipline is amendment by dated
   addendum at the site, and the site here is a **different record's** §1. §4
   routes it; this lane does not edit another record's measurement section.
9. **Deleting the `OWED_PRESENCE` entries without writing the clauses, or
   writing the clauses without deleting the entries — both refused as red.**
   Measured, by message, in both directions (§1.5b). They are one act.
10. **Asserting anything about how GitHub renders a private repository's README
    to a logged-in maintainer — refused as unmeasured.** Establishing it needs
    an authenticated read this lane will not perform, and no ruling here depends
    on the answer: the 404s in §1.4 are what a **stranger** gets, and the
    stranger is who the install section is written for.

---

## 4. Residue

1. **Q22 is not tickable this wave and will not be tickable until Q28 and Q34
   close.** This record does not shorten that; it makes the reason visible and
   moves the ship-path obligation onto the predicate that can actually be met
   (§2 R6). Whether Q22's `Accept` rows 2 and 3 should be restructured so the row
   can close before its own gate is **a real question this record does not
   answer** — it would touch Q28's and Q34's clauses too, and it is a planning
   subject, not a registrar edit.
2. **The 56-character key, the `TXT` pin and the OTS anchor remain untaken
   maintainer acts** with no row that names them as *maintainer-only and
   externally actioned*. Q30's row records them in prose; D71 §2 R5 `:494-496`
   puts the registrar act in *"Q33's class of externally-actioned rows"*. Whether
   the key act deserves its own marker on `TODO.md:818` is named here and left
   to the registrar.
3. **`README.md`'s anchor is unverified by any instrument.** §2 R3 requires a
   marker pair; nothing asserts it is still there when §5 step 1 comes to write
   into it. The `docs/threat-model.md` precedent has the same shape and is
   verified by a drift test; this one is not, and no test is minted (§3.7).
4. **The three sites carrying D140 §1.8's dead premise** (§1.9) are left
   standing, flagged, unrepaired.
5. **D140 §2 R1's unexecuted edit to Q24's `Accept`** is left to the registrar;
   Q24 is closed, so this is a record correction, not a reopening.
6. **`--passphrase-fd`'s user-facing sentence is still homeless in practice.**
   R8(b) keeps the obligation on Q22, but Q22 cannot tick — so the sentence can
   *land* this wave inside the README work without the row closing. Named so it
   is not mistaken for discharged.
7. **The `Do` bullets about `--no-fine-tree` and byte-range reveal were not
   re-verified against the code in this lane.** `U82`/**D149** changed
   `--split` × `--no-fine-tree` into a hard refusal on 2026-08-18, which may
   change what the README must say about that flag. **The Q22 lane must
   re-measure both bullets against D149 before writing them** — writing a stale
   product claim into the front door is the precise failure this record exists to
   prevent, and this lane did not do that measurement.

---

## 5. Registrar's edit set

Quotable instructions with their targets. Items marked **(lane)** are the Q22
implementing lane's, not the registrar's, and are listed so the registrar can
check them off.

**`TODO.md`**

1. `TODO.md:810` (Q22's checkbox line) — change the ordering run from
   `— after Q20,Q30 ~~,Q31~~` to `— after Q20 ~~,Q30~~ ~~,Q31~~`, and append the
   §2 R1 Notes clause, which must name D150, the consumer relation, and the
   prohibition on writing the reverse edge.
2. `TODO.md:810` — the row **must contain the string `D150`** (§2 R9 item 3);
   step 1's clause satisfies this. **This is not optional and its red is
   delayed**: `decision-owners` cannot see this record's `**Owner: Q22**`
   assignment until edit 4 lands, then requires this string. Edits 1, 4 and 11
   are one act.
3. `TODO.md:824` (Q65's row) — append §2 R6's dated addendum correcting the flip
   predicate to `grep -c '^check-copy-style: registered debt'`, **2 today, 0
   permits the flip**.
4. `TODO.md`'s decision register, after `:1038` (D149) — add
   `- [x] **D150** *(minted 2026-08-18, up-front — Q22 heads the M4 ship path and its two remaining preconditions were an edge nobody had re-tested and an install section nobody had priced)* Q22 — …`
   in the shape of the D149 row.

**`tasks/Q.md`**

5. `:434` (Q22 `Deps`) — strike `Q30 (verification instructions)` per §2 R1,
   with the consumer substance, and **record explicitly that D141 §2 R3's
   proposed replacement annotation is superseded, not restored** (§1.9).
6. `:436` (Q22 `Do`) — add §2 R5's parenthetical scoping *"Link every other doc
   page"* to the Class P partition.
7. `:438` (Q22 `Accept` row 1) — replace with §2 R8(a)'s text.
8. `:441` (Q22 `Accept` row 4) — append §2 R8(b)'s dated addendum striking the
   *"zero times"* premise; the obligation stands.
9. Q30's entry Notes — add §2 R2's consumer paragraph. **In the entry, not on the
   checkbox line.**
10. Q65's `Deps` — append §2 R6's addendum, mirroring TODO edit 3.

**`docs/decisions/README.md`**

11. Add, in ascending id order after the D149 row (`:167`):
    `| [D150](D150-q22-release-docs-preconditions.md) | Q22 — … | RESOLVED | 2026-08-18 |`.
    The summary must carry the three findings a later reader needs: the `Q30`
    edge falls **on §5 step 1, not on D141 §2 R3**; the self-test arm that Q22's
    own completion disarms; and D141 §2 R4's predicate that could never return
    zero.

**`docs/instrument-ledger.md`** (no id, routed per rule 8)

12. **`check-copy-style.py:789-799`'s P7 arm derives its red from the live
    `OWED_PRESENCE` register and is disarmed by Q22's completion.** Q252's class
    in a second instrument. Measured 2→0 P7 findings with the register emptied;
    the constructed replacement is measured at 1. Pointer: D150 §1.5c, §2 R7.
13. **D141 §2 R4's flip predicate cannot return the value it demands** — the
    lint's summary line contains the phrase it greps for; 3 today, floor of 1.
    Pointer: D150 §1.6, §2 R6.
14. **No instrument validates a markdown link in `README.md`.**
    `doc_pointer_liveness.rs` is rustdoc-only; `check-traceability.py`'s eight
    checks do not include one. Pointer: D150 §1.7.
15. **`check-copy-style.py`'s corpus figure has drifted again**: the summary
    reads **26 product-copy files across 8 scan roots** against D141 §1.8's
    **20** and Q20's recorded **14 across 5**. Sixth instance of the count-drift
    class; the figure has no mechanical reader.
16. **D141's cycle parser is blind to an `Accept` clause that names a successor
    gate as its verifier** — Q22 rows 2 and 3 make the row untickable before Q34
    and Q28, and the `after`-only graph reports zero cycles. Falsifier 7's
    surface, instantiated. Pointer: D150 §1.8.

**To the registrar as row amendments (no new id)**

17. **D140 §2 R1's ruled edit to Q24's `Accept` row 1 was never executed**, and
    Q24 is ticked with **no registrar Notes on its entry at all**. Land the
    amendment as a dated addendum on the closed row, or record that it was
    deliberately dropped. Pointer: D150 §1.9.
18. **Three sites carry D140 §1.8's premise, which D141 §2 R1/R3 killed** —
    `docs/decisions/D139-…:1072`, `docs/decisions/D140-…:360`, and the D140
    index row at `docs/decisions/README.md:158`. Accurate as narration, dead as
    reasoning. A one-line dated addendum at each, or a recorded decision not to.

**(lane) — the Q22 implementing lane, in one commit**

19. `README.md` — the positioning paragraph stating **both** owed clauses
    (§2 R4), as an **addition**; `:7-9` untouched.
20. `scripts/check-copy-style.py` — delete both `OWED_PRESENCE` entries
    (`:192-203`) **and** replace the `:789-799` self-test arm (§2 R7), with the
    planted fault proving the new arm can fail. **This lane is the only writer
    of that file in its wave** (D139 §2 R6).
21. `README.md` — the install section per §2 R3: no command block, no
    placeholder key, the named anchor pair, today's truth about the channel, and
    a pointer to `docs/signing/verifying-a-release.md`.
22. `README.md` — `docs/signing/` links added to `## Documentation` (§2 R5),
    each verified with `test -f`.
23. Report the flagless output of `python3 scripts/check-copy-style.py` with
    `REAL_EXIT` read back from a file, and the anchored predicate's value
    (**must be 0**).

---

## 6. What must be re-measured before this record is trusted again

1. **R1 falls** if the key act is ever ruled to be Q22's rather than §5 step
   1's — e.g. if `maintainer-key-procedure.md` §5 is rewritten to hand the
   README edit back to the docs row. Then `Q22 after Q30` is a real edge again,
   and §1.3's 2-cycle warning becomes the live constraint instead of a
   hypothetical.
2. **R3 falls, in the direction of *more* being writable**, the moment the
   repository is public **and** a release exists: the 404s become 200s, the
   channel becomes operative (D72 §2 R6), and the full D71 §2 R3 block belongs in
   the README with the real key. The anchor pair is what makes that a one-place
   edit.
3. **R7's replacement arm goes stale** if `PRESENCE_CLAUSES` ever loses
   `seal-before-you-share`, or if `README.md` stops stating it — at which point
   the constructed debt becomes a *live* debt and the arm silently changes
   meaning. Pick the clause the surface states most durably, and re-check it
   whenever `PRESENCE_CLAUSES` changes.
4. **§1.7's Class P scoping falls** if `COPY_SCAN` gains or loses a directory
   entry. It is read from the register rather than restated, which is why §2 R5
   cites `:73-105` / `:115-183` instead of listing paths in prose — but a
   reader who copies the list into a row will have restated it anyway.
5. **The whole of §1.4 is time-sensitive.** The three HTTP measurements were
   taken 2026-08-18 from this host, unauthenticated. Q65's flip changes two of
   them in a single act, and the flip is consented in principle and not taken.
