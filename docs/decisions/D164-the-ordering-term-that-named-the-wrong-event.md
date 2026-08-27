# D164 — the ordering term names the wrong event: `before the repository goes public` is neither a precondition of the flip nor co-timed with it, `Q238` is **SPLIT** with the lane half available today and the arming half bound to *a hosted run reporting the context green on `main`* — and the one sentence four surfaces rest on names no mechanism, in the file that prescribes an admin bypass

- **Status: RESOLVED. The wave's own hypothesis DIES on all three of its
  components, and the answer to the question as asked is NEITHER.**
  The hypothesis handed to the planning round was: *"(i) the headline is the
  mis-stated half and should be amended; (ii) the promotion is impossible
  pre-flip; (iii) therefore rule it JOINT WITH THE FLIP."*
  - **(ii) is REFUTED BY THE VERY BLOCK IT CITES.** `docs/ci-verification.md`'s
    C2, in the same paragraph the hypothesis quotes, says *"the flip is **not**
    what unblocks protection, and taking it for that reason would be taking it
    for a stale reason"*. Privacy is not the blocker and never was. §1.2.
  - **(iii) is REFUTED BY THE RUNBOOK'S OWN DEFINITION.** AT THE FLIP (co-timed)
    means *"Cannot be done earlier — **the API refuses it while the repository is
    private**"*. **No refusal has ever been measured**: `rulesets` → `200 []`,
    `branches/main/protection` → `404 "Branch not protected"` (an absence, not a
    refusal), and whether a `PUT` succeeds today is recorded **untested**
    (`TODO.md:91`). The burden is on the co-timed reading and it is unmet — and
    C2 forbids the act outright in this sitting. §1.2.
  - **(i) survives ONLY as a SPLIT, and both reasons the hypothesis gave for it
    are wrong.** If the refusal is an **account-level billing block**, clearing
    it is an account action available **today, pre-flip** — which makes the
    maintainer's deadline achievable exactly as written and makes the hypothesis
    argue against itself. And *"the invitation happens at the flip"* is falsified
    by the register: **A6** records the page *"already live and public"* while
    this repository is private, and **D135 §3 R5** rules the claim comes into
    existence for a third party *"at deploy time and at no other moment"*. The
    flip does not create the claim; it creates the ability to **check** it. §1.2.
  - **THE SHARPEST FINDING IS NOT THE ORDERING. The support under BOTH readings
    is UNSOUND.** C2's *"blocks the next push, including the maintainer's own"*
    names **no mechanism**, and sits in the file that prescribes
    `"enforce_admins": false` (`docs/ci-verification.md:277`) and spells out at
    `:292-294` that it *"leaves the repo admin an explicit bypass"*. Classic
    protection with that flag does **not** block an admin push; a **ruleset** has
    no implicit admin bypass; the register never distinguishes the two. That one
    unqualified sentence is load-bearing under **four** surfaces — D163 §1.6,
    D163 §2 R4, Maintainer actions entry **(8)**, and `Q238`'s replaced `Accept`
    row 3. *"Arming early is actively unsafe"* is therefore **UNPROVEN** — which
    removes the reason to defer **without supplying a reason to hurry**. §1.3.
  - **A DEFECT BIGGER THAN THE ORDERING: `Do` and `Accept` row 3 do not
    compose.** `Do` mandates a `paths:` filter on `push`; `Accept` row 3 mandates
    a required status context. A filtered-out workflow reports nothing, and a
    never-reported required context holds the gate **pending**. Three shapes
    measured, exactly one passes — the `cross-os-macos`/`cross-os-windows`
    precedent — and the lane is **explicitly permitted to return the question**
    rather than build an unarmable lane. §1.4, §2 R6.
  - **The two checkpoints the row names do not carry it.** `Q34`'s ordering run
    (`TODO.md:876`) has no `Q238`; `Q65`'s row (`:879`) has none; the M4
    `Gate =` line (`:861`) names five clauses and **none** is `Q238`. The
    `Notes`' *"`Q34` … and `Q65` … are where it must be checked"* is an
    assertion **nothing can redden**. §1.5, §2 R8.
- **Date: 2026-08-27**
- Owner rows: **`Q238`** (split, lane half kept, lane-available today) and
  **`Q265`** (minted, arming half, maintainer-only). This record **ticks
  nothing** and **authorises nothing**.
- Related: **D163 §3** (which explicitly refused to rule this and named it *"a
  genuine ordering contradiction on a live M4 row [that] needs its own
  decision"*); **D163 §2 R6/R7** (the SPLIT precedent and its clause-allocation
  discipline); **D163 §2 R9** (which replaced `Accept` row 3 and left the third
  timing word behind); **D163 §1.6** (the measured *flip → free runners → one
  green run → required contexts* sequence, whose last two steps this record
  re-cuts); **D163 §1.8** (name a block by its heading, never by its line
  number); **D162 §2 R4/R5/R11** (no edit root assigned to nobody; row-id +
  quoted-string locators; *resolved is not executed*); **D156 §2 R8** (a
  `before` deadline is not an `after` edge); **D161 §2 R7** (*no required status
  context may be added on the strength of an expectation*); **D135 §1.1** (the
  measured Actions bill) and **D135 §3 R1/R5** (deploy-gated, and when the claim
  comes into existence); **D141 §2 R8** (the 403s are gone); **D125 / rule 8**
  (why §2 R9 mints no instrument).

---

## 0. What was measured against

Read in full before anything was written: `tasks/Q.md`'s `### Q238` entry
(`Do`, `Deps`, every `Accept` row, every `Notes` block); `TODO.md`'s rows
`Q34`, `Q65`, `Q238`, the M4 `Gate =` line, `## Current focus` and the
**Maintainer actions** block; `docs/ci-verification.md`'s ordering-vocabulary
table and its `A6`, `A8`, `B1`, `B5`, `B6`, `C2`, `C4` steps plus the wave-7
maintainer runbook at `:214-224` and the branch-protection payload at
`:270-300`; `scripts/check-ci-paths.py`'s `REQUIRED_CONTEXTS` / `PUSH_EXEMPT`
block; `.github/workflows/ci-always.yml`'s header; `CONTRIBUTING.md` entire;
`docs/decisions/D163-clause-wise-after-and-the-missing-split.md` §1.5–§1.8, §2
R2–R4, §2 R9 and §3; `docs/decisions/D162-the-with-chain-that-could-not-start.md`
§2 R4/R5/R11.

Measured at source on **2026-08-27** on this host by `grep`, `sed`, `awk` and
`python3`. **No network command was run, no GitHub API call of any kind was
made, no build was started, and neither `scripts/local-gate.sh` nor
`scripts/check-traceability.py --self-test` nor `scripts/check-copy-style.py
--self-test` was invoked.** Every exit status quoted below was read back out of
a file. The one script run to completion is `scripts/check-traceability.py`
**flagless** — that run *is* the check, it completes in seconds, and it is the
only mode of it safe mid-wave.

**Shared-tree disclosure, and it is load-bearing (§4 and §5.2).** Wave 31 runs
parallel lanes in one working tree. Between the planning round that produced
this ruling and the writing of this record, the **ORCH** and **REG** lanes began
landing §4's edits. Where a baseline below has already moved, both numbers are
given with the time they were read, and no baseline is quoted from the planning
round without saying so. **Line numbers in the planning round had already
drifted before a lane read them** — the same defect D162 §2 R5 ruled on — so
every locator in this record is **row id or heading plus a quoted string**, with
the line number as a convenience measured today. If the string is not at the
line, trust the string.

---

## 1. What was measured

### 1.1 `Q238` states its own timing on five surfaces, in three different words

Read at `HEAD` (`3922ada`), before any wave-31 lane touched the row:

| surface | the words it uses | timing it asserts |
| --- | --- | --- |
| `tasks/Q.md` `### Q238` headline | *"Promote the two-environment reproducibility comparison to a required push context **before the repository goes public**"* | **BEFORE the flip** |
| `tasks/Q.md` `Deps:` run | *"**Blocks nothing at M3**; it is a **precondition of making the repository public**, which is why it is M4 and not Continuous."* | **BEFORE the flip**, restated as a *precondition* |
| `tasks/Q.md` `Accept` row 3, as **replaced 2026-08-22 by D163 §2 R9** | *"The measured sequence (D163 §1.6) is: flip → free runners → **one green run on `main`** → required contexts → ship. So the **joint dependence** on `Q65` is real but for a different reason than recorded"* | **AFTER the flip**, called *joint* |
| `tasks/Q.md` `Notes:` | *"**the trigger is publication, not a date** … **Q34** (the M4 gate) and **Q65** (publish scope and the pre-public scrub) are **where it must be checked**"* | checked at **two other rows** |
| `TODO.md:880` ordering run | `— after R86, D135 §3 R6 + §10 R2, Q1; joint with **Q65** … and checked at **Q34**` | **joint**, and checked at a third place |

Three different timing words for one obligation, and D163 §3 named the shape
without ruling on it: *"two different timing words for one obligation, the same
shape as `Q35` … a genuine ordering contradiction on a live M4 row and it needs
its own decision."* D163 §2 R6's diagnosis of `Q35` applies verbatim here: this
is a **missing split, not a mis-typed word**.

The three obligations the row actually carries are:
**(a)** build the filtered lane; **(b)** re-measure the bill; **(c)** arm the
required context. **(a) and (b) are agent-takeable with no network today.
(c) is a GitHub API write no agent may take.** No single ordering word is true
of all three, which is exactly why the row has three.

### 1.2 The hypothesis dies: two components are refuted by the documents they cite, and the third survives only in the form it denies

The hypothesis put to the planning round, in the brief's own words, was
*"(i) the headline is the mis-stated half and should be amended; (ii) the
promotion is impossible pre-flip; (iii) therefore rule it JOINT WITH THE FLIP"*.

**(ii) — REFUTED AT SOURCE, by the block the hypothesis quotes.**
`docs/ci-verification.md`'s **C2** (`### C2 — AFTER. Branch protection is now
available, and must still not be armed`, today `:3814`) reads, at `:3829`:

> the 403s that chapter recorded are gone — GitHub un-gated rulesets for private
> Free repositories — so the flip is **not** what unblocks protection, and
> taking it for that reason would be taking it for a stale reason.

Privacy is not the blocker and never was. The blocker is that **no context has a
recent green**, which is an Actions-billing state, not a visibility state.

**(iii) — REFUTED BY THE RUNBOOK'S OWN DEFINITION.** The ordering-vocabulary
table (today `docs/ci-verification.md:2907-2913`) defines the co-timed marker as:

> | **AT THE FLIP (co-timed)** | Cannot be done earlier — **the API refuses it
> while the repository is private** — and must not be left for later. Same
> sitting, same hour, one continuous act. |

and closes with **"A co-timed step is not a prerequisite and must never be
written as one."** The definition's condition is a **measured API refusal**, and
**no refusal has ever been measured**. What is on the record (D141 §2 R8, quoted
into D163 §1.6) is `rulesets` → `200 []` and `branches/main/protection` →
`404 "Branch not protected"` — a `200` and an **absence**, neither of them a
refusal — and `TODO.md:91`'s own words for the write: *"Whether a `PUT` now
succeeds is **untested**."* The burden of proof sits on the co-timed reading and
it is **unmet**. C2 then forbids the act outright in the same block:

> **Do not add a required status context in this sitting.**

Ruling *joint with the flip* would write into `Q238` precisely the defect the
ordering-vocabulary section exists to prevent.

**(i) — survives ONLY as a SPLIT, and the hypothesis's two reasons for amending
are each wrong.**

- **Its own material fact cuts the other way.** If the CI refusal is an
  **account-level billing block**, then clearing it is an **account action
  available today, pre-flip**. That makes *"before the repository goes public"*
  achievable **exactly as the maintainer asked** — so the hypothesis's premise
  argues against the hypothesis's conclusion.
- **"The invitation happens at the flip" is falsified by the register's own
  measurements.** `docs/ci-verification.md`'s **A6** (`:3158`) records the page
  is *"**already live and public** at `https://antseal.org/` while this
  repository is private"*, and **D135 §3 R5** rules the provenance claim
  *"come[s] into existence for a third party **at deploy time** and at no other
  moment"*, its residue *"**late discovery**"* and *"**not** a false published
  claim"*. The flip does not create the claim. **It creates the ability to
  check it** — which is a different thing and orders differently.

**On the brief's counter-argument that `B5` discharges the row.** It does not.
`Q238`'s `Problem` never mentions forks; its actor is the maintainer's own
pushes. `B5` (`### B5 — AT THE FLIP, co-timed. Fork-PR contributor approval`,
today `:3675`) sets `approval_policy=all_external_contributors`, which gates
whether **workflows run** on a fork PR — not what may be **merged**. If
anything it cuts *against* the required-context mechanism: an unapproved fork
PR's checks never report, which is precisely the never-reported state §1.4 is
about. And the fork path is not one this project has opened:

```
$ wc -l CONTRIBUTING.md                                   → 357
$ grep -cEi 'pull request|fork|merge' CONTRIBUTING.md      → 0
```

**Net:** the flip is neither necessary nor sufficient for either half of this
obligation. **The ordering term names the wrong event.** That is the finding.

### 1.3 The sharpest finding: the support under BOTH readings is unsound, and it is one unqualified sentence standing under four surfaces

C2's operative sentence, in full:

> **Do not add a required status context in this sitting.** A required context
> that has never reported green on `main` **blocks the next push, including the
> maintainer's own** — and the hosted CI has refused every job since wave 20 on
> an exhausted Actions allowance, so *no* context has a recent green.

**It names no mechanism.** Measured in the same file:

```
$ grep -n 'enforce_admins' docs/ci-verification.md
277:     "enforce_admins": false,
294:     workflow becomes PR-first. `"enforce_admins": false` (chosen here)
402:  "enforce_admins": false,
532:  "enforce_admins": false,
738:  "enforce_admins": false,
1216:`"enforce_admins": false` leaves the admin a bypass regardless. What it *would*
1245:  "enforce_admins": false, "required_pull_request_reviews": null,
                                                        (7 occurrences today)
```

and the consequence stated in the register's own words at `:292-294`:

> - With required status checks, **direct pushes to `main` are rejected**
>   unless the pushed SHA already carries green required checks — the workflow
>   becomes PR-first. `"enforce_admins": false` (chosen here) **leaves the repo
>   admin an explicit bypass** for emergencies while the project is
>   single-maintainer

So the file that says the arming *blocks the maintainer's own push* is the same
file that prescribes, in its own payload, the flag that **gives the maintainer a
bypass**. The two are reconcilable only by naming which mechanism is meant:
**classic branch protection with `"enforce_admins": false` does not block an
admin push; a ruleset has no implicit admin bypass.** The register never
distinguishes them anywhere.

**The same unqualified claim appears again**, in the wave-7 maintainer runbook
at `:218-221`, still with no mechanism named:

> Ordering is normative. **Do not apply branch protection (step 5) before step 3
> shows all thirteen lanes green on `main`** — required contexts that have never
> reported **would block every push/merge to `main`, including the pending
> backlog**.

**Four surfaces rest on that one sentence**, and none of them re-derives it:

| surface | what it takes from the sentence |
| --- | --- |
| **D163 §1.6** | quotes it verbatim as *"the sentence that decides this record"* |
| **D163 §2 R4** | routes `Q1`'s residue with the deadline *after `Q65` + one green run on `main`* on its strength |
| **Maintainer actions entry (8)** (`TODO.md`, named by heading) | *"`Q1`'s branch-protection clause — ADDED 2026-08-22 by D163 §2 R4, and **NOT TAKEABLE IN THIS SITTING**"* |
| **`Q238`'s `Accept` row 3**, as replaced by D163 §2 R9 | *"`docs/ci-verification.md` C2 warns a never-green required context…"* |

**Therefore *"arming early is actively unsafe"* is UNPROVEN — not false.** This
record does not assert the opposite either; it records that the claim is
unqualified and that qualifying it is E3c's job. The consequence for the ruling
is precise and limited: **it removes the reason to defer the obligation past the
flip, without supplying a reason to pull it forward.** Both directions lose
their support at once, which is why §2 R2 strikes the flip as the event this
obligation is ordered against rather than moving the obligation to the other
side of it.

### 1.4 `Do` and `Accept` row 3 do not compose, and exactly one of three shapes survives the tree

`Do`'s mandate: *"a **separate workflow** with a workflow-level
`on: push: paths:` filter, which GitHub evaluates **before any runner is
assigned**, so a push touching no build input costs zero minutes."*
`Accept` row 3's mandate: *"The promoted job is a **required status context** on
`main`."*

**A filtered-out workflow reports nothing, and a required context that never
reports holds the gate pending.** The two mandates are in direct tension on one
concrete case — a docs-only direct push to `main`. Three candidate shapes,
each measured against this tree:

| shape | verdict, measured |
| --- | --- |
| filter **both** `push` and `pull_request` | **refused by the tree** — `scripts/check-ci-paths.py` flagless asserts *"19 required contexts are each produced exactly once on `pull_request`"*; this shape breaks that invariant |
| twin workflows with complementary filters (GitHub's own documented workaround) | **refused in-repo** — `.github/workflows/ci-always.yml:26-30` records that GitHub's two filters *"both quantify **EXISTENTIALLY** over the changed set"*, so a mixed push fires both and *"every shared context is produced twice. `scripts/check-ci-paths.py` **R3 fails on a duplicated context**"* |
| filter `push` **only**, leave `pull_request` unfiltered, register the name in `REQUIRED_CONTEXTS` **and** in `PUSH_EXEMPT` | **passes** — this is the `cross-os-macos` / `cross-os-windows` precedent verbatim, whose stated safety condition is `check-ci-paths.py:160`: *"still produced on `pull_request`, which is what keeps them **safe to require**."* |

So **the shape exists**. What does **not** exist is a decision on the **arming
mechanism** — and §1.3 shows the two mechanisms behave differently on precisely
the case this shape creates. The lane cannot be built to a specification that
has not chosen between them, which is why §2 R6 permits the lane to **return the
question**.

Supporting measurements, both read today:

```
$ python3 scripts/check-ci-paths.py            → REAL_EXIT=0
  "19 required contexts are each produced exactly once on pull_request"
$ python3 scripts/check-ci-paths.py --self-test → PASS, REAL_EXIT=0
```

`check-ci-paths.py --self-test` is **pure in-memory** — no `copytree`, no
`mkdtemp`, no `TemporaryDirectory`, no `subprocess` — **unlike**
`check-traceability.py --self-test`, which stages a full tree copy and stays
banned mid-wave. It is therefore safe to run mid-wave and §2 R9's new arm lands
in it. The flagless run above was taken while a concurrent lane held
`scripts/check-ci-paths.py` modified; §5.2 records that and what it does and does
not license.

### 1.5 The two checkpoints the row names do not carry it, and nothing can redden that

`Notes` says *"**Q34** (the M4 gate) and **Q65** (publish scope and the
pre-public scrub) are **where it must be checked**"*. Measured at `HEAD`:

```
$ TODO.md:876  Q34's ordering run  → "after Q13,Q21,Q28,Q31–Q33,**Q65**"      no Q238
$ TODO.md:879  Q65's row           →  ordering run carries no Q238            no Q238
$ TODO.md:861  the M4 `Gate =` line → five clauses, and none is Q238
```

The `Gate =` line in full, so the count is not a subtraction the reader has to
perform:

> Gate = **Q34 evidence bundle**: Sepolia-mode E2E green; exactly ONE mainnet
> smoke seal verified end-to-end from a clean machine using only the released
> signature-checked binary + hosted page; disk-loss restore drill passed;
> release published with mainnet default; traceability matrix 100 % green.

Five clauses, `Q238` in none of them. **The `Notes` sentence is an assertion
nothing can redden** — the register-level instance of this project's dominant
defect class — and because rule 4 makes the **gate**, not the row count, the
exit criterion, **M4 could pass its gate with this row open and no instrument
would notice**. §2 R8 lands the check where a human actually reads it.

### 1.6 The billing premise is wrong in both directions, and the record must assert neither

C4 (`### C4 — AFTER. The first CI run that a hosted runner actually executes`,
today `:3867`) opens with:

> **Free minutes on public repositories is the mechanism that ends the refusal
> streak.**

That is a **prediction**, not a measurement, and the annotation visible on the
account today does not confirm it. Read verbatim on **2026-08-27**, the
annotation is a **disjunction**:

> recent account payments have failed **or** your spending limit needs to be
> increased

**A disjunction does not discriminate.** It is equally consistent with (a) a
failed payment and (b) an **included-minutes allowance exhausted behind a $0
spending limit** — and the two have opposite consequences for the flip, because
(b) is what free public-repository minutes would relieve and (a) is not.

**Evidence favouring (b), from the repository's own record** — a mid-cycle
exhaustion signature:

| datum | value |
| --- | --- |
| last run that got a runner | `31873411737`, **2026-08-15** |
| weighted minutes measured over **2026-08-01 → 15** (D135 §1.1) | **~3 154**, independently re-measured at **3 324** |
| the included allowance those ran against | **3 000** |
| refusals begin | **2026-08-16** |

**Evidence cutting the other way, measured independently by the orchestrator in
this wave and recorded here because it is the harder fact:** the **byte-identical
annotation** appeared on run `31407751482` on **2026-08-10** and **cleared the
same day, with no flip** — a **1 589 s** run at **21:08**, a success at
**22:05**, and the repository still private throughout. A 1 589-second run is
not a refusal (the refusal signature C4 itself gives is *"`conclusion: failure`
with an empty `steps` array, in 3–5 seconds"*), so on 2026-08-10 the annotation
stood while minutes were plainly being spent, and it went away without anyone
changing visibility.

**Neither branch is established.** §2 R5 rules that no row and no runbook step
may assert either, and names the read-only instrument that would settle it.

### 1.7 The checker candidate, with its measured yield

One rule was probed as a candidate instrument: *flag a row whose `Notes` name a
checkpoint row that does not name it back* — the §1.5 defect, generalised.

```
$ grep -o 'checked at [a-z]*' TODO.md tasks/*.md | sort | uniq -c
   1 tasks/A.md:checked at capture   "nonce checked at capture time"        prose
   1 tasks/Q.md:checked at freeze    "…complete at the Q14 freeze…"          prose
   1 tasks/Q.md:checked at their     "…checked at their milestone reviews"   prose
   1 TODO.md:880  Q238's row          "…and checked at **Q34**"     TRUE POSITIVE
```

**4 occurrences register-wide at `HEAD`, 3 prose false positives, 1 true
positive — and the true positive is `Q238` itself, which §2 R8 removes in the
same act.**
Yield **1**, false-positive rate **75 %**, and the yield goes to **0** the moment
this record is executed. §2 R9 refuses it and says so with the counts.

### 1.8 Locator drift, found before a single lane had read the plan

The planning round that produced this ruling cited `tasks/Q.md:2934` for the
`Q238` headline, `docs/ci-verification.md:3750` for C2, `:3082` for A6, `:3611`
for B5, `:3666` for B6, and `:2866` for the ordering-vocabulary table. Measured
today while writing this record:

| citation | planning round | measured 2026-08-27 | drift |
| --- | ---: | ---: | ---: |
| `tasks/Q.md` `### Q238` headline | 2934 | **2943** | **+9** |
| `docs/ci-verification.md` C2 heading | 3750 | **3814** | **+64** |
| A6 heading | 3082 | **3146** | **+64** |
| B5 heading | 3611 | **3675** | **+64** |
| B6 heading | 3666 | **3730** | **+64** |
| ordering-vocabulary table | 2866 | **2910** | **+64** |

This is **D162 §2 R5's finding recurring inside one wave**: line numbers drift
between the round that writes them and the lane that reads them, and here they
drifted **before the record citing them existed**. Every locator in this record
is therefore **heading or row id plus a quoted string**, with the line number as
a dated convenience. The `+64` is a concurrent CIRB-lane edit to
`docs/ci-verification.md` and the `+9` a concurrent ORCH-lane edit to
`tasks/Q.md`; §5.2 records what that does to §4's baselines.

---

## 2. RULING

### §2 R1 — `Q238` carries three timing words because it carries **three obligations**, and no single word is true of all three

Measured in §1.1: the row states its own timing on five surfaces in three
different words, and the three do not agree. This is **D163 §2 R6's diagnosis
verbatim** — *a missing split, not a mis-typed word*.

The three obligations, and what each costs:

| obligation | takeable by | needs |
| --- | --- | --- |
| **(a)** build the separate `on: push: paths:`-filtered lane | **an agent, today** | no network, no CI, no maintainer act |
| **(b)** re-measure the bill under the allowance | **an agent, today** — except for the one read-only query §2 R5 names | a `user` token scope this host lacks, for the settling query only |
| **(c)** arm the required status context | **the maintainer only** | a GitHub API write no agent may take |

No reword of a single ordering term can be true of all three at once. Any
attempt to make one true makes the other two false, which is what produced the
five surfaces in §1.1.

### §2 R2 — `before the repository goes public` is **NOT a precondition of `B1`**, and **NOT co-timed with it**. The flip is **struck as the event this obligation is ordered against**

- **Co-timed is excluded** by the runbook's own definition — *"Cannot be done
  earlier — the API refuses it while the repository is private"* — against a
  measured **absence of any refusal** (§1.2), and by C2's operative sentence
  *"Do not add a required status context in this sitting."*
- **Precondition-as-blocker is excluded** by the BEFORE row's own failure
  definition: *"The thing it guards is exposed at the instant of the flip, with
  no window to react."* **Nothing `Q238` guards becomes exposed at that
  instant.** The page is already live and public (A6); D135 §3 R5 rules the
  claim is made **at deploy time**, its residue **late discovery**, and *"**not**
  a false published claim"*.
- **The flip is therefore struck as the ordering event.** It is neither
  **necessary** (C2: *"the flip is not what unblocks protection"*) nor
  **sufficient** (the refusal's cause is unmeasured — §2 R5).

**This is not a ruling that arming early is safe.** §1.3 establishes that the
claim *"arming early is actively unsafe"* is **unproven**, not disproven. What
follows from unproven is exactly this much: **the flip loses its standing as the
event, in both directions at once.** A different event has to carry the
ordering, and §2 R4 names it.

### §2 R3 — `Q238` is **SPLIT** (D163 §2 R6's precedent), and the maintainer's deadline is kept on the whole obligation

- **`Q238` keeps the lane half** — the separate `on: push` filtered workflow, its
  filter self-test, its filter-completeness test, its registration in
  `scripts/check-ci-paths.py`, and §2 R6's design resolution. Its ordering run
  becomes **`— after R86, D135 §3 R6 + §10 R2, Q1; before Q65`** — one run
  carrying both words, precedented at `U78` (`— after U11/U18, before U32`) under
  D156 §2 R11 and at D163 §2 R6's own `Q35`. **It is lane-available today**: no
  network, no CI, no maintainer act.
- **A new M4 row, `Q265`, carries the arming half** — the GitHub API write. Its
  ordering run is **`— after Q238 + one hosted run reporting the new context
  green on main; before Q34`**, written as a `before` **deadline** and **not** as
  a new `after Q65` edge, per **D156 §2 R8**'s discipline and exactly as D163
  §2 R4 applied it. (Collapsing `before` into `after` invents dependencies and
  manufactured wave 27's phantom cycles.)
- **The maintainer's words are honoured, not overridden.** *"Require the context
  on every push before we go public"* is kept as a **deadline on the whole
  obligation**, discharged-or-recorded at `B0` by §2 R4's branch. The half that
  can meet it unconditionally is **bound to it**; the half that cannot is bound
  to the predicate that actually governs it.
- **No second maintainer act is minted.** The arming write is the **same write**
  as `Q1`'s residue and Maintainer actions entry **(8)**. `Q265` is that act's
  **row**; `Q258` and entry (8) keep the **act**.

### §2 R4 — The binding predicate is **a hosted run reporting the new context `success` on `main`**, and the runbook carries it as a **branch**

Precedented shape: **A6 — "BEFORE, and it is a branch"**.

- **Branch 1 — the context has reported green on `main` before `B0`'s consent is
  sought.** The arming is a **Phase A (BEFORE)** step, and the headline's
  deadline is met **literally**: the context is required before the repository
  goes public.
- **Branch 2 — it has not.** The arming is a **Phase C (AFTER)** step tied to
  **C4**, and the flip proceeds carrying a **recorded exposure** in **B6**'s
  shape — *"a recorded exposure, not a step to execute"* — **dated, owned by
  `Q265`, and written into the wave record**. It is **not** a blocker of `B1`,
  and it is **not** silence either.
- **Which branch obtains is decided by reading the check-runs, never by
  expectation.** D161 §2 R7's rider is restated and binds here verbatim: **no
  required status context may be added on the strength of an expectation.** An
  expectation is not a measurement.

**Why the cut is at the green-run predicate and not at the flip.** It is the
only predicate that is (i) directly readable, (ii) true of the obligation
regardless of which billing branch in §2 R5 is the real one, and (iii)
independent of whether the flip happens at all. §3 item 1 states the consequence
plainly: **if CI stays refused after the flip, nothing in this ruling moves.**

### §2 R5 — The billing premise is corrected at source **in both directions**, and **neither is asserted**

C4's *"Free minutes on public repositories is the mechanism that ends the
refusal streak"* is a **prediction** and is marked as one. Today's annotation is
a **disjunction** — *"recent account payments have failed **or** your spending
limit needs to be increased"* — and **does not discriminate** a failed payment
from an included-minutes allowance exhausted behind a $0 spending limit.

- The repository's own record carries a **mid-cycle exhaustion signature**
  favouring the second reading: last run with a runner `31873411737` on
  **2026-08-15**; **~3 154–3 324** weighted minutes against a **3 000**
  allowance over **2026-08-01 → 15**; refusals begin **2026-08-16** (§1.6).
- The orchestrator's independent measurement cuts the other way: the
  **byte-identical annotation** stood on run `31407751482` on **2026-08-10** and
  **cleared the same day with no flip** — a **1 589 s** run at **21:08**, success
  at **22:05**, repository still private (§1.6).

**Ruled: no row and no runbook step may assert either branch.** Both are named
at C4 as the two readings the annotation permits. The settling instrument is
added to the **Maintainer actions** block as an explicitly **read-only** item —
`gh api /user/settings/billing/actions` — which that block already records needs
a `user` scope this host's token lacks (current scopes: `gist`, `read:org`,
`repo`, `workflow`). **It is a `GET`. Obtaining the scope is a maintainer act
and nothing in this record is consent for it.**

### §2 R6 — The larger defect is not the ordering: **`Do` and `Accept` row 3 do not compose**, and the register conflates two arming mechanisms

§1.4's three shapes are ruled as measured:

- **The third shape is the one `Q238` builds** — filter `push` only, leave
  `pull_request` unfiltered, register the name in **`REQUIRED_CONTEXTS`** *and*
  in **`PUSH_EXEMPT`**. This is the `cross-os-macos` / `cross-os-windows`
  precedent verbatim, and it inherits that precedent's stated safety condition:
  *"still produced on `pull_request`, which is what keeps them safe to require."*
- **The arming-mechanism question is `Q265`'s first clause** — classic branch
  protection with `"enforce_admins": false` versus a **ruleset** — and **it must
  be settled before any write.** §1.3 measures why it matters: the two behave
  differently on exactly the case this shape creates, a docs-only direct push to
  `main` with the context unreported.
- **The lane half is EXPLICITLY PERMITTED TO RETURN THE QUESTION.** If, on
  building, the lane finds that no shape satisfies both `Do` and `Accept` row 3
  under the mechanism the register has not chosen, **it returns the question
  rather than building something that cannot be armed.** Returning it is a
  completed lane act, not a failure, and it is recorded on the row.

### §2 R7 — `Accept` row 3's *"the required-context count … moves in the same act"* is **AMENDED: regenerate, never increment — and the authoritative surface is the checker, not the prose**

`scripts/check-ci-paths.py`'s `REQUIRED_CONTEXTS` is a committed, CI-mounted set
of **19** names carrying its own instruction: *"**NEVER shrink this list to make
a check pass** — a context that stops being produced is a required check that
hangs a PR for ever."* `docs/ci-verification.md`'s prose payload lists **19
contexts from 17 jobs** while `ci.yml` declares **15** job ids (C2's own
measurement, 2026-08-19). **The prose is stale**, `Q56` owns that staleness, and
C2 already rules *"regenerate the payload rather than copying one"*.

**Incrementing a stale total by one produces a confidently wrong number.**
**Ruled:** the act adds the name to `REQUIRED_CONTEXTS` **and** to `PUSH_EXEMPT`
and **regenerates** the prose payload from the checker. It never writes
`19 → 20`.

### §2 R8 — The two checkpoints the row names **do not carry it**, and the check is landed where a human reads it

Measured in §1.5: no `Q238` in `Q34`'s ordering run, none in `Q65`'s row, none
in the M4 `Gate =` line's five clauses.

- **The `Q34` gate line is NOT widened.** This record does not amend a milestone
  gate; that is a different act with a different owner, and §3 item 6 states the
  consequence it leaves standing.
- **The check is landed as runbook step `A9`** — a Phase A step the flip operator
  reads **in the sitting**, which is the one place this obligation is actually
  looked at.
- **The `Notes` sentence is corrected** to name `A9` instead of two rows that do
  not carry it, with the measurement written beside it so a future reader does
  not have to re-derive it.

### §2 R9 — **No checker is minted**, and the candidate is REFUSED with its measured count

| candidate | measured today | verdict |
| --- | --- | --- |
| *a row whose `Notes` name a checkpoint row that does not name it back* | **4** `checked at X` occurrences across `TODO.md` + `tasks/*.md`; **3 prose false positives** (`checked at capture`, `checked at freeze`, `checked at their`); **1 true positive — `TODO.md:880`, this row itself** | **REFUSED** — yield **1**, FP rate **75 %**, and **§2 R8 removes the single true instance in the same act**, taking the yield to **0** |

Recorded so the refusal is not read as laziness: an instrument whose entire true
yield is deleted by the record that would mint it is an instrument with no
domain.

**What IS minted is a rule inside an existing checker, not a new instrument:**
**`check-ci-paths.py` R8** — *a workflow carrying a `paths:` filter on `push` may
not produce a name in `REQUIRED_CONTEXTS` unless that name is also in
`PUSH_EXEMPT`* — with a planted-fault arm in the existing `--self-test` harness,
which §1.4 measured **pure in-memory** and therefore safe to run mid-wave. It
must go **red by its own message**, not by an exit status alone.

**It is a clause of `Q238`'s `Accept`, and it is NOT BUILT THIS WAVE.** It is
executed when the row is taken, not by this record. **This record adds and
changes no script.**

---

## 3. What this record does NOT settle

1. **Whether the flip restores CI.** Unmeasured, **deliberately**, and the
   ruling is built so that neither branch changes it. The settling instrument is
   a read-only billing `GET` needing a `user` scope this host's token lacks
   (§2 R5). **If CI stays refused after the flip, nothing in this ruling
   moves**: `Q238` was already pre-flip work with no CI dependency, and `Q265`
   simply stays open with its exposure recorded at `B6`. **That is precisely why
   the ordering was cut at the green-run predicate rather than at the flip** —
   the cut is placed so this question does not have to be answered.
2. **Which arming mechanism.** §2 R6 names the question, measures why it
   matters, and routes it to `Q265`'s first clause. **It does not answer it**,
   and it cannot without a write.
3. **Whether a `PUT` to `branches/main/protection` or to `/rulesets` succeeds
   today.** `TODO.md:91` records it **untested** and this record ran no network
   command. §2 R2 rests on the **absence of a measured refusal** plus C2's own
   sentence — **not** on a measured success.
4. **`before Q34` is enforced by no parser.** Rule 7's own words are that
   nothing has ever parsed an `after` list; D141 §2 R7 struck the claim and D163
   §2 R8 refused the checker. The operative check is runbook step **`A9`**,
   executed by a human in the sitting. §2 R9 refuses to pretend otherwise.
5. **It does not re-open D135, and it ticks nothing** — not `Q1`, not `Q238`,
   not `Q65`, not `Q34`. The deploy-gated tier stays correct on the measurement
   available when it was ruled; `Q238` remains the raise D135 pre-authorised and
   pre-priced.
6. **It does not widen the M4 gate.** `Q34`'s `Gate =` line is untouched, so M4
   can still, in principle, pass with `Q265` open. **That is rule 4's design and
   this record does not overturn it** — §2 R8 lands the check at `A9` instead,
   which is a different surface with a different reader.
7. **It says nothing about fork-PR policy.** `B5` stands as written and is
   **not** a mitigation for this row (§1.2); `CONTRIBUTING.md` documents no
   contribution path at all (357 lines, **0** hits for *pull request*, *fork* or
   *merge*), and whether one should exist before the flip is a different row's
   question.
8. **It is not consent.** Nothing here authorises the flip, a push, a
   branch-protection write, or the obtaining of a token scope. See the closing
   block.

---

## 4. Edit list — per write scope, with a named lane and a verification predicate

Timing words are rule 7's and D156's, literal: `with` = same act; `before` =
strictly earlier, same wave; `after` = requires the other complete. Every target
is given as **field or heading plus a quoted old string**; line numbers are a
convenience and have already drifted once inside this wave (§1.8). **If the
quoted string is not at the line, trust the string.**

### Rule 3 as amended by D162 §2 R11, applied up front

**Three write scopes, three named lanes. Nothing is assigned to *"whichever lane
holds"* anything** — that phrase is what D162 §1.5 measured as an assignment to
**nobody**, and it is why D158's `with`-chain could not start for two waves.

| scope | lane | files |
| --- | --- | --- |
| register detail | **ORCH** (orchestrator) | `tasks/Q.md` |
| register surface | **REG** (registrar) | `TODO.md`, `docs/instrument-ledger.md`, `docs/decisions/README.md` |
| CI runbook | **CIRB** (a named `ci-runbook` lane) | `docs/ci-verification.md` |

**`docs/ci-verification.md` is on record as outside the registrar's write
scope** — `TODO.md:91`, verified verbatim today: *"that file is outside the
registrar's write scope"*. The planning round cited a **second** prior instance
of the same file falling outside a lane's scope at `TODO.md:921`; **that
locator has drifted and is NOT re-verified here** — `:921` today is `Q259`, an
unrelated row — so the second instance is recorded as **inherited and
unconfirmed**, and nothing in this ruling rests on it. One verified instance is
enough for the rule: **a lane must be named for this file in the wave brief
before this record is written, or the record must not be written. CIRB is that
lane.**

### **DELIBERATELY NO SINGLE `with`-CHAIN ROOT**

E1 and E2 are one `with` pair, because splitting them reds `task-entries` — a
row without an entry, or an entry without a row, is exactly what that check
finds. **E3 is INDEPENDENT and carries no `with` or `after` term to E1 or E2.**
It may land first, last, or in parallel.

**This is designed, not an omission.** D162's mechanism was a chain whose
**ordering root** sat in a write scope no lane held, so the whole act was
un-startable by construction. Here the scope most at risk of going unassigned —
`docs/ci-verification.md`, the one with two recorded prior misses — is the one
edit deliberately given **no dependency on any other scope**, so **no scope's
absence can stop the chain**. The failure mode is designed out rather than
warned about.

**The corollary, stated so it cannot be missed: the record is NOT EXECUTED until
E3 lands.** E3 is the only edit that puts §2 R8's check anywhere a human will
read it. A wave that lands E1 and E2 and stops has resolved this record without
executing it — the D162 §2 R11 shape, in this record's own edit list.

### The row this record mints, in full

| field | value |
| --- | --- |
| **Id** | **`Q265`** — next free; highest in use at the planning round was `Q264`, verified `grep -c Q265 TODO.md tasks/Q.md` → `0` / `0`. **The registrar confirms the id at registration.** |
| **Domain** | `Q` — CI / repository infrastructure, the same domain as `Q1`, `Q238`, `Q239` |
| **Milestone** | **M4** |
| **Size** | **S** — one API write, two read-backs, one regenerated payload. It is small **because §2 R3 moved every buildable clause to `Q238`** |
| **`Do`** | *Arm the promoted reproducibility lane as a required status context on `main` — after deciding classic-protection-with-`enforce_admins: false` versus a ruleset (§2 R6), and only once a hosted run has reported that context green on `main`.* |
| **Ordering run** | `— after Q238 + one hosted run reporting the new context green on main; before Q34` — a `before` **deadline**, not a new `after Q65` edge (D156 §2 R8) |
| **Owner** | **the maintainer. No agent may take it.** It is the **same GitHub write** as `Q1`'s residue and Maintainer actions entry **(8)**; `Q265` is that act's row, `Q258` and entry (8) keep the act. **No second maintainer act is minted.** |
| **Bounded and tickable** | it ticks on a **read-back of the armed context**, or on a **recorded refusal with its reason**. It does **not** belong in the Continuous section. |

### ORCH — `tasks/Q.md`

**E1a.** `### Q238` heading (today `:2943`) — **strike** `before the repository
goes public` (`~~struck~~`, **never deleted**, rule 7) and replace with
**`, and arm it when a hosted run has reported it green on main`**.
**with** E1b, E1c, E2a, E2b.

**E1b.** `Deps:` run — strike *"it is a **precondition of making the repository
public**"* and replace with §2 R2's finding: the flip is neither necessary nor
sufficient. The ordering run becomes
`— after R86, D135 §3 R6 + §10 R2, Q1; before Q65`. **with** E1a.

**E1c.** `Do:` — prepend **§2 R6's design question as the first clause**, with
§1.4's three-shape table and the **explicit permission to return the question**
rather than build an unarmable lane. Move the arming clause out to `Q265`.
**with** E1a.

**E1d.** `Accept` row 3 — **AMENDED per §2 R7**: regenerate the payload, never
increment; the authoritative surface is
`scripts/check-ci-paths.py`'s `REQUIRED_CONTEXTS` + `PUSH_EXEMPT`, and
`docs/ci-verification.md`'s prose is **regenerated beside it**. The arming half
moves to `Q265`. **with** E1a.

**E1e.** `Accept` — add §2 R9's clause: `check-ci-paths.py` **R8**, with a
planted-fault arm in the **existing** `--self-test`, red **by its own message**.
**Not built by this record.** **with** E1d.

**E1f.** `Notes:` — strike *"**Q34** … and **Q65** … are where it must be
checked"*; replace with §2 R8: the check is runbook step **`A9`**, and neither
`Q34`'s ordering run nor the M4 `Gate =` line carries this row, measured.
**with** E1a.

**E1g.** A new `### Q265` entry, to the spec in the table above. **with** E2b.

> **Predicate E1 — strike-aware, and a plain `grep -c` is the WRONG predicate
> here.** Rule 7 repairs by striking, never by deleting, so after E1a the old
> term is **still in the file**, inside `~~…~~`. A count-based predicate does
> not merely fail to fall — **it rises**: measured on this tree,
> `grep -c 'before the repository goes public' tasks/Q.md` read **2** at the
> planning round and **3** after E1a landed, because the strike keeps the old
> words and the replacement text cites them. A predicate demanding `0` is
> **unsatisfiable without breaking rule 7**, and a predicate demanding a fall is
> **satisfied by the defect**. The predicate must ask whether the term is still
> **LIVE**, which means stripping the struck spans first:
>
> ```
> python3 - <<'PY'
> import re
> h=[l for l in open('tasks/Q.md',encoding='utf-8') if l.startswith('### Q238 ')]
> assert len(h)==1
> print('LIVE_OLD_TERM=', 'before the repository goes public' in re.sub(r'~~.*?~~','',h[0]))
> print('Q265_ENTRY=', sum(1 for l in open('tasks/Q.md',encoding='utf-8') if l.startswith('### Q265 ')))
> PY
> ```
>
> **Baseline at the planning round: `LIVE_OLD_TERM= True`, `Q265_ENTRY= 0`.**
> **Required after: `LIVE_OLD_TERM= False`, `Q265_ENTRY= 1`.**
> *(Re-measured 2026-08-27 while this record was being written, with the ORCH
> lane already in flight: `LIVE_OLD_TERM= False`, `Q265_ENTRY= 0` — E1a landed,
> E1g had not. §5.2.)*

### REG — `TODO.md`, `docs/instrument-ledger.md`, `docs/decisions/README.md`

**E2a.** `Q238`'s row (`TODO.md:880`) — mirror E1a, E1b and E1f; **and strike the
stale parenthetical still live in the ordering run**, *"(publish scope, and
**branch protection is plan-blocked**)"*. D163 §2 R9 corrected that dead premise
in `tasks/Q.md` and **appended rather than replaced** here, so it is still live
text on the register's surface. **with** E1a.

**E2b.** Mint `Q265`'s row in the M4 block with the ordering run
`— after Q238 + one hosted run reporting the new context green on main; before Q34`.
**with** E1g.

**E2c.** The **Maintainer actions** block — **named by its heading**, *"**Maintainer
actions** (all external)"*, **never by line number** (D163 §1.8) — amend entry
**(8)** to name `Q265` as its row and to carry §2 R6's unresolved mechanism
question; and add a new, explicitly **read-only** item for §2 R5's settling
query (`gh api /user/settings/billing/actions`, needs a `user` scope this host's
token lacks). **Nothing here is consent for obtaining that scope.**
**after** E2b.

**E2d.** `## Current focus` (`TODO.md:91`) — strike *"two rows that are
preconditions of going public"* **as it applies to `Q238`**. `Q65` keeps that
description; `Q238` does not. **with** E2a.

**E2e.** `docs/instrument-ledger.md` — one `·`-attributed line for §1.3's
finding: the unqualified *"blocks the next push, including the maintainer's
own"* claim standing on **four** surfaces (`docs/ci-verification.md` C2 and the
wave-7 step-3→5 note, D163 §1.6, Maintainer actions entry (8)) against
`:277`/`:292-294`'s own `"enforce_admins": false` and its explicit admin bypass.
**after** E3.

**E2f.** `docs/decisions/README.md` — the **`D164` index row**, in ascending id
order, with `RESOLVED` and `2026-08-27` copied from this record's own
`- **Status`/`- **Date` lines. **Registrar's edit, not a lane's** (D163 §4 item
15). **This record does not write it.**

**E2g.** M4 heading count and the register totals — **recount by script, never
increment**, after E2b lands. **after** every edit above.

> **Predicate E2:**
> ```
> python3 scripts/check-traceability.py 2>&1 | grep -E 'task-entries|decision-index|decision-ledger-debt'; echo EXIT=${PIPESTATUS[0]}
> grep -c '^- \[ \] \*\*Q265\*\*' TODO.md
> ```
> **Baseline at the planning round:**
> `[task-entries] ok — 698 rows (697 live + 1 struck) against 698 entries`,
> `EXIT=0`, and `0`.
> **Required after:** `699 rows (698 live + 1 struck) against 699 entries`,
> `EXIT=0`, and `1`.
>
> `decision-index` enforces **E2f** and `decision-ledger-debt` enforces **E2e** —
> both are **existing arms of this same run**, so neither needs a predicate of
> its own, and **both go red on arrival of this file until their edit lands**,
> which is the mechanism that makes E2e and E2f self-enforcing rather than
> aspirational.
>
> *Measured 2026-08-27, this record's own baseline run:* `REAL_EXIT=0`,
> `[task-entries] ok — 698 rows (697 live + 1 struck) against 698 entries`,
> `[decision-index] ok — 157 index row(s) … against 157 record(s)`,
> `[decision-ledger-debt] ok — 18 record(s) of 157 … subject 18 >= floor 16`.
> **This file would make it 158 records against 157 index rows**, so
> `decision-index` reds until E2f lands — by design. **In the event it did not
> red**: the registrar landed E2f *before* this file existed (§5.2), so both
> sides moved 157 → 158 in one step and the check was green on its first run
> with the record present. The red is the mechanism, not an observation, and it
> is recorded that way rather than claimed as one.
>
> *(`check-traceability.py` **flagless** is the check; there is no `--check`
> flag. Its `--self-test` stages a full tree copy and stays banned mid-wave.)*

### CIRB — `docs/ci-verification.md` — **the edit that makes the ruling real**

**E3a.** A new step **`### A9 — BEFORE, and it is a branch. The reproducibility
context's report on `main``** — §2 R4's two branches written out, with the
check-runs command, C4's refusal signature (*empty `steps`, 3–5 s*), and the
`[UNOBSERVED — …]` tag the chapter requires of anything not yet seen. **Placed
after `A8`** (*"BEFORE. Push `main` by name"*), because the lane must be pushed
before it can report.

**E3b.** **C2** — keep *"Do not add a required status context in this sitting"*
and add the hand-off: **`Q265` owns the write**, §2 R7's
regenerate-never-increment rule, and §2 R6's **unresolved** mechanism question.

**E3c.** **C2 and the wave-7 step-3→5 note (`:218-221`)** — **qualify the
unqualified claim**: name the mechanism, cite `:277`'s `"enforce_admins": false`
and `:292-294`'s explicit admin bypass, and state that a **ruleset** has no
implicit admin bypass. **This is the correction on which §2 R2 and §2 R6 rest**,
and it is the reason E3 cannot be treated as optional trailing work.

**E3d.** **C4** — mark *"Free minutes on public repositories is the mechanism
that ends the refusal streak"* as a **prediction**; record the 2026-08-27
annotation **verbatim, as a disjunction**; and name **both** readings from §1.6
**without asserting either** (§2 R5), including the 2026-08-10 clearing on run
`31407751482` that cuts against the exhaustion reading.

> **Predicate E3** — each of the five lines was read on this tree today, so each
> is a real before/after and not an assertion about a number nobody measured:
> ```
> grep -c '^### A9 ' docs/ci-verification.md         # baseline 0,  required 1
> grep -c 'Q265' docs/ci-verification.md             # baseline 0,  required >= 2 (A9 and C2)
> grep -c 'enforce_admins' docs/ci-verification.md   # baseline 7,  required >= 9
> awk '/^### C2 /,/^### C3 /' docs/ci-verification.md | grep -c 'enforce_admins'
>                                                    # baseline 0,  required >= 1
> python3 scripts/check-ci-paths.py; echo EXIT=$?    # baseline EXIT=0, required EXIT=0
> ```
> The fourth line is the one that matters: `enforce_admins` occurs **7** times in
> the file and **0** times inside C2, which is the whole of §1.3 expressed as a
> count. A file-wide count alone would be **satisfied by the six occurrences that
> already exist somewhere else** — an assertion that cannot fail. The last line
> guards the DOCS-only invariant this file sits inside.
>
> **Re-take the flagless `check-ci-paths.py` baseline once the concurrent lane
> holding that script lands** (§5.2), before quoting the last line's `EXIT=0` as
> evidence of anything.

### Nothing else

**No script is added or changed by this record.** §2 R9 refuses the checker;
`check-ci-paths.py` **R8** is a **clause of `Q238`'s `Accept`**, executed when
the row is taken, not by this record. **No workflow is touched. No file under
`crates/`, `testdata/` or `.github/` is in this edit list**, so no build, no
golden vector and no tamper-matrix row is affected, and the
`wasm32-unknown-unknown` surface is untouched. **`Q34`'s `Gate =` line is not
edited** (§2 R8). **No decision record body is edited** — resolved records are
corrected by citation, per D117.

---

## 5. Disclosure — the tree this was measured on

### 5.1 Parallel lanes share one working tree

`git status --porcelain` at the time of writing shows **18 entries**, of which
four are in this record's own scopes: `TODO.md`, `tasks/Q.md`,
`docs/ci-verification.md` and `docs/instrument-ledger.md` are all **modified by
concurrent wave-31 lanes**, as are `scripts/check-ci-paths.py`,
`scripts/check-copy-style.py`, `.github/workflows/devnet-e2e-cron.yml`, five
`Cargo.toml`s and one test. Every citation in §1 was therefore read at
**`HEAD` (`3922ada`)** where the text is a claim about what was ruled on, and
**on the working tree, dated**, where the point is what is true today. Both are
labelled at each site.

**One baseline is explicitly NOT `HEAD`-clean.** The flagless
`check-ci-paths.py` run quoted in §1.4 — *"19 required contexts are each
produced exactly once on `pull_request`"*, `REAL_EXIT=0` — was taken on the
**working tree**, i.e. against another lane's in-flight edit to that very
script. A `HEAD`-only re-run from a staged copy returned `EXIT=1` **as an
artifact of the staging** (`[R4]: the ci.yml reader set resolved to only 0
file(s)` — the script enumerates tracked files relative to its own repo root and
the staged copy had no git repo), so **that exit code proves nothing about
`HEAD`** and is recorded here only so that nobody quotes it. **Re-take the
flagless baseline once the concurrent lane lands**, before running Predicate
E3's last line. §1.4's three-shape table does **not** depend on that run: it
rests on `PUSH_EXEMPT`'s comment and on `ci-always.yml`'s header, both verified
independently.

### 5.2 What moved between the ruling and this record, measured

The ruling was reached by a planning round on **2026-08-27**; the ORCH and REG
lanes began executing §4 **before this file existed**. Measured while writing,
so no baseline in §4 is quoted as current when it is not:

| §4 item | planning-round baseline | measured while writing this record |
| --- | --- | --- |
| **E1a** (`LIVE_OLD_TERM`) | `True` | **`False`** — landed |
| **E1g** (`Q265_ENTRY`) | `0` | **`0`** — not landed |
| **E2a** (`Q238` row ordering run) | `joint with Q65 … checked at Q34` live | **struck**; the run now reads `; **before Q65**` — landed |
| **E2b** (`Q265` row in `TODO.md`) | `0` | **`1`** — landed |
| **E2e** (ledger line naming D164) | `0` | **`1`** — landed |
| **E2f** (`D164` index row) | `0` | **`1`** — landed, at `docs/decisions/README.md:182`, `RESOLVED` / `2026-08-27`, link target matching this file |
| **E3a** (`### A9 `) | `0` | **`0`** — **not landed** |

**Two consequences, and the second is the one to act on.**

1. `task-entries` was `698 rows … against 698 entries` at the planning round;
   with `Q265`'s row landed and its `tasks/Q.md` entry not, the pair E1g/E2b is
   **mid-`with`** and the predicate must be re-read after both land, not
   between them. That is the `with` semantics working as designed, not a defect.
2. **E3 has not landed, and §4 says in its own words that the record is not
   executed until it does.** Everything §2 R2 and §2 R6 rest on is the
   correction E3c makes at source. A wave that stops here has published a ruling
   whose load-bearing correction is not in the file it corrects — the exact
   shape D162 §2 R11 appended to rule 3 to prevent.

---

## Closing — this record is not consent

**Nothing in this record authorises anything.** It does not authorise the
visibility flip, a push, a branch-protection or ruleset write, or the obtaining
of a `user` token scope. It arms no required status context and takes no
external action of any kind; **no network command was run in producing it.**

`Q265` is the maintainer's row and **no agent may take it**. The settling
billing query in §2 R5 is a **read-only `GET`** whose scope this host's token
lacks, and naming it is **not** a request to obtain that scope. The flip remains
maintainer-only by the runbook's own ruling.

---

## Note from the lane that wrote this record — three doubts, clearly separated

**Written as ruled. These are recorded, not acted on**, per the brief's
instruction that a doubt is written down rather than silently resolved.

1. **§2 R3's ordering run for `Q238` puts `before Q65` on a row whose lane half
   §2 R2 has just shown the flip does not order.** The run
   `— after R86, D135 §3 R6 + §10 R2, Q1; before Q65` reads as a deadline, which
   is the correct D156 §2 R8 shape — but it is a deadline **against the very
   event the ruling struck as the ordering event**. It is defensible as
   *"honour the maintainer's deadline on the whole obligation"* (§2 R3's own
   words) and I have written it exactly as ruled. My doubt is that a future
   reader who reaches §2 R2 first will read the surviving `before Q65` as a
   contradiction and try to repair it. **If it stands, E1b and E2a should say in
   one clause why a struck ordering event can still carry a deadline.**
2. **§2 R9 mints `check-ci-paths.py` R8 as a clause of an `Accept` while §2 R9's
   own heading says no checker is minted.** Both are true as written — a rule
   inside an existing checker is not a new instrument — but the yield discipline
   the register applies to checkers (a measured count, a plantable fault) is
   **asserted for R8 and not measured**: no count of workflows-with-`push`-filters
   is given, because today there are none. **R8's arm therefore has a domain of
   size 0 until `Q238` builds the first one**, which is the
   assertion-that-cannot-fail shape unless the planted-fault arm constructs its
   own subject in memory. §2 R9 says *"red by its own message"*; it does not say
   *"on a constructed subject"*, and I believe it must.
3. **A numbering discrepancy between the plan and this record, recorded so
   nobody thinks a section was dropped.** The planning notes number their
   scope-limits section `# 5` with **eight** items and their disclosure `# 6`;
   the brief that commissioned this record refers to *"§6's seven items"*. All
   **eight** are carried here as §3 items 1–8, with item 8 (*it is not consent*)
   additionally restated in the closing block. **Nothing was omitted and nothing
   was added.**
