# D126 — A25's re-run clause and the row-4 hand-off: discharge and strike the clause, execute the hand-off into Q26's `Do`, close A25 on its four rows

- **Status: RESOLVED — (1) the `Do`'s closing clause *"the full protocol
  re-runs at task completion"* is DISCHARGED on the `A25-wave16-cycle`
  campaign and STRUCK, with no Accept row minted in its place, because every
  future re-run trigger already has a per-step owner (runbook §5, A26/A44,
  A48 ✅, D54) and a full-protocol row would have no trigger to state;
  (2) Accept row 4 closes on the hand-off EXECUTED NOW — findings (a)–(e)
  written into Q26's `Do` verbatim-by-citation with A25 added to Q26's
  `Deps`, while (f) needs no new home because calendar rot is already
  quadruply homed (runbook §3.1, D54, A14, A44); (3) A25 CLOSES today on
  its four Accept rows, each conjunct measured true against the tree, with
  the submit-path residue standing and single-homed in `V7.1` (`gap`) and
  Q236's gate — its disposition is D127's and this record does not touch it.
  The register's lean survives on measurement, corrected in three
  particulars: the discharge is by the whole two-day CAMPAIGN (day-1
  submits + day-2 script run), not by the day-2 run alone, which contains
  no submit leg; the hand-off is not purely additive — finding (e)
  qualifies caveats Q26's `Do` already presents as if measured; and (d)'s
  skew figure enters Q26 as "~2 minutes" plus the citation, never as
  "129 s", because A107 measured 128 s per frozen token and the log's 129
  is a probe-offset mode.**
- **Date: 2026-08-11** (wave 17, D126 lane; briefed to overturn the
  strike/execute/close lean. All three overturn arms were taken to
  measurement — trigger-bearing Accept row, wait-for-the-document,
  read-row-1-as-through-the-script-including-submit — and each dies on
  tree facts recorded in §2.)
- **Owning tasks: A25** (the closure), **Q26** (receives the hand-off;
  its M4 lane implements the `Do` additions as table rows), with **A31**
  (finding (a)'s open table row), **A32** (finding (d)'s code rule),
  **A44/D54/A14** (finding (f)'s standing homes), **A105** (row 2's
  named-test half, unaffected). **Boundary: `V7.1` / Q236 / D127** (§4).
- **Amends**: `tasks/A.md` §A25 (`Do` strike note + closure bullet),
  `tasks/Q.md` §Q26 (`Deps`, `Do`), `TODO.md` A25 row + decision register,
  `testdata/anchors/README.md` (campaign row), runbook §3.4 (pointer).
  **Supersedes/Corrects**: nothing ruled; executes the 2026-08-07
  adjudication's own either/or on the clause.

---

## 1. What was measured

**(a) The clause, and the adjudication that framed this ruling.** The one
live copy sits in `tasks/A.md` §A25's `Do`: *"An early bootstrap capture
may run as soon as A3/A4 exist, seeding A5/A11/A12 development fixtures;
the full protocol re-runs at task completion."* (The other two occurrences,
`TODO.md`'s A25 row and the §A25 adjudication bullet, are quotations of it,
i.e. historical record, not copies to strike.) The 2026-08-07 adjudication:
the clause *"has no Accept row behind it … Closing A25 on its four Accept
rows is defensible; closing it on that clause is not, and that clause is
the only thing that makes A25 look permanently network-bound … If the
re-run is genuinely wanted it needs an Accept row of its own, with a
stated trigger; if it is not, the clause should go."* This record answers
that either/or.

**(b) What each protocol leg has now proven — the clause's own words are
met.** The runbook's protocol is §3.1 submit → wait → upgrade (+ the
step-4 promotion), §3.2 TSA, §3.3 must-agree, §3.4 liveness findings.
Measured per leg, at task completion:

| leg | by hand | through antseal's own clients (script, day-2 2026-08-11T17:55–17:56Z) |
| --- | --- | --- |
| submit | 2026-08-02T19:16Z (2 digests × 3 live calendars, bootstrap) **and** 2026-08-11T12:46Z day-1 (2 digests × the four `DEFAULT_OTS_CALENDARS` pool endpoints, 8/8 `200`, `A25-wave16-cycle/CAPTURE.log`, fresh recorded §1 consent) | **never** — day-2's recorded consent scope *"excludes fresh calendar submissions"*; this is the whole residue, `V7.1`'s |
| upgrade | 2026-08-03T09:03Z (6 commitments, all `200`) | **6 of 8 upgraded** via A13→A14's `pending_refs` → `UpgradeTarget::from_pending_uri` (A42's allowlist) → `poll_upgrade`; both eternitywall pendings answered the pending-42-byte-404 class → `not-yet-confirmed`, kept re-pollable, never promoted to the hard error (`A25-wave16-cycle/upgraded/UPGRADE-CAPTURE.log`) |
| `--online` promotion (step 4) | evidence complete offline since 2026-08-07: 80-byte headers for 960767/960768/960771 from both esplora endpoints, byte-identical, `double-SHA256(header) == claimed hash` | n/a — the CLI half is an M3 stub (`antseal verify --online`; `crates/antseal-cli/src/run.rs` maps `Verify` to M3), blocked by a milestone, not a network; not A25's, per the runbook §3.1 step 4 note |
| TSA | 2026-08-02 (nine TSAs, `D60-*`) | FreeTSA **and** DigiCert via A10's `capture_one` against `TsaRootStore::pinned()`: both `state=Proven root_store_version=1` (`TSA-CAPTURE.log`) — the proving run the day-1 log reserved for the script |
| must-agree | 2026-08-03T08:20–08:34Z | esplora pair **agreed** on the 80-byte header for 960767; Arbitrum One pair **agreed** over the extracted tuple (`status=1, block_number=490596171`) despite byte-different JSON — D55 §3 through A16/A17 (`MUSTAGREE-CAPTURE.log`) |
| liveness findings | recorded at every campaign | day-2 adds: eternitywall's submit front (`a.pool.eternitywall.com`) live while `finney.calendar.eternitywall.com` had not confirmed at ~5h09m — pending, not rot |

So at task completion the protocol **has re-run as a complete campaign**:
`A25-wave16-cycle` is a two-day cycle at the product's own four default
calendars (which no earlier campaign had stamped — D54's whole point),
under fresh per-campaign §1 consent both days, with three of four network
legs driven by antseal's own clients and the fourth (submit) excluded by
the day-2 consent's recorded scope. The clause's words — written before
the script was ever a conjunct — say *"the full protocol re-runs"*, and it
did.

**(c) Every future re-run trigger already has an owner, and none needs the
full protocol.** Enumerated: fixture refresh → runbook **§5** (*"re-run
the relevant §3 step under a fresh §1 consent, and commit the new capture
beside the old one, never over it"* — per-step by its own words); root
rotation/append → **A26** ✅ + `docs/anchors/root-store-update.md` (its own
document, out of the runbook's scope by the runbook's header); ongoing
endpoint rot → **A44** (open, scheduled, non-gating: calendar liveness
reads, RPC pairs probed with the production method, root expiry horizon —
and its `Do` says *"Submit nothing"*); limit re-measurement → **A48**
✅ 2026-08-10 (offline, over committed bytes); calendar-set changes →
**D54** (*"replacing a dead default is not a format event"*); the two
eternitywall re-polls → recorded re-pollable in the day-2 log, each under
its own fresh consent, optional evidence and never a blocker. There is no
residual event class that requires all legs in one campaign — so an Accept
row *"re-run the full protocol when X"* has no X to name, and a row
without a trigger is precisely the *"fresh real-endpoint campaign … every
time the task is touched"* defect the adjudication refused.

**(d) The submit residue already has three homes, and a closure precedent
that refused a fourth.** (1) `V7.1`
(`docs/testing/verification-matrix.md`, spec bullet "Anchor smoke tests"):
status `gap`, its cell recording exactly *"the submit path — day-1's
pendings were created by hand, and the run's recorded consent scope
excluded fresh submissions"*, that *"one consented script-driven submit
pair closes it, or the M2 review rules it on the record"*, and that
*"Q236's Accept forbids sliding past it"*. The status column is
machine-checked at the milestone under review, so an M2 row at `gap` reds
Q236's `--matrix --milestone M2` run **regardless of any task checkbox**.
(2) **Q236**, the M2 gate row minted by Q208, owner of the review and the
`CURRENT_MILESTONE` bump (TODO.md rule 4). (3) **D127**, the sibling
ruling on the disposition, running concurrently. And the precedent:
**Q99 closed 2026-08-11 on the day-2 run** with the identical residue
recorded as a qualification — *"that residue is V7.1's, tracked in the
matrix, not a second home here"*. Keeping A25 open on the same residue
would mint the second home Q99's closure explicitly refused.

**(e) Q26's entry, measured.** `tasks/Q.md` §Q26 (M4): `Deps` line names
Q20, A26, U26 — **no A25**. Its `Do` names the five TSAs and presents
Sectigo's *"~15 s spacing"* and SwissSign's *"~10/day"* as bare caveats —
the very presentation finding (e) exists to qualify (the runbook §2 table
already labels both **published**, never measured). The `Do` contains
**none** of findings (a)–(f). The runbook §3.4 records *"'Hand to Q26' is
not yet a place"* and points at A25's Notes as the standing list — a
pointer that keeps resolving after closure (entries persist), but the
A22 lesson (recorded at Q85's scope-widening: a lane that opens its entry
and finds nothing *improvises*) says the M4 lane must meet the findings
in **its own** `Do`, not through a pointer in another domain's file.

**(f) The hand-off precedent runs both ways, and the verb decides.**
**A26** closed ✅ 2026-08-03 with *"Q31's release checklist does not exist
yet, so the rows are written for it to adopt"* — a hand-off to an
unwritten document, closed by writing the content where the future lane
must find it. **A31** row 3 (*"The alternates table carries the caveat
with its measurement date"*) stays open — because its words name the
**table** as the deliverable. A25 row 4's words are *"findings **handed**
to Q for the alternates doc table"*: the deliverable is the hand-off, an
act on Q's register, executable today; the table itself is A31 row 3's
and Q26's. Same distinction, both directions, both already lived.

**(g) Finding (f)'s homes exist and are load-bearing.** Calendar rot:
runbook §3.1 carries the three measured calendar-behaviour classes
(pending-404 / hard-404 / `http=000` transport, the last *"never promoted
to the hard error"*) plus the finney-DNS note ending *"D54 owns the
calendar set and the rot policy this implies"*; **D54** is the resolved
decision that dropped the dead host by adopting upstream's pool set and
ruled replacement a non-format event; **A14**'s entry and classifier
carry the fourth observed case (catallaxy answering nothing where
alice/bob 404) with the stays-re-pollable rule; **A44** (open) is the
scheduled watch. Nothing about (f) is Q26's — Q26 is the TSA document —
and nothing about (f) is homeless.

**(h) Row-by-row, against the tree, today.**
- **Row 1** — *"Runbook + script committed"*:
  `docs/anchors/real-smoke-runbook.md` and `scripts/anchor-smoke` both
  exist; the script drives antseal's own clients through the dev-only
  `anchor-smoke-driver` (`required-features = ["test-util"]`), selftest
  12/12 with four red arms proven by message. *"the two-day OTS protocol
  completed at least once before M2 close"*: completed **twice** — the
  bootstrap cycle (submit 2026-08-02T19:16Z → upgrade 2026-08-03T09:03Z,
  literally spanning two days, satisfying even the most literal reading
  of "two-day") and the wave16 cycle (12:46Z → 17:55Z, ~5h09m — the
  protocol's shape, third measured cadence figure, still no interval to
  plan on); M2 close has not happened (`CURRENT_MILESTONE` reads `M1`;
  Q236 open). *"results logged"*: five campaign logs carrying runbook
  §4's four fields per request (the two pre-runbook logs' gaps are
  recorded in §4 itself, not repeated by any 2026-08-11 log). Every
  conjunct true.
- **Row 2** — held since 2026-08-07 (both real tokens reach `proven`
  against the pinned store, pinned by committed tests), and the day-2
  `TSA-CAPTURE.log` is now additionally a **run named for the property**
  (`state=Proven root_store_version=1`, both defaults, via A10) — curing
  the "anti-vacuity arm of a test named for something else" qualification
  at the evidence level. The named-**test** half remains **A105**'s and
  is not claimed here.
- **Row 3** — held: four campaigns under `testdata/anchors/`, only the
  two committed golden-vector digests ever stamped, no secret material.
- **Row 4** — closes per §3.2 below, on the executed hand-off.

---

## 2. The overturn arms, measured and refused

**Arm (i) — promote the clause to an Accept row with a stated trigger.**
Dies on §1 (c): the trigger set is empty. Every enumerable future event —
refresh, rotation, rot, re-measurement, re-poll — maps to a **per-step**
run with an existing owner, and §5 of the runbook already states the
per-step mechanism including its consent and append-only rules. A row
reading "re-runs at task completion" is self-consuming (task completion
is this closure, and the campaign ran); a row reading "re-runs when
needed" has no falsifiable trigger and permanently re-arms the task —
the exact permanently-network-bound defect the adjudication named. And
the one genuinely wanted future run — the consented submit pair — must
NOT be this row's, because it is `V7.1`'s and D127's (§4); minting it
here would double-home it.

**Arm (ii) — row 4 cannot close until Q26's document exists.** Dies on
§1 (f)'s precedent pair: the row's verb is "handed", and A26 closed on
exactly this shape while A31 row 3 — whose words do name the table —
correctly stays open to carry the table half. It also inverts the
dependency: Q26 (M4) consumes A25's data; making A25 (M2) wait on Q26's
document couples an M2 closure to an M4 deliverable and leaves A25 open
for months as a reminder-holder for another task's work — the row-standing-
for-another-row's-work shape D125 exists to stop. The one real risk the
arm protects against — the M4 lane missing the findings — is closed
harder by the executed hand-off (findings in Q26's own `Do`, A25 in its
`Deps`) than by an open A25 three files away.

**Arm (iii) — read row 1's "protocol completed" as "through the script,
all four legs including submit".** Dies three ways. (1) **The row's own
words**: the script is a *separate conjunct* of the same row — under the
proposed reading the 2026-08-07 adjudication could not have written *"the
two-day OTS protocol has been completed once and logged end to end"*
while adjudicating the script missing in the same breath; the conjuncts
were read as independent then and nothing has amended the row since.
(2) **The spec bullet** (MVP-SPEC.md line 173, "Anchor smoke tests")
demands *"real OTS calendars (pending → upgraded next day); real FreeTSA
… and DigiCert tokens verified against the pinned roots; CI uses a mock
TSA + recorded OTS fixtures"* — no client-path words. The
smoke-tests-the-client-not-the-endpoints refinement is **D118 §1.5's**,
and it is banked verbatim in `V7.1`'s cell, the matrix row that exists
for this bullet. (3) **The D117 precedent cuts the other way**: the
insufficient sentence (*"this row moves when that consented run has
happened through the script"*) was met, found to conflate the script's
real branch with both client paths, and REPLACED — *in `V7.1`'s cell*,
the row that owns the property. The lesson is that the both-client-paths
demand lives where it is machine-checked, not that a task row's words
get re-read wider post hoc. Re-homing the demand into A25 row 1 would
mint the second home Q99's closure refused (§1 d) — and it would change
nothing material, because `V7.1` at `gap` blocks the M2 gate with or
without A25's checkbox.

---

## 3. The ruling

**3.1 — The clause is discharged and struck; no Accept row replaces it.**
Discharged: at task completion the full protocol has re-run as the
`A25-wave16-cycle` campaign (§1 b) — day-1 submits at the product's four
default calendars, day-2 upgrade/TSA/must-agree through
`scripts/anchor-smoke` and antseal's own A14/A10/A16/A17 clients, findings
logged, fresh recorded §1 consent per day. Struck: the sentence comes out
of force by a dated inline note in the `Do` (the entry's own twice-used
convention — original text stays legible; task entries are not D117's
decision bodies, but the strike-don't-delete discipline is the same),
because keeping it live would re-arm the task forever against an empty
trigger set (§2 i). Future real-endpoint contact is governed by runbook
§5 per-step refreshes under fresh §1 consent, with the owners named in
§1 (c).

**3.2 — Row 4 closes on the hand-off executed now.** Findings (a)–(e)
enter Q26's `Do` verbatim-by-citation (exact text in §5 edit 3), A25
enters Q26's `Deps`, and the runbook §3.4 pointer gains one sentence
saying the hand-off executed. Three deliberate particulars: **(a)** is
written to connect to A31 (whose open Accept row lands the table cell,
with its measurement date); **(d)** enters as *"~2 minutes"* plus the
log citation — never "129 s" — because A107 measured the two frozen
tokens' skew at 128 s each and identified the log's headline 129 as the
mode of three probe offsets; writing 129 into Q26 would replicate the
defect A107 caught, in the document class (a doc table) least likely to
be re-measured; **(e)** does not merely append — it obliges Q26 to label
the Sectigo/SwissSign caveats *published, not measured*, qualifying text
the `Do` already carries. **(f) is discharged by citation, with no new
edit**: its homes (runbook §3.1, D54, A14, A44 — §1 g) predate this
record and are named in the hand-off text so the exclusion is visible
rather than silent.

**3.3 — A25 closes today on its four Accept rows** — row 1 on §1 (h)'s
conjunct-by-conjunct measurement, row 2 as held since 2026-08-07 and now
also evidenced by a run named for it (A105's named-test half untouched),
row 3 as held, row 4 per §3.2 — **conditional on the §5 edits landing in
the same registrar act**, because row 4's satisfaction *is* the executed
hand-off. The closure does not weaken any gate: the M2 gate's A25 clause
(*"real-endpoint smoke incl. two-day OTS pending→upgraded cycle complete"*)
is met on the same measurement, and the client-path refinement is checked
separately by the same review through the matrix, where `V7.1` at `gap`
is red-unless-ruled whatever this record does.

**3.4 — What this record deliberately does not rule** — see §4.

---

## 4. The boundary: V7.1, Q236, D127

The submit-path residue — **antseal's A13 submit path has never spoken to
a real calendar** (day-1 2026-08-11 was by hand; day-2's recorded consent
scope excluded fresh submissions) — **stands**, and this record neither
closes it, re-homes it, nor adjudicates its disposition. It is `V7.1`'s
(`gap`, with the residue and both exit paths recorded in the cell) and
Q236's (the gate that cannot slide past a `gap` M2 row); the choice
between *one consented script-driven submit pair* and *ruled on the record
at the M2 review* is **D127's**, being ruled by a sibling planner in this
same session. What this record does rule is only the conjunction: A25's
four Accept rows never named the submit path, so they can close while the
residue stands — exactly as Q99's rows did on 2026-08-11, with the
qualification recorded and single-homed. If D127 orders the submit pair,
that run is a **new campaign** under its own fresh §1 consent, committed
beside the old captures per runbook §5; nothing in A25 reopens for it.

---

## 5. Consequences — the edit set

**This lane wrote one file: this one.** Everything below is instruction
for the registrar; exact texts are normative, paths absolute in the lane
report.

1. **`tasks/A.md` §A25, end of the `Do` paragraph** — append the dated
   strike note (text in the lane report, edit 1): clause discharged on
   the wave16-cycle campaign, struck with the trigger-owners enumerated,
   residue pointer to V7.1/Q236/D127.
2. **`tasks/A.md` §A25, after the day-2 bullet** — append the closure
   bullet (lane report, edit 2): four rows measured, boundary stated.
3. **`tasks/Q.md` §Q26** — `Deps` gains A25; `Do` gains the (a)–(e)
   hand-off block with the (f) exclusion named (lane report, edits 3–4).
4. **`TODO.md` line 419** — `[ ]` → `[x]`, closure summary appended
   (lane report, edit 5); decision register gains the D126 row (edit 8);
   `docs/decisions/README.md` gains the index row (edit 7).
5. **`testdata/anchors/README.md`** — the `A25-wave16-cycle` table row
   updated for day-2 (it still reads *"day-2 upgrades owed"*), and the
   preamble's stale *"Two of the three record their maintainer
   authorisation"* corrected to *three of the four* (lane report,
   edit 6).
6. **`docs/anchors/real-smoke-runbook.md` §3.4** — one sentence recording
   that the hand-off executed (lane report, edit 9).
7. **No code, no fixtures, no frozen bytes, no error codes, no format
   surface.** No capture log is edited (A107's rule: a capture log
   records what was observed).

---

## 6. Discovered work — described, not registered (D125 rule 8)

No ids are minted here.

**(i) `testdata/anchors/README.md` counts campaigns as three while
tabulating four.** The preamble's *"Two of the three record their
maintainer authorisation"* predates `A25-wave16-cycle`; the truthful
count is three of the four (only `A16-A17-live/` lacks its own recorded
consent). Cured by §5 item 5; ledger line proposed in the lane report —
the class is provenance-README prose rotting when a campaign is appended.

**(ii) `tasks/A.md` §A48's `Deps` still carries the scheduling constraint
*"not before 2026-08-04"*.** Flagged stale by the 2026-08-07 adjudication
(*"the limits doc and A48's own `Deps` are outside this lane's files"*);
the limits-doc half was executed by A106 ✅, the `Deps` half never was.
A48 closed 2026-08-10, so the line is historical residue on a closed row —
recorded, no edit ordered.

**(iii) Q26's `Do` presented operator-published rate caveats without the
published-not-measured qualifier** — the product-doc face of finding (e),
cured by the hand-off itself; noted so the M4 lane understands the
qualifier is load-bearing, not stylistic.

---

## Outcome

The clause did its job and is retired on the evidence of the campaign it
demanded: a full protocol re-run at task completion exists on disk, at
the product's own calendars, mostly through the product's own clients,
consented per day and logged to the runbook's own standard. What the
clause could never do — carry the one genuinely open demand, that the
submit path speak to a real calendar — was never its to carry: that
demand lives where it is machine-checked and gate-enforced, and its
disposition belongs to the sibling record. The hand-off stops being a
promise and becomes text in the receiving task's own entry, with the one
number that was ever in dispute left to its citation. A25 closes the way
Q99 closed the same morning: on its rows, with the residue on the record,
in exactly one place.
