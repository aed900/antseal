# D165 — the recurrence gap is real, but the standing population is **not the shape a leak takes**: 612 findings resolve to **51 distinct lines** and **12 markers**, and **not one of them is a bare marker on its own line** — so `Q266` is wired as one **full-store** `local-gate.sh` step against a baseline that registers **digests with reasons**, refuses to suppress a stand-alone key line, and hard-fails on a registration that suppresses nothing; the `--since` routine arm is **REFUSED against the row's own `Do`**, and CI is **refused this wave** as a named live debt

- **Status: RESOLVED. The recurrence gap is confirmed and wired; the *shape*
  the brief assumed for the fix is OVERTURNED BY THE COMPOSITION MEASUREMENT,
  and one clause of the row's own `Do` is REFUSED.**
  - **The 612 are not 612 problems.** They are **407 distinct objects**
    carrying **51 distinct matched lines** carrying **12 distinct marker
    strings**. A resolution model sized to 612 — or to 407 — is sized to the
    wrong number by an order of magnitude, and a model sized to *markers* is an
    allowlist wearing a baseline's clothes. §1.2.
  - **The separation between the population and a leak is MEASURED, not
    asserted.** `grep -cxE` for each rule's own marker form over the 51 distinct
    lines returns **0**. Every one of the 612 is a marker embedded in a table
    cell, a sentence, a grep pattern quoted in a lane script or a workflow, or a
    printf that assembles a fixture at run time. **A real committed key's first
    line IS a bare marker line.** That single measurement is what makes a
    digest-keyed baseline safe, and it is what §2 R3 turns into a refusal. §1.2.
  - **`--since` is REFUSED, against the row's own `Do`**, which says *"Prefer
    `--since <last-scanned-rev>` for the routine arm"*. `--since` exists to make
    a slow scan affordable; the full-store scan is **25.8 s**. Adopting it needs
    a last-scanned-rev high-water mark, and **a state file that goes stale
    between waves is the dated document `Q266` exists to abolish, in a different
    file format**. §2 R7a.
  - **CI is REFUSED this wave and re-homed as a live debt with an owner and a
    timing word** — not dropped. A CI lane needs `fetch-depth: 0`, an assertion
    that the depth *stays* 0, a lane, and an edge classification; that is a
    second lane's work, and §2 R6 is what makes deferring it **safe** rather than
    merely convenient. §2 R7b.
  - **The finding nobody was looking for: a shallow store balances the
    arithmetic.** In a `--depth 1` clone the script's reachability invariant —
    the assertion that makes *"superset"* a measurement — **still balances**, so
    it does not catch it, and the script prints a confident verdict over **1 of
    718 commits** under a summary line textually identical to a full run. §1.7,
    §2 R6.
- **Date: 2026-08-29**
- Owner rows: **`Q266`** (this record rules its `Do` and its four `Accept`
  clauses). This record ticks nothing. `Q2` is named, not ruled.
- Related: **`Q269`'s personal-data guard** — the precedent §2 R1 borrows
  wholesale: a denylist that stores **SHA-256 digests and never the strings**,
  registered **per name with a reason and a ceiling**, because *"a single total
  lets one item appear while another disappears and the sum never moves"*;
  **`Q268`** (the direct-SHA exposure — a GitHub-side fetch, **not** an
  object-store scan, and untouched here); **`Q65`** finding 2 (the pre-public
  scrub this makes repeatable) and **`Q65`'s flip** (the deadline `Q266` is
  written against); **D144** (an accepted exposure is carried as a **registered
  count**, never as silence — the same instrument shape); **D162 §2 R6** and
  **D159 §2 R1** (a check whose subject can collapse to zero needs a floor;
  §2 R4/R5 are this record's form of that discipline); **`scripts/check-ci-paths.py`
  rule R4e** (a registered edge that no longer exists is a hard failure — the
  rule §2 R4 mirrors); **rule 8** (considered for the venue question and
  refused, as `Q266`'s own `Notes` already record).

---

## 0. What was measured against

Read in full: `scripts/scrub-history.sh` — its header (including the section
headed *WHY THIS FILE CONTAINS NO SECRET-SHAPED LITERAL*), `RULE_IDS`,
`rule_desc`, `rule_line_re`, `rules_scan`, `assert_reachability`,
`materialise`, and the entry point's argument handling; `scripts/local-gate.sh`'s
personal-data steps and its final exit; `scripts/ci-lanes.sh` for every mention
of a personal-data or history instrument; `scripts/check-ci-paths.py`'s
`FOLLOW_EDGES` / `UNREACHED_EDGES` classification and rule R4e;
`scripts/check-personal-data.py`'s header and its two arms; `TODO.md`'s `Q266`
row and `tasks/Q.md`'s `### Q266` entry (`Do`, all four `Accept` rows, `Notes`);
`docs/reviews/pre-public-scrub-history.md`.

Measured at **`ae4e167`** on **2026-08-29** by running the scan and by `git`,
not quoted from a record. **No network command was run, no object was written
to this repository's store, no build was started, and neither `local-gate.sh`
nor any `--self-test` was invoked.** Every exit status below was read back out
of a file, never from a `| tee` wrapper.

---

## 1. What was measured

### 1.1 The full-store run, in one line

```
objects=8026 blob=3703 tree=3604 commit=718 tag=1 reachable=8024
unreachable=2 scanned=4422 bytes=229419571 rules=11 findings=612
verdict=FINDINGS
REAL_EXIT=1      25.8s
```

Two facts the summary carries that matter later. **The reachability invariant
balanced** (`8026 − 8024 = 2`, and `git fsck` reports 2), which is what entitles
the run to call its corpus the whole store. And **`rules=11`** is derived from
the script's own scan body, not from a literal, so a rule added without a
scanner would show up as a count that did not move.

**On the earlier figure, stated rather than harmonised.** `Q266`'s row records
**7 935** objects on 2026-08-16 and **8 439** on 2026-08-27. The number above is
**8026**, and the two are separated by the history rewrite recorded under
`Q268`. **This record does not re-derive the 2026-08-27 count and does not
attribute the difference**; it reports what this scan measured, at the commit it
measured it at. A comparison across a rewrite is a different measurement from
the one that was taken, and the register should not inherit one for the other.

### 1.2 THE COMPOSITION FINDING — 612 → 407 → 51 → 12, and **zero** of the shape that matters

| level | count | what it is |
| --- | --- | --- |
| findings | **612** | `(rule, object)` hits over the whole store |
| distinct objects | **407** | the objects those hits live in |
| **distinct matched lines** | **51** | 47 across `R1`/`R3`/`R4a`/`R4b`/`R4c`/`E1`, 4 across `R2`'s conjunction |
| distinct marker strings | **12** | the marker text inside those lines |
| **bare marker lines** | **0** | `grep -cxE` of each rule's marker form over the 51 |

The last row is the ruling's whole foundation. **Zero of the 612 hits is a
marker standing alone on its own line.** Every one is *embedded* — in a table
cell, in a sentence of prose, in a grep pattern quoted inside a lane script,
a workflow or a verification document, or in a `printf` that assembles a test
fixture at run time. The one shape that is **absent from the entire store** is
the shape a real committed key has: **its first line is a bare marker line.**

That is why this is a measurement and not a hope. The standing population and
the leak occupy **disjoint line shapes**, and §2 R3 makes the disjointness
load-bearing by refusing to suppress anything on the leak side of it.

Because 612 is a **history-wide** count, and history is append-only, an
append-only baseline over the whole store is stable by construction; and
because the 51 are lines rather than objects, **editing a file that contains one
of them does not create a new finding**. That property is what makes the model
survive routine work on `TODO.md`, and it is stated as §2 R2.

### 1.3 Where the 612 live, and why that shape is expected

| path | hits |
| --- | --- |
| `TODO.md` | 176 |
| `scripts/ci-lanes.sh` | 122 |
| `docs/ci-verification.md` | 82 |
| `.github/workflows/ci.yml` | 68 |
| `tasks/U.md` | 36 |
| `docs/decisions/D71-…` | 15 |
| … tail | remainder |

Every heavy path is a document **about the guards** or a script that **carries
the guards' own patterns**. This is the self-reference problem
`check-personal-data.py`'s header names in terms — *"a report that documents
what it searched for reproduces the very string it was looking for"* — arriving
one corpus over. It is the expected distribution for a healthy tree, and it is
the reason a resolution model was needed at all.

### 1.4 A baseline holding literals is **self-defeating**, not merely inelegant

`scripts/scrub-history.sh`'s header already forbids committing a secret-shaped
literal, and gives two reasons: a literal here would red `secret-guard`, and —
the one that governs — **committing a literal poisons every future run of this
script, permanently, because history is append-only.**

A baseline whose entries carry the matched text would be exactly that literal,
in a file the script reads on every run. It would red the sibling guard, it
would be unremovable without a garbage collection, and it would make the
instrument the next leak. **The prohibition is not an obstacle the baseline has
to work around; it is the constraint that picks the design.**

### 1.5 The answer is already implemented in this tree, one corpus over

`scripts/check-personal-data.py` faced the identical problem and solved it:
store **SHA-256 digests, never the strings**; register **per name, with a
reason**; assert **per-name counts**, on the recorded ground that a single total
lets one item appear while another disappears and the sum never moves. It can
name the class and the location of a hit while being **physically unable to
print the value it matched**.

§2 R1 and §2 R5 are that design applied to the object store. Nothing is
invented here that this repository has not already run.

### 1.6 The venue question, measured — and a gate step is **not** a CI edge

```
occurrences of check-personal-data in scripts/ci-lanes.sh   : 0
occurrences of check-personal-data in scripts/local-gate.sh : 2
   (steps `personal-data-selftest` and `personal-data`)
```

Two consequences, both load-bearing:

1. **The precedent for a history/identity instrument in this repository is a
   `local-gate.sh` step, not a lane.** `Q266`'s sibling `Q2` is cited by the row
   as carrying the same hole; the guard that actually landed for `Q268` chose
   the gate.
2. **A `local-gate.sh` step manufactures no `check-ci-paths.py` classification.**
   That checker's domain is edges out of scripts that CI runs. A gate step is
   not such an edge, so wiring here creates **no `UNREACHED_EDGES` residue** and
   nothing has to be classified in the same commit. A CI lane *would* create
   one — which is a cost of §2 R7b's deferred option, not of §2 R7's chosen one.

**Locators, deliberately not by line number.** The two personal-data steps sat
at `scripts/local-gate.sh:542-543` at `ae4e167`; a lane is inserting a step into
that file in this very wave, so the anchor for every citation here is the **step
name** (`personal-data`, `scrub-history`), never the number. Locator drift of
exactly this kind has been recorded seven times.

### 1.7 Depth: the invariant that cannot see a shallow store

In a `--depth 1` clone the store is small, complete *as a store*, and internally
consistent: **the reachability arithmetic balances**, because every object
present is reachable and `git fsck` reports nothing unreachable. The invariant
that makes a clean verdict trustworthy on a full store is **silent** here, and
the script prints `verdict=CLEAN` over **1 commit of 718** under a summary line
whose shape is indistinguishable from a full run.

The correct predicate is the repository's own shallowness — not the commit
count. **`commit=1` is a legitimate state for a new repository**, and keying on
it would make the script refuse to run on the very tree a new contributor has.

---

## 2. RULING

### §2 R1 — Resolution model: a baseline of **digests with reasons**, never of literals

Baseline at `scripts/scrub-history-baseline.tsv`, one record per line:

```
<sha256-hex>  <rule-id>  <class>  <reason>
```

- **Key = (rule-id, digest).** The digest is the **SHA-256 of the matched
  line**, leading and trailing whitespace stripped, **no other normalisation** —
  one rule, stated once, so the detector and the resolution model cannot drift.
- **NO ENTRY MAY CONTAIN A SECRET-SHAPED LITERAL.** The `reason` names the
  **class and the site in prose** and never reproduces the marker (§1.4).
- **Classes:** `GUARD-PATTERN`, `FIXTURE-ASSEMBLY`, `RECORD`, `RESERVED-MAGIC`,
  `TRACKER`.
- **The lane RE-DERIVES the count.** **51** is the figure measured at `ae4e167`
  in §1.2; it is not an inheritance, and a lane that finds a different number has
  found a fact, not a discrepancy to be reconciled away.

### §2 R2 — What suppression means, and what it deliberately does not cover

A hit on a **new** object is suppressed **iff `(rule, digest)` is registered**.

- A new object carrying **only registered lines is silent.** This is precisely
  what lets the baseline survive editing `TODO.md`, which is the file with the
  largest share of the population (§1.3).
- **A NEW LINE IS A NEW DIGEST AND REDS.** Rewording a sentence that quotes a
  marker produces a finding, and that is correct: the new line has never been
  read by anyone.
- **Registration is a maintainer act performed in the commit that adds the
  entry**, with the reason written **then**. Never batched, never backfilled.

### §2 R3 — THE ANTI-VACUITY GUARD ON SUPPRESSION, and it is the load-bearing clause

**Suppression is REFUSED and the run REDS when the line about to be suppressed
is — whitespace stripped — EXACTLY one of the rule's marker forms**, i.e. a
stand-alone key-material line.

The message says so in terms: *the digest is registered, but the line stands
alone, which is the shape a real key takes, so the registration cannot cover
it.*

**Measured cost today: 0 of 612** (§1.2). This is the single clause that stops
the baseline degenerating into a marker allowlist — without it, one careless
registration of a bare marker line would suppress the real thing for ever, and
every subsequent run would report `CLEAN` for exactly the reason it should not.

### §2 R4 — A registered entry that suppresses nothing is a HARD FAILURE, described honestly

A registered `(rule, digest)` that suppresses **nothing** in a full run fails the
run and **names the digest**, mirroring `check-ci-paths.py`'s R4e.

**Stated honestly, because the alternative is a claim this check cannot
support:** because history is append-only, this fires mainly on a **mistyped
digest at registration**, and secondarily **after a history rewrite**. It is
**NOT a live drift detector and must not be described as one** anywhere. What it
does buy is that a registration which never matched cannot sit in the file
looking like coverage.

### §2 R5 — The summary line MUST NOT carry a single total

The summary gains **`baselined=<n>`** and **`baseline_entries=<n>`** alongside
`findings=`, where **`findings=` counts UNSUPPRESSED hits only**.

§2 R4 is what makes the pair meaningful: without it, the two numbers can move in
opposite directions and the reader cannot tell. **The totals alone are not
evidence** — the same reasoning `check-personal-data.py` records for asserting
per-name counts rather than a sum.

### §2 R6 — DEPTH DISCIPLINE: the script MUST REFUSE a shallow store

Before any enumeration, `git rev-parse --is-shallow-repository` returning true
(or `.git/shallow` existing) produces a **named error** and returns 1.

- **No structural change to the verdict logic is required.** The existing entry
  point already renders that as `verdict=INVARIANT-FAILED`, because the findings
  count is 0 on that path.
- **The justification is measured, not precautionary:** in a real `--depth 1`
  clone the reachability arithmetic **balances**, so the existing invariant does
  not catch it (§1.7).
- **DO NOT key on `commit=1`.** That is a legitimate state for a new repository.

This ruling is also what makes §2 R7b's deferral safe: **after §2 R6, a shallow
CI wiring cannot report a false clean** — it fails loudly instead.

### §2 R7 — VENUE AND TENSE: one `local-gate.sh` step, FULL-STORE, every gate run

Wired as **`run scrub-history scripts/scrub-history.sh`**, placed adjacent to the
personal-data steps (§1.6's anchor is the step name, not a line number).

Rationale, in order of weight:

1. **The maintainer's machine is the only venue with real history.** A CI
   checkout has none worth scanning, which is the whole of §2 R7b's problem.
2. **A gate step is not a `ci-lanes.sh` edge**, so it creates no
   `check-ci-paths.py` classification and no second residue of the class a
   sibling lane had to add mid-gate a wave ago.
3. **25.8 s full-store** (§1.1). Cost is not an obstacle, and saying so is what
   removes the only argument for §2 R7a's alternative.
4. **`local-gate.sh` is the wave-close ritual**, so *"re-runs without anyone
   remembering"* — the row's own words — is satisfied by the step existing.

### §2 R7a — THE `--since` ROUTINE ARM IS **REFUSED**, against the row's own `Do`

`Q266`'s `Do` says *"Prefer `--since <last-scanned-rev>` for the routine arm"*.
**Refused, and the refusal is the point of this sub-ruling.**

- `--since` exists to make a **slow** scan affordable. **25.8 s is not slow.**
- Adopting it requires a **last-scanned-rev high-water mark**, and **a state
  file that goes stale between waves is the dated document `Q266` exists to
  abolish, in a different file format.** The row was minted because
  `docs/reviews/pre-public-scrub-history.md` was current as of one commit and
  stale after the next; a rev marker in a tracked file fails the identical way,
  more quietly, and with a summary line that still looks like a full answer.
- **The full arm has no state to rot and cannot be silently narrower than it
  looks.**
- The row's `Accept` clause *"the routine arm names the revision it scans
  from"* is satisfied **a fortiori**: the header already prints the scanned
  `HEAD` short sha and the mode, and a full-store mode is not narrowable.
- **`--since` stays available for hand use.** Nothing is deleted; it stops being
  the routine arm.

### §2 R7b — CI IS **REFUSED THIS WAVE**, with the reason recorded and the debt re-homed

A CI lane for this scan needs four things that do not exist: **`fetch-depth: 0`**;
**an assertion that the depth stays 0** — nothing asserts `fetch-depth` anywhere
in this tree today; **a `ci-lanes.sh` lane**; and **a `check-ci-paths.py`
edge**. That is a second lane's work, and §2 R6 makes deferring it **safe**
rather than merely tolerable.

- **LIVE DEBT. OWNER: the wave-33 CI lane. TIMING WORD: before `Q65`'s flip.**

It is recorded as a debt with an owner and a deadline precisely so it is not
re-discovered as a finding two waves from now, which is the failure mode
`Q266` itself documents.

### §2 R8 — GATE-ENTRY PRECONDITION for the implementing lane

The implementing lane's **first act** is to run the full scan **with the
baseline in place**. **If `findings=` is not 0, the lane STOPS AND REPORTS**,
and §2 R7 is **void for this wave** — no step is wired.

A gate step added while the scan is red wires a known-red check into the ritual,
and the next reader cannot tell an unresolved population from a real leak.

---

## 3. Fault plants — five, each red **BY ITS MESSAGE**, and one safety constraint that is itself ruled

Exit status is not evidence. Each arm below must be confirmed by the **text** it
prints, with `REAL_EXIT` read back **from a file**.

| # | plant | required red |
| --- | --- | --- |
| 1 | **Shallow refusal.** Clone the throwaway repo `--depth 1` and run inside it. Plant: **invert the is-shallow test**. | stderr names the **shallow store**, summary reads `verdict=INVARIANT-FAILED`. The planted arm must fail saying **a verdict was reported over a shallow store**. |
| 2 | **§2 R3 bare-line guard.** In the throwaway repo, register the digest of a **bare marker line assembled at run time** and commit an object containing it. Plant: **disable the stripped-equality test**. | the **registered-but-stand-alone** message. |
| 3 | **§2 R4 stale entry.** Append a digest of a string **no object contains**. | the **stale-entry** message **naming the digest** — which is what proves §2 R4 is not vacuous. |
| 4 | **Suppression is not blanket.** Commit an object carrying an **UNREGISTERED** line under a rule that already has registered entries. | the ordinary **HIT** line under that rule, with **`findings=1` and `baselined>0`** — proving `baselined>0` does not imply silence. |
| 5 | **Gate wiring.** Force the script to exit 1 with a distinctive message and run the gate. | the **`scrub-history` step FAILs** and the overall gate status is **nonzero** through its final exit. `REAL_EXIT` from a **file**, never from a `\| tee` wrapper. |

### PLANT SAFETY — **RULED**, not advisory

**No plant may write an object into, or commit against, THIS repository's own
object store.** Every plant lives in the `--self-test` throwaway repository
under a `mktemp -d`.

The reason is §1.4's, sharpened: **a secret-shaped literal written into the real
store is unremovable without a garbage collection, and would red every future
run of this scan permanently.** A fault plant that damages the instrument it is
testing is not a test.

*(Numbered outside §2 deliberately: these arms are normative and this
constraint is a ruling, but no new `§2 R<n>` id is minted for them, so no
surface citing this record has to disambiguate one.)*

---

## 4. What this record does **NOT** settle

- **The rules themselves.** No rule is narrowed, widened, or given a body
  requirement. Whether `R1` should additionally require a base64 body is a real
  question and is **LEFT OPEN**; the script's prohibition on secret-shaped
  literals stands untouched.
- **The CI venue**, `fetch-depth: 0`, and an assertion that the depth stays 0
  (§2 R7b, re-homed with an owner and a timing word).
- **`Q2` / `secret-guard`'s own recurrence gap.** Only its `.git` exclusion is
  documented here, as the fact that makes `Q266`'s claim true; the sibling row
  is named, not ruled.
- **Whether any of the 612 is a leak.** The **naming of each resolution is the
  maintainer's act**, performed when the entry is written (§2 R2). This record
  rules the **mechanism**, not the verdict.
- **`Q268`.** Unaffected. That is a direct-SHA fetch against a remote, not an
  object-store scan, and no ruling here touches it or discharges it.
- **Whether the wave-31 object counts and this wave's are comparable.** §1.1
  states both and attributes neither.

---

## 5. Edit list — per write scope, with the timing word

Ordering words below are the register's. **Nothing here is an external action**,
and nothing here is a network call.

### Scanner scope — `scripts/scrub-history.sh` and `scripts/scrub-history-baseline.tsv`

1. **The depth refusal (§2 R6)** — first, before any enumeration, keyed on the
   repository's shallowness and **not** on the commit count. **before** every
   edit below, because a wrong-corpus scan cannot be baselined meaningfully.
2. **The baseline reader and the suppression path (§2 R1, §2 R2)**, keyed
   `(rule-id, digest)`, digest over the whitespace-stripped matched line, using
   the existing `rule_line_re` register as the **single source of truth** so the
   detector and the resolution model cannot drift apart. **with** edit 3.
3. **The anti-vacuity refusal (§2 R3)** — stripped-equality against the rule's
   marker form, refusing suppression and reddening. **with** edit 2: shipping
   suppression without its refusal is the one ordering that must not occur, even
   transiently.
4. **The stale-entry hard failure (§2 R4)**, naming the digest. **after** edit 2.
5. **The summary line (§2 R5)** — `baselined=` and `baseline_entries=` added,
   `findings=` redefined to unsuppressed hits only. **after** edits 2–4.
6. **`scripts/scrub-history-baseline.tsv` is created**, one line per registered
   `(rule, digest)` with class and prose reason, **no literal**, count
   **re-derived** (§2 R1). **with** edit 2.
7. **The five arms of §3** added to `--self-test`, every one inside a
   `mktemp -d` throwaway repository. **after** edits 1–6.

### Gate scope — `scripts/local-gate.sh`

8. **One step, `run scrub-history scripts/scrub-history.sh`**, full-store,
   adjacent to the personal-data steps. **after** §2 R8's precondition run comes
   back `findings=0` — and **not at all** if it does not.

### Registrar scope — `TODO.md`, `tasks/Q.md`, `docs/decisions/README.md`

9. **`Q266`'s row and `### Q266`** — record §2 R7 (venue), §2 R7a (the `--since`
   clause of its own `Do` is **REFUSED**, with the reason), §2 R7b (the CI debt,
   **owner: the wave-33 CI lane; before `Q65`'s flip**), and which `Accept`
   clauses this record's edits satisfy. **after** the scanner and gate scopes
   land.
10. **The `D165` index row.** **Registrar's edit, not a lane's** — this record
    does not write it.

### Nothing else

**No workflow file is touched** (§2 R7b). No file under `crates/`, `testdata/`
or `.github/` is in this record's edit list, so **no build, no golden vector and
no tamper-matrix row is affected**, and the `wasm32-unknown-unknown` surface is
untouched. The instrument-finding ledger is the registrar's surface and is
deliberately not part of any lane's edit set here.

---

## Closing — this record is not consent, and it adds no digest

This record rules a **local, read-only scan** and its wiring into a **local**
gate. It authorises no push, no visibility change, no repository setting, and no
network call, and nothing in it is consent for any external action.

**It was also written to match none of the eleven rules.** Every marker is named
by **class** — the PEM block, the keystore JSON pair, the reserved vault-export
magic, the age marker, the minisign/rsign header and body tag, the devnet wallet
export line, the PGP block, forge tokens, AWS key ids, Slack tokens — and never
reproduced, so this record contributes **no new line to the baseline's domain**
and needs no entry of its own. A decision record about a secret scanner that
reds the scanner would be the defect installed in the instrument, one document
over.
