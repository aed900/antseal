# D166 — an unwitnessed release workflow does **NOT** land: all three of the survey's premises were mis-measured — `Q31`'s documentation half landed a wave ago, the CI refusal is **billing** and provably separable from the publish flip, and the remedy is **maintainer-only** — and `Q32`'s `after Q31` is **DISCHARGED CLAUSE-WISE**, because no clause of its `Accept` needs `release.yml` to exist

- **Status: RESOLVED. The answer to the question as asked is NO, and the lean
  that produced the question COLLAPSES ON ITS OWN TEST.**
  - **The edge said to justify landing it does not exist.** The house test —
    *name the clause of `Q32`'s `Accept` that cannot be written until `Q31`'s
    `Do` has landed* — was walked over all three clauses. **None names
    `release.yml`.** The one candidate consumes a **documented channel** and a
    **version/tag scheme**, and both landed in **`0ae2c96`**, a wave ago. §1.5.
  - **Premise 1 was measured in the wrong place.** *"`Q31`'s `Do` is measurably
    unbuilt"* rested on `ls docs/` — **non-recursive**. `docs/user/versioning.md`
    (**225 lines**) and `docs/user/release-checklist.md` (**403 lines**) have
    existed since wave 28, exactly as `Q31`'s own 2026-08-22 `Notes` say. What is
    genuinely absent is the **pipeline**, and that is a narrower claim. §1.1–§1.2.
  - **Premise 2 is now diagnosed, and it is BILLING.** The register's standing
    note that *"the annotation is a disjunction"* is **SUPERSEDED**: the
    disjunction is **internal to billing** (failed payment *vs* spending limit).
    It has **no branch** touching the publish flip, workflow contents,
    permissions, or `sha_pinning_required` — **separable from the flip, as the
    register suspected, now measured.** §1.3, §2 R6.
  - **Premise 3: the diagnosis is complete and the remedy is not agent-reachable.**
    The token cannot read billing at all. That makes this **NOT-YET-WITNESSED**
    rather than **UNWITNESSABLE** — and banking an unverifiable artifact for a
    witness expected within days buys nothing. §1.4, §2 R1(b).
  - **The finding that outlives this wave.** `Q31` `Accept` row 1 — *"A dry-run
    tag produces a complete signed draft release"* — is **UNSATISFIABLE BY ANY
    WORKFLOW**, by three independent rulings and instruments already in this
    tree. It is a **TWO-ACTOR** clause, and a future reader must not tick it by
    pointing at a workflow. §1.6, §2 R5.
  - **No fault plant is minted, and that is a ruling with a number behind it.**
    The obvious guard would fire **0 times today**, and the worst concrete
    outcome is **already guarded** by a checker that reds without a line of new
    code. **Measured yield of a new checker: ZERO.** §3.
- **Date: 2026-08-29**
- Owner rows: **`Q31`** (stays **OPEN**; §2 R2 states what its `Do` must contain
  and what is owed before an agent may write it) and **`Q32`** (measured
  **lane-available today**). This record ticks nothing.
- Related: **D71 §2 R1/R7** (the signing key is on no runner — the ruling that
  makes §2 R5's two-actor finding structural rather than stylistic);
  **D163 §2 R1** (`after X` is discharged **clause-wise** when `X`'s `Do` is
  multi-clause) and **§2 R6/R7** (repairs never by deletion; a discharged term
  stays in the run); **D156 §2 R1** (what a tick means) and **§2 R7** (a
  `before` clause is a **deadline**, not a precondition); **D143 §2 R5** (the
  `sha_pinning_required` deferral and `Q255`, its named blocker); **D141 §2 R1**
  (`Q31` requires no external party — unaffected here); **D161 §2 R7** (no
  required status context on the *expectation* of free runners — the same
  discipline §2 R6 applies to the billing gate); **D153 §2 R9** (`Q258`, the row
  that exists because maintainer-only acts otherwise have no home).

---

## 0. What was measured against

Read in full: `tasks/Q.md`'s `### Q30`, `### Q31`, `### Q32` entries — `Do`,
every `Accept` row, every `Notes` block, including the D156 and D163
annotations; `TODO.md`'s `Q31` and `Q32` rows; every file under
`.github/workflows/`; `.github/action-pins.tsv`; `scripts/sign-release.sh`'s
custody statement; `scripts/check-ci-paths.py`'s classification of the
`ci-lanes.sh → sign-release.sh` edge; `scripts/check-action-pins.py`'s rules and
its gate invocation; `docs/user/versioning.md`; `docs/user/release-checklist.md`;
`docs/signing/verifying-a-release.md`.

Measured on **2026-08-29** at `ae4e167`. Two **read-only** GitHub API calls were
made — a run's job list and a billing endpoint that refused — and their results
are quoted verbatim in §1.3 and §1.4. **No API write was attempted, no
repository setting was read back or changed, no token scope was widened, no
build was started, and no `--self-test` was invoked.** Every exit status was
read back out of a file.

**Locators.** Script sites below are anchored by **quoted string or symbol
name**; where a line number appears it is *"at `ae4e167`"* and is not the
citation. Two of the files named are in other lanes' write scopes this wave, and
a locator that rots silently is the defect this project has recorded seven times.

---

## 1. What was measured — three corrections, and a fourth finding

### 1.1 CORRECTION 1 — the wrong-directory measurement

The survey reported `Q31`'s `Do` *"measurably unbuilt"* on the strength of
`ls docs/ | grep -iE 'release|version'` returning empty. **`ls` is
non-recursive, and it looked in the wrong place.** Verified directly:

| file | lines | bytes | landed |
| --- | --- | --- | --- |
| `docs/user/versioning.md` | **225** | 12306 | **`0ae2c96`** (wave 28) |
| `docs/user/release-checklist.md` | **403** | 22571 | **`0ae2c96`** (wave 28) |

`Q31`'s `Do` is **PARTIALLY LANDED**, exactly as its own 2026-08-22 `Notes`
already state: `Accept` row 2 (the versioning doc) and row 3's checklist half
are met, and row 5's escape branch is written with **`Q255`** named as its
blocker.

This correction matters beyond the bookkeeping. A premise that a row is
*entirely* unbuilt is what makes *"land something, anything, this wave"* sound
reasonable; the measured state is that the row's documentation half is **done**
and only its riskiest half remains.

### 1.2 What IS genuinely absent — the pipeline, stated narrowly

```
$ ls .github/workflows/ | wc -l
8                                            REAL_EXIT=0
$ grep -rn -- '--release' .github/workflows/ | wc -l
0                                            REAL_EXIT=1
```

Eight workflow files, **none of them a release workflow**, and **no job in this
repository builds a release binary at all**. That is the true gap, and it is the
one `Q31` `Accept` row 4's glibc-floor clause has been describing as *"a
property of a hypothetical build"*.

### 1.3 CORRECTION 2 — the CI refusal is **DIAGNOSED**, and it is **billing**

Run **`33256595248`** → jobs **`traceability`** and **`secret-guard`**, both
**`failure`**, **`steps: 0`**. The annotation, **verbatim**:

> "The job was not started because recent account payments have failed or your
> spending limit needs to be increased. Please check the 'Billing & plans'
> section in your settings"

Three properties of that sentence, each load-bearing:

1. **The disjunction is INTERNAL TO BILLING** — a failed payment *versus* a
   spending limit. Both branches are billing. The register's standing note that
   *"the annotation is a disjunction"* was true as text and has been read as
   *"one branch might be the flip"*; **it is not**.
2. **It has no branch touching anything file-shaped**: not the publish flip, not
   workflow contents, not `permissions:`, not `sha_pinning_required`.
3. **`steps: 0`** — the jobs never started. Nothing in the repository was
   evaluated, so nothing in the repository can be the cause.

Failures run back to at least **`2026-08-27T23:37:00Z`**, across **`ci`** and
**`ci-always`** alike. An account-level gate explains a uniform refusal across
unrelated workflows; a file-shaped cause does not.

**SEPARABLE FROM THE FLIP — confirmed by measurement**, which is what the
register suspected and could not show.

### 1.4 CORRECTION 3 — the token cannot read billing, so the remedy is not agent-reachable

```
$ gh api /users/aed900/settings/billing/actions
404
gh: This API operation needs the "user" scope
```

The diagnosis is **complete** at exactly this depth: it is billing, and which of
the two billing branches it is **cannot be read from here**. Widening the token
is **itself an external act**. This record therefore states the remedy as
**owed, with an owner and a timing word**, and **instructs no agent to take it**
(§2 R6).

### 1.5 The house test, walked clause by clause — does `Q32`'s `Accept` depend on `Q31`'s `Do`? **NO**

The test is D154 §2 R10 as amended by **D156 §2 R1**: *name the clause of the
successor's `Accept` that cannot be written until the predecessor's `Do` has
landed.* All three of `Q32`'s `Accept` rows were walked.

| `Q32` `Accept` clause | what it consumes from `Q31` | verdict |
| --- | --- | --- |
| 1. *"Scripts committed and re-runnable; Sepolia run green before any mainnet action"* | nothing. The scripts are `Q32`'s own; the Sepolia half is a **`before` deadline** already ruled a deadline and not a precondition (D156 §2 R7). A release-candidate binary comes from `cargo build --release`, not from a workflow file. | **NO DEPENDENCY** |
| 2. *"Clean-machine procedure uses zero repo-checkout resources (released artifacts + hosted page only)"* | **the only candidate.** `Q32`'s `Do` (b) has the VM *"install only the released binary from the documented channel, verif\[y\] its signature per Q22 instructions"* — so it consumes a **documented channel** and a **version/tag scheme**. Both landed: `docs/user/versioning.md`, `docs/user/release-checklist.md`, and from `Q30` `docs/signing/verifying-a-release.md`. The clause is about the procedure's **shape**. | **NO DEPENDENCY** — writable today |
| 3. Disk-loss drill | names nothing of `Q31`'s. | **NO DEPENDENCY** |

**No clause of `Q32`'s `Accept` requires `.github/workflows/release.yml` to
exist.** `after Q31` is therefore **DISCHARGED CLAUSE-WISE** under D163 §2 R1 —
the same construction `Q31` itself already uses for its own `after Q1`. **The
lean collapses on its own test.**

### 1.6 THE FOURTH FINDING — `Q31` `Accept` row 1 is unsatisfiable by any workflow

*"A dry-run tag produces a complete **signed** draft release"*, read as a
single-actor clause, is unsatisfiable **by construction**, and three independent
sources in this tree already say so:

1. **D71 §2 R1/R7** put the signing key off every runner.
2. `scripts/sign-release.sh` states it in terms: *"The secret key is never on a
   CI runner, in a GitHub secret, in a KMS, or in this checkout … Signing is a
   local act."*
3. `scripts/check-ci-paths.py` **already classifies** the
   `ci-lanes.sh → sign-release.sh` edge as **UNREACHED BY RULING**, with the
   reason written out: *"it never can be: D71 §2 R1/R7 forbid the signing key on
   any runner."*

**No workflow can emit the detached signature.** The clause is satisfiable only
as a **TWO-ACTOR** procedure: the runner builds and hashes; the maintainer signs
locally and attaches. §2 R5 records that without rewriting the row.

### 1.7 The checker candidate, and its measured yield

The obvious guard — *refuse `push: tags:` in a release workflow* — was costed
before being refused, because a refusal without a number is an opinion:

| candidate | measured on the tree today | verdict |
| --- | --- | --- |
| a guard forbidding `push: tags:` in a release workflow | **0 hits — no release workflow exists**, and its subject would be a file authored by the same wave that would review it | **REFUSED — nothing reachable could redden it** |
| a guard against a workflow invoking `sign-release.sh` | **already guarded.** `check-ci-paths.py` **hard-fails on an unclassified `scripts/x` edge**; a new `release.yml → sign-release.sh` edge is a new unclassified context and reds **without a line of new code** | **REFUSED — the yield is zero because the check already exists** |

---

## 2. RULING

### §2 R1 — **REFUSED.** No release workflow lands this wave, constrained or otherwise

Three independent grounds, **any one sufficient**:

- **(a) The edge said to justify it does not exist.** `Q32` does not need it
  (§1.5), so *"unblock `Q32`"* is not a reason.
- **(b) The witness is ONE maintainer billing act away.** This is
  **NOT-YET-WITNESSED**, not **UNWITNESSABLE** (§1.3–§1.4). Banking an
  unverifiable artifact for a witness expected within days buys nothing, and it
  spends the reviewer attention that the witnessed version will need.
- **(c) `.github/workflows/` is precisely where existence is read as
  capability.** A committed workflow that has never run reads, to every later
  survey, as a pipeline this project has. **This project's dominant defect class
  is a check nothing reachable could redden**, and an unwitnessed release
  workflow is that defect with a publish button attached.

### §2 R2 — What `Q31`'s `Do` must contain to count as landed, when the pipeline half **is** written

Recorded now so the eventual lane does not have to re-derive it, and so a
different shape is a visible deviation rather than a silent one:

1. **Trigger on `workflow_dispatch` ONLY, with a required `ref` input.**
   **`push: tags:` is FORBIDDEN** until §2 R6 is met. Two tags already exist
   (`format-v1-freeze`, `pre-trailer-strip-949dd9d`), so a `v*` filter is a
   loaded gun aimed at a repository **that tags for non-release reasons**.
2. **`permissions: contents: read` at workflow level.** `contents: write` may
   appear on the **publishing job only**, and that job must create a **draft**
   (`--draft`), never a published release.
3. **Pin `runs-on:` to a DATED IMAGE LITERAL** (an `ubuntu-24.04`-class literal),
   **never `ubuntu-latest`** — `Q31` `Accept` row 4 already forbids it — and
   **ASSERT the artifact's glibc floor as a build step that fails on a rise**,
   rather than recording it in prose. A floor recorded in prose is a floor that
   rises without a commit.
4. **MUST NOT invoke `scripts/sign-release.sh`.** Signing is the maintainer's
   local act (§1.6). The workflow's output is **unsigned artifacts plus
   `SHA256SUMS`**; the release checklist owns the handoff.
5. **Invoke `scripts/reproducible-build.sh --compare` for the wasm half, OR
   state in-file why not.** It is a two-checkout / two-`CARGO_HOME` comparison
   and is not wired to CI today; **a new CI edge to it must be classified in
   `check-ci-paths.py` in the same commit.**
6. **Carry a header comment naming the run id that FIRST WITNESSED it.**
   **A release workflow with no witnessed run id in its header IS NOT LANDED.**

**OWED: the hosted witness.** **OWNER: the maintainer (`aed900`).**
**TIMING: before the pipeline half of `Q31` is written** — the billing gate is
cleared, **one green hosted run of any workflow is observed**, and only **then**
does an agent write `release.yml`. **`Q31` stays OPEN.**

### §2 R3 — The `sha_pinning_required` deferral is **ALREADY DISCHARGED** and stands unchanged

No new wording is minted. The row's escape branch is written and names **`Q255`**
as its blocker (D143 §2 R5); the read-back remains
`gh api repos/aed900/antseal/actions/permissions`, **never *"having set it."***

The forward obligation is stated as a **PRECONDITION, not a follow-up**: any new
`uses:` in any future workflow must be a **40-hex SHA with a `# vX.Y.Z`
comment**, **and** carry its row in `.github/action-pins.tsv` with the
invocation count rebalanced, **in the same commit that introduces it**.
`check-action-pins.py` (rules P1–P7, run from the local gate) reds otherwise.
**All 57 current invocations comply.**

### §2 R4 — `Q32`'s `after Q31` is **DISCHARGED CLAUSE-WISE** and **deliberately NOT struck**

D163 §2 R1 is the instrument and §1.5 is the walk. The term **stays in the run**
— rule 7 repairs **never by deletion**, and a future reader must be able to see
why an **open** predecessor satisfied it. The consumed clauses landed in
**`0ae2c96`**.

**`Q32` IS LANE-AVAILABLE TODAY**, gated by its own `P17` Sepolia term for
`Accept` row 1's **run** half only — a `before` deadline (D156 §2 R7) — and
**not** by `Q31`.

### §2 R5 — `Q31` `Accept` row 1 is a **TWO-ACTOR** clause. Recorded, not rewritten

Read as single-actor it is **unsatisfiable by construction** (§1.6). The clause
is not amended here — amending an `Accept` row to fit what a tool can do is how
a requirement quietly becomes its own implementation — but the reading is fixed:

> the runner builds and hashes; the **maintainer signs locally and attaches**.

**A future reader must not tick this row by pointing at a workflow.**

### §2 R6 — The CI refusal is diagnosed as **BILLING**; the act is **OWED**, with an owner and a timing word

The register's *"the annotation is a disjunction"* note is **SUPERSEDED**: the
disjunction is **internal to billing** (§1.3). **Separable from the publish flip
— confirmed.**

- **OWED: clearing the GitHub Actions billing gate.** **[ADDENDUM 2026-09-03, D117-style — the owed act is re-identified, not the diagnosis.]** This ruling framed the owed act as a *Billing & plans* payment/limit change. The maintainer has no funds for private Actions, and **standard runners are free on PUBLIC repos** (verified 2026-09-03; every job here is standard). So the act that clears the gate is **the public flip itself**, at $0 — the billing→flip sequencing this record implied is inverted to flip→(free Actions). §1.3's diagnosis (cause = billing, not workflow contents) is unaffected; only the remedy and its ordering are corrected. See TODO.md Maintainer action (11) and the ledger.
- **OWNER: the maintainer (`aed900`)**, in the GitHub web UI, under **Billing &
  plans**.
- **TIMING: before the next wave's survey**, because **every hosted-witness row
  in M4 sits behind it** — §2 R2's witness among them.

**Explicitly, and this is part of the ruling:** **no agent may widen the token's
scopes, read or change billing, push, or flip visibility on the strength of this
record.** Those are external acts requiring the maintainer's own in-the-moment
consent, and **this ruling is not that consent**. The act is recorded here so it
has a home and an owner — the reason `Q258` exists (D153 §2 R9) — not so an
agent can take it.

---

## 3. Fault plants — **NONE ARE OWED, and that is a ruling, not an omission**

This decision **mints no checker and changes no executable path**. The numbers
behind the refusal, so it is not read as laziness:

- A guard forbidding `push: tags:` in a release workflow would fire **0 times
  today** — no release workflow exists — and its subject would be a file whose
  author is the same wave that would review it.
- The **worst concrete outcome** — a workflow invoking `sign-release.sh` on a
  runner — is **ALREADY GUARDED**: `check-ci-paths.py` hard-fails on an
  unclassified `scripts/x` edge, and its existing entry classifies that edge
  **UNREACHED BY RULING**. A new `release.yml → sign-release.sh` edge is a new
  unclassified context and **reds without a line of new code**.
- **MEASURED YIELD OF A NEW CHECKER: ZERO.**

**Plants that WILL be owed when §2 R2's pipeline half is written**, listed now so
the lane inherits them rather than inventing them:

1. **Flip one `uses:` SHA to a tag** → `check-action-pins.py` must say so **BY
   ITS MESSAGE**, naming the invocation.
2. **Add a `release.yml → sign-release.sh` edge** → `check-ci-paths.py` must
   name it **unclassified**.
3. **Raise the asserted glibc floor by one minor** → the build step must fail
   **ON THE FLOOR**, not on a compile error.

For every one: **read `REAL_EXIT` from a file**, and confirm the output says
what it should. **A `101` that is an `error[E…]` is a compile check, not a
plant.**

---

## 4. What this record does **NOT** decide

- **Whether the billing gate is a failed payment or a spending limit.** That is
  a genuine disjunction and **the token cannot read further** (§1.4). Neither
  branch is asserted.
- **`Q255`**, the transitive-pin blocker behind `sha_pinning_required`.
  Untouched.
- **`Q34` / `Q65`, the publish flip.** D141 §2 R1's finding that `Q31` requires
  no external party **stands and is unaffected**; this refusal rests on the
  **missing edge** and the **missing witness**, not on visibility.
- **Whether `reproducible-build.sh --compare` belongs in the release job or
  stays a local act.** §2 R2(5) requires the answer be **WRITTEN**, not that it
  be yes.
- **`Q31` `Accept` row 6** — licence text reaching the deployed page artifact.
  Still undecided, still owed, and not addressed here.
- **Whether `Q32` should be this wave's replacement act.** It is now measured
  **lane-available**; choosing it is the orchestrator's call, not this record's.
- **Anything about `Q31`'s remaining `Accept` rows becoming *reachable*.** §2 R2
  states what the pipeline half must contain; it does not schedule it.

---

## 5. Edit list — per write scope, with the timing word

Ordering words below are the register's. **Nothing in this list is an external
action, and no entry may be read as authorising one.**

### Registrar scope — `TODO.md`, `tasks/Q.md`, `docs/decisions/README.md`

1. **`Q31`'s row and `### Q31`** — record §2 R1 (**REFUSED this wave**, with the
   three grounds), §2 R2 (the six-item contents test, the **owed hosted
   witness**, its **owner** and its **timing word**), and §2 R5 (`Accept` row 1
   is a **two-actor** clause and must not be ticked by pointing at a workflow).
   **`Q31` stays OPEN and is not ticked.**
2. **`Q32`'s row and `### Q32`** — record §2 R4: `after Q31` is **DISCHARGED
   CLAUSE-WISE and NOT struck**, with §1.5's three-row walk named, the consumed
   artifacts named, and the row marked **lane-available today**, gated only by
   its own `P17` term for `Accept` row 1's run half. **with** edit 1.
3. **The correction of premise 1 at source** — wherever a surface still says
   `Q31`'s `Do` is unbuilt, it is corrected to **PARTIALLY LANDED**, naming the
   two files and `0ae2c96`, and narrowed to *the pipeline is absent*.
   **after** edit 1.
4. **The billing diagnosis (§2 R6)** — recorded wherever the *"the annotation is
   a disjunction"* note lives, marked **SUPERSEDED**, with **owner** and
   **timing word**, and with the sentence that **no agent may act on it**.
   **after** edit 3.
5. **The `D166` index row.** **Registrar's edit, not a lane's** — this record
   does not write it.

### Nothing else

**No workflow file is added, edited, or deleted** (§2 R1). **No script is added
or changed** (§3). **No repository setting is read back or written**, no token
scope is widened, and no push is made on the strength of this record. No file
under `crates/` or `testdata/` is touched, so **no build, no golden vector and
no tamper-matrix row is affected**, and the `wasm32-unknown-unknown` surface is
untouched. The instrument-finding ledger is the registrar's surface and is
deliberately not part of any lane's edit set here.

---

## Closing — this record is not consent

This record **refuses** an act, **defers** another, and **records a third as
owed by the maintainer**. It authorises nothing.

Specifically: it does not authorise clearing or inspecting billing, widening a
token's scopes, pushing, tagging, publishing a release, arming a repository
setting, or flipping visibility. **A recorded obligation with a named owner is a
statement about who must act — never a licence for an agent to act in their
place**, and the owner named in §2 R6 acts on their own decision, in their own
session, in their own words.
