# D161 — the per-file classification Q65 asks for cannot exist, because the flip publishes *history* and not a *tree*: the record is per-CLASS, `private` means never-tracked, `private-until-release` is empty of files, and D61 §9 is re-read in the same act

- **Status: RESOLVED. The lean is OVERTURNED — the question dissolves.**
  The register's lean was that `Q65` `Accept` row 1 is a straightforward
  missing document: *"write the per-file `public`/`private`/`private-until-release`
  table"*. It is not writable, and the reason is not cost.
  - **The unit of visibility is the repository, and it is retroactive.** The
    flip publishes every object reachable from the pushed refs, not the files
    at `HEAD`. Measured: **1 299** distinct paths have existed in `main`'s
    history against **1 289** tracked at `HEAD`, so **10 paths that no longer
    exist anywhere in the working tree are published anyway**. A label attached
    to a file at `HEAD` cannot make any of them private. §1.1.
  - **Therefore the classification function is CONSTANT over the tracked set.**
    Every one of the 1 289 tracked files resolves to `public`. A table whose
    every cell reads `public` is this project's dominant defect class — an
    assertion that cannot fail — and it goes stale on the next commit. §1.2.
  - **The only instrument that could produce a `private` tracked file is a
    history rewrite, and that is refused in writing twice** — `tasks/Q.md`'s
    own `Q65` Notes (*"no history scrub is warranted"*, force-push over a
    published freeze tag) and the runbook's *"does NOT cover"* section. This
    record **depends** on that refusal: if it is ever reversed, this record is
    **void, not merely stale**. §1.1.
  - **What the row is really asking, once the false granularity is stripped,
    is three questions the flip can actually answer** — what leaves the tree
    before the flip (**nothing**), what is `private` (**the never-tracked set,
    whose register already exists and is `.gitignore`**), and what is
    `private-until-release` (**empty of files**; the four genuinely
    release-timed things are *acts*, and each already has an owner). §1.3–§1.5.
  - **`Accept` rows 1 and 5 are ONE act.** Row 5 says D61 *"is re-read in this
    same wave"* when `Q65` resolves to *public*. Landing row 1 alone would
    manufacture a live breach of row 5's own timing clause — the wave in which
    `Q65` resolved would be a wave in which the re-read did not happen. The
    re-read is therefore §2 R7 of this record and not a separate item. §1.6.
- **Date: 2026-08-22**
- Owner row: **Q65** (`Accept` rows 1 and 5). This record does **not** tick
  `Q65`, and the reason is narrower than "rows 3 and 4 are open": **row 4's
  antecedent is FALSE** — it reads *"if the answer is 'stay private
  indefinitely'"*, and the answer is public, so it is satisfied vacuously and
  is not outstanding. **Row 3 has two conjuncts and only one is open**: the
  ordering *is* stated (measured, and `Q254`'s checklist landed), while
  *"executed **before** any visibility change"* is a **deadline confirmed at the
  flip**, not work. So what actually holds the tick is that deadline plus the
  `Do`'s finding-4 at-the-flip settings items — **all of it Phase B, none of it
  a lane's**.
- Related: **D61 §9** (the re-read trigger this record discharges); **D72 §2 R6**
  (release assets inherit repository visibility — why `Q65` is a precondition
  of `Q31`/`Q34`); **D144 §2 R1** (`Accept` row 2, the machine-path lint, green
  and untouched here); **D150 §2 R1** (the forbidden reverse edge); **D153 §2 R8**
  (A6, the key-anchor branch); **D154 §2 R2/R3** (`Q254` co-timed, the ordered
  flip procedure); **D156 §2 R5** (struck the `Q28` `after` term and made this
  row's lane half reachable); **D157** (the DNS `TXT` pin's direction).

---

## 0. What was measured against

Read in full before anything was written: `tasks/Q.md`'s `Q65` entry (`Do`
findings 1–4, all five `Accept` rows, all three `Notes` blocks),
`TODO.md`'s `Q65` row, `docs/decisions/D61-fuzz-venue.md` §9,
`docs/ci-verification.md` Phase A (A1–A8) and its *"does NOT cover"* section,
`docs/reviews/pre-public-scrub-worktree.md`, `-history.md`, `-github-side.md`,
and `.gitignore`.

Measured at source on **2026-08-22**, not quoted from a record: `git ls-files`,
`git log --name-only main`, `git ls-remote origin`, `git ls-files -i -c`,
`git status --porcelain --ignored`, `git check-ignore`, `git grep -l`, and one
read-only `gh api` call. Every figure below is a fresh parse. Where this record
corrects a figure carried in `Q65`, the superseded value is shown, because the
**direction** of the drift is itself the finding.

No `cargo build`, no `cargo test`, no `scripts/local-gate.sh`, no
`--self-test`: other lanes held the tree, and none of this record's claims
needs a build to settle.

---

## 1. What was measured

### 1.1 The flip publishes history, so it has no per-file granularity

`git ls-remote origin` carries exactly two refs — `refs/heads/main` (at
`bebc850`) and `refs/tags/format-v1-freeze`. Making the repository public makes
every object reachable from those two refs public, at once.

| measurement | value |
| --- | --- |
| distinct paths ever present in `main`'s history | **1 299** |
| paths tracked at `HEAD` | **1 289** |
| **published although absent from the working tree** | **10** |

The ten, by name — these are the proof that a `HEAD`-file label cannot be the
instrument:

```
crates/antseal-core/tests/format_registry_draft.rs
docs/decisions/D74-extraneous-s-root.md
scripts/__pycache__/check-traceability.cpython-311.pyc
testdata/tamper/format/body-malformed-seal-id.cbor
testdata/tamper/format/body-tagged-unit-kind.cbor
testdata/tamper/format/bundle-full-reveals-over-cap.cbor
testdata/vectors/hkdf/gen_vectors.py
testdata/vectors/hkdf/hkdf-sha256-v1.txt
testdata/vectors/hkdf/README.md
verifier-web/index.html
```

The only mechanism that would remove them is a history rewrite. It is refused
at `tasks/Q.md`'s `Q65` Notes (*"a scrub is the tool for a committed secret,
and its cost here is real: the `format-v1-freeze` tag is pushed, and a rewrite
would change every hash again and require force-pushing over a published
tag"*) and again in the runbook's *"does NOT cover"* section. The refusal is
sound — `docs/reviews/pre-public-scrub-history.md` found zero committed
secrets across 3 450 blobs, with 37 of 37 detector patterns fired on 44 planted
canaries before any zero was believed — but this record **rests on** it, and
§4 records what follows if it is ever reversed.

### 1.2 The classification function is constant, at every granularity anyone proposed

Per-file: **1 289** rows, every one `public`. Per-directory: **12** rows, every
one `public`:

| directory | tracked files | | directory | tracked files |
| --- | ---: | --- | --- | ---: |
| `testdata/` | 541 | | `.github/` | 12 |
| `crates/` | 429 | | `fuzz/` | 11 |
| `docs/` | 213 | | `tasks/` | 9 |
| `scripts/` | 43 | | `probes/` | 8 |
| *(repository root)* | 20 | | `verifier-web/`, `.claude/`, `.cargo/` | 1 each |

Both are enumerations, and an enumeration of a constant is stale at the next
commit and cannot redden. **Per-class is the only granularity that stays true
as the tree grows**, because it is a rule over the *tracking relation* rather
than a list of paths.

### 1.3 `private` = never tracked, and its register already exists

The only files a public repository does not publish are the ones git has never
held. That set is defined by `.gitignore`, which already carries its own
deny-by-default rule and a per-pattern reason for nearly every entry. Present
on disk on 2026-08-22, **8 entries**:

```
target/   .devnet/   fuzz/corpus   fuzz/artifacts   fuzz/target
scripts/__pycache__   .claude/worktrees   .claude/scheduled_tasks.lock
```

Two boundary measurements, both **0** today, and both cheap enough to re-run at
the flip:

- `git ls-files -i -c --exclude-standard` — tracked files that match an ignore
  pattern → **0**. (Ignore rules do not apply to already-tracked files, so this
  can go nonzero via `git add -f` or a widened pattern.)
- `git status --porcelain -uall | grep '^??'` — untracked, non-ignored → **0**.

### 1.4 `private-until-release` is empty of files

Nothing in the tree is being withheld until release. The four genuinely
release-timed things are **acts, not files**, and every one already has a
named owner:

| act | owner |
| --- | --- |
| first publication of the minisign public key (README anchor; and now the page footer) | `R96`; runbook **A6**; hazard `Q262` |
| the DNS `TXT` pin on `antseal.org` | **D71 §A R4** |
| the signing key's OTS anchor | **D71 §A R5** clause 4 |
| release assets themselves | **D72**, `Q31` |

Recording the class as empty **with those four named** is the content: it makes
any future non-emptiness a **reopening event** rather than a silent drift.

### 1.5 The one genuine file-level call, and the figures have all drifted upward

`Q65`'s `Do` finding 2 reversed itself once already — `MVP-SPEC.orig.md` and
`SPEC-REVIEW.md` were recorded as *"the only two documents that can leave
cheaply"* and are not deletable. `docs/reviews/pre-public-scrub-worktree.md` §6
reached *"keep both"* but flags it **"Recommendation, not executed"**.
Promoting that recommendation to a decision is the only file-level call this
row actually contains.

Re-measured 2026-08-22 (tracked files mentioning the basename, excluding the
file itself). **Every figure has grown since 2026-08-17**, which is the
direction `Q65` predicted:

| document | recorded | measured 2026-08-22 |
| --- | ---: | ---: |
| `MVP-SPEC.md` | 434 | **459** |
| `docs/threat-model.md` | 18 | **37** |
| `docs/security-assumptions.md` | 21 | **24** |
| `SPEC-REVIEW.md` | 12 | **13** |
| `MVP-SPEC.orig.md` | 8 | **9** |

The decisive one is not a count. `SPEC-REVIEW.md:287` is cited **by line
number** from a shipped artifact and from a test that reads it — and **both
citation sites have themselves drifted since `Q65` recorded them**:

| site | recorded in `Q65` | measured 2026-08-22 |
| --- | ---: | ---: |
| `verifier-web/index.template.html` | :134 | **:138** |
| `crates/antseal-wasm/tests/page_template.rs` | :151 | **:171** |

Both still say *"the comma is normative — `SPEC-REVIEW.md:287`'s comma-less
variant is not"*, and the quoted comma-less variant still wraps across
`SPEC-REVIEW.md:287-288`, so line 287 alone remains a fragment. Deleting either
document breaks a shipped artifact's provenance comment and a test. The
line-fragility is a real hazard and it is **not** a licence to delete; it is
noted here so the next reader does not rediscover it as an argument for
deletion.

### 1.6 D61 §9's two conditions, measured rather than assumed

`Q65` `Accept` row 5 fires *"when this resolves to **public**"*. D61 §9's own
sentence names the trigger's subject as the **row**, not the repository —
*"when Q65 resolves to 'public', D61 is re-read in the same wave"* — while
condition (a)'s subject is the repository, written separately as *"`aed900/antseal`
is public — the Q65-gated flip"*. The record keeps the two apart deliberately,
and the runbook performs the re-read as a **BEFORE** step (A7) while (a) is
still false. So the trigger fired at the maintainer's 2026-08-16 call, and the
re-read is due now, not at the flip.

- **(a) the repository is public — FALSE, measured.**
  `gh api repos/aed900/antseal --jq '.visibility'` → `private`,
  `REAL_EXIT=0`, read 2026-08-22T08:49Z. It is a read, not a state change.
- **(b) use by parties other than the maintainer, sufficient to argue
  OSS-Fuzz's own *"a significant user base and/or be critical to the global IT
  infrastructure"* criterion — FALSE**, and the flip does not change it. There
  is no release, no published binary, and no external user.

Separately measured, so that the *"no wave may carry D61 as open"* clause is
checked rather than assumed: four independent surfaces record D61 as resolved
and **none dissents** — `TODO.md`'s register row, `docs/decisions/README.md`'s
index row, the record's own `- **Status` line, and `docs/testing/fuzzing.md`.
Nothing needs repair.

---

## 2. Ruling

### R1 — `Q65` `Accept` row 1 is answered **per class, with a stated default**, and the per-file table is refused

The record is this document. Its granularity is four classes over the
*tracking* relation, not an enumeration of paths:

1. **`public` — the default, and the whole tracked set.** 1 289 files at
   `HEAD`, plus 10 paths that exist only in history. The unit is the
   repository and it is retroactive (§1.1).
2. **`private` — the never-tracked set** (R2).
3. **`private-until-release` — empty of files** (R3).
4. **deleted before the flip — empty** (R4).

The row's own test — *"nothing marked `private` may be load-bearing for
verification"* — is satisfied and is checked by R5 rather than asserted.

### R2 — `private` is the never-tracked set, and `.gitignore` is its register, **adopted by reference and not copied**

A copy of an ignore list inside a decision record is a second truth that drifts
against the first. This record names `.gitignore` as authoritative and records
only the measured state on 2026-08-22 (§1.3: 8 present-on-disk entries, both
boundary counts **0**).

**`.gitignore` has a measured deny-by-default hole, and closing it is NOT this
record's act** — see R9.

### R3 — `private-until-release` is **empty of files**, and the four release-timed **acts** are named with their owners

§1.4's table is the ruling. Any future file in this class **reopens this
record**; that is the point of writing the class as empty rather than omitting
it.

### R4 — The deletion list is **empty**. `MVP-SPEC.orig.md` and `SPEC-REVIEW.md` are **KEPT and PUBLIC**

This promotes `docs/reviews/pre-public-scrub-worktree.md` §6's *"Recommendation,
not executed"* to an executed decision, on §1.5's measurements. The same holds
a fortiori for `MVP-SPEC.md`, `docs/security-assumptions.md` and
`docs/threat-model.md`. **Nothing leaves the tree before the flip.**

### R5 — The test is a **run**, not a claim: verification must close over the published set alone

`git archive HEAD` emits exactly the tracked set, so anything ignored or
untracked is absent **by construction**. Verification closing over that tree is
the same property `Q34`'s gate tests with *"zero repo-checkout resources"*, one
step earlier and without a clean machine:

```bash
rm -rf /tmp/q65-published && mkdir -p /tmp/q65-published \
  && git -C /home/<user>/…/code0 archive HEAD | tar -x -C /tmp/q65-published
cd /tmp/q65-published
{ ./scripts/ci-lanes.sh golden-vectors > gv.out 2>&1; echo "REAL_EXIT=$?" > gv.exit; }
{ ./scripts/ci-lanes.sh tamper-matrix  > tm.out 2>&1; echo "REAL_EXIT=$?" > tm.exit; }
```

**Honesty conditions on it, stated so it is not over-read.** It is a
**one-shot pre-flip evidence capture, not a gate step**: it pays a full build
and needs a warm cargo registry or network. `REAL_EXIT` is read back out of a
file, never from a harness's exit report. And the failure it is designed to
catch is **not** theoretical — `testdata/vectors/hkdf/` is in the history-only
set (§1.1), and `.gitignore` ignores `fuzz/corpus/`, an ignore rule sitting
directly on top of test inputs.

**[OBSERVED 2026-08-22 — what was actually run, and what was not.]** The
**archive half was executed** and is the part that can go wrong silently:
`git archive HEAD | tar -x` produced **1 289 files against 1 289 tracked at
HEAD**, `REAL_EXIT=0`, and the inputs verification depends on are all present
in it — `testdata/vectors` (34 files), `testdata/tamper` (34),
`docs/format/registry-v1.md` and `docs/format/FROZEN.sha256`. **The two lane
runs over that archive were NOT executed**: they pay a full build from a cold
target directory, and this record already classes them as a one-shot pre-flip
capture rather than a gate step. What that leaves unproven is narrow and is
named here rather than glossed: nothing has *executed* verification against the
published set alone. The residual risk is bounded by two measurements — the
working tree carries **0** untracked non-ignored files, so tree and archive
differ only by ignored content, and the one ignore rule that sits on top of
test inputs is `fuzz/corpus/`, which neither `golden-vectors` nor
`tamper-matrix` reads. **Owner of the remaining half: the flip sitting**, as
Phase A evidence, before B0.

Two always-on companions that need no build, both measured **0** today, and
both belong in the flip sitting rather than here: `git ls-files -i -c
--exclude-standard`, and `git status --porcelain -uall | grep '^??'`.

### R6 — **No checker is minted for this row**, and the three candidates are refused *with their measured counts*

The house rule is that a proposed checker carries a measured yield, and that a
lane may refuse one. All three candidates are refused:

| candidate | measured yield | verdict |
| --- | ---: | --- |
| tracked file matches an ignore pattern (`git ls-files -i -c`) | **0**, and 0 across 533 remote commits | refused — no measured yield; kept as an R5 read-back |
| a lint over the classification table | **0 by construction** — every row reads `public` | refused — an assertion that cannot fail |
| *"the record names every top-level directory"* | green the moment it is written | refused — blind to the staleness it would exist to catch |

This is the row being honest about itself: `Q65`'s substance is a decision, and
a decision is not made checkable by wrapping a constant in a script.

### R7 — **D61 §9 is re-read, and this is that re-read.** `Q65` `Accept` row 5 is DISCHARGED

Both conditions measured at §1.6: **(a) FALSE** (`private`, measured
2026-08-22T08:49Z, `REAL_EXIT=0`), **(b) FALSE** (no external user; the flip
does not change it).

**(a) alone does not reopen the OSS-Fuzz arm.** Until both hold, **OSS-Fuzz is
*not applicable* rather than *pending*, and no wave may carry D61 as open on
that account.** A re-read that concludes *"still closed"* is a discharged
obligation, not a skipped one.

The **budget half** is the part that changes, and only when (a) becomes true in
Phase B: standard GitHub-hosted runners are free on public repositories, which
is the mechanism by which the exhausted-allowance refusals stop. Two riders,
both binding:

- **No required status context may be added on the strength of that
  expectation** (A7 → C2). The expectation is not a measurement.
- The budget half is reopened **on its own merits, in its own wave**, not here.

What this re-read does **not** do: it does not reopen D61, does not move the
fuzz cadence or the §5 ceiling, and does not tick `Q65`.

### R8 — Two corrections to the runbook's Phase A, made because a maintainer reads it aloud at the flip

- **A1 names a discharged obligation as outstanding.** It says the two `Q65`
  obligations the runbook cannot see are the per-file record **and** the two
  registered `OWED_PRESENCE` clauses. The latter were discharged 2026-08-19 by
  `Q22`'s lane, and D150 §2 R6's own anchored predicate — `python3
  scripts/check-copy-style.py | grep -c '^check-copy-style: registered debt'` —
  returns **0**, re-measured at this registration. **A1 has been stale since
  the day it was written.** One obligation was invisible to that file, not two.
- **A1 indexes an `Accept` row that does not exist.** It says *"Its `Accept`
  rows 1, 2, 5 and 6"*. `Q65` has exactly **five** top-level `Accept` bullets,
  and D156 §2 R5 says *"this row's five `Accept` rows"*. There is no row 6.
  Found independently by two planners and confirmed by parse; it is the
  **sixth** count drift of the class the header already tracks.

### R9 — The `.gitignore` deny-by-default hole is real, is NOT closed here, and takes a row

`docs/reviews/pre-public-scrub-worktree.md`'s blocker **S2** recorded `.env`,
`id_rsa` and `credentials.json` as uncovered by `.gitignore` on 2026-08-16.
Re-probed 2026-08-22 with `git check-ignore -q` against names that create no
files — **5 of 7 probes are NOT ignored**:

```
NOT-IGNORED  .env  .env.local  secrets.env  id_rsa  credentials.json
IGNORED      foo.key  .secrets/a
```

That contradicts `.gitignore`'s own stated deny-by-default rule, and it is the
`private` class's **only** enforcement mechanism. `grep` over `TODO.md` and
`tasks/` returns **zero** rows owning it: the scrub's §8 never minted one.

It is not closed inside this record, for the reason R2 gives — a decision
record that edits the register it adopts by reference becomes a second truth.
It is **minted as a row** at this wave's registration, with the 5-of-7 probe as
its own self-test, and it is owed **before** the flip because that is when the
hole stops being local.

---

## 3. Consequences

1. **`Q65` `Accept` row 1 is discharged** by this record, and **row 5** by R7.
   `Q65` does **not** tick: row 3 carries a flip conjunct co-timed with
   `Q254`, row 4 is the stay-private counterfactual, and the flip is an
   external action requiring express in-the-moment consent naming action,
   destination and account. **Nothing in this record is that consent.**
2. **`Q65`'s Notes are corrected at source** where they say *"Still owed by
   this row and not by any other: the per-file … decision record, … the D61 §9
   re-read"*. That is a live claim, and it is retracted in the act that
   discharges it — not left to be read by the next successor as true.
3. **A7 gains a pointer** to where the re-read landed, so the flip sitting
   reads it as executed rather than re-deriving it. A7 stays a step; C3 still
   reads condition (a) back after the flip.
4. **Two dated records that name the re-read as owed are left standing** —
   `tasks/Q.md`'s `Q254` wave-27 note and D140. They are records of what was
   true then, and under D117 they are not edited.
5. **One row is minted** (R9).

---

## 4. What this record does not cover

It decides what the flip publishes and why. It does **not** execute the flip,
does not authorise it, and is not consent.

It does not cover **history rewriting** — it explicitly *relies* on the refusal
of one, so if that verdict ever changes this record is **void, not stale**.

It says nothing about `Q65`'s finding-4 settings items (`homepage`, `topics`,
fuzz artifacts, fork-PR approval — all at-the-flip, Phase B), the ordered flip
procedure (`Q254`, landed), the machine-path lint (`Accept` row 2, green under
D144 §2 R1), release assets or crates.io (D72, `Q31`, `Q241`), or
`https://antseal.org/`, which is already public and whose source visibility the
flip does not change.

It **cannot certify that no secret was ever committed.** That is
`docs/reviews/pre-public-scrub-history.md`'s finding and `secret-guard`'s
standing job — and `secret-guard` excludes `*.md`, so Markdown is a measured
blind spot this record **inherits rather than closes**.

And it does not make anything private. **After the flip there is no rollback**,
which the runbook says in its own words.
