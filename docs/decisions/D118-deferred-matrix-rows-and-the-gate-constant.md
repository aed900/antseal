# D118 — Q165: the eleven `deferred` verification-matrix rows, and the constant that made them invisible

- **Status: RESOLVED — the eleven are adjudicated one by one, and both readings
  of them are refused.** The row's framing is that *"the eleven are eleven live
  claims that work is missing"*. The comfortable counter-reading is that they
  are all stale bookkeeping. **Measured against the tree, it is ten and one.**
  Ten rows describe work that landed between 2026-08-02 and 2026-08-06 and were
  never updated: `V2.3`, `V3.5`, `V6.1`–`V6.6`, `V7.2`, `V7.3`. All ten are now
  `covered` with named, resolving evidence — **97 references resolve where 55
  did**.
  **One is real, and it is not one the row singles out.** `V7.1` — *"real OTS
  calendars: pending, then upgraded the next day"* — is now **`gap`**. The
  two-day cycle genuinely happened and is logged to the second, but **`curl`
  performed it, not antseal**: `testdata/anchors/A25-bootstrap/CAPTURE.log`
  still carries curl's own `Could not resolve host` line. antseal's submit and
  upgrade paths have never spoken to a real calendar, `scripts/` carries no
  `anchor-smoke` entry point, and `docs/anchors/real-smoke-runbook.md` §0 says
  in its own words that the protocol *"is not yet executable end-to-end"*.
  Replaying captured bytes offline proves the parser; it does not prove the
  client, and the spec's heading for this bullet is **"Anchor smoke tests"**.
  **The row's sharp end — six M1 rows — is the blunt end.** All six are stale,
  and *"nobody knows which"* was never true: the answer sat in `TODO.md`'s own
  `S17`, `S18`, `S14`, `A1` and `Q15` rows, each dated 2026-08-02 and each
  carrying its test count. Nobody had looked; that is not the same as nobody
  being able to know.
  **`CURRENT_MILESTONE` moves `M0` → `M1`, not `M0` → `M2`**, and the
  difference is the whole ruling. It names the last milestone whose review has
  **passed**, not the one being built. Setting it to `M2` — a milestone
  109 rows into 228 — would force `V7.1` into `ACCEPTED_NON_COVERED`, a
  register whose own comment reserves it for *"a milestone shipping with a
  known hole"*, and would **mute `V7.1` at the M2 review**, the one moment it
  exists to speak. `ACCEPTED_NON_COVERED` therefore stays `{}`, as its comment
  says it should.
  **M1's declared-passed gate is not implicated, and the reason matters.** Every
  M1 verification bullet had a real test on the day M1 was declared passed. What
  failed was the *record*, not the *work* — and it failed silently, because the
  instrument that would have caught it was reading a constant nobody had moved.
  **Two `--self-test` fixtures had to be retargeted, and finding out why is the
  second-order result.** Both status-gate cases mutated the literal
  `| M1 | S17 + Q15 | deferred |` — `V6.1`'s cell. Marking `V6.1` covered
  deletes that string, both mutations match nothing, and the harness's no-op
  guard fails both cases loudly. **A self-test fixture pinned to a row's status
  inherits that row's lifetime.** Retargeted to `V9.2`'s `| M4 | Q34 |
  deferred |`, whose expiry lands on the release gate somebody must attend.
- **Date: 2026-08-10** (M2 wave 14, D118 lane; briefed to adjudicate eleven rows
  framed as eleven live gaps, and rules that ten are stale, one is a real gap
  the brief does not name, and the constant belongs at M1 rather than at the
  M2 the brief assumes)
- **Owning tasks: Q165** (the ruling; its `Problem` and `Notes` are amended).
  Touching, not executing: **A105** (`V7.2`'s recorded limitation is its
  motivating instance, restated in the row rather than resolved), **A25**
  (`V7.1`'s `gap` is A25 Accept row 1's PARTIAL, seen from the matrix side).
- **Amends**: **`TODO.md`'s Q165 row** and **`tasks/Q.md`'s Q165 entry** — the
  `Problem`'s *"either six uncovered verification bullets or six stale matrix
  rows, and nobody knows which"*, and the `Notes`' *"the eleven are eleven live
  claims that work is missing"*. Both are the orchestrator's to apply.
  **Supersedes**: nothing.
  **Corrects**: **D115 §4.1**, which cites `scripts/check-traceability.py:241`
  for `CURRENT_MILESTONE`; the constant is at `:244` at `95fcee0` and `:241` is
  a comment line. Also **D115 §4.1**'s claim that *"whether `V7.2`'s status may
  move `deferred` → `covered` depends on `A25`'s row-1 script"* — row 1 is the
  OTS cycle and is `V7.1`'s; `V7.2`'s bullet is A25 row **2**, adjudicated
  SATISFIED independently of the script. Both corrections are **recorded here
  and applied nowhere**, because `Q122` — whether a resolved decision's body may
  take a dated correction at all — was open when this lane measured.
  **Sequencing note for the orchestrator, 2026-08-10:** `D117` is being written
  in the same wave against `Q122` and appears to answer it. This lane does not
  read another lane's in-flight ruling as authority and has not acted on it. If
  `D117` lands, both corrections above become applicable immediately and are
  stated here in the form they should take; if it does not, they stay blocked.
  Either way the correction to make is the same and the evidence for it is in
  §8 row 5 and §10 (v).
- **Binds against**: `docs/testing/verification-matrix.md`'s own "How the gate
  uses this" and status-vocabulary notes; `check_matrix()` and
  `gated_milestones()`; `ACCEPTED_NON_COVERED`'s stated purpose;
  `docs/testing/anchor-ci-policy.md`'s no-real-network policy; D52's devnet
  venue; D53 §8's compound-clause finding; Q51 (the status gate this repairs);
  Q14's freeze gate (untouched — every M0 row was and remains `covered`).

---

## The problem, in one sentence

Eleven verification-matrix rows read `deferred` at or before M2, and the only
command that says so is one no runbook asks anyone to type — because the gate
that would have said it on every ordinary run is parameterised by a constant
that never moved off `M0`, through all of M1 and half of M2.

---

## 1. What was measured

Read from the working tree at `95fcee0` plus wave 14's in-flight work,
2026-08-10. Every figure below has its command in §8.

### 1.1 The starting point is exactly as reported

`python3 scripts/check-traceability.py --matrix --milestone M2` exits **1** with
**11** problems, naming `V2.3`, `V3.5`, `V6.1`–`V6.6`, `V7.1`, `V7.2`, `V7.3`
at `docs/testing/verification-matrix.md:67,77,102-107,116-118`. Six are M1 rows.
`CURRENT_MILESTONE = "M0"` at `:244` and `ACCEPTED_NON_COVERED = {}` at `:256`.
Q165's provenance bullet gives both line numbers and **both are exact**.

The flagless run — the one every lane performs — is **green**, with the matrix
lane printing *"all 16 row(s) at or before M0 read 'covered'"*. Sixteen of
thirty-four rows were being checked. The other eighteen were unread.

### 1.2 The ordering constraint the row states is true, and this is the measurement of it

Q165's `Do` says the constant *"must not move until the eleven are
dispositioned, because moving it reddens a required lane"*. Executed: with the
matrix at `95fcee0` and `--milestone M1`, the check fails with **exactly 6**
problems — `V6.1` through `V6.6`. `lane_traceability` runs the flagless form, so
the constant alone would have reddened a required lane. **Confirmed, not
assumed**, and it is the only claim in the row that survived intact.

### 1.3 Ten of the eleven describe work that had already landed

| owning task | landed | what it landed |
| --- | --- | --- |
| `S17` + `Q15` | 2026-08-02 | M1 devnet E2E, 3 tests on a live 14-node devnet; the venue script |
| `S18` | 2026-08-02 | kill/resume matrix, 7 tests, 183.1 s, payments settled on-chain |
| `S14` | 2026-08-02 | `RestoreEngine` |
| `A1` | 2026-08-01 | `AnchorGate` / `NoAnchorGate` zero-anchor contract |
| `A23` + `Q17` | 2026-08-05 | both anchor fuzz targets, both in `TARGETS` |
| `A21` | 2026-08-06 | eight M2 anchor tamper rows over six families |
| `A24` + `Q16` | 2026-08-03/06 | mock TSA + replay substrate; the enforced no-real-network policy |
| `A7` + `A25` | 2026-08-03/07 | four admitted roots; nine real TSA captures |

The M1 rows were stale for **eight days**, `V3.5` for five, `V2.3` for four.

### 1.4 The section preambles were stale in three separate factual claims

- **M1's preamble** said *"`antseal-net` is a doc-comment stub with no
  `StorageBackend` and no `MockBackend`, and no devnet script exists"*. All
  three clauses were false from 2026-08-02: `crates/antseal-net/` carries
  `ant_backend.rs` and a `test_util::mock`, and `scripts/e2e-devnet.sh` is D52's
  required local gate.
- **M2's preamble** said *"`antseal-anchor` is a doc-comment stub;
  `testdata/anchors/` holds a README and nothing else"*. `antseal-anchor` holds
  a TSA layer, an OTS engine, esplora and Arbitrum clients and a stub/replay
  substrate; `testdata/anchors/` holds **88 files** across three campaigns
  (`A25-bootstrap/` 61, `A25-upgrade-headers/` 14, `A16-A17-live/` 12, plus the
  directory README).
- **"How the gate uses this"** said later-milestone rows *"read `NONE` today and
  that is correct, not a gap: the crates they test are stubs"*. True when
  written; false for M1 and most of M2 by the time it was read.

A prose paragraph asserting the state of the tree has the same failure mode as
a hand-maintained count, and this file's own Finding 1 already said so about
its own Finding 1.

### 1.5 `V7.1` is a real gap, and the evidence is in the capture log

`testdata/anchors/A25-bootstrap/CAPTURE.log` records six submissions on
2026-08-02T19:16:18Z–19:16:26Z, all `200`; `upgraded/UPGRADE-CAPTURE.log`
records six upgrades on 2026-08-03T09:03:38Z–09:03:42Z, all `200`. The cycle is
real, and its bytes are verified offline by named tests.

But the log's fourth line reads `curl: (6) Could not resolve host:
finney.btc.calendar.opentimestamps.org`. The client was **curl**. The capture
was taken deliberately at the *start* of the M2 wave, before the code that
consumes it existed — `OTS-BOOTSTRAP.md` says so in its own words, and
explains why: the two-day clock had to start before the consumer was written.

Three independent statements of the same hole, none of which required this
lane to discover it:

1. `docs/anchors/real-smoke-runbook.md` §0: *"The protocol below is not yet
   executable end-to-end"*, and *"The protocol has now been executed three
   times without it, by hand and one request at a time, which is precisely the
   repeatability the script is for."*
2. A25's Accept-row adjudication, row 1: **PARTIAL**, *"the script is the whole
   of what is missing"*.
3. `MVP-SPEC.md:173`'s heading for the bullet: **"Anchor smoke tests"**.

### 1.6 `V7.2` is covered, with a limitation that is A105's whole reason for existing

`freetsa_verifies_ecdsa_p384_sha512` and `digicert_verifies_rsa_pkcs1v15_sha256`
in `crates/antseal-core/tests/anchor_real_tokens.rs` run on the real 2026-08-02
captures and both pass (measured, §8). The **pinned-store** half — reaching
`proven` under `TsaRootStore::pinned()` — is asserted only inside the
anti-vacuity arms of two `verdicts` tests named for something else. A25 row 2 is
adjudicated **SATISFIED**; A105 is open on the naming. The row is `covered`
with the limitation recorded, following V3.4's precedent of `covered` plus an
explicit recorded weakness rather than a status that hides the evidence.

---

## 2. The eleven, row by row

Disposition, with the evidence that decided it. "Stale" means the work existed
when the row said it did not.

| row | M | what it claims | what the tree has | verdict |
| --- | --- | --- | --- | --- |
| `V2.3` | M2 | M2 anchor tamper rows: untrusted root, forged header, wrong-digest `.ots`, expiry pair, BER-where-DER | **8 live rows** in `test_util/tamper_rows_anchor_verdicts.rs::ROWS`, extended into `all_rows()` at `tests/tamper_matrix.rs:428`; `tamper_matrix_m2_anchor_set_is_the_pinned_size_and_armed` pins size **and** arming. A21 landed 2026-08-06 | **stale → `covered`** |
| `V3.5` | M2 | anchor-parser fuzzing | `fuzz/fuzz_targets/anchor_token.rs`, `anchor_ots.rs`; both in `scripts/fuzz.sh:39 TARGETS`; in-crate drivers with three named tests in `src/anchor/fuzz_entry.rs`. A23 + Q17 landed 2026-08-05 | **stale → `covered`** |
| `V6.1` | M1 | devnet E2E, multi-file `--split` | `tests/e2e_devnet.rs::the_multi_file_split_seal_round_trips_against_a_live_devnet`; registered `live` in `e2e-devnet.sh` `suite_registry`. S17 + Q15, 2026-08-02 | **stale → `covered`** |
| `V6.2` | M1 | kill between pay and finalize, no double payment | three named tests in `tests/e2e_kill_resume.rs` incl. a real `SIGKILL` and a sub-batch case; payments counted on-chain; negative twin `..._without_a_durable_sink_...` exists. S18 | **stale → `covered`** |
| `V6.3` | M1 | kill mid-upload; byte-identical; abort rather than re-encrypt under a journaled nonce | `case2_a_sigkill_mid_upload_resumes_byte_identically` compares journaled nonces across the resume; `case3_changed_sources_with_staged_bytes_gone_abandons` is the `(k_u, nonce)` guard, with an intact-bytes twin. S18 | **stale → `covered`** |
| `V6.4` | M1 | `restore` from vault backup on a clean tree | `tests/e2e_restore.rs::a_clean_machine_restores_from_the_vault_backup_and_the_network`, real child process; no-vault twin as anti-vacuity. S19's suite over S14's engine | **stale → `covered`** |
| `V6.5` | M1 | UNANCHORED library-verify | `tests/e2e_devnet.rs::a_zero_anchor_seal_library_verifies_as_unanchored`, on V1.4's empty-anchor vector. A1 | **stale → `covered`** |
| `V6.6` | M1 | `--live` re-fetch passes | `antseal-net/tests/devnet_backend.rs::devnet_s15_live_persistence_identical_missing_and_different` — three outcomes separated, not one happy path | **stale → `covered`** |
| `V7.1` | M2 | real OTS calendars: pending, then upgraded next day | cycle ran 2026-08-02 → 2026-08-03, six commitments `200`, both logs committed — **by `curl`, before the client existed**. No `anchor-smoke` entry point; runbook §0 says not executable end-to-end; A25 row 1 **PARTIAL** | **REAL GAP → `gap`** |
| `V7.2` | M2 | real FreeTSA P-384 + DigiCert against pinned roots | two named tests on real captures, both pass; pinned-store `proven` asserted only in anti-vacuity arms (A105, asymmetric: FreeTSA at one site, DigiCert at four). A25 row 2 **SATISFIED** | **stale → `covered`**, limitation recorded |
| `V7.3` | M2 | CI uses a mock TSA + recorded OTS fixtures, no real network | runtime gate in `HttpClient::attempt` with a compiler-armed `cfg(test)` arm; `scripts/check-anchor-net.py` for the three things a runtime gate cannot see; request-matching stubs; 88 committed fixtures. A24 + Q16 | **stale → `covered`** |

**Ten stale, one real.** No row was struck, and none was registered in
`ACCEPTED_NON_COVERED`.

---

## 3. Both readings, attacked

**The row's reading — "eleven live claims that work is missing" — dies on ten
counts.** It also carries a hidden premise worth naming: that a `deferred` row
is *asserting* something. It is not. `deferred` is not a claim about the tree at
all; it is a claim about the **calendar** — "a later milestone owns this". Nine
of the eleven were true statements that quietly became false when a different
line in a different file failed to change. That is why no author was negligent
and no row was edited wrongly: **the rows rotted without being touched.**

**The comfortable reading — "all bookkeeping" — dies on one count, and it is the
count that matters.** `V7.1` is the row where a large, well-documented,
genuinely-executed real-endpoint campaign is most likely to be mistaken for
coverage. Eighty-eight committed fixtures, two capture logs, a provenance
document and five named tests all exist, and none of them is the thing the
bullet asks for. A lane sweeping for "does evidence exist?" marks it `covered`
in ten seconds. The distinction that saves it — *whose client made the
request* — is not visible in any status column, any test name, or any file
listing. It is visible in one line of a log, and it is a `curl` error message.

**What decided it in both directions was the same discipline**: go to the
artifact, not to the row, and not to the summary of the artifact.

---

## 4. Ruling

**R1 — The eleven are dispositioned individually, per §2.** Ten to `covered`
with named resolving evidence; `V7.1` to `gap`. No row is struck; the
`ACCEPTED_NON_COVERED` register stays empty.

**R2 — `CURRENT_MILESTONE = "M1"`.** It names the last milestone whose review
has **passed**, never the one in progress. §5 is the argument.

**R3 — `V7.1` is `gap`, not an exemption.** `gap` is the vocabulary's exact
value for *"the milestone owns the bullet and no test exists — this blocks that
milestone's gate"*, which is precisely the behaviour wanted at M2's review. It
is silent on the flagless run because M2 is not gated, and loud under
`--milestone M2`, which now returns a usable answer: **one row, not eleven.**

**R4 — `covered` plus a recorded limitation beats a status that hides the
evidence.** Applied to `V7.2` (A105's anti-vacuity arms) and to all six M1 rows
(a local and scheduled venue, never a required remote context). V3.4's note is
the precedent. A row that says `covered` and then says exactly how strong that
is remains readable; a row that says `gap` while five named tests pass teaches
readers to distrust the column.

**R5 — the status vocabulary note gains the sentence it was missing**:
`deferred` is a *relation* between the row's milestone and `CURRENT_MILESTONE`,
not a property of the row, and it is the only status that can rot without being
edited.

**R6 — a status-gate self-test fixture must be pinned to a row that outlives the
constant it tests against.** Both were pinned to `V6.1`; both are now pinned to
`V9.2`, the real-mainnet-seal row, whose expiry coincides with Q34's
whole-matrix-green requirement at the release gate.

---

## 5. Why `M1` and not `M2`

The brief and the row's `Accept` both say the constant must *"name the milestone
actually under review"*, and the failing command names M2. Three measurements
say M1.

**(a) There is no M2 review to be under.** `TODO.md`'s Current-focus reads
*"Phase: M2 — Anchors, IN PROGRESS. 109 of 228 rows done"*. The matrix's own
prose uses "review" for the gate event — *"checked at their own milestone
reviews"*, *"the line a milestone review bumps"*, *"at the M1 review, M0's rows
must still read `covered`"*. A review is a thing that happens at the end. Q165's
own `Do` agrees without noticing: *"`CURRENT_MILESTONE = "M0"` has been wrong
since M1 shipped"* — which says the correct value became `M1` when M1 shipped,
not `M2` when M2 started.

**(b) `M2` would force an abuse of `ACCEPTED_NON_COVERED` and then mute the
row.** With `M2`, `V7.1` must read `covered` or be registered. It is not
covered. Registering it means writing, in the register whose comment reads *"an
entry here is a milestone shipping with a known hole"*, an entry for a milestone
less than half built. And the entry would suppress `V7.1` at the M2 review
itself — converting the one live gap the eleven contained into a permanent
mute, which is the exact decay `check_matrix`'s stale-exemption rule exists to
prevent. **The fix for an invisible gap cannot be a register that hides it.**

**(c) `M1` costs nothing and catches the next drift.** The cumulative rule
means `M1` gates M0's sixteen rows and M1's six, forever — twenty-two of
thirty-four, where sixteen were gated before. M2's five stay free to say what is
true, including `gap`. When M2's review arrives, bumping the constant is a
one-character edit that turns `V7.1` red on the flagless run, which is exactly
what a milestone review is for.

**The residual risk, stated plainly:** `M1` does not make `V7.1` visible to the
ordinary run. Nothing can, without either lying about M2's state or muting the
row. What makes it visible is that `V7.1` now reads `gap` in a file people read,
in a section whose preamble says the M2 answer is *no, on `V7.1` alone*, with
`--matrix --milestone M2` returning one row instead of eleven. **An eleven-row
failure is noise; a one-row failure is a finding.**

---

## 6. Does this implicate M1's declared-passed gate?

**No — and the distinction is worth stating precisely rather than softly,
because the row is right that it is the sharp question.**

M1 was declared passed on the strength of `S17`, `S18`, `S14`, `A1` and `Q15`,
every one of which landed real, named, executing tests on a live 14-node devnet
between 2026-08-01 and 2026-08-02, with payment claims settled on-chain. §2
locates a test for **every** M1 verification bullet, and `scripts/e2e-devnet.sh`
independently registers four of the suites as `live` and fails if one goes
missing. **No M1 verification bullet was ever uncovered.** The disjunction in
Q165's `Problem` — *"six uncovered verification bullets or six stale matrix
rows"* — resolves entirely to the second branch.

**What is implicated is the gate's evidence, not its verdict.** At the moment M1
was declared passed, this matrix — the artefact whose whole purpose is to be the
checkable record of that verdict — said six of M1's own bullets were owned by a
later milestone, and the machine check agreed, because it was pointed at M0. So
M1's gate passed on work that was really done, recorded by a document that said
otherwise, verified by an instrument that read neither. **The verdict was right
by luck of the work rather than by the record**, and a reviewer who had audited
the record instead of the tree would have concluded M1 was not done.

Two things follow that are not softened here:

1. **A milestone review must move `CURRENT_MILESTONE` as part of the review**,
   and M1's did not. Nothing in the matrix's "How the gate uses this", in the
   checker, or in any runbook says who moves it or when. It is described as
   *"the line a milestone review bumps"* and no procedure bumps it. That is the
   defect, and it is procedural, not technical.
2. **Q51's fix was correct and unarmed.** Q51 made the status column
   machine-checked precisely so a stale row could not survive a milestone
   review — and then the first milestone review after Q51 produced six stale
   rows that survived, because Q51 checks the column *against a constant* and
   the constant is the thing that went stale. The second-order lesson from
   Finding 1 recurred at one remove: **a gate parameterised by a
   hand-maintained value is only as current as that value**, and nothing
   compared the value to the milestone the project was in.

---

## 7. Edit set

**`docs/testing/verification-matrix.md`** — the only file this lane owns
outright.

- "How the gate uses this": the M1/M2/M3/M4 bullet, and a new bullet stating
  R5 (`deferred` is a relation that decays).
- `V2.3`, `V3.5` — status and evidence.
- M1 section preamble — rewritten; the false paragraph quoted rather than
  deleted, so the correction is auditable, plus the venue and the recorded
  limitation covering all six rows.
- `V6.1`–`V6.6` — status, evidence and notes.
- M2 section preamble — rewritten, same treatment.
- `V7.1` → `gap`; `V7.2`, `V7.3` → `covered`; all three with evidence and notes.
- Findings 5–8 (this adjudication) and a changelog entry.

**`scripts/check-traceability.py`** — three surgical edits, **no reformatting or
restructuring**, in a file another lane is concurrently editing for a `copytree`
race and a scan-root widening. The two lanes' hunks do not overlap.

| lines (post-edit) | what |
| --- | --- |
| `244`–`259` | `CURRENT_MILESTONE = "M1"` and the comment stating R2 |
| `271`–`279` | comment on `ACCEPTED_NON_COVERED` stating why it stays `{}` — value unchanged |
| `1562`–`1580`, `1584`, `1593` | the two status-gate self-test fixtures retargeted `V6.1` → `V9.2`, with R6 as the comment |

The other lane's hunks are at `1227` (`import time`) and `1232`–`1287` (the
`copytree` replacement). Nothing else in the file was touched by this lane.

---

**`docs/decisions/README.md`** — this decision's index row. **Applied 2026-08-11**, executing [D119](D119-decision-index-identity-and-the-index-row-sections.md) §5 step 4; the former `## Index row` section is demoted to this line under D119 RULING 4, and RULING 6 puts the row in the act that commits the record.

## 8. Commands run, with verdicts

| # | command | verdict |
| --- | --- | --- |
| 1 | `python3 scripts/check-traceability.py` (before) | **exit 0**, green; matrix lane: *"all 16 row(s) at or before M0 read 'covered'"*, 55 references |
| 2 | `python3 scripts/check-traceability.py --matrix --milestone M2` (before) | **exit 1**, 11 problems, exactly the ids Q165 names, at `:67,77,102-107,116-118` |
| 3 | `python3 scripts/check-traceability.py --self-test` (before) | **exit 0**, 27 cases, 4 of them matrix cases |
| 4 | `python3 scripts/check-traceability.py --matrix --milestone M1`, matrix restored to `95fcee0` | **exit 1, exactly 6 problems** — `V6.1`–`V6.6`. Q165's *"moving it reddens a required lane"* confirmed |
| 5 | `git show HEAD:scripts/check-traceability.py \| grep -n` | `CURRENT_MILESTONE = "M0"` at `:244`, `ACCEPTED_NON_COVERED` at `:256` — Q165's citations exact; D115 §4.1's `:241` is a comment line |
| 6 | `cargo test -p antseal-core --test tamper_matrix -- <3 tests> --exact` | **3 passed**, 6.69 s — `V2.3`'s evidence executes |
| 7 | `cargo test -p antseal-core --test anchor_real_tokens -- <2 tests> --exact` | **2 passed** — `V7.2`'s real-token evidence executes |
| 8 | 41-reference resolver replay against `resolve()`'s own rules | **41 checked, 0 bad**, before any cell was written |
| 9 | `python3 -c` over `testdata/tamper/MATRIX.json` | 23 families, 6 at M2, **8 row ids** — the bullet's five clauses are eight rows |
| 10 | `find testdata/anchors -type f \| wc -l` | **88** |
| 11 | `python3 scripts/check-traceability.py` (after) | **exit 0**, green; *"all 22 row(s) at or before M1 read 'covered'"*, **97 references resolved** |
| 12 | `python3 scripts/check-traceability.py --matrix --milestone M2` (after) | **exit 1, 1 problem** — `V7.1` reads `gap`. The honest answer to "would M2 pass today?" |
| 13 | `python3 scripts/check-traceability.py --self-test` (after) | **exit 0**; all four matrix cases pass on the retargeted fixtures |

Note on measurement hygiene: the first three runs of this lane were piped to
`tail`, so `$?` reported **`tail`'s** status and printed `EXIT=0` for a command
that had exited 1. Every exit code in this table was re-taken without a pipe.
That is the same class of defect as Q149's red-by-exit-code sweep, produced by
this lane on its own first command.

---

## 9. What this does not do

- **It does not build `scripts/anchor-smoke`.** `V7.1` stays `gap` until that
  entry point exists; it is A25's, and A25 is open.
- **It does not resolve A105.** `V7.2`'s cell records the limitation and names
  the shape of the fix; the named verdict-level test is A105's to write, and
  the cell says so.
- **It does not run the M1 devnet suites.** No devnet was launched. Their
  evidence is existence plus `e2e-devnet.sh`'s independent `live` registration,
  which is what `covered` means in this file — *"a test exists and is named
  here"*.
- **It does not touch `TODO.md` or any `tasks/*.md`.** The Q165 row and entry
  amendments in the front matter are described for the orchestrator.
- **It does not correct D115 §4.1.** Blocked on `Q122`.
- **It does not move `CURRENT_MILESTONE` to `M2`.** That is the M2 review's
  edit, and §5 (c) is the argument for why it is one character when it comes.
- **It did not reformat `scripts/check-traceability.py`**, whose other lane was
  mid-edit throughout.

---

## 10. Discovered work — described, not registered

No ids are minted here. Each item is a description with its evidence.

**(i) Nothing makes a milestone review move `CURRENT_MILESTONE`, and that is
the defect that produced this whole decision.** The constant is documented as
*"the line a milestone review bumps"* in two places and no checklist, runbook or
gate bumps it. M1's review did not. The durable fix is not a bigger comment: it
is either a review checklist item, or a check comparing the constant to the
milestone `TODO.md`'s Current-focus block declares — the project already has a
register of that fact, and nothing reads it. Small, and it closes the class
rather than this instance.

**(ii) A second class of self-test fixture pinned to a mutable row's status may
exist.** Two were found here because they broke loudly. The generalisation —
*any* self-test fixture whose mutation string embeds a value that a normal edit
may change — has not been swept. `--self-test`'s no-op guard makes the class
self-announcing rather than silent, so this is a sweep for confidence, not for
safety. It is the same shape as A123's document-wide `REGISTRY.contains()`
finding: a fixture that pins a coincidence rather than the property.

**(iii) The matrix's section preambles are unchecked prose asserting the state
of the tree, and two of the five were badly wrong.** M1's and M2's each carried
three false clauses for eight days. The rows are machine-checked; the prose
around them is not, and it is what a reader reads first. Worth a decision on
whether such paragraphs should exist at all, or be reduced to statements the
checker can verify. This file's own Finding 1 is the precedent — a stale
*paragraph* survived a wave after the *row* it described was corrected.

**(iv) `V7.1`'s gap has a scope beyond the matrix.** `docs/anchors/real-smoke-runbook.md`
§0 and A25 Accept row 1 already name the missing `anchor-smoke` script, and
Q99's Accept row 1 makes the same script the precondition for deleting that §0.
Three documents are now waiting on one script, and a fourth — this matrix row —
joins them today. Whoever schedules A25 should know it unblocks four things.

**(v) D115 §4.1 mis-routes `V7.2` to A25's Accept row 1.** Row 1 is the OTS
cycle (`V7.1`); `V7.2`'s bullet is row 2, adjudicated SATISFIED and not blocked
on the script. The practical consequence is that A105's entry tells its
executor `V7.2`'s status is blocked on work that does not block it. Blocked on
`Q122` like the line-number correction, and worth carrying in the same change.

---

## Outcome

Eleven rows read `deferred` at or before M2. Ten were stale by between four and
eight days and are now `covered` with evidence that resolves and, where it
executes, executes. One — `V7.1` — is a genuine gap that a large and honest
pile of real captured fixtures had been concealing, and it now reads `gap`,
where it will block M2's review rather than be silently exempted from it.

`CURRENT_MILESTONE` moves `M0` → `M1`: twenty-two of thirty-four rows are now
gated by the run every lane actually performs, where sixteen were. The flagless
run is green. `--matrix --milestone M2` fails on one row, and that failure is
now information.

M1's gate was not wrong about M1. It was right about work while its own record
said the opposite and its own instrument was pointed at the wrong milestone —
and the reason no one noticed for eight days is that the only command that
would have said so is one no runbook asks anyone to type.
