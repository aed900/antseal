# D187 — One policy for unreachable-by-construction error paths, two outcomes: `R57`'s `proof_unit_refs` arm is **kept and documented**, and `U42`'s `ResumeSafetyReason::SourceChanged` is **deleted before `U32`**, with no class, exit code or `ALL` moving

- **Status: RESOLVED. H4 survived.** H4 read: shrink — delete the
  never-constructed `SourceChanged` and its exemplar before `U32` freezes them,
  and document R57's arm as unreachable by construction.
  - **Both measurable premises held.** The deletion is small — two snapshot
    lines, one exemplar, one test rewritten, one module-doc row, the variant
    and its Display arm — and moves no exit code or class (§1.2). No ruled
    future path needs the variant, and two ruled records forbid the behaviour
    its frozen text describes (§1.2).
  - **What fell is `U42`'s own framing.** *"The same question R57 asks — and
    apply the same answer to both"* is half true. Measured, the two subjects
    differ on all four axes that decide keep or remove (§1.3), so one policy
    gives two outcomes.
  - **`U42`'s stakes were misstated.** *"Shrink the error universe by one"*
    (`TODO.md:572`) is false: `resume-safety-abort` (24) lives on through
    `StagedBytesMissing`, so the message set shrinks by one and the class set
    does not. Its Accept names *"`ALL`"*, but `ResumeSafetyReason::ALL` does
    not exist and `ErrorClass::ALL` does not move.
  - **`R57`'s subject was re-verified, and it is a field.** The 2026-07-31
    review's U17 finding is **true**. `proof_unit_refs` is a struct field
    (`antseal-core/src/verify/structural.rs:145`), which is why a search for
    `fn proof_unit_refs` returned nothing.
- **Date: 2026-10-17**
- Owner rows: **`R57`** (§2 R1–R2); **`U42`** (§2 R1, R3–R4).
- Related:
  - **R54** (`check_manifest_refs`' arm, documented rather than removed — the
    precedent this record makes two-way);
  - **D45** §4 (D45:99-102: S11's changed-source case **resumes** from staged
    bytes);
  - **`S11`** (Accept: *"Changed-source test: mutating source files after
    staging has zero effect on resumed uploads (source never read)"*,
    `tasks/S.md:153`);
  - **`U17`** (Accept row 4, `tasks/U.md:327`; its changed-source half is
    superseded, §2 R4);
  - `docs/format/registry-v1.md` §7.6 (bundle key 10, `range_reveals`, v1.1);
  - the antseal-core error-code universe gate (R57's Problem: R54 documented
    its arm *"rather than removed because the code must stay emitted (D30 §3 /
    universe gate)"*);
  - **`U32`** (the freeze `U42` must land before).

## 0. What was measured against

`HEAD` `23f3093` (local `main`; `origin/main` = `cfd5868`). The tree was clean
when planning began.

Planning lane P1 (wave 38, 2026-10-17) worked read-only and ran no cargo build
or test; every claim below was read from code and docs with the line quoted.

Before this record was written, the records lane re-read every locator below at
`HEAD` through `git show 23f3093:<path>`, because implementing lanes had already
begun editing `crates/antseal-cli/src/error.rs` and
`crates/antseal-cli/tests/exit_codes.rs`, and L-VOCAB owns `structural.rs`'s
rustdoc this wave. Every citation held. One check the planned edit list relied
on did **not** hold, and §3 records what was measured instead: the review grep
for `changed source` matches the replacement row-24 text that §2 R3 itself
prescribes.

## 1. What was measured

### 1.1 `R57`: the arm, and why it cannot fire through the pipeline

- **The field.** `antseal-core/src/verify/structural.rs:142-145`: *"`unit_id`s
  referenced by GGM covers and boundary paths. These must name **revealed**
  units: a proof may only speak about disclosed bytes."* /
  `pub proof_unit_refs: &'a [u64],`.
- **Its population.** `verify/pipeline.rs:540-544` builds it from
  `bundle.covered_reveals()` (passed at `:555`). The revealed set is
  `bundle/schema.rs:1732-1742` `revealed_unit_ids()`, the covered reveals
  chained with the non-covered ones. So the proof references are a subset of
  the revealed ids **by construction**.
- **The arm.** The third loop of `check_reveal_refs`
  (`structural.rs:279-286`) returns `UnknownUnitRef` (`:284`) for a reference
  not in `seen`. After the first loop (`:261-268`) completes, `seen` equals the
  revealed set, which contains every reference, so through `verify_bundle` the
  arm cannot fire. Neither the arm, the field (`:142-145`) nor the function's
  doc (`:237-249`) says so.
- **The code stays reachable elsewhere.** The first loop's existence check
  (`:261-264`) emits `unknown-unit-ref` through the pipeline, driven by the
  tamper row `verify-unknown-unit-ref` (`tests/tamper_matrix.rs:383-389`,
  *"reveal a unit_id absent from the manifest"*) and listed in
  `COVERED_BY_SEED_ROWS` (`src/test_util/tamper_rows_structural.rs:840-848`).
  The arm itself is driven through the public stage function by
  `proof_referencing_an_unrevealed_unit_is_rejected` (`structural.rs:645`).
- **R54 points at R57, one way only.** `structural.rs:210-212`, on
  `check_manifest_refs`: *"(The same tautology-by-construction holds for
  `proof_unit_refs` in [`check_reveal_refs`], whose pipeline population is a
  subset of the revealed ids by construction — recorded as U17.)"*; D10:1046-1053
  says the same. Nothing points back from the arm.
- **A ruled document forbids deleting it.** `docs/format/registry-v1.md:991-998`:
  the state is *"**unrepresentable in v1** and that check idles. It stops idling
  the moment bundle key 10 (`range_reveals`) is assigned in v1.1, where a range
  proof may well name units by id from a separate section — recorded so the
  check is not deleted as dead code."*
- The review that found it (`docs/reviews/2026-07-31-adversarial-code-review.md:187`)
  cites `verify/pipeline.rs:343`; the population now sits at `:540-544`.

### 1.2 `U42`: a reason nothing constructs, whose frozen text contradicts two records

- **The variant** is `ResumeSafetyReason::SourceChanged` (`error.rs:252-274`; the enum opens at `:251`).
  Its own doc says nothing constructs it and keeps it as *"the frozen class for
  any future path that *does* read plaintext against a journaled nonce (a
  re-stage or repair feature would need exactly this refusal)"* (`:268-272`).
- **Its Display** (`error.rs:283-287`), frozen at
  `cli-errors.display.txt:59-60`: *"a source file changed since the interrupted
  seal: resume never re-encrypts (re-using a journaled nonce on new plaintext
  would break the encryption), so this seal is abandoned; re-run `antseal seal`
  to start a fresh one"*.
- **Only tests construct it:** `tests/exit_codes.rs:401-406` (the
  `resume-source-changed` exemplar) and `tests/seal_command.rs:1419`, inside
  `the_two_resume_safety_aborts_are_distinct_and_say_what_they_protect`
  (`:1406-1445`). `git grep -n SourceChanged 23f3093 -- crates/` finds those
  two and the definition and match arm (`error.rs:274`, `:283`), nothing else.
- **Deleting it removes no class.** `resume-safety-abort` (24) lives on through
  `StagedBytesMissing` (`pipeline/error.rs:276-278`; `pipeline/journal.rs:580-585`),
  with its own exemplar at `cli-errors.display.txt:61`. `ErrorClass::ALL` (35)
  and the `TABLE` in `tests/exit_codes.rs` are unchanged.
  `git grep -n 'ResumeSafetyReason::ALL' 23f3093 -- crates/` returns 0 lines.
- **Its frozen text describes an outcome two ruled records forbid.** D45:99-102:
  *"S11's safety aborts (changed source with staged bytes intact → resume from
  staged bytes; staged bytes unavailable → abandon with forfeiture message) pass
  through U17 unchanged"*; and S11's Accept (`tasks/S.md:153`): *"mutating source
  files after staging has zero effect on resumed uploads (source never read)"*.
  The exemplar says *"so this seal is abandoned"* for exactly the case D45 rules
  **resumes**.
- **No ruled record names the future consumer.** A case-insensitive search of
  `docs/decisions`, `MVP-SPEC.md`, `tasks/` and `docs/format` at `HEAD` for
  `re-stag|restag|repair feature|regenerate staged` finds one line,
  `tasks/Q.md:2730` (*"restage the lock file"*, a git-harness matter), and
  nothing about resume; `MVP-SPEC.md:145` rules the lost-staged-bytes case to
  abandon, not repair.
- **Green witnesses that a changed source is a non-event:**
  `resume_uploads_exactly_the_journaled_staged_bytes`
  (`tests/seal_resume.rs:252`, mock) and
  `case3_changed_sources_with_staged_bytes_intact_resume_from_staged_bytes`
  (`tests/e2e_kill_resume.rs:1946`, devnet, which asserts the restored content
  is the original text).
- **`U17` Accept row 4 was never literally true about codes.** It reads
  *"changed-source and missing-staged-bytes scenarios produce the two distinct
  messages/exit codes"* (`tasks/U.md:327`), but both reasons share exit 24 by
  design: *"one exit code, distinguishing messages"* (`error.rs:248-249`).

### 1.3 The four axes that decide keep or remove

| Axis | `R57`'s arm | `U42`'s variant |
|---|---|---|
| A reachable twin keeps the code emitted | yes (`structural.rs:261-264` and its tamper row) | not applicable: class 24 lives on regardless |
| Reachable through a public stage function | yes (`check_reveal_refs` is `pub`; a unit test drives it) | no |
| A ruled future consumer | **yes** (registry v1.1, bundle key 10) | **no**, and it contradicts D45:99-102 and S11's Accept |
| A frozen surface of its own | none | `cli-errors.display.txt:59-60` |

Restructuring R57's arm instead of documenting it is not buildable in v1: the
nesting makes a proof's references the covered ids, so no independent source
for them exists to check against.

## 2. RULING

### §2 R1 — The policy

An unreachable-by-construction error path is **kept and documented** when it is
reachable through a public stage function or named by a ruled future consumer,
**and** owns no frozen user-facing surface. It is **removed** when it is
constructed by nothing, owns a frozen exemplar, and describes an outcome a ruled
record forbids.

*Why two outcomes:* the axes in §1.3 are the ones that decide whether keeping a
path costs anything. A kept path with a public caller and a ruled future is a
backstop; a kept path with a frozen exemplar and a forbidden outcome is a
promise `U32` would freeze against the product's own rules.

### §2 R2 — `R57`: document the arm, and keep it

L-VOCAB adds the documentation on the arm (`structural.rs:279-286`), on the
field (`:142-145`) and in `check_reveal_refs`' doc (`:237-249`):
- the arm is unreachable from `verify_bundle` in v1 **by construction** — R5
  populates `proof_unit_refs` from `covered_reveals`, a subset of
  `revealed_unit_ids`, so `seen` already holds every reference;
- it is kept as the public stage function's backstop (R54's policy on
  `check_manifest_refs`), and because `docs/format/registry-v1.md:991-998`
  records it as idling only until bundle key 10 (`range_reveals`, v1.1);
- `unknown-unit-ref` stays pipeline-reachable at the existence check (tamper
  row `verify-unknown-unit-ref`).

R54's doc and this one cross-reference each other, so the two arms read as one
policy (R57 Accept 2). No code moves; the Q52 universe is unaffected.

### §2 R3 — `U42`: delete `SourceChanged` before `U32`

- Delete `ResumeSafetyReason::SourceChanged`, its doc and its Display arm.
  **Keep the enum** with its one variant, so `CliError::ResumeSafetyAbort {
  reason }` and its JSON are unchanged and a future reason is additive.
- `error.rs:34`, module-doc row 24, becomes: *"spec line 145: missing staged
  bytes — never re-encrypts (a changed source is not an abort: resume never
  reads a source file, D45 §4)"*.
- `cli-errors.display.txt` loses two lines (`:59-60`).
- `tests/exit_codes.rs:401-406`: the `resume-source-changed` exemplar is
  removed.
- `tests/seal_command.rs:1406-1445` is rewritten as a single-reason test that
  keeps every `StagedBytesMissing` assertion.
- No class, exit code or `ErrorClass::ALL` moves. `U42`'s *"shrink the error
  universe"* and *"`ALL`"* were wrong, and this record says so (§1.2).

*Why remove:* every removal criterion of §2 R1 holds — nothing constructs it,
it owns a frozen exemplar, and that exemplar says *"so this seal is abandoned"*
for the case D45 and S11 rule **resumes**. Its hypothetical consumer (a
re-stage or repair feature) is named by no ruled record. If one is ever ruled,
a new reason is additive to the kept enum.

### §2 R4 — `U17` Accept 4's changed-source half is superseded

The orchestrator adds a dated note: `U17` Accept row 4's changed-source half is
superseded by S11 and D45's stronger property — a resume re-uploads the
journaled staged bytes and never reads a source file. The missing-staged-bytes
half stands.

## 3. Fault plants

The implementing lanes owe these. Green baselines come first; each plant is
judged by its **message**; every restore is followed by a `touch`.
`tests/exit_codes.rs` spawns the binary and runs in a private
`CARGO_TARGET_DIR`.

**`R57` (doc only) — the green tests stay green, and both halves of the policy
can fail**

- Green: `proof_referencing_an_unrevealed_unit_is_rejected`
  (`structural.rs:645`; the arm stays live through the public function), the
  tamper row `verify-unknown-unit-ref` (the code stays emitted), and
  `error_code_universe_has_not_lost_or_renamed_a_code`
  (`antseal-core/src/error_universe.rs:568`; unchanged by a doc edit).
- Plant: delete the third loop → `proof_referencing_an_unrevealed_unit_is_rejected`
  reddens.
- Plant: delete the existence check → the tamper row reddens.

Together they show that "document, don't delete" is guarded at both sites.

**`U42`**

- Green: `display_output_matches_committed_snapshot` (`tests/exit_codes.rs:614`,
  re-blessed with the two lines gone); the rewritten `StagedBytesMissing` test;
  `resume_uploads_exactly_the_journaled_staged_bytes`; and, on the devnet,
  `case3_changed_sources_with_staged_bytes_intact_resume_from_staged_bytes`.
- Plant: put the `resume-source-changed` exemplar back without re-blessing →
  the snapshot test reddens.
- **The review grep, as planned, cannot pass — measured.** The planned check
  was `command grep -n 'changed source' crates/antseal-cli/src/error.rs` → 0.
  The replacement row-24 text that §2 R3 prescribes contains *"a changed source
  is not an abort"*, which that needle matches (measured: the prescribed line
  piped through `command grep -c 'changed source'` prints `1`). The check this
  record adopts instead names what is retired:
  `command grep -n -E 'changed source /|SourceChanged|a source file changed since' crates/antseal-cli/src/error.rs`
  → 0 lines after the edit. It can fail: at `HEAD` it returns 4 (`:34`,
  `:274`, `:283`, `:284`). Positive control: the new row's
  `resume never reads a source file` is present. No test enforces the module
  doc, so this grep is a review step, recorded in §6.

## 4. What this record does NOT decide

- **A re-stage or repair feature.** None is ruled. If one is, it brings its own
  refusal reason, additive to the kept enum, and its own record.
- **Restructuring `R57`'s arm.** Refused as unbuildable in v1 (§1.3). When bundle
  key 10 is assigned in v1.1, the arm stops idling and the doc this record adds
  must be revised in the same change.
- **The stale locator in the 2026-07-31 review** (`:187` cites
  `verify/pipeline.rs:343`). A dated review is history; its row cites the
  finding, not the line.
- **The historical notes** that describe `SourceChanged` (`tasks/U.md:334`,
  `TODO.md:1380`) stay as written.

## 5. Edit list — per write scope, with the lane named before this record was written

### L-VOCAB (round 1) — `R57`, §2 R2

- `crates/antseal-core/src/verify/structural.rs`, rustdoc only: the arm
  (`:279-286`), the field (`:142-145`), `check_reveal_refs`' doc (`:237-249`),
  and optionally R54's parenthetical (`:210-212`) so it cites the registry too.
- Optional: one comment line at `crates/antseal-core/src/verify/pipeline.rs:540`.
- The `wasm32` build of antseal-core stays green (a doc edit cannot change it,
  and the close gate re-proves it).

### L-ERR1 (round 1) — `U42`, §2 R3, first in the lane (before D185)

- `crates/antseal-cli/src/error.rs`: `:34` (row 24), the variant and its doc
  (`:252-274`, keeping the enum's doc honest), the Display arm (`:283-287`).
- `crates/antseal-cli/tests/exit_codes.rs:401-406`.
- `crates/antseal-cli/tests/seal_command.rs:1406-1445`.
- `crates/antseal-cli/tests/snapshots/cli-errors.display.txt:59-60`.

### Orchestrator — `TODO.md`, `tasks/U.md`, `tasks/R.md`, `docs/decisions/README.md`

- `R57` and `U42`: the ticks; `U42`'s misstated stakes recorded per §1.2.
- `U17` Accept row 4: the dated note of §2 R4.
- This record's index row and register row.

## 6. As built — wave 38, lanes L-ERR1 (`U42`) and L-VOCAB (`R57`) (recorded in place before this record was first committed)

Every verdict below was read from an exit file.

- **§2 R3, `U42` (L-ERR1).** `ResumeSafetyReason::SourceChanged` is deleted: its variant, its doc
  and its Display arm. The enum keeps one variant, so `CliError::ResumeSafetyAbort` and its JSON
  are unchanged, and no class, exit code or `ErrorClass::ALL` entry moved.
  - The enum's doc says why there is no changed-source reason, without naming the deleted
    identifier, so that the review needle cannot re-trip on prose.
  - Row 24 of the module doc reads *"spec line 145: missing staged bytes — never re-encrypts
    (a changed source is not an abort: resume never reads a source file, D45 §4)"*.
  - The `resume-source-changed` exemplar is gone, and `cli-errors.display.txt` lost exactly two
    lines.
  - The test became `the_resume_safety_abort_says_what_it_protects`, keeping every
    `StagedBytesMissing` assertion and adding `never re-encrypts`.
  - Unblessed, the snapshot test failed by its drift message; blessed, it passes.
- **§3's review step, as corrected before landing.** `command grep -n -E 'changed source
  /|SourceChanged|a source file changed since' crates/antseal-cli/src/error.rs` returns 4 at
  `23f3093` (`:34`, `:274`, `:283`, `:284`) and 0 after. The positive check, *"resume never
  reads a source file"*, has one hit (`:34`).
- **§2 R2, `R57` (L-VOCAB), documentation only.** The `proof_unit_refs` field, `check_reveal_refs`
  (a new section on the arm, unreachable from `verify_bundle` in v1 and kept), the third loop's
  comment and R54's parenthetical in `check_manifest_refs` all cite this record. One comment line
  was added in `pipeline.rs`.
  - The registry passage that records the idling is §7.11 (*"Covered-unit reveal"*), not §7.6:
    §7.6 only reserves bundle key 10. All three sites cite §7.11, by section, not by line.
- **Plants.**
  - R57a (the third loop deleted) reddened `proof_referencing_an_unrevealed_unit_is_rejected`:
    *"proof reaches outside the reveal"*.
  - R57b (the first loop's existence check deleted) reddened the tamper row
    `verify-unknown-unit-ref`: *"the surface ACCEPTED the tampered artifact … it must fail with
    error:unknown-unit-ref"*.
  - Two negative controls stayed green, each with the other plant applied, so the two guards are
    independent.
  - These ran in a copy of the tree with a private target directory (see D190 §6).
- **At the lanes' close.**
  - `cargo test -p antseal-cli --test exit_codes` passed 8 and `--test seal_command` passed 31.
  - `antseal-core`'s whole suite passed 1 823, including `--lib verify::structural` 19 and
    `--test tamper_matrix` 38. The error-universe test is unchanged.
- **The orchestrator's acts.** `R57` and `U42` are ticked, and `U42`'s tick records the misstated stakes of §1.2. `U17`'s Accept row 4 carries §2 R4's dated note.

## Closing — this record is not consent

It deletes one error reason and documents one arm inside the wave's own
commits. Nothing in it authorises a push, a workflow dispatch, a deploy or any
other outward act; each of those needs the maintainer's express consent naming
the action, the destination and the account.
