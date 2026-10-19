# D197 — An interrupted seal that never finished staging is **discarded by its exact re-run, which seals afresh**: pre-staging is measured from records that already exist, never tagged, and the journal gains one transition from an absent tag so that `antseal abandon` can exit it too

- **Status: RESOLVED. H2 fell (b): its destination survived and its mechanism fell.**
  - **H2** — *"a pre-staging journal state written in the SAME write as the meta record
    (closing L-ERR1's begin-internal window between create_work and the Staged tag), and an
    exact re-run of a work in that state restarts it fresh with a notice (nothing was quoted,
    consented or paid) — no new exit code; `antseal abandon` can exit it too."*
  - **What survives: the destination.** An exact re-run restarts fresh with a notice (§2 R2),
    no exit code is minted (§2, *What no ruling here moves*), and `antseal abandon` can exit the
    state (§2 R4).
  - **The mechanism falls.** The meta record and the state record are two files written by two
    atomic renames, and the store publishes no set of records together (§1.1). A "same write"
    exists only as a meta-record format change — a fifth coarse `WorkState` or a new meta
    field — which bumps `WORK_RECORD_VERSION` (`crates/antseal-cli/src/vault/store.rs:91`),
    touches 51 `WorkState::` references in 12 source files, and adds values to `list --json`
    vocabularies that `U32` freezes (§1.6, option A).
  - **It is also unnecessary.** Pre-staging is measurable from records that already exist.
    Wave 38's `staging_never_finished` (`crates/antseal-cli/src/seal_resume.rs:741-745`)
    already measures window 2, and lacks only window 1's absent tag (§2 R1).
  - **Found with it: window 1 is worse than the row says.** The row's Notes quote the internal
    detail *"work has no journal state record"*. The user sees exit **12**, the
    wrong-passphrase-or-tamper sentence, on every re-run, and `antseal abandon` meets the same
    exit after the user has confirmed (§1.3).
  - **The row's `Barrier` is refused** (§2 R8). It cannot reach window 1, and the existing
    seams reach both windows.
  - **The planner's one question is ruled here** (P1 §5): the auto-restart discards a
    pre-staging work without D51's destructive confirmation (§2 R2).
- **Date: 2026-10-19**
- Owner row: **`S45`** (§2 R1–R8). This record mints no row.
- Related:
  - **D45** §2 (the matching table; takes a dated addendum: a new row) and §5 (the dry-run
    detail; R5 narrows it);
  - **D106** R4 (`state()` stays hard; takes a dated addendum: `set_state`'s one absent-tag
    transition);
  - **D185** §2 R6 (T3's mapping, retired by R7) and §4 (the deeper fix, discharged; takes a
    dated addendum);
  - **D97** (the precedent: a new closed-enum journal tag is a format event);
  - **D49** (`--dry-run` writes nothing), **D51** (the destructive-confirm table; this record
    adds no row to it), **D36** (the fresh seal's consent), **D134** §2 R3 (no exit code moves);
  - MVP-SPEC line 145 (an in-progress seal whose staged bytes are unavailable is abandoned, and
    a fresh seal starts with a new `seal_id` and fresh nonces);
  - **`S10`** (the journal state machine), **`S11`** (resume never re-encrypts), **`U41`** (the
    abandon verb), **`U32`** (the freeze this lands before).

## 0. What was measured against

`HEAD` `07a170c` (local `main` = `origin/main`), tree clean, 2026-10-19.

Planning lane P1 (wave 39) worked read-only and ran no build. Every claim it made was read from
code, tests, the spec and the records, with the line quoted; both windows are traced through
code, not executed. The orchestrator's mid-round note — lane PS's list of the pins a new journal
state or a new barrier would move — was folded into P1's report and re-verified there.

Before this record was written, the records lane re-read the load-bearing locators through
`git show 07a170c:<path>`, because round-1 lanes were starting to edit the tree. Every figure
below held, with two refinements:
- the barrier count pin is `crates/antseal-cli/src/pipeline/error.rs:498`
  (`assert_eq!(count, 8, "S12 names eight step boundaries")`); P1 wrote `:497`, which is the
  uniqueness assert beside it;
- `git grep -c '\.begin(&' 07a170c -- crates/` counts **42** call sites, one of them the
  production call at `crates/antseal-cli/src/pipeline/seal.rs:279`, so **41** are fixtures
  (P1's figure); `git grep -n 'fn begin'` finds 4 definitions (the positive control).

## 1. What was measured

### 1.1 `begin` is two writes, so a work can exist with no fine tag (window 1)

- **The meta record.** `crates/antseal-cli/src/pipeline/vault_journal.rs:135`
  `self.store.create_work(&record, &mut **rng)?;` → `crates/antseal-cli/src/vault/store.rs:382`
  `self.write_meta(record, rng)` → `:423` `atomic_write(&path, &sealed)`. The record's coarse
  state is `SealState::Staged.work_state()` (`vault_journal.rs:123`), which is
  `WorkState::IncompletePrePay` (`crates/antseal-cli/src/pipeline/journal.rs:233`).
- **The fine tag, a second file.** `vault_journal.rs:137`
  `let bytes = encode_state(SealState::Staged)?;`, then `:139-140` `put_journal_entry(…,
  STATE_ENTRY, …)` → `store.rs:579` `self.require_work(seal_id)?;` (the meta file must exist)
  → `:590` `atomic_write(&path, &sealed)`.
- **Nothing makes the pair atomic, by design.** `store.rs:67-69`: *"every write is one atomic
  rename — but **not each work whole**: a work is several records and nothing publishes a set
  of them together."* The enumeration already expects the gap (`vault_journal.rs:343-345`):
  *"because `begin` is two writes, the absence is *expected* under a concurrent seal."*

### 1.2 Window 2: from `sink.begin` to `sink.put_plan`, nothing is quoted, consented, anchored or paid

- `crates/antseal-cli/src/pipeline/seal.rs:279` `sink.begin(&WorkIdentity {`; each unit's
  `sink.put_staged(&seal_id, &blob)?` (`:321`) and the manifest's (`:346`); `sink.put_plan(`
  (`:351`); `sink.record_outcome` (`:358`); `Barrier::PostStagingJournal` (`:359`).
- **The first backend call is `:372`**, `self.backend.quote_batch(&blobs).await?`. In both
  windows nothing has been quoted, consented to, anchored or paid.
- **`Staged` contradicts its own doc.** `journal.rs:164-165`: *"Every staged blob (units +
  encrypted manifest) and the plaintext manifest are durable. Nothing anchored, nothing
  paid."* `begin` writes the tag before any blob exists.

### 1.3 What an exact re-run does today, in each window

- **Detection reads the coarse tag.** `crates/antseal-cli/src/seal_run.rs:375` calls `detect`,
  whose candidate set is built from the meta record's state (`seal_resume.rs:154-157`), so
  both windows are exact-match candidates (`:186-203` → `ResumeDecision::Resume`).
- **A false notice, then a network read.** `seal_run.rs:376-378` prints *"Resuming the
  interrupted seal {id} — re-running the same command is how resume works (D45); nothing is
  re-encrypted."* (`seal_resume.rs:107-110`), then reads `backend.balances()` over the network
  (`seal_run.rs:401-404`), then calls `pipeline.resume` (`:455`).
- **Window 2 → usage (2).** `crates/antseal-cli/src/pipeline/resume.rs:153-156`
  `.ok_or(SealError::NothingStaged)?`; `seal_run.rs:464-469` maps it, when
  `staging_never_finished` holds, to D185 R6's text (`seal_resume.rs:766-768`): *"seal {id} was
  interrupted before its staging finished: nothing was anchored or paid for it and there is
  nothing to resume — discard it with `antseal abandon {id}` and re-run this command"*, frozen
  at `crates/antseal-cli/tests/snapshots/cli-errors.display.txt:95-96`.
- **Window 1 → exit 12, a false tamper alarm.** `resume.rs:147` `self.journal.state(seal_id)?`
  → `vault_journal.rs:258-259` `Err(corrupt("work has no journal state record"))` →
  `journal.rs:688` `JournalError::Corrupt { .. } => CliError::VaultAuthFailure` → exit 12
  (`crates/antseal-cli/src/error.rs:428`), whose Display (`error.rs:636-639`) is *"vault
  authentication failed: wrong passphrase, or the vault store or header has been modified or
  corrupted"*. The detail is dropped, and the alarm repeats on every re-run. `S45`'s Notes
  (`tasks/S.md:669`) quote only the internal detail.
- **`antseal abandon` cannot exit window 1.** `seal_resume.rs:708` `AbandonPreview::read`
  renders *"the journal records no state for it"* (`:623`), the user confirms, `:727` calls
  `abandon_pre_pay`, and `:451-453` `journal.set_state(seal_id, SealState::Abandoned)` starts
  with `vault_journal.rs:221` `let current = self.state(seal_id)?;` — exit 12, after the yes.
  D106 R4 kept `state()` hard on purpose (`crates/antseal-cli/tests/seal_journal.rs:718-720`:
  *"a state machine that cannot read the current state must not advance"*).
- **`--dry-run` describes a plan that does not exist.** `seal_run.rs:394-395` returns
  `ResumePlan(resume_plan_lines(candidate))`; for `Some(Staged)` that prints *"encrypted units
  and manifest are staged in the vault"* and *"anchor, pay, upload"*
  (`seal_resume.rs:787-790`) — false for a work with no plan, whose real run then fails.

### 1.4 No live writer can own a pre-staging work that a `seal` sees

`crates/antseal-cli/src/commands.rs:365-366` takes `VaultLock::acquire(…)` and binds it to
`_lock` for the whole of `seal_over_backend`, `run_seal` included (`:441-451`); `abandon` takes
the same lock (`:1190-1191`). A pre-staging work that a seal sees under the lock was left by a
dead process.

### 1.5 The spec already prescribes the outcome, and `S11` already acts on it without asking

- `MVP-SPEC.md:145`: *"So if staged bytes are unavailable, the in-progress seal is
  **abandoned** — a fresh seal starts with a new `seal_id` and freshly drawn nonces (never the
  journaled nonce table)"*.
- `S11` abandons on that path with no confirmation (`resume.rs:324-331`):
  `let _ = self.journal.set_state(seal_id, SealState::Abandoned); Err(SealError::StagedBytes(reason))`.
- A work with no plan cannot even name its staged set: the plan record carries `unit_count`,
  *"written when staging finishes"* (`tasks/S.md:143`, `S10`'s Notes (3)).

### 1.6 A new tag is a format event, and a new coarse state is a larger one

- **The fine enum is closed.** `SealState::from_wire` (`journal.rs:203-213`) has a `_ => None`
  arm, and `decode_state` maps an unknown value to `corrupt("unregistered state")`
  (`journal.rs:1159`): exit 12 on any binary that predates a new tag. D97 is the precedent: a
  new tag on another closed enum (`ArtifactKind::from_wire`) would have raised *"the same
  false-tamper-alarm"* (D97:15), so D97 bumped `SEAL_JOURNAL_VERSION` 1 → 2 instead, at a
  measured cost of *"two literal edits and zero regenerated artifacts"* (D97:16-17);
  `journal.rs:132` reads `2`.
- **The coarse enum is closed too.** `WorkState::from_wire` (`store.rs:124-132`), and
  `StoreError::Corrupt` maps to `CliError::VaultAuthFailure` (`store.rs:293-295`).
- **A new fine variant moves pins and frozen vocabularies.** `SealState::ALL: [Self; 6]`
  (`journal.rs:185`); `assert_eq!(SealState::from_wire(7), None)` (`journal.rs:1226`);
  `abandon --json`'s `"previous_state": self.previous_state.map(SealState::name)`
  (`seal_resume.rs:347`); `list --json`'s `detail_state` (`crates/antseal-cli/src/listing.rs:503-507`).
  Both `--json` vocabularies are frozen at `U32`.
- **The v1 registry does not freeze the journal.** P1's search of `docs/format/registry-v1.md`
  for `journal|vault|SealState|WorkState` hits only prose about capture order.

### 1.7 The options

| Option | Closes window 1? | Closes window 2? | Cost |
|---|---|---|---|
| **A.** H2 as written: a pre-staging state in the *same write* as the meta record | yes, at the writer | yes | Only a fifth coarse `WorkState` or a new meta field: `WORK_RECORD_VERSION` 1 → 2 (`store.rs:91`); 51 `WorkState::` references in 12 source files, including two wildcard-free tables that exist to break on a fifth variant (`crates/antseal-cli/src/status.rs:1135-1141`, `:1164-1170`); new values in `list --json`'s `state` and `detail_state`. |
| **B.** A new fine variant `Staging` (wire 7), written by `begin` | **no**: `begin` is still two files | yes | `SEAL_JOURNAL_VERSION` 2 → 3 (the D97 route); moves `ALL: [Self; 6]` and the `from_wire(7)` pin; a new value in two `--json` vocabularies; an arm in every `match SealState`; `begin` → `set_state(Anchored)` fixtures break, since `Staging → Anchored` is not a legal transition. |
| **C.** Move the `Staged` write out of `begin`, to after `put_plan` | no: the same meta-only window, longer | yes | Breaks the fixtures that call `journal.begin` and then advance or read state: 41 fixture call sites (§0). |
| **D.** A measured predicate, and an exact re-run abandons and seals fresh (**ruled**) | yes, its consequence (the trap) | yes | No format event, no new variant, no new `--json` value, no new exit code. D106 handled the same two-write situation by predicate. |
| **E.** D as message only: keep usage (2), extend D185's text to window 1, fix `set_state` | yes | yes (today's state) | The smallest diff, but undoing a Ctrl-C takes three commands (re-run, abandon with confirmation, re-run), and a script must parse a usage error to recover. |
| **F.** Route into `S11`'s class (abandon, then exit 24) | yes | yes | `StagedBytesMissing`'s text claims *"any payment already made is forfeited"* (`error.rs:320-327`), false here, so a new `ResumeSafetyReason` — a new `reason` value in the U32-frozen `--json` error — and it still takes two runs. Strictly worse than D. |

### 1.8 The existing seams reach both windows; a barrier reaches one

- **Window 2:** call `journal.begin` directly. Wave 38's T3 test does exactly that, with one
  `put_staged` blob (`crates/antseal-cli/tests/seal_command.rs:1567`,
  `a_seal_interrupted_before_its_staging_finished_names_abandon_and_then_seals`).
- **Window 1:** `journal.begin`, then `store.delete_journal_entry(&id, STATE_ENTRY)` — D106 R4's
  on-disk reconstruction (`tests/seal_journal.rs:744-751`).
- **A pipeline barrier cannot reach window 1**: the window lies inside `VaultJournal::begin`,
  below the pipeline's barrier hook. A new barrier also moves four pins —
  `pipeline/error.rs:80` `ALL: [Self; 8]`, `:498` `assert_eq!(count, 8, …)`, and the exact
  crossed-barrier lists at `crates/antseal-cli/tests/seal_pipeline.rs:108-120` and `:372-379`
  (the dry-run's) — and obliges an `S16` row under *"One row per barrier"*
  (`crates/antseal-cli/tests/seal_matrix.rs:288-290`).

## 2. RULING

### §2 R1 — Pre-staging is measured, never tagged

A work is **pre-staging** if and only if all of these hold:
- its coarse meta state is `IncompletePrePay`;
- it has no plan record (`recorded_plan` is `None`; the plan is staging's last write);
- it has no receipt (`get_receipt` is `None`);
- it has no consent (`meta.consent` is `None`);
- it has no anchor slots (`list_anchors` is empty);
- its fine tag is absent **or** `Staged`.

`staging_never_finished` (`seal_resume.rs:741-745`) is extended to this predicate and keeps its
name.

*Why:* every record the predicate reads already exists, so no format event is needed (§1.6). The
consent, anchor and receipt clauses cannot fail on a vault the pipeline wrote, because each of
those records is written after `put_plan` (§1.2). They are there so that the predicate is a
measurement rather than an inference, in D185 R6's style, and the receipt clause is the money
guard (§3, G6).

### §2 R2 — D45 §2 gains a row: an exact match of a pre-staging candidate is abandoned and the run seals fresh

The new row of D45 §2's matching table:

| Relation to a candidate | Behavior |
|---|---|
| exact ordered path-list match ∧ shaping flags equal ∧ the candidate is pre-staging (R1) | **abandon it and seal fresh**, with a one-line stderr notice |

- **The notice** (P1's text; the lane may tighten it, and every clause must stay true by
  measurement): *"note: seal {id} was interrupted before its staging finished — nothing was
  anchored or paid for it, so it is discarded and this run seals the files afresh (a new seal
  id and fresh nonces; MVP-SPEC line 145)"*. It replaces the false *"Resuming the interrupted
  seal …"* for this shape.
- **The near-miss rows are unchanged.** 25 (overlap) and 26 (flag mismatch) keep D185 R6's
  *"or abandon it"* way forward, which R4 makes real for window 1.
- **No D51 destructive confirmation.** Nothing usable is lost: no plan names a staged set
  (§1.5). `S11` already abandons without asking on the same spec rule (`resume.rs:324-331`).
  The fresh seal still asks for consent before any payment (D36).

*Why:* MVP-SPEC line 145 already prescribes this outcome for staged bytes that are unavailable
(§1.5). A pre-staging work has no staged set that resume could use, and nothing was quoted,
consented, anchored or paid for it (§1.2). Option E's message-only alternative costs the user
three commands to undo a Ctrl-C (§1.7).

### §2 R3 — The abandon strictly precedes the fresh `begin`, under the vault lock

The restart calls the existing engine, `abandon_pre_pay(&store, &journal, &id)`
(`seal_resume.rs:400`), which re-checks the receipt and the terminal state itself. It is placed
immediately before `pipeline.seal(..)`, after `balances()` and the source read (`read_all`),
inside the command's existing U5 lock (§1.4).

*Why:* reversing the order lets a failure between the two leave **two** exact candidates, and the
next re-run is then `CliError::Internal` (`seal_resume.rs:191-199`). Placed this late, a run that
fails before the fresh seal could start — the balance read, or reading the source files —
leaves the old work as it was.

### §2 R4 — `set_state` accepts exactly one transition from an absent fine tag

`VaultJournal::set_state` (`vault_journal.rs:220-242`) accepts **one** transition from an absent
fine tag: → `Abandoned`, when the coarse mirror is `IncompletePrePay`. It writes the fine tag
first and the mirror second, the existing order (`:231-241`). Every other transition from an
absent tag stays `Corrupt`. `state()` itself is unchanged and stays hard (D106 R4, point 3).

*Why:* `can_advance_to`'s own rule is *"Every non-terminal state may abandon"* (`journal.rs:264`),
and the coarse mirror that `begin` wrote proves the work is non-terminal and pre-pay. This makes
`antseal abandon` work in window 1 (exit 12 after the confirmation today, §1.3), and the same
call that `S11`'s best-effort abandon makes (`resume.rs:330`) succeeds on such a work too. D106
takes a dated addendum.

### §2 R5 — `--dry-run` writes nothing

Under D49, a `--dry-run` whose inputs exact-match a pre-staging candidate runs the **fresh**
dry-run (encrypt and quote, journaling disabled) and abandons nothing. Its notice is conditional:
*"… a real run discards it and seals the files afresh"*. It never prints the `resume_plan_lines`
block, which describes a plan that does not exist (§1.3).

*Why:* D45 §5's dry-run detail — print the resume plan of an exact-matched **resumable** work —
assumed every exact match could be resumed. A pre-staging work cannot be, and what the real run
will do is seal fresh, so the rehearsal shows that run. This narrows D45 §5 (D45's addendum).

### §2 R6 — `SealState::Staged`'s doc is corrected; the write does not move

`journal.rs:164-165` becomes (P1's text): *"`begin` writes this tag, before any blob is staged;
the plan record — staging's last write — is what says staging finished (S45). Nothing anchored,
nothing paid."* The `SealJournal::set_state` trait doc states R4's one absent-tag transition.

*Why:* moving the write (option C) churns 41 fixture call sites (§0) for no reader-visible gain
once R1 exists, and it would not close window 1 (§1.7).

### §2 R7 — D185 R6's T3 mapping is retired

Remove `run_seal`'s T3 branch (`seal_run.rs:457-470`), `interrupted_before_staging`
(`seal_resume.rs:747-771`), its `TABLE` exemplar row (`crates/antseal-cli/tests/exit_codes.rs:558-567`)
and its two snapshot lines (`cli-errors.display.txt:95-96`). D185 takes a dated addendum.

*Why:* R2 makes the mapping unreachable. A work its guard matched (no plan, a `Staged` tag, no
receipt) is pre-staging under R1 whenever the pipeline wrote it, and `detect` now restarts it
before `pipeline.resume` is reached. Removing a frozen snapshot row is allowed before `U32`.

### §2 R8 — The row's `Barrier` is refused

`S45`'s Do asks for a `Barrier` between `begin` and `put_plan`. It is refused:
- it cannot reach window 1, which lies inside `VaultJournal::begin`, below the pipeline's
  barrier hook (§1.8);
- window 2 is reached by calling `journal.begin` directly (wave 38's T3 fixture), and window 1
  by `begin` followed by `delete_journal_entry(STATE_ENTRY)` (D106 R4's reconstruction);
- a barrier costs four pins (`Barrier::ALL: [Self; 8]`, the `count == 8` assert, two exact
  crossed-barrier lists) plus an `S16` matrix row (§1.8).

### What no ruling here moves

- **No exit code is minted or retired**, and no class is added: `PINNED_CLASS_COUNT` stays 36
  (`crates/antseal-cli/tests/namespace_disjointness.rs:85`). `usage` (2) keeps its other
  producers.
- **No `--json` key or value is added.** Window 1's `abandon --json` `previous_state` stays
  `null`, the value its rustdoc already documents (*"`null` when its journal carried no tag"*,
  `seal_resume.rs:338-339`).
- **One behavioural `--json` change:** `seal --dry-run --json` on a pre-staging exact match
  returns the fresh dry-run document instead of `{"dry_run":true,"resume":true,"quoted":false,"resume_plan":[…]}`
  (`seal_run.rs:321-326`). No schema moves.
- **`U32`-frozen surfaces:** one `cli-errors.display.txt` row is removed (R7); the help snapshot
  and the config keys do not move.
- **The gate:** this is the seal path, and `set_state` performs every paid-path transition, so
  the close gate runs with the heavy tier and the devnet E2E forced
  (`ANTSEAL_GATE_HEAVY=1 ANTSEAL_GATE_E2E=1`).

## 3. Fault plants

The implementing lane owes these. The red baselines come first, on the unedited tree; each plant
is judged by its **message**; every restore is followed by a `touch`. In-process tests run in the
shared target under the lock protocol, spawned tests in a private `CARGO_TARGET_DIR`, and the
plants in a shadow copy.

**The green tests — the load-bearing half**

- **G1 — window 2, then `run_seal`.** `journal.begin` plus one `put_staged` blob (the wave-38
  fixture, rewriting `seal_command.rs:1567`'s test). Expect `Ok(Sealed)`; the notice contains
  *"interrupted before its staging finished"* and the old seal id; the old work is `Abandoned`,
  fine and coarse; the new seal id differs; `Pay` is called once. **Red baseline:** today's
  usage (2), D185 R6's text.
- **G2 — window 1, then `run_seal`.** `journal.begin`, then `delete_journal_entry(STATE_ENTRY)`,
  with a positive control that `recorded_state` is `None`. Expect G1's outcome. **Red
  baseline:** exit 12, `VaultAuthFailure`.
- **G3 — `run_abandon` on window 1.** Expect `Ok`, `previous_state == None`, and the new preview
  line. **Red baseline:** exit 12, after the confirmation.
- **G4 — `--dry-run` on window 2.** Expect `Ok(DryRun)` with a real quote, an unchanged vault
  fingerprint, and the old work still `IncompletePrePay` / `Staged`.
- **G5 — machine mode without `--yes`, on window 2.** The fresh seal stops at consent (10); the
  old work is `Abandoned`; a re-run's `detect` returns `Resume` of the **new** work, not
  `Internal`.
- **G6 — `begin` plus `put_receipt`, no plan, then `run_seal`.** Not restarted: `Pay` is called 0
  times and the work is unchanged — the money guard. G6 must also assert the run's own outcome
  (no restart notice, and the result's class and text), not only `Pay == 0`: `abandon_pre_pay`
  re-checks the receipt (R3), so a restart under the receipt plant can be refused by the engine
  and still call `Pay` 0 times.
- **The R4 unit row** in `tests/seal_journal.rs`, beside D106's: on an absent fine tag,
  → `Abandoned` succeeds when the mirror is `IncompletePrePay`, and another target stays
  `Corrupt`.

**The plants — proof that those tests can fail**

| Plant | Must redden |
|---|---|
| `detect` never returns the restart | G1 (usage 2 — the generic `NothingStaged` text once R7 has removed T3's), G2 (exit 12) |
| the absent-tag clause dropped from R1's predicate | G2 (exit 12) |
| R4's `set_state` arm removed | G2 and G3 (exit 12's text) |
| the abandon moved after `pipeline.seal` | G5 (two exact candidates → `Internal`) |
| the dry-run performs the abandon | G4 (the fingerprint changed) |
| the receipt clause dropped from R1's predicate | G6 (a restart notice, or `Pay` > 0) |

Not ruled, and cheap: a seventh plant dropping R4's mirror condition, witnessed by an R4 unit
case with an `IncompletePostPay` mirror that must stay `Corrupt`.

## 4. What this record does NOT decide

- **The window itself.** `begin` stays two writes. Closing window 1 at the writer is option A's
  format event (§1.7), refused on cost; and `store.rs:67-69` already says a multi-record work is
  never published whole. This record closes the trap, not the window.
- **A pre-staging tag** (option B). Refused with its price (§1.7). It is worth revisiting only
  for a reader that needs the tag, and none exists.
- **A pipeline-driven kill point.** If one is ever wanted, `PostWorkRecord` right after
  `pipeline/seal.rs:296` is the place. It costs the four pins and the `S16` row (§1.8) and
  still reaches only window 2.
- **A destructive confirmation for the discard.** Not added (R2). If the maintainer wants every
  discard confirmed, the costed fallback is option E (message only, §1.7), which still needs R4
  so that `antseal abandon` can exit window 1.
- **A signal handler.** The CLI installs none (D185 §1.3). R1–R3 make a killed staging
  recoverable whatever killed it, `SIGKILL` included; whether a handler should also exist is
  not decided here.
- **D45's other rows.** 25 (overlap), 26 (flag mismatch) and the disjoint-inputs notice are
  unchanged.
- **New rows.** This record mints none. P1's instrument findings (its report's §3; one of them is
  that `S45`'s Notes quote the internal detail while the user sees exit 12) are the
  orchestrator's to record.

## 5. Edit list — per write scope, with the lane named before this record was written

### L-RESUME (round 1) — this record

- `crates/antseal-cli/src/seal_resume.rs`:
  - `staging_never_finished`: R1;
  - `ResumeDecision`: a restart variant (P1: `Restart(Box<ResumeCandidate>)`) and its
    `notice()` arm (R2);
  - `detect`: returns the restart when `match_candidates` gave `Resume(c)` and R1's predicate
    holds; `match_candidates` stays pure;
  - `AbandonPreview::render`: the no-tag arm (`:623`) says that staging was interrupted before
    it finished and nothing was paid, instead of *"the journal records no state for it"*;
  - `interrupted_before_staging` deleted (R7); unit tests for the notice.
- `crates/antseal-cli/src/seal_run.rs` (`run_seal`): the restart arm (around `:380-396` and
  `:451-519`); the abandon immediately before `pipeline.seal` (R3); the fresh dry-run (R5); the
  T3 branch `:457-470` removed (R7).
- `crates/antseal-cli/src/pipeline/vault_journal.rs`: `set_state` (`:220-242`), R4.
- `crates/antseal-cli/src/pipeline/journal.rs`: `SealState::Staged`'s doc (`:164-165`) and the
  `SealJournal::set_state` trait doc only (R6).
- Tests: `tests/seal_command.rs` (G1, rewriting `:1567`; G2–G6) and `tests/seal_journal.rs` (the
  R4 unit row); `tests/exit_codes.rs` — only the T3 row's removal (`:558-567`);
  `tests/snapshots/cli-errors.display.txt` — only the removal of `:95-96`, re-blessed with the
  diff read.
- Not this lane's: `pipeline/error.rs`, `pipeline/resume.rs`, `pipeline/receipt_sink.rs`,
  `error.rs`, `backend.rs`, `commands.rs`, any other snapshot, `docs/**`.
- The close gate runs with `ANTSEAL_GATE_HEAVY=1 ANTSEAL_GATE_E2E=1` (§2, *What no ruling here
  moves*).

### L-ERR3 (round 2, after L-RESUME) — the two shared files

`tests/exit_codes.rs` and `tests/snapshots/cli-errors.display.txt` are shared with D201: L-ERR3
appends one exemplar and one block at their ends after L-RESUME's removals have landed.

### RECORDS-B — dated addenda

- **D45:** §2's new row (R2); §5's dry-run detail narrowed (R5).
- **D106:** R4's one transition from an absent fine tag.
- **D185:** §2 R6's T3 mapping retired (R7); §4's deeper fix discharged.

### Orchestrator — `TODO.md`, `tasks/S.md`, `docs/decisions/README.md`, `docs/instrument-ledger.md`

- `S45`: its tick, against §3. The Do's `Barrier` is refused by R8, so the tick cites R8 in its
  place.
- This record's index row and register row.
- P1's instrument findings (its report's §3).

## 6. As built — wave 39, lane L-RESUME (recorded in place before this record was first committed)

Every verdict below was read from an exit file, per the lane's report, and every red was judged by
its message. Red baselines and plants ran in a shadow copy with a private target; greens ran in the
shared tree under the lock protocol, and again in the shadow on the final bytes.

- **§2 R1 (`S45`).** `staging_never_finished` keeps its name and measures all six clauses
  (`crates/antseal-cli/src/seal_resume.rs:826-839`), the cheap reads first and the plan last. A
  read that fails counts as "not measured": the answer is `false`, the work stays a resume
  candidate, and the resume reports the failure in its own class. The witness is a 9-row clause
  matrix, its row count asserted before the loop:
  `pre_staging_is_measured_and_each_clause_alone_rules_it_out`
  (`crates/antseal-cli/tests/seal_command.rs:2805`). At `HEAD` four rows were red: *"MidBegin +
  Nothing: measured false, expected true / MidStaging + Consent: measured true, expected false /
  MidStaging + AnchorSlot: … / MidStaging + PostPayMirror: …"*.
- **§2 R2.** `ResumeDecision::Restart(Box<ResumeCandidate>)` is new (`seal_resume.rs:109`).
  `detect` returns it when `match_candidates` answered `Resume(exact)` and R1 holds (`:183-197`);
  `match_candidates` stays pure (`the_pure_table_never_restarts_on_its_own`, `:1085`). No D51
  confirmation was added. The notice is `restart_notice(seal_id, dry_run)` (`:151-162`): *"note:
  seal {id} was interrupted before its staging finished and nothing was anchored or paid for it,
  so it has been abandoned and this run starts a fresh seal of the same files (a new seal id and
  freshly drawn nonces; MVP-SPEC line 145)"*.
  - **Deviation: the notice prints at the abandon, not at detection.** `notice()` returns `None`
    for `Restart` (`:133`). Printed with the other D45 notices, it would precede `balances()` and
    `read_all`, either of which can fail, and a run refused there would have claimed a discard
    that never happened.
  - **Deviation: the text is tightened, as R2 permits.** *"is discarded"* → *"has been abandoned"*
    (the vault keeps the records, and `list` shows the work as `abandoned`); *"this run seals the
    files afresh"* → *"starts a fresh seal of the same files"*, true even when the fresh seal stops
    at consent; *"fresh nonces"* → the spec's *"freshly drawn nonces"*.
  - **Deviation: "stderr" means D45's notice channel**, `SealContext::emit`: stdout in plain mode,
    stderr under `--json` (`crates/antseal-cli/src/commands.rs:421`; D51 invariant 2). The lane
    left that convention as it was.
- **§2 R3.** `run_seal`'s `Fresh | Restart` arm runs `read_all`
  (`crates/antseal-cli/src/seal_run.rs:492`, after the balance read at `:405`), then
  `abandon_pre_pay(&store, &journal, stale)?` (`:532`, skipped under `--dry-run`), then the notice
  (`:534`), then `pipeline.seal` (`:536`). G5,
  `a_restart_stopped_at_consent_leaves_one_resumable_work_not_two` (`seal_command.rs:2665`), was
  red at `HEAD` with *"left: Usage / right: ConsentNotObtained"*. P4, the plant that moves the
  abandon after `pipeline.seal`, reddened G5 on its own ordering assert — which runs before the
  re-run `detect` that §3 expected to answer `Internal` — with *"the abandon came before the fresh
  seal's first write — left: IncompletePrePay, right: Abandoned"*.
- **§2 R4.** `set_state` (`crates/antseal-cli/src/pipeline/vault_journal.rs:257-274`) hands an
  absent tag to the new private fn `abandon_untagged` (`:128-135`). It calls `load_meta` first, so
  a missing work still reports `WorkNotFound`; it accepts only → `Abandoned` over an
  `IncompletePrePay` mirror; everything else gets the old `corrupt("work has no journal state
  record")`. The write moved verbatim into `write_state` (`:141-149`), fine tag first. `state()` is
  unchanged except for its comment.
  - **Deviation (implementation shape): `set_state` reads through `recorded_state`, not
    `state()`,** because only `recorded_state` tells an absent tag (`Ok(None)`) from an unreadable
    one (`Corrupt`). `state()` stays hard, as R4 says.
  - The R4 row, `an_untagged_pre_pay_work_may_be_abandoned_and_take_no_other_transition`
    (`crates/antseal-cli/tests/seal_journal.rs:1533`), covers the transition with its idempotence
    and terminality, the five other targets (counted against `SealState::ALL`, `:1595`), the
    `Complete` and `IncompletePostPay` mirrors, a garbled tag and a missing work. Red at `HEAD`:
    *"an untagged pre-pay work may abandon (D197 R4): journal record failed authentication or is
    corrupt: work has no journal state record"*.
  - G3, `abandon_exits_a_seal_killed_inside_begin` (`seal_command.rs:2516`), was red at `HEAD` by
    exit 12 `VaultAuthFailure`. The preview's arm for no tag and no plan now reads *"staging was
    interrupted before it finished; not paid"* (`seal_resume.rs:686-688`).
- **§2 R5.** A `Restart` falls through to the fresh rehearsal: its `resume_plan` is empty
  (`seal_run.rs:383`), the abandon is skipped (`:531`), and the notice is conditional (*"…; this dry
  run leaves it as it is, and a real run abandons it and starts a fresh seal of the same files
  (…)"*). G4, `a_dry_run_over_an_unfinished_staging_rehearses_a_fresh_seal_and_writes_nothing`
  (`seal_command.rs:2580`), was red at `HEAD` on the resume block (*"got ResumePlan([… "staged: …"
  …])"*). P5, the plant that abandons under `--dry-run`, reddened it with *"left: Abandoned, right:
  IncompletePrePay"*.
- **§2 R6.** `SealState::Staged`'s doc (`crates/antseal-cli/src/pipeline/journal.rs:164-166`) is
  P1's text with the record added to its parenthesis, *"(S45, D197 R6)"*. The trait doc
  (`:797-812`) states the one absent-tag transition, and its `# Errors` lists `IllegalTransition`,
  `Corrupt` and `WorkNotFound`.
- **§2 R7.** `interrupted_before_staging` is gone: `command grep -rn` over `crates/` finds no hit,
  and finds `fn staging_never_finished` (the positive control). `run_seal`'s `Resume` arm is now
  `pipeline.resume(..).await?` alone (`seal_run.rs:471`), and the T3 exemplar has left
  `tests/exit_codes.rs`. `cli-errors.display.txt` was re-blessed in the shadow, from `HEAD` plus
  the lane's files, so no other lane's change could leak in: the diff is exactly `95,96d94`, and
  the file went from 98 lines and 49 exemplars to 96 and 48 before L-ERR3 appended D201's block.
  P1, the plant in which `detect` never restarts, reddened G1 with the generic `NothingStaged`
  text, as the corrected §3 says (*"usage error: this work has no journaled seal plan; nothing was
  staged to resume from"*), and G2 by exit 12.
- **§2 R8.** No `Barrier` was added; the step-boundary pin still reads `assert_eq!(count, 8, …)`
  (`crates/antseal-cli/src/pipeline/error.rs:521`).
- **§3, the green tests.** G1 was rewritten in place as
  `a_seal_interrupted_before_its_staging_finished_is_abandoned_and_sealed_afresh`
  (`seal_command.rs:1569`); only D185, a dated record, cites its old name. G2 is
  `a_seal_killed_inside_begin_is_abandoned_and_sealed_afresh` (`:2497`). Their shared helper,
  `assert_the_exact_rerun_seals_afresh` (`:2403`), checks the notice at its producer, `Pay == 1`, a
  new seal id, the fresh work `Complete`, the stale one `Abandoned` fine and coarse, exactly two
  works, and a third `detect` answering `Fresh`. At `HEAD`, G1 was red with D185 R6's usage text
  and G2 by exit 12, as ruled.
  - G6, `an_unplanned_work_with_a_receipt_is_never_restarted_and_never_paid_again` (`:2733`),
    exited 0 at `HEAD` by design: `HEAD`'s predicate already excluded a work with a receipt. Under
    P6, the plant that drops the receipt clause, its `Pay == 0` assert passed, as §3 warned, and
    its exact-text assert reddened: *"left: "usage error: work d8d8… has already been paid for —
    …" / right: "usage error: this work has no journaled seal plan; …""*.
  - **Deviation: G6's "no restart notice" is asserted through the decision** (`detect` returns
    `Resume(stale)`), because no test can read the process's own streams (D146 §1.6).
- **Plants: 13, every one red by message,** in one build, each behind its own `W39_PLANT=<id>`
  switch; that build's control runs were green, 9 of 9, in both rounds. P7 is §3's seventh, red on
  the R4 row with *"Complete: Ok(())"*. Restore: every sha256 equals the tree's, and
  `git grep --untracked -n W39-PLANT` exits 1.
  - **Deviation: more witnesses than ruled** — the 9-row matrix, P7, and six plants P8–P13: one per
    remaining R1 clause (consent, anchor slot, mirror, plan) and two more R4 shapes (any target
    from an absent tag; a garbled tag read as absent).
  - **Deviation: two of P1's predictions did not hold as written.** They were re-derived in round
    2, and §3 already carries the corrections.
- **At the lane's close.** Shared tree: `--lib` 324 passed; `seal_journal` 29, `seal_pipeline` 15,
  `seal_matrix` 15, `seal_resume` 16, `list_command` 24, `seal_command` 35 (2 spawners filtered
  out), `exit_codes` 7 (`json_mode…` filtered out). Shadow, final bytes: `seal_command` 37 and
  `exit_codes` 8, spawned tests included. `clippy -p antseal-cli --all-targets -- -D warnings`
  exited 0; rustfmt, `check-copy-style` and `check-personal-data` passed.
- **Left open.**
  - `e2e_kill_resume` (`S18`, devnet) did not run in the lane; the close gate runs it with the
    heavy tier and the devnet E2E forced (§2, *What no ruling here moves*).
  - **Found, minted as a row: `S48`.** A kill between an abandon's two writes leaves the fine tag
    `Abandoned` over an `IncompletePrePay` mirror: `list` offers the work to resume, `seal` refuses
    it as `NotResumable` (usage 2), and `antseal abandon`'s idempotent early return never rewrites
    the mirror. `write_state`'s comment calling that lag one *"which no safety rule reads"*
    (`vault_journal.rs:139`) is false: D45's candidate scan filters on the mirror. D197's restart
    is the window's third producer, after `S11` and U17/D185. The lane traced it in code and did
    not plant it. `S48` owns it.
  - `L-LOC` owns the lane's doc findings outside its carve-out — `journal.rs`'s module-doc table
    (its `→ Staged` and `→ Abandoned` rows), the `SealPlan` doc's *"rewritten with the manifest"*,
    and `tests/show_command.rs:161`'s `seal_run.rs:507` (now `:506`) — and the six cited lines the
    lane's edits moved.
  - No in-process test witnesses what `run_seal` prints through `SealContext::emit` (D146 §1.6), so
    every D45 notice, this one included, is asserted only at its producer. No register row named
    this when this section was written.
  - `S45` is not ticked here; its tick is the orchestrator's (§5), citing R8 in place of the Do's
    `Barrier`.

## Closing — this record is not consent

It changes what an exact re-run does with a pre-staging work, adds one journal transition and
retires one usage message, inside the wave's own commits. Nothing in it authorises a push, a
workflow dispatch, a deploy or any other outward act; each of those needs the maintainer's
express consent naming the action, the destination and the account.
