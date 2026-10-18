# D185 — `antseal abandon <ID> [--yes]` is a **top-level verb** that reaches the pre-pay abandon engine **unchanged**, confirms as D51's second destructive-confirm with **`--yes` as its channel**, mints **no exit code**, and gives **four** dead ends their way forward

- **Status: RESOLVED. H2's direction survived and its premises fell (b).**
  - **What survives.** U41 needs a separate, id-taking destructive command,
    registered in D51's prompt table as a **destructive-confirm** with `--yes`
    as its machine-mode channel, and a decision record that amends U1's
    canonical surface (the D39 §3 / D41 precedent). All of that holds.
  - **The placement falls.** H2's `vault abandon` rested on *"`vault` is
    already the housekeeping namespace"*. It is the **backup** namespace:
    `cli.rs:204` and `cli-surface.help.txt:15`, `:328` read *"Encrypted vault
    backup: export to / import from a single file"*, and `cli.rs:486` scopes it
    as *"`vault` subcommands (D47: single re-encrypted file, no flags)"*.
  - **The argument falls.** A `<work-id>` cannot accept what the trap errors
    print. Both D45 errors name the work by its 32-hex **seal-id**
    (`seal_resume.rs:206-207`, `:260-261`), and a work killed mid-staging has
    no work-id at all: `list` prints `(no work id yet; seal {32-hex})` for it
    (`listing.rs:736-739`), because the work-id is recorded only at
    `pipeline/seal.rs:358`.
  - **The trap census is four, not one.** The row calls U41 *"the only thing
    standing between a user and the flag-mismatch trap"*. Measured, the verb is
    the exit for the flag-mismatch refusal (26), the overlap refusal (25), the
    D152 blocked work (27; D152:165-168 already said *"U85 is the second trap
    U41 exits"*) and a **new** mid-staging dead end (T3, §1.3), which is
    code-traced and not executed.
  - **The one maintainer question is ruled here.** P1's only question —
    top-level `abandon` or `vault abandon` — is a surface call the project has
    always made by record (D39 §3, D41). It is ruled top-level, and the refused
    alternative is recorded with its price (§2 R1) so the maintainer can
    overturn it cheaply before `U32`.
  - **The ordering is `before U32`.** The `TODO.md` run still reads
    `after U17,U32`; the recorded reading at `tasks/U.md:666` (wave 36) is that
    the true relation is a deadline: *"U32 freezes whatever this adds"*. This
    record lands the verb before that freeze.
- **Date: 2026-10-17**
- Owner row: **`U41`** (§2 R1–R9). Minted with this record, **not** this wave:
  **`S45`** (§4).
- Related:
  - **D45** (§2 the two refusals; residual risk *"The flag-mismatch trap needs
    an exit"*, D45:152-162; takes a dated addendum);
  - **D51** (the prompt-class table and its *"D51 deliberately adds none
    elsewhere"*, D51:146-149; takes a dated addendum);
  - **D152** (§4(3) the blocked-work copy; §5(c), the registrar edit that was
    never executed; takes a dated addendum);
  - **D39** §3 and **D41** (U1 surface amendments by record);
  - **D134** §2 R3(1) (the exit-code table is append-only; untouched here);
  - **D65** (`--json` tiers; the new envelopes are tier C);
  - **D194** (A97's abort text names `antseal abandon <seal-id>` once this
    record lands);
  - **`U17`** (the engine), **`S11`** (resume never re-encrypts), **`U85`**,
    **`U32`** (the freeze this lands before).

## 0. What was measured against

`HEAD` `23f3093` (local `main`; `origin/main` = `cfd5868`). The tree was clean
when planning began.

Planning lane P1 (wave 38, 2026-10-17) worked read-only. It ran no cargo build
or test; every claim was read from code and docs with the line quoted, and the
T3 dead end is traced through code, not executed. Lane PS supplied the
availability reading, the collision map and the exit-code map.

Before this record was written, the records lane re-read every locator below at
`HEAD` through `git show 23f3093:<path>`, because implementing lanes had already
begun editing `crates/antseal-cli/src/error.rs` and
`crates/antseal-cli/tests/exit_codes.rs` in the shared tree. Every citation
held, with two refinements: the test
`the_only_channel_less_prompt_is_the_import_overwrite` is at `machine.rs:508`
(P1 wrote `:507`), and the signal-handler search P1 reports as empty is empty
**for `crates/antseal-cli/`**; over all of `crates/` it finds only
`devnet-launcher`, a development tool.

## 1. What was measured

### 1.1 The engine exists, and only tests call it

- `seal_resume::abandon_pre_pay` is defined at `seal_resume.rs:368`. Its only
  callers are `tests/seal_command.rs:1276`, `:1315`, `:1348` and `:1397`.
  `listing.rs:1441` says it *"has no production caller"*, and the
  `ResumeOverlapNotExact` rustdoc (`error.rs:772-777`) says the surface token
  that would invoke it *"is D45's deliberately-deferred decision (U41)"*.
- Its doc (`seal_resume.rs:324-343`, *"Why this exists, and why nothing calls
  it yet"*) states three rules, checked in order: a finished work is never
  abandoned; a paid work is never abandoned on request, decided by the
  **journaled receipt** rather than the state tag (S16's double-payment
  finding); anything else, staged or anchored with no receipt, is abandonable
  through `SealJournal::set_state`. Rules 1 and 2 return `CliError::Usage`,
  *"no new exit class"* (`:362-367`).
- The engine-level trap → abandon → fresh test exists:
  `the_explicit_abandonment_marks_the_work_and_it_stops_being_a_resume_candidate`
  (`tests/seal_command.rs:1254`). Nothing drives the trap through `run_seal`
  and a command end to end.

### 1.2 The namespace and the identifier

- `vault` is the backup namespace (`cli.rs:204`, `:486`; help `:15`, `:328`).
  Putting `abandon` under it mutates three frozen help lines — the top-level
  `vault` about-line, the `vault` block's about-line and that block's
  `Commands:` list — and widens D47's *"no flags"* scope note.
- A top-level verb mutates one: the top-level `Commands:` list gains a row. It
  joins the verbs that already take a work id at top level (`show`, `status`,
  `restore`, `reveal`).
- Every resume message names the work by seal-id (`seal_resume.rs:109`, `:207`,
  `:261`, `:440`), and so does `AbandonReport::render` (`:301`, `:307`). `list`
  prints the 64-hex work-id once the manifest exists, and
  `(no work id yet; seal {32-hex})` before (`listing.rs:736-739`).
- `pipeline/restore.rs:520` `resolve_work_id` accepts only 64-hex work-ids and
  has no seal-id path. The two lengths disambiguate without any prefix scheme.

### 1.3 The four dead ends the verb exits

| | Trap | Exit | Today's way-forward text |
|---|---|---|---|
| T1 | same paths, different seal-shaping flags (`ResumeFlagMismatch`) | 26 | *"This build has no way to discard a staged work, so finishing it — or sealing a copy under a different path — are the two ways forward"* (`error.rs:791-797`) |
| T1′ | paths overlap an incomplete seal without matching it (`ResumeOverlapNotExact`) | 25 | *"re-run with exactly the original path list to resume it, or with a disjoint path list to start a fresh seal"* (`error.rs:779-785`) |
| T2 | the D152/U85 blocked work, whose own recorded command is refused | 27 | *"This build has no command that discards a staged work."* (`listing.rs:1477-1480`; golden `list-blocked-work.txt:6`, `:13`; asserted at `tests/list_command.rs:1353`) |
| T3 | a seal killed between `begin` and `put_plan` | 2 | *"this work has no journaled seal plan; nothing was staged to resume from"* (`pipeline/error.rs:226`) |

The overlap text's rustdoc (`error.rs:768-778`) records that it *"used to end
'or abandon it first', which was an instruction with no command behind it"*,
and the flag-mismatch text's (`:787-790`) points back to it.

**T3, traced (not executed).** `sink.begin` (`pipeline/seal.rs:279`) writes the
work record with `state: SealState::Staged.work_state()` and the journal tag
`Staged` (`vault_journal.rs:123`, `:137-140`) **before any blob is staged**,
which contradicts `SealState::Staged`'s own doc, *"Every staged blob … and the
plaintext manifest are durable"* (`journal.rs:164-165`). The plan is written
only at `pipeline/seal.rs:351`. A kill in between leaves an incomplete pre-pay
candidate with no plan. Its exact re-run reaches `run_seal`'s Resume arm
(`seal_run.rs:455`), then `resume.rs:153-156`
`.ok_or(SealError::NothingStaged)?`, which `pipeline/error.rs:279-281` maps to
`CliError::Usage` (exit 2). Nothing changes state, so it repeats on every run;
a flag variant meets 26 or 25. The CLI installs no signal handler
(`git grep -n -E 'ctrlc|SIGINT|tokio::signal' 23f3093 -- crates/antseal-cli/`
returns 0 lines), so a Ctrl-C during encryption produces T3.

### 1.4 The prompt substrate and D51

- `PromptClass::DestructiveConfirm` exists (`machine.rs:251-254`), but no
  interactive destructive confirm is implemented: `vault import`'s is
  refuse-always, declared `IMPORT_OVERWRITE` with `channel: None`
  (`machine.rs:269-272`; D51:66 *"none — deliberate"*).
- In machine mode a destructive confirm aborts as `consent-not-obtained`, exit 10
  (`machine.rs:172-173`). The test
  `the_only_channel_less_prompt_is_the_import_overwrite` (`machine.rs:508`)
  stays true if the new prompt declares a channel.
- `--yes` is per command, not global: `SealArgs` (`cli.rs:356`) and
  `RevealArgs` (`cli.rs:418`); `GlobalArgs` (`cli.rs:63`) carries none. D51's
  U1 consequence says D51 *"deliberately adds none elsewhere"* (D51:146-149).
- The prompt machinery exists: `trait ConsentPrompt` (`seal_consent.rs:257`)
  and `ask_on_tty` (`:294`), already reused by `reveal` (`reveal_consent.rs:159`).

### 1.5 What a new command costs in the registries

- `ALL_COMMAND_NAMES` is `[&str; 10]` (`machine.rs:207`) and `MINIMAL_ARGV` is
  `[&[&str]; 10]` (`machine.rs:458`); both become 11.
- `snapshot_enumerates_every_command_node` asserts 12 `════ antseal` headers
  (`tests/cli_surface.rs:95-116`); it becomes 13.
- `tests/machine_mode.rs:2077-2081` refuses a command without a registered
  `--json` fixture: *"{name} lacks a registered fixture — a command cannot ship
  without one"*.
- `listing.rs:1440` says *"`Command` has nine subcommands and none of them is
  one"*; that rustdoc and its *"becomes false the day U41 lands"* (`:1442`)
  move with the verb.

### 1.6 Exit codes

No new code is needed. The engine's refusals are `usage` (2); a declined or
unobtainable destructive confirm is `consent-not-obtained` (10), D51's existing
mapping. D134 §2 R3(1) (D134:308-312: the table is append-only, 44–49
reserved) is untouched.

## 2. RULING

### §2 R1 — The surface is a top-level `antseal abandon <ID> [--yes]`

A new top-level command amends U1's canonical surface by this record, as D39 §3
and D41 (*"Cost: one global flag added to U1's canonical surface"*, D41:76) did.
It mutates one frozen help line (the top-level `Commands:` list) and joins the
per-work verbs that already take an id at top level.

Refused, each with its price:
- **`vault abandon`.** `vault` is the backup namespace (§1.2). It would mutate
  three frozen help lines instead of one and widen D47's *"no flags"* note. It
  remains the fallback if the maintainer will not grow the top-level list; the
  rest of this ruling is identical under it.
- **`seal … --abandon`.** It overloads the paying verb with a destructive one.
  The flag would have to be excluded from D45's identity, `--dry-run --abandon`
  must not abandon, and the declined-consent path would need threading so that
  abandonment never becomes a side effect of a decline (U17). It is clean only
  for T1: abandoning a work named only by overlap (T1′) means re-running that
  work's paths with `--abandon`, which then seals them, and the blocked work
  (T2) is awkward in the same way.
- **`list --abandon`.** A read-only command stays read-only; the row rejects it
  on sight and this record agrees.

### §2 R2 — One positional ID, matched exactly

- The argument is exactly 32 hex digits (the seal-id, which every resume
  message prints) or exactly 64 hex digits (the work-id, which `list` prints
  once the work is staged). Matching is exact; there are no prefixes, and the
  length alone says which kind it is.
- Anything else, or an id that names no incomplete work, is `usage` (2), and
  the message names the two accepted forms.
- Resolution lives in `seal_resume.rs`. `pipeline/restore.rs::resolve_work_id`
  is untouched, because a seal-id path does not belong in restore's resolver.
- Vault access and `--network` handling mirror the existing id-taking verbs
  (`show`, `status`).

*Why:* a work killed mid-staging (T3) has only a seal-id, and the trap errors
print only seal-ids (§1.2), so a work-id-only argument cannot reach the works
that need the verb most.

### §2 R3 — The handler wraps the engine; it does not re-implement it

The handler unlocks the vault, resolves the id, renders what will be lost,
confirms (§2 R4), then calls `seal_resume::abandon_pre_pay` **unchanged**, and
renders `AbandonReport` (human output) or a `--json` result. A complete work and
a paid work are refused by the engine's own rules, **through the surface**
(`usage`, 2), each with a sentence saying why:
- **paid:** money has moved — finish it with the recorded command, which
  `antseal list` prints;
- **complete:** there is nothing to abandon.

*Why:* the engine's rules are the safety case (§1.1), and the paid-work rule is
decided by the journaled receipt, not the tag. A handler that set the state
itself would bypass exactly the check S16 was about. U41 Accept 2 asks for the
refusal *"through the surface, not only through the engine"*.

### §2 R4 — The confirm is D51's second destructive-confirm, with `--yes` as its channel

- **TTY prompt, default No:**
  `Abandon interrupted seal {id}? Nothing was paid for it; the staged work{, and the anchors already obtained for it,} can no longer be used. [y/N] `
  The anchors clause is printed only when the work is `Anchored`.
- **`--yes`** confirms in advance.
- **No TTY, or machine mode, without `--yes`** → `consent-not-obtained` (10):
  `abandoning requires confirmation: machine mode never prompts — pass --yes to confirm in advance; nothing was changed`.
- **Declined** → 10, nothing changed.
- Declared in `machine.rs`'s `spec()` with channel `--yes`, so
  `the_only_channel_less_prompt_is_the_import_overwrite` stays true.

*Why:* U41's Do already rules out `vault import`'s channel-less refuse-always
for this verb — *"abandoning is how a script gets unstuck"*. `--yes` is the
consent channel the surface already teaches, and D51 maps an unobtainable
destructive confirm to 10. The anchors clause exists because abandoning an
anchored, unpaid work gives up the timestamps it already holds: that is the
destructive part of the act.

### §2 R5 — No new exit code

Refusals are `usage` (2) and an unobtained confirm is `consent-not-obtained`
(10). D134 §2 R3(1) is untouched.

### §2 R6 — Four dead ends get their way-forward sentence

1. **T1, `ResumeFlagMismatch` (26)**, and **T1′, `ResumeOverlapNotExact`
   (25)** (`error.rs:768-797`): restore the *"or abandon it"* exit, naming
   `antseal abandon <seal-id>`, for pre-pay works only. Their rustdoc stops
   saying the clause was removed.
2. **T2, D152's blocked-work copy** (`listing.rs:1477-1480`; golden
   `list-blocked-work.txt:6`, `:13`): the pre-pay branch names
   `antseal abandon <id>`; the post-pay branch keeps its payment sentence and
   adds that `antseal abandon` refuses a paid work.
3. **T3:** `run_seal`'s Resume arm (`seal_run.rs` ~`:452-457`, where the
   candidate's seal-id is in scope) maps `SealError::NothingStaged` to a
   `usage` (2) message:
   ``seal {seal-id} was interrupted before staging finished: nothing was staged, anchored or paid, so there is nothing to resume — discard it with `antseal abandon {seal-id}` and re-run this command``.

Lanes may refine the wording; every clause must stay true by measurement.

*Why:* each of the four texts today names only exits that do not discard the
work, because no command could. With the verb, a pre-pay work has a one-command
exit, and T3 has an exit at all. The T3 mapping changes no state machine; the
deeper fix is `S45`'s (§4).

### §2 R7 — `--json` fixtures are registered

`[abandon] result` and `[abandon] error` are registered in
`tests/snapshots/json-envelopes.txt`; a command cannot ship without one
(§1.5). Both are tier C (D65; stable-additive under D134 §2 R3(2)).

### §2 R8 — The help snapshot is re-blessed deliberately

`cli-surface.help.txt` gains one top-level `Commands:` line and the new
`antseal abandon` block (U41 Accept 3). The as-built section (§6) records the
diff.

### §2 R9 — Records

- Dated addenda, written with this record: **D45** (the residual risk is
  discharged by this record), **D51** (the prompt table gains a second
  destructive-confirm row, channel `--yes`), **D152 §4(3)** (the blocked
  copy's way forward).
- The orchestrator executes D152 §5(c)'s never-executed registrar edit onto
  `U41`'s row in the act that ticks it.

## 3. Fault plants

The implementing lane owes these. Green baselines come first; each plant is
judged by its **message**, not by a red exit; every restore is followed by a
`touch`. The spawned-binary tests (`cli_surface.rs`, `machine_mode.rs`,
`exit_codes.rs`) run in a private `CARGO_TARGET_DIR`.

**The green tests — the load-bearing half**

1. **End to end (Accept 1)**, in `tests/seal_command.rs`, library level —
   `run_seal` plus the new handler over `MockBackend` and an `IsolatedVault`,
   the file's house pattern. Drive `run_seal` to T1; assert the error's
   Display contains `antseal abandon <seal-hex>`; run the handler with `--yes`;
   re-run the original invocation and assert `ResumeDecision::Fresh`, then
   `Sealed`.
2. **T3.** Call `journal.begin` directly, then `run_seal` with the same plan;
   assert the new message. Red baseline first: today it is the `NothingStaged`
   usage text.
3. **A paid work is refused through the handler (Accept 2):** `usage` (2), and
   the work's state is unchanged.
4. **Machine mode without `--yes`** → 10, and nothing written.
5. **Both id forms resolve** — a seal-id and a work-id — and a 40-hex string is
   `usage` (2).

Plus, moved by the new command: `machine_mode.rs`'s registry and
abort-not-hang tables, `cli_surface.rs` (13 headers),
`display_output_matches_committed_snapshot` in `exit_codes.rs`, and
`list_command.rs:1353`.

**The plants — proof that those tests can fail**

| Plant | Must redden |
|---|---|
| The handler sets `Abandoned` itself instead of calling `abandon_pre_pay` | test 3 |
| The `--yes` gating is dropped | test 4 |
| The old exit-26 text is restored | test 1 |
| The T3 mapping is removed | test 2 |

## 4. What this record does NOT decide

- **`S45` (minted with this record; not this wave): a seal killed mid-staging
  is a permanent dead end.** §2 R6 gives T3 an exit; it does not make
  `Staged` mean what its doc says. The deeper fix is one of: auto-abandon an
  exact-match candidate that has no plan, no anchors and no receipt, and
  proceed fresh with a notice (a D45 §2 amendment — nothing was quoted,
  consented or paid); or add a pre-staging tag so `begin` no longer writes
  `Staged` (an S10 state-machine change). Its test calls `journal.begin`
  directly and then `run_seal`, with a barrier between `begin` and `put_plan`
  so the kill point is injectable (`pipeline/error.rs:34-75` has none today).
  `S45` is `after U41`.
- **`vault import`'s refuse-always confirm.** Unchanged; it stays D51's
  channel-less row.
- **Whether `match_candidates` renders the whole copy-pasteable command into
  the D45 errors' `detail`.** P1 suggested it; it is within the lane's wording
  latitude under §2 R6.
- **Prefix ids, several ids per call, or a `--all`.** §2 R2 rules exact single
  ids; any widening is additive and needs its own record.
- **A user page for the trap → abandon flow.** No `docs/user` page enumerates
  the command set; not ruled.
- **A97's abort text.** D194 names `antseal abandon <seal-id>` in it, after
  this record lands; that sentence is D194's.

## 5. Edit list — per write scope, with the lane named before this record was written

### L-ERR1 (round 1) — `U42` first (D187 §2 R3), then this record

- `crates/antseal-cli/src/cli.rs`: the `Command::Abandon` variant and its
  about line.
- `crates/antseal-cli/src/run.rs` (dispatch) and `commands.rs` (the handler).
- `crates/antseal-cli/src/seal_resume.rs`: the id resolver, the `--json`
  rendering of `AbandonReport`, the `detail` strings at `:204-219` and
  `:258-268` if the wording moves, and the doc at `:324-343`.
- `crates/antseal-cli/src/error.rs:768-797`: the two D45 texts and their
  rustdoc.
- `crates/antseal-cli/src/listing.rs`: the doc at `:1440-1442` and the copy at
  `:1477-1480`.
- `crates/antseal-cli/src/machine.rs`, **code only**: `ALL_COMMAND_NAMES`,
  `MINIMAL_ARGV`, `spec()`, `command_name`, the new confirm declaration, and
  the module's `#[cfg(test)]` tests. Not the `//!` module-doc lines
  (~`:95-160`), which L-VOCAB edits this wave.
- `crates/antseal-cli/src/seal_run.rs`, **only** `run_seal`'s Resume arm
  (~`:440-460`, the T3 mapping). Not `AnchorStageConfig::from_config`, which
  L-CFG edits.
- Tests: `crates/antseal-cli/tests/{exit_codes.rs, seal_command.rs,
  cli_surface.rs, machine_mode.rs, list_command.rs}`, and any new test file
  for `abandon`.
- Snapshots: `crates/antseal-cli/tests/snapshots/{cli-errors.display.txt,
  cli-surface.help.txt, json-envelopes.txt, list-blocked-work.txt}`.
- Not touched by this lane: `pipeline/**`, `config.rs`, `verify_host.rs`,
  `backend.rs`, `status.rs`, `upgrade_hook.rs`, any `antseal-core`,
  `antseal-net` or `antseal-anchor` file, `docs/**`.

### L-ERR2 (round 2)

D194's A97 abort text names `antseal abandon <seal-id>`; it is written after
this record's verb lands, in `error.rs` after L-ERR1 has finished there.

### RECORDS-A — dated addenda

D45 (residual risk discharged), D51 (a second destructive-confirm row, channel
`--yes`), D152 §4(3) (the blocked copy's way forward).

### Orchestrator — `TODO.md`, `tasks/U.md`, `tasks/S.md`, `docs/decisions/README.md`

- `U41`: the tick, with D152 §5(c)'s registrar edit executed on its row.
- `S45`: the row and its `tasks/S.md` entry, per §4.
- This record's index row and register row.
- The close gate: `commands.rs` is a heavy-tier trigger
  (`scripts/gate-features.sh:112-121`), so the gate runs with
  `ANTSEAL_GATE_HEAVY=1 ANTSEAL_GATE_E2E=1`.

## 6. As built — wave 38, lane L-ERR1 (recorded in place before this record was first committed)

Every verdict below was read from an exit file. The four §3 plants ran in the shared tree under the
exclusive lock. P1 waited 51 minutes for it behind a long shared hold (`docs/instrument-ledger.md`),
and P2–P4 ran in one exclusive section.

- **§2 R1–R3, the surface.** `Command::Abandon { id, yes }` is the last variant, so the help and
  fixture diffs are pure appends.
  - The handler `commands::abandon` opens the layout, takes the U5 vault lock before the
    passphrase, and unlocks through `unlock_for_command`, which arms the upgrade hook as `show`
    does. It then calls `seal_resume::run_abandon`.
  - `abandon_pre_pay`'s signature and body are byte-identical to `23f3093`; only its doc changed.
  - `resolve_abandon_id` takes 32 hex digits (a seal id, which must be listed) or 64 (a work id,
    through the existing `resolve_work_id`), in either case. Anything else is `usage`, naming
    both forms.
- **§2 R4.** `ABANDON_CONFIRM` is a `DestructiveConfirm` with channel `--yes`. The preview prints
  before the question, and under `--yes` and machine mode too. The question is R4's text; its
  anchors clause appears only when anchor slots are recorded.
- **§2 R5.** No new exit code: a declined or unconfirmed abandon is
  `CliError::AbandonNotConfirmed`, class `consent-not-obtained` (10).
- **§2 R6.** The four way-forward sentences landed: in 25, in 26, in the D152 blocked-work copy
  (both branches), and in T3's new usage message.
- **§2 R7, R8.** `json-envelopes.txt` registers an `[abandon] error` document (the 10 refusal) and
  an `[abandon] result` document. The help snapshot gained one `Commands:` line and the new block.
  - `abandon` joined `ALL_COMMAND_NAMES` and `MINIMAL_ARGV` (10 → 11) in a second act, together
    with `tests/upgrade_hook.rs`'s arming table and `tests/secret_hygiene.rs`'s `COMMANDS`. Both
    files enumerate the axis with fixed-size tables and sat outside the lane's scope until the
    orchestrator extended it. `json-envelopes.txt` did not move.
  - The arming table spawns `abandon` and finds it armed. `verify_command.rs`'s closed set of
    prompting handlers went from 8 to 9; the scan caught the new handler before it was listed.
- **§3, the five green tests and more.** In `seal_command.rs`:
  - test 1: `the_flag_mismatch_trap_names_abandon_and_the_refused_invocation_then_seals`;
  - test 2: `a_seal_interrupted_before_its_staging_finished_names_abandon_and_then_seals`,
    watched red first;
  - test 3: `a_paid_work_is_refused_through_the_abandon_surface_and_nothing_changes`;
  - test 4: `abandon_without_yes_in_machine_mode_is_consent_not_obtained_and_writes_nothing`;
  - test 5: `both_id_forms_resolve_and_anything_else_is_usage_naming_both`;
  - and `the_anchors_clause_follows_the_recorded_anchors_not_the_tag`.

  Elsewhere: a spawned `machine_mode.rs` test, `cli_surface.rs`, `list_command.rs` and an
  in-crate `machine.rs` test.
- **§3 plants, every one red by message.**
  - P1 (the handler sets `Abandoned` itself): *"a paid work is never abandoned on request"*.
  - P2 (the machine-mode gating dropped): *"machine mode never prompts"*.
  - P3 (the old 26 text): *"the trap must name `antseal abandon …`"*.
  - P4 (the T3 mapping removed): *"missing `seal … was interrupted before its staging finished`"*.
  - The second act's plants: the arming bool flipped gave *"`abandon` took the wrong arm of D42's
    rule"*, and the 10-entry `COMMANDS` gave *"Never scanned: ["abandon"]"*.
- **Deviations.**
  - T3's sentence drops *"nothing was staged"*. `pipeline/seal.rs` journals unit blobs before
    the plan, and test 2 holds one, so the old text was false for the reachable shape.
  - The T3 mapping is guarded, not blanket. `NothingStaged` has three producers, one after
    payment, so the arm maps only when no plan, a `Staged` tag and no receipt are measured.
  - The anchors clause is keyed on recorded anchor slots, not the `Anchored` tag:
    `consent_anchor_pay` writes `Anchored` even when `--no-anchor` skipped the gate.
  - U17's report text, now user-facing through the verb, lost two false phrases: *"nothing is
    lost but the local encryption work"* and *"until it is compacted"* (no compaction exists).
  - The 25 and 26 abandon clauses are conditional (*"if nothing has been paid for it"*), and 26
    keeps *"seal a copy of the files under a different path"*: the one exit for a paid, blocked
    work.
  - `abandon` takes the U5 lock, because it writes; `show` and `status` are readers.
  - A complete, abandoned or paid work gets no preview and no question; the engine answers
    directly.
  - `ResumeOverlapNotExact` and `ResumeFlagMismatch` gained a `seal_id` field (a Rust API
    change; the JSON is unchanged).
  - The 25 and 26 exemplars are built through the real producer, plus one for T3.
  - **§3 said the spawned tests run in a private `CARGO_TARGET_DIR`; the lane's brief said the
    shared target under the shared lock, and the brief was followed.**
- **At the lane's close.**
  - `cargo test -p antseal-cli`: `seal_command` 31, `exit_codes` 8, `cli_surface` 24,
    `machine_mode` 16, `list_command` 24, `verify_command` 27, `upgrade_hook` 12,
    `secret_hygiene` 11, lib 307, all passed.
  - `clippy -D warnings` exited 0, re-run after a `touch` so that it re-checked.
  - `cargo check -p antseal-cli --features ant-backend --all-targets` exited 0 with 0 warnings,
    in a copy of the tree with a private target directory.
- **Found while building, minted as rows.**
  - `U102`: the global `--network` help names the commands that read no network, and not
    `abandon`.
  - A kill inside `begin` itself, between the meta record and the `Staged` tag, is a dead end
    `abandon` cannot exit; recorded on `S45`, whose fix closes both windows.
- **The orchestrator's acts.** D152 §5(c)'s registrar edit is executed onto `U41`'s row in the act that ticks it, as D152's dated addendum required. `U41` is ticked, and `U102` is minted from the lane's findings.

## Closing — this record is not consent

It adds a command, a prompt and four sentences inside the wave's own commits.
Nothing in it authorises a push, a workflow dispatch, a deploy or any other
outward act; each of those needs the maintainer's express consent naming the
action, the destination and the account.
