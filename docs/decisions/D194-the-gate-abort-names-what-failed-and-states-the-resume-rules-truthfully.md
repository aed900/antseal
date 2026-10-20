# D194 — The anchor-gate abort **names what failed** and **states the resume rules truthfully**: the per-endpoint failures reach the user, the trust state prints by its frozen name, and the message says that the exact command resumes and that `--force-degraded` cannot be added to it

- **Status: RESOLVED. H12, for `A97`, fell (a) as a sizing claim and (b) on `A97`'s own
  premises; the direction — rewrite the message — survived.**
  - **H12 — *`A97`, `Q116` and `Q89` are XS copy edits that one lane can take*.**
    - **(a), on its premise, as a sizing claim** (the availability survey): only `Q116` is an
      XS copy edit. `A97` reaches two crates, the frozen error snapshot, one test file that
      spawns the binary, and two documents, and it shares `error.rs`,
      `cli-errors.display.txt` and `exit_codes.rs` with `S37`, `U41` and `U42`. So it goes to
      the round-2 error lane, after D185 lands.
    - **(b), for `A97` itself** (P4):
      - **The string `A97` names is not the one users see.** `MinimumAnchor`'s text
        (`crates/antseal-anchor/src/gate.rs:184-189`) reaches no CLI user:
        `crates/antseal-cli/src/pipeline/error.rs:273` maps the gate error to a unit variant,
        and the binary prints only `CliError`'s text (`lib.rs:128`) — `error.rs:678-683`,
        frozen at `cli-errors.display.txt:53-54`.
      - **"A re-run auto-resumes it" is true only for the identical command** (D45 §2), and
        the message's own advice — *"or pass --force-degraded"* — is refused on the very re-run
        it recommends: `--force-degraded` is part of the resume identity (D45 §1), so that
        re-run is exit 26.
      - *"Left `Staged`"* is true as worded.
  - **Found with it: the abort throws the per-endpoint failures away.** That is **`U97`**,
    minted with this wave's rulings and ruled here (§2 R1).
- **Date: 2026-10-17**
- Owner rows: **`A97`** (§2 R2–R5); **`U97`** (§2 R1).
- Related:
  - **D45** §1, §2 and §4 (the resume identity, the flag-mismatch hard error, and re-quote with
    re-consent);
  - **D185** (`U41`'s `antseal abandon`, the way forward this message names);
  - **D65** (an error's `message` is human copy at every tier, so no key is added);
  - **D134** §2 R3 (no exit code or class moves);
  - **`A20`** (its Accept: failures verbatim in the typed abort error — met at the library) and
    **`U22`** (its `Do`: anchor failures never silent — unmet on the abort path until `U97`);
  - **D192** (which TSAs count; the `untrusted-chain` line is its seal-time surface);
  - **D186** (`L-ERR2`'s other ruling this wave, in the same files).

## 0. What was measured against

`HEAD` `23f3093` (local `main`; `origin/main` `cfd5868`), tree clean, 2026-10-17.

Planning lane P4 (wave 38) worked read-only and built nothing; every claim it made comes from
reading code, tests and records. The availability survey (PS) found `A97` available (`after
A20, U22`, both `[x]`) and named its hidden coupling: the words the row names are not the words
the binary prints.

Before this record was written, the records lane re-read the load-bearing lines through
`git show 23f3093:<path>`, because round-1 lanes were already editing the tree. Every figure
below held; two locators are stated more exactly than the planning reports had them:
`a_plain_seal_whose_tsas_all_fail_aborts_before_any_payment` is `fn` at
`crates/antseal-cli/tests/anchor_stage.rs:173` (its attribute is `:172`), and the CLI's
`#[error]` is `crates/antseal-cli/src/error.rs:678-682` with the variant at `:683`.

## 1. What was measured

### 1.1 What `antseal seal` prints at the gate

- **The failures are dropped at one line.** `crates/antseal-cli/src/pipeline/error.rs:273`:
  `SealError::AnchorGate(_) => CliError::AnchorGateAbort,` — a unit variant, so
  `MinimumAnchor { attempted, failures }` is discarded.
- **One print.** `crates/antseal-cli/src/lib.rs:128`: `eprintln!("error: {err}");`.
- **So the user reads only the CLI string**, `crates/antseal-cli/src/error.rs:678-683`,
  frozen at `crates/antseal-cli/tests/snapshots/cli-errors.display.txt:53-54`
  (`[anchor-gate-abort] class=anchor-gate-abort code=22`): *"no RFC 3161 timestamp token could
  be obtained, so the seal aborts before anything is paid or uploaded (the anchor gate); re-run
  when a TSA is reachable, or pass --force-degraded to proceed with a loudly recorded degraded
  anchor set"*. Its exemplar is `crates/antseal-cli/tests/exit_codes.rs:370`.
- **The library string reaches nobody.** `crates/antseal-anchor/src/gate.rs:184-189`:
  *"the minimum-anchor policy was not met: 0 of {attempted} TSA endpoint(s) produced a verified
  token, so nothing was paid for.\n{failures}\nRe-run when an endpoint recovers, or pass
  --force-degraded to seal with a loudly recorded degraded anchor set."* No test asserts it:
  `git grep` at `23f3093` finds its opening words only in `gate.rs` and at the page's `:301`
  (the threat model quotes it across a line break).
- **Two documents quote the library string as what the user sees.**
  `docs/user/timestamp-authorities.md:296-306` (*"When the gate refuses, the message names
  every endpoint that failed, verbatim"*, citing `gate.rs:184-196`) and
  `docs/threat-model.md:1960-1962`.

### 1.2 What the discarded failures would have said

- **Each failure has a class and a text.** The TSA stage's degradation report renders each one
  as `{endpoint} [{class}] {failure} ({ms} ms)`
  (`crates/antseal-anchor/src/tsa.rs:339-345`), over the classes `http`, `not-granted`,
  `unverifiable` and `untrusted-chain` (`:210-217`).
- **The `untrusted-chain` text leaks a Rust Debug name.** `tsa.rs:194`:
  `#[error("{endpoint}: the token verifies but does not chain to a pinned root ({state:?}{})",
  …)]` renders `(InternallyConsistentOnly)`. The frozen spelling of that state is
  `internally-consistent-only` (`crates/antseal-core/src/verify/report.rs:662`, the tier-A
  report's anchor state). Nothing pins the rendered text: `git grep` at `23f3093` finds it only
  at `tsa.rs:194`.
- **The consequence.** A user whose only TSAs answer with tokens that cannot count (SwissSign,
  GlobalSign, Certum) is told *"re-run when a TSA is reachable"*, which cannot work: every
  endpoint answered (D192 §1.2).
- **Whose promise this breaks.** `A20`'s Accept (`tasks/A.md:250`): *"Per-endpoint failures
  appear verbatim in the typed abort error and the degradation report."* — met at the library.
  `U22`'s `Do` (`tasks/U.md:417`): anchor failures *"always downgrade the seal report
  explicitly, never silently"* — not met on the abort path.

### 1.3 What a re-run does

- **The work is left `Staged`.** `crates/antseal-cli/src/pipeline/resume.rs:476-477`: the
  gate's `?` returns before `set_state(seal_id, SealState::Anchored)`. Witnessed by
  `crates/antseal-cli/tests/anchor_gate_prepay.rs:226`
  (`a_gate_abort_leaves_the_work_staged_and_resumable`) and `anchor_stage.rs:173`
  (`WorkState::IncompletePrePay`, `pay_calls() == 0`).
- **The identical command resumes it**, re-quoting and asking for consent again (D45 §2 and
  §4; `crates/antseal-cli/src/seal_resume.rs:44`, *"An exact match is auto-resumed rather than
  duplicated"*). `list` already says so for a staged work
  (`crates/antseal-cli/tests/snapshots/list-report.txt:19-21`: *"nothing was paid; the recorded
  quote is stale by design — resuming re-quotes at current prices and asks for consent again /
  resume with: antseal seal half-done.txt"*).
- **`--force-degraded` is identity.** D45 §1 (`D45:47-49`): *"plus the seal-shaping flag set:
  `--title`, `--split`, `--force-text`, `--no-fine-tree`, `--no-anchor`, `--force-degraded`"*.
  `crates/antseal-cli/src/seal_plan.rs:658` records it in the shaping flags;
  `SealShapingFlags` derives `PartialEq` (`crates/antseal-cli/src/vault/store.rs:174-175`,
  the field at `:189`); `seal_resume.rs:201-204` resumes on equality and otherwise returns
  `CliError::ResumeFlagMismatch`.
- **So the abort's second remedy is exit 26.** `antseal seal X` (exit 22) followed by
  `antseal seal X --force-degraded` prints *"these inputs match an incomplete seal but the
  seal-shaping flags differ (…): re-run with the original flags to resume and finish it. This
  build has no way to discard a staged work, so finishing it — or sealing a copy under a
  different path — are the two ways forward"* (`error.rs:791-796`).
- **The discard surface arrives this wave.** D185 (`U41`) adds a top-level
  `antseal abandon <ID> [--yes]` that calls `seal_resume::abandon_pre_pay`
  (`seal_resume.rs:368`) unchanged.
- **No test drives the whole path.** Its halves exist separately:
  `a_gate_abort_leaves_the_work_staged_and_resumable` (the state) and
  `crates/antseal-cli/tests/seal_resume.rs:113` `a_pre_anchor_kill_resumes_by_re_running_the_gate`
  (a staged work resumes through the gate). Nothing drives abort, then the same command, then a
  resumed seal.
- **The page repeats the imprecision**, in the section that recommends `--force-degraded`:
  `docs/user/timestamp-authorities.md:382-387`, *"the next run with the same inputs
  **auto-resumes** rather than sealing a second time ... The gate's own message does not say so
  today"*.

## 2. RULING

### §2 R1 — The abort carries the failures (`U97`)

`SealError::AnchorGate(e)` carries `MinimumAnchor`'s per-endpoint failures into
`CliError::AnchorGateAbort`, which becomes a struct variant. The message gives **one line per
endpoint, naming its class**. The TSA trust state is printed by its frozen name,
`internally-consistent-only`, never a Rust Debug name (`tsa.rs:194`). An `untrusted-chain`
line says that such a token never counts toward the gate, pointing at the page's §1.

Reasons: the failures are computed and then dropped at one line (§1.1); `U22`'s *"never
silently"* is unmet on exactly this path; and a user whose only TSAs cannot count is today told
to wait for an answer that has already arrived (§1.2).

### §2 R2 — The message states the resume rules truthfully (`A97`)

Every clause must be true by measurement. The abort says:
- nothing was paid or uploaded;
- the work is left staged;
- running **this exact command** again resumes it — it quotes again and asks for consent again
  — once a timestamp authority answers;
- `--force-degraded` cannot be added to that re-run, because the flags are part of the recorded
  command (D45 §1 and §2; it would be exit 26);
- to seal with a loudly recorded degraded anchor set instead, discard the work with
  `antseal abandon <seal-id>` (D185) and run the command again with `--force-degraded`.

`MinimumAnchor`'s library text (`gate.rs:184-189`) carries the same facts in library-neutral
words, so the two strings cannot disagree.

Refused, with their costs:
- **Editing `gate.rs` alone**, the row's literal target: it changes a string no CLI user reads.
- **Amending D45 so `--force-degraded` may be added on a pre-anchor resume** (the one shaping
  flag that changes no staged byte). It would make today's advice true without an abandon
  verb, at the price of a dated amendment to a resolved record, a special case in
  `seal_resume::detect` and tests in both directions. P4 offered it only if `U41` slipped;
  D185 lands `U41` this wave, so it is not minted.

### §2 R3 — `--json` adds no key

The error envelope's `message` carries the lines as text. No key is added: D65 makes `message`
human copy at every tier, and an array of failures would be a new tier-C key to freeze.

### §2 R4 — The snapshot is re-blessed deliberately

`cli-errors.display.txt:53-54` is regenerated on purpose (`exit_codes.rs:8-9`:
*"regenerate deliberately with `ANTSEAL_BLESS=1 cargo test -p antseal-cli`"*), and the
`exit_codes.rs` exemplar (`:370`) is built through the real producer — a hand-written exemplar
witnesses nothing.

### §2 R5 — The documents stop quoting a message the CLI never printed

`docs/user/timestamp-authorities.md` §5 (around `:296-306`) shows what the abort prints. §6
(around `:382-387`) says *"the same command — same files, same flags"*, adds the
`--force-degraded` caveat, and deletes *"does not say so today"*.
`docs/threat-model.md:1960-1962` follows.

## 3. Fault plants

The implementing lane owes these. Green baselines come first; each plant is judged by its
message, and every restore is followed by a `touch`.

**Green — the load-bearing half**, in `crates/antseal-cli/tests/anchor_gate_prepay.rs` (not
`anchor_stage.rs`, which `L-CFG` owns this wave):
- **(i)** An all-TSA-fail seal is exit 22 and its message carries the resume sentence.
- **(iii)** The same paths with `--force-degraded` added are exit 26, and the work is still
  `Staged` afterwards (the refusal changed nothing). **Run (iii) before (ii)**: once (ii)
  completes the work it leaves the candidate set (D45 excludes complete works), and a later
  `--force-degraded` run would be fresh rather than refused.
- **(ii)** The same plan against a verifying TSA resumes: `resumed == true`, the same seal-id,
  and `pay_calls() == 1` across both runs. A fresh seal would also pay once, so success alone
  proves nothing; the resume flag and the seal-id equality are the assertion.
- **`U97`**: an all-fail seal over a stub TSA serving a real unpinned token prints that
  endpoint with `[untrusted-chain]` and `internally-consistent-only`.
- Existing greens that must stay green:
  `a_plain_seal_whose_tsas_all_fail_aborts_before_any_payment`,
  `a_gate_abort_leaves_the_work_staged_and_resumable`,
  `a_pre_anchor_kill_resumes_by_re_running_the_gate`, and `exit_codes.rs`'s snapshot test.

(ii) and (iii) need `run_seal`'s resume detection (`seal_run.rs:349`; `resumed` is
`SealReport`'s field, `:92`). `anchor_gate_prepay.rs` drives `pipeline.seal` today (`:132`),
while `anchor_stage.rs` drives `run_seal` over a `StubServer` (`:182`); the lane brings that
harness into its own file.

**Red — each watched red by its message.**
- Abandon the work on a gate error (set it `Abandoned` before returning) → (ii) goes fresh:
  red.
- `force_degraded: false` in the plan identity (`seal_plan.rs:658`) → (iii) resumes instead of
  refusing: red.
- Restore the unit mapping at `pipeline/error.rs:273` → the `U97` test: red.
- Restore the old message → the needle and the snapshot: red.

Venue: measured by grep at `23f3093`, neither `anchor_gate_prepay.rs` nor `exit_codes.rs`
spawns the binary (the planning survey's collision map starred `exit_codes.rs` as spawning;
the grep did not reproduce that). Any spawned check a lane adds runs under a private
`CARGO_TARGET_DIR`.

## 4. What this record does NOT decide

- **`U97` is not deferred.** It is minted by this wave's rulings and decided here: §2 R1 is
  its `Do`. What it leaves open follows.
- **How the message obtains the seal-id** — carried on the error, or a pointer to
  `antseal list`, which prints it. The lane chooses, under §2 R2's rule that every clause is
  true.
- **A tier-C array of failures in `--json`.** Refused for now (§2 R3); adding one later is
  additive under D65 §6, and would be argued as such.
- **May `--force-degraded` be added on a pre-anchor resume?** Not minted (§2 R2), because
  D185's abandon verb makes the advice true without amending D45.
- **The rendering of `untrusted-chain` in the seal report's Anchors block and in `--json`'s
  `anchors.endpoints[].detail`.** Both read the same `tsa.rs:194` text, so §2 R1's frozen name
  reaches them too. No snapshot or test pins that text (`git grep` at `23f3093` finds it only
  at `tsa.rs:194`; the other hits compare enum values), so no other lane's file moves with it.
  No separate ruling is made here.
- Every build and test duration: the planning lane built nothing.

## 5. Edit list — per write scope, with the lane named before this record was written

### L-ERR2 (round 2, after D185 lands; also carries D186 and `Q116`)

- `crates/antseal-cli/src/pipeline/error.rs` — the mapping at `:273` (§2 R1).
- `crates/antseal-cli/src/error.rs` — `AnchorGateAbort` as a struct variant, and its message
  (§2 R1, R2).
- `crates/antseal-anchor/src/gate.rs` — `MinimumAnchor`'s text (§2 R2).
- `crates/antseal-anchor/src/tsa.rs` — **the rendering at `~:194` only** (§2 R1). Round 1's
  `L-ANCHOR` edits the module rustdoc for D193.
- Tests: `crates/antseal-cli/tests/anchor_gate_prepay.rs` (§3) and `exit_codes.rs` (the
  exemplar, §2 R4).
- Snapshot: `crates/antseal-cli/tests/snapshots/cli-errors.display.txt` (§2 R4).
- `docs/user/timestamp-authorities.md` **§5 and §6 only** (§2 R5); `L-ANCHOR` owns the rest of
  the page in round 1.
- `docs/threat-model.md` **`~:1960-1962` only** (§2 R5).

### Orchestrator — `TODO.md`, `tasks/A.md`, `tasks/U.md`, `docs/decisions/README.md`

- `U97`'s register row written (`TODO.md`, `tasks/U.md`): the id is minted by this wave's
  rulings and has no row at `23f3093`.
- `A97` and `U97` ticked when the lane's greens and plants are in its report.
- The index row and the register row.

## 6. As built — wave 38, lane L-ERR2 (recorded in place before this record was first committed)

Every verdict below was read from an exit file.

- **§2 R1 (`U97`).** `CliError::AnchorGateAbort { failures, seal_id }` carries one entry per failed
  endpoint, in the gate's own `AnchorEndpointFailure` form, with its class.
  - `tsa.rs:194-195` renders the trust state by its frozen name (`internally-consistent-only`).
    It is still two lines, and the file is still 534 lines.
  - An `untrusted-chain` entry adds that such a token never counts toward the gate.
  - **Deviation:** *"one line per endpoint"* became one `; `-separated entry per endpoint inside
    a one-line message. `CliError` text is single-line by an enforced rule
    (`display_output_is_single_line_and_fully_rendered`; D155 §1.9). The library's
    `MinimumAnchor` keeps one line per endpoint.
  - **The lane's choice under §4: the seal id rides on the error.** `SealError::AnchorGate` keeps
    its one-field shape, and its payload became `GateRefusal { seal_id, error }`, so the two
    matchers outside the lane's scope still compile. The message names the real id, ready to
    paste.
- **§2 R2 (`A97`).** The message states the resume rules, reworded where the ruling's words were
  false for this row's own case:
  - *"once a timestamp authority answers"* → *"returns a token that counts"*, because an unpinned
    authority answers every time;
  - the lead clause → *"no RFC 3161 timestamp token that counts toward the anchor gate was
    obtained"*.

  It names `antseal abandon <this seal-id>` for the `--force-degraded` route. `MinimumAnchor`'s
  library text carries the same facts. Its first rewording broke `submit/tests.rs:214`'s
  *"nothing was paid for"* needle, which §1.1's *"No test asserts it"* had missed by checking
  only the opening words; the final wording keeps that needle true.
- **§2 R3.** The `--json` error object's keys are exactly `class`, `exit_code` and `message`,
  asserted.
- **§2 R4.** `cli-errors.display.txt:54` was re-blessed in place: one line, after the unblessed
  run failed by its drift message.
- **§2 R5.** The page's §5 now quotes what `antseal seal` prints, as a template, and adds a
  paragraph on `[untrusted-chain]`. §6 says *"The gate's message says so."* and covers the exit-26
  route through `antseal abandon`. The threat model's `:1960-1965` quotes the CLI. Every citation
  was re-measured against the moved tree: `gate.rs:149-161` replaces the stale `:184-196`.
- **§3, the three-part test.** It lives in a new `tests/anchor_gate_resume.rs`, because (ii) and
  (iii) need `run_seal`. It runs in the order (i) → (iii) → (ii), and asserts every message claim
  against the fact it states:
  - (i) class 22, `pay_calls() == 0`, `Staged`;
  - (iii) class 26, the same seal id, still one `Staged` work, nothing paid;
  - (ii) `report.resumed`, the same id, one payment across all three runs, quoted again, the gate
    re-run, `Complete`.
- **§3, the U97 test.** It could not use a recorded third-party token. `capture_one` verifies the
  nonce and the imprint before the chain check, and the gate draws a fresh nonce with no seam, so
  a replayed SwissSign or GlobalSign response can only be `unverifiable`. The test uses A59's
  live-signing mock against the pinned store instead: a genuinely signed, verifying token that
  chains to no pinned root. The result is `[untrusted-chain]` and `(internally-consistent-only)`,
  never `InternallyConsistentOnly`.
- **Plants, every one red by message.**
  - **Pd-1 (`Abandoned` on a gate error):** caught at (i), not at (ii) as §3 predicted. The test
    checks the *"left staged"* claim against the journal: *"the message says the work is left
    staged; the journal must agree / left: Abandoned / right: Staged"*.
  - **Pd-2 (`force_degraded: false` in `seal_plan.rs`, in a copy of the tree):** at (iii) the
    added flag resumed instead of being refused: *"left: AnchorGateAbort / right:
    ResumeFlagMismatch"*.
  - **Pd-3 (the failures dropped):** *"What failed: ."*.
  - **Pd-4 (`{state:?}` restored):** `(InternallyConsistentOnly)`.
  - **Pd-5 and Pd-5b (the old message):** the three-part test failed, and so did the snapshot.
    Run as one command, cargo's fail-fast hid the snapshot's red behind the first binary's
    failure, so the lane ran it again alone.
  - **Pd-6 (the class misspelt):** the never-counts note vanished.
- **§3's venue sentence was mis-measured.** It said that, at `23f3093`, neither `exit_codes.rs`
  nor `anchor_gate_prepay.rs` spawns the binary. `exit_codes.rs` does, through
  `spawn::antseal()`. That test ran in the shared target under the shared lock, default
  features only.
- **At the lane's close.** `cargo test -p antseal-cli` passed 847, 0 failed.
  `cargo test -p antseal-anchor` passed 213. `clippy -D warnings` exited 0 on both crates.
- **Found, minted as a row.** `U103`: the gate's `Entropy` arm wears class 22 with a remedy that
  cannot apply. That mapping is not new.
- **The orchestrator's acts.** `A97` and `U97` are ticked.

## Closing — this record is not consent

It changes code, tests, a frozen snapshot and documents in the tree. Nothing in it authorises a
push, a dispatch, a deploy or any other outward act; its tests talk only to stubs on loopback.

## Addendum — 2026-10-19 (D201 §2 R1, R3): §6's `U103` entry is discharged — the gate's `Entropy` refusal leaves class 22

§6 recorded, under *"Found, minted as a row"*: *"`U103`: the gate's `Entropy` arm wears class 22 with a remedy that cannot apply. That mapping is not new."* **D201** discharges it. `AnchorGateError::Entropy` leaves `anchor-gate-abort` (22) for `internal` (1), through one `CliError` variant whose message names the machine, not antseal (`U104`). That message offers no timestamp authority, no `--force-degraded` and no `antseal abandon`: neither of the two routes §2 R2 states can apply to it, because no TSA is asked and every TSA nonce is drawn before the gate evaluates. The abort message §2 R1–R2 ruled is unchanged for every arm that stays in 22, and the exit-22 exemplar (`cli-errors.display.txt:53-54`) stays byte-identical. This record is not rewritten.

## Addendum — 2026-10-20 (D203 §2 M1–M2, M7): §1.3's quote of `list`'s note for a staged work loses its first clause

§1.3 quotes `crates/antseal-cli/tests/snapshots/list-report.txt:19-21` — *"nothing was paid; the
recorded quote is stale by design — resuming re-quotes at current prices and asks for consent
again / resume with: antseal seal half-done.txt"* — as `list` already saying that the identical
command resumes a staged work. D203 (`U109`) changes that note's first clause. The vault can
record a payment but cannot show the absence of one — an exit 37 whose capture did not become
durable leaves no record either way — so the `re-quote` note now opens *"no payment is recorded
for it"* (D203 §2 M1, M2), and the golden is regenerated deliberately (D203 §2 M7). The point
§1.3 makes stands: the note still says that resuming re-quotes at current prices and asks for
consent again, and the `resume with:` line does not change. The quotation was true when written
and is not edited.
