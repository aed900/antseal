# D202 — No request of the opportunistic upgrade pass **starts after its time budget**, the header confirmation included: a time-only gate before `confirm_header` drops the merge when the budget is spent, each of the confirmation's esplora requests checks the same deadline before it starts, and `budget.total + one in-flight call` becomes true as written

- **Status: RESOLVED. H7 fared (b): its direction — gate the confirmation and drop the merge,
  never restate the bound — survived, and its premise fell.**
  - **H7 — *check the remaining budget before `confirm_header` and drop the merge when spent
    (the route is re-polled next pass); restating the bound is refused*.**
    - **The direction survives.** The merge is dropped when the budget is spent, and nothing
      durable is lost: the engine persists nothing, and the existing failure arm already drops
      the merge and relies on the re-poll (§1.4).
    - **The premise falls: one gate before `confirm_header` does not make the stated bound
      true.** The confirmation is two **sequential** requests per esplora endpoint, so a poll
      that answers just inside the budget still buys an ungated two-request confirmation: about
      9 s against the documented `budget.total + one in-flight call`, about 6 s (§1.7). With
      that gate alone a restatement would still be owed, and "restating is refused" holds only
      if every request of the pass is start-gated (§2 R2).
    - **Its obvious spelling is a defect.** `budget.exhausted(started, report.polls)` also tests
      the poll count, and the poll has already been counted, so the last permitted poll's
      upgrade would always be dropped; two existing tests would redden (§1.5).
  - **The ceiling is now measured, not derived:** 9.4 s at `07a170c`, through loopback stubs
    with the real opportunistic client and budget (§1.3).
- **Date: 2026-10-19**
- Owner row: **`A141`** (§2 R1–R4).
- Related:
  - **D99** (R8, §8 and §9 state the ≈6 s bound; its 2026-10-17 addendum handed the bound to
    `A141`; takes a dated addendum closing that hand-off);
  - **D189** (§1.2 derived the ≈12 s ceiling; §4 minted `A141` and set its test; takes a dated
    addendum);
  - **D196** (the same hook's `HookContext::production` and its tests, edited by another lane
    this wave);
  - **`A15`** (the engine) and **`U24`** (the hook), `A141`'s `after` terms, both landed;
    **`U60`** (the off switch, whose register row repeats the bound); **`A76`** and **`U59`**
    (open rows on the same code block, §4).

## 0. What was measured against

`HEAD` `07a170c` (= `origin/main`). `git status --porcelain` printed 0 lines at every check of
the planning lane.

Planning lane P4 (wave 39, 2026-10-19) read the code and ran one probe outside the repository: a
small program built offline into a private target directory, which left the repository's
`git status --porcelain` at 0 lines. It drives `upgrade_pending_with` — the engine's seam —
exactly as `crates/antseal-anchor/src/ots/engine/tests.rs` does, with loopback stubs only, the
**real** `HttpPolicy::opportunistic()` client and the **real** `UpgradeBudget::opportunistic()`
(3 s, 4 polls). Its source and outputs are not committed; §1.3 quotes its output. Lane PS (the
availability survey) found that this row shares `crates/antseal-cli/src/upgrade_hook.rs` with
`U101` and sits in the block where `A76` and `U59` live.

Before this record was written, the records lane re-read every locator below at `07a170c`
through `git show 07a170c:<path>`. Every citation held, with one refinement: D189's `A141` bullet
is D189:291-301 (P4 quoted its `Do` part as `:295-301`).

## 1. What was measured

### 1.1 The budget gates, and the call outside them

- **The engine has exactly two gates, both before a poll:** `run`
  (`crates/antseal-anchor/src/ots/engine.rs:386`) and `upgrade_one_anchor` (`:434`), each
  `if budget.exhausted(started, report.polls) {`, where `exhausted` is
  `polls >= self.max_polls || started.elapsed() >= self.total` (`:154-155`). The hook adds a
  per-work gate (`crates/antseal-cli/src/upgrade_hook.rs:447`).
- **The confirmation runs after the poll, ungated.** `report.polls += 1;` (`engine.rs:451`) and
  the poll (`:452`) are followed, inside `if upgrade.is_none() {` (`:525`), by
  `match confirm_header(client, pair, attestation, fetch_date) {` (`:533`), with no budget check
  between them. The `is_none` guard allows at most one confirmation per artifact per pass.
- **The module doc promises otherwise.** *"# The budget bounds what is *started*"*
  (`engine.rs:39`), then *"The achievable bound is therefore `budget.total + one in-flight
  call` — with [`HttpPolicy::opportunistic`] that is `budget.total + 3 s`"* (`:42-45`). Wave 38
  left that sentence false.

### 1.2 What one confirmation costs

- `confirm_header` calls `fetch_agreed_header(client, pair, height)`
  (`crates/antseal-anchor/src/ots/upgrade.rs:546`), which is `fetch_and_agree` over the esplora
  pair (`crates/antseal-anchor/src/esplora.rs:106-114`). The two endpoints run concurrently
  (`std::thread::scope`, `crates/antseal-anchor/src/agree.rs:311-313`).
- Each endpoint's `header_at_height` makes **two sequential** requests: height to hash
  (`block_hash_at_height`, `esplora.rs:139`, whose request is built at `:184-187`), then hash to
  header (`get(client, &target)?`, `:148`).
- An existing test already measures that shape: `the_two_endpoints_are_queried_concurrently`
  (*"Each endpoint answers two requests … so one endpoint costs 2 x STALL"*) asserts
  `elapsed >= 2 * STALL` and `elapsed < 3 * STALL`
  (`crates/antseal-anchor/src/esplora/tests.rs:333-353`).
- The requests inherit the hook's client, `HttpClient::new(HttpPolicy::opportunistic())`
  (`upgrade_hook.rs:228`), which serves the polls and the confirmation alike. That policy is one
  attempt (`HTTP_OPPORTUNISTIC_ATTEMPTS = 1`, `crates/antseal-anchor/src/http.rs:146`) under a
  3 000 ms global timeout (`HTTP_OPPORTUNISTIC_GLOBAL_MILLIS`, `:134`), with per-phase rungs of
  2 900 ms down to 2 400 ms (`:365-370`).
- **The derived ceiling.** A last poll may start just inside the 3 s budget and run up to 3 s; a
  confirmation of up to 2 × 3 s follows: about 3 + 3 + 6 = **12 s** of exit lateness, against the
  documented ≈ 6 s. Nothing network-bound runs after the engine (P4 read `upgrade_hook.rs:494-543`;
  the vault write that follows is local).

### 1.3 Measured: 9.4 s, offline, through loopback stubs

P4's probe, each stub delaying 2.3 s (a stub that stalls before its headers must stay under the
2 500 ms `recv_response` rung, `http.rs:369`). Verbatim, with the notes of S0 and S2 elided:

```
SCENARIO S0-documented-bound-control(two slow pending polls, no upgrade): wall_ms=4677 polls=2 upgraded=0 budget_exhausted=true height=960768 esplora_conns=(0,0) cal_conns=(1,1,0) notes=[…]
SCENARIO S1-head-worst(slow pending, slow upgraded, slow esplora both GETs): wall_ms=9379 polls=2 upgraded=1 budget_exhausted=true height=960768 esplora_conns=(2,2) cal_conns=(1,1,0)
SCENARIO S2-head-confirm-times-out(header GET stalls past its rung): wall_ms=9584 polls=2 upgraded=0 … notes=[…]
SCENARIO S3-fast-control(fast pending, fast upgraded, fast esplora): wall_ms=76 polls=3 upgraded=1 budget_exhausted=false esplora_conns=(2,2)
```

- **S1** is two polls and then two sequential requests per endpoint, the endpoints concurrent
  (`esplora_conns=(2,2)`): 4 × 2.3 s = 9.2 s plus overhead, **9.4 s — 6.4 s past the 3 s
  budget**.
- **S2** shows that a confirmation which fails costs the same lateness and records nothing
  (`upgraded=0`).
- **S0** is the documented bound's own shape (4.7 s); **S3** is the fast control (76 ms).
- The 12 s ceiling needs every call to run to the 3 s global (a trickled body); 9.4 s is the
  floor of that ceiling a stub stalling before its headers can reach.
- **Two records said this could not be measured.** D189 §0 (D189:55-57) and D99's 2026-10-17
  addendum (D99:856-857) say that with Q16's gate armed no offline run can reach the ceiling. Q16
  refuses non-loopback hosts, not loopback stubs, and `A141`'s own Accept asks for exactly such a
  test.

### 1.4 What dropping a merge loses

- **Nothing durable.** *"# This module persists nothing"* (`engine.rs:49`). A transition reaches
  the vault only through `report.upgraded` (`:551-558`). The existing failure arm already drops
  the merge: *"Atomic: the merge is dropped with the header. Nothing half-done is ever handed to
  the vault."* (`:536-537`). `HeaderUnconfirmed`'s doc says *"Re-pollable: the merge is
  recomputed next time"* (`:232-233`), and the pending branch survives every merge, so the next
  pass polls the same calendar again (`:495-497`).
- **Not established:** whether a calendar can garbage-collect an upgrade before that re-poll.
  P4 found no repository source that states calendar retention. A dropped merge adds no new loss
  class — the `HeaderUnconfirmed` arm already relies on the re-poll — only frequency.

### 1.5 Two traps for any gate

1. **The spelling.** `budget.exhausted(started, report.polls)` also tests
   `polls >= self.max_polls` (`engine.rs:155`), and the poll was already counted (`:451`), so the
   last **permitted** poll's upgrade would always be dropped. The hook hands each later work
   `max_polls - pass.polls` (`upgrade_hook.rs:494-497`), and two existing tests drive exactly
   that case: `the_engine_records_artifact_and_header_together`
   (`crates/antseal-anchor/src/ots/engine/tests.rs:308`; `max_polls: 1` at `:351`;
   `assert_eq!(report.upgraded.len(), 1, "notes: {:?}", report.notes);` at `:357`) and
   `a_promotion_round_replays_at_a_real_attested_height` (`:435`; `max_polls: 1` at `:459`).
2. **The note.** `BudgetExhausted` reads *"the upgrade budget was exhausted before every pending
   anchor was polled"* (`engine.rs:242`), which is false for an anchor that was polled and then
   dropped. `UpgradeNote` is `#[non_exhaustive]` (`:175`). Notes reach `status --upgrade`'s
   `--json` `notes` as free text (`crates/antseal-cli/src/status.rs:255`, `:654`); nothing pins a
   note string (P4's grep found each existing note text only in `engine.rs`).

### 1.6 Where the bound is printed

- `engine.rs:39-47` — the stated bound itself.
- `upgrade_hook.rs:55-58`, wave 38's caveat: *"One pass's polling is bounded by
  [`UpgradeBudget::opportunistic`] — 3 s of wall clock and 4 polls — plus at most one in-flight
  call. That is not the whole of the *lateness of exit*: the block-header confirmation that
  follows a successful poll is not under the budget (A141)."*
- D99 R8 (*"≈ 6 s late to exit"*, D99:596), §8 (*"~6 s late"*, D99:750) and §9's `U58` entry
  (*"(~6 s)"*, D99:803). Its 2026-10-17 addendum (D99:845-871) corrected all three and handed the
  bound to `A141`.
- The register: `TODO.md:742` (`U60`, ticked: *"~6 s of exit latency in the worst case"*) and
  `tasks/U.md:864`, `:866`.
- `docs/config.md:107-108` prints no figure — *"a few seconds, longer when a calendar or block
  explorer is slow"* — and is true under every option.

### 1.7 The options

| Option | Worst-case exit lateness | What it costs |
|---|---|---|
| O1 restate the bound only | 3 + 3 + 6 = 12 s (9.4 s measured) | a weaker documented bound; no behaviour change |
| O2 (H7) a time gate before `confirm_header` only | max(3 + 3, 3 + 6) = 9 s | the documented bound is still false, so a restatement is owed anyway; merges answered after the budget are dropped and re-polled |
| O3 start-gate every request: O2's gate plus a deadline check before each esplora request | 3 + 3 = 6 s, the documented bound as written | the confirmation's second request may be refused, giving `HeaderUnconfirmed` (re-pollable); a deadline-taking sibling of the header fetch; one new `EndpointFailure` variant |

A fourth shape — admit the confirmation only when the remaining budget covers its own worst
case, 2 × 3 s — can never pass under a 3 s budget, so it would quietly turn the hook into a
poll-only pass that never records an upgrade.

## 2. RULING

### §2 R1 — A time-only gate immediately before `confirm_header` (P4's O3)

- The check is `started.elapsed() >= budget.total` — **never**
  `budget.exhausted(started, report.polls)`, which would drop the last permitted poll's upgrade
  and redden the two existing `max_polls: 1` tests (§1.5).
- When the budget is spent, the merge is dropped, `report.budget_exhausted` is set to `true`, and
  a **new** `UpgradeNote` variant names the anchor — not `BudgetExhausted`, whose text
  (*"…before every pending anchor was polled"*) would be false for an anchor that was polled.

*Why time only:* the poll budget has already been charged for this anchor; what the gate guards
is wall clock, and the engine's own module doc says the budget bounds what is **started**
(§1.1).

### §2 R2 — The confirmation's own requests are under the same start gate

- A deadline-taking sibling of `fetch_agreed_header` and `confirm_header` carries the deadline
  (`started + budget.total`) into the confirmation. The existing signatures stay for
  `verify --online` (`crates/antseal-cli/src/verify_host.rs:166`), which passes no deadline.
- `header_at_height` checks the deadline before **each** of its two requests.
- A refused second request is a new `EndpointFailure` variant, *"not started: the caller's
  deadline passed"*. The enum is `#[non_exhaustive]` (`agree.rs:69`), and `endpoint()`'s
  exhaustive in-crate match (`:112-117`) gains its arm. The engine maps it to
  `HeaderUnconfirmed`, which is re-pollable. `probe_failure` in the CLI already ends in
  `_ => ProbeFailureClass::Transport` (`verify_host.rs:407`), so the CLI needs no edit; the variant
  is unreachable there, since `verify --online` passes no deadline.

*Why:* a gate before `confirm_header` alone leaves a two-request confirmation of up to 6 s after
a poll that answered just inside the budget (§1.7). Start-gating each request is the only option
under which the documented bound holds without being restated.

### §2 R3 — The result

- `budget.total + one in-flight call` (`engine.rs` ~`:39-47`) is true **as written**: no request
  of the pass starts after the budget, so the pass outlives it by at most one call's timeout
  (the two esplora endpoints' requests run concurrently, §1.2) — 3 + 3 = 6 s under the
  opportunistic profile.
- Nothing durable is lost: the engine persists nothing, and a dropped merge is re-polled on the
  next pass, which the existing `HeaderUnconfirmed` arm already relies on (§1.4).
- Documents:
  - the module doc (`engine.rs` ~`:39-47`) gains one sentence: the confirmation's requests are
    under the same start gate;
  - `upgrade_hook.rs` ~`:54-63` drops its *"(A141)"* caveat, since the bound holds again;
  - D99 takes a dated addendum: R8's, §8's and §9's ≈ 6 s hold as written again, which closes the
    hand-off of its 2026-10-17 addendum;
  - D189 takes a dated addendum: its §4 `A141` bullet is answered.

### §2 R4 — Calendar retention is not decided

Whether a calendar can garbage-collect an upgrade before the next pass re-polls it is **not
established** (§1.4), and this ruling does not change it: the existing `HeaderUnconfirmed` arm
already relies on the re-poll. Recorded in §4.

## 3. Fault plants

The implementing lane owes these (P4 §2, A141 (g)). Green baselines come first; each plant is
judged by its **message**; every restore is followed by a `touch`. The new tests are in-process
engine tests over loopback stubs (`StubReply::SlowBody` and the replay helpers the existing engine
tests use); none spawns the binary. Each asserts the **shape exactly and the wall clock
loosely**, as `A141`'s Accept asks (`tasks/A.md:1678`).

**The green tests — the load-bearing half**, in `crates/antseal-anchor/src/ots/engine/tests.rs`

1. **`a_late_upgrade_starts_no_header_request`.** Budget `{ total: 1 s, max_polls: 4 }`; alice
   answers *pending* after 600 ms and bob answers *upgraded* after another 600 ms, about 1.2 s in,
   past the budget. Shape: `polls == 2`, `upgraded` empty, **both esplora stubs'
   `connections() == 0`**, the new note names bob, and `budget_exhausted` is set. Wall clock:
   at least 1.2 s (the stubs really stalled) and under 1 s + 600 ms + 1 s.
2. **`a_confirmation_starts_no_request_after_the_budget`.** Budget 1 s; alice answers *upgraded*
   after 10 ms; each esplora endpoint's height request stalls 1.2 s. Shape: each esplora stub's
   `connections() == 1` — the header request never started — `upgraded` empty, and
   `HeaderUnconfirmed` for alice.
3. **`a_slow_round_inside_the_budget_still_upgrades`.** The same slow stubs under a 60 s budget:
   `upgraded.len() == 1`, and each esplora stub's `connections() == 2`. This proves that the gate,
   not the stubs, drops the merge in tests 1 and 2.
4. **Unchanged and still green:** in `engine/tests.rs`,
   `the_engine_records_artifact_and_header_together` (`:308`),
   `a_promotion_round_replays_at_a_real_attested_height` (`:435`),
   `an_unconfirmable_header_records_no_transition` (`:625`), `the_poll_budget_is_respected`
   (`:141`) and `the_opportunistic_budget_matches_the_substrate_profile` (`:910`);
   `the_two_endpoints_are_queried_concurrently` (`esplora/tests.rs:333`); and the CLI's
   `crates/antseal-cli/tests/upgrade_hook.rs`.

**The plants — proof that those tests can fail**

| Plant | Must redden |
|---|---|
| P1 the pre-confirmation check deleted | test 1, on the esplora stubs' `connections()`: 2, not 0 |
| P2 the per-request deadline check deleted | test 2: 2, not 1 |
| P3 the check spelled `budget.exhausted(started, report.polls)` | the two existing `max_polls: 1` tests, at `assert_eq!(report.upgraded.len(), 1, "notes: {:?}", …)`, with the new note's text in the message (`engine/tests.rs:357`, and the first such assertion of the `:435` test) |
| P4 (the test's own instrument) the stub delays zeroed | test 1's lower bound, *"the stubs did not actually stall"*, as `esplora/tests.rs:345-348` does |

## 4. What this record does NOT decide

- **Calendar retention** (§2 R4): whether a calendar can garbage-collect an upgrade before the
  re-poll. Not established, and not changed here.
- **The residual of a dropped merge.** A merge dropped for budget is re-polled on the next pass.
  Because an artifact's calendars are polled in a fixed order, it can be dropped on every pass
  while an earlier calendar stays slow (the S1 setup of §1.3 would drop on every pass until alice
  answers faster). The earlier calendar's own upgrade bounds it, and `status --upgrade`, whose
  interactive budget is 120 s (`engine.rs:145-150`), still completes it.
- **The interactive profile.** Under the 120 s budget the new gate is practically unreachable;
  when it does fire, the new note's text appears in `status --upgrade --json`'s free-text `notes`,
  which nothing pins.
- **`A76`** (`merged.added.first()`, `engine.rs:526`) and **`U59`** (the hook re-polls routes
  that cannot change) sit in the block this record edits (`engine.rs:520-545`). Neither is
  decided or pre-empted here.
- **No figure is added to the user documents.** `docs/config.md:107-108` stays figure-free and
  true.
- **No row is minted by this record.**

## 5. Edit list — per write scope, with the lane named before this record was written

### L-ANCHOR2 (round 1)

- `crates/antseal-anchor/src/ots/engine.rs`: in `upgrade_one_anchor` (~`:416-560`) the
  time-only gate immediately before `confirm_header` (~`:533`), the new `UpgradeNote` variant
  (enum ~`:175-244`), the deadline passed into the confirmation, and the module doc's one
  sentence (~`:39-47`); `ots/engine/tests.rs` (§3).
- `crates/antseal-anchor/src/ots/upgrade.rs`: the deadline-taking sibling of `confirm_header`
  (~`:532-563`); `ots/mod.rs` only to re-export a new name.
- `crates/antseal-anchor/src/esplora.rs`: `fetch_agreed_header` (~`:106-114`) keeps its
  signature and delegates to a deadline-taking sibling; `header_at_height` (~`:134-171`) checks
  the deadline before each request; optionally a deadline unit test in `esplora/tests.rs`.
- `crates/antseal-anchor/src/agree.rs`: the new `EndpointFailure` variant (~`:69-107`) and its
  `endpoint()` arm (~`:112-117`).
- `crates/antseal-cli/src/upgrade_hook.rs` — **only** the module doc (~`:54-63`).
- Not touched by this lane: `crates/antseal-anchor/src/http/endpoint.rs` (`L-CFG2`, D195),
  `gate.rs` (`L-ERR3`), any other `antseal-cli` file, and `docs/**`.
- In-process tests run in the shared target under the lock protocol; plants run in a shadow copy.
- Not the storage or payment path, not `commands.rs`, no `U32`-frozen surface, and not a wasm
  input (`antseal-anchor` is native-only): this record forces neither the heavy tier nor the
  devnet E2E.

### L-CFG2 (round 1) — the same file, another hunk

- `crates/antseal-cli/src/upgrade_hook.rs`'s `HookContext::production` doc and the tests
  appended to its `mod tests` belong to D196, not to this record.

### RECORDS-A — dated addenda

- D99: R8's, §8's and §9's ≈ 6 s hold as written again; the 2026-10-17 addendum's hand-off to
  `A141` is closed, and its *"no offline run can reach it"* is answered by §1.3.
- D189: §4's `A141` bullet is answered (written with D196's, as one addendum).

### Orchestrator — `TODO.md`, `tasks/A.md`, `tasks/U.md`, `docs/decisions/README.md`, `docs/instrument-ledger.md`

- `A141` ticked when the lane's greens and plants are in its report; its `tasks/A.md` entry.
- `U60`'s *"~6 s"* (`TODO.md:742`, `tasks/U.md:864`, `:866`) is true again; a pointer at most.
- This record's index row and register row.
- P4's instrument finding: *"no offline run can reach the ceiling"* was false (§1.3).

## 6. As built — wave 39, lane L-ANCHOR2 (recorded in place before this record was first committed)

The verdicts are the lane's, quoted with the exit codes its report gives. Its plants ran in a
shadow copy, and none touched the tree. The lane's seven files still hash as its report lists,
and `ots/mod.rs` is unchanged. The code facts below were re-read in the tree.

- **§2 R1 (`A141`).** The gate is time-only: `if started.elapsed() >= budget.total`
  (`crates/antseal-anchor/src/ots/engine.rs:575-581`), inside `if upgrade.is_none()`, after the
  attestation is read.
  - It sets `report.budget_exhausted` and pushes a new last variant,
    `UpgradeNote::BudgetSpentBeforeHeader { uri }` (`:272`). Its text (`:269-270`) is *"{uri}: the
    calendar returned an upgrade, but the time budget ran out before its block header could be
    requested, so the upgrade was not recorded"*.
  - It uses `continue`, not `break`, so the next calendar's own check still records
    `BudgetExhausted` for any calendar left unpolled.
- **§2 R2.**
  - In `esplora.rs`, `fetch_agreed_header` keeps its signature and delegates with `None`
    (`:113-118`); `verify --online` still calls it (`crates/antseal-cli/src/verify_host.rs:175`).
    The new `pub(crate) fetch_agreed_header_by` (`:131`) carries the deadline.
  - `header_at_height` checks the deadline through `may_start` before the block-hash GET (`:167`)
    and again before the header GET (`:179`). `may_start` (`:298`) reads the clock only, so a
    refused request opens no socket.
  - In `ots/upgrade.rs`, `confirm_header` delegates with `None` (`:539`, `:545`) to the new
    `pub(crate) confirm_header_by` (`:558`). Both siblings are `pub(crate)`, so no public name is
    added.
  - In `agree.rs`, `EndpointFailure::NotStarted { endpoint }` (`:121-122`) reads *"{endpoint}: the
    request was not started, because the caller's deadline had passed"*. It gets its `endpoint()`
    arm (`:135`) and a `not_started` constructor (`:152`).
  - **Deviation: §2 R2's premise is half true** (the lane's deviation 1). `verify --online` calls
    `fetch_agreed_header` but never called `confirm_header`, whose only production caller was the
    engine. Kept as ruled, `confirm_header` is `pub` and re-exported, and only tests call it. The
    fix — take the deadline or demote it, per D190 §2 R2's rule — needs `ots/upgrade/tests.rs` in
    scope. **Minted as `A142`.**
  - **No `HeaderError` variant** (deviation 7). A refused GET reaches the engine as
    `HeaderUnconfirmed { source: NotAgreed }`, as ruled. Its text (*"could not be agreed by two
    endpoints"*) stays true but cannot name the deadline. Only a GET that straddles the deadline
    gets there (probe S4); the common case carries the new note.
- **§2 R3.** P4's probe was re-run on the fixed code, with the real opportunistic client and
  budget, over loopback stubs only (exit 0):

  | scenario | after the fix | P4 at `HEAD` |
  |---|---|---|
  | S0, the bound's control | 4 723 ms, esplora (0,0) | 4 677 ms |
  | S1, the worst case | **4 685 ms**, `upgraded=0`, esplora (0,0), bob's note the new text | 9 379 ms, `upgraded=1`, esplora (2,2) |
  | S2, a confirmation that times out | 4 680 ms, esplora (0,0) | 9 584 ms |
  | S3, the fast control | 58 ms, `upgraded=1`, esplora (2,2) | 76 ms |
  | S4 (new): an upgrade at ~1 s, then a 2.3 s block-hash GET that answers past the 3 s budget | 3 358 ms, esplora (1,1), `HeaderUnconfirmed` (`NotAgreed`, 960768) | **5 776 ms**, `upgraded=1`, esplora (2,2), measured by the lane under plant P0 |

  - Every scenario is within the budget (3 s) plus one in-flight call (3 s), 6 s. S1's lateness
    past the budget fell from 6.4 s to 1.7 s.
  - `engine.rs`'s module doc now says *"between requests"* (`:42`) and gains the start-gate
    paragraph (`:49-54`). `crates/antseal-cli/src/upgrade_hook.rs:56-58` drops the caveat, in
    place.
  - **Deviation: more docs than one sentence** (deviation 6). Each change keeps a clause true that
    the new arm or gate would falsify:
    - in `engine.rs`, the docs of `UpgradeBudget::total` and `exhausted()`;
    - in `agree.rs`, the enum's *"Two arms"* paragraph (wrong since `d4c0d1a`), the module doc's
      *"three ways"* and the `Agreement` parenthetical;
    - `HeaderError::NotAgreed`'s doc.
  - **Deviation: the hook doc keeps an "(A141)" token** (deviation 9). The caveat sentence is
    gone. *"(A141)"* now cites the row that made the bound true: *"…whose requests are under the
    same start gate as the polls (A141)"*.
- **§2 R4.** No code; the gate adds no new class of loss.
- **§3, the greens** (`ots/engine/tests.rs`, appended).
  - **Deviation: the clocks are seconds, and the tests use a patient client** (deviation 5).
    - Test 1: budget 2 s; alice pending after 0.5 s; bob upgraded after 2.5 s.
    - Test 2: budget 1.5 s; each block-hash GET answers after 2.5 s.
    - `patient_client()` (`:1230`) has a 30 s ceiling and one attempt. Under the real 2.5 s rung,
      a timed-out block-hash GET would leave the header GET unsent, and the test would pass
      vacuously. The probe covers the real profile.
  - Test 1 (`:1409`) asserts esplora (0,0), polls 2, calendars (1,1,0), nothing upgraded, and the
    notes exactly: `[NotYetConfirmed(alice), BudgetSpentBeforeHeader(bob), BudgetExhausted]`.
  - Test 2 (`:1467`) asserts esplora (1,1), each single request `/block-height/960767`.
  - Test 3 (`:1524`) runs the same rounds under 60 s, and both record their upgrade.
  - Each stalled test first checks that its stubs really stalled.
  - **Added beyond the ruling** (deviation 4):
    - `the_last_permitted_poll_still_has_its_header_confirmed` (`:1612`), a stall-free pin of
      §2 R1's time-only spelling;
    - `a_deadline_starts_no_request_at_or_after_it` (`esplora/tests.rs:367`, three legs);
    - `a_request_not_started_names_its_endpoint_and_blames_no_endpoint` (`agree.rs:495`).
- **Plants, every one red by message.** Each ran in the shadow and was restored by copy, `touch`
  and a sha256 check.
  - **P0, `HEAD`'s behaviour.** Exactly the three gated rows went red, `61 passed; 3 failed`.
    Test 1 failed on *"a header request started after the budget was spent; … left: (2, 2) /
    right: (0, 0)"*.
  - **P1. Deviation: §3's prediction was falsified** (deviation 2). The check before the first
    GET also refuses a late confirmation, so the connections stay (0,0) and the notes go red
    instead: `HeaderUnconfirmed { … NotAgreed { height: 960768 } }` where
    `BudgetSpentBeforeHeader` was expected.
  - **P2:** the esplora test's second leg and test 2, *"left: (2, 2) / right: (1, 1)"*.
  - **P3. Deviation: three existing rows, not two** (deviation 3). It gave `60 passed; 4 failed`:
    - `the_engine_records_artifact_and_header_together` and
      `a_promotion_round_replays_at_a_real_attested_height` (`:357`, `:465`), each on *"notes:
      [BudgetSpentBeforeHeader { … }, BudgetExhausted] / left: 0 / right: 1"*;
    - `a_promotion_round_at_a_real_height_records_nothing_when_one_endpoint_disagrees` (`:535`);
    - the new direct pin.
  - **P4:** the three stalled tests, on *"the stubs did not actually stall (56.111676ms); the test
    would measure nothing"*.
  - **P5, added** (the block-hash-GET check removed). The leg's outcome stays green — two
    `NotStarted` either way — so its count is the discriminator. It now carries a message:
    *"a block-hash GET started after a deadline that had already passed / left: (1, 1) / right:
    (0, 0)"* (`esplora/tests.rs:433`).
  - **P6, added:** *"the stubs did not actually stall (30.332219ms); the leg would measure
    nothing"*.
- **Found (instrument findings; no row).**
  - **I1:** `the_poll_budget_is_respected`'s `wall < 1_200ms` cannot fail by poll cost.
    `CalendarBehaviour::Slow` stalls only the submit route, so the test's real discriminators are
    `polls == 1` and `connections() == 1`.
  - **I2 and I3:** `crates/antseal-cli/src/pipeline/anchors.rs:424` cites `ots/engine.rs:451-484`,
    the poll match, for a property the `if upgrade.is_none()` block makes. The lane's edits also
    moved the citations of `ots/engine.rs:619-700` and `esplora.rs:83-84` in
    `docs/threat-model.md` and `docs/drills/clean-machine-verify.md`. `L-LOC` owns them; at this
    writing they are unchanged.
  - **I4:** `crates/antseal-core/src/verify/overlay.rs:79-81` still lists three of
    `EndpointFailure`'s four arms. Read as classes, that stays true, and the optional touch was not
    applied.
- **At the lane's close.**
  - In the shadow, on the final files: `antseal-anchor` lib 219 passed, 1 ignored (213 at `HEAD`
    plus the 6 new), green in three runs; `tests/no_real_network.rs` 1 passed.
  - In the shared tree: lib 219 passed; `antseal-cli --lib upgrade_hook` 3 passed. Its first
    attempt had hit `L-CFG2` mid-edit (*"cannot find function `disclosed`"*).
  - `clippy --all-targets -- -D warnings` exited 0 in both venues; `rustfmt --check` exited 0.
- **Rows.** `A141` is still open in `TODO.md` at this writing; the orchestrator ticks it (§5).
  `A142` was minted from deviation 1.

## Closing — this record is not consent

It changes when the opportunistic upgrade pass may start a request, inside the wave's own
commits. Nothing in it authorises a push, a workflow dispatch, a deploy or any other outward
act; each of those needs the maintainer's express consent naming the action, the destination and
the account.
