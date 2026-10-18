# D191 — A storage client antseal **refused to start** is not *"an unreachable network"*: `backend::degrade` carries **one kind-neutral prefix**, true of all five kinds that reach it, with no classifier, no new error variant and no API change

- **Status: RESOLVED. H10's direction — stop the misdescription — survived. Its premises fell
  (b).**
  - **H10 — *word the degrade prefix by error kind ("refused to start" versus "could not be
    reached")*.** What fell:
    - **The kind is not a type at `degrade`.** Every connect-time failure arrives as
      `StorageError::Network { reason }` by recorded design
      (`crates/antseal-net/src/ant_backend.rs:1180-1181`, `:1196-1198`: *"no new
      [`StorageError`] variant exists for it"*). The only discriminators are reason prefixes —
      two `pub const`s and one bare `format!` — so wording by kind would mean parsing messages
      in production.
    - **Five kinds reach the prefix, not two, and three of them are refusals**: the storage
      gate (D173), `S42`'s environment refusal (D178), the peer-locality refusal (D173 §2 R8,
      which `U96` does not name), a client that upstream could not create or start, and the
      60-second connect bound.
    - **The arm H10 would keep does not exist on the pinned stack.** A dead or empty bootstrap
      never fails at connect (D170 §2 R2, measured: a dead loopback set connected `Ok` in
      6.3 s, an empty one in 45 ms), so an unreachable network surfaces per fetch, in the fetch's
      own words, and never reaches `degrade`. The connect bound is the only kind for which
      *"could not be reached"* is even arguable, and the neutral prefix followed by the bound's
      own reason says the same thing truthfully.
    - **`U96`'s Accept control is unsatisfiable.** *"A dead-loopback `reveal` still does"*
      print *"could not be reached"* contradicts the record the row cites. It is struck (§2 R2).
    - **`verify --live` never shows the refusal at all.** It reaches the user as *"transport
      failure"* rows, so `U96`'s *"reach `reveal`, `restore` and `verify --live`"* holds for two
      of the three commands. The third is `R98`'s (§4).
- **Date: 2026-10-17**
- Owner rows: **`U96`** (§2 R1–R3).
- Related:
  - **D170** §2 R2 (the degrade, and the measurement that a dead bootstrap connects `Ok`);
  - **D173** (the storage gate; §2 R8, the peer-locality refusal; §2 R9, no new variant);
  - **D178** (`S42`'s refusal; its §6 recorded this misdescription as *"recorded, not changed"*
    and takes a dated addendum);
  - **D65** (an error's `message` is human copy and may be reworded at any tier);
  - **`S42`** (the predecessor, `[x]`);
  - minted with this wave's rulings and **not decided here**: **`R98`** (§4).

## 0. What was measured against

`HEAD` `23f3093` (local `main`; `origin/main` `cfd5868`), tree clean, 2026-10-17.

Planning lane P3 (wave 38) worked read-only. It built nothing and spawned no binary, so the
per-command output in §1.4 is derived from code and from two recorded measurements, not from a
run. The availability survey (PS) found `U96` available (`after S42`, `[x]`) and not complete
(`backend.rs:754-755` still formats the old prefix).

Before this record was written, the records lane re-read the load-bearing lines through
`git show 23f3093:<path>`, because round-1 lanes were already editing the tree. One locator
moved: the peer-locality refusal is `ant_backend.rs:1230-1234` (its text at `:1232`, inside
`client_config`, `:1227`), not P3's `:1226-1230`.

## 1. What was measured

### 1.1 `degrade` and its one caller

- **The function.** `crates/antseal-cli/src/backend.rs:732-760`. On `Err`, `detail` is the
  reason of a `StorageError::Network` and `to_string()` otherwise (`:743-746`). It emits a
  `tracing::warn!` (`:747-752`): *"the Autonomi network could not be reached; every fetch will
  fail on its own, so verified local copies can still be used (D170 §2 R2)"*. It builds the
  carried reason (`:754-756`): `format!("the Autonomi network could not be reached: {detail}")`.
- **One production caller.** `connect_within` (`:1549`, the call at `:1563`), reached by
  `restore` (`crates/antseal-cli/src/commands.rs:765`), `verify --live` (`commands.rs:1045`)
  and, lazily, `reveal` (`backend.rs:1662-1664`).
- **The trace is hidden by default.** `crates/antseal-cli/src/lib.rs:207-212` installs
  `EnvFilter::from_default_env()`, which shows ERROR only unless `RUST_LOG` is set
  (tracing-subscriber 0.3.23, per P3). The user-visible misdescription is the carried reason
  at `:755` alone.
- **The rustdoc restates it twice**: `:511` (*"**could not be reached**: every call fails on
  its own"*) and `:545` (*"Why the network could not be reached — carried into every
  failure."*). `degrade`'s own rustdoc (`:711-730`) describes the degrade without naming the
  prefix.

### 1.2 What reaches it: five kinds, one type

The type carries no kind. `AntCoreReader::connect` returns `StorageError::Network` *"for the
storage gate's refusal, the upstream-state refusal, a peer set no transport mode can dial, and
when upstream cannot create or start the client node"* (`ant_backend.rs:1034-1036`), and
the two refusal paths say why no variant was added (`:1180-1181`, `:1196-1198`). The reason
text is the only discriminator:

| kind | where | the reason begins | what it is |
| --- | --- | --- | --- |
| K1 | `crates/antseal-net/src/network.rs:857` (`storage_gate::REFUSAL`) | *"the no-real-storage-network gate refused this connection: "* | a refusal (D173) |
| K2 | `network.rs:1060` (`upstream_state::REFUSAL`) | *"refusing to start a storage client: the pinned Autonomi client keeps "* | a refusal (`S42`, D178) |
| K3 | `ant_backend.rs:1232`, a bare `format!` | *"refusing to connect over the {network} bootstrap set: "* | a refusal (D173 §2 R8) |
| K4 | `ant_backend.rs:1769-1770`, `map_ant_error`'s fallback arm | upstream's own `AntError` text | a local start failure |
| K5 | `backend.rs:1560` | *"the connection attempt did not finish within {budget:?}"* | the 60-second bound |

Only K5 is *"could not be reached"* in substance. K1–K3 already read as refusals in their own
words; K5 names its bound; K4 is upstream's sentence.

### 1.3 An unreachable network never reaches the prefix

- `ant_backend.rs:1016-1024`: *"Measured on a live devnet (2026-09-13): a dead loopback
  bootstrap connected `Ok` in 6.3 s and an empty one in 45 ms. So an unreachable network
  surfaces at the first `get_data`, not here"*.
- D170 §2 R2 (`D170:149-156`): *"on the pinned stack a dead or empty bootstrap never fails at
  connect ... so an unreachable network surfaces **per fetch** ... The degrade therefore covers
  real connect errors and a connect timeout"*.
- Since D173 §2 R8 an **empty** set is K3, a refusal. A dead **non-empty** loopback set
  connects `Ok` and fails per fetch with `fetch_chunk`'s own text (*"the network did not
  establish whether … is stored …"*, per P3), never *"could not be reached"*.

### 1.4 What the user sees today (derived from code)

- **`reveal`**: *"network failure: unit {N} could not be fetched from the network (network
  error: the Autonomi network could not be reached: {R}) and no verified local copy exists"*,
  exit 23, class `network-failure`. D178 §6 measured exactly this for K2 through a spawned
  `reveal` (`D178:319-321`).
- **`restore`**: each affected row is `fetch-failed` with that detail, human and `--json`
  (`files[].detail`); a manifest miss is *"network failure: the encrypted manifest could not be
  fetched: network error: the Autonomi network could not be reached: {R}"*.
- **`verify --live`**: `{R}` never renders. `crates/antseal-net/src/live.rs:168` maps every
  `StorageError::Network` to `FetchFailureClass::Transport`, so each row reads *"transport
  failure"*, and the handler prints only `run.render()` (`commands.rs:1051-1053`).

### 1.5 What pins it, and what freezes

- **Only K5's string is pinned.**
  `backend.rs:2257` `a_connection_that_never_finishes_degrades_at_its_bound_in_the_network_class`
  (in-crate, under the `ant-backend` feature, no spawned binary) asserts at `:2292-2297`:
  *"network error: the Autonomi network could not be reached: the connection attempt did not
  finish within 20ms"*.
- **The spawned K2 rows assert nothing about the prefix.**
  `crates/antseal-cli/tests/upstream_state.rs:371` `assert_refused` checks exit 23, the class,
  and `message.contains(upstream_state::REFUSAL) && message.contains(case)` (`:401`). Its
  control (`:475`, assertion at `:499`) requires the unfetchable sentence and no `REFUSAL`.
- **No frozen surface moves.** The text lives in `CliError::NetworkFailure`'s `message` (D65:
  human copy, rewordable at any tier) and in `restore`'s `files[].detail` (tier C). No snapshot
  carries it; `cli-errors.display.txt:58` is the no-backend message, untouched. Exit class 23
  stays.
- **The row's own words.** `U96` Do (`tasks/U.md:1401`): *"word the prefix by the error's kind
  (a refusal names itself; an unreachable network or the connect bound keeps today's words)"*.
  Accept (`:1403-1404`): *"A spawned `reveal` refused by `S42`'s environment check prints no
  *"could not be reached"*, and a dead-loopback `reveal` still does — both asserted by
  message."* and *"A plant restoring the single prefix reddens the refusal row by message."*
- **D178 §6** (`D178:322-324`): *"The wrapper's words *"could not be reached"* misdescribe an
  environment refusal, as they already did for the storage gate's. This is recorded, not
  changed, this wave."*

## 2. RULING

### §2 R1 — One kind-neutral prefix, and no classifier

`backend::degrade` carries a prefix that is true of all five kinds that reach it:
*"no connection to the Autonomi network was made: {detail}"*. The `tracing::warn!` text
changes the same way: *"no connection to the Autonomi network was made; every fetch will fail
on its own, so verified local copies can still be used (D170 §2 R2)"*. There is **no
classifier, no new `StorageError` variant and no API change**: every kind arrives as
`StorageError::Network { reason }` by recorded design, and each kind's own text already says
why (§1.2).

Refused, with their costs:
- **Classifying by the prefix constants inside `degrade`.** It is production message parsing,
  it spans two crates, and K3 stays mislabelled unless `antseal-net` exports a third constant.
- **A typed connect outcome** (a `Refused`/`Failed` split on `AntCoreReader::connect`). It is
  correct by type, but it is an `antseal-net` API change inside the `ant-backend` feature
  build, plus `degrade`'s signature and its unit tests — S–M on a two-core host, to separate
  words that the neutral prefix makes unnecessary.

### §2 R2 — `U96`'s Accept is restated, and its control is struck

The orchestrator restates clause 1: *a spawned `reveal` refused by `S42`'s environment check
prints the neutral prefix and no "could not be reached"; the bound's degrade names the bound
(in-process)*. The dead-loopback control is **struck as unsatisfiable**: D170 §2 R2 measured
that a dead or empty bootstrap connects `Ok` and never reaches `degrade` (§1.3). Clause 2 —
a plant restoring the single prefix reddens the refusal row by message — is unchanged.

### §2 R3 — The documents follow, and D178 §6 takes an addendum

`backend.rs`'s rustdoc at `:511` and `:545` stops saying the network *"could not be reached"*,
and `degrade`'s rustdoc (`:711-730`) states the prefix and why it is kind-neutral. D178 §6's
*"recorded, not changed, this wave"* is answered by a dated addendum on D178, written by the
records lane with this record: the misdescription is changed here.

## 3. Fault plants

The implementing lane owes these. Green baselines come first; each plant is judged by its
message, and every restore is followed by a `touch`.

**Green — the load-bearing half.**
- `upstream_state::s42_a_reveal_with_no_home_at_all_is_refused_never_a_panic` (`:410`) and
  `s42_an_empty_xdg_data_home_is_refused_and_nothing_lands_in_the_cwd` (`:438`), with
  `assert_refused` strengthened: the message carries the neutral prefix and does **not**
  contain *"could not be reached"*.
- The control `s42_cargos_xdg_data_home_keeps_upstreams_file_out_of_a_temporary_home`
  (`:475`), unchanged: still the unfetchable sentence and no `REFUSAL`.
- `backend.rs`'s `a_connection_that_never_finishes_degrades_at_its_bound_in_the_network_class`,
  its pinned string moved to *"network error: no connection to the Autonomi network was made:
  the connection attempt did not finish within 20ms"*.
- A new in-crate unit test over `degrade`, fed K1, K2, K3 and K5 reasons with no network and
  no binary: each carried message starts with the neutral prefix and contains its own reason.
  It is the cheap half that can go red without a feature build.

**Red — each watched red by its message.**
- **P1.** Restore `"the Autonomi network could not be reached: {detail}"`. Expect red in
  `assert_refused` (*"could not be reached"* inside the `S42` message) and in the unit test.
- **P2.** Drop the prefix and carry `detail` alone. Expect red in the bound test: the prefix is
  missing.

**Venue.** The `upstream_state.rs` rows spawn the `ant-backend` binary, so they run under a
**private `CARGO_TARGET_DIR`**: cargo releases its build lock before running tests, and another
lane's feature build re-linking the shared binary has voided a run before (D180 §6). The bound
test is in-crate and also needs the feature build.

## 4. What this record does NOT decide

- **`R98`** (minted with this wave's rulings; after `R91`, with `U96`, before `U32`; **not
  this wave**): `verify --live` reports a refused storage client as *"transport failure"* rows
  and never names the refusal (§1.4). A prefix edit cannot reach it; D190 §4 records the
  measurement.
- **Words that differ by kind.** Refused now (§2 R1). A future reason to separate them would
  be an argued change to this record, not a drive-by.
- **K4's text.** It is upstream's sentence, carried as it arrives; this record rewords only
  antseal's own prefix.
- **A spawned K1 row through `reveal`.** P3 offered one (a non-loopback RFC 5737 bootstrap
  under the armed gate); it is not ruled. K1 is asserted today only through `seal`, which pays
  and does not degrade.
- **`backend.rs:1438`** (*"no payment RPC: the payment endpoint could not be reached"*) is a
  `debug` trace on the payment-RPC path, outside `degrade`, and is untouched.
- Every build and test duration: the planning lane built nothing.

## 5. Edit list — per write scope, with the lane named before this record was written

### L-NET — dispatched alongside round 1 rather than in round 2, on a private `CARGO_TARGET_DIR`

- `crates/antseal-cli/src/backend.rs` — `degrade` (`:747-756`: the trace text and the carried
  reason), the rustdoc at `:511`, `:545` and `:711-730`, the bound test's pinned string
  (`:2292-2297`), and the new in-crate `degrade` unit test.
- `crates/antseal-cli/tests/upstream_state.rs` — `assert_refused` (`:371-404`).

### RECORDS-B — the dated addendum on D178 §6 (§2 R3)

### Orchestrator — `TODO.md`, `tasks/U.md`, `docs/decisions/README.md`

- `U96`: the Accept restated per §2 R2 and the row ticked when the lane's greens and plants
  are in its report.
- `R98`: the id is minted by this wave's rulings; its open register row (`TODO.md`,
  `tasks/R.md`) is the orchestrator's to write, and does not exist yet.
- The index row and the register row.

## 6. As built — wave 38, lane L-NET (recorded in place before this record was first committed)

Every verdict below was read from an exit file. Red-first and plant runs used a snapshot (`git archive`
of `23f3093` plus the lane's two files) with a private target directory. The shared tree's `backend.rs`
changed exactly once, from `8d257897…` to `02e50d30…`, by an atomic replace under the turnstile and
the shared lock.

- **§2 R1.** `degrade`'s carried reason is `format!("no connection to the Autonomi network was made:
  {detail}")`, and its warning is R1's text: *"no connection to the Autonomi network was made; every
  fetch will fail on its own, so verified local copies can still be used (D170 §2 R2)"*. No classifier
  was added. A non-`Network` error is rendered whole after the same words.
- **§2 R3.** `degrade`'s rustdoc gains *"What a degraded fetch says (D191)"*, naming the five kinds
  and why the old words fit none of them. The `UnreachableBackend` doc keeps the name and says the
  type stands for a connection that was not made. The `reason` field and the bound test's pin follow.
- **§3 tests.**
  - The in-crate `every_kind_that_reaches_the_degrade_is_told_no_connection_was_made` runs in both
    builds. Its fixtures come from the real pure producers: K1 the storage gate's verdict, K2 S42's
    verdict, K3 `peer_locality`, and K5 the bound's sentence. Each row asserts **equality** with
    `network error: no connection to the Autonomi network was made: {reason}`, stronger than §3's
    *"starts with … and contains"*, and a non-`Network` row is added.
  - `assert_refused` became `assert_no_connection_was_made`. It also asserts that stderr carries
    the warning exactly once and never *"could not be reached"*.
- **Red first, and the plants, every one red by message.**
  - The old words reddened both S42 rows and the new K1 row (*"U96 — antseal declined to start a
    storage client, and the message says the network could not be reached"*). They also reddened
    the unit and bound tests.
  - P2 (the reason's prefix dropped) and P1b (only the warning's old words) each reddened at their
    own assertions.
  - P3 (the connect bound at 1 ms) made the dead-loopback control reach `degrade` and fail its new
    premise assertion.
- **The struck control.** It was not built. The premise it contradicted was measured instead: on
  the old code the dead-loopback `reveal` printed no *"could not be reached"*, so it never reached
  `degrade`.
- **Deviations.**
  - **§3 says the control is *"unchanged"*.** It gained two assertions that measure §2 R2's premise
    (P3 proves them live).
  - **§4 lists the spawned K1 row as *"not ruled"*.** It was built, as the brief allowed.
  - **Through the binary only four kinds reach the prefix (K1, K2, K4, K5).** K3 is refused earlier
    as a usage error, because each handler's `read_only_network` runs the same `peer_locality` check
    first. It reaches `degrade` only through a library caller that skips that step.
  - **§1.2's *"every kind arrives as `StorageError::Network`"* fails for two K4 paths.**
    `map_ant_error(ErrContext::Connect, _)` classes `AntError::Payment` and `AlreadyStored` as `Quote`.
    The words stay true; the class is minted as `S47`.
  - **§2 R2's *"a dead or empty bootstrap connects `Ok`"* is half stale since D173 §2 R8.** An empty set
    is refused before any connect. The dead half stands, and is now asserted.
- **At the lane's close.**
  - Snapshot, feature build: lib 315 passed, `upstream_state` 5.
  - Shared tree, default build: lib 308 passed.
  - A copy of the live tree, feature build: lib 318, `upstream_state` 5.
  - `clippy -D warnings` exited 0 in both builds.
  - `check-anchor-net` exited 0, and so did its self-test.
- **The orchestrator's acts.** `U96`'s Accept is restated per §2 R2, with the dead-loopback control struck, and the row is ticked. `S47` is minted from §6's second deviation, and `R98` carries two restatements L-NET found.

## Closing — this record is not consent

It changes code, tests and rustdoc in the tree. Nothing in it authorises a push, a dispatch, a
deploy or any other outward act, and its tests open no socket beyond loopback.
