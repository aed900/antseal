# D189 — The opportunistic upgrade pass gets an off switch, `[anchors] opportunistic_upgrades = true|false` (default on), and the config subset grows **once**: bare lowercase booleans join it, typed per key, and an unknown key's value is **no longer parsed**

- **Status: RESOLVED. H6's direction survived and its premises fell (b).** H6
  read: a `[upgrade] hook = false`-style config key, no flag.
  - **What survives.** A config key, not a flag, turns the pass off. U1's
    canonical surface is frozen; a flag would be a U1 amendment and a
    help-snapshot re-bless, and nothing here needs one.
  - **Four premises fell.**
    1. **`= false` is outside the config grammar.** P2's probe measured exit 17
       for H6's spelling **and** for the row's own (§1.4): the subset has no
       booleans, so the key is unbuildable as written until the subset grows.
    2. **"~6 s" understates the ceiling.** The header confirmation that follows
       an upgraded poll is not budget-gated, so the derived ceiling is
       **≈12 s** (§1.2). Derived from code, not measured.
    3. **D41 does not ground "a config key, not an env var".** D41 rejects an
       environment-variable **passphrase** because `/proc/PID/environ` keeps a
       secret for the process lifetime; it says nothing about non-secret
       preferences. The key wins on other grounds: validation at load,
       discoverability, and travelling with `vault export` (§2 R5).
    4. **H6's `[upgrade] hook` spelling loses** to the row's own
       `[anchors] opportunistic_upgrades`. *Hook* is internal vocabulary; the
       user documents say *"an opportunistic pass"* (`README.md:84-85`).
  - **The grammar is ruled once, for every key.** A key outside the subset is
    exit 17 **even when the key is unknown**, because the value is parsed
    before the key is routed (§1.5). That makes `docs/config.md:18-19`'s promise
    — a config written by a newer antseal still loads — true only for string
    and array values. The first release is the first binary that cannot be
    patched, so the subset's growth is ruled before it.
- **Date: 2026-10-17**
- Owner row: **`U60`** (§2 R2, R4, R5). The grammar (§2 R1, R3) is no row's;
  it is ruled here because `U60` cannot be built without it. Minted this wave,
  **not** taken this wave: **`A141`** (§4).
- Related:
  - **D99** (R8, §8 and §9: the hook's placement, its *"≈ 6 s"* and its
    *"U58"*; takes a dated addendum);
  - **D41** (the env-var passphrase refusal, mis-cited by U60's Do);
  - **D173** §2 R5 (a peer environment variable refused as an injection
    vector — a different question);
  - **D180** (`Q31`, the first release, governs a config key, D180:49);
  - **D42** (the hook arms iff the command unlocked a vault), **D47** (`vault
    export` carries `config.toml`);
  - **D193** (A137's interval promise is withdrawn, so no integer is needed);
  - **`U24`** (the hook), **`U59`** (it re-polls routes that cannot change),
    **`U4`**, **`Q16`**, **`Q31`**.

## 0. What was measured against

`HEAD` `23f3093` (local `main`; `origin/main` = `cfd5868`). The tree was clean,
and no file under the repository changed mtime during the planning round.

Planning lane P2 (wave 38, 2026-10-17) worked read-only. Its one execution ran
a copy of the debug binary built after `config.rs`'s last commit
(`antseal 0.0.0`) against nine hand-written `config.toml` cases, each under a
fresh `HOME` and `ANTSEAL_DIR` with `ANTSEAL_NO_REAL_ANCHOR_NETWORK=1`, reading
the exit code from `$?` into a file. The ≈12 s ceiling is **derived from code,
not measured**: with Q16's gate armed a poll is refused before DNS, so no
offline run can reach it (`U60`'s Notes say the same, `tasks/U.md:861`).

Before this record was written, the records lane re-read every locator below at
`HEAD` through `git show 23f3093:<path>`, because L-CFG was already editing these
files in the shared tree. Every citation held, with two locator refinements in
`tests/upgrade_hook.rs`:
`every_subcommand_either_arms_the_hook_or_is_a_documented_non_armer` is at
`:761` and `a_pass_with_nothing_dialable_costs_no_budget` at `:1050` (P2 wrote
`:760` and `:1049`).

## 1. What was measured

### 1.1 What the pass is, and where it runs

`upgrade_hook::run_after_output(&vault_slot, &config, network)` has one call
site, `lib.rs:198`, after the command's output is printed (D99 R1). It already
receives the loaded `Config`, so a key needs no second load. It is armed iff
the command unlocked a vault (D42): `slot.take()` either traces `HOOK_NOT_ARMED`
and returns, or traces `HOOK_ARMED` (`upgrade_hook.rs:306-310`) and then builds
the production context — client, lock and polls — at `:312`.

### 1.2 What it costs: the stated bound omits a step

- **The stated bound.** `budget.total + one in-flight call`
  (`ots/engine.rs:39-47`), with `UpgradeBudget::opportunistic()` = 3 s
  (`HTTP_OPPORTUNISTIC_GLOBAL_MILLIS = 3_000`, `http.rs:134`) and 4 polls
  (`engine.rs:135-140`). Repeated as *"about 6 s"* in `upgrade_hook.rs:55-57`,
  as *"≈ 6 s"* in D99 R8 (D99:596), as *"~6 s"* in D99 §8 (D99:750) and in
  `U60`'s register row (`TODO.md:733`).
- **The omitted step.** After a poll returns an upgrade, `confirm_header`
  runs with no budget check (`engine.rs:533`, inside `:525-545`). It agrees a
  block header over the esplora pair: the two endpoints run concurrently
  (`agree.rs:311-321`), and each makes **two sequential** requests — height to
  hash (`esplora.rs:139`), then hash to header (`:148`) — each bounded by the
  3 s opportunistic timeout.
- **The derived ceiling.** A last poll may start just before the 3 s budget
  ends and run 3 s; a 6 s confirmation then follows: **≈ 3 + 3 + 6 = 12 s** of
  exit lateness. Derived, not measured (§0).
- **It is not transient until `U59`.** Already-merged routes are re-polled on
  every armed invocation; `U59` (`TODO.md:732`) owns that.
- **The one measurement on record** is `U24`'s: median exit latency 1378 ms
  with the hook against 1377 ms without, nine runs each, on the A42-refused
  path — the cost of deciding not to poll, not of polling
  (`tasks/U.md:861`).

### 1.3 No user-facing off switch exists

There is no key and no flag. Two levers stop the pass only as side effects:
- `ANTSEAL_NO_REAL_ANCHOR_NETWORK` (`antseal-anchor/src/http/offline.rs:103`),
  a test and CI gate documented in `CONTRIBUTING.md:259`, which equally
  refuses `seal`'s TSA stage and `verify --online`;
- a one-entry `[verify] bitcoin_endpoints`, which makes the hook skip
  (`upgrade_hook.rs:312-319`) and makes `status --upgrade` and
  `verify --online` fail with `usage` (`status.rs:801-808`,
  `verify_host.rs:309-318`).

### 1.4 `= false` is outside the subset

- The subset's value type is `enum Value { Str(String), Array(Vec<String>) }`
  (`config.rs:336-339`); `parse_value` (`:362`) refuses anything else with
  *"value `{raw}` is not a quoted string or a [\"…\"] array (integers, booleans,
  dates, and inline tables are outside the antseal config subset)"*
  (`:431-435`). `docs/config.md:104` lists booleans as rejected.
- P2's probe (the debug binary, `antseal list` with no vault):

| Case | `config.toml` | Exit | First stderr line |
|---|---|---|---|
| a | `[anchors]` / `opportunistic_upgrades = false` | **17** | `malformed config at …/config.toml:2: value \`false\` is not a quoted string or a ["…"] array (integers, booleans, dates, and inline tables are outside the antseal config subset) …` |
| f | `[upgrade]` / `hook = false` (H6's spelling) | **17** | the same text, line 2 |
| i | `default_network = true` | **17** | the same text, line 1 |
| b | `[anchors]` / `opportunistic_upgrades = "off"` | 2 (no vault) | `warning: config.toml line 2: unknown key \`anchors.opportunistic_upgrades\` — ignored (newer antseal?)` |
| g | `[upgrade]` / `hook = "off"` | 2 | `warning: … unknown key \`upgrade.hook\` — ignored (newer antseal?)` |

### 1.5 An unknown key's value is parsed before the key is routed

`parse` calls `parse_value` (`config.rs:328`) before `apply` routes the key
(`:330`); the only check that runs on the key first is D180's `rpc_url`
refusal (`:319-327`). Cases a and f show the consequence: a boolean under a key
this build does not know is still exit 17. `docs/config.md:18-19` — *"Unknown
keys and sections are warnings … so a config written by a newer antseal still
loads"* — holds only for string and array values.

### 1.6 What does and does not ground "a config key, not an env var"

- D99 §9's U58 entry and `U60`'s Do say: *"Not an env var: D41's channel
  discipline puts operator preferences in config"* (D99:810-811;
  `tasks/U.md:859`).
- D41 (D41:3-9) rejects an environment-variable **passphrase** because *"the
  kernel serves `/proc/PID/environ` from the execve-time snapshot, which no
  userland unset or zeroize can wipe"*. An on/off preference is not a secret.
- D173 §2 R5 (`:235-240`) refuses a **peer** environment variable as an
  invocation-scoped injection vector that load-time validation never sees —
  also not this question.

### 1.7 Stale ids and locators

- `upgrade_hook.rs:60`: *"its remedy is U58's config key"*. `U58` is now a
  different row (*"Three stale … claims"*, `tasks/U.md:836`); D99 §9's U58 was
  reconciled to `U60` (`tasks/U.md:861`).
- `docs/threat-model.md:2028` cites the hook's single call site as
  `lib.rs:185`; it is `lib.rs:198` at `HEAD`.

### 1.8 The test seam the new sentence must fit

The binary's debug trace on target `antseal_cli::upgrade_hook`
(`HOOK_LOG`, `tests/upgrade_hook.rs:700`) is read by `armed()` (`:706`), which
decides from exactly the two existing sentences which arm a run took
(`upgrade_hook.rs:84-86`); `the_two_trace_arms_cannot_be_mistaken_for_each_other`
(`upgrade_hook.rs:537`) keeps them apart. A third sentence must be
distinguishable from both.

## 2. RULING

### §2 R1 — Bare lowercase booleans join the subset, typed per key

`true` and `false`, bare and lowercase, become `Value::Bool`. Every string or
array closure refuses a `Bool` with its own message (*"takes a string"* /
*"takes an array"*), and the `bootstrap` match refuses it.

*Why:* `U60`'s key cannot be written without it (§1.4). Typing per key keeps
a boolean from ever becoming a string by accident. No release exists
(`version = "0.0.0"`), so no released binary is broken by the growth.

Refused alternatives:
- **A string enum, `opportunistic_upgrades = "off"`.** No grammar change, but
  unnatural TOML for a switch, and a user who writes the natural `= false`
  meets exit 17 telling them booleans are unsupported.
- **An environment variable.** Its one advantage is per-invocation scope (a
  script opts out while interactive use keeps upgrading). Against it: no
  validation at load, so a misspelt variable is silently ignored (U52's defect
  class); invisible to `config.toml` and to `vault export` (D47); and a second
  preference channel. The per-invocation scope is recorded as a residual (§4).

### §2 R2 — `[anchors] opportunistic_upgrades = true|false`, default on

- Absent means `true`: the pass runs, and `Config::default()` is unchanged.
- Any other value (`"false"`, `"off"`, `False`, `[]`) → exit 17, naming the key
  and the line: *"`opportunistic_upgrades` takes true or false"*.
- Honoured only by `upgrade_hook::run_after_output`. After `HOOK_ARMED` is
  traced, if the key is `false`, the hook traces a **third** sentence and
  returns before `HookContext::production`: no client, no lock, no poll.
- The sentence is a new constant, distinguishable from both existing arms,
  for example `HOOK_SUPPRESSED = "opportunistic OTS upgrade pass skipped:
  config.toml sets [anchors] opportunistic_upgrades = false"`. It names the
  key (U60's Accept).
- `status <work-id> --upgrade` is unaffected: it is user-requested, and D99 R7
  already distinguishes it.

*Why after `HOOK_ARMED`:* D42's rule — armed iff the command holds an
unlocked vault — is still true of a suppressed run, and keeping the armed
sentence keeps `armed()`'s reading of the trace exact (§1.8).

### §2 R3 — An unknown key's value is not parsed

- Unknown keys warn on the key alone. The `[networks.<id>]` **name** check
  still runs first, so `[networks.ropsten]` keeps its error.
- **Known** keys still refuse out-of-subset values.
- Integers and dates stay outside the subset; A137 needs none (D193).

*Why now:* the first released binary is the first that cannot be patched, and
as the parser stands it would hard-fail on any later growth of the subset.
After this ruling, `docs/config.md:18-19`'s promise holds for every
single-line value (§1.5).

### §2 R4 — Documents

- `docs/config.md`: the subset table gains `key = true` / `key = false` as
  accepted, and the `[anchors]` block gains the key, in words like P2's:
  *"The opportunistic upgrade pass. After any command that unlocked the vault,
  antseal asks the OpenTimestamps calendars whether pending attestations have
  reached Bitcoin. It runs after the command's output is printed but before the
  process exits, so a script waiting on the process waits for it too — a few
  seconds, longer when a calendar or block explorer is slow. false turns the
  pass off; pending attestations then upgrade only when you run antseal status
  <work-id> --upgrade. Absent = true."* **No "6 s" figure** is printed
  anywhere: `A141` owns the bound (§4).
- `upgrade_hook.rs:53-60`: *"U58's config key"* becomes `U60`'s
  `[anchors] opportunistic_upgrades`, and *"about 6 s"* goes.
- Optional, those lines only: `docs/user/wallet-hygiene.md:269-276`,
  `README.md:83-85`, and `docs/threat-model.md:2024-2031` (with its stale
  `lib.rs:185` → `:198`).

### §2 R5 — The deadline, and the record that is corrected

- The deadline is `Q31` (D180:49); this lands now, before it.
- **D99** takes a dated addendum, written with this record: R8's and §8's ≈6 s
  omits `confirm_header`; §9's `U58` is `U60`; and the D41 citation for "not an
  env var" is a mis-citation — the real grounds are validation at load,
  discoverability, and travelling with `vault export`.

## 3. Fault plants

The implementing lane owes these (P2 §2B(g)). Green baselines come first; each
plant is judged by its **message**; every restore is followed by a `touch`.
Test 3 spawns the binary: it runs in a private `CARGO_TARGET_DIR`, or in the
shared target under the lock protocol with default features only.

**The green tests — the load-bearing half**

1. `config_file.rs` `booleans_are_in_the_subset_and_typed_per_key`:
   `opportunistic_upgrades = false` and `= true` load as `Some(false)` and
   `Some(true)`; absent, the accessor says `true`; `"false"`, `"off"`, `False`
   and `["false"]` are refused naming the key; `default_network = true` is
   refused as *"takes a string"*; `tsa_urls = true` as *"takes an array"*;
   `bootstrap = true` under `[networks.arbitrum-one]` is refused.
2. `config_file.rs` `an_unknown_key_warns_whatever_its_value`:
   `[future] n = 42`, `[future] b = true` and a date value load with warnings;
   controls: a **known** key with such a value is still refused, and
   `[networks.ropsten] x = 1` still fails *"not a known network"*.
3. `tests/upgrade_hook.rs` `the_config_key_turns_the_pass_off_and_says_so`
   (spawned, fixture vault, `HOOK_LOG`): the off run's exit code and stdout are
   byte-identical to the on run's; its stderr contains `HOOK_ARMED` and the new
   sentence (which contains `opportunistic_upgrades`) and **not**
   `pass complete`; the on run (same vault, key removed) contains
   `pass complete`.
4. Unchanged and still green: `a_pass_with_nothing_dialable_costs_no_budget`
   (`tests/upgrade_hook.rs:1050`; it runs with no config, so it is the default-on
   witness), `every_subcommand_either_arms_the_hook_or_is_a_documented_non_armer`
   (`:761`) and `initial_config_round_trips`.

**The plants — proof that those tests can fail**

| Plant | Must redden |
|---|---|
| P1 the key is parsed but never read in `run_after_output` | 3 (`pass complete` present, the new sentence absent) |
| P2 the default inverted | 4 (`a_pass_with_nothing_dialable_costs_no_budget`) and 3's control |
| P3 the key's name dropped from the sentence | 3 (its `contains("opportunistic_upgrades")`) |
| P4 `"false"` accepted as false | 1 |
| P5 a `Bool` coerced into `expect_str` | 1 (the `default_network = true` case) |
| P6 unknown keys' values parsed again | 2 |
| P6′ the network-name check skipped for unknown `[networks.*]` keys | 2 (its control) |

## 4. What this record does NOT decide

- **`A141` (minted this wave; not taken this wave): the opportunistic pass's
  header confirmation is not budget-gated.** `confirm_header` runs after an
  upgraded poll with no budget check (`ots/engine.rs:525-545`), so the hook's
  exit lateness can reach ≈12 s against the stated `budget.total + one
  in-flight call` (§1.2). Either check the remaining budget before
  `confirm_header` and drop the merge when it is spent — the transition is
  already atomic, *"the merge is dropped with the header"*
  (`engine.rs:536-537`), and the route is polled again next pass — or restate
  the bound wherever it is printed. Its test: an engine test with a
  late-answering upgraded stub and slow esplora stubs, asserting the shape
  exactly and the wall clock loosely. `A141` is `after U60`.
- **A per-invocation opt-out.** The environment variable's one advantage
  (§2 R1) is recorded as a residual, not ruled.
- **Integers and dates in the subset.** Outside it; a future key that needs
  either brings its own record. After §2 R3 an older binary warns on such a key
  instead of refusing the file.
- **`U59`'s re-polling of routes that cannot change.** Unchanged; it is why the
  cost of an armed pass is permanent until `U59` lands.

## 5. Edit list — per write scope, with the lane named before this record was written

### L-CFG (round 1) — after D188, in the same lane

- `crates/antseal-cli/src/config.rs`: `enum Value` (`:336-339`, + `Bool`),
  `parse_value` (`:362`), the out-of-subset error text (`:431-435`, no longer
  listing booleans), `apply`'s closures (`:532`, `:536`) and the `bootstrap`
  arm (`:599`) refusing `Bool`, the new `(["anchors"],
  "opportunistic_upgrades")` arm, the `Config` field and an accessor defaulting
  to `true`, and the module doc's grammar list and schema block. For §2 R3:
  `parse` (`:319-330`) and `apply`'s signature — the raw value goes in and only
  recognised arms parse it.
- `crates/antseal-cli/src/upgrade_hook.rs`: the new constant beside `:87-92`,
  `run_after_output` (`:305`), the module doc `:53-60`, and
  `the_two_trace_arms_cannot_be_mistaken_for_each_other` (`:537`) extended to
  three sentences.
- `docs/config.md`: the `[anchors]` block and the subset table.
- Optional, those lines only: `docs/user/wallet-hygiene.md:269-276`,
  `README.md:83-85`, `docs/threat-model.md:2024-2031`.
- Tests: `crates/antseal-cli/tests/config_file.rs` and
  `crates/antseal-cli/tests/upgrade_hook.rs`.

### RECORDS-A — dated addendum

D99: the ≈6 s arithmetic, `U58` = `U60`, and the D41 mis-citation.

### Orchestrator — `TODO.md`, `tasks/U.md`, `tasks/A.md`, `docs/decisions/README.md`

- `U60`: the tick.
- `A141`: the row and its entry, per §4.
- This record's index row and register row.

## 6. As built — wave 38, lane L-CFG (recorded in place before this record was first committed)

Every verdict below was read from an exit file. Plants ran in the lane's copy of the tree with a
private target directory, as recorded in D188 §6.

- **§2 R1.** `enum Value` gains `Bool`, and `parse_value` accepts exactly bare `true` and `false`.
  - A boolean inside an array is refused.
  - Each key takes one kind, with typed refusals (*"`{what}` takes a string, not a boolean"*).
  - The subset's refusal now names bare `true`/`false` among what it accepts.
- **§2 R2.** `[anchors] opportunistic_upgrades` defaults to on (`opportunistic_upgrades_enabled`,
  `unwrap_or(true)`). Any value other than `true` or `false` is exit 17: *"`opportunistic_upgrades`
  takes true or false"*.
  - `run_after_output` traces `HOOK_ARMED`, then `HOOK_SUPPRESSED` (*"opportunistic OTS upgrade
    pass skipped: config.toml sets [anchors] opportunistic_upgrades = false"*), and returns before
    any client, lock or poll.
  - The module doc's *"6 s"* and its stale *"U58's config key"* are gone.
- **§2 R3.** An unknown key's value is never parsed. The table name of `[networks.*]` and
  `[verify.*]` is still judged first.
- **§2 R4.** `docs/config.md` covers the key, the subset table and the forward-compatibility
  bullet. Optional edits taken:
  - `docs/user/wallet-hygiene.md`'s locator moved by this edit;
  - `README.md`;
  - `docs/threat-model.md` outside its frozen block, where *"so it can never delay a command
    meaningfully"* became what is true and `lib.rs:185` became `:198`.
- **Tests.**
  - `booleans_are_in_the_subset_and_typed_per_key` and `an_unknown_key_warns_whatever_its_value`:
    8 warnings, with two controls.
  - The spawned `the_config_key_turns_the_pass_off_and_says_so`: same exit code and byte-identical
    stdout with the key off, `ARMED` then `SUPPRESSED`, and no *"pass complete"*. Its control,
    without the key, completes the pass.
  - The hook unit test was renamed `the_three_trace_sentences_cannot_be_mistaken_for_each_other`;
    no record cites the old name.
- **Plants: seven, every one red by message.**
  - D189-P1 (the key never read) reddened *"the trace must say the pass was suppressed"*.
  - D189-P2 (the default inverted) reddened `a_pass_with_nothing_dialable_costs_no_budget`.
  - D189-P4 (`"false"` accepted) reddened *"loaded — no refusal"*.
  - D189-P6 (unknown values parsed again) reddened *"an unknown key never fails on its value"*.
- **At the lane's close.** `cargo test -p antseal-cli --test config_file` passed 25, and
  `--test upgrade_hook` passed 12 (622 s under load). `clippy -D warnings` exited 0.
- **The orchestrator's act.** `U60` is ticked.

## Closing — this record is not consent

It adds a config key and grows the config grammar inside the wave's own
commits. Nothing in it authorises a push, a workflow dispatch, a deploy or any
other outward act; each of those needs the maintainer's express consent naming
the action, the destination and the account.

## Addendum — 2026-10-19 (wave 39, D196 §2 R1–R2; D202): an unknown key still only warns while a known key in the wrong table is refused, and `A141` is answered

1. **§2 R3's promise for unknown keys stands (D196 §2 R2).** §2 R3 reads *"Unknown keys warn on
   the key alone"* (`:211`), and its *Why now* — the first released binary cannot be patched, so
   a config written by a newer antseal must still load (`:216-219`) — is unchanged. D196 refuses
   only a key this build **knows**, written in a table where it does not live (D196 §2 R1). That
   refusal is raised on the key before its value is parsed, so no value is read for it either,
   and the `[networks.<id>]` name check still runs first, as §2 R3's first bullet requires. The
   refusal rests on D180's ground, not on this record's: D180 already refused a known key the
   binary cannot honour, and D196 measured that a misplaced recognised key only warns today, so
   the override it carried is silently lost (D196 §1.1). The cost is the one D180 accepted for
   `rpc_url`: a later build that gives a known key a second home would make this build refuse
   that file, and no release exists yet for such a refusal to break (D196 §4).
2. **§4's `A141` bullet (`:291-301`) is answered by D202.** §4 offered two remedies: check the
   remaining budget before `confirm_header` and drop the merge, or restate the bound wherever it
   is printed. D202 takes the first and widens it. A time-only gate
   (`started.elapsed() >= budget.total`, never `budget.exhausted(..)`, which would drop the last
   permitted poll's upgrade) runs immediately before `confirm_header`, and each of the
   confirmation's esplora requests checks the same deadline before it starts. So
   `budget.total + one in-flight call` is true as written, and no figure is restated. Its tests
   are the ones §4 asked for: a late-answering upgraded stub and slow esplora stubs, the shape
   asserted exactly and the wall clock loosely (D202 §3). The ≈12 s of §1.2 stays correct as a
   derivation, but §0's *"no offline run can reach it"* (`:55-57`) did not hold: a loopback-only
   run with the real opportunistic client and budget measured 9.4 s at `07a170c`, because Q16
   refuses non-loopback hosts, not loopback stubs (D202 §1.3).

The rest of this record stands. The text above stays as written.
