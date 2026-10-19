# D188 — One calendar list in two roles: `[anchors] ots_calendars` is the seal's submit list **and** the upgrade allowlist's widening, from one source; the verify RPC pair is **per network** under `[verify.<network>] rpc_endpoints`, checked at load; and the flat `[verify] arbitrum_endpoints` is **refused at load**, never echoed

- **Status: RESOLVED. H5's direction survived and its premises fell (b).** H5
  read: one function resolves the calendar list for both the submit path and
  the upgrade path; `[anchors] ots_calendars` is added; `[verify]
  arbitrum_endpoints` is reshaped per network, and the reshape is still needed
  after D180.
  - **What survives.** One source feeds both calendar paths; the key is added;
    the per-network reshape is still needed, because one flat list cannot hold
    A17's two pairs (*"Per-network endpoint sets (arbitrum-one vs
    arbitrum-sepolia; disabled on devnet) configurable"*, `tasks/A.md:216`).
    D173 and D180 do not change its spelling: a `[networks.<id>]` RPC key would
    sit beside the payment-RPC key D180 made the table's refusal.
  - **Five premises fell.**
    1. D55 §6's *"nothing consumes it"* (D55:419-420): `U30` consumes the flat
       key (`verify_host.rs:296`).
    2. U44 Accept 4's *"warning, not exit 17"*: reversed on D180's reasoning
       (§2 R5).
    3. U64's *"two spellings of one policy"*: it is one source with one
       collapse rule, serving **two roles** — submit targets, and hosts
       admitted beyond the pinned suffixes — with a stranding residual the
       documents must state.
    4. D55 §6's harm, a wrong-network endpoint read as `Lagging`
       (D55:414-417): superseded by the per-endpoint `eth_chainId` guard,
       which returns `WrongChain` (`arbitrum/confirm.rs:241-262`).
    5. The validator D54 §6.3, D55 §6 and U44's Do name, `expect_url_array`:
       stale since A49/A50 made the TLS policy a parameter of
       `expect_endpoint_array` (`config.rs:563-573`), and none of them chose
       a policy for calendars.
  - **The deadline is `Q31`, not `U32`.** No exit class, help line,
    error-display exemplar or `--json` shape moves; every refusal reuses
    `malformed-config` (17). D180 measured that the first release is the
    deadline that governs a config key (D180:49). One exit **behaviour** does
    move: a verify RPC pair of the wrong length, refused today at use as
    `usage` (2, `verify_host.rs:309-318`), is refused at load as 17. No code is
    renumbered.
- **Date: 2026-10-17**
- Owner rows: **`U44`**, **`U52`**, **`U64`** (§2 R1–R11). Not decided here:
  **`A94`** (§2 R9). Minted this wave, **not** taken this wave: **`U98`**
  (§4).
- Related:
  - **D54** §6.2–§6.3 (the calendar key and the allowlist widening; takes a
    dated addendum on its validator and TLS policy), §3 (OTS never blocks a
    seal), §4 (the pinned suffix list is append-only, D54:247);
  - **D55** §5 (devnet has no pair, D55:394-400) and §6 (the reshape; takes a
    dated addendum);
  - **D180** (refuse at load, never warn; never echo an RPC URL);
  - **D173** (per-network resolution), **D99** (the upgrade hook);
  - **`U4`**, **`U26`** (the override slots and `tsa_urls`' semantics),
    **`U30`** (the consumer), **`A17`**, **`A42`**, **`A49`**/**`A50`**,
    **`Q16`** (the no-real-network test gate), **`Q31`**.

## 0. What was measured against

`HEAD` `23f3093` (local `main`; `origin/main` = `cfd5868`). The tree was clean,
and no file under the repository changed mtime during the planning round.

Planning lane P2 (wave 38, 2026-10-17) worked read-only. Its one execution ran
a copy of the debug binary built after `config.rs`'s last commit
(`antseal 0.0.0`) against nine hand-written `config.toml` cases, each under a
fresh `HOME` and `ANTSEAL_DIR` with `ANTSEAL_NO_REAL_ANCHOR_NETWORK=1`, reading
the exit code from `$?` into a file (§1.8).

Before this record was written, the records lane re-read every locator below at
`HEAD` through `git show 23f3093:<path>`, because L-CFG was already editing these
files in the shared tree. Every citation held, with three locator refinements:
`docs/config.md`'s stale *"Reserved slot"* sentence is at `:82-83` (P2 wrote
`:80-82`); the Q16 scan skips its own file by name at
`tests/anchor_stage.rs:1019` (P2 wrote `:1000-1002`, which is the helper's
signature); and `http/endpoint.rs` names the flat key at `:107-110`.

## 1. What was measured

### 1.1 The calendar key, and the two constructors that would read it

- **The key does not exist.** At `HEAD`, `calendar` and `ots_` occur 0 times in
  `crates/antseal-cli/src/config.rs` and 0 times in `docs/config.md`.
- **The seal side** passes `None`: `AnchorStageConfig::from_config`
  (`seal_run.rs:632-642`) builds `AnchorEndpoints::from_config(
  config.tsa_urls.as_deref(), None)` (`:638`), which resolves through
  `effective_calendars` (`antseal-anchor/src/submit.rs:88-93`). Its doc still
  says *"the built-in calendar list"* (`:628-630`).
- **The upgrade side** hardcodes the defaults: `UpgradeConfig::from_config`
  (`status.rs:779-791`) sets `calendars: DEFAULT_OTS_CALENDARS…` (`:781-784`).
  Its field doc (`:768-771`): *"Its only role here is to **widen A42's
  allowlist** to the hosts the user chose: the URIs actually polled come out of
  the stored artifact, never out of this list."* It is consumed by
  `status --upgrade` (`:922`) and by the opportunistic hook
  (`upgrade_hook.rs:225`).
- Today both resolve to the same four defaults. They diverge the moment a key
  exists unless both are wired: that is U52's and U64's defect.
- **U52's silent-ignore window.** Today an `ots_calendars` key is **loud**: the
  loader warns `unknown key \`anchors.ots_calendars\` — ignored` (§1.8, case e).
  It becomes silent exactly when U44's parser arm lands without U52's wiring.

### 1.2 One source, two roles

- **Same source and collapse rule.** D54 §6.2 defines the widening argument as
  the user's calendar list (`upgrade_uri_allowed(uri, configured)`), and
  `upgrade_uri.rs:100-103` documents `configured` as *"the user's calendar list
  (U4's `[anchors] ots_calendars`)"* — a key that does not exist yet, and
  that `U44`, not `U4`, adds.
- **Different roles.** Seal: the calendars to submit to. Upgrade: the hosts
  admitted beyond the three pinned suffixes, *"that host and its subdomains
  only"*.
- **The consequence.** Removing a calendar from the list later strands that
  calendar's stored pending attestations: the upgrade refuses them as
  `HostNotAllowed`. It is the same reason D54 §4 makes the pinned suffix list
  append-only: *"Removing a suffix would strand every already-stored `.ots`"*
  (D54:247).
- **Nothing measured is stranded by the custom-list widening itself.** Every
  real pending URI D54 §1 recorded lies under the pinned suffixes
  (`REAL_PENDING_URIS`, `upgrade_uri.rs:203-208`).
- **Two more residuals.** The hook's budget is `max_polls: 4`
  (`ots/engine.rs:138`), equal to the number of default calendars and pinned
  by `the_opportunistic_budget_matches_the_substrate_profile`
  (`ots/engine/tests.rs:910`), so a configured list longer than four cannot be
  finished in one invocation (`status --upgrade` has its own budget,
  `UpgradeBudget::interactive()`: 120 s and unbounded polls, `:145-150`). And
  upgrades are fetched over https only (`UpgradeUriRefusal::NotHttps`,
  `upgrade_uri.rs:81`, enforced at `:125` and `:142`), so a calendar that names
  itself by an `http://` URI in its attestations is never upgraded.

### 1.3 Deduplication, and a comment that claims it

`effective_tsa_urls` deduplicates (`antseal-anchor/src/tsa.rs:135-141`);
`effective_calendars` does not (`ots/calendars.rs:77-85`). Yet
`seal_run.rs:634-637` says: *"One collapse rule, `antseal_anchor`'s, for both
families — deduplication and the empty-means-defaults decision included."*
Without deduplication a duplicated entry is submitted to twice and counted
once by pending URI (D54 §3's dedupe): a silent "1 calendar" degradation the
user did not intend.

### 1.4 The TLS policy for calendars was never chosen at load

- Since A49/A50 the override keys are validated by `expect_endpoint_array(value,
  what, tls)` (`config.rs:563-573`), whose comment states the rule: *"one
  implementation of 'which URLs this build will contact', used at config load
  and again inside `HttpClient::send`"* (`:552-554`).
- The calendar **submit** path already chose `TlsPolicy::Optional`
  (`ots/submit.rs:328-335`): *"the carve-out exists for the loopback stubs and
  for a user's private calendar. Note the deliberate asymmetry with A42, which
  requires https on the *upgrade* URI"*.
- `ots/calendars.rs:72-75` records why an empty list means the defaults:
  *"`ots_calendars = []` in a config file is far more likely to be a mistake
  than a considered decision to stamp nowhere, and the way to stamp nowhere is
  `--no-anchor`"*.

### 1.5 The flat verify key is consumed, and what it does on the wrong network

- **Consumed since `U30`.** `endpoints_from_config` (`verify_host.rs:279-306`)
  reads `config.verify_arbitrum_endpoints` (`:296`) and applies the one list to
  whichever network the run resolved (`commands.rs:1005-1012`:
  `effective_network`, then `endpoints_from_config(&config, network)`). The
  default pair is per network
  (`verify_rpcs(network)`, `None` on devnet).
- **Wrong network today:** each endpoint is asked `eth_chainId` first, and a
  mismatch is `EndpointFailure::WrongChain` (`arbitrum/confirm.rs:241-262`) —
  a loud, advisory failure, not D55 §6's false `Lagging`.
- **Devnet today:** the flat override makes `endpoints.arbitrum` `Some`, and
  only `expected_chain_id(Devnet) == None` stops the probe
  (`verify_host.rs:195-198`). The comment at `:189-191` — *"`endpoints.arbitrum`
  is therefore already `None`"* — is false whenever the flat key is set.
- **What remains of the defect:** one list cannot hold two networks' pairs. A
  user verifying both networks' bundles must edit the file between runs, and a
  pair configured for the other network is a guaranteed `WrongChain`.

### 1.6 Where the pair is checked today, and who relies on that

- **At use, not load.** `parse_pair` (`verify_host.rs:309-318`) returns
  `CliError::Usage`: *"`[verify] {key}` must list exactly two endpoints (found
  {})"*. A one-entry flat list loads (§1.8, case d). U44 Accept 3's feared
  *"silent single-endpoint overlay"* cannot happen today; it is a late usage
  error.
- **The hook turns a bad bitcoin pair into a debug-level skip**
  (`upgrade_hook.rs:312-319`), and
  `a_hook_that_cannot_start_leaves_the_command_untouched`
  (`tests/upgrade_hook.rs:999`) uses a one-entry `bitcoin_endpoints` list
  precisely because it loads. Moving the bitcoin check to load would remove
  that test's only vehicle.

### 1.7 Echo, and why D180's reasoning reaches this key

- **The URL is echoed at load today.** `EndpointError`'s Display is
  `"{endpoint}: not a usable endpoint URL ({reason})"` and
  `"{endpoint}: this endpoint must be https …"` (`http/endpoint.rs:246`,
  `:254`), and `a_plain_http_verify_endpoint_is_refused_at_config_load`
  asserts the echo (`tests/config_file.rs:186-189`). The subset's own
  *"not a quoted string"* error repeats the raw value (`config.rs:431-435`);
  D180's `rpc_url` refusal is therefore raised on the key before the value is
  parsed (`config.rs:319-327`, `rpc_url_refusal` at `:502-517`).
- **Receipt RPCs commonly need a key.** D55's survey recorded publicnode
  answering `eth_getTransactionReceipt` with *"-32602 … Archive requests
  require a personal token"* (D55:126).
- **D180's reasoning** (D180:11-20): a warned override means the command
  contacts *"the very endpoint the user configured away from"*, and
  `docs/config.md:16-17` already says *"silently dropped overrides are worse
  than a loud stop"*. After a reshape that only warns, `verify --online` would
  quietly return to the pinned public pair.
- **No release exists.** `crates/antseal-cli/Cargo.toml` is `version =
  "0.0.0"`; the only tags are `format-v1-freeze` and
  `pre-trailer-strip-949dd9d`. The only shipped instruction to write the flat
  key is the public repository's `docs/config.md:91` (and `config.rs`'s module
  doc).

### 1.8 What the loader does today (P2's probe)

| Case | `config.toml` | Exit | First stderr line |
|---|---|---|---|
| c | `[verify.arbitrum-one]` / `rpc_endpoints = [two https]` | 2 (no vault) | `warning: … unknown key \`verify.arbitrum-one.rpc_endpoints\` — ignored (newer antseal?)` |
| d | `[verify]` / `arbitrum_endpoints = [one entry]` | 2 | none — it loads; the count is checked only at use |
| e | `[anchors]` / `ots_calendars = ["https://cal.example.com"]` | 2 | `warning: … unknown key \`anchors.ots_calendars\` — ignored (newer antseal?)` |
| h | `[verify]` / `bitcoin_endpoints = [three entries]` | 2 | none — it loads; the hook will skip silently |

Exit 2 is the command's own "no vault" outcome: the config loaded.

### 1.9 Two test-placement facts

- **U52's consumer test can live in one file only.**
  `no_test_source_names_a_live_anchor_endpoint`
  (`tests/anchor_stage.rs:818`) forbids every name in `DEFAULT_LIST_ROUTES`
  (`:797-803`, including `AnchorStageConfig::from_config`) in every other test
  source, and skips its own file by name (`:1019`). In-process CLI tests are
  not gated by Q16's `cfg(test)` arm: a bare `cargo test -p antseal-cli` once
  sent a probe that *"**reached freetsa.org**"* (`:849-853`).
- **The Q16 route list omits `UpgradeConfig::from_config`**, which returns the
  live esplora pair by default. Measured yield today: **0** offenders
  (`command grep -rn UpgradeConfig crates/antseal-cli/tests/` finds one
  comment, `tests/upgrade_hook.rs:995`).

### 1.10 U44 Accept 5 has no referent at `init`

`initial_config_text` (`config.rs:225-231`) writes only `default_network`, so
*"`initial_config_text` … cover[s] the new shape"* had no old shape to replace.

## 2. RULING

### §2 R1 — `[anchors] ots_calendars`

- A single-line string array. Absent or `[]` means D54's four
  (`effective_calendars`, semantics unchanged — `[]` = defaults, the `tsa_urls`
  convention). A non-empty list replaces the defaults wholesale.
- Validated at load with `expect_endpoint_array(value, "ots_calendars",
  TlsPolicy::Optional)` — the submit path's own policy
  (`ots/submit.rs:328-335`), so load and use cannot disagree.
- An invalid entry is exit 17, naming the key, the line and the entry. Calendar
  URLs carry no credentials, so the `tsa_urls` echo convention stands.

*Why `Optional`:* A50's rule is one implementation of "which URLs this build
will contact" at load and at use (§1.4). A calendar cannot forge an
OpenTimestamps proof (D54:20-21: *"a liveness decision, not a trust decision"*),
so plain http weakens no evidence; its cost — such a calendar is never
upgraded — is documented (§2 R3).

### §2 R2 — `effective_calendars` deduplicates

Like `effective_tsa_urls`. This makes `seal_run.rs:634-637`'s *"deduplication
… included"* true (§1.3).

### §2 R3 — One source, two roles

- `AnchorStageConfig::from_config` passes `config.ots_calendars.as_deref()`
  (the submit targets).
- `UpgradeConfig::from_config` uses `effective_calendars(
  config.ots_calendars.as_deref())` (the allowlist widening).
- The asserted property is the **equality of the two constructors' lists**
  over {absent, `[]`, custom}.
- Residuals, documented in `docs/config.md` and not fixed: removing a calendar
  later strands its pending attestations (`HostNotAllowed`); the hook's
  `max_polls: 4` cannot finish a longer list in one invocation; upgrades are
  fetched over https only.

### §2 R4 — `[verify.arbitrum-one]` and `[verify.arbitrum-sepolia]` `rpc_endpoints`

- Exactly two endpoints, each `Endpoint::parse(_, RequiredExceptLoopback)`,
  with distinct origins checked through the substrate's own
  `EndpointPair::new`, all **at load** — otherwise exit 17.
- `[verify.devnet]` → 17: *"devnet has no RPC pair to override: its chain is a
  fresh Anvil per run (D55 §5)"*.
- `[verify.<unknown>]` → 17, in the `[networks.<id>]` wording.
- Other keys under `[verify.<network>]` warn, after the network name is
  validated.
- `[verify] bitcoin_endpoints` stays flat and is checked at use, as today
  (§1.6 names the test that depends on it loading).

### §2 R5 — No echo for `rpc_endpoints`; the flat key is refused at load

- A refusal of `rpc_endpoints` names the key, the table, the line and the entry
  **index**, never the URL — D180 §2's reason: an RPC URL commonly carries an
  API key (§1.7).
- The flat `[verify] arbitrum_endpoints` is **refused at load** (exit 17),
  raised on the key **before** its value is parsed, naming the key, the table,
  the line and the replacement tables, never the value. The refusal text
  follows `rpc_url_refusal`'s pattern.
- **U44 Accept 4's "warning" is reversed.** D55 §6's premise *"nothing consumes
  it"* fell when `U30` wired the key, and D180's reasoning applies: a warned
  override probes the very endpoints the user configured away from.

### §2 R6 — `endpoints_from_config` reads only the run's network

`endpoints_from_config(config, network)` reads only `network`'s pair.
`overridden` is true when the bitcoin override is present **or** this network's
pair is overridden. The devnet comment at `verify_host.rs:189-191` becomes true
by structure.

### §2 R7 — U44 Accept 5, restated

*"The D42/D47 export round trip carries the new keys and they load;
`initial_config_text` still parses with zero warnings"* (`init` writes no
slot, §1.10).

### §2 R8 — `docs/config.md`

- The schema block and the URL paragraphs: add `ots_calendars` with its note
  (wholesale replace; `[]` = defaults; upgrades over https only; the stranding
  residual; OTS never blocks a seal, D54 §3); replace the flat key with the two
  `[verify.<network>]` tables; replace the stale *"Reserved slot: validated
  now, consumed when online verification lands (M3)"* (`:82-83`), and say that
  `bitcoin_endpoints` also feeds `status --upgrade` and the opportunistic pass.
- Plus D192's *"which TSAs count"* sentence in the `[anchors]` comment (its
  text is D192 R3's).

### §2 R9 — `A94` is not decided

`[]` = defaults leaves "no OTS wanted" expressible only by a future, separate
key (additive, `Q31`-governed). The orchestrator annotates `A94`.

### §2 R10 — The Q16 route promotion is refused, with its count

Adding `"UpgradeConfig::from_config"` to `DEFAULT_LIST_ROUTES` is refused:
measured yield today is 0 offenders (§1.9).

### §2 R11 — Addenda

- Records lane, written with this record: **D54 §6.3** (the validator is
  `expect_endpoint_array` with `TlsPolicy::Optional`) and **D55 §6** (a
  consumer since `U30`; the `Lagging` harm superseded by the `eth_chainId`
  guard; Accept 4's reversal, citing D180).
- Orchestrator: U44 Accept 4 and 5 restated, and the U4 execution note's
  item 4 amended, in `tasks/U.md`.

## 3. Fault plants

The implementing lane owes these (P2 §2A(g)). Green baselines come first; each
plant is judged by its **message**; every restore is followed by a `touch`; a
type-changing plant is a compile check, not a red. `config_file.rs`,
`anchor_stage.rs` and `upgrade_hook.rs` contain spawned-binary tests and run in
a private `CARGO_TARGET_DIR`.

**The green tests — the load-bearing half**

1. `config_file.rs` `ots_calendars_load_validated_and_replace_wholesale`: two
   https entries load in order; `[]` loads; a plain `http://` entry loads
   (`Optional`); a hostless entry, a `gopher://` entry and an entry with
   userinfo are refused naming `ots_calendars` and the line; a string value is
   refused as *"takes an array"*.
2. `config_file.rs` `verify_rpc_pairs_are_per_network`: both tables load to
   distinct pairs, read back through the accessor; the accessor is `None` for
   devnet.
3. `config_file.rs` `a_devnet_or_unknown_verify_table_is_refused`:
   `[verify.devnet]` names the reason; `[verify.ropsten]` gives the exact
   `[networks.<id>]` text.
4. `config_file.rs` `a_verify_rpc_override_is_exactly_two_distinct_origins_at_load`:
   one entry, three entries, and two URLs at one origin are each refused.
5. `config_file.rs` `the_flat_arbitrum_endpoints_key_is_refused_by_name`: the
   detail names `arbitrum_endpoints` and `[verify.arbitrum-one]`, and a canary
   value is absent from it, including when the value is malformed (unquoted).
6. `config_file.rs` (modified): the full-schema fixture and the export round
   trip carry the new keys; `initial_config_round_trips` is unchanged.
7. `anchor_stage.rs` `a_configured_calendar_list_is_what_the_stage_contacts`
   (U52 Accept): two loopback calendar stubs in `ots_calendars`, unhelpful TSA
   stubs and `--force-degraded`. A pre-flight `assert_eq!` on the resolved
   calendar list runs **before** the seal, so a broken wiring fails offline
   instead of submitting to the four real aggregators; then both stubs'
   request counters are non-zero and the stage's OTS endpoint list is exactly
   the two stubs.
8. `anchor_stage.rs` `an_absent_or_empty_config_yields_the_built_in_defaults`
   (extended): absent and empty give `DEFAULT_OTS_CALENDARS`; a custom list
   replaces them.
9. `anchor_stage.rs` `the_seal_and_upgrade_paths_read_one_calendar_list` (U64
   Accept): the two constructors' lists are equal over {absent, `[]`, custom};
   and, with no network, `UpgradeTarget::from_pending_uri` on a custom host is
   `Ok` under the custom config and `Err(HostNotAllowed)` under the default.
10. `verify_host/tests.rs` `endpoints_from_config_reads_only_the_effective_networks_pair`:
    with a sepolia-only override, an arbitrum-one run gets the pinned pair and
    `overridden == false`, a sepolia run gets the override and
    `overridden == true`, and devnet gets no Arbitrum pair.
10b. `verify_host/tests.rs` `a_configured_pair_is_what_the_receipt_probe_contacts`
    (the consumer half — a key parsed and ignored is U52's defect class): two
    loopback stubs answering `eth_chainId` with arbitrum-one's id; both
    stubs' requests contain `eth_chainId` and `eth_getTransactionReceipt`. The
    no-table control is asserted at **resolution only** and never probed,
    because probing the default pair would dial the public RPCs on any machine
    without `ANTSEAL_NO_REAL_ANCHOR_NETWORK=1`.
11. Optional, spawned: the flat key exits 17 before any command runs, in the
    shape of `an_rpc_url_key_is_exit_17_before_any_command_runs`.

**The plants — proof that those tests can fail**

| Plant | Must redden |
|---|---|
| P1 `seal_run.rs:638` reverted to `None` | 7 (at the pre-flight assert, no request made), 9 |
| P2 `status.rs:781`'s hardcode restored | 9, on both assertions |
| P3a `ots_calendars` validated under `RequiredExceptLoopback` | 1 (the plain-http case) |
| P3b bare `expect_url_array`, no `Endpoint::parse` | 1 (the userinfo and hostless cases) |
| P4 the `ots_calendars` arm deleted (it falls to the warning) | 1, 7 |
| P5 one network's pair applied to every network | 10, 10b |
| P6 `[verify.devnet]` accepted | 3 |
| P7 the load-time count and origin check dropped | 4 |
| P8a the flat arm re-added, or downgraded to a warning | 5 |
| P8b the value formatted into the refusal | 5 (the canary assertion) |
| P9 the deduplication removed from `effective_calendars` | its new unit test |

## 4. What this record does NOT decide

- **`A94`**: how to say "no OTS wanted" (§2 R9).
- **`U98` (minted this wave; not taken this wave): `verify --online` discloses
  every configured endpoint's full URL.** `OnlineEndpoints::identities()`
  returns each endpoint's `url()` (`verify_host.rs:241-251`) into core's
  `ProbeEndpoints`, *"Every endpoint the run consulted, in disclosure order"*
  (`antseal-core/src/verify/overlay.rs:205-206`), so a keyed RPC URL reaches
  the overlay and `--json`; and every `[verify]` refusal other than
  `rpc_endpoints`' still echoes its URL (§1.7). Decide between disclosing the
  origin only and documenting "never put a credential in a `[verify]` URL".
  Before `Q31`. §2 R5's no-echo rule is the load-time half for
  `rpc_endpoints` only.
- **`bitcoin_endpoints`' count and origin check at load.** It stays at use;
  the inconsistency with `rpc_endpoints` is recorded, not fixed (§1.6).
- **The three residuals of §2 R3.** Documented, not fixed.
- **Whether anyone outside this repository wrote the flat key.** Unknowable for
  a public repository. The refusal names the line and the replacement tables.

## 5. Edit list — per write scope, with the lane named before this record was written

### L-CFG (round 1) — this record first, then D189, `U50`'s helper and D192's sentence

- `crates/antseal-cli/src/config.rs`: the module-doc schema block and prose;
  `struct Config` (add `ots_calendars`; replace `verify_arbitrum_endpoints`
  with per-network storage and an accessor whose `match` on the network has no
  `_` arm, devnet → `None`); `parse` (the pre-parse refusal of the flat key
  beside `rpc_url`'s, and value-free handling for `rpc_endpoints`); `apply`
  (the new arms; the flat arm at `:672-678` deleted).
- `crates/antseal-cli/src/seal_run.rs`: **only** `AnchorStageConfig::from_config`
  and its doc (~`:620-645`).
- `crates/antseal-cli/src/status.rs`: `UpgradeConfig::from_config`
  (`:779-791`), its struct doc, and the import at `:82` if it becomes unused.
- `crates/antseal-cli/src/verify_host.rs`: **only** `endpoints_from_config`,
  `parse_pair` and the comments about them (~`:140-145`, ~`:185-195`,
  ~`:275-335`). Not `collect_live`, which L-VOCAB edits.
- `crates/antseal-cli/src/verify_host/tests.rs`: tests 10 and 10b.
- `crates/antseal-anchor/src/ots/calendars.rs` (the deduplication and its unit
  test); `ots/upgrade_uri.rs` (doc ~`:100-103` only); `http/endpoint.rs` (doc
  ~`:106-110` only).
- Tests: `crates/antseal-cli/tests/{config_file.rs, anchor_stage.rs,
  upgrade_hook.rs}`.
- `docs/config.md` (the whole file, including D192 R3's sentence).
- Not touched by this lane: `error.rs`, `machine.rs`, `cli.rs`, `pipeline/**`,
  `backend.rs`, `docs/user/timestamp-authorities.md`, and any other
  `antseal-anchor` source file.

### RECORDS-A — dated addenda

D54 §6.3 (the validator and the TLS policy); D55 §6 (a consumer since `U30`;
the `Lagging` harm superseded; Accept 4 reversed, citing D180).

### Orchestrator — `TODO.md`, `tasks/U.md`, `tasks/A.md`, `docs/decisions/README.md`

- `U44`: Accept 4 and 5 restated per §2 R5 and §2 R7; the U4 execution note's
  item 4 amended (U44's Notes ask for it, `tasks/U.md:725`).
- `A94`: the annotation of §2 R9.
- `U98`: the row and its entry, per §4.
- `U44`, `U52`, `U64`: the ticks; this record's index row and register row.

## 6. As built — wave 38, lane L-CFG (recorded in place before this record was first committed)

Every verdict below was read from an exit file. The plants ran in a copy of the tree (an rsync
without `target/` and `.git/`, the lane's ten files sha-identical to the tree's), built into a private
target directory, offline and without the tree lock. The lane's exclusive tree-lock window waited
30 minutes and was never granted (`docs/instrument-ledger.md`), so no plant ever touched the tree.
An unplanted control ran green in the copy first.

- **§2 R1, R2.** `[anchors] ots_calendars` is validated at load by `expect_endpoint_array` with
  `TlsPolicy::Optional`, replaces the defaults wholesale, and treats `[]` as the defaults.
  `effective_calendars` deduplicates and keeps first occurrences, as `effective_tsa_urls` does.
- **§2 R3.** One list in two roles: `AnchorStageConfig::from_config` passes
  `config.ots_calendars` (`seal_run.rs:664`), and `UpgradeConfig::from_config` reads
  `effective_calendars(config.ots_calendars.as_deref())` (`status.rs:789`).
  - `the_seal_and_upgrade_paths_read_one_calendar_list` asserts the two equal for an absent
    list, `[]` and a custom list.
  - `a_configured_calendar_list_is_what_the_stage_contacts` loads its config from text, checks
    the parsed list before any request, and asserts that both calendar stubs were contacted.
- **§2 R4–R6.** `[verify.arbitrum-one]` and `[verify.arbitrum-sepolia]` `rpc_endpoints` are checked
  at load by one function, `config::rpc_endpoint_pair`, which `verify --online` also calls at use.
  The check requires exactly two entries from two origins, and every refusal names the entry
  index, never the value.
  - `[verify.devnet]` and the flat `[verify] arbitrum_endpoints` are refused by name (exit 17).
  - `endpoints_from_config` reads only the run's network.
  - The spawned `a_flat_arbitrum_endpoints_key_is_exit_17_before_any_command_runs` asserts exit 17
    and the `config.toml:2` line, with a canary absent from both streams.
- **§2 R7.** `exported_config_survives_import_and_resolves` carries the new keys, and
  `initial_config_round_trips` is unchanged, with zero warnings.
- **§2 R8.** `docs/config.md` is rewritten as ruled, with new *OpenTimestamps calendars* and
  *Online-verification endpoints* sections, and the stale *"Reserved slot … (M3)"* is gone.
- **Plants: twelve, every one red by message.** Among them:
  - D188-P1 (calendars `None` again) reddened the stage test's pre-flight: *"the configured calendar
    list did not reach the stage"*.
  - D188-P2 (the hardcode restored) reddened the equality test.
  - D188-P8b (the value formatted into the flat-key refusal) reddened *"never the value — an RPC URL
    often carries an API key"*.
  - D188-P9 (deduplication removed) reddened its test.
- **Deviations.**
  - `[verify.devnet]` is refused whatever key it holds, which is a second line of defence.
  - The shared URL shape refusal now names its entry for `tsa_urls`, `ots_calendars` and
    `bitcoin_endpoints`.
  - Two of this record's planned plant claims could not hold as planned:
    - P4 cannot redden a struct-literal test, so test 7 now parses config text.
    - The one-network form of P5 cannot redden 10b, so P5b (the lookup dropped) was added.
- **At the lane's close.**
  - `cargo test -p antseal-cli`: lib 307 passed; `config_file` 25, `anchor_stage` 14,
    `upgrade_hook` 12.
  - `cargo test -p antseal-anchor --lib`: 213 passed, 1 ignored.
  - `clippy -D warnings` on both crates: exit 0.
- **Rows minted from the lane's findings.**
  - `U99`: a URL refused for carrying userinfo prints that userinfo.
  - `U100`: a misplaced `rpc_endpoints` only warns.
  - `U101`: `bitcoin_endpoints`' check stays at use. §4 left that unowned; the row owns it now.
- **The orchestrator's acts.** `U44`'s Accept 4 and 5 are restated per §2 R5 and §2 R7, and the U4 execution note's item 4 is amended. `A94` is annotated per §2 R9. `U44`, `U52` and `U64` are ticked.

## Closing — this record is not consent

It adds config keys, retires one, and moves one validation from use to load,
inside the wave's own commits. Nothing in it authorises a push, a workflow
dispatch, a deploy or any other outward act; each of those needs the
maintainer's express consent naming the action, the destination and the
account.

## Addendum — 2026-10-19 (wave 39, D195 §2 R4; D196 §2 R1–R3): no config refusal repeats a URL, a known key outside its table is refused, and the Bitcoin pair is checked at load

Four parts of this record change. D195 and D196 record each.

1. **§2 R1's last sentence is amended (D195 §2 R4).** It reads *"An invalid entry is exit 17,
   naming the key, the line and the entry. Calendar URLs carry no credentials, so the `tsa_urls`
   echo convention stands"* (`:246-247`). The echo convention is retired: a refusal of any
   URL-list key — `tsa_urls`, `ots_calendars`, `bitcoin_endpoints`, `rpc_endpoints` — names the
   key, the line and the entry's position (`entry N`), never the value. The ground did not
   survive measurement: whatever a calendar URL is meant to carry, the value a user typed can
   carry userinfo, and 9 credential-bearing shapes driven through the binary were each refused
   with the canary on stderr and in `--json`'s `error.message`, through three paths — the parse
   check, the URL shape check that §6's second deviation introduced (*"The shared URL shape
   refusal now names its entry"*), and the config subset's own value error (D195 §1.4). The test
   written under this record that asserts the echo (`tests/config_file.rs:339-343`, *"names the
   entry (a calendar URL is no credential)"*) flips to `entry 1`. What stays is `A20`'s verbatim
   printing of the TSA and calendar URLs a seal contacted — in the seal report, a gate abort and
   `--json` — now with a documented rule that none of them may carry a credential (D195 §2 R3).
2. **§2 R5's ground is extended to every recognised key (D196 §2 R1, R2).** §2 R5 refused the
   flat `arbitrum_endpoints` because *"a warned override probes the very endpoints the user
   configured away from"* (`:295-297`). D196 measured the same harm beyond that one key: 10
   misplacements of 6 of the 7 live keys and of the retired one all only warned (the seventh
   reaches the same warning arms by code reading), and a `default_network` written after an
   `[anchors]` header silently made the invocation `arbitrum-one` (D196 §1.1). A known key in
   any table but its home is now exit 17, raised on the key before its value is parsed, naming
   the key, the table it was found in, the line and its home. §2 R5's refusal of the flat key is
   unchanged; `arbitrum_endpoints` under
   `[verify.<network>]`, which a test written under this record pins as *"an ordinary unknown
   key"* (`tests/config_file.rs:610-614`), is now refused too, with *"write `rpc_endpoints` in
   this table instead"*. Unknown keys still warn on the key alone (D189 §2 R3).
3. **§2 R4's last bullet and §4's `bitcoin_endpoints` bullet are overturned (D196 §2 R3).** §2
   R4 reads *"`[verify] bitcoin_endpoints` stays flat and is checked at use, as today (§1.6 names
   the test that depends on it loading)"* (`:283-284`), and §4 *"It stays at use; the
   inconsistency with `rpc_endpoints` is recorded, not fixed (§1.6)"* (`:427-428`). Their only
   ground was §1.6's test vehicle (`:179-180`). D196 found two vehicles, not one — a second test
   also needs a one-entry list to load and goes vacuous once the count moves
   (`tests/config_file.rs:271-276`) — and moves the hook's property in-process. The key stays
   flat; its count and origins are checked at load by one validator that `verify --online`,
   `status --upgrade` and the hook call too, and a bad list is exit 17 on every command, naming
   the key, `[verify]`, the line, and `found {n}` or the entry's position. (This wave's rulings
   call this bullet "§4's second"; it is the third, after `A94`'s and `U98`'s.)
4. **§4's `U98` bullet (`:417-426`) is answered by D195.** `verify --online` discloses each
   `[verify]` endpoint by its origin only — `scheme://host`, plus a port only when it is not the
   scheme's default — on its `endpoints:` line, its failure lines and in `--json`, and every
   `[verify]` refusal is value-free. Its deadline is `U32`, not `Q31`: the overlay is D65 tier C.

The rest of this record stands. The text above stays as written.
