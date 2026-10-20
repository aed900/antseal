# D196 — A config key this build knows is a **malformed config outside its home table**, and `[verify] bitcoin_endpoints` is **checked when the file is read**: one `KEY_HOMES` table refuses a misplaced known key at load (exit 17, never its value), unknown keys still only warn, and the Bitcoin pair takes one validator at load and at use

- **Status: RESOLVED. H10, for `U100`, and H11, for `U101`, both fared (b): each direction
  survived and a premise of each fell.**
  - **H10 — *refuse a misplaced `rpc_endpoints` by name at load (exit 17), mirroring D188 R5's
    refusal of the retired flat key*.** (b):
    - **The direction survives:** refuse at load, exit 17, by name, never the value.
    - **The premise falls.** The row reads *"The same harm sits one key over"*
      (`tasks/U.md:1456`). It sits under every key this build knows: P2's probe misplaced 6 of
      the 7 live keys and the retired `arbitrum_endpoints` in 10 cases, and all 10 only warn;
      the seventh key, `ots_calendars`, reaches the same warning arms by code reading (§1.1).
      The worst is not an RPC pair at all: `default_network = "arbitrum-sepolia"` written after
      an `[anchors]` header silently makes the invocation `arbitrum-one`.
    - **The forward-compatibility rule is not in the way.** It governs **unknown** keys (U4,
      D189 §2 R3); four rulings already refuse a known key in the wrong place (§1.2).
  - **H11 — *move `bitcoin_endpoints`' count and origin check to load (exit 17), mirroring
    `rpc_endpoints`; re-vehicle the hook test*.** (b):
    - **The direction survives:** the check moves to load, through one validator.
    - **"Re-vehicle the hook test" assumed one dependent test and another spawned vehicle.**
      Two tests depend on a bad list loading, and the second goes vacuous silently
      (`config_file.rs:271-276`, §1.4). No spawned vehicle survives the move, because a config
      that loaded can no longer fail the hook's only fallible step; the property moves
      in-process (§2 R4).
    - **D188's only ground for the use-time check was that test vehicle** (§1.4), so D188 §2 R4's
      last bullet and the matching bullet of D188 §4 are overturned (§2 R3).
- **Date: 2026-10-19**
- Owner rows: **`U100`** (§2 R1, R2, R5, R6); **`U101`** (§2 R3, R4, R6).
- Related:
  - **D188** (§2 R5's ground — *"a warned override probes the very endpoints the user
    configured away from"* — extended to every recognised key; §2 R4's last bullet and §4's
    `bitcoin_endpoints` bullet overturned; takes a dated addendum);
  - **D189** §2 R3 (unknown keys warn on the key alone — unchanged; takes a dated addendum);
  - **D180** (a known key the binary cannot honour is refused, not warned, before any release
    exists), **D173** §2 R4 (`bootstrap` refused under the other two `[networks.*]` tables);
  - **D195** (this wave's other config ruling: every refusal here is value-free under its
    §2 R4; the same lane and the same files);
  - **D99** and **D202** (the opportunistic hook, whose module doc another lane edits this wave);
  - **`U4`** (the forward-compatibility rule), **`U24`** (the hook's Accept row 2),
    **`U44`**, **`A50`** (one implementation of "which URLs this build will contact"),
    **`Q16`**, **`Q31`**.

## 0. What was measured against

`HEAD` `07a170c` (= `origin/main`). The tree was clean: `git status --porcelain` printed 0
lines at both of the planning lane's checks.

Planning lane P2 (wave 39, 2026-10-19) worked read-only. Its one execution ran a private copy
of the HEAD debug binary (`antseal 0.0.0`) over 26 hand-written `config.toml` cases, each under
a fresh `HOME` and `ANTSEAL_DIR` holding only the config, with
`ANTSEAL_NO_REAL_ANCHOR_NETWORK=1` and `ANTSEAL_NO_REAL_NETWORK=1`, as `antseal --json list`,
reading the exit code from `$?` into a file. Exit 2 is that command's "no vault exists": the
config **loaded**. D195 §0 describes the same run.

Before this record was written, the records lane re-read every locator below at `07a170c`
through `git show 07a170c:<path>`, because implementing lanes were already editing these files.
Every citation held, with one refinement: the bullet of D188 §4 that keeps the Bitcoin check
at use is that section's **third** bullet (D188:427-428; the second, D188:417-426, is `U98`'s,
which D195 answers). This wave's rulings call it "§4's second bullet"; this record and the
D188 addendum name it by its text.

## 1. What was measured

### 1.1 A known key in a foreign table only warns, and the override it carried is lost

- **The seven live keys and their homes**, read from `apply()`'s match arms
  (`crates/antseal-cli/src/config.rs`): `default_network` at the top level (`:860`); `bootstrap`
  under `[networks.<id>]` (`:882`); `tsa_urls`, `ots_calendars` and `opportunistic_upgrades`
  under `[anchors]` (`:923`, `:941`, `:954`); `bitcoin_endpoints` under `[verify]` (`:974`);
  `rpc_endpoints` under `[verify.<network>]` (`:988`).
- **Every other placement falls through to one of three warnings:**
  ``config.toml line {n}: unknown key `{other}` under [networks.{network}] — ignored (newer antseal?)``
  (`:911-914`), the same under `[verify.{network}]` (`:1001-1004`), and
  ``config.toml line {n}: unknown key `{full_key}` — ignored (newer antseal?)`` (the `_` arm,
  `:1012-1015`).
- **Two retired names are refused on the key, before the value is parsed:** `rpc_url` under
  any `[networks.<id>]` (`:422-427`) and the flat `[verify] arbitrum_endpoints` (`:428-436`),
  whose text is the shape to copy: *"`arbitrum_endpoints` under [verify] is retired: the
  Arbitrum RPC pair is set per network — write `rpc_endpoints` under [verify.arbitrum-one] or
  [verify.arbitrum-sepolia] instead. Its value is not repeated here, because an RPC URL often
  carries an API key"* (`arbitrum_endpoints_refusal`, `:661-667`).
- **P2's probe: 10 misplaced known keys, 10 loads with a warning** (exit 2). The cases cover 6
  of the 7 live keys and the retired `arbitrum_endpoints`; `ots_calendars` was not probed in a
  foreign table, but by code reading it reaches the same fall-through arms. (P2's summary says
  *"12 of 12"*; its probe log holds these 10, one misspelled key — `rpc_endpoint`, which warns
  as an unknown key should — and one control.) Each misplacement silently reverts the override
  the user wrote:
  - `rpc_endpoints` under `[verify]`, under `[networks.arbitrum-one]`, at the top level or under
    `[anchors]` → the pinned Arbitrum pair is probed;
  - `bitcoin_endpoints` under `[verify.arbitrum-one]` → the pinned esplora pair;
  - `tsa_urls` under `[verify]` → `seal` contacts the built-in TSAs;
  - `opportunistic_upgrades = false` under `[verify]` → the pass still runs;
  - a top-level `bootstrap` → the built-in peers are dialled;
  - **`default_network = "arbitrum-sepolia"` written after an `[anchors]` header** (TOML puts it
    in `[anchors]`) → *"warning: config.toml line 3: unknown key `anchors.default_network` —
    ignored (newer antseal?)"*, and the `--json` envelope's `network` is **`arbitrum-one`**; the
    control at the top level gives `arbitrum-sepolia`. A user who meant the testnet gets mainnet
    as the invocation network.
  - `arbitrum_endpoints` under `[verify.arbitrum-one]` also only warns. It is the migration's
    likeliest mistake, because `docs/config.md:132` tells the user to *"move its two URLs under
    the table for the network they serve"*. A test pins that it loads, with one warning:
    *"The retirement is the flat [verify] key's: under a per-network table the name is an
    ordinary unknown key"* (`crates/antseal-cli/tests/config_file.rs:610-614`).

### 1.2 The forward-compatibility rule governs unknown keys; placement already fails closed

- **The rule's origin** is `U4`'s Accept: *"malformed config → distinct exit code; unknown keys
  warn (forward-compat) rather than crash"* (`tasks/U.md:60`). D189 §2 R3 strengthened it for
  **values**: *"Unknown keys warn on the key alone"* (D189:209-219).
- **Placement already fails closed in four rulings:** D180 (`rpc_url`; its status reads *"The
  rule that unknown keys only warn points the other way here. An older binary that cannot honour
  a future `rpc_url` should refuse it, and no release exists yet that a refusal could break"*,
  D180:19-20); D173 §2 R4 (`bootstrap` under `arbitrum-sepolia` or `devnet`, D173:226-228);
  D188 §2 R4 (`[verify.<unknown>]` and `[verify.devnet]` → 17); D188 §2 R5 (the flat
  `arbitrum_endpoints`).
- **The loader's own module doc** already states the principle: *"a recognized key the loader
  cannot honor must be loud (never a silently-dropped override)"* (`config.rs:96-98`).
- **That paragraph also overclaims.** It says `bootstrap` is a hard error *"anywhere but
  `[networks.arbitrum-one]`"* (`config.rs:99-101`). The code refuses it only inside
  `[networks.*]` (`:882-893`; elsewhere it falls to the `_` arm), as D173 §2 R4 ruled, and P2's
  probe confirms that a top-level `bootstrap` warns. `docs/config.md:22-26` states the code's
  behaviour correctly.
- **No release exists** for a refusal to break: `crates/antseal-cli/Cargo.toml:3` is
  `version = "0.0.0"`, and the repository's two tags, `format-v1-freeze` and
  `pre-trailer-strip-949dd9d`, are not releases.

### 1.3 The Bitcoin pair is checked at use, by two validators with two texts

- `verify_host.rs` `parse_pair` (`:335-358`): *"{what} must list exactly two endpoints (found
  {n}): an override replaces the pinned pair wholesale, and a must-agree pair needs two
  independent sources"*; its parse and pair errors are `{what}: {source}`, and its doc says
  *"These refusals repeat the URL"* (`:332-334`).
- `status.rs` `UpgradeConfig::pair` (`:806-825`): *"`[verify] bitcoin_endpoints` must name
  exactly two endpoints (found {n})"*; its parse and pair errors are the bare `e.to_string()`,
  which names no key.
- Both accept exactly two. Two implementations break `A50`'s rule as `config.rs:718-721` states
  it for `rpc_endpoints` (*"the load-time check AND the pair `verify --online` is built with, so
  the two cannot disagree"*).
- **P2's probe:** a list of 1, of 3, `[]`, and two URLs at one origin all **load**, with no
  warning. A bad list then:
  - fails `verify --online` with `CliError::Usage`, exit 2 (`verify_host.rs:308`);
  - fails `status --upgrade` with exit 2 **only when a pending work exists**, because
    `poll_upgrades` returns before `config.pair()?` otherwise (`status.rs:918-921`);
  - turns the opportunistic hook into a debug-level skip, *"skipped: no usable endpoint
    configuration for the upgrade pass"* (`upgrade_hook.rs:333-341`).
- No test pins either use-time refusal (P2's grep for *"exactly two endpoints"* and *"must name
  exactly two"* under `crates/antseal-cli/tests` hits only `rpc_endpoints`' own refusals).

### 1.4 D188's only ground was a test vehicle, and there are two vehicles

- **D188's words.** §1.6: *"Moving the bitcoin check to load would remove that test's only
  vehicle"* (D188:179-180). §2 R4's last bullet: *"`[verify] bitcoin_endpoints` stays flat and is
  checked at use, as today (§1.6 names the test that depends on it loading)"* (D188:283-284).
  §4: *"It stays at use; the inconsistency with `rpc_endpoints` is recorded, not fixed (§1.6)"*
  (D188:427-428). No product reason is given anywhere.
- **Vehicle 1.** `a_hook_that_cannot_start_leaves_the_command_untouched`
  (`crates/antseal-cli/tests/upgrade_hook.rs:1010`; its doc calls it *"U24 Accept row 2"*,
  `:1001`) writes `[verify]\nbitcoin_endpoints = ["https://a.example"]` (`:1019-1022`) and
  asserts the healthy exit code, byte-identical stdout, `HOOK_ARMED`, *"no usable endpoint
  configuration"* and no *"pass complete"*.
- **Vehicle 2, hidden.**
  `https_and_loopback_verify_endpoints_are_admitted_and_tsa_http_is_untouched` feeds one-entry
  lists `http://localhost:8332/` and `http://127.0.0.1.evil.example/` and asserts only
  `.expect_err(hostile)` (`config_file.rs:271-276`). Once the count is checked at load, both are
  refused **for the count**, and the test stays green even if the loopback carve-out is widened:
  an assertion that cannot fail for its stated reason (plant P101e, §3).
- **No spawned vehicle survives the move.** `HookContext::production`'s only fallible step is
  `upgrade.pair()?` (`upgrade_hook.rs:227`); with one validator at load and at use, a config
  that loaded can never fail it, so "the hook cannot start" becomes unreachable through the
  binary.
- **An in-process vehicle is buildable.** The Q16 route scan reads only `tests/`
  (`crates/antseal-cli/tests/anchor_stage.rs:1105-1108`), so a unit test in
  `src/upgrade_hook.rs` may name `HookContext::production`; `VaultSlot::arm` is `pub(crate)`
  (`upgrade_hook.rs:139`); `tracing-subscriber` is a normal dependency
  (`crates/antseal-cli/Cargo.toml:71`); and `run_after_output` is
  `pub fn run_after_output(slot: &VaultSlot, config: &Config, network: &str)`
  (`upgrade_hook.rs:318`).
- **U24 Accept row 2** reads *"hook failure (mock network error) leaves the primary command's
  exit code and output untouched"* (`tasks/U.md:443`). Its spawned observable — exit code and
  stdout unchanged, with the production hook running — is also asserted by
  `the_hook_runs_on_a_real_invocation_without_touching_stdout` (`tests/upgrade_hook.rs:957`).

## 2. RULING

### §2 R1 — One `KEY_HOMES` table: a known key outside its home is a malformed config (`U100`)

- Every key antseal knows has exactly one home:
  - the top level, before the first header: `default_network`;
  - `[networks.arbitrum-one]`: `bootstrap`;
  - `[anchors]`: `tsa_urls`, `ots_calendars`, `opportunistic_upgrades`;
  - `[verify]`: `bitcoin_endpoints`;
  - `[verify.arbitrum-one]` and `[verify.arbitrum-sepolia]`: `rpc_endpoints`.

  The lane re-derives the exact set from `apply()` (§1.1 lists it at `07a170c`).
- A **known** key written in any other table is refused at load: exit 17, class
  `malformed-config`, raised on the key **before** its value is parsed, naming the key, the
  table it was found in, the line and its home — never the value. The template, which the lane
  may tighten while every clause stays true: *"`{key}` is not read under {found}: it belongs
  {home} — move the line there. Its value is not repeated here"*, where `{home}` is *"at the top
  of the file, before the first [table] header"*, *"under [networks.arbitrum-one]"*, *"under
  [anchors]"*, *"under [verify]"* or *"under [verify.arbitrum-one] or
  [verify.arbitrum-sepolia]"*, and the top level is spelled *"the top level"* when it is the
  table found.
- The table is consulted in `apply()`'s three fall-through arms (`:904-915`, `:997-1005`,
  `:1011-1016`), just before they would warn. The `apply()` match itself is untouched, so every
  existing refusal keeps its text and its precedence.
- The `[networks.<id>]` **name** check still runs first: an unknown network stays *"is not a
  known network"*.

*Why:* a warned override quietly uses the very defaults it was written to replace, and the harm
reaches every recognised key, the invocation's network included (§1.1). Raising
on the key keeps the value out of the error by construction, as D189 §2 R3 and D188 §2 R5 do.

### §2 R2 — What does not change

- **Unknown** keys still warn on the key alone: D189 §2 R3's forward-compatibility promise is
  intact (D189 takes a dated addendum that says so).
- `bootstrap` keeps D173's own text under `[networks.arbitrum-sepolia]` and
  `[networks.devnet]`.
- `rpc_url` stays refused in every `[networks.*]` table (D180).
- `arbitrum_endpoints` is refused everywhere: flat under `[verify]` by D188 R5's refusal,
  unchanged; under `[verify.<network>]`, where it only warns today (§1.1), with its retirement
  text saying *"write `rpc_endpoints` in this table instead"*.
- `[verify.devnet]` keeps its own refusal.

*The ground* is D188 §2 R5's — *"a warned override probes the very endpoints the user
configured away from"* — extended to every recognised key. Measured: every misplacement probed
— 6 of the 7 live keys and the retired one, in 10 cases — only warns, the seventh reaches the
same arms by code reading, and a `default_network` written after an `[anchors]` header silently
makes the invocation `arbitrum-one` (§1.1). D188 takes a dated addendum.

### §2 R3 — `[verify] bitcoin_endpoints` is checked when the file is read (`U101`)

- Exactly two endpoints at two distinct origins, each under the endpoint policy the use sites
  apply today (`TlsPolicy::RequiredExceptLoopback`), checked **at load** by **one** validator
  that the use sites call too: `config.rs`, `verify_host::endpoints_from_config` and
  `status::UpgradeConfig::pair`. The two divergent texts of §1.3 collapse into one.
- A refusal is exit 17 naming the key, `[verify]`, the line, and the count found (`found {n}`)
  or the entry's position — never a value (D195 §2 R4). `[]` is refused (`found 0`): deleting
  the key restores the built-in pair, as for `bootstrap`.
- **This overturns** D188 §2 R4's last bullet (*"stays flat and is checked at use, as today"*,
  D188:283-284) and the D188 §4 bullet that keeps the check at use (D188:427-428). Their only
  ground was a test vehicle (§1.4). D188 takes a dated addendum.
- The exit **behaviour** moves: a bad list, which today loads and then fails at use with
  `usage` (2), a silent skip, or nothing at all, is now exit 17 on every command, offline
  `verify` and `restore` included, exactly as a bad `rpc_endpoints` already is
  (`docs/config.md:14`: *"A **malformed** file is a hard error on every command"*). No class is
  added; `--json`'s `error.class` moves from `usage` to `malformed-config` for such a config.
- **Widened by the orchestrator on 2026-10-19, after the planning round and before the lane
  landed it (corrected in place; the record is uncommitted):** the same validator also refuses
  an entry whose URL carries a query (`?`) or a fragment (`#`). Esplora requests append
  `/{path}` to the whole base (`esplora.rs:245-246`, `join`), so `https://h/api?key=K` would
  request `…?key=K/block-height/H` and the reparse still accepts it. The refusal names the key,
  `[verify]`, the line and the entry's position, and says why (antseal appends request paths to
  the base), never the value. It does not apply to `rpc_endpoints`: an RPC URL is used as given,
  and a query there is legitimate. One matrix row (a `?key=` entry and a `#` entry, the canary
  absent) and one plant (the check dropped reds that row by message) prove it.

*Why:* no product reason for the difference was ever recorded, and the harm of keeping it is a
silently disabled upgrade pass (§1.3). One validator also restores `A50`'s rule for this key.

### §2 R4 — The hook's property is re-vehicled in-process

- **In-process, `src/upgrade_hook.rs`:** a unit test on a struct-literal `Config` whose
  `verify_bitcoin_endpoints` is a one-entry list — which bypasses the loader by construction —
  with a fresh vault, an armed `VaultSlot` and `run_after_output` under a scoped capturing
  subscriber. It asserts that `HOOK_ARMED` and *"no usable endpoint configuration"* are traced
  and *"pass complete"* is not, and that `HookContext::production(..)` is `Err`.
- **A signature pin** beside it: `let _: fn(&VaultSlot, &Config, &str) = run_after_output;`. The
  exit-code-and-stdout half of U24 Accept row 2 stays spawned in
  `the_hook_runs_on_a_real_invocation_without_touching_stdout`; the pin makes it structural, since
  a future `-> Result` would not compile.
- **The old spawned test is replaced** by the new behaviour's spawned test: the one-entry list is
  exit 17 before the hook can arm.
- **The hidden vehicle is fixed:** `config_file.rs` (~`:272-275`) uses two-entry hostile lists
  and asserts *"must be https"*. Plant P101e proves that the old form went vacuous (§3).

*Why:* no spawned vehicle can reach the declining arm once a loaded config cannot fail `pair()`
(§1.4); the arm stays, and an in-process test is the only place left that can prove it.

### §2 R5 — The optional guard

G100-3 — every key of the full-schema fixture is in `KEY_HOMES` — is accepted only at ≤ 10
lines. Its measured yield today is **0**, and the lane's report says so.

### §2 R6 — Documents

- `docs/config.md`:
  - `:18-29`, the second half of the forward-compatibility bullet, takes P2's replacement:
    *"A key antseal knows is an error in any table where it does not live — `rpc_endpoints`
    flat under `[verify]`, `tsa_urls` under `[verify]`, or `default_network` written after a
    `[table]` header (TOML puts it in that table) — because a warned override would quietly use
    the very defaults it was written to replace. The error names the key, the table and the
    line, and where the key belongs."*, followed by P2's sentences for `bootstrap`, `rpc_url`,
    `arbitrum_endpoints` and `[verify.devnet]` (§2 R2);
  - `:120-124` and `:126-132`, the schema comment;
  - `:273-279`: the pair is checked when the file is read; anything else — one, three, an empty
    list, or two URLs at one origin — is a malformed config (exit 17) on every command; delete
    the key to use the built-in pair.
- `config.rs`'s module doc: the schema block (~`:73-84`) and the placement paragraph
  (~`:93-112`), which drops the `bootstrap` overclaim (§1.2).
- `docs/user/timestamp-authorities.md` ~`:258-260` gains *"; a known key in the wrong table is
  an error"*.

**Timing.** Before `Q31`, as both rows' `Deps` say (*"before Q31 (the first release)"*).

## 3. Fault plants

The implementing lane owes these (P2 §2, U100 (g) and U101 (g)). Green baselines come first;
each plant is judged by its **message**; every restore is followed by a `touch`; a
type-changing plant is a compile check, not a red. G100-2, G101-2 and the replaced hook test
spawn the binary and run in a shadow copy with a private `CARGO_TARGET_DIR`.

**The green tests — the load-bearing half**

1. **G100-1** (in-process, `config_file.rs`): `a_known_key_outside_its_table_is_refused_by_name`.
   Each of the 7 live keys × {the top level, `[anchors]`, `[verify]`, `[verify.arbitrum-one]`,
   `[networks.arbitrum-one]`, `[future]`}, minus its home; `bootstrap` under
   `[networks.arbitrum-sepolia]` or `[networks.devnet]` keeps D173's text and is excluded;
   `[verify.devnet]` stays the devnet refusal; plus `arbitrum_endpoints` under both
   `[verify.<network>]` tables. The case count is asserted before the loop. Each case: an
   error on the right line whose detail names the key, the table found and the home, and no
   canary. Controls: the full-schema fixture still loads with zero warnings, and the existing
   unknown-key tests keep their counts — 8 (`config_file.rs:744`), 3 (`:865`) and 1 (`:416`).
2. **G100-2** (spawned): `a_misplaced_rpc_endpoints_is_exit_17_before_any_command_runs`.
   `[verify]` / `rpc_endpoints = [canary URLs]` makes `--json verify b.sealproof` exit 17, the
   message names `rpc_endpoints`, `[verify]`, `[verify.arbitrum-one]` and `config.toml:2`, and the
   canary is on neither stream. Control: the same line under `[verify.arbitrum-one]` reaches exit
   4. Second case: `default_network = "arbitrum-sepolia"` after an `[anchors]` header is 17,
   never a silent `arbitrum-one`.
3. **G100-3** (optional, §2 R5): every key of the full-schema fixture is in `KEY_HOMES`.
4. **G101-1** (in-process): `bitcoin_endpoints_is_exactly_two_distinct_origins_at_load`. Lists
   of 0, 1 and 3 entries (each naming `found {n}`); `https://a.example/x` with
   `https://A.example:443/y` (one origin); a userinfo canary as entry 1 (D195 §2 R4). Each: an
   error on line 2 naming `bitcoin_endpoints` and `[verify]`, with no canary. Two distinct https
   entries load.
5. **G101-2** (spawned): `a_bad_bitcoin_pair_is_exit_17_before_any_command_runs`. A one-entry
   list makes `--json verify b.sealproof` exit 17 with class `malformed-config`, `config.toml:2`
   and `found 1`; control: two entries reach exit 4. And `--json list` with
   `RUST_LOG=antseal_cli::upgrade_hook=debug` is 17 with no `HOOK_ARMED`: no vault was ever
   unlocked. This test replaces `a_hook_that_cannot_start_leaves_the_command_untouched`.
6. **G101-3** (unit, `src/upgrade_hook.rs`):
   `a_hook_whose_endpoints_are_unusable_declines_without_a_pass`, and the signature pin (§2 R4).
7. **G101-4:** the hidden vehicle (`config_file.rs` ~`:272-275`) as two-entry hostile lists
   asserting *"must be https"*.
8. **Flipped, deliberately:** the tail of `the_flat_arbitrum_endpoints_key_is_refused_by_name`
   (`config_file.rs:610-614`) — `[verify.arbitrum-one] arbitrum_endpoints` is now 17 naming
   `rpc_endpoints`.
9. **Unchanged and still green:** `the_hook_runs_on_a_real_invocation_without_touching_stdout`
   (`tests/upgrade_hook.rs:957`, U24 Accept row 2's spawned observable) and
   `a_configured_pair_is_what_the_receipt_probe_contacts` (two-entry Bitcoin stubs).

**The plants — proof that those tests can fail**

| Plant | Must redden |
|---|---|
| P100a the misplaced-key check removed | G100-1 (*"must be refused"*); G100-2 exits 4, not 17 |
| P100b the value formatted into the refusal | the canary assertions of G100-1 and G100-2 |
| P100c `default_network` dropped from `KEY_HOMES` | only G100-1's `default_network` rows — the table is consulted per key |
| P100d unknown keys refused too (a blanket refusal) | `an_unknown_key_warns_whatever_its_value`, on its 8-warning count |
| P100e the check run before the network-name judgement | the control `[networks.ropsten]` / `rpc_endpoints = […]`, which must still say *"is not a known network"* |
| P101a the load check removed (the arm back to `expect_endpoint_array`) | G101-1 (*"one entry must be refused at load"*); G101-2 exits 4, not 17 |
| P101b the count accepts `1..=2` | only G101-1's one-entry row |
| P101c the origin check dropped | only G101-1's same-origin row |
| P101d `run_after_output` `.expect()`s the context instead of skipping | G101-3, which panics — red by its message |
| P101e `host_is_loopback_literal` admits the name `localhost` (`http/endpoint.rs:224-233`) | G101-4, on *"must be https"*; the old one-entry form stays green under this plant once the count is checked at load — the vacuity, shown |

## 4. What this record does NOT decide

- **Typed storage.** `Config` could hold a validated `EndpointPair`, making `pair()` and
  `production()` infallible and deleting the hook's `Err` arm. Not now: it retypes `Config`
  (two tests read `verify_bitcoin_endpoints` as a `Vec`) and breaks the symmetry with
  `rpc_endpoints`' `Vec<String>` storage. It is the follow-on if the unreachable arm is judged
  dead weight.
- **`rpc_url` outside `[networks.*]`.** Whether it enters `KEY_HOMES` is the lane's choice (P2
  listed it as optional); D180's refusal in every `[networks.*]` table is unchanged either way.
- **A later build that gives a known key a second home.** This build would refuse such a file
  with exit 17, naming the key and its home here. That is the cost D180 accepted for `rpc_url`,
  taken before any release exists (§1.2); any such move needs its own record.
- **A growing second pin.** Every future config key must now also enter `KEY_HOMES`, beside
  `apply()`'s arms, the schema blocks (`config.rs:17-91`, `docs/config.md:56-136`),
  `full_schema_parses_with_every_slot`, `exported_config_survives_import_and_resolves` and the
  prose of `docs/config.md:18-29`. G100-3 is the optional guard, at a measured yield of 0.
- **An esplora base carrying a query or a fragment** is no longer open: the orchestrator folded
  it into §2 R3 on 2026-10-19 (see the widened bullet there). P2 measured the mechanism in code
  only, not through a request, and the known affected configs number 0; refusing it at load
  costs about two lines and one matrix row.
- **No row is minted by this record.**

## 5. Edit list — per write scope, with the lane named before this record was written

### L-CFG2 (round 1) — D195's `U99`, then `U101`, then `U100`, then D195's `U98`, in one lane

- `crates/antseal-cli/src/config.rs`: `KEY_HOMES` and a refusal helper beside the existing key
  refusals (~`:636-698`); `apply()`'s three fall-through arms (~`:904-915`, ~`:997-1005`,
  ~`:1011-1016`); the Bitcoin arm (~`:962-980`) through the one pair validator, beside
  `rpc_endpoint_pair` (~`:718-770`); the module doc (~`:73-84`, ~`:93-112`).
- `crates/antseal-cli/src/verify_host.rs` — **only** `endpoints_from_config`, `parse_pair` and
  their docs (~`:267-358`): the Bitcoin half calls the config validator; `parse_pair` stays for
  the pinned pairs, its doc amended.
- `crates/antseal-cli/src/status.rs` — **only** `UpgradeConfig::pair` (~`:799-825`), which
  delegates to the validator.
- `crates/antseal-cli/src/upgrade_hook.rs` — **only** `HookContext::production`'s `# Errors`
  doc (~`:213-218`), and G101-3 with the signature pin appended at the end of `mod tests`.
- Tests: `crates/antseal-cli/tests/config_file.rs` (G100-1, G100-2, G100-3 if taken, G101-1,
  G101-2, G101-4, and the flip at ~`:610-614`); `crates/antseal-cli/tests/upgrade_hook.rs`
  (~`:1001-1050`, the doc and the test that G101-2 replaces).
- `docs/config.md` (§2 R6); `docs/user/timestamp-authorities.md` — **only** the ~`:258-260`
  clause (and D195's §4 sentence). Its `path:line` citations are `L-LOC`'s.
- Spawned tests run in a shadow copy with a private `CARGO_TARGET_DIR` and `CARGO_BUILD_JOBS=1`;
  in-process tests in the shared target under the lock protocol.
- Not touched by this lane: `backend.rs`, `commands.rs`, `error.rs`, `seal_run.rs`,
  `antseal-core`, and any `antseal-anchor` file other than D195's `http/endpoint.rs`.
- Neither the storage and payment path nor `commands.rs` moves, so this record forces neither
  the heavy tier nor the devnet E2E.

### L-ANCHOR2 (round 1) — the same file, another hunk

- `crates/antseal-cli/src/upgrade_hook.rs`'s module doc (~`:54-63`) belongs to D202, not to
  this record.

### L-LOC (round 3, after the last code edit)

- The living docs' `path:line` citations into `config.rs`, `verify_host.rs`, `status.rs` and
  `docs/config.md`, re-pointed by meaning. An insertion at the head of `docs/config.md` shifts
  most of the living citations into that file (PS's citation map).

### RECORDS-A — dated addenda

- D188, one addendum with D195's: §2 R5's ground extended to every recognised key (§2 R2); §2
  R4's last bullet and the §4 bullet that keeps the Bitcoin check at use overturned (§2 R3).
- D189: §2 R3's promise for **unknown** keys stands, while a **known** key in the wrong table
  becomes an error (§2 R1, R2).

### Orchestrator — `TODO.md`, `tasks/U.md`, `docs/decisions/README.md`, `docs/instrument-ledger.md`

- `U100` and `U101` ticked when the lane's greens and plants are in its report.
- This record's index row and register row.
- P2's instrument findings: D188 §2 R4 rested a product behaviour on a test vehicle alone, and
  D188 §1.6 counted one dependent test where there are two.

## 6. As built — wave 39, lane L-CFG2 (recorded in place before this record was first committed)

The lane that landed D195 landed this record too, `U101` before `U100`, with every run and plant
in a shadow copy and a private `CARGO_TARGET_DIR`; no plant touched the tree. The verdicts are
the lane's, quoted with the exit codes its report gives. The code facts were re-read in the tree,
where `config.rs`, `config_file.rs`, `status.rs`, both `upgrade_hook.rs` files and
`docs/config.md` still hash as the report lists.

- **§2 R1 (`U100`).** `KEY_HOMES` (`crates/antseal-cli/src/config.rs:755-764`) holds §2 R1's
  seven live keys, re-derived from `apply()`, and the retired `arbitrum_endpoints`.
  `misplaced_key_refusal` (`:773`) returns `None` for an unknown key, which then warns. It runs
  only in the three fall-through arms (`:1104`, `:1203`, `:1219`), after each table's network name
  is judged and before the value is parsed. The template (`:801-802`) is §2 R1's.
  - **Deviation: the found-table spelling** (the lane's deviation 7). *"is not read under the top
    level"* would be wrong, so `{found}` carries its own preposition: *"at the top level"* or
    *"under [{table}]"*.
- **§2 R2.** Unknown keys still warn on the key alone. `bootstrap` keeps D173's text and
  `[verify.devnet]` its refusal. `rpc_url` is still refused in every `[networks.*]` table and only
  warned on elsewhere.
  - **The lane read *"refused everywhere"* literally** (its deviation 8). `arbitrum_endpoints` is
    now refused in every table: under `[verify.<network>]` with *"write `rpc_endpoints` in this
    table instead"*, and elsewhere with a text naming both per-network tables (`:794-796`). The
    flat `[verify]` refusal is byte-identical to `HEAD`'s (`:687-690`). If only the two
    `[verify…]` tables were meant, the undo is the generic text and 4 of G100-1's rows.
- **§2 R3 (`U101`).** One validator, `bitcoin_endpoint_pair` (`config.rs:895`), has three callers:
  the load arm (`:1179`), `verify_host::endpoints_from_config` (`verify_host.rs:333`) and
  `status::UpgradeConfig::pair` (`status.rs:812`). The pinned default still goes through
  `parse_pair` (`verify_host.rs:340`). The count refusal reads *"`bitcoin_endpoints` under
  [verify] must list exactly two endpoints (found {n}): …"*, and no refusal carries a URL.
  - **Deviation: one shared rule set, and the shape check first at load** (deviation 5). Both
    `[verify]` validators delegate to a private `must_agree_pair` (`:917`), with the
    `rpc_endpoints` texts byte-identical. The Bitcoin arm keeps `expect_url_array`'s shape check
    ahead of the validator (`:1178`), as `tsa_urls` has it.
  - **The orchestrator's widening** (`:902-907`). After the shared rules, an entry holding `?` or
    `#` is refused: *"… entry {i} carries a query or a fragment (`?` or `#`), and antseal appends
    request paths to it, so every request would lose its path; …"*. It does not apply to
    `rpc_endpoints`. The lane measured the mechanism: esplora's `join` appends `/{path}` to the
    base, and http 1.5.0's URI parser drops everything after `#`. **Deviation: two matrix rows,
    not one** (deviation 6), one per delimiter.
  - **Deviation: an edit outside the named region** (deviation 4). The delegation left `Endpoint`
    and `TlsPolicy` unused in `status.rs`, which is red under `-D warnings`, so `status.rs:80`
    became `use antseal_anchor::http::{HttpClient, HttpPolicy};`. No other lane owned the file.
- **§2 R4.** G101-3 (`src/upgrade_hook.rs:602`) opens with the signature pin (`:603`), runs
  `run_after_output` under a thread-scoped `DEBUG` capture (`traced`, `:656`), and asserts what
  §2 R4 rules, plus that the slot is emptied.
  - §3's G101-2 became two spawned tests. The `verify` half is at `tests/config_file.rs:1744`.
    The hook half, `a_bitcoin_pair_the_hook_cannot_use_is_exit_17_before_it_can_arm`
    (`tests/upgrade_hook.rs:1017`), replaces the old test.
  - The hook half adds a healthy control on the same vault: `--json --passphrase-fd 0 list` → 0,
    and armed. The broken config is 17, naming `config.toml:2` and `found 1`, with neither
    `HOOK_ARMED` nor `HOOK_NOT_ARMED` on stderr.
  - G101-4 (`config_file.rs:284`) fixes the hidden vehicle.
  - The old test's name survives in `tasks/U.md:1468`, which the orchestrator owns, and in D188
    §1.6.
- **§2 R5.** G100-3 (`config_file.rs:2057`) is accepted, with an 8-line body. **Its measured
  yield today is 0.** It hoisted the full-schema fixture into `const FULL_SCHEMA` (`:121`)
  (deviation 11).
- **§2 R6.** `docs/config.md:25-36` states the rule: *"**A key of the schema below is an error in
  any table where it does not live** — … The error names the key, the table, the line and where
  the key belongs, and never its value."* The sentences for `bootstrap`, `rpc_url`,
  `arbitrum_endpoints` and `[verify.devnet]` follow it.
  - **Deviation, not in the lane's list:** *"A key of the schema below"* replaces P2's *"A key
    antseal knows"*, and the report gives no reason.
  - `:289-297` says the pair is *"checked when the file is read"*, and that *"an esplora
    provider that wants a key must take it in the path."* The schema comment is at `:132-135`.
  - The module doc's `bootstrap` overclaim (*"anywhere but"*, `HEAD`'s `config.rs:99`) is gone.
  - `docs/user/timestamp-authorities.md:261-262` gains *"a known key in the wrong table is an
    error"*.
- **§3, the greens.**
  - **Deviation: G100-1 has 41 cases, not 37** (deviation 9). That is 7 live keys × 5 foreign
    tables, plus `arbitrum_endpoints` in 6, asserted at `config_file.rs:1873-1877`.
    - Each value is an inline table holding the canary, which lies outside the subset, so a
      refusal that read the value would fail differently.
    - It collects every failing case.
    - It gained two controls: one for order (`[networks.ropsten]` and `[verify.ropsten]` keep
      *"is not a known network"*), and one for unknown keys (`future_knob` in 6 tables, 6
      warnings).
  - G100-2 (`:1975`) also covers §1's worst case: `default_network` after `[anchors]` is 17, at
    `config.toml:3`, and its control at the top reaches 4 on `arbitrum-sepolia`.
  - G101-1 (`:1656`) asserts its 8 cases (`:1705`). The flip is at `:638`.
- **Red baselines.**
  - U101: G101-1 failed on *"no entries: must be refused at load, got Some([])"*. G101-2 and the
    hook test exited 4 and 0, not 17.
  - U100: `0 passed; 4 failed`. G100-1 failed on *"`default_network` under [anchors] must be
    refused, not warned on: …"*.
- **Plants, every one red by message.** Each compiled, and each restore was `cp` plus `touch`,
  with the sha256 matched.
  - Run against the collecting G100-1:
    - **P100a:** *"41 of 41 cases failed:"*.
    - **P100b:** *"26 of 41 cases failed:"* — exactly the rows through `apply()`'s `_` arm,
      each on *"the refusal must not carry the value"*; G100-2 failed as well.
    - **P100c:** *"5 of 41 cases failed:"* — exactly the `default_network` rows, so the table is
      consulted per key.
  - **P100d** reddened `an_unknown_key_warns_whatever_its_value` at its `expect`, before its
    8-warning count: *"an unknown key never fails on its value: … is not a key this build
    reads"*.
  - **P100e** reddened the order control: *"the table is judged before the key"*.
  - **P101a** reddened G101-1, and G101-2 exited 4.
  - **P101b, P101c and P101f** each reddened only their own G101-1 row. They were planted as:
    - the load check skipped for a one-entry list;
    - the origin refusal swallowed;
    - the widening dropped.
  - **P101d** made G101-3 panic on *"the hook context: Usage { message: "`bitcoin_endpoints`
    under [verify] must list exactly two endpoints (found 1): …" }"*, which is value-free.
  - **P101e** was run twice. With the old one-entry vehicle restored, it stayed green (`1
    passed`): P2's vacuity, measured. With G101-4 in place, it went red.
- **Found (instrument findings; no row).**
  - A stop-at-first-failure matrix cannot show a per-key property. P100a and P100c first failed
    G100-1 with byte-identical messages, hence the collecting rewrite.
  - §3's P100e had no detecting test until the order control was added.
  - A snapshot keyed by basename keeps only one of the two `upgrade_hook.rs` files.
- **Proposed, unnumbered, not minted this wave.**
  - Refuse `rpc_url` outside `[networks.*]`; §4 left this to the lane.
  - §4's typed storage.
- **At the lane's close (shadow).**
  - `--test config_file`: 32 passed. `--test upgrade_hook`: 12 passed.
  - `antseal-cli --lib`: 322 passed, G101-3 among them.
  - Clippy is in D195 §6.
  - In the shared tree, G101-3 and the 25 in-process `config_file` tests passed.
- **Rows.** `U100` and `U101` are still open in `TODO.md` at this writing; the orchestrator ticks
  them (§5).

## Closing — this record is not consent

It turns a class of config warnings into refusals and moves one validation from use to load,
inside the wave's own commits. Nothing in it authorises a push, a workflow dispatch, a deploy or
any other outward act; each of those needs the maintainer's express consent naming the action,
the destination and the account.

## Addendum — 2026-10-20 (wave 40, D207 §2 R5): `rpc_url` outside `[networks.*]` enters `KEY_HOMES`, with words of its own

§4 left this open — *"**`rpc_url` outside `[networks.*]`.** Whether it enters `KEY_HOMES` is
the lane's choice (P2 listed it as optional); D180's refusal in every `[networks.*]` table is
unchanged either way"* (`:374-375`) — and §6 listed *"Refuse `rpc_url` outside `[networks.*]`;
§4 left this to the lane"* among the lane's unnumbered proposals (`:553`). The lane did not take
it, and the register now carries it as `U107` (`TODO.md:1102`). **D207 (`U107`) answers both.**

- **Measured first, at `6e1cab3`:** `rpc_url` written at the top level or under `[verify]`,
  `[verify.arbitrum-one]`, `[verify.arbitrum-sepolia]` or `[anchors]` only warned (exit 4 on
  `--json verify`), and of the 9 names the loader has ever matched it was the only one that still
  warned anywhere (D207 §1.1, §1.3).
- **`rpc_url` enters `KEY_HOMES`**, through a new `Home` variant: a malformed config (exit 17)
  in every table, raised on the key before the value is parsed, never repeating the value.
- **Its words are not `arbitrum_endpoints`' retired text.** That redirect (*"the Arbitrum RPC
  pair is set per network — write `rpc_endpoints` … instead"*) is right for a key that was a
  receipt pair, and false for a payment-RPC user outside `[verify.<net>]`: antseal reads no
  payment-RPC override at all. D207's two texts say both facts — no payment-RPC override, and the
  receipt check's pair is `rpc_endpoints` — and under `[verify.<net>]` they say *"in this table"*,
  as §2 R2 does for `arbitrum_endpoints`.
- **§2 R2's *"`rpc_url` stays refused in every `[networks.*]` table (D180)"* holds unchanged.**
  D180's check in `config::parse` still runs first, with its own text, and its two pinned tests
  stay green.
- **One sentence of this record's code becomes false and is rewritten by D207's lane:** the
  `KEY_HOMES` doc's *"and `rpc_url` keeps its own refusal in `[networks.*]` only (D180)"*
  (`crates/antseal-cli/src/config.rs:753-754` at `6e1cab3`), with the module doc and
  `docs/config.md`'s three `rpc_url` passages (D207 §2 R3).
- **G100-3 does not move:** `rpc_url` is a retired name, not a key of the full schema, so its
  count of 8 stands. §2 R1's ground — *"a warned override quietly uses the very defaults it was
  written to replace"* — now reaches every name the loader has ever matched.

The rest of this record stands. The text above stays as written.
