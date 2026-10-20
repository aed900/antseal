# D207 — A retired `rpc_url` is **refused in every table**, in words that name **the absent payment override and the receipt pair**: one `KEY_HOMES` row and a new `Home` arm refuse it at load (exit 17, on the key, never its value), and D180's `[networks.*]` refusal keeps its own text

- **Status: RESOLVED. H8, for `U107`, fared (b): its direction survived and its premise that
  the existing retired-key text fits fell.**
  - **H8** — *"refuse rpc_url in every table with the retired-key text, value-free, exit 17 —
    one KEY_HOMES-style row."* (b):
    - **The direction survives whole:** a refusal in every table, at load, exit 17, raised on
      the key before its value is parsed, through one `KEY_HOMES` row. Executed at `HEAD`, five
      placements only warn (§1.1), and `rpc_url` is the only one of the 9 names the loader has
      ever matched that still warns anywhere (§1.3).
    - **The premise falls: the existing retired-key text misdirects a payment-RPC user.** The
      one retired text `KEY_HOMES` has is `Home::RetiredIntoRpcEndpoints`'s: *"the Arbitrum RPC
      pair is set per network — write `rpc_endpoints` {instead} instead"*
      (`crates/antseal-cli/src/config.rs:794-796`). That is true of `arbitrum_endpoints`, which
      was a receipt pair. `rpc_url` was the **payment** slot (`U4`, D180): antseal reads no
      payment-RPC override at all, and `rpc_endpoints` configures only the receipt check's pair
      (§1.2). A text true in every table must say both facts, and that takes a new `Home`
      variant (§2 R1, R2).
    - **The row's other branch, "record why not", has no ground.** D189 §2 R3 protects
      **unknown** keys; `rpc_url` is known and retired, and D180's own reasoning points to a
      refusal (§1.2).
- **Date: 2026-10-20**
- Owner row: **`U107`** (§2 R1–R5). This record mints no row.
- Related:
  - **D180** (`U94`: `rpc_url` under any `[networks.<id>]` is a malformed config; that refusal
    and its text are unchanged; takes a dated addendum on its scope);
  - **D196** (`U100`: `KEY_HOMES`; its §4 left `rpc_url` outside `[networks.*]` to the lane, and
    its §6 proposed it unnumbered; takes a dated addendum);
  - **D188** §2 R5 (the retired flat `arbitrum_endpoints`, whose refusal is the shape followed
    here) and **D189** §2 R3 (unknown keys warn on the key alone — unchanged);
  - **D195** (value-free config refusals; its §2 R4 rules `U108`, which the same lane lands this
    wave without a record of its own, and D195 takes a dated addendum for it);
  - **D205** (`U105`, whose `docs/config.md` clause the same lane writes);
  - **`U4`** (the reserved slot and the forward-compatibility rule) and **`Q31`** (the first
    release, before which a config acceptance may still tighten, D180 §4).

## 0. What was measured against

`HEAD` `6e1cab3` (local `main`, one records commit ahead of `origin/main` `ab640ae`). The tree
was clean: `git status --porcelain` printed 0 lines at the start and at the end of the planning
lane's round.

Planning lane P2 (wave 40, 2026-10-20) worked read-only. For `U107` it executed a byte-for-byte
copy of the `HEAD` debug binary (newer than every file under `crates/`) over ten hand-written
`config.toml` cases, each under `env -i` with its own `ANTSEAL_DIR` and `HOME`, as
`antseal --json verify <a missing bundle>` — a command that needs no vault and loads the config
at dispatch. Exit 4 is that command's missing bundle, so exit 4 means the config **loaded**.
Each case carried the canary `CANARYU107KEY` in its value.

Before this record was written, the records lane re-read the load-bearing locators through
`git show 6e1cab3:<path>`, because round-1 lanes were editing the tree, and re-ran P2's class
sweep (§1.3). Every claim held. Four statements are made more exactly here:
- P2 sends every other placement to `apply`'s *"three fall-through arms"*; `rpc_url` can reach
  only two of them, because the `[networks.<id>]` arm never sees it (`config.rs:1100`, §1.1).
- `docs/config.md`'s *"antseal has no payment-RPC override."* is `:241`; P2's `:240` is the
  blank line under the heading *"The payment RPC"* (`:239`).
- The receipt pair's bullet is `docs/config.md:298-306`; P2's `:293-301` begins in the
  `bitcoin_endpoints` bullet before it.
- The retired-key arm of `misplaced_key_refusal` is `config.rs:786-798`, its text `:794-796`.

## 1. What was measured

### 1.1 Outside `[networks.*]`, `rpc_url` only warns — executed

- **The only `rpc_url` refusal is in `parse`** (`crates/antseal-cli/src/config.rs:437-445`):
  `if let [family, network_name] = section.as_slice() && family == "networks" && key ==
  "rpc_url" { return Err(err(rpc_url_refusal(network_name))); }`, under the comment
  *"U94 (D180): refused on the KEY, before the value is parsed"*.
- **Every other placement reaches one of `apply`'s fall-through arms:**
  `(["verify", network_name], other)` (`:1198-1210`) or `_` (`:1218-1226`). Each asks
  `misplaced_key_refusal` (`:773`), whose first statement is
  `KEY_HOMES.iter().find(|(known, _)| *known == key)?` (`:774`). `rpc_url` is not in the table,
  so the answer is `None` and the arm pushes a warning. The third fall-through arm,
  `(["networks", network_name], other)` (`:1096-1111`), never sees the key: *"`rpc_url` never
  arrives here: `parse` refuses it on its key"* (`:1100`).
- **Executed (P2, ten cases, the value `"https://rpc.example/v2/CANARYU107KEY"`):**

  | placement | exit | what the user sees |
  |---|---|---|
  | top level | 4 | ``warning: config.toml line 1: unknown key `rpc_url` — ignored (newer antseal?)`` |
  | `[verify.arbitrum-one]` | 4 | the same warning, *"under [verify.arbitrum-one]"* |
  | `[verify.arbitrum-sepolia]` | 4 | the same warning, *"under [verify.arbitrum-sepolia]"* |
  | `[verify]` | 4 | *"unknown key `verify.rpc_url` — ignored (newer antseal?)"* |
  | `[anchors]` | 4 | *"unknown key `anchors.rpc_url` — ignored (newer antseal?)"* |
  | `[networks.arbitrum-one]`, `[networks.devnet]` | **17** | D180's text (§1.2) |
  | top-level `arbitrum_endpoints` (D196's precedent) | **17** | *"`arbitrum_endpoints` at the top level is retired: the Arbitrum RPC pair is set per network — …"* |
  | flat `[verify] rpc_endpoints` (D196's precedent) | **17** | *"`rpc_endpoints` is not read under [verify]: it belongs under [verify.arbitrum-one] or [verify.arbitrum-sepolia] — …"* |
  | control: `[verify.arbitrum-one] future_knob` | 4 | a warning, as for `rpc_url` |

  The canary was absent from both streams in all ten cases: today's warnings and refusals are
  value-free. The `[verify.arbitrum-one]` row is the row's own example, *"a plausible guess for
  the receipt RPC"* (`TODO.md:1102`): the run warns once and then probes the pinned pair.
- **It is deliberate today, and no record forbids the change.** The `KEY_HOMES` doc ends
  *"Unknown keys still warn (D189 R3's forward-compatibility promise), and `rpc_url` keeps its
  own refusal in `[networks.*]` only (D180)"* (`config.rs:753-754`). D196 §4 left it open:
  *"Whether it enters `KEY_HOMES` is the lane's choice (P2 listed it as optional); D180's refusal
  in every `[networks.*]` table is unchanged either way"* (D196:374-375). D196 §6 listed it among
  the lane's proposals, unnumbered: *"Refuse `rpc_url` outside `[networks.*]`; §4 left this to
  the lane"* (D196:553).

### 1.2 `rpc_url` has no current home, and the receipt check's RPC is a pair

- **No payment-RPC override exists.** `docs/config.md:241`: *"antseal has no payment-RPC
  override."* The retired slot's history, `config.rs:639-641`: *"U4 reserved it as a payment-RPC
  override slot for S6, and no build ever read it"*. D180's refusal says so in its own words
  (`config.rs:665-669`): *"`rpc_url` under [networks.{id}] is refused: antseal reads no
  payment-RPC override — arbitrum-one and arbitrum-sepolia pay through their pinned public RPC
  endpoints, and devnet through the RPC_URL of the export ANTSEAL_DEVNET_ENV names. Delete the
  line; …"*.
- **The receipt check's RPC is a pair, set per network.** `docs/config.md:298-306`:
  `[verify.arbitrum-one] rpc_endpoints` and `[verify.arbitrum-sepolia] rpc_endpoints` are *"the
  Arbitrum RPC pair a payment receipt is confirmed against, one pair per network … Each must name
  exactly two endpoints at different origins"*.
- **So the generic retired text is false outside `[verify.<net>]`.** Reused for `rpc_url` at
  the top level, `config.rs:794-796` would read *"`rpc_url` at the top level is retired: the
  Arbitrum RPC pair is set per network — write `rpc_endpoints` under [verify.arbitrum-one] or
  [verify.arbitrum-sepolia] instead"*. That tells a user who wanted a payment RPC that
  `rpc_endpoints` replaces it; it configures only `verify --online`'s receipt pair, and takes two
  endpoints. Under `[verify.<net>]` — the receipt-RPC guess — the redirect is the right one.
- **D180's ground points to a refusal.** D180:19-20: *"The rule that unknown keys only warn
  points the other way here. An older binary that cannot honour a future `rpc_url` should refuse
  it, and no release exists yet that a refusal could break."* The forward-compatibility rule
  governs **unknown** keys (`U4`'s Accept; D189 §2 R3; D196 §1.2), and `rpc_url` is a known,
  retired name.

### 1.3 The class: `rpc_url` is the only known name that still warns anywhere

- **Every key the loader has ever matched**, from the history of `config.rs`:
  `git log -p --follow 6e1cab3 -- crates/antseal-cli/src/config.rs | command grep -oE
  '\], "[a-z_]+"\)|\(\[\], "[a-z_]+"\)|key == "[a-z_]+"'` over 7 commits gives **9 names**:
  `arbitrum_endpoints`, `bitcoin_endpoints`, `bootstrap`, `default_network`,
  `opportunistic_upgrades`, `ots_calendars`, `rpc_endpoints`, `rpc_url`, `tsa_urls`. That is the
  8 `KEY_HOMES` rows (`config.rs:755-764`) plus `rpc_url`. The records lane re-ran the sweep at
  `6e1cab3` and got the same 9. P2's sweep of the schema lines (`docs/config.md` and the history
  of `config.rs`) gave the same 9, and the decisions, tasks and spec carry no other config
  spelling.
- So once §2 R1 lands, every name the loader has ever matched is refused outside its home —
  `rpc_url`, which has none, in every table — and only names it has never matched still warn.

### 1.4 No green test pins the warning, and the value never reaches the refusal

- **Every `rpc_url` config key in the tests is under `[networks.*]`:**
  `crates/antseal-cli/tests/config_file.rs:832` and `:838` (`[networks.ropsten]`,
  `[networks.devnet]`), `rpc_url_is_refused_at_load_under_every_network` (`:1189`) and
  `an_rpc_url_key_is_exit_17_before_any_command_runs` (`:1271`). (`:814` reads
  `NetworkConfig`'s pinned `rpc_url` field, not a config key.) The unknown-key tests (`:756`,
  `:880`, and the control inside `:1804`) use other names. A refusal turns no green test red.
- **Value-freedom is structural.** `misplaced_key_refusal(key: &str, section: &[String]) ->
  Option<String>` (`config.rs:773`) is given the key and the table, never the value, and its
  callers raise it before the value is parsed. A plant that leaked the value would have to change
  the signature, which makes it a compile check, not a message check (§3).
- **The idiom that proves the order** is an inline-table value holding the canary
  (`config_file.rs:1805-1806`): it is outside the config subset, so a refusal that waited for the
  value would fail on the value instead, and one that repeated it would carry the canary.
- **No snapshot names `rpc_url`:** `git grep -n rpc_url 6e1cab3 --
  crates/antseal-cli/tests/snapshots/` prints 0 lines (control `ropsten`: 1). The frozen
  malformed-config exemplar is a `default_network` refusal (`cli-errors.display.txt:43-44`).

### 1.5 The exact question, and the options

- `TODO.md:1102`: *"Refuse it in every table (one `KEY_HOMES`-style row and the generic retired
  text) or record why not."* `tasks/U.md:1544` (Do): *"refuse `rpc_url` in every table with the
  retired-key text (never repeating its value), or record why it differs from
  `arbitrum_endpoints`."* `tasks/U.md:1546` (Accept): *"`rpc_url` under `[verify.arbitrum-one]`
  and at the top level is exit 17 naming the key, the table and the line, the value absent
  (canary), asserted in-process and once through the binary; or the reason is recorded where the
  key is documented."*
- P2's options:

  | option | cost | verdict |
  |---|---|---|
  | 1. a `KEY_HOMES` row reusing `Home::RetiredIntoRpcEndpoints` | one line | false for a payment-RPC user outside `[verify.<net>]` (§1.2) |
  | **2. a `KEY_HOMES` row plus a new `Home` variant whose arm says both facts** | XS: one variant, one row, one arm | **ruled** — true in every table |
  | 3. record why not | docs | nothing grounds it (§1.2) |
  | 4. fold D180's `[networks.*]` check into `KEY_HOMES` too | re-blesses `config_file.rs:1189` and `:1271` | churn for no gain; refused |

## 2. RULING

### §2 R1 — One `KEY_HOMES` row and a new `Home` arm that says both facts

- `KEY_HOMES` gains one row for `rpc_url`, mapped to a **new** `Home` variant (for example
  `RetiredPaymentRpc`; the name is the lane's). Its arm in `misplaced_key_refusal` says both
  facts — no payment-RPC override exists, and the receipt check's RPC is the `rpc_endpoints`
  pair:
  - under `[verify.arbitrum-one]` or `[verify.arbitrum-sepolia]`: *"`rpc_url` under
    [verify.<net>] is retired: antseal reads no payment-RPC override, and the receipt check takes
    a pair — write `rpc_endpoints` with two endpoint URLs in this table instead. Its value is not
    repeated here, because an RPC URL often carries an API key"*;
  - in every other table, `{found}` being *"at the top level"*, *"under [anchors]"* and so on:
    *"`rpc_url` {found} is retired: antseal reads no payment-RPC override, and the receipt
    check's pair is `rpc_endpoints` under [verify.arbitrum-one] or [verify.arbitrum-sepolia]. Its
    value is not repeated here, because an RPC URL often carries an API key"*.
- Exit 17 (`malformed-config`), raised on the key before its value is parsed. Value-freedom is
  structural: the refusal never sees the value (§1.4).
- D180's `[networks.*]` refusal is raised earlier, in `parse` (`config.rs:437-445`), and is
  unchanged: under `[networks.<id>]` the user still reads D180's text. A bare `[networks]`
  header has no network name, matches none of the `[networks.<id>]` patterns (`:440`, `:1074`,
  `:1096`) and reaches the `_` arm, so it takes the second text.

*Why:* a warned `rpc_url` is the harm D188 §2 R5 and D196 §2 R1 refuse for every other known
key — the run quietly uses the very endpoints the user configured away from (§1.1) — and D180's
own reasoning asks for a refusal before any release exists (§1.2). Each text is true where it is
printed: no table holds a payment-RPC override, and under `[verify.<net>]` the user is one key
name away from the receipt pair, so that text says *"in this table"*, as D196 §2 R2 does for
`arbitrum_endpoints`.

### §2 R2 — Refused: the generic retired text, and folding D180's check

- **Reusing `Home::RetiredIntoRpcEndpoints`** (*"the generic retired text"* of the row) is
  refused. It would tell a payment-RPC user that `rpc_endpoints` replaces the key, and outside
  `[verify.<net>]` that is false (§1.2).
- **Folding D180's `[networks.*]` check into `KEY_HOMES`** is refused: it is churn, and it would
  re-bless D180's two pinned tests (`config_file.rs:1189`, `:1271`) for no change a user can see.

### §2 R3 — The documents follow the refusal

- `docs/config.md`:
  - `:31-34` — *"the retired `rpc_url` is an error in every `[networks.*]` table"* becomes every
    table;
  - the schema comment, `~:70-73` (*"`rpc_url` under any [networks.<id>] is REFUSED when the
    file is read"*);
  - "The payment RPC", `~:248-253` (*"Earlier builds parsed `rpc_url` under `[networks.<id>]`
    and never read it … Delete the line."*).
- `crates/antseal-cli/src/config.rs`: the `KEY_HOMES` doc (`~:743-754`), whose last sentence
  (*"`rpc_url` keeps its own refusal in `[networks.*]` only (D180)"*) becomes false; and the
  module doc — the schema mirror (`~:24-31`) and the prose (`~:103-120`).
- **Unchanged and still true:** `CONTRIBUTING.md:316` and `docs/threat-model.md:944`
  (*"`rpc_url` is refused at load"*).

*Why:* each named sentence states the `[networks.*]`-only scope that §2 R1 widens; the two
unchanged ones state the refusal without a scope.

### §2 R4 — Tests: every table in process, and once through the binary

- **G107-1** `rpc_url_is_refused_in_every_table` (in process). Seven tables, the count asserted
  before the loop: the top level, `[anchors]`, `[verify]`, `[verify.arbitrum-one]`,
  `[verify.arbitrum-sepolia]`, `[future]` and `[networks]` (one component). The value is an
  inline table holding the canary, which proves that the refusal precedes the value parse. Each
  case is an `Err` on the right line whose detail contains `` `rpc_url` ``, the found spelling,
  *"no payment-RPC override"* and `` `rpc_endpoints` ``; under `[verify.<net>]` it also contains
  *"in this table"*; the canary is absent. Controls: `[networks.arbitrum-one]` keeps D180's text,
  and `future_knob` still warns in all seven tables.
- **G107-2**, once through the binary, in a private target or a shadow copy:
  `[verify.arbitrum-one] rpc_url = "https://rpc.example/v2/{CANARY}"` with
  `--json verify missing.sealproof` → exit 17, class `malformed-config`, the message naming
  `` `rpc_url` ``, `[verify.arbitrum-one]` and `config.toml:2`, the canary on neither stream.
  Control: `future_knob` on the same line → exit 4. These are P2's executed cases at `HEAD`, the
  `[verify.arbitrum-one]` row and the control row of §1.1.

*Why:* the Accept asks for the key, the table, the line and the absent value, in process and
once through the binary. The seven tables reach both fall-through arms an `rpc_url` can reach,
`[verify.<id>]`'s and `_` (§1.1), and the controls show that the old refusal and the
forward-compatibility warning did not move.

### §2 R5 — Records

- **D196** takes a dated addendum: its §4 bullet (*"Whether it enters `KEY_HOMES` is the lane's
  choice"*) and its §6 unnumbered proposal are answered by this record.
- **D180** takes a dated addendum: its refusal now has every table in scope, not only
  `[networks.<id>]`; its own text and §2 R1–R2 are unchanged.

### What no ruling here moves

- **No exit code and no class:** 17 is reused, raised where every other misplaced known key is.
- **No snapshot, no help text and no `--json` key:** none of the 12 files under
  `crates/antseal-cli/tests/snapshots/` names `rpc_url`, the help snapshot
  `cli-surface.help.txt` among them (§1.4); `crates/antseal-cli/src/cli.rs` names it on 0 lines
  (control `default_network`: 3); and `cli-errors.display.txt`'s malformed-config exemplar is a
  `default_network` refusal.
- **One config acceptance tightens**, from a warning to exit 17. It does so before `Q31`, as D180
  notes for its own refusal: no release exists that a refusal could break.
- **Unknown keys still warn** on the key alone (D189 §2 R3); this record adds a known name to
  `KEY_HOMES` and nothing else.

## 3. Fault plants

The implementing lane owes these. The red baselines come first, on the unedited code; each plant
is judged by its **message**; every restore is followed by a `touch`. G107-2, the spawned tests
of `config_file.rs` and every plant run in a shadow copy with a private `CARGO_TARGET_DIR`: the
binary test spawns `antseal`, and other lanes build the shared target this wave.

**The green tests — the load-bearing half**

- **G107-1** (§2 R4), in process. **Red baseline at `HEAD`:** all seven cases are warned, not
  refused; five of them were executed in §1.1.
- **G107-2** (§2 R4), once through the binary. **Red baseline at `HEAD`:** exit 4 with a
  warning, executed (§1.1, the `[verify.arbitrum-one]` row).
- **Stay green, unchanged:**
  - D180's pins, `config_file.rs:1189` and `:1271`;
  - `a_known_key_outside_its_table_is_refused_by_name` (`:1804`). Its count pin
    `7 * 6 - 7 + 6` and its message *"seven live keys in five foreign tables each, and the
    retired one in six"* (`:1875-1876`) move only if the lane folds `rpc_url` into that test;
    the lane's brief prefers a new test;
  - the unknown-key tests `an_unknown_key_warns_whatever_its_value` (`:756`) and
    `unknown_keys_warn_and_do_not_crash` (`:880`);
  - G100-3, `every_full_schema_key_is_refused_outside_its_home` (`:2057`): `rpc_url` is not a
    schema key, so its count of 8 (`:2062`) does not move.

**The plants — proof that those tests can fail**

| Plant | Must redden |
|---|---|
| **P107-a** — delete the `rpc_url` row from `KEY_HOMES` | G107-1, every case (a warning where an `Err` is expected), and G107-2 (exit 4 where 17 is expected) |
| **P107-b** — map `rpc_url` to `Home::RetiredIntoRpcEndpoints` | G107-1, on *"no payment-RPC override"*: the test tells the two texts apart |
| **P107-c** — drop the *"in this table"* branch | G107-1's `[verify.arbitrum-one]` and `[verify.arbitrum-sepolia]` cases |

**Not plantable as a message check: a value leak.** `misplaced_key_refusal` is never given the
value (§1.4), so a plant that leaked it would have to change the signature, and that is a compile
check. The structure is the witness; the canary assertions stay as the tripwire.

## 4. What this record does NOT decide

- **Near-miss typos** (`rpc_endpoint`, `tsa_url`, `default-network`). They are unknown keys by
  construction and warn under D189 §2 R3. Refusing them would be a different policy; no row is
  proposed.
- **A payment-RPC override.** D180 §2 R1 refused wiring one and §2 R5 lists what a future wiring
  owes. This record does not reopen it; a wiring would also have to change §2 R1's texts, whose
  first clause would then be false.
- **Configs that already carry `rpc_url` outside `[networks.*]`.** Unknowable for a public
  repository, as D180 §4 says of its own scope; the refusal names the line.
- **`U108`.** D195 §2 R4 rules it without a record of its own, and the same lane lands it this
  wave; D195 takes the dated addendum.
- **`[verify.devnet]` and an unknown network's table.** They keep their own refusals, judged
  before `KEY_HOMES` is consulted (`config.rs:1101-1103`, `:1202`).
- **New rows.** This record mints none. The rows minted by this wave's planning (`S51`, `A143`,
  `U109`) belong to other rulings.
- **Build and test durations.** The planning lane built nothing for this row; its one execution
  was the copied binary (§0).

## 5. Edit list — per write scope, with the lane named before this record was written

### L-CFG3 (round 1) — `U108` first, then this record, then `docs/config.md`

- `crates/antseal-cli/src/config.rs` (the whole file is the lane's this wave; `U108`'s functions
  are disjoint from these): the `Home` enum (`:725-741`), one `KEY_HOMES` row (`:755-764`), the
  new arm in `misplaced_key_refusal` (`:773-805`), the `KEY_HOMES` doc (`:743-754`) and the
  module doc (`:24-31`, `:103-120`) (§2 R1, R3).
- `crates/antseal-cli/tests/config_file.rs`: G107-1 and G107-2, new tests appended at the end
  (§2 R4). The tightening at `~:1524-1526` is the same lane's, for `U108`.
- `docs/config.md` (the whole file is the lane's this wave): §2 R3's three places, beside
  `U108`'s `:180-182` clause (D195 §2 R4) and D205 §2 R4's `:11-12` clause.
- Builds: the in-process tests in the shared target, under the lock; G107-2, the file's spawned
  tests and every plant in a shadow copy with a private target.
- Not this lane's: `init.rs`, `verify_host.rs`, `status.rs`, any other `src` file, any snapshot,
  `docs/user/**`.

### RECORDS-D — dated addenda

- **D196:** its §4 `rpc_url` bullet and its §6 unnumbered proposal are answered (§2 R5).
- **D180:** the refusal's scope is every table; its text is unchanged (§2 R5).
- The same lane writes the addenda for the rows this wave rules without a record of their own:
  D195 (`U108`), D202 (`A142`) and D133 (`R100`).

### Orchestrator — `TODO.md`, `tasks/U.md`, `docs/decisions/README.md`

- `U107`'s tick, against §3: the key, the table, the line and the absent canary, asserted in
  process and once through the binary.
- This record's index row and register row.
- §6, from L-CFG3's report, before this record is first committed.

## 6. As built — wave 40, lane L-CFG3 (recorded in place before this record was first committed)

Every verdict below was read from an exit file, per the lane's report (*"exit codes from files,
never from a pipeline"*), and every red was judged by its message. Re-read for this section, the
lane's three files (`crates/antseal-cli/src/config.rs`, `crates/antseal-cli/tests/config_file.rs`
and `docs/config.md`) match its final sha256; the line numbers below are the tree's. The same lane
landed `U108` (D195 §2 R4, whose addendum records it) and D205 §2 R4's clause in those files; they
appear below only where they touch this record. `U108`'s hunks in `config.rs` are disjoint from
this record's, as §5 expected.

- **§2 R1.** `Home::RetiredPaymentRpc` (`crates/antseal-cli/src/config.rs:800-804`), the row
  `("rpc_url", Home::RetiredPaymentRpc)` (`:831`) and its arm in `misplaced_key_refusal`
  (`:867-886`) landed. The function still takes the key and the table, never the value (`:841`).
  The binary prints the ruled texts word for word, read back at exit 17, class
  `malformed-config`:
  - *"`rpc_url` under [verify.arbitrum-one] is retired: antseal reads no payment-RPC override,
    and the receipt check takes a pair — write `rpc_endpoints` with two endpoint URLs in this
    table instead. Its value is not repeated here, because an RPC URL often carries an API key"*
    (`config.toml:2`);
  - *"`rpc_url` at the top level is retired: antseal reads no payment-RPC override, and the
    receipt check's pair is `rpc_endpoints` under [verify.arbitrum-one] or
    [verify.arbitrum-sepolia]. Its value is not repeated here, because an RPC URL often carries
    an API key"* (`config.toml:1`).

  Under `[networks.<id>]` the refusal is still D180's, raised first in `parse` by the unchanged
  `rpc_url_refusal` (`:720`).
- **§2 R2.** Neither refused option was taken: the row maps to the new variant, and D180's check
  stays in `parse`. D180's two pins (`crates/antseal-cli/tests/config_file.rs:1189`, `:1271`) did
  not move and stay green.
- **§2 R3, the documents.**
  - `docs/config.md:37-40` now reads *"the retired `rpc_url` (see "The payment RPC") and the
    retired `arbitrum_endpoints` are errors in every table"*. The schema comment (`:74-77`) reads
    *"There is no payment-RPC override: `rpc_url` is REFUSED in every table when the file is read
    (exit 17, malformed config; U94, U107), naming the key, the table and the line but never the
    value."* "The payment RPC" (`:253-262`) reads *"The key is now refused when the file is read,
    in whichever table it is written — …"*. D205's clause (`:12-17`) went in above them, so these
    are the record's `:31-34`, `~:70-73` and `~:248-253`.
  - **Deviation:** "The payment RPC" gains a sentence (`:259-262`) that names the receipt pair
    and ends *"it takes two endpoint URLs, and only `verify --online` uses it — never a payment."*
    It states §1.2's reason where the key is documented. The schema comment cites the rows
    (`U94, U107`), as its existing `U94` did, not this record.
  - In `config.rs`, the `KEY_HOMES` doc (`:807-821`) now ends *"`rpc_url` is refused in every
    table (D207): `parse` refuses it under any `[networks.<id>]` first, in D180's words, and every
    other table reaches its row here."* The module doc (`:28-29`, `:114-116`) and the comment in
    `apply`'s `[verify.<net>]` arm (`:1293-1295`) say every table too.
  - **Deviation:** the `KEY_HOMES` doc's first sentence changed as well. *"Every key this build
    reads, with its one home"* was loose for `arbitrum_endpoints` and became false with a second
    retired key. It now reads *"Every key this build knows: each key it reads, with its one home
    (U100, D196 R1), and the two retired keys, refused in every table (D188 R5, D207)."*
  - **Deviation:** to keep the module doc line-neutral, `:114-116` drops the clause *"accepting it
    would tell a user the payer dials their endpoint when it dials the pinned one"*. The rationale
    stays in `rpc_url_refusal`'s doc (`:701-705`), and the living-doc citations of `config.rs:2`,
    `:8`, `:186-191` and `:273-278` do not move.
  - **Unchanged and still true:** `CONTRIBUTING.md:316`, and `docs/threat-model.md:944-945`, whose
    phrase wraps across two lines. The lane's one-line grep found `docs/threat-model.md:2708` and
    `docs/instrument-ledger.md:468` instead; both state no scope either. Neither `CONTRIBUTING.md`
    nor `docs/threat-model.md` changed (`git diff --quiet 6e1cab3` exit 0).
- **§2 R4, the tests**, appended at the end of `config_file.rs`.
  - **G107-1** `rpc_url_is_refused_in_every_table` (`:2249`), in process: the seven tables, a bare
    `[networks]` among them, with the count asserted first, and an inline-table value holding the
    canary. Each case is refused on its line with *"`rpc_url` {found} is retired"*, *"antseal reads
    no payment-RPC override"* and the whole pair phrase, and the canary absent. Control 1 keeps
    D180's text under all three `[networks.<id>]`; control 2 counts 7 `future_knob` warnings.
  - **G107-2** `an_rpc_url_key_in_any_table_is_exit_17_before_any_command_runs` (`:2360`), spawned,
    run only in a shadow: exit 17, `malformed-config`, the key, the table and the line, and the
    canary on neither stream. Its control, `future_knob`, is exit 4 with its warning and no canary.
  - **Deviation (stricter than ruled):** G107-1 asserts whole phrases, not the ruled needles, and
    control 1 covers all three networks. G107-2 adds the top-level placement (`config.toml:1`),
    which the Accept names, and its control asserts the warning's text.
  - G107-1 collects every failing case before it asserts, so each red message counts the cases a
    plant reached: the pattern of `a_known_key_outside_its_table_is_refused_by_name`.
  - **Red first, at `HEAD`'s `config.rs`:** G107-1, exit 101, *"7 of 7 tables failed:"*, e.g.
    *"`rpc_url` under [verify.arbitrum-one] must be refused, not warned on: ["config.toml line 3:
    unknown key `rpc_url` under [verify.arbitrum-one] — ignored (newer antseal?)"]"*. It stayed
    red, 7 of 7, with `U108` alone applied. G107-2, in the shadow: exit 101, *"left: Some(4)
    right: Some(17)"*, stderr *"warning: config.toml line 2: unknown key `rpc_url` under
    [verify.arbitrum-one] — ignored (newer antseal?)"*, which is P2's executed case, re-run.
  - **Green** (each count includes `U108`'s tests): in process in the shared target, with the
    eight spawning tests skipped, *"27 passed; 0 failed; 0 ignored; 0 measured; 8 filtered out"*;
    the whole file in the shadow, *"35 passed; 0 failed"*, and again after the shadow was
    refreshed to the combined tree (14 files under `crates/`, sha256-verified); the `antseal-cli`
    lib there, 332 passed; `clippy -p antseal-cli --all-targets -- -D warnings` on the shared tree
    with every lane's edits, 0 warning lines; `rustfmt --check` on both Rust files; and
    `check-copy-style.py` and `check-personal-data.py`.
  - **Read back through that binary** (`--json verify missing.sealproof` under `env -i`, with a
    throwaway vault): the two texts above at exit 17, and the control at exit 4. The canary was
    on neither stream in any case (positive control: one hit in each case's own `config.toml`).
- **§3, the plants**, in the shadow only, each red by message and restored to the final
  `config.rs` (sha256 `103b5c29…`):
  - **P107-a** (the row deleted; it compiles with one `dead_code` warning): G107-1 *"7 of 7 tables
    failed"* (*"must be refused, not warned on"*); G107-2 *"left: Some(4) right: Some(17)"*.
  - **P107-b** (the row mapped to `RetiredIntoRpcEndpoints`): G107-1 *"7 of 7 tables failed"*,
    each without *"no payment-RPC override"*, e.g. *"… in `rpc_url` at the top level is retired:
    the Arbitrum RPC pair is set per network — write `rpc_endpoints` under [verify.arbitrum-one]
    or [verify.arbitrum-sepolia] instead. …"*; G107-2 failed on its message. The test tells the
    two texts apart.
  - **P107-c** (the *"in this table"* branch dropped): G107-1 *"2 of 7 tables failed"*, exactly
    the two `[verify.<net>]` cases. G107-2 stays ok: it pins the key, the table, the line, *"no
    payment-RPC override"* and value-freedom, not the branch.
  - The value leak stays unplanted, as §3 ruled.
  - The stay-green tests held: D180's pins; `a_known_key_outside_its_table_is_refused_by_name`
    (`:1804`), whose count `7 * 6 - 7 + 6` and message (`:1875-1876`) did not move; the
    unknown-key tests (`:756`, `:880`); and G100-3 (`:2057`), whose count of 8 (`:2062`) stands.
    The plant-marker grep over the tree exits 1 (positive control: 1 hit).
- **What no ruling here moves, held.** 17 is reused. No snapshot changed for this record: no
  snapshot file that differs from `6e1cab3` names `rpc_url` (four differed when this was written).
  `crates/antseal-cli/src/cli.rs` is unchanged and names `rpc_url` on 0 lines (control
  `default_network`: 3).
- **Left open.**
  - **`U111` owns** the lane's one proposed row, which is `U108`'s: `rpc_endpoints`' subset
    refusal names the entry but not the reason. This record's texts send a payment-RPC user to
    that key; the row does not change them.
  - **For the instrument ledger:** the planning lane PS's spawn census read `config_file.rs` as
    spawning the binary once (`:1271`), because it counted call sites of `spawn::antseal(`. The
    file's local `spawn()` wrapper (`:903`) is called by 7 tests at `HEAD` and 8 now. The lane ran
    all eight only in the shadow, as §3's venue requires.
  - **L-LOC owns** the living-doc citations the lane's edits moved, per its line map: `config.rs`
    `:1015-1048` → `:1109-1142` and `:1159-1197` → `:1253-1291`
    (`docs/user/timestamp-authorities.md:237`, `:108`), six `docs/config.md` ranges from `:1-14` →
    `:1-19` to `:83-199` → `:87-204`, and the ledger's `docs/config.md:25` → `:30`.

## Closing — this record is not consent

It turns the last known config key that only warns into a refusal, and moves three documents to
say so, inside the wave's own commits. Nothing in it authorises a push, a workflow dispatch, a
deploy or any other outward act; each of those needs the maintainer's express consent naming the
action, the destination and the account.
