# D180 — Two dead surfaces are retired before the freeze: a configured `rpc_url` is **refused at load**, and the compiled-in arm's sentence, **which no build prints**, is deleted

- **Status: RESOLVED. Both rows' directions survived. `U94`'s premise fell, its "refuse, never
  warn" held for a reason other than its own, and `U95`'s scope was five items short.**
  - **`U94`'s premise, that wiring the key is unbuildable without an `ant-core` bump, is false.**
    The fields of evmlib 0.9.0's `CustomNetwork` are public. Every payer and wallet-helper RPC
    resolves through `Network::rpc_url()`. antseal already builds the `Custom` literal for `devnet`,
    and today the export's `RPC_URL` reaches the payer and the receipt reader by exactly that route.
    The key is retired for reversibility, credential exposure and a marginal privacy gain (§2 R1),
    **not because it cannot be wired**.
  - **"Refuse at load, never warn" holds, but the reason is the first run, not the freeze.** The
    row's ground, *the config surface freezes at `U32`*, is self-sourced. `U32`'s `Do` freezes exit
    codes, `--json` schemas and help text, not `config.toml`, and only `U94`'s own `Deps` line says
    otherwise. What decides it:
    - a warning prints while `seal` pays through the very endpoint the user configured away from;
    - `docs/config.md:16` already says *"silently dropped overrides are worse than a loud stop"*;
    - a misplaced `bootstrap` is already exit 17.

    The rule that unknown keys only warn points the other way here. An older binary that cannot
    honour a future `rpc_url` should refuse it, and no release exists yet that a refusal could break.
  - **`U95` held on its premise but missed five things:**
    - Three absence checks forbid the sentence, and deleting it would leave all three unable to
      fail.
    - `seal_command.rs:1598-1601` asserts a property of the `Compiled` text and is not in the row's
      Notes. The both-build `assert_ne!` at `machine_mode.rs:1741-1742` sits in a test the Notes
      cite only for its feature arm.
    - In the feature build there is no sentence left to assert *exactly*: that arm prints no backend
      refusal at all, and its surface is already asserted as class/exit pairs.
    - `machine_mode.rs:447/461` say *"the other arm is registered below"*, and nothing is.
    - `commands.rs:255-258` describes the message in the present tense.
  - **R82's "argued retraction" is a light procedure, but the question does not go away.** R82
    demands that arm (c) be argued: one feature-invariant sentence replacing **both** texts. This
    record does not take arm (c). The no-backend sentence stays, and the recorded choice's core claim
    gets stronger: *a message blaming the missing feature would be a lie in a build that has it*,
    and the build that has the feature now prints no backend refusal at all. R82 still requires the
    retirement to be argued at both venues in the same act, with no snapshot re-bless (§2 R11).
- **Date: 2026-10-16**
- Owner rows: **`U94`** (§2 R1–R5); **`U95`** (§2 R6–R11); **`R82`** (its Notes take a dated
  addendum: the retirement is argued, no snapshot is re-blessed, and its tick text was superseded by
  D170 and D175 §2 R10).
- Related:
  - **D173** §1.5 (where `U94` was found) and §2 R13 (the payer's EVM RPC lies outside both gates);
  - **D174** §2 R6 (what a future wiring must amend);
  - **D175** §2 R10–R11 (the `[reveal]` Compiled-arm document retired; the sentence routed to
    `U95`);
  - **D170** §2 R2 and §2 R12;
  - **D65** (`error.message` is tier C and may be reworded at any tier);
  - **`U32`** (the freeze both rows must land before);
  - **`Q31`** (the first release, which is the deadline that actually governs a config key).

## 0. What was measured against

`HEAD` `fbcee1e` (= `origin/main`).

Planning lane P3 (wave 37) worked read-only, built nothing, and read the self-test files through
`git show HEAD:`. It read:
- `config.rs`, `backend.rs`, `commands.rs`, and every test that cites the `Compiled` text;
- the pinned `evmlib` 0.9.0, `reqwest` 0.13.4 and `ant-core` 0.5.0 sources;
- `U94`, `U95`, R82, D65 and D173–D175;
- wave 36's devnet evidence.

Before this record was written, the records lane re-read at `HEAD`:
- `config.rs:24-31,117-121,437-440,546-560`;
- `backend.rs:160-181,233-279,394-402,1013-1020`;
- `evmlib-0.9.0/src/lib.rs:80-85,153-157` and `reqwest-0.13.4/src/error.rs:279-280`;
- every use of `UNWIRED_SENTENCE` in `tests/reveal_lazy_backend.rs`, which adds two sites to P3's
  census (§1.2).

## 1. What was measured

### 1.1 `U94`: the key, its readers, and the route a wiring would take

- **No production reader.** `rpc_url_override` occurs at `config.rs:119,121,149,150,559` and
  `tests/config_file.rs:139`, and nowhere else.
- **Wiring needs nothing upstream.**
  - `evmlib-0.9.0/src/lib.rs:80-85` declares `pub rpc_url_http`, `pub payment_token_address` and
    `pub payment_vault_address`.
  - `:153-157` resolves `Network::Custom(custom) => &custom.rpc_url_http`.
  - In `wallet.rs:213-214`, `to_provider` uses `self.network.rpc_url()`, and so do the balance, gas,
    allowance, approve and payment helpers (`:285, 296, 308, 322, 338, 353, 428`).
  - On the client side the variant decides only `Display`, `FromStr`, `identifier()` and the three
    getters (`lib.rs:111-174`). antseal names `EvmNetwork` nowhere outside `evm.rs`.
- **The devnet route works today.**
  - `NetworkConfig::devnet` sets `rpc_url: env.rpc_url` (`network.rs:368-372`).
  - `to_evm_network` builds the `Custom` literal (`evm.rs:98-108`).
  - The payer calls `wallet.to_provider()` (`ant_backend.rs:278`), then `chain_id_guard` (`:282`),
    then `with_evm_network` (`:287`).
  - The receipt reader calls `http_provider(config.rpc_url)`, then the guard (`:1198-1202`).
  - Witnessed by `e2e-devnet: PASS commit=c36949f nodes=14 suites_run=4 failed=[] pending=[]
    secs=665`, and by `receipt_backfill.rs:1178`'s `ReceiptRpcStub`.
- **Public ids ignore the key.**
  - `evm.rs:96-97` maps them to evmlib's built-ins whatever `config.rpc_url` says.
  - The Sepolia export's RPC is dropped by `..Self::arbitrum_sepolia()` (`network.rs:1627-1635`).
  - The receipt reader uses the pinned constants (`backend.rs:1347-1348`).
- **Error messages print the URL.** `ant_backend.rs:1301` formats `"payment RPC unreachable
  (eth_chainId): {e}"`, and `reqwest-0.13.4/src/error.rs:279-280` appends `" for url ({url})"`
  (0.12.28: `:266-268`). An RPC URL carrying an API key would therefore reach stderr and the
  `--json` envelope.
- **Validation checks only the prefix.** `config.rs:437-440` accepts `http://`. Compare the
  `[verify]` rationale at `config.rs:627-637`: those replies *"carry no signature of their own"*, so
  they need TLS.
- **Privacy.**
  - The threat model mentions an RPC only at lines 1185, 2000 and 2095, and never treats the payer's
    RPC operator as an observer.
  - §2.3 already says every seal hands storing peers transaction hashes that resolve to the paying
    wallet: *"This happens on the first seal, and nothing configurable changes it"* (`:907`).
  - A private RPC therefore removes one observer, not the link.
- **What freezes, and when.**
  - `U32`'s `Do` names exit codes, every `--json` schema and help text.
  - `grep -rni "config surface freezes"` finds only `tasks/U.md:1371`, which is `U94`'s own `Deps`.
  - MVP-SPEC makes only the TSA list configurable (lines 109, 189).
  - No release exists: the releases API returns `0`, and the only tags are `format-v1-freeze` and
    `pre-trailer-strip-949dd9d`. `Q31` is open.
- **Origin, and two stale claims.**
  - `U4` (`f24111b`, 2026-08-01) reserved *"a per-network `rpc_url` override SLOT
    (`[networks.<id>]`; consumer S6)"* (`tasks/U.md:63`). S6 never consumed it, yet `config.rs:24-29`
    and `:117` still name S6 as the consumer.
  - `CONTRIBUTING.md:310` says *"only `devnet` threads the configured `rpc_url`"*. In fact
    `config.toml`'s key is threaded for no network; devnet's RPC comes from its export.
- **Who meets the refusal.**
  - `init` writes only `default_network` (`config.rs:233-239`), and no test outside `config_file.rs`
    writes the key.
  - Case 6 in `config_file.rs` (`:269-272`) is `[networks.devnet] rpc_url = "ftp://x"`, expecting
    the error to contain `http:// or https://`.
  - `vault import` writes the embedded config verbatim without parsing it
    (`vault/export.rs:1096-1101`), so a restored config carrying the key meets the refusal at its
    next command.

### 1.2 `U95`: the sentence, its renderers and the tests that cite it

- **No production emitter in either build.** The sentence has two renderers: `backend.rs:296`
  (`unavailable_arm`) and `:401` (`VaultLocalBackend`). Production reaches them only from
  `cfg(not(feature = "ant-backend"))` items:
  - `commands.rs:322/331` (`seal_over_backend`), `:638/647` (`restore`) and `:989/991`
    (`verify --live`) call `unavailable`;
  - `backend.rs:1012/1020` (`drive_reveal`) is the only production construction of
    `VaultLocalBackend`;
  - `THIS_BUILD` is set at `backend.rs:233/237`.
- **Tests that cite the `Compiled` text:**
  - `reveal_vault_local.rs:337`, `contains("no storage backend compiled in") || contains("compiled
    in")`, which is true of both arms;
  - `machine_mode.rs:1440` (`ALL × message`), `:1733`, and the both-build `assert_ne!` at
    `:1741-1742`;
  - `seal_command.rs:1598-1601`.

  Other tests use `BackendArm` only as a discriminator: `seal_plan_conflict.rs:105-110/144/199`,
  `upgrade_hook.rs:771-778`, `restore_output.rs:1241/1347`, `seal_command.rs:1603-1611/1693/1789`
  and `machine_mode.rs:168-171`.
- **Absence checks that forbid the sentence.** `reveal_lazy_backend.rs:89` defines
  `UNWIRED_SENTENCE = "does not construct one yet"`. P3 listed its uses at `:457` (the default arm)
  and `:517` (the feature arm), plus `e2e_restore.rs:1497` (S19, live devnet). **The records lane's
  re-read adds two more uses.**
  - `:766` is the `Compiled` arm of the per-build test.
  - `:1015` is inside `mod feature_build`, which imports the constant at `:802`.

  Each of the two is a forbidden list `[UNWIRED_SENTENCE, ABSENCE_SENTENCE, "compiled in"]`. Their
  `"compiled in"` member already forbids the no-backend fragment. Once the sentence is deleted, their
  `UNWIRED_SENTENCE` member is a string no build emits.
- **The fixture registry contradicts itself.**
  - `render_fixture` (`machine_mode.rs:421-642`) calls only `unavailable_arm(…, NotCompiled)`, at 449
    and 462, while `:447` and `:461` say *"the other arm is registered below"*.
  - `[arm:` occurs only at 1645 (a doc comment) and 1657 (the marker).
  - `json-envelopes.txt` is 44 lines. Lines 4 and 12 carry the NotCompiled text, and it has no
    `[arm:` header.
  - `scripts/` and `.github/` contain no match for `\[arm:|BackendArm|backend-compiled|no-backend-compiled`
    (`grep` exits 1).
- **What R82 requires.**
  - The phrase *"argued retraction"* occurs only in `U95`'s own text (`tasks/U.md:1387`, `:1391`).
  - R82's Notes say arm (c) *"is a **retraction of a recorded design choice** and has to be argued as
    one, not slipped in as a snapshot repair"*.
  - The choice is recorded at `backend.rs:160-172` and at the fixture registry
    (`machine_mode.rs:371-418`, the venue of R82's `Accept` row 2).
  - R82's tick text says *"`render_fixture()` renders **both** arms' refusals … in **every**
    build"*. D170 and D175 §2 R10 superseded it without an addendum on R82.
  - D65:446-449: *"`message` is human copy and may be reworded freely at any time, at any tier."*
  - No frozen document carries either sentence.
- **What the feature build already pins.** Its surface is asserted as class/exit pairs
  (`machine_mode.rs:168-171`, `seal_command.rs:1611`, `restore_output.rs:1268/1355`,
  `upgrade_hook.rs:778`). There is no feature-build refusal sentence to assert.
- **Gate triggers.**
  - The tier-2 trigger (`gate-features.sh:112-121`) names `backend.rs`, `commands.rs`, `pipeline/`
    and `crates/antseal-net/`, but not `config.rs` or `tests/`. The devnet trigger is that list
    minus `commands.rs`.
  - `U94` is therefore light. `U95` moves `backend.rs`, so it needs the heavy tier and the devnet
    E2E.
  - No rustdoc lane exists: `cargo doc` and `RUSTDOCFLAGS` appear only in a comment at
    `check-traceability.py:2234-2236`. Nothing enforces `backend.rs:358`'s intra-doc link to
    `BackendArm::message`.
- **S19 prints no messages.** `suite-S19.log` reads `7 passed; 0 failed … finished in 223.19s`, so
  where its dead-export control's message comes from is not established (§4).

## 2. RULING

### §2 R1 — `rpc_url` under any `[networks.<id>]` is a malformed config (U94 R1)

The key is refused at load with exit 17 (`malformed-config`). The error names the key, the table
and the line, and **never echoes the value**. The grounds, in order:
1. Refusing is reversible. A later wiring is additive, and older binaries keep failing closed.
2. Wiring now would commit the surface to a single-source input that, in its common real form,
   carries a credential, and the error paths print that input verbatim (§1.1).
3. The privacy gain is marginal, because the storing peers already hold the wallet-to-address link.
4. The spec does not ask for the key.

**Wiring was measured as buildable at the pin, and it is refused on these grounds, not on
mechanism.** No document may call it unbuildable.

*[Amended in place by the registrar, wave 37, before this record was first committed, on lane
L-CLI's measurement P1d:]* the refusal is raised in `config::parse` **on the key, before the value
is parsed**, so no value shape can echo through the subset's own errors. With the check placed after
`parse_value`, as this record's arm order first read, an unquoted value echoed the whole URL:
*"value `https://rpc.example/v2/NOT-A-KEY-canary` is not a quoted string …"*.

### §2 R2 — The section name is validated first (U94 R2)

`[networks.ropsten]` keeps its *"not a known network"* error. Only an `rpc_url` under a known
network meets §2 R1.

### §2 R3 — The slot and its accessor are deleted (U94 R3)

`rpc_url_overrides` and `rpc_url_override()` are deleted, and `config.rs`'s rustdoc stops naming S6
as a consumer.

### §2 R4 — The documents say what is refused and what the payer dials (U94 R4)

`docs/config.md` and `CONTRIBUTING.md` state the refusal and what the payer actually dials: the
pinned public endpoint for each public id, and the export's `RPC_URL` for `devnet`. This removes
`CONTRIBUTING.md:310`'s *"only `devnet` threads the configured `rpc_url`"*.

### §2 R5 — What a future wiring owes (U94 R5)

Recorded so that any later wiring is an argued addition. It owes:
- **https only**, except for loopback IP literals;
- **URL redaction at every `{e}` site** that can carry the URL, at least `ant_backend.rs:1301` and
  `:473-475`;
- **a threat-model entry** naming the payment-RPC operator as an observer;
- **a dated addendum on D174 §2 R6**, under which public ids take the pinned chain half.

### §2 R6 — The `Compiled` sentence is deleted, not reworded (U95 R1)

Rewording is refused because a reworded sentence would still have no emitter.

### §2 R7 — `BackendArm` becomes a pure build discriminator (U95 R2)

`NotCompiled`, `Compiled`, `ALL`, `THIS_BUILD` and `name()` stay. `Compiled.name()` becomes
**`backend-compiled-in`**, because the retired `backend-compiled-in-command-unwired` is false for
every command. `ALL` stays because `pipeline/receipt_backfill.rs:167` links to it.

### §2 R8 — The no-backend sentence gets its own home, in both builds (U95 R3)

The sentence moves to `no_backend_message(command)` and `no_backend_refusal(command)`,
**byte-identical** to today's NotCompiled text. Both are compiled into both builds, because the
fixture renders the sentence in both (R82's consequence 2; `U3`'s real-producer rule).

`unavailable()` becomes `#[cfg(not(feature = "ant-backend"))]`. All three of its callers already
are, so no `commands.rs` code changes, and a build that has a backend can no longer call the
function that says it has none.

### §2 R9 — `VaultLocalBackend` renders the no-backend sentence explicitly (U95 R4)

It stays in both builds, because `U72`'s in-process suite runs in both.

### §2 R10 — The absence checks are re-anchored in the same act (U95 R5)

- In the feature build, the absence checks forbid the no-backend fragment *"no storage backend
  compiled in"*. That fragment is still compiled into the feature build, so a plant can redden the
  checks.
- The default build's absence check is deleted, because its string would exist in no build.
- Every use of `UNWIRED_SENTENCE` moves in this act: `:457`, `:517`, `:766`, `:1015` and the import
  at `:802` (§1.2). So does `e2e_restore.rs:1497`'s list. None may be left forbidding a string no
  build emits.

### §2 R11 — No snapshot moves, and the retirement is argued where the choice is recorded (U95 R6)

- `tests/snapshots/json-envelopes.txt` and `tests/snapshots/cli-errors.display.txt` stay
  byte-unchanged. A re-bless would be the snapshot repair R82 forbids.
- In the same act, the retirement is argued at the two venues where the choice is recorded:
  `backend.rs`'s design rustdoc (`:160-181`, and `BackendArm`'s *"Why this enum exists at all"*) and
  the fixture registry (`machine_mode.rs:371-418`). Both say that arm (c) is not taken, and why the
  choice's claim survives.
- `machine_mode.rs:447/461`'s *"registered below"* and `commands.rs:255-258`'s present tense are
  corrected.
- R82's Notes and D175 §2 R11 take dated addenda, written by the orchestrator.

## 3. Fault plants

The implementing lane owes these plants. Each is judged by its message. Green baselines come first,
and every restore is followed by a `touch`.

**`U94`**

- **P1** is a new test, `rpc_url_is_refused_at_load_under_every_network`. For each of the three ids
  it parses `[networks.{id}]\nrpc_url = "https://rpc.example/v2/NOT-A-KEY-canary"\n` and asserts four
  things:
  - `expect_err("`rpc_url` must be refused at load")`;
  - `line == 2`;
  - the detail names both `` `rpc_url` `` and `[networks.{id}]`;
  - `!detail.contains("NOT-A-KEY-canary")`, with the message *"the refusal must not echo the value:
    an RPC URL often carries an API key: {detail}"*.

  Plants:
  - **(a)** Replace the arm's `return Err(..)` with `config.warnings.push(..)`. Expect red:
    `` `rpc_url` must be refused at load: Config { … warnings: [..] } ``.
  - **(b)** Append `` (got `{url}`) `` to the detail. Expect red with the must-not-echo message.
  - **(c)** Refuse the key before the network name is parsed. Expect red in
    `malformed_configs_fail_with_line_and_problem`: `"[networks.ropsten]\nrpc_url = …": expected "not
    a known network" in …`.
- **P2** is a new spawned test, `an_rpc_url_key_is_exit_17_before_any_command_runs`, in the shape of
  `config_file.rs:557-600`. It runs `--json verify b.sealproof` against an
  `[networks.arbitrum-one] rpc_url` config and expects exit 17, class `malformed-config`, and a
  message naming `rpc_url` but not the canary. The control config (`default_network =
  "arbitrum-one"`) must exit 4. Under plant (a), expect red: `…: malformed-config code; stderr: …`
  (exit 4).
- **Green.**
  - `config_file` is green once case 6 uses an https value with the needle `` `rpc_url` ``. If case 6
    is left as it is, expect red: `"[networks.devnet]\nrpc_url = \"ftp://x\"\n": expected "http://
    or https://" in …`.
  - `grep -rn rpc_url_override crates/` returns 0 hits.
  - Both snapshots are unchanged. The malformed-config exemplar is `default_network`
    (`cli-errors.display.txt:43-44`).

**`U95`**

- **P3.** `reveal_vault_local.rs:337` becomes `assert!(text.contains(&no_backend_message("reveal")),
  "VaultLocalBackend names the whole no-backend sentence for `reveal`: {text}")`. Plant: make
  `backend.rs:401` render `no_backend_message("seal")`. `HEAD`'s assertion stays **green** under
  that plant, which proves it is blind. The new assertion goes red with its message.
- **P4.** In `assert_lazy_refusal`, `UNWIRED_SENTENCE` becomes `NO_BACKEND_FRAGMENT = "no storage
  backend compiled in"`, with the message *"{label}: a build with a backend compiled in never prints
  the no-backend sentence: {message}"*. Plant: append `; this build has no storage backend compiled
  in` to the `#[error]` at `devnet_env.rs:193`. In the feature build,
  `a_partial_cache_with_no_definition_is_refused_at_the_first_fetch_per_build` still exits
  2/`usage` and still finds its `must_name` fragments, then goes red with that message. The same
  plant stays **green** against `HEAD`'s check.
- **P5.** `e2e_restore.rs:1497`'s forbidden list becomes `["no storage backend compiled in", "has no
  data at this address"]`. The plant site is not established (§4); the lane runs the S19 dead-export
  control once with `--nocapture` to find it.
- **P6** is the test `unavailable_selects_this_builds_arm`.
  - Default arm: `assert_eq!(unavailable("seal").to_string(), no_backend_refusal("seal").to_string(),
    "`unavailable` is the no-backend refusal for its own command")`.
  - Feature arm: `THIS_BUILD == Compiled`.
  - Plant: make `unavailable`'s body call `no_backend_refusal("restore")`. Expect a red `assert_eq`
    diff with that message.
- **P7.** `the_refusal_messages_name_no_task_row` iterates the four commands over
  `no_backend_message`. Plant: append ` (U13)`. Expect red: ``the `no-backend-compiled-in` refusal
  for `seal` names ["U13"]. A refusal a user reads cannot cite a task identifier…``.
- **P8.** `no_registered_document_carries_the_compiled_arm_header` checks two markers: the new name
  and the retired literal `backend-compiled-in-command-unwired`. Plant: make `render_fixture` push a
  `[seal] error [arm: backend-compiled-in]` document. Expect red: ``rendered: no registered document
  may carry the `backend-compiled-in` arm…``.
- **Green.**
  - In both builds, `git diff --exit-code -- crates/antseal-cli/tests/snapshots/` exits 0 and
    `envelope_fixtures_match_the_committed_snapshot` is green.
  - `grep -rn "does not construct one yet" crates/` returns 0 hits, and `grep -rn command-unwired
    crates/` returns 1 (P8's marker).
  - `expected_class` is unchanged, and so is the default build's exit 23 for `seal`, `restore` and
    `verify --live`.
  - Failure-message labels in the feature build read `backend-compiled-in`.

## 4. What this record does NOT decide

- Whether the public RPC's rate limits create a reliability need for a private RPC. Not measured.
- Whether any user who builds from source has the key in a config. That is unknowable for a public
  repository; the refusal names the line.
- Whether alloy's RPC error bodies echo the URL beyond `reqwest`'s `Display`. Not read. It bears on
  §2 R5's redaction, not on the refusal.
- A §2.3 paragraph naming the payment-RPC operator as an observer today. P3 recommended it; this
  record does not rule it, and §2 R5 makes it a future wiring's debt.
- Which deadline governs config keys in general. `U94`'s `Deps` says `U32`, but `U32`'s `Do` freezes
  no config file; the measured deadline is the first release (`Q31`). Recorded here, not re-ruled.
- P5's plant site in S19, and every build and test duration (planning was not allowed to build).

## 5. Edit list — per write scope, with the lane named before this record was written

### L-CLI — `crates/antseal-cli/src/{config.rs, backend.rs, commands.rs (rustdoc only)}` and the named tests

- `config.rs` per §2 R1–R3. Lines at `fbcee1e`: `:24-31`, `:117-121`, `:146-155`, `:546-560`,
  `:562-565`.
- `tests/config_file.rs`: `:125-140` (drop the key and the accessor assertion), `:269-272` (case 6),
  and §3 P1–P2.
- `backend.rs` per §2 R6–R11: `:76-80`, `:160-181`, `:184-298`, `:358`, `:397-402`.
- `commands.rs:255-258` per §2 R11, rustdoc only.
- Tests per §2 R10–R11 and §3 P3–P8:
  - `machine_mode.rs`: `:371-418`, `:446-462`, `:1394-1446`, `:1642-1700`, `:1701-1745`;
  - `reveal_vault_local.rs:335-339`;
  - `reveal_lazy_backend.rs`: `:86-89`, `:452-458`, `:516-519`, `:766`, `:802`, `:1015`;
  - `seal_command.rs:1592-1611`;
  - `restore_output.rs`: `:1216`, `:1253`, `:1322`, `:1352`;
  - `exit_codes.rs:396`;
  - `e2e_restore.rs`: `:1268-1272`, `:1497`;
  - optionally `verify_command.rs:2091-2094`, to assert the whole sentence.
- Must stay byte-unchanged: `tests/snapshots/json-envelopes.txt` and
  `tests/snapshots/cli-errors.display.txt`.
- Because `backend.rs` moves, the close gate runs with `ANTSEAL_GATE_HEAVY=1 ANTSEAL_GATE_E2E=1`. P5
  runs only in the devnet E2E's suite S19.

### DOCS — `docs/config.md`, `CONTRIBUTING.md`

- `docs/config.md` (`:55-65`, `:110`) and `CONTRIBUTING.md` (`:308-311`) per §2 R4.
- *[Added by the registrar, wave 37:]* `docs/config.md` gains a section, *The payment RPC*, and
  `docs/threat-model.md` §2.3 gains the paragraph §4 left unruled. The orchestrator took it: it
  states an exposure that exists today and changes no behaviour (§6).

### Orchestrator — `TODO.md`, `tasks/U.md`, `tasks/R.md`, `docs/decisions/README.md`, dated addenda

- `U94` and `U95`: rows and Notes per this record.
- R82's Notes: a dated addendum per §2 R11.
- D175 §2 R11: a dated addendum recording that the sentence it routed to `U95` is retired here.
- The index row and the register row.

## 6. As built — wave 37, lane L-CLI (recorded in place before this record was first committed)

The lane built §2 R1–R11 as ruled, and `Q117`'s four rustdoc sites in the same file. Where the
build says more than the ruling did:

- **§2 R1's order** is amended above. The refusal sits on the key, before the value is parsed. P1
  widened to five value shapes, a line-4 case and the `ropsten` case. The new plant **P1d** (the
  check moved after `parse_value`) is red by the echoed URL.
- **§3 P4's site.** `devnet_env.rs:193` lies outside the lane's scope, so the plant went at
  `backend.rs:1602`, the feature-only `reveal` network resolver. The observable change is the same:
  the no-definition usage refusal carries the no-backend sentence, with its class, exit and
  `must_name` unchanged.
- **§3 P5 / §4's "plant site not established".** The site is now established as far as a lane
  without a devnet can establish it:
  - **N1:** S19's dead-export message comes from the connected reader's per-fetch failure (*"insufficient peers…"*), not from `UnreachableBackend`.
  - **P5:** under the plant at `backend.rs:998`, both feature-build unreachable checks go red.
  - **S19's predicate**, evaluated on the planted message: the old list stays green and the new list goes red.

  S19 itself under the plant needs a devnet and was not run.
- **§3's green clause on snapshots.** *"`git diff --exit-code -- crates/antseal-cli/tests/snapshots/`
  exits 0"* is false in this wave's tree, because `S43` (D179 §2 R5) moves
  `cli-errors.display.txt:92`, the exit-29 sentence. The lane proved the clause in a private tree
  instead, from `HEAD`'s snapshot files plus its own sources: `exit_codes` 8/8 and `machine_mode`
  15/15 in both builds. Read the clause as **byte-unchanged by U95**. `json-envelopes.txt` is
  byte-identical to `HEAD`.
- **§2 R11's venue.** `BackendArm`'s heading *"Why this enum exists at all"* became *"What it no
  longer carries, and why (U95; R82's argued retraction)"*.
- **P6** also asserts `name() == "backend-compiled-in"` in the feature arm. The deleted both-build
  `assert_ne!` was replaced by a both-build *"`no_backend_refusal` is exit 23 and carries the whole
  sentence"*.
- **P8r** was added: a plant of the retired arm name proves the second marker.
- **`commands.rs` stays line-count-neutral** (1 225 lines before and after), because 140 locators
  point into it.
- **One link outside the lane's scope.** `crates/antseal-cli/src/status.rs:1124` linked
  `[`crate::backend::unavailable`]`, which after §2 R8 resolves in the default build only. The
  orchestrator re-pointed it at `no_backend_refusal`, which is public for the same reason and is
  compiled into both builds.
- **The §2.3 paragraph §4 left unruled was taken** (edit list, DOCS).
- **A process finding the lane measured.** Cargo releases the build-directory lock before it runs
  tests. So another lane's `--features ant-backend` build re-linked the shared
  `target/debug/antseal` in the middle of this lane's default-build run, and every spawned-binary
  test after that moment ran the wrong binary. That first run is void, passes included. Every later
  run used a private target, and every plant ran in a private copy of the tree (instrument ledger,
  2026-10-16).

## Closing — this record is not consent

It changes code, tests and documents. It authorises no network act beyond the local devnet.

## Addendum — 2026-10-20 (wave 40, D207 §2 R5): the refusal's scope is every table, not only `[networks.<id>]`

§2 R1 refuses `rpc_url` *"under any `[networks.<id>]`"*. Everywhere else the key was an unknown
key and only warned. Wave 40's planning lane executed it at `6e1cab3` at the top level and under
`[verify]`, `[verify.arbitrum-one]`, `[verify.arbitrum-sepolia]` and `[anchors]`: exit 4 on
`--json verify` each time, after one *"unknown key … — ignored (newer antseal?)"* warning (D207
§1.1). This record's own reason for refusing — *"The rule that unknown keys only warn points the
other way here. An older binary that cannot honour a future `rpc_url` should refuse it, and no
release exists yet that a refusal could break"* (`:19-20`) — holds in those tables too, and the
`[verify.arbitrum-one]` case is a plausible guess for the receipt RPC. **D207 (`U107`) widens
the scope.**

- **`rpc_url` is refused at load in every table:** exit 17 (`malformed-config`), raised on the
  key before the value is parsed, never repeating the value. Outside `[networks.<id>]` the refusal
  goes through D196's `KEY_HOMES`, with a `Home` variant of its own.
- **Its words there name both facts:** antseal reads no payment-RPC override, and the receipt
  check's pair is `rpc_endpoints` under `[verify.arbitrum-one]` or `[verify.arbitrum-sepolia]`
  (*"in this table"* when the key sits in one). The generic retired text of `arbitrum_endpoints`
  was refused for it: it would tell a payment-RPC user that `rpc_endpoints` replaces the key.
- **Under `[networks.<id>]` nothing changes.** The check in `config::parse` (§2 R1's amended
  order) still runs first with this record's text, §2 R2's order still holds (an unknown network
  keeps *"not a known network"*), and the two pinned tests (`config_file.rs:1189`, `:1271` at
  `6e1cab3`) stay green unchanged. Folding this check into `KEY_HOMES` was refused as churn
  (D207 §2 R2).
- **A future wiring (§2 R5) meets one more surface.** D207's texts say that antseal reads no
  payment-RPC override, so a wiring would make them false and would have to change them too
  (D207 §4). §2 R5 itself is unchanged.
- `CONTRIBUTING.md:316` and `docs/threat-model.md:944` (*"`rpc_url` is refused at load"*) state
  no scope and stay true; `docs/config.md`'s three `[networks.*]`-scoped passages move with D207
  (§2 R3).

The rulings above are not rewritten.
