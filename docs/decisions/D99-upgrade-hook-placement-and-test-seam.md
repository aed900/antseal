# D99 — Where U24's opportunistic upgrade hook lives, and how any of it becomes executable

- **Status: RESOLVED — the hook is a property of **dispatch completion**, not
  of dispatching and not of unlocking. The call site is
  `crates/antseal-cli/src/lib.rs`, in `main_entry`, **after the exit code is
  computed and every byte of output is written**, over a vault handle each
  vault-holding handler *moves up* into a slot the dispatcher owns. That
  placement is forced three times over, not chosen: it is the only point that
  is post-output in **both** plain and `--json` mode, the only point at which
  the host command's `VaultLock` has been released (so the hook can take its
  own), and the only point at which the exit code is already a value the hook
  cannot touch. The register's lean — "put the hook in the shared dispatch
  path" — is **confirmed in location and overturned in mechanism**: a hook at
  `run.rs`'s `match` satisfies U24's Accept row 4 and violates D42, because
  neither shared point holds a vault. **U24's Accept row 4 is factually wrong
  as written** and is rewritten below into something testable that keeps the
  property it was reaching for. **U24's Accept row 1 is wrong in its
  mechanism** (`list` does not, and must not, take the lock — the hook does,
  after `list` has returned). **U23's Accept row 2 and U24's Accept row 1 are
  both unexecutable today** and are made executable by promoting two
  `#[cfg(test)]` items in `antseal-anchor` to `feature = "test-util"`, which
  is measured not to enter any shipped binary. The highest-risk finding is
  **not** the placement: `cargo test -p antseal-cli` runs today with Q16's
  gate **disarmed** — measured, `deny_reason() == None` — so a hook that fires
  on every vault-holding command dials live calendars from any bare developer
  test run, and **the compile-time fix that looks obvious is measured to break
  `antseal-anchor`'s own proof that the gate works.**
- **Date: 2026-08-06** (M2 wave 8 planning round; **minted mid-execution** by
  the U23–U25 lane from a contradiction between two committed obligations)
- **Owning tasks: U24** (the hook), **U23** (`status --upgrade`, which shares
  the seam), **U25** (the nag, which reads what the hook writes), **U47** (the
  slot reader — a hard predecessor, per D97), **Q16** (the arming), **A42**
  (the allowlist whose test seam this opens)
- **Amends**: `tasks/U.md` **U24 Accept rows 1 and 4** and its `Deps`;
  `tasks/U.md` **U23 Accept row 2**; **D42**'s consequence paragraph (its
  *rule* is untouched — the enumeration under it is wrong about two commands);
  **D97 R3**'s `apply_upgrade` parameter type; the doc comment on
  `antseal_cli::main_entry` (`lib.rs:52-53`); the doc comment on
  `seal_session.rs::a_session_holds_exactly_two_handles_to_one_vault`.
  **Supersedes**: nothing. **Binds against**: D42, D45, D51, D90, D97, A15,
  A42, Q16, S36, U2, U3.

---

## The problem, in one sentence

D42 binds the hook to *"the dispatching command already hold[ing] an unlocked
vault handle"* and U24's Accept binds it to *"the shared dispatch path"*, and
the tree has measured proof that no point sees both: the two points that see
every subcommand hold no vault, and every point that holds a vault sees one
command.

---

## 1. What was measured

Everything in this section was read from the tree at `740d7e6`, or executed on
this host on 2026-08-06. Nothing is inferred from prose, and where a task
entry disagrees with the code, **the code is recorded as the fact**.

### 1.1 The contradiction itself

| Fact | Where |
| --- | --- |
| D42's rule: the hook runs *iff the dispatching command already holds an unlocked vault handle*; locked/absent/vault-less ⇒ silent no-op, debug trace only, never unlocks, never prompts, never creates `~/.antseal` | `docs/decisions/D42-vault-encryption-boundary.md:76-83` |
| U24 Accept row 4: *"hook lives in the shared dispatch path — a test enumerates subcommands and asserts each passes through it"* | `tasks/U.md`, `### U24` |
| The two points that see all ten subcommands | `crates/antseal-cli/src/lib.rs:117` (`run::run(&cli)`) and `crates/antseal-cli/src/run.rs:28` (the `match`) |
| Neither holds a vault. `run` takes `&Cli` and nothing else; every handler collects its own passphrase and unlocks | `run.rs:26`; `commands.rs:234`, `:309`, `:348` |
| `UnlockedVault` is neither `Clone` nor `Copy`, deliberately — *"uncontrolled copies defeat zeroization"* | `vault/session.rs:68-75` |
| Production `unlock_vault` call sites: exactly **three** — `seal` (`:234`), `list` (`:309`), `vault export` (`:348`) — plus one inside the import primitive (`vault/export.rs:1240`) | grep over `crates/antseal-cli/src` |
| **`init` holds no handle at the dispatch layer.** `run_init` returns an `InitReport`; the `UnlockedVault` `create_vault` produced is consumed and dropped inside | `init.rs:363-371`, `:208-227` |
| **`vault import` holds no handle at the dispatch layer** either: its only unlock is the self-verification inside `import_vault` | `vault/export.rs:1240` |
| So D42's consequence paragraph — which lists `init` and `vault import` among the commands that *"unlock by need"* and would therefore run the hook — is **wrong about both**, and today only three commands can arm it | D42:96-104 vs. the four rows above |

### 1.2 The `list` write problem, and the fact the brief did not have

| Fact | Where |
| --- | --- |
| `list` deliberately takes no `VaultLock`: *"making `list` wait on a running seal would turn the one command you reach for when something looks wrong into the one command that hangs"* | `commands.rs:297-305` |
| Every mutating store API assumes the caller holds the lock | `vault/store.rs:61-66` |
| `put_anchor` is mutating (`create_dir_all` → `seal_record` → `atomic_write`) | `vault/store.rs:669-690` |
| **`VaultLock::acquire` is already a try-lock.** `file.try_lock()`; `TryLockError::WouldBlock` ⇒ `LockError::Held` ⇒ `CliError::VaultLockHeld`, exit **15**. It never waits | `vault/lock.rs:93-118`; `error.rs:330` |

That last row changes the shape of the question. `list`'s doc comment names
*hanging* as the harm, and hanging is not what taking the lock would cost —
**failing** is. The decision is unaffected in outcome (a `list` that exits 15
during a concurrent seal is as bad as one that hangs, arguably worse because
it looks like an error), but the argument recorded in the tree is about a
mechanism the tree does not have, and any future reader reasoning from it will
reason wrongly.

### 1.3 Q16's gate in the CLI test harness — **measured, not read**

`deny_reason()` is `decide(cfg!(test), env)` and `cfg!(test)` is evaluated in
*`antseal-anchor`'s own* compilation (`http/offline.rs:106-134`). The policy
doc already states the consequence in words — *"The environment arm covers
what `cfg(test)` structurally cannot — **other crates' integration-test
binaries**"* (`docs/testing/anchor-ci-policy.md` §3.1) — and
`check-anchor-net.py`'s R1 covers exactly two venues: every committed workflow
and `scripts/local-gate.sh` (`check-anchor-net.py:48-49`, `:114-134`). Nothing
in `crates/antseal-cli/tests/` sets the variable.

A temporary probe was compiled into `crates/antseal-cli/tests/` and run, then
removed:

```
$ cargo test -p antseal-cli --test <probe> -- --nocapture
D99-PROBE env=None deny_reason=None
```

**In a bare `cargo test -p antseal-cli` with no environment, the gate is
disarmed.** This is the highest-risk item in the decision and it is now a
measurement rather than a reading.

The existing CLI-side defence is a **source scanner**
(`anchor_stage.rs:806-825`, `no_test_source_names_a_live_anchor_endpoint`),
which sweeps test sources for `DEFAULT_LIST_ROUTES` and three `LIVE_HOSTS`.
It cannot see the hook's exposure at all: the hook's URIs come out of a
**stored `.ots` artifact**, not out of any source text, and A42's allowlist
admits the real calendar hostnames by design. That is the Q16 §2 violation
verbatim — *"the suite drove the production upgrade path with the committed
`.ots` artifact, whose pending URIs are the real calendar hostnames … and
**every assertion passed**"* — waiting to recur one crate over.

### 1.4 Feature unification — the evidence, not intuition

Four measurements, all on this host:

| Measurement | Result |
| --- | --- |
| `cargo tree -p antseal-cli -e normal` | `antseal-anchor` appears once, `default` only |
| `cargo tree -p antseal-cli -e features` | `antseal-anchor feature "test-util"` appears **only** under the `[dev-dependencies]` section |
| Fingerprints (`target/debug/.fingerprint/antseal-anchor-*/lib-antseal_anchor.json`) | two live feature sets: `["default"]` and `["default","test-util"]` |
| `cargo build -p antseal-cli -v` vs. `cargo test -p antseal-cli --test cli_surface -v`, both linking the **`antseal` binary** | `--extern antseal_anchor=…-be5a863c07dc6db5.rlib` (`["default"]`) vs. `…-8eb3f75656c1dff3.rlib` (`["default","test-util"]`); `md5sum target/debug/antseal` differs between the two and cargo hard-link-swaps it |

So: **the `antseal` binary that `CARGO_BIN_EXE_antseal` points at during
`cargo test` links a `test-util`-enabled `antseal-anchor`; the product binary
does not.** A `test-util`-gated item cannot enter `cargo build`,
`cargo build --release` or `cargo install` output.

And the fifth measurement, which kills the obvious fix:

```
$ cargo test -p antseal-anchor              --test no_real_network -v   →  …-13cb99f81329f81f.rlib  ["default"]
$ cargo test -p antseal-anchor -p antseal-cli --test no_real_network -v →  …-8eb3f75656c1dff3.rlib  ["default","test-util"]
```

Under `cargo test --workspace` — which is exactly what CI's `test` job runs
(`ci.yml:160`) — `antseal-anchor`'s own `tests/no_real_network.rs` links the
**`test-util`-enabled** rlib, because feature unification is per-invocation
and workspace-wide. That test's whole purpose is an A/B in which the
**disarmed** arm reaches the network (`no_real_network.rs:110-116`). A
compile-time deny arm carried by `test-util` — or by any feature any workspace
member enables on a dev-dependency edge — therefore turns the workspace's only
proof that the environment arm works into a permanently red test. **The
compile-time route is dead, and it is dead by measurement.**

### 1.5 The test seam

| Fact | Where |
| --- | --- |
| `upgrade_pending_with(…, resolve)` is `#[cfg(test)] pub(crate)`, with a `#[cfg(not(test))]` private twin | `ots/engine.rs:265-302` |
| `UpgradeTarget::loopback_for_tests` is `#[cfg(test)] pub(crate)` | `ots/upgrade.rs:123-136` |
| A42's allowlist requires `https`, a bare host, no port ⇒ `from_pending_uri` can never admit `http://127.0.0.1:<port>` | `ots/upgrade.rs:104-115`; A42's `Do` row |
| The recorded reason the seam exists: the suite once drove the real path and *"quietly contacted live calendars on every run — a Q16 violation that passed every assertion"* | `ots/engine.rs:271-279` |
| `antseal-cli` already takes `antseal-anchor = { features = ["test-util"] }` on its **dev** edge; `testing::{stub::StubServer, replay::{calendar, CalendarBehaviour}}` are reachable from its integration tests | `antseal-cli/Cargo.toml` dev-deps; `anchor_stage.rs:33-35` |

So U23's *"`--upgrade` against A's mock calendar transitions pending →
attested and persists the upgraded `.ots`"* and U24's *"upgrades a pending
fixture via mock-A and persists it"* are, today, **unexecutable from
`antseal-cli` by any route**.

### 1.6 What the hook needs from the vault, and what it can get

| Fact | Where |
| --- | --- |
| `PendingWork` requires `anchor_digest: [u8; 32]` | `ots/engine.rs:72-83` |
| `WorkRecord` carries `work_id` but **no `anchor_digest`** | `vault/store.rs:191-224` |
| `anchor_digest` = SHA-256 over the whole manifest envelope, recoverable only from `plan.manifest_bytes` (journal entry 1) | `manifest/ids.rs:165`; `pipeline/resume.rs:178-183`; `journal.rs:439` |
| Journal entries 0–2 are **always exported**, including for `Complete` works — the D43 cache exclusion is scoped to `entry >= UNIT_ENTRY_BASE` (S29's amendment) | `vault/export.rs:767-791` |
| Anchor slots are **always exported**, unconditionally | `vault/export.rs:793-800` |
| `list_works` is deterministic: ascending by seal-id bytes | `vault/store.rs:481-512` |
| `UpgradeBudget::opportunistic()` = 3 s / **4 polls**, sized to D54's calendar count so *"the next invocation starts on the next work rather than re-treading the first"* | `ots/engine.rs:117-127` |
| The engine iterates `works` in the order given and **returns** at the first budget exhaustion | `ots/engine.rs:322-345` |
| `UpgradePoll::is_repollable()` is `false` for `NotFound` — the engine knows a commitment will never upgrade, and persists nothing about it | `ots/upgrade.rs:166-171` |

Two consequences, both of which the riders act on. First, `anchor_digest`
**is** recoverable for every work that has a plan record with
`manifest_bytes`, including after a `vault import` — so `listing.rs:9-18`'s
present-tense claim that *"a `vault import`ed **complete** work carries no
journal entries at all"* is **stale post-S29** and is exactly the fact the
hook's read path would be designed around. Second, nothing rotates the
starting point, so with `max_polls = 4` the first work by seal-id byte order
consumes every invocation's budget for ever — and a commitment the calendar
answers `NotFound` for consumes it *permanently*, starving every work behind
it.

### 1.7 Two committed instruments the ruling moves under

| Fact | Where |
| --- | --- |
| `the_sinkless_journal_constructor_is_named_in_exactly_one_production_file` asserts `VaultJournal::new(` appears in production sources **only** in `seal_session.rs` | `seal_session.rs:310-325` |
| D97 R3 specifies `apply_upgrade(journal: &dyn SealJournal, …)`, called by **both** U23 and U24 | `D97…md:296-303` |
| `SealJournal` has `put_anchor` but **no** `get_anchor`; D97 R4's read-modify-write therefore reads through `WorkStore`/U47 and only writes through the journal | `journal.rs:824`; `vault_journal.rs:297-301` |
| `a_session_holds_exactly_two_handles_to_one_vault` asserts `Arc::strong_count == 2` and states *"A third would mean something outlives the command holding the vault key"* | `seal_session.rs:378-399` |

Both are live constraints on any hook design, and neither was in the brief.

---

## 2. The register's lean, attacked where it is strongest

The lean is *put the hook in the shared dispatch path*, on the authority of
U24's own Accept. Two ways to make that satisfy D42 were examined seriously,
because both are better ideas than they look.

### 2.1 A scoped guard registered at unlock time

`unlock_vault` is genuinely shared and genuinely holds the handle. It is also
the wrong place, on four independent grounds, and the fourth is fatal:

1. **Running inside `unlock_vault` is the pre-output position `engine.rs`
   rejects** at length: 3 s before `antseal list` prints anything it already
   had in hand (`ots/engine.rs:12-20`).
2. **A `Drop`-based guard fires too early in exactly the mode that matters.**
   The handler's `UnlockedVault` drops when the handler returns, and under
   `--json` the single envelope document is printed *after* that, by
   `main_entry` (`lib.rs:118-124`). A drop hook is post-output in plain mode
   and pre-output in machine mode — an asymmetry with no defence.
3. **`Drop` also runs during unwinding**, cannot return an error, cannot be
   given the config/endpoints/clock it needs, and cannot decline.
4. **It would fire in every test in the tree.** `unlock_vault`/`create_vault`
   have ~40 call sites in `crates/antseal-cli/tests/` and `src/`'s own test
   modules. With Q16's gate measured disarmed (§1.3), a hook attached to
   *unlocking* turns every vault test in the workspace into a calendar client.
   This is not a hypothetical; it is §1.3 multiplied by forty.

Unlock is where the *handle* is. It is not where the *invocation* ends, and
the hook is a property of the invocation ending.

### 2.2 Inverting the flow — handlers report their handle upward

This survives, and it is the ruling. It is worth being precise about what it
costs, because it costs something real:

- The vault key's lifetime is **extended past the handler's return**, to the
  end of `main_entry`. It is bounded (§4's budget), it is a **move**, not a
  copy — `UnlockedVault` stays `!Clone` and there is still exactly one
  `VaultKey` in the process — and the key was alive for the whole command
  already. But `seal_session.rs:378-399` asserts `Arc::strong_count == 2` and
  says in its own doc that a third handle *"would mean something outlives the
  command holding the vault key"*. Under this ruling something does, on
  purpose. The assertion stays green (it is built over a test-local session),
  but its stated claim becomes false about the product. **That doc comment is
  amended, and the amendment is the honest record of the cost.**
- Each vault-holding handler acquires one obligation (hand the handle up).
  A handler that forgets is a command that silently skips the hook — which is
  precisely the property Accept row 4 was reaching for. R2 makes forgetting
  impossible to express.

---

## 3. Ruling

**The hook runs at the end of `main_entry`, after the exit code is a value and
after every byte of output has been written, over whatever vault handle the
dispatched command moved into a slot the dispatcher owns.**

```rust
// crates/antseal-cli/src/lib.rs, main_entry — replacing lines 117-128.
let vault_slot = upgrade_hook::VaultSlot::default();
let code = match run::run(&cli, &vault_slot) {
    Ok(outcome) => {
        if cli.globals.json {
            println!("{}", machine::success_envelope(command, network, outcome.json));
        }
        ExitCode::SUCCESS
    }
    Err(err) => fail(network, &err),
};
// D42 + A15: after the answer, never before it; after the host command's
// VaultLock is released, so the hook can take its own; and after `code` is a
// value, so no hook outcome can reach the exit status.
upgrade_hook::run_after_output(&vault_slot, &config, cli.globals.network);
code
```

Three things are forced by this position rather than preferred, and each is a
separate argument:

1. **It is the only point that is post-output in both modes.** In plain mode
   handlers print through `Ui::line` before returning; in `--json` mode the
   one document is printed here. Any earlier point is pre-output for one of
   the two (`commands.rs:41-53`; `lib.rs:118-124`).
2. **It is the only point at which the host command's `VaultLock` is
   released.** `init` and `vault export` hold `_lock` across their handlers
   (`commands.rs:110-111`, `:341-342`) and the lock is a **try-lock** that
   refuses a second acquisition even within one process
   (`vault/lock.rs:14-24`). A hook that ran before the handler returned could
   not take the lock it needs — it would refuse itself.
3. **The exit code is already computed**, so U2's table cannot be perturbed by
   anything the hook does. This is structural, not a discipline.

**U24's Accept row 4 is factually wrong.** A hook at the shared dispatch point
cannot hold a vault; a hook that holds a vault is not at the shared dispatch
point. What row 4 was protecting is the property *no command silently skips
the hook*, and that property is preserved exactly — by R2's single arming
expression, by R1's unconditional call, and by the rewritten test in §5.

---

## 4. Riders (normative; an implementer follows these verbatim)

### R1 — The call site, and nothing else

The hook is invoked from exactly one place: `crates/antseal-cli/src/lib.rs`,
in `main_entry`, in the shape above. It is **not** invoked from `main.rs`
(D34: all product behaviour stays in the library), not from `run.rs`, and not
from any handler.

`main_entry`'s pre-dispatch error returns (config load failure, `lib.rs:100-108`)
stay as they are: no command dispatched, no vault was held, no hook. The hook
runs on every path **through** `run::run`.

The hook function returns `()`. It takes no `Result` and produces none, so
there is no error for a future edit to propagate — the same guarantee
`upgrade_pending` gives one layer down (`ots/engine.rs:31-36`), applied at the
CLI boundary.

### R2 — One arming expression, and a scan that makes forgetting unrepresentable

`run::run` gains a `&VaultSlot` parameter and threads it to every handler.
`VaultSlot` is `RefCell<Option<Arc<UnlockedVault>>>`, owned by `main_entry`.

A vault-holding handler obtains its vault through **exactly one** expression:

```rust
// crates/antseal-cli/src/commands.rs
fn unlock_for_command(
    layout: &VaultLayout,
    passphrase: &SecretBuf,
    slot: &VaultSlot,
) -> Result<Arc<UnlockedVault>, CliError>
```

which unlocks and arms in the same expression. `SealSession::open` changes to
take `Arc<UnlockedVault>` (it wraps in `Arc` on the next line today —
`seal_session.rs:104`), so `seal` uses the same expression as `list` and
`vault export`.

**The scan** (the S36 pattern, `production_files_naming`, proven red against a
planted violation): `unlock_vault(` and `unlock_vault_with_keyfile(` may be
named in production sources of `crates/antseal-cli/src` **only** in
`vault/session.rs` (their definition) and `vault/export.rs` (the import
primitive's self-verification). Any third file is a command that unlocked
without arming, and the assertion message says so.

**`init` and `vault import` do not arm, and this is a correction to D42, not a
deviation from it.** D42's *rule* keys on the dispatching command holding a
handle; measured (§1.1), neither command does — `init` consumes its handle
inside `run_init`, and `vault import`'s only unlock is a self-check inside
`import_vault`. D42's consequence paragraph lists both as hook-running
commands and is wrong about both. For `init` there is nothing to upgrade
anyway (a fresh vault has zero works); for `vault import`, arming would
require either threading the slot through the import primitive's internals or
paying a second ~1 s Argon2id derivation for a vault the user's next command
will unlock properly.

Today the arming set is therefore exactly `{seal, list, vault export}`, and it
grows to `{+ status, show, restore, reveal}` as U23/U27/U20/U28 land. The
enumeration test in §5 asserts the *current* partition, not a hard-coded three.

### R3 — The `list` write problem: the hook takes the lock, late, and declines when contended

`list` keeps its lock-free read. `commands.rs:297-305` stands unamended in
substance; it is untouched by this decision because **the hook is not part of
`list`** — it runs after `list`'s handler has returned and after `list`'s
output is on the wire.

The hook's lock discipline, exactly:

1. **Poll unlocked.** The single-writer lock is never held across network I/O.
   Holding it for up to 3 s + one in-flight call would block every concurrent
   `seal` for that window, which the hook has no right to do.
2. **Take the lock only when there is something to persist** —
   `!UpgradeReport::is_empty()`, which exists for this
   (`ots/engine.rs:236-240`).
3. **Contended ⇒ decline, silently.** `VaultLock::acquire` is already a
   try-lock returning `LockError::Held` (`vault/lock.rs:104-110`); the hook
   traces at `debug` and returns. It never waits, never retries, never
   surfaces. The transitions are recomputed on the next invocation — polls are
   idempotent, and re-polling is what `is_repollable` already assumes.
4. **Compare-and-set under the lock.** Between the read and the write another
   process may have rewritten `ots-pending` — D97's measured stale-group
   hazard, whose live case is the ordinary resume path. After taking the lock,
   re-read the slot and persist **only** if the stored artifact bytes are
   still the ones the transition was computed from (`apply_upgrade` already
   takes `prior: &AnchorArtifact` — D97 R3). Otherwise discard and trace.

**U24's Accept row 1 is wrong in its mechanism and right in its outcome.** It
reads as though `list` performs the upgrade. `list` does not and must not; the
*invocation* does. The rewritten row is in §6.

### R4 — Arming Q16 in the CLI test harness (the highest-risk rider)

**The arm stays the environment variable.** §1.4 measured that every
compile-time alternative reachable from a workspace member's dev-dependency
edge unifies onto the single `antseal-anchor` build unit under
`cargo test --workspace` and therefore reddens
`antseal-anchor/tests/no_real_network.rs`, whose disarmed arm must reach the
network. What changes is that the CLI test harness is made to **guarantee** the
variable, in the only two venues that can reach the hook.

**R4.1 — the spawn venue.** Measured: 12 sites across 9 files construct
`Command::new(env!("CARGO_BIN_EXE_antseal"))` directly; there is no shared
helper (`Process` is an alias for `std::process::Command`). Add one:

```rust
// crates/antseal-cli/tests/common/spawn.rs — included by
// `#[path = "common/spawn.rs"] mod spawn;` so it drags in none of the
// heavy pipeline harness in common/mod.rs.
pub fn antseal() -> std::process::Command {
    let mut c = std::process::Command::new(env!("CARGO_BIN_EXE_antseal"));
    c.env("ANTSEAL_NO_REAL_ANCHOR_NETWORK", "1"); // Q16, docs/testing/anchor-ci-policy.md §3.1
    c
}
```

All 12 sites move to it.

> **Corrected 2026-08-07, by the lane that implemented R4.** The count is
> **11 constructions, not 12**. There are 12 *occurrences* of the macro, but
> `secret_hygiene.rs`'s is `let exe = env!("CARGO_BIN_EXE_antseal");` — a bare
> path read feeding a `/proc/<pid>/cmdline` substring match, not a spawn.
>
> The difference is structural, not cosmetic. Had R4.3's rule been written as
> specified — *"only `spawn.rs` names the variable"* — that one site would have
> forced an exemption list, **and an exemption list is a rule the next caller
> adds itself to**. The helper therefore also exports `antseal_exe()`, that site
> uses it, and the rule stayed flat with zero carve-outs.
>
> R4 also gained a **fourth arm** the decision did not anticipate:
> `e2e_restore.rs`'s `run_clean_machine` re-executes the test binary with
> `.env_clear()`, stripping the arming **even in CI**, where the workflow arms
> it workflow-wide — and it never names `CARGO_BIN_EXE_antseal`, so the rule as
> specified would have missed it entirely. Fixed, and `env_clear()` is now
> checked. That whole class is **Q118**, this decision's §8 revisit trigger
> arriving immediately rather than later.

**R4.2 — the in-process venue is closed structurally, because it cannot be
closed any other way.** No test source may call `antseal_cli::main_entry`. This
is not a stylistic rule: a test **cannot** arm the variable for its own
process — `std::env::set_var` is `unsafe` in edition 2024 and the workspace
denies `unsafe_code` (`Cargo.toml`, `[workspace.lints.rust]`), and it would be
racy across libtest's threads even if it were not. That constraint is already
recorded verbatim at `no_real_network.rs:15-22` as the reason *that* test uses
a child process. Measured: **zero** test sources call `main_entry` today, so
the rule costs nothing to adopt and everything to adopt late.

`main_entry`'s doc comment (`lib.rs:52-53`, *"Testable — it never calls
`process::exit`"*) is amended to say what it now means and why: the entry is
testable **through the binary**, because it reads the process environment
(`config::load` → `VaultLayout::resolve`, `config.rs:163-169`) and, after this
decision, dials calendars. The claim was already narrower than it read — it
was only ever true for argv→exit-code mapping with no vault — so this is a
clarification, not a retraction.

**R4.3 — enforcement, not convention.** `scripts/check-anchor-net.py` gains a
rule **R4** (its R1/R2/R3 pattern, with planted faults run before every green
verdict):

- the only construction naming `CARGO_BIN_EXE_antseal` anywhere in the
  workspace is inside `crates/antseal-cli/tests/common/spawn.rs`, and that
  file sets `ANTSEAL_NO_REAL_ANCHOR_NETWORK`;
- no source under `crates/*/tests/` names `main_entry`;
- planted faults: (a) delete the `env(…)` line in the helper; (b) plant a bare
  `Command::new(env!("CARGO_BIN_EXE_antseal"))` in another test file; (c)
  plant a `main_entry(` call in a test source. Each must go red naming the
  file.

R1's arming inventory and its summary line extend to name the helper as a
third venue beside the workflows and `local-gate.sh`.

**R4.4 — the injection belt, for the hook's own suite.** The hook's production
endpoint/client construction lives behind exactly one constructor —
`upgrade_hook::HookContext::production(&Config, NetworkId)` — which is added to
`anchor_stage.rs`'s `DEFAULT_LIST_ROUTES` list, so no test source may name it.
Every test builds a `HookContext` over `127.0.0.1:0` stubs, exactly as
`AnchorStageConfig` is built today, and for the reason `common/mod.rs:61-73`
already records: a defaulted endpoint field is how a test reaches a live
service by omission.

**Note for the implementer, and it is good news.** With R4.1 in place, the
hook costs the spawned-binary suites approximately nothing: every poll is
refused *before DNS* with `RetryVerdict::Stop`
(`docs/testing/anchor-ci-policy.md` §3.1), so `machine_mode.rs`'s ~40-cell
abort-not-hang harness pays microseconds, not the 3 s budget.

### R5 — The test seam: two `#[cfg(test)]` items become `test-util`

`antseal-anchor` exports, under `#[cfg(any(test, feature = "test-util"))]`
instead of `#[cfg(test)]`:

- `ots::engine::upgrade_pending_with` (as `pub`, keeping the
  `#[cfg(not(...))]` private twin for the production build);
- `ots::upgrade::UpgradeTarget::loopback_for_tests` (as `pub`), renamed
  nothing — the name is the documentation.

**What A42's allowlist protects, and whether this weakens it.** A42 protects
the *product* from a server-side request forgery driven by a stored artifact
an attacker with disk access can edit (A42 `Notes`; `ots/upgrade.rs:88-95`).
The invariant it buys is: *no upgrade poll is issued against a URI read out of
a stored artifact without `classify_upgrade_uri` having run.* That invariant
is a property of the **resolver**, not of the target type, and the production
resolver is unchanged — `upgrade_pending` still closes over
`UpgradeTarget::from_pending_uri` (`ots/engine.rs:255-262`).

**Measured: it cannot leak into a shipped binary.** §1.4 — `cargo build
-p antseal-cli` links the `["default"]` anchor rlib; `cargo tree -e features`
shows `test-util` only under `[dev-dependencies]`; the two binaries differ.
The residual is that a `test-util` build contains a constructor that can mint
a `UpgradeTarget` over an arbitrary base, and that build includes the
`antseal` binary produced *during* `cargo test`. Closed by a scan of the same
S36 shape: `loopback_for_tests` and `upgrade_pending_with` have **zero**
production call sites in `crates/antseal-anchor/src` and
`crates/antseal-cli/src`, proven red against a planted call.

The house rule this rides on is already written down —
`antseal-core/Cargo.toml:10`, *"DEV-DEPENDENCY EDGES ONLY for `test-util`"* —
and `check-anchor-net.py` R4 gains its enforcement: no workspace manifest may
name `antseal-anchor`'s `test-util` on a normal-dependency edge. Without that,
a future crate taking the edge would silently ship the bypass.

The CLI side needs **no** feature. `upgrade_hook::run_with(ctx: &HookContext)`
takes its resolver from the context; `HookContext::production` supplies the
real one and is scan-forbidden in tests (R4.4).

### R6 — What the hook does with a work it cannot read

Every one of these is a **skip**, traced at `debug`, on the hook's own target
(`antseal_cli::upgrade_hook`), naming the work by seal-id hex and the reason;
never `warn`, never stderr copy, never stdout, never a changed exit code:

| Condition | Where it arises |
| --- | --- |
| `StoreError::NewerRecord` on the meta record, or `JournalError::NewerRecord` on the plan or the anchor record | a vault written by a newer build; live from D97's `SEAL_JOURNAL_VERSION` 1 → 2 onward |
| no plan record, or `plan.manifest_bytes == None` | a work killed before the manifest was built (`journal.rs:439`) — no `anchor_digest`, so no `PendingWork` |
| `Corrupt` / `VaultAuthFailure` on any record | tamper or corruption |
| `AnchorArtifact::decode` refuses (unknown key, unregistered kind) | `pipeline/anchors.rs:163`, `:170` |
| no `ots-pending` slot, or a slot with no pending attestations | the ordinary case for a TSA-only or fully-upgraded work |

`debug` and not `warn` is a ruling, and the reason is that the hook is
opportunistic: a `warn` on every invocation, for a condition with no action
attached, is a nag the user cannot act on. **`status <work-id>` (U23) is the
command that must report a corrupt or future-versioned anchor record loudly**,
because that is a command the user ran *about that work*. U23's Accept gains
no new row here — its existing per-anchor rendering row covers it — but the
division of labour is recorded so neither side assumes the other is shouting.

**Nothing reaches stdout**, and it is structural on three counts: the engine
prints nothing by construction (`ots/engine.rs:41-44`), `init_tracing` binds
the subscriber to stderr (`lib.rs:132-138`), and the hook runs after the
single `--json` document is already written, so even a stray byte would be
*after* the document rather than inside it. The assertion is a test that byte-
compares stdout for one command run with and without a hook-triggering
fixture.

### R7 — Which works the hook considers

**`WorkState::Complete` only.** An incomplete work is a D45 resume candidate,
and its `ots-pending` slot is rewritten wholesale by the next resume's fresh
submission (`pipeline/resume.rs:382-384`) — D97's measured stale-group hazard.
Upgrading an artifact that is about to be replaced spends the budget on
nothing at best, and manufactures the `invalid`/`anchor-ots-header-uncommitted`
pairing D97 §1 measured at worst. `Abandoned` works are skipped for the same
budget reason.

This is the **hook's** restriction, not the engine's. U23's `status --upgrade`
is synchronous, user-requested and single-work, and may widen it; that is
U23's call to make and record, not this decision's.

### R8 — Ordering, `--json`, and the exit code

- The hook is invoked after the exit code is a value (R1). It cannot change
  it: there is no expression in scope through which it could.
- The hook writes nothing to stdout (R6).
- **The hook runs in machine mode too.** MVP-SPEC.md:35 and D42 both say
  *every* invocation, and D51/U3's contract is about which bytes go where and
  which code is returned — not about wall time. Carving out `--json` would
  also carve out every non-TTY-stdin invocation (D51's machine-mode
  determination is `--json` ∨ non-TTY stdin ∨ `--passphrase-fd 0`), which
  would silently disable the hook for anyone piping input. The cost is
  recorded as a residual risk, not hidden: a shell `$(antseal list --json)`
  waits for process exit, so the post-output placement buys a **script**
  nothing, and the invocation can be up to `budget.total + one in-flight call`
  ≈ 6 s late to exit (`ots/engine.rs:38-47`).
- A **panic** in the hook would turn exit 0 into 101. No `catch_unwind`: the
  hook is written under library discipline (`clippy::unwrap_used` is `warn`
  and CI's `-D warnings` hardens it), errors are structurally swallowed rather
  than caught, and a panic is a bug to fix rather than a state to hide.
  Recorded as a residual.

### R9 — The budget must rotate

Measured (§1.6): `list_works` is a stable byte order, the engine returns at the
first exhaustion, and `max_polls` is 4. The first work therefore consumes every
invocation's budget until it upgrades — and a commitment the calendar answers
`NotFound` for (*"it will never upgrade"*, `ots/engine.rs:170-175`) consumes it
**permanently**, starving every work behind it for the life of the vault.

The hook orders its candidate works by seal-id byte order (as `list_works`
returns them) and starts at index `fetch_date % n`, wrapping. No persisted
state, no write on a read-only command, and deterministic under a pinned
`fetch_date` so a test can assert the rotation. This bounds starvation rather
than eliminating it; the elimination needs a remembered `NotFound`, which needs
a vault write on every invocation, and that is **U57** below.

### R10 — `apply_upgrade` takes the store, not the journal

D97 R3 specifies
`apply_upgrade(journal: &dyn SealJournal, seal_id, slot, prior, applied)`, and
the sibling lane has **already landed exactly that signature** in the working
tree (`pipeline/anchors.rs:386-392`, with `StoredAnchors` as U47's reader), so
this is a live collision rather than a hypothetical one.

Measured (§1.7): `VaultJournal::new(` is asserted to appear in exactly one
production file, `seal_session.rs`, and the hook has no legitimate way to
obtain a `&dyn SealJournal` — a `SealSession` would mint a D37 receipt sink
nobody arms, on a path that never pays, against S36's own *"the non-paying
commands … never need a session at all"*.

`apply_upgrade` therefore takes `&WorkStore<'_>` and `&mut R: TryCryptoRng`,
which is what it actually needs: `put_anchor` is a `WorkStore` method, and the
function uses no state machine, no plan, no receipt and no sink. **Everything
else in D97 R3 is untouched** — one write site, in `pipeline/anchors.rs`,
performing exactly one `put_anchor`, called by both U23 and U24. D97's U56
(the call-site count test) must count both spellings: `journal.put_anchor` in
`resume.rs:382-384` and `store.put_anchor` inside `apply_upgrade`.

---

## 5. The rewritten Accept row 4, and what it now proves

The property row 4 was reaching for is *no command silently skips the hook*.
Split into the two claims that are actually checkable, each against the venue
that can see it:

**(a) Every subcommand reaches the hook — asserted against the real binary.**
`machine::ALL_COMMAND_NAMES` (10) and `machine::MINIMAL_ARGV` (10) are the
enumeration axis, and `machine_mode.rs`'s abort-not-hang harness is the
template: *"every command × {plain, `--json`} × closed stdin against the REAL
binary under a real watchdog"*. Spawn each of the ten with
`RUST_LOG=antseal_cli::upgrade_hook=debug` through R4.1's helper, and assert
the hook's trace line is present on stderr for every one — in the **armed**
form for the commands that unlocked, in the **not-armed** form for the rest.
That asserts D42's rule in both directions, per command, which the original row
never did, and it asserts it about the shipped dispatch path rather than a
library path.

**(b) A vault-holding command actually upgrades and persists — asserted
in-process, with everything injected.** Drive `upgrade_hook::run_with` over a
`HookContext` built from a `StubServer` running
`calendar(&CalendarBehaviour::Upgraded { .. })`, R5's loopback resolver, a real
`UnlockedVault` over a fixture vault carrying a pending `.ots`, and a pinned
`fetch_date`. Assert: the slot's bytes changed, D97's keys 4/5/6 are present,
a re-run is a no-op, and the host command's stdout and exit code are
unaffected. This is U24 Accept row 1 and U23 Accept row 2 discharged by one
seam.

Neither test calls `main_entry` (R4.2), and neither names a live host.

---

## 6. What this amends — the exact rows

**`tasks/U.md` U24, Accept row 1** — replace:

> - running unrelated commands (`list`, `show`) upgrades a pending fixture via mock-A and persists it; primary command output unchanged

with:

> - an **invocation** of a vault-holding command (`list` at M2; `show`/`status` as they land) upgrades a pending fixture via a `127.0.0.1:0` calendar stub and persists it, **after** the command's own handler has returned: the hook takes the U5 single-writer lock itself, only when it has a transition to write, and declines silently when it is contended (D99 R3). `list` still takes no lock (`commands.rs:297-305` stands). Primary command output and exit code unchanged, asserted by byte-comparing stdout.

**`tasks/U.md` U24, Accept row 4** — replace:

> - hook lives in the shared dispatch path — a test enumerates subcommands and asserts each passes through it

with:

> - the hook is invoked from exactly one place — `main_entry`, after the exit code is computed and all output is flushed (D99 R1) — and a test enumerates `machine::ALL_COMMAND_NAMES` against the **real binary** with `RUST_LOG=antseal_cli::upgrade_hook=debug`, asserting the hook's trace appears for every subcommand: in its *armed* form for commands that unlocked, its *not-armed* form for the rest (D42's rule, both directions, per command). **The original row was factually unsatisfiable**: neither point that sees all subcommands holds a vault, so a hook there cannot satisfy D42 (D99 §1.1).

**`tasks/U.md` U24, Deps** — add **U47** (the slot reader; D97 makes it a hard
predecessor), **D97**, **D99**, and **Q16** (the arming R4 extends).

**`tasks/U.md` U23, Accept row 2** — append:

> — executable only from D99 R5: `upgrade_pending_with` and `UpgradeTarget::loopback_for_tests` move from `#[cfg(test)] pub(crate)` to `feature = "test-util"`, because A42's allowlist requires `https` + bare host + no port and can therefore never admit a loopback stub through the real constructor (`ots/engine.rs:265-279`).

**`docs/decisions/D42-vault-encryption-boundary.md`**, the consequence
paragraph (`:96-104`) — append:

> **Corrected 2026-08-06 by [D99](D99-upgrade-hook-placement-and-test-seam.md) §1.1/R2.** The rule above is unchanged. The enumeration under it is wrong about two of its commands: **`init` and `vault import` hold no handle at the dispatch layer** — `init` consumes the `UnlockedVault` inside `run_init`, and `vault import`'s only unlock is the self-verification inside `import_vault`. The arming set is therefore `{seal, list, vault export}` today, growing with `status`/`show`/`restore`/`reveal`.

**`docs/decisions/D97-…md` R3** — `apply_upgrade` takes `&WorkStore<'_>` +
`&mut R: TryCryptoRng`, not `&dyn SealJournal` (D99 R10). Everything else in R3
stands.

**`crates/antseal-cli/src/lib.rs:52-53`** — the `main_entry` doc comment, per
R4.2.

**`crates/antseal-cli/src/seal_session.rs:378-399`** — the doc comment on
`a_session_holds_exactly_two_handles_to_one_vault`, per §2.2: a third handle
now exists on purpose, bounded by the hook's budget, and the assertion is about
a session in isolation rather than about the product.

---
- `docs/decisions/README.md` — this decision's index row. **Applied 2026-08-11**, executing [D119](D119-decision-index-identity-and-the-index-row-sections.md) §5 step 4; the former `## Index row` section is demoted to this line under D119 RULING 4, and RULING 6 puts the row in the act that commits the record.

## 7. Measured vs. assumed

**Measured** — executed on this host on 2026-08-06, or read at the cited
line: `deny_reason() == None` in a bare `cargo test -p antseal-cli`
(§1.3, probe compiled and removed); the four feature-unification measurements
and the two rlib hashes (§1.4); that `no_real_network.rs` links the
`test-util` rlib once `antseal-cli` is in the selection (§1.4); the try-lock
in `VaultLock::acquire`; the three production `unlock_vault` sites and the two
commands that hold no handle; `anchor_digest`'s sole source and the S29 export
scoping; `list_works`'s ordering; the two S36 scans and the `strong_count == 2`
assertion; `SealJournal`'s missing `get_anchor`; the 12 spawn sites and the
absence of a shared helper; the absence of any `main_entry` caller in tests;
`gate-features.sh --check-partition`'s requirement that every declared feature
be classified.

**Assumed, and flagged:** that the `run::run(&cli, &vault_slot)` threading
compiles without a borrow conflict against `main_entry`'s existing `fail`
closure (it should — `fail` borrows `cli` and `command` immutably and
`VaultSlot` is a `RefCell`), and that changing `SealSession::open` to take
`Arc<UnlockedVault>` touches only its two production callers and its own test
module. Both are mechanical and the implementing lane confirms them. **No
`cargo clippy` or full `cargo test` was run** — this host is 2 cores with a
second planner active, and the ruling rests on the measurements above rather
than on a build.

---

## 8. Residual risks and revisit triggers

- **Machine-mode exit latency.** A script's `$(antseal list --json)` waits for
  process exit, so the post-output placement buys it nothing and the
  invocation can be ~6 s late (R8). No opt-out exists and U1's canonical CLI
  surface is frozen, so the available channel is a config key — **U58**.
  Trigger: any report of scripted use, or U3's contract acquiring a timing
  clause.
- **A hook panic turns exit 0 into 101** (R8). Mitigated by discipline, not by
  structure. Trigger: the first one.
- **The vault key outlives the handler** by up to the hook's budget (§2.2).
  Bounded, single-instance, zeroizing on its one drop — but it is a real
  extension and the S36 doc comment that denied it is being amended rather
  than quietly outlived. Trigger: any change that lets the slot outlive
  `main_entry`.
- **Starvation is bounded, not removed** (R9). A permanently-`NotFound`
  commitment still costs one rotation slot per invocation. Trigger: U57.
- **R4's enforcement is static.** `check-anchor-net.py` R4 refuses a bare
  spawn and a test-side `main_entry`; it cannot refuse a *new crate* whose
  tests drive the hook by some route nobody has thought of. The runtime gate
  remains the only thing that fails a call, and it remains armed only by the
  environment. Trigger: a fourth workspace member acquiring integration tests
  that link `antseal-anchor`.
- **`listing.rs:9-18` is stale.** Its present-tense claim that an imported
  complete work carries no journal entries is false post-S29
  (`vault/export.rs:767-791`), and the same sentence appears in TODO.md's U19
  row. Harmless where it sits (the fallback it justifies is still correct
  defensively) but it is exactly the fact the hook's read path depends on —
  **Q117**.

---

## 9. Discovered work

Ids from this planner's block only, taken above D97's allocations (U53–U56,
Q116) so the two lanes do not collide.

### U57 — The hook re-polls commitments the calendar has said will never upgrade
- Milestone: M2 | Size: S | Deps: U24, D99 R9
- Discovered by: **D99 §1.6** (2026-08-06)
- Problem: `UpgradePoll::is_repollable()` is `false` for `NotFound` — *"the
  calendar does not know this commitment — it will never upgrade"* — and
  nothing persists that. With `max_polls = 4` and a stable work order, one such
  commitment consumes an invocation's whole budget for the life of the vault.
  D99 R9's rotation bounds the damage to one slot per invocation; it does not
  remove it.
- Do: decide whether a per-anchor "dead calendar route" memory is worth a vault
  write. It is a write on every invocation, which means the lock on every
  invocation, which is what D99 R3 spends effort avoiding — so the answer may
  legitimately be "no, and record why".
- Accept: either the memory exists and a `NotFound` route is polled at most
  once per calendar per work, or the decision not to have one is recorded with
  its reason in `ots/engine.rs`'s module docs.

### U58 — No way to turn the opportunistic hook off
- Milestone: M2 | Size: XS | Deps: U24, U4
- Discovered by: **D99 R8** (2026-08-06)
- Problem: the hook adds up to `budget.total + one in-flight call` (~6 s) to
  every vault-holding invocation's *exit*, in every mode. A script polling
  `list --json` pays it every time, and the post-output placement — which is
  what makes the delay invisible to a human — buys a program nothing. U1's
  canonical CLI surface is frozen, so no flag is available.
- Do: add a `[anchors] opportunistic_upgrades = false` config key (U4's
  override-slot mechanism, validated at load like `tsa_urls`), defaulting to
  on. Not an env var: D41's channel discipline puts operator preferences in
  config.
- Accept: the key parses, defaults to on, is honoured by the hook, and appears
  in the config documentation; the hook's debug trace names the key when it is
  what suppressed the pass.

### Q117 — `listing.rs`'s import claim is stale post-S29
- Milestone: M2 | Size: XS | Deps: none
- Discovered by: **D99 §1.6** (2026-08-06)
- Problem: `crates/antseal-cli/src/listing.rs:9-18` states that *"a `vault
  import`ed **complete** work carries no journal entries at all (U12 applies
  D43 §3's cache exclusion to the whole journal area)"*. Measured false:
  `vault/export.rs:767-791` exports entries 0–2 unconditionally; only
  `entry >= UNIT_ENTRY_BASE` is excluded for a complete work. TODO.md's U19 row
  carries the same sentence. It is load-bearing for D99 because the hook
  recovers `anchor_digest` from journal entry 1.
- Do: correct both, keeping the coarse-tag fallback (it is still right
  defensively, and pre-S29 exports exist in principle) but stating the real
  reason.
- Accept: neither text asserts the exclusion covers entries 0–2; the S29
  amendment is cited.

### Q118 — `commands.rs`'s `list` rationale names a failure mode the lock cannot produce
- Milestone: M2 | Size: XS | Deps: none
- Discovered by: **D99 §1.2** (2026-08-06)
- Problem: `commands.rs:297-305` justifies `list`'s lock-free read by saying
  the lock would make `list` *"the one command that hangs"*. `VaultLock::acquire`
  is a try-lock (`vault/lock.rs:104-110`): it would make `list` **fail** with
  `VaultLockHeld` (exit 15), not hang. The conclusion is unchanged and is
  reaffirmed by D99 R3; the stated mechanism is wrong, and a future reader
  reasoning from it will reason wrongly.
- Do: correct the sentence to name the real cost.
- Accept: the doc names `VaultLockHeld`/exit 15; the decision to stay lock-free
  is unchanged.
