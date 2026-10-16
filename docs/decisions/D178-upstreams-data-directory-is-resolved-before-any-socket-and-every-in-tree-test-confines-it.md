# D178 — Upstream's data directory is **resolved before any socket**: a path upstream would **panic on**, or would **write into the working directory**, is refused with class 23; every in-tree test **confines it** with one cargo `[env]` entry; and the product's write is **kept and documented**

- **Status: RESOLVED. The row's panic holds and its predicate was wrong in both
  directions; one cargo entry replaces the per-venue redirection the row implied, while
  setting the variable in-process is unbuildable; and two of the row's venue claims are
  false or too wide.**
  - **The panic holds, on a different predicate.** Pinned `ant-core` 0.5.0 never asks the
    password database: its own `home_dir()` reads `HOME`, then `USERPROFILE`, and
    `data_dir()` unwraps it. A byte-identical transcription panics under `env -i` even with
    `USER` and `LOGNAME` set and a passwd entry present. But `USERPROFILE` alone prevents
    the panic; a `HOME` that is not UTF-8 panics although set; and an empty or relative
    `XDG_DATA_HOME` or `HOME` makes upstream write `ant/client_adaptive.json` **into the
    working directory**. `ant-core` 0.12.0's lookup is identical. §1.1.
  - **The panic comes after dialing.** `Client::connect` creates and starts the node before
    it builds the controller that computes the path — and antseal's own vault lookup uses
    std's passwd fallback, so an environment-cleared process finds the real vault and then
    panics inside upstream with its peers already contacted. §1.1.
  - **The file is real and shared**: three concurrency values and no peers, last written
    inside wave 36's devnet suite window, in a directory that predates antseal by three
    months and holds the developer's own upstream payment locks — antseal's devnet runs
    rewrite a file in a real user's `ant` state. The default-feature gate left it alone.
    §1.2.
  - **XDG is ignored on macOS and Windows — true from source; the consequence dissolves**:
    no hosted job there builds a storage client. §1.3.
  - **Setting `XDG_DATA_HOME` in-process is unbuildable** — edition 2024 makes `set_var`
    unsafe and `unsafe_code` is denied — and would move real users' state. **One mechanism
    that is not N venue edits exists**: cargo's `[env]` in the existing
    `.cargo/config.toml`, measured to reach test processes and their children. §1.4.
  - **Two venue claims fall**: *"which an `env_clear()` child reaches"* — the only such
    child re-sets both variables; *"every devnet and heavy-tier test"* — three spawn sites
    already confine. §1.4.
- **Date: 2026-10-16**
- Owner rows: **`S42`** (this record's subject); **`S20`** (the bump checklist's mirror
  bullet, §2 R2).
- Related: **D173** §1.2 (where the row was recorded; it takes a dated addendum), §2 R9 and
  §2 R10 (the storage gate, whose class and site this refusal shares), §2 R11 (the venues'
  arming) and §2 R13 (the not-covered list); **D176** §2 R5 (§2.11 states the write);
  **D99** (why a test cannot arm its own process); **D170** (a dead loopback connect
  returns `Ok`); **D179** (the other change to the same adapter file this wave).

## 0. What was measured against

`HEAD` `fbcee1e`. Planning lane P2 read pinned `ant-core` 0.5.0's `config.rs` and its
client `adaptive.rs` and `mod.rs` from the crates.io sources, and `ant-core` 0.12.0's;
transcribed upstream's lookup byte for byte into a std-only probe and ran it under `env -i`
in eleven environments; ran a second std-only probe of cargo's `[env]`; and stat'ed the
developer's own upstream file before, during and after the baseline gate, reading the gate
processes' environments. Both probes had their own target directory: **no `ant-core`
build, no node and no feature build** ran. This record's lane re-read, before writing, the
upstream lines (sha256 prefixes `eaf30eb8` for `config.rs`, `4f3ea021` for `adaptive.rs`),
the connect order, both constructors' gate calls, the existing `.cargo/config.toml` — which
has no `[env]` table today — every script's `cd` to the repository and every spawn site in
§1.4, and found no antseal source that reads an `XDG_` variable.

## 1. What was measured

### 1.1 Upstream's lookup, transcribed and run

- `ant-core-0.5.0/src/config.rs:11-24`, `data_dir()`: on macOS `home_dir()?` joined with
  `Library/Application Support`; on Windows `APPDATA`, else `home_dir().unwrap()` joined
  with `AppData/Roaming`; otherwise `XDG_DATA_HOME`, else `home_dir().unwrap()` joined with
  `.local/share`; then `ant`. `:87-92`, `home_dir()`:
  `env::var("HOME").or_else(|_| env::var("USERPROFILE"))`, else `HomeDirNotFound`.
- `src/data/client/adaptive.rs:1491` `PERSIST_FILENAME = "client_adaptive.json"`;
  `:1497-1501` `default_persist_path()` = `config::data_dir().ok().map(..)` — public, as
  `ant_core::data::client::adaptive::default_persist_path`; `:1544-1594` writes through a
  temporary file and a `rename`.
- `src/data/client/mod.rs:323-338`: `build_controller` computes the path on **both**
  branches of `adaptive_enabled`; `:420` `Network::new(..).await?` — which creates and
  starts the node (`data/network.rs:68-72`) — runs **before** `:421` `build_controller`;
  `:585-595`: `impl Drop for Client` saves with a 500 ms timeout.
- The probe — a byte-identical copy of `config.rs:1-57` and `:87-92`, `diff` clean — under
  `env -i` with (`$T` a temporary directory):

  | row | environment | result |
  |---|---|---|
  | 1 | nothing | panic `HomeDirNotFound` at the `unwrap`, exit 101 |
  | 2 | `HOME=$T/h2` | `$T/h2/.local/share/ant/client_adaptive.json` |
  | 3 | `XDG_DATA_HOME=$T/x3` | `$T/x3/ant/client_adaptive.json` |
  | 4 | `USERPROFILE=$T/u4` | `$T/u4/.local/share/ant/client_adaptive.json` |
  | 5 | `XDG_DATA_HOME=` (empty) | `ant/client_adaptive.json` — **the working directory** |
  | 6 | `HOME=` (empty) | `.local/share/ant/client_adaptive.json` — **the working directory** |
  | 7 | `XDG_DATA_HOME=rel/dir` | `rel/dir/ant/client_adaptive.json` — **under the working directory** |
  | 8 | a `HOME` holding byte `0xff` | panic, exit 101 |
  | 9 | row 8 plus `USERPROFILE=$T/u9` | `$T/u9/.local/share/ant/client_adaptive.json` |
  | 10 | a non-UTF-8 `XDG_DATA_HOME` plus `HOME=$T/h10` | under `$T/h10/.local/share` |
  | 11 | `USER` and `LOGNAME` set, a passwd entry present | panic, exit 101 |

- antseal's vault lookup, by contrast, uses `std::env::home_dir()`, which falls back to the
  password database (`crates/antseal-cli/src/vault/layout.rs:81-84`; under `env -i` it
  yields the real home). So an environment-cleared run unlocks the real vault, connects,
  and panics in upstream after its first dials.
- `ant-core` 0.12.0: `data_dir()` and `home_dir()` are identical to 0.5.0's (`diff` empty);
  `build_controller` still computes the path on both branches; `ClientConfig` has no path
  field.

### 1.2 The file on the maintainer's host

- `~/.local/share/ant/client_adaptive.json`: 86 bytes, three values, no peers; mtime
  2026-10-15 15:10:51 +0100, inside wave 36's devnet evidence window (`suite-S18.log`
  15:07:33, `suite-S19.log` 15:11:17, under `e2e-devnet: PASS commit=c36949f nodes=14
  suites_run=4 failed=[] pending=[] secs=665`). Timing evidence only.
- The directory's birth is 2026-04-29, three months before the repository's first commit
  (2026-07-27); it holds the developer's own upstream payment locks (`payments/single`,
  102 locks dated July), `spill/` and an empty `upgrades/`.
- During and after the running default-feature gate the file's inode and mtime were
  unchanged; the gate processes' environments carried `HOME` and no `XDG_DATA_HOME`.

### 1.3 macOS and Windows

`ant-core`'s split is its own `cfg!`: macOS `$HOME/Library/Application Support/ant`,
Windows `%APPDATA%\ant`; on macOS a missing home means no write and no panic. No macOS or
Windows hosted job builds a storage client: the `cross-os` lane runs `cargo test -p
antseal-core --locked -- corpus_ vector_` only (`scripts/ci-lanes.sh`, `lane_cross_os`;
`.github/workflows/cross-os-extended.yml:103-132`).

### 1.4 Venues, and the one mechanism

- **In-process `set_var` is unbuildable**: edition 2024 makes it `unsafe`, and
  `unsafe_code = "deny"` forbids the block (`crates/antseal-cli/tests/common/spawn.rs:54-70`,
  confirmed by compiling).
- **cargo `[env]`** (the probe, cargo 1.92.0): with the parent exporting a different
  `XDG_DATA_HOME`, the test process and its child both print
  `<probe>/target/upstream-data-home` under `force = true`; an `env_clear()` child prints
  `None`; invoked with `--manifest-path` from outside the tree, the test prints `None`.
  Every script `cd`s to the repository first (`scripts/local-gate.sh:244`,
  `scripts/e2e-devnet.sh:69-70`, `scripts/gate-features.sh:58-59`,
  `scripts/ci-lanes.sh:77`). After the value changed, `cargo test --no-run -v` still
  printed `Fresh` for the probe.
- **Spawn sites**: one code-line `env_clear()` (`crates/antseal-cli/tests/e2e_restore.rs:237`),
  which re-sets `HOME`, `XDG_CONFIG_HOME` and `XDG_DATA_HOME` into its own home
  (`:250-256`); no `env_remove` of `HOME`, `XDG_DATA_HOME` or `USERPROFILE` anywhere. Three
  confining sites: `e2e_restore.rs:766` and `restore_output.rs:1333` set `HOME` only — so
  they confine only while the parent exports no `XDG_DATA_HOME` — and
  `receipt_backfill.rs:1114` sets `XDG_DATA_HOME`, which no test asserts.
- **Writers**: the in-process devnet clients (`crates/antseal-net/tests/devnet_backend.rs`,
  15 client-building connects; `e2e_devnet.rs`, `e2e_kill_resume.rs`, `e2e_restore.rs`) and
  the heavy tier's dead-export reader rows (`reveal_lazy_backend.rs:734-788`;
  `restore_output.rs:1300`, `:1461`, `:1666`), which need no devnet because a dead
  loopback connect returns `Ok` (D170). `devnet-launcher` never builds a `Client`.
- Each write is a `rename`, so a new inode marks a write. An assertion that *"the real
  directory did not move"* is vacuous when no client was built: it needs a positive
  control.

## 2. RULING

### §2 R1 — The refusal, before any socket, mirrors upstream exactly

A storage client is refused when upstream's lookup would **panic** or would resolve a
**non-absolute** directory. The check mirrors `ant-core` 0.5.0's `data_dir()` branch for
branch:

- **Linux, and any target that is neither macOS nor Windows**: `XDG_DATA_HOME`, else
  `HOME` or `USERPROFILE` joined with `.local/share`;
- **macOS**: `HOME` or `USERPROFILE` — neither means upstream writes nothing, and antseal
  refuses nothing;
- **Windows**: `APPDATA`, else `HOME` or `USERPROFILE` joined with `AppData/Roaming`.

A value that is not UTF-8 counts as unset, exactly as upstream's `env::var` treats it — so
a non-UTF-8 `HOME` with no `USERPROFILE` is unresolvable (upstream panics, row 8), and one
with `USERPROFILE` resolves there (row 9). A resolved base that is empty or relative is
refused: upstream would write into the working directory (rows 5–7).

The refusal is **network-failure (23)**, the storage gate's class and site, with a
constant `REFUSAL` sentence that names the variables and never echoes a value. It sits in
**both** storage constructors, `AntCoreBackend::connect` and `AntCoreReader::connect`,
immediately after `consult_storage_gate(config)?` — which stays the first fallible step —
and before the payer's `eth_chainId`. The receipt reader builds no `Client` (D173 §2 R14)
and is not touched. Planning lane P2's suggested home is `network::upstream_state`, beside
`storage_gate`, where the default lane can test it with no `ant_core` use; the lane may
choose another.

### §2 R2 — The mirror is pinned twice

- **Default build**: unit rows over an injected environment with an OS parameter, so all
  three branches are tested on one host.
- **Feature build**: a cross-check in `crates/antseal-net/tests/storage_constants.rs`
  compares the mirror with upstream's public `adaptive::default_persist_path()` in one
  child process per row; a panic row must panic with `HomeDirNotFound`.

The bump checklist gains a bullet (DOCS lane): re-run the cross-check and re-read
`data_dir()` and `home_dir()` at every pin move, because the mirror is a copy of upstream
logic.

### §2 R3 — Tests are confined by one `[env]` entry

`.cargo/config.toml` gains:

```toml
[env]
XDG_DATA_HOME = { value = "target/upstream-data-home", relative = true, force = true }
```

`relative = true` resolves the value against the directory holding `.cargo/` — the
workspace root — and `force = true` overrides an inherited value. It reaches bare in-tree
`cargo test` and every script with no venue edit, because every script `cd`s to the
repository; `target/` is git-ignored. The file is an input of the wasm-tests and
wasm-bitmatch triggers (`scripts/wasm-tests.sh:122`, `scripts/wasm-bitmatch.sh:158`), so
the change runs both lanes once.

### §2 R4 — The heavy tier asserts it, with a positive control and no devnet

In the feature build, with no devnet:

- **precondition**: the test process's `XDG_DATA_HOME` is
  `<workspace>/target/upstream-data-home`;
- a spawned client-building command with `HOME=<temp>` leaves the temporary home clean;
- **positive control**: the same command with `XDG_DATA_HOME` removed writes
  `<temp>/.local/share/ant/client_adaptive.json`, holding exactly `schema` and
  `channels{quote,store,fetch}`.

The client-building command is of the dead-export reader rows' kind (§1.4). Optional and
not assigned this wave: `scripts/e2e-devnet.sh` comparing the real file's device and inode,
or its absence, before and after a run.

### §2 R5 — macOS and Windows are recorded, not engineered

No hosted job on either builds a storage client (§1.3). A future venue there sets `HOME` or
`APPDATA`.

### §2 R6 — The product write is kept and documented

The write stays: suppressing it with `ManuallyDrop` is buildable, but it leaks the P2P
node, still reads the snapshot, and needs re-proof at every bump. `docs/config.md` gains a
**"Files outside the vault"** section: the file, its directory per platform, what it holds
(three concurrency starting values, no peers), when it is read and written, and the
refusal. Threat-model §2.11's predicate is corrected: `USERPROFILE` also prevents the panic,
a non-UTF-8 `HOME` panics, an empty or relative value writes into the working directory,
and the panic came after dialing — now refused before any socket. The two contributor
sentences that carry the old predicate (`CONTRIBUTING.md:317-319`,
`docs/testing/anchor-ci-policy.md:210-213`) are corrected the same way.

### §2 R7 — A lexical `env_clear`/XDG rule is refused

Its yield is zero of one site: the one `env_clear()` child already re-sets both variables
(§1.4). *[Amended in place by the registrar, wave 37, before this record was first
committed: the record's draft added that the clean-machine child would assert its own
confinement in its body. That assertion was **not carried** this wave. The child re-sets
`HOME`, `XDG_CONFIG_HOME` and `XDG_DATA_HOME` into its own home
(`e2e_restore.rs:250-256`), and §2 R4's row with its positive control carries `S42`'s
`Accept` row 1.]*

## 3. Fault plants

Owed by the implementing lane, baseline green first, judged by message, `touch` after
every restore; every plant compiles.

| # | assertion | plant | expected red | green |
|---|---|---|---|---|
| A1 | an environment-cleared dead-export `reveal` with no `HOME`, `XDG_DATA_HOME` or `USERPROFILE` exits 23 | delete the refusal line in `AntCoreReader::connect` | *"expected Some(23) with the S42 refusal, got Some(101) … HomeDirNotFound"* — also HEAD's result | 23, `class=network-failure`, the message starting with `REFUSAL`, under 2 s (HEAD first spends about 6.3 s connecting to the dead loopback), no `ant/` in the working directory |
| A2 | `XDG_DATA_HOME=""` with no `HOME` | the predicate tests `var_os(..).is_some()` | *"upstream wrote …/cwd/ant/client_adaptive.json (empty XDG_DATA_HOME)"* — at HEAD, 23 **and** the file in the working directory | the refusal; no `ant/` in the working directory |
| A3 | the control, `HOME=<tmp>` | the `HOME` arm inverted | *"refused with HOME set"* | the engine's unfetchable sentence; the file under `<tmp>/.local/share/ant` |
| A4 | the shape scan: the refusal before the first `.await` of both constructors | the call moved below the chain-id guard's `.await` | *"`AntCoreBackend::connect` awaits before refusing an unresolvable upstream dir (S42)"* | green |
| A5 | the §2 R2 cross-check | the mirror reads `XDG_DATA_DIRS` | *"mirror …/.local/share/ant, upstream Some("/x/ant/client_adaptive.json")"* | rows equal; panic rows exit 101 with `HomeDirNotFound` |
| A6 | §2 R4: the precondition, the clean temporary home, the positive control | delete the `[env]` entry | *"S42: XDG_DATA_HOME = None; expected <ws>/target/upstream-data-home"* | the temporary home clean; the control file holds only `schema` and `channels{quote,store,fetch}` |

A1–A3, A5 and A6 run in the feature build; §2 R2's unit rows and A4 run in the default
lane. A1 is `S42`'s `Accept` row 2; A6 is its row 1.

## 4. What this record does NOT decide

- That the heavy tier's dead-export rows write into the inherited home today — read, and
  inferred from D170's 6.3 s dead-loopback connect; **not run**.
- That `[env]` rebuilds nothing in the 475-package graph — only the std probe was measured;
  the lane counts `Fresh` and `Compiling` with `-v` before and after.
- By cargo's documentation, `[env]` also reaches an in-tree `cargo run`, confining a
  developer's manual run the same way — **not measured**. The release binary and an
  installed binary are unaffected.
- The writer of the 15:10:51 file — timing evidence only.
- A macOS or Windows venue that builds a storage client (§2 R5).
- `S43`'s change to the same adapter's PUT loop — D179.

## 5. Edit list — per write scope, with the lane named before this record was written

### L-NET (the network lane; `S42` before `S43`, one owner)
- `crates/antseal-net/src/network.rs`: the mirror and `REFUSAL` beside `storage_gate`,
  with the default-build rows (§2 R1, R2).
- `crates/antseal-net/src/ant_backend.rs`: the refusal after `consult_storage_gate(config)?`
  in both constructors (§2 R1).
- `crates/antseal-net/tests/storage_gate.rs`: the shape scan's new clause (A4);
  `crates/antseal-net/tests/storage_constants.rs`: the cross-check (§2 R2, A5).
- **New** `crates/antseal-cli/tests/upstream_state.rs`: A1–A3 and §2 R4 (A6). An
  `env_clear()` there re-arms both gate variables on the same statement
  (`scripts/check-anchor-net.py` R4).
- `.cargo/config.toml`: the `[env]` entry (§2 R3).
- `docs/testing/anchor-ci-policy.md:210-213`: the corrected predicate (§2 R6).

### L-CLI (owner of `crates/antseal-cli/tests/e2e_restore.rs` this wave)
- ~~The clean-machine child's in-body confinement assertion (§2 R7), if carried this
  wave.~~ Not carried (§2 R7, amended in place).

### DOCS (the documentation lane)
- `docs/config.md`: "Files outside the vault" (§2 R6).
- `docs/threat-model.md` §2.11: the corrected predicate and the refusal (§2 R6).
- `CONTRIBUTING.md:317-319`: the corrected predicate (§2 R6).
- `docs/dependency-policy.md` §4: the mirror's bump-checklist bullet (§2 R2).

### Orchestrator (registrar) — `TODO.md`, `tasks/S.md`, `docs/decisions/README.md`, dated addenda
- `S42` Notes from planning lane P2; the `Accept` captures as they land.
- A dated addendum on **D173** §1.2: the panic's real predicate (§1.1), the panic after
  dialing, and the file's date — inside wave 36's devnet window, in a directory that
  predates antseal — not wave 35's devnet day.
- Index row and register row for this record.
- An `docs/instrument-ledger.md` entry for §1.4's finding: two of the three confining test
  sites worked only while the parent exported no `XDG_DATA_HOME`, and the third was never
  asserted.

## 6. As built — wave 37, lane L-NET (recorded in place before this record was first committed)

The lane built §2 R1–R6 as ruled. These are the points where the code says more than the
ruling did, or less:

- **§2 R1 judges absoluteness per OS by a text rule.** On Unix that is a leading `/`. On
  Windows it is `X:\`, `X:/` or two leading separators, so `\x` and `C:x` are refused, as
  Windows' own `Path::is_absolute` would refuse them. The text rule is cross-checked
  against the host's `Path::is_absolute`, for the host's arm only: Linux here.
- **§2 R1's refusal reaches read-only commands wrapped, not first.** `backend::degrade` in
  `crates/antseal-cli/src/backend.rs` turns every connection refusal into a per-fetch
  failure. So `reveal`'s message *contains* `REFUSAL`, and does not start with it: *"network
  failure: unit 0 could not be fetched from the network (network error: the Autonomi
  network could not be reached: refusing to start a storage client: …"*. The rows assert
  `contains`. The wrapper's words *"could not be reached"* misdescribe an environment
  refusal, as they already did for the storage gate's. This is recorded, not changed, this
  wave. The payer path (`seal`) renders the refusal through `CliError::NetworkFailure`; that
  is held by reading and by the shape scan, with no spawned run.
- **§3 A1's green column held except for "under 2 s".** There is no latency assertion,
  only a 120 s hang guard, because the run includes an Argon2id unlock on a shared 2-CPU
  host. *Before any socket* is held by the shape scan (A4) and by the refusal message.
- **§2 R2 is pinned twice.**
  - Default build: nine unit rows over an injected environment, covering all three OS arms.
  - Feature build: thirteen rows against upstream's own `default_persist_path()` on Linux,
    one child process per row. Its two panic rows exit 101 with `HomeDirNotFound`.
- **§4's rebuild question was measured, on one graph.**
  `cargo test -p antseal-net --features ant-backend --no-run -v` printed `Fresh=503
  Compiling=0` both immediately before and immediately after the `[env]` line was added.
  Other graphs were not measured cleanly, because other lanes were editing antseal-cli and
  antseal-core at the time.
- **The developer's real file was never touched** during the lane: inode 10355230, mtime
  2026-10-15 15:10:51. The confined copy under `target/upstream-data-home/ant/` was written
  by the lane's rows. The devnet E2E is a `cargo test` (`scripts/e2e-devnet.sh`), so it is
  confined too. The close gate re-reads the real file's inode and mtime around its run.
- **§3 A1's measurement through the real binary.** With the refusal removed, an
  environment-cleared `reveal` hits upstream's panic at `config.rs:21:44`
  (`HomeDirNotFound`), which is also `HEAD`'s result. With an empty `XDG_DATA_HOME`, the
  same command writes `ant/client_adaptive.json` into the working directory. Plants A1–A6
  were each seen red by their own message, restored byte-exact and touched.

## Closing — this record is not consent

It changes code, tests, one cargo configuration file and documents in the tree, and
authorises no network act: every test it adds refuses before any socket or runs against a
dead loopback export. Nothing here authorises a push, a dispatch or a settings write.
