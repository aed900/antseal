# D170 — `restore` and `verify --live` are wired in the release build through a **wallet-less download-only reader that cannot pay**, not through the paying door; a connect failure **degrades to per-fetch failures** so D43 §5's cache fallback still runs; `restore` uses the **work's recorded network**; and the default build **keeps refusing**

- **Status: RESOLVED. The orchestrator's lean survived on two clauses, fell on
  five, and one of its premises dissolved the M4 value it was chasing.**
  - **The defect is real and unowned.** `crates/antseal-cli/src/commands.rs`'s
    `restore` handler has no `#[cfg]` split and its whole body is
    `Err(crate::backend::unavailable("restore"))`; `verify`'s `--live` branch
    returns the same refusal unconditionally. Both refuse in the
    `--features ant-backend` build that D72 §2 R4 ships as the release binary.
    `U36` ticked on *"U13/S17 fill it"*, only `seal` was filled, and no open row
    owned the rest. §1.1.
  - **"Go through U36's read-only door" is UNBUILDABLE for `verify --live` and
    WRONG for `restore`.** There is no read-only door: the only production
    constructor is `SealBackend::connect(config, &WalletKey, receipts)`, and
    `ReadOnly` is a no-op receipt sink, not a constructor. `verify` opens no vault
    (D99 R2), so it has no wallet key; `restore` would demand a wallet record that
    a vault created by `create_vault` does not contain. Upstream needs none: ant-core
    0.5.0's `Client::connect(peers, ClientConfig)` takes no wallet and `chunk_get`
    uses none. §1.2, §2 R1.
  - **"Copy seal's eager connect" would DELETE D43 §5's fallback in exactly the
    outage it exists for**: `connect(..).await?` aborts before the restore engine
    runs whenever peers or the RPC are unreachable. §1.3, §2 R2.
  - **"MockBackend tests plus one devnet test" cannot reach the handlers**: they are
    `pub(crate)`, they build their own backend, in-process `main_entry` is banned,
    and a spawned binary cannot hold a mock. §1.4, §2 R8.
  - **"The only surface change is two refusal documents disappearing" falls on its
    premise**: only `restore` has such a document; the `[seal]` Compiled-arm document
    already describes text no build emits; and removing both would leave the
    Compiled sentence unwitnessed while `reveal` still reaches it. §1.5.
  - **The M4 value partly DISSOLVES.** `NetworkConfig::arbitrum_one()` and
    `arbitrum_sepolia()` carry **no bootstrap peers**, ant-core 0.5.0 compiles in
    none, and no CLI code supplies any — so **outside a local devnet every fetch
    fails, and so does every `seal`**. Wiring these commands makes them correct on
    the devnet and ready for a peer source; it does not make the M4 gate reachable.
    The peer source is planned separately. §1.6, §2 R10.
- **Date: 2026-09-13**
- Owner rows: **`U90`** (minted with this record: `restore` has no production
  backend in any build), **`U74`** (ruled by §2 R4), **`U75`** (ruled by §2 R6/R7),
  **`U91`** (minted with this record: `reveal` cannot fetch in any build — sequenced
  after `U90`), **`U36`** (its `Accept` restated by §2 R1).
- Related: **D43** §5 (restore is network-normative with a verified-cache fallback),
  **D48** (restore's output policy), **D52** (the devnet gate), **D69** §3 R6 (an
  exit 23 is sanctioned only for a build with no storage backend compiled in), **D72**
  §2 R4 (the release binary's feature set), **D99** R2 (`verify` opens no vault),
  **D146** (records the live wiring as outstanding), **`U20`**, **`U36`**, **`U72`**
  (cache-first `reveal` and lazy refusal), **`U73`** (per-build answers for a
  vault-less home), **`R79`** (the adapter reports mismatched bytes as a network
  error), **`R81`**, **`S14`**, **`S19`**.

## 0. What was measured against

`HEAD` `ef5f6d9`. Planning lane F (wave 35) read the handlers, the seam, the adapter
and the pinned upstream sources, and ran two `cargo check`s
(`-p antseal-cli --features ant-backend --locked`: 68 s cold, 1 s warm, both
`REAL_EXIT=0`); no test, gate or devnet run. The orchestrator re-verified in source
the two refusals, the absence of any wallet-less constructor, `ReadOnly`'s shape,
`reveal`'s `VaultLocalBackend`, and the empty bootstrap lists, before this record
was written.

## 1. What was measured

### 1.1 The refusals and their provenance

`restore` (`commands.rs`, the handler beginning `pub(crate) fn restore(`) returns
`unavailable("restore")` in both builds; `verify`'s `if live { … }` returns
`unavailable("verify")` with no `#[cfg]`. `backend.rs`'s `Compiled` arm text says a
backend is compiled in *"but the command has no wiring that constructs one"*. The
M4 artefacts depend on both: `scripts/e2e-sepolia.sh` stage S8 runs
`verify … --live` and S9 runs `restore` with a byte compare, and
`docs/drills/vault-restore-drill.md` prescribes `restore`. Every devnet green
(S17, S19, the E2E gate) drives the library (`RestoreEngine`, `collect_live`), and
`tests/machine_mode.rs` registers `restore`'s refusal as its documented envelope.

### 1.2 What each command needs

- **`restore`** needs, from the vault: the work record's `W`, the plan entry (the
  vault copy of the manifest), the manifest blob entry (locator and nonce), the
  recorded paths, state `Complete`, the **recorded network**, and unit cache entries
  **only as D43's fallback**. It needs **no wallet key** and makes no payment. The
  library entry already exists: `restore_out::run_restore(&B, &WorkStore, work_id,
  Option<&Path>)`, which runs the engine and the D48 write policy.
- **`verify --live`** needs a network definition from config (a manifest records no
  network), a download-only backend, and `collect_live(&BundleV1, &B)`; composition
  is `CollectedInputs::none().with_live(..)` → `run_verify` with live mode.
  `collect_live` has **never run against a devnet**.
- `AntCoreBackend::connect` builds a signing wallet and checks `eth_chainId` before
  `Client::connect`; the wallet is used only on payment paths upstream.

### 1.3 The fallback the eager shape would delete

D43 §5 makes the network normative **and** requires the verified-cache fallback when
a fetch fails; S14 implements it per fetch. An eager `connect(..).await?` fails the
whole command before any fetch is attempted, so a fully cached work cannot be
restored during a network outage — the case the fallback exists for.

### 1.4 What tests can reach

The handlers are `pub(crate)` and construct their own backends; spawned-binary tests
cannot inject a mock; in-process `main_entry` is refused by `check-anchor-net.py` R4.
The heavy tier compiles and runs every suite in the feature build, where four
registered expectations change (§2 R8).

### 1.5 The machine surface

`tests/snapshots/json-envelopes.txt` carries `[restore] error [arm: …unwired]` and a
`[seal]` Compiled-arm document whose text no build emits (`seal` is wired). No
`verify` refusal document is registered. `reveal` still reaches the Compiled
sentence through `VaultLocalBackend`. `U32` (the CLI freeze) is open and runs after
`Q32`, so nothing here is frozen.

### 1.6 Peers

`crates/antseal-net/src/network.rs` sets `bootstrap: Vec::new()` for both public ids
and says peers *"arrive from the caller"*; ant-core 0.5.0's `Client::connect` is
caller-supplied and its `config::load_bootstrap_peers()` file loader is never called
by antseal. A grep of `tasks/`, `docs/decisions/` and `MVP-SPEC.md` finds no owner.

## 2. RULING

### §2 R1 — A reader that cannot pay (DR1, arm B)

`crates/antseal-net/src/ant_backend.rs` — the adapter file, so upstream churn stays
contained per project rule 1 — gains a **wallet-less download-only client**
(`Client::connect` with no EVM network; loopback allowed only for the devnet id) that
shares the adapter's address re-check on `get_data`, and whose paying methods refuse
with an **existing** `StorageError` variant, so the fetch-failure class vocabulary
does not grow. The CLI wraps it in a read-only backend type. **`U36`'s `Accept` is
restated, never deleted**: *"anything that can pay goes through
`SealBackend::connect`"* — the property it protected (no paying path can skip D37's
capture hook) is unchanged, because the reader cannot pay. The raw reader type is
nameable in exactly one CLI file, extending the existing
`the_raw_backend_type_is_named_in_exactly_one_file` scan. **Refused**: arm A (a
throwaway or vault wallet for commands that never pay — `verify` would generate key
material to read public ciphertext, and `restore` would refuse vaults that hold no
wallet), and arm C (an optional wallet on `AntCoreBackend` — it puts a runtime
`None` check between D37's guarantee and every payment).

### §2 R2 — A connect failure degrades (DR2)

For the two read-only commands a connect failure becomes a backend whose every call
fails, so each fetch fails individually: `restore` runs D43 §5's cache fallback per
unit and reports `fetch-failed` only where no verified cache exists; `verify --live`
renders its offline verdict with an **Inconclusive** live section. **The
unavailable refusal is never produced by a build that has a backend compiled in**
(D69 §3 R6): `verify --live` exits with its offline verdict, and a `restore` whose
every fetch failed with no verified cache exits in the network-failure class **with a
result document**, as D48 §6 already rules. **Corrected before this record landed**: as
first written this sentence said no exit 23 at all, which contradicts D48 §6.
**Measured by the implementing lane, and it moves this ruling's centre of gravity: on
the pinned stack a dead or empty bootstrap never fails at connect** — `Client::connect`
returned `Ok` in 6.3 s against a dead loopback peer set and in 45 ms against an empty
one — so an unreachable network surfaces **per fetch**, each failing in about one
second, and that is honest only because of §2 R12. The degrade therefore covers real
connect errors and a connect timeout; the outage cost is roughly one second per
uncached unit, and the connect-timeout value is chosen by the handler lane with that
trade stated (a timeout under ~6.3 s sends a dead bootstrap down the fast path at the
risk of cutting off a slow live one).

### §2 R3 — `restore` uses the work's recorded network (DR3)

The network comes from the work record. An explicit `--network` that disagrees is a
usage error (2), not a silent override. For `restore` alone, a network-definition
error therefore surfaces after the passphrase, and the handler's rustdoc says so.

### §2 R4 — `U74`: the default build refuses, always (DR4)

A build that cannot attempt the network cannot be network-normative, so the default
build keeps its NotCompiled refusal **before** the vault, and the feature build opens
the vault first (`U73`'s precedent). `U74` closes on the comment and the test its own
row anticipates for this answer. Its arm (ii), what a partial cache promises, does
not arise.

### §2 R5 — No vault lock for `restore` (DR5)

`restore` writes nothing to the vault; read-only commands deliberately skip the U5
lock, and `restore` joins them.

### §2 R6 — `verify --live` verifies before it collects (DR6)

Offline verification runs first; a bundle rejected offline exits with its own class
(40) and **zero** fetches. A missing devnet definition is a usage error (2) before
verification, on the `--online` precedent.

### §2 R7 — `U75` takes arm (a), and its `Accept` is amended (DR7)

Arm (a) — wire it — is the only arm that closes `R81`'s `Accept` row 1 as written.
`U75`'s `Accept` clause asking for the manifest-**divergent** case *through the
binary* is **unbuildable**: a spawned binary cannot hold a mock, and the production
adapter reports mismatched bytes as a network error (`R79`'s recorded cost), so
`Different` never arises on a real network. It is restated as: through the binary,
the manifest row reported persisted **plus** a negative control (a dead-bootstrap
export yielding Inconclusive); the divergent case stays proven at the library route
(`tests/verify_live_manifest.rs`).

### §2 R8 — The machine surface changes per build, and each change is a test

No new exit code and no `ENVELOPE_VERSION` change. `json-envelopes.txt` loses the
`[restore]` unwired document and the stale `[seal]` one and gains a `[reveal]`
Compiled-arm example (so the default build still witnesses the feature-ON sentence,
R82's property), re-blessed with the reason in the commit. `machine_mode.rs` and
`upgrade_hook.rs` assert `restore`'s class **per build**; `verify_command.rs`'s
prompting-handler list gains `restore` while its reach-module set stays exactly as
it is. Default-build tests run in every CI job; feature-build tests run in the heavy
tier; process-level devnet tests (`tests/e2e_restore.rs`) spawn the release-feature
binary: `restore` byte-identical then idempotent, `vault import` then `restore` on a
clean home, and `reveal` → `verify --live --json` reporting persistence with a
dead-bootstrap negative control.

### §2 R9 — `reveal` is `U91`, sequenced after `U90`

`reveal` holds `VaultLocalBackend` in every build, import refuses unit blobs and
`restore` writes no cache, so the drill's clean-machine `reveal` step is refused in
every build — and MVP-SPEC.md line 36 says `reveal` *"fetches ciphertext from
Autonomi when no local copy exists"*, a **spec divergence** flagged here. It consumes
§2 R1's reader and must keep `U72`'s zero-call cached path, so it follows `U90` and is
not in this record's lanes.

### §2 R10 — What this record does NOT make reachable

The M4 gate stays unreachable after this lands, for the peer source (§1.6) and for
the `--network arbitrum-sepolia` meaning the Sepolia script and the drill rely on —
both routed to a separate planning round and its record.

### §2 R11 — The gate's own triggers are aligned

`commands.rs` is one of two CLI source files carrying `cfg(feature = "ant-backend")`
and is **missing** from `scripts/gate-features.sh`'s heavy trigger list, so a change
touching only it compiles no feature tier (the `Q112` class): it is added.
`gate-features.sh` claims its list is *"the same list as CONTRIBUTING's"* while
carrying `backend.rs`, `Cargo.toml` and `Cargo.lock` that `CONTRIBUTING.md`'s D52
list lacks: `CONTRIBUTING.md` is aligned to the superset, which only widens when the
devnet gate is mandatory. `commands.rs` is **not** added to the devnet trigger — the
standing test *"can anything in this diff reach the subject?"* already covers it.
Closing this wave therefore runs the gate with `ANTSEAL_GATE_HEAVY=1` and
`ANTSEAL_GATE_E2E=1`.

### §2 R12 — Absence is declared only by the network's own authoritative rule

Added mid-wave, before this record landed, when the peer-source planning round found the
reader copying a defect of the adapter (`S39`): pinned ant-core's `chunk_get` returns
`Ok(None)` after a failed lookup and after a non-unanimous timed-out sweep, not only for an
authoritative absence, and the adapter mapped every `None` to `NotFound` — *"the network
answered"*. The payer and the reader now share one fetch path that, on `None`, re-asks the
close group and declares `NotFound` only when at least `CLOSE_GROUP_MAJORITY` peers were
queried and every one answered not-found (a copy of ant-core's private rule, so it joins
`S20`'s bump checklist); anything short of that is the network class, naming only the
counts. Proven on a live devnet in both directions: a reader and a payer with a dead or an
empty bootstrap each fail in the network class and never report a chunk the devnet holds
as absent (a plant restoring *any `None` → `NotFound`* went red by message), while a
never-uploaded address still reports `NotFound` for the payer, the reader and S15.
`run_verify_live` also takes the connect as a lazy future, so a bundle rejected offline
never connects at all — the literal reading of §2 R6.

## 3. Fault plants

Owed by the implementing lanes, each keeping the code compiling and judged by
message: the reader's `quote_batch` returning `Ok` (the refusal test goes red); the
unreachable backend's `get_data` returning empty bytes (restore reports verification
failure, the test goes red); `--live` collecting before verifying (the zero-fetch
test goes red); dropping `with_live` (the persistence test goes red); mapping an
all-failed live collection to `unavailable` (the Inconclusive test goes red); the
default build running `restore` over `VaultLocalBackend` (the U74 test goes red);
the reader type named in `commands.rs` (the one-file scan goes red); the feature
build's `restore` reverted to the refusal (the spawned devnet test goes red with exit
23). Green baselines first; `touch` after every restore of a planted file.

## 4. What this record does NOT decide

- The public-network peer source and the meaning of `--network arbitrum-sepolia`.
- `reveal`'s wiring (`U91`).
- `scripts/e2e-sepolia.sh` stage S8 passing on exit status alone — after wiring,
  D69 §3 R6 means the exit status cannot reflect persistence, so the stage becomes
  an assertion that cannot fail; owner `Q32`.
- The connect budget's value (measured by the lane, recorded in `U90`).

## 5. Edit list — per write scope, with the lane named before this record was written

### W4a (the reader and composition lane)
- `crates/antseal-net/src/ant_backend.rs`, `crates/antseal-net/src/lib.rs`,
  `crates/antseal-net/tests/devnet_backend.rs` per §2 R1.
- `crates/antseal-cli/src/backend.rs` (the read-only wrapper and the degrading
  backend, not yet feature-gated construction) and `crates/antseal-cli/src/verify_host.rs`
  per §2 R2 and §2 R6, with `tests/restore_output.rs` and `tests/verify_command.rs`.

### W4b (the handler lane) — after W4a is verified
- `crates/antseal-cli/src/backend.rs` feature-gated construction,
  `crates/antseal-cli/src/commands.rs`, `crates/antseal-cli/src/restore_out.rs`
  (rustdoc), per §2 R3–R8.
- `crates/antseal-cli/tests/{machine_mode,upgrade_hook,verify_command,restore_output,e2e_restore}.rs`
  and `tests/snapshots/json-envelopes.txt` per §2 R8.

### W1 (the CI lane)
- `scripts/gate-features.sh` and `CONTRIBUTING.md`'s D52 list per §2 R11.

### Registrar — `TODO.md`, `tasks/U.md`, `docs/decisions/README.md`, `docs/instrument-ledger.md`
- Mint `U90` and `U91`; amend `U74`, `U75` and `U36` per §2 R1, R4, R7.
- `docs/instrument-ledger.md`: the heavy-trigger omission, the two trigger lists
  that claim to be one, the `[seal]` snapshot document no build emits, the Sepolia
  stage that will pass on exit status alone, and the stale locators in `U74`, `U75`,
  D146 and `backend.rs`'s module rustdoc.
- Index row and register row for this record.

## Closing — this record is not consent

It authorises no network act beyond the local devnet, which pays nothing and touches
no external service.
