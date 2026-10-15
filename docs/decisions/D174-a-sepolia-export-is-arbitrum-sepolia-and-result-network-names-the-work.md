# D174 — An export's network is decided by its **chain id**: a validated 421614 export is `arbitrum-sepolia` (never `devnet`), `arbitrum-one` never reads one; and the machine envelope's top-level `network` **stays the invocation's**, while every single-work result carries the **work's** network as `result.network`

- **Status: RESOLVED. `U92`'s recommended arm survived in direction with four of its
  premises falling; `U93`'s recorded question half-dissolved — the orchestrator's lean
  fell on its premise, and the arm the tree already uses answers it.**
  - **`U92` (D-b)** — arm (i), *`arbitrum-sepolia` reads the Sepolia export and `devnet`
    refuses it*, is right, and the alternatives are worse: `devnet` as the Sepolia reader
    keeps one id meaning two chains and records `devnet` for a public-chain payment; both
    ids accepting it records one payment under two names; deriving the id from the export
    overriding the flag is the silent override D170 §2 R3 refuses. **Four premises fall**:
    the contract check is **mandatory**, not optional (the adapter maps `arbitrum-sepolia`
    to evmlib's built-in network and ignores the export's contracts, so a foreign export
    would have nodes checking contracts the client never pays); the receipt backfill must
    be kept **off** the export path or arm (i) regresses it; `U89`'s laziness test cannot
    fail on the plant `U92`'s `Accept` names (the real-entry line runs with the variable
    unset); and the script and drill are wrong **whichever arm is chosen**. §1.
  - **`U93` (D-u93)** — the orchestrator leaned *the member should mean the network acted
    on*. **It falls on its premise**: the member has a recorded, implemented and consumed
    definition — the invocation's effective network (`tasks/U.md` `U3` item 5; `lib.rs`;
    the M4 gate's default-network evidence reads it on an offline `verify`; every
    command's pre-vault abort asserts `arbitrum-one` in `tests/machine_mode.rs`) — and
    "the network acted on" has no value on most envelopes. The tree already separates the
    two facts: `show`, `status`, `seal` and each `list` row carry `result.network`; of the
    five single-work results, **only `restore` and `reveal` lack it**. §1.5.
- **Date: 2026-09-15**
- Owner rows: **`U92`**, **`U93`**; **`S40`** (D173 §2 R6's Sepolia layer and §2 R8's
  classifier, which this record consumes); **`U91`** (inherits `result.network` on
  `reveal`); **`Q32`** (its script and drill are corrected under `U92`).
- Related: **D38** (the Sepolia contract pins), **D65** (the envelope's tiers), **D170**
  §2 R3, **D173**, **`U3`**, **`U89`**.

## 0. What was measured against

`HEAD` `3473ab2`. Planning lane P2 read `select_network` and every caller, the export
parser and the D38 pins, the adapter's loopback handling, the envelope code and its
documentation, the help text and its snapshot, `scripts/e2e-sepolia.sh`, the drill, and the
recorded real Sepolia-mode exports (`docs/devnet/sepolia-devnet.md`). No cargo run. The
orchestrator re-read `lib.rs`'s single effective-network computation and `select_network`'s
signature before this record was written.

## 1. What was measured

### 1.1 Exports and chains

A Sepolia-mode export carries `ANTSEAL_DEVNET_CHAIN_ID` (421614), and a recorded real one
carried the canonical D38 token and vault pair. `select_network` reads the export only for
`devnet`, so `arbitrum-sepolia` resolves to the built-in configuration with **no peers**,
and a Sepolia-mode export read as `devnet` records `devnet` for a payment on a public
chain. `ant-client`'s `main` publishes only the mainnet peer list: **there is no public
Autonomi storage network on Arbitrum Sepolia**, so nothing can be vendored for it.

### 1.2 The loopback flag

`client_config` sets `allow_loopback` only when the id is `devnet`; `saorsa-core` then
rejects every loopback peer when the flag is false, and Sepolia devnet peers are all
loopback. D173 §2 R8 replaces the id rule with the classifier; `U92` must not ship without it.

### 1.3 The script, the drill and the help text are wrong independently of the arm

- `scripts/e2e-sepolia.sh`'s mode guard greps `.devnet/env` for `ANTSEAL_DEVNET_NETWORK`,
  a key only `sepolia-preflight` writes — and to `.devnet/sepolia-env`. The recorded real
  `.devnet/env` holds exactly the nine keys without it, so **the guard always refuses**.
- The drill's Sepolia restore step needs a packet item its packet contract does not list,
  and a second machine cannot reach the devnet's peers at all: the launcher never sets an
  advertise address, so nodes bind loopback.
- `crates/antseal-cli/src/cli.rs` carries **three** wrong sentences, each copied into 12
  places in `tests/snapshots/cli-surface.help.txt`: `arbitrum-sepolia` works *"via the
  self-hosted devnet contracts"* (the contracts are the real D38 deployments); `devnet` is
  *"25 nodes"* (the launcher defaults to 14, and a count is a launcher knob); and the
  global flag's *"flag > config > default"* is false for `restore`, which uses the recorded
  network and ignores config.
- `devnet_env.rs`'s no-definition message suggests `--network arbitrum-sepolia` as an
  export-free alternative — which resolves to the peerless configuration.

### 1.4 The callers

`seal` passes the invocation's network; `backend.rs`'s `payment_rpc` (the receipt backfill)
passes the recorded network; `read_only_network` receives the recorded network from
`restore` and the invocation's from `verify --live`. The upgrade hook acts on no storage or
EVM network; its `network` argument reaches only a trace.

### 1.5 The envelope

The top-level `network` is resolved once, before dispatch, as flag > config > default. It is
tier B (key, type and placement frozen since M3; additions allowed); `result` interiors are
tier C, unstable until `U32`. Per committed fixture, `result.work_id` appears on exactly five
documents (`show`, `status`, `seal`, `restore`, `reveal`), and **`result.network` is missing
on exactly `restore` and `reveal`**. The committed `[list]` document already shows the two
members differing (`arbitrum-one` around a `devnet` row).

## 2. RULING

### Part A — `U92`

#### §2 R1 — An export is classified by its chain id, in one pure function

`crates/antseal-net/src/network.rs` (default features, no I/O): `421614` is a Sepolia-mode
export; `42161` is a chain no export may carry; anything else is a local devnet export. Never
by key count (nine versus ten is who funds, `U89`), path or file name.

#### §2 R2 — `arbitrum-sepolia` accepts a validated export, and only a validated one

When `select_network(arbitrum-sepolia)` reads `ANTSEAL_DEVNET_ENV` and it is set, it accepts
the export iff the chain is 421614 **and** the payment token **and** the payment vault equal
the D38 pins byte for byte. The definition is `NetworkConfig::arbitrum_sepolia()` — pinned
chain id, RPC and contracts — with `bootstrap` replaced by the export's peers; the export's
`RPC_URL` is not used, and a doc comment says so. Refusals are usage (2) and are never a
fall-through to another layer: a wrong chain names the chain the export carries, the path
and — for a non-public chain — `--network devnet`; a contract mismatch names the **key** and
the **pinned** address, never the export's value; an unreadable or malformed export keeps
`U89`'s arms. **An unset export is not refused here** — D173 §2 R7 keeps absence out of
`select_network`, and `resolve_peers`'s no-peers refusal carries the text naming
`scripts/devnet/sepolia-up`, `ANTSEAL_DEVNET_ENV` and the absence of a public network. The
wallet-less note moves to this arm.

#### §2 R3 — `devnet` refuses a public chain id by name

A 421614 export under `devnet` is refused naming `421614` and `--network arbitrum-sepolia`;
a 42161 export is refused naming `42161` and that `arbitrum-one` never reads an export. Every
other chain resolves exactly as today. No read-only carve-out — no project vault holds a
`devnet` work paid on 421614 (no Sepolia payment has ever been made).

#### §2 R4 — `arbitrum-one` never reads the export, provably

The export read is injected (`select_network_with(id, lookup)`; `select_network` passes the
real reader). A test hands `arbitrum-one` a lookup that panics if called; a second test proves
the same seam is called exactly once for `arbitrum-sepolia` and for `devnet`, so the first
cannot pass on an unwired seam.

#### §2 R5 — Loopback comes from the resolved peers

D173 §2 R8. `U92`'s Sepolia arm lands in the same act as the classifier or after it.

#### §2 R6 — The receipt backfill resolves the chain, never the peers or the export, for public ids

`payment_rpc` takes the pinned chain half for `arbitrum-one` and `arbitrum-sepolia` without
consulting `ANTSEAL_DEVNET_ENV` or any peer layer; `devnet` keeps reading the export, whose
chain is run-scoped. It composes with D173 §2 R14 (no Autonomi session).

#### §2 R7 — One no-definition message per id

`devnet` names `scripts/devnet/local-up`; `arbitrum-sepolia`'s no-peers text names
`scripts/devnet/sepolia-up`; both name `ANTSEAL_DEVNET_ENV`; neither offers another network as
an export-free alternative.

#### §2 R8 — The recorded network is the resolved network

The seal refuses, as an internal-invariant error and never a panic, when the resolved
definition's id differs from the plan's network.

#### §2 R9 — Help and user documents say what the product does

The three `cli.rs` sentences are corrected with **no node count**, and all 12 snapshot copies
re-blessed in one act; a content test over `Cli::command()` asserts that the
`arbitrum-sepolia` help names `ANTSEAL_DEVNET_ENV` and not *devnet contracts*, that the
`devnet` help carries no `N nodes`, and that the global flag's help states the
recorded-network rule — because an exact-equality snapshot is green on any re-bless.
`docs/user/funding-your-wallet.md` gains the export requirement; `docs/devnet/sepolia-devnet.md`
names `--network arbitrum-sepolia` as the CLI's reading of the export and annotates its
library recipe as the chain-blind constructor.

#### §2 R10 — The script and the drill are corrected in the same act

`scripts/e2e-sepolia.sh`'s guard reads `ANTSEAL_DEVNET_CHAIN_ID='421614'` from `.devnet/env`
and gains an offline mode that runs only that guard on a named file (read one file, write
nothing), so a plant can reach it. `docs/drills/vault-restore-drill.md`: the restore step
drops `--network` (restore reads the recorded network); a Sepolia-era restore runs on the
Sepolia devnet's own host under a fresh `ANTSEAL_DIR` with `ANTSEAL_DEVNET_ENV` pointed at its
export, because a second host cannot reach loopback-bound peers; the second-clean-machine
claim is reserved for a public-network run. Its evidence template follows.

### Part B — `U93`

#### §2 R11 — The top-level `network` is the invocation's effective network, on every envelope

Except the unparseable-arguments envelope (`null`), it is `--network`, else `config.toml`'s
default, else `arbitrum-one`; on a config-load failure, `--network`, else `arbitrum-one`.
Resolved once before dispatch, never dependent on what the command did. **No
`ENVELOPE_VERSION` change**: no key renamed, removed, retyped or moved, and no committed
top-level value changes.

#### §2 R12 — The network a command acted on for a recorded work is `result.network`

A `result` describing one sealed work carries `result.network` = that work's recorded network
string, verbatim from the work record. `restore` and `reveal` gain it; `seal`, `show` and
`status` keep it; `list` keeps it per row. `verify --live` (the bundle records no network, so
the top-level member already names what it acted on) and the upgrade hook (no storage or EVM
network, no document) gain nothing.

#### §2 R13 — The documentation states both halves in one place

`crates/antseal-cli/src/machine.rs`'s envelope section states R11 and R12, with the `restore`
example, and that a consumer wanting the network data came from reads `result.network`. D65
takes a dated addendum pointing here; its tier table is unchanged.
`docs/drills/clean-machine-verify.md`'s default-network evidence is correct under R11 and
unchanged.

#### §2 R14 — "Every such command agrees" is a registry test

Over every committed envelope fixture: a `result` carrying a top-level `work_id` string also
carries a top-level `network` string. It asserts that **exactly five** fixtures are selected,
so a selector that matches nothing cannot pass. Today it is red on exactly `[restore]` and
`[reveal]`.

#### §2 R15 — The test that fails on the other reading runs through the spawned binary

Feature build, `--json`, no `--network`, no `config.toml`, a `devnet`-recorded fully cached
work, a dead 31337 export: exit 0, top-level `network` `arbitrum-one` **and**
`result.network` `devnet`. Two controls, both mandatory: `--network devnet` (agreeing with the
record) gives top-level `devnet`; `config.toml` with `default_network = "arbitrum-sepolia"` and
no flag gives top-level `arbitrum-sepolia` — without it the test cannot tell *the invocation's
network* from a constant `arbitrum-one`. In both, `result.network` stays `devnet`.

## 3. Fault plants

`U92`: the Sepolia arm dropping the export's peers (`left: []`); building a `devnet` config
from a Sepolia export (id mismatch); deleting the chain comparison (a 31337 export carrying the
Sepolia contracts is accepted); comparing only one contract; formatting the export's address
into a refusal (the hygiene test); widening the lookup to every id (the panicking lookup fires);
ignoring the injected lookup (the call count is 0); deleting `devnet`'s 421614 refusal and its
42161 refusal separately; reverting a help sentence **and re-blessing** (only the content test
reds — which is why it exists); restoring the script's old grep (the offline guard mode refuses
a Sepolia-shaped file); restoring the old no-definition copy; routing the backfill's public chain
through `select_network` (its panicking lookup fires); comparing the plan's network with itself.
`U93`: passing the recorded network into the top-level member for `restore` (top-level reads
`devnet`); writing the invocation's network into `result.network` (reads `arbitrum-one` or
`arbitrum-sepolia`); hard-coding the top-level default (only the config control reds); deleting
`reveal`'s `result.network` (the registry test names `[reveal]`).

## 4. What this record does NOT decide

- A carve-out for an external vault holding a `devnet` work paid on 421614 — none recommended;
  none known to exist.
- D38's contingency D3 (self-deployed Sepolia contracts) — it would have no network id under
  §2 R2/R3; if ever built it owes its own ruling.
- The export's `RPC_URL` and `config.toml`'s per-network `rpc_url` being ignored — `U94`.
- End-to-end behaviour of a loopback-peer client with the flag false — superseded by D173 §2 R8.
- Whether a network member belongs in `error` objects after a work is resolved — not before
  `U32` without a consumer asking.

## 5. Edit list — per write scope, with the lane named before this record was written

### RN (the network-crate lane)
- `crates/antseal-net/src/network.rs`: §2 R1 and §2 R2's pure half (the chain classifier and
  the contract comparison), a canonical Sepolia fixture beside the existing mismatch fixture,
  and `arbitrum-sepolia`'s `bootstrap.is_empty()` assertion.

### RC1 (the CLI resolver lane)
- `crates/antseal-cli/src/devnet_env.rs` (§2 R2–R4, R7, the fixtures split into canonical and
  mismatch); `crates/antseal-cli/src/backend.rs` (`payment_rpc` §2 R6); `crates/antseal-cli/src/commands.rs`
  (§2 R8); `crates/antseal-cli/src/cli.rs`, `tests/snapshots/cli-surface.help.txt` and
  `tests/cli_surface.rs` (§2 R9); `tests/restore_output.rs` (the §2 R7 negative fragment).

### RC2a (the envelope lane) — after RC1
- `crates/antseal-cli/src/restore_out.rs`, `crates/antseal-cli/src/reveal_out.rs` (and
  `pipeline/restore.rs` only if the report does not already carry the record's network) per
  §2 R12; `crates/antseal-cli/src/machine.rs` docs per §2 R13; `tests/snapshots/json-envelopes.txt`
  (`[restore]` and `[reveal]` re-blessed through the real producers, the restore fixture recorded
  as `devnet` so the committed example shows the members differing); `tests/machine_mode.rs`
  (§2 R14 and struct literals); `tests/restore_output.rs` (§2 R15).

### RD (the devnet-and-user documentation lane)
- `docs/user/funding-your-wallet.md`, `docs/devnet/sepolia-devnet.md` (§2 R9);
  `scripts/e2e-sepolia.sh`, `docs/drills/vault-restore-drill.md` and its evidence template
  (§2 R10).

### Registrar
- `U92` and `U93` Notes; a dated addendum on D65 (§2 R13); index row and register row.

## Closing — this record is not consent

It authorises no network act beyond the local devnet.
