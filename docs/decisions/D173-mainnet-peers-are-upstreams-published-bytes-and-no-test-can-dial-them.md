# D173 — `arbitrum-one`'s peers are a **byte-identical copy of upstream's published list at the pin**, overridable only by `config.toml`; peers resolve **per network, replace-never-merge**, in a step only commands that dial ever call; one locality classifier decides loopback everywhere; **no test or CI job can dial a non-loopback storage peer**; and `status` reads its receipt with no Autonomi session and no key

- **Status: RESOLVED. Every one of the four planned decisions (D-a, D-c, D-d and the
  resolution rule) survived in direction and fell in its premises, one was unbuildable
  as written, and the planning round found a question nobody had asked.**
  - **D-a (vendor upstream's list) — the bytes are right, the claim was too wide.**
    Upstream's `resources/bootstrap_peers.toml` at the pin's publishing tag
    `ant-core-v0.5.0` (`d93a9719041e0acbafd3eb07feeb9cc06f3fff0b`) is git blob
    `ce77014eb4f387ff8c345473b4bffc68d445d8fd`, 464 bytes, sha256
    `9f372ec1c54e25d55cde380dbb7df358345112be26bffc57c167451e935f3e02`, seven IPv4
    `ip:port` entries — re-fetched by the orchestrator before this record was written.
    But a blob test proves *these are the bytes upstream published*, never *these are
    Autonomi's live nodes*: the seven are rented cloud machines with no pinned identity,
    the list has rotated once for dead addresses, and a git blob id is SHA-1. The list's
    own header calls it the **production** list, so it attaches to `arbitrum-one` alone.
    §1.1.
  - **"Overridable by config" does not exist and its precedent is dead**: `config.toml`
    has no peer key, and the sibling `rpc_url` override is parsed, validated and **never
    consumed** while `docs/config.md` says it is. §1.5.
  - **D-c (no peer flag) — holds**, on the ground that config and the devnet export meet
    every measured need; the stated reason for replace-not-merge then has no instance,
    and the rule survives on other grounds. §2 R5, R6.
  - **The resolution rule — one chain, "first non-empty", refuse before the passphrase —
    fell three ways**: the layers are **per network id**; a present layer must be
    **non-empty where it is parsed**, never skipped when empty; and `restore` reads its
    network from inside the vault (D170 §2 R3), so its refusal is after the unlock. And
    the refusal **cannot live in `select_network`**, because `status`'s receipt backfill
    calls it and needs no peers. §1.3, §2 R6–R7.
  - **D-d (a connect-only stage 0 proves the seeds reachable) is UNBUILDABLE**: a connect
    returns `Ok` against an empty or all-dead peer set (measured at wave 35: 45 ms and
    6.3 s), so the stage cannot fail; and *"before `Q34`"* dissolves, because nothing
    proves a public peer reachable without contacting it. §1.7, §2 R16.
  - **The dial gate's placement and arming fell**: the payer's first socket is an
    `eth_chainId` call to evmlib's **built-in public RPC** (the configured `rpc_url` is
    ignored for public ids), not `Client::connect`; and almost every connect-capable
    test is an in-process library test that no spawn helper reaches and that cannot arm
    itself. §1.4, §2 R9–R11.
  - **`status` dials Autonomi to read an EVM receipt**: its backfill runs
    `SealBackend::connect` → `Client::connect` and never uses the client, and loads the
    vault's wallet key to read a public receipt — so vendoring peers alone would make
    `status` dial mainnet. D33 had already ruled the key-less route. §1.3, §2 R14.
  - **A question nobody asked: whether the pinned client can still store and pay
    against today's network is NOT ESTABLISHED.** Upstream is at `ant-core` 0.8.1 and
    `ant-node` v0.18.1 against the pin's 0.5.0 and dev-pinned 0.15.0; nodes auto-upgrade
    within 24 hours; the protocol crate's own source is identical and the wire types
    lean compatible, but a new node check on payment settlement and thousands of lines of
    transport change were not read. Minted as **`S41`**. §1.6, §2 R17.
- **Date: 2026-09-15**
- Owner rows: **`S40`** (this record's subject; its `Accept` is restated by §2 R7 and
  §2 R16), **`U92`** (the Sepolia layer of §2 R6 — ruled by D174), **`U91`** (§2 R7's
  lazy call), **`Q34`** (§2 R16's stage 0 and the maintainer ruling it needs), **`Q272`**
  (the threat surface; §2 R15's pin), **`S41`** (minted: interoperability of the pinned
  client with the current node release), **`S42`** (minted: every connect reads and
  every dropped client writes upstream's `client_adaptive.json`, and a client panics
  with no `HOME`), **`U94`** (minted: the `rpc_url` override is parsed and never
  consumed), **`P19`**/**`S20`** (freshness and the bump checklist, §2 R18).
- Related: **D33** (the receipt read's locus), **D43**, **D52** (the devnet gate),
  **D99** and **`Q16`** (the no-real-anchor-network gate this mirrors), **D134** §2 R3
  (the exit-code table), **D170** (the reader; §1.6 and §2 R10 are superseded for the
  peer half by this record), **`U1`** (the canonical surface), **`U89`**.

## 0. What was measured against

`HEAD` `3473ab2`. Planning lane P1a read upstream `WithAutonomi/ant-client` at the pin's
tag and at its current release, the pinned `ant-core` 0.5.0, `saorsa-core` 0.26.2 and
`saorsa-transport` 0.35.1, and — at the orchestrator's mid-flight request — compared
`ant-protocol` 2.3.0→2.3.5, `saorsa-core` 0.26.2→0.27.3, `saorsa-transport`
0.35.1→0.36.3, `evmlib` 0.9.0→0.9.1 and `ant-node` 0.15.0→0.18.1 from crates.io
tarballs. Planning lane P1b read the anchor gate's whole shape (`Q16`, D99), every
connect site and `ClientConfig` path, and upstream's on-disk client state. Neither lane
ran cargo, a gate or any network write. The orchestrator re-fetched the list at the tag
and hashed it three ways (API `.sha`, `git hash-object`, `sha256sum`), and read the
crates.io version lists, before this record was written.

## 1. What was measured

### 1.1 Upstream's list

- `resources/bootstrap_peers.toml`: blob `ce77014e…` at `ant-core-v0.5.0`, at
  `ant-cli-v0.3.6` (the current release) and at upstream `main` (`c63ca68`); present in
  83 of 84 releases (the planning figure of 82 was wrong by one). One rotation, commit
  `bcf44182` (2026-04-03, *"replace dead IPs"*). Upstream rewrites `main` (a
  `backup/pre-main-rebase-…` branch exists), so the tag and the SHA are cited, never
  `main`.
- Seven IPv4 socket addresses, all port 10000; no hostname, IPv6 or multiaddr — exactly
  `Client::connect`'s `&[SocketAddr]`; nothing on the pinned path resolves DNS.
- Hosting registry data names Vultr, Hetzner and AWS; **no operator and no peer
  identity is pinned**. Whether any seed is live today was deliberately not measured —
  measuring is a public dial.
- Upstream's `ant` CLI resolves `--bootstrap` > a devnet manifest > its platform
  `bootstrap_peers.toml` > a hard error, installs that file only if absent, and **merges
  its peer cache into the dial list**; its developer docs say a source build must supply
  its own peers.

### 1.2 What the pinned stack does with peers, and what it leaves on disk

- `saorsa-core` returns `Ok` on an empty or all-dead bootstrap set.
- **No peer cache on antseal's path**: `ant-core` has one (`client_peer_cache.json`,
  cached peers ordered *ahead* of configured ones), enabled only through
  `Client::from_node_with_peer_cache`; `Client::connect` hard-codes
  `peer_cache_path: None` (`ant-core-0.5.0/src/data/client/mod.rs:431`) and no
  `ClientConfig` field reaches it. `saorsa-core`'s close-group cache defaults to `None`.
- **But upstream client state IS read and written**: `Client::connect` loads, and
  `impl Drop for Client` writes on every drop, `client_adaptive.json` (three
  concurrency starting values, no peers) in `$XDG_DATA_HOME/ant` or
  `~/.local/share/ant` — the directory upstream's own `ant` CLI uses
  (`mod.rs:323-338`, `:587-595`; `adaptive.enabled = false` does not stop the write).
  That directory exists on the maintainer's host with the file's mtime on wave 35's
  devnet day. And `Client::connect` **panics** in a process with neither `HOME` nor
  `XDG_DATA_HOME` (`ant-core-0.5.0/src/config.rs:19-21`). Both are `S42`.

### 1.3 The four doors, and the one that dials for no reason

| door | network source | adapter |
|---|---|---|
| `seal` (and resume) | the plan's network, default `arbitrum-one` | payer |
| `status <id>` receipt backfill | the work's **recorded** network | **payer** — `payment_rpc` → `SealBackend::connect` → `Client::connect`, whose client the backfill never uses; it also loads the wallet key |
| `restore` | the work's recorded network (read after the unlock, D170 §2 R3) | reader |
| `verify --live` | the invocation's network | reader, after offline verification |

The upgrade hook names no storage backend. `seal`'s refusal slot is after the vault
lock and before `collect_passphrase`, the unlock, the connect and the journal.

### 1.4 What the dial gate must cover

- **The payer's first socket is not `Client::connect`**: it calls `eth_chainId` first,
  and for `arbitrum-one`/`arbitrum-sepolia` that goes to evmlib's compiled-in public RPC
  (`crates/antseal-net/src/evm.rs` maps those ids to evmlib's built-in networks; only
  `devnet` threads the configured `rpc_url`).
- **Every connect runs UPnP gateway discovery**: `saorsa-transport`'s default `upnp`
  feature starts an IGD mapping service on every endpoint, may request a one-hour
  router port mapping, and no `ClientConfig` field or downstream feature switch turns it
  off at the pin.
- **The protection that exists is an unrecorded control**: the empty `bootstrap` of the
  public configs is the only reason a public-id connect dials no peer, and
  `network.rs`'s test records it as a fact about upstream (*"no compiled-in mainnet
  peers"*), not as a control — vendoring deletes it in the act that makes it
  load-bearing.
- **Arming by venue alone is too weak**: the anchor gate's spawn helper and workflow
  arming reach spawned binaries and whole runs, but every connect-capable storage test
  except two spawned rows is an in-process library test, and a test cannot arm itself
  (`set_var` is `unsafe` and `unsafe_code` is denied). D99 refused a compile-time arm
  because feature unification would arm a test whose disarmed arm must reach the
  network; the storage gate has no such test and must never have one, and
  `cfg!(debug_assertions)` is a profile property, not a feature.

### 1.5 The config surface

No peer key exists; a `bootstrap` key is today an unknown-key warning. The `rpc_url`
override under `[networks.*]` is validated at load and has **no production reader**
(the only reference outside its definition is a config-file test), while
`docs/config.md` says it is consumed by the payment backend (`U94`).

### 1.6 The version gap

| | antseal's pin | upstream today |
|---|---|---|
| `ant-core` | 0.5.0 (2026-07-23) | 0.8.1 (2026-09-02) |
| `ant-protocol` | 2.3.0 | 2.3.5 — `src/` sha256-identical |
| `saorsa-core` / `saorsa-transport` | 0.26.2 / 0.35.1 | 0.27.3 / 0.36.3 |
| `evmlib` | 0.9.0 | 0.9.1 — comment-only diff; payment contracts identical |
| `ant-node` | 0.15.0 (dev pin) | v0.18.1; v0.19.0-rc.2 out |

Unchanged: protocol identifiers, 28 of 29 serializable `saorsa-core` types (the 29th is
local configuration), PeerId derivation, address encoding, QUIC versions, the handshake
crypto; `ant-node` has no client-version gate. **Not read**: ~3.4k changed lines of
`saorsa-core` networking, ~2.6k of NAT traversal and relay, and ~461 production lines of
`ant-node` payment verification — including a new rejection when settlement does not
credit the quote's own rewards address. Upstream ships client and node in lockstep,
nodes auto-upgrade within 24 hours, and a node-side policy change has broken clients in
production before (the 2026-07-06 merkle outage). **So nothing proves the pinned client
can store and pay against today's network, and the paid smoke seal would be the first
test of it.**

### 1.7 What can prove the network answers without paying

A connect cannot (§1.2). `seal --dry-run` performs a real quote — each blob's close
group must answer — with no vault write, consent, anchor, payment or upload (D49), so it
proves routing and the quote protocol, not PUT acceptance or payment verification.
`docs/threat-model.md` §2.9 accepts *"a single small real mainnet smoke seal … one seal,
one work, before release"* and names no probe.

## 2. RULING

### §2 R1 — `arbitrum-one`'s built-in peers are upstream's bytes at the pin

A byte-identical copy of `resources/bootstrap_peers.toml` at `ant-core-v0.5.0` is
committed as a data file inside `crates/antseal-net` (default features, the pure-data
half; the verifier never depends on this crate) and embedded at compile time.
**`arbitrum-sepolia` and `devnet` carry no built-in peers**, asserted by test.
**[Corrected in place before this record landed, 2026-09-15 — a collision between this rule
and §2 R15, found by the lane writing the pin.]** §2 R15 refuses any code line naming the
literal `bootstrap_peers.toml`, so the vendored copy is **named without that substring**,
and upstream's path and commit URL appear **only in comments** — never in a string
constant or a test message. The pin is not given an exemption: the file's bytes, not its
name, are what the provenance test proves.

### §2 R2 — Provenance is three constants, each with one job

sha256 `9f372ec1…3e02` (**integrity**), upstream blob `ce77014e…` (**selector**, for the
freshness comparison) and the tag plus commit (**audit path** — the full URL, which ends in
upstream's filename, lives in the constants' doc comment per §2 R1's correction). One offline test
recomputes **both** hashes over the embedded bytes, with known-answer controls for the
blob-id function (`e69de29bb2d1d6434b8b29ae775ad8c2e48c5391` for the empty blob,
`ce013625030ba8dba906f756967f9e9ca394464a` for `hello\n`) so a function returning its
constant goes red; its failure message names the tag and says *re-transcribe at a pin
bump, never hand-edit*. **No document, comment or message claims the seeds are
authenticated, operated by a named party or live** — the claim is exactly *these are the
bytes upstream published at the pin*.

### §2 R3 — A strict parser, and a failure that cannot become an isolated client

Blank lines, `#` comments, one `peers = [` line, one `"<ip>:<port>",` per line, one `]`;
anything else is an error. Every entry is an IP-literal `SocketAddr`, not unspecified,
port not zero, no duplicates. A test compares the parse with an **independent
transcription** of the seven addresses in file order, so a parser that skips an entry
goes red. `NetworkConfig::arbitrum_one()` stays infallible: a parse failure yields an
empty list, which §2 R7 refuses — never an isolated client. **[Corrected in place before
this record landed, by the implementing lane]**: as first written this sentence asked for a
`debug_assert!` *and* said *"never a panic"*, which contradict each other in a debug build.
Read it as: a release build never panics; a debug build's `debug_assert!` fires on a vendored
file the provenance test would already have refused.

### §2 R4 — `config.toml` may override `arbitrum-one`'s peers, validated at load

`[networks.arbitrum-one] bootstrap = ["ip:port", …]`, accepted **only** under
`arbitrum-one`; under `arbitrum-sepolia` or `devnet` the key is a malformed-config error
(17) naming `ANTSEAL_DEVNET_ENV` as those networks' only peer source. Validated at load —
at least one entry, IP literals, no duplicates, no unspecified address or port zero, not
loopback, not mixed — else 17, raised before dispatch and therefore before any
passphrase. **A consumer-level test** asserts the `NetworkConfig` handed to the backend
constructor carries exactly the override's peers, because `rpc_url` shows a slot can
parse and go unused.

### §2 R5 — No peer flag and no peer environment variable

The surface does not change for `S40` (its evidence records the help snapshot's sha256
before and after the act). A later `--bootstrap` would be a recorded `U1` amendment,
global and repeatable, above config, replacing and never merging, validated as §2 R4.
A peer environment variable is refused: it would be an invocation-scoped injection
vector that load-time validation never sees.

### §2 R6 — Per-network tables, first present layer wins, replace and never merge

| network | layer 1 | layer 2 | none present |
|---|---|---|---|
| `arbitrum-one` | `[networks.arbitrum-one] bootstrap` | the vendored list | no peers → usage 2 (reachable only if the vendored list is unusable) |
| `arbitrum-sepolia` | the validated Sepolia export (D174) | — | no peers → usage 2, naming `scripts/devnet/sepolia-up`, `ANTSEAL_DEVNET_ENV`, and that no public Autonomi network exists on Arbitrum Sepolia |
| `devnet` | the export | — | the existing no-definition refusal → usage 2 |

**A present layer is non-empty, checked where it is parsed** (the export already
refuses an empty `BOOTSTRAP`; the override is 17 per §2 R4; the vendored list per §2 R3),
so no layer is ever silently skipped. `arbitrum-one` never reads the export (`U89`).
**No upstream file, no peer cache and no second layer is ever unioned into a resolved
set** — replace, because one resolved set has one provenance (which `Q272` ranks), an
override exists to stop dialing dead or hostile seeds that a merge would keep dialing,
and a merge of loopback with public peers manufactures the mixed state no transport
mode can serve.

### §2 R7 — Resolution is a separate step that only dialing commands call

`select_network` keeps returning the network **definition** — chain half plus whatever
peers its layers carry — and validates any export it reads (D174), but **never refuses
because peers are absent**. A new `resolve_peers` step applies §2 R6 and §2 R8 and maps
its refusals to usage (2). Its callers, and when:

- `seal` — before any passphrase, unlock, connection or journal write;
- `verify --live` — before verification (D170 §2 R6);
- `restore` — after the unlock, before any connection or output write (D170 §2 R3,
  stated in its rustdoc);
- `reveal` — lazily, at its first needed fetch (D175);
- `status` — **never**.

**`S40`'s `Accept` row 1 is restated accordingly**: a table test shows replace-not-merge;
a planted empty set refuses with usage 2 **before any passphrase is read for `seal`**,
with no vault file other than the lockfile changed; a one-byte edit to the vendored list
turns the provenance test red by message.

### §2 R8 — One locality classifier decides "loopback" everywhere

In `antseal-net`: canonicalize IPv4-mapped addresses (`[::ffff:127.0.0.1]` is loopback,
matching `saorsa-core`'s canonicalization); **an empty set is an error, never
"loopback"** (a bare `iter().all(is_loopback)` returns true for an empty slice); mixed
loopback and public is an error; unspecified, port-zero and duplicate entries are errors;
errors name indices, never addresses. The adapter's `client_config` derives
`allow_loopback` from it and **refuses with `StorageError::Network` before
`Client::connect`**, in both the payer and the reader — the variant D170's absence tests
already accept, so `devnet_d170_an_unreachable_network_is_never_reported_as_absence`'s
empty-bootstrap arm stays green and now witnesses the refusal (its doc comment is
rewritten). `arbitrum-one` requires public peers; `arbitrum-sepolia` and `devnet` accept
either class and refuse mixed. **Recorded behaviour change**: a `devnet` export with
non-loopback peers now binds all interfaces instead of loopback only.

### §2 R9 — The storage gate: a predicate, a variable, and a debug-build arm

`network.rs` owns the decision, with no `ant_core` use, so the required default-feature
`test` job unit-tests it: armed ⇒ §2 R8 classifies every bootstrap peer as loopback; an
empty set is admitted (no peer to refuse — §2 R7 refuses it separately); otherwise the
connect fails `StorageError::Network` with a reason beginning with one `pub const`
sentence naming the variable, followed by the number of refused peers (a constant cannot
hold the count — corrected in place by the implementing lane). **No new `StorageError`
variant.** The variable is **`ANTSEAL_NO_REAL_STORAGE_NETWORK`**, separate from the
anchor gate's. The decision: `cfg(test)` of `antseal-net` ⇒ armed, no off switch;
`Some("0")` ⇒ disarmed (the only off switch); any other value ⇒ armed (fail closed);
**unset ⇒ armed exactly when `cfg!(debug_assertions)`** — so a bare `cargo test` of any
devnet suite is armed, and the release binary is unaffected unless the variable is set.
Consulted per connect, never cached. The refusal text says a debug build needs `=0` to
reach a public network. No script runs `cargo test --release` (measured), so the profile
arm has no bypass venue today.

### §2 R10 — The gate is the first fallible step of both constructors, witnessed twice

It runs before `to_evm_network` and the `eth_chainId` call in `AntCoreBackend::connect`,
and first in `AntCoreReader::connect`. **Shape witness, default lane**: a source scan
asserts exactly one code-line `Client::connect(` per constructor in
`crates/antseal-net/src/ant_backend.rs`, none elsewhere under `crates/`, and the gate
named before each constructor's first `.await`. **Behaviour witness, heavy tier**: the
reader over `bootstrap: [[100::1]:9]` (RFC 6666's discard-only block — never a routable
host) with id `arbitrum-one` is refused by message within a second; the payer with id
`devnet`, a loopback `TcpListener` as its RPC and the same peer is refused with **zero**
accepted RPC connections; controls: a loopback peer is admitted, and the listener
observes an accept when the gate admits. **[Corrected in place by the implementing lane]**:
no heavy row runs a real reader `Client::connect` as a control, because each one would write
upstream's `client_adaptive.json` and run UPnP discovery on every heavy run (`S42`, §1.4);
admission is witnessed by the payer control and by the refusal messages.

### §2 R11 — Venues, as the anchor gate's

`crates/antseal-cli/tests/common/spawn.rs` sets both variables; the `env_clear()` child in
`tests/e2e_restore.rs` re-arms both; every `.github/workflows/*.yml` top-level `env:`
block and `scripts/local-gate.sh` export it; `tests/anchor_stage.rs`'s runtime spawn
assertion gains a storage sibling. `scripts/check-anchor-net.py` R1 and R4 iterate over
**both** variables through the same functions (so the storage arming cannot be checked
by a weaker copy), and its `env_clear()` rule tightens from **file level to call level**
— today a second, unarmed `env_clear()` in a file that re-arms once passes.

### §2 R12 — The retired control is recorded in the act that retires it

`network.rs`'s field doc and its `bootstrap.is_empty()` assertion flip with the reason
(`S40` `Accept` row 4); the Sepolia half of that test gains `bootstrap.is_empty()` with
the reason *the production list must never attach to a test chain*;
`crates/antseal-net/tests/devnet_backend.rs`'s sentence calling an empty list *the shape
the public configs carry today* is rewritten; and `docs/instrument-ledger.md` records that
the empty `bootstrap` was the unrecorded control, retired by `S40`, replaced by §2 R9.

### §2 R13 — The policy says what the gate does not cover

A `CONTRIBUTING.md` section beside the anchor gate's names: peers learned from the DHT
after bootstrap (safe only because an all-loopback set binds loopback, §2 R8); the payer's
EVM RPC; UPnP gateway discovery (§1.4 — unswitchable at the pin); and upstream's
`client_adaptive.json` (`S42`). Real-network runs remain scripts run with the release
binary in an unarmed environment, never tests.

### §2 R14 — `status` reads its receipt with no Autonomi session and no key

`ant_backend.rs` gains a third raw adapter type, a **receipt reader** built with
`ant_protocol::evm::utils::http_provider` over the definition's RPC URL — no `Client`, no
wallet, no EVM network object — whose constructor performs the payer's chain-id guard and
whose one method is today's `backfill_block_numbers` body; the payer delegates to it.
`backend.rs`'s `payment_rpc` builds it and **loads no wallet key**, so a vault with no
wallet record can be backfilled. The storage gate is not consulted by the receipt reader
(it opens no storage session); the EVM RPC stays outside both gates. The raw-type scan
and the net-site counts that pin today's shape are re-counted in the same act. The public
chain half for `arbitrum-one`/`arbitrum-sepolia` comes from the pinned constants without
reading the export (D174 §2 R6).

### §2 R15 — No upstream peer file, loader or cache, pinned in source

A default-lane source-text test (code lines only, comments exempt) fails naming the file,
the line and the name when anything under `crates/*/src` names
`from_node_with_peer_cache`, `save_peer_cache`, `load_bootstrap_peers`,
`close_group_cache_dir`, `client_peer_cache` or the literal `bootstrap_peers.toml`. Baseline
at `3473ab2`: zero hits. It is shared with `Q272`'s section, which states the property, and
is written by that row's lane (D176).

### §2 R16 — No reachability claim before `Q34`; a pay-free stage 0 inside it, on a maintainer ruling

Before `Q34` the list carries only §2 R1–R3's offline guarantees and §2 R18's freshness
comparison, and documents say exactly that. **A connect-only stage is refused** — it cannot
fail. The mechanism that can: **`seal --dry-run --json <smoke-file>` on `arbitrum-one`, on
the gate machine, with the released binary, immediately before the smoke seal** — pass is
exit 0 with `"dry_run": true` and at least one priced blob; anything else stops the gate.
It needs no code. **It is not ruled here**: `docs/threat-model.md` §2.9 accepts one seal, and
naming a pre-seal quote in that accepted exposure is a change to an accepted risk — **the
maintainer's ruling**, recorded on `Q34` as owed before the gate. A rehearsal of the stage's
predicate against a dead loopback devnet export (exit 23, no dry-run document) and a live
one (exit 0) is owed by `Q32`'s scripting before it is ever pointed at mainnet.
`scripts/e2e-sepolia.sh` gains no mainnet stage.

### §2 R17 — Interoperability is a row, and a red makes a pin bump a `Q34` prerequisite

**`S41`**: before `Q34`, antseal's pinned client runs the full devnet E2E — quote, pay,
store, fetch, restore — against the **latest non-prerelease `ant-node` release** on loopback
with Anvil, the only exposure-free test of storing and paying; its first act is measuring
whether `devnet-launcher` can host a foreign-version node at all. It joins `S20`'s bump
checklist as a standing check, re-run at `Q34`'s date. A red makes a deliberate pin bump
(rule 5: survey, pinning, devnet E2E) a prerequisite of `Q34`; a green is recorded on `Q34`
and in `Q272`'s section as *the pinned client is N releases behind the network;
interoperability proven on loopback at <date> against ant-node <version>*.

### §2 R18 — Freshness and the bump checklist

`P19`/`S20` gain a weekly read of the list's blob id at the pin's tag (authoritative) and at
upstream's current release (informational). Re-transcription happens at each pin bump, with
the constants re-derived from upstream, never from the vendored file. A **peers-only
re-transcription from a newer release tag** is allowed as a reviewed data event without a
pin bump — unless it coincides with an upstream network reset, which is a pin-bump event.
The `S20` checklist gains: `Client::connect`'s `peer_cache_path` initializer,
`build_controller`'s persistence and `impl Drop for Client`, `saorsa-transport`'s `upnp`
default feature, and upstream's newer `resolve_bootstrap_peers` (ant-core 0.8.0), which a
bump could make compete with §2 R6.

## 3. Fault plants

Owed by the implementing lanes, each keeping the code compiling, baseline green first,
judged by message, `touch` after every restore:

| clause | plant | red by |
|---|---|---|
| provenance | change `149.248.9.2` to `149.248.9.3` in the data file | the provenance test naming both hashes and the tag |
| strict parse | `continue` on a parse error | *an entry that is a hostname must be refused* (corrected in place: every entry in upstream's bytes parses, so the transcription test stays green under this plant) |
| no skipped entry | drop one parsed entry | *parse must equal the independent transcription: 6 vs 7* |
| production-only | `arbitrum_sepolia()` returns the vendored peers | *arbitrum-sepolia must carry no built-in peers* |
| override consumed | the backend config built from `arbitrum_one()` ignoring the override | the consumer-level test |
| override validated | drop the `SocketAddr` parse at load | `example.org:10000` loads |
| replace-not-merge | chain the override with the vendored list | the table row: 8 peers vs 1 |
| export never read for `arbitrum-one` | resolve it export-first | the injected reader panics |
| refusal before the passphrase | move `resolve_peers` after `collect_passphrase` | the spawned test: expected exit 2, got 11 |
| empty is never local | drop the `Empty` arm | `[]` classifies `Loopback` |
| mapped loopback | drop the canonicalization | `[::ffff:127.0.0.1]` classifies public |
| adapter defence | `client_config` ignores the classifier's `Err` | a set the armed gate admits but the classifier refuses (empty, a repeated loopback peer, loopback peers under `arbitrum-one`) reaches the connect — corrected in place: a mixed set cannot witness it, because the armed gate refuses it first |
| gate predicate | admit any IPv4 | `192.0.2.1:9` admitted while armed |
| fail closed | only `"1"` arms | `""`, `"false"`, `"0 "` disarm |
| debug arm | unset ⇒ disarmed | `decide(false, true, None)` disarmed |
| reader wiring | delete the reader's gate call | the heavy row: connected over `[100::1]:9` |
| payer placement | move the gate below `eth_chainId` | the listener counts ≥ 1 accept before the refusal |
| shape | a second `Client::connect(` without the gate | the scan counts 3 |
| workflow arming | delete the variable from `ci.yml` | `check-anchor-net.py` R1 naming the storage variable |
| call-level re-arm | a file with two `env_clear()`, one re-armed | `check-anchor-net.py` R4 |
| no Autonomi session in `status` | restore `SealBackend::connect` in `payment_rpc` | datagrams reach a held loopback bootstrap socket, with a `restore` control that also produces datagrams, and preconditions (a wallet record exists; the RPC stub saw `eth_chainId`) asserted inside the test |

## 4. What this record does NOT decide

- **The §2.9 wording for §2 R16's stage 0** — the maintainer's.
- Whether any seed is live, or who operates it.
- Confining `client_adaptive.json` or guarding the no-`HOME` panic (`S42`), and the unconsumed
  `rpc_url` override (`U94`).
- Whether the pinned client interoperates with the current node release (`S41`).
- Switching off UPnP discovery — unavailable at the pin; recorded, not gated.

## 5. Edit list — per write scope, with the lane named before this record was written

### RN (the network-crate lane) — first
- `crates/antseal-net/src/network.rs`: the vendored embed, parser, provenance constants and
  tests (§2 R1–R3); the locality classifier (§2 R8); the gate predicate and decision (§2 R9);
  the doc and assertion flips (§2 R12); D174 §2 R1's export classifier and §2 R2's pure half.
- The vendored data file under `crates/antseal-net/src/`.
- `crates/antseal-net/src/ant_backend.rs`: the gate first in both constructors (§2 R10); the
  derived `allow_loopback` and pre-connect refusal (§2 R8); the receipt reader (§2 R14).
- `crates/antseal-net/src/lib.rs`, `crates/antseal-net/Cargo.toml` (dev-dependencies `sha1`
  and `sha2` from the workspace), `Cargo.lock`.
- `crates/antseal-net/tests/`: the shape scan and the heavy-tier gate rows (§2 R10);
  `devnet_backend.rs`'s rewritten sentence and the backfill's move to the receipt reader.

### RC1 (the CLI resolver lane) — after RN is verified by the orchestrator
- `crates/antseal-cli/src/devnet_env.rs` (`resolve_peers`, the injected table core and its
  table test, §2 R6–R7, with D174's arms); `crates/antseal-cli/src/config.rs` and
  `tests/config_file.rs` (§2 R4); `crates/antseal-cli/src/commands.rs` (the three call sites,
  §2 R7); `crates/antseal-cli/src/backend.rs` (`read_only_network`'s peer step; `payment_rpc`
  per §2 R14; the raw-type scan); `crates/antseal-cli/src/pipeline/receipt_backfill.rs`
  (prose); `tests/common/spawn.rs`, `tests/e2e_restore.rs`, `tests/anchor_stage.rs`
  (§2 R11); `tests/receipt_backfill.rs` (net-site counts and the datagram row); the spawned
  ordering test (§2 R7).

### L-CI (phase 2) — after RC1
- Every `.github/workflows/*.yml` top-level `env:` and `scripts/local-gate.sh` (§2 R11);
  `scripts/check-anchor-net.py` (both variables, call-level `env_clear()`, new self-test
  arms); `CONTRIBUTING.md` (§2 R13).

### RD (the devnet-and-user documentation lane)
- `docs/config.md` (the new key); `docs/dependency-policy.md` §4 (§2 R18's checklist lines).

### RT (the threat-model lane)
- The §2 R15 source-text pin, per D176.

### Registrar — `TODO.md`, `tasks/S.md`, `tasks/U.md`, `tasks/Q.md`, `tasks/P.md`, `docs/decisions/README.md`, `docs/instrument-ledger.md`, dated addenda
- `S40`'s `Accept` rows 1 and the D-d clause restated per §2 R7 and §2 R16; `Q34` Notes (stage
  0 and the owed maintainer ruling); mint `S41`, `S42`, `U94`; `P19`/`S20` Notes per §2 R18.
- A dated addendum on D170 (§1.6 and §2 R10's peer half are superseded by this record).
- `docs/instrument-ledger.md`: the empty `bootstrap` as an unrecorded control (§2 R12); the
  anchor checker's file-level `env_clear()` rule; the planning figure 82 of 84 that is 83.
- Index row and register row for this record.

## Closing — this record is not consent

It authorises no public-network act. Every test it adds runs against loopback or refuses
before any socket; `Q34`'s stage 0 needs the maintainer's ruling on §2.9 and, like the
smoke seal, the maintainer's express consent at the gate.
