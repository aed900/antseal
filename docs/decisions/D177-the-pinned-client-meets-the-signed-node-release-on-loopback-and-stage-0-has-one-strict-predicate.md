# D177 — The pinned client is tested against the node release the network runs **as upstream ships it** — signed release binaries in **one loopback-only namespace**, behind a **control arm** — and stage 0 has **one strict predicate**, rehearsed on loopback

- **Status: RESOLVED. The row's harness lean fell on its premise; "the wire leans
  compatible" kept its direction while four of its premises fell; every named cause of a
  red was refuted by reading, which leaves the outcome NOT ESTABLISHED rather than green;
  and stage 0's predicate as D173 ruled it passes a document produced with no network
  contact.**
  - **`devnet-launcher` cannot host a foreign node.** Its nodes are tokio tasks of the
    launcher process, linked through `ant-core` 0.5.0's `devnet` feature, which requires
    `ant-node` 0.15.0 — upstream's own manifest says a skew makes the two crates'
    `MultiAddr` types mutually incompatible — and `ant-node` 0.22.0 needs rustc 1.95
    against the pinned 1.92.0. The row's fallback, upstream's `start-local-devnet`, is
    dominated: also in-process, 25 nodes, writes the shared data directory, needs rustc
    1.95 and a heavy build; no `ant-devnet` binary is released. §1.1.
  - **The row's versions moved.** The latest non-prerelease `ant-node` is **v0.22.0**
    (2026-10-08, `008d2ad`), with v0.23.0-rc.1 out; `ant-core` is at 0.12.0 and
    `ant-protocol` at 4.0.0 — against the row's 0.8.1, 2.3.5 and v0.18.1. **Ten**
    non-prerelease node releases follow the dev pin. §1.2.
  - **The wire still leans compatible, more strongly than D173 read it, and four premises
    fall**: `ant-protocol`'s `src/` changed (append-only on the wire); a client-version
    gate now exists — settlement versioning and `ClientUpdateRequired` — but is not
    applied to the legacy quote request the pinned client sends; and 25 of 29 serializable
    `saorsa-core` types are unchanged, not 28. Unread: 4,200 changed code lines in
    `saorsa-transport`. §1.3.
  - **Every named cause of a red is refuted by reading** — the client pays the quote's own
    rewards address, the contracts and the quote hash are byte-identical, the legacy
    request is still served, the median rule is the same — so the register drops them and
    names **the transport** as the residual risk. §1.3, §2 R8.
  - **Flags cannot make the released binary loopback-only**: it loads the mainnet peer
    file shipped beside it, defaults to Arbitrum One, and polls GitHub hourly to replace
    itself, with no off switch. A namespace whose only interface is `lo` closes all three;
    the orchestrator added a mount namespace that hides the operator's home secrets from
    the node processes. §1.4, §2 R2.
  - **Stage 0's predicate as D173 §2 R16 ruled it is too weak**: exit 0 with
    `"dry_run": true` passes the resume-plan document, which `seal --dry-run` emits over a
    resumable work **before any backend call**. On the committed envelopes the naive
    predicate passes two of the four `seal` documents and the strict one passes one.
    §1.6, §2 R10.
- **Date: 2026-10-16**
- Owner rows: **`S41`** (this record's subject: the harness, the control arm, the verdict
  line); **`Q32`** (stage 0's predicate and its loopback rehearsal, owed by D173 §2 R16);
  **`Q34`** (the verdict line is recorded on it; a red makes a pin bump its prerequisite;
  stage 0 runs inside it); **`S20`** (the bump checklist's `S41` bullet).
- Related: **D173** §2 R16, §2 R17 and its 2026-10-15 addendum (the maintainer's stage-0
  ruling, not reopened here — §4), **D176** (§2.11, where the verdict is recorded),
  **D52** (the devnet E2E venue whose suites the harness runs), **D49** (what a dry run
  contacts and writes), **D6** (the licence exceptions a pin bump would shed), **D178** and
  **D179** (wave 37's adapter records, which change the suites' code, not this harness).

## 0. What was measured against

`HEAD` `fbcee1e`. Planning lane P1 read the launcher and its dependency edges, `ant-core`
0.5.0's manifest, the crates.io release lists and GitHub's `WithAutonomi/ant-node`
releases; downloaded the v0.22.0 and v0.15.0 linux-x64 release archives with their
`SHA256SUMS`; verified both ML-DSA-65 signatures with a verifier built out of tree; ran
both binaries' `--version` inside a network namespace with a throwaway home; read the
0.22.0 node's defaults; diffed `ant-protocol` 2.3.0 → 4.0.0, `saorsa-core` 0.26.2 → 0.29.0,
`saorsa-transport` 0.35.1 → 0.38.0 and `evmlib` 0.9.0 → 0.10.0; deployed the payment
contracts with `cast` on an Anvil inside a network namespace; and probed both stage-0
predicates over the committed envelopes. **No node fleet was started and no suite was
run**; nothing was built in the tree. The orchestrator re-read the release list before
ruling. This record's lane re-read, before writing: the toolchain and manifest pins,
`ant-core` 0.5.0's manifest comment, the four suites' test counts and `SKIP:` gates, the
four committed `seal` envelopes, both archives' digests against `SHA256SUMS` and their
sizes against the verified message lengths, the embedded key against the source array and
the signing context in the 0.22.0 source, and both binaries' peer discovery.

## 1. What was measured

### 1.1 The launcher cannot host a foreign node

- `crates/devnet-launcher/src/devnet.rs:14-19`: *"the nodes are tokio tasks of THIS
  process"*; `main.rs:7`: *"no `antnode` binary"*.
- `cargo tree --locked --offline -p devnet-launcher --features devnet -e normal -i
  ant-node@0.15.0 --depth 2` — `S41`'s `Accept` row 1, with the two manifest lines below:

  ```
  ant-node v0.15.0
  ├── ant-core v0.5.0
  │   └── devnet-launcher v0.0.0 (…/crates/devnet-launcher)
  └── devnet-launcher v0.0.0 (…/crates/devnet-launcher)
  ```

- `ant-core-0.5.0/Cargo.toml.orig:68`: `ant-node = { version = "0.15.0", optional = true }`;
  `:61-67`: a skew *"makes `ant_node`'s and `ant_protocol`'s `MultiAddr` mutually
  incompatible in `node/devnet.rs`"*.
- Pins: `Cargo.toml:92` `ant-core = "=0.5.0"`, `:108` `ant-protocol = "=2.3.0"`, `:176`
  `ant-node = "=0.15.0"`; `rust-toolchain.toml:5` `1.92.0`. `ant-node` 0.22.0 and
  `saorsa-transport` 0.38.0 declare rust 1.95.
- The v0.22.0 archive holds `ant-node` (27,144,872 bytes, static-pie),
  `bootstrap_peers.toml` (seven public peers on port 10000) and licence files — no
  prebuilt `ant-devnet`.

### 1.2 Where the network is

- GitHub releases: latest non-prerelease **v0.22.0**, published 2026-10-08T22:14:16Z, tag
  commit `008d2ad394a72677736118764f374da46e0f3ac3`; v0.23.0-rc.1 is a prerelease of
  2026-10-15. **Ten** non-prereleases follow v0.15.0 — 0.16.0, 0.17.0, 0.17.1, 0.17.2,
  0.18.0, 0.18.1, 0.19.0, 0.20.0, 0.21.0, 0.22.0, seven minor versions.
- crates.io: `ant-core` 0.12.0 (nine releases after the pin), `ant-protocol` 4.0.0 (nine,
  two of them major), `evmlib` 0.10.0, `saorsa-core` 0.29.0, `saorsa-transport` 0.38.0.
- The node's upgrade monitor takes final releases only — `-rc.*` is rejected on both
  channels — so the fleet converges on v0.22.0. *"Upgrade within 24 hours"* is an hourly
  check plus a 24 h rollout window: up to about 25 h.

### 1.3 The wire, read — and the red causes it refutes

- `ant-protocol` 2.3.0 → 4.0.0: `chunk.rs` 0 lines removed, 699 added; `CHUNK_PROTOCOL_ID`
  and `PROTOCOL_VERSION` unchanged; new settlement versioning and `ClientUpdateRequired`,
  with *"Unversioned clients … handled by policy in the storer"* (`chunk.rs:87`);
  `pricing.rs` identical; `payment/proof.rs` changed in one test line.
- The node answers the legacy `QuoteRequest` and only counts it (`handler.rs:623-629`,
  `:1081-1095`), identically at v0.23.0-rc.1; the pinned client sends exactly that variant
  (`ant-core-0.5.0/src/data/client/quote.rs:334-341`).
- The node's verifier: multiplier 3 (`verifier.rs:56`), median index `n/2`
  (`:299-301`), at most seven quotes with no duplicates (`:2085-2108`), and a check that
  settlement credited the quote's own rewards address (`:1623-1640`). The pinned client:
  median index `CLOSE_GROUP_SIZE / 2` and 3×
  (`ant-protocol-2.3.0/src/payment/single_node.rs:4-5`), paying `quote.rewards_address`
  (`:101`, `:146`) — so the redirection check passes by construction; antseal's payment
  lines come straight from upstream (`crates/antseal-net/src/ant_backend.rs:698`,
  `:1519`).
- The payment contracts are byte-identical across `evmlib` 0.9.0 and 0.10.0
  (`IPaymentVault.json`, `AutonomiNetworkToken.json`, `PaymentVaultV2.json`), and so are
  the network constants and the quote-hash bytes.
- Transport and DHT: QUIC versions unchanged (v1 and draft-29); `saorsa-transport`'s
  `src/crypto` is 29 files with **0** changed code lines, but its `src/` as a whole is 228
  files, 23 with code changes, **4,200 changed code lines** — unread. `saorsa-core`'s
  identity and `saorsa-dht/1.0.0` ids are unchanged and its legacy `/dht/1.0.0` topic is
  kept *"byte-compatible"* (`dht_network_manager.rs:76-78`) under a regression test
  (`address_v2_tests.rs:1722-1770`); serializable types went 29 → 42 (25 same, 4 changed,
  13 added); PeerId is `blake3(pk)` in both.

### 1.4 What the released binary does by default, and what closes it

- **Peers**: CLI, then config, then auto-discovery — `ANT_BOOTSTRAP_PEERS_PATH` first, then
  **the file next to the executable**, then XDG config, then `/etc/ant`
  (`config.rs:670-730`). When the variable is set, `discover()` returns on what it names
  alone — re-read by this record's lane at 0.22.0, and the same at 0.15.0.
- **Chain**: `--evm-network` defaults to `arbitrum-one` (`cli.rs:77-83`).
- **Self-replacement**: the upgrade monitor is built unconditionally (`node.rs:153-156`),
  polls `api.github.com/repos/WithAutonomi/ant-node/releases` (`monitor.rs:352`) hourly
  with a 24 h rollout window (`config.rs:536-542`), caches under
  `$XDG_DATA_HOME/ant/upgrades` (`cache_dir.rs:21-27`), and `UpgradeConfig` has no
  `enabled` field (`:288-319`).
- A rewards address is required even in development mode (`node.rs:548-552`); development
  mode is `.local(true)` plus permissive diversity (`node.rs:307-341`).
- **The namespace**: `unshare -rn`, then `ip link set lo up` — links `lo` only, an empty
  main route table, `1.1.1.1:443` *"Network is unreachable"*, `127.0.0.1:9` *"Connection
  refused"*. Inside it, with a throwaway home, `ant-node --version` prints
  `ant-node 0.22.0` / `ant-node 0.15.0`, exit 0, and writes no file; the 0.15.0 binary has
  no `--disable-webrtc-direct` flag.
- **Provenance**: the v0.22.0 archive is sha256 `993671ed…5e8b`, equal to `SHA256SUMS` and
  to the API digest. Its ML-DSA-65 `.sig` (3,309 bytes) verifies against the key embedded
  in `ant-node` 0.22.0's `src/upgrade/signature.rs:40` (`RELEASE_SIGNING_KEY`, 1,952 bytes,
  sha256 `163f903d…6643`) under context `ant-node-release-v1` (`:27`): `VERIFY OK
  ctx="ant-node-release-v1" msg_len=11226608` — the archive's size. v0.15.0: sha256
  `1dacf3ce…6e5d`, equal to `SHA256SUMS`; `VERIFY OK msg_len=7452611`. The negative
  controls all fail: a flipped byte, the wrong context, and the crate's own
  `sign/release-signing-key.pub`, which is a **different key** (upstream's inconsistency;
  it does not change node behaviour).
- **Contracts on an isolated Anvil** (1.5.1, in a namespace): token
  `0x5fbdb2315678afecb367f032d93f642f64180aa3` (7,889 bytes of code), vault
  `0xe7f1725e7734ce288f8367e1bb143e90bb3f0512` (3,937 bytes); `balanceOf(acct0)` = 2.5e24;
  `antToken()` = the token; `batchLimit()` = 512. The token artifact's `bytecode` is a
  **string**: the first attempt, through `.bytecode.object`, silently deployed an empty
  contract (`token code bytes: 0`).

### 1.5 The suites

- `scripts/e2e-devnet.sh --list-suites` names four suites — S6-S8 (`antseal-net`,
  `devnet_backend`), S17 (`e2e_devnet`), S18 (`e2e_kill_resume`) and S19 (`e2e_restore`) —
  holding **8/3/11/7** `#[test]` functions at `fbcee1e`.
- Each suite's export gate prints `SKIP:` and returns success when the export is unset,
  unreadable, unparseable, missing a key, or names a launcher pid that is not alive
  (`crates/antseal-net/tests/devnet_backend.rs:74-145`;
  `crates/antseal-cli/tests/common/devnet.rs:86-151`). A harness whose export is wrong
  therefore goes **green with nothing tested**; its export needs all ten
  `network::devnet_keys` and a pid that stays alive for the run.
- `scripts/e2e-devnet.sh` mentions `SKIP` zero times. Hosted evidence, run 38550457695 at
  `3473ab2` (2026-10-14): `e2e-devnet: PASS commit=3473ab2 nodes=14 suites_run=4 failed=[]
  pending=[] secs=1205 anvil=1.8.5`, every suite `SKIP=0`, 8/3/11/6 passed; boot 5.2 s;
  suites 109.6/42.4/205.1/130.2 s.

### 1.6 Stage 0

- The seal path's order: select network → resolve peers → passphrase → wallet →
  `SealBackend::connect` (`crates/antseal-cli/src/commands.rs:381-435`); any connect
  error is 23 (`backend.rs:1728-1736`); a dead RPC is *"payment RPC unreachable
  (eth_chainId)"* (`crates/antseal-net/src/ant_backend.rs:1297-1302`); quote, payment,
  finalize and network errors are all 23 (`pipeline/error.rs:352-366`); the dry run
  truncates after the quote (`pipeline/seal.rs:372-386`).
- **A dry run over a resumable work returns before any backend call**
  (`seal_run.rs:394-396`) and emits
  `{"command":"seal","network":"arbitrum-one","ok":true,"result":{"dry_run":true,"quoted":false,"resume":true,"resume_plan":[…]},"v":1}`
  (`crates/antseal-cli/tests/snapshots/json-envelopes.txt:33-34`).
- The plain dry run (`:31-32`) carries `blob_count` 5, `storage_cost_atto` as the
  **decimal string** `"4200000000000000000"`, `resume` false, and **no** `quoted` key —
  re-read by this record's lane.
- Both predicates over the committed `seal` envelopes:

  | document | naive (exit 0 ∧ `dry_run`) | strict (§2 R10) |
  |---|---|---|
  | `[seal] error` | STOP | STOP |
  | `[seal] result` | STOP | STOP |
  | `[seal] result (--dry-run)` | PASS | PASS |
  | `[seal] result (--dry-run over a resumable work)` | **PASS** | STOP |

- So threat-model §2.9's sentence that stage 0 *"shows that the shipped peers route and
  that the quote protocol answers the pinned client"* holds only under the strict
  predicate.

### 1.7 What a red would cost

- Licences: pinned `saorsa-core` 0.26.2 is AGPL-3.0, `evmlib` 0.9.0 and `self_encryption`
  0.36.0 are GPL-3.0 (`deny.toml:107-152`); `saorsa-core` 0.29.0, `evmlib` 0.10.0 and
  `self_encryption` ≥0.36.1 are all MIT OR Apache-2.0.
- `ant-core` 0.12.0 requires `saorsa-transport` 0.38.0, which requires rust 1.95.0.
- Run cost, estimated and not measured: the hosted suites took 487 s, likely 1.5–2.5× on
  this host; about 15–25 min per arm, 30–50 min for both, plus 2–6 min of stage-0 arms;
  0.6–1.7 GB of RAM for the nodes; never concurrent with the gate.

## 2. RULING

### §2 R1 — The harness question is answered: no

`devnet-launcher` cannot host a foreign-version node: it runs `ant-node` in-process
through `ant-core` 0.5.0's `devnet` feature, pinned to `ant-node` 0.15.0 by upstream's own
manifest for a `MultiAddr` skew, and `ant-node` 0.22.0 needs rustc 1.95 against the pinned
1.92.0. `S41`'s `Accept` row 1 records §1.1's `cargo tree` output and the two manifest
lines behind its two edges — `ant-core-0.5.0/Cargo.toml.orig:68` and the workspace's
`Cargo.toml:176`.

### §2 R2 — The harness is upstream's released binary, in one loopback-only namespace that also hides the operator's secrets

The subject is the latest non-prerelease `ant-node` release — **v0.22.0** (2026-10-08,
`008d2ad`) today — and the control is **v0.15.0**, both as upstream ships them. *[Amended in
place by the orchestrator, wave 37: the rule is "the latest non-prerelease at run time", and at the
run that was **v0.23.0**, published 2026-10-16T02:27:41Z (tag commit `2d157cb`). Its archive sha256
`5962825a…39b3` equals `SHA256SUMS` and the API digest; its `signature.rs` is byte-identical to
v0.22.0's, with the same key and context; and its signature verifies, with both negative controls
failing. N became **11**, and `ant-core` 0.13.0 made the lag **10**. The release notes say running
nodes upgrade within a 24-hour staged rollout. v0.22.0 was boot-measured in phase A only.]*
Each is taken as upstream ships it: the
linux-x64 archive whose sha256 equals `SHA256SUMS` and the API digest, its ML-DSA-65
signature verified under context `ant-node-release-v1` against the key embedded in
`ant-node`'s source at the tag (§2 R12). Fourteen node processes and Anvil run inside
**one** unprivileged user and network namespace whose only interface is `lo`: the
namespace is the loopback guarantee, and flags are only a second layer.

**Amended by the orchestrator**: the same act adds a **mount namespace** that hides the
operator's home secrets from the node processes — at least `~/.minisign`, `~/.ssh`,
`~/.gnupg`, `~/.config/gh`, `~/.local/share/ant` and `~/.cargo/credentials*` — by binding
an empty directory over each of those directories (and, since a bind mount needs a file
over a file, an empty file over each `~/.cargo/credentials*` file), proven by a canary file
that is unreadable inside. If that is unbuildable on the host, the residual is recorded in
the runbook and beside the verdict line in `S41`'s Notes.

This builds nothing upstream and tests the bytes the fleet installs.

### §2 R3 — Contracts from the pinned artifacts, and a hand-written export

The payment contracts are deployed with `cast` from the pinned `evmlib` 0.9.0 artifacts
(byte-identical to 0.10.0's), taking ~~`.bytecode` as the string it is~~ *[amended in place,
wave 37, on lane L-S41's measurement]* each artifact's bytecode in its own format — the token's
`.bytecode` string (Hardhat; `AutonomiNetworkToken.json`), the vault's `.bytecode.object`
(Foundry; `PaymentVaultV2.json`) — with a hex check and on-chain sizes, and asserted by code
size, the funded balance, `antToken()` and `batchLimit()`. antseal's client reads a
hand-written ten-key export through `ANTSEAL_DEVNET_ENV`. **No product or launcher code
changes.**

### §2 R4 — The control arm runs first

The v0.15.0 release binary runs first, under the identical harness. An `S41` verdict is
recorded only if the control is green; a red control is recorded as *"harness defect, no
S41 verdict"*.

### §2 R5 — Harness rules

- A **distinct** rewards address per node — with one shared address the redirection check
  cannot fail (§1.3).
- Only the `ant-node` member is extracted, never the `bootstrap_peers.toml` beside it.
- `ANT_BOOTSTRAP_PEERS_PATH` names a nonexistent file, so discovery returns empty without
  searching further (§1.4).
- `HOME` and every `XDG_*` variable point into the run directory.
- `--network-mode development --ipv4-only --metrics-port 0` plus the custom-EVM flags.
- `ANT_DISABLE_WEBRTC_DIRECT=true` (0.15.0 ignores it). *[Amended in place, wave 37: the draft said `=1`. The variable is clap's environment source for the boolean `--disable-webrtc-direct`, which accepts only `true`/`false`. With `=1`, all fourteen v0.22.0 nodes exited at once with "invalid value '1' for '--disable-webrtc-direct' [possible values: true, false]" (lane L-S41, the first v0.22.0 boot).]*

### §2 R6 — The suites, and no SKIP

The suites are read from `scripts/e2e-devnet.sh --list-suites`, pre-built outside the
namespace and run inside it with `CARGO_NET_OFFLINE=true`. **Any `SKIP:` line is a FAIL**,
and each suite's pass count must equal its `cargo test -- --list` count at the run's
commit — read at run time, never taken from this record (8/3/11/7 at `fbcee1e`; this
wave's lanes may add tests).

### §2 R7 — The verdict line

Recorded verbatim on `S41`, on `Q34` and in threat-model §2.11:

```
s41-interop: <PASS|FAIL> commit=<sha7> client=ant-core-0.5.0 node=ant-node-<tag> node_commit=<…> archive_sha256=<…> sig=<ok|unchecked> nodes=<live> suites_run=4 tests=<n> skipped=0 failed=[…] control=<PASS|FAIL>(ant-node-v0.15.0) netns=isolated anvil=<ver> secs=<n> date=<UTC>
```

**N**, the number of non-prerelease `ant-node` releases after the dev pin, is recorded
beside it — **10** today — with the `ant-core` lag (**9**).

### §2 R8 — The register drops the refuted causes

`S41`'s text stops naming, as open reasons a run could go red, the node's
rewards-address settlement check, a contract or ABI change, the legacy quote request's
retirement or the median rule — each refuted by reading (§1.3). The prediction is **NOT
ESTABLISHED** — reading leans green — and the residual risk is named: **the transport**,
4,200 unread changed code lines in `saorsa-transport`.

### §2 R9 — What a red costs is recorded with the red

A red records a deliberate pin bump (rule 5: survey, pinning, devnet E2E) as a `Q34`
prerequisite, costed with its coupled **toolchain bump 1.92.0 → ≥1.95.0**
(`saorsa-transport` 0.38.0) and the **licence shift** it brings: the AGPL-3.0 and GPL-3.0
crates are replaced by MIT OR Apache-2.0 releases (§1.7).

### §2 R10 — Stage 0: one strict predicate, scripted under `Q32`, rehearsed on loopback

One predicate, in a new `scripts/stage0.sh` owned by `Q32` and **never** in
`scripts/e2e-sepolia.sh` (D173 §2 R16):

**STRICT** = exit 0 ∧ top-level `ok` ∧ top-level `network` = the expected network ∧
`dry_run` ∧ `resume` = false ∧ `quoted` ≠ false ∧ `blob_count` ≥ 1 ∧
`storage_cost_atto` > 0 — the last five read inside `result`. `quoted` is absent from the
plain dry run, so ≠ false passes by absence; `storage_cost_atto` is a decimal string,
compared as an integer.

- **`--self-test`** runs the predicate over the committed envelopes plus mutations; the
  naive predicate passing the resume-plan document is the plant (§3).
- **`--rehearse`** runs time-boxed arms on loopback, where a timeout means STOP: **dead RPC
  → 23, STOP**; **live RPC with dead nodes → 23, STOP**; **live → 0, PASS** — the live arm
  inside `S41`'s namespace, against the v0.22.0 fleet and against the control.
- **The real (mainnet) mode is written and never run** here; running it is `Q34`'s.
- Threat-model §2.9's stage-0 paragraph gains the resume-plan exclusion.

### §2 R11 — No new checker

No new repo-wide checker. **A SKIP counter for `scripts/e2e-devnet.sh` is refused**: its
measured yield is zero SKIPs in the one hosted evidence set (§1.5). The `S41` harness
counts SKIPs itself (§2 R6).

### §2 R12 — No nested Cargo project; the verifier is rebuilt from the runbook

**Amended by the orchestrator.** Planning lane P1 proposed `scripts/s41/sigcheck/` with
its own `[workspace]` and a second `Cargo.lock`, whose effect on the checkers it could not
establish. Instead nothing cargo would read as a project enters the tree: the ML-DSA-65
verifier is built out of tree, and its source — about thirty lines (38 as P1 built it,
on `fips204 =0.4.6`, already in `Cargo.lock`) — is printed in the runbook so anyone can
rebuild it. The committed script prints `sig=ok` only when it is given a verifier path and
that verifier verifies; given no verifier it prints `sig=unchecked`. The embedded key is a
trust root independent of GitHub, which is why a digest match (§2 R2) is never `sig=ok` on
its own. A verifier that **rejects** the signature is not `unchecked`: the run stops before
any node starts (§3).

### §2 R13 — A standing manual check, with its runbook

The harness is not wired into `scripts/local-gate.sh` this wave; it is a standing manual
check, as `scripts/e2e-sepolia.sh` is. Its runbook is `docs/devnet/foreign-node-interop.md`:
the §1.4 hazards, the namespaces and the canary, the control arm, N, and the verifier's
source.

## 3. Fault plants

Owed by the implementing lane, baseline green first, judged by message, `touch` after
every restore. A plant that an earlier check would also catch is planted where only its own
check can see it.

| assertion | plant | expected red | green |
|---|---|---|---|
| network isolation (R2) | the inner script run without `unshare -n` | `not inside an isolated network namespace: links=[lo,…]`; no node starts | `links: lo`, `routes(main): []` (measured) |
| secrets hidden (R2, amended) | the mount namespace omitted | a red naming the readable canary, no node started (wording the lane's) | the canary unreadable inside |
| signature (R12) | one byte flipped in a copy, the verifier run on it **directly** — in the script the digest check reds first on the same byte | `VERIFY FAIL ctx="ant-node-release-v1" msg_len=11226608` (measured) | `VERIFY OK … msg_len=11226608` (measured) |
| `sig=` honesty (R12) | `sig=ok` printed on a digest match alone | the no-verifier arm reds: `sig=ok` printed with no verifier, expected `sig=unchecked` (wording the lane's) | `sig=unchecked` with no verifier; `sig=ok` only with one that verifies |
| token deployed (R3) | extract with `.bytecode.object` | `token code bytes: 0`; `Error: contract 0x5fbd… does not have any code` (measured) | 7,889 bytes; balance 2.5e24 (measured) |
| no SKIP (R6) | `ANTSEAL_DEVNET_ENV=/nonexistent` | suites print `SKIP: … is not readable`; the runner prints `suite S6-S8: 8 SKIP lines — FAIL` | `skipped=0`; counts from `--list` |
| distinct rewards (R5) | one address for all nodes | `rewards addresses not distinct: 1 of 14` | `14 of 14` |
| control arm (R4) | a wrong vault address in the export | `control arm (ant-node v0.15.0) FAILED — harness defect, no S41 verdict` (exit 2) | `control=PASS` |
| node identity | the v0.15.0 binary run as the subject | `node version 0.15.0 != expected 0.22.0` | `version=0.22.0` |
| node liveness | `kill -9` one node mid-run | `node 7 (pid …) exited during the run` | `alive 14/14` |
| stage-0 strictness (R10) | the predicate cut to `ok ∧ dry_run` | `[seal] result (--dry-run over a resumable work): PASS, expected STOP` (naive = PASS, measured) | strict = STOP; the plain dry run PASSes |
| stage-0 dead RPC (R10) | the arm's exit test inverted | `arm dead-rpc: verdict=PASS expected=STOP` | 23, `network-failure`, *"payment RPC unreachable (eth_chainId)"* |

**Pre-registered red signatures for the `S41` run** — reading predicts that none appears:
*"was redirected: recorded rewards address prefix"*, *"was not paid enough"*, *"is not
among this node's local K=… closest peers"*, and `ClientUpdateRequired`.

## 4. What this record does NOT decide

- **The verdict.** `S41`'s run decides it; until then the prediction is NOT ESTABLISHED.
- **The pin bump a red would require** — recorded as `Q34`'s prerequisite and costed
  (§2 R9); the bump is its own deliberate event under rule 5.
- **The maintainer's 2026-10-15 stage-0 ruling is not reopened.** Its conditions — the same
  released binary, the same machine, the same smoke file, immediately before the seal in
  one sitting, its output kept as gate evidence — stand; the predicate is D173 §2 R16's,
  and §2 R10 only narrows what passes.
- What mainnet actually runs — inferred from the monitor's rule, never dialed.
- A prerelease as a subject — the monitor never installs one (§1.2).
- Boot time and the readiness line of fourteen loopback processes on two CPUs; whether a
  partial `[upgrade]` table is accepted; the dead-nodes arm's message and duration (capped
  near 300 s) — **not established**.
- Operators' `ANT_PRICE_FLOOR_ENFORCE`, and divergence between client and node views of
  issuer closeness — neither is testable on fourteen loopback nodes.
- Wiring the harness into `scripts/local-gate.sh` — not this wave (§2 R13).

## 5. Edit list — per write scope, with the lane named before this record was written

### L-S41 (the interop lane) — phase A now; phase B on the orchestrator's message after L-NET and L-CLI land
- **New** `scripts/s41-interop.sh`: `--plan`, `--self-test` and the run (§2 R2–R7, R12),
  including the namespaces, the canary, the control arm and the verdict line.
- **New** `scripts/stage0.sh`: the predicate, `--self-test`, `--rehearse`, and the real
  mode, written and never run (§2 R10).
- **New** `docs/devnet/foreign-node-interop.md`: the runbook, with the verifier's source
  (§2 R12, R13).
- Phase B: the control arm, the subject arm and the stage-0 rehearsal arms, each verdict
  captured verbatim.
- Untouched: `Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml`, `crates/devnet-launcher`,
  every workflow, `scripts/ci-lanes.sh`, `scripts/local-gate.sh`, `scripts/e2e-devnet.sh`,
  `scripts/e2e-sepolia.sh`.

### DOCS (the documentation lane)
- `docs/dependency-policy.md` §4: the `S41` bullet — the runner, the control arm, the
  namespaces, N and the toolchain coupling (§2 R2, R4, R7, R9).
- `docs/threat-model.md` §2.9: the resume-plan exclusion in the stage-0 paragraph
  (§2 R10); §2.11: the verdict line, once the run exists (§2 R7).

### Orchestrator (registrar) — `TODO.md`, `tasks/S.md`, `tasks/Q.md`, `docs/decisions/README.md`, dated addenda
- `S41`: `Accept` row 1's capture (§2 R1); the refuted causes dropped (§2 R8); Notes from
  planning lane P1; the verdict line after the run (§2 R7).
- `Q32` Notes (§2 R10); `Q34` Notes (§2 R7, R9).
- A dated addendum on **D173**: §2 R16's predicate is replaced by §2 R10's strict one, and
  its rehearsal is `scripts/stage0.sh`.
- Index row and register row for this record.

## 6. As built — wave 37, lane L-S41 phase A (recorded in place before this record was first committed)

`scripts/s41-interop.sh` (1 623 lines), `scripts/stage0.sh` (548 lines) and the runbook
`docs/devnet/foreign-node-interop.md` (481 lines, carrying the ML-DSA verifier's source) were built
and self-tested. No suite ran in phase A. §2 R3 and §2 R5 are amended above. Where the build says
more than the ruling did:

- **§2 R2: more isolation than ruled, each layer measured.**
  - The controller runs in user, network, mount, PID, IPC and UTS namespaces. The nodes run in a
    nested mount and PID namespace of their own, where they see neither the repository, nor
    `~/.cargo`, nor the controller's results (Anvil's keys, the export).
  - The whole home is an empty tmpfs with named bind-backs, and `/tmp`, `/var/tmp`, `/dev/shm` and
    `/run/user/<uid>` are masked.
  - Every workload runs with an empty capability bounding set, `no_new_privs` and `env -i`.

  Measured reasons:
  - without a PID namespace, 262 host processes were visible, the operator's argv was readable, and
    signalling the operator's shell was permitted;
  - a path-named Unix socket outside the namespace was connectable from inside it until `/tmp` was
    masked;
  - a node that could write the repository or `~/.cargo/bin` could plant code the operator runs later.

  `--probe-namespace` proved: `links=[lo]`, empty route tables, egress `ENETUNREACH`, the canary
  unreadable in both views, the six ruled paths absent, `~/.cargo/credentials.toml` overlaid with
  `/dev/null`, and no workload able to unmount a mask.
- **§2 R10: eleven conjuncts, not eight.** Added:
  - stdout is exactly one JSON document (D51);
  - `v` = 1, the schema the predicate was written against;
  - `command` = `seal`.

  Each can only turn a PASS into a STOP on an envelope the predicate was not written for, and each
  is proven load-bearing. `storage_cost_atto` must be a decimal string: a JSON number STOPs, so a
  schema drift fails closed.
- **The mainnet mode (`--gate`) cannot be reached by an agent.** It refuses before invoking the
  binary unless stdin and stdout are a terminal and the operator types `stage 0 on arbitrum-one`.
  It also refuses with `ANTSEAL_DEVNET_ENV` set. It is written and has never run.
- **Readiness and stability are defined by upstream's own lines.** A node is ready once it logs
  `Node running, waiting for shutdown signal`. The fleet is stable once every node logs at least
  three distinct `Added peer <id> to DHT routing table` (upstream devnet's minimum-connections rule).
  No suite sees the export before both.
- **A signature verifier must be able to say no.** `sig=ok` needs the exact `VERIFY OK
  ctx="ant-node-release-v1" msg_len=<size>` **and** a `VERIFY FAIL` on a one-byte-flipped copy
  **and** on the wrong context. The verifier is 32 lines, not 38.
- **§2 R4: a red control stops the run.** The subject arm is not started, the exit is 2, and the line
  reads `s41-interop: HARNESS-DEFECT … control=FAIL(ant-node-v0.15.0) — no S41 verdict`.
- **§2 R7: a notes line beside the verdict line.** It carries N, the `ant-core` lag, the control's
  test count, the masks, both arms' stage-0 results and the evidence directory. The verdict line
  itself is as ruled, and `node=` carries the tag (`ant-node-v0.22.0`), as `control=` does.
- **Deployment goes through Anvil's unlocked account** (`cast send --unlocked --from`), so no key
  appears on any argv. `--stop-on-upgrade` is added to the node flags; both versions accept it.
- **Boots, measured (≤ 5 min each):**
  - v0.15.0: 14/14 ready in 4 s and stable 1 s later, node commit `c8b01de` (the tag's);
  - v0.22.0: 14/14 ready in 6 s and stable 1 s later, node commit `008d2ad` (the tag's), about
    510 MiB per node at idle.

  The liveness plant on a real fleet: `kill -9` of node 7 → `node 7 (pid 570) exited during the run`.
- **Self-tests.**
  - `s41-interop: SELF-TEST ok arms=55 not_run=0` with the verifier and the v0.22.0 archive.
  - `stage0: SELF-TEST ok arms=57`. Its plant behaves as ruled: the resume-plan envelope passes the
    literal reading and the strict predicate stops it, and deleting any one of the 11 conjuncts makes
    a named fixture pass.
  - Faults planted in temporary copies turned the self-tests BROKEN, each naming the right arm: 8 of
    8 for the harness and 5 of 5 for stage 0.
- **Not run in phase A:** the §3 row *"a wrong vault address in the export"*, which needs a full
  control-arm run.
- **Bugs found and fixed before any run:**
  - the stage-0 rehearsal reopened a deleted key file for every arm, so no arm would have started;
  - the pre-build assumed the caller's working directory;
  - a refusal inside the namespace was misreported as a harness defect.

## 7. Phase B — the run (wave 37, lane L-S41 on the orchestrator's go)

The ruled subject moved before the run: v0.23.0 shipped at 2026-10-16T02:27:41Z, the lane's stop
clause fired, and the orchestrator applied §2 R2's rule (amended there). The lane pinned v0.23.0's
digest beside v0.22.0's, re-ran the self-test, and booted v0.23.0 once with `--boot-only`, which
needed no harness change. Then the full run. Verbatim:

```
s41-interop: PASS commit=fbcee1e client=ant-core-0.5.0 node=ant-node-v0.23.0 node_commit=2d157cb archive_sha256=5962825adb28604af4cf1a710bcb533dccc616ddf636bff7f182f326eefd39b3 sig=ok nodes=14 suites_run=4 tests=29 skipped=0 failed=[] control=PASS(ant-node-v0.15.0) netns=isolated anvil=1.5.1 secs=1963 date=2026-10-16T04:11:30Z
```

N = 11 and the `ant-core` lag is 10. Each arm passed four suites and 29 tests (S6–S8 8, S17 3, S18
11, S19 7), each count equal to `--list`, with no SKIP line and nothing recompiled inside the
namespace. The stage-0 rehearsal passed `arms=3` against both fleets:

- dead RPC → exit 23 STOP in 1–2 s;
- dead nodes → exit 23 STOP in 8 s, *"insufficient peers: Witnessed close group lookup failed before
  payment …"*, so that arm is now measured;
- live → PASS, `blob_count=2`, `storage_cost_atto=23437500000000000`.

Wall time was 32 m 43 s. No process was left behind.

**One prediction failed.** Planning predicted that none of the four pre-registered red phrases
would appear. None appears in any suite log, but two appear in the node logs of **both** arms, as
`WARN ant_node::replication` rejections of forwarded proofs of payment between nodes: 334 lines over
55 records at the v0.15.0 control, 77 over 15 at v0.23.0. They are not a regression of the subject.
Why they occur, and what they cost in replication depth, is not established.

**Not established:** a mixed-version fleet, as mainnet is during a release's 24-hour rollout;
transport across real NATs; and v0.22.0 under the suites, which was boot-measured in phase A only.

## Closing — this record is not consent

It authorises no network act beyond loopback. The harness runs inside a namespace whose
only interface is `lo`, and fetching a public release archive is a read. Stage 0's real
mode is written and never run here: pointing it at mainnet is `Q34`'s, inside §2.9's
accepted exposure, on the maintainer's express consent at the gate. Nothing here authorises
a push, a dispatch or a settings write.
