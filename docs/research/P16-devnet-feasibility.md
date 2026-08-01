# P16 — Local devnet feasibility on this machine (static analysis)

- **Date: 2026-08-01** (M1 Storage planning wave)
- **Kind: research memo** — not a decision record. Feeds P16 execution, the
  S2 lockfile event (P7), D52 (devnet E2E venue), and S17's harness design.
- **Method: static inspection only.** Nothing was built or started; a
  background test suite owned the CPUs. Sources are the pinned upstream
  crate archives fetched from static.crates.io into the session scratchpad
  and byte-verified against P9's recorded checksums, plus a dependency
  **resolution** probe (`cargo metadata`, no compilation).

## 0. Provenance of every citation

| Archive | sha256 | Matches |
| --- | --- | --- |
| `ant-core-0.5.0.crate` | `c3f3c2f61e3c16437b12133d697d22619835f8bd41fa249979459023c4c85a39` | P9 record §1 (`docs/upstream/P9-ant-core-reverification.md:32`) |
| `evmlib-0.9.0.crate` | `8da0d9ad5b5cab92cc92ddac9afb884f86b226340caf17f6e5c41d51175dcaa1` | P9 record §3 (line 87–89: byte-identical to the checksum in ant-core 0.5.0's packaged lock) |
| `ant-node-0.15.0.crate` | fetched 2026-08-01; the version ant-core 0.5.0's `devnet` feature resolves (see §5) | — |

`ant-protocol-2.3.0` citations are from the already-extracted registry copy
(`~/.cargo/registry/src/index.crates.io-*/ant-protocol-2.3.0/`). File:line
references below are into these archives.

## 1. What `start-local-devnet` actually does

The example (`ant-core-0.5.0/examples/start-local-devnet.rs`) is ~70 lines:
build a multi-thread tokio runtime with 8 MiB thread stacks (lines 34–37),
`LocalDevnet::start(DevnetConfig::default())` (line 46), write a manifest
JSON, wait for Ctrl+C, delete the manifest. It is gated
`required-features = ["devnet"]` (`Cargo.toml.orig:106-112`), and
`LocalDevnet` is only compiled under that feature
(`src/data/mod.rs:16-19`).

`LocalDevnet::start` (`ant-core-0.5.0/src/node/devnet.rs:42-98`) sequences:

1. **`Testnet::new()`** — `ant_protocol::evm::testnet` = `evmlib::testnet`
   (`evmlib-0.9.0/src/testnet.rs:48-62`). Spawns **Anvil as an external
   subprocess via alloy's `node_bindings`** (`testnet.rs:19`, `:94-118`) —
   it does *not* embed an EVM. Then **deploys both payment contracts onto
   the fresh Anvil chain per run**: `NetworkToken::deploy` signed by Anvil
   dev account 0 ("Alice", `testnet.rs:146-157`) and the unified
   PaymentVault implementation signed by account 1 ("Bob",
   `testnet.rs:187-199`). The contract bytecode ships inside evmlib
   (`evmlib-0.9.0/artifacts/AutonomiNetworkToken.json`,
   `PaymentVaultV2.json`; `sol!` binding at
   `src/contract/network_token.rs:18-24`).
2. Wraps the result as `EvmNetwork::Custom { rpc_url, payment_token_address,
   payment_vault_address }` (`testnet.rs:64-70`) and injects it into the
   node config (`node/devnet.rs:52-54`).
3. **`ant_node::devnet::Devnet::new(config)` + `.start()`** — the nodes.
4. Assembles a `DevnetManifest` (§4) and returns; **dropping `Testnet`
   kills Anvil** (`node/devnet.rs:25-26`), so the launcher process must
   stay alive for the devnet's lifetime.

### Nodes are in-process tasks, not subprocesses

`ant-node-0.15.0/src/devnet.rs` ("a local, **in-process** devnet", lines
1–4): each node is a `DevnetNode` holding an `Arc<P2PNode>` (saorsa-core
QUIC/DHT) plus an `AntProtocol` instance with its own **LMDB store via
`heed`** and its own generated ML-DSA-65 identity
(`devnet.rs:502-544`, `:547-593`, `:595-687`). There is **no `antnode`
binary involved anywhere** — the absence of an installed `antnode` on this
machine is irrelevant, and Q15's "cached node binaries" premise is obsolete
(the cacheable artifact is the cargo target directory).

Nodes start sequentially with a 200 ms spawn delay (`devnet.rs:46`),
bootstrap nodes first, then regular nodes pointed at the bootstrap
addresses; readiness then a stabilization wait until every node has
`min(bootstrap_count, 3)` connections, bounded by the stabilization
timeout (`devnet.rs:67`, `:716-756`).

### Client-side hookup

`LocalDevnet::create_funded_client` (`ant-core-0.5.0/src/node/devnet.rs:166-177`):
`Client::connect(bootstrap_addrs)` → `with_wallet(Wallet::new_from_private_key(custom_network, anvil_account_0_key))`
→ `approve_token_spend()`. The funded wallet is **Anvil dev account 0**,
which is also the token deployer — the AutonomiNetworkToken constructor
takes no arguments and premines the entire supply to its deployer (ABI:
constructor `inputs: []`, no `mint` function — see D38 §2 for the full
function list), so account 0 holds all devnet ANT. This answers P16's
"how does the example provision devnet ANT" and "which Anvil key the test
flows use" in one line: *contracts are deployed fresh per run; supply is
premined to Anvil account 0; that key is what `wallet_private_key()`
returns and what the manifest embeds.*

## 2. Requirements (`LocalDevnet` / `Testnet`)

| Requirement | Detail | This machine |
| --- | --- | --- |
| `anvil` binary on `PATH` | alloy `Anvil::new().try_spawn()` with no explicit path (`evmlib testnet.rs:97-110`); deploy failure hints "update anvil by running `foundryup`" (`network_token.rs:60`) | **present**: `anvil 1.5.1-stable` (commit `b0a9dd9c`, built 2025-12-22) at `~/.foundry/bin/anvil` — scripts must ensure `~/.foundry/bin` is on `PATH` |
| Anvil port | random OS-assigned by default; `ANVIL_PORT` / `ANVIL_IP_ADDR` env override (`testnet.rs:94-106`) | fine |
| Node ports | `base_port` random in 20 000–60 000 minus node_count, sequential per node; `base_port` configurable, 0 = auto (`ant-node devnet.rs:36-39`, `:174-196`, `:325-343`) | fine |
| Disk paths | default data root = `ProjectDirs("", "", "ant")` data dir → `~/.local/share/ant` on Linux (`ant-node config.rs:367-373`); per node `nodes/<peer_id_hex>/` (`:376-380`); `cleanup_data_dir: true` by default removes it on clean shutdown (`devnet.rs:161-162`, `:421-425`) | fine — but see §6: point `data_dir` at a repo-local gitignored dir instead |
| Manifest path | example writes `devnet-manifest.json` into the **shared** `ant_core::config::data_dir()` = `~/.local/share/ant/` (`ant-core config.rs:8-11`; README.md:508) so ant-gui/ant-cli auto-detect it | we do not want the shared path (§6) |
| Docker | not used anywhere in this path | present but unneeded |
| `antnode` binary | not used (in-process nodes) | absent, and correctly so |

## 3. Node count: configurable, not a constant — and the real minimum

**25 is only the default.** `DevnetConfig.node_count` is a plain public
field (`ant-node devnet.rs:136-138`); constants and presets:
`DEFAULT_NODE_COUNT = 25` / `DEFAULT_BOOTSTRAP_COUNT = 3` (`:90`, `:93`),
`DevnetConfig::minimal()` = 5 nodes / 2 bootstrap with a 30 s
stabilization timeout (`:96-99`, `:198-208`), `::small()` = 10 nodes
(`:102`, `:210-219`). ant-core exposes `LocalDevnet::start_minimal()` /
`start_small()` (`ant-core src/node/devnet.rs:100-116`). The *example*
hardcodes `DevnetConfig::default()` — node count control requires calling
the API ourselves (§6) or ant-node's `ant-devnet` CLI binary
(`ant-node Cargo.toml:21-23`, `--preset` flags), which would mean
compiling the same graph anyway.

**Replication constants (the "minimum viable" inputs), cited:**

- `CLOSE_GROUP_SIZE = 7` — `ant-protocol-2.3.0/src/chunk.rs:35` (the
  replication factor: quotes/storage target the 7 closest nodes).
- Node-side storage/replication quorum `QUORUM_THRESHOLD = 4`
  (= ⌊7/2⌋+1, `ant-node replication/config.rs:38`); nodes take
  `close_group_size` from `ReplicationConfig::default()`
  (`replication/config.rs:499`, consumed at `devnet.rs:569-573`).
- Client-side witnessed-quote quorum = ⌈7·2/3⌉ = **5 of 7**
  (`ant-core src/data/client/quote.rs:36-40`), degrading by missing
  responder views with a floor of 1 (`quote.rs:437-445`);
  `SINGLE_NODE_MIN_QUOTE_COUNT = 1` (`quote.rs:46`).
- Payment mode: `PaymentMode::Auto` switches from single-node to **merkle**
  payments at `DEFAULT_MERKLE_THRESHOLD = 64` chunks
  (`ant-core src/data/client/merkle.rs:38`, `:312`). Merkle mode wants far
  more peers: upstream's own comment says **"35+ for merkle tests (need 16
  peers per pool)"** (`ant-core tests/support/mod.rs:112`).

**What upstream itself uses for real paid uploads** (the strongest
minimum-viable evidence): its e2e suite defaults to
`DEFAULT_NODE_COUNT = CLOSE_GROUP_SIZE * 2` = **14 nodes**
(`tests/support/mod.rs:65`) for chunk/data/file/huge-file tests, **10**
for the cost-estimate tests (`tests/e2e_cost_estimate.rs:105` etc.), and
**35** for merkle-payment tests (`tests/e2e_adr0004.rs:198`).

**Conclusion:** for antseal's M1 E2E (S17–S19: multi-file `--split` seals
of small test files, kill/resume, restore), chunk counts stay far below 64
per batch, so the single-node payment path applies and **10–14 nodes is
the evidence-backed working size** (≥7 fills the close group; 14 is
upstream's own e2e parity point). 5 nodes (upstream's `minimal()`) is
below `CLOSE_GROUP_SIZE` and relies on the degraded-quorum floors —
usable for smoke, not for the flagship suite. Any future test that
deliberately exercises the merkle payment path needs ~35 nodes or a forced
`PaymentMode::Single`.

## 4. Environment surface exported (for S/U consumption)

`DevnetManifest` (types in ant-protocol, re-exported
`ant-node devnet.rs:222-225`; populated at
`ant-core src/node/devnet.rs:69-83`) — already machine-readable JSON:

```
base_port, node_count, bootstrap: [multiaddr…], data_dir, created_at,
evm: { rpc_url, wallet_private_key, payment_token_address, payment_vault_address }
```

This is everything U's `--network devnet` wiring and S's E2E need. Note
the manifest **embeds the funded private key** — an Anvil well-known dev
key, not a real secret, but it must never be committed: write it to a
gitignored repo-local dir (§6). (It does not match Q2's secret-guard
signatures — those target PEM/keystore/vault shapes, not bare hex — which
is acceptable given the gitignore, but noted as a candidate pattern
extension.)

## 5. The `devnet` feature: dependency and lockfile impact

Feature wiring (`ant-core-0.5.0/Cargo.toml.orig:81-90`):
`devnet = ["dep:ant-node"]` — that is the *entire* feature; `ant-node`
is optional (`:57-68`) with an explicit upstream warning that it must
track the same `saorsa-core`/`ant-protocol` lineage as the `ant-protocol`
pin or `MultiAddr` types bifurcate. (The Sepolia example needs no feature
because examples resolve against dev-dependencies, and `ant-node` is also
a dev-dep with `test-utils` at `:92-99`.)

`ant-node` version: the optional dep is `"0.15.0"` (caret). crates.io on
2026-08-01: 0.15.0 (2026-07-23, same release train as ant-core 0.5.0) and
0.16.0 (2026-07-29, outside the caret range); **no other 0.15.x exists,
so today the resolve is deterministic at 0.15.0** — but the day upstream
ships 0.15.1 it stops being so. Recommendation: when the lock lands, pin
`ant-node = "=0.15.0"` in `[workspace.dependencies]` under P7's exact-pin
class (it is network-consensus-affecting by the project's own definition).
ant-node 0.15.0's heavy deps (`ant-node-0.15.0/Cargo.toml`):
`saorsa-core 0.26.2`, `saorsa-pqc 0.5`, `evmlib 0.9.0`, `heed 0.22`
(LMDB), `mimalloc`, `reqwest 0.13`, `clap`, `directories`.

**Resolution probe (2026-08-01, `cargo metadata` on a scratch manifest —
resolution only, no build, no change to the workspace):**

| Graph | Packages resolved |
| --- | --- |
| `ant-core = "=0.5.0"` alone | **652** |
| `ant-core = { "=0.5.0", features=["devnet"] }` | **688** (+36 = the ant-node subtree) |
| our workspace `Cargo.lock` today | **110** (`grep -c '^\[\[package\]\]'`) |
| name overlap between the two | **81 names** (utility crates: serde, thiserror, digest-stack, …) |

So consuming ant-core at all (S2) grows the lock by roughly **~570 new
package entries**, and the devnet feature adds ~36 more. **None** of the
heavy stack is present today — `tokio`, `reqwest`, `axum`, `alloy`,
`saorsa-core`, `heed`, `self_encryption`, `evmlib` all absent from the
current lock. This is *the* M1 lockfile event and belongs to one
deliberate P7 §4 review, jointly for the base graph and the devnet
subtree (one changelog/RUSTSEC/GHSA sweep, not two).

Facts the review must carry:

1. **Caret drift vs upstream's tested set:** the fresh resolve picks
   `saorsa-core 0.26.4`, while ant-core 0.5.0's own packaged lock pinned
   **0.26.2** (P9 record §3). A fresh resolve today is *not* the graph
   upstream tested 0.5.0 against. Decide deliberately: accept the drift or
   `cargo update --precise` the deltas back to ant-core's packaged lock.
2. **Duplicate majors arrive:** `reqwest` 0.12 (ant-core) + 0.13
   (ant-node); RustCrypto 0.10-generation (`digest`, `block-buffer`,
   `chacha20`, …) beside our pinned 0.11 generation; the `ark-*` pairs
   under alloy. `deny.toml` has `multiple-versions = "warn"` (D19), so
   these warn rather than fail — same shape as the recorded fips204
   dev-dep addendum (D14) — but the warning volume will jump; record the
   expectation so nobody "fixes" it ad hoc.
3. **GPL boundary (P9 §3):** `self_encryption` and `evmlib` are GPL-3.0
   and enter the build via antseal-net only; the devnet launcher (§6) is
   equally net-side. Nothing here touches antseal-core, whose normal-dep
   graph the `core-dep-graph` lane keeps I/O-free — the launcher must not
   perturb it (containment below).

**Build-cost containment.** With resolver-v2 semantics, a workspace member
that unconditionally enables `ant-core/devnet` would make
`cargo test --workspace --locked` (the `test` lane) compile ant-node +
saorsa-core for every CI run. Put the launcher's
`ant-core = { workspace = true, features = ["devnet"] }` dependency behind
the launcher crate's **own non-default feature** (optional dep): the
lockfile still records the full 688-package union (locks cover all member
features), but default workspace builds/tests never compile the ant-node
subtree; only `scripts/devnet/local-up`'s
`cargo run -p <launcher> --features devnet --release` does.

## 6. Recommended script architecture

**Do not run the upstream example verbatim.** Reasons: (a) it hardcodes
`DevnetConfig::default()` — no node-count control on a 2-core machine;
(b) it writes the manifest (with the wallet key) to the shared
`~/.local/share/ant/`, coupling us to any other ant tooling on the
machine; (c) P16's task text asks to "locate the example in the upstream
ant-client repo at the ref matching the P9 pin" — the example in fact
ships *inside the pinned crate archive itself* (sha256-verified above),
so the ref-pin requirement is discharged by the existing `=0.5.0` crate
pin, and consuming the same `LocalDevnet` API from that pinned crate is
strictly better provenance than a git checkout.

Shape:

- **`crates/devnet-runner`** (name per project convention; `publish =
  false`, not `antseal-*`, precedent: `crates/wasm-bitmatch`): ~100-line
  binary over `LocalDevnet::start(DevnetConfig { … })`. Knobs via env/flags:
  `ANTSEAL_DEVNET_NODES` (default **14**; presets 5/10/25 accepted),
  `ANTSEAL_DEVNET_DIR` (default `<repo>/.devnet` — data_dir + manifest +
  pidfile all under it), optional fixed `ANVIL_PORT`/base_port for
  reproducible runs. Writes `manifest.json` (the upstream `DevnetManifest`
  shape, §4) plus a flat sourceable `env` file
  (`ANTSEAL_DEVNET_RPC_URL=…` etc.) for shell consumers. Handles
  SIGINT/SIGTERM → `Devnet::shutdown()` (nodes stopped, data dir removed
  by `cleanup_data_dir`), then exits — Anvil dies with the process.
- **`scripts/devnet/local-up`**: asserts `anvil` on PATH (appending
  `~/.foundry/bin` if needed), `cargo run -p devnet-runner --features
  devnet --release`, backgrounds it, waits for `manifest.json` to appear,
  prints the env-file path. **`local-down`**: SIGTERM via pidfile, wait.
  **`local-reset`**: down + `rm -rf .devnet`. One command each; no
  residue (`local-down` leaves only the empty `.devnet` skeleton;
  `reset` removes it).
- **`.gitignore`**: `.devnet/` (already-required by P5's "devnet data
  dirs and key material" clause — verify the existing pattern covers it).
- Docs state: Anvil dev keys are public constants, never real value; the
  funded wallet is Anvil account 0; **no public Autonomi 2.0 testnet
  exists today** (spec-mandated note, shared with P17).

## 7. Resource estimate for this machine

Host: 2 cores, 7.7 GiB RAM (~5.3 available), 130 GiB free disk,
anvil 1.5.1 present, docker present (unneeded), `antnode` absent
(unneeded). Estimates are static, flagged as such; P16 execution measures.

- **RAM (runtime):** one process; per node an LMDB env (sparse mapping —
  resident stays small at devnet data volumes), a QUIC endpoint + DHT
  state, ML-DSA keys. Estimate 40–120 MB RSS/node under E2E load →
  **10–14 nodes ≈ 0.5–1.7 GiB; 25 nodes ≈ 1–3 GiB**, plus Anvil
  (~150–300 MB) and the harness. Fits 7.7 GiB with margin in all
  configurations.
- **CPU / startup wall-clock:** the spike is stabilization — every
  connection pair runs post-quantum QUIC handshakes (ML-KEM-768 +
  ML-DSA-65 via saorsa) on 2 cores. Spawn alone is node_count × 200 ms.
  Expect **~30–60 s to Ready at 10–14 nodes; minutes at 25**, with the
  120 s default stabilization timeout (`devnet.rs:49`) as the failure
  mode under background load (this machine also runs agent lanes — stage
  them). The presets' shorter timeouts (30 s/60 s) are tuned to their
  sizes. Verdict: 25 is *expected* to work on an otherwise-idle machine
  but is the flake zone; 14 is the recommended default.
- **Build (the dominant cost):** ~600 new crates including alloy, axum,
  tokio, saorsa-core/-pqc, heed. On 2 cores, first build estimate:
  **debug ~20–40 min, release ~45–90 min**. Build **release** — debug-mode
  PQC handshakes at stabilization time would burn the timeouts. Target-dir
  growth estimate 4–8 GiB (disk fine; current target is already 14 GiB).
  Subsequent builds are incremental/cached.
- **Runtime profile note:** the runner is release; the *harness/tests*
  (S17) can stay debug — they link antseal crates plus base ant-core
  client, not the node stack, if the harness connects to an
  already-running devnet via the manifest instead of embedding
  `LocalDevnet` itself. That split (runner owns the node graph, harness
  owns the client graph) also keeps `cargo test` lanes light. S17 decides;
  both work.

## 8. Feasibility verdict

**P16 is FEASIBLE on this machine, with no maintainer-blocked steps.**
No accounts, no funds, no installs beyond what exists (anvil present;
foundryup only if a future anvil bump is ever needed). The two real costs
are (1) the one-time ~45–90 min release build of the ~688-package graph
on 2 cores, and (2) the M1 lockfile event it rides on, which is P7
governance work shared with S2, not devnet work. 25 nodes is upstream's
default, not a requirement; run 14 by default (upstream's own e2e parity
size), keep 25 as an explicit parity mode, and treat 5 as smoke-only.
Node count, ports, data dirs, and the EVM surface are all configurable
through `DevnetConfig` + the manifest; the recommended architecture is a
thin in-repo launcher over the pinned crate's own API with three
one-command scripts and a repo-local gitignored environment export.

## 9. Corrections and discovered work for integration (not applied here)

Task-text updates owed (owners: the integrating wave — this memo edits no
task file):

1. **tasks/P.md P16**: "locate the example in the upstream ant-client
   repo at the ref matching the P9 pin and pin that ref in the script" →
   the example ships inside the `ant-core-0.5.0` crate archive
   (sha256-matched to P9); the crate pin *is* the ref pin. "verify what
   host tooling it needs (foundry/anvil version)" → recorded here:
   `anvil` on PATH via alloy node-bindings; 1.5.1-stable present. "25
   nodes + Anvil" → node count configurable; recommended default 14.
2. **tasks/Q.md Q15**: "(with cached node binaries)" is obsolete — nodes
   are in-process; the cacheable artifact is the cargo target dir (see
   D52).
3. **tasks/S.md S17** Accept "Runs in CI (scheduled or gated job per Q's
   infra)" → align with D52's venue outcome.
4. **tasks/P.md P17 / Open decisions line 243**: D38 resolves the
   test-ANT mechanism — update the register entry.

New-task candidates:

- **Containment assertion**: a cheap CI/test assertion that default
  `--workspace` builds do not compile `ant-node` (the §5 feature-gating,
  test-of-the-test style; extends the `core-dep-graph` philosophy).
- **P7/P13 note for the M1 lock event**: expected duplicate-major warning
  wave (reqwest 0.12+0.13, RustCrypto 0.10 generation, ark-*) recorded in
  D19/deny.toml rationale before the lock lands; `ant-node = "=0.15.0"`
  into the exact-pin class; saorsa-core 0.26.4-vs-0.26.2 drift decision.
- **Q2 secret-guard**: consider a pattern for bare hex EVM keys in
  devnet manifests (low priority — `.devnet/` is gitignored and the Anvil
  keys are public constants).
