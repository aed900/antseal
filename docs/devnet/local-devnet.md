# Local devnet runbook (P16)

One-command, self-hosted Autonomi 2.0 devnet for M1 development and the
S17–S19 E2E suite: **N in-process nodes + a fresh Anvil chain with both
payment contracts deployed per run**. Decision context: D52 (venue),
docs/research/P16-devnet-feasibility.md (the feasibility memo every number
here comes from), docs/upstream/P16-lockfile-event.md (the dependency
review that admitted this graph).

**There is no public Autonomi 2.0 testnet today.** This local devnet and the
Arbitrum-Sepolia devnet (P17) are the only development networks; nothing
here can be outsourced to a faucet or a hosted endpoint. (Spec: MVP-SPEC.md
"Network decision".)

**D52 venue statement.** The devnet E2E runs as a **required local gate**
(`scripts/e2e-devnet.sh`, Q15) before merging storage-touching changes, plus
a scheduled non-required GitHub job at reduced node count if its measured
runtime fits the minutes budget. There is deliberately NO per-PR devnet CI
job and NO self-hosted runner — the reasoning and revisit triggers are in
docs/decisions/D52-devnet-e2e-venue.md.

## Host requirements

| Requirement | Detail |
| --- | --- |
| Linux | pidfile/`/proc` handling and the boot evidence below assume it; nothing else is portable-hostile |
| `anvil` on PATH | Foundry's Anvil, spawned as a subprocess by the launcher (alloy node-bindings). `local-up` appends `~/.foundry/bin` automatically; verified present on the dev machine (1.5.1-stable). Missing ⇒ install foundry (`foundryup`) |
| CPU/RAM | 2 cores / 7.7 GiB suffice: 14 nodes ≈ 0.5–1.7 GiB RSS + Anvil ~150–300 MB (memo §7). Stop agent lanes/background load during boot — PQC handshakes at stabilization are the CPU spike |
| Disk | first release build of the ~736-package graph adds ~4–8 GiB to `target/`; the devnet's own data is tiny |
| No docker, no `antnode` binary | nodes are in-process tokio tasks of the launcher (memo §1) |

## Commands

```bash
scripts/devnet/local-up              # build (release, --features devnet) + boot 14 nodes
scripts/devnet/local-up --nodes 5    # smoke preset (below CLOSE_GROUP_SIZE=7 — degraded quorums)
scripts/devnet/local-down            # SIGTERM the launcher; verify NO residue
scripts/devnet/local-reset           # down (best effort) + rm -rf .devnet — the recovery path
```

- **First `local-up` is dominated by the release build: ~45–90 min on
  2 cores** (measured value in Boot evidence below). Subsequent runs reuse
  `target/` and boot in well under two minutes.
- Release is mandatory, not preference: debug-mode ML-KEM-768/ML-DSA-65
  handshakes burn the node-stabilization timeout (memo §7).
- Node count: default **14** = upstream's own e2e parity count
  (`CLOSE_GROUP_SIZE = 7`, node quorum 4, witnessed client quorum 5-of-7;
  memo §3). 5/10 use upstream's `minimal()`/`small()` presets (shorter
  stabilization timeouts); 25 = upstream-default parity, the flake zone on
  2 cores. Range 5..=25 enforced by the launcher.
- Knobs (env): `ANTSEAL_DEVNET_NODES`, `ANTSEAL_DEVNET_DIR`,
  `ANTSEAL_DEVNET_STABILIZATION_SECS`, `ANTSEAL_DEVNET_NODE_LOGS=1`,
  `ANTSEAL_DEVNET_UP_TIMEOUT` / `ANTSEAL_DEVNET_DOWN_TIMEOUT` (scripts),
  `RUST_LOG` (launcher/node verbosity, stderr).

## Environment surface (for S5/S17/U consumers)

Everything lives under the repo-local **gitignored** `.devnet/` — never
`~/.local/share/ant/` (the upstream example's shared path), because the
export embeds the funded dev key and must stay inside the repo's
deny-by-default ignore rules. **Nothing under `.devnet/` is ever
committable.** Consumers re-read the export per run; every `local-up` mints
a fresh chain, fresh contract addresses, fresh ports.

| File | Contents |
| --- | --- |
| `.devnet/manifest.json` | upstream `DevnetManifest` JSON: `base_port`, `node_count`, `bootstrap` (multiaddrs), `data_dir`, `created_at`, `evm { rpc_url, wallet_private_key, payment_token_address, payment_vault_address }` |
| `.devnet/env` | flat `KEY='value'` lines, `source`-able |
| `.devnet/launcher.pid` | the launcher pid = the devnet's lifetime handle (`local-down` consumes it) |
| `.devnet/launcher.log` | launcher stdout+stderr incl. node tracing (`READY`/`STOPPED` protocol lines) |
| `.devnet/data/` | per-node LMDB stores; removed by the node stack on clean shutdown |

`env` keys:

```
ANTSEAL_DEVNET_RPC_URL                  Anvil EVM JSON-RPC endpoint
ANTSEAL_DEVNET_CHAIN_ID                 31337 (Anvil default; re-verified at boot evidence)
ANTSEAL_DEVNET_TOKEN_ADDRESS            AutonomiNetworkToken (deployed fresh per run)
ANTSEAL_DEVNET_PAYMENT_VAULT_ADDRESS    PaymentVault (deployed fresh per run)
ANTSEAL_DEVNET_WALLET_PRIVATE_KEY       funded wallet key (Anvil dev account 0 — see below)
ANTSEAL_DEVNET_BOOTSTRAP                comma-separated SocketAddrs for Client::connect
ANTSEAL_DEVNET_NODE_COUNT               actual node count booted
ANTSEAL_DEVNET_BASE_PORT                first node port (OS-random per run)
ANTSEAL_DEVNET_DATA_DIR                 node store root (under .devnet/)
ANTSEAL_DEVNET_PID                      launcher pid (same as launcher.pid)
```

## Wallet funding story (ANT + ETH)

There is no faucet and no funding step: **Anvil pre-funds its well-known
developer accounts with ETH, and the `AutonomiNetworkToken` constructor
premines the ENTIRE token supply to its deployer — Anvil dev account 0**
(evmlib deploys it from that account per run; memo §1). So the one key in
the export is both gas-funded and ANT-rich from block 0, and
`approve_token_spend` + paid uploads work immediately.

The key is a **well-known public Anvil constant** shipped in every Anvil
binary on earth — it is not a secret and guards nothing real. It is still
key-shaped material, so it lives only under gitignored `.devnet/` and must
never appear in committed files, fixtures, or logs that leave the machine
(project rule 6 applies to the PATTERN, not just to real secrets).

## Lifecycle and the no-residue contract

The launcher process IS the devnet: nodes are its tokio tasks, Anvil is its
child (dropping the embedded `Testnet` kills Anvil). `local-down` SIGTERMs
the pid; the launcher shuts nodes down, the node stack removes `data/`
(`cleanup_data_dir`), the launcher removes `manifest.json`/`env`/
`launcher.pid`, and the script removes `launcher.log` — after a clean down,
**`.devnet/` is empty**, and the script FAILS loudly if it is not. An
unclean stop (timeout → SIGKILL) keeps everything for diagnosis;
`local-reset` is the scorched-earth recovery. Consequence for harnesses
(S17): treat the export as run-scoped, re-`source` after every up.

## Troubleshooting

- **Resolve failure that looks like a yank** ("no matching version for
  ant-node"): a stale local sparse-index cache — reproduced during the P16
  probe. Refresh the index (`cargo update --dry-run -p ant-node` or clear
  `~/.cargo/registry/index/`) before concluding anything about upstream
  (docs/upstream/P16-lockfile-event.md §6).
- **`devnet not ready after Ns`**: stabilization timed out — background load
  on a 2-core host is the usual cause (memo §7). Free the cores or drop the
  count: `local-up --nodes 10`, then `--nodes 5`.
- **"a devnet is already running"**: `local-down`; if the pid is dead but
  the file remains (SIGKILL history), the launcher removes stale pidfiles
  itself on the next start; `local-reset` if in doubt.
- **Port collision**: ports are OS-random per run (base_port in
  20000–60000); re-run `local-up`.

## Boot evidence

*(Dated records; the numbers the E2E harness plans against.)*

<!-- BOOT-EVIDENCE -->
