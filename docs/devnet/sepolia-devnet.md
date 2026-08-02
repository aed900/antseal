# Arbitrum-Sepolia devnet + funding runbook (P17)

> ## ⚠ Arbitrum Sepolia — chain id **421614** (`0x66eee`). **NOT** Ethereum Sepolia (11155111 / `0xaa36a7`).
>
> Two different networks with confusingly similar names. Ethereum Sepolia
> ETH cannot pay for anything here, and the Autonomi payment contracts do
> not exist on it. The place this goes wrong is the **gas faucet**: most
> faucet pages offer both, one dropdown apart. `scripts/devnet/
> sepolia-preflight` refuses to proceed if the endpoint answers with any
> other chain id, and names Ethereum Sepolia by number when that is what
> answered.

**There is no public Autonomi 2.0 testnet today.** The local Anvil devnet
([local-devnet.md](local-devnet.md), P16) and this Sepolia devnet are the
only development networks. Nothing here can be outsourced to a hosted
endpoint or a faucet — for the *payment token*, no faucet exists at all
(see "Funding runbook" below and
[D38](../decisions/D38-sepolia-test-ant-acquisition.md)).

Decision context: **D38** (test-ANT acquisition — resolved), P16 (the
architecture this mirrors), Q32/Q33 (the M4 Sepolia-mode gate this exists
to derisk).

## What this is

Upstream's `start-devnet-sepolia` shape
(`ant-core-0.5.0/examples/start-devnet-sepolia.rs`): **local in-process
nodes that verify payments against the real deployed Arbitrum Sepolia
contracts**. No Anvil, no per-run contract deploy, and — unlike the local
devnet — **no embedded wallet**: *"no wallet key is provided — the user must
connect their own funded Sepolia wallet"* (ibid. lines 9-11).

That last difference is the whole reason this page exists. On the local
devnet the funded key is a public Anvil constant and funding is a non-event;
here the key is **real key material** and the tokens must come from a human.

### Status, stated plainly

| Piece | State |
| --- | --- |
| Chain + contract preflight (`sepolia-preflight`) | **Live.** Verified read-only against the public endpoint 2026-08-02 — see "Verification record" |
| Environment surface (`.devnet/sepolia-env`) | **Live**, chain half; the launcher half lands with the node boot |
| Funding runbook (below) | **Complete** — and its execution is ⛔ **maintainer-owned**, never an agent's |
| Node boot (`sepolia-up`) | **Blocked on P22** — `devnet-launcher` has no Sepolia mode yet. The script is written, runs the preflight, and stops with a named blocker listing exactly what P22 changes |
| Self-deploy contingency (D38 route D3) | **Documented, dormant** — see "Contingency" |

## Host requirements

| Requirement | Detail |
| --- | --- |
| `curl`, `python3` | the preflight's read-only JSON-RPC calls and its 18-decimal balance rendering |
| Network egress to `sepolia-rollup.arbitrum.io` | the canonical public Arbitrum Sepolia RPC (`evmlib-0.9.0/src/lib.rs:58-62`) |
| **No `anvil`** | unlike the local devnet — there is no local chain in this mode |
| CPU/RAM | as P16: 2 cores / 7.7 GiB carry 14 in-process nodes; the node stack is identical, only the payment target differs |
| A funded wallet | **the hard part.** See the funding runbook |

## Commands

```bash
scripts/devnet/sepolia-preflight                 # chain id + both contracts, read-only
scripts/devnet/sepolia-preflight --address 0x…   # …plus that address's gas and test-ANT balances
scripts/devnet/sepolia-preflight --self-test     # offline; planted wrong-chain answers must go red
scripts/devnet/sepolia-up [--nodes N]            # preflight, then boot (blocked on P22 today)
scripts/devnet/local-down                        # DOWN — the same script for both modes
scripts/devnet/local-reset                       # scorched-earth recovery, both modes
```

Down and reset are deliberately **not** duplicated: the devnet is one
launcher process with one pidfile under `.devnet/` in either mode, so a
second copy of that logic could only drift from the first. One devnet per
checkout still holds across modes — `sepolia-up` refuses to boot while a
local devnet is running, and vice versa.

`.devnet/sepolia-env` outlives any devnet by design — the chain and contract
addresses it records are the same before, during and after a run — so
`local-down`'s no-residue check exempts exactly that one filename and
nothing else (a real leftover beside it still fails the check).
`local-reset` does remove it, correctly: the preflight regenerates it in
seconds.

Exit codes worth knowing: preflight `0` = chain and contracts good, `3` =
chain good but **the wallet is not funded**, `1` = do not proceed.
`sepolia-up` adds `4` = blocked on P22.

## Environment surface (for S/U consumers)

`.devnet/sepolia-env`, same `KEY='value'` shape and the same
`ANTSEAL_DEVNET_*` key names as P16's local export, so consumers need no
second parser (`DevnetEnv`, `crates/antseal-net/src/network.rs`).

```
ANTSEAL_DEVNET_NETWORK                  'arbitrum-sepolia'  (extra key; the parser ignores unknown ANTSEAL_DEVNET_* keys by design)
ANTSEAL_DEVNET_RPC_URL                  https://sepolia-rollup.arbitrum.io/rpc
ANTSEAL_DEVNET_CHAIN_ID                 421614
ANTSEAL_DEVNET_TOKEN_ADDRESS            0x4bc1aCE0E66170375462cB4E6Af42Ad4D5EC689C
ANTSEAL_DEVNET_PAYMENT_VAULT_ADDRESS    0xd742E8CFEf27A9a884F3EFfA239Ee2F39c276522
```

The remaining launcher-produced keys (`BOOTSTRAP`, `NODE_COUNT`,
`BASE_PORT`, `DATA_DIR`, `PID`) appear in `.devnet/env` once nodes boot,
exactly as on the local devnet.

### The wallet key is never written to a file

Not to `.devnet/sepolia-env`, not to `.devnet/env`, not anywhere. The local
devnet's key is a well-known public Anvil constant; **a Sepolia key is a
real secret** — it controls real (if valueless) test balances, and project
rule 6 binds it absolutely. Supply it through the process environment:

```bash
set -a; . .devnet/sepolia-env; set +a
export ANTSEAL_DEVNET_WALLET_PRIVATE_KEY="$(your key source)"   # never a literal in a file, a history, or a script
```

`DevnetEnv::from_process_env()` then sees all ten keys and none of them
touched disk. **Known gap**: `DevnetEnv` today *requires* all ten keys, so a
Sepolia export alone (nine keys, no wallet) will not parse — the recipe
above is the workaround, and an optional-wallet variant is part of **P22**.

## Funding runbook

> ### ⛔ Every step in this section is a **maintainer action**.
>
> It creates accounts, signs in to faucet services, asks humans for tokens,
> and moves value between addresses. Per the standing external-actions rule
> **no agent executes any of it** — not the faucet request, not the
> community ask, not a transfer, not a contract deployment. An agent may
> read public explorers and make read-only RPC calls, which is exactly what
> `sepolia-preflight` does and all that it does.

**The mechanism is settled** ([D38](../decisions/D38-sepolia-test-ant-acquisition.md),
resolved 2026-08-01, from the deployed bytecode rather than from
expectation): test ANT can be acquired **only by an ordinary ERC-20
`transfer` from an existing holder.**

- The deployed token has **no `mint`** — the ABI is OpenZeppelin ERC-20 +
  Permit + Votes + Burnable, its constructor takes no inputs (fixed premine,
  supply can only shrink via `burn`), and sepolia.arbiscan.io shows it
  verified "Exact Match" with 20,000,000 total supply across ~13,700
  holders.
- Upstream operates **no faucet** — zero hits for `faucet` across the whole
  WithAutonomi org; the developer docs say "use a test wallet funded with
  test ANT and test gas" and never say how.
- It is **not a bridge token** — a plain premined ERC-20 with governance
  extensions, no escrow interfaces, no canonical-bridge registration.

### Step 1 — a fresh receiving address

Create a **new, unlinked** address for this purpose (Q25 wallet hygiene: the
payment receipt links a seal to a wallet, and a wallet to whatever funded
it). Never reuse a mainnet address. The private key lives wherever your key
management lives — **never in this repository**, never in `.devnet/`, never
in a shell history.

### Step 2 — gas (Arbitrum Sepolia ETH)

Ordinary public faucets. Most are account-gated (sign-in, a mainnet-balance
check, or a social account), which is why this half is maintainer-owned too.
Whichever you use: **confirm the network selector says Arbitrum Sepolia**,
then confirm it landed:

```bash
scripts/devnet/sepolia-preflight --address 0xYOURADDRESS
```

Gas alone is enough to *boot* the devnet and to *read*; it is not enough to
pay for storage.

### Step 3 — test ANT (the ask)

Request test ANT from the Autonomi team or community — the project Discord
or `forum.autonomi.community` — to the address from step 1. Thousands of
beta-reward holders and the team hold supply; there is no other route.

Size the ask from **real quotes plus margin** (the Q33 pattern), not from a
round number: run a quote against the devnet, multiply by the number of
paid operations you expect, add margin, ask for that. Test ANT has no value
guarantee and needs none; keep balances small and acquire close to need
(D38 residual risk 2 — upstream can redeploy the token, which would strand
an old balance).

### Step 4 — record the evidence

In this runbook's "Verification record" section, or the wave record:

- the receiving **address** and the **amounts** received (both assets);
- the **date** and the route used (community ask / contingency);
- the **token address** the balance is denominated in — reviewers of the M4
  gate evidence check exactly this, because it is what distinguishes the
  canonical contracts from a self-deployed instance.

**Never** the key, never a seed phrase, never a keystore file. The
`secret-guard` lane scans for all three shapes on every gate, but the rule
is the point and the lane is only the backstop.

### Step 5 — the first paid operation

Jointly with S's backend smoke: one paid upload against the real Sepolia
contracts. That is what closes P17's Accept row 2, and it needs the node
boot (P22) as well as the funds.

## Contingency (D38 route D3) — dormant, and it does not substitute

If the community ask stalls past its usefulness window, the fully self-serve
route is to **deploy our own instances of the same two verified contract
artifacts on chain 421614** and run the devnet in upstream's
`Network::Custom` mode (`evmlib-0.9.0/src/lib.rs:100-106`, `:137-143`, or
its `RPC_URL`/`PAYMENT_TOKEN_ADDRESS`/`PAYMENT_VAULT_ADDRESS` env form;
devnet nodes verify against whatever network they are configured with,
including Custom — `ant-node-0.15.0/src/devnet.rs:164-167`). The deployer
receives the full premine, so only faucet gas is needed. This is upstream's
own machinery, not a fork.

**It is a recorded deviation, and it is recorded the moment it is used:**

- development unblocking **only**;
- the **M4 Sepolia-mode gate (Q32/Q33) still targets the canonical
  contracts** of the table above — the gate's purpose is to prove the
  release binary against the contracts real users' wallets know;
- the deviation is written here with its date and the self-deployed
  addresses, so gate reviewers can tell the two apart by token address.

No self-deploy script is shipped today, deliberately: deploying is a
transaction-sending action (⛔ maintainer), and the launcher-side
Custom-network wiring it would need is the same change as **P22**. Landing
a dormant deploy script before either exists would be untested code with a
loaded gun attached to it.

## Verification record

### 2026-08-02 — preflight, read-only (P17 execution)

Executed against `https://sepolia-rollup.arbitrum.io/rpc`; four `eth_*`
reads, no transaction, no account, no funds requested.

| Check | Result |
| --- | --- |
| `eth_chainId` | `0x66eee` = **421614** — Arbitrum Sepolia confirmed |
| `eth_getCode` — payment token `0x4bc1…689C` | **7 889 bytes** |
| `eth_getCode` — payment vault `0xd742…6522` | **12 828 bytes** |
| `eth_getBalance` / ERC-20 `balanceOf` plumbing | exercised against a neutral address; 18-decimal rendering correct |
| Export | `.devnet/sepolia-env` written, five keys, **no key material** |

Two things worth carrying forward:

1. **The token is byte-for-byte the same artifact the local devnet
   deploys.** P16's boot evidence records the locally deployed
   `AutonomiNetworkToken` answering `eth_getCode` with **7 889 bytes** — the
   same number. Local-devnet token semantics therefore transfer to Sepolia.
2. **The payment vault does not.** The local deploy is 3 937 bytes; the
   Sepolia address holds 12 828. That is consistent with evmlib's own
   annotation ("proxy contract") and it makes **D38 residual risk 3**
   concrete: the vault's behaviour at that address is not the artifact we
   deploy locally, and it can change under the same address with no pin
   moving. Anything that depends on vault semantics must be re-smoked after
   any known upstream payment-surface change (P19 weekly + S20).

The `--self-test` (offline, planted RPC answers) is green in both
directions: an Ethereum-Sepolia chain id, a foreign chain id, and an
empty-code contract each turn the preflight red; the correct answers pass;
a zero test-ANT balance produces the distinct NOT-FUNDED outcome. That last
case exists because the first live run got it wrong — `eth_call` returns a
32-byte word, so a `"0x0"` string comparison silently reported an unfunded
wallet as funded. The fixtures now carry the wide form the endpoint really
emits.

## Troubleshooting

- **"THIS IS ETHEREUM SEPOLIA"** — the endpoint (or the faucet, or the
  wallet's network selector) is on 11155111. Nothing on it is useful here.
- **"no contract code at the … address"** — either not Arbitrum Sepolia, or
  upstream redeployed. The second surfaces as an ant-core/evmlib bump under
  dependency-policy §4 and the P19 weekly check, never as silent drift.
- **"BLOCKED ON P22"** — expected today; the message lists what the launcher
  change is.
- **Rate limiting from the public RPC** — the preflight makes four calls;
  if a shared endpoint throttles, `--rpc` takes an alternative (still
  assert the chain id — that is the whole point of the check).
