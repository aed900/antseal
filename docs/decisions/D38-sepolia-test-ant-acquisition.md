# D38 — Test-ANT acquisition mechanism on Arbitrum Sepolia (chain 421614)

- **Status: RESOLVED — the mechanism is an ordinary ERC-20 `transfer` from
  an existing holder; nothing else exists. The deployed test token has no
  mint function, upstream operates no faucet, and no bridge is involved.
  Primary route: a maintainer-owned ask to upstream/community holders.
  Contingency (fully self-serve, development only): deploy our own
  instances of the same two verified contract artifacts on 421614 and run
  the Sepolia devnet in Custom-network mode — a recorded deviation that
  never substitutes for the canonical-contract M4 gate.**
- **Date: 2026-08-01** (M1 Storage planning wave)
- **Owner: P17** (funding runbook); executed maintainer-side per the
  external-actions rule
- **Blocks: P17** (funding runbook + Sepolia devnet docs), and downstream
  **Q32/Q33** (M4 Sepolia-mode gate wallet funding). Register entry:
  `tasks/P.md` Open decisions ("Test-ANT acquisition mechanism on
  Arbitrum Sepolia (chain 421614) … must land by the M4 Sepolia-mode gate
  (targeted M1)", line 243).

## Context

`start-devnet-sepolia` runs 25 local in-process nodes that verify
payments against **the real deployed Arbitrum Sepolia contracts** and
deliberately embeds no wallet: "no wallet key is provided — the user must
connect their own funded Sepolia wallet"
(`ant-core-0.5.0/examples/start-devnet-sepolia.rs:9-11`, `:94`). P17 must
therefore write a per-developer funding runbook: Arbitrum Sepolia ETH
(gas) plus **test ANT** for the payment token. Gas has ordinary public
faucets. Test ANT does not — this record determines what the acquisition
mechanism actually is, from the pinned sources, the deployed contract,
and upstream's docs, so the runbook can be written instead of guessed.

Scope note: this decision names the mechanism and assigns execution.
Amount sizing belongs to execution time (quote-driven, Q33's "sized from
quote estimates plus margin" pattern). Nothing here sends a transaction,
creates an account, or registers anywhere.

## Evidence

Provenance: `ant-core-0.5.0` and `evmlib-0.9.0` archives fetched from
static.crates.io on 2026-08-01 and sha256-matched to the P9 record
(`docs/upstream/P9-ant-core-reverification.md:32`, `:87-89`); explorer
and docs retrievals dated below. File:line cites are into those archives.

### 1. The contracts the example targets, and where they are defined

The example prints the addresses it will use from
`ant_core::data::EvmNetwork::ArbitrumSepoliaTest`
(`start-devnet-sepolia.rs:43-47`), a re-export of `evmlib::Network`
via `ant_protocol::evm` (`ant-core-0.5.0/src/data/mod.rs:61-63`).
The constants (`evmlib-0.9.0/src/lib.rs`):

| What | Value | Cite |
| --- | --- | --- |
| RPC | `https://sepolia-rollup.arbitrum.io/rpc` (canonical public Arbitrum Sepolia endpoint; chain id 421614 — P17 scripts assert `eth_chainId == 0x66eee`) | `lib.rs:58-62` |
| Payment token (test ANT) | `0x4bc1aCE0E66170375462cB4E6Af42Ad4D5EC689C` | `lib.rs:67-68` |
| Payment vault | `0xd742E8CFEf27A9a884F3EFfA239Ee2F39c276522` — commented "**proxy contract**" | `lib.rs:74-76` |

### 2. The token has no mint function

The client binds the token through the artifact shipped in evmlib
(`evmlib-0.9.0/src/contract/network_token.rs:18-24`,
`artifacts/AutonomiNetworkToken.json`). The ABI's complete function list:

> CLOCK_MODE, DOMAIN_SEPARATOR, allowance, approve, balanceOf, **burn,
> burnFrom**, checkpoints, clock, decimals, delegate, delegateBySig,
> delegates, eip712Domain, getPastTotalSupply, getPastVotes, getVotes,
> name, nonces, numCheckpoints, permit, symbol, totalSupply, transfer,
> transferFrom

— OpenZeppelin ERC-20 + Permit + Votes + Burnable. **No `mint`. The
constructor takes no inputs** (fixed premine to the deployer; supply can
only shrink, via `burn`). The on-chain deployment matches the artifact:
sepolia.arbiscan.io shows the contract **verified "Exact Match"**,
AutonomiNetworkToken (ANT), total supply **20,000,000**, **13,696
holders** (retrieved 2026-08-01). A public mint is therefore not merely
undocumented — it is *absent from the deployed bytecode*.

### 3. Upstream operates no faucet and documents no acquisition path

- GitHub code search across the entire WithAutonomi org for `faucet`:
  **0 hits** (2026-08-01). The word does not appear in any upstream repo.
- The developer docs' wallet guide
  (`WithAutonomi/autonomi-developer-docs`,
  `docs/guides/prepare-a-wallet-for-uploads.md`, verified upstream
  2026-07-30) says for Sepolia only: *"Use a test wallet funded with test
  ANT and test gas"* — funded how is never stated, there or in any other
  guide in that repo.
- Web search (2026-08-01) surfaces only generic Arbitrum Sepolia **ETH**
  faucets (Alchemy, Chainlink, QuickNode, L2Faucet, …); no ANT faucet on
  421614 exists anywhere findable.
- The 13,696 holders are consistent with the community record: Autonomi's
  pre-launch beta rewards were distributed on the Arbitrum test networks
  (forum.autonomi.community), i.e. supply is already spread across many
  community wallets.

### 4. It is not a bridge token

The artifact is a plain premined OZ ERC-20 with governance extensions —
no bridge escrow interfaces, no canonical-bridge registration referenced
anywhere in evmlib or upstream docs. Bridging from Ethereum Sepolia is
not a route.

### 5. The self-deploy machinery already exists upstream (contingency)

The local devnet deploys **these same two artifacts** onto Anvil per run
(`evmlib-0.9.0/src/testnet.rs:48-62`: `NetworkToken::deploy` from account
0, PaymentVault from account 1), premining the full supply to the
deployer. The same works on any chain: evmlib exposes
`Network::Custom { rpc_url, payment_token_address, payment_vault_address }`
constructed either in code (`lib.rs:100-106`, `:137-143`) or from env
(`RPC_URL`, `PAYMENT_TOKEN_ADDRESS`, `PAYMENT_VAULT_ADDRESS`,
`utils.rs:117-135`), and devnet nodes verify payments against whatever
network they are configured with, including Custom
(`ant-node-0.15.0/src/devnet.rs:164-167`, `:561-566`). Since the Sepolia
devnet's 25 nodes are all ours anyway (there is no public Autonomi node
network on Sepolia), pointing nodes + client at self-deployed instances
of the same bytecode on 421614 is upstream-supported configuration, not a
fork.

## Options

**A — public mint on the deployed token.** ELIMINATED by evidence §2: no
`mint` in the ABI of a verified-exact-match contract.

**B — upstream faucet.** ELIMINATED by evidence §3: no faucet exists in
upstream code, docs, or anywhere findable.

**C — bridge from Ethereum Sepolia.** ELIMINATED by evidence §4.

**D — ERC-20 `transfer` from an existing holder.** The only mechanism the
token supports. Sub-routes:

- **D1 — ask upstream/community** (Discord/forum; the team and thousands
  of beta-reward holders hold supply). External action: needs the
  maintainer's accounts and a receiving wallet. Cost: latency +
  goodwill; zero deviation.
- **D2 — acquire from any third-party holder** (same mechanism, arbitrary
  counterparty). Kept only as D1's generalization; no marketplace for a
  valueless test token is assumed.
- **D3 — self-deploy the same artifacts on 421614** (evidence §5) and run
  the devnet in Custom mode; the deployer wallet receives the full 20 M
  premine. Needs only faucet ETH for gas. Deviation: payments no longer
  touch **the** canonical deployed contracts (the P17 task text and the
  Q33 gate language name those), though they exercise the identical
  bytecode, chain, RPC, and client code path.

## Decision

**RESOLVED: the mechanism is D — ERC-20 `transfer` from an existing
holder.** Concretely:

1. **Primary route D1, execution maintainer-owned.** P17's runbook names
   it as such: the maintainer requests test ANT from the Autonomi
   team/community (Discord or forum.autonomi.community) to a fresh,
   unlinked receiving address created per Q25 hygiene; amounts sized from
   quotes plus margin (Q33 pattern); addresses and amounts (never keys)
   recorded in the runbook evidence. Gas ETH comes from the standard
   public Arbitrum Sepolia faucets — most require accounts/logins, so
   that half is equally maintainer-owned. Per the standing external-
   actions rule, none of this is ever executed by an agent.
2. **Contingency route D3, scripted but dormant.** If D1 stalls past its
   usefulness window (it must not stall past the M4 gate), P17 may ship a
   self-deploy script (deploy both artifacts from the pinned evmlib
   version's build artifacts to 421614; run nodes + client in
   Custom-network mode). The deviation is recorded in the runbook the
   moment it is used: **development unblocking only — the M4 Sepolia-mode
   gate (Q32/Q33) still targets the canonical contracts of §1**, because
   the gate's language ("per upstream's start-devnet-sepolia
   requirements") and its purpose (prove the release binary against the
   contracts real users' wallets know) both point at the canonical
   deployment. The gate is also the register's own deadline for this
   mechanism ("must land by the M4 Sepolia-mode gate").
3. **The open-decision register entry closes.** Nothing about the
   mechanism is undecidable: the token's bytecode admits exactly one
   acquisition path, and both routes to it are named with owners.

## Rationale

1. **The contract decides, and it is verified.** With no `mint` and a
   fixed 20 M premine, every unit of test ANT any developer will ever
   hold arrived by `transfer` from the deployer outward. Naming any other
   mechanism would be fiction; a runbook built on "find the faucet at
   execution time" would fail at execution time (§3: there is none).
2. **Maintainer-owned is the honest resolution, not a deferral.** The
   register asked *what the mechanism is* because the runbook cannot be
   written without it. It now can be: the runbook's acquisition section
   is a concrete ask-and-receive procedure with wallet hygiene, not a
   research task. The remaining latency risk is exactly the risk P17's
   own Notes already carry ("if funding proves slow, the local devnet
   (P16) carries M1–M3 development without spec violation").
3. **The contingency removes the schedule cliff without moving the
   goalposts.** D3 is fully self-serve (gas-only), uses upstream's own
   Custom-network machinery, and exercises the identical client payment
   path — while the recorded-deviation clause stops it from quietly
   becoming the gate. This is the reversible-direction choice: adopting
   D3 temporarily costs nothing permanent; skipping the canonical-contract
   gate would.
4. **Chain-identity discipline is preserved.** Both routes stay on chain
   id 421614; the runbook and scripts assert it and carry the
   spec-mandated "Arbitrum Sepolia, NOT Ethereum Sepolia" warning (P17
   Accept), which matters doubly here because the *gas* faucets in §3 are
   the place a developer is most likely to wander onto the wrong Sepolia.

## Consequences for blocked tasks

- **P17** is unblocked to write the funding runbook now:
  (a) wallet setup — fresh unlinked address, key never committed (Q25);
  (b) gas — public Arbitrum Sepolia ETH faucets, maintainer-owned
  (account-gated), with the wrong-Sepolia warning;
  (c) test ANT — the D1 ask procedure, evidence recording
  (addresses/amounts, never keys), and the token/vault addresses of §1
  pinned in docs and asserted by scripts (chain id 0x66eee, token
  `0x4bc1…689C`, vault `0xd742…6522`);
  (d) the D3 contingency section, dormant, with its deviation clause;
  (e) the "no public Autonomi 2.0 testnet exists" note (shared with P16).
- **Q33** (M4 wallet funding) inherits route D1 and the evidence format;
  its "acquisition route recorded in gate evidence" item is now
  well-defined.
- **S's paid-Sepolia smoke** (closes P17's Accept jointly): first paid
  operation after D1 funds arrive; on D3 it may run earlier but does not
  discharge the Accept's "against the real Sepolia contracts" clause.
- **tasks/P.md line 243** (Open decisions): mark resolved to this record
  at integration. **tasks/P.md P17 text**: the "faucet, mint, bridge —
  whatever the example expects" enumeration can now cite the answer.

## Residual risks

1. **D1 latency is uncontrolled** (third-party humans). Bounded by: P16
   carries M1–M3; D3 exists; the hard deadline is the M4 gate, not M1.
   Escalation is a dated note in the runbook, not a silent slip.
2. **Upstream may redeploy or migrate the Sepolia contracts** (weekly
   release cadence). Our pinned evmlib hardcodes the §1 addresses, so a
   migration surfaces as an ant-core/evmlib bump under P7 §4 + the P19
   weekly check — never as silent drift. Acquired test ANT at the old
   token would strand; keep balances small (quote-sized), acquire close
   to need.
3. **The vault is a proxy** (`lib.rs:74`): its implementation can change
   under the same address, altering payment semantics without any pin
   moving. Watch: P19 weekly + S20's churn procedure; the S smoke re-run
   after any known upstream payment-surface change.
4. **D3, if used, can ossify.** The recorded-deviation clause plus the
   Q32/Q33 canonical-contract language are the guard; reviewers of the
   gate evidence check which token address the receipts name.
5. **Holder-transfer involves third-party interaction** from
   maintainer-controlled accounts; wallet hygiene (fresh unlinked
   addresses, Q25) contains linkage. Test ANT has no value guarantee and
   needs none.
