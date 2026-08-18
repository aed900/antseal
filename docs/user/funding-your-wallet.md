# Funding your wallet

Sealing costs money. This page explains what antseal spends, how to get it,
what the CLI does when your wallet is short, and how the development networks
differ (they cost nothing and prove nothing).

antseal is non-custodial. `antseal init` creates a payment wallet inside your
vault; the key stays on your machine. Nobody can fund that address for you,
and nobody else can spend from it. If you lose the vault you lose the wallet
with it — see `vault-loss.md`.

**Money moves only after you consent.** Before anything is paid, `seal` prints
the full quote beside both balances and asks. Every failure described on this
page happens *before* payment: the CLI says so in the error itself, with the
words "nothing was paid or uploaded".

## Two assets, and you need both

| Asset | Pays for | Runs out as |
| --- | --- | --- |
| **ANT** | the storage itself, once, forever | class `insufficient-ant-token`, exit code **20** |
| **ETH** | gas for the payment transaction | class `insufficient-eth-gas`, exit code **21** |

A wallet with one and not the other fails at a different step with a different
error, which is why `init` always names both
(`crates/antseal-cli/src/init.rs:270-275`).

Timestamping costs no ANT
(`docs/decisions/D36-prepay-resume-requote-reconsent.md:250-252`). The
timestamp anchors are fetched over HTTP from timestamp authorities and
calendars; they are not transactions on any chain, and a seal that abandons
before payment has still spent nothing.

Amounts are quoted in the smallest units. **1 ANT is 10^18 atto-ANT**
(`crates/antseal-net/src/quote.rs:12-14`, `tasks/U.md:367`), and gas is quoted
in wei, as everywhere else on an EVM chain.

## Find out what it costs before you fund

```
antseal seal <files> --dry-run
```

`--dry-run` runs every free step — it reads your files, encrypts them, and
asks the network for a **real** quote — then stops. Nothing is paid, anchored,
uploaded, or written to the vault. Its help text:

```
Run every free step and print the plan + true cost quote; nothing is paid, anchored, or uploaded (D49)
```

(`crates/antseal-cli/tests/snapshots/cli-surface.help.txt:130-131`)

The report shows the quote and both balances together, and marks any shortfall:

```
  Cost (indicative): <N> atto-ANT storage, plus about <N> wei of gas
  Wallet:      0x…
               <N> atto-ANT  ** SHORT by <N> **
               <N> wei
```

(`crates/antseal-cli/src/seal_consent.rs:139-158`, `:236-242`)

Read "true cost quote" there as *true pricing mechanism*, not a locked-in
price. The report itself labels the figure **indicative**, and that is the
honest word: a real seal draws fresh nonces, so it encrypts to different
addresses and re-quotes at a later moment
(`crates/antseal-cli/src/seal_run.rs:284-289`;
`docs/decisions/D49-dry-run-network-semantics.md:110-116`). Treat it as the
right order of magnitude.

`--dry-run` also exits with the same shortfall codes a real seal would, so it
works as a scripted check for "could this machine seal this work right now"
(`docs/decisions/D49-dry-run-network-semantics.md:98-105`).

One difference worth knowing, because it is easy to misread as a broken
command: **when a dry run finds you short, you get the one-line error and not
the report above it.** A real `seal` prints the whole report first and then
refuses (`crates/antseal-cli/src/seal_consent.rs:441-444`); a dry run checks
the balances after building the report and returns the error instead of it
(`crates/antseal-cli/src/seal_run.rs:505-520`). The error still carries both
numbers, so you can still work out the shortfall.

## Arbitrum One — real funds

This is the default network (`--network arbitrum-one`, chain **42161**,
`crates/antseal-net/src/network.rs:52`). `init` prints:

```
To seal, this address needs two things:
  1. ANT tokens on Arbitrum One — they pay for the storage itself.
  2. A little ETH on Arbitrum One — it pays the gas for the payment transaction.

Acquire ANT on Arbitrum One and send it to the address above, then bridge or buy a small amount of Arbitrum One ETH for gas. Real funds move on this network, and a seal is permanent and paid once.
```

(`crates/antseal-cli/src/init.rs:278-295` — quoted word for word.)

Three things that sentence packs in tightly:

- **The chain matters more than the token.** ANT held on any other chain
  cannot pay for a seal. antseal bridges nothing and swaps nothing; moving
  funds to Arbitrum One is entirely your own step, done before you seal.
- **Gas is the smaller half, and ETH is the easier half.** Most people already
  have a route to Arbitrum One ETH — bridge it from Ethereum mainnet, or buy
  it directly on Arbitrum One. ANT usually has to be acquired deliberately.
- **Send ANT to the address `init` printed**, not to an exchange account you
  control by other means. Only the vault's own key can spend it.

Check you are sending the right token: the payment token antseal uses on
Arbitrum One is `0xa78d8321B20c4Ef90eCd72f2588AA985A4BDb684`
(`crates/antseal-net/src/network.rs:66`). A same-named token at a different
address is a different token and will not pay for anything.

Keep the balance small and fund close to when you seal. A funding transfer is
public and permanent, and it links this wallet to wherever the funds came
from — that chain of inference is `wallet-hygiene.md`'s subject, and it is
worth reading before your first mainnet transfer rather than after.

## What a seal actually costs

**Nobody has measured this on Arbitrum One yet, and this page will not invent
a number.** No ANT storage price from mainnet or from Arbitrum Sepolia is
recorded anywhere in this project. The only way to get a real figure is to ask
the network for one, which is what `--dry-run` does.

What *has* been measured, so you know the shape of the bill:

- **Storage, on a local devnet.** Two end-to-end runs against live nodes
  quoted exactly 11 718 750 000 000 000 atto-ANT (0.01171875 ANT) per blob —
  82 031 250 000 000 000 atto-ANT for 7 blobs and 58 593 750 000 000 000 for 5
  (`TODO.md:363`, `tasks/S.md:277`). Those nodes were running on one laptop
  and set their own prices. **Read this as arithmetic that works, not as a
  price**: Arbitrum One's price is set by the real network's peers and is
  unrelated.
- **Gas.** antseal does not ask the chain to estimate gas at quote time — the
  call reverts before the token allowance exists — so it uses a static model
  built from costs measured on a local chain: 140 000 gas for the one `approve`
  transaction, 300 000 per payment transaction plus 220 000 per transfer, all
  deliberately 3–9x above what was measured, so the estimate stays above the
  real bill when the basefee moves
  (`crates/antseal-net/src/ant_backend.rs:108-129`).

Two rules of thumb that follow from how the payment is built:

- **You pay per blob, not per file.** A blob is every encrypted unit plus the
  encrypted manifest (`crates/antseal-cli/src/seal_consent.rs:140-142`), so a
  work split into many units has more blobs to pay for than the same work
  sealed whole. How much more depends on what the network's peers charge;
  `--dry-run` prints both the blob count and the total.
- **Gas grows with blobs too, but in one transaction, not many.** The estimate
  has a per-transfer term, and up to 256 transfers ride a single payment
  transaction (`crates/antseal-net/src/ant_backend.rs:293-296`), so you pay one
  transaction's fixed overhead rather than one per blob.

## The two funding failures, told apart

They are separate errors on purpose, because the remedies are different:
acquire ANT, versus top up ETH. They stay distinct all the way to the exit
code.

**Not enough ANT** — class `insufficient-ant-token`, exit code **20**:

```
insufficient ANT for this seal: the quote needs <required> atto-ANT but the wallet holds <available>; fund the wallet with ANT and re-run (nothing was paid or uploaded)
```

**Not enough ETH for gas** — class `insufficient-eth-gas`, exit code **21**:

```
insufficient ETH for gas: the payment transaction needs about <required> wei but the wallet holds <available>; fund the wallet with ETH for gas and re-run (nothing was paid or uploaded)
```

(`crates/antseal-cli/src/error.rs:611-631`; the exact rendering is frozen in
`crates/antseal-cli/tests/snapshots/cli-errors.display.txt:45-48`. Under
`--json` the same text arrives as the `message` field beside `class` and
`exit_code`.)

Three things to know about them:

- **Both numbers are in the message.** You are told what the quote needed and
  what the wallet held, so the shortfall is a subtraction, not a guess.
- **ANT is checked first.** If you are short on both, you are told about ANT
  and nothing else; fix that, re-run, and the gas shortfall appears next
  (`crates/antseal-net/src/backend.rs:61-63`, `:89-100`).
- **Nothing was spent.** The check runs before any transaction is signed, and
  runs again inside the payment path before money moves
  (`crates/antseal-net/src/ant_backend.rs:652-655`). Re-running after you fund
  the wallet is safe and costs nothing extra.

If you built antseal yourself, note that a default build has no storage
backend compiled in and `seal` refuses at the seam with a network error rather
than ever reaching a balance check. Release binaries are built with the
backend; a build from source needs `--features ant-backend`
(`crates/antseal-cli/Cargo.toml:49`,
`docs/decisions/D72-release-targets-distribution-and-crates-io-scope.md:493`).

## Development networks

Nothing on either of these has value, and neither produces evidence you should
rely on. Use them to rehearse.

### Arbitrum Sepolia — chain 421614, **not** Ethereum Sepolia

`--network arbitrum-sepolia`. `init` prints:

```
To seal, this address needs two things:
  1. Test-ANT on Arbitrum Sepolia (chain 421614).
  2. Arbitrum Sepolia ETH for gas.

This is Arbitrum Sepolia, NOT Ethereum Sepolia (11155111): ETH and contracts from Ethereum Sepolia are useless here. Use an Arbitrum Sepolia gas faucet, or bridge Sepolia ETH to Arbitrum Sepolia; test-ANT comes from the project's Sepolia runbook (docs/, D38). Nothing here has value.
```

(`crates/antseal-cli/src/init.rs:298-307` — quoted word for word.)

This is the mistake to expect. Most faucet pages offer both Sepolias one
dropdown apart, and picking the wrong one gives you ETH that cannot pay for
anything here. Confirm the network selector says Arbitrum Sepolia.

The runbook `init` refers to is `docs/devnet/sepolia-devnet.md`; the decision
behind it is `docs/decisions/D38-sepolia-test-ant-acquisition.md`. The part
worth knowing before you start: **there is no faucet for test-ANT and there
cannot be one.** The deployed token has no mint function at all, so the only
way to get some is an ordinary ERC-20 transfer from somebody who already holds
it — in practice, an ask to the Autonomi team or community. Gas has ordinary
public faucets; the token does not.

You can confirm both halves landed without sealing anything:

```
scripts/devnet/sepolia-preflight --address 0xYOURADDRESS
```

Exit 0 means the chain and contracts are good, 3 means the chain is fine but
the wallet is not funded (`docs/devnet/sepolia-devnet.md:81-82`).

### Local devnet

`--network devnet`. `init` prints:

```
To seal, this address needs two things:
  1. Devnet ANT — minted by the local devnet's own deployment.
  2. Devnet ETH for gas — Anvil pre-funds its accounts.

On the local devnet there is no faucet and no funding step for the built-in accounts: `scripts/devnet/local-up` starts Anvil with pre-funded well-known keys and exports one in `.devnet/`. To pay from THIS address instead, send devnet ANT and ETH to it from that account. Nothing here has value, and the chain is discarded when the devnet stops.
```

(`crates/antseal-cli/src/init.rs:310-320` — quoted word for word.)

Funding here is a non-event: the exported account holds both assets from block
zero. Setup is `docs/devnet/local-devnet.md`.

## What paying does not buy

Paying is what makes the storage permanent. It is not what makes the seal
evidence, and it does not add a proven time.

- **The payment receipt is not a timestamp.** antseal records it, and it is
  labelled for what it is:
  `supporting evidence — no independently proven time`
  Proven time comes from the timestamp anchors, never from the chain that took
  your money.
- **The spend is permanent and one-way.** There is no refund, no deletion, and
  no way to unpublish an encrypted blob once it is stored. `seal` warns you
  about this at the consent screen, before it asks.
- **The transfer is public.** Funding this wallet, and later paying from it,
  are both visible on Arbitrum One forever. What that reveals, and how to keep
  works from being linked to each other through it, is `wallet-hygiene.md`.

A seal proves that the holder of this vault possessed the content by the
anchored time. Funding a wallet is a prerequisite for making that record; it
is not itself a claim about anything.
