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
(`crates/antseal-cli/src/init.rs:271-276`).

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
Run every free step and print the plan + quote (true pricing mechanism, indicative figure); nothing is paid, anchored, or uploaded (D49)
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

The help's *true pricing mechanism, indicative figure* is the whole contract:
the quote comes from the network itself rather than an offline estimate, and
it is still not a locked-in price. The report labels the figure
**indicative**, and that is the honest word: a real seal draws fresh nonces,
so it encrypts to different addresses and re-quotes at a later moment
(`crates/antseal-cli/src/seal_run.rs:284-289`;
`docs/decisions/D49-dry-run-network-semantics.md:110-116`). Treat it as the
right order of magnitude.

`--dry-run` also exits with the same shortfall codes a real seal would, so it
works as a scripted check for "could this machine seal this work right now"
(`docs/decisions/D49-dry-run-network-semantics.md:98-105`).

When a dry run finds you short it prints the whole report first and then
refuses, exactly as a real `seal` does — the file list, the quote, both
balances, and a `** SHORT by <N> **` marker beside every asset you are
short of. The exit code says which remedy you need (20 = acquire ANT,
21 = bridge ETH) and the typed error repeats the figures for the first one
(`crates/antseal-cli/src/seal_run.rs`, the `DryRun` arm;
`docs/decisions/D146-dry-run-shortfall-screen.md`).

Under `--json`, that report goes to stderr and stdout carries one error
envelope with `ok: false` and the class — there is **no** `result` document
on the shortfall path, so gate a script on the exit code and on
`error.class`, never on the presence of `result`.

## What this address's key can and cannot do

`init` says this once, next to the address:

    No antseal command displays this address's key, and nothing moves its balance to another wallet: antseal can only spend it on seals. If antseal generated the key, your vault backup is the only copy of it there will ever be. Fund this address like a prepaid meter, not a savings account.

(That is the constant `WALLET_CUSTODY_NOTE` in
`crates/antseal-cli/src/init.rs`, quoted word for word; a test asserts this page
still carries it.)

Unpacked:

- **The key is made inside the vault, and antseal has no command that shows
  it.** `--wallet` defaults to `generate`
  (`crates/antseal-cli/src/cli.rs:193`), and a generated key goes straight into
  the vault's wallet record: `init` keeps the checksummed address and drops the
  key (`crates/antseal-cli/src/init.rs:539-541`). None of the nine subcommands
  prints, exports or rotates it.
- **You can keep spending it; you cannot move it.** A vault backup carries the
  key, and `vault import` reinstalls it
  (`crates/antseal-cli/src/vault/export.rs:1104-1106`), so a restored vault pays
  exactly as the original did. What no antseal command will ever do is hand you
  the key to sweep the balance into a wallet you hold elsewhere.
- **If you imported your own key, none of this binds you.** You still hold it
  outside antseal and can spend or sweep that address from any Arbitrum wallet.
- **This only works in advance.** Nothing here is a step you can take after a
  laptop is stolen or a vault is lost. It is a decision about how much to send,
  taken before you send it — `vault-theft.md` and `vault-loss.md` are what is
  left afterwards.

## Arbitrum One — real funds

This is the default network (`--network arbitrum-one`, chain **42161**,
`crates/antseal-net/src/network.rs:52`). `init` prints:

```
To seal, this address needs two things:
  1. ANT tokens on Arbitrum One — they pay for the storage itself.
  2. A little ETH on Arbitrum One — it pays the gas for the payment transaction.

Acquire ANT on Arbitrum One and send it to the address above, then bridge or buy a small amount of Arbitrum One ETH for gas. Real funds move on this network, and a seal is permanent and paid once.
```

(`crates/antseal-cli/src/init.rs:279-294` — quoted word for word.)

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

Keep the balance small and fund close to when you seal — for two independent
reasons. A funding transfer is public and permanent, and it links this wallet to
wherever the funds came from; that chain of inference is `wallet-hygiene.md`'s
subject, and it is worth reading before your first mainnet transfer rather than
after. And whatever sits at this address when the vault is lost or stolen is
bounded by what you put there, because nothing moves it out — see "What this
address's key can and cannot do" above.

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

(`crates/antseal-cli/src/error.rs:646-666`; the exact rendering is frozen in
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

## The two failures where money *was* spent

"Nothing was spent" above is true of exit codes **20** and **21**, because both
are checked before any transaction is signed. **Do not generalise it to every
payment error.** Two codes mean the opposite, and they are separate classes
precisely so that a script cannot mistake them for a transient failure worth
retrying blindly.

**Payment stranded mid-sequence** — class `payment-stranded`, exit code **28**:

```
payment stranded mid-sequence: <N> sub-batch transaction(s) landed before the failure and the journaled partial receipt is authoritative — this is not a transient network failure and money has already moved: re-run `antseal seal` with the same files and the same seal-shaping flags to finish it, which re-pays no quote the receipt already maps; `antseal list` prints the exact command (<detail>)
```

**Payment proofs expired** — class `payment-proofs-expired`, exit code **29**:

```
this seal's payment proofs have expired (the ~24 h node-side window has passed), so the storers reject them: completing it requires a new, separately consented payment — the already-spent ANT is not recoverable
```

(`crates/antseal-cli/src/error.rs:681-697` and `:699-707`; the exact rendering
is frozen in `crates/antseal-cli/tests/snapshots/cli-errors.display.txt:89-90`
and `:91-92`.)

What each one asks of you:

- **28 is finishable, and re-running is how you finish it.** The sub-batch
  transactions that landed are journaled and the partial receipt is
  authoritative, so completing the seal re-pays no quote that receipt already
  maps. **There is no `antseal resume` command** — re-running `antseal seal`
  with the same files and the same seal-shaping flags *is* the resume, and
  `antseal list` prints the exact command that finishes it. What you must not
  do is retry it as you would a network timeout, with a changed path list or
  changed shaping flags: that starts a new seal and pays a second quote.
- **29 costs a second payment, and the first one is gone.** The payment proofs
  have a node-side window of roughly 24 hours; once it passes the storers
  reject them, and no re-run recovers the ANT already spent. Finishing the work
  means a new payment, separately quoted and separately consented.
- **Branch on the code, never on "something failed".** A caller that treats
  every non-zero exit as retryable is the failure these two classes exist to
  prevent. Use the exit code, or `error.class` under `--json`.

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

(`crates/antseal-cli/src/init.rs:299-308` — quoted word for word.)

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

(`crates/antseal-cli/src/init.rs:311-321` — quoted word for word.)

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
