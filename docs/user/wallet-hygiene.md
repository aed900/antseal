# Wallet hygiene

Every seal is paid for from one Arbitrum address, and that payment is public
and permanent. This page is about what that address ties together, who can
follow the trail, and what it costs you to keep two pieces of work apart.

It is written for someone deciding whether the convenience of one wallet is
worth the exposure. That decision genuinely differs between a person sealing
their own drafts and a person sealing work for three clients who must not
learn about each other, so this page gives you the chain, the cost and the
choice rather than a rule.

Two limits first, because everything below assumes them.

> a seal proves the holder of the sealing key possessed this content by the proven time — not authorship, and not exclusive possession

That sentence is the product's frozen wording
(`crates/antseal-core/tests/snapshots/verdict-wording.txt:6`). What antseal
proves is existence, integrity and priority, and the priority it proves runs
only against *later* evidence — an earlier seal by someone who received your
work outranks yours. **Seal before you share.** It is not a legal notary, and
nothing on this page is advice about identity, tax or reporting obligations.

---

## 1. The chain, link by link

Linkage is not one fact. It is four separate steps, and they break in
different places for different reasons.

| # | The step | What creates it | Who can follow it |
| --- | --- | --- | --- |
| 1 | A bundle names a payment transaction | `reveal --include-receipt`, which is **off by default** | anyone you show the bundle to, forever |
| 2 | A transaction names the address that sent it | Arbitrum One is a public chain | anyone, on any block explorer, with no permission from you |
| 3 | An address names where its funds came from | the transfer that funded it, which is itself on the chain | anyone, on any block explorer |
| 4 | A funding route names a person | the exchange's own account records | the exchange, and whoever can compel or breach it |

**Only step 1 is antseal's to control, and antseal defaults it off.** Steps 2
to 4 are properties of a public chain and of how you obtained funds; no
setting in this tool touches them. That is the honest shape of the problem:
the software can withhold the pointer, and after that the work is yours.

Two directions matter, and people usually think of only one.

- **Forwards** — someone holding one receipt-bearing bundle learns the paying
  address, and from there can enumerate *every other seal that address ever
  paid for*. They do not need your other bundles to do it; the payments are
  on the chain whether or not anyone ever reveals the works.
- **Backwards** — someone who already knows your address, because you once
  received a payment at it or published it, recognises it the moment it
  appears in a bundle.

The first is why the receipt is opt-in. The second is why an address you use
for anything else should never be the address a vault pays from.

## 2. What the chain shows before any bundle exists

A seal's whole public footprint is one ERC-20 `approve` followed by one
`payForQuotes` call in the common case — up to 256 blob payments ride a
single transaction (`crates/antseal-net/src/ant_backend.rs:36-40`,
`:674-691`).

**Nothing in that calldata says "antseal".** The payment struct is Autonomi's
own three fields — the storage node's rewards address, an amount, and a quote
hash. There is no memo, no tag, not one antseal-authored byte, and antseal
deploys no contract of its own on any network
(`docs/decisions/D73-external-completions-without-telemetry.md:308-312`). An
observer watching those payments sees an Autonomi user, not an antseal user.

**The allowance is a different story, and this page records it without
settling it.** Before paying, antseal approves the payment contract to spend
**exactly the quoted total**, never an unlimited amount
(`crates/antseal-net/src/ant_backend.rs:437-455`). Upstream Autonomi clients
approve `U256::MAX` — unlimited — at the same point in the flow
(`evmlib-0.9.0/src/wallet.rs:421`; `ant-core-0.5.0/src/data/client/payment.rs:130`
documents *"Approves `U256::MAX` (unlimited) spending."*).

Both clients skip the approval when the standing allowance already covers the
bill (antseal at `crates/antseal-net/src/ant_backend.rs:446-448`, upstream at
`evmlib-0.9.0/src/wallet.rs:415`), so the shapes differ only in the amount —
but that difference decides how often the step happens. An unlimited
allowance is approved once and covers every later payment. An exact allowance
is consumed by the very payment it was raised for, so the next seal raises
another one. Both the calldata and the ERC-20 `Approval` log are public and
permanent.

The consequence, stated plainly and not softened: **an address that emits a
fresh, non-round approval before essentially every payment is separable from
the general population of Autonomi payers.** So the honest answer to "what
does someone with no bundle at all learn?" is: that this address is running
antseal, or a tool with identical habits. Not who you are — but enough to
narrow a search to a much smaller set of addresses than "everyone using
Autonomi".

This is a deliberate trade and it is genuinely unresolved. The exact
allowance was chosen **for** wallet hygiene — it leaves no standing unlimited
permission against your funds, so a future contract compromise cannot drain
an allowance you forgot you had granted. It also makes your payments easier
to pick out of a crowd. The three options are unlimited (costs a standing
allowance), exact (costs some anonymity) and rounded-up (might cost neither,
and nobody has measured it). **Row `Q240` owns that choice; neither this page
nor the threat model has made it**, and you should not read the description
above as a recommendation either way.

What this means for you today is small but real: if the size of the anonymity
set is what you are relying on, do not rely on it. Rely on the address being
fresh and its funding being unlinked, which are things you control.

## 3. What `--include-receipt` adds

`antseal reveal` takes an opt-in flag:

```
      --include-receipt
          Include the Arbitrum payment receipt in the bundle (off by default — it exposes the paying wallet)
```

(`crates/antseal-cli/tests/snapshots/cli-surface.help.txt:285-286`; the flag
is defined at `crates/antseal-cli/src/cli.rs:374-377`.)

**The default is off and there is no configuration that changes it.** It is a
plain boolean with no default value written anywhere and no config key behind
it, so there is no line for a future edit to get wrong; the reveal pipeline
gathers the receipt inside a single `if`
(`crates/antseal-cli/src/pipeline/reveal.rs:653-657`). At bundle level the
section's *presence is the choice* — a verifier is told to read nothing into
its absence (`crates/antseal-core/src/bundle/schema.rs:727-732`).

When you do pass it, the reveal confirmation screen says so before it asks:

```
  WARNING: --include-receipt puts the Arbitrum payment receipt in this bundle. It names the wallet that paid for this seal, and it links this work to every other seal that wallet ever paid for — to everyone who is shown the bundle, permanently. Leave it out unless a recipient specifically needs it.
```

(`crates/antseal-cli/src/reveal_consent.rs:131-134`, rendered in
`crates/antseal-cli/tests/snapshots/reveal-consent.txt:50`.) The warning
appears only when the receipt will actually ride in the bundle, so it never
warns about an exposure that is not happening.

What ships is the **whole journaled receipt**, not a summary. On the wire it
is the transaction hashes, the block number, and an opaque payload
(`crates/antseal-core/src/bundle/schema.rs:738-741`) that carries the entire
recorded receipt (`crates/antseal-cli/src/pipeline/receipt_sink.rs:79-82`).
So, concretely, opting in discloses:

- **The transaction hashes.** This is the link that matters. No field of the
  receipt contains your address, but a transaction hash resolves on any
  public explorer to the address that sent it, and from there to every other
  payment that address made.
- **Which storage nodes were paid**, by their rewards addresses, and which
  peers quoted for your blobs.
- **The exact amounts**, and therefore a good estimate of how large the work
  was — a size signal on top of the identity one.

Two things it does **not** disclose, both checked rather than incidental:

- **No chain identifier.** The wire record has exactly three fields —
  transaction hashes, a block number and the opaque payload
  (`crates/antseal-core/src/bundle/schema.rs:738-741`) — so which chain this
  was is the verifier's pinned setting, never something the bundle asserts.
- **No time of any kind** — not the block as a time, not a transaction
  timestamp (`crates/antseal-cli/src/status.rs:217-219`).

Two smaller behaviours worth knowing before you reach for the flag:

- **A work with no recorded payment refuses.** `--include-receipt` on such a
  work is a hard error — *"no payment receipt is recorded for this work"*
  (`crates/antseal-cli/src/pipeline/reveal.rs:948-950`) — rather than a
  bundle that quietly omits it.
- **The decision is per reveal, not per work.** You can reveal the same work
  twice, once with the receipt for a counterparty who needs it and once
  without for everyone else. What you cannot do is take it back out of a
  bundle you have already sent.

## 4. What a bundle does **not** link, by default

This is the good news, and it is worth knowing precisely, because it tells
you what a fresh address actually buys.

**The signing key in a bundle is per work, not per vault.** Each work gets
its own 32-byte master secret drawn from the system random source
(`crates/antseal-core/src/crypto/secrets.rs:43`), and the manifest's signing
keys are expanded from it — *"per-work by construction: the seed derives from
that work's `W`"* (`crates/antseal-core/src/crypto/sig_ed25519.rs:252`). Two
bundles from one vault therefore carry two unrelated public keys. There is no
"this is the same sealer" marker in the format.

**The storage addresses cannot be matched to a payment without the receipt.**
A payment names each blob by a *quote hash*, and that hash is taken over the
blob's address **plus** the quoting node's own local timestamp, its price,
its rewards address, its public key and its signature
(`evmlib-0.9.0/src/data_payments.rs:130-134`, `:146-170`). None of those extra
values is in a bundle. So someone holding a default bundle cannot recompute a
quote hash from the addresses they can see, and cannot search the chain for
your payment. This is exactly why the opt-in receipt carries the quote
preimages: they are the missing piece, and shipping them is what makes the
chain followable.

**One real exception, and it has nothing to do with the receipt.** The nodes
that store your chunks are handed the payment transaction hashes at upload
time, as part of the proof of payment
(`ant-protocol-2.3.0/src/payment/proof.rs:19-22`). A storage node that keeps
what it was given already knows which address paid for the chunk it holds.
Leaving the receipt out hides your wallet from the people you show bundles
to; it does not hide it from the network you uploaded to. Nothing you can
configure changes that, and it is a reason to treat the address as
semi-public from its first seal rather than to treat any single reveal as the
moment of exposure.

## 5. One vault pays with one address — and that is the whole affordance

**There is no per-work address support in this tool, and this page is not
going to imply otherwise.** Measured on the frozen CLI surface:

- The wallet record inside a vault is a **singleton** by construction — the
  identity it is stored under carries no discriminant, where a per-work
  record such as a receipt carries a seal id
  (`crates/antseal-cli/src/vault/cipher.rs:100-118`). One vault, one key,
  one address, for every work it will ever hold.
- The **only** wallet flags in the whole CLI belong to `antseal init`:
  `--wallet generate|import` and `--wallet-key-fd`
  (`crates/antseal-cli/tests/snapshots/cli-surface.help.txt:52-65`).
  `seal` has no wallet or address flag at all.
- There is **no rotate command and no new-address command**. The nine
  subcommands are `init`, `seal`, `list`, `show`, `status`, `restore`,
  `reveal`, `verify` and `vault`
  (`crates/antseal-cli/tests/snapshots/cli-surface.help.txt:7-15`).
- The config file holds operator preferences only — *"never secrets, never
  per-work"* (`crates/antseal-cli/src/config.rs:8`) — so no address can be
  named there either.
- `antseal init` will not run twice in one place. A vault already at the
  target path is an absolute refusal with no `--force`, because overwriting
  one destroys the reveal and restore keys of every work it holds
  (`crates/antseal-cli/src/init.rs:585-596`,
  `crates/antseal-cli/src/vault/session.rs:225-232`).

So the fresh-address recommendation has exactly one mechanism behind it: **a
separate vault per address**, selected by the `ANTSEAL_DIR` environment
variable, which is used verbatim when set and otherwise defaults to
`~/.antseal` (`crates/antseal-cli/src/vault/layout.rs:16`, `:75-86`).

```
ANTSEAL_DIR=~/.antseal-clientA antseal init
ANTSEAL_DIR=~/.antseal-clientA antseal seal ./deliverable.pdf --title "..."
ANTSEAL_DIR=~/.antseal-clientA antseal reveal <work-id> --all -o proof.sealproof
```

`ANTSEAL_DIR` is a **path, never a secret**, so putting it in a shell alias
or a per-project environment file is fine. Get it wrong on one command and
you are talking to the wrong vault, which will simply not find the work.

That is a vault-per-address workaround, not per-work address support. It
works, and you should know its price before adopting it.

## 6. What a second vault actually costs

Everything below is a cost you pay per vault, not per work.

- **A second passphrase, and a second thing you can permanently lose.** Each
  vault has its own key material and its own backup obligation; losing a
  vault and its export means losing the ability to reveal or restore every
  work in it, forever. See `vault-loss.md` and `vault-theft.md` — those costs
  do not merge when you split the vault, they multiply.
- **A second funding transfer, which is itself a public event.** Section 7 is
  about getting this part right; it is the part most likely to undo the
  benefit.
- **Pending timestamp upgrades stop happening for vaults you stop using.**
  Every antseal command opportunistically completes pending OpenTimestamps
  attestations, but only for the vault that invocation unlocked — an
  invocation holding no unlocked vault does nothing
  (`crates/antseal-cli/src/upgrade_hook.rs:87-92`). A vault you have not
  touched in a month has not upgraded anything in a month. Run
  `ANTSEAL_DIR=… antseal status <work-id> --upgrade` on each one, or accept
  that its bundles reveal with a `pending` anchor.
- **`list` shows one vault at a time.** There is no cross-vault view, no
  aggregate cost report, and nothing that will remind you a vault exists.
  Keep your own note of which directory holds which client's work.

And here is what it does **not** cost, which is the part that makes the
practice practical:

- **Nothing about verification changes.** `verify` needs no vault and never
  prompts (`crates/antseal-cli/tests/snapshots/cli-surface.help.txt:14`), so
  the person you send a bundle to is unaffected by how many vaults you keep.
- **No evidence is weakened.** Timestamp anchors are per seal and are
  fetched over HTTP from timestamp authorities and calendars; they know
  nothing about your wallet and cost no ANT
  (`docs/decisions/D36-prepay-resume-requote-reconsent.md:250-252`).
- **No work becomes harder to find.** Work ids are unchanged, bundles are
  unchanged, and a bundle stays self-contained regardless of which vault
  produced it.

## 7. A fresh address is only fresh if its funding is too

This is where the practice is most often wasted, and it is worth being blunt
about it.

Funding a new address **from your old one** links the two immediately and
permanently, in a single public transaction. So does funding both from the
same exchange withdrawal address, which is the more common mistake, because
it feels like two separate acts and is not: the exchange's withdrawal address
is right there in both funding transactions, and anyone can see them side by
side.

What actually keeps two addresses apart:

- **Fund each one independently, from its own source**, and treat "which
  account paid for this" as part of the separation rather than an
  afterthought.
- **Do not sweep leftovers between them.** A dust transfer at the end of a
  project undoes everything the separation bought. Fund close to when you
  seal and keep balances small — `antseal seal --dry-run` will tell you what
  a work costs before you move anything.
- **Never import the same key into two vaults.** `init --wallet import`
  exists for bringing your own key material in
  (`crates/antseal-cli/src/init.rs:497-513`), and using it twice with one key
  produces two vaults with one address, which is the appearance of hygiene
  with none of the substance.

`funding-your-wallet.md` covers how an address gets ANT and ETH in the first
place. Read it before your first mainnet transfer rather than after — the
funding step is where step 4 of section 1's chain is usually created, and it
cannot be undone afterwards.

## 8. Is it worth it? A rough answer

**For most people, keeping the receipt out is free and keeping one vault is
fine.** The receipt is off by default, a default bundle carries no cross-work
link (§4), and one address that was funded once and is used for nothing else
exposes very little. Splitting vaults costs you real effort and gains you
little if nobody is trying to correlate your works.

**Split when the works must not know about each other.** Client work is the
clear case: three clients, three vaults, three separately funded addresses.
So is any situation where one work is already public and another must not be
traceable to the same person — the linkage runs through the address, so one
public seal contaminates every other seal that address paid for.

**Opt into the receipt only for a specific counterparty who asked for it.**
What it buys today is one line in the verifier's output, and that line is
explicit about its own weakness:

```
receipt: supporting evidence — no independently proven time
```

(`crates/antseal-core/src/verify/wording.rs:392`, frozen at
`crates/antseal-core/tests/snapshots/verdict-wording.txt:74`.) The receipt is
never an anchor and never supplies the headline time; its result type carries
no time field and no state field at all
(`crates/antseal-core/src/verify/report.rs:743-757`). The defensible reason
to include it is forward-looking: a fuller receipt-verification chain is
specced for a later version, capture is already complete, and a counterparty
who will one day run that check needs the receipt to have been in the bundle
from the start. That is a considered choice for one recipient, not a default.

**The project will never ask you for a receipt-bearing bundle.** That is a
standing prohibition on the project itself, not a courtesy
(`docs/decisions/D73-external-completions-without-telemetry.md:664-672`); a
bundle that arrives with one anyway is not read, not recorded and never
quoted. If anything claiming to be antseal asks you to include a receipt,
that is reason enough to refuse.

---

## Where the evidence for this page lives

Nothing above is asserted from memory. The primary sources:

| claim | source |
| --- | --- |
| the flag, its help text and its default | `crates/antseal-cli/src/cli.rs:374-377`; `crates/antseal-cli/tests/snapshots/cli-surface.help.txt:285-286` |
| the include branch and the missing-receipt refusal | `crates/antseal-cli/src/pipeline/reveal.rs:653-657`, `:948-950` |
| presence in the bundle is the opt-in | `crates/antseal-core/src/bundle/schema.rs:727-741` |
| the whole journaled receipt is what ships | `crates/antseal-cli/src/pipeline/receipt_sink.rs:79-82` |
| receipts are wallet-linkable, so they never reach a log | `crates/antseal-net/src/receipt.rs:155-158` |
| the consent-screen warning, as rendered | `crates/antseal-cli/src/reveal_consent.rs:131-134`; `crates/antseal-cli/tests/snapshots/reveal-consent.txt:50` |
| the default is proven against produced bundle bytes | `crates/antseal-cli/tests/reveal_flow.rs:585-628`; `crates/antseal-cli/tests/reveal_output.rs:438-479` |
| one payment call, up to 256 blobs | `crates/antseal-net/src/ant_backend.rs:36-40`, `:674-691` |
| the exact-allowance approve, and upstream's unlimited one | `crates/antseal-net/src/ant_backend.rs:437-455`; `evmlib-0.9.0/src/wallet.rs:415`, `:421`; `ant-core-0.5.0/src/data/client/payment.rs:130` |
| the allowance question is open and owned | row `Q240`; `docs/decisions/D73-external-completions-without-telemetry.md:743-750`; `docs/threat-model.md` §2.3 |
| the signing key is per work | `crates/antseal-core/src/crypto/secrets.rs:43`; `crates/antseal-core/src/crypto/sig_ed25519.rs:252` |
| a quote hash needs more than the blob address | `evmlib-0.9.0/src/data_payments.rs:130-134`, `:146-170` |
| storage nodes receive the payment transaction hashes | `ant-protocol-2.3.0/src/payment/proof.rs:19-22` |
| one vault has exactly one wallet record | `crates/antseal-cli/src/vault/cipher.rs:100-118` |
| the only wallet flags, and the nine subcommands | `crates/antseal-cli/tests/snapshots/cli-surface.help.txt:7-15`, `:52-65` |
| config holds no wallet and no per-work data | `crates/antseal-cli/src/config.rs:8` |
| `init` refuses an existing vault, with no override | `crates/antseal-cli/src/init.rs:585-596`; `crates/antseal-cli/src/vault/session.rs:225-232` |
| `ANTSEAL_DIR` is a path, never a secret | `crates/antseal-cli/src/vault/layout.rs:16`, `:75-86` |
| the upgrade hook runs only for the unlocked vault | `crates/antseal-cli/src/upgrade_hook.rs:87-92` |
| the receipt's class, and that it carries no time | `crates/antseal-core/src/verify/wording.rs:392`; `crates/antseal-core/src/verify/report.rs:743-757` |
| the project may never request a receipt-bearing bundle | `docs/decisions/D73-external-completions-without-telemetry.md:664-672` |

The engineering analysis this page is written from is `docs/threat-model.md`
§2.3; the funding side of the chain is `docs/user/funding-your-wallet.md`.
