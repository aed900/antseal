# Vault theft

This is the worst thing that can happen to an antseal user, and it is worth
being blunt about why.

Autonomi storage is **pay-once and permanent**. Every ciphertext antseal has
ever uploaded for you is still out there and always will be. Nothing is
deletable, nothing expires, and confidentiality rests entirely on one
passphrase. So somebody who takes your vault today and breaks the passphrase in
five years decrypts everything you sealed *before* today. There is no expiry, no
re-key, and nothing to revoke.

That is not a warning about a future weakness. It is the shape of the system,
and every decision on this page follows from it.

## The warning antseal already gave you

`antseal init` prints this before you seal anything, and the first seal in a
vault with no recorded backup prints it again:

```
  THEFT — whoever holds this vault (or an export) and the passphrase can decrypt every work you have ever sealed, retroactively and permanently. The ciphertexts are public and undeletable, and there is no key rotation. Treat the passphrase as a long-term, high-value key.
```

That is not a paraphrase. It is the constant `THEFT_WARNING`
(`crates/antseal-cli/src/vault/bookkeeping.rs:74-77`), quoted byte for byte, and
it is the same string `init` renders
(`crates/antseal-cli/src/init.rs:337-342`) and the same string the first-seal
export nag carries (`crates/antseal-cli/src/vault/bookkeeping.rs:264`). One
author for all three, so a sentence you met at `init` is recognisable here
rather than being a second phrasing of the same risk. `MVP-SPEC.md` line 143
requires both the CLI and these docs to state it.

The same sentence is written where a maintainer meets it too, not only where a
user does (`crates/antseal-core/src/crypto/secrets.rs:47-49`).

## Two secrets, and what each one opens

Your vault holds one 32-byte master secret `W` **per work**
(`crates/antseal-cli/src/vault/store.rs:198-201`). Every key, salt and seed a
work will ever use derives from its `W` through a labelled HKDF registry
(`crates/antseal-core/src/crypto/hkdf.rs:137-146`). So the unit of theft is the
vault, and the blast radius is every work inside it.

| What an attacker takes | What it opens |
| --- | --- |
| one work's `W` | every unit key and manifest key, every salt and range seed, and therefore every uploaded ciphertext of that work — plus both signing seeds, so new manifests can be produced under that work's identity |
| the whole vault | the above for **every** work, plus `config.toml`, the seal journal, payment receipts, `.ots` and TSA tokens, storage addresses, your original file paths and what each seal cost |
| a `vault export` file | exactly the same payload again — one file, protected by the passphrase alone (`crates/antseal-cli/src/vault/export.rs:99-100`) |

Read the third row twice. **An export is not a lesser artifact than the vault.
It is a second complete copy of it**, in a single portable file, encrypted under
nothing but your passphrase. `vault export` says so itself when it finishes
(`crates/antseal-cli/src/commands.rs:819-822`):

```
Treat this file like the vault itself: whoever holds it and the passphrase holds the keys to every sealed work, forever.
```

The Arbitrum wallet key sits beside all of this. It has its own sub-key
(`crates/antseal-cli/src/vault/wallet.rs:9-12`), which decouples it from a
compromise of some *other* record's key — it does not decouple it from the
passphrase. Break the passphrase and you derive the vault key and therefore the
sub-key. What the wallet then discloses about you is `wallet-hygiene.md`'s
subject.

## There is no rotation. This was measured, not assumed

There is no command to change a passphrase, re-key a vault, or re-encrypt what
is already uploaded. The frozen command surface has nine commands and none of
them is `rotate`, `passwd` or `change-passphrase`
(`crates/antseal-cli/tests/snapshots/cli-surface.help.txt:7-15`).

The one re-encryption that exists is `vault import`, and it is worth
understanding exactly what it does *not* do: it builds a **new** vault with a
fresh salt and a fresh vault key, and re-encrypts every *local* record under it
(`crates/antseal-cli/src/vault/export.rs:130-131`). It never touches `W`, and
nothing can touch what is already stored on the network. Re-importing after a
suspected theft changes the local file bytes and changes nothing an attacker
who already copied your vault can do.

There is no escrow either: antseal is not a notary service, and there is nobody
holding a second copy of your keys. That is what non-custodial means, and it is
the same property that makes loss unrecoverable — see `vault-loss.md`.

**So the only defence is the passphrase, and the only time to choose it well is
before the first seal.**

## The passphrase floor is a floor, not advice

`init` enforces a minimum of **12 bytes** at vault creation
(`crates/antseal-cli/src/passphrase.rs:87`, enforced at `:238`), on both the
interactive prompt and the `--passphrase-fd` channel. Below it you get a `usage`
error that says why:

```
the passphrase is shorter than the 12-byte minimum (bytes, not characters); this vault's contents are permanent, public ciphertexts once sealed — pick a long passphrase you can keep forever
```

Four things that floor deliberately does not claim:

- **It is length only, in bytes.** No dictionary check, no entropy estimate, no
  score. The measure is exactly what the key-derivation function sees, and a
  multi-byte character counts by its encoded length. That was a recorded choice
  over a zxcvbn-class estimator: a number users game, in exchange for a new
  dependency and locale-sensitive judgements
  (`crates/antseal-cli/src/passphrase.rs:38-51`).
- **12 bytes is nowhere near enough.** It stops a typo and an empty line. It
  stops nothing an attacker with your vault would actually run.
- **It applies only at creation.** Unlocking an existing vault enforces no floor
  — an existing vault owns its passphrase, and there is no command to change it.
- **Nothing checks it again later.** No advisory, no re-prompt, no upgrade path.

What to aim for instead, given that the thing you are defending is an offline
attack with unlimited attempts and no deadline:

- **A long passphrase, generated rather than invented.** Five or six random
  words from a large list, or 20+ random characters from a password manager.
  Human-chosen phrases of the same length are far weaker than they look, and
  this is not a threat model that forgives that.
- **Unique to this vault.** Reuse means someone else's breach becomes your
  permanent disclosure, years later.
- **Written down and stored somewhere physically safe.** A passphrase you forget
  is the *other* failure on `vault-loss.md`, and it is equally final. Store the
  written copy apart from any export file: together in one place they are a
  single artifact, and it is the artifact this page is about.

## Argon2id, and what the hardening buys you

An attacker with your vault runs an offline guessing attack. The only thing that
slows them is the cost of testing one candidate passphrase, and that cost is set
by frozen parameters (`crates/antseal-cli/src/vault/kdf.rs:111-119`):

| Parameter | Value | Where |
| --- | --- | --- |
| Argon2id memory `m` | 262 144 KiB — **256 MiB** | `crates/antseal-cli/src/vault/kdf.rs:112` |
| Argon2id time `t` | 3 | `crates/antseal-cli/src/vault/kdf.rs:114` |
| Argon2id lanes `p` | 1 (exact match, not a floor) | `crates/antseal-cli/src/vault/kdf.rs:116` |
| scrypt `log2 N`, if chosen at `init` | 20, i.e. N = 2^20 | `crates/antseal-cli/src/vault/kdf.rs:119` |
| random salt | 16 bytes | `crates/antseal-cli/src/vault/kdf.rs:104` |

The memory cost is the point. 256 MiB per guess is what makes a GPU or ASIC
farm — which is how short passphrases actually fall — expensive rather than
free.

Argon2id is the default and scrypt is available only by explicit choice at
`init`. Note which direction that choice runs: `--kdf scrypt` needs **more**
memory, about 1 GiB against Argon2id's 256 MiB, and `init`'s own help says so
in as many words — *"it is not a low-RAM escape"*
(`crates/antseal-cli/tests/snapshots/cli-surface.help.txt:67-74`). There is no
setting anywhere that makes this cheaper.

Three consequences you can observe:

- **The floor cannot be negotiated away, even by you.** A machine that cannot
  allocate 256 MiB fails at both create and unlock with a distinct error, class
  `vault-kdf-memory`, exit code **13**, and no fallback
  (`crates/antseal-cli/src/error.rs:556-564`): *"the memory floor is a security
  parameter … antseal will not create or open a weaker vault"*.
- **A tampered header cannot weaken it either — and it fails before it costs
  anything.** The vault header is not encrypted, because an unlock has to read
  the parameters before it can decrypt anything. Edit them below the floor and
  the header is rejected **before authentication and before any allocation**, by
  a range check (`crates/antseal-cli/src/vault/kdf.rs:280`, floor test at
  `:288`) that `decode` runs at `:438` — one line ahead of key derivation
  (`crates/antseal-cli/src/vault/session.rs:423-427`). It carries its own class,
  `vault-kdf-params-out-of-range`, exit code **14**
  (`crates/antseal-cli/src/error.rs:375`, `:445`), so the failure names its
  cause instead of collapsing into a generic authentication error.
  `downgraded_params_are_rejected_pre_auth`
  (`crates/antseal-cli/tests/vault_encryption.rs:505`) rewrites a real vault's
  on-disk header with halved memory and asserts exactly that.
- **Every other header edit fails authentication.** The exact header bytes —
  algorithm id, parameters, salt, wrap mode — are bound into every vault record
  as the cipher's associated data (`crates/antseal-cli/src/vault/cipher.rs:180-186`).
  So an edit that stays *inside* the caps, such as raising `t` from 3 to 4 or
  swapping the salt, changes the derived key or the associated data and the
  vault refuses to open — class `vault-auth-failure`, exit code **12** — rather
  than opening under parameters you never chose
  (`crates/antseal-cli/tests/vault_encryption.rs:537`, `:574`).

There are ceilings as well as floors (`crates/antseal-cli/src/vault/kdf.rs:126-130`).
An *inflated* parameter in a header somebody handed you is a memory bomb, not a
gift, and it is refused by the same check.

*One correction worth stating, because the specification's own wording is
weaker than the shipped behaviour.* `MVP-SPEC.md` line 143 describes a parameter
downgrade as *"a detected authentication failure, not a silent weakening"*. What
ships is stronger: the downgrade never reaches authentication at all, and it
gets its own error class rather than being folded into one. The engineering
record of that correction is `docs/threat-model.md` §2.1.

## The keyfile: a second factor, and the honest limits

`antseal init --wrap keyfile` generates 32 bytes of operating-system randomness
and makes that file **required alongside the passphrase at every unlock**
(`crates/antseal-cli/src/vault/keyfile.rs:67`,
`crates/antseal-cli/tests/snapshots/cli-surface.help.txt:79-86`). The two
factors are combined with HKDF rather than XOR, so neither is recoverable from
the vault and neither is recoverable from the other
(`crates/antseal-cli/src/vault/keyfile.rs:10-24`).

Against the threat on this page it buys the thing that matters most: **a stolen
laptop is no longer sufficient.** An attacker with your whole `~/.antseal/` and
your passphrase still cannot derive the vault key, provided the keyfile lived
somewhere the theft did not reach. Note the proviso is doing real work: if
`init` recorded the keyfile's path, the vault directory tells a thief exactly
where to go looking next.

Which is the whole discipline in one line: **different media from the vault.** A
keyfile in your home directory beside `~/.antseal/` protects against nothing,
because anything that reaches one reaches the other. Put it on a USB stick you
keep separately, a second machine, or a password manager that stores
attachments. `docs/vault-keyfile.md` is the full placement guidance, including
what recording its path in the vault header does and does not disclose.

What it costs, stated up front because it is not small:

- **`vault export` and `vault import` both refuse a keyfile-wrapped vault**,
  with `usage`, exit code **2**, and the words *"nothing was written"*
  (`crates/antseal-cli/src/vault/export.rs:745-756`, `:520-535`). The v1 export
  file is keyed by the passphrase alone, so writing one would quietly turn a
  two-factor vault into a one-factor backup. You back up the vault directory and
  the keyfile by hand, in two pieces kept apart.
- **Lose the keyfile and the vault is gone**, exactly as if you had lost the
  passphrase. This is the loss failure again, from the other side.

`--wrap` is declined by default for that reason, and the trade is yours to make
deliberately.

### The OS keystore is not available, and will say so

`MVP-SPEC.md` line 143 mentions *"a high-entropy keyfile / OS-keystore wrap"*.
**Only the keyfile half ships.** The keystore is registered as wrap-mode id 2 in
the vault header (`crates/antseal-cli/src/vault/header.rs:83`) and is not
implemented: `antseal init --wrap` offers exactly `none` and `keyfile` and
nothing else (`crates/antseal-cli/tests/snapshots/cli-surface.help.txt:83-84`),
and a vault header naming mode 2 is refused at unlock with its own class,
`vault-wrap-mode-unsupported`, exit code **19**
(`crates/antseal-cli/src/vault/session.rs:398-403`;
`crates/antseal-cli/tests/vault_keyfile.rs:217-232` asserts the class, the code,
and that the message says the vault is *intact*).

The reason it was left out is this page's own argument turned around
(`docs/decisions/D50-os-keystore-scope.md:52-56`): the Linux keyring that needs
no desktop session is memory-resident and does not survive a reboot, and a
reboot-volatile store holding the sole copy of a wrap factor — for a vault whose
theft model is *no rotation, ever* — is not a wrap, it is a time bomb.

## If your laptop is stolen

Work through this honestly. Some of it is action and some of it is accepting
what cannot be undone.

1. **Assume the vault is copied.** Full-disk encryption that was unlocked when
   the machine was taken bought you nothing, and disk encryption at rest only
   moves the problem to that passphrase.
2. **The wallet is the only part with a live clock, and antseal gives you no
   way to win that race.** No command prints or exports the wallet key on its
   own: the key goes *in* at `init` (`--wallet import`, via a file descriptor)
   and never comes back out
   (`crates/antseal-cli/tests/snapshots/cli-surface.help.txt:52-65`). It is read
   only to sign a payment (`crates/antseal-cli/src/commands.rs:381`, `:387`) or
   to be copied into a `vault export`
   (`crates/antseal-cli/src/vault/export.rs:761`) — so your only route to the
   funds is the same artifact the thief is holding, protected by the same
   passphrase. If you supplied the key yourself at `init` you still have it
   elsewhere and can sweep the address from any Arbitrum wallet. If antseal
   generated it, you cannot. **This is why `funding-your-wallet.md` says to keep
   the balance small and fund close to when you seal** — that advice is the
   mitigation, and it only works in advance.
3. **Do not bother rotating.** There is nothing to rotate. Creating a new vault
   protects future works only, and re-importing the old one changes nothing an
   attacker holding a copy can do.
4. **Treat everything already sealed as compromised on the attacker's timetable,
   not yours.** If the passphrase is strong, that timetable may be effectively
   never. If it is weak, or reused, or written on the same laptop, assume the
   content is readable and plan around the content itself — tell the people
   whose information it was, and do it now rather than after a breach becomes
   visible.
5. **Inventory what was in there.** The vault also held your original file
   paths, titles, seal times and costs. Those are metadata about work you may
   never have published, and they are disclosed by the same theft.
6. **Seal new work in a new vault, with a new passphrase**, and treat the
   keyfile wrap as the default this time.
7. **Your existing bundles are unaffected in their own right.** A `.sealproof`
   bundle you already handed to a counterparty still verifies, and the theft
   does not retract it. It also does not help you: a thief holding `W` can
   produce new signed manifests under a stolen work's identity, so a bundle
   created *after* the theft is worth what your passphrase was worth.

## The other direction, which is why the CLI states both

Everything on this page argues for *fewer copies* and a passphrase you would
not put in a drawer. Read it alone and you will end up with no backup at all,
which is the other permanent failure — and it is the one users actually hit.
antseal never gives one of these warnings without the other, so neither does
this page:

```
  LOSS  — lose this vault and its passphrase, and no one can ever reveal or restore your sealed works again. The sealed data itself stays safely unreadable. Run `antseal vault export` and keep the backup somewhere else.
```

That is `LOSS_WARNING` (`crates/antseal-cli/src/vault/bookkeeping.rs:68-70`),
quoted byte for byte, exactly as the top of this page quotes `THEFT_WARNING`.
The two mitigations genuinely pull against each other — *make more copies*
versus *make fewer* — and only stating both makes the trade visible instead of
letting you optimise one failure into the other. `vault-loss.md` is that side
of it: the export procedure, where to keep the file, and the restore drill.

## What a seal claimed in the first place

A seal proves that the holder of this vault possessed the content by the
anchored time — not authorship, and not exclusive possession. A theft is
therefore not only a confidentiality failure: it hands somebody else the ability
to make that same claim about your works, and nothing distinguishes them from
you afterwards.

Which is the argument for choosing the passphrase as if it had to hold for a
decade. It does.

## Evidence

| Claim on this page | Where it is enforced |
| --- | --- |
| the theft warning, byte for byte | `crates/antseal-cli/src/vault/bookkeeping.rs:74-77` |
| `init` and the first-seal nag share that one constant | `crates/antseal-cli/src/init.rs:337-342`; `crates/antseal-cli/src/vault/bookkeeping.rs:264` |
| retroactive, permanent, unrotatable — stated in the code too | `crates/antseal-core/src/crypto/secrets.rs:47-49` |
| `W` is per work; everything derives from it | `crates/antseal-cli/src/vault/store.rs:198-201`; `crates/antseal-core/src/crypto/hkdf.rs:137-146` |
| an export carries `W` for every work | `crates/antseal-cli/src/vault/export.rs:99-100` |
| the wallet sub-key decouples records, not the passphrase | `crates/antseal-cli/src/vault/wallet.rs:9-12` |
| no command exports the wallet key; it is read only to sign or to be copied into an export | `crates/antseal-cli/tests/snapshots/cli-surface.help.txt:52-65`; `crates/antseal-cli/src/commands.rs:381`, `:387`; `crates/antseal-cli/src/vault/export.rs:761` |
| no rotate / passwd / change-passphrase: nine commands, frozen | `crates/antseal-cli/tests/snapshots/cli-surface.help.txt:7-15` |
| scrypt costs more memory, not less — no low-RAM escape | `crates/antseal-cli/tests/snapshots/cli-surface.help.txt:67-74` |
| import re-encrypts local records and never touches `W` | `crates/antseal-cli/src/vault/export.rs:130-131` |
| 12-byte creation floor, length only, creation only | `crates/antseal-cli/src/passphrase.rs:38-51`, `:87`, `:238` |
| frozen Argon2id and scrypt parameters | `crates/antseal-cli/src/vault/kdf.rs:104`, `:111-119` |
| memory floor has no fallback — exit **13** | `crates/antseal-cli/src/error.rs:556-564`; exit table at `:374` |
| below-floor parameters are refused pre-auth — exit **14** | `crates/antseal-cli/src/vault/kdf.rs:280`, `:288`, `:438`; `crates/antseal-cli/src/vault/session.rs:423-427`; `crates/antseal-cli/tests/vault_encryption.rs:505` |
| the whole header is bound as associated data — exit **12** | `crates/antseal-cli/src/vault/cipher.rs:180-186`; `crates/antseal-cli/tests/vault_encryption.rs:537`, `:574` |
| parameter ceilings, against a memory bomb | `crates/antseal-cli/src/vault/kdf.rs:126-130` |
| keyfile is 32 CSPRNG bytes, combined by HKDF | `crates/antseal-cli/src/vault/keyfile.rs:10-24`, `:67` |
| export and import both refuse a wrapped vault | `crates/antseal-cli/src/vault/export.rs:745-756`, `:520-535` |
| OS-keystore wrap is reserved and refused — exit **19** | `crates/antseal-cli/src/vault/header.rs:83`; `crates/antseal-cli/src/vault/session.rs:398-403`; `crates/antseal-cli/tests/vault_keyfile.rs:217-232` |
| why the keystore was left out | `docs/decisions/D50-os-keystore-scope.md:52-56` |
| the engineering account of this failure mode | `docs/threat-model.md` §2.1 |
