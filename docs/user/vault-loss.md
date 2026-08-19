# Vault loss

Lose `~/.antseal/` and its backup — or forget the passphrase that opens it —
and you permanently lose the ability to reveal or restore anything you have
sealed. Nobody can recover it for you. There is no reset link, no recovery
code, and no support address that can help, because antseal is non-custodial:
the only copy of your keys is the one on your machine.

This page is how to make sure that never happens, and what is honestly
recoverable if it already has.

**The good half, said first.** Losing the vault costs you *capability*. It
costs you no confidentiality at all. Everything you uploaded stays exactly as
unreadable as it was a minute earlier, because the keys that would open it went
with the vault. A lost vault leaves you with a permanent archive nobody can
read, including you. That is a much better failure than the other one — see
`vault-theft.md`, which pulls the opposite way.

## The warning antseal already gave you

`antseal init` prints this before you seal anything, and the first seal in a
vault with no recorded backup prints it again:

```
  LOSS  — lose this vault and its passphrase, and no one can ever reveal or restore your sealed works again. The sealed data itself stays safely unreadable. Keep a backup of this vault somewhere else.
```

and, a line or two later, what to do about it:

```
  BACK UP — run `antseal vault export` and keep the file on different media from the vault: another disk, another machine, a safe. The keys to everything you seal live in this one directory.
```

Neither is a paraphrase. They are two constants, quoted byte for byte: the fact
is `LOSS_WARNING` (`crates/antseal-cli/src/vault/bookkeeping.rs:73-75`) and the
remedy is `BACKUP_BY_EXPORT` (`:87-89`). Both are the same strings `init`
renders (`crates/antseal-cli/src/init.rs:375`, `:377-382`) and the same strings
the first-seal export nag carries
(`crates/antseal-cli/src/vault/bookkeeping.rs:300`, `:294-299`) — in `init` the
theft warning sits between them, and in the nag the
remedy comes first; the wording is identical either way. One author for each
fact, so a sentence you met at `init` is recognisable here rather than being a
second phrasing of the same risk. `MVP-SPEC.md` line 143 requires both the CLI
and these docs to state it.

The fact and the remedy are separate constants because **the remedy is not the
same for every vault**. `LOSS_WARNING` is true of any vault and names no
command; the backup line is chosen by the vault's wrap mode, and a
keyfile-wrapped vault gets `BACKUP_BY_HAND` (`:96-99`) instead — see *If your
vault uses a keyfile, `export` refuses* below.

The nag around it is equally direct
(`crates/antseal-cli/src/vault/bookkeeping.rs:285-303`):

```
  NO BACKUP YET — this vault has never been exported.
  BACK UP — run `antseal vault export` and keep the file on different media from the vault: another disk, another machine, a safe. The keys to everything you seal live in this one directory.
```

It stops as soon as one export has been written and self-verified, and never
before that (`crates/antseal-cli/src/commands.rs:805-810`) — the flag that
silences it means *a backup exists*, not *a backup was attempted*.

## What you lose, precisely

Three things, all of them permanently:

- **Reveal.** Building a `.sealproof` bundle needs the master secret `W` for
  the unit keys, the per-unit and per-file salts, and the range seeds. Without
  them no bundle — whole or partial — can be assembled at all.
- **Restore.** Fetching your own files back needs `W` to decrypt the uploaded
  units *and* the manifest. The manifest is itself uploaded encrypted
  (`MVP-SPEC.md` line 91), so the index of a work's own chunks is unreadable
  too: there is nothing left to even enumerate.
- **Signing.** Both signing seeds derive from `W`
  (`crates/antseal-core/src/crypto/hkdf.rs:137-146`), so the work's identity
  cannot be used again.

And the money is gone with it, in the case this page opens with — vault **and**
backup. From a surviving backup the address still pays: `vault import` reinstalls
the wallet key (`crates/antseal-cli/src/vault/export.rs:1104-1106`). What no
backup gives you is a way to move the balance to another wallet — see "What this
address's key can and cannot do" in `funding-your-wallet.md`.

## What survives, and this is the part people do not expect

**Every `.sealproof` bundle you have already produced still verifies. Forever,
offline, by anybody, with no vault involved.** Bundles are self-contained by
construction — that is the whole design, and it is why evidence validity never
depended on your vault, on antseal, or on Autonomi being reachable
(`format-stability.md`). `antseal verify` needs no vault and never prompts
(`crates/antseal-cli/tests/snapshots/cli-surface.help.txt:14`).

So losing the vault destroys your ability to make *new* disclosures. It
destroys no evidence you have already handed to a counterparty, and it weakens
no verdict anyone has already been shown. If a bundle is the thing that
actually matters to you, keep a copy of the bundle too — it is a different
artifact with a different failure mode, and it is not covered by a vault
backup.

## The backup: two commands, no flags

```
antseal vault export [FILE]
antseal vault import <FILE>
```

That is the whole surface. Neither takes an option beyond the three global ones
every command has (`crates/antseal-cli/tests/snapshots/cli-surface.help.txt:354-406`).
The design note in the source is the product decision in one line:
*"single re-encrypted file, no flags (D47)"* (`crates/antseal-cli/src/cli.rs:462`).

What `export` writes:

- **One encrypted file** containing your whole vault: every work's `W`, the
  seal journal, receipts, anchor artifacts, the wallet key and `config.toml`
  (`crates/antseal-cli/src/vault/export.rs:61-95`).
- **Encrypted under the same passphrase, with a fresh salt of its own** — never
  the vault's salt and never the vault's derived key
  (`crates/antseal-cli/src/vault/export.rs:23-28`). One AEAD covers the whole
  file, so any truncation, edit or missing work is an authentication failure
  rather than a partial restore (`crates/antseal-cli/src/vault/export.rs:20-22`).
- **Named for the moment it was taken.** With no `FILE` argument the default is
  `antseal-vault-export-YYYYMMDD-HHMMSS.sealvault` in the current directory,
  UTC (`crates/antseal-cli/src/commands.rs:889-896`). The timestamp is
  deliberate: repeated exports never silently overwrite an earlier backup.
- **Self-verified before it is named.** antseal writes a temp file, fsyncs it,
  re-reads it from disk, runs the *full* import-side validation, derives the
  key from the file's own header, decrypts, compares a SHA-256 digest of the
  decoded payload against what it meant to write — and only then renames it
  into place (`crates/antseal-cli/src/vault/export.rs:104-118`). An export that
  would not have imported is never left on disk looking like a backup. If that
  check fails you get class `export-self-verify-failed`, exit code **32**
  (`crates/antseal-cli/src/error.rs:391`).

It prints what it did, and then it says the thing this page is about
(`crates/antseal-cli/src/commands.rs:819-822`):

```
Treat this file like the vault itself: whoever holds it and the passphrase holds the keys to every sealed work, forever.
```

## Where to keep it, and how many

The export is a **second complete copy of everything**, so backup discipline
and theft discipline pull against each other. The honest rule is *few copies,
each somewhere a burglar and a house fire cannot both reach*:

- **At least two, in different places.** One on the machine is not a backup;
  the failure you are guarding against is that machine.
- **Different media and different failure modes.** A second partition on the
  same disk dies with the disk. A cloud folder that syncs your home directory
  is a copy of the vault, not an independent one.
- **Encrypted media are still worth it.** The file is already encrypted, but a
  passphrase is the only thing between it and everything you have sealed, so a
  second layer costs nothing.
- **Do not scatter.** Every extra copy is another place a theft can start. Two
  or three deliberate copies you can account for beat a dozen you cannot.
- **Re-export after anything that matters.** The export is a snapshot. A work
  sealed after your last export is not in it, and the nag will not fire again
  to remind you.

## The passphrase is half the backup, and antseal does not hold it

An export you cannot open is not a backup. The file is encrypted under the
vault passphrase alone, so **losing the passphrase is exactly as final as
losing the vault** — the two failures are one failure.

Nothing in antseal can help here: there is no recovery question, no escrow, no
key-splitting scheme in v1, and no `change-passphrase` command to give you a
second chance (the frozen surface has nine commands and that is not one of
them, `crates/antseal-cli/tests/snapshots/cli-surface.help.txt:7-15`).

`init` enforces a floor of **12 bytes** at creation and nothing more
(`crates/antseal-cli/src/passphrase.rs:87`) — a floor is not advice. Choose
something long that you will still have in ten years, and write it down
somewhere real. A passphrase in your head and nowhere else has a single point
of failure, and it is you. Store it **apart from the export file**: together in
one envelope, the two halves are one artifact and you have built the theft
scenario instead of the backup.

## If your vault uses a keyfile, `export` refuses

`antseal init --wrap keyfile` adds a second factor, and the v1 export format
cannot carry it — the backup file is keyed by the passphrase alone, so writing
one would quietly turn a two-factor vault into a one-factor backup. antseal
refuses in both directions rather than do that, with `usage`, exit code **2**,
and the words *"nothing was written"*
(`crates/antseal-cli/src/vault/export.rs:745-756` and `:520-535`).

A keyfile vault is therefore backed up by hand, in two pieces kept apart:

1. a copy of the vault directory `~/.antseal/`;
2. a copy of the keyfile.

Lose either and the vault is gone. `docs/vault-keyfile.md` is the full
placement guidance.

**Your first-seal nag says so, and it never goes away.** antseal records that a
backup exists only when `vault export` succeeds, and for your vault it never
will — so the nag is permanent by construction rather than because you have
neglected something, and it says that instead of naming a command that refuses
you:

```
  NO BACKUP RECORDED — a keyfile-wrapped vault is backed up by hand, and antseal cannot see that you did it, so this stays on every seal.
  BACK UP — this vault has a keyfile, so it is backed up by hand, in two pieces kept apart: a copy of the vault directory and a copy of the keyfile. There is no single backup file for a two-factor vault: it would be encrypted under the passphrase alone, which is weaker than the vault it backs up.
```

That second line is `BACKUP_BY_HAND`
(`crates/antseal-cli/src/vault/bookkeeping.rs:96-99`), quoted byte for byte;
`init` closes with the same line for a keyfile vault.

## The restore drill — rehearse it before you need it

Do this on a machine that has never seen the vault, or with `ANTSEAL_DIR`
pointing somewhere empty. A backup you have never restored is a belief, not a
backup.

1. **Copy the export file across.** Nothing else — no `~/.antseal/`, no config.
2. **Run `antseal vault import <FILE>`** and give the vault passphrase. It is
   collected only *after* the file's own header checks pass, so a corrupt file,
   an over-size one or a file that is not an antseal export at all is rejected
   without ever prompting you
   (`crates/antseal-cli/src/vault/export.rs:120-125`). A *wrong passphrase*
   still costs you the prompt and the derivation, as it must.
3. **Watch what it validates before it touches anything.** The whole payload is
   decoded and checked in memory, a complete fresh vault is built in a
   dot-prefixed temp directory beside the target, and one atomic directory
   rename installs it. A crash at any point leaves either nothing or an inert
   temp directory — never a half-written `~/.antseal/`
   (`crates/antseal-cli/src/vault/export.rs:122-133`).
4. **It is a new vault, not a copy.** Import derives a fresh vault salt and a
   fresh vault key and re-encrypts every record under it
   (`crates/antseal-cli/src/vault/export.rs:130-131`). Your works, `W`, the
   wallet and the config are the same; the bytes on disk are not.
5. **Confirm with `antseal list`.** The work count should match. Import already
   ran its own post-install check — a fresh unlock plus a full walk of every
   record (`crates/antseal-cli/src/vault/export.rs:1226-1250`) — but the
   command is yours to run and costs nothing.
6. **Then try a `restore`.** `antseal restore <WORK-ID>` fetches the
   ciphertexts, decrypts them, verifies them against the manifest commitments
   and writes your original files back
   (`crates/antseal-cli/tests/snapshots/cli-surface.help.txt:223`). That is the
   step that proves the backup carries what you actually care about, and it
   needs network access where the earlier steps do not.

**`import` will not overwrite an existing vault**, and there is no flag to make
it (`crates/antseal-cli/src/error.rs:577-585`):

```
refusing to import over the existing vault at <dir>: overwriting a vault irreversibly destroys the reveal/restore keys of every work in it. Move that directory aside yourself first — moving it keeps everything, and no antseal command has to run first; delete it only when you are certain nothing in it matters. Scripted overwrite-import is deliberately unsupported (D51)
```

Moving the old directory aside by hand *is* the consent. So rehearse in a
throwaway location, and never point an import at the vault you are still using.

*Scope note, stated rather than implied:* the mechanism above is unit-tested,
and the end-to-end proof — a restore on a machine that has never seen the
original vault — is an M4 release-gate item (task **Q34**), not a claim this
page is making on its own behalf. The steps are the drill; the gate is the
evidence.

## If it is already gone

Work through it in this order, because the cheap answers are also the likely
ones:

1. **Look for an export.** `antseal-vault-export-*.sealvault` on any disk,
   backup set, USB stick or cloud folder you have ever used. Identification is
   by content, not by name — a renamed file still imports
   (`crates/antseal-cli/src/vault/export.rs:184-185`).
2. **Look for the vault directory itself**, at `~/.antseal/` or wherever
   `ANTSEAL_DIR` pointed. A whole-machine backup, a cloned disk or a
   Time-Machine-class snapshot may hold it; the directory copies as an ordinary
   directory.
3. **Check whether the passphrase is the real loss.** If the vault or an export
   is present and the passphrase is not, there is nothing to try. Guessing is
   the attack that Argon2id at 256 MiB is designed to make expensive, and it is
   equally expensive for you (`crates/antseal-cli/src/vault/kdf.rs:111-116`).
4. **Collect the bundles you have already made.** They are unaffected, they
   still verify, and they may be all the evidence you actually needed.
5. **Then stop.** There is nothing after this. If the vault, every export and
   the passphrase are all gone, the sealed works are permanently unreadable and
   permanently un-revealable. antseal will not pretend otherwise, and neither
   should anyone selling you a recovery service.

Sealing new work still functions: `antseal init` builds a fresh vault, and the
old works simply are not in it. What is lost is the link between you and what
you sealed before, and that link cannot be rebuilt.

## The other direction, which is why the CLI states both

Everything above says *make copies*. The theft page says *make fewer*, and it
is not a contradiction — the two failures have opposite mitigations, and only
stating both makes the trade visible. That is why `antseal init` and the
first-seal nag give you the second warning in the same breath as the first,
and why this page repeats it rather than sending you away for it:

```
  THEFT — whoever holds this vault (or an export) and the passphrase can decrypt every work you have ever sealed, retroactively and permanently. The ciphertexts are public and undeletable, and there is no key rotation. Treat the passphrase as a long-term, high-value key.
```

That is `THEFT_WARNING` (`crates/antseal-cli/src/vault/bookkeeping.rs:74-77`),
quoted byte for byte, exactly as the paragraph above quotes `LOSS_WARNING`.
A reader told only about loss scatters copies of a file that retroactively
decrypts a permanent public archive; a reader told only about theft keeps no
backup and loses everything to a dead disk. `vault-theft.md` is the whole
argument, and it is worth reading before you decide how many copies of an
export you are comfortable having in the world.

A seal proves that the holder of this vault possessed the content by the
anchored time — not authorship, and not exclusive possession. Losing the vault
does not withdraw any proof you have already handed out; it ends your ability
to make new ones.

## Evidence

| Claim on this page | Where it is enforced |
| --- | --- |
| the loss warning, byte for byte | `crates/antseal-cli/src/vault/bookkeeping.rs:68-70` |
| `init` and the first-seal nag share that one constant | `crates/antseal-cli/src/init.rs:353-357`; `crates/antseal-cli/src/vault/bookkeeping.rs:263` |
| the nag stops only after a written and self-verified export | `crates/antseal-cli/src/commands.rs:805-810` |
| two commands, no flags | `crates/antseal-cli/src/cli.rs:462-480`; `crates/antseal-cli/tests/snapshots/cli-surface.help.txt:354-406` |
| the export carries `W` for every work | `crates/antseal-cli/src/vault/export.rs:61-95`, stated at `:99-100` |
| fresh salt, one AEAD over the whole file | `crates/antseal-cli/src/vault/export.rs:20-28` |
| default timestamped filename | `crates/antseal-cli/src/commands.rs:889-896` |
| mandatory self-verify before the rename | `crates/antseal-cli/src/vault/export.rs:104-118`; exit **32** at `crates/antseal-cli/src/error.rs:391` |
| import validates fully, installs atomically, verifies after | `crates/antseal-cli/src/vault/export.rs:120-133`, `:1226-1250` |
| import refuses an existing vault, with no bypass | `crates/antseal-cli/src/error.rs:535-542` |
| a keyfile-wrapped vault is refused by export and import | `crates/antseal-cli/src/vault/export.rs:745-756`, `:520-535` |
| 12-byte creation floor, and no floor at unlock | `crates/antseal-cli/src/passphrase.rs:87`, `:238` |
| no `change-passphrase`: nine commands, frozen | `crates/antseal-cli/tests/snapshots/cli-surface.help.txt:7-15` |
| the engineering account of this failure mode | `docs/threat-model.md` §2.2 |
| the end-to-end restore drill is a gate item | task **Q34** (M4) |
