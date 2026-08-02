# The vault keyfile (the optional second factor)

`antseal init --wrap keyfile` generates a 32-byte keyfile and makes it
**required alongside the passphrase at every unlock**. This page is the
placement guidance: where to put it, what it protects against, and what
it does not.

Task: U8. Decision: D50 (keyfile only at M1; the OS keystore is a
registered but unimplemented wrap mode). Spec: MVP-SPEC.md line 143.

## What it is

32 bytes of OS CSPRNG output — a key, not a password. There is nothing to
memorise and nothing to type. The vault key becomes

```
vault_key = HKDF-SHA256(salt = keyfile bytes,
                        ikm  = Argon2id|scrypt(passphrase, vault salt),
                        info = "antseal-cli vault v1: keyfile wrap")
```

so **both** factors are needed and neither can be derived from the vault.
An attacker with your passphrase and your whole `~/.antseal/` directory
still has nothing; an attacker with the keyfile still faces the full
Argon2id cost.

## Where to put it

The only rule that matters: **different media from the vault.** A keyfile
in your home directory beside `~/.antseal/` protects against nothing,
because anything that reaches one reaches the other — a stolen laptop, a
backup service, a copied home directory.

Good places:

- a USB stick you keep separately from the machine;
- a second machine you control;
- a password manager that stores file attachments;
- a printed or engraved copy of its hex, if you are willing to retype 64
  characters (antseal does not do this for you).

Bad places: the vault directory, the same disk's backup set, a cloud sync
folder that also syncs `~/.antseal/`, an email to yourself.

## Back it up separately

**`antseal vault export` does not contain the keyfile.** It cannot: the
export file is encrypted under the passphrase alone, so carrying the
second factor inside it would turn two factors back into one. This build
therefore **refuses to export a keyfile-wrapped vault at all** rather than
write a backup weaker than the thing it backs up.

That means a keyfile-wrapped vault is backed up by hand, in two pieces
kept apart:

1. a copy of the vault directory (`~/.antseal/`);
2. a copy of the keyfile.

Lose either and the vault is gone, exactly as if you had lost the
passphrase. This is the cost of the second factor, and it is the reason
D50 makes the wrap **declined by default**.

## How antseal finds it

In order:

1. `ANTSEAL_KEYFILE=<path>` — an environment variable holding a **path,
   never a secret** (the same rule `ANTSEAL_DIR` follows). Use it when the
   keyfile has moved, or on a machine where the recorded path is wrong.
2. The path recorded in the vault header, if `init` recorded one (it does
   by default).

There is no `--keyfile` flag: the command surface is frozen (U1), and
adding one is a deliberate decision rather than an implementation detail.

### What recording the path costs

The vault header is not encrypted (it holds the KDF parameters an unlock
needs before it can decrypt anything), so a recorded path tells anyone who
reaches your vault directory **where** the keyfile is kept. It does not
tell them what is in it, and they still need the medium it lives on.

The header is bound as AAD into every vault record, so an attacker cannot
*edit* the recorded path to point at a keyfile of their own — that breaks
authentication for the whole vault.

If that disclosure is unacceptable for your threat model, create the vault
so the path is not recorded and supply `ANTSEAL_KEYFILE` on every
invocation. The vault then says only that a keyfile is required, not where
it is.

## What goes wrong, and what antseal says

| Situation | Exit code | What it means |
| --- | ---: | --- |
| keyfile absent, unreadable, or the wrong size | 18 (`vault-keyfile-missing`) | The second factor is not where antseal looked. Your passphrase is fine. |
| keyfile present but the *wrong* keyfile | 12 (`vault-auth-failure`) | Something authenticated wrongly — the same code a wrong passphrase gives, deliberately (antseal does not say which factor failed). |
| header names wrap mode 2 | 19 (`vault-wrap-mode-unsupported`) | The vault uses the OS-keystore wrap, which D50 reserved but did not implement at M1. The vault is intact; a later build opens it. |
| `vault export` on a wrapped vault | 2 (`usage`) | Refused — see "Back it up separately" above. |

A missing keyfile is **never** reported as an authentication failure. A
user whose USB stick is unplugged must not be sent to re-type a passphrase
that was correct all along.
