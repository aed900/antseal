# Maintainer procedure — the acts only the maintainer can perform

Three acts here are **external**: they touch the maintainer's own machine, the
domain registrar account, and a public timestamp calendar. **No agent performs
any of them**; §7 records which have been performed and which have not. Each
needs the maintainer's own terminal and, for §2, express in-the-moment consent
at the registrar.

Order matters: **§1 → §3 → §2**. The key must exist before it can be anchored,
and D71 §A R4 wants the anchor a few days ahead of the release while the `TXT`
pin should be in place from the moment the key is first published.

> **Never paste a secret key, or its passphrase, into a terminal an agent can
> read, into an issue, or into this repository.** Nothing in this project ever
> needs the secret half. If you are asked for it, the request is wrong.

---

## 1. Generate the keypair — on your own machine

`minisign -G` **prompts interactively, twice, for a passphrase.** Run it in a
real terminal; it will not work from a script or a non-interactive shell, and
that is deliberate.

```
mkdir -p ~/.minisign
minisign -G -p ~/.minisign/minisign.pub -s ~/.minisign/minisign.key
```

> **Run this as your own user — not under `sudo`, not as `root`.** `~` expands to the
> *invoking* account's home, so a root run writes the key to `/root/.minisign/` owned by
> `root`. That is not where `key-custody.md` §2 puts the working location, and it is not
> where `scripts/sign-release.sh`'s `${HOME}/.minisign/minisign.key` default will look
> when you later sign as yourself. **Measured 2026-08-19: this is what happened on the
> real first run**, and it was corrected by moving the directory and re-running §1a as the
> maintainer. Signing needs no root at all (`sign-release.sh:98` — *signing is a local act*).

You will be asked:

```
Please enter a password to protect the secret key.

Password:
Password (one more time):
Deriving a key from the password in order to encrypt the secret key... done
```

**Do not pass `-W`.** `-W` writes the secret key unencrypted, and D71 §2 R7.1
forbids it — the key can never be withdrawn, so a plaintext copy on disk and in
every backup is unbounded in time. `scripts/sign-release.sh` refuses to run
against such a key.

Use a strong, unique passphrase, generated and stored the way the antseal vault
passphrase is. **It is not the vault passphrase.**

### 1a. Immediately after generating

```
# The 56-character public key — this is the value that gets published.
cat ~/.minisign/minisign.pub

# Confirm the secret key really is passphrase-wrapped: this reads the KDF
# field out of the key struct. It must print `Sc` (scrypt). If it prints
# `\0\0` the key is unencrypted — you passed -W. Delete it and start again.
sed -n '2p' ~/.minisign/minisign.key | base64 -d | head -c 4 | tail -c 2 | od -An -c | tr -d ' \n'; echo

# The key id, for the custody log.
minisign -R -s ~/.minisign/minisign.key -p /tmp/check.pub && head -1 /tmp/check.pub && rm -f /tmp/check.pub
```

Then — **step 3 immediately, and steps 1 and 2 before §3, not merely before §4**:

1. Make **two offline backups** of `~/.minisign/minisign.key`, on separate
   media in separate locations, and back up `minisign.pub` with them
   (`key-custody.md` §4).
2. Record the passphrase where the vault passphrase is recorded, **not** with
   the backups.
3. Add the first row to `key-custody.md` §10 — date, "generated", key id.

**Why steps 1 and 2 gate §3 and not only §4** (D153 §2 R4): §3 anchors *this*
key, and an anchor cannot be transferred to a replacement. D71 §A R4 puts the
anchor in a narrow window — *"a few days before the release date"* — so a key
lost after §3 and before the release costs the anchor **and** the window on top
of the regeneration. Loss is the failure `key-custody.md` §5 calls the cheap one
*because* published signatures survive it; before §3 there is nothing to survive,
and the backups are what keep it cheap. §1.7 of D153 is the measurement that
makes this concrete rather than theoretical: today the key has exactly one copy,
on a machine that is not dedicated to it.

---

## 2. Publish the independent pin — at the registrar

This is the **only** publication location that is not on the same account as
the code and the releases, and until it exists the scheme has no independent
pin at all (`key-custody.md` §9).

**External action. Requires the Porkbun registrar account and express consent
at the time. No agent takes it.**

Create one `TXT` record on the apex:

| field | value |
|---|---|
| **Type** | `TXT` |
| **Host / Name** | leave blank, or `@` — this is the apex, `antseal.org`, **not** a subdomain |
| **Value** | `antseal-minisign-key=RW<...the 56 characters from §1a...>` |
| **TTL** | the registrar default is fine |

In zone-file terms:

```
antseal.org.  IN  TXT  "antseal-minisign-key=RW<...56 characters...>"
```

One string, well inside a `TXT` record's 255-character limit.

Verify it from a machine that is not yours:

```
dig +short TXT antseal.org
```

**Measured 2026-08-18: the zone has no `TXT` records at all**, so this record
will be the only one and nothing can collide with it. Note also that
`antseal.org` is not DNSSEC-signed (the `DS` query returns nothing and answers
carry no authenticated-data flag), so this pin is independent of a compromise
of the code host but is not protected against an on-path attacker. Say that
where the key is published; do not oversell it.

---

## 3. Anchor the public key

Timestamp `minisign.pub` so that its age is on public record, using this
project's own OpenTimestamps machinery (D71 §2 R6). This adds no `antseal`
subcommand — the CLI surface is frozen — so it is driven with the existing
`anchor-smoke-driver` binary or a reference `ots` client:

```
ots stamp ~/.minisign/minisign.pub          # writes minisign.pub.ots
```

**Timing (D71 §A R4): stamp a few days BEFORE the release date**, not on the
day and not after. A fresh proof is *pending* — attested by calendar servers,
not yet by Bitcoin — and needs a later upgrade pass:

```
ots upgrade ~/.minisign/minisign.pub.ots
ots verify  ~/.minisign/minisign.pub.ots
```

Ship `minisign.pub.ots` beside `minisign.pub` in the release and at
`https://antseal.org/`. **State in the release notes which state the proof is
in.** If it is still pending, label it pending — an unqualified claim that the
key is Bitcoin-attested when it is not yet is exactly the kind of overstatement
`key-custody.md` §8 exists to prevent.

Only the digest is published. No repository name, no owner, no commit.

---

## 4. Sign a release

Once §1 is done, this is the routine act and it is not external:

```
scripts/sign-release.sh --version v0.1.0 --commit "$(git rev-parse HEAD)" --dir dist/
```

**Expect one passphrase prompt per artifact, plus one for the manifest.** That
is not a defect and it cannot be batched away: minisign signs several files in
one invocation only when they share a single trusted comment, and D71 §2 R4
requires each comment to carry its own artifact's basename — which is what
stops one artifact's signature being presented for another.

Then check the result exactly as a stranger would, before publishing:

```
scripts/verify-release.sh --version v0.1.0 --commit "$(git rev-parse HEAD)" \
  --dir dist/ --key "$(sed -n 2p ~/.minisign/minisign.pub)"
```

---

## 5. Publish the key in the other three places

**After §1 and §3, and never before §2.** *"Alongside §2"* was the original
wording, and it is the ambiguity this section is now explicit about: writing the
key into any location below **is** the first publication of the key, and D71 §A
R4 rules that the `TXT` pin's clock *"starts the moment the key is first
published"*. The `TXT` record therefore exists before the first of these three
is written, rather than at the same time as an afterthought (D153 §2 R1).

1. **`README.md`** — the 56-character key, with a pointer to
   [`verifying-a-release.md`](verifying-a-release.md).
2. **The page footer at `https://antseal.org/`.**
3. **`minisign.pub` as a release asset**, with `minisign.pub.ots` beside it.

All four locations change **in one act** whenever the key changes
(`key-custody.md` §6 step 4).

**Two locations this list does not name, both measured missing 2026-08-19.**

- **`verifying-a-release.md` carries the placeholder three times** (`:12`, `:35`,
  `:92`), behind its *"Not yet published"* banner at `:10-14`. It is not one of
  the four pins — which is why it may carry a placeholder at all (D150 §2 R3
  item 2) — but it is the one page a stranger actually follows, so replace all
  three and delete the banner in this same act.
- **The page footer has no key element and no marker to write into.**
  `verifier-web/` holds exactly one file and carries the word `minisign` zero
  times; the live page returns the same. The element is added to
  `verifier-web/index.template.html` and to nothing else, because
  `crates/antseal-wasm/tests/page_template.rs` asserts that directory holds
  exactly `index.template.html`.

**What the wording in those places may not say** (D71 §2 R11): not "verified"
on its own as a verdict about the software; not "revoked", "expired" or "key
rollover", as none of those mechanisms exists; not any suggestion that the key
in the README or on the page is independently checkable while it is served from
the same place as the binary; and no claim of legal effect.

---

## 6. Provisioning the tool — the pin this procedure assumes

D71 §2 R12 hands the choice to Q30, on the same terms
[`../dependency-policy.md`](../dependency-policy.md) applies to every other
pinned tool: a version, a source, and a checksum.

**Chosen: Debian's `minisign`, from the Debian archive.** It is an independent
trust root — Debian's archive, Debian's signing keys, no code-host account
involved — which is precisely the bootstrap property the tool needs and the key
cannot have. `cargo install rsign2` is not chosen for the *verifying* side: it
requires a Rust toolchain on a machine whose whole purpose is to have nothing
on it, and it is a much larger download than the tool it replaces.

| | |
|---|---|
| **Package** | `minisign` |
| **Version** | `0.11-1` on Debian bookworm; `0.12-1` on trixie / forky / sid |
| **Source** | `http://deb.debian.org/debian` |
| **Verified on** | Debian 12.15 (bookworm), 2026-08-18 |
| **`.deb` SHA-256** | `878264fbb6cfd39c7a67262f712ca73d1bfd0d8533f37c2a92c4af2b42b062fd` (`minisign_0.11-1_amd64.deb`) |

That digest pins the exact archive artifact this project's scripts were
exercised against. It is a record of what was tested, not a substitute for
`apt`'s own signature checking, which is the thing actually protecting the
download.

**Both flags this project depends on exist in 0.11** — checked against the
binary, not the manual: `-H` (require prehashed), `-Q` (print only the trusted
comment), `-P` (public key inline), `-t` (trusted comment), `-W` (the form we
forbid). A newer minisign is fine; an older one is not checked.

---

## 7. What has and has not been run

- **Run** (2026-08-18, against a throwaway key in a temporary directory that
  was deleted, never against a project key): `sign-release.sh` end to end
  including the interactive passphrase prompts; `verify-release.sh` over the
  resulting directory; the `-W` refusal; and `verify-release.sh --self-test`,
  whose ten arms include a flipped data byte, an edited trusted comment, a
  replayed previous release and a substituted key.
- **§1 RUN 2026-08-19.** The project key exists — key id `3E5D46890F192F58`, KDF
  field `Sc`, at `~/.minisign/` on the maintainer's account, logged as the first row
  of [`key-custody.md`](key-custody.md) §10. The §1a checks were re-run there after
  the move described in §1 and all three pass. **§1a step 1 is NOT complete: the two
  offline backups have not been made**, and §1a's own preamble — which since
  2026-08-19 reads *"step 3 immediately, and steps 1 and 2 before §3, not merely
  before §4"* — is what forbids **both §3 and §4** until they exist;
  `key-custody.md` §4 is the rule that defines them. **§1a step 3 (the `key-custody.md` §10 row) IS
  complete**, and §1a step 2 is the maintainer's to state.
- **Not run: §2 and §3.** `dig +short TXT antseal.org` still returns empty — the
  zone has no `TXT` records at all — and nothing has been anchored. **They are
  timed differently, and D71 §A R4 says so in its own heading**: *"both deferrable
  items share one property, and it decides them differently"*. §3, the anchor, is
  release-timed — *"stamp a few days before the release date"*, not now and not
  after. §2, the `TXT` pin, is **not** release-timed: §A R4 rules that its clock
  *"starts the moment the key is first published"* and calls it *"the one that
  should not be deferred"*, and §A R5 clause 3's *"before first release"* is its
  outer deadline rather than its schedule. Neither is overdue, because the key is
  published nowhere yet — and §5 may not publish it until §2 exists.
