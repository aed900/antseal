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

Use a long passphrase, **generated rather than invented** — five or six random
words from a large list, or 20+ random characters from a password manager — and
used for nothing else. **It is not the vault passphrase, and it is not kept the
way one is.** Losing this one is the cheap failure (`key-custody.md` §5):
generate a new key, run `key-custody.md` §6's rotation, and every signature
already published stays valid and checkable. Losing a vault passphrase is
final. So the effort here
goes into **strength, not into copies** — this passphrase is the only thing
between a copy of the key file and the key itself (D71 §2 R7.1), and
`key-custody.md` §4 requires that copies of that file exist.

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
2. Write the passphrase down **once**, on paper, and keep it somewhere you
   control that is **neither** backup location from step 1 — a passphrase kept
   beside the key file it wraps is not a passphrase. Do not make a second copy
   for safety: losing it costs a rotation (`key-custody.md` §5), while a copy in
   the wrong place costs the key.
3. Add the first row to `key-custody.md` §10 — date, "generated", key id.

**Why steps 1 and 2 gate §3 and not only §4** (D153 §2 R4): §3 anchors *this*
key, and an anchor cannot be transferred to a replacement. D71 §A R4 puts the
anchor in a narrow window — *"a few days before the release date"* — so a key
lost after §3 and before the release costs the anchor **and** the window on top
of the regeneration. Loss is the failure `key-custody.md` §5 calls the cheap one
*because* published signatures survive it; before §3 there is nothing to survive,
and the backups are what keep it cheap.
D153 §1.7 measured what that costs concretely rather than theoretically, on a
key that was then single-copy on a shared-use machine. §7 records whether the
backups exist today; this section states only why they gate §3.

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
- **The page footer's key element and marker pair EXIST as of 2026-08-22 (`R96`).**
  They live in `verifier-web/index.template.html` and in nothing else, because
  `crates/antseal-wasm/tests/page_template.rs` asserts that directory holds
  exactly `index.template.html`. The markers carry the **same name** the README
  pair does (`minisign-public-key`), so step 4's "one act" is one grep. Today the
  block reads that no key is published yet, and that two-state invariant is
  asserted — the test requires the block to be *either* the placeholder sentence
  *or* a key-shaped run, never both and never neither, so it does not obstruct
  this step. **Superseded here:** until 2026-08-22 this bullet read *"The page
  footer has no key element and no marker to write into"* and recorded that
  `verifier-web/` carried the word `minisign` zero times. Both were true when
  written and both are now false — the template and the built page carry it four
  times each. **A hazard this step must know about:** `docs/ci-verification.md`'s
  pre-flip check A6 greps **`README.md` only**, which was complete only while the
  footer could not hold a key. The page is already live and public while the
  repository is private, and `scripts/pages-publish.sh` contains no occurrence of
  `key`, `signing` or `minisign` — so a key placed in the footer reaches the world
  through a publish that never touches `Q65`'s flip. Owned by `Q262`.

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
  the move described in §1 and all three pass. **§1a step 3 (the §10 generation row)
  was complete on the same day.**
- **§1a step 1 RUN 2026-08-22 — the two offline backups exist, and §3 and §4 are no
  longer blocked by them.** Separate media — one USB device and one paper copy — held
  off-site, each carrying `minisign.pub` as well as the secret key, as `key-custody.md`
  §4 requires. Each was verified **from the backup copy rather than from the original**:
  `minisign -R` re-derived key id `3E5D46890F192F58` from both, which in one step
  establishes that the copy is intact, that it parses as a genuine passphrase-wrapped
  secret key, and that the recorded passphrase decrypts it. Appended as the second row
  of [`key-custody.md`](key-custody.md) §10. **The key is no longer single-copy** — the
  measurement in D153 §1.7, and the exposure it describes, are superseded as of this
  date. The media, the locations and their separateness are the maintainer's
  attestation; nothing here can verify them.
- **§1a step 2 is still outstanding, and is deferred on purpose.** It instructs the
  maintainer to record the passphrase *"where the vault passphrase is recorded"* — a
  referent that resolves, since it was written, to guidance for a different secret
  with the opposite loss profile (`docs/user/vault-theft.md`) — so following the
  pointer imports the wrong discipline rather than finding nothing — and the analogy
  inverts the risk model, since `key-custody.md` §5 makes signing-key loss the cheap
  failure while `docs/user/vault-loss.md` makes vault-passphrase loss final.
  **`Q259` owns the fix; take step 2 after it lands, not before.** Note that §1a
  step 1's verification above exercised the passphrase against both backups, so it
  is known-correct even though where it should be recorded is not yet settled.
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

### Which act releases what

Two fields, not one class word: what is *stopping* an act and when to *take* it
are independent, and one word for both is what D153 §2 R5 removed from this
section once already. Status stays in the bullets above; this table does not
restate it.

| act | who takes it | blocked by | take it when | releases |
|---|---|---|---|---|
| §1 generate | maintainer, own machine | — | — | §1a, and everything below it |
| §1a step 1 — two offline backups | maintainer | nothing | immediately after §1 | §3 and §4 (D153 §2 R4 moved this gate forward from §4 to §3) |
| §1a step 2 — record the passphrase | maintainer | **`Q259`** | after `Q259` lands, not before | nothing else; it closes the residue that a lost passphrase is a lost key |
| §2 — the registrar `TXT` pin | maintainer, at the registrar, **express in-the-moment consent naming action, destination and account** | **nothing — §1 is done** | any time from now. It must exist before §5, and D71 §A R4 calls it *"the one that should not be deferred"*; §A R5 clause 3's *"before first release"* is its outer deadline, not its schedule | §5, and with it `Q30` Accept row 1 |
| §3 — anchor the public key | maintainer, own machine + a public calendar | nothing (§1a step 1 discharged its gate) | **a few days before the release date — not now and not after** (D71 §A R5 clause 4) | §5 step 3's `minisign.pub.ots`; `Q30` Accept row 1 |
| §5 — publish the key in three places | **a lane, not the maintainer** — §5 is three repository edits, and the preamble above names only §1, §2 and §3 as external | §2 and §3 | after both | `Q30` Accept row 1; `R96` is the missing write target for step 2 |

`§1 → §3 → §2` at the top of this file is a **schedule**, not a dependency chain.
The only hard predecessor in the column above is §1.
