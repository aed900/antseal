# Checking an antseal download

Every antseal release is signed. This page shows you how to check a download
before you run it, what a green result means, and — just as important — what it
does not mean.

You need three things: the file you downloaded, its `.minisig` signature file
from the same release, and antseal's public key.

> **Not yet published.** antseal has not made its first release, so the key
> below is shown as a placeholder. When the first release ships, the real
> 56-character key replaces `RW<...56 characters...>` here, in the project
> README, in the page footer at <https://antseal.org/>, and in a `TXT` record
> on `antseal.org`.

## 1. Get the checking tool

minisign is a small, single-purpose tool — about 270 KB. **Get it from your own
operating system's package archive, not from us.** That is the point: a tool
obtained from antseal could not tell you anything trustworthy about a file
obtained from antseal.

```
Debian / Ubuntu   sudo apt install minisign
macOS             brew install minisign
Windows           scoop install minisign      (or: choco install minisign)
```

## 2. Check the file

One command per file you downloaded. There is no second step to remember.

```
minisign -H -Vm antseal-x86_64-unknown-linux-gnu.tar.gz \
  -P RW<...56 characters...>
```

`-H` is not optional. Always include it.

**A good result prints two lines, and you must read both:**

```
Signature and comment signature verified
Trusted comment: antseal v0.1.0 antseal-x86_64-unknown-linux-gnu.tar.gz commit:<40-hex> <timestamp>
```

**Compare the second line against the release you meant to download.** The
version and the filename on that line are covered by the signature and cannot
be altered without the secret key. The first line alone is not enough, and here
is exactly why:

> If someone serves you **an older antseal release together with its own
> genuine signature**, the first line still says *"Signature and comment
> signature verified"*. It is true — that older release really was signed by
> this key. Nothing about a signature can detect that you were handed last
> year's version instead of this one. **The second line is what tells you
> which release you actually have.**

If the version, the filename or the commit on that line is not the release you
went to download, stop, whatever the first line said.

**A bad result** prints one of these and exits non-zero:

| what you see | what it means |
|---|---|
| `Signature verification failed` | the file's contents are not what was signed — it has been altered or corrupted |
| `Comment signature verification failed` | the trusted-comment line has been edited |
| `Signature key id in … is …, but the key id in the public key is …` | this file was signed by a different key from the one you supplied |
| `Legacy (non-prehashed) signature found` | an old-format signature; antseal does not produce these |

In every one of those cases: **do not run the file.**

## 3. Check the rest of the release together

The release also carries `SHA256SUMS`, listing every artifact, and
`SHA256SUMS.minisig` signing that list. After checking the list itself with the
command in §2, check every file against it at once:

```
sha256sum -c SHA256SUMS
```

Do both. Checking `SHA256SUMS.minisig` on its own and then running the binary
without `sha256sum -c` tells you nothing about the binary.

If you have a shell and the antseal source, `scripts/verify-release.sh` does
the whole directory — every signature, every trusted comment and the digest
list — in one command:

```
scripts/verify-release.sh --version v0.1.0 --commit <40-hex> \
  --dir ./download --key RW<...56 characters...>
```

## 4. Where to get the key, and how much each source is worth

The same 56 characters are published in four places. They are **not** equally
useful, and this section says so plainly rather than listing them as if they
were.

- **The project README and the page footer at <https://antseal.org/>** are for
  discovery. They are served by the same account and the same hosting that
  serves the release itself, so someone able to replace a release binary is
  able to replace the key beside it in the same act. **Taking the key and the
  binary from there in the same minute adds very little over the transport
  security you already had.**
- **The `TXT` record on `antseal.org`** is the one that is worth something
  against that attack, because changing it needs the domain registrar account
  rather than the code-hosting account:

  ```
  dig +short TXT antseal.org
  ```

  Note the limit: `antseal.org` is not DNSSEC-signed, so this record is not
  protected against an attacker positioned on your network or a hostile
  resolver. It is independent of a compromise of the code host; it is not
  independent of everything.
- **`minisign.pub` inside the release** is there so you can compare key ids
  within a directory you already have.
- **`minisign.pub.ots`** is an OpenTimestamps proof that this exact key existed
  before a particular Bitcoin block. It shows the key is not new. It does not
  show whose key it is.

**Where a signature genuinely helps you** is not the first download at all. It
is (a) a copy that reached you by some other route — a mirror, a cache, a
colleague, a USB stick — which you can check against a key you obtained once
from a place you chose, and (b) *later*: if you keep this key, a substituted
future release is detectable even if the project's hosting is fully compromised
at that later moment. Keeping the key is what makes the scheme worth anything.

## 5. What a green check does and does not tell you

**It tells you:** the holder of antseal's key released exactly these bytes,
under the version and commit shown on the trusted-comment line.

**It does not tell you:**

- that the software is safe, correct, or free of defects;
- that it is the newest release — see the replay note in §2;
- that these bytes correspond to the published source. That is a *reproducible
  build*, which is a different and stronger check, and **the antseal command-line
  binary does not support it yet.** Do not read a signature as a claim that you
  could rebuild this binary and get the same bytes; today you could not. The
  verifier page is reproducible; the command-line binary is not.
- anything with legal effect. A signature here is evidence about bytes, and
  nothing more.

**There is no way to withdraw a key.** minisign has no revocation and no
expiry, and antseal does not have a mechanism that can reach you after the
fact if this key is ever compromised. If that happens, the project can only
publish a new key and say so; a user who pinned the old one is not reachable.
[`key-custody.md`](key-custody.md) §6–§7 is the whole story, written down so
nobody assumes a safety net that is not there.

## 6. If a check fails

Do not run the file. Re-download it from the release page, and check it again.
If it fails a second time, open an issue and include the exact message and the
full trusted-comment line printed by minisign — never a screenshot of a shell
where a passphrase might be visible.
