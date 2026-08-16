# D71 — The binary signing mechanism, where the public key is pinned, and the custody rules for a key that can never be revoked

> **AMENDED 2026-08-16 — READ THE ADDENDUM BEFORE §3.** Q65 has resolved toward
> making the repository **public**. The refusal of cosign in §3 below, and clause
> **(c)** of the Status block, rest on the repository being private; that
> argument is **WITHDRAWN**. The ruling is unchanged and is re-argued on
> self-contained verification in **§A R2**. Everything measured in §1 stands.
> This pointer exists so no reader meets the withdrawn argument first; the body
> is left as written, because this project amends by dated addendum and does not
> rewrite history.

- **Status: RESOLVED. The maintainer's choice of minisign is CONFIRMED, but not
  for the reason given, and cosign is REFUSED on a ground no brief in this round
  named.** The lean was *"minisign: one Ed25519 keypair I hold, no external
  service or account, CI never sees the secret key, public key pinned in the
  README/page."* The **tool** survives every attack run at it. **Two of its four
  supporting clauses do not.**
  **(a) "public key pinned in the README/page" is refused as a security claim.**
  Measured today: `https://antseal.org/` resolves to `185.199.108–111.153` and
  answers `server: GitHub.com` — it **is** GitHub Pages (D62 §3 R2 says so; this
  record measures it) — and its TLS chain is **byte-for-byte the same issuer
  path** as GitHub's release-asset host: both terminate at
  `Let's Encrypt YR1` → `ISRG Root YR`, and `objects.githubusercontent.com`
  presents a certificate whose subject is literally `CN = *.github.io`. The page,
  the README and the release assets are **one trust root, one account, one CA
  path**. A public key pinned there proves nothing a first-time user did not
  already get from TLS. The pin has to leave GitHub, and §2 R5 rules where.
  **(b) "CI never sees the secret key" is a true statement about a threat that
  is not the binding one.** It is kept — §2 R7 forbids the key on any runner —
  but the argument that actually decides against cosign is different and much
  harder, and it is (c).
  **(c) THE REPOSITORY IS PRIVATE.** `GET repos/aed900/antseal` returns
  `"private": true`; an unauthenticated fetch of `https://github.com/aed900/antseal`
  returns **HTTP 404**. **Q65 — publish-scope decision + the pre-public scrub —
  is OPEN.** Cosign keyless signing from GitHub Actions mints a Fulcio
  certificate carrying `Source Repository URI`, `Source Repository Digest`,
  `Source Repository Ref`, `Source Repository Identifier`,
  `Source Repository Owner URI`, `Build Signer URI` and — an OID that exists
  precisely because this matters — `Source Repository Visibility At Signing`
  (`1.3.6.1.4.1.57264.1.22`, *"For example: `private` or `public`"*), and writes
  it into **Rekor, a public append-only log that answers HTTP 200 to an
  unauthenticated `GET`, is searchable at `search.sigstore.dev`, and from which
  nothing can ever be deleted.** Cosign keyless would therefore **publish the
  identity of a private repository, irreversibly, into a permanent public log,
  before the decision about whether to publish it has been taken.** That is not
  a tension with the offline ethos. It is Q65 pre-empted by a side effect, and it
  cannot be undone. **Cosign is refused on that, not on Sigstore's reachability**
  — though the reachability finding is real and recorded in §3.
- **A fourth clause is confirmed and sharpened rather than overturned**: the
  register's third option, *"both"*, is refused, but §2 R6 rules an **anchor**
  that recovers the one property cosign genuinely has and minisign does not —
  public, dated, third-party-checkable evidence that this key is not new — using
  **this project's own OpenTimestamps machinery** and publishing **only an opaque
  digest**, never a repository name. That arm was in no brief.
- **Date: 2026-08-16**
- **Owning task: Q30.**
- Related: **D72** (release target set, distribution channel, crates.io scope —
  it owns the artifact **set**; this record rules the signing **function** over
  whatever set D72 picks, and §5 keeps the boundary), **Q31** (release workflow),
  **Q32/Q34** (the M4 gate's clean machine), **Q65** (publish scope — load-bearing
  here, see §1.1), **D62 §3 R1/R2** (the canonical URL, and that its host is
  GitHub Pages from `aed900/antseal`), **D63 §5 R4** and **D129 §5 R7** (the page's
  `SHA256SUMS`, authoritative *only* in its signed-release copy — and the filename
  collision that creates, §1.5), **D129 §5 R6 / §1 (m)**, **D66** and
  **`MVP-SPEC.md:127`** (the page's CSP is `connect-src https:` and its six pinned
  endpoints are measured browser-usable, so this project is *offline-first*,
  **not** offline-only — §3 states the cosign-vs-offline argument in the only form
  that survives that), **R25/R86/D135** (the two-environment
  reproducible build, which is wasm-only — §1.4), **Q2 / `secret-guard`** (which
  already greps for a minisign secret key, measured in §1.6), **D40** (scrypt as
  this project's chosen password KDF — minisign's own secret-key KDF, §4),
  **A109/D104** (the *"expires at first release"* class this record joins),
  **U32** (CLI surface freeze — why §2 R6 adds no subcommand).

---

## 1. The measurement

Everything in this section was produced today, 2026-08-16, by the command shown.
Nothing is transcribed from the brief; where the brief and the measurement
disagree, §6 says so.

### 1.1 The trust bootstrap, traced literally

The M4 gate (TODO.md:794) requires *"exactly ONE mainnet smoke seal verified
end-to-end **from a clean machine** using only the **released signature-checked
binary** + hosted page"*. To *check* a signature the clean machine needs the
tool and the authentic public key. Where does each come from?

```
$ dig +short antseal.org A
185.199.109.153   185.199.110.153   185.199.111.153   185.199.108.153

$ curl -sSI https://antseal.org/ | head -3
HTTP/2 200
server: GitHub.com
content-type: text/html; charset=utf-8
        (also: x-github-request-id, x-github-edge-region: uksouth)
```

**The page is GitHub Pages.** Those four addresses are GitHub's Pages anycast
set. D62 §3 R2 already states the host; this is the live confirmation.

The certificates are not merely *both* Let's Encrypt — they are the **same chain**:

| host | leaf subject | intermediate | root |
|---|---|---|---|
| `antseal.org` | `CN = antseal.org` | `C=US, O=Let's Encrypt, CN = YR1` | `C=US, O=ISRG, CN = Root YR` |
| `objects.githubusercontent.com` | **`CN = *.github.io`** | `C=US, O=Let's Encrypt, CN = YR1` | `C=US, O=ISRG, CN = Root YR` |

`objects.githubusercontent.com` is where a GitHub release asset is actually
downloaded from, and its SAN is
`*.github.com, *.github.io, *.githubusercontent.com, github.com, github.io, githubusercontent.com`.
**One wildcard certificate covers the release download path and the Pages
namespace, from the same intermediate, under the same root.** The "different
host, different TLS cert" intuition the brief asked me to test is **false at the
certificate level**, not merely weak at the account level.

`antseal.org`'s leaf expires `Nov 12 21:39:12 2026 GMT`, consistent with the
`https_certificate` state R26 recorded.

**And the repository is private:**

```
$ gh api repos/aed900/antseal --jq '{private,visibility,has_pages}'
{"has_pages":true,"private":true,"visibility":"private"}

$ curl -o /dev/null -w '%{http_code}' https://github.com/aed900/antseal
404
```

Two consequences the round must not skip:

1. **Today the ONLY public surface this project has is `https://antseal.org/`.**
   GitHub Releases on a private repository are not anonymously downloadable, so
   *"pinned in the README"* is not merely non-independent, it is **not readable
   at all** by the clean-machine user the gate names. Whatever D72 chooses as the
   distribution channel, **Q65 gates the pin as much as it gates the download**,
   and §2 R5 is written so that it works in both states.
2. **Anything that publishes repository identity is a Q65 decision, taken early
   and irreversibly.** §3 applies this to cosign.

**What the signature actually adds, stated honestly.** Against a first-time user
who takes the binary *and* the public key from GitHub in the same minute, a
minisign signature adds **almost nothing** over TLS: an attacker who can replace
one can replace both, and the check is then green because nothing reachable
could redden it — this project's dominant defect class
(`docs/instrument-ledger.md`), in a new suit. It adds real security in exactly
three places, and §2 is built around them:

- **(a) Off-path copies.** The signature travels with the file; TLS does not. A
  binary from a mirror, a package manager, a cache, a colleague, or a USB stick
  is checkable against a key obtained once from the canonical place.
- **(b) Across time (trust on first use).** A user who pinned the key at v0.1
  detects a substituted v0.2 **even under total compromise of GitHub at that
  later moment** — provided the key is long-lived (§2 R8) and they kept it.
- **(c) The sums file.** Without a signature, `SHA256SUMS` is decoration: an
  attacker replacing the binary replaces the sums in the same act (§2 R2).

(b) is the property worth the most and the one most easily lost, which is why
§2 R8 forbids routine key rotation and §2 R6 anchors the key's age.

### 1.2 What it costs a clean machine to obtain a verifier

**No signing or verifying tool is installed on this machine:**

```
$ for t in minisign rsign rsign2 cosign signify; do command -v $t || echo "$t (absent)"; done
minisign (absent)   rsign (absent)   rsign2 (absent)   cosign (absent)   signify (absent)
        (present: gpg /usr/bin/gpg, sha256sum, openssl)
```

That is a finding, not a blocker — §2 R12 hands provisioning to Q30 — but it
means **no lane in this repository has ever executed the verification command
this record is about**, and the M4 gate will be its first run. The tamper matrix
in §1.3 exists because of that.

Download sizes, from each project's own latest release (2026-08-16):

| tool | asset | bytes |
|---|---|---|
| minisign 0.12 | `minisign-0.12-linux.tar.gz` | **271 043** |
| cosign v3.1.3 | `cosign-linux-amd64` | **141 178 250** |

**520.9×.** minisign's macOS build is 81.5 KB and its WebAssembly build is
47.6 KB. This matters for a *clean-machine* gate: the verifier tool is itself
something the user must obtain and trust, and 271 KB of C is a different
proposition from 135 MB of Go.

**Both are packaged, which is the part that actually solves the bootstrap:**

```
$ curl -s https://sources.debian.org/api/src/minisign/  →  0.12-1 (trixie, forky, sid), 0.11-1 (bookworm)
$ curl -s https://sources.debian.org/api/src/cosign/    →  3.1.1-1 / 2.6.3-1 (forky, sid), 2.5.0-2 (trixie)
```

minisign's own README lists `brew install minisign`, `scoop install minisign`,
`choco install minisign`. **`apt install minisign` is a genuinely independent
trust root** — Debian's archive, Debian's signing keys, no GitHub — and it is
the answer to *"where does the tool come from"*. It is not an answer to *"where
does the key come from"*; that is §2 R5.

Rust-native, from crates.io today:

| crate | version | note |
|---|---|---|
| `rsign2` | 0.6.6 | pure-Rust CLI, `cargo install rsign2` |
| `minisign` | 0.9.1 | sign + verify library |
| `minisign-verify` | 0.2.5 | **zero-dependency verify-only**, 11 480 067 downloads |

`minisign-verify` being zero-dependency and verify-only is what makes §6's
follow-up row plausible rather than speculative.

### 1.3 The scheme, verified end-to-end, and the tamper matrix

The format is specified at `https://jedisct1.github.io/minisign/`:

```
untrusted comment: <arbitrary text>
base64(<signature_algorithm> || <key_id> || <signature>)
trusted_comment: <arbitrary text>
base64(<global_signature>)
```

with `signature_algorithm` = `Ed` (legacy) or `ED` (hashed), `key_id` 8 bytes,
`signature` (prehashed) = `ed25519(Blake2b-512(<file data>))`, and — the load-
bearing line —

> `global_signature` : `ed25519(<signature> || <trusted_comment>)`

so **the trusted comment is authenticated and the untrusted comment is not.**
Upstream states the purpose in as many words: *"Trusted comments can be used to
add instructions or application-specific metadata such as the intended file
name, timestamps, resource identifiers, or version numbers **to prevent
downgrade attacks**."* §2 R4 takes them up on it.

The public key is `base64(alg || key_id || public_key)` = **42 bytes → 56 base64
characters**, and `-P` accepts it inline as a single command-line token
(verified: the published minisign key decodes to 42 bytes beginning with ASCII
`Ed`). **56 characters fits in a DNS TXT string, a README line, a page footer,
and on a printed card** — that is what makes §2 R5 cheap.

Because no minisign binary exists here, the scheme was implemented from the
published spec in ~40 lines of Python (`cryptography`'s Ed25519 + `hashlib.blake2b`)
and run against **a real third-party release** — minisign's own
`minisign-0.12-linux.tar.gz` (271 043 B) and its `.minisig`, under the published
key `RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3` (key id
`1fe8b442180f62e7`). Then every field was mutated:

| # | mutation | key id | alg `ED` | content sig | global sig | verdict |
|---|---|---|---|---|---|---|
| 1 | none (real upstream artifact) | pass | pass | pass | pass | **ACCEPT** |
| 2 | one data byte flipped | pass | pass | **FAIL** | pass | REJECT |
| 3 | trusted comment `0.12`→`0.13` | pass | pass | pass | **FAIL** | REJECT |
| 4 | untrusted comment fully rewritten | pass | pass | pass | pass | **ACCEPT** |
| 5 | attacker's public key substituted | **FAIL** | pass | **FAIL** | **FAIL** | REJECT |
| 6 | **the 0.11 release + its own valid 0.11 signature** | pass | pass | pass | pass | **ACCEPT** |

Rows 2, 3 and 5 fail on **distinct** checks, which is the property the house
tamper-matrix discipline asks for. Rows 4 and 6 are the findings:

- **Row 4** — the untrusted comment is attacker-controlled and the artifact still
  fully verifies. Any documentation that shows it as if it were provenance is
  wrong. §2 R4 forbids putting anything meaningful there.
- **Row 6 is the one that shapes this record.** The previous release,
  `minisign-0.11-linux.tar.gz`, presented with **its own genuine signature** under
  **the same key**, produces a complete ACCEPT. A content signature structurally
  cannot detect replay or downgrade. The only thing that distinguishes the two is
  text minisign **prints but does not check**:

  ```
  trusted comment: timestamp:1673952371  file:minisign-0.11-linux.tar.gz  hashed
  trusted comment: timestamp:1737030580  file:minisign-0.12-linux.tar.gz  hashed
  ```

  Upstream's success output is, verbatim from `src/minisign.c:556-557`,
  `"Signature and comment signature verified\nTrusted comment: %s\n"`. **A user
  who reads line 1 and ignores line 2 has no downgrade protection.** That is an
  assertion that cannot fail, relocated into the user's hands, and §2 R4 and
  §2 R3 exist to close it.

Two more facts read from `src/minisign.c` rather than from the help text:
`minisign.c:513-518` rejects a legacy (non-prehashed) signature **only when `-H`
is given**, printing `Legacy (non-prehashed) signature found` and `exit(1)`; and
`-Q` ("pretty quiet") prints **only the trusted comment**, which is what turns
the human read into a machine check (§2 R3).

### 1.4 The CLI binary is NOT reproducible today

The brief asked for this to be measured rather than assumed. It was.

```
$ grep -rn 'remap-path-prefix' .            (excluding target/)
scripts/wasm-pack-build.sh:161      case " $REMAP " in *" --remap-path-prefix=..."*) ...
scripts/wasm-pack-build.sh:167      REMAP="${REMAP:+$REMAP }--remap-path-prefix=${from}=${to}"
        (+ documentation hits in docs/, TODO.md, tasks/, docs/decisions/)
```

`--remap-path-prefix` appears in **exactly one executable location, the wasm
build script**. `.cargo/config.toml`'s `rustflags` sit under
`[target.wasm32-unknown-unknown]` and reach no native build.
`scripts/reproducible-build.sh` builds `wasm32` only (`:394` — *"build B: wasm32
release"*). The workspace `Cargo.toml` has **no `[profile.release]`** at all.

The consequence, measured on the binary that is actually in the tree:

```
$ strings -a target/debug/antseal | grep -c '/home/deb/.cargo/registry'   → 2138
$ strings -a target/debug/antseal | grep -c '/home/deb/Documents/code0'   →    8
```

**R25/R86/D135's byte-reproducibility result covers the verifier page and
nothing else.** A third party cannot today rebuild `antseal` and compare — which
is the check that would be *stronger* than any signature, because it needs no
key and no trust in the maintainer at all. §2 R10 rules the relationship and
§6 raises the row.

### 1.5 A filename collision nobody has named

D63 §5 R4 and D129 §5 R7 rule that the verifier page ships a `SHA256SUMS` over
its served closure, and that this file is authoritative **only in its
signed-release copy** — i.e. it is destined for the release. `scripts/pages-publish.sh:83-96`
builds it as `target/verifier-web/SHA256SUMS`.

A GitHub release asset namespace is **flat**. A release-wide `SHA256SUMS` and
the page's `SHA256SUMS` cannot both exist in it. §2 R2 resolves this.

### 1.6 What the repository already enforces

`scripts/ci-lanes.sh:1075-1093` (`secret-guard`, an **unfiltered** CI lane per
D138 §2 R3) scans the checkout for secret-key markers. Its patterns were tested
against the literal header lines the candidate tools emit:

| planted line | caught by |
|---|---|
| `untrusted comment: minisign encrypted secret key` | pattern (4), `minisign encrypted secret key` |
| `-----BEGIN ENCRYPTED SIGSTORE PRIVATE KEY-----` | pattern (1), `[-]{5}BEGIN[ A-Z0-9]*PRIVATE KEY[-]{5}` |
| `-----BEGIN ENCRYPTED COSIGN PRIVATE KEY-----` | pattern (1) |
| `AGE-SECRET-KEY-1…` | pattern (4) |

**The custody rule "the secret key never enters the checkout" is already
mechanically enforced, for either tool, on every push.** §2 R7 relies on this
rather than inventing a new guard, and names the gap it does not cover.

---

## 2. The ruling

### §2 R1 — The mechanism is **minisign**. One long-lived Ed25519 keypair, held by the maintainer, signing performed locally. Cosign is refused (§3); "both" is refused.

The reference implementation is `minisign` (jedisct1). `rsign2` (crates.io
0.6.6) is the sanctioned interoperable alternative for producing signatures and
**must** produce artifacts a stock `minisign` verifies; a release signed with
either is verified by either. Signatures are Ed25519 and, in the reference
implementation, **deterministic**, so re-signing an unchanged artifact under an
unchanged trusted comment reproduces the same bytes — a property §2 R9's
rotation drill uses.

The secret key is **never** present on any CI runner, in any GitHub secret, in
any KMS, or in the checkout. Signing is a local act by the maintainer.

### §2 R2 — **Both**, and the sums file is the one that gets renamed. This settles `MVP-SPEC.md` line 157.

Line 157 was read directly (`sed -n '157p' MVP-SPEC.md`) and mandates
**`binary signing (sha256sums + minisign/cosign)`**. **The brief's gloss —
"BOTH" — is right about the conjunction and would be wrong if read across the
slash**: the spec conjoins *sums* with *a signature scheme*, and the slash
between `minisign` and `cosign` is a **disjunction this record resolves in
favour of minisign**. Nothing in line 157 requires both tools.

The release carries:

1. **`SHA256SUMS`** — one line per released artifact, in `sha256sum` format,
   listing every artifact except itself and except `*.minisig`.
2. **`SHA256SUMS.minisig`** — a signature over it.
3. **`<artifact>.minisig` for every artifact in `SHA256SUMS`** — a signature over
   each one individually.

**Signing only the sums file is refused**, because it makes the binary's
integrity depend on the user remembering to run a *second* command: a user who
verifies `SHA256SUMS.minisig` and then runs the binary without
`sha256sum -c SHA256SUMS` has verified nothing about the binary, and nothing
tells them so. **Signing only the artifacts is refused**, because line 157
mandates a sums file and an unauthenticated mandated file is a trap — a user who
treats it as their integrity source gets nothing. Signing costs milliseconds and
~320 bytes per artifact; the correct answer is both, and the per-artifact
signature is the one the user is told to use (§2 R3).

**The page's manifest is renamed on upload.** The file
`target/verifier-web/SHA256SUMS` that D63 §5 R4 and D129 §5 R7 send to the
release enters the release asset namespace as **`verifier-web-SHA256SUMS`**, is
listed in the release-wide `SHA256SUMS`, and is therefore transitively signed.
D63 and D129 are untouched: they govern the built and deployed directory, not
the release asset name. If Q31 prefers a different qualified name it may take
one, provided the release-wide manifest keeps the bare name `SHA256SUMS` — the
name a user's muscle memory types — and covers the page's.

### §2 R3 — The exact command a user runs, and the exact command a script runs

**Documented for humans (README, install doc, release notes), one command per
artifact, no second step to forget:**

```
minisign -H -Vm antseal-x86_64-unknown-linux-gnu.tar.gz \
  -P RW<...56 characters...>
```

- `-H` is **mandatory** in every documented invocation. Without it minisign
  accepts a legacy `Ed` signature (`minisign.c:513-518`); with it the algorithm
  code is pinned to `ED` and the accepted format is exactly the one we emit. It
  is free and it removes a variant nothing here will ever produce.
- `-P <key>` inline, **not** `-p keyfile`, in the documented form. A 56-character
  token in the command the user copies keeps the key visible at the moment of
  use, instead of hiding it in a file whose provenance they have already
  forgotten.
- Expected output, verbatim from `minisign.c:556-557`:
  ```
  Signature and comment signature verified
  Trusted comment: antseal <version> <artifact> commit:<sha> <RFC3339 UTC>
  ```
- **The documentation must print the expected trusted comment next to the
  command and instruct the reader to compare it.** §1.3 row 6 is the reason: the
  first line is true of a replayed old release too.
- Exit status is 0 on success and 1 on any failure (`minisign.c`), so it is
  scriptable.

**Machine-checked form, for `scripts/verify-release.sh` (Q30), the M4
clean-machine procedure (Q32) and CI:**

```
test "$(minisign -Q -H -Vm "$art" -P "$KEY")" = "$EXPECTED_TRUSTED_COMMENT"
```

`-Q` prints **only** the trusted comment (`minisign.c:558-560`), which converts
"a human should read line 2" into a string equality that can go red. **This is
the only form the gate may use.** A gate that asserts exit status alone is green
against §1.3 row 6 and is therefore an assertion that cannot fail.

Bulk check, after either form:

```
sha256sum -c SHA256SUMS
```

### §2 R4 — The trusted comment is a required, structured, authenticated field. The untrusted comment carries nothing.

Every signature this project emits is produced with an explicit `-t`:

```
minisign -Sm <artifact> -t 'antseal <version> <artifact-basename> commit:<full 40-hex sha> <RFC3339 UTC timestamp>'
```

It is covered by `ed25519(<signature> || <trusted_comment>)` and so cannot be
altered without the secret key (§1.3 row 3, measured FAIL on the global
signature). The **artifact basename** and the **version** are what defeat
cross-artifact and downgrade presentation; the **commit** is what ties a release
to a tree; the **timestamp** is the maintainer's claim, not an anchor, and the
docs must not present it as one — this project's own positioning discipline
applies to its own release notes.

**The untrusted comment is left at minisign's default and must never be used to
carry version, filename, provenance or any other meaningful datum**, because it
is freely modifiable after signing and the artifact still fully verifies
(§1.3 row 4, measured ACCEPT). Q30's docs must not display it.

### §2 R5 — Where the public key is pinned. **The page and the README are pins of convenience; the DNS TXT record is the only pin that is a different control plane.**

The key is published in **four** places, and the record states plainly what each
is worth:

| location | different control plane from GitHub Releases? | what it is for |
|---|---|---|
| `https://antseal.org/` (page footer) + README | **NO** — same GitHub account, same Pages/asset CA chain (§1.1) | discovery and convenience; today the only *public* one (§1.1) |
| **`TXT` at `antseal.org`** | **YES** — changing it requires the **Porkbun** registrar account, not the GitHub one | the pin that survives a GitHub compromise |
| the release itself (`minisign.pub` as an asset) | NO | so a user who has the release directory has the key id to compare |
| the OTS-anchored copy | **YES** — Bitcoin (§2 R6) | evidence the key is not new |

The DNS record is exactly one string and fits trivially inside a TXT record's
255-character limit:

```
antseal.org.  IN  TXT  "antseal-minisign-key=RW<...56 characters...>"
```

**Adding it is an EXTERNAL ACTION at the registrar and is NOT taken by this
record or by any agent.** It joins Q33's class of externally-actioned rows and
is listed in §6.

**Two honest limitations, recorded rather than glossed:**

1. **`antseal.org` is not DNSSEC-signed.** Measured over DNS-over-HTTPS today:
   the `DS` query returns `Status 0` with **no answer**, and every response
   carries **`AD: false`**. So the TXT pin is **not** authenticated against an
   on-path or hostile-resolver attacker. It *is* independent of the threat this
   record is actually about — compromise of the GitHub account or of GitHub —
   because forging it requires the registrar account instead. Saying it defends
   both would be false. There are today **no TXT records at all** on the zone.
2. **The README pin is not readable while the repository is private** (§1.1).
   Until Q65 rules, the page footer and the DNS record are the only pins a
   stranger can reach.

**Refused as independent pins, with the reason:** *crates.io* — its default
account identity is GitHub OAuth, so it is at best partially independent, and
whether antseal publishes there at all is **D72's** to decide; *a keyserver* —
minisign has no keyserver ecosystem, and reaching for one means reaching for
PGP, refused in §3; *`gh attestation`* — GitHub again, and unreadable for a
private repository.

### §2 R6 — The public key is OpenTimestamps-anchored, and this is what recovers the property cosign would have bought.

`minisign.pub` is anchored with **this project's own OTS submit client** (the
A13 machinery in `crates/antseal-anchor/src/ots/`, upgraded per A14) and the
resulting proof is published beside the key as **`minisign.pub.ots`**, in the
release and at the canonical URL.

**What it buys.** Rekor's real gift is not the signature — it is that a *silent*
substitution becomes *publicly detectable*, because the log is append-only and
dated. An OTS anchor gives the same shape of evidence from a completely
different root: anyone, offline once the proof is upgraded, can establish that
**this exact 42-byte key existed before a specific Bitcoin block**. An attacker
who substitutes a key next year can anchor their key **only as of next year**.
The discriminator is the date, and the date becomes a published, third-party-
checkable fact instead of a claim.

**And it publishes an opaque digest, nothing else.** This is the precise
contrast with §3: both mechanisms write a permanent public dated record, but OTS
writes a hash, while Rekor writes the repository's name, owner, ref, commit and
visibility. **One is compatible with Q65 being open; the other decides it.**

**What it does NOT buy, stated so nobody trusts it past its limit.** An anchor
proves the key is *old*, never that it is *the maintainer's*. It does not help a
first-time user who has no expectation about the project's age. It defeats
substitution-after-the-fact, not an adversary present from day one. And it needs
an OTS verifier.

**No CLI surface is added.** `antseal`'s subcommands are
`Init · Seal · List · Show · Status · Restore · Reveal · Verify · Vault`
(`crates/antseal-cli/src/cli.rs:113-181`); there is no `ots` or `anchor`
subcommand and **U32 freezes that surface**. The stamp is taken with the
existing `anchor-smoke-driver` binary or the reference `ots` client, as a
release-time act, not by growing the shipped CLI.

### §2 R7 — Custody

1. **The secret key is passphrase-protected. `-W` is forbidden.** minisign
   encrypts it by default with **scrypt** (`kdf_algorithm: Sc`) at libsodium's
   `OPSLIMIT_SENSITIVE` / `MEMLIMIT_SENSITIVE`, with a 32-byte salt and a
   Blake2b-256 checksum. That is the same primitive family this project chose
   for its own vault in **D40**, at the strongest published parameter set;
   nothing further is needed and nothing weaker is acceptable. The passphrase is
   generated and stored the way the vault passphrase is, and is **not** the vault
   passphrase.
2. **It lives at minisign's default path, `~/.minisign/minisign.key`, on the
   maintainer's machine, plus offline backups** (§2 R8). It is never on a
   runner, in a GitHub secret, in a KMS, in the checkout, or in any file this
   repository tracks.
3. **The repository half is already enforced**: `secret-guard` catches
   `minisign encrypted secret key` on every push, on an unfiltered workflow
   (§1.6, measured). **What it does not cover**, said plainly: an *unencrypted*
   secret key produced with `-W` carries no such marker line and would not be
   caught — which is a second, independent reason `-W` is forbidden, and a
   candidate check in §6.
4. **The key is used for nothing else.** It is not an SSH key, not a git signing
   key, not the vault key, not a wallet key. Cross-protocol reuse of an Ed25519
   key is the domain-separation failure this project designs against everywhere
   else and it is not going to be introduced at the release boundary.

### §2 R8 — Backup and loss

Two offline backups of the encrypted `minisign.key`, on separate media, in
separate physical locations, plus the passphrase recorded by whatever means the
vault passphrase is recorded by. **The public key must also be backed up** — it
is recoverable from the secret key (`minisign -R`) but not from anything else,
and losing both is losing the identity.

**On loss of the secret key** (backups gone): no further release can be signed
under it. A new key is generated and §2 R9's rotation runs. **Every previously
published signature remains valid and verifiable** — this is the failure mode
that costs the least, and it is the reason offline backups are enough.

**Loss is more likely than compromise, and the asymmetry is deliberate**: the
scheme is arranged so the likely failure is survivable and the unlikely one is
at least detectable (§2 R6).

### §2 R9 — Rotation, and the fact that **revocation does not exist**

**minisign has no revocation, no expiry, no key hierarchy and no cross-signing.**
This is not an oversight in the tool and it is not something this record can
engineer around; it is a property of the scheme, and it is written down here so
that nobody later assumes otherwise.

**The key is therefore long-lived and is NOT rotated on a schedule.** Routine
rotation is refused: every rotation destroys the trust-on-first-use property of
§1.1 (b) for every user who pinned the old key, which is the single most
valuable thing the scheme provides. Rotation happens for exactly two reasons —
loss (§2 R8) and suspected compromise.

**The rotation procedure** (Q30 writes it into the custody doc; it is not
executed here):

1. Generate the new keypair; anchor the new public key (§2 R6) **before**
   publishing it, so its age is on record from the first day.
2. **Sign the new public key with the old key, if the old key is still held and
   is not the thing that was compromised.** `minisign -Sm minisign.pub -t 'antseal key rotation <date> supersedes <old key id>'`
   published as `minisign.pub.minisig`. This is the only continuity mechanism
   available and it is worth nothing in the compromise case — an attacker
   holding the old key can mint the same statement. **It helps in the loss case
   only, and the docs must say which.**
3. Update all four locations in §2 R5 **in one act**, and record the old key id
   and the date of the change in the custody doc, which is append-only.
4. Announce out of band on whatever channel D72 establishes.

**On compromise there is no mechanism that reaches a user who has already
pinned the old key.** All that can be done is announce, rotate, and state a
date — and because a compromise's start is rarely known, **every release signed
by that key must be treated as suspect for its whole lifetime**, not from the
date of discovery. That is a genuine weakness of the chosen mechanism, it is
accepted deliberately in exchange for §1.1 (b) and §2 R6, and §2 R11 forbids
release documentation that implies otherwise.

### §2 R10 — A signature and a reproducible build answer different questions. Neither substitutes for the other, and one of them does not exist yet.

- A **signature** attests: *the holder of this key released these bytes.* It says
  nothing about whether the bytes correspond to the published source.
- A **reproducible build** attests: *these bytes are what this source compiles
  to* — checkable by a third party **with no key and no trust in the maintainer
  at all**. It is the stronger check, and it is the only one that survives a
  maintainer who is himself the adversary.

**The CLI is not reproducible today** (§1.4: `--remap-path-prefix` is applied by
the wasm build script alone; the native binary in the tree carries 2 138
`$CARGO_HOME/registry` path strings and 8 checkout-path strings). Therefore:

**Release documentation must not claim, imply, or invite the inference that the
CLI binary can be independently rebuilt and compared, until the row in §6 lands.**
The page's reproducibility (R25/R86/D135) is a statement about the page. Saying
otherwise would be this project's own instrument-ledger defect committed in
prose.

When the CLI does become reproducible, **the signature is not retired.** It still
carries §1.1 (a) and (b), and it is what a user who will never run a compiler
relies on.

### §2 R11 — What the release documentation may not say

1. Not *"verified"* alone as a verdict on the software — a valid signature means
   the key holder released these bytes, and nothing about whether they are safe,
   correct, or the newest. §1.3 row 6 is the demonstration.
2. Not *"revoked"*, *"expired"*, or *"key rollover"* as if mechanisms existed
   (§2 R9).
3. Not any claim that the public key on the page or in the README is
   independently verifiable **while it is served from the same origin as the
   binary** (§1.1). The docs state where the independent pin is (§2 R5) and what
   it is worth.
4. Not any claim of a *legal* or *notarial* property of the signature. The
   project's standing positioning discipline applies to its own release notes.

### §2 R12 — Provisioning, pinning, and the fact that nothing here has ever run this

No signing or verifying tool is installed on this machine (§1.2). Q30 must
therefore rule provisioning as part of building the pipeline, on the same terms
`docs/dependency-policy.md` applies to every other pinned tool: a version, a
source, and a checksum. The candidates and their trade are measured in §1.2;
`apt install minisign` (Debian 0.12-1) and `cargo install rsign2 --version 0.6.6`
are both defensible and the choice is Q30's, not this record's.

**Whichever is chosen, the M4 gate is the first time this project will execute a
*release-artifact* signature verification.** (It verifies Ed25519, ML-DSA, RFC
3161 and CMS signatures inside `antseal-core` constantly; none of that machinery
touches the release boundary, and no lane has ever run the §2 R3 command.)
Q32's clean-machine procedure must include the §1.3
tamper cases — at minimum a flipped data byte, an edited trusted comment, and a
replayed previous release — because a verification step that has only ever been
run on a good artifact is a check nothing has shown can fail.

---

## 3. Why cosign is refused, and the one thing it really would have bought

**What it genuinely offers.** Keyless signing binds the signature to the GitHub
Actions OIDC identity and records it in Rekor, a public append-only transparency
log. A *silent* key substitution then becomes *publicly detectable* by anyone
monitoring the log — a property minisign's model does not have, and the brief is
right that it is real. §2 R6 is this record's answer to it.

**The inversion, named as the brief required.** The maintainer chose local
signing so that CI never holds a secret. Cosign keyless satisfies that clause
*literally and better* — there is no secret at all — while inverting what it was
protecting: **the CI workflow becomes the identity.** Anyone who can cause a
workflow to run on the release path can produce a signature that verifies, and
`--certificate-identity` is satisfied by construction. The secret moves from a
file the maintainer holds to a permission on a repository. That is the real
trade and it is not obviously the safer side of it.

**Why it is refused here is neither of those.**

Signing keyless from `aed900/antseal` mints a Fulcio certificate carrying, per
`sigstore/fulcio/docs/oid-info.md`:

| OID | claim |
|---|---|
| `1.3.6.1.4.1.57264.1.12` | Source Repository URI |
| `1.3.6.1.4.1.57264.1.13` | Source Repository Digest (commit SHA) |
| `1.3.6.1.4.1.57264.1.14` | Source Repository Ref |
| `1.3.6.1.4.1.57264.1.15` | Source Repository Identifier |
| `1.3.6.1.4.1.57264.1.16` | Source Repository Owner URI |
| `1.3.6.1.4.1.57264.1.9` | Build Signer URI |
| `1.3.6.1.4.1.57264.1.22` | **Source Repository Visibility At Signing** — *"For example: `private` or `public`"* |

and writes it to Rekor. Rekor is public and unauthenticated —
`GET https://rekor.sigstore.dev/api/v1/log` returns **HTTP 200** with the signed
tree head to any anonymous caller, and `search.sigstore.dev` returns **HTTP 200**
— and it is **append-only: nothing can be removed.**

**The repository is private and Q65 (publish-scope decision + pre-public scrub)
is open** (§1.1). Adopting cosign keyless would publish the repository's name,
owner, commit, ref and workflow path into a permanent public log **as a side
effect of a signing decision**, taking Q65's decision irreversibly and in the
opposite direction from the "pre-public scrub" that row exists to perform. That
the Sigstore project felt the need to mint an OID recording *whether the source
repository was private at signing time* is the ecosystem's own acknowledgement
that this is a thing that happens to people.

**The escapes, and why they are worse.** `--insecure-ignore-tlog` keeps the
entry out of Rekor, but cosign's own documentation says it plainly —
*"Artifacts cannot be publicly verified when not included in a log"* — so it
discards the only property cosign was reached for. Key-based (non-keyless)
cosign avoids Rekor too, and is then strictly dominated by minisign: a 141 MB
tool instead of a 271 KB one, PEM key files instead of a 56-character token, and
no transparency property to show for it.

**The offline finding, which is real, is smaller than it is usually stated, and
is not the reason.** The brief expected the refusal to rest on Sigstore
reachability. Measured against cosign v3.1.3's own reference documentation for
`verify-blob`: **the word "offline" does not appear in it at all — zero
occurrences; there is no `--offline` flag.** The bundle carries the signature,
certificate and transparency-log proof, but the **trusted root** must still come
from somewhere: either `--trusted-root trusted_root.json`, a *fourth* file whose
own authenticity is the same bootstrap problem one level up, or cosign's TUF
client over the network (the command carries `-t, --timeout duration (default
3m0s)`). And keyless verification **requires** the user to supply
`--certificate-identity` (or `-regexp`) **and** `--certificate-oidc-issuer` (or
`-regexp`) — exact strings they must obtain from the project — where minisign
requires one 56-character token.

**The version of this argument that says "antseal never touches the network" is
FALSE and must not be made.** A mid-round correction proposed it and it was
checked rather than transcribed. `MVP-SPEC.md:127` says **"Offline-first: full
local verification"** — *offline-first*, not offline-only. **D129 §5 R6** sets the
page's CSP to `connect-src https:`, **scheme-only and deliberately not the six
pinned hosts**, because §1 (m) of that record measured that naming them silently
breaks the endpoint overrides spec line 137 mandates. **D66** then measured all
six pinned endpoints — two esplora, four Arbitrum RPC — live in Chromium 150 and
found them browser-usable. **The shipped page makes network calls by design.**
Any refusal resting on "this project is offline" is disprovable from its own
decision records in one grep, and a record that leaned on it would deserve to
fall.

**The accurate form of the argument, which is narrower and survives.** The
guarantee is that verification must **terminate in a verdict** using only the
artifact in hand plus material the user already holds — the network layer is
always *additional*, never load-bearing. Binary-signature checking is the one
step where that matters most, because it sits **upstream of everything**: the
user cannot run the verifier, or the page, or anything else, until the binary is
trusted, so a signature check that cannot complete without a reachable third
party converts the very first step into "cannot determine". minisign meets the
requirement by construction — artifact, signature file, 56-character key, no
service. Cosign meets it only once the user has independently obtained a
`trusted_root.json`, which is the §1.1 bootstrap problem again, one level up and
in a less familiar shape. That is a genuine cost, materially smaller than the
brief implied, and it is a supporting reason rather than the deciding one — the
deciding one is the Rekor disclosure above.

**Also refused: PGP/GPG.** `gpg` is the one signing tool actually installed here
(§1.2) and that is not a reason. It brings a large, complex trust surface, a
keyserver ecosystem whose trust model has collapsed, and no property minisign
lacks. **Also refused: GitHub artifact attestations** (`actions/attest-build-provenance`
/ `gh attestation verify`) — GitHub is the trust root being defended against,
verification wants the `gh` CLI and network, and attestations on a private
repository are not publicly readable.

**The re-open condition, so this is a ruling and not a prejudice.** Revisit
cosign keyless if **all** of: (i) Q65 has ruled the repository public and the
scrub has run; (ii) the release channel is GitHub Actions rather than a local
act; and (iii) offline verification against a shipped trusted root is
demonstrated end-to-end on a clean machine with the network down. Until then,
minisign, with §2 R6 supplying the transparency property.

---

## 4. What this record does NOT decide

1. **The artifact SET.** Which targets are built and released — linux-only,
   +macOS, +Windows — is **D72**'s, together with the distribution channel and
   the crates.io publish scope. This record rules a **function over whatever set
   D72 returns**: every artifact in `SHA256SUMS` gets a `.minisig`, the manifest
   gets one, and the trusted comment carries that artifact's basename. The one
   concrete filename used as an example in §2 R3 is an illustration, not a
   commitment to a target triple.
2. **The versioning scheme and the release checklist** — Q31. This record
   constrains it in exactly two places: `SHA256SUMS` keeps the bare name
   (§2 R2), and the trusted comment carries version, basename and commit
   (§2 R4).
3. **Whether the repository becomes public, and when** — Q65. §1.1 and §3 record
   that it is private *today* and that this is load-bearing; they do not rule on
   changing it.
4. **Whether antseal publishes to crates.io** — D72. §2 R5 declines crates.io as
   an independent *pin* on its merits, which is a narrower statement.
5. **Provisioning: which minisign build, from where, at what pin** — §2 R12
   hands this to Q30 with the measurements to decide it.
6. **Making the CLI binary reproducible** — the finding is §1.4 and the row is
   §6; the work is not scoped here and its natural home is beside R25/R86.
7. **Adding minisign verification to `antseal` itself or to the verifier page** —
   §6 raises it; it is a dependency-policy and U32-freeze question, not this
   record's.
8. **Executing anything.** No key was generated, nothing was signed, no DNS
   record was created, nothing was published or pushed. The only artifacts this
   lane produced outside this file are throwaway scratch files used for the §1.3
   measurements, and the only keys involved were **minisign's own published
   public key** and a deliberately invalid substitute.

---

## 5. What this ruling owes

1. **The DNS TXT record at Porkbun (§2 R5) is an external action** requiring the
   registrar account and express in-the-moment consent. It is not taken here. It
   belongs beside Q33 in the externally-actioned class, and **until it exists the
   scheme has no independent pin at all** — a state Q30's custody doc must say
   out loud rather than describe the intended end state.
2. **The OTS anchor of the public key (§2 R6)** is a release-time act that needs
   the A13/A14 clients driven over a file that does not yet exist. It also needs
   an upgrade pass some days later (A14) before the proof is Bitcoin-attested;
   the release cannot wait for it, so the first publication carries a *pending*
   proof and the custody doc must say which state it is in.
3. **`docs/dependency-policy.md`** gains a row for whichever minisign build
   §2 R12 selects.
4. **`CONTRIBUTING.md`'s CI-lane table and `docs/ci-verification.md`** are
   untouched by this record — §2 R7 adds no CI lane, relying on `secret-guard`
   as it already stands (§1.6). If §6's `-W` check is built, that changes.
5. **No lane in this repository has ever run a signature verification** (§1.2).
   Q43's rule — *a lane that has never run is not evidence* — applies to every
   command quoted in §2 R3. The §1.3 matrix was executed against a real
   third-party artifact with an independent implementation of the published
   format, which is the strongest evidence available before minisign itself is
   installed; it is **not** a substitute for running the shipped tool, and Q30
   owes that run.

---

## 6. New work this record surfaces

Described, not registered — the registrar mints rows after the round.

1. **Make the CLI binary reproducible** (§1.4). `--remap-path-prefix` for the
   workspace root and `$CARGO_HOME/registry` on the native release build, a
   `[profile.release]` the release actually uses, and an extension of
   `scripts/reproducible-build.sh` past `wasm32`. This is the check that beats
   any signature (§2 R10) and today it exists for the page alone. Natural
   neighbours: R25, R86, D135, Q31.
2. **`scripts/verify-release.sh`** implementing §2 R3's `-Q` form, with a
   `--self-test` that plants the §1.3 mutations — flipped data byte, edited
   trusted comment, replayed previous release, substituted key — and asserts each
   is caught **by its own distinct failure**. Without the replay arm the script is
   green against the one attack a content signature cannot see.
3. **Extend `secret-guard` to an unencrypted minisign secret key** (§2 R7.3).
   The current pattern keys on the string `minisign encrypted secret key`, which
   a `-W` key does not contain — so the one form of the key that is catastrophic
   to commit is the one form the guard cannot see. Small, and squarely in the
   assertions-that-cannot-fail class.
4. **The `SHA256SUMS` filename collision** (§1.5, resolved by §2 R2 as
   `verifier-web-SHA256SUMS`). It touches D63 §5 R4 / D129 §5 R7's file on its way
   into the release and Q31 should carry the rename explicitly rather than
   discover it at release time.
5. **`minisign-verify` (0.2.5, zero-dependency) inside antseal** — an
   `antseal --verify-release` path, and/or the verifier page checking a release
   signature client-side, would let an already-trusted older binary vouch for a
   newer one and turn §1.1 (b)'s trust-on-first-use into a chain. It is a
   dependency-policy event and it collides with **U32**'s CLI surface freeze, so
   it is **v1.1 at the earliest** and is named here only so the option is not
   lost.
6. **`SPEC-REVIEW.md` / spec line 157's slash.** §2 R2 resolves `minisign/cosign`
   in favour of minisign. If the spec is ever amended, that line is where the
   resolution belongs.

---

## Addendum — 2026-08-16: Q65 resolves toward PUBLIC, the privacy refusal is WITHDRAWN, and cosign is re-argued on ground that does not move

**Read this before §3.** Later the same day this record was written, the
maintainer decided to **make the repository public**, consenting to a pre-public
scrub first (a scrub lane is running as this is written). **§3's central refusal
— that cosign keyless would irreversibly publish a private repository's identity
into Rekor while Q65 was open — rests on a premise that is being reversed, and
it is withdrawn as a deciding argument.** The conclusion does not change. The
*reason* does, and this project amends by dated addendum rather than by silently
rewriting the paragraph that was wrong.

**One precision the addendum must not blur, because it has an operational
consequence.** The repository is **still private at the time of writing** —
measured again just now: `gh api repos/aed900/antseal` returns
`{"private": true, "visibility": "private"}` and an anonymous fetch of
`https://github.com/aed900/antseal` still returns **HTTP 404**. What has changed
is the **decision**, not the state. The disclosure objection evaporates **on
execution, not on decision**, and Fulcio's OID `1.3.6.1.4.1.57264.1.22` records
*"Source Repository Visibility At Signing"* — permanently, in an append-only
log. So: **if cosign is ever adopted, no keyless signature may be produced until
the repository is actually public**, or the log will carry `private` for ever.
That constraint outlives this addendum and is §A R5.

### §A R1 — What depended on repo-privacy, and what did not

**Unsupported from now on** (do not cite these as reasons):

- The **third clause of the Status block**, *"(c) THE REPOSITORY IS PRIVATE"*,
  as a refusal ground.
- **§3's deciding argument** — the Rekor disclosure. Once the repository is
  public there is no private identity left to leak, and Rekor's transparency
  becomes available **at no disclosure cost**. The measurements in that section
  remain accurate (the OIDs exist, Rekor is public, append-only, and answered
  HTTP 200 unauthenticated); what fails is the *inference* from them.
- **§1.1 consequence 1**, *"the only public surface this project has is
  `https://antseal.org/`"* — true today, false after the flip (§A R6).
- **§2 R5's limitation 2**, *"the README pin is not readable while the
  repository is private"* — resolves on the flip (§A R6).
- **§4 item 3**'s framing of Q65 as undecided.

**Standing, entirely untouched** — none of these ever depended on visibility, and
each was measured:

- The **identical certificate chain** (§1.1): `antseal.org` and
  `objects.githubusercontent.com` both terminate at `Let's Encrypt YR1` →
  `ISRG Root YR`, the asset host's leaf subject being `CN = *.github.io`. **A
  public README is still not an independent pin** (§A R6).
- The **520.9× bootstrap difference** — 271 043 B against 141 178 250 B (§1.2).
- **minisign's Debian availability** (0.12-1 trixie/forky/sid, 0.11-1 bookworm)
  as an independent trust root for the *tool* (§1.2).
- The **replay/downgrade defect** and the whole §1.3 tamper matrix — properties
  of content signatures, not of repositories. §2 R3 and §2 R4 stand unmodified.
- **§2 R2** (both sums and per-artifact signatures), **§2 R7/R8** (custody and
  backup), **§2 R10** (the CLI is not reproducible: 2 138 `$CARGO_HOME/registry`
  strings in the native binary), **§2 R11**, **§2 R12**.
- **§1.2's finding that no signing tool is installed here**, and that no lane has
  ever run the §2 R3 command.

### §A R2 — The re-ruling: **minisign still wins, and it now wins on self-contained verification alone**

The case for cosign is stronger post-public than this record first allowed, and
it is stated at full strength before it is answered:

1. **Rekor gives publicly-detectable key substitution for free** — precisely the
   property §2 R6 had to reconstruct with an anchor.
2. **There is no long-lived secret at all.** This is the strongest point and it
   is conceded without qualification: it answers §2 R8 (loss) and most of
   **§2 R9 (no revocation)**, which this record itself called *"a genuine
   weakness … accepted deliberately"*. Cosign simply does not have that weakness.
3. **The Fulcio certificate binds repository, commit and ref cryptographically**,
   without depending on the maintainer remembering to type `-t` correctly — a
   structurally better version of §2 R4's downgrade defence.
4. **Zero custody burden**: no passphrase, no backups, no rotation drill.

**What still decides it, and it is one thing.** Verification must terminate in a
verdict from **the artifact plus material the user already holds**. Measured
against cosign v3.1.3's own reference documentation for `verify-blob`: **there is
no `--offline` flag — the word does not occur in it at all.** The bundle carries
signature, certificate and log proof, but the **trusted root** still comes either
from `--trusted-root trusted_root.json` — a further file with its own bootstrap
problem, which is §1.1's question one level up — or from the TUF client over the
network, on a command whose default is `-t 3m0s`. minisign needs an artifact, a
signature file, and 56 characters.

That matters here more than it would elsewhere because of **where this check
sits: upstream of everything.** The user cannot run the CLI, the verifier page,
or any `.sealproof` verification until the binary is trusted. A product whose
entire thesis is evidence that verifies without a reachable third party cannot
have a third party in the *first* link. (Per the §3 revision: the project is
**offline-first**, `MVP-SPEC.md:127`, not offline-only — D129 §5 R6's
`connect-src https:` and D66's six measured endpoints prove it makes network
calls by design. The claim is not "never online"; it is that the network layer is
always *additional*, and this one link cannot be.)

Two supporting points, one of which the change **strengthens**:

- **Verification complexity.** One flag and one token, against `--bundle` plus
  two mandatory identity strings. `--certificate-identity-regexp` and
  `--certificate-oidc-issuer-regexp` accept loose patterns, and a loose pattern
  makes the identity binding vacuous — this project's dominant defect class,
  reachable through a documentation typo.
- **Signing authority becomes a repository permission**, and **going public
  enlarges that surface**, not shrinks it: forks, pull requests and more
  attention on the release workflow. The maintainer's original instinct — that
  release authority should not live in CI — is *better* motivated after the flip
  than before. This is a modest point, but it moves in the opposite direction
  from the premise change and is recorded for that reason.

**The margin is now narrow, and the record says so rather than pretending the
privacy argument's collapse cost nothing.** What is being chosen is
**self-contained verification at the price of key-custody risk** (§2 R7–R9). That
is the trade, named plainly. Reasonable people could take the other side.

**"Both" moves from REFUSED to DEFERRED.** With disclosure cost gone, a
supplementary cosign keyless signature alongside a primary minisign one is
genuinely defensible — CI holding an identity that produces only a *secondary*
signature is far less dangerous than CI holding the primary. It is **not adopted
for MVP**: it is a second toolchain, a second pipeline, a second document, and a
second thing that breaks, for a property §2 R6 already provides — and it carries
a real hazard, that users verify only the cosign signature, which is the one that
is not self-contained. **Re-open at v1.1**, conditioned on the repository being
public in fact and on the primary minisign path being unaffected.

### §A R3 — §2 R6's OTS anchor is **retained**, and here is why it is not redundant

The tempting inference is that Rekor now supplies substitution-detection, so the
anchor can go. It does not follow: **Rekor does not come without cosign.** With
minisign retained as primary (§A R2), no Rekor entry exists, and §2 R6's
justification is untouched — it remains the only substitution-detection the
scheme has.

The real question is narrower, and it is new: post-public one *could* record the
public key in Rekor **without** adopting cosign for signing. That option now
exists and is **declined**, on a difference that matters for this project
specifically:

- An **upgraded OTS proof** verifies against a **Bitcoin block header**, which
  the user may obtain from any source they already trust — including a node they
  run themselves. No Sigstore-specific trust root is involved.
- A **Rekor inclusion proof** verifies against Rekor's log key, distributed
  through the Sigstore TUF root — the same bootstrap dependency §A R2 declined
  one paragraph earlier. Adopting it for the *key* while rejecting it for the
  *signature* would be incoherent.
- The OTS path uses **machinery this project has already built and tested**
  (A13 submit, A14 upgrade) and dogfoods the product's own thesis.

Rekor is therefore recorded as an **available addition, not adopted**. §2 R6
stands as written, including its stated limits — an anchor proves a key is *old*,
never that it is *the maintainer's*.

### §A R4 — Timing: both deferrable items share one property, and it decides them differently

The maintainer asked whether deferring the DNS TXT pin and the OTS anchor costs
anything. **Both are instruments whose entire value depends on existing *before*
the event they detect, and neither can be retrofitted** — after a suspected
substitution you cannot add a pin and learn which key was genuine. That shared
property does not, however, make them equally urgent, because their value clocks
start at different moments.

- **The OTS anchor's clock starts when users appear.** Its discriminating power
  is the *gap* between the key's anchor date and an attacker's, and before first
  release there are no users to protect. Anchoring now rather than at release
  buys only the pre-release interval, during which nobody is exposed. **Deferring
  it to first release costs almost nothing** — but deferring it past first
  release is different in kind, because a key published without an anchor can be
  substituted during that window by a key whose anchor is no younger. Concretely:
  **stamp a few days before the release date**, so the A14 upgrade completes and
  the release ships an upgraded proof rather than a pending one.
- **The DNS TXT pin's clock starts the moment the key is first published**, which
  is the same moment the first user pins it. It is the **only row in §2 R5's
  table with a different control plane**, and without it the "independent pin"
  column is empty — the scheme's security at first contact reduces to *trust
  GitHub*, which is the thing §1.1 says a signature is supposed to improve on.
  **It is the one that should not be deferred**, on asymmetry rather than on
  probability: a one-time registrar action against an unbounded, retroactive,
  un-repairable downside.

**What deferring the pin actually costs, stated precisely so it is not
overstated.** It degrades **first contact**, not the ongoing chain: a user who
saves the key at v0.1 still detects substitution at v0.2 (§1.1 (b)), and §1.1 (a)
and (c) — off-path copies, and the authenticated sums file — hold regardless. The
loss is confined to the user's *first* encounter with the key, and to the
project's own ability to adjudicate a later dispute.

### §A R5 — What the maintainer must do differently

1. **Nothing about the mechanism.** §2 R1–R4 and §2 R7–R12 are unchanged. The
   pipeline Q30 builds is the pipeline this record already specifies.
2. **Do not cite the privacy argument.** If anyone re-opens D71, §3's deciding
   argument is withdrawn and §A R2 is the live one.
3. **Take the DNS TXT record before first release** (§A R4). Still an external
   action at the registrar, still requiring express consent, still not taken by
   any agent.
4. **Stamp the key a few days before the release date**, not now and not after
   (§A R4).
5. **If cosign is ever adopted, do not sign until the repository is public in
   fact** — OID `1.3.6.1.4.1.57264.1.22` records visibility at signing time,
   permanently.
6. **§2 R5's table and §1.1's "only public surface" sentence become wrong on the
   flip.** Q30's custody doc must describe the post-flip state, not this one.

### §A R6 — The README pin becomes readable, and is still not independent

On the flip, the README and the release page become anonymously readable and
§2 R5's limitation 2 resolves. **The pin does not thereby become independent.**
§1.1's measurement is unaffected by visibility: the page, the README and the
release assets remain one GitHub account, and `antseal.org` and
`objects.githubusercontent.com` remain one certificate chain — `Let's Encrypt
YR1` → `ISRG Root YR`, with `CN = *.github.io` on the asset host's leaf.

**Readable and independent are different properties, and going public supplies
only the first.** An attacker who can replace the binary can still replace the
README that carries the key, in the same act, under the same credential. The
table in §2 R5 keeps exactly one row in the "different control plane" column —
the DNS TXT record — and §A R4 is why it should exist before the first release
rather than after it.
