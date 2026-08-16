# Pre-public scrub — git history

**Date**: 2026-08-16 · **Repo**: `aed900/antseal` (`isPrivate: true` at time of scan)
**Subject**: **every blob that has ever existed in this repository's object store** — all refs,
all reflogs, unreachable and dangling objects, commit and tag objects.
**Gates**: task **Q65**. A sibling lane owns the current worktree; this file does not cover it.
**Scope note**: this lane **reports only**. No history was rewritten, no ref was moved, no
credential was revoked, rotated or tested, no repository setting was changed.

## Verdict

**No BLOCKER. No live credential material of any kind was found anywhere in this
repository's history.**

Every hit in every key-material category resolves to one of three things: the `secret-guard`
lane's own planted self-test literals, prose describing what the guard checks, or published
test vectors. Specifics and evidence below.

Two findings are worth the maintainer's attention before flipping the switch, neither a blocker:
a **scoping correction** about what publication actually exposes (§2), and **three concrete
blind spots in `secret-guard`** (§6) that are a row candidate.

---

## 1. What was scanned

All commands run from the repo root, read-only.

| Command | Covers |
|---|---|
| `git cat-file --batch-all-objects --batch-check='%(objectname) %(objecttype) %(objectsize)'` | **7935 objects**: 3450 blob, 3670 tree, 813 commit, 2 tag |
| `git rev-list --all --reflog --objects` | 7511 reachable objects |
| `git fsck --unreachable --dangling --no-progress` | **424 unreachable**: 83 blob, 279 tree, 61 commit, 1 tag |
| `git for-each-ref` | 40 refs — 36 `heads`, 1 `remotes`, 2 `tags`, **1 `original`** |
| `git reflog --all` | 445 reflog entries |
| `git stash list` | 0 entries (no stash exists) |

7935 total − 7511 reachable = **424**, which equals the fsck count exactly. That arithmetic is
the proof that `--batch-all-objects` reached the dangling set; the content scan below runs over
that superset, so **no blob in this repository escaped inspection**, reachable or not.

**Blob corpus**: 3450 blobs, **174 106 369 bytes (166.0 MB)** of content, every byte scanned.

### Content scan

`detect.py` streams `git cat-file --batch` and applies 37 compiled byte-regexes plus a separate
deduplicating 64-hex extractor to every blob body.

```
python3 detect.py blobs < blob-shas.txt > hits.tsv 2> hits.err   # BLOBSCAN_EXIT=0
  -> cat-file rc=0 objects=3450 ; distinct 64-hex values: 1644 ; 4431 hit lines
```

Commit messages are **not blobs** and this project's are exceptionally verbose, so commit and tag
objects were scanned as a second pass with the identical pattern set:

```
SCAN_ALL_TYPES=1 python3 detect.py blobs < commit-shas.txt      # COMMITSCAN_EXIT=0
  -> cat-file rc=0 objects=815 ; 1922 hit lines
```

Both runs report the child's real return code (`cat-file rc=`), not a pipeline's.

### Independent cross-check (different tooling, same corpus)

Because a systematic flaw in one pipeline would produce a confident false clean, the corpus was
re-scanned through a path sharing no code with `detect.py` — a plain shell `grep -aoE` over the
raw `git cat-file --batch` stream (`PIPESTATUS[0]=0`). The two agree exactly:

| pattern | shell grep | `detect.py` |
|---|---|---|
| `BEGIN EC PRIVATE KEY` | 44 | 44 |
| `AGE-SECRET-KEY-1` | 44 | 44 |
| `minisign encrypted secret key` + `minisign secret key` | 44 + 24 = 68 | 68 |
| `ghp_…` / `github_pat_…` / `AKIA…` / `xox[baprs]-…` / `-----BEGIN OPENSSH` | **0** | **0** |
| `maintainer-email` | **0** | **0** |

The same shell grep, fed injected fakes, returns all five — so its zeros are true negatives too.

### Path, metadata and structural scans

- Authoritative path set: `git log --all --reflog -m --name-only` ∪ `git ls-tree -r` over all 61
  unreachable commits → **1229 distinct paths ever**; HEAD has 1219.
- Identities: `git log --all --reflog --format='%ae|%an|%ce|%cn'`, plus a per-commit pass over
  the 61 unreachable commits.
- Remote reality: `git ls-remote origin` (read-only).

---

## 2. Scoping correction — what publication actually exposes

This is the single most consequential measurement in this review, and it narrows the blast
radius considerably.

The local clone has 36 branches, a `refs/original/` namespace, two tags, 61 unreachable commits
and 83 unreachable blobs. **None of that is on GitHub.** `git ls-remote origin` returns exactly:

```
3352fbec…  HEAD
3352fbec…  refs/heads/main
5b72bb0f…  refs/tags/format-v1-freeze
```

Making the repository public publishes **what GitHub holds**, not what this working copy holds:

| | Objects | Commits | Blobs |
|---|---|---|---|
| **Published** (reachable from `main` + `format-v1-freeze`) | 7277 | **533** | **3364** |
| **Local-only** (never pushed) | 658 | 280 | **86** |

The scan covered all 3450 blobs — a superset of the 3364 that publish — so the verdict holds for
publication and, separately, for the local-only remainder.

**The caveat that matters**: the local-only set stops being local the moment anyone runs
`git push --all`, `git push --mirror`, or pushes one of the 35 unpushed branches. It includes
`refs/original/refs/heads/m2w4-kappa` (a `filter-branch` backup), the tag
`pre-trailer-strip-949dd9d`, and the branch `backup/pre-trailer-strip-20260803` — three refs
preserving a superseded pre-rewrite state. They are clean (§5, BENIGN-6), but they are pure
clutter on a public repo and there is no reason to ever push them.

---

## 3. Canary results — proof each check can fire

This project's dominant defect class is the assertion that cannot fail, so **no category below is
reported clean without a demonstrated detection.** 44 fake secrets — one per class, structurally
faithful and cryptographically worthless — were written to a scratch directory **outside the
repository** and scanned by *the same `detect.py` code path* that produces the repo verdict.

```
patterns defined: 37   fired: 37
NOT FIRED: (none - every pattern proven live)
```

| Category | Canary | Fired | Blob hits | Commit-obj hits |
|---|---|---|---|---|
| PEM private key (RSA/EC/plain/OPENSSH/**PGP**/ENCRYPTED) | 6 files | ✅ all 6 | 44 (all benign) | 0 |
| PGP message block | ✅ | ✅ | 0 | 0 |
| SSH public key | ✅ | ✅ | 0 | 0 |
| age secret key | ✅ | ✅ | 44 (all benign) | 0 |
| minisign secret key — **encrypted *and* unencrypted** | 2 files | ✅ both | 68 (all benign) | 0 |
| antseal vault-export magic | ✅ | ✅ | 464 (all prose) | 0 |
| GitHub token (`ghp_`/`gho_`/`ghs_`/`github_pat_`) | 4 files | ✅ | **0** | **0** |
| crates.io / npm / AWS / Slack / Google / Stripe token | 6 files | ✅ | **0** | **0** |
| Porkbun API key (`pk1_`/`sk1_`) | ✅ | ✅ | **0** | **0** |
| JWT | ✅ | ✅ | **0** | **0** |
| RPC provider key (Infura/Alchemy/QuickNode/Ankr) | 4 files | ✅ | **0** | **0** |
| `.netrc` credential line | ✅ | ✅ | **0** | **0** |
| basic-auth URL | ✅ | ✅ | 105 (all test literals) | 1 |
| generic `password:`/`api_key:` assignment | ✅ | ✅ | **0** | **0** |
| EVM keystore JSON (ciphertext **∧** kdfparams) | ✅ | ✅ | 44 (all benign) | 0 |
| `PRIVATE_KEY=` / `MNEMONIC=` assignment | 2 files | ✅ | 9 (all benign) | 0 |
| Anvil standard mnemonic (`test …  junk`) | ✅ | ✅ | **0** | **0** |
| 12-word / 24-word lowercase run (BIP39 candidate) | 2 files | ✅ both | 2732 / 0 | 21 / 0 |
| **Anvil well-known key classifier** | 2 real keys | ✅ **2/2** | **0 ANVIL** of 1644 | 0 of 4 |
| maintainer email `maintainer-email` | ✅ | ✅ | **0** | **0** |
| any email address | ✅ | ✅ | 71 | 1900 |
| international phone number | ✅ | ✅ | **0** | **0** |
| private IPv4 / IPv6 | ✅ | ✅ | **0** / **0** | 0 |
| internal hostname (`.lan`/`.local`/`.internal`) | ✅ | ✅ | 28 (all false pos.) | 0 |
| `/home/deb` / any `/home/*` path | 2 files | ✅ | 185 / 484 | 1 / 0 |

Checks outside `detect.py` were canaried the same way, by injecting a fake into the real stream:

- **Author/committer metadata grep** — injecting one fake line into
  `git log --all --reflog --format='%H %ae %ce %an %cn'` yields exactly 1 hit; the unmodified
  stream yields **0**. The zero is a true negative.
- **Sensitive-filename grep** — injecting `secrets/id_rsa`, `config/.env`, `certs/wallet.pem`,
  `a/.netrc`, `x/secrets.toml`, `k/signing.key`, `m/release.minisig` into the 1229-path list
  returns exactly those 7. The real path set returns **none**.
- **Master-secret (`W`) extractor** — matches a fake random `"w": "9f3c1ad8…"`, so a differing
  value would have surfaced as a second distinct row (§4).
- **Wrapped-mnemonic detector** — a 24-word phrase hard-wrapped across three lines is matched
  after whitespace normalisation. This canary is why the line-based check was not trusted alone.

---

## 4. The wallet question — the highest-value target here

Answered directly, because for this project it is the question.

**Zero Anvil/devnet keys anywhere in history.** 1644 distinct 64-hex values appear across the
3450 blobs (4 more in commit objects). **None** matches any of the ten well-known Anvil/Hardhat
keys. The classifier was proven live in the same run: fed the real
`ac0974be…f2ff80` and `59c6995e…78690d`, it tags both `ANVIL`. So the zero is a measurement, not
an untested assumption — and it independently corroborates that `.devnet/env` was never
committed, which is the assumption `secret-guard`'s `.devnet` exclusion rests on.

**Exactly one value has ever been assigned to the master secret `W`.** A dedicated extractor for
`"w": "<hex>"` and `w = <hex>` over all 3450 blobs found **1 distinct value**, occurring 21 times:

```
000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
```

That is bytes `0x00`–`0x1f` in order — unambiguously synthetic. **Project rule 6 holds across the
entire history**: no real master secret, unit key or salt has ever entered a fixture.

**No mnemonic belonging to anyone.** Of 2732 12-word lowercase runs, all are English prose from
`TODO.md`, `tasks/` and `docs/`. Whitespace-normalised scanning across all 4265 blob+commit+tag
objects finds **18 distinct 24-word runs**; 17 are error-code name lists, dependency lists and
prose. The eighteenth is a genuine BIP39 phrase and is accounted for in §5 (BENIGN-3).

The 1644 64-hex values are otherwise SHA-256 digests, Merkle roots, commitments, NIST ACVP
ML-DSA vectors and proptest seeds — expected in a content-addressing project. The 196 that sit in
key-adjacent context all resolve to the synthetic `W` above, ACVP `"seed"` fields, or CA
certificate fingerprints.

---

## 5. Findings

### BLOCKER

**None.**

### SHOULD-FIX

**SF-1 — `secret-guard` has three demonstrated blind spots.** Detailed in §6. Not a leak; a
detection gap that would let a future leak through. Row candidate.

### NOTE

**N-1 — Maintainer's local username and absolute paths are in history (unfixable without a rewrite).**
`/home/deb` appears in **116 distinct blobs** across **20 paths**, and in **20 files in HEAD**.
Heaviest: `tasks/P.md` (42), `docs/ci-verification.md` (38), `tasks/Q.md` (33),
`docs/decisions/D91-anchor-error-code-namespace.md` (24). One occurrence is in a commit message
(object `b8411e5a10a2`), which is the one form that cannot be fixed without rewriting the commit.
Discloses: the maintainer's Linux username `deb` and that the project lives at
`/home/deb/Documents/code0`. Low severity — not a credential, no host identity, no network
reachability. Other `/home/*` values in history (`user` ×243, `runner` ×21, `fixture` ×17, `x`
×18, `u` ×4) are synthetic CLI test fixtures.

**N-2 — Commit metadata is clean, and that is worth stating explicitly** because it is the one
category that cannot be scrubbed without rewriting every commit. All **813** commits (752
reachable + 61 unreachable) carry only GitHub noreply addresses:

| identity | commits |
|---|---|
| `129773515+aed900@users.noreply.github.com` | 733 reachable + 60 unreachable |
| `aed900@users.noreply.github.com` | 14 reachable + 1 unreachable |
| `m2w4-kappa@users.noreply.github.com` | 5 |

**`maintainer-email` occurs 0 times** in commit metadata, commit messages, and all 3450 blobs — with
the detector for that exact string proven live. The noreply forms are public by construction:
`129773515` is the account's public numeric ID and `aed900` its public username, both already
visible on any public GitHub interaction. **Nothing here requires a history rewrite.**

**N-3 — 269 `Co-Authored-By: Claude …` trailers are in published history.** 136 `Claude Opus 5
(1M context)`, 132 `Claude Fable 5`, 1 `Claude Opus 5`. Not sensitive; flagged only because it
becomes publicly visible and the maintainer may have a preference. A previous rewrite (tag
`pre-trailer-strip-949dd9d`, 2026-08-03) already normalised some of these, so the topic is
evidently live. One malformed trailer exists —
`Co-Authored-By: prefix rather than on a name, because the previous strip missed` — a prose line
that a trailer parser will misread as an author.

### BENIGN — confirmed, not assumed

**BENIGN-1 — All 44 PEM / 44 age / 44 keystore / 68 minisign hits are `secret-guard`'s own
self-test literals.** Located to `scripts/ci-lanes.sh` (25 revisions), `.github/workflows/ci.yml`
(17 revisions, the pre-Q43 inline version), `CONTRIBUTING.md` (16), `testdata/README.md` (7). The
distinct matched lines are exhaustively:

```
printf 'fake for guard self-test\n-----BEGIN EC PRIVATE KEY-----\nAAAA\n…' > "$tmp/fake-wallet.pem"
printf 'AGE-SECRET-KEY-1SELFTESTSELFTESTSELFTEST\n'                      > "$tmp/fake-age.key"
hits+="$(ex 'minisign encrypted secret key')"
```

The three unreachable blobs that matched were opened and identified rather than assumed:
`0d3d0742c1b2` = an earlier `ci-lanes.sh`, `d4a0071711cc` = an earlier `.github/workflows/ci.yml`,
`cd58d10ca54a` = an earlier `CONTRIBUTING.md`. **No real key material.**

**BENIGN-2 — The BIP39 mnemonic in `crates/antseal-net/src/evm.rs` is the published all-zero
vector.** Blob `3bfab6303c4c`, line 631:

```rust
// Mnemonic: the distinct not-in-this-version rejection.
let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon \
                abandon abandon about";
let err = WalletKey::import(&buf(mnemonic)).expect_err("mnemonic");
assert_eq!(err, WalletImportError::MnemonicNotSupported);
```

Eleven × `abandon` + `about` is exactly the BIP39 spec's first test vector — all-zero entropy,
every index 0, plus the checksum word. Publicly documented, derives a long-swept address, and it
is used here in a **negative** test asserting mnemonics are *rejected*. Confirmed by structure,
not by recall.

**BENIGN-3 — The 24-word phrase in `docs/research/paper-key-transport-design-round.md` is a
documented example, and the document says so.** Introduced by commit `d8ce569` (2026-08-15, the
OBOL/D134 round), lines 191-199. It is a real, valid 24-word BIP39 mnemonic — and it is the
encoding of the published example entropy `000102…1e1f`, sitting three lines below its own
disclaimer:

> All from the fixed example entropy `000102…1e1f` (a published test vector pattern —
> **never a production key**; production K is drawn fresh from the CSPRNG per lock).

Anyone can rederive it; it protects nothing. **Flagged anyway** because once the repo is public,
automated seed-phrase scanners and good-faith security researchers *will* report it. The existing
disclaimer is the right mitigation and is already adjacent; no change required, but expect the
report. (Caught only by the wrapped-mnemonic pass — the phrase is hard-wrapped across three
lines, so a line-oriented check misses it. Worth knowing for D134's future implementation work.)

**BENIGN-4 — No vault-export file was ever committed.** The `ANTSEAL VAULT EXPORT` magic appears
464 times across 13 paths, but **0 blobs carry it at line 1**, i.e. none is an actual export
file. All occurrences are prose or the sanctioned constant: `TODO.md` (291),
`docs/ci-verification.md` (36), `tasks/U.md` (28), `scripts/ci-lanes.sh` (25),
`.github/workflows/ci.yml` (17), `docs/decisions/README.md` (16), `CONTRIBUTING.md` (16),
`crates/antseal-cli/src/vault/export.rs` (10, the `EXPORT_MAGIC` definition),
`docs/decisions/D47-vault-export-format.md` (8), `testdata/README.md` (7).

**BENIGN-5 — The two real third-party emails are from FreeTSA's public root CA.**
`busilezas@gmail.com` (3) and `busilezas@mailbox.org` (2) appear only inside X.509 subject DNs in
`crates/antseal-core/src/anchor/roots/PROVENANCE.md`,
`testdata/anchors/A25-bootstrap/roots-PROVENANCE.md` and
`testdata/vectors/v1/anchor/anchor.json`:

```
O=Free TSA, OU=Root CA, CN=www.freetsa.org, emailAddress=busilezas@gmail.com, L=Wuerzburg, ST=Bayern, C=DE
```

This is the pinned FreeTSA root's own subject field, distributed worldwide in the certificate
itself. Not a disclosure. The remaining email-shaped strings — `pw@tsa.example` (23),
`127.0.0.1@evil.example` (9), `pw@example.org` (3), `pw@tsa.invalid` (2),
`btc.calendar.catallaxy.com@attacker.example` (1) — are RFC 2606 reserved names in URL-rejection
tests.

**BENIGN-6 — Deleted-but-recoverable files: 10, all innocuous.** Two independent enumerations
(path-set difference, and `--diff-filter=D`) agree exactly:

| Path | Introduced | Removed |
|---|---|---|
| `testdata/vectors/hkdf/hkdf-sha256-v1.txt` | `0d51a69` | `ebd0759` |
| `testdata/vectors/hkdf/gen_vectors.py` | `0d51a69` | `ebd0759` |
| `testdata/vectors/hkdf/README.md` | `0d51a69` | `ebd0759` |
| `verifier-web/index.html` | `1f5c6ac` | `08c074c` |
| `crates/antseal-core/tests/format_registry_draft.rs` | `fe5bdfa` | `825629b`/`ef8300b` |
| `testdata/tamper/format/body-malformed-seal-id.cbor` | `2709ba5` | `ab39b88` |
| `testdata/tamper/format/body-tagged-unit-kind.cbor` | `2709ba5` | `ab39b88` |
| `testdata/tamper/format/bundle-full-reveals-over-cap.cbor` | `f4cfde9` | `ab39b88` |
| `scripts/__pycache__/check-traceability.cpython-311.pyc` | `2f1588c` | `350948b` |
| `docs/decisions/D74-extraneous-s-root.md` | `0c14845` | (dropped in a merge, see below) |

Add/delete commits were re-derived with `--full-history`, because default history simplification
hid `D74` entirely: `git log --all -- <path>` reported *nothing* for it, while the blob plainly
existed. Its removal is recorded in a merge resolution rather than as a plain `D`, so it has no
deletion commit to name. Blob `81d9ebdf` (3137 bytes) is an ordinary resolved decision record
("Extraneous `s_root` on a `FineTree::Absent` full reveal", RESOLVED–REJECT, 2026-07-28) and
**is** in the published set. Content benign.

The HKDF vectors were the one genuine concern here — deleted key-derivation vectors are exactly
where a real master secret would hide — and they carry the synthetic `W` of §4, nothing else.
The stray `.pyc` is build output, not a secret. All ten blobs were content-scanned.

**BENIGN-7 — No CI secret was ever referenced or echoed.** No workflow in history references a
GitHub Actions secret. The apparent `secrets.*` matches (`secrets.rs` ×27, `secrets.iter()` ×3,
`secrets.push()` ×2) are Rust identifiers. **Zero** lines echo, print or `cat` a secret.

**BENIGN-8 — No unexpected binaries.** Largest blobs ever: `testdata/acvp/ml-dsa-65-sigGen.json`
(1.37 MB, NIST ACVP vectors) and **163 revisions** of `TODO.md` (up to 1.05 MB each — consistent
with a 639-row tracker). Extensions ever committed are `.rs` (1350), `.md` (1053), `.bin` (260),
`.sh`, `.toml`, `.json`, `.txt`, `.py`, `.yml`, `.lock`, and `.tsr`/`.tsq`/`.der`/`.ots`/
`.timestamp`/`.upgrade` (RFC 3161 and OpenTimestamps artifacts — expected). No archives, no
executables, no images, no unexplained blobs.

**BENIGN-9 — All 83 unreachable blobs are ordinary project files.** Fingerprinted by first line:
`TODO.md` revisions, decision records, the error-code registry, Rust sources, vector-freeze
manifests, tamper-completeness registries. All content-scanned; nothing anomalous.

**BENIGN-10 — The 28 `internal_host` hits are false positives** of my own `.home`/`.local` TLD
pattern matching Rust field access and filenames: `vault.home` (16), `settings.local` (6),
`args.home` (6). No private IPv4, no private IPv6, no internal hostname exists in history.

---

## 6. `secret-guard` gaps — row candidate

`scripts/ci-lanes.sh:1055-1144`. The guard is well-built for what it targets — it self-tests
before every verdict, and it welds its `.devnet` exclusion to an `assert_gitignored` check so
"not scanned" stays tied to "not committable". §4 independently confirms that assumption held.

But its patterns are a starting point, not a specification, and three gaps are **measured**, not
inferred. Each was reproduced by running the guard's own literal patterns against the canary
corpus:

**Gap 1 — PGP private key blocks are invisible.** The pattern
`[-]{5}BEGIN[ A-Z0-9]*PRIVATE KEY[-]{5}` requires the closing dashes immediately after
`PRIVATE KEY`, so `-----BEGIN PGP PRIVATE KEY BLOCK-----` does not match:

```
secret-guard PEM pattern on pem_pgp.txt : *** NO MATCH (blind) ***
dropping the trailing [-]{5}            : MATCH
```

It catches RSA, EC, plain, OPENSSH and ENCRYPTED — 5 of 6 flavours. Fix: drop the trailing
`[-]{5}`.

**Gap 2 — Unencrypted (`minisign -W`) secret keys are invisible.** Confirmed independently of the
sibling lane that first raised it. The guard greps the literal
`minisign encrypted secret key`; a `-W` key's comment omits `encrypted`:

```
secret-guard 'minisign encrypted secret key' on minisign_unenc.txt : *** NO MATCH (blind) ***
'minisign( encrypted)? secret key'                                 : MATCH
```

This matters directly: D71 concerns binary signing and key custody, so minisign keys are material
this project expects to handle.

**Gap 3 — `--exclude='*.md'` is a large hole in a documentation-heavy repo.** Every pattern is
blind to every Markdown file. Demonstrated with identical content under two names:

```
$ grep -rlaE --exclude='*.md' -e '<PEM pattern>' mdtest/
    leak.txt          # leak.md, byte-identical, is invisible
```

`.md` accounts for **1053 of the 3367 reachable blob paths — 31% of everything ever committed** —
and includes `TODO.md`, the single largest text file in the repo (163 revisions, up to 1.05 MB).
It is also where secret-shaped strings already cluster: 291 of the 464 vault-export-magic
occurrences are in `TODO.md` alone. A real export blob, PEM key or token pasted into any `.md`
file passes `secret-guard` green today.

**But do not simply delete the exclusion** — it is load-bearing, and the naive fix reds the lane
on first run. Measured against the current tree, dropping `--exclude='*.md'` immediately flags:

| guard pattern | `.md` files newly flagged | which |
|---|---|---|
| (3) vault-export magic | **9** | `TODO.md`, `CONTRIBUTING.md`, `tasks/U.md`, `testdata/README.md`, `docs/ci-verification.md`, `docs/decisions/D47-…`, … |
| (1) PEM private key | **3** | `docs/decisions/D71-binary-signing-mechanism-and-key-custody.md`, and **both** pre-public scrub reports |
| (4) age secret key | **3** | same three |
| (4) minisign | **3** | same three |

This is the same trap the guard already solved once for `crates/antseal-cli/src/vault/export.rs`
(excluded by *exact path*, not basename). The workable shape is the same: drop the blanket `*.md`
exclusion, and either exclude the handful of documenting files by exact path, or tighten the
patterns to require key **body** material rather than the header literal alone — so prose that
*names* a marker stays green while a file that *contains* a key goes red. Note that this document
and its sibling are themselves on that list, by virtue of quoting the markers as evidence.

**Not covered by the guard at all** (all canary-proven detectable, all currently absent from
history): GitHub/crates.io/npm/AWS/Slack/Google/Stripe tokens, Porkbun API keys, JWTs, RPC
provider keys, `.netrc` lines, basic-auth URLs, generic `password:`/`api_key:` assignments, bare
64-hex private keys in any spelling other than
`ANTSEAL_DEVNET_WALLET_PRIVATE_KEY=`, and BIP39 mnemonics — the last of which becomes load-bearing
when **D134** ships hand-written 24-word paper keys.

---

## 7. What this scan does NOT cover

Stated plainly, because a scrub that overstates its reach is worse than none.

1. **The current worktree.** Sibling lane's subject. This lane scanned committed objects and
   ignored uncommitted, untracked and gitignored files. In particular **`.devnet/env` — which
   holds a funded devnet wallet key — was never examined**; it is gitignored, and §4's zero-Anvil
   result is evidence it never reached the object store, but its on-disk state is not my finding.
2. **No BIP39 wordlist exists on this host** (`python-mnemonic` absent; no `english.txt` in the
   cargo registry). Mnemonic detection is therefore *structural* — consecutive lowercase 3–8
   character word runs, line-based and whitespace-normalised — not membership-checked against the
   2048-word list, and no BIP39 checksum was validated. Writing the wordlist from memory was
   explicitly rejected as the wrong medium. Consequence: a mnemonic using words that are all
   3–8 lowercase characters is *caught* (this is why §4's 24-word sweep is trustworthy), but I
   cannot mechanically separate a real phrase from prose — the 18 candidates were separated by
   reading them.
3. **Encrypted, compressed or encoded payloads.** All patterns are plaintext. A secret inside a
   base64 blob, a `.tar.gz`, or an encrypted file would not match. No such archives exist in
   history (BENIGN-8), which bounds but does not eliminate the risk.
4. **No entropy-based detection.** Detection is signature-based. A high-entropy secret in a format
   none of the 37 patterns describes would be missed. The 64-hex sweep is the one exception and it
   is exhaustive for that shape.
5. **GitHub-side artifacts.** Issues, PRs, Actions run logs, Gists, release assets, wiki, and the
   repository description live outside git. Actions logs deserve a separate look before going
   public: this repo has run a 19-job matrix many times. **Out of scope here.**
6. **Anything already pushed elsewhere.** Only `origin` was queried.
7. **Whether any 64-hex value is a funded key.** Determining that requires deriving addresses and
   querying chain state — a network action, and out of scope. The classification rests on the
   Anvil set, on context, and on the single-`W` result.
8. **Objects deleted before the earliest reflog entry** and already garbage-collected are, by
   definition, unrecoverable and unscannable. 445 reflog entries were covered; nothing suggests a
   gap, but absence of evidence is noted as such.

---

## 8. Reproducing this

```
git cat-file --batch-all-objects --batch-check='%(objectname) %(objecttype) %(objectsize)'
git fsck --unreachable --dangling --no-progress
git rev-list --all --reflog --objects
git log --all --reflog --format='%ae|%an|%ce|%cn' | sort | uniq -c
git log --all --reflog -m --name-only --format=''
git ls-remote origin
python3 detect.py canary <scratch>/canary     # 37/37 patterns must fire before trusting a scan
python3 detect.py blobs  < blob-shas.txt
SCAN_ALL_TYPES=1 python3 detect.py blobs < commit-shas.txt
```

The canary corpus and `detect.py` were written to scratch space outside the repository and are
**not committed** — they contain 44 realistic fake secrets, and committing them would poison
every future scan of this repo, including `secret-guard`'s.
