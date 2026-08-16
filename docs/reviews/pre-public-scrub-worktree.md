# Pre-public scrub — the working tree and the disclosure surface

**Date: 2026-08-16.** Lane: worktree + disclosure. Gating row: **Q65**.
Tree measured: `main` at `3352fbe`, plus 3 modified and 5 untracked files
(the R87 source lane and four un-committed decision records).

**No live credential material was found anywhere in the working tree.** Every
key-shaped string in the tree is a detector's own planted self-test constant or
a table of key *header formats*; each is named and shown below. Nothing in this
report needed redaction, because there was nothing real to redact.

A sibling lane owns **git history**. This lane owns **HEAD**: what a stranger
reads and can copy on day one. A file that is clean here may still have been
dirty in an earlier commit — that question is the sibling's, and every finding
below that could have a history tail says so.

---

## 1. Scope and method

Two rules govern everything below, because this project's dominant defect class
is *assertions that cannot fail*:

1. **No category is reported clean without a canary.** Every detector was run
   first against a corpus of 23 planted fakes outside the repository
   (`$SCRATCH/wt/canary/`), and its repo verdict is reported only if the canary
   fired. §2 is that table.
2. **Real exit codes.** Long output went to files and `$?` was read directly;
   `${PIPESTATUS[0]}` where a pipe intervened.

**Coverage of the tracked set.** 1 219 tracked files; **841 text-scanned**,
**378 skipped as binary or empty** (256 `.bin` fuzz seeds, 30 `.cbor`, 22
`.tsr`, 22 `.timestamp`, 18 `.upgrade`, 13 `.tsq`, 9 `.der`, 3 `.ots`). See §9.

Principal commands:

```
git grep -nIE -e <pattern> -- .              # 24 detectors, §2
git status --porcelain --untracked-files=all # untracked set
git check-ignore -q <path>                   # ignore-rule probes, no files created
bash   scripts/ci-lanes.sh secret-guard      # EXIT=0
python3 scripts/check-copy-style.py          # EXIT=0
python3 scripts/check-copy-style.py --self-test   # EXIT=0, PASS
curl -s https://crates.io/api/v1/crates/<c>  # what is already public
gh repo view aed900/antseal --json isPrivate # {"isPrivate":true}
```

Repository visibility at time of writing: **PRIVATE**, re-verified. Nothing in
this lane changed any file outside this document, and no repository setting was
touched.

---

## 2. Canary results — proof each check can fire

24 detectors. `canary` = files hit in the planted corpus (0 would invalidate the
verdict); `repo` = matching lines in tracked files.

| Detector | canary | repo | Verdict |
| --- | --- | --- | --- |
| `pem-key` | 2 | 1 | benign — self-test constant |
| `openssh-key` | 1 | 0 | clean |
| `pgp-key` | 1 | 0 | clean |
| `age-secret` | 1 | 1 | benign — self-test constant |
| `minisign-secret` | 1 | 1 | benign — the guard's own pattern |
| `vault-export` magic | 1 | 15 | benign — format constant + docs |
| `gh-token` (`ghp_`/`gho_`/…) | 1 | 0 | clean |
| `gh-pat-fine` (`github_pat_`) | 1 | 0 | clean |
| `aws-akid` | 1 | 0 | clean |
| `slack-token` | 1 | 0 | clean |
| `jwt` | 1 | 0 | clean |
| `npm-token` | 1 | 0 | clean |
| `stripe-key` | 1 | 0 | clean |
| `named-hex64-key` | 1 | 0 | clean |
| `bip39-mnemonic` | 1 | 0 | clean |
| `email-any` | 2 | 13 | see §4 — all third-party or noreply |
| `email-maintainer` (`maintainer-email`) | 1 | **0** | clean |
| `abspath-homedeb` | 1 | **39** | **SHOULD-FIX S1** |
| `abspath-anyuser` | 1 | 80 | 40 `/home/deb`, rest CI/fixtures |
| `evm-address` | 1 | 38 | see §5 — no maintainer linkage |
| `hash-64hex` | 2 | 12 | see §5 — third-party tx/block hashes |
| `stub-not-written` | 1 | 52 | see §8 |
| `placeholder` (lorem/FIXME) | 1 | 0 | clean |
| `license-assert` | 1 | 29 | **BLOCKER B1** |

Five detectors initially reported `canary=0` — `openssh`, `pgp`, `npm`,
`stripe`, `placeholder`, plus `email-maintainer`, which my first corpus tested with a
different address. Their "clean" verdicts were **discarded and re-run** after
the corpus was extended. That is the §1 rule doing its job: six categories were
one step away from being reported clean by a check that could not fire.

The three key-shaped repo hits, in full, so no reader has to trust a summary:

```
scripts/ci-lanes.sh:1114:  printf 'fake for guard self-test\n-----BEGIN EC PRIVATE KEY-----\nAAAA\n-----END EC PRIVATE KEY-----\n' > "$tmp/fake-wallet.pem"
scripts/ci-lanes.sh:1117:  printf 'AGE-SECRET-KEY-1SELFTESTSELFTESTSELFTEST\n' > "$tmp/fake-age.key"
scripts/ci-lanes.sh:1093:    hits+="$(ex 'minisign encrypted secret key')"$'\n'
```

All three are `secret-guard`'s own planted fakes. Publishing them is harmless
and is arguably a feature: the guard's red direction is legible to a reader.

---

## BLOCKERS

### B1 — Publishing grants no rights: there is no LICENSE file, and five public crates.io records already say otherwise

This is the one finding that should stop a visibility flip on its own, and it is
**already live** rather than merely pending.

Measured:

| What | Measured value |
| --- | --- |
| Tracked `LICENSE`/`COPYING`/`NOTICE` files | **0** |
| Such files on disk (untracked included) | **0** |
| `license =` fields across 9 manifests | **0** |
| `Cargo.toml:37` | `# NOTE: no `license` field yet — the license decision (D6) lands later.` |

Meanwhile, **already public today**:

```
antseal          license= MIT OR Apache-2.0 | repo= https://github.com/aed900/antseal
antseal-core     license= MIT OR Apache-2.0 | repo= https://github.com/aed900/antseal
antseal-anchor   license= MIT OR Apache-2.0 | repo= https://github.com/aed900/antseal
antseal-net      license= MIT OR Apache-2.0 | repo= https://github.com/aed900/antseal
antseal-cli      license= MIT OR Apache-2.0 | repo= https://github.com/aed900/antseal
```

and `https://antseal.org/` answers **`200`, 2 516 397 bytes** — the verifier page
is serving `verifier-web` content to the world right now, and the page carries
**no copyright notice and no licence text** (`grep -niE 'licen|copyright|MIT|
Apache|©' verifier-web/index.template.html` returns only unrelated prose about
what a chain pin "licenses").

So a stranger following the crates.io link lands on source that, under default
copyright, is **all rights reserved**. The declaration and the artifact disagree,
and the declaration is the one already published.

**A correction to the brief this lane was given.** The brief states that
"`Cargo.toml` and D6 assert a license". `Cargo.toml` asserts the *opposite* — it
explicitly disclaims one, and deliberately, pointing at D6/Q29. The live
assertion lives on **crates.io** and in **`scripts/reserve-crates.sh:34`**
(`LICENSE="MIT OR Apache-2.0"`), not in any manifest. That distinction matters
for the fix: adding manifest fields alone leaves the repository's redistribution
grant still missing.

Every place a licence is asserted today (29 lines, 13 files) — none of them a
grant:

| Where | What it asserts |
| --- | --- |
| `docs/decisions/D6-license.md` (13 lines) | the per-crate ruling; **Status: RESOLVED**, files due at M4/Q29 |
| `scripts/reserve-crates.sh:31-34` | `MIT OR Apache-2.0` for the five placeholders |
| crates.io × 5 | the same, **published 2026-08-11** |
| `Cargo.toml:37` | that there is *no* licence field yet |
| `docs/dependency-policy.md`, `deny.toml`, D35/D58/D60/D90, `docs/upstream/P9-…` | dependency-side licence policy, not antseal's own grant |

Spec coupling, normative: **MVP-SPEC.md line 157** requires "at minimum
permissive/open for `antseal-core` + `verifier-web`", with the reason stated in
the spec's own words — *"'hostable on any static host' presumes redistribution
rights"*. Today the page is hosted and the rights are absent.

**Second half of the gap, which no user-facing surface states.** D6's ruling is
not uniform: `antseal-net` and `antseal-cli` are `MIT OR Apache-2.0` in their own
code but their **distribution is effectively GPL-3.0**, because `ant-core`'s
mandatory `self_encryption` dependency is GPL-3.0 with no linking exception. The
crates.io records for `antseal-net` and `antseal-cli` say `MIT OR Apache-2.0`
with no qualification. Anyone who ships a binary built from them inherits an
obligation the published metadata does not mention.

**Owner: Q29**, which must follow D6's per-crate ruling. This lane did not create
any LICENSE file, by instruction. Recommended shape (not executed): the licence
files themselves; `license` fields in all member manifests; and a README
paragraph stating the net/cli distribution reality in plain words.

### B2 — The README is materially false at the front door, and Q65's own dependency chain already forbids publishing before it is fixed

`README.md` is the single most-read file a public repository has. Measured
against the tree it describes:

| README says | Measured reality |
| --- | --- |
| `:11` **"Status:** pre-M0 scaffold — nothing usable yet." | M3 delivered: `https://antseal.org/` answers `200`; the CLI declares **9** top-level subcommands (`Init`, `Seal`, `List`, `Show`, `Status`, `Restore`, `Reveal`, `Verify`, `Vault`), each with its own argument set; format v1 is frozen and tagged |
| `:25` "(219 tasks…)" | **785** task rows — 515 checked, 270 unchecked |
| `:21` "`verifier-web/` … (M3)" — reads as future | the page is deployed and live |

The direction here is **underclaim, not overclaim**, which is the safer of the
two failure modes and worth saying plainly: nobody is misled into trusting
something unsafe. It is a blocker anyway, for two reasons.

First, it is false in a way that damages the product's own central claim: a
proof-of-existence tool asking strangers to audit its verifier cannot open with
"nothing usable yet" over a live verifier. A reader who checks one sentence and
finds it wrong stops checking.

Second — and this is the decisive one — **Q65's own `Deps` line already gates it**:
*"Q22 (README/install/product-limits), Q28 (copy audit), Q27 (format-stability
policy)"*. Q22 has not landed. Publishing now would violate Q65's recorded
dependency chain, not merely this reviewer's judgement.

**The copy lint cannot catch this, by design.** `scripts/check-copy-style.py`
exits 0 at HEAD and its `--self-test` PASSes — both re-run for this review — but
§10 of `docs/positioning-copy-style.md` states its limits in its own words:
*"It does not read intent"*, and it checks positioning rules, not factual
currency. It does correctly carry two registered presence debts against
`README.md`, both owed by Q22:

```
registered debt — README.md: 'limit-exclusive-possession' NOT YET STATED — owed by Q22 (M4)
registered debt — README.md: 'compelled-disclosure' NOT YET STATED — owed by Q22 (M4)
```

So the README is short of **MVP-SPEC.md line 28**'s two required limits *and*
its compelled-disclosure note, and the project already knows it. Those two debts
plus the three staleness rows above are one Q22 rewrite.

---

## SHOULD-FIX

### S1 — 39 `/home/deb/…` lines across 18 tracked files, including line 42 of the spec

Q65's Accept requires *"the `/home/…` path scrub landed, with a lint so it cannot
return"*. Measured now: **18 files, 39 lines**; `/home/deb` appears 40 times.
`/home/deb` is the only maintainer path — the other user-home strings are CI
runners and deliberate fixtures (`/home/user/` 23, `/home/runner/` 14,
`/home/fixture/` 7, `/home/u/` 2, `/home/x/` 1).

| File | lines |
| --- | --- |
| `docs/decisions/D91-anchor-error-code-namespace.md` | 6 |
| `docs/wasm-toolchain.md` | 4 |
| `docs/research/dms-mortsafe-design-round.md` | 4 |
| `tasks/P.md`, `docs/decisions/D63…`, `D3-repo-layout.md`, `D132…` | 3 each |
| `docs/decisions/D60…`, `D116…` | 2 each |
| `TODO.md`, `tasks/Q.md`, `scripts/wasm-pack-build.sh`, `MVP-SPEC.md`, `MVP-SPEC.orig.md`, `D136…`, `D135…`, `D124…`, `docs/ci-verification.md` | 1 each |

**Nothing is functionally broken by these.** The only hit inside a script is a
*comment* (`scripts/wasm-pack-build.sh:46`, describing the reproducibility
finding), so no outside contributor's build fails. The cost is disclosure: the
maintainer's username and machine layout, published permanently.

The most conspicuous is the first page of the spec itself:

```
MVP-SPEC.md:42:Cargo workspace, greenfield in `/home/deb/Documents/code0`:
MVP-SPEC.orig.md:39:Cargo workspace, greenfield in `/home/deb/Documents/code0`:
```

**Constraint the fix must respect, or it breaks the freeze:** `MVP-SPEC.md`'s
line numbers are load-bearing (§7). Any edit to line 42 must preserve the file's
line count — an in-place replacement on that line, never a reflow. The same care
does not apply to the other 17 files.

Q65's Accept also asks for a lint. `scripts/check-copy-style.py` is the natural
host; nothing enforces this today.

### S2 — `.gitignore` does not cover `.env`, `id_rsa`, or `credentials.json`

`.gitignore`'s own header sets the standard: *"no secret material may ever be
committable by default … deny-by-default — extend them freely, never narrow
them."* Probed with `git check-ignore -q`, creating no files:

| Path | Verdict |
| --- | --- |
| `.devnet/env`, `.devnet/manifest.json` | IGNORED |
| `devnet-data/x`, `.secrets/a`, `wallets/w.json` | IGNORED |
| `foo.key`, `foo.pem`, `mywallet.json` | IGNORED |
| **`.env`**, **`.env.local`**, **`secrets.env`**, **`config.env`** | **NOT IGNORED** |
| **`id_rsa`** | **NOT IGNORED** |
| **`credentials.json`** | **NOT IGNORED** |

No such file exists on disk today, so this is a latent gap, not a live leak. It
is cheap to close and it is exactly the deny-by-default posture the file already
claims.

### S3 — `secret-guard` has real blind spots, and the largest is Markdown

`scripts/ci-lanes.sh secret-guard` was **run for this review: EXIT=0**, self-test
green, `.devnet/` confirmed gitignored. It is a **required status context** in
`.github/workflows/ci-always.yml:78-84`, and that workflow carries no path
filter, so remote coverage is genuine on every push. Credit where due: its
self-test-first discipline is why its five patterns can be trusted.

The gaps, measured rather than assumed:

1. **`--exclude='*.md'` removes 218 tracked Markdown files from the scan** —
   including `MVP-SPEC.md`, all 169 `docs/` pages, `tasks/`, `CONTRIBUTING.md`
   and the 1 MB `TODO.md`. Markdown is the majority of this repository's prose
   surface and none of it is scanned. The exclusion is defensible (docs discuss
   key formats constantly — `docs/decisions/D71-…md:337-339` is a live example)
   but the consequence is that **a real key pasted into any doc is invisible to
   the guard**. A value-shaped second pattern would keep the exclusion's benefit
   without its hole.
2. **No detector** for: GitHub tokens (`ghp_`/`gho_`/`ghs_`/`github_pat_`), AWS
   `AKIA`, Slack `xox*`, npm, JWTs, OpenSSH or PGP private-key blocks, or a
   generic `PRIVATE_KEY=<64 hex>` under any name other than
   `ANTSEAL_DEVNET_WALLET_PRIVATE_KEY`. All eight were clean here (§2), but they
   were clean because *this lane* checked, not because the guard would.
3. **No BIP39 / mnemonic detector — and this one is newly material.** **D134**
   (minted 2026-08-15, due before U32) introduces paper-key locked bundles with a
   **hand-written 24-word BIP39 card**. Mnemonic material is about to become a
   first-class concept in this project and the guard cannot see it in any form.
4. **`scripts/local-gate.sh` does not run it.** It appears there only in comments
   (lines 27 and 95); there is no `run` line. The last check before a push is a
   manual step someone has to remember — which the wave records already note.

### S4 — Three vendored third-party corpora carry no licence terms

`grep -ciE 'licen|copyright|terms of use|public domain'` returns **0** for all
four provenance documents:

| Path | Size | Upstream | Risk |
| --- | --- | --- | --- |
| `testdata/unicode/NormalizationTest-17.0.0-sample.txt` | 286 KB | Unicode Consortium UCD 17.0.0 | **highest** — the Unicode licence requires the copyright and permission notice to accompany redistributed data files. Going public *is* redistribution. |
| `testdata/acvp/*.json` | 2.2 MB | `usnistgov/ACVP-Server` @ `2972def2` | GitHub's licence API returns **no SPDX** for that repo, so the terms are unverified, not merely unrecorded |
| `crates/antseal-core/src/anchor/roots/*.der` | 4 certs | FreeTSA, DFN, DigiCert, Sectigo | low — root CAs exist to be redistributed; noted for completeness |

To be clear about what *is* right: `testdata/unicode/PROVENANCE.md` is otherwise
exemplary — upstream URL, upstream SHA-256, derivative SHA-256, retrieval
timestamp to the second. The single missing field is the licence, and it is the
only one that matters the moment the repository is public.

`testdata/utf8-corpus/` is **project-authored** (G3 fixtures), not third-party —
no obligation. **No BIP39 wordlist is vendored anywhere** (`git ls-files |
grep -iE 'bip39|wordlist|mnemonic'` → empty), so D134's card has no corpus
provenance question attached yet.

### S5 — The published adversarial review has no per-finding disposition

`docs/reviews/2026-07-31-adversarial-code-review.md` publishes **33 findings**
(0 critical, 3 high, 14 medium, 11 low) and carries **no fixed/open status per
finding**; it is cross-referenced from only two task entries (`tasks/F.md`,
`tasks/Q.md`). A public reader gets a detailed list of this codebase's weaknesses
with no way to tell which are closed.

The document's own headline is reassuring and should be quoted alongside it —
*"No forgery, secrecy-loss, false-PASS, or attacker-reachable panic was found on
any surface"* — so this is a completeness gap, not a live-vulnerability
disclosure. A disposition column, or one line pointing at the rows that closed
each finding, converts it from a liability into the asset it deserves to be.

---

## NOTES

**N1 — The mainnet address in `testdata/` is a stranger's, not the maintainer's.**
38 EVM-address lines, 17 distinct values. The Arbitrum One receipts
(`testdata/anchors/A16-A17-live/arbone-{arb1,drpc}-receipt.json`) carry
`from: 0xb19da46f…648ab` on a real mainnet transaction. Its own README states the
provenance: *"Nothing here is antseal's own material — the transactions are
third parties' public mainnet/testnet transactions taken from head blocks"*,
captured **reads-only**, *"No account, no credentials, no submission"*. The rest
resolve to Autonomi's Sepolia token/vault contracts, Anvil's well-known
deterministic addresses, NuCypher's Polygon Amoy Coordinator, and obvious
fixtures (`0x5a5a…`, `0x00…01`). **No address in the tree links the maintainer to
a funded account**, which is what `MVP-SPEC.md:185` cares about. The 12 `0x`-64-hex
values are the matching third-party transaction and block hashes.

**N2 — Two maintainer-generated addresses exist, both provably unfunded.**
`docs/research/dms-mortsafe-design-round.md:189` records
`0x312d4E6E…c716A` and `0x985737DF…E48190` as *"two throwaway wallets by local
keygen, **never funded** … no faucet used, no contract deployed, no account
created"*. No private key accompanies them. Harmless; listed because they are the
only addresses in the tree the maintainer produced.

**N3 — Attribution is clean.** `maintainer-email` appears **0 times** in tracked
files (detector canary-proven, §2). Every commit in history has a single author
*and* committer identity: `aed900 <129773515+aed900@users.noreply.github.com>`.
No real name, street address, or personal identifier was found. The noreply
address appears once in prose (`docs/decisions/D2-hosting-ci.md:59`) with its
rationale attached. This is a deliberately good posture, not an accident.

**N4 — The remaining emails are third parties' own published data.** Of 13
email-shaped lines: 6 are test fixtures using `example.org`/`.invalid`; 4 are
FreeTSA's operator address inside its published root-certificate subject
(`crates/antseal-core/src/anchor/roots/PROVENANCE.md:72`,
`testdata/anchors/A25-bootstrap/roots-PROVENANCE.md:51`, and twice in
`testdata/vectors/v1/anchor/anchor.json`). Note the last two: they sit **inside
frozen golden-vector bytes** and cannot be edited without a format event. They
are also already public in the certificate itself, so nothing is disclosed by
publishing them.

**N5 — No workflow consumes any secret.** `grep -rnE 'secrets\.'` over
`.github/workflows/` returns nothing; `pages.yml:47` uses OIDC (`id-token:
write`) instead of a stored token. `.cargo/config.toml` is tracked and contains
no credential. There is no CI secret to leak.

**N6 — The live page already publishes commit identifiers.** The footer prints
``source ${info.source_commit}`` (`verifier-web/index.template.html:795`). On a
private repo that string is opaque; the moment the repo is public it becomes a
resolvable link. That is the intended reproducibility mechanism, not a defect —
noted so it is a choice rather than a surprise.

**N7 — The candour a reader will meet, listed so it is chosen knowingly.** Not
censored, and in this reviewer's judgement it is the most credible thing in the
repository. A stranger will find, among other things:

- an adversarial review of the project's own code whose stated conclusion is
  *"the dominant defect class in this codebase is not wrong code — it is
  **recorded claims the code does not implement**"* (S5);
- `docs/ci-verification.md` recording GitHub's verbatim refusal
  (*"Upgrade to GitHub Pro or make this repository public"*) and an exhausted
  minutes allowance;
- decision records that overturn the project's own earlier reasoning in plain
  language, and wave notes stating that a lane *"had been failing for an unknown
  number of commits"*;
- `docs/research/dms-mortsafe-design-round.md` reporting a named third-party
  service (NuCypher/TACo) as having *"no reachable decryption service
  anywhere"* — a measured, dated, reproducible claim, but a public one about
  someone else's product;
- a 1 MB `TODO.md` in which essentially every defect this project has had is
  described in detail.

The recommendation is to publish all of it. A verifier whose author documents
their own near-misses is more trustworthy than one who doesn't, and this
repository's records are its best evidence of the discipline the product claims.
The single item worth a second thought before publishing is the third-party
service assessment, because it names a company — it is defensible on its
measurements, and it is dated, which is the right mitigation.

---

## 3. The LICENSE gap in one place

Consolidated from B1, because Q29 needs it as a unit:

- **Missing:** licence files (0), `license` manifest fields (0/9).
- **Already asserted publicly:** 5 crates.io records
  (`MIT OR Apache-2.0`, `repository = https://github.com/aed900/antseal`),
  published 2026-08-11; `scripts/reserve-crates.sh:34`.
- **Already distributed without a grant:** `https://antseal.org/` (`200`,
  2 516 397 bytes), which carries no copyright or licence text.
- **Ruled but unexecuted:** D6 (**RESOLVED 2026-07-27**), per-crate:
  core/anchor/verifier-web `MIT OR Apache-2.0`; net/cli own code the same but
  **distribution effectively GPL-3.0** via `ant-core → self_encryption`.
- **Normative requirement:** MVP-SPEC.md:157 — *"'hostable on any static host'
  presumes redistribution rights"*.
- **Not stated anywhere user-facing:** the GPL-3.0 distribution reality for
  `antseal-net` / `antseal-cli`.
- **Brief correction:** `Cargo.toml` does **not** assert a licence; `:37`
  explicitly disclaims one pending D6/Q29.

Ordering consequence for Q65: this must land **before** the visibility flip, not
after. Every day the repository is public without it is a day the crates.io
metadata is wrong about the thing it links to.

---

## 4. Unfinished documents that read as finished

**The headline finding here is a negative one, and it corrects the brief this
lane was given.** `docs/threat-model.md` was cited to me as an example of a stub
that *reads as finished*. It does not. It declares its own incompleteness three
separate ways, at the top, before any reader reaches a stub:

```
docs/threat-model.md:3:  **Status: SKELETON (M0, task Q12).**
docs/threat-model.md:9:  Read section 1 as normative. Read section 2 as a table of
                        contents for work that has not been done.
docs/threat-model.md:24: | Threat sections (section 2) | **NOT WRITTEN** — stubs
                        only; due at M4 (Q21) | — | — |
```

Every one of the ten subsections then carries its own `*Status:*` line. The nine
unwritten ones, enumerated as requested:

| Line | Section |
| --- | --- |
| 431 | 2.1 Vault theft |
| 441 | 2.2 Vault loss |
| **452** | **2.3 Wallet linkability** (the one cited in the brief) |
| 462 | 2.4 Malicious verifier host |
| 473 | 2.5 Coercion / compelled disclosure |
| 485 | 2.6 Hostile bundles |
| 498 | 2.7 Sealer as adversary |
| 509 | 2.8 Size fingerprint |
| 521 | 2.9 Evidence independence |

The tenth, **§2.10 WASM zeroization caveat (line 523)**, is genuinely written and
says so: `582:*Status:* written (C21)`. Section 1 is complete, frozen, signed off
by `aed900` on 2026-07-28, and asserted byte-identical to
`docs/security-assumptions.md` by a test.

**Sweep for the class across the rest of `docs/`.** Real `TBD`/`FIXME`/`XXX`
markers, excluding matches on the tracker filename `TODO.md`: **0**. The
`placeholder` detector (lorem ipsum / `XXX_FIXME`) is canary-proven and returns
**0**. I found **no document in `docs/` that is incomplete without saying so**.

The residual disclosure question is therefore not honesty but expectation: a
public reader arriving at a file called `threat-model.md` for a *cryptographic
proof-of-existence tool* finds nine of ten threat sections unwritten. That is
disclosed accurately, and **MVP-SPEC.md M4 lists "threat-model doc finalized"
as a release deliverable**, so it is on schedule rather than overdue. It is worth
the maintainer deciding deliberately whether that file should be public before
Q21 writes it, because the honest label does not stop it reading as thin. The
same is true, at lower stakes, of `README.md` (B2).

---

## 5. `.devnet/` and the ignored-but-present set

Confirmed genuinely ignored and **empty**:

- `ls -A .devnet/` → **0 entries**. The funded Anvil dev key that
  `scripts/devnet/local-up` writes to `.devnet/env` is **not on disk at all**.
- `git ls-files .devnet` → **0** tracked. `git check-ignore -v .devnet/env` →
  `.gitignore:30:.devnet/`.
- `secret-guard` re-verifies this coupling itself and printed
  `OK: .devnet/ is gitignored, so excluding it from the scan removes nothing
  committable.`

Ignored directories present on disk, excluding `target/`: `.claude/worktrees/`,
`.claude/scheduled_tasks.lock`, `.devnet/`, `fuzz/{artifacts,corpus,target}/`,
`scripts/__pycache__/`. None is tracked; none would be published.

**Untracked but publishable** — the 5 files that will ship if committed:
`crates/antseal-core/tests/r87_doc_currency.rs` and decision records D71, D72,
D73, D134. Scanned with the same detectors: **0** hits for tokens, `maintainer-email`,
`/home/deb`, EVM addresses, or named hex keys. The two key-shaped hits are both
in `docs/decisions/D71-…md:337-339`, and are a **table of key header formats
mapped to the secret-guard pattern that catches each** — not material.

**For the history lane, not this one:** `.devnet/` being ignored today says
nothing about whether it was ever committed. Flagged, not assumed.

---

## 6. Q65's three recorded claims, re-measured

| Q65 claim | Recorded | Measured 2026-08-16 | Verdict |
| --- | --- | --- | --- |
| `MVP-SPEC.md` cannot be removed | 126 files + 13 registry citations | **433 tracked files**; **244** in `crates/`+`scripts/`+`.github/` alone; **13** citations in `docs/format/registry-v1.md` | **CONFIRMED, and 3.4× stronger.** The registry figure is exact. |
| `MVP-SPEC.orig.md` and `SPEC-REVIEW.md` have **zero** references from code, scripts or CI | zero | `MVP-SPEC.orig.md`: **7** files. `SPEC-REVIEW.md`: **10** files | **STALE — the claim is now false as written** |
| Five tracked files contain `/home/deb/…` | 5 | **18 files, 39 lines** | **STALE — 3.6× under** |

**On claim 2, the detail that decides the recommendation.** The references are
citations, not code dependencies — nothing parses either file, so removing them
breaks no build and no lane. But three of the new referents are load-bearing
surfaces:

```
scripts/check-traceability.py:592-597   explains why both files are OUT of the literal-scan roots
crates/antseal-wasm/tests/page_template.rs:151   // The comma is normative — SPEC-REVIEW.md:287's comma-less variant is not.
verifier-web/index.template.html:134             SPEC-REVIEW.md:287's comma-less variant is not. -->
```

`SPEC-REVIEW.md:287` is cited **by line number** as the provenance of a normative
copy rule, in a live test and in the **shipped page**. `check-traceability.py`
records that `MVP-SPEC.orig.md` is *"kept verbatim so that `SPEC-REVIEW.md`'s
line references still resolve"* — the two are load-bearing **for each other**.

**Recommendation, not executed** (deletion is the maintainer's call, and this
lane moved nothing): keep both. They are cheap to keep, they are two of the very
few documents that let an outsider audit how the spec reached its current form —
which is the argument Q65's own `Do` section makes for publishing the spec at all
— and removing them silently orphans a line-number citation in the page that is
already live. If they are removed anyway, the three references above must be
rewritten in the same change.

---

## 7. What this scan does NOT cover

Stated plainly, because a check whose limits are unwritten gets trusted for
things it never did.

1. **Git history — the sibling lane's.** Every "clean" verdict here describes
   HEAD only. A secret committed and later removed is invisible to `git grep`.
2. **378 of 1 219 tracked files were never string-scanned** — binary or empty,
   skipped by `grep -I`: 256 `.bin` fuzz seeds, 30 `.cbor`, 22 `.tsr`, 22
   `.timestamp`, 18 `.upgrade`, 13 `.tsq`, 9 `.der`, 3 `.ots`. A secret embedded
   in a CBOR vector or a DER fixture would not have been seen. `target/` and
   `.claude/worktrees/` were not scanned at all.
3. **Pattern detection only — no entropy analysis.** All 24 detectors match known
   shapes. A high-entropy secret with no recognisable prefix, an unlabelled
   base64 blob, or a key split across lines would pass every one of them.
4. **Documentary truth was spot-checked, not exhaustively audited.** I verified
   `README.md`, the licence surface, `docs/threat-model.md`, and the copy-lint
   corpus. The other ~165 `docs/` pages were swept for stub markers and candid
   language, **not** read for claims the code does not support — which this
   project's own review names as its dominant defect class. A full pass is a
   task, not a grep.
5. **Whether the 33 review findings are actually fixed** (S5) — unverified.
6. **The `.der` root certificates were not cryptographically re-verified**; I
   checked their provenance documents, not the bytes.
7. **Not legal advice.** Trademark availability for the name "antseal", export-
   control or crypto-notification obligations for publishing cryptographic
   source, and whether the GPL-3.0 obligations inherited via `ant-core` are
   satisfied by the intended distribution channel (D72/Q31's territory) are all
   outside this review.
8. **Third-party licence terms were checked for *presence*, not interpreted.** I
   report that no terms are recorded; I do not rule on what the Unicode or ACVP
   licences require.
9. **No dynamic analysis.** Nothing was built or executed except the two guards
   and their self-tests; no binary was inspected for embedded strings.

---

## 8. Work this scan suggests deserves a task row

Described for the registrar; **no rows were created by this lane.**

1. **Value-shaped secret detection for Markdown** — close S3's largest hole
   without losing the `*.md` exclusion's benefit (Q2's lane).
2. **A BIP39 / mnemonic detector in `secret-guard`, before D134 lands** — the
   guard cannot see the material D134 is about to introduce. Timing-critical:
   D134 is due before U32.
3. **`secret-guard` into `scripts/local-gate.sh`** — it is referenced there only
   in comments; the pre-push check is manual today.
4. **A `/home/…` lint** — Q65's Accept already requires it and nothing implements
   it; without it S1 regrows.
5. **Licence terms as a required field in every `PROVENANCE.md`** — the D31
   convention already makes a missing provenance file a red lane; licence is the
   field it forgets, and it is the one that binds on publication (S4).
6. **A disposition ledger for the 2026-07-31 review's 33 findings** (S5).
7. **A publication-currency check for `README.md`** — B2's staleness was
   invisible to every existing lane. A cheap version asserts the task count and
   the status line against measurable facts.

---

*Prepared by the worktree-scrub lane, 2026-08-16. The history half of Q65's
scrub is `docs/reviews/pre-public-scrub-history.md`, owned by a sibling lane and
untouched here. No file outside this document was created, modified, moved or
deleted; no repository setting was changed.*
