# Pre-public scrub — git history, delta since 2026-08-16

**Date**: 2026-08-27 · **Repo**: `aed900/antseal` (`isPrivate: true` at time of scan)
**Subject**: every object the store has gained since the 2026-08-16 history scrub, plus a
full re-scan of the whole store as a superset control.
**Instrument**: `scripts/scrub-history.sh` — new, read-only, self-testing, and **repeatable**.
**Scope note**: this review **reports only**. No history was rewritten, no ref was moved, no
credential was revoked, rotated or tested, no repository setting was changed.

## Verdict

**No BLOCKER. No live credential material of any kind was found, in the delta or in the
full store.**

All 129 delta findings and all 603 full-store findings resolve to five documentary classes,
enumerated and located in §4. Not one is a key, a token, a wallet, or a seed.

Three things are worth the maintainer's attention before the flip, none a blocker:

- **N-1**, the one measurement that CHANGED direction since 2026-08-16: the maintainer's
  personal email address, certified at **0 occurrences** by that review, is now in **15 blobs
  across 4 paths** — and every one of them is a scrub report quoting the address as the string
  it was searching for. The reports put it there.
- **N-2**, `secret-guard`'s **Gap 1 is still open** a wave later, and this scan proves it by
  measurement rather than by re-reading the old finding.
- **SF-1**, the reason this file has a script beside it: **nothing re-scans history**, and the
  next commit reopens the gap this review closes.

---

## 1. Why there is a delta at all

Making the repository public publishes **git history**, not a worktree — that is D161's measured
finding (`docs/decisions/D161-what-the-flip-publishes.md`). The only history-wide scrub on file
is `docs/reviews/pre-public-scrub-history.md`, dated **2026-08-16**. Nothing re-runs it.

`secret-guard` does not cover the gap and does not claim to. It is a **worktree** scan
(`lane_secret_guard()` in `scripts/ci-lanes.sh`), it passes `--exclude-dir=.git` explicitly, and
it is not wired into `scripts/local-gate.sh`. A blob that was committed and later deleted is not
in its subject at all.

| | 2026-08-16 | 2026-08-27 | change |
|---|---|---|---|
| objects | 7935 | **8439** | **+504** |
| blob | 3450 | **3749** | **+299** |
| tree | 3670 | **3855** | +185 |
| commit | 813 | **833** | **+20** |
| tag | 2 | 2 | 0 |
| unreachable | 424 | 424 | 0 |

Waves 28, 29 and 30 landed in that window. **504 objects had never been scanned by anything.**

---

## 2. What was scanned

Everything below is `scripts/scrub-history.sh`, run from the repo root, read-only.

### The delta run — the subject of this review

```
scripts/scrub-history.sh --since 3352fbec0b3ef7a2d79f438db412e6a80f48a62b
SCRUB_HISTORY mode=since:3352fbec… objects=8439 blob=3749 tree=3855 commit=833 tag=2
              reachable=8015 unreachable=424 scanned=687 bytes=45768925 rules=11
              findings=129 verdict=FINDINGS          # REAL_EXIT=1
```

`3352fbec` is `main` as `git ls-remote origin` reported it **on the day of the 2026-08-16 scan**,
quoted verbatim in that review's §2. It is therefore the exact baseline that review measured
publication against.

**Corpus: 687 objects — 385 blob, 300 commit, 2 tag — 45 768 925 bytes.** Trees are skipped: they
carry no free text, and every filename they hold reaches the corpus inside the commits that name
them.

`--since` scans the store **minus everything reachable from that commit**. That is a *superset*
of "introduced since", and the arithmetic says exactly by how much:

| | delta corpus | of which |
|---|---|---|
| blobs | 385 | 299 genuinely new + **86** local-only-at-baseline (2026-08-16 §2's own figure) |
| commits | 300 | 20 genuinely new + **280** local-only-at-baseline (same source) |

Both decompose exactly. That is an independent corroboration of the +504/+299/+20 growth figures
and of the old review's published local-only counts, from two measurements taken eleven days
apart.

### The full-store control run

Because a delta is only as good as its baseline, the whole store was re-scanned as well:

```
scripts/scrub-history.sh
SCRUB_HISTORY mode=full objects=8439 blob=3749 tree=3855 commit=833 tag=2
              reachable=8015 unreachable=424 scanned=4584 bytes=217249502 rules=11
              findings=603 verdict=FINDINGS          # REAL_EXIT=1
```

**4584 objects, 217 249 502 bytes (207 MB), every byte scanned.** The full run's findings are a
strict superset of the delta's and add no path the delta did not already surface (§4).

### The reachability proof, asserted rather than printed

```
8439 total − 8015 reachable = 424 = git fsck --unreachable count
```

The old review printed this arithmetic. **This script asserts it**, on every run in every mode,
and refuses to emit a verdict if it does not balance — because a scan whose corpus is not
provably the whole object store cannot mean anything by "clean". `--self-test` goes one step
further and plants a fixture in a **dangling blob that is never committed**, so "the corpus
reaches unreachable objects" is re-measured every run rather than inferred from a flag name.

---

## 3. The instrument, and the proof it can fail

This project's dominant defect class is the check that is green because nothing reachable could
redden it. So the instrument is reported before the verdict.

### 3.1 Rule set

Eleven rules. **R1–R5 mirror `lane_secret_guard()`'s `scan()` rule for rule, in its order, with
its patterns and its ids** — including the R4a/R4b/R4c split — so the two rule sets can be
diffed by eye. Nothing was dropped. Four rules were **added**, and they are marked `[ADDED]` in
the script, in its output, and here:

| id | class | source |
|---|---|---|
| R1 | PEM private-key block (RSA/EC/plain/OPENSSH/ENCRYPTED) | `secret-guard` (1) |
| R2 | EVM keystore JSON — both web3-secret-storage keys in one object | `secret-guard` (2) |
| R3 | reserved vault-export magic | `secret-guard` (3) |
| R4a | age secret-key marker | `secret-guard` (4a) |
| R4b | minisign/rsign secret-key header comment | `secret-guard` (4b) |
| R4c | minisign/rsign secret-key body type tag, both kdf_alg arms | `secret-guard` (4c) |
| R5 | devnet wallet-key export line with a 64-hex value | `secret-guard` (5) |
| **E1** | **PGP private-key block — the flavour R1 structurally cannot match** | **ADDED** (Gap 1, 2026-08-16 §6) |
| **E2** | **forge token (personal / OAuth / server / fine-grained)** | **ADDED** (2026-08-16 §6, "not covered at all") |
| **E3** | **AWS access key id** | **ADDED** (same) |
| **E4** | **Slack token** | **ADDED** (same) |

E1 is written to require at least one label character where R1's trailing dashes must sit, so an
E1 hit can only ever be a block R1 missed — the two are disjoint by construction, not by
convention. E2–E4 were measured at **zero** across all 3450 blobs on 2026-08-16, so they widen
coverage without adding resolution burden, and they remain at zero here.

**Two exclusions in `secret-guard` are deliberately NOT inherited**, and one of them is the point
of the whole exercise:

- **`--exclude='*.md'`** — D161 records this as "a measured blind spot this record inherits
  rather than closes". Markdown is 1053 of 3367 reachable blob paths. History is exactly where
  it matters. **Not inherited.** It is why R3 reports 365 objects in the full run and why the
  delta's largest corpus slice is `.md`.
- **`--exclude='ci-lanes.sh'` and the exact-path exemption for the vault-export module** — both
  are correct for a worktree gate and wrong for a history scrub, because a path-keyed exemption
  says nothing about what a *blob* contains. **Not inherited.** The cost is a fixed set of
  known-benign documentary hits on every run; they are resolved by name in §4 rather than
  filtered away, because a filter that hides a known hit hides an unknown one too.

### 3.2 The self-test

```
$ scripts/scrub-history.sh --self-test          # REAL_EXIT=0
arm [full scan] OK: 12/12 expected hits, every rule fired under its own id, no control reported.
arm [--since A (every fixture is newer than A)] OK: 12/12 expected hits, every rule fired under its own id, no control reported.
arm [--since B (only the dangling blob is outside B)] OK: 1/1 expected hits, every rule fired under its own id, no control reported.
self-test OK: 11 rules, 11 committed fixtures + 1 dangling fixture, 3 negative controls (including this script's own source), 3 arms.
SCRUB_HISTORY mode=self-test rules=11 fixtures=12 arms=3 findings=0 verdict=PASS
```

It builds a **real throwaway git repository** under `mktemp -d` and drives the same `scan_repo`
the verdict comes from. Structural properties, each an assertion rather than a claim:

- **One fixture per registered rule id**, each required back **under its own id**, so one rule
  cannot cover for another. This is the exact defect `secret-guard` carried for its whole life
  before Q245, where a neighbouring fixture filled an unexercised arm's slot in the arithmetic.
- **The rule count is derived from the live function body** (`declare -f rules_scan | grep -c`)
  and compared against the registered id list, so a rule cannot be added without a fixture.
- **The dangling fixture** is written with `hash-object -w` and never referenced by any tree,
  commit or ref. `git log` cannot reach it; a worktree scan cannot see it; the corpus must.
- **Three negative controls**, none of which may be reported: tool-naming prose, a minisign
  public key whose all-zero keynum shares five leading base64 characters with the unencrypted
  secret-key type tag, and the two signature header lines — plus **a verbatim copy of the
  scanner's own source**.
- **`--since` is exercised in both directions**: once where the delta must contain every
  fixture, once where it must contain **only** the dangling blob. A delta mode that quietly
  scanned everything would pass every other arm and fail this one; so would one that scanned
  nothing.

**Every fixture is assembled at run time from pieces. No secret-shaped literal exists in the
script.** That is load-bearing twice over: a literal would red `secret-guard`'s worktree scan
(which exempts exactly one basename, and it is not this one), and — because history is
append-only — it would poison **every future run of this script, permanently**. The copy-of-self
negative control is what turns that from a promise into an assertion. Confirmed end to end:
`scripts/ci-lanes.sh secret-guard` exits **0** with the new script in the tree.

**This document is written under the same rule** and for the same reason. No marker, key
fragment, token, address or machine path appears here as a matchable literal. §4 N-1 is what
happens when a review document does not observe it.

### 3.3 Proof the scan can go red — two plants, confirmed by message

A nonzero exit proves nothing on its own, so both plants were confirmed by the text of the
failure, and the file was restored byte-identically (`cmp`) and re-run green after each.

**Plant 1 — break a detection rule.** R4c's pattern was changed from its two real base64 type
tags to two that cannot occur, leaving the script syntactically valid and behaviourally wrong:

```
REAL_EXIT=1
::error::scrub-history: self-test arm [full scan] FAILED: expected 12 hits, got 11.
Rule/object pairs that did NOT fire: R4c:9b2a1133ab8a19ce1f68a78815f2edd02acf2fc4. …
```

The broken rule is named, with the object its fixture hashes to.

**Plant 2 — add a rule with no fixture.** A twelfth `hits+=` was appended to `rules_scan` and
deliberately left out of the id register — the shape of defect that stays invisible while every
total balances:

```
REAL_EXIT=1
::error::scrub-history: self-test FAILED: rules_scan carries 12 detection rules, but RULE_IDS
registers 11. A rule with no registered id gets no fixture, is never exercised, and every total
still balances — add the id AND its fixture in the same act.
```

**Plant 0 — the one nobody planted.** The self-test's *first* run failed on its own harness, and
then on its own fixture, before it ever passed:

1. `printf … | grep -q` under `set -o pipefail`: `grep -q` exits on first match, `printf` takes
   SIGPIPE, and the pipeline's status becomes the signal — so a **successful** lookup took the
   failure branch. It is a race, so it passed most of the time. Fixed by using here-strings, with
   the reason recorded at the site. **The same construction is live in `scripts/ci-lanes.sh`'s
   `secret-guard` self-test** (two sites, in the `missing`/`unexpected` loops) and in
   `check-custody-log.py`'s vicinity — flagged, not touched; out of this lane's write scope.
2. The R2 keystore fixture was assembled one character wrong and produced `cipherttext`, so R2
   fired on nothing. The arm named R2 and its object id. **A rule that could not detect its own
   planted secret was caught before it ever reported a clean verdict** — which is the entire
   argument for fixturing every rule.

---

## 4. Findings

### BLOCKER

**None.**

### SHOULD-FIX

**SF-1 — a scan is not a document; nothing re-runs history coverage.** This is the finding the
delta exists to prove: 504 objects accumulated unscanned in eleven days, across three waves,
with a green gate the whole time, because the only history scrub was a dated file.
`scripts/scrub-history.sh` makes the scan repeatable; **wiring it somewhere that runs is a
separate act and has not been done.** `--since <last-scanned-commit>` is seconds of work
(10.9 s for this delta); the full run is under two minutes. Row candidate. Until it is wired,
the honest statement is that history coverage is current **as of `3922ada`** and stale after the
next commit.

### NOTE

**N-1 — The maintainer's personal email address is now in history, and the scrub reports put it
there.** The 2026-08-16 review states, in bold: *"occurs 0 times in commit metadata, commit
messages, and all 3450 blobs — with the detector for that exact string proven live"*, and
concludes *"Nothing here requires a history rewrite."* **That is no longer true.** The address
now appears in **15 blobs** across **4 paths**:

| path | note |
|---|---|
| `docs/reviews/pre-public-scrub-history.md` | quotes the address as its search term, twice |
| `docs/reviews/pre-public-scrub-github-side.md` | same, in two tables |
| `docs/reviews/pre-public-scrub-worktree.md` | same |
| `tasks/Q.md` | 11 revisions, restating the finding |

Every occurrence is a report **certifying the address is absent** — quoting the literal it
searched for. All four paths are in `HEAD`, so all four publish.

Severity: low. It is a contact address, not a credential, and it is not a secret in the
cryptographic sense. Flagged because (a) it is the single measurement that reversed since the
last review, (b) it reversed *as a side effect of writing the review*, and (c) it is a
non-obvious class of harm that no lint catches — `secret-guard` excludes `*.md`, and the
`machine-paths` lint does not scan `docs/reviews/` or `tasks/`. Removing it needs a history
rewrite, so the decision is the maintainer's; the cheap half is to stop adding occurrences.
**No literal appears in this file.**

**N-2 — `secret-guard`'s Gap 1 is still open, and E1 now measures it rather than recalling it.**
The PGP private-key block header does not match `secret-guard`'s R1 pattern, because that pattern
requires the closing dashes immediately after the label. E1 exists to catch what R1 cannot, and
it fires **23 times** in the delta — every one of them documentation *about the gap*
(`tasks/Q.md` ×11, `docs/instrument-ledger.md` ×11, `docs/reviews/pre-public-scrub-history.md`
×1). **Zero real PGP blocks exist anywhere in history.** The gap is a detection hole, not a leak,
and it has now survived a wave since it was first measured. The one-character fix is in the old
review's §6.

**N-3 — The maintainer's home path keeps growing in history (N-1 of the old review, continued).**
The maintainer's absolute home prefix appears **248 times** across **20 paths** in the delta
alone, now including nine decision records, `docs/instrument-ledger.md`, `tasks/P.md`,
`tasks/Q.md`, `TODO.md`, `docs/ci-verification.md` and `scripts/check-traceability.py`. The
`machine-paths` lint (D144) covers LIVE surfaces — `crates/`, `scripts/`, `verifier-web/`,
`docs/user/` and four root files — and `check-traceability.py` carries the pattern as a
registered, pinned divergence. `docs/decisions/`, `docs/reviews/`, `tasks/` and `TODO.md` are
outside that boundary **by design** (the line is LIVE versus PRESERVED), and they are where the
248 sit. Discloses the maintainer's Linux username and project directory. Not a credential, no
host identity, no network reachability. Unfixable without a rewrite. No literal appears here.

**N-4 — Commit metadata is clean across the whole delta.** All **20** new commits, and all
**300** commit objects in the delta corpus, carry only GitHub noreply addresses:

| identity | author+committer lines across 300 delta commit objects |
|---|---|
| `129773515+aed900@users.noreply.github.com` | 560 |
| `aed900@users.noreply.github.com` | 30 |
| `m2w4-kappa@users.noreply.github.com` | 10 |

Both components are public by construction. **Nothing in commit metadata requires a rewrite** —
which matters, because it is the one category that cannot be scrubbed without rewriting every
commit.

### BENIGN — confirmed by reading, not assumed

Every one of the 129 delta findings falls into one of five classes. The classes were established
by extracting the **distinct matched strings** (with 55 characters of trailing context) across
every hit object and reading all 38 of them, not by sampling.

**BENIGN-1 — `secret-guard`'s own self-test literals (R1, R2, R3, R4a, R4b, R4c).** Live in
`scripts/ci-lanes.sh` and, in the unreachable set, in earlier revisions of `ci-lanes.sh`,
`.github/workflows/ci.yml` and `CONTRIBUTING.md` — the same three blobs the 2026-08-16 review
opened and identified individually (BENIGN-1 there). The R4c bodies decode to exactly
`self-test-no-key-material`, verified by decoding, not by trusting the filename.

**BENIGN-2 — Prose in documentation naming a marker (R1, R3, R4a, R4b, E1).** Backtick-quoted
markers in `TODO.md`, `tasks/Q.md`, `tasks/U.md`, `CONTRIBUTING.md`, `docs/threat-model.md`,
`docs/ci-verification.md`, `docs/instrument-ledger.md`, `docs/decisions/README.md`,
`docs/decisions/D47-vault-export-format.md` and
`docs/decisions/D71-binary-signing-mechanism-and-key-custody.md`. D71's are a table of PEM label
strings for sigstore/cosign formats — **labels, never bodies**.

**BENIGN-3 — The three scrub reports quoting their own evidence (R1, R2, R3, R4a, E1).**
`pre-public-scrub-history.md`, `pre-public-scrub-github-side.md` and
`pre-public-scrub-worktree.md`. The 2026-08-16 review predicted this about itself: *"this
document and its sibling are themselves on that list, by virtue of quoting the markers as
evidence."* Confirmed. It is also the mechanism behind N-1.

**BENIGN-4 — A superseded doc comment in `crates/antseal-cli/src/vault/header.rs` (R3).** Blob
`11ace62c`, a 2026-08-01/02 revision (`U5`/`U8` work), whose doc comment at line 41 named the
magic while explaining why the header carries it. **The current `HEAD` revision does not contain
it**; the string survives only in that superseded blob, on a branch not reachable from the
publication baseline. Worth naming because `secret-guard`'s R3 exemption is keyed to the exact
path of the *export* module — `header.rs` was never exempt, and the guard was right not to
exempt it.

**BENIGN-5 — No key material of any kind, established by direct measurement (R5, E2, E3, E4 all
zero).** Four probes over the 385 delta blobs, over and above the eleven rules:

- **0** devnet wallet-key export lines (R5), **0** forge tokens (E2), **0** AWS access key ids
  (E3), **0** Slack tokens (E4) — each rule proven live by its own fixture in the same run, so
  each zero is a true negative rather than an untested assumption.
- **0** master-secret (`W`) assignments introduced in the delta.
- **330** distinct 64-hex values, and **0** of them in key-adjacent context — a case-insensitive
  sweep for a secret/private/wallet/seed/mnemonic/key word within 26 characters of any 64-hex
  value returns nothing. The published all-zero-through-`0x1f` synthetic vector is present, as
  expected; it is bytes `0x00`–`0x1f` in order and protects nothing.
- **0** real PEM bodies: for every hit object, the line following any key-block header was tested
  for a 40+ character base64 run. Nothing matched. Every PEM hit in history is a **header
  without a body**.

**BENIGN-6 — Nothing unexpected in the delta's shape.** 385 blob paths by extension: `.md` 153,
`.rs` 82, `.yml` 15, `.sh` 13, `.py` 12, `.toml` 11, `.txt` 9, `.tsv` 1, `.html` 1, `.gitignore`
1. No archives, no executables, no images, no binaries. The five largest delta blobs are all
`TODO.md` revisions (1.30–1.45 MB), consistent with a 698-row tracker.

**BENIGN-7 — The full-store control adds no new path.** 603 findings across **20** distinct
paths, every one already accounted for above or in the 2026-08-16 review — the delta's paths
plus `crates/antseal-cli/src/vault/export.rs` (the sanctioned constant definition),
`.github/workflows/ci.yml`, `testdata/README.md`, and
`docs/research/paper-key-transport-design-round.md` (the old review's BENIGN-3, a documented
example phrase with its disclaimer three lines above it). Per-rule totals: R1 57, R2 90, R3 365,
R4a 57, R4b 8, R4c 3, R5 0, E1 23, E2 0, E3 0, E4 0.

---

## 5. What this scan does NOT cover

Stated plainly, because a scrub that overstates its reach is worse than none. Items 1–3 are
inherited limits of signature-based scanning and are unchanged from the 2026-08-16 review, which
states them at greater length.

1. **Plaintext only.** A secret inside a base64 blob, an archive or an encrypted file will not
   match. No such archives exist in the delta (BENIGN-6), which bounds but does not eliminate it.
2. **No entropy heuristic and no BIP39 wordlist.** Detection is signature-based. The 64-hex sweep
   is exhaustive for its shape and nothing else is. Mnemonic detection is **not** a rule of this
   script at all — the old review's structural sweep is not reproduced here, and D134's
   hand-written paper keys will need one when they ship.
3. **Whether any 64-hex value is a funded key.** Deriving addresses and querying chain state is a
   network action and out of scope. The classification rests on context and on the zero
   key-adjacent result.
4. **The current worktree.** `docs/reviews/pre-public-scrub-worktree.md` is that subject.
   Uncommitted, untracked and gitignored files — including the devnet environment export, which
   holds a funded devnet wallet key — were not examined here. R5's zero is evidence it never
   reached the object store; its on-disk state is not this review's finding.
5. **GitHub-side artifacts.** Issues, PRs, Actions run logs, gists, release assets, wiki and the
   repository description live outside git. `docs/reviews/pre-public-scrub-github-side.md` is
   that subject.
6. **Anything already pushed elsewhere.** Only the object store of this clone was read; no remote
   was queried in this run.
7. **Objects garbage-collected before this run** are, by definition, unrecoverable and
   unscannable.
8. **The gap after `3922ada`.** This review is a measurement at a commit, not a standing
   guarantee. That is SF-1, and it is why the script exists.

---

## 6. Reproducing this

```
scripts/scrub-history.sh --self-test                      # 11 rules, 12 fixtures, 3 arms; must pass first
scripts/scrub-history.sh --since 3352fbec0b3ef7a2d79f438db412e6a80f48a62b
scripts/scrub-history.sh                                  # full-store control
scripts/ci-lanes.sh secret-guard                          # the worktree complement
```

Exit 0 clean, 1 on any finding or failed invariant. Every mode ends with one machine-readable
`SCRUB_HISTORY …` line. The auxiliary probes in BENIGN-5 and N-1/N-3/N-4 are **not** part of the
script; they are recorded in §4 with their counts so a later reviewer can re-derive them, and
turning the useful ones into rules is a separate act.

Findings are resolved **by name in this file**, never by narrowing the script. A rule that is
loosened to make a documented hit disappear also hides the undocumented one next to it.
