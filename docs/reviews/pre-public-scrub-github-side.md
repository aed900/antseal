# Pre-public scrub — GitHub-side artifacts

**Date**: 2026-08-17 · **Repo**: `aed900/antseal` (`isPrivate: true`, re-verified at the end
of the scan and unchanged)
**Subject**: everything GitHub holds about this repository that **no local `git` scan can
reach** — Actions run logs, secrets and variables, releases, issues, PRs, comments, artifacts,
webhooks, deploy keys, environments, Pages, protection rules, and the security surface.
**Gates**: task **Q65**. Two sibling lanes own the working tree
(`docs/reviews/pre-public-scrub-worktree.md`) and git history
(`docs/reviews/pre-public-scrub-history.md`); this file covers neither.

This lane exists because the history lane closed by naming its own gap:

> Left uncovered and worth its own pass before going public: **GitHub-side artifacts —
> Actions logs, issues, PRs, release assets — which no local scan can see.**

**Scope note**: this lane **reports only**. Every `gh` call was a read. No repository setting
was changed, no visibility was flipped, no credential was rotated, revoked or tested, no
issue/PR/release/comment was created, and nothing was pushed. Rate-limit consumption for the
whole scan: **103 of 5 000** requests.

---

## Verdict

**Nothing on the GitHub side blocks going public.** No live credential material exists in any
server-side artifact. The two blockers that stand against the flip are the worktree lane's
**B1 (no LICENSE)** and **B2 (stale README)**; this lane adds none and independently confirms
B1 from GitHub's own community-profile API.

Four SHOULD-FIXes are recorded below, all of them about what publication *enables* rather than
what it *discloses* — a stranger's fork PR executing repo code, the absence of any
security-disclosure channel on a repository with issues switched on, an unpinned redaction in
the one artifact that handles a funded wallet key, and a recorded platform blocker that has
gone stale.

The single most consequential measurement: **all 57 workflow runs' logs are still retained and
none has expired**, so publication makes **91.8 MB across 610 job logs** world-readable in one
step. Every retrievable byte of it was scanned — not sampled — and it is clean.

---

## 1. Scope, method, and the auth I actually held

Three rules, inherited from the sibling lanes because this project's dominant defect class is
*the assertion that cannot fail*:

1. **No category is reported empty without a demonstrated detection.** Every regex was proven
   to fire against a planted corpus outside the repository (§2), and every `gh` query reported
   empty was proven to return data when data exists, by running the identical command against a
   repository that has some (§3).
2. **"Zero exist" and "I could not query it" are different results** and are reported
   separately (§4). A `gh` call that 403s on a missing scope is not evidence of absence.
3. **Real exit codes.** Output went to files and `$?` was read directly. Where a pipe
   intervened, note that `${PIPESTATUS[0]}` **does not survive a command substitution** —
   `n=$(grep … | wc -l); rc=${PIPESTATUS[0]}` reports the *assignment*, not grep, and my first
   pass printed `rc=0` for four greps that had actually returned 1. Those numbers were
   discarded and re-measured with `grep … > file; echo $?`. The corrected codes are in §3.

### Auth scopes held

```
$ gh auth status
✓ Logged in to github.com account aed900 (keyring)   [active]
  Token scopes: 'gist', 'read:org', 'repo', 'workflow'
```

`repo` + `workflow` covers Actions runs, logs, artifacts, secrets *metadata*, variables,
environments, hooks, deploy keys, Pages, protection and rulesets. **`read:project` and
`security_events` are NOT held.** The one query that failed *because of* that is Projects v2
(§4) — every other empty result below was a successful query returning zero, and each is
evidenced by its HTTP status.

### Principal commands

```
gh api repos/aed900/antseal/actions/runs --paginate      # 57 runs, total_count cross-checked
gh run list --limit 1000 --json databaseId,workflowName,conclusion,createdAt,headSha
gh api repos/aed900/antseal/actions/runs/<id>/logs       # x57, every run, full ZIP
gh api repos/aed900/antseal/actions/runs/<id>/jobs       # x57, 715 jobs enumerated
gh api repos/aed900/antseal/actions/artifacts --paginate # 10, then /zip x9 live
gh secret list [--app dependabot|codespaces] ; gh variable list
gh api repos/aed900/antseal/{hooks,keys,pages,environments,rulesets,forks,collaborators}
gh api repos/aed900/antseal/branches/main/protection -i
gh api repos/aed900/antseal/{comments,issues/comments,pulls/comments}
gh issue list --state all ; gh pr list --state all ; gh release list
gh api repos/aed900/antseal/{dependabot,code-scanning,secret-scanning}/alerts
gh api repos/aed900/antseal/contents/.github/workflows?ref=main   # remote truth, not local
gh api rate_limit ; gh repo view --json isPrivate     # first and last call, unchanged
python3 detect_gh.py canary <scratch>/canary          # 52/52 must fire before any verdict
python3 detect_gh.py scan   <scratch>/ext             # 91 838 443 bytes of log text
```

The workflow files were fetched **from the remote at `refs/heads/main`**, not read from the
local tree, because the local tree has uncommitted edits and it is the remote copy that a
stranger will read and that GitHub will execute.

---

## 2. Canary results — proof each detector can fire

**52 patterns, 52 fired.** The corpus is 55 structurally faithful, cryptographically worthless
fakes written to scratch space **outside the repository**. It is not committed, for the reason
the history lane gives: committing it would poison every future scan of this repo, including
`secret-guard`'s.

```
$ python3 detect_gh.py canary <scratch>/canary
MODE=canary FILES=55 BYTES=4096 PATTERNS=52
FIRED=52/52
NOT_FIRED=(none)
```

That is the second run. **The first returned `FIRED=51/52`**, and the miss is worth recording
because it is the exact defect class this project keeps finding in itself: my `google_api_key`
pattern ended in `\b` and my fake had 37 characters after `AIza` instead of 35, so the anchor
could never match. The pattern *and* the fake were fixed and the category re-run. One category
was one step away from being reported clean by a check that could not fire.

Detector families, all canary-proven: PEM private keys (RSA/EC/plain/ENCRYPTED/OPENSSH/**PGP
BLOCK**), PGP messages, SSH public keys, age, minisign (encrypted **and** unencrypted), EVM
keystore JSON, the antseal vault-export magic; GitHub classic and fine-grained tokens, Actions
runtime/OIDC token names, JWT, AWS, Slack, npm, crates.io/`CARGO_REGISTRY_TOKEN`, Stripe,
Google, Porkbun, Infura/Alchemy/QuickNode/Ankr RPC keys, `Authorization:` headers, basic-auth
URLs, `.netrc` lines, `curl -u`; generic `password:`/`api_key:` assignments,
`*PRIVATE_KEY=`, `MNEMONIC=`, `ANTSEAL_DEVNET_WALLET_PRIVATE_KEY`; the ten well-known
Anvil/Hardhat keys, the Anvil standard mnemonic, `0x`-prefixed 64-hex, 12- and 24-word BIP39
runs; `maintainer-email`, any email, `/home/deb`, any `/home/*`, `/Users/*`, `C:\Users\*`,
private IPv4, internal hostnames, phone numbers; and six CI-log-specific detectors —
`***` masking, `::add-mask::`, `set -x` traces, environment dumps, `/usr/bin/env` steps, and
`${{ secrets.* }}` references.

### 2.1 Planted-fault test on the **real** pipeline

A canary corpus proves the regexes compile. It does not prove the pipeline that produced the
verdict — walk the extracted tree, read bytes, apply patterns — fires on real log text. So two
genuine job logs were copied to scratch, scanned to establish a baseline, then a fake token, a
real Anvil key and a `/home/deb` path were appended **into the real log bytes** and the
identical command re-run:

| Detector | baseline | after planting |
| --- | --- | --- |
| `gh_token_classic` | 0 | **1** |
| `private_key_assign` | 0 | **1** |
| `antseal_devnet_key_name` | 0 | **1** |
| `anvil_wellknown_key` | 0 | **1** |
| `evm_privkey_0x` | 0 | **1** |
| `abspath_home_deb` | 0 | **1** |
| `abspath_any_home` | 39 | **40** |

Six detectors that read zero across the whole corpus went red on demand, in real log text,
through the same code path. The zeros in §5 are measurements.

### 2.2 Independent cross-check with different tooling

A systematic flaw in one pipeline produces a confident false clean, so the corpus was re-scanned
through a path sharing no code with `detect_gh.py` — plain `grep -rhaoE` — with real exit codes:

| Pattern | shell grep over logs | `detect_gh.py` | grep exit | same grep over canary |
| --- | --- | --- | --- | --- |
| `gh[pousr]_[A-Za-z0-9]{36,}` | **0** | **0** | 1 (no match) | 3 hits, exit 0 |
| `github_pat_…` | **0** | **0** | 1 | 1 hit |
| `(AKIA\|ASIA)[0-9A-Z]{16}` | **0** | **0** | 1 | 2 hits |
| `xox[baprs]-…` | **0** | **0** | 1 | 1 hit |
| `eyJ….eyJ….` (JWT) | **0** | **0** | 1 | 1 hit |
| any email address | **0** | **0** | 1 | 3 hits |
| `/home/deb` | **0** | **0** | 1 | 1 hit |
| `maintainer-email` | **0** | **0** | 1 | 1 hit |
| `\b[0-9a-f]{64}\b` | 1 471 | — | 0 | 11 hits |

Two independent implementations agree on every value, and each one's zeros are demonstrated
true negatives rather than silent failures.

### 2.3 The encoding-evasion test

GitHub masks a registered secret only on exact match; a base64'd or partially quoted secret is
not masked. The brief asks for that pattern specifically, so it was tested rather than reasoned
about: every base64-shaped blob of 40+ characters in the log corpus was decoded, filtered to
those decoding to ≥90 % printable text, and the token detectors re-run on the **plaintext**.

```
[canary-b64] base64-shaped blobs=4  decoded-to-text=4
     2 gh_token   2 x-access-token   1 aws   1 pem        <- CANARY OK, sweep is live
[ext]        base64-shaped blobs=18328  decoded-to-text=0
     0 gh_token   0 gh_pat   0 x-access-token   0 aws   0 pem   0 bearer
```

18 328 base64-shaped strings exist in the logs and **not one decodes to printable text** — they
are hex digests and build identifiers that happen to sit in the base64 alphabet. The canary
blobs pass the same printability filter and are caught, so the zero is the sweep working, not
the filter swallowing everything.

---

## 3. Proving the *queries* can return data

A detector canary says nothing about a `gh` call that returns `[]`. Each empty category was
therefore re-run as the identical command against a repository that has the thing:

| Query on `aed900/antseal` | Result | Same command, canary target | Canary result |
| --- | --- | --- | --- |
| `gh issue list --state all` | `[]` | `--repo cli/cli` | 3 issues |
| `gh pr list --state all` | `[]` | `--repo cli/cli` | 3 PRs |
| `gh release list` | empty | `--repo cli/cli` | 3 releases |
| `repos/…/comments` | `[]` | `repos/cli/cli/comments` | 3 |
| `users/aed900/gists` | `[]` | `users/octocat/gists` | 3 |
| `gists` (auth'd, **includes secret gists**) | `[]` (2 bytes) | — | — |
| `repos/…/hooks` | `[]`, **exit 0** | `repos/cli/cli/hooks` | **404 + scope hint** |

The last row is the sharpest of them. `[]` with exit 0 on antseal is an *authorized empty
answer*; the same endpoint on a repo I do not administer returns 404 with a scope hint. The
difference proves my `[]` is "no webhooks exist", not "I was silently denied".

---

## 4. Queries that FAILED, and what each failure means

Reported separately from the zeros, because a failed query is not evidence of absence.

| Endpoint | HTTP | Server message | Interpretation |
| --- | --- | --- | --- |
| `dependabot/alerts` | 403 | *"Dependabot alerts are disabled for this repository."* | **Feature off, not a scope failure.** `X-Accepted-Oauth-Scopes` for this endpoint lists `repo`, which I hold. `gh` additionally printed *"needs the admin:repo_hook scope"* — that hint is a generic heuristic naming the first scope in the accepted list, and it is **misleading here**. The header is the field that carries the claim. |
| `code-scanning/alerts` | 403 | *"Code scanning is not enabled for this repository."* | Feature off. |
| `secret-scanning/alerts` | 404 | *"Secret scanning is disabled on this repository."* | Feature off. |
| `vulnerability-alerts` | 404 | *"Vulnerability alerts are disabled."* | Feature off. |
| `repos/…/discussions` | 410 | *"Discussions are disabled for this repo"* | Feature off; matches `has_discussions:false`. |
| `repos/…/projects` | 404 | *"Not Found"* | Classic projects unavailable. |
| **`projectsV2` (GraphQL)** | — | **`INSUFFICIENT_SCOPES` — requires `read:project`** | **GENUINELY UNCOVERED.** `has_projects: true`, so a Projects v2 board may exist and I could not enumerate it. See §9.1. |
| `private-vulnerability-reporting` | 404 | *"Not Found"* | Cannot distinguish "unavailable while private" from "disabled". Unresolved. |
| `security-advisories` | 404 | *"Not Found"* | Same. Unresolved. |
| `actions/artifacts/9244072894/zip` | 410 | *"Artifact has expired"* | **Expected and useful**: it proves `expired: true` in the artifact list is a real state, not a label. |

---

## 5. Actions run logs — the main event

Workflow logs on a **public** repository are readable by anyone. This is the largest server-side
surface the flip exposes and it received the bulk of the work.

### 5.1 Coverage — full, not sampled

The brief anticipated that full coverage might be infeasible and asked for a stated sampling
rule. **It was feasible. There is no sampling rule, because there was no sample.**

| Measurement | Value |
| --- | --- |
| Workflow runs on the remote | **57** (`total_count: 57`; `gh run list` and the REST API return identical ID sets) |
| Date range | **2026-07-27T22:05:02Z → 2026-08-16T13:41:24Z** (20 days; the repo was created 2026-07-27) |
| Runs whose log archive downloaded (exit 0) | **57 / 57** |
| Runs yielding non-empty archives | **48** |
| Runs yielding a 22-byte empty archive | **9** — see §5.3 |
| Jobs registered across all runs | **715** |
| Job logs extracted and scanned | **610** (+610 per-job `system.txt` diagnostics) |
| **Log text scanned** | **91 838 443 bytes across 1 220 files — 100 % of what is retrievable** |
| Runs by branch / actor | **all 57 on `main`, all by `aed900`, `head_repository` always `aed900/antseal`** — no fork ever ran |

Runs by workflow: `ci` 37, `fuzz-nightly` 11, `ci-always` 3, `pages` 2, `advisory-cron` 2,
`verifier-page` 1, `devnet-e2e-cron` 1. Conclusions: 33 success, 24 failure, 0 in progress.
`cross-os-extended.yml` is registered but has never run.

### 5.2 Retention — measured, not assumed

The brief asked for the actual oldest retrievable log rather than an assumed 90 days. Both ends
were probed directly:

```
GET runs/30309407509/logs   (oldest, 2026-07-27)  -> HTTP 200, Content-Disposition: logs_82142152794.zip
GET runs/31950533442/logs   (newest, 2026-08-16)  -> HTTP 200, Content-Length: 22
```

Retention was then derived independently from artifact metadata, where GitHub states expiry
explicitly: `expires_at − created_at` = **89–90 days** for every ordinary artifact (the
`github-pages` artifact is the documented 1-day exception).

**Conclusion: nothing has expired.** The repository is 20 days old and the retention window is
90 days, so the oldest log's first possible expiry is **2026-10-25**. Publication today exposes
**every run this project has ever had**, with no attrition. Any decision that assumes "the old
noisy runs have aged out" is wrong today and will stay wrong until late October.

### 5.3 The nine empty archives — verified, not assumed

Nine runs returned a 22-byte (empty) ZIP. A tidy assumption would be "those jobs produced no
output"; the accounting gap (715 registered jobs, 610 logs = 105 missing) makes that worth
checking. Queried directly:

```
run 31407751482 (ci, 19 jobs):        status=completed conclusion=failure
                                      started→completed in 3 s, runner="" , steps=0   (x19)
run 31950533442 (ci-always, 2 jobs):  runner="", steps=0
run 31943600047 (verifier-page, 1):   runner="", steps=0
```

**Every one of the 105 jobs has an empty `runner_name` and zero steps.** They were never
assigned a runner and never executed a step, so no log text exists to leak. That is a
measurement of the field that carries the claim, and it independently corroborates D135's
"never assigned a runner" reading of the exhausted-minutes failures.

### 5.4 What the 91.8 MB actually contains

Full detector table over the log corpus; every zero is canary-proven (§2) and cross-checked
against an independent grep (§2.2):

| Detector | Hits | Files | Verdict |
| --- | --- | --- | --- |
| `pem_private_key` | 3 | 3 | benign — `secret-guard`'s own planted fake, see below |
| `age_secret` / `minisign_secret` / `keystore_kdfparams` / `vault_export_magic` | 3 each | 3 each | benign — same three files, same cause |
| GitHub tokens (classic + fine-grained), Actions runtime/OIDC token names, JWT, AWS, Slack, npm, crates.io, Stripe, Google, Porkbun, RPC-provider keys, `Authorization:`, basic-auth URLs, `.netrc`, `curl -u` | **0** | **0** | clean |
| generic `password:`/`api_key:`, `*PRIVATE_KEY=`, `MNEMONIC=`, `ANTSEAL_DEVNET_WALLET_PRIVATE_KEY` | **0** | **0** | clean |
| Anvil well-known keys, Anvil mnemonic, `0x`+64-hex, BIP39 12-/24-word runs | **0** | **0** | clean |
| PGP blocks, PGP messages, OpenSSH keys, SSH public keys, keystore `ciphertext` | **0** | **0** | clean |
| `maintainer-email`, **any email address** | **0** | **0** | clean |
| **`/home/deb`** | **0** | **0** | **clean — the maintainer's path is absent from every log** |
| `/home/<user>/` | 24 058 | 538 | **all `/home/runner/`**, no other value exists |
| `/Users/<name>/` | 1 220 | 32 | all `/Users/runner/` (macOS runners) |
| `C:\Users\<name>\` | 227 | 32 | all `C:\Users\runneradmin\` (Windows runners) |
| private IPv4, internal hostnames, phone numbers | **0** | **0** | clean |
| `::add-mask::`, env dumps, `/usr/bin/env` steps, `${{ secrets.* }}` | **0** | **0** | clean |
| `***` (masked value) | 1 240 | 602 | GitHub's own masking — §5.6 |
| `set -x`-shaped lines | 12 | 2 | **false positive**: `cargo fmt --check` diff output, lines beginning `+`. No shell xtrace exists anywhere. |

**The 64-hex sweep, which is where a wallet key would hide.** 1 471 occurrences resolve to only
**62 distinct values**, and their line context is unambiguous:

```
   60  bitmatch-emit: sha256 = <HEX64>
   60    [executed] testdata/vectors/v1/bundle/bundle.json — recomputed <HEX64>
   60    native transcript: N bytes, sha256 <HEX64>
   60    wasm32 transcript: N bytes, sha256 <HEX64>          … and eleven more of the same shape
```

Golden-vector digests and WASM bit-match transcripts. **Zero match any of the ten well-known
Anvil/Hardhat keys**, and the membership test was proven live in the same run by re-running it
with the Anvil set injected (`10` matches). The zero is a measurement.

### 5.5 The three key-shaped hits, in full

All three sit in the `secret-guard` job log of the three **oldest** runs — `30309407509`
(2026-07-27T22:05), `30376120625` and `30376668778` (both 2026-07-28) — and nowhere else:

```
[36;1mprintf 'fake for guard self-test\n-----BEGIN EC PRIVATE KEY-----\nAAAA\n-----END EC PRIVATE KEY-----\n' > "$tmp/fake-wallet.pem"[0m
[36;1mprintf 'AGE-SECRET-KEY-1SELFTESTSELFTESTSELFTEST\n' > "$tmp/fake-age.key"[0m
[36;1mprintf 'ANTSEAL VAULT EXPORT v0 guard-self-test\n' > "$tmp/fake-vault-export.bin"[0m
[36;1mprintf '{"version":3,"crypto":{"ciphertext":"00",…,"kdfparams":{"n":1},…}}\n' > "$tmp/fake-keystore.json"[0m
[36;1m  hits+="$(ex 'minisign encrypted secret key')"[0m
```

The `[36;1m` escapes are GitHub echoing the **body of an inline `run:` step**. This is the
brief's stated worry made concrete — and the finding is that **Q43 already fixed it**. Those
literals were 60 lines of inline shell in the workflow; moving them into
`scripts/ci-lanes.sh` means GitHub now echoes one line (`./scripts/ci-lanes.sh secret-guard`)
instead of the guard's whole body. Measured consequence: **3 runs of 48 echo the fakes; the
other 45 echo nothing.** Q43 was justified on reviewability and turned out to shrink the log
disclosure surface as well. The content is harmless in any case — the same literals are in
`scripts/ci-lanes.sh` at HEAD, so publishing them adds nothing a reader would not get from the
source.

### 5.6 The 1 240 masked values — what CI actually handles

Every `***` in 91.8 MB, classified exhaustively:

| Count | Line |
| --- | --- |
| 604 | `token: ***` |
| 538 | `[command]/usr/bin/git config --local http.https://github.com/.extraheader AUTHORIZATION: basic ***` |
| 32 | the same, `"C:\Program Files\Git\bin\git.exe"` (Windows runners) |
| 32 | the same, `/opt/homebrew/bin/git` (macOS runners) |
| 32 | `token: ***` |
| 2 | `"oidc_token": "***"` |

Every one is `actions/checkout` masking the **per-run ephemeral `GITHUB_TOKEN`**, or
`actions/deploy-pages` masking the **OIDC token**. Both are minted per run and expire when the
run ends; the newest is 20 hours old and worthless. **No project secret has ever flowed through
this CI**, because there is none to flow (§6). The brief's masking concern — a base64'd secret
escaping an exact-match mask — has no subject here, and was tested anyway (§2.3): the
`AUTHORIZATION: basic <base64>` form *is* masked, and no undecoded token survives anywhere.

---

## 6. Secrets, variables, and the workflow trigger surface

| Scope | Result | Query |
| --- | --- | --- |
| Actions secrets | **0** | `{"total_count":0,"secrets":[]}` |
| Dependabot secrets | **0** | `{"total_count":0,"secrets":[]}` |
| Codespaces secrets | **0** | `{"total_count":0,"secrets":[]}` |
| Repository variables | **0** | `{"variables":[],"total_count":0}` |
| `github-pages` environment secrets / variables | **0** / **0** | both queried explicitly |

No secret value was requested at any point — GitHub does not serve them and this lane did not
try. **No secret name exists to disclose infrastructure**, so the brief's name-disclosure
concern is empty here.

**No workflow references a secret.** `grep -nHE 'secrets\.'` across all 8 remote workflow files
returns **exit 1, zero lines**; the identical grep against a one-line planted file returns the
match. The brief's "a workflow referencing a secret that does not exist" check is therefore
vacuous in both directions: nothing is referenced and nothing exists.

### Triggers — `pull_request_target` is absent

| Trigger | Present? |
| --- | --- |
| `pull_request_target` | **NO — zero occurrences in all 8 workflows** (`grep -c` returns 0 for every file; canary grep on a planted file matches) |
| `workflow_run`, `issue_comment`, `issues`, `discussion`, `fork`, `watch` | **NO — exit 1 across the directory**, canary fires |
| `pull_request` (unfiltered) | **YES — `ci.yml`, `ci-always.yml`, `cross-os-extended.yml`** |
| `push` on `main` | `ci.yml` (path-filtered), `ci-always.yml` (deliberately unfiltered) |
| `schedule` / `workflow_dispatch` | the four cron lanes, `pages.yml`, `verifier-page.yml` |

The dangerous one is entirely absent, and that is the single most important fact in this
section. See **G-S2** for what the unfiltered `pull_request:` triggers mean once strangers can
open PRs.

Least-privilege posture, all measured:

```
repos/…/actions/permissions           {"enabled":true,"allowed_actions":"all","sha_pinning_required":false}
repos/…/actions/permissions/workflow  {"default_workflow_permissions":"read","can_approve_pull_request_reviews":false}
repos/…/actions/permissions/access    {"access_level":"none"}
```

and every one of the 8 workflows declares `permissions:` at **workflow level**, `contents: read`
— with `pages.yml` alone adding `pages: write` + `id-token: write`, which is exactly what OIDC
Pages deployment requires and no more.

---

## FINDINGS

### BLOCKER

**None from this lane.**

The worktree lane's **B1** (no LICENSE) and **B2** (stale README) stand and are unaffected by
anything measured here. B1 is independently confirmed from the GitHub side: `GET
/repos/aed900/antseal/contents/LICENSE` → **404**, and the community-profile API reports
`license: false`, `code_of_conduct: false`, `health_percentage: 42`.

### SHOULD-FIX

#### G-S1 — Issues are enabled, and a cryptographic tool is about to go public with no security-disclosure channel

Measured:

| Surface | State |
| --- | --- |
| `has_issues` | **true** |
| `SECURITY.md` | **404 — absent** |
| `.github/` contents | **`workflows/` only** — no `ISSUE_TEMPLATE`, no `PULL_REQUEST_TEMPLATE`, no `CODEOWNERS`, no `FUNDING.yml` |
| `CODE_OF_CONDUCT.md` | absent |
| Private vulnerability reporting | **404 — state not determinable while private** (§4) |
| Community health | **42 %** (`contributing: true`, `readme: true`; everything else false) |

`CONTRIBUTING.md` exists and is substantial (23 636 bytes), so the project is not indifferent
to contributors — the gap is specifically the *security* channel. The moment this repository is
public, the first person who finds a flaw in a verifier that makes cryptographic claims has
exactly one visible route: **a public issue**. For a proof-of-existence tool whose entire pitch
is that strangers should audit it, inviting the audit while providing no private path for its
results is the wrong pairing.

Cheapest sufficient fix, in order: a `SECURITY.md` naming a contact and a disclosure window;
then enabling private vulnerability reporting, which is free on public repositories and turns
"file a public issue" into a private form. Neither is executable while the repo is private, so
the `SECURITY.md` should land **in the same change as the flip**, not after.

#### G-S2 — Once public, any stranger's fork PR executes this repository's code on a runner

Three workflows carry unfiltered `pull_request:`, and `ci.yml`'s comment block explains why that
asymmetry is deliberate and correct for the CI question it was solving. It has a second
consequence that arrives with publication: on a public repository, **anyone may open a pull
request from a fork**, and `pull_request` runs the workflow definition from the base branch
against the fork's code. `ci.yml` alone then runs `cargo test`, `cargo clippy`, `cargo fmt`,
`scripts/ci-lanes.sh`, the tamper matrix and a fuzz smoke lane over a stranger's tree.

What already limits the damage, all measured rather than assumed:

- **Zero secrets exist** (§6) — there is nothing in the environment to exfiltrate.
- **`pull_request_target` is used nowhere** — the trigger that would hand a fork a
  write-capable token against the base repo is absent.
- **`default_workflow_permissions: "read"`** and `can_approve_pull_request_reviews: false`.
- **`allow_forking: true`, `forks: 0`, collaborators: `aed900` only** — nothing pre-existing.
- Public repositories get standard GitHub-hosted runners free, so this is not a billing exposure
  — which, note, also removes the exhausted-allowance constraint that D135 measured.

What remains is compute abuse: a hostile PR is arbitrary code execution in a runner, which is
what cryptominers use public CI for. GitHub's mitigation is the *"require approval for all
outside collaborators"* fork-PR setting, and **its state is not readable through the REST API
for a personal repository** — I could not verify it. Recommend the maintainer confirm it in
Settings → Actions → General at the moment of the flip; it is one radio button and it is the
difference between "a stranger's first PR runs 19 jobs" and "a stranger's first PR waits for
you".

#### G-S3 — The devnet evidence artifact redacts a funded wallet key, and nothing pins that redaction

**Nine artifacts are still live and become world-downloadable at the flip.** Eight are tiny
fuzz crash inputs. The ninth is the one that matters:

```
devnet-e2e-evidence   52 269 B   created 2026-08-12   expires 2026-11-10   run 31571938292
  ├── manifest.json      479 B
  ├── launcher.log   525 475 B      <- a real Anvil devnet + 5 saorsa nodes
  ├── local-up.log    48 290 B
  ├── evidence.txt       199 B
  └── suite-S6-S8 / S17 / S18 / S19 logs
```

This is the single highest-value target on the whole GitHub side: `scripts/devnet/local-up`
writes a **funded Anvil dev key** to `.devnet/env`, and this artifact is that run's captured
output. Scanned with all 52 detectors:

```
MODE=scan FILES=16 BYTES=626333 PATTERNS=52
      17      8f  abspath_any_home        <- all /home/runner/, nothing else fires
```

and the field itself:

```
$ grep -rhaoE 'wallet_private_key[^,}]{0,60}' <artifacts>
wallet_private_key": "<redacted>"                         # exit 0, exactly one occurrence
```

**The redaction fired.** The canary — the same grep against a planted manifest carrying an
unredacted `0x…` value — returns the full string, so the grep would have caught a failure. The
45 distinct 64-hex values in the artifact are saorsa-core DHT peer IDs and content addresses
(`DHT peer connected:`, `Created PNP node with peer ID:`, `close group lookup … for target`);
**zero** match a well-known Anvil key, with the classifier proven live.

So there is no leak. The finding is that **this is an unpinned invariant**. The evidence-capture
path redacts one JSON field, by hand, in a script; nothing tests that it still does; and the
artifact it writes has a 90-day public life and contains 525 KB of raw devnet output alongside
it. A one-line regression in that redaction publishes a funded key for three months. This
project's own standard is that an invariant with no test is not an invariant — and every other
comparable guard here (`secret-guard`, the tamper matrix, the freeze digests) is self-testing.
A tamper-style case that plants an unredacted key in the evidence directory and asserts the
uploader refuses is the shape that matches the rest of the repository.

Lower-cost complement, worth doing regardless: the eight `fuzz-smoke-artifacts` are crash inputs
whose only consumer is the maintainer, and they can simply be allowed to expire.

#### G-S4 — "Branch protection is BLOCKED BY PLAN" is stale, and nothing is protected today

`docs/ci-verification.md:1168` records, verified 2026-07-28:

> **Branch protection is BLOCKED BY PLAN** … `gh api repos/aed900/antseal/branches/main/protection`
> → `{"message":"Upgrade to GitHub Pro or make this repository public to enable this feature.",
> "status":"403"}` … `gh api repos/aed900/antseal/rulesets` → … same 403.

Re-measured 2026-08-17, on the same two endpoints:

| Endpoint | Recorded 2026-07-28 | **Measured 2026-08-17** |
| --- | --- | --- |
| `branches/main/protection` | 403 *"Upgrade to GitHub Pro…"* | **404 `{"message":"Branch not protected"}`** |
| `rulesets` | 403 *"Upgrade to GitHub Pro…"* | **200 OK, `[]`** |
| `rulesets?includes_parents=true` | — | **200 OK, `[]`** |

A **200** is an authorized, successful read. The plan gate is no longer being applied to the
rulesets endpoint, and the classic endpoint now answers "not protected" rather than "not
permitted". **What I did NOT test, and cannot**: whether a `PUT` would now succeed — creating a
ruleset is a write and writes are prohibited to this lane. So the honest statement is: *the
recorded evidence for the blocker no longer reproduces; whether the blocker itself is gone
requires one write to establish.*

This matters to the decision Q65 feeds, because the same document offers "make the repository
public" as **option 2 of three** for obtaining branch protection, and warns that it must not be
taken for a CI reason without taking Q65 first. If the platform now permits rulesets on a
private Free repository, then that argument for publishing has weakened and should not be
leaned on unexamined.

Independently of which way that resolves: **`main` has no protection and `format-v1-freeze` has
no tag protection**, `rulesets: []`, `web_commit_signoff_required: false`. The doc's own
assessment names force-push and branch-deletion protection as the thing that is genuinely
missing and *"matters more now that a published freeze tag exists"*. A public repository whose
central artifact is a **format freeze** is a strong argument for protecting the tag that
witnesses it.

### NOTE

**G-N1 — Publication exposes 20 days of CI in one step, undiminished.** 57 runs, 715 jobs,
610 readable job logs, 91.8 MB, nothing expired, first expiry 2026-10-25 (§5.2). The content is
clean; the point of the note is the *shape* of what a reader gets: 24 failure runs out of 57,
including a `devnet-e2e-cron` run whose evidence line reads
`e2e-devnet: FAIL … failed=[S6-S8,S17,S18,S19]`, and nine runs that failed in three seconds
without a runner. This is the same candour the worktree lane's N7 recommends publishing, and
the same recommendation applies — but it should be a choice, not a discovery.

**G-N2 — The only credential this CI has ever handled is GitHub's own ephemeral token.** Zero
secrets in four scopes, zero `secrets.*` references in eight workflows, 1 240 masked values all
of which are the per-run `GITHUB_TOKEN` or the Pages OIDC token, all expired. There is no
rotation to do before publishing, which is unusual and worth saying plainly.

**G-N3 — Repository metadata is thin but clean.** `description` reads
*"antseal — proof-of-existence & selective-disclosure sealing on Autonomi 2.0"* — accurate and
correctly positioned (existence and disclosure, no notary claim). `topics: []` and
`homepage: null`, the latter despite `https://antseal.org/` being live and served by this
repository's own Pages configuration (`cname: antseal.org`, `https_enforced: true`,
`protected_domain_state: verified`, certificate approved to **2026-11-12**). Setting the
homepage field and a few topics is the difference between a repository a stranger can find and
one they cannot. `has_wiki: false`, `has_discussions: false`, `has_downloads: false` — three
surfaces that cannot leak because they do not exist.

**G-N4 — Third-party actions are pinned to moving tags.** Nine distinct actions across the 8
workflows: `actions/checkout@v4` ×23, `Swatinem/rust-cache@v2` ×19,
`actions/upload-artifact@v4` ×5, `actions/cache@v4` ×5, `foundry-rs/foundry-toolchain@v1`,
`actions/upload-pages-artifact@v3`, `actions/setup-python@v5`, `actions/deploy-pages@v4`,
`actions/configure-pages@v5`. All tags, no SHAs, and `sha_pinning_required: false`. This is not
a disclosure issue and it is the normal posture; it is noted because it becomes a *supply-chain*
posture the moment the workflows are public and running against fork PRs (G-S2), and because
this project pins `ant-core = "=0.5.0"` exactly and documents why. The same reasoning applied to
actions would pin them by SHA.

**G-N5 — Going public switches on four GitHub features that are off today, and there are zero
pre-existing alerts to inherit.** Dependabot alerts, code scanning, secret scanning and
vulnerability alerts are all disabled (§4), so the "existing alert becomes relevant" risk the
brief raises is empty. What arrives instead: **secret scanning and push protection become
available free on public repositories**, **Actions minutes become unmetered on standard
runners** (removing the constraint D135 measured), and **branch protection becomes
unambiguously available** (G-S4). One consequence to expect rather than be surprised by: GitHub's
secret scanning and third-party seed-phrase scanners will flag the valid 24-word BIP39 mnemonic
in `docs/research/paper-key-transport-design-round.md` that the history lane documents as
BENIGN-3. It is the published example entropy `000102…1e1f` and carries its own disclaimer
three lines above; expect the report, and the disclaimer is the answer.

**G-N6 — Run metadata discloses nothing beyond what history already does.** All 57 runs are on
`main`, all triggered by `aed900`, all with `head_repository: aed900/antseal`. No local branch
name, no fork, no second identity ever reached the Actions surface. This corroborates the
history lane's §2 from the server side: the remote carries `main` and one tag, and the 35
unpushed local branches have left no trace on GitHub either.

**G-N7 — The one environment is correctly constrained.** `github-pages`, created
2026-08-14, with a `branch_policy` protection rule whose only allowed branch is `main`, no
environment secrets, no environment variables, `can_admins_bypass: true`. Two deployments, both
by `aed900`, both `ref: main`.

### BENIGN — confirmed, not assumed

Each of these is a real zero, evidenced in §3 and §4 rather than inferred from an empty
listing:

- **Issues: 0** (open and closed). **Pull requests: 0** (open, closed, merged, draft).
  **Releases: 0**, draft or otherwise. **Tags on the remote: 1** (`format-v1-freeze`).
- **Commit comments: 0. Issue comments: 0. PR review comments: 0.** There is no prose anywhere
  on the GitHub side except the repository description — no candid remark, no pasted URL, no
  credential, because there is no comment to hold one.
- **Webhooks: 0** — so the brief's payload-URL disclosure concern has no subject. **Deploy
  keys: 0.**
- **Gists: 0**, checked both publicly and through the authenticated endpoint that includes
  *secret* gists.
- **Forks: 0. Stargazers: 0. Subscribers: 0. Collaborators: 1** (`aed900`). **Pending
  invitations: 0.**
- **Wiki disabled. Discussions disabled. Downloads disabled. Classic projects unavailable.**
- **Actions cache entries** (`total_count: 43`, e.g. `v0-rust-clippy-Linux-x64-c996cd7a-3ea89987`,
  `fuzz-corpus-31670018990`) are key names describing lanes and platforms. They do not become
  publicly readable, and they disclose nothing beyond what the workflow files already say.

---

## 7. Corrections to the brief this lane was given

Stated in the siblings' convention, because a brief that goes uncorrected propagates.

1. **"If full coverage is infeasible, state the sampling rule."** Full coverage was feasible.
   All 57 runs, all 610 retrievable job logs, all 91 838 443 bytes were scanned. There is no
   sample and therefore no sampling rule — the only uncovered log text is the 105 jobs that
   produced none because they never started (§5.3), and that is verified, not assumed.
2. **"`verifier-page.yml` has a failure-path artifact upload."** True in the file, but that path
   has **never produced an artifact**: the workflow's single run (2026-08-16) never got a
   runner, and no `verifier-page` artifact exists. The failure-artifact path is unexercised on
   the remote, which is also what D136 §2 R13's seeded-failure input exists to exercise.
3. **"Check whether any workflow references a secret that does not exist."** Vacuous in both
   directions here: zero workflows reference any secret and zero secrets exist. Verified with a
   canaried grep rather than reported as "nothing found".
4. **"`set -x` / echoed variables are a real possibility, not theoretical."** Correct as to
   mechanism, and it did happen — but only in the **three oldest runs**, and Q43 has already
   closed it (§5.5). No shell xtrace exists in any log; the 12 apparent hits are `cargo fmt`
   diff lines.
5. **The `admin:repo_hook` scope hint `gh` prints on the Dependabot query is misleading.** The
   endpoint's own `X-Accepted-Oauth-Scopes` header lists `repo`, which I hold; the 403 is the
   feature being disabled. Reporting that as a scope failure would have been the
   verify-the-neighbouring-field error.

---

## 8. Work this scan suggests deserves a task row

Described for the registrar; **no rows were created by this lane.**

1. **A `SECURITY.md` and private vulnerability reporting, landing with the flip** (G-S1).
   Ordering matters: the file must be in the tree at the moment issues become world-writable.
2. **A tamper-style test pinning the devnet evidence redaction** (G-S3) — plant an unredacted
   `wallet_private_key` in the evidence directory and assert the uploader refuses. Highest-value
   row here, because it protects a funded key with a 90-day public life.
3. **Confirm the fork-PR approval setting at the flip** (G-S2) — not readable via REST, so it
   needs a human check and a recorded measurement, in the Q237 style that names which surface
   proved it.
4. **Re-measure D-whatever-owns-it: the branch-protection blocker** (G-S4). `rulesets` now
   returns 200. `docs/ci-verification.md:1168` should either be corrected or its 403 re-witnessed,
   and a ruleset protecting `main` and `format-v1-freeze` costed, before the flip is justified
   partly by that blocker.
5. **Pin third-party actions by SHA** (G-N4) — the same discipline `=0.5.0` already gets.
6. **Set `homepage` and topics** (G-N3) — one API call each, and the difference between findable
   and not.
7. **Let the eight `fuzz-smoke-artifacts` expire, and consider a shorter retention for
   crash-input artifacts** (G-S3, second half).

---

## 9. What this scan does NOT cover

Stated plainly, because a scrub that overstates its reach is worse than none.

1. **The working tree and git history** — the two sibling lanes' subjects. Nothing here
   re-verifies either.
2. **Projects v2.** `has_projects: true`, and the GraphQL query failed with
   `INSUFFICIENT_SCOPES` — it needs `read:project`, which this token does not hold. **A Projects
   v2 board may exist on this repository and I could not see it.** Classic projects return 404,
   which is not the same question. This is the one category where "empty" was not established.
   Resolving it needs `gh auth refresh -s read:project`, which is a change to the maintainer's
   own credential and therefore outside a read-only lane.
3. **Private vulnerability reporting and security advisories.** Both 404 while the repo is
   private; I cannot distinguish "unavailable on a private Free repo" from "disabled". Draft
   security advisories, if any exist, were not enumerable.
4. **The fork-PR approval setting** (Settings → Actions → General) is not exposed by the REST
   API for personal repositories and was not verified (G-S2).
5. **Log *content* was pattern-matched, not read.** 91.8 MB across 610 job logs is beyond
   human reading. 52 canary-proven signature detectors plus a decode-then-detect sweep and an
   exhaustive 64-hex enumeration were applied; **no entropy analysis was performed**, and a
   high-entropy secret in a shape none of the 52 patterns describes would be missed. The 64-hex
   sweep is the one exhaustive exception.
6. **Deleted runs and deleted artifacts are unrecoverable and unscannable.** 57 runs are what
   the API reports; if a run was deleted before this scan, nothing here would show it.
7. **The `github-pages` artifact (865 661 B, expired 2026-08-16) could not be inspected** — it
   410s. Its content is the built verifier page, which is already served publicly at
   `https://antseal.org/`, so nothing is hidden by that gap; it is recorded because it is a real
   hole in coverage.
8. **Nothing was verified about the deployed Pages *content*.** This lane read the Pages
   *configuration*; the worktree lane covers what the page says.
9. **No write was attempted anywhere**, so every "would a PUT succeed" question — most
   importantly G-S4's — is unresolved by construction.
10. **The maintainer's account-level surface** (other repositories, organisation memberships,
    SSH/GPG keys, personal access tokens) is out of scope. Only `aed900/antseal` was audited,
    plus read-only canary queries against `cli/cli` and `users/octocat`.
11. **Not legal advice**, and not a judgement on the licence question — B1 is the worktree
    lane's, confirmed here only as a GitHub-side fact.

---

## 10. Does anything here block going public?

**No.**

No live credential material exists in any GitHub-side artifact. All three lanes now agree: the
working tree is clean, the object store is clean, and the server-side surface — 91.8 MB of
retained Actions logs, 9 live artifacts, zero secrets, zero webhooks, zero deploy keys, zero
issues, PRs, releases, comments and gists — is clean, with every empty category backed by a
demonstrated detection and every failed query reported as a failure rather than a zero.

The flip remains blocked by the **worktree lane's B1 and B2**, which this lane does not touch
and independently confirms in B1's case.

Four things should land **with** the flip rather than after it, in this order:

1. **`SECURITY.md`** (G-S1) — must be in the tree before strangers can file issues.
2. **Confirm the fork-PR approval setting** (G-S2) — one radio button, checked at the moment of
   the change.
3. **Re-measure the branch-protection blocker and protect `main` + `format-v1-freeze`**
   (G-S4) — the freeze tag is this project's central artifact and is unprotected.
4. **A test pinning the devnet evidence redaction** (G-S3) — the only place a funded key could
   ever reach a public artifact.

None of the four is a reason to delay; all four are cheaper before the audience arrives than
after.

---

*Prepared by the GitHub-side scrub lane, 2026-08-17. Sibling reports:
`docs/reviews/pre-public-scrub-worktree.md` and `docs/reviews/pre-public-scrub-history.md`,
both untouched here. No file outside this document was created, modified, moved or deleted; no
repository setting was changed; no `gh` write subcommand of any kind was run; nothing was
pushed. Detector and canary sources live in scratch space outside the repository and are **not
committed** — they contain 55 realistic fake secrets, and committing them would poison every
future scan of this repo, including `secret-guard`'s. Note for the guard's maintainer: like both
sibling reports, this file quotes `secret-guard`'s own marker literals as evidence, so it joins
the three documents that go red if the `--exclude='*.md'` exclusion is dropped naively (history
lane §6, Gap 3).*
