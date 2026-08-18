# D143 — Pinning fifty-seven action invocations, and the renewal mechanism that is the actual decision

- **Status: RESOLVED. The lean's DIRECTION survives — all 57 invocations are
  pinned to 40-hex commit SHAs — and every one of the four premises under it
  falls.** (a) The **justification** is inverted: D71 §2 R5 applies exactly, and
  it applies *harder* than the brief suspected, because a 40-hex in a `uses:`
  line is **an identifier the same host resolves**, not bytes anyone verifies —
  so the pin buys nothing against GitHub-the-platform, which is the party that
  holds the Pages credential. Uniform pinning is nonetheless ruled, on **cost**
  rather than on threat: it is measured to forfeit almost nothing. (b) The
  **blast-radius ordering in Q244's `Do` is CORRECTED** — the dominant
  invocation is `pages.yml:77`'s `Swatinem/rust-cache@v2`, not `pages.yml:85`'s
  `actions/deploy-pages@v4`. (c) **`sha_pinning_required: true` is DEFERRED, not
  set**, and Q244's Accept row 2 is amended — a setting no committed instrument
  can see be wrong is the shape this repository's own CI comment already calls
  *"an arming nothing checks is an arming that silently disappears"*
  (`advisory-cron.yml:46`); today it could only redden a hosted run, every
  hosted run is already refused before it starts, **and armed today it would
  refuse `pages.yml` outright** through a composite action no edit here can
  reach. (d) **Dependabot is REFUSED** for now, on four measurements, and the
  renewal mechanism is an **offline, gate-enforced, dated ledger** instead.
- **The arm nobody listed, and it is the one that decides §2 R5: the
  repository's supply chain does not close at its own 57 lines.**
  `actions/upload-pages-artifact@v3` — `pages.yml:81`, inside the only job in
  the repository with write scope — is a **composite** action whose own
  `action.yml:77` reads `uses: actions/upload-artifact@v4`. A **bare moving
  tag, one level down, in the highest-privilege job**, which no edit to this
  repository's workflows can pin. GitHub fixed this in its own v5.0.0, whose
  `action.yml:84` reads `uses: actions/upload-artifact@bbbca2ddaa5d8feaa63e36b76fdaad77386f024f # v7.0.0`
  — GitHub adopting the exact form the lean proposes, in the exact action this
  repository has not upgraded in **923 days**. And it is not a curiosity: the
  SHA-pinning policy **traverses composite actions** (established from GitHub's
  own runtime output and public run data, never from GitHub's prose — §1.6), so
  this one line makes the lean's final step, `sha_pinning_required: true`, an
  act that would **refuse `pages.yml`** if taken in the order the lean gives.
- **The measurement that reverses the "pin and forget is worse than a moving
  tag" argument: six of the nine major tags are not moving.** Measured
  2026-08-18: `configure-pages@v5` last moved **871 days** ago,
  `deploy-pages@v4` **886**, `upload-pages-artifact@v3` **923**,
  `upload-artifact@v4` **517**, `setup-python@v5` **481**, `cache@v4` **328**.
  Only three move on a scale that makes freezing them a real forfeit
  (`rust-cache@v2` 12 days, `foundry-toolchain@v1` 29, `checkout@v4` 33). The
  moving-tag regime has been delivering `pages.yml` a **2024-vintage** toolchain
  for two and a half years while GitHub shipped two newer majors of each. There
  is no "fixes flow in automatically" property here to lose.
- **Date: 2026-08-18**
- **Owning task: Q244**, whose `Do` ordering is REPLACED, whose Accept row 2 is
  AMENDED, and whose `Spec:` citation is shown to be wrong — the full list is
  §2 R10. Two follow-on rows are described in §2 R6 and §2 R9 **without ids;
  the orchestrator assigns them.**
- Related: **D71 §2 R5 / §A R6** (one trust root, one account, one CA path — the
  argument this record inherits and then sharpens), **D138 §2 R7 / §3** (the
  checker doctrine and the `ci-always.yml traceability` venue that adds zero
  required contexts), **D19/P13** (`advisory-cron.yml`, the existing weekly
  renewal instrument and the reason a scheduled hosted lane cannot be this
  ruling's venue), **D52** (`foundry-rs/foundry-toolchain@v1`'s admission, at
  `devnet-e2e-cron.yml:100-104`, on the same footing as `rust-cache`), **D62**
  (the canonical URL `pages.yml` deploys to), **D135** (the exhausted
  allowance), **Q65** (the flip — a precondition of half the rulings here),
  **Q31** (the release workflow, which does not exist and whose actions are not
  yet in the ledger), **Q253** (the latent required-context red — this record
  adds **zero** contexts, deliberately).

---

## 1. The measurement

Every figure below was re-taken on **2026-08-18** against the tree at `de71a09`
and against the live API, not carried from the brief. Where the brief and the
measurement agree the row says CONFIRMED; where they do not it says CORRECTED
and gives the command.

### 1.1 The inventory, re-counted

```
$ grep -rcE "^\s*(- )?uses:" .github/workflows/ | awk -F: '{s+=$2} END {print s}'
57
$ grep -rhno "uses:[[:space:]]*[^[:space:]]*" .github/workflows/ \
    | sed 's/.*uses:[[:space:]]*//' | sort | uniq -c | sort -rn
```

| action | invocations | brief | verdict |
|---|---:|---:|---|
| `actions/checkout@v4` | 23 | 23 | CONFIRMED |
| `Swatinem/rust-cache@v2` | 19 | 19 | CONFIRMED |
| `actions/upload-artifact@v4` | 5 | 5 | CONFIRMED |
| `actions/cache@v4` | 5 | 5 | CONFIRMED |
| `actions/setup-python@v5` | 1 | 1 | CONFIRMED |
| `actions/configure-pages@v5` | 1 | 1 | CONFIRMED |
| `actions/upload-pages-artifact@v3` | 1 | 1 | CONFIRMED |
| `actions/deploy-pages@v4` | 1 | 1 | CONFIRMED |
| `foundry-rs/foundry-toolchain@v1` | 1 | 1 | CONFIRMED |
| **total** | **57** | **57** | **CONFIRMED** |

Nine distinct actions, 57 invocations, **zero** 40-hex references — CONFIRMED.
Three additional properties the brief did not state, each of which matters to
the checker in §2 R8:

1. **No `uses:` line is commented out** (`grep -rn "uses:" | grep -E ":[0-9]+:\s*#"` → empty),
   so a naive line grep and a YAML parse give the same 57 today. They will not
   necessarily agree tomorrow, which is why §2 R8's rule P5 records per-action
   counts rather than a single total.
2. **There are no local or composite actions in this repository**
   (`.github/actions/` does not exist), so all 57 are remote and all 57 are in
   scope. There are no reusable-workflow `uses:` either.
3. **`Swatinem/rust-cache` appears 22 times in the workflow files and only 19
   of those are invocations** — three are prose (`verifier-page.yml:98`,
   `devnet-e2e-cron.yml:91`, `devnet-e2e-cron.yml:102`). A checker that greps
   the action name rather than the `uses:` key inherits a count that is 16 %
   wrong. This is the first place a plausible implementation goes wrong and the
   self-test must contain it.

**Line numbers in this record are volatile and the ledger is deliberately not
keyed on them.** The inventory above was taken twice — once at `de71a09` and
again after a concurrent lane rewrote `devnet-e2e-cron.yml` mid-wave (+76/-7
lines). The **counts and the file:line pairs this record cites were unchanged**
by that edit, but `actions/upload-artifact@v4` moved from `:147` to `:216`
inside it. That is the ordinary condition here, and it is why
`.github/action-pins.tsv` (§2 R4) keys on the **action** and not on a location,
and why §2 R8's rules quote file:line only in failure messages.

**One brief/task figure is CORRECTED, and it is a citation rather than a count.**
`tasks/Q.md` Q244's `Spec:` line reads *"Risks — supply chain (MVP-SPEC.md line
189)"*. `grep -in "supply.chain" MVP-SPEC.md` returns **zero hits** — the spec's
`## Risks & mitigations` block (lines 177-189) has no supply-chain entry at all,
and line 189 is *"**Free-TSA terms/rate limits** → defaults chosen with recorded
caveats…"*. The companion citation is right: **`Milestones M4` IS line 157**
(`## Parking lot` is line 159; M2/M3/M4 are 155/156/157). So Q244 is anchored to
a spec risk that does not exist, and this record's subject is **unrepresented in
`MVP-SPEC.md`**. Recorded here rather than fixed — the spec is not this lane's
write scope, and §5 carries it.

### 1.2 What an action can actually reach here, measured

```
$ grep -rn "secrets\." .github/workflows/
(no output)
```

**Not one workflow references a single secret.** All eight arm
`permissions:` at workflow level, and seven of the eight are `contents: read`
and nothing else. Exactly one job in the repository has write scope:

| file | permissions | line |
|---|---|---|
| `advisory-cron.yml` | `contents: read` | `:32-33` |
| `ci-always.yml` | `contents: read` | `:56-57` |
| `ci.yml` | `contents: read` | `:130-131` |
| `cross-os-extended.yml` | `contents: read` | `:73-74` |
| `devnet-e2e-cron.yml` | `contents: read` | `:57-58` |
| `fuzz-nightly.yml` | `contents: read` | `:52-53` |
| `verifier-page.yml` | `contents: read` | `:64-65` |
| **`pages.yml`** | **`contents: read` + `pages: write` + `id-token: write`** | **`:44-47`** |

So the whole of the repository's write exposure to a compromised action is
`pages.yml`'s single `publish` job, plus whatever the Actions **cache** carries
between jobs (§5.1). The repository-level defaults confirm it:
`default_workflow_permissions: read`, `can_approve_pull_request_reviews: false`,
`actions/permissions/access: {"access_level":"none"}` — all three CONFIRMED
verbatim by `gh api` on 2026-08-18.

### 1.3 The blast-radius ordering is CORRECTED

Q244's `Do` says *"Two invocations dominate the blast radius: `pages.yml:85`'s
`deploy-pages@v4` … and `rust-cache@v2`"*, and orders the work *"`deploy-pages`
and the release workflow's actions first, `rust-cache` next"*. The file:line is
right — `pages.yml:85` is `uses: actions/deploy-pages@v4`, CONFIRMED — but **the
ordering is backwards**, on four measurements:

1. **`actions/deploy-pages@v4` is GitHub's own action, deploying to GitHub's own
   Pages service, under GitHub's own credential, from GitHub's own runner.**
   This is D71 §2 R5's *"one trust root, one account, one CA path"* in its
   purest form: every party that would have to be compromised for the action to
   be malicious already controls the thing it deploys to. Pinning it removes
   exactly one adversary — someone with write access to `actions/deploy-pages`
   who is not GitHub — and that adversary cannot reach `antseal.org` any other
   way only because they would not need to.
2. **`Swatinem/rust-cache@v2` runs in that same job, at `pages.yml:77`, eight
   lines earlier**, and it is *not* GitHub's. `action.yml:70-73` at the current
   `v2` commit reads `using: "node24"` / `main: "dist/restore.js"` /
   `post: "dist/save.js"`; `dist/` at that commit is **six committed files
   totalling 9 644 375 B of bundled, minified JavaScript**
   (`cache-DC26rUaF.js` alone is 6 569 292 B). That is arbitrary Node running
   with the job's full environment, in the only job that has one worth having.
3. **The job's token is on disk before `rust-cache` starts.** `pages.yml:72` is
   `actions/checkout@v4` with **no `with:` block at all** — no invocation of
   `checkout` anywhere in the eight files sets `persist-credentials`
   (`grep -rn "persist-credentials" .github/workflows/` → empty), and the
   default is `true`, read off the action's own manifest at the SHA this record
   pins:

   ```
   $ gh api repos/actions/checkout/contents/action.yml?ref=11d5960a326750d5838078e36cf38b85af677262 \
       --jq .content | base64 -d | sed -n '52,54p'
     persist-credentials:
       description: 'Whether to configure the token or SSH key with the local git config'
       default: true
   ```

   So `$GITHUB_WORKSPACE/.git/config` carries the job token as an
   `http.…extraheader` before line 77 executes, and in this job that token
   carries `pages: write`.
4. **`id-token: write` is a job-wide grant, not a step-scoped one.** Every step
   in `publish`, including `:77`, has `ACTIONS_ID_TOKEN_REQUEST_URL` and
   `ACTIONS_ID_TOKEN_REQUEST_TOKEN` in its environment.

**Ruled ordering, replacing Q244's:** `pages.yml` in full first (it is five
invocations and it is the whole write exposure), then the 19 `rust-cache` sites
and `devnet-e2e-cron.yml:108`'s `foundry-toolchain` (the two non-`actions/`
owners), then the remaining `actions/*` in bulk. Q31's release workflow keeps
its place at the head of the queue **when it exists**; today
`grep -rn '\-\-release' .github/workflows/` returns zero hits, so ordering work
behind it would order it behind nothing.

### 1.4 What a SHA pin is, against whom — D71 §2 R5 applied, and sharpened

D71 §2 R5 refused the README and the page as *security* pins of the minisign
key because they are *"same GitHub account, same Pages/asset CA chain"*, and §A
R6 said the sentence this record borrows: **"Readable and independent are
different properties."** The brief asks whether that reasoning makes pinning
`actions/*` theatre. It does not — but it decomposes the question in a way the
uniform lean cannot express. Three adversaries, not one:

| adversary | what they control | does a 40-hex pin defend? |
|---|---|---|
| **A1 — GitHub the platform** | the runner, the Actions service that resolves `@<sha>` into a download, the repository, Pages, the token mint, the OIDC issuer | **NO.** And it is worse than "no": the pin is *an identifier A1 resolves*, so A1 is on both sides of the check. |
| **A2 — write access to `actions/*` that is not A1** | the ability to re-point `refs/tags/v4` | **YES**, for any re-point after the pin is taken. |
| **A3 — write access to `Swatinem/rust-cache` or `foundry-rs/foundry-toolchain`** | same, on a repository with no GitHub-internal controls | **YES**, and this is the population where the class has actually fired (`tj-actions/changed-files`, `reviewdog/action-setup`, March 2025). |

**A1 is the party that holds `pages: write`.** Every threat that reaches
`antseal.org` through `pages.yml` and is *not* stopped by a pin is stopped by
nothing else this repository can do either. That is D71 §2 R5's conclusion
transplanted intact, and it is why §2 R1 declines to justify pinning as a
security claim for the seven `actions/*` entries.

**A2 is real and is not the same as A1.** A compromised maintainer account
inside the `actions` organisation is a narrower event than a GitHub platform
compromise, and it is the event `actions/checkout@v4` — a tag GitHub itself
re-points on every v4.x release — is exposed to. The pin closes it. So
"theatre" is the wrong word; "not the mitigation" is the right one.

**A3 is the mitigation.** Two invocations, 20 call sites, and both already
recognised in the tree as an accepted edge:
`devnet-e2e-cron.yml:100-104` says *"Third-party action edge accepted on the
same footing as `Swatinem/rust-cache@v2` and pinned to a major tag."* This
record is what turns *"pinned to a major tag"* into an actual pin.

**What the pin is NOT — and this was read off upstream source, not assumed.**
A 40-hex in a `uses:` line is **not a checksum anything verifies.** Read end to
end in `actions/runner` **v2.336.0** (`98aabcd`, confirmed byte-identical to
`main` for this file), `src/Runner.Worker/ActionManager.cs`:

- The runner sends only `{NameWithOwner, Ref, Path}` to a closed-source Actions
  service endpoint (`:1037-1042`, `:1068`; `LaunchHttpClient.cs:35`) and gets
  back a **server-supplied** `ActionDownloadInfo` carrying `ResolvedSha`,
  `TarballUrl` and `ZipballUrl` (`ActionDownloadInfo.cs:9-31`). There is no git
  fetch in the action path at all.
- It downloads whatever URL came back with a plain `httpClient.GetAsync`
  (`:1644-1760`) and extracts it with `tar -xzf` / `ZipFile.ExtractToDirectory`
  (`:1321`, `:1352`). **No digest, no checksum, no signature.**
- `ResolvedSha` **is never compared to anything.** Every non-test use is a log
  line, a telemetry string, or a cache *path* component (`:1207`, `:1212`,
  `:1241`, `:1266`, `:1283-1285`, `:1315`).
- The omission is a choice, not a missing capability: the runner **does**
  hash-verify its own self-update package —
  `SelfUpdater.cs:381-405`, *"Computed runner hash … did not match expected
  Runner Hash"*. There is no analogue for actions.
- **Immutable actions do not change this.** `ManifestDigest` is printed
  (`:1206`) and discarded; the immutable branch (`:1202-1214`) is output calls
  only and falls through to the same unverified download.
- And it could not be otherwise from what is delivered: a git **commit** SHA
  covers the tree hash *plus* parents, author, committer and message, none of
  which appear in a source archive. The commit SHA is not recomputable from the
  tarball; in the tarball it appears only as an unauthenticated self-assertion
  in the pax header and the directory prefix, and the runner reads neither.

GitHub's own *Secure use reference* justifies pinning like this: *"Pinning to a
particular SHA helps mitigate the risk of a bad actor adding a backdoor to the
action's repository, as they would need to generate a SHA-1 collision for a
valid Git object payload."* **That argument binds only a party that actually
checks the hash — and per the source above, the only such party is GitHub's own
service.** So the sentence is true against A2 and A3 and vacuous against A1.

The pin's whole force is therefore that **the request is specific**: a
maintainer can no longer re-point a tag under you. It has no force at all
against a party that can answer the request dishonestly. Recorded because the
opposite belief — that pinning makes CI's inputs *verified* — is the belief that
would license skipping everything else, and because a comment asserting it would
be false in a file this record is about to touch 57 times.

*(Not established, and not inferred: what the closed-source Launch service does
internally to map a SHA to bytes. The finding above is strictly about the
runner, which delegates entirely and re-checks nothing.)*

### 1.5 The moving tag is not moving

This is the measurement that decides the renewal half, and it points the
opposite way from the brief's *"a stale pinned SHA misses security fixes — so
'pin and forget' may be strictly worse than a moving major tag"*. That argument
requires the major tag to move. Measured 2026-08-18 by
`gh api repos/<owner>/<action>/commits/<tag>`:

| action | major tag now points at | dated | **age** | latest release | majors behind |
|---|---|---|---:|---|---:|
| `Swatinem/rust-cache@v2` | `6323deb…` = v2.9.2 | 2026-08-06 | **12 d** | v2.9.2 | 0 |
| `foundry-rs/foundry-toolchain@v1` | `908c540…` = v1.9.1 | 2026-07-20 | **29 d** | v1.9.1 | 0 |
| `actions/checkout@v4` | `11d5960…` = v4.4.0 | 2026-07-16 | **33 d** | v7.0.1 | 3 |
| `actions/cache@v4` | `0057852…` = v4.3.0 | 2025-09-24 | **328 d** | v6.1.0 | 2 |
| `actions/setup-python@v5` | `a26af69…` = v5.6.0 | 2025-04-24 | **481 d** | v7.0.0 | 2 |
| `actions/upload-artifact@v4` | `ea165f8…` = v4.6.2 | 2025-03-19 | **517 d** | v7.0.1 | 3 |
| `actions/configure-pages@v5` | `983d773…` = v5.0.0 | 2024-03-30 | **871 d** | v6.0.0 | 1 |
| `actions/deploy-pages@v4` | `d6db901…` = v4.0.5 | 2024-03-15 | **886 d** | v5.0.0 | 1 |
| `actions/upload-pages-artifact@v3` | `56afc60…` = v3.0.1 | 2024-02-07 | **923 d** | v5.0.0 | 2 |

Read the bottom three rows again. **`pages.yml` — the only job with write scope
— is running a Pages action set that has received no commit on its referenced
major in two and a half years**, while GitHub cut fresh majors of all three on
2026-03-25 / 2026-04-10. The moving tag has not been keeping this repository
current; it has been keeping it *at 2024* while making that fact invisible,
which is precisely the failure mode a pin is accused of.

Two honest counter-notes, so the table is not read past its limit:

- **`checkout@v4` genuinely is maintained.** The commit `v4` points at is
  *"backport fixes to releases-v4 (#2524)"* — GitHub is actively backporting to
  the v4 line. Freezing it is a real, if small, forfeit, and §2 R8's rule P6
  exists to pay it back on a schedule rather than never.
- **`rust-cache@v2` is the freshest of the nine and the one most worth
  freezing.** Its 12-day age is the argument *for* pinning, not against: an
  action that changes every few weeks, from a single-owner repository, running
  in the write-scope job, is the definition of an input you want to change only
  when you decide it changes.

### 1.6 The supply chain does not close at 57 lines

```
$ gh api repos/actions/upload-pages-artifact/contents/action.yml?ref=56afc609e74202658d3ffba0e8f6dda462b719fa \
    --jq .content | base64 -d | grep -nE "^\s*using:|^\s*(- )?uses:"
22:  using: composite
77:      uses: actions/upload-artifact@v4
```

`actions/upload-pages-artifact@v3` is a **composite** action, and its own body
calls `actions/upload-artifact@v4` by bare tag. So even after all 57
invocations in this repository carry 40-hex SHAs, **`pages.yml`'s publish job
still resolves one mutable tag at run time**, one level below anything a
workflow edit can reach — in the job that has `pages: write` and `id-token:
write`. This is the only one of the nine with a nested `uses:`; the other eight
are `node20`/`node24` JavaScript actions with no sub-action (measured for all
nine at their pinned SHAs).

The same query against the current v5 shows what the fix looks like and who
already took it:

```
$ gh api repos/actions/upload-pages-artifact/contents/action.yml?ref=fc324d3547104276b827a68afc52ff2a11cc49c9 \
    --jq .content | base64 -d | grep -nE "^\s*using:|^\s*(- )?uses:"
26:  using: composite
84:      uses: actions/upload-artifact@bbbca2ddaa5d8feaa63e36b76fdaad77386f024f # v7.0.0
```

**GitHub SHA-pinned its own nested reference, with a trailing semver comment, in
the exact action this repository is 923 days behind on.** That is the strongest
available evidence that the form §2 R3 rules is the right one, and it is also
the reason §2 R6 keeps the v3→v5 upgrade *out* of the pinning act rather than
folding it in: a two-major jump in the Pages action set can only be verified by
dispatching `pages.yml`, which costs metered minutes the account does not have
and publishes to a live domain.

**And the transitive tag is not a theoretical hole — it is what would break
`pages.yml` the moment `sha_pinning_required` is armed.** The policy traverses
the whole dependency tree. GitHub has **never said so in prose** — a search of
the `github/docs` source for *"nested actions"*, *"transitive"* and *"dependency
tree"* under `content/actions` returns **zero hits**, and the changelog says
only *"any workflow that attempts to use an action that isn't pinned will
fail"* — but GitHub's own runtime says so, repeatedly and in public. The error
template, quoted from four independent public repositories:

```
The action <owner>/<action>@<tag> is not allowed in <owner>/<repo> because all
actions must be pinned to a full-length commit SHA.
```

with observed instances naming `actions/checkout@v6`, `actions/cache@v4`,
`actions/cache@v5`, `actions/setup-python@v6`, `actions/setup-java@v3` and
`actions/create-github-app-token@v3` — **so `actions/*` are refused exactly like
anyone else's**, which GitHub *does* document (§2 R5 reason 3). In at least one
verified case (`NDDev-it-com/ci-workflows` run `31782942981`) every failing ref
came from *inside* a SHA-pinned third-party composite action, not from the
caller's own workflow.

**The failure shape matters more than the message, and it is a trap for whoever
takes the §2 R9 row.** A run refused by the SHA-pinning policy is dispatched to
a runner and fails inside **`Set up job`** — **one** step, `conclusion: failure`,
2–7 s. A run refused by an exhausted allowance has **zero** steps and takes 4–9 s
(§1.9). **The two refusals differ by exactly one step and are otherwise
identical to the eye.** Anyone confirming "the policy did not break anything"
by glancing at a duration or a conclusion will confirm the wrong thing. Read
`.jobs[].steps | length` — `0` is the allowance, `1` is the policy, `>1` is a
real run.

*Evidence tier, stated because it is not uniform:* the `actions/*`-are-not-exempt
sentence and the local-action exemption are **GitHub documentation**; the
transitive-traversal behaviour and the error strings are **GitHub's product
output quoted in public issues, plus run data I re-queried through the REST
API** — not GitHub prose. There is no GitHub-authored statement that the policy
traverses composite actions. It demonstrably does.

### 1.7 The annotated-tag trap, and why "40 hex" is an assertion that cannot fail

The obvious way to resolve a pin is `gh api repos/<o>/<r>/git/ref/tags/<tag>`.
For eight of the nine that returns a commit. For the ninth it does not:

```
$ gh api repos/Swatinem/rust-cache/git/ref/tags/v2 --jq '{type:.object.type, sha:.object.sha}'
{"sha":"49a0bdc70d2e1b713ca9e2869b211fcce03d3c1c","type":"tag"}
$ gh api repos/Swatinem/rust-cache/git/tags/49a0bdc70d2e1b713ca9e2869b211fcce03d3c1c \
    --jq '{tag:.tag, points_to:.object.type, commit:.object.sha}'
{"commit":"6323deb102c322ba6fcbdcafc7e3dddab59af2b6","points_to":"commit","tag":"v2"}
```

`Swatinem/rust-cache@v2` is an **annotated tag**, so the naive call yields
`49a0bdc7…` — the **tag object**, not the commit `6323deb1…`. Forty lowercase
hex characters, perfectly well-formed, and wrong. **The one action where the
obvious resolution method produces a wrong-but-well-shaped answer is the
genuinely third-party one that runs 19 times, including in the write-scope
job.** A checker whose rule is `^[0-9a-f]{40}$` is green on it. That is this
project's dominant defect class arriving inside the fix for a different one,
and it is why §2 R8 makes the ledger — not the regex — the authority, and why
`49a0bdc70d2e1b713ca9e2869b211fcce03d3c1c` is a **mandatory planted fault**.

Every SHA in §2 R3's table was therefore resolved by `repos/<o>/<r>/commits/<tag>`,
which peels annotated tags, and cross-checked against `git/ref/tags/…` for the
eight lightweight ones. Both outputs are recorded there.

### 1.8 The repository settings, re-read verbatim

All GET, all on 2026-08-18, all reproduced exactly as returned:

```
$ gh api repos/aed900/antseal/actions/permissions
{"enabled":true,"allowed_actions":"all","sha_pinning_required":false}
$ gh api repos/aed900/antseal/actions/permissions/workflow
{"default_workflow_permissions":"read","can_approve_pull_request_reviews":false}
$ gh api repos/aed900/antseal/actions/permissions/access
{"access_level":"none"}
$ gh api repos/aed900/antseal/actions/permissions/selected-actions
{"message":"Conflict","errors":"All actions and workflows are allowed on this repository",…,"status":"409"}
$ gh api repos/aed900/antseal/actions/permissions/fork-pr-contributor-approval
{"message":"Validation Failed","errors":"Fork PR approval is not allowed for private repositories.",…,"status":"422"}
$ gh api repos/aed900/antseal/rulesets
[]
$ gh api repos/aed900/antseal/branches/main/protection
{"message":"Branch not protected",…,"status":"404"}
$ gh api repos/aed900/antseal --jq '{private,visibility,default_branch}'
{"default_branch":"main","private":true,"visibility":"private"}
```

Every figure Q244 and the brief state about repository settings is **CONFIRMED
verbatim**, including the 422 on fork-PR approval and the empty rulesets. Two
additions:

- The **409** on `selected-actions` is new here and is worth having: it proves
  `allowed_actions` is genuinely `"all"` rather than `"selected"` with an empty
  list, which would read the same at the parent endpoint but behave differently.
- `sha_pinning_required` **is readable** on a private repository on a personal
  account — the field is present and `false`. So Q244's Accept row 2 asking for
  *"verified by API read-back rather than by having set it"* is satisfiable in
  principle. Whether the **PUT** is accepted on Free + private is **NOT
  MEASURED and deliberately not measured**: writing it is an external action.
  `docs/ci-verification.md:245-249` records the neighbouring precedent —
  branch protection is *"unavailable on a private repository on GitHub Free
  (403, verified on both the classic API and rulesets)"* — so a 403 on this PUT
  is a live possibility and §2 R5 does not assume otherwise.

### 1.9 The renewal venue: what can actually run

**Nothing hosted can.** The last twelve workflow runs, every one:

```
$ gh api "repos/aed900/antseal/actions/runs?per_page=12" \
    --jq '.workflow_runs[] | {name,conclusion,run_started_at,updated_at}'
```

returns `"conclusion":"failure"` for all twelve, spanning 2026-08-16 → 2026-08-18,
with `updated_at - run_started_at` between **4 and 9 seconds**. The most recent,
run **32096766647** (`ci`, `de71a09`, 2026-08-18T03:47:50Z → 03:47:56Z, **6 s**):

```
$ gh api repos/aed900/antseal/actions/runs/32096766647/jobs \
    --jq '{total:.total_count, steps:[.jobs[].steps|length]|unique, conclusions:[.jobs[].conclusion]|unique}'
{"total":15,"steps":[0],"conclusions":["failure"]}
```

**Fifteen jobs, every one `failure`, every one with `steps: 0`.** Not one step
was created, so not one line of any workflow — pinned or not — was evaluated.
This is the refusal signature, measured on this record's own base commit, and it
governs three separate rulings below:

1. A **scheduled hosted lane cannot be the renewal mechanism.**
   `advisory-cron.yml` is the tree's existing weekly-renewal instrument (D19/P13,
   `cron: "17 6 * * 1"`) and it has been refused every week since the allowance
   went. Putting pin-freshness on it would be putting it somewhere it cannot run.
2. A **Dependabot PR would arrive with fifteen red contexts that say nothing**,
   onto a branch that `rulesets → []` and `branches/main/protection → 404`
   confirm nothing protects.
3. `sha_pinning_required: true` **could not be falsified today**: its only
   observable is a workflow run failing at start-up, and every workflow run
   already fails at start-up for an unrelated reason. Setting it now would be
   setting a control whose green and whose red are indistinguishable.

The corollary is the venue ruling: **the renewal mechanism must be offline and
must live in `scripts/local-gate.sh`**, which is the only witness this project
has had since wave 20, and which is explicitly *"no cargo, no network, no git"*
for exactly this class of checker (`scripts/local-gate.sh:433`).

### 1.10 What the tree already pins, for contrast

Every other dependency axis in this repository is exactly pinned, and each has a
committed instrument:

| axis | pin | where |
|---|---|---|
| Rust crates | `ant-core = "=0.5.0"` and the workspace lock | project rule 2 |
| `cargo-deny` | `--version 0.19.8 --locked` | `ci.yml:729`, `advisory-cron.yml:69` |
| `cargo-fuzz` | `--version 0.13.2 --locked` | `ci.yml:683`, `fuzz-nightly.yml:99` |
| `wasm-bindgen-cli` | version literal, grep-asserted across `.github/workflows scripts docs` | `scripts/wasm-toolchain-audit.sh:161-163` |
| Python `cbor2` | `pip install --require-hashes -r requirements-crosscheck.txt`, **every PyPI artifact hashed** | `ci.yml:502`, `requirements-crosscheck.txt` |
| **GitHub Actions** | **nothing** | — |

The repository requires a hash for a decode-only Python dev tool and accepts a
moving pointer for the code that runs as step one of every job. That asymmetry,
not a threat model, is the cheapest correct statement of why this row exists.

---

## 2. The ruling

### §2 R1 — All 57 are pinned. The split is real, but it decides the *reason*, not the *scope*.

Every `uses:` in `.github/workflows/` names a 40-hex commit SHA. The split the
brief asks for is ruled and recorded — **`Swatinem/rust-cache` and
`foundry-rs/foundry-toolchain` are the mitigation; the seven `actions/*` are
not** (§1.4) — but it is recorded **in the ledger's `tier` column, as data**,
and not as two different treatments of two different sets of lines.

Three reasons, in order of weight:

1. **The forfeit is measured and it is near zero.** §1.5: six of nine major tags
   have not moved in 328–923 days. Refusing to pin them buys a stream of updates
   that does not exist.
2. **A heterogeneous rule cannot be checked simply, and this project's checkers
   are its only witness.** "Pin the third-party ones" is a rule whose subject
   set changes every time an action is added, by a judgement no script can make.
   "Every `uses:` is a 40-hex that equals the ledger" is a rule with no
   judgement in it at all.
3. **A2 is not A1** (§1.4). Pinning `actions/*` closes a narrow but genuine
   adversary. It is not theatre; it is simply not the reason to do the work.
4. **The third-party-only split is not implementable under the policy anyway.**
   GitHub's own documentation of `sha_pinning_required` says the requirement
   *"includes actions from your organization and actions authored by GitHub"*,
   and five independently observed refusals name `actions/*` refs (§2 R5 reason
   3). So a repository that pinned only `Swatinem/rust-cache` and
   `foundry-rs/foundry-toolchain` could never arm the setting. Uniformity is not
   merely the tidier rule; it is the only one with a destination.

**What this record refuses to claim, and the implementer must not write into a
comment:** that pinning makes CI's inputs verified, or that it defends
`antseal.org` against GitHub. It does neither (§1.4, last paragraph).

### §2 R2 — The order of work

`pages.yml` (5 invocations) → the 19 `rust-cache` sites and
`devnet-e2e-cron.yml:108` → the remaining 32 `actions/*` in bulk. This
**replaces** Q244's `Do` ordering; see §1.3. Q31's release workflow is not in
this ruling's scope because it does not exist (`grep -rn -- "--release"
.github/workflows/` → **0**, re-measured 2026-08-18); §2 R8's rule P4 makes
adding it impossible without adding its actions to the ledger in the same act.

### §2 R3 — The exact pins, and how they were resolved

**Resolved 2026-08-18T10:06:52Z** by, for each action:

```
gh api repos/<owner>/<action>/commits/<tag> --jq '{sha, committed:.commit.committer.date}'
gh api repos/<owner>/<action>/tags?per_page=100 --jq '.[] | select(.commit.sha=="<sha>") | .name'
```

The first peels annotated tags (§1.7); the second names the semver the commit
also carries, which becomes the trailing comment. `git/ref/tags/<tag>` was run
as a cross-check and its divergence for `rust-cache` is recorded in the last
column.

| # | action | **pin (commit SHA)** | comment | tier | `git/ref/tags` cross-check |
|---|---|---|---|---|---|
| 1 | `actions/checkout` | `11d5960a326750d5838078e36cf38b85af677262` | `# v4.4.0` | github-owned | same (lightweight) |
| 2 | `Swatinem/rust-cache` | `6323deb102c322ba6fcbdcafc7e3dddab59af2b6` | `# v2.9.2` | **third-party** | **DIFFERS — returns tag object `49a0bdc70d2e1b713ca9e2869b211fcce03d3c1c`** |
| 3 | `actions/upload-artifact` | `ea165f8d65b6e75b540449e92b4886f43607fa02` | `# v4.6.2` | github-owned | same |
| 4 | `actions/cache` | `0057852bfaa89a56745cba8c7296529d2fc39830` | `# v4.3.0` | github-owned | same |
| 5 | `actions/setup-python` | `a26af69be951a213d495a4c3e4e4022e16d87065` | `# v5.6.0` | github-owned | same |
| 6 | `actions/configure-pages` | `983d7736d9b0ae728b81ab479565c72886d7745b` | `# v5.0.0` | github-owned | same |
| 7 | `actions/upload-pages-artifact` | `56afc609e74202658d3ffba0e8f6dda462b719fa` | `# v3.0.1` | github-owned | same |
| 8 | `actions/deploy-pages` | `d6db90164ac5ed86f2b6aed7e0febac5b3c0c03e` | `# v4.0.5` | github-owned | same |
| 9 | `foundry-rs/foundry-toolchain` | `908c540300062bd5a7e473851cdb4282204cee09` | `# v1.9.1` | **third-party** | same |

**The comment is the exact semver (`# v4.4.0`), not the major (`# v4`).** Three
reasons: `# v4` re-encodes in a comment the mutable pointer the pin exists to
remove; the renewal act in §2 R7 needs to know which release it is diffing
against; and it is the form GitHub itself uses in the one place it pins
(`upload-pages-artifact@v5`'s `action.yml:84` → `# v7.0.0`, §1.6). Q244's `Do`
says *"the version in a trailing comment"* and does not specify granularity, so
this is a refinement, not a divergence.

**The edit, exactly.** Each of the 57 lines becomes
`uses: <owner>/<action>@<40-hex> # v<x.y.z>`, preserving existing indentation,
the `- ` list marker where present, and any `id:`/`name:` sibling keys. `with:`
blocks are untouched — including `foundry-rs/foundry-toolchain`'s
`version: stable` (`devnet-e2e-cron.yml:109-110`), `rust-cache`'s
`workspaces: fuzz` (`ci.yml:673-674`, `fuzz-nightly.yml:89-90`) and
`setup-python`'s `python-version: '3.12'` (`ci.yml:499-500`). **No `with:` key,
no `if:`, no `env:`, no step name, and no job changes.** Behaviour is
byte-identical because each SHA is the commit its tag pointed at when the table
was taken, which is what makes the equivalence checkable.

**The prose the pins falsify.** `devnet-e2e-cron.yml:102-104` currently reads
*"Third-party action edge accepted on the same footing as `Swatinem/rust-cache@v2`
and **pinned to a major tag**"*. That sentence stops being true in the same
commit and must be updated in it — this project has already been bitten by a
front-door claim that was true for 103 minutes (D140). Same for
`verifier-page.yml:98`'s `Swatinem/rust-cache@v2` reference, which is a version
mention in prose and may keep its major form provided it is not read as a pin.

### §2 R4 — The ledger: `.github/action-pins.tsv`

Nine data rows, one per distinct action, tab-separated, ASCII, `\n`-terminated,
with `#`-prefixed header lines. It is the **authority**; the workflows are
checked against it, never the reverse.

```
# antseal — GitHub Actions pin ledger. Authority for scripts/check-action-pins.py.
# Decision: docs/decisions/D143-third-party-action-pinning-and-renewal.md
# OWNER: the maintainer (aed900). CADENCE: 90 days. See D143 §2 R7.
# Re-resolve with:  gh api repos/<owner>/<action>/commits/<tag>   (peels annotated tags — D143 §1.7)
# action	sha	version	tier	invocations	resolved_utc	next_review_utc
actions/checkout	11d5960a326750d5838078e36cf38b85af677262	v4.4.0	github-owned	23	2026-08-18	2026-11-16
Swatinem/rust-cache	6323deb102c322ba6fcbdcafc7e3dddab59af2b6	v2.9.2	third-party	19	2026-08-18	2026-11-16
actions/upload-artifact	ea165f8d65b6e75b540449e92b4886f43607fa02	v4.6.2	github-owned	5	2026-08-18	2026-11-16
actions/cache	0057852bfaa89a56745cba8c7296529d2fc39830	v4.3.0	github-owned	5	2026-08-18	2026-11-16
actions/setup-python	a26af69be951a213d495a4c3e4e4022e16d87065	v5.6.0	github-owned	1	2026-08-18	2026-11-16
actions/configure-pages	983d7736d9b0ae728b81ab479565c72886d7745b	v5.0.0	github-owned	1	2026-08-18	2026-11-16
actions/upload-pages-artifact	56afc609e74202658d3ffba0e8f6dda462b719fa	v3.0.1	github-owned	1	2026-08-18	2026-11-16
actions/deploy-pages	d6db90164ac5ed86f2b6aed7e0febac5b3c0c03e	v4.0.5	github-owned	1	2026-08-18	2026-11-16
foundry-rs/foundry-toolchain	908c540300062bd5a7e473851cdb4282204cee09	v1.9.1	third-party	1	2026-08-18	2026-11-16
# RESIDUAL — transitive references this repository cannot pin, D143 §1.6.
# residual	actions/upload-pages-artifact	v3.0.1	actions/upload-artifact@v4	action.yml:77
```

`next_review_utc` is `resolved_utc + 90` (2026-08-18 → **2026-11-16**), one
cadence for all nine so there is one date to remember; the per-action truth
about *how fast* each moves lives in §1.5, not in nine different deadlines.

**The `invocations` column is not decoration.** It is this project's answer to
its own recurring defect — *header counts go stale silently; recount by script,
never increment* — applied to the one inventory Q244 exists to hold. Rule P5
makes the file wrong the moment a step is added or removed, so the counts in
Q244's row and in §1.1 stay true by construction rather than by a wave-24
re-measurement.

**The `residual` line is not a comment.** Rule P7 parses it. It is the committed
form of §1.6: the hole is named, in the tree, where the checker can see it stop
matching reality.

### §2 R5 — `sha_pinning_required: true` is DEFERRED, and Q244's Accept row 2 is AMENDED

The setting is **not** taken in the pinning act. Q244's Accept row 2 —
*"`sha_pinning_required` is `true` at the repository, verified by API read-back"*
— is amended to: *"the committed checker is green, and `sha_pinning_required` is
set at the flip, after the row in §2 R6 lands and after one green hosted run
exists, verified by API read-back."* Four measurements, in decreasing weight:

1. **It is the weaker of the two available instruments, by this repository's own
   doctrine.** A repository setting is invisible in the tree: no diff shows it
   changing, no reviewer sees it, and nothing in the gate can tell you it was
   turned off. `advisory-cron.yml:46` already states the rule this record
   applies — *"an arming nothing checks is an arming that silently
   disappears"* — and D138 §3 makes the same argument about a `paths-ignore`.
   `scripts/check-action-pins.py` (§2 R8) is a committed instrument with a
   planted-fault self-test; the setting is a claim. They are not substitutes,
   and the checker is the one that must exist.
2. **Today it could not be falsified.** Its only observable is a workflow run
   refusing to start. Every workflow run already refuses to start — 15 jobs,
   `steps: 0`, 6 s, run 32096766647 (§1.9). Turning it on now and observing
   "nothing broke" would be an assertion that cannot fail, taken deliberately.
3. **It would break `pages.yml` today, and that is established rather than
   feared.** GitHub's documentation of the policy
   (`github/docs`, `data/reusables/actions/actions-use-policy-settings.md`,
   fetched 2026-08-18) says: *"When you enable **Require actions to be pinned to
   a full-length commit SHA**, all actions must be pinned to a full-length
   commit SHA to be used. This includes actions from your organization and
   **actions authored by GitHub**. Reusable workflows can still be referenced by
   tag."* — so there is **no `actions/*` exemption**, and the widely repeated
   third-party claim that GitHub-owned actions are exempt is false. Docs are
   silent on sub-actions; **GitHub's runtime is not** (§1.6): the policy
   traverses the dependency tree, and `actions/upload-pages-artifact@v3.0.1`
   carries a bare `uses: actions/upload-artifact@v4` at its own
   `action.yml:77`. Arming the policy before §2 R6 lands would refuse
   `pages.yml` at `Set up job` — **a refusal indistinguishable at a glance from
   the one every run already gets** (§1.6, last paragraph). The only documented
   exemption is **local** actions (`./.github/actions/…`), added after a
   regression and recorded in the GHES 3.19.9 / 3.20.5 / 3.21.3 release notes;
   this repository has none (§1.1), so it does not apply. Reusable workflows may
   still be referenced by tag, but their *contents* are policed; this repository
   has none of those either.
4. **Settability on this plan is UNMEASURED, and the brief's premise about why
   is CORRECTED.** The GET returns the field on this private, personal-account,
   Free-plan repository (`sha_pinning_required: false`, §1.8), so read-back is
   available. The PUT was **not attempted** — an external action outside this
   lane's authority. What the search establishes: `github/docs` gates the
   feature as `fpt: '*'` (Free/Pro/Team on github.com) in
   `data/features/actions-blocklist-sha-pinning.yml`, there is **no**
   `gated-features` reusable for it, and the OpenAPI schema carries no
   restriction. **The public-repos-only restriction that exists is on a
   different field** — `patterns_allowed` under
   `.../actions/permissions/selected-actions`, whose docs note reads *"The
   patterns_allowed setting only applies to public repositories"* — and it does
   not textually extend to `sha_pinning_required`, which lives on the parent
   endpoint and is orthogonal to `allowed_actions`. So a 403 is **less** likely
   than the branch-protection precedent at `docs/ci-verification.md:245-249`
   suggested. Two gaps remain and the §2 R9 row must close both: **every**
   repository found carrying `sha_pinning_required: true` is public, and even a
   successful PUT would not prove the policy is *enforced* on an FPT private
   repo — the `patterns_allowed` note proves GitHub does scope parts of this
   policy family by visibility. **Read it back AND prove it with a deliberately
   tag-pinned action; a successful write is not evidence of enforcement.**

**What is NOT deferred:** the pins, the ledger and the checker all land now.
Losing the setting costs nothing that the checker does not already provide,
except enforcement against a workflow file that never reaches the gate — and
the gate is the only thing that reaches this repository at all today.

### §2 R6 — The Pages action set is NOT upgraded in this act. It gets its own row, after Q65.

`pages.yml` is pinned at its **current** majors (`configure-pages@v5.0.0`,
`upload-pages-artifact@v3.0.1`, `deploy-pages@v4.0.5`), even though all three
are one or two majors behind and 871/923/886 days stale (§1.5), and even though
the middle one carries the transitive tag §1.6 measured.

**It is nonetheless a HARD BLOCKER for §2 R9's setting, not a nice-to-have.**
§1.6 establishes that the SHA-pinning policy traverses composite actions, so
`upload-pages-artifact@v3.0.1`'s internal `actions/upload-artifact@v4` would
refuse `pages.yml` the moment the policy is armed — no matter what this
repository writes in its own 57 lines. The row below is therefore ordered
*between* the pins and the setting, and neither end of that ordering is
optional.

**Why the upgrade is refused *here*, in the pinning act, and not merely deferred
by taste:**

- A v3→v5 / v5→v6 / v4→v5 jump across the Pages set is a **behaviour change**,
  and Q244's own Accept says *"No workflow's behaviour changes"*. Folding it
  into the pinning commit would make that acceptance unmeetable and would put a
  breaking-change risk inside the one commit whose whole value is that it
  cannot break anything.
- The **only** way to verify it is to dispatch `pages.yml`, which (i) costs
  metered minutes on an exhausted allowance, (ii) is refused today anyway
  (§1.9), and (iii) **publishes to the live canonical URL** — `pages.yml:10-11`
  says a deploy *"should happen when a maintainer decides it happens"*.
- `pages.yml:25-32` makes this job the **reproducibility gate** (R86, D135 §3
  R1) with a load-bearing step order. A Pages-action major bump is exactly the
  kind of change that can move `upload-pages-artifact`'s tar/permissions
  handling under a build the gate byte-compares.

**A new row, fully described; the orchestrator assigns the id.**

- **Title:** *The Pages action set is two years and up to two majors stale, and
  the middle one carries a transitive moving tag into the only write-scope job*
- **Milestone:** M4 · **Size:** S
- **Deps:** after **Q65** (free minutes make a verifying dispatch affordable and
  a red dispatch cheap to repeat), after **Q244** (the pins and the ledger must
  exist first, so the upgrade is a ledger edit with a diff), before the
  `sha_pinning_required` row (§2 R9)
- **Do:** raise `actions/configure-pages` v5.0.0→v6.0.0,
  `actions/upload-pages-artifact` v3.0.1→v5.0.0 and `actions/deploy-pages`
  v4.0.5→v5.0.0, each pinned to the resolved commit with a `# vX.Y.Z` comment
  and each row updated in `.github/action-pins.tsv`. Read the three actions'
  release notes for input renames before editing. Delete the `residual` line
  once `upload-pages-artifact@v5`'s own `uses:` is confirmed SHA-pinned at the
  commit being adopted (it is at `fc324d3…`, `action.yml:84`) — do not delete it
  on the strength of this record.
- **Accept:** one `workflow_dispatch` of `pages.yml` completes green; the
  reproducibility gate at `pages-publish.sh --build` passes; the deployed page's
  hash is recorded; `check-action-pins.py` is green including P7; the run id and
  the verdict line are written into the row's Notes, not just into a transcript.
- **Notes:** the residual named in §1.6 is the reason this is a security row and
  not tidying. Until it lands, `pages.yml`'s publish job resolves
  `actions/upload-artifact@v4` at run time no matter what this repository pins.

### §2 R7 — The renewal mechanism: an offline ledger with a dated deadline the local gate enforces

**Owner: the maintainer (aed900), named in the ledger header.**
**Cadence: 90 days.** Next review **2026-11-16**.

This is not *"we will update them when we notice"* — Q244's Accept explicitly
refuses that — because the deadline is **enforced by a check that goes red**,
in the only venue that runs (§1.9). It is also not a bot (§2 R9).

**The review act, in full**, so the cadence is executable rather than aspirational:

```
# 1. Re-resolve all nine. Peels annotated tags; prints ledger-shaped rows.
while IFS=$'\t' read -r action sha ver tier n res rev; do
  case "$action" in \#*|'') continue;; esac
  cur=$(gh api "repos/$action/commits/${ver%%.*}" --jq .sha)     # e.g. v4 from v4.4.0
  tag=$(gh api "repos/$action/tags?per_page=100" --jq ".[]|select(.commit.sha==\"$cur\")|.name" | grep -v '^v[0-9]*$')
  printf '%s\t%s -> %s\t%s -> %s\n' "$action" "$sha" "$cur" "$ver" "$tag"
done < .github/action-pins.tsv
# 2. For each row that moved, read the diff between the two commits before adopting it.
# 3. Rewrite the workflow lines and the ledger row together; bump resolved_utc and next_review_utc.
# 4. Run scripts/check-action-pins.py --self-test && scripts/check-action-pins.py.
```

**Why a deadline and not a subscription.** A pin that nobody revisits is the
hazard the brief names, and the only mechanisms that answer it are (a) a bot
that watches upstream, refused in §2 R9 on measurements, and (b) a date that
makes the gate red. (b) is offline, needs no plan, no minutes, no branch
protection and no network, and it fails in the loud direction. Its cost is that
it will one day redden a gate on a day nobody planned for; §2 R8's warn tier
gives 14 days' notice, and the remedy above is minutes of work.

**The honest limitation, recorded rather than glossed:** the checker cannot
verify offline that a ledger SHA is still what the tag points at. A maintainer
who bumps `next_review_utc` without doing the resolution passes every rule. The
mitigation is that the review is a **diff**, not an edit: `resolved_utc` and
`next_review_utc` move together and both appear in `git log -p`, so a skipped
review is visible in the history even though no check can catch it. This is the
same shape as D71 §2 R5's DNSSEC note — a limit stated, not a limit denied.

### §2 R8 — `scripts/check-action-pins.py`: seven rules, nine planted faults, one green control, and a self-test that touches no tracked file

**Venue.** Two steps of `ci-always.yml`'s existing **`traceability`** job — the
unfiltered workflow (D138 §2 R7), inserted after the `check-ci-paths.py` pair at
`:154-156` — and two lanes of `scripts/local-gate.sh` beside
`ci-paths-selftest`/`ci-paths` at `:454-455`. **ZERO new required-status
contexts; the set stays at 19.** This is not thrift: **Q253 is a latent
required-context red and no required context may be added while hosted CI
refuses every job.** Python stdlib only, no network, no git, no cargo — so it
also satisfies that job's `cargo-free.sh --arm` property (D124/Q182)
unconditionally.

**Shape — and this part is a ruling, not an implementation note.** `check()` is
a **pure function of text**:

```python
def check(workflows: dict[str, str], ledger: str, today: date) -> Failures: ...
```

It takes the workflow file *contents* and the ledger *content* and a date; it
opens nothing. `main()` reads the files and calls it; `--self-test` plants each
fault by **string substitution on an in-memory copy** and calls it again.
**Nothing in the self-test writes to the working tree.**

This is not a new pattern — it is **`scripts/check-anchor-net.py`'s**, which
already separates `read_tree()` (`:446-463`) from a pure
`check(workflow_texts, …)` (`:466`) and plants its faults into `dict(workflow_texts)`
(`:513`). Copy that file's skeleton rather than `check-ci-paths.py`'s.
`check-ci-paths.py` genuinely cannot do it — it scans readers across the whole
repository — so its `--self-test` mutates and reverts four tracked files in
place (`:931-944`), which is a live hazard on a tree several lanes are writing
at once (§5.3). A pin checker has no such excuse, and taking the excuse anyway
would be importing a defect on purpose when the better pattern is two files
away.

**The rules, each with the fault to plant and the message that must appear.**
Every arm matches on the **rule tag of the returned failure**, in-process, per
`scripts/lib/red-arm.sh` — *"a red arm must match on the message the check
prints when it finds the planted fault, not on the exit status alone"* — so a
crash propagates and fails the harness instead of satisfying an arm.

| rule | asserts | planted fault | required in the message |
|---|---|---|---|
| **P1** | every `uses:` ref matches `^[0-9a-f]{40}$` | rewrite `pages.yml:85` to `actions/deploy-pages@v4` | `[P1]`, `pages.yml:85`, `deploy-pages`, the literal `v4` |
| **P2** | the 40-hex **equals the ledger's `sha`** for that action | rewrite `pages.yml:77`'s pin to **`49a0bdc70d2e1b713ca9e2869b211fcce03d3c1c`** — the annotated **tag object** of `rust-cache@v2` (§1.7) | `[P2]`, both SHAs, and the word `ledger` |
| **P3** | the trailing comment is `# v<semver>` and equals the ledger's `version` | change one `# v2.9.2` to `# v2.9.1` | `[P3]`, `v2.9.1`, `v2.9.2` |
| **P4a** | every action used has a ledger row | delete the `foundry-rs/foundry-toolchain` row | `[P4a]`, `foundry-rs/foundry-toolchain` |
| **P4b** | every ledger row is used by ≥1 workflow | add a row for `actions/stale` | `[P4b]`, `actions/stale`, the word `unused` |
| **P5** | per-action `invocations` equals the count in the workflows | delete one `- uses: Swatinem/rust-cache@…` line | `[P5]`, `Swatinem/rust-cache`, `19`, `18` |
| **P6-red** | `today > next_review_utc` for any row | set one row's `next_review_utc` to `today - 1` | `[P6]`, the action, the date, and the re-resolution command |
| **P6-warn** | inside 14 days, print and **exit 0** | set one row's `next_review_utc` to `today + 7` | the warning text **and** `Failures` empty — a *green* arm that must still print |
| **P7** | each `residual` line's parent action is still at the recorded version | bump the ledger's `upload-pages-artifact` version to `v5.0.0` without touching the residual line | `[P7]`, `upload-pages-artifact`, `v3.0.1`, `v5.0.0` |
| **control** | unmodified tree is green | none | `Failures` empty |

**Why P2 is the rule that matters and P1 alone is a check that cannot fail.**
`^[0-9a-f]{40}$` is satisfied by `49a0bdc7…`, which is a real object in the real
repository, is exactly forty lowercase hex characters, and **is not the commit**.
Any implementer — or bot, or model — who resolves pins with the obvious
`git/ref/tags/` call writes that value, and a shape-only checker certifies it.
P1 without P2 is this project's dominant defect class wearing the uniform of the
fix. **P2's arm is mandatory and its planted value is fixed by this record**;
it may not be replaced with a synthetic `deadbeef…`, which would exercise a
different, easier fault.

**Where the tags come from.** Rules are tagged `P*` and not `R*` to keep them
distinguishable from this record's own R-numbers in a failure message, following
the same instinct that gave `check-ci-paths.py` `R4a`/`R4b`/`R4c` rather than
prose.

**Cost.** Nine data rows, eight files, ~1 700 lines of YAML: the check is a
handful of regex passes over 93 622 B and should run in tens of milliseconds. The
self-test runs `check()` ten times over in-memory strings. Both together
should be well inside `check-ci-paths.py`'s measured 8.6 s pair and are expected
to be closer to `fuzz-budget`'s scale. **Measure it and record the figure in the
row rather than repeating this estimate** — an unmeasured performance claim in a
comment is how `check-ci-paths.py`'s 4.0 s regex cost survived (`local-gate.sh:445-449`).

### §2 R9 — Dependabot is REFUSED today, on four measurements, and adopted later on two named preconditions

`.github/dependabot.yml` does not exist and is not created by this act
(`ls .github/` → `workflows` only). The lean's *"adopt Dependabot for renewal"*
is refused, and not on taste:

1. **Its PRs would arrive with fifteen red contexts that say nothing about the
   change.** A `pull_request` triggers `ci` (15 jobs) and `ci-always`; both are
   refused in 4–9 s with `steps: 0` (§1.9). The bot would manufacture a steady
   supply of PRs whose CI verdict is structurally meaningless.
2. **Nothing would stop them being merged.** `rulesets` → `[]`,
   `branches/main/protection` → 404 *"Branch not protected"*. There is no
   required check, no review requirement, nothing.
3. **(1) and (2) together are worse than no bot.** A recurring stream of
   red-but-meaningless PRs onto an unprotected branch trains the maintainer to
   merge past red. That is precisely the habit this project's entire gate
   doctrine — self-tests, planted faults, `red-arm.sh` — exists to prevent, and
   it would be introduced by the mechanism meant to reduce risk.
4. **The feature is currently off.** `dependabot/alerts` returns **403**
   *"Dependabot alerts are disabled for this repository"*
   (`docs/reviews/pre-public-scrub-github-side.md:222`). Adopting the bot means
   enabling a disabled feature in the same window as the visibility flip, which
   is the one window where surprises are most expensive.

**A second new row, fully described; the orchestrator assigns the id.**

- **Title:** *Post-flip GitHub-side hardening: `sha_pinning_required`, branch
  protection over the 19 contexts, and Dependabot for the action pins*
- **Milestone:** M4 · **Size:** S
- **Deps:** after **Q65** (the flip: free minutes for public repositories make
  hosted runs produce verdicts again, and branch protection stops being
  plan-blocked per `docs/ci-verification.md:245-249`), after **Q244** (pins +
  ledger + checker), after the §2 R6 row (so the transitive tag is gone before
  the policy is armed), after **Q242** (`SECURITY.md` / private vulnerability
  reporting, which lands with the flip)
- **Do:** in this order, each verified before the next — (i) confirm at least
  one hosted run produces steps and a verdict; (ii) protect `main` requiring the
  19 contexts; (iii) `PUT actions/permissions` with
  `sha_pinning_required: true`, then GET it back — **and treat the read-back as
  proof of the write only, never of enforcement** (§2 R5 reason 4); (iv) prove
  enforcement: on a throwaway branch revert exactly one `uses:` to its tag,
  push, confirm the run fails inside `Set up job` with *"is not allowed in
  aed900/antseal because all actions must be pinned to a full-length commit
  SHA"*, quote it verbatim, delete the branch — **if the run instead succeeds,
  the setting is not enforced on this repository and every claim resting on it
  is void**; (v) dispatch `pages.yml` and confirm it still starts, reading
  `.jobs[].steps | length` rather than the duration (§1.6); (vi) add
  `.github/dependabot.yml` with
  `package-ecosystem: "github-actions"`, `directory: "/"`,
  `interval: "monthly"`, and a single `groups:` entry so the nine arrive as one
  PR rather than nine; (vii) confirm the bot's first PR rewrites both the SHA and
  the `# vX.Y.Z` comment, and that `check-action-pins.py` **reds** on it until
  `.github/action-pins.tsv` is updated in the same PR — if it does not red, the
  ledger has become decorative and the bot must be reverted.
- **Accept:** each of (i)–(vii) recorded with the API response or run id quoted
  verbatim **in the row**, not in a transcript; `sha_pinning_required` read back
  as `true`; one green `pages` dispatch after the setting; the first Dependabot
  PR's effect on the checker recorded either way.
- **Notes:** steps (iv) and (vii) are the acceptances that matter — (iv)
  because a setting that is written but not enforced is the purest form of this
  project's dominant defect, and (vii) because Dependabot does not know
  about `.github/action-pins.tsv`; if the checker stays green when the bot moves
  a pin, then §2 R8's P2 is not doing its job and the ledger is theatre. The row
  is written so that discovering this reverts the bot rather than the ledger.

**Until that row lands, the cadence in §2 R7 is the whole renewal mechanism**,
and it is sufficient: 90 days, one owner, one command, enforced by a red gate.

### §2 R10 — What changes in Q244

| Q244 element | change |
|---|---|
| `Do` — blast-radius ordering | **REPLACED** by §2 R2 (`pages.yml` first; `deploy-pages` is not the dominant invocation — §1.3) |
| `Do` — *"the version in a trailing comment"* | **REFINED** to the exact semver, `# v4.4.0` not `# v4` (§2 R3) |
| `Do` — *"Set `sha_pinning_required: true` once the pins land"* | **DEFERRED** to the §2 R9 row (§2 R5) |
| Accept 1 — grep-shaped lane, planted-fault proven | **KEPT and SPECIFIED** (§2 R8: seven rules, nine planted faults, one green control); note the lane is *not* grep-shaped alone — P1 without P2 is the check that cannot fail (§1.7) |
| Accept 2 — `sha_pinning_required` true, read back | **AMENDED** per §2 R5 |
| Accept 3 — renewal mechanism with owner and cadence | **SATISFIED** by §2 R7: maintainer (aed900), 90 days, enforced by rule P6 |
| Accept 4 — no behaviour change, equivalence checkable | **KEPT**; §2 R3's table is the record, and §2 R6 keeps the behaviour-changing upgrade out of the act |
| `Spec:` line | **WRONG** — there is no supply-chain risk in `MVP-SPEC.md` (§1.1, §5.4) |
| Deps *"after Q1, Q65, Q31"* | **Q31 is not a real dependency**: it does not exist (`--release` → 0 hits) and §2 R8's P4 forces its actions into the ledger whenever it is written. Pinning need not wait for it. |

---

## 3. What this record refuses

1. **Pinning only the two genuinely third-party actions.** It is the correct
   *threat* answer (§1.4) and the wrong *rule*: its subject set is a judgement
   no script can make, and this project's checkers are its only witness. The
   split is preserved as the ledger's `tier` column instead — data, not
   behaviour.
2. **Justifying the `actions/*` pins as a security control.** Refused as a
   claim, kept as an act. A comment saying *"pinned to defend the deploy"* on
   `pages.yml:85` would be false in the way D71 §2 R5 names.
3. **`sha_pinning_required: true` today** (§2 R5) — and today it would not
   merely be unfalsifiable, it would be **wrong**: it would refuse `pages.yml`
   through a composite action this repository cannot pin (§1.6). Also refused:
   taking it and reporting the read-back as evidence. A successful PUT proves
   the write landed, not that the policy is enforced, and on this plan and
   visibility enforcement is itself unestablished (§2 R5 reason 4).
4. **Upgrading the Pages action set inside the pinning act** (§2 R6). It is a
   behaviour change verifiable only by a live deploy on an exhausted allowance.
5. **Dependabot today** (§2 R9), and **Renovate at any point on the current
   argument.** Renovate is strictly worse on the axis this record cares about:
   it is a third-party GitHub App requiring write access to the repository, so
   adopting it to reduce third-party supply-chain exposure would add a
   third-party with more privilege than any action in the table.
6. **A new job or a new required-status context for the checker.** It rides as
   two steps of `ci-always.yml`'s `traceability`. **Q253 is a latent
   required-context red and the hosted allowance is exhausted**; adding a
   context now would be adding a red that no run can clear.
7. **A grep-only checker.** `^[0-9a-f]{40}$` alone is green on
   `49a0bdc70d2e1b713ca9e2869b211fcce03d3c1c` (§1.7). Q244's Accept says
   *"a grep-shaped lane"*; this record delivers more than that on purpose and
   says why.
8. **`# v4`-style major-only comments** (§2 R3). They re-encode the pointer the
   pin exists to remove.
9. **A self-test that mutates tracked files.** `check-ci-paths.py` has to;
   a pin checker does not, and taking the excuse anyway would import a known
   hazard on a tree several lanes write at once (§5.3).
10. **A "warn-only" first phase.** A checker that cannot go red is this
    project's dominant defect class by definition. P6's warn tier exists only
    *inside* a rule whose other tier is red, and it has its own planted arm.

---

## 4. Falsifiers

Each of these would overturn a specific ruling. They are written so someone can
take them, not as rhetoric.

1. **§2 R5 reason 3 falls** if, after the pins land, `sha_pinning_required` is
   set and `pages.yml` starts normally with `upload-pages-artifact@v3.0.1` still
   in place. The transitive-traversal behaviour is established from **other
   people's repositories** — GitHub's product output and run data, never
   GitHub's prose (§1.6) — so it is exactly the kind of claim that should be
   re-taken here rather than inherited. It is **confirmed** if the run fails at
   `Set up job` naming `actions/upload-artifact@v4`. **Read
   `.jobs[].steps | length`, not the duration**: `0` is the allowance refusal,
   `1` is the policy refusal, and the two look alike (§1.6). This is the
   cheapest experiment in this record and it becomes available the moment
   hosted runs work again.
2. **§1.5's "the forfeit is near zero" falls** for any action whose frozen major
   is later shown to have shipped a security fix during a freeze window. The
   ledger's `resolved_utc` makes the window exact, so the test is mechanical:
   at each review, diff the two commits and look for a security note.
3. **§2 R8's P2 is broken** if a Dependabot PR (§2 R9 step vi) moves a pin and
   `check-action-pins.py` stays green. The ledger would then be decorative. The
   row is written so this reverts the bot, not the ledger.
4. **§2 R7's cadence is theatre** if a review is ever recorded by bumping
   `next_review_utc` alone. No check can catch it; `git log -p` over
   `.github/action-pins.tsv` can. If a review appears in the history with
   `resolved_utc` moving and no `sha` changing across all nine rows on a date
   when §1.5's fast movers should have moved, that is the signature.
5. **§1.7's planted fault stops exercising its class** if `Swatinem/rust-cache`
   re-cuts `v2` as a lightweight tag. `49a0bdc7…` would remain a valid P2 fault
   (a 40-hex that is not the ledger's) but would no longer be an *annotated tag
   object*. Re-base it on whichever action is annotated at that time, and if
   none is, say so in the self-test rather than deleting the arm.
6. **§1.4's A1 row changes** if `actions/runner` ever compares `ResolvedSha`
   against the delivered content. Today it does not (`ActionManager.cs`, v2.336.0,
   `grep -rnE 'ResolvedSha\s*(==|!=|\.Equals|StartsWith)'` → zero hits). If that
   changes, a SHA pin becomes a genuine integrity control and §2 R1's reason (3)
   strengthens from "narrow but genuine" to "the mitigation".
7. **§2 R8's P5 counting method is wrong** if a line-based
   `grep -rcE "^\s*(- )?uses:"` and a YAML parse of the eight files ever
   disagree. They agree today at 57 (§1.1). A block scalar or a quoted `uses:`
   inside a `run:` heredoc would break it, and the fix is to parse rather than
   to widen the regex.
8. **§1.3's ordering falls** if `pages.yml` ever stops being the only job with
   write scope, or if a secret is ever added (`grep -rn "secrets\." ` → empty
   today). Both are one line of YAML away and neither is guarded — which is
   itself worth a rule, and is deliberately **not** added here (§5.2).

---

## 5. Defects found that are not this decision's subject

### 5.1 The three "pinned" tool binaries are pinned by a cache key, not by a digest

Three lanes install a version-pinned cargo tool and cache the **binary**:

| lane | cache step | key | install step |
|---|---|---|---|
| `ci.yml` `fuzz-smoke` | `:677` `actions/cache@v4`, `path: ~/.cargo/bin/cargo-fuzz` | `cargo-fuzz-0.13.2-${{ runner.os }}` | `:683`, `if: steps.fuzz-cache.outputs.cache-hit != 'true'` |
| `ci.yml` `audit-deny` | `:723`, `path: ~/.cargo/bin/cargo-deny` | `cargo-deny-0.19.8-${{ runner.os }}` | `:729`, same guard |
| `advisory-cron.yml` | `:63`, `path: ~/.cargo/bin/cargo-deny` | `cargo-deny-0.19.8-${{ runner.os }}` | `:69`, same guard |

**On a cache hit the pinned `cargo install` never runs, and the executed bytes
are whatever sits under that key.** Nothing hashes them. So
`docs/dependency-policy.md §5`'s version pin is enforced by a *cache key* — an
unauthenticated string — for the tool whose entire job is to be the repository's
advisory authority. Pinning the actions does not touch this at all. The cheap
fixes are (a) record the binary's sha256 and assert it after restore, or (b)
drop the cache and pay the install. Worth a row; not this one.

The same observation generalises: **the Actions cache is a cross-job channel the
permissions table in §1.2 does not describe.** Nineteen `rust-cache` sites and
five `actions/cache` sites write into a store later jobs read, so "only
`pages.yml` has write scope" describes the *token* graph and not the *data*
graph.

### 5.2 Nothing guards the permissions blocks or the absence of secrets

`scripts/ci-lanes.sh anchor-net-policy` requires `ANTSEAL_NO_REAL_ANCHOR_NETWORK`
in **every** workflow file, and reds on a new one that lacks it. There is no
equivalent for the two properties §1.3's whole argument rests on: that only
`pages.yml` has write scope, and that `grep -rn "secrets\."` is empty. Both are
one line of YAML from being false, in a repository about to go public and gain
contributors. The rule would be four lines in the same checker §2 R8 specifies —
and it is **deliberately not added here**, because widening a checker's subject
in the act that introduces it is how a checker acquires rules nobody planted a
fault for. It is a row of its own.

### 5.3 `check-ci-paths.py --self-test` writes to four tracked files

`scripts/check-ci-paths.py:931-944` plants each fault by
`target.write_text(original.replace(old, new, 1))` and reverts in a `finally`.
The targets include `.github/workflows/ci.yml`, `scripts/ci-lanes.sh`,
`docs/ci-verification.md` and `scripts/wasm-toolchain-audit.sh`. On a working
tree that several lanes write concurrently — the normal condition here — that is
a race, and an interrupted process leaves a mutated tracked file that looks like
someone's edit.

**It is the outlier, not the idiom.** The tree has three self-test shapes:
`check-traceability.py` stages a full tree copy (safe but expensive, which is
why it is banned mid-wave), `check-anchor-net.py` reads once into dicts and
plants faults in memory (`:446-463`, `:466`, `:513` — safe and free), and
`check-ci-paths.py` writes to the tree. Retrofitting the third to the second's
shape is a contained change: it needs `check()` to take texts instead of a
`root`, which is exactly the refactor `check-anchor-net.py` already models. A
row of its own.

### 5.4 Q244 cites a spec risk that does not exist

`tasks/Q.md` Q244 `Spec:` reads *"Risks — supply chain (MVP-SPEC.md line 189)"*.
`grep -in "supply.chain" MVP-SPEC.md` → **zero hits**; line 189 is the Free-TSA
entry. `MVP-SPEC.md`'s `## Risks & mitigations` (lines 177-189) has eleven
entries and none of them is supply chain — a gap in the spec rather than a
typo, since the spec's own M4 line does mandate signed binaries and a documented
distribution channel. Either add the risk or re-point the citation; `MVP-SPEC.md`
is not this lane's write scope, and per ground truth a spec/code divergence is
flagged, not silently reconciled.

### 5.5 `pages.yml:72`'s checkout leaves the `pages: write` token on disk for the whole job

Not a pinning defect, but it was measured on the way to §1.3 and it is a larger
reduction in the dominant blast radius than any pin in §2 R3.
`persist-credentials: false` on that one step removes the job token from
`$GITHUB_WORKSPACE/.git/config` before the third-party action at `:77` runs.
Nothing in `pages.yml` performs a git operation after checkout — the only `run:`
steps are `rustup show`, `pages-publish.sh --build` and `pages-publish.sh
--verify`. It is nonetheless a **behaviour change** to the job that is also the
reproducibility gate, so it is verifiable only by a dispatch and belongs with
the §2 R6 row rather than with the pins. Recorded here so it is not lost.

### 5.6 The ledger's scope is actions, not the tools actions install

`devnet-e2e-cron.yml:110` is `version: stable` for `foundry-toolchain` — a
moving toolchain reference, deliberately chosen and already reasoned at
`:104-107` (D52 residual risk 5; the mitigation is that `scripts/e2e-devnet.sh`
prints the actual `anvil --version` into its evidence line in both venues). This
record does **not** reopen it. It is listed only so that nobody reads
`.github/action-pins.tsv` as covering more than it does: it pins the nine
actions, and says nothing about what they install.
