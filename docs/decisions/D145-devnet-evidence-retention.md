# D145 — The devnet evidence artifact's retention: the knob governs 85 % of the bytes, the other 15 % is already published through a door it cannot reach, and the artifact everyone is worried about was never once opened

- **Status: RESOLVED. The lean's DIRECTION survives at a value the lean did not
  propose, and its stated REASON is overturned on measurement.** The lean was
  *"set `retention-days: 7` or `14` on the evidence upload, because a
  redacted-but-sensitive artifact from a funded wallet's neighbourhood should not
  sit publicly downloadable for three months, and Q247's trigger is unreachable
  anyway so nothing is lost."*
  - **`retention-days: 30` is ruled, and 7 and 14 are REFUSED on this workflow's
    own triage rule.** `.github/workflows/devnet-e2e-cron.yml:27-29` (unmoved) makes *"two
    consecutive reds block storage-wave starts until diagnosed"* — and at a weekly
    cadence a 7-day retention keeps **exactly one** artifact alive at a time
    (measured, §1.4), so the first red's diagnosis expires **the day the second red
    fires** and the rule it exists to serve can never be executed. 14 leaves two
    alive with a 7-day overlap; 30 leaves five. The value is chosen by the rule that
    reads the store, not by how small a number sounds.
  - **The clause doing all the work — *"a redacted-but-sensitive artifact"* — is
    measured, and it is neither.** Nobody had ever run Q243's own scanner on the one
    artifact that exists. Run for this record (§1.3): `files=8 findings=0
    verdict=CLEAN`, exit 0; `manifest.json`'s `evm.wallet_private_key` is the literal
    string `<redacted>` while both 40-hexdigit contract addresses survive intact —
    the two-sided property proven on the real artifact rather than on a fixture; 45
    distinct 64-hex tokens with **zero occurring exactly once**; **no** anvil
    startup banner in any file (`Available Accounts`, `Private Keys`, `Mnemonic`,
    `Derivation path`: 0 hits each); no `.devnet/env` dump; and zero occurrences of
    `/home/deb`, `/Users/`, `aed900` or `maintainer-handle` (D144's scrub, clean in a published
    artifact).
- **The arm nobody listed, and the one that decides the record: `retention-days`
  governs the smaller, better-guarded half of the exposure, and the half it cannot
  touch is the unguarded one.** Six of the eight evidence files are written with
  `tee` (`scripts/e2e-devnet.sh:322,339`) and are therefore **100 % duplicated,
  verbatim, into the job log** — measured line by line: `local-up.log` 1076/1076,
  `suite-S6-S8.log` 589/589, `suite-S18.log` 110/110, `suite-S17.log` 64/64,
  `suite-S19.log` 17/17, `evidence.txt` 1/1. Only `launcher.log` (1 of 2 991 lines
  in the log) and `manifest.json` (0 of 16) are artifact-only. The flip publishes
  the log on the same terms it publishes the artifact — GitHub's visibility page,
  verbatim: *"Actions history and logs will be visible to everyone"* — and
  `retention-days:` cannot reach a log. So the knob controls **525 954 B of the
  620 748 B** the reader receives, and it is the 525 954 B that `redact()` covers;
  the 94 794 B it cannot control is the part `redact()` never touches (§1.5).
- **A second unreachability in the promote-to-required trigger, which Q247 does not
  name and which is not fixable by any retention value.** The trigger is *"≥ 20
  clean scheduled runs with **warm** runtime ≤ 15 min"*
  (`docs/ci-verification.md:1278-1279`). This lane is **the one lane in the
  repository that deliberately carries no `Swatinem/rust-cache`** (D52 evidence E3,
  restated at `devnet-e2e-cron.yml:91-97`), so **no run of it is ever warm**: the
  cargo target directory is rebuilt cold every time, and the one run that exists
  spent 13 m 07 s of its 22.9 min on that build. *Warm* is a property this lane is
  architecturally forbidden to have. Give it 400-day retention and 20 green runs and
  the trigger still cannot fire.
- **Date: 2026-08-18**
- **Owning task: Q243** (its `Do`'s final sentence, *"Consider whether the evidence
  artifact needs a shorter retention than 90 days regardless"*, returned to planning
  by the implementing lane because Q247 reads this store). Rulings touch Q247,
  `docs/ci-verification.md`, and the flip-checklist row D141 §2 minted.
- Related: D52 (the devnet venue, the no-cache ruling E3, the promote trigger and
  the D→C degradation), Q243 (the redaction self-test and the artifact scan that
  gates this upload), Q246 (the `CLOSE_GROUP_SIZE` fix, unwitnessed), Q247 (the
  trigger arithmetic), Q65/D141 (the flip and its ordered checklist), D135 (the
  minute budget and the dispatch-refusal signature), D138 (path filters and weekly
  cadence), D144 (the home-path scrub, checked here against a published artifact),
  D143/Q244 (the pinning lane editing this same file right now).

---

## 1. The measurement

Every figure below carries the command that produced it. Read-only `gh api`
throughout; nothing was deleted, dispatched or configured. Working copies live in
the session scratchpad, never in the tree.

### 1.1 The artifact, confirmed against the facts this record was handed

```
gh api repos/:owner/:repo/actions/artifacts --paginate \
  -q '.artifacts[] | [.id,.name,.size_in_bytes,.created_at,.expires_at,.expired,.workflow_run.id] | @tsv'
gh api repos/:owner/:repo/actions/runs/31571938292 \
  -q '[.id,.event,.conclusion,.created_at,.run_started_at,.updated_at,.head_sha] | @tsv'
gh api repos/:owner/:repo/actions/workflows/devnet-e2e-cron.yml/runs?per_page=50 -q '.total_count'
```

| handed | measured | verdict |
| --- | --- | --- |
| artifact id `9132238802` | `9132238802`, run `31571938292` | **confirmed** |
| `size_in_bytes` 52 269 | 52 269 — and the downloaded zip is 52 269 B to the byte | **confirmed** |
| `expires_at 2026-11-10T06:56:33Z`, `expired: false` | identical | **confirmed** |
| retention is **90 days, not the 89 Q247 records** | **confirmed**, and the mechanism is confirmed too: Q247's 89 is `(expires_at − created_at).days` = `89 days, 23:36:39` floored — it measured from **artifact creation** (`07:19:54Z`, when the upload step ran) instead of from the run | **confirmed, with Q247's error mechanism identified** |
| the clock runs from **run start**, `06:56:33Z + 90d` | the clock runs from run start — but `run_started_at` is `2026-08-12T06:56:**32**Z`, and `expires_at` is run start **+ 90 d + 1 s** | **corrected (1 s)** |
| 90 is GitHub's default *and* the maximum a **public** repo may configure; private/internal may go to 400 | verbatim from GitHub docs (§1.6) | **confirmed** |
| at most **12** of the required 20 can coexist | **13.** Fencepost: `90 / 7 = 12.86` counts *intervals*. An artifact from run `T − 7k` is alive at `T` iff `7k < 90`, i.e. `k ∈ {0…12}` — thirteen runs. The same is true at Q247's own 89. | **corrected — 12 → 13** |
| the trigger is already unreachable from its own named store | **confirmed** (13 < 20), **and for a second reason Q247 never names** (§1.6) | **confirmed and strengthened** |
| exactly **one** scheduled run ever, `31571938292`, 2026-08-12, `conclusion: failure` | `total_count: 1`. `run_started_at 2026-08-12T06:56:32Z → updated_at 07:19:58Z`. | **confirmed** |
| hosted CI refuses every job | **confirmed as of today.** Run `32096766647` (`ci`, push, 2026-08-18T03:47:50Z → 03:47:56Z, **6 s**) reports **15 jobs, 0 steps in total**. Contrast run `31873422229` (pages, 2026-08-15): 1 job, **12 steps**. The refusal began after 08-15. | **confirmed** |
| the repository is private, the flip is decided and not taken | `gh api repos/:owner/:repo` → `aed900/antseal  true  private  main` | **confirmed** |
| artifact **bytes** need an authenticated read; **metadata** is anonymous | not re-probed here (probing it unauthenticated is the Q243 lane's measurement and re-running it proves nothing new); **not disputed** | **carried, not re-measured** |

**A timing fact the wave needs.** Today is Tuesday 2026-08-18. `cron: "37 5 * * 3"`
next fires **tomorrow, Wednesday 2026-08-19** — and on today's evidence it will be
refused in ~6 seconds with zero steps and will produce **no artifact at all**. Any
retention value landed this wave therefore governs its first real object at some
undated future point after the minute allowance recovers or the flip makes standard
runners free. That is an argument for ruling now and expecting nothing to move, not
against ruling.

### 1.2 The disposition Q65 finding 4 recorded for this artifact does not exist

`tasks/Q.md:939`, verbatim: *"`devnet-e2e-evidence` (52 269 B, retained to
**2026-11-10**) becomes publicly downloadable the moment visibility flips, **which
is why Q243 must land first**"*. D141 §1.9 turns that into an ordering ruling
(Q243 **strictly before** the flip). Both are right about the ordering and **both
assume Q243 reaches this artifact.** It does not, and cannot: what Q243 built is a
pre-upload gate (`--scan-evidence`, `devnet-e2e-cron.yml:176-179`, gating the upload
at `:224` through `steps.evidence-scan.outcome == 'success'`), and artifact
`9132238802` was uploaded on 2026-08-12, five days before that gate existed. **The
one artifact the flip will expose is the one artifact the gate never ran on.** So
finding 4's remedy for it is a null act, and the existing artifact needs a
disposition of its own — which is the arm the lean never named and which §2 R2
takes.

### 1.3 What is actually in it — Q243's scanner, run on the real artifact for the first time

```
gh api repos/aed900/antseal/actions/artifacts/9132238802/zip > evidence.zip   # 52 269 B
unzip -q evidence.zip -d art/
bash /home/deb/Documents/code0/scripts/e2e-devnet.sh --scan-evidence art/     # REAL_EXIT=0
```

```
e2e-devnet: scan-evidence: dir=…/art files=8 findings=0 verdict=CLEAN
==> scan-evidence: 8 file(s), none carrying key-shaped material
```

| file | bytes | non-blank lines |
| --- | --- | --- |
| `launcher.log` | 525 475 | 2 991 |
| `local-up.log` | 48 290 | 1 076 |
| `suite-S6-S8.log` | 29 176 | 589 |
| `suite-S18.log` | 11 259 | 110 |
| `suite-S17.log` | 4 242 | 64 |
| `suite-S19.log` | 1 628 | 17 |
| `manifest.json` | 479 | 16 |
| `evidence.txt` | 199 | 1 |
| **total** | **620 748** | **4 864** |

Four things follow, each measured rather than assumed, and together they are the
honest pricing of the residual risk after Q243 that this record was asked for:

1. **Every basename is in `evidence_name_allowed()`** (`scripts/e2e-devnet.sh:155-161`)
   — the unenumerated-content arm of the scan finds nothing to complain about.
2. **`manifest.json` is redacted and not over-redacted.** Key names and value
   *shapes* only, never values: `evm.wallet_private_key` is the literal
   `<redacted>`; `evm.payment_token_address` and `evm.payment_vault_address` are
   `0x` + 40 hexdigits, intact. That is `redact()`'s two-sided property — kill the
   key, keep the contract address — proven on the shipped artifact rather than on
   the self-test's fixture.
3. **45 distinct 64-hex tokens across the eight files, and exactly ZERO of them
   occurs once.** The most frequent six appear 22, 18, 18, 17, 16 and 15 times.
   Reported by `sha256(token)[:12]`, never by value. A private key pasted into a
   log is a singleton; a blob digest, xor name or peer address recurs. Zero
   singletons is the strongest single statement available about the 343 hex tokens
   in `launcher.log`, and it is the statement the name-scoped scan structurally
   cannot make.
4. **The one leak vector this record hypothesised is absent, and saying so is part
   of the pricing.** `anvil` prints its ten funded accounts and their private keys
   in a startup banner with **no `key: value` separator**, which both `redact()`
   (`:111-113`) and the scan's two arms (`EVIDENCE_HEX_ARM` `:144`, `EVIDENCE_B64_ARM` `:148`, over
   `EVIDENCE_KEY_NAMES` `:140`) require. Such a banner would pass both. It is not there: `Available
   Accounts`, `Private Keys`, `Wallet`, `Mnemonic`, `Derivation path` and
   `Listening on` each return **0** across all eight files. The launcher spawns
   anvil through evmlib/alloy node-bindings, which does not emit it. **The vector is
   real and the instrument is blind to it; this artifact simply does not contain
   it.** §5 row 2 routes that.

Also clean, and worth recording because a published artifact is exactly where
D144's subject would surface: `/home/deb` **0**, `/Users/` **0**, `aed900` **0**,
`maintainer-handle` **0**. Seventeen `/home/runner` occurrences, which are the hosted runner's
own paths and are not the scrub's subject.

### 1.4 How many artifacts a given retention keeps alive, at this lane's cadence

At cadence `s` days and retention `R` days, the run at `T − s·k` is alive at `T`
iff `s·k < R`:

| `retention-days` | artifacts alive at once (weekly, `s = 7`) | overlap between consecutive runs |
| --- | --- | --- |
| 90 (today's default) | **13** | 83 days |
| 30 | **5** | 23 days |
| 14 | **2** | 7 days |
| 7 | **1** | **none — the previous one is gone as the next is written** |

`devnet-e2e-cron.yml:27-29` (D52 residual risk 2, verbatim in intent): *"a red
scheduled run gets a tracking note in the next wave's bookkeeping; **two
consecutive reds block storage-wave starts** until diagnosed."* Diagnosing two
consecutive reds means holding both. **At `retention-days: 7` they never coexist**,
and the workflow's own triage rule becomes unexecutable from its own store. That is
what disqualifies 7, and it is a rule this workflow states about itself rather than
an aesthetic preference.

Storage is not a consideration in either direction and should not be advanced as
one: 13 × 52 269 B = 680 KB against the 2 GB the plan includes.

### 1.5 The half the knob cannot reach — measured line by line

`scripts/e2e-devnet.sh` writes the evidence directory by two different routes:

- **`tee`** — `:322` (`scripts/devnet/local-up … 2>&1 | tee "$evdir/local-up.log"`)
  and `:339` (`cargo test … --nocapture 2>&1 | tee "$evdir/suite-$task.log"`). `tee`
  writes the file **and** stdout, and stdout on a runner is the job log.
- **`redact()` on the way in** — `capture_devnet_logs()` at `:361-362`, which is
  the **only** place `redact()` is applied and covers exactly two files:
  `.devnet/launcher.log` and `.devnet/manifest.json`.

Those two routes are disjoint, and the consequence is measurable. Downloading the
job log (`gh api repos/:owner/:repo/actions/runs/31571938292/logs`, 37 674 B zipped
→ `0_devnet-e2e-scheduled.txt`, 171 479 B) and asking, for each artifact file, how
many of its non-blank lines appear verbatim in the log after stripping GitHub's
per-line ISO timestamp:

| file | lines | present verbatim in the job log |
| --- | --- | --- |
| `evidence.txt` | 1 | **1 (100.0 %)** |
| `local-up.log` | 1 076 | **1 076 (100.0 %)** |
| `suite-S6-S8.log` | 589 | **589 (100.0 %)** |
| `suite-S18.log` | 110 | **110 (100.0 %)** |
| `suite-S17.log` | 64 | **64 (100.0 %)** |
| `suite-S19.log` | 17 | **17 (100.0 %)** |
| `launcher.log` | 2 991 | 1 (0.0 %) |
| `manifest.json` | 16 | **0** |

**94 794 B (15.3 %) of the artifact is a byte-for-byte second copy of content the
job log already carries; 525 954 B (84.7 %) is unique to the artifact — and it is
precisely the two files `redact()` covers.** The `e2e-devnet:` verdict line is the
sharpest case: `evidence.txt` and the log line are **identical at sha256
`7dd3faa7c472206981963438c923a3f95ce07dabc62752f1005fdad11ae7c450`, 198 bytes
each** (`cmp` → identical).

Two rulings follow directly, and one row (§5).

- The lean's harm model — *"should not sit publicly downloadable for three
  months"* — applies with **more** force to the log than to the artifact, and
  `retention-days:` is powerless over the log: it is an input to
  `actions/upload-artifact` and log retention is a repository setting.
- Q243's gate has a companion gap. `--scan-evidence` can refuse the **upload**, but
  by the time it runs, `tee` has already put six of the eight files into the job
  log, which no gate in this workflow can retract. A finding in `suite-S18.log`
  blocks the artifact and publishes the log.

For the avoidance of doubt, the same scanner over the job log also returns
`files=1 findings=0 verdict=CLEAN`. The gap is structural, not realised.

### 1.6 The trigger, and the second reason it cannot fire

`docs/ci-verification.md:1278-1283`, verbatim:

> 2. **The evidence exists**: **≥ 20 clean scheduled runs** with **warm runtime
>    ≤ 15 min**, per D52 Adversarial-test 4. … `target/e2e-devnet/<run>/evidence.txt`,
>    which the workflow uploads as the `devnet-e2e-evidence` artifact.

**Reason one (Q247's, corrected):** 20 weekly runs span ≥ 133 days; at most **13**
artifacts coexist in a 90-day store.

**Reason two (unnamed anywhere):** *"warm runtime"* has no referent for this lane.
`devnet-e2e-cron.yml:91-97` — *"NO `Swatinem/rust-cache` here, deliberately — this
is the one lane in the repo that omits it"* (D52 E3: the devnet target dir would
evict the 19 required lanes' caches inside the 10 GiB per-repo cap). Without a
cargo cache every run is a cold build of the ~736-package devnet graph; the single
run measured `secs=1374` = **22.9 min**, of which 13 m 07 s was that build. **No
retention value fixes a clause whose subject does not exist.**

**And the remedy Q247 offers first is unbuildable under the visibility the project
has already chosen.** Q247's `Do`: *"either raise `retention-days` on the upload
step to cover the window, or …"*. GitHub docs, verbatim: *"For public repositories:
you can change this retention period to anywhere between 1 day or 90 days."* /
*"For private repositories: … between 1 day or 400 days."* / *"When you customize
the retention period, it only applies to new artifacts and log files, and does not
retroactively apply to existing objects."* And `actions/upload-artifact`'s README,
verbatim: *"Duration after which artifact will expire in days. 0 means using
default retention. Minimum 1 day. Maximum 90 days unless changed from the
repository settings page."* Post-flip the ceiling is 90 and the requirement is 133.
**That arm of Q247 must be struck rather than weighed.**

The arm Q247 does not list and that a fair reading must: **cadence**. 20 *daily*
runs span 19 days, comfortably inside any retention. Standard GitHub-hosted runners
are free on public repositories (GitHub billing docs), so the minutes objection
that forced weekly (`devnet-e2e-cron.yml:44-48`; D135 §1: 3 154 weighted minutes in
a fortnight against an exhausted allowance) **dies at the flip**. It is named here
so Q247 rules on it; this record does not take it, because a daily 23-minute cold
build is a different trade (D138's cadence reasoning, D52's D→C degradation) and
because it still leaves *"warm"* undefined.

### 1.7 What else this repository uploads, and why none of it is generalised here

```
grep -rn "upload-artifact" .github/workflows/     # 5 sites, 4 of them artifact uploads
grep -rn "retention-days" .github/                # 1 hit: the comment saying it is open
```

`retention-days` appears **nowhere** in `.github/` except
`devnet-e2e-cron.yml:213-216`'s own note that the question is open; all four uploads sit
at the 90-day default. **The devnet upload is the only one that is not
`if: failure()`** — `ci.yml:694`, `fuzz-nightly.yml:166` and both
`verifier-page.yml` uploads (`:124`, `:138`) fire only on a red run, while
`devnet-e2e-cron.yml:225` fires `always()`. It is therefore the only upload in the
repository whose store accumulates deterministically and the only one for which
"how many are alive at once" is a well-posed question. That asymmetry, not the
content, is why this ruling is scoped to one step.

---

## 2. The ruling

### R1 — `retention-days: 30` on the devnet evidence upload. Not 90, not 14, not 7.

**Who: the lane holding `.github/workflows/devnet-e2e-cron.yml` this wave** — the
Q243 implementation lane if it is still open, otherwise the registrar records it as
owed by the flip-checklist row D141 §2 minted. **Not this lane**: `.github/**` is
outside its write scope.

**Warning on locators, and it is not hypothetical — it happened inside this
record.** Every workflow file in `.github/workflows/` is modified in the working
tree right now (Q244/D143's pinning lane), and this one was rewritten minutes before
this record began. **`devnet-e2e-cron.yml` grew 220 → 229 lines while this document
was being written**: the upload step's `uses:` moved 216 → **225** and picked up
`@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4.6.2`, and every anchor below the
`foundry-toolchain` step shifted by nine. **Every line number in this record was
re-measured at 229 lines and none was carried forward from the first reading.** The
`retention-days` line is a `with:`-block addition and does not collide with a SHA
pin, but whoever applies R1 must grep the anchor text rather than trust the number —
this is D139 §C's failure mode (28 locators invalidated by the work the record
enabled) recurring in the same wave.

In the `Upload evidence, node and Anvil logs` step, under `with:` (`:226-229` as measured below), add one line so the block reads:

```yaml
        with:
          name: devnet-e2e-evidence
          path: target/e2e-devnet/
          if-no-files-found: ignore
          # D145 — 30 days, and the number is chosen by the rule that READS this
          # store, not by how small it sounds. This workflow's own triage rule
          # (see the header, "two consecutive reds block storage-wave starts")
          # needs two consecutive weekly artifacts to coexist. At a 7-day
          # retention exactly ONE is alive at a time and the first red expires
          # the day the second fires; 14 leaves a 7-day overlap; 30 leaves five
          # artifacts alive with a 23-day overlap. 90 was never chosen — it is
          # GitHub's default and also the ceiling a PUBLIC repository may set.
          retention-days: 30
```

And **replace** the `LEFT OPEN, deliberately:` paragraph (`:213-216`),
which is now answered, with the reason and the correction:

```
      # RULED (D145): `retention-days: 30`, set below. What that knob does and
      # does not reach was measured rather than assumed. Six of the eight files
      # here are written with `tee` (scripts/e2e-devnet.sh:322,339) and are
      # therefore 100 % duplicated, verbatim, into THIS JOB'S LOG — 1 857 of
      # 4 864 lines, 94 794 of 620 748 bytes — which the flip publishes on the
      # same terms and which `retention-days:` cannot govern at all. The knob
      # controls the other 525 954 B, `launcher.log` and `manifest.json`, which
      # are exactly the two files `redact()` covers (:361-362). So this setting
      # shortens the better-guarded half; the log-side half is a separate row.
      # Q247 counts this lane's runs from this store, and the ruling costs it
      # nothing: the `e2e-devnet:` verdict line it needs is byte-identical in
      # the job log (sha256 7dd3faa7…c450, 198 B in both), and Q247's trigger is
      # unreachable from artifacts for two reasons no retention value fixes.
```

Two further corrections to comments in the same block, both measured:

- `:203-206` currently says GitHub's visibility page *"points at deleting existing
  runs and artifacts BEFORE flipping"*. The page states *"Actions history and logs
  will be visible to everyone"* and **directs the reader to "Managing workflow
  runs" and the workflow-runs REST API**; it does **not** state the ordering.
  Replace *"points at deleting … BEFORE flipping"* with *"points at the
  workflow-run management docs for removing runs and artifacts; the ordering is
  this project's ruling (D141, D145 §2 R2), not GitHub's"*.
- `:194-195` gives *"Measured size … 52,269 bytes"*. True, and it is the
  **compressed** size. Add: *"52 269 B compressed; **620 748 B across 8 files**
  unzipped — a reader receives 11.9× what the metadata advertises."*
- `:208-210`'s *"exactly 90 days after its run began"* is **confirmed to within one
  second** and should say so: `run_started_at` is `2026-08-12T06:56:32Z` and
  `expires_at` is run start **+ 90 d + 1 s**. (The `06:56:33Z` run start this lane
  was handed is the *artifact's* expiry second, not the run's; the workflow comment
  never asserted it and needs no correction beyond the added precision.)

### R2 — Artifact `9132238802` is KEPT, not deleted before the flip — and the reason is a measurement, not a preference.

**Who: nobody. This is a ruling that no external act be taken.**

The lean's harm model pointed at this artifact, and D141 §1.9 / `tasks/Q.md:939`
both assume Q243's landing dispositions it. §1.2 shows it cannot: the gate was
built five days after the upload. So the disposition had to be made by someone
opening the artifact, and this record did (§1.3): Q243's own scanner returns
`files=8 findings=0 verdict=CLEAN`, the manifest's key field is the literal
`<redacted>` with both contract addresses intact, there are 45 distinct 64-hex
tokens and **zero singletons**, no anvil key banner, no `.devnet/env` dump, and no
`/home/deb`. **It is not a leak, and deleting evidence this project measured clean
is not a security act.**

Against deletion there is also a positive cost: it is the lane's **only** remote
run ever (`total_count: 1`), and `launcher.log` — 2 991 lines, 525 KB, 99.97 % of
it nowhere else — is the diagnostic baseline against which Q246's first green run
will be read.

**If the maintainer nevertheless chooses deletion**, the exact acts are below, and
they are **external, irreversible, and require express in-the-moment consent naming
the action, the destination `aed900/antseal`, and the account — a task list, this
document, and any agent's summary of it are none of those things.** Nothing here is
authorisation.

```
# the artifact alone (leaves the run and its log):
gh api -X DELETE repos/aed900/antseal/actions/artifacts/9132238802
# the run's log (leaves the run row and the artifact):
gh api -X DELETE repos/aed900/antseal/actions/runs/31571938292/logs
# the whole run (removes the lane's only remote evidence of ever having run):
gh api -X DELETE repos/aed900/antseal/actions/runs/31571938292
```

Note the third would delete the only proof the lane has ever executed on a runner —
Q43's evidence rule's own subject — while Q246's `Accept` is already satisfied from
the row: `TODO.md:831` and `tasks/Q.md` Q246 both carry the verdict line verbatim,
which is *evidence belongs in the row* working exactly as intended.

**Also ruled, and it is a null act by measurement:** deleting the artifact would not
withdraw the six `tee`'d files, which are in the job log (§1.5). Any deletion that
is taken for exposure reasons must delete the **log**, not the artifact, or it has
withdrawn the redacted copy and left the unredacted route standing.

### R3 — This ruling is scoped to one step and is explicitly NOT generalised.

**Who: the same lane as R1.** Do not add `retention-days` to `ci.yml:694`,
`fuzz-nightly.yml:166`, `verifier-page.yml:124` or `verifier-page.yml:138` in this
act. All four are `if: failure()` uploads with a different content class (fuzz crash
inputs; a browser screenshot and event log), and the eight live
`fuzz-smoke-artifacts` already have a recorded disposition — *left to **expire**
rather than deleted* (`tasks/Q.md:939` finding 4). §5 row 3 routes a look at them;
it is not this decision's subject and must not ride along on it.

### R4 — Q247 is AMENDED, not ticked and not left. Replacement text below, verbatim.

**Who: the registrar.** Q247 stays **open** — its subject (an inconsistent trigger)
is untouched by this record, which rules only on the store. Three of its clauses are
wrong or unbuildable and must not be inherited by whoever takes it.

For `tasks/Q.md` Q247 `Do`, replacing the arithmetic sentence and the two-option
sentence:

> `docs/ci-verification.md:1278-1283` makes the `devnet-e2e-scheduled`
> promote-to-required trigger **"≥ 20 clean scheduled runs with warm runtime
> ≤ 15 min"**, and names the `devnet-e2e-evidence` artifact as where that evidence
> lives. **The arithmetic does not close, and neither does the adjective.** The
> lane is weekly (`cron: "37 5 * * 3"`), so 20 runs span ≥ 133 days, while measured
> retention is **90 days from the RUN'S START** — artifact `9132238802`,
> `run_started_at 2026-08-12T06:56:32Z → expires_at 2026-11-10T06:56:33Z`
> (D145 §1.1; the **89** this row previously recorded was `expires_at − created_at`
> floored, i.e. measured from the upload rather than the run). At weekly cadence
> **13** of the required 20 coexist, not the 12 previously recorded — an artifact
> from run `T − 7k` is alive at `T` iff `7k < 90`, so `k ∈ {0…12}`. **Raising
> `retention-days` is not an available fix and is struck from this row**: a public
> repository's ceiling is **90 days** (GitHub docs) and the flip is decided, so no
> setting can cover 133 days. **And a second clause is unreachable independently of
> all of that**: this lane deliberately carries **no `Swatinem/rust-cache`**
> (D52 E3; `devnet-e2e-cron.yml:91-97`), so every run is a cold build of the
> ~736-package graph and **no run of it is ever "warm"** — the single run measured
> 22.9 min with 13 m 07 s of cold build. Rule **both** halves: replace *"warm
> runtime"* with a threshold this lane can satisfy or admit the cache it refuses,
> **and** stop treating a 90-day expiring store as the home for evidence a
> permanent document cites. The verdict line already survives the artifact — it is
> **byte-identical in the job log** (sha256 `7dd3faa7…c450`, 198 B both, D145 §1.5)
> — so what is missing is not capture but **commit**: append each run's one-line
> `e2e-devnet:` verdict to a committed file, leaving the artifact for the bulky
> diagnostics nothing cites. A third option this row never listed, and which the
> flip makes affordable: **daily cadence** (20 runs = 19 days), since standard
> runners are free on public repositories — weighed against D138's cadence
> reasoning and a 23-minute cold build per run.

Add to `Accept`:

> - The *"warm runtime"* clause names a runtime this lane can actually have, or the
>   no-cache ruling (D52 E3) is revisited in the same act — an unreachable threshold
>   is not made reachable by counting runs.

And to `Notes`:

> **D145 (2026-08-18) settled the store and left the trigger here.** Retention is
> ruled at **30 days** on the upload (D145 §2 R1) and that ruling costs this row
> nothing, because the artifact was never the sole home of the verdict line. Two
> figures in this row's original text were wrong and are corrected above: **89 → 90
> days** (measured from the wrong endpoint) and **12 → 13 coexisting** (a fencepost
> on intervals rather than runs). Both corrections move *toward* the store and the
> conclusion survives both.

The `TODO.md:832` row carries the same three corrections in its own compressed form;
**verify against the file, do not transcribe from here.**

### R5 — `docs/ci-verification.md:1278-1283` is not edited by this record.

**Who: nobody, yet — and stating that is the ruling.** The trigger text is Q247's
subject and R4 keeps Q247 open. Editing the page here would resolve by prose a
question whose two halves (*"20 runs"*, *"warm"*) are unresolved, and would put the
page and the row in disagreement — which is exactly what the row exists to end. The
one thing this record does place on that page's future editor: **whatever store the
trigger ends up naming, `devnet-e2e-evidence` cannot be it**, on §1.6's two reasons.

### R6 — The flip checklist gains one line, and it is a "do nothing, and here is why" line.

**Who: whoever takes the flip-checklist row D141 §2 minted (orchestrator assigns
the id).** Under **at-the-flip items**, beside finding 4's four settings:

> `devnet-e2e-evidence` artifact `9132238802` (52 269 B compressed / 620 748 B in
> 8 files) — **kept, not deleted.** Scanned 2026-08-18 with
> `scripts/e2e-devnet.sh --scan-evidence`: `files=8 findings=0 verdict=CLEAN`;
> manifest key field `<redacted>`, both contract addresses intact; 45 distinct
> 64-hex tokens, zero singletons; no anvil key banner; no `/home/deb`. Expires
> **2026-11-10T06:56:33Z** on its own. D145 §2 R2. The job log of run
> `31571938292` carries six of its eight files verbatim and is published by the
> same flip; deleting the artifact without the log withdraws the redacted copy and
> leaves the other route standing.

### R7 — One new row: the `tee`'d half of the evidence is published through a channel no gate can refuse.

**Who: the orchestrator assigns the id.** Domain **Q**, milestone **M4**, size
**S**. Not an instrument finding under protocol rule 8: its subject is what leaves
the machine, and it blocks an acceptance on the ship path (Q65's flip publishes
logs).

*Title:* **Q243's scan gates the artifact, and `tee` has already published six of its
eight files to the job log.**

*Deps:* after Q243 (the gate this completes), **before Q65** (the flip that publishes
logs), D52.

*Problem:* `scripts/e2e-devnet.sh` writes `local-up.log` (`:322`) and each
`suite-*.log` (`:339`) with `tee`, so every byte also goes to stdout and thence to
the job log; `redact()` is applied **only** in `capture_devnet_logs()` (`:361-362`)
and covers only `launcher.log` and `manifest.json`. Measured on run `31571938292`:
**1 857 of 4 864 non-blank lines — 100 % of six files — are byte-identical in
`0_devnet-e2e-scheduled.txt`**, including the `e2e-devnet:` verdict line at sha256
`7dd3faa7…c450`. Q243's `--scan-evidence` gate can refuse the upload
(`devnet-e2e-cron.yml:224`) but cannot retract a log line already written, and log
retention is a repository setting no `retention-days:` reaches. **A finding in
`suite-S18.log` today blocks the artifact and publishes the log.** GitHub's
visibility page, verbatim: *"Actions history and logs will be visible to everyone."*

*Do:* close the asymmetry at the write, not at the upload — pipe the `tee`'d streams
through `redact()` on **both** legs (`… | redact | tee "$evdir/…"`), so what reaches
stdout is what reaches the file, and prove it by planting a fake key into a suite's
output and asserting it appears redacted in **both** places. Consider whether the
scan should additionally run over the accumulated stdout, noting that a scan which
only reports cannot un-publish.

*Accept:* a planted key in a `tee`'d stream is `<redacted>` in the job log as well as
in the evidence file, proven by message; the redaction is applied on exactly one
code path so the two cannot drift; `--self-test` gains a **planted-fault arm for the log leg specifically** — the
existing redaction arm (`scripts/e2e-devnet.sh:501`) proves only the capture leg, and
an arm that cannot distinguish the two is the assertion-that-cannot-fail class again;
no real key material enters the repository (the self-test's `fake_hex` at `:520` is a
repeated-character non-key, and it stays that way).

*Notes:* found by D145 while pricing a retention setting — the retention question is
what made someone ask which bytes the artifact is the *only* home for, and the answer
was 84.7 % of them. The other 15.3 % had a second home nobody had named.

### R8 — This record cannot land alone.

**Who: the orchestrator/registrar.** Creating
`docs/decisions/D145-devnet-evidence-retention.md` keeps `check-traceability.py` red
until two files outside this lane's write scope are edited:

1. **`docs/decisions/README.md`** needs
   `| [D145](D145-devnet-evidence-retention.md) | … | RESOLVED | 2026-08-18 |` in
   ascending id order; `check_decision_index` globs `docs/decisions/D*.md` and
   requires one index row per record (D119 RULING 1/3). D141–D144 are in the same
   state right now, which is the expected red the brief names.
2. **`TODO.md`'s decision register** needs a `- [x] **D145**` row. **The id must be
   confirmed by the orchestrator before this file is cited anywhere**: this lane was
   handed `D145` and did not allocate it, and `docs/decisions/` currently holds
   records up to D144 with no D145 register row read by this lane.

---

## 3. What this record refuses

1. **`retention-days: 7` — refused on the workflow's own triage rule**
   (`devnet-e2e-cron.yml:27-29`). One artifact alive at a time; two consecutive reds
   never coexist; the rule that reads the store cannot be executed from it. This is
   the arm of the lean that is killed outright.
2. **`retention-days: 14` — refused as the weaker of two survivors**, not as an
   error. It leaves two artifacts with a 7-day overlap, which satisfies the triage
   rule with no margin and forecloses any three-run comparison. Since the storage
   cost of 30 over 14 is 156 KB and the exposure difference applies only to the
   half that is already gated, redacted and measured clean, the margin is worth more
   than the 16 days.
3. **Leaving 90 — refused**, though this was the closest call. 90 is not a choice;
   it is GitHub's default and simultaneously the public ceiling, so leaving it means
   the setting can only ever move down and never records why it sat where it sat.
   A shipped file that says *"LEFT OPEN, deliberately"* after the question is
   answered is worse than either value.
4. **The lean's premise that the artifact is *"redacted-but-sensitive"* — refused
   on measurement**, §1.3. It is redacted, it is scanned clean by the project's own
   broader-than-the-redactor instrument, and the strongest available statement about
   its 45 hex tokens is that none of them is a singleton.
5. **The lean's *"nothing is lost"* clause — refused as reasoning even though its
   conclusion holds.** Nothing is lost, but not because Q247's trigger is
   unreachable; it is lost-proof because the one line Q247 needs is byte-identical
   in the job log. Reasoning from *"the reader is broken so the store does not
   matter"* would license shortening to 1 day, which §1.4 shows is wrong. The
   correct reason is that the store is not the verdict line's only home.
6. **Deleting artifact `9132238802` before the flip — refused**, §2 R2, on the scan
   and on its being the lane's only remote evidence. And refused *as an exposure
   act* on a second ground: it withdraws the redacted copy and leaves the
   unredacted `tee`'d route in the log.
7. **Fixing Q247's trigger — refused as out of scope, having removed one of its
   arms.** This record rules that *raising retention cannot be the fix* and that
   *"warm" has no referent*, and hands both back. Ruling the trigger here would be
   this lane taking a decision that belongs to a row that is open and adequate.
8. **Generalising `retention-days` to the other three upload sites — refused**,
   §2 R3. Four sites, one content class each, and only this one uploads on green.
9. **Reading the repository-level retention setting from the API — refused as
   impossible, and the figure is derived instead.** No REST endpoint exposes it
   (`/repos/{owner}/{repo}/actions/permissions` returns
   `{"enabled":true,"allowed_actions":"all","sha_pinning_required":false}` and
   nothing about retention). The 90 is measured from `expires_at − run_started_at`
   on a real artifact, which is the observable, and corroborated by GitHub's
   documented default.

---

## 4. Falsifiers

Each is a thing that, if true, overturns a specific ruling.

- **X1 (R1).** If the cadence stops being weekly — the flip makes standard runners
  free and §1.6 names daily as a live option for Q247 — then 30 days holds 30 runs
  rather than 5 and the value should be re-derived from the triage rule at the new
  `s`. **Re-run §1.4's inequality; do not carry 30 across a cadence change.**
- **X2 (R1).** If `scripts/e2e-devnet.sh` ever starts capturing a file that is
  *not* also on stdout — i.e. if `capture_devnet_logs()` grows a third entry — the
  84.7 / 15.3 split moves and the knob governs more. Re-measure with §1.5's
  line-presence method against the newest run, not against run `31571938292`.
- **X3 (R2).** If **any** widened scan finds key-shaped material in artifact
  `9132238802` — most plausibly a bare-hex arm, since §1.3 row 4 names the exact
  blind spot — R2 inverts immediately and the artifact must be deleted **together
  with the run's log**. The falsifying command is one line: re-run
  `--scan-evidence` after the scan gains a bare-hex arm.
- **X4 (R2).** If the flip is taken *before* R2's line reaches the checklist, R2 has
  not been executed — it is a ruling to do nothing, and a ruling to do nothing is
  only discharged when it is recorded where the person doing the flip will read it.
- **X5 (R4).** If D52's Adversarial-test 4 is found to define *"warm"* as something
  this lane can have — a warm **runner image** rather than a warm cargo cache —
  then §1.6's reason two evaporates and only the arithmetic stands. **This record
  did not read D52's Adversarial-test 4 directly**; it read the trigger as
  transcribed at `docs/ci-verification.md:1278-1279` and the no-cache ruling as
  restated at `devnet-e2e-cron.yml:91-97`. Whoever takes Q247 must read D52 itself.
- **X6 (R7).** If GitHub ever applies a repository's `retention-days` to logs at
  the workflow level, or exposes a per-step log-redaction hook, R7's shape changes
  from "redact at the write" to a configuration act. Nothing in today's
  documentation offers either.
- **X7 (§1.1).** The public/private retention ceilings (90 / 400) are from GitHub's
  documentation, not from an API probe of this repository — the setting is not
  API-readable (§3 row 9). If the ceiling is ever observed to differ, the *"the
  flip caps this where it already sits"* sentence in `devnet-e2e-cron.yml:211-212`
  is what needs re-checking, not R1: 30 is below every candidate ceiling.

---

## 5. Defects found that are not this decision's subject

1. **`tasks/Q.md:939` finding 4 records a remedy that cannot act on its own
   subject.** *"…becomes publicly downloadable the moment visibility flips, which is
   why **Q243** must land first"* — Q243 as built is a pre-upload gate and cannot
   reach an artifact uploaded five days before it existed (§1.2). D141 §1.9 inherits
   the same assumption when it rules the Q243 edge *"inverted — strictly before"*.
   The **ordering ruling is right**; the belief that it disposes of artifact
   `9132238802` is not. §2 R6 supplies the missing disposition. **No new id** — this
   is a correction to an existing finding, and the registrar owns it.
2. **The redactor and the scan are both blind to a key printed without a `key: value`
   separator, and `anvil`'s startup banner is exactly that shape.** `redact()`
   (`:111-113`) and both scan arms (`:140-148`) require
   `<name><sep><value>`; anvil prints `Private Keys` / `==================` /
   `(0) 0x…` on separate lines with no name adjacent to the value. Measured absent
   from this artifact (§1.3 row 4) — the launcher spawns anvil via evmlib/alloy
   node-bindings — but the gap is one upstream change from being realised, and it
   would defeat the *output* check that Q243 built precisely to survive changes in
   the *filter*. Route to `docs/instrument-ledger.md` under rule 8 unless a wave is
   already pointed at `e2e-devnet.sh`, in which case fold it into R7's act: a
   positional arm (`^\s*\(\d+\)\s+0x[0-9a-fA-F]{64}\s*$`) costs one line and has no
   false-positive surface in this content.
3. **All four `upload-artifact` sites are at the 90-day default and only one has
   ever been thought about.** `retention-days` occurs nowhere in `.github/`
   (§1.7). `fuzz-nightly-artifacts` and `fuzz-smoke-artifacts` are **fuzz crash
   inputs** — the reproducers for whatever the fuzzer found — and
   `verifier-page-diagnosis` is a screenshot of a failing page. All become public at
   the flip. The eight existing `fuzz-smoke-artifacts` have a disposition
   (`tasks/Q.md:939`: left to expire); the **step settings** do not. Not this
   record's subject and deliberately not generalised (§2 R3).
4. **`devnet-e2e-cron.yml:116` predicted a venue divergence and the divergence
   happened, unremarked.** The comment says the mitigation for D52 residual risk 5
   is that the script prints `anvil --version` into the evidence line *"so a
   divergence from the host's 1.5.1-stable is recorded, not ambient"*. The evidence
   line reads `anvil=1.7.1`. The mechanism worked perfectly and **nothing read its
   output** — the divergence has sat in the artifact since 2026-08-12. Whoever
   witnesses Q246's first green run should record the anvil versions in both venues
   in the row, per *evidence belongs in the row*.
5. **`docs/ci-verification.md:1276-1277`'s trigger precondition 1 carries the
   ordering loop D141 §2 R8 struck elsewhere.** *"the repository goes public — which
   triggers **Q65 first**, never after"*. D141 R8 deletes the identically-shaped
   *"going public triggers Q65 first"* clause from `TODO.md:294` as *"the fourth
   ordering loop … now false in its premise"*, and precondition 1 also still offers
   *"GitHub Pro (option 1 above)"* as a future step although
   `docs/ci-verification.md:2082-2083` records that **the maintainer already
   upgraded the account to Pro**. Two stale clauses in three lines, on the page a
   future maintainer is told to read for this trigger. Not edited here (§2 R5 keeps
   the page for Q247), and flagged so Q247's editor fixes them in the same act.
6. **`scan_evidence()` returns 0 on an empty directory *and* on a missing one**
   (`scripts/e2e-devnet.sh:174-176`, `:206-210`), with a warning in each case, and
   the upload's gate is `steps.evidence-scan.outcome == 'success'`. Correct as
   designed — a scan of nothing must not red a job — but it means the gate's green
   is satisfiable by a run that captured nothing, and `if-no-files-found: ignore`
   then makes the upload green too. The `files=0` in the printed line is the only
   signal, and nothing reads it. An assertion that cannot fail, of the class this
   project has now found in four separate instruments. Ledger, not a row: it blocks
   no ship-path acceptance and reddening it would red the legitimate
   nothing-captured case.
