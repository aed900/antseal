# D61 — Long-run fuzz venue: the existing scheduled lane, re-cadenced to fit a budget it currently exceeds

- **Status: RESOLVED — the venue is `.github/workflows/fuzz-nightly.yml`, the
  lane that already exists and has already been running. OSS-Fuzz is
  **rejected as not applicable**, and not for the reason the register
  implies: its acceptance criterion is *adoption*, which no decision in this
  project controls, so it is not unblocked by Q65's public flip alone.
  ClusterFuzzLite — a third venue the register does not name — is evaluated
  and rejected (same minutes, more machinery). The real finding is that the
  venue question was never the binding one: the lane's committed
  configuration (daily × 4 targets × 900 s) consumes **≥ 1 824 minutes/month,
  91 % of the entire 2 000-minute GitHub Free allowance**, before any build
  time, and Q17's two M2 targets take it to **≥ 2 736 min/month, 137 %** —
  at which point GitHub blocks *all* workflow runs, including the 19 required
  contexts. It has been live on the default branch since 2026-07-28 and not
  one of its ~5 runs has ever been observed. The ruling therefore re-cadences
  it to **twice weekly at 600 s/target**, gives it a **named 700 min/month
  ceiling with a machine check that goes red when a new target breaks it**,
  and splits the failure policy so a genuine crash never inherits D52's
  two-consecutive-reds grace.**
- **Date: 2026-08-02** (M2 Anchors planning round; register TODO.md:573)
- **Owning task: Q9** (owns the infrastructure), with **Q17/A23** (the two
  M2 targets that force the arithmetic) and **Q65** (the re-evaluation's
  named owner)
- **Blocks: Q17** (which adds targets to a lane whose budget is already
  exceeded)

## Context

`TODO.md:573` registers D61 as *"Long-run fuzz venue: nightly CI vs
OSS-Fuzz (Q9)"*. `docs/testing/fuzzing.md` §7 states the project's standing
position:

> Whether long-running fuzzing eventually lives in scheduled CI or in
> **OSS-Fuzz** is decision D61, **due M3 — deliberately not resolved here.**
> […] The one thing D61 must decide either way: OSS-Fuzz requires a public
> repository and an upstream-facing contact, so it is gated on the same
> publication decisions as the release lane, not on anything technical here.

Both halves of that last sentence are examined below and one of them does not
survive. Before either, four facts about the present state that the register
entry does not contain.

## The register's framing, corrected

### Correction 1 — the lane is not hypothetical. It exists, it is on the remote default branch, and it has been running unobserved for five nights

`.github/workflows/fuzz-nightly.yml` was added by commit **5302829**
("Q9 (+Q39): cargo-fuzz infrastructure — toolchain pin, lanes, corpus
policy", 2026-07-28 15:48:23 +0100) and reached the remote in wave 6's
182-commit push. Verified:

```
$ git merge-base --is-ancestor 5302829 518f342 && echo "ancestor of remote head"
ancestor of remote head
$ git ls-remote --heads origin
518f342fdd83c8d246c552a4648cbbdd39c11e46  refs/heads/main
```

Its trigger is `cron: "41 3 * * *"` — **daily**, 03:41 UTC — and GitHub runs
`schedule:` against the default branch, which now contains this file.

**How many cron instants have passed is bounded but not pinned**, and the
distinction is stated rather than assumed: what is *verified* above is that
the Q9 commit is an ancestor of the current remote head, so the lane has been
live at latest since the 2026-08-01 push (**≥ 2 instants**: 08-01, 08-02).
`docs/ci-verification.md`'s Q43 section records that wave 6 — the wave whose
lane changes are documented at its line 831 as *"Q9 — wave-6 lane changes
(2026-07-28)"* — *"pushed 182 commits at once"*, which puts the true date at
2026-07-28 and the count at **5** (07-29 … 08-02). At ≥ 60 minutes each
(Correction 2) that is **≥ 120 and probably ≥ 300 minutes already spent**.
Decision 1 resolves the ambiguity by reading the runs, which is the first
thing this ruling asks for and the reason it asks for it first.

**Nothing anywhere records that a single one of them ran, passed, or cost
anything.** `docs/ci-verification.md` — the document whose own governing rule
is *"A lane that has never run on the remote is not evidence"* (Q43, its
§ at line 1075) — mentions `fuzz-long` twice, both times describing the
lane's construction, never a run of it. That is the same class of gap Q43
and Q66 were written to close, one level out: not a lane that never ran, but
a lane that ran and was never looked at.

So D61 is not choosing where long-run fuzzing should happen. It is ruling on
a lane that is already spending the project's minutes.

### Correction 2 — the committed configuration does not fit the budget, and Q17 makes it worse

`scripts/fuzz.sh` runs targets **sequentially** — `cmd_time_budget` loops
`for t in $(select_targets …)` and calls `run_fuzz` with
`-max_total_time=$seconds` per target (`scripts/fuzz.sh:141-149`) — and
`TARGETS=(manifest_decode bundle_decode codec_round_trip verify_bundle)`
(`scripts/fuzz.sh:32`). The workflow passes
`"${{ github.event.inputs.seconds || '900' }}"`.

**Derived** (arithmetic shown; the only inputs are the committed literals and
GitHub's published billing rules):

| | targets | s/target | fuzzing min/run | runs/month | min/month | % of 2 000 |
| --- | --- | --- | --- | --- | --- | --- |
| committed today | 4 | 900 | 60 | 30.4 | **1 824** | **91 %** |
| after Q17/A23 | 6 | 900 | 90 | 30.4 | **2 736** | **137 %** |

Every figure is a **strict lower bound**: it counts `-max_total_time` only,
and excludes checkout, `rustup`, the `Swatinem/rust-cache` round trip, the
instrumented build, the self-test, and the corpus report. The job's own
`timeout-minutes: 120` is the workflow author's estimate of the upper bound.

The 2 000 figure is GitHub's, retrieved **2026-08-02T19:26Z**:

> "2,000" minutes per month are provided for private repositories on the
> GitHub Free plan
> — <https://docs.github.com/en/billing/managing-billing-for-your-products/about-billing-for-github-actions>

Linux standard runners bill at 1×; `cross-os-macos` bills at 10× and
`cross-os-windows` at 2× on **every push** (D52 E3 records this as the
already-existing draw), and `devnet-e2e-cron` takes a weekly cold build of a
~736-package graph **with no `rust-cache`** by deliberate choice
(`docs/ci-verification.md`, promote-to-required section). None of that is
counted above.

### Correction 3 — exhausting the allowance does not degrade the fuzz lane. It stops every lane

Retrieved 2026-08-02T19:29Z, docs.github.com:

> If your account does not have a valid payment method on file, usage is
> blocked once you use up your quota.

There is no per-workflow fairness. The 19 required contexts, `advisory-cron`,
`devnet-e2e-cron` and every future PR stop with it. A lane budgeted at 91 %
of the allowance is therefore not "expensive" — it is a single point of
failure for the project's entire verification apparatus, which is the thing
the whole `docs/ci-verification.md` discipline exists to protect.

### Correction 4 — "OSS-Fuzz is gated on the same publication decisions as the release lane" is not true, and writing the deferral that way would arm the wrong trigger

OSS-Fuzz's acceptance criterion, retrieved **2026-08-02T19:24Z** from
<https://google.github.io/oss-fuzz/getting-started/accepting-new-projects/>:

> "To be accepted to OSS-Fuzz, an open-source project must have a significant
> user base and/or be critical to the global IT infrastructure."

and, for the submission itself:

> "Your project's homepage" · "Your project's main repository URL" · "Your
> project's primary language" · an email for "the engineering contact to be
> CCed on new issues", where "The address belongs to an established project
> committer (according to VCS logs)" and "The address is associated with a
> Google account".

Public-repository status is **necessary and not sufficient**. The sufficient
condition is a significant user base — which Q65 does not grant, which no
decision in this project grants, and which antseal (pre-release, unpublished,
zero users) does not have and will not have at M2 or M3.

This matters concretely: a deferral written as *"OSS-Fuzz becomes eligible if
and when Q65 flips the repo public"* would fire a re-evaluation on an event
that does not make it eligible, and would leave a wave believing D61 had
reopened when nothing had changed. The trigger has to name both conditions
(Decision 8).

Two further costs that must be weighed **then** rather than assumed away now:
the required engineering-contact email must belong to an established
committer *and* to a Google account — where a wave-7 scan found the only
email in the tree is the canonical noreply (`tasks/Q.md` Q65 Notes), so this
is a new personal disclosure, not a formality; and OSS-Fuzz publishes issues
on a 90-day disclosure deadline. For parsers that stand between a user and an
adversary's `.sealproof`, a public disclosure clock is a defensible trade for
an auditable verifier — but it is a trade, and it is not this record's to
make on adoption that does not exist.

### Correction 5 — a third venue exists and the register does not name it

**ClusterFuzzLite** is OSS-Fuzz's CI-resident sibling and it explicitly
supports what OSS-Fuzz refuses. Retrieved 2026-08-02T19:25Z from
<https://google.github.io/clusterfuzzlite/running-clusterfuzzlite/github-actions/>:

> "In order for ClusterFuzzLite to use private repos, the GitHub token needs
> to be passed to the build and run steps."

with modes `code-change`, `batch`, `prune`, `coverage` across four workflow
files, and a filestore that is either GitHub artifacts ("If a storage repo
isn't specified, corpora and coverage reports will be uploaded as GitHub
artifacts instead") or a separate git repository.

It is rejected, on measured grounds rather than unfamiliarity — see
Decision 2. The point of naming it is that the register's binary framing
concealed the only alternative that was actually available to a private repo.

## Evidence

### E1 — What the lane persists, measured

Working corpus on this machine, today (`scripts/fuzz.sh corpus-report`):

```
manifest_decode         271 files       1.2M
bundle_decode           505 files       3.4M
codec_round_trip          0 files       4.0K
verify_bundle           145 files       592K
                        921 files       5.1M total
```

Committed seeds (`testdata/fuzz-seeds/MANIFEST.json`, cross-checked against
`find … -name '*.bin' | wc -l`): **255 seeds, 1.3 MB** —
`manifest_decode` 26 / 70 247 B, `bundle_decode` 33 / 199 023 B,
`verify_bundle` 196 / 3 080 B. `codec_round_trip` has none by design
(`scripts/fuzz.sh:76-77` passes it both decode seed directories).

`fuzz/target` measures **564 MB** — that, not the corpus, is what
`Swatinem/rust-cache@v2 (workspaces: fuzz)` puts in the cache.

### E2 — GitHub's cache rules, and the one that decides the cadence

Retrieved 2026-08-02T19:29Z,
<https://docs.github.com/en/actions/reference/dependency-caching-reference>:

> "GitHub will remove any cache entries that have not been accessed in over
> 7 days."
>
> "The total size of all caches in a repository is limited. By default, the
> limit is 10 GB per repository."
>
> when exceeded, "the cache eviction policy will create space by deleting the
> caches in order of last access date, from oldest to most recent."

Two consequences:

1. **The corpus cache is free.** 5.1 MB per run against a 10 GB cap; even
   seven live generations is ~36 MB. The `rust-cache` entry (564 MB class) is
   the real consumer, and it is shared-key so it does not multiply.
2. **A weekly cadence would sit exactly on the eviction boundary.** The
   accumulate property is this lane's entire reason to exist — the workflow
   header says so: *"it needs the corpus to *accumulate* rather than start
   from the committed seeds each time"*. A 7-day interval leaves zero margin
   against a 7-day eviction rule. This is what rules out copying
   `devnet-e2e-cron`'s weekly answer wholesale, and it is the one place where
   the two scheduled lanes must differ.

### E3 — House precedent, and where it stops applying

`devnet-e2e-cron.yml` is the same class of decision taken eight days earlier,
and its header records the outcome verbatim:

> "**Weekly rather than D52's estimated daily, deliberately**: see the cache
> note on the job below. Without a shared cargo cache every run is a cold
> build of the ~736-package devnet graph, so the affordable cadence is weekly
> until the first dispatches measure the real cost. Cadence is a one-line
> change once the measurement exists."

So the project has already ruled, once, that a scheduled heavy lane's cadence
is set by the minutes budget and lands conditionally on measurement. D61
follows that method exactly. It **departs** on the cadence itself, for E2's
reason: the devnet lane has no corpus to keep warm.

### E4 — What I did not measure, and why

The one figure that would settle Correction 2 empirically is the actual
billed duration of the five runs that have already happened. It is available
only through the authenticated Actions API. The round's network permission
covers liveness reads, certificate downloads, TSA submissions and calendar
submissions, and excludes *"any account-bearing action"* — `gh api`
authenticates as the maintainer's account, so it was not run. The exact
commands are handed to the maintainer in Decision 1; the ruling is designed
so that the measurement **tightens** it rather than being required to reach
it (the lower bound alone already exceeds the affordable share).

## Options

**A — OSS-Fuzz.** Rejected: not eligible, and eligibility turns on adoption
(Correction 4), not on any decision this project can take. Also costs a
Google-linked committer email, a Docker/`build.sh` integration to maintain,
and a 90-day public disclosure clock.

**B — ClusterFuzzLite in GitHub Actions.** Available on a private repo
(Correction 5), and would give batch fuzzing, corpus pruning and coverage
reports. Rejected on three measured grounds: (i) it runs **in GitHub
Actions**, so it draws on the same 2 000-minute allowance that is already the
binding constraint — it solves nothing about the actual problem; (ii) it
requires an OSS-Fuzz-style Docker + `build.sh` build integration, replacing a
native `cargo fuzz` path that works today and whose toolchain and tool pins
are already exact (`fuzz/rust-toolchain.toml`, `cargo-fuzz =0.13.2`) — a
Docker image is a second, unpinned toolchain surface under
`docs/dependency-policy.md` §5; (iii) its default filestore is GitHub
artifacts, and the recommended one is a **separate git repository** needing a
personal access token, since "the default GitHub auth token is not able to
write to other repositories" — a standing cross-repo write credential for a
corpus that `actions/cache` already carries for free.

**C — the existing scheduled lane, re-cadenced and budgeted.** Keeps the
native cargo-fuzz path, the pinned nightly, the self-test tripwire, the
`actions/cache` corpus round trip and the committed-seed convention, all of
which are built and (locally) verified. Costs one cron edit, one default
change, and one new guard.

**D — delete the lane.** The honest fourth option, and it must be named
because D52's degradation path names its equivalent. Rejected: `fuzz-smoke`'s
90 s/target from the committed seeds is a regression net, not a search, and
the corpus never accumulates there. The 2026-07-28 finding that made the
whole apparatus worth having — the 32× allocation amplification surfaced *in
seconds* by the first run over the committed corpus (`docs/testing/fuzzing.md`
§1, F30) — came from search, not from regression.

## Decision

**Option C.** Concretely, and in this order.

### 1. First, measure what has already been spent — before changing anything

Maintainer-executed (account-bearing; see E4). Recorded in
`docs/ci-verification.md` under a dated section, per that file's append-only
convention:

```
gh api /repos/aed900/antseal/actions/workflows/fuzz-nightly.yml/runs \
  --jq '.workflow_runs[] | [.created_at, .conclusion, .run_started_at, .updated_at] | @tsv'
gh api /users/aed900/settings/billing/actions
```

The first gives the per-run wall clock (`run_started_at` → `updated_at`) and
whether any of the five nights was red; the second gives
`total_minutes_used` and `included_minutes` for the current cycle. **If any
of the five was red, that is a finding to triage under §7 before the cadence
change lands** — a red that has been sitting unobserved for days is exactly
the case §7 exists for.

### 2. Cadence: twice weekly, Mondays and Thursdays

`.github/workflows/fuzz-nightly.yml`, replacing the `cron:` line verbatim:

```yaml
    # TWICE WEEKLY, Mondays and Thursdays 03:41 UTC. Daily does not fit the
    # budget (D61 Correction 2: 4 x 900 s daily is >= 1 824 min/month, 91 %
    # of the 2 000-minute GitHub Free allowance, and exhausting it blocks
    # EVERY workflow, not just this one). Weekly does not work either: the
    # corpus cache is evicted after 7 days without access, and accumulation
    # is this lane's whole purpose (D61 E2). Mon/Thu leaves 3-4 days of
    # margin against that 7-day rule. Offset from advisory-cron (Mon 06:17)
    # and devnet-e2e-cron (Wed 05:37) so no two heavy jobs queue together.
    - cron: "41 3 * * 1,4"
```

The workflow **name stays `fuzz-nightly`** and the job id and `name:` stay
`fuzz-long`. Renaming them would break every cross-reference in
`docs/testing/fuzzing.md` §5, `docs/ci-verification.md`, `ci.yml`'s header
block and `devnet-e2e-cron.yml`'s own comments, for a cosmetic gain. The
header comment carries the correction; the identifier is a name, not a claim.

### 3. Per-target budget: 600 seconds

In the same file, the `workflow_dispatch` input default and the run step:

```yaml
      seconds:
        description: "Seconds per target"
        required: false
        default: "600"
```
```yaml
      - name: Long run
        run: ./scripts/fuzz.sh long "${{ github.event.inputs.seconds || '600' }}"
```

`scripts/fuzz.sh`'s own `long` default stays **900** — it is the documented
interactive budget and the workflow passes its value explicitly. The two are
deliberately different and the guard in §5 reads the workflow's, which is the
one that spends money.

**Derived cost**: 6 targets × 600 s = 60 min fuzzing/run; 8.7 runs/month
(52 × 2 ÷ 12) ⇒ **522 min/month** fuzzing, ~**650 min/month** with a 15-min
per-run allowance for checkout, cache, build and self-test — **33 %** of the
allowance, against 91 % today and 137 % after Q17. Per target per week:
1 200 s, against `fuzz-smoke`'s 90 s per PR.

`timeout-minutes: 120` stays; at 60 min of fuzzing it now has real headroom
instead of being the binding constraint.

### 4. Corpus persistence: mechanism unchanged, facts recorded

The `actions/cache` block stays exactly as written —
`path: fuzz/corpus`, `key: fuzz-corpus-${{ github.run_id }}`,
`restore-keys: fuzz-corpus-` — because it is correct and its rationale
(immutable caches, so a fixed key freezes the corpus on day one) is already
in the header. Two facts get added to that comment, both measured:

```
      # Sizing (D61 E1, measured 2026-08-02): the working corpus is
      # 921 files / 5.1 MB across four targets, so even seven live cache
      # generations are ~36 MB against GitHub's 10 GB per-repo cap. The
      # rust-cache entry (fuzz/target, 564 MB class) is the real consumer.
      # RETENTION: GitHub deletes cache entries not accessed for 7 days, so
      # this lane's cadence may never be lengthened past ~5 days without
      # losing the accumulation this cache exists for (D61 E2, Decision 2).
```

`testdata/fuzz-seeds/` is untouched and its convention is unchanged: it stays
committed, generated, drift-checked and deterministic; the cache stays
gitignored machine-found material with no claim to reproducibility. The two
never mix, and `corpus_dirs()` (`scripts/fuzz.sh:70-81`) already passes both
to libFuzzer, which is what makes a fresh cache degrade to "start from the
committed seeds" rather than to "start from nothing".

### 5. A machine check on the budget — the deliverable that makes this stick

New lane command `scripts/ci-lanes.sh fuzz-budget`, added to
`scripts/local-gate.sh` and to a job in `ci.yml`. It reads only committed
sources and computes the lane's monthly cost:

- target count from `scripts/fuzz.sh`'s `TARGETS=(…)` array;
- seconds from `fuzz-nightly.yml`'s `inputs.seconds` `default:`;
- runs/month from the `cron:` day-of-week field (`52 × ndays ÷ 12`);
- `minutes = targets × seconds × runs_per_month ÷ 60`, plus a
  `PER_RUN_OVERHEAD_MINUTES = 15` allowance × runs/month.

It fails if the total exceeds

```
FUZZ_BUDGET_CEILING_MINUTES = 700
```

— **35 % of the 2 000-minute allowance**, the named share this lane is
permitted. The ceiling is a constant in the script with the derivation in a
comment, and it is **raise-only by decision**, never by an implementer
needing a build to go green.

Why this is the important part: **Q17 adds two targets to `TARGETS`**, and
under today's arrangement that silently multiplies the bill by 1.5 with
nothing anywhere noticing until the allowance runs out and every lane stops.
With this guard, a target count that breaches the ceiling turns a lane red and
forces the one-line `seconds` change in the same PR. The knob is always
`seconds`; **cadence is not a knob**, because cadence protects the corpus (E2).

> **Corrected 2026-08-02 (Q81, at implementation).** This paragraph and the
> one at line ~442 said *"Q17's first commit turns a lane red"*. **That is
> false by this document's own arithmetic**: at six targets, twice weekly ×
> 600 s costs **650.25 min/month**, which is under the 700-minute ceiling, so
> Q17's two targets land **green**. §3's ~650 figure and §11's *"a seventh
> fuzz target … goes red by construction"* are the consistent pair — the
> ceiling is calibrated at **seven**, not at Q17. The guard is still what
> makes the breach visible; it simply does not fire where this sentence
> claimed. Measured red/green either side: 7 targets → 736.95 (RED), 6 →
> 650.25 (GREEN).

Self-test, mandatory and in the house pattern (`secret-guard`'s planted
fakes, `wasm-bitmatch`'s injected divergence, `fuzz.sh selftest`'s tripwire):
the command first runs itself against a synthetic `TARGETS` array of seven
names and asserts it goes **red**, then against the committed sources and
asserts **green**. A budget checker that has never been observed failing is
the exact defect this project keeps finding.

**Landing order, because the guard is red at HEAD.** At the committed
configuration the checker computes ≈ 2 275 minutes against a 700 ceiling, so
the guard and the §2/§3 changes must land in **one commit** — otherwise the
first commit turns `local-gate` and `ci` red. The red-before-green
demonstration the Accept asks for is therefore produced on a scratch tree (or
by reverting the two lines locally), recorded in the commit message, and is
what proves the guard is wired to reality rather than fitted to the numbers
that follow it.

### 6. Q17's two targets land in one place and are picked up by both lanes

A23's DER and `.ots` targets are added to `TARGETS` in `scripts/fuzz.sh:32`
and nowhere else. `fuzz-smoke`, `fuzz-long`, `selftest`, `cmin` and
`corpus-report` all iterate that array, so neither workflow needs an edit.
Two consequences to state so they are not discovered late:

- **`fuzz-smoke`'s per-PR cost rises from 4 × 90 s to 6 × 90 s = 9 minutes**
  of fuzzing plus its self-test, on a lane that runs on every PR and every
  push to main. That is the *other* half of Q17's budget footprint and it is
  not covered by the ceiling in §5, which scopes the scheduled lane. It is
  small enough to accept and large enough to record.
- The two new targets need seed directories under `testdata/fuzz-seeds/`
  emitted by the generator, exactly like the existing three, or
  `corpus_dirs()`'s `[ -d … ]` guard silently gives them the working corpus
  alone. Q17's Accept already says "corpora seeded and committed"; this is
  the mechanism it resolves to.

### 7. Failure policy — split, because importing D52's convention whole would give a real crash a free night

`devnet-e2e-cron.yml` records the house convention verbatim: *"a red
scheduled run gets a tracking note in the next wave's bookkeeping; **two
consecutive reds block storage-wave starts** until diagnosed."* Applying that
unmodified here would be wrong, and this is the refinement D61 exists to
make.

| red kind | how it is identified | policy |
| --- | --- | --- |
| **crash** | the run uploaded a non-empty `fuzz-nightly-artifacts` (i.e. `fuzz/artifacts/**` was non-empty) | **Release-blocking on the first occurrence.** No grace, no two-red rule. `docs/testing/fuzzing.md` §4's opening sentence is already normative — *"A crash is release-blocking. No exceptions"* — and a crash is a finding, not flake. It is triaged under §8 before the next wave starts. |
| **infrastructure** | the run failed with **no** artifact — build failure, toolchain rot, `cargo-fuzz` pin drift, cache or runner failure | D52's convention exactly: tracking note in the next wave's bookkeeping; **two consecutive infrastructure reds block wave starts** until diagnosed. |

The two are distinguishable without judgement because the workflow already
uploads `fuzz/artifacts/` on failure with `if-no-files-found: ignore`. Make
it explicit rather than inferable — add, before the upload:

```yaml
      - name: Classify the failure (D61 §7)
        if: failure()
        run: |
          if [ -n "$(find fuzz/artifacts -type f -print -quit 2>/dev/null)" ]; then
            echo "::error::CRASH — reproducer written. Release-blocking on the FIRST occurrence (D61 §7, docs/testing/fuzzing.md §4)."
          else
            echo "::warning::INFRASTRUCTURE RED — no reproducer. Tracking note; two consecutive block wave starts (D61 §7)."
          fi
```

Neither kind is ever a merge gate: `fuzz-long` is not a PR status context and
never becomes one.

### 8. Crash → fixture, for the nightly path specifically

`docs/testing/fuzzing.md` §4 already carries the triage procedure and is not
superseded. What it does not carry is the *nightly* case, where the crashing
input arrives as a downloaded CI artifact rather than as a file already on
disk. Those steps, exactly:

1. **Download**: `gh run download <run-id> -n fuzz-nightly-artifacts -D /tmp/fuzz-crash`
   (maintainer-executed; account-bearing).
2. **Confirm it is not the tripwire**: `ANTSEAL_FUZZ_SELFTEST` is unset in the
   workflow, and tripwire panics say so in their message
   (`fuzz/src/lib.rs::selftest_tripwire`). A tripwire artifact from this lane
   means the self-test step leaked, which is itself the finding.
3. **Reproduce locally**:
   `scripts/fuzz.sh repro <target> /tmp/fuzz-crash/<target>/<file>`.
4. **Move it into the ordinary suite** — fuzzing.md §4 step 2, unchanged: add
   the bytes as a case in `crates/antseal-core/tests/codec_fuzz.rs` (or
   `verify_fuzz.rs`, or A23's anchor equivalents) and watch it fail on the
   **stable** toolchain with no sanitizer. If it does not reproduce there, the
   finding is in the harness, not the parser.
5. **Classify** — fuzzing.md §4 step 3: panic or allocation-budget violation
   ⇒ parser bug; round-trip violation ⇒ a *format* bug and therefore a
   format-freeze event (Q14/Q27), escalated rather than patched quietly.
6. **Retain** — fuzzing.md §4 step 4: either as a committed seed **added to
   the generator** (never dropped in by hand — `codec_fuzz.rs`'s drift check
   would reject it), or as a `testdata/tamper/` row under Q7 when it maps to a
   distinct rejection class. **For an A23 anchor crash the tamper row is
   Q18's**, and it must carry a distinct error code per the error-code
   contract.
7. **Record**: a line in the owning task's entry, and — new here, because
   this lane's whole failure mode is going unobserved — a dated line in
   `docs/ci-verification.md`.

The rule that makes this durable, stated so it is not optional: **a crash
that produces no committed regression case has produced nothing.** The
artifact is gitignored and the cache is transient; the fixture is the only
thing that survives.

### 9. The re-evaluation rule, with its exact trigger

D61 is **resolved**, not deferred: the OSS-Fuzz arm is *closed with a
condition attached*, so no wave inherits it as an open decision past its due
milestone.

> **D61 is re-read when, and only when, BOTH of the following hold:**
>
> **(a)** `aed900/antseal` is public — the Q65-gated flip. This also removes
> the constraint that produced this ruling, since standard GitHub-hosted
> runners are free on public repositories
> (docs.github.com, retrieved 2026-08-02T19:26Z: *"The use of standard
> GitHub-hosted runners is free: In public repositories"*), so the cadence
> and the §5 ceiling are both re-openable at that moment on their own merits.
>
> **(b)** the project can point to use by parties other than its maintainer,
> sufficient to argue OSS-Fuzz's own criterion — *"a significant user base
> and/or be critical to the global IT infrastructure"*.
>
> **(a) alone does not reopen the OSS-Fuzz arm.** It reopens only the budget
> half. Until **both** hold, OSS-Fuzz is *not applicable* rather than
> *pending*, and no wave may carry D61 as open on that account.

**Named owner of the trigger: Q65.** Its Accept gains one line — when Q65
resolves to "public", D61 is re-read in the same wave, and the re-read
records which of (a)/(b) hold. That is what makes this a rule with a
mechanism rather than a hope, and it is the same shape D52 used for its own
promote trigger.

### 10. Documentation corrections that land with the change

- **`docs/testing/fuzzing.md` §7** — replace the section body with the
  ruling and a pointer here. Its two present errors: *"due M3"* (TODO.md:573
  lists D61 among M2's nine gating decisions) and *"OSS-Fuzz requires a
  public repository … so it is gated on the same publication decisions as
  the release lane"* (Correction 4: public is necessary, not sufficient).
  Its four portability observations are **correct and stay** — targets are
  plain `libfuzzer-sys` binaries, seeds live under a stable path, run
  parameters are flags in `scripts/fuzz.sh`, and no target reads a corpus
  from disk itself. They are why option B was even evaluable, and they cost
  nothing to keep.
- **`docs/testing/fuzzing.md` §5** — the table's `required` column says
  `fuzz-smoke` is *"yes — branch-protection context"*. **No context is
  required on this repository**: branch protection returns 403 on both the
  classic API and rulesets on a private GitHub Free repo
  (`docs/ci-verification.md`, "Branch protection is BLOCKED BY PLAN",
  verified 2026-07-28; D52 E1). The cell should read
  `mount point — required once the plan allows it (D52 E1)`.
- **`docs/ci-verification.md`** — a dated section recording §1's
  measurement, and the cadence change, on the model of the existing
  `devnet-e2e-cron` section.

### 11. Tests that must exist, and what makes each fail

| test | where | what makes it fail |
| --- | --- | --- |
| `scripts/ci-lanes.sh fuzz-budget` (self-test arm) | `scripts/ci-lanes.sh` | Runs the computation against a planted 7-name `TARGETS` array and asserts **red**, then against the committed sources and asserts **green**. Fails if the checker cannot fail — the vacuity defect this project keeps finding. |
| `scripts/ci-lanes.sh fuzz-budget` (live arm) | same | Goes red the moment `targets × seconds × runs/month ÷ 60 + 15 × runs/month > 700`. Fails today, before the cadence change: **4 × 900 × 30.4 ÷ 60 = 1 824 > 700**. That red-before-green ordering is the proof the guard is wired to reality and not to the post-change numbers. |
| cron-parse arm | same | Given `"41 3 * * 1,4"` it must compute **8.67** runs/month and given `"41 3 * * *"` **30.33** — the script's own `52 × ndays ÷ 12` convention, which differs from this record's prose figure of 30.4 (365 ÷ 12) by 0.3 % and changes no verdict anywhere (1 820 vs 1 824; both are 2.6× the ceiling). Assert the script's numbers, not the prose's. Fails if the day-of-week field is ignored — which would make the guard read a daily lane as weekly and pass it, the single most damaging way this checker could be wrong. |
| cadence-floor arm | same | Fails if the cron's maximum gap between runs exceeds **5 days**, protecting E2's 7-day eviction margin independently of the minutes arithmetic. Without it, a future maintainer could satisfy the budget by going monthly and silently destroy the corpus accumulation. |
| `./scripts/fuzz.sh selftest` | existing, in both lanes | Unchanged and still mandatory before a green run is believed. |

## Rationale

**Why the register's lean survives in name and not in substance.** "Nightly
CI" is the right venue, and it was already built — so the entry's lean is not
wrong so much as answered before it was asked. What the entry did not
contain, and what determines whether the lane is an asset or a liability, is
that its committed configuration spends 91 % of the project's entire CI
allowance and that exhausting the allowance stops every required lane. A
sign-off on "nightly CI" would have ratified that configuration and, at
Q17, taken it to 137 %.

**Why not simply reduce the per-target seconds and keep it daily?** Because
under §5's own formula it does not work. At ~30.4 runs/month the per-run
overhead alone takes 15 × 30.4 = **456 of the 700 minutes**, leaving 244
minutes of fuzzing across six targets: `seconds` would have to fall to
**80 s — below `fuzz-smoke`'s own 90 s per-PR budget**. Even ignoring
overhead entirely it only reaches 230 s. A daily lane at that budget is not a
search; it is an expensive second copy of the regression run that already
happens on every PR. Fewer, longer runs also amortize the build: the per-run
overhead is paid once whether the run fuzzes for 10 minutes or 60, which is
precisely why the affordable arrangement is fewer runs of full length rather
than many runs of clipped length.

**Why twice weekly and not weekly** is E2, and it is the one thing that
distinguishes this lane from `devnet-e2e-cron`: the devnet lane has no state
to keep warm, this one's entire justification is state that GitHub deletes
after 7 days of no access.

**Why the ceiling is a script and not a sentence.** Every prior instance of
this failure mode in the project was a number recorded in prose that then
drifted — `docs/ci-verification.md`'s own three contradictory
"authoritative context set" sections are the canonical example, corrected at
its line 1013. A budget that Q17 can exceed without anything going red is the
same defect with money attached.

## Consequences for the blocked tasks

- **Q9 — implements** §2, §3, §4, §5, §7 and §10; its Accept row *"Nightly
  scheduled run exists with corpus caching; crash artifacts are uploaded on
  failure (demonstrated with a synthetic crash)"* is already satisfied by
  what shipped, and gains the observation duty of §1 and the guard of §5.
  Its "nightly" wording becomes "scheduled", with the cadence recorded.
- **Q17 — unblocked, with a hard obligation.** Adding two names to
  `TARGETS` is one line, and both lanes pick them up (§6); but the same PR
  must carry the `seconds` adjustment, because §5 turns red on the target
  addition alone. Its Accept row *"Both targets run in the required smoke
  lane and nightly schedule"* holds; "required" is the §10 wording defect.
- **A23 — unaffected** in substance: the targets it writes are ordinary
  `libfuzzer-sys` binaries and nothing in this record changes their shape.
  It gains the seed-directory obligation of §6.
- **Q65 — gains one Accept line** (§9): when it resolves to "public", D61 is
  re-read in the same wave.
- **Q18 — gains the crash-derived-row path** of §8 step 6 for A23 findings.
- **`docs/dependency-policy.md` §5 — untouched.** `cargo-fuzz =0.13.2` and
  the dated nightly pin stay exactly as they are; this record changes no
  version literal, so the three-place grep convention is unaffected.
- **Required-context set — unchanged at 19**, plus one if `fuzz-budget`
  lands as a `ci.yml` job. `fuzz-long` is not a PR context and never becomes
  one, so Q56's generated-context-list discipline is untouched by §2 and §3.
- `docs/decisions/README.md` — this decision's index row. **Applied 2026-08-11**, executing [D119](D119-decision-index-identity-and-the-index-row-sections.md) §5 step 4; the former `## Index row` section is demoted to this line under D119 RULING 4, and RULING 6 puts the row in the act that commits the record.

## Residual risks

1. **The lane's cost is still derived, not measured.** §1 fixes that, and the
   ruling is built so the measurement can only tighten it: the lower bound
   already exceeds the affordable share by 2.6×, so no plausible measured
   overhead reverses the direction. If §1's numbers land far below the bound
   — impossible unless libFuzzer is exiting early, which would itself be the
   finding — the cadence is re-openable on evidence.
2. **Twice weekly finds fewer bugs than daily.** True and accepted: ~522
   fuzzing minutes/month against ~1 824. The mitigation is not a promise but
   the structure the project already has — the same engine functions run in
   the ordinary suite on **every** build (`docs/testing/fuzzing.md` §1), the
   smoke lane runs every PR from the committed seeds, and the corpus
   accumulates across runs. The alternative is not "more fuzzing"; it is
   "no CI at all, in about three weeks".
3. **A crash can still sit unobserved for up to 4 days.** The lane pages
   nobody. §7's `::error::` annotation and §8's `docs/ci-verification.md`
   line make it visible to the next person who looks, which is the same
   posture `devnet-e2e-cron` and `advisory-cron` already carry, and no
   worse than the daily lane's *five* unobserved nights that Correction 1
   found.
4. **`FUZZ_BUDGET_CEILING_MINUTES = 700` is a judgement, not a measurement.**
   It is 35 % of the allowance, chosen against the known competing draws (19
   contexts including a 10× macOS lane on every push, a weekly cold-build
   devnet lane, a weekly advisory lane) without knowing their totals. §1's
   billing read is what turns it into an informed number; until then it is
   deliberately conservative, and it is raise-only by decision.
5. **The re-evaluation's condition (b) is a judgement call with no metric.**
   Deliberately: OSS-Fuzz's own criterion is a judgement call with no metric.
   What §9 guarantees is that the question gets asked at the right moment and
   by a named owner, not that it answers itself.
6. **Both scheduled lanes now depend on the maintainer reading Actions runs.**
   That is a standing process obligation with no machine backstop, and it is
   the general form of what Correction 1 found. Naming it is the honest
   limit of what a decision record can do here.

## Discovered-work candidates

- **Q81** — implement §2–§7 and §10: the cadence and budget change, the
  failure-classification step, the `fuzz-budget` lane with its self-test, and
  the `docs/ci-verification.md` measurement record.
- **Q82** — the documentation corrections of §10 taken on their own if Q81
  is split, plus Q65's one-line Accept addition (§9).
- **Q-domain, general** — Correction 1 is an instance of a class: scheduled
  lanes whose runs nobody reads. `advisory-cron`, `devnet-e2e-cron` and
  `fuzz-nightly` now all have this shape. A single "read the scheduled lanes"
  bookkeeping step would close it for all three; recorded as a candidate, not
  mandated, because it is process rather than code.

## Revisit triggers

- **Both conditions of §9 hold** — D61 is re-read, OSS-Fuzz becomes
  evaluable on its costs, and the minutes constraint disappears with the
  public flip.
- **Condition (a) alone holds** (repo goes public, still no users) — the
  budget half only: cadence and the §5 ceiling are re-openable because
  standard runners are then free; the OSS-Fuzz arm stays closed.
- **The plan moves to GitHub Pro** — 3 000 minutes/month and enforceable
  required contexts; the §5 ceiling is recomputed against the new allowance
  and the cadence may go back up. Note this is the same plan change that
  unblocks branch protection (D52 E1), so it arrives with its own wave.
- **§1's measurement shows a per-run overhead far from 15 minutes, in either
  direction** — the `PER_RUN_OVERHEAD_MINUTES` constant moves and `seconds`
  moves with it; the ceiling does not. *(Corrected 2026-08-02 at
  implementation: this read "far **above** 15 minutes", which is one-sided and
  would have left the measured case unhandled. Q81 measured the five runs at
  ~61.9 min wall clock against 60 min of fuzzing — **1.9 min of overhead, not
  15**. The constant was deliberately **left at 15**, because over-estimating
  the bill is the safe direction for a ceiling whose breach stops every
  workflow in the repository; the trigger is recorded here so that choice is a
  decision rather than an oversight. Note the measurement also moved the
  **real** bill of the replaced configuration to ~1 877 min/month = **94 %** of
  the allowance, above §1's 91 % lower bound.)*
- **A seventh fuzz target is proposed** — §5 goes red by construction, which
  is the trigger firing correctly rather than a problem.
