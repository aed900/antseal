# D135 — R86's job shape and its tier: the two-ENVIRONMENT build comparison, gated at the deploy

- **Status: RESOLVED. The tier (b) is CONFIRMED — and the brief's description of
  arm (b) is OVERTURNED at its premise, on a measured log.** The brief asks for
  *"a second build inside the existing `pages.yml` job"*. **That second build has
  been in `pages.yml` since `9317a35` and it is worthless as reproducibility
  evidence.** R83's `stale_guard` calls `scripts/wasm-pack-build.sh --build-only`
  and byte-compares the result, so the deploy already builds the module twice
  and already fails naming both digests. Measured in run **31873422229**
  (2026-08-15): build 1 finished `08:02:25.290` at 1 853 031 B; build 2 ran
  `08:02:35.912 → 08:02:36.726` — **0.81 s wall, and cargo's own line is
  `Finished \`release\` profile [optimized] target(s) in 0.14s`.** Not one crate
  was recompiled. What that green asserts is that `wasm-bindgen` is a function
  of its input; it does not touch rustc, and R86's `Do` already names that
  non-property (*"a second build under identical conditions asserts only that
  `rustc` is deterministic … which is not the property at risk"*). **So the
  missing thing is not a second build. It is a second ENVIRONMENT**, and this
  decision rules a **third** build carrying the two axes, kept separate from
  R83's guard so the two reds cannot be confused.
- **The brief's second premise is also overturned, and this one moves the
  arithmetic.** The brief says the account is on **GitHub Pro** with a
  3 000-minute allowance. This tree says otherwise in three committed places —
  `docs/ci-verification.md:1184` (*"a **private repository on GitHub Free**"*,
  measured by a branch-protection 403 quoted verbatim at line 1177),
  `docs/ci-verification.md:1684`/`1888`, and
  `scripts/ci-lanes.sh:1169`'s `FUZZ_BUDGET_ALLOWANCE_MINUTES=2000`. Probed
  today, `GET /repos/aed900/antseal/branches/main/protection` returns **404
  "Branch not protected"**, not the recorded 403, which is consistent with an
  upgrade having happened since — so the brief is probably right and **the tree
  is stale**. It cannot be settled from here: the billing endpoint needs the
  `user` token scope this token does not carry (404 + `gh` says so), exactly as
  `docs/ci-verification.md:1697` already records. **This document prices against
  both numbers and rules against the worse one.**
- **The measurement that decides the tier, and which nobody in this tree had
  ever taken.** The only Actions-bill figure on record is **one lane's**
  (`docs/ci-verification.md:1348`, the fuzz lane at ~1 877 min/month). The
  whole-repository bill has never been measured. It is, for
  **2026-08-01 → 2026-08-15 inclusive, 538 dispatched jobs, per-job minutes
  rounded up and platform multipliers applied: 3 154 weighted minutes.** That is
  **158 %** of 2 000 and **105 %** of 3 000, **with 16 days of the month left**.
  Three runs in that same window contain **45 jobs that executed ZERO steps** —
  the dispatch-refusal signature `docs/ci-verification.md` diagnoses as an
  exhausted allowance. **There is no headroom to spend.** Every push-tier arm is
  refused on that number, not on plausibility.
  *(Correction WITHDRAWN, orchestrator, 2026-08-16. An earlier note here claimed
  this record's "never assigned a runner" was one word wrong because the 45 jobs
  carry `started_at`/`completed_at` stamps. **That claim was itself wrong, and it
  was wrong by measuring the wrong field.** Re-measured against `runner_name`:
  all 45 — `ci#31407751482` 19/19, `ci#31412086640` 19/19, `ci#31117310646` 7/19
  — have **`runner_name: ""`**. Both facts hold at once: a refused job is given
  timestamps 3–12 s apart, is given **no runner**, and executes **zero steps**.
  This record was right; the correction was the defect, and it is left here
  struck rather than deleted because the failure mode it demonstrates — querying
  `started_at` for a question about runner assignment and reporting the answer
  as a correction to someone else's work — is worth more as a record than a
  clean page. The independent bill re-measurement stands: **3 324** weighted
  minutes, within 5 % of the 3 154 above.)*

  **CONFIRMED IN PRODUCTION, 2026-08-16, by the very next push.** This record's
  *"there is no headroom to spend"* stopped being a projection at 11:08 UTC.
  The wave-21 push (`b253ae8`) triggered `ci` **`31943527193`**: **19 of 19 jobs,
  `steps == []`, `runner_name: ""`, whole run 11:08:35Z → 11:08:42Z (7 s)**. The
  maintainer-authorised Q19 witnessing dispatch that followed,
  `verifier-page` **`31943600047`**, was refused identically: **1 of 1 job, zero
  steps, no runner, 11:10:13Z → 11:10:18Z (5 s)**. Both workflow files parse
  (checked), so this is not syntax. **The allowance is exhausted.** Two
  consequences are already discharged: the **second** authorised dispatch was
  **not** spent, because a refused run costs the same minutes and proves
  nothing; and Q19 remains open owing a venue that cannot be bought this month.
  This is also the first time the refusal has been observed **prospectively** —
  every prior instance in `docs/ci-verification.md` was diagnosed after the
  fact.*
- **The lean survives on a mechanism, and the mechanism is step order**, not
  goodwill: `pages.yml` runs `./scripts/pages-publish.sh --build` **before**
  `actions/configure-pages`, `upload-pages-artifact` and `deploy-pages`, so a
  red comparison aborts the job with nothing uploaded. *A deploy cannot publish
  a digest two builds disagree on* is a property of the file as committed.
- **Price: +1 to +2 billed weighted minutes per deploy** (job wall 110 s → an
  estimated 170–200 s; billed 2 min → 3–4 min), **≤ 7 weighted minutes per
  month** at the measured cadence of 2 deploys in 19 days, and **zero in a month
  with no deploy**. Against 3 154 spent, that is 0.2 %.
- **R86's own Accept row 3 is CORRECTED.** It asks for *"the remap flag removed
  from one of the two builds"* as the planted regression. Measured against the
  code: `scripts/wasm-pack-build.sh`'s `check_build_paths` scans every built
  artifact for `$repo`, `$CARGO_HOME`, `/home/`, `/Users/` and `/root/`, and it
  runs in **both** `--check` and `--build-only` before either returns. Removing
  the remap therefore reds at the **path scan**, upstream, with the path-scan
  message — the comparison is never reached and is never shown to be fallible.
  **That plant proves the wrong check.** §7 rules the plant that works, and it
  is already demonstrated by this repository's own history.
- **Date: 2026-08-15** (M3 close-out planning round, D135 lane; briefed to
  overturn the register's lean rather than confirm it. Every figure was taken in
  this working tree or read from this repository's own Actions history that day
  via read-only `gh` queries. **Nothing was dispatched — this lane spent no
  Actions minute.**)
- **Owning task: R86.** Consumers: **R25** (Accept row 1, whose second clause
  this closes at deploy tier), **Q237** (the M3 gate's machine-naming
  constraint), **Q238** (the promotion to push tier, minted 2026-08-16 on the
  maintainer's instruction and gated on §3 R6's measured precondition).
  Adjacent and untouched: **R83** (the local path scan and the stale-artifact
  guard, which this must not duplicate), **Q19/D136** (the other dispatch-only
  page lane).
- Supersedes nothing. Cites D63 §5 R5 / §7 rules 1–2, D129 §5 R9, D131 §5 R4,
  D62 §3 R2, D61 (the budget model and its constants), Q43, R83, R25, R86.

---

## 1. What was measured

Every figure below was taken in this tree or against this repository's API
today, 2026-08-15, read-only. Where a number is taken on report it says so.

### 1.1 The bill, whole-repository, for the first half of this month

`gh run list` returns **50 runs total** — the complete history; the repository
was created `2026-07-27T20:59:42Z`. For every run created on or after
2026-08-01, every job's `started_at`/`completed_at` was fetched and each job's
duration rounded **up** to the whole minute (how GitHub bills), then multiplied
by its platform factor (Linux ×1, Windows ×2, macOS ×10). Jobs with an empty
`runner_name` were excluded — they were never dispatched and billed nothing.

| workflow | weighted billed minutes, 2026-08-01 → 08-15 |
| --- | --- |
| `ci` (30 push runs) | 2 787 |
| `fuzz-nightly` (8 runs) | 500 |
| `devnet-e2e-cron` (1 run) | 24 |
| `pages` (2 dispatches) | 11 |
| `advisory-cron` (2 runs) | 2 |
| **total, 538 dispatched jobs** | **3 154** |

- vs a **2 000**-minute allowance: **158 % used, −1 154 minutes**, 16 days left.
- vs a **3 000**-minute allowance: **105 % used, −154 minutes**, 16 days left.

Summed on exact durations without the per-job round-up the figure is **2 821.8**
weighted minutes; that is a strict **lower bound**, because GitHub bills whole
minutes per job and this repository runs 583 jobs a fortnight.

**Corroboration that the allowance is genuinely binding, from the same window.**
Runs `31412086640` (19 jobs), `31407751482` (19 jobs) and `31117310646`
(7 jobs) contain **45 jobs that executed ZERO steps**.
*(Orchestrator, 2026-08-16: independently reproduced — 45, across exactly those
three runs, at those per-run splits. An earlier version of this note also
"corrected" the description away from "never assigned a runner"; **that
correction is withdrawn and was wrong.** It rested on `started_at`/
`completed_at` being populated, which is true and answers a different question.
Re-measured against the field that actually carries the claim: **all 45 have
`runner_name: ""`**. A refused job is stamped, unassigned, and stepless, all
three at once — so this record's original wording was accurate and the grep-able
signature is either `runner_name == ""` or `steps == []`.)*
**Prospective confirmation, 2026-08-16.** The wave-21 push produced `ci`
**`31943527193`** — 19/19 jobs, `steps == []`, `runner_name: ""`, 7 s wall — and
the Q19 dispatch `verifier-page` **`31943600047`** — 1/1, same shape, 5 s. Both
workflow files parse, so it is not syntax. **The allowance predicted here as
exhausted was exhausted, on the next push after this record was written.**
`docs/ci-verification.md` (the section on `1c702d4`) already diagnoses that
signature, reproduced twice 44 minutes apart, as *"an exhausted minute allowance
or a reached spending limit"*, and records that the failure mode is not a
degraded lane but **every workflow in the repository refusing to dispatch,
including all 19 required contexts**. This has already happened to this
repository, twice, this month.

### 1.2 What a push costs

Three `ci` push runs, per-job, exact durations:

| run | jobs | raw min | weighted min |
| --- | --- | --- | --- |
| `31873411737` (2026-08-15, `9317a35`) | 19 | **67.00** | **83.70** |
| `31845958842` (2026-08-14, `08c074c`) | 19 | 67.28 | 84.75 |
| `31627097358` (2026-08-12, `fbf70e4`) | 19 | 66.57 | 95.12 |

The brief's figures for `31873411737` are **confirmed exactly**: 19 jobs, 67.00
raw, 83.70 weighted, `test` alone **31.97 min**, `cross-os-macos` 1.32 × 10 =
**13.17**, `cross-os-windows` 4.85 × 2 = **9.70**.

Push cadence, from the complete history: **34 push-`ci` runs over 20 calendar
days = 1.70/day ≈ 51.7 runs/month**. It is bursty (8 on 08-06, 7 on 08-10, 1 on
each of 08-12/14/15) and those bursts are red-chasing days.

### 1.3 The timing endpoint is not a probe

`gh api repos/aed900/antseal/actions/runs/<id>/timing` returns
`"total_ms": 0` and `"duration_ms": 0` for **every job of every run tested**
(`31873411737`, `31873422229`, `31847839638`) while correctly reporting
`run_duration_ms` and the job counts (17 UBUNTU + 1 MACOS + 1 WINDOWS). This
reproduces the finding already recorded at `docs/ci-verification.md:1691`.
**Weighted job wall-clock is the only consumption proxy available from this
checkout**, and every minute figure in this document is that proxy, not a
billing statement.

### 1.4 The `pages` job, decomposed

| | `31847839638` (08-14, `08c074c`) | `31873422229` (08-15, `9317a35`) |
| --- | --- | --- |
| run wall | 8.4 min (504 000 ms) | 1.8 min (110 000 ms) |
| runner | `GitHub Actions 1000000669` | `GitHub Actions 1000000689` |
| `Swatinem/rust-cache@v2` restore | 2 s (**miss**) | 17 s (**full match**, 289 MB) |
| `build and check the page` | **452 s** | **55 s** |
| — `cargo install wasm-bindgen-cli 0.2.126` | 184 s (`3m 04s` compile) | skipped (binary from cache) |
| — `cargo install wasm-pack 0.15.0` | 151 s (`2m 30s` compile) | skipped (binary from cache) |
| — wasm32 release build, build 1 | **70 s** (`Finished … in 1m 07s`) | **≈43 s** (`Finished … in 40.86s`) |
| — corpus emit + boundary (native) | 45 s | 10 s |
| — build 2 (R83 `stale_guard`) | *(guard not yet landed)* | **0.81 s** (`Finished … in 0.14s`) |
| — package + re-injection check | <1 s | <1 s |
| cache save | 14 s | 0 s |
| module | 1 853 735 B, **no remap** | 1 853 031 B, remapped |

**Why 8.4 → 1.8: `Swatinem/rust-cache@v2`, and specifically its binary cache.**
335 of the cold run's 452 s are the two `cargo install`s. The action's v2 default
caches `~/.cargo/bin` alongside the registry, so the warm run skipped both. It
did **not** deliver a warm wasm32 `target/`: the warm log recompiles the entire
dependency graph (`zeroize`, `subtle`, `curve25519-dalek`, …) and takes 40.86 s
to do it. The cache being restored is `~/.cargo`, not the build.

**Two hosted runners, identical environment.** The two runs above are different
VMs, nine hours apart. Both compile from `/home/runner/work/antseal/antseal`
and both install into `/home/runner/.cargo/bin`; the warm run prints its remap
line verbatim:

```
remap: --remap-path-prefix=/home/runner/.cargo/registry=/cargo/registry --remap-path-prefix=/home/runner/work/antseal/antseal=/antseal
```

Every `ubuntu-latest` runner uses those two paths. This is the measurement §4
turns on.

### 1.5 The commit stamp moves the module's bytes and not its length

`08c074c` and `9317a35` produce modules of **identical size, 1 853 031 B, with
different digests** — `baee3fc9125a04429232dcb8510985b570bb682f81cc1f54ef54f8dab54522a3`
(R25's six local reproductions) and `70235b8b6192b983…` (run 31873422229's
`module unchanged by the rebuild` line). Measured cause:
`git diff --name-only 08c074c..9317a35 -- crates/antseal-core/src crates/antseal-wasm Cargo.lock Cargo.toml .cargo rust-toolchain.toml`
is **empty**. Not one compile input changed. The only differing input is
`ANTSEAL_SOURCE_COMMIT`, a 40-character hex string that
`crates/antseal-wasm/build.rs` validates and stamps through
`cargo::rustc-env`, landing in `build_info.rs`'s
`pub const SOURCE_COMMIT: &str = env!("ANTSEAL_SOURCE_COMMIT")` and thence into
the module's data section — with `cargo::rerun-if-env-changed` forcing the
recompile. §7 builds the plant on this.

### 1.6 The path-filter hit rate

For each consecutive pair of push-`ci` head SHAs, the pushed range was diffed:
**33 resolvable ranges**, of which a narrow filter over
`crates/antseal-core/src/**`, `crates/antseal-wasm/**`, `Cargo.toml`,
`Cargo.lock`, `.cargo/config.toml`, `rust-toolchain.toml` and
`scripts/wasm-pack-build.sh` matches **17 (52 %)**; a broad filter over
`crates/**` plus the same files matches **20 (61 %)**. At commit granularity,
306 of 528 commits on `main` (58 %) touch the broad set. §10 prices the arm this
enables.

### 1.7 Things the brief got right, verified

`19 jobs / 67.0 raw / 83.7 weighted`; `macOS ×10 on 1.3 min = 13.2`;
`Windows ×2 on 4.8 min = 9.7`; `test` = 32 min; `pages` 8.4 cold / 1.8 warm;
timing API 0 billable ms; the repository is **private** (`"private": true`);
the two load-bearing axes are the checkout path and `$CARGO_HOME`.

---

## 2. The lean, dismantled — then re-assembled on a different mechanism

**Arm (b) as briefed is a no-op.** `pages.yml` calls
`scripts/pages-publish.sh --build`, which calls `wasm-pack-build.sh --check`
(build 1) and then `verifier-page-build.sh --check`, whose `stale_guard` calls
`wasm-pack-build.sh --build-only` (build 2) and byte-compares:

```
==> rebuild the module, so the packaged bytes are the tree's (R83)
    Finished `release` profile [optimized] target(s) in 0.14s
  module unchanged by the rebuild: 70235b8b6192b983…
```

Two builds, one digest comparison, a failure message printing `was:` and `is:`.
Everything R86's Accept row 1 asks for **except the one thing that makes it
mean anything**. The 0.14 s is the tell: cargo's fingerprints all hit, so rustc
never ran. The comparison's subject was `wasm-bindgen` re-emitting glue from a
`.wasm` cargo did not rebuild.

**And it must stay that way.** R83's guard has a different job — *the packaged
bytes are this tree's* — and its correctness depends on the second build being
**identical** in every respect except the state of `target/`. Varying the
environment inside it would make one red mean either staleness or
irreproducibility, which R86's Accept row 4 forbids. So the reproducibility
comparison is a **third** build, with its own script, its own message and its
own self-test.

**What survives of the lean.** The *tier* — deploy-gated — survives, and it
survives on step order rather than on discipline. In `pages.yml` the build step
precedes `configure-pages`, `upload-pages-artifact` and `deploy-pages`; a
non-zero exit there ends the job before any artifact is staged. The claim *"a
deploy cannot publish a digest two builds disagree on"* is therefore a property
of the committed file, not an aspiration.

---

## 3. The ruling — the tier

- **R1 — TIER: deploy-gated.** The two-environment comparison runs **inside
  `pages.yml`'s existing `publish` job**, invoked from
  `scripts/pages-publish.sh --build`, positioned so a red aborts before
  `actions/configure-pages`. It is **not** a required status context, **not** a
  new job in `ci`, and **not** a `workflow_dispatch`-only lane.
- **R2 — Its measured price.** +1 to +2 **billed** weighted minutes per deploy.
  The job billed 2 minutes warm (110 s) and 9 cold (504 s); the addition is an
  estimated 55–90 s (§5 R3 bounds it), taking the warm job to 170–200 s → 3–4
  billed minutes. At the measured cadence (2 dispatches in 19 days ≈ 3.2/month)
  that is **≤ 7 weighted minutes per month**, and **0 in a month with no
  deploy**, against a measured spend of 3 154 in a fortnight.
- **R3 — What it enforces.** That the module and the glue this repository ships
  are byte-identical when built twice at one commit under two different
  **checkout paths** and two different **`$CARGO_HOME`s**, and that the digest
  the page publishes about itself is therefore reproducible by a reader whose
  machine is not this one.
- **R4 — What it does NOT enforce, stated so no row may assume it.**
  1. **Nothing between deploys.** A commit that breaks reproducibility is
     detected at the next deploy, not at the push that broke it. Measured
     exposure: the only two deploys on record are 9 hours apart, but the whole
     19-day history contains only those two, so a break can plausibly sit on
     `main` for **days to weeks**.
  2. **One runner, one image.** Only the two path axes vary. Locale, `TZ`,
     `HOME`, user, hostname, CPU, kernel, rustc build, `wasm-bindgen` build and
     filesystem are shared. **D63 §7 rule 2's list stays only partly
     discharged**, exactly as R86's own `Notes` warn, and the six local
     reproductions share the same limitation.
  3. **The signed release path is not covered.** Q30/Q31 (M4) publish
     `SHA256SUMS` and a pre-packaging `antseal_wasm_bg.wasm` as **release**
     artifacts. A release cut without a deploy bypasses this gate entirely. §13
     routes that.
  4. **It says nothing about any other commit.** Byte-identity is asserted at
     one commit and is not transitive (R86 `Notes`).
- **R5 — Why that residue is acceptable, argued rather than assumed.** The
  footer digest and `SHA256SUMS` are claims **about the world only once they are
  served**. D63 §5 R2's number and D63 §5 R4's manifest come into existence for
  a third party at deploy time and at no other moment; before then nobody has
  been invited to reproduce anything. The gate therefore sits exactly on the
  boundary where the claim is made. Its residue is **late discovery** — a
  blocked deploy instead of a blocked push — and **not** a false published
  claim. That is the whole of the trade, and it is the reason a cheaper tier is
  not merely cheaper but correctly placed.
- **R6 — Raise-only by decision.** Promoting this to push tier is a decision,
  never an implementer's convenience, on the same terms as
  `FUZZ_BUDGET_CEILING_MINUTES` (`scripts/ci-lanes.sh:1162–1164`: *"RAISE-ONLY BY
  DECISION, never by an implementer needing a build to go green"*). Its
  precondition is a **measured** monthly bill under the allowance, taken the way
  §1.1 takes it. §10 R2 pre-prices the arm to promote it to, so that decision
  does not have to re-derive the arithmetic.

---

## 4. What varies between the two builds — and the word "runners" is wrong

- **R1 — Exactly two axes, and both must differ in content AND length.** Build B
  runs from a checkout path and with a `$CARGO_HOME` that differ from build A's
  in both the characters and the number of them. Content alone is not enough:
  the measured defect was a **192-byte** size delta produced by 52 occurrences
  of a path of different length, and a same-length substitution would exercise
  the remap without exercising the size arithmetic that made the original defect
  visible. R25's discharged pair (25 vs 122 characters) is the precedent.
- **R2 — One runner, deliberately, and this is STRONGER than two.** On
  GitHub-hosted runners every `ubuntu-latest` job checks out to
  `/home/runner/work/antseal/antseal` and installs to `/home/runner/.cargo`.
  Measured §1.4: two different runner VMs nine hours apart, identical paths,
  identical `$CARGO_HOME`. **Two hosted runners of the same label vary the
  hardware and hold both load-bearing axes constant** — which is precisely the
  configuration R86 calls *"a second build under identical conditions"*. Two
  environments on one runner vary the axes that were measured to move the bytes.
  The stronger test is the one on a single runner.
- **R3 — R25's Accept row 1 is RE-WORDED on the record.** *"Two clean CI builds
  (different runners) produce byte-identical artifacts"* asks for the weaker
  property. It is replaced by: **"Two clean CI builds under different
  environments — differing checkout path and differing `$CARGO_HOME` — produce
  byte-identical module and glue; a CI job enforces this."** The historical
  two-runner comparison that found the defect worked *because* the two runners
  happened to have different `$CARGO_HOME`s (`/home/runner/.cargo` against
  `/home/deb/.cargo`), i.e. the environment axis did the work and the runner
  identity did none. The registrar records this at R25's Accept row 1 and at
  R86, citing `D135 §4 R3`.
- **R4 — The axes must be ASSERTED to differ, before the comparison runs.** The
  harness fails, with its own message, if either `path_A == path_B` or
  `CARGO_HOME_A == CARGO_HOME_B`, or if either directory does not exist. A
  comparison whose two environments are equal is green for the wrong reason and
  is this project's dominant defect class; it must be structurally impossible,
  not merely unlikely.
- **R5 — Symlinking the second `$CARGO_HOME` is FORBIDDEN and asserted against.**
  `remap_flags()` in `scripts/wasm-pack-build.sh` calls
  `remap_add "$(readlink -f "$registry")" /cargo/registry` — it remaps the
  physically resolved path too. A build-B `$CARGO_HOME` that is a symlink into
  build A's therefore gets **both** forms remapped, the axis contributes
  nothing, and the comparison passes while testing nothing. The harness asserts
  `readlink -f` of the two registry roots differ.
- **R6 — Build B's sources are a verified copy of build A's.** Copy the working
  tree excluding `/target` (e.g. `rsync -a --exclude=/target ./ "$B"/`), then
  assert a `sha256` manifest of the tracked-and-untracked source set is
  identical on both sides. Without that assertion, a copy that silently dropped
  a file is indistinguishable from a copy that did not, and R83's lesson is
  exactly that a plausible-looking artifact passes every assertion that never
  looked at the sources. A `git archive` export is **refused**: it cannot see an
  uncommitted edit, which is the state a developer running the local half is
  actually in (R83's refused arm (c), same reasoning).
- **R7 — `ANTSEAL_SOURCE_COMMIT` is PINNED and passed identically to both
  builds.** Measured §1.5: that one 40-character string moves the module's bytes
  without moving its size. Build B's copy of the tree has no `.git`, so
  `scripts/wasm-pack-build.sh`'s `git rev-parse HEAD` would stamp `unknown` and
  the comparison would go **red on a correct build**. The harness resolves the
  commit once and exports it to both. This is not a hypothetical: it is the
  first bug a naive implementation will ship, and §7 R1 turns it into the plant.

---

## 5. Caching

- **R1 — Build A may use the job's cache; build B may not use any cache keyed
  across commits.** `pages.yml`'s `Swatinem/rust-cache@v2` is what turns 8.4
  minutes into 1.8 (measured §1.4: 335 s of `cargo install` skipped, `~/.cargo`
  restored at 289 MB, full key match). Build A keeps it. Build B gets a fresh
  `$CARGO_HOME` **by construction** — that is its axis — so it cannot restore
  that cache even if asked, and no second cache action may be added for it.
  R86's `Notes` are right that a job caching across commits would assert the
  wrong thing; here the axis enforces the rule rather than a policy doing it.
- **R2 — `target/` is never shared between the two builds.** Build B builds into
  its own tree, under its own path. `scripts/wasm-pack-build.sh` already does
  `rm -rf "$OUT"` before invoking wasm-pack; that covers the packaged output,
  not `target/wasm32-unknown-unknown/release`, and B's separate checkout is what
  keeps the compile caches disjoint.
- **R3 — The registry may be COPIED into build B's `$CARGO_HOME`, and this is
  the price bound.** The axis under test is the **path** of `$CARGO_HOME`, not
  the provenance of the crates in it, so `cp -a` from A's registry to B's is
  legitimate, keeps the axis intact (R4 R5 forbids the symlink shortcut that
  would not), and stays inside D63 §5 R5's no-network fence. Measured bounds for
  build B's compile: **40.86 s** with a populated registry, **70 s** with an
  empty one including the download. With the copy, expect ~40–55 s of compile
  plus ~10 s of copy: **55–90 s total**, which is R3 R2's price.
- **R4 — Build A's rust-cache key must not be perturbed.** The new step runs
  after build A and before packaging; it must not write into `~/.cargo` or
  `./target`, or the post-job cache save will store a tree contaminated by the
  second environment and the next deploy will restore it.

---

## 6. The failure surface

- **R1 — The message names both digests, both files and both environments.**
  Shape, in `scripts/wasm-pack-build.sh`'s and R83's idiom (`::error::` prefix,
  a distinct leading token, indented detail):

  ```
  ::error::reproducible-build: NOT REPRODUCIBLE — two builds of this commit under different
    environments produced different bytes. The footer digest and SHA256SUMS this deploy would
    publish describe bytes only one of these two machines produces (R25 Accept row 1, as re-worded
    by D135 §4 R3; D63 §7 rule 1).
      commit:   <40 hex, identical by construction — D135 §4 R7>
      build A:  path=/home/runner/work/antseal/antseal              CARGO_HOME=/home/runner/.cargo
      build B:  path=<second path>                                  CARGO_HOME=<second cargo home>
      antseal_wasm_bg.wasm   A <64 hex> (<n> B)   B <64 hex> (<m> B)   DIFFER
      antseal_wasm.js        A <64 hex> (<n> B)   B <64 hex> (<m> B)   same
    First differing byte offset: <k>.  Nothing was uploaded and no deploy was attempted.
  ```

- **R2 — Both files, always.** R86 Accept row 1 requires the module **and** the
  glue. Every line is printed on a red, with `DIFFER`/`same` per file, so a
  reader learns immediately whether the divergence is in cargo's output or in
  `wasm-bindgen`'s.
- **R3 — A GREEN must print both environments and the shared digest.** A green
  that does not show the two environments is indistinguishable from a green that
  compared a build with itself, which is the failure this whole decision exists
  to end:

  ```
    reproducible across environments: antseal_wasm_bg.wasm <64 hex> (1853031 B), antseal_wasm.js <64 hex>
      A path=… CARGO_HOME=…
      B path=… CARGO_HOME=…   (lengths differ by <d> and <e> characters)
  ```

- **R4 — `NOT REPRODUCIBLE` is a reserved leading token** and appears nowhere
  else in the repository, so §8's message-matching is exact and cannot drift
  onto another guard's red.
- **R5 — No secret material and no absolute path of the maintainer's machine
  ever reaches a published log.** The two paths printed are the CI job's own
  temporary directories. When the harness is run locally the same lines print
  local paths, and that is a local log, not an artifact.

---

## 7. The planted regression

- **R1 — The plant is a DIFFERING `ANTSEAL_SOURCE_COMMIT`, not a removed remap
  flag.** R86's Accept row 3 names the remap flag; measured against the code,
  that plant reds upstream at `check_build_paths`, which runs in both `--check`
  and `--build-only` and scans for `$repo`, `$CARGO_HOME`, `/home/`, `/Users/`
  and `/root/` — and an un-remapped build on any of these machines carries
  `/home/<user>/.cargo/registry` 52 times (measured at `08c074c`: 1 853 735 B on
  the runner against 1 853 543 B here). The comparison would never be reached
  and would never be shown to be fallible. **The commit-stamp plant is the right
  one** and §1.5 already proves it works in this repository: same size, different
  digest, zero compile-input changes, path scan green throughout.
- **R2 — Two cheap self-test arms run on every invocation, locally and in the
  job, and cost milliseconds.** Arm 1 hands the comparator two fabricated files
  differing in one byte and requires the red to carry `NOT REPRODUCIBLE` and to
  print **both** 64-hex digests and both sizes. Arm 2 hands it two identical
  environments and requires the axis guard (§4 R4) to refuse. Neither builds
  anything. This is the house `--self-test`-then-lane pair
  (`scripts/local-gate.sh:517–518` is the precedent for the page lanes) and it
  is what makes the guard's green mean something on a run that never goes red.
- **R3 — The expensive plant runs LOCALLY, once, and is recorded — never on a
  metered runner.** A `--plant-commit` arm re-runs build B with the last hex
  character of the commit changed, requiring a red naming both digests. It costs
  one wasm32-release rebuild on the maintainer's machine (measured elsewhere in
  this tree at tens of seconds) and **zero CI minutes**. Its output is captured
  into R86's row.
- **R4 — Verified by message, not by exit code.** Every arm greps the captured
  output for its own token; a non-zero exit alone is refused as evidence,
  because a crash exits non-zero too. Where a pipeline is used, `PIPESTATUS[0]`
  is read, not `$?`.
- **R5 — The comparator is a committed script under `scripts/`, never a `run:`
  block.** Q43, enforced by `scripts/check-ci-shell.py`, which globs **every**
  `*.yml` under `.github/workflows/` (line 52) and is therefore already
  authoritative over any new workflow. *(Noted in passing: `ci.yml`'s header
  says the check runs "across ALL THREE workflows" and there are now six files;
  the code is right and the comment is stale.)*

---

## 8. How this is not R83's scan, and how a reader tells three reds apart

- **R1 — Three properties, three tokens, one fixed order.** The order matters:
  the first two run on **every** build, so a fault they own can never surface as
  the third's red.

  | # | guard | property | red token | venue |
  | --- | --- | --- | --- | --- |
  | 1 | `check_build_paths` (R22/R25) | **no builder path reached this artifact** | `embeds the building machine's path` | every build, `--check` and `--build-only` |
  | 2 | `stale_guard` (R83) | **the packaged bytes are this tree's** — a rebuild under *identical* conditions changed nothing | `STALE ARTIFACT` | `verifier-page-build.sh` |
  | 3 | this decision | **two environments agree** — the published digest is reproducible off this machine | `NOT REPRODUCIBLE` | `pages-publish.sh --build`, deploy only |

- **R2 — Guard 1 is the necessary condition, guard 3 is the sufficient one.** A
  clean path scan says no *known* environment channel leaked; only a comparison
  says no *unknown* one did. Neither subsumes the other, and R86 Accept row 4 is
  satisfied by the token table above rather than by prose.
- **R3 — No guard may be made to carry another's message.** In particular
  `stale_guard` keeps its identical-environment rebuild (§2), because the moment
  its two builds differ in environment its own red becomes ambiguous.

---

## 9. R25's Accept row 1 — what closes and what survives

- **R1 — Accept row 1 may cite this job by name and CLOSE, once §11's remote
  execution exists.** Its first clause is already met by the six reproductions
  at `08c074c`; its second clause — *"CI job enforces this"* — is met by the
  comparison ruled here, at the deploy tier, with §3 R4's residue stated in the
  row rather than assumed away. The row must name the tier, not merely the
  script, so no later reader believes it fires on push.
- **R2 — The wording residue is real and is recorded, not waived.** R25 Accept
  row 1 says *"different runners"*; the job delivers *different environments on
  one runner*, which §4 R2 measures to be the stronger property. The row's text
  is re-worded per §4 R3 and the re-wording cites `D135 §4 R3`. **A row whose
  words were left alone and quietly read as satisfied would be the defect R86
  was minted for, one level out.**
- **R3 — What survives R25 and is NOT closed by this decision.**
  1. **Accept row 3** — the advice-line drift test (D63 §5 R6 / §7 rule 5, routed
     by D131 §9.2 into `crates/antseal-wasm/tests/page_template.rs`) still does
     not exist. Untouched here.
  2. **Accept row 2** — `SHA256SUMS` handed to Q's signing step is Q30/Q31, M4.
  3. **D63 §7 rule 2's environment list** — timestamps, filenames, locale,
     `$HOME` — is only partly discharged (§3 R4 item 2). It is recorded at R86's
     row as the named residue of this instrument, so a later reader cannot cite
     a green comparison as covering it.
  4. **The `wasm-opt`/binaryen pin.** `--no-opt --mode no-install` keeps the
     optimizer out of the build path today; re-enabling it needs a pinned
     binaryen first, and that is R25/F29's, not this decision's.

---

## 10. Refused arms, each priced on the same measurements

- **R1 — (a) A required context on every push: REFUSED, ~155 weighted minutes a
  month, against 0 available.** Components, all measured in §1.4: checkout 3 s +
  rustup 12 s + cache restore 17 s + build A ≈43 s + registry copy ≈10 s +
  build B ≈55 s + compare ≈1 s + cache save 14 s ≈ **155 s → 3 billed minutes**,
  plus a first run paying the 335 s of `cargo install` into a new cache key
  (≈9 min). At 51.7 push runs/month that is **~155 weighted min/month**. It also
  costs something the minutes do not show: `ci.yml`'s header makes every job
  name *"a (future) required status context for branch protection"*, and this
  project treats a branch-protection change as **an external action requiring
  express consent** (the Q13/Q37 note in the same header). Refused on the
  measurement in §1.1, not on taste.
- **R2 — (d) A separate `on: push` workflow with a `paths:` filter: REFUSED
  TODAY, and PRE-PRICED as the arm to promote to.** This is the arm the brief
  did not list and it is the best push-tier shape available: a workflow-level
  `paths:` filter is evaluated by GitHub **before any runner is assigned**, so
  a push that touches no build input costs **zero minutes** — unlike a job-level
  `if:`, which still bills its runner. Measured hit rate (§1.6): **52 %** of
  pushes with the narrow filter. Price: 0.52 × 51.7 × 3 = **~81 weighted
  min/month**. Still 2.6 % of a 3 000-minute allowance the repository is already
  past, so it is refused **today** — but §3 R6's promotion, when the bill
  allows, takes this shape and not (a), and the filter set and its measured hit
  rate are recorded here so that decision does not have to re-derive them. Two
  riders for whoever builds it: the filter must have a self-test (a filter that
  silently matches nothing is a lane that never runs and always looks green),
  and it must include `scripts/wasm-pack-build.sh` and the files the tool-pin
  greps read, because a pin bump moves the bytes without touching a crate.
- **R3 — (e) Fold the second build into an existing `ci` job: REFUSED on a
  committed convention.** `ci.yml`'s header: *"Jobs are deliberately small named
  units: extend by ADDING jobs, not by folding steps into existing lanes."*
  It would also still cost push-tier minutes (~2 min × 51.7 ≈ **103 weighted
  min/month**) while making one job's red mean two unrelated things.
- **R4 — (c) A `workflow_dispatch`-only lane: REFUSED in R86's own words** —
  *"enforcement in name and a human's memory in fact, and would be this row's
  own defect one level out."* Zero minutes buys zero enforcement. The one thing
  it would add over the ruled arm is the ability to check a commit without
  deploying, and §7 R3's local plant already provides that at zero CI cost.
- **R5 — (f) Normalise the environment instead of comparing two: REFUSED.**
  Building in a fixed container path with a fixed `$CARGO_HOME` would make two
  machines agree by construction. It converts a **measured** property into an
  **assumed** one, and it adds a container image to the build's identity —
  D63 §7 rule 1's class exactly, and the binaryen lesson restated: the moment
  the image is not exact-pinned with a digest, the published number is
  unreproducible by construction while looking more rigorous than before.
- **R6 — (g) Compare a local build against the LIVE page's footer digest:
  REFUSED as strictly weaker at the same tier.** It compares a build against a
  *served artifact* rather than against a *second build*, so a host serving a
  stale or rewritten body reds a correct build; it makes evidence depend on the
  host being reachable; and it can only ever speak about the deployed commit,
  which is the tier the ruled arm already covers — with a real second build
  instead of an HTTP fetch.

---

## 11. Evidence — what discharges "a lane that has never run on the remote"

- **R1 — ONE `workflow_dispatch` of `pages`, at the commit that lands the
  change. Cost: 3–4 billed weighted minutes.** That single run executes the
  whole path on a hosted runner — build A, the tree copy, the second
  `$CARGO_HOME`, build B, the comparison, and then the deploy. Nothing cheaper
  discharges the rule, because the harness's subject is a hosted runner's
  environment and no local run can produce one.
- **R2 — The deploy it performs is a no-op and must be shown to be one.** The
  live page already serves the reproducible bytes (`9317a35`); a dispatch at a
  commit whose page is byte-identical re-publishes the same artifact.
  `pages-publish.sh --verify` runs after `deploy-pages` and already compares the
  served bytes against the sums the run produced, so the run witnesses that too.
- **R3 — It witnesses the GREEN path only, and the record must say so.** The red
  path's evidence is §7's local plants. That asymmetry is acceptable **because
  the comparator is a committed script exercised identically in both venues**
  (Q43's whole point), and unacceptable to leave unstated — so R86's row records
  *"the red path has not been observed on a runner"* until a real red occurs in
  anger.
- **R4 — The capture goes in the ROW, in the act that ticks it, not in a wave
  transcript.** Required in R86's `Notes`: the run id; the two printed
  environment lines verbatim; the shared 64-hex module digest and byte count;
  the `build and check the page` step duration before and after, so §3 R2's
  price is measured rather than predicted; whether the deploy proceeded; and the
  sentence naming what the run does **not** cover (§3 R4). A measurement that
  lives only in a transcript is not evidence.
- **R5 — Q237's evidence rule is satisfied by naming the machine per clause.**
  Clauses proved on `GitHub Actions <runner id>`: the two-environment
  comparison, its green output, the price. Clauses proved on the maintainer's
  machine: both self-test arms and the commit-stamp plant. No clause may be
  recorded without its machine.

---

## 12. Residual risk

1. **The allowance question is unresolved and this document could not resolve
   it.** The brief says Pro/3 000; the tree says Free/2 000 in three places and
   in a committed constant; today's branch-protection probe returns 404 where
   the tree records 403, which points at Pro. The billing endpoint needs a token
   scope this session does not have. **Ruled against the worse number**, which
   is safe in the only direction that matters, but the maintainer should settle
   it — and if it is Pro, `scripts/ci-lanes.sh:1169` and three passages in
   `docs/ci-verification.md` are stale and the fuzz guard is 50 % tighter than
   its own rationale intends.
2. **The bill is the finding, and this decision does not fix it.** 3 154
   weighted minutes in 15 days, **88 % of it `ci` on push** (2 787 of 3 154, for
   30 pushes at ~93 billed minutes each). The single most expensive line is
   `test` at 32 minutes, and `cross-os-macos` bills 13.2 weighted minutes for
   1.3 minutes of work. Nothing in this decision touches that, and no arm of
   R86 could have. §13 routes it.
3. **The price of build B is estimated, not measured.** §5 R3's 55–90 s comes
   from two measured compiles (40.86 s warm-registry, 70 s cold) plus an
   unmeasured copy. The first remote run measures it (§11 R4) and the row
   records the real number; if it exceeds 2 billed minutes per deploy, §3 R2 is
   corrected at this document rather than absorbed silently.
4. **A green here can still be a green over a wrong artifact.** The comparison
   proves two environments agree; guard 1 proves no path leaked; guard 2 proves
   the packaged bytes are the tree's. None of the three proves the *sources* are
   what a reader expects — that is the signing chain's job (Q30/Q31) and it is
   not built.
5. **`paths:`-filter arithmetic ages.** §1.6's 52 % is measured over 33 pushes
   in this repository's first three weeks, during a documentation-heavy phase.
   The mix will move as M4 becomes code-heavy, and the promotion decision (§3
   R6) must re-measure rather than cite this figure.
6. **The deploy cadence is measured over two events.** Two dispatches in 19 days
   is a thin sample for "3.2/month". If deploys become routine, §3 R2's monthly
   figure rises linearly and stays negligible; the risk is in the other
   direction — a repository that stops deploying stops checking.

---

## 13. Discovered work — described, not registered

The registrar lands these; this document creates no rows.

1. **A whole-repository Actions budget, on the model D61 already built for one
   lane.** `scripts/ci-lanes.sh` has `FUZZ_BUDGET_CEILING_MINUTES`, a cron
   reader, a cost function and a self-test that plants configurations the
   ceiling must refuse — for **one** workflow. The measured whole-repo bill
   (§1.1) is 3 154 weighted minutes a fortnight and **has never been measured in
   this tree before today**; the only figure on record
   (`docs/ci-verification.md:1348`) is the fuzz lane's own. A `ci-budget` lane
   that prices every workflow from the committed YAML against the same named
   allowance — and that is red at today's configuration, which is the honest
   place for it to start — is the instrument that would have caught the two
   dispatch refusals this month before they happened. **Size M. Milestone M3 or
   M4, maintainer's call, and it is worth more than R86.**
2. **`ci`'s per-push bill, itemised for a decision.** 93 billed weighted minutes
   per push, of which `test` is 32 raw and `cross-os-macos` is 13.2 weighted for
   1.3 raw. Arms worth pricing rather than assuming: the macOS leg on a `paths:`
   filter or a cron rather than every push; `fuzz-smoke` (11.15 min) against the
   nightly lane's coverage; splitting `test`. Decision-shaped, not
   implementation-shaped. **Size S to rule, M to land.**
3. **The signed-release path is unguarded (§3 R4 item 3).** Q30/Q31 publish the
   digest this decision protects, by a route that never passes through
   `pages.yml`. Either the release workflow calls the same comparator, or the
   release is cut only from a deployed commit and says so. **A rider on Q30/Q31,
   not a new row.**
4. **`scripts/ci-lanes.sh:1169` and `docs/ci-verification.md`'s three
   Free/2 000 passages need re-measuring against the plan** once §12 item 1 is
   settled. **XS, and it is a correction rather than work.**
5. **`ci.yml`'s header says "across ALL THREE workflows" and there are six.**
   `scripts/check-ci-shell.py:52` globs them all and is correct; the comment is
   stale. **XS.**

---

## Outcome

**Tier (b) confirmed, mechanism overturned.** The deploy gate is the right
place — measured at ≤ 7 weighted minutes a month against a repository that has
already spent 3 154 in a fortnight and had 45 jobs refused dispatch for it — but
the brief's *"add a second build to `pages.yml`"* describes something that
landed at `9317a35`, runs in **0.81 s**, recompiles **nothing**, and asserts a
property R86's own `Do` says is not at risk. What is added is a **third** build
carrying the two axes that were measured to move the bytes, kept separate from
R83's guard so three reds stay three properties. R86's Accept row 3 is corrected
— its named plant is caught upstream by the path scan and would prove the wrong
check fallible; the plant that works is a differing `ANTSEAL_SOURCE_COMMIT`,
already demonstrated by this repository's own two commits at identical size and
different digest. R25's Accept row 1 is re-worded on the record from *"different
runners"* to *"different environments"*, because two hosted runners were
measured to share both load-bearing axes and are the weaker test.

---

## Correction — §1.1's method sentence still describes the mechanism the same section already corrected, 2026-08-16

**The corrected sentence, quoted verbatim**, from **§1.1**'s method paragraph:

> Jobs with an empty `runner_name` were excluded — they were never dispatched
> and billed nothing.

**The measured fact**, which this section already carries eleven lines below in
its own dated parenthetical, and which the method sentence above it contradicts:
across the whole 2026-08-01 → 08-15 window a query for jobs with **no runner
assignment returns zero**. Every one of the 45 zero-step jobs carries real
`started_at`/`completed_at` stamps 3–12 s apart and `conclusion: failure`. So the
exclusion the method describes **excluded nothing**, because the set it names is
empty.

**Nothing computed here moves.** Excluding an empty set changes no total: the
3 154 weighted minutes, the per-workflow table, the 2 821.8 lower bound and the
158 % / 105 % allowance figures are all unaffected, and the independent
re-measurement at **3 324** agrees to within 5 %. What is left is a **reader
who meets the old mechanism first** and carries it past the correction — which
matters because the mechanism is what a future reader greps for. The grep-able
signature is `conclusion: failure` with `steps == []` in seconds;
`docs/ci-verification.md` now carries it as a dated correction at the section
that first recorded the episode.

**Authority.** Orchestrator re-measurement 2026-08-15 (read-only `gh api` GETs
over 43 runs and 583 jobs), recorded by the registrar at the wave-21 close
2026-08-16. This correction lands in the same commit as R86's tick; the two are
not separable, because R86's tier rests on §1.1's bill.

**Which rulings still stand.** All of them, and the error runs in the direction
that **strengthens** the exhaustion finding rather than weakening it — a job that
was assigned a runner and executed zero steps is a clearer refusal signal than
one that was never scheduled. **§3 R1** (deploy-gated), **§3 R4** and its item 1
(*"nothing between deploys … days to weeks"*), **§3 R6** (raise-only by
decision, on a measured precondition), **§4 R3** (R25's Accept row 1 re-worded to
name environments rather than runners), **§1.5** (the commit stamp moves the
bytes and not the length) and **§10 R2** (the pre-priced `paths:`-filtered
workflow) are untouched. One downstream clause becomes weaker and is named at
its own site rather than here: *"the failed dispatches cost nothing"* in
`docs/ci-verification.md` rested on the absence of a runner and should now read
"at most one billed minute per job".
