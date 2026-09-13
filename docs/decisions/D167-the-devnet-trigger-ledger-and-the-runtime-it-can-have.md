# D167 — the devnet promote trigger's evidence lives in a **committed ledger appended by a script at wave close**, never by a workflow with a write grant; its runtime clause becomes **non-compile runtime**, the one runtime this lane can actually have; and `Q246` is witnessed by two scheduled greens that already existed

- **Status: RESOLVED. The orchestrator's lean fell on its premises and its
  direction survived; the mechanism it named did not.**
  - **`Q246`'s half of the lean SURVIVES every measurement that could have
    falsified it.** Two scheduled runs of `devnet-e2e-cron` went green after the
    2026-08-17 node-count fix, both carry `nodes=14 … failed=[] pending=[]`, both
    head commits contain the fix (`git merge-base --is-ancestor` → 0, with a
    negative control on the fix's own parent → 1), and both executed 23 tests.
    §1.1.
  - **`Q247`'s half falls on three premises.** Retention is now **30 days from the
    upload** (D145 §2 R1 landed), not 89 or 90; a public repository's retention
    ceiling is **90 days** (`{"days":90,"maximum_allowed_days":90}`), which holds
    **13** weekly runs against the **20** the trigger needs; and the trigger's
    *"warm runtime"* is **undefined at its source** (D52 never defines it) and
    **unreachable as printed** — compile alone is **142–148 %** of the 900 s
    budget. §1.2–§1.4.
  - **The mechanism the lean named is refused.** *"The workflow appends to a
    committed file"* would be the repository's **first `contents: write` grant**,
    its commits would **trigger no CI** (a `GITHUB_TOKEN` push starts no
    workflow), and each would move `HEAD`, which is a **wasm build input**. §1.5,
    §2 R2.
  - **A ruled clause never landed.** D145 §2 R4's *verbatim* `Accept` addition
    (the warm-runtime clause) occurs **0 times** in `tasks/Q.md` and `TODO.md`.
    This record carries it forward rather than re-ruling it. §2 R6.
- **Date: 2026-09-13**
- Owner rows: **`Q247`** (stays OPEN until its amended `Accept` is met — this record
  rules the store and the clause, the ledger lane builds them) and **`Q246`** (ticks
  on §1.1's evidence, recorded in its row by the registrar in the act that ticks it).
- Related: **D52** (the devnet venue, E2/E3 no-cache ruling, adversarial test 4),
  **D145** §2 R1 (30-day artifact retention) and §2 R4 (the amendment whose
  `Accept` clause never landed), **D138** (cadence reasoning), **D143** §1.3 (why
  only `pages.yml` holds a write grant), **D156** §2 R1 (what a tick means),
  **D162** §2 R11 (edit sets execute in the resolving commit), **`Q261`** /
  `scripts/check-custody-log.py` (the append-only walk precedent, and the
  rewrite-orphaned-pin lesson), **`Q79`** (the unrecorded-scheduled-lane class this
  ledger is a second instance of).

## 0. What was measured against

`HEAD` `ef5f6d9`, `origin/main` equal, public repository. Planning lane B (wave 35)
measured everything below with read-only `gh api` GETs and downloaded the two
evidence artifacts and both job logs; the orchestrator re-read the run list
independently before briefing. No workflow was dispatched and nothing was written
to GitHub.

## 1. What was measured

### 1.1 The two scheduled greens — `Q246`'s witness

| run | event | head | verdict line (verbatim) |
|---|---|---|---|
| `33616516399` | `schedule`, 2026-09-02 | `ae4e167` | `e2e-devnet: PASS commit=ae4e167 nodes=14 suites_run=4 failed=[] pending=[] secs=1745 anvil=1.8.1 evidence=/home/runner/work/antseal/antseal/target/e2e-devnet/20260902T095317Z-ae4e167` |
| `34338263485` | `schedule`, 2026-09-09 | `3437890` | `e2e-devnet: PASS commit=3437890 nodes=14 suites_run=4 failed=[] pending=[] secs=1721 anvil=1.8.1 evidence=/home/runner/work/antseal/antseal/target/e2e-devnet/20260909T100507Z-3437890` |

- Each `evidence.txt` is **183 B** and **byte-identical** to its single job-log
  occurrence (sha256 `a44aaaba…7407` and `18ed8527…ba05`).
- **The override took effect**, which the line alone cannot prove because the
  script's default is also 14: the job-log env echo reads
  `ANTSEAL_DEVNET_NODES: 14`, the launcher prints `booting 14 nodes`, and
  `manifest.json` has `node_count=14` — in both runs.
- **Executed, not planned** (instrument ledger's `--plan` false-PASS entry):
  `secs>0`, `evidence=` names a directory, and `test result: ok.` sums to
  6 + 3 + 11 + 3 = **23 passed, 0 failed, 0 ignored, 0 filtered out** in both.
- **The two runs between the red and the greens were refusals, not reds**:
  `32221569300` and `32936547060` each have one job with `steps=0` and an **empty
  `runner_name`** — so D52's two-consecutive-reds rule was never engaged.

### 1.2 Retention, re-measured

`gh api repos/aed900/antseal/actions/permissions/artifact-and-log-retention` →
`{"days":90,"maximum_allowed_days":90}`. Both current evidence artifacts expire
**exactly 30 days after upload** (`10099660953`: created 2026-09-09, expires
2026-10-09T10:33:50Z), so D145 §2 R1's explicit `retention-days: 30` is live and
its clock origin is the **upload**, not the run start D145 §1.1 measured under the
default setting. Neither origin changes a count at weekly granularity.

An artifact from run `T − k·P` is alive at `T` iff `k·P < R`:

| cadence `P` | `R` = 30 (landed) | `R` = 90 (public ceiling) | span of 20 runs |
|---|---|---|---|
| weekly | **5** | **13** | 133 d |
| daily | 30 | 90 | 19 d |

**No retention setting on a public repository holds 20 weekly runs.** The
earliest date a 20th consecutive clean weekly run can exist, counting
`33616516399` as the first, is **2027-01-13**.

### 1.3 The runtime clause is undefined at its source and unreachable as printed

D52 never defines *"warm"* (read at source, not at the transcription D145 X5
flagged). The `secs=` clock starts at `scripts/e2e-devnet.sh`'s timer, **before**
`scripts/devnet/local-up`'s release build and every suite's test compile. Split by
job-log timestamps and cross-checked against cargo's own `Finished … in` lines
(agreement within 2.1 s):

| run | release build | test compile | boot | execute | `secs=` | non-compile |
|---|---|---|---|---|---|---|
| `33616516399` | 790.1 s | 542.7 s | 6.0 s | 405.7 s | 1745 | **413.6 s** |
| `34338263485` | 761.9 s | 520.9 s | 6.0 s | 432.1 s | 1721 | **440.3 s** |

Against 900 s: cold `secs=` is **over by 845 s / 821 s**; non-compile runtime is
**under by 486 s / 460 s**. No run of this lane is warm by construction (D52 E3
refuses the cache), so counting runs can never make the printed clause reachable.

### 1.4 The count's statistical meaning

With `n` consecutive clean runs and zero failures, the 95 % upper bound on the
per-run flake rate is 45.1 % at `n = 5`, 20.6 % at `n = 13`, **13.9 % at
`n = 20`**. Weakening the count to what a store holds (5 or 13) would silently
re-decide D52's adversarial test 4 from a ~14 % bound to 21–45 %.

### 1.5 The write posture

The only write grants in any workflow are `pages.yml`'s `pages: write` and
`id-token: write`; **no workflow holds `contents: write`**, and the repository's
default workflow token is `read`. A workflow that commits its own verdict would
(a) add the first `contents: write` beside a ~736-package build, (b) land
commits on `main` that **no CI checks**, because a `GITHUB_TOKEN` push starts no
workflow, (c) move `HEAD` weekly — and `HEAD` is a wasm build input
(`scripts/wasm-pack-build.sh` stamps `git rev-parse HEAD`), so every local gate
after a pull would meet a stale page artifact — and (d) still append nothing for a
refused run, so a lag check is needed regardless.

### 1.6 An instrument finding this record depends on

**`steps == []` stops identifying a billing refusal once logs expire.** A
13-month-old public-repository run showed `steps=0` on a real `failure` job with a
runner assigned and logs `410 Gone`, while a 3-day-old run of the same workflow
showed 11 steps. On this repository all 38 refused jobs have an **empty
`runner_name`** and the one real red has a runner. **`runner_name` is the
discriminator that survives expiry**; any classifier this record mandates uses it.

## 2. RULING

### §2 R1 — The store is a committed, append-only ledger

One line per completed run of `.github/workflows/devnet-e2e-cron.yml`, carrying at
least: run id, event, head commit, the job's `runner_name` classification
(`executed` / `refused`), conclusion, the **verbatim** `e2e-devnet:` line for an
executed run, `secs`, the summed cargo compile seconds, the derived non-compile
seconds, and the run's start time. The artifact keeps its 30-day retention (D145
§2 R1) and carries only diagnostics that nothing cites. **The ledger file lives
under `docs/`** (never `scripts/devnet/**`, which is a D52 trigger glob), at a path
the implementing lane names and every checker classifies on arrival.

### §2 R2 — The writer is a committed script run at wave close; no workflow gains a write grant

**Refused, on §1.5:** any arm in which a workflow commits. The append is performed
by a committed script (`--append`) that reads the run list and job logs with
read-only GETs and writes new lines, executed by the registrar as a wave-close
ritual step. The ritual step is named where the registrar reads it (the Current
focus block's wave-close list), because a ritual that lives nowhere is the `Q79`
defect again.

### §2 R3 — The runtime clause is **non-compile runtime ≤ 15 min**

Derived at append time as `secs − Σ(cargo "Finished … in")`, and **fail-closed**:
if the job log yields any number of compile markers other than the lane's known
compile invocations (`1 + suites_run` — a surplus is as unplaceable as a shortfall), the line is written with the runtime field marked unmeasured and the
run **does not count as clean**. This replaces *"warm runtime"* wherever the
trigger is stated. The upgrade path — a `--prebuild` step outside the `secs=` clock
that measures the same quantity directly — is **deferred**, because it edits
`scripts/e2e-devnet.sh`, a D52 trigger, and belongs to the next lane that touches a
D52 surface anyway.

### §2 R4 — The count is **20 consecutive clean scheduled runs**

*Clean* = executed, **job conclusion `success`**, `PASS`, `nodes >= 14`,
`failed=[]`, `pending=[]`, non-compile runtime measured and ≤ 900 s. *Scheduled* = `event: schedule`; dispatched runs are
recorded and do not count. A **refused** run (empty `runner_name`) neither extends
nor breaks a streak; any executed non-clean run resets it. Weekly cadence stays —
daily cadence (arm B of lane B's survey) is **not taken**: it buys a reachable count
at 30× the flake exposure and triage load while leaving the evidence in an expiring
store, and cadence is D138's to re-decide, not this row's.

### §2 R5 — A checker in two halves

**Offline** (flagless run, no network; wired into `scripts/local-gate.sh`, green on
arrival): walks the ledger's git history and reds on an **edited or deleted** line
(`EDITED`), a **duplicate** record — keyed on (workflow, run id, attempt), so a re-run attempt is recorded rather than lost (`DUPLICATE`), a line counted clean that is not
(`COUNT`), a malformed line (`FORMAT`), and a history with **no commit that adds
the file** (`pinned == 0` is a hard error — derive the birth commit, never pin a
SHA; `Q261`'s rewrite lesson). **`--self-test`** builds synthetic repositories in a
temporary directory only (hazard class (c)), every arm red by its own tag, with a
green control. **Online** (`--against-api`, GET only; run in the wave-close ritual,
never in a CI lane or the offline gate): reds on a completed run with no line
(`LAG`), on a recorded line whose event, head, conclusion or start time disagrees
with the API (`MISMATCH` — the only check that can see a line forged before its first
commit), and on a newest scheduled run older than 7 days plus slack
(`STALE-SCHEDULE`; slack ≥ 5 h for the measured 4 h 16 m / 4 h 28 m schedule
delays, and it must also fire when **no** run exists, because public-repository
schedules auto-disable after 60 days without activity). Classification of
refused versus executed uses **`runner_name`, never `steps`** (§1.6). Its self-test
runs on recorded JSON fixtures.

### §2 R6 — `Q247`'s `Accept` is amended, and D145 §2 R4's dropped clause lands now

`Accept` row 3 is **restated** (never deleted): *"The ledger exists; a committed
script appends to it from the API at wave close with no workflow write grant (D167
§2 R2); and `--against-api` was observed red naming real unrecorded runs and green
after their append."* D145 §2 R4's clause is **added verbatim**: *"The 'warm
runtime' clause names a runtime this lane can actually have, or the no-cache ruling
(D52 E3) is revisited in the same act — an unreachable threshold is not made
reachable by counting runs."* — satisfied by §2 R3.

### §2 R7 — `Q246` ticks on §1.1

Its four `Accept` rows are met: verdict lines, run ids and commits (row 1);
`nodes=14` **with the env-echo proof** that the override took effect (row 2); both
runtime figures, **each labelled** — the cold `secs=` over by 845/821 s and the
non-compile runtime under by 486/460 s — and never written as a measured "warm
runtime" (row 3); row 4 not engaged, with the two refusals recorded so nobody reads
them as reds. **What it does not prove**, stated at the site: a cache-warm runtime,
memory headroom (no RSS figure exists anywhere; the evidence is zero OOM signals),
anything on the public 4-CPU runner class (both runs predate the flip), and any
flake rate.

### §2 R8 — Four refinements from the implementing lane, ruled before this record landed

The devnet-ledger lane (W2) found four places where §2 R3–R5 as first written
were looser than their purpose, and each is adopted above: records are keyed on
**(workflow, run id, attempt)**, because keying on the run id alone would erase a
red first attempt that is re-run green before the append, while only attempt 1 of a
scheduled run counts toward the twenty; *clean* also requires the job's conclusion to
be **`success`**, so a run GitHub shows red never counts green — at the stated cost
that an artifact-upload failure resets the streak; the compile-marker count must
**equal** `1 + suites_run`; and a fourth online tag, **`MISMATCH`**, compares each
recorded line with the API. `STALE-SCHEDULE`'s slack is **12 hours** (the five
recorded runs started between 22 minutes and 4 h 28 m late). No exception register
exists: an `EDITED` finding that reaches a commit stays red until a ruling and a code
change clear it.

## 3. Fault plants

Owed by the implementing lane and judged **by message**: each offline arm in §2 R5
red on its own tag against a constructed history, plus a green control; each
online arm red on a recorded fixture (an extra run → `LAG`; a nine-day-old newest
run → `STALE-SCHEDULE`; a `steps=[]` job **with** a runner → classified executed,
never refused), plus a green control of the real runs. The fail-closed runtime
derivation (§2 R3) gets a fixture log with one compile marker removed, which must
yield `unmeasured` and a non-clean line.

## 4. What this record does NOT decide

- **Generalising the ledger to every `schedule:` workflow.** Measured recurrence
  justifies it (`P13`'s scheduled evidence sat unrecorded 41 days), but it is not
  this row's subject. The script keys its records on workflow file so a later
  ruling can widen it without a format change.
- Cadence (D138), the cache refusal (D52 E3), and memory headroom.
- Whether hosted runs on the public runner class change either runtime figure —
  the first such scheduled run is due 2026-09-16 and is the ledger's first
  natural append.

## 5. Edit list — per write scope, with the lane named before this record was written

### W2 (the devnet-ledger lane)
- New checker script under `scripts/` implementing §2 R1–R5, with `--append`,
  `--against-api` and `--self-test`; new ledger file under `docs/`, seeded by its
  own `--append` from the real runs (the red-then-green witness of §2 R6).
- `scripts/local-gate.sh`: offline check + self-test lanes, green on arrival.
- `.github/workflows/devnet-e2e-cron.yml`: header comments only — the trigger
  restatement and the stale venue premises (private repository, 2-core class).

### W1 (the CI lane) — after W2 delivers
- `scripts/check-ci-paths.py`: classify the new script's edge.
- `docs/ci-verification.md`: the promote trigger names the ledger, states §1.2's
  arithmetic, the non-compile runtime clause and the 20-consecutive count; the
  hosted-runtime projection of ~21 min is corrected to the measured ~29 min.

### Registrar — `TODO.md`, `tasks/Q.md`, `docs/decisions/README.md`, `docs/instrument-ledger.md`
- `Q246`: tick with §1.1 and §2 R7's evidence in its Notes.
- `Q247`: §2 R6's `Accept` amendment and D145 §2 R4's clause; its `Do`'s stale
  89/12 figures corrected by dated addendum; the `tasks/Q.md` addendum at the end
  of `Q247` that cites `Q248`'s `Accept` recorded as misfiled.
- `docs/instrument-ledger.md`: §1.6's `runner_name` discriminator; the
  resolved-but-unexecuted D145 §2 R4 clause.
- Index row and register row for this record.

## Closing — this record is not consent

It authorises no workflow dispatch, no settings write and no push. The ledger's
first real append after this wave happens at the next wave close, under whatever
consent that close carries.
