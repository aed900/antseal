# D52 — Devnet E2E venue: CI job vs self-hosted vs required local gate (Q15)

- **Status: RESOLVED — required local gate (`scripts/e2e-devnet.sh`,
  mandatory before merging storage-touching changes, scripted evidence per
  the Q14 pattern), plus a scheduled, non-required GitHub-hosted devnet
  job at reduced node count on the fuzz-nightly pattern, landing only if
  its measured runtime fits the minutes budget. A per-PR required CI job
  is REJECTED (unenforceable on the current plan, and unaffordable /
  flake-prone on the runner class even if it were enforceable). A
  self-hosted runner is REJECTED (the only candidate host is the 2-core
  dev machine itself; a standing runner daemon there adds surface and
  contention for zero capability the local gate lacks).**
- **Date: 2026-08-01** (M1 Storage planning wave)
- **Owner: Q15** (implements the venue), with S17/S18/S19 (the suite it
  wraps) and P16 (the environment it boots)
- **Blocks: Q15** (execution), **S17** (its Accept line "Runs in CI
  (scheduled or gated job per Q's infra)" resolves to the scheduled
  lane), CONTRIBUTING (the when-is-the-gate-mandatory section Q15's
  Accept requires)

## Context

Q15 (`tasks/Q.md:323-332`) must pick where the M1 devnet E2E runs. Its
own text is already conditional: *"Measure the 25-node devnet + Anvil
resource footprint on a GitHub-hosted runner and decide the venue: a CI
job (with cached node binaries) if it fits, otherwise a documented
`scripts/e2e-devnet.sh` local gate required before merging
storage-touching PRs, optionally plus a scheduled self-hosted job."* The
register's lean is therefore "CI job if it fits". The suite at stake is
S17/S18/S19: multi-file `--split` seal, kill-between-pay-and-finalize →
no-double-payment (Anvil tx counting), kill-mid-upload → byte-identical
resume + nonce-reuse-guard abort with **at least one real process
SIGKILL** (`tasks/S.md:229-240`), restore-from-backup, UNANCHORED verify,
`--live` re-fetch — with deterministic setup/teardown and node/Anvil log
capture on failure.

Two facts the task text predates: the devnet is **in-process** (no node
binaries exist to cache — `ant-node-0.15.0/src/devnet.rs:1-4`; the
cacheable artifact is the cargo target dir), and the repo's
branch-protection situation changed from "pending" to "blocked by plan".

## Evidence

### E1 — "Required CI job" is not implementable as a merge gate today

Branch protection returns **403 on both the classic API and rulesets** on
this private GitHub Free repo — *"Upgrade to GitHub Pro or make this
repository public"* — verified 2026-07-28 and recorded as BLOCKED BY
PLAN, not pending (`docs/ci-verification.md`, "Branch protection is
BLOCKED BY PLAN" section; also TODO.md Current-focus maintainer action
4). **19 contexts from 17 jobs** already exist with the payload
unapplied. A 20th devnet context could not be *required* any more than
the existing 19 can. On the current plan, "required CI job" and "required
local gate" have **identical enforcement strength: convention backed by
the maintainer runbook** — so the CI job's supposed advantage (a red lane
blocks the merge) does not exist here.

### E2 — The runner class is this machine's class, so P16's measurements transfer

GitHub-hosted standard Linux runners for private repos on Free are
2-core/7 GB — the same class as the dev machine (2 cores, 7.7 GiB). The
P16 feasibility memo (`docs/research/P16-devnet-feasibility.md` §7) is
therefore the footprint measurement for both venues at once: 10–14
in-process nodes + Anvil fit RAM comfortably and stabilize in ~30–60 s;
25 nodes is the flake zone on 2 cores (120 s stabilization timeout,
`ant-node devnet.rs:49`, with post-quantum QUIC handshakes as the CPU
spike). Nothing about the hosted runner adds headroom.

### E3 — Build economics and cache pressure on the hosted runner

The devnet graph resolves **688 packages**, ~600 of them new against
today's 110-package lock (P16 memo §5, probe of 2026-08-01). Cold-build
estimate on a 2-core runner: 45–90 min release. `Swatinem/rust-cache`
would amortize it, but the devnet target dir (est. 4–8 GiB) competes
inside GitHub's **10 GiB per-repo cache cap** with the caches of all 19
existing lanes plus the fuzz corpus round-trip — eviction thrash would
slow every lane to speed one. Free-plan CI minutes are 2 000/month with
the `cross-os-macos` required context already burning at the 10×
multiplier on every push. A per-PR devnet job at 15–60 min/run is a
material fraction of the budget; one scheduled run/day at ~20–30 min
(~600–900 min/month) is affordable — and on Linux only, at 1× —
**only if** the measured warm runtime confirms the estimate.

### E4 — Flake surface of the suite itself

S18 is timing-sensitive by design: real SIGKILL mid-flow, Anvil
transaction counting, resume windows. Shared runners add CPU steal and
noisy neighbors to a suite whose failure mode is a timeout. A required
lane that flakes blocks merges (its one job); a non-required per-PR lane
that flakes trains people to ignore red — worse than absent under this
project's all-lanes-mean-something hygiene. A **scheduled** lane that
flakes wastes one slot and pages nobody's merge.

### E5 — Secrets are a non-issue for this decision

The local devnet needs no real secrets: the funded wallet is Anvil dev
account 0, a publicly known constant (`evmlib testnet.rs:72-81`). CI
wallet handling only bites a *Sepolia-mode* job, which is not Q15's
scope — the M4 Sepolia gate is deliberately scripts-plus-procedures
(Q32), not CI.

### E6 — House precedent

- **Q14**: the format-freeze gate is a required *local* gate with
  recorded, objective evidence — the project's highest-stakes gate
  already runs on this model.
- **Q43/Q66** (`docs/ci-verification.md`, "A lane that has never run on
  the remote is not evidence", and its local dual in
  `scripts/local-gate.sh:39-53`): evidence requires the lane to run **in
  both places**. This cuts against a local-only answer exactly as hard as
  against a remote-only one — which is why the scheduled remote leg is
  part of this decision, not decoration.
- **fuzz-nightly / advisory-cron**: the established pattern for heavy or
  periodic work — `schedule:` + `workflow_dispatch`, never a PR status
  context (`docs/ci-verification.md` Q9/P13 sections). The devnet job
  slots into it unchanged.
- **`scripts/ci-lanes.sh`**: CI and contributors run the same committed
  script bytes. `e2e-devnet.sh` follows it: the scheduled workflow's step
  is the same script the local gate runs.

## Options

**A — required per-PR CI job (GitHub-hosted).** The register lean.
Unenforceable as "required" (E1); cold-build/cache/minutes costs land on
every PR (E3); highest flake exposure where flake costs most (E4).

**B — scheduled self-hosted job.** Q15's optional extra. The only
available host is the dev machine; a runner daemon there executes
workflow-triggered code with standing credentials on the box that holds
the vault-adjacent dev environment, and contends for the same 2 cores the
local gate and agent lanes already share. It adds no capability over the
local gate (same hardware, same scripts) and the fork-isolation rationale
for self-hosting does not apply to a single-maintainer private repo.

**C — required local gate + scripted evidence.** Q15's own fallback arm,
on the Q14 pattern: `scripts/e2e-devnet.sh` boots the P16 devnet, runs
S17/S18/S19, captures node + Anvil logs on failure, and is **mandatory
before merging storage-touching changes** (definition in CONTRIBUTING per
Q15's Accept). Deliberately *not* folded into the default
`local-gate.sh` run (that gate is minutes; this one is tens of minutes) —
it is a named, separately-invoked gate whose execution is recorded.

**D — C plus a scheduled non-required GitHub-hosted job** at
minimal/small node count (5–10, per P16 §3), fuzz-nightly pattern,
landing only if its first measured runs fit E3's budget; it discharges
the run-on-the-remote half of Q43's evidence rule and doubles as an
upstream-drift tripwire between pushes.

## Adversarial test of the lean (house standard)

The register lean is A ("a CI job if it fits"), and this record's lean is
C/D — so the strongest case **for A / against C** must be put:

1. *"Local gates are convention; Q66 proved local-only lanes rot
   invisibly."* True, and answered twice: (a) on this plan **A is equally
   convention** — no context can be required (E1), so A's entire claimed
   advantage is absent; (b) rot is countered structurally, not by
   promises: the scheduled leg runs the same script bytes remotely
   (E6/Q43 both halves), and the gate emits recorded artifacts (logs,
   manifest, Anvil balance assertions) per Q15's Accept, so a skipped
   gate is a visible evidence gap, not a silent one.
2. *"Run it per-PR but non-required — early signal is worth minutes."*
   The signal repeats what the mandatory local gate already produced for
   exactly the PRs that matter (storage-touching), while paying E3's
   cache-eviction tax on **every** lane and E4's desensitization tax on
   every flake. One scheduled slot captures the remote-evidence value at
   a fraction of the cost.
3. *"S18's SIGKILL realism needs CI-grade isolation."* Inverted: kill
   /resume timing assertions are more reproducible on a controlled local
   box than on shared runners with CPU steal. The realism S18 wants is
   process death, not infrastructure variance.
4. *"If the plan ever upgrades, A becomes enforceable — decide A now so
   the lane exists."* The promote path is explicitly recorded below
   instead: D's scheduled job **is** the lane; promotion to a required
   context is a one-line branch-protection payload change gated on
   evidence (≥20 scheduled runs, ~0 flakes, warm runtime ≤15 min), on a
   plan that allows it (Pro, or public — which triggers Q65 first).

The lean does not survive: A's defining benefit is unavailable (E1), its
costs are concrete (E3/E4), and Q15's own text pre-authorizes the C arm
when A "does not fit". This is an overturn of the register lean by the
task's own criterion, not a spec deviation.

## Decision

**Option D.** Concretely:

1. **`scripts/e2e-devnet.sh` is the required gate** for storage-touching
   changes (S/P16-surface/`antseal-net`/journal/payment code — the precise
   trigger list lands in CONTRIBUTING per Q15's Accept). It wraps the
   S17/S18/S19 suite against the P16 devnet (default 14 nodes per the
   P16 memo), deterministic setup/teardown, log + artifact capture on
   failure, and prints a dated evidence line for the wave record.
2. **A scheduled workflow** (`schedule:` + `workflow_dispatch`, never a
   PR context — fuzz-nightly pattern) runs the same script at
   minimal/small node count on the hosted runner. It lands only after its
   first `workflow_dispatch` runs measure warm runtime within the E3
   budget; if it cannot fit, D degrades to C and the remote-evidence duty
   is discharged by recording that measurement.
3. **No per-PR devnet job, no self-hosted runner.** Revisit triggers,
   recorded here so the decision is reversible on evidence: (a) plan
   upgrade or Q65-gated public flip makes required contexts real — then
   the scheduled lane may be promoted per the criteria in Adversarial
   test 4; (b) a second, non-dev machine materializes — then self-hosted
   re-enters as a candidate for the *scheduled* slot only.
4. **Ordering deviation from Q15's Do, made deliberately:** Q15 says
   "measure on a GitHub-hosted runner **and** decide". The venue decision
   cannot wait for that measurement — measuring requires the scripts and
   a pushed workflow that only the venue decision unblocks, and the
   plan-blocker (E1) settles the "required" question independent of any
   measurement, while E2 makes local measurement transfer to the runner
   class. The scheduled job's first runs are the measurement, and they
   feed the promote/demote trigger rather than the venue choice.
   `tasks/Q.md` Q15 gets a status note to this effect at integration
   (Do/Accept are normative until deliberately revised — this is the
   deliberate revision, with the evidence above).

## Consequences for blocked tasks

- **Q15** implements: the script, the scheduled workflow (conditional),
  the CONTRIBUTING mandatory-when section, and the measurement record.
  Its Accept items map: "venue decision recorded with measurements" →
  this record + P16 memo §7 + the scheduled job's first-run numbers;
  "failure runs upload node + Anvil logs as artifacts" → both venues
  (local: evidence dir; remote: `actions/upload-artifact`, as
  fuzz-smoke already does); "contributor doc states when the gate is
  mandatory" → CONTRIBUTING.
- **S17** Accept "Runs in CI (scheduled or gated job per Q's infra)" is
  satisfied by the scheduled lane (or by its recorded infeasibility
  measurement under D→C degradation); "documented local invocation" is
  the gate itself. Text note at integration.
- **S18/S19** design for the local box first (timing tolerances sized to
  a 2-core host, not to runner variance).
- **P16** gains a consumer contract: `e2e-devnet.sh` consumes
  `local-up`'s machine-readable env export; node-count knob honored.
- **Q56's generated-context-list discipline** is unaffected: the
  scheduled job is never a PR context, so the 19-context payload does not
  change.

## Residual risks

1. **A required-by-convention gate can be skipped.** True of all 19
   contexts today (E1). Mitigation is the evidence trail (dated gate
   lines in wave records, artifacts on failure) plus the scheduled
   remote run making a silently-skipped local gate visible as drift.
2. **The scheduled lane can rot red** (upstream drift, runner changes)
   with nobody's merge blocked. Assign its triage the fuzz-nightly
   convention: a red scheduled run opens a tracking note in the next
   wave's bookkeeping; two consecutive reds block storage-wave starts.
3. **Minutes/cache estimates could be wrong** in either direction. The
   conditional-landing rule (measure, then keep or drop the scheduled
   lane) bounds the downside to a few measured runs.
4. **The 2-core dev machine is a single point of execution** for the
   required gate. Accepted for M1 (it is also the only machine); the
   scheduled lane is the partial hedge, and the revisit triggers name the
   exits.
5. **Flake-tolerance tuning may drift between venues** (local 14 nodes
   vs scheduled 5–10). The script owns one config surface (env knobs)
   and prints it into the evidence line, so any divergence is recorded
   rather than ambient.
