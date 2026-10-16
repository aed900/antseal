# D183 — Five `deny.toml` ignores are **re-dated on a measured reason**, unsound advisories **surface across the whole graph**, and review dates **get a checker**

- **Status: RESOLVED. The direction survived, three premises fell, and the review had a date but no
  owner.**
  - **Five entries fall due on 2026-11-01**: the four P16 residents (RUSTSEC-2023-0089, -2025-0141,
    -2024-0436, -2025-0134) and `Q275`'s RUSTSEC-2024-0449. `deny.toml:48-50` ties that date to
    *"the next ant-core/ant-node bump review (policy §4 / S20)"*. But `S20` is a continuous row whose
    `Do` and `Accept` do not include the review, no bump is scheduled, and nothing parses the dates.
    From now on the review belongs to `Q277`, a DEADLINE row.
  - **All six ignores are live.** Dropping any one of them turns the lane red with
    `advisories FAILED` naming that id. None of the five is in the default graph.
  - **Their shared reason fails.** They say the fix arrives only with an `ant-core` bump. But
    `ant-core` 0.12.0, the newest release (2026-10-08), still locks all five, and it needs Rust 1.95
    against the pinned 1.92.0.
  - **"Unsound … all surface" never held at the pinned tool.** cargo-deny 0.19.8, the version D19
    itself pinned, defaults `unsound` to the workspace scope. `deny.toml:38` and D19 both say the
    default makes unsound advisories surface. Setting `unsound = "all"` turns the lane red on
    RUSTSEC-2026-0253 (`lru` 0.16.4, a use-after-free class, in the `ant-backend` graph).
  - **A checker is minted on a measured yield.** It finds 6 dated entries: no reds and no warnings
    today, warnings from 2026-10-19, 5 reds from 2026-11-02, and 0 false positives.
- **Date: 2026-10-16**
- Owner rows: **`Q277`** (minted with this record; DEADLINE before 2026-11-01; §2 R1–R3).
- Related:
  - **D19**: the advisory lane and its ignore discipline. It takes a dated addendum on the unsound
    scope.
  - **P16**: the four residents (`docs/upstream/P16-lockfile-event.md` §4).
  - **`Q275`**: RUSTSEC-2024-0449's entry.
  - **D60**: RUSTSEC-2023-0071's entry, review date 2027-02-01, which this record does not touch.
  - **`S20`**: the bump procedure the old reason pointed at.
  - **`P19`**: its Notes recorded that the dates had no owner.
  - **D143** and `scripts/check-action-pins.py` rule P6: the review-date shape this checker copies.
  - **D184**: the same `[advisories]` table (`yanked = "deny"` and the yanked pair). The
    orchestrator applies it after this record's `deny.toml` edits land.

## 0. What was measured against

`HEAD` `fbcee1e`.

Planning lane P4 (wave 37) ran cargo-deny 0.19.8 (sha256 `574c3147…`, equal to the index) against
advisory-db `edb58f5974b8` (2026-10-14). It:
- removed each ignore in turn;
- ran copies of `deny.toml` with `unsound = "all"` and with `unmaintained = "all"`;
- generated a probe lockfile for `ant-core = "=0.12.0"` in its own `CARGO_HOME`;
- prototyped the checker.

Nothing tracked was written. Survey lane PS read the same dates as an act owed now.

Before this record was written, the records lane read:
- `cargo-deny-0.19.8/src/advisories/cfg.rs:101-115,275-290`, from P4's download;
- `deny.toml:37-59` at `HEAD`;
- RUSTSEC-2026-0253, in the local advisory-db at `edb58f59`;
- P4's probe lockfile;
- the `lru` requirement of each locked dependent, in the registry cache.

## 1. What was measured

### 1.1 The six ignores

| id | crate | class | review by | line | removed |
| --- | --- | --- | --- | --- | --- |
| RUSTSEC-2023-0089 | atomic-polyfill 1.0.3 | unmaintained | 2026-11-01 | `:51` | `error[unmaintained]` |
| RUSTSEC-2025-0141 | bincode 1.3.3 | unmaintained | 2026-11-01 | `:52` | `error[unmaintained]` |
| RUSTSEC-2024-0436 | paste 1.0.15 | unmaintained | 2026-11-01 | `:53` | `error[unmaintained]` |
| RUSTSEC-2025-0134 | rustls-pemfile 2.2.0 | unmaintained | 2026-11-01 | `:54` | `error[unmaintained]` |
| RUSTSEC-2023-0071 | rsa | vulnerability | 2027-02-01 | `:56` | `error[vulnerability]` |
| RUSTSEC-2024-0449 | unsafe-libyaml 0.2.11 | unmaintained | 2026-11-01 | `:58` | `error[unmaintained]` |

- With every ignore in place the control reads `advisories ok`.
- Each removal gives `rc=1` and `advisories FAILED`, naming its id (6 of 6).
- None of the five due on 2026-11-01 is in the default graph.
- Their reasons wait on a bump. The fix *"arrives only with an ant-core bump"* (`:51`), *"Re-assess
  at each ant-core bump"* (`:52`), it *"moves with the next evmlib/ant-core bump"* (`:53`), and it
  *"leaves this graph only with an ant-core bump"* (`:58`).
- The block header says the date is when *"the next ant-core/ant-node bump review (policy §4 / S20)
  must re-assess or these expire"* (`:48-50`).

### 1.2 What the newest `ant-core` locks

P4's probe declared `ant-core = "=0.12.0"`. Cargo printed `Locking 656 packages` and `Adding
saorsa-transport v0.38.0 (requires Rust 1.95.0)`. The resulting lockfile carries all five crates at
the same versions: atomic-polyfill 1.0.3, bincode 1.3.3, paste 1.0.15, rustls-pemfile 2.2.0 and
unsafe-libyaml 0.2.11.

This shows lock presence only. Whether each crate is actually compiled under 0.12.0 was not
established; upstream made `serde_yaml` optional in saorsa-transport 0.37.0. The toolchain pin is
1.92.0.

### 1.3 The unsound scope, and the advisory it hides

**cargo-deny's defaults.**
- `cargo-deny-0.19.8/src/advisories/cfg.rs:107-108` sets `unmaintained: … Scope::All` and
  `unsound: … Scope::Workspace`. The deserialiser falls back the same way (`:284-285`).
- `yanked` defaults to warn (`:110`).
- With `unsound = "all"` the lane gives `rc=1`, `advisories FAILED`, `error[unsound]`
  RUSTSEC-2026-0253.
- When cargo-deny's default became `Workspace` was not established. D19 itself pinned 0.19.8.

**RUSTSEC-2026-0253** (advisory-db at `edb58f59`).
- Title: *"Potential use-after-free due to lack of panic safety in `LruCache::pop()`"*.
- `informational = "unsound"`; `patched = [">= 0.18.2"]`.
- Per the advisory, the undefined behaviour is reachable in safe Rust *"only if unwinding panics are
  enabled and `std::panic::catch_unwind` is used with key types that have potentially-panicking
  `Drop` implementations"*.
- The lockfile has `lru` 0.16.4, in the `ant-backend` graph (`cargo tree -i lru@0.16.4` prints 27
  lines). ant-core 0.5.0, saorsa-core 0.26.2 and alloy-provider 1.8.3 require `0.16`; ant-node 0.15.0
  requires `0.16.3`. No patched version is therefore semver-compatible with any locked dependent.
- P4's ant-core 0.12.0 probe lockfile still carries `lru` 0.16.4.
- The dependents' requirements and the probe's `lru` line are the records lane's reading. The
  reachability assessment is left to §2 R2.

### 1.4 Nobody owned the review

- The dates were recorded in `P19`'s Notes (`tasks/P.md:245`) and in the ledger (2026-10-14:
  *"nothing enforces `deny.toml` review dates … all five go stale together in silence"*).
- `deny.toml:48-50` points at `S20`'s bump review. `S20` is continuous, its `Do` and `Accept` do not
  include this review, and no bump is scheduled.
- PS read `S20` as the owner, and P4 read no row as the owner. This record mints one.

### 1.5 The checker's measured yield

P4's prototype, run over the live `deny.toml`:
- 6 dated entries;
- on 2026-10-15/16, no reds and no warnings;
- warnings from 2026-10-19;
- 5 reds from 2026-11-02;
- 0 false positives.

The house shape is `scripts/check-action-pins.py`'s rule P6. It goes red once its review date
passes and warns for the 14 days before; its in-memory faults are judged by their rule tag
(`scripts/lib/red-arm.sh`).

## 2. RULING

### §2 R1 — Before 2026-11-01, the five are re-assessed and re-dated on the measured reason (P4 C R1)

For each of RUSTSEC-2023-0089, -2025-0141, -2024-0436, -2025-0134 and -2024-0449:
1. Re-prove that it is still detected and outside the default graph.
2. Replace the claim that the fix arrives only with an `ant-core` bump with the measured reason.
   `ant-core` 0.12.0, the newest release, still locks all five and needs Rust 1.95 against the pinned
   1.92.0, so no available bump removes them.
3. Re-date it to **2027-01-15, "or the next ant-core pin move, whichever first"**. Keep exactly one
   `Review by YYYY-MM-DD` in the entry, so the checker can read it (§2 R3).

The block header at `:43-50` is reworded to say the same. RUSTSEC-2023-0071 (D60, 2027-02-01) is
left untouched.

### §2 R2 — `unsound = "all"`, and RUSTSEC-2026-0253 assessed (P4 C R2, ruled)

`[advisories]` gains `unsound = "all"`, which is what `deny.toml:38` and D19 already claim.

RUSTSEC-2026-0253 (`lru` 0.16.4, `ant-backend` graph) is then assessed for whether antseal's use
reaches the unsound API:
- **If it is unreachable:** add an ignore carrying its justification and a review date.
- **If a compatible patched version exists:** that is a fix. Report it to the orchestrator, and
  leave `Cargo.lock` unmoved until the orchestrator rules.

D19 takes a dated addendum, written by the orchestrator.

### §2 R3 — `scripts/check-deny-reviews.py` (P4 C R3)

The checker:
- reads `deny.toml` with `tomllib`;
- requires **exactly one** `Review by YYYY-MM-DD` in each `[advisories].ignore` entry;
- goes red on a date in the past;
- warns, with exit 0, on a date within the next 14 days;
- goes red on an empty ignore list;
- has an in-memory self-test, with each arm judged by its message.

It is wired into three venues:
- `scripts/local-gate.sh`, as both the self-test and the check;
- the `traceability` job in `ci-always.yml`;
- `advisory-cron.yml`, the only one of the three that runs on a schedule, so a date that passes in
  a week with no push still turns red.

All three are direct script calls, so no `check-ci-paths.py` edge is needed.

## 3. Fault plants

**The checker.** P4's prototype ran 6 cases against the `deny.toml` at `fbcee1e`, with no wrong
verdicts. Each case is judged by its message at an injected date:

| case | expected |
| --- | --- |
| the live `deny.toml` | green, 6 entries |
| one entry's date removed | red `[R1] … carries 0` |
| one entry with two dates | red `[R1] … carries 2` |
| date set to 2026-11-02 | five reds `[R2] … 1 day(s) expired` |
| a date inside the 14-day window | five warnings, exit 0 |
| an empty list | red `[R0]` |

Green predictions after §2 R1, using the prototype's boundary (it warns when fewer than 14 days
remain, which is why it measured warnings from 2026-10-19):
- On 2026-11-02 the check is green.
- The five warn from 2027-01-02 and go red from 2027-01-16.
- RUSTSEC-2023-0071 warns from 2027-01-19 and goes red from 2027-02-02.

**The lane.** These follow `Q275`'s form: each is judged by message, then restored and `touch`ed.
- Dropping any re-dated entry gives `error[unmaintained]` naming its id, and `advisories FAILED`.
- `unsound = "all"` without §2 R2's disposition gives `error[unsound]` naming RUSTSEC-2026-0253.
- The tree as landed gives `advisories ok, bans ok, licenses ok, sources ok`.

## 4. What this record does NOT decide

- Whether the five are compiled under `ant-core` 0.12.0. Only lock presence was measured.
- When cargo-deny's `unsound` default became `Workspace`.
- What happens to RUSTSEC-2026-0253 if antseal's use **does** reach the unsound API and no compatible
  fix exists. §2 R2 names only two arms; that third case is reported to the orchestrator, not ruled
  here.
- `Q10`'s tracking issue for new advisories, which is a GitHub write.
- The hosted witness. The two workflow steps first run on a consented push; until then the local
  gate is the only venue that has run them.
- The `yanked` level and the yanked pair. Those are D184's.

## 5. Edit list — per write scope, with the lane named before this record was written

### L-TOOL — `deny.toml`, `scripts/check-deny-reviews.py` (new), `scripts/local-gate.sh`, `.github/workflows/{ci-always.yml, advisory-cron.yml}`

- `deny.toml`:
  - the five reasons, their dates and the block header (§2 R1);
  - `unsound = "all"` and RUSTSEC-2026-0253's disposition (§2 R2).

  `deny.toml` is a `task-citations` scan root (`check-traceability.py:685`). A `Q277` cited in a
  reason must therefore be registered in the same commit.
- `scripts/check-deny-reviews.py` with its in-memory self-test, its `run` lines in
  `scripts/local-gate.sh`, and its steps in `ci-always.yml`'s `traceability` job and in
  `advisory-cron.yml` (§2 R3).
- `Cargo.lock` is not this lane's to move (§2 R2).

### Orchestrator — `TODO.md`, `tasks/Q.md`, `docs/decisions/README.md`, dated addenda

- Mint `Q277`.
- D19: a dated addendum saying that cargo-deny 0.19.8 defaults `unsound` to the workspace scope, so
  *"unsound … all surface"* did not hold at the pinned tool until §2 R2.
- The index row and the register row.
- D184's `deny.toml` edit, after L-TOOL's edit has landed.

## 6. As built — wave 37, lane L-TOOL (recorded in place before this record was first committed)

- **§2 R1's premise changed during the wave.** A lock for the newest `ant-core` (=0.12.0; 656
  packages, read 2026-10-16) holds **four** of the five crates, not five. `saorsa-transport` 0.38.1,
  published 2026-10-16T01:50Z (after planning measured), dropped `serde_yaml`, so `unsafe-libyaml`
  leaves with that pin move. That move needs Rust 1.95. RUSTSEC-2024-0449 was still re-dated as
  ruled, and its reason records the change.
- **Re-proved by plant.** Dropping any one ignore reds `advisories FAILED` with exactly that id,
  for all five and for the `rsa` and `lru` entries. None of these crates is in the default workspace
  graph or either wasm32 graph. `atomic-polyfill` is in no host graph at all; cargo-deny lists it
  only because it scans every target. Its old reason was imprecise and is corrected.
- **One date per reason.** Each reason now reads *"Review by 2027-01-15 or at the next ant-core pin
  move, whichever comes first"*. The checker enforces only the date half, and the pin-move half has
  its own line in the dependency-policy §4 checklist (DOCS lane).
- **§2 R2 — RUSTSEC-2026-0253's disposition: ignored, with its assessment.** It is unreachable in
  antseal's use: every `pop()` in the graph is keyed by a type with no `Drop` (u64, XorName,
  `[u8; 32]`). No compatible fix exists: the patched version is `>= 0.18.2`, all four dependents
  require `^0.16`, and a dry-run `cargo update -p lru --precise 0.18.2` fails with *"failed to select
  a version for the requirement `lru = "^0.16"`"*. The live lock was not touched. The ignore uses
  the same deadline clause, because the ruling fixed no date for it.
- **`scripts/check-deny-reviews.py`.** It compares dates in UTC; `check-action-pins` uses the local
  date. Its 14 arms include date-injection arms that replay 2026-11-02. Four deliberate breakages
  were each caught, one of them only after the empty-list arm was added. Replayed on `HEAD`'s file,
  it gives five warnings from 2026-10-19 and the same five red from 2026-11-02, matching planning.
  In `advisory-cron` its steps run under `always()`, so an expired ignore and a new advisory are each
  reported even when the other has failed.
- **Final state:** `./scripts/ci-lanes.sh audit-deny` exits 0 and ends `advisories ok, bans ok,
  licenses ok, sources ok`. The review check is green, next due 2027-01-15.

## Closing — this record is not consent

It changes a configuration file, a checker and two workflow files, locally. The workflow steps reach
GitHub only with a push the maintainer has expressly consented to.
