#!/usr/bin/env bash
# Local pre-merge gate — a SUBSET of what CI enforces (CONTRIBUTING.md).
# Usage: scripts/local-gate.sh [path-to-repo-or-worktree]
#
# Q125 — THIS HEADER USED TO SAY "the same lanes CI enforces". It was not
# true, and the sentence licensed a real misreading: `wasm32 PASS` was read as
# "the wasm32 tests pass" when the lane was a `cargo build`, and the resulting
# blind spot cost a CI red at `6f69e1a` (a 64-bit-only `size_of` assertion in
# `antseal-core/src/anchor/caps.rs`). So, explicitly — what a green run of
# THIS script does NOT tell you, as of 2026-08-09 (19 required contexts from
# 17 jobs in `.github/workflows/ci.yml`):
#
#   cross-os-macos, cross-os-windows  no such host exists here. The Linux leg
#                                     is covered in substance by `test`.
#   core-dep-graph                    `./scripts/ci-lanes.sh dep-graph`
#   secret-guard                      `./scripts/ci-lanes.sh secret-guard`
#   audit-deny                        `./scripts/ci-lanes.sh audit-deny`
#                                     (needs the pinned cargo-deny)
#   vector-freeze                     `./scripts/vector-freeze.sh`
#   fuzz-smoke                        `./scripts/fuzz.sh` (nightly toolchain +
#                                     pinned cargo-fuzz)
#   golden-vectors, tamper-matrix     their SUITES run under `test`; their
#                                     non-empty-selection counters do not —
#                                     `./scripts/ci-lanes.sh <lane>`
#   cross-check                       `cbor-drift-guard` only, and only in
#                                     NAME: that lane is `cargo test -p
#                                     antseal-core --all-features --locked
#                                     --test cbor_crosscheck_contract`
#                                     (ci-lanes.sh:819), and antseal-core
#                                     declares exactly two features
#                                     (`test-util`, `test-vectors`), both
#                                     LIGHT and both in GATE_LIGHT_FEATURES —
#                                     so the `test` lane below already runs
#                                     that target at the same feature set. The
#                                     residual gap is the lane's IDENTITY, not
#                                     its coverage. BOTH `--check` and
#                                     `--self-test` now run below (Q141/D116).
#   wasm32-tests                      runs here only when the diff selects it
#                                     (the lane below, and ANTSEAL_GATE_WASM)
#   wasm-bitmatch                     same — the lane below, and
#                                     ANTSEAL_GATE_BITMATCH (Q128). Its
#                                     TRIGGER's self-test is unconditional;
#                                     the lane's own `--self-test` is not.
#   traceability's cargo-free         D124/Q182 asserts that CI's
#   PROPERTY                          `traceability` job invokes no cargo,
#                                     rustc or rustup, and the converse for
#                                     `core-dep-graph`. Both are ASSERTED ON
#                                     THE REMOTE ONLY, and not because nobody
#                                     wired them here: `--arm` works by
#                                     appending to `$GITHUB_PATH`, which
#                                     covers the LATER STEPS OF A JOB, and a
#                                     local run has no later steps. The
#                                     `cargo-free` lane below runs the
#                                     `--self-test`, which proves the guard
#                                     CAN go red; it does not run the job. So
#                                     a contributor can break this property
#                                     locally and find out only on the remote.
#
# And what a green run of this script asserts that CI DOES NOT (the other
# direction, and the one nothing had recorded until D116 §1.8). This is Q43's
# rule pointing the other way — "a lane that has never run on the remote is
# not evidence" (docs/ci-verification.md) — and until Q153 all five of these
# had never run there. THREE HAVE NOW MOVED and TWO HAVE NOT; the two that
# stayed carry their reason here rather than in a decision record, because
# this header is what a contributor reads before a push.
#
# MOVED TO THE REMOTE AT Q153 (2026-08-10), plus one addition at D124/Q182
# (2026-08-11) — no new required context; each rides as a step of a job that
# already exists, so the set stays at 19:
#
#   gate-features --self-test        now ALSO a step of CI's `core-dep-graph`
#   gate-features --check-partition  job, not `traceability` as Q153's row
#                                    said. The row called these two "seconds
#                                    and cargo-free"; they are seconds and
#                                    they are NOT cargo-free —
#                                    `declared_features()` runs `cargo
#                                    metadata --no-deps --locked`, and with
#                                    cargo off PATH `--check-partition` exits
#                                    1. `traceability` deliberately carries no
#                                    toolchain and no cache, so cargo there
#                                    would mean an implicit rustup install of
#                                    the 1.92.0 pin on one of only TWO CI jobs
#                                    that need no toolchain at all
#                                    (`secret-guard` is the other).
#                                    `core-dep-graph` already bootstraps,
#                                    already caches, and already runs `cargo
#                                    metadata`/`cargo tree` over the same
#                                    S22/P20 subject.
#                                    ADDED 2026-08-11 (D124/Q182): the
#                                    property this record was written to
#                                    correct — that `traceability` runs no
#                                    cargo — is no longer prose anywhere. It
#                                    is asserted on every run of that job by
#                                    `scripts/cargo-free.sh --arm`/
#                                    `--verdict`, and its converse for
#                                    `core-dep-graph` by `--require`. The
#                                    record above stands unchanged: it is what
#                                    happened.
#   bitmatch-trigger                 now ALSO a step of CI's `traceability`
#                                    job (Q153). Measured git-free, and
#                                    ASSERTED cargo-free every run since
#                                    D124/Q182 rather than measured once —
#                                    which is what earns it the job that has
#                                    no toolchain.
#   cargo-free                       `cargo-free.sh --self-test` is now ALSO a
#                                    step of CI's `traceability` job, because
#                                    `--arm` runs it before it arms (D124).
#                                    The ASSERTION it tests is two steps on
#                                    that job and has no local equivalent —
#                                    `$GITHUB_PATH` covers later steps of a
#                                    job, and there are no later steps here.
#                                    The gap that leaves is stated in the
#                                    FIRST list above, under "traceability's
#                                    cargo-free PROPERTY", because it is a
#                                    thing CI asserts and this script cannot.
#
# STILL LOCAL-ONLY, AND WHY (Q153's ruling — the asymmetry is declared here so
# it is not discovered a sixth time):
#
#   heavy-features                   `gate-features.sh --heavy` is a COMPILE,
#                                    not a check: clippy + test for three
#                                    package/feature pairs over the
#                                    ant-core/ant-node/EVM graph, 475 packages
#                                    against the default 120 (`ci-lanes.sh
#                                    dep-graph`). Per-PR it is the single most
#                                    expensive thing this workflow could gain,
#                                    on a private repo on GitHub Free whose
#                                    2 000-minute allowance is already the
#                                    standing suspect for a refused dispatch
#                                    (docs/ci-verification.md, the 2026-08-10
#                                    section). It stays a local, diff-selected
#                                    tier-2 gate; the HEAVY features are still
#                                    compiled by ZERO CI lanes and that is now
#                                    a decision rather than an oversight.
#                                    NOTE the residual: `--check-partition`
#                                    above proves every feature has a tier, so
#                                    CI can now see a feature nobody
#                                    classified — it still cannot see a
#                                    heavy-gated path that stopped compiling.
#   e2e-selftest                     `e2e-devnet.sh --self-test` needs no
#                                    devnet and costs seconds, but its remote
#                                    home is the SCHEDULED lane beside the
#                                    thing it tests, not a per-PR job:
#                                    .github/workflows/devnet-e2e-cron.yml
#                                    runs `./scripts/e2e-devnet.sh` BARE — the
#                                    lane without its test-of-the-test, Q141's
#                                    shape inverted. Ruled for Q154, which
#                                    owns that workflow: add `--self-test` as
#                                    its own step immediately before the bare
#                                    lane, the way ci.yml already runs the
#                                    cross-check's two halves. Not taken here
#                                    because a per-PR copy would have put the
#                                    self-test in one venue and the lane it
#                                    guards in another.
#
#   PROPTEST_CASES                   ci.yml:152 sets 1024 on the `test` job;
#                                    this script sets nothing, so the `test`
#                                    lane below runs proptest's default of
#                                    256. A green `test` here has explored a
#                                    QUARTER of the cases CI will
#                                    (docs/testing/proptest-conventions.md §4).
#
# `./scripts/ci-lanes.sh --list` enumerates the lanes that script owns.
# CONTRIBUTING's "PR checklist" says which of these to run by hand for which
# kind of change.
set -uo pipefail
cd "${1:-$(git rev-parse --show-toplevel)}" || exit 1

fail=0
run() {
  local name="$1"; shift
  local out
  if out=$("$@" 2>&1); then
    printf '  %-16s PASS' "$name"
    case "$name" in
      test)
        printf '  (%s tests)' \
          "$(printf '%s' "$out" | awk '/^test result: ok\./ {s+=$4} END {print s+0}')" ;;
    esac
    printf '\n'
  else
    printf '  %-16s FAIL\n' "$name"
    printf '%s\n' "$out" | tail -25
    fail=1
  fi
}

# S22 — TIER 1 of the gate feature policy: every LIGHT feature, i.e. every
# feature any workspace crate declares that is not on `gate-features.sh`'s
# HEAVY list. This line replaced `--all-features`, which since P16 landed
# `devnet-launcher/devnet` and S5 landed `antseal-net/ant-backend` dragged
# the whole upstream stack — 475 packages against the default 120, measured
# by `ci-lanes.sh dep-graph` — into a gate that has to stay minutes long on a
# 2-core host, for every change including a docs-only one.
#
# The heavy paths are not dropped, they are MOVED: tier 2 below compiles and
# tests them per package when a storage-touching path changed, and tier 3 is
# the devnet E2E gate. The two lists cannot drift apart —
# `gate-features.sh --check-partition` fails unless this literal equals the
# computed LIGHT union AND every declared feature is classified by some tier,
# which is what stops a newly added feature from being compiled by nothing.
# `antseal-anchor/test-util` added 2026-08-02 (found by `gate-features.sh
# --self-test`, whose control arm was RED at 408ca26): A3 landed the feature
# and did not classify it, so no tier compiled A24's stub servers. LIGHT by
# the partition's own rule — it activates no optional dependency and pulls no
# ant-core/EVM edge, exactly like `antseal-net/test-util` beside it.
GATE_LIGHT_FEATURES='antseal-anchor/test-util,antseal-core/test-util,antseal-core/test-vectors,antseal-net/test-util'

# Q16 — the no-real-anchor-network policy, armed for every lane below exactly
# as `.github/workflows/*.yml` arm it workflow-wide. Without this line the
# local gate would be the one venue where an integration test can reach a real
# TSA or OTS calendar, which is the venue a contributor actually runs. The
# `cfg(test)` half of the gate needs no variable and cannot be disabled; this
# covers the integration-test binaries (`antseal-cli/tests/*.rs`) that link
# antseal-anchor's ordinary build, where `cfg(test)` is false.
# `scripts/ci-lanes.sh anchor-net-policy` fails if this export goes missing.
# Policy and the A25 escape hatch: docs/testing/anchor-ci-policy.md.
export ANTSEAL_NO_REAL_ANCHOR_NETWORK=1

echo "gate: $(git rev-parse --short HEAD) — $(git log -1 --format=%s | cut -c1-60)"
run fmt    cargo fmt --all -- --check
run clippy cargo clippy --workspace --all-targets --features "$GATE_LIGHT_FEATURES" --locked -- -D warnings
run test   cargo test --workspace --features "$GATE_LIGHT_FEATURES" --locked
run wasm32-build cargo build -p antseal-core --target wasm32-unknown-unknown --locked

# Q125 — the wasm32 EXECUTION lane, which is a different statement from the
# `cargo build` directly above and now says so in its name. `wasm32-build`
# proves antseal-core COMPILES for the verifier's target; only this lane
# proves its unit tests PASS there, and the difference is not academic:
# `size_of::<x509_cert::Certificate>()` is 376 on wasm32 against 512 on
# x86-64, and two `caps.rs` equality rows asserting the 64-bit literals
# unconditionally reddened CI's `wasm32-core-tests` at `6f69e1a` with this
# gate green and a native `cargo test --workspace` green.
#
# On the `heavy-features` pattern below, for the same reason: it costs minutes
# and only some changes can move what it measures. Measured 2026-08-09 on this
# 2-core host: 3 min 42 s cold, then 2 min 46 s and 2 min 10 s warm — of which
# 2 min 15 s is node EXECUTING the module (the compile is cached at 0.3 s), so
# a warm target dir buys almost nothing. CI reports 2 min 40 s for the same
# step (run 31255637376, same 2-core runner class — D52 §E2).
# `scripts/wasm-tests.sh --needs-run` decides from the diff against `main`
# (override with ANTSEAL_GATE_BASE) rather than from the developer's memory;
# its trigger list has planted change-sets in both directions, pinned to the
# 6f69e1a incident, under `wasm-tests.sh --self-test`. Exit 2 means it could
# not decide, which is a visible SKIP with the reason, never a silent pass.
# ANTSEAL_GATE_WASM=1/0 forces it on or off.
#
# THE SELF-TEST RUNS UNCONDITIONALLY, and that placement is the point rather
# than habit: the trigger's own vacuity failure — a list that stops matching
# `crates/antseal-core/` — makes the lane render `n/a` forever, and a
# self-test guarded by the trigger would never run to say so. Ordered before
# the trigger for the same reason `format-freeze` and `features` are: a green
# verdict below means nothing until the guard has been shown able to go red.
# It is cheap enough to be unconditional — measured 3.1 s total, of which the
# R41 arm's throwaway wasm32 crate (fresh `mktemp -d`, so cold every run) is
# ~3 s. It covers both halves: Q125's planted change-sets in both directions,
# and R41's planted failing `#[test]` that the runner must NAME.
run wasm32-selftest scripts/wasm-tests.sh --self-test

wasm_why="$(scripts/wasm-tests.sh --needs-run 2>&1)"; wasm_rc=$?
case "${ANTSEAL_GATE_WASM:-auto}" in
  1) wasm_rc=0; wasm_why="forced by ANTSEAL_GATE_WASM=1" ;;
  0) wasm_rc=1; wasm_why="suppressed by ANTSEAL_GATE_WASM=0" ;;
esac
case "$wasm_rc" in
  0) run wasm32-tests scripts/wasm-tests.sh --check ;;
  1) printf '  %-16s n/a   (%s)\n' wasm32-tests "$wasm_why" ;;
  *) printf '  %-16s SKIP  (%s)\n' wasm32-tests "$wasm_why" ;;
esac

# Q128 — the SECOND wasm32 execution lane, and until now the one the gate did
# not run at all: `wasm-bitmatch` executes every committed golden vector
# through `antseal_core::test_util::vectors` natively and under wasm32 and
# requires a BYTE-IDENTICAL transcript (MVP-SPEC.md 167/169). It is the lane
# that certifies the M2 exit criterion — A22 met it on the `anchor` kind — and
# a manual CONTRIBUTING checkbox was all that stood behind it, which is Q125's
# defect one file over.
#
# It gets its OWN predicate rather than riding on `wasm-tests.sh --needs-run`,
# and the reason is the trigger, not the cost (measured on this host at 32 s
# for the lane plus 53 s for its self-test — CHEAPER than `wasm32-tests`; see
# the note on that figure's provenance below). `crates/wasm-bitmatch/build.rs`
# walks `testdata/vectors/` with no hardcoded file lists, so a VECTORS-ONLY
# change is this lane's mandatory case — and precisely the case the wasm32
# list must not match, since matching it would fire a 2 min 10 s PQC suite on
# every vector edit. Folding this lane under that predicate would have
# installed a gate lane that silently never fires for its most important
# input. `wasm-bitmatch.sh --trigger-self-test` arm 4 ASSERTS that asymmetry
# against the other script's list rather than leaving it as two comments in
# two files that cannot notice each other going stale.
#
# THE TRIGGER'S SELF-TEST RUNS UNCONDITIONALLY (Q125's vacuity link, one file
# over): a path list that stops matching `testdata/vectors/` renders this lane
# `n/a` for ever, and a guard placed behind the trigger would never run to say
# so. It costs milliseconds — no cargo, no git, only its own strings.
#
# THE LANE'S OWN `--self-test` is a different statement and gets a different
# placement: it injects a wasm32-only divergence and requires the comparison
# to go red, which needs two wasm32 builds (~53 s), so it runs only when the
# trigger fires — and then FIRST, immediately before the lane, because a green
# comparison means nothing until the comparison has been shown able to fail.
# That is the same ordering CI uses for this lane.
#
# ANTSEAL_GATE_BITMATCH=1/0 forces it on or off; exit 2 is a visible SKIP with
# the reason, never a silent pass.
#
# PROVENANCE OF THE TWO FIGURES ABOVE, because they are not equally sourced
# and a reader deciding whether to force this lane on deserves to know which:
#
#   * "32 s lane + 53 s self-test" is a SINGLE SAMPLE — one run, one host, one
#     day (2026-08-09), recorded in a shell comment and never re-measured. It
#     is quoted here because it is the only figure that exists and because the
#     ARGUMENT it supports is an inequality ("cheaper than wasm32-tests", which
#     is 2 min 10 s warm by a 3-run measurement), not a budget. Treat it as an
#     order of magnitude. Q125's `wasm-tests.sh:63-73` is the shape a
#     replacement should take: cold/warm/warm plus a CI run id for comparison.
#   * the UNCONDITIONAL half is measured properly, because it is the half this
#     gate pays on every run: `--trigger-self-test` 0.80 s / 0.08 s / 0.64 s
#     over three runs on this 2-core host (2026-08-09; no cargo, no git, so
#     the spread is page cache), and `--needs-run` 1.80 s / 0.61 s / 0.09 s
#     (two `git diff`/`git status` calls, cold index first). Under a second
#     each, which is what makes "unconditional" the right answer rather than a
#     concession.
run bitmatch-trigger scripts/wasm-bitmatch.sh --trigger-self-test

bm_why="$(scripts/wasm-bitmatch.sh --needs-run 2>&1)"; bm_rc=$?
case "${ANTSEAL_GATE_BITMATCH:-auto}" in
  1) bm_rc=0; bm_why="forced by ANTSEAL_GATE_BITMATCH=1" ;;
  0) bm_rc=1; bm_why="suppressed by ANTSEAL_GATE_BITMATCH=0" ;;
esac
case "$bm_rc" in
  0) run bitmatch-inject scripts/wasm-bitmatch.sh --self-test
     run wasm-bitmatch   scripts/wasm-bitmatch.sh --check ;;
  1) printf '  %-16s n/a   (%s)\n' wasm-bitmatch "$bm_why" ;;
  *) printf '  %-16s SKIP  (%s)\n' wasm-bitmatch "$bm_why" ;;
esac

# S22 — the policy's own guard (seconds): every declared feature is on
# exactly one tier, the HEAVY list still names features that exist, and the
# line above is exactly the computed LIGHT union. Self-test first, every run
# (the format-freeze pattern two blocks down): four planted faults — a new
# feature no tier compiles, a HEAVY entry whose feature is gone, a stale gate
# entry, and the gate line deleted outright — must each go red before the
# green verdict means anything.
run features scripts/gate-features.sh --self-test
run features scripts/gate-features.sh --check-partition

# Q50 — the wire-registry freeze digest. Not folded into `test` because its
# first layer is coreutils `sha256sum -c`, which shares no code with the crate
# whose format it pins, and because the self-test must run first for a green
# result to mean anything.
run format-freeze scripts/format-freeze.sh --self-test
run format-freeze scripts/format-freeze.sh

# Q43 — the CI lanes whose shell used to live only in YAML, and therefore ran
# only after a push. `ci-shell` is the enumerating guard (with its own planted
# faults); `ci-lanes --self-test` reproduces the Q8 flag-order defect and
# requires the tamper-matrix lane to go red locally. Both are seconds once the
# workspace is built, which is the point: a lane that has never run on the
# remote is not evidence, and neither is one that never runs locally.
run ci-shell   scripts/ci-lanes.sh ci-shell
run ci-lanes   scripts/ci-lanes.sh --self-test

# D124/Q182 — the test-of-the-test for the guard that asserts CI's
# `traceability` job runs no cargo. The ASSERTION is two steps on that job and
# has no local equivalent (`$GITHUB_PATH` covers a job's later steps; there are
# none here) — but the guard's own command must be executable before a push,
# which is the defect `check-ci-shell.py`'s docstring opens with and the exact
# reason Q8's malformed `--list` sat latent for two waves. Nine red arms, two
# direct property assertions, two green controls; no cargo, no network,
# milliseconds. The property itself is stated once, in scripts/cargo-free.sh's
# header, and every prose site in this file now cites it instead of asserting
# it.
run cargo-free scripts/cargo-free.sh --self-test

# Q16 — the no-real-anchor-network policy's static half (self-tests first,
# six planted faults). Reads committed files only, so it costs a fraction of
# a second. It is here because the arming it guards is a line in a YAML
# `env:` block and a line in THIS file: both are exactly the kind of thing a
# reformat drops without any test noticing, and the consequence is a test
# suite quietly stamping a rate-limited third-party TSA on every run — which
# this project has already done once (crates/antseal-anchor/src/ots/engine.rs,
# the `upgrade_pending_with` seam).
run anchor-net scripts/ci-lanes.sh anchor-net-policy

# Q81/D61 — the scheduled fuzz lane's monthly minute bill against its named
# 700-minute ceiling. Reads committed sources only (no cargo, no network), so
# it costs a fraction of a second. It is here because the failure it guards
# against is a REVIEW-time one: adding a name to scripts/fuzz.sh's TARGETS is
# a one-line diff that silently multiplies a bill which, when the 2 000-minute
# GitHub Free allowance runs out, stops EVERY workflow in the repository —
# including all 19 required contexts. Self-tests first, five arms, one of
# which asserts the configuration this lane shipped with (4 x 900 s daily,
# 2 274 min/month) is refused.
run fuzz-budget scripts/ci-lanes.sh fuzz-budget

# Q66 — the traceability lane, which until 2026-07-31 was the one required
# context this gate did not run. Its self-test fixtures rotted the moment Q14
# ticked the gate rows, and the red sat invisible for want of exactly this
# line: a lane that never runs locally is not evidence either (Q43's rule,
# in its local dual).
run traceability scripts/ci-lanes.sh traceability

# S22 — TIER 2: the heavy feature paths, per package. Required, but only for
# the changes that can break them — the same storage-touching path list the
# D52 devnet E2E gate uses, because the two gates guard the same surface.
# `--needs-heavy` decides from the diff against `main` (override with
# ANTSEAL_GATE_BASE) rather than from the developer's memory; exit 2 means it
# could not decide, which is a visible SKIP with the reason, never a silent
# pass. ANTSEAL_GATE_HEAVY=1/0 forces it on or off.
heavy_why="$(scripts/gate-features.sh --needs-heavy 2>&1)"; heavy_rc=$?
case "${ANTSEAL_GATE_HEAVY:-auto}" in
  1) heavy_rc=0; heavy_why="forced by ANTSEAL_GATE_HEAVY=1" ;;
  0) heavy_rc=1; heavy_why="suppressed by ANTSEAL_GATE_HEAVY=0" ;;
esac
case "$heavy_rc" in
  0) run heavy-features scripts/gate-features.sh --heavy ;;
  1) printf '  %-16s n/a   (%s)\n' heavy-features "$heavy_why" ;;
  *) printf '  %-16s SKIP  (%s)\n' heavy-features "$heavy_why" ;;
esac

# Q15/D52 — the devnet E2E gate, in two halves that are deliberately not the
# same thing:
#
#   * its SELF-TEST runs on every gate. It needs no devnet, takes seconds,
#     and covers the two pieces of `e2e-devnet.sh` that can silently stop
#     meaning anything: the suite-registry rules (a renamed suite must fail,
#     a landed-but-still-declared-pending suite must fail, an all-pending run
#     must say PENDING and never PASS) and the redaction filter that keeps
#     wallet-key-shaped material out of uploaded artifacts.
#   * the GATE ITSELF is opt-in here, because it boots a 14-node devnet and
#     runs for tens of minutes where this gate runs in minutes (D52 option C
#     keeps it a named, separately-invoked gate). It is NOT optional as
#     policy: for storage-touching changes it is mandatory before merge —
#     CONTRIBUTING, "Devnet E2E gate (D52)", defines what storage-touching
#     means and what evidence to record.
run e2e-selftest scripts/e2e-devnet.sh --self-test
if [ "${ANTSEAL_GATE_E2E:-0}" = "1" ]; then
  run e2e-devnet scripts/e2e-devnet.sh
else
  printf '  %-16s SKIP  (storage-touching change? ANTSEAL_GATE_E2E=1 %s — CONTRIBUTING "Devnet E2E gate")\n' \
    e2e-devnet "$0"
fi

# F14 — the independent cross-check (decision D31; contract:
# docs/testing/cbor-cross-check.md). Not a cargo lane: its whole value is that
# it shares no code with the crate it checks.
#
# SELF-TEST FIRST, like format-freeze, features, ci-lanes and vector-freeze.
# Q141, and the reason is a measured incident rather than symmetry: on
# 2026-08-09 the CBOR checker's scope rule was written twice, `run` was
# narrowed and `self_test` was not, and the tree was GREEN under `--check` and
# RED under `--self-test`. CI runs them as separate steps and only the second
# one selects, so CI saw it and THIS GATE STRUCTURALLY COULD NOT. Q130's three
# new instruments — the swept subject set, the computed fault counts, the
# non-vacuity CheckFailure — are all invisible to `--check` for the same
# reason: `--check` verifies committed bytes, `--self-test` verifies that the
# checker can still fail.
#
# COST, measured here 2026-08-10, two runs on this 2-core host: `--self-test`
# 55.66 s then 46.41 s; `--check` 24.63 s then 22.48 s. So this block roughly
# triples, to ~70-80 s. Two samples, one host, one day — the weaker kind of
# figure, and it says so (the provenance rule in the wasm-bitmatch block
# above). It is NOT the "~4 s" that reached TODO.md: that figure belongs to
# `crosscheck_cbor.py --self-test` alone, which is 0.10 s. The 46 s buys
# planted faults on SIX surfaces (provenance, reference.py's T0 anchors, the
# generators, the UTF-8 corpus, the CBOR checker, the report checker), five of
# which no other local lane exercises at all.
#
# Exit 2 means the dev tool is not provisioned on THIS machine. That is a
# visible SKIP locally, with the one-line fix printed — and a hard FAILURE in
# CI, where the `cross-check` lane passes --require so a freeze-gate input can
# never go quietly missing.
crosscheck_lane() {
  local label="$1"; shift
  local out; out=$(scripts/cross-check.sh "$@" 2>&1); local rc=$?
  case $rc in
    0) printf '  %-16s PASS  (%s)\n' "$label" \
         "$(printf '%s' "$out" | tail -1 | cut -c1-90)" ;;
    2) printf '  %-16s SKIP  (cbor2 not provisioned — scripts/cross-check.sh --setup)\n' \
         "$label" ;;
    *) printf '  %-16s FAIL\n' "$label"
       printf '%s\n' "$out" | tail -25
       fail=1 ;;
  esac
}
crosscheck_lane cross-check-st --self-test
crosscheck_lane cross-check    --check

# R25 — the verifier page's packaging step, over the BUILT artifact (D131 §5
# R8 (c)). Self-test first, as everywhere above: three planted faults — a
# one-byte edit to the inlined payload, a glue that was transformed rather than
# concatenated, and a footer digest that is not the module's — must each go red
# for their own reason before the green verdict means anything. The `--check`
# arm then also proves the injector REFUSES its own output (D63 §5 R1: a second
# injection is a hard error, never a silent no-op).
#
# The browser half of D129 §5 R9 — assertion 8, the zero-network file:// run —
# is deliberately NOT here: it is `scripts/verifier-page-browser.mjs`, run by
# R27's entry point, because it needs a browser and this gate must stay
# runnable on a host without one.
#
# COST — RE-MEASURED 2026-08-15, after R83 made the module rebuild
# UNCONDITIONAL (it previously built only when `target/wasm-pack/` was empty,
# so this lane could pass over an artifact no source produced). Two runs each on
# this 2-core host: `--check` 1.49 s / 1.42 s, `--self-test` 1.29 s. Two
# samples, one host, one day — the weaker kind of figure, and it says so.
#
# The rebuild is far cheaper than its description suggests because cargo
# recompiles nothing when the tree has not moved: wasm-pack relinks in 0.65 s.
# The figure NOT in this range is a run after a source change, which pays the
# wasm32-release build — measured 1 m 08 s cold. That is the honest reason this
# sits after the wasm lanes rather than before them.
#
# The superseded figures are kept for the record, because the delta IS R83:
# `--check` 0.39 s / 0.37 s when it was allowed to skip the build entirely.
run page-selftest scripts/verifier-page-build.sh --self-test
run verifier-page scripts/verifier-page-build.sh --check

exit $fail
