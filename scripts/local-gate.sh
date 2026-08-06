#!/usr/bin/env bash
# Local pre-merge gate — the same lanes CI enforces (CONTRIBUTING.md).
# Usage: scripts/local-gate.sh [path-to-repo-or-worktree]
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
run wasm32 cargo build -p antseal-core --target wasm32-unknown-unknown --locked

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
# Exit 2 means the dev tool is not provisioned on THIS machine. That is a
# visible SKIP locally, with the one-line fix printed — and a hard FAILURE in
# CI, where the `cross-check` lane passes --require so a freeze-gate input can
# never go quietly missing.
crosscheck=$(scripts/cross-check.sh --check 2>&1)
case $? in
  0) printf '  %-16s PASS  (%s)\n' cross-check \
       "$(printf '%s' "$crosscheck" | tail -1 | cut -c1-90)" ;;
  2) printf '  %-16s SKIP  (cbor2 not provisioned — scripts/cross-check.sh --setup)\n' \
       cross-check ;;
  *) printf '  %-16s FAIL\n' cross-check
     printf '%s\n' "$crosscheck" | tail -25
     fail=1 ;;
esac

exit $fail
