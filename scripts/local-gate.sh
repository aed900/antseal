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

echo "gate: $(git rev-parse --short HEAD) — $(git log -1 --format=%s | cut -c1-60)"
run fmt    cargo fmt --all -- --check
run clippy cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
run test   cargo test --workspace --all-features --locked
run wasm32 cargo build -p antseal-core --target wasm32-unknown-unknown --locked

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

# Q66 — the traceability lane, which until 2026-07-31 was the one required
# context this gate did not run. Its self-test fixtures rotted the moment Q14
# ticked the gate rows, and the red sat invisible for want of exactly this
# line: a lane that never runs locally is not evidence either (Q43's rule,
# in its local dual).
run traceability scripts/ci-lanes.sh traceability

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
