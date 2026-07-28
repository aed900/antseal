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
exit $fail
