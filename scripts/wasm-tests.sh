#!/usr/bin/env bash
# The `wasm32-core-tests` lane, as a committed script (tasks Q43, R41).
#
# One entry point for CI and for a contributor, so the lane's shell is
# executed locally before it is pushed — the class of defect Q43 exists to
# close (`docs/ci-verification.md`: a lane that has never run on the remote
# is not evidence, no matter how long it has been committed).
#
# Usage:
#   scripts/wasm-tests.sh              run the lane (tests + toolchain audit)
#   scripts/wasm-tests.sh --check      same, explicitly
#   scripts/wasm-tests.sh --self-test  plant a failing #[test] on wasm32 and
#                                      prove the runner NAMES it (R41)
#
# Exit: 0 pass · 1 failure or self-test breach.
#
# ── Why the self-test builds a throwaway crate ─────────────────────────────
#
# R41's guard is "a failing wasm32 test reports its name", and the only
# honest proof is a wasm32 test that actually fails. Committing one would
# turn the lane permanently red, and a feature-gated one would add a
# product-crate feature, a lint allowance and a `feature_pins.rs` row for a
# test-runner concern. So the self-test generates a dependency-free crate in
# a temp directory OUTSIDE the repository — outside deliberately, so it
# inherits neither `.cargo/config.toml` (no `runner`, so the runner is
# invoked explicitly and its exit status is observable) nor
# `rust-toolchain.toml` (the pin is passed instead, so the two cannot drift
# apart silently). Nothing is committed and nothing can rot.
set -uo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo" || exit 1

note() { printf '\033[36m==>\033[0m %s\n' "$*"; }
die()  { printf '\033[31m::error::wasm-tests: %s\033[0m\n' "$*" >&2; exit 1; }

# The pin governs the self-test's throwaway crate too, which is outside the
# repo and therefore out of `rust-toolchain.toml`'s reach.
toolchain="$(sed -n 's/^channel *= *"\(.*\)"/\1/p' "$repo/rust-toolchain.toml" | head -1)"
[ -n "$toolchain" ] || die "cannot read the channel from rust-toolchain.toml"

cmd_check() {
  note "antseal-core unit tests on wasm32-unknown-unknown (through scripts/wasm-test-runner.mjs)"
  cargo test -p antseal-core --lib --target wasm32-unknown-unknown --locked || return 1
  note "getrandom recipe + wasm-bindgen pin equality"
  "$repo/scripts/wasm-toolchain-audit.sh" || return 1
}

# R41's planted fault: a real libtest binary on the real target with a real
# failing `#[test]`. Asserts the failure is attributed to the RIGHT test —
# naming some test would pass a weaker check while still being useless.
cmd_self_test() {
  local dir status out
  dir="$(mktemp -d)" || die "mktemp failed"
  trap 'rm -rf "$dir"' RETURN

  mkdir -p "$dir/src"
  cat > "$dir/Cargo.toml" <<'EOF'
[package]
name = "wasm-runner-selftest"
version = "0.0.0"
edition = "2021"
publish = false

[dependencies]
EOF
  # Two tests, so "named A test" cannot pass for "named THE test". The
  # failing one sorts LAST, so everything before it has already run and its
  # progress line is the one std's line buffer is holding at the trap.
  cat > "$dir/src/lib.rs" <<'EOF'
#[cfg(test)]
mod planted {
    #[test]
    fn aaa_this_one_passes() {
        assert_eq!(2 + 2, 4);
    }

    #[test]
    fn zzz_this_one_is_the_planted_fault() {
        assert_eq!(1, 2, "R41 planted fault");
    }
}
EOF

  note "building the planted-fault crate for wasm32-unknown-unknown ($dir)"
  local wasm
  wasm="$(
    RUSTUP_TOOLCHAIN="$toolchain" cargo test \
      --manifest-path "$dir/Cargo.toml" \
      --target wasm32-unknown-unknown --no-run --message-format=json 2>/dev/null |
      sed -n 's/.*"executable":"\([^"]*\.wasm\)".*/\1/p' | head -1
  )"
  [ -n "$wasm" ] && [ -f "$wasm" ] || die "the planted-fault crate did not build a .wasm test binary"

  note "running it through scripts/wasm-test-runner.mjs (it MUST fail)"
  out="$(node "$repo/scripts/wasm-test-runner.mjs" "$wasm" 2>&1)"
  status=$?
  printf '%s\n' "$out" | sed 's/^/    /'

  local fail=0
  if [ "$status" -eq 0 ]; then
    printf '::error:: the runner returned 0 for a binary with a failing test\n' >&2
    fail=1
  fi
  if ! grep -q 'planted::zzz_this_one_is_the_planted_fault' <<<"$out" ; then
    printf '::error:: the runner did not NAME the failing test (R41 accept)\n' >&2
    fail=1
  fi
  if grep -q 'aaa_this_one_passes' <<<"$out" ; then
    printf '::error:: the runner named a test that PASSED — the attribution is wrong\n' >&2
    fail=1
  fi
  if ! grep -q 'R41 planted fault' <<<"$out" ; then
    printf '::error:: the runner did not report the assertion message\n' >&2
    fail=1
  fi
  # `panicked at :` is the panic hook's FORMAT STRING, a static literal in the
  # data section. Seeing it means the post-mortem is scanning below
  # `__heap_base` and is reporting decoys alongside evidence — the failure
  # mode that would let it name the wrong test on a bigger binary.
  if grep -q 'panicked at :' <<<"$out" ; then
    printf '::error:: the runner reported a data-section decoy — the __heap_base filter is not applied\n' >&2
    fail=1
  fi
  [ "$fail" -eq 0 ] || return 1
  note "self-test PASS — the failing test was named, the passing one was not"
}

case "${1:---check}" in
  --check|"") cmd_check ;;
  --self-test) cmd_self_test ;;
  *) die "usage: scripts/wasm-tests.sh [--check | --self-test]" ;;
esac
