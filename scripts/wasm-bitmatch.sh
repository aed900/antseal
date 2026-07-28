#!/usr/bin/env bash
# The Q5 native<->WASM bit-match lane, end to end.
#
#   ./scripts/wasm-bitmatch.sh              # the lane: must be GREEN
#   ./scripts/wasm-bitmatch.sh --self-test  # test-of-the-test: must go RED
#
# Contract (MVP-SPEC.md lines 167/169; tasks/Q.md Q5): executing every
# committed golden vector through `antseal_core::test_util::vectors` produces
# BYTE-IDENTICAL output natively and under wasm32-unknown-unknown.
#
# Three steps, each individually re-runnable:
#   1. build the harness for wasm32 (vectors are embedded by its build.rs,
#      which walks testdata/vectors/ — no per-vector wiring anywhere);
#   2. run the NATIVE binary to emit its transcript to a file;
#   3. run the wasm32 module in node and byte-compare against that file.
#
# --self-test rebuilds ONLY the wasm32 side with
# `--cfg antseal_bitmatch_inject_divergence`, which makes the wasm transcript
# order its entries differently — the platform-divergence class Q5 names
# ("HashMap-ordered serialization"). The lane must then go red; this script
# inverts the exit code so a correctly-failing lane is a passing self-test.
# Nothing is left behind: the injected artifact is rebuilt clean at the end.
#
# Doc: docs/wasm-toolchain.md; harness: crates/wasm-bitmatch/README.md.
set -euo pipefail

cd "$(dirname "$0")/.."

SELF_TEST=0
if [ "${1:-}" = "--self-test" ]; then
  SELF_TEST=1
elif [ -n "${1:-}" ]; then
  echo "usage: $0 [--self-test]" >&2
  exit 2
fi

TARGET="wasm32-unknown-unknown"
WASM="target/${TARGET}/debug/wasm_bitmatch.wasm"
OUT_DIR="target/bitmatch"
NATIVE="${OUT_DIR}/native.transcript.json"

mkdir -p "${OUT_DIR}"

# `--locked` everywhere: lockfile drift must fail loudly rather than
# silently change what is being compared.
build_wasm() {
  # DELIBERATELY does not set RUSTFLAGS: the environment variable OVERRIDES
  # `[target.wasm32-unknown-unknown] rustflags` in .cargo/config.toml, which
  # is where the getrandom `--cfg` half of the recipe lives (P14). The lane
  # must compile with exactly the flags a normal wasm32 build gets.
  cargo build -p wasm-bitmatch --target "${TARGET}" --locked
}

build_wasm_diverged() {
  # The self-test is the one place RUSTFLAGS is set, and it therefore drops
  # the config's `--cfg getrandom_backend="wasm_js"` for this build only.
  # Harmless: that flag is inert (no wasm32 graph pulls getrandom — see
  # ./scripts/wasm-toolchain-audit.sh), and the artifact is rebuilt clean
  # immediately afterwards.
  RUSTFLAGS='--cfg antseal_bitmatch_inject_divergence' \
    cargo build -p wasm-bitmatch --target "${TARGET}" --locked
}

echo "== 1/3 build the harness for ${TARGET} =="
if [ "${SELF_TEST}" -eq 1 ]; then
  echo "   (--self-test: injecting a wasm32-only platform divergence)"
  build_wasm_diverged
else
  build_wasm
fi

echo "== 2/3 emit the native transcript =="
cargo run -q -p wasm-bitmatch --bin bitmatch-emit --locked -- "${NATIVE}"

echo "== 3/3 execute on ${TARGET} and byte-compare =="
status=0
node scripts/wasm-bitmatch.mjs "${WASM}" "${NATIVE}" || status=$?

if [ "${SELF_TEST}" -eq 1 ]; then
  # Rebuild clean before reporting, so an interrupted self-test can never
  # leave a divergence-injected artifact behind for the next run.
  build_wasm >/dev/null
  if [ "${status}" -eq 0 ]; then
    echo
    echo "::error::SELF-TEST FAILED: an injected wasm32-only divergence did NOT turn the lane red."
    echo "The bit-match is not actually comparing anything — fix it before trusting a green lane."
    exit 1
  fi
  echo
  echo "SELF-TEST PASSED: the injected divergence turned the lane red (exit ${status}), as required."
  exit 0
fi

exit "${status}"
