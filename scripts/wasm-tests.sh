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
#   scripts/wasm-tests.sh --needs-run  Q125's trigger: 0 = this change can
#                                      move wasm32 behaviour, 1 = it cannot,
#                                      2 = undecidable
#   scripts/wasm-tests.sh --self-test  the trigger's planted change-sets, then
#                                      a failing #[test] on wasm32 to prove
#                                      the runner NAMES it (R41)
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

# The diff computation, shared with `wasm-bitmatch.sh --needs-run` since Q128.
# shellcheck source=lib/gate-trigger.sh
. "$repo/scripts/lib/gate-trigger.sh"

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

# ── Q125: does THIS change need the lane? ──────────────────────────────────
#
# `scripts/local-gate.sh`'s `wasm32-build` lane is a `cargo build`. THIS
# script is the only thing in the repository that EXECUTES antseal-core's
# tests on wasm32, and until Q125 it ran in no venue but CI. The gap has a
# measured cost: at `6f69e1a`, `size_of::<x509_cert::Certificate>()` — 376 on
# wasm32 against 512 on x86-64 — reddened `wasm32-core-tests` on two equality
# rows in `anchor/caps.rs` that a green local gate plus a green native
# `cargo test` structurally could not see.
#
# Diff-triggered rather than always-on because it costs minutes on a 2-core
# host and no cache will fix that. Measured 2026-08-09 on the 2-core dev
# machine, three runs of `--check`: 3 min 42 s cold, then 2 min 46 s and
# 2 min 10 s warm. The warm cost splits as **2 min 15 s of node EXECUTING the
# module** — cargo reports `Finished ... in 0.31s`, so the compile is entirely
# cached — plus 5 s for the toolchain audit. For comparison CI reports
# 2 min 40 s for the same step (run 31255637376; `ubuntu-latest` is the same
# 2-core class as this host, D52 §E2). The bill is the post-quantum suite under
# `WebAssembly.instantiate` in a 1.3 GB linear memory: it is EXECUTION, not
# compilation, so no warm target dir and no `rust-cache` will shrink it, which
# is exactly why this is a trigger and not a `run` line.
#
# Same SHAPE as `gate-features.sh --needs-heavy`: same `ANTSEAL_GATE_BASE`
# override, same committed-since-base PLUS uncommitted change-set, same 0/1/2
# contract. This was written as a deliberate second copy, with the condition
# for stopping written down: "if a third trigger appears, factor the diff
# computation out then, not now."
#
# Q128 IS THAT THIRD TRIGGER (`wasm-bitmatch.sh --needs-run`), and the diff
# computation now lives in `scripts/lib/gate-trigger.sh`. What did NOT move is
# the LIST: it still answers "can wasm32 behaviour move?", which is a
# different question from "did the storage path change?" and from "can the
# native<->wasm32 comparison move?", and it is still the part `--self-test`
# plants change-sets against. `scripts/gate-features.sh` remains a third copy
# of the computation — see the note in the helper.
#
# Why each entry:
#   crates/antseal-core/        the crate whose --lib tests this lane runs
#   Cargo.toml / Cargo.lock     an x509-cert/der bump moving a layout is the
#                               named failure mode of the caps.rs rows above
#   .cargo/config.toml          the `runner` that executes the .wasm, and the
#                               getrandom `--cfg` half of the P14 recipe
#   rust-toolchain.toml         the compiler that lays the types out
#   scripts/wasm-test-runner.mjs      the host harness + execution witness
#   scripts/wasm-tests.sh             a change to the lane is a change the
#                                     lane must survive
#   scripts/wasm-toolchain-audit.sh   step 2 of cmd_check
#
# NOT here, and NOT an oversight: `crates/wasm-bitmatch/` and
# `testdata/vectors/`. `wasm-bitmatch` is the OTHER wasm32 execution lane and
# since Q128 it is in the local gate with its OWN predicate
# (`wasm-bitmatch.sh --needs-run`), because its trigger is the opposite of
# this one's: its `build.rs` walks `testdata/vectors/`, so a vectors-only
# change is its mandatory case and precisely the case this list must not
# match — matching it would fire this 2 min 10 s PQC suite on every vector
# edit, for a lane that reads no vector. That asymmetry is ASSERTED, not
# merely described: `wasm-bitmatch.sh --trigger-self-test` arm 4 reads this
# very list out of this file and fails if the two predicates stop disagreeing
# about vectors or stop agreeing about `crates/antseal-core/`. Adding
# `testdata/vectors/` here will turn that arm red, and that is the point.
# The harness's manifest already selects this lane via `Cargo.toml`, which is
# all `wasm-toolchain-audit.sh` reads of it.
WASM_TRIGGER_PATHS='crates/antseal-core/
Cargo.toml
Cargo.lock
.cargo/config.toml
rust-toolchain.toml
scripts/wasm-test-runner.mjs
scripts/wasm-tests.sh
scripts/wasm-toolchain-audit.sh'

# Factored out so `--self-test` can feed it a planted change-set — the
# `gate-features.sh` pattern (Q84), and the reason the trigger below gets both
# a positive and a negative arm. Reads changed paths on stdin, prints the ones
# that select the lane.
wasm_hits() {
  gate_trigger_hits "$WASM_TRIGGER_PATHS"
}

cmd_needs_run() {
  gate_needs_run "$WASM_TRIGGER_PATHS" wasm32-relevant ANTSEAL_GATE_WASM
}

# Q125's arms: the TRIGGER, both directions, over planted change-sets (no git
# ref needed, so this runs identically in CI's shallow checkout).
#
# `cmd_check` is what the lane runs; this is what decides whether the local
# gate runs it AT ALL, and a dropped entry here is silent — the gate stays
# green and simply checks less, which is precisely the shape of the gap Q125
# exists to close.
trigger_self_test() {
  local fail=0 sel nonsel path
  local expected
  expected='crates/antseal-core/src/anchor/caps.rs'

  # The positive arm is pinned to the file whose absence from this lane had a
  # MEASURED cost. A trigger that would not have fired for the incident it
  # exists for is not a fix.
  sel="$(printf '%s\n' "$expected" | wasm_hits)"
  if [ "$sel" != "$expected" ]; then
    printf '::error:: a change to %s does NOT select the wasm32 test lane. That is the exact file whose unconditional 64-bit layout assertions reddened `wasm32-core-tests` at 6f69e1a while the local gate stayed green. Selected: [%s]\n' \
      "$expected" "$sel"; fail=1
  else
    printf '  planted change: %-45s -> RUN\n' "$expected (the 6f69e1a incident)"
  fi

  # The non-Rust inputs. None of them lives under `crates/`, so each needs an
  # entry of its own or a change to it reaches no wasm32 execution before a
  # push: the runner that executes the module, the toolchain that lays the
  # types out, the resolved dependency versions whose layout the caps.rs rows
  # assert, and the two scripts the lane is made of.
  for path in .cargo/config.toml scripts/wasm-test-runner.mjs \
              scripts/wasm-toolchain-audit.sh rust-toolchain.toml Cargo.lock; do
    if [ -z "$(printf '%s\n' "$path" | wasm_hits)" ]; then
      printf '::error:: %s does NOT select the wasm32 test lane, so a change to it would reach no wasm32 execution before a push\n' "$path"; fail=1
    else
      printf '  planted change: %-45s -> RUN\n' "$path"
    fi
  done

  # The negative arm is anti-vacuity and load-bearing: `grep -F -f` treats a
  # BLANK pattern line as "match everything", so one stray empty entry in
  # WASM_TRIGGER_PATHS would select the lane for every change and every
  # positive arm above would still pass.
  nonsel="$(printf '%s\n' crates/antseal-cli/src/listing.rs docs/wasm-toolchain.md \
    crates/antseal-anchor/src/ots/engine.rs README.md | wasm_hits | tr '\n' ' ')"
  if [ -n "$nonsel" ]; then
    printf '::error:: paths that cannot move wasm32 behaviour selected the lane: [%s]. A blank line in WASM_TRIGGER_PATHS makes `grep -F -f` match everything, which turns the trigger into a constant and the n/a state into a lie\n' "$nonsel"; fail=1
  else
    printf '  planted change: %-45s -> n/a\n' "antseal-cli/, antseal-anchor/, docs/, README.md"
  fi

  [ "$fail" -eq 0 ] || return 1
}

# R41's planted fault: a real libtest binary on the real target with a real
# failing `#[test]`. Asserts the failure is attributed to the RIGHT test —
# naming some test would pass a weaker check while still being useless.
cmd_self_test() {
  local dir status out fail=0

  note "Q125 trigger: which changed paths select this lane (planted change-sets, no git)"
  trigger_self_test || fail=1

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
  note "self-test PASS — the trigger fires on the 6f69e1a change-set and not on unrelated paths; the failing wasm32 test was named, the passing one was not"
}

case "${1:---check}" in
  --check|"") cmd_check ;;
  --needs-run) cmd_needs_run ;;
  --self-test) cmd_self_test ;;
  *) die "usage: scripts/wasm-tests.sh [--check | --needs-run | --self-test]" ;;
esac
