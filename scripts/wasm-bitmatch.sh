#!/usr/bin/env bash
# The Q5 native<->WASM bit-match lane, end to end.
#
#   ./scripts/wasm-bitmatch.sh                     # the lane: must be GREEN
#   ./scripts/wasm-bitmatch.sh --check             # same, explicitly
#   ./scripts/wasm-bitmatch.sh --self-test         # test-of-the-test: must go RED
#   ./scripts/wasm-bitmatch.sh --needs-run         # Q128's trigger: 0 = this
#                                                  # change can move the
#                                                  # comparison, 1 = it cannot,
#                                                  # 2 = undecidable
#   ./scripts/wasm-bitmatch.sh --trigger-self-test # the trigger's planted
#                                                  # change-sets (no cargo, no
#                                                  # git, milliseconds)
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
# ("HashMap-ordered serialization"). The lane must then go red WITH THE
# COMPARATOR SAYING SO, and this script inverts the verdict so a
# correctly-failing lane is a passing self-test. Nothing is left behind: the
# injected artifact is rebuilt clean at the end.
#
# "with the comparator saying so" is Q149 and is not decoration. Steps 1 and 2
# are now hard failures and step 3 matches on the divergence message, because
# a missing .wasm, a node error, an unemittable native transcript and a real
# byte divergence all exit non-zero, and only the last of them is what this
# lane claims to have proven. The rule and the register of instruments that
# owe it are in scripts/lib/red-arm.sh.
#
# ── TWO self-tests, deliberately, at two different places in the gate ──────
#
# `--self-test` (above) is the test of the LANE: does the byte comparison
# actually compare anything? It needs cargo and two wasm32 builds, ~53 s, so
# `local-gate.sh` runs it only when the trigger fires — immediately before the
# lane, never after, because a green comparison means nothing until the
# comparison has been shown able to go red.
#
# `--trigger-self-test` (Q128) is the test of the PREDICATE: does a change
# that can move the comparison actually select the lane? It reads nothing but
# its own string list, so the gate runs it UNCONDITIONALLY and before the
# trigger it guards. That placement is the point rather than habit, and it is
# Q125's vacuity link one file over: a path list that stops matching
# `testdata/vectors/` renders this lane `n/a` for ever, and a guard sitting
# behind the trigger would never run to say so.
#
# Doc: docs/wasm-toolchain.md; harness: crates/wasm-bitmatch/README.md.
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo" || exit 1

# The diff computation, shared with `wasm-tests.sh --needs-run` (Q128 is the
# third trigger, which is the condition that file set for factoring it out).
# shellcheck source=lib/gate-trigger.sh
. "$repo/scripts/lib/gate-trigger.sh"
# shellcheck source=lib/red-arm.sh
. "$repo/scripts/lib/red-arm.sh"

TARGET="wasm32-unknown-unknown"
WASM="target/${TARGET}/debug/wasm_bitmatch.wasm"
OUT_DIR="target/bitmatch"
NATIVE="${OUT_DIR}/native.transcript.json"

# ── Q128: does THIS change need the lane? ──────────────────────────────────
#
# Until Q128 this lane ran in no venue but CI, behind a manual CONTRIBUTING
# checkbox — Q125's defect one file over, and the same class: a wasm32
# EXECUTION lane that a green local gate says nothing about. Cost was never
# the reason it stayed out (measured 2026-08-09 on the 2-core dev host: 32 s
# for the lane plus 53 s for `--self-test`, CHEAPER than `wasm32-tests`). The
# reason was that its trigger is the OPPOSITE of that lane's:
#
#   `crates/wasm-bitmatch/build.rs` walks `testdata/vectors/` with no
#   hardcoded file lists and emits `include_bytes!` for everything it finds,
#   so a VECTORS-ONLY change is this lane's mandatory case — and precisely
#   the case `wasm-tests.sh`'s list must not match, since matching it would
#   fire a 2 min 10 s PQC suite on every vector edit.
#
# The two predicates are therefore asymmetric on purpose, and arm 4 of
# `--trigger-self-test` asserts that asymmetry in both directions rather than
# leaving it as a comment two files apart. A22 is the worked example: it added
# a whole vector kind, and the lane that certifies native<->wasm32
# byte-identity over it — the spec's M2 exit criterion — was the one the local
# gate did not run.
#
# Why each entry:
#   testdata/vectors/            build.rs walks this tree and embeds every
#                                file in it. The DIRECTORY PREFIX is the
#                                honest unit because build.rs's own
#                                `cargo::rerun-if-changed` is directory-level.
#                                NOT `testdata/`: that silently pulls in
#                                testdata/tamper/, testdata/anchors/ and every
#                                other fixture tree, none of which the harness
#                                reads (negative arm, trap 1).
#   crates/wasm-bitmatch/        the harness: build.rs (discovery + the D87
#                                budget), src/lib.rs (the wasm export),
#                                src/bin/bitmatch-emit.rs (the native
#                                transcript), tests/bitmatch.rs, Cargo.toml.
#                                A change to the lane is a change the lane
#                                must survive.
#   crates/antseal-core/         BOTH sides of the comparison are
#                                `antseal_core::test_util::vectors` under the
#                                `test-vectors` feature, so a core change
#                                moves what is compared on each side at once.
#                                The one entry this list shares with
#                                `wasm-tests.sh`, and shared correctly.
#   scripts/wasm-bitmatch.sh     this script — the three-step orchestration
#                                and the divergence injection.
#   scripts/wasm-bitmatch.mjs    the node host that instantiates the module,
#                                reads the transcript out of exported memory
#                                and does the byte comparison. It IS the
#                                comparison.
#   Cargo.toml / Cargo.lock      all three steps are `--locked`; a bit-match
#                                across two lockfiles compares two different
#                                programs and means nothing.
#   .cargo/config.toml           `[target.wasm32-unknown-unknown] rustflags`,
#                                which build_wasm below documents as
#                                deliberately NOT overridden (the P14
#                                getrandom recipe).
#   rust-toolchain.toml          the compiler that codegens both sides. A
#                                target-dependent codegen difference is the
#                                exact thing this lane exists to measure.
#
# Every entry is spelled with its leading directory, and directories with a
# trailing slash. `grep -F -f` is an unanchored substring match, so a bare
# stem is not a shorthand — it is a wider pattern: `bitmatch` alone would pull
# in `docs/decisions/D87-bitmatch-vector-carriage.md`, a docs-only edit that
# cannot change a single byte of the transcript (negative arm, trap 2).
#   crates/antseal-wasm/         R22's shipped page module, whose IMPORT TABLE
#                                this job also checks since D18 §5 R7/R8 — the
#                                allow-list rides this lane rather than getting
#                                a required context of its own, because this
#                                job already builds a wasm32 artifact and
#                                instantiates it in node. A change to the
#                                boundary can add an import; that is exactly
#                                what the check exists to see.
#   scripts/wasm-imports.mjs     the allow-list itself — the check's own
#                                inputs, same rule as the two entries above it.
BITMATCH_TRIGGER_PATHS='testdata/vectors/
crates/wasm-bitmatch/
crates/antseal-core/
crates/antseal-wasm/
scripts/wasm-bitmatch.sh
scripts/wasm-bitmatch.mjs
scripts/wasm-imports.mjs
Cargo.toml
Cargo.lock
.cargo/config.toml
rust-toolchain.toml'

# Factored so `--trigger-self-test` can feed it a planted change-set — the
# `gate-features.sh` (Q84) and `wasm-tests.sh` (Q125) pattern.
bitmatch_hits() {
  gate_trigger_hits "$BITMATCH_TRIGGER_PATHS"
}

cmd_needs_run() {
  gate_needs_run "$BITMATCH_TRIGGER_PATHS" bitmatch-relevant ANTSEAL_GATE_BITMATCH
}

# `WASM_TRIGGER_PATHS` as `scripts/wasm-tests.sh` actually spells it, read out
# of the file rather than restated here. Restating it is how the two copies
# would agree on the day this was written and diverge afterwards — Q130's
# lesson ("a scope rule expressed twice is a scope rule that will diverge"),
# and the same extraction-not-duplication trick `gate-features.sh` already
# uses to read `GATE_LIGHT_FEATURES` out of `local-gate.sh`.
#
# BITMATCH_SIBLING_WASM_TESTS is `--trigger-self-test`'s ONLY injection point,
# and it exists for the same reason `gate-features.sh`'s GATE_LOCAL_GATE does:
# the fault this arm guards against lives in ANOTHER script, so it cannot be
# planted any other way. The real file is the default and the parse under test
# is the real one.
#
# The path is a function, not a substitution repeated at each use site: when
# the extractor came up empty during Q128's own red run, the error named the
# DEFAULT file while the parse had been pointed at another one — a diagnostic
# that sends the reader to the wrong file is worse than none.
sibling_wasm_tests_path() {
  printf '%s\n' "${BITMATCH_SIBLING_WASM_TESTS:-$repo/scripts/wasm-tests.sh}"
}

sibling_wasm_trigger_paths() {
  # The quote is passed in rather than escaped, so the program stays
  # single-quoted and readable; `index(...) == 1` is a leading-anchor test, so
  # the prose two screens above that MENTIONS the variable cannot match.
  awk -v q="'" '
    index($0, "WASM_TRIGGER_PATHS=" q) == 1 { sub(/^WASM_TRIGGER_PATHS=./, ""); inside = 1 }
    inside {
      if (substr($0, length($0)) == q) { print substr($0, 1, length($0) - 1); exit }
      print
    }
  ' "$(sibling_wasm_tests_path)"
}

# THE ASYMMETRY ITSELF, asserted rather than described. Q125's list and this
# one must DISAGREE about vectors and AGREE about antseal-core, and nothing
# else in the tree says so: the reasoning lives in two comments in two files,
# and two comments cannot notice each other going stale (Q130's lesson — a
# scope rule expressed twice is a scope rule that will diverge).
#
# The concrete regression it catches: someone adds `testdata/vectors/` to
# WASM_TRIGGER_PATHS as an obvious-looking completion. Every arm in
# `wasm-tests.sh --self-test` stays green, every arm above stays green, and
# Q125's entire cost argument silently inverts — a 2 min 10 s PQC suite now
# runs on every vector edit, for a lane that reads no vector.
#
# Its own factored function so arm 5 can run it against a PLANTED copy of the
# sibling and require it to go red. An asymmetry check that has never been
# seen to fail is a comment with a `printf` in it.
asymmetry_check() {
  local fail=0 wasm_list path want_here want_there sel_here sel_there count
  wasm_list="$(sibling_wasm_trigger_paths)"
  if [ -z "$wasm_list" ]; then
    printf '::error:: could not read WASM_TRIGGER_PATHS out of %s — the asymmetry is then UNVERIFIED, not verified. Re-point sibling_wasm_trigger_paths at wherever that list now lives; do not delete this arm\n' \
      "$(sibling_wasm_tests_path)"
    return 1
  fi

  #   vectors  -> this lane only         (the reason Q128 is a second predicate)
  #   runner   -> the other lane only    (its host harness, not one of our steps)
  #   caps.rs  -> BOTH                   (shared antseal-core, shared on purpose)
  while read -r path want_here want_there; do
    [ -n "$path" ] || continue
    sel_here=no;  if [ -n "$(bitmatch_hits <<<"$path")" ]; then sel_here=yes; fi
    sel_there=no; if [ -n "$(gate_trigger_hits "$wasm_list" <<<"$path")" ]; then sel_there=yes; fi
    if [ "$sel_here" != "$want_here" ] || [ "$sel_there" != "$want_there" ]; then
      printf '::error:: %s: bit-match=%s wasm32-tests=%s, expected bit-match=%s wasm32-tests=%s. The two predicates are asymmetric ON PURPOSE (Q125/Q128) and this is the only place that says so — a vectors-only change must fire THIS lane and not the PQC one, and a change to antseal-core must fire both\n' \
        "$path" "$sel_here" "$sel_there" "$want_here" "$want_there"; fail=1
    else
      printf '  asymmetry:      %-52s -> bitmatch=%-3s wasm32-tests=%s\n' "$path" "$sel_here" "$sel_there"
    fi
  done <<'EOF'
testdata/vectors/v1/anchor/anchor.json yes no
scripts/wasm-test-runner.mjs no yes
crates/antseal-core/src/anchor/caps.rs yes yes
EOF

  # Herestring, not `printf | grep` — Q111: `grep -q`/`grep -c` closing the
  # pipe early makes printf die with EPIPE and `pipefail` invert the verdict.
  count=$(grep -c . <<<"$wasm_list" || true)
  printf '  asymmetry:      read %s entries from %s\n' \
    "$count" "$(sibling_wasm_tests_path) WASM_TRIGGER_PATHS"
  return "$fail"
}

# Q128's arms: the TRIGGER, over planted change-sets. No cargo, no git, no
# network — so it runs identically in CI's shallow checkout and costs
# milliseconds, which is what lets the gate run it unconditionally.
#
# `--self-test` above is what proves the COMPARISON works; this is what
# decides whether the local gate performs the comparison AT ALL, and a
# dropped entry here is silent — the gate stays green and simply checks less,
# which is exactly the shape of the gap Q128 exists to close.
trigger_self_test() {
  local fail=0 sel nonsel path expected
  expected='testdata/vectors/v1/anchor/anchor.json'

  # ARM 1 — positive, pinned to a vector file BY NAME. A22's anchor vector is
  # the worked example in Q128's own entry: the M2 exit criterion is
  # "native<->wasm32 byte-identity over the anchor vectors", it was met on
  # this file, and the lane that certifies it was the one the local gate did
  # not run. A trigger that would not fire for the change that motivated it
  # is not a fix.
  sel="$(bitmatch_hits <<<"$expected")"
  if [ "$sel" != "$expected" ]; then
    printf '::error:: a change to %s does NOT select the bit-match lane. A vectors-only change is this lane MANDATORY case — build.rs embeds every file under testdata/vectors/ — and A22 is the worked example: it added a whole vector kind and this lane is what certifies the M2 exit criterion over it. Selected: [%s]\n' \
      "$expected" "$sel"; fail=1
  else
    printf '  planted change: %-52s -> RUN\n' "$expected (A22, the M2 exit criterion)"
  fi

  # ARM 2 — the rest of the inputs, each of which can move the transcript or
  # the comparison without touching a vector. None of them is reachable from
  # arm 1, so each needs an entry of its own or a change to it reaches no
  # wasm32 execution before a push.
  for path in crates/wasm-bitmatch/build.rs \
              crates/wasm-bitmatch/src/bin/bitmatch-emit.rs \
              crates/antseal-core/src/test_util/vectors_anchor.rs \
              crates/antseal-wasm/src/boundary.rs \
              scripts/wasm-imports.mjs \
              scripts/wasm-bitmatch.mjs \
              scripts/wasm-bitmatch.sh \
              Cargo.lock .cargo/config.toml rust-toolchain.toml; do
    if [ -z "$(bitmatch_hits <<<"$path")" ]; then
      printf '::error:: %s does NOT select the bit-match lane, so a change to it would reach no native<->wasm32 comparison before a push\n' "$path"; fail=1
    else
      printf '  planted change: %-52s -> RUN\n' "$path"
    fi
  done

  # ARM 3 — negative / anti-vacuity, and load-bearing three times over.
  #
  #   (a) `grep -F -f` treats a BLANK pattern line as "match everything", so
  #       one stray empty entry in BITMATCH_TRIGGER_PATHS would select the
  #       lane for every change and every arm above would still pass;
  #   (b) `testdata/tamper/MATRIX.json` and `testdata/anchors/...` are here
  #       for TRAP 1: shortening the vectors entry to `testdata/` reads like
  #       a harmless simplification and silently pulls in every fixture tree
  #       in the repository;
  #   (c) `docs/decisions/D87-bitmatch-vector-carriage.md` is here for TRAP 2:
  #       dropping the directory prefix to a bare `bitmatch` stem pulls in the
  #       harness's own decision document, which cannot move a byte;
  #   (d) `scripts/wasm-tests.sh`, `scripts/wasm-test-runner.mjs` and
  #       `scripts/wasm-toolchain-audit.sh` are the DELIBERATE ASYMMETRY. They
  #       are the other wasm32 lane's inputs, none of them is one of this
  #       lane's three steps, and an over-broad entry such as a bare `.mjs`
  #       or `wasm-test` would swallow them.
  nonsel="$(bitmatch_hits <<<"crates/antseal-cli/src/listing.rs
crates/antseal-anchor/src/ots/engine.rs
crates/antseal-net/src/backend.rs
testdata/tamper/MATRIX.json
testdata/anchors/A25-bootstrap/CAPTURE.log
docs/decisions/D87-bitmatch-vector-carriage.md
docs/wasm-toolchain.md
.github/workflows/ci.yml
README.md
CONTRIBUTING.md
TODO.md
tasks/Q.md
scripts/wasm-tests.sh
scripts/wasm-test-runner.mjs
scripts/wasm-toolchain-audit.sh" | tr '\n' ' ')"
  if [ -n "$nonsel" ]; then
    printf '::error:: paths that cannot move the bit-match selected the lane: [%s]. Three ways this happens: a blank line in BITMATCH_TRIGGER_PATHS (grep -F -f then matches everything, turning the trigger into a constant and the n/a state into a lie); `testdata/vectors/` shortened to `testdata/`, which swallows every fixture tree; or a directory prefix dropped to a bare stem, which swallows the docs that merely NAME the harness\n' "$nonsel"; fail=1
  else
    printf '  planted change: %-52s -> n/a\n' "cli/anchor/net, testdata/{tamper,anchors}, docs, wasm-tests"
  fi

  # ARM 4 — the asymmetry, against the sibling list as it is actually spelled
  # today. Contract and rationale on `asymmetry_check` above.
  asymmetry_check || fail=1

  # ARM 5 — arm 4's OWN planted fault, because an arm that has only ever been
  # seen green proves nothing about what it would catch. The fault is the
  # realistic one: `testdata/vectors/` appended to the sibling's list, which
  # is what a well-meaning "the wasm32 trigger is missing the vectors" patch
  # looks like. Planted into a COPY — the real script is never written to.
  local copy out
  copy="$(mktemp)" || { printf '::error:: mktemp failed; arm 5 cannot plant its fault\n'; return 1; }
  awk -v ins='testdata/vectors/' \
      '{ print } index($0, "WASM_TRIGGER_PATHS=") == 1 { print ins }' \
      "$repo/scripts/wasm-tests.sh" > "$copy"
  if out="$(BITMATCH_SIBLING_WASM_TESTS="$copy" asymmetry_check 2>&1)"; then
    printf '::error:: arm 4 stayed GREEN with `testdata/vectors/` planted in the sibling list, so it is not actually comparing the two predicates and every asymmetry line above is decoration:\n%s\n' "$out"; fail=1
  elif ! grep -q 'testdata/vectors/v1/anchor/anchor.json' <<<"$out"; then
    printf '::error:: arm 4 went red for the WRONG row — the planted fault is about the vectors path and the error does not name it:\n%s\n' "$out"; fail=1
  else
    printf '  planted fault:  %-52s -> RED\n' "testdata/vectors/ added to WASM_TRIGGER_PATHS"
  fi
  rm -f "$copy"

  [ "$fail" -eq 0 ] || return 1
  printf 'trigger self-test PASS — a vectors-only change fires this lane and NOT wasm32-tests; unrelated paths fire neither\n'
}

mkdir_out() { mkdir -p "${OUT_DIR}"; }

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

cmd_lane() {
  local SELF_TEST="$1" status arm
  # The message the comparator prints when it finds a byte divergence — the
  # one thing `--self-test` is entitled to conclude from a red lane. Read from
  # scripts/wasm-bitmatch.mjs, where `fail(...)` emits it.
  local expected='wasm32 transcript differs from native'

  mkdir_out

  # ERRORS IN STEPS 1 AND 2 ARE HARD FAILURES (Q149). `set -e` is SUSPENDED
  # throughout this function — it is invoked on the left of `||` at the case
  # below — so before this, a build that never happened fell straight through
  # to step 3, where node failed on an absent or stale artifact, and that
  # nonzero was reported as "the injected divergence turned the lane red".
  echo "== 1/3 build the harness for ${TARGET} =="
  if [ "${SELF_TEST}" -eq 1 ]; then
    echo "   (--self-test: injecting a wasm32-only platform divergence)"
    if ! build_wasm_diverged; then
      echo "::error::--self-test could not build the divergence-injected wasm32 artifact, so NO divergence was ever injected and a red lane below would prove nothing."
      build_wasm >/dev/null 2>&1 || true
      return 1
    fi
  elif ! build_wasm; then
    echo "::error::the wasm32 build failed — the lane has no right-hand side to compare."
    return 1
  fi

  echo "== 2/3 emit the native transcript =="
  if ! cargo run -q -p wasm-bitmatch --bin bitmatch-emit --locked -- "${NATIVE}"; then
    echo "::error::the native transcript could not be emitted — the lane has no left-hand side to compare against."
    [ "${SELF_TEST}" -eq 1 ] && build_wasm >/dev/null 2>&1
    return 1
  fi

  echo "== 3/3 execute on ${TARGET} and byte-compare =="

  if [ "${SELF_TEST}" -eq 1 ]; then
    # THE red arm. `assert_red`, not "did node exit non-zero": a missing
    # .wasm, a node error, a transcript that is not valid JSON and a real byte
    # divergence all exit 1, and only the last is the platform-divergence
    # class this arm claims to have observed.
    assert_red "${expected}" node scripts/wasm-bitmatch.mjs "${WASM}" "${NATIVE}"
    arm=$?
    # Rebuild clean before reporting, so an interrupted self-test can never
    # leave a divergence-injected artifact behind for the next run.
    build_wasm >/dev/null
    if [ "${arm}" -ne 0 ]; then
      echo
      echo "::error::SELF-TEST FAILED: an injected wasm32-only divergence did NOT turn the lane red the way a divergence turns it red."
      echo "::error::The bit-match is not actually comparing anything — fix it before trusting a green lane."
      red_arm_evidence "${arm}" "${expected}"
      return 1
    fi
    printf '%s\n' "${ARM_OUT}"
    echo
    echo "SELF-TEST PASSED: the injected divergence turned the lane red (exit ${ARM_STATUS}) AND the comparator reported it as \"${expected}\", as required."
    return 0
  fi

  status=0
  node scripts/wasm-bitmatch.mjs "${WASM}" "${NATIVE}" || status=$?
  [ "${status}" -eq 0 ] || return "${status}"

  # ── R22's import allow-list, riding this job (D18 §5 R7/R8) ─────────────
  #
  # A SECOND artifact, a SEPARATE property, and deliberately NOT a second
  # required context: CI minutes are a stated constraint and this job already
  # has the toolchain, the wasm32 target and node. The bit-match above proves
  # the two builds AGREE; this proves the shipped module cannot ASK THE HOST
  # for anything R22 says it must not.
  #
  # It runs against the artifact `cargo` emits, not the one `wasm-pack` does,
  # and that is a deliberate scoping: `wasm-pack` and `wasm-bindgen-cli` are
  # not installed in CI and installing them here would cost the minutes this
  # rule was told not to spend. The import table is a function of the DECLARED
  # bindings, not of the post-processing step — measured at R22's landing: the
  # cargo artifact carries the same three shims in their pre-CLI placeholder
  # spelling plus the describe/xform pair the CLI resolves away, and
  # `scripts/wasm-imports.mjs` enumerates both spellings. The wasm-pack
  # artifact is checked by `scripts/wasm-pack-build.sh`, which is the only
  # thing that produces one.
  echo
  echo "== R22: the shipped module's import table (D18 §5 R7) =="
  # Self-test FIRST, always — an allow-list that has never refused anything is
  # a list with a `console.log` in it.
  node scripts/wasm-imports.mjs --self-test || return 1
  cargo build -p antseal-wasm --target "${TARGET}" --locked || {
    echo "::error::the antseal-wasm wasm32 build failed — there is no import table to check."
    return 1
  }
  node scripts/wasm-imports.mjs "target/${TARGET}/debug/antseal_wasm.wasm" || return 1
  return 0
}

# `|| rc=$?` on every branch: errexit is suspended for a function invoked on
# the left of `||`, which is what lets `cmd_needs_run` return its 1 and 2
# rather than having `set -e` turn the first non-zero step into an exit.
rc=0
case "${1:-}" in
  ""|--check)          cmd_lane 0 || rc=$? ;;
  --self-test)         cmd_lane 1 || rc=$? ;;
  --needs-run)         cmd_needs_run || rc=$? ;;
  --trigger-self-test) trigger_self_test || rc=$? ;;
  *)
    echo "usage: $0 [--check | --self-test | --needs-run | --trigger-self-test]" >&2
    exit 2 ;;
esac
exit "$rc"
