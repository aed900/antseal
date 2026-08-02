#!/usr/bin/env bash
# antseal fuzzing driver (Q9) — the ONE place run commands are written down.
#
#   scripts/fuzz.sh lint                     fmt + clippy the fuzz crate (stable)
#   scripts/fuzz.sh build [target...]        build the instrumented binaries
#   scripts/fuzz.sh smoke [seconds]          per-PR budget per target (default 90 s)
#   scripts/fuzz.sh long  [seconds]          interactive long budget (default 900 s)
#                                            NOTE: the SCHEDULED lane passes
#                                            600 explicitly (D61 §3). The two
#                                            are deliberately different and
#                                            `ci-lanes.sh fuzz-budget` reads
#                                            the workflow's, which is the one
#                                            that spends money.
#   scripts/fuzz.sh classify-failure         D61 §7: crash vs infrastructure red
#   scripts/fuzz.sh runs  <n> [target...]    a fixed ITERATION count (deterministic)
#   scripts/fuzz.sh selftest [target...]     prove a crash becomes an artifact
#   scripts/fuzz.sh cmin  [target...]        coverage-minimize the working corpus
#   scripts/fuzz.sh repro <target> <file>    re-run one crashing input
#
# Normative doc: docs/testing/fuzzing.md (corpus policy, cadence, triage).
# Target registry + ownership: fuzz/README.md.
#
# WHY A SCRIPT AND NOT INLINE CI STEPS: the corpus wiring is the fiddly part
# (`codec_round_trip` has no corpus of its own and takes both decode seed
# directories), and a run a contributor cannot reproduce byte-for-byte is a
# run whose green is not evidence. CI calls this file; so do humans.
#
# NO NETWORK, EVER: fuzzing is local. Nothing here uploads, publishes or
# registers anything.
set -uo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fuzz_dir="$repo/fuzz"
seed_root="$repo/testdata/fuzz-seeds"

# Every registered target. Adding one means editing fuzz/Cargo.toml, this
# list, and fuzz/README.md's table — deliberately, because a target nothing
# runs is worse than no target at all.
TARGETS=(manifest_decode bundle_decode codec_round_trip verify_bundle anchor_token)

# Toolchain: the pin in fuzz/rust-toolchain.toml governs, because cargo runs
# with `fuzz/` as its working directory. ANTSEAL_FUZZ_TOOLCHAIN overrides it
# for a contributor who already has some nightly installed; CI never sets it.
toolchain_arg=()
if [ -n "${ANTSEAL_FUZZ_TOOLCHAIN:-}" ]; then
  toolchain_arg=("+${ANTSEAL_FUZZ_TOOLCHAIN}")
fi

die()  { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }
note() { printf '\033[36m==>\033[0m %s\n' "$*"; }

known_target() {
  local t
  for t in "${TARGETS[@]}"; do [ "$t" = "$1" ] && return 0; done
  return 1
}

# Targets named on the command line, or all of them.
select_targets() {
  if [ "$#" -eq 0 ]; then
    printf '%s\n' "${TARGETS[@]}"
    return
  fi
  local t
  for t in "$@"; do
    known_target "$t" || die "unknown target '$t' (known: ${TARGETS[*]})"
    printf '%s\n' "$t"
  done
}

# The corpus directories a target runs over, first = the WRITABLE working
# corpus (libFuzzer writes new coverage there), rest = read-only seeds.
#
# `codec_round_trip` deliberately has no seed directory of its own: its input
# space is the union of the two decode corpora, so it reads both rather than
# committing the same bytes twice (testdata/fuzz-seeds/MANIFEST.json).
corpus_dirs() {
  local target="$1"
  local work="$fuzz_dir/corpus/$target"
  mkdir -p "$work"
  printf '%s\n' "$work"
  case "$target" in
    codec_round_trip)
      printf '%s\n%s\n' "$seed_root/manifest_decode" "$seed_root/bundle_decode" ;;
    *)
      [ -d "$seed_root/$target" ] && printf '%s\n' "$seed_root/$target" ;;
  esac
}

# `cargo fuzz` is exact-pinned like every other verdict-bearing dev tool
# (docs/dependency-policy.md §5). Checked, never installed by this script:
# installing a tool behind the operator's back is how an unreviewed version
# ends up producing the verdict.
CARGO_FUZZ_VERSION="0.13.2"
require_cargo_fuzz() {
  command -v cargo-fuzz >/dev/null 2>&1 \
    || die "cargo-fuzz is not installed. Pinned version (docs/dependency-policy.md §5):
    cargo install cargo-fuzz --version $CARGO_FUZZ_VERSION --locked"
  local have
  have="$(cargo fuzz --version 2>/dev/null | awk '{print $2}')"
  if [ "$have" != "$CARGO_FUZZ_VERSION" ]; then
    die "cargo-fuzz $have is installed but the pin is $CARGO_FUZZ_VERSION (dependency-policy §5).
    A version bump is a deliberate, reviewed event — move the literal in this script,
    the two workflow files and the policy doc together."
  fi
}

# Common libFuzzer flags.
#
#   -timeout=25        a single input taking >25 s is a HANG, i.e. a finding
#                      (F17's third invariant); the default 1200 s would let
#                      a quadratic parser look merely slow.
#   -rss_limit_mb=2048 libFuzzer's own out-of-memory backstop. The tighter,
#                      input-relative allocation budget is asserted inside
#                      the targets (fuzz/src/lib.rs).
#   -print_final_stats=1  so a lane's log records what the budget bought.
LIBFUZZER_FLAGS=(-timeout=25 -rss_limit_mb=2048 -print_final_stats=1)

run_fuzz() {
  local target="$1"; shift
  local -a dirs
  mapfile -t dirs < <(corpus_dirs "$target")
  ( cd "$fuzz_dir" \
    && cargo "${toolchain_arg[@]}" fuzz run "$target" "${dirs[@]}" -- "$@" )
}

cmd_lint() {
  note "fmt + clippy the fuzz crate on the WORKSPACE stable toolchain"
  local fail=0
  # Run from the repo root so the stable pin applies, not fuzz/'s nightly.
  ( cd "$repo" && cargo fmt --manifest-path fuzz/Cargo.toml --all -- --check ) || fail=1
  # clippy must build, and the instrumented build needs nightly; a plain
  # check on stable is enough to lint the source and is what the workspace
  # lanes do everywhere else.
  ( cd "$repo" && cargo clippy --manifest-path fuzz/Cargo.toml --all-targets --locked -- -D warnings ) || fail=1
  return "$fail"
}

cmd_build() {
  require_cargo_fuzz
  local t
  for t in $(select_targets "$@"); do
    note "build $t"
    ( cd "$fuzz_dir" && cargo "${toolchain_arg[@]}" fuzz build "$t" ) || return 1
  done
}

cmd_time_budget() {
  local seconds="$1"; shift
  require_cargo_fuzz
  local t fail=0
  for t in $(select_targets "$@"); do
    note "fuzz $t for ${seconds}s"
    run_fuzz "$t" "${LIBFUZZER_FLAGS[@]}" "-max_total_time=$seconds" || fail=1
  done
  return "$fail"
}

cmd_runs() {
  [ "$#" -ge 1 ] || die "usage: scripts/fuzz.sh runs <n> [target...]"
  local n="$1"; shift
  require_cargo_fuzz
  local t fail=0
  for t in $(select_targets "$@"); do
    note "fuzz $t for $n iterations"
    run_fuzz "$t" "${LIBFUZZER_FLAGS[@]}" "-runs=$n" || fail=1
  done
  return "$fail"
}

# The test-of-the-test, run BEFORE a green smoke run is believed — the same
# discipline `secret-guard` (planted fakes) and `wasm-bitmatch` (injected
# divergence) already apply. Arms fuzz/src/lib.rs's tripwire, so the target
# panics on its first input; the run MUST fail and MUST leave an artifact.
cmd_selftest() {
  require_cargo_fuzz
  local t fail=0
  for t in $(select_targets "$@"); do
    note "self-test $t (a synthetic crash MUST be caught and recorded)"
    rm -rf "$fuzz_dir/artifacts/$t"
    if ANTSEAL_FUZZ_SELFTEST="$t" run_fuzz "$t" -runs=1 -timeout=25 >/dev/null 2>&1; then
      printf 'FAIL %s: the injected panic did NOT fail the run\n' "$t" >&2
      fail=1
      continue
    fi
    if ! compgen -G "$fuzz_dir/artifacts/$t/*" >/dev/null; then
      printf 'FAIL %s: the run failed but no crash artifact was written\n' "$t" >&2
      fail=1
      continue
    fi
    printf 'ok   %s: crash caught, artifact written to fuzz/artifacts/%s/\n' "$t" "$t"
    # The artifact is the synthetic one, not a finding — do not leave it
    # lying around to be triaged tomorrow as a real crash.
    rm -rf "$fuzz_dir/artifacts/$t"
  done
  return "$fail"
}

cmd_cmin() {
  require_cargo_fuzz
  local t
  for t in $(select_targets "$@"); do
    note "coverage-minimize the working corpus of $t"
    ( cd "$fuzz_dir" && cargo "${toolchain_arg[@]}" fuzz cmin "$t" ) || return 1
  done
}

cmd_repro() {
  [ "$#" -eq 2 ] || die "usage: scripts/fuzz.sh repro <target> <artifact-file>"
  known_target "$1" || die "unknown target '$1'"
  require_cargo_fuzz
  ( cd "$fuzz_dir" && cargo "${toolchain_arg[@]}" fuzz run "$1" "$2" )
}

# D61 §7 — which KIND of red a scheduled run just had.
#
# The two are different findings and must not share a policy:
#
#   CRASH          fuzz/artifacts/ is non-empty, i.e. a reproducer was
#                  written. Release-blocking on the FIRST occurrence, no
#                  grace and no two-red rule — docs/testing/fuzzing.md §4's
#                  opening sentence is already normative ("A crash is
#                  release-blocking. No exceptions") and a crash is a
#                  finding, not flake. Triaged under D61 §8 before the next
#                  wave starts.
#   INFRASTRUCTURE no reproducer: build failure, toolchain rot, cargo-fuzz
#                  pin drift, cache or runner failure. D52's convention
#                  exactly — tracking note in the next wave's bookkeeping,
#                  two consecutive block wave starts until diagnosed.
#
# Importing D52's convention WHOLE would give a real crash a free night,
# which is the refinement D61 exists to make. Neither kind is ever a merge
# gate: `fuzz-long` is not a PR status context and never becomes one.
#
# Lives here rather than in the workflow because Q43's check-ci-shell.py
# refuses a `run:` block carrying logic — correctly: this is exactly the
# class of YAML-only shell that nobody executes before a push.
#
# Always exits 0. It is a CLASSIFIER, not a verdict: the step runs under
# `if: failure()` and the run is already red, so exiting non-zero would only
# obscure the original failure.
cmd_classify_failure() {
  if [ -n "$(find "$fuzz_dir/artifacts" -type f -print -quit 2>/dev/null)" ]; then
    printf '::error::CRASH — reproducer written. Release-blocking on the FIRST occurrence (D61 §7, docs/testing/fuzzing.md §4). Triage: D61 §8.\n'
    find "$fuzz_dir/artifacts" -type f | sed 's|^|  |'
    # If this fires on the scheduled lane it may be the tripwire leaking
    # rather than a finding — ANTSEAL_FUZZ_SELFTEST is unset in the
    # workflow, and a tripwire artifact would mean the self-test step
    # escaped its own scope, which is itself the finding (D61 §8 step 2).
    printf '::notice::Before triaging, confirm this is not the selftest tripwire (fuzz/src/lib.rs::selftest_tripwire says so in its panic message).\n'
  else
    printf '::warning::INFRASTRUCTURE RED — no reproducer. Tracking note; two consecutive block wave starts (D61 §7).\n'
  fi
  return 0
}

# The monthly-minimization input (docs/testing/fuzzing.md §3). Reports only:
# it never rewrites the committed tree. Lived inline in fuzz-nightly.yml
# until Q43 — CI shell that no local run ever executed.
cmd_corpus_report() {
  local t d
  for t in "${TARGETS[@]}"; do
    d="$repo/fuzz/corpus/$t"
    [ -d "$d" ] || continue
    printf '%-20s %6s files %10s\n' "$t" \
      "$(find "$d" -type f | wc -l)" "$(du -sh "$d" | cut -f1)"
  done
}

case "${1:-}" in
  lint)     shift; cmd_lint "$@" ;;
  build)    shift; cmd_build "$@" ;;
  smoke)    shift; s="${1:-90}";  [ "$#" -gt 0 ] && shift; cmd_time_budget "$s" "$@" ;;
  long)     shift; s="${1:-900}"; [ "$#" -gt 0 ] && shift; cmd_time_budget "$s" "$@" ;;
  runs)     shift; cmd_runs "$@" ;;
  selftest) shift; cmd_selftest "$@" ;;
  cmin)     shift; cmd_cmin "$@" ;;
  repro)    shift; cmd_repro "$@" ;;
  targets)  printf '%s\n' "${TARGETS[@]}" ;;
  corpus-report) shift; cmd_corpus_report "$@" ;;
  classify-failure) shift; cmd_classify_failure "$@" ;;
  ""|-h|--help|help)
    # The header comment block, however long it is: every line after the
    # shebang up to the first non-comment line. The fixed `2,30p` window this
    # replaces ran FIVE lines into the code (it printed `set -uo pipefail`,
    # `repo=…`, `fuzz_dir=…` and half the TARGETS comment) and drifted
    # further with every header edit — a help text that leaks its own
    # implementation is small, but it is the same class as a lane whose
    # prose and code disagree.
    awk 'NR > 1 { if ($0 !~ /^#/) exit; sub(/^# ?/, ""); print }' "${BASH_SOURCE[0]}" ;;
  *) die "unknown subcommand '$1' (try --help)" ;;
esac
