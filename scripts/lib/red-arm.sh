# shellcheck shell=bash
# THE RED-ARM RULE. SOURCED, never run — it defines three functions, sets two
# globals to empty, and does nothing else.
#
# ── The rule ───────────────────────────────────────────────────────────────
#
#   A RED ARM MUST MATCH ON THE MESSAGE THE CHECK PRINTS WHEN IT FINDS THE
#   PLANTED FAULT, NOT ON THE EXIT STATUS ALONE.
#
# A self-test's red arm plants a fault and requires the checker to fail. If it
# judges that failure on exit status alone, then ANY nonzero exit satisfies it
# — a traceback, a missing file, an import error, a fixture the mutation left
# unparseable, a build step that never ran — and the arm certifies a surface
# it never exercised. It reports "RED as required" and pins nothing.
#
# This is a repeat class, not a hypothesis. Three measured instances:
#
#   wave 12  the CBOR self-test planted each fault INSIDE the `try` that
#            judged it, so a mutation the harness could not plant printed
#            "RED as required" and the run announced `self-test PASSED`, rc 0.
#   wave 13  `check-traceability.py`: deleting check 6's unregistered-owner
#            branch left its case "going red" via a `KeyError` on the very
#            lookup that branch guarded. Under exit-code-only validation that
#            case pinned nothing.
#   wave 14  (Q149) the four instruments listed below, all four measured green
#            with the planted fault replaced by an unrelated crash.
#
# ── Who must obey it (the register; keep it current) ───────────────────────
#
# Every instrument in this repository with a red arm, and how it judges:
#
#   scripts/cross-check.sh        `prove_can_fail` — assert_red, per-surface
#                                 expected message (`expected_mismatch_for`
#                                 for the generators, explicit at the C27,
#                                 corpus and Unicode call sites)
#   scripts/wasm-bitmatch.sh      `cmd_lane --self-test` — assert_red on the
#                                 node comparator's divergence message; steps
#                                 1 and 2 are hard failures so a build that
#                                 does not happen can no longer be counted as
#                                 a divergence that did.
#                                 `trigger_self_test` arm 5 — already obeyed
#                                 the rule before Q149, in the raw
#                                 `grep -q` shape.
#   scripts/vector-freeze.sh      both arms — assert_red, and `check_digests`
#                                 now classifies MODIFIED vs MISSING so the
#                                 two arms can tell each other apart. Its
#                                 victim is also now chosen from the manifest
#                                 rather than from a directory walk: see the
#                                 PLANTING direction below.
#   scripts/format-freeze.sh      all four arms — same, plus the
#                                 unfrozen-discovery message.
#   scripts/gate-features.sh      four arms in the raw shape this file
#                                 generalises: `if [ $? -eq 0 ] || ! grep -q
#                                 '<expected>' <<<"$out"`. The in-repo
#                                 template; unconverted on purpose, so the
#                                 rule is legible without this helper.
#   scripts/cargo-free.sh         `--self-test` — assert_red through the local
#                                 `arm_case` wrapper, eight arms, each matching
#                                 one of the named MSG_* constants the guard
#                                 prints. The messages are constants rather
#                                 than literals precisely so an arm and the
#                                 sentence it proves cannot drift apart.
#                                 It also obeys the rule in a THIRD direction
#                                 this file had not named: every child is
#                                 launched with GITHUB_PATH and RUNNER_TEMP
#                                 SCRUBBED (`env -u`) and then set explicitly.
#                                 Measured 2026-08-11: its `--arm` refusal arm
#                                 passed standalone and proved NOTHING when the
#                                 self-test was invoked from a harness that had
#                                 GITHUB_PATH set, because `env VAR=…` does not
#                                 unset what it does not name. An arm that
#                                 inherits the caller's environment is an arm
#                                 the caller can satisfy — the same class as
#                                 judging on exit status, one level out.
#   scripts/check-ci-shell.py     structurally immune: its arm reads a
#                                 RETURNED failure list in-process, so a crash
#                                 propagates and fails the harness rather than
#                                 satisfying an arm. Its lesser weakness is
#                                 recorded at its own `self_test`.
#   scripts/check-ci-paths.py     the same in-process shape, and it CLOSES that
#                                 lesser weakness: every failure carries a RULE
#                                 TAG (R1..R6, R4a/R4c/R4e) and each of its
#                                 eighteen arms requires its own tag, so a
#                                 finding unrelated to the planted fault cannot
#                                 satisfy an arm. Nine arms plant in the tree
#                                 and restore in a `finally`; the rest pass a
#                                 mutated exclusion list as an argument, which
#                                 touches no file at all. Its own first version
#                                 FAILED this self-test — the MVP-SPEC.md arm
#                                 stayed green because both readers spell that
#                                 path as an offset from CARGO_MANIFEST_DIR and
#                                 the resolver anchored on the source file —
#                                 which is the evidence that the arms were not
#                                 fitted to the check. D138/Q239.
#
# Python instruments cannot source this file. The rule is the same for them
# and the shape is `check()`-returns-a-list, as `check-ci-shell.py` does it:
# judge on the value the check RETURNED, never on the fact that something
# exited nonzero.
#
# A FIFTH INSTRUMENT: source this file, use `assert_red`, and add a line to
# the register above. An instrument that is not in the register has not been
# checked against the rule — that is the whole point of writing the register
# here rather than in a document, next to the mechanism it describes.
#
# ── The same class in the PLANTING direction ───────────────────────────────
#
# An arm can also certify a surface it never exercised by planting its fault
# in the wrong place. `vector-freeze.sh` chose its victim with
# `find … -name '*.json' | LC_ALL=C sort | head -n 1`, which returns whatever
# is on disk and sorts a dot-directory first; a stray `v1/.vscode/settings.json`
# became the victim, mutating it moved nothing the freeze pins, and the arm
# condemned a guard that was working. Measured 2026-08-10.
#
# So: plant the fault in a subject the check DEMONSTRABLY covers — for a
# freeze, a path the manifest names; for a registry, a key the parser reads —
# and derive the subject from the check's own declaration of its scope, never
# from a walk that can pick up something the check ignores.
#
# ── Not the rule: "reject tracebacks" ──────────────────────────────────────
#
# Tempting, and wrong here. `testdata/vectors/v1/crypto/reference.py` signals
# a failed known-answer check by raising `AssertionError` — its DESIGNED
# failure is a traceback, and a blanket traceback ban would make its red arm
# unsatisfiable. Matching the expected message covers both: it accepts that
# traceback, whose text names the vector, and rejects every other one.
#
# ── The contract ───────────────────────────────────────────────────────────
#
# Every function captures stdout AND stderr into `ARM_OUT` and the exit status
# into `ARM_STATUS`. Capturing is not incidental: discarding the output is
# what made the exit status the only thing an arm COULD judge on, and it is
# also why a genuinely broken arm printed no evidence for the reader.
#
# All three are safe under `set -euo pipefail`. The capture is written as
# `ARM_OUT="$(...)" && ARM_STATUS=0 || ARM_STATUS=$?` so errexit is suspended
# for the command being judged — the raw `out="$(cmd)"; if [ $? -eq 0 ]` shape
# gate-features.sh uses is only safe there because that script runs under
# `set -uo pipefail` with no `-e`.
ARM_OUT=""
ARM_STATUS=0

# assert_red <expected-literal> <command> [args...]
#
# Run the command; require it to fail AND to say why. Returns:
#
#   0  SATISFIED — nonzero status and `<expected-literal>` present in ARM_OUT
#   1  GREEN     — the command succeeded; the planted fault was not caught
#   2  WRONG RED — nonzero, but the check never printed what it prints when it
#                  finds THIS fault. This is Q149's return code: today's arms
#                  cannot distinguish it from 0, which is the whole defect.
#
# The match is `grep -F` (fixed string): the expected literal is a sentence
# the check prints, not a pattern, and nobody should have to regex-escape it.
# Herestring rather than a pipe — Q111: `grep -q` closes the pipe early, the
# writer dies of EPIPE, and `pipefail` inverts the verdict.
assert_red() {
  local expected="$1"
  shift
  ARM_OUT="$("$@" 2>&1)" && ARM_STATUS=0 || ARM_STATUS=$?
  [ "$ARM_STATUS" -eq 0 ] && return 1
  grep -qF -- "$expected" <<<"$ARM_OUT" || return 2
  return 0
}

# assert_green <command> [args...]
#
# The control direction: 0 if the command succeeded, 1 otherwise. Exists so a
# control arm's failure carries EVIDENCE — the arms this replaced all ran
# `>/dev/null 2>&1` and reported "the unmodified copy already fails" with
# nothing to say what failed.
assert_green() {
  ARM_OUT="$("$@" 2>&1)" && ARM_STATUS=0 || ARM_STATUS=$?
  [ "$ARM_STATUS" -eq 0 ]
}
# `red_arm_evidence <assert_red-return-code> <expected-literal>`
#
# The uniform second half of a red arm's diagnostic. Callers print their own
# first half — the bespoke sentence saying what the arm proves — then call
# this, which says which of the two ways the arm failed and shows the output.
# Deliberately not a wrapper that owns the whole message: the bespoke
# sentences ("the must-exist list is broken", "the freeze guard is broken")
# are the part a reader needs and the part a generic helper would flatten.
red_arm_evidence() {
  case "$1" in
    1) printf '::error::  the check exited 0 — the planted fault was not caught at all.\n' ;;
    2) printf '::error::  the check exited %s but never printed `%s`, so it went red for some OTHER reason and this arm proved nothing about the surface it names (Q149: a red arm judged on exit status alone counts a crash as a proof).\n' \
         "$ARM_STATUS" "$2" ;;
    *) printf '::error::  unexpected red_arm_evidence code %s\n' "$1" ;;
  esac
  printf '::error::  captured output (%s byte(s)):\n' "${#ARM_OUT}"
  printf '%s\n' "$ARM_OUT" | sed 's/^/      /'
}
