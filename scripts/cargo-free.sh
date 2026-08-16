#!/usr/bin/env bash
# Q182/D124 — the cargo-free property of CI's `traceability` job, asserted.
#
# ── THE PROPERTY. STATED ONCE, HERE ────────────────────────────────────────
#
#   NO STEP OF THE `traceability` JOB INVOKES cargo, rustc OR rustup —
#   INCLUDING STEPS THAT ARE NOT YET WRITTEN.
#
# [D138/Q239, 2026-08-16] That job now lives in
# `.github/workflows/ci-always.yml`, not `ci.yml`. This sentence used to name
# the file and no longer does, on purpose: the property is about a JOB, the job
# id and `name:` are unchanged, and pinning the sentence to a workflow filename
# is what made it go stale the moment the job moved. `--arm`/`--verdict` take
# the job NAME as their argument and never read a workflow file, so nothing
# below changed. `core-dep-graph` is still in `ci.yml`.
#
#   And its converse, asserted by the same instrument so the two cannot drift
#   apart:
#
#   `core-dep-graph` DOES have a working cargo, because two of its steps need
#   one.
#
# Sixteen prose sites across six files used to ASSERT the first sentence; they
# now cite this header and assert nothing (D124 RULING 5). If you are about to
# write "no cargo" about a CI job somewhere else, cite this file instead.
#
# ── WHY IT MATTERS, AND WHY THE FAILURE IS NOT THE ONE IT LOOKS LIKE ───────
#
# Nothing in this repository installs rustup. Every toolchain step is
# `rustup show active-toolchain || rustup toolchain install`, which PRESUMES
# the shim is already there — so cargo is on `PATH` in `traceability` right
# now and a cargo step added there does NOT fail. It resolves
# `rust-toolchain.toml` through the rustup shim and implicitly installs the
# pinned 1.92.0 plus `rustfmt`, `clippy` and the `wasm32-unknown-unknown` std,
# on one of only TWO jobs in this workflow that need no toolchain at all
# (`secret-guard` is the other), in a job with no cache, on every pull request
# and every push — and reports SUCCESS. A green job that bills minutes for
# ever, on a repository whose Actions minutes were exhausted on 2026-08-10.
# Silent, billed, and permanent: D124 §1.2.
#
# It has already nearly happened. Q153's first placement put
# `./scripts/gate-features.sh --check-partition` on this job, which would have
# been its first cargo user. It was caught by a lane reading carefully.
#
# ── WHY IT IS NOT ASSERTED IN scripts/check-ci-shell.py ────────────────────
#
# That is where workflow facts get checked, and this is not a workflow fact.
# A per-job predicate over `run:` block text is VACUOUS against the very
# incident that produced the row: `./scripts/gate-features.sh
# --check-partition` contains no `cargo` token, and neither does any of the
# five `run:` lines the job carries today — 0 of 6, measured. Reading one
# level deeper is worse: `ci-lanes.sh` (the callee of four of the five steps)
# holds 31 `cargo` occurrences belonging to other lanes and `wasm-bitmatch.sh`
# holds 4, so a callee-grep reds all five of today's GREEN steps, starting
# with the one step Q153 measured cargo-free by running it.
#
# The property is a claim about a PROCESS TREE — which argument a committed
# script was called with, which branch it took, what it shelled out to. No
# reading of the YAML can see that. So the assertion goes where the fact is:
# at the job, at runtime, where a shim either gets called or does not.
# D124 RULING 2, §1.6, §3.1-3.3. A refusal note is recorded at
# `run_blocks()` in check-ci-shell.py so the shape is not re-proposed.
#
# ── THE MECHANISM ─────────────────────────────────────────────────────────
#
#   --arm <job>      FIRST step of the job, after checkout. Builds failing
#                    `cargo`, `rustc` and `rustup` shims in a directory under
#                    $RUNNER_TEMP and appends that directory to $GITHUB_PATH,
#                    which PREPENDS it to PATH for every subsequent step of
#                    the job, including steps not yet written.
#   --verdict <job>  LAST step of the job. Red if any step tripped a shim, red
#                    if the guard directory is gone (so deleting the arm step
#                    alone reds the verdict — the two steps guard each other),
#                    and red if the shims are not the ones PATH resolves, so a
#                    $GITHUB_PATH mechanism that silently stopped working
#                    cannot read as a green property.
#   --require <job>  The converse, for `core-dep-graph`.
#   --self-test      Thirteen checks: NINE red arms, each judged BY THE MESSAGE
#                    the guard prints and never by exit status
#                    (scripts/lib/red-arm.sh), TWO direct property assertions
#                    (the shim exits 127; the marker survives having both
#                    streams discarded) and TWO green controls.
#
# THREE DESIGN CONSTRAINTS, EACH FROM A MEASUREMENT — do not "simplify" them:
#
#  1. REMOVING cargo from PATH is the WRONG operation. Three named sites guard
#     with `command -v cargo >/dev/null || …` (reserve-crates.sh:74,
#     ci-lanes.sh:1204, fuzz.sh:133), so an absent binary makes them SKIP
#     SILENTLY — the failure direction this guard exists to close. A FAILING
#     SHIM is required: it makes `command -v` succeed and the invocation fail.
#  2. THE DIAGNOSIS MUST NOT TRAVEL BY STDERR ALONE. `gate-features.sh:116`
#     pipes `cargo metadata … 2>/dev/null`: measured, the callee redirects the
#     shim's message to /dev/null and the reader gets an unrelated Python
#     traceback. Hence a marker FILE, written BEFORE anything is printed, and
#     a later step that reads it back.
#  3. THE SHIMS EXIT 127, not 1 — the status a caller would have seen had the
#     binary genuinely been absent, so no `|| return 1`, `set -e` or
#     PIPESTATUS idiom in any callee meets a novel value.
#
# The guard directory lives under $RUNNER_TEMP and NEVER inside the workspace:
# `secret-guard`, `vector-freeze` and `check-traceability.py --self-test` all
# read or copy the tree, and a generated `cargo` in it would be a new subject
# for all three. That is asserted below rather than assumed.
#
# Usage:
#   scripts/cargo-free.sh --arm <job>       install the shims for this job
#   scripts/cargo-free.sh --verdict <job>   read the marker back
#   scripts/cargo-free.sh --require <job>   the converse: cargo IS available
#   scripts/cargo-free.sh --self-test       prove the guard can go red
# Exit: 0 pass · 1 failure.
set -uo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
self="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"

# shellcheck source=scripts/lib/red-arm.sh
. "$repo/scripts/lib/red-arm.sh"

# The three binaries a step could reach the toolchain through. `cargo fuzz`
# and `cargo deny` are subcommands and are covered by `cargo`.
SHIMMED="cargo rustc rustup"

# The literal sentences each failure prints, as named constants, because
# `--self-test`'s arms match ON THESE STRINGS. Q149's class is a red arm that
# judges on exit status and so certifies a surface it never exercised; the
# defence is matching the message, and the defence rots the moment the message
# and the arm can drift apart. They cannot: there is one copy of each.
MSG_CANNOT_ARM='cannot arm: $GITHUB_PATH is unset'
MSG_NOT_ARMED='the guard directory does not exist, so the arming step never ran'
MSG_JOB_MISMATCH='was armed for a different job'
MSG_TRIPPED='invoked a masked toolchain binary'
MSG_UNSHIMMED='did not resolve to the guard shim'
MSG_REQUIRE_ABSENT='is not on PATH at all'
MSG_REQUIRE_REFUSES='is on PATH but refuses to run'
MSG_IN_WORKSPACE='it is inside the workspace'

CITE="Q182/D124; the property and its reason are stated once, in scripts/cargo-free.sh's header"

err()  { printf '::error::cargo-free: %s\n' "$*"; }
err2() { printf '::error::  %s\n' "$*"; }
note() { printf 'cargo-free: %s\n' "$*"; }

# ${RUNNER_TEMP:-${TMPDIR:-/tmp}}/antseal-cargo-free, trailing slashes stripped.
guard_dir() {
  local base="${RUNNER_TEMP:-${TMPDIR:-/tmp}}"
  while [ "${base%/}" != "$base" ]; do base="${base%/}"; done
  [ -n "$base" ] || base=/tmp
  printf '%s/antseal-cargo-free' "$base"
}

# Refuse a guard directory inside the workspace (see the header) or one whose
# path cannot be safely quoted into a generated shim.
check_guard_location() {
  local g="$1"
  case "$g" in
    "$repo"|"$repo"/*)
      err "refusing to build the guard directory at '$g' — $MSG_IN_WORKSPACE ($repo), which secret-guard, vector-freeze and check-traceability.py --self-test all read or copy, and a generated 'cargo' in the tree would be a new subject for all three. Set RUNNER_TEMP (CI does) or TMPDIR to something outside the tree."
      return 1 ;;
    *"'"*)
      err "refusing to build the guard directory at '$g' — the path contains a single quote, which cannot be safely embedded in the generated shims."
      return 1 ;;
  esac
  return 0
}

# ── --arm ─────────────────────────────────────────────────────────────────
cmd_arm() {
  local job="$1"
  local guard bin tripped armed
  guard="$(guard_dir)"; bin="$guard/bin"; tripped="$guard/TRIPPED"; armed="$guard/ARMED"

  # House rule: self-test, then act. The recursion stops because --self-test
  # exports ANTSEAL_CARGO_FREE_SELFTEST=1 for the --arm invocations it makes.
  if [ -z "${ANTSEAL_CARGO_FREE_SELFTEST:-}" ]; then
    if ! self_test; then
      err "the self-test FAILED, so arming '$job' would install a guard that has not been shown able to go red — refusing to arm ($CITE)."
      return 1
    fi
  fi

  check_guard_location "$guard" || return 1
  mkdir -p "$bin" || { err "could not create the guard directory '$bin'"; return 1; }

  local name
  for name in $SHIMMED; do
    # An unquoted heredoc: `$job`, `$name` and `$tripped` are baked in at
    # generation time, `\$` survives to run time. No backticks in the text.
    cat >"$bin/$name" <<SHIM
#!/usr/bin/env bash
# GENERATED by scripts/cargo-free.sh --arm $job. Never committed; lives under
# \$RUNNER_TEMP, never inside the workspace.
#
# The record is written BEFORE anything is printed, because the caller can
# take the print away and cannot take the file away: gate-features.sh:116
# pipes 'cargo metadata … 2>/dev/null', measured, so a diagnosis that travels
# by stderr alone is a diagnosis a callee can silence.
{ printf '%s\t%s %s\n' "\${GITHUB_ACTION:-no-step-id}" '$name' "\$*" >>'$tripped'; } 2>/dev/null || :
msg="::error::cargo-free: the '$job' job invoked '$name' — $MSG_TRIPPED. That job is asserted to run no cargo, rustc or rustup at all ($CITE). Exiting 127, the status an absent binary would have produced."
printf '%s\n' "\$msg"
printf '%s\n' "\$msg" >&2
exit 127
SHIM
    chmod +x "$bin/$name" || { err "could not make '$bin/$name' executable"; return 1; }
  done

  # IDEMPOTENT: TRIPPED is never created, never truncated and never removed
  # here, so a re-run of this step cannot erase a marker an earlier run wrote.
  printf 'job=%s\narmed_at=%s\nbin=%s\nshims=%s\n' \
    "$job" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$bin" "$SHIMMED" >"$armed"

  note "guard directory: $guard"
  note "shims installed (each exits 127 and records to TRIPPED first): $SHIMMED"

  if [ -z "${GITHUB_PATH:-}" ]; then
    # NOT a silent local no-op. D124 §3.6 refuses `command -v cargo || skip`
    # precisely because an absent capability that exits 0 is the wrong
    # direction, and "printed an export line" is that same shape: it would let
    # a runner whose $GITHUB_PATH mechanism stopped working report an armed
    # job. So this is a hard failure that still prints what a human can use.
    note "the equivalent local command, for a human masking a step by hand:"
    printf '  export PATH=%s:"$PATH"\n' "$bin"
    err "$MSG_CANNOT_ARM, so nothing was added to PATH and the '$job' job is NOT armed. This mode requires a GitHub Actions runner (or a caller that sets GITHUB_PATH to a file it then applies, which is what --self-test does). The shims above were built and are usable by hand, but a green exit here would claim an arming that did not happen ($CITE)."
    return 1
  fi

  if grep -qxF -- "$bin" "$GITHUB_PATH" 2>/dev/null; then
    note "'$bin' is already on \$GITHUB_PATH — re-arm is a no-op (idempotent)"
  else
    printf '%s\n' "$bin" >>"$GITHUB_PATH" || {
      err "could not append '$bin' to \$GITHUB_PATH ($GITHUB_PATH)"; return 1; }
  fi
  note "ARMED for job '$job' — every SUBSEQUENT step of this job resolves cargo, rustc and rustup to a shim that fails. Read the marker back with: scripts/cargo-free.sh --verdict $job"
  return 0
}

# ── --verdict ─────────────────────────────────────────────────────────────
cmd_verdict() {
  local job="$1" rc=0
  local guard bin tripped armed
  guard="$(guard_dir)"; bin="$guard/bin"; tripped="$guard/TRIPPED"; armed="$guard/ARMED"

  if [ ! -d "$bin" ]; then
    err "$MSG_NOT_ARMED ('$guard'). This step and the arming step guard each other: if the '$job' job no longer runs 'scripts/cargo-free.sh --arm $job' as its FIRST step, then no step of it was masked and a green verdict here would assert a property nothing checked ($CITE)."
    return 1
  fi

  local armed_job=""
  if [ -f "$armed" ]; then
    armed_job="$(sed -n 's/^job=//p' "$armed" | head -n 1)"
  fi
  if [ -n "$armed_job" ] && [ "$armed_job" != "$job" ]; then
    err "the guard $MSG_JOB_MISMATCH: armed for '$armed_job', verdict asked for '$job'. One of the two steps was copied without the other ($CITE)."
    rc=1
  fi

  # The shims must be what PATH resolves NOW. $GITHUB_PATH additions apply to
  # every step after the one that made them, so by this step they must be in
  # force — and if they are not, no step was masked and TRIPPED would be empty
  # for the wrong reason. This is the arm of the guard that keeps an empty
  # marker file from meaning "clean" when it means "never armed".
  local name resolved
  for name in $SHIMMED; do
    resolved="$(command -v "$name" 2>/dev/null)"
    if [ "$resolved" != "$bin/$name" ]; then
      err "'$name' $MSG_UNSHIMMED: PATH resolves it to '${resolved:-<nothing>}', not to '$bin/$name'. The arming step ran but its \$GITHUB_PATH entry is not in force, so the '$job' job was NOT masked and no invocation could have been recorded ($CITE)."
      rc=1
    fi
  done

  if [ -s "$tripped" ]; then
    local n
    n="$(wc -l <"$tripped")"
    err "the '$job' job $MSG_TRIPPED — ${n// /} invocation(s) recorded. That job is asserted to run no cargo, rustc or rustup at all ($CITE)."
    while IFS= read -r line; do err2 "$line"; done <"$tripped"
    err2 "Each was answered with exit 127 and a message, which a callee may have discarded — this file is the channel it could not."
    rc=1
  fi

  if [ "$rc" -eq 0 ]; then
    note "OK — no step of the '$job' job invoked cargo, rustc or rustup. $(printf '%s' "$SHIMMED" | wc -w | tr -d ' ') shim(s) in force at '$bin', 0 invocations recorded."
  fi
  return "$rc"
}

# ── --require ─────────────────────────────────────────────────────────────
# The converse property. Without it, cargo missing from `core-dep-graph`
# surfaces as an unhandled JSONDecodeError followed by
# "cargo metadata returned NO features at all — the extractor is broken",
# which is loud AND misdiagnosing: it sends the reader to declared_features()
# when nothing is wrong with the extractor (D124 §1.9).
cmd_require() {
  local job="$1" rc=0 name resolved out st
  for name in cargo rustc; do
    resolved="$(command -v "$name" 2>/dev/null)"
    if [ -z "$resolved" ]; then
      err "'$name' $MSG_REQUIRE_ABSENT in the '$job' job, which needs a working toolchain — two of its steps shell out to cargo. Nothing in this repository installs rustup: every toolchain step is 'rustup show active-toolchain || rustup toolchain install', which presumes the shim ($CITE)."
      rc=1
      continue
    fi
    out="$("$name" --version 2>&1)"; st=$?
    if [ "$st" -ne 0 ]; then
      err "'$name' $MSG_REQUIRE_REFUSES in the '$job' job: '$resolved --version' exited $st. If that path is under a directory named antseal-cargo-free, this job has been armed by 'scripts/cargo-free.sh --arm', which is the OPPOSITE property and belongs on 'traceability' ($CITE)."
      while IFS= read -r line; do err2 "$line"; done <<<"$out"
      rc=1
      continue
    fi
    note "'$name' -> $resolved — ${out%%$'\n'*}"
  done
  [ "$rc" -eq 0 ] && note "OK — the '$job' job has a working cargo and rustc, which two of its steps need."
  return "$rc"
}

# ── --self-test ───────────────────────────────────────────────────────────
#
# Thirteen checks: nine red arms, two direct property assertions and two green
# controls. Every red arm judges on the MESSAGE the guard prints
# (scripts/lib/red-arm.sh's rule); a crash, a missing file or an unrelated
# traceback satisfies none of them.
#
# The PATHs are built inside the scratch tree from the ambient PATH with every
# element that carries a toolchain binary removed, so this gives the same
# verdict inside the armed `traceability` job as outside it — and the system
# directories survive, which the shebang of the script under test needs.
self_test() {
  local scratch fail=0
  scratch="$(mktemp -d "${TMPDIR:-/tmp}/cargo-free-selftest.XXXXXX")" || {
    err "could not create a scratch directory"; return 1; }
  # shellcheck disable=SC2064
  trap "rm -rf '$scratch'" RETURN

  # A HERMETIC system PATH: one directory of symlinks to exactly the utilities
  # this script and red-arm.sh use, and nothing else. Built rather than
  # filtered from $PATH, because filtering whole directories out of $PATH
  # breaks on any host that keeps cargo in a system directory alongside
  # coreutils — the self-test would then be unable to resolve `bash` and would
  # red for an environment reason, on a job whose whole value is that it does
  # not red for environment reasons. This construction cannot: cargo is absent
  # because it was never linked, not because a directory was removed.
  mkdir -p "$scratch/sysbin" "$scratch/working"
  local u src missing=""
  for u in bash env mktemp dirname basename mkdir chmod cat date grep sed wc tr rm head cut; do
    # `type -P` searches PATH only. `command -v` would return the NAME of a
    # shell function or builtin of the same name, and `ln -s` would then make
    # a dangling self-link that the check below reports as missing — measured
    # 2026-08-11 against a `grep` shell function.
    src="$(type -P "$u" 2>/dev/null)"
    if [ -z "$src" ]; then missing="${missing:+$missing }$u"; continue; fi
    ln -sf "$src" "$scratch/sysbin/$u"
  done
  if [ -n "$missing" ]; then
    err "cannot build the self-test's hermetic PATH: these utilities are not on PATH: $missing"
    return 1
  fi
  for u in cargo rustc rustup; do
    if [ -e "$scratch/sysbin/$u" ]; then
      err "the hermetic sysbin contains '$u' — the cargo-absent PATH is not cargo-absent, so the arms below would prove nothing"
      return 1
    fi
  done

  local n
  for n in cargo rustc rustup; do
    printf '#!/usr/bin/env bash\nprintf "%%s 1.92.0 (self-test fake)\\n" "%s"\nexit 0\n' "$n" \
      >"$scratch/working/$n"
    chmod +x "$scratch/working/$n"
  done

  local base_path="$scratch/sysbin"
  local path_absent="$scratch/sysbin"
  local path_working="$scratch/working:$scratch/sysbin"

  export ANTSEAL_CARGO_FREE_SELFTEST=1

  # A fresh runner: its own RUNNER_TEMP and its own $GITHUB_PATH file.
  local rt="$scratch/rt" gp="$scratch/github_path"
  mkdir -p "$rt"; : >"$gp"
  local guard="$rt/antseal-cargo-free" bin="$rt/antseal-cargo-free/bin"

  # Every child is launched with GITHUB_PATH and RUNNER_TEMP SCRUBBED and then
  # set explicitly, never inherited. `env VAR=…` does not unset what it does
  # not name, and an arm that inherits the caller's environment is an arm the
  # caller can satisfy: arm 7 below passed standalone and proved NOTHING when
  # this self-test was invoked from a harness that had GITHUB_PATH set, which
  # is how it was caught. Measured 2026-08-11. This is red-arm.sh's rule in the
  # environment direction — the arm must depend on what it plants, not on where
  # it is run from.
  sandbox() { env -u GITHUB_PATH -u RUNNER_TEMP "$@"; }
  arm() { sandbox "RUNNER_TEMP=$1" "GITHUB_PATH=$2" "PATH=$path_absent" "$self" --arm "$3"; }

  note "self-test: arming a simulated runner"
  if ! arm "$rt" "$gp" testjob >"$scratch/arm.log" 2>&1; then
    err "--arm failed on the simulated runner, so nothing below means anything:"
    sed 's/^/      /' "$scratch/arm.log"
    return 1
  fi
  # The runner PREPENDS every line of $GITHUB_PATH to PATH for later steps.
  if ! grep -qxF -- "$bin" "$gp"; then
    err "--arm did not append '$bin' to the simulated \$GITHUB_PATH — the mechanism the whole guard rests on did not happen"
    return 1
  fi
  local path_armed="$bin:$base_path"

  # ARM 1 (control, GREEN): armed, nothing invoked cargo.
  if assert_green sandbox "RUNNER_TEMP=$rt" "PATH=$path_armed" "$self" --verdict testjob; then
    printf '  %-58s -> GREEN\n' "control: armed job, no cargo invoked"
  else
    printf '  %-58s -> RED\n' "control: armed job, no cargo invoked"
    err "the control is RED, so every arm below is meaningless:"
    printf '%s\n' "$ARM_OUT" | sed 's/^/      /'
    fail=1
  fi

  # ARM 2 (RED): a step of the armed job invokes cargo — WITH BOTH ITS
  # STREAMS DISCARDED, which is exactly gate-features.sh:116's shape and the
  # measured hazard the marker file exists for.
  sandbox "PATH=$path_armed" cargo metadata --format-version 1 --no-deps --locked >/dev/null 2>&1
  local shim_status=$?
  if [ "$shim_status" -ne 127 ]; then
    printf '  %-58s -> exit %s\n' "the shim exits 127 (an absent binary's status)" "$shim_status"
    err "the cargo shim exited $shim_status, not 127 — a callee's '|| return 1' or PIPESTATUS idiom would meet a novel value"
    fail=1
  else
    printf '  %-58s -> 127\n' "the shim exits 127 (an absent binary's status)"
  fi
  if grep -qF -- 'cargo metadata --format-version 1 --no-deps --locked' "$guard/TRIPPED" 2>/dev/null; then
    printf '  %-58s -> RECORDED\n' "the marker survives 'cmd >/dev/null 2>&1'"
  else
    err "the invocation was NOT recorded in $guard/TRIPPED with both streams discarded — the marker file does not survive the one hazard it exists for (gate-features.sh:116)"
    fail=1
  fi
  arm_case "the armed job then invoked cargo" "$MSG_TRIPPED" \
    sandbox "RUNNER_TEMP=$rt" "PATH=$path_armed" "$self" --verdict testjob || fail=1

  # ARM 3 (RED): --arm is idempotent — re-arming must not erase the marker.
  if ! arm "$rt" "$gp" testjob >"$scratch/rearm.log" 2>&1; then
    err "re-arming an already-armed job failed; --arm is required to be idempotent"
    sed 's/^/      /' "$scratch/rearm.log"
    fail=1
  fi
  arm_case "re-arming did not erase the marker (idempotence)" "$MSG_TRIPPED" \
    sandbox "RUNNER_TEMP=$rt" "PATH=$path_armed" "$self" --verdict testjob || fail=1

  # ARM 4 (RED): the arming step was deleted from the job.
  local rt2="$scratch/rt-never-armed"; mkdir -p "$rt2"
  arm_case "the arming step is gone (guard directory absent)" "$MSG_NOT_ARMED" \
    sandbox "RUNNER_TEMP=$rt2" "PATH=$path_absent" "$self" --verdict testjob || fail=1

  # ARMS 5 and 6 get their OWN freshly armed runner, so their TRIPPED file is
  # empty and the only thing that can turn the verdict red is the fault the
  # arm plants. Re-using the tripped runner above would have let arm 2's red
  # satisfy them (red-arm.sh: an arm that can be satisfied by an unrelated
  # failure proves nothing about the surface it names).
  local rt_clean="$scratch/rt-clean" bin_clean="$scratch/rt-clean/antseal-cargo-free/bin"
  mkdir -p "$rt_clean"; : >"$scratch/gp-clean"
  if ! arm "$rt_clean" "$scratch/gp-clean" testjob >"$scratch/arm-clean.log" 2>&1; then
    err "--arm failed on the second simulated runner:"
    sed 's/^/      /' "$scratch/arm-clean.log"
    fail=1
  fi

  # ARM 5 (RED): armed, but the $GITHUB_PATH entry never took effect — the
  # silent-disarm case an empty TRIPPED file would otherwise read as clean.
  arm_case "armed, but PATH does not resolve to the shims" "$MSG_UNSHIMMED" \
    sandbox "RUNNER_TEMP=$rt_clean" "PATH=$path_working" "$self" --verdict testjob || fail=1

  # ARM 6 (RED): the pair was copied into another job under one name only.
  arm_case "verdict names a different job than the arm did" "$MSG_JOB_MISMATCH" \
    sandbox "RUNNER_TEMP=$rt_clean" "PATH=$bin_clean:$base_path" "$self" --verdict otherjob || fail=1

  # ARM 7 (RED): --arm outside Actions must FAIL, not print and pass.
  local rt3="$scratch/rt-no-github-path"; mkdir -p "$rt3"
  arm_case "--arm with \$GITHUB_PATH unset refuses to claim success" "$MSG_CANNOT_ARM" \
    sandbox "RUNNER_TEMP=$rt3" "PATH=$path_absent" "$self" --arm testjob || fail=1

  # ARM 8 (RED): a guard directory inside the workspace is refused. The
  # constraint is not decorative: secret-guard, vector-freeze and
  # check-traceability.py --self-test all read or copy the tree.
  arm_case "a guard directory inside the workspace is refused" "$MSG_IN_WORKSPACE" \
    sandbox "RUNNER_TEMP=$repo/target" "GITHUB_PATH=$scratch/gp-workspace" "PATH=$path_absent" \
    "$self" --arm testjob || fail=1

  # ARM 9 (GREEN control for the converse) and ARMS 10/11 (its two reds).
  if assert_green sandbox "PATH=$path_working" "$self" --require testjob; then
    printf '  %-58s -> GREEN\n' "control: --require with a working cargo"
  else
    printf '  %-58s -> RED\n' "control: --require with a working cargo"
    err "--require is red against a working toolchain, so its arms below prove nothing:"
    printf '%s\n' "$ARM_OUT" | sed 's/^/      /'
    fail=1
  fi
  arm_case "--require where cargo is absent" "$MSG_REQUIRE_ABSENT" \
    sandbox "PATH=$path_absent" "$self" --require testjob || fail=1
  arm_case "--require where cargo is the failing shim" "$MSG_REQUIRE_REFUSES" \
    sandbox "PATH=$path_armed" "$self" --require testjob || fail=1

  if [ "$fail" -ne 0 ]; then
    err "cargo-free self-test FAILED — the guard above is not trustworthy, so no verdict it prints is either"
    return 1
  fi
  note "self-test PASS — every arm went red BY ITS MESSAGE, and both controls are green"
  return 0
}

# One red arm: run the command, require it to fail AND to say why.
arm_case() {
  local label="$1" expected="$2"
  shift 2
  assert_red "$expected" "$@"
  local code=$?
  if [ "$code" -eq 0 ]; then
    printf '  %-58s -> RED\n' "$label"
    return 0
  fi
  printf '  %-58s -> NOT PROVEN\n' "$label"
  err "the arm '$label' did not prove the guard can go red for this reason"
  red_arm_evidence "$code" "$expected"
  return 1
}

usage() {
  printf 'usage: scripts/cargo-free.sh --arm <job> | --verdict <job> | --require <job> | --self-test\n'
}

case "${1:-}" in
  --arm)       [ -n "${2:-}" ] || { usage; exit 1; }; cmd_arm "$2" ;;
  --verdict)   [ -n "${2:-}" ] || { usage; exit 1; }; cmd_verdict "$2" ;;
  --require)   [ -n "${2:-}" ] || { usage; exit 1; }; cmd_require "$2" ;;
  --self-test) self_test ;;
  *)           usage; exit 1 ;;
esac
