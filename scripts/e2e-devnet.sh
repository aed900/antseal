#!/usr/bin/env bash
# Q15 / D52 — the devnet E2E gate.
#
# ONE script, TWO venues, the same bytes in both (the ci-lanes.sh rule):
#
#   * the REQUIRED LOCAL GATE, mandatory before merging storage-touching
#     changes (CONTRIBUTING, "Devnet E2E gate"), on the Q14 model: a named,
#     separately-invoked gate that emits recorded evidence; and
#   * the SCHEDULED, NON-REQUIRED hosted lane
#     (.github/workflows/devnet-e2e-cron.yml) at reduced node count, which
#     discharges the run-it-on-the-remote half of Q43's evidence rule.
#
# There is deliberately NO per-PR devnet job and NO self-hosted runner;
# docs/decisions/D52-devnet-e2e-venue.md carries the reasoning, the
# promote-to-required trigger and the revisit triggers.
#
# Usage:
#   scripts/e2e-devnet.sh [--nodes N] [--keep-devnet] [--require-suites]
#   scripts/e2e-devnet.sh --plan          registry + plan only; no devnet, no cargo
#   scripts/e2e-devnet.sh --list-suites   the registry, one row per line
#   scripts/e2e-devnet.sh --self-test     prove the registry rules can go red
#
# Exit: 0 = PASS or PENDING · 1 = FAIL (or PENDING under --require-suites).
#
# ── Why a suite REGISTRY, and why "pending" is a declaration ──────────────
#
# The venue (this script + the scheduled lane) lands BEFORE the suites it
# wraps: S17/S18/S19 are the gate lane's next wave. A gate that quietly
# passes because it found nothing to run is the Q66 class — "a lane that has
# never run is not evidence" — and a gate that goes red because its suite is
# not written yet trains people to ignore red, which is worse.
#
# So a missing suite is neither: it is a DECLARED pending row, and the
# declaration is checked in both directions, exactly as check-ci-shell.py
# checks ALLOWED_INLINE:
#
#   declared pending + absent  -> allowed; verdict PENDING, loudly, and the
#                                 run DISCHARGES NO GATE
#   declared pending + PRESENT -> hard FAIL (stale declaration: the suite
#                                 landed and the row was not moved to live)
#   declared live    + absent  -> hard FAIL (renamed/deleted suite; this is
#                                 the silent-stop this gate exists to catch)
#   declared live    + present -> it runs
#
# Which is also why `--require-suites` exists: once every row is live, that
# flag turns any future PENDING back into a failure, so the pending state
# cannot become permanent by inattention.
set -uo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo" || exit 1

note() { printf '\033[36m==>\033[0m %s\n' "$*"; }
die()  { printf '\033[31m::error::e2e-devnet: %s\033[0m\n' "$*" >&2; exit 1; }

# ── The suite registry ────────────────────────────────────────────────────
#
# status|task|package|feature|test-target|what it asserts
#
# The `feature` column is the PACKAGE-LOCAL feature name (antseal-cli's
# `ant-backend` forwards to antseal-net's; see crates/antseal-cli/Cargo.toml),
# and `test-target` is an integration test, i.e. crates/<package>/tests/
# <target>.rs — which is what the existence probe reads, so no cargo call is
# needed to decide the plan.
#
# THIS TABLE IS THE CONTRACT the S17-S19 lane lands against: match these
# names, or move the row in the same commit that lands the suite. A row is
# never deleted to make this gate quiet.
suite_registry() {
  cat <<'EOF'
live|S6-S8|antseal-net|ant-backend|devnet_backend|real-backend adapter suite against a live devnet: store/fetch round-trips, quote+pay, capture consistency
pending|S17|antseal-cli|ant-backend|e2e_devnet|multi-file --split seal, restore, UNANCHORED library verify, --live re-fetch
pending|S18|antseal-cli|ant-backend|e2e_kill_resume|kill between pay and finalize (no double payment, Anvil tx counting), kill mid-upload (byte-identical resume), (k_u,nonce)-reuse abort
pending|S19|antseal-cli|ant-backend|e2e_restore|clean-tree restore from the vault export alone
EOF
}

suite_path() { printf '%s/crates/%s/tests/%s.rs' "$repo" "$1" "$2"; }

# ── Redaction ─────────────────────────────────────────────────────────────
#
# Everything this gate captures can leave the machine: the scheduled lane
# uploads the evidence directory as a workflow artifact. The devnet's funded
# wallet key is a well-known public Anvil constant and guards nothing — but
# project rule 6 binds the PATTERN, not just real secrets
# (docs/devnet/local-devnet.md, "Wallet funding story"), so nothing
# key-shaped is written into an artifact.
#
# Redaction is BY KEY NAME, not by hex shape: a blanket 64-hex filter would
# also destroy the blob digests and addresses that make a failure log worth
# capturing.
redact() {
  sed -E "s/(wallet_private_key|[A-Za-z_]*PRIVATE_KEY|[A-Za-z_]*SECRET_KEY)([\"']?[[:space:]]*[:=][[:space:]]*[\"']?)(0x)?[0-9a-fA-F]{8,}/\1\2<redacted>/g"
}

# ── Plan ──────────────────────────────────────────────────────────────────
#
# Validates the registry (both directions above) and decides what will run.
# Sets: PLAN_RUN (rows to execute), PLAN_PENDING (task ids), PLAN_ERRORS.
build_plan() {
  PLAN_RUN=""
  PLAN_PENDING=""
  PLAN_ERRORS=""
  local rows status task pkg feat target what path
  rows="$(suite_registry)"
  [ -n "$rows" ] || { PLAN_ERRORS="the suite registry is EMPTY — this gate would assert nothing"; return; }
  while IFS='|' read -r status task pkg feat target what; do
    [ -n "${status:-}" ] || continue
    path="$(suite_path "$pkg" "$target")"
    case "$status" in
      live)
        if [ -f "$path" ]; then
          PLAN_RUN+="$task|$pkg|$feat|$target|$what"$'\n'
        else
          PLAN_ERRORS+="row $task is declared LIVE but crates/$pkg/tests/$target.rs does not exist. A gate whose suite silently stopped running is exactly the failure this registry exists to prevent: restore the suite, or move the row back to pending with the task that owns it."$'\n'
        fi ;;
      pending)
        if [ -f "$path" ]; then
          PLAN_ERRORS+="row $task is declared PENDING but crates/$pkg/tests/$target.rs EXISTS. Stale declaration: the suite landed — move the row to \`live\` in the commit that landed it (that commit is also where --require-suites gets switched on)."$'\n'
        else
          PLAN_PENDING+="$task "
          PLAN_RUN+=""
        fi ;;
      *)
        PLAN_ERRORS+="row $task has unknown status '$status' (expected live|pending)"$'\n' ;;
    esac
  done <<EOF
$rows
EOF
}

print_plan() {
  local task pkg feat target what
  note "suite registry (contract for the S17-S19 lane):"
  while IFS='|' read -r task pkg feat target what; do
    [ -n "${task:-}" ] || continue
    printf '    RUN     %-6s cargo test -p %s --features %s --test %s\n' "$task" "$pkg" "$feat" "$target"
    printf '            %s\n' "$what"
  done <<EOF
$PLAN_RUN
EOF
  local status task pkg feat target what
  while IFS='|' read -r status task pkg feat target what; do
    [ "${status:-}" = "pending" ] || continue
    [ -f "$(suite_path "$pkg" "$target")" ] && continue
    printf '    PENDING %-6s crates/%s/tests/%s.rs is not written yet — %s\n' \
      "$task" "$pkg" "$target" "$what"
  done <<EOF
$(suite_registry)
EOF
}

# ── The gate ──────────────────────────────────────────────────────────────
nodes="${ANTSEAL_DEVNET_NODES:-14}"
keep_devnet=0
plan_only=0
require_suites=0

run_gate() {
  build_plan
  print_plan
  if [ -n "$PLAN_ERRORS" ]; then
    printf '\033[31m::error::e2e-devnet: suite registry is inconsistent:\033[0m\n' >&2
    printf '%s' "$PLAN_ERRORS" | sed 's/^/    /' >&2
    return 1
  fi
  local n_run
  n_run="$(printf '%s' "$PLAN_RUN" | grep -c .)"
  [ "$plan_only" -eq 1 ] && { verdict "$n_run" "" "0" "(plan only — nothing executed)"; return $?; }

  # Nothing to run means nothing to boot: a 14-node devnet spun up for an
  # empty plan would burn minutes to prove nothing (and, on the scheduled
  # lane, would burn them nightly).
  if [ "$n_run" -eq 0 ]; then
    verdict 0 "" "0" "(no live suite — devnet not booted)"
    return $?
  fi

  local started evdir
  started="$(date -u +%s)"
  evdir="$repo/target/e2e-devnet/$(date -u +%Y%m%dT%H%M%SZ)-$(git rev-parse --short HEAD 2>/dev/null || echo nogit)"
  mkdir -p "$evdir" || die "cannot create the evidence directory $evdir"

  # Deterministic setup/teardown, with ONE exception that is not ours to
  # take: if a devnet is already up (the one-per-checkout contract of
  # local-up), we ATTACH to it and leave it standing — tearing down a devnet
  # this script did not boot would break whatever booted it.
  local borrowed=0 pidfile="$repo/.devnet/launcher.pid" oldpid
  if [ -f "$pidfile" ]; then
    oldpid="$(cat "$pidfile" 2>/dev/null || true)"
    if [ -n "$oldpid" ] && [ -d "/proc/$oldpid" ]; then borrowed=1; fi
  fi

  local boot_secs=0 boot_started
  if [ "$borrowed" -eq 1 ]; then
    note "attaching to the devnet already running (pid $oldpid) — it will NOT be torn down"
  else
    note "booting a devnet: $nodes nodes (scripts/devnet/local-up)"
    boot_started="$(date -u +%s)"
    if ! scripts/devnet/local-up --nodes "$nodes" 2>&1 | tee "$evdir/local-up.log"; then
      capture_devnet_logs "$evdir"
      verdict "$n_run" "" "$(( $(date -u +%s) - started ))" "(devnet failed to boot)" boot-failed
      return 1
    fi
    boot_secs=$(( $(date -u +%s) - boot_started ))
    [ "$keep_devnet" -eq 1 ] || trap 'scripts/devnet/local-down || true' EXIT
  fi

  local envfile="$repo/.devnet/env"
  [ -f "$envfile" ] || { capture_devnet_logs "$evdir"; die "no environment export at $envfile — the devnet is up but exported nothing (docs/devnet/local-devnet.md, Environment surface)"; }

  local failed="" task pkg feat target what
  while IFS='|' read -r task pkg feat target what; do
    [ -n "${task:-}" ] || continue
    note "$task: cargo test -p $pkg --features $feat --test $target"
    if ANTSEAL_DEVNET_ENV="$envfile" cargo test -p "$pkg" --features "$feat" --locked \
         --test "$target" -- --nocapture 2>&1 | tee "$evdir/suite-$task.log"; then
      printf '    %s PASS\n' "$task"
    else
      printf '\033[31m    %s FAIL (log: %s)\033[0m\n' "$task" "$evdir/suite-$task.log" >&2
      failed+="$task "
    fi
  done <<EOF
$PLAN_RUN
EOF

  # Logs are captured on BOTH paths: on failure they are the diagnosis
  # (Q15 Accept), on success the boot record is the runtime measurement
  # D52's conditional-landing rule needs.
  capture_devnet_logs "$evdir"
  verdict "$n_run" "$failed" "$(( $(date -u +%s) - started ))" "$evdir" ""
}

# node + Anvil logs (Anvil is the launcher's child, so its output is in the
# launcher log) plus the manifest, both redacted on the way in.
capture_devnet_logs() {
  local evdir="$1" devdir="$repo/.devnet"
  [ -d "$evdir" ] || return 0
  [ -f "$devdir/launcher.log" ] && redact < "$devdir/launcher.log" > "$evdir/launcher.log"
  [ -f "$devdir/manifest.json" ] && redact < "$devdir/manifest.json" > "$evdir/manifest.json"
  # `.devnet/env` is deliberately NOT captured in any form: it exists to
  # carry the wallet key to consumers, and an artifact has no use for it.
  return 0
}

# The dated evidence line — one greppable line for the wave record, in the
# Q14 gate's spirit. It carries the config (node count, anvil build) because
# D52 residual risk 5 is precisely that local and scheduled runs drift in
# configuration; a divergence is then recorded rather than ambient.
verdict() {
  local n_run="$1" failed="$2" secs="$3" evdir="$4" tag="${5:-}"
  local pending_list state rc=0
  pending_list="$(printf '%s' "${PLAN_PENDING:-}" | tr -s ' ' ',' | sed 's/,$//')"
  if [ -n "$failed" ] || [ "$tag" = "boot-failed" ]; then
    state=FAIL; rc=1
  elif [ -n "$pending_list" ]; then
    state=PENDING
    [ "$require_suites" -eq 1 ] && rc=1
  else
    state=PASS
  fi
  local line
  line="$(printf 'e2e-devnet: %s commit=%s nodes=%s suites_run=%s failed=[%s] pending=[%s] secs=%s anvil=%s evidence=%s' \
    "$state" "$(git rev-parse --short HEAD 2>/dev/null || echo nogit)" "$nodes" "$n_run" \
    "$(printf '%s' "$failed" | tr -s ' ' ',' | sed 's/,$//')" "$pending_list" "$secs" \
    "$(command -v anvil >/dev/null 2>&1 && anvil --version 2>/dev/null | head -1 | awk '{print $NF}' || echo '<absent>')" \
    "$evdir")"
  printf '\n%s\n' "$line"
  [ -d "$evdir" ] && printf '%s\n' "$line" > "$evdir/evidence.txt"
  case "$state" in
    PASS)    printf '\033[32me2e-devnet: PASS — the D52 gate is discharged for this commit.\033[0m\n' ;;
    PENDING) printf '\033[33m::warning::e2e-devnet: PENDING — %s not written yet. This run DISCHARGES NO GATE for those cases; it is not a pass.\033[0m\n' "$pending_list" ;;
    FAIL)    printf '\033[31m::error::e2e-devnet: FAIL — see the logs above and %s\033[0m\n' "$evdir" >&2 ;;
  esac
  return "$rc"
}

# ── Test-of-the-test ──────────────────────────────────────────────────────
#
# Runs in seconds and needs NO devnet, so scripts/local-gate.sh executes it
# on every gate: the registry rules and the redaction filter are the two
# pieces of this script that can silently stop meaning anything.
#
# The copy lives in scripts/ because the script derives `repo` from its own
# location — a copy anywhere else would be a different program (the
# ci-lanes.sh self-test note).
self_test() {
  local copy="$repo/scripts/.e2e-devnet-selftest.sh" out fail=0
  trap 'rm -f "$copy"' RETURN

  probe() { # <label> <sed-expr> <want-rc> <want-substring>
    local label="$1" expr="$2" want_rc="$3" want="$4" rc
    sed "$expr" "$repo/scripts/e2e-devnet.sh" > "$copy"
    if cmp -s "$copy" "$repo/scripts/e2e-devnet.sh"; then
      printf '::error:: planted fault %s did not apply — the registry no longer has the shape this self-test patches\n' "$label"
      fail=1; return
    fi
    out="$(bash "$copy" --plan 2>&1)"; rc=$?
    if [ "$rc" -ne "$want_rc" ] || ! printf '%s' "$out" | grep -qF "$want"; then
      printf '::error:: %s -> exit %s (wanted %s) and the output did not contain %s:\n%s\n' \
        "$label" "$rc" "$want_rc" "$want" "$(printf '%s' "$out" | tail -6)"
      fail=1; return
    fi
    printf '  planted fault: %-42s -> %s\n' "$label" "$want"
  }

  probe "a suite declared LIVE that does not exist" \
        's/^live|S6-S8|antseal-net|ant-backend|devnet_backend|/live|S6-S8|antseal-net|ant-backend|no_such_suite|/' \
        1 'declared LIVE but'
  probe "a stale PENDING row whose suite has landed" \
        's/^pending|S17|antseal-cli|ant-backend|e2e_devnet|/pending|S17|antseal-net|ant-backend|devnet_backend|/' \
        1 'Stale declaration'
  probe "an unknown row status" \
        's/^live|S6-S8|/liev|S6-S8|/' \
        1 "unknown status 'liev'"
  # The verdict half: with every row pending, the gate must be neither red
  # nor a quiet green — PENDING, saying so, and never the word PASS.
  probe "every row pending -> PENDING, not PASS" \
        's/^live|S6-S8|antseal-net|ant-backend|devnet_backend|/pending|S6-S8|antseal-net|ant-backend|not_written_yet|/' \
        0 'DISCHARGES NO GATE'
  out="$(sed 's/^live|S6-S8|antseal-net|ant-backend|devnet_backend|/pending|S6-S8|antseal-net|ant-backend|not_written_yet|/' \
        "$repo/scripts/e2e-devnet.sh" > "$copy"; bash "$copy" --plan 2>&1)"
  if printf '%s' "$out" | grep -q 'PASS'; then
    printf '::error:: an all-pending run printed PASS — a gate that passes with nothing to run is the Q66 class\n'
    fail=1
  fi
  # And the same shape under --require-suites must be a hard failure, which
  # is the latch that stops PENDING from becoming permanent.
  bash "$copy" --plan --require-suites >/dev/null 2>&1
  if [ $? -ne 1 ]; then
    printf '::error:: --require-suites did not turn PENDING into a failure — the anti-rot latch is not wired\n'
    fail=1
  else
    printf '  planted fault: %-42s -> %s\n' "PENDING under --require-suites" "exit 1"
  fi
  rm -f "$copy"

  # Redaction: an artifact that leaves the machine must carry no key-shaped
  # material (project rule 6 binds the pattern, not just real secrets).
  local key_a key_b red
  key_a="0x$(printf 'a%.0s' $(seq 64))"
  key_b="0x$(printf 'b%.0s' $(seq 64))"
  red="$(printf "ANTSEAL_DEVNET_WALLET_PRIVATE_KEY='%s'\n  \"wallet_private_key\": \"%s\",\n  \"payment_token_address\": \"0x4bc1aCE0E66170375462cB4E6Af42Ad4D5EC689C\"\n" \
        "$key_a" "$key_b" | redact)"
  if printf '%s' "$red" | grep -qE '(a{64}|b{64})'; then
    printf '::error:: redact() left key material in the capture:\n%s\n' "$red"
    fail=1
  elif ! printf '%s' "$red" | grep -q '0x4bc1aCE0E66170375462cB4E6Af42Ad4D5EC689C'; then
    printf '::error:: redact() destroyed a contract address — the filter must be key-name-scoped, not hex-shaped:\n%s\n' "$red"
    fail=1
  else
    printf '  planted fault: %-42s -> %s\n' "key material in a captured log" "redacted (addresses kept)"
  fi

  # Control: the registry as committed must validate.
  out="$(bash "$repo/scripts/e2e-devnet.sh" --plan 2>&1)"
  if [ $? -ne 0 ]; then
    printf '::error:: the committed registry does not validate; nothing above means anything:\n%s\n' "$out"
    fail=1
  fi
  printf '  control (committed registry)%29s -> %s\n' '' "$(printf '%s' "$out" | grep -o 'e2e-devnet: [A-Z]*' | tail -1)"
  [ "$fail" -eq 0 ] || return 1
  note "e2e-devnet self-test PASS — registry rules and redaction both go red on planted faults"
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --nodes) shift; nodes="${1:-}"; [ -n "$nodes" ] || die "--nodes needs a value" ;;
    --keep-devnet)    keep_devnet=1 ;;
    --plan)           plan_only=1 ;;
    --require-suites) require_suites=1 ;;
    --list-suites)    suite_registry; exit 0 ;;
    --self-test)      self_test; exit $? ;;
    -h|--help)        sed -n '1,30p' "$repo/scripts/e2e-devnet.sh"; exit 0 ;;
    *) die "unknown argument: $1 (see --help)" ;;
  esac
  shift
done

run_gate
