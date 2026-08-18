#!/usr/bin/env bash
# Q15 / D52 — the devnet E2E gate.
#
# ONE script, TWO venues, the same bytes in both (the ci-lanes.sh rule):
#
#   * the REQUIRED LOCAL GATE, mandatory before merging storage-touching
#     changes (CONTRIBUTING, "Devnet E2E gate"), on the Q14 model: a named,
#     separately-invoked gate that emits recorded evidence; and
#   * the SCHEDULED, NON-REQUIRED hosted lane
#     (.github/workflows/devnet-e2e-cron.yml), which discharges the
#     run-it-on-the-remote half of Q43's evidence rule. It ran at a
#     REDUCED node count (5) until 2026-08-17 and could not pass: 5 is
#     below ant-protocol's CLOSE_GROUP_SIZE=7, so no quote can be
#     obtained. It now uses this script's own default of 14.
#
# There is deliberately NO per-PR devnet job and NO self-hosted runner;
# docs/decisions/D52-devnet-e2e-venue.md carries the reasoning, the
# promote-to-required trigger and the revisit triggers.
#
# Usage:
#   scripts/e2e-devnet.sh [--nodes N] [--keep-devnet] [--allow-pending]
#   scripts/e2e-devnet.sh --plan          registry + plan only; no devnet, no cargo
#   scripts/e2e-devnet.sh --list-suites   the registry, one row per line
#   scripts/e2e-devnet.sh --self-test     prove the registry rules can go red
#   scripts/e2e-devnet.sh --scan-evidence [DIR]
#                                         refuse an evidence directory that
#                                         still carries key-shaped material
#
# Exit: 0 = PASS · 1 = FAIL, and PENDING is a FAIL unless --allow-pending.
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
# Which is why the latch exists — and, since S32, why it is ARMED BY
# DEFAULT: a PENDING verdict is a failure, so the pending state cannot
# become permanent by inattention.
#
# S17/S18/S19 landing made the registry fully live, and a registry with no
# pending rows is exactly when flipping this default costs nothing: the
# committed gate still reads PASS, and the only behaviour that changed is
# the one nobody should be relying on. `--allow-pending` is the opt-out for
# the one legitimate case — declaring a new suite row in the commit BEFORE
# the suite is written, which is what the declaration is for. It is a flag
# you type on purpose, which is the whole difference from a default.
#
# `--require-suites` is still accepted and still means "armed", so the
# CONTRIBUTING invocation and any existing CI line keep working; it is now
# a no-op restatement of the default rather than the thing that switches it
# on.
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
live|S17|antseal-cli|ant-backend|e2e_devnet|multi-file --split seal, restore, UNANCHORED library verify, --live re-fetch
live|S18|antseal-cli|ant-backend|e2e_kill_resume|kill between pay and finalize (no double payment, Anvil tx counting), kill mid-upload (byte-identical resume), (k_u,nonce)-reuse abort
live|S19|antseal-cli|ant-backend|e2e_restore|clean-tree restore from the vault export alone
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

# ── The artifact scan (Q243) ──────────────────────────────────────────────
#
# `redact()` above is a check on the FUNCTION. This is a check on the OUTPUT:
# it reads the evidence directory that is about to be uploaded and refuses if
# anything key-shaped is still in it. That is the half which survives a
# refactor that stops calling `redact()` at all — the failure the redactor's
# own self-test structurally cannot see, because it tests the filter and not
# the artifact.
#
# The name list below is deliberately BROADER than the redactor's. A scan
# built from the redactor's own alternation can only ever agree with it; the
# point of this one is to catch material the redactor did not see, so it adds
# the lowercase spellings, `mnemonic`, `passphrase`, `seed_phrase` and
# `keystore_password`, and a base64 value arm the hex-only redactor is
# structurally blind to.
#
# What it must NOT do is fire on the material that makes a failure log worth
# keeping. A bare 64-hex blob digest, a `0x`+40-hex contract address and a
# `0x`+64-hex transaction hash are all ordinary artifact content; the
# self-test asserts each of them survives, so this stays a NAME-scoped scan
# and never becomes the blanket hex filter `redact()` was written not to be.
#
# Findings are reported by LOCATION with the value withheld: a scan that
# echoes what it found into a CI log has published the thing it exists to
# withhold, and on a public repository that log is readable by everyone.
EVIDENCE_KEY_NAMES='private_?key|secret_?key|mnemonic|passphrase|seed_?phrase|keystore_password'
EVIDENCE_SEP="[\"']?[[:space:]]*[:=][[:space:]]*[\"']?"
# The redactor's own value shape — an unredacted hex run under a key name
# means the redaction did not reach this file.
EVIDENCE_HEX_ARM="($EVIDENCE_KEY_NAMES)$EVIDENCE_SEP(0x)?[0-9a-fA-F]{8,}"
# 40+ characters of base64 alphabet, not starting with `/` so a long unix path
# under a *_KEY_FILE-shaped name is not a finding. `<redacted>` cannot match:
# `<` is outside the class.
EVIDENCE_B64_ARM="($EVIDENCE_KEY_NAMES)$EVIDENCE_SEP[A-Za-z0-9+=][A-Za-z0-9+/=]{39,}"

# Every basename `run_gate`, `capture_devnet_logs` and `verdict` write into
# the evidence directory, and nothing else. An artifact whose contents nobody
# enumerated is an artifact nobody reviewed, so a file this list does not name
# is a finding rather than a curiosity: add the basename here in the same
# commit that adds the capture, or stop capturing it.
evidence_name_allowed() {
  case "$1" in
    local-up.log|launcher.log|manifest.json|evidence.txt) return 0 ;;
    suite-*.log) return 0 ;;
    *) return 1 ;;
  esac
}

# Replace the VALUE after a key-name separator, so a finding can be reported
# by file and line without republishing the material.
evidence_mask() {
  sed -E "s/(($EVIDENCE_KEY_NAMES)$EVIDENCE_SEP)[^[:space:]\"',]*/\1<<value withheld by scan>>/gI"
}

# Usage: scan_evidence [DIR]   (default: target/e2e-devnet)
# Exit 0 = nothing key-shaped found · 1 = at least one finding, DO NOT UPLOAD.
scan_evidence() {
  local dir="${1:-$repo/target/e2e-devnet}"
  local files=0 findings=0 f base hits h state
  if [ ! -d "$dir" ]; then
    printf '\033[33m::warning::e2e-devnet: scan-evidence: no evidence directory at %s — nothing was captured, so nothing can leave\033[0m\n' "$dir"
    printf 'e2e-devnet: scan-evidence: dir=%s files=0 findings=0 verdict=EMPTY\n' "$dir"
    return 0
  fi
  while IFS= read -r -d '' f; do
    files=$(( files + 1 ))
    base="${f##*/}"
    if ! evidence_name_allowed "$base"; then
      findings=$(( findings + 1 ))
      printf '\033[31m::error::e2e-devnet: scan-evidence: %s is a file this gate does not know how to capture. Unenumerated content is unreviewed content, and this artifact is downloadable by everyone the repository is visible to — add the basename to evidence_name_allowed(), or stop capturing it.\033[0m\n' "$f" >&2
    fi
    # ONE finding per (file,line): a value matching both arms is one leak,
    # not two, so the arms are a union rather than two passes.
    hits="$(grep -a -n -E -i -e "$EVIDENCE_HEX_ARM" -e "$EVIDENCE_B64_ARM" "$f" 2>/dev/null | evidence_mask)"
    if [ -n "$hits" ]; then
      while IFS= read -r h; do
        [ -n "$h" ] || continue
        findings=$(( findings + 1 ))
        printf '\033[31m::error::e2e-devnet: scan-evidence: %s:%s\033[0m\n' "$f" "$h" >&2
        printf '\033[31m::error::e2e-devnet: scan-evidence: the line above assigns a key-shaped value under a key name and was NOT reduced to <redacted> — the redaction did not reach this file.\033[0m\n' >&2
      done <<<"$hits"
    fi
  done < <(find "$dir" -type f -print0 | LC_ALL=C sort -z)
  state=CLEAN
  [ "$findings" -eq 0 ] || state=LEAK
  printf 'e2e-devnet: scan-evidence: dir=%s files=%s findings=%s verdict=%s\n' "$dir" "$files" "$findings" "$state"
  if [ "$findings" -ne 0 ]; then
    printf '\033[31m::error::e2e-devnet: scan-evidence: %s finding(s) — this evidence directory MUST NOT be uploaded.\033[0m\n' "$findings" >&2
    return 1
  fi
  # A clean scan of nothing asserts nothing, and must say so rather than read
  # as a pass: `files=0` in the line above is the number to look at.
  if [ "$files" -eq 0 ]; then
    printf '\033[33m::warning::e2e-devnet: scan-evidence: the directory exists but holds NO files — this run proved nothing about any artifact\033[0m\n'
    return 0
  fi
  note "scan-evidence: $files file(s), none carrying key-shaped material"
  return 0
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
          PLAN_ERRORS+="row $task is declared PENDING but crates/$pkg/tests/$target.rs EXISTS. Stale declaration: the suite landed — move the row to \`live\` in the commit that landed it."$'\n'
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
# S32: ARMED by default. See the latch paragraph in the header — a PENDING
# verdict fails unless the caller opts out with --allow-pending.
require_suites=1

run_gate() {
  build_plan
  print_plan
  if [ -n "$PLAN_ERRORS" ]; then
    printf '\033[31m::error::e2e-devnet: suite registry is inconsistent:\033[0m\n' >&2
    printf '%s' "$PLAN_ERRORS" | sed 's/^/    /' >&2
    return 1
  fi
  local n_run
  n_run="$(grep -c . <<<"$PLAN_RUN")"
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
    PENDING) printf '\033[33m::warning::e2e-devnet: PENDING — %s not written yet. This run DISCHARGES NO GATE for those cases; it is not a pass.\033[0m\n' "$pending_list"
             [ "$require_suites" -eq 1 ] && printf '\033[31m::error::e2e-devnet: and the latch is armed, so this run FAILS. Write the suite, or pass --allow-pending to declare a row ahead of it (S32).\033[0m\n' >&2
             ;;
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
  local copy="$repo/scripts/.e2e-devnet-selftest.sh" out fail=0 sdir=""
  trap 'rm -f "$copy"; [ -n "${sdir:-}" ] && rm -rf "$sdir"' RETURN

  # `extra` is S32's addition: probing a latch that is ON by default needs a
  # probe that can turn it off, or the tolerant direction is unreachable.
  probe() { # <label> <sed-expr> <want-rc> <want-substring> [extra-args…]
    local label="$1" expr="$2" want_rc="$3" want="$4" rc
    shift 4
    sed "$expr" "$repo/scripts/e2e-devnet.sh" > "$copy"
    if cmp -s "$copy" "$repo/scripts/e2e-devnet.sh"; then
      printf '::error:: planted fault %s did not apply — the registry no longer has the shape this self-test patches\n' "$label"
      fail=1; return
    fi
    out="$(bash "$copy" --plan "$@" 2>&1)"; rc=$?
    if [ "$rc" -ne "$want_rc" ] || ! grep -qF "$want" <<<"$out" ; then
      printf '::error:: %s -> exit %s (wanted %s) and the output did not contain %s:\n%s\n' \
        "$label" "$rc" "$want_rc" "$want" "$(printf '%s' "$out" | tail -6)"
      fail=1; return
    fi
    printf '  planted fault: %-42s -> %s\n' "$label" "$want"
  }

  probe "a suite declared LIVE that does not exist" \
        's/^live|S6-S8|antseal-net|ant-backend|devnet_backend|/live|S6-S8|antseal-net|ant-backend|no_such_suite|/' \
        1 'declared LIVE but'
  # Planted against the S6-S8 row, which is live and present and stays that
  # way. The original planted it against S17's *pending* row — which stopped
  # existing the moment S17 landed and the row moved to `live`, taking the
  # probe's own sed with it (a fault that no longer applies is reported as a
  # broken self-test, correctly, but the rule under test would have gone
  # unchecked). Demoting an always-present row is the same "pending +
  # PRESENT" shape and survives every future row flip.
  probe "a stale PENDING row whose suite has landed" \
        's/^live|S6-S8|antseal-net|ant-backend|devnet_backend|/pending|S6-S8|antseal-net|ant-backend|devnet_backend|/' \
        1 'Stale declaration'
  probe "an unknown row status" \
        's/^live|S6-S8|/liev|S6-S8|/' \
        1 "unknown status 'liev'"
  # The verdict half: with a row pending, the gate must be neither red nor a
  # quiet green — PENDING, saying so, and never the word PASS. (Phrased per
  # row rather than "every row" since S17 landed: what matters is that ONE
  # undeclared-absent suite is enough to withhold the verdict.)
  probe "a pending row -> PENDING, not PASS" \
        's/^live|S6-S8|antseal-net|ant-backend|devnet_backend|/pending|S6-S8|antseal-net|ant-backend|not_written_yet|/' \
        0 'DISCHARGES NO GATE' --allow-pending
  out="$(sed 's/^live|S6-S8|antseal-net|ant-backend|devnet_backend|/pending|S6-S8|antseal-net|ant-backend|not_written_yet|/' \
        "$repo/scripts/e2e-devnet.sh" > "$copy"; bash "$copy" --plan --allow-pending 2>&1)"
  if grep -q 'PASS' <<<"$out" ; then
    printf '::error:: an all-pending run printed PASS — a gate that passes with nothing to run is the Q66 class\n'
    fail=1
  fi
  # S32's latch, probed from BOTH sides of the default it now has.
  #
  # The armed direction is the one that matters and it is now the DEFAULT,
  # so it is probed with no flag at all: a probe that only ever passed
  # --require-suites would keep passing if someone reverted the default,
  # which is precisely the regression this latch exists to prevent.
  bash "$copy" --plan >/dev/null 2>&1
  if [ $? -ne 1 ]; then
    printf '::error:: a PENDING row did not fail BY DEFAULT — the anti-rot latch is disarmed, so a pending row can become permanent by inattention (S32)\n'
    fail=1
  else
    printf '  planted fault: %-42s -> %s\n' "PENDING by default (no flag)" "exit 1"
  fi
  # …and the explicit spelling still means the same thing, so CONTRIBUTING's
  # invocation and any existing CI line do not silently change meaning.
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
  if grep -qE '(a{64}|b{64})' <<<"$red" ; then
    printf '::error:: redact() left key material in the capture:\n%s\n' "$red"
    fail=1
  elif ! grep -q '0x4bc1aCE0E66170375462cB4E6Af42Ad4D5EC689C' <<<"$red" ; then
    printf '::error:: redact() destroyed a contract address — the filter must be key-name-scoped, not hex-shaped:\n%s\n' "$red"
    fail=1
  else
    printf '  planted fault: %-42s -> %s\n' "key material in a captured log" "redacted (addresses kept)"
  fi


  # ── The artifact scan (Q243), probed with a CONSTRUCTED fixture ─────────
  #
  # CONSTRUCTED, never derived from a live run. A fixture that reads whatever
  # the last devnet happened to write is green on a machine that has never
  # booted one, and green again for the wrong reason — the shape that disarms
  # itself the moment the state it derives from changes. Every byte below is
  # written here, in a temp directory OUTSIDE the repository, and every
  # planted value is a repeated-character non-key that could not be real.
  sdir="$(mktemp -d "${TMPDIR:-/tmp}/antseal-e2e-scan.XXXXXX")" || {
    printf '::error:: cannot create the scan fixture directory\n'; return 1; }

  local ev="$sdir/20260812T065811Z-3c8095a"
  local digest tx fake_hex fake_b64
  digest="$(printf 'd%.0s' $(seq 64))"                 # a blob digest: bare 64-hex
  tx="0x$(printf 'e%.0s' $(seq 64))"                   # a tx hash: 0x + 64-hex
  fake_hex="0x$(printf 'f%.0s' $(seq 64))"             # the planted "key"
  fake_b64="$(printf 'Z%.0s' $(seq 43))="              # 44 chars, NOT hex

  scan_fixture() { # rebuild the clean, fully-redacted capture from scratch
    rm -rf "$ev"; mkdir -p "$ev"
    printf '%s\n' \
      '{"base_port": 5000, "node_count": 14,' \
      '  "data_dir": "/home/runner/work/antseal/antseal/.devnet/data",' \
      '  "created_at": "2026-08-12T06:58:11Z",' \
      '  "evm": {"rpc_url": "http://127.0.0.1:8545/",' \
      '    "wallet_private_key": "<redacted>",' \
      '    "payment_token_address": "0x4bc1aCE0E66170375462cB4E6Af42Ad4D5EC689C",' \
      '    "payment_vault_address": "0x8464135c8F25Da09e49BC8782676a84730C318bC"}}' \
      > "$ev/manifest.json"
    printf '%s\n' \
      "ANTSEAL_DEVNET_WALLET_PRIVATE_KEY='<redacted>'" \
      "ANTSEAL_DEVNET_TOKEN_ADDRESS='0x4bc1aCE0E66170375462cB4E6Af42Ad4D5EC689C'" \
      "node 0 listening on /ip4/127.0.0.1/udp/5000/quic-v1" \
      > "$ev/launcher.log"
    # The over-redaction direction, in the artifact rather than in the filter:
    # a digest and a tx hash are ordinary content and must NOT be findings.
    printf '%s\n' \
      "chunk stored: $digest" \
      "payment tx: $tx" \
      "test result: ok. 7 passed; 0 failed" \
      > "$ev/suite-S17.log"
    printf '%s\n' "boot: 14 nodes in 6.2s" > "$ev/local-up.log"
    printf '%s\n' "e2e-devnet: PASS commit=3c8095a nodes=14 suites_run=4 failed=[] pending=[] secs=1374" > "$ev/evidence.txt"
  }

  scan_probe() { # <label> <dir> <want-rc> <want-substring>…
    local label="$1" d="$2" want_rc="$3" o rc w
    shift 3
    o="$(bash "$repo/scripts/e2e-devnet.sh" --scan-evidence "$d" 2>&1)"; rc=$?
    if [ "$rc" -ne "$want_rc" ]; then
      printf '::error:: scan probe [%s] -> exit %s (wanted %s):\n%s\n' "$label" "$rc" "$want_rc" "$o"
      fail=1; return
    fi
    for w in "$@"; do
      if ! grep -qF -- "$w" <<<"$o"; then
        printf '::error:: scan probe [%s] exited %s as wanted, but its output did not contain %s — an exit code is not a diagnosis:\n%s\n' \
          "$label" "$rc" "$w" "$o"
        fail=1; return
      fi
    done
    printf '  scan probe:    %-42s -> exit %s, %s\n' "$label" "$rc" \
      "$(grep -o 'files=[0-9]* findings=[0-9]* verdict=[A-Z]*' <<<"$o" | tail -1)"
  }

  # 1. The clean capture passes, and passes for a stated reason: five files,
  #    zero findings — a digest, a contract address and a tx hash all intact.
  scan_fixture
  scan_probe "a fully redacted capture" "$sdir" 0 "files=5 findings=0 verdict=CLEAN"

  # 2. A key that survived redaction, in the file the launcher writes.
  scan_fixture
  sed -i "s/<redacted>\",/$fake_hex\",/" "$ev/manifest.json"
  scan_probe "an unredacted hex key in manifest.json" "$sdir" 1 \
    "manifest.json" "findings=1 verdict=LEAK" "MUST NOT be uploaded"

  # 3. …and its output must not republish what it found. This is the arm that
  #    keeps the fix from being its own leak.
  scan_fixture
  sed -i "s/<redacted>\",/$fake_hex\",/" "$ev/manifest.json"
  out="$(bash "$repo/scripts/e2e-devnet.sh" --scan-evidence "$sdir" 2>&1)"
  if grep -qF -- "$fake_hex" <<<"$out"; then
    printf '::error:: scan-evidence echoed the key it found into its own output — the report is now the leak\n'
    fail=1
  else
    printf '  scan probe:    %-42s -> %s\n' "the finding withholds the value" "value not in the report"
  fi

  # 4. A base64 key. The redactor is hex-only and cannot see this at all, so
  #    this arm exercises the SECOND pattern rather than filling a slot the
  #    first one already covers (it contains no hex-only run of length 8).
  scan_fixture
  printf "%s\n" "ANTSEAL_DEVNET_WALLET_PRIVATE_KEY='$fake_b64'" >> "$ev/launcher.log"
  scan_probe "a base64 key the hex filter cannot see" "$sdir" 1 \
    "launcher.log" "findings=1 verdict=LEAK"

  # 5. A key name the REDACTOR does not carry — proof the scan is genuinely
  #    broader than the filter it backs up, not a copy of it.
  scan_fixture
  printf "%s\n" "mnemonic = $(printf '1%.0s' $(seq 32))" >> "$ev/suite-S17.log"
  scan_probe "a key name redact() does not cover" "$sdir" 1 \
    "suite-S17.log" "findings=1 verdict=LEAK"

  # 6. A file nobody enumerated — the refactor that adds a capture and forgets
  #    that an artifact is a publication.
  scan_fixture
  printf '%s\n' "some new capture" > "$ev/extra-capture.txt"
  scan_probe "a file the capture does not enumerate" "$sdir" 1 \
    "extra-capture.txt" "does not know how to capture" "findings=1 verdict=LEAK"

  # 7. The empty directions, stated rather than silent: an absent directory is
  #    a pass that asserts nothing, and must say EMPTY rather than CLEAN.
  scan_probe "no evidence directory at all" "$sdir/never-ran" 0 \
    "files=0 findings=0 verdict=EMPTY"
  rm -rf "$sdir"; mkdir -p "$sdir"
  scan_probe "an evidence directory with no files" "$sdir" 0 \
    "files=0 findings=0 verdict=CLEAN" "proved nothing about any artifact"

  # Control: the registry as committed must validate.
  out="$(bash "$repo/scripts/e2e-devnet.sh" --plan 2>&1)"
  if [ $? -ne 0 ]; then
    printf '::error:: the committed registry does not validate; nothing above means anything:\n%s\n' "$out"
    fail=1
  fi
  printf '  control (committed registry)%29s -> %s\n' '' "$(printf '%s' "$out" | grep -o 'e2e-devnet: [A-Z]*' | tail -1)"
  [ "$fail" -eq 0 ] || return 1
  note "e2e-devnet self-test PASS — the registry rules, the redaction filter and the artifact scan all go red on planted faults"
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --nodes) shift; nodes="${1:-}"; [ -n "$nodes" ] || die "--nodes needs a value" ;;
    --keep-devnet)    keep_devnet=1 ;;
    --plan)           plan_only=1 ;;
    # Kept for callers that spell the default out loud (CONTRIBUTING, CI).
    --require-suites) require_suites=1 ;;
    --allow-pending)  require_suites=0 ;;
    --list-suites)    suite_registry; exit 0 ;;
    --self-test)      self_test; exit $? ;;
    --scan-evidence)  shift; scan_evidence "${1:-$repo/target/e2e-devnet}"; exit $? ;;
    -h|--help)        sed -n '1,33p' "$repo/scripts/e2e-devnet.sh"; exit 0 ;;
    *) die "unknown argument: $1 (see --help)" ;;
  esac
  shift
done

run_gate
