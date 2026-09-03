#!/usr/bin/env bash
# Q32 Do (a) — the Sepolia-mode release-candidate E2E driver.
#
# Drives a PREBUILT release-candidate `antseal` binary end-to-end against
# Arbitrum Sepolia (chain 421614 — NOT Ethereum Sepolia), in the row's own
# order:
#
#   init -> funding preflight -> multi-file seal --split -> status --upgrade
#        -> reveal subset -> verify (offline, --online, --live)
#        -> restore + byte-compare
#
# A green run of this script is Q32 Accept row 1's DEADLINE: "Sepolia run
# green before any mainnet action". Green here gates mainnet; it does not
# discharge anything else.
#
# ── THIS SCRIPT HAS NEVER RUN ─────────────────────────────────────────────
#
# Writing a witness is not witnessing (D166's discipline: the workflow that
# has never executed is a CLAIM, not evidence). Every stage below is derived
# from the CLI surface as committed (crates/antseal-cli/src/cli.rs) and the
# P17 helpers, but no live Sepolia run has ever executed it. The first run
# is a calibration event: expect it to find a wrong assumption, and fix the
# script rather than the evidence. Until then the TESTED path is the
# refusal path — the preflight below refuses loudly, with a named reason,
# whenever the environment is not ready, and that refusal is what the
# repository's own verification exercised.
#
# What this script deliberately does NOT do:
#   * boot a devnet — scripts/devnet/sepolia-up owns boot (and the build of
#     the launcher); this driver ATTACHES to a running Sepolia-mode devnet
#     and refuses when there is none;
#   * build anything — the release-candidate binary arrives prebuilt via
#     ANTSEAL_RC_BIN (a driver that cargo-builds its subject is testing the
#     tree, not the candidate);
#   * fund anything — funding is a MAINTAINER action (P17, D38); the
#     funding preflight here is read-only and refusal-only;
#   * wire into any gate or workflow — the hosted-CI billing gate refuses
#     hosted runs today, and wiring this into local-gate.sh or a workflow
#     is a later, separate decision. Nothing invokes this script.
#
# The ONLY paid stage is `seal` (real test-ANT + Sepolia gas). Everything
# after it is unpaid: status --upgrade polls calendars, verify --online
# reads public endpoints, verify --live re-fetches already-paid-for
# ciphertexts, restore likewise.
#
# Usage:
#   scripts/e2e-sepolia.sh --plan      registry + env contract; no network,
#                                      no binary, REAL_EXIT=0
#   scripts/e2e-sepolia.sh             the run (refuses without the env)
#
# Environment contract (all refusals are named; see preflight_refusals):
#   ANTSEAL_RC_BIN                path to the prebuilt release-candidate
#                                 `antseal` binary (executable)
#   ANTSEAL_E2E_WALLET_ADDRESS    0x address of the FUNDED Sepolia wallet
#                                 (public; checked read-only via
#                                 scripts/devnet/sepolia-preflight)
#   ANTSEAL_E2E_WALLET_KEY_FILE   file holding that wallet's key material,
#                                 fed to `init --wallet import` over an fd
#                                 (D41: secrets never transit argv or the
#                                 environment); keep it OUTSIDE the repo
#   ANTSEAL_E2E_PASSPHRASE_FILE   file holding the test vault passphrase,
#                                 fed over an fd; test-only value, OUTSIDE
#                                 the repo
#   ANTSEAL_E2E_WORKDIR           optional scratch dir (default: mktemp)
#
# Exit: 0 = PASS (or PLAN under --plan) · 1 = FAIL or REFUSED (reason named on stderr).
set -uo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo" || exit 1

note() { printf '\033[36m==>\033[0m %s\n' "$*"; }

# A named refusal: the default outcome today, and the tested one. One line,
# machine-greppable, nonzero.
refuse() { # <REASON-CODE> <explanation…>
  local reason="$1"; shift
  printf '\033[31m::error::e2e-sepolia: PREFLIGHT-REFUSED reason=%s — %s\033[0m\n' "$reason" "$*" >&2
  printf 'e2e-sepolia: REFUSED reason=%s commit=%s\n' "$reason" \
    "$(git rev-parse --short HEAD 2>/dev/null || echo nogit)"
  exit 1
}

# Same key-name-scoped redaction as e2e-devnet.sh (project rule 6 binds the
# PATTERN, not just real secrets): key material never reaches a capture, but
# blob digests, addresses and tx hashes — what makes a failure log worth
# keeping — survive. One filter, applied before the tee fork, so the file
# and the terminal see the same bytes (the Q256 lesson).
redact() {
  sed -E "$@" "s/(wallet_private_key|[A-Za-z_]*PRIVATE_KEY|[A-Za-z_]*SECRET_KEY)([\"']?[[:space:]]*[:=][[:space:]]*[\"']?)(0x)?[0-9a-fA-F]{8,}/\1\2<redacted>/g"
}
capture_through() { redact -u | tee "$1"; }

# ── The stage registry ────────────────────────────────────────────────────
#
# id|function|what it does — ONE table drives both `--plan` and the run,
# so the plan cannot drift from the execution (the e2e-devnet.sh rule).
# The order is Q32 Do (a)'s, verbatim.
stage_registry() {
  cat <<'EOF'
S1|st_preflight|funding preflight: scripts/devnet/sepolia-preflight --address <wallet> (read-only; exit 3 = NOT FUNDED = refusal)
S2|st_init|init: fresh vault under an isolated ANTSEAL_DIR; --wallet import over an fd; passphrase over an fd
S3|st_seal|seal: three fixture text files, --split blank-lines --title --yes --json (THE PAID STAGE); work-id parsed from the JSON envelope
S4|st_status_upgrade|status <work-id> --upgrade: poll OTS calendars, complete pending attestations
S5|st_reveal|reveal <work-id> --units 0,2 (a strict subset) -o subset.sealproof --yes
S6|st_verify_offline|verify subset.sealproof — fully offline, no vault
S7|st_verify_online|verify subset.sealproof --online — pinned must-agree public endpoints
S8|st_verify_live|verify subset.sealproof --live — re-fetch ciphertexts from the network, byte-compare against the bundle
S9|st_restore_compare|restore <work-id> -o restored/ and byte-compare EVERY original against its restored copy (cmp + sha256, both sides recorded)
EOF
}

print_plan() {
  note "Q32 Do (a) stage plan (Arbitrum Sepolia, chain 421614):"
  local id fn what
  while IFS='|' read -r id fn what; do
    [ -n "${id:-}" ] || continue
    printf '    RUN  %-3s %s\n' "$id" "$what"
  done <<EOF
$(stage_registry)
EOF
  printf '\n'
  note "environment contract (each absence is a NAMED refusal):"
  printf '    %s\n' \
    'ANTSEAL_RC_BIN               prebuilt release-candidate binary' \
    'ANTSEAL_E2E_WALLET_ADDRESS   funded wallet 0x address (public)' \
    'ANTSEAL_E2E_WALLET_KEY_FILE  wallet key file, fed via fd, outside the repo' \
    'ANTSEAL_E2E_PASSPHRASE_FILE  vault passphrase file, fed via fd, outside the repo' \
    'a RUNNING Sepolia-mode devnet (scripts/devnet/sepolia-up) with .devnet/env' \
    'ANTSEAL_E2E_WORKDIR          optional scratch dir'
}

# ── Preflight (offline half): every named refusal, cheapest first ─────────
preflight_refusals() {
  [ -n "${ANTSEAL_RC_BIN:-}" ] \
    || refuse RC-BINARY-ABSENT "ANTSEAL_RC_BIN is not set. This driver consumes a PREBUILT release-candidate binary; it never builds one."
  [ -x "${ANTSEAL_RC_BIN}" ] \
    || refuse RC-BINARY-ABSENT "ANTSEAL_RC_BIN=${ANTSEAL_RC_BIN} is not an executable file."
  [ -n "${ANTSEAL_E2E_WALLET_ADDRESS:-}" ] \
    || refuse WALLET-ADDRESS-ABSENT "ANTSEAL_E2E_WALLET_ADDRESS is not set — the funding preflight needs the funded wallet's public 0x address (funding itself is the maintainer's P17 act)."
  printf '%s' "${ANTSEAL_E2E_WALLET_ADDRESS}" | grep -qE '^0x[0-9a-fA-F]{40}$' \
    || refuse WALLET-ADDRESS-ABSENT "ANTSEAL_E2E_WALLET_ADDRESS is not a 0x + 40-hex address."
  [ -n "${ANTSEAL_E2E_WALLET_KEY_FILE:-}" ] && [ -s "${ANTSEAL_E2E_WALLET_KEY_FILE:-/nonexistent}" ] \
    || refuse WALLET-KEY-ABSENT "ANTSEAL_E2E_WALLET_KEY_FILE does not name a non-empty readable file. The key is fed to init over an fd and never transits argv, the environment, or a log."
  [ -n "${ANTSEAL_E2E_PASSPHRASE_FILE:-}" ] && [ -s "${ANTSEAL_E2E_PASSPHRASE_FILE:-/nonexistent}" ] \
    || refuse PASSPHRASE-ABSENT "ANTSEAL_E2E_PASSPHRASE_FILE does not name a non-empty readable file (D41: the passphrase channel is an fd, never argv or env)."
  [ -x "$repo/scripts/devnet/sepolia-preflight" ] \
    || refuse HELPER-ABSENT "scripts/devnet/sepolia-preflight is missing — this driver reuses the P17 helper rather than duplicating its chain-id and contract checks."
  # A running Sepolia-mode devnet is a precondition, not something this
  # script boots (sepolia-up owns boot, and the one-per-checkout pidfile).
  local pidfile="$repo/.devnet/launcher.pid" envfile="$repo/.devnet/env" pid
  [ -f "$envfile" ] \
    || refuse SEPOLIA-DEVNET-NOT-RUNNING "no environment export at .devnet/env — boot the Sepolia-mode devnet first: scripts/devnet/sepolia-up --nodes 14"
  pid="$(cat "$pidfile" 2>/dev/null || true)"
  { [ -n "$pid" ] && [ -d "/proc/$pid" ]; } \
    || refuse SEPOLIA-DEVNET-NOT-RUNNING "no live launcher pid — the devnet export exists but nothing is running. scripts/devnet/sepolia-up --nodes 14"
  grep -q "ANTSEAL_DEVNET_NETWORK='arbitrum-sepolia'" "$envfile" \
    || refuse WRONG-DEVNET-MODE "the running devnet's export is not Sepolia-mode (expected ANTSEAL_DEVNET_NETWORK='arbitrum-sepolia'). A local Anvil devnet would silently drive the wrong chain — run scripts/devnet/local-down, then scripts/devnet/sepolia-up."
}

# ── Stage machinery ───────────────────────────────────────────────────────
evdir=""
workdir=""

# The work id crosses stages through the evidence file st_seal writes —
# stage functions run in pipeline subshells, so a variable cannot carry it.
current_work_id() {
  local wid
  wid="$(cat "$evdir/work-id.txt" 2>/dev/null || true)"
  printf '%s' "$wid" | grep -qE '^[0-9a-f]{64}$' || {
    printf '::error::e2e-sepolia: no recorded work id (did S3 run?)\n' >&2
    return 1
  }
  printf '%s' "$wid"
}

run_stage() { # <id> <fn>
  local id="$1" fn="$2" rc log="$evdir/stage-$1.log"
  note "$id: $fn"
  "$fn" 2>&1 | capture_through "$log"
  rc="${PIPESTATUS[0]}"
  printf 'REAL_EXIT=%s\n' "$rc" > "$evdir/stage-$id.exit"
  if [ "$rc" -ne 0 ]; then
    printf '\033[31m    %s FAIL (REAL_EXIT=%s, log: %s)\033[0m\n' "$id" "$rc" "$log" >&2
    return 1
  fi
  printf '    %s PASS\n' "$id"
}

# antseal with the vault-touching plumbing: isolated ANTSEAL_DIR, Sepolia
# network, devnet env, passphrase on fd 3. Key material only ever crosses
# fd 4, and only in st_init.
antseal_vault() {
  ANTSEAL_DIR="$workdir/home" ANTSEAL_DEVNET_ENV="$repo/.devnet/env" \
    "$ANTSEAL_RC_BIN" --network arbitrum-sepolia --passphrase-fd 3 "$@" \
    3< "$ANTSEAL_E2E_PASSPHRASE_FILE"
}

st_preflight() {
  scripts/devnet/sepolia-preflight --address "$ANTSEAL_E2E_WALLET_ADDRESS"
  local rc=$?
  case "$rc" in
    0) return 0 ;;
    3) printf '::error::e2e-sepolia: PREFLIGHT-REFUSED reason=WALLET-NOT-FUNDED — the wallet holds zero gas or zero test ANT. Funding is a MAINTAINER action (docs/devnet/sepolia-devnet.md, P17); this driver never funds.\n' >&2
       return 1 ;;
    *) printf '::error::e2e-sepolia: PREFLIGHT-REFUSED reason=CHAIN-PREFLIGHT-FAILED — sepolia-preflight exited %s (wrong chain, missing contracts, or no RPC). Do not proceed.\n' "$rc" >&2
       return 1 ;;
  esac
}

st_init() {
  ANTSEAL_DIR="$workdir/home" ANTSEAL_DEVNET_ENV="$repo/.devnet/env" \
    "$ANTSEAL_RC_BIN" --network arbitrum-sepolia --passphrase-fd 3 \
    init --wallet import --wallet-key-fd 4 \
    3< "$ANTSEAL_E2E_PASSPHRASE_FILE" 4< "$ANTSEAL_E2E_WALLET_KEY_FILE"
}

st_seal() {
  # Three text files, blank-line boundaries, so --split blank-lines yields
  # a real multi-unit tree and S5 can reveal a strict subset.
  mkdir -p "$workdir/originals" || return 1
  printf 'alpha section one\n\nalpha section two\n\nalpha section three\n' > "$workdir/originals/alpha.txt"
  printf 'bravo opening\n\nbravo middle\n\nbravo closing\n'                > "$workdir/originals/bravo.txt"
  printf '# charlie\n\nfirst paragraph\n\nsecond paragraph\n'              > "$workdir/originals/charlie.md"
  ( cd "$workdir/originals" && sha256sum alpha.txt bravo.txt charlie.md ) \
    | tee "$evdir/fixture-hashes.txt" || return 1

  # Machine mode (--json, D51): exactly one JSON document on stdout, human
  # copy on stderr — so stdout goes to its own evidence file for parsing
  # and stderr flows through the stage capture.
  antseal_vault --json seal \
      "$workdir/originals/alpha.txt" \
      "$workdir/originals/bravo.txt" \
      "$workdir/originals/charlie.md" \
      --title "Q32 sepolia e2e" --split blank-lines --yes \
      > "$workdir/seal-stdout.json" || return 1
  redact < "$workdir/seal-stdout.json" > "$evdir/seal.json"

  # The work id: prefer the envelope's `work_id` key; fall back to the one
  # 64-hex value the envelope must carry (work_id = SHA-256(manifest body)).
  # First-run calibration point: if the key is spelled otherwise, fix THIS
  # extraction, not the evidence.
  #
  # Persisted to a FILE, never a variable: every stage function runs as a
  # pipeline component — a subshell — so an assignment here would be
  # invisible to the stages that need it.
  local work_id
  work_id="$(python3 - "$evdir/seal.json" <<'PY'
import json, re, sys
raw = open(sys.argv[1], encoding="utf-8", errors="replace").read()
ids = []
try:
    doc = json.loads(raw)
except Exception:
    doc = None
def walk(node):
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "work_id" and isinstance(value, str):
                yield value
            yield from walk(value)
    elif isinstance(node, list):
        for value in node:
            yield from walk(value)
if doc is not None:
    ids = list(walk(doc))
if not ids:
    ids = re.findall(r"\b[0-9a-f]{64}\b", raw)
print(ids[0] if ids else "")
PY
)"
  if ! printf '%s' "$work_id" | grep -qE '^[0-9a-f]{64}$'; then
    printf '::error::e2e-sepolia: WORK-ID-UNPARSED — seal succeeded but no work id could be read from the JSON envelope (see seal.json in the evidence dir). Fix the extraction, then re-run.\n' >&2
    return 1
  fi
  printf '%s\n' "$work_id" > "$evdir/work-id.txt"
  printf 'work id: %s\n' "$work_id"
}

st_status_upgrade() {
  local wid; wid="$(current_work_id)" || return 1
  antseal_vault status "$wid" --upgrade
}

st_reveal() {
  local wid; wid="$(current_work_id)" || return 1
  antseal_vault reveal "$wid" --units 0,2 -o "$workdir/subset.sealproof" --yes
}

# verify needs no vault and never prompts — invoked bare, no fds.
st_verify_offline() { "$ANTSEAL_RC_BIN" verify "$workdir/subset.sealproof"; }
st_verify_online()  { "$ANTSEAL_RC_BIN" verify "$workdir/subset.sealproof" --online; }
st_verify_live() {
  ANTSEAL_DEVNET_ENV="$repo/.devnet/env" \
    "$ANTSEAL_RC_BIN" --network arbitrum-sepolia verify "$workdir/subset.sealproof" --live
}

st_restore_compare() {
  local wid; wid="$(current_work_id)" || return 1
  antseal_vault restore "$wid" -o "$workdir/restored" || return 1
  # The row's own words: restore ends in a BYTE-compare. cmp answers
  # identical-or-not; sha256 of BOTH sides goes into the log so the
  # evidence carries the values, not just a verdict word.
  local name orig got rc=0
  for name in alpha.txt bravo.txt charlie.md; do
    orig="$workdir/originals/$name"
    got="$(find "$workdir/restored" -type f -name "$name" | head -1)"
    if [ -z "$got" ]; then
      printf '::error::e2e-sepolia: RESTORE-COMPARE-FAILED — %s was not produced by restore\n' "$name" >&2
      rc=1; continue
    fi
    if cmp -s "$orig" "$got"; then
      printf 'byte-identical: %s\n' "$name"
    else
      printf '::error::e2e-sepolia: RESTORE-COMPARE-FAILED — %s differs from its restored copy\n' "$name" >&2
      rc=1
    fi
    sha256sum "$orig" "$got"
  done
  return "$rc"
}

# ── Verdict — one greppable line, e2e-devnet.sh's shape ───────────────────
verdict() { # <stages_run> <failed> <secs> <evnote> [plan]
  local state rc=0 tag="${5:-}"
  # A plan is not a PASS: the state word itself must refuse the misreading,
  # so a grep for 'e2e-sepolia: PASS' can never match a plan-only invocation
  # (the shape D165 reddened: a confident verdict textually identical to a
  # full run's). stages_run is 0 on a plan by definition.
  if [ -n "$2" ]; then state=FAIL; rc=1
  elif [ "$tag" = plan ]; then state=PLAN
  else state=PASS; fi
  local counts="stages_run=$1"
  [ "$tag" = plan ] && counts="stages_planned=$1 stages_run=0"
  local line
  line="$(printf 'e2e-sepolia: %s commit=%s network=arbitrum-sepolia %s failed=[%s] secs=%s evidence=%s' \
    "$state" "$(git rev-parse --short HEAD 2>/dev/null || echo nogit)" \
    "$counts" "$(printf '%s' "$2" | tr -s ' ' ',' | sed 's/,$//')" "$3" "$4")"
  line="$(printf '%s' "$line" | redact)"
  printf '\n%s\n' "$line"
  [ -d "$4" ] && printf '%s\n' "$line" > "$4/evidence.txt"
  case "$state" in
    PLAN)
      # Writing is not witnessing (D166): PLAN validated the registry and the
      # env contract, and must never read as the deadline being met — only a
      # real run's PASS says that.
      printf '\033[32me2e-sepolia: plan validated — nothing executed, nothing paid, nothing witnessed.\033[0m\n' ;;
    PASS)
      printf '\033[32me2e-sepolia: PASS — Q32 Accept row 1'\''s Sepolia-green deadline is met for this commit and binary.\033[0m\n' ;;
    FAIL) printf '\033[31m::error::e2e-sepolia: FAIL — see the stage logs under %s\033[0m\n' "$4" >&2 ;;
  esac
  return "$rc"
}

# ── Entry ─────────────────────────────────────────────────────────────────
plan_only=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --plan) plan_only=1 ;;
    -h|--help) sed -n '1,75p' "$repo/scripts/e2e-sepolia.sh"; exit 0 ;;
    *) printf '\033[31m::error::e2e-sepolia: unknown argument: %s (see --help)\033[0m\n' "$1" >&2; exit 1 ;;
  esac
  shift
done

n_stages="$(stage_registry | grep -c .)"

if [ "$plan_only" -eq 1 ]; then
  print_plan
  verdict "$n_stages" "" "0" "(plan only — nothing executed, nothing paid)" plan
  exit $?
fi

print_plan
preflight_refusals

started="$(date -u +%s)"
evdir="$repo/target/e2e-sepolia/$(date -u +%Y%m%dT%H%M%SZ)-$(git rev-parse --short HEAD 2>/dev/null || echo nogit)"
mkdir -p "$evdir" || refuse EVIDENCE-DIR-UNWRITABLE "cannot create $evdir"
workdir="${ANTSEAL_E2E_WORKDIR:-$(mktemp -d "${TMPDIR:-/tmp}/antseal-e2e-sepolia.XXXXXX")}"
mkdir -p "$workdir" || refuse WORKDIR-UNWRITABLE "cannot create $workdir"
note "evidence: $evdir"
note "workdir:  $workdir (holds the test vault — remove it after reading the evidence)"

failed=""
while IFS='|' read -r id fn what; do
  [ -n "${id:-}" ] || continue
  if ! run_stage "$id" "$fn"; then
    failed="$id"
    break   # every later stage depends on this one; running on is noise
  fi
done <<EOF
$(stage_registry)
EOF

verdict "$n_stages" "$failed" "$(( $(date -u +%s) - started ))" "$evdir"
