#!/usr/bin/env bash
# The Q6 golden-vector freeze lane, end to end.
#
#   ./scripts/vector-freeze.sh              # the lane: must be GREEN
#   ./scripts/vector-freeze.sh --self-test  # test-of-the-test: must go RED
#   ./scripts/vector-freeze.sh --update     # regenerate the digest blocks
#
# Contract (the byte pin is Q6's own act, executed at Q14; tasks/Q.md Q6):
# each `testdata/vectors/v<n>/FROZEN.sha256` pins the exact bytes of every
# committed vector of that format version AND is the must-exist list, so a
# deleted vector file — which the Q4 runner structurally cannot notice,
# since it only executes files it finds — turns this lane red.
#
# Retention — per version, indefinite — IS spec, and BOTH lines state it:
# MVP-SPEC.md line 123 ("per-version golden vectors are retained in CI
# indefinitely") and line 167 ("empty-anchor and per-version vectors retained
# in CI forever"). Neither states the byte pin.
#
# ── Authority: what makes a byte change illegal (Q148) ─────────────────────
#
# Q6's freeze manifest, flipped to `#! status frozen` at Q14 — NOT MVP-SPEC.md
# line 123. Line 123's first clause is the *compatibility* rule: "every
# RELEASED manifest/bundle format version remains verifiable by all future CLI
# and page releases", and D104 §1.5 measures with three independent
# confirmations that nothing has been released. Cited as the source of
# byte-immutability it is a conditional whose condition is false today, so a
# reader who checks it may conclude the freeze is soft — the inference D108 §3
# spends a section refusing. Q6/Q14 impose a STRONGER, self-imposed discipline
# than line 123 requires; line 123 is what it protects once a version ships.
#
# Two independent layers, both required:
#
#   1. coreutils `sha256sum -c`, which shares no code with antseal, so a
#      bug in our own hasher cannot make a tampered tree look clean. The
#      manifest is `sha256sum -c` compatible by design (`#` = comment).
#   2. `cargo test --test vector_freeze`, the authoritative checker: the
#      directive vocabulary, the misfiled/unfrozen/stray classes, the
#      per-version retention rule, the pending must-exist obligations, and
#      the Q14 zero-pending gate condition. It carries the tests-of-the-test
#      for every failure class.
#
# --self-test copies the vector tree to a scratch directory, mutates one
# frozen byte and deletes one frozen file there, and requires layer 1 to go
# red on the copy — red WITH THE RIGHT MESSAGE, never merely nonzero (Q149;
# the rule and the register of instruments that owe it are in
# scripts/lib/red-arm.sh). The committed tree is never touched. Layer 2's own
# tests-of-the-test live in crates/antseal-core/tests/vector_freeze.rs.
#
# --update rewrites each manifest's digest block from the tree, preserving
# the prose and `#!` directives. While `#! status pre-freeze` it may rewrite
# an entry (a recorded, justified regeneration — review the digest diff).
# Once Q14 sets `#! status frozen` it REFUSES to modify or drop an entry:
# additions are then the only legal change.
#
# --verdict-event <Dnn> is the ONE exception, and it is checked, not trusted.
#
# D94 minted a third class of moved pin. A `report` vector's bytes are a
# *function of the verifier*, which is not frozen and keeps changing through
# M2/M3/M4 — so "the bytes moved" and "the format moved" are the same
# statement for every other kind and are NOT the same statement here. D94
# Ruling 4 says the three classes are told apart **mechanically, not
# editorially**, and this is where "mechanically" has to live: a flag that
# merely asserted the classification would be the editorial version with an
# extra step. So the flag only unlocks the check below, which re-derives the
# classification from the diff against `HEAD` and refuses if it does not hold:
#
#   * only a `report/` kind vector may move at all (every other kind pins
#     format artifacts, where a moved byte really is a moved format);
#   * `bundle_len`, `bundle_sha256` and `revealed_unit_ids` byte-identical on
#     every case — the same inputs, so what moved is what the verifier SAYS
#     about them (this is the sentence that distinguishes it from a FIXTURE
#     EVENT);
#   * `report_version` unchanged on every case;
#   * at least one case unchanged — a FORMAT EVENT moves all of them at once,
#     which is what R32 measured when report_version 0 -> 1 rewrote all 21.
#
# First use: R12 (D94), which moved 1 of 21 cases and 0 bundle digests.
#
# Doc: testdata/vectors/README.md (contract), testdata/README.md (retention).
set -euo pipefail

cd "$(dirname "$0")/.."

# shellcheck source=lib/red-arm.sh
. scripts/lib/red-arm.sh

MODE="check"
VERDICT_EVENT=""
case "${1:-}" in
  "")           MODE="check" ;;
  --self-test)  MODE="self-test" ;;
  --update)     MODE="update" ;;
  *) echo "usage: $0 [--self-test | --update [--verdict-event <Dnn>]]" >&2; exit 2 ;;
esac
if [ "${MODE}" = "update" ] && [ "${2:-}" = "--verdict-event" ]; then
  VERDICT_EVENT="${3:-}"
  case "${VERDICT_EVENT}" in
    D[0-9]*) ;;
    *) echo "usage: --verdict-event needs the deciding record, e.g. D94" >&2; exit 2 ;;
  esac
fi

VECTORS="testdata/vectors"
# Is this file's move a VERDICT EVENT? Re-derived from the diff against HEAD,
# never taken on the flag's word. Prints the four numbers D94's commit-message
# rule requires, so the audit record is produced by the check rather than typed
# by the person the check is guarding against.
verdict_event_ok() {
  python3 - "$1" <<'PY'
import json, subprocess, sys

path = sys.argv[1]
rel = path[2:] if path.startswith("./") else path

def fail(msg):
    print(f"::error::not a verdict event: {msg}")
    sys.exit(1)

if "/report/" not in f"/{rel}":
    fail(f"`{rel}` is not a `report` kind vector. Only a report's bytes are a function "
         "of the verifier; every other kind pins format artifacts, where a moved byte "
         "IS a moved format (D94 §2a)")

try:
    before = json.loads(subprocess.run(["git", "show", f"HEAD:{rel}"],
                                       capture_output=True, check=True).stdout)
except subprocess.CalledProcessError:
    fail(f"`{rel}` is not at HEAD, so there is nothing to classify against")
after = json.loads(open(rel, "rb").read())

b, a = before["expect"]["cases"], after["expect"]["cases"]
if len(b) != len(a):
    fail(f"the case count moved ({len(b)} -> {len(a)}); a verdict event re-values "
         "existing cases and adds none")

moved = []
for i, (x, y) in enumerate(zip(b, a)):
    for k in ("bundle_len", "bundle_sha256", "revealed_unit_ids"):
        if x.get(k) != y.get(k):
            fail(f"case {i} moved `{k}` — the INPUT changed, which makes this a FIXTURE "
                 "EVENT. It moves frozen bundle/manifest vectors too and needs its own "
                 "decision (D94 §5)")
    if x.get("report", {}).get("report_version") != y.get("report", {}).get("report_version"):
        fail(f"case {i} moved `report_version` — that is a FORMAT EVENT and needs the "
             "R32 coupled-edit procedure, not this flag")
    if x != y:
        moved.append(i)

if not moved:
    fail("no case moved, so the digest changed for some reason this check cannot see")
if len(moved) == len(a):
    fail(f"all {len(a)} cases moved. A format event moves every case at once (R32 "
         "measured exactly that at report_version 0 -> 1); a verdict event does not")

print(f"    {len(moved)} of {len(a)} report cases moved (cases {moved}); "
      f"0 bundle digests moved; report_version unchanged")
PY
}

MANIFEST="FROZEN.sha256"
# F10's per-version roster. An auxiliary, not a vector: it is the list *of*
# the frozen set and changes whenever a vector lands, so freezing it would
# make every registration read as a format event. Held to the tree — and
# cross-checked against this manifest — by tests/vector_index.rs.
INDEX="INDEX.json"

# Prefer coreutils; fall back to the Perl `shasum` shipped on macOS. Comments
# are stripped before piping, so both tools see only digest lines.
if command -v sha256sum >/dev/null 2>&1; then
  SUM=(sha256sum)
elif command -v shasum >/dev/null 2>&1; then
  SUM=(shasum -a 256)
else
  echo "::error::neither sha256sum nor shasum is available — layer 1 cannot run" >&2
  exit 1
fi

version_dirs() {
  # Sorted, deterministic, and empty output is a caller-visible failure.
  find "$1" -mindepth 1 -maxdepth 1 -type d -name 'v[0-9]*' | LC_ALL=C sort
}

# Layer 1 over one vector tree. Prints per-version results; returns non-zero
# if any version fails or is missing its manifest.
check_digests() {
  local root="$1" rc=0 dir version count detail line
  local dirs
  dirs="$(version_dirs "${root}")"
  if [ -z "${dirs}" ]; then
    echo "::error::${root}: no format-version directories found"
    return 1
  fi
  while IFS= read -r dir; do
    version="$(basename "${dir}")"
    if [ ! -f "${dir}/${MANIFEST}" ]; then
      echo "::error::${dir}/${MANIFEST} is missing — every retained format version must be frozen"
      rc=1
      continue
    fi
    count="$(grep -cv '^#' "${dir}/${MANIFEST}" || true)"
    if [ "${count}" -eq 0 ]; then
      echo "::error::${dir}/${MANIFEST} pins zero vectors — an empty freeze asserts nothing"
      rc=1
      continue
    fi
    if ( cd "${dir}" && grep -v '^#' "${MANIFEST}" | "${SUM[@]}" -c - >/dev/null ); then
      echo "  ${version}: ${count} frozen vector(s) OK (independent ${SUM[*]} check)"
    else
      echo "::error::${dir}/${MANIFEST}: digest check FAILED — a frozen vector was modified or deleted"
      # WHICH of the two, said in our own words (Q149). `sha256sum -c` already
      # distinguishes them — `<file>: FAILED` for a content mismatch,
      # `<file>: FAILED open or read` for an absent one — and collapsing both
      # into the single verdict above is what left this script's two red arms,
      # a MUTATION and a DELETION of the same victim, accepting each other's
      # evidence. Ours rather than coreutils' wording because the arms match on
      # it: `FAILED` is a prefix of `FAILED open or read`, and the second half
      # of that sentence is locale- and implementation-dependent.
      detail="$( cd "${dir}" && grep -v '^#' "${MANIFEST}" | "${SUM[@]}" -c - 2>&1 | grep -v ': OK$' || true )"
      while IFS= read -r line; do
        case "${line}" in
          *': FAILED open or read')
            echo "::error::${dir}: frozen vector MISSING or unreadable: ${line%: FAILED open or read}" ;;
          *': FAILED')
            echo "::error::${dir}: frozen vector MODIFIED: ${line%: FAILED}" ;;
        esac
      done <<< "${detail}"
      printf '%s\n' "${detail}"
      rc=1
    fi
  done <<< "${dirs}"
  return "${rc}"
}

case "${MODE}" in

check)
  echo "vector-freeze layer 1 — independent digest check (${SUM[*]}):"
  check_digests "${VECTORS}"
  echo "vector-freeze layer 2 — authoritative checker:"
  cargo test -p antseal-core --locked --test vector_freeze
  echo "vector-freeze: GREEN"
  ;;

self-test)
  # Prove layer 1 actually goes red. Everything happens on a copy; the
  # committed tree is read-only here.
  SCRATCH="$(mktemp -d)"
  trap 'rm -rf "${SCRATCH}"' EXIT
  cp -R "${VECTORS}/." "${SCRATCH}/"

  # Both arms below are `assert_red <the message this fault produces> ...`,
  # not "did it exit nonzero" (Q149 — scripts/lib/red-arm.sh carries the
  # rule). The two arms tamper with the SAME victim in two different ways, so
  # before this they accepted each other's evidence, and both accepted a
  # vanished manifest, an unreadable scratch directory or a missing sha256sum.
  echo "self-test: the untouched copy must be GREEN"
  if ! assert_green check_digests "${SCRATCH}"; then
    echo "::error::the unmodified copy already fails — the self-test cannot conclude anything"
    printf '%s\n' "${ARM_OUT}" | sed 's/^/    /'
    exit 1
  fi

  # THE VICTIM IS CHOSEN FROM THE MANIFEST, NOT FROM A DIRECTORY WALK, and
  # `victim_rel` is the manifest's own spelling of it — which is also how
  # `sha256sum -c` names it, so the expected messages below are built from the
  # same string rather than from `basename`.
  #
  # Measured 2026-08-10, and the reason this is not a `find`: the old
  # `find "${SCRATCH}" -name '*.json' ! -name INDEX.json | LC_ALL=C sort |
  # head -n 1` returns whatever is on disk, and under LC_ALL=C a dot-directory
  # sorts first. A stray `v1/.vscode/settings.json` in the tree became the
  # victim; mutating it changed nothing the freeze pins, `check_digests` stayed
  # GREEN, and the arm reported "the freeze guard is broken" about a guard that
  # was working perfectly. An arm that can plant its fault outside the surface
  # it is testing is the Q149 class in the PLANTING direction: it certifies —
  # or here, condemns — a surface it never touched.
  victim=""
  victim_rel=""
  while IFS= read -r vdir; do
    [ -n "${vdir}" ] || continue
    line="$(grep -v '^#' "${vdir}/${MANIFEST}" | LC_ALL=C sort -k2 | head -n 1)"
    [ -n "${line}" ] || continue
    victim_rel="${line#*  }"
    victim="${vdir}/${victim_rel}"
    break
  done <<< "$(version_dirs "${SCRATCH}")"
  if [ -z "${victim}" ] || [ ! -f "${victim}" ]; then
    echo "::error::no PINNED vector file to tamper with (looked for the first digest line of the first version manifest under ${SCRATCH})"
    exit 1
  fi

  echo "self-test: MUTATING ${victim_rel} — the lane must go RED"
  printf '\n' >> "${victim}"
  assert_red "frozen vector MODIFIED: ${victim_rel}" check_digests "${SCRATCH}" || {
    rc=$?
    echo "::error::a mutated frozen vector did NOT turn the lane red — the freeze guard is broken"
    red_arm_evidence "${rc}" "frozen vector MODIFIED: ${victim_rel}"
    exit 1
  }

  cp -R "${VECTORS}/." "${SCRATCH}/"
  echo "self-test: DELETING ${victim_rel} — the lane must go RED"
  rm -f "${victim}"
  # The deletion and the mutation produce the same nonzero, so this arm has to
  # require that the file it deleted is the file reported absent, by name.
  assert_red "frozen vector MISSING or unreadable: ${victim_rel}" check_digests "${SCRATCH}" || {
    rc=$?
    echo "::error::a deleted frozen vector did NOT turn the lane red — the must-exist list is broken"
    red_arm_evidence "${rc}" "frozen vector MISSING or unreadable: ${victim_rel}"
    exit 1
  }

  echo "self-test: OK — mutation and deletion each turn the lane red FOR THEIR OWN REASON"
  ;;

update)
  changed=0
  while IFS= read -r dir; do
    version="$(basename "${dir}")"
    manifest="${dir}/${MANIFEST}"
    if [ ! -f "${manifest}" ]; then
      echo "::error::${manifest} is missing — create it from an existing version's header first"
      exit 1
    fi
    status="$(sed -n 's/^#! status  *//p' "${manifest}" | head -n 1)"
    old="$(grep -v '^#' "${manifest}" || true)"
    new="$( cd "${dir}" && find . -name '*.json' ! -name "${INDEX}" | sed 's|^\./||' \
              | LC_ALL=C sort | while IFS= read -r f; do "${SUM[@]}" "${f}"; done )"

    if [ "${status}" = "frozen" ]; then
      # Append-only: every existing line must survive byte-identically.
      while IFS= read -r line; do
        [ -z "${line}" ] && continue
        if ! grep -Fqx -- "${line}" <<<"${new}"; then
          path="${line#*  }"
          if [ -n "${VERDICT_EVENT}" ] && verdict_event_ok "${dir}/${path}"; then
            echo "  ${version}: \`${path}\` moves as a VERDICT EVENT (${VERDICT_EVENT}) — checked, not asserted"
            continue
          fi
          echo "::error::${manifest} is FROZEN: \`${path}\` would be modified or dropped."
          echo "::error::A moved pin has three causes (D94 §2a) and only one is legal here:"
          echo "::error::  FORMAT EVENT  — the D29 surface moved. Needs a report-version bump, not this script."
          echo "::error::  VERDICT EVENT — the same inputs now verify to a different value under an unchanged"
          echo "::error::                  format. Legal after the freeze: re-run with --verdict-event <Dnn>,"
          echo "::error::                  which re-derives the classification from the diff and refuses if it"
          echo "::error::                  does not hold. Only \`report/\` vectors can be one."
          echo "::error::  FIXTURE EVENT — the input bundle changed (\`bundle_sha256\` moved). Needs its own decision."
          exit 1
        fi
      done <<< "${old}"
    fi

    # Keep every comment/directive line in order, then re-emit the digests.
    tmp="$(mktemp)"
    grep '^#' "${manifest}" > "${tmp}"
    printf '%s\n' "${new}" >> "${tmp}"
    if cmp -s "${tmp}" "${manifest}"; then
      echo "  ${version}: unchanged"
      rm -f "${tmp}"
    else
      mv "${tmp}" "${manifest}"
      echo "  ${version}: digest block rewritten — REVIEW THE DIFF before committing"
      changed=1
    fi
  done <<< "$(version_dirs "${VECTORS}")"

  if [ "${changed}" -eq 1 ]; then
    echo "vector-freeze --update: manifests rewritten. A changed (not added) digest is a"
    echo "FORMAT or VERDICT event and never a silent one: name the class and its deciding"
    echo "record in the commit message (D94 §2a; testdata/README.md)."
  fi
  ;;

esac
