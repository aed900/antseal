#!/usr/bin/env bash
# The Q6 golden-vector freeze lane, end to end.
#
#   ./scripts/vector-freeze.sh              # the lane: must be GREEN
#   ./scripts/vector-freeze.sh --self-test  # test-of-the-test: must go RED
#   ./scripts/vector-freeze.sh --update     # regenerate the digest blocks
#
# Contract (MVP-SPEC.md line 123 format stability, line 167 "per-version
# vectors retained in CI forever"; tasks/Q.md Q6): each
# `testdata/vectors/v<n>/FROZEN.sha256` pins the exact bytes of every
# committed vector of that format version AND is the must-exist list, so a
# deleted vector file — which the Q4 runner structurally cannot notice,
# since it only executes files it finds — turns this lane red.
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
# red on the copy. The committed tree is never touched. Layer 2's own
# tests-of-the-test live in crates/antseal-core/tests/vector_freeze.rs.
#
# --update rewrites each manifest's digest block from the tree, preserving
# the prose and `#!` directives. While `#! status pre-freeze` it may rewrite
# an entry (a recorded, justified regeneration — review the digest diff).
# Once Q14 sets `#! status frozen` it REFUSES to modify or drop an entry:
# additions are then the only legal change.
#
# Doc: testdata/vectors/README.md (contract), testdata/README.md (retention).
set -euo pipefail

cd "$(dirname "$0")/.."

MODE="check"
case "${1:-}" in
  "")           MODE="check" ;;
  --self-test)  MODE="self-test" ;;
  --update)     MODE="update" ;;
  *) echo "usage: $0 [--self-test | --update]" >&2; exit 2 ;;
esac

VECTORS="testdata/vectors"
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
  local root="$1" rc=0 dir version count
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
      ( cd "${dir}" && grep -v '^#' "${MANIFEST}" | "${SUM[@]}" -c - 2>&1 | grep -v ': OK$' || true )
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

  echo "self-test: the untouched copy must be GREEN"
  if ! check_digests "${SCRATCH}" >/dev/null 2>&1; then
    echo "::error::the unmodified copy already fails — the self-test cannot conclude anything"
    exit 1
  fi

  victim="$(find "${SCRATCH}" -name '*.json' ! -name "${INDEX}" | LC_ALL=C sort | head -n 1)"
  if [ -z "${victim}" ]; then
    echo "::error::no vector files to tamper with"
    exit 1
  fi

  echo "self-test: MUTATING $(basename "${victim}") — the lane must go RED"
  printf '\n' >> "${victim}"
  if check_digests "${SCRATCH}" >/dev/null 2>&1; then
    echo "::error::a mutated frozen vector did NOT turn the lane red — the freeze guard is broken"
    exit 1
  fi

  cp -R "${VECTORS}/." "${SCRATCH}/"
  echo "self-test: DELETING $(basename "${victim}") — the lane must go RED"
  rm -f "${victim}"
  if check_digests "${SCRATCH}" >/dev/null 2>&1; then
    echo "::error::a deleted frozen vector did NOT turn the lane red — the must-exist list is broken"
    exit 1
  fi

  echo "self-test: OK — mutation and deletion both turn the lane red"
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
          echo "::error::${manifest} is FROZEN: \`${path}\` would be modified or dropped."
          echo "::error::After Q14 the only legal change is an addition; a byte change needs a new format version."
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
    echo "format event: record the justification in the commit message (testdata/README.md)."
  fi
  ;;

esac
