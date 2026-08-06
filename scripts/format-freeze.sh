#!/usr/bin/env bash
# The Q50 wire-registry freeze lane, end to end.
#
#   ./scripts/format-freeze.sh              # the lane: must be GREEN
#   ./scripts/format-freeze.sh --self-test  # test-of-the-test: must go RED
#   ./scripts/format-freeze.sh --update     # regenerate the digest block
#
# Contract (MVP-SPEC.md line 123 format stability; tasks/Q.md Q50):
# `docs/format/registry-v1.md` IS format v1 — the normative text a
# third-party verifier implements from — and `registry-v1.json` is its
# machine mirror. `docs/format/FROZEN.sha256` pins the exact bytes of both
# AND is the must-exist list.
#
# Why a digest and not just the cross-checks: `format_registry_freeze.rs`
# asserts that the code agrees with the mirror — 19 D10 caps, 68 map keys
# and names, 13 scalar lengths, 5 enums, version dispatch. Every one of
# those is a CONSISTENCY check, so a coordinated edit of both sides in one
# commit passes the whole suite forever. Post-freeze that is a silent format
# change. The digest is what a coordinated edit cannot satisfy quietly.
#
# Two independent layers, both required:
#
#   1. coreutils `sha256sum -c`, which shares no code with antseal, so a bug
#      in our own hasher cannot make a tampered registry look clean. The
#      manifest is `sha256sum -c` compatible by design (`#` = comment).
#   2. `cargo test --test format_freeze`, the authoritative checker: the
#      directive vocabulary (shared with the Q6 vector freeze), the
#      sorted/duplicate rules, the frozen-status rule, and the discovery
#      rule that no `registry-v<n>.{md,json}` may sit outside the freeze.
#      It carries the tests-of-the-test for every failure class.
#
# --self-test copies the directory to a scratch location, mutates one frozen
# byte and deletes one frozen file there, and requires layer 1 to go red on
# the copy. The committed tree is never touched.
#
# --update rewrites the digest block from the directory, preserving the
# prose and `#!` directives. Under `#! status frozen` it REFUSES to modify
# or drop an entry: additions are then the only legal change.
set -euo pipefail

cd "$(dirname "$0")/.."

MODE="check"
case "${1:-}" in
  "")           MODE="check" ;;
  --self-test)  MODE="self-test" ;;
  --update)     MODE="update" ;;
  *) echo "usage: $0 [--self-test | --update]" >&2; exit 2 ;;
esac

DIR="docs/format"
MANIFEST="FROZEN.sha256"

# Prefer coreutils; fall back to the Perl `shasum` shipped on macOS.
if command -v sha256sum >/dev/null 2>&1; then
  SUM=(sha256sum)
elif command -v shasum >/dev/null 2>&1; then
  SUM=(shasum -a 256)
else
  echo "::error::neither sha256sum nor shasum is available — layer 1 cannot run" >&2
  exit 1
fi

# Every file that must be frozen: the normative document and the mirror of
# every format version present. Discovery, not a hand-written list, so a
# future registry-v2 cannot land unfrozen.
registry_files() {
  find "$1" -maxdepth 1 -type f \
       \( -name 'registry-v[0-9]*.md' -o -name 'registry-v[0-9]*.json' \) \
    | sed "s|^$1/||" | LC_ALL=C sort
}

check_digests() {
  local dir="$1" rc=0 count missing
  if [ ! -f "${dir}/${MANIFEST}" ]; then
    echo "::error::${dir}/${MANIFEST} is missing — the wire registry would be unfrozen"
    return 1
  fi
  count="$(grep -cv '^#' "${dir}/${MANIFEST}" || true)"
  if [ "${count}" -eq 0 ]; then
    echo "::error::${dir}/${MANIFEST} pins zero files — an empty freeze asserts nothing"
    return 1
  fi
  if ( cd "${dir}" && grep -v '^#' "${MANIFEST}" | "${SUM[@]}" -c - >/dev/null ); then
    echo "  ${count} frozen registry file(s) OK (independent ${SUM[*]} check)"
  else
    echo "::error::${dir}/${MANIFEST}: digest check FAILED — the wire registry was modified or deleted"
    ( cd "${dir}" && grep -v '^#' "${MANIFEST}" | "${SUM[@]}" -c - 2>&1 | grep -v ': OK$' || true )
    rc=1
  fi
  # The other direction: nothing that defines a format version sits outside.
  missing=""
  while IFS= read -r f; do
    [ -z "${f}" ] && continue
    if ! grep -q "  ${f}\$" "${dir}/${MANIFEST}"; then
      missing="${missing} ${f}"
    fi
  done <<< "$(registry_files "${dir}")"
  if [ -n "${missing}" ]; then
    echo "::error::${dir}: registry document(s) not frozen:${missing}"
    rc=1
  fi
  return "${rc}"
}

case "${MODE}" in

check)
  echo "format-freeze layer 1 — independent digest check (${SUM[*]}):"
  check_digests "${DIR}"
  echo "format-freeze layer 2 — authoritative checker:"
  cargo test -p antseal-core --locked --test format_freeze
  echo "format-freeze: GREEN"
  ;;

self-test)
  SCRATCH="$(mktemp -d)"
  trap 'rm -rf "${SCRATCH}"' EXIT
  cp -R "${DIR}/." "${SCRATCH}/"

  echo "self-test: the untouched copy must be GREEN"
  if ! check_digests "${SCRATCH}" >/dev/null 2>&1; then
    echo "::error::the unmodified copy already fails — the self-test cannot conclude anything"
    exit 1
  fi

  echo "self-test: MUTATING registry-v1.md — the lane must go RED"
  printf '\n' >> "${SCRATCH}/registry-v1.md"
  if check_digests "${SCRATCH}" >/dev/null 2>&1; then
    echo "::error::a mutated registry did NOT turn the lane red — the freeze guard is broken"
    exit 1
  fi

  cp -R "${DIR}/." "${SCRATCH}/"
  echo "self-test: MUTATING registry-v1.json — the lane must go RED"
  printf '\n' >> "${SCRATCH}/registry-v1.json"
  if check_digests "${SCRATCH}" >/dev/null 2>&1; then
    echo "::error::a mutated mirror did NOT turn the lane red — the freeze guard is broken"
    exit 1
  fi

  cp -R "${DIR}/." "${SCRATCH}/"
  echo "self-test: DELETING registry-v1.md — the lane must go RED"
  rm -f "${SCRATCH}/registry-v1.md"
  if check_digests "${SCRATCH}" >/dev/null 2>&1; then
    echo "::error::a deleted registry did NOT turn the lane red — the must-exist list is broken"
    exit 1
  fi

  cp -R "${DIR}/." "${SCRATCH}/"
  echo "self-test: ADDING an unfrozen registry-v2.md — the lane must go RED"
  printf '# v2\n' > "${SCRATCH}/registry-v2.md"
  if check_digests "${SCRATCH}" >/dev/null 2>&1; then
    echo "::error::an unfrozen registry version did NOT turn the lane red — discovery is broken"
    exit 1
  fi

  echo "self-test: OK — mutation, deletion and an unfrozen version all turn the lane red"
  ;;

update)
  manifest="${DIR}/${MANIFEST}"
  if [ ! -f "${manifest}" ]; then
    echo "::error::${manifest} is missing — create it from the vector manifest's header first"
    exit 1
  fi
  status="$(sed -n 's/^#! status  *//p' "${manifest}" | head -n 1)"
  old="$(grep -v '^#' "${manifest}" || true)"
  new="$( cd "${DIR}" && registry_files . | while IFS= read -r f; do "${SUM[@]}" "${f}"; done )"

  if [ "${status}" = "frozen" ]; then
    while IFS= read -r line; do
      [ -z "${line}" ] && continue
      if ! grep -Fqx -- "${line}" <<<"${new}"; then
        path="${line#*  }"
        echo "::error::${manifest} is FROZEN: \`${path}\` would be modified or dropped."
        echo "::error::The wire registry IS format v1. After Q14 the only legal change is an"
        echo "::error::addition (a registry-v<n+1> pair); a byte change needs a new format version"
        echo "::error::(MVP-SPEC.md line 123; procedure Q27)."
        exit 1
      fi
    done <<< "${old}"
  fi

  tmp="$(mktemp)"
  grep '^#' "${manifest}" > "${tmp}"
  printf '%s\n' "${new}" >> "${tmp}"
  if cmp -s "${tmp}" "${manifest}"; then
    echo "  unchanged"
    rm -f "${tmp}"
  else
    mv "${tmp}" "${manifest}"
    echo "  digest block rewritten — REVIEW THE DIFF before committing"
    echo "format-freeze --update: a changed (not added) digest is a FORMAT EVENT."
  fi
  ;;

esac
