#!/usr/bin/env bash
# The independent cross-check lane (decision D31; MVP-SPEC.md line 5).
#
# One entry point for every "a second implementation agrees with our committed
# bytes" check, so CI calls one thing and a contributor runs one thing. Today
# it carries F14's CBOR half; Q11 adds the rest (see the ordered list below).
#
# Usage:
#   scripts/cross-check.sh              run every wired check (offline)
#   scripts/cross-check.sh --self-test  prove the checkers can go red
#   scripts/cross-check.sh --setup      provision cbor2 without pip (network)
#   scripts/cross-check.sh --require    a missing dev tool FAILS (CI uses this)
#
# Exit: 0 pass · 1 disagreement or self-test breach · 2 a dev tool is missing.
#
# The CBOR checker lives at testdata/vectors/v<n>/crosscheck_cbor.py — a `*.py`
# auxiliary, which Q4's discovery contract admits (it is never executed as a
# vector). One copy per format version, each checking its own directory, so a
# future v2/ is picked up by the glob below with no change here.
set -uo pipefail

root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"

python="${PYTHON:-python3}"
if ! command -v "$python" >/dev/null 2>&1; then
  echo "UNAVAILABLE  no ${python} on PATH; the cross-check needs a stdlib Python >= 3.10" >&2
  case " $* " in *" --require "*) exit 1 ;; *) exit 2 ;; esac
fi

# Q11 (D31 §6a) wires these in once each grows a `--check` mode. They are
# listed rather than silently absent so the gap is visible in the lane itself:
#   testdata/vectors/v1/crypto/reference.py            # T0 self-test, FIRST
#   testdata/vectors/v1/hkdf/gen_vectors.py --check
#   testdata/vectors/v1/crypto/gen_vectors.py --check
#   testdata/vectors/v1/fine-tree/gen_vectors.py --check
#   testdata/utf8-corpus/gen_corpus.py --check

status=0
found=0
for checker in "${root}"/testdata/vectors/v*/crosscheck_cbor.py; do
  [ -f "${checker}" ] || continue
  found=$((found + 1))
  version="$(basename "$(dirname "${checker}")")"
  echo "== cross-check: CBOR, ${version} =="
  if [ "$#" -eq 0 ]; then
    "$python" "${checker}" --check
  else
    "$python" "${checker}" "$@"
  fi
  rc=$?
  # Exit 2 (dev tool absent) must not be masked by a later 1, and vice versa:
  # a real disagreement is always the more urgent verdict.
  case "${rc}" in
    0) ;;
    1) status=1 ;;
    *) [ "${status}" -eq 0 ] && status="${rc}" ;;
  esac
done

if [ "${found}" -eq 0 ]; then
  echo "::error::no testdata/vectors/v*/crosscheck_cbor.py found — the cross-check lane would" \
       "pass vacuously. Discovery is broken, or the checker was deleted." >&2
  exit 1
fi

exit "${status}"
