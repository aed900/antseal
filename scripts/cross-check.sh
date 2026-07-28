#!/usr/bin/env bash
# The independent cross-check lane (decision D31; MVP-SPEC.md line 5).
#
# One entry point for every "a second implementation agrees with our committed
# bytes" check, so CI calls one thing and a contributor runs one thing.
#
# Usage:
#   scripts/cross-check.sh              run every surface (offline)
#   scripts/cross-check.sh --check      same, explicitly
#   scripts/cross-check.sh --self-test  prove every surface can go red
#   scripts/cross-check.sh --setup      provision cbor2 without pip (network)
#   scripts/cross-check.sh --require    a missing dev tool FAILS (CI uses this)
#
# Exit: 0 pass · 1 disagreement or self-test breach · 2 a dev tool is missing.
#
# ── The surfaces, in D31 section 6b's order ────────────────────────────────
#
#   1. crypto/reference.py            T0 known answers — RFC 5869 A.1/A.2/A.3,
#                                     RFC 8032 7.1 (all five), RFC 8439,
#                                     draft-irtf-cfrg-xchacha
#   2. hkdf/gen_vectors.py            HKDF label registry            (T1)
#   3. crypto/gen_vectors.py          commitments, AEAD, signatures  (T1)
#   4. fine-tree/gen_vectors.py       GGM tree, fine_root, Merkle    (T1)
#   5. utf8-corpus/gen_corpus.py      canonicalization v1            (T1)
#                                     + Unicode NormalizationTest    (T0)
#   6. crosscheck_cbor.py             canonical CBOR, work_id        (T1)
#                                     + RFC 8949 Appendix A          (T0)
#
# `reference.py` runs FIRST and unconditionally: if the reference's own known
# answers fail, every downstream agreement is worthless, and this ordering
# makes that legible instead of showing up as forty vector diffs.
#
# ML-DSA-65 is deliberately absent from this list. Its vehicle is NIST ACVP
# (T0) replayed from Rust, so it runs in the ordinary `test` lane as
# `crates/antseal-core/tests/acvp_ml_dsa.rs` — no new job, no network. The
# `ml-dsa`↔`fips204` comparison in `tests/mldsa_fallback_equivalence.rs` is T2
# and is D14's fallback evidence, never this lane's independence claim.
#
# ── Version iteration (D31 section 6c) ─────────────────────────────────────
#
# Every path below globs `testdata/vectors/v*/`, never a hard-coded `v1`: a
# future v2 format directory is picked up with no change here. Each class of
# surface must find at least one instance or the lane fails, because a lane
# that discovers nothing passes vacuously and reports success.
set -uo pipefail

root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"

python="${PYTHON:-python3}"
if ! command -v "$python" >/dev/null 2>&1; then
  echo "UNAVAILABLE  no ${python} on PATH; the cross-check needs a stdlib Python >= 3.10" >&2
  case " $* " in *" --require "*) exit 1 ;; *) exit 2 ;; esac
fi

mode="check"
require=0
for arg in "$@"; do
  case "${arg}" in
    --check)     mode="check" ;;
    --self-test) mode="selftest" ;;
    --setup)     mode="setup" ;;
    --require)   require=1 ;;
    *)
      echo "::error::unknown argument: ${arg}" >&2
      exit 1
      ;;
  esac
done

status=0
note() { printf '\n== %s ==\n' "$1"; }

# Merge one surface's exit code. Exit 2 (dev tool absent) must not be masked
# by a later 1, and vice versa: a real disagreement is always the more urgent
# verdict.
merge_rc() {
  case "$1" in
    0) ;;
    1) status=1 ;;
    *) [ "${status}" -eq 0 ] && status="$1" ;;
  esac
}

# ── --setup: only the CBOR surface needs provisioning ──────────────────────
# Every other surface is Python-stdlib-only by construction (that is what
# makes them independent of our Rust stack and of PyPI).
if [ "${mode}" = "setup" ]; then
  found=0
  for checker in "${root}"/testdata/vectors/v*/crosscheck_cbor.py; do
    [ -f "${checker}" ] || continue
    found=$((found + 1))
    "$python" "${checker}" --setup
    merge_rc $?
  done
  if [ "${found}" -eq 0 ]; then
    echo "::error::no testdata/vectors/v*/crosscheck_cbor.py to provision" >&2
    exit 1
  fi
  exit "${status}"
fi

# ── discovery ──────────────────────────────────────────────────────────────
references=()
generators=()
cbor_checkers=()

for path in "${root}"/testdata/vectors/v*/crypto/reference.py; do
  [ -f "${path}" ] && references+=("${path}")
done
# `*/gen_vectors.py` rather than a named list: a future component directory
# under any format version is picked up automatically.
for path in "${root}"/testdata/vectors/v*/*/gen_vectors.py; do
  [ -f "${path}" ] && generators+=("${path}")
done
# Version-less: canonicalization is not a per-format-version artifact.
if [ -f "${root}/testdata/utf8-corpus/gen_corpus.py" ]; then
  generators+=("${root}/testdata/utf8-corpus/gen_corpus.py")
fi
for path in "${root}"/testdata/vectors/v*/crosscheck_cbor.py; do
  [ -f "${path}" ] && cbor_checkers+=("${path}")
done

if [ "${#references[@]}" -eq 0 ]; then
  echo "::error::no testdata/vectors/v*/crypto/reference.py found — the T0 known-answer" \
       "self-test would be skipped and every downstream agreement would be unanchored." >&2
  exit 1
fi
if [ "${#generators[@]}" -lt 4 ]; then
  echo "::error::found only ${#generators[@]} reference generators; D31 section 2 names four" \
       "(hkdf, crypto, fine-tree, utf8-corpus). A surface is missing and the lane would" \
       "pass without checking it." >&2
  exit 1
fi
if [ "${#cbor_checkers[@]}" -eq 0 ]; then
  echo "::error::no testdata/vectors/v*/crosscheck_cbor.py found — the CBOR surface would" \
       "pass vacuously. Discovery is broken, or the checker was deleted." >&2
  exit 1
fi

rel() { printf '%s' "${1#"${root}"/}"; }

# ── --check ────────────────────────────────────────────────────────────────
if [ "${mode}" = "check" ]; then
  for path in "${references[@]}"; do
    note "cross-check: reference known answers (T0) — $(rel "${path}")"
    "$python" "${path}"
    merge_rc $?
  done

  for path in "${generators[@]}"; do
    note "cross-check: $(rel "${path}") --check"
    "$python" "${path}" --check
    merge_rc $?
  done

  for path in "${cbor_checkers[@]}"; do
    note "cross-check: CBOR — $(rel "${path}") --check"
    if [ "${require}" -eq 1 ]; then
      "$python" "${path}" --check --require
    else
      "$python" "${path}" --check
    fi
    merge_rc $?
  done

  if [ "${status}" -eq 0 ]; then
    printf '\ncross-check PASSED: %d reference self-test(s), %d generator(s), %d CBOR checker(s)\n' \
      "${#references[@]}" "${#generators[@]}" "${#cbor_checkers[@]}"
  fi
  exit "${status}"
fi

# ── --self-test ────────────────────────────────────────────────────────────
#
# D31 section 9 step 3 / section 11 item 6: "a checker never observed failing
# is not evidence." So every surface is proven able to go red, here, every
# time the lane runs — not once by hand in a report nobody re-reads.
#
# Faults are planted in a COPY of testdata/ under a temp directory, never in
# the working tree: a self-test that can leave the repo dirty on a crash is a
# worse hazard than the one it guards against.
work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT
cp -a "${root}/testdata" "${work}/testdata" || {
  echo "::error::could not stage a copy of testdata/ for the self-test" >&2
  exit 1
}

selftest_status=0

# Plant a fault, expect red, restore, expect green.
#
# $1 label · $2 script (path inside the copy) · $3 victim (path inside the
# copy) · $4 mutation mode passed to the helper below.
prove_can_fail() {
  local label="$1" script="$2" victim="$3" mutation="$4"
  note "self-test: ${label}"

  if [ ! -f "${victim}" ]; then
    echo "FAIL  ${label}: victim ${victim} does not exist" >&2
    selftest_status=1
    return
  fi
  cp -a "${victim}" "${victim}.orig"

  if ! "$python" - "${victim}" "${mutation}" <<'PY'
import pathlib
import sys

victim = pathlib.Path(sys.argv[1])
mutation = sys.argv[2]

if mutation == "hex":
    # Flip the first character of the first long lowercase-hex run. Generic on
    # purpose: committed vector bytes legitimately move (a format event), and a
    # self-test pinned to a literal value would break every time they did.
    import re

    text = victim.read_text(encoding="utf-8")
    match = re.search(r"[0-9a-f]{32,}", text)
    if match is None:
        sys.exit(f"no long hex run to mutate in {victim}")
    start = match.start()
    flipped = "1" if text[start] == "0" else "0"
    victim.write_text(text[:start] + flipped + text[start + 1 :], encoding="utf-8")
elif mutation == "byte":
    # Flip one bit of the first byte; works on the binary corpus goldens.
    data = bytearray(victim.read_bytes())
    if not data:
        sys.exit(f"{victim} is empty and cannot be mutated")
    data[0] ^= 0x01
    victim.write_bytes(bytes(data))
elif mutation.startswith("replace:"):
    # A targeted, semantic mutation: `replace:<from>:<to>`. Errors loudly if
    # the anchor is gone, so a refactor cannot silently disarm the proof.
    _, source, target = mutation.split(":", 2)
    text = victim.read_text(encoding="utf-8")
    if source not in text:
        sys.exit(f"self-test anchor {source!r} not found in {victim}")
    victim.write_text(text.replace(source, target, 1), encoding="utf-8")
else:
    sys.exit(f"unknown mutation mode {mutation!r}")
PY
  then
    echo "FAIL  ${label}: could not plant the fault" >&2
    selftest_status=1
    mv -f "${victim}.orig" "${victim}"
    return
  fi

  local args=("--check")
  case "${script}" in *reference.py) args=() ;; esac
  "$python" "${script}" "${args[@]}" >/dev/null 2>&1
  local rc=$?
  mv -f "${victim}.orig" "${victim}"

  if [ "${rc}" -eq 0 ]; then
    echo "FAIL  ${label}: the checker stayed GREEN with a planted fault — it is not" \
         "actually checking this surface" >&2
    selftest_status=1
    return
  fi

  # And green again once restored, so the red was the fault and not the setup.
  "$python" "${script}" "${args[@]}" >/dev/null 2>&1
  if [ $? -ne 0 ]; then
    echo "FAIL  ${label}: still red after restoring — the self-test is unsound" >&2
    selftest_status=1
    return
  fi
  echo "OK    ${label}: red with the fault, green without it"
}

copy_of() { printf '%s' "${work}/testdata/${1#"${root}"/testdata/}"; }

# 1. reference.py — no committed artifact of its own, so the fault goes in the
#    implementation: RFC 5869's expand loop starts its counter at 1.
for path in "${references[@]}"; do
  prove_can_fail "$(rel "${path}") known answers (T0)" \
    "$(copy_of "${path}")" "$(copy_of "${path}")" \
    "replace:counter = 1:counter = 2"
done

# 2-4. The vector generators — flip a hex digit in the committed vector.
for path in "${generators[@]}"; do
  script="$(copy_of "${path}")"
  dir="$(dirname "${script}")"
  case "${path}" in
    */utf8-corpus/gen_corpus.py)
      # Two checks live behind this one --check, so prove both can fail.
      prove_can_fail "$(rel "${path}") corpus goldens" \
        "${script}" "${dir}/expected/lone-cr" "byte"
      prove_can_fail "$(rel "${path}") Unicode NormalizationTest anchor (T0)" \
        "${script}" "${work}/testdata/unicode/NormalizationTest-17.0.0-sample.txt" \
        "replace:1E0A;1E0A;:1E0A;1E0C;"
      ;;
    *)
      victim=""
      for candidate in "${dir}"/*.json; do
        [ -f "${candidate}" ] && victim="${candidate}" && break
      done
      if [ -z "${victim}" ]; then
        echo "FAIL  $(rel "${path}"): no committed *.json to plant a fault in" >&2
        selftest_status=1
        continue
      fi
      prove_can_fail "$(rel "${path}") committed vectors" "${script}" "${victim}" "hex"
      ;;
  esac
done

# 5. The CBOR checker carries its own richer self-test (F14: 8 planted faults).
for path in "${cbor_checkers[@]}"; do
  note "self-test: $(rel "${path}") (built-in)"
  if [ "${require}" -eq 1 ]; then
    "$python" "${path}" --self-test --require
  else
    "$python" "${path}" --self-test
  fi
  rc=$?
  case "${rc}" in
    0) ;;
    1) selftest_status=1 ;;
    *) [ "${selftest_status}" -eq 0 ] && selftest_status="${rc}" ;;
  esac
done

if [ "${selftest_status}" -eq 0 ]; then
  printf '\nself-test PASSED: every surface was observed failing on a planted fault\n'
fi
exit "${selftest_status}"
