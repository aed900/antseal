#!/usr/bin/env bash
# Q19/D136 §2 R5 — install the two pinned wasm tools this repository's page
# build needs, at the versions their DECLARATION SITES record.
#
#   ./scripts/wasm-tools-provision.sh           install whichever is missing
#   ./scripts/wasm-tools-provision.sh --check   report only; exit 1 if either is absent or wrong
#   ./scripts/wasm-tools-provision.sh --help
#
# ── Why this is a script that two jobs CALL, and not two lines they each carry ─
#
# MEASURED 2026-08-15 (D136 §1 c): `.github/workflows/verifier-page.yml` had
# five steps and none of them installed anything, `ubuntu-latest` ships neither
# `wasm-pack` nor `wasm-bindgen-cli` (their names appear nowhere in the image
# manifest — re-checked against `Ubuntu2404-Readme.md` today, zero hits), and
# `scripts/wasm-pack-build.sh` `die`s when either is missing. The lane had
# never run on the remote — zero runs — and could not have gone green if it
# had. `pages.yml`'s own header named the asymmetry without noticing it was a
# defect: it provisions these two "which no other job does".
#
# The obvious repair — copy `pages-publish.sh`'s two `cargo install` lines into
# the other workflow — is REFUSED (D136 §3): two copies of a version derivation
# agree on the day they are written and drift afterwards, which is the failure
# `wasm-pack-build.sh`'s own `recorded_pin()` comment exists to prevent. So the
# derivation lives here, once, and both jobs reach it through this file.
#
# ── The versions are READ, never restated ─────────────────────────────────
#
# Both pins are grepped out of wherever an install line already records them
# (`docs/wasm-toolchain.md` today). A version literal in this file would be a
# third copy — and worse, `wasm-pack-build.sh::recorded_pin` REFUSES to build
# when the tree records more than one wasm-pack version, so a literal here that
# ever disagreed would break the build rather than merely mislead.
set -uo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo" || exit 1

note() { printf '\033[36m==>\033[0m %s\n' "$*"; }
die()  { printf '\033[31m::error::wasm-tools-provision: %s\033[0m\n' "$*" >&2; exit 1; }

# Byte-for-byte the grep `scripts/pages-publish.sh` carried before this script
# existed, so the move changed the caller and not the derivation.
recorded_pin() {
  grep -rhoE "$1[^\n]*--version [0-9]+\.[0-9]+\.[0-9]+" docs scripts .github/workflows 2>/dev/null |
    sed -nE 's/.*--version ([0-9]+\.[0-9]+\.[0-9]+).*/\1/p' | sort -u | head -n1
}
have() { "$1" --version 2>/dev/null | awk '{print $2}'; }

# ── wasm-pack's crates.io call, suppressed here too (D182, task Q276) ───────
#
# wasm-pack 0.15.0 asks crates.io for its newest version on EVERY invocation,
# `--version` included — and `have` above runs `wasm-pack --version`, on a
# fresh runner right after `cargo install`, before any build has written the
# stamp that skips the call. Measured 2026-10-16 with no network: a bare
# `--version` completed a call attempt before it exited in 1 of 20 runs. So the
# stamp is written by its one owner, `wasm-pack-build.sh
# --suppress-update-check`, before every wasm-pack process this script starts,
# and read back after the last one: unchanged bytes mean provisioning made no
# call either.
UPDATE_STAMP=""
UPDATE_STAMP_HELD=""
suppress_update_check() {
  UPDATE_STAMP="$("$repo/scripts/wasm-pack-build.sh" --suppress-update-check)" ||
    die "could not write wasm-pack's update-check stamp (D182, task Q276)"
  UPDATE_STAMP_HELD=""
  [ -z "$UPDATE_STAMP" ] || UPDATE_STAMP_HELD="$(cat "$UPDATE_STAMP")"
}
assert_update_stamp_held() {
  [ -n "$UPDATE_STAMP" ] || return 0
  [ "$(cat "$UPDATE_STAMP" 2>/dev/null)" = "$UPDATE_STAMP_HELD" ] && return 0
  die "wasm-pack's update-check stamp ${UPDATE_STAMP} moved while provisioning: a wasm-pack process called crates.io, which D63 §5 R5 forbids (D182, task Q276)"
}
shown() { local v; v="$(have "$1")"; printf '%s' "${v:-<absent>}"; }

cmd_provision() { # $1 = 1 to install, 0 to report only
  local install="$1" pack bindgen rc=0
  pack="$(recorded_pin wasm-pack)"
  bindgen="$(recorded_pin wasm-bindgen-cli)"
  [ -n "$pack" ]    || die "no wasm-pack version is recorded anywhere (docs/dependency-policy.md §5)"
  [ -n "$bindgen" ] || die "no wasm-bindgen-cli version is recorded anywhere (docs/dependency-policy.md §5)"

  suppress_update_check
  if [ "$(have wasm-bindgen)" != "$bindgen" ]; then
    if [ "$install" -eq 1 ]; then
      note "installing the pinned wasm-bindgen-cli ${bindgen}"
      cargo install wasm-bindgen-cli --locked --version "$bindgen" || return 1
    else
      printf '::error::wasm-bindgen-cli is %s, the recorded pin is %s\n' "$(shown wasm-bindgen)" "$bindgen" >&2
      rc=1
    fi
  fi
  if [ "$(have wasm-pack)" != "$pack" ]; then
    if [ "$install" -eq 1 ]; then
      note "installing the pinned wasm-pack ${pack}"
      cargo install wasm-pack --locked --version "$pack" || return 1
      suppress_update_check
    else
      printf '::error::wasm-pack is %s, the recorded pin is %s\n' "$(shown wasm-pack)" "$pack" >&2
      rc=1
    fi
  fi
  [ "$rc" -eq 0 ] || return 1
  printf '  wasm-bindgen-cli %s · wasm-pack %s (both at their recorded pins)\n' \
    "$(have wasm-bindgen)" "$(have wasm-pack)"
  assert_update_stamp_held
}

case "${1:-}" in
  "" )        cmd_provision 1 ;;
  --check)    cmd_provision 0 ;;
  --help|-h)  sed -n '2,8p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//' ;;
  *) die "usage: scripts/wasm-tools-provision.sh [--check | --help]" ;;
esac
