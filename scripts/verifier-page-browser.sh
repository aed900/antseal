#!/usr/bin/env bash
# R27/Q19 — the verifier page's browser assertions (D129 §5 R9 assertion 8).
#
#   ./scripts/verifier-page-browser.sh             build + every check
#   ./scripts/verifier-page-browser.sh --check     same, explicitly
#   ./scripts/verifier-page-browser.sh --self-test the checks' own planted fault
#
# Exit 0 = the built page loads from a `file://` URL in a real browser, asks the
# network for NOTHING but itself, reports zero Content-Security-Policy
# violations, and renders a verdict for a real `.sealproof`.
#
# ── The fixture is MATERIALISED, not committed ─────────────────────────────
#
# `testdata/vectors/v1/bundle/bundle.json` already carries canonical bundle
# bytes as hex (F13's golden vectors), so a second binary copy of the same
# bundle committed under another name would be a second source of truth that
# agrees on the day it is written. The bundle this drives is decoded from that
# vector into `target/`, which also means the browser arm is exercising the
# same bytes the native and wasm boundary arms do.
#
# ── Exit 2 means "no browser on THIS machine" ──────────────────────────────
#
# A visible SKIP locally with the one-line fix printed, following the
# cross-check lane's convention. Q19's lane is local-only by the maintainer's
# ruling, so a developer without a browser must not be blocked by it — but the
# workflow that CAN run it passes --check, where absence is a hard failure.
set -uo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo" || exit 1

note() { printf '\033[36m==>\033[0m %s\n' "$*"; }
die()  { printf '\033[31m::error::verifier-page-browser: %s\033[0m\n' "$*" >&2; exit 1; }

PAGE="target/verifier-web/index.html"
FIXTURES="target/verifier-web-fixtures"
BROWSER="${ANTSEAL_BROWSER:-chromium}"

command -v "$BROWSER" >/dev/null || {
  printf '::notice::%s is not installed — the browser arm cannot run here.\n' "$BROWSER" >&2
  printf '  Debian/Ubuntu: sudo apt install chromium    (or set ANTSEAL_BROWSER)\n' >&2
  exit 2
}

# One case per shape, decoded from the committed F13 vector.
materialise() {
  mkdir -p "$FIXTURES"
  python3 - "$FIXTURES" <<'PY' || return 1
import json, pathlib, sys
out = pathlib.Path(sys.argv[1])
doc = json.load(open("testdata/vectors/v1/bundle/bundle.json"))
made = []
for case in doc["expect"]["cases"]:
    path = out / f"{case['name'].replace('/', '_')}.sealproof"
    path.write_bytes(bytes.fromhex(case["bundle_bytes"]))
    made.append(f"{path.name} ({len(case['bundle_bytes']) // 2} B)")
print("  " + ", ".join(made))
PY
}

cmd_check() {
  note "package the page (R25)"
  ./scripts/verifier-page-build.sh --check || return 1
  [ -f "$PAGE" ] || die "$PAGE does not exist after a green build"

  note "materialise the bundle fixtures from the committed F13 vector"
  materialise || return 1

  note "drive ${BROWSER} against ${PAGE} from a file:// origin"
  # shellcheck disable=SC2046
  node scripts/verifier-page-browser.mjs --self-test "$PAGE" $(ls "$FIXTURES"/*.sealproof 2>/dev/null)
}

case "${1:---check}" in
  --check | "")  cmd_check ;;
  --self-test)
    note "the network instrument's own planted fault"
    [ -f "$PAGE" ] || ./scripts/verifier-page-build.sh --build-only || exit 1
    node scripts/verifier-page-browser.mjs --self-test "$PAGE" ;;
  *) die "usage: scripts/verifier-page-browser.sh [--check | --self-test]" ;;
esac
