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
# The eleventh and twelfth fixtures (R84/D133) arrive the same way and for the
# same reason. `attested-ots-960767.sealproof` and
# `attested-plus-invalid-ots.sealproof` are assembled from two frozen
# documents — F13's `empty-anchor-unanchored` bundle bytes and the anchor
# vector's `ots-upgraded-offline` artifact plus its real block-960767 upgrade
# group — by `crates/antseal-core/tests/page_fixtures.rs`, which asserts them
# on every `cargo test` and writes them only when this script asks. They are
# the only bundles in the tree that verify OFFLINE to `attested`, which is what
# R27's four online cases need: the overlay gate admits no other state.
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

# One case per shape, decoded from the committed F13 vector, plus D133's two
# attested fixtures from the emitter that also asserts them.
materialise() {
  mkdir -p "$FIXTURES"
  # The emitter is the assertion suite: without the variable it only checks, so
  # a fixture that stopped verifying can never reach the browser as bytes.
  #
  # ABSOLUTE, and the test refuses anything else. Cargo runs an integration
  # test from the PACKAGE root, so `target/verifier-web-fixtures` here and in
  # the test are two different directories — and the failure is invisible from
  # both ends, because the glob below still finds the ten files python wrote.
  ANTSEAL_EMIT_PAGE_FIXTURES="$repo/$FIXTURES" \
    cargo test -p antseal-core --locked --test page_fixtures -- --nocapture || return 1
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

  note "materialise the bundle fixtures from the committed frozen vectors"
  materialise || return 1
  # The count is asserted because the glob below cannot fail: a fixture that
  # never arrived leaves `ls` returning the others, and the run goes green
  # having tested less than it claims. Measured at R84, where a relative emit
  # path put two fixtures somewhere else and this lane passed regardless.
  for required in attested-ots-960767 attested-plus-invalid-ots; do
    [ -s "$FIXTURES/$required.sealproof" ] ||
      die "$FIXTURES/$required.sealproof did not materialise — the browser arm would run without the only bundles that verify to \`attested\`"
  done

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
