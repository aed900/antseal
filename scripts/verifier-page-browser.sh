#!/usr/bin/env bash
# R27/Q19 — the verifier page's browser assertions (D129 §5 R9 assertion 8).
#
#   ./scripts/verifier-page-browser.sh             build + every check
#   ./scripts/verifier-page-browser.sh --check     same, explicitly
#   ./scripts/verifier-page-browser.sh --self-test the checks' own planted fault
#   ./scripts/verifier-page-browser.sh --seed-test D136 §2 R13's seeded failure
#
# Exit 0 = the built page loads from a `file://` URL in a real browser, asks the
# network for NOTHING but itself, reports zero Content-Security-Policy
# violations, renders every fixture STRING-IDENTICALLY to `antseal verify`,
# produces R27's four online cases over mocked routes carrying real captured
# mainnet bytes, and — R85 / D137 §5 — renders the two receipt cases over the
# receipt-bearing twin: the chain-scoped absence line when the chain-id guard
# passes, and the endpoint-naming failure line when it refuses, with zero
# receipt queries issued in the second.
#
# ── R27 owns the assertions; Q19 owns the venue (D136 §2 R15) ──────────────
#
# Everything this script asserts about what RENDERED is R27's. The workflow, the
# trigger, the local-gate wiring and the artifact upload are Q19's and are not
# here. Neither row may tick citing the other's green.
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
# The eleventh, twelfth and thirteenth fixtures (R84/D133, D137 §7) arrive the
# same way and for the same reason. `attested-ots-960767.sealproof`,
# `attested-plus-invalid-ots.sealproof` and
# `attested-ots-960767-with-receipt.sealproof` are assembled from frozen
# documents — F13's `empty-anchor-unanchored` bundle bytes, the anchor vector's
# `ots-upgraded-offline` artifact plus its real block-960767 upgrade group, and
# F13's `every-anchor-kind-with-receipt` receipt record — by
# `crates/antseal-core/tests/page_fixtures.rs`, which asserts them on every
# `cargo test` and writes them only when this script asks. The first two are the
# only bundles in the tree that verify OFFLINE to `attested`, which is what
# R27's four online cases need: the overlay gate admits no other state.
#
# ── The native side of the parity comparison ───────────────────────────────
#
# `antseal verify <fixture>`'s own stdout, captured per fixture into
# `<fixture>.cli.txt`, is what the rendered DOM is compared against. It is
# captured from a binary built in THIS run rather than from a committed
# snapshot: both surfaces read one assembly (D130 §3 R3), so if a wording change
# lands between two builds the comparison must move with it, and a frozen
# expectation file would instead turn every intentional change into a red gate
# with no key.
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
SUMS="target/verifier-web/SHA256SUMS"
MODULE="target/wasm-pack/antseal-wasm/antseal_wasm_bg.wasm"
FIXTURES="target/verifier-web-fixtures"
DIAGNOSIS="target/verifier-page-diagnosis"
CAPTURES="testdata/anchors/A25-upgrade-headers"
WORDING="crates/antseal-core/src/verify/wording.rs"
VERDICTS="crates/antseal-core/src/anchor/verdicts.rs"
CLI="target/debug/antseal"
ONLINE_FIXTURE="$FIXTURES/attested-ots-960767.sealproof"
RECEIPT_FIXTURE="$FIXTURES/attested-ots-960767-with-receipt.sealproof"
BROWSER="${ANTSEAL_BROWSER:-chromium}"

# The reveal shapes R27's Accept row 4 names. Used as the cheap invocation for
# --seed-test, which must be green unplanted before a plant proves anything.
SHAPE_FIXTURES=(
  covered-unit-partial-reveal
  leaf-level-cover-partial-reveal
  full-file-reveal-with-mirror
  nothing-revealed
)

command -v "$BROWSER" >/dev/null || {
  printf '::notice::%s is not installed — the browser arm cannot run here.\n' "$BROWSER" >&2
  printf '  Debian/Ubuntu: sudo apt install chromium    (or set ANTSEAL_BROWSER)\n' >&2
  exit 2
}

# One case per shape, decoded from the committed F13 vector, plus D133's and
# D137's three attested fixtures from the emitter that also asserts them.
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

# `antseal verify` over every fixture, one capture file each.
#
# The exit code is DELIBERATELY ignored: `verify` folds the verdict into D69's
# rung and a well-formed unanchored bundle exits 43. What is asserted instead is
# that stdout is NON-EMPTY — an empty capture would make the parity comparison
# pass over nothing at all, which is this project's dominant defect class.
capture_native() {
  local bundle name lines total=0
  for bundle in "$FIXTURES"/*.sealproof; do
    name="$(basename "$bundle")"
    "$CLI" verify "$bundle" >"$FIXTURES/$name.cli.txt" 2>/dev/null
    lines="$(wc -l <"$FIXTURES/$name.cli.txt")"
    [ "$lines" -gt 0 ] || die "\`$CLI verify $name\` printed nothing to stdout, so the parity row for it would compare the page against an empty expectation"
    total=$((total + 1))
  done
  [ "$total" -gt 0 ] || die "no fixture was captured — the parity gate would then cover nothing"
  printf '  captured %s native rendering(s) from %s\n' "$total" "$CLI"
}

drive() {
  # shellcheck disable=SC2046
  node scripts/verifier-page-browser.mjs \
    --page "$PAGE" \
    --sums "$SUMS" \
    --module-sha256 "$(sha256sum "$MODULE" | awk '{print $1}')" \
    --spec MVP-SPEC.md \
    --expect "$FIXTURES" \
    --wording "$WORDING" \
    --verdicts "$VERDICTS" \
    --diagnosis "$DIAGNOSIS" \
    "$@"
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
  for required in attested-ots-960767 attested-plus-invalid-ots attested-ots-960767-with-receipt; do
    [ -s "$FIXTURES/$required.sealproof" ] ||
      die "$FIXTURES/$required.sealproof did not materialise — the browser arm would run without the only bundles that verify to \`attested\`"
  done
  [ -s "$FIXTURES/attested-ots-960767.sealproof.plan.json" ] ||
    die "the probe-plan sidecar did not materialise — R27's online cases route off the emitted plan and never off a hard-coded height (D133 §5.2)"

  note "build the CLI, the native half of the parity comparison"
  cargo build -p antseal-cli --locked || return 1
  [ -x "$CLI" ] || die "$CLI is absent after a green build"
  capture_native || return 1

  note "drive ${BROWSER} against ${PAGE} from a file:// origin"
  rm -rf "$DIAGNOSIS"
  # An ARRAY and an asserted floor, not a bare glob: an unmatched glob expands
  # to nothing here, the driver would be handed zero bundles, and every
  # per-bundle row would be green over an empty loop.
  local bundles=("$FIXTURES"/*.sealproof)
  [ "${#bundles[@]}" -ge 13 ] ||
    die "only ${#bundles[@]} fixture(s) matched $FIXTURES/*.sealproof; the ten F13 cases plus D133's two and D137's twin are 13"
  printf '  driving %s fixture(s)\n' "${#bundles[@]}"
  drive --self-test \
    --online "$ONLINE_FIXTURE" \
    --receipt "$RECEIPT_FIXTURE" \
    --captures "$CAPTURES" \
    "${bundles[@]}"
}

# D136 §2 R13 — the seeded failure. `--self-test` is a POSITIVE control on one
# row whose success path is green, so no path in this repository had ever made
# this job red; the workflow's `if: failure()` artifact branch had therefore
# never executed. This is the plant that does.
#
# Verified BY ITS MESSAGE, never by the exit status: a crash exits nonzero too.
# Three clauses, all of them here:
#
#   * the PRE-IMAGE — the named row must be green unplanted, or a "seeded"
#     failure is just the failure that was already there (Q234's lesson). The
#     driver enforces this too, refusing a seed whose row did not fire;
#   * the MESSAGE — the log must carry `::error::verifier-page-browser: [<row>]`
#     for the row that was named, and for no other reason;
#   * the NEGATIVE CONTROL on the artifact clause — with the variable unset the
#     same invocation is green AND leaves the diagnosis directory empty, so the
#     artifact set's presence is caused by the plant rather than by every run.
#
# The plant is an environment variable and never a patched file: a plant that
# edits the tree in a shared working directory is a hazard this project has
# already met.
cmd_seed_test() {
  local rows=(boot network csp bundle parity format-version shape page-build advice page-sums)
  local bundles=() name out status seeded=0 extra=0
  for name in "${SHAPE_FIXTURES[@]}"; do
    [ -s "$FIXTURES/$name.sealproof" ] ||
      die "$FIXTURES/$name.sealproof is absent — run --check first; the seed test needs an invocation that is GREEN before it plants"
    [ -s "$FIXTURES/$name.sealproof.cli.txt" ] ||
      die "$FIXTURES/$name.sealproof.cli.txt is absent — run --check first"
    bundles+=("$FIXTURES/$name.sealproof")
  done

  note "pre-image: the same invocation, unplanted, must be GREEN and upload NOTHING"
  rm -rf "$DIAGNOSIS"
  out="$(drive "${bundles[@]}" 2>&1)"; status=$?
  if [ "$status" -ne 0 ]; then
    printf '::error::the unplanted invocation is already red, so seeding a row would prove nothing:\n%s\n' \
      "$(grep '::error::' <<<"$out" | head -5)" >&2
    return 1
  fi
  if [ -d "$DIAGNOSIS" ] && [ -n "$(ls -A "$DIAGNOSIS" 2>/dev/null)" ]; then
    printf '::error::a GREEN run left files in %s, so the artifact branch would fire on every run and its presence would prove nothing about a failure\n' "$DIAGNOSIS" >&2
    return 1
  fi
  printf '  unplanted: GREEN, %s empty\n' "$DIAGNOSIS"

  for row in "${rows[@]}"; do
    rm -rf "$DIAGNOSIS"
    out="$(ANTSEAL_PAGE_SEED_FAILURE="$row" drive "${bundles[@]}" 2>&1)"; status=$?
    if [ "$status" -eq 0 ]; then
      printf '::error::seeding row %s left the job GREEN — the plant never fired\n' "$row" >&2
      return 1
    fi
    if ! grep -qF "::error::verifier-page-browser: [$row]" <<<"$out"; then
      printf '::error::seeding row %s went red for the WRONG reason:\n%s\n' \
        "$row" "$(grep '::error::' <<<"$out" | head -3)" >&2
      return 1
    fi
    for artefact in screenshot.png events.ndjson; do
      [ -s "$DIAGNOSIS/$artefact" ] ||
        { printf '::error::seeding row %s produced no %s — R14 requires the artifact set to carry the DIAGNOSIS, and `if-no-files-found: error` would then upload nothing\n' "$row" "$artefact" >&2; return 1; }
    done
    printf '  seeded %-15s -> RED by its own message, %s carries the screenshot and the event log\n' \
      "$row" "$DIAGNOSIS"
    seeded=$((seeded + 1))
  done

  # ── the receipt row's own phase (R85; D137 §5 point 3) ───────────────────
  #
  # The cheap invocation above cannot reach it: `receipt` only fires under
  # `--receipt`, exactly as `online` and `probe-plan` only fire under
  # `--online`. Rather than add a third name to the footnote of rows nothing
  # can plant, it gets a phase — `--receipt` drives TWO browser sessions and
  # does not pull in `--online`'s five, so the pre-image discipline costs
  # about as much as one row of the loop above.
  #
  # The same three clauses, none of them dropped: the unplanted invocation must
  # be GREEN and upload nothing; the plant must go red by its own message; and
  # the diagnosis set must appear because of the plant.
  note "the receipt row needs --receipt, so it gets its own pre-image and plant"
  [ -s "$RECEIPT_FIXTURE" ] ||
    die "$RECEIPT_FIXTURE is absent — run --check first; the receipt cases need D137 §7's twin"
  [ -s "$RECEIPT_FIXTURE.plan.json" ] ||
    die "$RECEIPT_FIXTURE.plan.json is absent — run --check first; the receipt cases route off the emitted plan"
  rm -rf "$DIAGNOSIS"
  out="$(drive --receipt "$RECEIPT_FIXTURE" --captures "$CAPTURES" "${bundles[@]}" 2>&1)"; status=$?
  if [ "$status" -ne 0 ]; then
    printf '::error::the unplanted --receipt invocation is already red, so seeding it would prove nothing:\n%s\n' \
      "$(grep '::error::' <<<"$out" | head -5)" >&2
    return 1
  fi
  if [ -d "$DIAGNOSIS" ] && [ -n "$(ls -A "$DIAGNOSIS" 2>/dev/null)" ]; then
    printf '::error::a GREEN --receipt run left files in %s\n' "$DIAGNOSIS" >&2
    return 1
  fi
  printf '  unplanted --receipt: GREEN, %s empty\n' "$DIAGNOSIS"

  rm -rf "$DIAGNOSIS"
  out="$(ANTSEAL_PAGE_SEED_FAILURE=receipt drive --receipt "$RECEIPT_FIXTURE" --captures "$CAPTURES" "${bundles[@]}" 2>&1)"; status=$?
  if [ "$status" -eq 0 ]; then
    printf '::error::seeding row receipt left the job GREEN — the plant never fired\n' >&2
    return 1
  fi
  if ! grep -qF "::error::verifier-page-browser: [receipt]" <<<"$out"; then
    printf '::error::seeding row receipt went red for the WRONG reason:\n%s\n' \
      "$(grep '::error::' <<<"$out" | head -3)" >&2
    return 1
  fi
  for artefact in screenshot.png events.ndjson; do
    [ -s "$DIAGNOSIS/$artefact" ] ||
      { printf '::error::seeding row receipt produced no %s\n' "$artefact" >&2; return 1; }
  done
  printf '  seeded %-15s -> RED by its own message, %s carries the screenshot and the event log\n' \
    "receipt" "$DIAGNOSIS"
  extra=$((extra + 1))

  rm -rf "$DIAGNOSIS"
  [ "$seeded" -eq "${#rows[@]}" ] ||
    die "seeded $seeded of ${#rows[@]} rows — the count is asserted because the loop above cannot fail for a row it never ran"
  [ "$extra" -eq 1 ] ||
    die "the receipt phase seeded $extra of 1 row — asserted for the same reason as the loop's count"
  printf 'seed-test PASS — %s row(s) planted in the cheap invocation plus %s under --receipt, each red\n' "$seeded" "$extra"
  printf '  by its own message; the two rows neither invocation reaches (probe-plan, online) need\n'
  printf '  --online and are covered by --check.\n'
}

case "${1:---check}" in
  --check | "")  cmd_check ;;
  --self-test)
    note "the network instrument's own planted fault"
    [ -f "$PAGE" ] || ./scripts/verifier-page-build.sh --build-only || exit 1
    drive --self-test ;;
  --seed-test)   cmd_seed_test ;;
  *) die "usage: scripts/verifier-page-browser.sh [--check | --self-test | --seed-test]" ;;
esac
