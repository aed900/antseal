#!/usr/bin/env bash
# WASM toolchain audit (P14) — two invariants, both enforced, both currently
# vacuous-but-live:
#
#   1. the getrandom recipe for every wasm32 build graph, and
#   2. wasm-bindgen crate pin == wasm-bindgen-cli pin (dependency-policy §5).
#
# ── 1. getrandom ────────────────────────────────────────────────────────────
#
#   MVP-SPEC.md line 153 mandates an "exact getrandom recipe": feature `js`
#   for the getrandom-0.2 line, feature `wasm_js` **plus**
#   RUSTFLAGS `--cfg getrandom_backend="wasm_js"` for the 0.3/0.4 lines —
#   both simultaneously, because a mixed workspace can carry both.
#
# Today no wasm32 build graph pulls getrandom at all (antseal-core takes an
# injected `TryCryptoRng`; the only getrandom edges in the lockfile come from
# `proptest`, which the wasm32 test build excludes). A recipe that is written
# down but never exercised rots silently, so this script turns it into an
# ENFORCED invariant instead of prose: the moment a getrandom-bearing
# dependency enters a wasm32 graph, the lane goes red and prints the exact
# manifest stanza to add.
#
# ── 2. wasm-bindgen crate <-> CLI pin equality ──────────────────────────────
#
# docs/dependency-policy.md §5 requires wasm-pack and wasm-bindgen-cli to be
# exact-pinned wherever installed, with the CLI version EQUAL to the
# `wasm-bindgen` crate pin (a mismatch breaks the generated glue). The check
# was written at P14 against an empty state and reports "not applicable" while
# BOTH sides are absent, at which point it starts enforcing equality with no
# further wiring.
#
# **[R22/D18, 2026-08-12] The paragraph this replaces read false.** It said the
# surface location "is decision D18, not due until M3" and that "pinning a
# version now would pre-empt D18". D18 is RESOLVED (2026-08-12): the surface is
# the workspace member `crates/antseal-wasm`, the pin is
# `wasm-bindgen = "=0.2.126"` — the version the committed Cargo.lock already
# carried — and the CLI is installed equal to it. The N/A state below is
# therefore no longer the live one; it is kept because "both absent" remains a
# reachable state (someone removing both), not because it describes today.
#
#   ./scripts/wasm-toolchain-audit.sh
#
# Exit 0 = every invariant holds (vacuously, while there is nothing to
# configure). Exit 1 = a missing or mismatched knob, named.
#
# Doc: docs/wasm-toolchain.md.
set -euo pipefail

# The audited target. The override exists for ONE documented purpose: the
# red-lane self-test of this detector. Pointing it at the host triple puts
# `proptest`'s getrandom 0.3/0.4 edges into the audited graph without the
# `wasm_js` feature, so the detector must go red and name both. Procedure and
# recorded result: docs/wasm-toolchain.md, "Red-lane evidence".
TARGET="${ANTSEAL_WASM_AUDIT_TARGET:-wasm32-unknown-unknown}"
CFG_FILE=".cargo/config.toml"

cd "$(dirname "$0")/.."

# The wasm32 build graphs that matter. Format: <package>|<cargo-tree edges>|<what it is>
GRAPHS=(
  "antseal-core|normal|the crate the verifier page ships"
  "antseal-core|normal,dev|the wasm32-core-tests libtest binary"
  "wasm-bitmatch|normal,dev|the Q5 native<->WASM bit-match harness"
)

fail=0

echo "getrandom audit — target ${TARGET}, recipe per MVP-SPEC.md line 153"
echo

for entry in "${GRAPHS[@]}"; do
  pkg="${entry%%|*}"
  rest="${entry#*|}"
  edges="${rest%%|*}"
  what="${rest#*|}"

  if ! cargo metadata --no-deps --format-version 1 --locked 2>/dev/null |
    grep -q "\"name\":\"${pkg}\""; then
    echo "  SKIP  ${pkg} (-e ${edges}) — package does not exist yet"
    continue
  fi

  # `{f}` prints the resolved feature list, which is what the knob check needs.
  tree="$(cargo tree -p "${pkg}" --target "${TARGET}" -e "${edges}" \
    --prefix none --format '{p} [{f}]' --locked)"
  hits="$(printf '%s\n' "${tree}" | grep -E '^getrandom v' | sort -u || true)"

  if [ -z "${hits}" ]; then
    echo "  OK    ${pkg} (-e ${edges}) — no getrandom in the graph  [${what}]"
    continue
  fi

  while IFS= read -r hit; do
    version="$(printf '%s' "${hit}" | sed -E 's/^getrandom v([0-9]+\.[0-9]+).*/\1/')"
    features="$(printf '%s' "${hit}" | sed -E 's/.*\[(.*)\]$/\1/')"
    case "${version}" in
      0.1 | 0.2) needed_feature="js" ; needs_cfg=0 ;;
      *)         needed_feature="wasm_js" ; needs_cfg=1 ;;
    esac

    if grep -qw "${needed_feature}" <<<"${features}" ; then
      echo "  OK    ${pkg} (-e ${edges}) — getrandom ${version} has feature \`${needed_feature}\`"
    else
      echo "::error::${pkg} (-e ${edges}) pulls getrandom ${version} into the ${TARGET} graph WITHOUT the \`${needed_feature}\` feature."
      cat <<EOF
        Fix (docs/wasm-toolchain.md, MVP-SPEC.md line 153) — declare the pin in
        the root [workspace.dependencies] (docs/dependency-policy.md §2), then
        add a target-gated edge to the crate that needs it:

            [target.'cfg(target_arch = "wasm32")'.dependencies]
            getrandom = { workspace = true, features = ["${needed_feature}"] }

        Resolved features seen instead: [${features}]
EOF
      fail=1
    fi

    if [ "${needs_cfg}" -eq 1 ] &&
      ! grep -q 'getrandom_backend="wasm_js"' "${CFG_FILE}"; then
      echo "::error::getrandom ${version} needs --cfg getrandom_backend=\"wasm_js\", missing from ${CFG_FILE}"
      fail=1
    fi
  done <<<"${hits}"
done

echo
echo "Lockfile-wide getrandom inventory (informational — includes native-only graphs):"
inventory="$(cargo tree --workspace --all-features --prefix none --locked -e normal,dev 2>/dev/null |
  grep -E '^getrandom v' | sort -u || true)"
if [ -z "${inventory}" ]; then
  echo "  (none in the lockfile)"
else
  printf '%s\n' "${inventory}" | sed 's/^/  /'
  echo "  consumers:"
  printf '%s\n' "${inventory}" | while IFS= read -r line; do
    ver="$(printf '%s' "${line}" | sed -E 's/^getrandom v([0-9.]+).*/\1/')"
    cargo tree --workspace --all-features --locked -e normal,dev \
      -i "getrandom@${ver}" 2>/dev/null | sed 's/^/    /'
  done
fi

echo
if [ "${fail}" -eq 0 ]; then
  echo "getrandom audit: OK — every wasm32 graph is either getrandom-free or correctly configured."
else
  echo "getrandom audit: FAILED — see the errors above."
fi

# ---------------------------------------------------------------------------
# 2. wasm-bindgen crate pin == wasm-bindgen-cli pin (dependency-policy §5)
# ---------------------------------------------------------------------------

echo
echo "wasm-bindgen pin equality — docs/dependency-policy.md §5"

# The crate pin may only ever live in the root [workspace.dependencies] (§2).
crate_pin="$(grep -E '^wasm-bindgen\b' Cargo.toml |
  sed -nE 's/.*"=([0-9]+\.[0-9]+\.[0-9]+)".*/\1/p' | head -n1 || true)"
# The CLI/`wasm-pack` pins live wherever they are installed: CI workflows and
# scripts. Any `--version X.Y.Z` following a wasm-bindgen-cli install counts.
cli_pins="$(grep -rhoE 'wasm-bindgen-cli[^\n]*--version [0-9]+\.[0-9]+\.[0-9]+' \
  .github/workflows scripts docs 2>/dev/null |
  sed -nE 's/.*--version ([0-9]+\.[0-9]+\.[0-9]+).*/\1/p' | sort -u || true)"

if [ -z "${crate_pin}" ] && [ -z "${cli_pins}" ]; then
  echo "  N/A   no \`wasm-bindgen\` crate pin and no wasm-bindgen-cli install anywhere."
  echo "        This was the M0 state and it is NO LONGER the expected one:"
  echo "        [R22/D18, 2026-08-12] the surface landed as crates/antseal-wasm and"
  echo "        the pin is \`wasm-bindgen = \"=0.2.126\"\` in [workspace.dependencies]."
  echo "        Reaching this branch today means BOTH sides were removed — check"
  echo "        the root Cargo.toml before believing it."
elif [ -z "${crate_pin}" ]; then
  echo "::error::wasm-bindgen-cli is pinned (${cli_pins}) but no \`wasm-bindgen\` crate pin exists in the root Cargo.toml — the two must be equal and the crate pin must live in [workspace.dependencies] (dependency-policy §2/§5)."
  fail=1
elif [ -z "${cli_pins}" ]; then
  echo "::error::\`wasm-bindgen = \"=${crate_pin}\"\` is pinned but nothing installs wasm-bindgen-cli at that exact version — glue generated by a mismatched CLI is a silent breakage (dependency-policy §5)."
  fail=1
else
  for pin in ${cli_pins}; do
    if [ "${pin}" != "${crate_pin}" ]; then
      echo "::error::wasm-bindgen-cli pinned at ${pin} but the wasm-bindgen crate is pinned at ${crate_pin} — they MUST be equal (dependency-policy §5)."
      fail=1
    fi
  done
  [ "${fail}" -eq 0 ] && echo "  OK    wasm-bindgen crate and CLI both pinned at ${crate_pin}"
fi

echo
if [ "${fail}" -ne 0 ]; then
  echo "wasm toolchain audit: FAILED"
  exit 1
fi
echo "wasm toolchain audit: OK"
