#!/usr/bin/env bash
# Package the verifier page and check it (R25).
#
#   ./scripts/verifier-page-build.sh              build + every check
#   ./scripts/verifier-page-build.sh --check      same, explicitly
#   ./scripts/verifier-page-build.sh --build-only build, no assertions
#   ./scripts/verifier-page-build.sh --self-test  the checks' own planted faults
#
# Exit 0 = one file exists at target/verifier-web/index.html, it decomposes back
# to the committed template, it carries the ruled Content-Security-Policy over
# hashes of the scripts actually present, and its SHA256SUMS has one line.
#
# ── The output NEVER lands in verifier-web/ ────────────────────────────────
#
# D131 §5 R4: `verifier-web/` is source-only and holds exactly the template.
# The built page goes to `target/`, which `.gitignore:8` already covers, so no
# ignore rule is added over a source directory and no rebuild ever appears in a
# diff. Measured, the alternative costs a 4 912 507-byte `git diff` for a
# one-byte change, whose `--stat` reads "1 insertion(+), 1 deletion(-)".
# R26 uploads what this script built, from `target/verifier-web/`, in the same
# run — D62 §3 R2 already rules Pages publishes from Actions and never from the
# tree, naming the hand-copied artifact as the hazard that prevents.
#
# ── Substitution is not idempotent, by design ─────────────────────────────
#
# D63 §5 R1: running the injector over an already-injected file is a hard
# error, never a silent no-op, and that extends to all four token kinds. The
# --self-test arm below proves it goes red rather than quietly re-emitting.
set -uo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo" || exit 1

note() { printf '\033[36m==>\033[0m %s\n' "$*"; }
die()  { printf '\033[31m::error::verifier-page-build: %s\033[0m\n' "$*" >&2; exit 1; }

PKG="target/wasm-pack/antseal-wasm"
TEMPLATE="verifier-web/index.template.html"
OUT="target/verifier-web"

cmd_build() {
  [ -f "$TEMPLATE" ] || die "the committed template $TEMPLATE does not exist — R23 authors it"

  if [ ! -f "${PKG}/antseal_wasm_bg.wasm" ] || [ ! -f "${PKG}/antseal_wasm.js" ]; then
    note "the module is not built yet — running scripts/wasm-pack-build.sh --build-only"
    ./scripts/wasm-pack-build.sh --build-only || return 1
  fi

  note "package the page into ONE file (D129 §5 R1-R2, ordering R8)"
  node scripts/verifier-page-pack.mjs "$PKG" "$TEMPLATE" "$OUT" || return 1
}

cmd_check() {
  local build_only="$1"

  # Always self-test first: a green assertion set proves nothing until it has
  # been seen to refuse something.
  if [ "$build_only" -eq 0 ]; then
    note "the assertions' own planted faults"
    node scripts/verifier-page-pack.mjs --self-test "$PKG" "$TEMPLATE" || return 1
  fi

  cmd_build || return 1

  if [ "$build_only" -eq 1 ]; then
    note "--build-only: stopping before the re-injection check"
    return 0
  fi

  # D63 §5 R1 over the real artifact: the injector must refuse its own output.
  note "re-injection is a hard error, not a silent no-op (D63 §5 R1)"
  local out status
  out="$(node scripts/verifier-page-pack.mjs "$PKG" "${OUT}/index.html" "${OUT}-reinject" 2>&1)"
  status=$?
  rm -rf "${OUT}-reinject"
  if [ "$status" -eq 0 ]; then
    die "the injector accepted an already-injected page and produced a second artifact — D63 §5 R1 requires a hard error"
  fi
  if ! grep -q 'already injected' <<<"$out"; then
    printf '::error::the re-injection check went red for the WRONG reason:\n%s\n' "$out" >&2
    return 1
  fi
  printf '  re-injection over the built page                  -> RED (%s)\n' \
    "$(grep -o 'does not carry the [a-zA-Z0-9]* token' <<<"$out" | head -1)"

  note "PASS — one file, decomposable to the template, policy over real hashes"
}

case "${1:---check}" in
  --check | "")  cmd_check 0 ;;
  --build-only)  cmd_check 1 ;;
  --self-test)   node scripts/verifier-page-pack.mjs --self-test "$PKG" "$TEMPLATE" ;;
  *) die "usage: scripts/verifier-page-build.sh [--check | --build-only | --self-test]" ;;
esac
