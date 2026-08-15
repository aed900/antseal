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
MODULE="${PKG}/antseal_wasm_bg.wasm"
TEMPLATE="verifier-web/index.template.html"
OUT="target/verifier-web"

# R83, arm (b): REBUILD, then require byte-equality with whatever was there.
#
# This script used to build only when `target/wasm-pack/`'s two files were
# ABSENT, so `--check` — the mode the gate runs, and the default — packaged,
# hashed and asserted whatever artifact happened to be sitting in `target/`.
# Every one of D129 §5 R9's assertions still passed, and that is not a bug in
# them: each compares the built page against **the module it was built from**,
# which is exactly the property a stale module preserves. Nothing compared the
# artifact against the sources.
#
# Arm (b) rather than a bare "always rebuild" (arm (a)) because the difference
# IS R25's Accept row 1. A rebuild alone makes the packaged bytes current; the
# comparison makes the build's reproducibility an assertion rather than a
# precondition for one, so two runners each re-using their own stale `target/`
# can no longer agree with themselves and prove nothing. Measured, un-remapped
# against remapped: this check goes red where every R9 assertion stayed green.
#
# Arm (c) — an mtime or commit-stamp predicate — is refused: neither handle
# sees an uncommitted edit, which is the case a developer is actually in.
stale_guard() {
  local before after
  before=""
  [ -f "$MODULE" ] && before="$(sha256sum "$MODULE" | awk '{print $1}')"

  note "rebuild the module, so the packaged bytes are the tree's (R83)"
  ./scripts/wasm-pack-build.sh --build-only || return 1
  [ -f "$MODULE" ] || die "the module is absent after a green build"
  after="$(sha256sum "$MODULE" | awk '{print $1}')"

  if [ -n "$before" ] && [ "$before" != "$after" ]; then
    printf '::error::verifier-page-build: STALE ARTIFACT — the module in %s was not built from this tree.\n' "$PKG" >&2
    printf '  was:   %s\n  is:    %s\n' "$before" "$after" >&2
    printf '  Everything packaged from the old bytes — the page, its CSP hashes and the footer digest\n' >&2
    printf '  the page publishes about itself — described an artifact the sources do not produce.\n' >&2
    printf '  The rebuild has corrected it; re-run to package the current module.\n' >&2
    return 1
  fi
  [ -n "$before" ] && printf '  module unchanged by the rebuild: %s\n' "${after:0:16}…"
  return 0
}

cmd_build() {
  [ -f "$TEMPLATE" ] || die "the committed template $TEMPLATE does not exist — R23 authors it"
  stale_guard || return 1

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

# R83's Accept row 1: a planted STALE artifact must turn --check red, and be
# seen to do it for the right reason. A nonzero exit is not the evidence — a
# crash exits nonzero too — so this matches on the message.
cmd_stale_self_test() {
  local out status saved
  [ -f "$MODULE" ] || ./scripts/wasm-pack-build.sh --build-only >/dev/null 2>&1 || return 1
  saved="$(mktemp)"
  cp "$MODULE" "$saved"

  # A module that is not this tree's. One flipped byte in a data section is
  # enough and is exactly the shape of the real defect: a plausible artifact,
  # from a different build, that every page-level assertion would still accept.
  printf 'stale' | dd of="$MODULE" bs=1 seek=1024 conv=notrunc status=none

  out="$(cmd_build 2>&1)"; status=$?
  cp "$saved" "$MODULE"; rm -f "$saved"

  if [ "$status" -eq 0 ]; then
    printf '::error::the stale-artifact guard stayed GREEN over a planted module — a green --check is not evidence the packaged bytes came from the tree (R83)\n' >&2
    return 1
  fi
  if ! grep -q 'STALE ARTIFACT' <<<"$out"; then
    printf '::error::the guard went red for the WRONG reason:\n%s\n' "$(grep '::error::' <<<"$out" | head -3)" >&2
    return 1
  fi
  printf '  planted fault: a module not built from this tree      -> RED (STALE ARTIFACT)\n'
}

case "${1:---check}" in
  --check | "")  cmd_check 0 ;;
  --build-only)  cmd_check 1 ;;
  --self-test)
    node scripts/verifier-page-pack.mjs --self-test "$PKG" "$TEMPLATE" || exit 1
    cmd_stale_self_test ;;
  *) die "usage: scripts/verifier-page-build.sh [--check | --build-only | --self-test]" ;;
esac
