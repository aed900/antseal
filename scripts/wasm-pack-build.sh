#!/usr/bin/env bash
# Build the verifier page's WASM module and check it (R22).
#
#   ./scripts/wasm-pack-build.sh              build + every check
#   ./scripts/wasm-pack-build.sh --check      same, explicitly
#   ./scripts/wasm-pack-build.sh --build-only  build, no boundary comparison
#   ./scripts/wasm-pack-build.sh --self-test  the checks' own planted faults
#
# Exit 0 = the artifact exists, imports nothing outside the allow-list, carries
# no path from the machine that built it, and produces reports byte-identical
# to native over R9's corpus.
#
# ── The build is HERMETIC, and both flags are load-bearing ─────────────────
#
# MEASURED 2026-08-12 (R22's first act, D18 §7 P5 asked for exactly this):
# with every proxy variable pointed at a dead port, `wasm-pack build --release`
# still reached the network and downloaded a `wasm-opt` binary — binaryen
# **version 117, dated 2024-02-28** — into `~/.cache/.wasm-pack/`, then ran it.
# Nothing in this repository pins binaryen and `which wasm-opt` is empty, so
# that download is an unpinned, unreviewed program editing the artifact whose
# SHA-256 the page publishes about itself. It breaches D63 §5 R5's "no network
# access during the build" fence and docs/dependency-policy.md §5's
# "exact-pinned wherever installed".
#
#   --no-opt          does not run wasm-opt at all
#   --mode no-install does not fetch a wasm-bindgen-cli either; the one on
#                     PATH is used, and its version is asserted below
#
# Cost of the choice, measured on this 2-core host: 1.84 MB unoptimized
# against 1.53 MB optimized, and 2.8 s against 3 m 05 s. Re-enabling the
# optimizer is F29/R25's question and needs a PINNED binaryen first; it is not
# a flag an implementation lane may flip.
#
# ── The commit is SUPPLIED, never discovered ───────────────────────────────
#
# `crates/antseal-wasm/build.rs` reads ANTSEAL_SOURCE_COMMIT and stamps it into
# the build-info export D63 §5 R3's footer renders. This script is the one
# place that runs `git`; the crate itself runs no process, so a build from a
# source tarball with no `.git` still works and honestly reports `unknown`.
#
# ── No path from the BUILDING MACHINE may reach the artifact (R25/R83) ─────
#
# MEASURED 2026-08-14 at 08c074c, two runners, one commit: the GitHub Actions
# module was 1 853 735 B and this machine's 1 853 543 B, and the cause was the
# builder's absolute $CARGO_HOME — `/home/runner/.cargo/registry` against
# `/home/deb/.cargo/registry`, **52 occurrences each**. Base64-expanded
# (3 B -> 4 B) the 192-byte module delta is 256 B, which is exactly the
# 2 517 337 / 2 517 081 page gap.
#
# The per-occurrence arithmetic does NOT close and is not relied on: 52 x 3 B
# of path-length predicts 156 B against 192 B measured, and the local fix
# predicts 52 x 10 B = 520 B against 512 B measured. The residual is
# data-section and offset encoding. What the claim rests on is byte-identity
# across two runners, measured directly below — not on counting characters.
#
# D63 §7 rule 1 names two roots. Only one of them leaks HERE, and the record's
# own counts are for a different artifact: §1 (j) measured 300 checkout-path
# occurrences in the DEBUG `wasm_bitmatch.wasm`; in the release module this
# script ships the checkout path occurs **zero** times, because cargo already
# hands the local crate a relative path (§1 (k)'s first row). Both roots are
# remapped anyway — the workspace one costs nothing today and is precisely what
# starts leaking the moment any profile turns debuginfo back on.
#
# CHANNEL — `CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUSTFLAGS`, set on this one
# command. All four candidates were measured on cargo 1.92.0 and only this one
# composes with what is already there:
#
#   RUSTFLAGS / CARGO_ENCODED_RUSTFLAGS   REPLACE the whole rustflags
#       selection, so `.cargo/config.toml`'s getrandom `--cfg` (MVP-SPEC
#       line 153's recipe) silently disappears. Measured: cfg count 0.
#   --config 'target.cfg(target_arch="wasm32").rustflags=[...]'
#       ALSO replaces it — the cargo book's "all matching target.* entries
#       joined together" does not survive a `--config` override. Measured: cfg
#       count 0. This is the candidate that looks safe and is not.
#   [profile.release] trim-paths = "all"   would derive both remaps by itself
#       and is NOT STABILIZED: cargo 1.92.0 refuses it in `Cargo.toml` and in
#       `.cargo/config.toml` alike — "feature `trim-paths` is required … not
#       stabilized in this version of Cargo". Nightly is not this toolchain.
#   CARGO_TARGET_<TRIPLE>_RUSTFLAGS   MERGES with the config file's entry for
#       the same target. Measured: the getrandom `--cfg` survives beside both
#       remaps, in one rustc invocation.
#
# SCOPE — this invocation, never `.cargo/config.toml`. D18 §10's rider (quoted
# into D63's amendment) warned that config-level flags are per TARGET and would
# move `wasm_bitmatch.wasm`'s bytes too, and asked R25 to verify rather than
# assume. Verified by not touching that input at all: the wasm32 DEBUG cache
# (the `wasm32-core-tests` lane and Q5's bit-match) and the entire NATIVE cache
# see no flag change, and the cost is one wasm32-release rebuild here.
#
# The replacement values are `trim-paths`'s own (`/cargo/registry`), so
# adopting it when it stabilizes would not move the published digest.
#
# WHITESPACE — cargo splits `CARGO_TARGET_*_RUSTFLAGS` on spaces and offers no
# encoded form for the per-target key (there is no CARGO_ENCODED_TARGET_*),
# so a build path containing whitespace would be truncated into a HALF-remap.
# `remap_flags` refuses to build instead of publishing one.
set -uo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo" || exit 1

note() { printf '\033[36m==>\033[0m %s\n' "$*"; }
die()  { printf '\033[31m::error::wasm-pack-build: %s\033[0m\n' "$*" >&2; exit 1; }

PKG="crates/antseal-wasm"
OUT_REL="../../target/wasm-pack/antseal-wasm"
OUT="target/wasm-pack/antseal-wasm"
CORPUS="target/antseal-wasm/boundary-corpus.json"
MODULE="${OUT}/antseal_wasm_bg.wasm"

# ── the pins (docs/dependency-policy.md §5) ────────────────────────────────
#
# Read from where they are DECLARED, never restated here: the crate pin from
# the root [workspace.dependencies] with the same line grep
# `scripts/wasm-toolchain-audit.sh` uses, and the tool pins from wherever an
# install line records them. A version literal copied into this script is a
# second copy that would agree today and drift afterwards (Q130).
crate_pin() {
  grep -E '^wasm-bindgen\b' Cargo.toml |
    sed -nE 's/.*"=([0-9]+\.[0-9]+\.[0-9]+)".*/\1/p' | head -n1
}
recorded_pin() {
  grep -rhoE "$1[^\n]*--version [0-9]+\.[0-9]+\.[0-9]+" .github/workflows scripts docs 2>/dev/null |
    sed -nE 's/.*--version ([0-9]+\.[0-9]+\.[0-9]+).*/\1/p' | sort -u
}
installed() { "$1" --version 2>/dev/null | sed -nE 's/^[^ ]+ ([0-9]+\.[0-9]+\.[0-9]+).*/\1/p' | head -n1; }

check_toolchain() {
  local want_bindgen have_bindgen want_pack have_pack
  want_bindgen="$(crate_pin)"
  [ -n "$want_bindgen" ] || die "no \`wasm-bindgen\` crate pin in the root Cargo.toml — the CLI must equal it (dependency-policy §5), so there is nothing to build against"
  have_bindgen="$(installed wasm-bindgen)"
  [ -n "$have_bindgen" ] || die "wasm-bindgen-cli is not on PATH. Install the pinned one: cargo install wasm-bindgen-cli --locked --version ${want_bindgen}"
  [ "$have_bindgen" = "$want_bindgen" ] ||
    die "wasm-bindgen-cli ${have_bindgen} is installed but the crate is pinned at ${want_bindgen} — glue generated by a mismatched CLI is a silent breakage (dependency-policy §5)"

  want_pack="$(recorded_pin wasm-pack)"
  [ -n "$want_pack" ] || die "no wasm-pack install line records an exact version anywhere — §5 requires exact-pinning wherever installed"
  [ "$(printf '%s\n' "$want_pack" | grep -c .)" -eq 1 ] ||
    die "wasm-pack is recorded at more than one version: $(printf '%s' "$want_pack" | tr '\n' ' ')"
  have_pack="$(installed wasm-pack)"
  [ -n "$have_pack" ] || die "wasm-pack is not on PATH. Install the pinned one: cargo install wasm-pack --locked --version ${want_pack}"
  [ "$have_pack" = "$want_pack" ] ||
    die "wasm-pack ${have_pack} is installed but ${want_pack} is the recorded pin (dependency-policy §5; the tool list IS part of the build's identity, D63 §7 rule 1)"

  printf '  wasm-bindgen %s (crate pin %s) · wasm-pack %s (recorded pin %s)\n' \
    "$have_bindgen" "$want_bindgen" "$have_pack" "$want_pack"
}

# ── the path remap (D63 §7 rule 1) ────────────────────────────────────────
#
# Both roots are DERIVED from the environment doing the building, never
# hard-coded: that is the whole property — a different $CARGO_HOME and a
# different checkout path must produce the same bytes. `REMAP` is the value
# handed to cargo; `remap_flags` fills it or refuses.
REMAP=""

remap_add() { # $1 = absolute prefix, $2 = its replacement
  local from="$1" to="$2"
  [ -n "$from" ] || return 0
  case " $REMAP " in *" --remap-path-prefix=${from}=${to} "*) return 0 ;; esac
  case "$from" in
    *[[:space:]]*)
      printf '::error::the build path `%s` contains whitespace; cargo splits CARGO_TARGET_*_RUSTFLAGS on spaces and has no encoded form for the per-target key, so this remap would be silently truncated into a half-remapped artifact\n' "$from" >&2
      return 1 ;;
  esac
  REMAP="${REMAP:+$REMAP }--remap-path-prefix=${from}=${to}"
}

remap_flags() {
  local cargo_home registry
  REMAP=""
  cargo_home="${CARGO_HOME:-}"
  if [ -z "$cargo_home" ]; then
    [ -n "${HOME:-}" ] ||
      die "neither CARGO_HOME nor HOME is set, so \$CARGO_HOME/registry cannot be derived — and a hard-coded prefix is not portable, which is the point of D63 §7 rule 1"
    cargo_home="${HOME}/.cargo"
  fi
  registry="${cargo_home%/}/registry"

  # Cargo emits $CARGO_HOME verbatim, symlinks included (measured), but rustc
  # can still be handed the physically resolved path, so remap both forms
  # whenever a symlink makes them differ. Duplicates are dropped by remap_add.
  remap_add "$registry" /cargo/registry                          || return 1
  remap_add "$(readlink -f "$registry" 2>/dev/null)" /cargo/registry || return 1
  remap_add "$repo" /antseal                                     || return 1
  remap_add "$(readlink -f "$repo" 2>/dev/null)" /antseal        || return 1
}

# ── `--locked` is passed AND verified, because passing it is not enough ───
#
# D63 §5 R5 (i) rules the build *"invoke `wasm-pack` at the pinned versions
# with `--locked`"*. MEASURED 2026-08-15, in a scratch copy of the tree, that
# the ruled mechanism does not do what its name says:
#
#   cargo build --target wasm32… --release --locked, lock file deleted
#       -> exit 101, "the lock file … needs to be updated but --locked was
#          passed", lock NOT recreated.                     (cargo behaves)
#   wasm-pack build … -- --locked, lock file deleted
#       -> exit 0, and the lock is RECREATED.               (the flag is moot)
#
# Extra options do reach cargo — a bogus one is rejected — so the flag is not
# dropped. wasm-pack runs `cargo metadata` BEFORE the build, that call
# re-resolves and writes `Cargo.lock`, and the `--locked` build then trivially
# agrees with the lock that was just regenerated. (In the deleted-lock probe
# the re-resolution picked `thiserror 2.0.20` where the committed lock names
# `2.0.19` — a different dependency graph, silently.)
#
# So `--locked` is passed (it does bind the build step, and costs nothing —
# measured: the digest is unchanged) and the property it was supposed to buy
# is asserted directly instead: the lock is byte-identical across the build.
lock_digest() { sha256sum Cargo.lock 2>/dev/null | cut -d' ' -f1; }

build() {
  local commit lock_before lock_after
  remap_flags || return 1
  # `git` is this script's, never the crate's. A tree with no git still builds.
  commit="$(git rev-parse HEAD 2>/dev/null || printf 'unknown')"
  lock_before="$(lock_digest)"
  rm -rf "${OUT:?}"
  ANTSEAL_SOURCE_COMMIT="$commit" \
  CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUSTFLAGS="$REMAP" \
    wasm-pack build "$PKG" \
    --release --target web --no-pack --no-opt --mode no-install \
    --out-dir "$OUT_REL" -- --locked || return 1
  lock_after="$(lock_digest)"
  if [ "$lock_before" != "$lock_after" ]; then
    printf '::error::Cargo.lock changed during the build (%s -> %s). `--locked` binds `cargo build`, but wasm-pack runs `cargo metadata` first and that call re-resolves — so this module was built against a dependency graph the committed lock does not name, and a second runner may resolve differently (D63 §5 R5 (i); R25 Accept row 1)\n' \
      "${lock_before:-<absent>}" "${lock_after:-<absent>}" >&2
    return 1
  fi
  [ -f "$MODULE" ] || { printf '::error::wasm-pack reported success but %s does not exist\n' "$MODULE"; return 1; }
  printf '  %s — %s bytes, commit %s\n' "$MODULE" "$(wc -c <"$MODULE")" "$commit"
  printf '  remap: %s\n' "$REMAP"
  printf '  Cargo.lock unchanged across the build (%s)\n' "${lock_before:0:12}"
}

# ── the artifact carries no path from the machine that built it ───────────
#
# The NEGATIVE direction is the one that matters: two runners agree only if
# neither stamped its own $CARGO_HOME or checkout into the bytes, and a flag
# that stops reaching cargo (a reordered command, a wasm-pack change) fails
# exactly here rather than 192 bytes later in someone else's diff. Scanned as
# raw text so it covers strings the module never executes.
#
# The placeholder count is PRINTED, not asserted: a dependency bump that
# stopped emitting registry paths altogether would be fine, and an assertion
# on it would be a red for a non-defect.
check_build_paths() {
  local f pat n sample fail=0 home_cargo
  home_cargo="${CARGO_HOME:-}"
  [ -n "$home_cargo" ] || home_cargo="${HOME:+${HOME}/.cargo}"

  for f in "$@"; do
    [ -f "$f" ] || { printf '::error::%s does not exist, so the path scan proves nothing\n' "$f" >&2; return 1; }
    for pat in "$repo" "$home_cargo" '/home/' '/Users/' '/root/'; do
      [ -n "$pat" ] || continue
      n="$(grep -aoF -e "$pat" "$f" | wc -l)"
      [ "$n" -eq 0 ] && continue
      sample="$(strings -a "$f" | grep -F -e "$pat" | head -n1)"
      printf "::error::%s embeds the building machine's path: %d occurrence(s) of \`%s\` (e.g. %s) — two runners cannot agree on these bytes (D63 §7 rule 1)\n" \
        "$f" "$n" "$pat" "$sample" >&2
      fail=1
    done
  done
  [ "$fail" -eq 0 ] || return 1
  printf '  no builder path in %d file(s); %s remapped registry path(s) carry the /cargo/registry placeholder\n' \
    "$#" "$(grep -aoF -e '/cargo/registry' "$1" | wc -l)"
}

emit_corpus() {
  cargo run -q -p antseal-wasm --example boundary-emit --locked -- "$CORPUS"
}

cmd_check() {
  local build_only="$1" rc=0

  note "toolchain pins (dependency-policy §5)"
  check_toolchain || return 1

  note "build the shipped module (release, no wasm-opt, no tool download)"
  build || return 1

  note "import allow-list over the BUILT artifact (D18 §5 R7)"
  # Self-test first, always: a green allow-list proves nothing until it has
  # been seen to refuse something.
  node scripts/wasm-imports.mjs --self-test || return 1
  node scripts/wasm-imports.mjs "$MODULE" || return 1

  note "no path from the building machine in the shipped files (D63 §7 rule 1)"
  check_build_paths "$MODULE" "${OUT}/antseal_wasm.js" || return 1

  if [ "$build_only" -eq 1 ]; then
    note "--build-only: stopping before the boundary comparison"
    return 0
  fi

  note "emit the native side of R9's corpus"
  emit_corpus || return 1

  note "R9 vectors through the JS boundary, against native (Accept row 2)"
  node scripts/wasm-boundary.mjs "$OUT" "$CORPUS" || rc=1
  return "$rc"
}

# ── the tests of the tests ─────────────────────────────────────────────────
#
# Three planted faults, each proving that the check downstream of it can go red
# FOR THE RIGHT REASON. A nonzero exit is not the evidence — a crash exits
# nonzero too — so every arm matches on the message.
cmd_self_test() {
  local fail=0 out status corrupt planted

  note "planted fault 1: a report byte changed on the native side"
  emit_corpus >/dev/null || die "the corpus could not be emitted, so nothing below proves anything"
  [ -f "$MODULE" ] || build >/dev/null || die "no module to compare against"
  corrupt="$(mktemp)"
  # Flip one byte inside the FIRST case's report hex. The boundary must report
  # a byte-position difference, not a load error and not a thrown export.
  node -e '
    const {readFileSync, writeFileSync} = require("node:fs");
    const corpus = JSON.parse(readFileSync(process.argv[1], "utf8"));
    const hex = corpus.cases[0].report_hex;
    const flipped = (hex[41] === "a" ? "b" : "a");
    corpus.cases[0].report_hex = hex.slice(0, 41) + flipped + hex.slice(42);
    writeFileSync(process.argv[2], JSON.stringify(corpus));
  ' "$CORPUS" "$corrupt" || die "could not plant the corrupt corpus"
  out="$(node scripts/wasm-boundary.mjs "$OUT" "$corrupt" 2>&1)"
  status=$?
  rm -f "$corrupt"
  if [ "$status" -eq 0 ]; then
    printf '::error:: the boundary comparison stayed GREEN with a planted report-byte difference — it is not comparing anything\n'; fail=1
  elif ! grep -q 'the report differs from native at byte' <<<"$out"; then
    printf '::error:: the boundary comparison went red for the WRONG reason:\n%s\n' "$(grep '::error::' <<<"$out" | head -3)"; fail=1
  else
    printf '  planted fault: one report byte flipped            -> RED (%s)\n' \
      "$(grep -o 'the report differs from native at byte [0-9]*' <<<"$out" | head -1)"
  fi

  note "planted fault 2: an unlisted host capability in the import table"
  out="$(node scripts/wasm-imports.mjs --self-test 2>&1)"
  status=$?
  if [ "$status" -ne 0 ]; then
    printf '::error:: the import allow-list self-test itself failed:\n%s\n' "$out"; fail=1
  else
    printf '%s\n' "$out" | sed 's/^/  /'
  fi

  note "planted fault 3: the builder's \$CARGO_HOME left in the artifact"
  # Appended as raw text to a copy of the real module: the scan is a byte
  # scan, so the fault is exactly the leak the remap exists to prevent and
  # nothing else. The copy is never instantiated.
  planted="$(mktemp)"
  { cat "$MODULE"
    printf '%s/registry/src/index.crates.io-0000000000000000/planted-0.0.0/src/lib.rs' \
      "${CARGO_HOME:-${HOME:-/nonexistent}/.cargo}"
  } > "$planted" || die "could not plant the leaking artifact"
  out="$(check_build_paths "$planted" 2>&1)"
  status=$?
  rm -f "$planted"
  if [ "$status" -eq 0 ]; then
    printf "::error:: the path scan stayed GREEN over an artifact carrying the builder's \$CARGO_HOME — it is not scanning anything\n"; fail=1
  elif ! grep -q "embeds the building machine's path" <<<"$out"; then
    printf '::error:: the path scan went red for the WRONG reason:\n%s\n' "$(grep '::error::' <<<"$out" | head -3)"; fail=1
  else
    printf '  planted fault: builder $CARGO_HOME appended       -> RED (%s)\n' \
      "$(grep -o 'occurrence(s) of `[^`]*`' <<<"$out" | head -1)"
  fi

  [ "$fail" -eq 0 ] || return 1
  note "self-test PASS — all three checks go red for their own reason"
}

case "${1:---check}" in
  --check | "") cmd_check 0 ;;
  --build-only) cmd_check 1 ;;
  --self-test)  cmd_self_test ;;
  *) die "usage: scripts/wasm-pack-build.sh [--check | --build-only | --self-test]" ;;
esac
