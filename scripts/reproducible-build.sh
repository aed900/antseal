#!/usr/bin/env bash
# R86/D135 — the TWO-ENVIRONMENT build comparison.
#
#   ./scripts/reproducible-build.sh --compare       self-test, then build B and compare
#   ./scripts/reproducible-build.sh --self-test     the comparator's own planted faults (ms)
#   ./scripts/reproducible-build.sh --plant-commit  the expensive LOCAL plant (D135 §7 R3)
#   ./scripts/reproducible-build.sh --help
#
# Exit 0 = this commit's `antseal_wasm_bg.wasm` and `antseal_wasm.js` are
# byte-identical when built twice under two different checkout paths and two
# different `$CARGO_HOME`s, so the footer digest and SHA256SUMS this deploy
# publishes describe bytes a reader whose machine is not this one can reproduce.
#
# ── WHY A THIRD BUILD, when the deploy already builds twice ────────────────
#
# It already does, and that pair is worthless as reproducibility evidence.
# `pages-publish.sh --build` runs `wasm-pack-build.sh --check` (build 1) and
# then `verifier-page-build.sh --check`, whose R83 `stale_guard` runs
# `--build-only` (build 2) and byte-compares. MEASURED in run 31873422229
# (D135 §1.4): build 2 took **0.81 s wall**, and cargo's own line was
# `Finished \`release\` profile [optimized] target(s) in 0.14s`. Not one crate
# was recompiled — the comparison's subject was `wasm-bindgen` re-emitting glue
# from a `.wasm` cargo did not rebuild. R86's own `Do` names that non-property:
# *"a second build under identical conditions asserts only that `rustc` is
# deterministic … which is not the property at risk."*
#
# So the missing thing was never a second BUILD. It is a second ENVIRONMENT,
# and this script is it — kept separate from `stale_guard` on purpose, because
# the moment that guard's two builds differ in environment its own red means
# either staleness or irreproducibility (D135 §8 R3).
#
# ── THE TIER IS DEPLOY-GATED, AND IT IS RAISE-ONLY ─────────────────────────
#
# `pages.yml` calls `pages-publish.sh --build` BEFORE `actions/configure-pages`,
# `upload-pages-artifact` and `deploy-pages`, so a red here ends the job with
# nothing staged and nothing published. *A deploy cannot publish a digest two
# builds disagree on* is therefore a property of the committed file rather than
# an aspiration.
#
# Measured price (D135 §3 R2): +1 to +2 BILLED weighted minutes per deploy, and
# ZERO in a month with no deploy, against a repository that spent 3 154 weighted
# minutes in the first fortnight of 2026-08 and had 45 jobs refused a runner for
# it — twice — in that same window.
#
# The tier below is RAISE-ONLY BY DECISION, never by an implementer needing a
# build to go green (the idiom and the rule are `scripts/ci-lanes.sh`'s
# FUZZ_BUDGET_CEILING_MINUTES). Its precondition is a MEASURED monthly bill
# under the allowance, taken the way D135 §1.1 takes it — per job, rounded up,
# platform multipliers applied — and NOT an estimate.
#
# The arm to promote to is already priced, so that decision does not re-derive
# the arithmetic (D135 §10 R2): a SEPARATE `on: push` workflow with a workflow
# level `paths:` filter — evaluated by GitHub before a runner is assigned, so a
# push touching no build input costs zero minutes, unlike a job-level `if:`
# which still bills its runner. Measured hit rate over 33 pushes: 52 % narrow
# (`crates/antseal-core/src/**`, `crates/antseal-wasm/**`, `Cargo.toml`,
# `Cargo.lock`, `.cargo/config.toml`, `rust-toolchain.toml`,
# `scripts/wasm-pack-build.sh`), 61 % broad. Price: 0.52 x 51.7 x 3 = ~81
# weighted min/month. Two riders that decision inherits: the filter needs its
# own self-test (a filter that silently matches nothing is a lane that never
# runs and always looks green), and it must include `scripts/wasm-pack-build.sh`
# and the files the tool-pin greps read, because a pin bump moves the bytes
# without touching a crate. NOT arm (a), a required context on every push:
# ~155 weighted min/month, refused on the measurement.
REPRO_TIER="deploy-gated (D135 §3 R1) — RAISE-ONLY BY DECISION"
set -uo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo" || exit 1

note() { printf '\033[36m==>\033[0m %s\n' "$*"; }
die()  { printf '\033[31m::error::reproducible-build: %s\033[0m\n' "$*" >&2; exit 1; }

OUT_REL="target/wasm-pack/antseal-wasm"
MODULE_NAME="antseal_wasm_bg.wasm"
GLUE_NAME="antseal_wasm.js"

# Printed by every message, set by whoever calls the comparator — including the
# self-test, which passes fabricated values. A green that does not show the two
# environments is indistinguishable from a green that compared a build with
# itself, which is the failure this whole script exists to end (D135 §6 R3).
ENV_A_PATH=""; ENV_A_HOME=""; ENV_B_PATH=""; ENV_B_HOME=""; ENV_COMMIT=""

digest() { sha256sum "$1" 2>/dev/null | cut -d' ' -f1; }
bytes()  { wc -c <"$1" 2>/dev/null | tr -d ' '; }

# ── the axes, ASSERTED before anything is built (D135 §4 R4) ───────────────
#
# A comparison whose two environments are equal is green for the wrong reason
# and is this project's dominant defect class; it must be structurally
# impossible, not merely unlikely. Both axes must differ in CONTENT and in
# LENGTH: the measured defect was a 192-byte size delta produced by 52
# occurrences of a path of a different length, and a same-length substitution
# would exercise the remap without exercising the size arithmetic that made the
# original defect visible (D135 §4 R1; R25's discharged pair was 25 against 122
# characters).
assert_axes() { # $1 path_a $2 home_a $3 path_b $4 home_b
  local pa="$1" ha="$2" pb="$3" hb="$4" fail=0 ra rb
  local -a problems=()

  [ -d "$pa" ] || problems+=("build A's checkout path does not exist: $pa")
  [ -d "$pb" ] || problems+=("build B's checkout path does not exist: $pb")
  [ -d "$ha" ] || problems+=("build A's \$CARGO_HOME does not exist: $ha")
  [ -d "$hb" ] || problems+=("build B's \$CARGO_HOME does not exist: $hb")

  [ "$pa" != "$pb" ] || problems+=("the checkout path is IDENTICAL in both builds ($pa) — the axis varies nothing")
  [ "$ha" != "$hb" ] || problems+=("\$CARGO_HOME is IDENTICAL in both builds ($ha) — the axis varies nothing")
  [ "${#pa}" -ne "${#pb}" ] ||
    problems+=("the two checkout paths differ in content but NOT in length (${#pa} characters each) — a same-length substitution exercises the remap without exercising the size arithmetic that made the original defect visible (D135 §4 R1)")
  [ "${#ha}" -ne "${#hb}" ] ||
    problems+=("the two \$CARGO_HOMEs differ in content but NOT in length (${#ha} characters each) — same reason (D135 §4 R1)")

  # `remap_flags()` remaps the PHYSICALLY RESOLVED registry path too, so a
  # build-B $CARGO_HOME symlinked into build A's gets both forms remapped, the
  # axis contributes nothing, and the comparison passes while testing nothing
  # (D135 §4 R5).
  ra="$(readlink -f "${ha%/}/registry" 2>/dev/null)"
  rb="$(readlink -f "${hb%/}/registry" 2>/dev/null)"
  if [ -n "$ra" ] && [ "$ra" = "$rb" ]; then
    problems+=("the two \$CARGO_HOME registries RESOLVE TO ONE DIRECTORY ($ra) — a symlink defeats the axis, because remap_flags() remaps \`readlink -f\` of the registry as well (D135 §4 R5)")
  fi

  if [ "${#problems[@]}" -gt 0 ]; then
    printf '::error::reproducible-build: AXES NOT INDEPENDENT — the two builds were not going to be a\n' >&2
    printf '  test of anything. This is not a build failure and not a reproducibility failure; it is the\n' >&2
    printf '  harness refusing to compare two environments that are not two environments (D135 §4 R4).\n' >&2
    printf '    build A:  path=%s  CARGO_HOME=%s\n' "$pa" "$ha" >&2
    printf '    build B:  path=%s  CARGO_HOME=%s\n' "$pb" "$hb" >&2
    local p
    for p in "${problems[@]}"; do printf '    - %s\n' "$p" >&2; done
    fail=1
  fi
  return "$fail"
}

# ── the comparison itself (D135 §6) ────────────────────────────────────────
#
# `NOT REPRODUCIBLE` is a RESERVED leading token: it appears nowhere else in
# this repository, so a reader — and D135 §8's message matching — can tell this
# red apart from `check_build_paths`'s "embeds the building machine's path"
# (guard 1: no builder path reached this artifact) and from `stale_guard`'s
# `STALE ARTIFACT` (guard 2: the packaged bytes are this tree's). Three
# properties, three tokens, and no guard carries another's message.
compare_artifacts() { # $1 dir_A $2 dir_B
  local a="$1" b="$2" f differ=0 offset="" name
  local -a lines=()

  for name in "$MODULE_NAME" "$GLUE_NAME"; do
    for f in "$a/$name" "$b/$name"; do
      [ -f "$f" ] || {
        printf '::error::reproducible-build: %s does not exist, so the comparison proves nothing\n' "$f" >&2
        return 1
      }
    done
    local da db sa sb verdict
    da="$(digest "$a/$name")"; db="$(digest "$b/$name")"
    sa="$(bytes "$a/$name")"; sb="$(bytes "$b/$name")"
    if [ "$da" = "$db" ]; then
      verdict="same"
    else
      verdict="DIFFER"
      differ=1
      if [ -z "$offset" ]; then
        offset="$(cmp "$a/$name" "$b/$name" 2>/dev/null | sed -nE 's/.*differ: byte ([0-9]+).*/\1/p' | head -n1)"
        [ -n "$offset" ] || offset="beyond the shorter file (sizes ${sa} vs ${sb})"
      fi
    fi
    lines+=("$(printf '%-22s A %s (%s B)   B %s (%s B)   %s' "$name" "$da" "$sa" "$db" "$sb" "$verdict")")
  done

  if [ "$differ" -eq 1 ]; then
    {
      printf '\033[31m::error::reproducible-build: NOT REPRODUCIBLE — two builds of this commit under different\033[0m\n'
      printf '  environments produced different bytes. The footer digest and SHA256SUMS this deploy would\n'
      printf '  publish describe bytes only one of these two machines produces (R25 Accept row 1, as re-worded\n'
      printf '  by D135 §4 R3; D63 §7 rule 1).\n'
      printf '    commit:   %s (identical by construction — D135 §4 R7)\n' "$ENV_COMMIT"
      printf '    build A:  path=%s  CARGO_HOME=%s\n' "$ENV_A_PATH" "$ENV_A_HOME"
      printf '    build B:  path=%s  CARGO_HOME=%s\n' "$ENV_B_PATH" "$ENV_B_HOME"
      local l
      for l in "${lines[@]}"; do printf '    %s\n' "$l"; done
      printf '  First differing byte offset: %s.  Nothing was uploaded and no deploy was attempted.\n' "$offset"
    } >&2
    return 1
  fi

  printf '  reproducible across environments: %s %s (%s B), %s %s\n' \
    "$MODULE_NAME" "$(digest "$a/$MODULE_NAME")" "$(bytes "$a/$MODULE_NAME")" \
    "$GLUE_NAME" "$(digest "$a/$GLUE_NAME")"
  printf '    A path=%s CARGO_HOME=%s\n' "$ENV_A_PATH" "$ENV_A_HOME"
  printf '    B path=%s CARGO_HOME=%s   (lengths differ by %s and %s characters)\n' \
    "$ENV_B_PATH" "$ENV_B_HOME" \
    "$(( ${#ENV_B_PATH} - ${#ENV_A_PATH} ))" "$(( ${#ENV_B_HOME} - ${#ENV_A_HOME} ))"
  printf '    tier: %s\n' "$REPRO_TIER"
  return 0
}

# ── the tests of the tests, run on EVERY invocation (D135 §7 R2) ───────────
#
# Neither arm builds anything; together they cost milliseconds. They are what
# makes the green above mean something on a run that never goes red, and the
# third arm is the one this project's defect register demands: a comparator
# that is always red is as useless as one that is always green.
cmd_self_test() {
  local fail=0 out status tmp
  tmp="$(mktemp -d)" || die "no temporary directory"
  # shellcheck disable=SC2064
  trap "rm -rf '$tmp'" RETURN

  mkdir -p "$tmp/a" "$tmp/b"
  head -c 4096 /dev/urandom >"$tmp/a/$MODULE_NAME"
  head -c 512  /dev/urandom >"$tmp/a/$GLUE_NAME"
  cp "$tmp/a/$MODULE_NAME" "$tmp/b/$MODULE_NAME"
  cp "$tmp/a/$GLUE_NAME"   "$tmp/b/$GLUE_NAME"

  ENV_COMMIT="0000000000000000000000000000000000000000"
  ENV_A_PATH="$tmp/a"; ENV_A_HOME="$tmp/home-a"; ENV_B_PATH="$tmp/bb"; ENV_B_HOME="$tmp/home-bbb"

  note "control arm: two IDENTICAL artifacts must be GREEN"
  out="$(compare_artifacts "$tmp/a" "$tmp/b" 2>&1)"; status=$?
  if [ "$status" -ne 0 ]; then
    printf '::error:: the comparator went RED over two identical artifacts — it is red for reasons of its own, so its reds say nothing:\n%s\n' "$out"; fail=1
  elif ! grep -q 'reproducible across environments' <<<"$out"; then
    printf '::error:: the comparator went green WITHOUT printing the two environments and the shared digest, which is the green D135 §6 R3 forbids:\n%s\n' "$out"; fail=1
  else
    printf '  control:       two identical artifacts                -> GREEN (%s)\n' \
      "$(grep -o 'antseal_wasm_bg.wasm [0-9a-f]\{16\}' <<<"$out" | head -1)…"
  fi

  note "planted fault 1: ONE byte of the module differs between the two builds"
  printf 'X' | dd of="$tmp/b/$MODULE_NAME" bs=1 seek=2048 conv=notrunc status=none
  out="$(compare_artifacts "$tmp/a" "$tmp/b" 2>&1)"; status=$?
  if [ "$status" -eq 0 ]; then
    printf '::error:: the comparator stayed GREEN over two artifacts differing in one byte — it is not comparing anything\n'; fail=1
  elif ! grep -q 'NOT REPRODUCIBLE' <<<"$out"; then
    printf '::error:: the comparator went red for the WRONG reason:\n%s\n' "$(head -3 <<<"$out")"; fail=1
  elif [ "$(grep -oE '\b[0-9a-f]{64}\b' <<<"$out" | sort -u | wc -l)" -lt 3 ]; then
    printf '::error:: the red did not print both digests of both files — a reader is left comparing hashes by eye (D135 §6 R1/R2):\n%s\n' "$out"; fail=1
  elif ! grep -q "$MODULE_NAME.*DIFFER" <<<"$out" || ! grep -q "$GLUE_NAME.*same" <<<"$out"; then
    printf '::error:: the red did not say WHICH file diverged; both files are printed on every red (D135 §6 R2):\n%s\n' "$out"; fail=1
  elif ! grep -q '4096 B' <<<"$out"; then
    printf '::error:: the red did not print the byte counts (D135 §6 R1):\n%s\n' "$out"; fail=1
  else
    printf '  planted fault: one module byte differs between A and B -> RED (%s)\n' \
      "$(grep -o 'First differing byte offset: [0-9]*' <<<"$out" | head -1)"
  fi

  note "planted fault 2: two environments that are not two environments"
  # Every directory exists before the arms run, so a "does not exist" problem
  # can never be the thing that makes one of them red: each arm must red for
  # ITS OWN sub-reason, which is what the per-arm grep below requires.
  mkdir -p "$tmp/home-a/registry" "$tmp/home-bbb" "$tmp/bbbb" "$tmp/same-length-b"
  local arm want
  for arm in "same-path" "same-cargo-home" "symlinked-cargo-home" "same-length-path"; do
    case "$arm" in
      same-path)
        want='the checkout path is IDENTICAL'
        out="$(assert_axes "$tmp/a" "$tmp/home-a" "$tmp/a" "$tmp/home-bbb" 2>&1)"; status=$? ;;
      same-cargo-home)
        want='CARGO_HOME is IDENTICAL'
        out="$(assert_axes "$tmp/a" "$tmp/home-a" "$tmp/bbbb" "$tmp/home-a" 2>&1)"; status=$? ;;
      symlinked-cargo-home)
        want='RESOLVE TO ONE DIRECTORY'
        rm -rf "$tmp/home-bbb/registry"
        ln -sfn "$tmp/home-a/registry" "$tmp/home-bbb/registry"
        out="$(assert_axes "$tmp/a" "$tmp/home-a" "$tmp/bbbb" "$tmp/home-bbb" 2>&1)"; status=$?
        rm -f "$tmp/home-bbb/registry"; mkdir -p "$tmp/home-bbb" ;;
      same-length-path)
        # Content differs, length does not — the substitution that exercises
        # the remap without exercising the size arithmetic (D135 §4 R1).
        want='NOT in length'
        mkdir -p "$tmp/same-length-a"
        out="$(assert_axes "$tmp/same-length-a" "$tmp/home-a" "$tmp/same-length-b" "$tmp/home-bbb" 2>&1)"; status=$? ;;
    esac
    if [ "$status" -eq 0 ]; then
      printf '::error:: the axis guard ACCEPTED the %s configuration — a comparison that varies nothing is green for the wrong reason\n' "$arm"; fail=1
    elif ! grep -q 'AXES NOT INDEPENDENT' <<<"$out"; then
      printf '::error:: the axis guard went red for the WRONG reason (%s):\n%s\n' "$arm" "$(head -3 <<<"$out")"; fail=1
    elif ! grep -qF "$want" <<<"$out"; then
      printf '::error:: the axis guard red for %s did not name its own cause (%s):\n%s\n' "$arm" "$want" "$out"; fail=1
    else
      printf '  planted fault: %-22s                -> RED (%s)\n' "$arm" "$want"
    fi
  done

  note "control arm: two genuinely different environments must be ACCEPTED"
  out="$(assert_axes "$tmp/a" "$tmp/home-a" "$tmp/bbbb" "$tmp/home-bbb" 2>&1)"; status=$?
  if [ "$status" -ne 0 ]; then
    printf '::error:: the axis guard REFUSED two genuinely different environments — it refuses everything, so its refusals say nothing:\n%s\n' "$out"; fail=1
  else
    printf '  control:       two distinct paths and cargo homes      -> ACCEPTED\n'
  fi

  [ "$fail" -eq 0 ] || return 1
  note "self-test PASS — the comparator and the axis guard each go red for their own reason, and neither is always red"
}

# ── building the second environment ────────────────────────────────────────
#
# The copy is of the WORKING TREE, not of a `git archive` export: an export
# cannot see an uncommitted edit, which is the state a developer running this
# locally is actually in (D135 §4 R6, R83's refused arm (c), same reasoning).
# The source set is git's own tracked-and-untracked-not-ignored list, which
# excludes `/target` and `.git` by construction, and a sha256 manifest of it is
# asserted identical on both sides — without that, a copy that silently dropped
# a file is indistinguishable from a copy that did not.
B_ROOT=""
cleanup_b() {
  [ -n "$B_ROOT" ] || return 0
  if [ "${ANTSEAL_REPRO_KEEP:-0}" = "1" ]; then
    printf '  ANTSEAL_REPRO_KEEP=1 — build B left at %s\n' "$B_ROOT"
    return 0
  fi
  rm -rf "$B_ROOT"
}

source_manifest() { # $1 = tree root, $2 = NUL-separated file list
  ( cd "$1" 2>/dev/null && xargs -0 -r sha256sum -- <"$2" 2>/dev/null ) |
    LC_ALL=C sort | sha256sum | cut -d' ' -f1
}

make_env_b() { # sets B_PATH, B_HOME; $1 = the NUL file list
  local list="$1" cargo_home_a
  cargo_home_a="${CARGO_HOME:-${HOME:-}/.cargo}"

  B_ROOT="$(mktemp -d "${ANTSEAL_REPRO_TMP:-${TMPDIR:-/tmp}}/antseal-repro.XXXXXXXX")" ||
    die "could not create build B's directory"
  B_PATH="${B_ROOT}/checkout"
  B_HOME="${B_ROOT}/cargo-home"
  # Both axes must differ in LENGTH as well as content, and that is made
  # STRUCTURAL here rather than assumed: if a temporary directory ever happens
  # to give a name the same length as this checkout's, the name grows until it
  # does not. assert_axes then re-checks it, so the guarantee has a witness.
  while [ "${#B_PATH}" -eq "${#repo}" ]; do B_PATH="${B_PATH}x"; done
  while [ "${#B_HOME}" -eq "${#cargo_home_a}" ]; do B_HOME="${B_HOME}x"; done
  mkdir -p "$B_PATH" "$B_HOME" || die "could not create build B's directories"

  assert_axes "$repo" "$cargo_home_a" "$B_PATH" "$B_HOME" || return 1

  local t0="$SECONDS"
  note "copy the working tree into build B (excluding /target and .git)"
  tar --null -T "$list" -cf - 2>/dev/null | tar -xf - -C "$B_PATH"
  [ "${PIPESTATUS[0]}" -eq 0 ] || die "the working-tree copy failed"

  local ma mb
  ma="$(source_manifest "$repo" "$list")"
  mb="$(source_manifest "$B_PATH" "$list")"
  if [ -z "$ma" ] || [ "$ma" != "$mb" ]; then
    printf '::error::reproducible-build: build B is NOT a copy of build A — the sha256 manifest of the\n' >&2
    printf '  tracked-and-untracked source set differs, so any comparison below would be over two different\n' >&2
    printf '  trees and would mean nothing (D135 §4 R6).\n    A: %s\n    B: %s\n' "${ma:-<empty>}" "${mb:-<empty>}" >&2
    return 1
  fi
  printf '  %s file(s) copied in %s s; source manifest identical on both sides: %s…\n' \
    "$(tr -cd '\0' <"$list" | wc -c)" "$(( SECONDS - t0 ))" "${ma:0:16}"

  # The axis under test is the PATH of $CARGO_HOME, not the provenance of the
  # crates in it, so copying is legitimate and keeps the build inside D63 §5
  # R5's no-network fence (D135 §5 R3). `cache` and `index` are copied and
  # `src` is not: cargo re-extracts sources from the `.crate` files, which is
  # cheaper than copying an extracted tree that is 6x larger. A SYMLINK here
  # would defeat the axis (D135 §4 R5) and assert_axes above refuses one.
  if [ -d "${cargo_home_a%/}/registry" ]; then
    t0="$SECONDS"
    note "copy the registry into build B's \$CARGO_HOME (never symlink it)"
    mkdir -p "${B_HOME}/registry"
    local part
    # MEASURED on this host 2026-08-15: 478 MB (364 cache + 114 index) in 60 s
    # idle and 153 s with three sibling lanes competing for the disk. That is
    # this machine's DEVELOPMENT registry — every crate of every project it has
    # ever built — and a CI runner's holds only this lock's dependencies, so
    # the remote figure is expected to be far smaller. D135 §12 item 3 makes
    # the first hosted run the thing that measures it; if it is the dominant
    # cost there, the ruled next step is a copy filtered to the crates
    # `Cargo.lock` names, NOT a symlink (§4 R5) and NOT a hardlink into a
    # registry three other lanes are reading. `--reflink=auto` is free on a
    # copy-on-write filesystem and silently a plain copy on ext4.
    for part in cache index; do
      [ -d "${cargo_home_a%/}/registry/${part}" ] || continue
      cp -a --reflink=auto "${cargo_home_a%/}/registry/${part}" "${B_HOME}/registry/" ||
        die "could not copy the registry ${part} into build B"
    done
    printf '  registry cache+index copied in %s s: %s\n' \
      "$(( SECONDS - t0 ))" "$(du -sh "${B_HOME}/registry" 2>/dev/null | cut -f1)"
  fi
  # Only the two axes may vary: a cargo config that shapes build A must shape
  # build B too, or a green would be a green over two different builds.
  [ -f "${cargo_home_a%/}/config.toml" ] && cp -a "${cargo_home_a%/}/config.toml" "${B_HOME}/"
  return 0
}

build_b() { # $1 = the commit to stamp
  local commit="$1" rc t0="$SECONDS"
  note "build B: wasm32 release from ${B_PATH} with CARGO_HOME=${B_HOME}"
  ( cd "$B_PATH" && CARGO_HOME="$B_HOME" ANTSEAL_SOURCE_COMMIT="$commit" \
      ./scripts/wasm-pack-build.sh --build-only ) 2>&1 | sed 's/^/    /'
  rc="${PIPESTATUS[0]}"
  printf '  build B: %s s\n' "$(( SECONDS - t0 ))"
  [ "$rc" -eq 0 ] || {
    printf '::error::reproducible-build: build B did not complete (exit %s) — this is a BUILD failure, not a\n' "$rc" >&2
    printf '  reproducibility failure; nothing was compared (D135 §8 R1).\n' >&2
    return 1
  }
  return 0
}

# The commit is resolved ONCE and handed to both builds. Build B's copy has no
# `.git`, so `wasm-pack-build.sh`'s own `git rev-parse HEAD` would stamp
# `unknown` there and the comparison would go RED ON A CORRECT BUILD — measured
# in this repository at D135 §1.5, where two commits produced modules of
# IDENTICAL SIZE and different digests with not one compile input changed.
# That is the first bug a naive implementation ships, and --plant-commit turns
# it into the planted regression.
head_commit() { git rev-parse HEAD 2>/dev/null || printf 'unknown'; }

# Build A is read ONCE, into a snapshot beside build B, and every comparison
# below is against that snapshot. Not defensive programming — MEASURED: on
# 2026-08-15, with three lanes sharing this working tree, a sibling's
# `wasm-pack-build.sh` ran its `rm -rf "$OUT"` while this comparison was in
# build B, and the comparison found build A's module GONE after two minutes of
# work. `pages.yml` has no such neighbour; a developer's machine does. The
# snapshot also sharpens the claim: A and B are then a pair taken from ONE
# instant, rather than an artifact read minutes after the sources it is
# compared against were copied.
A_SNAP=""
snapshot_a() {
  local f attempt
  A_SNAP="${B_ROOT}/A"
  mkdir -p "$A_SNAP" || return 1
  for attempt in 1 2; do
    for f in "$MODULE_NAME" "$GLUE_NAME"; do
      cp -a "${repo}/${OUT_REL}/${f}" "${A_SNAP}/${f}" 2>/dev/null
    done
    [ -f "${A_SNAP}/${MODULE_NAME}" ] && [ -f "${A_SNAP}/${GLUE_NAME}" ] && return 0
    note "build A's artifact was not readable (a concurrent build?) — rebuilding it once"
    ./scripts/wasm-pack-build.sh --build-only >/dev/null || return 1
  done
  printf '::error::reproducible-build: build A produced no readable artifact to compare against\n' >&2
  return 1
}

prepare() { # sets B_PATH/B_HOME/A_SNAP and ENV_*; $1 = commit
  local list
  ENV_COMMIT="$1"
  ENV_A_PATH="$repo"
  ENV_A_HOME="${CARGO_HOME:-${HOME:-}/.cargo}"

  if [ ! -f "${repo}/${OUT_REL}/${MODULE_NAME}" ]; then
    note "build A's artifact is absent — building it (normally the deploy has already done this)"
    ./scripts/wasm-pack-build.sh --build-only || return 1
  fi
  list="$(mktemp)" || die "no temporary file"
  git ls-files -co --exclude-standard -z >"$list" || { rm -f "$list"; die "git could not list the source set"; }
  [ -s "$list" ] || { rm -f "$list"; die "the source set is empty, so a copy of it would prove nothing"; }
  make_env_b "$list" || { rm -f "$list"; return 1; }
  rm -f "$list"
  snapshot_a || return 1
  ENV_B_PATH="$B_PATH"
  ENV_B_HOME="$B_HOME"
}

# ── telling THIS red from R83's, on the red path only (D135 §8) ───────────
#
# Guard 2 (`stale_guard`) owns "the packaged bytes are this tree's" and runs
# AFTER this comparison in `pages-publish.sh`. So a build A that predates an
# edit would surface HERE first, wearing this guard's token — three properties
# collapsing into two reds, which D135 §8 R1 exists to prevent.
#
# In `pages.yml` it cannot happen: build A runs two steps earlier in the same
# job. Locally it happens easily, and this project measured it happening twice
# in one hour on 2026-08-15 while three lanes shared one working tree. So on a
# red — and only on a red, where a relink costs nothing anybody is waiting for —
# build A is rebuilt and re-digested. If A moved, the red was STALENESS and this
# says so in R83's vocabulary rather than claiming irreproducibility.
attribute_red() { # $1 = build A's digest as compared
  local before="$1" after
  ./scripts/wasm-pack-build.sh --build-only >/dev/null 2>&1 || {
    printf '::error::reproducible-build: build A could not be rebuilt, so the red above cannot be attributed\n' >&2
    return 1
  }
  after="$(digest "${repo}/${OUT_REL}/${MODULE_NAME}")"
  [ "$before" = "$after" ] && return 0
  printf '::error::reproducible-build: …and that red is NOT this guard'"'"'s property. Build A'"'"'s artifact was\n' >&2
  printf '  STALE — rebuilding it from this tree just now changed it (%s -> %s), so the two builds were\n' \
    "${before:0:16}…" "${after:0:16}…" >&2
  printf '  compared over two different SOURCE states, not two environments. That is R83'"'"'s property\n' >&2
  printf '  (`STALE ARTIFACT`), not reproducibility. Re-run: `scripts/wasm-pack-build.sh --check` and then\n' >&2
  printf '  this comparison. In pages.yml this cannot occur — build A runs two steps earlier in the job.\n' >&2
  return 0
}

cmd_compare() {
  local started="$SECONDS" commit a_digest
  cmd_self_test || return 1
  commit="$(head_commit)"
  note "the commit both builds stamp: ${commit}"
  trap cleanup_b EXIT
  prepare "$commit" || return 1
  a_digest="$(digest "${A_SNAP}/${MODULE_NAME}")"
  build_b "$commit" || return 1
  note "compare the two environments' artifacts (R86 Accept row 1)"
  if ! compare_artifacts "$A_SNAP" "${B_PATH}/${OUT_REL}"; then
    attribute_red "$a_digest"
    return 1
  fi
  printf '  two-environment comparison: %s s\n' "$(( SECONDS - started ))"
}

# ── the expensive plant, LOCAL ONLY, never on a metered runner (§7 R3) ─────
#
# R86's own Accept row 3 names a different plant — "the remap flag removed from
# one of the two builds" — and D135 §7 R1 measured that it CANNOT WORK:
# `check_build_paths` runs in both `--check` and `--build-only` and scans for
# `$repo`, `$CARGO_HOME`, `/home/`, `/Users/` and `/root/`, so an un-remapped
# build reds UPSTREAM at the path scan with the path-scan message, and this
# comparison is never reached and never shown to be fallible. That plant proves
# the wrong check. The plant below is the ruled one, and this repository's own
# history already proves it works: `08c074c` and `9317a35` differ in no compile
# input, produce modules of identical size, and produce different digests.
#
# The pre-image assertion is Q234's lesson: the same tree is compared GREEN
# first, so a red afterwards is caused by the plant and not by a tree that was
# already broken. The second build re-uses build B's tree and target directory,
# so only `crates/antseal-wasm` recompiles — `cargo::rerun-if-env-changed`
# forces exactly that and nothing else.
cmd_plant_commit() {
  local commit planted out status fail=0 t0
  cmd_self_test || return 1
  commit="$(head_commit)"
  [ "$commit" != "unknown" ] || die "this tree has no git commit, so there is no 40-hex stamp to perturb"
  case "${commit: -1}" in 0) planted="${commit:0:39}1" ;; *) planted="${commit:0:39}0" ;; esac
  [ "$planted" != "$commit" ] || die "the plant did not change the commit"

  trap cleanup_b EXIT
  prepare "$commit" || return 1

  note "PRE-IMAGE: build B at the true commit must be GREEN before the plant means anything"
  t0="$SECONDS"
  build_b "$commit" || return 1
  out="$(compare_artifacts "$A_SNAP" "${B_PATH}/${OUT_REL}" 2>&1)"; status=$?
  printf '%s\n' "$out" | sed 's/^/    /'
  if [ "$status" -ne 0 ]; then
    printf '::error:: the pre-image comparison is already RED, so the plant below would prove nothing (Q234)\n'
    return 1
  fi
  printf '  pre-image GREEN in %s s\n' "$(( SECONDS - t0 ))"

  note "PLANT: rebuild B with the commit's last hex character changed (${commit: -8} -> ${planted: -8})"
  t0="$SECONDS"
  build_b "$planted" || return 1
  out="$(compare_artifacts "$A_SNAP" "${B_PATH}/${OUT_REL}" 2>&1)"; status=$?
  printf '%s\n' "$out" | sed 's/^/    /'
  if [ "$status" -eq 0 ]; then
    printf '::error:: the comparison stayed GREEN with a DIFFERENT commit stamped into build B — it is not comparing the bytes\n'; fail=1
  elif ! grep -q 'NOT REPRODUCIBLE' <<<"$out"; then
    printf '::error:: the comparison went red for the WRONG reason:\n%s\n' "$(head -3 <<<"$out")"; fail=1
  elif [ "$(grep -oE '\b[0-9a-f]{64}\b' <<<"$out" | sort -u | wc -l)" -lt 3 ]; then
    printf '::error:: the red did not name both digests (R86 Accept row 1; D135 §6 R1)\n'; fail=1
  else
    printf '  planted regression: ANTSEAL_SOURCE_COMMIT differs by one hex character -> RED (NOT REPRODUCIBLE, both digests printed), %s s\n' \
      "$(( SECONDS - t0 ))"
  fi
  [ "$fail" -eq 0 ] || return 1
  note "plant PASS — the two-environment comparison goes red for its own reason, verified by its message"
}

cmd_help() {
  sed -n '2,8p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
  printf '\ntier: %s\n' "$REPRO_TIER"
}

case "${1:---compare}" in
  --compare | "") cmd_compare ;;
  --self-test)    cmd_self_test ;;
  --plant-commit) cmd_plant_commit ;;
  --help | -h)    cmd_help ;;
  *) die "usage: scripts/reproducible-build.sh [--compare | --self-test | --plant-commit | --help]" ;;
esac
