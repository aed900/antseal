#!/usr/bin/env bash
# S22 — the required gate's feature policy.
#
# THE PROBLEM (recorded when S5 landed): `scripts/local-gate.sh` used to run
# `cargo clippy --workspace --all-targets --all-features` and
# `cargo test --workspace --all-features`. Since P16 landed
# `devnet-launcher/devnet` and S5 landed `antseal-net/ant-backend`,
# `--all-features` drags the whole upstream stack — 120 packages default vs
# **475** with the devnet feature on, measured by `ci-lanes.sh dep-graph` —
# into the *required* gate that the containment design deliberately keeps out
# of the default lanes. A minutes-long gate became a tens-of-minutes gate for
# every change, including a docs-only one, on a 2-core host.
#
# THE POLICY (three tiers; CONTRIBUTING "Gate feature policy" states it for
# contributors, and the reasoning is in tasks/S.md S22):
#
#   Tier 1 — ALWAYS, required, minutes.  Every LIGHT feature, i.e. every
#            declared workspace feature that is not on the HEAVY list. Run by
#            local-gate.sh's own clippy/test lines.
#   Tier 2 — WHEN TOUCHED, required, tens of minutes.  The HEAVY feature
#            paths, compiled and tested per package (`--heavy` below).
#            Triggered by the same storage-touching path list as the D52
#            devnet E2E gate.
#   Tier 3 — the devnet E2E gate itself (scripts/e2e-devnet.sh, Q15/D52).
#
# WHY NOT JUST KEEP `--all-features`: it costs the most and proves the least.
# `--all-features` compiles the UNION of features, which is not the same as
# compiling each feature configuration — workspace feature unification can
# hide a package that does not build with only its own feature enabled, which
# is the shape a consumer actually gets. Tier 2 compiles the heavy paths
# per package, which is both cheaper when it runs and a stricter statement.
#
# WHY NOT LET `ci-lanes.sh dep-graph` STAND IN FOR THE HEAVY TIER: it cannot.
# dep-graph reads `cargo tree`/`cargo metadata` — it proves the heavy graph
# stays OUT of the default build (P20 rule 1), which is a containment claim
# about the dependency graph. It never compiles a line of the feature-gated
# code, so it cannot see a feature-gated path that no longer builds. The two
# are complementary: dep-graph is the cheap always-on boundary check, tier 2
# is the compile.
#
# THE ROT THIS SCRIPT EXISTS TO PREVENT: dropping `--all-features` means the
# gate now names its features, and a NEW feature added later would be
# compiled by no tier at all — the exact "feature-gated code path no required
# lane ever compiles" risk that made keeping `--all-features` tempting. So
# `--check-partition` (seconds, every gate) requires every feature declared
# by every workspace member to be classified LIGHT or HEAVY, and requires
# local-gate.sh's declared list to equal the computed LIGHT union. A new
# feature fails the gate until someone classifies it.
#
# Usage:
#   scripts/gate-features.sh --check-partition   classify-everything guard
#   scripts/gate-features.sh --light-union       the tier-1 feature list
#   scripts/gate-features.sh --needs-heavy       0 = yes, 1 = no, 2 = undecidable
#   scripts/gate-features.sh --heavy             run tier 2
#   scripts/gate-features.sh --self-test         prove the guard can go red
set -uo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo" || exit 1

note() { printf '\033[36m==>\033[0m %s\n' "$*"; }
die()  { printf '\033[31m::error::gate-features: %s\033[0m\n' "$*" >&2; exit 1; }

# ── The classification ────────────────────────────────────────────────────
#
# HEAVY = activating it pulls the upstream ant-core/ant-node/EVM graph. These
# are exactly the features `ci-lanes.sh dep-graph` (P20 rule 1) asserts stay
# out of the default build, and exactly the ones whose Cargo.toml comments
# say "NON-DEFAULT, deliberately (containment rule)".
#
# `default` is excluded from the partition on both sides: it is not a feature
# a tier has to opt into — tier 1 compiles it by definition — and both
# declarations of it in this workspace are empty.
HEAVY_FEATURES='antseal-cli/ant-backend
antseal-net/ant-backend
devnet-launcher/devnet'

# Tier 2, per package. The launcher is a binary with no tests, so `test` on
# it is a compile; it is still run through `cargo test` so a future test
# target is picked up without editing this list.
HEAVY_LANES='antseal-net ant-backend
antseal-cli ant-backend
devnet-launcher devnet'

# Tier 2's trigger. Same list as CONTRIBUTING's "Devnet E2E gate", because
# the two gates guard the same surface: if a change can break the storage
# path, it must both compile the feature paths and run the devnet E2E.
HEAVY_TRIGGER_PATHS='crates/antseal-net/
crates/antseal-cli/src/pipeline/
crates/antseal-cli/src/vault/wallet.rs
crates/devnet-launcher/
scripts/devnet/
scripts/e2e-devnet.sh
Cargo.toml
Cargo.lock'

declared_features() {
  # `<package>/<feature>` for every feature every workspace member declares.
  # --no-deps: workspace members only, no resolution needed.
  #
  # GATE_FEATURES_EXTRA is `--self-test`'s ONLY injection point, and it exists
  # because the one case this guard is built for — a crate declaring a NEW
  # feature — lives in a Cargo.toml and so cannot be simulated by patching a
  # copy of this script the way the other planted faults are.
  { cargo metadata --format-version 1 --no-deps --locked 2>/dev/null | python3 -c '
import json,sys
m = json.load(sys.stdin)
for p in m["packages"]:
    for f in p["features"]:
        if f != "default":
            print(p["name"] + "/" + f)
'
    [ -n "${GATE_FEATURES_EXTRA:-}" ] && printf '%s\n' "$GATE_FEATURES_EXTRA"
  } | grep -v '^$' | sort
}

light_union() {
  declared_features | grep -vxF -f <(printf '%s\n' "$HEAVY_FEATURES") | paste -sd, -
}

# The declaration local-gate.sh carries, so the two cannot drift silently.
# GATE_LOCAL_GATE points this at a patched copy for `--self-test`; the real
# gate file is the default, and the parse under test is the real one.
gate_declared_light() {
  sed -nE "s/^GATE_LIGHT_FEATURES='([^']*)'.*/\1/p" "${GATE_LOCAL_GATE:-$repo/scripts/local-gate.sh}"
}

check_partition() {
  local declared light gate_light unclassified
  declared="$(declared_features)"
  [ -n "$declared" ] || { printf '::error::gate-features: cargo metadata returned NO features at all — the extractor is broken, so a green verdict here would mean nothing\n'; return 1; }
  # Anti-vacuity: the heavy list names features that must actually exist.
  local missing
  missing="$(printf '%s\n' "$HEAVY_FEATURES" | grep -vxF -f <(printf '%s\n' "$declared") || true)"
  if [ -n "$missing" ]; then
    printf '::error::gate-features: the HEAVY list names feature(s) no workspace crate declares any more:\n%s\nA heavy feature that vanished means tier 2 is compiling nothing; re-derive the list.\n' "$missing"
    return 1
  fi
  # The guard that replaces `--all-features`: tier 1's feature list is a
  # LITERAL in local-gate.sh, so it must equal the computed LIGHT union
  # exactly. The two directions are different bugs and get different
  # messages — a feature no tier compiles is the risk that made keeping
  # `--all-features` tempting, and a stale gate entry is how the list starts
  # meaning less than it says.
  light="$(light_union)"
  gate_light="$(gate_declared_light)"
  if [ "$light" != "$gate_light" ]; then
    local uncompiled stale
    uncompiled="$(comm -23 <(printf '%s' "$light" | tr ',' '\n' | sort) \
                           <(printf '%s' "$gate_light" | tr ',' '\n' | sort))"
    stale="$(comm -13 <(printf '%s' "$light" | tr ',' '\n' | sort) \
                      <(printf '%s' "$gate_light" | tr ',' '\n' | sort))"
    if [ -n "$uncompiled" ]; then
      printf '::error::gate-features: feature(s) NO tier compiles:\n%s\nClassify each one: add it to GATE_LIGHT_FEATURES in scripts/local-gate.sh (tier 1, always), or to HEAVY_FEATURES + HEAVY_LANES here (tier 2, when touched). Dropping --all-features is only safe while every declared feature has a tier.\n' "$uncompiled"
    fi
    if [ -n "$stale" ]; then
      printf '::error::gate-features: GATE_LIGHT_FEATURES names feature(s) no workspace crate declares any more:\n%s\nDelete them — a gate line that lists features that do not exist stops being a statement about the tree.\n' "$stale"
    fi
    printf '  gate:     %s\n  computed: %s\n' "${gate_light:-<no GATE_LIGHT_FEATURES line found>}" "$light"
    return 1
  fi
  printf 'OK: %s declared feature(s); tier 1 compiles [%s], tier 2 compiles [%s].\n' \
    "$(printf '%s\n' "$declared" | grep -c .)" "$light" "$(printf '%s' "$HEAVY_FEATURES" | tr '\n' ',')"
}

needs_heavy() {
  local base="${ANTSEAL_GATE_BASE:-main}" changed
  if ! git rev-parse --verify --quiet "$base" >/dev/null; then
    printf 'cannot decide: no `%s` ref to diff against (set ANTSEAL_GATE_BASE, or ANTSEAL_GATE_HEAVY=1/0 to force)\n' "$base"
    return 2
  fi
  # Committed-since-base AND uncommitted: the gate runs before a merge, and
  # a dirty tree is the normal state when it does.
  changed="$( { git diff --name-only "$base"...HEAD; git status --porcelain | cut -c4-; } | sort -u )"
  local hits
  hits="$(printf '%s\n' "$changed" | grep -F -f <(printf '%s\n' "$HEAVY_TRIGGER_PATHS") || true)"
  if [ -n "$hits" ]; then
    printf 'storage-touching: %s\n' "$(printf '%s' "$hits" | tr '\n' ' ')"
    return 0
  fi
  printf 'no storage-touching path changed vs %s\n' "$base"
  return 1
}

run_heavy() {
  local fail=0 pkg feat
  while read -r pkg feat; do
    [ -n "${pkg:-}" ] || continue
    note "tier 2: $pkg --features $feat"
    if ! cargo clippy -p "$pkg" --features "$feat" --all-targets --locked -- -D warnings; then
      printf '::error::gate-features: clippy failed for %s --features %s\n' "$pkg" "$feat"; fail=1; continue
    fi
    # The devnet-gated tests inside these suites skip themselves without
    # ANTSEAL_DEVNET_ENV (docs/devnet/local-devnet.md); running them here
    # still compiles every one of them, which is the point of the tier.
    if ! cargo test -p "$pkg" --features "$feat" --locked; then
      printf '::error::gate-features: tests failed for %s --features %s\n' "$pkg" "$feat"; fail=1
    fi
  done <<EOF
$HEAVY_LANES
EOF
  [ "$fail" -eq 0 ] || return 1
  note "tier 2 PASS — every heavy feature path compiles and its tests pass"
}

# ── Test-of-the-test ──────────────────────────────────────────────────────
#
# The partition guard is the whole safety argument for dropping
# --all-features, so it gets the house treatment: planted faults first, both
# directions, before any green verdict is trusted.
self_test() {
  local copy="$repo/scripts/.gate-features-selftest.sh" gatecopy out fail=0
  trap 'rm -f "$copy"' RETURN

  # 1. THE case this guard exists for: a crate declares a NEW feature, and no
  #    tier compiles it. Injected through declared_features' documented seam
  #    because the real thing lives in a Cargo.toml.
  out="$(GATE_FEATURES_EXTRA='antseal-core/brand-new' check_partition 2>&1)"
  if [ $? -eq 0 ] || ! printf '%s' "$out" | grep -q 'NO tier compiles' \
     || ! printf '%s' "$out" | grep -q 'antseal-core/brand-new'; then
    printf '::error:: a newly declared feature did NOT turn the guard red (this is the whole safety argument for dropping --all-features):\n%s\n' "$out"; fail=1
  else
    printf '  planted fault: %-44s -> RED\n' "a new feature no tier compiles"
  fi

  # 2. A heavy entry naming a feature nobody declares (the anti-vacuity
  #    direction: tier 2 silently compiling nothing).
  sed 's|^antseal-net/ant-backend$|antseal-net/ant-backend-typo|' "$repo/scripts/gate-features.sh" > "$copy"
  out="$(bash "$copy" --check-partition 2>&1)"
  if [ $? -eq 0 ] || ! printf '%s' "$out" | grep -q 'no workspace crate declares'; then
    printf '::error:: a HEAVY entry naming a nonexistent feature did NOT turn the guard red:\n%s\n' "$out"; fail=1
  else
    printf '  planted fault: %-44s -> RED\n' "a HEAVY entry for a feature that is gone"
  fi
  rm -f "$copy"

  # 3. A STALE entry on the gate line — a feature that no longer exists.
  #    The mirror of fault 1, and the direction that makes the gate line
  #    stop being a statement about the tree.
  gatecopy="$(mktemp)"
  sed "s|^GATE_LIGHT_FEATURES='\(.*\)'|GATE_LIGHT_FEATURES='\1,antseal-core/removed-feature'|" \
    "$repo/scripts/local-gate.sh" > "$gatecopy"
  out="$(GATE_LOCAL_GATE="$gatecopy" check_partition 2>&1)"
  if [ $? -eq 0 ] || ! printf '%s' "$out" | grep -q 'GATE_LIGHT_FEATURES names' \
     || ! printf '%s' "$out" | grep -q 'antseal-core/removed-feature'; then
    printf '::error:: a stale GATE_LIGHT_FEATURES entry did NOT turn the guard red:\n%s\n' "$out"; fail=1
  else
    printf '  planted fault: %-44s -> RED\n' "a stale entry on the gate line"
  fi

  # 4. The gate line deleted outright (a revert to --all-features, or a
  #    careless edit): every light feature is then compiled by no tier.
  sed '/^GATE_LIGHT_FEATURES=/d' "$repo/scripts/local-gate.sh" > "$gatecopy"
  out="$(GATE_LOCAL_GATE="$gatecopy" check_partition 2>&1)"
  if [ $? -eq 0 ] || ! printf '%s' "$out" | grep -q 'NO tier compiles'; then
    printf '::error:: a MISSING GATE_LIGHT_FEATURES line did NOT turn the guard red:\n%s\n' "$out"; fail=1
  else
    printf '  planted fault: %-44s -> RED\n' "the gate line deleted outright"
  fi
  rm -f "$gatecopy"

  # Control.
  out="$(check_partition 2>&1)"
  if [ $? -ne 0 ]; then
    printf '::error:: the committed classification does not validate; nothing above means anything:\n%s\n' "$out"; fail=1
  fi
  printf '  control (committed classification)%22s -> %s\n' '' "$(printf '%s' "$out" | tail -1)"
  [ "$fail" -eq 0 ] || return 1
  note "gate-features self-test PASS"
}

case "${1:---check-partition}" in
  --check-partition) check_partition ;;
  --light-union)     light_union ;;
  --needs-heavy)     needs_heavy ;;
  --heavy)           run_heavy ;;
  --self-test)       self_test ;;
  *) die "usage: scripts/gate-features.sh [--check-partition|--light-union|--needs-heavy|--heavy|--self-test]" ;;
esac
