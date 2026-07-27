#!/usr/bin/env bash
# P2 — crates.io name reservation for the antseal crate family.
#
# Runbook (READ FIRST): docs/naming/P2-crates-reservation-runbook.md
# Blocked on: D1-final (docs/decisions/D1-product-name.md) + `cargo login`.
#
# What it does, per crate (antseal, antseal-core, antseal-anchor,
# antseal-net, antseal-cli), in publish order:
#   1. re-verifies availability via the crates.io API (with a proper
#      User-Agent) — 404 = free, 200 = taken;
#   2. generates a minimal 0.0.0 placeholder crate in a temp dir
#      (empty lib, description/license/repository metadata only);
#   3. `cargo publish --dry-run` (DEFAULT — no upload, no auth needed), or
#      the real `cargo publish` ONLY with --execute + typed confirmation.
#
# PERMANENCE WARNING: a real publish claims the name FOREVER. crates.io has
# no un-publish; yank hides a version but keeps the name claimed. Never run
# --execute until D1 is final.
#
# Default mode (dry-run) is safe to run any time and MUST be green before
# --execute is ever attempted.

set -euo pipefail

# ── Constants ───────────────────────────────────────────────────────────────
# Publish order: bare product name first (most squat-attractive), then the
# member crates in spec-tree order.
CRATES=(antseal antseal-core antseal-anchor antseal-net antseal-cli)
VERSION="0.0.0"
DESCRIPTION="Reserved name for the antseal project (pre-M0 placeholder — see repo)"
# D6 (docs/decisions/D6-license.md): own-code license for ALL five —
# placeholders contain only our own empty lib and no ant-core dependency,
# so the GPL-3.0 distribution effect on net/cli does not attach to them.
LICENSE="MIT OR Apache-2.0"
REPOSITORY="https://github.com/aed900/antseal"
USER_AGENT="antseal-setup (+https://github.com/aed900/antseal)"
API="https://crates.io/api/v1/crates"
# Pause between real publishes (crates.io rate-limits new-crate publishes).
PUBLISH_PAUSE_SECS=30

usage() {
    cat <<'EOF'
usage: reserve-crates.sh [--execute]

Default: availability re-check + `cargo publish --dry-run` for all five
antseal crates (safe, no upload, no login required).

--execute   REALLY publish the 0.0.0 placeholders (PERMANENT — claims the
            names forever). Requires: D1 final, `cargo login` done, and a
            typed confirmation at the prompt.
EOF
}

EXECUTE=0
for arg in "$@"; do
    case "$arg" in
        --execute) EXECUTE=1 ;;
        -h | --help)
            usage
            exit 0
            ;;
        *)
            echo "error: unknown argument: $arg" >&2
            usage >&2
            exit 2
            ;;
    esac
done

command -v curl >/dev/null || {
    echo "error: curl is required" >&2
    exit 1
}
command -v cargo >/dev/null || {
    echo "error: cargo is required" >&2
    exit 1
}

# ── Availability check ──────────────────────────────────────────────────────
# Prints the HTTP status; 404 = free, 200 = taken, anything else = network
# trouble or API change (treated as indeterminate — never publish on it).
check_availability() {
    local name="$1"
    curl -sS -o /dev/null -w '%{http_code}' -A "$USER_AGENT" "$API/$name" \
        || echo "000"
}

# ── Placeholder generation ──────────────────────────────────────────────────
# Standalone crates OUTSIDE the workspace: edition 2021 on purpose so they
# build on any ambient toolchain (see D4 note); the placeholders are
# metadata-only and are superseded by real publishes from the workspace.
make_placeholder() {
    local name="$1" dir="$2"
    mkdir -p "$dir/src"
    cat >"$dir/Cargo.toml" <<EOF
[package]
name = "$name"
version = "$VERSION"
edition = "2021"
description = "$DESCRIPTION"
license = "$LICENSE"
repository = "$REPOSITORY"
EOF
    cat >"$dir/src/lib.rs" <<EOF
//! $DESCRIPTION
//!
//! This crate name is reserved for the antseal project (proof-of-existence
//! with selective disclosure on Autonomi). See the repository for status.
EOF
}

# ── Confirmation gate (real publishes only) ─────────────────────────────────
if [ "$EXECUTE" -eq 1 ]; then
    cat <<EOF

  *** REAL PUBLISH MODE ***

  This will PERMANENTLY claim the following crates.io names under the
  currently `cargo login`-ed account:

$(printf '      %s\n' "${CRATES[@]}")

  crates.io publishes are FOREVER (yank hides a version but the name stays
  claimed). Prerequisites you are confirming:
    - D1 is FINAL (docs/decisions/D1-product-name.md updated)
    - You are logged in as the intended MAINTAINER account (cargo login)

EOF
    printf '  Type exactly "publish-forever" to proceed: '
    read -r reply
    if [ "$reply" != "publish-forever" ]; then
        echo "aborted (no publish performed)."
        exit 1
    fi
fi

# ── Main loop ───────────────────────────────────────────────────────────────
workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT

declare -a results=()
failures=0

for name in "${CRATES[@]}"; do
    echo ""
    echo "== $name =="

    status="$(check_availability "$name")"
    case "$status" in
        404) echo "   availability: FREE (HTTP 404)" ;;
        200)
            echo "   availability: TAKEN (HTTP 200)" >&2
            if [ "$EXECUTE" -eq 1 ]; then
                # Allows re-running after a partial publish run — but demands
                # a human ownership check either way.
                echo "   SKIPPING publish. Verify on https://crates.io/crates/$name" >&2
                echo "   whether the owner is the maintainer account (earlier run of" >&2
                echo "   this script) — if it is NOT, STOP: this feeds back into P1" >&2
                echo "   as a forced re-decision (squatted name)." >&2
                results+=("$name: TAKEN — skipped, ownership check required")
                failures=$((failures + 1))
                continue
            else
                results+=("$name: TAKEN — P1 feedback required if not owned by maintainer")
                failures=$((failures + 1))
                continue
            fi
            ;;
        *)
            echo "   availability: INDETERMINATE (HTTP $status) — refusing to proceed for this crate" >&2
            results+=("$name: availability check failed (HTTP $status)")
            failures=$((failures + 1))
            continue
            ;;
    esac

    dir="$workdir/$name"
    make_placeholder "$name" "$dir"

    if [ "$EXECUTE" -eq 1 ]; then
        echo "   publishing $name@$VERSION (REAL) ..."
        (cd "$dir" && cargo publish)
        results+=("$name: PUBLISHED $VERSION")
        # Be gentle with the registry between new-crate publishes.
        if [ "$name" != "${CRATES[-1]}" ]; then
            echo "   sleeping ${PUBLISH_PAUSE_SECS}s (publish rate limits) ..."
            sleep "$PUBLISH_PAUSE_SECS"
        fi
    else
        echo "   cargo publish --dry-run ..."
        if (cd "$dir" && cargo publish --dry-run); then
            results+=("$name: FREE, dry-run OK")
        else
            results+=("$name: FREE, dry-run FAILED")
            failures=$((failures + 1))
        fi
    fi
done

echo ""
echo "── Summary ─────────────────────────────────────────────────────────────"
printf '   %s\n' "${results[@]}"
if [ "$failures" -gt 0 ]; then
    echo "   RESULT: $failures problem(s) — see above."
    exit 1
fi
if [ "$EXECUTE" -eq 1 ]; then
    echo "   RESULT: all names published. Record versions + date in the P2"
    echo "   runbook and verify ownership on crates.io (P2 acceptance)."
else
    echo "   RESULT: all names free; all dry-runs green. Safe to --execute"
    echo "   once D1 is final and cargo login is done."
fi
