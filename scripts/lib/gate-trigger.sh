# shellcheck shell=bash
# The diff computation behind every diff-triggered gate lane. SOURCED, never
# run — it defines two functions and does nothing else.
#
# ── Why this file exists (Q128) ────────────────────────────────────────────
#
# `scripts/gate-features.sh --needs-heavy` (S22/Q84) and
# `scripts/wasm-tests.sh --needs-run` (Q125) each carry their own copy of the
# same eighteen lines, and `wasm-tests.sh` wrote down the condition for
# stopping:
#
#     "Deliberately a second copy rather than a shared helper — this list
#      answers 'can wasm32 behaviour move?', which is a different question
#      from 'did the storage path change?' [...] If a third trigger appears,
#      factor the diff computation out then, not now."
#
# Q128 is that third trigger. Note precisely what is and is not shared: the
# LISTS stay in their own scripts, because that is the part that answers a
# different question per lane and that each script's `--self-test` plants
# change-sets against. What moves here is the part that is the SAME question
# every time — "which paths does this change-set touch, and does the base ref
# even exist?" — and which no self-test anywhere has ever covered, in any of
# its copies.
#
# The factoring is output-identical for both existing callers, by
# construction: `<subject>: <hits>` and `no <subject> path changed vs <base>`
# reproduce `wasm-tests.sh`'s "wasm32-relevant" and `gate-features.sh`'s
# "storage-touching" strings exactly. That was a design constraint, not a
# coincidence — a factoring that changed a gate line's wording would make
# every reader re-verify what the gate now means.
#
# STILL A THIRD COPY: `scripts/gate-features.sh`. Not converted at Q128 only
# because that file belonged to a concurrent lane; the conversion is
# `needs_heavy() { gate_needs_run "$HEAVY_TRIGGER_PATHS" storage-touching
# ANTSEAL_GATE_HEAVY; }` and nothing else. Until it happens the tree has two
# implementations, not one, and this comment is the record of that.
#
# ── The contract every caller shares ───────────────────────────────────────
#
#   0  run the lane      1  n/a for this change      2  cannot decide
#
# 2 is never a silent pass: `local-gate.sh` renders it as a visible SKIP with
# the reason. That distinction is the whole reason this is a tri-state and
# not a boolean.

# Print the paths a caller's pattern list matches. Reads candidates on stdin.
#
# `grep -F -f`: fixed strings, unanchored, so an entry is a SUBSTRING test and
# a trailing slash makes it a directory prefix. Two consequences every caller
# must know:
#
#   * a blank line in the list matches EVERY input line, which turns the
#     trigger into the constant `true` and the `n/a` state into a lie. Every
#     caller's self-test owes an anti-vacuity arm for exactly this;
#   * because it is unanchored, `Cargo.toml` matches every member manifest in
#     the workspace, not just the root one. That is deliberate over-selection
#     — running a lane too often is a cost, running it too rarely is a hole.
#
# `|| true` because grep exits 1 on "no lines selected", which is a normal
# answer here and not an error.
gate_trigger_hits() {
  grep -F -f <(printf '%s\n' "$1") || true
}

# gate_needs_run <newline-separated-patterns> <subject> <force-var-name>
#
# Decides whether a change-set selects a lane. Prints one line of reason on
# every path, because a gate that says `n/a` without saying why is a gate
# nobody can audit.
gate_needs_run() {
  local patterns="$1" subject="$2" forcevar="$3"
  local base="${ANTSEAL_GATE_BASE:-main}" changed hits

  if ! git rev-parse --verify --quiet "$base" >/dev/null; then
    printf 'cannot decide: no `%s` ref to diff against (set ANTSEAL_GATE_BASE, or %s=1/0 to force)\n' \
      "$base" "$forcevar"
    return 2
  fi

  # Committed-since-base UNION uncommitted. Both halves are load-bearing:
  # the gate runs before a merge, so the branch's committed work counts, and
  # a dirty tree is the normal state when a contributor runs it. `...` is the
  # merge base, so an unrelated advance of `main` does not enlarge the
  # change-set. On `main` itself the first half is empty by definition and
  # the predicate reduces to the working tree, which is correct: there is
  # nothing else to compare against.
  changed="$( { git diff --name-only "$base"...HEAD; git status --porcelain | cut -c4-; } | sort -u )"
  hits="$(gate_trigger_hits "$patterns" <<<"$changed")"

  if [ -n "$hits" ]; then
    # Parameter expansion, not `| tr '\n' ' '`: a herestring appends a newline
    # and so would add a trailing space that neither caller's line had before
    # Q128. Output-identical was a design constraint here, and a diff of one
    # invisible character is exactly the kind that gets waved through.
    printf '%s: %s\n' "$subject" "${hits//$'\n'/ }"
    return 0
  fi
  printf 'no %s path changed vs %s\n' "$subject" "$base"
  return 1
}
