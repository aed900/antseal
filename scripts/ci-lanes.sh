#!/usr/bin/env bash
# The CI lanes that used to be inline YAML shell (task Q43).
#
# One entry point per lane, so CI and a contributor run the SAME bytes and a
# malformed command is caught before it is pushed. The two CI-logic defects
# this project has had were both in inline `run:` blocks; the lanes that call
# `scripts/vector-freeze.sh`, `scripts/cross-check.sh`, `scripts/fuzz.sh` and
# `scripts/check-traceability.py` were green on their first remote run.
#
# Usage:
#   scripts/ci-lanes.sh <lane> [args]
#   scripts/ci-lanes.sh --list          every lane this script owns
#
# Lanes:
#   dep-graph         antseal-core's normal deps stay I/O-free
#   cross-os          the cross-platform-sensitive suites (allowed-empty)
#   golden-vectors    the golden-vector suite (must NOT be empty)
#   tamper-matrix     the tamper harness, registry and Q8 completeness
#   cbor-drift-guard  the two implementations of the rendering table agree
#   traceability      self-test, then the two documented-claim checks
#   ci-shell          self-test, then Q43's own guard over every workflow
#   secret-guard      self-test, then the vault-export/wallet-key scan
#   audit-deny        cargo-deny advisories/bans/sources
#
# Exit: 0 pass · 1 failure. Every lane is runnable locally; the ones that
# need a pinned external tool say which and how (audit-deny).
#
# ── Why the `matched=` counters exist, and why they are here ───────────────
#
# Three lanes select tests by libtest FILTER, not by an explicit list. A
# filter that matches nothing exits 0, so a green lane would assert nothing —
# the counters turn "no evidence" into a visible outcome (a hard error where
# the suite must be non-empty, a notice where it is allowed-empty by design).
#
# Q8 introduced one of them with `--list` passed to *cargo* instead of to the
# test binary after `--`. Cargo rejects the flag, the count came out empty,
# and the guard did exactly what it was built for: it refused to report
# success from a check that produced no evidence. The defect was that the
# GUARD'S OWN COMMAND had never been executed — the lane sat 182 commits
# behind and `scripts/local-gate.sh` runs four lanes to CI's eighteen. Having
# the command here is what makes it executable without a push.
set -uo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo" || exit 1

note() { printf '\033[36m==>\033[0m %s\n' "$*"; }
die()  { printf '\033[31m::error::ci-lanes: %s\033[0m\n' "$*" >&2; exit 1; }

LANES="dep-graph cross-os golden-vectors tamper-matrix cbor-drift-guard traceability ci-shell secret-guard audit-deny"

# Count the tests a libtest filter actually selects.
#
#   count_matched <cargo args...> [-- <libtest filter args...>]
#
# `--list` MUST reach the test binary, i.e. AFTER `--`; cargo rejects it as
# one of its own options. That is the Q8 defect, and `--self-test` below puts
# it back and requires the lane to go red.
#
# The caller's own `--` is *split out and re-emitted*, never appended to.
# Writing this as a bare `cargo test "$@" -- --list` produced `-- vector_ --
# --list` for the filtered lanes — two separators, a filter libtest never
# saw, and a count of 0 that would have turned `golden-vectors` red. Caught
# by running the lane locally, which is the entire point of Q43.
count_matched() {
  local cargo_args=() filter=() a seen=0
  for a in "$@"; do
    if [ "$seen" -eq 1 ]; then filter+=("$a")
    elif [ "$a" = "--" ]; then seen=1
    else cargo_args+=("$a"); fi
  done
  cargo test "${cargo_args[@]}" -- ${filter[@]+"${filter[@]}"} --list 2>/dev/null | grep -c ': test$'
}

lane_dep_graph() {
  # ── P15/D35: the self_encryption prohibition ────────────────────────────
  # `self_encryption` exists ONLY as a transitive dependency inside
  # ant-core's graph (GPL-3.0 with no linking exception; mandatory
  # tokio/tempfile/rayon/rand — wasm32-dead; docs/decisions/
  # D35-self-encryption-dependency-mode.md). No antseal crate may DECLARE
  # it: a direct edge anywhere would put GPL code one `use` away from the
  # permissive core and the redistributable verifier page, and D32 removed
  # every reason to want one (storage addresses are BLAKE3-256 — the
  # pinned `blake3`, not self_encryption, is the recomputation primitive).
  #
  # The check reads DECLARED manifests (`cargo metadata --no-deps` needs no
  # dependency resolution), not the resolved tree: a declaration is the
  # thing D35 prohibits, it is visible before any lock entry exists for it,
  # and normal/dev/build/target-gated/optional edges ALL appear in it — a
  # feature-gated edge cannot hide. Red direction proven at P15 (2026-08-01)
  # by planting the edge in a member manifest and in
  # [workspace.dependencies]; both runs failed on the messages below.
  note "P15/D35: self_encryption must be a direct dependency of NO antseal crate"
  local detector='"name":"self_encryption"'
  # Self-test FIRST, every run (the secret-guard pattern): the detector must
  # trip on a planted declaration — in the compact-JSON shape cargo metadata
  # actually emits for a dependency entry — before the real verdict is
  # trusted.
  local planted='{"name":"self_encryption","source":"registry+https://github.com/rust-lang/crates.io-index","req":"^0.36"}'
  if ! printf '%s\n' "$planted" | grep -qF "$detector"; then
    printf '::error::dep-graph self-test FAILED: the detector does not match a planted self_encryption dependency entry — fix the detector before trusting any green verdict\n'
    return 1
  fi
  local declared
  declared="$(cargo metadata --format-version 1 --no-deps --locked)" || return 1
  if printf '%s\n' "$declared" | grep -qF "$detector"; then
    printf '::error::P15/D35 violation: a workspace crate DECLARES self_encryption as a direct dependency. It is GPL-3.0 and wasm32-hostile, and D32/D35 removed every reason to depend on it (addresses are blake3). Candidate declaration sites:\n'
    grep -n 'self_encryption' crates/*/Cargo.toml Cargo.toml 2>/dev/null || true
    return 1
  fi
  # A [workspace.dependencies] entry nobody references yet would not appear
  # in package metadata — but it is a standing invitation to add the edge,
  # so it is banned with the same severity.
  if grep -En '^[[:space:]]*self_encryption[[:space:]]*=' Cargo.toml; then
    printf '::error::P15/D35 violation: [workspace.dependencies] carries a self_encryption entry (line above). The prohibition covers the declaration point too — remove it; docs/dependency-policy.md §1 records why\n'
    return 1
  fi
  printf 'OK: no antseal crate declares self_encryption (D35 prohibition).\n'

  note "antseal-core's NORMAL dependency graph must be I/O-free and RNG-free"
  # RNG half added at S4 ("no I/O, tokio, or RNG reachable" — the
  # storage-address function must be a pure function of its input):
  # `getrandom`/`rand`/`rand_chacha` are banned from the normal graph.
  # `rand_core` is deliberately NOT banned — it is the pinned pure-trait
  # crate (zero deps; the injected-CSPRNG API contract of C5/C9) and
  # structurally cannot reach an OS RNG; the `^rand ` entry's trailing
  # space keeps it unmatched. blake3 is consumed with default-features off
  # precisely so none of these enter (workspace Cargo.toml pin comment).
  local forbidden='^(tokio|async-std|smol|hyper|reqwest|mio|socket2|getrandom|rand|rand_chacha) ' tree offenders
  tree="$(cargo tree -p antseal-core -e normal --prefix none --locked)" || return 1
  printf '%s\n' "$tree"
  offenders="$(printf '%s\n' "$tree" | grep -E "$forbidden" || true)"
  if [ -n "$offenders" ]; then
    printf '\n::error::antseal-core normal dependency graph contains forbidden I/O/async/network/RNG crates:\n'
    printf '%s\n' "$offenders"
    return 1
  fi
  printf 'OK: no forbidden I/O/async/network/RNG crate in the normal graph.\n'

  # ── S6: ant-core adapter containment ────────────────────────────────────
  # Two rules from the S6 accept rows:
  #
  # (a) FORBIDDEN CALL SITES — `.data_upload(` / `.data_upload_with_mode(` /
  #     `.chunk_put(` / `.batch_pay(` appear NOWHERE in workspace source.
  #     Their results carry no payment data (`DataUploadResult`, S1 §10) or
  #     their error path destroys the partial paid map (`batch_pay`, D37
  #     ruling 2). Method-call position with an exact name boundary, so
  #     `chunk_put_with_proof(` — the sanctioned store primitive — cannot
  #     match.
  # (b) UPSTREAM-USE CONFINEMENT — `ant_core::` / `ant_protocol::` tokens on
  #     CODE lines (comment-leading lines are citations, which the house
  #     style REQUIRES everywhere — e.g. `ant_protocol::MAX_CHUNK_SIZE` in
  #     blob.rs docs — and are not dependencies) appear only in the
  #     containment allowlist: the ONE adapter impl file (ant_backend.rs),
  #     S5's EVM half (evm.rs), the feature-gated devnet suite that parses
  #     the adapter's real bytes via upstream's own deserializer (S7
  #     capture-consistency — tests consuming upstream to VERIFY the
  #     adapter are the point), and the never-published devnet-launcher.
  #     Churn from an ant-core bump is thereby bounded to exactly these
  #     files (S20's procedure relies on it).
  note "S6: forbidden upstream call sites + ant-core usage confinement"
  local forbidden_calls='[.](data_upload|data_upload_with_mode|chunk_put|batch_pay)[[:space:]]*[(]'
  local allowlist='crates/antseal-net/src/ant_backend.rs
crates/antseal-net/src/evm.rs
crates/antseal-net/tests/devnet_backend.rs
crates/devnet-launcher/src/devnet.rs
crates/devnet-launcher/src/main.rs'
  # Self-test FIRST (house pattern): both detectors must trip on planted
  # violations before any green verdict is trusted.
  local s6tmp
  s6tmp="$(mktemp -d)"
  printf 'fn f(c: &C) { let _ = c.chunk_put(bytes); }\n' > "$s6tmp/planted_call.rs"
  printf 'use ant_core::data::Client;\n' > "$s6tmp/planted_use.rs"
  if ! grep -rqE "$forbidden_calls" "$s6tmp" || ! grep -rq 'ant_core::' "$s6tmp"; then
    printf '::error::S6 containment self-test FAILED: a planted violation was not detected — fix the detector before trusting any green verdict\n'
    rm -rf "$s6tmp"; return 1
  fi
  rm -rf "$s6tmp"
  local call_hits
  call_hits="$(grep -rnE --include='*.rs' "$forbidden_calls" crates/ || true)"
  if [ -n "$call_hits" ]; then
    printf '::error::S6 violation: a forbidden upstream call site (data_upload/chunk_put/batch_pay — no payment capture, or capture-destroying error path):\n%s\n' "$call_hits"
    return 1
  fi
  local upstream_files stray
  # Code lines only: lines whose first non-whitespace is `//` (doc/line
  # comments — the citation style) are filtered before the verdict.
  upstream_files="$(grep -rnE --include='*.rs' 'ant_core::|ant_protocol::' crates/ \
    | grep -vE '^[^:]+:[0-9]+:[[:space:]]*//' | cut -d: -f1 | sort -u || true)"
  stray="$(printf '%s\n' "$upstream_files" | grep -vxF -f <(printf '%s\n' "$allowlist") | grep -v '^$' || true)"
  if [ -n "$stray" ]; then
    printf '::error::S6 violation: ant_core/ant_protocol used outside the containment allowlist (the one adapter impl file + evm.rs + the devnet suite + devnet-launcher):\n%s\n' "$stray"
    return 1
  fi
  printf 'OK: no forbidden call sites; upstream use confined to the adapter allowlist.\n'

  # ── P15/D35, resolved-graph half ────────────────────────────────────────
  # From the moment ant-core's graph is consumed (P16's launcher, S6's
  # adapter), self_encryption IS in the locked graph — transitively. Its
  # immediate parents must then contain no workspace crate: workspace
  # members print with their local path in parentheses, registry crates do
  # not, so a parent line containing " (/" is a workspace crate holding a
  # direct edge. This half catches what a declared-manifest scan cannot: a
  # path/patch sneak that renames the declaration but still resolves to the
  # crate.
  if grep -q '^name = "self_encryption"$' Cargo.lock; then
    note "self_encryption is in the locked graph (transitive) — checking its immediate parents"
    local inverse parents bad
    inverse="$(cargo tree -i self_encryption --workspace --all-features -e normal,build,dev --prefix depth --depth 1 --locked)" || return 1
    parents="$(printf '%s\n' "$inverse" | grep '^1' || true)"
    printf 'immediate parents:\n%s\n' "${parents:-(none)}"
    bad="$(printf '%s\n' "$parents" | grep -F ' (/' || true)"
    if [ -n "$bad" ]; then
      printf '::error::P15/D35 violation: a WORKSPACE crate is an immediate parent of self_encryption in the resolved graph:\n%s\n' "$bad"
      return 1
    fi
    printf 'OK: every parent of self_encryption is an upstream crate, none is ours.\n'
  else
    printf 'self_encryption is not in the locked graph at all (no ant-core consumer yet) — prohibition vacuously holds.\n'
  fi
}

lane_cross_os() {
  note "cross-platform-sensitive suites (corpus_ vector_; allowed-empty by design)"
  cargo test -p antseal-core --locked -- corpus_ vector_ || return 1
  local matched
  matched="$(count_matched -p antseal-core --locked -- corpus_ vector_)"
  printf 'cross-OS suite: matched %s test(s) for reserved-name filters [corpus_ vector_]\n' "$matched"
  if [ "${matched}" -eq 0 ]; then
    printf '::notice title=cross-OS suite set is EMPTY::No corpus_*/vector_* tests exist yet — this lane is vacuously green by design (Q1). G3 (UTF-8 corpus) and Q4 (golden vectors) populate it.\n'
  fi
}

lane_golden_vectors() {
  note "golden-vector suite (vector_ reserved-name marker; must NOT be empty)"
  cargo test -p antseal-core --locked -- vector_ || return 1
  local matched
  matched="$(count_matched -p antseal-core --locked -- vector_)"
  printf 'golden-vector suite: matched %s test(s) for reserved-name filter [vector_]\n' "$matched"
  if [ "${matched}" -eq 0 ]; then
    printf '::error::golden-vector suite is EMPTY — the Q4 runner tests must always match; the vector_ marker or the runner is broken\n'
    return 1
  fi
}

lane_tamper_matrix() {
  note "tamper harness self-tests (colliding codes, panicking row)"
  cargo test -p antseal-core --locked --lib -- test_util::tamper || return 1
  note "tamper registry + Q8 completeness (--nocapture prints the Q14 gate)"
  cargo test -p antseal-core --locked --test tamper_matrix --test tamper_crypto -- --nocapture || return 1
  local matched
  matched="$(count_matched -p antseal-core --locked --test tamper_matrix)"
  printf 'tamper-matrix suite: matched %s test(s) in the registry target\n' "$matched"
  if [ "${matched}" -eq 0 ]; then
    printf '::error::tamper-matrix registry target is EMPTY — the harness or the completeness check is broken\n'
    return 1
  fi
}

lane_cbor_drift_guard() {
  note "drift guard — the two implementations of the rendering table agree"
  cargo test -p antseal-core --all-features --locked --test cbor_crosscheck_contract
}

lane_traceability() {
  python3 --version
  if ! python3 scripts/check-traceability.py --self-test; then
    printf '::error::traceability self-test FAILED — a check stayed green over corrupted input, so a green run below would prove nothing\n'
    return 1
  fi
  python3 scripts/check-traceability.py
}

# Q43's guard over this very refactor: every `run:` block in every workflow
# must be a committed script call or an allowlisted line. Python-only, so it
# rides in the `traceability` job rather than costing a new required-status
# context.
lane_ci_shell() {
  if ! python3 scripts/check-ci-shell.py --self-test; then
    printf '::error::check-ci-shell self-test FAILED — the check stayed green over a planted inline block, so a green run below would prove nothing\n'
    return 1
  fi
  python3 scripts/check-ci-shell.py
}

# Q2: vault-export / wallet-key signature guard.
#
# The detection patterns are spelled with character classes so they cannot
# match themselves; what DOES have to be excluded is the self-test's planted
# fakes, which are written as literals a few lines below. That used to be
# handled by excluding all of `.github/`, because the guard lived in the
# workflow. Moving it here would have meant excluding all of `scripts/` — a
# strictly LARGER hole in a directory far more likely to receive a stray key.
#
# So the exclusion is now the single file that carries the literals, by
# basename, and `.github/` is scanned again: moving the logic into a script
# tightened the guard rather than relaxing it.
lane_secret_guard() {
  scan() {
    local root="$1" hits=""
    ex() { grep -rlaE --exclude-dir=.git --exclude-dir=target \
             --exclude='ci-lanes.sh' --exclude='*.md' -e "$1" "$root" || true; }
    # (1) PEM private-key blocks (wallet/signing keys, any flavor).
    hits+="$(ex '[-]{5}BEGIN[ A-Z0-9]*PRIVATE KEY[-]{5}')"$'\n'
    # (2) EVM keystore JSON (web3 secret storage): both signature keys must
    #     appear in the same file.
    local a b
    a="$(ex '"ciphertext"')" ; b="$(ex '"kdfparams"')"
    hits+="$(comm -12 <(printf '%s\n' "$a" | sort -u) <(printf '%s\n' "$b" | sort -u))"$'\n'
    # (3) Reserved antseal vault-export magic (testdata/README.md). The
    #     ONE sanctioned source occurrence is the format module that
    #     defines the EXPORT_MAGIC constant — the U12 exclusion event the
    #     Q2 convention anticipated (recorded 2026-08-01; tests reference
    #     the constant, never the literal). Excluded by EXACT PATH, not
    #     basename, so a stray export file named export.rs anywhere else
    #     still trips the scan; the self-test's planted fake lives under
    #     a temp root and is unaffected by this repo-rooted path.
    hits+="$(ex 'ANTSEAL[ ]VAULT[ ]EXPORT' \
             | grep -vxF "$root/crates/antseal-cli/src/vault/export.rs" || true)"$'\n'
    # (4) age / minisign secret-key markers.
    hits+="$(ex 'AGE[-]SECRET[-]KEY[-]1')"$'\n'
    hits+="$(ex 'minisign encrypted secret key')"$'\n'
    # (5) A committed devnet environment export (S5): the wallet-key line
    #     of `.devnet/env` — the key name followed by an actual 64-hex
    #     value. The export must only ever exist under gitignored
    #     .devnet/ (docs/devnet/local-devnet.md); docs naming the KEY are
    #     fine (*.md excluded, and the pattern requires the value), and so
    #     are test fixtures that interpolate a runtime-derived value (no
    #     64-hex literal after the `=` in source).
    hits+="$(ex "ANTSEAL[_]DEVNET[_]WALLET[_]PRIVATE[_]KEY[[:space:]]*=[[:space:]]*'?(0x)?[0-9a-fA-F]{64}")"$'\n'
    hits="$(printf '%s\n' "$hits" | grep -v '^$' | sort -u || true)"
    if [ -n "$hits" ]; then
      printf '%s\n' "$hits"
      return 1
    fi
    return 0
  }
  # Self-test FIRST, every run: planted fakes in a temp dir MUST trigger
  # every pattern class before the repo verdict is trusted.
  local tmp planted found
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' RETURN
  printf 'fake for guard self-test\n-----BEGIN EC PRIVATE KEY-----\nAAAA\n-----END EC PRIVATE KEY-----\n' > "$tmp/fake-wallet.pem"
  printf '{"version":3,"crypto":{"ciphertext":"00","cipherparams":{},"kdf":"scrypt","kdfparams":{"n":1},"mac":"00"}}\n' > "$tmp/fake-keystore.json"
  printf 'ANTSEAL VAULT EXPORT v0 guard-self-test\n' > "$tmp/fake-vault-export.bin"
  printf 'AGE-SECRET-KEY-1SELFTESTSELFTESTSELFTEST\n' > "$tmp/fake-age.key"
  # The devnet-export wallet-key line (pattern 5): 64 x 'a' is hex-shaped
  # enough to trip the guard and unmistakably fake.
  printf "ANTSEAL_DEVNET_WALLET_PRIVATE_KEY='%s'\n" "$(printf 'a%.0s' $(seq 64))" > "$tmp/fake-devnet-env"
  planted=5
  found="$(scan "$tmp" | wc -l)" || true
  if [ "$found" -ne "$planted" ]; then
    printf '::error::secret-guard self-test FAILED: planted %s fakes, detected %s — the detector is broken; fix it before trusting a green scan\n' "$planted" "$found"
    scan "$tmp" || true
    return 1
  fi
  printf 'self-test OK: all %s planted fakes detected in the temp dir\n' "$planted"
  # The real scan.
  if ! scan .; then
    printf '::error::secret-guard: vault-export/wallet-key file signature(s) found (paths above). No real secret material may ever be committed (project rule 6; testdata/README.md).\n'
    return 1
  fi
  printf 'OK: no vault-export/wallet-key signatures in the tree.\n'
}

lane_audit_deny() {
  command -v cargo-deny >/dev/null 2>&1 || die "cargo-deny is not installed. Pinned version (docs/dependency-policy.md §5):
    cargo install cargo-deny --version 0.19.8 --locked"
  cargo deny --version
  # Explicit check list, never a bare `check`: licenses are STUBBED until Q29.
  cargo deny --locked check advisories bans sources
}

# Q43's test-of-the-test: reproduce the Q8 defect and watch this lane go red
# WITHOUT a push. Not a description of the defect — the defect itself, put
# back into a copy of this script and executed.
#
# The copy lives in `scripts/` rather than a temp dir on purpose: the script
# derives `repo` from its own location, so a copy anywhere else would be
# testing a different program.
self_test() {
  local copy="$repo/scripts/.ci-lanes-selftest.sh" out status fail=0
  trap 'rm -f "$copy"' RETURN

  note "control: the counter with the CORRECT flag order"
  local good
  good="$(count_matched -p antseal-core --locked --test tamper_matrix)"
  printf '    matched %s test(s)\n' "$good"
  if [ "${good}" -eq 0 ]; then
    printf '::error:: the correct form counts 0 — the control is broken, so nothing below means anything\n'
    return 1
  fi

  note "planted fault: Q8's flag order — \`--list\` to cargo instead of after \`--\`"
  # The malformed shape, as Q8 wrote it: `--list` before the `--`, so cargo
  # takes it as one of its own options and rejects it.
  sed 's|cargo test "${cargo_args\[@\]}" -- \${filter\[@\]+"${filter\[@\]}"} --list|cargo test "${cargo_args[@]}" --list -- ${filter[@]+"${filter[@]}"}|' \
    "$repo/scripts/ci-lanes.sh" > "$copy"
  if cmp -s "$copy" "$repo/scripts/ci-lanes.sh"; then
    printf '::error:: the planted fault did not apply — count_matched no longer has the shape this self-test patches\n'
    return 1
  fi
  out="$(bash "$copy" tamper-matrix 2>&1)"
  status=$?
  printf '%s\n' "$out" | tail -3 | sed 's/^/    /'
  if [ "$status" -eq 0 ]; then
    printf '::error:: the lane stayed GREEN with the Q8 flag order — the counter guard is not wired in\n'
    fail=1
  fi
  if ! printf '%s' "$out" | grep -q 'registry target is EMPTY'; then
    printf '::error:: the lane went red for some other reason than the empty count\n'
    fail=1
  fi
  rm -f "$copy"

  note "restored: the lane is green again"
  if ! lane_tamper_matrix >/dev/null 2>&1; then
    printf '::error:: the lane is still red after restoring — the self-test left damage behind\n'
    fail=1
  fi
  [ "$fail" -eq 0 ] || return 1
  note "ci-lanes self-test PASS — the Q8 defect turns this lane red locally"
}

case "${1:-}" in
  --list) printf '%s\n' $LANES ;;
  --self-test) self_test ;;
  dep-graph)        lane_dep_graph ;;
  cross-os)         lane_cross_os ;;
  golden-vectors)   lane_golden_vectors ;;
  tamper-matrix)    lane_tamper_matrix ;;
  cbor-drift-guard) lane_cbor_drift_guard ;;
  traceability)     lane_traceability ;;
  ci-shell)         lane_ci_shell ;;
  secret-guard)     lane_secret_guard ;;
  audit-deny)       lane_audit_deny ;;
  *) die "usage: scripts/ci-lanes.sh <$(printf '%s' "$LANES" | tr ' ' '|')> | --list | --self-test" ;;
esac
