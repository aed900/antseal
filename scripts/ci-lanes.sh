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
#   dep-graph         one containment story: antseal-core's normal deps stay
#                     I/O-free, self_encryption is nobody's direct dep, only
#                     net/devnet-launcher DECLARE the payment stack and only
#                     the adapter files USE it, the devnet-era graph stays out
#                     of the default build, alloy moves only with evmlib
#                     (docs/dependency-policy.md §1)
#   cross-os          the cross-platform-sensitive suites (allowed-empty)
#   golden-vectors    the golden-vector suite (must NOT be empty)
#   tamper-matrix     the tamper harness, registry and Q8 completeness
#   cbor-drift-guard  the two implementations of the rendering table agree
#   traceability      self-test, then the two documented-claim checks
#   ci-shell          self-test, then Q43's own guard over every workflow
#   secret-guard      self-test, then the vault-export/wallet-key scan
#   audit-deny        cargo-deny advisories/bans/sources
#   fuzz-budget       self-test, then the scheduled fuzz lane's monthly
#                     minute cost against its named ceiling (D61)
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

LANES="dep-graph cross-os golden-vectors tamper-matrix cbor-drift-guard traceability ci-shell secret-guard audit-deny fuzz-budget"

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

  # ── S23/S2: manifest-level exclusivity for the upstream payment stack ────
  # S2's accept row is phrased at the DEPENDENCY-GRAPH level ("proves only
  # antseal-net depends on ant-core"); S6's containment check below is at the
  # SOURCE-TOKEN level (`ant_core::`/`ant_protocol::` code lines confined to
  # the adapter allowlist). They are complementary, not redundant: a consumer
  # writing a fully qualified `::ant_core::Client`, or aliasing the crate
  # under another name, spells `ant_core::` nowhere and would pass the token
  # check while holding a real edge. This is the missing manifest half, and
  # it lives here because it is the same rule shape as the self_encryption
  # scan directly above — same command, same JSON, same self-test-first
  # discipline — and the whole containment story reads in one place.
  #
  # Owners: `antseal-net` (the one product adapter; MVP-SPEC.md lines 60-69
  # make it the churn-isolation boundary) and `devnet-launcher` (never
  # published, every edge behind its non-default `devnet` feature). Those are
  # exactly the two crates the S6 file allowlist below is built around.
  note "S23/S2: only antseal-net and devnet-launcher may DECLARE the upstream payment-stack edges"
  local stack_deps='^(ant-core|ant-protocol|alloy|bytes)$'
  local stack_owners='^(antseal-net|devnet-launcher) '
  # `cargo metadata --no-deps` lists every DECLARED edge — normal, dev,
  # build, target-gated, optional and RENAMED alike (a renamed entry carries
  # the real crate in "name" and the local alias in "rename") — and needs no
  # resolution, so a declaration is visible before any lock entry exists.
  #
  # Records split on the literal `{"name":"` that opens every package AND
  # every dependency object; a PACKAGE record is the one that also carries an
  # `"id"` (dependency entries have none), so the state machine is one flag
  # and does not depend on cargo's field ORDER beyond that. Fidelity is not
  # taken on trust: the self-test feeds the extractor a planted violation in
  # cargo's own shape, and the anti-vacuity check below requires it to still
  # find the edges we know exist.
  local extract='BEGIN { RS = "{\"name\":\"" }
    { n = $0; sub(/".*/, "", n)
      if ($0 ~ /","id":"/) { pkg = n; next }
      if (pkg != "" && n ~ deps) print pkg " " n }'
  # Self-test FIRST: a plain forbidden edge, a RENAMED one (the sneak this
  # rule exists for — S6's token check cannot see it), and an ALLOWED one
  # that must NOT be reported, so both directions of the extractor are
  # pinned rather than just its willingness to print something.
  local planted_meta planted_pairs
  planted_meta='{"packages":[{"name":"antseal-cli","version":"0.0.0","id":"path+file:///x/crates/antseal-cli#0.0.0","source":null,"dependencies":[{"name":"alloy","source":"registry","req":"=1.8.3","kind":null,"rename":null,"optional":false},{"name":"ant-core","source":"registry","req":"=0.5.0","kind":null,"rename":"upstream","optional":false},{"name":"thiserror","source":"registry","req":"2","kind":null,"rename":null,"optional":false}]},{"name":"antseal-net","version":"0.0.0","id":"path+file:///x/crates/antseal-net#0.0.0","source":null,"dependencies":[{"name":"bytes","source":"registry","req":"=1.12.1","kind":null,"rename":null,"optional":true}]}]}'
  planted_pairs="$(printf '%s' "$planted_meta" | awk -v deps="$stack_deps" "$extract" | grep -vE "$stack_owners" | tr '\n' ';')"
  if [ "$planted_pairs" != "antseal-cli alloy;antseal-cli ant-core;" ]; then
    printf '::error::S23 self-test FAILED: the declared-edge extractor reported [%s] for a planted manifest carrying a plain edge, a RENAMED edge and one allowed edge — it should report exactly the first two. Fix it before trusting any green verdict\n' "$planted_pairs"
    return 1
  fi
  local stack_edges stack_strays
  stack_edges="$(printf '%s' "$declared" | awk -v deps="$stack_deps" "$extract")"
  # Anti-vacuity, and S2's own existential half: "only antseal-net depends on
  # ant-core" is also the claim that it DOES. If this disappears, the parser
  # stopped matching and every verdict below is worthless.
  if ! printf '%s\n' "$stack_edges" | grep -qxF 'antseal-net ant-core'; then
    printf '::error::S23 scan found no `antseal-net ant-core` edge — S2 says that edge exists, so the metadata parse is broken, not the tree clean. Edges found:\n%s\n' "${stack_edges:-(none)}"
    return 1
  fi
  stack_strays="$(printf '%s\n' "$stack_edges" | grep -vE "$stack_owners" | grep -v '^$' || true)"
  if [ -n "$stack_strays" ]; then
    printf '::error::S23/S2 violation: a crate outside {antseal-net, devnet-launcher} DECLARES an upstream payment-stack edge. antseal-net is the churn-isolation boundary (MVP-SPEC.md lines 60-69) and an ant-core bump must stay bounded to it (S20). `<crate> <dependency>`:\n%s\n' "$stack_strays"
    grep -nE '^[[:space:]]*(ant-core|ant-protocol|alloy|bytes)[[:space:].]' crates/*/Cargo.toml 2>/dev/null || true
    return 1
  fi
  printf 'OK: all %s declared payment-stack edge(s) belong to antseal-net or devnet-launcher.\n' "$(printf '%s\n' "$stack_edges" | grep -c .)"

  # ── S4/Q74: what this rule proves, and what it cannot ───────────────────
  #
  # SCOPE, stated because the wording this replaces overclaimed. The
  # headline was "antseal-core's NORMAL dependency graph must be I/O-free
  # and RNG-free" — two unbounded properties — over a nine-name deny-list
  # that establishes neither in general. D58 measured the gap: the
  # `opentimestamps 0.2.0` codec declares `env_logger` NON-OPTIONALLY, which
  # drags an environment-variable reader, a stderr writer, `is-terminal`,
  # `libc` and a regex engine into the crate that MVP-SPEC.md lines 47-53
  # require to be I/O-free and that ships as the verifier page's WASM — and
  # every one of those five passes all nine names. A lane whose stated job
  # is "this graph is I/O-free" would have gone green on it.
  #
  # WIDENING THE LIST IS NOT THE FIX, and that is measured rather than
  # assumed: the same crates pass an extended name list too, because the
  # property is not decidable from a dependency graph. A crate name carries
  # no capability, any crate can open a file or read an environment variable
  # without depending on anything, and the set of crates that do is not
  # enumerable. A deny-list can only ever say "not these"; the claim above
  # says "none at all".
  #
  # So the CLAIM IS NARROWED to what a graph actually decides:
  #
  #     antseal-core's NORMAL dependency graph is EXACTLY the reviewed set
  #     below. Nothing enters it without an edit here.
  #
  # A GREEN VERDICT IS NOT A PURITY PROOF, and no other task may cite it as
  # one. It says the set has not changed since a human last read it — which
  # is exactly the property that would have caught `env_logger`: not because
  # the name was on a forbidden list, but because it was on no list at all.
  # The purity argument is made ONCE PER ENTRY, by the reviewer who admits
  # it; this rule's whole job is to force that review to happen and to make
  # skipping it a red lane rather than a silent merge.
  #
  # SCOPE, precisely, because each dimension has bitten somewhere before:
  #   * `-e normal` — build- and dev-dependencies are excluded. They run on
  #     the builder's machine and are not in the shipped artifact.
  #   * DEFAULT features. `--all-features` adds 22 packages (proptest,
  #     tempfile, rand, getrandom, libc, rustix …) under `test-util` /
  #     `test-vectors`, which are test-only and never reach the verifier.
  #     S22's gate-features partition is what stops a feature going
  #     uncompiled; this rule is about what SHIPS.
  #   * `--target all`, so the verdict does not depend on whose machine ran
  #     it. It is a superset of every host's graph — it can over-report and
  #     never under-report — which is why `libc` (via `cpufeatures`, non-x86
  #     only) and `fiat-crypto` (curve25519-dalek's 32-bit backend) are in
  #     the set at all: neither is in the x86_64 or the wasm32 graph.
  #   * `-p antseal-core`, NOT the workspace. Edges added to antseal-net or
  #     antseal-anchor — A3's `ureq`, for instance — cannot reach this set,
  #     because those crates sit ABOVE core. Nothing here counts workspace
  #     packages, so a lane that grows the default `--workspace` graph does
  #     not touch this rule (P20 rule 1 below prints those counts as
  #     evidence and deliberately asserts nothing about them).
  #
  # ── layer 1: the DECIDED prohibitions ───────────────────────────────────
  # Names that no reviewer may admit to the set below without first
  # overturning the decision that banned them. Kept as a separate, earlier
  # check because it gives the right DIAGNOSIS: "you added tokio" is a more
  # useful failure than "you added an unreviewed package".
  #
  # RNG half added at S4 ("no I/O, tokio, or RNG reachable" — the
  # storage-address function must be a pure function of its input):
  # `getrandom`/`rand`/`rand_chacha` are banned from the normal graph.
  # `rand_core` is deliberately NOT banned — it is the pinned pure-trait
  # crate (zero deps; the injected-CSPRNG API contract of C5/C9) and
  # structurally cannot reach an OS RNG; the `^rand ` entry's trailing
  # space keeps it unmatched. blake3 is consumed with default-features off
  # precisely so none of these enter (workspace Cargo.toml pin comment).
  note "antseal-core's NORMAL graph: none of the DECIDED-prohibited crates"
  local forbidden='^(tokio|async-std|smol|hyper|reqwest|mio|socket2|getrandom|rand|rand_chacha) ' tree offenders
  # Self-test FIRST, in BOTH directions — the D89 rule-5 pattern, and the
  # thing this rule went without from S4 until Q74. It was the ONLY rule in
  # this lane with no planted fault (its siblings self-test above and
  # below), which is very likely why its hole survived two waves: nobody had
  # ever watched it bite. The negative direction is load-bearing, not
  # decoration: the `^rand ` trailing space is the only thing keeping
  # `rand_core` — a real member of the set below — out of the ban.
  if ! printf 'tokio v1.49.0\n' | grep -qE "$forbidden"; then
    printf '::error::dep-graph prohibition self-test FAILED: the detector does not match a planted `tokio` tree line — fix it before trusting any green verdict\n'
    return 1
  fi
  if printf 'rand_core v0.9.3\n' | grep -qE "$forbidden"; then
    printf '::error::dep-graph prohibition self-test FAILED: the detector ALSO matches `rand_core`, which C5/C9 require in the graph. The `^rand ` entry has lost its trailing space, so this rule can never be green for the right reason\n'
    return 1
  fi
  tree="$(cargo tree -p antseal-core -e normal --target all --prefix none --locked)" || return 1
  printf '%s\n' "$tree"
  offenders="$(printf '%s\n' "$tree" | grep -E "$forbidden" || true)"
  if [ -n "$offenders" ]; then
    printf '\n::error::antseal-core normal dependency graph contains a DECIDED-prohibited async/network/RNG crate. These are not merely unreviewed — each is banned by a recorded decision, so admitting one to the reviewed set below is not enough:\n'
    printf '%s\n' "$offenders"
    return 1
  fi
  printf 'OK: no decided-prohibited crate in the normal graph.\n'

  # ── layer 2: the graph is EXACTLY the reviewed set (Q74) ────────────────
  # The claim the scope note above narrows to. Set EQUALITY, both
  # directions: an unreviewed arrival is a violation, and a stale entry is
  # one too — an allow-list carrying names that are no longer there stops
  # describing the graph, which is how allow-lists quietly stop meaning
  # anything (check-ci-shell.py applies the same rule to ALLOWED_INLINE).
  #
  # Measured 2026-08-02: 57 names under `--target all`, of which 55 on
  # x86_64-unknown-linux-gnu. Every entry is `cargo tree`-verified as
  # reachable; the annotations name the parent for the ones a reader would
  # otherwise have to look up.
  note "antseal-core's NORMAL graph is EXACTLY the reviewed set (Q74)"
  local core_reviewed='antseal-core          # the crate itself, as cargo tree roots it

  # --- BLAKE3 content addressing (default-features off; D32) ---
  blake3
  arrayref
  arrayvec
  constant_time_eq
  cfg-if
  cpufeatures
  libc                # <- cpufeatures, non-x86 targets only; absent on x86_64 and wasm32

  # --- RFC 3161 / CMS / X.509 anchor verification (D60, A5/A8/A9) ---
  # Reviewed 2026-08-05 at the A10/A20 merge. Every one of these arrives through
  # the SEVEN pins D60 ruled, and D60 section 1 argued each against the alternatives it
  # rejected; what follows is the I/O argument this lane demands per entry,
  # which is a different question from whether the crate is any good.
  #
  # The whole subtree is PARSE-AND-ARITHMETIC. Not one of these opens a socket,
  # reads a clock or touches a filesystem: DER decoding is byte-slice work,
  # certificate path validation takes `verify_at` as a caller-supplied parameter
  # (A32 makes reading a local clock a prohibition, not merely an omission),
  # and the signature primitives are pure field arithmetic over caller-supplied
  # bytes. Two specific absences that matter for the WASM page: NO getrandom and
  # NO rand — `k256` is declared WITHOUT `ecdsa` (D89) and `rsa 0.9.10` was
  # REJECTED by D60 precisely because it drags rand/rand_chacha in here, which
  # this this lane own denylist would have failed red.
  der                 # the DER reader; strictness IS the product requirement (A5)
  der_derive          # proc-macro, compile-time only, contributes no runtime code
  const-oid           # OID constants, feature `db`; identity of every algorithm named
  spki                # SubjectPublicKeyInfo
  pkcs1               # key encoding reached through the above
  pkcs8
  pem-rfc7468         # base64 armour; parse-only
  base16ct            # constant-time hex codec, no I/O
  base64ct            # constant-time base64 codec, no I/O
  x509-cert           # certificate PARSING only — it has no path validation, which
                      #   is why A9 writes single-path validation by hand (spec:108)
  cms                 # RFC 5652 SignedData structure only; every semantic check is ours
  flagset             # bitflag helper reached through the x509-cert KeyUsage type
  sha1                # REQUIRED and simultaneously FORBIDDEN as a signature digest:
                      #   the ESSCertID v1 certHash is SHA-1 by definition (RFC 5035)
                      #   and FreeTSA emits v1, so the signer binding is impossible
                      #   without it. Used for identity binding, never validation.
  rsa                 # PKCS#1 v1.5 VERIFY only. antseal holds no RSA private key and
                      #   performs no private-key operation, which is the whole basis
                      #   of the RUSTSEC-2023-0071 ignore (a private-key timing channel
                      #   with no secret in our computation to leak).
  crypto-bigint       # the rsa arithmetic backend
  crypto-primes
  cpubits
  p384                # ECDSA P-384 verification
  primefield
  primeorder
  elliptic-curve
  ff
  group
  sec1
  wnaf
                      # ECDSA P-384 verification — FreeTSA signs ecdsa-with-SHA512,
                      #   not the SHA-384 the pairing suggests (measured, D60)
  ecdsa               # deterministic ECDSA
  rfc6979             # what lets the A59 signing mock
                      #   be RNG-free, keeping getrandom out of this graph entirely

  # --- RustCrypto traits and plumbing ---
  aead
  block-buffer
  cipher
  crypto-common
  ctutils             # <- digest, hybrid-array, ml-dsa, module-lattice, universal-hash
  cmov                # <- ctutils; constant-time conditional move
  digest
  hybrid-array
  inout
  signature
  subtle
  typenum
  universal-hash
  zeroize

  # --- hashes and XOFs ---
  sha2
  keccak              # SHA-3/SHAKE permutation
  shake               # <- ml-dsa
  sponge-cursor       # <- shake

  # --- AEAD (XChaCha20-Poly1305) ---
  chacha20
  chacha20poly1305
  poly1305

  # --- key derivation ---
  hkdf
  hmac

  # --- Ed25519 ---
  curve25519-dalek
  curve25519-dalek-derive
  ed25519
  ed25519-dalek
  fiat-crypto         # <- curve25519-dalek, 32-bit backend; absent on x86_64 and wasm32

  # --- ML-DSA-65 ---
  ml-dsa
  module-lattice      # <- ml-dsa
  num-traits          # <- module-lattice

  # --- CBOR ---
  minicbor

  # --- serde and the vector/report JSON surface ---
  serde
  serde_core
  serde_derive
  serde_json
  itoa                # <- serde_json
  memchr              # <- serde_json
  zmij                # <- serde_json, float formatting

  # --- Unicode normalization (NFC; G-domain canonicalization) ---
  unicode-normalization
  tinyvec
  tinyvec_macros

  # --- proc-macro support for the derives above ---
  proc-macro2
  quote
  syn
  unicode-ident

  # --- errors ---
  thiserror
  thiserror-impl

  # --- the injected-CSPRNG TRAIT only (C5/C9); never an OS RNG ---
  rand_core'
  # Comments and blank lines are stripped before use. A blank line reaching
  # a pattern list would match EVERY name and turn the check vacuous, which
  # is why this normalisation is not optional.
  strip_reviewed() { sed 's/#.*//' | tr -d '[:blank:]' | grep -v '^$' | sort -u; }
  names_of() { sed 's/ .*//' | grep -v '^$' | sort -u; }
  # Self-test FIRST, in BOTH directions: over a planted tree, the extractor
  # must report the intruder and must NOT report names that are on the list.
  # A set check that reports everything is as useless as one that reports
  # nothing, and only the second direction can tell them apart.
  local planted_tree planted_unknown
  planted_tree='antseal-core v0.0.0 (/x/crates/antseal-core)
sha2 v0.11.0
env_logger v0.10.2'
  planted_unknown="$(printf '%s\n' "$planted_tree" | names_of \
    | comm -23 - <(printf '%s\n' "$core_reviewed" | strip_reviewed) | tr '\n' ' ')"
  if [ "$planted_unknown" != "env_logger " ]; then
    printf '::error::dep-graph reviewed-set self-test FAILED: over a planted tree of {antseal-core, sha2, env_logger} the check reported [%s] — it must report exactly `env_logger`. Fix it before trusting any green verdict\n' "$planted_unknown"
    return 1
  fi
  local core_names core_unknown core_stale
  core_names="$(printf '%s\n' "$tree" | names_of)"
  # Anti-vacuity: an empty or unparsed tree yields an empty "unknown" set
  # and would pass. The root is always in its own tree, so its absence means
  # the parse broke rather than the graph being clean.
  if ! printf '%s\n' "$core_names" | grep -qxF 'antseal-core'; then
    printf '::error::dep-graph: the parsed package set does not contain `antseal-core` itself, so `cargo tree` failed or its output shape changed — every verdict here would be vacuous. Parsed %s name(s)\n' \
      "$(printf '%s\n' "$core_names" | grep -c .)"
    return 1
  fi
  core_unknown="$(comm -23 <(printf '%s\n' "$core_names") <(printf '%s\n' "$core_reviewed" | strip_reviewed))"
  if [ -n "$core_unknown" ]; then
    printf '::error::Q74 violation: package(s) entered antseal-core NORMAL dependency graph without review. This graph ships as the verifier page WASM and MVP-SPEC.md lines 47-53 require it to do no I/O; that property is argued per entry by a human, not detected by this lane. Read what each of these pulls in, then add it above IN THE SAME COMMIT:\n'
    printf '%s\n' "$core_unknown" | sed 's/^/  + /'
    printf 'Provenance: cargo tree -p antseal-core -e normal --target all --locked -i <name>\n'
    return 1
  fi
  core_stale="$(comm -13 <(printf '%s\n' "$core_names") <(printf '%s\n' "$core_reviewed" | strip_reviewed))"
  if [ -n "$core_stale" ]; then
    printf '::error::Q74: the reviewed set names package(s) that are no longer in the graph. A list carrying names that are not there has stopped describing the graph, which is how an allow-list quietly stops meaning anything — delete them:\n'
    printf '%s\n' "$core_stale" | sed 's/^/  - /'
    return 1
  fi
  printf 'OK: antseal-core normal graph is exactly the %s reviewed package(s). NOTE: this is a "nothing entered unreviewed" proof, NOT an I/O-freedom proof — see the scope note in this function.\n' \
    "$(printf '%s\n' "$core_names" | grep -c .)"

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
  #     adapter are the point), S9's constants suite whose whole purpose is
  #     to assert our constants EQUAL upstream's (a literal copy would be
  #     the bug it exists to catch; feature-gated, test-only, zero product
  #     graph), and the never-published devnet-launcher.
  #     Churn from an ant-core bump is thereby bounded to exactly these
  #     files (S20's procedure relies on it).
  note "S6: forbidden upstream call sites + ant-core usage confinement"
  local forbidden_calls='[.](data_upload|data_upload_with_mode|chunk_put|batch_pay)[[:space:]]*[(]'
  local allowlist='crates/antseal-net/src/ant_backend.rs
crates/antseal-net/src/evm.rs
crates/antseal-net/tests/devnet_backend.rs
crates/antseal-net/tests/storage_constants.rs
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
    # Self-test FIRST for THIS detector too (P20 rule 2: P15 landed the
    # check, this keeps its red direction tested). The declared-manifest
    # half above has had a planted-fake self-test since P15; the
    # resolved-parent half had none, so a typo in the ' (/' pattern would
    # have made it silently unfalsifiable — the exact failure mode the
    # counters at the top of this file exist to prevent.
    local planted_parent='1antseal-net v0.0.0 (/home/x/crates/antseal-net)'
    if ! printf '%s\n' "$planted_parent" | grep -qF ' (/'; then
      printf '::error::P15/D35 resolved-parent self-test FAILED: the workspace-crate detector does not match a planted local-path parent — fix it before trusting any green verdict\n'
      return 1
    fi
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

  # ── P20 rule 1: the devnet era stays out of the default build ───────────
  # P16 resolved ant-node into Cargo.lock (the M1 lockfile event, 128 → 744
  # entries) and put every heavy edge behind a NON-DEFAULT feature:
  # `devnet-launcher/devnet` and `antseal-net/ant-backend`. A lock entry is
  # not a compile — locks cover all member features — so the property that
  # actually matters is that a default `cargo build`/`cargo test --workspace`
  # compiles none of it. That is convention until something asserts it, and
  # a single non-optional edge added in review would flip ~355 packages into
  # every contributor's default build without any lane noticing.
  #
  # The whole upstream stack is checked, not just ant-node: ant-core,
  # ant-protocol, evmlib and alloy sit behind the same two feature gates by
  # the same recorded decisions (workspace Cargo.toml pin comments; D33,
  # D35, D52), so they are one boundary, and naming them individually makes
  # the failure message say which edge broke it.
  note "P20/D52: a default --workspace build/test must not reach the devnet-era graph"
  local upstream_stack='^(ant-node|ant-core|ant-protocol|evmlib|alloy) v'
  # Self-test FIRST, and against the REAL graph rather than a planted
  # string: with the launcher's own feature ON, the same command and the
  # same pattern MUST find ant-node. A detector that cannot see the thing it
  # forbids is green for the wrong reason.
  local devnet_tree default_tree offending
  local treeerr rc
  treeerr="$(mktemp)"
  devnet_tree="$(cargo tree --workspace --features devnet-launcher/devnet -e normal,build,dev --prefix none --locked 2>"$treeerr")"
  rc=$?
  if [ "$rc" -ne 0 ] || ! printf '%s\n' "$devnet_tree" | grep -qE '^ant-node v'; then
    # Diagnosable on purpose: a broken pattern and a cargo that failed to
    # produce a tree are different faults with the same symptom (an empty
    # match), and a lane whose red cannot be told apart from a flake gets
    # ignored, which is worse than not having it.
    printf '::error::P20 self-test FAILED (cargo exit %s, %s tree line(s)): with devnet-launcher/devnet enabled the tree does NOT show ant-node — the command or the pattern is wrong, so the green verdict below would be meaningless. cargo stderr:\n%s\n' \
      "$rc" "$(printf '%s\n' "$devnet_tree" | grep -c .)" "$(cat "$treeerr")"
    rm -f "$treeerr"
    return 1
  fi
  rm -f "$treeerr"
  default_tree="$(cargo tree --workspace -e normal,build,dev --prefix none --locked)" || return 1
  offending="$(printf '%s\n' "$default_tree" | grep -E "$upstream_stack" || true)"
  if [ -n "$offending" ]; then
    printf '::error::P20 violation: the DEFAULT --workspace graph reaches the devnet-era upstream stack. Every such edge is feature-gated by decision (devnet-launcher/devnet, antseal-net/ant-backend); a default edge puts the ~355-package ant-node/EVM subtree into every contributor build and every CI lane:\n%s\n' "$offending"
    return 1
  fi
  # Evidence, not decoration: the two package counts are the size of what
  # the feature gate is holding back, and a collapse toward each other is
  # visible in the log before it is a violation.
  local default_n devnet_n
  default_n="$(printf '%s\n' "$default_tree" | sed 's/ .*//' | sort -u | grep -c .)"
  devnet_n="$(printf '%s\n' "$devnet_tree" | sed 's/ .*//' | sort -u | grep -c .)"
  printf 'OK: default --workspace graph is %s packages and reaches none of ant-node/ant-core/ant-protocol/evmlib/alloy (with devnet-launcher/devnet: %s).\n' "$default_n" "$devnet_n"

  # ── P20 rule 3: alloy moves only with evmlib ────────────────────────────
  # D44 defines the accepted wallet/payment set as "what the pinned
  # evmlib/alloy parse accepts", and S5/S6 validate against it. antseal-net
  # holds a DIRECT alloy edge because evmlib re-exports no `Provider` trait
  # (evmlib-0.9.0/src/utils.rs:184-200), so two independent things now name
  # alloy — and independent drift between them would silently fork the
  # accepted set with no test failing.
  #
  # Cargo.lock encodes exactly this property already: a dependency entry is
  # version-QUALIFIED (`"alloy 1.7.0"`) if and only if the package resolves
  # to more than one version. So `evmlib` listing a bare `"alloy"` is the
  # lock's own statement that there is one alloy and both of us are on it.
  # That is the check, plus the recorded pin literal, so the comment in
  # Cargo.toml cannot drift from the resolution it claims.
  note "P20/D44: alloy stays in lockstep with the evmlib the ant-core graph locks"
  # Self-test FIRST: the qualified-entry detector must trip on a planted
  # split, in the exact shape Cargo.lock emits for one.
  local split_detector='^ "alloy [0-9]'
  if ! printf ' "alloy 1.7.0",\n' | grep -qE "$split_detector"; then
    printf '::error::P20 lockstep self-test FAILED: the split-version detector does not match a planted version-qualified alloy entry — fix it before trusting any green verdict\n'
    return 1
  fi
  if grep -q '^name = "evmlib"$' Cargo.lock; then
    local alloy_locked alloy_pinned evmlib_alloy family_split
    alloy_locked="$(awk '/^name = "alloy"$/{f=1; next} f && /^version = /{gsub(/"/,"",$3); print $3; f=0}' Cargo.lock)"
    if [ "$(printf '%s\n' "$alloy_locked" | grep -c .)" -ne 1 ]; then
      printf '::error::P20 violation: Cargo.lock carries %s alloy versions — we and evmlib are no longer on one alloy:\n%s\n' "$(printf '%s\n' "$alloy_locked" | grep -c .)" "$alloy_locked"
      return 1
    fi
    evmlib_alloy="$(awk '/^name = "evmlib"$/{f=1; next} f && /^\]$/{exit} f && /^ "alloy/{print}' Cargo.lock)"
    if [ -z "$evmlib_alloy" ]; then
      printf '::error::P20 violation: evmlib no longer depends on alloy at all — the lockstep partner this rule pins is gone; re-derive the rule before deleting it\n'
      return 1
    fi
    if printf '%s\n' "$evmlib_alloy" | grep -qE "$split_detector"; then
      printf '::error::P20 violation: evmlib depends on a version-QUALIFIED alloy (%s), which Cargo.lock emits only when alloy resolves to more than one version. D44 defines the accepted payment set as what the PINNED evmlib/alloy accept; two alloys means two accepted sets\n' "$evmlib_alloy"
      return 1
    fi
    # The whole `alloy-*` family moves as one for the same reason.
    family_split="$(awk '/^name = "alloy/{gsub(/"/,"",$3); n=$3; next} n != "" && /^version = /{gsub(/"/,"",$3); print n; n=""}' Cargo.lock | sort | uniq -d)"
    if [ -n "$family_split" ]; then
      printf '::error::P20 violation: an alloy family crate resolves to more than one version:\n%s\n' "$family_split"
      return 1
    fi
    alloy_pinned="$(sed -nE 's/^alloy = \{ version = "=([^"]+)".*/\1/p' Cargo.toml)"
    if [ "$alloy_pinned" != "$alloy_locked" ]; then
      printf '::error::P20 violation: [workspace.dependencies] pins alloy "=%s" but the lock resolves %s. The pin comment claims it is the version evmlib resolves; make one of them true\n' "$alloy_pinned" "$alloy_locked"
      return 1
    fi
    printf 'OK: one alloy (%s), pinned exactly, and evmlib depends on that same one.\n' "$alloy_locked"
  else
    printf 'evmlib is not in the locked graph at all — the lockstep rule has no partner yet and holds vacuously.\n'
  fi

  # ── P20/D89 rule 5: one k256, and it is alloy-signer-local's ────────────
  # D89 (2026-08-02) moved the wallet light half into the DEFAULT graph over
  # a DIRECT exact-pinned `k256`, on one argument: D44's acceptance predicate
  # bottoms out in exactly `k256::SecretKey::from_slice`
  # (alloy-signer-local-1.8.3/src/private_key.rs:224-230 -> :52-54 ->
  # ecdsa-0.16.9/src/signing.rs:99-103), so calling that function ourselves
  # is the SAME predicate rather than a second implementation of it.
  #
  # That argument holds only while there is exactly ONE k256 and it is the
  # one `alloy-signer-local` resolves. Two k256 versions would fork the
  # accepted wallet-key set with nothing failing — the identical failure mode
  # rule 3 guards for alloy, so this is the identical mechanism: Cargo.lock
  # version-QUALIFIES a dependency entry (`"k256 0.14.0"`) if and only if the
  # package resolves to more than one version, so a BARE `"k256"` entry under
  # alloy-signer-local is the lock's own statement that there is one k256 and
  # both of us are on it.
  #
  # ADDITIVE: this rule relaxes, removes and re-scopes nothing above it.
  note "P20/D89: one k256, exact-pinned, and it is the one alloy-signer-local resolves"
  # Self-test FIRST (house pattern), in BOTH directions: the detector must
  # trip on a planted version-qualified entry in the exact shape Cargo.lock
  # emits, and must NOT trip on the bare entry that is the green case — a
  # detector that matches everything is as useless as one that matches
  # nothing.
  local k256_split_detector='^ "k256 [0-9]'
  if ! printf ' "k256 0.14.0",\n' | grep -qE "$k256_split_detector"; then
    printf '::error::D89 rule-5 self-test FAILED: the split-version detector does not match a planted version-qualified k256 entry — fix it before trusting any green verdict\n'
    return 1
  fi
  if printf ' "k256",\n' | grep -qE "$k256_split_detector"; then
    printf '::error::D89 rule-5 self-test FAILED: the split-version detector ALSO matches a bare k256 entry, so it can never be green for the right reason — fix it before trusting any verdict\n'
    return 1
  fi
  if grep -q '^name = "k256"$' Cargo.lock; then
    local k256_locked k256_pinned signer_k256
    k256_locked="$(awk '/^name = "k256"$/{f=1; next} f && /^version = /{gsub(/"/,"",$3); print $3; f=0}' Cargo.lock)"
    if [ "$(printf '%s\n' "$k256_locked" | grep -c .)" -ne 1 ]; then
      printf '::error::D89 violation: Cargo.lock carries %s k256 versions — the wallet light half and the pinned payment stack are no longer on one secp256k1, so D44 acceptance is forked:\n%s\n' "$(printf '%s\n' "$k256_locked" | grep -c .)" "$k256_locked"
      return 1
    fi
    k256_pinned="$(sed -nE 's/^k256 = \{ version = "=([^"]+)".*/\1/p' Cargo.toml)"
    if [ -z "$k256_pinned" ]; then
      printf '::error::D89 violation: [workspace.dependencies] carries no exact `k256 = { version = "=x.y.z" ... }` pin, but k256 is in the lock. D89 requires the light half ride an EXACT pin in lockstep with alloy/evmlib\n'
      return 1
    fi
    if [ "$k256_pinned" != "$k256_locked" ]; then
      printf '::error::D89 violation: [workspace.dependencies] pins k256 "=%s" but the lock resolves %s. The pin comment claims it is the version the alloy/evmlib graph resolves; make one of them true\n' "$k256_pinned" "$k256_locked"
      return 1
    fi
    if grep -q '^name = "alloy-signer-local"$' Cargo.lock; then
      signer_k256="$(awk '/^name = "alloy-signer-local"$/{f=1; next} f && /^\]$/{exit} f && /^ "k256/{print}' Cargo.lock)"
      if [ -z "$signer_k256" ]; then
        printf '::error::D89 violation: alloy-signer-local no longer depends on k256 at all — D44 acceptance is defined as what the PINNED stack accepts, and the function this rule pins us to has moved. Re-derive the rule (and D89 Evidence 4) before deleting it\n'
        return 1
      fi
      if printf '%s\n' "$signer_k256" | grep -qE "$k256_split_detector"; then
        printf '::error::D89 violation: alloy-signer-local depends on a version-QUALIFIED k256 (%s), which Cargo.lock emits only when k256 resolves to more than one version. Our light half would then validate wallet keys against a DIFFERENT secp256k1 than the payment path accepts\n' "$signer_k256"
        return 1
      fi
      printf 'OK: one k256 (%s), pinned exactly, and alloy-signer-local depends on that same one.\n' "$k256_locked"
    else
      printf 'OK: one k256 (%s), pinned exactly; alloy-signer-local is not in the lock, so the lockstep half holds vacuously.\n' "$k256_locked"
    fi
  else
    printf 'k256 is not in the locked graph at all — the wallet light half has no secp256k1 edge yet and this rule holds vacuously.\n'
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
    # `.devnet` is excluded for the same reason `target` is: it is
    # gitignored run output, and this lane's subject is what can be
    # COMMITTED. Found by the S17 gate run — `scripts/e2e-devnet.sh` boots a
    # devnet, `local-up` writes the funded Anvil key to `.devnet/env`
    # exactly where the runbook says it belongs, and pattern (5) then fired
    # on it. That made the two REQUIRED local lanes mutually exclusive: any
    # developer following CONTRIBUTING's devnet-gate instruction got a red
    # secret-guard for doing precisely the right thing, and the only way to
    # green it was to tear the devnet down — which is how a real hit would
    # have been explained away too.
    #
    # The exclusion cannot become a hole: `assert_gitignored` below fails
    # the lane if `.devnet/` ever stops being ignored, so "not scanned"
    # stays welded to "not committable".
    ex() { grep -rlaE --exclude-dir=.git --exclude-dir=target --exclude-dir=.devnet \
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
  # The exclusion above is only safe while `.devnet/` is genuinely
  # unstageable. Check that, rather than trusting it.
  if git rev-parse --git-dir >/dev/null 2>&1; then
    if ! git check-ignore -q .devnet/env 2>/dev/null; then
      printf '::error::secret-guard: .devnet/ is NOT gitignored, but this lane skips scanning it. Restore the .gitignore rule (the devnet export carries the funded wallet key) or drop the --exclude-dir=.devnet above.\n'
      return 1
    fi
    printf 'OK: .devnet/ is gitignored, so excluding it from the scan removes nothing committable.\n'
  fi
  # The real scan.
  if ! scan .; then
    printf '::error::secret-guard: vault-export/wallet-key file signature(s) found (paths above). No real secret material may ever be committed (project rule 6; testdata/README.md).\n'
    return 1
  fi
  printf 'OK: no vault-export/wallet-key signatures in the tree.\n'
}

# ── Q81/D61: the scheduled fuzz lane's monthly minute bill ─────────────────
#
# WHY A SCRIPT AND NOT A SENTENCE. Every prior instance of this failure mode
# in the project was a number recorded in prose that then drifted. This one
# has money attached: `fuzz-nightly.yml` shipped at daily x 4 targets x 900 s
# on 2026-07-28 and ran five times, unobserved, at a LOWER BOUND of
# 1 824 min/month — 91 % of the entire 2 000-minute GitHub Free allowance.
# Exhausting that allowance does not degrade this lane; GitHub blocks EVERY
# workflow in the repository, including the 19 required contexts. Q17's two
# incoming targets would have taken it to 137 % with nothing going red.
#
# THE KNOB IS `seconds`. Cadence is NOT a knob: it protects the corpus, which
# GitHub evicts after 7 days without access, and accumulation is the only
# reason this lane exists rather than `fuzz-smoke` (D61 E2). Hence the
# separate cadence-floor arm below — without it the budget could be satisfied
# by going monthly, silently destroying the thing being paid for.
#
# The ceiling is RAISE-ONLY BY DECISION, never by an implementer needing a
# build to go green.
FUZZ_BUDGET_CEILING_MINUTES=700
# 35 % of the 2 000-minute allowance — the named share this lane is
# permitted, chosen (D61 residual risk 4) against the known competing draws:
# 19 required contexts including a 10x-billed macOS lane on every push, a
# weekly cold-build devnet lane, and a weekly advisory lane.
FUZZ_BUDGET_ALLOWANCE_MINUTES=2000
# Checkout + rustup + rust-cache + instrumented build + selftest + corpus
# report, per run.
#
# MEASURED at 2026-08-02 over the five 900 s runs that had already happened
# (`gh api …/workflows/fuzz-nightly.yml/runs`, run_started_at -> updated_at):
# 61.6, 61.6, 61.7, 61.7 and 62.8 minutes against 60 minutes of fuzzing —
# i.e. ~1.9 min of real overhead, because both caches hit. 15 is therefore
# ~8x the measured value and is KEPT ON PURPOSE: over-estimating the bill is
# the safe direction for a guard whose failure mode is "every workflow in the
# repository stops". Lowering it loosens the guard and is a decision, not an
# implementer's call. (D61's revisit trigger anticipated the opposite
# finding — an overhead far ABOVE 15 — and that is not what the runs say.)
FUZZ_BUDGET_PER_RUN_OVERHEAD_MINUTES=15
# The corpus cache is evicted after 7 days without access (D61 E2); 5 leaves
# margin for a delayed or skipped run. Measured 2026-08-02: GitHub started
# these runs at ~06:15Z against a 03:41Z cron, so scheduled instants slip by
# hours under load — another reason not to sit on the 7-day boundary.
FUZZ_BUDGET_MAX_GAP_DAYS=5

# Day-of-week numbers a cron selects, sorted, one per line. 0 and 7 are both
# Sunday; normalised to 0. Prints `ERR …` and returns 1 on anything it cannot
# parse — refusing to guess, because a cron this misreads is a bill this
# under-reports.
cron_days() {
  local cron="$1" f=() item lo hi d out=""
  read -r -a f <<<"$cron"
  if [ "${#f[@]}" -ne 5 ]; then
    printf 'ERR expected five cron fields, got %s in `%s`\n' "${#f[@]}" "$cron"; return 1
  fi
  # With BOTH day-of-month and day-of-week restricted, cron ORs them and the
  # day-of-week model below is simply wrong. Refuse rather than mis-bill.
  if [ "${f[2]}" != '*' ] || [ "${f[3]}" != '*' ]; then
    printf 'ERR day-of-month and month must both be `*` (cron ORs DOM with DOW when both are restricted, and this model reads DOW alone): `%s`\n' "$cron"; return 1
  fi
  if [ "${f[4]}" = '*' ]; then
    out=$'0\n1\n2\n3\n4\n5\n6'
  else
    local IFS=','
    for item in ${f[4]}; do
      case "$item" in
        [0-7])       lo="$item"; hi="$item" ;;
        [0-7]-[0-7]) lo="${item%-*}"; hi="${item#*-}" ;;
        *) printf 'ERR unsupported day-of-week item `%s` (this reader takes digits, comma lists and ranges — a step or a name is a change worth being explicit about)\n' "$item"; return 1 ;;
      esac
      if [ "$lo" -gt "$hi" ]; then printf 'ERR reversed range `%s`\n' "$item"; return 1; fi
      for (( d=lo; d<=hi; d++ )); do out+="$(( d % 7 ))"$'\n'; done
    done
  fi
  printf '%s\n' "$out" | grep -v '^$' | sort -un
}

# Runs per month x100. GitHub fires a weekly cron 52 times a year, so
# `52 x ndays / 12` — rounded, not truncated, which is what makes `1,4`
# report 8.67 rather than 8.66. Deliberately NOT 365/12: this is a
# day-of-WEEK schedule.
cron_runs_per_month_x100() {
  local days; days="$(cron_days "$1")" || { printf '%s\n' "$days"; return 1; }
  local n; n="$(printf '%s\n' "$days" | grep -c .)"
  printf '%s\n' "$(( (5200 * n + 6) / 12 ))"
}

# Longest gap in days between consecutive runs, including the week wrap.
cron_max_gap_days() {
  local days d=() n i gap max=0
  days="$(cron_days "$1")" || { printf '%s\n' "$days"; return 1; }
  mapfile -t d <<<"$days"
  n=${#d[@]}
  for (( i=0; i<n; i++ )); do
    if [ $(( i + 1 )) -lt "$n" ]; then gap=$(( d[i+1] - d[i] )); else gap=$(( d[0] + 7 - d[i] )); fi
    [ "$gap" -gt "$max" ] && max="$gap"
  done
  printf '%s\n' "$max"
}

# Monthly minutes x100 for <targets> <seconds/target> <runs-per-month-x100>.
# scripts/fuzz.sh runs targets SEQUENTIALLY (cmd_time_budget loops and passes
# -max_total_time per target), so the per-run fuzzing cost is the product.
fuzz_budget_minutes_x100() {
  printf '%s\n' "$(( $1 * $2 * $3 / 60 + FUZZ_BUDGET_PER_RUN_OVERHEAD_MINUTES * $3 ))"
}

fmt_x100() { printf '%s.%02d' "$(( $1 / 100 ))" "$(( $1 % 100 ))"; }

lane_fuzz_budget() {
  local fail=0

  # ── Self-test FIRST, every run (the house pattern) ──────────────────────
  # A budget checker that has never been observed failing is the exact defect
  # this project keeps finding.
  note "fuzz-budget self-test: the arithmetic, the cron reader, and both directions of the verdict"
  # `cron` is declared here rather than at its first `for` loop below: a loop
  # variable that has not been declared `local` first assigns to the GLOBAL
  # scope, and a lane leaking a global into a script that runs nine of them
  # is the kind of thing that is harmless until it is not.
  local got want cron
  # (1) cron reader. Getting the day-of-week field wrong would make the guard
  #     read a DAILY lane as weekly and pass it — the single most damaging way
  #     this checker could be wrong.
  for want in "41 3 * * 1,4|867|4" "41 3 * * *|3033|1" "41 3 * * 1|433|7" "41 3 * * 1-5|2167|3"; do
    local cron="${want%%|*}" rest="${want#*|}"
    got="$(cron_runs_per_month_x100 "$cron")/$(cron_max_gap_days "$cron")"
    if [ "$got" != "${rest%|*}/${rest#*|}" ]; then
      printf '::error::fuzz-budget self-test FAILED: cron `%s` read as %s, expected %s/%s\n' \
        "$cron" "$got" "${rest%|*}" "${rest#*|}"
      fail=1
    fi
  done
  # (2) the cron reader REFUSES what it cannot model, rather than guessing.
  for cron in "41 3 * *" "41 3 1 * 1,4" "41 3 * * MON" "41 3 * * */2"; do
    if cron_days "$cron" >/dev/null 2>&1; then
      printf '::error::fuzz-budget self-test FAILED: `%s` was accepted; an unparseable cron must be refused, not guessed at\n' "$cron"
      fail=1
    fi
  done
  # (3) RED direction, on a planted seven-target array at the committed
  #     seconds and cadence: 7 x 600 s twice weekly is 736.95 min > 700.
  got="$(fuzz_budget_minutes_x100 7 600 867)"
  if [ "$got" -le $(( FUZZ_BUDGET_CEILING_MINUTES * 100 )) ]; then
    printf '::error::fuzz-budget self-test FAILED: a planted SEVEN-target array computes %s min, which does NOT exceed the %s ceiling — the checker cannot fail, so its green means nothing\n' \
      "$(fmt_x100 "$got")" "$FUZZ_BUDGET_CEILING_MINUTES"
    fail=1
  fi
  # (4) GREEN direction: six targets (i.e. after Q17/A23) must still fit, or
  #     the ceiling is refusing the configuration D61 §3 costed.
  got="$(fuzz_budget_minutes_x100 6 600 867)"
  if [ "$got" -gt $(( FUZZ_BUDGET_CEILING_MINUTES * 100 )) ]; then
    printf '::error::fuzz-budget self-test FAILED: six targets at 600 s twice weekly computes %s min and does not fit the %s ceiling — D61 §3 costed that arrangement at ~650. One of the constants is wrong\n' \
      "$(fmt_x100 "$got")" "$FUZZ_BUDGET_CEILING_MINUTES"
    fail=1
  fi
  # (5) RED-BEFORE-GREEN, the arm that proves this guard is wired to reality
  #     rather than fitted to the numbers that follow it: the configuration
  #     this lane SHIPPED WITH — 4 x 900 s DAILY — must be refused. It is
  #     also a permanent tripwire against restoring the daily cadence.
  got="$(fuzz_budget_minutes_x100 4 900 3033)"
  if [ "$got" -le $(( FUZZ_BUDGET_CEILING_MINUTES * 100 )) ]; then
    printf '::error::fuzz-budget self-test FAILED: the pre-D61 committed configuration (4 targets x 900 s DAILY) computes %s min and passes the ceiling. That configuration spent 91%% of the whole allowance; a guard that admits it is measuring the wrong thing\n' \
      "$(fmt_x100 "$got")"
    fail=1
  fi
  [ "$fail" -eq 0 ] || return 1
  printf 'self-test OK: cron reader exact on 4 crons and refuses 4 malformed ones; 7 targets RED (%s), 6 targets GREEN (%s), the shipped 4x900-daily RED (%s)\n' \
    "$(fmt_x100 "$(fuzz_budget_minutes_x100 7 600 867)")" \
    "$(fmt_x100 "$(fuzz_budget_minutes_x100 6 600 867)")" \
    "$(fmt_x100 "$(fuzz_budget_minutes_x100 4 900 3033)")"

  # ── The live arm: read the committed sources only ───────────────────────
  note "fuzz-budget: the committed scheduled configuration against the ${FUZZ_BUDGET_CEILING_MINUTES}-minute ceiling"
  local wf="$repo/.github/workflows/fuzz-nightly.yml"
  [ -f "$wf" ] || die "fuzz-budget: $wf is missing — this lane's whole subject is gone; delete the lane deliberately or restore the workflow"
  # Target count from scripts/fuzz.sh's own TARGETS array, via its `targets`
  # subcommand — reading the array rather than re-parsing the file, so the
  # guard and the runner can never disagree about what runs.
  local targets seconds_default seconds_schedule n
  targets="$(bash "$repo/scripts/fuzz.sh" targets | grep -c .)"
  # Anti-vacuity, on every parse below: a failed parse yields an empty value
  # that arithmetic reads as ZERO, and a zero-cost lane always passes. Each
  # is checked for exactly one numeric result.
  if ! [ "$targets" -ge 1 ] 2>/dev/null; then
    printf '::error::fuzz-budget: scripts/fuzz.sh targets produced %s target(s) — the parse failed, and a zero-target bill passes any ceiling\n' "$targets"
    return 1
  fi
  cron="$(sed -nE 's/^[[:space:]]*-[[:space:]]*cron:[[:space:]]*"([^"]+)".*/\1/p' "$wf")"
  n="$(printf '%s\n' "$cron" | grep -c .)"
  if [ "$n" -ne 1 ]; then
    printf '::error::fuzz-budget: found %s `cron:` line(s) in fuzz-nightly.yml, expected exactly 1. A second schedule multiplies the bill and this reader would price only one\n' "$n"
    return 1
  fi
  # The workflow_dispatch default, and the literal a SCHEDULED run actually
  # uses. `schedule:` supplies no inputs, so the `|| 'NNN'` fallback in the
  # run step is what spends the money; requiring the two to agree is what
  # stops this guard pricing a number the scheduled run never sees.
  seconds_default="$(awk '/^[[:space:]]*seconds:[[:space:]]*$/{f=1} f && /default:/{gsub(/[^0-9]/,"",$2); print $2; exit}' "$wf")"
  seconds_schedule="$(sed -nE "s/.*fuzz\.sh long .*\|\|[[:space:]]*'([0-9]+)'.*/\1/p" "$wf")"
  for got in "$seconds_default" "$seconds_schedule"; do
    if ! [ "${got:-0}" -ge 1 ] 2>/dev/null; then
      printf '::error::fuzz-budget: could not read a seconds-per-target literal from fuzz-nightly.yml (dispatch default=%s, schedule fallback=%s). An unparsed budget reads as zero and passes\n' \
        "${seconds_default:-<none>}" "${seconds_schedule:-<none>}"
      return 1
    fi
  done
  if [ "$seconds_default" != "$seconds_schedule" ]; then
    printf '::error::fuzz-budget: the workflow_dispatch default (%s s) and the scheduled fallback (%s s) disagree. A scheduled run supplies no inputs, so it spends the SECOND number while a reader of the first believes the first — make them equal\n' \
      "$seconds_default" "$seconds_schedule"
    return 1
  fi
  local rpm100 gap minutes100
  rpm100="$(cron_runs_per_month_x100 "$cron")" || { printf '::error::fuzz-budget: %s\n' "$rpm100"; return 1; }
  gap="$(cron_max_gap_days "$cron")" || { printf '::error::fuzz-budget: %s\n' "$gap"; return 1; }
  minutes100="$(fuzz_budget_minutes_x100 "$targets" "$seconds_default" "$rpm100")"
  printf 'cron `%s` -> %s run(s)/month, max gap %s day(s)\n' "$cron" "$(fmt_x100 "$rpm100")" "$gap"
  printf '%s target(s) x %s s = %s min fuzzing/run, + %s min overhead/run\n' \
    "$targets" "$seconds_default" "$(( targets * seconds_default / 60 ))" "$FUZZ_BUDGET_PER_RUN_OVERHEAD_MINUTES"
  printf 'monthly cost: %s min = %s%% of the %s-minute allowance (ceiling %s min = %s%%)\n' \
    "$(fmt_x100 "$minutes100")" \
    "$(( minutes100 / FUZZ_BUDGET_ALLOWANCE_MINUTES ))" "$FUZZ_BUDGET_ALLOWANCE_MINUTES" \
    "$FUZZ_BUDGET_CEILING_MINUTES" "$(( FUZZ_BUDGET_CEILING_MINUTES * 100 / FUZZ_BUDGET_ALLOWANCE_MINUTES ))"
  if [ "$minutes100" -gt $(( FUZZ_BUDGET_CEILING_MINUTES * 100 )) ]; then
    printf '::error::D61 violation: the scheduled fuzz lane would cost %s min/month against a %s-minute ceiling. THE KNOB IS `seconds`, not the cadence — cadence protects the corpus GitHub evicts after 7 days (D61 E2). Lower `seconds` in fuzz-nightly.yml (BOTH literals) in this same commit. The ceiling is raise-only by decision: exhausting the %s-minute allowance blocks EVERY workflow in the repository, not just this one\n' \
      "$(fmt_x100 "$minutes100")" "$FUZZ_BUDGET_CEILING_MINUTES" "$FUZZ_BUDGET_ALLOWANCE_MINUTES"
    return 1
  fi
  if [ "$gap" -gt "$FUZZ_BUDGET_MAX_GAP_DAYS" ]; then
    printf '::error::D61 violation: the cron leaves %s days between runs, over the %s-day cadence floor. GitHub deletes a cache not accessed for 7 days, and corpus ACCUMULATION is the only thing distinguishing this lane from fuzz-smoke — a schedule that meets the budget by running less often has destroyed what it is paying for\n' \
      "$gap" "$FUZZ_BUDGET_MAX_GAP_DAYS"
    return 1
  fi
  printf 'OK: %s min/month, within the %s-minute ceiling, and the cadence keeps the corpus cache warm.\n' \
    "$(fmt_x100 "$minutes100")" "$FUZZ_BUDGET_CEILING_MINUTES"
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
  fuzz-budget)      lane_fuzz_budget ;;
  *) die "usage: scripts/ci-lanes.sh <$(printf '%s' "$LANES" | tr ' ' '|')> | --list | --self-test" ;;
esac
