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
#   audit-deny        cargo-deny advisories/bans/sources/licenses
#   fuzz-budget       self-test, then the scheduled fuzz lane's monthly
#                     minute cost against its named ceiling (D61)
#   anchor-net-policy self-test, then Q16's no-real-anchor-network policy:
#                     the environment arm is armed in every workflow and in
#                     the local gate, exactly one HTTP client is declared and
#                     only by antseal-anchor, and every URL-valued constant
#                     is covered by the gate's endpoint walk
#   custody-log       self-test, then Q261's append-only guard over
#                     docs/signing/key-custody.md §10 — the signing-key
#                     custody log, whose own rule is "Never edit a row".
#                     Walks every commit from the file's birth forward and
#                     reds on any row that was edited, deleted, reordered or
#                     pushed down, honouring the one replacement §11 registers
#   cargo-free        the test-of-the-test for the guard that asserts CI's
#                     `traceability` job runs no cargo (D124/Q182). The guard
#                     itself is two steps ON that job — `cargo-free.sh --arm`
#                     and `--verdict` — which cannot be run anywhere but a
#                     runner; what CAN be run before a push is the proof that
#                     the guard can go red, and Q43's own opening defect is a
#                     guard whose command had never been executed
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

LANES="dep-graph cross-os golden-vectors tamper-matrix cbor-drift-guard traceability ci-shell secret-guard audit-deny fuzz-budget anchor-net-policy cargo-free custody-log"

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
  if ! grep -qF "$detector" <<<"$planted" ; then
    printf '::error::dep-graph self-test FAILED: the detector does not match a planted self_encryption dependency entry — fix the detector before trusting any green verdict\n'
    return 1
  fi
  local declared
  declared="$(cargo metadata --format-version 1 --no-deps --locked)" || return 1
  if grep -qF "$detector" <<<"$declared" ; then
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
  if ! grep -qxF 'antseal-net ant-core' <<<"$stack_edges" ; then
    printf '::error::S23 scan found no `antseal-net ant-core` edge — S2 says that edge exists, so the metadata parse is broken, not the tree clean. Edges found:\n%s\n' "${stack_edges:-(none)}"
    return 1
  fi
  stack_strays="$(printf '%s\n' "$stack_edges" | grep -vE "$stack_owners" | grep -v '^$' || true)"
  if [ -n "$stack_strays" ]; then
    printf '::error::S23/S2 violation: a crate outside {antseal-net, devnet-launcher} DECLARES an upstream payment-stack edge. antseal-net is the churn-isolation boundary (MVP-SPEC.md lines 60-69) and an ant-core bump must stay bounded to it (S20). `<crate> <dependency>`:\n%s\n' "$stack_strays"
    grep -nE '^[[:space:]]*(ant-core|ant-protocol|alloy|bytes)[[:space:].]' crates/*/Cargo.toml 2>/dev/null || true
    return 1
  fi
  printf 'OK: all %s declared payment-stack edge(s) belong to antseal-net or devnet-launcher.\n' "$(grep -c . <<<"$stack_edges")"

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
  # HTTP/TLS half added at D90/Q83 (2026-08-02): `ureq` joins because it is
  # the client D90 adopts for `antseal-anchor`, and
  # `rustls`/`native-tls`/`openssl`/`webpki-roots`/`httparse`/`http` join it
  # so no transport crate can enter antseal-core without one of them being
  # named. antseal-anchor sits ABOVE core, so this is a regression guard on
  # a direction the adoption makes newly plausible, not a claim about A3.
  #
  # SCOPE (D90, 2026-08-02): this is a DENYLIST. It catches the crates
  # named and nothing else — `libc`, `regex`, `env_logger`, `is-terminal`
  # and `termcolor` all pass it today, measured. The lane's headline
  # ("must be I/O-free") is therefore stronger than this assertion, and
  # closing that gap with a positive allowlist of antseal-core's permitted
  # normal-graph names is Q74's work — landed as layer 2 below. Until then,
  # treat a green verdict HERE as "none of the named offenders is present",
  # not as "the graph is pure".
  note "antseal-core's NORMAL graph: none of the DECIDED-prohibited crates"
  local forbidden='^(tokio|async-std|smol|hyper|reqwest|ureq|ureq-proto|attohttpc|isahc|curl|rustls|native-tls|openssl|webpki-roots|httparse|http|mio|socket2|getrandom|rand|rand_chacha) ' tree offenders
  # Self-test FIRST, in BOTH directions — the D89 rule-5 pattern, and the
  # thing this rule went without from S4 until Q74. It was the ONLY rule in
  # this lane with no planted fault (its siblings self-test above and
  # below), which is very likely why its hole survived two waves: nobody had
  # ever watched it bite. The negative direction is load-bearing, not
  # decoration: the `^rand ` trailing space is the only thing keeping
  # `rand_core` — a real member of the set below — out of the ban.
  #
  # THREE directions since Q83, because the pattern now has two independent
  # halves and one planted name only exercises one of them. `tokio` proves
  # the S4 half still bites; `ureq` proves the D90 half does, in the shape
  # `cargo tree --prefix none` actually emits; `rand_core` proves the rule
  # still tells the permitted pure-trait crate apart from the banned family.
  # A pattern edit that dropped the whole HTTP alternation would leave the
  # tokio direction green, which is precisely why it is not sufficient.
  if ! printf 'tokio v1.49.0\n' | grep -qE "$forbidden"; then
    printf '::error::dep-graph prohibition self-test FAILED: the detector does not match a planted `tokio` tree line — fix it before trusting any green verdict\n'
    return 1
  fi
  if ! printf 'ureq v3.3.0\n' | grep -qE "$forbidden"; then
    printf '::error::dep-graph prohibition self-test FAILED: the forbidden-crate pattern does not match a planted `ureq v3.3.0` line in the shape `cargo tree --prefix none` emits — the D90 HTTP/TLS half is gone. Fix it before trusting any green verdict\n'
    return 1
  fi
  if printf 'rand_core v0.10.1\n' | grep -qE "$forbidden"; then
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
  if ! grep -qxF 'antseal-core' <<<"$core_names" ; then
    printf '::error::dep-graph: the parsed package set does not contain `antseal-core` itself, so `cargo tree` failed or its output shape changed — every verdict here would be vacuous. Parsed %s name(s)\n' \
      "$(grep -c . <<<"$core_names")"
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
    "$(grep -c . <<<"$core_names")"

  # ── D18 §5 R6: the SHIPPED page module's graph (R22) ────────────────────
  # The rule above guards `antseal-core`, which is what the page's WASM is
  # BUILT FROM. This one guards `antseal-wasm`, which is what the page
  # actually LOADS — the wasm-bindgen boundary D18 ruled into its own package
  # so that none of the five lanes above had to change to accommodate it.
  #
  # It is the same Q74 idiom, deliberately, with three differences and a
  # reason for each:
  #
  #   * `--target wasm32-unknown-unknown`, NOT `--target all`. Unlike
  #     antseal-core this package ships to exactly ONE target, so the
  #     over-reporting `--target all` buys nothing here and would admit names
  #     no build contains (D18 §5 R6).
  #   * the expected set is DERIVED from `$core_reviewed` above rather than
  #     restated. A second copy of 84 names is a second copy that will
  #     diverge; the boundary's contribution is the seven-name delta below.
  #   * because the target is narrower than `--target all`, four names in the
  #     set above are legitimately ABSENT here — and that absence is asserted
  #     in BOTH directions, so the exclusion list cannot rot into a silent
  #     permission (third check below).
  #
  # WHY THIS IS THE STRUCTURAL HALF OF "no I/O inside the WASM module": R22's
  # `Do` says it and D18 §5 refuses to leave it to review. A dependency graph
  # decides what CAN be reached; `scripts/wasm-imports.mjs` decides what the
  # built artifact actually imports. Neither alone is the property, and
  # together they are what makes the sentence enforced.
  note "antseal-wasm's wasm32 graph: none of the DECIDED-prohibited crates (D18 §5 R3)"
  # `js-sys`/`web-sys` are the crates through which host capability — fetch,
  # XMLHttpRequest, localStorage, Date — becomes reachable from Rust, so they
  # are named here to get the RIGHT DIAGNOSIS: "you added js-sys" rather than
  # "an unreviewed package arrived". `wasm-bindgen` itself is NOT banned — it
  # is the boundary — and the trailing space plus the `-` boundary keep the
  # `wasm-bindgen-*` family it legitimately brings from matching `web-`/`js-`.
  # The async/HTTP half repeats layer 1's names for the same reason it exists
  # there: this graph ships to a browser, where a fetch is one edge away.
  local wasm_forbidden='^(js-sys|web-sys|wasm-bindgen-futures|web-time|getrandom|rand|rand_chacha|tokio|async-std|smol|hyper|reqwest|ureq|http|rustls|native-tls|openssl|console_error_panic_hook|serde-wasm-bindgen|serde_wasm_bindgen) '
  # Self-test FIRST, in BOTH directions (the house pattern, and the reason
  # layer 1 above went two waves without anyone watching it bite): the
  # detector must match the capability crate it exists to refuse, and must NOT
  # match the boundary crate the decision admits. A pattern that swallowed
  # `wasm-bindgen` could never be green for the right reason.
  if ! printf 'js-sys v0.3.103\n' | grep -qE "$wasm_forbidden"; then
    printf '::error::D18 R6 prohibition self-test FAILED: the detector does not match a planted `js-sys` tree line — js-sys is the crate through which `fetch` becomes reachable, so a detector that cannot see it makes every green verdict below meaningless\n'
    return 1
  fi
  if printf 'wasm-bindgen v0.2.126\n' | grep -qE "$wasm_forbidden"; then
    printf '::error::D18 R6 prohibition self-test FAILED: the detector ALSO matches `wasm-bindgen`, which D18 §5 R3 ADMITS as the boundary itself. The rule can then never be green for the right reason\n'
    return 1
  fi
  local wasm_tree wasm_names wasm_offenders
  wasm_tree="$(cargo tree -p antseal-wasm -e normal --target wasm32-unknown-unknown --prefix none --locked)" || return 1
  printf '%s\n' "$wasm_tree"
  wasm_offenders="$(printf '%s\n' "$wasm_tree" | grep -E "$wasm_forbidden" || true)"
  if [ -n "$wasm_offenders" ]; then
    printf '\n::error::D18 §5 R3 violation: a DECIDED-PROHIBITED crate entered the SHIPPED verifier-page module graph. js-sys/web-sys/wasm-bindgen-futures/web-time/getrandom are refused BY DECISION — refusing them is what makes R22 "No I/O inside the WASM module" a property of the graph rather than of a reviewer attention:\n'
    printf '%s\n' "$wasm_offenders"
    return 1
  fi
  printf 'OK: no decided-prohibited crate in the shipped page module graph.\n'

  note "antseal-wasm's wasm32 graph is EXACTLY core's reviewed set + the boundary (D18 §5 R6)"
  # The boundary's whole contribution, measured at D18 §1 (k) and re-measured
  # at R22's landing. Six names plus the package itself; each argued here, in
  # the Q74 style, because the point of the idiom is that a human makes the
  # argument once, at the site, for every name admitted.
  local wasm_added='antseal-wasm        # the package itself, as cargo tree roots it

  # --- the wasm-bindgen boundary (D18 §5 R3/R4) ---
  wasm-bindgen        # THE boundary. Admitted deliberately and alone: it is the
                      #   crate that makes a typed JS error and a panic hook
                      #   possible, which R22 Accept row 3 requires and a raw C
                      #   ABI cannot deliver (D18 §4.1). Declared
                      #   default-features = false, features = ["std"];
                      #   `serde-serialize` is prohibited (D18 §5 R5).
  wasm-bindgen-macro  # proc-macro; compile-time only, contributes no runtime code
  wasm-bindgen-macro-support
  wasm-bindgen-shared
  bumpalo             # <- wasm-bindgen-macro-support; a bump ALLOCATOR. Arena
                      #   allocation over memory the caller owns: no syscall, no
                      #   file, no clock.
  once_cell           # <- wasm-bindgen-macro-support; lazy initialization of
                      #   in-memory statics. No I/O of any kind.'
  # Names in the `--target all` set above that no wasm32 graph contains. Each
  # is annotated in that set as target-conditional; listed here so the two
  # sets can be compared at all, and asserted ABSENT below so this list can
  # never become a quiet permission.
  local wasm_absent='cpufeatures             # x86 CPU-feature detection; not compiled for wasm32
  libc                    # <- cpufeatures, non-x86 only (already annotated as absent above)
  fiat-crypto             # <- curve25519-dalek 32-bit backend (already annotated as absent above)
  curve25519-dalek-derive # <- curve25519-dalek, 64-bit serial backend only'
  wasm_names="$(printf '%s\n' "$wasm_tree" | names_of)"
  # Anti-vacuity, same reason as above: the root is always in its own tree, so
  # its absence means the parse broke rather than the graph being clean.
  if ! grep -qxF 'antseal-wasm' <<<"$wasm_names" ; then
    printf '::error::D18 R6: the parsed package set does not contain `antseal-wasm` itself, so `cargo tree` failed or its output shape changed — every verdict here would be vacuous. Parsed %s name(s)\n' \
      "$(grep -c . <<<"$wasm_names")"
    return 1
  fi
  local wasm_expected wasm_unknown wasm_stale wasm_present_absent
  wasm_expected="$(cat <(printf '%s\n' "$core_reviewed" | strip_reviewed) \
                       <(printf '%s\n' "$wasm_added" | strip_reviewed) |
    sort -u | comm -23 - <(printf '%s\n' "$wasm_absent" | strip_reviewed))"
  # Self-test FIRST, over a planted tree, in BOTH directions: the extractor
  # must report an intruder and must NOT report names the expectation
  # contains. `js-sys` is the intruder on purpose — it is the realistic one.
  local wasm_planted wasm_planted_unknown
  wasm_planted='antseal-wasm v0.0.0 (/x/crates/antseal-wasm)
wasm-bindgen v0.2.126
sha2 v0.11.0
js-sys v0.3.103'
  wasm_planted_unknown="$(printf '%s\n' "$wasm_planted" | names_of \
    | comm -23 - <(printf '%s\n' "$wasm_expected") | tr '\n' ' ')"
  if [ "$wasm_planted_unknown" != "js-sys " ]; then
    printf '::error::D18 R6 reviewed-set self-test FAILED: over a planted tree of {antseal-wasm, wasm-bindgen, sha2, js-sys} the check reported [%s] — it must report exactly `js-sys`. Fix it before trusting any green verdict\n' "$wasm_planted_unknown"
    return 1
  fi
  # The exclusion-list direction runs FIRST, and the order is the whole point:
  # a name that is both excluded as "absent on wasm32" and actually present is
  # ALSO an unreviewed arrival, so the generic check below would fire on it and
  # send the reader to add it to `wasm_added` — the wrong repair for the wrong
  # diagnosis. Ordered the other way this arm is unreachable, which is how a
  # check quietly becomes decoration (measured at R22's landing: with the
  # generic check first, a planted `blake3` in the exclusion list reddened as
  # "package entered without review").
  wasm_present_absent="$(comm -12 <(printf '%s\n' "$wasm_names") <(printf '%s\n' "$wasm_absent" | strip_reviewed))"
  if [ -n "$wasm_present_absent" ]; then
    printf '::error::D18 R6: package(s) excluded as "absent on wasm32" ARE in the wasm32 graph. The exclusion list is a statement about the target, not a permission; a name that arrived must be reviewed into `wasm_added` instead:\n'
    printf '%s\n' "$wasm_present_absent" | sed 's/^/  ! /'
    return 1
  fi
  wasm_unknown="$(comm -23 <(printf '%s\n' "$wasm_names") <(printf '%s\n' "$wasm_expected"))"
  if [ -n "$wasm_unknown" ]; then
    printf '::error::D18 §5 R6 violation: package(s) entered the SHIPPED verifier-page module NORMAL graph without review. This graph IS what the browser executes and R22 requires it to do no I/O; that property is argued per entry by a human, not detected by this lane. Read what each of these pulls in, then add it to `wasm_added` above IN THE SAME COMMIT:\n'
    printf '%s\n' "$wasm_unknown" | sed 's/^/  + /'
    printf 'Provenance: cargo tree -p antseal-wasm -e normal --target wasm32-unknown-unknown --locked -i <name>\n'
    return 1
  fi
  wasm_stale="$(comm -13 <(printf '%s\n' "$wasm_names") <(printf '%s\n' "$wasm_expected"))"
  if [ -n "$wasm_stale" ]; then
    printf '::error::D18 R6: the expected set names package(s) that are no longer in the shipped graph. A list carrying names that are not there has stopped describing the graph — delete them from `wasm_added` (or move them to `wasm_absent` WITH a reason if they went target-conditional):\n'
    printf '%s\n' "$wasm_stale" | sed 's/^/  - /'
    return 1
  fi
  printf 'OK: antseal-wasm wasm32 normal graph is exactly the %s expected package(s) — core reviewed set + %s boundary name(s), minus %s absent on this target.\n' \
    "$(grep -c . <<<"$wasm_names")" \
    "$(printf '%s\n' "$wasm_added" | strip_reviewed | grep -c .)" \
    "$(printf '%s\n' "$wasm_absent" | strip_reviewed | grep -c .)"

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
    if ! grep -qF ' (/' <<<"$planted_parent" ; then
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
  if [ "$rc" -ne 0 ] || ! grep -qE '^ant-node v' <<<"$devnet_tree" ; then
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
    if grep -qE "$split_detector" <<<"$evmlib_alloy" ; then
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
      if grep -qE "$k256_split_detector" <<<"$signer_k256" ; then
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

# Q16: the STATIC half of the no-real-anchor-network policy.
#
# The enforcing half is a runtime gate in the anchor HTTP substrate
# (`crates/antseal-anchor/src/http/offline.rs`), executed by the `test` lane
# — this lane does not repeat it. It checks the three things a runtime gate
# cannot see about itself: that its environment arm is actually armed in
# every venue, that no second HTTP client exists to route around it, and that
# no endpoint constant has appeared outside the walk that proves the refusal.
#
# Python-only and no network, so it rides in the `traceability` job beside
# `ci-shell` and `fuzz-budget` rather than costing a new required-status
# context (the set stays at 19). The cargo half of that placement argument is
# no longer stated here: `scripts/cargo-free.sh` asserts it on every run of
# that job and states the property once, in its own header (D124/Q182). Its
# own six planted faults run first, every run.
lane_anchor_net_policy() {
  if ! python3 scripts/check-anchor-net.py --self-test; then
    printf '::error::check-anchor-net self-test FAILED — the policy check stayed green over a planted fault, so a green run below would prove nothing\n'
    return 1
  fi
  python3 scripts/check-anchor-net.py
}

# Q261 / D157 §2 R9: `docs/signing/key-custody.md` §10 is an APPEND-ONLY log,
# and until this lane it said so with nothing behind it.
#
# §10 is the record of what was done to the project signing key and when. Its
# whole evidentiary value rests on rows never changing — the file says
# *"Never edit a row"* in terms — and the failure mode is silent by
# construction: a row edited to say an act was taken reads exactly like a row
# that always said so, and the log is the only place that history lives.
# Measured 2026-08-22, `grep -rn key-custody scripts/` returned ONE hit, a
# prose string inside a `check-copy-style.py` rationale. Nothing checked it.
#
# The check walks the file from its BIRTH COMMIT forward, one state per commit
# that touched it, then the working tree, and requires each state's §10 rows to
# be a prefix-extension of the one before: an append passes, a disturbance to
# an already-written row reds and NAMES the row. The one exception — the
# placeholder row replaced on 2026-08-19 — is read out of §11's fenced quote at
# run time rather than hardcoded, because a hardcoded list drifts from the
# document it exists to track.
#
# WHY IT IS NOT A BIRTH-VERSUS-TODAY DIFF. D157 §2 R9 measured that too. Once
# the single exception is registered, the birth baseline is EMPTY and the
# comparison can never redden — this project's dominant defect class. The walk
# reports `pinned=`, the count of row comparisons actually performed, and a run
# that pins zero is a hard error rather than a pass.
#
# Python-only, no cargo, no network, milliseconds — so it rides beside
# `ci-shell`, `anchor-net-policy` and `fuzz-budget` rather than costing a new
# required-status context. Its `--self-test` runs SIXTEEN arms — 10 planted
# faults (one per violation class, one per parser refusal, one per exception
# failure mode), 3 GREEN CONTROLS, 2 derived property assertions and a
# no-writes hygiene check — and prints that tally DERIVED from the arms that
# actually ran, so this comment and the run visibly disagree if an arm is
# added without updating it. The green controls are required by name: a suite
# of red arms alone passes on a check that reddens on everything. It reads the
# log ABOUT the key and never the key: no maintainer act, no secret material.
lane_custody_log() {
  if ! python3 scripts/check-custody-log.py --self-test; then
    printf '::error::check-custody-log self-test FAILED — the append-only check stayed green over a planted fault, so a green run below would prove nothing\n'
    return 1
  fi
  python3 scripts/check-custody-log.py
}

# D124/Q182: the guard that asserts CI's `traceability` job invokes no cargo,
# rustc or rustup — including from steps not yet written.
#
# THE GUARD ITSELF CANNOT RIDE HERE, and that asymmetry is the point rather
# than an omission. `--arm` writes to `$GITHUB_PATH` so that the shims cover
# every LATER STEP OF THE SAME JOB, which is a runner mechanism with no local
# equivalent; running it from this script would mask one process and prove
# nothing about a job. So the two halves land in the two venues that can hold
# them: the assertion is two steps on the `traceability` job (which since
# D138/Q239 lives in `.github/workflows/ci-always.yml`, unchanged in id and
# `name:`), and the TEST OF THAT ASSERTION is this lane, runnable before a push.
#
# `--self-test` runs thirteen checks — nine red arms, two direct property
# assertions and two green controls. Each red arm plants one fault (a verdict
# that ignores the marker, an arm that claims success without arming, a
# $GITHUB_PATH entry that never took effect, the pair copied onto another job)
# and requires it to be caught BY ITS MESSAGE (scripts/lib/red-arm.sh). No
# cargo, no network, milliseconds.
lane_cargo_free() {
  ./scripts/cargo-free.sh --self-test
}

# ── Q263 / D161 §2 R9: `.gitignore`'s deny-by-default rule, ENFORCED ───────
#
# `.gitignore`'s header declares that "no secret material may ever be
# committable by default". Measured 2026-08-22 it did not deliver it: of the
# seven secret-shaped names D161 §2 R9 probed, FIVE were not ignored —
# `.env`, `.env.local`, `secrets.env`, `id_rsa`, `credentials.json` — while
# `foo.key` and `.secrets/a` were. D161 §2 R2 adopts `.gitignore` BY
# REFERENCE as the register of Q65's `private` class, so that file is the
# only enforcement the class has, and a rule nothing re-runs is an assertion
# rather than a guard. Nothing was mis-tracked when this was found; what the
# arm buys is that the NEXT one cannot be committed by accident.
#
# WHY IT SITS ON THIS LANE AND NOT ITS OWN SCRIPT. `secret-guard` is the
# CONTENT scanner over what is already staged — the second line. This is the
# first: it asserts the NAMES never become stageable. They are complementary,
# neither substitutes for the other, and they fail with different messages.
#
# THE PROBES CREATE NO FILES. `git check-ignore` is pure pattern matching and
# never stats the path, so the table below is free and repeatable. Writing a
# real `.env` into the tree to test this would be planting the exact artifact
# the rule exists to keep out.
#
# `--no-index` IS LOAD-BEARING, and it is the trap here. By DEFAULT
# `check-ignore` reports a TRACKED path as not-ignored whatever the patterns
# say — so every `visible` row below would be green even if a deny pattern
# had swallowed it, an assertion that could not fail. `--no-index` asks the
# patterns alone. Verified against a scratch repo where `*.md` and a tracked
# `README.md` coexist: default says rc=1, `--no-index` says rc=0.
#
# SO IS THE SOURCE CHECK. `-v` prints `<source>:<line>:<pattern>`, and an
# `ignored` verdict is accepted ONLY when the source is `.gitignore` itself.
# This repository's `.git/info/exclude` carries ten live rules and a global
# excludes file is one `git config` away; without the source check a
# developer's untracked local state could green a rule the committed register
# does not carry, and CI would go red instead.
#
# Each row is `<path>|<want>|<why>`. `want` is `ignored` or `visible`; `why`
# carries no `|`. The expected count is derived from this array's length
# (Q245) — never written as a literal that drifts away from the list.
GITIGNORE_DENY_PROBES=(
  # The seven D161 §2 R9 probed. The first five were the defect; the last two
  # were already green, and the self-test below proves they can still go red.
  '.env|ignored|dotenv, the conventional home of API keys and RPC secrets'
  '.env.local|ignored|dotenv variant'
  'secrets.env|ignored|dotenv under a non-dotfile basename'
  'id_rsa|ignored|OpenSSH private key, the ssh-keygen default basename'
  'credentials.json|ignored|cloud / service-account credential JSON'
  'foo.key|ignored|denied before Q263 — the green arm, proven red by the self-test'
  '.secrets/a|ignored|denied before Q263 — the green arm, proven red by the self-test'
  # The rest of each family, so no pattern here is unprobed.
  'id_ed25519|ignored|OpenSSH private key, the modern default basename'
  'deploy_rsa|ignored|the <name>_<algo> form a deploy key takes'
  'backup_ed25519|ignored|the <name>_<algo> form a per-host key takes'
  '.ssh/config|ignored|anything under a stray .ssh directory'
  '.netrc|ignored|cleartext login/password store'
  '.git-credentials|ignored|git credential store, https://user:token@host in cleartext'
  'aws-credentials.json|ignored|credential JSON under a vendor prefix'
  'client.p12|ignored|PKCS#12 key and certificate container'
  '.devnet/env|ignored|the P16 funded-key export this lane also excludes from its scan'
  # The other polarity. Without these the check would pass by ignoring
  # everything, and the deny families would be free to eat the project.
  'README.md|visible|a tracked file — the deny patterns must not swallow the repo'
  'crates/antseal-core/src/crypto/secrets.rs|visible|a tracked source file whose NAME says secrets'
  'docs/format/registry-v1.json|visible|a tracked JSON — the credential rules are not *.json'
  'minisign.pub|visible|D71 §2 R5 publishes this into the repository at release'
  'id_ed25519.pub|visible|a public half is public — the key rules are basename-exact'
)

# The deny families the CONSTRUCTED self-test subject is built from, and the
# probes each one owns: `<name>|<patterns>|<probes that must go red without it>`.
# Grouped so that removing a whole family leaves its probes matched by nothing
# — `id_rsa` is covered by both `id_rsa` and `*_rsa`, so a per-PATTERN plant
# would be masked by its own neighbour and prove nothing.
GITIGNORE_DENY_FAMILIES=(
  'dotenv|.env .env.* *.env|.env .env.local secrets.env'
  'ssh-private-keys|id_rsa id_dsa id_ecdsa id_ecdsa_sk id_ed25519 id_ed25519_sk *_rsa *_dsa *_ecdsa *_ecdsa_sk *_ed25519 *_ed25519_sk|id_rsa id_ed25519 deploy_rsa backup_ed25519'
  'ssh-dir|.ssh/|.ssh/config'
  'credential-files|credentials.json *credentials*.json .netrc _netrc .git-credentials|credentials.json aws-credentials.json .netrc .git-credentials'
  'key-containers|*.p12 *.pfx *.ppk|client.p12'
  'pre-existing-key-material|*.key *.pem wallets/ *wallet*.json .secrets/|foo.key .secrets/a'
  'devnet|.devnet/ *.devnet/|.devnet/env'
)

# The mirror plants: `<pattern to append>|<visible probes it must swallow>`.
# A deny-only self-test proves the ignore arm and leaves the `visible` arm
# green-by-construction, because nothing in the family table could ever match
# a project path. These make the other polarity load-bearing too.
GITIGNORE_DENY_SWALLOWS=(
  '*.md|README.md'
  '*secrets*|crates/antseal-core/src/crypto/secrets.rs'
  '*.json|docs/format/registry-v1.json'
  '*.pub|minisign.pub id_ed25519.pub'
)

# Probe one work tree against the table. Prints one `FAIL <path>: …` line per
# disagreement — naming the specific probe, never a generic verdict — and a
# `probed=<n>` line, always. It returns nothing about pass/fail: the caller
# asserts on the MESSAGE (Q149), because an exit status cannot say which name
# was left committable.
#
# The directory is an ARGUMENT. That is what lets the self-test point this at
# a constructed subject instead of the live `.gitignore` (Q252) — a fixture
# whose subject is state the project is driving to green disarms itself the
# day the project succeeds.
gitignore_deny_probe() {
  local dir="$1" row path want why out rc src n=0
  for row in "${GITIGNORE_DENY_PROBES[@]}"; do
    path="${row%%|*}"
    want="${row#*|}"; want="${want%%|*}"
    why="${row##*|}"
    out="$(git -C "$dir" -c core.excludesFile=/dev/null check-ignore -v --no-index -- "$path" 2>/dev/null)"
    rc=$?
    n=$(( n + 1 ))
    if [ "$rc" -gt 1 ]; then
      printf 'FAIL %s: git check-ignore exited %s, which is neither 0 (ignored) nor 1 (visible) — the probe could not be taken, and a probe that did not run is not a pass\n' "$path" "$rc"
      continue
    fi
    src="${out%%:*}"
    if [ "$want" = ignored ]; then
      if [ "$rc" -ne 0 ]; then
        printf 'FAIL %s: expected IGNORED (%s) but NO pattern matches it — .gitignore does not deny this name, and its own header says no secret material may ever be committable by default\n' "$path" "$why"
      elif [ "$src" != '.gitignore' ]; then
        printf 'FAIL %s: expected IGNORED but the rule is `%s` — a local or global exclude is untracked developer state, and D161 §2 R2 adopts the COMMITTED .gitignore as the private class register\n' "$path" "$out"
      fi
    elif [ "$rc" -eq 0 ]; then
      printf 'FAIL %s: expected VISIBLE (%s) but `%s` ignores it — a deny pattern has swallowed a path the project must be able to track\n' "$path" "$why" "$out"
    fi
  done
  printf 'probed=%s\n' "$n"
}

# Write the constructed subject into <dir>/.gitignore. <skip> omits one
# family (a removal plant); <extra> appends one pattern (a swallow plant).
gitignore_deny_write_subject() {
  local dir="$1" skip="$2" extra="$3" f fname fpats
  local -a pat_arr
  : > "$dir/.gitignore" || return 1
  for f in "${GITIGNORE_DENY_FAMILIES[@]}"; do
    fname="${f%%|*}"; fpats="${f#*|}"; fpats="${fpats%%|*}"
    if [ "$fname" = "$skip" ]; then continue; fi
    # `read -a` splits on IFS and does NOT glob-expand. An unquoted expansion
    # here would let `*.md` and `*.key` match this repository's own files.
    IFS=' ' read -r -a pat_arr <<<"$fpats"
    printf '%s\n' "${pat_arr[@]}" >> "$dir/.gitignore" || return 1
  done
  if [ -n "$extra" ]; then printf '%s\n' "$extra" >> "$dir/.gitignore" || return 1; fi
  return 0
}

gitignore_deny_selftest_body() {
  local tmp="$1" fail=0 out probed expected base row name plant p fpats
  local -a fail_arr pat_arr
  expected="${#GITIGNORE_DENY_PROBES[@]}"
  if ! git -C "$tmp" init -q >/dev/null 2>&1; then
    printf '::error::gitignore deny-by-default self-test: could not init a scratch repo in %s — the constructed subject cannot be built, so nothing here was tested\n' "$tmp"
    return 1
  fi
  # The constructed subject must be the ONLY source of a verdict in here.
  : > "$tmp/.git/info/exclude"
  base="$tmp/.git/constructed-baseline"

  # Control. A red baseline means the family table does not satisfy the probe
  # table, and every plant below would be indistinguishable from it.
  gitignore_deny_write_subject "$tmp" "" "" || { printf '::error::gitignore deny-by-default self-test: could not write the constructed subject\n'; return 1; }
  cp "$tmp/.gitignore" "$base"
  out="$(gitignore_deny_probe "$tmp")"
  probed="$(sed -n 's/^probed=//p' <<<"$out")"
  if [ "${probed:-0}" != "$expected" ]; then
    printf '::error::gitignore deny-by-default self-test: the control probed %s name(s) against a table of %s — the probe loop does not run to completion, so no result below can be believed\n' "${probed:-0}" "$expected"
    return 1
  fi
  if grep -q '^FAIL ' <<<"$out"; then
    grep '^FAIL ' <<<"$out" | sed 's/^/    /'
    printf '::error::gitignore deny-by-default self-test: the CONSTRUCTED baseline is NOT green — the family table does not satisfy the probe table\n'
    return 1
  fi

  # Plant one: remove a deny family. Every probe it owns must name itself.
  for row in "${GITIGNORE_DENY_FAMILIES[@]}"; do
    name="${row%%|*}"; plant="${row##*|}"
    gitignore_deny_write_subject "$tmp" "$name" "" || { fail=1; continue; }
    if cmp -s "$tmp/.gitignore" "$base"; then
      printf '::error::gitignore deny-by-default self-test: removing family `%s` changed the subject not at all — the plant did not apply and this arm tested an unmodified file (a nonzero exit is not proof a fault was found, and a zero exit is not proof it was absent)\n' "$name"
      fail=1; continue
    fi
    out="$(gitignore_deny_probe "$tmp")"
    IFS=' ' read -r -a fail_arr <<<"$plant"
    for p in "${fail_arr[@]}"; do
      # Two greps, not one. `expected IGNORED` alone is ALSO produced by the
      # wrong-source message below, so a single fixed string let this arm pass
      # while the no-pattern branch was neutered — found by planting exactly
      # that fault. The two failure classes must stay distinguishable.
      if ! grep -F "FAIL $p: expected IGNORED (" <<<"$out" | grep -qF 'but NO pattern matches it'; then
        printf '::error::gitignore deny-by-default self-test: with family `%s` removed, probe `%s` did NOT report itself by name as undenied — nothing in this check is load-bearing for that name\n' "$name" "$p"
        fail=1
      fi
    done
  done

  # Plant two: append a pattern that swallows a path the project must track.
  for row in "${GITIGNORE_DENY_SWALLOWS[@]}"; do
    name="${row%%|*}"; plant="${row##*|}"
    gitignore_deny_write_subject "$tmp" "" "$name" || { fail=1; continue; }
    if cmp -s "$tmp/.gitignore" "$base"; then
      printf '::error::gitignore deny-by-default self-test: appending `%s` changed the subject not at all — the plant did not apply\n' "$name"
      fail=1; continue
    fi
    out="$(gitignore_deny_probe "$tmp")"
    IFS=' ' read -r -a fail_arr <<<"$plant"
    for p in "${fail_arr[@]}"; do
      if ! grep -qF "FAIL $p: expected VISIBLE" <<<"$out"; then
        printf '::error::gitignore deny-by-default self-test: with `%s` appended, tracked path `%s` was NOT reported as swallowed — the visible arm is green by construction and would not notice a pattern eating the project\n' "$name" "$p"
        fail=1
      fi
    done
  done

  # Plant three: move a family OUT of `.gitignore` and into the repo's local
  # `.git/info/exclude`. Every name stays ignored, so an exit-status check
  # would see nothing at all — but the committed register no longer carries
  # the rule, which is precisely the false green the source check exists to
  # refuse. Without this plant that branch is unreachable and would be a
  # deny-by-default guard a developer's untracked local state could satisfy.
  for row in "${GITIGNORE_DENY_FAMILIES[@]}"; do
    name="${row%%|*}"; plant="${row##*|}"
    fpats="${row#*|}"; fpats="${fpats%%|*}"
    gitignore_deny_write_subject "$tmp" "$name" "" || { fail=1; continue; }
    IFS=' ' read -r -a pat_arr <<<"$fpats"
    printf '%s\n' "${pat_arr[@]}" > "$tmp/.git/info/exclude"
    out="$(gitignore_deny_probe "$tmp")"
    : > "$tmp/.git/info/exclude"
    IFS=' ' read -r -a fail_arr <<<"$plant"
    for p in "${fail_arr[@]}"; do
      if ! grep -qF "FAIL $p: expected IGNORED but the rule is" <<<"$out"; then
        printf '::error::gitignore deny-by-default self-test: family `%s` moved from .gitignore into .git/info/exclude and probe `%s` still passed — the check accepts untracked local developer state as the private class register, which D161 §2 R2 does not\n' "$name" "$p"
        fail=1
      fi
    done
  done

  # Restored: byte-identical to the control, and green again.
  gitignore_deny_write_subject "$tmp" "" "" || { fail=1; }
  if ! cmp -s "$tmp/.gitignore" "$base"; then
    printf '::error::gitignore deny-by-default self-test: the restored subject differs from the control — the plants left damage behind\n'
    fail=1
  fi
  out="$(gitignore_deny_probe "$tmp")"
  if grep -q '^FAIL ' <<<"$out"; then
    grep '^FAIL ' <<<"$out" | sed 's/^/    /'
    printf '::error::gitignore deny-by-default self-test: still red after restoring the control\n'
    fail=1
  fi

  [ "$fail" -eq 0 ] || return 1
  printf 'self-test OK: %s probes against a CONSTRUCTED .gitignore; %s deny families each proven load-bearing by removal, %s swallow patterns each proven to red a trackable path, and %s families re-proven via .git/info/exclude so the source check cannot be dead code — %s plants, every assertion on the MESSAGE and none on exit status.\n' \
    "$expected" "${#GITIGNORE_DENY_FAMILIES[@]}" "${#GITIGNORE_DENY_SWALLOWS[@]}" "${#GITIGNORE_DENY_FAMILIES[@]}" \
    "$(( ${#GITIGNORE_DENY_FAMILIES[@]} * 2 + ${#GITIGNORE_DENY_SWALLOWS[@]} ))"
}

# Self-test on a constructed subject, then the live repository.
assert_gitignore_deny_by_default() {
  local tmp rc out probed expected ign vis
  tmp="$(mktemp -d)" || { printf '::error::gitignore deny-by-default: mktemp failed; the self-test cannot run and an unproven check is not a pass\n'; return 1; }
  gitignore_deny_selftest_body "$tmp"; rc=$?
  rm -rf "$tmp"
  [ "$rc" -eq 0 ] || return 1

  expected="${#GITIGNORE_DENY_PROBES[@]}"
  ign="$(printf '%s\n' "${GITIGNORE_DENY_PROBES[@]}" | grep -c '|ignored|')"
  vis="$(printf '%s\n' "${GITIGNORE_DENY_PROBES[@]}" | grep -c '|visible|')"
  out="$(gitignore_deny_probe "$repo")"
  probed="$(sed -n 's/^probed=//p' <<<"$out")"
  if [ "${probed:-0}" != "$expected" ]; then
    printf '::error::gitignore deny-by-default: probed %s name(s) against a table of %s — the loop did not run to completion, and a partial probe is not a pass\n' "${probed:-0}" "$expected"
    return 1
  fi
  if grep -q '^FAIL ' <<<"$out"; then
    grep '^FAIL ' <<<"$out" | sed 's/^/    /'
    printf '::error::gitignore deny-by-default (Q263 / D161 §2 R9): .gitignore does not deliver the rule its own header declares — "no secret material may ever be committable by default". WIDEN the patterns; never narrow this table or the file to make it green.\n'
    return 1
  fi
  printf 'OK: %s deny-by-default probes (%s secret-shaped names denied, %s project paths still trackable), every verdict sourced from the committed .gitignore.\n' \
    "$expected" "$ign" "$vis"
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
    # (4a) age secret-key marker.
    hits+="$(ex 'AGE[-]SECRET[-]KEY[-]1')"$'\n'
    # (4b) minisign / rsign2 secret-key HEADER COMMENT, anchored to the
    #      comment PREFIX. Widened by Q245 to cover `rsign` and to make the
    #      word `encrypted` optional; anchored here, in the same act as the
    #      false positive that widening created was measured.
    #
    #      WHAT THE ANCHOR IS FOR. Both tools write the SAME `untrusted
    #      comment:` line into every SIGNATURE they produce, and both name
    #      themselves in it:
    #        minisign      `src/minisign.h`  DEFAULT_COMMENT
    #                      = "signature from minisign secret key"
    #        rust-minisign `src/constants.rs` DEFAULT_COMMENT
    #                      = "signature from rsign secret key"
    #      Unanchored, `(minisign|rsign)([ ]encrypted)?[ ]secret[ ]key`
    #      matches both — so the Q245 pattern reported EVERY `.minisig` this
    #      project will ever ship as secret material, including the
    #      `SHA256SUMS.minisig` and per-artifact signatures
    #      `scripts/sign-release.sh` emits and the `minisign.pub.minisig`
    #      D71 §2 R9 step 2 publishes on rotation. A signature is public by
    #      construction; a lane that reds on one blocks the release act it
    #      exists to protect. It also matched ordinary PROSE — any non-`.md`
    #      file saying "the minisign secret key never enters the checkout"
    #      (a script header, a workflow comment, page HTML) went red.
    #      Measured on real artifacts from a real `minisign` binary, not
    #      inferred. This was a REGRESSION: the shipped literal Q245
    #      replaced, `minisign encrypted secret key`, appears in no
    #      signature file.
    #
    #      A `*.minisig` EXCLUSION WOULD BE THE WRONG FIX and is refused.
    #      `ex()`'s excludes apply to every rule at once, so excluding the
    #      extension would blind (1)-(5) and (4c) as well — a real secret key
    #      renamed `foo.minisig` would become invisible to the whole lane.
    #      The anchor removes the false positive from THIS rule and adds no
    #      hole; the `renamed-secret-key.minisig` fixture below asserts that
    #      such a file is still caught, so a later "simpler fix" reds.
    #
    #      `untrusted comment: ` is COMMENT_PREFIX, verified identical in
    #      both implementations (minisign `src/minisign.h`; rust-minisign
    #      `src/constants.rs`). A secret key's comment BEGINS with the tool
    #      name; a signature's begins with `signature from`. That is the
    #      whole discriminator, and it is exact.
    #
    #      WHAT THIS RULE IS WORTH, stated plainly so nobody over-trusts it.
    #      D71 §B R3 ruled that no comment-keyed rule can be the answer:
    #      §1.3 row 4 MEASURED the untrusted comment as unauthenticated free
    #      text, `-c` replaces it outright, and a rewritten comment still
    #      verifies. (4c) below is the rule that catches keys. Measured over
    #      real keys of every form D71 cares about, (4b)'s true positives are
    #      a SUBSET of (4c)'s but for one case: a key file whose body is
    #      absent or mangled and whose header survives. It is kept for that
    #      case and as the regression arm for the shipped literal, never as
    #      the fix. Removing it outright is a decision, not an implementer's
    #      call — D71 §B R3 records it as landed and kept.
    hits+="$(ex 'untrusted[ ]comment:[ ](minisign|rsign)([ ]encrypted)?[ ]secret[ ]key')"$'\n'
    # (4c) minisign / rsign2 secret-key BODY — the rule no comment can dodge,
    #      and the one that actually closes Q245.
    #
    #      WHY A HEADER RULE CANNOT BE THE ANSWER: the untrusted comment is
    #      free text. `-c` replaces it outright, and D71 §1.3 row 4 MEASURED
    #      that rewriting it leaves the artifact fully verifying — the field
    #      is not authenticated. Any rule keyed on it is a convenience.
    #
    #      This one keys on the first six bytes of the key struct — sig_alg
    #      `Ed`, kdf_alg, chk_alg `B2` — the type tag, at offset 0, so it
    #      survives base64 verbatim and 6 bytes land on exactly 8 characters
    #      with no alignment slack:
    #        kdf_alg 00 00 (KDFNONE — an UNENCRYPTED `-W` key) -> RWQAAEIy
    #        kdf_alg `Sc`  (KDFALG  — the passphrase-wrapped key) -> RWRTY0Iy
    #      Field order verified in BOTH implementations (minisign
    #      `src/minisign.h` SeckeyStruct; rust-minisign
    #      `SecretKey::to_bytes()`), which agree byte for byte.
    #
    #      It cannot fire on the minisign PUBLIC key, which D71 §2 R5
    #      publishes into this very repo: that struct is 42 bytes and has no
    #      kdf_alg field at all, so byte 2 is random keynum. The self-test
    #      plants the nearest possible miss — a public key with an all-zero
    #      keynum, `RWQAAAAA…`, which shares five characters and must NOT be
    #      reported — so that stays an assertion rather than a belief.
    hits+="$(ex 'RWQAAEI[y]|RWRTY0I[y]')"$'\n'
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
  #
  # Q245 — WHY THIS IS SHAPED THE WAY IT IS. It used to be a hand-written
  # `planted=5` compared against a total, over SIX rules. The arithmetic
  # balanced anyway, because the age file at (4a) filled the slot the
  # minisign rule at (4b) had no fake for — so (4b) was never once exercised
  # in the guard's whole life, inside the guard that exists to make failure
  # possible. Two changes, and both are needed:
  #
  #   1. `planted` is DERIVED from the fixture list, so a rule cannot be
  #      added without a fake and the number cannot drift out of step.
  #   2. Every fixture is asserted BY NAME in the scan output, and every path
  #      in the scan output must be a fixture. A total that merely balances
  #      cannot tell "six rules, six fakes" from "five rules firing twice".
  #
  # ONE FIXTURE PER RULE ARM, and each isolates its own arm: the header
  # fixtures carry no key-shaped body and the body fixtures carry no matching
  # header, so a broken arm cannot be covered by its neighbour. No fixture
  # contains real key material — the (4c) bodies are the format's type tag
  # and zero padding, which is why they can be written down at all.
  #
  # ONE FIXTURE IS THE EXCEPTION AND SAYS SO: `renamed-secret-key.minisig`
  # covers (4c)'s `Sc` arm a second time, because what it asserts is not the
  # arm but the ABSENCE of a filename exclusion. If that arm breaks, two
  # fixtures go missing and the message names both.
  #
  # The NEGATIVE fixtures are the other half of the same discipline: files
  # that must NOT be reported, left out of the list so the `unexpected` arm
  # names them if they ever are. They cover the two near misses that would
  # otherwise be found in production — the published public key, and every
  # signature this project ships.
  local tmp planted found out missing unexpected rules f
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' RETURN
  printf 'fake for guard self-test\n-----BEGIN EC PRIVATE KEY-----\nAAAA\n-----END EC PRIVATE KEY-----\n' > "$tmp/fake-wallet.pem"
  printf '{"version":3,"crypto":{"ciphertext":"00","cipherparams":{},"kdf":"scrypt","kdfparams":{"n":1},"mac":"00"}}\n' > "$tmp/fake-keystore.json"
  printf 'ANTSEAL VAULT EXPORT v0 guard-self-test\n' > "$tmp/fake-vault-export.bin"
  printf 'AGE-SECRET-KEY-1SELFTESTSELFTESTSELFTEST\n' > "$tmp/fake-age.key"
  # (4b), all four header arms: {minisign, rsign} x {with, without} the word
  # `encrypted`. The first is the literal the lane shipped with and is kept
  # as the regression arm; the other three are what it could not see.
  printf 'untrusted comment: minisign encrypted secret key\n(body elided: this fixture exercises the header rule only)\n' > "$tmp/fake-minisign-enc-header.key"
  printf 'untrusted comment: minisign secret key\n(body elided: this fixture exercises the header rule only)\n' > "$tmp/fake-minisign-plain-header.key"
  printf 'untrusted comment: rsign encrypted secret key\n(body elided: this fixture exercises the header rule only)\n' > "$tmp/fake-rsign-enc-header.key"
  printf 'untrusted comment: rsign secret key\n(body elided: this fixture exercises the header rule only)\n' > "$tmp/fake-rsign-plain-header.key"
  # (4c), both body arms, each under a CUSTOM untrusted comment — i.e. the
  # exact file (4b) is blind to, which is the point of having (4c) at all.
  # `RWQAAEIy` + 64 x 'A' is `Ed` 00 00 `B2` followed by the 48 zero bytes an
  # unencrypted key leaves in kdf_salt/opslimit/memlimit; the tail is base64
  # `self-test-no-key-material` where a real key's keynum+sk+chk would be.
  printf 'untrusted comment: antseal release signing key\nRWQAAEIy%s%s\n' "$(printf 'A%.0s' $(seq 64))" 'c2VsZi10ZXN0LW5vLWtleS1tYXRlcmlhbA==' > "$tmp/fake-minisign-unencrypted-body.key"
  printf 'untrusted comment: antseal release signing key\nRWRTY0Iy%s\n' 'c2VsZi10ZXN0LW5vLWtleS1tYXRlcmlhbA==' > "$tmp/fake-minisign-encrypted-body.key"
  # The devnet-export wallet-key line (pattern 5): 64 x 'a' is hex-shaped
  # enough to trip the guard and unmistakably fake.
  printf "ANTSEAL_DEVNET_WALLET_PRIVATE_KEY='%s'\n" "$(printf 'a%.0s' $(seq 64))" > "$tmp/fake-devnet-env"
  # A REAL secret key does not become safe by being renamed. This fixture is
  # a (4c)-shaped body under a custom comment — i.e. invisible to (4b) — with
  # the extension every release signature carries. It is IN the list below, so
  # if anyone ever "fixes" a `.minisig` false positive by adding
  # `--exclude='*.minisig'` to `ex()`, this file stops being reported and the
  # self-test names it. That exclusion would blind every rule at once, which
  # is why the fix at (4b) is an anchor and not an exclude.
  printf 'untrusted comment: antseal release signing key\nRWRTY0Iy%s\n' 'c2VsZi10ZXN0LW5vLWtleS1tYXRlcmlhbA==' > "$tmp/renamed-secret-key.minisig"
  # NEGATIVE fixtures, deliberately NOT in the list below: a minisign public
  # key, which D71 §2 R5 publishes into this repository, with an all-zero
  # keynum so its body shares five leading characters with (4c)'s
  # unencrypted arm. If (4c) is ever loosened to `RWQAA`, Q30 reds the tree
  # on the day the real key lands — this is what stops that being found in
  # production.
  printf 'untrusted comment: minisign public key 0000000000000000\nRWQAAAAAAAAAAO7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u\n' > "$tmp/not-a-secret-minisign.pub"
  # ... and the two SIGNATURE header lines, one per tool, verbatim from
  # upstream's DEFAULT_COMMENT. These are what the un-anchored Q245 pattern
  # reported as secret material: every `.minisig` this project ships, its
  # release manifest signature, and the rotation signature over the public
  # key. The bodies are `ED` + zero padding — the prehashed sig_alg — so they
  # also assert that a signature cannot reach (4c). If (4b) ever loses its
  # `untrusted comment:` anchor, these are reported, they are not fixtures,
  # and the self-test names them.
  printf 'untrusted comment: signature from minisign secret key\nRURAAAAAAAAAAAAA%s\ntrusted comment: guard self-test, not a real signature\n%s\n' \
    'c2VsZi10ZXN0LW5vLWtleS1tYXRlcmlhbA==' 'c2VsZi10ZXN0LW5vLWtleS1tYXRlcmlhbA==' > "$tmp/not-a-secret-minisign-signature.minisig"
  printf 'untrusted comment: signature from rsign secret key\nRURAAAAAAAAAAAAA%s\ntrusted comment: guard self-test, not a real signature\n%s\n' \
    'c2VsZi10ZXN0LW5vLWtleS1tYXRlcmlhbA==' 'c2VsZi10ZXN0LW5vLWtleS1tYXRlcmlhbA==' > "$tmp/not-a-secret-rsign-signature.minisig"
  # ... and the PROSE case: an ordinary non-`.md` file that names the tool and
  # the key in a sentence. The un-anchored pattern reported this too.
  printf '#!/bin/sh\n# The maintainer holds the minisign secret key offline (D71 §2 R7);\n# an rsign secret key would be the same story. Neither is ever in the tree.\n' > "$tmp/not-a-secret-prose.sh"
  local -a fakes=(
    fake-wallet.pem                     # (1)  PEM private-key block
    fake-keystore.json                  # (2)  EVM keystore conjunction
    fake-vault-export.bin               # (3)  antseal vault-export magic
    fake-age.key                        # (4a) age secret key
    fake-minisign-enc-header.key        # (4b) header, minisign, encrypted
    fake-minisign-plain-header.key      # (4b) header, minisign, no `encrypted`
    fake-rsign-enc-header.key           # (4b) header, rsign2, encrypted
    fake-rsign-plain-header.key         # (4b) header, rsign2, no `encrypted`
    fake-minisign-unencrypted-body.key  # (4c) body, kdf_alg = 00 00
    fake-minisign-encrypted-body.key    # (4c) body, kdf_alg = `Sc`
    fake-devnet-env                     # (5)  committed devnet wallet key
    renamed-secret-key.minisig          # (4c) body, `Sc`, under the extension
                                        #      a release signature carries
  )
  planted="${#fakes[@]}"
  # The fixture list cannot see a rule nobody wrote a fixture for: an eighth
  # `hits+=` added to `scan` would match none of the files above, contribute
  # no path, and every total would still balance — which is Q245's defect one
  # level up, waiting to happen again. So the rules are counted too, off the
  # live function body (`declare -f` strips comments, and the pattern carries
  # a character class so this line cannot count itself). Adding a rule is now
  # an act that has to touch this block.
  rules="$(declare -f lane_secret_guard | grep -c 'hits[+]=')" || true
  if [ "$rules" -ne 7 ]; then
    printf '::error::secret-guard self-test FAILED: scan() carries %s detection rules, but the fixture list above is written against 7. A rule with no fixture is never exercised and the totals still balance — that is exactly the defect Q245 closed. Add a fixture for every arm of the new rule and update this number in the same act\n' "$rules"
    return 1
  fi
  out="$(scan "$tmp")" || true
  found="$(grep -c . <<<"$out")" || true
  missing="" ; unexpected=""
  for f in "${fakes[@]}"; do
    grep -qxF "$tmp/$f" <<<"$out" || missing+=" $f"
  done
  while read -r f; do
    [ -n "$f" ] || continue
    printf '%s\n' "${fakes[@]}" | grep -qxF "${f#"$tmp/"}" || unexpected+=" ${f#"$tmp/"}"
  done <<<"$out"
  if [ -n "$missing" ] || [ -n "$unexpected" ] || [ "$found" -ne "$planted" ]; then
    printf '::error::secret-guard self-test FAILED: planted %s fakes, detected %s; rule arm(s) with NO detection:%s; file(s) matched that are not fixtures:%s — the detector is broken; fix it before trusting a green scan\n' \
      "$planted" "$found" "${missing:- (none)}" "${unexpected:- (none)}"
    scan "$tmp" || true
    return 1
  fi
  printf 'self-test OK: %s planted fakes, every rule arm detected by name; the public-key, signature and prose near-misses were not flagged\n' "$planted"
  # The exclusion above is only safe while `.devnet/` is genuinely
  # unstageable. Check that, rather than trusting it.
  if git rev-parse --git-dir >/dev/null 2>&1; then
    if ! git check-ignore -q .devnet/env 2>/dev/null; then
      printf '::error::secret-guard: .devnet/ is NOT gitignored, but this lane skips scanning it. Restore the .gitignore rule (the devnet export carries the funded wallet key) or drop the --exclude-dir=.devnet above.\n'
      return 1
    fi
    printf 'OK: .devnet/ is gitignored, so excluding it from the scan removes nothing committable.\n'
    # ... and the same question asked of the whole secret-shaped family
    # (Q263 / D161 §2 R9). The arm above answers it for ONE name and only
    # about the exclusion above; this one answers it for the family the
    # `private` class is defined by, and additionally requires each verdict
    # to come from the COMMITTED .gitignore rather than a local exclude.
    if ! assert_gitignore_deny_by_default; then
      return 1
    fi
  else
    printf 'SKIP: not a git work tree, so neither the .devnet/ exclusion nor the .gitignore deny-by-default family (Q263) was verified. The content scan below still ran; the name-level line did NOT.\n'
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
  local n; n="$(grep -c . <<<"$days")"
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
  n="$(grep -c . <<<"$cron")"
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
  cargo deny --locked check advisories bans sources licenses
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
  if ! grep -q 'registry target is EMPTY' <<<"$out" ; then
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
  anchor-net-policy) lane_anchor_net_policy ;;
  cargo-free)       lane_cargo_free ;;
  custody-log)      lane_custody_log ;;
  *) die "usage: scripts/ci-lanes.sh <$(printf '%s' "$LANES" | tr ' ' '|')> | --list | --self-test" ;;
esac
