# Q — Test infrastructure, CI, threat model, docs, release

> Part of the antseal MVP task breakdown (generated 2026-07-27 from MVP-SPEC.md Revision 2 by a 9-agent decomposition).
> **Status tracking lives in `../TODO.md`** — do not add checkboxes here. Treat Do/Accept as normative until deliberately revised; spec line references are into `MVP-SPEC.md` as of 2026-07-27.
> Dep prefixes: P=setup/toolchain/pins, F=CBOR+manifest/bundle codecs, C=crypto primitives, G=canonicalization+units+GGM fine tree, S=storage/payments/journal/restore, A=anchors, R=reveal/verification/web page, U=CLI/vault/config/UX, Q=test-infra/CI/threat-model/docs/release.

### Q1 — Extend the CI skeleton to the full M0 matrix
- Milestone: M0
- Size: M
- Deps: P: CI skeleton workflow + pinned Rust toolchain/caching (P8)
- Spec: Milestones M0/M4 (MVP-SPEC.md lines 153, 157); Verification (line 167)
- Do: Extend P's skeleton into the required PR matrix: `cargo fmt --check`, `cargo clippy -D warnings` (all targets/features), workspace `cargo test`, and a `wasm32-unknown-unknown` build of `antseal-core` from day one of M0. Add a multi-OS lane (ubuntu + macOS + Windows GitHub-hosted runners) scoped to the cross-platform-sensitive suites — the canonicalization UTF-8 corpus (G3) and the golden-vector runs — so byte-identical behavior across OSes is CI-proven. Add mount points (initially allowed-empty, later required) for the lanes that land in Q4–Q10: golden-vector run, WASM bit-match, tamper matrix, fuzz smoke, audit/deny. Configure branch protection so all lanes are required statuses.
- Accept:
  - fmt/clippy/test/wasm32 lanes run on every PR and are required to merge
  - Multi-OS lane runs the corpus/vector suites on linux, macOS, and Windows (satisfies G3's cross-platform Accept)
  - wasm32 lane demonstrably fails on a scratch commit that adds a non-WASM-safe dep (e.g. tokio) to `antseal-core` (test-of-the-test recorded once)
  - Lane mount points for Q4/Q5/Q7/Q9/Q10 exist and are documented in CONTRIBUTING
- Notes: The M4 bullet "CI (fmt/clippy/test/wasm/fuzz)" is the final-state confirmation; this task establishes it at M0 and Q13/Q34 re-verify completeness later.

### Q2 — Define `testdata/` layout and fixture conventions
- Milestone: M0
- Size: S
- Deps: Q1
- Spec: Architecture tree (line 57); Milestones M0 (line 153); project rule 6 (secrets never in fixtures)
- Do: Create the `testdata/` tree matching the spec's contents: `vectors/<format-version>/` (golden vectors), `utf8-corpus/`, `tamper/`, `fine-tree/` (range-proof fixtures), plus `anchors/` (reserved for M2 recorded fixtures) and fuzz seed corpora location. Write a `testdata/README.md` stating layout, contribution rules, and the secret-material convention: every fixture secret (test `W`, keys, salts) derives from a documented fixed test seed, is clearly labeled test-only, and no real vault/wallet material may ever be committed. Add a CI guard that greps for vault-export/wallet-key file signatures under the repo.
- Accept:
  - All four spec-named fixture categories have a home directory and documented ownership (F/C/G/A/R contribute content)
  - Test-secret convention documented; CI guard fails on a planted fake vault-export file (test-of-the-test)

### Q3 — Establish proptest conventions and shared strategy helpers
- Milestone: M0
- Size: S
- Deps: Q2; P: proptest version pin
- Spec: Verification "(M0) Unit/property tests per crate" (line 167); Milestones M0 (line 153)
- Do: Write the property-testing conventions all component domains follow: pinned proptest version, deterministic RNG seeding for CI reproducibility, per-environment case counts (local vs CI via env var), committed `proptest-regressions/` policy, shrink/timeout settings, and the location of shared strategies (a test-util module with generators for works/files/units/byte ranges). Provide one working example strategy and test.
- Accept:
  - Conventions doc committed; example property test runs in the Q1 test lane with fixed config
  - `proptest-regressions/` committed-and-never-deleted policy stated
  - Component domains (F/C/G/S/A/R) can import shared strategies without redefining them

### Q4 — Build the golden-vector framework (schema, index, native runner)
- Milestone: M0
- Size: M
- Deps: Q1, Q2; F: manifest/bundle vector content (F12/F13); C: crypto vector content (C16); G: canonicalization/fine-tree vector content (G3/G15); R: deterministic byte-stable verification-report serialization (R1)
- Spec: Revision note (line 5); Definitions (line 73); Format stability (line 123); Milestones M0 (line 153); Verification (line 167)
- Do: Define the vector file schema — inputs (test `W`, `seal_id`, nonces, file bytes), expected artifact bytes (manifest, bundle), expected digests (`work_id`, `anchor_digest`, commitments, `fine_root`), and expected verification-report bytes — plus a discovery mechanism (glob over `testdata/vectors/<version>/`, no hardcoded lists) and the native runner test that executes full `antseal-core` verification on every vector of every version. Components add vectors by dropping files; the harness never changes per vector.
- Accept:
  - Runner discovers and executes all committed vectors in CI; a malformed vector file fails loudly (not silently skipped)
  - Adding a vector requires no harness code change (documented procedure)
  - Schema supports later M2 anchor vectors and M3 bundle vectors without redesign

### Q5 — Build the WASM/native bit-match harness and CI lane
- Milestone: M0
- Size: M
- Deps: Q1, Q4; C: WASM probe recipe (C11/P14); R: deterministic verification-report serialization (R1)
- Spec: Milestones M0 "wasm32 build in CI from day one" (line 153); M2 exit criteria (line 155); Verification (line 167)
- Do: Compile `antseal-core` verification to `wasm32-unknown-unknown`, execute it (wasm-bindgen-test under node or a headless runner) over every golden vector, and byte-compare the WASM verification output (report bytes + recomputed digests) against the native runner's output. Wire as a required CI lane from M0 day one; it must automatically cover new vectors, including M2 anchor vectors (an explicit M2 exit criterion).
- Accept:
  - Every committed vector's WASM output is SHA-256-identical to native output in CI
  - Lane fails on an injected platform divergence (e.g. HashMap-ordered serialization) — test-of-the-test recorded once
  - Lane runs all format versions and requires no per-vector wiring

### Q6 — Enforce vector freeze and indefinite per-version retention in CI
- Milestone: M0
- Size: S
- Deps: Q4; F: empty-anchor vector exists (F13); G: unbalanced-n (n=6) vector exists (G15)
- Spec: Format stability (line 123); Verification (lines 167, 169)
- Do: Implement the append-only guarantee: a per-version `FROZEN.sha256` manifest of frozen vector files; a CI job recomputes hashes and fails on any modification or deletion of a frozen entry, while allowing additions. Maintain a must-exist list checked at freeze time — at minimum the empty-anchor manifest/bundle vectors and the unbalanced-`n` (n=6, MSB-first GGM) fine-tree vector. Document that per-version directories are retained indefinitely and every future release's CI runs all of them.
- Accept:
  - Mutating or deleting a frozen vector on a test branch turns CI red; adding a new vector stays green
  - Must-exist list (empty-anchor, unbalanced-n) enforced before the M0 freeze tag (Q14)
  - Retention policy stated in `testdata/README.md` and referenced by the format-stability doc (Q27)

### Q7 — Build the tamper-matrix harness with distinct-error assertion
- Milestone: M0
- Size: M
- Deps: Q1, Q2; F: stable error codes on codec errors; C: stable error codes on crypto errors; G: stable error codes on canonicalization/tree errors; R: stable error codes / verdict states from verification
- Spec: Verification tamper matrix (line 168); Milestones M0 (line 153); working principle "parse defensively"
- Do: Implement the shared runner: a row = {row-id, base fixture, mutation (function or pre-mutated fixture), expected outcome}. An expected outcome is either a stable machine-readable error code or a specific non-headline verdict state (needed for M2 rows like untrusted-root → `internally-consistent-only`). The runner asserts: every row produces exactly its expected outcome; no row panics (adversarial input must error, never crash); and expected outcomes are pairwise distinct across the registry (the spec's "every mutation fails with a distinct error"). Define the error-code stability contract components must implement.
- Accept:
  - Runner wired into the Q1 CI matrix; row-addition procedure documented for F/C/G/A/R
  - Two rows declaring the same expected code fail the distinctness assertion (test-of-the-test)
  - A mutation that panics instead of erroring fails the harness
  - Error-code contract documented and referenced by component domains

### Q8 — Track tamper-matrix completeness against the spec's M0 row list
- Milestone: M0
- Size: S
- Deps: Q7
- Spec: Verification M0 rows (line 168); Milestones M0 (line 153)
- Do: Commit a machine-readable registry (e.g. `testdata/tamper/MATRIX.toml`) enumerating every spec-mandated M0 mutation family with owner domain and linked test/row id: flipped ciphertext byte; altered manifest field with both failure routes (covered unit → `fine_root` leaf-range/boundary-path failure; non-covered unit → `unit_commit` failure); wrong salt; wrong-length salt/seed (16-B `*_salt`, 32-B `s_root`/GGM seed/boundary node); wrong key; swapped unit; the four `sig_policy` violations (missing / invalid / unlisted-extra / empty); non-canonical Ed25519 `S`; non-canonical ML-DSA encoding; the four non-canonical-CBOR cases (duplicate key, non-shortest int, indefinite length, trailing bytes); overlapping / out-of-bounds / non-tiling non-mirror ranges; raw-mirror wrongly in the tiling set; raw-mirror `canonicalize(raw)` ≠ canonical; `true_length` ≠ range width; over-padded unit; over-broad GGM cover; `file_salt`/`s_root` present for a partially revealed file; oversized/deep CBOR. A CI script fails when any registry entry lacks an implemented row or any spec-listed mutation is absent from the registry.
- Accept:
  - Registry maps 1:1 onto the spec's M0 enumeration (every family above present, including sub-variants)
  - CI red when a registry row is unimplemented; green only at full M0 coverage before the freeze (Q14)
  - Registry format supports the M2 anchor extension (Q18)

### Q9 — Stand up cargo-fuzz infrastructure, CI lanes, and corpus management
- Milestone: M0
- Size: M
- Deps: Q1, Q2; F: manifest + bundle CBOR fuzz targets (F17)
- Spec: Milestones M0 (line 153); Verification (line 169); Risks "hostile bundles" (line 187)
- Do: Create the `fuzz/` cargo-fuzz workspace and target-registration convention. Wire two CI lanes: a per-PR smoke run (fixed seconds per target, e.g. 90 s) required to merge, and a scheduled nightly longer run with corpus persistence. Seed corpora from golden vectors and tamper fixtures; commit minimized corpora; document minimization cadence and the crash-triage workflow (crash = release-blocking, regression case added to `testdata/tamper/` or the corpus).
- Accept:
  - F's manifest and bundle CBOR targets run in the required smoke lane at M0
  - Nightly scheduled run exists with corpus caching; crash artifacts are uploaded on failure (demonstrated with a synthetic crash)
  - Corpus-management and triage doc committed

### Q10 — Wire cargo-audit/cargo-deny with a RUSTSEC advisory watch
- Milestone: continuous
- Size: S
- Deps: Q1; P: exact pins + deny.toml skeleton (P13); Q29 (license allowlist, later)
- Spec: Cryptography crate pins (line 97); Risks "PQC crate maturity" (line 183)
- Do: Add cargo-audit and cargo-deny lanes (PR-triggered and scheduled) during M0 and keep them running permanently. Record the two known Jan-2026 `ml-dsa` advisories as accepted ignores with written rationale (the spec's pin decision); any new advisory turns the lane red and opens a tracking issue. Configure deny for licenses (allowlist finalized by Q29), bans, and sources.
- Accept:
  - Lanes green with the documented `ml-dsa` ignore rationale; removing an ignore turns them red (test-of-the-test)
  - Scheduled run exists independent of PR traffic; new-advisory path opens an issue
  - Watchlist covers `ml-dsa`, `fips204`, `ed25519-dalek`, `ant-core`, and the CBOR encoder
- Notes: P13 stands up the lane; this task owns its permanent operation + the licenses section completion.

### Q11 — Define and execute the independent-implementation cross-check before M0 freeze
- Milestone: M0
- Size: L
- Deps: Q4, Q6; F: data-model definitions + decoder-rejection fixtures (F14); C: primitive definitions (C16); G: canonicalization/fine-tree definitions
- Spec: Revision note (line 5); Definitions & encoding (line 73); Milestones M0 (line 153)
- Do: Implement the mandated cross-check as committed scripts in an independent language plus a one-shot audit artifact plus a retained CI lane. Part A (CBOR, line 73): re-encode every golden manifest/bundle vector's data model with an independent non-Rust canonical-CBOR implementation (candidate: Python `cbor2` canonical mode, augmented with explicit RFC 8949 §4.2.1 checks) and byte-compare against the committed vectors; also confirm the rejection fixtures are genuinely non-canonical. Part B (crypto, line 5): independently re-derive HKDF outputs (length-prefixed info encoding), all salted commitments, the GGM salt tree, `fine_root`, Merkle roots, `work_id`/`anchor_digest`, padding, and Ed25519 strict-verification outcomes for every M0 vector; validate ML-DSA-65 via NIST ACVP KATs plus a cross-check between the two pinned Rust crates (`ml-dsa` vs `fips204`). Produce a discrepancy report; freeze (Q14) is blocked until it is empty.
- Accept:
  - 100% of frozen M0 vectors reproduced byte-identically by the second implementation; report committed and referenced by Q14
  - Decoder-rejection fixtures confirmed non-canonical by the independent implementation
  - Scripts live in-repo; a CI lane re-runs them when `testdata/vectors/` changes
- Notes: Whether an ml-dsa↔fips204 cross-crate check counts as "independent" for ML-DSA (both Rust, shared ecosystem) is Open decision 1; ACVP KATs are the mitigation.

### Q12 — Write the threat-model skeleton with the frozen Security-assumptions block
- Milestone: M0
- Size: S
- Deps: C: final Security-assumptions text (C20)
- Spec: Cryptography "Security assumptions" (lines 99–104); Milestones M0 (line 153)
- Do: Create `docs/threat-model.md` at M0 containing verbatim the frozen Security-assumptions block (binding = standard-model SHA-256 CR; hiding = ROM salted-prefix property; GGM PRG assumption + leaf-exact-cover soundness; AEAD confidentiality-only with the "never trust AEAD for binding" refactor rule; hybrid signature non-downgradability), plus a recorded sign-off (who/when) making the freeze an explicit decision, plus empty stubs for every M4 section (vault theft, vault loss, wallet linkability, malicious verifier host, coercion/compelled disclosure, hostile bundles, sealer-as-adversary, size-fingerprint, evidence independence, WASM zeroize caveat).
- Accept:
  - Skeleton exists before the M0 freeze tag; assumptions block matches C's frozen text verbatim
  - Sign-off record present; all M4 stubs enumerated
  - Referenced by the Q14 freeze checklist

### Q13 — Build the verification-coverage traceability matrix (spec lines 165–175)
- Milestone: M0
- Size: M
- Deps: Q4, Q7, Q8; C: adversarial doc-tests (C19); G: UTF-8 corpus + fine-tree E2E + perf budget; S: M1 devnet E2E suite; A: M2 smoke tests; R: M3 playwright/snapshot/endpoint-disagreement tests
- Spec: Verification section, all bullets (lines 165–175)
- Do: Commit a machine-checkable matrix mapping every Verification-section bullet to concrete test paths/IDs, owner domain, and milestone: M0 unit/property tests per crate, golden vectors + WASM bit-match, retained vectors, tamper matrix (M0 and M2 sets), fine-tree range-proof E2E + perf/memory budget, CBOR fuzzing, UTF-8 corpus, adversarial doc-tests (unsalted-unit and unsalted-file-hash confirmation-attack demonstrations); M1 devnet E2E items; M2 anchor smoke tests; M3 CLI+page verification, verdict-wording snapshots, online endpoint-disagreement; M4 gate. A CI script asserts every referenced test path resolves; each milestone gate requires the matrix rows for that milestone to be filled.
- Accept:
  - Every bullet in lines 165–175 has at least one row; CI check verifies referenced tests exist
  - M0 rows complete at the Q14 freeze; M1/M2/M3/M4 rows checked at their milestone reviews (M4 via Q34)
- Notes: Maintained continuously through M4; tagged M0 because it must exist at freeze. Artifacts: `docs/testing/verification-matrix.md` (34 rows) + `scripts/check-traceability.py --matrix`, CI lane `traceability`. **References are by NAME, never by line number** — D83 will move the GGM cover-node wire encoding and its tests with it, and a line-number matrix rots silently on the first refactor.
- **Finding, 2026-07-28 (M0 wave 6, first build of the matrix): one M0 bullet has no test and it blocks Q14.** Spec line 169's *"bundle/manifest CBOR fuzzing in CI"* is row **V3.4**, status `gap`. `fuzz/fuzz_targets/` holds exactly one target — R10's `verify_bundle`, which drives `verify_bundle`, not the CBOR decoders the spec names. The `fuzz-smoke` CI job is a reserved mount point whose only step prints *"Green here asserts NOTHING until Q9 lands the smoke run."* And the targets could not run if they existed: `rust-toolchain.toml` pins stable 1.92.0 while cargo-fuzz needs nightly, which `fuzz/Cargo.toml` records in its own header. **Three things are missing, not one** — the targets (F17), the nightly pin (**Q39**), the lane (Q9). Every other M0 bullet of lines 165–175 is covered.

### Q14 — Run the M0 format-freeze gate with recorded sign-off
- Milestone: M0
- Size: S
- Deps: Q5, Q6, Q8, Q11, Q12, Q13; P: encoder-crate pin + `ant-core` pin re-verified at M0 start (P9/P10); C: HKDF-distinctness golden test + WASM probe verdict (C3/C11); F: Definitions-section registries frozen (F4); G: pinned Unicode/NFC version recorded (G1)
- Spec: Revision note (line 5); Security assumptions (line 99); Milestones M0 (line 153)
- Do: Write and execute the freeze checklist: Definitions section frozen (CBOR profile + pinned encoder, domain-tag registry, id encodings, length-prefixed HKDF info, pinned Unicode version, signature context string); all M0 golden vectors committed and frozen (Q6) including the must-exist list; independent cross-check clean (Q11); tamper M0 registry fully implemented (Q8); HKDF-distinctness golden test green; WASM bit-match green (Q5); WASM probe decision recorded; Security-assumptions sign-off recorded (Q12); traceability M0 rows filled (Q13). **Plus every row in the `#### Q14 freeze checklist — normative rows` block immediately below this entry** (landed by Q37): the D84 freeze boundary, the three coupled report-version constants, the D86 decode-layer closure, the D88 zeroization disposition, the D75-contingent-on-D83 row, and the D31 cross-check row. Freeze is an annotated `format-v1-freeze` tag plus CHANGELOG entry.
- Accept:
  - Checklist committed; every item objectively green before the tag exists
  - Tag + CHANGELOG entry present; sign-off names/dates recorded
  - Any post-tag change to frozen material requires a format-version bump per Q27 policy
  - Every row in the normative-rows block below is ticked, **including the ones that record something as closed** — a row that says "known-and-accepted, not open" is ticked by verifying the evidence it names, not by agreeing with it
  - `scripts/check-traceability.py --freeze-boundary` green (the D84 rows here and in `docs/format/anchor-artifact-limits.md` §2 have not drifted)

#### Q14 freeze checklist — normative rows

> Landed by **Q37** (2026-07-28, M0 wave 6). These are the rows the gate
> quotes; Q14's `Do` above is the procedure that executes them. Rows marked
> *verbatim* are byte-identical copies of a decision record's own wording and
> must not be paraphrased — a paraphrase is how the two drift.

**Freeze boundary (D84 §7, verbatim).** Mirrored byte-identically in
`docs/format/anchor-artifact-limits.md` §2, which is what A5 and A11 read.
The two copies are drift-checked by
`scripts/check-traceability.py --freeze-boundary`.

<!-- FREEZE-BOUNDARY:BEGIN — D84 §7 verbatim. Byte-identical copies live in `docs/format/anchor-artifact-limits.md` §2 (A27) and here; `scripts/check-traceability.py --freeze-boundary` fails if they drift. Edit D84 first, then both copies. -->

- [ ] **Anchor-artifact freeze scope (D84).** Inside the v1 freeze: the
  anchor **envelope** — that an `.ots`, a TSA token, an intermediate
  certificate and a receipt payload are opaque CBOR `bstr`s in their
  registered keys (`docs/format/registry-v1.md` §7.8, §7.9); D10's byte and
  count caps over those fields — rows 6, 7, 8, 9, 16, 17, 18, 19:
  `MAX_OTS_ANCHOR_COUNT`, `MAX_TSA_ANCHOR_COUNT`, `MAX_INTERMEDIATE_COUNT`,
  `MAX_TX_HASH_COUNT`, `MAX_OTS_BYTES`, `MAX_TSA_TOKEN_BYTES`,
  `MAX_CERT_BYTES`, `MAX_RECEIPT_PAYLOAD_BYTES` — with their error codes;
  and rules **F1–F4** of D84 §4 (limits are
  evaluated only in the anchor stage; an over-limit artifact fails that
  anchor alone as `invalid`; limits may afterwards be raised, never
  lowered). **Outside the v1 freeze:** every numeric limit on the
  *internal* structure of those artifacts — DER nesting depth, certificate
  count and size within a validated chain, signed-attribute count, `.ots`
  op count, operand length, branch depth/width, attestation count. Those
  are verifier policy over foreign formats, are set at M2 against A25's
  recorded real artifacts (MVP-SPEC.md lines 153 and 155 place them there),
  and are **not** an exception to line 123 — under F1–F3 no released
  verifier ever rendered a verdict that depends on them, because M0/M1
  render every anchor `absent` (R12 replaces that stub at M2).
- [ ] **Report-version evolution is not blocked by this freeze.** The Q14
  freeze fixes report **v1** (`REPORT_VERSION = 1`, per R32 and D29 §8).
  D29 records that adding fields after the freeze requires a version bump,
  not that no bump may occur. M2's anchor stage will populate anchor states
  that report v1 does not carry and will therefore ship report **v2**; that
  is ordinary versioned evolution under line 123, whose promise is that v1
  reports remain verifiable, not that v1 is the last version.

<!-- FREEZE-BOUNDARY:END -->

**Coupled version constants — the row that makes a bump impossible to
half-land.**

- [ ] **`REPORT_VERSION` is `1` and its coupled edits are all in (R32; D29
  Recommendation rule 8).** Bumping it is a format event, never a chore.
  **Three** sites, and the third is a deliberate NEGATIVE:

  1. `testdata/vectors/v1/report/verification-reports.json` — all 21 pinned
     byte strings begin `{"report_version":1`. Re-emit with
     `cargo test -p antseal-core --features test-util --test report_vectors --
     --ignored emit_report_vector_document`, then `scripts/vector-freeze.sh
     --update`. **ENFORCED**: the vector executor fails on a bump without a
     re-emit, and post-freeze the checker refuses the changed digest.
  2. `EXPECTED_CANONICAL_JSON` in `crates/antseal-core/src/verify/mod.rs`'s
     `tests` — D29's fixed-fixture snapshot. **Enforced by NOTHING else.** It
     is a `#[cfg(test)]` unit test, so it runs in `wasm32-core-tests`, where
     stdout is discarded and a panic aborts the module: the whole diagnosis
     available there is `the test binary trapped: unreachable`, with no test
     name, no assertion and no message. Reproduce natively with
     `cargo test -p antseal-core --lib`. R32 missed this site; it passed every
     other lane. **R41** makes that lane name its failing test.
  3. **NOT** `wasm_bitmatch::TRANSCRIPT_VERSION` and **NOT**
     `EXPECTED_TRANSCRIPT_VERSION` in `scripts/wasm-bitmatch.mjs`. R32
     established on evidence that these version the transcript **envelope**:
     the transcript carries no report field, aggregates all **seven** vector
     kinds, is written to `target/`, appears in no `FROZEN.sha256`, and never
     meets `--update`'s changed-digest refusal. They stay `0` through this
     gate. Their `0` was a schema version doing double duty as a
     provisionality flag — *"`0` while D29 is a recommendation"* describes
     D29's status, not the transcript's shape. The rule now recorded in all
     four places that asserted the false coupling: **the transcript version
     moves when a transcript FIELD is added, removed, renamed or reordered,
     and never for a change in what the fields contain.**

  The gate confirms by `grep`, not by memory: (1) and (2) read `1`, (3) reads
  `0`, `FROZEN.sha256` matches after `--update`, and the `wasm-bitmatch` lane
  is green *after* the bump, not only before it.

  *(History: an earlier wave-6 draft of this row named all three constants as
  coupled and asked for all three to read `1`. R32's implementation disproved
  it — see its coupling verdict. **Q40**, registered against the superseded
  reading, is retargeted by **R42**.)*

**Report-format scope — what the freeze does and does not close.**

- [ ] **The decode layer is never a report field (D86, permanent).** `layer` is
  reserved forever in the report's namespace for the **evidence layer** and the
  **storage-linkage layer** (MVP-SPEC.md lines 118–119). The *decode* layer of
  registry §7.6.3 is **failure context only**: `VerificationReport` exists only
  for a bundle that passed (D27 §4), so a decode layer can never have a report
  to appear in. This is not "not yet" — it is closed for v1 and every future
  report version. If U30's `--json` **failure** envelope carries it (D65's call,
  M3), the field is named `decode_layer` and lives outside `VerificationReport`.
  The gate records this as **decided, not open**, so no later reader
  re-litigates it as a gap.

**Known-and-closed dispositions (so the gate does not read silence as an open
question).**

- [ ] **Zeroization dispositions closed (C21/C22/D88).** `Cargo.toml` shows
  `sha2 = { version = "=0.11.0", default-features = false, features =
  ["zeroize"] }`; `crates/antseal-core/tests/zeroization_residue.rs` green
  on native; `docs/zeroization-audit.md` R1 carries the dated D88
  disposition and its narrowed residue; R2–R5 carry dated accepted
  dispositions. **Known-and-accepted, not open.**

- [ ] **Full-reveal cover shape (D75) — closed *contingent on D83.*** D75 is
  RESOLVED and ratified: a full reveal ships per-unit covers **and** `s_root`
  (`covered_reveal.cover`, registry §7.11 key 3, stays required at tier [P]).
  **This row may not be ticked while D83 is open.** D75's discharged open
  action carries an exception whose subject is exactly D83's inert leaf-level
  seed tails: the two routes to `fine_root` agree transitively on every byte
  any check reads, and the bytes they may disagree on are the ones D83 governs.
  If D83 shortens or canonicalizes the tail, D75's original discharge becomes
  true as written and the exception is deleted; if D83 accepts the malleability,
  the exception becomes permanent and D75 carries it for good. Either way the
  amendment is written **after** D83, not before. Tick this row only once D83 is
  RESOLVED and D75's amendment records which branch was taken. Related: **R36**
  (no committed fixture currently produces a leaf-level cover node — every
  fixture length is even, so `n` is never odd) and **R37**.

**Verification coverage — the row that names what is still missing.**

- [ ] **Traceability matrix M0 rows complete (Q13).**
  `docs/testing/verification-matrix.md` carries a row for every bullet of
  MVP-SPEC.md lines 165–175, and `scripts/check-traceability.py --matrix`
  is green — every test the matrix names resolves. **Every M0 row reads
  `covered`.** As of 2026-07-28 exactly one does not: **V3.4, spec line 169's
  "bundle/manifest CBOR fuzzing in CI"**, which needs three things that do not
  exist — the manifest/bundle targets (F17), a pinned nightly toolchain
  (**Q39**; `rust-toolchain.toml` pins stable and cargo-fuzz needs nightly),
  and the smoke lane (Q9). The `fuzz-smoke` job's own output says *"Green here
  asserts NOTHING until Q9 lands the smoke run"*, so a green CI run is not
  evidence for this row. **This row blocks the freeze tag.** The in-suite
  arbitrary-bytes property tests (`verify_fuzz.rs::arbitrary_bytes_never_panic`,
  `codec_properties.rs::arbitrary_bytes_never_panic_the_decoder`) are a
  recorded partial mitigation and explicitly do not discharge it.

**Independent cross-check (D31 §10, verbatim).**

- [ ] **Independent cross-check clean (Q11/F14/D31).** `docs/testing/
  cross-check.md` carries a dated report for this freeze commit with
  **zero discrepancies**, naming per surface the vehicle, its exact version,
  the vector count and the evidence tier (T0 external oracle / T1
  independent re-implementation / T2 same-ecosystem agreement). Every
  surface in D31 §2 rows 1–13 is present at T0 or T1. **Row 14
  (`ml-dsa`↔`fips204`) is T2 and does not count toward this row** — it is
  D14's fallback-equivalence evidence. The `cross-check` CI lane is green
  and unconditional, and `scripts/cross-check.sh` iterates every retained
  format version rather than a hard-coded `v1`.

### Q15 — Decide and implement the devnet E2E execution strategy
- Milestone: M1
- Size: M
- Deps: Q1; S: M1 E2E test suite (S17/S18/S19) + devnet environment scripts (P16)
- Spec: Milestones M1 (line 154); Verification M1 (line 172)
- Do: Measure the 25-node devnet + Anvil resource footprint on a GitHub-hosted runner and decide the venue: a CI job (with cached node binaries) if it fits, otherwise a documented `scripts/e2e-devnet.sh` local gate required before merging storage-touching PRs, optionally plus a scheduled self-hosted job. Wrap S's suite (multi-file `--split` seal, kill-between-pay-and-finalize → no-double-payment, kill-mid-upload → byte-identical resume + nonce-reuse-guard abort, restore-from-backup, UNANCHORED library verify, `--live` re-fetch) with deterministic setup/teardown and node/Anvil log capture on failure.
- Accept:
  - Venue decision recorded with measurements; chosen mechanism runs S's full M1 suite green
  - Failure runs upload node + Anvil logs as artifacts
  - Contributor doc states when the gate is mandatory

### Q16 — Establish anchor CI lanes and the real-network smoke policy
- Milestone: M2
- Size: M
- Deps: Q1, Q13; A: mock TSA server + recorded OTS/TSA fixtures (A24); A: smoke-test implementations (A25)
- Spec: Milestones M2 (line 155); Verification M2 (line 173); Risks "Free-TSA terms/rate limits" (line 189)
- Do: Wire the CI anchor lane to run exclusively against A's mock TSA and recorded OTS fixtures, and enforce a no-real-anchor-network policy in CI (rate-limit and terms-of-service respect: SwissSign ~10/day, Sectigo ~15 s, dfn non-commercial). Write the real-network smoke runbook A executes at M2: OTS calendar submit with next-day pending→upgraded confirmation, real FreeTSA (ECDSA P-384) and DigiCert token capture verified against pinned roots, and the fixture re-record/refresh procedure (including pinned-root-store updates).
- Accept:
  - CI anchor lane green with zero external anchor-network calls (verified via sandbox or endpoint blocklist)
  - Runbook committed; one M2 execution recorded with artifacts and fixtures committed by A
  - Fixture/root refresh procedure documented

### Q17 — Extend fuzz lanes with DER and `.ots` targets
- Milestone: M2
- Size: S
- Deps: Q9; A: DER TimeStampResp + `.ots` fuzz targets (A23); A: recorded real-token fixtures (via Q16/A25)
- Spec: Milestones M2 (line 155); Verification (line 169)
- Do: Register A's DER (TimeStampResp/TSTInfo) and `.ots` parser targets in the fuzz workspace; seed their corpora from recorded real tokens, `.ots` fixtures, and the M2 tamper cases (including BER-where-DER); include them in both the per-PR smoke lane and the nightly run.
- Accept:
  - Both targets run in the required smoke lane and nightly schedule
  - Corpora seeded and committed; crash-triage path identical to Q9

### Q18 — Register the M2 anchor rows in the tamper-matrix tracker
- Milestone: M2
- Size: S
- Deps: Q7, Q8; A: implemented anchor tamper rows (A21)
- Spec: Verification M2 rows (line 168); Milestones M2 (line 155)
- Do: Extend the Q8 registry with the six M2 families: `.ots`/TSA token for a different digest; well-formed TSA token from an untrusted root → `internally-consistent-only` (verdict-state row, never headline); forged Bitcoin header failing the `--online` block match → `invalid`; an `attested` OTS anchor correctly withheld from the offline headline; expired-at-genTime vs expired-after-genTime chain cases rendering distinctly; BER-where-DER-required. Re-run the distinctness assertion across the combined M0+M2 set.
- Accept:
  - Registry complete against the spec's M2 enumeration; CI red until A implements every row
  - Distinctness holds across the full combined matrix, including verdict-state rows

### Q19 — Add the headless-browser (playwright) page-verification CI lane
- Milestone: M3
- Size: M
- Deps: Q1; R: built page + reproducible build output (R23/R25). R27's suite runs in this lane — consumer, not an ordering dep.
- Spec: Milestones M3 (line 156); Verification M3 (line 174)
- Do: Install playwright + chromium in CI, serve R's built page from localhost with external network disabled (the offline verdict must need no network), and run R's suite: bundle drag-drop verification, verdict-wording snapshots, redaction-view checks, and the online-mode endpoint-disagreement case (against local stub endpoints). Upload screenshots/traces on failure and log the wasm build hash of the page under test.
- Accept:
  - Lane green in CI at M3; offline enforcement demonstrated (external requests blocked, verdict still renders)
  - Failure artifacts (screenshot + trace) produced on a seeded failure
  - Lane consumes the reproducible build output, hash logged

### Q20 — Extract the positioning-copy style guide and copy lint
- Milestone: M3
- Size: M
- Deps: R: authoritative verdict wording set (R18); U: CLI string inventory (U31)
- Spec: Product definition (lines 23–31, esp. 28); Anchoring receipt copy (line 110); Verifier page (lines 127–137, esp. 137); Vault (line 143)
- Do: Codify the normative copy rules as a checkable style guide: banned — "notary" in legal/product copy, unqualified "priority", any authorship or exclusive-possession claim; required — possession phrasing ("the holder of key X possessed this content by time T"), "seal before you share", the compelled-disclosure note, receipt as "supporting evidence — no independently proven time", claimed time as "asserted by sealer — NOT verified", and the single canonical verifier URL as a shared constant. Implement a lint script scanning docs, CLI strings, and page copy with an allowlist for quoted/spec contexts, wired into CI.
- Accept:
  - Guide committed by M3 so R's snapshot-tested wording set passes it; each rule cites its spec line
  - Lint in CI; a seeded violation ("legal notary" in a docs file) is caught (test-of-the-test)
- Notes: Spec assigns the docs set to M4, but line 28/137 constraints bind R's M3 verdict copy, so the guide must exist at M3; full-corpus enforcement completes in Q28. Implement the lint once, shared with U31.

### Q21 — Finalize the threat-model document
- Milestone: M4
- Size: M
- Deps: Q12, Q20; C: adversarial doc-test references (C19). (Q34 appends the concrete mainnet-exposure work-id/date note post-gate — consumer, not a dep.)
- Spec: Milestones M4 (line 157); Risks (lines 177–189); Cryptography size-fingerprint (line 91); Vault (line 143)
- Do: Expand the skeleton into the finalized document covering: vault theft (retroactive, permanent decryption of public undeletable ciphertexts; no rotation exists; KDF-hardening context); vault loss (reveal/restore lost forever; sealed data stays unreadable); wallet linkability (receipt links every seal to one wallet and that wallet to a KYC identity; fresh-address-per-work hygiene; `--include-receipt` default-off); malicious verifier host (lying JS; provenance mitigations; CLI cross-check); coercion/compelled disclosure (the vault holder can always be forced to reveal; vault destruction is the only, irreversible opt-out); hostile bundles (adversary-authored CBOR/DER/`.ots` in the counterparty's browser; parser hardening, caps, fuzzing); sealer-as-adversary (chosen positions/sizes/claimed time; structural invariants; single-authoritative-commitment rule); the residual per-unit size-fingerprint (bucketed sizes under `--split` as a partial fingerprint; grouping difficulty as the primary defense; format-version escape hatch for coarser padding). Include the frozen assumptions block, the evidence-independence-from-Autonomi stance with the accepted one-time mainnet exposure, and the WASM zeroize caveat; cross-link C's confirmation-attack doc-tests as regression guards.
- Accept:
  - All eight mandated topics plus assumptions, Autonomi-independence, and WASM-zeroize caveat present
  - Every Risks-section row (lines 177–189) is addressed here or explicitly delegated to a named doc page
  - Q20 lint passes; assumptions block still verbatim

### Q22 — Write README, install guide, and product-limits/disclosure docs
- Milestone: M4
- Size: M
- Deps: Q20, Q30 (verification instructions), Q31 (distribution channel); U: canonical CLI command surface; R: canonical verifier URL live (R26)
- Spec: Product definition (lines 23–31); Core flows (line 34); scope decision 2 (line 18); Salted commitments metadata note (line 95); Milestones M4 (line 157)
- Do: Write the README: one-liner (line 24), MVP-user framing, quickstart (`init` → `seal` → `status` → `reveal` → `verify`), install instructions including binary signature verification (sha256sums + minisign/cosign steps), and the zero-install verifier story with the canonical URL. Include the limits/disclosure model up front: possession-not-authorship, not a legal notary, seal-before-you-share, compelled-disclosure note; the title is embedded in the plaintext manifest every bundle carries; structure metadata (file count, sizes, unit boundaries) is visible to bundle recipients; `--no-fine-tree` files are permanently whole-file-reveal only; per-unit reveal now, byte-range reveal in v1.1. Link every other doc page.
- Accept:
  - All listed sections present; Q20 lint green
  - Install-and-verify instructions proven on a clean machine during the Q34 gate
  - Canonical URL identical to CLI/page usage (checked by Q28)

### Q23 — Write the "funding your wallet" doc
- Milestone: M4
- Size: S
- Deps: Q20; U: `init` funding-instruction text (U11); S: quote/cost figures for realistic examples
- Spec: Core flows consent step (line 34); Milestones M4 (line 157); CLI surface network flags (line 149)
- Do: Document funding on Arbitrum One: acquiring ETH (gas) and ANT (storage payment) on Arbitrum One, bridging notes, and how the CLI reports insufficient-token vs insufficient-gas as distinct errors. Cover the development networks (`--network arbitrum-sepolia|devnet`, noting it is Arbitrum Sepolia chain 421614, not Ethereum Sepolia) and typical seal-cost expectations.
- Accept:
  - Both ETH and ANT paths covered; distinct-error explanation matches CLI behavior
  - Consistent with the text `init` prints (U); lint green

### Q24 — Write the vault-loss and vault-theft doc pages
- Milestone: M4
- Size: S
- Deps: Q20, Q21; U: CLI nag wording (U18)
- Spec: Vault (line 143); Risks (line 184); Milestones M4 (line 157)
- Do: Write both loud failure-mode pages. Loss: losing the vault and backup means losing reveal/restore ability forever while the sealed data stays safely unreadable; `vault export`/`import` procedure and backup discipline. Theft: a stolen vault retroactively and permanently decrypts public, undeletable ciphertexts with no possible rotation; treat the passphrase and any export as a long-term high-value key; passphrase-strength floor, keyfile/OS-keystore wrap option, Argon2id hardening context.
- Accept:
  - Both pages exist and are linked from README and `init` output (U)
  - Wording consistent with CLI nags and the threat model; lint green

### Q25 — Write the wallet-hygiene guidance
- Milestone: M4
- Size: S
- Deps: Q20, Q21, Q23
- Spec: Risks "wallet linkability" (line 185); Reveal flow `--include-receipt` (line 36); Milestones M4 (line 157)
- Do: Document the linkability chain (payment receipt → wallet → funding exchange/KYC → identity), the fresh-address-per-work-or-client recommendation, and why `--include-receipt` is off by default with what opting in discloses.
- Accept:
  - Fresh-address practice, receipt-exposure explanation, and linkability chain all present
  - Consistent with the threat-model section and Q23; lint green

### Q26 — Write the TSA defaults-and-alternates doc
- Milestone: M4
- Size: S
- Deps: Q20; A: pinned root-store update procedure (A26); U: TSA-list config mechanism (U26)
- Spec: Anchoring RFC 3161 (line 109); Risks (lines 182, 189); Milestones M4 (line 157)
- Do: Document the default TSAs — FreeTSA (`https://freetsa.org/tsr`) and DigiCert (`http://timestamp.digicert.com`) — and the alternates with their recorded caveats: zeitstempel.dfn.de (non-commercial terms), Sectigo (~15 s spacing), SwissSign (~10/day). Explain configuring a custom TSA list, the ≥1-token-or-abort minimum-anchor policy, `--force-degraded` consequences, and how TSA failures downgrade the seal report rather than failing silently; note genTime LTV ("expired ≠ invalid") for aging bundles.
- Accept:
  - All five TSAs listed with caveats; config steps match the implemented mechanism
  - Minimum-anchor and degraded semantics documented; lint green

### Q27 — Write the format-stability policy doc
- Milestone: M4
- Size: S
- Deps: Q6, Q14; G: Unicode-table retention mechanism (G1); R: page multi-version support (R28)
- Spec: Format stability (line 123); Canonicalization Unicode versioning (line 83); Milestones M4 (line 157)
- Do: State the normative policy: every released manifest/bundle format version remains verifiable by all future CLI and page releases; per-version golden vectors are retained in CI indefinitely (Q6 mechanism); the hosted page supports all released versions; NFC normalization tables are retained per descriptor-recorded Unicode version so aging bundles never false-positive as tampered; evolution prefers reserved slots over breaking changes; define what forces a format-version bump and the freeze procedure for a new version (mirroring Q14). **Carry the v1 freeze boundary forward (Q37/D84 §7)**: reproduce the boundary statement so it survives past M0 — inside the freeze, the anchor **envelope** (opaque `bstr`s in their registered keys) and D10's byte/count caps over it, plus rules **F1–F4** of `docs/format/anchor-artifact-limits.md`; outside it, every numeric limit on the *internal* structure of a foreign artifact (`.ots` ops, DER nesting, chain certificate count/size, signed attributes). State plainly that artifact-internal limits are **verifier policy over foreign formats and are NOT an exception to MVP-SPEC.md line 123** — under F1–F3 no released verifier ever rendered a verdict that depends on them. **This document is the third copy of that rule; extend `scripts/check-traceability.py --freeze-boundary` to cover it in the same commit — no separate task, because a copy added without its lint is the drift this row exists to prevent.**
- Accept:
  - Policy doc committed, citing the Q6 retention guard and R's multi-version support as enforcement
  - Unicode-version retention and reserved-slot preference stated; version-bump criteria defined
  - The freeze-boundary statement is present, names artifact-internal limits as verifier policy over foreign formats rather than an exception to line 123, and is byte-identical to Q14's block and A27's §2 — asserted by the drift lint, not by review
- Notes: **This task, not Q19, is the format-stability policy.** D84's F4, D84 §Consequences item 3, and Q37's original entry all cited "Q19"; Q19 is the M3 playwright lane. Corrected 2026-07-28 — see Q37's Correction note.

### Q28 — Audit all copy for positioning and canonical-URL consistency
- Milestone: M4
- Size: S
- Deps: Q20, Q21–Q27; U: final CLI strings (U31/U32); R: final page copy + footer (R23/R25)
- Spec: Product definition (line 28); Page provenance (line 139); Milestones M4 (line 157)
- Do: Run the Q20 lint plus a manual pass over the full corpus: README, all doc pages, threat model, CLI `--help` and runtime output (U), page copy and footer (R), and release-note templates. Verify the canonical verifier URL is a single shared constant appearing identically in docs, `reveal` output, and the page footer; verify receipt copy always reads "supporting evidence" and claimed-time copy is always subordinate/NOT-verified.
- Accept:
  - Lint green repo-wide including extracted CLI/page strings
  - Exactly one canonical URL value found by grep across all surfaces
  - Signed-off audit checklist committed; violations fixed before Q34 release

### Q29 — Choose the license and add license files
- Milestone: M4
- Size: S
- Deps: Q10 (deny license allowlist); P: crates.io name reservations (P2 — may need placeholder license earlier)
- Spec: Milestones M4 (line 157)
- Do: Decide the license set — at minimum permissive/open for `antseal-core` and `verifier-web`, since "hostable on any static host" presumes redistribution rights (MIT OR Apache-2.0 dual is the Rust-ecosystem default candidate). Add LICENSE files at workspace root and per published crate plus verifier-web, set `license` fields in every Cargo.toml, define the SPDX-header policy, and align the cargo-deny license allowlist with the choice.
- Accept:
  - LICENSE files present for workspace, `antseal-core`, and `verifier-web`; Cargo.toml fields set
  - cargo-deny licenses lane green against the final dependency tree
  - Decision + rationale recorded
- Notes: Spec assigns this to M4; recommend deciding at pre-M0/M0 anyway since P's crates.io placeholder publishes require a license — recorded as a disagreement, task stays at its spec milestone.

### Q30 — Generate signing keys and build the binary-signing pipeline
- Milestone: M4
- Size: M
- Deps: Q1 (Q31 is the consumer of the signing step)
- Spec: Milestones M4 "binary signing (sha256sums + minisign/cosign) + documented distribution channel" (line 157); Page provenance (line 139); Risks (line 186)
- Do: Choose the mechanism (minisign, cosign, or both — Open decision 7), generate the signing keypair as an external action with a written custody procedure (offline backup, holder, compromise response), and publish the public key in at least the repo and the docs/release notes. Wire signing into the release workflow: every released artifact ships with sha256sums plus signature(s). Write the user-facing verification instructions consumed by Q22, and document the distribution channel (e.g. GitHub Releases) as the single authoritative source.
- Accept:
  - Public key published in ≥2 places; custody doc committed
  - A test artifact's signature verifies on a clean machine using only published instructions
  - sha256sums + signatures produced automatically by the release pipeline; distribution channel documented

### Q31 — Build the release workflow, versioning scheme, and provenance publication
- Milestone: M4
- Size: L
- Deps: Q1, Q30; P: crate naming for any crates.io publish (P2); R: reproducible wasm-pack build recipe + build hash + deployed page (R25/R26)
- Spec: Milestones M4 (line 157); Page provenance (line 139); Format stability (line 123)
- Do: Implement the tag-triggered release pipeline: build release binaries for the decided target set, generate sha256sums, sign (Q30), rebuild the verifier wasm twice in independent environments and require identical hashes (R's reproducible recipe), and publish a draft release containing artifacts, hashes, the wasm build hash, and a release-notes template (canonical URL; first release notes the accepted one-time mainnet exposure). Define the version/tag scheme: app SemVer tags, manifest/bundle format versions as independent integers, and freeze tags — documented with their relationship. Execute the crates.io publish decision (which crates, if any). Write the release checklist that gates publication on Q34 gate evidence and on the deployed page's hash matching the published one.
- Accept:
  - A dry-run tag produces a complete signed draft release; wasm hash identical across two independent builds
  - Versioning doc committed; format-version independence stated
  - Release checklist requires gate evidence + page-hash match; crates.io decision recorded and executed

### Q32 — Script the M4 gate (Sepolia E2E, clean-machine verification, disk-loss drill)
- Milestone: M4
- Size: L
- Deps: Q22, Q30, Q31; S: Sepolia devnet environment (P17) + restore capability (S14/S19); U: full CLI surface incl. `vault export`/`import` (U12/U32); R: hosted page live at canonical URL (R26); A: anchor flow on real TSAs/calendars (A25)
- Spec: Milestones M4 (line 157); Verification M4 gate (line 175); Restore flow (line 37)
- Do: Implement the gate as runnable scripts plus procedures. (a) Sepolia-mode E2E driving the release-candidate binary end-to-end: `init` → funding preflight → multi-file `seal` with `--split` → `status --upgrade` → `reveal` subset → `verify` (offline, `--online`, `--live`) → `restore` with byte-compare. (b) Clean-machine procedure: a fresh VM/container definition that installs only the released binary from the documented channel, verifies its signature per Q22 instructions, and verifies a bundle via both the hosted page and the CLI. (c) Disk-loss restore drill: a second clean machine with nothing but the encrypted vault backup — `vault import` → `restore` → byte-identical originals → `reveal`+`verify` still work. Include evidence-recording templates.
- Accept:
  - Scripts committed and re-runnable; Sepolia run green before any mainnet action
  - Clean-machine procedure uses zero repo-checkout resources (released artifacts + hosted page only)
  - Drill proves vault-backup-only recovery with byte-identical output; procedures executable by a non-author (walkthrough recorded)

### Q33 — Fund the gate wallets (external action)
- Milestone: M4
- Size: S
- Deps: Q25 (hygiene rules), Q32; S: cost estimation via quotes
- Spec: Milestones M4 (line 157); Verification M4 (line 175); Network decision (line 20)
- Do: Create fresh, unlinked wallet addresses per the Q25 hygiene guidance. Fund the Arbitrum One wallet with small amounts of ANT + ETH sized from quote estimates plus margin for the single smoke seal; fund the Arbitrum Sepolia wallet (Sepolia ETH + Sepolia ANT per upstream's `start-devnet-sepolia` requirements) for the gate E2E. Record addresses and amounts (never keys) in the gate evidence.
- Accept:
  - Both wallets pass the CLI balance preflight; fresh addresses confirmed
  - Funding amounts and acquisition route recorded in gate evidence

### Q34 — Execute the M4 gate, perform the mainnet smoke seal, and ship the release
- Milestone: M4
- Size: M
- Deps: Q13, Q21, Q28, Q31, Q32, Q33; U: `--network` default = arbitrum-one in release build (U32)
- Spec: Milestones M4 (line 157); Verification M4 gate (line 175); Risks (line 180)
- Do: Run the full gate against the release candidate: Sepolia E2E green → exactly one small real mainnet seal (the only pre-release public-network exposure) → end-to-end verification from the clean machine using only the signature-checked released binary and the hosted page (headline time from a TSA token) → disk-loss restore drill → confirm the released binary defaults to `arbitrum-one`. Then complete the Q31 checklist, publish the release, and record the accepted one-time exposure (work-id, date) in the release notes and threat model. Confirm the Q13 traceability matrix is fully green for all milestones.
- Accept:
  - Evidence bundle committed: gate logs, page-verdict capture, restore byte-compare, drill results
  - Release public via the documented channel with mainnet default verified
  - One-time mainnet exposure recorded; traceability matrix 100% green

### Q35 — Plan and run the ≥10-external-users success metric
- Milestone: M4
- Size: S
- Deps: Q22, Q34; R: hosted page live (R26)
- Spec: Milestones M4 success metric (line 157); Product definition MVP user (line 26)
- Do: Write the plan before release: completion = an external user seals their own work, reveals a subset, and an independent third party verifies the bundle on the hosted page. Define recruitment (Autonomi/Saorsa community channels, Show-HN-style post, direct outreach to researchers/creators/small IP-legal practices per the MVP-user profile), a guided onboarding path reusing Q22 docs, and measurement without telemetry (the page has no backend): facilitated sessions, self-report form, optional shared verdict screenshots. Maintain a tracking sheet with weekly review until ≥10 completions.
- Accept:
  - Plan + tracking artifact committed pre-release; completion definition matches the spec metric verbatim
  - First outreach batch scheduled; progress reviewed weekly post-release
- Notes: Execution is post-release/continuous; the plan is the M4 deliverable. Measurement method is Open decision 9.

### Q36 — Stand up the weekly upstream-bump check chore
- Milestone: continuous
- Size: S
- Deps: Q10; P: authoritative pin list (P7/P19); S: devnet E2E as bump-validation gate (via Q15)
- Spec: Milestones M4 post-release chore (line 157); Risks "ant-core churn" (line 179); Network decision (line 20)
- Do: Create a scheduled weekly CI job that diffs the pinned versions (`ant-core =0.5.0`, `ml-dsa =0.1.1`, `fips204 =0.4.6`, `ed25519-dalek`, `opentimestamps 0.2.0`, the CBOR encoder) against latest crates.io releases and the RUSTSEC database, then opens or refreshes a tracking issue with changelog links. Write the bump-procedure doc making bumps deliberate reviewed events: read upstream changelog, assess `StorageBackend`-adapter impact, run devnet E2E plus the full CI matrix before merge — never drive-by.
- Accept:
  - Cron workflow live and producing a weekly report/issue (first run recorded)
  - Bump procedure doc committed; user acceptance of the tracking cadence noted per spec
- Notes: Same chore as P19 — implement once, owned jointly (P mechanics, Q operation).

### Q37 — Record the v1 freeze boundary in the Q14 checklist and the stability policy
- Milestone: M0
- Size: S
- Deps: D84; Q14 (this is a checklist edit Q14 executes); **Q27** (the stability policy it also lands in — **not Q19**, see Notes); A27 (the mirror A5/A11 read)
- Spec: Format stability (MVP-SPEC.md line 123); Milestones M0/M2 (lines 153, 155)
- Discovered by: **D84** (2026-07-28). The freeze gate currently has no statement of what is *outside* the freeze. Without one, a later reader has two equally available misreadings: that A's M2 artifact limits were frozen and may never move, or that anything not listed is free — including the anchor envelope, which is frozen. D84 §7 writes the boundary in both directions; this task lands it where the gate can quote it.
- Do: Add D84 §7's two rows verbatim to Q14's freeze checklist — the anchor-artifact freeze-scope row (what is inside: the opaque-`bstr` envelope, D10 rows 6–9 and 16–19 with their codes, rules F1–F4; what is outside: every numeric limit on artifact-internal structure) and the report-version-evolution row (the Q14 freeze fixes report **v1**; M2's anchor stage ships report v2, which is ordinary versioned evolution under line 123, not a freeze violation). Carry the same freeze-boundary statement into **Q27's** format-stability policy so it survives past M0, and cross-reference A27's contract. **Also fold into the same checklist block the rows that have no other home**: the three coupled report-version constants (D87 §6 — R32 names only one of three), the D86 decode-layer closure, the D88 zeroization disposition, the D75 row that is contingent on D83, and the D31 §10 cross-check row.
- Accept:
  - Both rows present in Q14's checklist, byte-identical to D84 §7 and to A27's mirror.
  - **Q27's** policy text states the boundary and names artifact-internal limits as verifier policy over foreign formats, **not** as an exception to line 123.
  - A test or checklist-lint asserts the copies of the boundary rule have not drifted — hand-maintained copies of one rule is how the rule dies. **Two copies exist at M0** (Q14's block, A27's doc), checked by `scripts/check-traceability.py --freeze-boundary`; the third (Q27's policy) appears at M4, and extending the lint to it is written into Q27's own `Do`/`Accept` rather than deferred to a task of its own.
- Notes: The report-version-evolution row exists because R32's `REPORT_VERSION` 0 → 1 bump lands in the same wave, which makes "the report format is frozen" an easy and wrong thing to conclude.
- **Correction, 2026-07-28 (Q37 execution)**: D84's F4, D84 §Consequences item 3, and this entry as originally written all cited **"Q19"** for the format-stability policy. **Q19 is the headless-browser (playwright) page-verification CI lane, an M3 task.** The format-stability policy doc is **Q27**, and the freeze procedure it mirrors is **Q14**. All three citations are the same slip; it is corrected in this entry and in Q27, and recorded — with D84's F4 text left byte-identical to the record — as an editorial note in `docs/format/anchor-artifact-limits.md` §1.

### Q38 — Cross-check the verification-report byte format against an independent reader
- Milestone: M0
- Size: S
- Deps: D29 (the contract), R9 (the 21 pinned report vectors), R32 (the `REPORT_VERSION` bump — run **after** it, or all 21 strings move underneath this), D31 (the lane it joins)
- Spec: Revision-2 independent cross-check mandate (MVP-SPEC.md line 5); Verification (line 167)
- Discovered by: **D31** (2026-07-28). Q11's scope is "CBOR + crypto". The verification-report byte format is neither, yet it is a **v1 format that freezes at Q14** (D29) with 21 byte-pinned strings (R9) and **no independent implementation checking any of it**. A full independent vehicle is not sensible — reproducing a report means reproducing all of verification — but D29's contract is a set of *syntactic* properties, and those are cheap to check with an independent JSON reader.
- Do: Write a Python checker (stdlib `json` only, no third-party dependency) over every committed report vector in `testdata/vectors/v1/report/`, asserting D29's contract independently of the Rust encoder: every pinned string parses as JSON; re-serialising the parsed value with `json.dumps(..., separators=(',', ':'), ensure_ascii=False)` preserving the original key order reproduces the exact bytes (compact separators + declaration order); no value anywhere in the tree is a float; every hex string is lowercase and even-length; ~~every key matches `^[a-z0-9]+(-[a-z0-9]+)*$`~~ **[corrected at execution — see the correction note below]** every key matches snake_case `^[a-z][a-z0-9]*(_[a-z0-9]+)*$`, and every *enum value* matches kebab-case `^[a-z0-9]+(-[a-z0-9]+)*$`; `report_version` is the first key of every document and equals the pinned constant. Add a `--check` mode and wire it into `scripts/cross-check.sh` (D31 §6b) so it runs in the same permanent lane.
- Accept:
  - All committed report vectors pass; the run is recorded in `docs/testing/cross-check.md` as its own surface row with its tier.
  - Self-test: a deliberately mutated copy (a float introduced; a key reordered; an uppercase hex digit) makes the checker fail, once for each property — a checker never observed failing proves nothing.
  - Iterates `testdata/vectors/v*/report/`, not a hard-coded `v1`.
- Notes: Tier is **T1 with no T0 anchor** and the report must say so — the contract is ours, so there is nothing external to check it against. That is the honest ceiling here, not a shortfall.
- **[2026-07-28] Correction, found at execution.** This entry's key regex `^[a-z0-9]+(-[a-z0-9]+)*$` is **wrong** and contradicts the artifact it claims to check. D29 rule 7 has two clauses: *"Enum wire names are kebab-case … Field names are the Rust snake_case names, unrenamed."* The regex is the enum clause applied to keys. Run as written it rejects **20 of the 34 keys** in the committed reports — `report_version`, `work_id`, `format_version`, `signature_scheme`, `storage_linkage` and the rest — i.e. it would have failed on correct bytes, at the freeze gate, and the obvious "fix" would have been to change the *bytes*. Implemented as two separate properties (P6 snake_case keys, P9 kebab-case enum values) and the planted-fault suite carries a kebab-case-key fault as the standing regression guard. Worth noting how it survived: the D29 summary line in `testdata/vectors/v1/report/README.md` reads *"kebab-case enum names"*, which is correct but compresses to "kebab-case" in a reader's memory.
- **[2026-07-28] LANDED.** `scripts/crosscheck-report.py`, 21 pinned strings, 9 byte-level properties + 3 envelope checks each, self-test proving all 12 able to go red on 17 planted faults + 1 control. All 21 strings verified to begin `{"report_version":1` (R32 confirmed present, not assumed). **One limit found and recorded** rather than glossed: **P3 cannot detect a key reordering**, because it re-serialises in the order the bytes carried — a uniformly-applied reorder round-trips cleanly. P8 catches an *inconsistent* order and P7 catches `report_version` leaving the front, but a global reorder would survive both. Catching it needs a reader that independently knows the Rust struct declaration order, and regex-parsing that out of `report.rs` is exactly the brittleness that produces a false red at a freeze gate. The mitigation is not a cross-check: reordering a field moves every pinned string at once, so `vector-freeze` and the bit-match lane both go red. Also relevant: **P9's enum registry and P5's 16-character hex-shape floor are heuristics**, both documented in the script with why the alternatives (token-shaped→kebab, any-hex-chars→hex) were rejected as false-positive generators.

### Q39 — Pin the fuzz-lane nightly toolchain (the blocker under F17, Q9 and Q17)
- Milestone: M0 (it gates an M0 spec bullet; the work is small and the blocker is absolute)
- Size: S
- Deps: P8/P13 (the toolchain-pin policy this must not violate); consumed by F17, Q9, Q17, A23
- Spec: Milestones M0 (MVP-SPEC.md line 153, "cargo-fuzz targets for the bundle/manifest CBOR parsers in CI"); Verification (line 169); Risks — hostile bundles (line 187)
- Discovered by: **Q13** (2026-07-28), building the traceability matrix against the tree rather than against task text. `rust-toolchain.toml` pins stable **1.92.0**; cargo-fuzz needs nightly for `-Z sanitizer` and libFuzzer instrumentation. `fuzz/Cargo.toml` records this in its own header — *"It also cannot build on the pinned stable toolchain… Q9 owns that pin"* — and `.github/workflows/ci.yml` says the same in the `fuzz-smoke` mount point's comment. **So the blocker is documented in two places and owned in neither**: Q9's `Do` describes wiring lanes and its Accept says F's targets "run in the required smoke lane at M0", which is unachievable as written. This is the piece that makes the rest possible.
- Do: Choose and pin the nightly toolchain the fuzz lanes use, **without** touching `rust-toolchain.toml` (the workspace MSRV pin must stay stable — a nightly there would silently widen what the product is allowed to compile against). Options to weigh and record: a `fuzz/rust-toolchain.toml` scoped to the detached fuzz crate; an explicit `cargo +nightly-<date>` in the lane with the date pinned in one place; or `RUSTUP_TOOLCHAIN` set per job. Whichever is chosen, the nightly is an **exact dated pin** under the same deliberate-event rule as every other pin (`docs/dependency-policy.md`), with a documented bump procedure — a floating `nightly` makes the fuzz lane a source of unreproducible red.
- Accept:
  - `cargo fuzz build` succeeds locally and in CI for the existing `verify_bundle` target, with the workspace's stable pin unchanged and `cargo build --workspace` unaffected.
  - The nightly version is pinned exactly, in exactly one place, and named in `docs/toolchain.md` alongside the stable pin with its bump procedure.
  - The `core-dep-graph` lane stays green — the fuzz crate is deliberately not a workspace member, and this must not change that.
  - Q13's matrix row **V3.4** can move from `gap` toward `covered` once F17's targets and Q9's lane land on top of this.
- Notes: Deliberately separated from Q9. Q9 is "build the lanes"; this is "make any lane possible at all", and it is a toolchain decision with its own permanence, not a CI detail. Registering it separately is what stops it being rediscovered at the freeze gate — which is precisely how Q13 found it.

### Q40 — Machine-check the three coupled report-format version constants
- Milestone: M0
- Size: S
- Deps: R32 (the bump this guards); Q5 (the bit-match lane the constants live in); D87 §6 (the routing that found it)
- Spec: Format stability (MVP-SPEC.md line 123); Verification (line 167); Milestones M0 (line 153)
- Discovered by: **Q37** (2026-07-28), executing D87 §6's routing. Three constants must move together at the report-format freeze — `antseal_core::verify::report::REPORT_VERSION`, `wasm_bitmatch::TRANSCRIPT_VERSION`, and `EXPECTED_TRANSCRIPT_VERSION` in `scripts/wasm-bitmatch.mjs`. **Exactly one of the two couplings is enforced.** The `.mjs` comparator checks itself against `TRANSCRIPT_VERSION` at runtime and fails the lane on a mismatch — that pair is safe. Nothing whatsoever couples `REPORT_VERSION` to `TRANSCRIPT_VERSION`: not the compiler, not a test, not a lane. `TRANSCRIPT_VERSION`'s own doc comment promises it becomes `1` when Q14 freezes the report byte format, and that promise is enforced by nobody. R32's entry names only `REPORT_VERSION`, so following R32 exactly leaves the transcript declaring version `0` over a frozen v1 report format — the same shape of Q14 trap R32 exists to close, reproduced one file over.
- **[2026-07-28] SUPERSEDED IN PART by R32's implementation.** The premise below — that the two constants are one number — is **false**. R32 established on evidence that `TRANSCRIPT_VERSION` versions the transcript *envelope*, which carries no report field, aggregates all seven vector kinds, is written to `target/`, and is never frozen. Do **not** add the equality assertion: it would pin a coupling that does not exist and would go red the first time either version legitimately moves alone. What survives is the real hazard this task noticed — that a version constant's doc comment promised something no check enforced. The replacement work is (a) the corrected Q14 row above, and (b) asserting the rule R32 recorded: the transcript version moves when a transcript **field** is added, removed, renamed or reordered, never for a change in field *contents*. Retarget or close with **R42**.
- Do: Add a test in `crates/wasm-bitmatch` asserting `wasm_bitmatch::TRANSCRIPT_VERSION == antseal_core::verify::report::REPORT_VERSION`, with a comment stating *why* they are one number rather than two (the transcript serializes under D29's rules, so the transcript's format version and the report's format version freeze together). That single assertion closes the unenforced half; the `.mjs` runtime check already closes the other, so the chain becomes complete. If a future version ever needs the two to diverge, the test is the place that must be deliberately edited — which is the point.
- Accept:
  - The test exists and is green at the current values, and goes red when either constant is changed alone (test-of-the-test: flip one, watch it fail, restore).
  - Q14's coupled-version-constants row cites this test instead of instructing a `grep`.
  - `crates/wasm-bitmatch` still builds for `wasm32-unknown-unknown`; the assertion is a native test, not a `const` assertion in the wasm path.
- Notes: Deliberately a test and not a `const _: () = assert!(...)`: the wasm-bitmatch crate is compiled for wasm32 in the lane, and a const assertion there would couple a build failure to a documentation-shaped invariant. A red test names the problem; a failed const evaluation does not.

### Q41 — Enforce external-fixture provenance digests in CI
- Milestone: M0
- Size: S
- Deps: Q11 (wrote the provenance records and the re-derivation scripts); D31 consequence 6 (the rule this enforces); joins the D31 §6b lane
- Spec: Revision-2 independent cross-check mandate (MVP-SPEC.md line 5); Verification (line 167)
- Discovered by: **Q11** (2026-07-28), which wrote `testdata/acvp/PROVENANCE.md` and `testdata/unicode/PROVENANCE.md` and left the digests in them unread by anything. **This entry was itself missing** — TODO.md carried the one-liner from wave 6 and `tasks/Q.md` never gained the detail entry; written up at execution in wave 7, which is why the finding below appears here rather than in a `Discovered by` line.
- The gap, confirmed on the tree before any work: the four externally-sourced fixtures are `testdata/acvp/ml-dsa-65-{keyGen,sigGen,sigVer}.json` and `testdata/unicode/NormalizationTest-17.0.0-sample.txt`. Their SHA-256s appear in exactly one place each — the prose table of their `PROVENANCE.md` — and `grep` for those digests across the tree returns that one file and nothing else. `FROZEN.sha256` does **not** cover them: it is per-format-version and scoped to `testdata/vectors/v<n>/*.json` by construction. So a fixture whose bytes came from outside this repo could be edited silently, and D31 consequence 6 explicitly calls that out as *"the first committed test data in the repo whose provenance is external and unverifiable from the tree alone"* with *"a missing or stale PROVENANCE.md is a red lane, not a documentation nit."* Nothing made it one. The sharp edge is that these four files are the **T0 anchors** under `docs/testing/cross-check.md` rows 10, 12 and 13: an edit to them changes what "checked against NIST" and "checked against Unicode" mean, while every lane stays green.
- Do: `scripts/crosscheck-provenance.py`, run first in `scripts/cross-check.sh`. **Parse the digests out of PROVENANCE.md itself** rather than duplicating them into a second `EXTERNAL.sha256` manifest — one fact in two places invites the two disagreeing while both look authoritative. Reading the prose makes all three directions red: fixture edited but not prose, prose edited but not fixture, and (green, correctly) both together in a reviewed commit whose diff shows a provenance change explicitly. Offline by construction: upstream is never contacted, because what needs enforcing is that the committed bytes are the bytes the record claims, not that upstream still serves them.
- Accept:
  - Every non-auxiliary file in an external-fixture directory has an enforced digest; a mutated fixture turns the lane red.
  - Discovery is by directory walk (`testdata/*/PROVENANCE.md`), so `testdata/anchors/` is enforced the moment M2's recorded captures give it a record — no edit needed (→ **Q44**).
  - A **roster rule**: any file in such a directory that is not `PROVENANCE.md`, `README.md` or a `*.py` derivation script must carry a claim. Without it the checker would enforce only what someone remembered to register.
  - Self-test with one planted fault per claim class, in a temp copy, never the working tree.
  - The update procedure for a legitimate upstream change is recorded (below).
- **Update procedure** (part of the deliverable): **never in place.** Both provenance records and `docs/testing/cross-check.md` §6 already fix the retention rule — the committed subset *is the evidence that this freeze was clean*, so a newer upstream release is **added** as a second pinned subset, never substituted. Fetch the new upstream and check its digest by hand against the new record's upstream row (network, one-off, outside CI); re-run the directory's filter script to derive the new subset under a **new filename naming its version**; append the SHA-256 and byte-count rows for it; leave every existing row and file untouched. The one case where an existing row may move is a **correction** — the recorded digest never matched the committed bytes — which is a reviewed commit on its own whose message must say *which of the two was wrong*, because "the digest was updated to match" and "the fixture was restored to match" are opposite events that look identical in a diff.
- Notes: The self-test found a hole in the first design and it is worth recording, because it is the generic hazard of discovery-by-marker: **deleting a `PROVENANCE.md` removed its directory from discovery entirely**, un-enforcing every fixture in it while the lane stayed green. Closed with `REQUIRED_DIRS`, the same must-exist device `FROZEN.sha256` uses for deleted vectors — discovery may return a superset, never a subset. Deliberately out of scope: `requirements-crosscheck.txt`'s `cbor2` wheel hashes. They are enforced by `pip --require-hashes` at install time and the wheel is not committed, so there is nothing offline to compare against; a locally-provisioned cache under `~/.cache/antseal/` is a dev-machine artifact, not committed test data.

### Q44 — `testdata/anchors/` must gain a `PROVENANCE.md` when M2's recorded captures land
- Milestone: M2
- Size: XS
- Deps: Q41 (the enforcer this feeds); A24/A25 and Q16 (the captures and the runbook)
- Spec: Anchors (MVP-SPEC.md lines 112-114); Verification (line 167)
- Discovered by: **Q41** (2026-07-28), building the provenance enforcer. `testdata/anchors/` is reserved for M2 and holds only a README today, so it is correctly absent from the enforced set. Its contents when they arrive are **the most externally-sourced data in the repo**: real OTS calendar responses, real FreeTSA/DigiCert tokens, and pinned root-store snapshots — bytes produced by third parties that cannot be re-derived from anything in this tree at all, unlike the ACVP and Unicode subsets which at least have a committed filter script and a reproducible upstream URL.
- Do: When the first capture lands, write `testdata/anchors/PROVENANCE.md` and add `testdata/anchors` to `REQUIRED_DIRS` in `scripts/crosscheck-provenance.py`. Discovery picks the directory up automatically once the record exists; the `REQUIRED_DIRS` entry is what stops the record being deleted later. The record needs the capture timestamp, the endpoint, the digest submitted, and the SHA-256 + byte count of every committed artifact.
- Accept: `scripts/cross-check.sh --check` enforces the anchor fixtures; deleting the record turns the lane red rather than silently retiring them.
- Notes: The `no-origin` rule the enforcer applies is satisfied by an `https://` endpoint, which a recorded TSA or calendar capture has by nature. Q16's runbook is where the capture procedure lives; this task only ensures the bytes it produces are pinned.

### Q43 — Exercise every CI shell step locally, or stop writing logic in CI shell
- Milestone: M0
- Size: S
- Deps: Q1 (the lane set), Q8 (which introduced the defect), Q9/Q11/Q13 (which each added more CI-only shell)
- Spec: Milestones M0 (MVP-SPEC.md line 153); Verification (line 167)
- Discovered by: **the first remote CI run of wave 6** (run 30376120625, 2026-07-28). The `tamper-matrix` lane went red on `tamper-matrix registry target is EMPTY — the harness or the completeness check is broken`. The harness was fine; the **counting command** was malformed: `cargo test … --test tamper_matrix --list` passes `--list` to *cargo*, which rejects it, where it must reach the test binary after `--`. Q8 introduced it when it repurposed Q1's counter (Q1's own two counters at lines 273/314 have the correct form and stayed green). It sat latent through waves 5 and 6 because **the lane had never executed remotely** — the push was 182 commits behind — and `scripts/local-gate.sh` runs four lanes while CI has eighteen contexts, so nothing local touches it either.
  The guard itself worked exactly as designed: it refused to report success from a check that produced no evidence, which is precisely the false-green it exists to prevent. The defect is that a *guard's own command* was never executed.
- Do: Close the class, not the instance. Either (a) extend `scripts/local-gate.sh` (or a new `scripts/ci-local.sh`) to run every CI lane's shell steps, so a malformed CI-only command is caught before it is pushed; or (b) move the logic out of YAML into committed scripts that both CI and the local gate call — the pattern `scripts/vector-freeze.sh`, `scripts/cross-check.sh`, `scripts/fuzz.sh` and `scripts/check-traceability.py` already establish, and which is why none of those lanes could fail this way. (b) is the recommendation: the three lanes that call scripts were green on the first remote run; the two defects this project has had in CI logic were both in inline YAML shell.
- Accept:
  - Every `run:` block in `.github/workflows/ci.yml` either calls a committed script or is exercised by a local lane; a check enumerates them and fails on a new inline block that is neither.
  - Reproduce the Q8 defect as a test-of-the-test: restore the malformed flag order, watch the local lane go red *before* a push, restore.
  - The three `matched=…` counters keep their guards; the point is that the guards are now themselves executed.
- Notes: Also record the general form in `docs/ci-verification.md`: **a lane that has never run on the remote is not evidence, no matter how long it has been committed.** Wave 6 pushed 182 commits at once, so five lanes ran remotely for the first time simultaneously; the two brand-new ones (`cross-check`, `traceability`) passed and the old one failed, which is the opposite of the intuition.
  **DONE 2026-07-28 (M0 wave 7) — option (b).** Ten inline blocks moved into committed scripts: `scripts/ci-lanes.sh` (dep-graph, cross-os, golden-vectors, tamper-matrix, cbor-drift-guard, traceability, ci-shell, secret-guard, audit-deny), `scripts/wasm-tests.sh` (the wasm32 lane, landed with R41) and `scripts/fuzz.sh corpus-report`. **All three workflows, not just `ci.yml`** — this entry's Accept names `ci.yml`, but `advisory-cron.yml` carried a second copy of the `cargo deny` invocation and `fuzz-nightly.yml` a corpus-size loop, so scoping it to one file would have closed the instance again. `scripts/check-ci-shell.py` enumerates all **54** `run:` blocks across the three and requires each to be a committed-script call or one of **9** allowlisted lines, each recording the local lane that exercises it; a stale allowlist entry and a script call with logic wrapped around it are both failures. Wired into `scripts/local-gate.sh` as two new lanes (`ci-shell`, `ci-lanes`) and into CI as **steps of existing jobs**, so the 18-context set is unchanged. Test-of-the-test: `check-ci-shell.py --self-test` is red under three planted faults and green on the control; `ci-lanes.sh --self-test` puts `--list` back before `--` in a copy of the lane script, runs the lane, and requires `registry target is EMPTY` and a non-zero exit — control 25, faulted 0, restored green. The three counters keep their guards and now report 57 (`golden-vectors`), 70 (`cross-os`), 25 (`tamper-matrix`). **The method paid for itself during the task**: the first version of the shared `count_matched` helper appended its own `--`, producing `-- vector_ -- --list` for the filtered lanes — two separators, a filter libtest never saw, and a count of 0 that would have turned `golden-vectors` red on the next push. A local run caught it. One thing tightened rather than relaxed: `secret-guard` excluded all of `.github/` because the guard lived in the workflow; the naive move would have excluded all of `scripts/`, a strictly larger hole, so the exclusion is now the single file carrying the planted literals and `.github/` is scanned again. General form recorded in `docs/ci-verification.md`. Follow-ups: **Q62** (the allowlist's "exercised by a local lane" claim is prose, not a check), **Q63** (`golden-vectors` and `cross-os` run the same suite twice, once to execute and once to count).

### Q62 — The CI-shell allowlist's "exercised by a local lane" claim is prose, not a check
- Milestone: M0
- Size: S
- Deps: Q43 (landed)
- Spec: Milestones M0 (MVP-SPEC.md line 153); Verification (line 167)
- Discovered by: **Q43** (2026-07-28). `scripts/check-ci-shell.py`'s `ALLOWED_INLINE` exempts nine inline `run:` lines, and each exemption is justified by naming the local lane that runs the same tool — `cargo fmt --check` → `scripts/local-gate.sh`'s `fmt`, and so on. **Nothing verifies that claim.** If someone deletes a lane from `local-gate.sh`, or changes CI's flags so the two diverge, the allowlist keeps asserting a relationship that no longer holds — and the whole point of the allowlist is that those entries are safe *because* something local exercises them. The staleness check only catches an entry no workflow uses; it cannot catch an entry whose justification has rotted.
  There is already visible drift the entries record honestly rather than fix: CI runs `cargo clippy --all-targets --locked` and `cargo test --workspace --locked`, while the local gate runs both with `--workspace --all-features`. The local side is stricter, so this is safe today — but it is a difference nobody is watching.
- Do: Make the claim machine-checked. The cheapest sound form: give each allowlist entry a `local_lane` field naming the `run <name>` line in `scripts/local-gate.sh`, and assert that line exists and invokes the same *tool* (`cargo fmt`, `cargo clippy`, `cargo test`, `cargo build`). Report the flag differences rather than requiring equality — they are deliberate, and a check that demanded byte-equality would be routed around within a wave.
- Accept:
  - Every `ALLOWED_INLINE` entry that names a local lane resolves to a line in `scripts/local-gate.sh`.
  - Deleting or renaming that line turns the check red (planted fault).
  - The flag differences between the CI and local forms are printed, so a drift that makes CI *stricter* than the local gate — the dangerous direction — is visible.
- Notes: The `rustup show` / `node --version` / `cargo install <pin>` entries name no local lane and need none; the check must accept a recorded "no local lane, and why" as a first-class value rather than a missing field.

### Q63 — `golden-vectors` and `cross-os` build and run their suite twice per lane
- Milestone: M0 (cheap) / M1
- Size: S
- Deps: Q43 (landed), Q1
- Spec: Milestones M0 (MVP-SPEC.md line 153)
- Discovered by: **Q43** (2026-07-28), while running the migrated lanes locally for the first time. Each filtered lane executes `cargo test … -- <filter>` and then, to count what the filter matched, runs `cargo test … -- <filter> --list` — a **second** cargo invocation over the same targets. On the `cross-os` matrix that is three runners paying it. The counts are small (57 / 70 / 25) so the listing itself is instant, but cargo still resolves and links the test targets again, and the cost is paid on every PR of every lane.
- Do: Take the count from the run that already happened rather than from a second invocation — libtest's own summary line (`test result: ok. N passed`) is already in the output that `scripts/local-gate.sh` parses with `awk` for exactly this purpose. Keep the *guard*, which is the load-bearing part: a filter matching nothing must remain a visible outcome, not a silent green.
- Accept:
  - One cargo invocation per lane; the counter reads the run's own output.
  - The guard still fires on an empty selection, proven by a planted fault (a filter that matches nothing).
  - `scripts/ci-lanes.sh --self-test`'s Q8 reproduction keeps working, or is restated against the new mechanism — it is the reason the counter is written down at all.
- Notes: `tamper-matrix` has the same shape but a weaker case for changing it: its run passes `--nocapture` to print the Q14 gate, so its output is already being read for something else.

## Open decisions (Q)
- Independent cross-check vehicles and permanence — which second implementations per surface (Python `cbor2` for CBOR; Python crypto stack for HKDF/commitments/GGM; whether ml-dsa↔fips204 cross-crate + ACVP KATs counts as "independent" for ML-DSA), and one-shot audit artifact vs permanent CI lane (proposal: both). Blocks Q11, Q14. Must land by M0. — **[2026-07-28]** RESOLVED (D31): one vehicle per surface, graded **T0 external oracle / T1 independent re-implementation / T2 same-ecosystem agreement**. CBOR keeps D12's `cbor2 ==6.1.3` for **decode only** — our own RFC 8949 §4.2.1 encoder is the encoding authority, which retires D7 §D12's length-first ordering caveat instead of documenting it. Crypto/GGM/padding/canonicalization reuse the Python references C16/G15/G3 already landed, each now **required to carry a T0 known-answer anchor** (RFC 5869 App. A, RFC 8032 §7.1, Unicode `NormalizationTest.txt` + a `unidata_version == '17.0.0'` assertion). **ML-DSA-65: NIST ACVP replayed against `ml-dsa =0.1.1` — T0, the strongest tier, and the answer to this entry's own question is that `ml-dsa`↔`fips204` is T2 and is NOT independence** (it is D14's fallback-equivalence check, retained and labelled as such). Permanence: **both**, and the two are not redundant — the dated one-shot report is the evidence *for* the freeze, the permanent unconditional `cross-check` lane is the guard *after* it. Buildable breakdown for Q11/F14 in D31 §9; Q14's verbatim row in §10. Found a gap: the report byte format has no cross-check at all → **Q38**.
- Deterministic verification-report byte format compared by the bit-match harness (exact serialized output contract with R/F). Blocks Q4, Q5. Must land by M0.
- Stable machine-readable error-code contract (how `antseal-core` exposes codes for tamper-distinctness across F/C/G/A/R errors and verdict states). Blocks Q7, Q8, Q18. Must land by M0.
- Devnet E2E venue: GitHub-hosted CI job vs self-hosted scheduled job vs required scripted local gate. Blocks Q15. Must land by M1.
- Long-run fuzz venue: nightly CI vs an OSS-Fuzz application. Blocks the nightly half of Q9 (smoke lane unaffected). Decide by M2.
- License choice (MIT OR Apache-2.0 dual vs other). Blocks Q29, Q10 license allowlist, and P's crates.io placeholders. Spec milestone M4; recommend deciding pre-M0.
- Signing mechanism (minisign vs cosign vs both) and key custody. Blocks Q30, Q31, Q22. Must land by M4.
- Release target set (linux-x86_64 only vs +macOS/+Windows), distribution channel details, and crates.io publish scope. Blocks Q31, Q22. Must land by M4.
- Success-metric measurement method with zero telemetry (facilitated sessions vs self-report vs both). Blocks Q35. Must land by M4.

## Cross-domain expectations
- P: CI skeleton workflow + pinned toolchain/caching that Q1 extends
- P: exact dependency pins (`ant-core =0.5.0` re-verified at M0 start, CBOR encoder, `ml-dsa`/`fips204`/`ed25519-dalek`) feeding Q10/Q14/Q36
- P: crate-name/domain reservations and crates.io naming consumed by Q31
- F: manifest/bundle golden vectors (incl. empty-anchor), CBOR decoder-rejection fixtures, manifest+bundle cargo-fuzz targets (M0), stable codec error codes
- C: frozen Security-assumptions text (Q12), crypto golden vectors + signature reject-vectors, HKDF-info pairwise-distinctness golden test, adversarial confirmation-attack doc-tests (unsalted-unit and unsalted-file-hash variants), WASM probe verdict for Q14
- G: UTF-8 corpus cases, fine-tree range-proof fixtures incl. unbalanced n=6 MSB-first vector and leaf-exact-cover test, perf/memory budget test, pinned Unicode/NFC version record
- S: M1 devnet E2E suite (multi-file `--split`, pay/finalize and mid-upload kill tests, restore-from-backup, `--live`), MockBackend for network-free CI lanes, devnet/Sepolia environment scripts, quote-based cost estimates for Q23/Q33
- A: mock TSA server + recorded OTS/TSA fixtures for the Q16 CI lane, DER/`.ots` fuzz targets for Q17, implemented anchor tamper rows for Q18, M2 smoke execution per the Q16 runbook, pinned-root-store update procedure for Q26
- R: deterministic byte-stable verification-report serialization for Q4/Q5, reproducible wasm-pack build recipe + build hash for Q19/Q31, page deployed at the canonical URL (M3) for Q28/Q32/Q34, playwright + verdict-snapshot test suites for Q19, page footer hash + CLI-cross-check copy conforming to Q20
- U: CLI copy conforming to Q20 (permanence consent, title-visibility and `--no-fine-tree` warnings, vault-export and pending-anchor nags), canonical verifier URL printed by `reveal`, `init` funding instructions matching Q23, release default `--network arbitrum-one` for Q34, `vault export`/`import` used by the Q32 drill
