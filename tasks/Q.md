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

- [x] **Anchor-artifact freeze scope (D84).** Inside the v1 freeze: the
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
  rendered every anchor `absent` (R12 replaced that stub at M2, and this
  row is the historical statement it was always meant to be).
- [x] **Report-version evolution is not blocked by this freeze.** The Q14
  freeze fixes report **v1** (`REPORT_VERSION = 1`, per R32 and D29 §8).
  D29 records that adding fields after the freeze requires a version bump,
  not that no bump may occur. M2's anchor stage populates anchor states that
  report v1 **already carries** — `AnchorState::ALL` is all seven at the
  freeze — so R12 moves recomputed verdicts, not format surface, and
  `REPORT_VERSION` stays 1 (**D94**: a VERDICT EVENT re-emits the frozen
  vector under the full ceremony and bumps nothing). A bump remains
  available for a genuine field addition; line 123's promise is that v1
  reports remain verifiable, not that v1 is the last version.

<!-- FREEZE-BOUNDARY:END -->

**Coupled version constants — the row that makes a bump impossible to
half-land.**

- [x] **`REPORT_VERSION` is `1` and its coupled edits are all in (R32; D29
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

- [x] **The decode layer is never a report field (D86, permanent).** `layer` is
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

- [x] **Zeroization dispositions closed (C21/C22/D88).** `Cargo.toml` shows
  `sha2 = { version = "=0.11.0", default-features = false, features =
  ["zeroize"] }`; `crates/antseal-core/tests/zeroization_residue.rs` green
  on native; `docs/zeroization-audit.md` R1 carries the dated D88
  disposition and its narrowed residue; R2–R5 carry dated accepted
  dispositions. **Known-and-accepted, not open.**

- [x] **Full-reveal cover shape (D75) — closed *contingent on D83.*** D75 is
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

- [x] **Traceability matrix M0 rows complete (Q13).**
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

- [x] **Independent cross-check clean (Q11/F14/D31).** `docs/testing/
  cross-check.md` carries a dated report for this freeze commit with
  **zero discrepancies**, naming per surface the vehicle, its exact version,
  the vector count and the evidence tier (T0 external oracle / T1
  independent re-implementation / T2 same-ecosystem agreement). Every
  surface in D31 §2 rows 1–13 is present at T0 or T1. **Row 14
  (`ml-dsa`↔`fips204`) is T2 and does not count toward this row** — it is
  D14's fallback-equivalence evidence. The `cross-check` CI lane is green
  and unconditional, and `scripts/cross-check.sh` iterates every retained
  format version rather than a hard-coded `v1`.

### Q15 — Implement the devnet E2E execution strategy (venue decided by D52)
- Milestone: M1
- Size: M
- Deps: Q1; S: M1 E2E test suite (S17/S18/S19) + devnet environment scripts (P16)
- Spec: Milestones M1 (line 154); Verification M1 (line 172); D52 (docs/decisions/D52-devnet-e2e-venue.md)
- Do: The venue is **decided — D52 (2026-08-01), which deliberately inverted this task's measure-then-decide framing** (the decision was derivable from recorded facts: branch protection 403s on Free-private so a required context is unenforceable; the hosted runner is the same 2-core class against a 688-package graph vs the 10 GiB cache cap; S18's SIGKILL matrix is flake-prone there; and the "(cached node binaries)" premise of the original task text is **obsolete** — P16's nodes are in-process, there are no node binaries). Implement it: (1) the **required local gate** — `scripts/e2e-devnet.sh`, mandatory before merging storage-touching changes, producing scripted evidence per the Q14 pattern; (2) the **scheduled, non-required GitHub-hosted job** at reduced node count on the fuzz-nightly pattern, landing only if its measured runtime fits the minutes budget (measurement now serves lane-sizing, not the venue choice). Wrap S's suite (multi-file `--split` seal, kill-between-pay-and-finalize → no-double-payment, kill-mid-upload → byte-identical resume + nonce-reuse-guard abort, restore-from-backup, UNANCHORED library verify, `--live` re-fetch) with deterministic setup/teardown and node/Anvil log capture on failure. Record D52's **promote-to-required trigger** (plan upgrade or the Q65 public flip, after ≥20 clean scheduled runs with warm runtime ≤15 min) and the **scheduled-lane triage convention**: a red scheduled run gets a wave-bookkeeping note; **two consecutive reds block storage-wave starts** until diagnosed.
- Accept:
  - `scripts/e2e-devnet.sh` runs S's full M1 suite green and emits the evidence artifact; the scheduled hosted lane exists, is non-required, and its measured runtime is recorded against the minutes budget
  - Failure runs upload node + Anvil logs as artifacts
  - Contributor doc states when the local gate is mandatory (storage-touching changes), the triage convention, and the promote-to-required trigger verbatim from D52
- **[2026-08-02 EXECUTED — the VENUE lands; the SUITE it wraps does not exist yet (S17/S18/S19 are the next wave), so Accept row 1 is PARTIAL by construction and stays open until they land.]**
  - **What landed**: `scripts/e2e-devnet.sh` (the required local gate and the scheduled lane's entry point — one script, two venues, the ci-lanes.sh same-bytes rule); `.github/workflows/devnet-e2e-cron.yml` (`schedule:` + `workflow_dispatch`, job `devnet-e2e-scheduled`, **never a PR context** — the 19-context payload is unchanged, Q56); the `local-gate.sh` wiring; CONTRIBUTING "Devnet E2E gate (D52)" with the storage-touching path list, the triage convention and the promote trigger; the maintainer-facing promote runbook in `docs/ci-verification.md` (deliberately placed immediately after the branch-protection payload — that is the file a promotion actually edits); the runbook pointer in `docs/devnet/local-devnet.md`.
  - **The missing-suite problem, and why it is not a red lane or a silent pass.** The venue lands before its suite, so the script carries a **suite registry** whose `pending` rows are *declarations*, checked in both directions exactly as `check-ci-shell.py` checks `ALLOWED_INLINE`: declared-pending + absent → verdict `PENDING` (exit 0, and the line says `DISCHARGES NO GATE`; the word PASS is never printed); declared-pending + **present** → hard fail (stale declaration — the suite landed and the row was not moved); declared-live + **absent** → hard fail (the renamed/deleted-suite case, i.e. the Q66 class this gate would otherwise embody). `--require-suites` is the latch that turns any future PENDING into a failure once every row is live. All five rules plus the redaction filter are covered by `--self-test`, which needs no devnet, runs in seconds, and is therefore wired into **every** `local-gate.sh` run — the gate itself stays opt-in (`ANTSEAL_GATE_E2E=1`) per D52 option C.
  - **What the legs run today, and what they will run once S17-S19 land.** The registry is not vacuous now: `S6-S8 | antseal-net | ant-backend | devnet_backend` is **live**, so a real run boots the devnet and executes the real-backend adapter suite against it (the runbook already anticipated this: "D52's scheduled lane and the S17 harness drive it"). Pending rows, which are the contract those tasks land against: `S17 → crates/antseal-cli/tests/e2e_devnet.rs` (multi-file `--split` seal, restore, UNANCHORED library verify, `--live` re-fetch), `S18 → e2e_kill_resume.rs` (kill between pay and finalize with Anvil tx counting, kill mid-upload → byte-identical resume, `(k_u, nonce)`-reuse abort), `S19 → e2e_restore.rs` (clean-tree restore from the vault export alone). Each is `cargo test -p <pkg> --features ant-backend --test <target>` with `ANTSEAL_DEVNET_ENV` pointed at the booted export — the same double gate S5/S6 already use. A task that names its test file differently **moves its registry row in the same commit**; the script fails loudly either way rather than quietly running less.
  - **Log capture and artifact safety.** Node + Anvil logs (Anvil is the launcher's child, so its output is in `launcher.log`) and the manifest are captured to `target/e2e-devnet/<utc>-<sha>/` on **both** paths — on failure as diagnosis, on success as the runtime measurement D52's conditional-landing rule is waiting for — and the workflow uploads that directory with `if: always()`. Capture runs through a **key-name-scoped redaction filter**, not a hex-shaped one: the devnet's funded key is a public Anvil constant, but project rule 6 binds the pattern and an artifact leaves the machine, while a blanket 64-hex filter would destroy the blob digests that make a failure log worth having. `.devnet/env` is never captured in any form. Self-tested in both directions (key redacted, contract address preserved).
  - **Deviations, all deliberate and recorded here.** (1) **Ordering**: D52 §Decision 4 already inverted this entry's "measure on a hosted runner **and** decide" — the venue was decided from recorded facts and the scheduled job's first runs are the measurement. Honored as written; no measurement is claimed. (2) **Cadence**: D52's E3 arithmetic assumed a *warm* daily run, but its own cache argument forbids this lane from taking `Swatinem/rust-cache` (the devnet target dir would evict the 19 required lanes inside the 10 GiB per-repo cap), so every run is a cold build and the landed cadence is **weekly**, not daily — the conservative direction, and a one-line change once measured. (3) **Node count**: default 14 locally (P16 parity), `5` on the hosted runner via the dispatch input. (4) **anvil provisioning** on the runner is `foundry-rs/foundry-toolchain@v1` with `version: stable` — a third-party action edge on the same footing as `Swatinem/rust-cache@v2`; a literal version pin was not invented, and instead the actual `anvil --version` is printed into the evidence line in both venues, which is the mitigation D52 residual risk 5 asks for. (5) Accept row 1's "runs S's full M1 suite green" is **not** claimed: no S17-S19 suite exists. Row 2 (log artifacts) and row 3 (contributor doc) are complete.
  - **Not executed in this lane**: a full devnet boot + suite run (the release devnet build is not warm in this worktree and the 2-core host was shared with a sibling lane). `--plan`, `--list-suites` and `--self-test` were executed; the boot path is P16's, proven 2026-08-01 (runbook, Boot evidence). First full-run evidence line belongs to whoever runs the gate next — that is what `target/e2e-devnet/<run>/evidence.txt` exists to carry.
  - Discovered: **Q71** (below) — the gate cannot be *enforced*, only recorded, and the honest tripwire for a skipped gate is a wave-record check rather than a promise.

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

### Q42 — Tighten the Unicode conformance anchor when CPython ships Unicode 17.0.0
- Milestone: M1 — a tripwire, not scheduled work
- Size: S
- Deps: Q11 (which built the anchor in place of D31's assertion), D31 §3/§11 (the assertion this restores), D25 (the pinned table), Q41 (the provenance enforcement it rides on)
- Spec: Canonicalization — the exact Unicode data version is frozen per seal (MVP-SPEC.md line 83); pinned Unicode/NFC version at M0 (line 153); the UTF-8 corpus (line 170)
- Discovered by: **Q11** (2026-07-28), which found D31's assertion unsatisfiable and built something stronger instead. **This entry was itself missing** — TODO.md carried the one-liner and `tasks/Q.md` never gained the detail entry; written up in wave 7.
- The situation, verified. D31 asked for `unicodedata.unidata_version == '17.0.0'` (`docs/decisions/D31-cross-check-vehicles.md:96`, restated at `:421-422`), and §11 item 3 (`:469-472`) calls a mismatch *"a format-relevant finding for G, not a CI detail"*. **No released CPython embeds Unicode 17.0.0.** The interpreter here is 3.11.2 with `unidata_version` **14.0.0**; CI pins Python 3.12 (`.github/workflows/ci.yml:365-367`), which is Unicode 15.0.0. The assertion would make the lane permanently red. Q11 built the real anchor instead: `normalization_test_anchor()` (`testdata/utf8-corpus/gen_corpus.py:380-439`) replays UAX #15's NFC leg against Unicode's own conformance data, asserting per line `c2 == NFC(c1) == NFC(c2) == NFC(c3)` and `c4 == NFC(c4) == NFC(c5)`, skipping any line containing a scalar the *running* interpreter reports as `Cn` (`:420-422`), with `NORMALIZATION_TEST_MIN_LINES = 1200` (`:105`, enforced `:455-463`) so the anchor cannot rot into a no-op. Soundness rests on the Unicode Normalization Stability Policy (`gen_corpus.py:35-42`, `testdata/unicode/PROVENANCE.md:80-86`).
- **Correction to a number this entry will be read beside.** "1 537 lines of Unicode's own `NormalizationTest.txt`" is a **runtime** count, not a file size, and it is environment-dependent. The committed sample `testdata/unicode/NormalizationTest-17.0.0-sample.txt` is 1 630 lines, of which **1 607 are data**; 1 537 = 1 607 − 70 skipped as unassigned **in Unicode 14.0.0**. On CI's Python 3.12 the skip count is smaller and the executed count larger. `docs/testing/cross-check.md` prints 1 537 in three places (`:57`, `:120`, `:371`) and does record the dependence at `:376-385`, but the figure still reads as a constant. Any tightening must say which interpreter produced it.
- What is missing today, precisely: **nothing fails or warns when the running Unicode version is not 17.0.0.** The only version-driven failure is the `NFC_SAFE_FLOOR = (6, 0)` guard (`gen_corpus.py:89`, `:481-487`); otherwise the running version is merely recorded in the verdict string (`:466`, `:512`, `:521`). And `requirements-crosscheck.txt` pins no Python and no Unicode version — the Python pin lives only in `ci.yml:367`, the data pin only in `testdata/unicode/PROVENANCE.md` and in Rust.
- Do: this is the tripwire's content, not work to schedule. When a released CPython embeds Unicode 17.0.0, add D31's assertion as a **conditional tightening**, not a flip. Assert `unicodedata.unidata_version == '17.0.0'` on interpreters at or beyond the first release that ships it, and on those interpreters require the executed count to reach the full 1 607 with zero skips — every scalar the sample names is assigned by then, so a residual skip would mean the sample or the filter is wrong. Bump `ci.yml`'s `python-version` in the same commit: a tightening that fires only on interpreters CI never runs is not a tightening. Nothing in `testdata/unicode/` moves — the committed sample is already 17.0.0 data, so `scripts/crosscheck-provenance.py` and the pinned digests are untouched.
- Accept:
  - The assertion is present and **fires** — proved by running the lane on an interpreter that has the version, and by a planted fault reporting the wrong one.
  - The pre-17.0.0 path keeps working with its stated reason until the last supported interpreter catches up; the `NFC_SAFE_FLOOR` guard and the 1 200-line floor both survive.
  - Every place that prints an executed-line count names the interpreter that produced it, so the number stops reading as a property of the file.
  - `docs/testing/cross-check.md` §4b's "not satisfiable" record is amended rather than deleted: the reasoning was correct when written, and it is the reason this tripwire exists.
- Notes: The **code-side** pin is already machine-checked and is not what this touches — `pinned_crate_ships_the_recorded_unicode_data_version` (`crates/antseal-core/src/canon/unicode.rs:210-216`) asserts `unicode_normalization::UNICODE_VERSION == (17, 0, 0)`, `UnicodeVersion::CURRENT.as_str() == "unicode-17.0.0"` and `REGISTERED == &["unicode-17.0.0"]`, and D25 names it the standing tripwire for pin motion. What Q42 restores is the *cross-check's* independence claim: that the second implementation's NFC table shares the pinned table's lineage, which today is argued from the stability policy rather than asserted. Minor and worth not tripping over: MVP-SPEC.md line 83's illustrative string is `unicode-16.0.0` while the pin is `unicode-17.0.0` — it is an example in the spec's prose, not a requirement, and it must not be "corrected" into one.

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

### Q49 — Make the freeze-boundary lint tolerate a ticked checkbox
- Milestone: M0 (it blocks Q14 absolutely)
- Size: S
- Deps: Q37 (which created the normative-rows block), Q13 (the lint), D84 (the source of truth the copies are cut from)
- Spec: Format stability (MVP-SPEC.md line 123); Milestones M0 (line 153)
- Discovered by: **the Q14 gate audit** (2026-07-28, wave 7), and **proven on a scratch tree rather than argued**. Q14's `Accept` requires *both* `scripts/check-traceability.py --freeze-boundary` green **and** every normative row ticked. Rows N1 and N2 live *inside* the `<!-- FREEZE-BOUNDARY:BEGIN … END -->` markers in `tasks/Q.md`, and that block is byte-compared against `docs/decisions/D84-…md` §7, which contains the literal `- [ ]`. Changing `- [ ]` to `- [x]` is a byte change, so the lint went red on the tick. **There was no ordering of the two Accept criteria that satisfied both: the gate could not be executed as written.**
- Do: Normalise the checkbox marker before comparing, on **both** sides, in `extract_boundary` and the source-block extractor. The rule *text* stays byte-compared — that is the property the lint exists to protect — while the tick, which is per-copy **gate state** and legitimately differs between the decision record (which never ticks) and the checklist (which must), stops counting as drift. The alternative considered and rejected: move the tick outside the markers into a sibling table keyed on row id, which costs the rows their checkbox affordance and makes a reader cross-reference.
- Accept:
  - Ticking every normative row leaves `--freeze-boundary` green.
  - The tolerance is **narrow, and proven narrow**: `--self-test` carries a green case (a ticked row passes) *and* red cases for a changed word and for a **deleted** marker. A normalisation that widened to "compare nothing" would otherwise leave this lint green forever.
  - The reported first-difference is computed on the same normalised forms, so a message can never point at a tick the comparison deliberately ignored.
- Notes: **[2026-07-28] DONE, wave 7.** ~8 lines of change plus four self-test cases; the self-test harness gained an `expect` field of `"red"` or `"green"` per case, and a guard that a mutation which matched nothing fails its own case rather than passing vacuously. Landed before any lane merged, because every other gate row was unreachable behind it.
  — **[2026-07-28] Two amendments from a post-hoc read of the landed code, neither changing the verdict.** (1) The `Do` above says the substitution goes *"in `extract_boundary` and the source-block extractor"*; it landed in `check_freeze_boundary` instead, via `blank_gate_state()` (`scripts/check-traceability.py:85-87`, applied at `:165-167`, marker regex at `:82`). That is the better placement and the reason is worth keeping: the extractors keep returning the real text, so the reported first difference is computed on the same blanked forms and can never point at a tick the comparison deliberately ignored — which is Accept bullet 3, satisfied by *where* the fix went. (2) One residue: the per-check success line at `:183-187` still compares **un-blanked** (`all(block == source ...)`), so now that Q14 has ticked the rows, `[freeze-boundary] ok — 2 copies byte-identical to … (N bytes)` no longer prints. Verified at HEAD: `tasks/Q.md`'s copy differs from D84 §7 raw and matches after blanking, the check exits 0, and the driver's `check-traceability: ok (freeze-boundary)` line still appears — only the byte-count detail is silently gone. Cosmetic, and the one place the normalisation was not applied consistently.

### Q50 — A freeze digest for the wire registry, and the caps it silently un-pins
- Milestone: M0
- Size: S
- Deps: Q6 (the manifest format and its directive parser), Q14 (the gate that sets `status frozen`), F4 (the registry itself), D10 (the caps), D84 §7 (which puts them inside the freeze)
- Spec: Format stability — every released version verifiable forever (MVP-SPEC.md line 123); Definitions & encoding (line 73); Milestones M0 (line 153)
- Discovered by: **the Q14 freeze-gate planning pass** (`docs/format/Q14-freeze-gate-plan.md` §B2, 2026-07-28). `docs/format/registry-v1.md` and `registry-v1.json` sat outside **every** freeze mechanism in the project: `scripts/vector-freeze.sh` covers `testdata/vectors/v<n>/*.json` only, and no `FROZEN.sha256` anywhere had an entry for either file. The consequence was sharpest for the 19 D10 parser caps: `code_caps_match_the_registry` asserts in both directions that `codec::caps`'s constants equal the mirror's values, which is a **consistency** check, not a **pin** — a coordinated edit of both files in one commit passes the whole suite forever. The same shape covered every other registry fact (map keys, field names, reserved bands, scalar lengths, tuple arities, enum values, version dispatch): all "code and JSON must agree", none "this value is X". Post-freeze that is a silent format change, and the registry *is* format v1.
- Do: Add both files to a freeze manifest with the same append-only / refuse-on-change semantics `vector-freeze.sh` implements. Reuse the existing directive parser rather than writing a second one — a second parser is a second answer to "what does `#! status frozen` mean". Provide the two independent layers Q6 has: coreutils `sha256sum -c` (sharing no code with the crate whose format it pins) and an authoritative Rust checker carrying the tests-of-the-test. Make the must-freeze set **discovered**, not listed, so a future `registry-v<n+1>` cannot land unfrozen. Sequence it **after** the registry content is final — a digest over a file still being edited is churn.
- Accept:
  - A mutated registry document, a mutated mirror, a deleted document and an unfrozen registry version each turn the lane red, proved on a scratch copy that never touches the committed tree.
  - A working document in the same directory cannot be frozen: editing a plan must not read as a format event, or the freeze becomes noise.
  - `--update` refuses to modify or drop an entry while `#! status frozen`; an addition stays legal.
  - The lane runs in CI and in `scripts/local-gate.sh`, self-test first.
- Notes: The digest does not say the values are *right* — the cross-checks do that. It says they are the ones that were signed off, and that changing them is a visible act with a diff in a committed file.
- **[2026-07-28] LANDED.** `docs/format/FROZEN.sha256` (`#! status frozen`, gate Q14) pins both files; `scripts/format-freeze.sh` (check / `--self-test` / `--update`) and `crates/antseal-core/tests/format_freeze.rs` (12 tests, 10 of them tests-of-the-test) are the two layers; new CI lane `format-freeze`. The parser is genuinely **shared**: `vector_freeze.rs`'s manifest model and directive parser moved to `crates/antseal-core/tests/freeze_manifest/mod.rs`, included by both consumers through `#[path]`, with what differs carried as an `EntryPolicy` (name prefix, allowed suffixes, excluded auxiliaries) so neither manifest can reach outside its domain. Q6's nineteen tests pass unchanged apart from one assertion needle. Surfaced from this task: **F42** (the registry's *prose* restatements of machine-checkable facts — §7.15's band list, §9's headroom table — are unchecked and now frozen).
### Q51 — A per-milestone status gate for the traceability matrix
- Milestone: M0 (before Q14 — it is the guard against the failure that already happened once)
- Size: XS
- Deps: Q13 (the matrix and the checker); Q37/Q49 (the same script's other check and its self-test structure); Q14 (the gate that reads the matrix)
- Spec: Verification (MVP-SPEC.md lines 165–175, every bullet); Milestones M0 (line 153)
- Discovered by: **the Q14 freeze-gate audit** (`docs/format/Q14-freeze-gate-plan.md` finding **A4(b)** and §1.4, 2026-07-28). `scripts/check-traceability.py --matrix` parsed the table into `dict(zip(header, cells))` — **including the `status` column** — and then never read it. It resolved references and nothing else, so a row could sit at `gap` through a milestone review with the lint green. That is not hypothetical: **V3.4 read `gap` for a full wave after F17, Q39 and Q9 landed**, and Q14's normative row N7 reproduced the stale claim and added *"This row blocks the freeze tag."* A gate executor following the row literally would have concluded the freeze was blocked by work that was already done.
- **[2026-07-28] LANDED (M0 wave 7).** Three properties, one of which was not in the brief and is the one that made the whole thing land clean:
  - **The gate is cumulative, not per-milestone.** Every row at or before the milestone under review must read `covered`. A gate that looked only at the current milestone would let an earlier one regress to `gap` the moment its own review passed.
  - **The milestone is a constant (`CURRENT_MILESTONE`), not a required flag.** A gate that runs only when someone remembers to pass `--milestone` is the same unenforced prose it replaces — and would have rotted exactly the way the status column did. The constant is the line a milestone review bumps; `--milestone` overrides it for the one-off question (`--milestone M1` answers *"would M1 pass today?"* — today: no, 6 rows, correctly, because M1's crates are stubs). Wiring cost: **zero**. The `traceability` CI lane already runs the script with no arguments, so the gate runs on every PR without a workflow edit and without a nineteenth required context.
  - **The status vocabulary is closed.** `covered` / `gap` / `deferred` and nothing else, at *every* milestone. A typo'd status at a not-yet-gated milestone would otherwise stay invisible until that milestone's review — the same class of latency as the original defect.
  - Escape hatch as specified: `ACCEPTED_NON_COVERED`, `id -> (status, reason)`, empty today. It is guarded in **both** directions — an entry whose row is now `covered`, whose status has moved, or whose row no longer exists is itself a failure, so it cannot decay into a permanent mute.
- Do: Read the status column; fail naming the offending rows, the file and the line; wire it so the M0 gate calls it; self-test it like the existing cases.
- Accept:
  - `--matrix` prints its gate verdict alongside the reference count: *"status gate: all 16 row(s) at or before M0 read 'covered'"*. A run where the gate matched no rows fails rather than passing — a vacuous gate is the defect being fixed.
  - Three new `--self-test` cases, in the existing `(check, file, mutation, expect)` tuple shape:
    - **red** — flip V3.4 back to `**gap**`, in the `**bold**` spelling the file actually used, so the marker stripping is exercised on the way through. This is the original regression, reproduced.
    - **green** — flip an M1 row to `gap`. Without this the rule could quietly widen to *"every row must be covered"*, which would make the check unrunnable until M4 — i.e. switched off.
    - **red** — a status outside the vocabulary (`defered`).
  - `python3 scripts/check-traceability.py --self-test` green: 8 cases, 6 red and 2 green.
- Notes: Also corrected the matrix's **Findings** section, which still asserted *"One M0 bullet has no test: V3.4 … Q14's M0 rows cannot be complete until F17, Q39 and Q9 land"* — stale in the same way and for a full wave longer, because the wave-6 correction fixed the row and not the paragraph. Gate-plan §5 error #6. The second-order finding is the one worth keeping and is recorded in its place: **a hand-maintained matrix goes stale in the direction of pessimism, and a stale row claiming a milestone is blocked costs more than a missing row.**
### Q52 — Freeze the stable error-code universe with an additions-only snapshot
- Milestone: M0 (before Q14 — it is the mechanism D30's freeze does not have)
- Size: S
- Deps: Q7 (the contract and the distinctness layers this sits beside); Q8 (the completeness registry); D30 (the rule being enforced); Q14 (the freeze this unblocks)
- Spec: Verification — "every mutation fails with a **distinct** error" (MVP-SPEC.md line 168); Format stability (line 123); Milestones M0 (line 153)
- Discovered by: **the Q14 freeze-gate audit** (`docs/format/Q14-freeze-gate-plan.md` §2.3, finding **B1**, 2026-07-28). D30's append-only rule is what third-party verifiers depend on — they compare against the literal code string — and it was enforced by **review discipline alone**. The contract's own §4 names three enforcement layers (per-domain distinctness meta-tests, the Q7 registry sweep, Q8 completeness) and **not one of them can detect a rename**, because a renamed code is still pairwise distinct from every other code and still correctly prefixed kebab-case. Measured independently at wave 7 rather than taken from the audit: **53 of 191 codes (28 %) could be renamed with a fully green suite** — 38 `manifest-`, 9 `content-`, 4 `crypto-`, 2 `cbor-`. The codes that were safe were safe *incidentally*, because some committed vector, tamper row or hardcoded assertion happened to spell them out; `bundle-`, `fine-root-` and R's unprefixed set were fully covered that way and `manifest-` almost not at all.
- **[2026-07-28] LANDED (M0 wave 7).** `testdata/error-codes/v1/CODES.txt` — 191 codes, sorted — plus `crates/antseal-core/src/error_universe.rs`, compared on every `cargo test -p antseal-core --lib` run. No new CI context: it rides the existing `test` lane and needs no feature flags. Three corrections to the audit's figures fell out of doing it and are recorded in `docs/testing/error-code-contract.md` §7:
  - **The universe is 191, not 190.** The audit's table adds per-enumerator counts under prefix headings, but a prefix is not a partition of the enumerators: `fine-root-` has **9** codes, not the 8 `content::fine_tree::error` yields, because `fine-root-rebuild-mismatch` is minted by **R** at `crates/antseal-core/src/verify/error.rs:767`. That is also a second standing exception to contract §2's *"a domain never mints a code under another domain's prefix"*, beyond the one §2 already records.
  - **The renameable set is 53, not 54** (`manifest-` 38, not 39).
  - **There were only seven enumerators, not eight.** The `cbor-` family's list was an array *inside* `codes_are_pairwise_distinct_kebab_case`; it is now `codec::decode::all_code_exemplars`, consumed by that test so the family has one list rather than two. The audit also says three enumerators are already `pub`; **two** are (`crypto::error`, `content::fine_tree::error`), behind two different features.
- Do:
  - Collect the universe from the eight per-domain enumerators, de-duplicated, sorted; commit it as one plain-text artifact and compare it on every run.
  - **Additions-only semantics**, mirroring `scripts/vector-freeze.sh`'s: adding a code passes (D30 §3 — *"routine and unrestricted"*), removing or renaming one fails **naming the code under its frozen name**, because that is the name a third-party verifier holds.
  - Give the refresh path (`ANTSEAL_BLESS_ERROR_CODES=1`) union semantics so blessing can never drop a code; removing one stays a hand edit with a reviewable diff.
  - Keep it a lib unit test rather than an integration test: five of the eight enumerators are `#[cfg(test)] pub(crate)` and widening them to `pub` would put a test-support surface into the crate's public API to buy nothing.
- Accept:
  - The snapshot exists, is compared in CI, and the check is non-vacuous (an empty or missing snapshot fails loudly rather than passing).
  - **Renaming any code turns it red naming the code.** Demonstrated, not assumed: `manifest-empty-files` → `manifest-empty-file-list` (a *realistic* lowercase kebab-case rename) run against the whole workspace suite — **exactly one failure**, `error_code_universe_has_not_lost_or_renamed_a_code`, reporting `- manifest-empty-files`. The other 705 tests stayed green, which is the same run confirming the 53/191 measurement on a live sample.
  - **Adding a code passes.** Demonstrated by dropping a line from the snapshot and re-running: green, with the new code named and the bless command printed.
  - Test-of-the-test: the comparison is a pure function with planted rename / removal / addition / unchanged cases, plus a proof that the bless path writes the union, plus a proof that the universe is *exactly* the union of the eight enumerators.
- Notes: It pins **existence, not coverage** — a code can be in the snapshot and reachable by no tamper row; that is `Q55`'s. One bounded residue, recorded rather than hidden: a code added *and then renamed* before anyone re-blesses is invisible, because it was never committed. Blessing is therefore part of landing a new code, exactly as regenerating a vector is.
  A methodological note worth keeping, because it nearly produced a wrong number: the first planted rename used an **uppercase** suffix and went red in `manifest::error::tests::codes_are_pairwise_distinct_and_prefixed` — the kebab-case shape check, not a rename detector. A rename-detectability measurement that plants unrealistic names measures the shape guard instead of the thing it is asking about.
### Q53 — Assert the exact-pin class, and convert the gate's remaining `grep` rows
- Milestone: M0 (before Q14 — item 1 of Q14's own `Do` list is asserted by nothing)
- Size: S
- Deps: P7 (`docs/dependency-policy.md`, the class definition this derives from); D7/P10 (the encoder pin); D29/R1 (the serde pins); R32 (the negative clause); D86 (the layer rule); D13/D14 (the probe verdict)
- Spec: Definitions — the pinned CBOR encoder (MVP-SPEC.md line 73); Format stability (line 123); Verification (line 167)
- Discovered by: **the Q14 freeze-gate audit** (`docs/format/Q14-freeze-gate-plan.md` §1.4 and finding **B3**, 2026-07-28). Six of the gate's 28 rows resolved to a `grep` or a human reading a document. The sharpest was **D2**: `minicbor = "=2.3.0"` is item 1 of Q14's `Do`, and **no test asserted it** — `tests/cbor_pin_eval.rs` names the version only in a doc comment and all 13 of its assertions are behavioural, so they would pass on any conforming minicbor. The same hole covered every other member of the exact-pin class, `serde`/`serde_json` included — and a serializer output change there is a silent break of D29's frozen report vectors. Meanwhile `tests/feature_pins.rs` already scraped `Cargo.toml` and asserted pin lines, for exactly two dependencies: `sha2` and `hmac`.
- **[2026-07-28] LANDED (M0 wave 7).** Four conversions, each placed next to its subject rather than gathered into one file — an assertion about a constant belongs beside the constant:
  - `crates/antseal-core/tests/feature_pins.rs` — the exact-pin class, **derived from `docs/dependency-policy.md` §1's table, not restated**. The policy defines the class normatively (*"Every format-, crypto-, or network-consensus-affecting dependency MUST be pinned with an exact `=x.y.z`"*), so a membership list copied into a test would be a second thing to keep in step — the failure this file exists to catch, one level up. The parser finds **17 members**: `ant-core`, `chacha20poly1305`, `ed25519-dalek`, `fips204`, `hkdf`, `hmac`, `minicbor`, `ml-dsa`, `opentimestamps`, `rand_core`, `self_encryption`, `serde`, `serde_json`, `sha2`, `subtle`, `unicode-normalization`, `zeroize` — **15 landed and checked**, 2 (`opentimestamps`, `self_encryption`) skipped by §1's own rule that *"the pin rule binds from the moment it lands"*. That is five more than any hand-written list would have carried.
  - Same file, the **reverse** direction: nothing may be exact-pinned *without* a policy row. An exact pin is a promise somebody re-defends at every bump (§4's checklist); a pin with no row is a promise nobody owns. One allowlisted exception, the internal `antseal-core` path dep, whose `=0.0.0` exists only so the requirement is never cargo's implicit `*`.
  - Same file, row **D13**: the ML-DSA wasm32 probe verdict. Asserting a marker string in `docs/research/C11-signature-probe.md` would pin prose; the *fact* is already machine-asserted by `wasm32-core-tests` executing this crate's `--lib` tests on wasm32. What nothing checked is that the **chain** holds, so the test asserts its three links — the record exists, `crypto::sig_mldsa` still carries unit tests, and a CI lane still runs `cargo test -p antseal-core --lib --target wasm32-unknown-unknown` — and names whichever one broke.
  - `crates/antseal-core/tests/report_vectors.rs`, row **N4** (D86): the zero-`layer` count, in three places rather than the row's one. The committed document as a whole (the literal grep the row names), each of the 21 byte-pinned `report_json` strings, and the **regenerated** reports — the last being the only one of the three that is about the live `VerificationReport` type rather than about frozen bytes.
  - `crates/wasm-bitmatch/tests/bitmatch.rs`, row **N3 site 3**: `TRANSCRIPT_VERSION == 0`, R32's deliberate NEGATIVE clause. Asserted at **both** sites — the Rust constant by reference, and `scripts/wasm-bitmatch.mjs`'s literal by scrape. Asserting only their *agreement* would not do: the runner already compares the two at lane runtime, so bumping **both** passed the lane and broke the negative clause silently. That was the actual hole.
- Do: Extend the declaration layer from two lines to the whole class; derive membership from the policy; convert the three cheap `grep` rows; keep every failure message naming the consequence and the fix, not just the mismatch.
- Accept:
  - `cargo test -p antseal-core --test feature_pins` covers every landed class member, and the parse is non-vacuous (floors on both the parsed class and the parsed manifest, each failing with "the section was renamed" rather than passing over nothing). A diagnostic `--ignored` test prints what both parsers see, for when a pin test is red and the question is which side is wrong.
  - **Every mechanism observed failing**, on planted faults, with the message it must produce:
    - policy says `=2.4.0` while the manifest says `=2.3.0` → red, naming **both** versions;
    - `thiserror` exact-pinned with no policy row → red, naming the crate and the two legal fixes;
    - `scripts/wasm-bitmatch.mjs`'s literal moved to 1 → red;
    - `wasm_bitmatch::TRANSCRIPT_VERSION` moved to 1 → red;
    - a `layer` key injected into a committed report → red.
  - Committed planted-fault self-tests for the parsers and the rule, on synthetic input: the two-name row (`serde` + `serde_json`), the assignment row (`sha2 = "=0.11.0"`), a row whose prose carries backticked types, a manifest parser that stops at the end of `[workspace.dependencies]`, a floating requirement, and a version disagreement.
  - No new CI context: all four ride existing lanes (`test`, `cross-os` for the `vector_`-prefixed one).
- Notes: The policy parser reads prose, and that is a deliberate trade. If §1 is reworded past what it can read, the floor assertion goes **red** rather than the check silently succeeding over an empty class — and the message says to fix the parser with the document and explicitly not to paste the list into the test. Deviation from the audit's *"one test file, ~40 lines"*: `TRANSCRIPT_VERSION` lives in another crate that `antseal-core` does not (and must not) depend on, so asserting the real constant rather than a scrape of its source requires the test to live in `wasm-bitmatch`.
### Q54 — Every registered vector kind needs a named cross-check vehicle, or a recorded "none possible"
- Milestone: M0
- Size: S
- Deps: Q11/D31 §2 (the vehicle register), F31 (which this extends), Q6's `#! kind` directives (the registry it should key on)
- Spec: Revision-2 independent cross-check mandate (MVP-SPEC.md line 5); Verification — golden vectors (line 167)
- Discovered by: **the Q14 freeze-gate audit** (`docs/format/Q14-freeze-gate-plan.md` finding **C1**, `:489-525`, 2026-07-28), which reserved the ID; written up in wave 7 after the tag.
- The structural defect. Q14's normative row N8 reads *"Every surface in **D31 §2 rows 1–13** is present at T0 or T1"*, and D31 §2's register was written **before G21 landed the `content-model` kind**. The row therefore quantifies over a fixed list of *surfaces* rather than over the live set of *vector kinds*, so a kind added after D31 satisfies it vacuously. That is the "coupled edit enforced by nothing" shape, one level up from where F23/F24/R7 found it in the error codes. F31 is adjacent and narrower — its scope is "commits format CBOR"; this one's is "has any vehicle at all".
- **Correction to the plan's scope: two kinds have no vehicle, not one.** Executed at HEAD, `./scripts/cross-check.sh --check` covers nine of the eleven registered kinds — `hkdf-labels`, `commitments`, `unit-aead`, `manifest-aead` and `signatures` through the per-directory `gen_vectors.py --check` generators, `fine-tree` likewise, `manifest` and `bundle` through `crosscheck_cbor.py`, `report` through `scripts/crosscheck-report.py`. **`content-model` and `sig-reject` have none**: both print the checker's neutral "no diagnostic sidecar (out of scope)" line, neither has a generator, and `grep -rl sig-reject scripts/ testdata/ --include='*.py' --include='*.sh'` returns nothing. That is three of the twelve committed files. Related overclaim to fix in the same pass: `docs/testing/cross-check.md:367` gives Ed25519 a scope of *"21 reject cases + keygen"*, but `testdata/vectors/v1/crypto/reference.py` contains zero occurrences of `reject` and never opens `sig-reject/*.json` — that column is describing the Rust side, i.e. the system under test, not a vehicle.
- **And the plan's one *blocking* sub-requirement is still owed.** §3 C1 (`:517-520`) requires the new dated report section to carry a `content-model` row reading *"no vehicle — composition is ours; primitives covered at rows 5/9/10"*, or *"the report is incomplete by its own rule"*. The freeze commit `a41eac7` added the dated report to `docs/testing/cross-check.md`, and `content-model` appears in that file exactly once — at `:342`, as a note that G21 added the kind, not as a register row. `sig-reject` appears nowhere. So a requirement classified as blocking was not met, and it is now owed *after* the tag rather than before it. That is the first thing this task should do, and it is prose, not code.
- Do: key the claim on the kind registry instead of on a prose list. `vector_freeze_records_every_registered_kind` (`crates/antseal-core/tests/vector_freeze.rs:368-380`) already asserts `KNOWN_KINDS` ≡ the `#! kind <name> <task>` directives in `testdata/vectors/v1/FROZEN.sha256:54-64`, so every kind is already paired with an owning task; add a **vehicle** column and assert that each kind resolves to a named vehicle or to a recorded "none possible" carrying its reason. Land it with F31's CBOR flag rather than beside it — two columns on one directive line and one parser, not two mechanisms over the same registry.
- Accept:
  - Adding a vector kind with neither a vehicle nor a recorded reason turns a lane red, proved on a synthetic kind.
  - `content-model` and `sig-reject` each end in exactly one recorded state. For `content-model` the honest tier is already known: it pins *composition* — unit ordering, LE64 `unit_id`, D23 mirror-last — which is ours, has no possible external oracle, and whose primitives are covered at register rows 5/9/10. `sig-reject`'s state must be decided rather than inherited from that argument.
  - `docs/testing/cross-check.md`'s register carries the missing rows, so the report is complete by the rule it states about itself.
  - N8's wording moves from "rows 1–13" to "every registered kind" — the numbered-list form is the defect, and leaving it while fixing its inputs reproduces this in one wave.
- Notes: Cite the table, not the number. "13 independence rows" is the *superseding* per-surface table (`cross-check.md:360-374`); §2's register has 16 numbered rows plus one unnumbered provenance row, and `:66-67` records that row 14 is T2 and does not count. Two counts that look like the same count are how N8 got its fixed list in the first place.
### Q55 — Reverse coverage for the `crypto-` and `content-`/`fine-root-` families
- Milestone: M0
- Size: S
- Deps: F23/F24/R7 (the three existing sweeps), **F37** (which merges them — land as one mechanism, not a fourth), Q52 (the frozen code universe this quantifies over)
- Spec: Tamper matrix — every mutation fails with a **distinct** error (MVP-SPEC.md line 168); the stable error-code contract (`docs/testing/error-code-contract.md` §§1, 3, 4a)
- Discovered by: **the Q14 freeze-gate audit** (`docs/format/Q14-freeze-gate-plan.md` §2.3 line 238 and finding **C3**, `:561-576`, 2026-07-28), which reserved the ID; written up in wave 7.
- The gap, confirmed at HEAD. Three reverse-coverage sweeps exist and not one quantifies over C's or G's codes. F23's `every_registered_domain_code_has_a_row_or_a_named_owner *(renamed 2026-08-03 at A38 — the check is no longer F-side)*` (`crates/antseal-core/src/test_util/tamper_coverage.rs:450`) iterates `DOMAINS`, which is exactly `&[&BUNDLE, &MANIFEST]` (`:93`). F24's `every_cbor_code_has_a_row_or_a_named_owner` (`test_util/tamper_rows_cbor.rs:437`) covers the 15 `cbor-` codes. R7's `every_unprefixed_verify_code_has_a_row_or_a_named_owner` (`test_util/tamper_rows_structural.rs:874`) **skips six prefixes by name**, and `crypto-`, `content-` and `fine-root-` are three of them (`:875-882`). Q52's snapshot pins *existence*, not coverage, and says so at `docs/testing/error-code-contract.md:176-178`.
- The numbers, counted from the frozen snapshot `testdata/error-codes/v1/CODES.txt` (191 codes): **25 `crypto-`**, **14 `content-`**, **9 `fine-root-`** — **48 codes outside any enum→rows quantifier**. Measured row coverage: 20 of 25 `crypto-`, 4 of 9 `fine-root-`, and **0 of 14 `content-`**.
- **Correction to the plan's own scope.** §2.3 names five unrowed `crypto-` codes and they are exactly right — `crypto-fine-root-commit-mismatch`, `crypto-rng-failure`, `crypto-signature-invalid-ml-dsa-65`, `crypto-signature-missing-ed25519`, `crypto-signature-unlisted-ed25519`. It does **not** name the five unrowed `fine-root-` codes: `fine-root-bad-node-hash-length`, `fine-root-bad-seed-length`, `fine-root-byte-len-mismatch`, `fine-root-range-out-of-bounds`, `fine-root-wrong-cover-shape`. So the unrowed count across the two families is **ten**, not five, on top of the fourteen `content-` codes that have no sweep at all. One trap to avoid while counting: the strings `content-fine-root-*` at `test_util/tamper_rows_fine_tree.rs:501`, `:508`, `:516` are row **ids**, not error codes, and must not be read as coverage.
- Do: build on F37's shared helper — universe in, rows + seed-row list + named-owner list in, unaccounted codes out — and supply two more namespaces rather than writing two more sweeps. The failure mode to avoid is already on the tree and documented: F23's `DOMAINS` doc comment (`tamper_coverage.rs:91-92`) says *"F24 appends its `cbor-` domain here"* and **F24 did not** — it built a sibling and recorded why (`tamper_rows_cbor.rs:70-76`). Repeating that gives five sweeps that each cover a fifth of the ground.
- Accept:
  - Every one of the 48 codes ends as claimed-by-a-row or as a **named non-row with its argument**; none stays merely "owed".
  - Each namespace's sweep goes red on a synthetic unaccounted code (test-of-the-test, per family — a shared helper makes one proof tempting and it is not enough).
  - Reachability is checked before a row is written: a code no surface can emit is a *finding* about the schema, and its honest end state is a named non-row, not a fixture that cannot be built (F24's `cbor-int-out-of-range` is the precedent).
  - The accounting lists are checked live in both directions, so a code that disappears fails as loudly as one that appears.
- Notes: One shape must be accommodated rather than forced into the row/non-row binary — `error-code-contract.md:665-669` records a code whose owner is *"the strict-detection contract of the public `canon` API"*: a real owner, a real test, and no pipeline row. Counting caution: the plan's §2.3 table says "190 codes" and "54 of 190"; the frozen file and the contract doc both say **191** and **53**, and `error-code-contract.md:679-685` explains the discrepancy (adding per-family counts across enumerators undercounts by exactly one, `fine-root-rebuild-mismatch` being minted by R at `verify/error.rs:767`). Cite 191.
### Q56 — Generate `docs/ci-verification.md`'s context set from the workflows
- Milestone: M0
- Size: S
- Deps: Q1 (the lane set), Q43 (which moved CI logic into committed scripts and built the workflow parser this can join)
- Spec: Milestones M0 (MVP-SPEC.md line 153); Verification (line 167)
- Discovered by: **the Q14 freeze-gate audit** (`docs/format/Q14-freeze-gate-plan.md` §5 rows 3–4, `:891-892`, 2026-07-28), which reserved the ID; written up in wave 7.
- **The one-liner's numbers are all stale, including the one it calls real.** It reads *"17 vs 'still 16' vs the real 18"*. At HEAD `.github/workflows/ci.yml` defines **17 jobs**, and `cross-os` is a three-way matrix (`name: cross-os-${{ matrix.label }}` at `:217`, `include:` at `:223-231`), so the required-status context set is **19 contexts from 17 jobs**. 18 was correct at `5f794ff`, before Q50 added the `format-freeze` job — which is precisely the failure this task exists to close, and the wave-7 correction section has already rotted the same way it was written to fix.
- The disagreements, enumerated at HEAD. The document declares an "authoritative" context set **seven** times, each with a different total: `:162` (13), `:348` (14), `:476` (15), `:684` (16), `:927` (17, omitting `traceability` **and** `format-freeze`), `:991` (*"still 16"*, appearing **after** the 17-section because Q11 material was interleaved into the Q9 section), and `:1008` (18 — the wave-7 correction, which omits `format-freeze`). `grep -c format-freeze docs/ci-verification.md` is **0**: the job does not appear anywhere in the document. The correction section is itself wrong in three specific places — `:1025` says "18 contexts from 16 jobs"; `:1053`'s own recompute recipe comments `# job ids (16)` while the `awk` at `:1054` now emits 17; `:1059` says the payload must list 18. Two further hand-maintained copies disagree: `CONTRIBUTING.md:72` says 16 and its lane table carries neither a `format-freeze` nor a `traceability` row, and the gate plan says "7 of the 18" and "5 of the 18" (`:555`, `:557`, `:668`).
- Why this is not tidiness: **this list is the branch-protection payload.** The wave-7 change log records that a payload cut from either contradictory set would have left required lanes unprotected, and branch protection has still not been applied. A wrong number here is an unprotected lane, not a documentation nit.
- Do: generate rather than maintain, and **delete the superseded sections** rather than adding an eighth. `scripts/check-ci-shell.py` already parses all three workflows and enumerates every `run:` block, so it is the natural host: have it emit the context set — expanding matrix jobs and preferring the `name:` field where one is set — and fail when the document's single authoritative section disagrees. A document with seven authoritative answers has none, and the historical ones are in git.
- Accept:
  - Adding, renaming or re-matrixing a job turns a lane red until the document is regenerated — proved on a planted job.
  - Exactly one section claims to be authoritative and matches the workflows on the name set, not merely on the count.
  - No number in the document is a literal a human maintains; the count is derived from the list.
  - `CONTRIBUTING.md`'s lane table is generated from the same source or explicitly scoped as illustrative.
- Notes: Matrix expansion is exactly what the existing recipe gets wrong — `:1053-1054`'s `awk` counts job ids and calls them contexts, which is how "18 from 16 jobs" was written down as a correction. Carry Q43's general form with it: **a lane that has never run on the remote is not evidence.** The only remote run in this project's history is `30309407509` (14 contexts, 2026-07-27, cited at `:87` and `:238`), so the gap between 14 and 19 is the size of the untested set, and that fact belongs beside the generated list rather than in a paragraph someone has to find.
### Q57 — D78 and D79 are normative in code and have no decision record at all
- Milestone: M0
- Size: S
- Deps: F4/D8 (which depends on both), Q14 (the gate that freezes what they decide)
- Spec: Milestones M0 — Definitions sign-off (MVP-SPEC.md line 153); Format stability (line 123)
- Discovered by: **F4/D8 §17 item 3** (2026-07-28), confirmed while executing the registry freeze. **D78** (bundle schema validation never opens the embedded manifest) and **D79** (the OTS upgrade group is free-standing, never keyed on `status`) are cited as normative in `bundle/error.rs`, `bundle/schema.rs`, `codec/caps.rs`, `verify/error.rs`, in `docs/testing/error-code-contract.md` §2 ("decision D78, ratified 2026-07-28"), and now throughout the frozen wire registry — but **neither has a record file**, and `docs/decisions/README.md` jumps D77 → D80. They exist only as `TODO.md` lines. **D8 also has no README row**, though it does have a file. Three rows owed, two files owed. D78 in particular is the decision that fixes *which error family* every cross-side rejection lands in, permanently under D30: a reader who wants its argument has nowhere to go.
- Do: Write `docs/decisions/D78-bundle-schema-manifest-isolation.md` and `docs/decisions/D79-ots-upgrade-group-free-standing.md` from the evidence already in the tree — the type witness in `bundle/error.rs` (a `BundleError` has no arm that can carry a `ManifestError`, "the strength D78 needs"), `bundle/schema.rs`'s all-or-nothing decode, `tests/bundle_codec.rs:447`, the error-code contract §2, and registry §§0/7.6.3/7.8. Add README rows for D8, D78 and D79. Check no other decision cited in code lacks a file: the same sweep that found these two.
- Accept:
  - Both records exist with the project's Status/Date/Owning-task/Gate shape and are cited from `docs/decisions/README.md` in ID order with no gap.
  - Every `D<n>` cited in `crates/`, `docs/format/` or `docs/testing/` resolves to a file; a check enumerates them so a future citation-without-a-record fails rather than accumulates.
  - No outcome changes: both records document decisions already ratified in code and frozen in the registry.
- Notes: This is a *record* gap, not a decision gap. The rules themselves are landed, tested and now frozen; what is missing is the written argument a third party would need to disagree with them.
- **[2026-07-28] DISCHARGED, wave 7** — and it was already half-done when this entry was written: the two records and all three README rows landed earlier in the same wave, before lane E's freeze surfaced the gap independently. Filenames differ from the ones proposed here (`D78-bundle-schema-manifest-opacity.md`, `D79-ots-upgrade-group-presence.md`); IDs are what resolve, not titles. The remaining Accept bullet — the enumerating check — is now `scripts/check-traceability.py --decisions`, and writing it corrected the entry's own premise twice. **(a)** "every `D<n>` cited must resolve to a file" is too strong in two directions: three decisions are legitimately homed *inside* other records (D11 in the S1 memo, D12 in D7 §D12, D16 in the C11 probe report) and 47 are legitimately open with no file yet, so the check resolves against records **or** a registered home **or** an open register entry, and a decision with no home at all is the only failure. **(b)** A naive sweep reports `D800` — the Unicode surrogate, in a `canon/pipeline.rs` comment — as a missing decision, which is how a lint teaches people to ignore it; citations are therefore bounded by the highest **allocated** id from the register. The red-path proof is the Q57 failure itself, simulated faithfully: flipping D18's register checkbox to resolved, while its record does not exist, turns the check red.

### Q58 — Line-number citations into the registry rot, and the registry just froze
- Milestone: M0
- Size: S
- Deps: F4 (the freeze), Q6/Q50 (the freeze mechanisms), the `check-traceability.py` lint
- Spec: Format stability (MVP-SPEC.md line 123); Milestones M0 (line 153)
- Discovered by: **F4/D8 §17 item 5** (2026-07-28), and confirmed worse than recorded while executing the freeze. `docs/decisions/D76-file-salt-split.md`'s Consequences cites `docs/format/registry-v1.md:861` for §7.14 key 1; the bundle-slice pass moved that row to ~922, and the freeze moved it again to ~1097. The citation is now wrong twice over and nothing noticed either time. The general form is worse in two directions: (a) **decision records cite registry line numbers**, and the registry is a growing document; (b) **the registry cites MVP-SPEC line numbers** — "line 98", "line 121", "line 137" appear well over a hundred times in a document that is now **frozen**, while `MVP-SPEC.md` is not. Re-editing the spec would silently invalidate a frozen normative document, and `scripts/check-traceability.py` covers only the `FREEZE-BOUNDARY` block and the M-milestone matrix — spec line citations are outside the lint entirely.
- Do: Decide and record the citation convention, then enforce it. Cheapest credible shape: cite **sections** (`registry §7.14 key 1`, `MVP-SPEC "Reveal bundle"`) rather than lines, and extend `check-traceability.py` with a resolver that (i) fails on a `registry-v1.md:<n>` citation anywhere in `docs/`, and (ii) for each `MVP-SPEC.md line <n>` citation, asserts the line still contains a recorded anchor phrase. Fix D76's stale citation at source as the first instance. Consider whether MVP-SPEC.md should itself gain a freeze digest at Q14 — it is the input every frozen document quotes.
- Accept:
  - No `registry-v1.md:<n>` citation remains in `docs/`; the lint fails on a reintroduced one.
  - Every `MVP-SPEC.md line <n>` citation in the frozen registry resolves to a line whose content still matches its recorded anchor; a deliberately shifted spec line turns the lint red (test-of-the-test).
  - The convention is written down where a record author will read it.
- Notes: The registry freeze makes this urgent rather than tidy. A frozen document whose citations decay is worse than an unfrozen one, because the freeze is exactly the promise that its content is stable — and a reader who follows a wrong line number concludes the format is wrong, not the citation.

### Q64 — Extend the freeze-boundary lint to D84's F1–F4 block
- Milestone: M0
- Size: S
- Deps: Q37 (the lint and the boundary rows), A27 (the mirror), D84 §4/§7, Q14 (which froze F1–F4)
- Spec: Format stability (MVP-SPEC.md line 123); anchors are recorded real artifacts (lines 153, 155)
- Discovered by: **D84's own "Correction to the correction"** (`docs/decisions/D84-anchor-artifact-limits-permanence.md:362-397`, 2026-07-28), which registered the ID at `:393-394` while fixing a related error and found the general form underneath it. Written up in wave 7.
- The asymmetry, verified. `scripts/check-traceability.py --freeze-boundary` compares **§7's blockquote** — located by the first `## 7.` heading whose text contains "freeze boundary" (`:113`), unquoted at `:117-127` — against the text between `<!-- FREEZE-BOUNDARY:BEGIN` and `<!-- FREEZE-BOUNDARY:END -->` in exactly two files, `tasks/Q.md` and `docs/format/anchor-artifact-limits.md` (`BOUNDARY_COPIES`, `:57-60`). **Rules F1–F4 are not in §7.** They are stated in D84 **§4** (`:135-161`) and mirrored by hand in `docs/format/anchor-artifact-limits.md` **§1** (`:37-63`) — outside the markers, which do not begin until `:110`. Nothing between `:33` and `:104` of that file is read by any lint. And D84 §7's own row, the one the lint *does* check, puts rules F1–F4 **inside the v1 freeze** (`D84:233-236`). So the frozen rules are the unchecked copy, and the checked copy is the sentence asserting that they are frozen.
- **The mirror has drifted twice, and is drifted now.** The first drift is what D84's correction section records: the source was corrected on 2026-07-28 and the A27 mirror went on saying `Q19` where it should have said `Q27` for a full wave, while an editorial note beside it described the error as *"the source's to fix"* and then never noticed the source had fixed it. The second is live: diffing D84 `:135-161` against A27 `:37-63` — 27 lines each — yields exactly one differing line, `see the 2026-07-28 correction **below**` versus `**in D84**`. That divergence is deliberate cross-reference retargeting and is arguably the right text for each copy, but it makes A27's own stated Accept criterion — byte-identity with D84 (`anchor-artifact-limits.md:24-25`, `:72-73`) — **literally false at HEAD**, with nothing able to notice in either direction. A frozen rule, mirrored by hand, that has already drifted once is the case for this task rather than a hypothetical about one.
- Also verified: `docs/format/anchor-artifact-limits.md` is inside **no** freeze manifest. `docs/format/FROZEN.sha256` (`#! status frozen`) carries exactly two rows, `registry-v1.json` and `registry-v1.md`; the vector manifest is scoped to `testdata/vectors/v1/*.json`. So neither the rules nor their mirror are digest-pinned anywhere.
- Do: take one of the two answers D84 names, and record which. **(a) Extend the lint** — put a second marker pair around §1's block and register it as a second copy of a second source section. This needs the source locator generalised from "§7's blockquote" to "a named section", because §4's rules are ordinary prose rather than a blockquote, and that generalisation is most of the work. **(b) Splice programmatically**, the way §7 is, so §1 becomes generated rather than typed. Either way the `below`/`in D84` divergence must end in a recorded state: a lint demanding byte-identity has to accept a registered per-copy substitution, or the source has to word itself copy-neutrally — and the second is cheaper and does not add a mechanism.
- Accept:
  - Editing an F1–F4 rule in D84 §4 without re-cutting the mirror turns the check red, and editing the mirror alone does too — both directions, each demonstrated.
  - A27's byte-identity Accept is either satisfied or corrected at source; it must not be left stating a property the tree does not have.
  - The vacuity floor generalises with the mechanism: the existing check refuses to pass below two copies (`check-traceability.py:176-181`), and a second block that could silently find one copy would be worse than no check.
  - No normative content changes — this asserts text that is already frozen.
- Notes: The general form is Q58's — a frozen document whose correctness depends on an unfrozen or unchecked one — and **F44** owns the F-side instance (the frozen registry citing `MVP-SPEC.md` by line number). This entry is the narrowest and the only one with a *demonstrated* failure rather than a predicted one. D84's own honest replacement statement is worth preserving verbatim in whatever record this produces: *"correcting it here corrects it everywhere the lint reaches, and the lint reaches §7 only."*

### Q65 — Publish-scope decision, and the pre-public scrub it gates
- Milestone: M4 (with Q22/Q28); **becomes urgent the moment making the repo public is considered for any reason**
- Size: M
- Deps: Q22 (README/install/product-limits), Q28 (copy audit), Q27 (format-stability policy); interacts with the branch-protection blocker recorded in `docs/ci-verification.md`
- Spec: Milestones M4 (MVP-SPEC.md line 163); Risks — malicious verifier host (line 189)
- Discovered by: **2026-07-28 (wave 7, maintainer question)**, immediately after the branch-protection runbook step was found to be blocked by GitHub plan — where *"make the repository public"* is one of three options. That coupling is the point: a change made for a CI reason would publish the entire history in one step, and the decision about **what** is published would never get taken on its own terms.
- Do: Decide, deliberately and once, what is public at release and what is not — then execute the scrub **before** the repository's visibility changes, never after. Three findings from the wave-7 survey that the decision must start from rather than rediscover:
  1. **`MVP-SPEC.md` cannot be removed.** It is referenced by **126 files** across `crates/`, `scripts/` and `.github/`, and cited **13 times inside the frozen registry**; `scripts/check-traceability.py --matrix` resolves the traceability matrix against its line numbers, and that lane is a freeze-gate condition. Removing it does not lose a document — it breaks the verification chain the product's credibility rests on. The same holds in weaker form for `docs/security-assumptions.md` (4 refs, byte-identity drift tests) and `docs/threat-model.md` (2).
  2. **`MVP-SPEC.orig.md` and `SPEC-REVIEW.md` have ZERO references** from code, scripts or CI. They are the only two documents that can leave cheaply, and both are superseded drafts.
  3. **Five tracked files contain `/home/deb/...` paths** — including `MVP-SPEC.md`, `docs/ci-verification.md`, `tasks/P.md` and `docs/decisions/D3-repo-layout.md`. Not a secret, but it publishes the maintainer's machine layout and local username. Cheapest to fix *before* a visibility change, because afterwards it needs a history rewrite to undo.
  Then take the substantive call, which is **not** obvious in the direction it first appears: for a proof-of-existence tool the **format spec and the verifier must be public** for a third party to implement and audit them. A verifier nobody can audit is worth very little, and MVP-SPEC.md line 123's promise (versions verifiable forever) is a promise to people outside this repository. The genuinely private material is commercial timing, not security.
- Accept:
  - A decision record naming, per file or directory, `public` / `private` / `private-until-release`, with the reason — and it must survive the test above: nothing marked `private` may be load-bearing for verification.
  - The `/home/…` path scrub landed, with a lint so it cannot return.
  - Executed **before** any visibility change, and the ordering stated where the visibility change would be made (the `docs/ci-verification.md` runbook).
  - If the answer is "stay private indefinitely", that is recorded as the decision too, with its consequence: third parties cannot audit the verifier, which weakens the product's central claim.
  - **D61 is re-read in this same wave** when this resolves to *public*, and the re-read records which of D61 §9's two conditions hold: **(a)** the repository is public — which alone reopens only the *budget* half, since standard GitHub-hosted runners are free on public repositories; **(b)** use by parties other than the maintainer, sufficient to argue OSS-Fuzz's own *"significant user base and/or critical to the global IT infrastructure"* criterion. **(a) alone does not reopen the OSS-Fuzz arm.** Until both hold, OSS-Fuzz is *not applicable* rather than *pending*, and no wave may carry D61 as open on that account. *(Added 2026-08-02 by D61 §9 — armed by the orchestrator, since the lane that resolved it may not edit `tasks/*.md`.)*
- Notes: **The repository is private today and nothing is exposed.** A wave-7 scan found the only email address in the tree is the canonical noreply, no key or wallet material (enforced continuously by the `secret-guard` lane, Q2), and therefore **no history scrub is warranted now** — a scrub is the tool for a committed secret, and its cost here is real: the `format-v1-freeze` tag is pushed, and a rewrite would change every hash again and require force-pushing over a published tag. Maintainer's call, 2026-07-28: **defer removal until going public, if ever.** This entry exists so that deferral is a recorded decision with its trigger attached, rather than something forgotten at the moment it matters.

### Q66 — The traceability self-test rotted on the gate's own tick, and the local gate never ran the lane
- Milestone: M0 (post-freeze repair; blocks any push — `traceability` is a required context and was exiting 1)
- Size: S
- Deps: Q49 (the gate-state normalisation), Q43 (lanes must run locally), Q13 (the lane)
- Spec: Verification section (MVP-SPEC.md lines 165–175) — the traceability lane is the machine check over it
- Discovered by: **2026-07-31 five-agent verification audit** (gate re-execution lane) — the first time `scripts/ci-lanes.sh traceability` was executed against a tree at or after the freeze commit.
- The defect, precisely: three of `check-traceability.py`'s self-test fixtures mutated the literals `- [ ] **Anchor-artifact freeze scope` and `- [ ] **Report-version evolution` in `tasks/Q.md`. The gate commit `2f1588c` ticked both rows to `- [x]` — exactly the state change Q49 re-engineered the *check* to tolerate — so all three planted mutations matched nothing, the vacuity guard (correctly) reported each as proving nothing, and the lane exited 1 on every tree from the freeze commit onward. Q49's failure mode, one level down: the check was fixed for gate state; its self-test fixtures were not.
- Why it sat invisible: `scripts/local-gate.sh` — the runner that produced the "all green" gate verdict — did not run the traceability lane at all, and no remote CI run was ever recorded for the freeze push. Q43's rule ("a lane that has never run on the remote is not evidence") in its local dual: a lane that never runs locally is not evidence either.
- Do: make the three gate-state fixtures derive their mutation from whatever state the row is currently in — strip the marker for the red case, flip the tick and re-case it for the two green cases — so no future tick, untick or case change can vacate them; leave the vacuity guard untouched (it is what caught this). Add `run traceability scripts/ci-lanes.sh traceability` to `scripts/local-gate.sh`.
- Accept:
  - `scripts/ci-lanes.sh traceability` exits 0 at HEAD, with the self-test printing all four freeze-boundary bounds (word change red, deleted marker red, tick tolerated in both directions and either case).
  - Reverting both normative rows to `- [ ]` on a scratch tree leaves the self-test non-vacuous and green — the rot class is closed for both gate states, not patched to the current one.
  - `scripts/local-gate.sh` runs the lane.
- Notes: the lane's substantive checks were green throughout (`--matrix`: all 16 M0 rows `covered`; `--decisions`: every citation resolves; `--freeze-boundary`: copies identical) — the red was confined to the self-test harness. The freeze itself is unaffected. It stays a red gate lane rather than an excused one by the project's own doctrine: a checker never observed failing is not evidence, and for the whole post-freeze window this lane's ability to fail was exactly what was broken.
- **[2026-07-31] DONE** — both fixtures state-agnostic (regex-derived mutations), both-states proof run on a scratch tree (`- [ ]` and `- [x]` forms, self-test exit 0 non-vacuous in each), `local-gate.sh` gained the lane, `ci-lanes.sh traceability` green at HEAD.

### Q67 — D28 rationale 3's totality claim is unsound, and D74 inherited it
- Milestone: M0 (post-freeze residue)
- Size: S
- Deps: R4
- Spec: D28, D74
- Discovered by: the **2026-07-31 adversarial code review** (finding 7, `medium`; verified from both the mechanical and the record side).
- Problem: D28 rationale 3 claims *"a third party cannot alter a bundle's reveal shape undetected — strip units and the leak arm fires, strip salts and the missing arm fires"*. A **consistent** strip fires neither: remove a file's reveal entries, its `touched_files` entry and its `full_reveals` entry *together* and the result verifies clean (D80 cannot fire — no unit of that file is revealed; D82 cannot fire — the file has no touched entry; R4 classifies it `Untouched`). D74 rationale 3 quotes the claim verbatim, and D74's wave-6 audit table leans on it. R4's own TODO entry repeats it as the argument that closed D74.
- Do: **This is a records fix, not a code fix.** The mechanism is not a vulnerability: the bundle is unsigned by design, stripping disclosures yields a narrower but honest bundle, and the verifier correctly reports less — the review's verifier noted the stripped bundle is byte-identical to an honest narrower bundle, since every bundle-side disclosed value is per-work deterministic. What is wrong is the *stated* reasoning, which is universally quantified and is not universal. Amend D28 rationale 3 to say what is actually true — *inconsistent* edits are caught, consistent narrowing is not, and consistent narrowing is not a threat because the bundle claims only what it discloses. Then fix D74 rationale 3, D74's audit table, and R4's TODO entry at source rather than leaving three copies of a corrected claim and one of the original.
- Accept:
  - D28, D74 and R4's entry all state the corrected argument; grep finds no surviving copy of the totality phrasing.
  - The corrected records say explicitly why consistent narrowing is *not* a threat, so the next reader does not re-open it as one.
  - If any current test or comment cites the totality claim as its reason, it is re-justified or retired.
- Notes: The review's headline pattern is that this project's dominant defect class is recorded claims the code does not implement (see `docs/reviews/2026-07-31-adversarial-code-review.md`, "The pattern worth naming"). This is the decision-register instance of it, and it is the one that matters most, because D74 was *decided* partly on the strength of the false clause.

### Q68 — The report-kind vector set is structurally closed post-freeze
- Milestone: M0 (post-freeze residue; decide before any new report shape needs freezing)
- Size: S
- Deps: Q6, R9, R30
- Discovered by: **R53** (2026-08-01), trying to pin a corrected report shape.
- Problem: the report-kind executor (`vectors_report::check_shape_coverage`) requires **every** report-kind document to carry all 11 `REQUIRED_SHAPES`, while the frozen 21-case document may not change a byte — so no new report vector can be committed at all: a minimal second document structurally cannot pass, and a full duplicate document would fork the frozen bytes. New shapes are pinned only as in-tree tests (R53's precedent: D29 byte-snapshot + R30 digest row, native+wasm).
- Do: decide whether M0-shape coverage should hold across the **union** of discovered report documents (an executor change; zero frozen bytes move) so future shapes can be frozen without a format event — or record that the report vector set is closed until v2 and in-tree pins are the sanctioned mechanism. Either outcome is a one-paragraph record where the executor lives.
- Accept:
  - The decision is recorded at `REQUIRED_SHAPES`/the executor, naming R53's precedent.
  - If the union rule: it lands with a test proving a minimal one-shape document + the frozen document together satisfy coverage, and that a shape missing from the union still fails.
- Notes: without this, every future report-affecting fix pays R53's workaround cost, and the freeze quietly converts "frozen" into "closed".

### Q69 — Doc-named-test liveness: rustdoc pointers must resolve
- Milestone: M1 (quality infra; no freeze interaction)
- Size: S
- Deps: F41
- Discovered by: **F41** (2026-08-01) — `ids.rs`'s naming-ban pointer named a test and a file that never existed; nothing could notice.
- Problem: docs that name their enforcing test rot silently when the test is renamed, moved, or never written; the class is greppable and is the rustdoc instance of F42's registry-prose problem. The review's pattern ("recorded claims the code does not implement") includes claims about *tests*.
- Do: a discipline test that extracts backtick-quoted `fn`-shaped names and `tests/*.rs` paths from doc comments and asserts each resolves (start with `manifest/`, `bundle/`, `codec/`, `crypto/`; allowlist mechanism for deliberate forward references, each carrying a task id).
- Accept:
  - The `ids.rs` case, re-planted, is caught.
  - Zero unexplained allowlist entries; each names the task that will land the referenced test.
- Notes: keep it heuristic and honest — the goal is catching pointers to *nothing*, not proving pointers point at the right assertion (that is review work).
- **Landed 2026-08-02** as `crates/antseal-core/tests/doc_pointer_liveness.rs`. Deviations and findings:
  1. **The recognition rule is an underscore floor, measured before it was frozen** — a backtick token is a test pointer when it is lowercase snake_case with **≥ 4 underscores** (after dropping a trailing `()`, a trailing `*` glob, and any `::` qualifier). Not a guess: at ≥ 2 the rule recognises 351 tokens with 135 non-resolving (unusable — ordinary API names); at ≥ 3, 135 with 6, of which 4 are false (a module, an upstream method, two prose phrases); at ≥ 4, 105 with **3, every one a genuine defect**. The cost is recall — 86.7 % of the crate's 1 207 `#[test]` names clear the floor, so pointers at the 161 short-named tests are unchecked. Recorded in the test's own module docs, table included, because a threshold without its measurement is the kind of claim this task exists to catch.
  2. **Scope is `antseal-core` only**, not the four `manifest/ bundle/ codec/ crypto/` subtrees the Do line suggested — the whole crate costs the same and finds more (two of the three defects were outside those four). The other five crates were surveyed read-only under the same rule and are **clean**; widening is **Q70**, and it starts with no backlog.
  3. **The allowlist has two legitimate entry kinds, not one.** The Accept line anticipated forward references (each naming a task); the tree's one real entry is an *external* reference — `ed25519-dalek`'s own `tests/x25519.rs`, cited as provenance for RFC 8032 §7.1 seeds. Both kinds must say which they are, and a staleness guard fails when any entry starts resolving, so an exemption cannot outlive its reason.
- Findings, all fixed at source: `forced_total_form_matches_the_fallible_one` (`canon/pipeline.rs` — a mangling of `kat_forced_total_form_matches_the_fallible_one`, *and* attributing the arbitrary-bytes claim to the KAT test rather than the proptest); `streaming_fine_root_equals_an_independent_reference` line-wrapped mid-identifier in `tests/content_properties.rs`, so the rendered code span named nothing; and `the_encode_gate_reports_the_decode_paths_own_codes` in `codec/encode.rs` — **F53's own, one commit old**. The last one is the argument for the task: the class regrows within a day, in a doc written by someone who knew about it.
- Red directions executed: a planted `fn` pointer and a planted `tests/*.rs` pointer (both in `manifest/ids.rs`, the site F41 found — both named in the failure output), and a planted stale allowlist entry. The rule fixture in `the_recognition_rules_are_exactly_as_documented` is the permanent half, pinning what the rules do and do not recognise so a later narrowing cannot pass vacuously.

### Q70 — Widen the doc-pointer sweep past `antseal-core`
- Milestone: M1 (quality infra; no freeze interaction)
- Size: XS
- Deps: Q69
- Discovered by: **Q69** (2026-08-02) — the sweep landed scoped to one crate; the rules and the walk are already crate-parameterised (two roots and a `CARGO_MANIFEST_DIR`), so nothing but placement is crate-specific.
- Problem: `antseal-cli`, `antseal-net`, `antseal-anchor`, `devnet-launcher` and `wasm-bitmatch` document their own guards and can rot the same way. They are **not rotten today**: surveyed at Q69 under the identical rules, 53 files, **zero** unresolved pointers. So this guards future drift rather than clearing a backlog, which is also why it is XS and not blocking.
- Do: decide the home first — a per-crate test target (each crate owns its own sweep, no cross-crate path assumptions) or one workspace-level sweep in a single crate (one allowlist, one rule statement, but it must walk `../`). Then land it with the same allowlist + staleness guard, and re-run Q69's planted-fault directions in whichever crate the sweep newly covers.
- Accept:
  - Every workspace crate's doc comments are swept by something.
  - A planted dangling pointer in a newly covered crate goes red.
  - The recognition rule is stated once, not copied per crate.
- Notes: if the per-crate shape wins, the rule prose belongs in one place with the others citing it — restating a rule per crate is the duplication F42 warns about, one layer up.

### Q71 — Make a skipped devnet E2E gate visible instead of merely forbidden
- Milestone: M1 (after the first storage merge that actually runs the gate)
- Size: S
- Deps: Q15 (the gate + its evidence line); S17 (the first merge the gate really guards)
- Discovered by: **Q15** (2026-08-02), and it is D52 residual risk 1 stated as work rather than as an accepted risk.
- Problem: the gate is *required by convention*. Nothing can enforce it — branch protection is 403-blocked on this plan, which is the same fact that made a required CI job pointless (D52 E1). D52's stated mitigation is "the evidence trail (dated gate lines in wave records, artifacts on failure) plus the scheduled remote run making a silently-skipped local gate visible as drift". Today that trail is a **promise**: `scripts/e2e-devnet.sh` writes `target/e2e-devnet/<run>/evidence.txt`, which is gitignored and local, and nothing anywhere checks that a storage-touching commit is accompanied by one. A skipped gate is currently indistinguishable from a passed one after the fact — which is precisely the Q66 shape ("a lane that never runs is not evidence"), one level up from lanes to gates.
- Do: make the trail checkable. Sketch, not a decision: the gate's evidence line is pasted into the wave record (TODO.md / the task entry) exactly as the Q14 format-freeze gate lines already are, and a check — the natural home is `scripts/check-traceability.py`, which already reads TODO.md and the task files — asserts that every commit range touching the CONTRIBUTING storage-path list carries a recorded `e2e-devnet: PASS commit=<sha>` line whose sha is in that range. Decide first whether the check runs over a commit range (pre-push) or over the wave record (post-hoc); the second is weaker but needs no hook and cannot be bypassed by not running the hook.
- Accept:
  - A storage-touching change with no recorded gate line is detectable by a committed check, and a planted example goes red.
  - The check cannot be satisfied by a line that names a different commit, or a `PENDING` line (PENDING discharges nothing — `scripts/e2e-devnet.sh` already refuses to call it a pass).
  - The convention is stated once, in CONTRIBUTING's "Devnet E2E gate" section, and the check cites it.
- Notes: deliberately NOT a new required CI context — the payload stays at 19 (Q56/D52). This is a records check, and its whole point is that it works on a plan where enforcement does not.

## Open decisions (Q)
- Independent cross-check vehicles and permanence — which second implementations per surface (Python `cbor2` for CBOR; Python crypto stack for HKDF/commitments/GGM; whether ml-dsa↔fips204 cross-crate + ACVP KATs counts as "independent" for ML-DSA), and one-shot audit artifact vs permanent CI lane (proposal: both). Blocks Q11, Q14. Must land by M0. — **[2026-07-28]** RESOLVED (D31): one vehicle per surface, graded **T0 external oracle / T1 independent re-implementation / T2 same-ecosystem agreement**. CBOR keeps D12's `cbor2 ==6.1.3` for **decode only** — our own RFC 8949 §4.2.1 encoder is the encoding authority, which retires D7 §D12's length-first ordering caveat instead of documenting it. Crypto/GGM/padding/canonicalization reuse the Python references C16/G15/G3 already landed, each now **required to carry a T0 known-answer anchor** (RFC 5869 App. A, RFC 8032 §7.1, Unicode `NormalizationTest.txt` + a `unidata_version == '17.0.0'` assertion). **ML-DSA-65: NIST ACVP replayed against `ml-dsa =0.1.1` — T0, the strongest tier, and the answer to this entry's own question is that `ml-dsa`↔`fips204` is T2 and is NOT independence** (it is D14's fallback-equivalence check, retained and labelled as such). Permanence: **both**, and the two are not redundant — the dated one-shot report is the evidence *for* the freeze, the permanent unconditional `cross-check` lane is the guard *after* it. Buildable breakdown for Q11/F14 in D31 §9; Q14's verbatim row in §10. Found a gap: the report byte format has no cross-check at all → **Q38**.
- Deterministic verification-report byte format compared by the bit-match harness (exact serialized output contract with R/F). Blocks Q4, Q5. Must land by M0.
- Stable machine-readable error-code contract (how `antseal-core` exposes codes for tamper-distinctness across F/C/G/A/R errors and verdict states). Blocks Q7, Q8, Q18. Must land by M0.
- Devnet E2E venue: GitHub-hosted CI job vs self-hosted scheduled job vs required scripted local gate. Blocks Q15. Must land by M1. — **[2026-08-01]** RESOLVED (D52): the **required local gate** `scripts/e2e-devnet.sh` plus a **scheduled, non-required** hosted job (`devnet-e2e-cron`, never a PR context); per-PR CI job and self-hosted runner both rejected. The register's own lean ("a CI job if it fits") was overturned by its defining benefit being unavailable here — branch protection 403s on this plan, so "required CI job" and "required local gate" have identical enforcement strength. **[2026-08-02]** IMPLEMENTED by Q15 (venue only; the S17-S19 suite it wraps is declared pending in the script's registry).
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
- **[2026-07-28] DISCHARGED, wave 7** — the conversions landed before the freeze rather than after it, which was the point: F4 moved ~30 sections of the registry in this same wave, so every line-number citation into it would have rotted at once, silently. All six sites across D76 and D77 became section references (§0, §7.12, §7.14 key 1). Enforcement is the second half of `scripts/check-traceability.py --decisions`: any `registry-v1.md:<n>` or `registry-v1.json:<n>` under `crates/`, `docs/format/` or `docs/testing/` fails the lane, naming the file and telling the author to cite the section. Self-tested by planting one. **Deliberately NOT done**: the second Accept bullet — verifying that each `MVP-SPEC.md line <n>` citation still lands on matching content — is a different and larger mechanism (the spec is *not* frozen and carries 100+ such citations from the now-frozen registry). That is **F44**'s, registered by lane E for exactly this, and it is a real residual, not a closed one.

### Q73 — Register the `anchor-` codes A5/A8 minted beyond the ten already ruled
- Milestone: M2
- Size: S
- Deps: D91, A38/Q77, A5 + A8 (landed)
- Do: D60 §7.3 mints eight codes and D53/D59 add two more, but A8's Accept row
  requires distinct errors for outcomes **no decision enumerated** — a
  stripped content-type attribute, a message-digest mismatch, an ESSCertID
  naming a different certificate, a missing or non-critical EKU, a token
  signature that does not verify. A rejection class with no code of its own
  cannot be a tamper row, so A5/A8 minted **25 further codes**, all under
  `anchor-` per D91 §6.1, all pairwise distinct, all disjoint from the 216 in
  `testdata/error-codes/v1/CODES.txt` (machine-checked in
  `anchor::error::tests::codes_are_frozen_in_the_committed_universe` *(renamed 2026-08-03: the original asserted these codes were ABSENT from the snapshot — true only while the A domain was unregistered, false one commit later; the replacement asserts live ⊆ committed, which is what §4a claims)*).
  They are **not yet in the committed universe**: `anchor::error::all_code_exemplars`
  is deliberately not wired into `error_universe::by_enumerator`, because D91
  §8.2 makes that A38's move together with the roster assertion going 8 -> 9.
  Land the registration: A38 wires the enumerator, the snapshot gains the
  rows, and this task reviews the **names** while renaming is still free —
  error-contract §3 makes a code permanent from the first binding, and there
  is no binding yet.
- Accept:
  - `testdata/error-codes/v1/CODES.txt` contains every `anchor-` code.
  - `the_universe_is_exactly_the_registered_enumerators` reads **eleven** *(renamed and recounted 2026-08-03: the A domain has three code sources, not one)*.
  - A review pass over the 25 minted names against D91 §7.3's convention, with
    any rename applied **before** a tamper row or golden vector binds one.
- Notes: The judgement call worth reviewing explicitly: the two
  response-envelope codes carry a `tsa` segment (`anchor-tsa-status-not-granted`,
  `anchor-tsa-token-absent`) although D91 §7.3's letter would drop it, since
  there is no OTS analogue to be ambiguous with. They follow the
  `anchor-tsa-nonce-mismatch` precedent, which carries `tsa` for the same
  non-reason. Either is defensible; pick one deliberately.

### Q74 — Close the `core-dep-graph` I/O-purity hole: the forbidden list is nine names, not a property
- Milestone: M2
- Size: S
- Deps: P15, P20 (the lane and its three rules); D58 §2(b)
- Spec: Architecture — `antseal-core` is WASM-safe, no I/O (MVP-SPEC.md lines 47–53); CLI/page must not diverge (line 73)
- Do: `scripts/ci-lanes.sh`'s `lane_dep_graph` announces *"antseal-core's NORMAL dependency graph must be I/O-free and RNG-free"* and enforces it with `forbidden='^(tokio|async-std|smol|hyper|reqwest|mio|socket2|getrandom|rand|rand_chacha) '`. That is nine names, and the property is larger than the names: a measured nominee (D58 §2) would have added `env_logger`, `is-terminal`, `libc`, `regex` and `termcolor` to the core graph — an environment-variable reader, a terminal detector, a libc binding and a regex engine — and the lane would have gone **green**. Extend the rule so the check matches its own sentence. Two mechanisms, and the task must choose deliberately rather than adding names reflexively: (a) extend the deny-list with the logger/terminal/libc/process-environment class; (b) invert it to an **allow-list** — `antseal-core`'s normal graph is 56 packages and every one is deliberate, so an unrecognised *addition* fails and must be justified in the same PR. (b) is the shape that scales, catches the crate nobody predicted, and is the reason this task exists; (a) is the fallback if (b) proves too noisy against proc-macro tiers. Whichever is chosen, keep the lane's existing self-test-first discipline: the detector must trip on a planted entry before any green verdict is trusted.
- Accept:
  - The lane fails on a graph containing `env_logger` (or the chosen mechanism's equivalent), demonstrated by a scratch run with the edge planted — **red direction executed, not asserted**.
  - Anti-vacuity: the lane still passes on today's graph, and the recorded package count is asserted so a silent graph change surfaces (the P20 rule-1 pattern).
  - If (b): the allow-list is generated from today's graph, committed, and an *addition* fails naming the package while a *removal* passes (additions-only, inverted — the `error_universe.rs` shape).
  - The lane's announcement string and its enforcement agree; a reviewer reading only the `note` line is not misled about what was checked.
- Notes: Discovered by D58 (2026-08-02) while measuring a nominee's closure — the finding is independent of that nominee and of D58's ruling. This is the same defect shape Q52 found in the error-code contract: three enforcement layers whose stated claim was broader than any of them could check, and the codes that were safe were safe incidentally. Here the crates that are absent are absent because nobody has yet proposed one, not because the lane would stop it.

### Q75 — `MATRIX.json` row `anchor-ber-not-der` is now satisfiable
- Milestone: M2
- Size: XS
- Deps: A5 (landed); the beta lane owns `MATRIX.json`
- Do: `testdata/tamper/MATRIX.json`'s `ber-where-der-required` case carries
  `"expected": null` with the pending note *"M2; strict-DER limits and their
  fuzz targets are A/Q17."* A5 has landed the code and the fixtures: set
  `"expected": "anchor-der-not-strict"` and drop the pending block. The
  evidence is `crates/antseal-core/tests/der_pin_eval.rs::der_pin_rejects_indefinite_length`
  and `::der_pin_rejects_nonminimal_length`, over the four committed BER
  fixtures in `testdata/anchors/A25-bootstrap/`, two of which are proven to be
  **valid BER** by `from_ber` accepting them.
- Accept:
  - The row's `expected` is `anchor-der-not-strict` and its `pending` block is
    gone.
  - The tamper-completeness meta-test counts it as satisfied rather than
    deferred.
- Notes: Hand-off, not an edit from this lane — `MATRIX.json` is being changed
  concurrently by the beta lane (Q76) and two lanes writing the same JSON is
  how a merge conflict eats a row.

---

## `TODO.md` checkbox lines

```markdown
- [ ] **A33** — Rule what a critical unrecognised `TSTInfo` extension means (M2, S) — A5 parses the field and ignores criticality; no live TSA sends one, and `no_live_tsa_sends_tst_info_extensions` is the measurement that goes red when one does
- [ ] **A36** — Registry §7.9 key 1 names two ASN.1 types with one slash ("DER TimeStampResp/token"); A5 accepts both by structural dispatch — ratify or narrow, and narrowing is a format decision under line 123 (M2, S)
- [ ] **A37** — Record the `digestAlgorithm`/`signatureAlgorithm` consistency **non-rule** (M2, S) — D60 §3.2.6 forbids taking another decision from `digestAlgorithm`; an unexplained absence invites the "obvious" hardening
- [ ] **P24** — D60 §1.6's "zero new duplicate pairs" is false at the workspace level: 2 -> 10 pairs, 8 new, from `antseal-net`'s D89 `k256 =0.13.4` (RustCrypto 0.13) meeting `p384 =0.14.0` — amend D60, decide the `deny.toml` note (M2, S)
- [ ] **P26** — A30's `from_ber` ban needs exactly one carve-out, `tests/der_pin_eval.rs`, which D60 §7.4 requires as the anti-vacuity leg — with a planted-fault self-test (M2, XS)
- [ ] **Q73** — Register the 25 `anchor-` codes A5/A8 minted beyond the ruled ten: A38 wires the enumerator (8 -> 9), CODES.txt gains the rows, and the names get their one free review before §3 makes them permanent (M2, S)
- [ ] **Q75** — `MATRIX.json` row `anchor-ber-not-der`: set `expected` to `anchor-der-not-strict` and drop the pending block; A5's code and four committed BER fixtures have landed (M2, XS) — hand-off to the beta lane
```

### Q76 — Pre-fill the M2 anchor pending rows and split the compound digest-mismatch family
- Milestone: M2
- Size: S
- Deps: Q8 (the completeness checker); **before A21** — the whole point is to run the distinctness rule ahead of implementation
- Discovered by: **D53 §8** (2026-08-02), while counting the rows the M2 gate calls "all 7".
- Problem: two defects in `testdata/tamper/MATRIX.json`'s M2 half. (1) **The count is wrong, in both directions.** MVP-SPEC.md line 168's M2 enumeration is **six** semicolon-separated clauses, two of them explicitly compound (*"`.ots`/TSA token for a different digest"*, *"expired-at-genTime vs expired-after-genTime chain cases"*), so it expands to **eight** cases. `MATRIX.json` splits the expiry clause and keeps the digest clause whole (7 row ids); `tasks/A.md` A21's Do splits the digest clause and keeps the expiry clause whole (7 numbered items describing 8 tests); `TODO.md` says *"all 7 anchor tamper rows"* without saying which seven. **They are two different sevens.** (2) **Four pending rows carry `"expected": null`**, so §4b layer 3 — which exists to refuse a pending row whose outcome key is already claimed *"while it is still cheap to fix"* — cannot do its job on precisely the rows D53/D56 show are at risk of colliding on `verdict:invalid`.
- Spec: Verification — tamper matrix M2 rows (MVP-SPEC.md line 168); `docs/testing/error-code-contract.md` §4b layer 3, §5
- Do: Apply the verbatim edits in **D53 §8**: split the `anchor-token-for-a-different-digest` family into the two cases `ots-digest-mismatch` (row `anchor-ots-digest-mismatch`) and `tsa-imprint-mismatch` (row `anchor-tsa-imprint-mismatch`) — the family's `spec_quote` is unchanged, so `spec_source.note`'s literal-substring check still passes — and fill the four null `expected` slots with `anchor-cert-not-valid-at-gentime` (D53 C3), `valid-at-stamping-cert-since-expired` (D53 C2), `anchor-ots-digest-mismatch` (D56 O2) and `anchor-tsa-imprint-mismatch`. Then re-run the combined distinctness sweep with all eight M2 rows pending and assert it is green. Correct the "7" in `TODO.md`'s M2 gate line and in `tasks/A.md` A21's numbering to eight.
- Accept:
  - `MATRIX.json` holds **eight** M2 anchor cases, each with a non-null `expected`, and the checker is green.
  - A planted ninth pending row re-claiming `verdict:invalid` (already held by `anchor-forged-header`) goes red naming both rows — proving layer 3 is live on the M2 half, which it demonstrably was not while `expected` was null.
  - The family `spec_quote` strings still pass the literal-substring check against MVP-SPEC.md line 168's M2 marker.
  - No implemented row's expected outcome is edited (contract §6: *"never edit an existing row's expected code"*) — this task touches `pending` entries only.
- Notes: Q18 still registers the rows when A21 implements them; this is the *ahead-of-implementation* half, and it is separated precisely because Q18's deps place it after A21, which is too late for layer 3 to be worth anything.

### Q77 — Make §2's namespace rules machine-enforced (prefix conformance + cross-namespace disjointness)
- Milestone: M2 — **must land in the same wave**, since it is the only thing that would catch the next D58
- Size: S
- Deps: Q52 (the frozen universe and `by_enumerator`), U2 (the class table), **D91** (which specifies the mechanism), A38 (which adds the ninth enumerator)
- Discovered by: **Q80** (2026-08-02) for the disjointness half; **merged with D91 §8's prefix sweep by D91 §10**, deliberately as one mechanism rather than two sweeps — the F23/F24 sibling failure applied at the moment it would otherwise repeat.
- Problem: **§2's headline rule — *"a domain never mints a code under another domain's prefix"* — is enforced by NOTHING.** A foreign-prefix code is pairwise distinct, correctly kebab-shaped and new, so all three distinctness layers pass it; `census()` sorts it into the `"(unprefixed)"` bucket and *prints* it; and Q52's snapshot has additions-only semantics, so it is simply absorbed. That is not hypothetical: it is how **D58 came to specify sixteen codes under a namespace nobody had registered, with a fully green suite**. Second, smaller leg: the project has two stable kebab namespaces — codes (194, frozen by `CODES.txt`) and U2's `ErrorClass` names (28, frozen by the module table and `tests/exit_codes.rs`) — each checked within itself, the pair checked by nothing. Q80 measured zero intersection **by hand** and reserved `anchor-gate-abort`; D91 §5 makes that reservation load-bearing.
- Do: exactly D91 §8.1–§8.3. `ENUMERATOR_PREFIXES` pairing each `by_enumerator()` entry with its §2 prefix (`verify::error` deliberately permissive, since §2's wrapper rule makes R's list a superset); `REGISTERED_PREFIXES` **replacing** `census`'s private `PREFIXES` literal (`error_universe.rs:192-199`) so census and gate cannot drift; and a test parsing §2's table's first column (backticked cells only) so the const **is** the doc. Second leg in `crates/antseal-cli/tests/` — the only place that can see both `CliError` and the committed `CODES.txt`.
- Accept:
  - `every_code_carries_the_prefix_registered_to_its_domain` goes red on `ots-bad-magic` from the anchor enumerator, naming the `(enumerator, code)` pair.
  - **The enumerator lookup is TOTAL: an enumerator with no table row FAILS, never skips.** D91 is emphatic — a `filter_map` there would silently exempt the entire A family, i.e. go green over exactly the domain the ruling exists to constrain.
  - Test-of-the-test over a synthetic roster: `[("anchor::error::all_code_exemplars", {"ots-bad-magic"})]` must be returned.
  - `section_2_prefix_table_matches_registered_prefixes` asserts set equality **plus** `len() >= 7`, so a parse finding nothing cannot pass.
  - `the_universe_is_exactly_the_registered_enumerators` moves 8 → **11** with A38/A52 *(renamed and recounted 2026-08-03)*.
  - `error_codes_and_exit_class_names_are_disjoint` asserts both sets non-empty and the class set at its pinned size — it cannot pass vacuously, and it stays in the CLI target rather than being weakened to a hardcoded list in `error_universe.rs`.
- Notes: blocks nothing (A5 and A11 may proceed on D91's ruling). Native-only, like the rest of `error_universe.rs` (P14: wasm32 has no filesystem).

### Q78 — Price the whole Actions allowance, not just the fuzz lane
- Milestone: M2 (before any new scheduled or matrix lane)
- Size: M
- Deps: Q81 (the method and the cron reader), D61
- Discovered by: **Q81** (2026-08-02). D61 residual risk 4 states the gap and this is it as work: the 700-minute ceiling is *"a judgement, not a measurement … chosen against the known competing draws without knowing their totals"*.
- Problem: `ci-lanes.sh fuzz-budget` prices **one** lane against 35 % of the allowance. Nothing prices the other 65 %, and the other draws are the larger ones: `cross-os-macos` bills at **10×** and `cross-os-windows` at **2×** on *every push*, `devnet-e2e-cron` takes a weekly **cold** build of a ~736-package graph with no `rust-cache` by deliberate choice (D52 E3), `advisory-cron` runs weekly, and 19 required contexts run per PR. Exhausting the 2 000-minute GitHub Free allowance blocks **every** workflow in the repository, so the quantity that actually matters is the total — and it is the one quantity nobody has. Q81 measured the fuzz lane at ~1 877 min/month *before* its re-cadence, i.e. one lane alone was 94 %, which is evidence that the total is not comfortably inside the allowance and has never been checked.
- Do: two halves, in this order. (1) **Read the counter**: `gh api /users/aed900/settings/billing/actions` gives `total_minutes_used` / `included_minutes` and needs the `user` OAuth scope, which the current token lacks; obtaining it is account-bearing and needs the maintainer. This is the half of D61 §1 still owed. (2) **Extend the guard**: generalise `fuzz-budget`'s arithmetic to every workflow — per-runner multipliers (1×/2×/10×), scheduled crons via the existing `cron_days` reader, per-push lanes via a stated pushes-per-month assumption — and price the *sum* against a named whole-repo ceiling. Reconcile (2) against (1); a derived total that disagrees with GitHub's own counter by more than a stated margin is itself the finding.
- Accept:
  - The lane prints a per-workflow breakdown and a total, with the runner multiplier shown for each.
  - It goes red when the total exceeds the named ceiling, proven by planting a lane (e.g. restoring `fuzz-nightly` to daily) and watching it bite.
  - The 700-minute fuzz ceiling is either confirmed against the measured total or moved by decision, with the arithmetic recorded.
  - `docs/ci-verification.md` carries the billing read, dated, or records why it could not be taken.
- Notes: the runner multipliers are GitHub's published billing rates, not a project constant — cite them at the point of use. **Do not** let this quietly raise the fuzz ceiling: D61 makes it raise-only by decision.

### Q79 — Read the scheduled lanes, as a bookkeeping step
- Milestone: M2 (process; no code dependency)
- Size: S
- Deps: none
- Discovered by: **Q81** (2026-08-02), and named as a candidate by D61's own discovered-work list ("Q-domain, general").
- Problem: three lanes now run on a schedule and **nobody reads any of them**. `fuzz-nightly` ran five times between 2026-07-29 and 08-02 and Q81 was the first time a single run had been looked at — five green runs, ~309 minutes, invisible. `advisory-cron` and `devnet-e2e-cron` have the identical shape. This is `docs/ci-verification.md`'s own governing rule one level out: not *"a lane that has never run on the remote is not evidence"*, but **a lane that ran and was never read is not evidence either**. Both scheduled lanes carry triage conventions ("two consecutive reds block wave starts") that are unexecutable if nobody looks, and D61 §7 adds a *first-occurrence* release block for a fuzz crash — which is a promise about a signal that reaches no one.
- Do: add one bookkeeping step to the wave-close procedure: for each scheduled workflow, `gh run list --workflow <file> --limit 10` (read-only), record conclusion + duration in `docs/ci-verification.md` under a dated line, and act on the triage convention. Decide whether it is a documented step in CONTRIBUTING's wave-close list or a script (`scripts/ci-lanes.sh scheduled-report`) — a script is better only if it can run unauthenticated for the parts that do not need `gh`, otherwise it fails on every contributor machine and becomes noise.
- Accept:
  - Each of the three scheduled workflows has a dated read recorded at least once per wave.
  - A red run cannot reach a second wave unrecorded: the step names the convention that applies (D61 §7 for fuzz — crash vs infrastructure; D52's two-consecutive rule for the others).
  - The procedure is written where a wave-close reader will hit it, not only in a decision record.
- Notes: this is process, deliberately — D61 recorded it as a candidate rather than mandating it for that reason. The machine-backstop version is Q71's shape (evidence lines checked by `check-traceability.py`) and is a bigger piece of work; do not start there.

---

## Checkbox lines (for `TODO.md`)

- [ ] **Q77** (S) **(M2)** Make §2's namespace rules machine-enforced — the headline rule *"a domain never mints a code under another domain's prefix"* is enforced by **nothing**: a foreign-prefix code is distinct, correctly shaped and new, so every distinctness layer passes it and `census` absorbs it into the `(unprefixed)` bucket, **which is how D58 specified sixteen codes under an unregistered namespace with a green suite**. D91 §8.1–§8.3: per-enumerator prefix table with a **total** lookup (a `filter_map` would exempt exactly the A family), `REGISTERED_PREFIXES` replacing `census`'s private literal, a test asserting the const equals §2's table, and Q80's code/`ErrorClass` disjointness as the second leg — after Q52,U2,D91,A38; **same wave** · discovered by Q80 2026-08-02, merged by D91 §10
- [ ] **Q78** (M) **(M2)** Price the whole Actions allowance, not just the fuzz lane — `fuzz-budget` guards 35 % of 2 000 minutes and nothing guards the other 65 %, where the big draws are (`cross-os-macos` bills **10×** on every push, `devnet-e2e-cron` is a weekly cold build of ~736 packages by design, 19 required contexts per PR). One lane alone measured 94 % before Q81 re-cadenced it. Read GitHub's own counter (needs the `user` scope — the half of D61 §1 still owed) and extend Q81's arithmetic to every workflow with runner multipliers — after Q81 · discovered by Q81 2026-08-02
- [ ] **Q79** (S) **(M2)** Read the scheduled lanes as a wave-close step — `fuzz-nightly` ran **five** times unobserved (Q81 was the first read; all green, ~309 min), and `advisory-cron` and `devnet-e2e-cron` have the same shape. Their triage conventions ("two consecutive reds block wave starts"; D61 §7's first-occurrence crash block) are unexecutable if nobody looks. `docs/ci-verification.md`'s own rule one level out: a lane that ran and was never read is not evidence either — no deps · discovered by Q81 2026-08-02

---

## Hand-off: D61 §9's re-read trigger on Q65 (orchestrator must apply — `tasks/Q.md` is out of this lane's scope)

The brief asked this lane to arm D61's re-read trigger; D61 §9 puts the
mechanism in **Q65's Accept list**, and `tasks/*.md` is orchestrator-owned.
Exact line to add to Q65's Accept:

> - **D61 is re-read in this same wave** when this resolves to *public*, and
>   the re-read records which of D61 §9's two conditions hold: **(a)** the
>   repository is public — which alone reopens only the *budget* half, since
>   standard GitHub-hosted runners are free on public repositories; **(b)**
>   use by parties other than the maintainer, sufficient to argue OSS-Fuzz's
>   own *"significant user base and/or critical to the global IT
>   infrastructure"* criterion. **(a) alone does not reopen the OSS-Fuzz
>   arm.** Until both hold, OSS-Fuzz is *not applicable* rather than
>   *pending*, and no wave may carry D61 as open on that account.

### Q80 — Register the A-domain error-code prefix, and file `anchor-tsa-nonce-mismatch` as owner-backed
- Milestone: M2
- Size: S
- Deps: Q7 (the contract), A8/A10 (the first codes), A21/Q18 (the six anchor rows that need the prefix); D59
- Spec: Tamper matrix — every mutation fails with a distinct error (MVP-SPEC.md line 168)
- Discovered by: **D59 (2026-08-02, M2 planning round)**. `docs/testing/error-code-contract.md` declares itself *"Normative for every component domain (F/C/G/S/A/R)"* and then its §2 prefix table lists only `cbor-`, `manifest-`, `bundle-`, `crypto-`, `content-` and unprefixed R. **A and S have no registered prefix**, and A21/Q18's six M2 anchor families all need one.
- Do: Add the `anchor-` row to §2's table with A as owner and "anchor artifact parsing, token/chain verification, capture-path outcomes" as the surface; decide and record whether S needs one at all (S's failures are CLI-surfaced through U2's exit codes today, which may be the correct answer — record it either way, so the omission stops looking like an oversight). Register `anchor-tsa-nonce-mismatch` and record it explicitly as **owner-backed, not row-backed**: it can carry no tamper row because a tamper row mutates a *bundle* and no bundle path ever supplies an expected nonce, so the comparison is unreachable from one. Its named owner is A10. Re-run the Q7 cross-domain distinctness sweep over the combined set.
- Accept:
  - §2's table covers every domain its own header claims to bind, or records why one is deliberately absent.
  - `anchor-tsa-nonce-mismatch` appears in the registry with `owner: A10` and no tamper row, and the Q7 sweep does **not** report it as unclaimed — a build that omits the owner annotation must make the sweep red (test-of-the-test).
  - Distinctness holds across the full combined M0+M2 set; no A code borrows another family's prefix.
- Notes: Purely a taxonomy task — no code path changes. It must land before A21, whose six rows would otherwise mint codes under an unregistered prefix.

### Q81 — Re-cadence and budget the scheduled fuzz lane, and add the machine check that keeps it inside its share
- Milestone: M2
- Size: M
- Deps: Q9 (the lane), Q17 (the two targets that force the arithmetic), Q43 (the run-on-the-remote rule); D61, D52
- Spec: Milestones M0 (MVP-SPEC.md line 153), Verification (line 169), Risks — hostile bundles (line 187)
- Discovered by: **D61 (2026-08-02, M2 planning round)**. The lane's committed configuration — `cron: "41 3 * * *"` × 4 targets × 900 s — is a strict lower bound of **1 824 minutes/month, 91 % of the 2 000-minute GitHub Free allowance**, and Q17's two targets take it to **≥ 2 736 min/month, 137 %**. Exhausting the allowance blocks *every* workflow, not just this one. The lane has been live on the remote default branch since 2026-07-28 (commit 5302829) and **not one of its ~5 runs has ever been observed or recorded**.
- Do: In order. (1) **Measure first**: read the five existing runs' wall clock and the account's Actions usage (`gh api /repos/aed900/antseal/actions/workflows/fuzz-nightly.yml/runs`; `gh api /users/aed900/settings/billing/actions`), record both in a dated `docs/ci-verification.md` section, and triage any red found under D61 §7 **before** changing the cadence. (2) Change the cron to `"41 3 * * 1,4"` (twice weekly, Mon + Thu 03:41 UTC) — daily does not fit the budget, weekly sits exactly on GitHub's 7-day cache-eviction boundary and would destroy the corpus accumulation the lane exists for. Workflow name and job id stay `fuzz-nightly` / `fuzz-long`. (3) Change `inputs.seconds` default and the run step to `600`; leave `scripts/fuzz.sh`'s own `long` default at 900. (4) Record the measured corpus sizing and the 7-day retention rule in the cache step's comment. (5) Add `scripts/ci-lanes.sh fuzz-budget` — computes `targets × seconds × runs_per_month ÷ 60 + PER_RUN_OVERHEAD_MINUTES × runs_per_month` from the committed sources (the `TARGETS` array, the workflow's `inputs.seconds` default, the cron day-of-week field) and fails above `FUZZ_BUDGET_CEILING_MINUTES = 700`; wire it into `scripts/local-gate.sh` and a `ci.yml` job. (6) Add D61 §7's failure-classification step so a crash red (artifact present) and an infrastructure red (artifact absent) are distinguishable without judgement.
- Accept:
  - The `fuzz-budget` self-test arm plants a 7-name `TARGETS` array, asserts **red**, then asserts green on the committed sources — a checker never observed failing is the defect this project keeps finding.
  - The live arm is demonstrated red **before** the cadence change (at HEAD the checker computes ≈ 2 275 min against a 700 ceiling) and green after, and that ordering is recorded in the commit message. **The guard and the cadence change land in one commit** — otherwise the first of them turns `local-gate` and `ci` red — so the red half is produced on a scratch tree or by reverting the two lines locally.
  - The cron-parse arm computes **8.67** runs/month for `"41 3 * * 1,4"` and **30.33** for `"41 3 * * *"` (the script's `52 × ndays ÷ 12` convention); a build that ignores the day-of-week field fails, which is the most damaging way this checker could be wrong.
  - The cadence-floor arm fails if the maximum gap between runs exceeds **5 days**, so the budget can never be satisfied by lengthening the cadence into the cache-eviction window.
  - The measurement of step 1 is recorded in `docs/ci-verification.md` with its dates, and any red among the five runs has a triage line.
  - Required-context set unchanged at 19 (+1 only if `fuzz-budget` lands as a `ci.yml` job); `fuzz-long` is still never a PR context.
- Notes: D61 §5 is the point of this task — Q17 adds two names to `TARGETS`, and without the guard that silently multiplies the bill by 1.5 with nothing noticing until every lane stops. The knob for staying inside the ceiling is always `seconds`; cadence is not a knob, because cadence protects the corpus.

### Q82 — Correct the fuzzing doc's venue and required-context claims, and arm D61's re-evaluation on Q65
- Milestone: M2
- Size: S
- Deps: Q9, Q65; D61, D52
- Spec: Verification (MVP-SPEC.md line 169)
- Discovered by: **D61 (2026-08-02, M2 planning round)**
- Do: Three documentation corrections and one Accept-line addition. (1) `docs/testing/fuzzing.md` §7 says D61 is *"due M3 — deliberately not resolved here"* — TODO.md:573 lists it among M2's nine gating decisions; replace the section body with D61's ruling and a pointer. (2) The same section says *"OSS-Fuzz requires a public repository and an upstream-facing contact, so it is gated on the same publication decisions as the release lane"* — public status is **necessary and not sufficient**: OSS-Fuzz's criterion is *"an open-source project must have a significant user base and/or be critical to the global IT infrastructure"*, which Q65 does not grant and no decision in this project grants. Its four portability observations are correct and stay. (3) `docs/testing/fuzzing.md` §5's table marks `fuzz-smoke` *"yes — branch-protection context"*; **no context is required on this repository** (403 on both the classic API and rulesets, `docs/ci-verification.md` "Branch protection is BLOCKED BY PLAN", D52 E1) — the cell reads `mount point — required once the plan allows it (D52 E1)`. (4) Add one Accept line to **Q65**: when it resolves to "public", D61 is re-read in the same wave, and the re-read records which of D61 §9's two conditions hold.
- Accept:
  - No document states D61 as open, deferred, or due M3.
  - No document states that any CI context is currently required.
  - Q65's Accept carries the D61 re-read line, so the trigger has a named owner rather than being a hope.
  - `scripts/ci-lanes.sh traceability --decisions` resolves every new citation.
- Notes: Correction (2) is the one that matters operationally: a deferral written as "OSS-Fuzz becomes eligible if and when Q65 flips the repo public" would fire a re-evaluation on an event that does not make it eligible, and would leave a wave believing D61 had reopened when nothing had changed.

### Q83 — Interim `core-dep-graph` guard: name the adopted HTTP client, and give the rule its missing self-test
- Milestone: M2
- Size: S
- Deps: D90; **adjacent to Q74** (see Notes); lands with or before A3
- Spec: Architecture (lines 47–53); A3 Accept row 2
- Discovered by: **D90** (2026-08-02) §5. Two findings, one edit. (1) The lane's forbidden-crate scan (`scripts/ci-lanes.sh:197`) does not name `ureq`, so under D90 the workspace acquires an HTTP client the lane cannot see. (2) **It is the only rule in `lane_dep_graph` with no self-test** — P15/D35 (:100), S23 (:154), S6 (:239), P20 rule 1 (:325), rule 3 (:376) and D89 rule 5 (:424) all plant a violation first — so a dropped `^`, a lost alternation bar or a missing trailing space would make it green forever, the exact failure mode those self-tests exist to prevent.
- Do: Extend the pattern at `scripts/ci-lanes.sh:197` with `ureq|ureq-proto|attohttpc|isahc|curl|rustls|native-tls|openssl|webpki-roots|httparse|http` (D90 Decision 5 gives the line verbatim). Insert the two-direction self-test immediately after it: the pattern MUST match a planted `ureq v3.3.0` line in the shape `cargo tree --prefix none` emits, and MUST NOT match `rand_core v0.10.1` — the pinned pure-trait crate the rule deliberately permits, kept out only by the `^rand ` entry's trailing space. Add the **scope comment** D90 Decision 5 supplies, stating in the file that this is a denylist whose green verdict means "none of the named offenders is present", not "the graph is pure" — measured: `libc`, `regex`, `env_logger`, `is-terminal` and `termcolor` pass both the old rule and this extension.
- Accept:
  - Red direction proven for both self-tests: mutate the pattern so it stops matching `ureq`, and separately so it matches `rand_core`; the lane must fail with the respective message each time.
  - `dep-graph` stays green on the real tree with the extended pattern (verified 2026-08-02: no offender in `antseal-core`'s normal graph).
  - Planting `ureq` in `crates/antseal-core/Cargo.toml` turns the lane red naming it — the check is proven to catch the crate D90 actually adopts, not merely to exist.
  - The scope comment is present and names Q74 as the owner of the structural fix, so the next reader is not misled by a rule that reads like a guarantee.
- Notes: **Adjacent to Q74, not a duplicate of it and not blocking on it.** Q74 owns replacing the denylist with a positive allowlist of `antseal-core`'s permitted normal-graph names, which is what would actually discharge A3's Accept row 2. This task is the interim regression guard for the one crate D90 adds plus the missing self-test; if Q74 lands first, the eleven added names are subsumed by its allowlist and this task reduces to the self-test alone. Until Q74 lands, A3 Accept row 2 is **review-enforced**, and D90 §5.3 says so rather than pretending otherwise.

### Q84 — Assert the runtime-flavour invariant the anchor substrate depends on, and make the file that carries it tier-2 visible
- Milestone: M2
- Size: S
- Deps: D90; U36 (the runtime seam); after A3
- Spec: Architecture (lines 52–53); Core user flows (line 34)
- Discovered by: **D90** (2026-08-02) §3.3. D90 makes `antseal-anchor`'s clients blocking, which is what lets A15/U24's hook run in a build with no tokio compiled in. Blocking inside `rt.block_on` is safe **only because** `crates/antseal-cli/src/backend.rs:206` builds `new_multi_thread`: ant-core's spawned tasks progress on worker threads while the main thread sits on a socket. On a `new_current_thread` runtime they would starve, and the symptom would be a seal that hangs or times out far from the cause. The invariant is currently unwritten and unasserted, and a one-word edit would remove it silently.
- Do: Add a test `anchor_blocking_calls_require_a_multi_thread_runtime` beside `runtime()` (feature-gated with the rest of `backend::ant`) asserting `tokio::runtime::Handle::current().runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread` from inside `runtime()?.block_on(...)`. Cross-reference D90 §3.3 in `runtime()`'s doc comment and in `antseal-anchor`'s crate docs, on both sides of the coupling. Add `crates/antseal-cli/src/backend.rs` to `HEAVY_TRIGGER_PATHS` in `scripts/gate-features.sh:88-95`: the file is the sole home of the runtime and the `SealBackend` seam, and today a change to it is classified **light** and compiled by no tier that runs — the same coverage gap D89 Evidence 3 recorded, in the one file whose feature-gated content this decision now depends on.
- Accept:
  - Changing `new_multi_thread` to `new_current_thread` makes the test fail (red direction executed and recorded — the test must be shown to be capable of failing, not merely to pass).
  - `scripts/gate-features.sh` classifies a change touching only `crates/antseal-cli/src/backend.rs` as **heavy**; proven with the script's own dry-run path, and the pre-change classification (**light**) recorded alongside so the fix is a measurement rather than a claim.
  - The doc comments on both sides name each other and D90 §3.3, so neither can be edited in ignorance of the other.
- Notes: Small, and deliberately so — the cost of the invariant being implicit is a hang with no local cause, which is the most expensive class of bug this substrate can produce. The trigger-path half is the more valuable half: it is what makes the test *run* when the file changes.

### Q85 — Make the traceability lane resolve **task** citations, not only decision citations
- Milestone: M2
- Size: S
- Deps: Q66 (the lane and its self-tests), Q57/Q58 (the decision half this mirrors)
- Spec: `TODO.md` adaptation protocol rules 1–2 (statuses live only in TODO.md; discovered work takes the next free ID and gets a row)
- Discovered by: **the wave-5 orchestrator** (2026-08-06), reconciling the wave-4 merge.
- Do: `scripts/check-traceability.py` already has exactly the right mechanism for **decisions**: `check_decisions()` sweeps `crates/`, `docs/format/` and `docs/testing/` for `D<n>` citations, bounds them by `allocated_decision_ids()` read from TODO.md's register, and fails when a cited decision has no record. There is **no equivalent for task IDs**, and the consequence has already happened: seven task IDs (`A56`, `A59`, `A63`, `A67`, `A68`, `A70`, `Q87`) were minted in wave-4 lane briefs, cited in committed source and docs, and given **no row in TODO.md and no entry in `tasks/*.md`** — invisible to every lane, including this one. Add the mirrored check: sweep the same surfaces for `[A-Z][0-9]+` task citations in the nine allocated domains, bound them by the IDs actually registered in TODO.md, and fail naming each unregistered citation. Bound the sweep the same way the decision half is bounded — an unbounded pattern reports `P384`, `U256`, `A5` inside a hash and every curve name in the tree, which is how a lint teaches people to ignore it.
- Accept:
  - The check fails on the current tree **before** the seven rows are added, naming all seven (run it against the pre-fix state to prove it, then again after).
  - A planted citation of a genuinely unallocated ID (e.g. `A99`) in a swept file turns the lane red; removing it turns it green. Both directions executed.
  - False-positive control: `P384`, `U256`, `p384`, `sha1` and the DER/curve identifiers already in the tree do **not** trip it, asserted as a test rather than observed once.
  - The self-test fixtures derive their mutations from the file's current state, per Q66's rule — a fixture that hard-codes a literal goes vacuous the moment the tree moves past it.
- Notes: this is the Q43/Q49 shape one level out — the guard exists, and its sibling was never written. The decision half proves the design works; this is the same twenty lines pointed at the other kind of pointer.

### Q87 — The wasm32 lane can prove *something* ran, but not *what* or *how many*
- Milestone: M2
- Size: S
- Deps: P14 (the runner), Q66
- Spec: Architecture (lines 47–51, WASM-safe core); `docs/wasm-toolchain.md`
- Discovered by: **the A43 lane** (2026-08-03), which had to plant a failure to prove its five wasm32 rows executed at all.
- Do: On `wasm32-unknown-unknown` std's stdout is a discarding sink, so libtest's report is unreadable and `main() == 0` is the only success signal. `scripts/wasm-test-runner.mjs` already closes the worst half of this with a real non-vacuity check: it scans linear memory for an execution witness, asserts it is **absent before** `main()` and **present after**, and fails a green run whose witness is missing with *"the suite ran ZERO tests"*. What it still cannot report is **which** tests ran or **how many** — so a lane that silently drops from 44 rows to 1 stays green, and every task adding wasm32 rows must plant a fault to prove its own rows execute. Recover the count: libtest writes `test <name> ... ` before each body into memory that survives, and the runner already parses those progress lines for the failure path (`postMortem`). Use the same parse on the **success** path to report the executed count and names, and let a caller assert an expected minimum.
- Accept:
  - A successful run prints the executed test count and it matches `cargo test --lib` on native for the same crate — measured, both numbers recorded.
  - Deleting a `#[cfg(target_arch = "wasm32")]` test makes the reported count drop; a lane asserting a minimum goes **red**. Executed, not assumed.
  - The existing witness check is kept, not replaced: the count is a strictly stronger signal but is parsed from memory heuristics, and the witness is the thing that cannot lie.
  - A43's five rows, and A18's 44, are asserted by count rather than by having planted a fault once.
- Notes: correcting the wave-4 note that recorded this as *"the runner discards libtest's count"* — the runner discards libtest's **stdout**; the count is recoverable from the same linear-memory progress lines it already reads to name a failing test. That makes this smaller than it was recorded as being.

### Q92 — Register the O7 row in `MATRIX.json`'s `project_added[]`
- Milestone: M2
- Size: XS
- Deps: D93; **before A81**
- Do: Add the `project_added[]` entry for `anchor-ots-online-block-absent` with the D93 §12 justification (line 168 names it nowhere; its only instrument was measured blind). Re-run the combined distinctness sweep.
- Accept: the sweep is green with the new key; a planted duplicate of an existing key goes red naming both rows.
- Notes: registry-side only — A81 builds the fixture. Ordered before A81 for the same reason Q76 was ordered before A21.

### Q96 — No lane builds the documentation
- Milestone: M2
- Size: S
- Deps: Q1
- Discovered by: **the Q16 lane** (2026-08-06).
- Do: `cargo rustdoc -p antseal-anchor` emits **3 unresolved intra-doc links** and 9 warnings, all pre-existing and all invisible because no CI lane and no local lane builds docs. This codebase navigates by intra-doc link — the review culture leans on rustdoc cross-references as the record of why a thing is the way it is — so a broken link is a broken record, not a cosmetic warning. Add a docs lane (`cargo doc --workspace --no-deps` with `-D rustdoc::broken_intra_doc_links`) and fix the three.
- Accept:
  - The lane is red on the current tree before the three are fixed, and green after — both states recorded.
  - A planted broken link (`[`no::such::item`]`) turns it red naming the file.
  - Minute cost measured and stated; if it is material against the allowance Q78 tracks, say so rather than landing it quietly.

### Q97 — The no-real-network gate covers anchor traffic only
- Milestone: M2
- Size: S
- Deps: Q16
- Discovered by: **the Q16 lane** (2026-08-06).
- Do: Q16's gate sits in `antseal-anchor`'s `HttpClient::attempt`, which is the whole of anchor network I/O. `antseal-net`'s `ant-backend` path (ant-core / evmlib) has **no equivalent chokepoint**, and the devnet gate is loopback **by convention, not by enforcement**. Decide whether the same treatment applies there: either find the one dial site and gate it, or record why the convention suffices — with the reason, not the assertion.
- Accept:
  - Either a gate exists with both directions executed, or a recorded decision says why not and names what would detect a violation instead.
  - If gated, a planted real-endpoint call from a `cfg(test)` build in `antseal-net` is refused before DNS.
- Notes: the honest asymmetry is that `ant-backend` is feature-gated and not in the default CI graph, which is a real mitigation — but "not compiled by the required lane" is exactly the coverage argument D89 and D90 both had to overturn.

### Q98 — Make the HTTP-client rule an allowlist, not a denylist
- Milestone: M2
- Size: S
- Deps: Q16, adjacent to Q74
- Discovered by: **the Q16 lane** (2026-08-06).
- Do: `scripts/check-anchor-net.py`'s R2 rule names HTTP-client crates to forbid. That is the same shape D90 §5 already recorded as insufficient for `dep-graph` — a denylist's green verdict means *"none of the named offenders is present"*, never *"nothing here opens a socket"*, and `libc`, `regex` and `env_logger` all pass the existing one. Replace it with a positive rule: the set of crates permitted to open sockets, asserted by set equality, with the same scope comment Q74/Q83 carry.
- Accept:
  - A crate that opens sockets and is on no denylist (the case a denylist cannot catch) is caught — planted and executed.
  - Set equality against a reviewed list, with a stated scope note that green is not a purity proof.
- Notes: Q74 owns the same conversion for `core-dep-graph`. If Q74 lands first this reduces to reusing its mechanism; the two should not grow two different allowlist implementations.

### Q99 — Commit the real-smoke runbook's script half and delete its §0
- Milestone: M2
- Size: S
- Deps: Q16, U22, A25
- Discovered by: **the Q16 lane** (2026-08-06).
- Do: `docs/anchors/real-smoke-runbook.md` §0 records that the protocol is **not executable end-to-end today**, because the CLI still cannot anchor. When U22 wires the gate into `seal` and A25 executes the protocol, commit the script half the runbook describes and delete §0. A caveat section that outlives its cause is how a document starts lying.
- Accept:
  - §0 is deleted in the same change that commits the script, never before.
  - The script runs the protocol A25 executed, against real endpoints, and is excluded from every gating lane (Q16's policy holds: it must be un-runnable under `ANTSEAL_NO_REAL_ANCHOR_NETWORK`).
  - Real-endpoint execution requires express maintainer consent in-session; the runbook says so.

### Q101 — The doc-pointer sweep does not cover the documents that cite tests most
- Milestone: M2
- Size: S
- Deps: Q69 (the sweep), Q70 (which widens it to other crates)
- Discovered by: **the core lane** (2026-08-06).
- Do: Q69's dangling-pointer sweep covers `crates/antseal-core/src/` and `tests/`. It caught two dead test names the A80 lane wrote and **missed the one that landed in `docs/decisions/D56-…` §9**, because decision docs are outside its scope. Decision documents cite test names routinely — D56 §9 alone specifies ~22 — and a renamed test leaves them silently wrong for ever, which is precisely the "recorded claim the code does not implement" class this project's reviews keep finding. Widen the sweep to `docs/decisions/` and `tasks/`, or rule explicitly that prose there is not a pointer and mark it so.
- Accept:
  - The sweep is red on a planted dangling test name in a decision doc, green when it resolves — both executed.
  - If the ruling is "not a pointer", the convention is stated in the decisions README and the existing citations are left alone deliberately rather than by omission.
- Notes: the D56 §9 pointer this found was repaired by hand at integration; the point of the task is that nothing would have caught the next one.

### Q107 — Name the three kinds of pinned-artifact change
- Milestone: M2
- Size: XS
- Deps: R12 (D94)
- Do: the tree has words for *format event* and for *target divergence*, and none for the case D94 ruled on — a **verdict event**, where a recomputed value moves under a format that did not change. Add the three-class vocabulary (FORMAT / VERDICT / FIXTURE) to `testdata/vectors/README.md` and to Q27's procedure, with D94's four distinguishing measurements: how many vector cases moved, how many in-tree pins moved, how many freeze digests moved, and how many **bundle** digests moved — the last being the one that separates a verdict event from a format event.
- Accept: a future re-emit is classified by running the four measurements, not by argument; the vocabulary is identical in both files.

### Q108 — A vector's `pins` prose is compared only against the const that generated it
- Milestone: M2
- Size: S
- Deps: R12 (D94)
- Do: `report_vectors.rs`'s regeneration test compares the committed document against what the code computes — but a case's `pins` sentence lives in `inputs`, which the comparison never reaches, and the only thing it is checked against is the same const that produced it. So a description can be **green on both sides and false**, in a frozen file, for ever. `"each an absent M0 slot"` is about to become exactly that. Either derive the prose from the data it describes, or assert it against the data.
- Accept: a planted false `pins` sentence turns the lane red; the existing sentences are re-checked against their cases rather than assumed.

### Q109 — A22's anchor vectors have two specified homes and only one of them is frozen
- Milestone: M2
- Size: S
- Deps: before A22 (D94)
- Do: A22's Accept says vectors land under `testdata/anchors/` **and** that they are retained forever in CI per the format-stability policy, verified bit-identically on wasm32. Those properties belong to the reserved `anchor` **vector kind** under `testdata/vectors/`, not to `testdata/anchors/` — which is A25's capture area and is covered by no freeze, no retention rule and no wasm parity lane. A22 Accept rows 1 and 2 depend on the distinction. Rule which home A22 uses before it starts.
- Accept: the ruling is in A22's entry before A22 begins; if the vector kind is chosen, its append is legal-forever and needs no re-emit of R9's document.
- **Count dropped 2026-08-09 (D103 §7.2, RULING 6a).** The sentence above read: *"Three of A22's four Accept rows depend on the distinction."* A22 had **three** Accept rows, not four — the fourth was an artefact of splitting row 1's semicolon, the same compound-row expansion D53 caught on A21 and this row re-derived silently. The count was wrong in three committed places at once (`tasks/Q.md` here, `D94:554-555`, `TODO.md`'s Q109 row), so it is **dropped** rather than corrected to three: D101 §2.2's own fallback, taken. A22's Accept is now explicitly numbered 1–4 (D103 §7.1), which is what makes a citation by number stable; rows 1 and 2 are the home row and the freeze-and-retention row. **`D94:554-555` still reads *"three of A22's four Accept rows"* and is not corrected — a ruled record is immutable; the drift is recorded here.**

### Q110 — Sweep for prose that predicts a future test failure
- Milestone: M2
- Size: S
- Deps: R67 (D94)
- Do: five committed places asserted that one named test would go red when R12 landed. All five were wrong simultaneously, because nothing compares a prediction to the thing predicted. Sweep the tree for the pattern — *"this will fail when X lands"*, *"invert this at X"*, *"X replaces this stub"* — and for each either bind it to a mechanism that fires, or delete it. A prediction nothing checks is a claim that ages into a lie, which is this project's dominant defect class stated in the future tense.
- Accept: every surviving prediction names the task that will falsify it and is reachable from that task's entry; the sweep is repeatable as a script or recorded as a one-off with its date.

### Q111 — `printf | grep -q` under `pipefail` inverts its own verdict
- Milestone: M2
- Size: S
- Deps: Q43 (every CI `run:` block calls a committed script)
- Discovered by: **CI run 31086210534** (2026-08-06), where it reddened `core-dep-graph` on a self-test that had passed locally for days.
- Problem: `scripts/*.sh` run under `set -uo pipefail`. In `printf '%s\n' "$var" | grep -q PATTERN`, `grep -q` exits the instant it matches and closes the read end; bash's `printf` builtin flushes through stdio in ~4–8 KiB chunks, so on a payload of more than a few KiB its next write gets `EPIPE`; `pipefail` then makes the **pipeline's** status the failing `printf`'s. The result is that the idiom reports **"no match" exactly when the match is found early** — the guard inverts. It is timing-dependent, which is why the P20 self-test was green on this host (38 KB payload, printf wins) and red on the runner. Demonstrated deterministically: with an 8.4 MB payload whose match is on **line 1**, the old form reports NO MATCH and the herestring form reports MATCH.
- Do: 32 sites were converted to `grep -q PATTERN <<<"$var"` (a herestring is a temp file — no pipe, no EPIPE). Every `printf | grep -q` left in the tree is safe **only because its payload is a small literal**, which is a property a future edit can silently remove. Add a lint (a `ci-shell` rule, since that lane already parses these scripts) forbidding `printf … | grep -q` in any script that sets `pipefail`, with the herestring named as the fix.
- Accept:
  - The lint is red on a planted `printf '%s' "$var" | grep -q x` and green on the converted form; both directions executed.
  - The lint's own payload-size blindness is stated: it forbids the shape rather than trying to judge whether a given payload is large enough to race, because that judgement is exactly what was wrong before.
- Notes: this is the third CI defect this project has had, and like the other two it was in shell rather than in Rust. Unlike them it was in a *committed script*, so Q43's rule ("call a committed script, don't inline YAML") did not protect against it — worth recording, because Q43 is cited as though it closes this class.

### Q112 — The tier-2 compile gate does not trigger on the files that hold tier-2 code
- Milestone: M2
- Size: S
- Deps: Q84 (which fixed this for `backend.rs`), D89 (which established the argument)
- Discovered by: **the full local gate** (2026-08-06), on the second attempt — the first gate run of the wave classified this lane **n/a**.
- Problem: U22 landed a change that **does not compile under `--features ant-backend`**, and every gate that ran was green. `commands.rs`'s `seal_over_backend` takes `config: &crate::config::Config` and then binds `let config = NetworkConfig::select(...)`, **shadowing the parameter**; U22 added `AnchorStageConfig::from_config(config)` below that, which therefore received a `NetworkConfig`. Rust caught it instantly — under the feature. Nothing ran under the feature: required CI is `--workspace --locked` with no `--features` (D89's finding, verbatim), and `scripts/gate-features.sh`'s `HEAVY_TRIGGER_PATHS` names neither `crates/antseal-cli/src/commands.rs` nor `crates/antseal-cli/src/seal_run.rs`, so a wave that edited both was classified *"no storage-touching path changed"*. Q84 added `backend.rs` to those paths for exactly this reason; `commands.rs` is its sibling and holds the other half of the `#[cfg(feature = "ant-backend")]` surface.
- Do: add `crates/antseal-cli/src/commands.rs` and `crates/antseal-cli/src/seal_run.rs` to `HEAVY_TRIGGER_PATHS`, with the light→heavy classification measured before and after the way Q84 did it. Then consider the deeper fix: the trigger list is a hand-maintained denylist-by-omission, and the property that actually matters is *"this file contains `#[cfg(feature = ...)]` code for a gated feature"*, which is derivable. A derived list cannot go stale when a new file grows a `cfg`.
- Accept:
  - A change touching only `commands.rs` classifies **heavy**; the pre-change classification (**light**) is recorded alongside, so the fix is a measurement rather than a claim.
  - The shadowing defect is a regression test or a lint: `cargo clippy -- -W clippy::shadow_unrelated` on this crate, or a targeted test, so a re-shadow does not silently retype an argument again.
  - If the derived-list option is taken, a planted new gated file is picked up without editing the list.
- Notes: three separate mechanisms were supposed to prevent exactly this — D89's coverage argument, Q84's trigger paths, and the heavy tier itself — and it still shipped, because each was scoped to the file that was in front of it at the time.

### Q113 — The machine-interface snapshot cannot be green under both feature sets
- Milestone: M2
- Size: S
- Deps: Q112 (which is why nobody saw it)
- Discovered by: **the full local gate** (2026-08-06), running the heavy tier for the first time in the wave.
- Problem: `crates/antseal-cli/tests/snapshots/json-envelopes.txt` pins the `--json` error envelopes. Two of them — `seal` and `restore` — render `backend::unavailable`'s message, which differs **by `cfg` on purpose**: without the feature it says *"this build has no storage backend compiled in"*, with it *"has a storage backend compiled in but this command is not yet wired to it"*. Only the default-features variant is committed, so `cargo test -p antseal-cli --features ant-backend --test machine_mode` fails on drift **by construction**, and blessing it under the feature breaks the default build instead. **Verified pre-existing**: the cfg-dependent message is present at the wave-4 head, so this has been true for as long as the heavy tier has existed — it was simply never run (Q112).
- Do: pick one. (a) Commit a per-feature fixture and have the harness select by `cfg`, which keeps both texts pinned and is the honest option since both are user-visible. (b) Normalise the cfg-dependent clause in the harness before comparison, which keeps one fixture but stops pinning the very text that differs. (a) is preferred unless the second text is judged not worth pinning, in which case say so.
- Accept:
  - `cargo test -p antseal-cli --test machine_mode` and the same with `--features ant-backend` are **both** green, and both are run by a lane.
  - Changing either message reddens the corresponding fixture — planted and executed in both feature sets, since a fixture that only one build checks is half a fixture.
- Notes: the `seal` variant's text is now also **stale under the feature** — it says connecting the command "lands with U13", and U22 has since wired it. Whichever option is taken, that sentence needs rewriting; it is the kind of message that ages into a false statement precisely because no green run ever renders it.

### Q114 — `vector-freeze.sh` only knew two of D94's three classes, and refused the one D94 authorised
- Milestone: M2
- Size: S
- Deps: D94; R12
- Discovered by: **executing D94 §4 step 5** (2026-08-06). D94 wrote *"`./scripts/vector-freeze.sh --update` — REQUIRED. Exactly one digest line moves"* and the script refused outright: *"After Q14 the only legal change is an addition; a byte change needs a new format version."*
- Problem: D94 Ruling 4 created the VERDICT EVENT class and said the three classes are told apart **mechanically, not editorially** — but the only mechanism in the tree implemented the two-class world the ruling replaced. A record that authorises something its own enforcement refuses is a record the next lane works around, and the obvious workaround (hand-editing `FROZEN.sha256`) discards the ceremony D94 §2a explicitly kept.
- Do: add `--verdict-event <Dnn>`, and make it **checked rather than trusted** — a flag that merely asserted the classification would be the editorial version with an extra step. The flag unlocks a check that re-derives the class from the diff against `HEAD` and refuses if it does not hold: only a `report/` kind vector may move; `bundle_len`/`bundle_sha256`/`revealed_unit_ids` byte-identical on every case (else FIXTURE EVENT); `report_version` unchanged (else FORMAT EVENT); at least one case unchanged (a format event moves all of them, which is what R32 measured at `report_version` 0 → 1). The check prints the four numbers D94's commit-message rule requires, so the audit record is produced by the guard rather than typed by the person it guards against.
- Accept: **landed 2026-08-06.** Default `--update` still refuses a frozen byte change with the three-class explanation. The guard was shown red on all three wrong classifications before being trusted to permit the right one — a moved `bundle_sha256`, all 21 cases moved, and a non-`report` vector each refused with their own cause. R12's real update printed *"1 of 21 report cases moved (cases [19]); 0 bundle digests moved; report_version unchanged"*.
- Notes: Q107 owns the same vocabulary on the **documentation** side (`testdata/vectors/README.md`'s "What changes at Q14" table and Q27's policy); this is its enforcement counterpart, and the two must not disagree. The script's closing line said *"a changed (not added) digest is a format event"* — corrected in the same edit, since it was a seventh copy of the two-class claim.

### Q115 — The wasm32 lane's warnings are invisible

- Milestone: M2
- Size: XS
- Deps: P14 (the wasm32 lane), Q1 (CI)
- Do: `cargo test -p antseal-core --lib --target wasm32-unknown-unknown`
  currently emits `unused import: error::all_code_exemplars`
  (`crates/antseal-core/src/anchor/ots/mod.rs:70`) and the lane stays green.
  The import is used by `error_universe` and `tamper_coverage`, neither of
  which compiles on the wasm32 dev edge (`test-vectors` only), so on that
  target it really is unused. The finding is not the import — it is that
  **`wasm32-core-tests` runs `cargo test`, not clippy**, so no warning on
  that target can fail anything, and a target-specific `unused`/`dead_code`
  regression can accumulate silently. Decide between: adding `-D warnings`
  to the lane (and fixing whatever it surfaces), or gating the import so the
  warning is genuinely absent rather than merely tolerated. Prefer the
  first: the second fixes one instance of a class.
- Accept:
  - The wasm32 lane is warning-clean, and a planted warning turns it red
    (self-test, the pattern every other lane in this tree uses).
  - Whichever route is taken, the reason is recorded — a `#[cfg]` that
    silences a warning without explaining which lane could not see it is
    the same defect one layer down.
- Notes: Pre-existing; observed 2026-08-06 by A21's lane while running the
  wasm32 suite for the tamper rows, and unrelated to that work. Recorded by
  D96 §Discovered work.

### Q116 — The `strict v1 schema` needles carry a version number
- Milestone: M2
- Size: XS
- Deps: D97 R9
- Discovered by: **D97 R9** (2026-08-06).
- Problem: two committed assertions match error strings containing the literal `v1` — the anchor-record needle in `pipeline/anchors/tests.rs` and its twin at `journal.rs:401`. Every future `SEAL_JOURNAL_VERSION` bump silently invalidates them, and the cheapest repair on the day of the bump is to edit the needle, which is how an assertion quietly stops asserting anything. The counter-example is in the same file: `a_future_version_refuses_distinctly` needs no edit at a bump, because it is written **against the constant** — which is the shape the other two should have had.
- Do: drop the version token from both messages, or assert them against the constant.
- Accept: a bump requires no edit to either needle.
- Notes: **partly discharged 2026-08-07** by the D97 foundation lane, which landed the journal-version bump: the anchor needle now reads `(strict schema)`. The `journal.rs:401` copy remains, and this row stays open for it — the half that was discharged is the half whose bump was already in flight, which is exactly the half a bump-driven repair would have caught anyway.

### Q117 — `commands.rs`'s `list` rationale names a failure mode the lock cannot produce
- Milestone: M2
- Size: XS
- Deps: none
- Discovered by: **D99 §1.2** (2026-08-06).
- Problem: `commands.rs:297-305` justifies `list`'s lock-free read by saying that taking the lock would make `list` *"the one command that hangs"*. `VaultLock::acquire` is a **try-lock**: under contention `list` would **fail** with `VaultLockHeld`, exit 15 — not hang. The conclusion is unchanged and D99 R3 reaffirms it (and after U24 it is the **hook**, not `list`, that takes the lock — late, and declining silently when contended), but the recorded rationale describes a mechanism the code does not have, and a future reader reasoning from it will reason wrongly about every other command's lock cost too.
- Do: correct the sentence to name the real cost.
- Accept: the doc names `VaultLockHeld`/exit 15; the decision to stay lock-free is unchanged.
- Notes: D99 §9 files this as **Q118**; reconciled to Q117 at bookkeeping, where three lanes' overlapping id blocks were resolved.

### Q118 — Routes to the binary that an enumeration rule cannot see
- Milestone: M2
- Size: S
- Deps: Q16, U24; D99 R4, D99 §8
- Discovered by: **the D99 R4 lane** (2026-08-07), while landing the rule the finding is about.
- Problem: D99 R4.3 specifies a static rule — the only construction naming `CARGO_BIN_EXE_antseal` in the workspace lives in the spawn helper, and that helper sets `ANTSEAL_NO_REAL_ANCHOR_NETWORK`. Landing it found two routes to the shipped binary the rule **as specified** could not see.
  - `e2e_restore.rs`'s `run_clean_machine` re-executes the test binary with `.env_clear()`, which strips the arming **even in CI**, and it never names `CARGO_BIN_EXE_antseal` at all — so the rule as written would have missed it entirely. It was fixed, and `env_clear()` became R4's **fourth arm**.
  - `option_env!("CARGO_BIN_EXE_antseal")` is a second spelling of the same reach. The landed regex covers it, but **no test names it**, so that coverage is incidental rather than asserted, and the next edit to the regex can remove it without anything going red.
  This is D99 §8's own revisit trigger arriving before the ink dried: the rule refuses the shapes it enumerates, and the venue that reaches the binary by a route nobody enumerated is precisely the one that matters. The premise is not hypothetical — the same lane measured that a bare `cargo test -p antseal-cli` **reached freetsa.org**, completing DNS, TCP and TLS and taking a real 403 from its nginx in 0.83 s.
- Do: enumerate the property — *"this reaches the shipped binary"* — rather than the macro spelling. Add a planted-fault case for the `option_env!` form so its coverage is asserted, and decide whether an environment-clearing re-exec can be refused **structurally** rather than by a named arm; a fifth arm per newly discovered route is the shape this task exists to escape.
- Accept:
  - A planted `option_env!` construction reddens the rule by name, and a planted `env_clear()` without re-arming reddens; both directions executed, as R4's other arms already are.
  - What the rule still cannot see is recorded beside it — D99 §8 already concedes that a new crate driving the hook by an unforeseen route is out of reach of a static check, and the runtime gate remains the only thing that fails a call.

### Q119 — A `secret_hygiene.rs` flake that is not attributable
- Milestone: M2
- Size: XS
- Deps: U21
- Discovered by: **the D99 R4 lane** (2026-08-07).
- Problem: `secret_hygiene.rs` failed once on its first run of the wave — 9 passed, 1 failed — and **could not be attributed**. A/B measured on this host: after the change, five further passes including runs under deliberate 2-core load; before the change, at `HEAD`, three of three under the same load. The suite polls `/proc` and is timing-sensitive, which is the mechanism a flake of this shape would have, but **the specific failing test was not identified**, so this row records an observation and not a diagnosis.
- Do: make the `/proc` polling insensitive to scheduling, or make its failure name what it timed out waiting for, so that a second occurrence is attributable in one run instead of costing another A/B. A hygiene suite that flakes is worse than most flakes: its red means *"a secret escaped"*, and a reader who has seen it flake will discount the one time it is right.
- Accept: the polling has a stated bound and a failure message naming the process and the field it was waiting on; a deliberately slowed child produces that message rather than a bare assertion failure.
- Notes: not reproduced since. Recorded now so that a second occurrence is a second data point rather than another first one.

### Q120 — D98 rider 3c is honoured by `status` and unenforced across surfaces
- Milestone: M2
- Size: S
- Deps: U23, U25; D98 rider 3c
- Discovered by: **the U23 lane** (2026-08-07).
- Problem: D98 rider 3c names three predicates that share the word UNANCHORED and rules that they must not be collapsed — `WorkRow.unanchored` is the `--no-anchor` shaping flag, `NagState::Unanchored` means *"no anchors at all"*, and MVP-SPEC.md line 137's UNANCHORED means *"zero headline-eligible anchors"*. `status` computes the spec's version, as ruled. `list` badges off `WorkRow.unanchored`. The nag reads `NagState`. **U23's fixture work 3 makes the disagreement concrete**: one work, all three predicates answering differently, each correctly by its own definition. The ruling is honoured at the one surface that was being built and is enforced at none — nothing mechanically stops a fourth reader picking whichever predicate is nearest to hand, which is how the three become interchangeable in a reader's memory and then in the code.
- Do: give the spec's predicate a name and a single home, so a surface that wants *"zero headline-eligible anchors"* cannot spell it as either of the other two by accident, and so the two that are **not** the spec's say what they are at their own definition.
- Accept: each of the three predicates is reachable by a name that states which question it answers; a test pins work 3's three different answers, so a future collapse of any two of them reddens.
- Notes: revisit trigger is **R18/R22** — M3's authoritative wording set is where this either becomes one word with three qualifiers or three words, and D98 already flags rider 1b's marker as owing the same surfaces.
- **Closed 2026-08-09, and this row's own fixture turned out unable to discharge its own Accept.** `status_command.rs::the_three_unanchored_predicates_answer_three_questions_and_may_not_collapse` reads `list`'s row and `status`'s report off **one vault**. On U23's work 3 the three predicates measure (a) `false`, (b) `AttestedOnly`, (c) `true` — three different answers, which is what made the row look sufficient. It is not: **(a) and (b) both answer *"not unanchored"* on work 3**, so rewriting `WorkRow.unanchored` to `nag == Unanchored` would have collapsed exactly that pair and stayed green. Separating them needed a **sixth work** — a `--force-degraded` seal that obtained no anchors (`evaluate_seal_gate` → `ProceedDegraded` from a `None` submission), journaled by the test alone so `status-report.txt` is untouched. The generalisable finding: *"the three answers differ on some work"* is a weaker property than *"no two of the three are the same function"*, and only the second is what rider 3c forbids.
- **The prohibition is asserted as functional dependence over all six rows, not as a table of constants.** A table of expected values is re-blessable — a lane that collapses two predicates can update the table and stay green — and it is blind to a **negated** collapse: the fourth planted fault, `is_unanchored() { !self.anchors.is_empty() }`, disagrees with (b) on **every** row and would pass any *"they differ somewhere"* check. Asserting that no column is a function of another catches it, and did. Four planted faults, all red. Also landed: `list_command.rs`'s *"three predicates, three answers"* comment asserted two of the three and now computes the third; **two `NagState` variant docs defined themselves as the wrong predicate** — `Unanchored` read *"No anchors at all: the `--no-anchor` seal"*, which is predicate (b) written as predicate (a), rider 3c's own collapse at doc level, and `AttestedOnly`'s *"every OTS anchor is already attested"* is false for work 3, whose OTS is neither attested nor pending. The recon's `engine.rs:616` drift claim was **rejected as false** (*"four different meanings"* is correct — four of five states do not nag; the stale `three` was `listing.rs`'s quotation of it). Renames are **deferred, not skipped**: `NagState::name()` emits the wire string `"unanchored"` and `json-envelopes.txt` carries three senses of the word, so re-recording is blocked by **Q113**, and `AttestedOnly`'s over-claiming name rides the R18/R22 revisit. A **fourth** sense of the word, in frozen normative text, is **Q129**.

### Q121 — A test whose vehicle is "a still-unimplemented command" breaks every time a handler lands
- Milestone: M2
- Size: XS
- Deps: U19, U23, U24; before U27
- Discovered by: **the U24 lane** (2026-08-07), on this test's second migration.
- Problem: `config_file.rs::binary_resolves_network_through_the_config` needs a command that reaches config resolution and then stops, so it picks one that is **still a stub** — and a stub is by definition the thing the next wave removes. It has now migrated twice: `list` → `status` at U19, `status` → `show` at U24. It will break again at U27, and the repair each time is to hunt for the next stub, which reproduces the defect rather than closing it.
- Do: derive the vehicle instead of naming it — `machine::ALL_COMMAND_NAMES` minus the implemented set yields the current stub without a lane having to notice — or remove the vehicle question entirely by asserting the envelope's `network` field rather than pinning an exit code, since network resolution is what the test is about and the exit code is only how it currently observes it.
- Accept: landing a handler for any command requires no edit to this test; the property it asserts — that config resolves the network before the command's own failure — is still red when that resolution is broken.
- Notes: U19's execution note 8 recorded the same shape for four sibling suites (`cli_surface`, `exit_codes`, `config_file`, and `machine_mode`'s abort table each used `list` as their *"a stub command"* exemplar) and re-pointed each at a still-stubbed command — which re-armed the defect rather than disarming it. This is the instance that has been re-pointed twice since and is therefore the one worth giving a derived vehicle first.

### Q125 — The local gate compiles for `wasm32` and never runs the wasm32 tests
- Milestone: M2
- Size: S
- Deps: none
- Discovered by: **CI run 31251119065** (2026-08-08).
- Problem: `scripts/local-gate.sh`'s `wasm32` lane is `cargo build -p antseal-core --target wasm32-unknown-unknown`. The lane that *executes* wasm32 tests is `scripts/wasm-tests.sh --check`, and only CI runs it. So a green local gate plus a green native `cargo test` — the exact pair wave 9 verified on — **structurally cannot** catch an architecture-dependent assertion, and did not: `size_of::<x509_cert::Certificate>()` is **376 on wasm32 against 512 on x86-64**, and two new equality rows in `caps.rs` reddened `wasm32-core-tests` at `6f69e1a`. The gate printed `wasm32 PASS`, which is exactly how it was read.
- Do: either fold `wasm-tests.sh --check` into the gate, or make the gate say out loud that its wasm32 lane is compile-only, so the next lane does not read `wasm32 PASS` as *"the wasm32 tests pass"*. Note the sibling asymmetry: `heavy-features` already carries a spelled-out n/a state for the same class of reason.
- Accept: either the executing lane runs locally, or the gate's own output distinguishes "compiled for wasm32" from "tested on wasm32"; and the sentence claiming the gate runs the lanes CI enforces is true of whatever lands.
- **DONE 2026-08-09 — both halves, plus the sentence that licensed the misreading.** The compile lane is now named `wasm32-build`, and its name says what it does. A new **diff-triggered `wasm32-tests` lane** runs `scripts/wasm-tests.sh --check` on the `heavy-features` pattern: `--needs-run` decides from the diff (`ANTSEAL_GATE_BASE`; `ANTSEAL_GATE_WASM=1/0` forces; exit 2 is a **visible SKIP**, never a silent one). Validated **rc 0 against `6f69e1a` in a detached worktree at that commit** — all seven `antseal-core` files selected, `caps.rs` among them, so the trigger demonstrably fires on the change that caused the red — and rc 1 against wave 8's 49-file `09a81c2`. `--self-test` gained planted change-sets in **both** directions, with the positive arm pinned to `anchor/caps.rs` **by name**, and it **runs unconditionally before the trigger**: behind the trigger, a path list that stopped matching `crates/antseal-core/` would render `n/a` for ever and silence its own guard. `local-gate.sh:2`'s *"the same lanes CI enforces"* now enumerates the contexts a green gate does **not** reproduce, and four `feature_pins.rs` arms pin the wiring, each shown red before it was trusted.
- **The cost figure that kept the executing lane out of the gate was unsourced, and its stated cause was wrong too.** Measured here: **3 m 42 s cold, 2 m 10 s warm**, of which **2 m 15 s is node *executing*** the PQC suite in a 1.3 GB linear memory — the compile is cached at **0.31 s**. So no cache and no build tuning shrinks it; the runtime *is* the cost, which is why the answer is a diff trigger and not a `run` line. Any future argument about this lane's price must start from the execution number, not from a build number.
- Notes: **`wasm-bitmatch` stays out deliberately, and not for cost** — measured 32 s plus 53 s of self-test, *cheaper* than this lane. Its `build.rs` walks `testdata/vectors/`, which is the one path this trigger must **not** match, so folding it under the same predicate would install a lane that silently never fires for its most important input. It needs its own predicate → **Q128**.

### Q126 — The F4 registry's changelog has never recorded anything
- Milestone: M2
- Size: S
- Deps: after A27 (D104 §5)
- Discovered by: **the D104 lane** (2026-08-09).
- Problem: `docs/format/anchor-artifact-limits.md` §6 Changelog has taken **zero entries across seven document-changing commits** — measured, `git log --oneline 1620543..HEAD -- docs/format/anchor-artifact-limits.md` returns seven. It is not missing an entry; it has never been used. That matters because §5's Update rule routes F4's auditability *through* it: *"a dated note in §6 saying which release lowered it and why"* is the evidence step that makes *"has this ever been lowered?"* answerable from the tree, and it depends on a section with a 100 % miss rate.
- Do: either enforce §6 with a lint of the `--freeze-boundary` shape, or delete it and move the lowering note into the `lowered` cell itself, where the reader already looks. Do **not** write seven retrospective entries: a changelog composed by lanes that did not make the edits is fabricated provenance, which this project refuses elsewhere.
- Accept: a document-changing commit that owes a §6 entry cannot land without one, or §6 does not exist and the `lowered` cell carries the history; either way the question *"has this ever been lowered?"* is answerable without reading seven diffs.
- Notes: this conditions the `MAX_OTS_DEPTH` lowering window **D104 left open** — whoever exercises that window closes this row first, or the ceremony §5's Update rule prescribes produces an entry in a section nothing maintains. It is **not A106's** (scoped to two provenance citations) and **not Q64's** (the F1–F4 mirror lint).

### Q127 — Report enums are not enumerable, so a value can land unexercised
- Milestone: M2
- Size: S
- Deps: after R69 (D105 §6)
- Discovered by: **the D105 planner** (2026-08-09).
- Problem: nothing enforces *"a new value in report v1's value space must be exercised by a committed assertion"*. R69 was that gap, and it was found by inspection rather than by a red lane — `SupportingEvidenceResult::ArbitrumReceipt` shipped post-freeze, legally, with **nothing rendering it inside a whole report**. Of the report's five enums only `AnchorState` is immune, and for an unrelated reason: it has a `const ALL`, a wildcard-free `wire_name` match, and a sweep over `ALL` that asserts the serialized spelling, so an eighth state is a **compile error**. `SignatureScheme`, `AnchorKind`, `StorageLinkageResult` and `SupportingEvidenceResult` have none of that; their coverage is *incidental*, holding only because some fixture happens to render the value.
- Do: give the other four the triple `AnchorState` already has — `const ALL`, a wildcard-free spelling accessor, a sweep over `ALL` asserting the serialized bytes — so a variant that is named and never rendered reddens on the day it is named. `SupportingEvidenceResult` needs a hand-written arm for its struct variant; the point is that the sweep is **exhaustive**, not that it is uniform. Then state **R-VAL** (*every value report v1 can serialize is exercised by a committed assertion that renders it inside a whole canonical report*) wherever the report's format discipline is written, so the "in composition" half has a home rather than living only in R69's snapshot.
- Accept: adding a variant to any report enum without rendering it is a compile error or a red test, not a silent value addition; the four enums' `ALL` arrays are swept; and R-VAL is written down where a lane adding a variant will read it.
- Notes: the shape worth carrying is D105 §4.3's — **zero moved pins is a correct *format* signal and an empty *coverage* signal, and the tree has no second signal.** A value addition nothing emits moves zero pins; a format event moves all 21 report cases and all 26 `REPORT_DIGEST_BY_SHAPE` rows. That is why `arbitrum-receipt` shipped with nothing red and nothing wrong, and why the pin count cannot be the instrument here. **Not Q120**: Q120 is cross-surface agreement between `list`, `status` and `WorkRecord` on UNANCHORED; this is the report's own value space being a checkable set. Do not merge them. Adjacent and not ruled: **R70**, the converse gap (a value report v1 carries that the pipeline may no longer produce), which this work would make visible. Also recorded by D105 §6 and **not edited into its owner**: D94's three-class vocabulary has **no class for adding a case to a frozen report document**, and **Q107** as scoped only splits the existing row into the three classes rather than adding a fourth.

### Q128 — `wasm-bitmatch` is Q125's defect one file over
- Milestone: M2
- Size: S
- Deps: after Q125
- Discovered by: **the Q125 lane** (2026-08-09).
- Problem: `wasm-bitmatch` is a second wasm32-**execution** lane that the local gate does not run, carried only as a CONTRIBUTING checkbox. Q125 closed the `wasm32-tests` half and deliberately left this one out — **not for cost**: measured **32 s plus 53 s of self-test**, *cheaper* than the lane that did land. The reason is the trigger. `crates/wasm-bitmatch/build.rs` walks `testdata/vectors/` by design (*"no hardcoded file lists"*), so a **vectors-only change is its mandatory case** — and that is precisely the case Q125's `--needs-run` predicate must not match, since matching it would fire the expensive PQC lane on every vector edit. Folding this lane under that predicate would install a gate that silently never runs for its most important input.
- Do: give it its own predicate, keyed on `testdata/vectors/` and on the harness itself, with its own planted change-sets in both directions — the positive arm pinned to a vector file by name, the way Q125's is pinned to `anchor/caps.rs`.
- Accept: a vectors-only change fires this lane locally; a change that touches neither vectors nor the harness skips it visibly, not silently; and the self-test runs unconditionally before the trigger, so a path list that stops matching cannot render `n/a` for ever.
- Notes: A22 is the worked example of why this matters — it added a whole vector kind, and the lane that certifies native↔wasm32 byte-identity over it is the one the local gate does not run.

### Q129 — A fourth sense of UNANCHORED, in frozen normative text
- Milestone: M2
- Size: XS
- Deps: after Q120
- Discovered by: **the Q120 lane** (2026-08-09).
- Problem: `docs/format/registry-v1.md:664` says *"an UNANCHORED bundle is **both** anchor arrays empty"*. That is `NagState::Unanchored`'s **artifact-presence** sense wearing the spec's name: a bundle holding one pending OTS anchor is **MVP-SPEC.md:137's** UNANCHORED — zero *headline-eligible* anchors — and is not this one. D98 rider 3c already forbids collapsing the three predicates Q120 separated; this is a fourth spelling of the word, in normative text, saying the wrong one.
- Do: decide whether the sentence is corrected, annotated, or kept as a **scoped term of art** for the wire schema — and if it is kept, say at the line that it is the array-emptiness sense and not line 137's. Note the cost before choosing: the file is SHA-256-pinned by `scripts/format-freeze.sh`, so correcting it is a **format-freeze event**, not a drive-by edit.
- Accept: the registry line either states the spec's predicate or names which of the four senses it means; the decision is recorded with its freeze cost either way.
- Notes: this is the one instance of the word Q120 could not reach — Q120's mechanism is a test over `list`, `status` and `WorkRecord`, and a frozen document is outside it. The renames Q120 deferred are blocked by **Q113** (`NagState::name()` emits the wire string `"unanchored"`, and `json-envelopes.txt` carries three senses of the word); this row is blocked by a different mechanism, which is why it is separate.

### Q131 — The registry's two prose surfaces are never compared
- Milestone: M2
- Size: S
- Deps: after Q129 (D108 §1.6)
- Discovered by: **the D108 lane** (2026-08-09).
- Problem: `docs/format/registry-v1.md` and `docs/format/registry-v1.json` state the same facts twice, and `crates/antseal-core/tests/format_registry_freeze.rs`'s D-family ("document ⟷ mirror") cross-checks only the *mechanical* half — keys, field names, presence, reserved slots, bands, enums, scalar lengths, tuple arities, caps. The `.md`'s `len/shape` cells and the `.json`'s `notes` fields are compared **to nothing, in either direction**: `the_document_map_tables_match_the_mirror` reads `cells[0]`, `cells[1]` and `cells[3]` and asserts `cells.len() == 5`, so `cells[4]` — the prose — is never read. §7.6 key 3 is the measured instance: the two copies of one claim differ in wording (the `.json` drops the emphasis and adds a clause). Both files are SHA-256-pinned, so a divergence is **frozen in place** rather than caught, and Q129 had to be resolved as an erratum against *two* sites precisely because nothing had noticed they were two.
- Do: add a **closed-vocabulary** cross-check to the D-family: a short list of load-bearing terms — `UNANCHORED`, `reserved`, `may be empty`, the tier letters `[P]`/`[X]`/`[R]` — which, if present in one surface's prose for a given key, must be present in the other's. Pin *terms*, not wording.
- Accept: the two prose surfaces cannot diverge on a load-bearing term without a named test going red, **or** the document records at the D-family why a prose cross-check must not exist, carrying `622f5fe` §1's argument so the next lane does not re-derive it.
- Notes: **the naive form is already ruled out and the ruling is right** — `622f5fe` §1: *"a substring match on the prose would pin editorial wording rather than format facts."* That is why this is scoped to a closed vocabulary rather than to equality. Explicitly **not Q129**, which is one word at one key; this is a structural gap spanning fourteen maps. It is also the reason Q129's site count was wrong in its own row: the second frozen site was invisible because nothing in the tree relates the two files' prose.

### Q132 — The freeze machinery cites a spec line that does not say what it is cited for
- Milestone: M2
- Size: XS
- Deps: after Q14, Q27 (D108 §1.7)
- Discovered by: **the D108 lane** (2026-08-09).
- Problem: `scripts/format-freeze.sh:179-181`, `docs/format/FROZEN.sha256:48-52` and `crates/antseal-core/tests/format_freeze.rs`'s failure text all cite `MVP-SPEC.md` line 123 as the authority for *"a byte change to a frozen entry is a format-version event"*. Line 123 says something else: *"every **released** manifest/bundle format version remains verifiable by all future CLI and page releases"* — a **compatibility** guarantee, conditioned on *released*, and D104 §1.5 measures with three independent confirmations that nothing has been released. The freeze antseal actually operates is a **stronger, self-imposed** discipline that line 123 does not require.
- Do: cite **Q14's own act** as the authority for byte-immutability, and name line 123 as the compatibility rule the freeze exists to protect. Three call sites, no behaviour change.
- Accept: every citation of the byte-immutability rule names Q14, and line 123 is cited only for compatibility — or the derivation from line 123 is written out where it is claimed.
- Notes: not pedantry. A reader who follows the citation finds a conditional whose condition is false today and may conclude the freeze is soft — which is exactly the inference D108 §3 spends a section refusing, and exactly the inference that would have made Q129's "just re-bless it" answer look cheap. A rule defended by a misquotation is defended by nothing.
