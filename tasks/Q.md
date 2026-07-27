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
- Notes: Maintained continuously through M4; tagged M0 because it must exist at freeze.

### Q14 — Run the M0 format-freeze gate with recorded sign-off
- Milestone: M0
- Size: S
- Deps: Q5, Q6, Q8, Q11, Q12, Q13; P: encoder-crate pin + `ant-core` pin re-verified at M0 start (P9/P10); C: HKDF-distinctness golden test + WASM probe verdict (C3/C11); F: Definitions-section registries frozen (F4); G: pinned Unicode/NFC version recorded (G1)
- Spec: Revision note (line 5); Security assumptions (line 99); Milestones M0 (line 153)
- Do: Write and execute the freeze checklist: Definitions section frozen (CBOR profile + pinned encoder, domain-tag registry, id encodings, length-prefixed HKDF info, pinned Unicode version, signature context string); all M0 golden vectors committed and frozen (Q6) including the must-exist list; independent cross-check clean (Q11); tamper M0 registry fully implemented (Q8); HKDF-distinctness golden test green; WASM bit-match green (Q5); WASM probe decision recorded; Security-assumptions sign-off recorded (Q12); traceability M0 rows filled (Q13). Freeze is an annotated `format-v1-freeze` tag plus CHANGELOG entry.
- Accept:
  - Checklist committed; every item objectively green before the tag exists
  - Tag + CHANGELOG entry present; sign-off names/dates recorded
  - Any post-tag change to frozen material requires a format-version bump per Q27 policy

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
- Do: State the normative policy: every released manifest/bundle format version remains verifiable by all future CLI and page releases; per-version golden vectors are retained in CI indefinitely (Q6 mechanism); the hosted page supports all released versions; NFC normalization tables are retained per descriptor-recorded Unicode version so aging bundles never false-positive as tampered; evolution prefers reserved slots over breaking changes; define what forces a format-version bump and the freeze procedure for a new version (mirroring Q14).
- Accept:
  - Policy doc committed, citing the Q6 retention guard and R's multi-version support as enforcement
  - Unicode-version retention and reserved-slot preference stated; version-bump criteria defined

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

## Open decisions (Q)
- Independent cross-check vehicles and permanence — which second implementations per surface (Python `cbor2` for CBOR; Python crypto stack for HKDF/commitments/GGM; whether ml-dsa↔fips204 cross-crate + ACVP KATs counts as "independent" for ML-DSA), and one-shot audit artifact vs permanent CI lane (proposal: both). Blocks Q11, Q14. Must land by M0.
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
