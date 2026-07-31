# R — Reveal, bundle assembly, verification pipeline, verifier web page

> Part of the antseal MVP task breakdown (generated 2026-07-27 from MVP-SPEC.md Revision 2 by a 9-agent decomposition).
> **Status tracking lives in `../TODO.md`** — do not add checkboxes here. Treat Do/Accept as normative until deliberately revised; spec line references are into `MVP-SPEC.md` as of 2026-07-27.
> Dep prefixes: P=setup/toolchain/pins, F=CBOR+manifest/bundle codecs, C=crypto primitives, G=canonicalization+units+GGM fine tree, S=storage/payments/journal/restore, A=anchors, R=reveal/verification/web page, U=CLI/vault/config/UX, Q=test-infra/CI/threat-model/docs/release.
> Milestone split (normative): structural-invariant verification logic + its tamper rows are M0 (they ship with core verification); the bundle BUILDER, reveal/verify CLI UX, and the web page are M3.

### R1 — Define the verification report model and error taxonomy in `antseal-core::verify`
- Milestone: M0
- Size: M
- Deps: F: decoded bundle/manifest typed structs from the strict-canonical CBOR codec
- Spec: Reveal bundle — two proof layers; Verifier structural invariants (MVP-SPEC.md lines 116–121); Verification (lines 167–168)
- Do: Create the WASM-safe `VerificationReport` type: work metadata (work_id, title, format/app version, claimed time as an informational-only field, signature-scheme label slot), an evidence-layer result, a storage-linkage-layer result slot, per-anchor result slots (state + verified time + artifact metadata + fetch dates; absent-tolerant from day one), and the redaction/reveal-set data (per file: revealed spans, unrevealed unit spans, unrevealed-file placeholders). Define a `thiserror` `VerifyError` taxonomy with one distinct, field-identifying variant per failure class this domain owns (decrypt, padding, true-length, lengths, referential integrity, tiling, path-commit, partial-isolation, full-reveal material/cross-checks, raw-mirror binding), plus wrapper variants for C/G/F/A errors so every tamper row surfaces distinctly through `verify_bundle`. The report must be serde-serializable deterministically (drives `--json` and the WASM bit-match vectors).
- Accept:
  - Report and error types compile for `wasm32-unknown-unknown` with no I/O/tokio deps
  - Every structural invariant in line 121 has a named, distinct error variant (unit-tested for distinctness, e.g. exhaustive-match test)
  - Report serializes deterministically (two serializations of the same report are byte-identical)
  - No secret material (`k_u`, salts, `W`) appears in any `Display`/`Debug` output of report or errors (test asserts redaction)
- Notes: Decide fail-fast vs collect-all error reporting (see Open decisions); design for both: typed first-error for the tamper matrix, optional multi-error collection for rendering.
  — **[2026-07-27] executed**: D27 resolved (hybrid, docs/decisions/D27-verify-error-mode.md); D29 recommended (byte-deterministic compact JSON, serde/serde_json exact-pinned; freeze reserved to Q14 via Q4/Q5 — docs/decisions/D29-report-byte-format.md). The C/G/F/A wrapper variants are a documented extension point in `verify/error.rs` (wildcard-free `code()` match makes an armless addition a compile error); they land with their consumers (R2 for C/G, F3 for codec, A-stage for anchors) so wrapping semantics are decided by real call sites, not guessed at R1.

### R2 — Implement per-unit evidence stages: decrypt, padding verify/strip, true-length binding, content-binding dispatch
- Milestone: M0
- Size: M
- Deps: R1; C: XChaCha20-Poly1305 open with AAD (C9); G: leaf-range verification against `fine_root` (G13); C: `unit_commit` recomputation (C6)
- Spec: Cryptography — unit encryption (line 91); Reveal bundle — evidence layer (lines 114, 118); Verifier structural invariants (line 121)
- Do: For each revealed unit entry: decrypt the embedded ciphertext with the bundled `k_u`, the nonce taken exclusively from the manifest unit table, and AAD = `seal_id ‖ LE64(unit_id)`; verify AEAD-plaintext length equals `padded_length = ⌈(true_length+1)/256⌉·256` recomputed from the manifest's `true_length` (rejects over-/under-padding); verify every byte beyond `true_length` is `0x00`; strip length-first to `true_length`; verify `true_length` equals the unit's manifest byte-range width. Then dispatch content binding by unit kind/coverage: fine-tree-covered units go through G's sub-cover → leaf → boundary-path verification against `fine_root`; non-covered units (`--no-fine-tree`, raw-mirror) recompute `unit_commit = SHA-256(0x02 ‖ unit_salt ‖ bytes)` via C and match the manifest.
- Accept:
  - Unit tests per stage with distinct errors: `UnitDecryptFailed`, `PaddedLengthMismatch`, `NonZeroPadding`, `TrueLengthRangeMismatch`, `FineRootBindingFailed` (wrapping G), `UnitCommitMismatch`
  - Edge vectors pass: empty unit (`true_length` 0 pads to 256), unit ending exactly on a 256-B boundary (one extra pad block), one-byte file (single-leaf tree)
  - Nonce is read only from the manifest unit table — a bundle-side nonce field neither exists nor is consulted (asserted against F's schema)
  - G's over-broad-cover rejection (node spanning an unrevealed real leaf) surfaces through this stage as a distinct wrapped error
  - WASM-safe (compiles for wasm32)

### R3 — Implement manifest/bundle structural checks: exact lengths, referential integrity, tiling invariant, path verification
- Milestone: M0
- Size: M
- Deps: R1; F: decoded types (coordinate whether fixed-length fields are enforced at decode or here); C: `path_commit` recomputation (C6)
- Spec: Verifier structural invariants (line 121); Salted commitments — per-file salts, raw mirror (lines 92, 95); Tamper matrix (line 168)
- Do: Implement, each as an explicit check with a distinct field-identifying error: (1) exact-length validation of every disclosed secret-adjacent byte string — `unit_salt`/`path_salt`/`file_salt` = 16 B; `s_root` and every GGM covering seed = 32 B; every boundary Merkle node hash = 32 B; (2) referential integrity — every bundle unit entry references an existing manifest `unit_id` with no duplicates, every touched-file/full-reveal entry references an existing `file_id`, covers/paths reference revealed units only; (3) the per-file tiling invariant over the manifest unit table (all files, regardless of reveal shape): non-mirror unit byte-ranges sorted, non-overlapping, exactly tiling `[0, size)`, with raw-mirror units exempted strictly by `kind` — and a raw-mirror wrongly participating in the tiling set is its own distinct error; (4) for every touched file, recompute `path_commit = SHA-256(0x05 ‖ path_salt ‖ path_utf8)` via C and match the manifest.
- Accept:
  - Distinct errors: per-field length variants, `UnknownUnitRef`, `DuplicateUnitReveal`, `UnknownFileRef`, `TilingViolation{unsorted|overlap|gap|out_of_bounds}`, `RawMirrorInTilingSet`, `PathCommitMismatch`
  - Tiling check runs on partial reveals too (manifest-level; unit test proves it fires without any revealed bytes)
  - Wrong-length mutation of each individual field class yields its distinct error — never a panic, never an undistinguishable generic decode error (coordinated with F if F's schema rejects first)
- Notes: If F encodes these as fixed-size CBOR byte strings, agree at M0 whose layer emits the length error; the tamper fixtures (R7) must pass either way with a field-identifying error.

### R4 — Implement reveal-shape classification and file-level checks: partial-reveal isolation, full-reveal cross-checks, raw-mirror binding
- Milestone: M0
- Size: L
- Deps: R2, R3; G: full fine-tree rebuild from `s_root` (G9); G: `canonicalize_v` pinned to the descriptor's recorded Unicode version (G2); C: `canon_commit`/`raw_commit` recomputation (C6)
- Spec: Verifier structural invariants (line 121); Raw mirror (line 92); Salted commitments (line 95); GGM fine tree (line 96); M0 milestone (line 153)
- Do: Classify each file's reveal shape: fully revealed iff every non-mirror `unit_id` of the file is in the bundle's revealed set; otherwise partial (or untouched). Enforce partial-reveal isolation: hard-reject any bundle containing `file_salt` or `s_root` for a partially revealed file (the leaf-exact GGM sub-cover of a covered per-unit reveal is explicitly permitted). For fully revealed files, require the full-reveal material (`file_salt`; `s_root` iff the descriptor records a fine tree) with a distinct error when absent, then: concatenate the verified non-mirror unit bytes in range order and match `canon_commit` (text) / `raw_commit` (binary) under `file_salt`; when a fine tree exists, rebuild the entire fine tree from the bundled `s_root` over those bytes via G and match `fine_root`. When the file's raw-mirror unit is also revealed: verify `raw_commit = SHA-256(0x03 ‖ file_salt ‖ raw_mirror_bytes)`, and enforce raw-mirror ↔ canonical binding — recompute `canonicalize_v(raw_mirror_bytes)` with the descriptor-recorded version via G and require byte-equality with the validated canonical bytes.
- Accept:
  - Distinct errors: `PartialRevealSaltLeak{file_salt|s_root}`, `FullRevealMaterialMissing{file_salt|s_root}`, `ConcatCommitMismatch{canon|raw}`, `FineRootRebuildMismatch`, `RawCommitMismatch`, `RawMirrorCanonicalizationMismatch`
  - `--no-fine-tree` full reveal runs only the concat→commit check (no tree rebuild); text-with-mirror full reveal runs all of: concat→`canon_commit`, tree rebuild→`fine_root`, mirror→`raw_commit`, `canonicalize_v(raw)==canonical`
  - Empty-file vector (no fine tree, one empty unit) verifies as a full reveal
  - Full-file reveal expressed via `--units` enumerating all non-mirror units classifies identically to `--all` for that file
- Notes: The "full reveal requires `file_salt`/`s_root` present" strictness is derived from line 121's mandatory cross-checks ("using the bundled `s_root`, the verifier MUST rebuild") — confirm as an M0 freeze decision (see Open decisions).

### R5 — Assemble the `verify_bundle` evidence-pipeline orchestration in `antseal-core`
- Milestone: M0
- Size: M
- Deps: R1, R2, R3, R4; F: strict-canonical decode + size/count/depth caps; C: hybrid strict signature verification + `sig_policy` enforcement + scheme label (C14); A: (M2) anchor state machine — stage slot only at M0 (A1)
- Spec: Core user flows — verify (line 38); Reveal bundle — evidence layer order (lines 116–118); M0 milestone (line 153); Verification (line 167)
- Do: Implement `verify_bundle(bytes, opts) -> Result<VerificationReport, VerifyError>` as pure, WASM-safe orchestration in stage order: F strict decode → structural pre-validation (R3) → per-unit stages (R2) → file-level checks (R4) → `sig_policy`/signature stage via C over the embedded body bytes (never re-encoded) → anchor stage (at M0: tolerate and report `absent` per anchor; A's state machine plugs in at M2 via R12) → populate the redaction/reveal-set data and metadata (work_id recomputed as SHA-256(body), hybrid-vs-Ed25519-only label from C). Guarantee no panic on any input; all failures are typed errors. Storage-linkage is a separate later stage (R20) and must not gate the evidence verdict.
- Accept:
  - End-to-end verify of a valid fixture bundle (R6) produces a report with evidence layer passed and anchors `absent`
  - Empty-anchor golden vector verifies (M0 requirement)
  - C's `sig_policy` violations (missing/invalid/unlisted-extra/empty policy) and non-canonical-signature rejections surface through `verify_bundle` as distinct wrapped errors (rows themselves owned by C)
  - `cargo build --target wasm32-unknown-unknown` passes for the whole pipeline; no tokio/I-O in the dependency graph
  - Verification of the same bundle twice yields byte-identical serialized reports (determinism)

### R6 — Build the test-only bundle fixture constructor for M0 verification testing
- Milestone: M0
- Size: M
- Deps: R1; F: bundle/manifest encode API; C: HKDF derivations, AEAD seal, commitments, signing; G: fine tree build, leaf-exact covers + boundary paths, canonicalization
- Spec: Architecture — `testdata/` (line 57); M0 milestone (line 153); Verification (lines 167–169)
- Do: Implement a seeded, deterministic test-only constructor (in a test-support module or `testdata` generator binary) that produces valid works and `.sealproof` bundles of every shape needed at M0 — single/multi-file, text and binary, `--split` multi-unit, `--no-fine-tree`, raw-mirror (CRLF/BOM/NFD sources), empty file, one-byte file, unbalanced n=6, full/partial/`--all` selections, empty anchors — without waiting for the M3 production builder. It is the substrate for R7–R10 mutations and vectors; the M3 builder (R13) later replaces or absorbs it, with a parity test between the two.
- Accept:
  - Seeded runs are byte-reproducible
  - Property test: for randomized synthetic works × randomized valid selections, constructed bundles pass `verify_bundle` (M0 early version of the R14 guarantee)
  - Constructed partial-reveal bundles contain no `file_salt`/`s_root`/ancestor-of-unrevealed-leaf seeds (asserted structurally)
  - No secret material from fixtures leaks into committed vector files beyond what a bundle legitimately discloses
- Notes: Fixture secrets are synthetic test keys only — still keep them out of logs to preserve the hygiene discipline.

### R7 — Implement the M0 structural tamper-fixture suite (every structural row, distinct error asserted)
- Milestone: M0
- Size: L
- Deps: R5, R6; F: raw-CBOR-level mutation helpers where typed mutation can't express a row; G: over-broad-cover construction helper (G19)
- Spec: Verifier structural invariants (line 121); Tamper matrix — M0 structural rows (line 168); M0 milestone (line 153)
- Do: For each structural invariant, commit a tamper fixture (mutated from R6 bundles, checked into `testdata/`) and a test asserting `verify_bundle` fails with exactly that row's distinct error: wrong-length `unit_salt`/`path_salt`/`file_salt` (16 B), wrong-length `s_root`/GGM covering seed/boundary node hash (32 B); `true_length` ≠ byte-range width; over-padded unit (AEAD-plaintext length ≠ `padded_length`); non-zero padding byte beyond `true_length`; overlapping / out-of-bounds / gap / unsorted non-mirror ranges; raw-mirror wrongly included in the tiling set; raw-mirror whose `canonicalize_v(raw)` ≠ canonical bytes; `file_salt` present for a partially revealed file; `s_root` present for a partially revealed file; full-reveal bundle with its `file_salt`/`s_root` stripped; concat-mismatch vs `canon_commit`/`raw_commit`; fine-tree-rebuild mismatch vs `fine_root`; over-broad GGM cover spanning an unrevealed real leaf (constructed via G, rejected through the pipeline); duplicate/unknown unit and file references.
- Accept:
  - One committed fixture + one test per row above; each asserts the specific error variant (not just "failed")
  - A coverage test cross-references the row list against the error enum so a new invariant without a row fails CI
  - Suite runs on native and wasm32 with identical outcomes
- Notes: The permitted case — leaf-exact sub-cover present on a partial reveal — gets an explicit *positive* fixture so the isolation check is proven not over-broad.

### R8 — Implement pipeline-integration tamper rows (ciphertext/key/salt/swap/manifest-alteration through `verify_bundle`)
- Milestone: M0
- Size: M
- Deps: R5, R6, R7 (shared mutation harness)
- Spec: Tamper matrix — M0 format/commitment rows as exercised end-to-end (line 168)
- Do: Add end-to-end rows that mutate bundle contents and assert the distinct pipeline error: flipped ciphertext byte → AEAD decrypt failure; wrong `k_u` → decrypt failure; swapped unit (unit A's ciphertext under unit B's entry) → decrypt failure via the AAD's `unit_id` binding (test documents that AAD, not a commitment, catches this first); wrong `unit_salt` → `unit_commit` mismatch (non-covered unit); wrong `path_salt`/path → `path_commit` mismatch; altered manifest field such that a covered unit's bytes fail the `fine_root` leaf-range/boundary-path check and a non-covered unit's bytes fail `unit_commit`. Primitive-level reject tests for AEAD/commitments/signatures remain C's and G's; these rows prove the failures surface distinctly through the full pipeline.
- Accept:
  - Each listed mutation has a fixture + test asserting its distinct error through `verify_bundle`
  - Covered-unit vs non-covered-unit manifest-alteration rows fail at their respective single authoritative commitment (`fine_root` vs `unit_commit`), matching the single-commitment rule
  - C's signature/`sig_policy` and F's non-canonical-CBOR rows run in the same harness (hook provided; rows owned by C/F)

### R9 — Commit verification golden vectors with native/WASM bit-match
- Milestone: M0
- Size: M
- Deps: R5, R6; F: per-version vector layout (F10); G: unbalanced-n and range-proof fixtures (G15); Q: wasm32 test execution in CI (Q5)
- Spec: M0 milestone (line 153); Verification — golden vectors, WASM bit-match (lines 167, 169); Format stability (line 123)
- Do: Commit `testdata/` golden vectors mapping canonical bundles → expected serialized `VerificationReport`s for every M0 shape: full text reveal, partial reveal with leaf-exact covers, per-unit reveal at unbalanced n=6 (pins MSB-first GGM indexing through the pipeline), binary file, `--no-fine-tree` file, raw-mirror full reveal, empty file, one-byte file, multi-file with an unrevealed committed-placeholder file, empty-anchor bundle. A test runs `verify_bundle` on each vector on native and on wasm32 and requires byte-identical serialized reports.
- Accept:
  - Vectors committed and immutable (CI fails on drift); retained indefinitely per the format-stability policy (retention infra Q)
  - Native and wasm32 outputs byte-match for every vector
  - Vector set enumerated in a manifest file so the R28 multi-version suite can extend it per released format version

### R10 — Add `verify_bundle` no-panic fuzz and property coverage
- Milestone: M0
- Size: S
- Deps: R5, R6; F: codec-level cargo-fuzz targets exist separately (F17); Q: fuzz jobs in CI (Q9)
- Spec: M0 milestone — parser hardening, fuzzing in CI (line 153); Risks — hostile bundles (line 187)
- Do: Add a cargo-fuzz target feeding arbitrary bytes and structure-aware mutations (bit-flips, truncations, section swaps of valid R6 bundles) into `verify_bundle`, asserting it never panics, never allocates beyond F's caps, and always returns a typed error or report. Complements — does not duplicate — F's CBOR-decoder fuzzers.
- Accept:
  - Fuzz target builds and runs in CI (Q wiring); seed corpus includes all R9 vectors and R7 tamper fixtures
  - Proptest: random mutations of valid bundles never panic (runs in the normal test suite, not only under fuzzing)

### R11 — Provide the library-level live-check helper (re-fetch and byte-compare)
- Milestone: M1
- Size: S
- Deps: S: `StorageBackend::get_data` + the S15 persistence primitive; F: manifest/unit-table types
- Spec: Core user flows — verify `--live` (line 38); Storage-linkage layer (line 119); M1 verification — `--live` re-fetch passes via library APIs (lines 154, 172)
- Do: Provide the verify-side wrapper over S15's persistence primitive (implemented once in `antseal-net`; consumed here): `live_check(expected: &[(Address, ExpectedBytes)], backend) -> Vec<PerBlobResult>`. Design it to work from a manifest unit table + ciphertext map (so the M1 devnet E2E can call it before any bundle builder exists) and, at M3, from a bundle's embedded ciphertexts + the encrypted-manifest blob. Per-blob results: match, mismatch, fetch-failed.
- Accept:
  - Unit-tested against `MockBackend` (match/mismatch/missing cases); no live network required
  - Usable by the M1 devnet E2E (S/Q own that test) and later by R21's `--live`
  - Covers unit ciphertexts and the encrypted-manifest blob
- Notes: Implementation lives in S15 — this task is the verify-side interface + M3 bundle-shaped adapter; do not implement fetching twice.

### R12 — Wire the anchor-verification stage into the evidence pipeline
- Milestone: M2
- Size: S
- Deps: R5; A: per-anchor offline state machine + per-anchor verified time + artifact/fetch-date metadata, WASM-safe in `antseal-core` (A18)
- Spec: Anchoring (lines 106–110); M2 milestone (line 155); Reveal bundle — evidence layer step order (line 118)
- Do: Replace the M0 `absent` stub: for each anchor artifact in the bundle, invoke A's state machine against `anchor_digest` (recomputed over the full embedded manifest bytes, signatures included) and store the resulting state, verified time, and metadata in the report's anchor slots. A's M2 anchor tamper rows execute through `verify_bundle` via this stage; the Arbitrum receipt artifact is routed to the report's separate supporting-evidence slot, never into the anchor set.
- Accept:
  - Bundles carrying each of the 7 states produce reports with that state populated (fixtures from A)
  - A's anchor tamper rows (wrong-digest `.ots`/TSA, untrusted root, forged header, expired-at-vs-after-genTime, BER-where-DER) fail distinctly through `verify_bundle`
  - Receipt present → supporting-evidence slot populated, anchor slots unaffected; wasm32 build still passes

### R13 — Implement the bundle builder (pure assembly) in `antseal-core`
- Milestone: M3
- Size: L
- Deps: R5 (self-verify), R6 (absorb/parity); F: bundle encode (F9); C: HKDF derivations (`k_u`, `unit_salt`, `path_salt`, `file_salt`) via C7's disclosure types; G: leaf-exact GGM sub-cover + boundary Merkle path computation (G11/G12)
- Spec: Reveal bundle — contents (lines 112–114); Core user flows — reveal (line 36); M3 milestone (line 156)
- Do: Implement `build_bundle(...)` as a pure function taking the plaintext manifest bytes, manifest storage record {address, nonce, `k_m`}, the resolved reveal selection (per file: full / partial-with-unit-set / untouched), per-unit ciphertexts, per-file plaintext bytes for touched files (needed by G to compute boundary paths), the derivation secret (`W` or a derivation handle), anchor artifacts + fetch dates, and an optional receipt. Emit exactly the spec content sets: per covered revealed unit {`unit_id`, `k_u`, embedded ciphertext, leaf-exact GGM sub-cover of exactly the revealed leaves (via G), boundary Merkle paths}; per non-covered revealed unit {`unit_id`, `unit_salt`, `k_u`, ciphertext}; per touched file {path, `path_salt`}; per fully revealed file {`file_salt`, `s_root`} plus its raw-mirror unit; manifest storage record always; anchors always; receipt iff opted. No nonce fields — nonces stay manifest-only. Enforce generation-side isolation by construction: derive and emit nothing for untouched files, and never `file_salt`/`s_root`/any ancestor-of-unrevealed-leaf seed for partially revealed files. Run `verify_bundle` on the output as a mandatory self-check before returning.
- Accept:
  - Built bundles for every reveal shape pass `verify_bundle` (self-check wired in; failure aborts the build)
  - Structural assertions: partial-reveal bundles contain no `file_salt`/`s_root`/forbidden ancestor seeds; mirrors appear only with full-file reveals; receipt present iff opted; no nonce fields anywhere in the bundle
  - Parity test: R13 output for R6's fixture scenarios verifies identically to R6's constructions
  - WASM-safe (pure, no I/O); secrets zeroized/never logged
- Notes: Raw-mirror inclusion on full-file reveal implemented as automatic (see Open decisions).

### R14 — Property-test the builder's generation-side guarantees
- Milestone: M3
- Size: M
- Deps: R13, R6 (generators)
- Spec: Reveal bundle — generation-side guarantees (line 114); Verifier structural invariants — partial-reveal isolation (line 121)
- Do: Proptest over randomized synthetic works × randomized selections (unit subsets, whole files, `--all`, mixes across multiple files, `--no-fine-tree` and mirror-bearing files, empty/one-byte files): every built bundle (a) passes `verify_bundle`; (b) for each partially revealed file contains no `file_salt`, no `s_root`, and no GGM seed that is an ancestor of any unrevealed leaf (checked by walking the emitted cover against the selection); (c) includes mirrors only alongside full-file reveals; (d) discloses paths only for touched files.
- Accept:
  - Property suite green with a seeded RNG (reproducible failures)
  - Ancestor-seed checker is independent of G's cover code (re-derives ancestry from indices, so a shared bug can't hide)
  - Negative control: forcing the builder to emit a forbidden item makes the self-check fail (guards the guard)

### R15 — Implement the disclosure-preview computation
- Milestone: M3
- Size: S
- Deps: C: unit decrypt for snippet plaintext; U: vault path/record access (U9); S: `get_data` when no local copy
- Spec: Core user flows — reveal confirmation (line 36); CLI surface — `show` (line 149); Verifier structural invariants — position + total size (line 121)
- Do: Implement a library function that, for a resolved selection, produces per-unit preview rows {file path (from vault), byte-range, size, plaintext snippet} plus totals (units, bytes, files touched, which files become fully revealed, whether a raw mirror will ride along) — the exact data the irreversible-disclosure confirmation prints and that U's `show` command reuses ("the preview for `reveal --units`"). Snippets come from decrypted plaintext (local staged bytes or fetched ciphertext); when plaintext is unavailable the row renders without a snippet rather than failing.
- Accept:
  - Unit tests: text snippet, binary snippet (hex/elided form), snippet-unavailable case, full-file-implied and mirror-rides-along annotations present
  - Function is consumed by both R16 and (cross-domain) U's `show` (U27)
  - No secret material in the preview output beyond the plaintext being deliberately disclosed
- Notes: Snippet length/format is an open decision (small).

### R16 — Implement the reveal-flow library API (selection resolution, ciphertext gathering, builder invocation)
- Milestone: M3
- Size: L
- Deps: R13, R14, R15; S: `get_data` fetch when no local copy. U28/U29 are the CLI consumers (arg surface, prompts, file output, URL print — not ordering deps); the opportunistic upgrade hook (A15) is invoked by U's command dispatch before this API runs.
- Spec: Core user flows — reveal (line 36); Raw mirror selection rule (line 92); Reveal bundle (lines 112–114); CLI surface (line 149); M3 milestone (line 156)
- Do: Implement the library-side reveal flow that U28/U29 wire into the `reveal` command (this task ships no CLI surface): resolve the selection — `--all`, or work-global unit ids validated (unknown id → typed error; duplicate ids deduped; any raw-mirror id explicitly listed → typed rejection pointing at whole-file reveal/`--all`); classify per-file full/partial; auto-include raw-mirror units for fully revealed files. Gather ciphertexts for **all** units of every touched file (boundary Merkle paths need the whole file's leaves): prefer byte-identical staged journal bytes, else fetch from Autonomi via S using manifest addresses; decrypt for preview and tree rebuild. Produce the R15 disclosure-preview data for U29's confirmation gate, then build via R13 (self-verify included) and return the encoded `.sealproof` bytes plus a summary (revealed unit ids, files fully revealed, receipt-included flag). The canonical verifier-page URL constant is owned by R26 and printed by U28.
- Accept:
  - Library tests (MockBackend): `--all`, unit subset, subset completing a file (mirror rides), bare mirror id rejected, unknown id rejected, fetch-from-network path (no local copy), staged-bytes path — all through this API with no CLI involvement
  - Returned bundles pass `verify_bundle`; the preview data matches the final bundle contents (units, totals, mirror/receipt annotations)
  - `--include-receipt` toggles receipt embedding in the returned bundle; omitted by default
  - No prompting, printing, or file I/O beyond backend fetch inside this API (those concerns live in U28/U29)
- Notes: Fetching all touched-file units (not just selected) is a bandwidth note for docs; it is unavoidable for boundary-path computation without a persisted tree cache. (Redefined as a library API after the consistency audit — U28/U29 are the sole CLI owners.)

### R17 — Implement verdict aggregation: headline, eligibility, divergence, UNANCHORED, receipt class
- Milestone: M3
- Size: M
- Deps: R12; A: per-anchor states + verified times (A18); C: hybrid-vs-Ed25519-only label (C14)
- Spec: Verifier web page — verdict taxonomy and headline rules (lines 127–137); Anchoring — `--online` promotion (line 108)
- Do: Implement pure aggregation in `antseal-core`: the headline-eligibility map (`proven` [H], `valid-at-stamping-cert-since-expired` [H]; `attested`/`pending`/`internally-consistent-only`/`invalid`/`absent` not eligible); ONE headline = earliest headline-eligible anchor's verified time + source; divergence flag when headline-eligible anchors disagree by >48 h; zero headline-eligible → the UNANCHORED outcome; the Arbitrum receipt kept in a wholly separate supporting-evidence class, never eligible, never in the anchor set; claimed time carried as subordinate metadata that can never enter the headline (type-level: the headline input set excludes it). Support a second, online-augmented computation where `--online`-promoted anchors (`attested`→`proven`, per A) participate — producing an overlay verdict distinct from, and never overwriting, the offline verdict.
- Accept:
  - Unit tests per rule: earliest-wins across TSA/OTS mixes; [H] map exhaustive over all 7 states (exhaustive match, compile-breaks on new states); 48 h boundary cases (47 h 59 m no flag, 48 h 01 m flagged); zero-eligible → UNANCHORED; receipt-only bundle → UNANCHORED + supporting evidence; promotion feeds only the overlay computation
  - Claimed time provably cannot reach the headline (test constructs a claimed time earlier than all anchors; headline unchanged)
  - WASM-safe, deterministic

### R18 — Freeze the single authoritative verdict-wording set with snapshot tests
- Milestone: M3
- Size: M
- Deps: R17; Q: snapshot-test tooling in CI (Q19/Q20 are consumers of the frozen wording — not ordering deps)
- Spec: Verifier web page (lines 127–139); M3 milestone + verification (lines 156, 174); Positioning constraints (line 28)
- Do: Author the one authoritative wording table in `antseal-core` (shared verbatim by CLI and page — renderers receive final strings, never compose their own): per-state renderings for all 7 anchor states with [H] tags — including the spec-mandated guidance strings for `pending` ("not yet independently provable — ask the sealer to run `status --upgrade`"), `attested` (ops commit `anchor_digest` to block H, header embedded, `--online` required for a provable time), and the distinct "valid at stamping; certificate since expired" phrasing; the headline template "Existed no later than \<time\> (source)"; the subordinate claimed-time label "asserted by sealer — NOT verified"; the >48 h divergence flag text; the loud "UNANCHORED — integrity and signature only, no provable time" banner; the receipt class "supporting evidence — no independently proven time"; the "hybrid (PQ)" vs "Ed25519-only" signature label; the online-advisory-overlay framing distinct from the offline verdict; storage-linkage and `--live` layer labels; anchor fetch-date lines; possession-language compliance (no "notary", no unqualified "priority").
- Accept:
  - Snapshot tests cover every one of the 7 states' rendering, headline, claimed-time, divergence, UNANCHORED, receipt class, overlay, sig label, storage-linkage pass/fail lines — an exhaustive-enumeration test fails if any state lacks a snapshot
  - Grep-style test: CLI and page sources contain no verdict-wording literals outside the table
  - Wording reviewed against positioning constraints (checklist in the test file header)
- Notes: Overlay-vs-headline layout must be frozen here (see Open decisions) since snapshots pin it.

### R19 — Implement the redaction-view model and CLI renderer
- Milestone: M3
- Size: M
- Deps: R5 (reveal-set data in the report), R18 (labels)
- Spec: Verifier structural invariants — anti-out-of-context guardrail (line 121); Salted commitments — committed placeholders (line 95); M3 milestone (line 156)
- Do: From the verified report, build the shared redaction model (in `antseal-core`, reused by the page): per file — ordered spans of revealed content (each with byte-range position and size against the file's total size) interleaved with unrevealed units rendered as sized blackout blocks {byte-range, size}; unrevealed files as committed placeholders showing size only, path withheld ("file #3 — 48 KB"); work-level totals. Implement the CLI text renderer over this model so every reveal displays position + total size unconditionally.
- Accept:
  - Snapshot tests: partial reveal (blackout blocks with positions/sizes), full reveal, multi-file with placeholder file, `--no-fine-tree` whole-file, empty file
  - Placeholders never leak paths or content-derived data (asserted)
  - Position + total size present in every rendering (test iterates all fixture shapes)
  - Model serializes into the report (drives the page DOM in R23)

### R20 — Implement the storage-linkage layer stage and its distinct rendering
- Milestone: M3
- Size: M
- Deps: R5, R18; S: deterministic self_encryption address recomputation (S4); C: AEAD seal for manifest re-encryption (C10); F: manifest storage record type
- Spec: Reveal bundle — storage-linkage layer (lines 116, 119); Manifest storage record (line 98); Core user flows — page storage story (line 38); M3 milestone (line 156)
- Do: Add the offline storage-linkage stage to `verify_bundle` (report-slot populated, evidence verdict untouched): for every embedded unit ciphertext, recompute its Autonomi address via S's deterministic self_encryption function and compare with the manifest's recorded address; for the manifest, re-encrypt the embedded plaintext manifest bytes with the storage record's `k_m` + nonce (AAD empty), recompute the resulting blob's address, and compare with the record's address. Render results as a layer visually and semantically distinct from the evidence layer ("storage is the product's bonus, not its proof"), on both CLI and page.
- Accept:
  - Fixtures: all-match; unit-address mismatch; manifest-address mismatch — each renders a distinct storage-linkage result while the evidence verdict is unchanged (test asserts evidence outcome identical across all three)
  - Fully offline (runs under wasm32 with no network); snapshot rows for pass/fail renderings (via R18)
  - Works on bundles with no local Autonomi access whatsoever

### R21 — Implement the verify orchestration library API (offline, `--online` overlay, `--live` composition)
- Milestone: M3
- Size: L
- Deps: R11, R17, R18, R19, R20; A: must-agree endpoint-pair primitives + promotion core (A16/A17/A18); S: backend for `--live` (S15). U30 is the CLI consumer (flags, exit codes, `--json` envelope — not an ordering dep).
- Spec: Core user flows — verify (line 38); Verifier web page — online mode (line 137); Anchoring — `--online` promotion (line 108); M3 milestone + verification (lines 156, 174)
- Do: Implement the library orchestration that U30's `antseal verify` wires up (this task ships no CLI surface): offline mode — run `verify_bundle` and produce the rendered verdict via R18/R19/R20 plus the machine-readable report. Online mode — for each `attested` OTS anchor, fetch block H via A's two pinned must-agree esplora endpoints and, when a receipt is present, the Arbitrum tx via two pinned RPCs (endpoint overrides supplied by the caller from U's config); require per-source agreement; feed results to A's promotion check; produce an advisory overlay distinct from and never overwriting the offline verdict, including promoted headline attribution, `invalid` on header mismatch, and an explicit disagreement outcome when the endpoint pair conflicts (no promotion on disagreement). Live mode — run R11 over the bundle's embedded ciphertexts + encrypted-manifest record and produce per-blob persistence results in the storage layer's section. TSA anchors get no online step (already offline-proven).
- Accept:
  - Test: offline mode performs zero network I/O (panicking mock backend/HTTP client proves no call is made)
  - Mock-endpoint tests: agreement → promotion + overlay headline; disagreement → advisory disagreement outcome, offline verdict untouched (the M3 endpoint-disagreement case, also exercised in R27); header mismatch → `invalid` rendering
  - Live mode renders match/mismatch/fetch-failed per blob against `MockBackend`; distinct from evidence layer
  - The full deterministic report (incl. overlay/live sections) is exposed for U30's `--json`; verdict-class data is exposed for U30's exit-code mapping (the mapping itself is U30's, per D69)
- Notes: The page never gets `--live`; CLI-only by spec. CLI flag surface, exit codes, and the `--json` envelope are U30's. (Redefined as a library API after the consistency audit — U30 is the sole CLI owner.)

### R22 — Build the wasm-bindgen binding surface for the verifier page
- Milestone: M3
- Size: S
- Deps: R5, R17, R18, R19, R20; P: pinned wasm toolchain (P14); C: M0 WASM probe results (C11)
- Spec: Architecture — verifier-web (lines 56, 47–51); Verifier web page (line 127); M0 WASM probe (line 153)
- Do: Create the thin wasm-bindgen crate/exports over `antseal-core`: `verify(bundle_bytes) -> JsValue` returning the full serialized report (final display strings from R18 embedded, so page JS does layout only); an entry accepting pre-fetched online-endpoint responses for the overlay (feeding A's WASM-safe must-agree/header-match core); exports for core version, format versions supported, and build info for the footer. No I/O inside the WASM module.
- Accept:
  - `wasm-pack build` succeeds with the pinned toolchain; module loads in node and browser tests
  - Binding-level test: R9 golden vectors verified through the JS boundary produce reports byte-identical to native
  - Panic hook installed; malformed input returns a typed JS error object, never an unhandled trap

### R23 — Build the verifier page: plain HTML/JS, drag-and-drop, offline-first full verification
- Milestone: M3
- Size: L
- Deps: R22, R18, R19; F: bundle size caps (browser memory safety); Q: page asset conventions
- Spec: Verifier web page (lines 125–137); Core user flows — verify item 5 (line 38); Format stability (line 123); M3 milestone (line 156)
- Do: Author `verifier-web/`: a single static page (plain HTML/JS/CSS, no framework, no build step beyond `wasm-pack`) with drag-and-drop plus a file-picker fallback; on drop, run full verification locally via R22 — anchors included — and render: the one headline, per-anchor states with [H] tags and fetch dates, subordinate claimed-time line, evidence-layer detail, the storage-linkage section (offline address recomputation — the page's entire storage story), the receipt's supporting-evidence class, the redaction view as DOM (revealed spans with position/size, sized blackout blocks, committed-placeholder files), signature-scheme label, and format version. All wording comes verbatim from the report's R18 strings. Handles all released format versions (dispatch inside `antseal-core`), and renders typed errors for malformed/hostile bundles without crashing the tab.
- Accept:
  - Page verifies every R9 vector with strings identical to CLI output (parity assertion in R27)
  - Works fully offline: file:// or a no-network browser context completes verification incl. anchor checks
  - Malformed/oversized bundles produce a graceful typed-error display (tamper fixtures dropped onto the page)
  - No external resources fetched in offline mode (asserted via R27's network interception); no framework or bundler in the repo

### R24 — Implement the page's online mode: browser-fetch must-agree overlay, user-overridable endpoints
- Milestone: M3
- Size: M
- Deps: R23; A: pinned endpoint defaults + WASM-safe must-agree/header-match/promotion core (A16/A18)
- Spec: Verifier web page — online mode (line 137); Anchoring — `--online` semantics (line 108); Core user flows (line 38)
- Do: Add an explicit user-triggered "confirm online" action: browser `fetch()` against the two pinned esplora endpoints for each `attested` anchor's block H (and the two Arbitrum RPCs when a receipt is present), endpoints user-overridable via simple inputs; pass raw responses into A's core check through R22; require per-source agreement; render results as an advisory overlay visually distinct from the offline cryptographic verdict — promotion to `proven` with overlay headline attribution, `invalid` on header mismatch, an explicit disagreement state, and per-endpoint fetch-failure states. No Autonomi/`--live` affordance exists anywhere on the page.
- Accept:
  - Offline verdict rendering is byte-identical before and after overlay activation (overlay strictly additive)
  - Mocked-endpoint tests (R27 playwright routes): agreement/promotion, disagreement, mismatch→invalid, one-endpoint-down
  - Endpoint override persists for the session and is clearly labeled as departing from pinned defaults
  - Overlay wording matches R18 snapshots
- Notes: Verify CORS availability of the pinned endpoints from browsers early in M3; overrides are the mitigation if a default becomes CORS-hostile (open decision).

### R25 — Make the page build reproducible and surface provenance (footer hash + published SHA-256)
- Milestone: M3
- Size: M
- Deps: R23; P: pinned rustc/wasm-pack/wasm-bindgen toolchain (P6/P14). Q30/Q31 (M4) consume the SHA-256SUMS artifact for signing/publication — not ordering deps.
- Spec: Page provenance (line 139); Risks — malicious verifier host (line 186); M3 milestone (line 156)
- Do: Produce a documented, deterministic build script for `verifier-web/`: locked dependencies, pinned toolchain, path-prefix remapping, no embedded timestamps — two independent builds must be byte-identical. Emit a SHA-256SUMS artifact over the page file set for publication (signing itself is Q's). Implement the footer: the page displays its own build hash plus the exact advice line "for high-stakes verification, run `antseal verify` and compare verdicts" (hash-injection mechanism per the open decision).
- Accept:
  - Two clean CI builds (different runners) produce byte-identical artifacts; CI job enforces this
  - SHA-256SUMS artifact generated and handed to Q's signing step
  - Footer shows the build hash matching the published sum, plus the advice string (snapshot/playwright-asserted)

### R26 — Deploy the page to the chosen host at the one canonical URL
- Milestone: M3
- Size: S
- Deps: R25; P: host + domain decision and access (P3); Q: docs referencing the URL; U: CLI prints the same URL in `reveal` output
- Spec: Page provenance — canonical URL, hosting is an M3 deliverable (line 139); Pre-M0 naming/domain check (line 3)
- Do: Deploy the reproducible-build artifacts to the decided static host under the one canonical URL; configure HTTPS and cache headers sane for a hash-published artifact; record the deploy procedure so releases redeploy deterministically. Export the canonical URL as a single shared constant consumed by U (reveal output) and Q (docs) so no second URL can drift into existence.
- Accept:
  - Canonical URL serves the page; served bytes hash-match the published SHA-256SUMS (scripted check)
  - Drag-and-drop verification of a real bundle succeeds against the hosted page
  - URL constant referenced from CLI output and docs (grep test: no other verifier URL literal in the repo)
- Notes: Blocked on the hosting/domain open decision (with P/Q); domain availability is a pre-M0 check per line 3 (P3).

### R27 — Build the M3 end-to-end suite: CLI + headless-page verification, parity, offline and disagreement cases
- Milestone: M3
- Size: L
- Deps: R16, R21, R23, R24; Q: playwright job + local static server in CI (Q19); S: MockBackend/devnet fixtures; A: recorded anchor fixtures for pending/attested/proven states (A25)
- Spec: Verification — M3 bullet (line 174); M3 milestone (line 156)
- Do: Script the full M3 loop: seal a fixture work (library/devnet path), `reveal` a subset via the CLI, then (a) `antseal verify` offline asserting the expected verdict; (b) playwright loads the page from a local static server, drops the same bundle (setInputFiles), and asserts the rendered headline, per-anchor states, redaction view, and layer sections — string-equal to the CLI's R18 wording (parity gate); (c) an offline-context run (playwright network blocked) proving full verification incl. anchors completes with zero requests; (d) online-mode runs with playwright route interception on both CLI (mock HTTP) and page: endpoint agreement → promotion, and the endpoint-disagreement case → advisory disagreement, offline verdict untouched.
- Accept:
  - CI job green: reveal→CLI-verify and reveal→page-verify on the same bundle, verdict strings identical
  - Offline-context page run makes zero network requests and reaches a full verdict
  - Endpoint-disagreement case asserted on both CLI and page renderings
  - Suite covers a partial reveal (blackouts + placeholder file visible in the page DOM) and a full reveal with raw mirror

### R28 — Keep verification working across all released format versions (page + pipeline)
- Milestone: continuous
- Size: S
- Deps: R9, R23; F: per-version codec dispatch + version vectors (F10); Q: indefinite CI retention of per-version vectors (Q6)
- Spec: Format stability (line 123); Verification — vectors retained forever (line 167)
- Do: For every released manifest/bundle format version, extend the R9 vector manifest with that version's bundles → expected reports, and keep a CI job running `verify_bundle` (native + wasm32) and the hosted-page verification path over the full historical set. The page advertises and accepts all released versions; a release checklist item forbids shipping a version bump without its vectors.
- Accept:
  - CI fails if any released version's vectors are missing, altered, or fail on CLI, wasm32, or the page path
  - Release checklist (with Q) includes the per-version vector gate
  - Page displays the verified bundle's format version for every historical vector

### R29 — Retire R5's hand-built smoke fixture in favour of R6's constructor
- Milestone: M0
- Size: S
- Deps: R6 (landed)
- Spec: Verification (lines 167–169) — one source of truth for "what a valid bundle looks like"
- Do: `verify::pipeline::tests::fixture` is ~280 lines of hand-built work that predates R6 and, by its own module comment, lives outside `test_util` deliberately so "nothing outside R5 can depend on it and R6 has nothing to unpick". R6 now exists and covers a strict superset of its shapes (its three-file work *is* R6's `shapes::multi_file`). Decide whether to (a) rewrite R5's tests against R6's shapes and delete the hand-built fixture, or (b) keep it as a deliberate independent construction and add an assertion that the two agree. Either is defensible; what is not defensible is leaving two unrelated definitions of a valid bundle drifting apart, since a bug that reached both would be invisible to both.
- Accept:
  - One of the two options implemented, with the reasoning recorded
  - If (b): a test asserting R5's fixture and the corresponding R6 shape produce the same verification report shape (not the same bytes — the RNG seeds differ by design)
  - R5's stage-order pins keep working unchanged either way; they are the reason the fixture exists and must not be weakened to make the merge easier
- Notes: Surfaced at R6/R7 (M0 wave 5). Low risk, and cheapest to do before R9's vectors bind either fixture's bytes.
- Rider (R9): R9 landed and binds **R6's** bundle bytes (`bundle_sha256`) and the reports derived from them, for 21 shapes. It does not touch R5's fixture, so neither option is blocked and the cost of R29 is unchanged — but the asymmetry it warned about is now concrete: one of the two definitions of "a valid bundle" is a frozen, CI-enforced artifact and the other is unpinned hand-built code. A bug reaching both is still invisible to both, and the frozen half now lends it false authority. Option (b) got cheaper in one respect (the R6 side of the agreement assertion is a committed artifact, not just live code) and option (a) got slightly dearer (deleting R5's fixture must not disturb the stage-order pins that R9's vectors do *not* cover — R9 pins outputs, R5 pins the order they are produced in). Verdict: more urgent, not more expensive.

### R30 — Assert the report's native↔wasm32 byte-match over R6-constructed bundles
- Milestone: M0
- Size: S
- Deps: R6 (landed), R9; Q: the wasm32 execution lane (P14/Q5, landed)
- Spec: Verification — WASM bit-match (line 169); M0 milestone (line 153)
- Do: R6 is `test-vectors`-gated precisely so the wasm32 lane can build bundles *in-process*, and today the wasm32 lane runs its unit tests (including R6's own) but nothing asserts that a report serialized on wasm32 is byte-identical to the native one for the same input. R9 will assert this over *committed* vectors; this asserts it over *constructed* ones, which covers shapes no vector file pins and costs nothing extra to run. Add a test that, for each named R6 shape, serializes the `VerificationReport` canonically and compares against a value the native lane computed — or, more cheaply, compares a digest of the serialized report against a committed per-shape constant that both lanes check.
- Accept:
  - Every named R6 shape has a report digest asserted on both native and wasm32
  - A shape whose bytes change fails both lanes with the same message, so a drift is diagnosed once rather than twice
  - No committed artifact carries secret material beyond what the bundle legitimately discloses (R6's existing hygiene assertion extends to it)
- Notes: Surfaced at R6 (M0 wave 5). Deliberately *not* folded into R9: R9 owns the committed-vector contract and its retention policy, whereas this is an in-process property with no artifact to retain. Sequence it after R9 so the report serialization it digests is the frozen one.
- Rider (R9): R9's committed vectors now assert exactly this over 21 of R6's shapes — every named catalogue entry except the three the vector deliberately omits. R30's remaining value is therefore the *constructed* half: it should assert over `shapes::catalogue()` directly, so a shape added to R6 after R9's file was frozen is covered from the moment it exists rather than at the next re-emit.

### R31 — Hoist the golden-vector JSON diff locator out of the `fine-tree` kind
- Milestone: M0
- Size: XS
- Deps: G15 (landed), R9 (landed)
- Spec: n/a — internal test-infrastructure tidy
- Do: `test_util::vectors_fine_tree::first_difference` is a *generic* JSON structural-diff locator (path + both sides) with nothing fine-tree-specific about it, and R9's `vectors_report` executor and its regenerator test both import it from G15's module because re-implementing it would be worse. Move it to `test_util::vectors` beside the other cross-kind helpers (`hex`, `decode_hex`, `prefix_len`) and leave a re-export or update the two call sites. Deliberately deferred out of R9: `vectors.rs` had three concurrent editors in M0 wave 5 (F12, F13, R9) and a gratuitous move there would have cost a merge for no functional gain.
- Accept:
  - `first_difference` lives in `test_util::vectors`; `vectors_fine_tree` and `vectors_report` both use it from there
  - Its own unit test (`first_difference_locates_the_field`) moves with it
  - No behaviour change: every vector executes identically, digests unchanged
- Notes: Surfaced at R9 (M0 wave 5).

### R32 — Bump `REPORT_VERSION` to 1 and re-emit R9's vectors at the format freeze
- Milestone: M0
- Size: S
- Deps: R9 (landed); Q14 (the freeze gate); D29
- Spec: Format stability (line 123); M0 milestone (line 153); Verification — golden vectors (line 167)
- Do: `REPORT_VERSION` is `0` today and D29 §8 says plainly that **Q14 freezes `1`**. `report_version` is the first field of every serialized report, so that bump changes the pinned bytes of **every** case in `testdata/vectors/v1/report/verification-reports.json` — 21 of them. Q14's checklist (tasks/Q.md) currently says "all M0 golden vectors committed and frozen" without naming this one coupled edit, which is exactly the kind of thing a freeze gate discovers at the worst moment. Bump the constant, re-emit (`cargo test -p antseal-core --features test-util --test report_vectors -- --ignored emit_report_vector_document`), re-run `scripts/vector-freeze.sh --update`, and add the row to Q14's checklist so the ordering is recorded rather than remembered.
- Accept:
  - `REPORT_VERSION == 1` and every committed report vector pins bytes beginning `{"report_version":1`
  - The freeze manifest shows 21 *changed* digests in one commit whose message names D29 §8 as the cause — a changed digest is a format event and must read as one
  - Q14's checklist carries the row, so a future report-format bump cannot land without its vector re-emit
- Notes: Surfaced at R9 (M0 wave 5). Must land **before** Q14 flips `status frozen`, since after the freeze `--update` refuses to modify an existing digest and the same change becomes a report-format version bump instead of a pre-freeze re-snapshot.

### R33 — Decide whether `unit_commit` mismatch deserves a cause discriminator, or close it the way D81 closed the AEAD
- Milestone: M0 (before Q14 — it is a code-set question)
- Size: S (a record, and either zero or one code)
- Deps: R8 (landed); reads `docs/decisions/D81-unit-decrypt-cause.md`
- Spec: Tamper matrix (line 168); single authoritative commitment (line 94); Format stability (line 123)
- Do: R8 found a **third** collision of D81's exact shape, one commitment layer up, and discharged it as the recorded non-row `pipeline-level-wrong-unit-salt` on the argument that a salted commitment opening is one bit: the verifier recomputes `SHA-256(0x02 ‖ unit_salt ‖ bytes)` and compares, and a mismatch cannot attribute itself to a substituted bundle `unit_salt` rather than to an altered manifest `unit_commit`, because both are inputs to the one comparison. That argument is sound and is asserted by a named test, but unlike D81 it has **no decision record**, and the code set freezes at Q14. Either ratify the non-row in a short record (the expected outcome — it is the same argument, and D81's four candidate discriminators have no analogue here), or find the discriminator and mint the code before the freeze. Note the asymmetry that makes it worth a look rather than a rubber stamp: unlike the AEAD, both inputs to this comparison are *structurally* attributable — the salt is bundle-side and the commit is manifest-side, and the manifest is **signed**. A verifier that ran the signature stage first could say which side was altered. That is precisely the trade the frozen stage order rejects (Files before Signatures, so a content failure reports as a content failure), so the answer is very likely "no code" — but the reasoning should be written down rather than inferred from R8's module docs.
- Accept:
  - A decision record, or a recorded ratification of the existing non-row, before Q14
  - If a code is minted, it is appended (never an edited expected code), and `pipeline-level-wrong-unit-salt` becomes a row in `tamper_rows_pipeline`
  - If not, `docs/testing/error-code-contract.md` §7's R8 entry is the citation and the non-row's `record` field points at the ratifying record rather than at the registry
- Notes: Surfaced at R8 (M0 wave 5). The generalisation worth keeping either way, already recorded in the contract: R's codes name the *check that failed*, not the field that was wrong — so any check that is a single comparison over several inputs (AEAD tag, commitment opening, Merkle root) cannot carry a cause.
  **DONE 2026-07-28 (M0 wave 7) — outcome: no code minted, the non-row ratified.** D85 was authored in wave 6's planning round and RESOLVED the question; **neither** of the two Accept bullets was actually in the tree, so both were applied here, not merely verified. (1) `testdata/tamper/MATRIX.json`'s `pipeline-level-wrong-unit-salt` had `record: "This registry, and docs/decisions/D81-… for the argument's shape…"` — it now reads `docs/decisions/D85-unit-commit-cause.md`, and D85's supplementary sentence is appended to the entry's `why`; two changed lines, no other field, no row, no count. (2) `docs/testing/error-code-contract.md` §7 had **no** D85 or R33 entry; the dated one is appended before `**Formal freeze**`. D85 §4's module-doc citation in `test_util/tamper_rows_pipeline.rs` is applied too. Evidence: `tests/tamper_matrix.rs` green (25 tests), Q14 gate prints `M0 tamper matrix: COMPLETE (0 pending)`, `EXPECTED_NON_ROWS` unchanged at six, `scripts/vector-freeze.sh` **GREEN** (zero changed digests), R's variant meta-test still asserts **27**, no `VerifyError` variant gained a field and no `code()` arm changed. **Deviation from D85's verbatim, deliberate**: the §7 entry is labelled *wave 7*, not wave 6 — D85 anticipated landing in the wave it was written in, §7 is chronological, and wave 6's F26/D86 and G22 entries already sit between F15 and the freeze line. **Not done here**: D85 §5's three salt-route tests, which are the record's own falsification and are carried by **R51**; they are not in this entry's Accept and they need a `Tweak` knob in a fixture file other wave-7 lanes are in.

### R34 — Extend R10's structure-aware mutators to the sections R6 cannot currently vary
- Milestone: M0
- Size: S
- Deps: R10 (landed), R6
- Spec: M0 milestone — parser hardening, fuzzing in CI (line 153); Risks — hostile bundles (line 187)
- Do: R10's structure-aware mutation set works on encoded bundle bytes (bit-flips, truncations, prefix/suffix splices) plus R6's typed `Tweak` knobs. What it cannot yet do is *section-level* recombination that stays decodable — swap the `covered_reveals` and `noncovered_reveals` arrays wholesale, move a `full_reveals` entry between files, or graft one work's `storage_record`/anchor section onto another work's bundle — because R6 builds a bundle in one pass and exposes no re-assembly seam. Those are exactly the inputs a hostile relay can cheaply produce, and they exercise decode-then-cross-check paths that byte-level mutation reaches only by luck. Add a builder seam (a `BundleParts` round-trip on R6's output, or a decode→mutate→re-encode helper) and drive it from both the proptest and the fuzz target.
- Accept:
  - Section-level recombination mutators that produce *decodable* bundles, so the mutation lands past stage 1 rather than dying at the codec
  - Both the in-suite proptest and the fuzz target consume them; the no-panic and typed-outcome invariants are unchanged
  - Cross-work grafts included (one work's manifest, another's reveals), since that is the shape no single-work fixture can produce
- Notes: Surfaced at R10 (M0 wave 5). R10 deliberately shipped without it rather than blocking on a builder change; the fuzz target's `Corpus::Reject` accounting means adding mutators later cannot silently reduce coverage.

### R35 — Record and assert that `.sealproof` bundles are not union-closed
- Milestone: M0 (the property + its assertion); the UX half is M3
- Size: S
- Deps: R4, R5, R6 (landed); D28, D74
- Spec: Reveal bundle — evidence layer (lines 112–114); Verifier structural invariants (line 121); Format stability (line 123)
- Do: D28's strictness has a consequence in the add-material family that no record states. Take two honest bundles of the *same* work from the same sealer — bundle A reveals units `{1,2}` of a three-unit file `F`, bundle B reveals `{3}`. Neither is a full reveal, so neither carries `F`'s `file_salt` or `s_root`, correctly per R4 rows 1–2. Merge them (any relay can: the reveal sections are plain arrays that need only re-sorting to satisfy F8's strict ascent) and the merged bundle reveals all of `N(F)`, so `full(F)` holds and R4 row 3 fires with `full-reveal-material-missing-file-salt`. **The union of two valid bundles is not necessarily a valid bundle**, and the material that would make it valid is derivable only from `W`. This is the *right* failure — the merged bundle really does lack what a full reveal must carry, and it fails loudly with a named code rather than verifying a false claim — but it is unstated, and a relay can use it to turn two valid bundles into one invalid one (a denial-of-evidence nuisance; both originals still verify). Assert it as a property so the behaviour is pinned rather than incidental, and record the product consequence: an M3 "combine these bundles" affordance is **not implementable client-side**, because only the sealer can widen a reveal.
- Accept:
  - A named property over R6's fixtures: for any two reveal selections of one work whose union is a full reveal of some file but neither of which is, the merged bundle fails with `full-reveal-material-missing-file-salt` (and `full-reveal-material-missing-s-root` where the file has a fine tree)
  - The complementary positive: merging two selections whose union is *still* partial for every file verifies — so the property is about the material, not about merging
  - The residual is written into `docs/decisions/D74-extraneous-full-reveal-s-root.md` (already appended) and cross-referenced from D28
  - The M3 consequence is recorded against R13/R16 so a reveal-combining UX is never designed on the assumption it can work offline
- Notes: Surfaced 2026-07-28 by wave 6's D74 re-audit. Not a soundness defect and **not** a reason to relax D28 — relaxing is the illegal direction (line 123) and would delete the `canon_commit`/`raw_commit` check entirely (D28 rationale 1). The point is that the property should be a pinned fact, not a surprise found at M3.

### R36 — Restate R10's authentication-boundary equality once D83 lands
- Milestone: M0 (before Q14)
- Size: S
- Deps: R10 (landed); **D83 must resolve first**; D75
- Spec: Verification — tamper matrix (line 168); Risks — hostile bundles (line 187); storage is the bonus, not the proof (line 119)
- Do: `the_unauthenticated_region_at_m0_is_exactly_the_storage_record` (`crates/antseal-core/tests/verify_fuzz.rs:176`) asserts as an **equality** that the only unauthenticated bytes in an anchor-free M0 bundle are the 88-byte storage record, on the strength of a one-off exhaustive sweep of all 7891 bytes of `valid-multi-file-mixed`. The equality is true of that corpus and **false in general**: D83's inert leaf-level cover-seed tails are a third unauthenticated region — 16 bytes per cover node whose `level == d`, which the GGM walker never reads (`content/fine_tree/ggm_walk.rs:95, 207`). It has not been caught because no R6 fixture produces a leaf-level cover node: the `[0, n)` decomposition contains a size-1 block **iff `n` is odd**, and every fixture length and split boundary is even (`CRLF_TEXT` canonicalizes to 34, `data/blob.bin` is 30 split 10/10/10, `notes/split.md` is 34 split 12/12/10). Once D83 resolves, restate the boundary: if D83 shortens the wire form or canonicalizes the tail, the equality becomes true in general and its doc comment should say *why* rather than resting on one corpus; if D83 accepts the malleability, the test must name the third region explicitly, the way it already names the storage record and the anchor artifacts.
- Accept:
  - The test's claim is scoped to what it actually proves, or generalised because D83 made it general — never left reading as universal while being corpus-dependent
  - If D83 accepts the malleability, the third region is located by content (as the storage record already is), sized, and asserted; the `88 + 67` bound in `byte_changing_mutations_outside_the_inert_regions_are_rejected` gains its third term
  - The doc comment records the `n` odd ⇒ leaf-level-node rule, so the corpus dependence cannot silently return
- Notes: Surfaced 2026-07-28 by wave 6's D75 re-audit (`docs/decisions/D75-full-reveal-cover-shape.md`, wave-6 amendment). Strictly ordered **after** D83 and **before** Q14 — the freeze should not ship a boundary statement that one added fixture falsifies. Landing R37 before this makes the test go red, which is the analysis confirmed, not a regression.
  — **[2026-07-28] CORRECTION, at source:** this entry's own incidence rule is **wrong**. It says the `[0, n)` decomposition contains a size-1 block *iff `n` is odd*; D83 §1 Fact 1 measured that a whole-file cover **never** decomposes — it is the single root node for every `n` — so an unsplit odd-length file discloses no leaf-level node at all, and the entry's reasoning about "every fixture length" is beside the point. The governing rule is D83 §1 Fact 2, `d == 0 ∨ a odd ∨ (b odd ∧ b < n)`, over **unit** boundaries: `CRLF_TEXT` → 34 and `split.md` 34 split 12/12/10 are exempt because their *boundaries* are even, not because 34 is.
  — **[2026-07-28] DONE.** D83 resolved as option B, so the branch this entry calls "the equality becomes true in general" is the one that applies and **Accept bullet 2 must NOT be discharged** — there is no third term to add. Landed: (1) a third exhaustive sweep over all 32 bytes of a real leaf-level payload in a real bundle, asserting the rejection *class* per half (`0..16` → `fine-root-binding-failed`, `16..32` → `fine-root-leaf-seed-tail-not-zero`) — all 32 reject, so the region is authenticated, measured rather than argued; (2) the doc comment says *why* the equality generalises and records Fact 2 verbatim; (3) `byte_changing_mutations_outside_the_inert_regions_are_rejected` keeps its bound at exactly `88 + 67` and now records that this is a D83 *result*, over a corpus that (since G24) contains leaf-level payloads. The test did **not** go red.

### R37 — Add the leaf-level-cover reveal shapes R6's catalogue cannot produce
- Milestone: M0
- Size: S
- Deps: R6 (landed), R7, R10; interacts with D83, D75
- Spec: Cryptography — GGM fine tree (line 96); Verifier structural invariants (line 121); Verification — golden vectors (line 167)
- Do: R6's fixture catalogue has no bundle containing a **leaf-level** GGM cover node (`level == d`), so an entire class of proof shape is unexercised end to end — including the one D83 is about and the one R2's Accept list names as a required edge vector. Every fixture length and split boundary is even, and a leaf-level node appears in a `[0, n)` decomposition iff `n` is odd. Add (a) an **odd-length** fine-tree text file, whose full reveal ships a leaf-level cover node under D75's "both" rule, and (b) the **one-byte** fine-tree file, where `d = 0` so the whole cover is the single node `(0,0)` whose seed *is* `s_root` — meaning a full reveal carries the same 32 bytes twice, in §7.11 key 3 and §7.14 key 2, with (today) independently unconstrained upper halves. Also add an odd split boundary so the shape appears in a *partial* reveal, not only a full one. These are fixture additions, not new rules: they must verify.
- Accept:
  - The catalogue contains at least one shape whose covered reveal includes a node with `level == d`, asserted directly rather than assumed from the file length
  - The one-byte fine-tree file verifies as a full reveal, and its `s_root` and its single cover seed are pinned as the same value in the honest fixture — so any future divergence is visible
  - R7/R9's registries and vectors are extended, not edited: existing fixture bytes and digests are unchanged, new ones are added
  - The interaction with R36 is stated in the commit: if D83 has not yet resolved, adding these shapes is expected to turn `the_unauthenticated_region_at_m0_is_exactly_the_storage_record` red, and the correct response is R36, never a widened tolerance
- Notes: Surfaced 2026-07-28 by wave 6's D75 re-audit. The reason the gap survived five waves is that "even" is the natural thing to type in a fixture; the fix is one odd number, and the class it unlocks is roughly half of all real files.
  — **[2026-07-28] CORRECTION, at source:** clause (a) is **wrong as written**. An odd-*length* file's full reveal ships no leaf-level cover node: by D83 §1 Fact 1 a whole-file cover is the single root node for every `n`, so the exposure comes from an odd **unit boundary** (D83 §1 Fact 2, `d == 0 ∨ a odd ∨ (b odd ∧ b < n)`), which D75-BOTH then surfaces once per unit. Clause (c)'s "also add an odd split boundary" is therefore not an extra — it is the mechanism, and (a) collapses into it. The exposure is ~75 % of ranges, not "roughly half" (D83 §1 Fact 3). Clause (b) was also already half-satisfied: `shapes::one_byte_file` and the catalogue case `one-byte-file/full` existed since R6, and R9's report vector already carried it; what was missing was the **bundle vector** and the **fuzz corpus**.
  — **[2026-07-28] DONE.** Two new R6 shapes (`odd_split_multi_unit`, 35 canonical bytes split 11/11/13 — D83 §1 Fact 5's own worked row; and `unbalanced_n6_odd_split`, the same six leaves retiled 2/1/3) and four catalogue cases. `tests/leaf_level_cover_shapes.rs` states the result as a pinned census read off **decoded cover addresses** against `d`, never inferred from a file length; pins `cover[0][2] == full_reveal.s_root` at `n == 1` as one value; and re-derives Fact 2 exhaustively from `minimal_cover` (to `n = 128` in the default lane, `n = 512` offline, zero mismatches — which discharges D83 §9.6). All 21 pre-existing R30 report digests reproduce byte-for-byte and no committed vector moved in R37's own commit; the bundle vector moves in G24, for D83 reasons.

### R38 — Give R6's works a per-work storage record
- Milestone: M0 (found) / **post-freeze, see the constraint below**
- Size: XS to change the constructor; the cost is entirely in what moves with it
- Deps: R6 (the constructor), R34 (which found it and deliberately declined to work around it)
- Spec: Storage is the bonus, not the proof (MVP-SPEC.md lines 118–119, 180); verifier structural invariants (line 121); hostile bundles (line 187)
- Discovered by: **R34** (2026-07-28). **This entry was itself missing** — TODO.md carried the one-liner and `tasks/R.md` never gained the detail entry; written up in wave 7 after the freeze, which changes what the task can do.
- The fact, verified. `crates/antseal-core/src/test_util/bundle_fixtures.rs:1337-1343` builds the record inline inside `fn assemble` from three literals — `ContentAddress::from_bytes([0x5E; 32])`, `ManifestNonce::from_bytes([0x5A; 24])`, `Key32::from_bytes([0x5C; 32])`. It is a function of nothing: not of `spec`, not of `spec.seed`, not of any `Tweak` (all 26 knobs are at `:431-553` and none touches it), and `WorkSpec` (`:315-327`) has no field for it. Corroborated in committed bytes: `testdata/vectors/v1/bundle/bundle.json` carries ten `storage_record` objects with exactly one distinct value each.
- **Correction to the one-liner.** "A cross-work graft … is a *provable* no-op" overstates what is on the tree: **there is no storage-record graft to run.** R34 declined to add one and recorded why, at `crates/antseal-core/src/test_util/bundle_mutators.rs:297-303` — *"There is deliberately no storage-record graft. R6 gives every fixture the same constant storage record, so grafting one across works is a provable no-op — a corpus entry that duplicated its own target under a name claiming otherwise."* `Recombination::all()` has nine entries (`bundle_mutators.rs:342-366`) and none touches `parts.storage_record`. So the no-op is a **counterfactual**; what is provable today is only its antecedent. The deliverable is therefore not "fix a broken mutator" but "make one worth adding".
- Why the section is worth a graft at all: its M0 inertness is a product claim, not an implementation detail — MVP-SPEC.md line 118 (*"storage is the product's bonus, not its proof"*), line 119 (the linkage layer is separate), line 180 (Risks, same words). In code, `verify/pipeline.rs:65-69` states it and `pipeline.rs:437` sets `StorageLinkageResult::NotEvaluated`, an enum with exactly one arm (`verify/report.rs:234-237`); R20, which replaces it, is M3. And the boundary is already asserted **by content**: `crates/antseal-core/tests/verify_fuzz.rs:230` `the_unauthenticated_region_at_m0_is_exactly_the_storage_record` locates the exempt region by searching for those `0x5E`/`0x5A`/`0x5C` patterns (`:236-241`), asserts `exempt.len() == 88`, and then flips all 88 bytes requiring `Outcome::Verified`. A graft would say the same thing at section granularity instead of byte granularity.
- **The constraint the freeze adds, and it is the whole reason to read this entry before starting.** `vectors_bundle.rs`, `vectors_manifest.rs` and `vectors_report.rs` all build on `bundle_fixtures`, so changing the record for the catalogue's existing works moves `testdata/vectors/v1/bundle/bundle.json` and, through the manifest and report emitters, potentially two more frozen rows. Once Q14 flips `#! status frozen`, `scripts/vector-freeze.sh --update` refuses exactly that. So the shape of the fix is fixed by the freeze: **derive the record per work while leaving every catalogue shape that feeds a committed vector on today's constant**, or add the varying record only on shapes that feed no vector. A change that re-emits `bundle.json` is not available and should not be attempted.
- Do: give `WorkSpec` a storage-record input derived from the work — `spec.seed` is already there, and `alternate_test_secret(label)` (`test_util/mod.rs:245-251`, `W' = SHA-256(label ‖ W)`) is the existing per-work-material device — with the vector-feeding shapes pinned to the current bytes. Then add the `GraftStorageRecord` variant beside the eight at `bundle_mutators.rs:265-366` and let `no_cross_work_graft_verifies_except_the_m0_inert_anchor_section` (`:1080`) classify it: it belongs in the *verifies* arm with `GraftAnchors`, because M0 inertness is precisely what it should demonstrate.
- Accept:
  - Two fixtures of different works have different storage records — asserted, not assumed.
  - `GraftStorageRecord` produces a bundle that differs from its target (`every_recombination_but_the_control_changes_the_bundle`, `bundle_mutators.rs:1030`, is the assertion that would have failed today) **and still verifies**. That pair is the M0 property stated as a test rather than as prose.
  - `the_unauthenticated_region_at_m0_is_exactly_the_storage_record` still passes. It finds the region by byte pattern, so a per-work record means it must find a *different* pattern per fixture — that test is the one thing this change can break, and making it still hold is the work.
  - **No committed vector digest moves.** `scripts/vector-freeze.sh` green without `--update`; if a digest moves, the change escaped its scope.
- Notes: `Recombination` is `#[non_exhaustive]` (`bundle_mutators.rs:265`), so a new variant is additive — but two assertions must be revisited with it: `unrepresentable_recombinations_are_named` (`:1054`) pins the unrepresentable set to exactly one name, and `crates/antseal-core/tests/verify_fuzz.rs:704` asserts `recombined >= 8`. R5's separate hand-built record (`verify/pipeline.rs:1474`, `0x77`/`0x78`/`0x79`) is deliberately outside R6's catalogue per R29 and stays that way.

### R39 — Key R6's per-work material on the work, not on the ordinal under one shared `W`
- Milestone: M0 (found) / **post-freeze, see the constraint below**
- Size: S
- Deps: R6 (the constructor), R34 (which found it); C2's frozen HKDF label registry bounds the solution
- Spec: Per-work master secret `W` (MVP-SPEC.md line 89); HKDF derivation (line 77); verifier structural invariants (line 121); sealer-as-adversary (line 121)
- Discovered by: **R34** (2026-07-28), recorded as wave-6/7 carry-forward finding (5): *"No fixture-built test can currently distinguish another sealer's material from this work's."* **This entry was itself missing** — TODO.md carried the one-liner and `tasks/R.md` never gained the detail entry; written up in wave 7, and the write-up corrects the title.
- The fact, verified. `bundle_fixtures.rs:650-652` — `fn w() -> MasterSecretRef<'static> { MasterSecretRef::from_bytes(&TEST_MASTER_SECRET_W) }` — takes no argument and ignores the spec. `seal_id()` (`:654-656`) is the same shape over the constant `FIXTURE_SEAL_ID` (`:164-167`). Every derivation in the fixture is then `(shared W, ordinal)`: `derive_file_salt`/`derive_path_salt`/`derive_fine_seed` on `FileId` at `:983`, `:984`, `:1005`, `:1131`, `:1239`, `:1247`, `:1267`, `:1290`, `:1310`; `derive_unit_salt`/`derive_unit_key` on `UnitId` at `:1057`, `:1120`; `encrypt_unit` at `:925`; `public_keys`/`sign_body` at `:1031`/`:1047`. The consequence is written down where it bit — `bundle_mutators.rs:699-706`: *"two different works that both fully reveal their file 0 emit byte-identical `full_reveals` entries, and a 'cross-work' graft of that section moves nothing."*
- **Correction to the title, and it changes the fix.** "Key the material on the **work**, not the ordinal" reads as a change to the derivation. It is not, and must not be: the frozen construction is `info = u8(len(label)) ‖ label ‖ LE64(id)` (MVP-SPEC.md line 77; `crates/antseal-core/src/crypto/hkdf.rs:19-34`, `Label::ALL` at `:123-132`, id domains at `:165-171`), which carries **no work-identity term at all** — in production too. Work separation comes entirely from `W` being per-work (MVP-SPEC.md line 89). Adding a label or an info term is a format event on a registry that is now frozen. **R6 is not diverging from the real derivation; it is diverging from the real *key management*, by using one `W` for every work.** The fix is a per-work `W` (and/or a per-work `seal_id`), which is what `bundle_mutators.rs:705-706` says verbatim. `work_id` is not an option and never was: `work_id = SHA-256(body)` (line 75) does not exist at derivation time, and MVP-SPEC.md line 90 records that making the AAD depend on the manifest *"would create a dependency cycle and make sealing impossible"*.
- The gap this leaves open, confirmed by search: **no fixture-built test asserts rejection of another sealer's material.** The one cross-work test that exists — `no_cross_work_graft_verifies_except_the_m0_inert_anchor_section` (`bundle_mutators.rs:1080`) — distinguishes its two works by section **shape**, not by material: `recombination_pair()` (`:719-729`) picks a donor that fully reveals *two* files against the target's one, and `:709-712` records that this was necessary precisely because the material collides. So the test is sound and proves something narrower than its name suggests.
- **The constraint the freeze adds.** `w()` feeds every fixture, and `vectors_bundle.rs`, `vectors_manifest.rs` and `vectors_report.rs` all build on `bundle_fixtures`. Changing `w()` for the catalogue's existing shapes re-derives every unit key, salt, commitment, ciphertext and signature in them, moving `bundle/bundle.json`, `manifest/manifest.json` and `report/verification-reports.json` at once — three frozen rows that `--update` refuses once `#! status frozen`. So the only available shape of the fix is **additive**: existing shapes keep `TEST_MASTER_SECRET_W`; a per-work secret is introduced for works that feed no committed vector, or as a new opt-in `WorkSpec` field defaulting to today's constant. Sequence this before anything asserts cross-work rejection, as the one-liner says — but sequence it *inside* that constraint, not around it.
- Do: add a per-work secret source to `WorkSpec` (`bundle_fixtures.rs:315-327`) defaulting to `TEST_MASTER_SECRET_W`, thread it through `w()` and `seal_id()`, and give at least one donor shape a genuinely different `W`. Then write the test the register says does not exist: a graft of that donor's `full_reveals`/`covered_reveals` into the target must be **rejected** on material, with a named code, rather than merely differing in shape.
- Accept:
  - A donor exists whose per-file material is byte-different from the target's for the same `file_id` — asserted directly, since that equality is the defect.
  - A cross-work graft of a reveal section is rejected with a named error code, and the test says which; the existing shape-based test keeps working and keeps its narrower claim.
  - **No committed vector digest moves** — `scripts/vector-freeze.sh` green without `--update`.
  - The frozen HKDF registry is untouched: no new label, no new info term, no change to `crypto/hkdf.rs`'s `Label::ALL`.
- Notes: The register's phrase "collide on ordinals" is accurate but easy to misread as a defect in the derivation. It is not — collision under a shared `W` is the correct and intended behaviour of a per-work secret used for two works. Record that in the fix, so the next reader does not go looking for a bug in `hkdf.rs`.

### R40 — Add the non-covered→covered migration D83 unblocked
- Milestone: M0
- Size: XS
- Deps: R34 (the seam and the eight existing variants), G23/D83 (which removed the stated blocker)
- Spec: Cryptography — GGM fine tree (MVP-SPEC.md line 96); verifier structural invariants (line 121); hostile bundles (line 187)
- Discovered by: **R34** (2026-07-28), which omitted the direction and said why. **This entry was itself missing** — TODO.md carried the one-liner and `tasks/R.md` never gained the detail entry; written up in wave 7.
- The premise, verified and still exact. `Recombination::MigrateCoveredIntoNonCovered` (`crates/antseal-core/src/test_util/bundle_mutators.rs:319`) is one-directional, and the omission is reasoned at `:313-318`: *"the reverse — migrating non-covered entries into `covered_reveals` — would have to fabricate cover entries, and a fixture that hard-codes the cover-seed wire shape is a fixture that breaks when that shape changes."* **D83 is what changed.** It resolved as option B (the canonical zero tail: a `level == d` payload is `salt ‖ 16 zero bytes`, `docs/decisions/D83-leaf-cover-seed-tail-malleability.md` §0) and G23 landed the shape as a *public library function* — `canonical_leaf_level_payload` (`crates/antseal-core/src/content/fine_tree/cover.rs:393`, re-exported at `content/mod.rs:77`). So the mutator no longer has to hard-code anything: it can ask the library for the wire form, which is exactly the condition R34 named.
- Do: add the inverse variant beside `MigrateCoveredIntoNonCovered` at `bundle_mutators.rs:265-366`, building each fabricated cover through `prove_range` and `canonical_leaf_level_payload` rather than through a literal. It is the *section-level* form; the single-unit form already exists as R6's `Tweak::misplace_noncovered_unit` (`bundle_fixtures.rs:553`, doc at `:546-552`), which borrows a real cover and is the right model for what the section form must produce.
- Accept:
  - The new variant produces a **decodable** bundle (`every_representable_recombination_decodes`, `bundle_mutators.rs:1003`) that differs from its target (`every_recombination_but_the_control_changes_the_bundle`, `:1030`).
  - It is **rejected** by `verify_bundle` with a named code, and the test says which — a non-covered unit presented as covered is a structural claim about the fine tree, and the point of the mutator is that it dies for that reason rather than at the codec.
  - No cover byte is written by a literal; every fabricated cover comes from the library, so a future change to the payload shape moves this mutator automatically. That is the property D83 bought.
  - The seed-corpus accounting moves with it: `unrepresentable_recombinations_are_named` (`:1054`) pins the unrepresentable set to exactly one name and `crates/antseal-core/tests/verify_fuzz.rs:704` asserts `recombined >= 8`; both are `#[non_exhaustive]`-safe but neither is automatic.
- Notes: The register's "now D83 has settled the cover encoding" is right, and the entry above records *why* it matters rather than only that it does — the blocker was never the direction, it was the literal. Also note the corpus-naming hazard **R43** owns: seed files select corpus entries positionally, so inserting a recombination in the middle re-points named seeds. Land this after R43, or regenerate the seed corpus wholesale in the same commit.

### R43 — Make the `verify_bundle` fuzz seeds name their corpus entry instead of indexing it
- Milestone: M0
- Size: S
- Deps: R10, R34 (both landed); Q9's fuzz CI wiring consumes the corpus
- Spec: Verification — tamper matrix (line 168); Risks — hostile bundles (line 187)
- Do: `testdata/fuzz-seeds/verify_bundle/` holds 196 two-byte files, each a `(corpus index, mutation kind)` selector (`test_util::codec_fuzz::verify_bundle_seeds`). The index is **positional**, so inserting a seed anywhere but the end silently re-points every later file at a different bundle: G24 added three corpus entries and 133 committed seeds changed meaning while keeping their names, so `tamper-corrupt-ciphertext--mutation-3.bin` now drives a different fixture than the one its name claims. Nothing catches this — the round-trip test only checks that identity entries are two bytes and that the count matches. The same fragility sits in `tests/verify_fuzz.rs`, where `corpus()[0]` appears twice as a stand-in for `valid-multi-file-mixed`. Replace the positional selector with a **name-derived** one: hash the seed's `&'static str` name to an index at load time, or emit the name into the seed file and resolve it in the driver. Either way a corpus insertion must leave every unrelated seed's meaning unchanged.
- Accept:
  - Inserting a new corpus entry in the middle changes only the new seeds' bytes — asserted by a test that builds the corpus twice, once with an extra entry spliced in, and requires every shared name to resolve to the same bundle
  - `corpus()[0]` and any other positional corpus reference in `verify_fuzz.rs` is replaced by a lookup by name, which fails loudly if the name is gone
  - The fuzz driver's behaviour on an unknown/stale name is defined and typed (it parses adversarial-shaped input from disk — a missing name is a report, not a panic)
- Notes: Discovered 2026-07-28 while landing G24. Not a correctness bug today — every committed seed still decodes to *a* valid input, and the corpus is regenerated wholesale by an emitter — but it silently destroys the triage value of a crash name, which is the only reason the seeds carry names at all. Cheap now, and much harder once a real crash corpus exists.

### R41 — Make a wasm32 `--lib` test failure say which test failed
- Milestone: M0
- Size: S
- Deps: P14 (the runner), R32 (which is how it surfaced)
- Spec: Verification — the WASM build must bit-match native verification (MVP-SPEC.md line 167/169); no CLI/page divergence (line 73)
- Discovered by: **R32** (2026-07-28). Its fourth coupled site, `EXPECTED_CANONICAL_JSON` in `verify/mod.rs`, was enforced by nothing else, passed every other lane, and failed on `wasm32-core-tests` as a bare `the test binary trapped: unreachable` — no test name, no assertion, no message, because stdout is discarded on that target and a panic aborts the module.
- Do: Fix `scripts/wasm-test-runner.mjs` so a failure names its test. Constraints that must survive: the module has **zero imports** (verified per run); the harness keeps executing the real `#[test]` functions; and D18 stays free — no wasm-bindgen, no crate-type change, no JS surface committed to the product. The in-memory execution witness is the precedent for getting information out without stdio.
- Accept:
  - A deliberately failing `#[test]` under `--target wasm32-unknown-unknown` reports its name.
  - The zero-import property still holds and is still asserted.
  - `wasm32-core-tests` stays green otherwise.
- Notes: **DONE 2026-07-28 (M0 wave 7).** Nothing was added to the crate and no import was introduced: **linear memory survives the trap**, and the program has already written the diagnosis into it. (1) libtest writes `test <name> ... ` before invoking a test body and `ok\n` after it; `stdout` on this target is a discarding sink *behind std's line buffer*, so the flushing newline never arrives and the buffer still holds the line for the test that was running at the abort. (2) The default panic hook's record — `panicked at <file>:<line>:<col>:` plus the payload — is on the heap. The runner reads both from the exported `memory` and filters by the exported **`__heap_base`** global, which is what makes it sound: every test name and the panic format string are static literals in the data section, so an unfiltered scan reports decoys and can name the wrong test. Zero or several candidates are reported as such rather than guessed. Measured on a failing build: one progress line and one panic record above `__heap_base`, three decoys correctly below. Planted-fault self-test: `scripts/wasm-tests.sh --self-test` builds a throwaway crate **outside the repo** (so it inherits neither `.cargo/config.toml`'s runner nor `rust-toolchain.toml`) with one passing and one failing `#[test]`; red under all three faults tried — diagnostic lost, attribution wrong, `__heap_base` filter dropped — and green unmodified. Follow-up **R52**: the run-order assumption this rests on.

### R42 — Carry `REPORT_VERSION`'s coupled-edit row into Q14's checklist, negative clause included
- Milestone: M0 (before Q14)
- Size: XS
- Deps: R32 (which produced the corrected content), Q37 (which wrote the row this corrects), D29 rule 8
- Spec: Format stability (MVP-SPEC.md line 123); Verification (line 167)
- Discovered by: **R32** (2026-07-28), whose implementation disproved the row already in the checklist. **This entry was itself missing** — TODO.md carried the one-liner and `tasks/R.md` never gained the detail entry; written up in wave 7 at the point of ticking it.
- What was wrong before. Q37 had written a row naming **three constants that must all move to 1**: `antseal_core::verify::report::REPORT_VERSION`, `wasm_bitmatch::TRANSCRIPT_VERSION` and `EXPECTED_TRANSCRIPT_VERSION` in `scripts/wasm-bitmatch.mjs`. R32 established on evidence that two of those three are an **independent axis** — the transcript versions the bit-match *envelope*, which carries no report field, aggregates all seven vector kinds, is written to `target/`, appears in no `FROZEN.sha256`, and never meets `--update`'s changed-digest refusal — and that a real coupled site had gone unnamed: D29's `EXPECTED_CANONICAL_JSON`, enforced by nothing and mute on wasm32. A checklist row that is wrong in the direction of "bump this too" is worse than a missing one: following it would have moved a constant that must not move, at the gate that makes it permanent.
- Do: replace the row with the corrected form, keeping the history visible rather than silently rewriting it — a checklist that changed its mind without saying so is one a reviewer cannot audit.
- Accept:
  - Q14's checklist names every site that moves with `REPORT_VERSION`, including the one R32 found.
  - The **negative** clause is stated as a clause, not implied by omission: the transcript constants stay `0` through this gate, with the reason.
  - The rule R32 recorded — the transcript version moves on a **field** change, never on a change in what the fields contain — is written where the next bumper reads it.
- Notes: The register's framing of "four sites" and the checklist's "three sites" are the same set counted differently: R32 counts `REPORT_VERSION` itself (TODO.md's R32 line, and commit `5395f6f`), the checklist counts only the things that move *with* it. The doc comment on the constant (`crates/antseal-core/src/verify/report.rs:44-71`) uses the checklist's numbering. Cite whichever, but not both in one sentence.
- **[2026-07-28] DISCHARGED, wave 7** — landed at commit `88526bb` ("Q14 checklist: correct the report-version row — the third constant is a NEGATIVE") and never ticked; verified rather than redone. The row is `tasks/Q.md:215-253`, headed *"**Three** sites, and the third is a deliberate NEGATIVE"*: site 1 the 21 pinned strings in `testdata/vectors/v1/report/verification-reports.json` with its re-emit command (`:219-224`); site 2 `EXPECTED_CANONICAL_JSON` in `crates/antseal-core/src/verify/mod.rs`'s `tests`, recorded as enforced by nothing else and as the wasm32 bare-trap case (`:225-232`); site 3 the negative, verbatim **"NOT `wasm_bitmatch::TRANSCRIPT_VERSION` and NOT `EXPECTED_TRANSCRIPT_VERSION`"** with the envelope argument and the field-change rule (`:233-247`), plus a closing gate instruction to confirm by `grep` rather than memory (`:249-251`). Q40 carries the matching `SUPERSEDED IN PART` banner. Verified live at HEAD: `REPORT_VERSION` is `1` (`verify/report.rs:72`), `EXPECTED_CANONICAL_JSON` still exists at `verify/mod.rs:350` and begins `{"report_version":1`, and both transcript constants still read `0` (`crates/wasm-bitmatch/src/lib.rs:104`, `scripts/wasm-bitmatch.mjs:30`) — now machine-asserted at both sites by Q53's `transcript_version_is_still_zero_at_both_sites` (`crates/wasm-bitmatch/tests/bitmatch.rs:352`), whose failure message names the negative clause directly. So the row is not merely written down; its negative half is the only one of the three that a test can break.

### R51 — D85's own falsification: the salt route at the other three commitment sites
- Milestone: M0 (before Q14 — it can falsify a record Q14 freezes)
- Size: S
- Deps: R33/D85 (ratified), R6's `Tweak` knobs, R7/R8's row set
- Spec: Tamper matrix (MVP-SPEC.md line 168); single authoritative commitment (line 94)
- Discovered by: **R33** (2026-07-28), splitting D85's ratification bookkeeping from D85's owed evidence. D85 generalises "a salted-commitment opening cannot carry a cause" from `unit_commit` to **four** sites, and §5 of the record says plainly that the generalisation is only *checked* at one of them: `unit_commit` has the D81 pairing (a recorded non-row plus a named test for the demoted route), the other three have their manifest-side route as a row and their **salt route asserted by nothing**. D85's own words: "If any of the three turns out to reach a *different* code from the one tabled, stop and report it — that would mean the site is not the collapse D85 claims, and D85's generalisation would need amending before Q14 rather than after."
- Do: Add the three named tests D85 §5 tables, in `crates/antseal-core/src/test_util/tamper_rows_pipeline.rs`'s `tests` module, modelled exactly on `the_wrong_unit_salt_route_reaches_the_same_code`: `d85_the_wrong_path_salt_route_reaches_the_same_code` (→ `path-commit-mismatch`), `d85_the_wrong_file_salt_route_reaches_the_concat_code` (text file → `concat-commit-mismatch-canon`), `d85_the_wrong_file_salt_route_on_a_binary_file` (→ `concat-commit-mismatch-raw`). If R6's `Tweak` has no `path_salt`/`file_salt` substitution knob, add one beside `wrong_unit_salt` (`test_util/bundle_fixtures.rs`); never hand-edit encoded bytes.
- Accept:
  - Each mutation substitutes a **genuine, correctly sized** salt from elsewhere in the same work — never random bytes and never a wrong length, which R3's group 1 catches earlier and which would assert nothing about the commitment.
  - None of the three is added to any registry slice: each would claim an outcome an existing row owns, and `check_registry` must keep refusing the pair. Each doc comment says so and cites D85.
  - Each of the three lands on its tabled code, reported individually. If any lands elsewhere, stop: amend D85 before Q14, never edit the expected code (error-code contract §3).
- Notes: No committed artifact moves — the fixtures are built at runtime from R6's builder, so no golden vector, no `vector-freeze` digest, and no `.sealproof` fixture is affected. If a digest moves, the change escaped scope. R33 deliberately did **not** do this: its Accept names only the two bookkeeping items, and adding a `Tweak` knob touches a fixture file other wave-7 lanes are in.

### R52 — The wasm32 post-mortem rests on two toolchain behaviours nothing pins
- Milestone: M0 (record) / on every toolchain bump (act)
- Size: S
- Deps: R41 (landed), P14, `docs/toolchain.md`'s bump procedure
- Spec: Verification (MVP-SPEC.md line 167); no CLI/page divergence (line 73)
- Discovered by: **R41** (2026-07-28), while making it work. The runner recovers the failing test's name from **libtest's `test <name> ... ` progress line sitting unflushed in std's stdout line buffer**, and the assertion from **the default panic hook's formatted record**. Both are behaviours of the pinned toolchain, not of anything this repository controls: if a future `std` makes `wasm32-unknown-unknown`'s stdout unbuffered, or libtest changes its progress-line shape, or the panic hook's format moves, the diagnostic disappears. It disappears **loudly** — the runner reports "0 libtest progress lines were found above `__heap_base`" rather than naming the wrong test — but a toolchain bump would silently give back the bare trap that R32 hid behind, and nothing would notice until the next real failure.
- Do: Add `./scripts/wasm-tests.sh --self-test` to the toolchain-bump checklist in `docs/toolchain.md` (and to whatever Q36's upstream-bump chore executes), so a bump that costs the diagnostic is caught by the bump, not by the next incident. Consider making the self-test unconditional in the `wasm32-core-tests` lane rather than an on-demand check — it costs one small `cargo build` for a dependency-free crate, which is the same trade `scripts/wasm-bitmatch.sh --self-test` already took when it made its divergence probe a **permanent per-run** guard.
- Accept:
  - The toolchain-bump procedure names the self-test explicitly, with the reason (this entry).
  - A recorded decision on unconditional-per-run vs on-demand, with the measured cost of the extra build.
  - The runner's fallback message stays honest: zero or several candidates must never be resolved by guessing.
- Notes: The **`__heap_base`** dependency is the sturdiest part — it is wasm-ld's, not std's, and the runner already refuses to attribute anything without it. The fragile parts are the two textual shapes. A crate-side alternative (a panic hook writing a magic-prefixed record into a static) would pin the *message* but still not the *name*: libtest sets no thread name on this target and passes the description to nothing observable, so the progress line really is the only place the running test's identity exists at trap time.

### R53 — The two raw-mirror consumers disagree, and the report claims a mirror nothing checked
- Milestone: M0 (post-freeze residue)
- Size: S
- Deps: R4, R5, F40
- Spec: raw-mirror↔canonical binding (MVP-SPEC.md line 121); D23 clause 3; D28
- Discovered by: the **2026-07-31 adversarial code review** (findings 1–3 `high`, finding 8 `medium`).
- Problem: two defects on one seam.
  1. **First-wins vs last-wins.** `check_full_reveal_content` (`verify/file_stages.rs:1119`) resolves "the mirror" with `.iter().find(…)` — first wins, and only that one gets row 9 (`raw_commit` opening) and row 10 (`canonicalize_v(raw) == canonical`). `reveal_set` (`verify/pipeline.rs:930`) assigns `raw_mirror` in a loop with no break — **last wins**, and that is the one the report names. On a two-mirror file the checked mirror and the reported mirror are different objects.
  2. **`raw_mirror` is emitted for partial reveals.** `report.rs:416-419` documents it as full-reveal-only with `raw_size` = "the raw file size", but its producer gates it on `revealed_ids.contains(unit_id)` alone — while `fully_revealed`, two lines below at `pipeline.rs:982`, *does* consult `is_full()`. The asymmetry is the bug. `check_raw_mirror` is reachable only via `check_full_reveal_content`, which `check_file_stages:1161-1163` invokes only for `FileRevealShape::Full`, so on a partial reveal the report carries a mirror whose bytes were never opened against `raw_commit` (no `file_salt` exists) and never canonicalization-bound. A renderer following the documented meaning shows an attacker-chosen document as "the original file".
- Do: For (1), make the two consumers share one resolution — a single accessor both call — so they cannot drift again even if F40's rule were ever relaxed; a comment asserting they agree is not sufficient (that is exactly what D23 clause 3 was). For (2), gate the `raw_mirror` arm on the same `is_full()` the sibling field already consults, or — if a partial-reveal mirror is genuinely wanted in the report — give it a field name and doc that state it is unbound, and record why the weaker datum is worth emitting.
- Accept:
  - One resolution path for "the file's mirror", used by both the check and the report; a test that would go red if a second one appeared.
  - A partial reveal carrying a mirror produces a report that either omits `raw_mirror` or marks it unverified — pinned in a golden vector.
  - A report vector for the two-mirror case (post-F40 it is a rejection; the vector pins *which* code).
- Notes: F40 makes (1) unreachable from decoded input. Do it anyway: `reveal_set` and `file_stages` are independently reachable through the pub API, and the review's whole thesis is that unenforced agreements between two components are what rot. (2) is independent of F40 and is the live one.

### R54 — Quadratic pre-authentication scans: the caps admit a product nothing bounds
- Milestone: M0 (post-freeze residue)
- Size: M
- Deps: R3, R4, F11
- Spec: D10 §5's frozen complexity table; parser caps (D10)
- Discovered by: the **2026-07-31 adversarial code review** (finding 6 `medium→low`, plus U1 and U3, same class at two more sites).
- Problem: stages 2 and 3 are built from nested linear scans over adversary-controlled counts, and the signature stage is **stage 5**, so none of that work is gated on any authenticator. D10 itself states in bold that both count caps are reachable simultaneously inside `MAX_MANIFEST_BYTES` (~10.2 MiB) — and **nothing bounds their product**. A legal ~8 MiB bundle declaring `MAX_FILE_COUNT` = 16384 and `MAX_UNIT_COUNT` = 65536 with *no reveals at all* forces ~10⁹ iterations in `check_tiling` (`structural.rs:277`) plus ~10⁹ more in `check_manifest_refs` (`structural.rs:205-213`) — the latter for a check that **cannot fail**, since `flatten_units` derives `file_id` from the enumerate index rather than from a wire field. Same shape at `file_stages.rs:746` (per-file loops rescanning the work-global unit table; ~1.9e10 scans on a *valid* at-cap bundle against ~18 MB of honest AEAD work) and at `bundle/schema.rs:1462` (tier-[X] cross-section rules, Θ(|noncovered|×|covered|), inside the stage D10 §5 labels O(input)). In the browser verifier this is a hang.
- Do: Index rather than reorder. Build the file→units map once per verification and share it across stages 2, 3, 4 and `reveal_set`; replace `file_exists`'s linear scan; make the cross-section rules set-based. Then either bound the product in D10 or state explicitly that it is unbounded and that the implementation is linear regardless. Re-check D10 §5's table against the code afterwards — the finding is partly that the table asserts a complexity the code does not have.
- Accept:
  - The at-cap no-reveal bundle above verifies in time linear in input, demonstrated by a measurement, not an argument.
  - `check_manifest_refs`' tautological arm is either removed or documented as unreachable-by-construction (see U17, which says the same of `proof_unit_refs`).
  - D10 §5's complexity table matches the implementation, row by row.
- Notes: **Stage 5 running last is correct and must not be "fixed"** — the manifest is self-signed, so an attacker can always mint a valid signature over a forged body and an earlier signature check would gate nothing. The review verified this explicitly. The defect is the scan shape, not the order.

## Open decisions (R)
- Verifier-page host + domain (one canonical URL) — decide with P/Q; blocks R26 (and the URL constant consumed by R16/R25); must land by M3 (domain availability checked pre-M0 per spec line 3).
- Footer build-hash mechanism (build-time injection into HTML vs runtime self-hash of the fetched wasm) and exactly which artifact set the published SHA-256 covers — blocks R25; by M3.
- `verify_bundle` error mode: fail-fast single distinct error (tamper-matrix authoritative) vs collect-all for rendering, and which the report exposes — blocks R1/R5/R7; by M0. — **[2026-07-27]** RESOLVED (D27): hybrid — fail-fast typed first-error (`Result<VerificationReport, VerifyError>`) is the sole normative mode the tamper matrix/Q7 bind to; `VerifyFailures` is rendering-only collection, primary-first by construction, first element must equal the fail-fast error (docs/decisions/D27-verify-error-mode.md).
- Confirm the derived strictness rule: a bundle revealing all of a file's non-mirror units MUST carry `file_salt` (+ `s_root` when a fine tree exists) or hard-fail (`FullRevealMaterialMissing`) — blocks R4/R7; by M0 (format-freeze relevant).
- Raw-mirror inclusion on whole-file reveals: always automatic (implemented default) vs a future opt-out — blocks R13/R16 final UX; by M3.
- Online-overlay ↔ headline presentation: exact layout for how a `--online`-promoted anchor supplies the headline while the offline cryptographic verdict stays distinct and visible — blocks R17/R18 (snapshots freeze it); by M3.
- `--json` report schema stability commitment (is the report schema versioned/stable for scripting from M3?) — blocks R21; by M3.
- CORS viability of the pinned esplora/Arbitrum endpoints from browsers (fallback/override policy if a default blocks browser fetch) — blocks R24; by M3.
- Disclosure-preview snippet length and binary-snippet format — blocks R15; by M3 (small).

## Cross-domain expectations
- F: strict RFC-8949-canonical bundle/manifest codec with typed structs, version dispatch, size/count/depth caps, empty-anchor support, encode API usable by R6/R13, raw-CBOR mutation helpers for tamper fixtures, and per-version vector layout.
- C: AEAD open/seal (XChaCha20-Poly1305, AAD), HKDF label derivations (`k_u`, `unit_salt`, `path_salt`, `file_salt`, `k_m`), salted commitment recomputation (`unit_commit`/`path_commit`/`canon_commit`/`raw_commit`), strict hybrid Ed25519+ML-DSA verification with full `sig_policy` enforcement, distinct signature-error variants, and the "hybrid (PQ)" vs "Ed25519-only" scheme datum; C owns the signature/`sig_policy` tamper rows run through my harness.
- G: `canonicalize_v` pinned to descriptor-recorded Unicode versions; leaf-exact GGM sub-cover + boundary Merkle path computation (builder side); range verification (salt derivation from cover, leaf rebuild, boundary-path check to `fine_root`) with over-broad/non-leaf-exact cover rejection; full fine-tree rebuild from `s_root` + bytes; the n=6 unbalanced and leaf-exact-cover M0 fixtures.
- S: deterministic self_encryption address recomputation as a WASM-safe `antseal-core` function; `StorageBackend::get_data` + `MockBackend`; devnet fixtures for R27; the M1 devnet E2E itself (which may call R11); the S15 persistence primitive under R11/R21.
- A: per-anchor offline state machine over all 7 states with verified times and artifact/fetch-date metadata (WASM-safe); anchor tamper rows (M2); online-confirmation primitives — must-agree pinned endpoint pairs (esplora ×2, Arbitrum RPC ×2), WASM-safe header-match/promotion core consumable from browser-fetched responses; pinned endpoint defaults; anchor artifact types stored in the vault; the opportunistic-upgrade hook invoked before reveal.
- U: clap surfaces for `reveal`/`verify` (flags `--all/--units/-o/--include-receipt/--yes/--online/--live`), confirmation-prompt + `--yes` utility, vault read APIs (manifest, `W`/derivation handle, staged ciphertexts, receipts, anchor artifacts, paths, addresses), canonical-URL printing in `reveal` output, `show` consuming R15's preview function, global `--json` plumbing.
- Q: CI infra — wasm32 build + test execution from day one, snapshot-test tooling, playwright job + static server, cargo-fuzz jobs, indefinite per-version vector retention; page release signing (minisign/cosign) + publication channel; docs carrying the canonical URL; host/domain decision partnership.
- P: workspace scaffolding for `verifier-web/` and the wasm-bindgen crate; exact toolchain pins (rustc, wasm-pack, wasm-bindgen) required for the reproducible build; product-name/domain reservation feeding the canonical URL.
