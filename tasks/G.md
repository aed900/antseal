# G — Content model: canonicalization, units, raw mirror, GGM fine tree

> Part of the antseal MVP task breakdown (generated 2026-07-27 from MVP-SPEC.md Revision 2 by a 9-agent decomposition).
> **Status tracking lives in `../TODO.md`** — do not add checkboxes here. Treat Do/Accept as normative until deliberately revised; spec line references are into `MVP-SPEC.md` as of 2026-07-27.
> Dep prefixes: P=setup/toolchain/pins, F=CBOR+manifest/bundle codecs, C=crypto primitives, G=canonicalization+units+GGM fine tree, S=storage/payments/journal/restore, A=anchors, R=reveal/verification/web page, U=CLI/vault/config/UX, Q=test-infra/CI/threat-model/docs/release.

### G1 — Pin the Unicode/NFC data version and ship its normalization table in antseal-core
- Milestone: M0
- Size: M
- Deps: P: workspace + `antseal-core` crate scaffold with wasm32 target and exact-pin dependency policy
- Spec: Canonicalization (MVP-SPEC.md lines 81–83), M0 milestone "pinned Unicode/NFC version" (line 153), Format stability (line 123)
- Do: Select the normalization implementation (candidates: `unicode-normalization`, ICU4X `icu_normalizer` with compiled data) and pin it exactly; determine from upstream release notes the exact Unicode data version it implements and freeze the descriptor version string (e.g. `unicode-16.0.0`). Architect a version-dispatch registry in `antseal-core` (`canonicalize_v(version, …)`) so future Unicode versions are *added* while every shipped table is retained forever under the format-stability policy; verifiers must be able to apply exactly the descriptor-recorded version, never "latest". Confirm the dependency is WASM-safe, deterministic, and free of I/O/non-determinism.
- Accept:
  - Exact-version pin in `antseal-core`'s Cargo.toml; documented crate-release → Unicode-data-version mapping verified against the crate's upstream changelog
  - Version registry resolves `unicode-16.0.0` (or chosen) and returns a distinct `UnknownUnicodeVersion` error for any unregistered string
  - `cargo build --target wasm32-unknown-unknown` passes with the dependency included
  - Freeze decision recorded (ADR/notes) including the retention obligation
- Notes: Upstream verification required: which Unicode version the pinned crate release actually ships (do not assume). Retention interacts with Q's format-stability policy doc (Q27).

### G2 — Implement canonicalization v1: text detection + canonical rendition transform with version dispatch
- Milestone: M0
- Size: M
- Deps: G1; U: `--force-text` flag plumbing (semantics defined here, flag surface is CLI's)
- Spec: Canonicalization (line 83), CLI surface `--force-text` (line 149), Verifier invariants raw-mirror recompute (line 121)
- Do: Implement `canonicalize_v(version, mode, raw_bytes) -> Result<CanonicalBytes>` in `antseal-core`: text detection = strict UTF-8 validity; forced-text mode per the force-text decision (must make text-mode canonicalization total and deterministic over arbitrary bytes so R's `canonicalize(raw) == canonical` recompute can always run). Pipeline (fixed order): decode → strip a single leading BOM (U+FEFF) → normalize line endings (CRLF and lone CR → LF) → NFC using the version-selected table → encode UTF-8, no BOM. Binary kind: no rendition (identity/none). The function is pure, panic-free on arbitrary input, and idempotent; it is the exact function R's verifier calls for the raw-mirror binding check.
- Accept:
  - Proptest: `canonicalize(canonicalize(x)) == canonicalize(x)` for arbitrary byte inputs (text and forced-text modes)
  - Unit tests: valid-UTF-8 detected text; invalid-UTF-8 detected binary; forced-text on invalid UTF-8 behaves per the frozen decision
  - KATs: leading BOM stripped, interior U+FEFF preserved, CRLF→LF, lone CR→LF, NFD input → NFC output
  - Unknown version string → distinct error; no panics on arbitrary bytes (proptest)
  - Compiles for wasm32-unknown-unknown
- Notes: Open decisions 1–2 below must be frozen before this task completes (canonicalization is frozen at seal time and recorded in the manifest). **[2026-07-27] Deliberate revision**: the Do-text's "strip a single leading BOM" is superseded by D21 — the implemented, frozen rule is strip the **contiguous leading run** of U+FEFF (idempotence requirement; docs/decisions/D21-canonicalization-micro-semantics.md).

### G3 — Build the M0 UTF-8 corpus with committed golden canonical outputs + idempotence/stability tests
- Milestone: M0
- Size: M
- Deps: G2; Q: multi-OS (linux/macos/windows) and wasm32 CI jobs to prove cross-platform stability and native/WASM bit-match
- Spec: Verification UTF-8 corpus (line 170), M0 milestone (line 153), testdata layout (line 57), golden vectors (line 167)
- Do: Create `testdata/utf8-corpus/` with input fixtures: CRLF and lone-CR files, NFD-vs-NFC pairs (Latin diacritics, Hangul, combining sequences), BOM'd files (leading BOM; interior U+FEFF), emoji/ZWJ sequences, mixed scripts (RTL + CJK + combining), already-canonical files, empty file, and invalid-UTF-8 samples (detection + force-text cases). Commit the expected canonical output bytes as golden fixtures. Write tests asserting output == golden, idempotence on every corpus file, and that each NFD/NFC pair converges to identical canonical bytes.
- Accept:
  - Corpus inputs + golden outputs committed under `testdata/utf8-corpus/`
  - All corpus tests pass byte-identically on linux, macos, windows CI and under the wasm32 test job
  - NFD/NFC pair convergence asserted; idempotence asserted per file
  - Harness fails if a corpus input lacks a golden output (coverage guard)
- Notes: No secret material in fixtures (project rule 6) — corpus is public text only.

### G4 — Canonicalization descriptor struct, construction decision logic, and cross-field validation
- Milestone: M0
- Size: S
- Deps: G2; F: deterministic-CBOR field encoding of the descriptor inside the manifest file table
- Spec: Canonicalization descriptor (line 83), manifest body fields (line 98), fine-tree default/opt-out (lines 18, 85)
- Do: Define `CanonDescriptor { kind: Text|Binary, fine_tree_present: bool, fine_tree_domain: Canonical|Raw (iff present), unicode_version (iff text) }` plus `describe_file(...)` deciding: kind from detection/force-text; presence = default true, false when `--no-fine-tree` matched or the file is empty (n = 0 → no tree); domain = canonical for text, raw for binary. Provide a validation predicate with distinct errors for every illegal combination (binary + canonical domain, text without unicode_version, present tree without domain, version on binary) for F/R to invoke at decode time. Document that verifiers recompute canonicalization with the descriptor-recorded version only.
- Accept:
  - Unit tests for each invalid field combination, each yielding a distinct error
  - Empty file → `fine_tree_present == false`; `--no-fine-tree` match → false and permanent (no override path exists in the model)
  - Rustdoc cites spec lines 83/85 for the "descriptor-recorded version, never latest" rule

### G5 — Unit model: types, work-global unit_id assignment, file-size semantics, unit_commit-presence predicate
- Milestone: M0
- Size: M
- Deps: G4; C: per-`unit_id` key/salt derivations consume these ids; F: unit-table CBOR encoding
- Spec: Definitions `unit_id`/`file_id` (line 76), Units (line 84), unit_commit presence (line 94), body fields incl. `size` semantics (line 98), Merkle/edge defs (line 78)
- Do: Define `Unit { unit_id: u64 (work-global LE64 ordinal), file_id, kind: Normal|RawMirror, byte_range, true_length }` and the assignment algorithm: one counter across all files in manifest order, mirror entries included at their frozen placement (see G7 / open decision 4). Encode the model rules: default one unit per file; binary always single-unit; `--no-fine-tree` file → exactly one whole-file unit; `true_length` = byte-range width for normal units; byte-ranges are canonical-byte offsets for text, raw offsets for binary; file-table `size` = leaf count = canonical byte count (text) / raw byte count (binary), with a text file's raw byte count carried only by its mirror's `true_length`. Implement `is_fine_tree_covered(unit, descriptor)` (true iff descriptor.fine_tree_present && kind == Normal) — this predicate drives the normative rule that `unit_commit` is present iff NOT covered, making `fine_root` the sole content commitment for covered bytes.
- Accept:
  - Regression test: two files each with multiple units → globally unique, strictly increasing `unit_id`s across files (guards the file-scoped-numbering identical-key/salt hazard, spec line 76)
  - Truth-table tests for `is_fine_tree_covered`: covered normal unit → no unit_commit slot; `--no-fine-tree` whole-file unit → commit present; raw-mirror → commit present; empty-file unit → commit present
  - Empty file → exactly one unit, byte-range [0,0), `true_length` 0
  - `size` semantics unit tests for text (canonical count) vs binary (raw count)
- Notes: "Permanently whole-file-reveal-only" for `--no-fine-tree` files falls out of the single-unit rule (its one unit = the whole file); no extra reveal predicate needed beyond G7's mirror rule.

### G6 — `--split blank-lines` paragraph splitting with precisely defined boundary semantics
- Milestone: M0
- Size: M
- Deps: G2, G5; U: `--split blank-lines` flag surface
- Spec: Units (line 84), CLI surface (line 149), M1 E2E uses `--split` (line 172), verifier tiling invariant (line 121)
- Do: Implement `split_blank_lines(canonical_bytes) -> Vec<Range<u64>>` operating on the canonical rendition (LF-only, so semantics are platform-stable): paragraph boundary = maximal run of blank lines per the frozen blank-line definition (open decision 3); separator bytes attach to the preceding unit (trailing blank run included), a leading blank run attaches to the first unit; no blank lines → one unit; all-blank file → one unit; empty file → one empty unit. Output ranges MUST be sorted, non-overlapping, and exactly tile [0, canonical_len) — this is what R's tiling invariant later checks. Splitting applies only to text files; binary and `--no-fine-tree` files are never split (per decision 5).
- Accept:
  - Proptest over arbitrary text: ranges sorted, non-overlapping, exact tiling of [0, len)
  - KATs: leading blank run, trailing blank run, consecutive multi-line runs, single-paragraph file, all-blank file, empty file
  - Determinism: identical input → identical ranges; boundary semantics documented in rustdoc verbatim enough to reimplement
  - Test that unit boundaries are byte offsets usable directly as fine-tree leaf ranges (leaf-aligned by construction)

### G7 — Raw-mirror model: detection, entry construction, exemption + selection predicates
- Milestone: M0
- Size: M
- Deps: G2, G5; C: `raw_commit`/`unit_commit` computation over mirror bytes; R: invariant + selection enforcement in the verifier/reveal; S: `restore` consumes the mirror to write exact originals; U: reveal selection UX
- Spec: Raw mirror (line 92), body fields (line 98), bundle contents (line 114), structural invariants (line 121), restore flow (line 37)
- Do: Implement `needs_mirror(raw, canonical) -> bool` (byte inequality — the CRLF/BOM/NFD cases) and mirror-entry construction: `kind = RawMirror`, its own work-global `unit_id` at the frozen placement in manifest order (normal `k_u`/`unit_salt`/AAD derivation via C follows from the id), byte-range [0, raw_size) in the RAW domain, `true_length = raw_size`; never fine-tree-covered (⇒ unit_commit present via G5's predicate). Provide the predicates other domains enforce: `tiling_exempt(kind)` and `full_reveal_concat_exempt(kind)` (true for RawMirror — exempt from per-file tiling/overlap and full-reveal concatenation), and the selection rule `mirror_selectable(selection) -> Result` — includable only via whole-file reveal or `--all`; a bare `--units <mirror-id>` yields a distinct rejection error. Document the two verify paths (unit_commit opening always; `file_salt`-keyed `raw_commit` opening when proving exact original bytes; `canonicalize_v(raw) == canonical` binding executed by R using G2's function).
- Accept:
  - Unit tests: CRLF-only, BOM-only, NFD-only differences each trigger a mirror; raw == canonical → no mirror
  - Mirror entry fields exactly per spec (kind, domain, range, true_length); id assignment interleaves correctly with G5's global counter
  - Predicate tests incl. the bare `--units <mirror-id>` distinct-rejection value and both exemption predicates
  - Truth test: mirror is never `is_fine_tree_covered` (canonical fine tree does not cover the raw domain)

### G8 — GGM salt-tree derivation (0x06 children, MSB-first indexing, 16-B leaf salts)
- Milestone: M0
- Size: M
- Deps: G5; C: `s_root = HKDF(W, "fine-seed", file_id)` (32 B) supplied by caller; C: hash domain-tag registry constant `0x06` + SHA-256 primitive
- Spec: GGM fine tree (line 96), domain tags (line 79), M0 milestone (line 153)
- Do: Implement the salt tree as pure functions over an injected 32-B `s_root`: depth `d = ⌈log₂ n⌉` (n = file size field; n = 1 → d = 0), a complete binary tree with 2^d leaf slots independent of the content Merkle shape; `child(seed, b) = SHA-256(0x06 ‖ seed ‖ b)` for b ∈ {0x00, 0x01}; leaf `i` reached by the bits of `i` MSB-first (bit d−1 first); slots `i ≥ n` unused; `salt_i = leaf_seed[..16]`; `d = 0` → `salt_0 = s_root[..16]`. Define the canonical node-address type (bit-path/(level,index) — open decision 7, shared with covers and boundary paths; F owns its CBOR encoding). All derivation is deterministic, allocation-bounded, WASM-safe.
- Accept:
  - KATs incl. n = 1 (`salt_0 = s_root[..16]`) committed as code-level vectors (golden files land in G15)
  - MSB-first pinned: at n = 6 (d = 3), leaf 2's path is bits (0,1,0) — asserted explicitly
  - Proptest (small n): leaf seeds pairwise distinct; sibling children differ; re-derivation deterministic
  - wasm32 build passes; no derivation of unused slots in any public output path

### G9 — Streaming fine-tree construction with O(log n) memory + verifier-side `rebuild_fine_root`
- Milestone: M0
- Size: L
- Deps: G2 (domain bytes), G4 (domain rule), G8; C: domain-tag constants `0x00`/`0x01`
- Spec: Fine tree (lines 85, 96), Merkle defs (line 78), full-reveal rebuild (line 121), M0 milestone (line 153)
- Do: Implement single-pass streaming construction over the content bytes (canonical for text, raw for binary) with a chunked-feed API (no I/O in core): a DFS-amortized GGM co-traversal deriving each `salt_i` in amortized O(1) hashes using an O(d) seed stack, computing `leaf_i = SHA-256(0x00 ‖ salt_i ‖ LE64(i) ‖ byte_i)` and folding a Merkle frontier with `0x01` node prefix and RFC 6962-style unbalanced promotion, peak auxiliary memory O(log n). Edge cases: n = 0 → no tree (None); n = 1 → root = leaf. The identical function, taking a bundle-supplied `s_root`, is exported as `rebuild_fine_root(s_root, bytes)` — the rebuild primitive R's verifier executes on full-file reveals. Instrument hash-compression counting (test-only) to validate the ~5–7 compressions/byte model.
- Accept:
  - Proptest: streaming result equals a naive in-memory reference implementation for all n ∈ 0..~300 with random bytes
  - Chunk-boundary independence: identical `fine_root` regardless of how input is sliced across feed calls
  - n = 1 → root == leaf KAT; n = 0 → None
  - Instrumented compressions/byte within the 5–7 envelope for large n, including n just above a power of two (worst GGM padding)
  - wasm32 build passes; memory bound asserted structurally (stack/frontier length ≤ c·⌈log₂ n⌉) — full budget test is G18

### G10 — Fine-tree cost estimator function (~5–7 SHA-256 compressions/byte)
- Milestone: M0
- Size: S
- Deps: G9; U: prints the estimate in `seal` output for large files (M1 wiring, U15)
- Spec: Fine tree cost print (line 85)
- Do: Implement pure `estimate_fine_tree_cost(n) -> CostEstimate` returning estimated SHA-256 compressions (leaf hashes n + Merkle ~2(n−1) + GGM ≤ ~2·2^d bounded) and the per-byte factor, matching G9's instrumented accounting. Shape the return type for U's human-readable print at seal time.
- Accept:
  - Tests bracket G9's measured compression counts within the estimate for several n, incl. n just above a power of two
  - Documented formula in rustdoc referencing the 5–7/byte spec figure

### G11 — Leaf-exact minimal GGM sub-cover computation (normative no-ancestor-seed rule)
- Milestone: M0
- Size: M
- Deps: G8
- Spec: GGM cover normative rules (line 96), bundle sub-cover contents (line 114), M0 milestone (line 153)
- Do: Implement `minimal_cover(range [a,b), n, d) -> Vec<NodeAddr>`: the maximal-subtree decomposition where every emitted node's REAL-leaf span (slots < n) ⊆ [a,b) — boundaries decompose to deepest single-leaf nodes; nodes additionally spanning only unused slots ≥ n are permitted (this preserves the ≤ 2·⌈log₂ n⌉ bound); range [0,n) → `[root]` (s_root). Pair addresses with derived seeds for bundle assembly (`cover_seeds(s_root, cover)`); serialization is F's. Enforce by construction: no output node is an ancestor of any unrevealed real leaf < n; `s_root` appears iff the range is [0,n) — the "no ancestor seed ever leaves the vault" rule.
- Accept:
  - n = 6, reveal {2}: exact expected node set (single-leaf node for slot 2)
  - n = 6, reveal [4,6): the node spanning slots [4,8) (real leaves 4,5 + unused 6,7) is emitted — positive case for the unused-slot allowance
  - Proptest over (n, range): |cover| ≤ 2·⌈log₂ n⌉; every in-range salt derivable (completeness); the derivable-salt closure contains NO `salt_j` for unrevealed j < n (soundness); s_root emitted iff full range
  - Full-range → exactly `[s_root]`

### G12 — Range-proof generation, with per-unit reveals routed through the same machinery
- Milestone: M0
- Size: M
- Deps: G9, G11; F: `RangeProof` (cover seeds + boundary paths) deterministic-CBOR encoding
- Spec: GGM range proofs (line 96), bundle per-covered-unit contents (line 114), M0 milestone (line 153), parking lot — arbitrary-range *selection* UX is v1.1, generation/verification are MVP (line 161)
- Do: Implement `prove_range(s_root, content_bytes, [a,b), n) -> RangeProof { range, cover: Vec<(NodeAddr, Seed)>, boundary_paths }`: recompute the tree (streaming) while collecting the minimal sibling node hashes — left and right boundary paths, correct under RFC 6962 unbalanced promotion including ranges touching the ragged right edge — needed to fold the range's rebuilt subtree roots up to `fine_root`. Implement `prove_unit(unit, …)` mapping a covered unit's byte-range to its leaf range and delegating — a per-unit reveal IS a leaf-aligned range opening, one code path, no special casing. Revealed bytes travel alongside per F/R's bundle layout; the proof struct carries range, seeds, paths.
- Accept:
  - Proptest: generate → G13-verify round-trips over random n/ranges incl. [0,n), single-leaf ranges, ranges at the unbalanced right edge; empty/reversed ranges rejected at generation
  - `prove_unit` output byte-identical to `prove_range` over the unit's range
  - Generated covers re-checked against G11's soundness property (no ancestor of unrevealed real leaf ships)
  - Proof-size bound asserted: ≤ 2·⌈log₂ n⌉ seeds and O(log n) boundary hashes

### G13 — Range-proof verification against `fine_root` (defensive, distinct errors, leaf-exact enforcement)
- Milestone: M0
- Size: M
- Deps: G8, G9, G11; F: decoded proof structs arrive from F's hardened CBOR layer; R: orchestrates this inside bundle verification and owns bundle-level structural invariants
- Spec: GGM verification (line 96), evidence layer (line 118), length checks (lines 96, 121), M0 "arbitrary byte-range verification exists and is M0-tested" (lines 96, 153), tamper matrix (line 168)
- Do: Implement `verify_range(proof, revealed_bytes, n, fine_root) -> Result<(), FineTreeError>`: length-check every cover seed (32 B) and boundary node hash (32 B); recompute the expected leaf-exact cover for the claimed range and require the proof's node set to match exactly — rejecting any over-broad cover (a node spanning an unrevealed real leaf, or `s_root` on a partial range); derive in-range salts, rebuild leaves (`0x00 ‖ salt_i ‖ LE64(i) ‖ byte_i`), fold with boundary paths to the root, compare to `fine_root`. Distinct error variants at minimum: `RootMismatch`, `OverBroadCover`, `WrongCoverShape`, `BadSeedLength`, `BadNodeHashLength`, `RangeOutOfBounds`, `ByteLenMismatch`. Defensive against adversarial values: huge claimed n vs actual byte length, reversed ranges, d capped (≤ 64), no panics, no unbounded allocation. The full-range case delegates to `rebuild_fine_root` (G9) — the function R uses for full-reveal checks.
- Accept:
  - Adversarial unit test per error variant; variants pairwise distinct (tamper-matrix requirement "distinct error")
  - Proptest: no panic on arbitrary/mutated proof struct fields
  - Verifies every G12-generated proof; rejects `s_root`-bearing covers for partial ranges
  - wasm32 build passes; native and wasm verdicts bit-match on G15 vectors (Q wires the CI comparison)

### G14 — Pure seal-side content-pipeline assembly (files + flags → ContentModel)
- Milestone: M0
- Size: M
- Deps: G2, G4, G5, G6, G7, G9; C: per-file `s_root` (and salt) supplier interface; F: consumes ContentModel to build the manifest body; S: seal flow + journal staging consume it at M1; U: passes flag inputs
- Spec: Seal flow order (line 34), crypto DAG (line 90), body fields (line 98)
- Do: One pure entry point: `(per-file raw bytes, flags { force_text, split: Option<BlankLines>, no_fine_tree_matched }, per-file s_root supplier) -> ContentModel { per file: descriptor, canonical rendition (text), mirror entry?, units with work-global ids, size/n, fine_root? }`. It enforces every model rule in one place — detection, canonicalization, splitting, single-unit binary/no-fine-tree, empty-file rule (one empty unit, no tree), mirror detection + placement, global id assignment, per-file fine-tree build over the correct domain — so the CLI never re-implements content rules. Deterministic: identical inputs → bit-identical model.
- Accept:
  - Golden end-to-end fixture committed: a small multi-file work (CRLF text file with `--split`, a binary file, a `--no-fine-tree` file, an empty file) with the full expected ContentModel (ids, ranges, descriptors, fine_roots) — using a fixed synthetic test seed supplier, clearly labeled test-only
  - Determinism test: two runs bit-identical
  - Property: every output satisfies G5/G6/G7 invariants (tiling, id uniqueness, mirror exemptions, commit-presence rule)
  - No I/O; wasm32 build passes

### G15 — Fine-tree/GGM golden vectors: unbalanced n = 6 (MSB-first pin) + edge cases
- Milestone: M0
- Size: M
- Deps: G8, G9, G11, G12; Q: vectors retained in CI indefinitely + wasm bit-match job; F: serialized-proof forms of the same vectors where F's encoding applies
- Spec: Verification (line 169: unbalanced-n golden vector), M0 milestone (line 153), Merkle defs (line 78), testdata (line 57)
- Do: Commit to `testdata/fine-tree/`: a fixed synthetic `s_root` and n = 6 content vector with every intermediate pinned — all GGM node seeds along used paths, every `salt_i` (pinning MSB-first bit order), each Merkle level under RFC 6962 unbalanced promotion, and `fine_root`; covers + boundary paths + full proofs for reveal {2}, reveal [4,6), and full [0,6); plus n = 1 (root == leaf), n = 0 (no tree), and one n just past a power of two (e.g. n = 5 or 9) exercising unused GGM slots. Include a generator test that regenerates and diffs, so drift fails CI.
- Accept:
  - Vectors committed; generator-diff test green; any construction/indexing change breaks the vector test
  - Native test suite consumes them; wasm32 run bit-matches native on every vector (Q CI)
  - Fixtures contain only synthetic, clearly-labeled test seeds — no vault-derived material (project rule 6)
  - Vector README documents MSB-first indexing as the pinned property

### G16 — Leaf-exact-cover disclosure test (n = 6, reveal {2})
- Milestone: M0
- Size: S
- Deps: G8, G11
- Spec: M0 milestone leaf-exact-cover test (line 153), GGM normative cover rule (line 96)
- Do: Implement the spec-mandated test: at n = 6, build the shipped cover for reveal {2}; enumerate every seed it contains; compute the full closure of salts derivable from those seeds; assert the closure contains `salt_2` and no `salt_j` for j ∈ {0,1,3,4,5}, and that `s_root` is absent. Add the companion positive case reveal [4,6) asserting the emitted node spanning unused slots {6,7} still discloses no real unrevealed salt.
- Accept:
  - Test in CI; regressing the cover algorithm to any merely-valid (non-leaf-exact) dyadic cover fails it
  - Documented in-test as the puncturing-soundness regression guard for the "no ancestor of any unrevealed real leaf" rule

### G17 — E2E opening test: leaf-aligned (per-unit) AND arbitrary byte-range both verify against `fine_root`
- Milestone: M0
- Size: M
- Deps: G12, G13, G14; C: salt/seed derivation used by the pipeline fixture; Q: wasm test job
- Spec: M0 milestone (line 153), Verification fine-tree E2E (line 169), GGM sole-commitment rule (lines 94, 96)
- Do: End-to-end in-core test: run G14's pipeline on a text file with `--split` (multiple units) and a binary file; produce (a) a per-unit opening via `prove_unit` and (b) an arbitrary, non-unit-aligned byte-range opening incl. one spanning a unit boundary; verify all against the manifest-committed `fine_root` via G13. Assert the per-unit case equals the range case on the same span (single machinery), and that covered units in the fixture carry no `unit_commit` (fine_root is the sole content commitment for covered bytes).
- Accept:
  - Both opening kinds verify green, native and wasm32
  - Unit-vs-range identical proof/verdict on the same span asserted
  - Cross-unit-boundary range verifies (demonstrates no per-unit commitment involvement)
  - Model assertion: `unit_commit` absent for every covered unit in the fixture

### G18 — Perf/memory budget tests for streaming construction
- Milestone: M0
- Size: M
- Deps: G9, G10; Q: CI job placement + threshold/variance policy
- Spec: Fine tree streaming (line 85), M0 milestone perf/memory budget (line 153), Verification (line 169)
- Do: Define and assert concrete budgets: (1) structural memory bound — instrumented frontier + GGM stack sizes ≤ C₁·⌈log₂ n⌉ during a large streamed synthetic input (largest CI-feasible size, e.g. ≥ 256 MiB streamed in chunks, with the structural assertion making the bound allocator-independent); (2) measured SHA-256 compressions/byte within the [5, 7] envelope, cross-checked against G10's estimator; (3) a generous wall-clock smoke ceiling tolerant of CI variance. Budgets are named constants with rationale.
- Accept:
  - Budget tests in CI failing on regression of memory shape or compressions/byte
  - Structural memory assertion (not RSS-based) passes at the large streamed size
  - Estimator-vs-measured agreement asserted (ties G10)
  - wasm32 run at reduced size, or documented native-only rationale (dep Q)
- Notes: Open decision 8 fixes C₁ and the corpus size.

### G19 — Fine-tree tamper-matrix rows with distinct errors
- Milestone: M0
- Size: S
- Deps: G13, G17 (fixtures); R: registration in the overall tamper-matrix harness; Q: matrix harness conventions (Q7/Q8)
- Spec: Tamper matrix (line 168), M0 milestone (line 153)
- Do: Implement the two G-owned rows against a known-good opening fixture: (1) flip a byte of a covered unit's revealed content → verification fails the `fine_root` leaf-range/boundary-path check (`RootMismatch`-class); (2) substitute an over-broad but dyadically-valid GGM cover whose node spans an unrevealed real leaf → `OverBroadCover`-class rejection. Assert error identity, not merely failure, and distinctness from each other and from every other G13 variant.
- Accept:
  - Both rows implemented with exact-error assertions
  - Rows registered in R's consolidated tamper matrix (dependency handoff recorded)
  - Distinctness asserted across the full G13 error enum
- Notes: Wrong-length salt/seed rows, structural rows (tiling, `true_length`, partial-reveal isolation, raw-mirror rows) are R's; G13's length errors give R the primitives.

### G20 — Consolidated content-model property-test suite (seeded, deterministic)
- Milestone: M0
- Size: M
- Deps: G2, G6, G9, G11, G12, G13; Q: proptest conventions, committed regression seeds, CI wiring (Q3)
- Spec: Verification property tests (lines 153, 167–170), working principles determinism
- Do: One seeded proptest suite consolidating the domain's invariants: canonicalization idempotence over arbitrary bytes; split tiling; GGM cover bound/completeness/soundness; prove→verify round-trip over (n ≤ 2^12, arbitrary ranges); streaming-vs-reference `fine_root` equality; a no-panic harness mutating proof structs into G13. Committed RNG seeds make runs deterministic; shrunken counterexamples are committed as named regression cases.
- Accept:
  - Suite green in CI with fixed seeds; every listed property present as a named test
  - Regression-case files committed for any counterexample ever found
  - Suite runs (possibly size-reduced) under wasm32 (dep Q)

## Open decisions (G)
- `--force-text` semantics on invalid UTF-8: deterministic lossy U+FFFD replacement (making text-mode canonicalization total — required so R's `canonicalize(raw) == canonical` mirror check can always recompute) vs. recording a forced-mode flag in the descriptor. Blocks G2, G3, G7, G14. Must land by M0 (canonicalization freeze). — **[2026-07-27]** RESOLVED (D20): lossy U+FFFD (Unicode §3.9 maximal subparts), total, **no descriptor flag** — `kind=Text` alone determines recompute semantics; R4's raw-mirror recompute must call `TextMode::Forced`; truncated-BOM → leading-U+FFFD corner KAT-pinned (docs/decisions/D20-force-text.md).
- Canonicalization micro-semantics: lone CR → LF (in addition to CRLF), strip exactly one leading BOM with interior U+FEFF preserved, and the fixed pipeline order (BOM → EOL → NFC). Blocks G2, G3. M0. — **[2026-07-27]** RESOLVED (D21) with one recorded deviation from this entry's proposal: strip **ALL** leading U+FEFF (contiguous run), not exactly one — strip-exactly-one violates G2's normative idempotence proptest on multi-BOM inputs; interior U+FEFF preserved; one-pass EOL (CR CR LF → LF LF); order decode → BOM → EOL → NFC frozen (docs/decisions/D21-canonicalization-micro-semantics.md). G3 must pin the double-BOM and BOM-only-file fixtures.
- Blank-line definition for `--split blank-lines`: whether whitespace-only lines count as blank; separator-attachment (trailing run to preceding unit, leading run to first unit). Blocks G6, G14. M0.
- Raw-mirror entry placement within manifest order (proposal: appended after the file's normal units) — affects work-global id assignment, frozen forever in the format. Blocks G5, G7, G14. M0.
- `--no-fine-tree` × `--split` on the same file: silently force single-unit vs. hard CLI error (model must be single-unit either way, per the unit_commit-only-for-whole-file-units rule). Blocks G5, G6, G14 (+U flag validation). M0.
- Normalization crate + exact Unicode data version + multi-version retention architecture (the G1 decision itself; needs upstream verification of the crate's shipped Unicode version). Blocks G1 and all canonicalization downstream. M0. — **[2026-07-27]** RESOLVED (D25): `unicode-normalization = "=0.1.25"` shipping Unicode **17.0.0** (verified from published crate bytes, `tables.rs` `UNICODE_VERSION == (17,0,0)`; machine-asserted in tests); frozen descriptor string `unicode-17.0.0`; retention = append-only registry, future versions vendored as distinctly named pinned crates, every shipped table retained forever (docs/decisions/D25-unicode-normalization.md).
- Canonical node-address representation for GGM covers/boundary paths ((level,index) vs bit-path) — semantic form is G's, CBOR encoding is F's; must be co-frozen with F. Blocks G8, G11, G12, G13. M0.
- Perf/memory budget constants (C₁, streamed corpus size, wall-clock ceiling, wasm reduced size). Blocks G18. M0.

## Cross-domain expectations
- P: workspace + `antseal-core` crate scaffold, exact-pin dependency policy, wasm32-unknown-unknown target configured from day one
- C: `HKDF-SHA256(W, label, id)` with the length-prefixed info encoding; `s_root = HKDF(W, "fine-seed", file_id)` (32 B) and unit/file/path salt derivations keyed by G's work-global ids
- C: the single hash domain-tag registry constants (0x00 leaf, 0x01 node, 0x06 GGM child, 0x02–0x05 commitments) and the SHA-256 primitive
- C: salted commitment functions (`unit_commit`/`raw_commit`/`canon_commit`/`path_commit`) computed over the bytes/domains G's model designates (incl. mirror bytes and the presence-iff-not-covered rule G5 supplies)
- F: deterministic-CBOR encodings + canonical-form decode rejection for the descriptor, unit table (kind/byte-range/true_length/size), RangeProof cover seeds + boundary paths, and their manifest/bundle placement
- R: verifier orchestration invoking `canonicalize_v`, `rebuild_fine_root`, and `verify_range`; bundle-level structural invariants (tiling with G7's exemption predicates, salt/seed length rows, `true_length` rows, partial-reveal isolation, full-reveal concatenation + fine-tree rebuild, raw-mirror `canonicalize(raw) == canonical` execution); consolidated tamper-matrix harness registering G19's rows
- R/U: enforcement of G7's mirror selection rule (bare `--units <mirror-id>` rejected) and reveal flows built on G's predicates
- U: CLI flags `--split blank-lines`, `--force-text`, `--no-fine-tree <glob>` (glob matching), the `--no-fine-tree` permanent-whole-file-reveal warning at seal, and printing G10's cost estimate for large files
- S: `restore` consuming the raw-mirror model to write exact original bytes; seal journal staging consuming G's unit model/ids
- Q: multi-OS + wasm32 CI proving cross-platform corpus stability and native/WASM bit-match on G's golden vectors; proptest/fuzz conventions; format-stability policy retaining shipped Unicode tables and per-version vectors indefinitely
