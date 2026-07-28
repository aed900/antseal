# F — Formats: deterministic CBOR, manifest & bundle codecs, parser hardening

> Part of the antseal MVP task breakdown (generated 2026-07-27 from MVP-SPEC.md Revision 2 by a 9-agent decomposition).
> **Status tracking lives in `../TODO.md`** — do not add checkboxes here. Treat Do/Accept as normative until deliberately revised; spec line references are into `MVP-SPEC.md` as of 2026-07-27.
> Dep prefixes: P=setup/toolchain/pins, F=CBOR+manifest/bundle codecs, C=crypto primitives, G=canonicalization+units+GGM fine tree, S=storage/payments/journal/restore, A=anchors, R=reveal/verification/web page, U=CLI/vault/config/UX, Q=test-infra/CI/threat-model/docs/release.

### F1 — Evaluate and exact-pin the deterministic CBOR encoder crate
- Milestone: M0
- Size: M
- Deps: P: workspace scaffolding + exact-pin policy execution (joint decision with P10)
- Spec: Definitions & encoding (MVP-SPEC.md line 73); Milestones M0 (line 153)
- Do: Evaluate the candidate `minicbor` (integer keys) for a concrete version against the RFC 8949 §4.2.1 profile: encoder emits shortest-form integer/length heads and definite lengths only; map-key emission order is caller-controlled so bytewise-sorted keys can be guaranteed; decoder exposes item-header/probe APIs sufficient for the strict-decode layer (F3) to detect non-shortest encodings and indefinite items; builds for `wasm32-unknown-unknown` with no I/O and no non-deterministic deps. Record the decision and pin the exact version (`=x.y.z`) jointly with P. Define the contingency: if no crate satisfies strict-decode probing, commit to a small in-house canonical CBOR reader/writer inside `antseal-core::codec`.
- Accept:
  - Decision record names crate + exact pinned version with test-snippet evidence for each profile requirement (shortest-form ints, definite lengths, controllable key order, header introspection, wasm32 build).
  - `Cargo.toml` pins with `=`; no second CBOR crate in `antseal-core`'s dependency tree (independent-implementation crate stays dev-tool-only, see F14).
  - Verification performed against the pinned version's actual docs.rs/source, not memory.
- Notes: Upstream-verification task by design. If derive macros cannot express the embedded-`body`-bstr envelope or strictness, F5–F9 assume manual `Encode`/`Decode` impls.

### F2 — Implement the canonical CBOR encode layer
- Milestone: M0
- Size: M
- Deps: F1
- Spec: Definitions & encoding (MVP-SPEC.md line 73)
- Do: Build `antseal_core::codec::encode`: helpers guaranteeing RFC 8949 §4.2.1 Core Deterministic output — definite lengths only, shortest-form integer and length heads, map keys emitted in bytewise-sorted order of their encoded form (registry uses only unsigned integer keys, so shortest-form numeric ascending order equals bytewise order — assert this equivalence in a test), no floats, no indefinite-length items. Output must be byte-identical across platforms and native/WASM. Provide no API path that can emit a float, an indefinite-length item, or an unsorted map.
- Accept:
  - Unit tests pin shortest-form heads at all integer boundaries (0, 23, 24, 255, 256, 2^16−1, 2^16, 2^32−1, 2^32, u64::MAX) and at bstr/tstr/array/map length boundaries.
  - Self-consistency: every encoder output passes the F3 strict decoder (test wired once F3 lands).
  - Sorted-key equivalence test (encoded-form bytewise order == ascending uint order for shortest-form keys) passes.
  - Sample-corpus outputs bit-identical native vs wasm32 (executed under Q's wasm CI job).

### F3 — Implement the strict canonical decode layer with a distinct-error taxonomy
- Milestone: M0
- Size: L
- Deps: F1, F2
- Spec: Definitions & encoding — decoder MUST reject non-canonical form (MVP-SPEC.md line 73); Tamper matrix distinct-error requirement (line 168); Milestones M0 (line 153)
- Do: Build `antseal_core::codec::decode`: a canonicality-enforcing reader over the pinned crate (or in-house per F1 contingency) that hard-errors on every rejection class of line 73: duplicate map keys; non-shortest integer encodings; non-shortest length-argument encodings; indefinite-length items (maps, arrays, strings, byte strings); map keys not in strictly-ascending bytewise encoded order (strict ascent rejects duplicates and disorder via two separate variants); floats and out-of-schema simple values; trailing bytes after the top-level item; invalid UTF-8 in tstr. Errors are a `thiserror` enum with one distinct variant per class, carrying position/context but never the byte content of secret-bearing fields. The same layer is invoked on the outer manifest, the outer bundle, the inner `body` bstr contents, and the bundle-embedded manifest bytes. Library code returns errors — no panics, no `unwrap`, on any input.
- Accept:
  - One unit test per rejection class × {outer envelope, inner body} proving the exact distinct variant is returned.
  - Duplicate-key and out-of-order-key produce two different variants.
  - Truncation sweep: every strict prefix (length 0..len−1) of a valid golden encoding returns a typed error, never panics.
  - `decode(encode(x)) == x` and `encode(decode(bytes)) == bytes` for canonical inputs.
  - Error `Display`/`Debug` output contains no field byte content (reviewed test over a secret-bearing fixture).

### F4 — Author the frozen v1 wire-format registry (keys, types, lengths, reserved slots)
- Milestone: M0
- Size: M
- Deps: F1; C: signature algorithm-ID set + pubkey/signature/commitment/key byte sizes; G: canonicalization-descriptor field set + GGM cover/path node-coordinate convention; A: anchor artifact envelope fields + status enum values; S: Autonomi address byte length verified against ant-core =0.5.0 (S1)
- Spec: Definitions & encoding (MVP-SPEC.md lines 71–79); Manifest body fields (line 98); Reveal bundle (lines 112–114); Format stability (line 123)
- Do: Write the normative in-repo registry document assigning every unsigned-integer map key for: manifest envelope, body, file-table entry, unit-table entry, bundle top level, and every bundle section; the CBOR type and presence rule of every field; exact byte lengths for all fixed-size fields (commitments/`s_root`/seeds/node hashes 32 B, salts/`seal_id` 16 B, XChaCha nonce 24 B, Bitcoin header 80 B, address length pinned from ant-core via S); the integer time encoding for claimed time and anchor fetch dates (no floats exist in the profile); the byte-range representation; the signatures-container encoding (enumerable, integer-keyed); anchor status enum wire values; the GGM sub-cover/boundary-path node encoding matching G's coordinate convention; and reserved key ranges for v1.1 sub-unit range covers and future use. Only unsigned integer keys are permitted (keeps bytewise ordering equal to numeric ordering). This document freezes as part of the M0 Definitions sign-off.
- Accept:
  - Every field named in spec lines 74–75, 98, and 112–114 has an assigned key, type, presence rule, and (if fixed-size) exact length — verified by a checklist mapping spec item → registry row.
  - Reserved v1.1 slots (sub-unit range covers + boundary paths) listed as reserved-not-accepted in v1.
  - A machine-readable table mirrors the doc; a test asserts code constants match it 1:1.
  - No negative or non-integer map keys anywhere in the registry.
- Notes: Address length must come from ant-core 0.5.0 source (via S1), not assumption. Decide here whether touched-file bundle entries carry an explicit `file_id` key.

### F5 — Define manifest body schema types + parse-time presence/shape validation
- Milestone: M0
- Size: M
- Deps: F3, F4; C: registered algorithm-ID list; G: descriptor value domain (kind, fine-tree presence/domain, Unicode version string)
- Spec: Manifest (MVP-SPEC.md line 74); seal_id (line 90); unit_commit presence rule (line 94); sig_policy parse-time rules (line 97); Manifest body fields (line 98)
- Do: In `antseal_core::manifest`, define `ManifestBodyV1` and sub-types covering every field: format version, app version, `seal_id` (16 B), title (tstr), claimed time (int, informational), pubkeys, `sig_policy`, file table {`path_commit`, `raw_commit`, `canon_commit`?, `size`, canonicalization descriptor, `fine_root`?}, nested unit table {`unit_id`, `kind` (normal | raw-mirror), byte-range, `true_length`, `unit_commit`?, nonce (24 B), ciphertext network address}. Implement parse-time validation with distinct error variants: `sig_policy` non-empty, duplicate-free, all IDs registered (hard parse error otherwise, per line 97); `canon_commit` present iff descriptor says text; `fine_root` present iff descriptor says fine-tree; `unit_commit` present iff the unit is not fine-tree-covered and absent otherwise (line 94); unknown `kind` rejected; exact byte lengths enforced on every fixed-size field. Semantic invariants (tiling/overlap, `true_length` = range width) are R's verifier checks, not parse-time — document the boundary in module docs.
- Accept:
  - Reject-tests, each a distinct error: empty `sig_policy`; duplicated `sig_policy` entry; unregistered algorithm ID; `unit_commit` present on a covered unit; `unit_commit` absent on a non-covered unit; `canon_commit` on a binary file; `fine_root` on a `--no-fine-tree` file; wrong-length `seal_id`/nonce/commitment/`fine_root`/address; unknown `kind`.
  - Accept-tests decode: text file with raw-mirror unit; binary single-unit; `--no-fine-tree` file; empty file (size 0, `true_length` 0); multi-file multi-unit (`--split`-shaped) body; ed25519-only `sig_policy` (reserved fallback shape).
  - All validation runs inside the strict-decode path so a schema-invalid body can never be constructed from bytes.

### F6 — Implement the manifest envelope codec with body-as-embedded-bstr semantics
- Milestone: M0
- Size: M
- Deps: F2, F3, F5
- Spec: Definitions & encoding — Manifest (MVP-SPEC.md lines 73–74)
- Do: Implement `Manifest` = deterministic CBOR `{body: bstr, signatures}`. Encode: serialize `ManifestBodyV1` to canonical bytes, embed as a bstr, attach the signatures container. Decode: strict-decode the outer envelope; expose `body_bytes() -> &[u8]` returning the exact received bstr contents (zero-copy) so `work_id` and signature verification operate on those bytes as received; then strict-decode the inner body from those same bytes (F3 + F5 — both layers reject non-canonical input per line 73). Provide no public API that re-encodes a decoded body for verification (verifiers never re-encode). The signatures container is enumerable so C/R can detect present-but-unlisted signatures; duplicate algorithm-ID entries are structurally impossible (map-key duplicate rejection).
- Accept:
  - Round-trip: encode → decode yields byte-identical `body_bytes()` and byte-identical re-encoded envelope.
  - Test: canonical outer + non-canonical inner body fails with the inner-layer F3 variant; non-canonical outer fails with the outer-layer variant — distinguishable.
  - Test against a hand-built vector proving `body_bytes()` equals the wire bstr contents exactly.
  - API review: no re-encode-for-verify path exists in the public surface.

### F7 — Implement `work_id` and `anchor_digest` as two distinct named functions
- Milestone: M0
- Size: S
- Deps: F6; P: pinned `sha2` crate
- Spec: work_id/anchor_digest (MVP-SPEC.md line 75); domain-tag non-collision note (line 79); Security assumptions — binding (line 100)
- Do: Implement `work_id(body_bytes) -> WorkId` = SHA-256(body) and `anchor_digest(manifest_bytes) -> AnchorDigest` = SHA-256(full encoded manifest, signatures included) as two distinct named functions returning distinct newtypes (lowercase-hex `Display`; CLI presentation is U's). Document why neither needs a registry domain tag: the leading byte is a CBOR header that cannot collide with tags 0x00–0x06 (line 79). Enforce the spec's naming ban: no `manifest_hash` identifier anywhere.
- Accept:
  - Golden vectors: fixed manifest fixture → expected `work_id` and `anchor_digest` hex committed to testdata and asserted.
  - Newtypes are non-interchangeable (API-shape or compile-fail test).
  - Test: mutating one signature byte changes `anchor_digest` but not `work_id`.
  - Repo-wide check (test greps source) that the identifier `manifest_hash` does not appear.

### F8 — Define `.sealproof` bundle schema types + parse-time shape validation
- Milestone: M0
- Size: L
- Deps: F3, F4; A: opaque artifact byte-envelope confirmation; C: `k_u`/`k_m` sizes; G: sub-cover/boundary-path node encoding
- Spec: Reveal bundle (MVP-SPEC.md lines 112–114); manifest storage record (line 98)
- Do: In `antseal_core::bundle`, define `BundleV1` covering every content item of lines 112–114: format version; plaintext manifest bytes (bstr); manifest storage record {address, nonce, `k_m`}; per-anchor artifacts (anchor type, status, `.ots` bytes + optional embedded 80-byte Bitcoin header + fetch dates, TSA token bytes + intermediate cert list, optional Arbitrum receipt record); per revealed fine-tree-covered unit {`unit_id`, `k_u`, embedded ciphertext, leaf-exact GGM sub-cover (seed + node-coordinate list), boundary Merkle paths}; per revealed non-covered unit {`unit_id`, `unit_salt`, `k_u`, embedded ciphertext}; per touched file {path, `path_salt`}; per fully-revealed file {`file_salt`, `s_root`}; reserved v1.1 slots for sub-unit range covers, rejected-if-present in v1. Parse-time shape checks with distinct errors: exact lengths (16-B salts, 32-B `k_u`/`k_m`/seeds/boundary node hashes, 24-B nonce, exactly-80-B header), valid-UTF-8 paths, well-formed section lists. `.ots`/DER/receipt internals remain opaque bstrs at this layer (A parses them); semantic rules (leaf-exact cover, partial-reveal isolation, `file_salt`/`s_root` presence policy) are R's — state so in module docs.
- Accept:
  - A checklist test maps every content item enumerated in lines 112–114 to a concrete field.
  - Reject-tests, each distinct: wrong-length `k_u`, `k_m`, `unit_salt`, `path_salt`, `file_salt`, `s_root`, cover seed, boundary node hash, nonce; header ≠ 80 B; invalid-UTF-8 path; reserved v1.1 key present; unknown section key.
  - Representable and decodable at schema level: empty-anchor bundle, zero-revealed-unit bundle, receipt present and absent, all anchor kinds present.
  - Nonces for revealed units are NOT bundle fields (manifest is the single source of truth, line 114) — checklist confirms absence.
- Notes: The GGM node-coordinate wire form must be fixed jointly with G in F4 before this freezes.

### F9 — Implement the `.sealproof` bundle codec with nested strict decoding
- Milestone: M0
- Size: M
- Deps: F6, F8
- Spec: Reveal bundle (MVP-SPEC.md lines 112–114); decoder strictness on outer bundle (line 73); Format stability (line 123)
- Do: Implement encode/decode for `BundleV1` through F2/F3. Decode pipeline runs three strict layers — outer bundle → embedded plaintext manifest bytes → F6 manifest decode (outer envelope + inner body) — with each layer's errors distinguishable. Encoding is deterministic: the same logical bundle always produces identical bytes (section ordering and list ordering rules per the F4 registry). This codec is the API surface R's M3 bundle builder and verifier consume; assembly/verification logic stays out of this crate module.
- Accept:
  - Round-trip byte-identity on fixtures covering: covered-unit reveal, non-covered-unit reveal, raw-mirror unit, full-file reveal (with `file_salt`/`s_root`), touched-file entries, every anchor kind, receipt in/out, empty-anchor bundle.
  - Test: canonical bundle wrapping non-canonical embedded manifest bytes fails at the manifest layer; canonical manifest with non-canonical inner body fails at the body layer; each reports its layer.
  - `encode` is deterministic across repeated runs and native/wasm32 (byte-compare).

### F10 — Implement version fields, per-version decode dispatch, and reserved-slot mechanics
- Milestone: M0
- Size: M
- Deps: F4, F5, F8, F9
- Spec: Format stability (MVP-SPEC.md line 123); format version body field (line 98); Milestones M0 (line 153)
- Do: Read version discriminants first (manifest body field; bundle top-level field); dispatch through a `version -> decoder` table with v1 as sole entry; unknown version returns a distinct `UnsupportedVersion{found, supported}` error — never a canonicality or unknown-key error. Structure per-version modules so adding v2 later cannot alter v1 byte behavior (v1 path frozen behind dispatch). Reserved registry keys present in v1 input fail with a distinct reserved-slot error naming the key. Establish the per-version golden-vector directory layout (`testdata/vectors/v1/…`) that Q's retain-forever CI consumes, and document the stability contract (every released version verifiable by all future releases) in module docs.
- Accept:
  - Tests: synthetic version-2 manifest and version-2 bundle each yield `UnsupportedVersion`, not any other error.
  - Tests: each reserved key injected into v1 input yields the reserved-slot error.
  - Versioned vector directory exists with a machine-readable index consumed by at least one test.
  - Doc states the line-123 policy; retention CI wiring referenced as Q's.
- Notes: Version-field placement inside the body bstr means version dispatch for the body happens after outer-envelope decode — the outer `{body, signatures}` envelope shape is frozen across versions; record this in F4.

### F11 — Enforce parser resource caps and allocation bounding
- Milestone: M0
- Size: M
- Deps: F3, F5, F8, F9
- Spec: Milestones M0 — parser hardening (MVP-SPEC.md line 153); Risks — hostile bundles (line 187)
- Do: Define frozen cap constants in one module: max bundle byte size, max manifest byte size, max unit count, max file count, max anchor count, max per-list lengths (cover seeds, boundary paths, certs), max CBOR nesting depth. Thread a depth/budget tracker through the decode layer; clamp every pre-allocation to `min(claimed_length, remaining_input)` so a length header can never drive allocation beyond input size. Caps behave identically native and wasm32 and are checked before any crypto work so hostile bundles fail cheaply.
- Accept:
  - Tests per cap: at-cap input passes, cap+1 fails with that cap's distinct error (size, unit count, depth, each list cap).
  - Adversarial allocation test: a small input claiming a huge bstr/array length is rejected without a large allocation (counting/limiting test allocator asserts peak).
  - Cap constants recorded in the F4 registry; a test asserts code == registry table.
  - Legitimate maxima fit with margin (e.g., 2·⌈log₂ n⌉ cover seeds at n = 10⁸ per line 96 sizing).
- Notes: Concrete cap values are an open decision — must be frozen at M0 because oversized/deep tamper fixtures (F15) encode them.

### F12 — Commit manifest golden vectors (per-version layout, native/WASM bit-match)
- Milestone: M0
- Size: M
- Deps: F6, F7, F10; C: test-only seed/signature material for fully-real vectors; Q: wasm bit-match CI harness + retention (Q5/Q6)
- Spec: testdata layout (MVP-SPEC.md line 57); Milestones M0 (line 153); Verification golden vectors (line 167)
- Do: Commit to `testdata/vectors/v1/manifest/`: canonical encoded bytes, a human-readable diagnostic sidecar (input to F14), and expected `work_id`/`anchor_digest` hex for at least: minimal single-file binary; text file with raw-mirror unit; `--no-fine-tree` file (carrying `unit_commit`); multi-file multi-unit body; empty-file unit; hybrid `sig_policy` and ed25519-only `sig_policy` variants. Field values use published, clearly-labeled test-only seeds/dummies of schema-correct lengths — never real secret material (project rule 6); fully crypto-consistent vectors additionally arrive from C/G through this codec.
- Accept:
  - Vector suite: decode each vector, re-encode, byte-compare; assert expected `work_id`/`anchor_digest`.
  - WASM build decodes/encodes every vector bit-identically to native (run under Q's CI).
  - Vectors README documents the test-only-secret convention.
  - Vectors registered in the F10 per-version index (retention forever is Q's CI).

### F13 — Commit bundle golden vectors including empty-anchor vectors
- Milestone: M0
- Size: M
- Deps: F9, F10, F12; G: fixture GGM sub-cover + boundary-path data; A: placeholder-opaque artifact bytes (real recorded fixtures land M2 via A25)
- Spec: Milestones M0 — empty-anchor vectors (MVP-SPEC.md line 153); Verification (line 167); Reveal bundle (lines 112–114)
- Do: Commit `testdata/vectors/v1/bundle/` vectors with sidecars: whole-work reveal; single covered-unit reveal (embedding G-supplied leaf-exact sub-cover + boundary paths); non-covered unit reveal; full-file reveal with raw-mirror and `file_salt`/`s_root`; the empty-anchor (UNANCHORED) bundle; a bundle with every anchor kind populated (opaque fixture bytes); receipt-included and receipt-excluded variants. Same decode/re-encode byte-identity and native/WASM bit-match discipline as F12.
- Accept:
  - Every vector round-trips byte-identically; WASM bit-match asserted.
  - The empty-anchor bundle vector exists and decodes (explicit M0 milestone bullet).
  - R's M3 verification tests can consume these vectors unmodified (interface handshake with R recorded).
- Notes: Anchor artifact bytes are schema-opaque placeholders at M0; A swaps in recorded real `.ots`/TSA fixtures at M2 with no schema change — flag this to A.

### F14 — Build the independent-CBOR cross-check artifact (jointly with Q)
- Milestone: M0
- Size: M
- Deps: F4, F12, F13; Q: CI job wiring + freeze-gate enforcement (Q11/Q14)
- Spec: Revision-2 pre-freeze mandate (MVP-SPEC.md line 5); Definitions & encoding — cross-check (line 73)
- Do: Using a second, unrelated CBOR implementation (open decision: e.g., Python `cbor2` script or a second Rust crate in a dev-only tool crate — must not enter `antseal-core`'s dependency tree), implement a checker that (a) decodes every F12/F13 golden vector and asserts structural equality against its diagnostic sidecar, (b) independently re-encodes per RFC 8949 §4.2.1 and asserts byte-equality with our bytes, and (c) independently validates canonicality (shortest forms, sorted keys, definite lengths) over our outputs. This is the mandated cross-check before the M0 freeze.
- Accept:
  - Cross-check green over all committed vectors.
  - Self-test: a deliberately non-canonical vector (non-shortest int) makes the checker fail — the checker is proven able to detect defects.
  - Documented as an M0 Definitions-freeze gate; CI wiring handed to Q.

### F15 — Author the format-level tamper-matrix fixtures with distinct expected errors
- Milestone: M0
- Size: M
- Deps: F3, F5, F6, F9, F10, F11, F12; Q: global tamper-harness runner consumes the mapping (Q7/Q8)
- Spec: Tamper matrix format rows (MVP-SPEC.md line 168); testdata layout (line 57)
- Do: Derive from golden vectors and commit to `testdata/tamper/format/` one fixture per row plus a machine-readable fixture→expected-error mapping table. Named M0 rows (four separate rows, per line 168): (1) duplicate map key in the body; (2) non-shortest int in the body; (3) indefinite-length item in the body; (4) trailing bytes after the body's top-level item; plus (5) oversized CBOR and (6) over-deep CBOR (two fixtures, two errors). Completeness fixtures for every remaining line-73 rejection class: out-of-order keys, non-shortest length head, unknown map key, reserved key, float, trailing bytes after the outer manifest, non-canonical outer bundle, non-canonical embedded-manifest layer. Include inner-body and outer-layer variants for the canonicality classes.
- Accept:
  - Local test: every fixture fails with exactly its mapped error variant; all format-row errors are pairwise distinct.
  - The four named body rows exist as four separate fixtures with four distinct errors; oversized ≠ over-deep.
  - Mapping table checked in and consumed by at least one in-repo test; format documented for Q's global harness.
- Notes: Wrong-length salt/seed rows, `sig_policy` rows, and structural-invariant rows belong to C/R even where my schema length errors underlie them — coordinate error naming with R and Q so the global matrix stays globally distinct without double-claiming rows.

### F16 — Write property tests for codec round-trip, determinism, and canonicality
- Milestone: M0
- Size: M
- Deps: F5, F6, F8, F9, F10, F11
- Spec: Verification — property tests (MVP-SPEC.md line 167); Definitions & encoding (line 73)
- Do: Proptest strategies generating arbitrary schema-valid manifests and bundles bounded by F11 caps. Properties: encode → strict-decode round-trip equality; encode determinism (repeat encodes byte-identical); encoder output always passes the strict decoder; decode → re-encode reproduces input bytes for canonical inputs; generated non-canonical mutations (int widening, key reorder, duplicate-key injection, indefinite-length rewrite, trailing-byte append, float substitution, length-head widening) always fail with the correct error class and never panic. Seeds fixed and recorded per the determinism rule.
- Accept:
  - All properties pass with recorded seeds; failure cases minimize.
  - Mutation generators demonstrably cover every line-73 rejection class at least once (coverage assertion in the test).
  - Zero panics across the full property corpus (any panic fails the suite).
  - Runs under Q's CI (wiring is Q's).

### F17 — Create cargo-fuzz targets for the manifest and bundle CBOR parsers
- Milestone: M0
- Size: M
- Deps: F6, F9, F11, F12, F13, F15; Q: CI scheduling (fuzz-in-CI is an M0 exit criterion, Q9)
- Spec: Milestones M0 (MVP-SPEC.md line 153); Verification — CBOR fuzzing in CI (line 169); Risks — hostile bundles (line 187)
- Do: Add a `fuzz/` workspace (excluded from the WASM build) with targets: `fuzz_manifest_decode` (arbitrary bytes → full manifest decode including inner body), `fuzz_bundle_decode` (arbitrary bytes → full three-layer nested decode), and a round-trip target asserting decode-success ⇒ re-encode ⇒ re-decode equality with canonical-byte identity. Seed corpora from the F12/F13 golden vectors and F15 tamper fixtures. Invariants: no panic, no allocation beyond the F11 budget, no hang; all failures surface as typed errors only. DER/`.ots` fuzz targets are A's M2 scope.
- Accept:
  - Both decode targets and the round-trip target build and run clean locally (e.g., `cargo fuzz run <target> -- -runs=100000` over the seed corpus).
  - Seed corpus directories committed.
  - Harness proven able to fail: a temporarily injected panic is caught by the target, then removed.
  - Targets handed to Q with documented run commands for CI.

### F18 — Tamper rows + a property for the F10 version/reserved-slot surfaces
- Milestone: M0
- Size: S
- Deps: F10, F15; Q: the Q7 tamper harness + the Q8 completeness registry
- Spec: Tamper matrix — every mutation fails with a **distinct** error (MVP-SPEC.md line 168); Format stability (line 123)
- Discovered by: **F10** (2026-07-28). F10 landed four now-reachable rejection classes — `manifest-unsupported-format-version`, `bundle-unsupported-format-version`, `manifest-reserved-key`, `bundle-reserved-key` — and **none of them has a tamper row**. `testdata/tamper/MATRIX.json` has no version or reserved-slot case at all, and Q8's completeness check does not catch the gap because these are *project-added* rows rather than spec-enumerated M0 cases: the line-168 enumeration predates the reserved-slot mechanism. They are exactly the mutations a third-party verifier must be able to tell apart ("your file is from a newer antseal" vs "your file is corrupt"), so leaving them unrowed leaves the most user-visible distinction in the format untested at the harness level.
- Do: Add four `project_added` rows to `testdata/tamper/MATRIX.json` + the Q7 registry: bundle discriminant bumped to 2; manifest body discriminant bumped to 2; a reserved key injected into a manifest map; a reserved key injected into a bundle map. Each row mutates exactly one thing on a valid base fixture (R6's constructor once it exists; the hand-rolled wire writers until then — `tests/format_version_dispatch.rs` already builds every one of these byte strings). Also add the property `F10` proves case-wise but not universally: for arbitrary input bytes, `format::peek_format_version(x) == Some(v)` with `v ∉ SUPPORTED_VERSIONS` ⟹ decode fails with that family's version code, and decode *success* ⟹ the peek returned `Some(1)` — i.e. the peek and the schema pass can never disagree on any input, not just the ones a test enumerates.
- Accept:
  - Four rows in the Q7 registry, all four outcomes pairwise distinct and distinct from every existing row (`check_registry` is the proof).
  - Rows recorded as `project_added` in `MATRIX.json` with the rationale above, so Q8 does not read them as spec cases.
  - The peek/decode agreement property runs in the F16 suite with a recorded seed; a deliberately mis-wired peek makes it fail.
- Notes: The two version rows are the natural home for a **third-party-verifier wording check** later (M3/R): the message a user sees for "too new" must be actionable, and the `supported` payload F10 added to both error variants is what makes that possible without reaching into the crate.

### F19 — Hand F14 the diagnostic-sidecar contract (it is in-file, and its rendering is normative)
- Milestone: M0
- Size: S
- Deps: F12, F13; F14 consumes this
- Spec: Revision-2 pre-freeze mandate (MVP-SPEC.md line 5); Definitions & encoding — cross-check (line 73)
- Discovered by: **F12/F13** (2026-07-28). F14's Do text says the checker "asserts structural equality against its diagnostic sidecar", which reads as *a sibling file beside the vector*. That file cannot exist: Q4's discovery contract admits only `*.json` **vector** files, `README.md`, `*.py` and the two auxiliaries under `vectors/v<n>/`, so a `*.diag.json` sibling would be executed as a vector and fail the runner. F12/F13 therefore put the sidecar **inside** the vector, as `expect.cases[].diagnostic`, with one rendered object per strict-decode layer (`envelope`/`body` for `manifest`; `bundle`/`manifest`/`body` for `bundle`). Two further facts F14 must be told rather than rediscover: (a) the rendering is a **fixed table**, written down in `testdata/vectors/README.md` § "The diagnostic sidecar" and implemented by `test_util::vectors_cbor_diag` — F14 implements exactly that table or the comparison is meaningless; (b) there is deliberately **no** `body_bytes`/`manifest_bytes` field, so the `work_id` pre-image must be read out of the envelope's key-0 byte string, which is the point (it demonstrates that `work_id` hashes the embedded bytes and never a re-encoding).
- Do: Update tasks/F.md F14's Do/Accept text (or record the delta where F14 will read it) to name the in-file sidecar location, the rendering table, and the four checks F12/F13's READMEs already enumerate: render-and-compare per layer; re-encode per RFC 8949 §4.2.1 and compare to the committed bytes; `SHA-256` of the key-0 bstr equals `work_id`; `SHA-256` of the whole envelope equals `anchor_digest`. Confirm Python `cbor2` preserves map order on load (it does, via `dict` insertion order) — the sidecar pins wire order, so a checker that sorts would silently weaken to a set comparison.
- Accept:
  - F14's checker reads `expect.cases[].diagnostic` and needs no new file in the vector tree.
  - The self-test fails on a non-canonical vector **and** on a sidecar whose map entries are correct but reordered.
  - The rendering table in `testdata/vectors/README.md` and F14's implementation are cross-referenced from each other, so a change to one is visibly a change to both.
- Notes: The `MAX_JSON_SAFE_INT` refusal (2^53 − 1) exists so no reader with double-typed JSON numbers can silently round a pinned value; F14 should assert it rather than assume it.

### F20 — Tamper rows for the anchor-artifact schema surface F13 made constructible
- Milestone: M0
- Size: S
- Deps: F8, F13, F15; A: A21's anchor rows and status semantics; Q: the Q7 harness + Q8 completeness registry
- Spec: Tamper matrix — every mutation fails with a **distinct** error (MVP-SPEC.md line 168); Reveal bundle (lines 112–114)
- Discovered by: **F13** (2026-07-28). F8 defines the OTS upgrade group (D79: all-or-nothing, never keyed on `status`), the TSA intermediate list and `source`, and the whole Arbitrum receipt record — and has schema-level reject-tests for them. None of it had ever been **constructed** by a fixture: R6's `AnchorSet` offered only `Empty` and `OneOtsTwoTsa`, both of which leave every optional slot absent and the receipt section missing. F13 added `AnchorSet::EveryKind { receipt }` and committed vectors over it, so these shapes are now reachable from the shared constructor — which means the Q7 matrix can now carry rows for them, and currently carries none.
- Do: Add `project_added` rows to `testdata/tamper/MATRIX.json` + the Q7 registry, each mutating exactly one thing on an `AnchorSet::EveryKind` fixture: a 79-byte and an 81-byte `block_header`; the upgrade group with one of its three fields missing (the D79 partial state); an empty `intermediates` entry vs an empty `tx_hashes` list; a wrong-length transaction hash; a reserved `chain_inputs` key present in the receipt; an out-of-band `anchor_status` value. Reuse the existing distinct schema errors rather than minting new ones — the row's claim is *reachability from the shared constructor*, not a new failure class.
- Accept:
  - Every added row's outcome is pairwise distinct from every existing row (`check_registry` is the proof).
  - Each row is built by typed construction from R6, never by byte-patching, so "this mutation, this error" stays an honest claim.
  - Rows recorded as `project_added` with the rationale above, so Q8 does not read them as spec-enumerated cases.
- Notes: Anchor **semantics** (what an upgraded attestation proves, chain validation, the `--online` gate) stay A's at M2; these rows are schema-level only. Coordinate naming with A21 so the global matrix does not double-claim.

### F21 — Decide how the bit-match harness carries the vector tree before v2 doubles it
- Milestone: M0
- Size: S
- Deps: F12, F13; Q5 (the bit-match harness), Q6 (retention), R28 (the multi-version suite)
- Spec: Format stability — per-version vectors retained indefinitely (MVP-SPEC.md line 123); Verification (line 167)
- Discovered by: **F13** (2026-07-28). `crates/wasm-bitmatch/build.rs` **embeds the whole `testdata/vectors/` tree into the wasm artifact**. That was free when the tree was ~98 kB; F12 and F13 take it to ~520 kB, and the growth is structural rather than incidental — a byte-level format freeze necessarily commits the bytes twice (the artifact and its sidecar), and Q6's retention policy is *per version, forever*, so v2 adds its own full tree beside v1's rather than replacing it. Nothing is broken today; the point is that the decision to embed was made when embedding was obviously cheap, and it should be re-taken deliberately rather than discovered as a slow build.
- Do: Measure the current wasm artifact size and bit-match wall time; decide between (a) keep embedding, with a recorded ceiling that turns a lane red before it becomes a problem, (b) have the harness read the tree at run time through the Node host (it already runs under Node, so the file access exists), or (c) embed a *manifest of digests* and stream the vectors in. Record the decision with its measurements. Whatever is chosen must keep the property that makes the lane meaningful: native and wasm32 execute the **identical bytes** through the **identical executor**.
- Accept:
  - Decision recorded with before/after measurements, referencing R28's per-version multiplication.
  - If (a), the ceiling is enforced by a check rather than a comment.
  - The bit-match still covers every committed vector automatically, with no per-vector wiring (the property `testdata/vectors/README.md` promises).

## Open decisions (F)
- CBOR encoder crate + exact pinned version (candidate `minicbor`), including the in-house-codec contingency trigger — blocks F2, F3 (and transitively all codecs) — must land by M0 (jointly with P10). — **[2026-07-27]** RESOLVED (D7): `minicbor = "=2.3.0"` pinned; all line-73 rejection classes implementable on public probe APIs (evidence: crates/antseal-core/tests/cbor_pin_eval.rs); derive stays off — F5–F9 use manual `Encode`/`Decode` impls; contingency trigger recorded in docs/decisions/D7-cbor-crate.md.
- Complete v1 wire registry: integer key assignments, reserved-slot ranges, signatures-container encoding, anchor-status enum wire values, byte-range representation (start+length vs start+end), integer time encoding for claimed time and fetch dates, GGM cover/path node-coordinate encoding (with G), explicit `file_id` in touched-file bundle entries or not — blocks F5, F8 — must freeze at M0 Definitions sign-off.
- Concrete parser cap constants (bundle/manifest byte size, unit/file/anchor counts, list lengths, nesting depth) with recorded rationale — blocks F11, F15 — M0.
- Autonomi ciphertext-address byte length pinned from ant-core =0.5.0 source (via S1) — blocks F4, F5, F8 length checks — M0. — **[2026-07-27]** RESOLVED (D11 via S1): **32 bytes** — `XorName = [u8; 32]`, BLAKE3-256 of chunk content (ant-protocol 2.3.0 src/chunk.rs:43; docs/research/S1-ant-core-api-survey.md).
- Independent CBOR implementation for the cross-check (Python `cbor2` vs a second Rust crate, dev-tool-only) — blocks F14 — M0 (jointly with Q). — **[2026-07-27]** RESOLVED (D12, nominated in D7): Python `cbor2 ==6.1.3` (PyPI 2026-07-04, MIT), dev-tool-only; independent lineage; proven byte-identical to minicbor at integer boundaries + sorted-uint-key map; RFC 7049 ordering caveat recorded (moot for uint-only keys).

## Cross-domain expectations
- P: workspace scaffolding, exact-pin execution for the CBOR crate and `sha2`, wasm32 target setup so `antseal-core` builds for `wasm32-unknown-unknown`.
- C: registered signature algorithm-ID set and exact byte sizes for pubkeys, signatures, commitments, and `k_u`/`k_m`; test-only seed/signature material for fully-real golden vectors; C consumes `body_bytes()` for signing/verifying without re-encoding.
- G: canonicalization-descriptor field set and Unicode-version string format; GGM sub-cover and boundary-path node-coordinate convention; fixture cover/path data for the F13 covered-unit bundle vector.
- A: confirmation that `.ots`/TSA/DER/receipt internals stay opaque bstrs at the format layer; anchor-status enum values and fetch-date semantics; recorded real anchor fixture bytes swapped into bundle vectors at M2 without schema change; A owns the 80-byte header's meaning (F enforces only its length).
- S: Autonomi address type and byte length verified against ant-core =0.5.0; confirmation the manifest storage record is exactly {address, nonce, `k_m`}.
- R: consumes the manifest/bundle codecs and `body_bytes()` API for M3 assembly and verification; owns all semantic/structural invariant checks (tiling, `true_length` = range width, leaf-exact cover, partial-reveal isolation, salt-length verdict mapping) and their tamper rows; joint error-name mapping where F's schema length errors underlie R rows.
- Q: CI wiring for cargo-fuzz, wasm32 build + native/WASM bit-match jobs, per-version golden-vector retain-forever policy; global tamper-matrix harness consuming F15's fixture→error mapping; co-owned F14 cross-check CI job and M0 freeze gate.
- U: presentation of `WorkId` (lowercase hex provided by F's `Display`) and all user-facing format-error rendering.
