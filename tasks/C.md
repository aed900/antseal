# C — Crypto primitives: HKDF, AEAD, salted commitments, hybrid signatures

> Part of the antseal MVP task breakdown (generated 2026-07-27 from MVP-SPEC.md Revision 2 by a 9-agent decomposition).
> **Status tracking lives in `../TODO.md`** — do not add checkboxes here. Treat Do/Accept as normative until deliberately revised; spec line references are into `MVP-SPEC.md` as of 2026-07-27.
> Dep prefixes: P=setup/toolchain/pins, F=CBOR+manifest/bundle codecs, C=crypto primitives, G=canonicalization+units+GGM fine tree, S=storage/payments/journal/restore, A=anchors, R=reveal/verification/web page, U=CLI/vault/config/UX, Q=test-infra/CI/threat-model/docs/release.

### C1 — Implement the hash domain-tag registry as a single module
- Milestone: M0
- Size: S
- Deps: P: `antseal-core` crate scaffold + pinned `sha2`
- Spec: Definitions & encoding (MVP-SPEC.md lines 75–79)
- Do: Create `antseal-core/src/crypto/domain.rs` as the single registry of the seven domain tags: `0x00` fine-tree leaf, `0x01` fine-tree node, `0x02` unit_commit, `0x03` raw_commit, `0x04` canon_commit, `0x05` path_commit, `0x06` GGM salt-child, each a named `u8` const with doc comments citing the spec. Provide one `tagged_sha256(tag, parts: &[&[u8]]) -> [u8; 32]` helper that every commitment/tree/salt-derivation preimage in the codebase must route through, so the tag is always the first preimage byte. Document (module-level) that `work_id`/`anchor_digest` hash raw deterministic-CBOR bytes and are domain-separated by construction because a top-level CBOR map/bstr header byte cannot be `0x00`–`0x06`; export `const MAX_DOMAIN_TAG: u8 = 0x06` for F's disjointness assertion.
- Accept:
  - All seven tags defined once, values exactly per spec line 79; no other module hard-codes a tag byte (grep-enforced test or clippy-style check).
  - Unit test: `tagged_sha256` output equals `SHA-256(tag ‖ concat(parts))` computed independently in the test.
  - Doc comment on the work_id/anchor_digest CBOR-header separation present, citing spec line 79.
  - Compiles for `wasm32-unknown-unknown`.

### C2 — Implement HKDF-SHA256 derivation with the frozen label registry and injective info encoding
- Milestone: M0
- Size: M
- Deps: P: pinned `hkdf`/`sha2` crates
- Spec: Definitions & encoding; Cryptography (MVP-SPEC.md lines 76–77, 89, 91, 95–98)
- Do: Create `antseal-core/src/crypto/hkdf.rs` implementing `HKDF-SHA256(W, label, id)` with salt = empty, IKM = W, and **info = `u8(len(label)) ‖ label ‖ LE64(id)`** (length prefix makes `(label, id) → info` injective by construction). Define the full frozen label registry with per-use output lengths and the id domain each label takes: `"unit-key"` (32 B, unit_id), `"unit-salt"` (16 B, unit_id), `"path-salt"` (16 B, file_id), `"file-salt"` (16 B, file_id), `"fine-seed"` (32 B, file_id — consumed by G), `"sig-ed25519"` (32 B, sentinel), `"sig-mldsa65"` (32 B, sentinel), `"manifest-key"` (32 B, sentinel); reserved sentinel `id = 0xFFFFFFFFFFFFFFFF` for no-natural-id calls. Expose only typed per-label functions (`derive_unit_key(&W, unit_id)`, `derive_file_salt(&W, file_id)`, `derive_manifest_key(&W)`, …) so passing the wrong id kind or wrong output length is unrepresentable; include the shared LE64 encoding helper (spec line 76: every label concatenation is `ASCII-label ‖ LE64(id)`).
- Accept:
  - Info bytes for a known (label, id) pair match a hand-computed `u8(len) ‖ label ‖ LE64(id)` fixture; sentinel encoding is exactly `0xFFFFFFFFFFFFFFFF` LE.
  - Each registry entry's output length enforced by return type (`[u8; 16]` vs `[u8; 32]` newtypes).
  - No public API accepts a free-form label string; the registry is the only path.
  - RFC 5869 empty-salt semantics confirmed against a reference vector.
  - Compiles for `wasm32-unknown-unknown`.

### C3 — HKDF golden test: pairwise-distinct infos + derivation vectors
- Milestone: M0
- Size: S
- Deps: C2; Q: CI retains vectors indefinitely (Q6)
- Spec: Milestones M0 (MVP-SPEC.md line 153); Definitions (line 77)
- Do: Write the M0 golden test that enumerates every registered HKDF label crossed with a representative id set (0, 1, max-real, and the sentinel) and asserts all encoded info byte strings are pairwise distinct. Add a property test that for any two `(label, id) ≠ (label′, id′)` pairs (arbitrary labels up to 255 B, arbitrary ids) the encoded infos differ — verifying structural injectivity, not just the current registry's accident. Commit golden vectors under `testdata/` for each registry entry derived from a fixed test-only `W`.
- Accept:
  - Pairwise-distinctness test over the full registry passes and is named/documented as the spec-line-153 golden test.
  - Proptest injectivity property passes (≥10k cases in CI config).
  - Committed golden vectors: (label, id, info-bytes, output) tuples for all 8 labels; WASM run bit-matches native (harness from Q).
- Notes: The test `W` is a fixed public fixture — mark it clearly non-secret to respect the no-secrets-in-fixtures rule (project rule 6).

### C4 — Define the crypto error taxonomy with secret-redaction discipline
- Milestone: M0
- Size: S
- Deps: P: pinned `thiserror`
- Spec: Verification tamper matrix (MVP-SPEC.md line 168); project rules 4, 6
- Do: Create `antseal-core/src/crypto/error.rs` with `thiserror` enums giving every crypto failure class its own variant, sized for the tamper matrix's distinct-error requirement: `CommitmentMismatch{kind}`, `SaltLength{kind, expected, got}`, `SeedLength{expected, got}`, `NodeHashLength{expected, got}`, `AeadDecryptFailed`, `PaddingLengthMismatch{expected, got}`, `NonZeroPadding{offset}`, `SigPolicyEmpty`, `SigPolicyDuplicate`, `SigPolicyUnknownAlg`, `SignatureMissing{alg}`, `SignatureInvalid{alg}`, `SignatureUnlisted{alg}`, `NonCanonicalSignature{alg}`, `RngFailure`. No variant may carry key, salt, seed, or plaintext bytes — only kinds, lengths, offsets, ids; `Debug`/`Display` impls must be reviewed for this.
- Accept:
  - A unit test asserts pairwise-distinct discriminants across all variants used by tamper-matrix rows.
  - A test (or documented review checklist item) greps `Display` output of every variant constructed with dummy data for absence of input byte content.
  - Library code in `antseal-core::crypto` has no `unwrap`/`panic!` on adversarial input paths (clippy `unwrap_used` deny on the module).

### C5 — Implement master secret W and seal_id types with CSPRNG generation and zeroization
- Milestone: M0
- Size: S
- Deps: C4; P: pinned `zeroize`, `rand_core`/`getrandom` (wasm_js recipe); U: vault stores/loads `W`
- Spec: Cryptography (MVP-SPEC.md lines 89–90); Vault (line 143)
- Do: Create `antseal-core/src/crypto/secrets.rs` with `MasterSecret` (`W`, 32 B) and `SealId` (16 B) newtypes. Generation takes an injected `&mut impl CryptoRngCore` (OS CSPRNG in production, seeded in tests per the determinism principle); `SealId` is generated at seal start and is public (stored in the manifest body — F's field). `MasterSecret` implements `ZeroizeOnDrop` with a redacted `Debug`; also export a zeroizing `SecretBuf`/`Passphrase` byte-buffer type for U's passphrase handling so passphrase-holding buffers inside crypto-adjacent code zeroize uniformly. Document the pipeline-DAG role of `seal_id` (AAD independence from the finished manifest, spec line 90).
- Accept:
  - `MasterSecret::generate(rng)` returns 32 B; `SealId::generate(rng)` returns 16 B; deterministic under a seeded test RNG.
  - `Debug`/`Display` for `MasterSecret` and `SecretBuf` print a redaction marker, never bytes (tested).
  - `ZeroizeOnDrop` implemented for `MasterSecret` and `SecretBuf` (compile-time trait assertion test).
  - Compiles for `wasm32-unknown-unknown` with the pinned getrandom backend recipe.

### C6 — Implement the four salted-commitment primitives and their salt derivations
- Milestone: M0
- Size: M
- Deps: C1, C2, C4, C5; G: canonical bytes input for `canon_commit`
- Spec: Salted commitments (MVP-SPEC.md lines 93–95); Definitions (line 79)
- Do: Create `antseal-core/src/crypto/commit.rs` implementing compute-and-verify for: `unit_commit = SHA-256(0x02 ‖ unit_salt ‖ unit_bytes)` with 16-B `unit_salt = HKDF(W, "unit-salt", unit_id)`; `path_commit = SHA-256(0x05 ‖ path_salt ‖ path_utf8)` with independent 16-B `path_salt = HKDF(W, "path-salt", file_id)`; `raw_commit = SHA-256(0x03 ‖ file_salt ‖ raw_bytes)` and `canon_commit = SHA-256(0x04 ‖ file_salt ‖ canonical_bytes)` (text files only) both salted by the single 16-B `file_salt = HKDF(W, "file-salt", file_id)`. All preimages go through C1's `tagged_sha256`. Define length-checked salt newtypes `Salt16`, `Seed32`, `NodeHash32` with `TryFrom<&[u8]>` returning C4's distinct `SaltLength`/`SeedLength`/`NodeHashLength` errors — these are the constructors R's verifier uses to execute the structural length checks on bundle-supplied values (spec line 121). Verify functions return `CommitmentMismatch{kind}` on failure, constant-time equality via `subtle`.
- Accept:
  - Golden fixtures: each of the four commitments over known salt+message equals an independently computed SHA-256 of `tag ‖ salt ‖ msg`.
  - `Salt16::try_from` rejects 15-B and 17-B inputs; `Seed32`/`NodeHash32` reject 31-B/33-B — each with its distinct error variant.
  - Test proving `path_salt` and `file_salt` for the same `file_id` are distinct values (independent labels), and that disclosing one does not equal the other.
  - Verification is constant-time on the digest comparison (uses `subtle::ConstantTimeEq`; asserted by code review checklist item).
  - Compiles for `wasm32-unknown-unknown`.

### C7 — Enforce the commitment-mode and salt-disclosure rules in the API type system
- Milestone: M0
- Size: M
- Deps: C5, C6; G: per-unit fine-tree-coverage determination (G5) and the mirror `s_root` guard; F: `unit_commit` as kind-conditional manifest field; R: reveal-bundle builder consumes these types (M3)
- Spec: per-unit commitment rule (MVP-SPEC.md line 94); per-file salts (line 95); bundle contents & partial-reveal isolation (lines 114, 121)
- Do: Encode two normative rules as unrepresentable-misuse API shapes in `antseal-core/src/crypto/disclosure.rs`. (1) `unit_commit` presence IFF the unit is NOT fine-tree-covered: a `UnitBinding` enum with variants `FineTreeCovered` (carries no `unit_commit`; content bound solely by `fine_root` — G's machinery) and `NonCovered { unit_commit }` (only `--no-fine-tree` whole-file units and raw-mirror units); generation code cannot construct a covered unit carrying a `unit_commit`, preserving the single-authoritative-commitment/anti-equivocation rule of line 94. (2) Generation-side guarantee that partial reveals can never emit `file_salt`: `file_salt` is never exposed as raw bytes by the salts API; it is obtainable only through a `FullFileRevealDisclosure` constructor that structurally requires the full-reveal context, so R's M3 bundle builder cannot leak it on a partial reveal even by bug. Document the normative confirmation-oracle rationale (shared/early-disclosed `file_salt` hands a partial-reveal recipient an offline full-file confirmation oracle) as doc comments citing line 95; `path_salt` remains freely obtainable per touched file, `unit_salt` per revealed non-covered unit.
- Accept:
  - Compile-fail test (trybuild or doc-test) showing a `FineTreeCovered` unit cannot be given a `unit_commit`, and `file_salt` bytes cannot be reached outside `FullFileRevealDisclosure`.
  - Unit tests: a partial-reveal disclosure set for a file provably contains no `file_salt` (type-level plus a runtime serialization assertion helper R can reuse); a full-file reveal yields exactly `{file_salt}` (plus `s_root` from G's side, referenced not implemented).
  - Doc comments state the line-94 equivocation rationale and the line-95 confirmation-oracle rationale verbatim in substance.
- Notes: The symmetric guard for `s_root`/GGM ancestor seeds is G's (G11); emit only the interface expectation. The tamper-matrix row "`file_salt`/`s_root` present for an only-partially-revealed file" is R's verifier-side check — C supplies the types and fixtures via C17/R.

### C8 — Implement the unit padding codec (formula, apply, length-first strip, rejections)
- Milestone: M0
- Size: S
- Deps: C4
- Spec: Unit encryption padding (MVP-SPEC.md line 91); structural invariants (line 121); tamper matrix (line 168)
- Do: Create `antseal-core/src/crypto/padding.rs` with `padded_length(true_length) = ⌈(true_length + 1) / 256⌉ · 256` (always ≥1 pad byte; a unit ending on a 256-B boundary is unambiguous; empty unit with `true_length = 0` pads to 256), `apply_padding(bytes) -> Vec<u8>` (zero-fill), and `strip_padding(plaintext, true_length) -> Result<&[u8]>` which is length-first — driven by the manifest's `true_length`, so genuine trailing `0x00` content survives. Strip must reject with `PaddingLengthMismatch` when `plaintext.len() != padded_length(true_length)` (blocks silent over-padding) and with `NonZeroPadding{offset}` when any byte beyond `true_length` is non-zero. Module docs record: the bucketing leak (an observer learns `⌊true_length/256⌋`), that this is defense-in-depth not a full fingerprint defense, and that the formula is format-version-scoped (a future version may adopt Padmé without breaking v1).
- Accept:
  - Table-driven tests: `true_length` ∈ {0, 1, 255, 256, 257, 511, 512} → `padded_length` ∈ {256, 256, 256, 512, 512, 512, 768}.
  - Round-trip property: `strip(apply(b), b.len()) == b` for arbitrary bytes including trailing-`0x00` content.
  - Reject tests: plaintext one 256-block too long (correct formula violated) → `PaddingLengthMismatch`; correct length but a non-zero pad byte → `NonZeroPadding`; the two errors are distinct.
  - Compiles for `wasm32-unknown-unknown`.

### C9 — Implement unit AEAD encrypt/decrypt with AAD binding and the single-use invariant
- Milestone: M0
- Size: M
- Deps: C2, C4, C5, C8; F: manifest unit table holds the single authoritative nonce + `true_length`; S: journal/resume enforces single-use across restarts (S11)
- Spec: Unit encryption (MVP-SPEC.md line 91); seal journal (line 145)
- Do: Create `antseal-core/src/crypto/unit_aead.rs`: `k_u = HKDF(W, "unit-key", unit_id)` (via C2), XChaCha20-Poly1305, `encrypt_unit(&W, seal_id, unit_id, unit_bytes, &mut rng) -> (Ciphertext, Nonce24)` which pads via C8, draws a fresh random 24-B nonce internally from the injected CSPRNG, and sets **AAD = `seal_id ‖ LE64(unit_id)`** (24 bytes). There is deliberately no public encrypt API accepting a caller-supplied nonce — the `(k_u, nonce)` single-use invariant (one plaintext, ever) is documented as a module invariant, with resume-side enforcement referenced to S (line 145). `decrypt_unit(&W, seal_id, unit_id, nonce, ciphertext, true_length)` decrypts, then runs C8's strip with both rejections — the verifier-side path R orchestrates. Unit keys are zeroized after use.
- Accept:
  - Round-trip test over unit bytes including the empty unit (ciphertext plaintext-length 256) and a 256-B-aligned unit.
  - AAD fixture test: encoded AAD for a known `(seal_id, unit_id)` equals the 24-byte concatenation.
  - Decrypt fails with `AeadDecryptFailed` when: wrong `unit_id` in AAD, wrong `seal_id`, wrong nonce, flipped ciphertext byte, wrong key — and these are distinguishable from padding errors (C8 variants) which fire only after successful AEAD verification.
  - Two encrypts of the same plaintext produce different nonces and ciphertexts (fresh-nonce check); no API path allows re-encrypting under a caller-chosen nonce (compile-level review + doc-test).
  - `UnitKey` zeroizes on drop; compiles for `wasm32-unknown-unknown`.
- Notes: The tamper fixture "over-padded unit" needs a test-only mis-encryptor that pads to the wrong bucket — build it here behind `#[cfg(test)]`/test-util feature for C17.

### C10 — Implement manifest encryption (k_m) and storage-record value production
- Milestone: M0
- Size: S
- Deps: C2, C5, C9 (shared AEAD plumbing); F: storage-record {address, nonce, k_m} schema; S: upload of the opaque blob
- Spec: Manifest encryption (MVP-SPEC.md line 98)
- Do: In `antseal-core/src/crypto/manifest_aead.rs` implement `k_m = HKDF(W, "manifest-key")` (sentinel id), XChaCha20-Poly1305 with a fresh random nonce and **empty AAD**, over the plaintext manifest bytes — producing the opaque blob that is the only manifest copy the network stores (title, path commitments, sizes, pubkeys never in plaintext on the network). Provide decrypt for `restore`/persistence checks. Emit the storage-record values `{nonce, k_m}` for F's schema (address comes from S/self-encryption); document that `k_m` in a bundle discloses nothing beyond the manifest the bundle already embeds.
- Accept:
  - Round-trip test; decrypt with wrong `k_m` or mutated blob → `AeadDecryptFailed`.
  - Test asserting AAD is empty (a ciphertext produced with any non-empty AAD fails decrypt).
  - `k_m` derivation uses the sentinel id (info bytes fixture cross-checked with C3's vectors).
  - `ManifestKey` zeroizes on drop; compiles for `wasm32-unknown-unknown`.

### C11 — Run the M0 signature-crate probe: ml-dsa WASM viability, fips204 fallback, ed25519-dalek pin
- Milestone: M0
- Size: M
- Deps: P: records the resulting exact pins in workspace manifests (P11/P12/P14); Q: RUSTSEC tracking for the two Jan-2026 `ml-dsa` advisories (Q10)
- Spec: Author signature crate reality (MVP-SPEC.md line 97); Milestones M0 (line 153); Risks — PQC crate maturity (line 183)
- Do: Build a probe harness (scratch crate or `antseal-core` feature-gated test) that compiles and runs `ml-dsa = "=0.1.1"` sign/verify on `wasm32-unknown-unknown` using the exact pinned getrandom recipe, and byte-compares wasm vs native outputs. Verify by reading the pinned crate source/docs: (a) that the primary crate exposes the FIPS-204 `ctx` parameter needed for `"antseal-manifest-v1"`; (b) that it rejects non-canonical/out-of-range signature encodings (hint count/positions, `z` bounds) at decode — recording evidence for C13; (c) `fips204 = "=0.4.6"` as fallback: seed-based keygen from 32-B ξ, ctx support, WASM build. Decide and record the `ed25519-dalek` pin (2.x vs 3.0.0), verifying the chosen version's `verify_strict` semantics and whether `Signature::from_bytes` already rejects non-canonical `S ≥ L` at parse time (feeds C12's distinct-error design). Output: a written probe report fixing primary crate, fallback trigger, and pins.
- Accept:
  - wasm32 probe passes (or documented failure triggering the fips204 path; if both fail, the Ed25519-only `sig_policy` fallback of C14 is invoked — format unchanged, slot reserved).
  - ctx-parameter availability and canonical-rejection behavior of the chosen ML-DSA crate documented with source references; gaps enumerated for C13 to close with a pre-validation layer.
  - `ed25519-dalek` pin decision recorded with rationale and `verify_strict`/parse-rejection behavior notes; P has the exact `=x.y.z` pins.
  - Probe artifacts checked in so the decision is reproducible.
- Notes: Must run at M0 start — gates C12–C16. Upstream-verification task by design: do not trust memory of crate APIs; read the pinned versions.

### C12 — Implement Ed25519 signing and strict verification with the frozen context prefix
- Milestone: M0
- Size: M
- Deps: C2, C4, C11
- Spec: Author signature (MVP-SPEC.md line 97); security assumptions (line 104)
- Do: In `antseal-core/src/crypto/sig_ed25519.rs`: derive the signing seed as `HKDF(W, "sig-ed25519", sentinel)` (32 B → `SigningKey`), and sign/verify the message `ctx ‖ 0x00 ‖ body` where `ctx` is the frozen context string `"antseal-manifest-v1"` — the domain prefix folded into the pre-image so a signature can never be lifted into another context. Verification MUST implement RFC 8032 `verify_strict` semantics as a conformance requirement: reject non-canonical `S ≥ L`, reject small-order/non-canonical `R` and `A`. Layer explicit canonicality pre-checks (S range check on the last 32 bytes; decompression-canonicality and small-order checks on `R`/`A`) so that a mauled-but-strict-invalid signature surfaces C4's `NonCanonicalSignature{ed25519}` distinctly from `SignatureInvalid{ed25519}` (wrong signature over the right bytes).
- Accept:
  - Round-trip: seed from a fixed test `W` → deterministic signature over a fixed body; verifies.
  - Context binding test: a signature over `body` fails verification against `body` with any different ctx, and a signature made without the prefix fails.
  - `S ≥ L` mauled signature → `NonCanonicalSignature`; small-order `R` and small-order `A` vectors → `NonCanonicalSignature`; a valid-form signature by the wrong key → `SignatureInvalid`; the two variants are distinct.
  - RFC 8032 known-answer vectors (adapted for the prefix construction where applicable) pass; seed material zeroized after key construction.
  - Compiles for `wasm32-unknown-unknown`.

### C13 — Implement ML-DSA-65 signing and canonical-strict verification with FIPS-204 ctx
- Milestone: M0
- Size: M
- Deps: C2, C4, C11
- Spec: Author signature (MVP-SPEC.md line 97); security assumptions (line 104); Risks (line 183)
- Do: In `antseal-core/src/crypto/sig_mldsa.rs`: derive seed ξ = `HKDF(W, "sig-mldsa65", sentinel)` (32 B; FIPS 204 keygen expands it), keygen per FIPS 204, and sign/verify body bytes with the FIPS-204 `ctx` parameter set to `"antseal-manifest-v1"`. Verification MUST reject any non-canonical/out-of-range signature encoding — hint bounds (count ≤ ω, ordering), `z` coefficient bounds — surfacing `NonCanonicalSignature{mldsa65}` distinct from `SignatureInvalid{mldsa65}`. Where C11's probe found the pinned crate does not itself enforce a canonical-encoding rule, add a pre-validation layer over the raw signature bytes before handing to the crate. Fix stable byte encodings and sizes (pk 1952 B, sig 3309 B) for F's schema.
- Accept:
  - Round-trip sign/verify over a fixed body with ctx; wrong-ctx verification fails.
  - Keygen from a fixed ξ is deterministic and matches a committed vector (cross-checked against NIST ACVP/known-answer material for the parameter set where available).
  - Reject tests: hint-overflow encoding, out-of-range `z`, and at least one bit-mutated-but-decodable signature → correct distinct variants (`NonCanonicalSignature` vs `SignatureInvalid`).
  - ξ zeroized after expansion; compiles for `wasm32-unknown-unknown` (or the documented fips204/Ed25519-only fallback path from C11 is active and recorded).
- Notes: Open decision on hedged vs deterministic signing mode affects golden-vector reproducibility (see Open decisions); verification is unaffected either way.

### C14 — Implement sig_policy validation and hybrid sign/verify orchestration
- Milestone: M0
- Size: M
- Deps: C12, C13; F: body field encoding for `sig_policy`, pubkeys, and the signatures structure over the embedded-bstr body; R: renders the verdict label
- Spec: Author signature — sig_policy, anti-downgrade, fallback (MVP-SPEC.md line 97); manifest body fields (line 98); security assumptions (line 104)
- Do: In `antseal-core/src/crypto/sig_policy.rs` define the registered algorithm-ID registry (ed25519, ml-dsa-65; values coordinated with F) and `SigPolicy` validation: MUST be non-empty, duplicate-free, registered-IDs-only — violations are parse-time rejects (`SigPolicyEmpty`/`SigPolicyDuplicate`/`SigPolicyUnknownAlg`) so a signature-less manifest can never verify vacuously. Implement hybrid signing (derive both seeds from `W`, sign the exact body bytes with every policy-listed algorithm) and hybrid verification enforcing **present-signature-set = policy-set**: validate every listed signature and hard-fail on missing (`SignatureMissing`), invalid (`SignatureInvalid`/`NonCanonicalSignature`), or present-but-unlisted (`SignatureUnlisted`) — a hybrid manifest never passes on one good signature. The verification result exposes which policy was satisfied (`Hybrid` vs `Ed25519Only`) as data for R's "hybrid (PQ)" vs "Ed25519-only" verdict labeling. Support the C11 fallback: `sig_policy = [ed25519]` ships with the format unchanged (ML-DSA slot reserved). Document and test the anti-downgrade property: the policy sits inside the signed (and, once anchored, timestamped) body, so stripping ML-DSA from an existing hybrid manifest breaks signature verification — a fresh Ed25519-only forgery is a different body, hence a new `work_id` with its own later anchors.
- Accept:
  - Parse-time reject tests for empty, duplicate, and unregistered-ID policies — three distinct errors.
  - Verify-time tests: hybrid policy with ML-DSA signature removed → `SignatureMissing`; with one signature corrupted → `SignatureInvalid`; with a valid extra unlisted Ed25519 signature added → `SignatureUnlisted`; all-present-all-valid → success carrying the correct label datum.
  - Ed25519-only policy round-trips through the identical code path (fallback exercised in CI regardless of probe outcome).
  - Anti-downgrade doc-test: mutating `sig_policy` inside the body invalidates both signatures (body bytes changed).
  - Compiles for `wasm32-unknown-unknown`.

### C15 — Build committed reject-vector suites for both signature algorithms
- Milestone: M0
- Size: M
- Deps: C12, C13, C14; Q: vectors retained in CI indefinitely (Q6)
- Spec: Author signature strict verification + reject-vectors (MVP-SPEC.md line 97); Milestones M0 (line 153)
- Do: Commit under `testdata/sig-reject/` a vector suite per algorithm, each entry = (pubkey, message-with-ctx inputs, signature bytes, expected distinct error). Ed25519: `S ≥ L` (several values straddling L), small-order `R`, small-order `A`, non-canonical point encodings, valid-signature-wrong-key, valid-signature-wrong-ctx. ML-DSA-65: hint-count/hint-order violations, `z` out-of-range, truncated and over-length signatures, bit-flipped valid signature, wrong-ctx. Include positive control vectors per suite. Wire a table-driven test that runs every vector through C14's full verification path.
- Accept:
  - Every reject vector fails with exactly its expected error variant; positive controls pass.
  - Suite runs identically on native and wasm32 (bit-matching verdict, per Q's harness).
  - Vector files are format-documented (README in the directory) so an independent implementation can consume them.

### C16 — Produce crypto golden vectors and cross-check against an independent implementation
- Milestone: M0
- Size: L
- Deps: C2, C6, C8, C9, C10, C14; F: canonical CBOR encodings where vectors embed structures; Q: CI wasm-bit-match harness + indefinite retention (Q5/Q6/Q11)
- Spec: Revision preamble independent-cross-check mandate (MVP-SPEC.md line 5); Verification (line 167); Milestones M0 (line 153)
- Do: Commit `testdata/golden/crypto/` vectors from fixed public test inputs (`W`, `seal_id`, ids, contents): HKDF outputs for all 8 labels; all four salted commitments; unit AEAD (key, nonce, AAD, padded plaintext, ciphertext) including the empty-unit and boundary-length cases; manifest AEAD; Ed25519 and ML-DSA-65 keys and signatures with ctx; the hybrid signatures over a fixed body. Write an independent cross-check implementation in a different language/stack (e.g. Python: `hkdf`/`cryptography`, PyNaCl XChaCha20-Poly1305, RFC 8032 reference code, an independent ML-DSA implementation) that regenerates every vector byte-for-byte — the spec's mandated pre-freeze cross-check. Record the cross-check run as a committed artifact/script runnable on demand.
- Accept:
  - All vectors reproduce byte-identically from the independent implementation; discrepancy list empty, run recorded.
  - Native and wasm32 test runs bit-match on every vector.
  - Vectors cover: sentinel-id derivations, empty unit (→ 256-B plaintext), 256-aligned unit, AAD bytes, empty-AAD manifest encryption.
  - Vector files never contain real secret material — all inputs are marked test-only fixtures.
- Notes: If deterministic ML-DSA signing is not selected (Open decisions), signature vectors pin keygen + verification of a stored signature rather than sign-output bytes.

### C17 — Implement the M0 crypto tamper-matrix rows with pairwise-distinct errors
- Milestone: M0
- Size: M
- Deps: C6, C7, C8, C9, C14, C15; F: fixture bundle/manifest encoding; R: executes the salt/seed/node length checks in the verifier path; Q: tamper-matrix harness conventions (Q7/Q8)
- Spec: Tamper matrix (MVP-SPEC.md line 168); structural invariants (line 121)
- Do: Build the crypto-owned tamper fixtures and tests, one row per mutation, asserting each fails with its own distinct error: (1) wrong salt — bit-flipped `unit_salt`/`path_salt`/`file_salt` → `CommitmentMismatch{kind}`; (2) wrong-length salt/seed primitive reject tests — 15/17-B `*_salt`, 31/33-B `s_root`/GGM seed/boundary node hash — exercised via C6's newtype constructors (the COMMITTED bundle-level tamper fixtures for these families are R7's; single Q8 fixture owner = R; C supplies the newtype constructors and mutation helpers) → `SaltLength`/`SeedLength`/`NodeHashLength`; (3) wrong key — decrypt under a different `W` → `AeadDecryptFailed`; (4–7) the four `sig_policy` rows — missing sig, invalid sig, unlisted-extra sig, empty policy; (8) non-canonical Ed25519 `S` (mauled but strict-invalid); (9) non-canonical ML-DSA encoding; (10) over-padded unit — C9's test-only mis-encryptor producing plaintext length ≠ `padded_length` → `PaddingLengthMismatch`; plus the non-zero-pad-byte reject as a companion case (the mis-encryptor is C's helper; the committed bundle-level fixtures for the over-padding family are R7's, per the Q8 single-owner rule). Add a meta-test asserting the error variants across all rows are pairwise distinct.
- Accept:
  - Every listed row exists as a committed fixture + test; each yields its documented distinct error variant; the pairwise-distinctness meta-test passes.
  - The mutation helpers (wrong-length constructors, mis-encryptor) are exported for R7's committed bundle-level fixtures; the Q8 registry lists R as the fixture owner for those families with C's primitive tests cross-referenced (no duplicate rows).
  - Rows run on native and wasm32 with identical outcomes.

### C18 — Property-test the crypto primitives
- Milestone: M0
- Size: M
- Deps: C2, C6, C8, C9, C10, C14; P: pinned `proptest`
- Spec: Verification — unit/property tests per crate (MVP-SPEC.md line 167)
- Do: Add proptest suites with seeded RNG (determinism principle): HKDF info-encoding injectivity over arbitrary (label, id) pairs (extends C3); commitment verify succeeds iff (salt, bytes) match exactly (any single-byte perturbation of salt or message fails — including shifts across the salt/message boundary, which the fixed 16-B salt length prevents from being malleable); padding round-trip plus strip-rejection completeness over arbitrary lengths (`0..=4·256+3`); unit AEAD round-trip over arbitrary unit bytes and ids, and decrypt-failure on any AAD component mismatch; hybrid sign/verify round-trip over arbitrary bodies with mutation ⇒ failure.
- Accept:
  - All properties pass at CI case counts; failure seeds are reproducible (checked-in proptest regressions file policy).
  - Boundary-shift property explicitly covers moving bytes between salt and message (must fail — 16-B fixed length asserted).
  - Suites run in CI on native; a representative subset compiled for wasm32.

### C19 — Write the adversarial confirmation-attack doc-tests
- Milestone: M0
- Size: S
- Deps: C6
- Spec: Adversarial doc-tests (MVP-SPEC.md line 171); salted-commitments rationale (lines 93, 95); Context corollary (line 13)
- Do: Add two executable regression-guard demonstrations in `antseal-core` (doc-tests or `#[test]`s with extensive doc comments): (1) unsalted-unit variant — compute `SHA-256(tag ‖ unit_bytes)` without salt and show an attacker holding a candidate plaintext confirms the guess offline against the commitment; then show the real salted `unit_commit` makes the same guess-check fail without the salt; (2) unsalted-file-hash variant — an unsalted `canon_commit` lets a partial-reveal bundle recipient confirm a guessed full document; the real construction (salted by `file_salt`, disclosed only on full reveal per C7) defeats it. These document *why* every commitment is salted and pin the property against regression.
- Accept:
  - Both attacks succeed against the deliberately-unsalted toy variants and fail against the production constructions, in the same test.
  - Tests are wired into CI as permanent regression guards and referenced from the threat-model content (C20).

### C20 — Author the frozen Security-assumptions block content
- Milestone: M0
- Size: S
- Deps: C6, C8, C9, C14 for accuracy review; Q: skeleton threat-model doc file (Q12; finalized M4 via Q21)
- Spec: Security assumptions (MVP-SPEC.md lines 99–104); Milestones M0/M4 (lines 153, 157)
- Do: Write, as reviewed content handed to Q's skeleton threat-model doc, the frozen security-assumptions block: binding of every commitment (`unit_commit`/`raw_commit`/`canon_commit`/`path_commit`/`fine_root`) and of `work_id`/`anchor_digest` = standard-model SHA-256 collision resistance (~128-bit), no hash agility, format-version hook reserved; hiding (confirmation-attack resistance incl. low-entropy single-byte fine-tree leaves) = random-oracle-model salted SHA-256 with 128-bit secret salt, multi-target erosion ~2^128/K over K exposed commitments, 128-bit salts as the intended margin; GGM hiding = SHA-256 as a length-doubling PRG on the fixed 34-B input `0x06 ‖ seed ‖ b` (length-extension inapplicable — all preimages fixed-length or equality-compared), puncturing soundness resting on the leaf-exact-cover/no-ancestor-seed rule; AEAD confidentiality-only and non-committing (invisible-salamanders class), acceptable because no verdict-bearing check relies on unique decryption, with the frozen rule "a future refactor MUST NOT drop a content commitment in favor of trusting the AEAD" — this sentence also embedded as a doc comment in the AEAD modules (C9/C10); signature unforgeability = strict Ed25519 SUF-CMA + ML-DSA-65, hybrid requires both, non-downgradable via the signed+anchored policy. Record the freeze as an explicit signed-off decision.
- Accept:
  - Content covers all five assumption classes with the exact normative rules above; cross-references C19's regression tests.
  - The MUST-NOT-trust-AEAD rule appears verbatim in `unit_aead.rs`/`manifest_aead.rs` module docs.
  - Sign-off (freeze decision) recorded in the doc's change header; delivered to Q by end of M0.

### C21 — Audit zeroization coverage and document the WASM caveat
- Milestone: M0
- Size: S
- Deps: C5, C9, C10, C12, C13; U: vault-side zeroization of stored records
- Spec: Vault — zeroize (MVP-SPEC.md line 143)
- Do: Sweep `antseal-core::crypto` for every secret-holding type — `MasterSecret` (`W`), `UnitKey`, `ManifestKey`, both signature seeds/signing keys, `SecretBuf`/passphrase buffers — and verify each implements `ZeroizeOnDrop`, is never `Clone` without cause, never appears in `Debug`/`Display`/error output, and intermediate copies (HKDF OKM buffers, padded-plaintext buffers holding secret work content) are zeroized where the API allows. Document the normative caveat: the WASM verifier cannot guarantee zeroization for bundle-supplied keys (`k_u`, `k_m`, salts) in browser memory — as a doc comment on the crypto module root and as content handed to the threat-model doc (Q).
- Accept:
  - Compile-time trait-assertion tests: all listed types are `ZeroizeOnDrop`.
  - A checklist artifact enumerating each secret-bearing buffer and its zeroization disposition (or the documented reason none is possible, e.g. crate-internal key state).
  - WASM caveat text present in module docs and delivered to Q.
  - No secret material found in any log/error/fixture path (ties to C4's redaction tests; grep sweep recorded).

## Open decisions (C)
- **ed25519-dalek exact pin (2.x vs 3.0.0)** — chosen from C11's probe with P; blocks C11→C12, C15, C16; must land by M0 (start).
- **Primary ML-DSA crate (`ml-dsa =0.1.1` vs `fips204 =0.4.6` fallback) and whether the Ed25519-only `sig_policy` fallback ships** — outcome of the C11 WASM probe; blocks C13, C14, C15, C16; M0.
- **ML-DSA signing mode: hedged (FIPS 204 default) vs deterministic** — determines whether signature golden vectors pin sign-output bytes or keygen+verify-only; blocks C16; M0.
- **Mechanism for the distinct non-canonical-Ed25519-S error: rely on the pinned dalek version's parse-time `S ≥ L` rejection vs an explicit pre-validation layer** — decided from C11's findings; blocks C12, C17; M0.
- **Registered `sig_policy` algorithm-ID values (numeric IDs + reserved slots), coordinated with F's CBOR schema** — blocks C14, C15; M0 (format freeze).

## Cross-domain expectations
- P: workspace + `antseal-core` scaffold; exact pins for `sha2`, `hkdf`, `chacha20poly1305`, `ed25519-dalek`, `ml-dsa =0.1.1`, `fips204 =0.4.6`, `zeroize`, `subtle`, `thiserror`, `proptest`, `rand_core`/`getrandom` with the exact wasm_js backend recipe; wasm32-unknown-unknown in CI from day one.
- F: deterministic-CBOR manifest schema carrying the 24-B nonce (single authoritative copy), `true_length`, kind-conditional `unit_commit` field, pubkeys, `sig_policy`, signatures over the embedded-bstr body verified without re-encoding; `work_id`/`anchor_digest` computed over exact received bytes; storage-record `{address, nonce, k_m}` schema; golden-vector assertion that encoded manifest/body first byte ∉ `0x00–0x06` (using C1's `MAX_DOMAIN_TAG`).
- G: per-unit fine-tree-coverage determination driving C7's `UnitBinding`; `fine-seed`/`s_root` derivation via C2's `"fine-seed"` entry; the GGM-side disclosure guard (no ancestor seed of an unrevealed leaf, `s_root` full-reveal-only) mirroring C7; canonical bytes as `canon_commit` input; consumption of C1's tags `0x00`/`0x01`/`0x06`.
- R: verifier orchestration calling C's decrypt/strip/commitment-verify/sig-policy functions per revealed unit; execution of the 16-B/32-B length checks via C6's newtypes on all bundle-supplied salts/seeds/node hashes; the `file_salt`/`s_root`-present-on-partial-reveal tamper check; rendering "hybrid (PQ)" vs "Ed25519-only" from C14's result datum.
- S: journal/resume enforcement of the `(k_u, nonce)` single-use invariant — byte-identical staged-ciphertext re-upload, abort-rather-than-re-encrypt under a journaled nonce.
- U: vault persistence of `W` and records; Argon2id/scrypt vault KDF; passphrase collection via C5's zeroizing `SecretBuf` type.
- A: consumption of `anchor_digest` (SHA-256 over full plaintext manifest bytes, computed at the F boundary) as the sole datum submitted to OTS/TSA.
- Q: CI harness running all golden/reject/tamper vectors on native and wasm32 with bit-match assertion; indefinite per-version vector retention; skeleton threat-model doc file receiving C20/C21 content; RUSTSEC tracking for the pinned `ml-dsa` advisories; cargo-fuzz infrastructure (C supplies no fuzz targets — CBOR/DER fuzzing is F's/A's).
