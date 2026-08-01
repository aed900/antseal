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

### C22 — Decide the disposition of the un-zeroized HKDF/HMAC key state (C21 residual risk R1)
- Milestone: M0 (decision) / M1 (implementation, if any)
- Size: S (accept) / M (replace)
- Deps: C2 (the derivation this touches is frozen); P7 dependency pin-governance; surfaced by C21
- Spec: Vault — zeroize (MVP-SPEC.md line 143); HKDF label registry (lines 94–98)
- Do: C21's sweep found that every `derive_*` call builds an `hkdf::Hkdf<Sha256>` whose internal `Hmac<Sha256>` is keyed with the HKDF **PRK**, and that `Hkdf::extract` additionally materialises and discards the raw 32-B PRK. Both are `W`-equivalent for that work (they reproduce every unit key, salt, fine seed and signing seed) and **neither is zeroized**. No feature fixes it: `hkdf =0.13.0` has no `zeroize` feature at all, and `hmac =0.13.0`'s `zeroize = ["digest/zeroize"]` does not help because `Hmac<D>` is generated by `digest::buffer_fixed!(… impl: MacTraits KeyInit)` and `MacTraits` expands to `BaseFixedTraits MacMarker`, which does not name `ZeroizeOnDrop` — `digest`'s macro only emits that impl for types whose trait list names it. Decide between: **(a)** accept permanently (exposure is one stack-resident value per derivation, never heap, never logged, never serialized, and `W` itself is resident for the same window — record as a permanent residual risk); **(b)** upstream a `ZeroizeOnDrop` addition to `hmac`'s `buffer_fixed!` invocation and re-pin when it lands; **(c)** replace the `hkdf` crate call with an in-house RFC 5869 extract/expand over a zeroizing HMAC (~40 lines; this crate's tests already carry an independent raw-HMAC reference implementation from C2's accept criteria, so the correctness evidence exists). Note (c) moves a **frozen derivation** into our own code and is a deliberate pin-governance event, never a drive-by.
- Accept:
  - A decision record (`docs/decisions/`) stating the choice with its reasoning, or an explicit dated "accepted permanently" row in `docs/zeroization-audit.md` R1.
  - If (c): byte-identical output against the existing HKDF golden vectors and the C2 raw-HMAC reference, on native **and** wasm32, before the swap lands.
  - If (a) or (b): `docs/zeroization-audit.md` R1 updated with the dated disposition; the Q14 freeze checklist notes it as known-and-accepted rather than open.
- Notes: **[2026-07-28] RESOLVED by D88 — none of (a), (b), (c).** The decision is option **(d)**, which this entry does not list: enable the non-default `zeroize` feature on the existing `sha2 =0.11.0` pin. This entry's premise — "No feature fixes it" — is **false**: `digest`'s `buffer_fixed!` `ZeroizeOnDrop` arm emits a *marker impl with no `Drop`*, so the trait bound on `Hmac<D>` was never the mechanism; the wipe is ordinary drop glue reaching `Sha256VarCore::drop` and `BlockBuffer::drop`, both gated on `sha2`'s feature. Measured: the full 144-byte `Hkdf<Sha256>` wiped, including the block buffer that holds `W` **verbatim** (this entry also understates the exposure — see D88 §1). Implement `docs/decisions/D88-hkdf-hmac-zeroization.md` §4/§6/§7 exactly; the work is one `Cargo.toml` word plus two residue regression tests plus doc edits, and it lands **before Q14**, not at M1.

### C23 — Sweep for un-wiped secret preimage buffers we own
- Milestone: M0
- Size: S
- Deps: C21 (the sweep this widens), C22/D88 (lands first — it changes what is left over)
- Spec: Vault — zeroize (MVP-SPEC.md line 143); GGM hiding (line 96); security assumptions class 3
- Discovered by: **D88** (2026-07-28). C21's table E scoped "intermediate buffers" to `crypto/` and to buffers handed *to* a primitive. It missed the class where **we build a secret preimage into a buffer we own and drop it un-wiped**. D88 §2b found the shape via `Sha256`'s internal buffer (fixed by D88's feature enable), but the caller-side buffers are ours and no feature touches them: `crypto::domain::tagged_sha256` assembles `tag ‖ parts` where the parts include GGM covering seeds (`content::ggm::child_seed`), `unit_salt`, `file_salt` and `path_salt`; `content/fine_tree` builds leaf and node preimages the same way. A leaked ancestor seed opens leaves a reveal deliberately withheld, so these are not the already-disclosed class R2 covers.
- Do: Enumerate every site in `crates/antseal-core/src/crypto/` and `crates/antseal-core/src/content/` that assembles a buffer containing secret material (master secret, any derived key/salt/seed, GGM seeds, decrypted unit plaintext) and does not wipe it before drop. For each, record: the buffer, its lifetime, whether the secret is already disclosed by the bundle at that point (R2's argument), and the disposition — wiped, or accepted with the reason. Wipe the ones where the secret is *not* already disclosed, starting with the GGM seed preimages. Where a buffer is handed onward and cannot be wiped, record it in the same table rather than fixing it (R3's precedent).
- Accept:
  - A new table in `docs/zeroization-audit.md` covering caller-owned secret preimage buffers, with every site's disposition; the existing table E cross-references it.
  - Every GGM seed preimage buffer is wiped before drop; a test asserts it for at least `child_seed` using D88's residue-probe technique.
  - No golden vector byte changes (wiping is post-hash); `scripts/vector-freeze.sh` green without `--update`.
  - `wasm32-unknown-unknown` build passes.
- Notes: Do **not** widen this into R3's territory — decrypted unit plaintext returned to a caller is already dispositioned as caller-owned and stays that way.

### C24 — Guard the `sha2` zeroize feature against silent removal
- Milestone: M0
- Size: S
- Deps: C22/D88
- Spec: Vault — zeroize (MVP-SPEC.md line 143); dependency pin governance (P7)
- Discovered by: **D88** (2026-07-28). D88's fix is a Cargo feature whose effect is `Drop` behaviour, and **no compile-time detector can see it**: `crypto.rs::zeroization_sweep`'s `ZeroizeOnDrop` const assertions pass identically with the feature on or off, because `Hmac<Sha256>` never implements the trait either way. A routine dependency edit that drops `features = ["zeroize"]` — exactly what `docs/dependency-policy.md` §4 exists to catch for *versions* — would silently restore recoverable `W` and GGM-seed residue with a green test suite.
- Do: Add a guard that fails loudly if the feature is off. Two layers, both cheap: (1) a `#[cfg(not(feature = ...))]`-style compile-time assertion is **not** available (the feature belongs to `sha2`, not to us), so instead assert it from the build side — a test that reads the workspace `Cargo.toml` and requires the `sha2` entry to list `zeroize`, in the same spirit as the existing pin-shape tests; (2) the runtime residue tests D88 §6 step 3 lands, which are the only true detector. Cross-reference both from `docs/dependency-policy.md` §1's exact-pin row so a future bump reviewer is told where the guard lives.
- Accept:
  - Removing `features = ["zeroize"]` from the `sha2` pin turns the suite red, demonstrated once by actually removing it.
  - The failure message names D88 and says what the feature protects, not just "assertion failed".
  - `docs/dependency-policy.md` §1 names the guard.
- Notes: This is the generic hazard for any *feature*-carried security property; if a second one appears, generalise the Cargo.toml assertion into a small table rather than duplicating it.

### C25 — Decide whether the material newtypes' `from_bytes` should take a reference
- Milestone: M0 (decide) / M1 (act, if the answer is by-reference)
- Size: S
- Deps: C23 (the sweep that recorded it), C7 (the newtype API this changes), C22/D88 (the standard of evidence)
- Spec: Vault — zeroize (MVP-SPEC.md line 143); GGM hiding (line 96); security assumptions class 3
- Discovered by: **C23** (2026-07-28), which recorded it in `docs/zeroization-audit.md` table F (lines 141–147) as a deliberate non-wipe rather than fixing it. **This entry was itself missing** — TODO.md carried the one-liner and `tasks/C.md` never gained the detail entry; written up in wave 7, and the investigation found the one-liner understates the scope in two ways.
- **Correction 1 — the temporary is not confined to the `*seed.as_bytes()` sites.** A by-value `from_bytes` materialises an un-wipeable argument copy at *every* call, and that includes all of the buffers **C23 itself wiped**: `crypto/hkdf.rs:223`, `:231`, `:239` are `let out = Key32::from_bytes(okm); okm.zeroize();` — `okm` is `[u8; N]`, which is `Copy`, so the call copies the secret into the argument slot *before* the named local is wiped. Same shape at `crypto/material.rs:190-191` and `:213-214`, `content/ggm.rs:453-454`, `content/fine_tree/ggm_walk.rs:127-128`, `content/fine_tree/cover.rs:399-400`, `content/fine_tree/verify.rs:353-354`. So C23's six wipes cover the named local and not the argument slot, and one change at the macro closes both classes at once. That is the real argument for this task, and it is stronger than the one the one-liner makes.
- **Correction 2 — the audit's site list is short by one.** `docs/zeroization-audit.md:141-147` names three production sites (`ggm::SaltTree::derive_along`, `ggm_walk::GgmWalker::new`, `cover::descend`). There are **four**: `content/fine_tree/cover.rs:395`, inside `pub fn canonical_leaf_level_payload`, is the same `Seed32::from_bytes(*seed.as_bytes())` shape in the same file and is not listed. It is on a production path — `cover_seeds` (`cover.rs:343`) calls it at `cover.rs:350` for every cover node whose `address.level() != depth`, i.e. every non-leaf-level node. That is a fact about the audit, not about the fix, and it should be corrected whichever way the decision goes.
- The surface, verified at HEAD. The by-value signature is emitted once, by `material_newtype!` at `crates/antseal-core/src/crypto/material.rs:104` (macro declared `:93`; invoked for `Key32` `:148`, `Seed32` `:155`, `Salt16` `:163`; `UnitKey` and `ManifestKey` are aliases of `Key32`), plus `MasterSecret::from_bytes([u8; 32])` at `crypto/secrets.rs:78`. `as_bytes()` already returns `&[u8; N]` (`material.rs:110`), so the reference form needs no new accessor — and the precedent is already in the same module: `MasterSecretRef::from_bytes` takes `&'a [u8; 32]` (`material.rs:74`). The newtypes do wipe (`Zeroize` `material.rs:131`, `Drop` `:137`, `ZeroizeOnDrop` `:144`, roll-up asserted at `crypto.rs:164` `zeroization_sweep` and `material.rs:436`) and the source value is borrowed rather than consumed, so the argument temporary really is the only un-wiped copy at those sites.
- Blast radius, measured: **none outside the crate**. The three material constructors appear zero times in `antseal-cli`, `antseal-net`, `antseal-anchor`, `wasm-bitmatch`, `verifier-web/` and `probes/`; all 142 occurrences are inside `antseal-core`. There is no wasm-bindgen surface anywhere in the workspace to break. It *is* `pub` API on a crate that does not set `publish = false`, so it is semver-breaking in principle with no consumer in practice — which is exactly why now is the cheap moment.
- Do: decide by-value or by-reference for the whole material API at once and record it; a per-type answer is the outcome to avoid, because the value of the change is that one rule covers every call. If by reference: change `material.rs:104` and `secrets.rs:78`, keep both `const fn` (a `&[u8; N]` parameter stays const-legal), and state explicitly whether the public non-secret newtypes move with them (`NodeHash32` `material.rs:238`, `SealId` `secrets.rs:157`, `Nonce24` `unit_aead.rs:110` and `manifest/body.rs:115`, `FineRoot` `content/fine_tree/build.rs:83`, `WorkId`/`AnchorDigest` `manifest/ids.rs:79`, the `wire_value` signature types) — uniformity has a real argument and so does leaving non-secrets alone; what is not defensible is not saying which. Decide `into_bytes` (`material.rs:118`) in the same breath: it hands out a copy that does not self-wipe, it is residual risk **R4** (`docs/zeroization-audit.md:286-296`), and it is the same question one step further on.
- Accept:
  - A recorded decision, or an explicit dated "accepted permanently" row in `docs/zeroization-audit.md` table F — silence is the one outcome that loses the analysis.
  - Table F's site list reads four, not three, either way.
  - If changed: no golden vector byte moves — this is a calling convention, not a derivation — so `scripts/vector-freeze.sh` is green without `--update`, and `wasm32-unknown-unknown` still builds.
  - The claim "the argument temporary is the only un-wiped copy" is stated where a reader of `from_bytes` will see it, not only in the audit.
- Notes: The argument is hygiene, not performance — do not justify it on the elided copy, which the optimiser is free to remove or keep and which nothing here measures. **C26** owns the separate question of whether any of this can be *asserted*; keep the two apart. Waiting for C26 before acting here would leave a known copy standing on the strength of a probe that may turn out not to exist.

### C26 — Decide whether caller-owned local wipes can be asserted at all
- Milestone: M0 (decide) / M1 (act)
- Size: S
- Deps: C23 (the six wipes this would guard), C22/D88 (the probe whose reach is in question)
- Spec: Vault — zeroize (MVP-SPEC.md line 143); security assumptions class 3
- Discovered by: **C23** (2026-07-28), on the asymmetry between its own evidence and D88's. **This entry was itself missing** — TODO.md carried the one-liner and `tasks/C.md` never gained the detail entry; written up in wave 7, and writing it found C23's Accept criterion undischarged.
- The premise, verified. D88's claims are **measured**, by `crates/antseal-core/tests/zeroization_residue.rs`: `residue_after_drop` (line 82) allocates the value's exact `Layout`, poisons every byte with `0xAA` (line 78, so "untouched" is distinguishable from "wiped" and an all-zero result cannot be an artefact of a fresh allocation), `ptr::write`s the constructed value in, runs `ptr::drop_in_place` — which does not free — and reads the bytes back. Four tests: the control `probe_reads_real_bytes_of_a_type_that_does_not_wipe` (line 135), which exists so that "all zero" is falsifiable, plus `dropped_hkdf_extract_context_retains_no_verbatim_master_secret` (161), `dropped_hkdf_state_retains_no_master_secret_bytes` (201) and `dropped_sha256_retains_no_ggm_seed` (237).
- **Why it does not reach C23's sites — and the first reason is stronger than the one the one-liner gives.** (1) `[u8; N]` has **no `Drop`**. C23's wipe is an explicit `.zeroize()` statement in the middle of a function, not destructor glue, so there is nothing for `drop_in_place` to run; the probe measures drop, and these sites have no drop. (2) The storage is a callee's stack slot, and the technique works precisely because the *test* owns the allocation — a caller cannot hand a callee's frame to it, and reading it after return is reading a dead frame. The one-liner's "cannot be probed without asserting on UB" is true (the caveat is recorded at `tests/zeroization_residue.rs:45-51` and is why this is a test-only device) but it is the second obstacle, not the first.
- **The finding this write-up produced, and it is the sharper one.** C23's Accept bullet 2 reads *"Every GGM seed preimage buffer is wiped before drop; a test asserts it for at least `child_seed` using D88's residue-probe technique."* **No such test exists.** The only candidate, `dropped_sha256_retains_no_ggm_seed`, is **C22/D88's** — specified verbatim at `docs/decisions/D88-hkdf-hmac-zeroization.md:266-269`, its doc comment citing D88 §2b — it never calls `content::ggm::child_seed`, and it probes the third-party hasher's `BlockBuffer`, which is `sha2/zeroize`'s doing and not C23's. Nor could such a test be written: `child_seed` (`content/ggm.rs:328`) owns no preimage buffer at all — it passes borrowed slices to `tagged_sha256` (`crypto/domain.rs:110`), which streams its parts into the hasher and owns nothing. The same is true of `fine_tree::leaf_hash` and `node_hash` (`content/fine_tree/build.rs:111`, `:122`). So that bullet was **unachievable as written**, and the wipe it asks for does not exist because there is nothing there to wipe. Corroborating: `grep -rn "C23" crates/ --include=*.rs` is seven hits, all under `src/`, **none under `tests/`** — not one of C23's six wipes has a test.
- Do: choose between three answers and record it. **(a) Accept permanently** — the six wipes stay review-only, recorded as a named residual in `docs/zeroization-audit.md` with the argument, leaning on the `C23:` source markers a reviewer greps. **(b) Move the wipe to where it can be asserted** — replace the raw `[u8; N]` locals with a small zeroize-on-drop wrapper, at which point the existing probe works unchanged and the claim becomes measured. This is the same move D88 made: stop asking for a hand-written wipe and let drop glue do it. **(c) Assert something weaker but real** — a source-level check that every `C23:`-marked buffer is followed by a `.zeroize()` before its scope ends; that catches deletion, not correctness, and should be labelled as such. Whichever wins, close the cheap gap found here: **nothing probes `Key32`/`Seed32`/`Salt16`'s own drop-wipe.** It is asserted today only by the `ZeroizeOnDrop` trait bound (`crypto.rs:164`, `material.rs:436`) and by `explicit_zeroize_wipes` (`material.rs:448`), which calls `.zeroize()` on a *live* value and reads it back — neither observes a drop. Those types are directly probeable with the existing helper.
- Accept:
  - A recorded decision with its reasoning; if (a), a dated residual row rather than silence.
  - C23's Accept bullet 2 is corrected **at source**: the `child_seed` claim is withdrawn with the reason (no owned buffer exists), rather than left reading as discharged.
  - If (b) or (c): removing one wipe turns the suite red, demonstrated once by actually removing it.
  - The material newtypes gain a `residue_after_drop` probe under every option — it is four lines and it is the one claim in this area that is trivially measurable and currently is not.
- Notes: Keep the probe's test-only boundary; `residue_after_drop` reads storage the abstract machine considers deinitialised, and no answer here may promote it to a library helper. Do **not** widen into R2/R3's territory — a secret the bundle has already disclosed, or a plaintext handed back to a caller, is dispositioned elsewhere and stays there. Two statements in `crates/antseal-core/src/crypto.rs` are stale at HEAD and will mislead whoever picks this up: line 159 (*"would fail the build rather than pass a green test suite"*, which `docs/zeroization-audit.md:21-27` calls false for `sha2`) and lines 210–212 (*"no feature combination on the pinned crates makes it wipeable"*, the exact premise D88 §1 marks FALSE). Correct them here or under C24; do not cite them as current.

### C27 — Make `signatures.json`'s ML-DSA half re-derivable by the cross-check
- Milestone: M0
- Size: S
- Deps: Q11 (the cross-check lane), C16 (the vector), D31 rows 12/13 (the T0 vehicle that already covers the primitive)
- Spec: Revision-2 independent cross-check mandate (MVP-SPEC.md line 5); hybrid author signature (line 97, line 104)
- Discovered by: **Q11** (2026-07-28), which recorded it as a known gap in `docs/testing/cross-check.md` §5 and marked it *"by design"*. **This entry was itself missing** — TODO.md carried the one-liner from wave 6 and `tasks/C.md` never gained the detail entry; written up at execution in wave 7.
- The claim, verified on the tree rather than taken on trust: **it held.** `gen_vectors.py::check_all` loaded the committed `signatures.json`, copied `expect.mldsa65.public_key` and `.signature` into a `borrowed` dict, passed that to `gen_signatures_from`, which re-emitted both fields verbatim — and then byte-compared the result against the file it had just read them from. The two fields cancelled exactly, so a tamper of either left `--check` **green**. Confirmed by planting one: the byte-diff leg stays green under a flipped nibble in `public_key`.
- Honest framing, which the record must keep: **this is completeness, not soundness.** ML-DSA-65 is covered at tier **T0** by NIST ACVP (D31 rows 12/13, replayed from Rust in `crates/antseal-core/tests/acvp_ml_dsa.rs`), and `signatures.json`'s bytes are separately frozen by `FROZEN.sha256`, so the tamper was never invisible to CI as a whole — only to *this checker*. Do not upgrade the language to "a hole in the signature cross-check".
- Do: The phrase carrying the weight was "cannot be re-derived here", and it was doing more work than it should. Three properties are derivable in stdlib Python, and the fourth is a pin. In `check_mldsa_half`:
  1. **Lengths** — pk 1952, sig 3309 (FIPS 204 Table 2, ML-DSA-65).
  2. **ρ, re-derived from the HKDF seed** — Algorithm 6 `KeyGen_internal` computes `(ρ, ρ′, K) = H(ξ ‖ IntegerToBytes(k,1) ‖ IntegerToBytes(ℓ,1), 128)` with H = SHAKE-256 and `(k, ℓ) = (6, 5)`, and `pkEncode` places ρ in the first 32 bytes. `hashlib.shake_256` is stdlib, so the first 32 bytes of the committed public key are checkable as a pure function of the seed — which is itself HKDF of `W`. **This is the strongest leg**: it ties the committed key to the master secret through two independent derivations.
  3. **Hint-section validity** — Algorithm 21 `HintBitUnpack` over the trailing ω + k = 61 bytes: cut points non-decreasing and ≤ ω, indices strictly increasing within each polynomial, pad above the last hint zero.
  4. **A residue pin** — `SHA-256(pk ‖ sig)`, covering `t1` and the `c̃`/`z` sections legs 2 and 3 cannot reach. This is what makes the coverage total: with it, any single-byte change to either field turns `--check` red.
- Accept:
  - A tamper of `expect.mldsa65.public_key` or `.signature` turns `scripts/cross-check.sh --check` red. **Two standing self-test cases** in `cross-check.sh` prove it, and they prove specifically the right thing: the byte-diff leg **stays green** under both faults — the tautology is still there and still visible — and the red comes only from `check_mldsa_half`.
  - The self-test fault is targeted (`field:"mldsa65":public_key`), because the generic per-directory fault lands in the first `*.json` alphabetically, which is `commitments.json` — signatures.json's ML-DSA half had never been fault-planted at all.
  - `docs/testing/cross-check.md` §5's "by design" row is corrected rather than deleted, and still names ACVP as the real vehicle.
- Notes: Leg 2 is specific to the **final** FIPS 204 (August 2024). The 2023 draft omitted the `k ‖ ℓ` domain separator, so an implementation of the draft fails this check — deliberately, since `ml-dsa =0.1.1` implements the final standard and a silent regression to draft behaviour is exactly the kind of thing a golden vector should catch. `MLDSA65_RESIDUE_SHA256` moves with the vector: if the ML-DSA half is ever legitimately re-emitted the constant moves in the same commit, exactly as that file's `FROZEN.sha256` entry does, and the failure message prints the observed digest so the update is a copy-paste. It is deliberately not auto-updatable — "regenerate until it agrees" is the move D31 §11 item 5 forbids.

### C28 — `verify_body`'s claimed duplicate re-check does not exist, and `lookup` is first-wins
- Milestone: M0 (post-freeze residue)
- Size: XS
- Deps: C14
- Spec: no first-wins/last-wins divergence between conforming implementations (MVP-SPEC.md line 73)
- Discovered by: the **2026-07-31 adversarial code review** (finding 5, `medium→low` after verification).
- Problem: `crypto/sig_policy.rs:221-224` documents that pubkeys and signatures are "both already duplicate-free and exact-length by F's schema, and re-checked here **so this function is safe to call on any input**". Exact-length *is* re-checked (`try_from_slice` → `NonCanonicalSignature`). Duplicate-freedom is **not**: the unlisted-algorithm loop (247-251) only tests `policy.requires(alg)`, which a duplicate of a listed algorithm passes, and `lookup` (275-280) is `Iterator::find` — strictly first-wins. A caller of the pub API passing `[(Ed25519, valid), (Ed25519, garbage), (MlDsa65, valid)]` gets `Ok(Hybrid)`; a last-wins or duplicate-rejecting implementation reaches a different verdict on the same input.
- Do: Either add the duplicate check the doc promises (making the "safe on any input" claim true), or delete that clause and state plainly that the function's contract requires a duplicate-free input which only F's schema establishes. Prefer the former — it is a few lines and the doc already told everyone it was there.
- Accept:
  - A duplicated listed algorithm is rejected, or the doc no longer claims it is.
  - The chosen behaviour has a test with a *duplicate* in it, not just a well-formed input.
- Notes: Not reachable through the shipped pipeline — F's schema does reject duplicates before `verify_body` sees them — which is why the verifier corrected this down to `low`. It matters because `antseal-core` is a published API surface and this is a cross-implementation divergence class the spec names explicitly. Related, and deliberately separate: **U16** in the review (a missing *pubkey* is reported as `crypto-signature-missing-*`, collapsing two distinct mutations onto one code).

### C29 — `verify_body` silently ignores unlisted pubkeys
- Milestone: M0 (post-freeze residue)
- Size: XS
- Deps: C28, C14
- Spec: no first-wins/last-wins/lenient divergence between conforming implementations (MVP-SPEC.md line 73)
- Discovered by: **C28** (2026-08-01), while confirming finding 5.
- Problem: the present-set == policy-set rule is enforced for `signatures` only. A `pubkeys` entry for an algorithm the policy does not list draws no error and no lookup — it cannot change the verdict here, but an implementation that also rejects unlisted pubkeys reaches a different verdict on the same input: the same spec-line-73 divergence class C28 just treated, one collection over.
- Do: decide — enforce symmetry (reject an unlisted pubkeys entry; reuse an honest variant or append per D30 §3) or record the acceptance in `verify_body`'s doc with the reason. Either way the doc must state exactly what is checked, which is the standard C28 set.
- Accept:
  - A test with an unlisted pubkey entry in it pins the chosen behaviour.
  - `verify_body`'s doc matches the mechanism; no silent asymmetry survives undocumented.
- Notes: U16 (missing-pubkey collapses onto `crypto-signature-missing-*`; Display text then factually wrong) stays deliberately separate; C28's report records a one-line fix sketch if it is ever promoted to a task.

## Open decisions (C)
- **ed25519-dalek exact pin (2.x vs 3.0.0)** — chosen from C11's probe with P; blocks C11→C12, C15, C16; must land by M0 (start). — **[2026-07-27]** RESOLVED (D13): `=3.0.0`; C12 consumption shape `default-features = false, features = ["alloc","zeroize"]`; never enable `legacy_compatibility` (C11 report §9).
- **Primary ML-DSA crate (`ml-dsa =0.1.1` vs `fips204 =0.4.6` fallback) and whether the Ed25519-only `sig_policy` fallback ships** — outcome of the C11 WASM probe; blocks C13, C14, C15, C16; M0. — **[2026-07-27]** RESOLVED (D14): primary `ml-dsa =0.1.1` (wasm32 executed bit-match; canonical rejection complete at `Signature::decode` — C13 needs NO pre-validation layer); fips204 pinned-unconsumed byte-identical fallback; **Ed25519-only fallback NOT shipped**. C13: use `sign_deterministic`/`verify_with_context`, enable the non-default `zeroize` feature, zeroize ξ caller-side.
- **ML-DSA signing mode: hedged (FIPS 204 default) vs deterministic** — determines whether signature golden vectors pin sign-output bytes or keygen+verify-only; blocks C16; M0. — **[2026-07-27]** D15 inputs captured (C11): the pinned crate's default sign path is deterministic (rnd = 0³²), hedged sits behind a rand_core feature; deterministic output is cross-implementation byte-identical (fips204 probe check) → portable sign-output vectors favor deterministic. Resolve at C13/C16.
- **Mechanism for the distinct non-canonical-Ed25519-S error: rely on the pinned dalek version's parse-time `S ≥ L` rejection vs an explicit pre-validation layer** — decided from C11's findings; blocks C12, C17; M0. — **[2026-07-27]** RESOLVED (D16): **explicit pre-validation layer in C12** — dalek's `Signature` parse is infallible on both lines (S ≥ L only checked inside verify, opaque error); C12 pre-checks S < L plus A-canonicality (ZIP-215 `VerifyingKey::from_bytes` gap: decompress→recompress→compare) (C11 report §9).
- **Registered `sig_policy` algorithm-ID values (numeric IDs + reserved slots), coordinated with F's CBOR schema** — blocks C14, C15; M0 (format freeze). — **[2026-07-27]** D17 proposal drafted in the F4 registry: 0 = ed25519, 1 = ml-dsa-65, 2–15 reserved (ed25519 = 0 because the fallback policy is `[0]`); freeze with F4/C14 at Q14. R2 note: signature error codes went per-algorithm (`crypto-signature-*-{ed25519,ml-dsa-65}`) — C14 ratifies.

## Cross-domain expectations
- P: workspace + `antseal-core` scaffold; exact pins for `sha2`, `hkdf`, `chacha20poly1305`, `ed25519-dalek`, `ml-dsa =0.1.1`, `fips204 =0.4.6`, `zeroize`, `subtle`, `thiserror`, `proptest`, `rand_core`/`getrandom` with the exact wasm_js backend recipe; wasm32-unknown-unknown in CI from day one.
- F: deterministic-CBOR manifest schema carrying the 24-B nonce (single authoritative copy), `true_length`, kind-conditional `unit_commit` field, pubkeys, `sig_policy`, signatures over the embedded-bstr body verified without re-encoding; `work_id`/`anchor_digest` computed over exact received bytes; storage-record `{address, nonce, k_m}` schema; golden-vector assertion that encoded manifest/body first byte ∉ `0x00–0x06` (using C1's `MAX_DOMAIN_TAG`).
- G: per-unit fine-tree-coverage determination driving C7's `UnitBinding`; `fine-seed`/`s_root` derivation via C2's `"fine-seed"` entry; the GGM-side disclosure guard (no ancestor seed of an unrevealed leaf, `s_root` full-reveal-only) mirroring C7; canonical bytes as `canon_commit` input; consumption of C1's tags `0x00`/`0x01`/`0x06`.
- R: verifier orchestration calling C's decrypt/strip/commitment-verify/sig-policy functions per revealed unit; execution of the 16-B/32-B length checks via C6's newtypes on all bundle-supplied salts/seeds/node hashes; the `file_salt`/`s_root`-present-on-partial-reveal tamper check; rendering "hybrid (PQ)" vs "Ed25519-only" from C14's result datum.
- S: journal/resume enforcement of the `(k_u, nonce)` single-use invariant — byte-identical staged-ciphertext re-upload, abort-rather-than-re-encrypt under a journaled nonce.
- U: vault persistence of `W` and records; Argon2id/scrypt vault KDF; passphrase collection via C5's zeroizing `SecretBuf` type.
- A: consumption of `anchor_digest` (SHA-256 over full plaintext manifest bytes, computed at the F boundary) as the sole datum submitted to OTS/TSA.
- Q: CI harness running all golden/reject/tamper vectors on native and wasm32 with bit-match assertion; indefinite per-version vector retention; skeleton threat-model doc file receiving C20/C21 content; RUSTSEC tracking for the pinned `ml-dsa` advisories; cargo-fuzz infrastructure (C supplies no fuzz targets — CBOR/DER fuzzing is F's/A's).
