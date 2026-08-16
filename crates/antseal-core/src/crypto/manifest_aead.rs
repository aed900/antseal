//! Manifest AEAD: XChaCha20-Poly1305 over the plaintext manifest bytes with
//! an **empty AAD**, producing the opaque blob that is the only manifest copy
//! the network ever stores (tasks/C.md C10; MVP-SPEC.md line 98).
//!
//! ```text
//! k_m       = HKDF(W, "manifest-key", sentinel)   (C2; 32 B)
//! nonce     = 24 random bytes, drawn HERE, fresh per encryption
//! AAD       = empty                                (frozen; MANIFEST_AAD)
//! plaintext = the encoded manifest bytes           (F's canonical CBOR)
//! ```
//!
//! # Why the network copy is encrypted (spec line 98)
//!
//! Autonomi storage is public, permanent and content-addressed. Uploading a
//! plaintext manifest would publish the work's title, its file/unit
//! structure, its commitments and its pubkeys forever. Encrypting it means
//! **the network holds opaque AEAD bytes only** — title, path commitments,
//! sizes and pubkeys never appear in plaintext on the network. Wrapping in a
//! randomized AEAD *before* upload is also what keeps Autonomi's convergent
//! self-encryption from turning the manifest into a confirmation oracle: two
//! sealers with the same manifest bytes upload different ciphertexts.
//!
//! # Anchored bytes ≠ stored bytes (spec line 98)
//!
//! Anchors bind `anchor_digest` over the **plaintext** manifest bytes, and a
//! `.sealproof` bundle embeds those same plaintext bytes. The blob produced
//! here exists only for network persistence, so a bundle additionally carries
//! the **manifest storage record** `{address, nonce, k_m}` — this module
//! emits the `{nonce, k_m}` half ([`ManifestStorageRecord`]); `address` comes
//! from S's self-encryption upload.
//!
//! **Disclosing `k_m` in a bundle discloses nothing.** `k_m` decrypts exactly
//! one thing — the manifest the bundle already embeds in plaintext — and it
//! is derived under its own HKDF label with the sentinel id, so it reveals
//! nothing about `W` or about any unit key (label separation, C2). It ships
//! so a recipient can check that the network copy at `address` really is this
//! manifest (the persistence check), not to grant access to anything new.
//!
//! # Empty AAD is normative
//!
//! [`MANIFEST_AAD`] is the empty slice and this module is the only place that
//! chooses it. Unlike a unit ciphertext — which is bound to its work and slot
//! by `AAD = seal_id ‖ LE64(unit_id)` (C9) — the manifest is a single
//! work-global object whose identity is already fixed by `k_m`'s derivation
//! from that work's `W`: there is no sibling manifest to confuse it with, so
//! there is no context to bind. Changing this is a format event: a ciphertext
//! made with any non-empty AAD does not decrypt here (test
//! `non_empty_aad_ciphertext_fails_decrypt`, driven by the test-only
//! mis-encryptor below).
//!
//! # The `(k_m, nonce)` single-use invariant
//!
//! `k_m` is work-global and *not* nonce-diversified by an id, so the fresh
//! random 24-byte nonce is the entire separation between two encryptions of a
//! manifest under one `W` (re-seal after an edit, resume after a crash).
//! Structurally enforced exactly as in C9: **no public API accepts a
//! caller-supplied encryption nonce** — [`encrypt_manifest`] draws one
//! internally from the injected CSPRNG on every call, and so does the
//! test-only mis-encryptor. XChaCha20's 192-bit random nonce makes collision
//! probability negligible.
//!
//! One crate-internal door takes a nonce, and it is not an encryption:
//! `recompute_manifest_blob` reproduces a blob that already exists, from a
//! bundle's own plaintext manifest and its own recorded `{nonce, k_m}`, so
//! R20's offline storage-linkage stage can hash it into an address. It is
//! `pub(crate)` precisely so the sentence above stays true of the API this
//! crate exports; its own docs carry the argument.
//!
//! **The crate does export a nonce-taking *reproduction*, and it is not this
//! module's (R81).** `verify::storage_linkage::recompute_manifest_storage_blob`
//! is `pub`, because `verify --live` must byte-compare the network's copy of
//! the manifest blob against the bundle's own. Read literally, the claim
//! above is unmoved — it governs **encryption** APIs, and no public function
//! of this module accepts a nonce — and the widening was argued rather than
//! assumed: that door takes a `ManifestLinkageSubject`, whose four fields are
//! already `pub` because `check_storage_linkage` is a public stage, so a
//! caller gains no material they could not already read out of the bundle
//! (`k_m` ships in every bundle and opens only the plaintext the bundle
//! already embeds). It is named here so this paragraph cannot be read as
//! promising more than it says; the full ruling lives on that function.
//!
//! # AEAD is confidentiality-only (spec line 103)
//!
//! XChaCha20-Poly1305 is not key-committing (invisible-salamanders /
//! partitioning class). This is acceptable because **no verdict-bearing
//! check relies on a ciphertext decrypting to a unique plaintext** — the
//! manifest's identity is bound by `work_id`/`anchor_digest` over its
//! plaintext bytes and by the author signatures, never by the fact that this
//! blob decrypted. **A future refactor MUST NOT drop a content commitment in
//! favor of trusting the AEAD.**
//!
//! That sentence is the frozen rule of assumption class 4 in
//! `docs/security-assumptions.md` (C20, signed off 2026-07-28). It is
//! carried verbatim here and in [`crate::crypto::unit_aead`], and its
//! presence in both is machine-checked by
//! `crates/antseal-core/tests/security_assumptions_drift.rs` — deleting it
//! fails the test suite.

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use rand_core::TryCryptoRng;

use super::error::CryptoError;
use super::hkdf::derive_manifest_key;
use super::material::{Key32, MasterSecretRef};
use super::unit_aead::Nonce24;

/// The 32-byte manifest AEAD key `k_m = HKDF(W, "manifest-key", sentinel)`
/// (spec line 98). An alias of the zeroize-on-drop [`Key32`] material type,
/// like C9's `UnitKey`.
///
/// Unlike a unit key this one is **work-global** (sentinel id — there is one
/// manifest per work) and it is disclosed in every bundle as part of the
/// manifest storage record (module docs: it opens nothing the bundle does not
/// already contain).
pub type ManifestKey = Key32;

/// The frozen manifest AAD: **empty** (spec line 98). Public so F's schema
/// docs and the golden vectors can pin it, and so the choice has exactly one
/// definition in the codebase (module docs).
pub const MANIFEST_AAD: &[u8] = &[];

/// The `{nonce, k_m}` half of the **manifest storage record**
/// `{address, nonce, k_m}` (spec line 98; F's schema). `address` is produced
/// by S when the blob is uploaded, so it is not this type's business.
///
/// Owns the key, so it inherits [`ManifestKey`]'s wiping `Drop`; the nonce is
/// public data. Deliberately not `Clone`: uncontrolled key copies defeat
/// zeroization (C5 discipline).
pub struct ManifestStorageRecord {
    nonce: Nonce24,
    k_m: ManifestKey,
}

impl ManifestStorageRecord {
    /// The 24-byte nonce the blob was encrypted under (public; goes in the
    /// record verbatim).
    #[must_use]
    pub const fn nonce(&self) -> &Nonce24 {
        &self.nonce
    }

    /// The manifest key (module docs: bundle-disclosable).
    #[must_use]
    pub const fn key(&self) -> &ManifestKey {
        &self.k_m
    }

    /// Consume into the two record fields. The returned [`ManifestKey`] keeps
    /// wiping on *its* drop; a caller that copies the raw bytes out owns
    /// their hygiene from that point (U's vault zeroizes what it stores).
    #[must_use]
    pub fn into_parts(self) -> (Nonce24, ManifestKey) {
        (self.nonce, self.k_m)
    }
}

impl core::fmt::Debug for ManifestStorageRecord {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // The key redacts itself (`Key32`); render the public nonce.
        f.debug_struct("ManifestStorageRecord")
            .field("nonce", &self.nonce)
            .field("k_m", &self.k_m)
            .finish()
    }
}

impl zeroize::Zeroize for ManifestStorageRecord {
    fn zeroize(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.k_m);
    }
}

// Contract upheld by the inner `ManifestKey`'s wiping `Drop`.
impl zeroize::ZeroizeOnDrop for ManifestStorageRecord {}

/// Build the cipher over an explicit `k_m` — the shared core of the
/// W-derived and key-direct paths (C9's `cipher_for_key` shape). The
/// cipher's internal key copy zeroizes on *its* drop (the
/// chacha20poly1305 `zeroize` feature).
fn cipher_for_key(k_m: &ManifestKey) -> XChaCha20Poly1305 {
    // Static impossibility: `Key32::LEN` (32) is exactly the
    // XChaCha20-Poly1305 key size, so `new_from_slice` cannot fail.
    XChaCha20Poly1305::new_from_slice(k_m.as_bytes())
        .expect("Key32::LEN equals the XChaCha20-Poly1305 key size")
}

/// Encrypt plaintext manifest bytes under a fresh internally-drawn nonce and
/// the given AAD — the single shared path of [`encrypt_manifest`] and the
/// test-only mis-encryptor, so no code path exists that accepts an external
/// nonce (module docs).
fn encrypt_with_aad<R: TryCryptoRng + ?Sized>(
    w: MasterSecretRef<'_>,
    manifest_bytes: &[u8],
    aad: &[u8],
    rng: &mut R,
) -> Result<(Vec<u8>, ManifestStorageRecord), CryptoError> {
    let mut nonce_bytes = [0u8; Nonce24::LEN];
    rng.try_fill_bytes(&mut nonce_bytes)
        .map_err(|_| CryptoError::RngFailure)?;
    let nonce = Nonce24::from_bytes(nonce_bytes);

    let k_m: ManifestKey = derive_manifest_key(w);
    let cipher = cipher_for_key(&k_m);
    let xnonce = XNonce::from(nonce_bytes);
    // Precondition (documented, sealer-side): a manifest is orders of
    // magnitude below the XChaCha20-Poly1305 P_MAX (≈ 256 GiB). Exceeding it
    // would be a programming error, not an adversarial input.
    let blob = cipher
        .encrypt(
            &xnonce,
            Payload {
                msg: manifest_bytes,
                aad,
            },
        )
        .expect("manifest plaintext is far below the XChaCha20-Poly1305 P_MAX");
    Ok((blob, ManifestStorageRecord { nonce, k_m }))
}

/// Encrypt the plaintext manifest bytes into the **opaque blob** the network
/// stores, under `k_m = HKDF(W, "manifest-key", sentinel)`, a fresh random
/// 24-byte nonce drawn internally from the injected CSPRNG, and the frozen
/// empty AAD (spec line 98).
///
/// Returns `(blob, record)` where `record` carries the `{nonce, k_m}` half of
/// the manifest storage record (module docs); S supplies `address` after
/// upload.
///
/// There is deliberately no parameter to supply a nonce — the `(k_m, nonce)`
/// single-use invariant (module docs).
///
/// # Errors
///
/// [`CryptoError::RngFailure`] when the injected CSPRNG fails.
pub fn encrypt_manifest<R: TryCryptoRng + ?Sized>(
    w: MasterSecretRef<'_>,
    manifest_bytes: &[u8],
    rng: &mut R,
) -> Result<(Vec<u8>, ManifestStorageRecord), CryptoError> {
    encrypt_with_aad(w, manifest_bytes, MANIFEST_AAD, rng)
}

/// Decrypt the network blob back to the plaintext manifest bytes, deriving
/// `k_m` from `W` — the sealer-side path (`restore`, re-upload checks).
///
/// Thin delegation to [`decrypt_manifest_with_key`], the single AEAD-open
/// implementation, which is also the bundle-side entry point (the recipient
/// holds the record's `k_m`, never `W`).
///
/// # Errors
///
/// [`CryptoError::AeadDecryptFailed`] — wrong `W`/`k_m`, wrong nonce,
/// tampered blob, or a blob produced with a non-empty AAD (the AEAD cannot
/// and must not distinguish which).
pub fn decrypt_manifest(
    w: MasterSecretRef<'_>,
    nonce: &Nonce24,
    blob: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let k_m: ManifestKey = derive_manifest_key(w);
    decrypt_manifest_with_key(&k_m, nonce, blob)
}

/// Decrypt the network blob with an **explicit** `k_m` — the single
/// AEAD-open implementation, and the entry point for the bundle-side
/// **persistence check**: a `.sealproof` recipient holds the manifest storage
/// record `{address, nonce, k_m}` and never holds `W`, so this is how it
/// confirms that the bytes stored at `address` are the very manifest the
/// bundle embeds.
///
/// A failure here is a *persistence* finding, never an evidence finding:
/// verification is fully offline and does not depend on Autonomi
/// availability (spec line 98 / project rule 4).
///
/// # Errors
///
/// [`CryptoError::AeadDecryptFailed`] — as [`decrypt_manifest`].
pub fn decrypt_manifest_with_key(
    k_m: &ManifestKey,
    nonce: &Nonce24,
    blob: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = cipher_for_key(k_m);
    let xnonce = XNonce::from(*nonce.as_bytes());
    cipher
        .decrypt(
            &xnonce,
            Payload {
                msg: blob,
                aad: MANIFEST_AAD,
            },
        )
        .map_err(|_| CryptoError::AeadDecryptFailed)
}

/// Reproduce the network blob from the plaintext manifest bytes a bundle
/// already embeds, under that bundle's recorded `{nonce, k_m}` — the
/// **crate-internal** primitive R20's offline storage-linkage stage hashes to
/// recover the manifest's Autonomi address (`super::super::verify`).
///
/// # Why this is not an encryption, and does not breach the invariant
///
/// The module's `(k_m, nonce)` rule is about *minting* a second ciphertext
/// under a pair that has already been spent. This mints nothing: every input
/// is read out of one `.sealproof` that already exists, the output is the
/// blob that was uploaded at seal time, it is hashed and dropped, and no byte
/// of it is stored, transmitted, or handed to a caller who could store it.
/// XChaCha20-Poly1305 is deterministic in `(key, nonce, aad, plaintext)`, so
/// "re-encrypt and compare the address" is the only way to check a recorded
/// address offline — the bundle carries the *plaintext* manifest, and the
/// address is a hash of the *ciphertext* (spec line 98: anchored bytes ≠
/// stored bytes).
///
/// **`pub(crate)`, deliberately.** The module docs' structural claim — *no
/// public API accepts a caller-supplied encryption nonce* — is what keeps
/// `(k_m, nonce)` single-use, and it stays literally true: this module
/// exports no nonce-taking encryption door. A `pub` version of *this*
/// function would be a general encrypt-under-a-chosen-nonce API wearing a
/// verification name.
///
/// **R81 asked for exactly that widening and it was refused here.** `verify
/// --live` needs these bytes to compare the network's copy of the manifest
/// blob against the bundle's, and the cheap fix was one word on this line.
/// Instead the door is
/// [`verify::storage_linkage::recompute_manifest_storage_blob`], which takes
/// a [`ManifestLinkageSubject`] rather than a free `(key, nonce, plaintext)`
/// triple and lives in the verification layer, so the shape a careless future
/// caller reaches for is not the shape this offers. That function carries the
/// whole argument, including why the widening costs no material: its
/// parameter's four fields are already `pub`. Two callers now, both inside
/// the offline linkage layer's own vocabulary, and still no consumer of this
/// module.
///
/// [`verify::storage_linkage::recompute_manifest_storage_blob`]:
///     crate::verify::storage_linkage::recompute_manifest_storage_blob
/// [`ManifestLinkageSubject`]:
///     crate::verify::storage_linkage::ManifestLinkageSubject
///
/// Returns `None` if the cipher refuses the plaintext — reachable only above
/// XChaCha20-Poly1305's `P_MAX` (≈ 256 GiB), which no decoded manifest can
/// reach under F11's caps. It is an `Option` rather than an `expect` because
/// the input is adversary-supplied on this path (unlike
/// [`encrypt_manifest`]'s, which is the sealer's own), and library code that
/// a browser verifier runs must not panic on any input; and it is an
/// `Option` rather than a new [`CryptoError`] arm because the failure is not
/// a verification finding — the caller's only honest reading is *these bytes
/// have no address, so they cannot be the bytes at the recorded one*.
pub(crate) fn recompute_manifest_blob(
    k_m: &ManifestKey,
    nonce: &Nonce24,
    manifest_bytes: &[u8],
) -> Option<Vec<u8>> {
    let cipher = cipher_for_key(k_m);
    let xnonce = XNonce::from(*nonce.as_bytes());
    cipher
        .encrypt(
            &xnonce,
            Payload {
                msg: manifest_bytes,
                aad: MANIFEST_AAD,
            },
        )
        .ok()
}

/// Test-only mis-encryptor for the empty-AAD conformance test (`test-util`
/// feature; never part of a production build), mirroring C9's mis-encryptor
/// pattern.
///
/// [`encrypt_manifest_with_aad`](mis_encrypt::encrypt_manifest_with_aad)
/// produces a blob that is a perfectly valid XChaCha20-Poly1305 ciphertext
/// under the right `k_m` and a fresh nonce, but binds a **non-empty** AAD —
/// the only way to prove from the outside that [`decrypt_manifest`] really
/// authenticates under the empty AAD and nothing else.
#[cfg(any(test, feature = "test-util"))]
pub mod mis_encrypt {
    use super::{
        CryptoError, ManifestStorageRecord, MasterSecretRef, TryCryptoRng, encrypt_with_aad,
    };

    /// Encrypt a manifest binding an arbitrary (test-chosen) AAD instead of
    /// the frozen empty one; the resulting blob must fail
    /// [`super::decrypt_manifest`].
    ///
    /// # Errors
    ///
    /// [`CryptoError::RngFailure`] when the injected CSPRNG fails.
    pub fn encrypt_manifest_with_aad<R: TryCryptoRng + ?Sized>(
        w: MasterSecretRef<'_>,
        manifest_bytes: &[u8],
        aad: &[u8],
        rng: &mut R,
    ) -> Result<(Vec<u8>, ManifestStorageRecord), CryptoError> {
        encrypt_with_aad(w, manifest_bytes, aad, rng)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hkdf::{Label, SENTINEL_ID};
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;
    use zeroize::ZeroizeOnDrop;

    /// Fixed, public, NON-SECRET fixtures (project rule 6) — the same `W` the
    /// committed `testdata/vectors/v1/hkdf/hkdf-labels.json` derives from.
    const TEST_W: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D,
        0x1E, 0x1F,
    ];
    const TEST_SEED: [u8; 32] = [0x44u8; 32];

    /// Stand-in for F's canonical CBOR manifest bytes.
    const MANIFEST: &[u8] = b"\xa2\x00\x58\x20manifest body bytes (stand-in)\x01\xa0";

    fn w() -> MasterSecretRef<'static> {
        MasterSecretRef::from_bytes(&TEST_W)
    }

    fn test_rng() -> ChaCha20Rng {
        ChaCha20Rng::from_seed(TEST_SEED)
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// C10 accept: round-trip through both decrypt entry points, including
    /// the degenerate empty plaintext (a manifest is never empty, but the
    /// AEAD layer must not care).
    #[test]
    fn round_trip_through_both_entry_points() {
        const TAG_LEN: usize = 16;
        let mut rng = test_rng();

        let (blob, record) = encrypt_manifest(w(), MANIFEST, &mut rng).expect("encrypts");
        assert_eq!(blob.len(), MANIFEST.len() + TAG_LEN);
        // The blob is opaque: it does not contain the plaintext.
        assert!(!blob.windows(8).any(|window| window == b"manifest"));

        // W path (restore).
        assert_eq!(
            decrypt_manifest(w(), record.nonce(), &blob).expect("decrypts"),
            MANIFEST
        );
        // Key-direct path (bundle persistence check) — same implementation.
        assert_eq!(
            decrypt_manifest_with_key(record.key(), record.nonce(), &blob).expect("decrypts"),
            MANIFEST
        );

        let (empty_blob, empty_record) = encrypt_manifest(w(), b"", &mut rng).expect("encrypts");
        assert_eq!(empty_blob.len(), TAG_LEN);
        assert_eq!(
            decrypt_manifest(w(), empty_record.nonce(), &empty_blob).expect("decrypts"),
            b""
        );
    }

    /// C10 accept: decrypt with a wrong `k_m` or a mutated blob →
    /// `AeadDecryptFailed`. Also covers the wrong nonce and adversarial
    /// lengths (truncated/empty input must reject, never panic).
    #[test]
    fn wrong_key_or_mutated_blob_fails() {
        let mut rng = test_rng();
        let (blob, record) = encrypt_manifest(w(), MANIFEST, &mut rng).expect("encrypts");

        // Wrong k_m, both shapes: another work's W, and a raw wrong key
        // through the key-direct path.
        let other_w_bytes = [0xEEu8; 32];
        let other_w = MasterSecretRef::from_bytes(&other_w_bytes);
        assert_eq!(
            decrypt_manifest(other_w, record.nonce(), &blob).expect_err("must fail"),
            CryptoError::AeadDecryptFailed
        );
        let wrong_key = ManifestKey::from_bytes([0x11u8; 32]);
        assert_eq!(
            decrypt_manifest_with_key(&wrong_key, record.nonce(), &blob).expect_err("must fail"),
            CryptoError::AeadDecryptFailed
        );

        // Mutated blob: first ciphertext byte and last tag byte.
        for flip_at in [0, blob.len() - 1] {
            let mut tampered = blob.clone();
            tampered[flip_at] ^= 0x80;
            assert_eq!(
                decrypt_manifest(w(), record.nonce(), &tampered).expect_err("must fail"),
                CryptoError::AeadDecryptFailed
            );
        }

        // Wrong nonce.
        let mut wrong_nonce = *record.nonce().as_bytes();
        wrong_nonce[23] ^= 0x01;
        assert_eq!(
            decrypt_manifest(w(), &Nonce24::from_bytes(wrong_nonce), &blob).expect_err("must fail"),
            CryptoError::AeadDecryptFailed
        );

        // Adversarial lengths: truncated, empty, and appended bytes.
        let mut extended = blob.clone();
        extended.push(0x00);
        for bad in [&blob[..8], &[][..], &extended[..]] {
            assert_eq!(
                decrypt_manifest(w(), record.nonce(), bad).expect_err("must fail"),
                CryptoError::AeadDecryptFailed
            );
        }
    }

    /// C10 accept: the AAD is empty — a ciphertext produced with ANY
    /// non-empty AAD fails to decrypt (the mis-encryptor is the only way to
    /// prove this from outside), while the frozen constant really is empty
    /// and encrypting with it is byte-identical to the AEAD's no-AAD form.
    #[test]
    fn non_empty_aad_ciphertext_fails_decrypt() {
        let mut rng = test_rng();

        assert!(MANIFEST_AAD.is_empty());

        // Every non-empty AAD shape, including a single zero byte (the
        // closest possible thing to "empty") and a plausible-looking
        // seal_id-shaped AAD someone might be tempted to add later.
        for aad in [&[0x00u8][..], b"antseal", &[0xFFu8; 24][..]] {
            let (blob, record) =
                mis_encrypt::encrypt_manifest_with_aad(w(), MANIFEST, aad, &mut rng)
                    .expect("encrypts");
            assert_eq!(
                decrypt_manifest(w(), record.nonce(), &blob).expect_err("must fail"),
                CryptoError::AeadDecryptFailed,
                "AAD {aad:?} must not authenticate under the empty-AAD rule"
            );
            assert_eq!(
                decrypt_manifest_with_key(record.key(), record.nonce(), &blob)
                    .expect_err("must fail"),
                CryptoError::AeadDecryptFailed
            );
        }

        // Positive control: the mis-encryptor with the empty AAD is exactly
        // `encrypt_manifest` (so the failures above are attributable to the
        // AAD alone, not to the mis-encryptor being different in some other
        // way).
        let mut rng_a = test_rng();
        let mut rng_b = test_rng();
        let (honest, honest_record) =
            encrypt_manifest(w(), MANIFEST, &mut rng_a).expect("encrypts");
        let (via_mis, mis_record) =
            mis_encrypt::encrypt_manifest_with_aad(w(), MANIFEST, MANIFEST_AAD, &mut rng_b)
                .expect("encrypts");
        assert_eq!(honest, via_mis);
        assert_eq!(honest_record.nonce(), mis_record.nonce());
        assert_eq!(
            decrypt_manifest(w(), mis_record.nonce(), &via_mis).expect("decrypts"),
            MANIFEST
        );
    }

    /// C10 accept: `k_m` derivation uses the **sentinel** id, with the info
    /// bytes and the derived key cross-checked against C3's committed
    /// vector (`testdata/vectors/v1/hkdf/hkdf-labels.json`, label
    /// `manifest-key`, `W` = the fixed test seed 0x00..0x1f).
    #[test]
    fn manifest_key_matches_c3_hkdf_vector() {
        // info = u8(len("manifest-key")) ‖ "manifest-key" ‖ LE64(0xFFFF_FFFF_FFFF_FFFF)
        let mut expected_info = vec![0x0Cu8];
        expected_info.extend_from_slice(b"manifest-key");
        expected_info.extend_from_slice(&[0xFF; 8]);
        assert_eq!(Label::ManifestKey.info_bytes(SENTINEL_ID), expected_info);
        // Byte-for-byte against the committed vector's `info` field.
        assert_eq!(
            hex(&expected_info),
            "0c6d616e69666573742d6b6579ffffffffffffffff"
        );
        // …and the sentinel really is the id domain the registry assigns.
        assert_eq!(
            Label::ManifestKey.id_domain(),
            crate::crypto::hkdf::IdDomain::Sentinel
        );

        // The key this module encrypts under is the vector's `okm`.
        let k_m: ManifestKey = derive_manifest_key(w());
        assert_eq!(
            hex(k_m.as_bytes()),
            "7ac2a2cd9c3696f2c75260d0bfa4da4ff62b422092fba8495e5009a397c0cd5c"
        );

        // And it is the key `encrypt_manifest` actually used: the record's
        // key opens the blob.
        let mut rng = test_rng();
        let (blob, record) = encrypt_manifest(w(), MANIFEST, &mut rng).expect("encrypts");
        assert_eq!(hex(record.key().as_bytes()), hex(k_m.as_bytes()));
        assert_eq!(
            decrypt_manifest_with_key(&k_m, record.nonce(), &blob).expect("decrypts"),
            MANIFEST
        );
    }

    /// C10 accept: `ManifestKey` zeroizes on drop, and so does the storage
    /// record that owns it (compile-time trait assertions + an in-place
    /// wipe check).
    #[test]
    fn manifest_key_zeroizes_on_drop() {
        const fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}
        const _: () = {
            assert_zeroize_on_drop::<ManifestKey>();
            assert_zeroize_on_drop::<ManifestStorageRecord>();
        };

        let mut rng = test_rng();
        let (_blob, mut record) = encrypt_manifest(w(), MANIFEST, &mut rng).expect("encrypts");
        zeroize::Zeroize::zeroize(&mut record);
        assert_eq!(record.key().as_bytes(), &[0u8; 32]);
    }

    /// The record's `Debug` renders the public nonce and redacts `k_m`
    /// (project rule 6: no secret material in logs or error messages).
    #[test]
    fn record_debug_redacts_the_key() {
        let mut rng = test_rng();
        let (_blob, record) = encrypt_manifest(w(), MANIFEST, &mut rng).expect("encrypts");
        let rendered = format!("{record:?}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
        assert!(
            rendered.contains(&hex(record.nonce().as_bytes())),
            "{rendered}"
        );
        assert!(
            !rendered.contains(&hex(record.key().as_bytes())),
            "{rendered}"
        );
    }

    /// C9's nonce discipline, here too: two encryptions of the same manifest
    /// draw different nonces and produce different blobs, and under a
    /// same-seed injected RNG the whole operation is bit-reproducible (the
    /// property C16's golden vectors rely on).
    #[test]
    fn fresh_nonce_per_encryption_and_deterministic_under_seeded_rng() {
        let mut rng = test_rng();
        let (blob_a, record_a) = encrypt_manifest(w(), MANIFEST, &mut rng).expect("encrypts");
        let (blob_b, record_b) = encrypt_manifest(w(), MANIFEST, &mut rng).expect("encrypts");
        assert_ne!(record_a.nonce(), record_b.nonce(), "fresh nonce per call");
        assert_ne!(blob_a, blob_b, "randomized AEAD: distinct blobs");

        let mut rng_a = test_rng();
        let mut rng_b = test_rng();
        let (repeat_a, repeat_record_a) =
            encrypt_manifest(w(), MANIFEST, &mut rng_a).expect("encrypts");
        let (repeat_b, repeat_record_b) =
            encrypt_manifest(w(), MANIFEST, &mut rng_b).expect("encrypts");
        assert_eq!(repeat_a, repeat_b);
        assert_eq!(repeat_record_a.nonce(), repeat_record_b.nonce());
        assert_eq!(repeat_a, blob_a);
    }

    /// A failing injected RNG surfaces `RngFailure` before anything is
    /// encrypted (C4 mapping; no panic) — same contract as C9.
    #[test]
    fn failing_rng_surfaces_rng_failure() {
        struct FailingRng;
        #[derive(Debug)]
        struct Exhausted;
        impl core::fmt::Display for Exhausted {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str("entropy source exhausted")
            }
        }
        impl core::error::Error for Exhausted {}
        impl rand_core::TryRng for FailingRng {
            type Error = Exhausted;
            fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
                Err(Exhausted)
            }
            fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
                Err(Exhausted)
            }
            fn try_fill_bytes(&mut self, _dst: &mut [u8]) -> Result<(), Self::Error> {
                Err(Exhausted)
            }
        }
        impl rand_core::TryCryptoRng for FailingRng {}

        assert_eq!(
            encrypt_manifest(w(), MANIFEST, &mut FailingRng).expect_err("fails"),
            CryptoError::RngFailure
        );
    }

    /// The record round-trips through `into_parts` (F's schema consumes the
    /// two fields separately).
    #[test]
    fn record_into_parts() {
        let mut rng = test_rng();
        let (blob, record) = encrypt_manifest(w(), MANIFEST, &mut rng).expect("encrypts");
        let nonce_hex = hex(record.nonce().as_bytes());
        let (nonce, k_m) = record.into_parts();
        assert_eq!(hex(nonce.as_bytes()), nonce_hex);
        assert_eq!(
            decrypt_manifest_with_key(&k_m, &nonce, &blob).expect("decrypts"),
            MANIFEST
        );
    }
}
