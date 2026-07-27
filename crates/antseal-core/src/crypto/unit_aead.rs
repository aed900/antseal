//! Unit AEAD: XChaCha20-Poly1305 encrypt/decrypt with AAD binding and the
//! single-use invariant (tasks/C.md C9; MVP-SPEC.md lines 91, 145).
//!
//! ```text
//! k_u   = HKDF(W, "unit-key", unit_id)          (C2)
//! nonce = 24 random bytes, drawn HERE, fresh per encryption
//! AAD   = seal_id ‖ LE64(unit_id)               (24 bytes)
//! plaintext = unit bytes, zero-padded per the C8 formula
//! ```
//!
//! The nonce is recorded in the manifest unit table — **the single
//! authoritative copy** (F's schema; spec line 91). The AAD binds the
//! ciphertext to its work (`seal_id`) and its unit slot (`unit_id`) without
//! depending on the finished manifest — see
//! [`crate::crypto::secrets::SealId`] for the pipeline-DAG rationale (spec
//! line 90).
//!
//! # The `(k_u, nonce)` single-use invariant (spec line 145)
//!
//! **A unit's `(k_u, nonce)` pair is single-use — it encrypts exactly one
//! plaintext, ever.** Encrypting two plaintexts under one XChaCha20 keystream
//! yields the plaintext XOR and enables Poly1305-key recovery ⇒ forgery.
//! Structurally enforced here: **no public API accepts a caller-supplied
//! encryption nonce** — [`encrypt_unit`] draws a fresh random nonce
//! internally from the injected CSPRNG on every call, and the test-only
//! mis-encryptors do the same. Across process restarts the invariant is S's
//! (seal journal, spec line 145): resume re-uploads byte-identical *staged
//! ciphertexts* and aborts rather than ever re-encrypting under a journaled
//! nonce. [`decrypt_unit`] takes the manifest-recorded nonce, of course —
//! decryption is not keystream reuse.
//!
//! ```compile_fail,E0061
//! use antseal_core::crypto::hkdf::UnitId;
//! use antseal_core::crypto::material::MasterSecretRef;
//! use antseal_core::crypto::secrets::SealId;
//! use antseal_core::crypto::unit_aead::{Nonce24, encrypt_unit};
//!
//! let w_bytes = [0u8; 32];
//! let w = MasterSecretRef::from_bytes(&w_bytes);
//! let seal_id = SealId::from_bytes([0u8; 16]);
//! let nonce = Nonce24::from_bytes([0u8; 24]);
//! let mut rng = unreachable!();
//! // error[E0061]: there is no nonce parameter — nonces are drawn
//! // internally, fresh, per encryption (the single-use invariant).
//! let _ = encrypt_unit(w, &seal_id, UnitId(0), b"unit bytes", &nonce, &mut rng);
//! ```
//!
//! # AEAD is confidentiality-only (spec line 103)
//!
//! XChaCha20-Poly1305 is not key-committing (invisible-salamanders /
//! partitioning class). This is acceptable because **no verdict-bearing
//! check relies on a ciphertext decrypting to a unique plaintext** — all
//! content/identity binding is via the salted SHA-256 commitments
//! ([`crate::crypto::commit`], `fine_root`) and the signatures. **A future
//! refactor MUST NOT drop a content commitment in favor of trusting the
//! AEAD.**
//!
//! # Failure ordering (tamper-matrix distinctness, spec line 168)
//!
//! [`CryptoError::AeadDecryptFailed`] fires on authentication failure
//! (wrong key/W, wrong nonce, wrong AAD component, tampered ciphertext —
//! the AEAD cannot and must not distinguish which). The C8 padding
//! rejections (`PaddingLengthMismatch`, `NonZeroPadding`) run only **after**
//! successful AEAD verification, so the error classes are structurally
//! distinct.

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use rand_core::TryCryptoRng;
use zeroize::Zeroize;

use super::error::CryptoError;
use super::hkdf::{UnitId, derive_unit_key, le64};
use super::material::{Key32, MasterSecretRef};
use super::padding::{apply_padding, strip_padding};
use super::secrets::SealId;

/// The 32-byte per-unit AEAD key `k_u = HKDF(W, "unit-key", unit_id)`
/// (spec line 91). An alias of the zeroize-on-drop [`Key32`] material type;
/// it never crosses the public API here — both [`encrypt_unit`] and
/// [`decrypt_unit`] derive it internally and wipe it on scope exit (the
/// cipher's own key copy also zeroizes on drop via the `zeroize` feature).
pub type UnitKey = Key32;

/// A 24-byte XChaCha20-Poly1305 nonce as recorded in the manifest unit
/// table (**public** data — the manifest is the single authoritative copy,
/// spec line 91). Plain value semantics; there is deliberately no
/// RNG-taking constructor — only [`encrypt_unit`] mints fresh nonces.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Nonce24([u8; 24]);

impl Nonce24 {
    /// Length in bytes (spec line 91: random 24-B nonce).
    pub const LEN: usize = 24;

    /// Construct from exactly-sized bytes (manifest decode path, F; a
    /// wrong-length manifest nonce is a decode error at F's layer — no
    /// slice constructor exists here, keeping C4's frozen taxonomy free of
    /// a nonce-length variant).
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 24]) -> Self {
        Self(bytes)
    }

    /// Borrow the raw bytes (manifest encode).
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 24] {
        &self.0
    }

    /// Consume into the raw bytes.
    #[must_use]
    pub const fn into_bytes(self) -> [u8; 24] {
        self.0
    }
}

impl core::fmt::Debug for Nonce24 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Public manifest value: hex rendering is fine.
        f.write_str("Nonce24(")?;
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        f.write_str(")")
    }
}

/// The 24-byte AAD `seal_id ‖ LE64(unit_id)` (spec line 91). Public helper
/// so F/R and the golden vectors can pin the exact encoding.
#[must_use]
pub fn unit_aad(seal_id: &SealId, unit_id: UnitId) -> [u8; 24] {
    let mut aad = [0u8; 24];
    aad[..SealId::LEN].copy_from_slice(seal_id.as_bytes());
    aad[SealId::LEN..].copy_from_slice(&le64(unit_id.0));
    aad
}

/// Build the cipher for one unit, deriving `k_u` internally. The derived
/// `k_u` ([`UnitKey`], ZeroizeOnDrop) wipes when this function returns; the
/// cipher's internal key copy zeroizes on *its* drop (the chacha20poly1305
/// `zeroize` feature).
fn unit_cipher(w: MasterSecretRef<'_>, unit_id: UnitId) -> XChaCha20Poly1305 {
    let k_u: UnitKey = derive_unit_key(w, unit_id);
    // Static impossibility: `Key32::LEN` (32) is exactly the
    // XChaCha20-Poly1305 key size, so `new_from_slice` cannot fail.
    XChaCha20Poly1305::new_from_slice(k_u.as_bytes())
        .expect("Key32::LEN equals the XChaCha20-Poly1305 key size")
}

/// Encrypt already-padded plaintext under a fresh internally-drawn nonce —
/// the single shared path of [`encrypt_unit`] and the test-only
/// mis-encryptors, so no code path exists that accepts an external nonce.
fn encrypt_padded<R: TryCryptoRng + ?Sized>(
    w: MasterSecretRef<'_>,
    seal_id: &SealId,
    unit_id: UnitId,
    padded: &[u8],
    rng: &mut R,
) -> Result<(Vec<u8>, Nonce24), CryptoError> {
    let mut nonce_bytes = [0u8; Nonce24::LEN];
    rng.try_fill_bytes(&mut nonce_bytes)
        .map_err(|_| CryptoError::RngFailure)?;
    let nonce = Nonce24::from_bytes(nonce_bytes);

    let cipher = unit_cipher(w, unit_id);
    let aad = unit_aad(seal_id, unit_id);
    let xnonce = XNonce::from(nonce_bytes);
    // Precondition (documented, sealer-side): the padded plaintext is far
    // below the XChaCha20-Poly1305 P_MAX (≈ 256 GiB); unit construction
    // (G/S) bounds unit sizes long before this. Exceeding it would be a
    // programming error, not an adversarial input.
    let ciphertext = cipher
        .encrypt(
            &xnonce,
            Payload {
                msg: padded,
                aad: &aad,
            },
        )
        .expect("padded unit plaintext is far below the XChaCha20-Poly1305 P_MAX");
    Ok((ciphertext, nonce))
}

/// Encrypt one unit's exact bytes (canonical for text, raw for binary):
/// pads per C8, draws a **fresh random 24-B nonce internally** from the
/// injected CSPRNG, and binds `AAD = seal_id ‖ LE64(unit_id)`
/// (spec line 91). Returns `(ciphertext, nonce)`; the nonce's only
/// authoritative home is the manifest unit table (F).
///
/// There is deliberately no parameter to supply a nonce — the `(k_u,
/// nonce)` single-use invariant (module docs; spec line 145).
///
/// # Errors
///
/// [`CryptoError::RngFailure`] when the injected CSPRNG fails.
pub fn encrypt_unit<R: TryCryptoRng + ?Sized>(
    w: MasterSecretRef<'_>,
    seal_id: &SealId,
    unit_id: UnitId,
    unit_bytes: &[u8],
    rng: &mut R,
) -> Result<(Vec<u8>, Nonce24), CryptoError> {
    let mut padded = apply_padding(unit_bytes);
    let result = encrypt_padded(w, seal_id, unit_id, &padded, rng);
    // The padded buffer holds secret unit content — wipe it (C21).
    padded.zeroize();
    result
}

/// Decrypt one unit and strip its padding — the verifier-side path R
/// orchestrates (spec lines 91, 118, 121). Authenticates under
/// `AAD = seal_id ‖ LE64(unit_id)` with the manifest-recorded nonce, then
/// runs C8's **length-first** strip driven by the manifest's `true_length`,
/// with both rejections.
///
/// # Errors
///
/// - [`CryptoError::AeadDecryptFailed`] — wrong `W`/key, wrong `seal_id` or
///   `unit_id` (AAD mismatch), wrong nonce, or tampered ciphertext.
/// - [`CryptoError::PaddingLengthMismatch`] — authenticated plaintext whose
///   length ≠ `padded_length(true_length)` (over-padded unit).
/// - [`CryptoError::NonZeroPadding`] — authenticated plaintext with a
///   non-zero byte beyond `true_length`.
///
/// The padding errors fire only after successful AEAD verification —
/// structurally distinct failure classes (module docs).
pub fn decrypt_unit(
    w: MasterSecretRef<'_>,
    seal_id: &SealId,
    unit_id: UnitId,
    nonce: &Nonce24,
    ciphertext: &[u8],
    true_length: usize,
) -> Result<Vec<u8>, CryptoError> {
    let cipher = unit_cipher(w, unit_id);
    let aad = unit_aad(seal_id, unit_id);
    let xnonce = XNonce::from(*nonce.as_bytes());
    let mut padded = cipher
        .decrypt(
            &xnonce,
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| CryptoError::AeadDecryptFailed)?;

    // Length-first strip (C8); borrow released by mapping to the length.
    let strip_result = strip_padding(&padded, true_length).map(<[u8]>::len);
    match strip_result {
        Ok(_) => {
            // Validated: everything beyond true_length is zero, so
            // truncation leaves no residual secret past the new length.
            padded.truncate(true_length);
            Ok(padded)
        }
        Err(error) => {
            // Authenticated-but-malformed plaintext is still the sealer's
            // secret content — wipe before discarding.
            padded.zeroize();
            Err(error)
        }
    }
}

/// Test-only mis-encryptors for the C17/R7 tamper fixtures (`test-util`
/// feature; never part of a production build). They produce ciphertexts
/// that **authenticate correctly** but violate the padding format — the
/// only way to exercise the post-AEAD rejections end-to-end:
///
/// - [`encrypt_unit_overpadded`] pads one whole 256-B bucket too far
///   (plaintext length ≠ `padded_length(true_length)` ⇒ the *over-padded
///   unit* tamper row, [`CryptoError::PaddingLengthMismatch`]);
/// - [`encrypt_unit_nonzero_padding`] pads to the correct bucket but sets
///   the final pad byte non-zero (⇒ the companion row,
///   [`CryptoError::NonZeroPadding`]).
///
/// Both draw fresh internal nonces like every encryptor here — even
/// test-util code cannot supply a nonce.
#[cfg(any(test, feature = "test-util"))]
pub mod mis_encrypt {
    use super::{
        CryptoError, MasterSecretRef, Nonce24, SealId, TryCryptoRng, UnitId, Zeroize,
        apply_padding, encrypt_padded,
    };
    use crate::crypto::padding::PAD_BLOCK;

    /// Wrong-bucket mis-encryptor: pads to `padded_length(len) + 256`
    /// (still all-zero fill), so decryption authenticates and then fails
    /// with [`CryptoError::PaddingLengthMismatch`].
    ///
    /// # Errors
    ///
    /// [`CryptoError::RngFailure`] when the injected CSPRNG fails.
    pub fn encrypt_unit_overpadded<R: TryCryptoRng + ?Sized>(
        w: MasterSecretRef<'_>,
        seal_id: &SealId,
        unit_id: UnitId,
        unit_bytes: &[u8],
        rng: &mut R,
    ) -> Result<(Vec<u8>, Nonce24), CryptoError> {
        let mut padded = apply_padding(unit_bytes);
        let overpadded_len = padded.len() + PAD_BLOCK;
        padded.resize(overpadded_len, 0);
        let result = encrypt_padded(w, seal_id, unit_id, &padded, rng);
        padded.zeroize();
        result
    }

    /// Non-zero-pad mis-encryptor: correct bucket, final pad byte `0xFF`
    /// (the formula guarantees at least one pad byte exists), so
    /// decryption authenticates and then fails with
    /// [`CryptoError::NonZeroPadding`].
    ///
    /// # Errors
    ///
    /// [`CryptoError::RngFailure`] when the injected CSPRNG fails.
    pub fn encrypt_unit_nonzero_padding<R: TryCryptoRng + ?Sized>(
        w: MasterSecretRef<'_>,
        seal_id: &SealId,
        unit_id: UnitId,
        unit_bytes: &[u8],
        rng: &mut R,
    ) -> Result<(Vec<u8>, Nonce24), CryptoError> {
        let mut padded = apply_padding(unit_bytes);
        if let Some(last) = padded.last_mut() {
            *last = 0xFF;
        }
        let result = encrypt_padded(w, seal_id, unit_id, &padded, rng);
        padded.zeroize();
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::padding::padded_length;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;
    use zeroize::ZeroizeOnDrop;

    /// Fixed, public, NON-SECRET fixtures (project rule 6).
    const TEST_W: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D,
        0x1E, 0x1F,
    ];
    const TEST_SEED: [u8; 32] = [0x33u8; 32];

    fn w() -> MasterSecretRef<'static> {
        MasterSecretRef::from_bytes(&TEST_W)
    }

    fn seal_id() -> SealId {
        SealId::from_bytes([
            0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD,
            0xAE, 0xAF,
        ])
    }

    fn rng() -> ChaCha20Rng {
        ChaCha20Rng::from_seed(TEST_SEED)
    }

    /// C9 accept: the encoded AAD for a known `(seal_id, unit_id)` equals
    /// the 24-byte concatenation `seal_id ‖ LE64(unit_id)` — pinned
    /// byte-for-byte.
    #[test]
    fn aad_fixture_bytes() {
        let aad = unit_aad(&seal_id(), UnitId(0x0102_0304_0506_0708));
        let expected: [u8; 24] = [
            // seal_id, verbatim.
            0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD,
            0xAE, 0xAF, // LE64(0x0102030405060708): little-endian.
            0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
        ];
        assert_eq!(aad, expected);
        assert_eq!(aad.len(), 24);
    }

    /// C9 accept: round-trip over ordinary bytes, the empty unit (padded
    /// plaintext exactly 256 B), and a 256-B-aligned unit.
    #[test]
    fn round_trip_including_boundary_lengths() {
        let mut rng = rng();
        const TAG_LEN: usize = 16;

        // Ordinary unit.
        let content: &[u8] = b"a paragraph of sealed work, ending in zeros\x00\x00";
        let (ciphertext, nonce) =
            encrypt_unit(w(), &seal_id(), UnitId(1), content, &mut rng).expect("encrypts");
        assert_eq!(ciphertext.len(), padded_length(content.len()) + TAG_LEN);
        let plaintext = decrypt_unit(
            w(),
            &seal_id(),
            UnitId(1),
            &nonce,
            &ciphertext,
            content.len(),
        )
        .expect("decrypts");
        assert_eq!(plaintext, content);

        // Empty unit: true_length 0 pads to one full 256-B block.
        let (ciphertext, nonce) =
            encrypt_unit(w(), &seal_id(), UnitId(2), b"", &mut rng).expect("encrypts");
        assert_eq!(ciphertext.len(), 256 + TAG_LEN);
        let plaintext =
            decrypt_unit(w(), &seal_id(), UnitId(2), &nonce, &ciphertext, 0).expect("decrypts");
        assert_eq!(plaintext, b"");

        // 256-aligned unit: unambiguous — always ≥ 1 pad byte, so it pads
        // to 512.
        let aligned = [0x7Eu8; 256];
        let (ciphertext, nonce) =
            encrypt_unit(w(), &seal_id(), UnitId(3), &aligned, &mut rng).expect("encrypts");
        assert_eq!(ciphertext.len(), 512 + TAG_LEN);
        let plaintext =
            decrypt_unit(w(), &seal_id(), UnitId(3), &nonce, &ciphertext, 256).expect("decrypts");
        assert_eq!(plaintext, aligned);
    }

    /// C9 accept: decryption fails with `AeadDecryptFailed` on wrong
    /// `seal_id` (AAD-only mismatch — `k_u` does not depend on `seal_id`),
    /// wrong `unit_id`, wrong nonce, flipped ciphertext/tag byte, and wrong
    /// key (`W`) — and padding errors are the distinguishable post-AEAD
    /// class, firing only when authentication succeeded.
    #[test]
    fn decrypt_failure_classes_are_distinct() {
        let mut rng = rng();
        let content = b"bound to seal and unit";
        let unit_id = UnitId(9);
        let (ciphertext, nonce) =
            encrypt_unit(w(), &seal_id(), unit_id, content, &mut rng).expect("encrypts");

        // Wrong seal_id: SAME unit key, different AAD ⇒ pure AAD-binding
        // failure.
        let other_seal = SealId::from_bytes([0u8; 16]);
        assert_eq!(
            decrypt_unit(
                w(),
                &other_seal,
                unit_id,
                &nonce,
                &ciphertext,
                content.len()
            )
            .expect_err("must fail"),
            CryptoError::AeadDecryptFailed
        );

        // Wrong unit_id (changes both k_u and AAD).
        assert_eq!(
            decrypt_unit(
                w(),
                &seal_id(),
                UnitId(10),
                &nonce,
                &ciphertext,
                content.len()
            )
            .expect_err("must fail"),
            CryptoError::AeadDecryptFailed
        );

        // Wrong nonce.
        let mut wrong_nonce = *nonce.as_bytes();
        wrong_nonce[0] ^= 0x01;
        assert_eq!(
            decrypt_unit(
                w(),
                &seal_id(),
                unit_id,
                &Nonce24::from_bytes(wrong_nonce),
                &ciphertext,
                content.len()
            )
            .expect_err("must fail"),
            CryptoError::AeadDecryptFailed
        );

        // Flipped ciphertext byte (body) and flipped tag byte.
        for flip_at in [0, ciphertext.len() - 1] {
            let mut tampered = ciphertext.clone();
            tampered[flip_at] ^= 0x80;
            assert_eq!(
                decrypt_unit(w(), &seal_id(), unit_id, &nonce, &tampered, content.len())
                    .expect_err("must fail"),
                CryptoError::AeadDecryptFailed
            );
        }

        // Wrong W (wrong key).
        let other_w_bytes = [0xEEu8; 32];
        let other_w = MasterSecretRef::from_bytes(&other_w_bytes);
        assert_eq!(
            decrypt_unit(
                other_w,
                &seal_id(),
                unit_id,
                &nonce,
                &ciphertext,
                content.len()
            )
            .expect_err("must fail"),
            CryptoError::AeadDecryptFailed
        );

        // Everything right but the wrong true_length: authentication
        // SUCCEEDS, then the C8 length check fires — a distinct,
        // post-AEAD error class.
        let wrong_length_err = decrypt_unit(
            w(),
            &seal_id(),
            unit_id,
            &nonce,
            &ciphertext,
            content.len() + 300,
        )
        .expect_err("must fail");
        assert_eq!(
            wrong_length_err,
            CryptoError::PaddingLengthMismatch {
                expected: 512,
                got: 256
            }
        );
        assert_ne!(
            core::mem::discriminant(&wrong_length_err),
            core::mem::discriminant(&CryptoError::AeadDecryptFailed)
        );

        // Truncated and empty ciphertexts reject as AEAD failures — no
        // panic on adversarial input.
        assert_eq!(
            decrypt_unit(
                w(),
                &seal_id(),
                unit_id,
                &nonce,
                &ciphertext[..10],
                content.len()
            )
            .expect_err("must fail"),
            CryptoError::AeadDecryptFailed
        );
        assert_eq!(
            decrypt_unit(w(), &seal_id(), unit_id, &nonce, &[], content.len())
                .expect_err("must fail"),
            CryptoError::AeadDecryptFailed
        );
    }

    /// C9 accept: two encrypts of the same plaintext produce different
    /// nonces and different ciphertexts (fresh internal draw per call).
    #[test]
    fn fresh_nonce_per_encryption() {
        let mut rng = rng();
        let content = b"same plaintext twice";
        let (ct_a, nonce_a) =
            encrypt_unit(w(), &seal_id(), UnitId(5), content, &mut rng).expect("encrypts");
        let (ct_b, nonce_b) =
            encrypt_unit(w(), &seal_id(), UnitId(5), content, &mut rng).expect("encrypts");
        assert_ne!(nonce_a, nonce_b, "fresh nonce per call");
        assert_ne!(ct_a, ct_b, "randomized AEAD: distinct ciphertexts");
        // Both decrypt to the same plaintext.
        for (ct, nonce) in [(&ct_a, &nonce_a), (&ct_b, &nonce_b)] {
            assert_eq!(
                decrypt_unit(w(), &seal_id(), UnitId(5), nonce, ct, content.len())
                    .expect("decrypts"),
                content
            );
        }
    }

    /// Determinism principle: under a same-seed injected RNG, encryption is
    /// bit-reproducible (nonce and ciphertext) — the property the golden
    /// vectors (C16) rely on.
    #[test]
    fn deterministic_under_seeded_rng() {
        let content = b"reproducible";
        let mut rng_a = rng();
        let mut rng_b = rng();
        let (ct_a, nonce_a) =
            encrypt_unit(w(), &seal_id(), UnitId(4), content, &mut rng_a).expect("encrypts");
        let (ct_b, nonce_b) =
            encrypt_unit(w(), &seal_id(), UnitId(4), content, &mut rng_b).expect("encrypts");
        assert_eq!(nonce_a, nonce_b);
        assert_eq!(ct_a, ct_b);
    }

    /// A failing injected RNG surfaces `RngFailure` before any encryption
    /// happens (C4 mapping; no panic).
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
            encrypt_unit(w(), &seal_id(), UnitId(0), b"x", &mut FailingRng).expect_err("fails"),
            CryptoError::RngFailure
        );
    }

    /// C9 accept: `UnitKey` zeroizes on drop (compile-time trait
    /// assertion; `UnitKey = Key32`, whose wiping `Drop` is asserted in
    /// `material`).
    #[test]
    fn unit_key_zeroizes_on_drop() {
        const fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}
        const _: () = assert_zeroize_on_drop::<UnitKey>();
    }

    /// C9 Notes / C17 seam: the wrong-bucket mis-encryptor produces an
    /// AEAD-authentic ciphertext that fails with exactly
    /// `PaddingLengthMismatch`; the non-zero-pad variant with exactly
    /// `NonZeroPadding`. Honest decryptions are unaffected.
    #[test]
    fn mis_encryptors_produce_the_two_padding_tamper_cases() {
        let mut rng = rng();
        let content = b"over-padded fixture content";

        let (ciphertext, nonce) =
            mis_encrypt::encrypt_unit_overpadded(w(), &seal_id(), UnitId(6), content, &mut rng)
                .expect("encrypts");
        // One bucket too long: 256-B content bucket + 256 extra + 16 tag.
        assert_eq!(ciphertext.len(), padded_length(content.len()) + 256 + 16);
        assert_eq!(
            decrypt_unit(
                w(),
                &seal_id(),
                UnitId(6),
                &nonce,
                &ciphertext,
                content.len()
            )
            .expect_err("must fail post-AEAD"),
            CryptoError::PaddingLengthMismatch {
                expected: 256,
                got: 512
            }
        );

        let (ciphertext, nonce) = mis_encrypt::encrypt_unit_nonzero_padding(
            w(),
            &seal_id(),
            UnitId(7),
            content,
            &mut rng,
        )
        .expect("encrypts");
        assert_eq!(
            decrypt_unit(
                w(),
                &seal_id(),
                UnitId(7),
                &nonce,
                &ciphertext,
                content.len()
            )
            .expect_err("must fail post-AEAD"),
            CryptoError::NonZeroPadding {
                offset: padded_length(content.len()) - 1
            }
        );
    }
}
