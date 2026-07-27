//! Owning secret types: the per-work master secret `W`, the public
//! `seal_id`, and the zeroizing byte buffer for passphrase-class material
//! (tasks/C.md C5; MVP-SPEC.md lines 89–90, 143).
//!
//! # Injected randomness — no OS RNG inside `antseal-core`
//!
//! Every generation function here takes an **injected CSPRNG**
//! (`&mut impl `[`TryCryptoRng`]) and this crate deliberately links **no OS
//! randomness source**: the pinned `rand_core` is a pure trait crate (zero
//! dependencies), so `getrandom` cannot enter `antseal-core`'s graph.
//! Production callers (the CLI/vault layer, U) inject the OS CSPRNG; the
//! exact wasm32 `getrandom` backend recipe is **P14's problem**, kept out of
//! this crate by construction (MVP-SPEC.md line 153). Tests inject a seeded
//! deterministic CSPRNG (determinism principle).
//!
//! Trait-name note: the task vocabulary `CryptoRngCore` is rand_core 0.6's
//! name; the pinned rand_core 0.10 replaced it with
//! [`CryptoRng`](rand_core::CryptoRng) (infallible) over
//! [`TryCryptoRng`] (fallible). We bound on `TryCryptoRng` — the weakest,
//! most inclusive bound: every infallible `CryptoRng` satisfies it
//! (`CryptoRng: TryCryptoRng<Error = Infallible>`), and a fallible OS
//! source surfaces [`CryptoError::RngFailure`] instead of panicking.
//!
//! # Secret hygiene (project rule 6; MVP-SPEC.md line 143)
//!
//! [`MasterSecret`] and [`SecretBuf`] are `ZeroizeOnDrop` with redacted
//! `Debug` and no `Display`/`Clone`. [`SealId`] is **public** data (a
//! manifest-body field) and has ordinary value semantics.

use core::fmt;
use rand_core::TryCryptoRng;
use zeroize::Zeroize;

use super::error::CryptoError;
use super::material::MasterSecretRef;

/// Fill `dst` from the injected CSPRNG, mapping any RNG failure to the
/// taxonomy's [`CryptoError::RngFailure`] (C4) — never a panic.
fn try_fill<R: TryCryptoRng + ?Sized>(rng: &mut R, dst: &mut [u8]) -> Result<(), CryptoError> {
    rng.try_fill_bytes(dst).map_err(|_| CryptoError::RngFailure)
}

/// The per-work master secret `W` (32 B, CSPRNG; MVP-SPEC.md line 89).
///
/// Everything else — unit keys, all salts, the fine seed, both signing
/// seeds, the manifest key — derives from `W` via the HKDF label registry
/// ([`crate::crypto::hkdf`]); the vault stores only `W` + records. A stolen
/// `W` retroactively and permanently decrypts public, undeletable
/// ciphertexts with no possible rotation (spec line 143), so this type is
/// self-wiping (`ZeroizeOnDrop`), redacts `Debug`, and implements neither
/// `Clone` nor `Display`.
pub struct MasterSecret([u8; 32]);

impl MasterSecret {
    /// Length of `W` in bytes (MVP-SPEC.md line 89).
    pub const LEN: usize = 32;

    /// Generate a fresh `W` from the injected CSPRNG (spec line 89: OS
    /// CSPRNG in production — injected by the caller, module docs).
    ///
    /// # Errors
    ///
    /// [`CryptoError::RngFailure`] when the injected source fails.
    pub fn generate<R: TryCryptoRng + ?Sized>(rng: &mut R) -> Result<Self, CryptoError> {
        let mut bytes = [0u8; Self::LEN];
        try_fill(rng, &mut bytes)?;
        let secret = Self(bytes);
        bytes.zeroize();
        Ok(secret)
    }

    /// Reconstruct `W` from stored bytes (the vault load path, U).
    ///
    /// Takes ownership of a stack copy; the **caller** must zeroize
    /// whatever buffer the bytes came from (this constructor cannot reach
    /// it).
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrow as the HKDF input view — the C2 seam: every typed
    /// `derive_*` function in [`crate::crypto::hkdf`] takes this
    /// [`MasterSecretRef`].
    #[must_use]
    pub const fn secret_ref(&self) -> MasterSecretRef<'_> {
        MasterSecretRef::from_bytes(&self.0)
    }
}

impl fmt::Debug for MasterSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MasterSecret(<redacted>)")
    }
}

impl Zeroize for MasterSecret {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for MasterSecret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

// Contract upheld by the `Drop` impl above.
impl zeroize::ZeroizeOnDrop for MasterSecret {}

/// The 16-byte public `seal_id` (MVP-SPEC.md line 90), generated at seal
/// start and stored in the manifest body (F's field).
///
/// # Why it exists — the pipeline DAG (spec line 90)
///
/// `seal_id` keeps the unit-AEAD AAD independent of the *finished*
/// manifest: ciphertext addresses are content-derived, so any AAD that
/// depended on the manifest (e.g. `work_id`) would create a dependency
/// cycle — the manifest needs the unit addresses, the addresses need the
/// ciphertexts, the ciphertexts would need the manifest — and make sealing
/// impossible. With `seal_id` drawn up front, pipeline order is a clean
/// DAG:
///
/// ```text
/// W / seal_id → keys/salts/commitments → unit ciphertexts → unit addresses
///   → manifest body → work_id → signatures → plaintext manifest bytes
///   → { anchor_digest → anchors }
///   and { k_m-encrypt → encrypted-manifest blob → manifest address
///         → quote_batch(all blobs) → pay → finalize }
/// ```
///
/// It feeds the AAD `seal_id ‖ LE64(unit_id)` ([`crate::crypto::unit_aead`],
/// C9). It is **not secret** — it ships in the manifest body — hence plain
/// value semantics (`Copy`, hex `Debug`).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct SealId([u8; 16]);

impl SealId {
    /// Length in bytes (MVP-SPEC.md line 90).
    pub const LEN: usize = 16;

    /// Generate a fresh `seal_id` at seal start from the injected CSPRNG
    /// (spec line 90).
    ///
    /// # Errors
    ///
    /// [`CryptoError::RngFailure`] when the injected source fails.
    pub fn generate<R: TryCryptoRng + ?Sized>(rng: &mut R) -> Result<Self, CryptoError> {
        let mut bytes = [0u8; Self::LEN];
        try_fill(rng, &mut bytes)?;
        Ok(Self(bytes))
    }

    /// Construct from exactly-sized bytes (manifest decode path, F).
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Borrow the raw bytes (manifest encode / AAD construction).
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// Consume into the raw bytes.
    #[must_use]
    pub const fn into_bytes(self) -> [u8; 16] {
        self.0
    }
}

impl fmt::Debug for SealId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Public manifest-body value: hex rendering is fine.
        f.write_str("SealId(")?;
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        f.write_str(")")
    }
}

/// A zeroizing owned byte buffer for passphrase-class secrets (MVP-SPEC.md
/// line 143: `zeroize` on passphrase buffers; consumed by U's vault
/// passphrase collection per tasks/C.md C5).
///
/// Wraps its backing `Vec<u8>` so the **full capacity** is wiped on drop
/// (and on [`Zeroize::zeroize`]). Deliberately **no growth API**:
/// `Vec` reallocation would strand an unwipeable copy of the old
/// allocation on the heap (zeroize's documented `Vec` caveat), so callers
/// build the complete buffer first and wrap it exactly once. Construction
/// *moves* the `Vec` (pointer move — no byte copy is left behind).
pub struct SecretBuf(Vec<u8>);

impl SecretBuf {
    /// Take ownership of a fully built secret buffer. The move leaves no
    /// copy behind; from here on the bytes are redacted and self-wiping.
    #[must_use]
    pub const fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Borrow the secret bytes (e.g. to feed a KDF). Keep the exposure
    /// surface minimal; never log or format the result.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Length in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the buffer is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<Vec<u8>> for SecretBuf {
    fn from(bytes: Vec<u8>) -> Self {
        Self::new(bytes)
    }
}

impl fmt::Debug for SecretBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Redact even the length: passphrase length is guessing-relevant.
        f.write_str("SecretBuf(<redacted>)")
    }
}

impl Zeroize for SecretBuf {
    fn zeroize(&mut self) {
        // Vec impl: wipes all initialized elements AND the spare capacity.
        self.0.zeroize();
    }
}

impl Drop for SecretBuf {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

// Contract upheld by the `Drop` impl above.
impl zeroize::ZeroizeOnDrop for SecretBuf {}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::ChaCha20Rng;
    use rand_core::{SeedableRng, TryRng};
    use zeroize::ZeroizeOnDrop;

    /// Fixed, public, NON-SECRET test seed for the deterministic RNG
    /// (project rule 6: fixtures are never real secrets).
    const TEST_SEED: [u8; 32] = [0x42u8; 32];

    /// C5 accept: `MasterSecret::generate` returns 32 B, `SealId::generate`
    /// 16 B, and both are deterministic under a seeded test RNG.
    #[test]
    fn generation_is_seed_deterministic() {
        let mut rng_a = ChaCha20Rng::from_seed(TEST_SEED);
        let mut rng_b = ChaCha20Rng::from_seed(TEST_SEED);

        let w_a = MasterSecret::generate(&mut rng_a).expect("infallible test RNG");
        let w_b = MasterSecret::generate(&mut rng_b).expect("infallible test RNG");
        assert_eq!(MasterSecret::LEN, 32);
        assert_eq!(w_a.secret_ref().as_bytes().len(), 32);
        assert_eq!(w_a.secret_ref().as_bytes(), w_b.secret_ref().as_bytes());

        let id_a = SealId::generate(&mut rng_a).expect("infallible test RNG");
        let id_b = SealId::generate(&mut rng_b).expect("infallible test RNG");
        assert_eq!(SealId::LEN, 16);
        assert_eq!(id_a.as_bytes().len(), 16);
        assert_eq!(id_a, id_b, "same seed, same draw position → same id");

        // The same stream position yields W ≠ the next draw (sanity: the
        // RNG is actually advancing).
        assert_ne!(&w_a.secret_ref().as_bytes()[..16], id_a.as_bytes());
    }

    /// Distinct seeds produce distinct secrets (smoke check that the seed
    /// actually parameterizes the draw).
    #[test]
    fn distinct_seeds_distinct_secrets() {
        let mut rng_a = ChaCha20Rng::from_seed([1u8; 32]);
        let mut rng_b = ChaCha20Rng::from_seed([2u8; 32]);
        let w_a = MasterSecret::generate(&mut rng_a).expect("infallible test RNG");
        let w_b = MasterSecret::generate(&mut rng_b).expect("infallible test RNG");
        assert_ne!(w_a.secret_ref().as_bytes(), w_b.secret_ref().as_bytes());
    }

    /// A failing injected RNG surfaces `RngFailure` — no panic (C4; module
    /// docs: fallible sources map into the taxonomy).
    #[test]
    fn failing_rng_surfaces_rng_failure() {
        /// A CSPRNG stand-in whose source always fails.
        struct FailingRng;

        #[derive(Debug)]
        struct Exhausted;
        impl core::fmt::Display for Exhausted {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str("entropy source exhausted")
            }
        }
        impl core::error::Error for Exhausted {}

        impl TryRng for FailingRng {
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

        let mut rng = FailingRng;
        assert_eq!(
            MasterSecret::generate(&mut rng).expect_err("must fail"),
            CryptoError::RngFailure
        );
        assert_eq!(
            SealId::generate(&mut rng).expect_err("must fail"),
            CryptoError::RngFailure
        );
    }

    /// C5 accept: `Debug` for `MasterSecret` and `SecretBuf` prints a
    /// redaction marker, never bytes; `SealId` (public) renders hex.
    #[test]
    fn debug_redaction() {
        let w = MasterSecret::from_bytes([0xABu8; 32]);
        let out = format!("{w:?}");
        assert!(out.contains("<redacted>"), "{out}");
        assert!(!out.to_lowercase().contains("ab"), "{out}");
        assert!(!out.contains("171"), "{out}");

        let buf = SecretBuf::new(vec![0xAB; 12]);
        let out = format!("{buf:?}");
        assert!(out.contains("<redacted>"), "{out}");
        assert!(!out.to_lowercase().contains("ab"), "{out}");
        // Even the length is withheld (guessing-relevant for passphrases).
        assert!(!out.contains("12"), "{out}");

        let id = SealId::from_bytes([0xABu8; 16]);
        let out = format!("{id:?}");
        assert!(out.contains(&"ab".repeat(16)), "{out}");
    }

    /// C5 accept: compile-time trait assertion that `MasterSecret` and
    /// `SecretBuf` are `ZeroizeOnDrop`.
    #[test]
    fn zeroize_on_drop_assertions() {
        const fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}
        const _: () = {
            assert_zeroize_on_drop::<MasterSecret>();
            assert_zeroize_on_drop::<SecretBuf>();
        };
    }

    /// Explicit `zeroize()` wipes both types in place.
    #[test]
    fn explicit_zeroize_wipes() {
        let mut w = MasterSecret::from_bytes([0x5Au8; 32]);
        w.zeroize();
        assert_eq!(w.secret_ref().as_bytes(), &[0u8; 32]);

        let mut buf = SecretBuf::new(vec![0x5A; 8]);
        buf.zeroize();
        // Vec zeroize clears: the secret bytes are gone.
        assert!(buf.is_empty());
    }

    /// `SecretBuf` round-trips its bytes and reports length without
    /// exposing anything through `Debug`.
    #[test]
    fn secret_buf_accessors() {
        let buf = SecretBuf::from(b"correct horse battery staple".to_vec());
        assert_eq!(buf.as_bytes(), b"correct horse battery staple");
        assert_eq!(buf.len(), 28);
        assert!(!buf.is_empty());
        assert!(SecretBuf::new(Vec::new()).is_empty());
    }

    /// The C2 seam: `secret_ref()` feeds the typed HKDF API, and the same
    /// `W` bytes derive the same outputs whether borrowed from
    /// `MasterSecret` or supplied directly as a `MasterSecretRef` fixture.
    #[test]
    fn secret_ref_wires_into_hkdf_seam() {
        use crate::crypto::hkdf::{UnitId, derive_unit_key};
        use crate::crypto::material::MasterSecretRef;

        let bytes = [0x21u8; 32];
        let owned = MasterSecret::from_bytes(bytes);
        let via_owned = derive_unit_key(owned.secret_ref(), UnitId(7));
        let via_ref = derive_unit_key(MasterSecretRef::from_bytes(&bytes), UnitId(7));
        assert_eq!(via_owned.as_bytes(), via_ref.as_bytes());
    }
}
