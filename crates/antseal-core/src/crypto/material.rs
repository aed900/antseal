//! Fixed-length newtypes for derived key/salt/seed material, plus the
//! borrowed master-secret view the HKDF layer takes as input (tasks/C.md
//! C2/C5/C6).
//!
//! The 16-vs-32-byte output lengths of the HKDF label registry
//! (MVP-SPEC.md lines 94–98) are enforced by these return types: a 16-byte
//! salt cannot be handed to a consumer expecting a 32-byte key or seed, and
//! vice versa, because the types don't convert.
//!
//! Three roles live here:
//!
//! - **Secret material** ([`Key32`], [`Seed32`], [`Salt16`], [`FileSalt`]):
//!   `Zeroize` + `ZeroizeOnDrop` (C5 landed the `zeroize` pin), redacted
//!   `Debug`, no `Display`, no `Clone`/`Copy`/`PartialEq` — uncontrolled
//!   copies defeat zeroization, and comparisons of secret-derived digests
//!   must be explicit and constant-time where verdict-bearing
//!   ([`crate::crypto::commit`] uses `subtle`).
//! - **The borrowed master-secret view** ([`MasterSecretRef`]): a `Copy`
//!   borrow with no drop semantics; the *owning*, self-wiping
//!   [`crate::crypto::secrets::MasterSecret`] borrows into it (C5).
//! - **Public verifier-side values** ([`NodeHash32`]): bundle-supplied
//!   Merkle boundary node hashes are public bundle bytes — plain value
//!   semantics, no redaction, no zeroization.
//!
//! # Structural length checks (MVP-SPEC.md line 121)
//!
//! *"Every disclosed salt/seed/node hash has its exact spec length."* The
//! fallible constructors here — [`Salt16::try_from_slice`],
//! `Seed32::try_from(&[u8])`, `NodeHash32::try_from(&[u8])` — are how R's
//! verifier executes those checks on bundle-supplied values, returning the
//! distinct `SaltLength`/`SeedLength`/`NodeHashLength` errors the tamper
//! matrix requires (MVP-SPEC.md line 168; tasks/C.md C6). `Salt16` has
//! deliberately **no** kind-free `TryFrom<&[u8]>`: its length error carries
//! [`SaltKind`], and inventing a default kind would mislabel tamper-matrix
//! rows, so slice conversion must name the salt being parsed.
//!
//! # `file_salt` opacity (MVP-SPEC.md line 95; tasks/C.md C7)
//!
//! [`FileSalt`] wraps the one salt whose raw bytes must never leave the
//! generation side except on a full-file reveal: the salts API returns it
//! opaque (no public byte accessor), and the only public byte path is
//! [`crate::crypto::disclosure::FullFileRevealDisclosure`]. See
//! [`crate::crypto::disclosure`] for the confirmation-oracle rationale.
//!
//! # Secret hygiene (project rule 6)
//!
//! Secret-material types redact `Debug`, implement no `Display`, and are
//! wiped on drop. [`into_bytes`](Key32::into_bytes)-style extractors hand
//! the caller a raw copy that is **not** self-wiping — callers own its
//! hygiene from that point (the vault layer, U, zeroizes what it stores).

use core::fmt;
use zeroize::Zeroize;

use super::error::{CryptoError, SaltKind};

/// Borrowed view of the 32-byte per-work master secret `W`
/// (MVP-SPEC.md line 89). The minimal input type the typed HKDF derivation
/// functions take.
///
/// This is a `Copy` **borrow** — it owns nothing and wipes nothing; the
/// owning, CSPRNG-generated, `ZeroizeOnDrop` wrapper is
/// [`crate::crypto::secrets::MasterSecret`], which borrows into this type
/// via [`crate::crypto::secrets::MasterSecret::secret_ref`] (C5).
#[derive(Clone, Copy)]
pub struct MasterSecretRef<'a>(&'a [u8; 32]);

impl<'a> MasterSecretRef<'a> {
    /// Length of `W` in bytes (MVP-SPEC.md line 89).
    pub const LEN: usize = 32;

    /// Wrap a borrowed 32-byte master secret.
    #[must_use]
    pub const fn from_bytes(bytes: &'a [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The raw secret bytes (HKDF IKM). Keep the exposure surface minimal.
    #[must_use]
    pub const fn as_bytes(self) -> &'a [u8; 32] {
        self.0
    }
}

impl fmt::Debug for MasterSecretRef<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MasterSecretRef(<redacted>)")
    }
}

/// Declare a fixed-length secret-material newtype: redacted `Debug`,
/// `Zeroize`, wiped on drop (`ZeroizeOnDrop`).
macro_rules! material_newtype {
    ($(#[$doc:meta])* $name:ident, $len:literal) => {
        $(#[$doc])*
        pub struct $name([u8; $len]);

        impl $name {
            /// Length in bytes.
            pub const LEN: usize = $len;

            /// Construct from exactly-sized bytes.
            #[must_use]
            pub const fn from_bytes(bytes: [u8; $len]) -> Self {
                Self(bytes)
            }

            /// Borrow the raw bytes.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; $len] {
                &self.0
            }

            /// Consume into the raw bytes. The original wipes on drop as
            /// usual; the **returned copy is not self-wiping** — the caller
            /// owns its hygiene (module docs).
            #[must_use]
            pub fn into_bytes(self) -> [u8; $len] {
                // `[u8; N]: Copy`, so this copies out; `self` still drops
                // (and zeroizes) normally.
                self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), "(<redacted>)"))
            }
        }

        impl zeroize::Zeroize for $name {
            fn zeroize(&mut self) {
                self.0.zeroize();
            }
        }

        impl Drop for $name {
            fn drop(&mut self) {
                self.0.zeroize();
            }
        }

        // Contract upheld by the `Drop` impl above.
        impl zeroize::ZeroizeOnDrop for $name {}
    };
}

material_newtype!(
    /// A derived 32-byte symmetric key (`unit-key`, `manifest-key` registry
    /// entries; MVP-SPEC.md lines 91, 98). Feeds the AEAD layer (C9/C10).
    Key32,
    32
);

material_newtype!(
    /// A derived 32-byte seed (`fine-seed` GGM root, signature seeds,
    /// bundle-supplied GGM covering seeds; MVP-SPEC.md lines 96–97). Feeds
    /// keygen/GGM expansion, never AEAD.
    Seed32,
    32
);

material_newtype!(
    /// A derived 16-byte salt (`unit-salt`, `path-salt` registry entries,
    /// and bundle-supplied disclosed salts; MVP-SPEC.md lines 94–95). Salts
    /// the SHA-256 commitments (C6). The `file-salt` registry entry is
    /// derived as the opaque [`FileSalt`] instead (C7 disclosure rule).
    Salt16,
    16
);

impl Salt16 {
    /// Length-checked construction from a bundle-supplied slice — the
    /// structural check of MVP-SPEC.md line 121 for the three 16-byte salts,
    /// executed by R's verifier. `kind` names the salt being parsed so the
    /// tamper-matrix error is exact (line 168: *wrong-length salt*).
    ///
    /// There is deliberately no kind-free `TryFrom<&[u8]>` for `Salt16`
    /// (module docs).
    ///
    /// # Errors
    ///
    /// [`CryptoError::SaltLength`] when `bytes.len() != 16`.
    pub fn try_from_slice(kind: SaltKind, bytes: &[u8]) -> Result<Self, CryptoError> {
        match <[u8; Self::LEN]>::try_from(bytes) {
            // C23: `array` is a copy of secret salt bytes in a buffer we own,
            // and `[u8; N]` has no `Drop` — wipe it once the value is inside
            // the zeroizing newtype.
            Ok(mut array) => {
                let salt = Self::from_bytes(array);
                array.zeroize();
                Ok(salt)
            }
            Err(_) => Err(CryptoError::SaltLength {
                kind,
                expected: Self::LEN,
                got: bytes.len(),
            }),
        }
    }
}

/// Length-checked construction from a bundle-supplied slice (`s_root`, GGM
/// covering seeds): the 32-byte structural check of MVP-SPEC.md line 121.
impl TryFrom<&[u8]> for Seed32 {
    type Error = CryptoError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        match <[u8; Self::LEN]>::try_from(bytes) {
            // C23: as `Salt16::try_from_slice` — a bundle-supplied covering
            // seed copied into a `Drop`-less buffer we own.
            Ok(mut array) => {
                let seed = Self::from_bytes(array);
                array.zeroize();
                Ok(seed)
            }
            Err(_) => Err(CryptoError::SeedLength {
                expected: Self::LEN,
                got: bytes.len(),
            }),
        }
    }
}

/// A 32-byte Merkle boundary node hash as carried in reveal bundles
/// (MVP-SPEC.md lines 96, 121). A **public** bundle value — plain value
/// semantics (`Copy`, ordinary `Debug`), no redaction, no zeroization.
/// Consumed by G's fine-tree boundary-path verification.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct NodeHash32([u8; 32]);

impl NodeHash32 {
    /// Length in bytes.
    pub const LEN: usize = 32;

    /// Construct from exactly-sized bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrow the raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Consume into the raw bytes.
    #[must_use]
    pub const fn into_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl fmt::Debug for NodeHash32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Public value: hex rendering is fine and useful for verifier
        // diagnostics.
        f.write_str("NodeHash32(")?;
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        f.write_str(")")
    }
}

/// Length-checked construction from a bundle-supplied slice: the 32-byte
/// node-hash structural check of MVP-SPEC.md line 121.
impl TryFrom<&[u8]> for NodeHash32 {
    type Error = CryptoError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        match <[u8; Self::LEN]>::try_from(bytes) {
            Ok(array) => Ok(Self::from_bytes(array)),
            Err(_) => Err(CryptoError::NodeHashLength {
                expected: Self::LEN,
                got: bytes.len(),
            }),
        }
    }
}

/// The 16-byte `file_salt` (`file-salt` registry entry; MVP-SPEC.md
/// line 95), **opaque by design** (tasks/C.md C7).
///
/// `file_salt` salts `raw_commit`/`canon_commit`, which sit in the manifest
/// embedded in *every* bundle; its bytes may therefore be disclosed **only
/// on a full-file reveal**. A partial-reveal recipient holding it would gain
/// an offline full-file confirmation oracle (recompute `canon_commit` for a
/// guessed document) — exactly the confirmation attack this design exists to
/// prevent (spec line 95). So, unlike [`Salt16`], this type exposes **no
/// public byte accessor**: on the generation side the only public byte path
/// is [`crate::crypto::disclosure::FullFileRevealDisclosure`], which
/// structurally requires the full-reveal context.
///
/// Crate-internal access exists for the commitment preimages
/// ([`crate::crypto::commit`]) — *using* the salt is not *disclosing* it.
///
/// The derivation API cannot yield the bytes:
///
/// ```compile_fail,E0599
/// use antseal_core::crypto::hkdf::{FileId, derive_file_salt};
/// use antseal_core::crypto::material::MasterSecretRef;
///
/// let w_bytes = [0u8; 32];
/// let w = MasterSecretRef::from_bytes(&w_bytes);
/// // error[E0599]: no method named `as_bytes` found — `FileSalt` is
/// // opaque; bytes are reachable only via
/// // `disclosure::FullFileRevealDisclosure::file_salt_bytes`
/// // (MVP-SPEC.md line 95).
/// let leaked = derive_file_salt(w, FileId(0)).as_bytes();
/// ```
pub struct FileSalt(Salt16);

impl FileSalt {
    /// Length in bytes.
    pub const LEN: usize = Salt16::LEN;

    /// Wrap a derived salt (crate-internal: the HKDF layer's constructor).
    pub(crate) const fn from_derived(salt: Salt16) -> Self {
        Self(salt)
    }

    /// Verifier-side construction from a **bundle-disclosed** salt (already
    /// public to that recipient — a full-file reveal carried it; spec
    /// lines 114, 121). Feeds `raw_commit`/`canon_commit` re-verification
    /// (C6). This cannot be abused to extract a generation-side salt: the
    /// derivation API never yields `file_salt` bytes to wrap in the first
    /// place.
    #[must_use]
    pub fn from_disclosed(salt: Salt16) -> Self {
        Self(salt)
    }

    /// Preimage access for the commitment functions (crate-internal).
    pub(crate) const fn as_salt(&self) -> &Salt16 {
        &self.0
    }

    /// Raw bytes for committed test-vector generation (C3/C16) —
    /// **NON-PRODUCTION**: exists only under the `test-vectors` feature (and
    /// hence under `test-util`, which implies it), which no shipped build
    /// enables. Production disclosure goes through
    /// [`crate::crypto::disclosure::FullFileRevealDisclosure`] only.
    #[cfg(feature = "test-vectors")]
    #[must_use]
    pub const fn expose_bytes_for_test_vectors(&self) -> &[u8; 16] {
        self.0.as_bytes()
    }
}

impl fmt::Debug for FileSalt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FileSalt(<redacted>)")
    }
}

impl Zeroize for FileSalt {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

// Contract upheld by the inner `Salt16`'s wiping `Drop`.
impl zeroize::ZeroizeOnDrop for FileSalt {}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::ZeroizeOnDrop;

    /// Project rule 6: `Debug` for every secret-material type prints a
    /// redaction marker and never byte content.
    #[test]
    fn debug_is_redacted() {
        let w = [0xABu8; 32];
        let rendered = [
            format!("{:?}", MasterSecretRef::from_bytes(&w)),
            format!("{:?}", Key32::from_bytes([0xABu8; 32])),
            format!("{:?}", Seed32::from_bytes([0xABu8; 32])),
            format!("{:?}", Salt16::from_bytes([0xABu8; 16])),
            format!(
                "{:?}",
                FileSalt::from_derived(Salt16::from_bytes([0xABu8; 16]))
            ),
        ];
        for out in &rendered {
            assert!(out.contains("<redacted>"), "{out}");
            // Neither hex (`ab`) nor decimal (`171`) renderings of the
            // fill byte may appear.
            assert!(!out.to_lowercase().contains("ab"), "{out}");
            assert!(!out.contains("171"), "{out}");
        }
    }

    /// `NodeHash32` is a public value: `Debug` renders its hex (useful for
    /// verifier diagnostics; nothing secret to redact).
    #[test]
    fn node_hash_debug_renders_hex() {
        let hash = NodeHash32::from_bytes([0xABu8; 32]);
        let out = format!("{hash:?}");
        assert!(out.starts_with("NodeHash32("));
        assert!(out.contains(&"ab".repeat(32)));
    }

    #[test]
    fn lengths_and_round_trips() {
        assert_eq!(MasterSecretRef::LEN, 32);
        assert_eq!(Key32::LEN, 32);
        assert_eq!(Seed32::LEN, 32);
        assert_eq!(Salt16::LEN, 16);
        assert_eq!(NodeHash32::LEN, 32);
        assert_eq!(FileSalt::LEN, 16);

        let key = Key32::from_bytes([7u8; 32]);
        assert_eq!(key.as_bytes(), &[7u8; 32]);
        assert_eq!(key.into_bytes(), [7u8; 32]);
        let salt = Salt16::from_bytes([9u8; 16]);
        assert_eq!(salt.as_bytes(), &[9u8; 16]);
        assert_eq!(salt.into_bytes(), [9u8; 16]);
        let seed = Seed32::from_bytes([5u8; 32]);
        assert_eq!(seed.as_bytes(), &[5u8; 32]);
        assert_eq!(seed.into_bytes(), [5u8; 32]);
        let node = NodeHash32::from_bytes([3u8; 32]);
        assert_eq!(node.as_bytes(), &[3u8; 32]);
        assert_eq!(node.into_bytes(), [3u8; 32]);

        let w_bytes = [1u8; 32];
        let w = MasterSecretRef::from_bytes(&w_bytes);
        assert_eq!(w.as_bytes(), &[1u8; 32]);
    }

    /// C5/C21 accept: compile-time trait assertion that every secret-material
    /// type is `ZeroizeOnDrop` (wiped on drop).
    #[test]
    fn secret_material_is_zeroize_on_drop() {
        const fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}
        const _: () = {
            assert_zeroize_on_drop::<Key32>();
            assert_zeroize_on_drop::<Seed32>();
            assert_zeroize_on_drop::<Salt16>();
            assert_zeroize_on_drop::<FileSalt>();
        };
    }

    /// `zeroize()` actually wipes in place.
    #[test]
    fn explicit_zeroize_wipes() {
        let mut key = Key32::from_bytes([0x5Au8; 32]);
        key.zeroize();
        assert_eq!(key.as_bytes(), &[0u8; 32]);
        let mut salt = Salt16::from_bytes([0x5Au8; 16]);
        salt.zeroize();
        assert_eq!(salt.as_bytes(), &[0u8; 16]);
    }

    /// C6 accept: `Salt16::try_from_slice` rejects 15-B and 17-B inputs with
    /// `SaltLength` carrying the named kind; `Seed32`/`NodeHash32` reject
    /// 31-B/33-B with their own distinct variants (MVP-SPEC.md lines 121,
    /// 168; the three families are pairwise-distinct errors).
    #[test]
    fn length_checked_constructors_reject_off_by_one() {
        for kind in SaltKind::ALL {
            for bad_len in [15usize, 17] {
                let err = Salt16::try_from_slice(kind, &vec![0u8; bad_len])
                    .expect_err("wrong length must be rejected");
                assert_eq!(
                    err,
                    CryptoError::SaltLength {
                        kind,
                        expected: 16,
                        got: bad_len
                    }
                );
            }
            assert!(Salt16::try_from_slice(kind, &[0u8; 16]).is_ok());
        }

        for bad_len in [31usize, 33] {
            let seed_err =
                Seed32::try_from(vec![0u8; bad_len].as_slice()).expect_err("must reject");
            assert_eq!(
                seed_err,
                CryptoError::SeedLength {
                    expected: 32,
                    got: bad_len
                }
            );
            let node_err =
                NodeHash32::try_from(vec![0u8; bad_len].as_slice()).expect_err("must reject");
            assert_eq!(
                node_err,
                CryptoError::NodeHashLength {
                    expected: 32,
                    got: bad_len
                }
            );
            // The two 32-byte families are distinct variants (tamper matrix
            // line 168: wrong-length *seed* vs wrong-length *node hash*).
            assert_ne!(
                core::mem::discriminant(&seed_err),
                core::mem::discriminant(&node_err)
            );
        }
        assert!(Seed32::try_from([0u8; 32].as_slice()).is_ok());
        assert!(NodeHash32::try_from([0u8; 32].as_slice()).is_ok());
    }

    /// Empty and grossly oversized inputs also reject (defensive-parsing
    /// smoke check — no panics on adversarial lengths).
    #[test]
    fn length_checked_constructors_reject_extremes() {
        assert!(Salt16::try_from_slice(SaltKind::Unit, &[]).is_err());
        assert!(Seed32::try_from([].as_slice()).is_err());
        assert!(NodeHash32::try_from(vec![0u8; 4096].as_slice()).is_err());
    }
}
