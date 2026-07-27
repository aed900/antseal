//! Fixed-length newtypes for derived key/salt/seed material, plus the
//! borrowed master-secret view the HKDF layer takes as input (tasks/C.md C2).
//!
//! The 16-vs-32-byte output lengths of the HKDF label registry
//! (MVP-SPEC.md lines 94–98) are enforced by these return types: a 16-byte
//! salt cannot be handed to a consumer expecting a 32-byte key or seed, and
//! vice versa, because the types don't convert.
//!
//! # Seams (deliberate, documented forward-compatibility)
//!
//! - **C5**: the owning, zeroizing `MasterSecret` (`W`, 32 B, CSPRNG-
//!   generated) lands in `crypto::secrets` and borrows into
//!   [`MasterSecretRef`]; C5/C21 retrofit `Zeroize`/`ZeroizeOnDrop` onto
//!   [`Key32`]/[`Seed32`]/[`Salt16`] once the `zeroize` pin lands. Until
//!   then these buffers are secret but not self-wiping — treat them as
//!   short-lived.
//! - **C6**: extends this module with `TryFrom<&[u8]>` constructors
//!   returning the distinct `SaltLength`/`SeedLength`/`NodeHashLength`
//!   errors of [`crate::crypto::error::CryptoError`] (the structural length
//!   checks R's verifier executes on bundle-supplied values), and adds the
//!   `NodeHash32` newtype for 32-byte Merkle boundary node hashes.
//!
//! # Secret hygiene (project rule 6)
//!
//! Every type here redacts its `Debug` output, implements no `Display`, and
//! deliberately derives neither `Clone` nor `Copy` (uncontrolled copies
//! defeat the zeroization C5 adds) nor `PartialEq` (comparisons of secret
//! material must be explicit, and constant-time where verdict-bearing —
//! C6 introduces `subtle`-based equality for commitment verification).

use core::fmt;

/// Borrowed view of the 32-byte per-work master secret `W`
/// (MVP-SPEC.md line 89). The minimal input type the typed HKDF derivation
/// functions take.
///
/// C5 seam: the owning `MasterSecret` (vault-held, CSPRNG-generated,
/// `ZeroizeOnDrop`) lands in C5 and exposes a borrow into this type; the
/// derivation signatures in [`crate::crypto::hkdf`] stay unchanged.
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

/// Declare a fixed-length secret-material newtype with a redacted `Debug`.
macro_rules! material_newtype {
    ($(#[$doc:meta])* $name:ident, $len:literal) => {
        $(#[$doc])*
        pub struct $name([u8; $len]);

        impl $name {
            /// Length in bytes.
            pub const LEN: usize = $len;

            /// Construct from exactly-sized bytes. (Fallible slice
            /// conversion with distinct length errors is C6's
            /// `TryFrom<&[u8]>` seam.)
            #[must_use]
            pub const fn from_bytes(bytes: [u8; $len]) -> Self {
                Self(bytes)
            }

            /// Borrow the raw bytes.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; $len] {
                &self.0
            }

            /// Consume into the raw bytes.
            #[must_use]
            pub fn into_bytes(self) -> [u8; $len] {
                self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), "(<redacted>)"))
            }
        }
    };
}

material_newtype!(
    /// A derived 32-byte symmetric key (`unit-key`, `manifest-key` registry
    /// entries; MVP-SPEC.md lines 91, 98). Feeds the AEAD layer (C9/C10).
    Key32,
    32
);

material_newtype!(
    /// A derived 32-byte seed (`fine-seed` GGM root, signature seeds;
    /// MVP-SPEC.md lines 96–97). Feeds keygen/GGM expansion, never AEAD.
    Seed32,
    32
);

material_newtype!(
    /// A derived 16-byte salt (`unit-salt`, `path-salt`, `file-salt`
    /// registry entries; MVP-SPEC.md lines 94–95). Salts the SHA-256
    /// commitments (C6).
    Salt16,
    16
);

#[cfg(test)]
mod tests {
    use super::*;

    /// Project rule 6: `Debug` for every material type prints a redaction
    /// marker and never byte content.
    #[test]
    fn debug_is_redacted() {
        let w = [0xABu8; 32];
        let rendered = [
            format!("{:?}", MasterSecretRef::from_bytes(&w)),
            format!("{:?}", Key32::from_bytes([0xABu8; 32])),
            format!("{:?}", Seed32::from_bytes([0xABu8; 32])),
            format!("{:?}", Salt16::from_bytes([0xABu8; 16])),
        ];
        for out in &rendered {
            assert!(out.contains("<redacted>"), "{out}");
            // Neither hex (`ab`) nor decimal (`171`) renderings of the
            // fill byte may appear.
            assert!(!out.to_lowercase().contains("ab"), "{out}");
            assert!(!out.contains("171"), "{out}");
        }
    }

    #[test]
    fn lengths_and_round_trips() {
        assert_eq!(MasterSecretRef::LEN, 32);
        assert_eq!(Key32::LEN, 32);
        assert_eq!(Seed32::LEN, 32);
        assert_eq!(Salt16::LEN, 16);

        let key = Key32::from_bytes([7u8; 32]);
        assert_eq!(key.as_bytes(), &[7u8; 32]);
        assert_eq!(key.into_bytes(), [7u8; 32]);
        let salt = Salt16::from_bytes([9u8; 16]);
        assert_eq!(salt.as_bytes(), &[9u8; 16]);
        assert_eq!(salt.into_bytes(), [9u8; 16]);
        let seed = Seed32::from_bytes([5u8; 32]);
        assert_eq!(seed.as_bytes(), &[5u8; 32]);
        assert_eq!(seed.into_bytes(), [5u8; 32]);

        let w_bytes = [1u8; 32];
        let w = MasterSecretRef::from_bytes(&w_bytes);
        assert_eq!(w.as_bytes(), &[1u8; 32]);
    }
}
