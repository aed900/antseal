//! [`Address`] — the 32-byte Autonomi chunk address at the network
//! boundary.
//!
//! Under D32/D11 a blob's address is BLAKE3-256 of its ciphertext bytes
//! (`XorName = [u8; 32]`, `ant-protocol-2.3.0/src/chunk.rs:43`;
//! `compute_address` = `blake3::hash`, `data_types.rs:10-12`). This type
//! carries that value at the storage boundary and converts losslessly
//! to/from [`antseal_core::manifest::ContentAddress`] — the manifest unit
//! table's frozen representation. **The address semantics live in one
//! place**: S4's `compute_storage_address` in `antseal-core` is the only
//! derivation; this crate never re-derives an address from bytes, it only
//! transports the 32 bytes (the real backend receives addresses computed
//! upstream by ant-core itself, and the two are asserted equal by S9).

use antseal_core::manifest::ContentAddress;

/// A 32-byte Autonomi chunk address (`XorName`), convertible to/from
/// `antseal-core`'s [`ContentAddress`] without loss.
///
/// Ordered/hashable so it can key the per-address stores and deterministic
/// maps this crate's backends maintain. Displayed as 64 lowercase hex
/// characters (the house rendering for 32-byte digests).
#[derive(
    Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub struct Address([u8; Address::LEN]);

impl Address {
    /// Length in bytes — equals `ContentAddress::LEN` (registry §2, D11);
    /// the equality is asserted in tests.
    pub const LEN: usize = 32;

    /// Construct from exactly-sized bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; Self::LEN]) -> Self {
        Self(bytes)
    }

    /// Borrow the raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::LEN] {
        &self.0
    }

    /// Copy out the raw bytes.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; Self::LEN] {
        self.0
    }
}

impl From<ContentAddress> for Address {
    fn from(address: ContentAddress) -> Self {
        Self(*address.as_bytes())
    }
}

impl From<Address> for ContentAddress {
    fn from(address: Address) -> Self {
        ContentAddress::from_bytes(address.0)
    }
}

impl From<[u8; Address::LEN]> for Address {
    fn from(bytes: [u8; Address::LEN]) -> Self {
        Self(bytes)
    }
}

impl core::fmt::Display for Address {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl core::fmt::Debug for Address {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Address({self})")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn length_matches_the_core_representation() {
        // ContentAddress::LEN is a u64 (registry table type); the two must
        // agree or the conversions below could not be lossless.
        assert_eq!(Address::LEN as u64, ContentAddress::LEN);
    }

    #[test]
    fn round_trips_with_content_address_both_directions() {
        let mut bytes = [0u8; Address::LEN];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = u8::try_from(i).expect("index fits in u8");
        }

        // net -> core -> net
        let addr = Address::from_bytes(bytes);
        let core: ContentAddress = addr.into();
        assert_eq!(core.as_bytes(), &bytes);
        let back: Address = core.into();
        assert_eq!(back, addr);

        // core -> net -> core
        let core_first = ContentAddress::from_bytes(bytes);
        let via_net: Address = core_first.into();
        let core_back: ContentAddress = via_net.into();
        assert_eq!(core_back, core_first);
    }

    #[test]
    fn display_is_lowercase_hex() {
        let addr = Address::from_bytes([0xAB; 32]);
        let hex = addr.to_string();
        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| c == 'a' || c == 'b'));
        assert_eq!(format!("{addr:?}"), format!("Address({hex})"));
    }
}
