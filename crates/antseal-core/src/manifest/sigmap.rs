//! The per-algorithm material maps: body `pubkeys` (registry §7.2 key 5)
//! and envelope `signatures` (registry §7.1 key 1).
//!
//! Both are CBOR maps whose keys are `sig_alg` ids and whose values are
//! byte strings of that algorithm's exact length. One type serves both,
//! tagged by [`SigMaterial`], so the length rule, the unregistered-id
//! rule, and the duplicate rule are written once and cannot drift apart
//! between the two positions.
//!
//! # Duplicates are structurally impossible
//!
//! On the wire, [`crate::codec::MapReader`] enforces strictly ascending
//! unsigned-integer keys, so a repeated `sig_alg` id is a
//! `cbor-duplicate-map-key` rejection before this layer ever sees it —
//! the F6 requirement, satisfied by map semantics rather than by a
//! checked invariant. In memory the entries are kept sorted and
//! duplicate-free by [`SigAlgMap::new`], so no constructed value can
//! encode a duplicate either.
//!
//! # What this layer does *not* check
//!
//! Whether the key set equals the `sig_policy` set is **C14/R5's**
//! cross-field rule (MVP-SPEC.md line 97: the present signature set MUST
//! equal the policy set, so a hybrid manifest never passes on one good
//! signature). This layer validates each map's own shape; the two maps
//! and the policy list are compared by the verifier, which is also the
//! only place that can hard-fail on a *valid-shaped but unlisted*
//! signature.

use core::fmt;

use crate::codec::encode::MapEncoder;
use crate::codec::{CanonicalDecoder, EncodeError};
use crate::crypto::error::SigAlg;

use super::error::{AlgPosition, ContainerField, FixedLenField, ManifestError};
use super::registry::{pubkey_len, sig_alg_from_wire, sig_alg_to_wire, sig_len};

/// Which per-algorithm material a [`SigAlgMap`] carries. Selects the
/// exact-length rule, the error field class, and the position tag that
/// keeps the two maps' rejections on separate tamper rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SigMaterial {
    /// Body `pubkeys`: 32 B for Ed25519, 1952 B for ML-DSA-65.
    Pubkey,
    /// Envelope `signatures`: 64 B for Ed25519, 3309 B for ML-DSA-65.
    Signature,
}

impl SigMaterial {
    /// Every material kind, for exhaustive tests.
    pub const ALL: [Self; 2] = [Self::Pubkey, Self::Signature];

    /// The registry's exact byte length for `alg` in this position.
    #[must_use]
    pub const fn expected_len(self, alg: SigAlg) -> u64 {
        match self {
            Self::Pubkey => pubkey_len(alg),
            Self::Signature => sig_len(alg),
        }
    }

    /// The length-error field class for this position.
    #[must_use]
    pub const fn len_field(self, alg: SigAlg) -> FixedLenField {
        match self {
            Self::Pubkey => FixedLenField::Pubkey(alg),
            Self::Signature => FixedLenField::Signature(alg),
        }
    }

    /// The unregistered-/duplicate-algorithm position tag.
    #[must_use]
    pub const fn position(self) -> AlgPosition {
        match self {
            Self::Pubkey => AlgPosition::Pubkeys,
            Self::Signature => AlgPosition::Signatures,
        }
    }

    /// The non-empty-container class for this position.
    #[must_use]
    pub const fn container(self) -> ContainerField {
        match self {
            Self::Pubkey => ContainerField::Pubkeys,
            Self::Signature => ContainerField::Signatures,
        }
    }
}

impl fmt::Display for SigMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Pubkey => "pubkeys",
            Self::Signature => "signatures",
        })
    }
}

/// A non-empty, duplicate-free, exact-length-checked map from `sig_alg`
/// to that algorithm's material, held in ascending wire-id order.
///
/// Enumerable ([`Self::iter`]) so C14/R5 can compare the present set
/// against `sig_policy` and detect a *present-but-unlisted* entry — the
/// F6 requirement that the container never hide what it holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigAlgMap {
    material: SigMaterial,
    /// Ascending by `sig_alg_to_wire`, duplicate-free (invariant of
    /// [`Self::new`] and of the strict-ascent decode).
    entries: Vec<(SigAlg, Vec<u8>)>,
}

impl SigAlgMap {
    /// Build from arbitrary entries: sorted into wire order, checked
    /// non-empty, duplicate-free, and exact-length per algorithm.
    ///
    /// # Errors
    ///
    /// - [`ManifestError::EmptyContainer`] — no entries.
    /// - [`ManifestError::DuplicateAlg`] — two entries for one algorithm.
    /// - [`ManifestError::WrongLength`] — a value of the wrong size for
    ///   its algorithm and position.
    pub fn new(
        material: SigMaterial,
        entries: impl IntoIterator<Item = (SigAlg, Vec<u8>)>,
    ) -> Result<Self, ManifestError> {
        let mut entries: Vec<(SigAlg, Vec<u8>)> = entries.into_iter().collect();
        if entries.is_empty() {
            return Err(ManifestError::EmptyContainer {
                field: material.container(),
            });
        }
        entries.sort_by_key(|(alg, _)| sig_alg_to_wire(*alg));
        for window in entries.windows(2) {
            if window[0].0 == window[1].0 {
                return Err(ManifestError::DuplicateAlg {
                    position: material.position(),
                    alg_id: sig_alg_to_wire(window[0].0),
                });
            }
        }
        for (alg, value) in &entries {
            check_len(material, *alg, value.len() as u64)?;
        }
        Ok(Self { material, entries })
    }

    /// Which material this map carries.
    #[must_use]
    pub const fn material(&self) -> SigMaterial {
        self.material
    }

    /// Entries in ascending wire-id order — the order they encode in.
    pub fn iter(&self) -> impl Iterator<Item = (SigAlg, &[u8])> {
        self.entries.iter().map(|(alg, v)| (*alg, v.as_slice()))
    }

    /// The algorithms present, ascending.
    pub fn algorithms(&self) -> impl Iterator<Item = SigAlg> + '_ {
        self.entries.iter().map(|(alg, _)| *alg)
    }

    /// The material for one algorithm, if present.
    #[must_use]
    pub fn get(&self, alg: SigAlg) -> Option<&[u8]> {
        self.entries
            .iter()
            .find(|(a, _)| *a == alg)
            .map(|(_, v)| v.as_slice())
    }

    /// Whether an algorithm is present.
    #[must_use]
    pub fn contains(&self, alg: SigAlg) -> bool {
        self.get(alg).is_some()
    }

    /// Number of entries (always `>= 1`).
    #[must_use]
    pub fn len(&self) -> u64 {
        self.entries.len() as u64
    }

    /// Always `false` — the type is non-empty by construction. Present so
    /// the `len`/`is_empty` pair reads normally at call sites.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Emit this map's entries into an open CBOR map scope (F2).
    ///
    /// # Errors
    ///
    /// [`EncodeError`] only for caller bugs the encode layer detects; a
    /// value built by [`Self::new`] or by decode cannot trigger one (its
    /// keys are distinct by invariant).
    pub(super) fn encode_into(&self, m: &mut MapEncoder) -> Result<(), EncodeError> {
        for (alg, value) in &self.entries {
            m.entry(sig_alg_to_wire(*alg), |e| e.bytes(value))?;
        }
        Ok(())
    }

    /// Decode one per-algorithm map from `d`, mapping codec failures
    /// through `wrap` so the caller's layer tag (envelope vs body) is
    /// preserved.
    ///
    /// Ascending, duplicate-free keys are guaranteed by
    /// [`crate::codec::MapReader`]; this adds the registered-id and
    /// exact-length rules and the non-empty rule.
    pub(super) fn decode(
        d: &mut CanonicalDecoder<'_>,
        material: SigMaterial,
        wrap: fn(crate::codec::DecodeError) -> ManifestError,
    ) -> Result<Self, ManifestError> {
        let mut reader = d.map().map_err(wrap)?;
        let mut entries: Vec<(SigAlg, Vec<u8>)> = Vec::new();
        while let Some(alg_id) = reader.next_key(d).map_err(wrap)? {
            let alg = sig_alg_from_wire(alg_id).ok_or(ManifestError::UnregisteredAlg {
                position: material.position(),
                alg_id,
            })?;
            let value = d.bytes().map_err(wrap)?;
            check_len(material, alg, value.len() as u64)?;
            entries.push((alg, value.to_vec()));
        }
        if entries.is_empty() {
            return Err(ManifestError::EmptyContainer {
                field: material.container(),
            });
        }
        // Strict ascent on the wire == sorted, duplicate-free here.
        Ok(Self { material, entries })
    }
}

fn check_len(material: SigMaterial, alg: SigAlg, got: u64) -> Result<(), ManifestError> {
    let expected = material.expected_len(alg);
    if got == expected {
        Ok(())
    } else {
        Err(ManifestError::WrongLength {
            field: material.len_field(alg),
            expected,
            got,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::registry::{ED25519_PUBKEY_LEN, ED25519_SIG_LEN, MLDSA65_PUBKEY_LEN};

    fn pk(alg: SigAlg) -> Vec<u8> {
        vec![0x11; SigMaterial::Pubkey.expected_len(alg) as usize]
    }

    #[test]
    fn entries_sort_into_wire_order_regardless_of_input_order() {
        let map = SigAlgMap::new(
            SigMaterial::Pubkey,
            [
                (SigAlg::MlDsa65, pk(SigAlg::MlDsa65)),
                (SigAlg::Ed25519, pk(SigAlg::Ed25519)),
            ],
        )
        .expect("valid pubkeys map");
        let order: Vec<SigAlg> = map.algorithms().collect();
        assert_eq!(order, [SigAlg::Ed25519, SigAlg::MlDsa65]);
        assert_eq!(map.len(), 2);
        assert!(!map.is_empty());
        assert!(map.contains(SigAlg::Ed25519));
    }

    #[test]
    fn empty_map_is_rejected_per_position() {
        for material in SigMaterial::ALL {
            assert_eq!(
                SigAlgMap::new(material, []),
                Err(ManifestError::EmptyContainer {
                    field: material.container()
                })
            );
        }
    }

    #[test]
    fn duplicate_algorithm_is_rejected_per_position() {
        for material in SigMaterial::ALL {
            let value = vec![0u8; material.expected_len(SigAlg::Ed25519) as usize];
            assert_eq!(
                SigAlgMap::new(
                    material,
                    [
                        (SigAlg::Ed25519, value.clone()),
                        (SigAlg::Ed25519, value.clone())
                    ]
                ),
                Err(ManifestError::DuplicateAlg {
                    position: material.position(),
                    alg_id: 0
                })
            );
        }
    }

    #[test]
    fn wrong_length_is_rejected_per_position_and_algorithm() {
        assert_eq!(
            SigAlgMap::new(SigMaterial::Pubkey, [(SigAlg::Ed25519, vec![0u8; 31])]),
            Err(ManifestError::WrongLength {
                field: FixedLenField::Pubkey(SigAlg::Ed25519),
                expected: ED25519_PUBKEY_LEN,
                got: 31,
            })
        );
        assert_eq!(
            SigAlgMap::new(SigMaterial::Signature, [(SigAlg::Ed25519, vec![0u8; 65])]),
            Err(ManifestError::WrongLength {
                field: FixedLenField::Signature(SigAlg::Ed25519),
                expected: ED25519_SIG_LEN,
                got: 65,
            })
        );
        assert_eq!(
            SigAlgMap::new(SigMaterial::Pubkey, [(SigAlg::MlDsa65, vec![0u8; 32])]),
            Err(ManifestError::WrongLength {
                field: FixedLenField::Pubkey(SigAlg::MlDsa65),
                expected: MLDSA65_PUBKEY_LEN,
                got: 32,
            })
        );
    }
}
