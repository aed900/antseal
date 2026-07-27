//! The code side of the v1 wire registry (F4): map keys, reserved bands,
//! fixed byte lengths, closed enums, and the `sig_alg` numeric mapping.
//!
//! Normative table: `docs/format/registry-v1.md`; machine mirror
//! `docs/format/registry-v1.json`. Every constant below is asserted equal
//! to its registry row by `crates/antseal-core/tests/format_registry_draft.rs`
//! — the 1:1 code ⟷ registry check the F4 draft defers to F5/F8
//! (registry §14). **Changing a number here without changing the registry
//! (or vice versa) fails that test**, which is the point: after the Q14
//! `format-v1-freeze` gate, either change is a format-version event
//! (MVP-SPEC.md line 123).
//!
//! # Key bands (registry §1 rule 4)
//!
//! Every v1 key lives in `0..=23` (single-byte CBOR heads). Within that
//! band, an unassigned key is **reserved** for v1.x and rejects with
//! [`super::ManifestError::ReservedKey`]; a key `>= 24` was never reserved
//! and rejects with [`super::ManifestError::UnknownKey`]. Two bands, two
//! errors, so "a v1.1 field reached a v1 verifier" and "this is not our
//! format" never look alike. The manifest **envelope** is the one
//! exception: its shape `{0: body, 1: signatures}` is frozen across all
//! future versions (registry §1 rule 6), so it has no reserved band and
//! every key other than 0/1 is unknown, forever.
//!
//! F10 owns version *dispatch* (reading key 0 before choosing a schema)
//! and may re-home this classification; it stays keyed by these same two
//! errors, exactly as F3's provisional depth guard is keyed by F11's
//! eventual cap error.

use core::fmt;

use crate::crypto::error::SigAlg;

/// `format_version` value of the v1 manifest body (registry §7.2 key 0).
pub const FORMAT_VERSION_V1: u64 = 1;

/// Highest map key assignable in v1 — single-byte CBOR heads only
/// (registry §1 rule 4).
pub const V1_KEY_BAND_MAX: u64 = 23;

/// `seal_id` length in bytes (MVP-SPEC.md line 90; registry §2).
pub const SEAL_ID_LEN: u64 = 16;

/// XChaCha20-Poly1305 nonce length in bytes (spec line 91; registry §2).
pub const NONCE_LEN: u64 = 24;

/// Length of every salted commitment and of `fine_root` (spec lines
/// 94–96; registry §2).
pub const COMMITMENT_LEN: u64 = 32;

/// Autonomi ciphertext address length in bytes — `XorName = [u8; 32]`,
/// BLAKE3-256 (decision D11; registry §2).
pub const ADDRESS_LEN: u64 = 32;

/// Ed25519 public key length (RFC 8032; registry §2).
pub const ED25519_PUBKEY_LEN: u64 = 32;

/// Ed25519 signature length (RFC 8032; registry §2).
pub const ED25519_SIG_LEN: u64 = 64;

/// ML-DSA-65 public key length (FIPS 204 Table 2; registry §2).
pub const MLDSA65_PUBKEY_LEN: u64 = 1952;

/// ML-DSA-65 signature length (FIPS 204 Table 2; registry §2).
pub const MLDSA65_SIG_LEN: u64 = 3309;

/// Unsigned-integer map keys of every v1 manifest-side map (registry
/// §§7.1–7.5). Grouped by map so call sites read as
/// `key::unit::UNIT_COMMIT` rather than as bare numbers.
pub mod key {
    /// Manifest envelope — registry §7.1. Frozen across all versions.
    pub mod envelope {
        /// The embedded canonical-CBOR body, as a byte string.
        pub const BODY: u64 = 0;
        /// The signatures map (`sig_alg` → signature bytes).
        pub const SIGNATURES: u64 = 1;
    }

    /// Manifest body — registry §7.2.
    pub mod body {
        /// Format version discriminant; sorted first on the wire.
        pub const FORMAT_VERSION: u64 = 0;
        /// Producing build, informational only.
        pub const APP_VERSION: u64 = 1;
        /// 16-byte `seal_id`.
        pub const SEAL_ID: u64 = 2;
        /// Work title (may be empty).
        pub const TITLE: u64 = 3;
        /// Claimed time, POSIX seconds UTC, informational only.
        pub const CLAIMED_TIME: u64 = 4;
        /// `sig_alg` → public key.
        pub const PUBKEYS: u64 = 5;
        /// Ordered list of required `sig_alg` ids.
        pub const SIG_POLICY: u64 = 6;
        /// File table; array index is `file_id`.
        pub const FILES: u64 = 7;
        /// First reserved key of the body map.
        pub const RESERVED_FIRST: u64 = 8;
    }

    /// File-table entry — registry §7.3.
    pub mod file {
        /// Salted commitment to the file's path.
        pub const PATH_COMMIT: u64 = 0;
        /// Salted commitment to the file's raw bytes.
        pub const RAW_COMMIT: u64 = 1;
        /// Salted commitment to the canonical rendition (text only).
        pub const CANON_COMMIT: u64 = 2;
        /// Leaf count / tiling-domain byte count.
        pub const SIZE: u64 = 3;
        /// Canonicalization descriptor map.
        pub const DESCRIPTOR: u64 = 4;
        /// Fine-tree root (fine-tree files only).
        pub const FINE_ROOT: u64 = 5;
        /// Unit table.
        pub const UNITS: u64 = 6;
        /// First reserved key of the file-entry map.
        pub const RESERVED_FIRST: u64 = 7;
    }

    /// Canonicalization descriptor — registry §7.4.
    pub mod descriptor {
        /// `descriptor_kind`: binary or text.
        pub const KIND: u64 = 0;
        /// 0/1 flag: does this file have a fine tree?
        pub const FINE_TREE_PRESENT: u64 = 1;
        /// `fine_tree_domain`: raw or canonical (fine-tree files only).
        pub const FINE_TREE_DOMAIN: u64 = 2;
        /// Unicode data version used for NFC (text files only).
        pub const UNICODE_VERSION: u64 = 3;
        /// First reserved key of the descriptor map.
        pub const RESERVED_FIRST: u64 = 4;
    }

    /// Unit-table entry — registry §7.5.
    pub mod unit {
        /// Work-global manifest-order ordinal.
        pub const UNIT_ID: u64 = 0;
        /// `unit_kind`: normal or raw-mirror.
        pub const KIND: u64 = 1;
        /// `[start, length]` byte range in the unit's byte domain.
        pub const RANGE: u64 = 2;
        /// Pre-padding byte length.
        pub const TRUE_LENGTH: u64 = 3;
        /// Salted commitment, present iff the unit is not fine-tree-covered.
        pub const UNIT_COMMIT: u64 = 4;
        /// 24-byte AEAD nonce — the single authoritative copy.
        pub const NONCE: u64 = 5;
        /// 32-byte Autonomi ciphertext address.
        pub const ADDRESS: u64 = 6;
        /// First reserved key of the unit-entry map.
        pub const RESERVED_FIRST: u64 = 7;
    }
}

/// Which fixed-schema wire map a key-space error refers to.
///
/// The `pubkeys` and `signatures` maps are deliberately absent: their keys
/// are `sig_alg` values, not schema slots, so an unrecognised key there is
/// an [`super::AlgPosition`]-tagged unregistered-algorithm rejection, not
/// an unknown-key one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MapId {
    /// The manifest envelope `{body, signatures}` (registry §7.1).
    Envelope,
    /// The manifest body (registry §7.2).
    Body,
    /// One file-table entry (registry §7.3).
    FileEntry,
    /// One canonicalization descriptor (registry §7.4).
    Descriptor,
    /// One unit-table entry (registry §7.5).
    UnitEntry,
}

/// How a decoded map key relates to its map's v1 schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyClass {
    /// A key this v1 schema assigns.
    Assigned,
    /// An unassigned key inside the `0..=23` v1.x reserved band.
    Reserved,
    /// A key outside every v1 band — never reserved, never assignable.
    Unknown,
}

impl MapId {
    /// Every map, for exhaustive tests.
    pub const ALL: [Self; 5] = [
        Self::Envelope,
        Self::Body,
        Self::FileEntry,
        Self::Descriptor,
        Self::UnitEntry,
    ];

    /// The map's registry name — identical to the `maps[].name` of
    /// `registry-v1.json`, which is how the 1:1 test pairs them up.
    #[must_use]
    pub const fn registry_name(self) -> &'static str {
        match self {
            Self::Envelope => "manifest_envelope",
            Self::Body => "manifest_body",
            Self::FileEntry => "file_entry",
            Self::Descriptor => "canon_descriptor",
            Self::UnitEntry => "unit_entry",
        }
    }

    /// The keys this v1 schema assigns, ascending.
    #[must_use]
    pub const fn assigned_keys(self) -> &'static [u64] {
        match self {
            Self::Envelope => &[key::envelope::BODY, key::envelope::SIGNATURES],
            Self::Body => &[
                key::body::FORMAT_VERSION,
                key::body::APP_VERSION,
                key::body::SEAL_ID,
                key::body::TITLE,
                key::body::CLAIMED_TIME,
                key::body::PUBKEYS,
                key::body::SIG_POLICY,
                key::body::FILES,
            ],
            Self::FileEntry => &[
                key::file::PATH_COMMIT,
                key::file::RAW_COMMIT,
                key::file::CANON_COMMIT,
                key::file::SIZE,
                key::file::DESCRIPTOR,
                key::file::FINE_ROOT,
                key::file::UNITS,
            ],
            Self::Descriptor => &[
                key::descriptor::KIND,
                key::descriptor::FINE_TREE_PRESENT,
                key::descriptor::FINE_TREE_DOMAIN,
                key::descriptor::UNICODE_VERSION,
            ],
            Self::UnitEntry => &[
                key::unit::UNIT_ID,
                key::unit::KIND,
                key::unit::RANGE,
                key::unit::TRUE_LENGTH,
                key::unit::UNIT_COMMIT,
                key::unit::NONCE,
                key::unit::ADDRESS,
            ],
        }
    }

    /// The map's reserved-for-v1.x band, or `None` for the envelope —
    /// whose shape is frozen across all versions (registry §1 rule 6), so
    /// it can never gain a key and reserves nothing.
    #[must_use]
    pub const fn reserved_band(self) -> Option<(u64, u64)> {
        match self {
            Self::Envelope => None,
            Self::Body => Some((key::body::RESERVED_FIRST, V1_KEY_BAND_MAX)),
            Self::FileEntry => Some((key::file::RESERVED_FIRST, V1_KEY_BAND_MAX)),
            Self::Descriptor => Some((key::descriptor::RESERVED_FIRST, V1_KEY_BAND_MAX)),
            Self::UnitEntry => Some((key::unit::RESERVED_FIRST, V1_KEY_BAND_MAX)),
        }
    }

    /// Classify a decoded key against this map's v1 schema.
    #[must_use]
    pub fn classify(self, decoded_key: u64) -> KeyClass {
        if self.assigned_keys().contains(&decoded_key) {
            return KeyClass::Assigned;
        }
        match self.reserved_band() {
            Some((first, last)) if decoded_key >= first && decoded_key <= last => {
                KeyClass::Reserved
            }
            _ => KeyClass::Unknown,
        }
    }
}

impl fmt::Display for MapId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Envelope => "manifest envelope",
            Self::Body => "manifest body",
            Self::FileEntry => "file entry",
            Self::Descriptor => "canonicalization descriptor",
            Self::UnitEntry => "unit entry",
        })
    }
}

/// `descriptor_kind` (registry §6.3): does this file have a canonical
/// rendition? (MVP-SPEC.md line 83.)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DescriptorKind {
    /// No canonical rendition; offsets are raw-byte offsets.
    Binary = 0,
    /// UTF-8/NFC/LF/no-BOM canonical rendition; offsets are canonical.
    Text = 1,
}

/// `fine_tree_domain` (registry §6.3): which byte domain the fine tree
/// commits (MVP-SPEC.md line 84).
///
/// The value is fully determined by [`DescriptorKind`] — binary ⇒ raw,
/// text ⇒ canonical — and is recorded explicitly on the wire per spec
/// line 83. [`DescriptorKind::fine_tree_domain`] is the single source of
/// that mapping; decode compares the wire value against it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FineTreeDomain {
    /// Raw file bytes (binary files).
    Raw = 0,
    /// Canonical rendition bytes (text files).
    Canonical = 1,
}

/// `unit_kind` (registry §6.3; MVP-SPEC.md lines 92, 98).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UnitKind {
    /// An ordinary unit in the file's tiling domain.
    Normal = 0,
    /// The file's raw mirror: raw byte domain, exempt from tiling and
    /// from full-reveal concatenation (spec line 92).
    RawMirror = 1,
}

/// Declare a closed wire enum's `u64` ⟷ Rust mapping plus its
/// registry name, with wildcard-free matches so a new variant cannot
/// silently miss a wire value.
macro_rules! wire_enum {
    ($ty:ty, $registry_name:literal, [$(($value:literal, $variant:ident, $name:literal)),+ $(,)?]) => {
        impl $ty {
            /// Every value, for exhaustive tests.
            pub const ALL: &'static [Self] = &[$(Self::$variant),+];

            /// The enum's `enums[].name` in `registry-v1.json`.
            pub const REGISTRY_NAME: &'static str = $registry_name;

            /// The wire value.
            #[must_use]
            pub const fn to_wire(self) -> u64 {
                match self { $(Self::$variant => $value),+ }
            }

            /// Parse a wire value; `None` for anything unregistered in v1
            /// (a hard parse reject — never a silently ignored value).
            #[must_use]
            pub const fn from_wire(value: u64) -> Option<Self> {
                match value { $($value => Some(Self::$variant),)+ _ => None }
            }

            /// The registry's own spelling of this value.
            #[must_use]
            pub const fn registry_value_name(self) -> &'static str {
                match self { $(Self::$variant => $name),+ }
            }
        }

        impl fmt::Display for $ty {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.registry_value_name())
            }
        }
    };
}

wire_enum!(
    DescriptorKind,
    "descriptor_kind",
    [(0, Binary, "binary"), (1, Text, "text")]
);
wire_enum!(
    FineTreeDomain,
    "fine_tree_domain",
    [(0, Raw, "raw"), (1, Canonical, "canonical")]
);
wire_enum!(
    UnitKind,
    "unit_kind",
    [(0, Normal, "normal"), (1, RawMirror, "raw-mirror")]
);

impl DescriptorKind {
    /// The fine-tree byte domain implied by this kind (MVP-SPEC.md
    /// line 84: "over canonical bytes for text, raw bytes for binary").
    /// The wire records the domain explicitly (spec line 83) and decode
    /// checks it against this function, so a descriptor claiming a
    /// binary file's tree covers canonical bytes cannot decode.
    #[must_use]
    pub const fn fine_tree_domain(self) -> FineTreeDomain {
        match self {
            Self::Binary => FineTreeDomain::Raw,
            Self::Text => FineTreeDomain::Canonical,
        }
    }
}

/// Map a wire `sig_alg` id to its algorithm (registry §6.2, decision
/// D17 proposal: `0 = ed25519`, `1 = ml-dsa-65`, `2..=15` reserved).
///
/// `None` = unregistered in v1: an appearance in `sig_policy`, in
/// `pubkeys`, or in `signatures` is a parse-time reject (spec line 97),
/// each position carrying its own [`super::AlgPosition`] so the three
/// tamper rows stay distinct.
///
/// **C14 seam.** The numeric registry lives here because it is a *wire*
/// assignment (F's schema); [`SigAlg`] itself is C's type, reused rather
/// than duplicated so no second algorithm enum can drift. If C14 re-homes
/// the mapping to `crypto::sig_policy`, the values move unchanged — they
/// freeze with the registry at Q14.
#[must_use]
pub const fn sig_alg_from_wire(id: u64) -> Option<SigAlg> {
    match id {
        0 => Some(SigAlg::Ed25519),
        1 => Some(SigAlg::MlDsa65),
        _ => None,
    }
}

/// The wire `sig_alg` id of an algorithm (inverse of
/// [`sig_alg_from_wire`]). Wildcard-free: a new [`SigAlg`] variant fails
/// to compile until it is assigned a wire id.
#[must_use]
pub const fn sig_alg_to_wire(alg: SigAlg) -> u64 {
    match alg {
        SigAlg::Ed25519 => 0,
        SigAlg::MlDsa65 => 1,
    }
}

/// Exact public-key length for an algorithm (registry §2/§6.2).
#[must_use]
pub const fn pubkey_len(alg: SigAlg) -> u64 {
    match alg {
        SigAlg::Ed25519 => ED25519_PUBKEY_LEN,
        SigAlg::MlDsa65 => MLDSA65_PUBKEY_LEN,
    }
}

/// Exact signature length for an algorithm (registry §2/§6.2).
#[must_use]
pub const fn sig_len(alg: SigAlg) -> u64 {
    match alg {
        SigAlg::Ed25519 => ED25519_SIG_LEN,
        SigAlg::MlDsa65 => MLDSA65_SIG_LEN,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Assigned keys are ascending, duplicate-free, and inside the v1
    /// single-byte band; the reserved band starts right after the last
    /// assigned key and runs to the band max.
    #[test]
    fn key_spaces_are_well_formed() {
        for map in MapId::ALL {
            let keys = map.assigned_keys();
            assert!(!keys.is_empty(), "{map}: no keys assigned");
            for window in keys.windows(2) {
                assert!(
                    window[0] < window[1],
                    "{map}: keys must ascend, got {window:?}"
                );
            }
            for &k in keys {
                assert!(k <= V1_KEY_BAND_MAX, "{map}: key {k} outside the v1 band");
            }
            let last_assigned = *keys.last().expect("non-empty");
            match map.reserved_band() {
                Some((first, last)) => {
                    assert_eq!(first, last_assigned + 1, "{map}: reserved band must abut");
                    assert_eq!(last, V1_KEY_BAND_MAX, "{map}: reserved band must fill");
                }
                None => assert_eq!(
                    map,
                    MapId::Envelope,
                    "only the frozen envelope may reserve nothing"
                ),
            }
        }
    }

    /// Classification: assigned, reserved band, and the `>= 24` unknown
    /// band — with the envelope's no-reserved-space exception.
    #[test]
    fn key_classification_covers_three_bands() {
        assert_eq!(MapId::Body.classify(0), KeyClass::Assigned);
        assert_eq!(MapId::Body.classify(7), KeyClass::Assigned);
        assert_eq!(MapId::Body.classify(8), KeyClass::Reserved);
        assert_eq!(MapId::Body.classify(23), KeyClass::Reserved);
        assert_eq!(MapId::Body.classify(24), KeyClass::Unknown);
        assert_eq!(MapId::Body.classify(u64::MAX), KeyClass::Unknown);

        // The envelope's shape is frozen forever: no reserved slots at all.
        assert_eq!(MapId::Envelope.classify(1), KeyClass::Assigned);
        assert_eq!(MapId::Envelope.classify(2), KeyClass::Unknown);
        assert_eq!(MapId::Envelope.classify(23), KeyClass::Unknown);
    }

    /// Wire enums round-trip and reject unregistered values.
    #[test]
    fn wire_enums_round_trip_and_reject_unregistered() {
        for &k in DescriptorKind::ALL {
            assert_eq!(DescriptorKind::from_wire(k.to_wire()), Some(k));
        }
        for &d in FineTreeDomain::ALL {
            assert_eq!(FineTreeDomain::from_wire(d.to_wire()), Some(d));
        }
        for &k in UnitKind::ALL {
            assert_eq!(UnitKind::from_wire(k.to_wire()), Some(k));
        }
        assert_eq!(DescriptorKind::from_wire(2), None);
        assert_eq!(FineTreeDomain::from_wire(2), None);
        assert_eq!(UnitKind::from_wire(2), None);
        assert_eq!(UnitKind::from_wire(u64::MAX), None);
    }

    /// The fine-tree domain is a function of the descriptor kind
    /// (MVP-SPEC.md line 84) — the mapping decode enforces.
    #[test]
    fn fine_tree_domain_is_determined_by_kind() {
        assert_eq!(
            DescriptorKind::Binary.fine_tree_domain(),
            FineTreeDomain::Raw
        );
        assert_eq!(
            DescriptorKind::Text.fine_tree_domain(),
            FineTreeDomain::Canonical
        );
    }

    /// D17 values, both directions, plus the reserved band.
    #[test]
    fn sig_alg_wire_mapping_matches_d17() {
        assert_eq!(sig_alg_from_wire(0), Some(SigAlg::Ed25519));
        assert_eq!(sig_alg_from_wire(1), Some(SigAlg::MlDsa65));
        for reserved in 2..=15u64 {
            assert_eq!(sig_alg_from_wire(reserved), None, "id {reserved}");
        }
        assert_eq!(sig_alg_from_wire(u64::MAX), None);
        for alg in SigAlg::ALL {
            assert_eq!(sig_alg_from_wire(sig_alg_to_wire(alg)), Some(alg));
        }
    }

    /// Frozen per-algorithm material lengths (registry §2).
    #[test]
    fn per_algorithm_lengths_are_frozen() {
        assert_eq!(pubkey_len(SigAlg::Ed25519), 32);
        assert_eq!(sig_len(SigAlg::Ed25519), 64);
        assert_eq!(pubkey_len(SigAlg::MlDsa65), 1952);
        assert_eq!(sig_len(SigAlg::MlDsa65), 3309);
    }

    /// Wire length constants agree with the crypto-side types that carry
    /// the same values (no second source of truth for a byte length).
    #[test]
    fn lengths_agree_with_crypto_newtypes() {
        assert_eq!(SEAL_ID_LEN, crate::crypto::secrets::SealId::LEN as u64);
        assert_eq!(COMMITMENT_LEN, 32);
        assert_eq!(ADDRESS_LEN, 32);
        assert_eq!(NONCE_LEN, 24);
    }
}
