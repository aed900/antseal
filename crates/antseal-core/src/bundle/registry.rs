//! The code side of the v1 wire registry's **bundle half** (F4 §§7.6–7.15):
//! `.sealproof` map keys, reserved bands, fixed byte lengths, and the
//! `anchor_status` enum.
//!
//! Normative table: `docs/format/registry-v1.md` §§7.6–7.15; machine mirror
//! `docs/format/registry-v1.json`. Every **map key**, **reserved band**
//! (including the two *named* reserved slots), **closed-enum value and
//! spelling**, **fixed byte length**, and **tuple arity** below is asserted
//! equal to its registry row by
//! `crates/antseal-core/tests/format_registry_draft.rs`
//! (`code_map_keys_match_the_registry`,
//! `code_reserved_bands_match_the_registry`, `code_enums_match_the_registry`,
//! `code_scalar_lengths_match_the_registry`,
//! `code_tuple_arities_match_the_registry`) — the 1:1 code ⟷ registry check
//! registry §14 defers to F5/F8, in **both** directions. **Changing a number
//! here without changing the registry (or vice versa) fails those tests**,
//! which is the point: after the Q14 `format-v1-freeze` gate, either change
//! is a format-version event (MVP-SPEC.md line 123).
//!
//! [`FORMAT_VERSION_V1`] is the one constant with no machine-readable row to
//! bind to — registry §7.6 key 0 states its value in prose — so it is pinned
//! by this module's own test instead.
//!
//! # Key bands (registry §1 rule 4, §7.15)
//!
//! Every v1 key lives in `0..=23`. Within that band an unassigned key is
//! **reserved** for v1.x and rejects with [`super::BundleError::ReservedKey`];
//! a key `>= 24` was never reserved and rejects with
//! [`super::BundleError::UnknownKey`]. Unlike the manifest envelope, **no
//! bundle map is shape-frozen**: all nine reserve the remainder of their band
//! (`last_assigned + 1 ..= 23`).
//!
//! Two slots are *named* reserved slots — bundle key 10 (`range_reveals`,
//! v1.1 sub-unit range covers) and receipt key 3 (`chain_inputs`, the v1.1
//! Arbitrum verification chain). Per registry §7.15 a named reserved slot is
//! **documentation, not a new error class**: both raise the same
//! reserved-slot error as a nameless reserved key, because giving one its own
//! code would mean v1.1 *changes* an error code when it assigns the key —
//! exactly what D30's stable-code contract forbids.
//!
//! # The bundle versions independently of the manifest
//!
//! [`FORMAT_VERSION_V1`] here and [`crate::manifest::registry::FORMAT_VERSION_V1`]
//! are two discriminants, not one (registry §7.6 key 0): a v1 bundle may
//! embed a v2 manifest and vice versa, so F10 dispatches them separately and
//! never infers one from the other.

use core::fmt;

use crate::manifest::registry::{ADDRESS_LEN, NONCE_LEN, V1_KEY_BAND_MAX};

pub use crate::manifest::registry::KeyClass;

/// `format_version` value of the v1 `.sealproof` bundle (registry §7.6
/// key 0) — **independent** of the manifest body's own discriminant.
pub const FORMAT_VERSION_V1: u64 = 1;

/// Disclosed 32-byte AEAD key length — `k_u` (per reveal) and `k_m` (storage
/// record); registry §2 scalar `key32`.
pub const KEY_LEN: u64 = 32;

/// Disclosed 16-byte salt length — `unit_salt`, `path_salt`, `file_salt`;
/// registry §2 scalar `salt16` (MVP-SPEC.md line 121).
pub const SALT_LEN: u64 = 16;

/// Disclosed 32-byte GGM seed length — `s_root` and every cover seed;
/// registry §2 scalar `seed32` (MVP-SPEC.md line 121).
pub const SEED_LEN: u64 = 32;

/// Boundary Merkle node hash length; registry §2 scalar `hash32`
/// (MVP-SPEC.md line 121).
pub const NODE_HASH_LEN: u64 = 32;

/// EVM transaction hash length (Keccak-256); registry §2 scalar `hash32`.
pub const TX_HASH_LEN: u64 = 32;

/// Bitcoin block header length — **exactly** 80 bytes (MVP-SPEC.md line 108;
/// registry §2 scalar `btc_header`). A wrong length is its own rejection,
/// never a "malformed header": header *parsing* is A's, at M2.
pub const BLOCK_HEADER_LEN: u64 = 80;

/// XChaCha20-Poly1305 nonce length in the storage record; registry §2.
pub const STORAGE_NONCE_LEN: u64 = NONCE_LEN;

/// Autonomi address length in the storage record (D11); registry §2.
pub const STORAGE_ADDRESS_LEN: u64 = ADDRESS_LEN;

/// `padded_length` block size (MVP-SPEC.md line 91): every unit plaintext is
/// padded to a positive multiple of 256 bytes.
pub const PADDING_BLOCK: u64 = 256;

/// XChaCha20-Poly1305 tag length appended to every unit ciphertext.
pub const AEAD_TAG_LEN: u64 = 16;

/// Smallest well-shaped unit ciphertext: one padding block plus the tag
/// (registry §2). Combined with the residue rule below this is the cheap
/// parse-time gate; the exact `len == padded_length(true_length) + 16` needs
/// the manifest and is R's.
pub const MIN_CIPHERTEXT_LEN: u64 = PADDING_BLOCK + AEAD_TAG_LEN;

/// Unsigned-integer map keys of every v1 bundle-side map (registry
/// §§7.6–7.14). Grouped by map so call sites read as
/// `key::covered_reveal::COVER` rather than as bare numbers.
pub mod key {
    /// `.sealproof` top level — registry §7.6.
    pub mod bundle {
        /// Format version discriminant; sorted first on the wire.
        pub const FORMAT_VERSION: u64 = 0;
        /// The full plaintext manifest **envelope** bytes, as anchored.
        pub const MANIFEST: u64 = 1;
        /// The manifest's own storage triple.
        pub const STORAGE_RECORD: u64 = 2;
        /// OTS anchor artifacts (may be empty).
        pub const OTS_ANCHORS: u64 = 3;
        /// TSA anchor artifacts (may be empty).
        pub const TSA_ANCHORS: u64 = 4;
        /// The opt-in Arbitrum receipt — the one optional top-level key.
        pub const RECEIPT: u64 = 5;
        /// Fine-tree-covered unit reveals (may be empty).
        pub const COVERED_REVEALS: u64 = 6;
        /// Non-covered unit reveals (may be empty).
        pub const NONCOVERED_REVEALS: u64 = 7;
        /// Touched-file entries (may be empty).
        pub const TOUCHED_FILES: u64 = 8;
        /// Fully-revealed-file entries (may be empty).
        pub const FULL_REVEALS: u64 = 9;
        /// **Named reserved slot**: v1.1 `range_reveals` (registry §9).
        /// Reject-if-present in v1 with the *ordinary* reserved-slot error.
        pub const RESERVED_RANGE_REVEALS: u64 = 10;
        /// First reserved key of the bundle map.
        pub const RESERVED_FIRST: u64 = RESERVED_RANGE_REVEALS;
    }

    /// Manifest storage record — registry §7.7.
    pub mod storage_record {
        /// Autonomi address of the **encrypted** manifest copy.
        pub const ADDRESS: u64 = 0;
        /// That copy's XChaCha20-Poly1305 nonce.
        pub const NONCE: u64 = 1;
        /// `k_m = HKDF(W, "manifest-key")`.
        pub const K_M: u64 = 2;
        /// First reserved key of the storage-record map.
        pub const RESERVED_FIRST: u64 = 3;
    }

    /// OTS anchor artifact — registry §7.8.
    pub mod ots_anchor {
        /// Sealer-recorded `anchor_status` — never trusted.
        pub const STATUS: u64 = 0;
        /// Raw `.ots` bytes, opaque at this layer.
        pub const OTS: u64 = 1;
        /// Attested Bitcoin block height — upgrade group.
        pub const BLOCK_HEIGHT: u64 = 2;
        /// The 80-byte Bitcoin block header — upgrade group.
        pub const BLOCK_HEADER: u64 = 3;
        /// When the upgrade/header was fetched — upgrade group.
        pub const FETCH_DATE: u64 = 4;
        /// First reserved key of the OTS-artifact map.
        pub const RESERVED_FIRST: u64 = 5;
    }

    /// TSA anchor artifact — registry §7.9.
    pub mod tsa_anchor {
        /// Sealer-recorded `anchor_status` — never trusted.
        pub const STATUS: u64 = 0;
        /// DER `TimeStampResp`/token, opaque at this layer.
        pub const TOKEN: u64 = 1;
        /// DER intermediate certificates — **intermediates only**.
        pub const INTERMEDIATES: u64 = 2;
        /// When the token was obtained.
        pub const FETCH_DATE: u64 = 3;
        /// First reserved key of the TSA-artifact map.
        ///
        /// Key 4 held an informational `source` string in the draft
        /// registry; **D8 §1 removed it from v1** and it is now a checked
        /// absence (registry §7.6.1). Plain reserved, not a named slot — a
        /// TSA source string is committed to nothing, so the option is
        /// preserved by the band rather than by a name.
        pub const RESERVED_FIRST: u64 = 4;
    }

    /// Arbitrum receipt record — registry §7.10.
    pub mod receipt {
        /// Keccak-256 EVM transaction hashes, capture order.
        pub const TX_HASHES: u64 = 0;
        /// The payment's Arbitrum One block number.
        pub const BLOCK_NUMBER: u64 = 1;
        /// Opaque A/S capture (quote preimages, `proof_bytes`).
        pub const PAYLOAD: u64 = 2;
        /// **Named reserved slot**: v1.1 `chain_inputs` (registry §9).
        pub const RESERVED_CHAIN_INPUTS: u64 = 3;
        /// First reserved key of the receipt map.
        pub const RESERVED_FIRST: u64 = RESERVED_CHAIN_INPUTS;
    }

    /// Covered-unit reveal — registry §7.11.
    pub mod covered_reveal {
        /// Work-global unit ordinal; resolves into the manifest **`[R]`**.
        pub const UNIT_ID: u64 = 0;
        /// The disclosed 32-byte unit key.
        pub const K_U: u64 = 1;
        /// The embedded unit ciphertext.
        pub const CIPHERTEXT: u64 = 2;
        /// The leaf-exact GGM sub-cover.
        pub const COVER: u64 = 3;
        /// Boundary Merkle sibling path up to `fine_root`.
        pub const PATHS: u64 = 4;
        /// First reserved key of the covered-reveal map.
        pub const RESERVED_FIRST: u64 = 5;
    }

    /// Non-covered-unit reveal — registry §7.12. Keys 0–2 are deliberately
    /// key-aligned with [`covered_reveal`] so both reveal kinds share one
    /// decode prefix.
    pub mod noncovered_reveal {
        /// Work-global unit ordinal; resolves into the manifest **`[R]`**.
        pub const UNIT_ID: u64 = 0;
        /// The disclosed 32-byte unit key.
        pub const K_U: u64 = 1;
        /// The embedded unit ciphertext.
        pub const CIPHERTEXT: u64 = 2;
        /// The 16-byte salt that opens `unit_commit`.
        pub const UNIT_SALT: u64 = 3;
        /// First reserved key of the non-covered-reveal map.
        pub const RESERVED_FIRST: u64 = 4;
    }

    /// Touched-file entry — registry §7.13.
    pub mod touched_file {
        /// Index into the manifest file table; in-range **`[R]`**.
        pub const FILE_ID: u64 = 0;
        /// The sealed path — bytes **as received** are the commitment
        /// pre-image.
        pub const PATH: u64 = 1;
        /// The 16-byte path-only salt.
        pub const PATH_SALT: u64 = 2;
        /// First reserved key of the touched-file map.
        pub const RESERVED_FIRST: u64 = 3;
    }

    /// Fully-revealed-file entry — registry §7.14.
    pub mod full_reveal {
        /// Index into the manifest file table; in-range **`[R]`**.
        pub const FILE_ID: u64 = 0;
        /// The 16-byte content-commitment salt.
        pub const FILE_SALT: u64 = 1;
        /// The 32-byte full `[0, n)` GGM cover; presence is **`[R]`**.
        pub const S_ROOT: u64 = 2;
        /// First reserved key of the full-reveal map.
        pub const RESERVED_FIRST: u64 = 3;
    }
}

/// Which fixed-schema bundle-side wire map a key-space error refers to
/// (registry §7.15's nine map identities).
///
/// Deliberately a **separate** enum from
/// [`crate::manifest::registry::MapId`]: §7.15 forbids re-homing or
/// renumbering the five manifest-side variants, and keeping the two spaces
/// apart is what stops a bundle rejection from rendering as a manifest one
/// under D78.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BundleMapId {
    /// The `.sealproof` top level (registry §7.6).
    Bundle,
    /// The manifest storage record (registry §7.7).
    StorageRecord,
    /// One OTS anchor artifact (registry §7.8).
    OtsAnchor,
    /// One TSA anchor artifact (registry §7.9).
    TsaAnchor,
    /// The Arbitrum receipt record (registry §7.10).
    ReceiptRecord,
    /// One covered-unit reveal (registry §7.11).
    CoveredReveal,
    /// One non-covered-unit reveal (registry §7.12).
    NonCoveredReveal,
    /// One touched-file entry (registry §7.13).
    TouchedFile,
    /// One fully-revealed-file entry (registry §7.14).
    FullReveal,
}

impl BundleMapId {
    /// Every bundle map, for exhaustive tests.
    pub const ALL: [Self; 9] = [
        Self::Bundle,
        Self::StorageRecord,
        Self::OtsAnchor,
        Self::TsaAnchor,
        Self::ReceiptRecord,
        Self::CoveredReveal,
        Self::NonCoveredReveal,
        Self::TouchedFile,
        Self::FullReveal,
    ];

    /// The map's registry name — identical to the `maps[].name` of
    /// `registry-v1.json` (registry §7.15), which is how the 1:1 test pairs
    /// code to table.
    #[must_use]
    pub const fn registry_name(self) -> &'static str {
        match self {
            Self::Bundle => "bundle",
            Self::StorageRecord => "storage_record",
            Self::OtsAnchor => "ots_anchor",
            Self::TsaAnchor => "tsa_anchor",
            Self::ReceiptRecord => "receipt_record",
            Self::CoveredReveal => "covered_reveal",
            Self::NonCoveredReveal => "noncovered_reveal",
            Self::TouchedFile => "touched_file",
            Self::FullReveal => "full_reveal",
        }
    }

    /// The keys this v1 schema assigns, ascending.
    #[must_use]
    pub const fn assigned_keys(self) -> &'static [u64] {
        match self {
            Self::Bundle => &[
                key::bundle::FORMAT_VERSION,
                key::bundle::MANIFEST,
                key::bundle::STORAGE_RECORD,
                key::bundle::OTS_ANCHORS,
                key::bundle::TSA_ANCHORS,
                key::bundle::RECEIPT,
                key::bundle::COVERED_REVEALS,
                key::bundle::NONCOVERED_REVEALS,
                key::bundle::TOUCHED_FILES,
                key::bundle::FULL_REVEALS,
            ],
            Self::StorageRecord => &[
                key::storage_record::ADDRESS,
                key::storage_record::NONCE,
                key::storage_record::K_M,
            ],
            Self::OtsAnchor => &[
                key::ots_anchor::STATUS,
                key::ots_anchor::OTS,
                key::ots_anchor::BLOCK_HEIGHT,
                key::ots_anchor::BLOCK_HEADER,
                key::ots_anchor::FETCH_DATE,
            ],
            Self::TsaAnchor => &[
                key::tsa_anchor::STATUS,
                key::tsa_anchor::TOKEN,
                key::tsa_anchor::INTERMEDIATES,
                key::tsa_anchor::FETCH_DATE,
            ],
            Self::ReceiptRecord => &[
                key::receipt::TX_HASHES,
                key::receipt::BLOCK_NUMBER,
                key::receipt::PAYLOAD,
            ],
            Self::CoveredReveal => &[
                key::covered_reveal::UNIT_ID,
                key::covered_reveal::K_U,
                key::covered_reveal::CIPHERTEXT,
                key::covered_reveal::COVER,
                key::covered_reveal::PATHS,
            ],
            Self::NonCoveredReveal => &[
                key::noncovered_reveal::UNIT_ID,
                key::noncovered_reveal::K_U,
                key::noncovered_reveal::CIPHERTEXT,
                key::noncovered_reveal::UNIT_SALT,
            ],
            Self::TouchedFile => &[
                key::touched_file::FILE_ID,
                key::touched_file::PATH,
                key::touched_file::PATH_SALT,
            ],
            Self::FullReveal => &[
                key::full_reveal::FILE_ID,
                key::full_reveal::FILE_SALT,
                key::full_reveal::S_ROOT,
            ],
        }
    }

    /// The map's reserved-for-v1.x band. Every bundle map reserves — there
    /// is no bundle-side counterpart of the shape-frozen manifest envelope
    /// (registry §7.15), so this is not an `Option`.
    #[must_use]
    pub const fn reserved_band(self) -> (u64, u64) {
        let first = match self {
            Self::Bundle => key::bundle::RESERVED_FIRST,
            Self::StorageRecord => key::storage_record::RESERVED_FIRST,
            Self::OtsAnchor => key::ots_anchor::RESERVED_FIRST,
            Self::TsaAnchor => key::tsa_anchor::RESERVED_FIRST,
            Self::ReceiptRecord => key::receipt::RESERVED_FIRST,
            Self::CoveredReveal => key::covered_reveal::RESERVED_FIRST,
            Self::NonCoveredReveal => key::noncovered_reveal::RESERVED_FIRST,
            Self::TouchedFile => key::touched_file::RESERVED_FIRST,
            Self::FullReveal => key::full_reveal::RESERVED_FIRST,
        };
        (first, V1_KEY_BAND_MAX)
    }

    /// Classify a decoded key against this map's v1 schema.
    #[must_use]
    pub fn classify(self, decoded_key: u64) -> KeyClass {
        if self.assigned_keys().contains(&decoded_key) {
            return KeyClass::Assigned;
        }
        let (first, last) = self.reserved_band();
        if decoded_key >= first && decoded_key <= last {
            KeyClass::Reserved
        } else {
            KeyClass::Unknown
        }
    }
}

impl fmt::Display for BundleMapId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Bundle => "bundle",
            Self::StorageRecord => "storage record",
            Self::OtsAnchor => "OTS anchor artifact",
            Self::TsaAnchor => "TSA anchor artifact",
            Self::ReceiptRecord => "receipt record",
            Self::CoveredReveal => "covered-unit reveal",
            Self::NonCoveredReveal => "non-covered-unit reveal",
            Self::TouchedFile => "touched-file entry",
            Self::FullReveal => "full-reveal entry",
        })
    }
}

/// `anchor_status` (registry §6.1) — the spec's seven-state per-anchor
/// taxonomy (MVP-SPEC.md lines 129–135) as it appears on the wire.
///
/// **Sealer-recorded, never trusted.** The verifier derives its own verdict
/// state from the artifacts (sealer-as-adversary, spec line 121); this field
/// exists so a bundle can carry what the *sealer* believed at capture time.
/// Which subset is legal *as recorded* is an A/R semantic rule, not a parse
/// rule — the schema admits all seven.
///
/// Values `7..=15` are reserved and unregistered in v1: any appearance is a
/// parse-time reject ([`super::BundleError::UnknownAnchorStatus`]), never a
/// silently ignored value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AnchorStatus {
    /// Independently proven time (headline-eligible).
    Proven = 0,
    /// Token verified; its chain was valid at `genTime` but the certificate
    /// has since expired (headline-eligible — aging bundles must not rot).
    ValidAtStampingCertSinceExpired = 1,
    /// Committed to a Bitcoin block whose header is embedded; needs
    /// `--online` confirmation before it can carry a headline time.
    Attested = 2,
    /// Submitted to a calendar, not yet upgraded.
    Pending = 3,
    /// Chain closes only against bundle-supplied material.
    InternallyConsistentOnly = 4,
    /// Verification failed.
    Invalid = 5,
    /// Representable for uniformity; an artifact *recording* `absent` is
    /// self-contradictory (absence of an anchor is the empty section, not an
    /// entry) and is expected to be rejected by A/R's semantic rule, not
    /// here.
    Absent = 6,
}

impl AnchorStatus {
    /// Every registered value, for exhaustive tests.
    pub const ALL: &'static [Self] = &[
        Self::Proven,
        Self::ValidAtStampingCertSinceExpired,
        Self::Attested,
        Self::Pending,
        Self::InternallyConsistentOnly,
        Self::Invalid,
        Self::Absent,
    ];

    /// The enum's `enums[].name` in `registry-v1.json`.
    pub const REGISTRY_NAME: &'static str = "anchor_status";

    /// The wire value.
    #[must_use]
    pub const fn to_wire(self) -> u64 {
        match self {
            Self::Proven => 0,
            Self::ValidAtStampingCertSinceExpired => 1,
            Self::Attested => 2,
            Self::Pending => 3,
            Self::InternallyConsistentOnly => 4,
            Self::Invalid => 5,
            Self::Absent => 6,
        }
    }

    /// Parse a wire value; `None` for anything unregistered in v1.
    #[must_use]
    pub const fn from_wire(value: u64) -> Option<Self> {
        match value {
            0 => Some(Self::Proven),
            1 => Some(Self::ValidAtStampingCertSinceExpired),
            2 => Some(Self::Attested),
            3 => Some(Self::Pending),
            4 => Some(Self::InternallyConsistentOnly),
            5 => Some(Self::Invalid),
            6 => Some(Self::Absent),
            _ => None,
        }
    }

    /// The registry's own spelling of this value.
    #[must_use]
    pub const fn registry_value_name(self) -> &'static str {
        match self {
            Self::Proven => "proven",
            Self::ValidAtStampingCertSinceExpired => "valid-at-stamping-cert-since-expired",
            Self::Attested => "attested",
            Self::Pending => "pending",
            Self::InternallyConsistentOnly => "internally-consistent-only",
            Self::Invalid => "invalid",
            Self::Absent => "absent",
        }
    }
}

impl fmt::Display for AnchorStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.registry_value_name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Assigned keys ascend, are duplicate-free, sit inside the v1
    /// single-byte band, and the reserved band abuts the last assigned key
    /// and fills to the band max — the bundle-side twin of F5's
    /// `key_spaces_are_well_formed`, and exactly what registry §7.15
    /// prescribes ("reserved bands abut and fill").
    #[test]
    fn key_spaces_are_well_formed() {
        for map in BundleMapId::ALL {
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
            let (first, last) = map.reserved_band();
            assert_eq!(first, last_assigned + 1, "{map}: reserved band must abut");
            assert_eq!(last, V1_KEY_BAND_MAX, "{map}: reserved band must fill");
        }
    }

    /// The two *named* reserved slots are ordinary reserved keys: they sit
    /// inside their map's reserved band and are not assigned (registry
    /// §7.15 — a named slot is documentation, not a new error class).
    #[test]
    fn named_reserved_slots_classify_as_plain_reserved() {
        assert_eq!(
            BundleMapId::Bundle.classify(key::bundle::RESERVED_RANGE_REVEALS),
            KeyClass::Reserved
        );
        assert_eq!(
            BundleMapId::ReceiptRecord.classify(key::receipt::RESERVED_CHAIN_INPUTS),
            KeyClass::Reserved
        );
    }

    /// Classification across the three bands, on every bundle map.
    #[test]
    fn key_classification_covers_three_bands() {
        for map in BundleMapId::ALL {
            for &k in map.assigned_keys() {
                assert_eq!(map.classify(k), KeyClass::Assigned, "{map}: key {k}");
            }
            let (first, last) = map.reserved_band();
            assert_eq!(map.classify(first), KeyClass::Reserved, "{map}");
            assert_eq!(map.classify(last), KeyClass::Reserved, "{map}");
            assert_eq!(map.classify(last + 1), KeyClass::Unknown, "{map}");
            assert_eq!(map.classify(u64::MAX), KeyClass::Unknown, "{map}");
        }
    }

    /// Registry names are pairwise distinct and disjoint from the
    /// manifest-side map names (registry §7.15: F8 registers *nine more*
    /// maps, it does not re-home the five that exist).
    #[test]
    fn registry_names_are_distinct_from_the_manifest_half() {
        use std::collections::BTreeSet;
        let bundle: BTreeSet<&str> = BundleMapId::ALL.iter().map(|m| m.registry_name()).collect();
        assert_eq!(bundle.len(), BundleMapId::ALL.len(), "names must be unique");
        for manifest_map in crate::manifest::registry::MapId::ALL {
            assert!(
                !bundle.contains(manifest_map.registry_name()),
                "{manifest_map} collides with a bundle map name"
            );
        }
    }

    /// `anchor_status` round-trips and rejects the reserved band.
    #[test]
    fn anchor_status_round_trips_and_rejects_unregistered() {
        for &status in AnchorStatus::ALL {
            assert_eq!(AnchorStatus::from_wire(status.to_wire()), Some(status));
        }
        for reserved in 7..=15u64 {
            assert_eq!(AnchorStatus::from_wire(reserved), None, "value {reserved}");
        }
        assert_eq!(AnchorStatus::from_wire(u64::MAX), None);
        // Seven states, in spec order (MVP-SPEC.md lines 129–135).
        assert_eq!(AnchorStatus::ALL.len(), 7);
        for (i, &status) in AnchorStatus::ALL.iter().enumerate() {
            assert_eq!(status.to_wire(), i as u64);
        }
    }

    /// Bundle-side lengths agree with the manifest-side constants and the
    /// crypto newtypes that carry the same values — no second source of
    /// truth for a byte length.
    #[test]
    fn lengths_agree_with_the_shared_constants() {
        use crate::crypto::material::{Key32, NodeHash32, Salt16, Seed32};
        assert_eq!(KEY_LEN, Key32::LEN as u64);
        assert_eq!(SALT_LEN, Salt16::LEN as u64);
        assert_eq!(SEED_LEN, Seed32::LEN as u64);
        assert_eq!(NODE_HASH_LEN, NodeHash32::LEN as u64);
        assert_eq!(STORAGE_NONCE_LEN, NONCE_LEN);
        assert_eq!(STORAGE_ADDRESS_LEN, ADDRESS_LEN);
        assert_eq!(BLOCK_HEADER_LEN, 80);
        assert_eq!(TX_HASH_LEN, 32);
        assert_eq!(MIN_CIPHERTEXT_LEN, 272);
        assert_eq!(MIN_CIPHERTEXT_LEN % PADDING_BLOCK, AEAD_TAG_LEN);
    }

    /// The bundle discriminant is its own constant. It happens to equal the
    /// manifest's today; the assertion records that this is a coincidence of
    /// v1, not a shared definition (registry §7.6 key 0).
    #[test]
    fn bundle_version_is_independent_of_the_manifest_version() {
        assert_eq!(FORMAT_VERSION_V1, 1);
        assert_eq!(crate::manifest::registry::FORMAT_VERSION_V1, 1);
    }
}
