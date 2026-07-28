//! The v1 manifest body schema (F5): [`ManifestBodyV1`] and its
//! sub-types, with every presence/shape rule of MVP-SPEC.md lines 94 and
//! 98 enforced where a body is *created* — which is the same place it is
//! decoded.
//!
//! # Unrepresentable beats checked
//!
//! Four of the registry's conditional-presence rules are not checks here
//! at all; the types cannot express the violation:
//!
//! | rule (registry) | how it is enforced |
//! | --- | --- |
//! | `canon_commit` iff text | [`CanonMode::Text`] carries it; `Binary` has no field |
//! | `unicode_version` iff text | same variant |
//! | `fine_root` iff fine tree | [`FineTree::Present`] carries it; `Absent` has no field |
//! | `fine_tree_domain` iff fine tree | derived from the kind, never stored twice |
//! | `unit_commit` iff not covered | [`UnitBinding`] (C7) — the covered variant has no field |
//!
//! Decode still produces the corresponding [`ManifestError`] for each,
//! because the *wire* can express all of them; the type system's job is
//! to stop the seal side from ever building one.
//!
//! Two rules genuinely are cross-entry checks, and stay checks:
//!
//! - a unit's coverage mode must agree with its file's fine-tree state
//!   and its own `kind` (a mirror is never covered — spec line 92);
//! - each unit's stored `unit_id` must equal its work-global
//!   manifest-order ordinal (registry §7.5 key 0).
//!
//! # What is deliberately *not* validated here
//!
//! `true_length` = byte-range width, per-file tiling, `size` vs the unit
//! table, and `start + length` overflow are R's semantic checks (see the
//! [`super`] module docs). The wire carries `true_length` and the range
//! width independently *precisely so* the tamper row "`true_length` ≠
//! range width" exists (registry §4); collapsing them at parse would
//! delete a required tamper-matrix row.

use crate::codec::caps::{DecodeBudget, MAX_FILE_COUNT, MAX_UNIT_COUNT, clamped_capacity};
use crate::codec::encode::MapEncoder;
use crate::codec::{CanonicalDecoder, DecodeError, EncodeError, encode_item};
use crate::crypto::commit::CommitmentDigest;
use crate::crypto::disclosure::UnitBinding;
use crate::crypto::error::SigAlg;
use crate::crypto::secrets::SealId;
use crate::format::{SUPPORTED_VERSIONS, V1, VersionDispatch};

use super::error::{
    AlgPosition, CondField, ContainerField, EnumId, FixedLenField, ManifestError, ManifestListKind,
};
use super::registry::{
    ADDRESS_LEN, DescriptorKind, FORMAT_VERSION_V1, FineTreeDomain, KeyClass, MapId, NONCE_LEN,
    UnitKind, key, sig_alg_from_wire, sig_alg_to_wire,
};
use super::sigmap::{SigAlgMap, SigMaterial};

/// Wrap a codec rejection as a body-layer failure (F6's inner layer).
pub(super) const fn body_layer(source: DecodeError) -> ManifestError {
    ManifestError::Body { source }
}

/// Length-checked conversion of a decoded `bstr` into a fixed-size array.
fn fixed<const N: usize>(field: FixedLenField, bytes: &[u8]) -> Result<[u8; N], ManifestError> {
    <[u8; N]>::try_from(bytes).map_err(|_| ManifestError::WrongLength {
        field,
        // usize -> u64 is lossless on every supported target; wire-facing
        // values are u64 so errors match bit-for-bit on wasm32.
        expected: N as u64,
        got: bytes.len() as u64,
    })
}

/// Reject an assigned-key match arm that the classifier already excluded.
/// Unreachable: [`MapId::classify`] returns `Assigned` only for keys the
/// map's decode loop handles. Present so the match is total without a
/// panic path (library code never unwraps).
const fn unhandled_assigned_key(map: MapId, key: u64) -> ManifestError {
    ManifestError::UnknownKey { map, key }
}

/// Classify a decoded map key, converting the two non-assigned bands into
/// their distinct errors (registry §1 rule 4).
fn admit_key(map: MapId, key: u64) -> Result<(), ManifestError> {
    match map.classify(key) {
        KeyClass::Assigned => Ok(()),
        KeyClass::Reserved => Err(ManifestError::ReservedKey { map, key }),
        KeyClass::Unknown => Err(ManifestError::UnknownKey { map, key }),
    }
}

/// A required key that never arrived.
const fn missing(map: MapId, key: u64) -> ManifestError {
    ManifestError::MissingKey { map, key }
}

// ---------------------------------------------------------------------------
// leaf value types
// ---------------------------------------------------------------------------

/// A 24-byte XChaCha20-Poly1305 nonce as carried in the unit table — the
/// single authoritative copy of that unit's nonce (MVP-SPEC.md line 91;
/// reveal entries deliberately carry none).
///
/// Public wire value: plain value semantics, no redaction, no zeroization
/// (a nonce is not secret; it ships in every bundle's manifest).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Nonce24([u8; NONCE_LEN as usize]);

impl Nonce24 {
    /// Length in bytes (registry §2).
    pub const LEN: u64 = NONCE_LEN;

    /// Construct from exactly-sized bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; NONCE_LEN as usize]) -> Self {
        Self(bytes)
    }

    /// Borrow the raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; NONCE_LEN as usize] {
        &self.0
    }
}

/// A 32-byte Autonomi content address — `XorName = [u8; 32]`, BLAKE3-256
/// of the stored chunk (decision D11; `docs/research/S1-ant-core-api-survey.md`
/// §1).
///
/// Held as an opaque 32-byte value: this crate must stay WASM-safe and
/// network-free, so nothing here interprets the address. `antseal-net`
/// converts at its boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ContentAddress([u8; ADDRESS_LEN as usize]);

impl ContentAddress {
    /// Length in bytes (registry §2, decision D11).
    pub const LEN: u64 = ADDRESS_LEN;

    /// Construct from exactly-sized bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; ADDRESS_LEN as usize]) -> Self {
        Self(bytes)
    }

    /// Borrow the raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; ADDRESS_LEN as usize] {
        &self.0
    }
}

/// A unit's byte range in its own byte domain: `[start, length]`
/// (registry §4 — width is the load-bearing quantity, so it is a field
/// rather than a subtraction, and `end < start` is unrepresentable).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ByteRange {
    start: u64,
    length: u64,
}

impl ByteRange {
    /// A range from its start offset and width.
    #[must_use]
    pub const fn new(start: u64, length: u64) -> Self {
        Self { start, length }
    }

    /// First byte offset covered.
    #[must_use]
    pub const fn start(self) -> u64 {
        self.start
    }

    /// Width in bytes — the quantity every consumer actually wants
    /// (`true_length` equality, `padded_length` input, leaf count).
    #[must_use]
    pub const fn length(self) -> u64 {
        self.length
    }

    /// Exclusive end, or `None` on `u64` overflow.
    ///
    /// The registry records overflow as the one residual hazard of the
    /// `[start, length]` form (§4): it must be checked wherever the
    /// exclusive end is formed. Returning `Option` makes forgetting the
    /// check impossible — there is no wrapping accessor. Overflow is
    /// **not** a parse error: an unreachable-but-representable range is
    /// caught by R's tiling check with its own error.
    #[must_use]
    pub const fn end_exclusive(self) -> Option<u64> {
        self.start.checked_add(self.length)
    }

    fn decode(d: &mut CanonicalDecoder<'_>) -> Result<Self, ManifestError> {
        let len = d.array().map_err(body_layer)?;
        if len != 2 {
            return Err(ManifestError::WrongRangeArity { got: len });
        }
        let start = d.u64().map_err(body_layer)?;
        let length = d.u64().map_err(body_layer)?;
        Ok(Self { start, length })
    }
}

// ---------------------------------------------------------------------------
// canonicalization descriptor (registry §7.4)
// ---------------------------------------------------------------------------

/// Whether a file has a canonical rendition, and — if it does — the
/// commitment to it and the Unicode version that produced it.
///
/// The registry's two text-only fields (`canon_commit`, `unicode_version`)
/// live inside the `Text` variant, so "canon_commit on a binary file" is
/// not a state this type can hold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CanonMode {
    /// Binary: no canonical rendition; offsets are raw-byte offsets
    /// (MVP-SPEC.md line 83).
    Binary,
    /// Text: UTF-8/NFC/LF/no-BOM canonical rendition; offsets are
    /// canonical-byte offsets.
    Text {
        /// `canon_commit = SHA-256(0x04 ‖ file_salt ‖ canonical_bytes)`
        /// (spec line 95) — enables full-reveal cross-checks, since
        /// canonicalization is lossy.
        canon_commit: CommitmentDigest,
        /// The exact Unicode data version used for NFC, e.g.
        /// `"unicode-17.0.0"` (spec line 83; decision D25). Frozen per
        /// seal: a verifier recomputing canonicalization applies *this*
        /// version, never "latest".
        ///
        /// Parse checks the CBOR type only. Which version strings are
        /// *known* is G's registry at verify time — an unknown version is
        /// a verification outcome, not a malformed manifest, so an aging
        /// bundle stays parseable forever.
        unicode_version: String,
    },
}

impl CanonMode {
    /// The wire `descriptor_kind`.
    #[must_use]
    pub const fn kind(&self) -> DescriptorKind {
        match self {
            Self::Binary => DescriptorKind::Binary,
            Self::Text { .. } => DescriptorKind::Text,
        }
    }

    /// The `canon_commit`, present iff this is a text file.
    #[must_use]
    pub const fn canon_commit(&self) -> Option<&CommitmentDigest> {
        match self {
            Self::Binary => None,
            Self::Text { canon_commit, .. } => Some(canon_commit),
        }
    }

    /// The recorded Unicode version, present iff this is a text file.
    #[must_use]
    pub fn unicode_version(&self) -> Option<&str> {
        match self {
            Self::Binary => None,
            Self::Text {
                unicode_version, ..
            } => Some(unicode_version),
        }
    }
}

/// Whether a file carries a fine tree, and its root if so.
///
/// `--no-fine-tree` files and empty files are [`Self::Absent`] (G4);
/// those files are permanently whole-file-reveal only and their units
/// carry `unit_commit` instead (spec lines 84, 94).
///
/// The wire's `fine_tree_domain` is **not** stored: it is a function of
/// the descriptor kind (binary ⇒ raw, text ⇒ canonical; spec line 84), so
/// storing it again could only create a contradiction. Encode writes the
/// derived value; decode compares the recorded one against it and rejects
/// a mismatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FineTree {
    /// No fine tree (`--no-fine-tree`, or an empty file).
    Absent,
    /// A fine tree whose root is the file's sole content commitment for
    /// covered bytes (spec line 96).
    Present {
        /// `fine_root` — 32 B.
        root: CommitmentDigest,
    },
}

impl FineTree {
    /// Whether the file has a fine tree (the wire's `fine_tree_present`).
    #[must_use]
    pub const fn is_present(self) -> bool {
        matches!(self, Self::Present { .. })
    }

    /// The root, if present.
    #[must_use]
    pub const fn root(&self) -> Option<&CommitmentDigest> {
        match self {
            Self::Absent => None,
            Self::Present { root } => Some(root),
        }
    }

    /// The wire `fine_tree_present` flag as a `uint` 0/1 (registry §1
    /// rule 1: v1 has no booleans).
    #[must_use]
    pub const fn wire_flag(self) -> u64 {
        if self.is_present() { 1 } else { 0 }
    }
}

/// The canonicalization descriptor as it appears on the wire (registry
/// §7.4): a derived *view* over a [`FileEntry`]'s already-consistent
/// state, never independent storage.
///
/// G4 owns the descriptor's value *semantics* (which transform each kind
/// selects, which Unicode versions are known); F5 owns its wire shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CanonDescriptor<'a> {
    kind: DescriptorKind,
    fine_tree_present: bool,
    fine_tree_domain: Option<FineTreeDomain>,
    unicode_version: Option<&'a str>,
}

impl CanonDescriptor<'_> {
    /// `descriptor_kind` (key 0).
    #[must_use]
    pub const fn kind(&self) -> DescriptorKind {
        self.kind
    }

    /// `fine_tree_present` (key 1).
    #[must_use]
    pub const fn fine_tree_present(&self) -> bool {
        self.fine_tree_present
    }

    /// `fine_tree_domain` (key 2), present iff a fine tree exists.
    #[must_use]
    pub const fn fine_tree_domain(&self) -> Option<FineTreeDomain> {
        self.fine_tree_domain
    }

    /// `unicode_version` (key 3), present iff the file is text.
    #[must_use]
    pub const fn unicode_version(&self) -> Option<&str> {
        self.unicode_version
    }
}

/// The decoded descriptor's raw parts, before they are folded into the
/// [`CanonMode`]/[`FineTree`] pair a [`FileEntry`] stores.
struct DescriptorParts {
    kind: DescriptorKind,
    fine_tree_present: bool,
    unicode_version: Option<String>,
}

impl DescriptorParts {
    fn decode(d: &mut CanonicalDecoder<'_>) -> Result<Self, ManifestError> {
        const MAP: MapId = MapId::Descriptor;
        let mut reader = d.map().map_err(body_layer)?;
        let mut kind: Option<DescriptorKind> = None;
        let mut present: Option<bool> = None;
        let mut domain: Option<FineTreeDomain> = None;
        let mut unicode_version: Option<String> = None;

        while let Some(k) = reader.next_key(d).map_err(body_layer)? {
            admit_key(MAP, k)?;
            match k {
                key::descriptor::KIND => {
                    let raw = d.u64().map_err(body_layer)?;
                    kind = Some(DescriptorKind::from_wire(raw).ok_or(
                        ManifestError::UnknownEnumValue {
                            enumeration: EnumId::DescriptorKind,
                            value: raw,
                        },
                    )?);
                }
                key::descriptor::FINE_TREE_PRESENT => {
                    // Registry §1 rule 1: booleans are uint 0/1. Any
                    // other value is a hard reject, never "non-zero is
                    // truthy" — a lenient reading here would let two
                    // conforming verifiers disagree about whether a file
                    // has a fine tree, under one anchored `work_id`.
                    let raw = d.u64().map_err(body_layer)?;
                    present = Some(match raw {
                        0 => false,
                        1 => true,
                        other => {
                            return Err(ManifestError::UnknownEnumValue {
                                enumeration: EnumId::FineTreeFlag,
                                value: other,
                            });
                        }
                    });
                }
                key::descriptor::FINE_TREE_DOMAIN => {
                    let raw = d.u64().map_err(body_layer)?;
                    domain = Some(FineTreeDomain::from_wire(raw).ok_or(
                        ManifestError::UnknownEnumValue {
                            enumeration: EnumId::FineTreeDomain,
                            value: raw,
                        },
                    )?);
                }
                key::descriptor::UNICODE_VERSION => {
                    unicode_version = Some(d.str().map_err(body_layer)?.to_owned());
                }
                other => return Err(unhandled_assigned_key(MAP, other)),
            }
        }

        let kind = kind.ok_or(missing(MAP, key::descriptor::KIND))?;
        let fine_tree_present = present.ok_or(missing(MAP, key::descriptor::FINE_TREE_PRESENT))?;

        // fine_tree_domain: present iff a tree exists, and equal to the
        // value the kind implies (spec lines 83–84).
        match (fine_tree_present, domain) {
            (true, Some(found)) => {
                let implied = kind.fine_tree_domain();
                if found != implied {
                    return Err(ManifestError::DescriptorDomainMismatch {
                        kind,
                        implied,
                        found,
                    });
                }
            }
            (true, None) => {
                return Err(ManifestError::MissingField {
                    field: CondField::FineTreeDomain,
                });
            }
            (false, Some(_)) => {
                return Err(ManifestError::UnexpectedField {
                    field: CondField::FineTreeDomain,
                });
            }
            (false, None) => {}
        }

        // unicode_version: present iff text.
        match (kind, &unicode_version) {
            (DescriptorKind::Text, None) => {
                return Err(ManifestError::MissingField {
                    field: CondField::UnicodeVersion,
                });
            }
            (DescriptorKind::Binary, Some(_)) => {
                return Err(ManifestError::UnexpectedField {
                    field: CondField::UnicodeVersion,
                });
            }
            _ => {}
        }

        Ok(Self {
            kind,
            fine_tree_present,
            unicode_version,
        })
    }
}

// ---------------------------------------------------------------------------
// unit-table entry (registry §7.5)
// ---------------------------------------------------------------------------

/// One unit-table entry (MVP-SPEC.md lines 91–92, 98).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnitEntry {
    unit_id: u64,
    kind: UnitKind,
    range: ByteRange,
    true_length: u64,
    binding: UnitBinding,
    nonce: Nonce24,
    address: ContentAddress,
}

impl UnitEntry {
    /// Assemble a unit entry. Every shape rule this level owns is
    /// type-enforced ([`UnitBinding`] carries `unit_commit` iff the unit
    /// is non-covered), so there is nothing left to fail on: the
    /// coverage-vs-file agreement is [`FileEntry::new`]'s check and the
    /// id ordinal is [`ManifestBodyV1::new`]'s.
    #[must_use]
    pub const fn new(
        unit_id: u64,
        kind: UnitKind,
        range: ByteRange,
        true_length: u64,
        binding: UnitBinding,
        nonce: Nonce24,
        address: ContentAddress,
    ) -> Self {
        Self {
            unit_id,
            kind,
            range,
            true_length,
            binding,
            nonce,
            address,
        }
    }

    /// Work-global ordinal in manifest order (MVP-SPEC.md line 76) — the
    /// id `reveal --units` takes and the id every per-unit derivation
    /// (`k_u`, `unit_salt`, AAD) keys on.
    #[must_use]
    pub const fn unit_id(&self) -> u64 {
        self.unit_id
    }

    /// Normal or raw-mirror (spec line 92).
    #[must_use]
    pub const fn kind(&self) -> UnitKind {
        self.kind
    }

    /// Byte range in the unit's own byte domain.
    #[must_use]
    pub const fn range(&self) -> ByteRange {
        self.range
    }

    /// Pre-padding byte length. Equality with the range width is R's
    /// invariant, deliberately not a parse rule (registry §4).
    #[must_use]
    pub const fn true_length(&self) -> u64 {
        self.true_length
    }

    /// How the unit's content is bound (C7's [`UnitBinding`]).
    #[must_use]
    pub const fn binding(&self) -> &UnitBinding {
        &self.binding
    }

    /// The `unit_commit`, present iff the unit is not fine-tree-covered.
    #[must_use]
    pub const fn unit_commit(&self) -> Option<&CommitmentDigest> {
        self.binding.unit_commit()
    }

    /// The unit's AEAD nonce — the manifest is the single source of truth
    /// (spec line 91).
    #[must_use]
    pub const fn nonce(&self) -> &Nonce24 {
        &self.nonce
    }

    /// The ciphertext's Autonomi address.
    #[must_use]
    pub const fn address(&self) -> &ContentAddress {
        &self.address
    }

    fn decode(d: &mut CanonicalDecoder<'_>) -> Result<Self, ManifestError> {
        const MAP: MapId = MapId::UnitEntry;
        let mut reader = d.map().map_err(body_layer)?;
        let mut unit_id: Option<u64> = None;
        let mut kind: Option<UnitKind> = None;
        let mut range: Option<ByteRange> = None;
        let mut true_length: Option<u64> = None;
        let mut unit_commit: Option<CommitmentDigest> = None;
        let mut nonce: Option<Nonce24> = None;
        let mut address: Option<ContentAddress> = None;

        while let Some(k) = reader.next_key(d).map_err(body_layer)? {
            admit_key(MAP, k)?;
            match k {
                key::unit::UNIT_ID => unit_id = Some(d.u64().map_err(body_layer)?),
                key::unit::KIND => {
                    let raw = d.u64().map_err(body_layer)?;
                    kind = Some(UnitKind::from_wire(raw).ok_or(
                        ManifestError::UnknownEnumValue {
                            enumeration: EnumId::UnitKind,
                            value: raw,
                        },
                    )?);
                }
                key::unit::RANGE => range = Some(ByteRange::decode(d)?),
                key::unit::TRUE_LENGTH => true_length = Some(d.u64().map_err(body_layer)?),
                key::unit::UNIT_COMMIT => {
                    let bytes = d.bytes().map_err(body_layer)?;
                    unit_commit = Some(fixed(FixedLenField::UnitCommit, bytes)?);
                }
                key::unit::NONCE => {
                    let bytes = d.bytes().map_err(body_layer)?;
                    nonce = Some(Nonce24::from_bytes(fixed(FixedLenField::Nonce, bytes)?));
                }
                key::unit::ADDRESS => {
                    let bytes = d.bytes().map_err(body_layer)?;
                    address = Some(ContentAddress::from_bytes(fixed(
                        FixedLenField::Address,
                        bytes,
                    )?));
                }
                other => return Err(unhandled_assigned_key(MAP, other)),
            }
        }

        let binding = match unit_commit {
            Some(unit_commit) => UnitBinding::NonCovered { unit_commit },
            None => UnitBinding::FineTreeCovered,
        };
        Ok(Self {
            unit_id: unit_id.ok_or(missing(MAP, key::unit::UNIT_ID))?,
            kind: kind.ok_or(missing(MAP, key::unit::KIND))?,
            range: range.ok_or(missing(MAP, key::unit::RANGE))?,
            true_length: true_length.ok_or(missing(MAP, key::unit::TRUE_LENGTH))?,
            binding,
            nonce: nonce.ok_or(missing(MAP, key::unit::NONCE))?,
            address: address.ok_or(missing(MAP, key::unit::ADDRESS))?,
        })
    }

    fn encode_into(&self, m: &mut MapEncoder) -> Result<(), EncodeError> {
        m.entry(key::unit::UNIT_ID, |e| e.u64(self.unit_id))?;
        m.entry(key::unit::KIND, |e| e.u64(self.kind.to_wire()))?;
        m.entry(key::unit::RANGE, |e| {
            e.array(|a| {
                a.item(|e| e.u64(self.range.start()))?;
                a.item(|e| e.u64(self.range.length()))
            })
        })?;
        m.entry(key::unit::TRUE_LENGTH, |e| e.u64(self.true_length))?;
        if let Some(commit) = self.binding.unit_commit() {
            m.entry(key::unit::UNIT_COMMIT, |e| e.bytes(commit))?;
        }
        m.entry(key::unit::NONCE, |e| e.bytes(self.nonce.as_bytes()))?;
        m.entry(key::unit::ADDRESS, |e| e.bytes(self.address.as_bytes()))?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// file-table entry (registry §7.3)
// ---------------------------------------------------------------------------

/// One file-table entry (MVP-SPEC.md line 98). Its index in the body's
/// file table **is** its `file_id` (spec line 76) — no id is stored,
/// because position is total and authoritative and a stored copy could
/// only contradict it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileEntry {
    path_commit: CommitmentDigest,
    raw_commit: CommitmentDigest,
    canon: CanonMode,
    size: u64,
    fine_tree: FineTree,
    units: Vec<UnitEntry>,
}

impl FileEntry {
    /// Assemble a file entry, checking the three rules this level owns:
    /// the unit table is non-empty, it contains at least one `kind = normal`
    /// unit, and every unit's coverage mode agrees with the file's fine-tree
    /// state and the unit's own kind.
    ///
    /// # Errors
    ///
    /// - [`ManifestError::EmptyContainer`] with
    ///   [`ContainerField::Units`] — no units (an empty file still has one
    ///   empty unit, spec line 78).
    /// - [`ManifestError::EmptyContainer`] with
    ///   [`ContainerField::NormalUnits`] — units exist but every one is a
    ///   raw mirror (**D77**). Raw mirrors are tiling-exempt by kind (spec
    ///   line 92), so such a file has no tiling domain for line 121 to speak
    ///   about, D28's `full(F)` is false for it forever, and its
    ///   `canon_commit`/`raw_commit` would be permanently unopenable. No
    ///   honest sealer emits the shape — a mirror exists **iff** raw ≠
    ///   canonical, and G5 emits the `[0,0)` Normal unit alongside the mirror
    ///   even in the degenerate BOM-only case — so the rule costs nothing and
    ///   makes the shape unrepresentable in any decoded manifest.
    /// - [`ManifestError::UnexpectedField`] — a fine-tree-covered unit
    ///   carries a `unit_commit` (spec line 94: covered content is bound
    ///   *solely* by `fine_root`, so a second commitment would let a
    ///   sealer open the same byte two ways).
    /// - [`ManifestError::MissingField`] — a non-covered unit (raw
    ///   mirror, or any unit of a `--no-fine-tree` file) has no
    ///   `unit_commit`, leaving its content unbound.
    pub fn new(
        path_commit: CommitmentDigest,
        raw_commit: CommitmentDigest,
        canon: CanonMode,
        size: u64,
        fine_tree: FineTree,
        units: Vec<UnitEntry>,
    ) -> Result<Self, ManifestError> {
        if units.is_empty() {
            return Err(ManifestError::EmptyContainer {
                field: ContainerField::Units,
            });
        }
        // D77. The position is frozen and observable in both directions: it
        // must come **after** `units.is_empty()`, so a genuinely unit-less
        // file reports `manifest-empty-units` and not this code (two codes
        // for one input would break "one code per outcome a mutation can be
        // pinned to"); and **before** the coverage loop, so a mirror-only
        // file reports the shape error rather than whichever per-unit
        // `unit_commit` error a malformed mirror happens to trip first.
        if !units.iter().any(|unit| unit.kind() == UnitKind::Normal) {
            return Err(ManifestError::EmptyContainer {
                field: ContainerField::NormalUnits,
            });
        }
        for unit in &units {
            let covered = is_covered(fine_tree, unit.kind());
            match (covered, unit.binding()) {
                (true, UnitBinding::NonCovered { .. }) => {
                    return Err(ManifestError::UnexpectedField {
                        field: CondField::UnitCommit,
                    });
                }
                (false, UnitBinding::FineTreeCovered) => {
                    return Err(ManifestError::MissingField {
                        field: CondField::UnitCommit,
                    });
                }
                _ => {}
            }
        }
        Ok(Self {
            path_commit,
            raw_commit,
            canon,
            size,
            fine_tree,
            units,
        })
    }

    /// `path_commit = SHA-256(0x05 ‖ path_salt ‖ path_utf8)` (spec
    /// line 95). Paths themselves live in the vault, never here.
    #[must_use]
    pub const fn path_commit(&self) -> &CommitmentDigest {
        &self.path_commit
    }

    /// `raw_commit = SHA-256(0x03 ‖ file_salt ‖ raw_bytes)` (line 95).
    #[must_use]
    pub const fn raw_commit(&self) -> &CommitmentDigest {
        &self.raw_commit
    }

    /// Text-vs-binary mode, carrying the text-only fields.
    #[must_use]
    pub const fn canon(&self) -> &CanonMode {
        &self.canon
    }

    /// Leaf count / tiling-domain byte count: canonical bytes for text,
    /// raw bytes for binary (spec line 98). A text file's *raw* byte
    /// count travels as its raw-mirror unit's `true_length`.
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.size
    }

    /// Fine-tree state and root.
    #[must_use]
    pub const fn fine_tree(&self) -> FineTree {
        self.fine_tree
    }

    /// The unit table, in manifest order (always non-empty).
    #[must_use]
    pub fn units(&self) -> &[UnitEntry] {
        &self.units
    }

    /// The file's raw-mirror unit, if it has one.
    ///
    /// Located by `kind`, never by position: D23 fixes the mirror as the
    /// file's **last** unit as a seal-side construction rule, but the
    /// verifier must stay correct against hand-built manifests that
    /// ignore it (`docs/decisions/D23-raw-mirror-placement.md`,
    /// Consequences). At most one mirror exists per file (the mirror
    /// predicate is per-file), so the first match is the mirror.
    #[must_use]
    pub fn raw_mirror(&self) -> Option<&UnitEntry> {
        self.units.iter().find(|u| u.kind() == UnitKind::RawMirror)
    }

    /// The wire descriptor this entry encodes (registry §7.4), assembled
    /// from the already-consistent state.
    #[must_use]
    pub fn descriptor(&self) -> CanonDescriptor<'_> {
        let kind = self.canon.kind();
        CanonDescriptor {
            kind,
            fine_tree_present: self.fine_tree.is_present(),
            fine_tree_domain: self.fine_tree.is_present().then(|| kind.fine_tree_domain()),
            unicode_version: self.canon.unicode_version(),
        }
    }

    /// Decode one file entry, charging its `units` claim against the
    /// **work-global** [`DecodeBudget`] (F11 / decision D10).
    ///
    /// The budget is work-global rather than per-file so that "one file
    /// claiming 2^20 units" and "2^20 files claiming one unit each" hit the
    /// same cap with the same code — a per-file cap would let a hostile
    /// manifest multiply unit count by file count.
    fn decode(
        d: &mut CanonicalDecoder<'_>,
        budget: &mut DecodeBudget,
    ) -> Result<Self, ManifestError> {
        const MAP: MapId = MapId::FileEntry;
        let mut reader = d.map().map_err(body_layer)?;
        let mut path_commit: Option<CommitmentDigest> = None;
        let mut raw_commit: Option<CommitmentDigest> = None;
        let mut canon_commit: Option<CommitmentDigest> = None;
        let mut size: Option<u64> = None;
        let mut descriptor: Option<DescriptorParts> = None;
        let mut fine_root: Option<CommitmentDigest> = None;
        let mut units: Option<Vec<UnitEntry>> = None;

        while let Some(k) = reader.next_key(d).map_err(body_layer)? {
            admit_key(MAP, k)?;
            match k {
                key::file::PATH_COMMIT => {
                    let bytes = d.bytes().map_err(body_layer)?;
                    path_commit = Some(fixed(FixedLenField::PathCommit, bytes)?);
                }
                key::file::RAW_COMMIT => {
                    let bytes = d.bytes().map_err(body_layer)?;
                    raw_commit = Some(fixed(FixedLenField::RawCommit, bytes)?);
                }
                key::file::CANON_COMMIT => {
                    let bytes = d.bytes().map_err(body_layer)?;
                    canon_commit = Some(fixed(FixedLenField::CanonCommit, bytes)?);
                }
                key::file::SIZE => size = Some(d.u64().map_err(body_layer)?),
                key::file::DESCRIPTOR => descriptor = Some(DescriptorParts::decode(d)?),
                key::file::FINE_ROOT => {
                    let bytes = d.bytes().map_err(body_layer)?;
                    fine_root = Some(fixed(FixedLenField::FineRoot, bytes)?);
                }
                key::file::UNITS => {
                    // D10 §4 order: head canonicality, then the cap on the
                    // claimed count before any element is read, then the
                    // clamped allocation, then the elements.
                    let claimed = d.array().map_err(body_layer)?;
                    budget
                        .take_units(claimed)
                        .map_err(|()| ManifestError::ListTooLong {
                            list: ManifestListKind::Units,
                            claimed,
                            cap: MAX_UNIT_COUNT,
                        })?;
                    let mut list = Vec::with_capacity(clamped_capacity(claimed, d.remaining()));
                    for _ in 0..claimed {
                        list.push(UnitEntry::decode(d)?);
                    }
                    units = Some(list);
                }
                other => return Err(unhandled_assigned_key(MAP, other)),
            }
        }

        let descriptor = descriptor.ok_or(missing(MAP, key::file::DESCRIPTOR))?;

        // canon_commit: present iff text.
        let canon = match (descriptor.kind, canon_commit, descriptor.unicode_version) {
            (DescriptorKind::Text, Some(canon_commit), Some(unicode_version)) => CanonMode::Text {
                canon_commit,
                unicode_version,
            },
            (DescriptorKind::Text, None, _) => {
                return Err(ManifestError::MissingField {
                    field: CondField::CanonCommit,
                });
            }
            (DescriptorKind::Binary, Some(_), _) => {
                return Err(ManifestError::UnexpectedField {
                    field: CondField::CanonCommit,
                });
            }
            (DescriptorKind::Binary, None, _) => CanonMode::Binary,
            // Text without a Unicode version was already rejected inside
            // the descriptor; kept total without a panic path.
            (DescriptorKind::Text, Some(_), None) => {
                return Err(ManifestError::MissingField {
                    field: CondField::UnicodeVersion,
                });
            }
        };

        // fine_root: present iff the descriptor declares a fine tree.
        let fine_tree = match (descriptor.fine_tree_present, fine_root) {
            (true, Some(root)) => FineTree::Present { root },
            (true, None) => {
                return Err(ManifestError::MissingField {
                    field: CondField::FineRoot,
                });
            }
            (false, Some(_)) => {
                return Err(ManifestError::UnexpectedField {
                    field: CondField::FineRoot,
                });
            }
            (false, None) => FineTree::Absent,
        };

        Self::new(
            path_commit.ok_or(missing(MAP, key::file::PATH_COMMIT))?,
            raw_commit.ok_or(missing(MAP, key::file::RAW_COMMIT))?,
            canon,
            size.ok_or(missing(MAP, key::file::SIZE))?,
            fine_tree,
            units.ok_or(missing(MAP, key::file::UNITS))?,
        )
    }

    fn encode_into(&self, m: &mut MapEncoder) -> Result<(), EncodeError> {
        let descriptor = self.descriptor();
        m.entry(key::file::PATH_COMMIT, |e| e.bytes(&self.path_commit))?;
        m.entry(key::file::RAW_COMMIT, |e| e.bytes(&self.raw_commit))?;
        if let Some(commit) = self.canon.canon_commit() {
            m.entry(key::file::CANON_COMMIT, |e| e.bytes(commit))?;
        }
        m.entry(key::file::SIZE, |e| e.u64(self.size))?;
        m.entry(key::file::DESCRIPTOR, |e| {
            e.map(|dm| {
                dm.entry(key::descriptor::KIND, |e| {
                    e.u64(descriptor.kind().to_wire())
                })?;
                dm.entry(key::descriptor::FINE_TREE_PRESENT, |e| {
                    e.u64(self.fine_tree.wire_flag())
                })?;
                if let Some(domain) = descriptor.fine_tree_domain() {
                    dm.entry(key::descriptor::FINE_TREE_DOMAIN, |e| {
                        e.u64(domain.to_wire())
                    })?;
                }
                if let Some(version) = descriptor.unicode_version() {
                    dm.entry(key::descriptor::UNICODE_VERSION, |e| e.str(version))?;
                }
                Ok(())
            })
        })?;
        if let Some(root) = self.fine_tree.root() {
            m.entry(key::file::FINE_ROOT, |e| e.bytes(root))?;
        }
        m.entry(key::file::UNITS, |e| {
            e.array(|a| {
                for unit in &self.units {
                    a.item(|e| e.map(|um| unit.encode_into(um)))?;
                }
                Ok(())
            })
        })?;
        Ok(())
    }
}

/// Is this unit's content covered by its file's fine tree?
///
/// Raw-mirror units never are: they live in the raw byte domain that a
/// text file's canonical fine tree does not cover (MVP-SPEC.md lines 92,
/// 94), so they carry a `unit_commit` even when their file has a tree.
const fn is_covered(fine_tree: FineTree, kind: UnitKind) -> bool {
    match kind {
        UnitKind::RawMirror => false,
        UnitKind::Normal => fine_tree.is_present(),
    }
}

// ---------------------------------------------------------------------------
// the body (registry §7.2)
// ---------------------------------------------------------------------------

/// The v1 manifest body (MVP-SPEC.md line 98) — the bytes `work_id`
/// hashes and the author signatures cover.
///
/// `format_version` is not a field: this type *is* v1, so encode always
/// writes 1 and decode rejects anything else. A future v2 body is a
/// different Rust type reached through F10's version dispatch, which is
/// why the discriminant sits at key 0 and therefore first on the wire.
///
/// **Not `Clone`, on purpose.** [`Manifest`](super::Manifest) hands out
/// `&ManifestBodyV1`, and [`encode_body`] consumes its argument, so a
/// verifier holding a decoded manifest has no way to re-encode the body —
/// the "verifiers never re-encode" rule of spec line 74 is enforced by
/// the borrow checker rather than by documentation.
#[derive(Debug, PartialEq, Eq)]
pub struct ManifestBodyV1 {
    app_version: String,
    seal_id: SealId,
    title: String,
    claimed_time: u64,
    pubkeys: SigAlgMap,
    sig_policy: Vec<SigAlg>,
    files: Vec<FileEntry>,
}

impl ManifestBodyV1 {
    /// Assemble a body, running the whole-body validation — the same
    /// function [`Self::decode`] runs, so "constructible" and "decodable"
    /// are one predicate and a schema-invalid body cannot exist.
    ///
    /// # Errors
    ///
    /// - [`ManifestError::SigPolicyEmpty`] — empty `sig_policy` (spec
    ///   line 97: otherwise a signature-less manifest could verify
    ///   vacuously).
    /// - [`ManifestError::DuplicateAlg`] — a repeated `sig_policy` entry.
    /// - [`ManifestError::EmptyContainer`] — no files.
    /// - [`ManifestError::UnitIdMismatch`] — a unit's stored id is not
    ///   its manifest-order ordinal.
    pub fn new(
        app_version: String,
        seal_id: SealId,
        title: String,
        claimed_time: u64,
        pubkeys: SigAlgMap,
        sig_policy: Vec<SigAlg>,
        files: Vec<FileEntry>,
    ) -> Result<Self, ManifestError> {
        validate_sig_policy(&sig_policy)?;
        if files.is_empty() {
            return Err(ManifestError::EmptyContainer {
                field: ContainerField::Files,
            });
        }
        validate_unit_ordinals(&files)?;
        Ok(Self {
            app_version,
            seal_id,
            title,
            claimed_time,
            pubkeys,
            sig_policy,
            files,
        })
    }

    /// The format version this body declares on the wire — always
    /// [`FORMAT_VERSION_V1`].
    #[must_use]
    pub const fn format_version(&self) -> u64 {
        FORMAT_VERSION_V1
    }

    /// Producing build string. Informational only — never verdict-bearing
    /// (spec line 98).
    #[must_use]
    pub fn app_version(&self) -> &str {
        &self.app_version
    }

    /// The 16-byte `seal_id` (spec line 90): the AEAD AAD's manifest-
    /// independent half, which is what keeps the seal pipeline a DAG.
    #[must_use]
    pub const fn seal_id(&self) -> &SealId {
        &self.seal_id
    }

    /// The work title; may be empty (no `--title` ⇒ `""`, one shape).
    #[must_use]
    pub fn title(&self) -> &str {
        &self.title
    }

    /// Claimed time, POSIX seconds UTC. **Informational only** (spec
    /// line 98) — the provable times live in the anchors.
    #[must_use]
    pub const fn claimed_time(&self) -> u64 {
        self.claimed_time
    }

    /// The author public keys, keyed by algorithm.
    #[must_use]
    pub const fn pubkeys(&self) -> &SigAlgMap {
        &self.pubkeys
    }

    /// The ordered, non-empty, duplicate-free list of required signature
    /// algorithms (spec line 97). Order is the sealer's and is preserved
    /// byte-for-byte; the *set* is what C14/R5 compares against the
    /// present signatures.
    #[must_use]
    pub fn sig_policy(&self) -> &[SigAlg] {
        &self.sig_policy
    }

    /// The file table; index **is** `file_id` (spec line 76).
    #[must_use]
    pub fn files(&self) -> &[FileEntry] {
        &self.files
    }

    /// Total number of units across all files — the work-global id space
    /// `0..units_total()`.
    #[must_use]
    pub fn units_total(&self) -> u64 {
        self.files.iter().map(|f| f.units().len() as u64).sum()
    }

    /// Decode a manifest body **through F10's version dispatch**.
    ///
    /// The discriminant (registry §7.2 key 0) is read first, by
    /// [`crate::format::peek_format_version`], and the matching row of the
    /// `version -> decoder` table runs; a version with no row is
    /// [`ManifestError::UnsupportedFormatVersion`] and nothing else. Because
    /// the field sits inside the body `bstr`, this happens *after* the
    /// envelope decode — which is exactly why the envelope's
    /// `{0: body, 1: signatures}` shape is frozen across all versions
    /// (registry §7.1, §9).
    ///
    /// # Errors
    ///
    /// [`ManifestError::UnsupportedFormatVersion`] for a version this build
    /// has no decoder for; otherwise whatever the selected version's decoder
    /// returns — for v1, [`ManifestError::Body`] for canonicality failures
    /// (the F6 inner layer) and the `manifest-*` schema classes.
    pub fn decode(body_bytes: &[u8]) -> Result<Self, ManifestError> {
        VersionDispatch::v1_only(FORMAT_VERSION_V1, Self::decode_v1).decode(body_bytes)
    }

    /// Strict-decode a **v1** body from the exact bytes the envelope carried.
    ///
    /// Reachable only with a [`V1`] witness, i.e. only from version dispatch
    /// (F10) — so no future version can widen or otherwise disturb this
    /// path: a v2 body decoder takes a different witness and lives in its
    /// own module. That is the structural half of MVP-SPEC.md line 123.
    ///
    /// Every read goes through the F3 strict reader and every item is
    /// read *typed* — no subtree is skipped — so this pass subsumes
    /// [`crate::codec::check_canonical`]: canonicality and schema are
    /// established together, and `finish` rejects trailing bytes.
    fn decode_v1(input: V1<'_>) -> Result<Self, ManifestError> {
        const MAP: MapId = MapId::Body;
        let body_bytes = input.bytes();
        let mut d = CanonicalDecoder::new(body_bytes);
        let mut reader = d.map().map_err(body_layer)?;

        let mut format_version: Option<u64> = None;
        let mut app_version: Option<String> = None;
        let mut seal_id: Option<SealId> = None;
        let mut title: Option<String> = None;
        let mut claimed_time: Option<u64> = None;
        let mut pubkeys: Option<SigAlgMap> = None;
        let mut sig_policy: Option<Vec<SigAlg>> = None;
        let mut files: Option<Vec<FileEntry>> = None;
        // One budget per body decode: the unit cap is work-global (F11).
        let mut budget = DecodeBudget::new();

        while let Some(k) = reader.next_key(&mut d).map_err(body_layer)? {
            admit_key(MAP, k)?;
            match k {
                key::body::FORMAT_VERSION => {
                    let found = d.u64().map_err(body_layer)?;
                    // Dispatch already read this value and selected this
                    // decoder for it. Re-checking is the guard against the
                    // peek and the schema pass ever disagreeing about the
                    // first key — two parsers silently diverging is exactly
                    // the class of bug a permanent format cannot afford.
                    if found != FORMAT_VERSION_V1 {
                        return Err(ManifestError::UnsupportedFormatVersion {
                            found,
                            supported: SUPPORTED_VERSIONS,
                        });
                    }
                    format_version = Some(found);
                }
                key::body::APP_VERSION => {
                    app_version = Some(d.str().map_err(body_layer)?.to_owned());
                }
                key::body::SEAL_ID => {
                    let bytes = d.bytes().map_err(body_layer)?;
                    seal_id = Some(SealId::from_bytes(fixed(FixedLenField::SealId, bytes)?));
                }
                key::body::TITLE => title = Some(d.str().map_err(body_layer)?.to_owned()),
                key::body::CLAIMED_TIME => claimed_time = Some(d.u64().map_err(body_layer)?),
                key::body::PUBKEYS => {
                    pubkeys = Some(SigAlgMap::decode(&mut d, SigMaterial::Pubkey, body_layer)?);
                }
                key::body::SIG_POLICY => {
                    // A recorded **non-cap** (D10 §3): the registered
                    // `sig_alg` universe is `0..=15` and duplicates are
                    // rejected, so element 17 of a hostile array always fails
                    // on an existing code before any cap could fire. The
                    // clamp still applies — a cap and a clamp are different
                    // mechanisms, and only the clamp bounds allocation.
                    let claimed = d.array().map_err(body_layer)?;
                    let mut list = Vec::with_capacity(clamped_capacity(claimed, d.remaining()));
                    for _ in 0..claimed {
                        let alg_id = d.u64().map_err(body_layer)?;
                        list.push(sig_alg_from_wire(alg_id).ok_or(
                            ManifestError::UnregisteredAlg {
                                position: AlgPosition::SigPolicy,
                                alg_id,
                            },
                        )?);
                    }
                    sig_policy = Some(list);
                }
                key::body::FILES => {
                    let claimed = d.array().map_err(body_layer)?;
                    if claimed > MAX_FILE_COUNT {
                        return Err(ManifestError::ListTooLong {
                            list: ManifestListKind::Files,
                            claimed,
                            cap: MAX_FILE_COUNT,
                        });
                    }
                    let mut list = Vec::with_capacity(clamped_capacity(claimed, d.remaining()));
                    for _ in 0..claimed {
                        list.push(FileEntry::decode(&mut d, &mut budget)?);
                    }
                    files = Some(list);
                }
                other => return Err(unhandled_assigned_key(MAP, other)),
            }
        }
        d.finish().map_err(body_layer)?;

        // The discriminant itself must be present. An artifact with no
        // version field is *malformed*, not *unsupported* — F10 keeps the
        // two claims separate, so this stays `manifest-missing-key`.
        format_version.ok_or(missing(MAP, key::body::FORMAT_VERSION))?;

        Self::new(
            app_version.ok_or(missing(MAP, key::body::APP_VERSION))?,
            seal_id.ok_or(missing(MAP, key::body::SEAL_ID))?,
            title.ok_or(missing(MAP, key::body::TITLE))?,
            claimed_time.ok_or(missing(MAP, key::body::CLAIMED_TIME))?,
            pubkeys.ok_or(missing(MAP, key::body::PUBKEYS))?,
            sig_policy.ok_or(missing(MAP, key::body::SIG_POLICY))?,
            files.ok_or(missing(MAP, key::body::FILES))?,
        )
    }

    /// Emit the body's map entries into an open CBOR map scope.
    pub(super) fn encode_into(&self, m: &mut MapEncoder) -> Result<(), EncodeError> {
        m.entry(key::body::FORMAT_VERSION, |e| e.u64(FORMAT_VERSION_V1))?;
        m.entry(key::body::APP_VERSION, |e| e.str(&self.app_version))?;
        m.entry(key::body::SEAL_ID, |e| e.bytes(self.seal_id.as_bytes()))?;
        m.entry(key::body::TITLE, |e| e.str(&self.title))?;
        m.entry(key::body::CLAIMED_TIME, |e| e.u64(self.claimed_time))?;
        m.entry(key::body::PUBKEYS, |e| {
            e.map(|pm| self.pubkeys.encode_into(pm))
        })?;
        m.entry(key::body::SIG_POLICY, |e| {
            e.array(|a| {
                for alg in &self.sig_policy {
                    a.item(|e| e.u64(sig_alg_to_wire(*alg)))?;
                }
                Ok(())
            })
        })?;
        m.entry(key::body::FILES, |e| {
            e.array(|a| {
                for file in &self.files {
                    a.item(|e| e.map(|fm| file.encode_into(fm)))?;
                }
                Ok(())
            })
        })?;
        Ok(())
    }
}

/// `sig_policy` must be non-empty and duplicate-free; registration is
/// already guaranteed by the [`SigAlg`] type (an unregistered id cannot
/// survive [`sig_alg_from_wire`]).
fn validate_sig_policy(policy: &[SigAlg]) -> Result<(), ManifestError> {
    if policy.is_empty() {
        return Err(ManifestError::SigPolicyEmpty);
    }
    for (i, alg) in policy.iter().enumerate() {
        if policy[..i].contains(alg) {
            return Err(ManifestError::DuplicateAlg {
                position: AlgPosition::SigPolicy,
                alg_id: sig_alg_to_wire(*alg),
            });
        }
    }
    Ok(())
}

/// Every unit's stored `unit_id` equals its work-global ordinal: files in
/// manifest order, units in per-file order, counting from 0 with no gaps
/// (registry §7.5 key 0; decision D23 for the mirror's place in that
/// walk on the *seal* side).
fn validate_unit_ordinals(files: &[FileEntry]) -> Result<(), ManifestError> {
    let mut expected: u64 = 0;
    for file in files {
        for unit in file.units() {
            if unit.unit_id() != expected {
                return Err(ManifestError::UnitIdMismatch {
                    expected,
                    found: unit.unit_id(),
                });
            }
            // The counter cannot overflow before the input does: each
            // increment consumed at least one decoded map.
            expected = expected.saturating_add(1);
        }
    }
    Ok(())
}

/// Encode a validated body to its canonical CBOR bytes — the seal-side
/// entry point, and the **only** way to produce body bytes.
///
/// Consumes the body: a decoded [`Manifest`](super::Manifest) lends out
/// `&ManifestBodyV1` and the type is not `Clone`, so no verification path
/// can reach this function. Verifiers hash the bytes they received
/// ([`super::Manifest::body_bytes`]); they never re-encode (spec
/// line 74).
///
/// # Errors
///
/// [`EncodeError`] reports caller bugs the F2 layer detects (duplicate
/// map key, a scope that did not emit exactly one item, a rejecting
/// sink). None is reachable for a validated body — the keys are registry
/// constants and every scope emits one item — so this is a totality
/// `Err`, never a panic path.
pub fn encode_body(body: ManifestBodyV1) -> Result<Vec<u8>, EncodeError> {
    encode_item(|e| e.map(|m| body.encode_into(m)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::fixtures;

    /// F10's cross-parser guard: the v1 decoder re-checks the discriminant it
    /// was dispatched on, so if [`crate::format::peek_format_version`] and
    /// this schema pass ever disagreed about the first key, the artifact is
    /// rejected rather than silently decoded as v1.
    ///
    /// Only reachable by minting the witness directly — production code has
    /// no such constructor, which is the point.
    #[test]
    fn the_v1_decoder_rechecks_the_discriminant_dispatch_read() {
        // A body declaring v2, handed to the v1 decoder as if dispatch had
        // (wrongly) selected it.
        let body = encode_item(|e| {
            e.map(|m| {
                m.entry(key::body::FORMAT_VERSION, |e| e.u64(2))?;
                m.entry(key::body::APP_VERSION, |e| e.str("x"))
            })
        })
        .expect("encode");
        assert!(matches!(
            ManifestBodyV1::decode_v1(V1::admit_for_test(&body)),
            Err(ManifestError::UnsupportedFormatVersion { found: 2, .. })
        ));
    }

    #[test]
    fn byte_range_exposes_width_and_checked_end() {
        let r = ByteRange::new(10, 32);
        assert_eq!(r.start(), 10);
        assert_eq!(r.length(), 32);
        assert_eq!(r.end_exclusive(), Some(42));
        // The empty unit of an empty file (registry §4).
        assert_eq!(ByteRange::new(0, 0).end_exclusive(), Some(0));
        // Overflow is representable on the wire and is R's check, not a
        // parse error — the accessor refuses to wrap.
        assert_eq!(ByteRange::new(u64::MAX, 1).end_exclusive(), None);
    }

    #[test]
    fn descriptor_view_matches_the_stored_state() {
        let body = fixtures::text_with_mirror_body();
        let file = &body.files()[0];
        let descriptor = file.descriptor();
        assert_eq!(descriptor.kind(), DescriptorKind::Text);
        assert!(descriptor.fine_tree_present());
        assert_eq!(
            descriptor.fine_tree_domain(),
            Some(FineTreeDomain::Canonical)
        );
        assert_eq!(
            descriptor.unicode_version(),
            Some(fixtures::UNICODE_VERSION)
        );

        let binary = fixtures::binary_single_unit_body();
        let descriptor = binary.files()[0].descriptor();
        assert_eq!(descriptor.kind(), DescriptorKind::Binary);
        assert_eq!(descriptor.fine_tree_domain(), Some(FineTreeDomain::Raw));
        assert_eq!(descriptor.unicode_version(), None);
    }

    #[test]
    fn raw_mirror_is_found_by_kind_not_position() {
        let body = fixtures::text_with_mirror_body();
        let file = &body.files()[0];
        let mirror = file.raw_mirror().expect("fixture has a mirror");
        assert_eq!(mirror.kind(), UnitKind::RawMirror);
        // D23: the mirror is the file's last unit on the seal side.
        assert_eq!(
            mirror.unit_id(),
            file.units().last().expect("non-empty").unit_id()
        );
        // ...and a mirror is never fine-tree-covered, so it carries a
        // unit_commit even though its file has a fine tree.
        assert!(file.fine_tree().is_present());
        assert!(mirror.unit_commit().is_some());

        assert!(
            fixtures::binary_single_unit_body().files()[0]
                .raw_mirror()
                .is_none()
        );
    }

    #[test]
    fn unit_ordinals_are_work_global_across_files() {
        let body = fixtures::multi_file_split_body();
        let ids: Vec<u64> = body
            .files()
            .iter()
            .flat_map(|f| f.units().iter().map(UnitEntry::unit_id))
            .collect();
        let expected: Vec<u64> = (0..ids.len() as u64).collect();
        assert_eq!(ids, expected);
        assert_eq!(body.units_total(), ids.len() as u64);
    }
}
