//! Manifest schema-level error taxonomy (F5/F6) — one distinct variant
//! per rejection class, sized for the tamper matrix's distinct-error
//! requirement (MVP-SPEC.md line 168).
//!
//! # Where this sits
//!
//! Three layers reject three different things (see the module docs of
//! [`super`]). This taxonomy is the middle one: CBOR *canonicality*
//! failures stay [`DecodeError`]s and surface through the two wrapper
//! arms below; *semantic* failures over a well-formed body are R's
//! [`crate::verify::VerifyError`]. Accordingly every code minted here is
//! `manifest-`-prefixed, while the wrapper arms pass the codec's own
//! `cbor-*` codes through unchanged — those errors genuinely *are* the
//! codec layer's, merely re-labelled with the layer they occurred in.
//!
//! # Outer vs inner layer (F6)
//!
//! [`ManifestError::Envelope`] and [`ManifestError::Body`] wrap the same
//! [`DecodeError`] type but are distinct variants, so "the envelope is
//! not canonical" and "the embedded body is not canonical" never look
//! alike — the F6 requirement. The *code* is deliberately the wrapped
//! `cbor-*` code in both cases, matching the decision already recorded on
//! [`crate::verify::VerifyError::Codec`]: which layer was being decoded
//! is pipeline context, not a separate rejection class. Callers that need
//! it programmatically read [`ManifestError::layer`]; humans read the
//! `Display` prefix.
//!
//! # Secret hygiene (project rule 6)
//!
//! Payloads are key numbers, byte lengths, ids, and closed enum
//! discriminants — **never field content**. Manifest bodies are not
//! secret, but they are adversary-supplied and travel through the same
//! rendering paths as bundle errors, so the same discipline applies and
//! is asserted by `display_renders_metadata_only`.

use core::fmt;

use thiserror::Error;

use crate::codec::DecodeError;
use crate::crypto::error::SigAlg;

use super::registry::MapId;

/// Which decode layer a wrapped [`DecodeError`] came from (F6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Layer {
    /// The outer manifest envelope `{body, signatures}`.
    Envelope,
    /// The embedded body byte string's own contents.
    Body,
}

impl fmt::Display for Layer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Envelope => "manifest envelope",
            Self::Body => "manifest body",
        })
    }
}

/// A wire field whose byte length is fixed by the registry (§2) and
/// checked at parse. One code per class, so "wrong-length nonce" and
/// "wrong-length address" are different tamper rows even though both are
/// 32-vs-24 slips in the same unit entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FixedLenField {
    /// Body `seal_id`, 16 B (MVP-SPEC.md line 90).
    SealId,
    /// File `path_commit`, 32 B.
    PathCommit,
    /// File `raw_commit`, 32 B.
    RawCommit,
    /// File `canon_commit`, 32 B.
    CanonCommit,
    /// Unit `unit_commit`, 32 B.
    UnitCommit,
    /// File `fine_root`, 32 B.
    FineRoot,
    /// Unit `nonce`, 24 B.
    Nonce,
    /// Unit ciphertext `address`, 32 B (decision D11).
    Address,
    /// A `pubkeys` entry, length fixed by its algorithm.
    Pubkey(SigAlg),
    /// A `signatures` entry, length fixed by its algorithm.
    Signature(SigAlg),
}

impl FixedLenField {
    /// Every class, for exhaustive tests.
    pub const ALL: [Self; 12] = [
        Self::SealId,
        Self::PathCommit,
        Self::RawCommit,
        Self::CanonCommit,
        Self::UnitCommit,
        Self::FineRoot,
        Self::Nonce,
        Self::Address,
        Self::Pubkey(SigAlg::Ed25519),
        Self::Pubkey(SigAlg::MlDsa65),
        Self::Signature(SigAlg::Ed25519),
        Self::Signature(SigAlg::MlDsa65),
    ];
}

impl fmt::Display for FixedLenField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SealId => f.write_str("seal_id"),
            Self::PathCommit => f.write_str("path_commit"),
            Self::RawCommit => f.write_str("raw_commit"),
            Self::CanonCommit => f.write_str("canon_commit"),
            Self::UnitCommit => f.write_str("unit_commit"),
            Self::FineRoot => f.write_str("fine_root"),
            Self::Nonce => f.write_str("nonce"),
            Self::Address => f.write_str("address"),
            Self::Pubkey(alg) => write!(f, "{alg} public key"),
            Self::Signature(alg) => write!(f, "{alg} signature"),
        }
    }
}

/// A field whose presence is governed by an iff-rule — the conditional
/// half of the schema (MVP-SPEC.md lines 94, 98; registry §§7.3–7.5).
///
/// Each field yields **two** codes, one per direction: present when the
/// rule forbids it ([`ManifestError::UnexpectedField`]) and absent when
/// the rule requires it ([`ManifestError::MissingField`]). The F5 accept
/// list needs both directions distinguishable for `unit_commit`, and the
/// same discipline is applied to every conditional field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CondField {
    /// File `canon_commit` — present iff the descriptor says text.
    CanonCommit,
    /// File `fine_root` — present iff the descriptor has a fine tree.
    FineRoot,
    /// Descriptor `fine_tree_domain` — present iff `fine_tree_present`.
    FineTreeDomain,
    /// Descriptor `unicode_version` — present iff the file is text.
    UnicodeVersion,
    /// Unit `unit_commit` — present iff the unit is **not**
    /// fine-tree-covered, i.e. iff it is a raw mirror or its file has no
    /// fine tree (MVP-SPEC.md line 94: a covered unit is bound *solely*
    /// by `fine_root`, so a second commitment over the same bytes would
    /// reopen sealer equivocation).
    UnitCommit,
}

impl CondField {
    /// Every conditional field, for exhaustive tests.
    pub const ALL: [Self; 5] = [
        Self::CanonCommit,
        Self::FineRoot,
        Self::FineTreeDomain,
        Self::UnicodeVersion,
        Self::UnitCommit,
    ];

    /// The condition under which the field MUST be present.
    const fn present_when(self) -> &'static str {
        match self {
            Self::CanonCommit | Self::UnicodeVersion => "the file is text",
            Self::FineRoot | Self::FineTreeDomain => "the file has a fine tree",
            Self::UnitCommit => "the unit is not fine-tree-covered",
        }
    }

    /// The complementary condition, under which it MUST be absent.
    const fn absent_when(self) -> &'static str {
        match self {
            Self::CanonCommit | Self::UnicodeVersion => "the file is binary",
            Self::FineRoot | Self::FineTreeDomain => "the file has no fine tree",
            Self::UnitCommit => "the unit is fine-tree-covered",
        }
    }
}

impl fmt::Display for CondField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::CanonCommit => "canon_commit",
            Self::FineRoot => "fine_root",
            Self::FineTreeDomain => "fine_tree_domain",
            Self::UnicodeVersion => "unicode_version",
            Self::UnitCommit => "unit_commit",
        })
    }
}

/// A container the schema requires to be non-empty (registry §§7.2–7.5).
///
/// `sig_policy` is deliberately **not** here: its emptiness is the
/// spec's own named rejection (line 97) and keeps its own variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ContainerField {
    /// Body `files` — a work is one or more files (spec line 83).
    Files,
    /// File `units` — an empty file still has one empty unit (line 78).
    Units,
    /// Body `pubkeys`.
    Pubkeys,
    /// Envelope `signatures`.
    Signatures,
    /// A file's `kind = normal` units — a file must have at least one unit
    /// in its tiling domain (**D77**). Raw mirrors are tiling-exempt by kind
    /// (spec line 92), so a mirror-only file has no tiling domain at all and
    /// its `canon_commit`/`raw_commit` would be permanently unopenable: with
    /// `N(F) = ∅`, D28's `full(F)` is false for every bundle forever, which
    /// is verbatim the condition D28 exists to remove.
    NormalUnits,
}

impl ContainerField {
    /// Every container, for exhaustive tests.
    pub const ALL: [Self; 5] = [
        Self::Files,
        Self::Units,
        Self::Pubkeys,
        Self::Signatures,
        Self::NormalUnits,
    ];
}

impl fmt::Display for ContainerField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Files => "files",
            Self::Units => "units",
            Self::Pubkeys => "pubkeys",
            Self::Signatures => "signatures",
            Self::NormalUnits => "normal units",
        })
    }
}

/// A manifest list with a **frozen length cap** (decision D10, registry §11).
///
/// Only two lists are capped. The others are recorded non-caps (D10 §3):
/// `sig_policy`, `pubkeys` and `signatures` are bounded instead by the
/// 16-value registered `sig_alg` universe *and* by duplicate-freedom, so an
/// existing code fires before any cap could; `range` has fixed arity; and
/// `title`/`app_version` are free-form `tstr`s with no principled maximum,
/// transitively bounded by [`MAX_MANIFEST_BYTES`](crate::codec::caps::MAX_MANIFEST_BYTES).
/// The clamp rule still applies to every one of them — a cap and a clamp are
/// different mechanisms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ManifestListKind {
    /// Body key 7 `files`.
    Files,
    /// A file's key 6 `units` — charged against a **work-global** budget
    /// ([`DecodeBudget`](crate::codec::caps::DecodeBudget)), not a per-file
    /// one, so "one file claiming 2^20 units" and "2^20 files claiming one
    /// unit each" hit the same cap with the same code.
    Units,
}

impl ManifestListKind {
    /// Every capped list, for exhaustive tests.
    pub const ALL: [Self; 2] = [Self::Files, Self::Units];

    /// The frozen maximum element count (decision D10 §1).
    #[must_use]
    pub const fn cap(self) -> u64 {
        use crate::codec::caps;
        match self {
            Self::Files => caps::MAX_FILE_COUNT,
            Self::Units => caps::MAX_UNIT_COUNT,
        }
    }
}

impl fmt::Display for ManifestListKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Files => "files",
            Self::Units => "units",
        })
    }
}

/// Which closed wire enum rejected a value (registry §6.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EnumId {
    /// `descriptor_kind` — 0 binary, 1 text.
    DescriptorKind,
    /// `fine_tree_domain` — 0 raw, 1 canonical.
    FineTreeDomain,
    /// `unit_kind` — 0 normal, 1 raw-mirror.
    UnitKind,
    /// `fine_tree_present` — the 0/1 uint that stands in for a boolean
    /// (registry §1 rule 1: v1 has no simple values). Anything else is
    /// rejected rather than read as truthy.
    FineTreeFlag,
}

impl EnumId {
    /// Every closed enum, for exhaustive tests.
    pub const ALL: [Self; 4] = [
        Self::DescriptorKind,
        Self::FineTreeDomain,
        Self::UnitKind,
        Self::FineTreeFlag,
    ];
}

impl fmt::Display for EnumId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::DescriptorKind => "descriptor_kind",
            Self::FineTreeDomain => "fine_tree_domain",
            Self::UnitKind => "unit_kind",
            Self::FineTreeFlag => "fine_tree_present",
        })
    }
}

/// Where an unregistered `sig_alg` id appeared. Three positions, three
/// codes: spec line 97 rejects an unregistered id in **any** of them, and
/// keeping them distinct means the tamper matrix can tell "policy names a
/// ghost algorithm" from "a signature arrived for one".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AlgPosition {
    /// An element of the body's `sig_policy` list.
    SigPolicy,
    /// A key of the body's `pubkeys` map.
    Pubkeys,
    /// A key of the envelope's `signatures` map.
    Signatures,
}

impl AlgPosition {
    /// Every position, for exhaustive tests.
    pub const ALL: [Self; 3] = [Self::SigPolicy, Self::Pubkeys, Self::Signatures];
}

impl fmt::Display for AlgPosition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::SigPolicy => "sig_policy",
            Self::Pubkeys => "pubkeys",
            Self::Signatures => "signatures",
        })
    }
}

/// Every manifest schema failure class, one distinct variant each.
///
/// `#[non_exhaustive]`: additive schema rejections must not break
/// downstream matches (the CryptoError precedent). Inside this crate the
/// matches stay exhaustive, so [`Self::code`] remains the compile-time
/// guard that every new variant receives a distinct stable code.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum ManifestError {
    // ── Layer-tagged codec wrappers (F6) ────────────────────────────
    /// The outer envelope bytes failed the strict canonical CBOR layer.
    #[error("manifest envelope: {source}")]
    Envelope {
        /// The codec-layer rejection, positions relative to the envelope.
        #[source]
        source: DecodeError,
    },

    /// The embedded body bytes failed the strict canonical CBOR layer.
    /// Positions are relative to the **body** slice, never to the
    /// envelope — the two layers are decoded independently, which is why
    /// verifiers never need to re-encode (spec line 74).
    #[error("manifest body: {source}")]
    Body {
        /// The codec-layer rejection, positions relative to the body.
        #[source]
        source: DecodeError,
    },

    // ── Key space (registry §1 rule 4) ──────────────────────────────
    /// A map key outside every v1 band (`>= 24`) — never reserved, never
    /// assignable. For the manifest envelope, whose shape is frozen
    /// forever, *any* key besides 0/1 lands here.
    #[error("{map}: unknown map key {key}")]
    UnknownKey {
        /// The map that rejected the key.
        map: MapId,
        /// The offending key.
        key: u64,
    },

    /// An unassigned key inside the `0..=23` band: reserved for a future
    /// v1.x field, so its presence means a newer producer met an older
    /// verifier — distinct from [`Self::UnknownKey`] on purpose.
    #[error("{map}: map key {key} is reserved for a future v1.x field")]
    ReservedKey {
        /// The map that rejected the key.
        map: MapId,
        /// The offending key.
        key: u64,
    },

    /// A key the schema requires is absent.
    #[error("{map}: required map key {key} is missing")]
    MissingKey {
        /// The map with the hole.
        map: MapId,
        /// The required key.
        key: u64,
    },

    // ── Shape ───────────────────────────────────────────────────────
    /// A fixed-length `bstr` field has the wrong byte length.
    #[error("{field} has invalid length: expected {expected} bytes, got {got}")]
    WrongLength {
        /// Which field was mis-sized.
        field: FixedLenField,
        /// The registry-mandated length.
        expected: u64,
        /// The length actually present.
        got: u64,
    },

    /// A conditional field is present where its rule forbids it.
    #[error("{field} must be absent when {cond}", cond = field.absent_when())]
    UnexpectedField {
        /// The offending field.
        field: CondField,
    },

    /// A conditional field is absent where its rule requires it.
    #[error("{field} must be present when {cond}", cond = field.present_when())]
    MissingField {
        /// The missing field.
        field: CondField,
    },

    /// A container the schema requires to be non-empty is empty.
    #[error("{field} must not be empty")]
    EmptyContainer {
        /// Which container.
        field: ContainerField,
    },

    // ── Resource caps (decision D10, registry §11) ──────────────────
    /// The manifest envelope input exceeds
    /// [`MAX_MANIFEST_BYTES`](crate::codec::caps::MAX_MANIFEST_BYTES).
    ///
    /// Raised as the **first statement** of the envelope decode, before the
    /// decoder is constructed, so it precedes every canonicality and schema
    /// code and bounds the SHA-256 work behind `work_id`/`anchor_digest`
    /// (D10 §5). The **body** needs no separate cap: it is a `bstr` inside
    /// the envelope, so `len(body) < len(envelope)` by construction.
    #[error("manifest input of {len} bytes exceeds the {cap}-byte limit")]
    InputTooLarge {
        /// The input length actually offered.
        len: u64,
        /// The frozen cap.
        cap: u64,
    },

    /// A capped manifest list claims more elements than its cap allows.
    ///
    /// Checked on the **claimed count at the array head**, before a single
    /// element is read. For `units` the claim is charged against the
    /// work-global [`DecodeBudget`](crate::codec::caps::DecodeBudget), so
    /// `claimed` is this file's claim while `cap` is always the work-global
    /// constant — never the residue, so the reported error never depends on
    /// how far through the file list the decoder had got.
    #[error("{list} claims {claimed} entries, exceeding the limit of {cap}")]
    ListTooLong {
        /// Which list overflowed.
        list: ManifestListKind,
        /// The element count claimed.
        claimed: u64,
        /// The frozen cap.
        cap: u64,
    },

    /// A closed enum received an unregistered value.
    #[error("{enumeration}: unregistered value {value}")]
    UnknownEnumValue {
        /// Which enum rejected it.
        enumeration: EnumId,
        /// The unregistered value.
        value: u64,
    },

    /// A `byte_range` tuple is not the 2-element `[start, length]` array
    /// of registry §4.
    #[error("byte range must be a 2-element [start, length] array, got {got} element(s)")]
    WrongRangeArity {
        /// Element count actually present.
        got: u64,
    },

    /// The descriptor's `fine_tree_domain` contradicts its `kind`: a
    /// binary file's tree covers raw bytes and a text file's covers the
    /// canonical rendition (MVP-SPEC.md lines 83–84). Both are recorded
    /// on the wire, so the pair has to agree.
    #[error("descriptor kind {kind} implies fine-tree domain {implied}, but {found} is recorded")]
    DescriptorDomainMismatch {
        /// The recorded `kind`.
        kind: super::registry::DescriptorKind,
        /// The domain that `kind` implies.
        implied: super::registry::FineTreeDomain,
        /// The domain actually recorded.
        found: super::registry::FineTreeDomain,
    },

    // ── Version ─────────────────────────────────────────────────────
    /// The body declares a `format_version` with no decoder in this build
    /// (F10). Raised by `crate::format`'s version dispatch **before** any
    /// schema decode, so a newer-than-this-verifier manifest is never
    /// reported as corrupt: it is neither a canonicality error nor an
    /// unknown-key error, which is the whole point of the class.
    ///
    /// Per the line-123 stability contract a released version is decodable
    /// forever, so this can only ever mean "this artifact is newer than
    /// this build" — never "that version was dropped".
    #[error(
        "unsupported manifest format_version {found}; this build decodes {}",
        crate::format::supported_versions_str(supported)
    )]
    UnsupportedFormatVersion {
        /// The version the body declares.
        found: u64,
        /// Every version this build *can* decode
        /// ([`crate::format::SUPPORTED_VERSIONS`]) — carried as data so a
        /// caller can render an actionable "upgrade to a build that
        /// supports v{found}" message without reaching into the crate.
        supported: &'static [u64],
    },

    // ── sig_policy (MVP-SPEC.md line 97) ────────────────────────────
    /// `sig_policy` is empty — rejected at parse so a signature-less
    /// manifest can never verify vacuously.
    #[error("sig_policy is empty")]
    SigPolicyEmpty,

    /// The same algorithm appears twice in one position. In `sig_policy`
    /// this is spec line 97's duplicate rule — left undetected, a
    /// first-wins and a last-wins reader could disagree about the
    /// security level of one anchored `work_id` (spec line 73). In the
    /// `pubkeys`/`signatures` maps it is unreachable from the wire (map
    /// keys ascend strictly, so a repeat is `cbor-duplicate-map-key`) and
    /// guards the in-memory constructors instead.
    #[error("{position} lists algorithm id {alg_id} more than once")]
    DuplicateAlg {
        /// Where the repeat occurred.
        position: AlgPosition,
        /// The repeated wire id.
        alg_id: u64,
    },

    /// An unregistered `sig_alg` id appeared in `sig_policy`, `pubkeys`,
    /// or `signatures` (registry §6.2: `2..=15` reserved, unregistered in
    /// v1).
    #[error("{position}: unregistered signature algorithm id {alg_id}")]
    UnregisteredAlg {
        /// Where the id appeared.
        position: AlgPosition,
        /// The unregistered wire id.
        alg_id: u64,
    },

    // ── Cross-entry structure ───────────────────────────────────────
    /// A unit's stored `unit_id` is not its manifest-order ordinal
    /// (registry §7.5 key 0). The field is stored *and* checked, so
    /// reveal ids are self-describing and a silent reordering — which
    /// would re-map every per-unit key, salt, and AAD — is
    /// unrepresentable.
    #[error("unit_id {found} does not match its manifest-order ordinal {expected}")]
    UnitIdMismatch {
        /// The ordinal derived by walking files then units in order.
        expected: u64,
        /// The id the entry stores.
        found: u64,
    },
}

impl ManifestError {
    /// Which decode layer a wrapped codec error came from, or `None` for
    /// a schema-level rejection (whose own payload names its map).
    #[must_use]
    pub const fn layer(&self) -> Option<Layer> {
        match self {
            Self::Envelope { .. } => Some(Layer::Envelope),
            Self::Body { .. } => Some(Layer::Body),
            _ => None,
        }
    }

    /// Stable machine-readable code, pairwise-distinct across every
    /// (variant, discriminant) pair — the F-side leg of Q7's error-code
    /// stability contract, alongside the codec's `cbor-*` and crypto's
    /// `crypto-*` codes. Lowercase kebab-case, `manifest-`-prefixed;
    /// never changes once a tamper row binds to it.
    ///
    /// The two wrapper arms are the deliberate exception: they surface
    /// the wrapped [`DecodeError::code`] unchanged, because those
    /// failures genuinely *are* the codec layer's rejection classes and
    /// re-prefixing them would fork one taxonomy into three. The layer is
    /// available separately via [`Self::layer`] (the decision recorded on
    /// [`crate::verify::VerifyError::Codec`]: layer is pipeline context,
    /// not a rejection class).
    ///
    /// The exhaustive, variant-wildcard-free match is the compile-time
    /// guard: a new variant — or a new [`FixedLenField`]/[`CondField`]/
    /// [`ContainerField`]/[`EnumId`]/[`AlgPosition`]/[`ManifestListKind`]
    /// discriminant — fails compilation here until it receives a distinct
    /// code and an exemplar in `all_code_exemplars`.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Envelope { source } | Self::Body { source } => source.code(),
            Self::UnknownKey { .. } => "manifest-unknown-key",
            Self::ReservedKey { .. } => "manifest-reserved-key",
            Self::MissingKey { .. } => "manifest-missing-key",
            Self::WrongLength { field, .. } => match field {
                FixedLenField::SealId => "manifest-wrong-length-seal-id",
                FixedLenField::PathCommit => "manifest-wrong-length-path-commit",
                FixedLenField::RawCommit => "manifest-wrong-length-raw-commit",
                FixedLenField::CanonCommit => "manifest-wrong-length-canon-commit",
                FixedLenField::UnitCommit => "manifest-wrong-length-unit-commit",
                FixedLenField::FineRoot => "manifest-wrong-length-fine-root",
                FixedLenField::Nonce => "manifest-wrong-length-nonce",
                FixedLenField::Address => "manifest-wrong-length-address",
                FixedLenField::Pubkey(SigAlg::Ed25519) => "manifest-wrong-length-pubkey-ed25519",
                FixedLenField::Pubkey(SigAlg::MlDsa65) => "manifest-wrong-length-pubkey-ml-dsa-65",
                FixedLenField::Signature(SigAlg::Ed25519) => {
                    "manifest-wrong-length-signature-ed25519"
                }
                FixedLenField::Signature(SigAlg::MlDsa65) => {
                    "manifest-wrong-length-signature-ml-dsa-65"
                }
            },
            Self::UnexpectedField { field } => match field {
                CondField::CanonCommit => "manifest-unexpected-canon-commit",
                CondField::FineRoot => "manifest-unexpected-fine-root",
                CondField::FineTreeDomain => "manifest-unexpected-fine-tree-domain",
                CondField::UnicodeVersion => "manifest-unexpected-unicode-version",
                CondField::UnitCommit => "manifest-unexpected-unit-commit",
            },
            Self::MissingField { field } => match field {
                CondField::CanonCommit => "manifest-missing-canon-commit",
                CondField::FineRoot => "manifest-missing-fine-root",
                CondField::FineTreeDomain => "manifest-missing-fine-tree-domain",
                CondField::UnicodeVersion => "manifest-missing-unicode-version",
                CondField::UnitCommit => "manifest-missing-unit-commit",
            },
            Self::EmptyContainer { field } => match field {
                ContainerField::Files => "manifest-empty-files",
                ContainerField::Units => "manifest-empty-units",
                ContainerField::Pubkeys => "manifest-empty-pubkeys",
                ContainerField::Signatures => "manifest-empty-signatures",
                ContainerField::NormalUnits => "manifest-empty-normal-units",
            },
            Self::InputTooLarge { .. } => "manifest-too-large",
            Self::ListTooLong { list, .. } => match list {
                ManifestListKind::Files => "manifest-too-many-files",
                ManifestListKind::Units => "manifest-too-many-units",
            },
            Self::UnknownEnumValue { enumeration, .. } => match enumeration {
                EnumId::DescriptorKind => "manifest-unknown-descriptor-kind",
                EnumId::FineTreeDomain => "manifest-unknown-fine-tree-domain",
                EnumId::UnitKind => "manifest-unknown-unit-kind",
                EnumId::FineTreeFlag => "manifest-unknown-fine-tree-flag",
            },
            Self::WrongRangeArity { .. } => "manifest-wrong-range-arity",
            Self::DescriptorDomainMismatch { .. } => "manifest-descriptor-domain-mismatch",
            Self::UnsupportedFormatVersion { .. } => "manifest-unsupported-format-version",
            Self::SigPolicyEmpty => "manifest-sig-policy-empty",
            Self::DuplicateAlg { position, .. } => match position {
                AlgPosition::SigPolicy => "manifest-duplicate-alg-sig-policy",
                AlgPosition::Pubkeys => "manifest-duplicate-alg-pubkeys",
                AlgPosition::Signatures => "manifest-duplicate-alg-signatures",
            },
            Self::UnregisteredAlg { position, .. } => match position {
                AlgPosition::SigPolicy => "manifest-unregistered-alg-sig-policy",
                AlgPosition::Pubkeys => "manifest-unregistered-alg-pubkeys",
                AlgPosition::Signatures => "manifest-unregistered-alg-signatures",
            },
            Self::UnitIdMismatch { .. } => "manifest-unit-id-mismatch",
        }
    }
}

/// F10: the manifest family's unsupported-version rejection, so
/// `crate::format`'s version dispatch can raise it without knowing anything
/// about the manifest schema.
impl crate::format::VersionRejection for ManifestError {
    fn unsupported_version(found: u64, supported: &'static [u64]) -> Self {
        Self::UnsupportedFormatVersion { found, supported }
    }
}

/// One exemplar per distinct schema-level [`ManifestError::code`] — every
/// (variant, discriminant) pair exactly once, with pairwise-distinct
/// `Display` renderings.
///
/// The two codec wrapper arms are excluded by design: their codes are the
/// codec's own 15 `cbor-*` values, already exemplified (and asserted
/// pairwise-distinct) by `codec::decode` and by `verify::error`'s
/// meta-test. Including them here would assert distinctness of the *same*
/// code twice — once per layer — and fail, which is precisely the
/// recorded "layer is not a rejection class" decision.
#[cfg(test)]
pub(crate) fn all_code_exemplars() -> Vec<ManifestError> {
    use ManifestError as E;
    let mut exemplars = Vec::new();
    // One code per key-space class, not per map: the map is payload
    // (registry §1 rule 4 speaks of *the* unknown-key and *the*
    // reserved-slot error, each naming its key), so a single exemplar per
    // class is the whole code space.
    exemplars.extend([
        E::UnknownKey {
            map: MapId::Envelope,
            key: 24,
        },
        E::ReservedKey {
            map: MapId::Body,
            key: 8,
        },
        E::MissingKey {
            map: MapId::UnitEntry,
            key: 5,
        },
    ]);
    for (i, field) in FixedLenField::ALL.into_iter().enumerate() {
        exemplars.push(E::WrongLength {
            field,
            expected: 32,
            got: i as u64,
        });
    }
    for field in CondField::ALL {
        exemplars.push(E::UnexpectedField { field });
        exemplars.push(E::MissingField { field });
    }
    for field in ContainerField::ALL {
        exemplars.push(E::EmptyContainer { field });
    }
    for (i, enumeration) in EnumId::ALL.into_iter().enumerate() {
        exemplars.push(E::UnknownEnumValue {
            enumeration,
            value: 100 + i as u64,
        });
    }
    for (i, position) in AlgPosition::ALL.into_iter().enumerate() {
        exemplars.push(E::UnregisteredAlg {
            position,
            alg_id: 7 + i as u64,
        });
        exemplars.push(E::DuplicateAlg {
            position,
            alg_id: i as u64,
        });
    }
    for list in ManifestListKind::ALL {
        let cap = list.cap();
        exemplars.push(E::ListTooLong {
            list,
            claimed: cap + 1,
            cap,
        });
    }
    exemplars.extend([
        E::InputTooLarge {
            len: crate::codec::caps::MAX_MANIFEST_BYTES + 1,
            cap: crate::codec::caps::MAX_MANIFEST_BYTES,
        },
        E::WrongRangeArity { got: 3 },
        E::DescriptorDomainMismatch {
            kind: super::registry::DescriptorKind::Binary,
            implied: super::registry::FineTreeDomain::Raw,
            found: super::registry::FineTreeDomain::Canonical,
        },
        E::UnsupportedFormatVersion {
            found: 2,
            supported: crate::format::SUPPORTED_VERSIONS,
        },
        E::SigPolicyEmpty,
        E::UnitIdMismatch {
            expected: 4,
            found: 9,
        },
    ]);
    exemplars
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::error::Error as _;

    /// The domain distinctness meta-test (the C4/F3 pattern): every
    /// schema-level code is `manifest-`-prefixed lowercase kebab-case,
    /// pairwise distinct, and paired with a pairwise-distinct `Display`.
    #[test]
    fn codes_are_pairwise_distinct_and_prefixed() {
        let exemplars = all_code_exemplars();
        assert_eq!(
            exemplars.len(),
            48,
            "one exemplar per distinct code — update deliberately"
        );

        let codes: BTreeSet<&'static str> = exemplars.iter().map(ManifestError::code).collect();
        assert_eq!(codes.len(), exemplars.len(), "codes pairwise distinct");
        for code in &codes {
            assert!(
                code.starts_with("manifest-"),
                "code {code:?} must carry the domain prefix"
            );
            assert!(
                code.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'),
                "code {code:?} is not lowercase kebab-case"
            );
        }

        let displays: BTreeSet<String> = exemplars.iter().map(ToString::to_string).collect();
        assert_eq!(
            displays.len(),
            exemplars.len(),
            "displays pairwise distinct"
        );
    }

    /// The banned prefixes: schema errors never borrow another domain's
    /// namespace (the brief's error-code rule).
    #[test]
    fn codes_avoid_other_domains_prefixes() {
        for err in all_code_exemplars() {
            let code = err.code();
            for banned in ["crypto-", "cbor-", "content-", "verify-"] {
                assert!(
                    !code.starts_with(banned),
                    "code {code:?} collides with the {banned} domain"
                );
            }
        }
    }

    /// Every schema variant reachable from the code list — no variant can
    /// miss a code (mirrors the C4 guard).
    #[test]
    fn every_schema_variant_has_an_exemplar() {
        use core::mem::discriminant;
        let exemplars = all_code_exemplars();
        let one_of_each = [
            ManifestError::UnknownKey {
                map: MapId::Body,
                key: 24,
            },
            ManifestError::ReservedKey {
                map: MapId::Body,
                key: 8,
            },
            ManifestError::MissingKey {
                map: MapId::Body,
                key: 0,
            },
            ManifestError::WrongLength {
                field: FixedLenField::SealId,
                expected: 16,
                got: 15,
            },
            ManifestError::UnexpectedField {
                field: CondField::UnitCommit,
            },
            ManifestError::MissingField {
                field: CondField::UnitCommit,
            },
            ManifestError::EmptyContainer {
                field: ContainerField::Files,
            },
            ManifestError::UnknownEnumValue {
                enumeration: EnumId::UnitKind,
                value: 2,
            },
            ManifestError::InputTooLarge { len: 1, cap: 0 },
            ManifestError::ListTooLong {
                list: ManifestListKind::Files,
                claimed: 1,
                cap: 0,
            },
            ManifestError::WrongRangeArity { got: 3 },
            ManifestError::DescriptorDomainMismatch {
                kind: super::super::registry::DescriptorKind::Text,
                implied: super::super::registry::FineTreeDomain::Canonical,
                found: super::super::registry::FineTreeDomain::Raw,
            },
            ManifestError::UnsupportedFormatVersion {
                found: 2,
                supported: crate::format::SUPPORTED_VERSIONS,
            },
            ManifestError::SigPolicyEmpty,
            ManifestError::DuplicateAlg {
                position: AlgPosition::SigPolicy,
                alg_id: 0,
            },
            ManifestError::UnregisteredAlg {
                position: AlgPosition::SigPolicy,
                alg_id: 9,
            },
            ManifestError::UnitIdMismatch {
                expected: 1,
                found: 2,
            },
        ];
        for variant in one_of_each {
            assert!(
                exemplars
                    .iter()
                    .any(|e| discriminant(e) == discriminant(&variant)),
                "{variant:?} missing from all_code_exemplars"
            );
        }
    }

    /// The two codec wrapper arms surface the wrapped `cbor-*` code
    /// unchanged and stay distinguishable by variant and by `Display`
    /// even when the wrapped error is identical (the F6 requirement).
    #[test]
    fn wrapper_arms_delegate_codes_but_stay_distinguishable() {
        let inner = DecodeError::NonShortestInt { position: 7 };
        let outer_err = ManifestError::Envelope {
            source: inner.clone(),
        };
        let inner_err = ManifestError::Body {
            source: inner.clone(),
        };

        assert_eq!(outer_err.code(), inner.code());
        assert_eq!(inner_err.code(), inner.code());
        assert_eq!(outer_err.code(), "cbor-non-shortest-int");

        assert_ne!(outer_err, inner_err, "the two layers are distinct values");
        assert_ne!(
            outer_err.to_string(),
            inner_err.to_string(),
            "the two layers render differently"
        );
        assert_eq!(outer_err.layer(), Some(Layer::Envelope));
        assert_eq!(inner_err.layer(), Some(Layer::Body));
        assert_eq!(ManifestError::SigPolicyEmpty.layer(), None);

        // The wrapped error remains reachable as an `Error::source`, so
        // callers can inspect the codec position without string parsing.
        assert!(outer_err.source().is_some());
        assert!(ManifestError::SigPolicyEmpty.source().is_none());
    }

    /// Project rule 6: `Display` renders sanctioned metadata only — key
    /// numbers, lengths, ids, enum names — never field content.
    #[test]
    fn display_renders_metadata_only() {
        let expected: &[(ManifestError, &str)] = &[
            (
                ManifestError::UnknownKey {
                    map: MapId::Envelope,
                    key: 24,
                },
                "manifest envelope: unknown map key 24",
            ),
            (
                ManifestError::ReservedKey {
                    map: MapId::Body,
                    key: 8,
                },
                "manifest body: map key 8 is reserved for a future v1.x field",
            ),
            (
                ManifestError::MissingKey {
                    map: MapId::UnitEntry,
                    key: 5,
                },
                "unit entry: required map key 5 is missing",
            ),
            (
                ManifestError::WrongLength {
                    field: FixedLenField::Nonce,
                    expected: 24,
                    got: 23,
                },
                "nonce has invalid length: expected 24 bytes, got 23",
            ),
            (
                ManifestError::WrongLength {
                    field: FixedLenField::Pubkey(SigAlg::MlDsa65),
                    expected: 1952,
                    got: 32,
                },
                "ml-dsa-65 public key has invalid length: expected 1952 bytes, got 32",
            ),
            (
                ManifestError::UnexpectedField {
                    field: CondField::UnitCommit,
                },
                "unit_commit must be absent when the unit is fine-tree-covered",
            ),
            (
                ManifestError::MissingField {
                    field: CondField::CanonCommit,
                },
                "canon_commit must be present when the file is text",
            ),
            (
                ManifestError::EmptyContainer {
                    field: ContainerField::Units,
                },
                "units must not be empty",
            ),
            (
                ManifestError::EmptyContainer {
                    field: ContainerField::NormalUnits,
                },
                "normal units must not be empty",
            ),
            (
                ManifestError::UnknownEnumValue {
                    enumeration: EnumId::UnitKind,
                    value: 2,
                },
                "unit_kind: unregistered value 2",
            ),
            (
                ManifestError::InputTooLarge {
                    len: 16_777_217,
                    cap: 16_777_216,
                },
                "manifest input of 16777217 bytes exceeds the 16777216-byte limit",
            ),
            (
                ManifestError::ListTooLong {
                    list: ManifestListKind::Units,
                    claimed: 65_537,
                    cap: 65_536,
                },
                "units claims 65537 entries, exceeding the limit of 65536",
            ),
            (
                ManifestError::WrongRangeArity { got: 3 },
                "byte range must be a 2-element [start, length] array, got 3 element(s)",
            ),
            (
                ManifestError::DescriptorDomainMismatch {
                    kind: super::super::registry::DescriptorKind::Binary,
                    implied: super::super::registry::FineTreeDomain::Raw,
                    found: super::super::registry::FineTreeDomain::Canonical,
                },
                "descriptor kind binary implies fine-tree domain raw, but canonical is recorded",
            ),
            (
                ManifestError::UnsupportedFormatVersion {
                    found: 2,
                    supported: crate::format::SUPPORTED_VERSIONS,
                },
                "unsupported manifest format_version 2; this build decodes v1",
            ),
            (ManifestError::SigPolicyEmpty, "sig_policy is empty"),
            (
                ManifestError::DuplicateAlg {
                    position: AlgPosition::SigPolicy,
                    alg_id: 1,
                },
                "sig_policy lists algorithm id 1 more than once",
            ),
            (
                ManifestError::UnregisteredAlg {
                    position: AlgPosition::Signatures,
                    alg_id: 9,
                },
                "signatures: unregistered signature algorithm id 9",
            ),
            (
                ManifestError::UnitIdMismatch {
                    expected: 4,
                    found: 9,
                },
                "unit_id 9 does not match its manifest-order ordinal 4",
            ),
        ];
        for (err, want) in expected {
            assert_eq!(&err.to_string(), want);
        }
        // No schema-level variant can render byte content: the exemplar
        // sweep must stay free of hex escapes and of slice Debug output.
        for err in all_code_exemplars() {
            let rendered = err.to_string();
            assert!(!rendered.contains("0x"), "{rendered}");
        }
    }

    /// Schema-level variants carry no `source` chain that could wrap and
    /// leak input; only the two codec arms have one (checked above).
    #[test]
    fn schema_variants_have_no_source_chain() {
        for err in all_code_exemplars() {
            assert!(err.source().is_none(), "{err}");
        }
    }
}
