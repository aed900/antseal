//! `.sealproof` bundle schema-level error taxonomy (F8) — one distinct
//! variant per rejection class, sized for the tamper matrix's distinct-error
//! requirement (MVP-SPEC.md line 168).
//!
//! # Where this sits, and why it is a separate family from `manifest-`
//!
//! **D78 (ratified): bundle schema validation never consults the embedded
//! manifest.** [`BundleError`] is therefore the *layer 1* taxonomy of the
//! three-layer decode of registry §7.6.3 — and it structurally cannot
//! express a manifest failure: there is no `Manifest` arm on this enum, and
//! no constructor that could produce one. Layers 2 and 3 are
//! [`crate::manifest::ManifestError`]'s `Envelope`/`Body` arms, reached only
//! through F9's [`crate::bundle::SealProofError`], which is a *different
//! type*.
//!
//! That split is the point D78 makes: a bundle that is **well-formed but
//! inconsistent with its manifest** must report a verify code, and a
//! **malformed manifest inside a well-formed bundle** must report a
//! manifest code. Neither can borrow a `bundle-` code, because a
//! `bundle-`-coded failure is by construction decidable from the bundle's
//! own bytes (registry §0, tiers `[P]` and `[X]`). D30 makes error families
//! permanent, so this had to be true of the enum from its first line.
//!
//! # Two delegating wrapper arms
//!
//! [`BundleError::Cbor`] surfaces the codec's `cbor-*` code unchanged (those
//! failures genuinely *are* F3's rejection classes), and
//! [`BundleError::NodeAddress`] surfaces G8's `content-*` code unchanged.
//! The second is deliberate: registry §5 instructs F8 to construct GGM node
//! addresses through [`crate::content::ggm::NodeAddress::try_new`] rather
//! than re-checking `level <= 64` / `index < 2^level` inline — one
//! implementation of the bound, one error per class (D30). Re-prefixing
//! either would fork one taxonomy into two.
//!
//! # Secret hygiene (project rule 6)
//!
//! Payloads are key numbers, byte lengths, ids, and closed enum
//! discriminants — **never field content**. A `.sealproof` carries disclosed
//! key material (`k_u`, `k_m`) and disclosed salts; none of it may reach a
//! rendered error, and `display_renders_metadata_only` asserts it.

use core::fmt;

use thiserror::Error;

use crate::codec::DecodeError;
use crate::content::ContentError;

use super::registry::BundleMapId;

/// A bundle field whose byte length is fixed by the registry (§2) and checked
/// at parse. One code per class, so "wrong-length `k_u`" and "wrong-length
/// `unit_salt`" are different tamper rows even though both are byte-string
/// length slips in the same reveal entry.
///
/// **Two layers, different jobs** (registry §7.15): this is F8's *wire gate*
/// — a bundle that came through this decoder can never reach R with a
/// wrong-length salt. R's [`crate::verify::LengthField`] is the *view gate*,
/// because `BundleView` is also populated by R5 and by fixtures; it is not
/// dead code and must not be deleted. `k_u`/`k_m` are **F8-only**: MVP-SPEC.md
/// line 121's list is "every disclosed salt/seed/node hash", and keys are
/// neither — R binds keys by whether they *decrypt*, not by their length.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FixedLenField {
    /// A reveal's disclosed unit key `k_u`, 32 B (registry §§7.11–7.12).
    UnitKey,
    /// The storage record's `k_m`, 32 B (registry §7.7).
    ManifestKey,
    /// A non-covered reveal's `unit_salt`, 16 B.
    UnitSalt,
    /// A touched file's `path_salt`, 16 B.
    PathSalt,
    /// A full reveal's `file_salt`, 16 B.
    FileSalt,
    /// A full reveal's `s_root`, 32 B.
    SRoot,
    /// A GGM sub-cover seed, 32 B.
    CoverSeed,
    /// A boundary Merkle node hash, 32 B.
    PathNodeHash,
    /// The storage record's nonce, 24 B.
    StorageNonce,
    /// The storage record's Autonomi address, 32 B (decision D11).
    StorageAddress,
    /// An OTS artifact's Bitcoin block header, **exactly** 80 B
    /// (MVP-SPEC.md line 108).
    BlockHeader,
    /// A receipt transaction hash, 32 B (Keccak-256).
    TxHash,
}

impl FixedLenField {
    /// Every class, for exhaustive tests.
    pub const ALL: [Self; 12] = [
        Self::UnitKey,
        Self::ManifestKey,
        Self::UnitSalt,
        Self::PathSalt,
        Self::FileSalt,
        Self::SRoot,
        Self::CoverSeed,
        Self::PathNodeHash,
        Self::StorageNonce,
        Self::StorageAddress,
        Self::BlockHeader,
        Self::TxHash,
    ];
}

impl fmt::Display for FixedLenField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::UnitKey => "k_u",
            Self::ManifestKey => "k_m",
            Self::UnitSalt => "unit_salt",
            Self::PathSalt => "path_salt",
            Self::FileSalt => "file_salt",
            Self::SRoot => "s_root",
            Self::CoverSeed => "GGM cover seed",
            Self::PathNodeHash => "boundary node hash",
            Self::StorageNonce => "storage record nonce",
            Self::StorageAddress => "storage record address",
            Self::BlockHeader => "Bitcoin block header",
            Self::TxHash => "receipt transaction hash",
        })
    }
}

/// A bundle container the schema requires to be non-empty.
///
/// The four top-level reveal/anchor sections are deliberately **not** here:
/// registry §7.6 makes every one of them `req, may be empty`, so that the
/// "nothing revealed, nothing anchored" bundle has exactly one encoding
/// rather than splitting into an absent-vs-empty pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ContainerField {
    /// A covered reveal's `cover` — a covered unit has ≥ 1 leaf, and the
    /// empty unit is never covered (registry §7.11; empty files have no fine
    /// tree).
    Cover,
    /// A receipt's `tx_hashes` — a payment has ≥ 1 transaction
    /// (registry §7.10).
    TxHashes,
}

impl ContainerField {
    /// Every container, for exhaustive tests.
    pub const ALL: [Self; 2] = [Self::Cover, Self::TxHashes];
}

impl fmt::Display for ContainerField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Cover => "cover",
            Self::TxHashes => "tx_hashes",
        })
    }
}

/// A bundle list whose order is **parse-enforced** (registry §8).
///
/// Strict ascent doubles as the duplicate check: equal successive keys fail
/// the same test as inverted ones, so "two entries for one `unit_id`" and
/// "entries out of order" are one rejection class per list rather than two.
///
/// `ots_anchors` / `tsa_anchors` / `intermediates` / `tx_hashes` are absent
/// on purpose: an anchor artifact has no content-independent sort key
/// (registry §8), so their order is a *builder* rule backed by the seal
/// journal, not a parse rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OrderedList {
    /// Bundle `covered_reveals`, by `unit_id`.
    CoveredReveals,
    /// Bundle `noncovered_reveals`, by `unit_id`.
    NonCoveredReveals,
    /// Bundle `touched_files`, by `file_id`.
    TouchedFiles,
    /// Bundle `full_reveals`, by `file_id`.
    FullReveals,
    /// A covered reveal's `cover`, by leaf-interval start.
    Cover,
    /// A covered reveal's `paths`, by leaf-interval start.
    Paths,
}

impl OrderedList {
    /// Every parse-ordered list, for exhaustive tests.
    pub const ALL: [Self; 6] = [
        Self::CoveredReveals,
        Self::NonCoveredReveals,
        Self::TouchedFiles,
        Self::FullReveals,
        Self::Cover,
        Self::Paths,
    ];

    /// What the list is sorted by — used in the rendered message.
    const fn sort_key(self) -> &'static str {
        match self {
            Self::CoveredReveals | Self::NonCoveredReveals => "unit_id",
            Self::TouchedFiles | Self::FullReveals => "file_id",
            Self::Cover | Self::Paths => "leaf-interval start",
        }
    }
}

impl fmt::Display for OrderedList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::CoveredReveals => "covered_reveals",
            Self::NonCoveredReveals => "noncovered_reveals",
            Self::TouchedFiles => "touched_files",
            Self::FullReveals => "full_reveals",
            Self::Cover => "cover",
            Self::Paths => "paths",
        })
    }
}

/// A bundle list with a **frozen length cap** (decision D10, registry §11).
///
/// One discriminant per capped list, so a tamper row can pin exactly which
/// list overflowed — the same variant-level-code pattern F8 already used for
/// its four `bundle-unsorted-*` codes over four of these same lists.
///
/// Every value's cap is a `codec::caps` constant; [`Self::cap`] is the only
/// mapping, so the code and the registry table cannot drift (a test asserts
/// code == registry).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BundleListKind {
    /// Bundle key 3 `ots_anchors`.
    OtsAnchors,
    /// Bundle key 4 `tsa_anchors`.
    TsaAnchors,
    /// A TSA anchor's key 2 `intermediates`.
    Intermediates,
    /// A receipt's key 0 `tx_hashes`.
    TxHashes,
    /// Bundle key 6 `covered_reveals`.
    CoveredReveals,
    /// Bundle key 7 `noncovered_reveals`.
    NonCoveredReveals,
    /// A covered reveal's key 3 `cover`.
    Cover,
    /// A covered reveal's key 4 `paths`.
    Paths,
    /// Bundle key 8 `touched_files`.
    TouchedFiles,
    /// Bundle key 9 `full_reveals`.
    FullReveals,
}

impl BundleListKind {
    /// Every capped list, for exhaustive tests.
    pub const ALL: [Self; 10] = [
        Self::OtsAnchors,
        Self::TsaAnchors,
        Self::Intermediates,
        Self::TxHashes,
        Self::CoveredReveals,
        Self::NonCoveredReveals,
        Self::Cover,
        Self::Paths,
        Self::TouchedFiles,
        Self::FullReveals,
    ];

    /// The frozen maximum element count (decision D10 §1).
    ///
    /// The reveal and touched/full caps are defined *as* their manifest-side
    /// partner (`MAX_UNIT_COUNT` / `MAX_FILE_COUNT`) so the two halves cannot
    /// drift, while staying bundle-side constants — D78 forbids this layer
    /// from consulting the manifest at all.
    #[must_use]
    pub const fn cap(self) -> u64 {
        use crate::codec::caps;
        match self {
            Self::OtsAnchors => caps::MAX_OTS_ANCHOR_COUNT,
            Self::TsaAnchors => caps::MAX_TSA_ANCHOR_COUNT,
            Self::Intermediates => caps::MAX_INTERMEDIATE_COUNT,
            Self::TxHashes => caps::MAX_TX_HASH_COUNT,
            Self::CoveredReveals => caps::MAX_COVERED_REVEAL_COUNT,
            Self::NonCoveredReveals => caps::MAX_NONCOVERED_REVEAL_COUNT,
            Self::Cover => caps::MAX_COVER_ENTRIES,
            Self::Paths => caps::MAX_PATH_NODES,
            Self::TouchedFiles => caps::MAX_TOUCHED_FILE_COUNT,
            Self::FullReveals => caps::MAX_FULL_REVEAL_COUNT,
        }
    }
}

impl fmt::Display for BundleListKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::OtsAnchors => "ots_anchors",
            Self::TsaAnchors => "tsa_anchors",
            Self::Intermediates => "intermediates",
            Self::TxHashes => "tx_hashes",
            Self::CoveredReveals => "covered_reveals",
            Self::NonCoveredReveals => "noncovered_reveals",
            Self::Cover => "cover",
            Self::Paths => "paths",
            Self::TouchedFiles => "touched_files",
            Self::FullReveals => "full_reveals",
        })
    }
}

/// A bundle `bstr` field holding an **opaque foreign artifact**, with a frozen
/// byte-length cap (decision D10, registry §11).
///
/// The artifacts' *internals* are A's at M2 (registry §7.8/§7.9), but a
/// byte-length cap on a v1 wire field decides whether a given `.sealproof` is
/// valid v1, so it freezes with format v1 and lives here. All four caps are
/// ≥30× the largest real artifact: guessing high is free, guessing low is a
/// compatibility break.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OpaqueField {
    /// An OTS anchor's key 1 `ots` — the `.ots` proof blob.
    Ots,
    /// A TSA anchor's key 1 `token` — the DER `TimeStampToken`.
    TsaToken,
    /// One element of a TSA anchor's `intermediates` — a DER X.509 cert.
    Certificate,
    /// A receipt's key 2 `payload`.
    ReceiptPayload,
}

impl OpaqueField {
    /// Every capped opaque field, for exhaustive tests.
    pub const ALL: [Self; 4] = [
        Self::Ots,
        Self::TsaToken,
        Self::Certificate,
        Self::ReceiptPayload,
    ];

    /// The frozen maximum byte length (decision D10 §1).
    #[must_use]
    pub const fn cap(self) -> u64 {
        use crate::codec::caps;
        match self {
            Self::Ots => caps::MAX_OTS_BYTES,
            Self::TsaToken => caps::MAX_TSA_TOKEN_BYTES,
            Self::Certificate => caps::MAX_CERT_BYTES,
            Self::ReceiptPayload => caps::MAX_RECEIPT_PAYLOAD_BYTES,
        }
    }
}

impl fmt::Display for OpaqueField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Ots => "ots artifact",
            Self::TsaToken => "TSA token",
            Self::Certificate => "TSA chain certificate",
            Self::ReceiptPayload => "receipt payload",
        })
    }
}

/// One of the two positional 3-element tuples of registry §5.
///
/// Arrays have no key space and therefore no reserved slots, so a wrong
/// element count is a *shape* error, not a missing-field one — and extending
/// either tuple would be a format-version event (registry §9).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TupleId {
    /// `cover_entry = [level, index, seed]`.
    CoverEntry,
    /// `path_node = [level, index, hash]`.
    PathNode,
}

impl TupleId {
    /// Every tuple, for exhaustive tests.
    pub const ALL: [Self; 2] = [Self::CoverEntry, Self::PathNode];

    /// The tuple's arity in v1 — both are 3-element definite arrays.
    #[must_use]
    pub const fn arity(self) -> u64 {
        match self {
            Self::CoverEntry | Self::PathNode => 3,
        }
    }
}

impl fmt::Display for TupleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::CoverEntry => "cover_entry",
            Self::PathNode => "path_node",
        })
    }
}

/// How a unit ciphertext failed the cheap parse-time shape gate of
/// registry §2.
///
/// XChaCha20-Poly1305 output = padded plaintext + a 16-byte tag, and
/// `padded_length` is a positive multiple of 256 (MVP-SPEC.md line 91), so
/// every unit ciphertext satisfies `len >= 272` **and** `len ≡ 16 (mod 256)`.
/// The two are checked in that order and carry separate codes: a length of
/// 271 fails both, and a fixed order is what makes the outcome of a given
/// mutation deterministic (the D30 requirement that a tamper row pin one
/// code).
///
/// The exact equality `len == padded_length(true_length) + 16` needs the
/// manifest's `true_length` and is R's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CiphertextDefect {
    /// Shorter than one padding block plus the tag.
    TooShort,
    /// Not congruent to the tag length modulo the padding block.
    BadResidue,
}

impl CiphertextDefect {
    /// Every defect, for exhaustive tests.
    pub const ALL: [Self; 2] = [Self::TooShort, Self::BadResidue];
}

impl fmt::Display for CiphertextDefect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::TooShort => "shorter than one padding block plus the AEAD tag",
            Self::BadResidue => "not one AEAD tag past a whole number of padding blocks",
        })
    }
}

/// Every `.sealproof` **layer-1** schema failure class, one distinct variant
/// each.
///
/// `#[non_exhaustive]`: additive schema rejections must not break downstream
/// matches (the `CryptoError`/`ManifestError` precedent). Inside this crate
/// the matches stay exhaustive, so [`Self::code`] remains the compile-time
/// guard that every new variant receives a distinct stable code.
///
/// **There is deliberately no manifest arm** (D78) — see the module docs.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum BundleError {
    // ── Delegating wrappers ─────────────────────────────────────────
    /// The bundle bytes failed the strict canonical CBOR layer (F3).
    /// Positions are relative to the **bundle** input.
    #[error("bundle: {source}")]
    Cbor {
        /// The codec-layer rejection.
        #[source]
        source: DecodeError,
    },

    /// A GGM node address in a `cover_entry` / `path_node` failed G8's
    /// self-contained validity bounds (`level <= 64`, `index < 2^level` —
    /// registry §5's two `[P]` checks). Constructed through
    /// [`crate::content::ggm::NodeAddress::try_new`] so there is exactly one
    /// implementation of the bound.
    #[error("bundle: {source}")]
    NodeAddress {
        /// G8's rejection, code delegated unchanged.
        #[source]
        source: ContentError,
    },

    // ── Key space (registry §1 rule 4, §7.15) ───────────────────────
    /// A map key outside every v1 band (`>= 24`) — never reserved, never
    /// assignable.
    #[error("{map}: unknown map key {key}")]
    UnknownKey {
        /// The map that rejected the key.
        map: BundleMapId,
        /// The offending key.
        key: u64,
    },

    /// An unassigned key inside the `0..=23` band: reserved for a future
    /// v1.x field, so its presence means a newer producer met an older
    /// verifier. Both *named* reserved slots (bundle key 10
    /// `range_reveals`, receipt key 3 `chain_inputs`) land here — a named
    /// slot is documentation, not a separate code (registry §7.15).
    #[error("{map}: map key {key} is reserved for a future v1.x field")]
    ReservedKey {
        /// The map that rejected the key.
        map: BundleMapId,
        /// The offending key.
        key: u64,
    },

    /// A key the schema requires is absent.
    #[error("{map}: required map key {key} is missing")]
    MissingKey {
        /// The map with the hole.
        map: BundleMapId,
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

    /// A container the schema requires to be non-empty is empty.
    #[error("{field} must not be empty")]
    EmptyContainer {
        /// Which container.
        field: ContainerField,
    },

    /// A parse-ordered list is not strictly ascending — out of order, or
    /// carrying a duplicate sort key (registry §8).
    #[error("{list} must be strictly ascending by {key}, but {previous} is followed by {found}", key = list.sort_key())]
    UnsortedList {
        /// Which list.
        list: OrderedList,
        /// The preceding entry's sort key.
        previous: u128,
        /// The offending entry's sort key.
        found: u128,
    },

    /// A positional tuple has the wrong element count (registry §5).
    #[error("{tuple} must be a {expected}-element array, got {got} element(s)", expected = tuple.arity())]
    WrongTupleArity {
        /// Which tuple.
        tuple: TupleId,
        /// Element count actually present.
        got: u64,
    },

    /// A unit ciphertext fails the cheap length-shape gate of registry §2.
    #[error("unit ciphertext of {got} bytes is {defect}")]
    CiphertextShape {
        /// How it failed.
        defect: CiphertextDefect,
        /// The length actually present.
        got: u64,
    },

    // ── Resource caps (decision D10, registry §11) ──────────────────
    /// The `.sealproof` input exceeds
    /// [`MAX_BUNDLE_BYTES`](crate::codec::caps::MAX_BUNDLE_BYTES).
    ///
    /// Raised as the **first statement** of the bundle decode, before the
    /// decoder is even constructed, so it precedes every canonicality and
    /// schema code as well as every AEAD, hash, and signature operation
    /// (D10 §5). An oversized bundle that is *also* non-canonical reports
    /// this, deliberately.
    #[error("bundle input of {len} bytes exceeds the {cap}-byte limit")]
    InputTooLarge {
        /// The input length actually offered.
        len: u64,
        /// The frozen cap.
        cap: u64,
    },

    /// A capped bundle list claims more elements than its cap allows.
    ///
    /// Checked on the **claimed count at the array head**, before a single
    /// element is read, so the rejecting input is an array head and nothing
    /// else — the cap fires cheaply by construction (D10 §4).
    #[error("{list} claims {claimed} entries, exceeding the limit of {cap}")]
    ListTooLong {
        /// Which list overflowed.
        list: BundleListKind,
        /// The element count the array head claimed.
        claimed: u64,
        /// The frozen cap.
        cap: u64,
    },

    /// An opaque foreign artifact (`.ots`, TSA token, certificate, receipt
    /// payload) exceeds its frozen byte-length cap.
    ///
    /// Length only — the artifact's bytes are never rendered, and its
    /// *internal* structure is A's at M2.
    #[error("{field} of {len} bytes exceeds the {cap}-byte limit")]
    ArtifactTooLarge {
        /// Which field overflowed.
        field: OpaqueField,
        /// The byte length actually present.
        len: u64,
        /// The frozen cap.
        cap: u64,
    },

    /// An `anchor_status` value outside the registered `0..=6`
    /// (registry §6.1; `7..=15` are reserved and unregistered in v1).
    #[error("anchor_status: unregistered value {value}")]
    UnknownAnchorStatus {
        /// The unregistered value.
        value: u64,
    },

    // ── Version ─────────────────────────────────────────────────────
    /// The bundle declares a `format_version` with no decoder in this build
    /// (F10). Raised by `crate::format`'s version dispatch **before** any
    /// schema decode, so a newer-than-this-verifier bundle is never reported
    /// as corrupt: it is neither a canonicality error nor an unknown-key
    /// error.
    ///
    /// Distinct from the manifest's own version error: the two discriminants
    /// are independent (registry §7.6 key 0 vs §7.2 key 0), so a v1 bundle
    /// may legitimately carry a v2 manifest one day and the two rejections
    /// must stay separable.
    #[error(
        "unsupported bundle format_version {found}; this build decodes {}",
        crate::format::supported_versions_str(supported)
    )]
    UnsupportedFormatVersion {
        /// The version the bundle declares.
        found: u64,
        /// Every version this build *can* decode
        /// ([`crate::format::SUPPORTED_VERSIONS`]).
        supported: &'static [u64],
    },

    // ── Presence groups (registry §7.8) ─────────────────────────────
    /// An OTS artifact carries **some** of the upgrade group
    /// (`block_height`, `block_header`, `fetch_date`) but not all of it.
    ///
    /// **D79 (ratified): the group is free-standing and all-or-nothing.**
    /// The rule never consults the sealer-written `status` field — that is
    /// the one field the design says a verifier must never trust, so making
    /// a *parse* rule depend on it would let a sealer steer the decoder.
    /// Two of three present is a malformed artifact, not a partially-known
    /// one.
    #[error(
        "OTS upgrade group is all-or-nothing: key {missing_key} is absent \
         while other group keys are present"
    )]
    OtsUpgradeGroupIncomplete {
        /// The **lowest-numbered** absent group key, so the payload is
        /// deterministic when two of the three are missing.
        missing_key: u64,
    },

    // ── Cross-section rules (registry §7.6, tier `[X]`) ───────────────
    /// One `unit_id` appears in **both** reveal arrays. Decidable from the
    /// bundle alone — a unit revealed twice is malformed regardless of what
    /// the manifest says. R's `DuplicateUnitReveal` remains the backstop for
    /// the manifest-aware case.
    #[error("unit {unit_id} is revealed in both covered_reveals and noncovered_reveals")]
    UnitRevealedTwice {
        /// The doubly-revealed unit.
        unit_id: u64,
    },

    /// A `full_reveals` entry names a `file_id` with no `touched_files`
    /// entry: a full reveal whose path was never disclosed is malformed on
    /// its face. Tier **`[X]`**, not `[R]` — both lists are in the bundle, so
    /// F8 decides it without the manifest.
    #[error("file {file_id} is fully revealed but has no touched_files entry")]
    FullRevealWithoutTouchedFile {
        /// The fully revealed file whose path was withheld.
        file_id: u64,
    },
}

impl BundleError {
    /// Stable machine-readable code, pairwise-distinct across every
    /// (variant, discriminant) pair — the bundle leg of Q7's error-code
    /// stability contract. Lowercase kebab-case, `bundle-`-prefixed; never
    /// changes once a tamper row binds to it.
    ///
    /// The two wrapper arms are the deliberate exception: they surface the
    /// wrapped [`DecodeError::code`] / [`ContentError::code`] unchanged,
    /// because those failures genuinely *are* the codec's and G8's rejection
    /// classes (the `ManifestError::Envelope` precedent — a wrapped failure
    /// keeps its owning domain's identity rather than acquiring a second
    /// one).
    ///
    /// The exhaustive, variant-wildcard-free match is the compile-time
    /// guard: a new variant — or a new [`FixedLenField`]/[`ContainerField`]/
    /// [`OrderedList`]/[`TupleId`]/[`CiphertextDefect`]/[`BundleListKind`]/
    /// [`OpaqueField`] discriminant — fails compilation here until it
    /// receives a distinct code and an exemplar in `all_code_exemplars`.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Cbor { source } => source.code(),
            Self::NodeAddress { source } => source.code(),
            Self::UnknownKey { .. } => "bundle-unknown-key",
            Self::ReservedKey { .. } => "bundle-reserved-key",
            Self::MissingKey { .. } => "bundle-missing-key",
            Self::WrongLength { field, .. } => match field {
                FixedLenField::UnitKey => "bundle-wrong-length-k-u",
                FixedLenField::ManifestKey => "bundle-wrong-length-k-m",
                FixedLenField::UnitSalt => "bundle-wrong-length-unit-salt",
                FixedLenField::PathSalt => "bundle-wrong-length-path-salt",
                FixedLenField::FileSalt => "bundle-wrong-length-file-salt",
                FixedLenField::SRoot => "bundle-wrong-length-s-root",
                FixedLenField::CoverSeed => "bundle-wrong-length-cover-seed",
                FixedLenField::PathNodeHash => "bundle-wrong-length-path-node-hash",
                FixedLenField::StorageNonce => "bundle-wrong-length-storage-nonce",
                FixedLenField::StorageAddress => "bundle-wrong-length-storage-address",
                FixedLenField::BlockHeader => "bundle-wrong-length-block-header",
                FixedLenField::TxHash => "bundle-wrong-length-tx-hash",
            },
            Self::EmptyContainer { field } => match field {
                ContainerField::Cover => "bundle-empty-cover",
                ContainerField::TxHashes => "bundle-empty-tx-hashes",
            },
            Self::UnsortedList { list, .. } => match list {
                OrderedList::CoveredReveals => "bundle-unsorted-covered-reveals",
                OrderedList::NonCoveredReveals => "bundle-unsorted-noncovered-reveals",
                OrderedList::TouchedFiles => "bundle-unsorted-touched-files",
                OrderedList::FullReveals => "bundle-unsorted-full-reveals",
                OrderedList::Cover => "bundle-unsorted-cover",
                OrderedList::Paths => "bundle-unsorted-paths",
            },
            Self::WrongTupleArity { tuple, .. } => match tuple {
                TupleId::CoverEntry => "bundle-wrong-cover-entry-arity",
                TupleId::PathNode => "bundle-wrong-path-node-arity",
            },
            Self::CiphertextShape { defect, .. } => match defect {
                CiphertextDefect::TooShort => "bundle-ciphertext-too-short",
                CiphertextDefect::BadResidue => "bundle-ciphertext-length-residue",
            },
            Self::InputTooLarge { .. } => "bundle-too-large",
            Self::ListTooLong { list, .. } => match list {
                BundleListKind::OtsAnchors => "bundle-too-many-ots-anchors",
                BundleListKind::TsaAnchors => "bundle-too-many-tsa-anchors",
                BundleListKind::Intermediates => "bundle-too-many-intermediates",
                BundleListKind::TxHashes => "bundle-too-many-tx-hashes",
                BundleListKind::CoveredReveals => "bundle-too-many-covered-reveals",
                BundleListKind::NonCoveredReveals => "bundle-too-many-noncovered-reveals",
                BundleListKind::Cover => "bundle-too-many-cover-entries",
                BundleListKind::Paths => "bundle-too-many-path-nodes",
                BundleListKind::TouchedFiles => "bundle-too-many-touched-files",
                BundleListKind::FullReveals => "bundle-too-many-full-reveals",
            },
            Self::ArtifactTooLarge { field, .. } => match field {
                OpaqueField::Ots => "bundle-ots-too-large",
                OpaqueField::TsaToken => "bundle-tsa-token-too-large",
                OpaqueField::Certificate => "bundle-cert-too-large",
                OpaqueField::ReceiptPayload => "bundle-receipt-payload-too-large",
            },
            Self::UnknownAnchorStatus { .. } => "bundle-unknown-anchor-status",
            Self::UnsupportedFormatVersion { .. } => "bundle-unsupported-format-version",
            Self::OtsUpgradeGroupIncomplete { .. } => "bundle-ots-upgrade-group-incomplete",
            Self::UnitRevealedTwice { .. } => "bundle-unit-revealed-twice",
            Self::FullRevealWithoutTouchedFile { .. } => "bundle-full-reveal-without-touched-file",
        }
    }
}

/// F10: the bundle family's unsupported-version rejection, so
/// `crate::format`'s version dispatch can raise it without knowing anything
/// about the bundle schema.
impl crate::format::VersionRejection for BundleError {
    fn unsupported_version(found: u64, supported: &'static [u64]) -> Self {
        Self::UnsupportedFormatVersion { found, supported }
    }
}

/// One exemplar per distinct schema-level [`BundleError::code`] — every
/// (variant, discriminant) pair exactly once, with pairwise-distinct
/// `Display` renderings.
///
/// The two delegating wrapper arms are excluded by design: their codes are
/// the codec's 15 `cbor-*` values and G8's `content-*` values, already
/// exemplified (and asserted pairwise-distinct) by `codec::decode` and
/// `content::error`. Including them here would assert distinctness of the
/// *same* code twice.
#[cfg(test)]
pub(crate) fn all_code_exemplars() -> Vec<BundleError> {
    use BundleError as E;
    let mut exemplars = vec![
        E::UnknownKey {
            map: BundleMapId::Bundle,
            key: 24,
        },
        E::ReservedKey {
            map: BundleMapId::Bundle,
            key: super::registry::key::bundle::RESERVED_RANGE_REVEALS,
        },
        E::MissingKey {
            map: BundleMapId::StorageRecord,
            key: 2,
        },
    ];
    for (i, field) in FixedLenField::ALL.into_iter().enumerate() {
        exemplars.push(E::WrongLength {
            field,
            expected: 32,
            got: i as u64,
        });
    }
    for field in ContainerField::ALL {
        exemplars.push(E::EmptyContainer { field });
    }
    for (i, list) in OrderedList::ALL.into_iter().enumerate() {
        exemplars.push(E::UnsortedList {
            list,
            previous: 7,
            found: i as u128,
        });
    }
    for tuple in TupleId::ALL {
        exemplars.push(E::WrongTupleArity { tuple, got: 4 });
    }
    for (i, defect) in CiphertextDefect::ALL.into_iter().enumerate() {
        exemplars.push(E::CiphertextShape {
            defect,
            got: 100 + i as u64,
        });
    }
    for list in BundleListKind::ALL {
        let cap = list.cap();
        exemplars.push(E::ListTooLong {
            list,
            claimed: cap + 1,
            cap,
        });
    }
    for field in OpaqueField::ALL {
        let cap = field.cap();
        exemplars.push(E::ArtifactTooLarge {
            field,
            len: cap + 1,
            cap,
        });
    }
    exemplars.extend([
        E::InputTooLarge {
            len: crate::codec::caps::MAX_BUNDLE_BYTES + 1,
            cap: crate::codec::caps::MAX_BUNDLE_BYTES,
        },
        E::UnknownAnchorStatus { value: 7 },
        E::UnsupportedFormatVersion {
            found: 2,
            supported: crate::format::SUPPORTED_VERSIONS,
        },
        E::OtsUpgradeGroupIncomplete { missing_key: 3 },
        E::UnitRevealedTwice { unit_id: 5 },
        E::FullRevealWithoutTouchedFile { file_id: 2 },
    ]);
    exemplars
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::error::Error as _;

    /// The domain distinctness meta-test (the F3/F5 pattern): every
    /// schema-level code is `bundle-`-prefixed lowercase kebab-case,
    /// pairwise distinct, and paired with a pairwise-distinct `Display`.
    #[test]
    fn codes_are_pairwise_distinct_and_prefixed() {
        let exemplars = all_code_exemplars();
        assert_eq!(
            exemplars.len(),
            47,
            "one exemplar per distinct code — update deliberately"
        );

        let codes: BTreeSet<&'static str> = exemplars.iter().map(BundleError::code).collect();
        assert_eq!(codes.len(), exemplars.len(), "codes pairwise distinct");
        for code in &codes {
            assert!(
                code.starts_with("bundle-"),
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

    /// The banned prefixes: bundle schema errors never borrow another
    /// domain's namespace. `manifest-` is the load-bearing one — D78 fixes
    /// which family a cross-side rejection lands in, and D30 makes families
    /// permanent, so a `manifest-`-coded bundle rejection would be
    /// unfixable after Q14.
    #[test]
    fn codes_avoid_other_domains_prefixes() {
        for err in all_code_exemplars() {
            let code = err.code();
            for banned in ["manifest-", "crypto-", "cbor-", "content-", "verify-"] {
                assert!(
                    !code.starts_with(banned),
                    "code {code:?} collides with the {banned} domain"
                );
            }
        }
    }

    /// Bundle codes never collide with the manifest half's codes, in either
    /// direction — the two families share a tamper registry (Q7 layer 2).
    #[test]
    fn codes_are_disjoint_from_the_manifest_family() {
        let bundle: BTreeSet<&'static str> =
            all_code_exemplars().iter().map(BundleError::code).collect();
        let manifest: BTreeSet<&'static str> = crate::manifest::error::all_code_exemplars()
            .iter()
            .map(crate::manifest::ManifestError::code)
            .collect();
        assert!(
            bundle.is_disjoint(&manifest),
            "overlap: {:?}",
            bundle.intersection(&manifest).collect::<Vec<_>>()
        );
    }

    /// Every schema variant is reachable from the exemplar list — no
    /// variant can miss a code (mirrors F5's guard).
    #[test]
    fn every_schema_variant_has_an_exemplar() {
        use core::mem::discriminant;
        let exemplars = all_code_exemplars();
        let one_of_each = [
            BundleError::UnknownKey {
                map: BundleMapId::Bundle,
                key: 24,
            },
            BundleError::ReservedKey {
                map: BundleMapId::Bundle,
                key: 10,
            },
            BundleError::MissingKey {
                map: BundleMapId::Bundle,
                key: 0,
            },
            BundleError::WrongLength {
                field: FixedLenField::UnitKey,
                expected: 32,
                got: 31,
            },
            BundleError::EmptyContainer {
                field: ContainerField::Cover,
            },
            BundleError::UnsortedList {
                list: OrderedList::Cover,
                previous: 1,
                found: 0,
            },
            BundleError::WrongTupleArity {
                tuple: TupleId::CoverEntry,
                got: 2,
            },
            BundleError::CiphertextShape {
                defect: CiphertextDefect::TooShort,
                got: 16,
            },
            BundleError::InputTooLarge { len: 1, cap: 0 },
            BundleError::ListTooLong {
                list: BundleListKind::Cover,
                claimed: 1,
                cap: 0,
            },
            BundleError::ArtifactTooLarge {
                field: OpaqueField::Ots,
                len: 1,
                cap: 0,
            },
            BundleError::UnknownAnchorStatus { value: 7 },
            BundleError::UnsupportedFormatVersion {
                found: 2,
                supported: crate::format::SUPPORTED_VERSIONS,
            },
            BundleError::OtsUpgradeGroupIncomplete { missing_key: 2 },
            BundleError::UnitRevealedTwice { unit_id: 0 },
            BundleError::FullRevealWithoutTouchedFile { file_id: 0 },
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

    /// The two wrapper arms delegate their codes unchanged and keep their
    /// wrapped error reachable as an `Error::source`.
    #[test]
    fn wrapper_arms_delegate_codes() {
        let cbor = DecodeError::NonShortestInt { position: 7 };
        let wrapped = BundleError::Cbor {
            source: cbor.clone(),
        };
        assert_eq!(wrapped.code(), cbor.code());
        assert_eq!(wrapped.code(), "cbor-non-shortest-int");
        assert!(wrapped.source().is_some());

        let content = ContentError::NodeAddressLevelTooDeep { level: 65, max: 64 };
        let wrapped = BundleError::NodeAddress { source: content };
        assert_eq!(wrapped.code(), content.code());
        assert_eq!(wrapped.code(), "content-node-address-level-too-deep");
        assert!(wrapped.source().is_some());
    }

    /// **D78 as a type witness.** `BundleError` has no arm that can carry a
    /// `ManifestError`, so bundle schema validation cannot report a manifest
    /// failure even by accident. The check is a compile-fail doctest rather
    /// than a runtime assertion because that is the strength D78 needs.
    ///
    /// ```compile_fail,E0599
    /// use antseal_core::bundle::BundleError;
    /// use antseal_core::manifest::ManifestError;
    /// // error: no variant named `Manifest` — layers 2/3 belong to
    /// // `SealProofError` (registry §7.6.3), never to the schema layer.
    /// let _ = BundleError::Manifest {
    ///     source: ManifestError::SigPolicyEmpty,
    /// };
    /// ```
    #[test]
    fn d78_no_manifest_arm() {
        // The doctest above is the enforcement; this body records that a
        // schema error never wraps a manifest error at runtime either.
        for err in all_code_exemplars() {
            assert!(err.source().is_none(), "{err}");
        }
    }

    /// Project rule 6: `Display` renders sanctioned metadata only — key
    /// numbers, lengths, ids, enum names — never disclosed key material,
    /// salts, ciphertext, or paths.
    #[test]
    fn display_renders_metadata_only() {
        let expected: &[(BundleError, &str)] = &[
            (
                BundleError::UnknownKey {
                    map: BundleMapId::Bundle,
                    key: 24,
                },
                "bundle: unknown map key 24",
            ),
            (
                BundleError::ReservedKey {
                    map: BundleMapId::ReceiptRecord,
                    key: 3,
                },
                "receipt record: map key 3 is reserved for a future v1.x field",
            ),
            (
                BundleError::MissingKey {
                    map: BundleMapId::StorageRecord,
                    key: 2,
                },
                "storage record: required map key 2 is missing",
            ),
            (
                BundleError::WrongLength {
                    field: FixedLenField::UnitKey,
                    expected: 32,
                    got: 31,
                },
                "k_u has invalid length: expected 32 bytes, got 31",
            ),
            (
                BundleError::WrongLength {
                    field: FixedLenField::BlockHeader,
                    expected: 80,
                    got: 79,
                },
                "Bitcoin block header has invalid length: expected 80 bytes, got 79",
            ),
            (
                BundleError::EmptyContainer {
                    field: ContainerField::Cover,
                },
                "cover must not be empty",
            ),
            (
                BundleError::UnsortedList {
                    list: OrderedList::CoveredReveals,
                    previous: 4,
                    found: 4,
                },
                "covered_reveals must be strictly ascending by unit_id, but 4 is followed by 4",
            ),
            (
                BundleError::UnsortedList {
                    list: OrderedList::Cover,
                    previous: 8,
                    found: 2,
                },
                "cover must be strictly ascending by leaf-interval start, but 8 is followed by 2",
            ),
            (
                BundleError::WrongTupleArity {
                    tuple: TupleId::PathNode,
                    got: 2,
                },
                "path_node must be a 3-element array, got 2 element(s)",
            ),
            (
                BundleError::CiphertextShape {
                    defect: CiphertextDefect::TooShort,
                    got: 16,
                },
                "unit ciphertext of 16 bytes is shorter than one padding block plus the AEAD tag",
            ),
            (
                BundleError::InputTooLarge {
                    len: 268_435_457,
                    cap: 268_435_456,
                },
                "bundle input of 268435457 bytes exceeds the 268435456-byte limit",
            ),
            (
                BundleError::ListTooLong {
                    list: BundleListKind::Cover,
                    claimed: 257,
                    cap: 256,
                },
                "cover claims 257 entries, exceeding the limit of 256",
            ),
            (
                BundleError::ArtifactTooLarge {
                    field: OpaqueField::Certificate,
                    len: 65_537,
                    cap: 65_536,
                },
                "TSA chain certificate of 65537 bytes exceeds the 65536-byte limit",
            ),
            (
                BundleError::UnknownAnchorStatus { value: 7 },
                "anchor_status: unregistered value 7",
            ),
            (
                BundleError::UnsupportedFormatVersion {
                    found: 2,
                    supported: crate::format::SUPPORTED_VERSIONS,
                },
                "unsupported bundle format_version 2; this build decodes v1",
            ),
            (
                BundleError::OtsUpgradeGroupIncomplete { missing_key: 3 },
                "OTS upgrade group is all-or-nothing: key 3 is absent while other group keys \
                 are present",
            ),
            (
                BundleError::UnitRevealedTwice { unit_id: 5 },
                "unit 5 is revealed in both covered_reveals and noncovered_reveals",
            ),
            (
                BundleError::FullRevealWithoutTouchedFile { file_id: 2 },
                "file 2 is fully revealed but has no touched_files entry",
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
            assert!(!rendered.contains('['), "{rendered}");
        }
    }
}
