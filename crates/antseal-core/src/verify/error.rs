//! The `verify_bundle` error taxonomy (task R1).
//!
//! Bundles arrive from adversaries — including the sealer (MVP-SPEC.md
//! line 121: "the sealer is an adversary too"). Every failure class the
//! R domain owns gets one distinct, field-identifying variant so the
//! tamper matrix ("every mutation fails with a distinct error",
//! MVP-SPEC.md line 168) can assert exactly which invariant a mutation
//! tripped, and the Q7 harness can key rows on stable machine-readable
//! codes ([`VerifyError::code`]).
//!
//! Error mode is decided in `docs/decisions/D27-verify-error-mode.md`:
//! fail-fast typed first-error is normative (`Result<_, VerifyError>`);
//! [`VerifyFailures`] is the optional multi-finding collection for
//! rendering, whose first element MUST equal the fail-fast error.
//!
//! No secret material — `W`, unit keys `k_u`, salts, seeds — is ever
//! carried by (or formattable from) these types: payloads are ids,
//! lengths, offsets, and kind discriminants only. A test in
//! `super::tests` asserts this over every variant.

use core::fmt;

use super::unit_stages::FineTreeError;

/// Which exact-length-checked disclosed field failed its length rule.
///
/// MVP-SPEC.md line 121: "**every disclosed salt/seed/node hash has its
/// exact spec length** — `unit_salt`/`path_salt`/`file_salt` = 16 B
/// (blocks shift-malleable openings across the salt/message boundary),
/// `s_root` and every GGM covering seed = 32 B, boundary Merkle node
/// hashes = 32 B". Carried by [`VerifyError::WrongLength`] so each field
/// class surfaces as its own distinct error code (R3's "per-field length
/// variants").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LengthField {
    /// 16-byte `unit_salt` of a non-covered (`--no-fine-tree`/raw-mirror) unit.
    UnitSalt,
    /// 16-byte `path_salt` of a touched file.
    PathSalt,
    /// 16-byte `file_salt` of a fully revealed file.
    FileSalt,
    /// 32-byte GGM fine-seed root `s_root` of a fully revealed file.
    SRoot,
    /// 32-byte GGM covering seed inside a leaf-exact sub-cover.
    GgmCoveringSeed,
    /// 32-byte boundary Merkle node hash on a path to `fine_root`.
    BoundaryNodeHash,
}

impl LengthField {
    /// The spec-mandated exact byte length for this field class
    /// (MVP-SPEC.md line 121).
    #[must_use]
    pub const fn spec_len(self) -> u64 {
        match self {
            Self::UnitSalt | Self::PathSalt | Self::FileSalt => 16,
            Self::SRoot | Self::GgmCoveringSeed | Self::BoundaryNodeHash => 32,
        }
    }
}

impl fmt::Display for LengthField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::UnitSalt => "unit_salt",
            Self::PathSalt => "path_salt",
            Self::FileSalt => "file_salt",
            Self::SRoot => "s_root",
            Self::GgmCoveringSeed => "GGM covering seed",
            Self::BoundaryNodeHash => "boundary Merkle node hash",
        })
    }
}

/// How a file's non-mirror unit ranges violate the tiling invariant.
///
/// MVP-SPEC.md line 121: "**non-mirror** unit byte-ranges sorted,
/// non-overlapping, and exactly tiling \[0, size) per file". Carried by
/// [`VerifyError::TilingViolation`] (R3's
/// `TilingViolation{unsorted|overlap|gap|out_of_bounds}`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TilingViolationKind {
    /// Ranges are not sorted by start offset.
    Unsorted,
    /// Two ranges overlap.
    Overlap,
    /// A byte in `[0, size)` is covered by no range.
    Gap,
    /// A range extends beyond `size` (or otherwise leaves `[0, size)`).
    OutOfBounds,
}

impl fmt::Display for TilingViolationKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Unsorted => "unsorted",
            Self::Overlap => "overlap",
            Self::Gap => "gap",
            Self::OutOfBounds => "out-of-bounds",
        })
    }
}

/// Full-reveal-only material: the two secrets a bundle may carry **only**
/// for a fully revealed file.
///
/// MVP-SPEC.md line 121: partial-reveal isolation forbids them on partial
/// reveals; the full-reveal cross-checks require them on full reveals.
/// Carried by [`VerifyError::PartialRevealSaltLeak`] and
/// [`VerifyError::FullRevealMaterialMissing`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FullRevealMaterial {
    /// The file's 16-byte content-commitment salt `file_salt`.
    FileSalt,
    /// The file's 32-byte GGM fine-seed root `s_root`.
    SRoot,
}

impl fmt::Display for FullRevealMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::FileSalt => "file_salt",
            Self::SRoot => "s_root",
        })
    }
}

/// Which whole-file content commitment a full-reveal concatenation check
/// failed against.
///
/// MVP-SPEC.md line 121: "on a full file reveal, the concatenated
/// non-mirror unit bytes must hash to `canon_commit` (text) /
/// `raw_commit` (binary)". Carried by
/// [`VerifyError::ConcatCommitMismatch`] (R4's
/// `ConcatCommitMismatch{canon|raw}`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentCommitKind {
    /// `canon_commit` — the salted commitment over canonical text bytes.
    Canon,
    /// `raw_commit` — the salted commitment over raw bytes.
    Raw,
}

impl fmt::Display for ContentCommitKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Canon => "canon_commit",
            Self::Raw => "raw_commit",
        })
    }
}

/// How the **signed manifest** binds a unit's content — the
/// single-authoritative-commitment rule of MVP-SPEC.md line 94, as a
/// discriminator (the R-side projection of
/// [`crate::crypto::disclosure::UnitBinding`]).
///
/// Carried by [`VerifyError::RevealModeMismatch`], where it names the
/// mode the manifest declares; the bundle's reveal section is the other
/// half of the disagreement and is implied by it (there are exactly two
/// modes, so naming one names both).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindingMode {
    /// The manifest binds the unit **solely** through the file's
    /// `fine_root`; the bundle must reveal it as a *covered* reveal
    /// carrying a leaf-exact GGM sub-cover + boundary path.
    FineTreeCovered,
    /// The manifest binds the unit through its own `unit_commit`
    /// (`--no-fine-tree` whole-file units and raw mirrors); the bundle
    /// must reveal it as a *non-covered* reveal carrying `unit_salt`.
    NonCovered,
}

impl fmt::Display for BindingMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::FineTreeCovered => "fine-tree-covered",
            Self::NonCovered => "non-covered",
        })
    }
}

/// Typed, field-identifying verification failure (D27 fail-fast mode).
///
/// One variant per failure class the R domain owns; each
/// (variant, discriminant) pair has a distinct stable code
/// ([`Self::code`]) — the R-side hook for Q7's error-code stability
/// contract. Payload fields identify the failing subject (`unit_id` /
/// `file_id`, work-global LE64 ordinals per MVP-SPEC.md line 76) and
/// observed vs expected quantities. **Never** secret material.
///
/// Spec-invariant → variant map (MVP-SPEC.md line 121; also R2–R4 Accept
/// lists): exact lengths → [`Self::WrongLength`]; `true_length` =
/// byte-range width → [`Self::TrueLengthRangeMismatch`]; `true_length` =
/// AEAD-plaintext length after strip (the `padded_length` formula) →
/// [`Self::PaddedLengthMismatch`]; all-zero padding →
/// [`Self::NonZeroPadding`]; non-mirror tiling →
/// [`Self::TilingViolation`] / [`Self::RawMirrorInTilingSet`];
/// full-reveal concat + tree rebuild → [`Self::ConcatCommitMismatch`],
/// [`Self::FineRootRebuildMismatch`], [`Self::FullRevealMaterialMissing`]
/// (and, per D74, [`Self::FullRevealSRootWithoutFineTree`] for the
/// symmetric *unexpected-material* direction);
/// raw-mirror ↔ canonical binding →
/// [`Self::RawMirrorCanonicalizationMismatch`] (plus
/// [`Self::RawCommitMismatch`] for the mirror's `raw_commit` opening);
/// partial-reveal isolation → [`Self::PartialRevealSaltLeak`]. The
/// remaining variants carry the evidence-layer decrypt/binding steps
/// (line 118) and bundle referential integrity (R3). Line 121's
/// position-and-total-size display guardrail is not an error class — it
/// is modeled structurally by [`super::report::RevealSet`].
///
/// # Cross-domain wrapper arms (integration extension point)
///
/// Failures produced by the sibling domains surface through this same
/// enum via wrapper arms (each `#[error(transparent)]`-style or with a
/// `#[source]`, keeping the wrapped error's own distinct code surfaced
/// via a `code()` delegation arm).
///
/// **Landed:**
///
/// - [`Self::Codec`] — F (landed with F3): strict-canonical CBOR decode
///   rejections (duplicate keys, non-shortest ints/lengths, indefinite
///   lengths, out-of-order keys, floats/simples/tags, trailing bytes,
///   invalid UTF-8, plus the totality classes; MVP-SPEC.md line 73).
///   Codes are `cbor-`-prefixed, delegated from
///   [`crate::codec::DecodeError::code`]. Unknown-key and cap errors
///   arrive later through the same arm's wrapped type or as F5/F8/F11
///   extend the codec taxonomy.
///
/// - [`Self::Crypto`] — C (landed with R2): the full C4 taxonomy with
///   codes delegated from [`crate::crypto::CryptoError::code`]
///   (`crypto-`-prefixed). Deliberately **no** `#[from]`: R2's per-unit
///   stage maps its decrypt/padding/commit failures into the named,
///   field-identifying variants above (`UnitDecryptFailed`,
///   `PaddedLengthMismatch`, `NonZeroPadding`, `UnitCommitMismatch`), and
///   an auto-`From` would let a stray `?` silently bypass that mapping —
///   so wrapping a crypto error is always an explicit, reviewed act. The
///   arm's live rows arrive with C14's signature/`sig_policy` stage
///   (R5); until then it is the defensive-totality outlet for crypto
///   classes no named variant owns.
/// - The G **fine-tree** wrapper (landed with R2):
///   [`Self::FineRootBindingFailed`] carries its `#[source]`
///   [`FineTreeError`] (the G13 seam placeholder in
///   [`super::unit_stages`]), with per-class codes so G's over-broad-
///   cover rejection surfaces distinctly through R2's covered-unit
///   stage.
///
/// - [`Self::Canon`] — G (landed with R4): canonicalization failures
///   outside the fine tree — descriptor-version dispatch and the
///   `canonicalize_v` recompute of the raw-mirror ↔ canonical binding.
///   Codes are `content-`-prefixed, delegated from
///   [`crate::canon::CanonicalizeError::code`]. Like [`Self::Crypto`] it
///   has **no** `#[from]`: R4's binding stage maps *content disagreement*
///   to [`Self::RawMirrorCanonicalizationMismatch`], and only a genuine
///   canonicalization failure (an unregistered Unicode version — "upgrade
///   the verifier", never an integrity verdict) travels through this arm.
///
/// **Still pending — the integrator adds these at merge:**
///
/// - `Anchor(…)` — A: anchor-artifact **structural** failures only.
///   NOTE: most anchor outcomes are per-anchor report *states*
///   (`invalid`, `internally-consistent-only`, …), not errors — Q7
///   expects verdict-state outcomes for those rows (see D27 §4).
///
/// Adding an arm deliberately breaks the exhaustive matches in
/// [`Self::code`] and in the distinctness test below — that is the
/// mechanism forcing the integrator to assign the new arm a distinct
/// stable code and an exemplar. This enum is intentionally **not**
/// `#[non_exhaustive]` for the same reason.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VerifyError {
    // ── Per-unit evidence stages (R2; MVP-SPEC.md lines 91, 118, 121) ──
    /// AEAD decryption of a revealed unit's embedded ciphertext failed
    /// (flipped ciphertext, wrong `k_u`, or a swapped unit caught by the
    /// AAD's `unit_id` binding — MVP-SPEC.md line 91).
    #[error("unit {unit_id}: AEAD decryption failed")]
    UnitDecryptFailed {
        /// Work-global id of the unit whose ciphertext failed to open.
        unit_id: u64,
    },

    /// The AEAD plaintext length does not equal the recomputed
    /// `padded_length = ⌈(true_length + 1) / 256⌉ · 256` — silent over-
    /// or under-padding (MVP-SPEC.md lines 91, 121).
    #[error(
        "unit {unit_id}: AEAD plaintext length {actual} != padded_length {expected} recomputed from true_length"
    )]
    PaddedLengthMismatch {
        /// Work-global id of the offending unit.
        unit_id: u64,
        /// `padded_length` recomputed from the manifest's `true_length`.
        expected: u64,
        /// Observed AEAD plaintext length.
        actual: u64,
    },

    /// A padding byte beyond `true_length` is not `0x00`
    /// (MVP-SPEC.md line 121: padding "is all-zero beyond `true_length`").
    #[error("unit {unit_id}: non-zero padding byte at plaintext offset {offset}")]
    NonZeroPadding {
        /// Work-global id of the offending unit.
        unit_id: u64,
        /// Plaintext offset of the first non-zero pad byte.
        offset: u64,
    },

    /// The manifest's `true_length` does not equal the unit's byte-range
    /// width — a unit claiming more span than it reveals
    /// (MVP-SPEC.md line 121: "`true_length` = its byte-range width").
    #[error("unit {unit_id}: true_length {true_length} != byte-range width {range_width}")]
    TrueLengthRangeMismatch {
        /// Work-global id of the offending unit.
        unit_id: u64,
        /// `true_length` recorded in the manifest unit table.
        true_length: u64,
        /// Width of the unit's manifest byte-range.
        range_width: u64,
    },

    /// A fine-tree-covered unit's bytes failed the GGM sub-cover → leaf →
    /// boundary-path verification against `fine_root`
    /// (MVP-SPEC.md lines 96, 118) — the G wrapper arm, landed with its
    /// R2 consumer per the extension-point plan. Wraps G's
    /// range-verification failure ([`FineTreeError`], the G13 seam type in
    /// [`super::unit_stages`]); [`Self::code`] discriminates on the
    /// wrapped class, so the over-broad-cover rejection (a cover node
    /// spanning an unrevealed real leaf) is its own distinct tamper row,
    /// never folded into the generic root mismatch. G13's future
    /// `FineTreeError` variants each compile-break `code()` until they
    /// receive distinct codes.
    #[error(
        "unit {unit_id}: leaf-range/boundary-path verification against fine_root failed ({source})"
    )]
    FineRootBindingFailed {
        /// Work-global id of the covered unit that failed binding.
        unit_id: u64,
        /// G's range-verification failure class (G13 seam).
        #[source]
        source: FineTreeError,
    },

    /// A non-covered (`--no-fine-tree`/raw-mirror) unit's recomputed
    /// `unit_commit = SHA-256(0x02 ‖ unit_salt ‖ bytes)` does not match
    /// the manifest (MVP-SPEC.md lines 94, 118).
    #[error("unit {unit_id}: recomputed unit_commit does not match the manifest")]
    UnitCommitMismatch {
        /// Work-global id of the non-covered unit that failed its opening.
        unit_id: u64,
    },

    // ── Structural checks (R3; MVP-SPEC.md line 121) ──
    /// A disclosed salt/seed/node hash has the wrong length
    /// (MVP-SPEC.md line 121 exact-length rule; one distinct code per
    /// [`LengthField`] class).
    #[error("{field} has length {actual}, spec requires exactly {expected}")]
    WrongLength {
        /// Which length-checked field class failed.
        field: LengthField,
        /// The spec length for that class (16 or 32).
        expected: u64,
        /// Observed length.
        actual: u64,
    },

    /// A bundle entry references a `unit_id` absent from the manifest
    /// unit table (referential integrity, R3).
    #[error("bundle references unit {unit_id}, which does not exist in the manifest unit table")]
    UnknownUnitRef {
        /// The dangling unit id.
        unit_id: u64,
    },

    /// The same `unit_id` is revealed more than once in the bundle
    /// (referential integrity, R3).
    #[error("unit {unit_id} is revealed more than once in the bundle")]
    DuplicateUnitReveal {
        /// The duplicated unit id.
        unit_id: u64,
    },

    /// A bundle entry references a `file_id` absent from the manifest
    /// file table (referential integrity, R3).
    #[error("bundle references file {file_id}, which does not exist in the manifest file table")]
    UnknownFileRef {
        /// The dangling file id.
        file_id: u64,
    },

    /// A file's non-mirror unit byte-ranges are not sorted,
    /// non-overlapping, and exactly tiling `[0, size)`
    /// (MVP-SPEC.md line 121; runs on partial reveals too — it is a
    /// manifest-level invariant).
    #[error("file {file_id}: non-mirror unit ranges violate the tiling invariant ({kind})")]
    TilingViolation {
        /// The file whose unit table fails to tile.
        file_id: u64,
        /// Which way the tiling invariant is violated.
        kind: TilingViolationKind,
    },

    /// A raw-mirror unit participates in the tiling set despite its
    /// `kind` exemption (MVP-SPEC.md lines 92, 121: "raw-mirror units
    /// are exempt by `kind`").
    #[error("unit {unit_id}: raw-mirror unit wrongly participates in the tiling set")]
    RawMirrorInTilingSet {
        /// Work-global id of the misplaced raw-mirror unit.
        unit_id: u64,
    },

    /// A touched file's recomputed
    /// `path_commit = SHA-256(0x05 ‖ path_salt ‖ path_utf8)` does not
    /// match the manifest (MVP-SPEC.md line 95).
    #[error("file {file_id}: recomputed path_commit does not match the manifest")]
    PathCommitMismatch {
        /// The file whose disclosed path failed its commitment opening.
        file_id: u64,
    },

    // ── Bundle ↔ manifest coherence (R5; see `super::coherence`) ──
    /// A revealed unit's owning file has no `touched_files` entry, so the
    /// recipient cannot verify the path of what they were shown
    /// (**decision D80**, on MVP-SPEC.md line 95: `path_salt` "ships
    /// whenever any reveal *touches* the file", and line 121 defines no
    /// rendering state for "revealed content, path withheld").
    ///
    /// Distinct from F8's `bundle-full-reveal-without-touched-file`,
    /// which is the *whole-file* case and is decidable from the bundle
    /// alone (tier `[X]`). This one needs the manifest's unit table to
    /// map `unit_id → file_id`, which D78 keeps out of the bundle layer.
    #[error("unit {unit_id}: owning file {file_id} has no touched_files entry")]
    RevealedUnitFileNotTouched {
        /// The revealed unit whose owning file was not disclosed.
        unit_id: u64,
        /// That owning file, per the manifest unit table.
        file_id: u64,
    },

    /// A `touched_files` entry names a file the bundle reveals no unit of
    /// (**decision D82**, closing the converse half D80 left open:
    /// `touched_files` must *equal* the set of files with a revealed unit).
    ///
    /// MVP-SPEC.md line 95 says bundle recipients see unrevealed files
    /// "only as committed placeholders", and line 121's rendering taxonomy
    /// names the state — an unrevealed file renders as a placeholder with
    /// its **path withheld**. A disclosed path for a file with no revealed
    /// unit is therefore a disclosure the format does not define, and the
    /// verifier discards its verified value anyway
    /// ([`reveal_set`](super::pipeline)).
    ///
    /// It is not a forgery — `path_salt = HKDF(W, "path-salt", file_id)` is
    /// a per-work constant, so any party holding another bundle of the same
    /// work can splice a *genuine* `{path, path_salt}` pair in, overriding
    /// the sealer's per-bundle disclosure decision. That is the D74
    /// add-material hole in the touched-file section, and this closes it.
    #[error("file {file_id}: touched_files entry for a file with no revealed unit")]
    TouchedFileWithoutRevealedUnit {
        /// The disclosed file that no reveal touches.
        file_id: u64,
    },

    /// The bundle reveals a unit in the wrong reveal section for the way
    /// the **signed manifest** binds it (MVP-SPEC.md line 94): a
    /// fine-tree-covered unit shipped as a non-covered reveal (so it
    /// carries a `unit_salt` for a `unit_commit` that does not exist), or
    /// a non-covered unit shipped as a covered reveal (so it carries a
    /// GGM cover for a file whose bytes are not tree-bound).
    ///
    /// Neither layer can catch this alone: the bundle is well formed on
    /// its own bytes (D78 keeps F8 out of the manifest) and the manifest
    /// is internally consistent (F5 already ties each unit's binding to
    /// its file's fine-tree state). It is exactly the "well-formed but
    /// inconsistent with its manifest" class the error-code contract §2
    /// assigns to R's unprefixed namespace.
    #[error("unit {unit_id}: manifest binds it {manifest_binding}, bundle reveals it otherwise")]
    RevealModeMismatch {
        /// The unit revealed in the wrong section.
        unit_id: u64,
        /// How the manifest binds it (the bundle did the other thing).
        manifest_binding: BindingMode,
    },

    // ── File-level reveal-shape checks (R4; MVP-SPEC.md line 121) ──
    /// The bundle contains `file_salt` or `s_root` for a file that is
    /// only **partially** revealed — a violation of partial-reveal
    /// isolation (MVP-SPEC.md line 121: the bundle "MUST NOT contain
    /// that file's `file_salt` or `s_root`"; the leaf-exact GGM
    /// sub-cover of a covered per-unit reveal is explicitly permitted
    /// and does not raise this error).
    #[error("file {file_id}: bundle contains {material} for a partially revealed file")]
    PartialRevealSaltLeak {
        /// The partially revealed file whose secret material leaked.
        file_id: u64,
        /// Which forbidden material is present.
        material: FullRevealMaterial,
    },

    /// A full-file reveal is missing its `file_salt` (or its `s_root`,
    /// when the descriptor records a fine tree), so the mandatory
    /// full-reveal cross-checks of MVP-SPEC.md line 121 ("the verifier
    /// MUST rebuild") cannot run.
    ///
    /// Strictness is resolved by **D28**
    /// (`docs/decisions/D28-full-reveal-strictness.md`): format v1 has no
    /// "reveal every unit but withhold the whole-file openings" shape, so
    /// omission is a hard failure rather than a weaker-but-valid reveal.
    #[error("file {file_id}: full reveal is missing its {material}")]
    FullRevealMaterialMissing {
        /// The fully revealed file with absent material.
        file_id: u64,
        /// Which required material is absent.
        material: FullRevealMaterial,
    },

    /// A full-file reveal carries an `s_root` for a file whose manifest
    /// records **no** fine tree (`--no-fine-tree`, or an empty file —
    /// [`crate::manifest::body::FineTree::Absent`]).
    ///
    /// The symmetric *unexpected* direction of
    /// [`Self::FullRevealMaterialMissing`], resolved by **D74** as a hard
    /// rejection: R4's typed classifier has nowhere to put such a value
    /// ([`super::file_stages::FullRevealFineTree::Absent`] carries no
    /// `s_root` field), and this project does not carry unverifiable
    /// fields in an adversarial format — the same present-set-equals-
    /// required-set rule C14 applies to `sig_policy` (MVP-SPEC.md line 97:
    /// "the present signature set MUST equal the policy set … or present
    /// but unlisted").
    ///
    /// One code, not two: a `file_salt` arm would be unreachable, since
    /// `file_salt` is *always* required on a full reveal, so an
    /// unexpected-`file_salt` state cannot exist. (F8 reaches the same
    /// conclusion from the wire side: key 1 is `req` at schema level, so a
    /// full-reveal entry without `file_salt` is rejected as
    /// `bundle-missing-key` before R4 ever runs.)
    ///
    /// The permissive reading — silently ignoring the stray seed — was
    /// rejected because a bundle that ships material the schema has no use
    /// for is either built by a confused producer or probing for a lenient
    /// verifier, and neither deserves a pass. Distinct from
    /// [`Self::PartialRevealSaltLeak`]`{ material: SRoot }`, which fires
    /// when the file is *not* fully revealed: here the reveal is legitimate
    /// and the material is not.
    #[error("file {file_id}: full reveal carries an s_root but the manifest records no fine tree")]
    FullRevealSRootWithoutFineTree {
        /// The fully revealed, fine-tree-less file carrying a stray `s_root`.
        file_id: u64,
    },

    /// On a full file reveal, the concatenated non-mirror unit bytes do
    /// not hash (under `file_salt`) to the file's content commitment
    /// (MVP-SPEC.md line 121; `canon_commit` for text, `raw_commit` for
    /// binary).
    #[error("file {file_id}: concatenated unit bytes do not match {commit}")]
    ConcatCommitMismatch {
        /// The fully revealed file that failed its concatenation check.
        file_id: u64,
        /// Which whole-file commitment the bytes were checked against.
        commit: ContentCommitKind,
    },

    /// A fully revealed file's disclosed `s_root` violates D83's canonical
    /// leaf-level payload rule.
    ///
    /// Reachable **only at `n == 1`**, where `d == 0` makes the GGM grid
    /// root itself a leaf: the verifier then reads `salt_0 = s_root[..16]`
    /// with no descent (MVP-SPEC.md line 96), so bytes `16..32` are never
    /// hashed and v1 fixes them at zero (`docs/format/registry-v1.md` §7.14
    /// key 2). At every larger `n` the check is a no-op.
    ///
    /// **Delegating arm, no new code.** [`Self::code`] surfaces the wrapped
    /// [`FineTreeError::LeafSeedTailNotZero`]'s own
    /// `fine-root-leaf-seed-tail-not-zero` unchanged — a code names a
    /// rejection *class*, never a site (`docs/testing/error-code-contract.md`
    /// §2), and this class already has one from
    /// [`Self::FineRootBindingFailed`]'s side of the seam. The two sites are
    /// separated in the fixture table by `(code, layer)`.
    #[error("file {file_id}: disclosed s_root is not the canonical leaf-level payload ({source})")]
    FineRootSeedTailNotCanonical {
        /// The fully revealed one-leaf file whose `s_root` was not canonical.
        file_id: u64,
        /// G's value-rule failure ([`FineTreeError::LeafSeedTailNotZero`]).
        #[source]
        source: FineTreeError,
    },

    /// On a full file reveal, the fine tree rebuilt from the bundled
    /// `s_root` over the revealed bytes does not match the manifest's
    /// `fine_root` (MVP-SPEC.md line 121: "the verifier MUST rebuild the
    /// whole fine tree from those bytes and match `fine_root`").
    #[error("file {file_id}: fine tree rebuilt from s_root does not match fine_root")]
    FineRootRebuildMismatch {
        /// The fully revealed file whose fine-tree rebuild diverged.
        file_id: u64,
    },

    /// A revealed raw-mirror's bytes do not open the file's
    /// `raw_commit = SHA-256(0x03 ‖ file_salt ‖ raw_bytes)`
    /// (MVP-SPEC.md line 92: the mirror's verify path).
    #[error("file {file_id}: raw-mirror bytes do not match raw_commit")]
    RawCommitMismatch {
        /// The file whose raw-mirror failed its `raw_commit` opening.
        file_id: u64,
    },

    /// Raw-mirror ↔ canonical binding failed:
    /// `canonicalize_v(raw_mirror_bytes)` under the descriptor-recorded
    /// Unicode version does not equal the validated canonical bytes —
    /// the co-timestamped-"original" equivocation
    /// (MVP-SPEC.md line 121).
    #[error("file {file_id}: canonicalized raw-mirror bytes != validated canonical bytes")]
    RawMirrorCanonicalizationMismatch {
        /// The file whose mirror does not canonicalize to its content.
        file_id: u64,
    },

    // ── Cross-domain wrapper arms (see the enum-level doc) ──────────
    /// F: the `.sealproof` failed one of the **three strict decode
    /// layers** (F9's [`SealProof::decode`] — bundle schema, manifest
    /// envelope, manifest body). This is R5's stage-1 arm: the wrapped
    /// [`SealProofError`] already keeps `bundle-*` and `manifest-*`
    /// separate (D78) and reports which layer rejected, and its inner
    /// code — `bundle-*`, `manifest-*`, or a delegated `cbor-*` — is
    /// surfaced unchanged through [`Self::code`].
    ///
    /// **Intentionally no `#[from]`** (the [`Self::Crypto`] rule): the
    /// decode stage is the only legitimate producer, so wrapping stays an
    /// explicit act at that one call site.
    ///
    /// [`SealProof::decode`]: crate::bundle::SealProof::decode
    /// [`SealProofError`]: crate::bundle::SealProofError
    #[error(transparent)]
    Decode(crate::bundle::SealProofError),

    /// F: the bundle/manifest/body bytes failed the strict canonical
    /// CBOR decode layer (MVP-SPEC.md line 73; task F3). The wrapped
    /// error's distinct `cbor-*` code is surfaced unchanged through
    /// [`Self::code`], so every codec rejection class stays its own
    /// tamper-matrix row. Positions inside the wrapped error are
    /// relative to the decoded slice (outer envelope or inner body);
    /// which layer was being decoded is pipeline context the R5
    /// orchestrator reports, not part of the code.
    #[error(transparent)]
    Codec(#[from] crate::codec::DecodeError),

    /// C: a crypto failure surfacing through the pipeline **outside** the
    /// classes owned by a named variant above (task R2 landed the arm;
    /// C14's signature/`sig_policy` stage is its main future producer —
    /// see the enum-level doc). The wrapped error's distinct `crypto-*`
    /// code ([`crate::crypto::CryptoError::code`]) is surfaced unchanged
    /// through [`Self::code`]. **Intentionally no `#[from]`** — wrapping
    /// must be explicit so it can never bypass R2's named-variant mapping
    /// (enum-level doc).
    #[error(transparent)]
    Crypto(crate::crypto::CryptoError),

    /// G: canonicalization itself failed while R4 recomputed the
    /// raw-mirror ↔ canonical binding (MVP-SPEC.md line 121). In practice
    /// this is exactly one condition — the file descriptor names a
    /// Unicode/canonicalization version this build does not register
    /// (`content-unknown-unicode-version`), i.e. **this verifier is too
    /// old**, which must never be conflated with an integrity verdict
    /// (`crate::canon::CanonicalizeError` docs).
    ///
    /// "In practice exactly one condition" became **structurally exactly
    /// one** at G22. R4's recompute now goes through
    /// [`crate::canon::canonicalize_v_forced`], whose error type is
    /// [`crate::canon::UnicodeVersionError`] — a type that cannot express
    /// [`crate::canon::CanonicalizeError::InvalidUtf8`] — so this arm's
    /// only reachable inhabitant is `UnknownVersion`, by the signatures
    /// rather than by the argument R4 happens to pass. The seam's whole
    /// code set is stated and tested as
    /// [`super::file_stages::CANONICALIZATION_SEAM_CODES`].
    ///
    /// The **payload type is deliberately left wide**: narrowing it to
    /// `UnicodeVersionError` would retire `content-canonicalize-invalid-utf8`
    /// from R's code set, and codes are append-only (§3 of the error-code
    /// contract). The variant stays admissible and coded; it simply has no
    /// verifier-side producer.
    ///
    /// **Intentionally no `#[from]`** (the [`Self::Crypto`] rule): content
    /// disagreement is [`Self::RawMirrorCanonicalizationMismatch`], and an
    /// auto-`From` would let a stray `?` silently reclassify an integrity
    /// failure as a canonicalization failure.
    #[error(transparent)]
    Canon(crate::canon::CanonicalizeError),
    // ── INTEGRATION EXTENSION POINT ─────────────────────────────────
    // The Anchor(A) wrapper arm is added HERE at merge — see the
    // enum-level doc comment for the contract. (Codec landed with F3;
    // Crypto and the FineRootBindingFailed source landed with R2; Canon
    // landed with R4.)
    // ────────────────────────────────────────────────────────────────
}

impl VerifyError {
    /// Stable machine-readable code, pairwise-distinct across every
    /// (variant, discriminant) pair — the R-side implementation of Q7's
    /// error-code stability contract (tamper-matrix rows key on these).
    ///
    /// Codes are lowercase kebab-case and never change once a tamper row
    /// binds to them; the exhaustive matches here are the compile-time
    /// guard forcing any new arm (e.g. the integration wrapper arms) to
    /// receive a distinct code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::UnitDecryptFailed { .. } => "unit-decrypt-failed",
            Self::PaddedLengthMismatch { .. } => "padded-length-mismatch",
            Self::NonZeroPadding { .. } => "non-zero-padding",
            Self::TrueLengthRangeMismatch { .. } => "true-length-range-mismatch",
            // Discriminated on the wrapped G13 class. Since G13 landed the
            // full taxonomy in `content::fine_tree::error`, the inner code
            // is surfaced **unchanged** — the wrapper rule of
            // `docs/testing/error-code-contract.md` §2, so each fine-tree
            // outcome has exactly one code. `FineTreeError::code` is
            // itself a wildcard-free `const fn`, so a new class still
            // fails compilation there until it gets a distinct code. The
            // generic binding failure keeps R1's original code; the
            // over-broad-cover rejection remains its own tamper row (R2
            // accept; MVP-SPEC.md line 96 leaf-exact-cover rule).
            Self::FineRootBindingFailed { source, .. } => source.code(),
            Self::UnitCommitMismatch { .. } => "unit-commit-mismatch",
            Self::WrongLength { field, .. } => match field {
                LengthField::UnitSalt => "wrong-length-unit-salt",
                LengthField::PathSalt => "wrong-length-path-salt",
                LengthField::FileSalt => "wrong-length-file-salt",
                LengthField::SRoot => "wrong-length-s-root",
                LengthField::GgmCoveringSeed => "wrong-length-ggm-covering-seed",
                LengthField::BoundaryNodeHash => "wrong-length-boundary-node-hash",
            },
            Self::UnknownUnitRef { .. } => "unknown-unit-ref",
            Self::DuplicateUnitReveal { .. } => "duplicate-unit-reveal",
            Self::UnknownFileRef { .. } => "unknown-file-ref",
            Self::TilingViolation { kind, .. } => match kind {
                TilingViolationKind::Unsorted => "tiling-unsorted",
                TilingViolationKind::Overlap => "tiling-overlap",
                TilingViolationKind::Gap => "tiling-gap",
                TilingViolationKind::OutOfBounds => "tiling-out-of-bounds",
            },
            Self::RawMirrorInTilingSet { .. } => "raw-mirror-in-tiling-set",
            Self::PathCommitMismatch { .. } => "path-commit-mismatch",
            Self::RevealedUnitFileNotTouched { .. } => "revealed-unit-file-not-touched",
            Self::TouchedFileWithoutRevealedUnit { .. } => "touched-file-without-revealed-unit",
            // Named from the *bundle's* mistake, since that is what a
            // tamper row mutates: the manifest side is the fixed fact.
            Self::RevealModeMismatch {
                manifest_binding, ..
            } => match manifest_binding {
                BindingMode::FineTreeCovered => "covered-unit-revealed-as-non-covered",
                BindingMode::NonCovered => "non-covered-unit-revealed-as-covered",
            },
            Self::PartialRevealSaltLeak { material, .. } => match material {
                FullRevealMaterial::FileSalt => "partial-reveal-salt-leak-file-salt",
                FullRevealMaterial::SRoot => "partial-reveal-salt-leak-s-root",
            },
            Self::FullRevealMaterialMissing { material, .. } => match material {
                FullRevealMaterial::FileSalt => "full-reveal-material-missing-file-salt",
                FullRevealMaterial::SRoot => "full-reveal-material-missing-s-root",
            },
            Self::FullRevealSRootWithoutFineTree { .. } => "full-reveal-s-root-without-fine-tree",
            Self::ConcatCommitMismatch { commit, .. } => match commit {
                ContentCommitKind::Canon => "concat-commit-mismatch-canon",
                ContentCommitKind::Raw => "concat-commit-mismatch-raw",
            },
            // D83's second call site. Delegates, exactly as
            // `FineRootBindingFailed` does: one rejection class, one code,
            // two layers (error-code contract §2).
            Self::FineRootSeedTailNotCanonical { source, .. } => source.code(),
            Self::FineRootRebuildMismatch { .. } => "fine-root-rebuild-mismatch",
            Self::RawCommitMismatch { .. } => "raw-commit-mismatch",
            Self::RawMirrorCanonicalizationMismatch { .. } => {
                "raw-mirror-canonicalization-mismatch"
            }
            // Wrapper arms: the wrapped error's own distinct stable code
            // (`bundle-*` / `manifest-*` / `cbor-*` / `crypto-*` /
            // `content-*`) is the row key — never flattened or renamed.
            Self::Decode(e) => e.code(),
            Self::Codec(e) => e.code(),
            Self::Crypto(e) => e.code(),
            Self::Canon(e) => e.code(),
        }
    }
}

/// Ordered, non-empty multi-finding collection for rendering (D27 §2–3).
///
/// The fail-fast [`VerifyError`] stays authoritative: by construction the
/// first element ([`Self::primary`]) is the error the fail-fast path
/// returns for the same input — R5 builds both modes from one stage list
/// and R7/R10 property-test the equality. Additional findings come only
/// from *independent* checks whose prerequisites were established
/// (no speculative cascades), ordered by stage then subject id, so the
/// collection is deterministic. Non-emptiness is by construction:
/// [`Self::new`] requires the primary and no `Default` exists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyFailures {
    /// The tamper-matrix-authoritative first error (== fail-fast result).
    primary: VerifyError,
    /// Further independent findings, in deterministic pipeline order.
    additional: Vec<VerifyError>,
}

impl VerifyFailures {
    /// Start a collection from the authoritative first finding.
    #[must_use]
    pub const fn new(primary: VerifyError) -> Self {
        Self {
            primary,
            additional: Vec::new(),
        }
    }

    /// Append a later independent finding (rendering detail; never
    /// reorders or displaces the primary).
    pub fn push(&mut self, finding: VerifyError) {
        self.additional.push(finding);
    }

    /// The authoritative first error — identical to what the fail-fast
    /// `verify_bundle` path returns for the same input (D27 invariant).
    #[must_use]
    pub const fn primary(&self) -> &VerifyError {
        &self.primary
    }

    /// Consume the collection and yield the authoritative first error.
    ///
    /// This is how the two D27 entry points share **one** stage list:
    /// [`verify_bundle`](super::verify_bundle) runs the collecting
    /// pipeline with collection disabled and unwraps the (necessarily
    /// single-finding) result through here, so "primary == fail-fast"
    /// holds by construction rather than by parallel implementations.
    #[must_use]
    pub fn into_primary(self) -> VerifyError {
        self.primary
    }

    /// The findings after the primary, in deterministic pipeline order.
    #[must_use]
    pub fn additional(&self) -> &[VerifyError] {
        &self.additional
    }

    /// Total number of findings (always ≥ 1).
    #[must_use]
    pub fn count(&self) -> usize {
        1 + self.additional.len()
    }

    /// All findings in order, primary first.
    pub fn iter(&self) -> impl Iterator<Item = &VerifyError> {
        core::iter::once(&self.primary).chain(self.additional.iter())
    }
}

impl From<VerifyError> for VerifyFailures {
    fn from(primary: VerifyError) -> Self {
        Self::new(primary)
    }
}

impl fmt::Display for VerifyFailures {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "verification failed with {} finding(s); primary: {}",
            self.count(),
            self.primary
        )
    }
}

impl std::error::Error for VerifyFailures {}

/// One exemplar per (variant, discriminant) pair — every distinct
/// [`VerifyError::code`] appears exactly once. Shared by the
/// distinctness, redaction, and Display tests. Kept next to the enum so
/// the integrator extends it together with the wrapper arms (the
/// exhaustive tally in `tests::codes_are_pairwise_distinct_and_stable`
/// breaks the build otherwise).
#[cfg(test)]
pub(crate) fn all_error_exemplars() -> Vec<VerifyError> {
    use crate::codec::{DecodeError as CodecError, ForbiddenKind};
    use VerifyError as E;
    let mut exemplars = vec![
        E::UnitDecryptFailed { unit_id: 3 },
        E::PaddedLengthMismatch {
            unit_id: 4,
            expected: 512,
            actual: 768,
        },
        E::NonZeroPadding {
            unit_id: 5,
            offset: 300,
        },
        E::TrueLengthRangeMismatch {
            unit_id: 6,
            true_length: 250,
            range_width: 260,
        },
        // One exemplar per wrapped G13 class. Sourced from G's own
        // exemplar list so R can never fall behind the taxonomy: adding a
        // class there adds a row here automatically, and the tally below
        // states the expected count so a *silent* addition still fails.
    ];
    exemplars.extend(
        crate::content::fine_tree::error::all_code_exemplars()
            .into_iter()
            .map(|source| E::FineRootBindingFailed { unit_id: 7, source }),
    );
    exemplars.extend(vec![
        E::UnitCommitMismatch { unit_id: 8 },
        E::WrongLength {
            field: LengthField::UnitSalt,
            expected: 16,
            actual: 15,
        },
        E::WrongLength {
            field: LengthField::PathSalt,
            expected: 16,
            actual: 17,
        },
        E::WrongLength {
            field: LengthField::FileSalt,
            expected: 16,
            actual: 32,
        },
        E::WrongLength {
            field: LengthField::SRoot,
            expected: 32,
            actual: 16,
        },
        E::WrongLength {
            field: LengthField::GgmCoveringSeed,
            expected: 32,
            actual: 31,
        },
        E::WrongLength {
            field: LengthField::BoundaryNodeHash,
            expected: 32,
            actual: 33,
        },
        E::UnknownUnitRef { unit_id: 99 },
        E::DuplicateUnitReveal { unit_id: 2 },
        E::UnknownFileRef { file_id: 41 },
        E::TilingViolation {
            file_id: 1,
            kind: TilingViolationKind::Unsorted,
        },
        E::TilingViolation {
            file_id: 1,
            kind: TilingViolationKind::Overlap,
        },
        E::TilingViolation {
            file_id: 1,
            kind: TilingViolationKind::Gap,
        },
        E::TilingViolation {
            file_id: 1,
            kind: TilingViolationKind::OutOfBounds,
        },
        E::RawMirrorInTilingSet { unit_id: 9 },
        E::PathCommitMismatch { file_id: 2 },
        E::RevealedUnitFileNotTouched {
            unit_id: 10,
            file_id: 2,
        },
        E::TouchedFileWithoutRevealedUnit { file_id: 2 },
        E::RevealModeMismatch {
            unit_id: 11,
            manifest_binding: BindingMode::FineTreeCovered,
        },
        E::RevealModeMismatch {
            unit_id: 12,
            manifest_binding: BindingMode::NonCovered,
        },
        E::PartialRevealSaltLeak {
            file_id: 3,
            material: FullRevealMaterial::FileSalt,
        },
        E::PartialRevealSaltLeak {
            file_id: 3,
            material: FullRevealMaterial::SRoot,
        },
        E::FullRevealMaterialMissing {
            file_id: 4,
            material: FullRevealMaterial::FileSalt,
        },
        E::FullRevealMaterialMissing {
            file_id: 4,
            material: FullRevealMaterial::SRoot,
        },
        E::FullRevealSRootWithoutFineTree { file_id: 4 },
        E::ConcatCommitMismatch {
            file_id: 5,
            commit: ContentCommitKind::Canon,
        },
        E::ConcatCommitMismatch {
            file_id: 5,
            commit: ContentCommitKind::Raw,
        },
        E::FineRootRebuildMismatch { file_id: 6 },
        E::RawCommitMismatch { file_id: 7 },
        E::RawMirrorCanonicalizationMismatch { file_id: 8 },
        // ── Decode wrapper arm (R5 stage 1, over F9's SealProof): one
        // exemplar per composition arm, each choosing an inner error
        // whose family is that arm's own — `bundle-` for layer 1,
        // `manifest-` for layers 2–3. The delegated `cbor-*` codes both
        // arms can also carry are already enumerated by the Codec arm
        // below, so exemplifying them here would collide by design
        // (error-code contract §2: one code, one owning domain, many
        // paths).
        E::Decode(crate::bundle::SealProofError::Bundle {
            source: crate::bundle::BundleError::UnitRevealedTwice { unit_id: 3 },
        }),
        // NB the manifest exemplar deliberately avoids
        // `ManifestError::SigPolicyEmpty`: its *code* is distinct from C's
        // (`manifest-sig-policy-empty` vs `crypto-sig-policy-empty`, a
        // recorded near-miss) but its `Display` text is word-for-word
        // identical, and `display_identifies_the_failing_subject` requires
        // the exemplar set's Display strings to be distinct too.
        E::Decode(crate::bundle::SealProofError::Manifest {
            source: crate::manifest::ManifestError::UnitIdMismatch {
                expected: 4,
                found: 9,
            },
        }),
        // ── Codec wrapper arm (F3): one exemplar per distinct cbor-*
        // code of crate::codec::DecodeError ──
        E::Codec(CodecError::Truncated { position: 10 }),
        E::Codec(CodecError::Malformed { position: 11 }),
        E::Codec(CodecError::ForbiddenType {
            kind: ForbiddenKind::Float,
            position: 12,
        }),
        E::Codec(CodecError::ForbiddenType {
            kind: ForbiddenKind::Simple,
            position: 13,
        }),
        E::Codec(CodecError::ForbiddenType {
            kind: ForbiddenKind::Tag,
            position: 14,
        }),
        E::Codec(CodecError::IndefiniteLength { position: 15 }),
        E::Codec(CodecError::NonShortestInt { position: 16 }),
        E::Codec(CodecError::NonShortestLength { position: 17 }),
        E::Codec(CodecError::DuplicateMapKey { position: 18 }),
        E::Codec(CodecError::UnsortedMapKeys { position: 19 }),
        E::Codec(CodecError::InvalidUtf8 { position: 20 }),
        E::Codec(CodecError::TrailingBytes {
            position: 21,
            trailing: 2,
        }),
        E::Codec(CodecError::NestingTooDeep { position: 22 }),
        E::Codec(CodecError::UnexpectedType {
            expected: crate::codec::ExpectedKind::Unsigned,
            found: crate::codec::ItemKind::Bytes,
            position: 23,
        }),
        E::Codec(CodecError::IntOutOfRange { position: 24 }),
    ]);
    // ── Crypto wrapper arm (R2): one exemplar per distinct crypto-*
    // code of crate::crypto::CryptoError (the C-side list owns the
    // per-discriminant enumeration; its own test pins the count) ──
    exemplars.extend(
        crate::crypto::error::all_code_exemplars()
            .into_iter()
            .map(E::Crypto),
    );
    // ── Canon wrapper arm (R4): one exemplar per distinct content-* code
    // of crate::canon::CanonicalizeError, sourced from G's own list so R
    // can never fall behind that taxonomy either ──
    exemplars.extend(
        crate::canon::canon_code_exemplars()
            .into_iter()
            .map(E::Canon),
    );
    exemplars
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use super::*;

    /// The number of distinct stable codes: 16 single-code variants plus
    /// the discriminated ones (WrongLength×6, TilingViolation×4,
    /// PartialRevealSaltLeak×2, FullRevealMaterialMissing×2,
    /// ConcatCommitMismatch×2, RevealModeMismatch×2,
    /// FineRootBindingFailed×**8** — one per delegated `fine-root-*`
    /// class of G13's taxonomy, the eighth being D83's
    /// `fine-root-leaf-seed-tail-not-zero`), plus the 2 exemplified composition arms
    /// of the Decode wrapper arm (R5: one `bundle-*`, one `manifest-*`),
    /// plus the 15 delegated `cbor-*` codes of the Codec wrapper arm (12
    /// codec variants, ForbiddenType×3), plus the 25 delegated `crypto-*`
    /// codes of the Crypto wrapper arm (CommitmentMismatch×5,
    /// SaltLength×3, four signature variants ×2 algorithms, 9 single-code
    /// variants), plus the 2 delegated `content-*` codes of the Canon
    /// wrapper arm (R4).
    ///
    /// The 14th single-code variant is D74's
    /// `FullRevealSRootWithoutFineTree` (R4); the 15th is D80's
    /// `RevealedUnitFileNotTouched` (R5); the 16th is D82's
    /// `TouchedFileWithoutRevealedUnit` (R5), the converse of the 15th.
    ///
    /// 16 + (6+4+2+2+2+2+8) + 2 + 15 + 25 + 2 = 86.
    const DISTINCT_CODES: usize = 86;

    /// Exhaustive-match distinctness over the line-121-derived taxonomy:
    /// every (variant, discriminant) exemplar yields a distinct, stable,
    /// kebab-case code, and the exemplar list covers every variant with
    /// every discriminant value. The wildcard-free matches here and in
    /// `VerifyError::code` make any new arm (wrapper arms included) a
    /// compile error until it gets a code and an exemplar.
    #[test]
    fn codes_are_pairwise_distinct_and_stable() {
        let exemplars = all_error_exemplars();
        assert_eq!(exemplars.len(), DISTINCT_CODES);

        // Pairwise distinctness of stable codes (Q7 contract).
        let codes: BTreeSet<&'static str> = exemplars.iter().map(VerifyError::code).collect();
        assert_eq!(
            codes.len(),
            DISTINCT_CODES,
            "codes must be pairwise distinct"
        );

        // Stable-code format: lowercase kebab, no other characters.
        for code in &codes {
            assert!(
                !code.is_empty()
                    && code
                        .chars()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'),
                "code {code:?} is not lowercase kebab-case"
            );
        }

        // Exhaustive per-variant tally: the match below has NO wildcard,
        // so a new variant fails compilation; the counts prove the
        // exemplar list exercises every discriminant of every variant.
        let mut tally: BTreeMap<&'static str, usize> = BTreeMap::new();
        for e in &exemplars {
            let variant = match e {
                VerifyError::UnitDecryptFailed { .. } => "UnitDecryptFailed",
                VerifyError::PaddedLengthMismatch { .. } => "PaddedLengthMismatch",
                VerifyError::NonZeroPadding { .. } => "NonZeroPadding",
                VerifyError::TrueLengthRangeMismatch { .. } => "TrueLengthRangeMismatch",
                VerifyError::FineRootBindingFailed { .. } => "FineRootBindingFailed",
                VerifyError::UnitCommitMismatch { .. } => "UnitCommitMismatch",
                VerifyError::WrongLength { .. } => "WrongLength",
                VerifyError::UnknownUnitRef { .. } => "UnknownUnitRef",
                VerifyError::DuplicateUnitReveal { .. } => "DuplicateUnitReveal",
                VerifyError::UnknownFileRef { .. } => "UnknownFileRef",
                VerifyError::TilingViolation { .. } => "TilingViolation",
                VerifyError::RawMirrorInTilingSet { .. } => "RawMirrorInTilingSet",
                VerifyError::PathCommitMismatch { .. } => "PathCommitMismatch",
                VerifyError::RevealedUnitFileNotTouched { .. } => "RevealedUnitFileNotTouched",
                VerifyError::TouchedFileWithoutRevealedUnit { .. } => {
                    "TouchedFileWithoutRevealedUnit"
                }
                VerifyError::RevealModeMismatch { .. } => "RevealModeMismatch",
                VerifyError::PartialRevealSaltLeak { .. } => "PartialRevealSaltLeak",
                VerifyError::FullRevealMaterialMissing { .. } => "FullRevealMaterialMissing",
                VerifyError::FullRevealSRootWithoutFineTree { .. } => {
                    "FullRevealSRootWithoutFineTree"
                }
                VerifyError::ConcatCommitMismatch { .. } => "ConcatCommitMismatch",
                // Deliberately unexemplified (see `all_error_exemplars`):
                // its only code is already claimed by FineRootBindingFailed.
                VerifyError::FineRootSeedTailNotCanonical { .. } => "FineRootSeedTailNotCanonical",
                VerifyError::FineRootRebuildMismatch { .. } => "FineRootRebuildMismatch",
                VerifyError::RawCommitMismatch { .. } => "RawCommitMismatch",
                VerifyError::RawMirrorCanonicalizationMismatch { .. } => {
                    "RawMirrorCanonicalizationMismatch"
                }
                VerifyError::Decode(_) => "Decode",
                VerifyError::Codec(_) => "Codec",
                VerifyError::Crypto(_) => "Crypto",
                VerifyError::Canon(_) => "Canon",
            };
            *tally.entry(variant).or_insert(0) += 1;
        }
        // 27 of the 28 variants. `FineRootSeedTailNotCanonical` (D83) is the
        // exception and is asserted separately below: it is a *delegating*
        // arm whose only code — `fine-root-leaf-seed-tail-not-zero` — is
        // already exemplified through `FineRootBindingFailed`, so giving it
        // an exemplar here would collide by design (error-code contract §2:
        // one code, one owning domain, many paths). The same reasoning keeps
        // the `cbor-*` codes out of the `Decode` arm's exemplars.
        assert_eq!(tally.len(), 27, "27 variants must be represented");
        let expected: BTreeMap<&str, usize> = [
            ("WrongLength", 6),
            ("TilingViolation", 4),
            ("PartialRevealSaltLeak", 2),
            ("FullRevealMaterialMissing", 2),
            ("ConcatCommitMismatch", 2),
            ("RevealModeMismatch", 2),
            // One exemplar per composition arm of F9's SealProofError (R5).
            ("Decode", 2),
            // One exemplar per delegated fine-root-* code (G13, +D83).
            ("FineRootBindingFailed", 8),
            // One exemplar per delegated cbor-* code (F3).
            ("Codec", 15),
            // One exemplar per delegated crypto-* code (R2).
            ("Crypto", 25),
            // One exemplar per delegated content-* canonicalization code (R4).
            ("Canon", 2),
        ]
        .into_iter()
        .collect();
        for (variant, count) in &tally {
            assert_eq!(
                *count,
                expected.get(variant).copied().unwrap_or(1),
                "exemplar count for {variant} must cover every discriminant exactly once"
            );
        }
    }

    /// Display strings are field-identifying: they name the failing
    /// subject id (and quantities) so a human can locate the failure
    /// without the machine code — and, like the codes, they are
    /// pairwise distinct over the exemplar set.
    #[test]
    fn display_identifies_the_failing_subject() {
        let displays: BTreeSet<String> = all_error_exemplars()
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(displays.len(), DISTINCT_CODES);

        let e = VerifyError::PaddedLengthMismatch {
            unit_id: 4,
            expected: 512,
            actual: 768,
        };
        let s = e.to_string();
        assert!(
            s.contains("unit 4") && s.contains("512") && s.contains("768"),
            "{s}"
        );

        let e = VerifyError::WrongLength {
            field: LengthField::SRoot,
            expected: 32,
            actual: 16,
        };
        let s = e.to_string();
        assert!(
            s.contains("s_root") && s.contains("32") && s.contains("16"),
            "{s}"
        );

        let e = VerifyError::TilingViolation {
            file_id: 1,
            kind: TilingViolationKind::OutOfBounds,
        };
        assert!(e.to_string().contains("out-of-bounds"), "{e}");
    }

    /// The Codec wrapper arm honors the extension-point contract:
    /// `From` conversion, transparent `Display` (equal to the wrapped
    /// error's), and `code()` delegation to the wrapped `cbor-*` code.
    #[test]
    fn codec_wrapper_arm_delegates_display_and_code() {
        let inner = crate::codec::DecodeError::DuplicateMapKey { position: 7 };
        let wrapped = VerifyError::from(inner.clone());
        assert_eq!(wrapped.code(), "cbor-duplicate-map-key");
        assert_eq!(wrapped.code(), inner.code());
        assert_eq!(wrapped.to_string(), inner.to_string());
    }

    /// The Crypto wrapper arm (R2) honors the same contract — transparent
    /// `Display`, `code()` delegation to the wrapped `crypto-*` code —
    /// minus `From`: wrapping is deliberately explicit-only, so R2's
    /// named-variant mapping (`AeadDecryptFailed` → `UnitDecryptFailed`
    /// etc.) cannot be bypassed by a stray `?` (enum-level doc).
    #[test]
    fn crypto_wrapper_arm_delegates_display_and_code() {
        let inner = crate::crypto::CryptoError::SigPolicyEmpty;
        let wrapped = VerifyError::Crypto(inner);
        assert_eq!(wrapped.code(), "crypto-sig-policy-empty");
        assert_eq!(wrapped.code(), inner.code());
        assert_eq!(wrapped.to_string(), inner.to_string());

        // The delegated code and the R2 named variant for the same
        // underlying event stay distinct rows: a wrapped AEAD failure is
        // NOT the per-unit decrypt row.
        let wrapped_aead = VerifyError::Crypto(crate::crypto::CryptoError::AeadDecryptFailed);
        assert_eq!(wrapped_aead.code(), "crypto-aead-decrypt-failed");
        assert_ne!(
            wrapped_aead.code(),
            VerifyError::UnitDecryptFailed { unit_id: 0 }.code()
        );
    }

    /// The Canon wrapper arm (R4) honors the same contract as Crypto —
    /// transparent `Display`, `code()` delegation to the wrapped
    /// `content-*` code, no `From`. The delegated code and R4's integrity
    /// verdict for the same *subject* (the raw-mirror binding) stay
    /// distinct rows: "this verifier does not know that Unicode version"
    /// is never "these bytes do not canonicalize to that content".
    #[test]
    fn canon_wrapper_arm_delegates_display_and_code() {
        let inner = crate::canon::CanonicalizeError::UnknownVersion(
            crate::canon::UnicodeVersionError::UnknownUnicodeVersion {
                requested: "unicode-99.0.0".to_owned(),
            },
        );
        let wrapped = VerifyError::Canon(inner.clone());
        assert_eq!(wrapped.code(), "content-unknown-unicode-version");
        assert_eq!(wrapped.code(), inner.code());
        assert_eq!(wrapped.to_string(), inner.to_string());

        assert_ne!(
            wrapped.code(),
            VerifyError::RawMirrorCanonicalizationMismatch { file_id: 0 }.code()
        );
    }

    /// The G13 seam arm (R2): `FineRootBindingFailed` exposes its wrapped
    /// class both as a `source()` chain and as per-class stable codes —
    /// the over-broad-cover rejection is its own distinct row, never the
    /// generic binding failure.
    #[test]
    fn fine_root_binding_arm_discriminates_g13_classes() {
        use std::error::Error as _;

        let generic = VerifyError::FineRootBindingFailed {
            unit_id: 21,
            source: FineTreeError::RootMismatch,
        };
        let over_broad = VerifyError::FineRootBindingFailed {
            unit_id: 21,
            source: FineTreeError::OverBroadCover,
        };
        assert_eq!(generic.code(), "fine-root-binding-failed");
        assert_eq!(over_broad.code(), "fine-root-over-broad-cover");
        assert_ne!(generic.code(), over_broad.code());

        let source = generic.source().expect("wrapped G error is the source");
        assert_eq!(source.to_string(), FineTreeError::RootMismatch.to_string());
        assert!(
            over_broad.to_string().contains("over-broad"),
            "{over_broad}"
        );
    }

    /// D83's second call site is a *delegating* arm: it surfaces G's
    /// `fine-root-leaf-seed-tail-not-zero` unchanged, the same string the
    /// fine-tree site produces, so exactly one code exists for the class and
    /// the two sites are separated by layer instead. This is the assertion
    /// that keeps the exemplar list's deliberate omission honest.
    #[test]
    fn the_d83_seed_tail_arm_mints_no_second_code() {
        use std::error::Error as _;

        let inner = FineTreeError::LeafSeedTailNotZero { level: 0, index: 0 };
        let r_side = VerifyError::FineRootSeedTailNotCanonical {
            file_id: 4,
            source: inner,
        };
        let g_side = VerifyError::FineRootBindingFailed {
            unit_id: 4,
            source: inner,
        };
        assert_eq!(r_side.code(), "fine-root-leaf-seed-tail-not-zero");
        assert_eq!(r_side.code(), inner.code());
        assert_eq!(r_side.code(), g_side.code());

        // The exemplar list therefore must NOT carry this variant — its code
        // is already claimed — but every code it does carry stays reachable.
        assert!(
            !all_error_exemplars()
                .iter()
                .any(|e| matches!(e, VerifyError::FineRootSeedTailNotCanonical { .. })),
            "a second exemplar would collide with FineRootBindingFailed's"
        );
        assert!(
            all_error_exemplars()
                .iter()
                .any(|e| e.code() == "fine-root-leaf-seed-tail-not-zero"),
            "the code must still be exemplified, through the G-side arm"
        );

        // Distinct `Display` (the *site* differs) over a shared source chain.
        assert_ne!(r_side.to_string(), g_side.to_string());
        assert_eq!(
            r_side
                .source()
                .expect("wrapped G error is the source")
                .to_string(),
            inner.to_string()
        );
        assert!(r_side.to_string().contains("file 4"), "{r_side}");
    }

    /// `LengthField::spec_len` mirrors the line-121 exact-length table.
    #[test]
    fn spec_lengths_match_line_121() {
        assert_eq!(LengthField::UnitSalt.spec_len(), 16);
        assert_eq!(LengthField::PathSalt.spec_len(), 16);
        assert_eq!(LengthField::FileSalt.spec_len(), 16);
        assert_eq!(LengthField::SRoot.spec_len(), 32);
        assert_eq!(LengthField::GgmCoveringSeed.spec_len(), 32);
        assert_eq!(LengthField::BoundaryNodeHash.spec_len(), 32);
    }

    /// D27: the collection container keeps the fail-fast primary first,
    /// in insertion order, non-empty by construction.
    #[test]
    fn failures_collection_keeps_primary_first() {
        let primary = VerifyError::UnitDecryptFailed { unit_id: 1 };
        let second = VerifyError::PathCommitMismatch { file_id: 2 };
        let mut failures = VerifyFailures::new(primary.clone());
        failures.push(second.clone());

        assert_eq!(failures.primary(), &primary);
        assert_eq!(failures.additional(), core::slice::from_ref(&second));
        assert_eq!(failures.count(), 2);
        let in_order: Vec<&VerifyError> = failures.iter().collect();
        assert_eq!(in_order, [&primary, &second]);

        let display = failures.to_string();
        assert!(display.contains("2 finding(s)"), "{display}");
        assert!(display.contains("unit 1"), "{display}");

        // From<VerifyError> gives the single-finding (fail-fast-shaped) form.
        let single = VerifyFailures::from(primary.clone());
        assert_eq!(single.count(), 1);
        assert_eq!(single.primary(), &primary);
    }
}
