//! The bundle builder's error taxonomy (task R13).
//!
//! # Deliberately OUTSIDE the frozen error-code universe (D30/Q52)
//!
//! These are **builder**-side failures: they are returned to the sealer's
//! own tooling (R16, the CLI) and never rendered to a bundle recipient, so
//! no variant carries a stable wire code, none enters
//! `testdata/error-codes/v1/CODES.txt`, and this enum is not registered
//! with the Q52 per-domain enumerators. The verifier-facing codes a failed
//! build *surfaces* are the wrapped ones: [`BuildError::SelfCheck`] carries
//! the pipeline's own [`VerifyError`] (whose codes are frozen), and the
//! decode/assembly wrappers carry F's frozen families unchanged.
//!
//! # Secret hygiene (project rule 6)
//!
//! No variant carries key, salt, seed, nonce or content **bytes** — only
//! ids, counts and closed discriminants. [`ForbiddenMaterial`] names a
//! *class* of material and its subject id, never the material itself, so a
//! rendered error cannot become the leak it reports.

use thiserror::Error;

use crate::bundle::BundleError;
use crate::codec::EncodeError;
use crate::content::fine_tree::FineTreeError;
use crate::manifest::ManifestError;
use crate::verify::VerifyError;

/// Which class of vault material the post-encode byte scan found in the
/// bundle's non-manifest bytes (see
/// [`BuildError::ForbiddenBytesInEncoding`]).
///
/// A closed discriminant plus the subject id — never the bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForbiddenMaterial {
    /// A not-fully-revealed file's `file_salt` (MVP-SPEC.md lines 95, 121;
    /// C7's confirmation-oracle rationale).
    FileSalt {
        /// The file whose salt was found.
        file_id: u64,
    },
    /// A not-fully-revealed fine-tree file's `s_root` fine seed
    /// (MVP-SPEC.md line 96: no ancestor seed of an unrevealed leaf ever
    /// leaves the vault).
    FineSeed {
        /// The file whose fine seed was found.
        file_id: u64,
    },
    /// A revealed unit's AEAD nonce outside the embedded manifest — nonces
    /// are manifest-only, the single authoritative copy (MVP-SPEC.md
    /// line 91; R2's rule).
    UnitNonce {
        /// The unit whose nonce was found.
        unit_id: u64,
    },
}

impl core::fmt::Display for ForbiddenMaterial {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::FileSalt { file_id } => {
                write!(f, "file {file_id}'s file_salt (file not fully revealed)")
            }
            Self::FineSeed { file_id } => {
                write!(f, "file {file_id}'s fine seed (file not fully revealed)")
            }
            Self::UnitNonce { unit_id } => {
                write!(f, "unit {unit_id}'s nonce (nonces are manifest-only)")
            }
        }
    }
}

/// Everything [`build_bundle`](super::build_bundle) can refuse to do.
///
/// Three families, in the order the build encounters them:
///
/// 1. **Input validation** — the manifest bytes, the reveal plan, and the
///    supplied ciphertexts/contents disagree with one another.
/// 2. **Assembly/encoding** — F's own schema or encoder rejected what was
///    assembled (wrapped unchanged, per the error-code contract's layering
///    rule).
/// 3. **The mandatory self-check and the internal assertions** — the built
///    bytes failed [`verify_bundle`](crate::verify::verify_bundle), or one
///    of the D70 §7.3 structural assertions the self-check *cannot* make
///    fired. Most assertion variants are unreachable through the public API
///    by construction; the [`forcing`](super::forcing) seam exists so tests
///    can prove each one can fail (its negative control).
///    [`BuildError::StorageLinkageMismatch`] is the one exception and needs
///    no seam: it accuses the **caller's inputs** rather than the builder's
///    emission, so a caller can reach it with material this API accepts
///    (R78).
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum BuildError {
    /// The plaintext manifest bytes do not strict-decode (envelope or
    /// body layer; F's frozen `manifest-*`/`cbor-*` identity is preserved).
    #[error("manifest input does not decode: {source}")]
    Manifest {
        /// F's decode failure, unchanged.
        #[from]
        source: ManifestError,
    },

    /// The reveal plan's file count differs from the manifest file table's.
    #[error("reveal plan names {got} files but the manifest records {expected}")]
    PlanFileCountMismatch {
        /// Manifest file-table length.
        expected: u64,
        /// Plan length.
        got: u64,
    },

    /// A per-file unit selection names a normal-unit index the file does
    /// not have (indices address the file's **normal**-unit list — a raw
    /// mirror has no index and cannot be named, MVP-SPEC.md line 92).
    #[error(
        "file {file_id}: selection names normal-unit index {index}, but the file has \
         {normal_units} normal units"
    )]
    UnitIndexOutOfRange {
        /// The selecting file.
        file_id: u64,
        /// The out-of-range index.
        index: u64,
        /// How many normal units the file actually has.
        normal_units: u64,
    },

    /// A touched selection reveals no unit at all. Emitting a path for a
    /// file while revealing nothing of it is the D82 shape the verifier
    /// rejects; refusing it here names the real mistake instead of
    /// surfacing a self-check failure later.
    #[error("file {file_id}: a touched selection must reveal at least one unit")]
    NoUnitsSelected {
        /// The file whose selection is empty.
        file_id: u64,
    },

    /// A revealed unit's ciphertext was not supplied.
    #[error("unit {unit_id}: no ciphertext supplied for a revealed unit")]
    MissingCiphertext {
        /// The revealed unit.
        unit_id: u64,
    },

    /// A touched fine-tree file's plaintext content was not supplied — G
    /// cannot compute its boundary Merkle paths without the whole file's
    /// bytes (tasks/R.md R16 fetch-all note).
    #[error("file {file_id}: no plaintext content supplied for boundary-path computation")]
    MissingFileContent {
        /// The touched fine-tree file.
        file_id: u64,
    },

    /// The manifest records a fine tree for a file whose `size` admits no
    /// GGM depth. Unreachable through an honestly sealed manifest; kept
    /// total rather than unwrapped (working principle 2).
    #[error("file {file_id}: no fine-tree depth exists for size {size}")]
    FineTreeDepth {
        /// The inconsistent file.
        file_id: u64,
        /// Its manifest `size`.
        size: u64,
    },

    /// C7's full-file-reveal witness refused the attestation. Unreachable
    /// when classification and attestation read the same manifest unit
    /// table, as they do here; kept as a typed defense so a future drift
    /// between the two surfaces loudly instead of panicking.
    #[error("file {file_id}: the full-file-reveal witness refused the attestation")]
    FullRevealWitnessRefused {
        /// The file that classified as full but failed to attest.
        file_id: u64,
    },

    /// G refused a range proof for a revealed covered unit (content length
    /// vs manifest `size`, unit range outside `[0, n)`, …).
    #[error("file {file_id} unit {unit_id}: range proof failed: {source}")]
    RangeProof {
        /// The owning file.
        file_id: u64,
        /// The revealed unit.
        unit_id: u64,
        /// G's failure, unchanged.
        source: FineTreeError,
    },

    /// F's bundle schema rejected an assembled section or the section set
    /// (caps, ordering, ciphertext shape, cross-section rules).
    #[error("bundle assembly rejected: {source}")]
    Assembly {
        /// F's rejection, unchanged.
        source: BundleError,
    },

    /// F's canonical encoder rejected the validated bundle (aggregate byte
    /// caps).
    #[error("bundle encoding failed: {source}")]
    Encode {
        /// F's rejection, unchanged.
        source: EncodeError,
    },

    /// **The mandatory self-check** (R13 Do): the encoded bundle failed
    /// [`verify_bundle`](crate::verify::verify_bundle). Nothing that fails
    /// its own verification ever leaves the builder.
    #[error("the built bundle failed its mandatory self-verification: {source}")]
    SelfCheck {
        /// The pipeline's first failure, unchanged (frozen code family).
        source: VerifyError,
    },

    /// Internal assertion (D70 §7.3 forward direction): a raw-mirror reveal
    /// entry was emitted for a file that is not fully revealed. The
    /// verifier deliberately tolerates this shape (R53), so the self-check
    /// cannot catch it — this assertion is the enforcement.
    #[error(
        "internal assertion: mirror unit {unit_id} emitted for file {file_id}, which is not \
         fully revealed"
    )]
    MirrorEmittedWithoutFullReveal {
        /// The mirror's owning file.
        file_id: u64,
        /// The mirror unit.
        unit_id: u64,
    },

    /// Internal assertion (D70 §7.3 converse direction): a fully revealed
    /// file whose manifest records a raw mirror was emitted without its
    /// mirror entry. The mirror-less full reveal is a frozen *accepted*
    /// verifier shape, so the self-check cannot catch it — this assertion
    /// is the enforcement.
    #[error(
        "internal assertion: file {file_id} is fully revealed and its manifest records mirror \
         unit {unit_id}, but the mirror was not emitted"
    )]
    MirrorMissingFromFullReveal {
        /// The fully revealed file.
        file_id: u64,
        /// The manifest's mirror unit for it.
        unit_id: u64,
    },

    /// Internal assertion: receipt presence in the built bundle disagrees
    /// with the caller's opt-in. Receipt presence is legal either way on
    /// the wire (registry §7.10), so the self-check cannot see intent —
    /// this assertion is the enforcement of "receipt iff opted".
    #[error(
        "internal assertion: receipt presence disagrees with the caller's opt-in (opted: {opted})"
    )]
    ReceiptPresenceMismatch {
        /// Whether the caller opted the receipt in.
        opted: bool,
    },

    /// Internal assertion: the post-encode byte scan found vault material
    /// in the bundle's non-manifest bytes. The verifier does not hold `W`
    /// and structurally cannot make this check — this scan is C7's
    /// prescribed defense-in-depth on top of the type-level guarantees.
    #[error("internal assertion: forbidden bytes in the encoded bundle: {material}")]
    ForbiddenBytesInEncoding {
        /// What was found (class + subject id, never bytes).
        material: ForbiddenMaterial,
    },

    /// Re-parsing the builder's own encoded output for the byte scan
    /// failed. Unreachable — the self-check already decoded the same bytes
    /// — but kept total rather than unwrapped.
    #[error("re-parsing the encoded bundle for the secret-byte scan failed: {source}")]
    Reparse {
        /// F's rejection of our own output.
        source: BundleError,
    },

    /// The re-parsed bundle's embedded-manifest slice could not be located
    /// inside the encoded bytes. Unreachable — `BundleV1` guarantees the
    /// slice borrows the decoded input — but kept total.
    #[error("the embedded manifest's span could not be located in the encoded bundle")]
    ManifestSpanUntracked,

    /// Internal assertion (R78): the self-check's storage-linkage layer
    /// found that what this bundle embeds does not address to what its
    /// **signed** manifest records. Both halves are reported together, so a
    /// bent unit address and a bent manifest address render distinctly.
    ///
    /// Unlike its four siblings this one is reachable through the public
    /// API; `assert_beyond_self_check`'s docs carry R78's ruling on why it
    /// is a refusal and not a warning.
    #[error(
        "internal assertion: the built bundle does not address to what its signed manifest \
         records — {units_mismatched} of {units_checked} embedded unit ciphertext(s) mismatched, \
         manifest blob matched: {manifest_matched}"
    )]
    StorageLinkageMismatch {
        /// Embedded unit ciphertexts whose recomputed address differs from
        /// the address the manifest records for that unit.
        units_mismatched: u64,
        /// How many embedded unit ciphertexts were checked.
        units_checked: u64,
        /// Whether the blob rebuilt from the embedded plaintext manifest
        /// addresses to the storage record's claimed address.
        manifest_matched: bool,
    },
}
