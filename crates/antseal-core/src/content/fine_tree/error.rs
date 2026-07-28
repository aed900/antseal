//! The fine-tree failure taxonomy (tasks/G.md G13) — one distinct variant,
//! and one distinct stable code, per illegal state a fine-tree construction
//! or range opening can be asked to hold.
//!
//! # Provenance: this type was pre-declared by R2
//!
//! `FineTreeError` was first written in `verify::unit_stages` as R2's
//! compile-enforced extension point, with two classes
//! ([`Self::RootMismatch`], [`Self::OverBroadCover`]) and a documented
//! contract: *"Its full variant set (at minimum `WrongCoverShape`,
//! `BadSeedLength`, `BadNodeHashLength`, `RangeOutOfBounds`,
//! `ByteLenMismatch` in addition to the two below) extends **this** enum
//! … G13 may relocate the type into G's fine-tree module; the
//! `VerifyError` arm and its codes are the stable surface."*
//!
//! G13 takes both halves of that offer: the type now lives here (G owns the
//! fine tree, and `content` must not depend on `verify` — the layering runs
//! the other way), and `verify::unit_stages` re-exports it, so R2's
//! [`VerifyError::FineRootBindingFailed`] arm and every downstream `use`
//! path are unchanged.
//!
//! # Why the codes are unprefixed
//!
//! `docs/testing/error-code-contract.md` §2 assigns G the `content-` prefix
//! and leaves R's codes unprefixed, *and* §3 forbids renaming a code once it
//! exists. R2 already minted `fine-root-binding-failed` and
//! `fine-root-over-broad-cover` for the two original classes, so the family
//! is unprefixed by inheritance; renaming to satisfy the prefix table is
//! exactly the "third option that destroys the contract" §3 rules out. The
//! five classes added here therefore extend the same `fine-root-` family.
//!
//! This is consistent with §2's *wrapper* rule read in the other direction:
//! R surfaces the inner code unchanged
//! ([`VerifyError::code`] delegates to [`FineTreeError::code`]), so each
//! outcome has exactly **one** code, and the codes name pipeline-level
//! outcomes a user sees in a verdict — which is what R's unprefixed
//! namespace is for. Global distinctness (the property that actually
//! matters) is asserted here and again in R's registry sweep.
//!
//! # Redaction discipline (project rules 4 and 6)
//!
//! No variant carries seed, salt, or content bytes. Payloads are structural
//! public quantities only — byte lengths, leaf counts, range endpoints —
//! every one of them a `usize`/`u64`, so no code path can smuggle secret or
//! content material into a `Debug`/`Display` rendering.
//!
//! [`VerifyError::FineRootBindingFailed`]: crate::verify::VerifyError::FineRootBindingFailed
//! [`VerifyError::code`]: crate::verify::VerifyError::code

use thiserror::Error;

/// Every fine-tree failure class, one distinct variant each
/// (tasks/G.md G13; MVP-SPEC.md lines 96, 118, 121).
///
/// Like [`crate::verify::VerifyError`], deliberately **not**
/// `#[non_exhaustive]`: breaking downstream matches on extension is the
/// mechanism that forces a new class to receive a distinct stable code.
///
/// The two classes R2 declared ([`Self::RootMismatch`],
/// [`Self::OverBroadCover`]) keep their original field-free shape and their
/// original codes; R2's exemplars construct them positionally.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum FineTreeError {
    /// The recomputed root does not match the manifest's `fine_root`
    /// (wrong bytes, wrong salts, wrong boundary path — the generic
    /// binding failure).
    #[error("recomputed root does not match fine_root")]
    RootMismatch,

    /// The GGM sub-cover is not leaf-exact: a cover node spans an
    /// unrevealed real leaf, which would disclose that leaf's salt
    /// (MVP-SPEC.md line 96: "the cover MUST be leaf-exact").
    ///
    /// This includes the headline case of `s_root` (the tree root, whose
    /// real span is all of `[0, n)`) offered for a *partial* range: the
    /// root spans every unrevealed leaf, so it is over-broad by definition.
    ///
    /// **Must stay its own distinct code forever**: an over-broad cover
    /// would disclose `salt_j` and reopen the per-byte confirmation attack
    /// (spec line 96), so its rejection is its own tamper row (G19), not a
    /// generic mismatch.
    #[error("over-broad GGM cover spans an unrevealed leaf")]
    OverBroadCover,

    /// The offered node set is not the expected leaf-exact cover / boundary
    /// path for this `(range, n)` — wrong count, wrong order, duplicated or
    /// missing nodes, a node addressing a slot that is not on this tree's
    /// depth-`d` grid, or a node covering only unused slots `>= n`.
    ///
    /// Distinct from [`Self::OverBroadCover`], which is the *security*
    /// violation (the offered node would disclose an unrevealed real leaf's
    /// salt); this variant is the residual structural mismatch, which
    /// discloses nothing but proves the proof is not the canonical one.
    #[error("GGM cover / boundary path does not match the expected leaf-exact shape")]
    WrongCoverShape,

    /// A disclosed GGM covering seed is not exactly 32 bytes
    /// (MVP-SPEC.md lines 96, 121: "Every disclosed 32-B seed … is
    /// length-checked by the verifier").
    ///
    /// R3's structural stage raises its own
    /// [`VerifyError::WrongLength`](crate::verify::VerifyError::WrongLength)
    /// row for the same wire field at bundle-schema level (G19 notes: the
    /// wrong-length *rows* are R's); this variant is the primitive that
    /// makes [`super::verify_range`] safe to call **directly**, as the
    /// WASM verifier and G's own tests do, without a preceding R stage.
    #[error("GGM covering seed length {got} != {expected}")]
    BadSeedLength {
        /// Required length in bytes (32).
        expected: usize,
        /// Observed length in bytes.
        got: usize,
    },

    /// A disclosed boundary Merkle node hash is not exactly 32 bytes
    /// (MVP-SPEC.md lines 96, 121). See [`Self::BadSeedLength`] for the
    /// division of labour with R3's structural row.
    #[error("boundary Merkle node hash length {got} != {expected}")]
    BadNodeHashLength {
        /// Required length in bytes (32).
        expected: usize,
        /// Observed length in bytes.
        got: usize,
    },

    /// The claimed leaf range is not a non-empty sub-range of `[0, n)`:
    /// `start + length` overflowed, ran past `n`, or the range is empty —
    /// including every range against a file with no fine tree at all
    /// (`n = 0`; MVP-SPEC.md line 78).
    ///
    /// A hostile `n` needs no separate class: `n` bounds the tree depth at
    /// `d = ceil(log2 n) <= 64`
    /// ([`depth_for_leaf_count`](crate::content::depth_for_leaf_count)), and
    /// the work a range opening performs is bounded by the *revealed* byte
    /// count, not by `n`.
    #[error(
        "leaf range [{start}, {start}+{length}) is not a non-empty sub-range of [0, {leaf_count})"
    )]
    RangeOutOfBounds {
        /// First leaf index the proof claims.
        start: u64,
        /// Number of leaves the proof claims.
        length: u64,
        /// The file's leaf count `n` (the file-table `size` field).
        leaf_count: u64,
    },

    /// The revealed byte count does not equal the claimed range width — a
    /// proof that claims more span than it reveals, or a streaming
    /// construction fed a different number of bytes than the declared leaf
    /// count (MVP-SPEC.md line 121: `true_length` = byte-range width =
    /// plaintext length).
    #[error("revealed byte count {got} != claimed leaf-range width {expected}")]
    ByteLenMismatch {
        /// Bytes the claimed range requires.
        expected: u64,
        /// Bytes actually supplied.
        got: u64,
    },
}

impl FineTreeError {
    /// Stable machine-readable code, pairwise-distinct across every variant.
    ///
    /// `RootMismatch` and `OverBroadCover` return **exactly** the strings R2
    /// minted for them; the module docs explain why the family is unprefixed
    /// and why renaming is not an option. `const` so
    /// [`VerifyError::code`](crate::verify::VerifyError::code) — itself a
    /// `const fn` — can delegate here.
    ///
    /// The exhaustive, wildcard-free match is the compile-time guard: a new
    /// variant fails compilation here until it receives a distinct code —
    /// and an exemplar in [`all_code_exemplars`].
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::RootMismatch => "fine-root-binding-failed",
            Self::OverBroadCover => "fine-root-over-broad-cover",
            Self::WrongCoverShape => "fine-root-wrong-cover-shape",
            Self::BadSeedLength { .. } => "fine-root-bad-seed-length",
            Self::BadNodeHashLength { .. } => "fine-root-bad-node-hash-length",
            Self::RangeOutOfBounds { .. } => "fine-root-range-out-of-bounds",
            Self::ByteLenMismatch { .. } => "fine-root-byte-len-mismatch",
        }
    }
}

/// One exemplar per distinct [`FineTreeError::code`] — every variant exactly
/// once. Consumed by this module's distinctness meta-test and by R's
/// `VerifyError` exemplar list, so the two can never drift apart.
///
/// Public behind `test-util` (not `#[cfg(test)]`) because R's exemplar list
/// and G19's tamper rows live in other modules and integration tests.
#[cfg(any(test, feature = "test-util"))]
#[must_use]
pub fn all_code_exemplars() -> Vec<FineTreeError> {
    use FineTreeError as E;
    vec![
        E::RootMismatch,
        E::OverBroadCover,
        E::WrongCoverShape,
        E::BadSeedLength {
            expected: 32,
            got: 31,
        },
        E::BadNodeHashLength {
            expected: 32,
            got: 33,
        },
        E::RangeOutOfBounds {
            start: 4,
            length: 4,
            leaf_count: 6,
        },
        E::ByteLenMismatch {
            expected: 2,
            got: 3,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::content::error::ContentError;
    use crate::verify::VerifyError;
    use core::mem::discriminant;
    use std::collections::BTreeSet;
    use std::error::Error as _;

    /// G13 accept ("variants pairwise distinct") plus the D30 format rules:
    /// every variant has an exemplar, codes are pairwise distinct and
    /// lowercase kebab-case, `Display` renderings are pairwise distinct, and
    /// discriminants are pairwise distinct (no two exemplars share a
    /// variant).
    #[test]
    fn codes_are_pairwise_distinct() {
        let exemplars = all_code_exemplars();
        assert_eq!(
            exemplars.len(),
            7,
            "one exemplar per variant — keep exhaustive when adding variants"
        );

        let codes: BTreeSet<&'static str> = exemplars.iter().map(FineTreeError::code).collect();
        assert_eq!(codes.len(), exemplars.len(), "codes pairwise distinct");
        for code in &codes {
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

        for i in 0..exemplars.len() {
            for j in (i + 1)..exemplars.len() {
                assert_ne!(
                    discriminant(&exemplars[i]),
                    discriminant(&exemplars[j]),
                    "{:?} vs {:?}",
                    exemplars[i],
                    exemplars[j]
                );
            }
        }
    }

    /// D30 §3, append-only: the two codes R2 minted are reproduced
    /// **verbatim**. This test is the guard that a future refactor cannot
    /// "tidy" the family under a `content-` prefix — doing so would silently
    /// break every third-party verifier comparing against them.
    #[test]
    fn r2_minted_codes_are_never_renamed() {
        assert_eq!(
            FineTreeError::RootMismatch.code(),
            "fine-root-binding-failed"
        );
        assert_eq!(
            FineTreeError::OverBroadCover.code(),
            "fine-root-over-broad-cover"
        );
    }

    /// Cross-domain distinctness: the whole family sits in R's unprefixed
    /// namespace and must not collide with any prefixed domain code, nor
    /// with a `content-` code of G's own [`ContentError`] — the tamper
    /// matrix is global (D30 §4 layer 2).
    #[test]
    fn codes_cannot_collide_with_other_domains() {
        let content_codes: BTreeSet<&'static str> = crate::content::error::all_code_exemplars()
            .iter()
            .map(ContentError::code)
            .collect();
        for err in all_code_exemplars() {
            let code = err.code();
            for prefix in ["content-", "crypto-", "cbor-", "manifest-"] {
                assert!(!code.starts_with(prefix), "{code} borrows {prefix}");
            }
            assert!(
                !content_codes.contains(code),
                "{code} collides with G's own"
            );
        }
    }

    /// Every class surfaces through R2's wrapper arm with its own code —
    /// the property that makes G19's rows pinnable to an exact outcome.
    /// (R's own exemplar list asserts global distinctness across all 76
    /// codes; this asserts the delegation itself.)
    #[test]
    fn every_class_surfaces_distinctly_through_verify_error() {
        let wrapped: BTreeSet<&'static str> = all_code_exemplars()
            .into_iter()
            .map(|source| VerifyError::FineRootBindingFailed { unit_id: 7, source }.code())
            .collect();
        assert_eq!(wrapped.len(), 7, "R must not collapse two classes");
        for err in all_code_exemplars() {
            assert!(
                wrapped.contains(err.code()),
                "R must surface the inner code unchanged (D30 §2): {}",
                err.code()
            );
        }
    }

    /// Project rules 4/6: `Display` renders structural metadata only — no
    /// byte content, nothing hex-formatted that could carry it, no source
    /// chain smuggling one in.
    #[test]
    fn display_renders_structural_metadata_only() {
        for err in all_code_exemplars() {
            let msg = err.to_string();
            assert!(!msg.contains("0x"), "{msg}");
            assert!(msg.is_ascii(), "keep messages ASCII-renderable: {msg}");
            assert!(err.source().is_none(), "{msg}");
        }
    }

    /// Exact `Display` strings for the payload-carrying variants: any change
    /// to a rendering must be a deliberate, reviewed edit.
    #[test]
    fn payload_variants_render_their_numbers() {
        assert_eq!(
            FineTreeError::BadSeedLength {
                expected: 32,
                got: 31
            }
            .to_string(),
            "GGM covering seed length 31 != 32"
        );
        assert_eq!(
            FineTreeError::BadNodeHashLength {
                expected: 32,
                got: 33
            }
            .to_string(),
            "boundary Merkle node hash length 33 != 32"
        );
        assert_eq!(
            FineTreeError::RangeOutOfBounds {
                start: 4,
                length: 4,
                leaf_count: 6
            }
            .to_string(),
            "leaf range [4, 4+4) is not a non-empty sub-range of [0, 6)"
        );
        assert_eq!(
            FineTreeError::ByteLenMismatch {
                expected: 2,
                got: 3
            }
            .to_string(),
            "revealed byte count 3 != claimed leaf-range width 2"
        );
    }
}
