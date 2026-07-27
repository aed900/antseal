//! Content-model error taxonomy (tasks/G.md G4/G5/G8) — one distinct variant,
//! and one distinct stable `content-`-prefixed code, per illegal state the
//! content model can be asked to hold.
//!
//! # Why these are errors at all
//!
//! The content model's seal-side constructors are correct by construction:
//! [`CanonDescriptor::describe_file`](super::CanonDescriptor::describe_file)
//! and the unit-model builders cannot produce an illegal value. Every variant
//! here therefore exists for the **decode side** — F's strict CBOR decoder and
//! R's verifier handing the model field values that arrived from an adversary
//! (MVP-SPEC.md line 74: the sealer authors and self-signs every byte, so the
//! decoder is the only thing standing between a hand-built manifest and the
//! verdict). Each illegal field combination gets its own error so the tamper
//! matrix's "every mutation fails with a distinct error" requirement
//! (MVP-SPEC.md line 168) is satisfiable row by row.
//!
//! # Secret-redaction discipline (project rules 4 and 6)
//!
//! No variant carries key, salt, seed, or content bytes. Payloads are
//! structural public quantities only — tree levels, slot indices, leaf counts
//! — all of which a bundle recipient already sees on the wire. This is
//! structural: every payload field is a `u8`/`u64`, so no code path can
//! smuggle secret or content bytes into a `Debug`/`Display` rendering.
//!
//! # Integration seam (R)
//!
//! `verify::VerifyError` gains a `Content(ContentError)` wrapper arm
//! delegating [`ContentError::code`], exactly as it already does for
//! `codec::DecodeError` (`cbor-*`) and `crypto::CryptoError` (`crypto-*`).
//! Adding that arm is R's edit, not G's — this module owns only the codes and
//! their pairwise distinctness within the `content-` domain.

use thiserror::Error;

/// Every content-model failure class, one distinct variant each.
///
/// Payloads are structural public quantities only (module docs).
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ContentError {
    // ── Canonicalization descriptor (G4; MVP-SPEC.md lines 83, 85, 98) ──
    /// `kind = binary` with a **canonical**-bytes fine-tree domain. Binary
    /// files have no canonical rendition at all (MVP-SPEC.md line 83), so
    /// their tree can only live in the raw domain.
    #[error(
        "canonicalization descriptor: binary file with a canonical-bytes \
         fine-tree domain (binary files have no canonical rendition)"
    )]
    BinaryCanonicalFineTreeDomain,

    /// `kind = text` with a **raw**-bytes fine-tree domain. A text file's
    /// fine tree commits its canonical rendition — that is what makes
    /// `fine_root`'s leaves the same bytes `canon_commit` commits
    /// (MVP-SPEC.md lines 85, 96).
    #[error(
        "canonicalization descriptor: text file with a raw-bytes fine-tree \
         domain (a text file's fine tree is built over its canonical rendition)"
    )]
    TextRawFineTreeDomain,

    /// `kind = text` without a recorded Unicode data version. NFC output is
    /// version-dependent, so a text descriptor that does not pin its version
    /// cannot be recomputed by any verifier (MVP-SPEC.md line 83).
    #[error(
        "canonicalization descriptor: text file without a recorded Unicode \
         normalization version"
    )]
    TextMissingUnicodeVersion,

    /// `kind = binary` carrying a Unicode data version. Binary files are
    /// never normalized; a recorded version would be a meaningless field
    /// whose value the signature nevertheless binds (MVP-SPEC.md line 83).
    #[error(
        "canonicalization descriptor: binary file with a recorded Unicode \
         normalization version"
    )]
    BinaryUnicodeVersion,

    /// `fine_tree_present` is set but no domain is recorded — the domain says
    /// which bytes the tree's leaves are (MVP-SPEC.md line 85), so a present
    /// tree without it is unverifiable.
    #[error(
        "canonicalization descriptor: fine tree present but no fine-tree \
         domain recorded"
    )]
    FineTreePresentWithoutDomain,

    /// A fine-tree domain is recorded while `fine_tree_present` is clear.
    /// The descriptor's domain field exists **iff** the tree does (the other
    /// half of the biconditional [`Self::FineTreePresentWithoutDomain`]
    /// enforces); a stray domain is a field the signature binds and nothing
    /// interprets.
    #[error(
        "canonicalization descriptor: fine-tree domain recorded but no fine \
         tree present"
    )]
    FineTreeAbsentWithDomain,

    /// `fine_tree_present` is set for a file whose `size` is 0. An empty file
    /// has no leaves, hence no tree and one empty unit (MVP-SPEC.md line 78).
    /// Only reachable through the size-aware check
    /// [`CanonDescriptor::validate_with_size`](super::CanonDescriptor::validate_with_size),
    /// since the descriptor alone does not carry `n`.
    #[error(
        "canonicalization descriptor: fine tree present on an empty file \
         (size 0 has no leaves)"
    )]
    FineTreePresentOnEmptyFile,

    // ── GGM salt tree (G8; MVP-SPEC.md line 96) ─────────────────────────
    /// A node address names a level deeper than any representable tree.
    /// `n <= u64::MAX` bounds `d = ceil(log2 n)` at
    /// [`NodeAddress::MAX_LEVEL`](super::NodeAddress::MAX_LEVEL).
    #[error("GGM node address: level {level} exceeds the maximum tree depth {max}")]
    NodeAddressLevelTooDeep {
        /// The rejected level.
        level: u8,
        /// The maximum representable level (64).
        max: u8,
    },

    /// A node address names an index outside its level: a level-`l` slot
    /// index must satisfy `index < 2^l` (the index's `l` bits **are** the
    /// root-to-node path, MVP-SPEC.md line 96).
    #[error(
        "GGM node address: index {index} is out of range at level {level} \
         (index must be less than 2^level)"
    )]
    NodeAddressIndexOutOfRange {
        /// The address's level.
        level: u8,
        /// The rejected index.
        index: u64,
    },

    /// A node address names a level below the depth of the tree it is being
    /// resolved against (`level > d`). Distinct from
    /// [`Self::NodeAddressLevelTooDeep`], which is the absolute bound: this
    /// address is representable, just not in *this* file's tree.
    #[error("GGM node address: level {level} is below this tree's depth {depth}")]
    NodeAddressLevelExceedsDepth {
        /// The address's level.
        level: u8,
        /// The resolving tree's depth `d`.
        depth: u8,
    },

    /// A node address covers only **unused** leaf slots (`i >= n`). Slots at
    /// or past the leaf count commit nothing (MVP-SPEC.md line 96: "slots
    /// `i >= n` are unused"), and no public output path derives their seeds —
    /// this is the error that makes that rule structural.
    #[error(
        "GGM node address: slot covers only unused leaf slots \
         (first slot {first_slot} is at or past the leaf count {leaf_count})"
    )]
    UnusedGgmSlot {
        /// First leaf slot the address covers.
        first_slot: u64,
        /// The tree's leaf count `n`.
        leaf_count: u64,
    },
}

impl ContentError {
    /// Stable machine-readable code, pairwise-distinct across every variant —
    /// the G-side leg of Q7's error-code stability contract (open decision
    /// D30), delegated through `verify::VerifyError`'s wrapper arm exactly
    /// like the codec's `cbor-*` and the crypto layer's `crypto-*` codes.
    /// Lowercase kebab-case, `content-` prefixed so the global tamper matrix
    /// stays distinct across domains; never changes once a tamper row binds
    /// to it.
    ///
    /// The exhaustive, wildcard-free match is the compile-time guard: a new
    /// variant fails compilation here until it receives a distinct code — and
    /// an exemplar in `all_code_exemplars`.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::BinaryCanonicalFineTreeDomain => "content-binary-canonical-fine-tree-domain",
            Self::TextRawFineTreeDomain => "content-text-raw-fine-tree-domain",
            Self::TextMissingUnicodeVersion => "content-text-missing-unicode-version",
            Self::BinaryUnicodeVersion => "content-binary-unicode-version",
            Self::FineTreePresentWithoutDomain => "content-fine-tree-present-without-domain",
            Self::FineTreeAbsentWithDomain => "content-fine-tree-absent-with-domain",
            Self::FineTreePresentOnEmptyFile => "content-fine-tree-present-on-empty-file",
            Self::NodeAddressLevelTooDeep { .. } => "content-node-address-level-too-deep",
            Self::NodeAddressIndexOutOfRange { .. } => "content-node-address-index-out-of-range",
            Self::NodeAddressLevelExceedsDepth { .. } => "content-node-address-level-exceeds-depth",
            Self::UnusedGgmSlot { .. } => "content-unused-ggm-slot",
        }
    }
}

/// One exemplar per distinct [`ContentError::code`] — every variant exactly
/// once, with pairwise-distinct `Display` renderings. Consumed by this
/// module's distinctness meta-test; the shape R's `verify::error` meta-test
/// reuses when it wraps these in the `VerifyError::Content` arm (the
/// `cbor-*`/`crypto-*` precedent).
#[cfg(test)]
pub(crate) fn all_code_exemplars() -> Vec<ContentError> {
    use ContentError as E;
    vec![
        E::BinaryCanonicalFineTreeDomain,
        E::TextRawFineTreeDomain,
        E::TextMissingUnicodeVersion,
        E::BinaryUnicodeVersion,
        E::FineTreePresentWithoutDomain,
        E::FineTreeAbsentWithDomain,
        E::FineTreePresentOnEmptyFile,
        E::NodeAddressLevelTooDeep { level: 65, max: 64 },
        E::NodeAddressIndexOutOfRange { level: 3, index: 8 },
        E::NodeAddressLevelExceedsDepth { level: 4, depth: 3 },
        E::UnusedGgmSlot {
            first_slot: 6,
            leaf_count: 6,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::discriminant;
    use std::collections::BTreeSet;
    use std::error::Error as _;

    /// Distinctness meta-test for the `content-` domain (mirrors the
    /// `crypto-`/`cbor-` meta-tests): every variant has an exemplar, codes are
    /// pairwise distinct, correctly prefixed and kebab-cased, and `Display`
    /// renderings are pairwise distinct too (the property R's verify-side
    /// meta-test relies on when it wraps these).
    #[test]
    fn codes_are_pairwise_distinct_and_prefixed() {
        let exemplars = all_code_exemplars();
        assert_eq!(
            exemplars.len(),
            11,
            "one exemplar per variant — keep exhaustive when adding variants"
        );

        let codes: BTreeSet<&'static str> = exemplars.iter().map(ContentError::code).collect();
        assert_eq!(codes.len(), exemplars.len(), "codes pairwise distinct");
        for code in &codes {
            assert!(
                code.starts_with("content-"),
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

        // Discriminants pairwise distinct: no two exemplars share a variant.
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

    /// Cross-domain distinctness: no `content-` code can collide with a
    /// `crypto-` or `cbor-` code, because the prefixes differ — asserted
    /// rather than assumed, since the tamper matrix is global.
    #[test]
    fn content_codes_cannot_collide_with_other_domains() {
        for err in all_code_exemplars() {
            let code = err.code();
            assert!(!code.starts_with("crypto-"), "{code}");
            assert!(!code.starts_with("cbor-"), "{code}");
        }
    }

    /// Project rules 4/6: `Display` renders structural metadata only — no
    /// byte content, and nothing hex-formatted that could carry it.
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
            ContentError::NodeAddressLevelTooDeep { level: 65, max: 64 }.to_string(),
            "GGM node address: level 65 exceeds the maximum tree depth 64"
        );
        assert_eq!(
            ContentError::NodeAddressIndexOutOfRange { level: 3, index: 8 }.to_string(),
            "GGM node address: index 8 is out of range at level 3 \
             (index must be less than 2^level)"
        );
        assert_eq!(
            ContentError::NodeAddressLevelExceedsDepth { level: 4, depth: 3 }.to_string(),
            "GGM node address: level 4 is below this tree's depth 3"
        );
        assert_eq!(
            ContentError::UnusedGgmSlot {
                first_slot: 6,
                leaf_count: 6
            }
            .to_string(),
            "GGM node address: slot covers only unused leaf slots \
             (first slot 6 is at or past the leaf count 6)"
        );
    }
}
