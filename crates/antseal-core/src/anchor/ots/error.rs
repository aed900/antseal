//! The `.ots` codec's rejection taxonomy (task **A11**).
//!
//! # One prefix, `anchor-` (D91)
//!
//! D58 §10.4 listed sixteen codes under a proposed `ots-` prefix. **`ots-` is
//! not registered and never will be**: D91 §6.1 rules one prefix for the A
//! domain, and §7.1 maps D58's sixteen onto it — fifteen mechanically, and
//! one by *merge*. The merged one is the digest-commitment check: its code is
//! **`anchor-ots-digest-mismatch`** (D56 §7 / rule O2), which D53 §8 already
//! binds M2 tamper row 1 to, and D58's spelling
//! `ots-ops-do-not-commit-anchor-digest` is **never minted**.
//!
//! So A11 mints **fifteen** codes and raises a sixteenth that is D56's.
//!
//! # Registration is A38's, not A11's
//!
//! `docs/testing/error-code-contract.md` §2 has no `anchor-` row in this
//! worktree and `error_universe::by_enumerator()` has no A-domain enumerator;
//! both are **A38/Q80**'s (D91 §10). [`all_code_exemplars`] is written to the
//! same shape as its six siblings so that A38's wiring is one entry, and
//! `tests::every_ots_code_is_pairwise_distinct_and_anchor_prefixed` (D56
//! §9) holds the line until then.
//!
//! # Secret hygiene (project rule 6)
//!
//! Payloads are byte counts, wire tags and limit values — **never artifact
//! content**, never the `anchor_digest`, never an operand. `.ots` bytes are
//! public evidence, but the discipline is the crate's and does not get an
//! exception for a format that happens to be public.

use core::fmt;

use thiserror::Error;

/// Why an attestation's own payload parse failed, for **rendering only**.
///
/// One code covers all three (`anchor-ots-attestation-payload-not-consumed`).
/// This follows C28's rule as D91 §1 restates it — *"the duplicated algorithm
/// is payload, not a code discriminant"* — and D85/R33's *"the codes name the
/// check that failed, not the field that was wrong"*. The check that failed
/// is one check: **D58 §10.2 rule 2**, *"parse the height or the URI within
/// that slice, and require the slice to be exhausted"*.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PayloadDefect {
    /// The type's own parse succeeded but left bytes in the sub-slice. This
    /// is D58 §4's differential exactly: `opentimestamps` 0.2.0 reads the
    /// declared length and then ignores it, so a Bitcoin attestation
    /// declaring 9 payload bytes and writing 1 makes that crate and
    /// `python-opentimestamps` report **different attestation sets from
    /// identical bytes**.
    Leftover,
    /// The type's own parse ran past the end of its sub-slice — a length
    /// inside the payload that reaches outside it.
    ShortRead,
    /// A pending attestation's URI is not valid UTF-8.
    ///
    /// D58 §10.4's sixteen codes have no arm for this and the reference
    /// implementation rejects the whole file (`PendingAttestation.deserialize`
    /// raises after `validate_uri`), so rejecting matches it. Recorded here
    /// rather than minted as a sixteenth A11 code: under
    /// `docs/testing/error-code-contract.md` §3 a code is permanent from its
    /// first binding, and D91 exists because sixteen codes were once minted
    /// under a namespace nobody had registered.
    NotUtf8,
}

impl fmt::Display for PayloadDefect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::Leftover => "declared length not consumed by the payload's own parse",
            Self::ShortRead => "payload parse ran past its declared length",
            Self::NotUtf8 => "pending URI is not valid UTF-8",
        };
        f.write_str(text)
    }
}

/// A rejected `.ots` artifact.
///
/// Every variant renders that **anchor alone** `invalid` (rule F2/F3); none
/// of them can fail a bundle decode, because [`super::parse_ots`] is not
/// reachable from `SealProof::decode` (rule F1).
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum OtsError {
    /// The 31-byte container magic is wrong (check order step 1).
    #[error("not an .ots file: the 31-byte OpenTimestamps magic does not match")]
    BadMagic,

    /// The major version varuint is not 1 (step 2).
    #[error("unsupported .ots major version {version}")]
    UnsupportedVersion {
        /// The version the file declares.
        version: u64,
    },

    /// The digest-type tag is not `0x08` = SHA-256 (step 3).
    ///
    /// Distinct from [`Self::DigestMismatch`] on purpose (D91 §7.2's near-miss
    /// list): same header, one field earlier, a *type* rather than a *value*.
    #[error("unsupported .ots digest type tag 0x{tag:02x} (only SHA-256, 0x08, is supported)")]
    UnsupportedDigestType {
        /// The tag the file declares.
        tag: u8,
    },

    /// A read ran past the end of the input (step 4, and walk rule j).
    #[error("truncated .ots: {needed} more byte(s) needed at offset {offset}")]
    Truncated {
        /// Where the read started.
        offset: u64,
        /// How many more bytes it wanted.
        needed: u64,
    },

    /// The DAG ended before the input did (step 7).
    ///
    /// The other direction of [`Self::Truncated`]'s boundary. Two codes, not
    /// one: D58 §10.3 fires them at different steps and both are reachable
    /// (D91 §7.2).
    #[error("{extra} trailing byte(s) after the end of the .ots timestamp")]
    TrailingBytes {
        /// How many bytes are left over.
        extra: u64,
    },

    /// A varuint ran past 9 bytes (walk rule a).
    ///
    /// The bound is what makes the decoder's answer independent of the build
    /// profile: 9 continuation-free bytes carry 63 bits, so no shift can
    /// reach 64. D58 §3.3 measured the alternative — the rejected crate's
    /// unbounded `shift` **panics in debug and silently parses to a different
    /// answer in release**, and this project's CI has no release test lane
    /// anywhere, so that divergence is structurally invisible to it.
    #[error("over-long .ots varuint at offset {offset}: more than 9 bytes")]
    VarintTooLong {
        /// Where the varuint started.
        offset: u64,
    },

    /// The file's start digest is not this seal's `anchor_digest` (step 5).
    ///
    /// **The code is D56's, not D58's** — see the module docs. Raised inside
    /// the parser, before the walk, deliberately: every attestation in the
    /// file descends from the start digest, so the equality on that one
    /// header field *is* the commitment check, and putting it ahead of the
    /// walk means a wrong-digest `.ots` costs one 32-byte comparison and can
    /// never be used as a work amplifier (D58 §10.3; D91 §6.4).
    #[error("the .ots stamps a different digest than this seal's anchor_digest")]
    DigestMismatch,

    /// [`super::MAX_OTS_OPS`] exceeded (walk rule c).
    #[error("too many .ots ops: more than {limit}")]
    TooManyOps {
        /// The limit that fired.
        limit: u32,
    },

    /// [`super::MAX_OTS_DEPTH`] exceeded (walk rule b).
    #[error("the .ots op DAG is deeper than {limit}")]
    TooDeep {
        /// The limit that fired.
        limit: u32,
    },

    /// [`super::MAX_OTS_BRANCH_WIDTH`] exceeded (walk rule f).
    #[error("an .ots fork node has more than {limit} children")]
    BranchTooWide {
        /// The limit that fired.
        limit: u32,
    },

    /// [`super::MAX_OTS_ATTESTATIONS`] exceeded (walk rule g).
    #[error("too many .ots attestations: more than {limit}")]
    TooManyAttestations {
        /// The limit that fired.
        limit: u32,
    },

    /// [`super::MAX_OTS_OPERAND_BYTES`] exceeded (walk rule d), checked
    /// **before** the operand is read.
    #[error("an .ots append/prepend operand declares {declared} bytes, over the limit of {limit}")]
    OperandTooLong {
        /// The limit that fired.
        limit: u32,
        /// The length the file declares.
        declared: u64,
    },

    /// [`super::MAX_OTS_VALUE_BYTES`] would be exceeded (walk rule e),
    /// checked **before** the new value is allocated.
    ///
    /// Closes D58 §3.2: in the rejected crate the *operand* was capped and
    /// the *running value* was not, so a 102-byte file drove an uncatchable
    /// `SIGABRT` out of a doubling chain.
    #[error(
        "an .ots op would grow the running value to {would_be} bytes, over the limit of {limit}"
    )]
    ValueTooLong {
        /// The limit that fired.
        limit: u32,
        /// The length the op would have produced.
        would_be: u64,
    },

    /// [`super::MAX_OTS_ATTESTATION_PAYLOAD_BYTES`] exceeded (walk rule h),
    /// checked **before** the payload is read.
    ///
    /// Closes D58 §3.1: `vec![0; attacker_varint]` with no cap, allocated
    /// before a byte was read. That is `handle_alloc_error`, **not** a panic
    /// — `catch_unwind` cannot intercept it and in WASM it is a module trap.
    #[error("an .ots attestation declares a {declared}-byte payload, over the limit of {limit}")]
    AttestationPayloadTooLong {
        /// The limit that fired.
        limit: u32,
        /// The length the file declares.
        declared: u64,
    },

    /// An attestation's payload sub-slice did not parse under its own type's
    /// grammar (walk rule i).
    #[error("an .ots attestation payload is malformed: {defect}")]
    AttestationPayloadNotConsumed {
        /// Which way it failed — rendering only, never a code discriminant.
        defect: PayloadDefect,
    },

    /// An op tag in neither the implemented set `{0x08, 0xf0, 0xf1}` nor the
    /// registered-but-unimplemented set `{0x02, 0x03, 0x67, 0xf2, 0xf3}`.
    ///
    /// **A parse error, not an unverifiable result**, and this is the
    /// correction D58 §12.2 makes to A11's original `Do`: an unknown
    /// *attestation* payload is length-prefixed and therefore skippable, but
    /// an unknown *op tag carries no length*, so the parser cannot find where
    /// it ends and cannot reach anything after it. An artifact we cannot
    /// finish reading is not known to be well-formed — F3's own reasoning.
    #[error("unknown .ots op tag 0x{tag:02x}")]
    UnknownOp {
        /// The tag that was not recognised.
        tag: u8,
    },
}

impl OtsError {
    /// The stable diagnostic code for this rejection.
    ///
    /// Fifteen of the sixteen are A11's; `anchor-ots-digest-mismatch` is
    /// D56's and is *raised* here rather than minted (D91 §7.1).
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::BadMagic => "anchor-ots-bad-magic",
            Self::UnsupportedVersion { .. } => "anchor-ots-unsupported-version",
            Self::UnsupportedDigestType { .. } => "anchor-ots-unsupported-digest-type",
            Self::Truncated { .. } => "anchor-ots-truncated",
            Self::TrailingBytes { .. } => "anchor-ots-trailing-bytes",
            Self::VarintTooLong { .. } => "anchor-ots-varint-too-long",
            Self::DigestMismatch => "anchor-ots-digest-mismatch",
            Self::TooManyOps { .. } => "anchor-ots-too-many-ops",
            Self::TooDeep { .. } => "anchor-ots-too-deep",
            Self::BranchTooWide { .. } => "anchor-ots-branch-too-wide",
            Self::TooManyAttestations { .. } => "anchor-ots-too-many-attestations",
            Self::OperandTooLong { .. } => "anchor-ots-operand-too-long",
            Self::ValueTooLong { .. } => "anchor-ots-value-too-long",
            Self::AttestationPayloadTooLong { .. } => "anchor-ots-attestation-payload-too-long",
            Self::AttestationPayloadNotConsumed { .. } => {
                "anchor-ots-attestation-payload-not-consumed"
            }
            Self::UnknownOp { .. } => "anchor-ots-unknown-op",
        }
    }
}

/// One exemplar per distinct code, in the shape `error_universe` collects.
///
/// Kept `pub(crate)` and `cfg(test)` to match its six siblings; **A38** adds
/// the `anchor::error::all_code_exemplars` row that reaches it (D91 §8.1),
/// which is also when `the_universe_is_exactly_the_eight_enumerators` moves
/// 8 → 9 (D91 §8.2).
#[cfg(test)]
pub(crate) fn all_code_exemplars() -> Vec<OtsError> {
    use OtsError as E;
    vec![
        E::BadMagic,
        E::UnsupportedVersion { version: 2 },
        E::UnsupportedDigestType { tag: 0x02 },
        E::Truncated {
            offset: 65,
            needed: 1,
        },
        E::TrailingBytes { extra: 1 },
        E::VarintTooLong { offset: 65 },
        E::DigestMismatch,
        E::TooManyOps {
            limit: super::MAX_OTS_OPS,
        },
        E::TooDeep {
            limit: super::MAX_OTS_DEPTH,
        },
        E::BranchTooWide {
            limit: super::MAX_OTS_BRANCH_WIDTH,
        },
        E::TooManyAttestations {
            limit: super::MAX_OTS_ATTESTATIONS,
        },
        E::OperandTooLong {
            limit: super::MAX_OTS_OPERAND_BYTES,
            declared: 16_385,
        },
        E::ValueTooLong {
            limit: super::MAX_OTS_VALUE_BYTES,
            would_be: 32_800,
        },
        E::AttestationPayloadTooLong {
            limit: super::MAX_OTS_ATTESTATION_PAYLOAD_BYTES,
            declared: 8_193,
        },
        E::AttestationPayloadNotConsumed {
            defect: PayloadDefect::Leftover,
        },
        E::UnknownOp { tag: 0x01 },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    /// D56 §9's row. Fails on a copy-pasted code, or one minted under
    /// another domain's prefix — which is the mutation D91 exists to forbid
    /// and which, measured, **nothing in the tree can otherwise see**:
    /// `census()` sorts an unregistered prefix into R's `"(unprefixed)"`
    /// bucket and prints it (D91 §8).
    #[test]
    fn every_ots_code_is_pairwise_distinct_and_anchor_prefixed() {
        let exemplars = all_code_exemplars();
        assert_eq!(
            exemplars.len(),
            16,
            "one exemplar per distinct code: A11 mints 15 and raises D56's 1 \
             (D91 §7.1) — update deliberately"
        );

        let codes: BTreeSet<&'static str> = exemplars.iter().map(OtsError::code).collect();
        assert_eq!(codes.len(), exemplars.len(), "codes pairwise distinct");

        for code in &codes {
            assert!(
                code.starts_with("anchor-"),
                "code {code:?} must carry the A domain's prefix; `ots-` is not \
                 registered and never will be (D91 §6.1)"
            );
            assert!(
                code.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'),
                "code {code:?} must be lowercase kebab-case"
            );
            assert!(!code.ends_with('-'), "code {code:?} must not end with '-'");
        }
    }

    /// D91 §6.2 rules that D58's spelling is never minted. A grep-level
    /// assertion, because the failure mode is a hand edit that "restores"
    /// D58's name from its own §10.3 table.
    #[test]
    fn the_losing_digest_code_spelling_is_never_minted() {
        for code in all_code_exemplars().iter().map(OtsError::code) {
            assert_ne!(
                code, "ots-ops-do-not-commit-anchor-digest",
                "D91 §6.2: the digest-commitment check is `anchor-ots-digest-mismatch`, \
                 to which D53 §8 already binds M2 tamper row 1"
            );
        }
        assert_eq!(
            OtsError::DigestMismatch.code(),
            "anchor-ots-digest-mismatch"
        );
    }

    /// Project rule 6, asserted rather than reviewed: rendering an error
    /// discloses metadata only.
    #[test]
    fn display_renders_metadata_only() {
        for error in all_code_exemplars() {
            let rendered = error.to_string();
            assert!(!rendered.is_empty(), "{error:?} renders empty");
            assert!(
                !rendered.contains("083f87df"),
                "{error:?} leaked artifact content"
            );
        }
    }
}
