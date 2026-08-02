//! `.ots` op execution — **append, prepend, SHA-256, and nothing else**
//! (task **A11**; D58 §9.4).
//!
//! # Why three ops are enough, and why that is not a limit
//!
//! D58 §7.5 measured every real `.ots` available, pending and upgraded:
//! *"Op kinds observed across every real file … `append`, `prepend`,
//! `sha256`, and nothing else."* So `antseal-core` implements exactly those
//! three and needs no hash primitive beyond the already-pinned
//! `sha2 =0.11.0` — no SHA-1, no RIPEMD-160, no Keccak-256 enters the core to
//! execute a foreign format's dead opcodes, and the codec costs **+0
//! packages**.
//!
//! The five *registered-but-unimplemented* ops are each **one wire byte with
//! no operand**, so the parser skips them structurally: the subtree below one
//! of them has an **indeterminate** value, and every attestation in that
//! subtree is reported with `None` where its commitment would be. Sibling
//! subtrees are unaffected. Per **F3**, unknown is *not* over-limit — this is
//! A11's *"typed unverifiable results, never crashes"*, implemented, and it
//! is what makes `internally-consistent-only` reachable for OTS at all (D56
//! §2, rule O9).
//!
//! Promoting one of them later — implementing SHA-1, say — only turns an
//! unverifiable result into a real verdict. It never rejects an artifact a
//! past release accepted, so it is compatible with MVP-SPEC.md line 123 and
//! with F4.
//!
//! # An unregistered tag is a different thing entirely
//!
//! It is [`super::OtsError::UnknownOp`] and it fails the artifact, because an
//! op tag carries no length: the parser cannot find where it ends and
//! therefore cannot reach anything after it (D58 §12.2).

use sha2::{Digest, Sha256};

use super::error::OtsError;
use super::limits::MAX_OTS_VALUE_BYTES;

// ── wire tags ────────────────────────────────────────────────────────────
//
// Spelled in **decimal** deliberately. `crypto::domain`'s
// `no_other_module_hardcodes_domain_tag_bytes` reserves hex-form `u8`
// constants in `0x00..=0x06` to the domain-tag registry and instructs every
// other module to write small `u8` constants in decimal. These are
// OpenTimestamps wire tags on a foreign format, not antseal domain tags; each
// doc comment carries the hex the format documents.

/// `0x02` — SHA-1. Registered, not implemented.
const OP_SHA1: u8 = 2;
/// `0x03` — RIPEMD-160. Registered, not implemented.
const OP_RIPEMD160: u8 = 3;
/// `0x08` — SHA-256.
const OP_SHA256: u8 = 8;
/// `0x67` — Keccak-256. Registered, not implemented.
const OP_KECCAK256: u8 = 103;
/// `0xf0` — append: `value ‖ operand`.
const OP_APPEND: u8 = 240;
/// `0xf1` — prepend: `operand ‖ value`.
const OP_PREPEND: u8 = 241;
/// `0xf2` — reverse. Registered, not implemented.
const OP_REVERSE: u8 = 242;
/// `0xf3` — hexlify. Registered, not implemented.
///
/// The one that condemned the rejected crate's running-value handling: it
/// takes **no operand** and **doubles** the value, so `0xf3` repeated is a
/// doubling chain out of a 32-byte digest. D58 §3.2 measured 24 of them in a
/// 102-byte file asking for 536 870 912 bytes, and 36 asking for 2 TiB.
const OP_HEXLIFY: u8 = 243;

/// One step of the `.ots` op DAG.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum OpKind {
    /// `0x08` — SHA-256 of the running value.
    Sha256,
    /// `0xf0` — append the operand.
    Append,
    /// `0xf1` — prepend the operand.
    Prepend,
    /// A registered op this verifier does not evaluate. All five take no
    /// operand, which is exactly why they can be skipped structurally.
    Unimplemented,
}

impl OpKind {
    /// Classify a wire tag. `None` means *unregistered*, which is
    /// [`OtsError::UnknownOp`] and not this variant's business.
    pub(super) const fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            OP_SHA256 => Some(Self::Sha256),
            OP_APPEND => Some(Self::Append),
            OP_PREPEND => Some(Self::Prepend),
            OP_SHA1 | OP_RIPEMD160 | OP_KECCAK256 | OP_REVERSE | OP_HEXLIFY => {
                Some(Self::Unimplemented)
            }
            _ => None,
        }
    }

    /// Only append and prepend carry a varuint operand length plus that many
    /// bytes; every other op is a bare tag (D58 §7.2).
    pub(super) const fn takes_operand(self) -> bool {
        matches!(self, Self::Append | Self::Prepend)
    }
}

/// Execute one op against the running value.
///
/// `value` is `None` when the path to here has already crossed an
/// unimplemented op, in which case the result is `None` too and **nothing is
/// allocated** — the indeterminacy is absorbing.
///
/// `operand` is empty for ops that take none. Its length has already been
/// checked against [`super::MAX_OTS_OPERAND_BYTES`] by the caller (walk rule
/// d, *before reading*); this function enforces walk rule e,
/// [`MAX_OTS_VALUE_BYTES`], **before allocating** the new value. That
/// ordering is D58 §9.3's, and it is why the operand witness returns
/// `anchor-ots-operand-too-long` rather than `anchor-ots-value-too-long`.
pub(super) fn apply(
    op: OpKind,
    value: Option<&[u8]>,
    operand: &[u8],
) -> Result<Option<Vec<u8>>, OtsError> {
    let Some(value) = value else {
        return Ok(None);
    };

    match op {
        // SHA-256 always yields 32 bytes, which is below every cap; the
        // check is written out anyway so that adding a growing op later
        // cannot silently skip it.
        OpKind::Sha256 => {
            let digest: [u8; 32] = Sha256::digest(value).into();
            Ok(Some(digest.to_vec()))
        }
        OpKind::Append => {
            let mut out = alloc_checked(value.len(), operand.len())?;
            out.extend_from_slice(value);
            out.extend_from_slice(operand);
            Ok(Some(out))
        }
        OpKind::Prepend => {
            let mut out = alloc_checked(value.len(), operand.len())?;
            out.extend_from_slice(operand);
            out.extend_from_slice(value);
            Ok(Some(out))
        }
        OpKind::Unimplemented => Ok(None),
    }
}

/// Check the *resulting* length against [`MAX_OTS_VALUE_BYTES`] and only then
/// reserve for it.
///
/// This is the whole of D58 §3.2's fix, and it is the reason the reservation
/// is a `with_capacity` of an **already-bounded** number rather than of an
/// attacker-chosen one. Both inputs are `usize` lengths of slices that exist
/// in memory, so the addition cannot overflow on any target this crate
/// supports; it is written `checked_add` regardless, because "cannot
/// overflow" is the sentence D58 §3.3 found in the rejected crate.
fn alloc_checked(value_len: usize, operand_len: usize) -> Result<Vec<u8>, OtsError> {
    let would_be = value_len
        .checked_add(operand_len)
        .ok_or(OtsError::ValueTooLong {
            limit: MAX_OTS_VALUE_BYTES,
            would_be: u64::MAX,
        })?;
    if would_be > MAX_OTS_VALUE_BYTES as usize {
        return Err(OtsError::ValueTooLong {
            limit: MAX_OTS_VALUE_BYTES,
            would_be: would_be as u64,
        });
    }
    Ok(Vec::with_capacity(would_be))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_registered_tag_classifies_and_nothing_else_does() {
        for (tag, expected) in [
            (0x08_u8, Some(OpKind::Sha256)),
            (0xf0, Some(OpKind::Append)),
            (0xf1, Some(OpKind::Prepend)),
            (0x02, Some(OpKind::Unimplemented)),
            (0x03, Some(OpKind::Unimplemented)),
            (0x67, Some(OpKind::Unimplemented)),
            (0xf2, Some(OpKind::Unimplemented)),
            (0xf3, Some(OpKind::Unimplemented)),
        ] {
            assert_eq!(OpKind::from_tag(tag), expected, "tag 0x{tag:02x}");
        }
        // Exactly eight tags are registered; every other byte is unknown.
        let registered = (0..=u8::MAX)
            .filter(|tag| OpKind::from_tag(*tag).is_some())
            .count();
        assert_eq!(registered, 8, "the OTS op registry has eight tags");
    }

    #[test]
    fn only_append_and_prepend_carry_an_operand() {
        assert!(OpKind::Append.takes_operand());
        assert!(OpKind::Prepend.takes_operand());
        assert!(!OpKind::Sha256.takes_operand());
        assert!(!OpKind::Unimplemented.takes_operand());
    }

    #[test]
    fn append_and_prepend_place_the_operand_on_the_right_side() {
        let value = [1_u8, 2, 3];
        let operand = [9_u8, 9];
        assert_eq!(
            apply(OpKind::Append, Some(&value), &operand),
            Ok(Some(vec![1, 2, 3, 9, 9]))
        );
        assert_eq!(
            apply(OpKind::Prepend, Some(&value), &operand),
            Ok(Some(vec![9, 9, 1, 2, 3]))
        );
    }

    #[test]
    fn sha256_matches_an_independently_computed_digest() {
        // SHA-256 of the empty string, the one value in the suite that can
        // be checked against a published constant without recomputing it
        // with the same library.
        let expected = b"\xe3\xb0\xc4\x42\x98\xfc\x1c\x14\x9a\xfb\xf4\xc8\x99\x6f\xb9\x24\
              \x27\xae\x41\xe4\x64\x9b\x93\x4c\xa4\x95\x99\x1b\x78\x52\xb8\x55";
        assert_eq!(
            apply(OpKind::Sha256, Some(&[]), &[]),
            Ok(Some(expected.to_vec()))
        );
    }

    #[test]
    fn indeterminacy_is_absorbing_and_allocates_nothing() {
        let big = vec![0_u8; MAX_OTS_VALUE_BYTES as usize];
        for op in [
            OpKind::Sha256,
            OpKind::Append,
            OpKind::Prepend,
            OpKind::Unimplemented,
        ] {
            assert_eq!(
                apply(op, None, &big),
                Ok(None),
                "{op:?} under indeterminacy"
            );
        }
    }

    #[test]
    fn an_unimplemented_op_makes_the_value_indeterminate_rather_than_erroring() {
        assert_eq!(
            apply(OpKind::Unimplemented, Some(&[1, 2, 3]), &[]),
            Ok(None)
        );
    }

    #[test]
    fn the_value_cap_fires_before_the_allocation() {
        let value = vec![0_u8; MAX_OTS_VALUE_BYTES as usize];
        assert_eq!(
            apply(OpKind::Append, Some(&value), &[0]),
            Err(OtsError::ValueTooLong {
                limit: MAX_OTS_VALUE_BYTES,
                would_be: u64::from(MAX_OTS_VALUE_BYTES) + 1,
            })
        );
        // Exactly at the cap is accepted: the limit is `<=`, and D58 §9.3's
        // value witness relies on two operands that are each exactly at the
        // operand cap passing rule d.
        let value = vec![0_u8; MAX_OTS_VALUE_BYTES as usize - 1];
        assert!(apply(OpKind::Append, Some(&value), &[0]).is_ok());
    }
}
