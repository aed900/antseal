//! Unit padding codec: formula, apply, length-first strip, rejections
//! (tasks/C.md C8; MVP-SPEC.md lines 91, 121, 168).
//!
//! ```text
//! padded_length(true_length) = ⌈(true_length + 1) / 256⌉ · 256
//! ```
//!
//! Always **at least one pad byte**, so a unit whose content already ends
//! on a 256-B boundary is unambiguous, and the empty unit
//! (`true_length = 0`) pads to 256. Stripping is **length-first** — driven
//! by the manifest's `true_length`, never by scanning — so genuine trailing
//! `0x00` content survives. The verifier recomputes the formula and rejects
//! any unit whose AEAD-plaintext length ≠ `padded_length`
//! ([`CryptoError::PaddingLengthMismatch`], blocking silent over-padding)
//! and any non-zero byte beyond `true_length`
//! ([`CryptoError::NonZeroPadding`]) — the spec-line-121 structural
//! invariant "padding conforms to the `padded_length` formula and is
//! all-zero beyond `true_length`", and the line-168 tamper rows
//! *over-padded unit* + its non-zero-pad companion.
//!
//! # What padding does and does not hide (spec line 91)
//!
//! Padding coarsens each unit's ciphertext length to a 256-B bucket: an
//! observer still learns **`⌊true_length / 256⌋`** — the bucketing leak. It
//! is cheap **defense-in-depth** against a passive storage-layer size peek,
//! **not** a full fingerprint defense — per-unit selective disclosure
//! inherently exposes per-unit size, so the vector of bucketed sizes
//! (especially under `--split`) remains a partial fingerprint; the residual
//! risk and who can exploit it are documented in the threat model. Bundle
//! recipients see true lengths by design.
//!
//! # Format-version scope (spec line 91)
//!
//! This formula is **format-version-scoped**: a future format version may
//! adopt a coarser scheme (e.g. Padmé, `O(log log n)` leak) without
//! breaking v1 seals, if real fingerprinting data ever justifies its
//! permanent storage cost. Verifiers dispatch on the recorded format
//! version; this module is the v1 codec.

use super::error::CryptoError;

/// The v1 padding bucket size in bytes (spec line 91).
pub const PAD_BLOCK: usize = 256;

/// The exact formula over `u128` — total for every `u64`/`usize` input
/// (adversarial manifest values included), with headroom that cannot
/// overflow. All verdict-bearing comparisons use this form.
const fn padded_length_exact(true_length: u128) -> u128 {
    (true_length + 1).div_ceil(PAD_BLOCK as u128) * (PAD_BLOCK as u128)
}

/// `padded_length(true_length) = ⌈(true_length + 1) / 256⌉ · 256`
/// (spec line 91).
///
/// Exact for every length a real plaintext buffer can have (allocations
/// cap at `isize::MAX`, comfortably below the overflow range). In the
/// degenerate top range no buffer can occupy
/// (`true_length > usize::MAX − 256`) it saturates to `usize::MAX` instead
/// of panicking; [`strip_padding`]'s verdict-bearing comparison uses the
/// exact wide-arithmetic form and is unaffected by the saturation.
#[must_use]
pub fn padded_length(true_length: usize) -> usize {
    usize::try_from(padded_length_exact(true_length as u128)).unwrap_or(usize::MAX)
}

/// Zero-fill `bytes` up to `padded_length(bytes.len())` (the encrypt-side
/// step C9 runs before AEAD; spec line 91). The returned buffer holds
/// secret unit content — C9 zeroizes it after encryption.
#[must_use]
pub fn apply_padding(bytes: &[u8]) -> Vec<u8> {
    let mut padded = Vec::with_capacity(padded_length(bytes.len()));
    padded.extend_from_slice(bytes);
    padded.resize(padded_length(bytes.len()), 0);
    padded
}

/// Length-first padding strip, driven by the manifest's `true_length`
/// (spec lines 91, 121): validates, then returns the unit's exact bytes
/// `&plaintext[..true_length]`. Genuine trailing `0x00` content survives —
/// nothing is ever inferred by scanning.
///
/// # Errors
///
/// - [`CryptoError::PaddingLengthMismatch`] when
///   `plaintext.len() != padded_length(true_length)` (blocks silent
///   over-padding; tamper row *over-padded unit*, spec line 168).
/// - [`CryptoError::NonZeroPadding`] when any byte beyond `true_length` is
///   non-zero (`offset` = the first offending byte's position within the
///   padded plaintext).
pub fn strip_padding(plaintext: &[u8], true_length: usize) -> Result<&[u8], CryptoError> {
    let expected = padded_length_exact(true_length as u128);
    if plaintext.len() as u128 != expected {
        return Err(CryptoError::PaddingLengthMismatch {
            // Comparison above is exact; the payload saturates only in the
            // degenerate range no real buffer can occupy (diagnostic
            // metadata, never verdict-bearing).
            expected: usize::try_from(expected).unwrap_or(usize::MAX),
            got: plaintext.len(),
        });
    }
    // Length check passed ⇒ plaintext.len() ≥ true_length + 1 (the formula
    // guarantees at least one pad byte), so the range below is in bounds.
    if let Some(position) = plaintext[true_length..].iter().position(|&byte| byte != 0) {
        return Err(CryptoError::NonZeroPadding {
            offset: true_length + position,
        });
    }
    Ok(&plaintext[..true_length])
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use proptest::test_runner::RngSeed;

    /// C8 accept: the table-driven formula cases.
    #[test]
    fn padded_length_table() {
        let table: [(usize, usize); 7] = [
            (0, 256),
            (1, 256),
            (255, 256),
            (256, 512),
            (257, 512),
            (511, 512),
            (512, 768),
        ];
        for (true_length, expected) in table {
            assert_eq!(padded_length(true_length), expected, "t = {true_length}");
        }
    }

    /// Always at least one pad byte, and the result is always a positive
    /// multiple of the block (spec line 91: a unit ending on a 256-B
    /// boundary is unambiguous).
    #[test]
    fn always_at_least_one_pad_byte() {
        for true_length in 0..=(4 * PAD_BLOCK + 3) {
            let padded = padded_length(true_length);
            assert!(padded > true_length, "t = {true_length}");
            assert!(padded.is_multiple_of(PAD_BLOCK), "t = {true_length}");
            assert!(padded - true_length <= PAD_BLOCK, "t = {true_length}");
        }
    }

    /// Round-trip including genuine trailing-`0x00` content — length-first
    /// stripping must preserve it (spec line 91).
    #[test]
    fn round_trip_preserves_trailing_zero_content() {
        let content = b"data ending in zeros\x00\x00\x00";
        let padded = apply_padding(content);
        assert_eq!(padded.len(), 256);
        let stripped = strip_padding(&padded, content.len()).expect("valid padding");
        assert_eq!(stripped, content);

        // All-zero content of one full block: pads to two blocks, strips
        // back intact.
        let zeros = [0u8; 256];
        let padded = apply_padding(&zeros);
        assert_eq!(padded.len(), 512);
        assert_eq!(strip_padding(&padded, 256).expect("valid"), &zeros[..]);
    }

    /// The empty unit pads to exactly one block and strips back to empty
    /// (spec line 91).
    #[test]
    fn empty_unit_pads_to_one_block() {
        let padded = apply_padding(b"");
        assert_eq!(padded, vec![0u8; 256]);
        assert_eq!(strip_padding(&padded, 0).expect("valid"), b"");
    }

    /// C8 accept: a plaintext one whole block too long (over-padded — the
    /// formula violated) rejects with `PaddingLengthMismatch`; a correct
    /// length with a non-zero pad byte rejects with `NonZeroPadding`; the
    /// two errors are distinct (tamper matrix line 168).
    #[test]
    fn rejects_over_padding_and_non_zero_padding_distinctly() {
        let content = b"unit";

        // One 256-block too long: correct-formula violation.
        let mut over_padded = apply_padding(content);
        over_padded.extend_from_slice(&[0u8; 256]);
        let over_err = strip_padding(&over_padded, content.len()).expect_err("must reject");
        assert_eq!(
            over_err,
            CryptoError::PaddingLengthMismatch {
                expected: 256,
                got: 512
            }
        );

        // Correct length, but a non-zero byte in the pad region.
        let mut tampered = apply_padding(content);
        tampered[100] = 0x01;
        let pad_err = strip_padding(&tampered, content.len()).expect_err("must reject");
        assert_eq!(pad_err, CryptoError::NonZeroPadding { offset: 100 });

        // Distinct variants.
        assert_ne!(
            core::mem::discriminant(&over_err),
            core::mem::discriminant(&pad_err)
        );
    }

    /// The `NonZeroPadding` offset is the position within the padded
    /// plaintext of the **first** offending byte.
    #[test]
    fn non_zero_padding_reports_first_offending_offset() {
        let content = [0xFFu8; 300]; // pads to 512
        let mut padded = apply_padding(&content);
        padded[400] = 0x02;
        padded[500] = 0x03;
        assert_eq!(
            strip_padding(&padded, 300).expect_err("must reject"),
            CryptoError::NonZeroPadding { offset: 400 }
        );
        // A non-zero byte at true_length itself (the first pad position) is
        // caught with that exact offset.
        let mut padded = apply_padding(&content);
        padded[300] = 0x01;
        assert_eq!(
            strip_padding(&padded, 300).expect_err("must reject"),
            CryptoError::NonZeroPadding { offset: 300 }
        );
    }

    /// Under-length and truncated plaintexts also reject via the length
    /// check (length-first: no byte scanning happens on a wrong-length
    /// buffer).
    #[test]
    fn rejects_wrong_length_without_scanning() {
        // Too short by one block.
        assert_eq!(
            strip_padding(&[0u8; 256], 300).expect_err("must reject"),
            CryptoError::PaddingLengthMismatch {
                expected: 512,
                got: 256
            }
        );
        // Not a block multiple.
        assert_eq!(
            strip_padding(&[0u8; 300], 300).expect_err("must reject"),
            CryptoError::PaddingLengthMismatch {
                expected: 512,
                got: 300
            }
        );
        // Empty plaintext can never satisfy the formula (minimum is 256).
        assert_eq!(
            strip_padding(&[], 0).expect_err("must reject"),
            CryptoError::PaddingLengthMismatch {
                expected: 256,
                got: 0
            }
        );
    }

    /// Adversarial `true_length` values near `usize::MAX` are handled
    /// totally — an error verdict, never a panic or overflow (defensive
    /// parsing; the wide-arithmetic comparison is exact).
    #[test]
    fn adversarial_true_length_cannot_panic() {
        for extreme in [
            usize::MAX,
            usize::MAX - 1,
            usize::MAX - 255,
            usize::MAX - 256,
        ] {
            let err = strip_padding(&[0u8; 256], extreme).expect_err("must reject");
            assert!(matches!(err, CryptoError::PaddingLengthMismatch { .. }));
        }
        // The saturating public helper also stays total.
        assert_eq!(padded_length(usize::MAX), usize::MAX);
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            // Deterministic fixed seed per the determinism principle (Q3
            // later centralizes proptest conventions).
            cases: 2048,
            rng_seed: RngSeed::Fixed(0xC8_5EA1),
            .. ProptestConfig::default()
        })]

        /// C8 accept: round-trip property over arbitrary bytes (trailing
        /// zeros included by the byte distribution).
        #[test]
        fn prop_round_trip(bytes in proptest::collection::vec(any::<u8>(), 0..=(4 * PAD_BLOCK + 3))) {
            let padded = apply_padding(&bytes);
            prop_assert_eq!(padded.len(), padded_length(bytes.len()));
            prop_assert!(padded.len() > bytes.len());
            prop_assert!(padded.len().is_multiple_of(PAD_BLOCK));
            let stripped = strip_padding(&padded, bytes.len()).expect("apply output is valid");
            prop_assert_eq!(stripped, &bytes[..]);
        }

        /// Strip rejects every wrong `true_length` for a validly padded
        /// buffer — either the formula check or the zero check fires; a
        /// wrong length never silently succeeds unless the bytes are
        /// genuinely consistent with it (same bucket AND the tail beyond
        /// the wrong length is all zeros — an information-theoretic
        /// ambiguity no codec can distinguish, which is why `true_length`
        /// is manifest-authoritative and covered by the signed body).
        #[test]
        fn prop_wrong_true_length_rejects_or_is_consistent(
            bytes in proptest::collection::vec(any::<u8>(), 0..=(2 * PAD_BLOCK)),
            wrong in 0usize..=(3 * PAD_BLOCK),
        ) {
            let padded = apply_padding(&bytes);
            match strip_padding(&padded, wrong) {
                Ok(stripped) => {
                    // Only reachable when `wrong` lands in the same bucket
                    // and everything beyond it is zero — consistent by
                    // construction.
                    prop_assert_eq!(padded_length(wrong), padded.len());
                    prop_assert!(padded[wrong..].iter().all(|&b| b == 0));
                    prop_assert_eq!(stripped, &padded[..wrong]);
                }
                Err(CryptoError::PaddingLengthMismatch { expected, got }) => {
                    prop_assert_eq!(got, padded.len());
                    prop_assert_eq!(expected, padded_length(wrong));
                    prop_assert!(expected != got);
                }
                Err(CryptoError::NonZeroPadding { offset }) => {
                    prop_assert_eq!(padded_length(wrong), padded.len());
                    prop_assert!(offset >= wrong);
                    prop_assert!(padded[offset] != 0);
                }
                Err(other) => prop_assert!(false, "unexpected error {other:?}"),
            }
        }
    }
}
