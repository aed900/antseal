//! The anchor-stage fuzz entry point (A5's Accept row; A23 owns the runs).
//!
//! # Why this lives in the crate and not in the fuzz target
//!
//! The same reason `codec_fuzz` does: a fuzz target is nightly-only, is not a
//! workspace member, and is built by nobody on a normal `cargo test`. A
//! driver written *inside* the target is therefore code no required lane ever
//! compiles, which is how a fuzz harness quietly stops matching the API it
//! drives. Written here it is compiled by every build of this crate, and
//! [`tests::the_driver_is_exercised_by_the_normal_suite`] runs it on real and
//! degenerate input, so the harness cannot rot between fuzz sessions.
//!
//! # The invariant, stated so it cannot be weakened into nothing
//!
//! For **every** input — well-formed, malformed, hostile, empty — the anchor
//! stage returns either a [`VerifiedToken`] or a typed [`AnchorError`] whose
//! code is under `anchor-`. It never panics, never aborts, and never
//! recurses without bound. "Never aborts" is the one that needs a fuzzer
//! rather than a unit test: a stack overflow is not a panic, is not catchable
//! by `catch_unwind`, and traps on `wasm32` — and D60 §2.4 measured a
//! recursive DER walker reaching it at depth 20 000 in 83 407 bytes.
//!
//! Depth here is bounded by `der`'s own guard rather than by antseal code
//! (D60 §6 b1), so what this target is really searching for is a *path that
//! escapes that guard* — a re-parse of an inner field starting a fresh depth
//! budget, of which this stage has several: `TSTInfo` out of `eContent`, a
//! certificate out of the bag, an ESS attribute value, an extension's
//! `extnValue`.

use super::error::AnchorError;
use super::tsa::{VerifiedToken, verify_token};

/// Drive the full anchor stage over arbitrary bytes.
///
/// `data` is split: the first 32 bytes (zero-padded) become the
/// `anchor_digest`, the rest is the artifact. Feeding a *fixed* digest would
/// make [`AnchorError::ImprintMismatch`] the terminal outcome for almost
/// every input and starve every check downstream of it — the imprint
/// comparison is step 7 of 9, so a fuzzer that always fails there explores
/// two thirds of the stage and none of the signature, EKU or chain-material
/// paths. Letting the input choose the digest lets it *find* the imprint.
///
/// The nonce is always `None`: that is the bundle path, the one a hostile
/// `.sealproof` actually reaches. The capture path is a `Some` supplied by
/// antseal's own code from the vault, never by an attacker.
///
/// # Errors
///
/// Whatever the anchor stage returns. The point of the driver is that this is
/// always an `AnchorError` and never a panic.
pub fn drive_anchor_token(data: &[u8]) -> Result<VerifiedToken, AnchorError> {
    let (digest, artifact) = split_digest(data);
    verify_token(artifact, &digest, None)
}

/// The same input, run on the capture path with an attacker-chosen expected
/// nonce.
///
/// Separate from [`drive_anchor_token`] because it exercises the one branch
/// the bundle path can never take, and because collapsing them would make
/// the `None` arm's inertness (D59) unfuzzed on half the corpus.
///
/// # Errors
///
/// As [`drive_anchor_token`], plus [`AnchorError::NonceMismatch`].
pub fn drive_anchor_token_with_nonce(data: &[u8]) -> Result<VerifiedToken, AnchorError> {
    let (digest, rest) = split_digest(data);
    // A nonce of at most 16 bytes, taken from the head of the artifact so a
    // mutation can steer both sides of the comparison toward each other.
    let split = rest.len().min(16);
    let (nonce, artifact) = rest.split_at(split);
    verify_token(artifact, &digest, Some(nonce))
}

/// First 32 bytes as the digest, zero-padded; remainder as the artifact.
fn split_digest(data: &[u8]) -> ([u8; 32], &[u8]) {
    let mut digest = [0u8; 32];
    let take = data.len().min(32);
    digest[..take].copy_from_slice(&data[..take]);
    (digest, &data[take..])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The harness is compiled and executed by the ordinary suite, so it
    /// cannot drift out of sync with the API it drives between fuzz
    /// sessions. Every outcome is either a success or an `anchor-` code —
    /// the invariant the fuzz target asserts, asserted here on inputs a
    /// fuzzer would take a long time to reach.
    #[test]
    fn the_driver_is_exercised_by_the_normal_suite() {
        let inputs: [&[u8]; 6] = [
            &[],
            &[0x30],
            &[0x30, 0x00],
            &[0xFF; 64],
            &[0x30, 0x80, 0x05, 0x00, 0x00, 0x00],
            &[0x02, 0x01, 0x01],
        ];
        for data in inputs {
            match drive_anchor_token(data) {
                Ok(_) => panic!("degenerate input must not verify"),
                Err(e) => assert!(e.code().starts_with("anchor-"), "{}", e.code()),
            }
            match drive_anchor_token_with_nonce(data) {
                Ok(_) => panic!("degenerate input must not verify"),
                Err(e) => assert!(e.code().starts_with("anchor-"), "{}", e.code()),
            }
        }
    }

    /// The digest split is the anti-starvation property, and it is worth an
    /// assertion because "feed the fuzzer a fixed digest" is the obvious
    /// implementation and it silently caps coverage at step 7 of 9.
    #[test]
    fn the_input_chooses_the_digest() {
        let mut a = vec![0u8; 40];
        let mut b = vec![0u8; 40];
        a[0] = 0x01;
        b[0] = 0x02;
        let (da, ra) = split_digest(&a);
        let (db, rb) = split_digest(&b);
        assert_ne!(da, db, "the digest must vary with the input");
        assert_eq!(ra.len(), 8);
        assert_eq!(rb.len(), 8);
        // Short inputs are zero-padded rather than rejected: a fuzzer's first
        // thousand inputs are short, and a driver that discards them is a
        // driver that does nothing for the first thousand inputs.
        let (short, rest) = split_digest(&[0xAA]);
        assert_eq!(short[0], 0xAA);
        assert_eq!(short[1], 0x00);
        assert!(rest.is_empty());
    }
}
