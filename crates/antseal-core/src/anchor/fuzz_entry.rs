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
//!
//! # Two drivers, and they are not symmetric
//!
//! [`drive_anchor_token`] (+ [`drive_anchor_token_with_nonce`]) drive the
//! RFC 3161 stage; [`drive_ots`] drives the `.ots` codec (task **A23**).
//! They take their digest from **different places**, deliberately, and each
//! function's docs give the reason. Do not "unify" them: the shared shape
//! would silently cost one of the two targets the coverage it exists for,
//! and no crash and no green run would ever say so.

use super::error::AnchorError;
use super::ots::{OTS_MAGIC, OTS_VERSION, OtsArtifact, OtsError, parse_ots};
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

/// Drive the `.ots` codec over arbitrary bytes (task **A23**).
///
/// # Why this does NOT use [`split_digest`]
///
/// The RFC 3161 driver above takes the digest off the head of the input,
/// which is right there because a TSA token carries its imprint in a
/// signed structure the input cannot cheaply satisfy. `.ots` is the
/// opposite shape: the artifact *carries the start digest itself*, at a
/// fixed offset, and [`parse_ots`] compares the two at **step 5 of 7** —
/// before the walk. A head-split driver would therefore fail every
/// well-formed input at `DigestMismatch` and never execute a single op,
/// which is the entire reason this target exists: all four D58 crashers
/// (§3.1's 80-byte `SIGABRT`, §3.2's 102-byte one, §3.3's 87-byte
/// profile-dependent verdict) live in the walk, past step 5. A head-split
/// would also make every raw `.ots` file useless as a seed.
///
/// So the digest is read from the artifact's **own** start-digest field:
/// 31 bytes of magic, one varuint version, one digest-type byte, then the
/// 32-byte digest. Consequences, all deliberate:
///
/// - a real `.ots` file is a valid input **byte for byte**, so
///   `testdata/anchors/A25-bootstrap/`'s captured artifacts seed this
///   target with no derived corpus and no second copy of the bytes;
/// - a mutation inside the digest field moves *both* sides of the
///   comparison, so the fuzzer cannot starve itself at step 5 the way a
///   fixed digest would;
/// - `DigestMismatch` stays reachable — any mutation that changes the
///   *length* of the version varuint shifts the field out from under this
///   offset — so step 5 is still fuzzed rather than switched off.
///
/// The offset is a **coverage heuristic, not a claim about the format**.
/// If it is ever wrong the only cost is that inputs fail earlier; the
/// asserted invariant (no panic, no abort, typed `anchor-ots-` code,
/// bounded allocation) does not depend on it.
///
/// # Errors
///
/// Whatever the codec returns. The point of the driver is that this is
/// always an [`OtsError`] and never a panic, an abort, or an unbounded
/// allocation — the crate this codec replaced failed all three
/// (D58 §3).
pub fn drive_ots(data: &[u8]) -> Result<OtsArtifact, OtsError> {
    parse_ots(data, &embedded_start_digest(data))
}

/// The 32 bytes at `.ots`'s start-digest offset, zero-padded when the input
/// is shorter than that.
///
/// Zero-padded rather than rejected for [`split_digest`]'s reason: a
/// fuzzer's first thousand inputs are short, and a driver that discards
/// them does nothing for the first thousand inputs. A short input is
/// exactly the interesting case here — every one of D58's four crashers is
/// under 103 bytes.
fn embedded_start_digest(data: &[u8]) -> [u8; 32] {
    // magic ‖ varuint(version) ‖ digest-type ‖ digest. The two `+ 1`s are
    // the version varuint and the digest-type byte. The version's width is
    // an assumption, so it is a COMPILE-TIME one: a bump past 0x7F makes it
    // a two-byte varuint and moves this offset, and the build stops here
    // rather than the target quietly losing its coverage.
    const _: () = assert!(
        OTS_VERSION < 0x80,
        "a multi-byte version varuint moves the start-digest offset"
    );
    let offset = OTS_MAGIC.len() + 1 + 1;

    let mut digest = [0u8; 32];
    if let Some(field) = data.get(offset..offset + 32) {
        digest.copy_from_slice(field);
    }
    digest
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

    /// The `.ots` driver, held to the same contract on the same shape of
    /// input: every outcome is a success or an `anchor-ots-` code, and
    /// nothing panics or aborts. A23's whole memory-safety argument is that
    /// the crate this codec replaced did all three on inputs under 103
    /// bytes (D58 §3), so short and degenerate inputs are the cases that
    /// matter most here.
    #[test]
    fn the_ots_driver_is_exercised_by_the_normal_suite() {
        let mut truncated_magic = OTS_MAGIC.to_vec();
        truncated_magic.pop();
        let inputs: [&[u8]; 7] = [
            &[],
            &[0x00],
            &[0xFF; 33],
            &[0xFF; 200],
            &OTS_MAGIC,
            &truncated_magic,
            // A varuint with every continuation bit set — the shape D58
            // §3.2 rode into an uncapped running value.
            &[0xFF; 64],
        ];
        for data in inputs {
            match drive_ots(data) {
                Ok(_) => panic!("degenerate input must not parse"),
                Err(e) => assert!(e.code().starts_with("anchor-ots-"), "{}", e.code()),
            }
        }
    }

    /// The offset heuristic is load-bearing for coverage, so it is asserted
    /// rather than trusted: on a header whose fields are well-formed, the
    /// driver must get **past** step 5. If the offset were wrong, every
    /// input would terminate at `anchor-ots-digest-mismatch` and this
    /// target would fuzz four header checks and nothing else — a silent
    /// coverage collapse that no crash and no green run would reveal.
    #[test]
    fn the_ots_driver_reaches_the_walk_rather_than_stalling_at_the_digest() {
        use crate::anchor::ots::OTS_DIGEST_TYPE_SHA256;

        let mut header = OTS_MAGIC.to_vec();
        header.push(u8::try_from(OTS_VERSION).expect("version 1 is one byte"));
        header.push(OTS_DIGEST_TYPE_SHA256);
        header.extend_from_slice(&[0xAB; 32]);
        assert_eq!(header.len(), OTS_MAGIC.len() + 2 + 32);

        let err = drive_ots(&header).expect_err("a header with no DAG is incomplete");
        assert_ne!(
            err.code(),
            "anchor-ots-digest-mismatch",
            "the driver stalled at step 5 — `embedded_start_digest`'s offset no longer points \
             at the start-digest field, so the walk (and every D58 crasher in it) is unreachable"
        );
        assert_eq!(err.code(), "anchor-ots-truncated");

        // And the negative direction: shift the field by one byte and step 5
        // must fire, so the check is still live rather than switched off.
        let mut shifted = header.clone();
        shifted.insert(OTS_MAGIC.len(), 0x81);
        assert_eq!(
            drive_ots(&shifted)
                .expect_err("a shifted header does not parse")
                .code(),
            "anchor-ots-unsupported-version",
            "a mutation in the version varuint must still be rejected"
        );
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
