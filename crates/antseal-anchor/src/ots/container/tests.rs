//! Container writer tests.
//!
//! The load-bearing one is
//! [`the_assembled_container_is_byte_identical_to_the_committed_merge`]: this
//! writer and `testdata/anchors/A25-bootstrap/merged-A.ots` were produced by
//! two different pieces of code from the same three real calendar responses,
//! so agreement is a cross-check and not a round-trip.

use antseal_core::anchor::ots::{OtsAttestation, parse_ots};
use antseal_core::codec::caps::MAX_OTS_BYTES;

use super::*;
use crate::testing::replay::fixtures;

fn branches_a() -> Vec<Vec<u8>> {
    vec![
        fixtures::CALENDAR_ALICE_A.to_vec(),
        fixtures::CALENDAR_BOB_A.to_vec(),
        fixtures::CALENDAR_CATALLAXY_A.to_vec(),
    ]
}

/// D58 §7.3's recipe, executed by this crate, against the file A11 committed.
///
/// 664 = 65 header + 207 + 170 + 220 responses + 2 separators.
#[test]
fn the_assembled_container_is_byte_identical_to_the_committed_merge() {
    let merged = assemble(&fixtures::DIGEST_A, &branches_a());
    assert_eq!(merged.len(), 664);
    assert_eq!(
        merged,
        fixtures::MERGED_A,
        "the writer must reproduce the committed merge byte for byte"
    );

    // And the same for digest B, whose arithmetic differs (629 B).
    let merged_b = assemble(
        &fixtures::DIGEST_B,
        &[
            fixtures::CALENDAR_ALICE_B.to_vec(),
            fixtures::CALENDAR_BOB_B.to_vec(),
            fixtures::CALENDAR_CATALLAXY_B.to_vec(),
        ],
    );
    assert_eq!(merged_b.len(), 629);
    assert_eq!(merged_b, fixtures::MERGED_B);
}

/// The instrument check: the equality above must be capable of failing.
///
/// A writer that emitted a separator before *every* branch, or none at all,
/// would be caught — so the assertion is not passing because both sides are
/// computed the same way.
#[test]
fn a_wrong_separator_count_does_not_reproduce_the_committed_merge() {
    let branches = branches_a();
    let digest = fixtures::DIGEST_A;

    // A `0xff` before every branch, including the last — the off-by-one that
    // the "N children cost N-1 markers" rule exists to prevent.
    let mut every: Vec<u8> = container_header(&digest).to_vec();
    for branch in &branches {
        every.push(TAG_FORK);
        every.extend_from_slice(branch);
    }
    assert_ne!(every, fixtures::MERGED_A);
    assert_eq!(every.len(), 665);
    // …and it is not merely different, it fails to parse: the trailing marker
    // leaves the last child's tag unread.
    assert!(parse_ots(&every, &digest).is_err());

    // No separators at all: three branches read as one long chain.
    let mut none: Vec<u8> = container_header(&digest).to_vec();
    for branch in &branches {
        none.extend_from_slice(branch);
    }
    assert_ne!(none, fixtures::MERGED_A);
    assert!(parse_ots(&none, &digest).is_err());
}

/// A single-calendar container needs no separator at all, and is what A13
/// validates each response through for per-calendar attribution.
#[test]
fn one_branch_needs_no_separator_and_parses() {
    let single = assemble(&fixtures::DIGEST_A, &[fixtures::CALENDAR_ALICE_A.to_vec()]);
    assert_eq!(
        single.len(),
        OTS_HEADER_LEN + fixtures::CALENDAR_ALICE_A.len()
    );
    let artifact = parse_ots(&single, &fixtures::DIGEST_A).expect("a one-branch container parses");
    assert_eq!(artifact.attestations.len(), 1);
}

/// The header is the parser's steps 1–4, and the fixture is where that is
/// checked — not against a transcription of the same constants.
#[test]
fn the_header_is_the_first_sixty_five_bytes_of_a_real_artifact() {
    assert_eq!(
        container_header(&fixtures::DIGEST_A).as_slice(),
        &fixtures::MERGED_A[..OTS_HEADER_LEN]
    );
    // Wrong digest in, different header out — so the digest really is carried.
    assert_ne!(
        container_header(&fixtures::DIGEST_B).as_slice(),
        &fixtures::MERGED_A[..OTS_HEADER_LEN]
    );
}

/// The needle is constructed, so it has to be checked against bytes a real
/// calendar emitted rather than against itself.
#[test]
fn the_pending_needle_is_present_in_the_real_captures() {
    for (capture, uri) in [
        (
            fixtures::CALENDAR_ALICE_A,
            "https://alice.btc.calendar.opentimestamps.org",
        ),
        (
            fixtures::CALENDAR_BOB_A,
            "https://bob.btc.calendar.opentimestamps.org",
        ),
        (
            fixtures::CALENDAR_CATALLAXY_A,
            "https://btc.calendar.catallaxy.com",
        ),
    ] {
        let needle = pending_attestation_bytes(uri);
        assert!(
            capture.ends_with(&needle),
            "a calendar's submit response ends with its own pending attestation"
        );
        // D58 §7.1's dump: 0x00, 8 tag bytes, then two varuints.
        assert_eq!(needle[0], TAG_ATTESTATION);
        assert_eq!(
            &needle[1..9],
            &[0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e]
        );
    }

    // The 45-character alice URI: payload = varuint(45) + 45 = 46 bytes, and
    // the whole attestation is 1 + 8 + 1 + 46 = 56. The dump's own numbers.
    let alice = pending_attestation_bytes("https://alice.btc.calendar.opentimestamps.org");
    assert_eq!(alice.len(), 56);
    assert_eq!(alice[9], 46);
    assert_eq!(alice[10], 45);
}

/// The count agreement that makes index-matching sound, in both directions.
#[test]
fn locating_requires_the_byte_search_and_the_parser_to_agree() {
    let merged = fixtures::MERGED_A;
    let uri = "https://bob.btc.calendar.opentimestamps.org";

    let offset = locate_pending(merged, uri, 0, 1).expect("one occurrence, one attestation");
    assert_eq!(
        &merged[offset..offset + 9],
        &pending_attestation_bytes(uri)[..9]
    );

    // The parser says two, the bytes say one → refuse rather than guess.
    assert_eq!(
        locate_pending(merged, uri, 0, 2),
        Err(ContainerError::Unlocatable {
            found: 1,
            expected: 2
        })
    );
    // Index past the end.
    assert_eq!(
        locate_pending(merged, uri, 1, 1),
        Err(ContainerError::NoSuchOccurrence { index: 1, found: 1 })
    );
    // A URI that is not in the file.
    assert_eq!(
        locate_pending(merged, "https://absent.example", 0, 0),
        Err(ContainerError::NoSuchOccurrence { index: 0, found: 0 })
    );
}

/// Two branches naming the **same** calendar — the shape that breaks a naive
/// needle search, since one URI then produces two identical needles.
///
/// D54's pool aliases make this reachable: two configured endpoints can front
/// one calendar. The k-th occurrence must map to the k-th attestation in the
/// parser's document order, and document order is byte order.
#[test]
fn duplicate_calendar_branches_are_told_apart_by_position() {
    // Alice's response twice, plus bob's — a legitimate file, two distinct
    // commitments under one URI.
    let doubled = assemble(
        &fixtures::DIGEST_A,
        &[
            fixtures::CALENDAR_ALICE_A.to_vec(),
            fixtures::CALENDAR_BOB_A.to_vec(),
            fixtures::CALENDAR_ALICE_A.to_vec(),
        ],
    );
    let artifact = parse_ots(&doubled, &fixtures::DIGEST_A).expect("parses");
    let alice_uri = "https://alice.btc.calendar.opentimestamps.org";
    let alice_count = artifact
        .attestations
        .iter()
        .filter(|a| matches!(a, OtsAttestation::Pending { uri, .. } if uri == alice_uri))
        .count();
    assert_eq!(alice_count, 2);

    let first = locate_pending(&doubled, alice_uri, 0, 2).expect("first alice");
    let second = locate_pending(&doubled, alice_uri, 1, 2).expect("second alice");
    assert!(first < second, "occurrences are returned in byte order");
    // A single-occurrence expectation now fails, which is the guard working.
    assert!(locate_pending(&doubled, alice_uri, 0, 1).is_err());
}

/// The splice is a pure insertion: every original byte survives, in order.
#[test]
fn splicing_inserts_and_never_rewrites() {
    let merged = fixtures::MERGED_A.to_vec();
    let uri = "https://bob.btc.calendar.opentimestamps.org";
    let offset = locate_pending(&merged, uri, 0, 1).expect("locate");
    let sibling = [0x08_u8; 4];

    let out = splice_sibling_before(&merged, offset, &sibling, MAX_OTS_BYTES).expect("splice");
    assert_eq!(out.len(), merged.len() + 1 + sibling.len());
    assert_eq!(&out[..offset], &merged[..offset]);
    assert_eq!(out[offset], TAG_FORK);
    assert_eq!(&out[offset + 1..offset + 1 + sibling.len()], &sibling);
    assert_eq!(&out[offset + 1 + sibling.len()..], &merged[offset..]);

    // Removing the inserted bytes recovers the original exactly.
    let mut recovered = out[..offset].to_vec();
    recovered.extend_from_slice(&out[offset + 1 + sibling.len()..]);
    assert_eq!(recovered, merged);
}

/// A28's Accept row: the ceiling fires at merge, not at bundle build.
#[test]
fn a_splice_over_the_embeddable_ceiling_is_refused_before_it_is_built() {
    let merged = fixtures::MERGED_A.to_vec();
    let uri = "https://bob.btc.calendar.opentimestamps.org";
    let offset = locate_pending(&merged, uri, 0, 1).expect("locate");

    // 664 + 1 separator + 16 = 681, so 680 is the ceiling that must refuse it
    // and 681 is the one that must not. Both directions, because a check
    // written `>=` instead of `>` passes the first assertion alone.
    let error = splice_sibling_before(&merged, offset, &[0x08; 16], 680)
        .expect_err("681 bytes over a 680-byte ceiling must be refused");
    assert_eq!(
        error,
        ContainerError::TooLarge {
            len: 681,
            limit: 680
        }
    );
    assert!(
        splice_sibling_before(&merged, offset, &[0x08; 16], 681).is_ok(),
        "a result of exactly the ceiling is admitted"
    );
    // The real ceiling admits it with room: 681 against 1 MiB.
    assert!(splice_sibling_before(&merged, offset, &[0x08; 16], MAX_OTS_BYTES).is_ok());
}
