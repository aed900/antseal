//! **A2** acceptance over real `.sealproof` bytes.
//!
//! The unit tests in `antseal_core::anchor::model` pin the model's own
//! invariants on hand-built values. This file pins the one Accept row that
//! cannot be checked that way:
//!
//! > F can encode/decode every artifact field the bundle must carry (status,
//! > `.ots`, height+header+fetch date, token+intermediates+fetch dates,
//! > optional receipt).
//!
//! So every assertion below travels through the real codec — encode, decode,
//! then read through the A2 views — and the file carries its own **red
//! direction**: an artifact whose fields are changed must be *seen* to change,
//! or a getter wired to a constant would satisfy every other test here.
//!
//! Native-only: it builds fixtures, which is heavy for the wasm32 `--lib`
//! lane, and the model's own target-independent invariants already run there.

#![cfg(not(target_arch = "wasm32"))]

use antseal_core::anchor::model::{AnchorArtifacts, AnchorKind, OtsArtifactView, TsaArtifactView};
use antseal_core::bundle::{
    AnchorStatus, BundleV1, OpaqueBytes, OtsAnchor, OtsUpgrade, TsaAnchor, encode_bundle,
};
use antseal_core::test_util::bundle_fixtures::{
    self, FIXTURE_BLOCK_HEADER, FIXTURE_BLOCK_HEIGHT, FIXTURE_BLOCK_NUMBER, FIXTURE_CLAIMED_TIME,
    shapes,
};

/// The `.sealproof` bytes of F13's every-anchor-kind shape: two OTS artifacts
/// (one with the D79 upgrade group, one without), two TSA artifacts (one with
/// intermediates, one without), and the opt-in receipt.
fn every_anchor_kind_bytes() -> Vec<u8> {
    let spec = shapes::multi_file_every_anchor_kind();
    let selection = shapes::multi_file_mixed_selection();
    bundle_fixtures::build(&spec, &selection).bytes
}

/// **A2 Accept row 4.** Every artifact field the bundle must carry survives
/// the codec and is readable through the A2 views.
///
/// The field list is the Accept row's own, item by item: the `.ots` bytes; the
/// height + header + fetch date of the D79 upgrade group, and its *absence* on
/// a not-yet-upgraded artifact; the DER token, its intermediates (present and
/// empty), and the TSA fetch date; and the optional receipt.
#[test]
fn every_artifact_field_survives_encode_decode_and_is_visible_to_the_model() {
    let bytes = every_anchor_kind_bytes();
    let bundle = BundleV1::decode(&bytes).expect("fixture bundle decodes");
    let artifacts = AnchorArtifacts::from_bundle(&bundle);

    assert_eq!(artifacts.count_for(AnchorKind::Ots), 2);
    assert_eq!(artifacts.count_for(AnchorKind::Tsa), 2);

    let ots: Vec<OtsArtifactView<'_>> = artifacts.ots().collect();

    // (a) `.ots` bytes + the upgrade group, all three fields.
    assert_eq!(ots[0].ots(), b"fixture .ots artifact, upgraded");
    let upgrade = ots[0]
        .upgrade()
        .expect("artifact 0 carries the upgrade group");
    assert_eq!(upgrade.block_height(), FIXTURE_BLOCK_HEIGHT);
    assert_eq!(upgrade.block_header(), &FIXTURE_BLOCK_HEADER);
    assert_eq!(upgrade.block_header().len(), 80, "registry §7.8 key 3");
    assert_eq!(upgrade.fetch_date(), FIXTURE_CLAIMED_TIME);

    // (b) …and its absence, in the same bundle (D79: all three or none).
    assert_eq!(ots[1].ots(), b"fixture .ots artifact, pending");
    assert_eq!(ots[1].upgrade(), None);

    let tsa: Vec<TsaArtifactView<'_>> = artifacts.tsa().collect();

    // (c) token + intermediates + fetch date.
    assert_eq!(tsa[0].token(), b"fixture TSA token A");
    assert_eq!(tsa[0].intermediate_count(), 2);
    assert_eq!(
        tsa[0].intermediates().collect::<Vec<_>>(),
        vec![
            b"fixture TSA intermediate A1".as_slice(),
            b"fixture TSA intermediate A2".as_slice(),
        ]
    );
    assert_eq!(tsa[0].fetch_date(), FIXTURE_CLAIMED_TIME);

    // (d) …and the empty-intermediates shape, in the same bundle.
    assert_eq!(tsa[1].token(), b"fixture TSA token B");
    assert_eq!(tsa[1].intermediate_count(), 0);
    assert_eq!(tsa[1].intermediates().count(), 0);
    assert_eq!(tsa[1].fetch_date(), FIXTURE_CLAIMED_TIME);

    // (e) the optional receipt.
    let receipt = artifacts.receipt().expect("this shape opts the receipt in");
    assert_eq!(receipt.transaction_hashes(), &[[0xE1; 32], [0xE2; 32]]);
    assert_eq!(receipt.block_number(), FIXTURE_BLOCK_NUMBER);
    assert_eq!(
        receipt.payload_len(),
        b"fixture Arbitrum receipt payload (opaque)".len() as u64
    );

    // (f) `status` — the one item in the Accept row's list the model
    // deliberately does **not** expose. F carries it and the verifier ignores
    // it (registry §7.8/§7.9 key 0: sealer-recorded, never trusted), so it is
    // asserted here on F's own type. All four recorded values survive, which
    // is what "F can encode/decode status" means; that the views cannot see
    // them is `the_sealer_recorded_status_is_not_visible_to_the_verifier`.
    assert_eq!(bundle.ots_anchors()[0].status(), AnchorStatus::Attested);
    assert_eq!(bundle.ots_anchors()[1].status(), AnchorStatus::Pending);
    assert_eq!(bundle.tsa_anchors()[0].status(), AnchorStatus::Proven);
    assert_eq!(
        bundle.tsa_anchors()[1].status(),
        AnchorStatus::ValidAtStampingCertSinceExpired
    );

    // Reading through the model loses nothing: the decoded bundle re-encodes
    // to the byte string it came from.
    assert_eq!(
        encode_bundle(&bundle).expect("re-encodes"),
        bytes,
        "a field the model can read must also survive the encoder"
    );
}

/// The **red direction** for the row above: change the artifact fields and the
/// model must report the changes.
///
/// Without this, every getter could return a constant and the acceptance test
/// would still be green — the "test that cannot fail" shape. The mutated
/// bundle is reassembled through `BundleV1::new`, so it is a genuinely valid
/// bundle, not a byte smear.
#[test]
fn changed_artifact_fields_are_seen_through_the_model() {
    let bytes = every_anchor_kind_bytes();
    let mut parts = BundleV1::decode(&bytes)
        .expect("fixture bundle decodes")
        .into_parts();

    parts.ots_anchors = vec![
        OtsAnchor::new(
            AnchorStatus::Attested,
            OpaqueBytes::from_vec(b"a different .ots".to_vec()),
            Some(OtsUpgrade::new(
                FIXTURE_BLOCK_HEIGHT + 7,
                [0x5A; 80],
                FIXTURE_CLAIMED_TIME + 11,
            )),
        )
        .expect("under the D10 caps"),
    ];
    parts.tsa_anchors = vec![
        TsaAnchor::new(
            AnchorStatus::Proven,
            OpaqueBytes::from_vec(b"a different token".to_vec()),
            vec![OpaqueBytes::from_vec(b"only one cert".to_vec())],
            FIXTURE_CLAIMED_TIME + 13,
        )
        .expect("under the D10 caps"),
    ];
    parts.receipt = None;

    let rebuilt = BundleV1::new(parts).expect("the recombination is a valid bundle");
    let mutated = encode_bundle(&rebuilt).expect("encodes");
    assert_ne!(mutated, bytes, "the mutation must change the bytes");

    let bundle = BundleV1::decode(&mutated).expect("mutated bundle decodes");
    let artifacts = AnchorArtifacts::from_bundle(&bundle);

    assert_eq!(artifacts.count_for(AnchorKind::Ots), 1);
    assert_eq!(artifacts.count_for(AnchorKind::Tsa), 1);

    let ots = artifacts.ots().next().expect("one OTS artifact");
    assert_eq!(ots.ots(), b"a different .ots");
    let upgrade = ots.upgrade().expect("upgrade group present");
    assert_eq!(upgrade.block_height(), FIXTURE_BLOCK_HEIGHT + 7);
    assert_eq!(upgrade.block_header(), &[0x5A; 80]);
    assert_eq!(upgrade.fetch_date(), FIXTURE_CLAIMED_TIME + 11);

    let tsa = artifacts.tsa().next().expect("one TSA artifact");
    assert_eq!(tsa.token(), b"a different token");
    assert_eq!(tsa.intermediate_count(), 1);
    assert_eq!(
        tsa.intermediates().collect::<Vec<_>>(),
        vec![b"only one cert".as_slice()]
    );
    assert_eq!(tsa.fetch_date(), FIXTURE_CLAIMED_TIME + 13);

    // Dropping the receipt is legal — presence *is* the opt-in (registry
    // §7.10) — and the model reports its absence rather than a default.
    assert!(artifacts.receipt().is_none());
}

/// D53 §4a over a real bundle: `absent` answers a question about a **kind**,
/// and only when the bundle carries no artifact of it.
///
/// The empty-anchor shape is the one bundle where both kinds are absent; the
/// every-kind shape is where neither is. Together they are the two directions
/// the empty-anchor golden vector alone cannot witness — that vector emits
/// **zero** anchor slots, so a clause resting on it would pass vacuously even
/// with the variant deleted.
#[test]
fn absent_answers_a_kind_query_and_only_for_a_kind_with_no_artifact() {
    let empty =
        bundle_fixtures::build(&shapes::multi_file(), &shapes::multi_file_mixed_selection()).bytes;
    let bundle = BundleV1::decode(&empty).expect("empty-anchor bundle decodes");
    let artifacts = AnchorArtifacts::from_bundle(&bundle);
    for kind in [AnchorKind::Ots, AnchorKind::Tsa] {
        assert_eq!(artifacts.count_for(kind), 0);
        let verdict = artifacts
            .absent_verdict(kind)
            .expect("no artifact of this kind");
        assert_eq!(verdict.state(), antseal_core::verify::AnchorState::Absent);
        assert_eq!(
            verdict.to_anchor_result(),
            None,
            "R12 emits no slot for an absent kind"
        );
    }

    let anchored = every_anchor_kind_bytes();
    let bundle = BundleV1::decode(&anchored).expect("anchored bundle decodes");
    let artifacts = AnchorArtifacts::from_bundle(&bundle);
    for kind in [AnchorKind::Ots, AnchorKind::Tsa] {
        assert!(artifacts.count_for(kind) > 0);
        assert_eq!(
            artifacts.absent_verdict(kind),
            None,
            "a kind with artifacts has no absent verdict"
        );
    }
}
