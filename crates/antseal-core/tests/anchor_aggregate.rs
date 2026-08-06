//! A1 — library verification of F13's committed empty-anchor golden
//! vector yields all-`absent` anchors plus the zero-headline-eligible
//! aggregate flag (the UNANCHORED path the M1 E2E consumes,
//! MVP-SPEC.md lines 137/153/154).
//!
//! Reads the **committed** vector bytes (`testdata/vectors/v1/bundle/
//! bundle.json`, frozen at Q14) rather than rebuilding fixtures: what is
//! asserted here is exactly what a verifier sees given the golden
//! `.sealproof` bytes. Test names carry the reserved `vector_` marker so
//! the cross-OS lanes run them everywhere (CONTRIBUTING.md).

#![cfg(not(target_arch = "wasm32"))] // reads the vector file from disk

use std::fs;

use antseal_core::verify::{VerifyOptions, aggregate_anchors, verify_bundle};
use serde_json::Value;

const VECTOR_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../testdata/vectors/v1/bundle/bundle.json"
);

/// Test-local strict hex decoder (the shared one is `pub(super)` to the
/// vector executors).
fn decode_hex(hex: &str) -> Vec<u8> {
    assert!(hex.len().is_multiple_of(2), "odd-length hex in vector");
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("vector bundle_bytes is hex"))
        .collect()
}

/// The committed `bundle_bytes` of one named case in the F13 document.
fn committed_bundle_bytes(case_name: &str) -> Vec<u8> {
    let raw = fs::read_to_string(VECTOR_PATH).expect("committed bundle vector document exists");
    let document: Value = serde_json::from_str(&raw).expect("vector document is JSON");
    let case = document["expect"]["cases"]
        .as_array()
        .expect("expect.cases is an array")
        .iter()
        .find(|case| case["name"] == case_name)
        .unwrap_or_else(|| panic!("case `{case_name}` present in the committed document"));
    decode_hex(
        case["bundle_bytes"]
            .as_str()
            .expect("bundle_bytes is a hex string"),
    )
}

/// The M0 milestone artifact (`empty-anchor-unanchored`): both anchor
/// sections empty ⇒ an empty per-anchor slot list ⇒ zero
/// headline-eligible anchors ⇒ UNANCHORED, with no headline time
/// producible.
#[test]
fn vector_empty_anchor_bundle_verifies_unanchored() {
    let bytes = committed_bundle_bytes("empty-anchor-unanchored");
    let report = verify_bundle(&bytes, &VerifyOptions::new())
        .expect("the empty-anchor golden vector passes the evidence layer");

    assert!(
        report.anchors.is_empty(),
        "empty anchor sections yield an empty slot list"
    );

    let aggregate = aggregate_anchors(&report.anchors);
    assert!(
        aggregate.is_unanchored(),
        "the zero-headline-eligible flag (A1 accept)"
    );
    assert_eq!(aggregate.headline_eligible_count(), 0);
    assert_eq!(aggregate.total_anchors(), 0);
    assert_eq!(
        aggregate.headline_time_unix(),
        None,
        "no code path produces a headline time from an empty anchor set"
    );
}

/// The populated-anchor golden vector, **through R12's wired stage**: four
/// artifacts are embedded (2 OTS + 2 TSA), each a schema-opaque placeholder
/// the anchor stage cannot parse, so each renders `invalid` in its own slot
/// (D84 F3) and the aggregate is still UNANCHORED with no headline time.
///
/// # What moved at R12, and why this row is stronger for it
///
/// Until R12 this asserted `absent` on all four and was a statement about a
/// *stub*. It is now a statement about the machine, and a differential one:
/// the bundle records four **different** sealer-claimed statuses —
/// `attested`, `pending`, `proven` and `valid-at-stamping-cert-since-expired`
/// (`test_util::bundle_fixtures`, the `EveryKind` set) — and the report
/// renders one answer for all four. A stage that believed the bundle's own
/// `status` field would produce four different states here and would be
/// caught by this row alone.
///
/// It is also the instrument D94 §4 did not count. That record concluded that
/// nothing in the tree observed *verdicts* rather than the accept/reject bit,
/// and named A21 rows 1–2 as the first that would; this row observes report
/// states, and it went red at R12 exactly as an M0-inertness claim should.
/// See D94's dated corrections and R71.
#[test]
fn vector_every_anchor_kind_bundle_is_all_invalid_and_unanchored_at_m2() {
    use antseal_core::verify::AnchorState;

    let bytes = committed_bundle_bytes("every-anchor-kind-no-receipt");
    let report = verify_bundle(&bytes, &VerifyOptions::new())
        .expect("the every-anchor-kind golden vector passes the evidence layer");

    assert_eq!(report.anchors.len(), 4, "2 OTS + 2 TSA artifact slots");
    assert!(
        report
            .anchors
            .iter()
            .all(|slot| slot.state == AnchorState::Invalid),
        "an artifact the stage will not finish reading renders `invalid` (D84 F3); got {:?}",
        report
            .anchors
            .iter()
            .map(|slot| slot.state)
            .collect::<Vec<_>>()
    );

    // D84 F2 at the bundle surface: four refuted anchors, and the bundle
    // still verified — the `expect` above is the assertion.
    let aggregate = aggregate_anchors(&report.anchors);
    assert!(aggregate.is_unanchored());
    assert_eq!(aggregate.total_anchors(), 4);
    assert_eq!(
        aggregate.headline_time_unix(),
        None,
        "a refuted anchor contributed a headline time"
    );
}
