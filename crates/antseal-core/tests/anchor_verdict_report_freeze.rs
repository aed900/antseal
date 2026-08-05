//! **A39 Accept row 4, and D53 §6's measurement made mechanical.**
//!
//! D53 and D56 both claim *"zero frozen report bytes change"*, and both back
//! the claim with one measurement taken by hand on 2026-08-02:
//! `testdata/vectors/v1/report/verification-reports.json` holds **21** cases
//! at `report_version: 1`; exactly **one** carries a non-empty `anchors`
//! array; that array holds **three** slots, every one of them
//! `{"state":"absent", …}`; and the other six state strings occur **zero**
//! times in the whole file.
//!
//! A hand measurement in a decision document is not an instrument. This is
//! the instrument. It goes red if A18/R12 ever start emitting a non-`absent`
//! slot into a pinned vector, if the diagnostic code or the A39 anomaly list
//! reaches `AnchorResult`, or if the fixed-slot-pair alternative D53 §4a
//! rejects is reached for — each of which is a `REPORT_VERSION` event and a
//! coupled edit across `report.rs`, the vectors and `FROZEN.sha256`, never a
//! lane decision.
//!
//! It is **not** a duplicate of `vector_freeze.rs`, which pins the file's
//! SHA-256 and would go red on any edit whatever. This one names *what* is in
//! the file, so the failure message says which invariant broke rather than
//! "a digest moved" — and it survives a legitimate addition of a
//! non-anchor-bearing case, which the digest cannot.
//!
//! # `report_json` is hex, not JSON
//!
//! Written down because the first draft of this file assumed otherwise and
//! its own anti-vacuity guard caught it: `report_json` holds the **canonical
//! JSON bytes in lowercase hex**, and `report` beside it is the decoded
//! structure. The byte-level scan below therefore decodes the hex — scanning
//! the file's raw text for `"state":"proven"` would match nothing however the
//! vectors changed, which is a check that cannot fail.
//!
//! Native-only: it reads a committed file, and `wasm32-unknown-unknown` has
//! no filesystem (P14).
#![cfg(not(target_arch = "wasm32"))]

use std::fs;

const VECTORS: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../testdata/vectors/v1/report/verification-reports.json"
);

/// The six state strings that must not appear anywhere in the pinned bytes.
/// `absent` is deliberately not in this list: it is the one that *does*
/// appear, and the anti-vacuity assertion below uses it.
const NON_ABSENT_STATES: [&str; 6] = [
    "proven",
    "valid-at-stamping-cert-since-expired",
    "attested",
    "pending",
    "internally-consistent-only",
    "invalid",
];

fn cases() -> Vec<serde_json::Value> {
    let raw = fs::read_to_string(VECTORS).expect("the committed report vectors are readable");
    let doc: serde_json::Value =
        serde_json::from_str(&raw).expect("the committed report vectors are JSON");
    doc["expect"]["cases"]
        .as_array()
        .expect("expect.cases is an array")
        .clone()
}

/// The canonical report bytes a case pins, as a string.
fn pinned_report_bytes(case: &serde_json::Value) -> String {
    let hex = case["report_json"]
        .as_str()
        .expect("report_json is a hex string");
    assert!(hex.len().is_multiple_of(2), "hex has an odd length");
    let bytes: Vec<u8> = hex
        .as_bytes()
        .chunks(2)
        .map(|pair| {
            u8::from_str_radix(std::str::from_utf8(pair).expect("ascii hex"), 16)
                .expect("lowercase hex digits")
        })
        .collect();
    String::from_utf8(bytes).expect("the canonical report is UTF-8 JSON")
}

/// D53 §6 / D56 §6, measured rather than asserted — the same four numbers the
/// two decisions took by hand.
#[test]
fn the_pinned_report_vectors_still_carry_only_absent_anchor_slots() {
    let cases = cases();
    assert_eq!(
        cases.len(),
        21,
        "the pinned case count moved; D53 §6 and D56 §6 both cite 21"
    );

    let mut with_anchors = 0_usize;
    let mut slots = 0_usize;
    for case in &cases {
        let report = &case["report"];
        assert_eq!(
            report["report_version"], 1,
            "a pinned case left report_version 1"
        );
        let anchors = report["anchors"]
            .as_array()
            .expect("every report carries an anchors array");
        if anchors.is_empty() {
            continue;
        }
        with_anchors += 1;
        for anchor in anchors {
            slots += 1;
            assert_eq!(
                anchor["state"], "absent",
                "a pinned vector gained a non-absent anchor slot — that is a REPORT_VERSION \
                 event, not a lane change"
            );
            assert_eq!(anchor["verified_time_unix"], serde_json::Value::Null);
            assert_eq!(anchor["source"], serde_json::Value::Null);
            assert_eq!(anchor["fetch_date"], serde_json::Value::Null);
            // Exactly the five frozen fields, no sixth. The obvious way to
            // satisfy A9's "with a distinct error detail" is to add one for
            // the diagnostic; D53 §6 forbids it, and A39's anomaly list is
            // under the same rule.
            let fields = anchor
                .as_object()
                .expect("an anchor slot is an object")
                .len();
            assert_eq!(fields, 5, "AnchorResult grew a field: {anchor}");
        }
    }

    assert_eq!(
        with_anchors, 1,
        "exactly one of the 21 cases carries a non-empty anchors array"
    );
    assert_eq!(slots, 3, "that case carries three anchor slots");
}

/// The other half of D53 §6's measurement, over the **pinned bytes**: none of
/// the six non-`absent` state spellings occurs in any canonical report, and
/// neither does any anchor diagnostic code or A39 anomaly key.
///
/// A byte scan on purpose. The structural walk above only inspects `state`
/// fields it knows to look at, so a state string appearing in a *new* place —
/// a nested envelope, an added key, a diagnostic that leaked — would slip
/// past it. This cannot: it is every byte the format commits to.
#[test]
fn no_non_absent_state_or_diagnostic_appears_in_the_pinned_bytes() {
    let mut saw_absent = false;
    let mut saw_empty_array = false;
    for case in &cases() {
        let json = pinned_report_bytes(case);
        for state in NON_ABSENT_STATES {
            let needle = format!("\"state\":\"{state}\"");
            assert!(
                !json.contains(&needle),
                "the state string `{state}` entered the pinned report bytes"
            );
        }
        saw_absent |= json.contains("\"state\":\"absent\"");
        saw_empty_array |= json.contains("\"anchors\":[]");
        // D53 §6 / D56 §6: the diagnostic code and the A39 anomaly list never
        // enter `VerificationReport`. Neither the family prefix nor the field
        // name may appear.
        assert!(
            !json.contains("anchor-"),
            "an anchor diagnostic code reached a pinned report"
        );
        assert!(
            !json.contains("suppressed"),
            "the A39 anomaly list reached a pinned report"
        );
    }
    // Anti-vacuity, both directions: the needle shape must match the file's
    // own encoding, and the pinned `"anchors":[]` string D53 §4a names must
    // really be in there — otherwise every assertion above is a comparison
    // against a pattern that could never occur however the vectors changed.
    assert!(
        saw_absent,
        "no `\"state\":\"absent\"` in any pinned report — the needle shape is wrong and the \
         six assertions above are vacuous"
    );
    assert!(
        saw_empty_array,
        "the pinned `\"anchors\":[]` byte string is gone"
    );
}
