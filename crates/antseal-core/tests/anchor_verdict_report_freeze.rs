//! **A39 Accept row 4, and D53 §6's measurement made mechanical.**
//!
//! D53 and D56 both claim *"zero frozen report bytes change"*, and both back
//! the claim with one measurement taken by hand on 2026-08-02:
//! `testdata/vectors/v1/report/verification-reports.json` holds **21** cases
//! at `report_version: 1`; exactly **one** carries a non-empty `anchors`
//! array; and that array holds **three** slots of exactly five fields each.
//!
//! A hand measurement in a decision document is not an instrument. This is
//! the instrument.
//!
//! # What R12 moved, and the message this file used to print
//!
//! The 2026-08-02 measurement also recorded every slot as
//! `{"state":"absent", …}` with the other six spellings occurring zero times,
//! and this file asserted that. R12 wired A18's machine into `verify_bundle`
//! and the three placeholder artifacts now render `invalid` — so the two
//! assertions moved, and both messages named the wrong cause when they fired:
//! one called a changed *state* a `REPORT_VERSION` event (**D94** Ruling 1
//! overruled exactly that — it is a **verdict event** and the version stays
//! 1), and the other told the reader its own needle shape was wrong when in
//! fact `absent` had legitimately left the file for good (D53 §4a makes it a
//! kind-level answer that emits no slot). Both are corrected; see **R75**.
//!
//! What the file measures is unchanged and is the part D53 §6 actually
//! froze: the **shape**. It goes red if a slot gains a sixth field, if the
//! diagnostic code or the A39 anomaly list reaches `AnchorResult`, if the
//! fixed-slot-pair alternative D53 §4a rejects is reached for, or if a state
//! requiring a successfully-read artifact appears while no committed fixture
//! has one. The first three are `REPORT_VERSION` events and coupled edits
//! across `report.rs`, the vectors and `FROZEN.sha256`; a changed *value* in
//! an existing field is not.
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

/// The state spellings that no committed report may contain.
///
/// `invalid` left this list at R12 and `absent` never joined it. Both moves
/// are the taxonomy working: D84 rule F3 puts an unreadable artifact at
/// `invalid`, and every artifact in every committed vector is a schema-opaque
/// placeholder — while D53 §4a makes `absent` a *kind-level* answer that emits
/// no slot, so no report can carry it from M2 onward. What is left is the five
/// states that require an artifact the verifier actually read, and no
/// committed fixture has one until A22 lands real material.
const STATES_NO_PINNED_REPORT_MAY_CARRY: [&str; 5] = [
    "proven",
    "valid-at-stamping-cert-since-expired",
    "attested",
    "pending",
    "internally-consistent-only",
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
///
/// # What R12 moved here, and what it deliberately did not
///
/// Until R12 this asserted `absent` on all three of case 19's slots. That was
/// a fact about the **M0 stub**, and it was never D53 §6's invariant. D53 §6's
/// invariant is the *shape*: exactly one of 21 cases carries anchors, it
/// carries three slots, each slot has **exactly five fields**, and neither the
/// A9 diagnostic code nor A39's anomaly list ever reaches the report. R12
/// touches none of that, and this row still measures all of it.
///
/// The three slots now read `invalid`, because each artifact is a
/// schema-opaque placeholder the anchor stage will not finish reading (D84
/// rule F3) — and the bundle still verifies, which is F2. The two TSA slots
/// additionally render the sealer's recorded fetch date, which **D95** rules
/// is not a function of the verdict; the `.ots` slot renders none because the
/// fixture carries no D79 upgrade group to hold one, which is availability
/// rather than policy.
#[test]
fn the_pinned_report_vectors_carry_one_populated_anchor_array_of_invalid_slots() {
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
                anchor["state"], "invalid",
                "a pinned anchor slot left `invalid`. That is a VERDICT EVENT, not a \
                 REPORT_VERSION event (D94 §2a — this message said the opposite until \
                 2026-08-06): report v1 already carries all seven states, so re-emit \
                 under D94 §4 and bump nothing. Only a changed FIELD SET is a version \
                 event, and the `fields == 5` assertion below is what catches that"
            );
            assert_eq!(anchor["verified_time_unix"], serde_json::Value::Null);
            // No source on any of the three: nothing parsed far enough to
            // claim one, on either the OTS O1 arm or the TSA T1/T2 arm. The
            // `source` question D53 §4 rules — a *claimed* identity renders
            // on `invalid` — is therefore not exercised by any committed
            // vector, and A22's `anchor` kind is where it will be.
            assert_eq!(anchor["source"], serde_json::Value::Null);
            // **D95**: sealer-recorded, rendered on every state that emits a
            // slot, as decimal POSIX seconds. `null` here only where the wire
            // carries none — the OTS upgrade group is optional (registry §7.8
            // key 4) while the TSA field is `req` (§7.9 key 3).
            let expected_fetch_date = match anchor["kind"].as_str() {
                Some("ots") => serde_json::Value::Null,
                _ => serde_json::Value::String("1767225600".into()),
            };
            assert_eq!(
                anchor["fetch_date"], expected_fetch_date,
                "a pinned anchor slot's sealer-recorded fetch date moved. It is not a \
                 function of the verdict (D95); if it vanished, something started \
                 gating it on the state"
            );
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
/// the five states that require a successfully-read artifact occurs in any
/// canonical report, and neither does any anchor diagnostic code or A39
/// anomaly key.
///
/// A byte scan on purpose. The structural walk above only inspects `state`
/// fields it knows to look at, so a state string appearing in a *new* place —
/// a nested envelope, an added key, a diagnostic that leaked — would slip
/// past it. This cannot: it is every byte the format commits to.
#[test]
fn no_unreachable_state_or_diagnostic_appears_in_the_pinned_bytes() {
    let mut saw_a_state_needle = false;
    let mut saw_empty_array = false;
    for case in &cases() {
        let json = pinned_report_bytes(case);
        for state in STATES_NO_PINNED_REPORT_MAY_CARRY {
            let needle = format!("\"state\":\"{state}\"");
            assert!(
                !json.contains(&needle),
                "the state string `{state}` entered the pinned report bytes — it names a \
                 verdict reachable only from an artifact the verifier read successfully, \
                 and no committed fixture carries one (A22 lands the first)"
            );
        }
        saw_a_state_needle |= json.contains("\"state\":\"invalid\"");
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
        saw_a_state_needle,
        "no `\"state\":\"<spelling>\"` in any pinned report — the needle shape is wrong and \
         the assertions above are vacuous. NOTE (2026-08-06): this guard witnessed \
         `absent` until R12, and `absent` has since left the pinned bytes legitimately — \
         D53 §4a makes it a kind-level answer that emits no slot, so from M2 onward no \
         report can contain it. The witness is now `invalid`. If this fires, check the \
         needle shape before weakening the guard"
    );
    assert!(
        saw_empty_array,
        "the pinned `\"anchors\":[]` byte string is gone"
    );
}
