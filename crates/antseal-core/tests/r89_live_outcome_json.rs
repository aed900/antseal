//! **R89 — the `--live` outcome's machine shape, pinned where it is
//! produced.**
//!
//! [`LiveBlobOutcome`] derives `Serialize`, and `LiveSection::to_canonical_json`
//! is what U30 emits under `--json` as the envelope's `live` member. R89
//! replaced that variant's free-form `reason: String` with the closed
//! [`FetchFailureClass`], which **moves those bytes**: the fetch-failure row
//! used to serialize as
//!
//! ```json
//! {"fetch-failed":{"reason":"transport failure"}}
//! ```
//!
//! and now serializes as
//!
//! ```json
//! {"fetch-failed":{"class":"Transport"}}
//! ```
//!
//! The move was legitimate under D65 §3 — the `live` sibling is **tier C**,
//! *"deterministic by construction … reviewed, not promised until U32"* — but
//! it was also **unwitnessed**, and that is the reason this file exists rather
//! than a comment. Before R89 nothing in the workspace asserted the shape of
//! the `fetch-failed` member: `verify_live_manifest.rs` pins `"identical"`,
//! `"different"` and `"not-found"`, all unit variants with no payload, and no
//! committed envelope snapshot contains a live section at all. A machine
//! surface that no test reads is one an edit moves in silence — this
//! project's dominant defect class, applied to a shape rather than to an
//! assertion.
//!
//! What this pins is the shape, not a promise: the D65 tier is unchanged and
//! U32 remains where the commitment would be made. Moving a byte here after
//! R89 must be a deliberate act with this file edited in the same change.

use antseal_core::verify::orchestration::{FetchFailureClass, LiveBlobOutcome};

/// One JSON rendering per outcome, spelled out. The fetch-failure arm is
/// swept over [`FetchFailureClass::ALL`] rather than written once, so a third
/// class arrives here as a red rather than as an unpinned shape.
#[test]
fn every_live_outcome_serializes_to_its_pinned_shape() {
    let cases = [
        (LiveBlobOutcome::Identical, r#""identical""#),
        (LiveBlobOutcome::Different, r#""different""#),
        (LiveBlobOutcome::NotFound, r#""not-found""#),
    ];
    for (outcome, expected) in &cases {
        let json = serde_json::to_string(outcome).expect("the outcome serializes");
        assert_eq!(&json, expected, "{outcome:?} moved its machine shape");
    }

    // A sweep is vacuous over an empty operand, so the operand is asserted
    // before it is swept (the discipline the class's own label test follows).
    assert_eq!(
        FetchFailureClass::ALL.len(),
        2,
        "the sweep below is vacuous if ALL shrinks; grow or shrink it deliberately"
    );
    let fetch_failed: Vec<String> = FetchFailureClass::ALL
        .into_iter()
        .map(|class| {
            serde_json::to_string(&LiveBlobOutcome::FetchFailed { class })
                .expect("the outcome serializes")
        })
        .collect();
    assert_eq!(
        fetch_failed,
        vec![
            r#"{"fetch-failed":{"class":"Transport"}}"#.to_owned(),
            r#"{"fetch-failed":{"class":"BackendRefused"}}"#.to_owned(),
        ],
        "the fetch-failure member's machine shape moved"
    );
}

/// The machine member carries the **class**, never the rendered sentence.
///
/// This is the serialized half of R79's guarantee, restated over R89's type:
/// a `--json` consumer that wants to branch reads a discriminant, and the
/// display word — which is the frozen wording table's, not this type's —
/// stays out of the machine surface entirely.
#[test]
fn the_machine_member_carries_no_display_word() {
    for class in FetchFailureClass::ALL {
        let json = serde_json::to_string(&LiveBlobOutcome::FetchFailed { class })
            .expect("the outcome serializes");
        let label = antseal_core::verify::wording::live_fetch_failure_class_label(class);
        assert!(
            !json.contains(label),
            "{class:?}'s display word `{label}` reached the machine member: {json}"
        );
        // The positive half: the member is not merely free of the sentence,
        // it carries the thing a consumer is meant to read.
        assert!(
            json.contains(&format!("{class:?}")),
            "{class:?} is not identifiable in its own machine member: {json}"
        );
    }
}

/// The outcome's own stable token is unaffected by R89 — the variant gained a
/// payload, and `token()` names the variant, not what it carries.
#[test]
fn the_outcome_token_is_unchanged_by_the_payload() {
    assert_eq!(
        LiveBlobOutcome::FetchFailed {
            class: FetchFailureClass::Transport,
        }
        .token(),
        "fetch-failed"
    );
    assert_eq!(
        LiveBlobOutcome::FetchFailed {
            class: FetchFailureClass::BackendRefused,
        }
        .token(),
        "fetch-failed",
        "the token names the outcome, so both classes share it"
    );
}
