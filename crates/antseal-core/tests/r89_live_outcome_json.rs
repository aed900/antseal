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
//! and R89 made it
//!
//! ```json
//! {"fetch-failed":{"class":"Transport"}}
//! ```
//!
//! — one value in two casings, a kebab-case outcome around a PascalCase class.
//! **D190 R1 (R91) respelled the class kebab-case**, the casing of the outcome
//! that encloses it and of its online sibling `ProbeFailureClass`, so the
//! member now serializes as
//!
//! ```json
//! {"fetch-failed":{"class":"transport"}}
//! ```
//!
//! Both moves were legitimate under D65 §3 — the `live` sibling is **tier C**,
//! *"deterministic by construction … reviewed, not promised until U32"* — and
//! D190 landed the second before U32 on purpose: after the freeze, narrowing
//! an enum-valued key's spelling set is D65 §6-breaking. `ENVELOPE_VERSION`
//! stays 1 and `REPORT_VERSION` is unmoved (D190 R6). R89's move was also
//! **unwitnessed**, and that is the reason this file exists rather
//! than a comment. Before R89 nothing in the workspace asserted the shape of
//! the `fetch-failed` member: `verify_live_manifest.rs` pins `"identical"`,
//! `"different"` and `"not-found"`, all unit variants with no payload, and no
//! committed envelope snapshot contains a live section at all. A machine
//! surface that no test reads is one an edit moves in silence — this
//! project's dominant defect class, applied to a shape rather than to an
//! assertion.
//!
//! What this pins is the shape, not a promise: the D65 tier is unchanged and
//! U32 remains where the commitment would be made. Moving a byte here must be
//! a deliberate act with this file edited in the same change, as D190 did.
//! The casing has a second producer — the online boundary's
//! `ProbeFailureClass` — and
//! `the_storage_and_online_failure_classes_share_one_wire_spelling` pins both
//! (D190 R4).

use antseal_core::verify::orchestration::{FetchFailureClass, LiveBlobOutcome};
use antseal_core::verify::overlay::ProbeFailureClass;

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
            r#"{"fetch-failed":{"class":"transport"}}"#.to_owned(),
            r#"{"fetch-failed":{"class":"backend-refused"}}"#.to_owned(),
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
        // it carries the thing a consumer is meant to read — the class's
        // kebab-case wire token (D190 R1). Spelled by a wildcard-free match,
        // so a third class is a compile error here rather than a quiet pass.
        let token = match class {
            FetchFailureClass::Transport => "transport",
            FetchFailureClass::BackendRefused => "backend-refused",
        };
        assert!(
            json.contains(&format!(r#""class":"{token}""#)),
            "{class:?} is not identifiable by its wire token `{token}` in its own machine member: \
             {json}"
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

/// **D190 R4 — the storage and the online failure classes share one wire
/// spelling.** [`FetchFailureClass`] (the storage boundary, this file's
/// subject) and [`ProbeFailureClass`] (the online boundary) are one
/// discipline, and each class's doc names the other. Until D190 they
/// disagreed on casing, so a `--json` consumer met `"Transport"` from a
/// failed live fetch and `"transport"` from a failed online probe.
///
/// Each class's `Transport` is pinned to the literal, not to the other
/// class, so a casing change on **either** producer alone reddens this test
/// (R91's Accept); and every spelling of both classes is checked kebab-case,
/// so a per-variant rename cannot bring a second casing back.
#[test]
fn the_storage_and_online_failure_classes_share_one_wire_spelling() {
    assert_eq!(
        serde_json::to_string(&FetchFailureClass::Transport).expect("the class serializes"),
        r#""transport""#,
        "the storage boundary's Transport moved its wire spelling"
    );
    assert_eq!(
        serde_json::to_string(&ProbeFailureClass::Transport).expect("the class serializes"),
        r#""transport""#,
        "the online boundary's Transport moved its wire spelling"
    );

    // A sweep is vacuous over an empty operand, so both operands are
    // asserted before they are swept.
    assert_eq!(
        FetchFailureClass::ALL.len(),
        2,
        "grow or shrink this sweep deliberately"
    );
    assert_eq!(
        ProbeFailureClass::ALL.len(),
        3,
        "grow or shrink this sweep deliberately"
    );
    let spellings: Vec<String> = FetchFailureClass::ALL
        .iter()
        .map(|class| serde_json::to_string(class).expect("the class serializes"))
        .chain(
            ProbeFailureClass::ALL
                .iter()
                .map(|class| serde_json::to_string(class).expect("the class serializes")),
        )
        .collect();
    assert_eq!(
        spellings.len(),
        5,
        "every variant of both classes was spelled"
    );
    for spelling in &spellings {
        let token = spelling
            .strip_prefix('"')
            .and_then(|rest| rest.strip_suffix('"'))
            .unwrap_or_else(|| panic!("a unit variant serializes as a bare string: {spelling}"));
        let kebab = !token.is_empty()
            && !token.starts_with('-')
            && !token.ends_with('-')
            && !token.contains("--")
            && token.bytes().all(|b| b.is_ascii_lowercase() || b == b'-');
        assert!(
            kebab,
            "{spelling} is not a kebab-case token; both failure classes spell kebab-case (D190 R1)"
        );
    }
}
