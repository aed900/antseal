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

/// The outcome's own token is unaffected by R89 — the variant gained a
/// payload, and the token names the variant, not what it carries. The token
/// is the serde tag, read the way the verifier page reads it: a struct
/// variant is a one-key object, and its key is the outcome's token. Until
/// D200 (R99) this asserted a hand-written `token()` that mirrored the tag
/// and had no production caller; serde's tag is now the one spelling.
#[test]
fn the_outcome_token_is_unchanged_by_the_payload() {
    assert_eq!(
        FetchFailureClass::ALL.len(),
        2,
        "the sweep below is vacuous if ALL shrinks; grow or shrink it deliberately"
    );
    for class in FetchFailureClass::ALL {
        let value = serde_json::to_value(LiveBlobOutcome::FetchFailed { class })
            .expect("the outcome serializes");
        let keys: Vec<&str> = value
            .as_object()
            .unwrap_or_else(|| panic!("a struct variant serializes as an object: {value}"))
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            keys,
            ["fetch-failed"],
            "the tag names the outcome, so every class shares it: {value}"
        );
    }
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

/// **D200 (R99) — serde is the single source of verify's wire names, held by
/// absence.** Four hand-written `token()` methods once re-spelled serde's
/// tags — [`LiveBlobOutcome`]'s in `orchestration.rs`, and `HeadlineImpact`'s,
/// `OverlayOutcomeClass`'s and `AggregateDelta`'s in `overlay.rs` — with no
/// production caller, against D190 §2 R2's rule that a public method either
/// has a production caller or does not exist. D200 deleted all four, and the
/// tests that read them now read the serde tag; this keeps them deleted by
/// reading the two source files and finding no `fn token(` in either.
///
/// The crate's other `token()` methods (in `anchor/` and `bundle/`) return
/// RFC 3161 token bytes, not class spellings, and are not scanned.
#[test]
fn no_hand_written_token_method_mirrors_a_verify_class_enum() {
    const NEEDLE: &str = "fn token(";
    // The needle matches the shape the deleted methods had, so a zero below
    // is a finding about the files rather than about the needle.
    assert_eq!(
        "    pub const fn token(&self) -> &'static str {"
            .matches(NEEDLE)
            .count(),
        1,
        "the needle no longer matches the deleted methods' own signature"
    );
    let sources = [
        (
            "src/verify/orchestration.rs",
            include_str!("../src/verify/orchestration.rs"),
        ),
        (
            "src/verify/overlay.rs",
            include_str!("../src/verify/overlay.rs"),
        ),
    ];
    // A sweep is vacuous over an empty operand or an unread file: the operand
    // is asserted first, and each file carries a positive control of the
    // needle's own alphabet (both files still define `pub const fn`s).
    assert_eq!(sources.len(), 2, "the two files the four methods lived in");
    for (path, text) in sources {
        assert!(
            text.matches("pub const fn ").count() > 0,
            "{path}: the positive control found no `pub const fn` — the scan is not reading \
             the file it names"
        );
        assert_eq!(
            text.matches(NEEDLE).count(),
            0,
            "{path} defines a `token()` again: a class enum's wire name has one spelling, its \
             serde tag (D200, R99) — delete the method and read the tag in the test instead"
        );
    }
}
