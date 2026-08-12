//! D69 §7's rows 4 and 5 for the classifier: the rung table exhaustively,
//! and the fold over mixed sets stated as the rule rather than as examples.
//!
//! Unit tests on purpose (R17's arrangement): the `wasm32-core-tests` lane
//! runs this crate's `--lib` tests on `wasm32-unknown-unknown`, so every row
//! here runs on both targets — which is what makes *"R22's page can state the
//! same rung"* (D69 §3 R4) a measured claim rather than an intention.

use super::*;

use crate::anchor::model::{AnchorDiagnostic, AnchorVerdict};
use crate::verify::report::AnchorKind;

/// A fixture `.ots` diagnostic — the code is not what this module reads, but
/// `invalid` carries one by construction (A2) and a fixture must be buildable
/// the way the machinery builds it.
fn diagnostic() -> AnchorDiagnostic {
    AnchorDiagnostic::new("anchor-ots-online-header-mismatch")
}

/// One verdict per state, through the real constructors — never a hand-set
/// `state` field, so a fixture cannot express a shape A2 forbids.
fn verdict(state: AnchorState, time_unix: i64) -> AnchorVerdict {
    match state {
        AnchorState::Proven => AnchorVerdict::proven(AnchorKind::Tsa, time_unix, None, None),
        AnchorState::ValidAtStampingCertSinceExpired => {
            AnchorVerdict::valid_at_stamping_cert_since_expired(
                AnchorKind::Tsa,
                time_unix,
                None,
                None,
            )
        }
        AnchorState::Attested => AnchorVerdict::attested(AnchorKind::Ots, None, None),
        AnchorState::Pending => AnchorVerdict::pending(AnchorKind::Ots, None, None),
        AnchorState::InternallyConsistentOnly => {
            AnchorVerdict::internally_consistent_only(AnchorKind::Tsa, None, None)
        }
        AnchorState::Invalid => AnchorVerdict::invalid(AnchorKind::Tsa, diagnostic(), None, None),
        AnchorState::Absent => AnchorVerdict::absent(AnchorKind::Tsa),
    }
}

/// The rung of a set given as `(state, time)` pairs — the whole classifier
/// end to end, over `VerdictAggregate::from_parts` (which exists *"for
/// fixtures that need arbitrary states and times without minting artifacts"*).
fn rung_of(set: &[(AnchorState, i64)]) -> Option<VerdictExitRung> {
    let verdicts: Vec<AnchorVerdict> = set
        .iter()
        .map(|(state, time)| verdict(*state, *time))
        .collect();
    let aggregate = VerdictAggregate::from_parts(verdicts.iter(), None);
    let refuted = count_refuted(verdicts.iter().map(AnchorVerdict::state));
    verdict_exit_rung(&aggregate, refuted)
}

/// One labelled rung case: a name, a set of `(state, time)` pairs, and the
/// rung the fold must return for it.
type RungCase = (
    &'static str,
    Vec<(AnchorState, i64)>,
    Option<VerdictExitRung>,
);

const T: i64 = 1_785_000_000;
/// 49 h after `T` — past the strictly-greater-than 48 h threshold.
const T_PLUS_49H: i64 = T + 49 * 60 * 60;

// ─────────────────────────────────────────────────────────────────────
// the refutation predicate
// ─────────────────────────────────────────────────────────────────────

/// Exactly one of the seven states is a refutation, and it is the one
/// MVP-SPEC.md line 134 names. A sweep, not an example: a later lane widening
/// the predicate to (say) `internally-consistent-only` reddens here.
#[test]
fn invalid_is_the_only_refuting_state() {
    let refuting: Vec<&str> = AnchorState::ALL
        .into_iter()
        .filter(|state| is_refutation(*state))
        .map(AnchorState::wire_name)
        .collect();
    assert_eq!(refuting, vec!["invalid"]);
}

/// The report-slot adapter is the shared count, not a second one: for every
/// state, a slot sequence and the bare state sequence give the same answer.
///
/// The *other* adapter ([`refuted_in_verdicts`]) is held to the same equality
/// over a **real** evaluation in `tests/verify_orchestration.rs`, where a
/// genuine `AnchorVerdicts` and the report it projects to both exist —
/// `AnchorOutcome`'s constructor is private, so a hand-built verdict set here
/// would be a fixture the machinery cannot produce.
#[test]
fn the_report_slot_adapter_is_the_shared_count() {
    for extra in AnchorState::ALL {
        let states = [AnchorState::Invalid, extra, AnchorState::Invalid];
        let slots: Vec<AnchorResult> = states
            .iter()
            .map(|state| AnchorResult {
                kind: AnchorKind::Tsa,
                state: *state,
                verified_time_unix: None,
                source: None,
                fetch_date: None,
            })
            .collect();
        assert_eq!(
            refuted_in_report_slots(&slots),
            count_refuted(states),
            "the slot adapter disagreed with the shared count with `{}` in the set",
            extra.wire_name()
        );
    }
}

// ─────────────────────────────────────────────────────────────────────
// the rung table (D69 §7 row 4)
// ─────────────────────────────────────────────────────────────────────

/// One case per rung plus the clean case, and the names are asserted rather
/// than assumed — the names are what U30 maps onto U2's code table, so a
/// respelling here is a machine-interface change and must redden.
#[test]
fn each_rung_fires_on_its_own_shape_and_carries_its_name() {
    let cases: &[RungCase] = &[
        (
            "clean: one proven anchor",
            vec![(AnchorState::Proven, T)],
            None,
        ),
        (
            "refuted",
            vec![(AnchorState::Proven, T), (AnchorState::Invalid, T)],
            Some(VerdictExitRung::AnchorRefuted),
        ),
        (
            "divergence",
            vec![(AnchorState::Proven, T), (AnchorState::Proven, T_PLUS_49H)],
            Some(VerdictExitRung::HeadlineDivergence),
        ),
        (
            "unanchored",
            vec![(AnchorState::Pending, T), (AnchorState::Attested, T)],
            Some(VerdictExitRung::Unanchored),
        ),
        (
            "unanchored: the empty set",
            vec![],
            Some(VerdictExitRung::Unanchored),
        ),
    ];

    for (label, set, expected) in cases {
        assert_eq!(rung_of(set), *expected, "{label}");
    }

    assert_eq!(
        VerdictExitRung::ALL.map(VerdictExitRung::name),
        [
            "verify-unanchored",
            "verify-headline-divergence",
            "verify-anchor-refuted",
        ],
        "the rung class names are U30's mapping keys; a respelling is a \
         machine-interface change"
    );
}

/// D69 §3 R2: the four ineligible non-`Invalid` states get **no rung of their
/// own** — each produces UNANCHORED when alone, and none produces a rung when
/// a `proven` anchor is present. A sweep over `AnchorState::ALL`, so an
/// eighth state must be placed here deliberately.
#[test]
fn ineligible_non_refuting_states_produce_unanchored_alone_and_nothing_beside_proven() {
    for state in AnchorState::ALL {
        if is_refutation(state) {
            continue;
        }
        let alone = rung_of(&[(state, T)]);
        let beside_proven = rung_of(&[(AnchorState::Proven, T), (state, T)]);

        if crate::verify::aggregate::headline_eligible(state) {
            assert_eq!(alone, None, "`{}` alone proves a time", state.wire_name());
        } else {
            assert_eq!(
                alone,
                Some(VerdictExitRung::Unanchored),
                "`{}` alone must be UNANCHORED",
                state.wire_name()
            );
        }
        assert_eq!(
            beside_proven,
            None,
            "`{}` must not produce a rung beside a proven anchor",
            state.wire_name()
        );
    }
}

// ─────────────────────────────────────────────────────────────────────
// the fold (D69 §7 row 5)
// ─────────────────────────────────────────────────────────────────────

/// D69 §7 row 5's six mixed sets, verbatim. The point of the row is that the
/// answers come out of the rule, not out of a list — `{invalid}` satisfies
/// rungs 1 **and** 3 at once and rung 1 wins by the `Ord` derive.
#[test]
fn the_fold_resolves_every_mixed_set_by_the_rule() {
    let cases: &[RungCase] = &[
        (
            "{proven, invalid} -> refuted",
            vec![(AnchorState::Proven, T), (AnchorState::Invalid, T)],
            Some(VerdictExitRung::AnchorRefuted),
        ),
        (
            "{proven, pending} -> clean",
            vec![(AnchorState::Proven, T), (AnchorState::Pending, T)],
            None,
        ),
        (
            "{proven@T, proven@T+49h} -> divergence",
            vec![(AnchorState::Proven, T), (AnchorState::Proven, T_PLUS_49H)],
            Some(VerdictExitRung::HeadlineDivergence),
        ),
        (
            "{pending, attested} -> unanchored",
            vec![(AnchorState::Pending, T), (AnchorState::Attested, T)],
            Some(VerdictExitRung::Unanchored),
        ),
        (
            "{invalid} -> refuted (rungs 1 and 3 both hold; 1 wins)",
            vec![(AnchorState::Invalid, T)],
            Some(VerdictExitRung::AnchorRefuted),
        ),
        (
            "{} -> unanchored",
            vec![],
            Some(VerdictExitRung::Unanchored),
        ),
    ];

    for (label, set, expected) in cases {
        assert_eq!(rung_of(set), *expected, "{label}");
    }
}

/// A refutation beside a divergence beside an absence: all three predicates
/// hold at once and the ladder returns the top rung. This is the case an
/// `if`/`else` cascade and a `max()` can differ on if the cascade is
/// mis-ordered, so it is asserted rather than reasoned about.
#[test]
fn the_worst_established_fact_wins_when_every_predicate_holds() {
    let set = vec![
        (AnchorState::Proven, T),
        (AnchorState::Proven, T_PLUS_49H),
        (AnchorState::Invalid, T),
    ];
    assert_eq!(
        rung_of(&set),
        Some(VerdictExitRung::AnchorRefuted),
        "all three predicates hold and the ladder must return the top rung"
    );

    // …and removing only the refutation exposes the rung underneath, which is
    // what makes the assertion above about the *ladder* rather than about the
    // set having one answer.
    assert_eq!(
        rung_of(&set[..2]),
        Some(VerdictExitRung::HeadlineDivergence),
        "with the refutation gone the rung underneath must surface"
    );
}

/// D69 §3 R3's stated property: rungs 2 and 3 are mutually exclusive by
/// construction, so the ladder only ever arbitrates 1-vs-2 and 1-vs-3.
/// Asserted over the aggregate rather than trusted, because the day it stops
/// being true the fold's reasoning changes.
#[test]
fn divergence_and_unanchored_cannot_hold_together() {
    for set in [
        vec![(AnchorState::Proven, T), (AnchorState::Proven, T_PLUS_49H)],
        vec![(AnchorState::Pending, T), (AnchorState::Attested, T)],
        vec![(AnchorState::Invalid, T), (AnchorState::Proven, T)],
        vec![],
    ] {
        let verdicts: Vec<AnchorVerdict> = set
            .iter()
            .map(|(state, time)| verdict(*state, *time))
            .collect();
        let aggregate = VerdictAggregate::from_parts(verdicts.iter(), None);
        assert!(
            !(aggregate.divergence().is_some() && aggregate.is_unanchored()),
            "a flagged divergence needs two timed eligible anchors, so it \
             cannot coexist with zero of them"
        );
    }
}

/// The ladder is the `Ord` derive, and the `Ord` derive is the declaration
/// order. Pinned so a lane that reorders the variants to "read better" finds
/// something red rather than a silently inverted severity ladder.
#[test]
fn the_rank_is_the_declaration_order_and_is_not_the_code_order() {
    assert!(VerdictExitRung::Unanchored < VerdictExitRung::HeadlineDivergence);
    assert!(VerdictExitRung::HeadlineDivergence < VerdictExitRung::AnchorRefuted);

    let mut sorted = VerdictExitRung::ALL;
    sorted.sort_unstable();
    assert_eq!(sorted, VerdictExitRung::ALL);

    // D69's integers descend as the rank ascends (41 refuted, 42 divergence,
    // 43 unanchored). No integer lives in this crate; the ordering above is
    // why a numeric comparison could never have stood in for it.
    assert_eq!(
        VerdictExitRung::ALL.map(VerdictExitRung::name)[2],
        "verify-anchor-refuted"
    );
}
