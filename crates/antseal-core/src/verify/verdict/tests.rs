//! R17's offline-aggregate rows. Unit tests on purpose: the
//! `wasm32-core-tests` lane runs this crate's `--lib` tests on
//! `wasm32-unknown-unknown`, so every row below runs natively **and** on
//! wasm32 (the A18 arrangement; R17's Accept requires "WASM-safe,
//! deterministic" as tested properties, not adjectives).
//!
//! Fixtures are built from [`AnchorVerdict`]'s own public state constructors
//! (`AnchorArtifacts::from_parts`' precedent: literals, no artifacts, no
//! network), except where a row needs the real machinery — the receipt-only
//! row goes through `evaluate_anchors` because [`ReceiptEvidence`] is
//! deliberately constructible by evaluation alone.

use super::*;

use crate::anchor::model::{AnchorArtifacts, AnchorDiagnostic, AnchorVerdict, OnlineEvidence};
use crate::anchor::roots::TsaRootStore;
use crate::anchor::verdicts::evaluate_anchors;
use crate::bundle::schema::{OpaqueBytes, ReceiptRecord};
use crate::verify::aggregate::aggregate_anchors;
use crate::verify::aggregate::headline_eligible;
use crate::verify::report::AnchorState;

/// A proven TSA at `time` — the ordinary headline carrier.
fn proven_tsa(time: i64, source: &str) -> AnchorVerdict {
    AnchorVerdict::proven(AnchorKind::Tsa, time, Some(source.to_owned()), None)
}

/// A proven OTS at `time` — what `--online` promotion produces; here it
/// stands in for the online-augmented computation's input, since this module
/// aggregates whatever verdicts it is handed.
fn proven_ots(time: i64, source: &str) -> AnchorVerdict {
    AnchorVerdict::proven(AnchorKind::Ots, time, Some(source.to_owned()), None)
}

fn aggregate_of(verdicts: &[AnchorVerdict]) -> VerdictAggregate {
    VerdictAggregate::from_parts(verdicts.iter(), None)
}

/// One verdict of every constructible state, A2's `every_state_verdict`
/// shape — the ineligible five carry sources so a wrongly-eligible
/// implementation would have data to leak.
fn one_of_each_state() -> Vec<AnchorVerdict> {
    vec![
        AnchorVerdict::proven(AnchorKind::Tsa, 1_785_000_000, Some("freetsa".into()), None),
        AnchorVerdict::valid_at_stamping_cert_since_expired(
            AnchorKind::Tsa,
            1_785_000_600,
            Some("digicert".into()),
            None,
        ),
        AnchorVerdict::attested(AnchorKind::Ots, Some("bitcoin-block-42".into()), None),
        AnchorVerdict::pending(AnchorKind::Ots, Some("calendar.example".into()), None),
        AnchorVerdict::internally_consistent_only(AnchorKind::Tsa, Some("swisssign".into()), None),
        AnchorVerdict::invalid(
            AnchorKind::Ots,
            AnchorDiagnostic::new("verdict-tests-probe-code"),
            None,
            None,
        ),
        AnchorVerdict::absent(AnchorKind::Tsa),
    ]
}

// ── the [H] map, exhaustively ───────────────────────────────────────────

/// R17 Accept: the eligibility map is exhaustive over all 7 states and is
/// **the** predicate — this module contributes eligibility for a state iff
/// A1's `headline_eligible` says so. There is no second table to drift: the
/// aggregate contains no `AnchorState` match at all, and the compile-break
/// on an eighth state lives on the predicate's own wildcard-free match.
#[test]
fn eligibility_in_the_aggregate_is_a1s_predicate_over_every_one_of_the_seven_states() {
    for verdict in one_of_each_state() {
        let expected = u64::from(headline_eligible(verdict.state()));
        let aggregate = VerdictAggregate::from_parts([&verdict], None);
        assert_eq!(
            aggregate.eligible_count(),
            expected,
            "{:?}: the aggregate disagrees with the one predicate",
            verdict.state()
        );
        assert_eq!(
            aggregate.is_unanchored(),
            expected == 0,
            "{:?}: UNANCHORED must be exactly zero-eligible",
            verdict.state()
        );
    }
    // The sweep above is exhaustive because the fixture is: one verdict per
    // state, checked against `AnchorState::ALL`'s length.
    let states: Vec<AnchorState> = one_of_each_state()
        .iter()
        .map(AnchorVerdict::state)
        .collect();
    assert_eq!(states.len(), AnchorState::ALL.len());
    for state in AnchorState::ALL {
        assert!(states.contains(&state), "{state:?} missing from the sweep");
    }
}

// ── earliest-wins, across kinds and on ties ─────────────────────────────

/// R17 Accept: earliest-wins across TSA/OTS mixes — whichever kind carries
/// the smallest verified time wins the headline, and the whole datum (time,
/// kind, source) is the winner's. Differential in both directions so a
/// kind-biased implementation fails one of the two.
#[test]
fn the_earliest_eligible_time_wins_the_headline_across_tsa_and_ots_mixes() {
    let ots_earlier = [
        proven_tsa(500, "freetsa"),
        proven_ots(300, "bitcoin-block-42"),
    ];
    let headline = aggregate_of(&ots_earlier)
        .headline()
        .expect("two eligible anchors")
        .clone();
    assert_eq!(headline.time_unix(), 300);
    assert_eq!(headline.kind(), AnchorKind::Ots);
    assert_eq!(headline.source(), Some("bitcoin-block-42"));

    let tsa_earlier = [
        proven_ots(500, "bitcoin-block-42"),
        proven_tsa(300, "freetsa"),
        AnchorVerdict::valid_at_stamping_cert_since_expired(
            AnchorKind::Tsa,
            400,
            Some("digicert".into()),
            None,
        ),
    ];
    let headline = aggregate_of(&tsa_earlier)
        .headline()
        .expect("three eligible anchors")
        .clone();
    assert_eq!(headline.time_unix(), 300);
    assert_eq!(headline.kind(), AnchorKind::Tsa);
    assert_eq!(headline.source(), Some("freetsa"));
}

/// The frozen tie-break (D64 §9's risk area): two eligible anchors at the
/// same second with **different sources** — the first slot in report order
/// wins, deterministically, and the whole datum is the winner's. Swapping
/// the order swaps the winner, which is what makes this row able to fail
/// against any "latest wins on tie" or unordered implementation.
#[test]
fn an_exact_time_tie_is_broken_by_report_order_and_the_whole_datum_follows_the_winner() {
    let ots_first = [
        proven_ots(300, "bitcoin-block-42"),
        proven_tsa(300, "freetsa"),
    ];
    let headline = aggregate_of(&ots_first)
        .headline()
        .expect("eligible anchors")
        .clone();
    assert_eq!(
        (headline.kind(), headline.source()),
        (AnchorKind::Ots, Some("bitcoin-block-42")),
        "first in order keeps the tie"
    );

    let tsa_first = [
        proven_tsa(300, "freetsa"),
        proven_ots(300, "bitcoin-block-42"),
    ];
    let headline = aggregate_of(&tsa_first)
        .headline()
        .expect("eligible anchors")
        .clone();
    assert_eq!(
        (headline.kind(), headline.source()),
        (AnchorKind::Tsa, Some("freetsa")),
        "the tie-break is order, not kind"
    );
}

/// Two headlines equal on time but different in source are **different
/// datums** — the equality D64 §9 requires the overlay's Stands/Supplies
/// classifier to lean on. A time-only `PartialEq` would pass everything
/// else in this file and fail here.
#[test]
fn headline_equality_compares_the_whole_datum_never_time_alone() {
    let a = aggregate_of(&[proven_tsa(300, "freetsa")])
        .headline()
        .expect("eligible")
        .clone();
    let b = aggregate_of(&[proven_tsa(300, "digicert")])
        .headline()
        .expect("eligible")
        .clone();
    let a_again = aggregate_of(&[proven_tsa(300, "freetsa")])
        .headline()
        .expect("eligible")
        .clone();
    assert_eq!(a.time_unix(), b.time_unix());
    assert_ne!(
        a, b,
        "same second, different source: different headline datum"
    );
    assert_eq!(a, a_again, "equal datum compares equal");
}

// ── the >48 h divergence boundary, both sides and the exact second ──────

/// R17 Accept: 47 h 59 m apart is not flagged; 48 h 01 m apart is. Plus the
/// frozen exact boundary: 48 h 00 m 00 s is NOT flagged (strictly
/// greater-than — the spec's ">48 h") and one second more is. The four
/// probes bracket the constant so `>=`, an off-by-minute, or a wrong unit
/// all fail at least one.
#[test]
fn the_divergence_boundary_is_strictly_greater_than_48_hours() {
    let base = 1_700_000_000i64;
    let spread = |delta: i64| {
        aggregate_of(&[
            proven_tsa(base, "freetsa"),
            proven_ots(base + delta, "bitcoin-block-42"),
        ])
    };

    // 47 h 59 m — under the threshold by a minute.
    assert_eq!(
        spread(HEADLINE_DIVERGENCE_THRESHOLD_SECS - 60).divergence(),
        None
    );
    // Exactly 48 h — frozen unflagged (strict `>`).
    assert_eq!(
        spread(HEADLINE_DIVERGENCE_THRESHOLD_SECS).divergence(),
        None
    );
    // 48 h and one second — flagged.
    let flagged = spread(HEADLINE_DIVERGENCE_THRESHOLD_SECS + 1);
    let divergence = flagged
        .divergence()
        .expect("one second past the threshold flags");
    assert_eq!(divergence.earliest_unix(), base);
    assert_eq!(
        divergence.latest_unix(),
        base + HEADLINE_DIVERGENCE_THRESHOLD_SECS + 1
    );
    // 48 h 01 m — the Accept row's flagged side.
    assert!(
        spread(HEADLINE_DIVERGENCE_THRESHOLD_SECS + 60)
            .divergence()
            .is_some()
    );
    // The headline is still the earliest anchor either way: the flag is an
    // outcome beside the headline, never a suppression of it.
    assert_eq!(
        flagged.headline().expect("still anchored").time_unix(),
        base
    );
}

/// Ineligible times cannot create a divergence: only headline-eligible
/// anchors enter the spread. An `attested`/`pending`/`invalid` slot carries
/// no verified time by construction (A2), so the eligible-only rule and the
/// constructors close the same door twice.
#[test]
fn only_eligible_anchors_enter_the_divergence_spread() {
    let verdicts = [
        proven_tsa(1_700_000_000, "freetsa"),
        proven_tsa(1_700_000_100, "digicert"),
        // Five ineligible states beside them, none carrying a time.
        AnchorVerdict::attested(AnchorKind::Ots, Some("bitcoin-block-42".into()), None),
        AnchorVerdict::pending(AnchorKind::Ots, None, None),
        AnchorVerdict::internally_consistent_only(AnchorKind::Tsa, None, None),
        AnchorVerdict::invalid(
            AnchorKind::Ots,
            AnchorDiagnostic::new("verdict-tests-probe-code"),
            None,
            None,
        ),
        AnchorVerdict::absent(AnchorKind::Tsa),
    ];
    let aggregate = aggregate_of(&verdicts);
    assert_eq!(aggregate.divergence(), None, "100 s apart is no divergence");
    assert_eq!(aggregate.eligible_count(), 2);
    assert_eq!(aggregate.total_anchors(), 7);
}

/// Hostile extremes cannot overflow the spread arithmetic: the constructors
/// accept any `i64`, and `i64::MAX - i64::MIN` does not fit an `i64`. The
/// fold works in `i128`, so this is a flagged divergence rather than a wrap
/// or a panic — total on adversarial input, per the crate's parsing rules.
#[test]
fn extreme_times_flag_a_divergence_instead_of_overflowing() {
    let aggregate = aggregate_of(&[
        proven_tsa(i64::MIN, "freetsa"),
        proven_ots(i64::MAX, "bitcoin-block-42"),
    ]);
    let divergence = aggregate
        .divergence()
        .expect("the widest possible spread flags");
    assert_eq!(divergence.earliest_unix(), i64::MIN);
    assert_eq!(divergence.latest_unix(), i64::MAX);
    assert_eq!(
        aggregate.headline().expect("anchored").time_unix(),
        i64::MIN
    );
}

// ── UNANCHORED ──────────────────────────────────────────────────────────

/// R17 Accept: zero headline-eligible → the UNANCHORED outcome. All five
/// ineligible states together still aggregate to no headline, no divergence,
/// UNANCHORED — and an empty set does too.
#[test]
fn zero_eligible_anchors_aggregate_to_the_unanchored_outcome() {
    let ineligible = [
        AnchorVerdict::attested(AnchorKind::Ots, Some("bitcoin-block-42".into()), None),
        AnchorVerdict::pending(AnchorKind::Ots, Some("calendar.example".into()), None),
        AnchorVerdict::internally_consistent_only(AnchorKind::Tsa, Some("swisssign".into()), None),
        AnchorVerdict::invalid(
            AnchorKind::Ots,
            AnchorDiagnostic::new("verdict-tests-probe-code"),
            None,
            None,
        ),
        AnchorVerdict::absent(AnchorKind::Tsa),
    ];
    let aggregate = aggregate_of(&ineligible);
    assert!(aggregate.is_unanchored());
    assert_eq!(aggregate.headline(), None);
    assert_eq!(aggregate.divergence(), None);
    assert_eq!(aggregate.eligible_count(), 0);
    assert_eq!(aggregate.total_anchors(), 5);

    let empty = VerdictAggregate::from_parts([], None);
    assert!(empty.is_unanchored());
    assert_eq!(empty.headline(), None);
    assert_eq!(empty.total_anchors(), 0);
}

/// R17 Accept: a receipt-only bundle is UNANCHORED **and** its supporting
/// evidence is present — through the real machinery, because
/// [`ReceiptEvidence`] is deliberately constructible only by evaluation.
/// The receipt never enters the anchor fold: `AnchorKind` has no receipt
/// variant and `ReceiptEvidence` has no state or time field to read, so
/// "never eligible, never in the anchor set" is the shape of the input, not
/// a filter (A19; MVP-SPEC.md line 110).
#[test]
fn a_receipt_only_bundle_is_unanchored_with_its_supporting_evidence_present() {
    let record = ReceiptRecord::new(
        vec![[0xab; 32]],
        200_000_001,
        OpaqueBytes::from_vec(b"opaque capture payload".to_vec()),
    )
    .expect("a one-transaction receipt is well-formed");
    let artifacts = AnchorArtifacts::from_parts(&[], &[], Some(&record));
    let verdicts = evaluate_anchors(
        &artifacts,
        &[0x5a; 32],
        &OnlineEvidence::new(),
        1_785_000_000,
        TsaRootStore::pinned(),
    );

    let aggregate = VerdictAggregate::from_verdicts(&verdicts);
    assert!(aggregate.is_unanchored(), "no anchor artifact, no headline");
    assert_eq!(aggregate.headline(), None);
    assert_eq!(aggregate.total_anchors(), 0);
    let receipt = aggregate
        .receipt()
        .expect("the supporting evidence is present");
    assert_eq!(receipt.block_number(), 200_000_001);
    assert_eq!(receipt.transaction_count(), 1);
    assert!(
        !receipt.is_headline_eligible(),
        "A19's structural claim, echoed"
    );
}

// ── the claimed time cannot reach the headline ──────────────────────────

/// R17 Accept: a claimed time **earlier than every anchor** leaves the
/// headline unchanged. The exclusion is type-level (module docs): the
/// aggregate's input set is anchor verdicts and the receipt, and no type in
/// it has a field that could carry
/// `WorkMetadata::claimed_time_informational_only` — the metadata below sits
/// beside the computation with no parameter to enter through. The assertion
/// is the earlier-claim differential the Accept row names; deleting the
/// exclusion would require *adding* a parameter, which is the loud event.
#[test]
fn a_claimed_time_earlier_than_every_anchor_cannot_move_the_headline() {
    use crate::verify::report::{SignatureScheme, WorkMetadata};

    let claimed_earlier = WorkMetadata {
        work_id: crate::verify::report::Digest32([0x11; 32]),
        title: "claimed-time probe".to_owned(),
        format_version: 1,
        app_version: "test".to_owned(),
        // Earlier than every anchor time below, in the field's frozen
        // decimal-POSIX spelling. Nothing reads it into this module.
        claimed_time_informational_only: Some("100".to_owned()),
        signature_scheme: SignatureScheme::NotEvaluated,
    };

    let verdicts = [
        proven_tsa(500, "freetsa"),
        proven_ots(300, "bitcoin-block-42"),
    ];
    let aggregate = aggregate_of(&verdicts);
    let headline = aggregate.headline().expect("two eligible anchors");
    assert_eq!(
        headline.time_unix(),
        300,
        "the headline is the earliest ANCHOR time; the claimed 100 has no route in"
    );
    // The claim is bound to the work, not to this computation: the metadata
    // exists, says 100, and the aggregate neither read it nor could have.
    assert_eq!(
        claimed_earlier.claimed_time_informational_only.as_deref(),
        Some("100")
    );
    // Belt and braces: the winning datum's serialized form carries the
    // anchor's time, not the claim.
    let json = serde_json::to_string(headline).expect("headline serializes");
    assert!(json.contains("300"), "{json}");
    assert!(!json.contains("\"100\""), "{json}");
}

// ── consistency with A1 and the eligible-but-timeless stance ────────────

/// The full aggregate and A1's minimal one agree on every shared datum —
/// eligibility count, UNANCHORED, and the earliest time — over the same
/// verdicts, projected the way R12 projects them. One predicate, one
/// earliest-wins rule, two granularities.
#[test]
fn the_full_aggregate_agrees_with_a1s_minimal_aggregate_on_shared_data() {
    let verdicts = one_of_each_state();
    let full = aggregate_of(&verdicts);
    let projected: Vec<_> = verdicts
        .iter()
        .filter_map(AnchorVerdict::to_anchor_result)
        .collect();
    let minimal = aggregate_anchors(&projected);

    assert_eq!(full.eligible_count(), minimal.headline_eligible_count());
    assert_eq!(full.is_unanchored(), minimal.is_unanchored());
    assert_eq!(
        full.headline().map(Headline::time_unix),
        minimal.headline_time_unix(),
        "the two earliest-wins folds agree on the time"
    );
    // The projections drop `absent` (no slot), so the totals legitimately
    // differ by exactly the absent verdicts — pinned so the difference is a
    // decision, not a drift.
    assert_eq!(full.total_anchors() - 1, minimal.total_anchors());
}

// ── determinism (property; native-only per the crate's proptest split) ──

#[cfg(feature = "test-util")]
mod properties {
    use super::*;
    use crate::test_util::proptest::prelude::*;

    fn arbitrary_verdict() -> impl Strategy<Value = AnchorVerdict> {
        let kind = prop_oneof![Just(AnchorKind::Ots), Just(AnchorKind::Tsa)];
        let source = proptest::option::of("[a-z0-9.-]{1,12}");
        (kind, source, any::<i64>(), 0u8..7).prop_map(|(kind, source, time, arm)| match arm {
            0 => AnchorVerdict::proven(kind, time, source, None),
            1 => AnchorVerdict::valid_at_stamping_cert_since_expired(kind, time, source, None),
            2 => AnchorVerdict::attested(kind, source, None),
            3 => AnchorVerdict::pending(kind, source, None),
            4 => AnchorVerdict::internally_consistent_only(kind, source, None),
            5 => AnchorVerdict::invalid(
                kind,
                AnchorDiagnostic::new("verdict-tests-probe-code"),
                source,
                None,
            ),
            _ => AnchorVerdict::absent(kind),
        })
    }

    proptest! {
        /// Determinism: the same verdict sequence aggregates to the same
        /// value, and the aggregate's laws hold on arbitrary input — the
        /// headline is the minimum eligible time, UNANCHORED is exactly
        /// zero-eligible, and the flag is exactly `spread > 48 h`.
        #[test]
        fn aggregation_is_deterministic_and_lawful(
            verdicts in proptest::collection::vec(arbitrary_verdict(), 0..12)
        ) {
            let a = VerdictAggregate::from_parts(verdicts.iter(), None);
            let b = VerdictAggregate::from_parts(verdicts.iter(), None);
            prop_assert_eq!(&a, &b, "two folds over one input are one value");

            let eligible_times: Vec<i64> = verdicts
                .iter()
                .filter(|v| v.is_headline_eligible())
                .filter_map(AnchorVerdict::verified_time_unix)
                .collect();
            prop_assert_eq!(
                a.headline().map(Headline::time_unix),
                eligible_times.iter().copied().min(),
                "earliest-wins is the minimum over eligible times"
            );
            prop_assert_eq!(a.is_unanchored(), a.eligible_count() == 0);
            let spread = eligible_times.iter().copied().max().map(i128::from)
                .zip(eligible_times.iter().copied().min().map(i128::from))
                .map(|(max, min)| max - min);
            prop_assert_eq!(
                a.divergence().is_some(),
                spread.is_some_and(
                    |s| s > i128::from(HEADLINE_DIVERGENCE_THRESHOLD_SECS)
                ),
                "the flag is exactly `spread > threshold`"
            );
        }
    }
}
