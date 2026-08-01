//! The minimal anchor **aggregate** (task A1): the zero-anchor /
//! UNANCHORED path, ahead of the full M2 state machine.
//!
//! MVP-SPEC.md line 137 defines the UNANCHORED outcome as the aggregate
//! over a report's per-anchor slots when **zero anchors are
//! headline-eligible** — the state a dev-only `--no-anchor` seal (empty
//! anchor set, F13's `empty-anchor-unanchored` golden vector) always
//! lands in, and the state every M0/M1 report lands in (the anchor stage
//! parses no artifact bytes yet and reports `absent` per slot;
//! [`pipeline`] module docs).
//!
//! This module exists so the M1 E2E can library-verify an UNANCHORED
//! devnet seal (spec line 154) before A18's per-anchor state machine
//! (M2) and R17's full verdict aggregation + wording (M3) arrive. It is
//! deliberately minimal and **additive**: nothing here touches the
//! serialized [`VerificationReport`] byte format (frozen at Q14) — the
//! aggregate is derived data computed by the host over an existing
//! report.
//!
//! # Headline eligibility
//!
//! Exactly the spec's two `[H]` states prove a time offline
//! (MVP-SPEC.md lines 129–135): [`AnchorState::Proven`] and
//! [`AnchorState::ValidAtStampingCertSinceExpired`]. `attested` is not
//! headline-eligible offline — an `--online` confirmation *promotes it
//! to `proven`* rather than making `attested` eligible — and no other
//! state carries proven time. Eligibility is therefore a pure function
//! of [`AnchorState`], written as a wildcard-free match so a future
//! eighth state forces an explicit decision here.
//!
//! # The invariant with teeth
//!
//! **No code path can produce a headline time from an empty (or
//! all-ineligible) anchor set**: [`aggregate_anchors`] reads
//! `verified_time_unix` only from headline-eligible slots, so even a
//! hostile/malformed [`AnchorResult`] carrying a time on an `absent` or
//! `invalid` slot contributes nothing (tested below). R18 owns the
//! user-facing UNANCHORED wording (M3); this module owns only the datum.
//!
//! [`pipeline`]: super::pipeline
//! [`VerificationReport`]: super::report::VerificationReport

use super::report::{AnchorResult, AnchorState};

/// Whether `state` proves a time offline — the spec's `[H]` marker
/// (MVP-SPEC.md lines 129–135; module docs).
#[must_use]
pub const fn headline_eligible(state: AnchorState) -> bool {
    match state {
        AnchorState::Proven | AnchorState::ValidAtStampingCertSinceExpired => true,
        AnchorState::Attested
        | AnchorState::Pending
        | AnchorState::InternallyConsistentOnly
        | AnchorState::Invalid
        | AnchorState::Absent => false,
    }
}

/// The A1 minimal aggregate over a report's per-anchor result slots.
///
/// Constructed only by [`aggregate_anchors`], so the zero-eligible flag
/// and the counts can never disagree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnchorAggregate {
    total_anchors: u64,
    headline_eligible_count: u64,
    headline_time_unix: Option<i64>,
}

impl AnchorAggregate {
    /// Number of anchor slots aggregated (eligible or not).
    #[must_use]
    pub const fn total_anchors(&self) -> u64 {
        self.total_anchors
    }

    /// Number of headline-eligible slots.
    #[must_use]
    pub const fn headline_eligible_count(&self) -> u64 {
        self.headline_eligible_count
    }

    /// The **zero-headline-eligible flag** (A1): `true` iff no anchor
    /// slot is headline-eligible — the UNANCHORED outcome
    /// (MVP-SPEC.md line 137). An empty anchor set (a `--no-anchor`
    /// seal) is always UNANCHORED; so is every M0/M1 report (all slots
    /// `absent` until A18).
    #[must_use]
    pub const fn is_unanchored(&self) -> bool {
        self.headline_eligible_count == 0
    }

    /// The earliest independently verified time (Unix seconds) among
    /// **headline-eligible** slots — `None` whenever
    /// [`is_unanchored`](Self::is_unanchored), by construction. Earliest
    /// wins because the product's claim is proof of existence *by* a
    /// time: the oldest proven time is the strongest statement.
    #[must_use]
    pub const fn headline_time_unix(&self) -> Option<i64> {
        self.headline_time_unix
    }
}

/// Aggregate a report's per-anchor slots (`report.anchors`) into the A1
/// minimal aggregate.
///
/// Pure and total over arbitrary slot data; only headline-eligible slots
/// contribute to the count and the headline time (module docs — the
/// invariant with teeth). An eligible slot without a recorded time
/// contributes eligibility but no time; the invariant that time-proving
/// states carry times is A18/R17's (M2/M3), not enforced here.
#[must_use]
pub fn aggregate_anchors(anchors: &[AnchorResult]) -> AnchorAggregate {
    let mut headline_eligible_count = 0u64;
    let mut headline_time_unix: Option<i64> = None;
    for anchor in anchors {
        if headline_eligible(anchor.state) {
            headline_eligible_count += 1;
            if let Some(time) = anchor.verified_time_unix {
                headline_time_unix = Some(match headline_time_unix {
                    Some(earliest) if earliest <= time => earliest,
                    _ => time,
                });
            }
        }
    }
    AnchorAggregate {
        total_anchors: anchors.len() as u64,
        headline_eligible_count,
        headline_time_unix,
    }
}

#[cfg(test)]
mod tests {
    use super::super::report::AnchorKind;
    use super::*;

    fn slot(state: AnchorState, verified_time_unix: Option<i64>) -> AnchorResult {
        AnchorResult {
            kind: AnchorKind::Tsa,
            state,
            verified_time_unix,
            source: None,
            fetch_date: None,
        }
    }

    #[test]
    fn empty_anchor_set_is_unanchored_with_no_headline_time() {
        let aggregate = aggregate_anchors(&[]);
        assert!(aggregate.is_unanchored());
        assert_eq!(aggregate.total_anchors(), 0);
        assert_eq!(aggregate.headline_eligible_count(), 0);
        assert_eq!(aggregate.headline_time_unix(), None);
    }

    /// The predicate is pinned over every state: exactly the spec's two
    /// `[H]` states are eligible. `AnchorState::ALL` makes the sweep
    /// exhaustive; the wildcard-free match in `headline_eligible` makes
    /// an eighth state a compile error before it is a wrong answer.
    #[test]
    fn exactly_the_two_spec_h_states_are_headline_eligible() {
        for state in AnchorState::ALL {
            let expected = matches!(
                state,
                AnchorState::Proven | AnchorState::ValidAtStampingCertSinceExpired
            );
            assert_eq!(headline_eligible(state), expected, "{state:?}");
        }
    }

    /// The teeth: even if every ineligible slot carries a (bogus)
    /// verified time, no headline time and no eligibility come out —
    /// there is no code path from an all-ineligible set to a headline.
    #[test]
    fn ineligible_slots_never_contribute_time_or_eligibility() {
        let hostile: Vec<AnchorResult> = [
            AnchorState::Attested,
            AnchorState::Pending,
            AnchorState::InternallyConsistentOnly,
            AnchorState::Invalid,
            AnchorState::Absent,
        ]
        .into_iter()
        .map(|state| slot(state, Some(1_234_567_890)))
        .collect();
        let aggregate = aggregate_anchors(&hostile);
        assert!(aggregate.is_unanchored());
        assert_eq!(aggregate.headline_eligible_count(), 0);
        assert_eq!(
            aggregate.headline_time_unix(),
            None,
            "bogus times ignored by construction"
        );
        assert_eq!(aggregate.total_anchors(), 5);
    }

    #[test]
    fn earliest_eligible_time_wins_and_mixed_sets_are_anchored() {
        let anchors = vec![
            slot(AnchorState::Absent, Some(1)), // ineligible: ignored entirely
            slot(AnchorState::Proven, Some(500)),
            slot(AnchorState::ValidAtStampingCertSinceExpired, Some(300)),
            slot(AnchorState::Proven, None), // eligible, timeless: counts, no time
        ];
        let aggregate = aggregate_anchors(&anchors);
        assert!(!aggregate.is_unanchored());
        assert_eq!(aggregate.headline_eligible_count(), 3);
        assert_eq!(aggregate.headline_time_unix(), Some(300));
    }
}
