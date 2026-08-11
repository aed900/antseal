//! The full offline verdict aggregate (**task R17**; D64 §6.1) — headline,
//! eligibility, divergence, the UNANCHORED outcome, and the receipt's
//! separate supporting-evidence class, computed from [`AnchorVerdicts`].
//!
//! MVP-SPEC.md lines 127–137 define the verdict taxonomy this aggregates;
//! line 108 defines the `--online` promotion that must **never** reach this
//! computation directly — promotion feeds only the overlay
//! ([`super::overlay`]), and R21's orchestration hands this module the
//! verdicts of an evaluation whose [`OnlineEvidence`] was empty. Nothing here
//! can tell the difference, and nothing here needs to: the same function over
//! the online-augmented verdicts **is** the overlay's second aggregation
//! (D64 §3 — "same eligibility map, same earliest-wins, same divergence rule,
//! same UNANCHORED predicate — one predicate").
//!
//! # One eligibility predicate
//!
//! Eligibility is [`headline_eligible`](super::aggregate::headline_eligible)
//! — A1's single predicate, reached
//! through [`AnchorVerdict::is_headline_eligible`]. This module adds **no**
//! second table and contains **no** match on
//! [`AnchorState`](crate::verify::report::AnchorState) at all (U23's "there
//! is no second eligibility table here", made a ruling by D64 §6.1); the
//! wildcard-free match that makes an eighth state a compile error lives on
//! the predicate itself.
//!
//! # The claimed time is excluded at the type level
//!
//! MVP-SPEC.md line 137 renders the sealer's claimed time subordinate and
//! never headline-eligible. Here that is not a filter but an absence: the
//! headline computation's input is anchor verdicts —
//! [`AnchorVerdict`] values and the receipt's [`ReceiptEvidence`] — and **no
//! type in that input set has a field that could carry the claimed time**.
//! It lives in exactly one place,
//! [`WorkMetadata::claimed_time_informational_only`], a type this module
//! never receives; there is no parameter to smuggle it through and no code
//! to delete to let it in. The same shape excludes the Arbitrum receipt from
//! the anchor set: [`ReceiptEvidence`] has no state, no time field, and no
//! conversion to an anchor, so it arrives in [`VerdictAggregate::receipt`]'s
//! wholly separate class or not at all (MVP-SPEC.md line 110; A19).
//!
//! # WASM-safe and deterministic
//!
//! Pure data folding: no clock, no I/O, no randomness, no map iteration.
//! Equal inputs produce equal aggregates on every target.
//!
//! [`OnlineEvidence`]: crate::anchor::model::OnlineEvidence
//! [`WorkMetadata::claimed_time_informational_only`]:
//!     crate::verify::report::WorkMetadata::claimed_time_informational_only

use serde::Serialize;

use crate::anchor::model::AnchorVerdict;
use crate::anchor::verdicts::{AnchorVerdicts, ReceiptEvidence};
use crate::verify::report::AnchorKind;

/// The >48 h headline-divergence threshold, in seconds (MVP-SPEC.md
/// line 137: "divergence flag when headline-eligible anchors disagree by
/// >48 h").
///
/// **The comparison is strictly greater-than, and the boundary is frozen
/// here**: a spread of exactly 48 h 00 m 00 s (172 800 s) is *not* flagged;
/// 172 801 s is. The spec's own token is ">48 h", and R17's Accept pins the
/// two sides (47 h 59 m no flag, 48 h 01 m flagged);
/// `tests::the_divergence_boundary_is_strictly_greater_than_48_hours` pins
/// the exact second so an `>=` cannot land silently.
pub const HEADLINE_DIVERGENCE_THRESHOLD_SECS: i64 = 48 * 60 * 60;

/// The one headline datum: the earliest headline-eligible anchor's verified
/// time, kind, and source (MVP-SPEC.md line 137's "Existed no later than
/// \<time\> (source)" — this is the datum; the sentence is
/// [`super::wording::headline_sentence`]'s, and its spelling is R18's).
///
/// Equality is over the **whole datum** — time, kind, and source — never
/// time alone. D64 §9 records why that matters: the overlay's Stands/Supplies
/// classifier compares headlines, and a time-only comparison would render
/// "stands" while the source parenthesis silently changed.
///
/// Fields are private and there is no public constructor: a `Headline` exists
/// only as the output of [`VerdictAggregate`]'s fold over anchor verdicts, so
/// a claimed time — or any other non-anchor datum — cannot be smuggled into
/// one (module docs).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Headline {
    time_unix: i64,
    kind: AnchorKind,
    source: Option<String>,
}

impl Headline {
    /// The independently verified time, Unix seconds UTC.
    #[must_use]
    pub const fn time_unix(&self) -> i64 {
        self.time_unix
    }

    /// Which anchoring mechanism carries the headline.
    #[must_use]
    pub const fn kind(&self) -> AnchorKind {
        self.kind
    }

    /// The winning anchor's source identity, when it recorded one.
    #[must_use]
    pub fn source(&self) -> Option<&str> {
        self.source.as_deref()
    }

    /// A test-only constructor for sibling test modules (`wording`,
    /// `overlay`) — production headlines exist only as aggregate output.
    #[cfg(test)]
    pub(crate) fn fixture(time_unix: i64, kind: AnchorKind, source: Option<&str>) -> Self {
        Self {
            time_unix,
            kind,
            source: source.map(str::to_owned),
        }
    }
}

/// The measured spread behind a flagged >48 h divergence — carried so R18's
/// flag text can name the two times without recomputing them.
///
/// Exists **only when flagged**: "not flagged" needs no payload, and with
/// fewer than two timed eligible anchors there is nothing to disagree — the
/// vacuous case is genuinely "no divergence", not "not computed" (contrast
/// A39, where the two must stay apart).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct HeadlineDivergence {
    earliest_unix: i64,
    latest_unix: i64,
}

impl HeadlineDivergence {
    /// The earliest verified time among headline-eligible anchors.
    #[must_use]
    pub const fn earliest_unix(&self) -> i64 {
        self.earliest_unix
    }

    /// The latest verified time among headline-eligible anchors.
    #[must_use]
    pub const fn latest_unix(&self) -> i64 {
        self.latest_unix
    }
}

/// The R17 verdict aggregate (D64 §6.1): headline by earliest-wins over the
/// eligible set, eligible count, the >48 h divergence outcome, the UNANCHORED
/// predicate, and the receipt's separate class.
///
/// Constructed only by [`Self::from_verdicts`] /
/// [`Self::from_parts`], so the headline, the counts and the flag can never
/// disagree with each other. Not serialized into any wire or report byte:
/// like A1's [`AnchorAggregate`](super::aggregate::AnchorAggregate) it is
/// derived data the hosts compute — report v1 is frozen, and D64 §6 rules an
/// aggregate field on [`VerificationReport`](super::report::VerificationReport)
/// a refused FORMAT EVENT.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerdictAggregate {
    total_anchors: u64,
    eligible_count: u64,
    headline: Option<Headline>,
    divergence: Option<HeadlineDivergence>,
    receipt: Option<ReceiptEvidence>,
}

impl VerdictAggregate {
    /// Aggregate one bundle's evaluation — the production entry (R21 hands
    /// it `evaluate_anchors`' output; the overlay computation calls it twice,
    /// once per evidence regime).
    #[must_use]
    pub fn from_verdicts(verdicts: &AnchorVerdicts) -> Self {
        Self::from_parts(
            verdicts.outcomes().iter().map(|outcome| outcome.verdict()),
            verdicts.receipt().copied(),
        )
    }

    /// Aggregate from raw parts — the same fold over a plain verdict
    /// sequence, for fixtures that need arbitrary states and times without
    /// minting artifacts ([`AnchorArtifacts::from_parts`]'s precedent).
    ///
    /// The sequence order **is** the tie-break order: pass verdicts in
    /// report order (OTS artifacts first, then TSA, each in wire order),
    /// which is what [`Self::from_verdicts`] does by construction.
    ///
    /// # Earliest-wins, and the frozen tie-break
    ///
    /// The headline is the eligible anchor with the strictly smallest
    /// verified time; on an exact tie **the first slot in report order
    /// wins**. Frozen here because two eligible anchors can share a second
    /// while their sources differ, and the winner's *whole datum* is what
    /// the overlay's impact classifier compares (D64 §9). First-in-order is
    /// also what the CLI's `status` headline already does (`min_by_key`
    /// keeps the first minimum), so the two surfaces cannot disagree on a
    /// tie.
    ///
    /// An eligible verdict without a verified time contributes eligibility
    /// and no headline candidate — unreachable through
    /// [`AnchorVerdict`]'s constructors, which give exactly the two `[H]`
    /// states a time (A2; asserted in both directions by
    /// `anchor::model::tests::no_ineligible_state_carries_a_verified_time`) —
    /// kept total rather than assumed, the same stance A1's
    /// [`aggregate_anchors`](super::aggregate::aggregate_anchors) takes.
    ///
    /// [`AnchorArtifacts::from_parts`]:
    ///     crate::anchor::model::AnchorArtifacts::from_parts
    #[must_use]
    pub fn from_parts<'a, I>(verdicts: I, receipt: Option<ReceiptEvidence>) -> Self
    where
        I: IntoIterator<Item = &'a AnchorVerdict>,
    {
        let mut total_anchors = 0u64;
        let mut eligible_count = 0u64;
        let mut headline: Option<Headline> = None;
        let mut earliest: Option<i64> = None;
        let mut latest: Option<i64> = None;

        for verdict in verdicts {
            total_anchors += 1;
            // The ONE predicate (A1's), through the verdict's own delegate —
            // no state match here, so an eighth state breaks compilation at
            // `headline_eligible` and nowhere else.
            if !verdict.is_headline_eligible() {
                continue;
            }
            eligible_count += 1;
            let Some(time) = verdict.verified_time_unix() else {
                continue;
            };
            // Strict `<`: the first slot in report order keeps a tie.
            if headline.as_ref().is_none_or(|best| time < best.time_unix) {
                headline = Some(Headline {
                    time_unix: time,
                    kind: verdict.kind(),
                    source: verdict.source().map(|s| s.identity().to_owned()),
                });
            }
            earliest = Some(earliest.map_or(time, |e: i64| e.min(time)));
            latest = Some(latest.map_or(time, |l: i64| l.max(time)));
        }

        // Strictly greater than the threshold (const docs freeze the exact-
        // 48 h case as unflagged). `i128` so hostile extremes — an
        // `AnchorVerdict` constructor accepts any `i64` — cannot overflow
        // the subtraction.
        let divergence = match (earliest, latest) {
            (Some(earliest_unix), Some(latest_unix))
                if i128::from(latest_unix) - i128::from(earliest_unix)
                    > i128::from(HEADLINE_DIVERGENCE_THRESHOLD_SECS) =>
            {
                Some(HeadlineDivergence {
                    earliest_unix,
                    latest_unix,
                })
            }
            _ => None,
        };

        Self {
            total_anchors,
            eligible_count,
            headline,
            divergence,
            receipt,
        }
    }

    /// Number of anchor verdict slots aggregated (eligible or not; `absent`
    /// kind-level verdicts are not slots and never arrive here).
    #[must_use]
    pub const fn total_anchors(&self) -> u64 {
        self.total_anchors
    }

    /// Number of headline-eligible slots — the spec's `[H]` count.
    #[must_use]
    pub const fn eligible_count(&self) -> u64 {
        self.eligible_count
    }

    /// The one headline (MVP-SPEC.md line 137): earliest-wins over the
    /// eligible set; `None` exactly when [`Self::is_unanchored`].
    #[must_use]
    pub const fn headline(&self) -> Option<&Headline> {
        self.headline.as_ref()
    }

    /// The spec's UNANCHORED outcome: **zero headline-eligible anchors**
    /// (MVP-SPEC.md line 137) — the same predicate A1's
    /// [`AnchorAggregate::is_unanchored`] computes, restated over this
    /// aggregate's own count so the two can never diverge on one input.
    ///
    /// This is the *verdict* sense of the word (D98 rider 3c): not the
    /// `--no-anchor` shaping flag, not "no anchor records at all", and not
    /// the registry's "both anchor arrays empty" shape fact — a bundle
    /// carrying one `pending` OTS is UNANCHORED here with artifacts present.
    ///
    /// [`AnchorAggregate::is_unanchored`]:
    ///     super::aggregate::AnchorAggregate::is_unanchored
    #[must_use]
    pub const fn is_unanchored(&self) -> bool {
        self.eligible_count == 0
    }

    /// The flagged >48 h divergence, when headline-eligible anchors disagree
    /// by more than [`HEADLINE_DIVERGENCE_THRESHOLD_SECS`].
    #[must_use]
    pub const fn divergence(&self) -> Option<&HeadlineDivergence> {
        self.divergence.as_ref()
    }

    /// The Arbitrum receipt's wholly separate supporting-evidence datum —
    /// never an anchor, never eligible, never in the anchor fold above
    /// (MVP-SPEC.md line 110; A19: [`ReceiptEvidence`] has no state and no
    /// time field to read).
    #[must_use]
    pub const fn receipt(&self) -> Option<&ReceiptEvidence> {
        self.receipt.as_ref()
    }
}

#[cfg(test)]
mod tests;
