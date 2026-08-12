//! The **verdict-rung classifier** (task R21; D69 §3 R4) — the verdict-class
//! datum U30's exit-code mapping reads, and the only place the anchor set is
//! folded into one severity-ordered answer.
//!
//! D69 overturned the framing that `antseal verify` has a scalar verdict to
//! map: the `Ok` arm of [`verify_bundle`] carries a `Vec<AnchorResult>` in
//! which each slot independently holds one of seven states. What exists
//! instead is a **fold**, and this module is it:
//!
//! ```text
//! rung = the highest-ranked rung whose predicate holds over the whole set
//! rank:  verify-anchor-refuted > verify-headline-divergence > verify-unanchored
//! none holds → no rung (the clean verdict)
//! ```
//!
//! # Two folds, deliberately kept apart (D69 §3 R4)
//!
//! [`VerdictAggregate`] carries no state field and matches on
//! [`AnchorState`] **nowhere** — R17's one-predicate rule, which is what
//! keeps a single eligibility table in the product. So it can answer *"is
//! there a proven time?"* and cannot answer *"was anything refuted?"*: a
//! bundle with one `invalid` anchor and a bundle with one `pending` anchor
//! produce identical aggregates.
//!
//! Counting refutations is therefore a **second pass**, and D69 rules it must
//! stay one rather than become a field on the aggregate — *"a field would be
//! an R17 API change for a CLI concern, and D64 §6 already refused the
//! analogous move on the report"*. [`RefutedCount`] is that pass's result and
//! an **input** to [`verdict_exit_rung`], never a member of the aggregate.
//!
//! # One predicate, two adapters
//!
//! Both callers that can count refutations — the orchestration (which holds
//! [`AnchorVerdicts`]) and any host that holds only a report — route through
//! the one wildcard-free [`is_refutation`]. There is no second table here
//! either.
//!
//! # Core, not the CLI, and no integers
//!
//! D69 §3 R4 sites the classifier in `antseal-core` *"because **R22's page
//! must be able to state the same rung** — the parity gate (R27 (b),
//! CLI/page string-equality) is worthless if the two surfaces classify from
//! different code"*.
//!
//! The **exit codes are not here**. `ErrorClass` and its committed code table
//! are U2's (D69 §3 R1: *"exactly **one** code table in the product"*), so
//! this module exposes each rung's **stable kebab name** and U30 maps the
//! name onto the integer. A second numeric table in core is exactly the
//! disagreement D69 §3 R7 prevents by construction.
//!
//! Pure, WASM-safe and deterministic: no clock, no I/O, no map iteration.
//!
//! [`verify_bundle`]: super::pipeline::verify_bundle

use crate::anchor::verdicts::AnchorVerdicts;
use crate::verify::report::{AnchorResult, AnchorState};
use crate::verify::verdict::VerdictAggregate;

/// Whether `state` is a **refutation** — D69 §3 R2 rung 1's predicate
/// (*"≥1 anchor slot is [`AnchorState::Invalid`]"*; MVP-SPEC.md line 134,
/// *"`invalid` — signature/op check fails"*).
///
/// Wildcard-free, so an eighth state forces a decision here rather than
/// silently joining the non-refutation majority. This is the module's **one**
/// state match: everything else folds counts.
///
/// The four ineligible non-`Invalid` states get no rung of their own by D69
/// §3 R2 — each already contributes to the UNANCHORED rung when it is all a
/// bundle has, and none is a refutation, so none may outrank one.
#[must_use]
pub const fn is_refutation(state: AnchorState) -> bool {
    match state {
        AnchorState::Invalid => true,
        AnchorState::Proven
        | AnchorState::ValidAtStampingCertSinceExpired
        | AnchorState::Attested
        | AnchorState::Pending
        | AnchorState::InternallyConsistentOnly
        | AnchorState::Absent => false,
    }
}

/// How many anchor slots are refuted — the second fold D69 §3 R4 requires,
/// as a value that cannot be confused with any other count.
///
/// A newtype rather than a bare `u64` because [`verdict_exit_rung`]'s other
/// parameter is an aggregate full of counts, and *"the refuted count"* and
/// *"the eligible count"* are one transposition apart at a call site.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct RefutedCount(u64);

impl RefutedCount {
    /// Nothing was refuted.
    pub const ZERO: Self = Self(0);

    /// The count itself.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Whether at least one slot is refuted — rung 1's existential.
    #[must_use]
    pub const fn any(self) -> bool {
        self.0 > 0
    }
}

/// Count refutations over any sequence of states — the one place the count is
/// computed, so the two adapters below cannot disagree.
#[must_use]
pub fn count_refuted<I>(states: I) -> RefutedCount
where
    I: IntoIterator<Item = AnchorState>,
{
    let mut count: u64 = 0;
    for state in states {
        if is_refutation(state) {
            count = count.saturating_add(1);
        }
    }
    RefutedCount(count)
}

/// The second pass over an evaluation's verdicts — D69 §3 R4's own phrasing
/// (*"counting `Invalid` slots is a second pass over `AnchorVerdicts`"*).
///
/// Under `--online` this is called over the **online-augmented** verdicts, so
/// an agreed refutation (D56 rules O6/O7 → `invalid`) reaches the rung; D69
/// §3 R5's second row is exactly that transition.
#[must_use]
pub fn refuted_in_verdicts(verdicts: &AnchorVerdicts) -> RefutedCount {
    count_refuted(
        verdicts
            .outcomes()
            .iter()
            .map(|outcome| outcome.verdict().state()),
    )
}

/// The same count over a report's projected slots — what a host holding only
/// a [`VerificationReport`] can compute.
///
/// Equal to [`refuted_in_verdicts`] over the verdicts that produced the
/// report: [`AnchorVerdicts::project_anchor_results`] drops only kind-level
/// `absent` verdicts, and `absent` is not a refutation.
///
/// [`VerificationReport`]: super::report::VerificationReport
/// [`AnchorVerdicts::project_anchor_results`]:
///     crate::anchor::verdicts::AnchorVerdicts::project_anchor_results
#[must_use]
pub fn refuted_in_report_slots(anchors: &[AnchorResult]) -> RefutedCount {
    count_refuted(anchors.iter().map(|anchor| anchor.state))
}

/// One rung of D69's severity ladder.
///
/// **Declaration order is ascending severity**, and that is the reason this
/// enum derives `Ord` — the same reason `FileStatus` does in
/// `antseal-cli`'s `restore_out` (D48 §6), so [`verdict_exit_rung`] can be
/// `filter(...).max()` exactly as `FileStatus::most_severe()` is.
///
/// The **numeric codes run the other way** (`verify-anchor-refuted` is 41 and
/// `verify-unanchored` is 43), which is why the rank is an explicit `Ord` and
/// never a comparison of exit codes — U2's own note on why restore's
/// verification class can live at 35 without disturbing the 40–49 band.
///
/// `verify-bundle-rejected` (40) is **not** a rung: it is the `Err` arm of
/// [`verify_bundle`], where no report and no aggregate exist (D69 §3 R2's
/// `‡` row), so it has nothing to fold and no representation here.
///
/// [`verify_bundle`]: super::pipeline::verify_bundle
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum VerdictExitRung {
    /// Zero headline-eligible anchors — MVP-SPEC.md line 137's UNANCHORED
    /// outcome. An **absence**, so it ranks below both established facts.
    Unanchored,
    /// Headline-eligible anchors disagree by strictly more than 48 h
    /// (MVP-SPEC.md line 137): two proofs contradict each other.
    HeadlineDivergence,
    /// At least one anchor slot is refuted: something is forged. The worst
    /// established fact, so it wins the fold.
    AnchorRefuted,
}

impl VerdictExitRung {
    /// Every rung, **in ascending severity** — the declaration order, so a
    /// sweep and the `Ord` derive cannot disagree.
    pub const ALL: [Self; 3] = [
        Self::Unanchored,
        Self::HeadlineDivergence,
        Self::AnchorRefuted,
    ];

    /// This rung's stable class name (D69 §3 R8, kebab-case, U2's
    /// convention). Wildcard-free, so a fourth rung cannot land unnamed.
    ///
    /// The `verify-` stem is reserved against the verifier's *rejection-code*
    /// namespace by D69 §3 R8 — the two namespaces are ruled disjoint by
    /// `docs/testing/error-code-contract.md` §2, and this name belongs to the
    /// exit-class one.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Unanchored => "verify-unanchored",
            Self::HeadlineDivergence => "verify-headline-divergence",
            Self::AnchorRefuted => "verify-anchor-refuted",
        }
    }
}

/// Fold one evaluation into its rung — D69 §3 R3's rule, as a rule.
///
/// > *the code of the highest-ranked rung whose predicate holds over the
/// > whole anchor set; `None` when none does.*
///
/// Written as filter-then-`max` rather than as an `if`/`else` chain so the
/// ladder is the `Ord` derive rather than a hand-ordered cascade a later edit
/// could reorder without reddening anything.
///
/// `aggregate` is the aggregate of **the strongest computation the run
/// performed** (D69 §3 R5): the offline one for a plain run, the
/// online-augmented one under `--online`. `refuted` must come from the same
/// computation. The orchestration pairs them; nothing here can detect a
/// mismatched pair, which is why the pairing is stated rather than assumed
/// (`build_online_overlay`'s precedent).
///
/// Two properties worth stating because they make the rule cheap to reason
/// about (D69 §3 R3):
///
/// - **Rungs 2 and 3 are mutually exclusive by construction.** A divergence
///   needs two timed eligible anchors, so `divergence.is_some()` implies
///   `eligible_count >= 2` implies not-unanchored. The ladder only ever
///   arbitrates 1-vs-2 and 1-vs-3.
/// - **`{proven, invalid}` resolves without a special case**: rung 1 holds,
///   rung 3 does not — not because a list says so, but because the fold does.
///
/// `--live` and the storage-linkage layer contribute **nothing**: neither is
/// a parameter here, so D69 §3 R6's rule (*"storage is the product's bonus,
/// not its proof"*, MVP-SPEC.md line 118) is an absence at the type level
/// rather than a check.
#[must_use]
pub fn verdict_exit_rung(
    aggregate: &VerdictAggregate,
    refuted: RefutedCount,
) -> Option<VerdictExitRung> {
    VerdictExitRung::ALL
        .into_iter()
        .filter(|rung| match rung {
            VerdictExitRung::Unanchored => aggregate.is_unanchored(),
            VerdictExitRung::HeadlineDivergence => aggregate.divergence().is_some(),
            VerdictExitRung::AnchorRefuted => refuted.any(),
        })
        .max()
}

#[cfg(test)]
mod tests;
