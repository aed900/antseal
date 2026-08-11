//! The `--online` advisory overlay (**task R17**; D64 §§3–6) — the typed
//! probe-outcome input, the overlay computation, and the sibling document it
//! produces.
//!
//! D64 rules the layout this module computes for: **two stacked blocks**, the
//! offline verdict first and byte-identical to a run without `--online`, the
//! overlay appended below as *"a full second aggregation … rendered as an
//! impact against the offline verdict"* (D64 §§2–3). MVP-SPEC.md line 137 is
//! the spec anchor: the overlay is *"an advisory overlay distinct from the
//! offline cryptographic verdict"*, and for a bundle with no offline-eligible
//! anchor `--online` *"then supplies the headline"*.
//!
//! # Two computations, one run (D64 §6)
//!
//! R21's orchestration calls [`evaluate_anchors`] twice — once with empty
//! [`OnlineEvidence`] (the offline verdicts), once with the agreed evidence
//! (the online-augmented verdicts) — and hands both, plus the [`ProbeLog`],
//! to [`build_online_overlay`]. The builder derives **both aggregates
//! itself** from the two verdict sets, so an aggregate/verdict pair that
//! disagrees is unrepresentable at this boundary; the offline aggregate R21
//! renders the offline block from is the same
//! [`VerdictAggregate::from_verdicts`] value, computed over the same offline
//! verdicts, and nothing in this module mutates or re-runs the offline
//! computation. **Promotion feeds only the overlay** (R17's Accept): the
//! offline verdicts never see block evidence, and this module receives them
//! only to compare against.
//!
//! # The sibling document (D64 §6; D105)
//!
//! [`OnlineOverlay`] is a **sibling document beside report v1, never a report
//! field** — an `overlay` field on
//! [`VerificationReport`](super::report::VerificationReport) is a FORMAT
//! EVENT (D105 §2.4) and was refused; `REPORT_VERSION` stays `1` and the
//! online computation's states never serialize into report v1 at all. The
//! overlay serializes deterministically under D29's discipline *by
//! construction* — compact JSON, declaration order, no conditional keys, no
//! maps — but is **not** governed by D29's report freeze: it rides U30's
//! `--json` envelope beside the verbatim report bytes (envelope schema
//! stability is D65's) and is the return value of R22's overlay entry for the
//! page.
//!
//! # The probe input is rendering input, never verdict input (D64 §6.3)
//!
//! [`ProbeLog`] carries what D56 §3 keeps out of the verdict path: per-height
//! agreed / disagreed / failed-per-endpoint / not-attempted, the receipt
//! probe outcome, and the endpoint identities with the overridden flag. It is
//! data-only and constructible from literals — the CLI populates it from
//! `antseal-anchor`'s A16/A17 typed outcomes, the page from its own `fetch()`
//! outcomes through R22 — and [`evaluate_anchors`]'s signature and the
//! no-failure-variant rule on
//! [`OnlineBlockResult`](crate::anchor::model::OnlineBlockResult) are
//! untouched. Without this type the page's disagreement and fetch-failure
//! lines would be page-authored wording — exactly the R61 asymmetry class.
//!
//! # Final display strings embedded
//!
//! Every line in the output is drawn from [`super::wording`] (the R74/R22
//! pattern; renderers do layout only), with D64 §8's structure frozen and
//! every spelling provisional until **R18**.
//!
//! [`evaluate_anchors`]: crate::anchor::verdicts::evaluate_anchors
//! [`OnlineEvidence`]: crate::anchor::model::OnlineEvidence

use std::collections::BTreeMap;

use serde::Serialize;

use crate::anchor::model::{AnchorArtifacts, ReceiptConfirmation};
use crate::anchor::verdicts::{AnchorOutcome, AnchorVerdicts};
use crate::verify::report::{AnchorKind, AnchorState};

use super::verdict::{Headline, VerdictAggregate};
use super::wording;

// ---------------------------------------------------------------------------
// the probe-outcome input (D64 §6.3)
// ---------------------------------------------------------------------------

/// The class of one endpoint's probe failure — the WASM-safe projection of
/// `antseal-anchor`'s `EndpointFailure` taxonomy (transport / payload /
/// wrong-chain), which lives in a non-WASM crate this one must never depend
/// on.
///
/// Classes only, no free-form detail: an adversary-controlled endpoint must
/// not get a byte channel into a display line (the same rule `agree.rs`
/// applies to its `Payload.reason`), and the wording for each class is
/// core's ([`wording::probe_failure_class_label`]), never the host's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProbeFailureClass {
    /// The request itself failed: transport, timeout, non-2xx, over-cap.
    Transport,
    /// A reply arrived and its body was not usable.
    Payload,
    /// The endpoint answered, correctly, about a different chain (A17's
    /// `eth_chainId` guard; D55 §3).
    WrongChain,
}

impl ProbeFailureClass {
    /// Every class, in declaration order — the sweep operand for the L2-style
    /// wording test (module docs, R-VAL's pattern).
    pub const ALL: [Self; 3] = [Self::Transport, Self::Payload, Self::WrongChain];
}

/// One endpoint's probe failure: which endpoint, and which class.
///
/// Public fields on purpose — this is leaf input data, constructible from
/// literals ([`crate::anchor::model::ReceiptFacts`]'s precedent).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EndpointProbeFailure {
    /// The endpoint's identity (its configured URL).
    pub endpoint: String,
    /// What went wrong, as a closed class.
    pub class: ProbeFailureClass,
}

/// What happened when the host probed one block height against its
/// must-agree endpoint pair (D64 §6.3's per-height classes).
///
/// Only [`BlockProbe::Agreed`] may be accompanied by an entry in the
/// [`OnlineEvidence`](crate::anchor::model::OnlineEvidence) handed to the
/// online-augmented evaluation — that pairing is R21/R22's obligation, and
/// the overlay treats the **online-augmented state as authoritative**: an
/// `Agreed` entry whose evidence evidently never reached the evaluator
/// renders as no-evidence, because for the verdict path that is what it was
/// (D56 §3's absence rule).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockProbe {
    /// Both endpoints agreed; the agreed result was handed to the
    /// online-augmented evaluation as [`OnlineBlockResult`] evidence.
    ///
    /// Carries no payload deliberately: the agreed value lives in the
    /// evidence path, and a second copy here could disagree with it.
    ///
    /// [`OnlineBlockResult`]: crate::anchor::model::OnlineBlockResult
    Agreed,
    /// The endpoints answered differently — no promotion for anchors at this
    /// height, offline state stands (D56 §3; D64 §5).
    Disagreed,
    /// The probe failed, per endpoint.
    Failed(Vec<EndpointProbeFailure>),
    /// The host deliberately did not probe this height. Equivalent to the
    /// entry's absence; both render as no-evidence.
    NotAttempted,
}

/// What happened when the host probed the receipt's transaction against its
/// must-agree Arbitrum RPC pair (A17/D55).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiptProbe {
    /// Both endpoints agreed — on the facts, or on absence from the chain.
    Agreed(ReceiptConfirmation),
    /// The endpoints answered differently.
    Disagreed,
    /// The probe failed, per endpoint.
    Failed(Vec<EndpointProbeFailure>),
    /// No receipt probe was attempted (also the default).
    NotAttempted,
}

/// The endpoint identities a probe run used, and whether they departed from
/// the pinned defaults (MVP-SPEC.md line 137: "two pinned default endpoints
/// per source … user-overridable").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeEndpoints {
    identities: Vec<String>,
    overridden: bool,
}

impl ProbeEndpoints {
    /// Every endpoint the run consulted, in disclosure order, and whether
    /// any departed from the pinned defaults.
    #[must_use]
    pub const fn new(identities: Vec<String>, overridden: bool) -> Self {
        Self {
            identities,
            overridden,
        }
    }

    /// The endpoint identities, in disclosure order.
    #[must_use]
    pub fn identities(&self) -> &[String] {
        &self.identities
    }

    /// `true` iff the run departed from the pinned defaults.
    #[must_use]
    pub const fn overridden(&self) -> bool {
        self.overridden
    }
}

/// Everything a host's probe run observed, as **rendering input** — never
/// verdict input (module docs; D64 §6.3).
///
/// `BTreeMap` for the reason the report and [`BlockEvidence`] give:
/// iteration order must not vary between runs or targets.
///
/// [`BlockEvidence`]: crate::anchor::model::BlockEvidence
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeLog {
    blocks: BTreeMap<u64, BlockProbe>,
    receipt: ReceiptProbe,
    endpoints: ProbeEndpoints,
}

impl ProbeLog {
    /// A probe log that attempted nothing, over the given endpoints.
    #[must_use]
    pub const fn new(endpoints: ProbeEndpoints) -> Self {
        Self {
            blocks: BTreeMap::new(),
            receipt: ReceiptProbe::NotAttempted,
            endpoints,
        }
    }

    /// Record what happened at one height (mirrors
    /// [`OnlineEvidence::with_block`]'s builder shape).
    ///
    /// [`OnlineEvidence::with_block`]:
    ///     crate::anchor::model::OnlineEvidence::with_block
    #[must_use]
    pub fn with_block(mut self, height: u64, probe: BlockProbe) -> Self {
        self.blocks.insert(height, probe);
        self
    }

    /// Record the receipt probe's outcome.
    #[must_use]
    pub fn with_receipt(mut self, probe: ReceiptProbe) -> Self {
        self.receipt = probe;
        self
    }

    /// The probe outcome for `height`, if the host recorded one.
    #[must_use]
    pub fn block(&self, height: u64) -> Option<&BlockProbe> {
        self.blocks.get(&height)
    }

    /// The receipt probe's outcome.
    #[must_use]
    pub const fn receipt(&self) -> &ReceiptProbe {
        &self.receipt
    }

    /// The endpoints this run used.
    #[must_use]
    pub const fn endpoints(&self) -> &ProbeEndpoints {
        &self.endpoints
    }
}

// ---------------------------------------------------------------------------
// the overlay document (D64 §3's fixed structure, §6.2's closed classes)
// ---------------------------------------------------------------------------

/// The three-way headline-impact class (D64 §3.1) — exactly one renders,
/// always.
///
/// The Stands/Supplies boundary compares the **whole headline datum** —
/// [`Headline`]'s equality is over time, kind and source — never time alone:
/// two eligible anchors can share a second while their sources differ, and a
/// time-only comparison would render "stands" while the parenthesis silently
/// changed (D64 §9's recorded risk; the tie-break itself is
/// [`VerdictAggregate::from_parts`]'s).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum HeadlineImpact {
    /// The online computation's headline differs from the offline one — a
    /// promoted anchor is now earliest, or the offline block was UNANCHORED
    /// and the online set has an eligible anchor. Carries the full headline
    /// datum; its line is the one spec template with the mandatory
    /// online-attribution marker (MVP-SPEC.md line 137's *"supplies the
    /// headline"*).
    Supplies {
        /// The online-augmented computation's headline.
        headline: Headline,
    },
    /// The online computation's headline equals the offline one — the
    /// routine case (a TSA `genTime` precedes the confirming block's
    /// `nTime`). The line points at the offline headline and does **not**
    /// restate the sentence (Q89 via D64 §3).
    Stands,
    /// The online set still has zero eligible anchors (probe failed /
    /// disagreed / refuted-only).
    StillUnanchored,
}

impl HeadlineImpact {
    /// Classify the online-augmented aggregate against the offline one —
    /// pure over the two aggregates, exposed so the boundary cases are
    /// testable without artifacts.
    #[must_use]
    pub fn classify(offline: &VerdictAggregate, online: &VerdictAggregate) -> Self {
        match online.headline() {
            None => Self::StillUnanchored,
            Some(headline) if offline.headline() == Some(headline) => Self::Stands,
            Some(headline) => Self::Supplies {
                headline: headline.clone(),
            },
        }
    }

    /// This class's stable token — D64 §6.2's names, wildcard-free so a new
    /// class cannot land unnamed (the L2 discipline; the wording sweep in
    /// `tests` is the second stop).
    #[must_use]
    pub const fn token(&self) -> &'static str {
        match self {
            Self::Supplies { .. } => "supplies",
            Self::Stands => "stands",
            Self::StillUnanchored => "still-unanchored",
        }
    }
}

/// Why a probed anchor was **not** promoted (D64 §6.2's reason set, plus the
/// measured fourth case the machinery can produce).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum NotPromotedReason {
    /// The endpoint pair disagreed about this height — promotion suppressed
    /// for this anchor alone, offline state stands (D56 §3; D64 §5).
    Disagreed,
    /// The probe failed, per endpoint (R24's "per-endpoint fetch-failure
    /// states").
    EndpointFailures {
        /// What failed, endpoint by endpoint.
        failures: Vec<EndpointProbeFailure>,
    },
    /// No agreed online evidence reached the verdict path for this height —
    /// not attempted, or nothing usable arrived.
    NoEvidence,
    /// Agreed evidence **refutes** the embedded header, but a pending branch
    /// out-votes the refutation (D56 §4's best-evidence-wins as amended by
    /// D93 §5): the online-augmented state is `pending`, the refutation is
    /// carried as an A39 suppressed anomaly, and `code` is that anomaly's.
    ///
    /// Not one of D64 §6.2's three spelled reasons — recorded as R17's
    /// measured extension, because the machinery reaches it
    /// (`anchor/verdicts.rs`'s O5-over-O6/O7 precedence) and D64's L2 rule
    /// demands every reachable outcome be a renderable class rather than a
    /// mis-filed one: `Refuted` would lie about the state (it did not move
    /// to `invalid`) and the other three reasons would hide an agreed
    /// refutation.
    RefutationSuppressed {
        /// The suppressed refutation's stable code.
        code: String,
    },
}

/// One probed anchor's closed outcome class (D64 §6.2, frozen there):
/// `Promoted` · `Refuted` · `NotPromoted`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum OverlayOutcomeClass {
    /// Agreed evidence matched the embedded header: the online-augmented
    /// state is `proven`, at the **agreed** header's time (D56 §5 — never
    /// the embedded one), attributed to Bitcoin block `height`.
    Promoted {
        /// The agreed header's `nTime`, Unix seconds UTC.
        time_unix: i64,
        /// The attested Bitcoin block height.
        height: u64,
        /// The promoted verdict's source identity (`bitcoin-block-<H>`).
        source: Option<String>,
    },
    /// Agreed evidence refutes the anchor (header differs, or agreed
    /// no-such-block): the online-augmented state is `invalid` — that fixed
    /// state **is** this class's meaning, the way
    /// [`ReceiptClass`](crate::anchor::model::ReceiptClass)'s one variant is
    /// its — and `code` names which refutation (D56 rules O6/O7; the
    /// `anchor-forged-header` tamper family).
    Refuted {
        /// The refutation's stable code
        /// (`anchor-ots-online-header-mismatch` /
        /// `anchor-ots-online-block-absent`).
        code: String,
    },
    /// No promotion — the offline state stands, for the stated reason.
    NotPromoted {
        /// Why not.
        reason: NotPromotedReason,
    },
}

impl OverlayOutcomeClass {
    /// This class's stable token — D64 §6.2's names, wildcard-free (L2).
    #[must_use]
    pub const fn token(&self) -> &'static str {
        match self {
            Self::Promoted { .. } => "promoted",
            Self::Refuted { .. } => "refuted",
            Self::NotPromoted { .. } => "not-promoted",
        }
    }
}

/// One always-rendered per-probed-anchor outcome line (D64 §3): slot-named,
/// with the final display string embedded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OverlayAnchorOutcome {
    /// The slot name, aligned with the offline block's per-anchor rows
    /// ([`wording::slot_name`]; U23's convention via D64 §6.2).
    pub slot: String,
    /// The probed block height (the anchor's embedded upgrade height).
    pub height: u64,
    /// The closed outcome class.
    pub class: OverlayOutcomeClass,
    /// The final display line (R18's to respell; drawn from
    /// [`super::wording`]).
    pub line: String,
}

/// The receipt-confirmation echo's datum — supporting-evidence register:
/// **no time field and no state field, not null ones, none** (the
/// report-side [`SupportingEvidenceResult`] shape is the model; D64 §5,
/// D98 rider 4).
///
/// [`SupportingEvidenceResult`]: super::report::SupportingEvidenceResult
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReceiptEchoOutcome {
    /// Both RPCs agreed on the transaction's facts.
    Confirmed {
        /// The confirmed block number — display-only, as everywhere else
        /// the receipt appears (registry §7.10).
        block_number: u64,
        /// Whether the EVM receipt status byte was 1 (success).
        status_success: bool,
    },
    /// Both RPCs agreed the transaction is not on chain.
    NotOnChain,
    /// The RPC pair disagreed.
    Disagreed,
    /// The confirmation probe failed, per endpoint.
    Failed {
        /// What failed, endpoint by endpoint.
        failures: Vec<EndpointProbeFailure>,
    },
}

/// The receipt-confirmation echo: rendered **only when a receipt is present
/// and was probed** (D64 §3), in the overlay and nowhere else.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReceiptEcho {
    /// What the probe observed.
    pub outcome: ReceiptEchoOutcome,
    /// The final display line.
    pub line: String,
}

/// The endpoints-disclosure element: identities, the overridden flag, and
/// the labeled line (D64 §8 edit 5: "departing from pinned defaults" is this
/// line's datum, never page-authored).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EndpointsDisclosure {
    /// Every endpoint consulted, in disclosure order.
    pub identities: Vec<String>,
    /// `true` iff the run departed from the pinned defaults.
    pub overridden: bool,
    /// The final display line.
    pub line: String,
}

/// A change-only aggregate outcome — something the online-augmented
/// aggregate flags that the offline one did not (D64 §3's change-only
/// lines).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AggregateDelta {
    /// The online-augmented eligible set disagrees by more than 48 h where
    /// the offline one did not. The only delta the machinery can produce
    /// today: online evidence adds eligible times and removes none, so the
    /// divergence flag can appear and never disappear.
    DivergenceNewlyFlagged {
        /// The augmented set's earliest verified time.
        earliest_unix: i64,
        /// The augmented set's latest verified time.
        latest_unix: i64,
    },
}

impl AggregateDelta {
    /// This delta's stable token — wildcard-free (L2).
    #[must_use]
    pub const fn token(&self) -> &'static str {
        match self {
            Self::DivergenceNewlyFlagged { .. } => "divergence-newly-flagged",
        }
    }
}

/// One change-only aggregate line: the datum plus its final display string.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OverlayDelta {
    /// What changed.
    pub delta: AggregateDelta,
    /// The final display line.
    pub line: String,
}

/// Encoding the overlay to its canonical bytes failed. Structurally
/// unreachable for these types (no maps, no non-string keys) but surfaced as
/// a typed error — library code never unwraps.
#[derive(Debug, thiserror::Error)]
#[error("online overlay could not be encoded as canonical JSON")]
pub struct OverlayEncodeError(#[source] serde_json::Error);

/// The online-advisory overlay — D64 §3's fixed structure as a value, field
/// declaration order = render order, every display string final (renderers
/// do layout only).
///
/// A **sibling document**: never a `VerificationReport` field, never inside
/// the report bytes (module docs; D105). Serialized by
/// [`Self::to_canonical_json`] for U30's `--json` envelope and R22's page
/// entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OnlineOverlay {
    /// The framing sentence: "online", "advisory", non-replacement of the
    /// verdict above, strengthen-or-refute disclosure (D64 §5/§8).
    pub framing_line: String,
    /// The three-way impact datum — exactly one, always.
    pub headline_impact: HeadlineImpact,
    /// The impact line (the Supplies form is the one headline template with
    /// the mandatory online-attribution marker).
    pub headline_impact_line: String,
    /// One outcome per probed anchor, always rendered, slot-named. TSA
    /// anchors get no row (no online step, R21; D64 §5) — the framing
    /// sentence carries the scope.
    pub anchor_outcomes: Vec<OverlayAnchorOutcome>,
    /// The receipt echo — present only when a receipt is present and was
    /// probed.
    pub receipt: Option<ReceiptEcho>,
    /// The endpoints disclosure.
    pub endpoints: EndpointsDisclosure,
    /// Change-only aggregate lines (empty when nothing aggregate-level
    /// changed).
    pub aggregate_deltas: Vec<OverlayDelta>,
}

impl OnlineOverlay {
    /// The canonical, deterministic byte form of the overlay document:
    /// compact JSON, struct-declaration field order, kebab-case enum names —
    /// D29's discipline by construction, without D29's freeze (D64 §6;
    /// carriage and schema stability are D65's).
    pub fn to_canonical_json(&self) -> Result<Vec<u8>, OverlayEncodeError> {
        serde_json::to_vec(self).map_err(OverlayEncodeError)
    }
}

// ---------------------------------------------------------------------------
// the overlay computation
// ---------------------------------------------------------------------------

/// Build the online-advisory overlay from the two evaluations and the probe
/// log — **the only computation promotion feeds** (R17 Accept; D64 §6).
///
/// `artifacts` must be the same anchor sections both evaluations ran over:
/// it supplies the one datum the verdicts deliberately do not carry as a
/// number — each probed anchor's attested block height
/// ([`OtsUpgrade::block_height`]); the verdicts render it only inside the
/// `bitcoin-block-<H>` source string. Both hosts hold the bundle already
/// (R21 decoded it; R22's entry receives it), so this parameter adds no
/// capability, only the slot↔height association. Mismatched inputs are not
/// detectable here and yield a deterministic overlay over the intersection —
/// handing all three from one bundle is R21/R22's obligation, stated rather
/// than assumed.
///
/// The probed set is the OTS slots whose **offline** state is `attested` and
/// whose artifact carries an upgrade height — for `evaluate_anchors`-produced
/// inputs the two coincide (rule O4 requires the upgrade). TSA anchors are
/// never probed (already offline-proven or offline-refuted; R21) and get no
/// row.
///
/// Never panics, never mutates: both verdict sets, the artifacts and the
/// probe log are read-only, and the offline aggregate this builder derives is
/// the same value R21 renders the offline block from — computed, not
/// altered.
///
/// [`OtsUpgrade::block_height`]: crate::bundle::schema::OtsUpgrade::block_height
#[must_use]
pub fn build_online_overlay(
    artifacts: &AnchorArtifacts<'_>,
    offline: &AnchorVerdicts,
    online: &AnchorVerdicts,
    probes: &ProbeLog,
) -> OnlineOverlay {
    let offline_aggregate = VerdictAggregate::from_verdicts(offline);
    let online_aggregate = VerdictAggregate::from_verdicts(online);

    // ── headline impact (D64 §3.1) ─────────────────────────────────────
    let headline_impact = HeadlineImpact::classify(&offline_aggregate, &online_aggregate);
    let headline_impact_line = headline_impact_line(&headline_impact);

    // ── per-probed-anchor outcomes (D64 §5/§6.2) ───────────────────────
    //
    // OTS artifacts come first in the outcome order (`AnchorVerdicts::
    // outcomes`), so index i addresses the same artifact in all three
    // inputs.
    let mut anchor_outcomes = Vec::new();
    for (index, view) in artifacts.ots().enumerate() {
        let Some(upgrade) = view.upgrade() else {
            continue;
        };
        let (Some(offline_outcome), Some(online_outcome)) =
            (offline.outcomes().get(index), online.outcomes().get(index))
        else {
            continue;
        };
        if offline_outcome.verdict().kind() != AnchorKind::Ots
            || online_outcome.verdict().kind() != AnchorKind::Ots
            || offline_outcome.verdict().state() != AnchorState::Attested
        {
            continue;
        }
        let height = upgrade.block_height();
        let slot = wording::slot_name(AnchorKind::Ots, index + 1);
        let class = classify_probed_anchor(online_outcome, height, probes.block(height));
        let line = anchor_outcome_line(&slot, height, &class);
        anchor_outcomes.push(OverlayAnchorOutcome {
            slot,
            height,
            class,
            line,
        });
    }

    // ── receipt echo (D64 §3: present iff a receipt exists AND was probed) ─
    let receipt = if online.receipt().is_some() {
        receipt_echo(probes.receipt())
    } else {
        None
    };

    // ── endpoints disclosure ───────────────────────────────────────────
    let endpoints = EndpointsDisclosure {
        identities: probes.endpoints().identities().to_vec(),
        overridden: probes.endpoints().overridden(),
        line: wording::endpoints_line(
            probes.endpoints().identities(),
            probes.endpoints().overridden(),
        ),
    };

    // ── change-only aggregate deltas ───────────────────────────────────
    let mut aggregate_deltas = Vec::new();
    if offline_aggregate.divergence().is_none()
        && let Some(divergence) = online_aggregate.divergence()
    {
        let delta = AggregateDelta::DivergenceNewlyFlagged {
            earliest_unix: divergence.earliest_unix(),
            latest_unix: divergence.latest_unix(),
        };
        let line = wording::divergence_newly_flagged_line(
            divergence.earliest_unix(),
            divergence.latest_unix(),
        );
        aggregate_deltas.push(OverlayDelta { delta, line });
    }

    OnlineOverlay {
        framing_line: wording::overlay_framing_line().to_owned(),
        headline_impact,
        headline_impact_line,
        anchor_outcomes,
        receipt,
        endpoints,
        aggregate_deltas,
    }
}

/// The impact line for each class — one of three, drawn from the wording
/// source (D64 §3.1).
pub(crate) fn headline_impact_line(impact: &HeadlineImpact) -> String {
    match impact {
        HeadlineImpact::Supplies { headline } => wording::supplies_line(headline),
        HeadlineImpact::Stands => wording::stands_line().to_owned(),
        HeadlineImpact::StillUnanchored => wording::still_unanchored_line().to_owned(),
    }
}

/// Classify one probed anchor from its **online-augmented outcome** — the
/// authoritative datum — refined by the probe log only where the state is
/// unchanged.
///
/// Wildcard-free over all seven states so an eighth forces a decision here;
/// the last arm's three states are unreachable for a slot that was
/// `attested` offline (an OTS never renders `valid-at-stamping…`, and the
/// O-rules leave a committed upgraded artifact `proven`, `attested`,
/// `pending` or `invalid`) and fold to the probe-derived reason, kept total
/// rather than assumed.
fn classify_probed_anchor(
    online_outcome: &AnchorOutcome,
    height: u64,
    probe: Option<&BlockProbe>,
) -> OverlayOutcomeClass {
    let verdict = online_outcome.verdict();
    match verdict.state() {
        // O3 fired: agreed evidence matched. The time is the agreed
        // header's `nTime` — sourced by `evaluate_anchors`, never recomputed
        // here — and `proven` carries it by construction (A2), so the `else`
        // fold is unreachable and deliberately harmless.
        AnchorState::Proven => match verdict.verified_time_unix() {
            Some(time_unix) => OverlayOutcomeClass::Promoted {
                time_unix,
                height,
                source: verdict.source().map(|s| s.identity().to_owned()),
            },
            None => OverlayOutcomeClass::NotPromoted {
                reason: reason_from_probe(probe),
            },
        },
        // O6/O7 fired: agreed evidence refutes. `invalid` requires a
        // diagnostic by construction (A2); the empty-string fold is
        // unreachable and never rendered.
        AnchorState::Invalid => OverlayOutcomeClass::Refuted {
            code: verdict
                .diagnostic()
                .map(|d| d.code().to_owned())
                .unwrap_or_default(),
        },
        // O5 out-voted an agreed refutation (D93 §5): the refutation is the
        // A39 suppressed entry. A pending state with nothing suppressed can
        // only mean mismatched inputs; fold to the probe-derived reason.
        AnchorState::Pending => match online_outcome.suppressed().first() {
            Some(anomaly) => OverlayOutcomeClass::NotPromoted {
                reason: NotPromotedReason::RefutationSuppressed {
                    code: anomaly.code().to_owned(),
                },
            },
            None => OverlayOutcomeClass::NotPromoted {
                reason: reason_from_probe(probe),
            },
        },
        // Unchanged (no usable agreed evidence at this height), or the
        // unreachable-from-machinery states — the probe log says why.
        AnchorState::Attested
        | AnchorState::ValidAtStampingCertSinceExpired
        | AnchorState::InternallyConsistentOnly
        | AnchorState::Absent => OverlayOutcomeClass::NotPromoted {
            reason: reason_from_probe(probe),
        },
    }
}

/// The not-promoted reason a probe entry explains. An `Agreed` entry beside
/// an unchanged state means the claimed agreement never reached the verdict
/// path — for that path it **was** no evidence (D56 §3's absence rule), and
/// rendering it as anything stronger would let a probe log out-claim the
/// evaluation.
fn reason_from_probe(probe: Option<&BlockProbe>) -> NotPromotedReason {
    match probe {
        Some(BlockProbe::Disagreed) => NotPromotedReason::Disagreed,
        Some(BlockProbe::Failed(failures)) => NotPromotedReason::EndpointFailures {
            failures: failures.clone(),
        },
        Some(BlockProbe::Agreed | BlockProbe::NotAttempted) | None => NotPromotedReason::NoEvidence,
    }
}

/// The per-anchor display line for one classified outcome (L2: every class
/// renders; the sweep in `tests` holds the set closed).
pub(crate) fn anchor_outcome_line(slot: &str, height: u64, class: &OverlayOutcomeClass) -> String {
    match class {
        OverlayOutcomeClass::Promoted {
            time_unix, source, ..
        } => wording::promoted_line(slot, height, *time_unix, source.as_deref()),
        OverlayOutcomeClass::Refuted { code } => wording::refuted_line(slot, code),
        OverlayOutcomeClass::NotPromoted { reason } => match reason {
            NotPromotedReason::Disagreed => wording::disagreed_line(slot, height),
            NotPromotedReason::EndpointFailures { failures } => {
                wording::endpoint_failures_line(slot, height, failures)
            }
            NotPromotedReason::NoEvidence => wording::no_evidence_line(slot, height),
            NotPromotedReason::RefutationSuppressed { code } => {
                wording::refutation_suppressed_line(slot, code)
            }
        },
    }
}

/// The receipt echo for a probed receipt — `None` for
/// [`ReceiptProbe::NotAttempted`] (the "was probed" half of D64 §3's
/// presence rule; the "receipt present" half is the caller's).
fn receipt_echo(probe: &ReceiptProbe) -> Option<ReceiptEcho> {
    let outcome = match probe {
        ReceiptProbe::Agreed(ReceiptConfirmation::Agreed(facts)) => ReceiptEchoOutcome::Confirmed {
            block_number: facts.block_number,
            status_success: facts.status == 1,
        },
        ReceiptProbe::Agreed(ReceiptConfirmation::NotOnChain) => ReceiptEchoOutcome::NotOnChain,
        ReceiptProbe::Disagreed => ReceiptEchoOutcome::Disagreed,
        ReceiptProbe::Failed(failures) => ReceiptEchoOutcome::Failed {
            failures: failures.clone(),
        },
        ReceiptProbe::NotAttempted => return None,
    };
    let line = match &outcome {
        ReceiptEchoOutcome::Confirmed {
            block_number,
            status_success,
        } => wording::receipt_confirmed_line(*block_number, *status_success),
        ReceiptEchoOutcome::NotOnChain => wording::receipt_not_on_chain_line().to_owned(),
        ReceiptEchoOutcome::Disagreed => wording::receipt_disagreed_line().to_owned(),
        ReceiptEchoOutcome::Failed { failures } => wording::receipt_failed_line(failures),
    };
    Some(ReceiptEcho { outcome, line })
}

#[cfg(test)]
mod tests;
