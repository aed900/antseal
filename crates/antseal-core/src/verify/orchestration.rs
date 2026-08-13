//! The **verify orchestration library API** (task R21) — the one call U30's
//! `antseal verify` and R22's page both make, and the composition of every
//! piece M3 landed separately.
//!
//! This module ships **no CLI surface**: flags, exit codes and the `--json`
//! envelope are U30's (R21 Notes). What it ships is the composition:
//!
//! | mode | what it does |
//! |---|---|
//! | offline | [`verify_bundle`] → the machine-readable report **plus** its canonical bytes, R17's verdict aggregate, R18's rendered verdict, R19's redaction view, R20's linkage slot, and D69's rung |
//! | `--online` | the same, **unchanged**, with D64's advisory overlay computed beside it |
//! | `--live` | the same, with R11's per-blob persistence results projected into their own section |
//!
//! # The offline block is not a mode, it is the floor
//!
//! Every entry point runs the whole offline computation first and exposes it
//! identically. D64 §6's equality — *"the canonical report bytes of an
//! `--online` run are byte-identical to the offline run's"* — is therefore
//! not a check performed here but the shape of the code: the report comes
//! from [`verify_bundle`], which has no parameter through which online
//! evidence could arrive ([`VerifyOptions`]'s own docs record that as
//! deliberate), and the online computation is a **second** evaluation whose
//! output goes into a sibling document.
//!
//! [`RenderedVerdict`] is likewise built from the report and the **offline**
//! aggregate under every mode (D64 §2: *"the offline block cannot gain a
//! heading, a label, or any 'see below' marker"*). The one thing `--online`
//! may move is the **rung** (D69 §3 R5: the rung is computed over the
//! strongest computation the run performed), and that is not a report byte
//! and not an offline-block rendering.
//!
//! # Core does no I/O, so the network arrives through exactly one seam
//!
//! `antseal-core` must compile for `wasm32-unknown-unknown` and has no
//! network crate in its graph. Fetching is the host's: the CLI's
//! `antseal-anchor`/`antseal-net`, the page's `fetch()` through R22. Every
//! network-derived datum therefore enters through [`VerifyHost`] and through
//! nothing else — there is no other parameter on any entry point here that
//! could carry one, which is what makes *"offline mode performs zero network
//! I/O"* a property of the type signature rather than of a code path.
//!
//! `verify_offline` is [`verify_with_host`] at [`VerifyModes::OFFLINE`], and
//! `offline_mode_never_consults_the_host` runs the *panicking* host through
//! it: a host whose every method is `panic!`, handed to the run, never
//! reached.
//!
//! # The anchor stage runs a second time, and that is stated rather than hidden
//!
//! [`verify_bundle`] evaluates the anchors internally and returns only the
//! projected report slots (D27 froze that signature; `anchor_stage` is
//! private). R17's aggregate needs the **verdicts** — the headline datum is
//! time *and kind and source*, and D64 §9 records why a time-only comparison
//! is not enough — so this module calls
//! [`evaluate_anchors`](crate::anchor::verdicts::evaluate_anchors) again over
//! the same artifacts and the same recomputed digest. Under `--online` it
//! calls it twice more (D64 §6: *"R21's orchestration calls `evaluate_anchors`
//! twice"*).
//!
//! Deriving the aggregate from the report's slots instead would need a second
//! earliest-wins fold over a second eligibility reading — exactly the second
//! table R17 exists to prevent. The cost is real (TSA chain validation is the
//! expensive half) and
//! `the_re_evaluated_verdicts_project_to_the_reports_own_slots` is what keeps
//! the two evaluations honest: it asserts the re-derived verdicts project to
//! **the report's own `anchors` array**, so a mismatched `verify_at_unix` or
//! root store cannot pass unnoticed.
//!
//! # What U30 is handed, and the one trap D65 measured
//!
//! [`VerifyOutcome::report_bytes`] hands over
//! [`VerificationReport::to_canonical_json`]'s bytes **as bytes**. There is
//! deliberately **no** accessor here that returns a `serde_json::Value`:
//! `serde_json::Map` is a `BTreeMap` in this build, so a `Value` round trip
//! alphabetizes the report's keys and destroys D29 rule 1's declaration order
//! — with D64's byte-equality row green throughout, because that row compares
//! the *library's* bytes across two runs (D65 §1f). The library must not
//! pre-parse the report on U30's behalf, *"because the parse is precisely
//! where declaration order is lost"* (D65, R21's amended Accept row).
//!
//! The two siblings follow D65 §5.1: `overlay` and `live` are `None` when the
//! mode was off — U30 renders them as `null` and **never omits the key**,
//! because conditional presence *"is the shape that makes a presence
//! assertion untestable"*.
//!
//! [`verify_bundle`]: super::pipeline::verify_bundle
//! [`VerifyOptions`]: super::pipeline::VerifyOptions
//! [`VerificationReport::to_canonical_json`]:
//!     super::report::VerificationReport::to_canonical_json

use serde::Serialize;

use crate::anchor::model::{AnchorArtifacts, OnlineEvidence};
use crate::anchor::verdicts::{AnchorVerdicts, evaluate_anchors};
use crate::bundle::SealProof;
use crate::manifest::anchor_digest;

use super::error::VerifyError;
use super::overlay::{OnlineOverlay, ProbeEndpoints, ProbeLog, build_online_overlay};
use super::pipeline::{VerifyOptions, verify_bundle};
use super::redaction::RedactionView;
use super::report::{
    AnchorKind, AnchorResult, AnchorState, ReportEncodeError, SupportingEvidenceResult,
    VerificationReport,
};
use super::rung::{RefutedCount, VerdictExitRung, refuted_in_verdicts, verdict_exit_rung};
use super::verdict::VerdictAggregate;
use super::wording;

// ---------------------------------------------------------------------------
// modes
// ---------------------------------------------------------------------------

/// Which advisory layers a run performs beside the offline verdict.
///
/// Neither flag can change the offline computation: they select **additional
/// documents**, and the code that produces the report never sees this value.
///
/// The page never gets `--live` (CLI-only by spec, MVP-SPEC.md line 119;
/// R21 Notes), which is a fact about R22's caller rather than a restriction
/// expressible here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct VerifyModes {
    online: bool,
    live: bool,
}

impl VerifyModes {
    /// Neither advisory layer — the third party's default, and the only mode
    /// that needs no host at all.
    pub const OFFLINE: Self = Self {
        online: false,
        live: false,
    };

    /// Same as [`Self::OFFLINE`]; the builder's starting point.
    #[must_use]
    pub const fn new() -> Self {
        Self::OFFLINE
    }

    /// Compute D64's advisory online overlay.
    #[must_use]
    pub const fn with_online(mut self) -> Self {
        self.online = true;
        self
    }

    /// Render R11's live storage-persistence section.
    #[must_use]
    pub const fn with_live(mut self) -> Self {
        self.live = true;
        self
    }

    /// Whether the online overlay is requested.
    #[must_use]
    pub const fn online(self) -> bool {
        self.online
    }

    /// Whether the live section is requested.
    #[must_use]
    pub const fn live(self) -> bool {
        self.live
    }
}

// ---------------------------------------------------------------------------
// the host seam
// ---------------------------------------------------------------------------

/// What one host's probe run produced: the **agreed** evidence the verdict
/// path may read, and the probe log the overlay renders from.
///
/// The two are separate because D56 §3 and D64 §6.3 keep them separate:
/// `OnlineEvidence` has no failure variant, so an unreachable or disagreeing
/// endpoint is the *absence* of an entry, and the probe log is the only place
/// that absence has a reason. Pairing them correctly is the host's
/// obligation — an `Agreed` probe whose evidence never reached the evaluation
/// renders as no-evidence, because for the verdict path that is what it was.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OnlineInputs {
    evidence: OnlineEvidence,
    probes: ProbeLog,
}

impl OnlineInputs {
    /// Pair the agreed evidence with the probe log it came from.
    #[must_use]
    pub const fn new(evidence: OnlineEvidence, probes: ProbeLog) -> Self {
        Self { evidence, probes }
    }

    /// The agreed evidence handed to the online-augmented evaluation.
    #[must_use]
    pub const fn evidence(&self) -> &OnlineEvidence {
        &self.evidence
    }

    /// The probe log the overlay's per-anchor reasons are drawn from.
    #[must_use]
    pub const fn probes(&self) -> &ProbeLog {
        &self.probes
    }
}

/// What the network said about one stored blob — the WASM-safe projection of
/// `antseal-net`'s `PersistenceOutcome`, which lives in a crate this one must
/// never depend on (the same relationship
/// [`ProbeFailureClass`](super::overlay::ProbeFailureClass) has with
/// `antseal-anchor`'s failure taxonomy).
///
/// Four outcomes, and they are S15's four. `Different` is its own outcome
/// rather than a flavour of `NotFound` because under content addressing it
/// should be unreachable, which is R11's reason for ranking it worst.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum LiveBlobOutcome {
    /// The network returned exactly the expected bytes.
    Identical,
    /// The network returned bytes, and they differ from the expectation.
    Different,
    /// The network answered, negatively: nothing is stored at this address.
    NotFound,
    /// The fetch could not be completed, so nothing was established either
    /// way.
    FetchFailed {
        /// Host-supplied diagnostic detail from the storage boundary.
        ///
        /// **Never a classification key** — callers match on the outcome, not
        /// on this string — and never secret material (S15's own hygiene
        /// rule, inherited). It is host-authored text that reaches a display
        /// line, so a renderer escapes it for its own surface exactly as it
        /// escapes [`FileRedaction::path`](super::redaction::FileRedaction::path)
        /// (D67 §3 R6's value-vs-rendering split).
        reason: String,
    },
}

impl LiveBlobOutcome {
    /// The only outcome that confirms persistence (S15's predicate,
    /// restated over the projection).
    #[must_use]
    pub const fn is_identical(&self) -> bool {
        matches!(self, Self::Identical)
    }

    /// This outcome's stable token — wildcard-free, so a fifth outcome cannot
    /// land unnamed.
    #[must_use]
    pub const fn token(&self) -> &'static str {
        match self {
            Self::Identical => "identical",
            Self::Different => "different",
            Self::NotFound => "not-found",
            Self::FetchFailed { .. } => "fetch-failed",
        }
    }
}

/// One live-check row as the host observed it: which blob, and what the
/// network said.
///
/// `subject` is the label the row renders under (`unit 7`, the encrypted
/// manifest). It is the host's, because the subject vocabulary is R11's
/// `LiveSubject` and lives in `antseal-net`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveBlobRow {
    /// The rendered subject label.
    pub subject: String,
    /// What the network said about it.
    pub outcome: LiveBlobOutcome,
}

/// Everything a host's `--live` run observed, in row order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LiveInputs {
    rows: Vec<LiveBlobRow>,
}

impl LiveInputs {
    /// No rows — what a host with nothing to report supplies. Renders as a
    /// section with no rows and R11's `AllPersisted`-shaped **vacuum** is
    /// refused: see [`LiveSection::verdict`], which reports
    /// [`LiveLayerVerdict::NothingChecked`] rather than a vacuous pass.
    #[must_use]
    pub const fn none() -> Self {
        Self { rows: Vec::new() }
    }

    /// Build from the host's rows, in the order the records were supplied.
    #[must_use]
    pub const fn from_rows(rows: Vec<LiveBlobRow>) -> Self {
        Self { rows }
    }

    /// The rows.
    #[must_use]
    pub fn rows(&self) -> &[LiveBlobRow] {
        &self.rows
    }
}

/// The one seam through which a network-derived datum can enter verification.
///
/// Implemented by hosts, never by this crate: the CLI's implementation drives
/// `antseal-anchor` and `antseal-net`, R22's drives the page's `fetch()`
/// results in from JS. Both methods are **pure accessors over data the host
/// has already collected** — nothing here is async, because the browser's
/// fetch is and core cannot be.
///
/// A method is called **at most once per run, and only when
/// [`VerifyModes`] asks for its layer**. That is the property
/// `offline_mode_never_consults_the_host` proves with a panicking
/// implementation, and it is why the trait has no default methods: a default
/// returning empty inputs would let a host silently under-report rather than
/// fail to compile.
pub trait VerifyHost {
    /// The agreed online evidence and the probe log, for `--online`.
    fn online_inputs(&self) -> OnlineInputs;

    /// The per-blob live results, for `--live`.
    fn live_inputs(&self) -> LiveInputs;
}

/// The host of a run that asks for nothing — used by [`verify_offline`] and
/// deliberately **private**, so no caller can pair it with a network mode and
/// receive an empty overlay that looks like a completed probe.
struct NoNetworkHost;

impl VerifyHost for NoNetworkHost {
    fn online_inputs(&self) -> OnlineInputs {
        OnlineInputs::new(
            OnlineEvidence::new(),
            ProbeLog::new(ProbeEndpoints::new(Vec::new(), false)),
        )
    }

    fn live_inputs(&self) -> LiveInputs {
        LiveInputs::none()
    }
}

// ---------------------------------------------------------------------------
// the rendered offline verdict (R18's strings, R19's view beside it)
// ---------------------------------------------------------------------------

/// One per-anchor slot as the offline block renders it — the datum plus its
/// final display strings, the shape D64 §3 fixed for the overlay and this
/// block mirrors so a renderer does layout only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RenderedAnchorSlot {
    /// The slot name (`ots-1`, `tsa-2`) — [`wording::slot_name`], the U23
    /// convention the overlay's rows align with.
    pub slot: String,
    /// Which anchoring mechanism.
    pub kind: AnchorKind,
    /// The offline verdict state.
    pub state: AnchorState,
    /// `[H]` when the state is headline-eligible, empty otherwise.
    pub headline_tag: &'static str,
    /// The state row.
    pub state_line: String,
    /// The state's guidance rows, if any.
    pub guidance_lines: Vec<String>,
    /// The source row, when the slot recorded a source.
    pub source_line: Option<String>,
    /// The sealer-recorded fetch date, labelled NOT verified (D95 rider (a))
    /// — rendered under **every** state that emits a slot, `invalid`
    /// included.
    pub fetch_date_line: Option<String>,
}

/// The receipt's supporting-evidence rows — a register of its own, never an
/// anchor (MVP-SPEC.md line 110; A19).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RenderedSupportingEvidence {
    /// The class row: supporting evidence, no independently proven time.
    pub class_line: String,
    /// The receipt's detail row.
    pub detail_line: String,
}

/// The offline verdict block, as final display strings.
///
/// Every string is drawn from [`wording`], which R18 froze; a renderer adds
/// indentation, escaping and its own surface's markup and **nothing else**.
/// Field declaration order is render order.
///
/// Built from the report and the **offline** aggregate under every mode, so
/// an `--online` run's block is byte-identical to a plain run's (D64 §2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RenderedVerdict {
    /// The one headline sentence, or the loud UNANCHORED banner.
    pub headline_line: String,
    /// `true` when the banner is what `headline_line` carries.
    pub unanchored: bool,
    /// The >48 h divergence flag, when flagged.
    pub divergence_line: Option<String>,
    /// One block per anchor slot, in report order.
    pub anchors: Vec<RenderedAnchorSlot>,
    /// The sealer's claimed time, subordinate and labelled NOT verified.
    pub claimed_time_line: Option<String>,
    /// The receipt's rows, when the bundle carries one.
    pub supporting_evidence: Option<RenderedSupportingEvidence>,
    /// The evidence layer's label — *"this alone carries the evidentiary
    /// verdict"*.
    pub evidence_layer_label: &'static str,
    /// The storage-linkage layer's label.
    pub storage_linkage_label: &'static str,
    /// The storage-linkage layer's result row (including the literal truth
    /// about a run that did not evaluate it).
    pub storage_linkage_line: String,
    /// Which signature scheme the manifest was signed under.
    pub signature_scheme_line: String,
    /// What a seal proves, and what it does not (MVP-SPEC.md line 28).
    pub seal_meaning_line: &'static str,
}

impl RenderedVerdict {
    /// Render the offline block.
    ///
    /// `aggregate` must be the **offline** aggregate of the same run —
    /// `build_online_overlay`'s stated-obligation precedent: a mismatched
    /// pair is not detectable here and would render a headline that does not
    /// belong to the slots beneath it. [`verify_with_host`] pairs them by
    /// construction and is the only production caller.
    ///
    /// # The escape is the caller's, and it covers every authored value
    ///
    /// `escape` is the **caller's surface's** neutralisation policy (D130 §3
    /// R5/R9): the CLI passes D67 §3 R3's terminal set, `antseal-wasm` passes
    /// its own DOM policy, and no escape set moves into this crate — the two
    /// surfaces neutralise different byte sets, which is why
    /// [`wording::redacted_file_line`] takes an already-escaped path and says
    /// so.
    ///
    /// It is applied to **every** sealer- or artifact-authored value this
    /// block embeds. Measured on this tree, that is **four**, not the three
    /// D130 §1 (j) enumerated:
    ///
    /// | value | where it comes from |
    /// | --- | --- |
    /// | the headline's source slot | the winning verdict's `source()` — a TSA subject or an OTS block name, read out of the artifact |
    /// | `claimed_time_line` | `work.claimed_time_informational_only`, sealer-written |
    /// | `source_line` | `AnchorResult::source`, read out of the artifact |
    /// | `fetch_date_line` | `AnchorResult::fetch_date`, sealer-recorded |
    ///
    /// Every other string here is a table constant, an enum label, or a
    /// number this crate computed, and none of them can carry authored bytes.
    #[must_use]
    pub fn new(
        report: &VerificationReport,
        aggregate: &VerdictAggregate,
        escape: &impl Fn(&str) -> String,
    ) -> Self {
        let (headline_line, unanchored) = match aggregate.headline() {
            Some(headline) => (
                wording::headline_sentence(
                    headline.time_unix(),
                    headline.kind(),
                    // The headline's source slot is artifact-authored too —
                    // the same class as the per-slot `source_line` below, and
                    // the one D130 §1 (j)'s survey of three missed.
                    &escape(&wording::source_slot(headline.source())),
                ),
                false,
            ),
            None => (wording::UNANCHORED_BANNER.to_owned(), true),
        };

        let divergence_line = aggregate.divergence().map(|divergence| {
            wording::divergence_flag_line(divergence.earliest_unix(), divergence.latest_unix())
        });

        let mut ots_seen = 0usize;
        let mut tsa_seen = 0usize;
        let anchors = report
            .anchors
            .iter()
            .map(|anchor| {
                let ordinal = match anchor.kind {
                    AnchorKind::Ots => {
                        ots_seen += 1;
                        ots_seen
                    }
                    AnchorKind::Tsa => {
                        tsa_seen += 1;
                        tsa_seen
                    }
                };
                rendered_slot(anchor, ordinal, escape)
            })
            .collect();

        let claimed_time_line = report
            .work
            .claimed_time_informational_only
            .as_deref()
            .map(|claimed| wording::claimed_time_line(&escape(claimed)));

        let supporting_evidence = match report.supporting_evidence {
            SupportingEvidenceResult::None => None,
            SupportingEvidenceResult::ArbitrumReceipt {
                block_number,
                transaction_count,
            } => Some(RenderedSupportingEvidence {
                class_line: wording::receipt_class_line(),
                detail_line: wording::receipt_detail_line(block_number, transaction_count),
            }),
        };

        Self {
            headline_line,
            unanchored,
            divergence_line,
            anchors,
            claimed_time_line,
            supporting_evidence,
            evidence_layer_label: wording::EVIDENCE_LAYER_LABEL,
            storage_linkage_label: wording::STORAGE_LINKAGE_LAYER_LABEL,
            storage_linkage_line: wording::storage_linkage_line(report.storage_linkage),
            signature_scheme_line: wording::signature_scheme_line(report.work.signature_scheme),
            seal_meaning_line: wording::SEAL_MEANING_NOTE,
        }
    }

    /// The block's canonical bytes, for the rendered document's `rendered`
    /// member (D130 §3 R3) — the same [`SiblingEncodeError`] idiom
    /// [`LiveSection::to_canonical_json`] and
    /// [`VerdictClass::to_canonical_json`] already use.
    ///
    /// Deterministic by construction — compact JSON, declaration order, no
    /// maps — but **tier C** under D65 §3: reviewed, not promised until U32.
    ///
    /// # Errors
    ///
    /// [`SiblingEncodeError`] — structurally unreachable for this type, and
    /// typed rather than unwrapped because library code never unwraps.
    pub fn to_canonical_json(&self) -> Result<Vec<u8>, SiblingEncodeError> {
        serde_json::to_vec(self).map_err(SiblingEncodeError)
    }
}

/// One slot's rows.
///
/// The guidance match is **wildcard-free** so an eighth state must be given
/// rows here (or explicitly given none) rather than silently rendering bare —
/// the arrangement `verdict_wording.rs`'s own `state_block` uses.
///
/// Two deliberate absences:
///
/// - **`attested` gets no block row.** MVP-SPEC.md line 108's sentence names
///   block H, and the height is not on [`AnchorResult`] — it lives on the
///   artifact's upgrade group, which is why `build_online_overlay` takes the
///   artifacts as a separate parameter. Rendering it here would make this
///   block underivable from the report alone, which is the property that lets
///   R22's page draw the same rows from the same bytes. R18's residue list
///   already records the question as open.
/// - **`pending` gets the third-party guidance**, never the sealer's
///   `--upgrade` one: `verify` needs no vault and never prompts (the frozen
///   help text), so the audience that could run `antseal status --upgrade` is
///   not the one reading this.
fn rendered_slot(
    anchor: &AnchorResult,
    ordinal_within_kind: usize,
    escape: &impl Fn(&str) -> String,
) -> RenderedAnchorSlot {
    let guidance_lines = match anchor.state {
        AnchorState::Proven | AnchorState::ValidAtStampingCertSinceExpired => anchor
            .verified_time_unix
            .map(wording::verified_time_line)
            .into_iter()
            .collect(),
        AnchorState::Pending => vec![wording::PENDING_GUIDANCE.to_owned()],
        AnchorState::Attested
        | AnchorState::InternallyConsistentOnly
        | AnchorState::Invalid
        | AnchorState::Absent => Vec::new(),
    };

    RenderedAnchorSlot {
        slot: wording::slot_name(anchor.kind, ordinal_within_kind),
        kind: anchor.kind,
        state: anchor.state,
        headline_tag: wording::headline_tag(anchor.state),
        state_line: wording::anchor_state_line(anchor.state),
        guidance_lines,
        source_line: anchor.source.as_deref().map(|identity| {
            // "verified" is exactly headline eligibility, read off the same
            // tag the row above prints — never a second table (D53 §4).
            // The identity itself is artifact-authored and reaches a terminal
            // or a DOM, so it goes through the caller's escape (D130 §3 R9).
            wording::source_line(
                &escape(identity),
                !wording::headline_tag(anchor.state).is_empty(),
            )
        }),
        fetch_date_line: anchor
            .fetch_date
            .as_deref()
            .map(|fetch_date| wording::fetch_date_line(&escape(fetch_date))),
    }
}

// ---------------------------------------------------------------------------
// the live section (R11's results, rendered in the storage layer)
// ---------------------------------------------------------------------------

/// The storage-layer word for a whole live check — the WASM-safe projection
/// of R11's `LiveVerdict`, with its **normative precedence** restated over
/// the projected rows:
///
/// > the worst *established fact* wins, and uncertainty rules only when
/// > nothing negative was established — `Divergent` > `SomeMissing` >
/// > `Inconclusive` > `AllPersisted`.
///
/// Declaration order is **ascending severity**, so [`LiveSection`]'s fold is
/// the `Ord` derive rather than a cascade (the [`VerdictExitRung`]
/// arrangement, for the same reason).
///
/// [`Self::NothingChecked`] has no counterpart in R11 because R11 refuses an
/// empty check outright (`LiveCheckError::NothingToCheck`, *"an empty check
/// would report `AllPersisted` vacuously"*). A rendering layer cannot refuse,
/// so the vacuum gets a name of its own rather than being folded into the
/// pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum LiveLayerVerdict {
    /// No rows were supplied. Never a pass.
    NothingChecked,
    /// Every record came back byte-identical.
    AllPersisted,
    /// Nothing negative was established, but at least one fetch failed.
    Inconclusive,
    /// No divergence, but at least one record is not on the network.
    SomeMissing,
    /// At least one address served bytes that are not the expected ones.
    Divergent,
}

/// Per-outcome counts over a live section's rows; the four partition
/// `checked` exactly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
pub struct LiveCounts {
    /// Rows the network confirmed byte-identical.
    pub identical: u64,
    /// Rows where the network served different bytes.
    pub different: u64,
    /// Rows the network had nothing for.
    pub not_found: u64,
    /// Rows whose fetch could not be completed.
    pub fetch_failed: u64,
    /// Total rows.
    pub checked: u64,
}

/// One rendered live row: the datum plus its final display string.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RenderedLiveRow {
    /// The subject label, as the host supplied it.
    pub subject: String,
    /// What the network said.
    pub outcome: LiveBlobOutcome,
    /// The final display line.
    pub line: String,
}

/// The `--live` section: a **third sibling document**, CLI-only, advisory,
/// and incapable of moving the evidence verdict or the exit code (D64 §6;
/// D69 §3 R6; MVP-SPEC.md line 118 — *"storage is the product's bonus, not
/// its proof"*).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LiveSection {
    /// The layer label — advisory, gates no verdict above.
    pub label: &'static str,
    /// The storage-layer verdict over the rows.
    pub verdict: LiveLayerVerdict,
    /// The verdict's display line, when the layer has one to state.
    pub verdict_line: Option<String>,
    /// One row per checked blob, in the order the host supplied them.
    pub rows: Vec<RenderedLiveRow>,
    /// Per-outcome counts.
    pub counts: LiveCounts,
}

impl LiveSection {
    /// Render a host's live results.
    #[must_use]
    fn new(inputs: &LiveInputs) -> Self {
        let mut counts = LiveCounts::default();
        let rows: Vec<RenderedLiveRow> = inputs
            .rows()
            .iter()
            .map(|row| {
                counts.checked = counts.checked.saturating_add(1);
                let line = match &row.outcome {
                    LiveBlobOutcome::Identical => {
                        counts.identical = counts.identical.saturating_add(1);
                        wording::live_blob_identical_line(&row.subject)
                    }
                    LiveBlobOutcome::Different => {
                        counts.different = counts.different.saturating_add(1);
                        wording::live_blob_different_line(&row.subject)
                    }
                    LiveBlobOutcome::NotFound => {
                        counts.not_found = counts.not_found.saturating_add(1);
                        wording::live_blob_not_found_line(&row.subject)
                    }
                    LiveBlobOutcome::FetchFailed { reason } => {
                        counts.fetch_failed = counts.fetch_failed.saturating_add(1);
                        wording::live_blob_fetch_error_line(&row.subject, reason)
                    }
                };
                RenderedLiveRow {
                    subject: row.subject.clone(),
                    outcome: row.outcome.clone(),
                    line,
                }
            })
            .collect();

        let verdict = live_verdict(counts);
        let verdict_line = match verdict {
            LiveLayerVerdict::NothingChecked => None,
            LiveLayerVerdict::AllPersisted => {
                Some(wording::live_all_persisted_line(counts.checked))
            }
            LiveLayerVerdict::Inconclusive => {
                Some(wording::live_inconclusive_line(counts.fetch_failed))
            }
            LiveLayerVerdict::SomeMissing => {
                Some(wording::live_some_missing_line(counts.not_found))
            }
            LiveLayerVerdict::Divergent => Some(wording::live_divergent_line(counts.different)),
        };

        Self {
            label: wording::LIVE_LAYER_LABEL,
            verdict,
            verdict_line,
            rows,
            counts,
        }
    }

    /// The section's canonical bytes, for U30's `--json` `live` member.
    ///
    /// Deterministic by construction — compact JSON, declaration order, no
    /// maps — but **tier C** under D65 §3: reviewed, not promised until U32.
    ///
    /// # Errors
    ///
    /// [`SiblingEncodeError`] — structurally unreachable for these types, and
    /// typed rather than unwrapped because library code never unwraps.
    pub fn to_canonical_json(&self) -> Result<Vec<u8>, SiblingEncodeError> {
        serde_json::to_vec(self).map_err(SiblingEncodeError)
    }
}

/// R11's precedence, as a fold over the counts.
///
/// Written as filter-then-`max` over the declared severity order for the
/// reason [`verdict_exit_rung`] is: the ladder must be the `Ord` derive, not
/// a hand-ordered cascade.
fn live_verdict(counts: LiveCounts) -> LiveLayerVerdict {
    if counts.checked == 0 {
        return LiveLayerVerdict::NothingChecked;
    }
    [
        LiveLayerVerdict::AllPersisted,
        LiveLayerVerdict::Inconclusive,
        LiveLayerVerdict::SomeMissing,
        LiveLayerVerdict::Divergent,
    ]
    .into_iter()
    .filter(|verdict| match verdict {
        LiveLayerVerdict::AllPersisted => true,
        LiveLayerVerdict::Inconclusive => counts.fetch_failed > 0,
        LiveLayerVerdict::SomeMissing => counts.not_found > 0,
        LiveLayerVerdict::Divergent => counts.different > 0,
        LiveLayerVerdict::NothingChecked => false,
    })
    .max()
    .unwrap_or(LiveLayerVerdict::AllPersisted)
}

// ---------------------------------------------------------------------------
// the verdict-class datum (D69's, for U30's exit-code mapping)
// ---------------------------------------------------------------------------

/// The verdict-class datum U30's exit-code mapping reads (D69 §3 R7): the
/// rung's **stable name** and the facts it coarsens.
///
/// **No integer.** `ErrorClass` and its committed code table are U2's, and
/// D69 §3 R1 keeps exactly one code table in the product; U30 maps
/// [`Self::rung`] onto it and adds the `exit_code` key its own Accept row
/// asserts against `$?`. A second numeric table here is precisely the
/// disagreement D69 §3 R7 prevents by construction.
///
/// `rung` is `null` for the clean verdict — a value, never a missing key
/// (D65 §7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct VerdictClass {
    /// The rung's stable class name, or `None` for a clean verdict.
    pub rung: Option<&'static str>,
    /// Zero headline-eligible anchors (MVP-SPEC.md line 137).
    pub unanchored: bool,
    /// Headline-eligible anchors disagree by strictly more than 48 h.
    pub headline_divergence: bool,
    /// How many anchor slots are refuted.
    pub anchors_refuted: u64,
    /// How many anchor slots are headline-eligible — the spec's `[H]` count.
    pub headline_eligible: u64,
    /// How many anchor slots were aggregated.
    pub total_anchors: u64,
}

impl VerdictClass {
    /// Coarsen one computation into the datum.
    fn new(aggregate: &VerdictAggregate, refuted: RefutedCount) -> Self {
        Self {
            rung: verdict_exit_rung(aggregate, refuted).map(VerdictExitRung::name),
            unanchored: aggregate.is_unanchored(),
            headline_divergence: aggregate.divergence().is_some(),
            anchors_refuted: refuted.get(),
            headline_eligible: aggregate.eligible_count(),
            total_anchors: aggregate.total_anchors(),
        }
    }

    /// The datum's canonical bytes, for U30's `--json` `verdict` member.
    ///
    /// # Errors
    ///
    /// [`SiblingEncodeError`] — structurally unreachable, typed anyway.
    pub fn to_canonical_json(&self) -> Result<Vec<u8>, SiblingEncodeError> {
        serde_json::to_vec(self).map_err(SiblingEncodeError)
    }
}

/// Encoding a sibling document to canonical bytes failed.
///
/// Structurally unreachable for these types (no maps, no non-string keys) but
/// surfaced as a typed error, because library code never unwraps.
///
/// The field is `pub(crate)` rather than private so
/// [`RenderedRedaction`](super::redaction::RenderedRedaction) — which D130 §3
/// R4 places beside [`RedactionView`], not here — can report the same failure
/// through the same type. It stays invisible outside this crate.
#[derive(Debug, thiserror::Error)]
#[error("a verify sibling document could not be encoded as canonical JSON")]
pub struct SiblingEncodeError(#[source] pub(crate) serde_json::Error);

// ---------------------------------------------------------------------------
// the run's error
// ---------------------------------------------------------------------------

/// What can stop a verification **run** — the bundle's own rejection, or the
/// one internal step that has a failure arm.
///
/// A distinct type rather than a new [`VerifyError`] variant, deliberately:
/// `VerifyError`'s value space is the Q52 **frozen error universe** and every
/// arm of it carries a committed code, so widening it for a serializer arm
/// that cannot fire would be a frozen-universe event bought with nothing.
/// [`ReportEncodeError`] and
/// [`OverlayEncodeError`](super::overlay::OverlayEncodeError) are the
/// existing precedent: typed, code-free, structurally unreachable.
///
/// U30 routes the two arms differently and D69 §3 R2 already names both
/// destinations — [`Self::Verify`] is the `verify-bundle-rejected` (40) arm
/// where *"tamper and malformed are one class, deliberately"*, and
/// [`Self::ReportEncode`] is an antseal bug on the verify path, which is
/// `internal` (1).
#[derive(Debug, thiserror::Error)]
pub enum VerifyRunError {
    /// The bundle did not pass the evidence layer — D27's fail-fast first
    /// error, carrying the stable rejection code U30 puts in the message.
    #[error(transparent)]
    Verify(#[from] VerifyError),
    /// The verified report could not be serialized. No input can reach this:
    /// report v1 has no map, no non-string key and no float.
    #[error("the verified report could not be encoded as canonical JSON")]
    ReportEncode(#[source] ReportEncodeError),
}

impl VerifyRunError {
    /// The bundle-rejection error, when that is what happened.
    ///
    /// The accessor exists so U30 can reach `VerifyError::code()` for its
    /// message without matching on this enum's shape — D69 §7 row 8 makes
    /// *"its distinct code appears in the message"* a test.
    #[must_use]
    pub const fn verify_error(&self) -> Option<&VerifyError> {
        match self {
            Self::Verify(error) => Some(error),
            Self::ReportEncode(_) => None,
        }
    }
}

// ---------------------------------------------------------------------------
// the outcome
// ---------------------------------------------------------------------------

/// Everything one verification run produced.
///
/// Owns its report so the canonical bytes and the typed value cannot drift —
/// they are computed together, once — and so [`Self::redaction`] can hand out
/// a borrowed view without a self-referential struct.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyOutcome {
    report: VerificationReport,
    report_bytes: Vec<u8>,
    offline_verdict: VerdictAggregate,
    exit_verdict: VerdictAggregate,
    refuted: RefutedCount,
    verdict_class: VerdictClass,
    rendered: RenderedVerdict,
    overlay: Option<OnlineOverlay>,
    live: Option<LiveSection>,
}

impl VerifyOutcome {
    /// The machine-readable report — the typed value, for a caller building a
    /// typed `--json` envelope (D65 §5's first acceptable carriage route).
    #[must_use]
    pub const fn report(&self) -> &VerificationReport {
        &self.report
    }

    /// The report's canonical bytes, **as bytes** — exactly
    /// [`VerificationReport::to_canonical_json`]'s output, computed once.
    ///
    /// This is the whole of R21's obligation to U30's `--json` `report`
    /// member (D65 tier A, byte-verbatim). There is no accessor here that
    /// returns a `serde_json::Value`, and there must never be: the parse is
    /// where D29 rule 1's declaration order is lost.
    ///
    /// [`VerificationReport::to_canonical_json`]:
    ///     super::report::VerificationReport::to_canonical_json
    #[must_use]
    pub fn report_bytes(&self) -> &[u8] {
        &self.report_bytes
    }

    /// R19's redaction view, derived from the report on demand — a lens, not
    /// a second copy that could drift.
    #[must_use]
    pub fn redaction(&self) -> RedactionView<'_> {
        RedactionView::from_report(&self.report)
    }

    /// R17's **offline** verdict aggregate — the one the rendered block is
    /// built from, under every mode (D64 §2).
    #[must_use]
    pub const fn verdict(&self) -> &VerdictAggregate {
        &self.offline_verdict
    }

    /// The aggregate the rung was computed over: the offline one for a plain
    /// run, the **online-augmented** one under `--online` (D69 §3 R5 — *"the
    /// strongest computation the run performed"*).
    ///
    /// Equal to [`Self::verdict`] whenever `--online` was not requested, and
    /// whenever it was requested and no endpoint pair agreed — the second
    /// case is a theorem off `OnlineBlockResult`'s missing failure variant,
    /// not a policy (D69 §1 i).
    #[must_use]
    pub const fn exit_verdict(&self) -> &VerdictAggregate {
        &self.exit_verdict
    }

    /// How many anchor slots the rung's computation found refuted.
    #[must_use]
    pub const fn refuted(&self) -> RefutedCount {
        self.refuted
    }

    /// D69's rung, or `None` for a clean verdict.
    #[must_use]
    pub fn exit_rung(&self) -> Option<VerdictExitRung> {
        verdict_exit_rung(&self.exit_verdict, self.refuted)
    }

    /// The verdict-class datum for U30's `--json` `verdict` member.
    #[must_use]
    pub const fn verdict_class(&self) -> VerdictClass {
        self.verdict_class
    }

    /// R18's rendered offline verdict block.
    #[must_use]
    pub const fn rendered(&self) -> &RenderedVerdict {
        &self.rendered
    }

    /// D64's advisory overlay — `None` exactly when `--online` was not
    /// requested. U30 renders `null` rather than omitting the key (D65 §5.1).
    #[must_use]
    pub const fn overlay(&self) -> Option<&OnlineOverlay> {
        self.overlay.as_ref()
    }

    /// The `--live` section — `None` exactly when `--live` was not requested.
    /// U30 renders `null` rather than omitting the key (D65 §5.1).
    #[must_use]
    pub const fn live(&self) -> Option<&LiveSection> {
        self.live.as_ref()
    }
}

// ---------------------------------------------------------------------------
// the entry points
// ---------------------------------------------------------------------------

/// Verify a `.sealproof` with **no host and no network at all** — the third
/// party's default, and the whole of what the page does before its explicit
/// "confirm online" action.
///
/// Exactly [`verify_with_host`] at [`VerifyModes::OFFLINE`], and the outcomes
/// are asserted equal rather than described as equal — which is what makes the
/// panicking-host row a statement about *this* function too.
///
/// # Errors
///
/// [`VerifyRunError::Verify`] — [`verify_bundle`]'s first failure in stage
/// order (D27: fail-fast, tamper-authoritative), which U30 maps onto D69's
/// `verify-bundle-rejected`.
///
/// [`verify_bundle`]: super::pipeline::verify_bundle
pub fn verify_offline(
    bundle: &[u8],
    options: &VerifyOptions,
    escape: &impl Fn(&str) -> String,
) -> Result<VerifyOutcome, VerifyRunError> {
    verify_with_host(
        bundle,
        options,
        VerifyModes::OFFLINE,
        &NoNetworkHost,
        escape,
    )
}

/// Verify a `.sealproof` and compose whatever advisory layers `modes` asks
/// for.
///
/// `host` is consulted **only** for the layers `modes` requests: at
/// [`VerifyModes::OFFLINE`] it is not consulted at all, which
/// `offline_mode_never_consults_the_host` proves by handing in an
/// implementation whose every method panics.
///
/// # Errors
///
/// [`VerifyRunError::Verify`] — [`verify_bundle`]'s first failure in stage
/// order. No advisory layer can produce an error: a probe that failed is an
/// overlay outcome, and a live fetch that failed is a row — neither can fail
/// a bundle.
///
/// # The rendering policy is the caller's, and it arrives here
///
/// [`RenderedVerdict`] is built on this path, unconditionally, under every
/// mode — so the escape its authored values need has to arrive with the call
/// (D130 §3 R5/R9). `escape` is the caller's surface's set and nothing else:
/// no escape set lives in this crate, and the alternative — a block built
/// unescaped and neutralised later — is the seam D130 §1 (j) measured open
/// and this parameter closes.
///
/// [`verify_bundle`]: super::pipeline::verify_bundle
pub fn verify_with_host<H>(
    bundle: &[u8],
    options: &VerifyOptions,
    modes: VerifyModes,
    host: &H,
    escape: &impl Fn(&str) -> String,
) -> Result<VerifyOutcome, VerifyRunError>
where
    H: VerifyHost + ?Sized,
{
    // The bundle is decoded before it is verified so the two failures cannot
    // be reported differently: a decode failure here is stage 1's, and it is
    // exactly the error `verify_bundle` would return for the same input
    // (`VerifyError::Decode`, `pipeline.rs`'s first line of work).
    let proof = SealProof::decode(bundle).map_err(VerifyError::Decode)?;

    // ── the offline computation, identical under every mode ────────────
    let report = verify_bundle(bundle, options)?;
    let report_bytes = report
        .to_canonical_json()
        .map_err(VerifyRunError::ReportEncode)?;

    let inputs = AnchorInputs::of(&proof);
    let offline_verdicts = inputs.evaluate(options, &OnlineEvidence::new());
    let offline_verdict = VerdictAggregate::from_verdicts(&offline_verdicts);
    let rendered = RenderedVerdict::new(&report, &offline_verdict, escape);

    // ── `--online`: a second evaluation, into a sibling document ───────
    let (overlay, exit_verdict, refuted) = if modes.online() {
        let online = host.online_inputs();
        let online_verdicts = inputs.evaluate(options, online.evidence());
        let overlay = build_online_overlay(
            inputs.artifacts(),
            &offline_verdicts,
            &online_verdicts,
            online.probes(),
        );
        // D69 §3 R5: the rung reads the strongest computation the run
        // performed. The report bytes and the rendered block above are
        // already built and are not revisited.
        (
            Some(overlay),
            VerdictAggregate::from_verdicts(&online_verdicts),
            refuted_in_verdicts(&online_verdicts),
        )
    } else {
        (
            None,
            offline_verdict.clone(),
            refuted_in_verdicts(&offline_verdicts),
        )
    };

    // ── `--live`: a third sibling, in the storage layer ────────────────
    let live = modes.live().then(|| LiveSection::new(&host.live_inputs()));

    let verdict_class = VerdictClass::new(&exit_verdict, refuted);

    Ok(VerifyOutcome {
        report,
        report_bytes,
        offline_verdict,
        exit_verdict,
        refuted,
        verdict_class,
        rendered,
        overlay,
        live,
    })
}

/// The two things every anchor evaluation in this module needs, derived once.
///
/// Exists so the offline evaluation, the online-augmented one and
/// [`offline_verdicts`] cannot drift apart on **which digest** they evaluate
/// against: the digest is recomputed from the bundle's own manifest-envelope
/// pre-image (F7), so a bundle can never state its own anchor identity, and
/// deriving it twice in two places is how one of them ends up reading
/// `work_id` instead.
struct AnchorInputs<'a> {
    artifacts: AnchorArtifacts<'a>,
    digest: [u8; 32],
}

impl<'a> AnchorInputs<'a> {
    fn of(proof: &'a SealProof<'a>) -> Self {
        Self {
            artifacts: AnchorArtifacts::from_bundle(proof.bundle()),
            digest: *anchor_digest(proof.anchor_digest_preimage()).as_bytes(),
        }
    }

    const fn artifacts(&self) -> &AnchorArtifacts<'a> {
        &self.artifacts
    }

    /// One evaluation under the given evidence regime. `None` verification
    /// time evaluates as `0` — D53 §5b's one-sided end, exactly as
    /// `verify_bundle`'s own anchor stage does it.
    fn evaluate(&self, options: &VerifyOptions, online: &OnlineEvidence) -> AnchorVerdicts {
        evaluate_anchors(
            &self.artifacts,
            &self.digest,
            online,
            options.verify_at_unix().unwrap_or(0),
            options.tsa_roots(),
        )
    }
}

/// Re-evaluate a decoded bundle's anchors — exposed so a caller that already
/// holds the verdicts (R22's page entry, or a test) can build the same
/// aggregate this module builds, from the same code.
///
/// Offline by construction: the evidence is empty and there is no parameter
/// to supply any.
#[must_use]
pub fn offline_verdicts(proof: &SealProof<'_>, options: &VerifyOptions) -> AnchorVerdicts {
    AnchorInputs::of(proof).evaluate(options, &OnlineEvidence::new())
}

#[cfg(test)]
mod tests;
