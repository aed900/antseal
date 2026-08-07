//! `list` (U19): every work in the vault, what state it is in, what it
//! cost, and — for an unfinished seal — the exact command that finishes it.
//!
//! MVP-SPEC.md line 149 (`list`) and line 145 ("`list` shows `incomplete`
//! works").
//!
//! # Two state tags, and why `list` reads both
//!
//! S10 keeps the fine [`SealState`] in journal entry 0 and U9's coarse
//! [`WorkState`] as a derived mirror in the meta record. `list` prefers the
//! fine tag — `staged` vs `anchored` is what tells a user how far their
//! interrupted seal got — but it must not *require* it: a `vault import`ed
//! **complete** work carries no journal entries at all (U12 applies D43
//! §3's cache exclusion to the whole journal area), so after a restore-from-
//! backup the coarse mirror is the only tag left. Reading the mirror as the
//! fallback is what keeps `list` working on exactly the machine where a
//! user most needs it. (That same gap stops `restore` working there; it is
//! recorded as S29 and is not `list`'s to fix.)
//!
//! **The paragraph above is stale and is U58's to correct, not U25's.**
//! S29 changed the export on 2026-08-02 and `vault/export.rs:781-786` now
//! skips only `entry >= UNIT_ENTRY_BASE`, so entries 0 (state), 1 (plan)
//! and 2 (manifest blob) survive `vault import` for a complete work too
//! (D98 gap 3). That is load-bearing below: the anchor nag recovers
//! `anchor_digest` from the **plan** record, and it therefore works on a
//! restored vault. What is now unclear is `list`'s stated *reason* for the
//! coarse-mirror fallback, since entry 0 survives as well — also U58's.
//!
//! # The two clocks (U19, from the D36/D37 planning round)
//!
//! An unfinished seal is on one of two clocks, and they pull in opposite
//! directions:
//!
//! - **pre-pay** — nothing was paid, and the journaled quote is stale *by
//!   design*: resume always re-quotes and re-asks for consent (D36). There
//!   is no hurry and no risk of a surprise charge.
//! - **post-receipt** — money already moved, and the payment proofs stay
//!   usable for uploading only about a day (D37's conservative client-side
//!   window). Past it, finishing the seal costs a **second** payment.
//!   Hence the nag: resume promptly.
//!
//! Saying "resume when convenient" to the second class would cost users
//! money, and saying "hurry" to the first would be a lie, so the row states
//! which clock it is on rather than printing one generic reminder.
//!
//! # The anchor nag (U25, ruled by D98 rider 3)
//!
//! `pending_anchors` was the reserved M2 column and is now filled: the
//! number of OTS calendar attestations this work is still waiting on. The
//! **class** rides beside it in [`WorkRow::nag`], because a count cannot
//! carry one — D98 rider 3b, and [`NagState`]'s own doc says why (*"'no
//! nag' has three different meanings and rendering them identically is how
//! an UNANCHORED work comes to look merely pending"*).
//!
//! Adding `nag` to the `--json` row is permitted now: **D65 is not in
//! force.** It has no `docs/decisions/D65-*.md`, its register row is
//! unchecked under "Due M3", its own text scopes it *"from M3"*, and U50
//! exists to draw its scope (D98, "smaller measured facts"). The in-force
//! machine contract is `ENVELOPE_VERSION`, about the envelope wrapper.
//! Recorded here so a future reader does not re-derive it.
//!
//! ## Three predicates share the word UNANCHORED (D98 rider 3c)
//!
//! They are kept apart in the code and in the rendered words:
//!
//! - [`WorkRow::unanchored`] — the `--no-anchor` **flag as the sealer gave
//!   it**. It describes how the seal was made, and it is what
//!   [`WorkRow::badge`] prints. Nothing below changes it.
//! - [`NagState::Unanchored`] — this work holds **no anchor artifacts at
//!   all**. Usually the same works, but not by construction: a seal killed
//!   before the anchor stage has neither flag nor artifacts, and a
//!   hand-emptied `anchors/` directory has artifacts missing without the
//!   flag.
//! - MVP-SPEC.md line 137's UNANCHORED — **zero headline-eligible
//!   anchors**, which a `--force-degraded` work carrying one pending `.ots`
//!   satisfies while `NagState` calls it `OnlyPendingOts` and
//!   `WorkRow::unanchored` is `false`. `list` does **not** print that
//!   sentence; `status` (U23) computes it per anchor.
//!
//! ## Why the TSA half is recomputed rather than read
//!
//! A15's nag rule turns on `StoredTsaAnchor::verified`, and **the vault
//! stores no such bit**: `AnchorArtifact` is kind, endpoint, fetch date,
//! bytes and the D97 upgrade group. The tempting reading is the seal-time
//! invariant — `pipeline/anchors.rs` stores only captures that verified, so
//! hardcode `true` — and it is wrong for a reason that needs no attacker:
//! the capture verified against the root store **of the day it was taken**,
//! and headline eligibility is a statement about the root store *now*. A
//! root-store bump (the trigger A101 already records) silently turns a
//! stored token into `internally-consistent-only` without anything in the
//! vault changing, and the invariant would keep answering `true` — the nag
//! goes quiet on precisely the work that just lost its only strong anchor.
//! Editing the vault by hand is the same failure with an author.
//!
//! So [`WorkRow::nag`] recomputes it: `evaluate_tsa_artifact` over
//! `TsaArtifactView::from_parts`, against `TsaRootStore::pinned()`, reading
//! `AnchorVerdict::is_headline_eligible` — which is also what D98 rider 3c
//! requires the spec's UNANCHORED be computed from. It costs one full CMS
//! verification and path build per stored token (measured ~15–22 ms in a
//! debug build, per token, on the four pinned-root TSAs).
//!
//! ## `list` reads no clock, and needs none
//!
//! `evaluate_tsa_artifact` takes a `verify_at_unix`, and `list` passes the
//! constant [`NAG_VERIFY_AT_UNIX`]. That is sound rather than lazy:
//! `verify_at` is **one-sided** (D53 §5(b)) and separates only `proven`
//! from `valid-at-stamping-cert-since-expired` — and both of those are
//! headline-eligible, so the predicate the nag turns on is invariant under
//! it. Measured over all five real captures at `verify_at` ∈ {0, capture
//! time, 2060}, on both sides of the predicate; the invariance is asserted
//! in this module's tests so a future rule that made `verify_at` matter
//! goes red here.
//!
//! ## What `list` does not render
//!
//! No per-anchor state, and no human line for [`NagState::Anchored`] or
//! [`NagState::AttestedOnly`]. Per-anchor state is `status`'s (U23, D98:
//! A18's seven names computed per artifact); `list`'s job is the nag. The
//! class is in the `--json` row for machines either way.
//!
//! Note also that A15 folds an **unreadable** `.ots` into `AttestedOnly`
//! (`work_status` drops `Unreadable` artifacts before testing for pending
//! ones, then falls through), so that state means *"attested, or
//! unparseable"*. Rendering the word "attested" off it would publish the
//! conflation; `list` does not.

use antseal_anchor::ots::{NagState, PendingWork, StoredOtsAnchor, StoredTsaAnchor, work_status};
use antseal_core::anchor::model::TsaArtifactView;
use antseal_core::anchor::roots::TsaRootStore;
use antseal_core::anchor::verdicts::evaluate_tsa_artifact;
use antseal_core::crypto::secrets::SealId;
use antseal_core::manifest::anchor_digest;

use crate::error::CliError;
use crate::pipeline::anchors::{AnchorArtifact, StoredAnchors};
use crate::pipeline::journal::{JournalError, SealState, recorded_plan, recorded_state};
use crate::vault::store::{SealShapingFlags, WorkState, WorkStore};

/// The instant `list` evaluates every stored TSA token at.
///
/// A constant, not a clock, and `0` specifically because that is the value
/// the house already documents for a caller with no clock
/// (`VerifyOptions::with_verify_at_unix`: *"a caller with no clock loses
/// one distinction and no safety. `None` evaluates as `0`"*). The
/// distinction lost is `proven` versus
/// `valid-at-stamping-cert-since-expired`, and `list` renders neither.
///
/// D98 rider 2b's prohibition is honoured by construction: there is no
/// flag, env var or config key that reaches this, because an over-claim
/// knob on a nag is a knob that silences it.
pub const NAG_VERIFY_AT_UNIX: u64 = 0;

/// Which clock an unfinished seal is on (module docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResumeClock {
    /// Pre-pay: the journaled quote is stale by design; resume re-quotes
    /// and re-consents (D36). No time pressure.
    ReQuote,
    /// Post-receipt: the payment proofs are PUT-usable for roughly a day
    /// (D37); past that, finishing costs a second payment.
    TimeBoxed,
}

impl ResumeClock {
    /// Stable kebab identifier for `--json`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::ReQuote => "re-quote",
            Self::TimeBoxed => "time-boxed",
        }
    }

    /// The human note the row carries.
    #[must_use]
    pub const fn note(self) -> &'static str {
        match self {
            Self::ReQuote => {
                "nothing was paid; the recorded quote is stale by design — resuming re-quotes \
                 at current prices and asks for consent again"
            }
            Self::TimeBoxed => {
                "RESUME PROMPTLY: this seal is paid for, and the payment proofs stay usable for \
                 uploading only about a day — after that, finishing it costs a second payment"
            }
        }
    }
}

/// How to finish an unfinished seal: the exact invocation, and the clock
/// it is on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResumeHint {
    /// The recorded invocation, reproduced verbatim from D45's identity
    /// block — the `seal` re-run that will exact-match this work rather
    /// than starting a second one.
    pub invocation: String,
    /// Which clock this work is on.
    pub clock: ResumeClock,
}

/// One work's row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkRow {
    /// `work_id = SHA-256(manifest body)` — absent until the manifest was
    /// built (a seal killed during staging has none yet).
    pub work_id: Option<[u8; 32]>,
    /// The vault's store key.
    pub seal_id: SealId,
    /// `--title`, as recorded (D45 identity block).
    pub title: Option<String>,
    /// When the user consented to this permanent seal, Unix seconds —
    /// see [`WorkListing`] docs for why this is the date `list` shows.
    pub sealed_at_unix_secs: Option<u64>,
    /// The work's network, canonical CLI spelling.
    pub network: String,
    /// The coarse state (always available, survives `vault import`).
    pub state: WorkState,
    /// The fine state (S10's journal tag), when the journal still carries
    /// it.
    pub fine_state: Option<SealState>,
    /// Sealed with `--no-anchor`: the UNANCHORED class.
    pub unanchored: bool,
    /// Sealed with `--force-degraded`.
    pub degraded: bool,
    /// Total storage cost, atto-ANT, as journaled at seal.
    pub cost_atto: Option<u128>,
    /// Present exactly for unfinished works.
    pub resume: Option<ResumeHint>,
    /// How many OTS calendar attestations this work is still waiting on —
    /// summed over its `.ots` artifacts, in the sense A15's
    /// `OtsAnchorStatus::pending_uris` gives the word.
    ///
    /// The slot U19 reserved, filled by U25 (D98 rider 3a): its documented
    /// meaning is unchanged, and `None → Some(n)` is exactly what
    /// *"reserved"* promised, so nothing an existing `--json` consumer
    /// reads changes meaning.
    ///
    /// `Some(0)` and `None` are different facts. `Some(0)` means *counted,
    /// and there are none*; `None` means **not computable** — see
    /// [`Self::nag`].
    pub pending_anchors: Option<u64>,
    /// Whether this work should be nagged about, and why not when it
    /// should not be (D98 rider 3b).
    ///
    /// `None` means the class could not be computed: this work holds
    /// anchor artifacts but no recoverable `anchor_digest`, so nothing can
    /// be said about what they attest to. That needs the journaled
    /// manifest to be gone while the artifacts remain — a damaged or
    /// hand-edited vault, since S29 keeps journal entries 0–2 across
    /// `vault import`. `list` renders it as unclassified rather than
    /// guessing a class or failing the whole listing, because a listing
    /// that refuses to run is the one thing a user on a damaged vault
    /// cannot work around.
    pub nag: Option<NagState>,
}

impl WorkRow {
    /// The coarse state identifier a user sees: `complete`, `incomplete`
    /// or `abandoned`.
    #[must_use]
    pub const fn state_name(&self) -> &'static str {
        match self.state {
            WorkState::IncompletePrePay | WorkState::IncompletePostPay => "incomplete",
            WorkState::Complete => "complete",
            WorkState::Abandoned => "abandoned",
        }
    }

    /// The finest state identifier available: S10's journal tag when the
    /// vault still carries it, otherwise the coarse mirror's own spelling.
    #[must_use]
    pub const fn detail_state_name(&self) -> &'static str {
        match self.fine_state {
            Some(state) => state.name(),
            None => match self.state {
                WorkState::IncompletePrePay => "incomplete-pre-pay",
                WorkState::IncompletePostPay => "incomplete-post-pay",
                WorkState::Complete => "complete",
                WorkState::Abandoned => "abandoned",
            },
        }
    }

    /// The nag class's kebab identifier for `--json`, or `None` when the
    /// class could not be computed ([`Self::nag`]).
    ///
    /// The table lives here rather than on [`NagState`] because the enum is
    /// `antseal-anchor`'s and `list` is the renderer; it is written
    /// wildcard-free so a fifth state fails compilation at this line
    /// instead of acquiring a wrong name in a `_` arm.
    #[must_use]
    pub const fn nag_name(&self) -> Option<&'static str> {
        match self.nag {
            Some(NagState::Anchored) => Some("anchored"),
            Some(NagState::OnlyPendingOts) => Some("only-pending-ots"),
            Some(NagState::AttestedOnly) => Some("attested-only"),
            Some(NagState::Unanchored) => Some("unanchored"),
            None => None,
        }
    }

    /// Whether `list` shows the nag marker for this row.
    ///
    /// Delegates to [`NagState::nags`] — there is no second rule here. An
    /// unclassified row does not nag: `list` says it cannot tell, which is
    /// a different sentence and is rendered as one.
    #[must_use]
    pub const fn nags(&self) -> bool {
        match self.nag {
            Some(nag) => nag.nags(),
            None => false,
        }
    }

    /// The state badge, UNANCHORED included — the one place the
    /// orthogonal anchor class is folded into the state column.
    ///
    /// Untouched by U25 and deliberately so: this UNANCHORED is the
    /// `--no-anchor` flag, the first of the three predicates the module
    /// docs keep apart. The nag is rendered beside the row, never folded
    /// into this string.
    #[must_use]
    pub fn badge(&self) -> String {
        let mut badge = self.state_name().to_owned();
        if self.unanchored {
            badge.push_str(" UNANCHORED");
        }
        if self.degraded {
            badge.push_str(" (degraded anchors)");
        }
        badge
    }
}

/// Everything `list` gathered, in display order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkListing {
    /// One row per work, newest first (see [`WorkListing::gather`]).
    pub works: Vec<WorkRow>,
}

impl WorkListing {
    /// Read every work in the vault.
    ///
    /// **Order**: newest first by seal date, works with no recorded date
    /// last, ties broken by seal id — total and deterministic, so a
    /// snapshot or a script sees a stable sequence.
    ///
    /// **The date**: the D36 consent timestamp. It is the moment the user
    /// agreed to make this seal permanent, it is within the same
    /// invocation as the manifest's `claimed_time`, and — unlike
    /// `claimed_time`, which lives in the journaled manifest — it rides in
    /// the meta record, so it survives a `vault import`. A work killed
    /// before consent has no date, which is honest: nothing was sealed.
    ///
    /// # Errors
    ///
    /// Store-level failures, as their CLI classes. A record that cannot be
    /// read is *not* softened into a row: an unreadable work record means
    /// a damaged or tampered vault, which `list` reports as such rather
    /// than rendering a partial picture that looks complete.
    pub fn gather(store: &WorkStore<'_>) -> Result<Self, CliError> {
        let mut works = Vec::new();
        for seal_id in store.list_works().map_err(CliError::from)? {
            let record = store.load_meta(&seal_id).map_err(CliError::from)?;
            // The fine tag is preferred; its absence is a state, not a
            // failure (module docs).
            let fine_state =
                recorded_state(store, &seal_id).map_err(|err: JournalError| CliError::from(err))?;
            // U25's column. Same discipline as the two reads above: an
            // artifact that cannot be decoded fails the listing rather
            // than being softened into a row, because a work rendered
            // "no anchors" when its slot is unreadable is the one wrong
            // answer a nag must never give.
            let nag = anchor_nag(store, &seal_id, record.work_id, NAG_VERIFY_AT_UNIX)
                .map_err(|err: JournalError| CliError::from(err))?;
            let state = record.state;
            let resume = match state {
                WorkState::IncompletePrePay => Some(ResumeHint {
                    invocation: seal_invocation(
                        &record.input_paths_as_given,
                        &record.shaping,
                        &record.network,
                    ),
                    clock: ResumeClock::ReQuote,
                }),
                WorkState::IncompletePostPay => Some(ResumeHint {
                    invocation: seal_invocation(
                        &record.input_paths_as_given,
                        &record.shaping,
                        &record.network,
                    ),
                    clock: ResumeClock::TimeBoxed,
                }),
                WorkState::Complete | WorkState::Abandoned => None,
            };
            works.push(WorkRow {
                work_id: record.work_id,
                seal_id,
                title: record.shaping.title.clone(),
                sealed_at_unix_secs: record.consent.map(|c| c.consent_time_unix_secs),
                network: record.network.clone(),
                state,
                fine_state,
                unanchored: record.unanchored,
                degraded: record.degraded,
                cost_atto: record.cost_atto,
                resume,
                pending_anchors: nag.as_ref().map(|read| read.pending),
                nag: nag.map(|read| read.nag),
            });
        }
        works.sort_by(|a, b| {
            // Newest first; undated last; seal id as the total tie-break.
            b.sealed_at_unix_secs
                .cmp(&a.sealed_at_unix_secs)
                .then_with(|| a.seal_id.as_bytes().cmp(b.seal_id.as_bytes()))
        });
        Ok(Self { works })
    }

    /// How many works are in each class (the summary line, and the
    /// `--json` counts object).
    #[must_use]
    pub fn counts(&self) -> ListingCounts {
        let mut counts = ListingCounts {
            total: self.works.len(),
            ..ListingCounts::default()
        };
        for row in &self.works {
            match row.state {
                WorkState::Complete => counts.complete += 1,
                WorkState::IncompletePrePay | WorkState::IncompletePostPay => {
                    counts.incomplete += 1;
                }
                WorkState::Abandoned => counts.abandoned += 1,
            }
            if row.unanchored {
                counts.unanchored += 1;
            }
            if row.nags() {
                counts.pending_anchor_nags += 1;
            }
        }
        counts
    }

    /// The `--json` result document (U3's envelope wraps it).
    ///
    /// Amounts are decimal **strings**: atto-ANT is an 18-decimal unit, so
    /// real values sit far above the 2^53 a JSON number survives in most
    /// consumers. The house already takes this route for EVM addresses —
    /// exactness beats convenience in a machine contract.
    #[must_use]
    pub fn json(&self) -> serde_json::Value {
        let counts = self.counts();
        serde_json::json!({
            "works": self.works.iter().map(row_json).collect::<Vec<_>>(),
            "counts": {
                "total": counts.total,
                "complete": counts.complete,
                "incomplete": counts.incomplete,
                "abandoned": counts.abandoned,
                "unanchored": counts.unanchored,
                "pending_anchor_nags": counts.pending_anchor_nags,
            },
        })
    }

    /// The human report, as lines (the caller routes them to stdout or —
    /// under `--json` — to stderr, D51).
    #[must_use]
    pub fn render(&self) -> Vec<String> {
        let mut out = Vec::new();
        if self.works.is_empty() {
            out.push("No sealed works in this vault yet.".to_owned());
            return out;
        }
        for row in &self.works {
            let id = row.work_id.as_ref().map_or_else(
                || format!("(no work id yet; seal {})", hex_seal(&row.seal_id)),
                crate::pipeline::hex32,
            );
            out.push(format!("{id}  {}", row.badge()));
            let title = row.title.as_deref().unwrap_or("(untitled)");
            let when = row
                .sealed_at_unix_secs
                .map_or_else(|| "not yet sealed".to_owned(), format_utc);
            out.push(format!("  {title}   {when}   {}", row.network));
            match row.cost_atto {
                Some(cost) => out.push(format!("  cost: {cost} atto-ANT")),
                None => out.push("  cost: not recorded (nothing paid)".to_owned()),
            }
            out.extend(nag_lines(row));
            if let Some(resume) = &row.resume {
                out.push(format!("  state: {}", row.detail_state_name()));
                out.push(format!("  {}", resume.clock.note()));
                out.push(format!("  resume with: {}", resume.invocation));
            }
        }
        let counts = self.counts();
        // Two orthogonal notes in one parenthetical, kept as separate
        // clauses because they are separate predicates: UNANCHORED is the
        // `--no-anchor` flag, the nag count is A15's `OnlyPendingOts`.
        let mut notes = Vec::new();
        if counts.unanchored > 0 {
            notes.push(format!("{} UNANCHORED", counts.unanchored));
        }
        if counts.pending_anchor_nags > 0 {
            notes.push(format!(
                "{} waiting on pending anchors",
                counts.pending_anchor_nags
            ));
        }
        out.push(format!(
            "{} work(s): {} complete, {} incomplete, {} abandoned{}.",
            counts.total,
            counts.complete,
            counts.incomplete,
            counts.abandoned,
            if notes.is_empty() {
                String::new()
            } else {
                format!(" ({})", notes.join(", "))
            }
        ));
        out
    }
}

/// The nag block for one row: nothing at all for a work with nothing to
/// chase.
///
/// Two lines when it nags — the marker with its count, and the exact
/// command that changes the state — because a marker with no next step is
/// a complaint rather than a nag. The hint's wording is D98 rider 5's:
/// `status`'s reader **is** the sealer, so it is second-person and names
/// the command, unlike MVP-SPEC.md line 130's `pending` copy, which is
/// written for the third-party verifier page (R18 owns re-aligning the
/// two at M3).
fn nag_lines(row: &WorkRow) -> Vec<String> {
    if row.nag.is_none() {
        return vec![
            "  anchors: unclassified — this work holds anchor artifacts but its journaled \
             manifest is gone, so what they attest to cannot be recovered"
                .to_owned(),
        ];
    }
    if !row.nags() {
        return Vec::new();
    }
    let count = row.pending_anchors.unwrap_or_default();
    let mut lines = vec![format!(
        "  ANCHORS PENDING: {count} calendar attestation(s) not yet confirmed by Bitcoin, and \
         nothing else here proves a time independently"
    )];
    // A work that never reached `record_outcome` has no work id, and
    // `status` takes one (`cli.rs`'s `WORK-ID`). Printing the hint with a
    // hole in it would be worse than saying which step comes first.
    match row.work_id.as_ref() {
        Some(work_id) => lines.push(format!(
            "  run antseal status {} --upgrade",
            crate::pipeline::hex32(work_id)
        )),
        None => lines.push(
            "  no work id yet — finish this seal first, then run antseal status <id> --upgrade"
                .to_owned(),
        ),
    }
    lines
}

/// What `list` concluded about one work's anchor set.
struct NagRead {
    /// A15's class.
    nag: NagState,
    /// Pending OTS calendar attestations, summed over the `.ots`
    /// artifacts.
    pending: u64,
}

/// Read one work's anchor set and classify it (**U25**).
///
/// `Ok(None)` means *unclassifiable*: artifacts exist but the
/// `anchor_digest` they commit cannot be recovered, so neither A15's rule
/// nor A18's evaluator can be run over them. See [`WorkRow::nag`] for why
/// that is rendered rather than failed.
///
/// # Errors
///
/// Whatever [`StoredAnchors::read`] and
/// [`recorded_plan`](crate::pipeline::journal::recorded_plan) raise —
/// store-level failures, [`JournalError::NewerRecord`] for a record from a
/// newer antseal, and [`JournalError::Corrupt`] for a malformed one. None
/// is softened.
fn anchor_nag(
    store: &WorkStore<'_>,
    seal_id: &SealId,
    work_id: Option<[u8; 32]>,
    verify_at_unix: u64,
) -> Result<Option<NagRead>, JournalError> {
    let anchors = StoredAnchors::read(store, seal_id)?;
    // No artifacts is a complete answer on its own, and it is the only
    // branch that needs no digest — which is why it comes first rather
    // than falling out of the classifier with a fabricated one.
    if anchors.is_empty() {
        return Ok(Some(NagRead {
            nag: NagState::Unanchored,
            pending: 0,
        }));
    }
    // `anchor_digest` is SHA-256 of the plaintext manifest envelope and is
    // not on `WorkRecord`; the journaled plan is where the bytes are, and
    // S29 keeps that record across `vault import` (module docs).
    let Some(manifest_bytes) = recorded_plan(store, seal_id)?.and_then(|plan| plan.manifest_bytes)
    else {
        return Ok(None);
    };
    Ok(Some(classify_anchors(
        anchors.ots(),
        anchors.tsa(),
        anchor_digest(&manifest_bytes).as_bytes(),
        work_id.unwrap_or_default(),
        verify_at_unix,
    )))
}

/// Run A15's per-work nag rule over one work's decoded artifacts.
///
/// The rule itself is **not** reimplemented here: this assembles
/// `PendingWork` and calls [`work_status`], so `list` and `status` cannot
/// drift on what "nag" means (D98's ruling — A15 owns the per-work nag,
/// A18 owns the per-artifact state, and neither is projected into the
/// other).
///
/// `work_id` is `PendingWork`'s identity tag, which [`work_status`] only
/// echoes back into a field this function discards; the classification
/// never reads it. A work with anchors but no recorded `work_id` — killed
/// between the anchor stage and `finalize` — therefore classifies exactly
/// as it would with one.
fn classify_anchors(
    ots: &[(String, AnchorArtifact)],
    tsa: &[(String, AnchorArtifact)],
    anchor_digest: &[u8; 32],
    work_id: [u8; 32],
    verify_at_unix: u64,
) -> NagRead {
    let work = PendingWork {
        work_id,
        anchor_digest: *anchor_digest,
        ots: ots
            .iter()
            .map(|(_, artifact)| StoredOtsAnchor {
                artifact: artifact.bytes.clone(),
                upgrade: artifact.upgrade.clone(),
            })
            .collect(),
        tsa: tsa
            .iter()
            .map(|(_, artifact)| StoredTsaAnchor {
                // A record in a `tsa-<n>` slot is a token by
                // construction: `StoredAnchors::assemble` refuses a record
                // whose kind disagrees with its slot family.
                token_present: true,
                verified: tsa_is_headline_eligible(artifact, anchor_digest, verify_at_unix),
                fetch_date: artifact.fetch_date,
            })
            .collect(),
    };
    let status = work_status(&work);
    let pending: usize = status
        .ots
        .iter()
        .map(|anchor| anchor.pending_uris.len())
        .sum();
    NagRead {
        nag: status.nag,
        // Saturating rather than panicking: an artifact holding more than
        // 2^64 attestations is unreachable (the container is bounded long
        // before this), and library code does not unwrap.
        pending: u64::try_from(pending).unwrap_or(u64::MAX),
    }
}

/// Whether one stored TSA capture is headline-eligible **now**, recomputed
/// from its bytes.
///
/// The one un-persisted input to A15's nag rule, and the module docs argue
/// why it is recomputed rather than assumed from the seal-time invariant.
///
/// Intermediates are `&[]`, and that is the same input `verify` will get:
/// `validate_token_chain` pools the token's own `chain_material()` with the
/// bundle's, nothing in `antseal-cli` has ever populated
/// `TsaAnchor::intermediates`, and all four pinned-root TSAs self-carry
/// their chains. The error direction is monotone — omitting certificates
/// can only shrink the candidate-path set — so this can under-claim
/// eligibility and never over-claim it, which for a nag means it can only
/// ever nag too much. (A101 records the day a configured TSA stops
/// self-carrying.)
fn tsa_is_headline_eligible(
    artifact: &AnchorArtifact,
    anchor_digest: &[u8; 32],
    verify_at_unix: u64,
) -> bool {
    let view = TsaArtifactView::from_parts(&artifact.bytes, &[], artifact.fetch_date);
    evaluate_tsa_artifact(&view, anchor_digest, TsaRootStore::pinned(), verify_at_unix)
        .verdict()
        .is_headline_eligible()
}

/// Per-class counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ListingCounts {
    /// Every work.
    pub total: usize,
    /// `finalize_batch` succeeded.
    pub complete: usize,
    /// Still resumable.
    pub incomplete: usize,
    /// Abandoned (S11's safety outcome).
    pub abandoned: usize,
    /// Sealed with `--no-anchor` (orthogonal to the three above).
    pub unanchored: usize,
    /// Works whose only strong anchor is still pending — U25's nag, and
    /// orthogonal to every count above. **Not** the same set as
    /// `unanchored`: that one is the `--no-anchor` flag (module docs).
    pub pending_anchor_nags: usize,
}

fn row_json(row: &WorkRow) -> serde_json::Value {
    serde_json::json!({
        "work_id": row.work_id.as_ref().map(crate::pipeline::hex32),
        "seal_id": hex_seal(&row.seal_id),
        "title": row.title,
        "sealed_at": row.sealed_at_unix_secs,
        "network": row.network,
        "state": row.state_name(),
        "detail_state": row.detail_state_name(),
        "unanchored": row.unanchored,
        "degraded": row.degraded,
        "cost_atto": row.cost_atto.map(|c| c.to_string()),
        "resume": row.resume.as_ref().map(|hint| serde_json::json!({
            "invocation": hint.invocation,
            "clock": hint.clock.name(),
            "note": hint.clock.note(),
        })),
        // U25 (M2). Both `null` together, and only for a work whose
        // anchor class could not be computed (see `WorkRow::nag`).
        "pending_anchors": row.pending_anchors,
        "nag": row.nag_name(),
    })
}

/// Rebuild the recorded `seal` invocation from D45's identity block.
///
/// Reproduced **verbatim**: the paths exactly as the user gave them, and
/// every seal-shaping flag that was recorded — because D45 matches a
/// resume on precisely this tuple, and a hint that dropped a flag would
/// print a command that starts a *second* seal instead of finishing this
/// one. Session flags (`--yes`, `--json`, `--passphrase-fd`, `--dry-run`)
/// are deliberately absent: they are not identity, and reprinting them
/// would be advice rather than a record.
///
/// `--network` is included whenever the work's network is not the built-in
/// default, since the effective network *is* part of D45's identity and
/// the config file could resolve it differently on the next run.
#[must_use]
pub fn seal_invocation(paths: &[String], shaping: &SealShapingFlags, network: &str) -> String {
    let mut parts = vec!["antseal".to_owned(), "seal".to_owned()];
    for path in paths {
        parts.push(shell_quote(path));
    }
    if let Some(title) = &shaping.title {
        parts.push("--title".to_owned());
        parts.push(shell_quote(title));
    }
    if shaping.split_blank_lines {
        parts.push("--split".to_owned());
        parts.push("blank-lines".to_owned());
    }
    if shaping.force_text {
        parts.push("--force-text".to_owned());
    }
    for glob in &shaping.no_fine_tree {
        parts.push("--no-fine-tree".to_owned());
        parts.push(shell_quote(glob));
    }
    if shaping.no_anchor {
        parts.push("--no-anchor".to_owned());
    }
    if shaping.force_degraded {
        parts.push("--force-degraded".to_owned());
    }
    if network != antseal_net::NetworkId::default().as_str() {
        parts.push("--network".to_owned());
        parts.push(network.to_owned());
    }
    parts.join(" ")
}

/// Single-quote a token that a shell would otherwise re-split or expand.
/// Anything outside a conservative safe set is quoted; embedded single
/// quotes take the POSIX `'\''` dance. A token that needs nothing is
/// printed exactly as recorded — which is what "verbatim" means for the
/// overwhelmingly common case.
fn shell_quote(token: &str) -> String {
    let safe = !token.is_empty()
        && token.chars().all(|c| {
            c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '/' | '+' | '=' | ':' | ',')
        });
    if safe {
        return token.to_owned();
    }
    format!("'{}'", token.replace('\'', r"'\''"))
}

fn hex_seal(seal_id: &SealId) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(32);
    for byte in seal_id.as_bytes() {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Unix seconds as `YYYY-MM-DD HH:MM:SS UTC` (the same std-only calendar
/// arithmetic `commands.rs` uses for export filenames; no chrono-class
/// dependency for two renderers).
fn format_utc(unix_secs: u64) -> String {
    let (y, mo, d, h, mi, s) = crate::commands::civil_utc(unix_secs);
    format!("{y:04}-{mo:02}-{d:02} {h:02}:{mi:02}:{s:02} UTC")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pipeline::anchors::{ArtifactKind, OTS_SLOT, tsa_slot};

    // ── U25's fixture material ───────────────────────────────────────
    //
    // NON-SECRET: every byte below is committed public cryptographic
    // material — real RFC 3161 responses, a real merged `.ots`, and the F12
    // golden manifest envelope. No key, salt or `W` appears here.
    //
    // These three files agree on **one digest** and that is what makes the
    // matrix buildable at all: `D60-CAPTURE.log` records the nine `D60-*`
    // tokens as stamped over
    // `083f87df…69df` "( = testdata/vectors/v1/manifest/manifest.json
    // anchor_digest )", `CAPTURE.log` records the same value as its
    // `digest_A` for the three calendar submissions merged into
    // `merged-A.ots`, and `anchor_digest` is bare SHA-256 of the manifest
    // envelope — so the golden envelope bytes are a *preimage* the fixture
    // can journal as a plan record.

    /// A real, verified DigiCert `TimeStampResp` over the fixture digest —
    /// chains to a root pinned in store v1.
    const TSA_PINNED: &[u8] =
        include_bytes!("../../../testdata/anchors/A25-bootstrap/D60-tsa-digicert-resp.tsr");

    /// A real GlobalSign `TimeStampResp` over the same digest, whose root is
    /// **deliberately outside store v1** — the shape a root-store bump
    /// leaves behind, and the case the seal-time `verified` invariant gets
    /// wrong.
    const TSA_UNPINNED: &[u8] =
        include_bytes!("../../../testdata/anchors/A25-bootstrap/D60-tsa-globalsign-resp.tsr");

    /// A real merged `.ots` over the same digest: three calendar
    /// attestations, none yet confirmed by Bitcoin.
    const OTS_PENDING: &[u8] =
        include_bytes!("../../../testdata/anchors/A25-bootstrap/merged-A.ots");

    /// A real upgraded `.ots` over a **different** digest — unreadable
    /// against this fixture's `anchor_digest`.
    const OTS_FOREIGN: &[u8] = include_bytes!(
        "../../../testdata/anchors/A25-bootstrap/upgraded/rust-opentimestamps-LARGE_TEST.ots"
    );

    /// The F12 golden manifest envelope whose SHA-256 is the digest all
    /// three captures were taken over.
    fn fixture_manifest_bytes() -> Vec<u8> {
        let doc: serde_json::Value = serde_json::from_str(include_str!(
            "../../../testdata/vectors/v1/manifest/manifest.json"
        ))
        .expect("the F12 manifest vectors parse");
        let hex = doc["expect"]["cases"][1]["manifest_bytes"]
            .as_str()
            .expect("case 1 carries its envelope bytes");
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("vector hex"))
            .collect()
    }

    fn fixture_digest() -> [u8; 32] {
        *anchor_digest(&fixture_manifest_bytes()).as_bytes()
    }

    fn ots(bytes: &[u8]) -> Vec<(String, AnchorArtifact)> {
        vec![(
            OTS_SLOT.to_owned(),
            AnchorArtifact {
                kind: ArtifactKind::OtsPending,
                endpoint: String::new(),
                fetch_date: 1_798_761_600,
                bytes: bytes.to_vec(),
                upgrade: None,
            },
        )]
    }

    fn tsa(bytes: &[u8]) -> Vec<(String, AnchorArtifact)> {
        vec![(
            tsa_slot(0),
            AnchorArtifact {
                kind: ArtifactKind::TsaToken,
                endpoint: "tsa-fixture:committed-capture".to_owned(),
                fetch_date: 1_798_761_600,
                bytes: bytes.to_vec(),
                upgrade: None,
            },
        )]
    }

    /// The fixture material really does agree on one digest — asserted
    /// rather than trusted, because the whole matrix below is vacuous if
    /// the captures and the golden envelope ever stop lining up.
    #[test]
    fn the_committed_captures_and_the_golden_envelope_share_one_anchor_digest() {
        const STAMPED: &str = "083f87df00fd5c703d35b883d83535644c686f9e53f1584d7df126abdabd69df";
        assert_eq!(
            anchor_digest(&fixture_manifest_bytes()).to_string(),
            STAMPED,
            "D60-CAPTURE.log's stamped digest and CAPTURE.log's digest_A"
        );
        let parsed = antseal_core::anchor::ots::parse_ots(OTS_PENDING, &fixture_digest())
            .expect("the merged .ots commits this digest");
        assert_eq!(parsed.attestations.len(), 3, "three calendars, none buried");
    }

    /// **U25 accept row 1, the no-nag arm**: a work carrying a TSA token
    /// that verifies against the pinned roots is `anchored` and does not
    /// nag — even though its `.ots` half is still pending. A headline
    /// anchor already exists; there is nothing to chase.
    #[test]
    fn a_work_with_a_pinned_root_tsa_token_does_not_nag() {
        let read = classify_anchors(
            &ots(OTS_PENDING),
            &tsa(TSA_PINNED),
            &fixture_digest(),
            [0xA1; 32],
            NAG_VERIFY_AT_UNIX,
        );
        assert_eq!(read.nag, NagState::Anchored);
        assert!(!read.nag.nags());
        assert_eq!(
            read.pending, 3,
            "the count is still reported: it is a fact about the .ots, not about the nag"
        );
    }

    /// **U25 accept row 1, the nag arm**: a work whose only anchor is a
    /// pending `.ots` nags, and the count is the number of calendars.
    #[test]
    fn a_work_whose_only_anchor_is_a_pending_ots_nags() {
        let read = classify_anchors(
            &ots(OTS_PENDING),
            &[],
            &fixture_digest(),
            [0xA2; 32],
            NAG_VERIFY_AT_UNIX,
        );
        assert_eq!(read.nag, NagState::OnlyPendingOts);
        assert!(read.nag.nags());
        assert_eq!(read.pending, 3);
    }

    /// **U25 accept row 1, the UNANCHORED arm**: no artifacts at all is
    /// `unanchored`, never "pending" — and its count is a counted zero,
    /// not the `None` that means "could not tell".
    #[test]
    fn a_work_with_no_artifacts_is_unanchored_and_never_pending() {
        let read = classify_anchors(&[], &[], &fixture_digest(), [0xA3; 32], NAG_VERIFY_AT_UNIX);
        assert_eq!(read.nag, NagState::Unanchored);
        assert!(!read.nag.nags());
        assert_eq!(read.pending, 0);
        assert_ne!(
            WorkRow::nag_name(&row_with(Some(NagState::Unanchored))),
            WorkRow::nag_name(&row_with(Some(NagState::OnlyPendingOts))),
            "the two classes must not render as one word"
        );
    }

    /// **The `verified` gap, ruled.** A token whose root is not in store
    /// v1 is not headline-eligible, so it must not silence the nag — the
    /// answer the seal-time invariant (*"only verified captures are
    /// stored, so hardcode `true`"*) gets wrong. This needs no hand-edited
    /// vault: the capture verified on the day it was taken, and a root
    /// store that later stops carrying its root is the ordinary way a
    /// stored token arrives in this state.
    #[test]
    fn a_token_whose_root_is_not_pinned_does_not_silence_the_nag() {
        assert!(
            !tsa_is_headline_eligible(
                &tsa(TSA_UNPINNED)[0].1,
                &fixture_digest(),
                NAG_VERIFY_AT_UNIX
            ),
            "GlobalSign's root is deliberately outside store v1"
        );
        let read = classify_anchors(
            &ots(OTS_PENDING),
            &tsa(TSA_UNPINNED),
            &fixture_digest(),
            [0xA4; 32],
            NAG_VERIFY_AT_UNIX,
        );
        assert_eq!(
            read.nag,
            NagState::OnlyPendingOts,
            "a present-but-unverifiable token is evidence of nothing, and the nag must survive it"
        );
    }

    /// **`list` needs no clock, and this is why.** `verify_at` is
    /// one-sided (D53 §5(b)) and separates only `proven` from
    /// `valid-at-stamping-cert-since-expired`, both of which are
    /// headline-eligible — so the nag is invariant under it. Driven over
    /// both sides of the predicate at three times spanning 1970, capture
    /// time and 2060; a rule change that made `verify_at` reach the nag
    /// fails here rather than in a user's vault.
    #[test]
    fn the_nag_is_invariant_under_the_verification_time() {
        for verify_at in [0, 1_785_000_000, 2_840_000_000] {
            assert_eq!(
                classify_anchors(
                    &ots(OTS_PENDING),
                    &tsa(TSA_PINNED),
                    &fixture_digest(),
                    [0xA5; 32],
                    verify_at,
                )
                .nag,
                NagState::Anchored,
                "pinned-root token at verify_at={verify_at}"
            );
            assert_eq!(
                classify_anchors(
                    &ots(OTS_PENDING),
                    &tsa(TSA_UNPINNED),
                    &fixture_digest(),
                    [0xA5; 32],
                    verify_at,
                )
                .nag,
                NagState::OnlyPendingOts,
                "unpinned-root token at verify_at={verify_at}"
            );
        }
    }

    /// **Recorded, not endorsed.** A15 drops `Unreadable` artifacts before
    /// testing for pending ones and then falls through to `AttestedOnly`,
    /// so an `.ots` that does not parse against this work's
    /// `anchor_digest` lands in the state whose doc says *"every OTS
    /// anchor is already attested"* — and stops nagging. `list` therefore
    /// never renders the word "attested" off that state (module docs).
    /// This pins the behaviour so a fix upstream shows up as a diff here.
    #[test]
    fn an_unreadable_ots_is_folded_into_attested_only_and_stops_nagging() {
        let read = classify_anchors(
            &ots(OTS_FOREIGN),
            &[],
            &fixture_digest(),
            [0xA6; 32],
            NAG_VERIFY_AT_UNIX,
        );
        assert_eq!(read.nag, NagState::AttestedOnly);
        assert!(!read.nag.nags(), "A15's rule, recorded rather than agreed");
        assert_eq!(read.pending, 0);
    }

    /// Every class has its own kebab spelling, and an unclassified row has
    /// none — four states plus the absent one, all distinct.
    #[test]
    fn each_nag_class_has_its_own_name() {
        let names: Vec<Option<&'static str>> = [
            Some(NagState::Anchored),
            Some(NagState::OnlyPendingOts),
            Some(NagState::AttestedOnly),
            Some(NagState::Unanchored),
            None,
        ]
        .into_iter()
        .map(|nag| row_with(nag).nag_name())
        .collect();
        assert_eq!(
            names,
            vec![
                Some("anchored"),
                Some("only-pending-ots"),
                Some("attested-only"),
                Some("unanchored"),
                None,
            ]
        );
    }

    /// The nag block is two lines and names the command, and an
    /// unclassified row says so instead of guessing.
    #[test]
    fn the_nag_block_names_the_command_that_changes_the_state() {
        let mut row = row_with(Some(NagState::OnlyPendingOts));
        row.pending_anchors = Some(3);
        row.work_id = Some([0xA1; 32]);
        let lines = nag_lines(&row);
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("ANCHORS PENDING: 3 calendar attestation(s)"));
        assert_eq!(
            lines[1],
            format!("  run antseal status {} --upgrade", "a1".repeat(32))
        );

        // A seal killed before `finalize` has artifacts but no work id,
        // and `status` takes one.
        row.work_id = None;
        assert!(nag_lines(&row)[1].contains("no work id yet"));

        // Every non-nagging class renders nothing at all.
        for nag in [
            NagState::Anchored,
            NagState::AttestedOnly,
            NagState::Unanchored,
        ] {
            assert!(nag_lines(&row_with(Some(nag))).is_empty(), "{nag:?}");
        }
        let unclassified = nag_lines(&row_with(None));
        assert_eq!(unclassified.len(), 1);
        assert!(unclassified[0].contains("unclassified"));
    }

    /// A bare row carrying one nag class, for the rendering assertions.
    fn row_with(nag: Option<NagState>) -> WorkRow {
        WorkRow {
            work_id: None,
            seal_id: SealId::from_bytes([0xE1; 16]),
            title: None,
            sealed_at_unix_secs: None,
            network: "devnet".to_owned(),
            state: WorkState::Complete,
            fine_state: None,
            unanchored: false,
            degraded: false,
            cost_atto: None,
            resume: None,
            pending_anchors: nag.map(|_| 0),
            nag,
        }
    }

    fn shaping() -> SealShapingFlags {
        SealShapingFlags {
            title: Some("my thesis".to_owned()),
            split_blank_lines: true,
            force_text: false,
            no_fine_tree: vec!["*.png".to_owned()],
            no_anchor: true,
            force_degraded: false,
        }
    }

    #[test]
    fn the_resume_hint_reproduces_every_identity_flag() {
        let hint = seal_invocation(
            &["chapter one.txt".to_owned(), "notes.md".to_owned()],
            &shaping(),
            "devnet",
        );
        assert_eq!(
            hint,
            "antseal seal 'chapter one.txt' notes.md --title 'my thesis' --split blank-lines \
             --no-fine-tree '*.png' --no-anchor --network devnet"
        );
    }

    #[test]
    fn a_bare_invocation_stays_bare() {
        let hint = seal_invocation(
            &["a.txt".to_owned()],
            &SealShapingFlags::default(),
            "arbitrum-one",
        );
        assert_eq!(
            hint, "antseal seal a.txt",
            "no flags invented, no network noise"
        );
    }

    /// Session flags are not identity, so they never appear — and a path
    /// that could be re-split by a shell is quoted rather than mangled.
    #[test]
    fn quoting_is_conservative_and_reversible() {
        assert_eq!(shell_quote("plain-1.txt"), "plain-1.txt");
        assert_eq!(shell_quote("with space"), "'with space'");
        assert_eq!(shell_quote("it's"), r"'it'\''s'");
        assert_eq!(shell_quote("$(rm -rf /)"), "'$(rm -rf /)'");
        assert_eq!(shell_quote(""), "''");
    }

    #[test]
    fn the_two_clocks_say_opposite_things() {
        assert!(ResumeClock::ReQuote.note().contains("nothing was paid"));
        assert!(ResumeClock::TimeBoxed.note().contains("RESUME PROMPTLY"));
        assert_ne!(ResumeClock::ReQuote.note(), ResumeClock::TimeBoxed.note());
        assert_eq!(ResumeClock::ReQuote.name(), "re-quote");
        assert_eq!(ResumeClock::TimeBoxed.name(), "time-boxed");
    }
}
