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
//! nag' has four different meanings and rendering them identically is how
//! an UNANCHORED work comes to look merely pending"*).
//!
//! **The quoted count was `three` here and in D98 rider 3b, and both were
//! right when written**: D100 R7 added `NagState::Unreadable`, a fifth
//! variant that does not nag, taking the non-nagging count from three to
//! four — so the sentence being quoted now reads *four*. Corrected here
//! rather than in the decision record, which is immutable (Q122 is the open
//! question about dated corrections). The count is pinned by a test —
//! `status_command.rs`'s Q120 suite — so the next variant reddens instead
//! of quietly falsifying this paragraph a second time.
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
//! A15 used to fold an **unreadable** `.ots` into `AttestedOnly` — a state
//! whose own doc says *"every OTS anchor is already attested"* — so that
//! state meant *"attested, or unparseable"* and `list` refused to render the
//! word "attested" off it. **A102 is fixed** (D100 R7): the fifth state
//! [`NagState::Unreadable`] carries that case under its own name, and its
//! `nags()` stays `false` because the two-line PENDING block it would
//! otherwise print reads `ANCHORS PENDING: 0` and instructs `--upgrade`,
//! which cannot help bytes nothing can parse. A102's Accept row asked for
//! the literal word *"nags"* and was wrong about the boolean; it needed the
//! name.
//!
//! # A slot whose record will not open (U65, ruled by D100)
//!
//! One undecodable anchor record used to make `list` refuse the **entire
//! vault** — exit 12, *"wrong passphrase, or the vault store or header has
//! been modified or corrupted"* — for a CBOR schema refusal on plaintext the
//! AEAD had already accepted, with not one row emitted in either mode. It is
//! now a **datum**: [`WorkRow::damaged_anchors`], a summary clause, a
//! `--json` array and a `counts.damaged_anchors`, at **exit 0**.
//!
//! Three things make that safe rather than merely kinder:
//!
//! - **The split is exactly at the AEAD boundary.** A genuine authentication
//!   failure is `CipherError::AuthFailure` → `CliError::VaultAuthFailure`
//!   *directly* and never through `JournalError`, so the two populations do
//!   not share a producer and no unauthenticated caller can observe the
//!   distinction. U6's *"insofar as distinguishing them is safe"* is
//!   preserved, and codes 18 and 19 are the committed precedents for carving
//!   a distinguishable condition out of 12.
//! - **No `ErrorClass` is minted and no exit code moves.** `status` already
//!   renders the identical damage one layer down at exit 0 — an `.ots` whose
//!   *bytes* do not parse renders `invalid` — so a new class would put exit 0
//!   and exit N on two sides of a boundary the user cannot see.
//! - **The damage is not evidence**, so it gets no [`NagState`] and no
//!   `AnchorState`: a verdict cannot be stated without naming a mechanism,
//!   and the mechanism lives at key 0 *inside* the record that will not open.
//!
//! The cost, recorded rather than hidden: `list` exits 0 even on a vault
//! every one of whose works is unreadable. The rows say why and `--json`
//! counts it, and a script that must fail on vault damage tests
//! `.counts.damaged_anchors > 0`, which is strictly more expressive than one
//! exit code because it separates *upgrade antseal* from *your vault is
//! damaged* from *another antseal is running*.

use antseal_anchor::ots::{NagState, PendingWork, StoredOtsAnchor, StoredTsaAnchor, work_status};
use antseal_core::anchor::model::TsaArtifactView;
use antseal_core::anchor::roots::TsaRootStore;
use antseal_core::anchor::verdicts::evaluate_tsa_artifact;
use antseal_core::crypto::secrets::SealId;
use antseal_core::manifest::anchor_digest;

use crate::error::CliError;
use crate::pipeline::anchors::{
    AnchorArtifact, DamageReason, DamagedSlot, StoredAnchors, damaged_slot_json,
};
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
    /// Answers exactly one question: **was this seal made with
    /// `--no-anchor`?** A shaping input recorded at seal time
    /// (`pipeline/seal.rs`, from `request.no_anchor`), copied here and never
    /// recomputed — so it stays true for a `--no-anchor` work no matter what
    /// its vault later holds.
    ///
    /// It is **not** MVP-SPEC.md line 137's UNANCHORED (*zero
    /// headline-eligible anchors*, which is `WorkStatus::is_unanchored`) and
    /// **not** [`NagState::Unanchored`] (*no anchor records at all*). D98
    /// rider 3c forbids collapsing any two of the three, and
    /// `status_command.rs` pins a table of works on which they disagree
    /// (Q120). [`WorkRow::badge`] renders this one, and only this one.
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
    ///
    /// Summed over the artifacts that **decoded**, which is the only set
    /// there is anything to count in: a slot whose record will not open
    /// contributes no attestations because none can be read out of it. That
    /// is why [`Self::damaged_anchors`] is unconditional — a work with one
    /// damaged `ots-pending` slot and nothing else honestly reports
    /// `Some(0)` here, and only the damage array distinguishes it from a
    /// work that genuinely has nothing pending.
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
    /// The anchor slots of this work whose record could not be interpreted
    /// (**D100 R3**), and how many slots it holds in total.
    ///
    /// **Orthogonal to [`Self::nag`], and deliberately not folded into it**
    /// (R4). A work with a verified TSA token and one damaged slot renders
    /// `nag: "anchored"` — which is *true*, because it does hold a
    /// headline-eligible anchor — and this array is what stops that being
    /// read as the whole story. Suppressing `nag` to `None` on damage is
    /// refused: `None` already means *"no recoverable `anchor_digest`"*, and
    /// putting a second fact in one null is A102's disease one level up.
    ///
    /// The one case where the two are **not** orthogonal is a work whose
    /// only slots are damaged; that is [`NagState::Unreadable`]'s, decided in
    /// A15 rather than here (R7.3).
    pub damaged_anchors: AnchorDamage,
}

/// What one work's anchor slots could not be read, and out of how many.
///
/// The count is the whole reason per-record isolation beat a per-work badge:
/// a badge produced by catching an error at the work boundary can say
/// *damaged* and cannot say *1 of 4*, so on a work with three good anchors
/// and one bad slot it over-claims, and on a one-slot work it under-claims by
/// looking like the same event (D100 §2(b)).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AnchorDamage {
    /// One entry per unreadable slot, in the order the reader found them.
    /// **Empty, never absent**, for a healthy work.
    pub slots: Vec<DamagedSlot>,
    /// Every anchor slot this work holds, damaged included.
    pub total_slots: usize,
}

impl AnchorDamage {
    /// Whether every slot of this work read cleanly.
    #[must_use]
    pub fn is_intact(&self) -> bool {
        self.slots.is_empty()
    }

    /// The highest record-format version any `newer-record` slot names.
    ///
    /// `None` when no slot is one. Deterministic over a mixed set, which a
    /// per-slot version in one sentence would not be.
    #[must_use]
    pub fn newest_record_version(&self) -> Option<u64> {
        self.slots
            .iter()
            .filter_map(|slot| slot.reason.format_version())
            .max()
    }
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
    /// **A103**: the table used to live here, wildcard-free, so that a fifth
    /// state failed compilation at this line rather than acquiring a wrong
    /// name in a `_` arm. That forcing is preserved and has simply moved to
    /// the enum it is about — [`NagState::name`] is the wildcard-free match
    /// now, and there is one table for one taxonomy instead of two.
    #[must_use]
    pub fn nag_name(&self) -> Option<&'static str> {
        self.nag.map(NagState::name)
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
    /// Store-level failures, as their CLI classes — the **enumeration** and
    /// **authentication** classes, and nothing else on the anchor path.
    ///
    /// An anchor *record* that cannot be read is **not** one of them any
    /// more (**D100 R3**). It used to be, and the paragraph that said so
    /// contradicted this module twenty lines further down (§1.2): a work
    /// holding anchor artifacts with no journaled manifest has always
    /// rendered here as a soft *"anchors: unclassified"* row at exit 0,
    /// documented as obviously right, while a work holding an artifact whose
    /// CBOR would not decode refused the **entire vault** with *"wrong
    /// passphrase, or the vault store or header has been modified or
    /// corrupted"*. Two rules, one module, neither citing the other. The
    /// damage is now a per-row datum with its own reason, `list` exits 0,
    /// and the honesty burden sits on [`WorkRow::damaged_anchors`], the
    /// summary line and the machine document — where it can carry detail an
    /// exit code cannot.
    pub fn gather(store: &WorkStore<'_>) -> Result<Self, CliError> {
        let mut works = Vec::new();
        for seal_id in store.list_works().map_err(CliError::from)? {
            let record = store.load_meta(&seal_id).map_err(CliError::from)?;
            // The fine tag is preferred; its absence is a state, not a
            // failure (module docs).
            let fine_state =
                recorded_state(store, &seal_id).map_err(|err: JournalError| CliError::from(err))?;
            // U25's column, and D100's. A slot that cannot be decoded is a
            // datum on this row, not a refusal of the listing: the wrong
            // answer a nag must never give is "no anchors" for a work whose
            // slot is unreadable, and that is closed by
            // `NagState::Unreadable` (R7) rather than by refusing to print.
            // What still fails here is the enumeration and the AEAD.
            let read = anchor_nag(store, &seal_id, record.work_id, NAG_VERIFY_AT_UNIX)
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
                pending_anchors: read.nag.as_ref().map(|nag| nag.pending),
                nag: read.nag.map(|nag| nag.nag),
                damaged_anchors: read.damaged,
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
            // Works, not slots — matching how `unanchored` and
            // `pending_anchor_nags` already count, so the three clauses of
            // the summary line are three counts of one thing (D100 R3).
            if !row.damaged_anchors.is_intact() {
                counts.damaged_anchors += 1;
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
                // D100 R9: what a script gets instead of an exit code, and
                // strictly more expressive than one — it distinguishes
                // "upgrade antseal" from "your vault is damaged" from
                // "something else is running", and names the works.
                "damaged_anchors": counts.damaged_anchors,
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
        if counts.damaged_anchors > 0 {
            notes.push(format!(
                "{} with unreadable anchors",
                counts.damaged_anchors
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
    // The damage block comes first and is **unconditional on damage**
    // (D100 R3) — this is the honesty guarantee, because `NagState::Anchored`
    // and `AttestedOnly` print nothing at all, so without it a damaged work
    // would be visually identical to a clean one.
    let mut lines = damage_lines(row);
    if row.nag.is_none() {
        lines.push(
            "  anchors: unclassified — this work holds anchor artifacts but its journaled \
             manifest is gone, so what they attest to cannot be recovered"
                .to_owned(),
        );
        return lines;
    }
    if row.nag == Some(NagState::Unreadable) && lines.is_empty() {
        // R7.4: `Unreadable` reached without any *record* damage — the slots
        // opened and the artifact **bytes** inside them do not parse against
        // what this work sealed. There is no slot-level reason to print, so
        // the state is named once, with the command that can say more.
        // `--upgrade` is deliberately absent: it cannot help bytes nothing
        // can parse, and unsatisfiable advice is what R7 refused.
        lines.push(
            "  anchors: unreadable — this work holds anchor artifacts that do not parse against \
             what it sealed, so none of them proves a time"
                .to_owned(),
        );
        lines.push(status_hint(row, ""));
        return lines;
    }
    if !row.nags() {
        // Every non-nagging class prints nothing *of its own*. The damage
        // block above is not one of them, and for `NagState::Unreadable` —
        // whose `nags()` is false — it is the entire rendering, which is
        // what makes R3's "the damage block replaces the nag block" literal
        // in the case it was written about.
        return lines;
    }
    let count = row.pending_anchors.unwrap_or_default();
    lines.push(format!(
        "  ANCHORS PENDING: {count} calendar attestation(s) not yet confirmed by Bitcoin, and \
         nothing else here proves a time independently"
    ));
    lines.push(status_hint(row, " --upgrade"));
    lines
}

/// The `run antseal status …` line, with whatever flags the caller's advice
/// actually needs.
///
/// A work that never reached `record_outcome` has no work id, and `status`
/// takes one (`cli.rs`'s `WORK-ID`). Printing the hint with a hole in it
/// would be worse than saying which step comes first.
fn status_hint(row: &WorkRow, flags: &str) -> String {
    match row.work_id.as_ref() {
        Some(work_id) => format!(
            "  run antseal status {}{flags}",
            crate::pipeline::hex32(work_id)
        ),
        None => format!(
            "  no work id yet — finish this seal first, then run antseal status <id>{flags}"
        ),
    }
}

/// The damaged-slot block for one row: nothing at all when every slot read.
///
/// One block per **reason present**, in a fixed order, because R1's three
/// reasons demand three different next steps and only one of them is anybody's
/// fault. A single merged sentence would have to pick one of the three, and
/// picking wrong is how *"upgrade antseal"* becomes *"your vault is damaged"*.
fn damage_lines(row: &WorkRow) -> Vec<String> {
    let damage = &row.damaged_anchors;
    if damage.is_intact() {
        return Vec::new();
    }
    let total = damage.total_slots;
    let mut lines = Vec::new();

    // Partitioned by a **wildcard-free match**, not by comparing
    // `reason.name()` to a literal: a fourth reason must be given a
    // rendering at this line rather than falling into no group and silently
    // printing nothing at all. That is the same failure D100 R10.4 plants a
    // fault for one layer up — a state that exists, has a name, compiles
    // clean, and is never produced.
    let mut undecodable: Vec<&DamagedSlot> = Vec::new();
    let mut newer: Vec<&DamagedSlot> = Vec::new();
    let mut moved: Vec<&DamagedSlot> = Vec::new();
    for slot in &damage.slots {
        match &slot.reason {
            DamageReason::Undecodable { .. } => undecodable.push(slot),
            DamageReason::NewerRecord { .. } => newer.push(slot),
            DamageReason::SlotMoved => moved.push(slot),
        }
    }

    if !undecodable.is_empty() {
        let detail = undecodable
            .iter()
            .map(|slot| format!("{}: {}", slot.slot, slot.reason.detail()))
            .collect::<Vec<_>>()
            .join(", ");
        lines.push(format!(
            "  anchors: {} of {total} slot(s) unreadable — {detail}",
            undecodable.len()
        ));
        lines.push(format!(
            "{}; the other anchors are counted as if they were absent",
            status_hint(row, "")
        ));
    }

    if !newer.is_empty() {
        let version = damage.newest_record_version().unwrap_or_default();
        let slots = newer
            .iter()
            .map(|slot| slot.slot.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        lines.push(format!(
            "  anchors: {} of {total} slot(s) written by a newer antseal (record format v{version}) \
             — {slots}",
            newer.len()
        ));
        lines.push(
            "  upgrade antseal to read them; the others are counted as if they were absent"
                .to_owned(),
        );
    }

    if !moved.is_empty() {
        let slots = moved
            .iter()
            .map(|slot| slot.slot.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        lines.push(format!(
            "  anchors: {} slot(s) changed while being read — {slots} (another antseal may be \
             running)",
            moved.len()
        ));
        lines.push("  re-run antseal list".to_owned());
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

/// One work's whole anchor answer: the nag, and the damage beside it.
///
/// Two facts and two fields, not one field carrying both — `nag: None`
/// already means *"no recoverable `anchor_digest`"*, and a work can be
/// unclassifiable **and** damaged at once (R4).
struct AnchorRead {
    /// `None` when the class could not be computed at all.
    nag: Option<NagRead>,
    /// The slots that would not read, and the slot total.
    damaged: AnchorDamage,
}

/// Read one work's anchor set and classify it (**U25**, **D100 R3**).
///
/// `nag: None` means *unclassifiable*: artifacts exist but the
/// `anchor_digest` they commit cannot be recovered, so neither A15's rule
/// nor A18's evaluator can be run over them. See [`WorkRow::nag`] for why
/// that is rendered rather than failed — and note that the damage half is
/// filled in either way, because a work can be both.
///
/// # Errors
///
/// Whatever [`StoredAnchors::read`] and
/// [`recorded_plan`](crate::pipeline::journal::recorded_plan) raise. For the
/// anchor set that is the enumeration and cipher-layer classes only: a
/// per-record schema refusal or a `NewerRecord` **arrives as data** here
/// (R5), because the split is at the AEAD boundary and nothing on the far
/// side of it is observable to a caller who has not already demonstrated the
/// passphrase.
fn anchor_nag(
    store: &WorkStore<'_>,
    seal_id: &SealId,
    work_id: Option<[u8; 32]>,
    verify_at_unix: u64,
) -> Result<AnchorRead, JournalError> {
    let anchors = StoredAnchors::read(store, seal_id)?;
    // `list` is a reporter, so it takes the reporting door and receives the
    // damage whether it asked for it or not.
    let (intact, damaged_slots) = anchors.intact_and_damaged();
    let damaged = AnchorDamage {
        slots: damaged_slots.to_vec(),
        total_slots: anchors.total_slots(),
    };
    // No slots at all is a complete answer on its own, and it is the only
    // branch that needs no digest — which is why it comes first rather
    // than falling out of the classifier with a fabricated one. A work whose
    // every slot is damaged does **not** take it: it has anchors, it just
    // cannot read them, and calling that UNANCHORED is the lie R7 closes.
    if anchors.is_empty() {
        return Ok(AnchorRead {
            nag: Some(NagRead {
                nag: NagState::Unanchored,
                pending: 0,
            }),
            damaged,
        });
    }
    // `anchor_digest` is SHA-256 of the plaintext manifest envelope and is
    // not on `WorkRecord`; the journaled plan is where the bytes are, and
    // S29 keeps that record across `vault import` (module docs).
    let Some(manifest_bytes) = recorded_plan(store, seal_id)?.and_then(|plan| plan.manifest_bytes)
    else {
        return Ok(AnchorRead { nag: None, damaged });
    };
    let nag = classify_anchors(
        intact.ots(),
        intact.tsa(),
        damaged.slots.len(),
        anchor_digest(&manifest_bytes).as_bytes(),
        work_id.unwrap_or_default(),
        verify_at_unix,
    );
    Ok(AnchorRead {
        nag: Some(nag),
        damaged,
    })
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
    unreadable_records: usize,
    anchor_digest: &[u8; 32],
    work_id: [u8; 32],
    verify_at_unix: u64,
) -> NagRead {
    let work = PendingWork {
        work_id,
        anchor_digest: *anchor_digest,
        // D100 R7.3: the damaged slots never became artifacts, so A15 cannot
        // see them in `ots`/`tsa` and must be told the count. Deciding
        // `Unreadable` here instead would be a second nag rule in the CLI —
        // the shape D98 rejected its option (c) for.
        unreadable_records,
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
    /// Works holding at least one anchor slot whose record could not be
    /// interpreted (**D100 R3/R9**). A fourth orthogonal predicate, counted
    /// in **works** like the two above it, and the number a CI job tests
    /// instead of an exit code.
    pub damaged_anchors: usize,
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
        // D100 R3. **Empty, never `null`**, for a healthy work — deliberately,
        // because `null` would re-create the `Some(0)`/`None` ambiguity U25 had
        // to disambiguate at cost, and there is no not-computable case here:
        // collecting the damaged set is what the reader now does. Present
        // unconditionally for the same reason the human block is (R3): a key
        // that only appeared on damage would leave a damaged work looking
        // exactly like a clean one under `anchored`/`attested-only`.
        "damaged_anchors": row
            .damaged_anchors
            .slots
            .iter()
            .map(damaged_slot_json)
            .collect::<Vec<_>>(),
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
            0,
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
            0,
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
        let read = classify_anchors(
            &[],
            &[],
            0,
            &fixture_digest(),
            [0xA3; 32],
            NAG_VERIFY_AT_UNIX,
        );
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
            0,
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
                    0,
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
                    0,
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

    /// **A102, fixed** (D100 R7). A15 used to drop `Unreadable` artifacts
    /// before testing for pending ones and then fall through to
    /// `AttestedOnly`, so an `.ots` that does not parse against this work's
    /// `anchor_digest` landed in the state whose doc says *"every OTS anchor
    /// is already attested"* — a state `list` could never render the word
    /// "attested" off without publishing the conflation.
    ///
    /// It now lands in `Unreadable`, which is the **name** A102 needed. The
    /// boolean is unchanged and deliberately so: `nags()` stays `false`,
    /// because the block it drives would read `ANCHORS PENDING: 0` and
    /// instruct `--upgrade`, which cannot help bytes nothing can parse. This
    /// row was renamed rather than deleted, per A102's own Accept.
    #[test]
    fn an_unreadable_ots_has_its_own_class_and_still_does_not_nag() {
        let read = classify_anchors(
            &ots(OTS_FOREIGN),
            &[],
            0,
            &fixture_digest(),
            [0xA6; 32],
            NAG_VERIFY_AT_UNIX,
        );
        assert_eq!(read.nag, NagState::Unreadable);
        assert!(
            !read.nag.nags(),
            "the state changed; the unsatisfiable nag it would have printed is still refused"
        );
        assert_eq!(read.pending, 0);
    }

    /// **D100 R7.3, through `list`'s own seam**: a record the vault codec
    /// refused never becomes an artifact, so the count is how A15 learns it
    /// exists — and a work with nothing but damaged slots must not classify
    /// `unanchored`, which would say *"no anchors at all"* about a work that
    /// has anchors it cannot read.
    #[test]
    fn a_work_whose_only_slots_are_damaged_is_unreadable_not_unanchored() {
        let read = classify_anchors(
            &[],
            &[],
            1,
            &fixture_digest(),
            [0xA7; 32],
            NAG_VERIFY_AT_UNIX,
        );
        assert_eq!(read.nag, NagState::Unreadable);
        assert!(!read.nag.nags());
        assert_eq!(read.pending, 0);

        // The instrument check: the identical call with nothing damaged is
        // the UNANCHORED work, so the row above is testing the count and not
        // the empty slices.
        let empty = classify_anchors(
            &[],
            &[],
            0,
            &fixture_digest(),
            [0xA7; 32],
            NAG_VERIFY_AT_UNIX,
        );
        assert_eq!(empty.nag, NagState::Unanchored);
    }

    /// Every class has its own kebab spelling, and an unclassified row has
    /// none — every state plus the absent one, all distinct.
    ///
    /// **Rewritten over [`NagState::ALL`]** (D100 R8). It used to enumerate a
    /// hand-written five-element array, which is a shape that **passes while
    /// under-covering**: a sixth state does not redden it, it simply is not
    /// asked about. `nag_name`'s wildcard-free match used to force the
    /// production edit and this row would then have gone green at 5-of-6.
    /// Driven off the enum, its length cannot disagree with the enum's.
    #[test]
    fn each_nag_class_has_its_own_name() {
        let names: Vec<Option<&'static str>> = NagState::ALL
            .into_iter()
            .map(Some)
            .chain(std::iter::once(None))
            .map(|nag| row_with(nag).nag_name())
            .collect();
        assert_eq!(
            names,
            vec![
                Some("anchored"),
                Some("only-pending-ots"),
                Some("unreadable"),
                Some("attested-only"),
                Some("unanchored"),
                None,
            ]
        );
        assert_eq!(
            names.len(),
            NagState::ALL.len() + 1,
            "the covered set is the enum's own, plus the unclassified row"
        );
        let mut unique = names.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), names.len(), "two rows share one spelling");
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

        // The silent classes render nothing at all — and this list is written
        // out rather than derived from `NagState::ALL` on purpose: it is a
        // claim about *which* states are silent, and `NagState::Unreadable`
        // is deliberately not one of them (R7.4). A sixth state joins one
        // list or the other by a decision, never by a default.
        for nag in [
            NagState::Anchored,
            NagState::AttestedOnly,
            NagState::Unanchored,
        ] {
            assert!(nag_lines(&row_with(Some(nag))).is_empty(), "{nag:?}");
        }
        assert!(
            !nag_lines(&row_with(Some(NagState::Unreadable))).is_empty(),
            "`Unreadable` does not nag, but it is not silent either — it is the one class \
             whose whole purpose is to stop a row saying nothing about anchors nothing can \
             read (D100 R7.4)"
        );
        assert_eq!(
            NagState::ALL.len(),
            4 + 1,
            "three silent, one nagging, one that renders without nagging — a sixth state \
             must be sorted into one of the three groups above, and this length is what \
             stops it being forgotten"
        );
        let unclassified = nag_lines(&row_with(None));
        assert_eq!(unclassified.len(), 1);
        assert!(unclassified[0].contains("unclassified"));
    }

    /// **D100 R3**: the damage block is two lines, names the slot, carries
    /// the decoder's message, says how much, and gives a **satisfiable** next
    /// step — one per reason, because the three reasons imply three different
    /// actions and only one of them is the user's fault.
    #[test]
    fn the_damage_block_names_the_slot_the_count_and_a_satisfiable_next_step() {
        let undecodable = row_damaged(
            Some(NagState::Anchored),
            DamageReason::Undecodable {
                detail: "anchor slot family disagrees with the record kind",
            },
            3,
        );
        let lines = nag_lines(&undecodable);
        assert_eq!(lines.len(), 2);
        assert_eq!(
            lines[0],
            "  anchors: 1 of 3 slot(s) unreadable — tsa-1: anchor slot family disagrees with \
             the record kind"
        );
        assert!(lines[1].contains(&format!("run antseal status {}", "a1".repeat(32))));
        assert!(
            !lines[1].contains("--upgrade"),
            "`--upgrade` cannot help a record nothing can open; unsatisfiable advice is what \
             R7 refused"
        );

        // "upgrade antseal" is a different sentence and is not the user's
        // fault, so it must not be reached through the malformed wording.
        let newer = nag_lines(&row_damaged(
            Some(NagState::Anchored),
            DamageReason::NewerRecord { found: 3 },
            3,
        ));
        assert_eq!(newer.len(), 2);
        assert!(newer[0].contains("written by a newer antseal (record format v3)"));
        assert!(newer[1].contains("upgrade antseal to read them"));
        assert!(!newer[0].contains("unreadable"));

        // …and a slot that moved is not damage at all: `list` takes no lock,
        // so a concurrent seal makes it expected.
        let moved = nag_lines(&row_damaged(
            Some(NagState::Anchored),
            DamageReason::SlotMoved,
            3,
        ));
        assert_eq!(moved.len(), 2);
        assert!(moved[0].contains("changed while being read"));
        assert!(moved[0].contains("another antseal may be running"));
        assert_eq!(moved[1], "  re-run antseal list");
        assert!(
            !moved[0].contains("unreadable") && !moved[0].contains("newer"),
            "rendering a healthy mid-seal vault as damaged would be a new false accusation \
             replacing the old one"
        );
    }

    /// **D100 R3, the honesty guarantee**: the block is unconditional on
    /// damage.
    ///
    /// `NagState::Anchored` and `AttestedOnly` print nothing at all, so a
    /// block that only appeared when the row *also* nagged would leave a
    /// damaged work visually identical to a clean one — which is the failure
    /// the whole decision exists to remove. And a row that both nags and is
    /// damaged prints **both**, because `--upgrade` genuinely can help the
    /// pending half (R7.2's "satisfiable advice wins").
    #[test]
    fn the_damage_block_is_unconditional_and_does_not_swallow_a_satisfiable_nag() {
        for nag in [NagState::Anchored, NagState::AttestedOnly] {
            let row = row_damaged(Some(nag), DamageReason::Undecodable { detail: "junk" }, 2);
            assert!(
                nag_lines(&row_with(Some(nag))).is_empty(),
                "the premise: {nag:?} renders nothing of its own"
            );
            assert_eq!(
                nag_lines(&row).len(),
                2,
                "{nag:?} plus damage must not render as {nag:?} alone"
            );
        }

        let mut mixed = row_damaged(
            Some(NagState::OnlyPendingOts),
            DamageReason::Undecodable { detail: "junk" },
            2,
        );
        mixed.pending_anchors = Some(3);
        let lines = nag_lines(&mixed);
        assert_eq!(lines.len(), 4, "the damage block AND the pending block");
        assert!(lines[0].contains("1 of 2 slot(s) unreadable"));
        assert!(lines[2].contains("ANCHORS PENDING: 3"));
        assert!(lines[3].ends_with("--upgrade"));

        // An unclassifiable row can be damaged too — two facts, two lines.
        let unclassified = row_damaged(None, DamageReason::SlotMoved, 2);
        let lines = nag_lines(&unclassified);
        assert_eq!(lines.len(), 3);
        assert!(lines[2].contains("unclassified"));
    }

    /// **R7.4**: `Unreadable` reached with no *record* damage still renders,
    /// and names a command that can actually say more.
    ///
    /// This is the hole the damage block alone would leave: the artifact
    /// bytes do not parse, the record opened fine, so there is no damaged
    /// slot to describe — and before D100 the row printed nothing at all
    /// while calling itself `attested-only`.
    #[test]
    fn an_unreadable_row_with_no_record_damage_still_says_so() {
        let row = {
            let mut row = row_with(Some(NagState::Unreadable));
            row.work_id = Some([0xA1; 32]);
            row
        };
        let lines = nag_lines(&row);
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("anchors: unreadable"));
        assert!(lines[0].contains("do not parse against what it sealed"));
        assert_eq!(
            lines[1],
            format!("  run antseal status {}", "a1".repeat(32)),
            "satisfiable: `status` renders it as `invalid`, which is a real answer"
        );
        assert!(!lines[1].contains("--upgrade"));

        // And when the damage IS in the records, that block speaks instead —
        // it has a slot name and a reason, which this one cannot have.
        let damaged = row_damaged(
            Some(NagState::Unreadable),
            DamageReason::Undecodable { detail: "junk" },
            1,
        );
        let lines = nag_lines(&damaged);
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("1 of 1 slot(s) unreadable — tsa-1: junk"));
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
            damaged_anchors: AnchorDamage::default(),
        }
    }

    /// A row carrying one damaged slot, for the D100 rendering assertions.
    fn row_damaged(nag: Option<NagState>, reason: DamageReason, total_slots: usize) -> WorkRow {
        let mut row = row_with(nag);
        row.work_id = Some([0xA1; 32]);
        row.damaged_anchors = AnchorDamage {
            slots: vec![DamagedSlot {
                slot: "tsa-1".to_owned(),
                reason,
            }],
            total_slots,
        };
        row
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
