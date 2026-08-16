//! `status <work-id> [--upgrade]` (U23): what state each of a work's
//! anchors is in **now**, and — with `--upgrade` — a calendar poll that
//! drives pending OpenTimestamps attestations to a Bitcoin attestation.
//!
//! MVP-SPEC.md lines 106–110 (the anchoring machinery), 127–137 (the verdict
//! taxonomy this renders), 149/155 (the command). The ruling this implements
//! is `docs/decisions/D98-status-anchor-state-vocabulary.md`; the record
//! shape it reads and writes is D97's.
//!
//! # Two machines, and this one is A18
//!
//! Two state machines could claim this job and D98 rules which does:
//!
//! - **A18** answers *"what state is this artifact in?"* — per artifact, in
//!   the seven frozen [`AnchorState`] names. That is what `status` renders.
//! - **A15**'s `work_status` answers *"should I nag about this work?"* — per
//!   work, by `NagState`. `list` renders that (U25). `OtsAnchorState` is
//!   not user-visible vocabulary and appears nowhere here (five `NagState`s
//!   since D100 R7).
//!
//! Neither is projected into the other. A named projection table — the third
//! option D98 rejected — is the **only** design that guarantees `status` and
//! `verify` disagree, because it would compute a state by one rule and print
//! it under a name defined by another.
//!
//! # Nothing is fabricated
//!
//! A18's bundle-shaped door ([`AnchorArtifacts::from_parts`], `OtsAnchor::new`,
//! `TsaAnchor::new`) demands a sealer-recorded `AnchorStatus`, and the vault
//! stores none: [`AnchorArtifact`] has kind, endpoint, fetch date, bytes and
//! D79's upgrade group, and not one of them is a verdict claim. So this
//! module goes through the **per-artifact** evaluators
//! ([`evaluate_ots_artifact`], [`evaluate_tsa_artifact`]) over the
//! `*ArtifactView::from_parts` views, which take no status at all and whose
//! own doc comments name A18 as their intended consumer. There is therefore
//! no claimed/verified boundary to police *for the status field*: the
//! distinction D95 and R74 fight over is **vacuous here**, recorded as
//! vacuous rather than discharged, and a future record schema that added a
//! sealer status would reopen it (D98 rider 1a).
//!
//! The boundary is live for the **source identity**, and this is the first
//! consumer in the tree that can mechanise D53 §4's *"MUST render as such"*:
//! [`AnchorVerdict::source`] hands over an [`AnchorSource`] with its
//! `Verified`/`Claimed` discriminant intact, and [`AnchorSource::is_verified`]
//! decides the wording. The collapse R74 records happens in
//! `AnchorVerdict::to_anchor_result`, at the report boundary — which this
//! module never crosses, in either direction (rider 1b).
//!
//! # Where `status` and `verify` may differ, exhaustively
//!
//! They call the same functions on the same bytes with the same
//! `anchor_digest` and the same [`TsaRootStore`], so they agree by
//! construction except in two documented ways, both of which are the taxonomy
//! working rather than a defect:
//!
//! 1. **Time.** `status` evaluates at status-time and `verify` at
//!    verify-time; that difference *is* the `proven` /
//!    `valid-at-stamping-cert-since-expired` distinction.
//! 2. **Online evidence.** `status` is offline ([`BlockEvidence::new`]), so
//!    an upgraded `.ots` renders `attested` here and never `proven`.
//!    `verify --online` can promote it (MVP-SPEC.md line 108).
//!
//! Intermediates are **not** a third difference. `TsaAnchor::intermediates`
//! has never been populated by anything in this crate, so the empty slice
//! passed below is byte-identical to what M3's bundle builder will carry; and
//! `validate_token_chain` pools the token's own certificate bag, which all
//! four pinned-root TSAs self-carry. Omitting certificates is monotone — it
//! can only ever lower or preserve a grade — so it can never over-claim
//! (D98 gap 2; the reliance on self-carrying tokens is **A101**).
//!
//! # Two statements that are permanently true of this renderer
//!
//! - **An OTS anchor is never `proven`.** O3 needs an online block header and
//!   this is offline by construction.
//! - **`absent` is never an outcome.** It is a statement about a *kind* with
//!   no artifact (R70), so it is asked for explicitly — [`WorkStatus::absent`]
//!   — and iterating [`WorkStatus::anchors`] can never produce one.

use antseal_anchor::agree::EndpointPair;
use antseal_anchor::http::{Endpoint, HttpClient, HttpPolicy, TlsPolicy};
use antseal_anchor::ots::{
    DEFAULT_OTS_CALENDARS, PendingWork, StoredOtsAnchor, StoredTsaAnchor, UpgradeBudget,
    UpgradeReport, upgrade_pending,
};
use antseal_core::anchor::model::{
    AnchorSource, AnchorVerdict, BlockEvidence, OtsArtifactView, TsaArtifactView,
};
use antseal_core::anchor::roots::TsaRootStore;
use antseal_core::anchor::verdicts::{evaluate_ots_artifact, evaluate_tsa_artifact};
use antseal_core::crypto::secrets::SealId;
use antseal_core::manifest::anchor_digest;
use antseal_core::verify::report::{AnchorKind, AnchorState};
use antseal_core::verify::wording;
use rand_core::TryCryptoRng;

use crate::error::CliError;
use crate::pipeline::anchors::{
    AnchorArtifact, ArtifactKind, DamageReason, DamagedSlot, StoredAnchors, apply_upgrade,
    damaged_slot_json,
};
use crate::pipeline::journal::{JournalError, recorded_plan};
use crate::pipeline::receipt_sink::recorded_receipt;
use crate::vault::store::{WorkState, WorkStore};

/// The class the Arbitrum receipt renders in — MVP-SPEC.md lines 110 and 137,
/// verbatim.
///
/// A `const` and not a format string, because D98 rider 4 makes this the
/// **replacement** for a guarantee `status` does not inherit. On the bundle
/// path the type enforces it: `ReceiptEvidence::is_headline_eligible` is a
/// `const fn -> false` with no path to `true`, and the receipt is a separate
/// field rather than an entry in `outcomes()`. None of that is reachable from
/// here — `receipt_evidence` is private and `AnchorVerdicts` has no public
/// constructor — so U23's *"receipt never rendered as an anchor is enforced by
/// the type"* is true of the bundle and **false of this path**, and a test
/// enforces it instead.
///
/// **R18**: the string itself now comes from the one authoritative wording
/// table (`antseal_core::verify::wording`); this const is the name `status`
/// and its tests already knew it by, not a second spelling of it.
pub const RECEIPT_CLASS: &str = wording::RECEIPT_CLASS;

/// What a work with zero headline-eligible anchors says (MVP-SPEC.md line
/// 137, verbatim; the string is R18's table row).
pub const UNANCHORED_NOTE: &str = wording::UNANCHORED_BANNER;

/// What a work holding artifacts but no journaled manifest says (**D100 R6**).
///
/// The same fact `list` renders as *"anchors: unclassified"* at exit 0
/// (`listing.rs`), in the same words, because the two commands answering one
/// vault state differently is the divergence D100 §1.2 found and closed.
pub const UNCLASSIFIED_NOTE: &str = "this work holds anchor artifacts but its journaled manifest \
                                     is gone, so what they attest to cannot be recovered";

/// The pending-anchor hint, in the second person (D98 rider 5).
///
/// MVP-SPEC.md line 130's *"ask the sealer to run `status --upgrade`"* is
/// verifier-page copy, whose reader is a third party. This command's reader
/// **is** the sealer. **R18 resolved the person mismatch by keeping both**:
/// the table carries the page's third-party form
/// (`wording::PENDING_GUIDANCE`) and this second-person one as its first
/// *declared* divergence, so one fact has one home and two audiences.
pub const PENDING_HINT: &str = wording::PENDING_GUIDANCE_SELF;

/// Per-invocation inputs `status` does not decide.
///
/// # `verify_at_unix` has no user surface, by ruling (D98 rider 2)
///
/// This mirrors `SealContext.now_unix_secs` and copies
/// `VerifyOptions::with_verify_at_unix`'s shape — a struct field, filled from
/// the host clock in production and from a literal in tests. It deliberately
/// does **not** copy `AnchorStageConfig.fetch_date`'s *rationale*, whose own
/// doc says it is safe to expose *because `fetch_date` gates no outcome*.
/// This one gates the headline: `chain.rs`'s
/// `one_fixture_two_verify_times_flips_proven_and_since_expired` is the
/// committed proof, and the test is one-sided (D53 §5(b)) — an early
/// `verify_at` can never produce a failure, only a false **`proven`**.
/// Measured: `verify_at = 0` renders a real DigiCert token `proven` with an
/// expired chain. An over-claim knob on the tool whose job is to state what
/// is proven is precisely the knob that must not exist, so there is no
/// `--now`, no `--verify-at`, no environment variable and no config key.
///
/// The clock is read **once per invocation** and threaded to every anchor, so
/// one rendered output cannot straddle a certificate expiry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatusContext {
    /// The verification time every TSA chain is evaluated at, POSIX seconds.
    pub verify_at_unix: u64,
    /// The pinned root store T3 validates against. Injectable for the same
    /// reason `AnchorStageConfig.roots` is (A6/A7): the untrusted-root and
    /// mock-signer rows are unbuildable otherwise. `TsaRootStore::from_static`
    /// is `test-util`-gated, so outside a test build
    /// [`TsaRootStore::pinned`] is the only value that exists to pass.
    pub roots: TsaRootStore,
}

impl StatusContext {
    /// The production context: this invocation's single clock read, and the
    /// pinned root store.
    #[must_use]
    pub fn new(verify_at_unix: u64) -> Self {
        Self {
            verify_at_unix,
            roots: *TsaRootStore::pinned(),
        }
    }
}

/// One stored artifact's verdict, with the slot it was read from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorRow {
    /// The U9 slot name — `ots-pending` or `tsa-<n>`.
    pub slot: String,
    /// A18's per-artifact verdict: state, verified time, source, fetch date,
    /// diagnostic. Never [`AnchorState::Absent`] (R70).
    pub verdict: AnchorVerdict,
}

/// The headline, when any anchor can carry one.
///
/// MVP-SPEC.md line 137's *"Existed no later than \<earliest headline-eligible
/// time\> (source)"*, computed from [`AnchorVerdict::is_headline_eligible`]
/// per anchor and nothing else (D98 rider 3c).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Headline {
    /// The earliest independently verified time, POSIX seconds UTC.
    pub time_unix: i64,
    /// Which mechanism proved it.
    pub kind: AnchorKind,
    /// That anchor's source identity — always a **verified** one, because
    /// only the two headline-eligible states carry a time.
    pub source: Option<String>,
}

/// The vault's payment record, as supporting evidence.
///
/// **No time of any kind** (D98 rider 4d): not the block as a time, not a
/// transaction timestamp. The block number is display-only and unverified in
/// v1 (registry §7.10 key 1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiptRow {
    /// How many transactions the payment took (D37's sequential sub-batches).
    pub transactions: usize,
    /// The block numbers those transactions landed in, where the D33
    /// enrichment slot was filled. Ascending, deduplicated.
    pub block_numbers: Vec<u64>,
}

/// What one `--upgrade` run did.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct UpgradeOutcome {
    /// Calendar polls actually issued.
    pub polls: usize,
    /// Transitions persisted.
    pub applied: usize,
    /// Transitions discarded because the slot moved under them
    /// ([`JournalError::AnchorSlotMoved`]) — a benign outcome, not a fault:
    /// the engine polls unlocked, so another process may have rewritten the
    /// slot in the interval, and polls are idempotent.
    pub declined: usize,
    /// Every per-anchor note the engine returned, rendered. Never fatal.
    pub notes: Vec<String>,
    /// Whether work was left undone because the budget ran out.
    pub budget_exhausted: bool,
}

impl UpgradeOutcome {
    /// The outcome of a report nothing was persisted from.
    #[must_use]
    pub fn of_report(report: &UpgradeReport) -> Self {
        Self {
            polls: report.polls,
            applied: 0,
            declined: 0,
            notes: report.notes.iter().map(ToString::to_string).collect(),
            budget_exhausted: report.budget_exhausted,
        }
    }
}

/// One work's anchor status, in display order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkStatus {
    /// `work_id = SHA-256(manifest body)`; absent until the manifest exists.
    pub work_id: Option<[u8; 32]>,
    /// The vault's store key.
    pub seal_id: SealId,
    /// `--title`, as recorded.
    pub title: Option<String>,
    /// The work's network, canonical CLI spelling.
    pub network: String,
    /// The coarse completion state.
    pub state: WorkState,
    /// Sealed with `--force-degraded`.
    pub degraded: bool,
    /// One row per stored artifact, OTS first then TSA by slot index.
    ///
    /// Empty when this work's `anchor_digest` cannot be recovered — see
    /// [`Self::unclassifiable`], which then holds the same slots.
    pub anchors: Vec<AnchorRow>,
    /// Slots holding an artifact that decoded, and about which no verdict can
    /// be stated because this work's journaled manifest is gone (**D100 R6**).
    ///
    /// Every A18 evaluator takes an `anchor_digest`, which is `SHA-256` of
    /// that manifest, so there is nothing to evaluate against. `status` used
    /// to refuse the whole work here with exit 12 and *"wrong passphrase"*
    /// while `list` rendered the identical state as a soft row at exit 0
    /// (D100 §1.2) — two commands, two answers, neither citing the other.
    /// The divergence is closed in `list`'s favour.
    pub unclassifiable: Vec<UnclassifiableRow>,
    /// Slots whose record could not be interpreted at all (**D100 R1/R6**).
    ///
    /// Rendered **outside** A18's frozen seven-state vocabulary, and D100
    /// §1.4 is why it must be: no verdict can be stated without naming a
    /// mechanism, and the mechanism is at key 0 inside the record that will
    /// not open. So this is a fact about the vault, not evidence about a
    /// time, and it gets a field rather than a verdict or an exit code.
    pub damaged: Vec<DamagedSlot>,
    /// One kind-level `absent` verdict per [`AnchorKind`] this work holds no
    /// artifact of. Asked for explicitly, because R70 keeps `absent` out of
    /// the outcome list entirely — iterating [`Self::anchors`] over a
    /// `--no-anchor` work prints nothing at all.
    pub absent: Vec<AnchorVerdict>,
    /// The Arbitrum receipt, outside the per-anchor section by construction.
    pub receipt: Option<ReceiptRow>,
    /// What `--upgrade` did, when it ran.
    pub upgrade: Option<UpgradeOutcome>,
}

impl WorkStatus {
    /// Read one work and evaluate every anchor it holds.
    ///
    /// **Damage is data here, not an error** (D100 R6). A slot whose record
    /// will not decode becomes a [`Self::damaged`] row, and a work whose
    /// journaled manifest is gone becomes [`Self::unclassifiable`] rows —
    /// both at exit 0, which is what `status` already does for an `.ots`
    /// whose *bytes* do not parse (that renders `invalid`, D98's cross-walk).
    /// One layer of wrapping apart, the exit codes used to be 0 and 12.
    ///
    /// # Errors
    ///
    /// Store- and journal-level failures as their CLI classes — the
    /// enumeration and cipher-layer classes [`StoredAnchors::read`] still
    /// raises, and nothing else.
    pub fn gather(
        store: &WorkStore<'_>,
        seal_id: &SealId,
        ctx: StatusContext,
    ) -> Result<Self, CliError> {
        let record = store.load_meta(seal_id).map_err(CliError::from)?;
        let stored = StoredAnchors::read(store, seal_id).map_err(CliError::from)?;
        // The reporting door: `status` is the command D99 R6 assigns the loud
        // per-work report to, so it receives the damage whether or not it
        // remembered to ask.
        let (intact, damaged) = stored.intact_and_damaged();
        let digest = anchor_digest_of(store, seal_id, &stored)?;

        let mut anchors = Vec::new();
        let mut unclassifiable = Vec::new();
        match digest {
            Some(digest) => {
                anchors.reserve(intact.len());
                for (slot, artifact) in intact.all() {
                    anchors.push(AnchorRow {
                        slot: slot.clone(),
                        verdict: evaluate(artifact, &digest, ctx),
                    });
                }
            }
            None => {
                unclassifiable = intact
                    .all()
                    .iter()
                    .map(|(slot, artifact)| UnclassifiableRow {
                        slot: slot.clone(),
                        kind: anchor_kind_of(artifact.kind),
                    })
                    .collect();
            }
        }

        // R70's kind-level answer, asked for by name. The list is over
        // `AnchorKind`'s own variants rather than over the slots, so a kind
        // with no artifact is a rendered fact and not a silence.
        //
        // D100: a slot this read could not interpret is **not** evidence that
        // its kind is absent. The record's `kind` is at key 0 inside it, so a
        // damaged slot's kind is unknowable and only its *name* gives a
        // family — and a name outside both families could have held either.
        // Claiming `absent` over one would make a damaged work look cleaner
        // than a healthy one, which is the exact honesty failure this
        // decision exists to remove.
        let damaged_kinds: Vec<Option<AnchorKind>> = damaged
            .iter()
            .map(|slot| slot.slot_kind().map(anchor_kind_of))
            .collect();
        let absent = [AnchorKind::Ots, AnchorKind::Tsa]
            .into_iter()
            .filter(|kind| !anchors.iter().any(|row| row.verdict.kind() == *kind))
            .filter(|kind| !unclassifiable.iter().any(|row| row.kind == *kind))
            .filter(|kind| {
                !damaged_kinds
                    .iter()
                    .any(|damaged| damaged.is_none_or(|damaged| damaged == *kind))
            })
            .map(AnchorVerdict::absent)
            .collect();

        let receipt = recorded_receipt(store, seal_id)
            .map_err(CliError::from)?
            .map(|receipt| {
                let mut block_numbers: Vec<u64> = receipt
                    .txs
                    .iter()
                    .filter_map(|tx| tx.block_number)
                    .collect();
                block_numbers.sort_unstable();
                block_numbers.dedup();
                ReceiptRow {
                    transactions: receipt.txs.len(),
                    block_numbers,
                }
            });

        Ok(Self {
            work_id: record.work_id,
            seal_id: *seal_id,
            title: record.shaping.title.clone(),
            network: record.network.clone(),
            state: record.state,
            degraded: record.degraded,
            anchors,
            unclassifiable,
            damaged: damaged.to_vec(),
            absent,
            receipt,
            upgrade: None,
        })
    }

    /// The earliest independently proven time any anchor carries.
    ///
    /// Computed from [`AnchorVerdict::is_headline_eligible`], which delegates
    /// to A1's single predicate — there is no second eligibility table here.
    #[must_use]
    pub fn headline(&self) -> Option<Headline> {
        self.anchors
            .iter()
            .filter(|row| row.verdict.is_headline_eligible())
            .filter_map(|row| {
                row.verdict.verified_time_unix().map(|time_unix| Headline {
                    time_unix,
                    kind: row.verdict.kind(),
                    source: row.verdict.source().map(|s| s.identity().to_owned()),
                })
            })
            .min_by_key(|headline| headline.time_unix)
    }

    /// How many anchors can carry the headline time.
    #[must_use]
    pub fn headline_eligible(&self) -> usize {
        self.anchors
            .iter()
            .filter(|row| row.verdict.is_headline_eligible())
            .count()
    }

    /// The spec's UNANCHORED class: **zero headline-eligible anchors**.
    ///
    /// Deliberately not `WorkRecord.unanchored`, and D98 rider 3c is why:
    /// three different predicates currently share the word. `WorkRow.unanchored`
    /// is the `--no-anchor` *shaping flag* and describes how the seal was
    /// made; `NagState::Unanchored` is *"no anchors at all"*; MVP-SPEC.md line
    /// 137's is this one. They disagree on a real work — a `--force-degraded`
    /// seal carrying one pending OTS satisfies the spec's UNANCHORED while
    /// `NagState` calls it `OnlyPendingOts` and the shaping flag is `false`.
    /// `list` keeps its badge; `status` must never print the spec's sentence
    /// off the shaping flag.
    #[must_use]
    pub fn is_unanchored(&self) -> bool {
        self.headline_eligible() == 0
    }

    /// The human report, as lines (the caller routes them to stdout or —
    /// under `--json` — to stderr, D51).
    #[must_use]
    #[allow(clippy::too_many_lines)] // one linear rendering; splitting it hides the order
    pub fn render(&self) -> Vec<String> {
        let mut out = Vec::new();
        let id = self.work_id.as_ref().map_or_else(
            || format!("(no work id yet; seal {})", hex_seal(&self.seal_id)),
            crate::pipeline::hex32,
        );
        let mut badge = work_state_name(self.state).to_owned();
        if self.degraded {
            badge.push_str(" (degraded anchors — recorded at seal time)");
        }
        out.push(format!("{id}  {badge}"));
        out.push(format!(
            "  {}   {}",
            self.title.as_deref().unwrap_or("(untitled)"),
            self.network
        ));

        match self.headline() {
            // R18: the one headline template, from the one table — this
            // renderer supplies the indent and nothing else.
            Some(headline) => out.push(format!(
                "  {}",
                wording::headline_sentence(
                    headline.time_unix,
                    headline.kind,
                    &wording::source_slot(headline.source.as_deref()),
                )
            )),
            None => out.push(format!("  {UNANCHORED_NOTE}")),
        }
        // The total counts every slot, damaged and unclassifiable included:
        // a work with three slots one of which will not open holds three
        // anchor artifacts, and reporting two would make the damage
        // disappear into a smaller number. Identical to the old sentence
        // whenever nothing is damaged.
        out.push(format!(
            "  {} anchor artifact(s); {} can carry the headline time",
            self.anchors.len() + self.unclassifiable.len() + self.damaged.len(),
            self.headline_eligible()
        ));

        for row in &self.anchors {
            out.push(format!(
                "  {}   {}   {}",
                row.slot,
                kind_name(row.verdict.kind()),
                row.verdict.state().wire_name()
            ));
            out.extend(verdict_detail(&row.verdict, &id));
        }
        for row in &self.unclassifiable {
            // D100 R6: an artifact whose meaning cannot be recovered. It is
            // rendered as a slot and a kind with **no state word**, because
            // the seven states are verdicts about evidence and no verdict can
            // be run without an `anchor_digest`.
            out.push(format!(
                "  {}   {}   (unclassified)",
                row.slot,
                kind_name(row.kind)
            ));
        }
        if !self.unclassifiable.is_empty() {
            out.push(format!("      {UNCLASSIFIED_NOTE}"));
        }

        for slot in &self.damaged {
            // D100 R6: one row per damaged slot, outside the frozen seven —
            // the slot name, the reason, and the decoder's own detail.
            out.push(format!(
                "  {}   (record unreadable)   {}",
                slot.slot,
                slot.reason.name()
            ));
            out.push(format!("      {}", damage_sentence(&slot.reason)));
        }

        for verdict in &self.absent {
            // R70: rendered from its own kind-level verdict, never from an
            // empty outcome list. `absent` carries nothing else by
            // construction — no source, no fetch date, no time — so there is
            // no detail block to print.
            out.push(format!(
                "  (no artifact)   {}   {}",
                kind_name(verdict.kind()),
                verdict.state().wire_name()
            ));
        }

        // Outside the per-anchor section, under the spec's own sentence, with
        // no state spelling and no time (D98 rider 4).
        if let Some(receipt) = &self.receipt {
            out.push(format!("  {}", wording::receipt_class_line()));
            out.push(format!(
                "      paid in {} transaction(s){}",
                receipt.transactions,
                if receipt.block_numbers.is_empty() {
                    String::new()
                } else {
                    format!(
                        "; Arbitrum block {}",
                        receipt
                            .block_numbers
                            .iter()
                            .map(u64::to_string)
                            .collect::<Vec<_>>()
                            .join(", ")
                    )
                }
            ));
        }

        if let Some(upgrade) = &self.upgrade {
            out.push(format!(
                "  upgrade: {} poll(s), {} anchor(s) upgraded{}",
                upgrade.polls,
                upgrade.applied,
                if upgrade.budget_exhausted {
                    " (budget exhausted)"
                } else {
                    ""
                }
            ));
            if upgrade.declined > 0 {
                out.push(format!(
                    "      {} transition(s) discarded: the anchor slot changed while polling; \
                     re-run to recompute",
                    upgrade.declined
                ));
            }
            for note in &upgrade.notes {
                out.push(format!("      {note}"));
            }
        }
        out
    }

    /// The `--json` result document (U3's envelope wraps it into the one
    /// document the invocation prints).
    #[must_use]
    pub fn json(&self) -> serde_json::Value {
        serde_json::json!({
            "work_id": self.work_id.as_ref().map(crate::pipeline::hex32),
            "seal_id": hex_seal(&self.seal_id),
            "title": self.title,
            "network": self.network,
            "state": work_state_name(self.state),
            "degraded": self.degraded,
            // Rider 3c: headline eligibility, never the `--no-anchor`
            // shaping flag `list` badges off.
            "unanchored": self.is_unanchored(),
            "headline": self.headline().map(|headline| serde_json::json!({
                "time_unix": headline.time_unix,
                "kind": kind_name(headline.kind),
                "source": headline.source,
            })),
            "anchors": self.anchors.iter().map(|row| {
                let mut value = verdict_json(&row.verdict);
                value["slot"] = serde_json::json!(row.slot);
                value
            }).collect::<Vec<_>>(),
            // D100 R6. Both arrays are **empty, never `null`**, for a healthy
            // work — deliberately, and R3 gives the reason: a `null` would
            // re-create the `Some(0)`/`None` ambiguity U25 had to
            // disambiguate at cost, and there is no not-computable case here.
            // Unconditional for the same reason `list`'s block is: a damaged
            // slot that only appeared when damage existed would leave a
            // damaged work indistinguishable from a clean one.
            "unclassifiable": self.unclassifiable.iter().map(|row| serde_json::json!({
                "slot": row.slot,
                "kind": kind_name(row.kind),
            })).collect::<Vec<_>>(),
            // The four keys of D100 R3, spelled exactly as `list` spells
            // them: one fact, one shape, across both commands.
            "damaged_anchors": self.damaged.iter().map(damaged_slot_json).collect::<Vec<_>>(),
            "absent": self.absent.iter().map(verdict_json).collect::<Vec<_>>(),
            "receipt": self.receipt.as_ref().map(|receipt| serde_json::json!({
                "class": RECEIPT_CLASS,
                "transactions": receipt.transactions,
                "block_numbers": receipt.block_numbers,
            })),
            "upgrade": self.upgrade.as_ref().map(|upgrade| serde_json::json!({
                "polls": upgrade.polls,
                "applied": upgrade.applied,
                "declined": upgrade.declined,
                "budget_exhausted": upgrade.budget_exhausted,
                "notes": upgrade.notes,
            })),
        })
    }
}

/// Classify one stored artifact through A18's **per-artifact** evaluator.
///
/// The bundle constructors are deliberately not on this path: they would
/// require an `AnchorStatus` the vault never stored (module docs).
fn evaluate(artifact: &AnchorArtifact, digest: &[u8; 32], ctx: StatusContext) -> AnchorVerdict {
    let outcome = match artifact.kind {
        ArtifactKind::OtsPending => evaluate_ots_artifact(
            &OtsArtifactView::from_parts(&artifact.bytes, artifact.upgrade.as_ref()),
            digest,
            // Offline, by construction — which is what makes "an OTS anchor
            // is never `proven` in `status`" a property rather than a habit.
            &BlockEvidence::new(),
        ),
        ArtifactKind::TsaToken => evaluate_tsa_artifact(
            // No intermediates: nothing in this crate has ever captured any,
            // so this is the same input `verify` will get (module docs, A101).
            &TsaArtifactView::from_parts(&artifact.bytes, &[], artifact.fetch_date),
            digest,
            &ctx.roots,
            ctx.verify_at_unix,
        ),
    };
    outcome.verdict().clone()
}

/// The detail lines under one anchor's state line.
fn verdict_detail(verdict: &AnchorVerdict, work_id: &str) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(time) = verdict.verified_time_unix() {
        out.push(format!("      {}", wording::verified_time_line(time)));
    }
    if verdict.state() == AnchorState::Pending {
        out.push(format!(
            "      {}",
            wording::pending_guidance_self_line(&format!("`antseal status {work_id} --upgrade`"))
        ));
    }
    if verdict.state() == AnchorState::Attested {
        out.push(
            "      a Bitcoin attestation is embedded, but an embedded header proves no time on \
             its own — `antseal verify --online` is what promotes this to proven"
                .to_owned(),
        );
    }
    if let Some(source) = verdict.source() {
        // Rider 1b/1c: the discriminant decides the wording, and the word
        // "verified" is never printed about anything this run did not verify.
        out.push(format!(
            "      source: {} ({})",
            source.identity(),
            source_label(source)
        ));
    }
    if let Some(fetch_date) = verdict.fetch_date() {
        // D95, unchanged: sealer-recorded, decimal POSIX seconds, subordinate
        // to the state. For an OTS artifact this is the *upgrade group's*
        // header fetch date (key 6), which D97 R5 pins from the engine's
        // parameter — not the capture date in key 2, which `resume.rs` still
        // writes from `SystemTime::now()` (U48).
        out.push(format!("      fetch date: {fetch_date}"));
    }
    if let Some(diagnostic) = verdict.diagnostic() {
        out.push(format!("      diagnostic: {}", diagnostic.code()));
    }
    out
}

/// How a source identity is labelled — the whole of rider 1c, in one place.
///
/// **R18/R74**: both spellings are the shared table's, so the CLI's and the
/// page's answers to *"was this identity verified?"* are string-equal by
/// construction rather than by review.
fn source_label(source: &AnchorSource) -> &'static str {
    if source.is_verified() {
        wording::SOURCE_VERIFIED_LABEL
    } else {
        wording::SOURCE_CLAIMED_LABEL
    }
}

/// One verdict as `--json`.
fn verdict_json(verdict: &AnchorVerdict) -> serde_json::Value {
    serde_json::json!({
        "kind": kind_name(verdict.kind()),
        "state": verdict.state().wire_name(),
        "headline_eligible": verdict.is_headline_eligible(),
        "verified_time_unix": verdict.verified_time_unix(),
        "source": verdict.source().map(|source| serde_json::json!({
            "identity": source.identity(),
            "verified": source.is_verified(),
        })),
        "fetch_date": verdict.fetch_date(),
        "diagnostic": verdict.diagnostic().map(|d| d.code()),
    })
}

// ─────────────────────────────────────────────────────────────────────────
// `--upgrade`
// ─────────────────────────────────────────────────────────────────────────

/// Where `--upgrade` polls: the user's calendars, and the must-agree esplora
/// pair the block header is confirmed against.
///
/// Read from U4's config exactly as `AnchorStageConfig::from_config` reads the
/// seal-side endpoints, so one file cannot resolve a calendar for `seal` and a
/// different one for `status`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpgradeConfig {
    /// The configured calendar list. Its only role here is to **widen A42's
    /// allowlist** to the hosts the user chose: the URIs actually polled come
    /// out of the stored artifact, never out of this list.
    pub calendars: Vec<String>,
    /// The two esplora endpoints `confirm_header` must agree between.
    pub bitcoin_endpoints: Vec<String>,
}

impl UpgradeConfig {
    /// The production configuration.
    #[must_use]
    pub fn from_config(config: &crate::config::Config) -> Self {
        Self {
            calendars: DEFAULT_OTS_CALENDARS
                .iter()
                .map(|url| (*url).to_owned())
                .collect(),
            bitcoin_endpoints: config.verify_bitcoin_endpoints.clone().unwrap_or_else(|| {
                antseal_anchor::esplora::DEFAULT_ESPLORA_ENDPOINTS
                    .iter()
                    .map(|url| (*url).to_owned())
                    .collect()
            }),
        }
    }

    /// Build the must-agree pair.
    ///
    /// # Errors
    ///
    /// [`CliError::Usage`] when the configured list is not exactly two
    /// endpoints, when one does not parse, or when both name one origin — a
    /// pair of one endpoint agrees with itself and proves nothing.
    pub fn pair(&self) -> Result<EndpointPair, CliError> {
        let [first, second] = self.bitcoin_endpoints.as_slice() else {
            return Err(CliError::Usage {
                message: format!(
                    "`[verify] bitcoin_endpoints` must name exactly two endpoints (found {})",
                    self.bitcoin_endpoints.len()
                ),
            });
        };
        let parse = |url: &String| {
            Endpoint::parse(url, TlsPolicy::RequiredExceptLoopback).map_err(|e| CliError::Usage {
                message: e.to_string(),
            })
        };
        EndpointPair::new(parse(first)?, parse(second)?).map_err(|e| CliError::Usage {
            message: e.to_string(),
        })
    }
}

/// Assemble A15's input for one work from the vault.
///
/// Returns the decoded slot set beside it, because the transition the engine
/// hands back indexes into `PendingWork::ots` — the `Vec` **this reader
/// built** — and D97 R10 requires the apply site to resolve that index
/// against the same ordered list rather than by re-listing the directory.
///
/// The [`PendingWork`] is `None` when the work holds no readable OTS artifact,
/// and when its `anchor_digest` cannot be recovered: there is nothing to poll,
/// which is a state and not a failure. Both are D99 R6 **skip** rows for the
/// U24 hook, and under D100 they arrive as `None` rather than as an error —
/// the same skip, reached without manufacturing a refusal.
///
/// A damaged slot narrows the skip from the whole work to the slot (D100
/// §2(c)): the readable `.ots` of a work whose `tsa-3` will not decode is
/// still polled, and the damaged slot is simply not one of the things being
/// upgraded.
///
/// # Errors
///
/// As [`WorkStatus::gather`].
pub fn pending_work(
    store: &WorkStore<'_>,
    seal_id: &SealId,
) -> Result<(StoredAnchors, Option<PendingWork>), CliError> {
    let record = store.load_meta(seal_id).map_err(CliError::from)?;
    let stored = StoredAnchors::read(store, seal_id).map_err(CliError::from)?;
    let (intact, damaged) = stored.intact_and_damaged();
    if intact.ots().is_empty() {
        return Ok((stored, None));
    }
    // No manifest, no digest, nothing to poll against. D99 R6's own skip row,
    // and no longer an exit-12 refusal manufactured to produce it.
    let Some(anchor_digest) = anchor_digest_of(store, seal_id, &stored)? else {
        return Ok((stored, None));
    };
    let work = PendingWork {
        // `AppliedUpgrade` echoes this back and nothing on this path reads
        // it: the transition is resolved to a slot positionally (D97 R10)
        // and the work is identified by its `seal_id` throughout. A work
        // reached through `status` always carries one, because a printed
        // work id is how it was resolved.
        work_id: record.work_id.unwrap_or([0; 32]),
        anchor_digest,
        ots: intact
            .ots()
            .iter()
            .map(|(_, artifact)| StoredOtsAnchor {
                artifact: artifact.bytes.clone(),
                upgrade: artifact.upgrade.clone(),
            })
            .collect(),
        tsa: intact
            .tsa()
            .iter()
            .map(|(_, artifact)| StoredTsaAnchor {
                // Only verified captures are ever stored (`pipeline/anchors.rs`
                // module docs), so slot existence *is* the token's presence and
                // its verification at capture time. A15 reads these two bits
                // for its nag only; `status` renders no state from them.
                token_present: true,
                verified: true,
                fetch_date: artifact.fetch_date,
            })
            .collect(),
        unreadable_records: damaged.len(),
    };
    Ok((stored, Some(work)))
}

/// Poll every pending attestation of one work, as far as the interactive
/// budget goes. **Reads no clock and writes nothing.**
///
/// The lock is deliberately not held across this: it exists to serialize
/// writers, and holding it for a calendar round-trip would block every
/// concurrent `seal` (D99 R3). The caller takes it afterwards, only if there
/// is something to persist, and [`apply_upgrade`]'s compare-and-set is what
/// makes that safe.
///
/// # Errors
///
/// As [`pending_work`], plus [`CliError::Usage`] for a malformed endpoint
/// configuration. Poll failures are **not** errors: the engine returns a
/// report and no `Result`, so there is no path by which a dead calendar can
/// fail the command.
pub fn poll_upgrades(
    store: &WorkStore<'_>,
    seal_id: &SealId,
    config: &UpgradeConfig,
    fetch_date: u64,
) -> Result<(StoredAnchors, UpgradeReport), CliError> {
    let (stored, work) = pending_work(store, seal_id)?;
    let Some(work) = work else {
        return Ok((stored, UpgradeReport::default()));
    };
    let pair = config.pair()?;
    let client = HttpClient::new(HttpPolicy::opportunistic());
    let report = upgrade_pending(
        &client,
        &pair,
        std::slice::from_ref(&work),
        &config.calendars,
        // The user asked, so drive it as far as it goes — unlike U24's hook,
        // which gets one calendar's worth of time.
        UpgradeBudget::interactive(),
        fetch_date,
    );
    Ok((stored, report))
}

/// Persist every transition in `report`, through the one write path that may
/// record an upgrade group.
///
/// `stored` **must** be the slot set [`pending_work`] built the polled
/// [`PendingWork`] from: `AppliedUpgrade::anchor_index` is an index into that
/// `Vec`, and resolving it against a fresher listing would pair a transition
/// with a different capture (D97 R10).
///
/// The caller holds U5's single-writer lock. A transition whose slot moved
/// under it is **discarded and counted**, never written: the engine polled
/// unlocked, so an ordinary resume may have rewritten `ots-pending` from a
/// fresh submission in the interval, and writing anyway would pair a
/// genuinely upgraded `.ots` with a previous submission's bytes (D97 §2 K2's
/// false `anchor-ots-header-uncommitted` verdict on an honest work).
///
/// # Errors
///
/// Store-level failures, and [`JournalError::IllegalAnchorWrite`] for a
/// transition D97 R6 forbids. [`JournalError::AnchorSlotMoved`] is **not** an
/// error here — it is the `declined` count.
pub fn persist_upgrades<R: TryCryptoRng + ?Sized>(
    store: &WorkStore<'_>,
    seal_id: &SealId,
    stored: &StoredAnchors,
    report: &UpgradeReport,
    rng: &mut R,
) -> Result<UpgradeOutcome, CliError> {
    let mut outcome = UpgradeOutcome::of_report(report);
    // The reporting door with its second element deliberately dropped, and
    // R2's residual states this shape is greppable on purpose. It is the
    // right door here because this is not a renderer: it writes **one named
    // slot**, and D97 R10 requires the index to resolve against the same
    // ordered list `pending_work` built the polled `PendingWork` from — which
    // is the intact list, damage or no damage. `require_intact()` would
    // refuse a write that was already computed and is already safe, and the
    // per-slot compare-and-set in `apply_upgrade` is what makes it so.
    let (intact, _damaged) = stored.intact_and_damaged();
    for applied in &report.upgraded {
        let Some((slot, prior)) = intact.ots_entry(applied.anchor_index) else {
            // The report named an anchor this work does not have. A caller
            // bug, surfaced rather than indexed past.
            return Err(CliError::Internal {
                detail: format!(
                    "an applied OTS upgrade names anchor index {}, which this work does not have",
                    applied.anchor_index
                ),
            });
        };
        match apply_upgrade(store, seal_id, slot, prior, applied, rng) {
            Ok(()) => outcome.applied += 1,
            Err(JournalError::AnchorSlotMoved) => {
                tracing::debug!(
                    slot,
                    "anchor slot moved under a computed upgrade; discarded"
                );
                outcome.declined += 1;
            }
            Err(other) => return Err(CliError::from(other)),
        }
    }
    Ok(outcome)
}

// ─────────────────────────────────────────────────────────────────────────
// helpers
// ─────────────────────────────────────────────────────────────────────────

/// Recover the digest every anchor of this work commits.
///
/// `anchor_digest` is not on `WorkRecord`; it is `SHA-256` of the journaled
/// manifest envelope, which is the same shape `pipeline/resume.rs` uses in
/// production and which survives `vault import` — the D43 cache exclusion is
/// scoped to journal entries `>= UNIT_ENTRY_BASE`, so entries 0–2 are always
/// exported (D98 gap 3).
///
/// # Why this reports rather than refuses (**D100 R6**)
///
/// A work with **no** anchors needs no digest, and `Some([0; 32])` is
/// harmless because nothing consumes it: the caller has nothing to evaluate.
/// A work *with* anchors and no manifest used to be *"an inconsistency this
/// reader refuses rather than papers over"* — a refusal that reached the user
/// as exit 12 and *"wrong passphrase"* on a vault whose passphrase had
/// already been proven, on a work they had named by id.
///
/// It refuses no longer, and the reason is not kindness: `list` renders the
/// **identical** vault state as a soft row at exit 0 and documents that
/// choice as obviously right (*"a listing that refuses to run is the one
/// thing a user on a damaged vault cannot work around"*), while this reader
/// documented the opposite as obviously right. Two committed authorities,
/// days apart, neither citing the other (D100 §1.2). The divergence is closed
/// in `list`'s favour, and `None` here is what carries it: no verdict can be
/// stated, so `status` states none and says why.
///
/// # Errors
///
/// Journal-level failures reading the plan record. Never the absence of one.
fn anchor_digest_of(
    store: &WorkStore<'_>,
    seal_id: &SealId,
    stored: &StoredAnchors,
) -> Result<Option<[u8; 32]>, CliError> {
    let manifest = recorded_plan(store, seal_id)
        .map_err(CliError::from)?
        .and_then(|plan| plan.manifest_bytes);
    match manifest {
        Some(bytes) => Ok(Some(anchor_digest(&bytes).into_bytes())),
        None if stored.is_empty() => Ok(Some([0; 32])),
        None => Ok(None),
    }
}

/// One stored artifact `status` can name but cannot state a verdict about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnclassifiableRow {
    /// The slot it sits in.
    pub slot: String,
    /// Which mechanism it is — known here, unlike for a damaged slot, because
    /// the record itself opened.
    pub kind: AnchorKind,
}

/// The report-level kind one vault-level artifact kind is.
///
/// Exhaustive, so a third mechanism has to name itself here too — the same
/// discipline [`kind_name`] holds.
const fn anchor_kind_of(kind: ArtifactKind) -> AnchorKind {
    match kind {
        ArtifactKind::OtsPending => AnchorKind::Ots,
        ArtifactKind::TsaToken => AnchorKind::Tsa,
    }
}

/// The sentence one damage reason gets, and the next step it implies.
///
/// Three, because *"upgrade antseal"*, *"your vault is damaged"* and
/// *"another antseal is running"* are three different sentences and only one
/// of them is the user's fault (D100 R1). The `detail` is the decoder's own
/// `&'static str` — a failure-class summary whose type forbids record bytes,
/// so publishing it is safe by construction.
fn damage_sentence(reason: &DamageReason) -> String {
    match reason {
        DamageReason::Undecodable { detail } => {
            format!("this record is malformed ({detail}); inspect it or restore from a backup")
        }
        DamageReason::NewerRecord { found } => format!(
            "written by a newer antseal (record format v{found}); upgrade antseal to read it"
        ),
        DamageReason::SlotMoved => {
            "changed while it was being read (another antseal may be running); re-run".to_owned()
        }
    }
}

/// The kind's stable identifier — the kebab spelling `serde` emits for
/// [`AnchorKind`], written as an exhaustive match so a third mechanism has to
/// name itself here too.
const fn kind_name(kind: AnchorKind) -> &'static str {
    match kind {
        AnchorKind::Ots => "ots",
        AnchorKind::Tsa => "tsa",
    }
}

/// The coarse state identifier a user sees — **the** one, since U70.
///
/// # The census this doc used to carry was wrong (U70)
///
/// It read *"the tree already carries a second, wordier spelling in
/// `pipeline/restore.rs` and a third as `listing::WorkRow::state_name`; a
/// fourth is what this visibility avoids"* — and undercounted by one:
/// `pipeline/reveal.rs` held a byte-identical twin of the restore engine's
/// spelling, so there were **four** productions in three vocabularies, and
/// the same vault state answered in different words depending on which
/// command was typed (`status` said `incomplete`, `restore` said
/// `incomplete (paid, not finalized)`). That is the D100 §1.2 class exactly:
/// one fact, several homes, each documented as obviously right and none
/// citing the others.
///
/// U70 reduced the coarse word to this function and nothing else. The three
/// other producers are gone: `listing::WorkRow::state_name` calls this,
/// and the two engine copies did not want the coarse word at all — they
/// wanted the pre-pay/post-pay distinction, which now has exactly one
/// production of its own in [`detail_state_name`] below.
///
/// `tests/work_state_word.rs` fails if a second producer appears. An
/// assertion that the words currently *agree* would not do: it goes green
/// again the moment somebody adds a fourth that happens to agree, which is
/// precisely how the fourth arrived.
///
/// The match is **wildcard-free** so a fifth [`WorkState`] variant breaks at
/// this table rather than rendering as something plausible. The exact copy
/// is U31/Q20's; this owns the count.
/// `pub` rather than `pub(crate)` since U70, for the reason
/// [`crate::backend::unavailable`] is: the property the row is about — that
/// there is exactly **one** of these — is asserted by an integration test,
/// and `tests/` is an external crate. The crate root's stability note
/// sanctions exactly this widening (*"it exists for the binary and the
/// workspace's own harnesses"*).
#[must_use]
pub const fn work_state_name(state: WorkState) -> &'static str {
    match state {
        WorkState::IncompletePrePay | WorkState::IncompletePostPay => "incomplete",
        WorkState::Complete => "complete",
        WorkState::Abandoned => "abandoned",
    }
}

/// The **finer** state identifier: the pre-pay/post-pay distinction, in the
/// kebab spelling `list --json` already publishes as `detail_state`.
///
/// One production, deliberately beside the coarse one (U70). The two are
/// **not** two spellings of one fact and must not be collapsed: the coarse
/// word answers *what state is this work in*, and this one answers the
/// question a user who has to act needs answered — the difference between
/// *"you owe nothing"* and *"you have paid and the proofs expire"*. That is
/// why `restore` and `reveal` reach for it: at the moment they refuse, it is
/// the actionable fact. What U70 forbids is re-spelling the coarse word with
/// a parenthetical, which is how four producers happened.
///
/// This is the fallback half of `listing::WorkRow::detail_state_name` — the
/// arm used when the vault no longer carries S10's finer journal tag — and
/// it is the whole answer for a caller that holds only a [`WorkState`].
/// `detail_state`'s kebab pair stays the shipped machine form; nothing about
/// the `--json` key moves.
///
/// Wildcard-free, for [`work_state_name`]'s reason.
/// `pub` for [`work_state_name`]'s reason.
#[must_use]
pub const fn detail_state_name(state: WorkState) -> &'static str {
    match state {
        WorkState::IncompletePrePay => "incomplete-pre-pay",
        WorkState::IncompletePostPay => "incomplete-post-pay",
        WorkState::Complete => "complete",
        WorkState::Abandoned => "abandoned",
    }
}

/// A seal id as lowercase hex — the way a work is named in a debug trace when
/// it has no `work_id` yet, and the spelling U24's hook uses for every skip it
/// records.
pub(crate) fn hex_seal(seal_id: &SealId) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(32);
    for byte in seal_id.as_bytes() {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

#[cfg(test)]
#[path = "status/tests.rs"]
mod tests;
