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
//!   work, four `NagState`s. `list` renders that (U25). `OtsAnchorState` is
//!   not user-visible vocabulary and appears nowhere here.
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
use rand_core::TryCryptoRng;

use crate::error::CliError;
use crate::pipeline::anchors::{AnchorArtifact, ArtifactKind, StoredAnchors, apply_upgrade};
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
pub const RECEIPT_CLASS: &str = "supporting evidence — no independently proven time";

/// What a work with zero headline-eligible anchors says (MVP-SPEC.md line
/// 137, verbatim).
pub const UNANCHORED_NOTE: &str = "UNANCHORED — integrity and signature only, no provable time";

/// The pending-anchor hint, in the second person (D98 rider 5).
///
/// MVP-SPEC.md line 130's *"ask the sealer to run `status --upgrade`"* is
/// verifier-page copy, whose reader is a third party. This command's reader
/// **is** the sealer. The person mismatch is flagged for R18's authoritative
/// wording set at M3 — an alignment check, not an ordering dependency.
pub const PENDING_HINT: &str = "not yet independently provable — run";

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
    pub anchors: Vec<AnchorRow>,
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
    /// # Errors
    ///
    /// Store- and journal-level failures as their CLI classes, and
    /// [`JournalError::Corrupt`] for a work that holds anchor artifacts but
    /// no journaled manifest — the one inconsistency this reader cannot
    /// render around, because `anchor_digest` is derived from the manifest
    /// and every evaluator requires it.
    pub fn gather(
        store: &WorkStore<'_>,
        seal_id: &SealId,
        ctx: StatusContext,
    ) -> Result<Self, CliError> {
        let record = store.load_meta(seal_id).map_err(CliError::from)?;
        let stored = StoredAnchors::read(store, seal_id).map_err(CliError::from)?;
        let digest = anchor_digest_of(store, seal_id, &stored)?;

        let mut anchors = Vec::with_capacity(stored.len());
        for (slot, artifact) in stored.all() {
            anchors.push(AnchorRow {
                slot: slot.clone(),
                verdict: evaluate(artifact, &digest, ctx),
            });
        }

        // R70's kind-level answer, asked for by name. The list is over
        // `AnchorKind`'s own variants rather than over the slots, so a kind
        // with no artifact is a rendered fact and not a silence.
        let absent = [AnchorKind::Ots, AnchorKind::Tsa]
            .into_iter()
            .filter(|kind| !anchors.iter().any(|row| row.verdict.kind() == *kind))
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
            Some(headline) => out.push(format!(
                "  existed no later than {} ({}, {})",
                headline.time_unix,
                kind_name(headline.kind),
                headline.source.as_deref().unwrap_or("source not recorded")
            )),
            None => out.push(format!("  {UNANCHORED_NOTE}")),
        }
        out.push(format!(
            "  {} anchor artifact(s); {} can carry the headline time",
            self.anchors.len(),
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
            out.push(format!("  receipt: {RECEIPT_CLASS}"));
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
        out.push(format!("      independently proven time: {time}"));
    }
    if verdict.state() == AnchorState::Pending {
        out.push(format!(
            "      {PENDING_HINT} `antseal status {work_id} --upgrade`"
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
fn source_label(source: &AnchorSource) -> &'static str {
    if source.is_verified() {
        "verified by this run"
    } else {
        "claimed by the artifact — this run did not verify it"
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
/// The [`PendingWork`] is `None` when the work holds no OTS artifact: there is
/// nothing to poll, which is a state and not a failure.
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
    if stored.ots().is_empty() {
        return Ok((stored, None));
    }
    let anchor_digest = anchor_digest_of(store, seal_id, &stored)?;
    let work = PendingWork {
        // `AppliedUpgrade` echoes this back and nothing on this path reads
        // it: the transition is resolved to a slot positionally (D97 R10)
        // and the work is identified by its `seal_id` throughout. A work
        // reached through `status` always carries one, because a printed
        // work id is how it was resolved.
        work_id: record.work_id.unwrap_or([0; 32]),
        anchor_digest,
        ots: stored
            .ots()
            .iter()
            .map(|(_, artifact)| StoredOtsAnchor {
                artifact: artifact.bytes.clone(),
                upgrade: artifact.upgrade.clone(),
            })
            .collect(),
        tsa: stored
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
    for applied in &report.upgraded {
        let Some((slot, prior)) = stored.ots_entry(applied.anchor_index) else {
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
/// A work with **no** anchors needs no digest, and returning a zero here is
/// harmless because nothing consumes it: the caller has nothing to evaluate.
/// A work *with* anchors and no manifest is an inconsistency this reader
/// refuses rather than papers over.
fn anchor_digest_of(
    store: &WorkStore<'_>,
    seal_id: &SealId,
    stored: &StoredAnchors,
) -> Result<[u8; 32], CliError> {
    let manifest = recorded_plan(store, seal_id)
        .map_err(CliError::from)?
        .and_then(|plan| plan.manifest_bytes);
    match manifest {
        Some(bytes) => Ok(anchor_digest(&bytes).into_bytes()),
        None if stored.is_empty() => Ok([0; 32]),
        None => Err(CliError::from(JournalError::Corrupt {
            detail: "this work holds anchor artifacts but no journaled manifest to derive their \
                     anchor digest from",
        })),
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

/// The coarse state identifier a user sees.
const fn work_state_name(state: WorkState) -> &'static str {
    match state {
        WorkState::IncompletePrePay | WorkState::IncompletePostPay => "incomplete",
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
