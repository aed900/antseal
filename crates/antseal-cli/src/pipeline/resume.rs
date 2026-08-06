//! Resume (S11): finishing an interrupted seal from the journal alone —
//! and the shared post-staging tail that a fresh seal (S12) runs too.
//!
//! # The rule everything here serves
//!
//! **Resume re-uploads the byte-identical staged ciphertexts. It never
//! reads a source file, never re-encrypts, and never rebuilds or re-signs
//! the manifest.** Re-encrypting would hand a journaled nonce to a
//! different plaintext — catastrophic `(k_u, nonce)` reuse — and rebuilding
//! the manifest would change bytes that are already anchored. Both are
//! structural here, not conventional: resume never touches `W` at all
//! ([`RecordedIdentity`](super::journal::RecordedIdentity) deliberately
//! carries no secret), so the code that could re-encrypt or re-sign has no
//! key to do it with.
//!
//! # Kill points and what each resumes into
//!
//! | journaled state | what happened | resume does |
//! | --- | --- | --- |
//! | `Staged` | killed before the anchor gate | re-run the gate, then the pre-pay path |
//! | `Anchored` | killed after anchoring, before paying | **re-quote → re-consent → pay** (D36), then finalize |
//! | `Paid` | receipt durable, finalize not started | finalize only — no quote, no consent, no payment |
//! | `Finalizing` | finalize interrupted mid-store | finalize again (idempotent), no payment |
//! | `Complete` / `Abandoned` | terminal | refused as not resumable |
//!
//! # Two outcomes, and the third that is not one
//!
//! - **Staged bytes unavailable** (missing, corrupt, or failing the S4
//!   address recompute) ⇒ the work is **abandoned**: any payment is
//!   forfeited and a fresh seal must start with a new `seal_id` and freshly
//!   drawn nonces. Deliberate, spec-mandated safety-over-cost; it requires
//!   disk loss of the staged bytes after payment, which is rare.
//! - **Consent declined** ⇒ the work stays **incomplete**. Decline is not
//!   abandonment (D36 rule 3): no state transition is written and the work
//!   is resumable later at whatever the market then quotes.
//!
//! # The ~24 h post-pay window (D37)
//!
//! Journaled payment proofs are network-acceptable for about a day. Past
//! that, storers reject them: the payment is stranded and completing the
//! seal needs a *second* payment. That is never silent — the pipeline
//! re-quotes and re-runs the consent gate with
//! [`ConsentRequest::proofs_expired`] set, so the user is told that the
//! already-spent ANT is gone and asked to authorize the new spend. One
//! re-payment attempt per invocation; declining leaves the work incomplete.

use antseal_anchor::AnchorGate;
use antseal_core::crypto::secrets::SealId;
use antseal_core::manifest::{Manifest, anchor_digest, work_id};
use antseal_net::{
    Address, Blob, BlobCost, CostQuote, PaymentReceipt, StorageBackend, StorageError,
};

use super::anchors::{AnchorSummary, artifacts_of};
use super::consent::{ConsentDecision, ConsentHook, ConsentRequest, consent_record};
use super::error::{Barrier, BarrierHook, SealError};
use super::journal::{
    BlobSlot, SealJournal, SealPlan, SealState, StagedBytesUnavailable, check_staged_integrity,
};
use super::receipt_sink::merge_receipts;

/// What a completed seal produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealOutcome {
    /// The work's seal id.
    pub seal_id: SealId,
    /// `work_id = SHA-256(manifest body)` (MVP-SPEC.md line 75).
    pub work_id: [u8; 32],
    /// Every blob's address, in canonical blob order — as returned by
    /// `finalize_batch`, which S17 asserts equals both the S4
    /// precomputation and the manifest's recorded addresses.
    pub addresses: Vec<Address>,
    /// Total storage cost actually paid, atto-ANT. Zero on a resume that
    /// only finalized (the payment happened in an earlier invocation).
    pub paid_atto: u128,
    /// Whether this invocation moved money.
    pub paid_here: bool,
    /// What **this invocation's** anchor stage produced (U22).
    ///
    /// `None` covers three distinct situations that the report renders
    /// differently and must not be collapsed here: `--no-anchor` (no stage),
    /// a resume of a work that was already `Anchored` (the stage ran in an
    /// earlier invocation and anchors are never re-submitted, D36 rule 6),
    /// and a resume that only had to finalize.
    pub anchors: Option<AnchorSummary>,
}

/// The seal pipeline over its injected interfaces (D34 Decision 2).
///
/// Generic over every one of them and `dyn`-free: `StorageBackend` and
/// `AnchorGate` are `async fn` traits and therefore not dyn-compatible, and
/// the pipeline never needed dynamic dispatch — it is monomorphic over the
/// ant-core backend in production and over `MockBackend` in tests.
pub struct Pipeline<'i, B, G, J, C, H> {
    pub(super) backend: &'i B,
    pub(super) gate: &'i G,
    pub(super) journal: &'i J,
    pub(super) consent: &'i C,
    pub(super) barriers: &'i H,
}

impl<'i, B, G, J, C, H> Pipeline<'i, B, G, J, C, H>
where
    B: StorageBackend,
    G: AnchorGate,
    J: SealJournal,
    C: ConsentHook,
    H: BarrierHook,
{
    /// Assemble a pipeline over the four injected interfaces plus the
    /// fault-barrier hook (production passes
    /// [`NoBarriers`](super::error::NoBarriers)).
    pub fn new(
        backend: &'i B,
        gate: &'i G,
        journal: &'i J,
        consent: &'i C,
        barriers: &'i H,
    ) -> Self {
        Self {
            backend,
            gate,
            journal,
            consent,
            barriers,
        }
    }

    /// Finish an interrupted seal from the journal alone (S11).
    ///
    /// # Errors
    ///
    /// [`SealError::NotResumable`] for a terminal work;
    /// [`SealError::StagedBytes`] (the work is marked abandoned first);
    /// [`SealError::ConsentDeclined`] (no state change);
    /// [`SealError::ProofsExpired`] when re-payment is refused; plus the
    /// storage, journal and anchor classes.
    pub async fn resume(&self, seal_id: &SealId) -> Result<SealOutcome, SealError> {
        let state = self.journal.state(seal_id)?;
        if state.is_terminal() {
            return Err(SealError::NotResumable {
                state: state.name(),
            });
        }
        let plan = self
            .journal
            .plan(seal_id)?
            .ok_or(SealError::NothingStaged)?;
        let identity = self.journal.recorded_identity(seal_id)?;

        // The staged-bytes gate, before anything else touches the network:
        // failure here abandons rather than re-encrypts.
        let blobs = self.load_staged(seal_id, &plan)?;

        // The pre-pay path, in the normative order: re-quote → re-consent
        // → (anchor, if the kill landed before it) → pay. The anchor step
        // runs *after* consent even on a resume, because anchoring makes
        // network submissions that outlive the invocation and nothing is
        // submitted on a user's behalf before they agree (spec line 34).
        // A work killed after anchoring never re-anchors: anchors made
        // before the kill stay valid (D36 rule 6).
        // **A journaled receipt is what says money moved — not the state
        // tag.** The two normally agree, but there is exactly one window
        // where they cannot: D37's capture hook journals each sub-batch
        // receipt *inside* `pay`, before `pay` returns, so a crash between
        // that write and the `Paid` transition leaves a durable receipt on
        // a work still tagged pre-pay. Branching on the tag there would
        // re-quote, re-consent and **pay a second time** for a seal that is
        // already paid for. The receipt is therefore the authority and the
        // tag is repaired from it (S11's "`pay` is never invoked when a
        // receipt is journaled", read strictly). Found by S16's matrix.
        let journaled_receipt = self.journal.receipt(seal_id)?;
        let mut paid_here = false;
        let mut paid_atto = 0_u128;
        let mut anchors = None;
        if journaled_receipt.is_none() && !state.is_post_pay() {
            let anchor = if state == SealState::Staged {
                let manifest = plan
                    .manifest_bytes
                    .as_deref()
                    .ok_or(SealError::NothingStaged)?;
                Some(anchor_digest(manifest).into_bytes())
            } else {
                None
            };
            let quote = self.backend.quote_batch(&blobs).await?;
            self.barriers.at(Barrier::PostQuote)?;
            let (receipt, staged_anchors) = self
                .consent_anchor_pay(seal_id, &quote, anchor, identity.unanchored, false, None)
                .await?;
            anchors = staged_anchors;
            paid_atto = receipt.storage_cost_atto;
            paid_here = true;
        } else {
            if !state.is_post_pay() {
                // The repair: a durable receipt on a pre-pay tag. Advancing
                // it is what lets `finalize` run at all (`Anchored →
                // Finalizing` is not a legal edge, and widening the machine
                // to allow it would erase the distinction the repair exists
                // to record).
                self.journal.set_state(seal_id, SealState::Paid)?;
            }
            // **The unpaid remainder** (D37 Decision 5, extended by S31).
            // D37's sink journals each sub-batch receipt from inside `pay`,
            // so a crash between sub-batch txs leaves a receipt that covers
            // *some* blobs. Those must never be re-paid — and the rest must
            // still be paid, or the seal cannot finish: `finalize_batch`
            // refuses a receipt with no record for an unstored blob.
            //
            // The already-paid quote hashes cannot be recovered by
            // re-deriving them: a fresh quote round mints fresh hashes. The
            // durable receipt is the only thing that can say what was
            // already bought, which is the whole reason it has to be
            // durable.
            if let Some(partial) = journaled_receipt {
                let candidates = uncovered_blobs(&blobs, &partial)?;
                if !candidates.is_empty() {
                    let quote = self.backend.quote_batch(&candidates).await?;
                    self.barriers.at(Barrier::PostQuote)?;
                    // **"No record" is not the same as "must be bought."**
                    // A blob the network already holds is quoted
                    // [`BlobCost::AlreadyStored`], is never paid for, and
                    // therefore never acquires a payment record — and
                    // `finalize_batch` skips it on exactly that evidence
                    // (`chunk_exists` first, record required only for the
                    // rest). So the quote, not the receipt, is what decides
                    // whether there is anything left to buy. Paying anyway
                    // would ask the user to consent to a zero spend, and
                    // asserting a record must appear for every candidate
                    // would be asserting something upstream will never do.
                    let anything_to_buy = quote
                        .blobs
                        .iter()
                        .any(|line| matches!(line.cost, BlobCost::Priced { .. }));
                    if anything_to_buy {
                        let already_bought = partial.blobs.len();
                        // Consent is over the remainder quote and nothing
                        // else, so what the user authorizes is exactly what
                        // is about to be spent (D36's unconditional
                        // re-consent).
                        let (merged, _) = self
                            .consent_anchor_pay(
                                seal_id,
                                &quote,
                                None,
                                identity.unanchored,
                                false,
                                Some(partial),
                            )
                            .await?;
                        paid_atto = quote.total_ant_atto;
                        paid_here = true;
                        debug_assert!(
                            merged.blobs.len() > already_bought,
                            "the merge lost records the network was already paid for"
                        );
                    }
                }
            }
        }
        let state = self.journal.state(seal_id)?;

        debug_assert!(state.is_post_pay(), "the pre-pay branches are exhaustive");
        let receipt = self.journal.receipt(seal_id)?.ok_or(SealError::Journal(
            super::journal::JournalError::Corrupt {
                detail: "a post-pay work has no journaled receipt",
            },
        ))?;

        let addresses = match self.finalize(seal_id, &receipt, &blobs).await {
            Ok(addresses) => addresses,
            // D37/D36: the ~24 h window passed. Never silent — re-quote,
            // re-consent (with the stranded-payment warning), re-pay once.
            Err(SealError::Storage(StorageError::ProofsExpired)) => {
                let quote = self.backend.quote_batch(&blobs).await?;
                self.barriers.at(Barrier::PostQuote)?;
                // `prior: None` — see `consent_anchor_pay`: the expired
                // records are what is being replaced, not extended.
                let (fresh, _) = self
                    .consent_anchor_pay(seal_id, &quote, None, identity.unanchored, true, None)
                    .await?;
                paid_atto = paid_atto.saturating_add(fresh.storage_cost_atto);
                paid_here = true;
                self.finalize(seal_id, &fresh, &blobs).await?
            }
            Err(other) => return Err(other),
        };

        let work_id = self.complete(seal_id, &plan, paid_atto, paid_here)?;
        Ok(SealOutcome {
            seal_id: *seal_id,
            work_id,
            addresses,
            paid_atto,
            paid_here,
            anchors,
        })
    }

    // ── shared tail steps (S12's fresh seal runs the same code) ──────

    /// Read every expected staged blob, verify its S4 address, and turn it
    /// into a [`Blob`] — in canonical blob order.
    ///
    /// Any failure marks the work abandoned before returning: the
    /// alternative would be re-encrypting under a journaled nonce, so the
    /// abandon is the safe branch, not the give-up branch.
    pub(super) fn load_staged(
        &self,
        seal_id: &SealId,
        plan: &SealPlan,
    ) -> Result<Vec<Blob>, SealError> {
        match self.try_load_staged(seal_id, plan) {
            Ok(blobs) => Ok(blobs),
            Err(reason) => {
                // Best effort: if the abandon marker itself cannot be
                // written, the staged-bytes failure is still what the
                // caller must hear.
                let _ = self.journal.set_state(seal_id, SealState::Abandoned);
                Err(SealError::StagedBytes(reason))
            }
        }
    }

    fn try_load_staged(
        &self,
        seal_id: &SealId,
        plan: &SealPlan,
    ) -> Result<Vec<Blob>, StagedBytesUnavailable> {
        let slots = plan
            .expected_slots()
            .map_err(|_| StagedBytesUnavailable::Corrupt)?;
        let mut blobs = Vec::with_capacity(slots.len());
        for slot in slots {
            let staged = self.journal.staged(seal_id, slot).map_err(staged_reason)?;
            check_staged_integrity(&staged)?;
            let blob = Blob::new(staged.ciphertext)
                .map_err(|_| StagedBytesUnavailable::ExceedsChunkCap)?;
            blobs.push(blob);
        }
        Ok(blobs)
    }

    /// Run the pre-pay anchor step and persist what it produced (U22).
    ///
    /// In `--no-anchor` mode the gate is **not called at all** (S13): the
    /// skip is the pipeline's, so no injected gate — not even a real one —
    /// can perform a submission for an unanchored work. The early return is
    /// what makes that structural: there is no path through this function on
    /// which `unanchored` is true and `self.gate.run` is reached, so the
    /// property holds for every gate the pipeline can be built with.
    ///
    /// **Do not test that property through the product**, and the reason is
    /// measured: `SubmitAnchorGate::run` checks the same flag, so deleting
    /// this early return leaves every command-level `--no-anchor` test green.
    /// The row that isolates *this* layer is
    /// `tests/seal_pipeline.rs::no_anchor_is_allowed_on_the_development_networks`,
    /// which drives a **refusing** gate double — with this return deleted it
    /// fails with `AnchorGate(PolicyNotMet)`.
    ///
    /// Everything after the gate call is bookkeeping about a submission that
    /// has already happened, and all of it lands **before `pay`** — the
    /// artifacts are durable before any money can move, which is what makes
    /// a crash in the payment window recoverable rather than a seal whose
    /// anchors exist only at the calendars.
    pub(super) async fn run_anchor_gate(
        &self,
        seal_id: &SealId,
        unanchored: bool,
        digest: [u8; 32],
    ) -> Result<Option<AnchorSummary>, SealError> {
        if unanchored {
            return Ok(None);
        }
        let outcome = self.gate.run(digest).await?;
        let Some(submission) = outcome.submission() else {
            // A gate that submitted nothing and did not refuse: the
            // `--no-anchor` gate driven on a development network. Nothing to
            // persist and nothing to report.
            return Ok(None);
        };
        for (slot, artifact) in artifacts_of(submission, self.now_for_artifacts()) {
            self.journal
                .put_anchor(seal_id, &slot, &artifact.encode()?)?;
        }
        let summary = AnchorSummary::from_submission(submission);
        if summary.degraded {
            // The `--force-degraded` flag already sets this at `begin`; this
            // is the case the flag cannot know about — a stage that cleared
            // the gate and still lost an endpoint. "Anchor failures always
            // downgrade the seal report explicitly, never silently" (U22).
            self.journal.mark_degraded(seal_id)?;
        }
        Ok(Some(summary))
    }

    /// The fetch date stamped on the **OTS** artifact record.
    ///
    /// TSA captures carry their own (A2 recorded it at the exchange), so this
    /// is only the merged `.ots`'s. It is provenance that gates no outcome
    /// anywhere (A32), which is why reading the host clock here is safe and
    /// why no test needs to control it.
    fn now_for_artifacts(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |since| since.as_secs())
    }

    /// The money path, in the only order it may ever run:
    /// consent → anchor gate → `pay` → journal the receipt.
    ///
    /// The caller supplies the **fresh** quote it just fetched, and that
    /// exact object is what the consent gate is rendered against and what
    /// `pay` receives — one binding, no re-fetch in between (D36's
    /// pay-argument identity rule, which S16 asserts from the outside).
    ///
    /// `anchor` is `Some(digest)` when the anchor step still has to run
    /// (a fresh seal, or a resume killed before it) and `None` when the
    /// work is already anchored — anchors are never re-submitted.
    ///
    /// `prior` carries payment records that are **already durable and
    /// still usable** — the partial receipt a crash between sub-batch txs
    /// left behind (D37 Decision 5, as extended by S31). When it is
    /// present, `quote` covers only the *unpaid remainder* and what gets
    /// journaled is the merge; journaling the fresh receipt alone would
    /// erase records the network was already paid for.
    pub(super) async fn consent_anchor_pay(
        &self,
        seal_id: &SealId,
        quote: &CostQuote,
        anchor: Option<[u8; 32]>,
        unanchored: bool,
        proofs_expired: bool,
        prior: Option<PaymentReceipt>,
    ) -> Result<(PaymentReceipt, Option<AnchorSummary>), SealError> {
        let request = ConsentRequest {
            seal_id: *seal_id,
            quote,
            blob_count: quote.blobs.len(),
            prior: self.journal.consent(seal_id)?,
            resume: proofs_expired || anchor.is_none(),
            proofs_expired,
        };
        match self
            .consent
            .confirm(&request)
            .map_err(|err| SealError::Consent(Box::new(err)))?
        {
            ConsentDecision::Granted {
                channel,
                at_unix_secs,
            } => {
                self.journal
                    .put_consent(seal_id, consent_record(quote, channel, at_unix_secs))?;
            }
            // D36 rule 3: no transition, no abandon, no state loss.
            ConsentDecision::Declined(reason) => return Err(SealError::ConsentDeclined(reason)),
        }
        self.barriers.at(Barrier::PostConsent)?;

        // The anchor gate: consented, and strictly before `pay`. A refusal
        // here aborts with zero money spent.
        let mut anchors = None;
        if let Some(digest) = anchor {
            anchors = self.run_anchor_gate(seal_id, unanchored, digest).await?;
            self.journal.set_state(seal_id, SealState::Anchored)?;
            self.barriers.at(Barrier::PostAnchor)?;
        }

        // D37 Decision 7 (S31): name the work the durable sink is about to
        // write receipts for. Every path that can pay funnels through here,
        // so the sink's target is structural rather than remembered — and
        // the arm has to land *before* `pay`, because the first sub-batch
        // capture fires from inside it.
        self.journal.arm_receipts(seal_id, prior.as_ref());

        let receipt = self.backend.pay(quote).await?;
        // Only the LAST sub-batch's receipt is still unwritten when `pay`
        // returns cleanly — every earlier one was journaled from inside
        // `pay` by the sink. This write supersedes them with the complete
        // receipt (`put_receipt` is idempotent and last-write-wins), and
        // merges in whatever a previous invocation already paid for.
        let receipt = match prior {
            // Merging is only ever right when the prior records are still
            // *usable*. On the proofs-expired path they are exactly what is
            // being replaced, so that caller passes `None` — merging there
            // would leave `finalize_batch` matching a stale record first.
            Some(prior) => merge_receipts(prior, receipt),
            None => receipt,
        };
        // The one window where money has moved and nothing records it.
        // With `NoBarriers` this call is the empty statement it looks like.
        self.barriers.at(Barrier::PostPayPreReceiptJournal)?;
        self.journal.put_receipt(seal_id, &receipt)?;
        // The machine only moves forward. A first payment advances the work
        // to `Paid`; a *re*-payment of an expired-proof work (D37) is money
        // moving again on a work that is already past that barrier, and the
        // right answer is that it does not travel backwards — not that
        // `Finalizing → Paid` becomes a legal edge. The receipt above is
        // the thing that changed, and it is already durable.
        if !self.journal.state(seal_id)?.is_post_pay() {
            self.journal.set_state(seal_id, SealState::Paid)?;
        }
        self.barriers.at(Barrier::PostReceiptJournalPreFinalize)?;
        Ok((receipt, anchors))
    }

    /// Store every not-yet-stored blob under the recorded receipt. Issues
    /// no payment by construction and is idempotent over partial stores.
    pub(super) async fn finalize(
        &self,
        seal_id: &SealId,
        receipt: &PaymentReceipt,
        blobs: &[Blob],
    ) -> Result<Vec<Address>, SealError> {
        self.journal.set_state(seal_id, SealState::Finalizing)?;
        let addresses = self.backend.finalize_batch(receipt, blobs).await?;
        self.barriers.at(Barrier::PostFinalizePreComplete)?;
        Ok(addresses)
    }

    /// The D43 reclassification plus the outcome fields.
    pub(super) fn complete(
        &self,
        seal_id: &SealId,
        plan: &SealPlan,
        paid_atto: u128,
        paid_here: bool,
    ) -> Result<[u8; 32], SealError> {
        let manifest = plan
            .manifest_bytes
            .as_deref()
            .ok_or(SealError::NothingStaged)?;
        // A read, never a rebuild: `work_id` is SHA-256 over the body
        // bytes, which the envelope carries verbatim.
        let envelope = Manifest::decode(manifest)?;
        let id = work_id(envelope.body_bytes()).into_bytes();
        self.journal.set_state(seal_id, SealState::Complete)?;
        self.journal.record_outcome(
            seal_id,
            Some(id),
            if paid_here { Some(paid_atto) } else { None },
        )?;
        Ok(id)
    }
}

/// The staged blobs a receipt holds **no payment record** for — the
/// *candidates* a resume may still have to buy (D37 Decision 5, extended by
/// S31).
///
/// Candidates, not purchases: a blob the network already holds is quoted
/// `AlreadyStored`, never paid for and therefore never given a record, so
/// the caller re-quotes this set and lets the quote decide.
///
/// Membership is by S4 storage address, which is the same key
/// `finalize_batch` looks a record up by, so "uncovered here" and "refused
/// there" are the same predicate rather than two that agree by habit.
///
/// # The granularity caveat, stated because it is invisible otherwise
///
/// This predicate is per **blob**; payment is per **transfer**. Upstream
/// builds a blob's record only once *every* transfer of that blob has a tx
/// hash (`finalize_ready_blobs`), so a blob whose transfers were split
/// across the crash has no record and lands in the remainder — and its
/// already-paid transfer would be bought again under a fresh quote hash.
///
/// That is unreachable on the pinned stack, and not by luck: single-node
/// payment sorts the quotes by price, pays the median 3× and zeroes every
/// other amount, so a blob has **exactly one** non-zero transfer (D37
/// evidence row 3; S18 measured 5 transfers for 5 blobs). One transfer
/// cannot straddle a sub-batch boundary. If a future upstream ever gives a
/// blob two paying quotes, this needs transfer-level accounting, and the
/// S20 bump review is where that must be caught — the symptom would be a
/// silent overpayment, not a failure.
///
/// # Errors
///
/// [`SealError::Journal`] if a staged blob is over the D32 cap — which
/// [`Blob::new`] already refuses, so reaching it means the journal handed
/// out bytes it should not have. Surfaced rather than unwrapped (library
/// code returns errors).
fn uncovered_blobs(blobs: &[Blob], receipt: &PaymentReceipt) -> Result<Vec<Blob>, SealError> {
    let paid: std::collections::BTreeSet<Address> =
        receipt.blobs.iter().map(|record| record.address).collect();
    let mut remainder = Vec::new();
    for blob in blobs {
        if !paid.contains(&blob_address(blob)?) {
            remainder.push(blob.clone());
        }
    }
    Ok(remainder)
}

/// S4's storage address of a blob's ciphertext (D32's rule, the same one
/// the adapter and the manifest use).
fn blob_address(blob: &Blob) -> Result<Address, SealError> {
    antseal_core::storage::compute_storage_address(blob.as_bytes())
        .map(Address::from)
        .map_err(|_| {
            SealError::Journal(super::journal::corrupt(
                "a staged blob exceeds the chunk cap, which staging refuses",
            ))
        })
}

/// Classify a journal read failure for the staged-bytes gate: only the
/// classes that mean "these bytes cannot be trusted to re-upload" abandon;
/// a newer-schema record or a store failure is not one of them.
fn staged_reason(err: super::journal::JournalError) -> StagedBytesUnavailable {
    match err {
        super::journal::JournalError::StagedBytes(reason) => reason,
        _ => StagedBytesUnavailable::Corrupt,
    }
}

/// Convenience for callers that only have a slot list.
#[must_use]
pub fn canonical_order(unit_count: u64, has_manifest: bool) -> Vec<BlobSlot> {
    let mut slots: Vec<BlobSlot> = (0..unit_count)
        .map(|unit_id| BlobSlot::Unit { unit_id })
        .collect();
    if has_manifest {
        slots.push(BlobSlot::EncryptedManifest);
    }
    slots
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use antseal_anchor::{AnchorGate, AnchorGateError, AnchorSubmissionOutcome};
    use antseal_core::content::{FileFlags, SplitMode};
    use antseal_core::crypto::secrets::SecretBuf;
    use antseal_core::crypto::sig_policy::SigPolicy;
    use antseal_net::test_util::{Fault, MockBackend};
    use antseal_net::{BlobCost, BlobQuote, GasSummary, NetworkId, StorageError, TxRecord};
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    use super::{Pipeline, SealError, merge_receipts, uncovered_blobs};
    use crate::pipeline::consent::{ConsentDecision, ConsentHook, ConsentRequest};
    use crate::pipeline::error::NoBarriers;
    use crate::pipeline::journal::{SealJournal, SealState};
    use crate::pipeline::receipt_sink::VaultReceiptSink;
    use crate::pipeline::seal::{SealFile, SealRequest};
    use crate::pipeline::vault_journal::VaultJournal;
    use crate::vault::kdf::KdfSelection;
    use crate::vault::layout::VaultLayout;
    use crate::vault::session::{UnlockedVault, create_vault, unlock_vault};
    use crate::vault::store::{ConsentChannel, SealShapingFlags, WorkStore};
    use antseal_net::{Address, Blob, CostQuote, PaymentReceipt, StorageBackend};

    // ── the smallest doubles that let a real pipeline run ──────────────

    struct YesGate;
    impl AnchorGate for YesGate {
        async fn run(&self, _digest: [u8; 32]) -> Result<AnchorSubmissionOutcome, AnchorGateError> {
            Ok(AnchorSubmissionOutcome::Empty)
        }
    }

    #[derive(Default)]
    struct YesConsent {
        calls: std::cell::Cell<usize>,
        last_total: std::cell::Cell<u128>,
    }
    impl ConsentHook for YesConsent {
        fn confirm(
            &self,
            request: &ConsentRequest<'_>,
        ) -> Result<ConsentDecision, crate::error::CliError> {
            self.calls.set(self.calls.get() + 1);
            self.last_total.set(request.quote.total_ant_atto);
            Ok(ConsentDecision::Granted {
                channel: ConsentChannel::YesFlag,
                at_unix_secs: 1_800_000_000,
            })
        }
    }

    /// A backend that emulates **exactly** what D37's hook + sink do when a
    /// crash lands between sub-batch txs: the first `landed` blobs are
    /// really paid for through the inner mock, the receipt covering them is
    /// really written to the vault by the real [`VaultReceiptSink`], and
    /// then `pay` fails.
    ///
    /// The mock's own `Fault::AfterSubBatches` cannot serve here on its
    /// own: it fires *instead of* paying, and it has no capture hook, so
    /// it can produce the error but not the durable partial receipt that
    /// is the thing under test.
    struct CrashesBetweenSubBatches<'m> {
        inner: &'m MockBackend,
        sink: Arc<VaultReceiptSink>,
        landed: usize,
        armed: std::cell::Cell<bool>,
    }

    impl StorageBackend for CrashesBetweenSubBatches<'_> {
        async fn quote_batch(&self, blobs: &[Blob]) -> Result<CostQuote, StorageError> {
            self.inner.quote_batch(blobs).await
        }

        async fn balances(&self) -> Result<antseal_net::BalanceReport, StorageError> {
            self.inner.balances().await
        }

        async fn pay(&self, quote: &CostQuote) -> Result<PaymentReceipt, StorageError> {
            if !self.armed.replace(false) {
                return self.inner.pay(quote).await;
            }
            // Only the first `landed` blobs' sub-batches went through.
            let lines: Vec<BlobQuote> = quote.blobs.iter().take(self.landed).cloned().collect();
            let total: u128 = lines
                .iter()
                .map(|line| match &line.cost {
                    BlobCost::AlreadyStored => 0,
                    BlobCost::Priced { payments, .. } => {
                        payments.iter().map(|p| p.amount_atto).sum()
                    }
                })
                .sum();
            let partial = self
                .inner
                .pay(&CostQuote {
                    blobs: lines,
                    total_ant_atto: total,
                    gas_estimate_wei: 0,
                })
                .await?;
            // The hook, doing its one job: the receipt-so-far is on disk
            // before anything else happens.
            self.sink.capture(&partial);
            Err(StorageError::StrandedPayment {
                landed_tx_count: partial.txs.len(),
                reason: "test: killed between sub-batch txs".into(),
            })
        }

        async fn finalize_batch(
            &self,
            receipt: &PaymentReceipt,
            blobs: &[Blob],
        ) -> Result<Vec<Address>, StorageError> {
            self.inner.finalize_batch(receipt, blobs).await
        }

        async fn get_data(&self, address: Address) -> Result<Vec<u8>, StorageError> {
            self.inner.get_data(address).await
        }
    }

    // ── fixtures ──────────────────────────────────────────────────────

    /// NON-SECRET test passphrase.
    fn passphrase() -> SecretBuf {
        SecretBuf::new(b"resume-remainder-test-passphrase".to_vec())
    }

    struct Vault {
        dir: std::path::PathBuf,
        vault: Arc<UnlockedVault>,
    }

    impl Vault {
        fn new(tag: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "antseal-s31-{tag}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_nanos())
            ));
            std::fs::create_dir_all(&dir).expect("mk dir");
            let layout = VaultLayout::at(dir.join("vault"));
            create_vault(
                &layout,
                &passphrase(),
                KdfSelection::Argon2id,
                &mut crate::rng::OsEntropy,
            )
            .expect("create vault");
            let vault = Arc::new(unlock_vault(&layout, &passphrase()).expect("unlock"));
            Self { dir, vault }
        }
    }

    impl Drop for Vault {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    /// Three blank-line-split paragraphs plus a binary file: enough units
    /// that a crash after the first two leaves a real remainder.
    const TEXT: &[u8] = b"alpha paragraph\n\nbeta paragraph\n\ngamma paragraph\n";
    const BINARY: &[u8] = &[0x00, 0xFF, 0x10, 0x20, 0x30, 0x40];

    fn request<'a>(files: &'a [SealFile<'a>]) -> SealRequest<'a> {
        SealRequest {
            files,
            title: "S31 remainder".to_owned(),
            claimed_time_unix_secs: 1_800_000_000,
            app_version: "antseal-test/1".to_owned(),
            network: NetworkId::Devnet,
            no_anchor: true,
            degraded: false,
            dry_run: false,
            sig_policy: SigPolicy::hybrid(),
            shaping: SealShapingFlags::default(),
        }
    }

    fn files() -> Vec<SealFile<'static>> {
        vec![
            SealFile {
                path_as_given: "work.txt",
                path_absolute: "/w/work.txt",
                bytes: TEXT,
                flags: FileFlags::new().with_split(SplitMode::BlankLines),
            },
            SealFile {
                path_as_given: "work.bin",
                path_absolute: "/w/work.bin",
                bytes: BINARY,
                flags: FileFlags::new(),
            },
        ]
    }

    fn block_on<F: std::future::Future>(future: F) -> F::Output {
        antseal_net::test_util::block_on(future)
    }

    // ── the rows ──────────────────────────────────────────────────────

    /// **The S31 property, at mock speed** (the cheap mirror of S18's
    /// devnet row): a crash between sub-batch txs leaves a durable partial
    /// receipt, and the resume buys **only the blobs that receipt does not
    /// cover** — never re-paying the ones it does.
    ///
    /// The counter that settles it is the mock's cumulative quote→tx paid
    /// map. One non-zero transfer per blob, so a correct run ends with
    /// exactly `blob_count` entries; a resume that re-paid the covered
    /// blobs would end with `blob_count + landed`.
    #[test]
    fn a_crash_between_sub_batches_resumes_by_paying_only_the_remainder() {
        const LANDED: usize = 2;

        let fx = Vault::new("remainder");
        let mock = MockBackend::new().with_max_transfers_per_tx(1);
        let sink = VaultReceiptSink::new(Arc::clone(&fx.vault));
        let gate = YesGate;
        let consent = YesConsent::default();
        let mut rng = ChaCha20Rng::from_seed([31u8; 32]);
        let journal = VaultJournal::new(WorkStore::new(fx.vault.as_ref()), &mut rng)
            .with_receipt_sink(Arc::clone(&sink));

        let crashing = CrashesBetweenSubBatches {
            inner: &mock,
            sink: Arc::clone(&sink),
            landed: LANDED,
            armed: std::cell::Cell::new(true),
        };

        let files = files();
        let seal_id = {
            let pipeline = Pipeline::new(&crashing, &gate, &journal, &consent, &NoBarriers);
            let err =
                block_on(pipeline.seal(&request(&files), &mut ChaCha20Rng::from_seed([32u8; 32])))
                    .expect_err("the crash aborts the seal");
            assert!(
                matches!(
                    err,
                    SealError::Storage(StorageError::StrandedPayment { .. })
                ),
                "expected the stranded-payment class, got {err:?}"
            );
            WorkStore::new(fx.vault.as_ref())
                .list_works()
                .expect("enumerate")[0]
        };

        // What the sink made durable, mid-`pay`.
        let partial = journal
            .receipt(&seal_id)
            .expect("journal read")
            .expect("the sink journaled the receipt-so-far from inside pay");
        assert_eq!(partial.blobs.len(), LANDED);
        assert_eq!(sink.writes(), 1);
        assert_eq!(sink.fault(), None);
        assert_eq!(
            journal.state(&seal_id).expect("state"),
            SealState::Anchored,
            "the crash left a pre-pay tag with a durable receipt on it"
        );
        assert_eq!(
            mock.paid_map().len(),
            LANDED,
            "only the landed sub-batches moved money"
        );

        // The resume, over a healthy backend.
        let outcome = {
            let pipeline = Pipeline::new(&mock, &gate, &journal, &consent, &NoBarriers);
            block_on(pipeline.resume(&seal_id)).expect("the crashed work resumes")
        };

        let merged = journal
            .receipt(&seal_id)
            .expect("journal read")
            .expect("journaled");
        let staged: Vec<Blob> = {
            let plan = journal.plan(&seal_id).expect("read").expect("plan");
            super::canonical_order(plan.unit_count, true)
                .into_iter()
                .map(|slot| {
                    Blob::new(journal.staged(&seal_id, slot).expect("staged").ciphertext)
                        .expect("blob")
                })
                .collect()
        };

        assert!(
            uncovered_blobs(&staged, &merged)
                .expect("addresses")
                .is_empty(),
            "the merged receipt must cover every staged blob or finalize could not have run"
        );
        assert_eq!(
            mock.paid_map().len(),
            staged.len(),
            "exactly one paying quote per blob across the crash — a re-pay of the covered blobs \
             would add {LANDED} more"
        );
        assert_eq!(
            mock.payment_tx_count() as usize,
            staged.len(),
            "one sub-batch tx per blob at cap 1, across both invocations"
        );
        assert!(
            mock.double_paid().is_empty(),
            "a quote hash was paid twice: {:?}",
            mock.double_paid()
        );
        assert_eq!(
            merged.txs.len(),
            staged.len(),
            "the merged receipt carries every sub-batch tx, not just the resume's"
        );
        assert!(
            outcome.paid_here,
            "the resume did move money — the remainder"
        );
        assert_eq!(journal.state(&seal_id).expect("state"), SealState::Complete);
        assert_eq!(mock.stored_count(), staged.len(), "every blob is stored");

        // The consent the user actually saw on the resume covered the
        // remainder alone — exactly what was about to be spent.
        assert_eq!(consent.calls.get(), 2, "one consent per payment");
        assert_eq!(
            consent.last_total.get(),
            merged.storage_cost_atto - partial.storage_cost_atto,
            "the resume's consent quoted the remainder, not the whole work"
        );
    }

    /// **The second crash.** A remainder payment is itself a multi-tx
    /// payment, so its sub-batch captures go through the same sink — and a
    /// capture writes the receipt-so-far *of the current `pay`*, which
    /// covers only this round's blobs. Written bare it would **overwrite**
    /// the durable partial the first crash left, and a third invocation
    /// would buy those blobs again: the exact hazard S31 closed, one
    /// invocation deeper.
    ///
    /// So the pipeline arms the sink with the prior it must preserve, and
    /// every capture writes the merge. The counter is the same one: one
    /// paying quote per blob, however many crashes it took.
    #[test]
    fn a_crash_during_the_remainder_keeps_what_the_first_crash_paid_for() {
        const LANDED_FIRST: usize = 2;
        const LANDED_SECOND: usize = 1;

        let fx = Vault::new("double");
        let mock = MockBackend::new().with_max_transfers_per_tx(1);
        let sink = VaultReceiptSink::new(Arc::clone(&fx.vault));
        let gate = YesGate;
        let consent = YesConsent::default();
        let mut rng = ChaCha20Rng::from_seed([35u8; 32]);
        let journal = VaultJournal::new(WorkStore::new(fx.vault.as_ref()), &mut rng)
            .with_receipt_sink(Arc::clone(&sink));

        let files = files();
        let crash = |landed: usize| CrashesBetweenSubBatches {
            inner: &mock,
            sink: Arc::clone(&sink),
            landed,
            armed: std::cell::Cell::new(true),
        };

        // Crash one: two sub-batches land, then `pay` dies.
        let first = crash(LANDED_FIRST);
        block_on(
            Pipeline::new(&first, &gate, &journal, &consent, &NoBarriers)
                .seal(&request(&files), &mut ChaCha20Rng::from_seed([36u8; 32])),
        )
        .expect_err("the first crash aborts the seal");
        let seal_id = WorkStore::new(fx.vault.as_ref())
            .list_works()
            .expect("enumerate")[0];
        assert_eq!(
            journal
                .receipt(&seal_id)
                .expect("read")
                .expect("durable")
                .blobs
                .len(),
            LANDED_FIRST
        );

        // Crash two: the remainder pay lands one more sub-batch, then dies.
        let second = crash(LANDED_SECOND);
        block_on(Pipeline::new(&second, &gate, &journal, &consent, &NoBarriers).resume(&seal_id))
            .expect_err("the second crash aborts the resume");

        let after_two = journal
            .receipt(&seal_id)
            .expect("read")
            .expect("still durable");
        assert_eq!(
            after_two.blobs.len(),
            LANDED_FIRST + LANDED_SECOND,
            "the remainder's capture overwrote the first crash's records instead of extending \
             them — everything the first payment bought is now stranded"
        );
        assert_eq!(
            after_two.txs.len(),
            LANDED_FIRST + LANDED_SECOND,
            "the merged receipt must carry both rounds' transactions"
        );

        // The third invocation finishes it, buying only what is still owed.
        block_on(Pipeline::new(&mock, &gate, &journal, &consent, &NoBarriers).resume(&seal_id))
            .expect("the twice-crashed work resumes");

        let staged_count = journal
            .plan(&seal_id)
            .expect("read")
            .expect("plan")
            .unit_count as usize
            + 1;
        assert_eq!(
            mock.paid_map().len(),
            staged_count,
            "exactly one paying quote per blob across TWO crashes"
        );
        assert_eq!(journal.state(&seal_id).expect("state"), SealState::Complete);
        assert_eq!(mock.stored_count(), staged_count);
        assert_eq!(sink.fault(), None);
    }

    /// The pre-S31 behaviour, kept as the red direction: **without** a
    /// durable sink the same crash leaves no receipt at all, so the resume
    /// re-quotes and pays for the whole work — the already-paid sub-batches
    /// a second time.
    ///
    /// This is what makes the row above a result rather than a tautology.
    #[test]
    fn without_a_durable_sink_the_same_crash_re_pays_the_landed_sub_batches() {
        const LANDED: usize = 2;

        let fx = Vault::new("nosink");
        let mock = MockBackend::new().with_max_transfers_per_tx(1);
        let gate = YesGate;
        let consent = YesConsent::default();
        let mut rng = ChaCha20Rng::from_seed([33u8; 32]);
        // No `.with_receipt_sink(..)` — the tree as it stood before S31.
        let journal = VaultJournal::new(WorkStore::new(fx.vault.as_ref()), &mut rng);

        let files = files();
        let pipeline = Pipeline::new(&mock, &gate, &journal, &consent, &NoBarriers);
        mock.arm_fault(Fault::AfterSubBatches(LANDED));
        block_on(pipeline.seal(&request(&files), &mut ChaCha20Rng::from_seed([34u8; 32])))
            .expect_err("the crash aborts the seal");
        let seal_id = WorkStore::new(fx.vault.as_ref())
            .list_works()
            .expect("enumerate")[0];

        assert!(
            journal.receipt(&seal_id).expect("read").is_none(),
            "no sink, no durable receipt — this is the hazard S31 closed"
        );
        let paid_before = mock.paid_map().len();
        assert_eq!(
            paid_before, LANDED,
            "money moved for the landed sub-batches"
        );

        block_on(Pipeline::new(&mock, &gate, &journal, &consent, &NoBarriers).resume(&seal_id))
            .expect("the resume completes — by paying again");

        let staged_count = {
            let plan = journal.plan(&seal_id).expect("read").expect("plan");
            plan.unit_count as usize + 1
        };
        assert_eq!(
            mock.paid_map().len(),
            paid_before + staged_count,
            "the sinkless resume paid for the WHOLE work again — the {LANDED} already-paid \
             sub-batches included. That is the cost D37 Decision 2 promised was impossible and \
             S31 made so."
        );
    }

    /// `uncovered_blobs` keys on the S4 address, which is the same key
    /// `finalize_batch` resolves a record by — so "uncovered" and
    /// "refused there" cannot drift apart.
    #[test]
    fn uncovered_is_by_storage_address_not_by_position() {
        let blobs: Vec<Blob> = [b"one".as_slice(), b"two".as_slice(), b"three".as_slice()]
            .into_iter()
            .map(|b| Blob::new(b.to_vec()).expect("blob"))
            .collect();
        let covered = |blob: &Blob| super::blob_address(blob).expect("address");

        // A receipt covering the LAST blob only, in no particular order.
        let receipt = PaymentReceipt {
            blobs: vec![antseal_net::BlobPaymentRecord {
                address: covered(&blobs[2]),
                payments: Vec::new(),
                peer_quotes: Vec::new(),
                commitment_sidecars: Vec::new(),
                proof_bytes: Vec::new(),
            }],
            tx_map: std::collections::BTreeMap::new(),
            txs: Vec::new(),
            storage_cost_atto: 0,
            gas: GasSummary { gas_cost_wei: 0 },
        };
        let remainder = uncovered_blobs(&blobs, &receipt).expect("addresses");
        assert_eq!(remainder.len(), 2);
        assert_eq!(remainder[0].as_bytes(), b"one");
        assert_eq!(remainder[1].as_bytes(), b"two");

        // An empty receipt covers nothing; a receipt over all of them
        // covers everything.
        assert_eq!(
            uncovered_blobs(&blobs, &receipt_over(&blobs))
                .expect("addresses")
                .len(),
            0
        );
    }

    fn receipt_over(blobs: &[Blob]) -> PaymentReceipt {
        PaymentReceipt {
            blobs: blobs
                .iter()
                .map(|blob| antseal_net::BlobPaymentRecord {
                    address: super::blob_address(blob).expect("address"),
                    payments: Vec::new(),
                    peer_quotes: Vec::new(),
                    commitment_sidecars: Vec::new(),
                    proof_bytes: Vec::new(),
                })
                .collect(),
            tx_map: std::collections::BTreeMap::new(),
            txs: Vec::new(),
            storage_cost_atto: 0,
            gas: GasSummary { gas_cost_wei: 0 },
        }
    }

    /// The merge keeps the prior records **first** and adds, never
    /// replaces: `finalize_batch` resolves a blob by the first matching
    /// address, and the durable prior is the half whose proofs the network
    /// was already paid for.
    #[test]
    fn merging_keeps_prior_records_first_and_sums_the_cost() {
        let tx = |n: u8| antseal_net::TxHash::from_bytes([n; 32]);
        let qh = |n: u8| antseal_net::QuoteHash::from_bytes([n; 32]);
        let record = |addr: u8| antseal_net::BlobPaymentRecord {
            address: Address::from([addr; 32]),
            payments: Vec::new(),
            peer_quotes: Vec::new(),
            commitment_sidecars: Vec::new(),
            proof_bytes: vec![addr],
        };
        let prior = PaymentReceipt {
            blobs: vec![record(1)],
            tx_map: [(qh(1), tx(1))].into_iter().collect(),
            txs: vec![TxRecord {
                tx_hash: tx(1),
                block_number: Some(7),
                status: antseal_net::TxStatus::Confirmed,
                quote_hashes: vec![qh(1)],
            }],
            storage_cost_atto: 100,
            gas: GasSummary { gas_cost_wei: 5 },
        };
        let fresh = PaymentReceipt {
            blobs: vec![record(2)],
            tx_map: [(qh(2), tx(2))].into_iter().collect(),
            txs: vec![TxRecord {
                tx_hash: tx(2),
                block_number: Some(8),
                status: antseal_net::TxStatus::Confirmed,
                quote_hashes: vec![qh(2)],
            }],
            storage_cost_atto: 40,
            gas: GasSummary { gas_cost_wei: 3 },
        };

        let merged = merge_receipts(prior, fresh);
        assert_eq!(
            merged
                .blobs
                .iter()
                .map(|b| b.proof_bytes[0])
                .collect::<Vec<_>>(),
            vec![1, 2],
            "prior first"
        );
        assert_eq!(merged.tx_map.len(), 2);
        assert_eq!(merged.txs.len(), 2);
        assert_eq!(merged.storage_cost_atto, 140, "the seal's total cost");
        assert_eq!(merged.gas.gas_cost_wei, 8);
        assert!(
            merged.covers_all_paid_quotes(),
            "the merged map must satisfy finalize's gap rule"
        );
    }
}
