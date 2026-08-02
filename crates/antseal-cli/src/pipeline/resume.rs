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

use antseal_anchor::{AnchorGate, AnchorSubmissionOutcome};
use antseal_core::crypto::secrets::SealId;
use antseal_core::manifest::{Manifest, anchor_digest, work_id};
use antseal_net::{Address, Blob, CostQuote, PaymentReceipt, StorageBackend, StorageError};

use super::consent::{ConsentDecision, ConsentHook, ConsentRequest, consent_record};
use super::error::{Barrier, BarrierHook, SealError};
use super::journal::{
    BlobSlot, SealJournal, SealPlan, SealState, StagedBytesUnavailable, check_staged_integrity,
};

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
        let mut paid_here = false;
        let mut paid_atto = 0_u128;
        if !state.is_post_pay() {
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
            let receipt = self
                .consent_anchor_pay(seal_id, &quote, anchor, identity.unanchored, false)
                .await?;
            paid_atto = receipt.storage_cost_atto;
            paid_here = true;
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
                let fresh = self
                    .consent_anchor_pay(seal_id, &quote, None, identity.unanchored, true)
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

    /// Run the pre-pay anchor step.
    ///
    /// In `--no-anchor` mode the gate is **not called at all** (S13): the
    /// skip is the pipeline's, so no injected gate — not even a real one —
    /// can perform a submission for an unanchored work.
    pub(super) async fn run_anchor_gate(
        &self,
        unanchored: bool,
        digest: [u8; 32],
    ) -> Result<AnchorSubmissionOutcome, SealError> {
        if unanchored {
            return Ok(AnchorSubmissionOutcome::Empty);
        }
        Ok(self.gate.run(digest).await?)
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
    pub(super) async fn consent_anchor_pay(
        &self,
        seal_id: &SealId,
        quote: &CostQuote,
        anchor: Option<[u8; 32]>,
        unanchored: bool,
        proofs_expired: bool,
    ) -> Result<PaymentReceipt, SealError> {
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
        if let Some(digest) = anchor {
            self.run_anchor_gate(unanchored, digest).await?;
            self.journal.set_state(seal_id, SealState::Anchored)?;
            self.barriers.at(Barrier::PostAnchor)?;
        }

        let receipt = self.backend.pay(quote).await?;
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
        Ok(receipt)
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
