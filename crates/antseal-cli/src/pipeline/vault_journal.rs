//! [`VaultJournal`] — the production [`SealJournal`], written over U9's
//! encrypted record store (S10 × D34 Decision 2).
//!
//! This is the seam where "when and what to journal" (S) meets "where and
//! how durably" (U): every method here is a shape decision plus a call into
//! [`WorkStore`], which supplies the atomic + fsync'd write, the per-record
//! AEAD, and the splice-resistant identity AAD. Nothing about the vault
//! layout, the cipher, or the file naming is re-decided here.
//!
//! # Two tags, one truth
//!
//! State lives in the fine [`SealState`] record (journal entry
//! [`STATE_ENTRY`]); U9's coarse [`WorkState`] in the meta record is a
//! **derived mirror**, written in the same call so `list`/`status`/D45's
//! resume scan never decrypt a journal entry to know where a work stands.
//! [`SealJournal::state`] reads the fine tag; if the two ever disagreed,
//! the fine tag is authoritative and the mirror is what a repair would
//! rewrite.
//!
//! # The RNG lives here
//!
//! U9's record writes draw a fresh AEAD nonce per record, so the journal
//! needs a CSPRNG. It is **injected** (never reached for), held behind a
//! `RefCell` so the trait can keep its `&self` receivers — see the trait's
//! rustdoc for why `&mut self` was not an option.

use std::cell::RefCell;

use antseal_core::crypto::secrets::{MasterSecret, SealId};
use antseal_net::{JournalReceipt, PaymentReceipt};
use rand_core::TryCryptoRng;

use super::journal::{
    BlobSlot, JournalError, PLAN_ENTRY, RecordedIdentity, STATE_ENTRY, SealJournal, SealPlan,
    SealState, StagedBlob, StagedBytesUnavailable, WorkIdentity, corrupt, decode_plan,
    decode_state, encode_plan, encode_state,
};
use crate::vault::store::{ConsentRecord, WorkRecord, WorkStore};

/// The production seal journal over an unlocked vault's record store.
///
/// Mutating calls assume the caller holds the U5 single-writer vault lock
/// (the same discipline [`WorkStore`] documents).
pub struct VaultJournal<'v, R: TryCryptoRng + ?Sized> {
    store: WorkStore<'v>,
    rng: RefCell<&'v mut R>,
}

impl<'v, R: TryCryptoRng + ?Sized> VaultJournal<'v, R> {
    /// Open the journal over a record store with an injected CSPRNG.
    pub fn new(store: WorkStore<'v>, rng: &'v mut R) -> Self {
        Self {
            store,
            rng: RefCell::new(rng),
        }
    }

    /// The underlying record store (restore and the U-side renderers read
    /// records this module has no opinion about).
    #[must_use]
    pub fn store(&self) -> &WorkStore<'v> {
        &self.store
    }

    /// Read-modify-write of the meta record. Kept private: every field
    /// this journal touches has a named method, so no caller can drift the
    /// record's shape.
    fn update_meta<F>(&self, seal_id: &SealId, edit: F) -> Result<(), JournalError>
    where
        F: FnOnce(&mut WorkRecord),
    {
        let mut record = self.store.load_meta(seal_id)?;
        edit(&mut record);
        let mut rng = self.rng.borrow_mut();
        self.store.store_meta(&record, &mut **rng)?;
        Ok(())
    }
}

impl<R: TryCryptoRng + ?Sized> SealJournal for VaultJournal<'_, R> {
    fn begin(&self, identity: &WorkIdentity<'_>) -> Result<(), JournalError> {
        let record = WorkRecord {
            // `MasterSecret` owns and zeroizes; the identity only lent us
            // a borrowed view, so this is the single copy that persists.
            w: MasterSecret::from_bytes(*identity.w.as_bytes()),
            seal_id: identity.seal_id,
            network: identity.network.clone(),
            state: SealState::Staged.work_state(),
            degraded: identity.degraded,
            unanchored: identity.unanchored,
            input_paths_as_given: identity.input_paths_as_given.clone(),
            input_paths_absolute: identity.input_paths_absolute.clone(),
            shaping: identity.shaping.clone(),
            work_id: None,
            cost_atto: None,
            consent: None,
        };
        {
            let mut rng = self.rng.borrow_mut();
            self.store.create_work(&record, &mut **rng)?;
        }
        let bytes = encode_state(SealState::Staged)?;
        let mut rng = self.rng.borrow_mut();
        self.store
            .put_journal_entry(&identity.seal_id, STATE_ENTRY, &bytes, &mut **rng)?;
        Ok(())
    }

    fn put_staged(&self, seal_id: &SealId, blob: &StagedBlob) -> Result<(), JournalError> {
        let entry = blob
            .slot
            .entry_key()
            .ok_or(JournalError::UnitIdOutOfRange)?;
        let bytes = blob.encode()?;
        let mut rng = self.rng.borrow_mut();
        self.store
            .put_journal_entry(seal_id, entry, &bytes, &mut **rng)?;
        Ok(())
    }

    fn staged(&self, seal_id: &SealId, slot: BlobSlot) -> Result<StagedBlob, JournalError> {
        let entry = slot.entry_key().ok_or(JournalError::UnitIdOutOfRange)?;
        let Some(plaintext) = self.store.get_journal_entry(seal_id, entry)? else {
            return Err(StagedBytesUnavailable::Missing.into());
        };
        // A malformed body is a staged-bytes-unavailable classification
        // (S11 abandons on it); a *newer* record is not — that is "upgrade
        // antseal", and conflating the two would abandon a recoverable
        // seal.
        let blob = StagedBlob::decode(plaintext.as_bytes()).map_err(|err| match err {
            JournalError::Corrupt { .. } => StagedBytesUnavailable::Corrupt.into(),
            other => other,
        })?;
        if blob.slot != slot {
            // The AAD already binds the entry key; the authenticated body
            // must agree with it (the defense-in-depth check U9 performs
            // for `meta`, applied to the journal area).
            return Err(StagedBytesUnavailable::Corrupt.into());
        }
        Ok(blob)
    }

    fn staged_slots(&self, seal_id: &SealId) -> Result<Vec<BlobSlot>, JournalError> {
        let mut units: Vec<u64> = Vec::new();
        let mut manifest = false;
        for key in self.store.list_journal_entries(seal_id)? {
            match BlobSlot::from_entry_key(key) {
                Some(BlobSlot::EncryptedManifest) => manifest = true,
                Some(BlobSlot::Unit { unit_id }) => units.push(unit_id),
                // The reserved non-blob keys (state, plan).
                None => {}
            }
        }
        units.sort_unstable();
        // Canonical blob order: units ascending, encrypted manifest last.
        let mut slots: Vec<BlobSlot> = units
            .into_iter()
            .map(|unit_id| BlobSlot::Unit { unit_id })
            .collect();
        if manifest {
            slots.push(BlobSlot::EncryptedManifest);
        }
        Ok(slots)
    }

    fn put_plan(&self, seal_id: &SealId, plan: &SealPlan) -> Result<(), JournalError> {
        let bytes = encode_plan(seal_id, plan)?;
        let mut rng = self.rng.borrow_mut();
        self.store
            .put_journal_entry(seal_id, PLAN_ENTRY, &bytes, &mut **rng)?;
        Ok(())
    }

    fn plan(&self, seal_id: &SealId) -> Result<Option<SealPlan>, JournalError> {
        let Some(plaintext) = self.store.get_journal_entry(seal_id, PLAN_ENTRY)? else {
            return Ok(None);
        };
        let (recorded_id, plan) = decode_plan(plaintext.as_bytes())?;
        if recorded_id != *seal_id {
            return Err(corrupt("plan record seal_id disagrees with its slot"));
        }
        Ok(Some(plan))
    }

    fn set_state(&self, seal_id: &SealId, state: SealState) -> Result<(), JournalError> {
        let current = self.state(seal_id)?;
        if !current.can_advance_to(state) {
            return Err(JournalError::IllegalTransition {
                from: current,
                to: state,
            });
        }
        if current == state {
            return Ok(());
        }
        // Fine tag first (authoritative), coarse mirror second: a crash
        // between them leaves the mirror one barrier stale, which no
        // safety rule reads — whereas the reverse could show a work as
        // paid before its receipt-bearing state record exists.
        let bytes = encode_state(state)?;
        {
            let mut rng = self.rng.borrow_mut();
            self.store
                .put_journal_entry(seal_id, STATE_ENTRY, &bytes, &mut **rng)?;
        }
        self.update_meta(seal_id, |record| record.state = state.work_state())
    }

    fn state(&self, seal_id: &SealId) -> Result<SealState, JournalError> {
        match self.store.get_journal_entry(seal_id, STATE_ENTRY)? {
            Some(plaintext) => decode_state(plaintext.as_bytes()),
            None => {
                // No state record: either the work does not exist, or it
                // predates this schema. `load_meta` distinguishes.
                self.store.load_meta(seal_id)?;
                Err(corrupt("work has no journal state record"))
            }
        }
    }

    fn put_receipt(&self, seal_id: &SealId, receipt: &PaymentReceipt) -> Result<(), JournalError> {
        let envelope = JournalReceipt::seal(receipt.clone());
        let bytes = serde_json::to_vec(&envelope).map_err(|_| JournalError::Encode)?;
        let mut rng = self.rng.borrow_mut();
        self.store.put_receipt(seal_id, &bytes, &mut **rng)?;
        Ok(())
    }

    fn receipt(&self, seal_id: &SealId) -> Result<Option<PaymentReceipt>, JournalError> {
        let Some(plaintext) = self.store.get_receipt(seal_id)? else {
            return Ok(None);
        };
        let envelope: JournalReceipt = serde_json::from_slice(plaintext.as_bytes())
            .map_err(|_| corrupt("journaled receipt is malformed"))?;
        let receipt = envelope
            .open()
            .map_err(|_| corrupt("journaled receipt carries an unsupported version"))?;
        Ok(Some(receipt))
    }

    fn put_consent(&self, seal_id: &SealId, consent: ConsentRecord) -> Result<(), JournalError> {
        self.update_meta(seal_id, |record| record.consent = Some(consent))
    }

    fn consent(&self, seal_id: &SealId) -> Result<Option<ConsentRecord>, JournalError> {
        Ok(self.store.load_meta(seal_id)?.consent)
    }

    fn recorded_identity(&self, seal_id: &SealId) -> Result<RecordedIdentity, JournalError> {
        let record = self.store.load_meta(seal_id)?;
        // `record` owns `W`; nothing below reads it, and it wipes on drop.
        Ok(RecordedIdentity {
            network: record.network.clone(),
            unanchored: record.unanchored,
            degraded: record.degraded,
            work_id: record.work_id,
            cost_atto: record.cost_atto,
        })
    }

    fn record_outcome(
        &self,
        seal_id: &SealId,
        work_id: Option<[u8; 32]>,
        cost_atto: Option<u128>,
    ) -> Result<(), JournalError> {
        self.update_meta(seal_id, |record| {
            if work_id.is_some() {
                record.work_id = work_id;
            }
            if cost_atto.is_some() {
                record.cost_atto = cost_atto;
            }
        })
    }

    fn incomplete_works(&self) -> Result<Vec<(SealId, SealState)>, JournalError> {
        let mut out = Vec::new();
        for seal_id in self.store.list_works()? {
            let state = self.state(&seal_id)?;
            if state.is_incomplete() {
                out.push((seal_id, state));
            }
        }
        Ok(out)
    }
}
