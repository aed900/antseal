//! The reveal-flow library API (R16): selection resolution, ciphertext
//! gathering, disclosure preview, and R13 builder invocation.
//!
//! MVP-SPEC.md line 36 (core flow — reveal), line 92 (raw-mirror selection
//! rule), lines 112–114 (reveal bundle contents), line 149 (the canonical
//! `reveal` surface U28/U29 wire onto this API). Per **D34** this
//! orchestration lives in the `antseal_cli` `[lib]` target beside the seal
//! and restore engines — it is forced out of `antseal-core` by the same
//! dependency direction (its `StorageBackend`-typed argument is churn
//! surface), a fact D34 records once for both milestones.
//!
//! # This module ships no CLI surface
//!
//! No prompting, no printing, no file I/O beyond the backend fetch: the API
//! takes typed inputs and returns typed outputs, and the concerns around it
//! — arg parsing, the irreversible-disclosure confirmation, `-o` output,
//! the verifier-page URL print (R26 owns the constant) — are U28/U29's.
//! The two-phase shape exists for exactly that split:
//!
//! ```text
//! RevealEngine::prepare ──► PreparedReveal ──(U29's consent gate)──►
//!   PreparedReveal::build ──► RevealOutput { .sealproof bytes, summary }
//! ```
//!
//! [`RevealEngine::prepare`] resolves and validates the selection, gathers
//! and decrypts ciphertexts, and computes the R15 [`DisclosurePreview`] —
//! everything U29 must show *before* the disclosure is irreversible.
//! Nothing bundle-shaped exists until [`PreparedReveal::build`] runs; a
//! declined consent drops the prepared value and no whole-file commitment
//! is ever opened. Work-id resolution stays with
//! [`resolve_work_id`](super::restore::resolve_work_id) — one resolver,
//! every command that names a work.
//!
//! # Selection semantics (spec lines 92/149; D70)
//!
//! The selection is `--all` or a set of work-global unit ids
//! ([`UnitSelection`]). Duplicates collapse; an unknown id is a typed
//! error; a raw-mirror id explicitly listed is **rejected** through G7's
//! own predicate ([`mirror_selectable`]) so the mistyped-id guard has one
//! implementation — the resulting `ContentError::RawMirrorNotUnitSelectable`
//! is *mapped* (not wrapped) into
//! [`RevealError::RawMirrorNotUnitSelectable`], which carries the offending
//! id and points at the whole-file paths the spec permits. Mirror
//! **inclusion** is derivation, never selection (D70): the mirror rides iff
//! the resolved per-file shape is full and the file has one — including on
//! promotion, where a `--units` subset completing a file pulls in
//! `file_salt`, `s_root` and the mirror together. The [`FilePlan`]s this
//! module constructs can express neither "full without mirror" nor
//! "partial with mirror" (R13's parity property): plans are built only
//! from validated normal-unit ids, so a mirror id cannot reach
//! [`FilePlan::Units`], and [`FilePlan::Full`] has no mirror field to
//! misuse.
//!
//! # Gathering (D43 — cache-first, integrity-rechecked, never an error)
//!
//! Ciphertexts are gathered for **all** units of every touched file —
//! boundary Merkle paths need the whole file's leaves, and D70 §7.5
//! includes the mirror in that set — with the D43 journal→cache
//! reclassified copy preferred: every cache copy is integrity-rechecked
//! (the S4 BLAKE3-256 address recompute via [`check_staged_integrity`],
//! plus equality with the **manifest's** recorded address, the
//! authoritative copy) *before* use, and any mismatch is warned and
//! silently refetched via the backend. Cache loss or corruption is never
//! an error — the refetch is; note the deliberate asymmetry with restore
//! (network-first, cache-fallback, D43 §5): reveal is the interactive
//! consent moment D43's retention exists for. Fetching all touched-file
//! units (not just selected ones) is the documented bandwidth cost of
//! having no persisted tree cache (R16 Notes).
//!
//! # What is decrypted, and why
//!
//! Every touched file's **normal** units are decrypted (the tiling-domain
//! plaintext rebuilds the fine tree for boundary paths, and feeds the R15
//! snippets of the selected ones); a **mirror** is decrypted only when it
//! rides. Nonces come from the manifest unit table exclusively (spec line
//! 91 — the staged duplicate is for resume); AAD binding and key
//! derivation are [`decrypt_unit`]'s, never re-derived here. An unselected
//! unit's plaintext reaches the fine-tree rebuild but never the preview —
//! [`SealedPlaintexts`] is fed disclosed units only, and the preview
//! sources only what it discloses (R15's contract).
//!
//! # What the builder is handed (R13; D70 §7)
//!
//! [`PreparedReveal::build`] invokes [`build_bundle`] with the resolved
//! plan and already-gathered material. Mirror inclusion, `full(F)`
//! classification, the mandatory `verify_bundle` self-check and the D70
//! §7.3 internal assertions are all the **builder's**; this module does
//! not re-verify the returned bytes (the builder's contract says nothing
//! that fails its own verification ever leaves it). Preview parity holds
//! by construction: the preview, the summary and the plan are derived from
//! one resolved selection under the same frozen `full(F)` predicate the
//! builder re-derives (D28 rider 1; D70 §7.6).
//!
//! # Anchors and the receipt
//!
//! Anchor artifacts are read through [`StoredAnchors::require_intact`] —
//! the evidence door: a damaged slot refuses the reveal rather than
//! silently shipping a partial anchor set (D100 R2). Each artifact is
//! mapped to its bundle shape with the **capture-time** status the sealer
//! honestly observed (registry §6.1: sealer-recorded, never trusted): a
//! pending `.ots` is `pending`, an upgraded one is `attested` (offline —
//! only `verify --online` can say `proven` for OTS), and a stored TSA
//! token is `proven` because only tokens passing full core verification
//! are ever stored (U22). `intermediates` is empty — nothing in this crate
//! has ever populated it, and D98 records that the empty slice here is
//! byte-identical to what `status` evaluates. The Arbitrum receipt is
//! embedded **iff** [`RevealRequest::include_receipt`] — presence is the
//! opt-in (registry §7.10) — as `{tx_hashes (capture order), block_number
//! (the minimum over the transactions' recorded numbers — registry §7.10
//! key 1's total definition), payload (the versioned at-rest envelope,
//! A/S's own serialization)}`. A work with no embeddable receipt, or one
//! whose transactions all lack a recorded block number, is a typed error
//! rather than a fabricated field.
//!
//! # Secret hygiene (project rule 6)
//!
//! `W` lives in the loaded [`WorkRecord`]'s zeroizing `MasterSecret` and
//! is only ever borrowed; `k_u`/`k_m` derivations happen inside C's
//! helpers and the builder. No error variant, no tracing field and no
//! summary field carries key material or plaintext content —
//! [`PreparedReveal`]'s hand-written `Debug` renders lengths and counts,
//! never the gathered plaintexts, and [`RevealOutput`]'s renders the
//! bundle's length. The disclosed plaintext appears exactly where R15's
//! carve-out puts it: in the preview snippets of units being deliberately
//! disclosed.
//!
//! [`mirror_selectable`]: antseal_core::content::mirror_selectable
//! [`SealedPlaintexts`]: crate::preview::SealedPlaintexts
//! [`decrypt_unit`]: antseal_core::crypto::unit_aead::decrypt_unit
//! [`check_staged_integrity`]: super::journal::check_staged_integrity
//! [`StoredAnchors::require_intact`]: super::anchors::StoredAnchors::require_intact
//! [`build_bundle`]: antseal_core::builder::build_bundle

use std::collections::{BTreeMap, BTreeSet};

use antseal_core::builder::{BuildError, BuildInputs, FilePlan, RevealPlan, build_bundle};
use antseal_core::bundle::{
    AnchorStatus, OpaqueBytes, OtsAnchor, ReceiptRecord, StorageRecord, TsaAnchor,
};
use antseal_core::content::{RevealSelection as G7Selection, mirror_selectable};
use antseal_core::crypto::hkdf::{UnitId, derive_manifest_key};
use antseal_core::crypto::material::MasterSecretRef;
use antseal_core::crypto::secrets::SealId;
use antseal_core::crypto::unit_aead::{Nonce24 as AeadNonce, decrypt_unit};
use antseal_core::manifest::{
    ContentAddress, Manifest, ManifestBodyV1, Nonce24 as WireNonce24, UnitEntry, UnitKind,
    work_id as manifest_work_id,
};
use antseal_net::{Address, PaymentReceipt, StorageBackend};
use thiserror::Error;

use super::anchors::{AnchorArtifact, ArtifactKind, StoredAnchors};
use super::journal::{
    BlobSlot, JournalError, NONCE_LEN, PLAN_ENTRY, StagedBlob, check_staged_integrity, decode_plan,
};
use super::receipt_sink::{encode_receipt, recorded_receipt};
use super::restore::{BlobOrigin, address_matches, storage_detail};
use crate::preview::{
    DisclosurePreview, PreviewError, SealedPlaintexts, all_normal_units, disclosure_preview,
};
use crate::vault::store::{StoreError, WorkRecord, WorkState, WorkStore};

// ─────────────────────────────────────────────────────────────────────────
// The request
// ─────────────────────────────────────────────────────────────────────────

/// What the user asked to reveal — the semantic form of the canonical
/// `reveal <work-id> (--all | --units <id>...)` surface (spec line 149).
///
/// Deliberately **not** G7's
/// [`RevealSelection`](antseal_core::content::RevealSelection): that enum
/// classifies how a *unit* came to be included (its `WholeFile` arm is a
/// derivation outcome, not a flag), whereas this one is the request as
/// typed. Resolution maps this onto per-file [`FilePlan`]s and consults
/// G7's predicate for the mirror rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnitSelection {
    /// `--all`: every normal unit of the work; mirrors then ride per file
    /// automatically (D70).
    All,
    /// `--units <id>...`: work-global unit ids. Duplicates collapse during
    /// resolution (the same dedup rule [`FilePlan::units`] applies);
    /// unknown and raw-mirror ids are typed errors.
    Ids(Vec<u64>),
}

/// One reveal invocation's typed inputs (the library half of U28's flags).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevealRequest {
    /// Which units.
    pub selection: UnitSelection,
    /// `--include-receipt`: embed the recorded Arbitrum payment receipt.
    /// Omitted by default (spec lines 36/149; presence is the opt-in,
    /// registry §7.10). The receipt record is not even read unless this is
    /// set.
    pub include_receipt: bool,
}

// ─────────────────────────────────────────────────────────────────────────
// The outputs
// ─────────────────────────────────────────────────────────────────────────

/// The reveal summary U28 renders beside the written file: exactly what
/// was disclosed, derived from the same preview the user consented to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevealSummary {
    /// Every disclosed unit id, ascending — selected normal units plus
    /// riding mirrors (= the preview's rows).
    pub revealed_unit_ids: Vec<u64>,
    /// Manifest file ids that became fully revealed (their `file_salt` —
    /// and `s_root` where a fine tree exists — is in the bundle; paths
    /// live in the preview's file entries).
    pub files_fully_revealed: Vec<u64>,
    /// Whether the Arbitrum receipt is embedded.
    pub receipt_included: bool,
    /// Units whose ciphertext came from the D43 cache (observability for
    /// the D43 rules; the restore report carries the same split).
    pub units_from_cache: usize,
    /// Units whose ciphertext was fetched from the network.
    pub units_from_network: usize,
}

/// What one reveal produced: the encoded `.sealproof` (already
/// self-verified by the builder — R13) and the summary.
pub struct RevealOutput {
    /// The encoded `.sealproof` bytes. Writing them to disk is U28's
    /// (`-o`, D48-class overwrite policy); this module performs no file
    /// I/O.
    pub sealproof: Vec<u8>,
    /// The disclosure summary.
    pub summary: RevealSummary,
}

impl core::fmt::Debug for RevealOutput {
    /// Length, not bytes: a bundle is a public artifact, but multi-megabyte
    /// dumps belong in no log line (the `OpaqueBytes` discipline).
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RevealOutput")
            .field("sealproof", &format_args!("<{} B>", self.sealproof.len()))
            .field("summary", &self.summary)
            .finish()
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Errors
// ─────────────────────────────────────────────────────────────────────────

/// Why a reveal could not proceed. A reveal is all-or-nothing — a bundle
/// either builds and self-verifies or nothing is produced — so unlike
/// restore there are no per-file rows. Total over adversarial records;
/// carries ids, states and failure classes — never key material, content
/// bytes or receipt fields.
#[derive(Debug, Error)]
pub enum RevealError {
    /// No work with this id exists in the vault.
    #[error("no work with this id exists in the vault")]
    WorkNotFound,

    /// The work exists but is not `complete`: its content was never fully
    /// uploaded, so no bundle can point at network copies.
    #[error(
        "this work is `{state}`, not complete: its content was never fully uploaded, so there \
         is nothing to reveal (finish it with `antseal seal` to resume, or seal the sources \
         afresh)"
    )]
    NotRevealable {
        /// The coarse work state, as a stable identifier.
        state: &'static str,
    },

    /// `--units` was given with no ids (after deduplication nothing
    /// remains to reveal).
    #[error("the selection names no units; give at least one unit id, or use --all")]
    EmptySelection,

    /// The selection names a unit id the manifest does not contain.
    #[error("the selection names unit {unit_id}, which does not exist in this work")]
    UnknownUnitId {
        /// The offending id.
        unit_id: u64,
    },

    /// The selection names a raw-mirror unit directly — the mistyped-id
    /// guard (spec line 92). Produced through G7's [`mirror_selectable`]
    /// and mapped here so the rejection carries the id and the actionable
    /// alternative (the `ContentError` itself is id-less; the ruling is
    /// still G7's single implementation).
    ///
    /// [`mirror_selectable`]: antseal_core::content::mirror_selectable
    #[error(
        "unit {unit_id} is this file's raw mirror and cannot be selected by id; raw mirrors are \
         included only by revealing the whole file (select all of its units) or by --all"
    )]
    RawMirrorNotUnitSelectable {
        /// The offending id.
        unit_id: u64,
    },

    /// Neither a vault copy nor a locatable network copy of the manifest
    /// exists — no unit table, no reveal.
    #[error(
        "this work's manifest is not available: the vault holds neither the plaintext copy nor \
         the address of the encrypted manifest, and a manifest cannot be located on the \
         network without it"
    )]
    ManifestUnavailable,

    /// The vault no longer records where the encrypted manifest lives, so
    /// the bundle's manifest storage record (registry §7.7 — always
    /// embedded) cannot be assembled.
    #[error(
        "this work's manifest storage record is not available: the vault no longer records the \
         encrypted manifest's address and nonce, which every bundle must embed"
    )]
    StorageRecordUnavailable,

    /// The encrypted manifest could not be fetched.
    #[error("the encrypted manifest could not be fetched: {detail}")]
    ManifestUnfetchable {
        /// The storage-layer failure class, as text (never bytes).
        detail: String,
    },

    /// The manifest blob did not open under `k_m`.
    #[error("the encrypted manifest did not decrypt under this vault's manifest key")]
    ManifestDecrypt,

    /// The manifest bytes are not a well-formed manifest.
    #[error("the manifest is malformed: {detail}")]
    ManifestMalformed {
        /// The decode failure class, as text.
        detail: String,
    },

    /// The manifest does not belong to this work — refusing to disclose
    /// content that may belong to another seal.
    #[error(
        "the manifest recovered for this work does not match its recorded identity ({detail}): \
         refusing to reveal content that may belong to another seal"
    )]
    ManifestIdentityMismatch {
        /// Which field disagreed.
        detail: &'static str,
    },

    /// A vault record cannot drive a safe reveal.
    #[error("{detail}")]
    MalformedRecord {
        /// What is wrong (never record bytes).
        detail: String,
    },

    /// A unit's ciphertext could not be obtained: the network fetch failed
    /// and no usable cache copy exists (cache loss itself is never an
    /// error — this is the refetch failing, D43).
    #[error(
        "unit {unit_id} could not be fetched from the network ({detail}) and no verified local \
         copy exists"
    )]
    Unfetchable {
        /// The unit that could not be obtained.
        unit_id: u64,
        /// The storage-layer failure class, as text.
        detail: String,
    },

    /// The bytes served for a unit are not the bytes its address names
    /// (S4's BLAKE3-256 recompute, D32) — embedding them would fail the
    /// recipient's storage-linkage check, so the reveal refuses instead.
    #[error("unit {unit_id}: the bytes served do not hash to the address the manifest records")]
    AddressMismatch {
        /// The affected unit.
        unit_id: u64,
    },

    /// AEAD open or padding strip failed on an address-verified
    /// ciphertext.
    #[error("unit {unit_id} did not decrypt under the vault's keys: {detail}")]
    UnitDecrypt {
        /// The affected unit.
        unit_id: u64,
        /// The crypto failure class, as text (C4's taxonomy is
        /// content-free).
        detail: String,
    },

    /// The work's anchor slots could not all be read intact — the
    /// [`require_intact`](super::anchors::StoredAnchors::require_intact)
    /// refusal: a bundle silently missing recorded evidence would be
    /// dishonest, so the first damaged slot's own error surfaces instead.
    #[error("an anchor record of this work is unreadable: {source}")]
    AnchorsUnreadable {
        /// The underlying journal failure (`NewerRecord` stays distinct
        /// from `Corrupt` — D100).
        #[source]
        source: JournalError,
    },

    /// A stored anchor artifact cannot be embedded in a bundle (a cap the
    /// wire enforces on decode, enforced by the schema constructors on
    /// this side too).
    #[error("the anchor artifact in slot `{slot}` cannot be embedded: {detail}")]
    AnchorUnembeddable {
        /// The vault slot name.
        slot: String,
        /// The schema-level refusal, as text.
        detail: String,
    },

    /// `--include-receipt` was given but the work has no embeddable
    /// payment receipt.
    #[error("no payment receipt can be embedded: {detail}")]
    ReceiptUnavailable {
        /// Which absence: no record, or a record with no transactions.
        detail: &'static str,
    },

    /// `--include-receipt` was given but the recorded receipt cannot be
    /// turned into the bundle's receipt record.
    #[error("the recorded payment receipt cannot be embedded: {detail}")]
    ReceiptUnusable {
        /// The failure class, as text (never receipt fields — receipts
        /// are wallet-linkable, S7).
        detail: String,
    },

    /// `--include-receipt` was given but no transaction of the recorded
    /// receipt carries a confirmed block number, so registry §7.10 key 1
    /// (the minimum over the transactions' block numbers) is undefinable.
    /// Fabricating one is not an option; enrichment backfills the numbers
    /// idempotently on later pipeline invocations (D33).
    #[error(
        "the recorded payment receipt carries no confirmed block number for any of its \
         transactions, so it cannot be embedded yet"
    )]
    ReceiptBlockNumberUnknown,

    /// The preview computation refused the resolved selection — a
    /// defensive seam (this module validates the selection and the path
    /// count first, so no input that reaches the preview can trip it).
    #[error("the disclosure preview could not be computed: {source}")]
    Preview {
        /// The preview's own typed error.
        #[source]
        source: PreviewError,
    },

    /// The builder refused the assembled inputs, or the built bundle
    /// failed its own mandatory verification (R13's self-check).
    #[error("the proof bundle could not be built: {source}")]
    Build {
        /// R13's typed error.
        #[source]
        source: BuildError,
    },

    /// The record store failed (I/O, cipher, vault state).
    #[error(transparent)]
    Store(#[from] Box<StoreError>),
}

impl From<StoreError> for RevealError {
    fn from(err: StoreError) -> Self {
        match err {
            StoreError::WorkNotFound => RevealError::WorkNotFound,
            other => RevealError::Store(Box::new(other)),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────
// The engine
// ─────────────────────────────────────────────────────────────────────────

/// The reveal engine over a storage backend and an unlocked vault's record
/// store — the same two capabilities the restore engine holds, and for the
/// same reason: `W` and the recorded paths live in U9's meta record, which
/// the journal interface deliberately never exposes.
pub struct RevealEngine<'i, 'v, B> {
    backend: &'i B,
    store: &'i WorkStore<'v>,
}

impl<'i, 'v, B: StorageBackend> RevealEngine<'i, 'v, B> {
    /// Assemble the engine over a backend and an unlocked vault's store.
    pub fn new(backend: &'i B, store: &'i WorkStore<'v>) -> Self {
        Self { backend, store }
    }

    /// Resolve, validate, gather, decrypt and preview one reveal — every
    /// step that must happen *before* U29's irreversible-disclosure
    /// confirmation. Returns a [`PreparedReveal`] holding the preview and
    /// everything [`PreparedReveal::build`] needs; dropping it (a declined
    /// consent) discloses nothing.
    ///
    /// Validation precedes gathering: a rejected selection (unknown id,
    /// bare mirror id, empty set) returns before any byte is fetched or
    /// decrypted.
    ///
    /// # Errors
    ///
    /// [`RevealError::WorkNotFound`] / [`RevealError::NotRevealable`], the
    /// selection classes, the manifest-resolution classes, anchor/receipt
    /// refusals, and per-unit gather/decrypt failures.
    pub async fn prepare(
        &self,
        seal_id: &SealId,
        request: &RevealRequest,
    ) -> Result<PreparedReveal, RevealError> {
        let record = self.store.load_meta(seal_id)?;
        if record.state != WorkState::Complete {
            return Err(RevealError::NotRevealable {
                state: work_state_name(record.state),
            });
        }
        let w = record.w.secret_ref();

        // ── Manifest bytes (vault copy first) + the §7.7 locator ───────
        let locator = self.staged(seal_id, BlobSlot::EncryptedManifest)?;
        let manifest_bytes = self
            .resolve_manifest_bytes(seal_id, w, locator.as_ref())
            .await?;
        // The storage record is embedded in every bundle regardless of
        // which source served the bytes, so the locator is required even
        // when the plaintext copy was.
        let Some(locator) = locator else {
            return Err(RevealError::StorageRecordUnavailable);
        };

        // `manifest` borrows `manifest_bytes`; the borrow ends at the last
        // `body` use below, before the bytes move into the returned value.
        let manifest =
            Manifest::decode(&manifest_bytes).map_err(|err| RevealError::ManifestMalformed {
                detail: err.to_string(),
            })?;
        let body = manifest.body();
        let work_id = manifest_work_id(manifest.body_bytes()).into_bytes();

        // Identity binding (the restore rule, verbatim): the manifest we
        // recovered must be *this* work's — never another seal's content
        // under this work's name.
        if body.seal_id() != seal_id {
            return Err(RevealError::ManifestIdentityMismatch { detail: "seal_id" });
        }
        if let Some(recorded) = record.work_id
            && recorded != work_id
        {
            return Err(RevealError::ManifestIdentityMismatch { detail: "work_id" });
        }
        if record.input_paths_as_given.len() != body.files().len() {
            return Err(RevealError::MalformedRecord {
                detail: format!(
                    "the vault records {} original path(s) for a work whose manifest has {} \
                     file(s)",
                    record.input_paths_as_given.len(),
                    body.files().len()
                ),
            });
        }

        // ── Selection resolution — typed errors before any fetch ───────
        let selection = resolve_selection(body, &request.selection)?;

        // ── Local evidence, before network work: anchors always ride
        //    (empty is legal); the receipt only on the opt-in ────────────
        let (ots_anchors, tsa_anchors) = self.bundle_anchors(seal_id)?;
        let receipt = if request.include_receipt {
            Some(self.bundle_receipt(seal_id)?)
        } else {
            None
        };

        // ── Gather + decrypt every touched file, cache-first (D43) ─────
        let mut plan_files = Vec::with_capacity(body.files().len());
        let mut unit_ciphertexts: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
        let mut file_contents: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
        let mut sealed = SealedPlaintexts::new();
        let mut units_from_cache = 0usize;
        let mut units_from_network = 0usize;

        for (index, entry) in body.files().iter().enumerate() {
            let file_id = index as u64;
            let normal_ids: Vec<u64> = entry
                .units()
                .iter()
                .filter(|unit| unit.kind() == UnitKind::Normal)
                .map(UnitEntry::unit_id)
                .collect();
            let selected_indices: BTreeSet<usize> = normal_ids
                .iter()
                .enumerate()
                .filter(|(_, id)| selection.contains(id))
                .map(|(normal_index, _)| normal_index)
                .collect();
            if selected_indices.is_empty() {
                // Untouched: nothing gathered, nothing decrypted, nothing
                // planned — the generation-side isolation posture.
                plan_files.push(FilePlan::Untouched);
                continue;
            }

            // The same frozen predicate the preview and the builder use:
            // full(F) ⟺ N(F) ≠ ∅ ∧ R(F) = N(F) (D28 rider 1). Naming
            // every normal unit by id IS a full reveal — the promotion
            // case D70 §7.6 requires the consent gate to say.
            let full = selected_indices.len() == normal_ids.len();
            let mirror_rides = full && entry.raw_mirror().is_some();
            let path = record.input_paths_as_given[index].clone();

            let mut tiled: Vec<u8> = Vec::new();
            for unit in entry.units() {
                let unit_id = unit.unit_id();
                let (ciphertext, origin) = self.gather_unit(seal_id, unit).await?;
                match origin {
                    BlobOrigin::Cache => units_from_cache += 1,
                    BlobOrigin::Network => units_from_network += 1,
                }

                let disclosed = match unit.kind() {
                    UnitKind::Normal => selection.contains(&unit_id),
                    UnitKind::RawMirror => mirror_rides,
                };
                // Normal units are always decrypted (the tiling domain
                // rebuilds the fine tree); a mirror only when it rides —
                // an undisclosed mirror's plaintext is never produced.
                if unit.kind() == UnitKind::Normal || disclosed {
                    let plaintext = decrypt_gathered(w, seal_id, unit, &ciphertext)?;
                    if unit.kind() == UnitKind::Normal {
                        if unit.range().start() != tiled.len() as u64 {
                            return Err(RevealError::MalformedRecord {
                                detail: format!(
                                    "the manifest unit table for file {file_id} is not a \
                                     contiguous tiling: unit {unit_id} starts at {} where {} \
                                     bytes have been assembled",
                                    unit.range().start(),
                                    tiled.len()
                                ),
                            });
                        }
                        tiled.extend_from_slice(&plaintext);
                    }
                    if disclosed {
                        sealed.insert(unit_id, plaintext);
                    }
                }
                unit_ciphertexts.insert(unit_id, ciphertext);
            }
            if tiled.len() as u64 != entry.size() {
                return Err(RevealError::MalformedRecord {
                    detail: format!(
                        "file {file_id}'s units assemble to {} bytes; the file entry records {}",
                        tiled.len(),
                        entry.size()
                    ),
                });
            }
            file_contents.insert(file_id, tiled);

            // The plan states what was SELECTED, never a derived shape
            // (D28 rider 1): `--all` is a full-file statement, an id list
            // stays an id list even when it completes the file — the
            // builder derives full(F) and the riding mirror itself, so
            // the classification has exactly one owner.
            plan_files.push(match request.selection {
                UnitSelection::All => FilePlan::full(path),
                UnitSelection::Ids(_) => FilePlan::units(path, selected_indices),
            });
        }

        // ── The R15 preview, over the plaintexts just decrypted ─────────
        let preview =
            disclosure_preview(body, &record.input_paths_as_given, &selection, &mut sealed)
                .map_err(|source| RevealError::Preview { source })?;

        let summary = RevealSummary {
            revealed_unit_ids: preview.rows.iter().map(|row| row.unit_id).collect(),
            files_fully_revealed: preview
                .files
                .iter()
                .filter(|file| file.fully_revealed)
                .map(|file| file.file_id)
                .collect(),
            receipt_included: receipt.is_some(),
            units_from_cache,
            units_from_network,
        };

        Ok(PreparedReveal {
            record,
            manifest_bytes,
            locator_address: locator.address,
            locator_nonce: locator.nonce,
            plan: RevealPlan::new(plan_files),
            unit_ciphertexts,
            file_contents,
            ots_anchors,
            tsa_anchors,
            receipt,
            preview,
            summary,
        })
    }

    /// The manifest envelope bytes: the journaled plaintext copy first
    /// (free, vault-AEAD-authenticated), else the encrypted blob — its D43
    /// cache copy when the integrity recheck passes, else fetched by the
    /// journaled address — opened with `k_m`. Both sources are S14's, in
    /// reveal's cache-first order.
    async fn resolve_manifest_bytes(
        &self,
        seal_id: &SealId,
        w: MasterSecretRef<'_>,
        locator: Option<&StagedBlob>,
    ) -> Result<Vec<u8>, RevealError> {
        if let Some(plaintext) = self.store.get_journal_entry(seal_id, PLAN_ENTRY)? {
            let (recorded, plan) =
                decode_plan(plaintext.as_bytes()).map_err(|err| RevealError::MalformedRecord {
                    detail: format!("the journaled seal plan is unusable: {err}"),
                })?;
            if recorded != *seal_id {
                return Err(RevealError::MalformedRecord {
                    detail: "the journaled seal plan names a different seal".to_owned(),
                });
            }
            if let Some(bytes) = plan.manifest_bytes {
                return Ok(bytes);
            }
        }

        let Some(staged) = locator else {
            return Err(RevealError::ManifestUnavailable);
        };
        let blob = if check_staged_integrity(staged).is_ok() {
            staged.ciphertext.clone()
        } else {
            tracing::warn!(
                "the cached encrypted-manifest copy failed its integrity recheck; refetching (D43)"
            );
            let bytes = self
                .backend
                .get_data(Address::from(staged.address))
                .await
                .map_err(|err| RevealError::ManifestUnfetchable {
                    detail: storage_detail(&err),
                })?;
            if !address_matches(&bytes, &staged.address) {
                return Err(RevealError::ManifestMalformed {
                    detail: "the bytes served do not hash to the manifest's recorded address"
                        .to_owned(),
                });
            }
            bytes
        };
        let nonce = AeadNonce::from_bytes(staged.nonce);
        decrypt_manifest_bytes(w, &nonce, &blob)
    }

    /// One unit's ciphertext, cache-first (D43): the reclassified
    /// journal→cache copy is used iff its S4 address recompute matches
    /// **and** its recorded address is the one the manifest names;
    /// anything else warns and silently refetches. Fetched bytes face the
    /// same recompute — nothing enters a bundle without hashing to the
    /// address the manifest records.
    async fn gather_unit(
        &self,
        seal_id: &SealId,
        unit: &UnitEntry,
    ) -> Result<(Vec<u8>, BlobOrigin), RevealError> {
        let unit_id = unit.unit_id();
        if let Some(blob) = self.staged(seal_id, BlobSlot::Unit { unit_id })? {
            if blob.address.as_bytes() == unit.address().as_bytes()
                && check_staged_integrity(&blob).is_ok()
            {
                return Ok((blob.ciphertext, BlobOrigin::Cache));
            }
            tracing::warn!(
                unit_id,
                "a cached unit ciphertext failed its integrity recheck; refetching (D43)"
            );
        }
        let wanted = Address::from(*unit.address());
        let bytes =
            self.backend
                .get_data(wanted)
                .await
                .map_err(|err| RevealError::Unfetchable {
                    unit_id,
                    detail: storage_detail(&err),
                })?;
        if !address_matches(&bytes, unit.address()) {
            return Err(RevealError::AddressMismatch { unit_id });
        }
        Ok((bytes, BlobOrigin::Network))
    }

    /// The D43 cache copy of one blob, or `None` when the vault holds none
    /// — a malformed cache record degrades to absent (the cache is
    /// refetchable by definition), exactly the restore engine's rule.
    fn staged(&self, seal_id: &SealId, slot: BlobSlot) -> Result<Option<StagedBlob>, RevealError> {
        let Some(entry) = slot.entry_key() else {
            return Ok(None);
        };
        let Some(plaintext) = self.store.get_journal_entry(seal_id, entry)? else {
            return Ok(None);
        };
        match StagedBlob::decode(plaintext.as_bytes()) {
            Ok(blob) if blob.slot == slot => Ok(Some(blob)),
            Ok(_) => {
                tracing::warn!(
                    entry,
                    "a cached blob record names a different slot; ignoring"
                );
                Ok(None)
            }
            Err(err) => {
                tracing::warn!(entry, error = %err, "a cached blob record is unusable; ignoring");
                Ok(None)
            }
        }
    }

    /// Every stored anchor artifact in its bundle shape, through the
    /// evidence door: a damaged slot refuses the whole read (D100 R2 —
    /// `require_intact`, never the reporting door).
    fn bundle_anchors(
        &self,
        seal_id: &SealId,
    ) -> Result<(Vec<OtsAnchor>, Vec<TsaAnchor>), RevealError> {
        let stored = StoredAnchors::read(self.store, seal_id)
            .map_err(|source| RevealError::AnchorsUnreadable { source })?;
        let intact = stored
            .require_intact()
            .map_err(|source| RevealError::AnchorsUnreadable { source })?;

        let mut ots_anchors = Vec::with_capacity(intact.ots().len());
        for (slot, artifact) in intact.ots() {
            ots_anchors.push(bundle_ots_anchor(artifact).map_err(|detail| {
                RevealError::AnchorUnembeddable {
                    slot: slot.clone(),
                    detail,
                }
            })?);
        }
        let mut tsa_anchors = Vec::with_capacity(intact.tsa().len());
        for (slot, artifact) in intact.tsa() {
            tsa_anchors.push(bundle_tsa_anchor(artifact).map_err(|detail| {
                RevealError::AnchorUnembeddable {
                    slot: slot.clone(),
                    detail,
                }
            })?);
        }
        Ok((ots_anchors, tsa_anchors))
    }

    /// The recorded payment receipt in its bundle shape (registry §7.10).
    fn bundle_receipt(&self, seal_id: &SealId) -> Result<ReceiptRecord, RevealError> {
        let receipt = recorded_receipt(self.store, seal_id)
            .map_err(|err| RevealError::ReceiptUnusable {
                detail: err.to_string(),
            })?
            .ok_or(RevealError::ReceiptUnavailable {
                detail: "no payment receipt is recorded for this work",
            })?;
        bundle_receipt_record(&receipt)
    }
}

// ─────────────────────────────────────────────────────────────────────────
// The prepared reveal
// ─────────────────────────────────────────────────────────────────────────

/// Everything one reveal needs, resolved and gathered — the value U29's
/// confirmation gate holds while the user decides. Dropping it discloses
/// nothing; [`Self::build`] turns it into `.sealproof` bytes exactly once.
pub struct PreparedReveal {
    /// The work record (owns the zeroizing `W`).
    record: WorkRecord,
    /// The plaintext manifest envelope bytes, exactly as anchored.
    manifest_bytes: Vec<u8>,
    /// The encrypted manifest's address (registry §7.7).
    locator_address: ContentAddress,
    /// Its AEAD nonce.
    locator_nonce: [u8; NONCE_LEN],
    /// The resolved per-file plan.
    plan: RevealPlan,
    /// Gathered ciphertexts, every unit of every touched file.
    unit_ciphertexts: BTreeMap<u64, Vec<u8>>,
    /// Tiling-domain plaintext per touched file (the fine-tree rebuild
    /// input).
    file_contents: BTreeMap<u64, Vec<u8>>,
    /// Anchor artifacts in bundle shape, journal order.
    ots_anchors: Vec<OtsAnchor>,
    /// TSA artifacts in bundle shape, slot-index order.
    tsa_anchors: Vec<TsaAnchor>,
    /// The receipt, present iff opted in.
    receipt: Option<ReceiptRecord>,
    /// The R15 preview.
    preview: DisclosurePreview,
    /// The summary [`Self::build`] returns unchanged.
    summary: RevealSummary,
}

impl core::fmt::Debug for PreparedReveal {
    /// Lengths and counts only: `file_contents` holds plaintext the reveal
    /// may only partially disclose, and printing it would be the
    /// disclosure (the `BuildInputs` discipline, project rule 6).
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PreparedReveal")
            .field(
                "manifest_bytes",
                &format_args!("<{} B>", self.manifest_bytes.len()),
            )
            .field("plan_files", &self.plan.files().len())
            .field("unit_ciphertexts", &self.unit_ciphertexts.len())
            .field("file_contents", &self.file_contents.len())
            .field("ots_anchors", &self.ots_anchors.len())
            .field("tsa_anchors", &self.tsa_anchors.len())
            .field("receipt", &self.receipt.is_some())
            .field("summary", &self.summary)
            .finish_non_exhaustive()
    }
}

impl PreparedReveal {
    /// The disclosure preview — the exact data U29's irreversible-
    /// disclosure confirmation prints (R15), derived from the same
    /// resolved selection the builder is handed, so what the user consents
    /// to is what the bundle contains.
    #[must_use]
    pub fn preview(&self) -> &DisclosurePreview {
        &self.preview
    }

    /// The disclosure summary (also returned by [`Self::build`]).
    #[must_use]
    pub fn summary(&self) -> &RevealSummary {
        &self.summary
    }

    /// Build, self-verify and encode the `.sealproof` (R13's
    /// [`build_bundle`] — the mandatory `verify_bundle` self-check and the
    /// D70 §7.3 assertions run inside it; nothing that fails its own
    /// verification is ever returned).
    ///
    /// Consumes the prepared value: one consent, one bundle.
    ///
    /// # Errors
    ///
    /// [`RevealError::Build`] — the builder's input validation, assembly
    /// and self-check classes.
    pub fn build(self) -> Result<RevealOutput, RevealError> {
        let Self {
            record,
            manifest_bytes,
            locator_address,
            locator_nonce,
            plan,
            unit_ciphertexts,
            file_contents,
            ots_anchors,
            tsa_anchors,
            receipt,
            preview: _,
            summary,
        } = self;

        // The §7.7 triple: address and nonce from the journaled locator,
        // `k_m` derived fresh (disclosing it costs nothing — the bundle
        // embeds the plaintext manifest).
        let storage_record = StorageRecord::new(
            locator_address,
            WireNonce24::from_bytes(locator_nonce),
            derive_manifest_key(record.w.secret_ref()),
        );

        let sealproof = build_bundle(BuildInputs {
            manifest: &manifest_bytes,
            storage_record,
            plan: &plan,
            unit_ciphertexts: &unit_ciphertexts,
            file_contents: &file_contents,
            w: record.w.secret_ref(),
            ots_anchors,
            tsa_anchors,
            receipt,
        })
        .map_err(|source| RevealError::Build { source })?;

        Ok(RevealOutput { sealproof, summary })
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Selection resolution
// ─────────────────────────────────────────────────────────────────────────

/// Resolve a [`UnitSelection`] against the manifest into the set of
/// **normal** unit ids to reveal.
///
/// `--all` is [`all_normal_units`] (mirrors then ride per file, D70); an
/// id list is deduplicated and validated per id in ascending order —
/// unknown ids and raw-mirror ids are typed errors, the mirror rejection
/// routed through G7's [`mirror_selectable`] so the spec-line-92 rule has
/// one implementation.
///
/// [`mirror_selectable`]: antseal_core::content::mirror_selectable
fn resolve_selection(
    body: &ManifestBodyV1,
    spec: &UnitSelection,
) -> Result<BTreeSet<u64>, RevealError> {
    match spec {
        UnitSelection::All => Ok(all_normal_units(body)),
        UnitSelection::Ids(ids) => {
            let requested: BTreeSet<u64> = ids.iter().copied().collect();
            if requested.is_empty() {
                return Err(RevealError::EmptySelection);
            }
            let kinds: BTreeMap<u64, UnitKind> = body
                .files()
                .iter()
                .flat_map(|file| file.units())
                .map(|unit| (unit.unit_id(), unit.kind()))
                .collect();
            for &unit_id in &requested {
                match kinds.get(&unit_id) {
                    None => return Err(RevealError::UnknownUnitId { unit_id }),
                    Some(UnitKind::RawMirror) => {
                        // The ruling is G7's; this arm only attaches the id.
                        mirror_selectable(G7Selection::UnitIds).map_err(|_source| {
                            RevealError::RawMirrorNotUnitSelectable { unit_id }
                        })?;
                    }
                    Some(UnitKind::Normal) => {}
                }
            }
            Ok(requested)
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Bundle-shape mappings (pure)
// ─────────────────────────────────────────────────────────────────────────

/// One stored OTS artifact as the bundle carries it. The sealer-recorded
/// capture-time status (registry §6.1 — never trusted by a verifier):
/// `pending` until upgraded, `attested` once the D79 upgrade group exists
/// — never `proven`, which for OTS needs the online confirmation only
/// `verify --online` performs.
fn bundle_ots_anchor(artifact: &AnchorArtifact) -> Result<OtsAnchor, String> {
    debug_assert_eq!(artifact.kind, ArtifactKind::OtsPending);
    let status = if artifact.upgrade.is_some() {
        AnchorStatus::Attested
    } else {
        AnchorStatus::Pending
    };
    OtsAnchor::new(
        status,
        OpaqueBytes::from_vec(artifact.bytes.clone()),
        artifact.upgrade.clone(),
    )
    .map_err(|err| err.to_string())
}

/// One stored TSA capture as the bundle carries it. Status `proven` is the
/// honest capture-time record: only tokens passing full core verification
/// are ever stored (U22). `intermediates` stays empty — nothing in this
/// crate has ever populated it, all pinned-root TSAs self-carry their
/// chains, and omission is monotone (D98 gap 2 / A101).
fn bundle_tsa_anchor(artifact: &AnchorArtifact) -> Result<TsaAnchor, String> {
    debug_assert_eq!(artifact.kind, ArtifactKind::TsaToken);
    TsaAnchor::new(
        AnchorStatus::Proven,
        OpaqueBytes::from_vec(artifact.bytes.clone()),
        Vec::new(),
        artifact.fetch_date,
    )
    .map_err(|err| err.to_string())
}

/// The journaled [`PaymentReceipt`] as the bundle's receipt record
/// (registry §7.10): transaction hashes in capture order, the **minimum**
/// recorded block number (key 1's total definition under multi-tx
/// payments), and the versioned at-rest envelope as the opaque payload —
/// the same encoder every vault write uses, so the capture round-trips
/// bit-identically.
fn bundle_receipt_record(receipt: &PaymentReceipt) -> Result<ReceiptRecord, RevealError> {
    let tx_hashes: Vec<[u8; 32]> = receipt
        .txs
        .iter()
        .map(|tx| *tx.tx_hash.as_bytes())
        .collect();
    if tx_hashes.is_empty() {
        // A zero-cost seal paid nothing on-chain; there is no transaction
        // to point a counterparty at.
        return Err(RevealError::ReceiptUnavailable {
            detail: "the recorded receipt contains no payment transaction",
        });
    }
    let block_number = receipt
        .txs
        .iter()
        .filter_map(|tx| tx.block_number)
        .min()
        .ok_or(RevealError::ReceiptBlockNumberUnknown)?;
    let payload = encode_receipt(receipt).map_err(|err| RevealError::ReceiptUnusable {
        detail: err.to_string(),
    })?;
    ReceiptRecord::new(tx_hashes, block_number, OpaqueBytes::from_vec(payload)).map_err(|err| {
        RevealError::ReceiptUnusable {
            detail: err.to_string(),
        }
    })
}

// ─────────────────────────────────────────────────────────────────────────
// Small helpers
// ─────────────────────────────────────────────────────────────────────────

/// Decrypt one gathered unit: nonce from the manifest unit table (the
/// single authoritative copy — spec line 91), AAD and key derivation
/// inside [`decrypt_unit`] (`seal_id ‖ LE64(unit_id)` — never re-derived
/// here).
///
/// [`decrypt_unit`]: antseal_core::crypto::unit_aead::decrypt_unit
fn decrypt_gathered(
    w: MasterSecretRef<'_>,
    seal_id: &SealId,
    unit: &UnitEntry,
    ciphertext: &[u8],
) -> Result<Vec<u8>, RevealError> {
    let unit_id = unit.unit_id();
    let true_length =
        usize::try_from(unit.true_length()).map_err(|_| RevealError::MalformedRecord {
            detail: format!("unit {unit_id} records a length this platform cannot address"),
        })?;
    let nonce = AeadNonce::from_bytes(*unit.nonce().as_bytes());
    decrypt_unit(w, seal_id, UnitId(unit_id), &nonce, ciphertext, true_length).map_err(|err| {
        RevealError::UnitDecrypt {
            unit_id,
            detail: err.to_string(),
        }
    })
}

/// Open the encrypted manifest under `k_m` (empty AAD — spec line 98).
fn decrypt_manifest_bytes(
    w: MasterSecretRef<'_>,
    nonce: &AeadNonce,
    blob: &[u8],
) -> Result<Vec<u8>, RevealError> {
    antseal_core::crypto::manifest_aead::decrypt_manifest(w, nonce, blob)
        .map_err(|_| RevealError::ManifestDecrypt)
}

/// The coarse work state as a stable identifier for messages (the restore
/// engine's spelling, so `reveal` and `restore` name states identically).
const fn work_state_name(state: WorkState) -> &'static str {
    match state {
        WorkState::IncompletePrePay => "incomplete (nothing paid)",
        WorkState::IncompletePostPay => "incomplete (paid, not finalized)",
        WorkState::Complete => "complete",
        WorkState::Abandoned => "abandoned",
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Tests (pure halves; the engine suite is tests/reveal_flow.rs)
// ─────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use antseal_core::bundle::schema::OtsUpgrade;
    use antseal_core::crypto::disclosure::UnitBinding;
    use antseal_core::crypto::error::SigAlg;
    use antseal_core::manifest::fixtures as mf;
    use antseal_core::manifest::{ByteRange, CanonMode, FileEntry, FineTree};
    use antseal_net::{GasSummary, TxHash, TxRecord, TxStatus};

    use super::*;

    // ── fixture helpers (synthetic, NON-SECRET — manifest::fixtures) ──

    /// A single-text-file body: two covered normal units (ids 0/1) and a
    /// raw mirror (id 2) — the preview module's `mirror_body` shape.
    fn mirror_body() -> ManifestBodyV1 {
        let canon = CanonMode::Text {
            canon_commit: mf::commit32(0x03),
            unicode_version: mf::UNICODE_VERSION.to_owned(),
        };
        let units = vec![
            covered(0, 0, 4),
            covered(1, 4, 4),
            noncovered(2, UnitKind::RawMirror, 10),
        ];
        let file = FileEntry::new(
            mf::commit32(0x01),
            mf::commit32(0x02),
            canon,
            8,
            FineTree::Present {
                root: mf::commit32(0x04),
            },
            units,
        )
        .expect("test file entry is well formed");
        ManifestBodyV1::new(
            mf::APP_VERSION.to_owned(),
            mf::seal_id(),
            "reveal fixture".to_owned(),
            mf::CLAIMED_TIME,
            mf::hybrid_pubkeys(),
            vec![SigAlg::Ed25519, SigAlg::MlDsa65],
            vec![file],
        )
        .expect("test body is well formed")
    }

    fn covered(unit_id: u64, start: u64, length: u64) -> UnitEntry {
        UnitEntry::new(
            unit_id,
            UnitKind::Normal,
            ByteRange::new(start, length),
            length,
            UnitBinding::FineTreeCovered,
            mf::nonce(unit_id as u8),
            mf::address(unit_id as u8),
        )
    }

    fn noncovered(unit_id: u64, kind: UnitKind, length: u64) -> UnitEntry {
        UnitEntry::new(
            unit_id,
            kind,
            ByteRange::new(0, length),
            length,
            UnitBinding::NonCovered {
                unit_commit: mf::commit32(0x20 ^ unit_id as u8),
            },
            mf::nonce(unit_id as u8),
            mf::address(unit_id as u8),
        )
    }

    fn tx(seed: u8, block_number: Option<u64>) -> TxRecord {
        TxRecord {
            tx_hash: TxHash::from_bytes([seed; 32]),
            block_number,
            status: TxStatus::Confirmed,
            quote_hashes: Vec::new(),
        }
    }

    fn receipt_with(txs: Vec<TxRecord>) -> PaymentReceipt {
        PaymentReceipt {
            blobs: Vec::new(),
            tx_map: BTreeMap::new(),
            txs,
            storage_cost_atto: 42,
            gas: GasSummary { gas_cost_wei: 7 },
        }
    }

    // ── selection resolution ──

    #[test]
    fn all_resolves_to_every_normal_unit_and_never_a_mirror() {
        let body = mirror_body();
        let resolved =
            resolve_selection(&body, &UnitSelection::All).expect("--all always resolves");
        assert_eq!(resolved, [0u64, 1].into_iter().collect::<BTreeSet<_>>());
    }

    #[test]
    fn duplicate_ids_collapse_to_one_selection() {
        let body = mirror_body();
        let resolved = resolve_selection(&body, &UnitSelection::Ids(vec![0, 0, 0]))
            .expect("duplicates are not an error");
        assert_eq!(resolved, [0u64].into_iter().collect::<BTreeSet<_>>());
    }

    #[test]
    fn an_empty_id_list_is_a_typed_error() {
        let body = mirror_body();
        assert!(matches!(
            resolve_selection(&body, &UnitSelection::Ids(Vec::new())),
            Err(RevealError::EmptySelection)
        ));
    }

    #[test]
    fn an_unknown_id_is_a_typed_error_naming_the_id() {
        let body = mirror_body();
        assert!(matches!(
            resolve_selection(&body, &UnitSelection::Ids(vec![0, 9])),
            Err(RevealError::UnknownUnitId { unit_id: 9 })
        ));
    }

    #[test]
    fn a_bare_mirror_id_is_rejected_through_g7_with_the_pointer() {
        let body = mirror_body();
        let err = resolve_selection(&body, &UnitSelection::Ids(vec![2]))
            .expect_err("the mistyped-id guard fires");
        assert!(matches!(
            err,
            RevealError::RawMirrorNotUnitSelectable { unit_id: 2 }
        ));
        let message = err.to_string();
        assert!(
            message.contains("whole file") && message.contains("--all"),
            "the rejection points at the two legal inclusion routes: {message}"
        );

        // Even alongside the unit that would complete the file: an
        // explicitly listed mirror id is always the mistyped-id case
        // (spec line 92) — the mirror rides by derivation, never by name.
        assert!(matches!(
            resolve_selection(&body, &UnitSelection::Ids(vec![0, 1, 2])),
            Err(RevealError::RawMirrorNotUnitSelectable { unit_id: 2 })
        ));
    }

    // ── anchor mappings (capture-time statuses, registry §6.1) ──

    #[test]
    fn a_pending_ots_artifact_maps_to_status_pending() {
        let artifact = AnchorArtifact {
            kind: ArtifactKind::OtsPending,
            endpoint: String::new(),
            fetch_date: 1_800_000_100,
            bytes: b"not-a-real-ots".to_vec(),
            upgrade: None,
        };
        let anchor = bundle_ots_anchor(&artifact).expect("embeds");
        assert_eq!(anchor.status(), AnchorStatus::Pending);
        assert_eq!(anchor.ots().as_slice(), b"not-a-real-ots");
        assert!(anchor.upgrade().is_none());
    }

    #[test]
    fn an_upgraded_ots_artifact_maps_to_attested_with_its_group_carried() {
        let upgrade = OtsUpgrade::new(850_000, [0x11; 80], 1_800_000_200);
        let artifact = AnchorArtifact {
            kind: ArtifactKind::OtsPending,
            endpoint: String::new(),
            fetch_date: 1_800_000_100,
            bytes: b"upgraded-ots".to_vec(),
            upgrade: Some(upgrade.clone()),
        };
        let anchor = bundle_ots_anchor(&artifact).expect("embeds");
        // Never `proven`: O3 needs an online block header check, and the
        // sealer is offline by construction (the same rule `status` pins).
        assert_eq!(anchor.status(), AnchorStatus::Attested);
        assert_eq!(anchor.upgrade(), Some(&upgrade));
    }

    #[test]
    fn a_tsa_capture_maps_to_proven_with_empty_intermediates() {
        let artifact = AnchorArtifact {
            kind: ArtifactKind::TsaToken,
            endpoint: "https://tsa.example/".to_owned(),
            fetch_date: 1_800_000_300,
            bytes: b"der-token".to_vec(),
            upgrade: None,
        };
        let anchor = bundle_tsa_anchor(&artifact).expect("embeds");
        assert_eq!(anchor.status(), AnchorStatus::Proven);
        assert_eq!(anchor.token().as_slice(), b"der-token");
        assert!(anchor.intermediates().is_empty());
        assert_eq!(anchor.fetch_date(), 1_800_000_300);
    }

    // ── receipt mapping (registry §7.10) ──

    #[test]
    fn the_receipt_block_number_is_the_minimum_over_recorded_transactions() {
        let receipt = receipt_with(vec![
            tx(1, Some(900)),
            tx(2, None), // enrichment pending on this one — not a blocker
            tx(3, Some(750)),
        ]);
        let record = bundle_receipt_record(&receipt).expect("embeds");
        assert_eq!(record.block_number(), 750, "minimum, not first or last");
        assert_eq!(
            record.tx_hashes(),
            &[[1u8; 32], [2; 32], [3; 32]],
            "capture order, every transaction"
        );
        assert!(!record.payload().is_empty(), "the A/S capture rides along");
    }

    #[test]
    fn a_receipt_with_no_recorded_block_number_is_a_typed_error() {
        let receipt = receipt_with(vec![tx(1, None), tx(2, None)]);
        assert!(matches!(
            bundle_receipt_record(&receipt),
            Err(RevealError::ReceiptBlockNumberUnknown)
        ));
    }

    #[test]
    fn a_receipt_with_no_transactions_has_nothing_to_embed() {
        let receipt = receipt_with(Vec::new());
        assert!(matches!(
            bundle_receipt_record(&receipt),
            Err(RevealError::ReceiptUnavailable { .. })
        ));
    }

    // ── the no-CLI-surface discipline, structurally (R16 Accept) ──

    /// The production half of this module performs no prompting, no
    /// printing and no file I/O — those concerns are U28/U29's. Enforced
    /// the way every scan in this crate is (`production_files_naming`
    /// cuts at the first `#[cfg(test)]`), and proven red by a planted
    /// violation.
    #[test]
    fn the_reveal_flow_neither_prompts_nor_prints_nor_touches_files() {
        // `print!(`/`println!(` cover stdout; `eprint` both stderr macros;
        // `std::io` covers stdin prompting and raw handles; `std::fs`
        // covers file I/O. Backend fetch is the one sanctioned I/O and
        // goes through `StorageBackend`, which none of these spell.
        const FORBIDDEN: [&str; 5] = ["print!(", "println!(", "eprint", "std::io", "std::fs"];
        let file = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("pipeline");
        for needle in FORBIDDEN {
            let (named, visited) = crate::seal_session::production_files_naming(&file, needle);
            assert!(visited > 5, "the scan must have walked the pipeline tree");
            assert!(
                !named.iter().any(|f| f == "reveal.rs"),
                "reveal.rs names `{needle}` in its production half — prompting, printing and \
                 file I/O live in U28/U29, never here"
            );
        }

        // The red direction, planted: the scan must catch each needle.
        let dir = std::env::temp_dir().join("antseal-r16-no-cli-surface-scan");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch dir");
        std::fs::write(
            dir.join("reveal.rs"),
            "fn ask() { println!(\"proceed?\"); let _ = std::io::stdin(); std::fs::write(\"x\", \
             b\"y\").ok(); eprint!(\"no\"); print!(\"?\"); }\n",
        )
        .expect("plant");
        for needle in FORBIDDEN {
            let (planted, _) = crate::seal_session::production_files_naming(&dir, needle);
            assert_eq!(
                planted,
                vec!["reveal.rs".to_owned()],
                "the scan must name the planted `{needle}`, or it is not enforcing anything"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
