//! The seal pipeline (S12): the normative order, the complete blob set, and
//! ciphertext-only egress.
//!
//! # The order, and why it is the order
//!
//! ```text
//! plan validation → canonicalize → encrypt units (journaled)
//!   → build + sign manifest → encrypt manifest → compute every address
//!   → quote_batch (the FULL blob set)   ── D49 truncation point ──
//!   → consent → anchor gate → pay → journal the receipt → finalize_batch
//! ```
//!
//! **Every cheap, failable step precedes the one irreversible paid step.**
//! An over-cap file, a missing consent, an unreachable TSA — each aborts
//! with nothing spent. That is not a stylistic preference: `pay()` is the
//! only operation in the system that cannot be undone, so everything that
//! can say no must say it first.
//!
//! Two orderings inside that sequence are load-bearing and easy to get
//! backwards:
//!
//! - **Staged bytes are journaled before the quote**, not after. The quote
//!   is a backend call, and the invariant is that nothing irreversible can
//!   happen while the bytes that would have to be re-uploaded exist only in
//!   memory.
//! - **Consent precedes the anchor gate.** Anchoring makes network
//!   submissions (OTS calendars, TSAs) that outlive the invocation, so
//!   nothing is submitted on a user's behalf before they have agreed to the
//!   seal (MVP-SPEC.md line 34).
//!
//! # Ciphertext-only egress
//!
//! The blob set handed to the backend is exactly: every unit ciphertext
//! (raw mirrors included) plus the encrypted manifest. This is enforced by
//! type, not by review — the only way to construct the vector the pipeline
//! passes to `quote_batch`/`finalize_batch` is from
//! [`StagedBlob`](super::journal::StagedBlob) values, whose `ciphertext`
//! field is populated solely by `encrypt_unit`/`encrypt_manifest` output.
//! No plaintext value in this module has a path to a `Blob`.
//!
//! # `--dry-run` is this pipeline, truncated (D49)
//!
//! Dry-run is not a parallel mode with its own bugs: it is the same code
//! running to the `PostQuote` barrier and stopping. Every plan-validation
//! error fires identically — that is the rehearsal value — and the quote is
//! a **real** quote over the real blob set.
//!
//! The one carve-out, and its exact scope: **journaling is disabled** for a
//! dry-run ([`JournalSink::Disabled`]), so it performs zero vault writes.
//! The "no backend call precedes journaling of staged bytes" invariant is
//! scoped to the **paid path** — it exists so staged bytes are durable
//! before anything *paid or anchored* can happen, and a dry-run reaches
//! neither. Reading that invariant literally enough to demand journal
//! writes from a mode that must not mutate the vault is the contradiction
//! D49 found between S12 and U16; this is where it is resolved, in the
//! doc comment D49 required.
//!
//! The cost figure a dry-run reports is **indicative**: the real seal draws
//! fresh nonces, so its ciphertexts have different addresses, reach a
//! different peer set, and are priced at a later moment. True pricing
//! mechanism, indicative figure.

use antseal_core::content::{
    ContentModel, FileFlags, FileInput, Unit, UnitKind as ContentUnitKind, assemble_content_model,
};
use antseal_core::crypto::commit::{canon_commit, path_commit, raw_commit, unit_commit};
use antseal_core::crypto::disclosure::UnitBinding;
use antseal_core::crypto::hkdf::{
    FileId, UnitId, derive_file_salt, derive_fine_seed, derive_path_salt, derive_unit_salt,
};
use antseal_core::crypto::manifest_aead::encrypt_manifest;
use antseal_core::crypto::material::MasterSecretRef;
use antseal_core::crypto::padding::padded_length;
use antseal_core::crypto::secrets::{MasterSecret, SealId};
use antseal_core::crypto::sig_policy::{SigPolicy, public_keys, sign_body};
use antseal_core::crypto::unit_aead::encrypt_unit;
use antseal_core::manifest::{
    ByteRange, CanonMode, ContentAddress, FileEntry, FineTree, ManifestBodyV1, Nonce24, SigAlgMap,
    SigMaterial, UnitEntry, UnitKind as WireUnitKind, anchor_digest, encode_body, encode_envelope,
};
use antseal_core::storage::compute_storage_address;
use antseal_net::{Blob, CostQuote, MAX_CHUNK_SIZE, NetworkId, StorageBackend};
use rand_core::TryCryptoRng;

use super::consent::ConsentHook;
use super::error::{Barrier, BarrierHook, SealError};
use super::journal::{BlobSlot, JournalError, SealJournal, SealPlan, StagedBlob, WorkIdentity};
use super::resume::{Pipeline, SealOutcome};
use crate::vault::store::SealShapingFlags;
use antseal_anchor::AnchorGate;

/// The XChaCha20-Poly1305 authentication tag, in bytes — the difference
/// between a unit's padded plaintext length and its ciphertext length
/// (D32's seal-time size arithmetic).
pub const AEAD_TAG_LEN: u64 = 16;

/// One file of the work as handed to the pipeline.
///
/// Bytes are borrowed: the caller read the file (this library performs no
/// I/O of its own on the seal path), and the content model borrows them
/// onward, so a file's bytes exist once in memory however many units
/// reference them.
#[derive(Debug, Clone, Copy)]
pub struct SealFile<'a> {
    /// The path exactly as the user gave it (recorded, and committed to via
    /// `path_commit`).
    pub path_as_given: &'a str,
    /// The same path lexically absolutized — D45's resume match key.
    pub path_absolute: &'a str,
    /// The file's raw bytes.
    pub bytes: &'a [u8],
    /// The per-file seal flags in semantic form (`--force-text`,
    /// `--split`, `--no-fine-tree` already glob-resolved).
    pub flags: FileFlags,
}

/// Everything a seal invocation needs that is not an injected interface.
#[derive(Debug)]
pub struct SealRequest<'a> {
    /// The work's files, in argument order (position = `file_id`).
    pub files: &'a [SealFile<'a>],
    /// `--title`, or the empty string.
    pub title: String,
    /// The sealer's claimed time, Unix seconds. **Injected, never read
    /// from a clock here**, so the pipeline stays deterministic under test
    /// (and so the one place a clock is trusted is a place a reviewer can
    /// find).
    pub claimed_time_unix_secs: u64,
    /// The `app_version` string the manifest records.
    pub app_version: String,
    /// The effective network.
    pub network: NetworkId,
    /// `--no-anchor` (dev only).
    pub no_anchor: bool,
    /// `--force-degraded`, recorded on the work.
    pub degraded: bool,
    /// `--dry-run` (D49): run to the post-quote barrier and stop.
    pub dry_run: bool,
    /// The signature policy the manifest is signed under.
    pub sig_policy: SigPolicy,
    /// The D45 seal-shaping flag set, for the invocation identity record.
    pub shaping: SealShapingFlags,
}

/// What a dry-run produced (D49): a real quote over the real blob set, and
/// nothing else.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DryRunReport {
    /// The quote — **indicative**: the real seal re-encrypts under fresh
    /// nonces and therefore re-quotes different addresses at a later time.
    pub quote: CostQuote,
    /// How many blobs the quote covers (units + the encrypted manifest).
    pub blob_count: usize,
    /// Total ciphertext bytes that would be uploaded.
    pub ciphertext_bytes: u64,
    /// Per-file unit counts, in `file_id` order.
    pub units_per_file: Vec<u64>,
}

/// The outcome of [`Pipeline::seal`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SealResult {
    /// The seal completed: paid, uploaded, marked complete.
    Sealed(SealOutcome),
    /// `--dry-run`: quoted and stopped, with zero vault writes, zero
    /// anchor submissions, zero payment and zero upload.
    DryRun(DryRunReport),
}

/// The D49 journal carve-out as a type rather than as scattered `if`s.
///
/// Every staging write goes through this, so "a dry-run performs no
/// journal write" is a property of one enum with two arms instead of a
/// property of five call sites all remembering the same condition.
enum JournalSink<'j, J> {
    Enabled(&'j J),
    Disabled,
}

impl<J: SealJournal> JournalSink<'_, J> {
    fn begin(&self, identity: &WorkIdentity<'_>) -> Result<(), JournalError> {
        match self {
            Self::Enabled(journal) => journal.begin(identity),
            Self::Disabled => Ok(()),
        }
    }

    fn put_staged(&self, seal_id: &SealId, blob: &StagedBlob) -> Result<(), JournalError> {
        match self {
            Self::Enabled(journal) => journal.put_staged(seal_id, blob),
            Self::Disabled => Ok(()),
        }
    }

    fn put_plan(&self, seal_id: &SealId, plan: &SealPlan) -> Result<(), JournalError> {
        match self {
            Self::Enabled(journal) => journal.put_plan(seal_id, plan),
            Self::Disabled => Ok(()),
        }
    }

    fn record_outcome(&self, seal_id: &SealId, work_id: [u8; 32]) -> Result<(), JournalError> {
        match self {
            Self::Enabled(journal) => journal.record_outcome(seal_id, Some(work_id), None),
            Self::Disabled => Ok(()),
        }
    }
}

impl<B, G, J, C, H> Pipeline<'_, B, G, J, C, H>
where
    B: StorageBackend,
    G: AnchorGate,
    J: SealJournal,
    C: ConsentHook,
    H: BarrierHook,
{
    /// Seal a work: the full normative order, end to end.
    ///
    /// `rng` supplies `W`, the `seal_id`, and every AEAD nonce. It is
    /// injected rather than reached for, which is what lets the whole
    /// pipeline be replayed byte-identically under test.
    ///
    /// # Errors
    ///
    /// Plan-validation failures ([`SealError::NoAnchorOnMainnet`],
    /// [`SealError::BlobExceedsChunkCap`], [`SealError::EmptyWork`]) abort
    /// before any write, submission, quote or payment.
    /// [`SealError::ConsentDeclined`] and [`SealError::AnchorGate`] abort
    /// with zero money spent. Storage, journal and crypto failures surface
    /// in their own classes.
    pub async fn seal<R: TryCryptoRng + ?Sized>(
        &self,
        request: &SealRequest<'_>,
        rng: &mut R,
    ) -> Result<SealResult, SealError> {
        // ── Plan validation, part 1: the checks that need no content ──
        //
        // S13's guard is here, beneath U13's CLI check, so driving the
        // library directly cannot mint a paid-for mainnet seal with the
        // anchor gate bypassed.
        if request.no_anchor && request.network == NetworkId::ArbitrumOne {
            return Err(SealError::NoAnchorOnMainnet);
        }
        if request.files.is_empty() {
            return Err(SealError::EmptyWork);
        }

        let w = MasterSecret::generate(rng)?;
        let seal_id = SealId::generate(rng)?;
        let secret = w.secret_ref();

        // ── Canonicalize + assemble the content model (pure; no I/O, no
        //    clock, no randomness — and, crucially, no side effect) ──
        let inputs: Vec<FileInput<'_>> = request
            .files
            .iter()
            .map(|file| FileInput::new(file.bytes, file.flags))
            .collect();
        let model = assemble_content_model(&inputs, &|id: FileId| derive_fine_seed(secret, id));

        // ── Plan validation, part 2: D32's per-blob chunk cap ──
        //
        // Still before every side effect: assembly wrote nothing, so this
        // fires before any journal write, consent render, anchor
        // submission or backend call — which is what makes it the
        // authoritative check rather than a courtesy. Leaving it to
        // upstream would mean quoting and *paying* for an unstorable
        // chunk.
        validate_blob_caps(&model)?;
        self.barriers.at(Barrier::PostPlanValidation)?;

        let sink = if request.dry_run {
            JournalSink::Disabled
        } else {
            JournalSink::Enabled(self.journal)
        };

        sink.begin(&WorkIdentity {
            w: secret,
            seal_id,
            network: request.network.as_str().to_owned(),
            unanchored: request.no_anchor,
            degraded: request.degraded,
            input_paths_as_given: request
                .files
                .iter()
                .map(|f| f.path_as_given.to_owned())
                .collect(),
            input_paths_absolute: request
                .files
                .iter()
                .map(|f| f.path_absolute.to_owned())
                .collect(),
            shaping: request.shaping.clone(),
        })?;

        // ── Encrypt every unit, journaling each as it is produced ──
        let mut staged: Vec<StagedBlob> = Vec::with_capacity(model.units().len() + 1);
        for unit in model.units() {
            let plaintext =
                model
                    .unit_bytes(unit)
                    .ok_or(SealError::Journal(JournalError::Corrupt {
                        detail: "the content model produced a unit with no bytes",
                    }))?;
            let (ciphertext, nonce) =
                encrypt_unit(secret, &seal_id, UnitId(unit.unit_id()), plaintext, rng)?;
            let address = compute_storage_address(&ciphertext).map_err(|_| {
                // Unreachable: `validate_blob_caps` already refused this.
                over_cap(&format!("file {}, unit {}", unit.file_id(), unit.unit_id()))
            })?;
            let blob = StagedBlob {
                slot: BlobSlot::Unit {
                    unit_id: unit.unit_id(),
                },
                nonce: *nonce.as_bytes(),
                address,
                ciphertext,
            };
            sink.put_staged(&seal_id, &blob)?;
            staged.push(blob);
        }

        // ── Build + sign the manifest over those nonces and addresses ──
        let manifest_bytes = build_manifest(request, secret, &seal_id, &model, &staged)?;
        let work_id_bytes =
            antseal_core::manifest::work_id(manifest_body_of(&manifest_bytes)?).into_bytes();

        // ── Encrypt the manifest; it is a blob like any other ──
        let (manifest_blob, _record) = encrypt_manifest(secret, &manifest_bytes, rng)?;
        let manifest_address = compute_storage_address(&manifest_blob)
            .map_err(|_| over_cap("the encrypted manifest"))?;
        let manifest_staged = StagedBlob {
            slot: BlobSlot::EncryptedManifest,
            nonce: [0; 24],
            address: manifest_address,
            ciphertext: manifest_blob,
        };
        // The manifest's own nonce lives in its storage record, not in the
        // unit table; the journal keeps the slot for shape uniformity.
        let manifest_staged = StagedBlob {
            nonce: *_record.nonce().as_bytes(),
            ..manifest_staged
        };
        sink.put_staged(&seal_id, &manifest_staged)?;
        staged.push(manifest_staged);

        let unit_count = u64::try_from(model.units().len())
            .map_err(|_| SealError::Journal(JournalError::UnitIdOutOfRange))?;
        sink.put_plan(
            &seal_id,
            &SealPlan {
                unit_count,
                manifest_bytes: Some(manifest_bytes.clone()),
            },
        )?;
        sink.record_outcome(&seal_id, work_id_bytes)?;
        self.barriers.at(Barrier::PostStagingJournal)?;

        // ── The complete blob set, in canonical order ──
        let mut blobs = Vec::with_capacity(staged.len());
        let mut ciphertext_bytes = 0_u64;
        for blob in &staged {
            ciphertext_bytes = ciphertext_bytes.saturating_add(blob.ciphertext.len() as u64);
            blobs.push(
                Blob::new(blob.ciphertext.clone()).map_err(|_| over_cap("a staged ciphertext"))?,
            );
        }

        // ── Quote the FULL set (units + encrypted manifest) ──
        let quote = self.backend.quote_batch(&blobs).await?;
        self.barriers.at(Barrier::PostQuote)?;

        // ── D49's truncation point ──
        if request.dry_run {
            return Ok(SealResult::DryRun(DryRunReport {
                quote,
                blob_count: blobs.len(),
                ciphertext_bytes,
                units_per_file: model
                    .files()
                    .iter()
                    .map(|f| model.units_of(f.file_id()).len() as u64)
                    .collect(),
            }));
        }

        // ── consent → anchor gate → pay → journal → finalize ──
        let digest = anchor_digest(&manifest_bytes).into_bytes();
        let receipt = self
            .consent_anchor_pay(&seal_id, &quote, Some(digest), request.no_anchor, false)
            .await?;
        let addresses = self.finalize(&seal_id, &receipt, &blobs).await?;
        let plan = SealPlan {
            unit_count,
            manifest_bytes: Some(manifest_bytes),
        };
        let work_id = self.complete(&seal_id, &plan, receipt.storage_cost_atto, true)?;

        Ok(SealResult::Sealed(SealOutcome {
            seal_id,
            work_id,
            addresses,
            paid_atto: receipt.storage_cost_atto,
            paid_here: true,
        }))
    }
}

/// **D32's authoritative cap check.**
///
/// Every blob's projected ciphertext length is
/// `padded_length(true_length) + 16`, and the largest storable padded
/// length is `16 383 · 256`, so the maximum unit plaintext is
/// 4 MiB − 257 B. Over-cap **text** units name
/// the `--split blank-lines` remedy in the error; over-cap binary files
/// are a recorded v1 product limit, stated rather than implied.
fn validate_blob_caps(model: &ContentModel<'_>) -> Result<(), SealError> {
    for unit in model.units() {
        let projected = projected_ciphertext_len(unit.true_length());
        if projected > MAX_CHUNK_SIZE as u64 {
            let file = model.file(unit.file_id());
            // `--split` divides a text file's *tiling* domain, so it can
            // only help a normal unit of a text file — never a raw mirror
            // (whole-file by definition) and never a binary file.
            // A file is text exactly when it has a canonical rendition
            // (MVP-SPEC.md line 83).
            let split_hint = file.is_some_and(|f| f.canonical().is_some())
                && unit.kind() == ContentUnitKind::Normal;
            return Err(SealError::BlobExceedsChunkCap {
                subject: format!("file {}, unit {}", unit.file_id(), unit.unit_id()),
                projected_len: projected,
                split_hint,
            });
        }
    }
    Ok(())
}

/// D32's seal-time size arithmetic: padded plaintext plus the AEAD tag.
#[must_use]
pub fn projected_ciphertext_len(true_length: u64) -> u64 {
    let padded = usize::try_from(true_length).map_or(u64::MAX, |len| padded_length(len) as u64);
    padded.saturating_add(AEAD_TAG_LEN)
}

/// Encoding a manifest we just constructed cannot fail on a well-formed
/// body — but library code returns errors rather than unwrapping.
fn encode_failed() -> SealError {
    SealError::Journal(JournalError::Encode)
}

fn over_cap(subject: &str) -> SealError {
    SealError::BlobExceedsChunkCap {
        subject: subject.to_owned(),
        projected_len: MAX_CHUNK_SIZE as u64 + 1,
        split_hint: false,
    }
}

/// Recover the body bytes from an envelope we just encoded (`work_id` is
/// SHA-256 over the body, `anchor_digest` over the whole envelope).
fn manifest_body_of(envelope: &[u8]) -> Result<&[u8], SealError> {
    Ok(antseal_core::manifest::envelope::Manifest::decode(envelope)?.body_bytes())
}

/// Build and sign the manifest over the content model and the staged
/// nonces/addresses.
///
/// Every commitment is salted from `W` through C's derivations; the
/// coverage rule (`fine_root` is the sole commitment of covered bytes) is
/// carried by [`UnitBinding`], which makes "a covered unit has no
/// `unit_commit`" unrepresentable rather than merely checked.
fn build_manifest(
    request: &SealRequest<'_>,
    w: MasterSecretRef<'_>,
    seal_id: &SealId,
    model: &ContentModel<'_>,
    staged: &[StagedBlob],
) -> Result<Vec<u8>, SealError> {
    let mut entries = Vec::with_capacity(model.files().len());
    for (index, file) in model.files().iter().enumerate() {
        let file_id = FileId(file.file_id());
        let file_salt = derive_file_salt(w, file_id);
        let path_salt = derive_path_salt(w, file_id);
        let source = request
            .files
            .get(index)
            .ok_or(SealError::EmptyWork)?
            .path_as_given;

        let canon = match file.canonical() {
            None => CanonMode::Binary,
            Some(canonical) => CanonMode::Text {
                canon_commit: canon_commit(&file_salt, canonical.as_bytes()),
                unicode_version: file
                    .descriptor()
                    .unicode_version()
                    .unwrap_or_default()
                    .to_owned(),
            },
        };
        let fine_tree = match file.fine_root() {
            Some(root) => FineTree::Present {
                root: *root.as_bytes(),
            },
            None => FineTree::Absent,
        };

        let mut units = Vec::with_capacity(model.units_of(file.file_id()).len());
        for unit in model.units_of(file.file_id()) {
            units.push(unit_entry(w, model, unit, staged)?);
        }

        entries.push(FileEntry::new(
            path_commit(&path_salt, source),
            raw_commit(&file_salt, file.raw()),
            canon,
            file.size(),
            fine_tree,
            units,
        )?);
    }

    let pubkeys = SigAlgMap::new(SigMaterial::Pubkey, public_keys(w, &request.sig_policy))?;
    let body = ManifestBodyV1::new(
        request.app_version.clone(),
        *seal_id,
        request.title.clone(),
        request.claimed_time_unix_secs,
        pubkeys,
        request.sig_policy.algorithms().to_vec(),
        entries,
    )?;
    let body_bytes = encode_body(body).map_err(|_| encode_failed())?;
    let signatures = SigAlgMap::new(
        SigMaterial::Signature,
        sign_body(w, &request.sig_policy, &body_bytes),
    )?;
    encode_envelope(&body_bytes, &signatures).map_err(|_| encode_failed())
}

fn unit_entry(
    w: MasterSecretRef<'_>,
    model: &ContentModel<'_>,
    unit: &Unit,
    staged: &[StagedBlob],
) -> Result<UnitEntry, SealError> {
    let binding = if model.is_covered(unit) {
        UnitBinding::FineTreeCovered
    } else {
        let bytes = model
            .unit_bytes(unit)
            .ok_or(SealError::Journal(JournalError::Corrupt {
                detail: "the content model produced a unit with no bytes",
            }))?;
        UnitBinding::NonCovered {
            unit_commit: unit_commit(&derive_unit_salt(w, UnitId(unit.unit_id())), bytes),
        }
    };
    let blob = staged
        .iter()
        .find(|b| {
            b.slot
                == BlobSlot::Unit {
                    unit_id: unit.unit_id(),
                }
        })
        .ok_or(SealError::Journal(JournalError::Corrupt {
            detail: "a unit was not staged before the manifest was built",
        }))?;
    Ok(UnitEntry::new(
        unit.unit_id(),
        match unit.kind() {
            ContentUnitKind::Normal => WireUnitKind::Normal,
            ContentUnitKind::RawMirror => WireUnitKind::RawMirror,
        },
        ByteRange::new(unit.byte_range().start(), unit.byte_range().length()),
        unit.true_length(),
        binding,
        Nonce24::from_bytes(blob.nonce),
        ContentAddress::from_bytes(*blob.address.as_bytes()),
    ))
}
