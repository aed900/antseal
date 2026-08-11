//! The restore engine (S14): fetch every unit ciphertext, decrypt it with
//! vault-derived keys, and **prove the bytes before anyone writes them**.
//!
//! MVP-SPEC.md line 37 (core flow step 4) and lines 141–143 (the vault).
//! This is the door of the permanent vault: the operation that turns `W`
//! plus a network address back into the user's original files. U20 is its
//! CLI half (output directory, overwrite policy, rendering — D48); this
//! module owns everything up to and including "these bytes are provably the
//! sealed content", and it deliberately performs **no file I/O at all**.
//!
//! # The order, and why it is the order
//!
//! ```text
//! resolve work → load W + recorded paths → resolve manifest
//!   → per unit: fetch → address-recompute → AEAD-open + padding-strip
//!   → per file: concatenate non-mirror units → verify commitment
//!              → verify raw mirror (when present)
//!   → hand back verified bytes
//! ```
//!
//! Verification is not a post-hoc audit of files already on disk: nothing
//! leaves this module until its commitment opens. S14's Accept row — "the
//! affected file is not written as verified output" — is a property of the
//! return type, since a file that failed verification yields a
//! [`FileOutcome::Failed`] and there are no bytes in it to write.
//!
//! # Network-first, with a verified-cache fallback (D43 §5)
//!
//! `get_data` is the normative source: it is what the M4 disk-loss drill
//! proves, and what a clean machine has. When a fetch fails and the vault
//! still holds the D43 cache copy of that blob, the cache is used —
//! **after** an S4 address recompute proves the cached bytes are the bytes
//! the manifest names (`check_staged_integrity` plus an equality check
//! against the manifest's own address). Commitment verification then runs
//! on every unit regardless of source, so the fallback costs no trust; and
//! after an Autonomi data loss the cache is the only remaining copy, so a
//! restore that refused to read it would be purism at the worst moment.
//!
//! # Exact original bytes (spec line 92)
//!
//! Where a file has a raw mirror, the mirror's bytes — verified against
//! `raw_commit` — are the output: CRLF endings, a leading BOM and NFD
//! sequences survive a seal/restore round trip intact. Where it has none,
//! the concatenated non-mirror units are the output, and for a text file
//! that concatenation is checked against **both** `canon_commit` and
//! `raw_commit`, which is exactly the manifest's claim that this file
//! needed no mirror (G7's `needs_mirror` is byte inequality).
//!
//! # What restore does **not** check
//!
//! The manifest's signatures. Both manifest sources already prove vault
//! authorship — the vault copy sits inside the vault AEAD, and the network
//! copy opens only under `k_m`, which is derived from this vault's `W` —
//! so a signature check here would re-prove what the AEAD just proved.
//! Signature verification is evidence-layer work and belongs to the
//! verifier (R), which holds no `W` and therefore has nothing else to go
//! on. What restore *does* check about identity is stronger for its
//! purpose: the manifest's `seal_id` and recomputed `work_id` must equal
//! the vault's recorded ones, so one work can never be restored from
//! another's manifest.
//!
//! # Secret hygiene (project rule 6)
//!
//! `W`, `k_u`, `k_m` and every salt live inside a call frame and die with
//! it; no error variant, no tracing field and no report field carries key
//! material or plaintext content. Reports carry file ids, recorded paths,
//! addresses, lengths and counts.
//!
//! # Where the bytes live
//!
//! A whole work's verified bytes are held in memory before U20 writes
//! them, so restore's peak memory is the work's size. At MVP scale
//! (documents, D32's 4 MiB-per-unit cap) that is the honest simple choice;
//! a streaming restore is the v1.1 answer if works ever grow.

use antseal_core::crypto::commit::{verify_canon_commit, verify_raw_commit};
use antseal_core::crypto::error::CryptoError;
use antseal_core::crypto::hkdf::{FileId, UnitId, derive_file_salt};
use antseal_core::crypto::manifest_aead::decrypt_manifest;
use antseal_core::crypto::material::MasterSecretRef;
use antseal_core::crypto::secrets::SealId;
use antseal_core::crypto::unit_aead::{Nonce24 as AeadNonce, decrypt_unit};
use antseal_core::manifest::{
    CanonMode, ContentAddress, FileEntry, Manifest, UnitEntry, UnitKind as WireUnitKind,
    work_id as manifest_work_id,
};
use antseal_core::storage::compute_storage_address;
use antseal_net::{Address, StorageBackend, StorageError};
use thiserror::Error;

use super::journal::{BlobSlot, PLAN_ENTRY, StagedBlob, decode_plan};
use crate::error::CliError;
use crate::vault::store::{StoreError, WorkState, WorkStore};

/// Where a work's manifest came from — reported so an operator can see
/// whether a restore exercised the network path or leaned on the vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManifestSource {
    /// The journaled plaintext manifest (the vault copy; S14's first
    /// source, and free).
    VaultCopy,
    /// Fetched from Autonomi by its journaled address and opened with
    /// `k_m`.
    Network,
    /// The D43 cache copy of the encrypted manifest blob, opened with
    /// `k_m` after its address recompute matched.
    Cache,
}

impl ManifestSource {
    /// Stable kebab identifier for `--json` renders.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::VaultCopy => "vault-copy",
            Self::Network => "network",
            Self::Cache => "cache",
        }
    }
}

/// Where one blob's ciphertext came from (D43 §5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlobOrigin {
    /// `get_data` — the normative path.
    Network,
    /// The verified D43 cache copy, after a fetch failure.
    Cache,
}

/// Which rendition of a file the verified bytes are.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ByteSource {
    /// The file's raw mirror — the exact original bytes (spec line 92).
    RawMirror,
    /// A text file's canonical rendition, which for a mirror-less file is
    /// byte-identical to the original.
    Canonical,
    /// A binary file's raw units (binary files have no canonical
    /// rendition, so their units already *are* the raw bytes).
    Raw,
}

impl ByteSource {
    /// Stable kebab identifier for `--json` renders.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::RawMirror => "raw-mirror",
            Self::Canonical => "canonical",
            Self::Raw => "raw",
        }
    }
}

/// One file whose bytes verified against the manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedFile {
    /// Manifest file id (= position in the recorded path list).
    pub file_id: u64,
    /// The path as the vault recorded it at seal time. Re-rooting it is
    /// U20's job (D48 §2) — this module never touches the filesystem.
    pub recorded_path: String,
    /// The exact bytes to write: raw-mirror bytes wherever one exists.
    pub bytes: Vec<u8>,
    /// Which rendition `bytes` is.
    pub source: ByteSource,
    /// How many of the file's units came from the network.
    pub from_network: usize,
    /// How many came from the D43 cache (D43 §5's fallback).
    pub from_cache: usize,
}

/// One file that could not be produced as verified output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FailedFile {
    /// Manifest file id.
    pub file_id: u64,
    /// The path as the vault recorded it.
    pub recorded_path: String,
    /// Why.
    pub error: FileError,
}

/// Per-file result. `Failed` carries no bytes **by construction**: a file
/// that did not verify cannot be written, because there is nothing to
/// write (S14 Accept row 2, D48 row 4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileOutcome {
    /// Verified bytes, ready for U20's D48 write policy.
    Verified(VerifiedFile),
    /// A typed failure; the run continues with the remaining files.
    Failed(FailedFile),
}

impl FileOutcome {
    /// The manifest file id, whatever the outcome.
    #[must_use]
    pub const fn file_id(&self) -> u64 {
        match self {
            Self::Verified(file) => file.file_id,
            Self::Failed(file) => file.file_id,
        }
    }

    /// The vault-recorded path, whatever the outcome.
    #[must_use]
    pub fn recorded_path(&self) -> &str {
        match self {
            Self::Verified(file) => &file.recorded_path,
            Self::Failed(file) => &file.recorded_path,
        }
    }
}

/// What one restore produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreReport {
    /// The work's seal id (the vault's store key).
    pub seal_id: SealId,
    /// `work_id = SHA-256(manifest body)` — recomputed from the manifest
    /// actually used, and checked against the vault's recorded value.
    pub work_id: [u8; 32],
    /// The work's recorded network (canonical CLI spelling).
    pub network: String,
    /// Sealed with `--no-anchor` — the shaping flag as recorded, copied
    /// straight off the work record.
    ///
    /// Not *"the UNANCHORED work class"*, which is what this line used to
    /// say: MVP-SPEC.md line 137's UNANCHORED is *zero headline-eligible
    /// anchors* and is computed, not recorded (D98 rider 3c;
    /// `WorkStatus::is_unanchored`). `restore` has no anchor evidence in
    /// hand and must not imply it has.
    pub unanchored: bool,
    /// Where the manifest came from.
    pub manifest_source: ManifestSource,
    /// Per-file outcomes, in `file_id` order.
    pub files: Vec<FileOutcome>,
}

impl RestoreReport {
    /// Files that produced verified bytes.
    pub fn verified(&self) -> impl Iterator<Item = &VerifiedFile> {
        self.files.iter().filter_map(|f| match f {
            FileOutcome::Verified(file) => Some(file),
            FileOutcome::Failed(_) => None,
        })
    }

    /// Files that failed.
    pub fn failed(&self) -> impl Iterator<Item = &FailedFile> {
        self.files.iter().filter_map(|f| match f {
            FileOutcome::Failed(file) => Some(file),
            FileOutcome::Verified(_) => None,
        })
    }

    /// Total unit blobs served by the D43 cache rather than the network.
    #[must_use]
    pub fn cache_served_units(&self) -> usize {
        self.verified().map(|f| f.from_cache).sum()
    }
}

/// How a per-file failure ranks for D48 §6's severity ordering.
///
/// The axis is **evidence vs transient**, which is what D48 §6 is really
/// ordering: bytes that arrived and did not verify are an evidence
/// problem, bytes that never arrived are a transient one. D48's table
/// groups "fetch/decrypt" in one row but explicitly admits "distinct per
/// S14's classes"; an AEAD or padding failure on a blob whose address
/// already matched is an integrity statement, so it ranks with
/// verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum FailureKind {
    /// The bytes could not be obtained at all (network, not-found, and no
    /// usable cache copy). D48's transient floor.
    Fetch,
    /// A vault record could not drive a safe restore for this file.
    MalformedRecord,
    /// Bytes arrived and did not verify: address recompute, AEAD open,
    /// padding, or a commitment mismatch.
    Verification,
}

impl FailureKind {
    /// The D48 per-file status identifier (`--json`, and the human
    /// report).
    #[must_use]
    pub const fn status(self) -> &'static str {
        match self {
            Self::Fetch => "fetch-failed",
            Self::MalformedRecord => "malformed-record",
            Self::Verification => "verification-failed",
        }
    }
}

/// Why one file failed. Total over adversarial inputs; carries ids,
/// lengths and addresses — never key material or content bytes.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum FileError {
    /// Neither the network nor a verified cache copy could supply a unit.
    #[error(
        "unit {unit_id} could not be fetched from the network ({detail}) and no verified \
         local copy exists"
    )]
    Unfetchable {
        /// The unit that could not be obtained.
        unit_id: u64,
        /// The storage-layer failure class, as text (never bytes).
        detail: String,
    },

    /// The bytes served for a unit are not the bytes its address names
    /// (S4's BLAKE3-256 recompute, D32).
    #[error("unit {unit_id}: the bytes served do not hash to the address the manifest records")]
    AddressMismatch {
        /// The affected unit.
        unit_id: u64,
    },

    /// AEAD open or padding strip failed on an authenticated fetch.
    #[error("unit {unit_id} did not decrypt under the vault's keys: {detail}")]
    UnitDecrypt {
        /// The affected unit.
        unit_id: u64,
        /// The crypto failure class, as text.
        detail: String,
    },

    /// The file's bytes did not open its manifest commitment — the
    /// distinct verification failure S14 Accept row 2 names.
    #[error("{subject} of this file do not match the commitment the manifest records")]
    CommitmentMismatch {
        /// Which commitment: `canonical bytes`, `raw bytes`, or
        /// `raw-mirror bytes`.
        subject: &'static str,
    },

    /// The unit table cannot be assembled into a file (ranges that do not
    /// tile `[0, size)`, or a length that disagrees with the file entry).
    #[error("the manifest unit table for this file is not a contiguous tiling: {detail}")]
    BrokenTiling {
        /// What disagreed.
        detail: String,
    },

    /// A vault record for this file cannot drive a safe restore.
    #[error("{detail}")]
    MalformedRecord {
        /// What is wrong (never record bytes).
        detail: String,
    },
}

impl FileError {
    /// This failure's D48 severity class.
    #[must_use]
    pub const fn kind(&self) -> FailureKind {
        match self {
            Self::Unfetchable { .. } => FailureKind::Fetch,
            Self::MalformedRecord { .. } => FailureKind::MalformedRecord,
            Self::AddressMismatch { .. }
            | Self::UnitDecrypt { .. }
            | Self::CommitmentMismatch { .. }
            | Self::BrokenTiling { .. } => FailureKind::Verification,
        }
    }
}

/// Whole-run restore failures — the ones that mean there is no report to
/// render at all.
#[derive(Debug, Error)]
pub enum RestoreError {
    /// No work with this id exists in the vault.
    #[error("no work with this id exists in the vault")]
    WorkNotFound,

    /// The work-id argument is not 64 hex characters (D29's printed form).
    #[error("`{given}` is not a work id (expected 64 hexadecimal characters)")]
    NotAWorkId {
        /// What the user typed, echoed back for correction.
        given: String,
    },

    /// The work exists but is not in a state whose bytes are on the
    /// network.
    #[error(
        "this work is `{state}`, not complete: its content was never fully uploaded, so there \
         is nothing to restore (finish it with `antseal seal` to resume, or seal the sources \
         afresh)"
    )]
    NotRestorable {
        /// The coarse work state, as a stable identifier.
        state: &'static str,
    },

    /// Neither a vault copy nor a locatable network copy of the manifest
    /// exists — restore cannot proceed without the unit table.
    #[error(
        "this work's manifest is not available: the vault holds neither the plaintext copy nor \
         the address of the encrypted manifest, and a manifest cannot be located on the \
         network without it"
    )]
    ManifestUnavailable,

    /// The manifest blob could not be fetched.
    #[error("the encrypted manifest could not be fetched: {detail}")]
    ManifestUnfetchable {
        /// The storage failure class, as text.
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

    /// The manifest does not belong to this work.
    #[error(
        "the manifest recovered for this work does not match its recorded identity ({detail}): \
         refusing to restore content that may belong to another seal"
    )]
    ManifestIdentityMismatch {
        /// Which field disagreed.
        detail: &'static str,
    },

    /// A vault record cannot drive a safe restore (D48's
    /// malformed-restore-record class).
    #[error("{detail}")]
    MalformedRecord {
        /// What is wrong (never record bytes).
        detail: String,
    },

    /// The record store failed (I/O, cipher, vault state).
    #[error(transparent)]
    Store(#[from] Box<StoreError>),
}

impl From<StoreError> for RestoreError {
    fn from(err: StoreError) -> Self {
        match err {
            StoreError::WorkNotFound => RestoreError::WorkNotFound,
            other => RestoreError::Store(Box::new(other)),
        }
    }
}

impl From<RestoreError> for CliError {
    fn from(err: RestoreError) -> Self {
        match err {
            RestoreError::WorkNotFound => CliError::Usage {
                message: "no work with this id exists in the vault (see `antseal list`)".to_owned(),
            },
            RestoreError::NotAWorkId { .. } | RestoreError::NotRestorable { .. } => {
                CliError::Usage {
                    message: err.to_string(),
                }
            }
            RestoreError::ManifestUnavailable
            | RestoreError::ManifestMalformed { .. }
            | RestoreError::ManifestIdentityMismatch { .. }
            | RestoreError::MalformedRecord { .. } => CliError::MalformedRestoreRecord {
                detail: err.to_string(),
            },
            RestoreError::ManifestUnfetchable { detail } => CliError::NetworkFailure { detail },
            RestoreError::ManifestDecrypt => CliError::RestoreVerificationFailed {
                failed_files: 1,
                detail: "the encrypted manifest did not decrypt under this vault's manifest key"
                    .to_owned(),
            },
            RestoreError::Store(inner) => (*inner).into(),
        }
    }
}

/// The restore engine over a storage backend and an unlocked vault's
/// record store.
///
/// # Why the record store and not the [`SealJournal`] interface
///
/// Restore needs two things the journal interface deliberately never
/// exposes: `W` (the journal is written so that no secret crosses it —
/// [`RecordedIdentity`] carries none) and the recorded original paths.
/// Both live in U9's meta record, which is also the one record a
/// `vault import` always carries, so reading the store directly is what
/// makes "restore from a vault backup alone" expressible at all.
///
/// [`SealJournal`]: super::journal::SealJournal
/// [`RecordedIdentity`]: super::journal::RecordedIdentity
pub struct RestoreEngine<'i, 'v, B> {
    backend: &'i B,
    store: &'i WorkStore<'v>,
}

/// Resolve a printed work id (64 lowercase hex, D29/D48 §1) to the vault's
/// store key.
///
/// Exact match only: a prefix match would be a second, silently ambiguous
/// naming scheme over the one artifact users copy and paste.
///
/// Free-standing rather than a method because it needs no backend, and
/// every command that names a work must resolve it the same way — `status`
/// (U23) reaches no network at all and cannot build a [`RestoreEngine`] to
/// borrow the rule from. One resolver, two callers.
///
/// # Errors
///
/// [`RestoreError::NotAWorkId`] for anything that is not 64 hex characters;
/// [`RestoreError::WorkNotFound`] when no work carries it.
pub fn resolve_work_id(store: &WorkStore<'_>, work_id: &str) -> Result<SealId, RestoreError> {
    let wanted = parse_hex32(work_id).ok_or_else(|| RestoreError::NotAWorkId {
        given: work_id.to_owned(),
    })?;
    for seal_id in store.list_works()? {
        let record = store.load_meta(&seal_id)?;
        if record.work_id == Some(wanted) {
            return Ok(seal_id);
        }
    }
    Err(RestoreError::WorkNotFound)
}

impl<'i, 'v, B: StorageBackend> RestoreEngine<'i, 'v, B> {
    /// Assemble the engine over a backend and an unlocked vault's store.
    pub fn new(backend: &'i B, store: &'i WorkStore<'v>) -> Self {
        Self { backend, store }
    }

    /// Resolve a printed work id — [`resolve_work_id`], as a method on the
    /// engine that already holds the store.
    ///
    /// # Errors
    ///
    /// As [`resolve_work_id`].
    pub fn resolve_work_id(&self, work_id: &str) -> Result<SealId, RestoreError> {
        resolve_work_id(self.store, work_id)
    }

    /// Restore one work: fetch, decrypt, verify, and hand back the exact
    /// original bytes of every file.
    ///
    /// Per-file failures are **rows in the report**, not early returns —
    /// D48 §3's convergent re-run needs a run to get as far as it can. The
    /// `Err` cases are the ones where no per-file work is possible at all.
    ///
    /// # Errors
    ///
    /// [`RestoreError::WorkNotFound`], [`RestoreError::NotRestorable`],
    /// the manifest-resolution classes, and store-level failures.
    pub async fn restore(&self, seal_id: &SealId) -> Result<RestoreReport, RestoreError> {
        let record = self.store.load_meta(seal_id)?;
        if record.state != WorkState::Complete {
            return Err(RestoreError::NotRestorable {
                state: work_state_name(record.state),
            });
        }
        let w = record.w.secret_ref();

        let (manifest_bytes, manifest_source) = self.resolve_manifest(seal_id, w).await?;
        let manifest =
            Manifest::decode(&manifest_bytes).map_err(|err| RestoreError::ManifestMalformed {
                detail: err.to_string(),
            })?;
        let body = manifest.body();
        let work_id = manifest_work_id(manifest.body_bytes()).into_bytes();

        // Identity binding: the manifest we just recovered must be *this*
        // work's. On the network path the k_m AEAD already proves the
        // vault authored it; this additionally proves it is not another
        // seal of the same vault.
        if body.seal_id() != seal_id {
            return Err(RestoreError::ManifestIdentityMismatch { detail: "seal_id" });
        }
        if let Some(recorded) = record.work_id
            && recorded != work_id
        {
            return Err(RestoreError::ManifestIdentityMismatch { detail: "work_id" });
        }

        let paths = &record.input_paths_as_given;
        if paths.len() != body.files().len() {
            return Err(RestoreError::MalformedRecord {
                detail: format!(
                    "the vault records {} original path(s) for a work whose manifest has {} \
                     file(s)",
                    paths.len(),
                    body.files().len()
                ),
            });
        }

        let mut files = Vec::with_capacity(body.files().len());
        for (index, entry) in body.files().iter().enumerate() {
            let file_id = index as u64;
            let recorded_path = paths[index].clone();
            files.push(match self.restore_file(seal_id, w, file_id, entry).await {
                Ok(mut file) => {
                    file.recorded_path = recorded_path;
                    FileOutcome::Verified(file)
                }
                Err(error) => FileOutcome::Failed(FailedFile {
                    file_id,
                    recorded_path,
                    error,
                }),
            });
        }

        Ok(RestoreReport {
            seal_id: *seal_id,
            work_id,
            network: record.network.clone(),
            unanchored: record.unanchored,
            manifest_source,
            files,
        })
    }

    /// S14's manifest resolution: the vault's plaintext copy first (free
    /// and authenticated by the vault AEAD), otherwise the network copy by
    /// its journaled address, opened with `k_m`.
    async fn resolve_manifest(
        &self,
        seal_id: &SealId,
        w: MasterSecretRef<'_>,
    ) -> Result<(Vec<u8>, ManifestSource), RestoreError> {
        if let Some(plaintext) = self.store.get_journal_entry(seal_id, PLAN_ENTRY)? {
            let (recorded, plan) =
                decode_plan(plaintext.as_bytes()).map_err(|err| RestoreError::MalformedRecord {
                    detail: format!("the journaled seal plan is unusable: {err}"),
                })?;
            if recorded != *seal_id {
                return Err(RestoreError::MalformedRecord {
                    detail: "the journaled seal plan names a different seal".to_owned(),
                });
            }
            if let Some(bytes) = plan.manifest_bytes {
                return Ok((bytes, ManifestSource::VaultCopy));
            }
        }

        // No vault copy: the encrypted manifest must be fetched, which
        // needs its address and nonce. Both live in the journaled staged
        // record for the manifest blob.
        let Some(staged) = self.staged(seal_id, BlobSlot::EncryptedManifest)? else {
            return Err(RestoreError::ManifestUnavailable);
        };
        let nonce = AeadNonce::from_bytes(staged.nonce);
        let (blob, origin) = match self.fetch(&staged.address, Some(&staged)).await {
            Ok(found) => found,
            Err(FetchFailure::Unavailable { detail }) => {
                return Err(RestoreError::ManifestUnfetchable { detail });
            }
            Err(FetchFailure::AddressMismatch) => {
                return Err(RestoreError::ManifestMalformed {
                    detail: "the bytes served do not hash to the manifest's recorded address"
                        .to_owned(),
                });
            }
        };
        let bytes =
            decrypt_manifest(w, &nonce, &blob).map_err(|_| RestoreError::ManifestDecrypt)?;
        Ok((
            bytes,
            match origin {
                BlobOrigin::Network => ManifestSource::Network,
                BlobOrigin::Cache => ManifestSource::Cache,
            },
        ))
    }

    /// Restore one file: every unit fetched, decrypted and verified before
    /// a single byte is offered as output.
    async fn restore_file(
        &self,
        seal_id: &SealId,
        w: MasterSecretRef<'_>,
        file_id: u64,
        entry: &FileEntry,
    ) -> Result<VerifiedFile, FileError> {
        let file_salt = derive_file_salt(w, FileId(file_id));
        let mut from_network = 0usize;
        let mut from_cache = 0usize;

        // ── The tiling domain: every non-mirror unit, in manifest order ──
        let mut tiled: Vec<u8> = Vec::new();
        let mut mirror_bytes: Option<Vec<u8>> = None;
        for unit in entry.units() {
            let plaintext = self
                .unit_bytes(seal_id, w, unit, &mut from_network, &mut from_cache)
                .await?;
            match unit.kind() {
                WireUnitKind::RawMirror => {
                    if mirror_bytes.is_some() {
                        return Err(FileError::BrokenTiling {
                            detail: "the file has more than one raw mirror".to_owned(),
                        });
                    }
                    mirror_bytes = Some(plaintext);
                }
                WireUnitKind::Normal => {
                    let start = unit.range().start();
                    if start != tiled.len() as u64 {
                        return Err(FileError::BrokenTiling {
                            detail: format!(
                                "unit {} starts at {start} where {} bytes have been assembled",
                                unit.unit_id(),
                                tiled.len()
                            ),
                        });
                    }
                    tiled.extend_from_slice(&plaintext);
                }
            }
        }
        if tiled.len() as u64 != entry.size() {
            return Err(FileError::BrokenTiling {
                detail: format!(
                    "the units assemble to {} bytes; the file entry records {}",
                    tiled.len(),
                    entry.size()
                ),
            });
        }

        // ── Verify the tiling domain against its commitment ──
        //
        // A file is text exactly when it has a canonical rendition
        // (MVP-SPEC.md line 83), and then the tiled bytes ARE the
        // canonical rendition.
        let source = match entry.canon() {
            CanonMode::Text { .. } => {
                let expected = entry
                    .canon()
                    .canon_commit()
                    .ok_or(FileError::MalformedRecord {
                        detail: "a text file entry with no canonical commitment".to_owned(),
                    })?;
                verify_canon_commit(&file_salt, &tiled, expected).map_err(|_| {
                    FileError::CommitmentMismatch {
                        subject: "the canonical bytes",
                    }
                })?;
                ByteSource::Canonical
            }
            CanonMode::Binary => {
                verify_raw_commit(&file_salt, &tiled, entry.raw_commit()).map_err(|_| {
                    FileError::CommitmentMismatch {
                        subject: "the raw bytes",
                    }
                })?;
                ByteSource::Raw
            }
        };

        // ── Prefer the mirror: exact original bytes (spec line 92) ──
        let (bytes, source) = match mirror_bytes {
            Some(mirror) => {
                verify_raw_commit(&file_salt, &mirror, entry.raw_commit()).map_err(|_| {
                    FileError::CommitmentMismatch {
                        subject: "the raw-mirror bytes",
                    }
                })?;
                (mirror, ByteSource::RawMirror)
            }
            None => {
                // No mirror means the manifest claims raw == the tiling
                // domain (G7's `needs_mirror` is byte inequality), so
                // `raw_commit` must open over the same bytes. Checking it
                // costs one hash and turns a silent claim into a proven
                // one — this is the path that decides a text file's
                // original bytes when no mirror exists.
                verify_raw_commit(&file_salt, &tiled, entry.raw_commit()).map_err(|_| {
                    FileError::CommitmentMismatch {
                        subject: "the raw bytes (no raw mirror exists, so they must equal the \
                                  tiled bytes)",
                    }
                })?;
                (tiled, source)
            }
        };

        Ok(VerifiedFile {
            file_id,
            // Filled in by the caller, which owns the recorded path list.
            recorded_path: String::new(),
            bytes,
            source,
            from_network,
            from_cache,
        })
    }

    /// One unit's plaintext: fetch (network-first, verified-cache
    /// fallback), address-recompute, AEAD-open, padding-strip.
    async fn unit_bytes(
        &self,
        seal_id: &SealId,
        w: MasterSecretRef<'_>,
        unit: &UnitEntry,
        from_network: &mut usize,
        from_cache: &mut usize,
    ) -> Result<Vec<u8>, FileError> {
        let unit_id = unit.unit_id();
        let cached = self
            .staged(seal_id, BlobSlot::Unit { unit_id })
            .map_err(|err| FileError::MalformedRecord {
                detail: format!("the local copy of unit {unit_id} is unusable: {err}"),
            })?;
        let (ciphertext, origin) =
            self.fetch(unit.address(), cached.as_ref())
                .await
                .map_err(|failure| match failure {
                    FetchFailure::Unavailable { detail } => {
                        FileError::Unfetchable { unit_id, detail }
                    }
                    FetchFailure::AddressMismatch => FileError::AddressMismatch { unit_id },
                })?;
        match origin {
            BlobOrigin::Network => *from_network += 1,
            BlobOrigin::Cache => *from_cache += 1,
        }

        let true_length =
            usize::try_from(unit.true_length()).map_err(|_| FileError::MalformedRecord {
                detail: format!("unit {unit_id} records a length this platform cannot address"),
            })?;
        let nonce = AeadNonce::from_bytes(*unit.nonce().as_bytes());
        decrypt_unit(
            w,
            seal_id,
            UnitId(unit_id),
            &nonce,
            &ciphertext,
            true_length,
        )
        .map_err(|err| FileError::UnitDecrypt {
            unit_id,
            detail: crypto_detail(&err),
        })
    }

    /// D43 §5: `get_data` first; on failure, the verified cache copy.
    ///
    /// Both paths end at the same S4 address recompute, so no byte reaches
    /// the AEAD without having hashed to the address the manifest names.
    async fn fetch(
        &self,
        address: &ContentAddress,
        cached: Option<&StagedBlob>,
    ) -> Result<(Vec<u8>, BlobOrigin), FetchFailure> {
        let wanted = Address::from(*address);
        // Why the network failure is held as the typed value rather than
        // as text: the cache is tried in between, and re-deciding the
        // class afterwards by inspecting a message would make the two
        // distinct outcomes (nothing arrived / the wrong thing arrived)
        // depend on a string.
        let network_failure = match self.backend.get_data(wanted).await {
            Ok(bytes) => {
                if address_matches(&bytes, address) {
                    return Ok((bytes, BlobOrigin::Network));
                }
                tracing::warn!(
                    address = %wanted,
                    "the network served bytes that do not hash to the requested address"
                );
                FetchFailure::AddressMismatch
            }
            Err(err) => {
                let detail = storage_detail(&err);
                tracing::debug!(address = %wanted, error = %detail, "fetch failed");
                FetchFailure::Unavailable { detail }
            }
        };

        // The D43 fallback: the cache is only ever used after its own
        // address recompute proves it is the blob the manifest names.
        if let Some(blob) = cached {
            if blob.address.as_bytes() == address.as_bytes()
                && address_matches(&blob.ciphertext, address)
            {
                tracing::warn!(
                    address = %wanted,
                    "serving a verified local cache copy after a failed fetch (D43)"
                );
                return Ok((blob.ciphertext.clone(), BlobOrigin::Cache));
            }
            tracing::warn!(
                address = %wanted,
                "the local cache copy failed its integrity recheck and was not used (D43)"
            );
        }

        Err(network_failure)
    }

    /// The D43 cache copy of one blob, or `None` when the vault holds
    /// none. A malformed cache record is *not* an error here: the cache is
    /// refetchable by definition, so it degrades to absent.
    fn staged(&self, seal_id: &SealId, slot: BlobSlot) -> Result<Option<StagedBlob>, RestoreError> {
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
}

/// Why a fetch produced nothing usable.
enum FetchFailure {
    /// No copy could be obtained (network failure/not-found, no cache).
    Unavailable { detail: String },
    /// Bytes arrived but do not hash to the address they were asked for.
    AddressMismatch,
}

/// Does `bytes` hash to `expected` (S4's BLAKE3-256 recompute, D32)?
/// Shared with the reveal engine (`pub(super)`) — one recompute rule for
/// every byte either engine accepts.
pub(super) fn address_matches(bytes: &[u8], expected: &ContentAddress) -> bool {
    compute_storage_address(bytes).is_ok_and(|actual| actual.as_bytes() == expected.as_bytes())
}

/// A storage failure's class as short text — never bytes, never a key.
/// Shared with the reveal engine (`pub(super)`), same reason as
/// [`address_matches`].
pub(super) fn storage_detail(err: &StorageError) -> String {
    match err {
        StorageError::NotFound { .. } => "the network has no data at this address".to_owned(),
        other => other.to_string(),
    }
}

/// A crypto failure's class as short text (C4's taxonomy is already
/// content-free).
fn crypto_detail(err: &CryptoError) -> String {
    err.to_string()
}

/// The coarse work state as a stable identifier for messages.
const fn work_state_name(state: WorkState) -> &'static str {
    match state {
        WorkState::IncompletePrePay => "incomplete (nothing paid)",
        WorkState::IncompletePostPay => "incomplete (paid, not finalized)",
        WorkState::Complete => "complete",
        WorkState::Abandoned => "abandoned",
    }
}

/// Parse exactly 64 hex characters into 32 bytes (D29's printed form;
/// upper case accepted, since users paste what they are given).
fn parse_hex32(text: &str) -> Option<[u8; 32]> {
    let bytes = text.as_bytes();
    if bytes.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (index, pair) in bytes.chunks_exact(2).enumerate() {
        out[index] = (hex_val(pair[0])? << 4) | hex_val(pair[1])?;
    }
    Some(out)
}

const fn hex_val(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// 32 bytes as 64 lowercase hex characters (D29's printed form).
#[must_use]
pub fn hex32(bytes: &[u8; 32]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(64);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn work_ids_round_trip_through_their_printed_form() {
        let bytes: [u8; 32] = core::array::from_fn(|i| (i * 7 + 1) as u8);
        let printed = hex32(&bytes);
        assert_eq!(printed.len(), 64);
        assert_eq!(parse_hex32(&printed), Some(bytes));
        assert_eq!(parse_hex32(&printed.to_uppercase()), Some(bytes));
    }

    #[test]
    fn non_work_ids_are_rejected_rather_than_guessed() {
        assert_eq!(parse_hex32(""), None);
        assert_eq!(parse_hex32("abc"), None);
        assert_eq!(parse_hex32(&"g".repeat(64)), None);
        assert_eq!(parse_hex32(&"0".repeat(63)), None);
        assert_eq!(parse_hex32(&"0".repeat(65)), None);
    }

    #[test]
    fn failure_kinds_order_by_d48_severity() {
        assert!(FailureKind::Verification > FailureKind::Fetch);
        assert_eq!(FailureKind::Verification.status(), "verification-failed");
        assert_eq!(FailureKind::Fetch.status(), "fetch-failed");
    }

    #[test]
    fn every_file_error_carries_its_d48_class() {
        assert_eq!(
            FileError::Unfetchable {
                unit_id: 1,
                detail: "x".to_owned()
            }
            .kind(),
            FailureKind::Fetch
        );
        assert_eq!(
            FileError::AddressMismatch { unit_id: 1 }.kind(),
            FailureKind::Verification
        );
        assert_eq!(
            FileError::CommitmentMismatch { subject: "x" }.kind(),
            FailureKind::Verification
        );
        assert_eq!(
            FileError::MalformedRecord {
                detail: "x".to_owned()
            }
            .kind(),
            FailureKind::MalformedRecord
        );
    }
}
