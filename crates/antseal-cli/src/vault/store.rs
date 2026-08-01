//! The per-work record store (U9): where every work's records live and
//! how durably — `W`, the seal journal area, the payment receipt, anchor
//! artifacts, paths, costs, state, the D45 invocation identity, and the
//! D36 consent record, all AEAD-encrypted under the vault key with the
//! D42 header + identity AAD.
//!
//! **Division of labor (U9 Notes):** S owns *when and what* to journal —
//! journal-entry and receipt contents are opaque bytes here, their shapes
//! S10's/S7's — while this module owns *where and how durably*: one file
//! per record, every write atomic + fsync'd ([`crate::vault::fs`]), every
//! byte under `store/` ciphertext.
//!
//! # On-disk shape (under [`VaultLayout::works_dir`])
//!
//! ```text
//! store/works/<seal-id-hex>/          one directory per work; the name is
//!     │                              the 16-byte seal_id in lowercase hex
//!     │                              (random at seal start — content-free)
//!     ├── meta                       the WorkRecord: W + everything small
//!     ├── journal/<entry>            staged ciphertext + nonce + address
//!     │                              (opaque; entry key = canonical
//!     │                              decimal u64, chosen by S10)
//!     ├── receipt                    the journaled PaymentReceipt bytes
//!     └── anchors/<slot>             `.ots`/TSA artifacts (slots named by
//!                                    A; exercised from M2)
//! ```
//!
//! # Enumeration without decrypting bodies (U9 Accept)
//!
//! [`WorkStore::list_works`] is a readdir — zero decryption. Per-work
//! display needs exactly one small `meta` decrypt; journal bodies (the
//! content-scale bytes, D43) are **never** touched by list/status-class
//! reads. No plaintext index exists: D42 puts record indexes inside the
//! AEAD, and the directory listing — random hex names — is index enough.
//!
//! # The D43 journal → cache reclassification
//!
//! The staged bytes' class is **derived from the meta state tag**, so the
//! reclassification at `finalize` success is exactly what D43 mandates: a
//! state-tag write ([`WorkStore::mark_complete`]), same bytes, no move,
//! no copy. `state ≠ complete` ⇒ journal contract (resume-critical,
//! never prunable, always exported); `state = complete` ⇒ cache contract
//! (integrity-rechecked on use, refetchable, excluded from D47's export —
//! the export itself is U12's, reading this same tag).
//!
//! # Receipt durability (U9 Accept; feeds S's no-double-pay E2E)
//!
//! [`WorkStore::put_receipt`] is a single [`atomic_write`] — temp +
//! fsync + rename + parent-dir fsync — so the instant it returns, a
//! `SIGKILL` leaves the receipt readable on reopen: "journaled the
//! instant the tx lands" is a filesystem fact, not a hope.
//!
//! # Splice resistance (D42 rider — the test U5 deferred)
//!
//! Every record binds `(class, seal_id, entry/slot)` plus the serialized
//! KDF header as AAD ([`crate::vault::cipher`]), so a valid blob moved
//! between works, between entries, between record classes, or between
//! vaults fails authentication instead of being silently accepted. The
//! file-level swap matrix lives in `tests/work_store.rs`.
//!
//! # Concurrency
//!
//! Mutating APIs assume the caller holds the single-writer
//! [`crate::vault::lock::VaultLock`] (U5 discipline — the command layer
//! acquires it before any store mutation). Readers are safe against a
//! concurrent writer because every write is an atomic rename.

use std::io::Read;
use std::path::{Path, PathBuf};

use antseal_core::codec::{CanonicalDecoder, encode_item};
use antseal_core::crypto::secrets::{MasterSecret, SealId, SecretBuf};
use rand_core::TryCryptoRng;
use thiserror::Error;
use zeroize::Zeroize;

use super::cipher::RecordIdentity;
use super::fs::atomic_write;
use super::session::UnlockedVault;
use crate::error::CliError;

/// Version of the work-record (meta) schema. Bumping it is a vault-format
/// event: new body schema, migration story, and tests land together.
pub const WORK_RECORD_VERSION: u32 = 1;

/// Defensive read cap for any single record file. Our records are
/// authenticated AEAD blobs, but the *files* are substitutable by a local
/// writer, so no read is unbounded (D10 discipline). Sized generously
/// above the largest legitimate record: a journal entry carries one
/// staged unit ciphertext, and a blob is one chunk (D32) — single-digit
/// MiB — while receipts carry per-blob proof bytes at KB scale.
pub const MAX_RECORD_FILE_BYTES: usize = 64 * 1024 * 1024;

/// Cap on anchor-slot name length (filesystem hygiene).
pub const MAX_ANCHOR_SLOT_LEN: usize = 64;

/// Completion state of a work — the tag the D43 journal/cache split and
/// D45's resume candidate set both key on. Transitions are S10's state
/// machine; this store records them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum WorkState {
    /// Sealing started, nothing paid (D45: resumable; D36: consent
    /// re-fires on resume).
    IncompletePrePay = 1,
    /// Receipt journaled, finalize not yet complete (resume is
    /// finalize-only, no consent — D45 §4).
    IncompletePostPay = 2,
    /// `finalize_batch` succeeded — the D43 reclassification: staged
    /// bytes are cache from here on.
    Complete = 3,
    /// Abandoned (S11's safety outcome; never a resume candidate).
    Abandoned = 4,
}

impl WorkState {
    fn from_wire(v: u64) -> Option<Self> {
        match v {
            1 => Some(WorkState::IncompletePrePay),
            2 => Some(WorkState::IncompletePostPay),
            3 => Some(WorkState::Complete),
            4 => Some(WorkState::Abandoned),
            _ => None,
        }
    }
}

/// How the D36 consent was given.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum ConsentChannel {
    /// An interactive prompt was answered affirmatively.
    Interactive = 0,
    /// `--yes` consented in advance (scripts).
    YesFlag = 1,
}

impl ConsentChannel {
    fn from_wire(v: u64) -> Option<Self> {
        match v {
            0 => Some(ConsentChannel::Interactive),
            1 => Some(ConsentChannel::YesFlag),
            _ => None,
        }
    }
}

/// The D36 consent record, journaled at every affirmative consent (the
/// latest one; D36 rule 4 reads it for the prior-totals display, never
/// for gating).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConsentRecord {
    /// Total consented storage cost, atto-ANT (exact).
    pub total_ant_atto: u128,
    /// The gas estimate shown beside it, wei (as rendered — an estimate,
    /// never a bound; D36 residual 3).
    pub gas_estimate_wei: u128,
    /// When consent was given (Unix seconds).
    pub consent_time_unix_secs: u64,
    /// Which channel affirmed.
    pub channel: ConsentChannel,
}

/// The D45 seal-shaping flag set — the flags that are part of the
/// invocation identity (session flags — `--yes`, `--json`, `--dry-run`,
/// `--passphrase-fd` — are deliberately NOT here).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SealShapingFlags {
    /// `--title` (also embedded in the manifest by F; recorded here as
    /// identity).
    pub title: Option<String>,
    /// `--split blank-lines` (the only v1 split mode, hence a bool; a
    /// second mode is a schema event).
    pub split_blank_lines: bool,
    /// `--force-text`.
    pub force_text: bool,
    /// `--no-fine-tree <glob>` values, in the order given.
    pub no_fine_tree: Vec<String>,
    /// `--no-anchor` (dev-only flag; identity nonetheless).
    pub no_anchor: bool,
    /// `--force-degraded`.
    pub force_degraded: bool,
}

/// One work's meta record — everything except the opaque journal /
/// receipt / anchor bytes.
///
/// Carries `W` as C's zeroizing [`MasterSecret`], so this type is
/// deliberately **not `Clone`** and its `Debug` redacts the secret.
#[derive(Debug)]
pub struct WorkRecord {
    /// The 32-byte per-work master secret (spec line 89) — the reason the
    /// vault exists.
    pub w: MasterSecret,
    /// The work's public seal id; also the store key (directory name).
    pub seal_id: SealId,
    /// Effective network (D45 identity component). Canonical CLI
    /// spelling, e.g. `"devnet"`, `"arbitrum-one"`, `"arbitrum-sepolia"`.
    pub network: String,
    /// Completion state (S10's machine; D43/D45 key on it).
    pub state: WorkState,
    /// Loudly-recorded degraded anchor set (`--force-degraded` path).
    pub degraded: bool,
    /// Sealed without anchors (dev-only `--no-anchor` path).
    pub unanchored: bool,
    /// Input paths exactly as given, in argument order (= `file_id`
    /// order; D45 §1 stores both spellings).
    pub input_paths_as_given: Vec<String>,
    /// The same paths lexically absolutized (cwd-joined, `.`/`//`
    /// cleaned, NO symlink or existence resolution) — the D45 resume
    /// match key.
    pub input_paths_absolute: Vec<String>,
    /// The seal-shaping flag set (D45 identity component).
    pub shaping: SealShapingFlags,
    /// `work_id = SHA-256(manifest body)` — absent until the manifest is
    /// built.
    pub work_id: Option<[u8; 32]>,
    /// Total storage cost paid, atto-ANT — absent until known (U13
    /// persists it at finalize).
    pub cost_atto: Option<u128>,
    /// The D36 consent record — absent until the first affirmative
    /// consent.
    pub consent: Option<ConsentRecord>,
}

/// Everything that can go wrong in the record store. Total over
/// adversarial bytes — no panic path.
#[derive(Debug, Error)]
pub enum StoreError {
    /// No work with this seal id exists in the vault.
    #[error("no work record for this id exists in the vault")]
    WorkNotFound,

    /// `create_work` over an existing record (the pipeline draws a fresh
    /// random seal_id, so this is a bug class, not a user state).
    #[error("a work record with this seal id already exists")]
    AlreadyExists,

    /// A record file failed authentication or has an impossible shape —
    /// tamper, splice, or corruption (one class, deliberately).
    #[error("work record failed authentication or is corrupt: {detail}")]
    Corrupt { detail: &'static str },

    /// A meta record written by a newer antseal.
    #[error("work record format v{found} is newer than this build supports")]
    NewerRecord { found: u64 },

    /// A path that is not valid UTF-8 cannot be recorded in the v1 vault
    /// schema (recorded limitation; surfaced as D46's invalid-argument
    /// class before anything is journaled).
    #[error("an input path is not valid UTF-8, which the v1 vault record cannot store")]
    NonUtf8Path,

    /// Anchor slot names are `[a-z0-9][a-z0-9._-]*`, ≤ 64 bytes (caller
    /// bug — slot names come from A's code, not from users).
    #[error("invalid anchor slot name")]
    InvalidSlotName,

    /// A file under `store/works/` that is neither a work directory nor
    /// an inert atomic-write temp file.
    #[error("alien entry in the work store: {detail}")]
    AlienEntry { detail: String },

    /// Ordinary filesystem I/O failure.
    #[error("work store I/O failure at {}: {source}", path.display())]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// AEAD/RNG failure surfaced by the cipher layer.
    #[error(transparent)]
    Cli(#[from] Box<CliError>),
}

impl From<StoreError> for CliError {
    fn from(err: StoreError) -> Self {
        match err {
            StoreError::WorkNotFound => CliError::Usage {
                message: "no work with this id exists in the vault (see `antseal list`)".to_owned(),
            },
            StoreError::AlreadyExists | StoreError::InvalidSlotName => CliError::Internal {
                detail: err.to_string(),
            },
            StoreError::Corrupt { .. } | StoreError::AlienEntry { .. } => {
                CliError::VaultAuthFailure
            }
            StoreError::NewerRecord { found } => CliError::VaultNewerVersion {
                found,
                supported: WORK_RECORD_VERSION,
            },
            StoreError::NonUtf8Path => CliError::InvalidSealArgument {
                problems: vec![
                    "an input path is not valid UTF-8 (unsupported in v1 vault records)".to_owned(),
                ],
            },
            StoreError::Io { path, source } => CliError::Io {
                context: format!("work store access at {}", path.display()),
                source,
            },
            StoreError::Cli(inner) => *inner,
        }
    }
}

impl From<CliError> for StoreError {
    fn from(err: CliError) -> Self {
        StoreError::Cli(Box::new(err))
    }
}

/// The record store over an unlocked vault.
pub struct WorkStore<'v> {
    vault: &'v UnlockedVault,
}

impl<'v> WorkStore<'v> {
    /// Open the store through an unlocked vault handle. Mutations assume
    /// the caller holds the U5 vault lock (module docs).
    #[must_use]
    pub fn new(vault: &'v UnlockedVault) -> Self {
        WorkStore { vault }
    }

    // ── paths ────────────────────────────────────────────────────────

    fn work_dir(&self, seal_id: &SealId) -> PathBuf {
        self.vault.layout().works_dir().join(hex32(seal_id))
    }

    fn meta_path(&self, seal_id: &SealId) -> PathBuf {
        self.work_dir(seal_id).join("meta")
    }

    fn journal_dir(&self, seal_id: &SealId) -> PathBuf {
        self.work_dir(seal_id).join("journal")
    }

    fn journal_path(&self, seal_id: &SealId, entry: u64) -> PathBuf {
        self.journal_dir(seal_id).join(entry.to_string())
    }

    fn receipt_path(&self, seal_id: &SealId) -> PathBuf {
        self.work_dir(seal_id).join("receipt")
    }

    fn anchors_dir(&self, seal_id: &SealId) -> PathBuf {
        self.work_dir(seal_id).join("anchors")
    }

    // ── work lifecycle ───────────────────────────────────────────────

    /// Create a fresh work record (the seal pipeline's first durable
    /// write, before any unit is journaled).
    ///
    /// # Errors
    ///
    /// [`StoreError::AlreadyExists`] when the slot is taken (bug class:
    /// seal ids are drawn fresh); I/O and cipher errors.
    pub fn create_work<R: TryCryptoRng + ?Sized>(
        &self,
        record: &WorkRecord,
        rng: &mut R,
    ) -> Result<(), StoreError> {
        let meta = self.meta_path(&record.seal_id);
        if meta.exists() {
            return Err(StoreError::AlreadyExists);
        }
        let dir = self.work_dir(&record.seal_id);
        std::fs::create_dir_all(&dir).map_err(|source| StoreError::Io {
            path: dir.clone(),
            source,
        })?;
        self.write_meta(record, rng)
    }

    /// Overwrite an existing work's meta record (state transitions, the
    /// work_id/cost/consent field updates).
    ///
    /// # Errors
    ///
    /// [`StoreError::WorkNotFound`] when the work was never created.
    pub fn store_meta<R: TryCryptoRng + ?Sized>(
        &self,
        record: &WorkRecord,
        rng: &mut R,
    ) -> Result<(), StoreError> {
        if !self.meta_path(&record.seal_id).exists() {
            return Err(StoreError::WorkNotFound);
        }
        self.write_meta(record, rng)
    }

    fn write_meta<R: TryCryptoRng + ?Sized>(
        &self,
        record: &WorkRecord,
        rng: &mut R,
    ) -> Result<(), StoreError> {
        let mut plaintext = record.encode()?;
        let sealed = self
            .vault
            .seal_record(
                RecordIdentity::WorkMeta {
                    seal_id: &record.seal_id,
                },
                &plaintext,
                rng,
            )
            .map_err(StoreError::from);
        // The plaintext holds W verbatim: wipe it before propagating
        // either outcome.
        plaintext.zeroize();
        let sealed = sealed?;
        let path = self.meta_path(&record.seal_id);
        atomic_write(&path, &sealed).map_err(|source| StoreError::Io { path, source })
    }

    /// Load one work's meta record (the small decrypt behind every
    /// list/show/status row).
    ///
    /// # Errors
    ///
    /// [`StoreError::WorkNotFound`] / [`StoreError::Corrupt`] /
    /// [`StoreError::NewerRecord`] per their docs.
    pub fn load_meta(&self, seal_id: &SealId) -> Result<WorkRecord, StoreError> {
        let path = self.meta_path(seal_id);
        let blob = read_record_file(&path)?.ok_or(StoreError::WorkNotFound)?;
        let plaintext = self
            .vault
            .open_record(RecordIdentity::WorkMeta { seal_id }, &blob)
            .map_err(StoreError::from)?;
        let record = WorkRecord::decode(plaintext.as_bytes())?;
        // Defense in depth: the AAD already binds the store key; the
        // authenticated body must agree with it.
        if record.seal_id != *seal_id {
            return Err(StoreError::Corrupt {
                detail: "meta body seal_id disagrees with its authenticated slot",
            });
        }
        Ok(record)
    }

    /// Set the completion state (read-modify-write of meta).
    ///
    /// # Errors
    ///
    /// Propagates [`Self::load_meta`]/[`Self::store_meta`] errors.
    pub fn set_state<R: TryCryptoRng + ?Sized>(
        &self,
        seal_id: &SealId,
        state: WorkState,
        rng: &mut R,
    ) -> Result<(), StoreError> {
        let mut record = self.load_meta(seal_id)?;
        record.state = state;
        self.store_meta(&record, rng)
    }

    /// The D43 reclassification write: `finalize_batch` succeeded, the
    /// staged bytes become cache — a state tag, same bytes, no move.
    ///
    /// # Errors
    ///
    /// Propagates [`Self::set_state`] errors.
    pub fn mark_complete<R: TryCryptoRng + ?Sized>(
        &self,
        seal_id: &SealId,
        rng: &mut R,
    ) -> Result<(), StoreError> {
        self.set_state(seal_id, WorkState::Complete, rng)
    }

    /// Every work in the vault — a readdir, zero decryption (module
    /// docs). Order: ascending by seal-id bytes (deterministic).
    ///
    /// # Errors
    ///
    /// [`StoreError::AlienEntry`] for non-work, non-temp entries (a
    /// corrupted or hand-edited store is loud, never skipped silently).
    pub fn list_works(&self) -> Result<Vec<SealId>, StoreError> {
        let dir = self.vault.layout().works_dir();
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            // A vault with no work yet may predate the directory.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(source) => return Err(StoreError::Io { path: dir, source }),
        };
        let mut ids = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|source| StoreError::Io {
                path: dir.clone(),
                source,
            })?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            // Inert atomic-write residue is expected and skipped (fs.rs).
            if name.starts_with('.') {
                continue;
            }
            match parse_hex32(&name) {
                Some(id) => ids.push(id),
                None => {
                    return Err(StoreError::AlienEntry {
                        detail: format!("unexpected entry {name:?} in the work store"),
                    });
                }
            }
        }
        ids.sort_unstable_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
        Ok(ids)
    }

    // ── journal area (content contract: S10) ─────────────────────────

    /// Durably persist one journal entry (staged ciphertext + nonce +
    /// address — opaque S10 bytes), atomically.
    ///
    /// # Errors
    ///
    /// [`StoreError::WorkNotFound`] when the work was never created; I/O
    /// and cipher errors.
    pub fn put_journal_entry<R: TryCryptoRng + ?Sized>(
        &self,
        seal_id: &SealId,
        entry: u64,
        bytes: &[u8],
        rng: &mut R,
    ) -> Result<(), StoreError> {
        self.require_work(seal_id)?;
        let dir = self.journal_dir(seal_id);
        std::fs::create_dir_all(&dir).map_err(|source| StoreError::Io {
            path: dir.clone(),
            source,
        })?;
        let sealed = self
            .vault
            .seal_record(RecordIdentity::JournalEntry { seal_id, entry }, bytes, rng)
            .map_err(StoreError::from)?;
        let path = self.journal_path(seal_id, entry);
        atomic_write(&path, &sealed).map_err(|source| StoreError::Io { path, source })
    }

    /// Read one journal entry; `None` when the entry does not exist.
    ///
    /// # Errors
    ///
    /// [`StoreError::Corrupt`]-class failures via the cipher layer.
    pub fn get_journal_entry(
        &self,
        seal_id: &SealId,
        entry: u64,
    ) -> Result<Option<SecretBuf>, StoreError> {
        let path = self.journal_path(seal_id, entry);
        let Some(blob) = read_record_file(&path)? else {
            return Ok(None);
        };
        let plaintext = self
            .vault
            .open_record(RecordIdentity::JournalEntry { seal_id, entry }, &blob)
            .map_err(StoreError::from)?;
        Ok(Some(plaintext))
    }

    /// Every journal entry key of a work, ascending. Zero decryption.
    ///
    /// # Errors
    ///
    /// [`StoreError::AlienEntry`] for non-canonical names (a `"007"`
    /// beside a `"7"` would be a splice-ambiguity — canonical decimal
    /// only).
    pub fn list_journal_entries(&self, seal_id: &SealId) -> Result<Vec<u64>, StoreError> {
        let dir = self.journal_dir(seal_id);
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(source) => return Err(StoreError::Io { path: dir, source }),
        };
        let mut keys = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|source| StoreError::Io {
                path: dir.clone(),
                source,
            })?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with('.') {
                continue;
            }
            match parse_canonical_u64(&name) {
                Some(key) => keys.push(key),
                None => {
                    return Err(StoreError::AlienEntry {
                        detail: format!("unexpected journal entry name {name:?}"),
                    });
                }
            }
        }
        keys.sort_unstable();
        Ok(keys)
    }

    /// Delete one journal entry (abandonment cleanup, S11). Returns
    /// whether it existed — idempotent by design.
    ///
    /// # Errors
    ///
    /// I/O failures other than absence.
    pub fn delete_journal_entry(&self, seal_id: &SealId, entry: u64) -> Result<bool, StoreError> {
        let path = self.journal_path(seal_id, entry);
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(source) => Err(StoreError::Io { path, source }),
        }
    }

    // ── receipt (content contract: S7/D37) ───────────────────────────

    /// Journal the payment receipt — one atomic, fsync'd write; when this
    /// returns, the receipt survives `SIGKILL` (module docs).
    ///
    /// # Errors
    ///
    /// [`StoreError::WorkNotFound`] when the work was never created; I/O
    /// and cipher errors.
    pub fn put_receipt<R: TryCryptoRng + ?Sized>(
        &self,
        seal_id: &SealId,
        bytes: &[u8],
        rng: &mut R,
    ) -> Result<(), StoreError> {
        self.require_work(seal_id)?;
        let sealed = self
            .vault
            .seal_record(RecordIdentity::Receipt { seal_id }, bytes, rng)
            .map_err(StoreError::from)?;
        let path = self.receipt_path(seal_id);
        atomic_write(&path, &sealed).map_err(|source| StoreError::Io { path, source })
    }

    /// Read the journaled receipt; `None` = not paid yet (a state, not an
    /// error).
    ///
    /// # Errors
    ///
    /// [`StoreError::Corrupt`]-class failures via the cipher layer.
    pub fn get_receipt(&self, seal_id: &SealId) -> Result<Option<SecretBuf>, StoreError> {
        let path = self.receipt_path(seal_id);
        let Some(blob) = read_record_file(&path)? else {
            return Ok(None);
        };
        let plaintext = self
            .vault
            .open_record(RecordIdentity::Receipt { seal_id }, &blob)
            .map_err(StoreError::from)?;
        Ok(Some(plaintext))
    }

    // ── anchor artifact slots (contents: A's shapes; exercised M2) ───

    /// Store one anchor artifact (`.ots` bytes, a TSA token + fetch date
    /// — A's shapes, opaque here) under a named slot.
    ///
    /// # Errors
    ///
    /// [`StoreError::InvalidSlotName`] / [`StoreError::WorkNotFound`];
    /// I/O and cipher errors.
    pub fn put_anchor<R: TryCryptoRng + ?Sized>(
        &self,
        seal_id: &SealId,
        slot: &str,
        bytes: &[u8],
        rng: &mut R,
    ) -> Result<(), StoreError> {
        validate_slot_name(slot)?;
        self.require_work(seal_id)?;
        let dir = self.anchors_dir(seal_id);
        std::fs::create_dir_all(&dir).map_err(|source| StoreError::Io {
            path: dir.clone(),
            source,
        })?;
        let sealed = self
            .vault
            .seal_record(RecordIdentity::Anchor { seal_id, slot }, bytes, rng)
            .map_err(StoreError::from)?;
        let path = dir.join(slot);
        atomic_write(&path, &sealed).map_err(|source| StoreError::Io { path, source })
    }

    /// Read one anchor artifact; `None` when the slot is empty.
    ///
    /// # Errors
    ///
    /// [`StoreError::InvalidSlotName`]; [`StoreError::Corrupt`]-class
    /// failures via the cipher layer.
    pub fn get_anchor(
        &self,
        seal_id: &SealId,
        slot: &str,
    ) -> Result<Option<SecretBuf>, StoreError> {
        validate_slot_name(slot)?;
        let path = self.anchors_dir(seal_id).join(slot);
        let Some(blob) = read_record_file(&path)? else {
            return Ok(None);
        };
        let plaintext = self
            .vault
            .open_record(RecordIdentity::Anchor { seal_id, slot }, &blob)
            .map_err(StoreError::from)?;
        Ok(Some(plaintext))
    }

    /// Every filled anchor slot of a work, ascending by name.
    ///
    /// # Errors
    ///
    /// [`StoreError::AlienEntry`] for names outside the slot grammar.
    pub fn list_anchors(&self, seal_id: &SealId) -> Result<Vec<String>, StoreError> {
        let dir = self.anchors_dir(seal_id);
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(source) => return Err(StoreError::Io { path: dir, source }),
        };
        let mut slots = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|source| StoreError::Io {
                path: dir.clone(),
                source,
            })?;
            let name = entry.file_name();
            let name = name.to_string_lossy().into_owned();
            if name.starts_with('.') {
                continue;
            }
            if validate_slot_name(&name).is_err() {
                return Err(StoreError::AlienEntry {
                    detail: format!("unexpected anchor slot name {name:?}"),
                });
            }
            slots.push(name);
        }
        slots.sort_unstable();
        Ok(slots)
    }

    fn require_work(&self, seal_id: &SealId) -> Result<(), StoreError> {
        if self.meta_path(seal_id).exists() {
            Ok(())
        } else {
            Err(StoreError::WorkNotFound)
        }
    }
}

// ─────────────────────────────────────────────────────────────────────
// Meta record codec (versioned canonical CBOR, D7 manual-impl rule)
// ─────────────────────────────────────────────────────────────────────

impl WorkRecord {
    /// Serialize to the versioned plaintext bytes (the caller encrypts
    /// and then wipes this buffer — it contains `W`).
    ///
    /// # Errors
    ///
    /// Encode failures are unreachable for well-formed records but never
    /// panic (library discipline). [`StoreError::NonUtf8Path`] never
    /// arises here (paths are already `String`), it belongs to the
    /// record-construction layer.
    pub fn encode(&self) -> Result<Vec<u8>, StoreError> {
        let internal = |_| StoreError::Corrupt {
            detail: "work record encode failed on a fixed shape",
        };
        let body = encode_item(|e| {
            e.map(|m| {
                m.entry(0, |e| e.bytes(self.w.secret_ref().as_bytes()))?;
                m.entry(1, |e| e.bytes(self.seal_id.as_bytes()))?;
                m.entry(2, |e| e.bytes(self.network.as_bytes()))?;
                m.entry(3, |e| e.u64(self.state as u64))?;
                m.entry(4, |e| e.u64(u64::from(self.degraded)))?;
                m.entry(5, |e| e.u64(u64::from(self.unanchored)))?;
                m.entry(6, |e| {
                    e.array(|a| {
                        for p in &self.input_paths_as_given {
                            a.item(|e| e.bytes(p.as_bytes()))?;
                        }
                        Ok(())
                    })
                })?;
                m.entry(7, |e| {
                    e.array(|a| {
                        for p in &self.input_paths_absolute {
                            a.item(|e| e.bytes(p.as_bytes()))?;
                        }
                        Ok(())
                    })
                })?;
                m.entry(8, |e| {
                    e.map(|f| {
                        if let Some(title) = &self.shaping.title {
                            f.entry(0, |e| e.bytes(title.as_bytes()))?;
                        }
                        f.entry(1, |e| e.u64(u64::from(self.shaping.split_blank_lines)))?;
                        f.entry(2, |e| e.u64(u64::from(self.shaping.force_text)))?;
                        f.entry(3, |e| {
                            e.array(|a| {
                                for g in &self.shaping.no_fine_tree {
                                    a.item(|e| e.bytes(g.as_bytes()))?;
                                }
                                Ok(())
                            })
                        })?;
                        f.entry(4, |e| e.u64(u64::from(self.shaping.no_anchor)))?;
                        f.entry(5, |e| e.u64(u64::from(self.shaping.force_degraded)))
                    })
                })?;
                if let Some(work_id) = &self.work_id {
                    m.entry(9, |e| e.bytes(work_id))?;
                }
                if let Some(cost) = self.cost_atto {
                    m.entry(10, |e| e.bytes(&cost.to_be_bytes()))?;
                }
                if let Some(consent) = &self.consent {
                    m.entry(11, |e| {
                        e.map(|c| {
                            c.entry(0, |e| e.bytes(&consent.total_ant_atto.to_be_bytes()))?;
                            c.entry(1, |e| e.bytes(&consent.gas_estimate_wei.to_be_bytes()))?;
                            c.entry(2, |e| e.u64(consent.consent_time_unix_secs))?;
                            c.entry(3, |e| e.u64(consent.channel as u64))
                        })
                    })?;
                }
                Ok(())
            })
        })
        .map_err(internal)?;
        encode_item(|e| {
            e.array(|a| {
                a.item(|e| e.u64(u64::from(WORK_RECORD_VERSION)))?;
                a.item(|e| e.bytes(&body))
            })
        })
        .map_err(internal)
    }

    /// Parse versioned meta plaintext defensively.
    ///
    /// # Errors
    ///
    /// [`StoreError::NewerRecord`] for future versions (body unparsed);
    /// [`StoreError::Corrupt`] for every malformed shape.
    pub fn decode(bytes: &[u8]) -> Result<Self, StoreError> {
        let corrupt = |detail: &'static str| StoreError::Corrupt { detail };
        let codec = |_| corrupt("meta record is not canonical CBOR");

        let mut d = CanonicalDecoder::new(bytes);
        if d.array().map_err(codec)? != 2 {
            return Err(corrupt("meta envelope must be [version, body]"));
        }
        let version = d.u64().map_err(codec)?;
        if version == 0 {
            return Err(corrupt("meta version 0 is invalid"));
        }
        if version > u64::from(WORK_RECORD_VERSION) {
            return Err(StoreError::NewerRecord { found: version });
        }
        let body = d.bytes().map_err(codec)?;
        d.finish().map_err(codec)?;

        let mut b = CanonicalDecoder::new(body);
        let mut map = b.map().map_err(codec)?;

        let mut w: Option<[u8; 32]> = None;
        let mut seal_id: Option<SealId> = None;
        let mut network: Option<String> = None;
        let mut state: Option<WorkState> = None;
        let mut degraded: Option<bool> = None;
        let mut unanchored: Option<bool> = None;
        let mut paths_given: Option<Vec<String>> = None;
        let mut paths_abs: Option<Vec<String>> = None;
        let mut shaping: Option<SealShapingFlags> = None;
        let mut work_id: Option<[u8; 32]> = None;
        let mut cost_atto: Option<u128> = None;
        let mut consent: Option<ConsentRecord> = None;

        while let Some(key) = map.next_key(&mut b).map_err(codec)? {
            match key {
                0 => {
                    let raw = b.bytes().map_err(codec)?;
                    w = Some(
                        raw.try_into()
                            .map_err(|_| corrupt("W must be exactly 32 bytes"))?,
                    );
                }
                1 => {
                    let raw = b.bytes().map_err(codec)?;
                    let arr: [u8; 16] = raw
                        .try_into()
                        .map_err(|_| corrupt("seal_id must be exactly 16 bytes"))?;
                    seal_id = Some(SealId::from_bytes(arr));
                }
                2 => network = Some(read_utf8(&mut b)?),
                3 => {
                    let v = b.u64().map_err(codec)?;
                    state =
                        Some(WorkState::from_wire(v).ok_or(corrupt("unregistered work state"))?);
                }
                4 => degraded = Some(read_bool(&mut b)?),
                5 => unanchored = Some(read_bool(&mut b)?),
                6 => paths_given = Some(read_string_array(&mut b)?),
                7 => paths_abs = Some(read_string_array(&mut b)?),
                8 => shaping = Some(read_shaping(&mut b)?),
                9 => {
                    let raw = b.bytes().map_err(codec)?;
                    work_id = Some(
                        raw.try_into()
                            .map_err(|_| corrupt("work_id must be exactly 32 bytes"))?,
                    );
                }
                10 => cost_atto = Some(read_u128(&mut b)?),
                11 => {
                    let mut c = b.map().map_err(codec)?;
                    let mut total = None;
                    let mut gas = None;
                    let mut time = None;
                    let mut channel = None;
                    while let Some(ck) = c.next_key(&mut b).map_err(codec)? {
                        match ck {
                            0 => total = Some(read_u128(&mut b)?),
                            1 => gas = Some(read_u128(&mut b)?),
                            2 => time = Some(b.u64().map_err(codec)?),
                            3 => {
                                let v = b.u64().map_err(codec)?;
                                channel = Some(
                                    ConsentChannel::from_wire(v)
                                        .ok_or(corrupt("unregistered consent channel"))?,
                                );
                            }
                            _ => return Err(corrupt("unknown consent-record key")),
                        }
                    }
                    consent = Some(ConsentRecord {
                        total_ant_atto: total.ok_or(corrupt("consent total missing"))?,
                        gas_estimate_wei: gas.ok_or(corrupt("consent gas estimate missing"))?,
                        consent_time_unix_secs: time.ok_or(corrupt("consent time missing"))?,
                        channel: channel.ok_or(corrupt("consent channel missing"))?,
                    });
                }
                _ => return Err(corrupt("unknown meta key (strict v1 schema)")),
            }
        }
        b.finish().map_err(codec)?;

        Ok(WorkRecord {
            w: MasterSecret::from_bytes(w.ok_or(corrupt("W missing"))?),
            seal_id: seal_id.ok_or(corrupt("seal_id missing"))?,
            network: network.ok_or(corrupt("network missing"))?,
            state: state.ok_or(corrupt("state missing"))?,
            degraded: degraded.ok_or(corrupt("degraded flag missing"))?,
            unanchored: unanchored.ok_or(corrupt("unanchored flag missing"))?,
            input_paths_as_given: paths_given.ok_or(corrupt("as-given path list missing"))?,
            input_paths_absolute: paths_abs.ok_or(corrupt("absolutized path list missing"))?,
            shaping: shaping.ok_or(corrupt("shaping flags missing"))?,
            work_id,
            cost_atto,
            consent,
        })
    }
}

fn read_utf8(d: &mut CanonicalDecoder<'_>) -> Result<String, StoreError> {
    let raw = d.bytes().map_err(|_| StoreError::Corrupt {
        detail: "expected a byte string",
    })?;
    String::from_utf8(raw.to_vec()).map_err(|_| StoreError::Corrupt {
        detail: "string field is not valid UTF-8",
    })
}

fn read_bool(d: &mut CanonicalDecoder<'_>) -> Result<bool, StoreError> {
    match d.u64() {
        Ok(0) => Ok(false),
        Ok(1) => Ok(true),
        _ => Err(StoreError::Corrupt {
            detail: "flag fields must be 0 or 1",
        }),
    }
}

fn read_u128(d: &mut CanonicalDecoder<'_>) -> Result<u128, StoreError> {
    let raw = d.bytes().map_err(|_| StoreError::Corrupt {
        detail: "expected a 16-byte amount",
    })?;
    let arr: [u8; 16] = raw.try_into().map_err(|_| StoreError::Corrupt {
        detail: "amounts must be exactly 16 big-endian bytes",
    })?;
    Ok(u128::from_be_bytes(arr))
}

fn read_string_array(d: &mut CanonicalDecoder<'_>) -> Result<Vec<String>, StoreError> {
    let corrupt = |detail: &'static str| StoreError::Corrupt { detail };
    let n = d.array().map_err(|_| corrupt("expected an array"))?;
    let mut out = Vec::new();
    for _ in 0..n {
        out.push(read_utf8(d)?);
    }
    Ok(out)
}

fn read_shaping(d: &mut CanonicalDecoder<'_>) -> Result<SealShapingFlags, StoreError> {
    let corrupt = |detail: &'static str| StoreError::Corrupt { detail };
    let mut map = d
        .map()
        .map_err(|_| corrupt("shaping flags must be a map"))?;
    let mut flags = SealShapingFlags::default();
    let mut saw = [false; 6];
    while let Some(key) = map
        .next_key(d)
        .map_err(|_| corrupt("shaping flags map is malformed"))?
    {
        match key {
            0 => flags.title = Some(read_utf8(d)?),
            1 => flags.split_blank_lines = read_bool(d)?,
            2 => flags.force_text = read_bool(d)?,
            3 => flags.no_fine_tree = read_string_array(d)?,
            4 => flags.no_anchor = read_bool(d)?,
            5 => flags.force_degraded = read_bool(d)?,
            _ => return Err(corrupt("unknown shaping-flag key")),
        }
        // `key` matched 0..=5 above, so the index is always in range.
        if let Ok(idx) = usize::try_from(key)
            && idx < saw.len()
        {
            saw[idx] = true;
        }
    }
    // Key 0 (title) is optional; 1..=5 are required.
    if !saw[1..].iter().all(|s| *s) {
        return Err(corrupt("shaping flags incomplete"));
    }
    Ok(flags)
}

// ─────────────────────────────────────────────────────────────────────
// Small helpers
// ─────────────────────────────────────────────────────────────────────

/// Convert user-supplied paths into the v1 record's string form,
/// rejecting non-UTF-8 spellings (a recorded v1 limitation: the vault
/// schema stores UTF-8; the rejection surfaces pre-consent through D46's
/// invalid-argument class). U13 calls this for both the as-given and the
/// absolutized lists.
///
/// # Errors
///
/// [`StoreError::NonUtf8Path`] on the first non-UTF-8 path.
pub fn utf8_paths(paths: &[PathBuf]) -> Result<Vec<String>, StoreError> {
    paths
        .iter()
        .map(|p| p.to_str().map(str::to_owned).ok_or(StoreError::NonUtf8Path))
        .collect()
}

/// Lowercase-hex directory name of a seal id.
fn hex32(seal_id: &SealId) -> String {
    let mut s = String::with_capacity(32);
    for byte in seal_id.as_bytes() {
        use std::fmt::Write;
        let _ = write!(s, "{byte:02x}");
    }
    s
}

/// Parse a 32-char lowercase-hex work-directory name.
fn parse_hex32(name: &str) -> Option<SealId> {
    if name.len() != 32 || !name.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    let mut bytes = [0u8; 16];
    for (i, chunk) in name.as_bytes().chunks_exact(2).enumerate() {
        let hi = hex_val(chunk[0])?;
        let lo = hex_val(chunk[1])?;
        bytes[i] = (hi << 4) | lo;
    }
    Some(SealId::from_bytes(bytes))
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    }
}

/// Canonical decimal u64 (no leading zeros except `"0"` itself — a
/// `"007"` beside a `"7"` would alias one entry key onto two files).
fn parse_canonical_u64(name: &str) -> Option<u64> {
    if name.is_empty() || (name.len() > 1 && name.starts_with('0')) {
        return None;
    }
    if !name.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    name.parse().ok()
}

/// Anchor-slot grammar check (shared with the U12 export validator —
/// slots that could never live in the store must not import either).
pub(crate) fn validate_slot_name(slot: &str) -> Result<(), StoreError> {
    let bytes = slot.as_bytes();
    // Empty first: everything below indexes past the head byte.
    let Some((head, rest)) = bytes.split_first() else {
        return Err(StoreError::InvalidSlotName);
    };
    let head_ok = matches!(head, b'a'..=b'z' | b'0'..=b'9');
    let rest_ok = rest
        .iter()
        .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-'));
    if slot.len() <= MAX_ANCHOR_SLOT_LEN && head_ok && rest_ok {
        Ok(())
    } else {
        Err(StoreError::InvalidSlotName)
    }
}

/// Bounded read of one record file; `None` when absent.
fn read_record_file(path: &Path) -> Result<Option<Vec<u8>>, StoreError> {
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(StoreError::Io {
                path: path.to_owned(),
                source,
            });
        }
    };
    let mut bytes = Vec::new();
    file.take((MAX_RECORD_FILE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|source| StoreError::Io {
            path: path.to_owned(),
            source,
        })?;
    if bytes.len() > MAX_RECORD_FILE_BYTES {
        return Err(StoreError::Corrupt {
            detail: "record file exceeds the defensive size cap",
        });
    }
    Ok(Some(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trip_and_canonical_decimal() {
        let id = SealId::from_bytes([
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ]);
        let name = hex32(&id);
        assert_eq!(name, "00112233445566778899aabbccddeeff");
        assert_eq!(parse_hex32(&name), Some(id));
        assert_eq!(
            parse_hex32("00112233445566778899AABBCCDDEEFF"),
            None,
            "uppercase"
        );
        assert_eq!(parse_hex32("0011"), None, "short");

        assert_eq!(parse_canonical_u64("0"), Some(0));
        assert_eq!(parse_canonical_u64("7"), Some(7));
        assert_eq!(parse_canonical_u64("10"), Some(10));
        assert_eq!(parse_canonical_u64("007"), None, "leading zeros alias keys");
        assert_eq!(parse_canonical_u64(""), None);
        assert_eq!(parse_canonical_u64("7x"), None);
    }

    #[test]
    fn slot_name_grammar() {
        for good in ["ots-pending", "tsa-0.der", "a", "0", "x_y-z.9"] {
            assert!(validate_slot_name(good).is_ok(), "{good}");
        }
        for bad in [
            "",
            ".hidden",
            "-lead",
            "UPPER",
            "with space",
            "a/b",
            &"x".repeat(65),
        ] {
            assert!(validate_slot_name(bad).is_err(), "{bad}");
        }
    }
}
