//! The seal journal (S10): what a seal makes durable, when, and the state
//! machine those writes advance.
//!
//! MVP-SPEC.md lines 34 (core flow step 1) and 145 (vault — seal journal).
//! **Division of labor** (U9 Notes, restated from the other side): U9's
//! [`WorkStore`](crate::vault::store::WorkStore) owns *where and how
//! durably* — one file per record, atomic + fsync'd, every byte inside the
//! vault AEAD. This module owns *when and what*: the record shapes, the
//! entry-key namespace, the state machine, and the ordering rules the
//! pipeline may not violate.
//!
//! # The one rule the journal exists for
//!
//! **Staged bytes are durable before money moves.** Every unit's exact
//! ciphertext, its nonce and its precomputed target address — plus the
//! encrypted-manifest blob and the built plaintext manifest — are journaled
//! before the anchor gate runs and long before `pay()`. A crash anywhere
//! after that point is recoverable *without ever re-encrypting*, which is
//! what makes the `(k_u, nonce)` single-use invariant survivable across
//! process death (spec line 145; S11 owns the resume side).
//!
//! Scoping, per **D49**: the invariant binds the **paid path**. A
//! `--dry-run` reaches neither payment nor anchor, so it runs with
//! journaling disabled and performs no write at all; S12's dry-run
//! truncation barrier sits after `quote_batch`, and S16 asserts the mode
//! separately rather than exempting it.
//!
//! # The state machine
//!
//! ```text
//!   Staged ──► Anchored ──► Paid ──► Finalizing ──► Complete
//!      │           │          │           │
//!      └───────────┴──────────┴───────────┴────────► Abandoned
//! ```
//!
//! Transition writes land at pipeline barriers, not at convenience points:
//!
//! | transition | written | why |
//! | --- | --- | --- |
//! | → `Staged` | after every staged blob is durable | the pre-anchor barrier |
//! | → `Anchored` | after the anchor gate returns | pre-anchor kills re-run the gate |
//! | → `Paid` | the instant a receipt is durable, per sub-batch (D37) | before any finalize call |
//! | → `Finalizing` | before the first `finalize_batch` | marks the crash window |
//! | → `Complete` | after `finalize_batch` succeeds | the **D43 reclassification** |
//! | → `Abandoned` | staged bytes unavailable (S11) | payment forfeited, deliberately |
//!
//! [`SealState::Complete`] is D43's journal → cache reclassification: a
//! state-tag write, the same bytes, no move and no copy. From that tag on,
//! the staged bytes are *cache* — integrity-rechecked on use, refetchable,
//! and their loss is never an error. Before it they are *journal* —
//! resume-critical, never prunable, always exported.
//!
//! # Entry-key namespace (S10's to choose; U9 stores opaque bytes)
//!
//! ```text
//! journal/0            state record   — the fine state tag
//! journal/1            plan record    — seal_id, expected blob count,
//!                                       and the built plaintext manifest
//! journal/2            staged blob    — the encrypted manifest
//! journal/3 + unit_id  staged blob    — one per unit, in unit_id order
//! ```
//!
//! The **canonical blob order** the backend sees is derived from this
//! namespace, never stored twice: every unit ascending by `unit_id`, then
//! the encrypted manifest last ([`SealJournal::staged_slots`]). One source
//! of truth for the order that `quote_batch`/`finalize_batch` index into.
//!
//! What the plan record *does* carry independently is the **expected** blob
//! count ([`SealPlan`]): a directory listing can only report what is
//! present, so the set a resume checks its staged bytes against must be
//! recorded rather than derived — otherwise a deleted entry silently
//! shrinks the set it is checked against, which is the exact disk loss S11
//! must abandon on.
//!
//! # Secret hygiene (project rule 6)
//!
//! The journal holds exactly what the spec mandates: AEAD **ciphertexts**,
//! their nonces, their addresses, and the plaintext manifest — which is the
//! public artifact every bundle embeds. No plaintext unit bytes, no `W`, no
//! unit keys and no salts pass through this module: `W` reaches the vault
//! only as the borrowed [`WorkIdentity::w`] at creation, and is written by
//! U9's meta record, never by a journal entry. Journal content is never
//! logged, and no error variant here carries record bytes.

use antseal_core::codec::{CanonicalDecoder, encode_item};
use antseal_core::crypto::secrets::SealId;
use antseal_core::manifest::ContentAddress;
use antseal_core::storage::compute_storage_address;
use antseal_net::PaymentReceipt;

use crate::error::{CliError, ResumeSafetyReason};
use crate::vault::store::{ConsentRecord, SealShapingFlags, StoreError, WorkState};

/// Version of the journal record schema. Bumping it is a vault-format
/// event: new record shapes, a migration story, and tests land together
/// (the same discipline U9's `WORK_RECORD_VERSION` carries).
pub const SEAL_JOURNAL_VERSION: u32 = 1;

/// Journal entry key of the fine state record.
pub const STATE_ENTRY: u64 = 0;

/// Journal entry key of the plan record (`seal_id` + plaintext manifest).
pub const PLAN_ENTRY: u64 = 1;

/// Journal entry key of the encrypted-manifest staged blob.
pub const MANIFEST_BLOB_ENTRY: u64 = 2;

/// First journal entry key of the per-unit staged blobs: unit `u` lives at
/// `UNIT_ENTRY_BASE + u`.
pub const UNIT_ENTRY_BASE: u64 = 3;

/// Length of a unit/manifest AEAD nonce (spec line 91).
pub const NONCE_LEN: usize = 24;

// ─────────────────────────────────────────────────────────────────────────
// State machine
// ─────────────────────────────────────────────────────────────────────────

/// The per-work seal state machine (module docs).
///
/// Finer than U9's [`WorkState`], which is the *coarse mirror* every
/// list/status/D45 read keys on: this tag distinguishes the two pre-pay
/// barriers (`Staged` vs `Anchored`) and the two post-pay ones (`Paid` vs
/// `Finalizing`), which is exactly what resume needs to know and what a
/// display never does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u64)]
pub enum SealState {
    /// Every staged blob (units + encrypted manifest) and the plaintext
    /// manifest are durable. Nothing anchored, nothing paid.
    Staged = 1,
    /// The anchor gate returned; anchors (if any) are recorded. Nothing
    /// paid — a kill here resumes by re-quoting and re-consenting (D36).
    Anchored = 2,
    /// A payment receipt is durable. Money moved; no finalize has run.
    Paid = 3,
    /// `finalize_batch` has been called at least once. Idempotent to
    /// re-enter; the receipt is never re-paid.
    Finalizing = 4,
    /// `finalize_batch` succeeded. **D43**: the staged bytes are cache
    /// from this tag onward.
    Complete = 5,
    /// Staged bytes were unavailable and the seal was abandoned (S11).
    /// Any payment is forfeited — safety over cost, spec line 145.
    Abandoned = 6,
}

impl SealState {
    /// Every state, in machine order (exhaustiveness anchor for tests).
    pub const ALL: [Self; 6] = [
        Self::Staged,
        Self::Anchored,
        Self::Paid,
        Self::Finalizing,
        Self::Complete,
        Self::Abandoned,
    ];

    /// Wire tag.
    #[must_use]
    pub const fn as_wire(self) -> u64 {
        self as u64
    }

    /// Parse a wire tag; `None` for an unregistered value (never a panic —
    /// journal bytes are substitutable by a local writer).
    #[must_use]
    pub const fn from_wire(v: u64) -> Option<Self> {
        match v {
            1 => Some(Self::Staged),
            2 => Some(Self::Anchored),
            3 => Some(Self::Paid),
            4 => Some(Self::Finalizing),
            5 => Some(Self::Complete),
            6 => Some(Self::Abandoned),
            _ => None,
        }
    }

    /// Stable kebab identifier, for diagnostics and `--json` renders.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Staged => "staged",
            Self::Anchored => "anchored",
            Self::Paid => "paid",
            Self::Finalizing => "finalizing",
            Self::Complete => "complete",
            Self::Abandoned => "abandoned",
        }
    }

    /// The coarse [`WorkState`] mirror U9 records in the meta record —
    /// what `list`/`status`/D45's resume-candidate scan read.
    #[must_use]
    pub const fn work_state(self) -> WorkState {
        match self {
            Self::Staged | Self::Anchored => WorkState::IncompletePrePay,
            Self::Paid | Self::Finalizing => WorkState::IncompletePostPay,
            Self::Complete => WorkState::Complete,
            Self::Abandoned => WorkState::Abandoned,
        }
    }

    /// Whether money has provably moved for this work (the D36 rule that
    /// decides whether a resume re-quotes and re-consents at all).
    #[must_use]
    pub const fn is_post_pay(self) -> bool {
        matches!(self, Self::Paid | Self::Finalizing | Self::Complete)
    }

    /// Whether this state admits no further transition.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Complete | Self::Abandoned)
    }

    /// Whether the work is still resumable (D45's candidate predicate).
    #[must_use]
    pub const fn is_incomplete(self) -> bool {
        !self.is_terminal()
    }

    /// Whether `self → next` is a legal transition.
    ///
    /// Re-writing the same state is always legal (transitions are
    /// idempotent, because a crash between the durable write and the
    /// caller's return is indistinguishable from never having written).
    /// Every non-terminal state may abandon. Nothing leaves a terminal
    /// state — abandoning a `Complete` work or completing an `Abandoned`
    /// one are both bugs, not user states.
    #[must_use]
    pub const fn can_advance_to(self, next: Self) -> bool {
        if self as u64 == next as u64 {
            return true;
        }
        if self.is_terminal() {
            return false;
        }
        if matches!(next, Self::Abandoned) {
            return true;
        }
        matches!(
            (self, next),
            (Self::Staged, Self::Anchored)
                | (Self::Anchored, Self::Paid)
                | (Self::Paid, Self::Finalizing)
                | (Self::Finalizing, Self::Complete)
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Blob slots
// ─────────────────────────────────────────────────────────────────────────

/// Which blob of the seal a staged record holds.
///
/// The blob set the backend ever sees is exactly these: unit ciphertexts
/// (raw mirrors included) and the encrypted manifest. Nothing readable
/// leaves the machine (S12's egress rule; this enum is where that becomes
/// a type-level fact).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BlobSlot {
    /// One unit's AEAD ciphertext, keyed by its work-global `unit_id`
    /// (MVP-SPEC.md line 76).
    Unit {
        /// The work-global unit id.
        unit_id: u64,
    },
    /// The encrypted manifest blob (`k_m`, empty AAD — spec line 98).
    EncryptedManifest,
}

impl BlobSlot {
    /// This slot's journal entry key; `None` when `unit_id` is so large
    /// the key would overflow (unreachable for honest works — D32's chunk
    /// cap bounds unit counts far below — and an error rather than a wrap).
    #[must_use]
    pub const fn entry_key(self) -> Option<u64> {
        match self {
            Self::EncryptedManifest => Some(MANIFEST_BLOB_ENTRY),
            Self::Unit { unit_id } => unit_id.checked_add(UNIT_ENTRY_BASE),
        }
    }

    /// The slot a journal entry key names; `None` for the reserved
    /// non-blob keys ([`STATE_ENTRY`], [`PLAN_ENTRY`]).
    #[must_use]
    pub const fn from_entry_key(key: u64) -> Option<Self> {
        match key {
            MANIFEST_BLOB_ENTRY => Some(Self::EncryptedManifest),
            k if k >= UNIT_ENTRY_BASE => Some(Self::Unit {
                unit_id: k - UNIT_ENTRY_BASE,
            }),
            _ => None,
        }
    }

    /// Wire tag pair `(kind, id)` for the record codec.
    const fn wire(self) -> (u64, u64) {
        match self {
            Self::Unit { unit_id } => (0, unit_id),
            Self::EncryptedManifest => (1, 0),
        }
    }

    fn from_wire(kind: u64, id: u64) -> Option<Self> {
        match kind {
            0 => Some(Self::Unit { unit_id: id }),
            1 if id == 0 => Some(Self::EncryptedManifest),
            _ => None,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Records
// ─────────────────────────────────────────────────────────────────────────

/// One staged blob: the **exact bytes that will be uploaded**, the nonce
/// they were produced under, and the address they were precomputed to land
/// at (S4's BLAKE3-256 rule, D32).
///
/// The nonce duplicates the manifest's authoritative copy *for resume use
/// only* (S10 Notes) — resume needs it before it has decoded a manifest,
/// and the `(k_u, nonce)` single-use guard (S11) reads it to prove no
/// journaled nonce is ever handed back to the encryptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StagedBlob {
    /// Which blob this is.
    pub slot: BlobSlot,
    /// The 24-byte AEAD nonce this ciphertext was produced under.
    pub nonce: [u8; NONCE_LEN],
    /// The precomputed target address (S4/D32: BLAKE3-256 of `ciphertext`).
    pub address: ContentAddress,
    /// The exact ciphertext bytes. Public-destined AEAD output — inside
    /// the vault AEAD for uniformity and integrity, not confidentiality
    /// (D43).
    pub ciphertext: Vec<u8>,
}

impl StagedBlob {
    /// Encode to the versioned canonical-CBOR record bytes.
    ///
    /// # Errors
    ///
    /// [`JournalError::Encode`] — unreachable for well-formed records, but
    /// never a panic (library discipline).
    pub fn encode(&self) -> Result<Vec<u8>, JournalError> {
        let (kind, id) = self.slot.wire();
        let body = encode_item(|e| {
            e.map(|m| {
                m.entry(0, |e| e.u64(kind))?;
                m.entry(1, |e| e.u64(id))?;
                m.entry(2, |e| e.bytes(&self.nonce))?;
                m.entry(3, |e| e.bytes(self.address.as_bytes()))?;
                m.entry(4, |e| e.bytes(&self.ciphertext))
            })
        })
        .map_err(|_| JournalError::Encode)?;
        envelope(&body)
    }

    /// Parse a staged-blob record defensively.
    ///
    /// # Errors
    ///
    /// [`JournalError::NewerRecord`] for a future schema version;
    /// [`JournalError::Corrupt`] for every malformed shape.
    pub fn decode(bytes: &[u8]) -> Result<Self, JournalError> {
        let body = open_envelope(bytes)?;
        let mut d = CanonicalDecoder::new(body);
        let mut map = d.map().map_err(codec)?;

        let mut kind: Option<u64> = None;
        let mut id: Option<u64> = None;
        let mut nonce: Option<[u8; NONCE_LEN]> = None;
        let mut address: Option<ContentAddress> = None;
        let mut ciphertext: Option<Vec<u8>> = None;

        while let Some(key) = map.next_key(&mut d).map_err(codec)? {
            match key {
                0 => kind = Some(d.u64().map_err(codec)?),
                1 => id = Some(d.u64().map_err(codec)?),
                2 => {
                    let raw = d.bytes().map_err(codec)?;
                    nonce = Some(
                        raw.try_into()
                            .map_err(|_| corrupt("staged nonce must be exactly 24 bytes"))?,
                    );
                }
                3 => {
                    let raw = d.bytes().map_err(codec)?;
                    let arr: [u8; 32] = raw
                        .try_into()
                        .map_err(|_| corrupt("staged address must be exactly 32 bytes"))?;
                    address = Some(ContentAddress::from_bytes(arr));
                }
                4 => ciphertext = Some(d.bytes().map_err(codec)?.to_vec()),
                _ => return Err(corrupt("unknown staged-blob key (strict v1 schema)")),
            }
        }
        d.finish().map_err(codec)?;

        let slot = BlobSlot::from_wire(
            kind.ok_or_else(|| corrupt("staged-blob slot kind missing"))?,
            id.ok_or_else(|| corrupt("staged-blob slot id missing"))?,
        )
        .ok_or_else(|| corrupt("unregistered staged-blob slot"))?;

        Ok(Self {
            slot,
            nonce: nonce.ok_or_else(|| corrupt("staged nonce missing"))?,
            address: address.ok_or_else(|| corrupt("staged address missing"))?,
            ciphertext: ciphertext.ok_or_else(|| corrupt("staged ciphertext missing"))?,
        })
    }
}

/// The seal plan: how many blobs this work has, and the built plaintext
/// manifest once it exists.
///
/// The `unit_count` is what makes "are all my staged bytes still there?"
/// answerable at all. Enumerating the journal directory can only report
/// what *is* present, so a deleted entry would silently shrink the set it
/// was checked against — precisely the disk-loss case S11's abandon guard
/// exists for. The expected set is therefore recorded, not derived: the
/// plan is written as soon as staging finishes and rewritten with the
/// manifest once it is built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealPlan {
    /// Number of unit blobs staged for this work: slots
    /// `Unit { unit_id: 0..unit_count }`.
    pub unit_count: u64,
    /// The built plaintext manifest (envelope bytes); `None` until the
    /// manifest is built. Its presence is also what says the
    /// [`BlobSlot::EncryptedManifest`] blob is expected.
    pub manifest_bytes: Option<Vec<u8>>,
}

impl SealPlan {
    /// The complete expected blob set in canonical order: every unit
    /// ascending, then the encrypted manifest last (when the manifest
    /// exists).
    ///
    /// # Errors
    ///
    /// [`JournalError::UnitIdOutOfRange`] when `unit_count` exceeds what
    /// the entry-key namespace can address.
    pub fn expected_slots(&self) -> Result<Vec<BlobSlot>, JournalError> {
        let count = usize::try_from(self.unit_count).map_err(|_| JournalError::UnitIdOutOfRange)?;
        let mut slots = Vec::with_capacity(count.saturating_add(1));
        for unit_id in 0..self.unit_count {
            let slot = BlobSlot::Unit { unit_id };
            slot.entry_key().ok_or(JournalError::UnitIdOutOfRange)?;
            slots.push(slot);
        }
        if self.manifest_bytes.is_some() {
            slots.push(BlobSlot::EncryptedManifest);
        }
        Ok(slots)
    }
}

/// Everything the journal records about a work when the seal starts —
/// the D45 invocation identity plus the master secret the vault exists to
/// hold.
///
/// `w` is **borrowed**: the pipeline owns the secret and the journal impl
/// copies it into U9's meta record (which zeroizes on drop). Nothing here
/// clones or logs it, and a test double stores the non-secret fields only.
#[derive(Debug)]
pub struct WorkIdentity<'w> {
    /// The 32-byte per-work master secret `W` (spec line 89).
    pub w: antseal_core::crypto::material::MasterSecretRef<'w>,
    /// The work's public seal id and store key.
    pub seal_id: SealId,
    /// Effective network, canonical CLI spelling (D45 identity component).
    pub network: String,
    /// Sealed without anchors (the dev-only `--no-anchor` path, S13).
    pub unanchored: bool,
    /// Loudly-recorded degraded anchor set (`--force-degraded`).
    pub degraded: bool,
    /// Input paths exactly as given, in argument order.
    pub input_paths_as_given: Vec<String>,
    /// The same paths lexically absolutized — D45's resume match key.
    pub input_paths_absolute: Vec<String>,
    /// The seal-shaping flag set (D45 identity component).
    pub shaping: SealShapingFlags,
}

// ─────────────────────────────────────────────────────────────────────────
// Errors
// ─────────────────────────────────────────────────────────────────────────

/// Why the staged bytes of a work cannot be trusted to re-upload.
///
/// Every variant means the same operational thing — **the seal is
/// abandoned** (S11), because the only alternative is re-encrypting under a
/// journaled nonce, which is catastrophic `(k_u, nonce)` reuse. They are
/// distinguished for diagnosis, never for policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum StagedBytesUnavailable {
    /// The journal has no entry for this slot at all.
    #[error("staged bytes are missing from the journal")]
    Missing,
    /// The record decrypted and parsed, but the recomputed address (S4)
    /// disagrees with the journaled target: the bytes are not the bytes
    /// that were staged.
    #[error("staged bytes fail their address integrity check (S4 recompute disagrees)")]
    AddressMismatch,
    /// The staged ciphertext exceeds the chunk cap, so no address exists
    /// for it (D32) — a corrupt record, since staging enforced the cap.
    #[error("staged bytes exceed the chunk cap and cannot be addressed")]
    ExceedsChunkCap,
    /// The record failed authentication or has an impossible shape.
    #[error("the staged-bytes record failed authentication or is corrupt")]
    Corrupt,
}

impl From<StagedBytesUnavailable> for CliError {
    fn from(_: StagedBytesUnavailable) -> Self {
        CliError::ResumeSafetyAbort {
            reason: ResumeSafetyReason::StagedBytesMissing,
        }
    }
}

/// Everything the journal layer can fail with. Total over adversarial
/// bytes — no panic path, and no variant carries record content.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum JournalError {
    /// The work has no record in this vault.
    #[error("no journal exists for this work")]
    WorkNotFound,

    /// A record failed authentication or has an impossible shape.
    #[error("journal record failed authentication or is corrupt: {detail}")]
    Corrupt {
        /// Failure-class summary — never record bytes.
        detail: &'static str,
    },

    /// A record written by a newer antseal.
    #[error("journal record format v{found} is newer than this build supports")]
    NewerRecord {
        /// The version found on disk.
        found: u64,
    },

    /// A record could not be encoded (unreachable for well-formed
    /// records; surfaced rather than unwrapped).
    #[error("journal record encode failed on a fixed shape")]
    Encode,

    /// The pipeline attempted an illegal state transition — a bug class,
    /// not a user state, and refused before it can be written.
    #[error("illegal seal state transition: {} -> {}", .from.name(), .to.name())]
    IllegalTransition {
        /// Current state.
        from: SealState,
        /// Refused target.
        to: SealState,
    },

    /// A `unit_id` so large its journal entry key would overflow.
    #[error("unit id is too large to journal")]
    UnitIdOutOfRange,

    /// The staged bytes are unavailable — the abandon trigger (S11).
    #[error(transparent)]
    StagedBytes(#[from] StagedBytesUnavailable),

    /// The underlying record store failed (I/O, cipher, vault state).
    #[error(transparent)]
    Store(#[from] Box<StoreError>),
}

impl From<StoreError> for JournalError {
    fn from(err: StoreError) -> Self {
        match err {
            StoreError::WorkNotFound => JournalError::WorkNotFound,
            StoreError::Corrupt { detail } => JournalError::Corrupt { detail },
            StoreError::NewerRecord { found } => JournalError::NewerRecord { found },
            other => JournalError::Store(Box::new(other)),
        }
    }
}

impl From<JournalError> for CliError {
    fn from(err: JournalError) -> Self {
        match err {
            JournalError::WorkNotFound => CliError::Usage {
                message: "no work with this id exists in the vault (see `antseal list`)".to_owned(),
            },
            JournalError::Corrupt { .. } => CliError::VaultAuthFailure,
            JournalError::NewerRecord { found } => CliError::VaultNewerVersion {
                found,
                supported: SEAL_JOURNAL_VERSION,
            },
            JournalError::Encode
            | JournalError::IllegalTransition { .. }
            | JournalError::UnitIdOutOfRange => CliError::Internal {
                detail: err.to_string(),
            },
            JournalError::StagedBytes(reason) => reason.into(),
            JournalError::Store(inner) => (*inner).into(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────
// The interface (D34 Decision 2: defined here, beside the pipeline)
// ─────────────────────────────────────────────────────────────────────────

/// The durable half of a seal — implemented by
/// [`VaultJournal`](super::vault_journal::VaultJournal) over U9's record
/// store, and by test doubles.
///
/// # Why `&self`
///
/// Every method takes `&self` (the impl carries its CSPRNG behind interior
/// mutability) for two reasons: it mirrors
/// [`WorkStore`](crate::vault::store::WorkStore)'s own `&self` API, and
/// D37's per-sub-batch capture hook — a `Fn(&PaymentReceipt)` installed on
/// the backend at construction — could never be built from a `&mut`
/// borrow the pipeline is simultaneously holding.
///
/// # Ordering contract the pipeline owes (S12 asserts it)
///
/// 1. [`begin`](SealJournal::begin) before any other call for that work.
/// 2. Every [`put_staged`](SealJournal::put_staged) and
///    [`put_manifest`](SealJournal::put_manifest) before the state reaches
///    [`SealState::Anchored`] — and therefore before the anchor gate, the
///    quote, and `pay()`.
/// 3. [`put_receipt`](SealJournal::put_receipt) before **any**
///    `finalize_batch` call, per sub-batch as each tx lands (D37).
/// 4. [`SealState::Complete`] only after `finalize_batch` returns `Ok`.
pub trait SealJournal {
    /// Create the work's durable record: identity, `W`, and the initial
    /// [`SealState::Staged`] tag. The seal pipeline's first durable write.
    ///
    /// # Errors
    ///
    /// [`JournalError::Store`] when the slot is taken (a bug class: seal
    /// ids are drawn fresh) or the write fails.
    fn begin(&self, identity: &WorkIdentity<'_>) -> Result<(), JournalError>;

    /// Durably persist one staged blob — its ciphertext, nonce and
    /// address. Atomic: when this returns, a `SIGKILL` leaves the bytes
    /// readable on reopen.
    ///
    /// # Errors
    ///
    /// [`JournalError::UnitIdOutOfRange`], [`JournalError::WorkNotFound`],
    /// or a store failure.
    fn put_staged(&self, seal_id: &SealId, blob: &StagedBlob) -> Result<(), JournalError>;

    /// Read one staged blob back, byte-identically.
    ///
    /// # Errors
    ///
    /// [`JournalError::StagedBytes`] when the entry is absent or corrupt.
    fn staged(&self, seal_id: &SealId, slot: BlobSlot) -> Result<StagedBlob, JournalError>;

    /// Every staged slot of this work in **canonical blob order**: units
    /// ascending by `unit_id`, then the encrypted manifest last (module
    /// docs). Zero decryption of blob bodies.
    ///
    /// # Errors
    ///
    /// Store-level failures only.
    fn staged_slots(&self, seal_id: &SealId) -> Result<Vec<BlobSlot>, JournalError>;

    /// Journal the seal plan: the expected blob count and — once built —
    /// the plaintext manifest, which resume re-encrypts nothing to obtain
    /// and never rebuilds or re-signs (S11).
    ///
    /// # Errors
    ///
    /// Store-level failures.
    fn put_plan(&self, seal_id: &SealId, plan: &SealPlan) -> Result<(), JournalError>;

    /// The journaled plan; `None` before staging finished.
    ///
    /// # Errors
    ///
    /// [`JournalError::Corrupt`] on a malformed record.
    fn plan(&self, seal_id: &SealId) -> Result<Option<SealPlan>, JournalError>;

    /// The journaled plaintext manifest; `None` before it was built.
    ///
    /// # Errors
    ///
    /// [`JournalError::Corrupt`] on a malformed record.
    fn manifest(&self, seal_id: &SealId) -> Result<Option<Vec<u8>>, JournalError> {
        Ok(self.plan(seal_id)?.and_then(|plan| plan.manifest_bytes))
    }

    /// Advance the state machine, writing both the fine tag and U9's
    /// coarse [`WorkState`] mirror.
    ///
    /// # Errors
    ///
    /// [`JournalError::IllegalTransition`] — refused before any write.
    fn set_state(&self, seal_id: &SealId, state: SealState) -> Result<(), JournalError>;

    /// The current fine state.
    ///
    /// # Errors
    ///
    /// [`JournalError::WorkNotFound`] / [`JournalError::Corrupt`].
    fn state(&self, seal_id: &SealId) -> Result<SealState, JournalError>;

    /// Journal a payment receipt — the write that must land *the instant*
    /// each sub-batch tx does, and strictly before any finalize call
    /// (D37). Idempotent: a later, more complete receipt overwrites an
    /// earlier partial one.
    ///
    /// # Errors
    ///
    /// Store-level failures; encoding failures.
    fn put_receipt(&self, seal_id: &SealId, receipt: &PaymentReceipt) -> Result<(), JournalError>;

    /// The journaled receipt; `None` means *not paid yet* — a state, not
    /// an error, and the one fact that tells resume never to call `pay`.
    ///
    /// # Errors
    ///
    /// [`JournalError::Corrupt`] on a malformed record.
    fn receipt(&self, seal_id: &SealId) -> Result<Option<PaymentReceipt>, JournalError>;

    /// Record the D36 consent record at every affirmative consent —
    /// display-only baseline for the next resume render, never a payment
    /// input.
    ///
    /// # Errors
    ///
    /// Store-level failures.
    fn put_consent(&self, seal_id: &SealId, consent: ConsentRecord) -> Result<(), JournalError>;

    /// The latest consent record; `None` before the first consent.
    ///
    /// # Errors
    ///
    /// Store-level failures.
    fn consent(&self, seal_id: &SealId) -> Result<Option<ConsentRecord>, JournalError>;

    /// Record the seal's outcome fields once known: `work_id` (spec line
    /// 75) and the total storage cost actually paid.
    ///
    /// # Errors
    ///
    /// Store-level failures.
    fn record_outcome(
        &self,
        seal_id: &SealId,
        work_id: Option<[u8; 32]>,
        cost_atto: Option<u128>,
    ) -> Result<(), JournalError>;

    /// Every work whose state [`SealState::is_incomplete`] — the resume
    /// candidate set (D45), enumerable without decrypting a single staged
    /// blob body. Rendering is U's (`list`).
    ///
    /// # Errors
    ///
    /// Store-level failures.
    fn incomplete_works(&self) -> Result<Vec<(SealId, SealState)>, JournalError>;
}

// ─────────────────────────────────────────────────────────────────────────
// Integrity
// ─────────────────────────────────────────────────────────────────────────

/// The S4 staged-bytes integrity check: recompute the address from the
/// journaled ciphertext (BLAKE3-256, D32) and compare it to the journaled
/// target.
///
/// This is the check whose failure classifies a work as
/// staged-bytes-unavailable and therefore **abandons** it (S11). It is
/// cheap, total, and runs on every resume before a single byte is
/// re-uploaded.
///
/// # Errors
///
/// [`StagedBytesUnavailable::AddressMismatch`] or
/// [`StagedBytesUnavailable::ExceedsChunkCap`].
pub fn check_staged_integrity(blob: &StagedBlob) -> Result<(), StagedBytesUnavailable> {
    let recomputed = compute_storage_address(&blob.ciphertext)
        .map_err(|_| StagedBytesUnavailable::ExceedsChunkCap)?;
    if recomputed.as_bytes() == blob.address.as_bytes() {
        Ok(())
    } else {
        Err(StagedBytesUnavailable::AddressMismatch)
    }
}

/// Run [`check_staged_integrity`] over every blob the work is **expected**
/// to have staged.
///
/// The resume precondition in one call: `Ok` means every byte that would be
/// re-uploaded is exactly the byte that was staged, and none has gone
/// missing.
///
/// The expected set comes from the journaled [`SealPlan`], never from a
/// directory listing — a listing can only report what is present, so a
/// deleted entry would silently shrink the set it is checked against, which
/// is exactly the disk loss S11 must abandon on. A work with no plan record
/// yet (killed mid-staging, before anything was anchored or paid) is checked
/// against what it has: there is nothing at risk and nothing to reconcile.
///
/// # Errors
///
/// The first [`StagedBytesUnavailable`] found (wrapped), or a store-level
/// failure.
pub fn verify_all_staged<J: SealJournal + ?Sized>(
    journal: &J,
    seal_id: &SealId,
) -> Result<(), JournalError> {
    let expected = match journal.plan(seal_id)? {
        Some(plan) => plan.expected_slots()?,
        None => journal.staged_slots(seal_id)?,
    };
    for slot in expected {
        let blob = journal.staged(seal_id, slot)?;
        check_staged_integrity(&blob)?;
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────
// Record codec helpers (versioned canonical CBOR, D7 manual-impl rule)
// ─────────────────────────────────────────────────────────────────────────

pub(super) fn corrupt(detail: &'static str) -> JournalError {
    JournalError::Corrupt { detail }
}

pub(super) fn codec<E>(_: E) -> JournalError {
    JournalError::Corrupt {
        detail: "journal record is not canonical CBOR",
    }
}

/// Wrap a record body in the `[version, body]` envelope every journal
/// record carries.
pub(super) fn envelope(body: &[u8]) -> Result<Vec<u8>, JournalError> {
    encode_item(|e| {
        e.array(|a| {
            a.item(|e| e.u64(u64::from(SEAL_JOURNAL_VERSION)))?;
            a.item(|e| e.bytes(body))
        })
    })
    .map_err(|_| JournalError::Encode)
}

/// Unwrap the `[version, body]` envelope, rejecting future versions
/// without parsing their bodies.
pub(super) fn open_envelope(bytes: &[u8]) -> Result<&[u8], JournalError> {
    let mut d = CanonicalDecoder::new(bytes);
    if d.array().map_err(codec)? != 2 {
        return Err(corrupt("journal envelope must be [version, body]"));
    }
    let version = d.u64().map_err(codec)?;
    if version == 0 {
        return Err(corrupt("journal version 0 is invalid"));
    }
    if version > u64::from(SEAL_JOURNAL_VERSION) {
        return Err(JournalError::NewerRecord { found: version });
    }
    let body = d.bytes().map_err(codec)?;
    d.finish().map_err(codec)?;
    Ok(body)
}

/// Encode the tiny state record (entry [`STATE_ENTRY`]).
pub(super) fn encode_state(state: SealState) -> Result<Vec<u8>, JournalError> {
    let body = encode_item(|e| e.map(|m| m.entry(0, |e| e.u64(state.as_wire()))))
        .map_err(|_| JournalError::Encode)?;
    envelope(&body)
}

/// Decode the state record.
pub(super) fn decode_state(bytes: &[u8]) -> Result<SealState, JournalError> {
    let body = open_envelope(bytes)?;
    let mut d = CanonicalDecoder::new(body);
    let mut map = d.map().map_err(codec)?;
    let mut state = None;
    while let Some(key) = map.next_key(&mut d).map_err(codec)? {
        match key {
            0 => {
                let v = d.u64().map_err(codec)?;
                state = Some(SealState::from_wire(v).ok_or_else(|| corrupt("unregistered state"))?);
            }
            _ => return Err(corrupt("unknown state-record key")),
        }
    }
    d.finish().map_err(codec)?;
    state.ok_or_else(|| corrupt("state tag missing"))
}

/// Encode the plan record (entry [`PLAN_ENTRY`]).
pub(super) fn encode_plan(seal_id: &SealId, plan: &SealPlan) -> Result<Vec<u8>, JournalError> {
    let body = encode_item(|e| {
        e.map(|m| {
            m.entry(0, |e| e.bytes(seal_id.as_bytes()))?;
            m.entry(1, |e| e.u64(plan.unit_count))?;
            match &plan.manifest_bytes {
                Some(bytes) => m.entry(2, |e| e.bytes(bytes)),
                None => Ok(()),
            }
        })
    })
    .map_err(|_| JournalError::Encode)?;
    envelope(&body)
}

/// Decode the plan record into `(seal_id, plan)`.
pub(super) fn decode_plan(bytes: &[u8]) -> Result<(SealId, SealPlan), JournalError> {
    let body = open_envelope(bytes)?;
    let mut d = CanonicalDecoder::new(body);
    let mut map = d.map().map_err(codec)?;
    let mut seal_id = None;
    let mut unit_count = None;
    let mut manifest_bytes = None;
    while let Some(key) = map.next_key(&mut d).map_err(codec)? {
        match key {
            0 => {
                let raw = d.bytes().map_err(codec)?;
                let arr: [u8; 16] = raw
                    .try_into()
                    .map_err(|_| corrupt("plan seal_id must be exactly 16 bytes"))?;
                seal_id = Some(SealId::from_bytes(arr));
            }
            1 => unit_count = Some(d.u64().map_err(codec)?),
            2 => manifest_bytes = Some(d.bytes().map_err(codec)?.to_vec()),
            _ => return Err(corrupt("unknown plan-record key")),
        }
    }
    d.finish().map_err(codec)?;
    Ok((
        seal_id.ok_or_else(|| corrupt("plan seal_id missing"))?,
        SealPlan {
            unit_count: unit_count.ok_or_else(|| corrupt("plan unit count missing"))?,
            manifest_bytes,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_state_round_trips_its_wire_tag() {
        for state in SealState::ALL {
            assert_eq!(SealState::from_wire(state.as_wire()), Some(state));
        }
        assert_eq!(SealState::from_wire(0), None);
        assert_eq!(SealState::from_wire(7), None);
        assert_eq!(SealState::from_wire(u64::MAX), None);
    }

    /// The exact transition table of the module docs — asserted as data so
    /// a future edit to `can_advance_to` cannot silently widen it.
    #[test]
    fn the_transition_table_is_exactly_the_documented_one() {
        use SealState::{Abandoned, Anchored, Complete, Finalizing, Paid, Staged};
        let legal = [
            (Staged, Anchored),
            (Anchored, Paid),
            (Paid, Finalizing),
            (Finalizing, Complete),
            (Staged, Abandoned),
            (Anchored, Abandoned),
            (Paid, Abandoned),
            (Finalizing, Abandoned),
        ];
        for from in SealState::ALL {
            for to in SealState::ALL {
                let expected = from == to || legal.contains(&(from, to));
                assert_eq!(
                    from.can_advance_to(to),
                    expected,
                    "{} -> {} should be {}",
                    from.name(),
                    to.name(),
                    if expected { "legal" } else { "refused" }
                );
            }
        }
    }

    /// Terminal states are sinks: no transition leaves them, in either
    /// direction of the money boundary.
    #[test]
    fn terminal_states_are_sinks() {
        for terminal in [SealState::Complete, SealState::Abandoned] {
            for to in SealState::ALL {
                if to == terminal {
                    continue;
                }
                assert!(
                    !terminal.can_advance_to(to),
                    "{} must be terminal",
                    terminal.name()
                );
            }
        }
    }

    #[test]
    fn coarse_mirror_matches_the_d43_and_d45_split() {
        assert_eq!(SealState::Staged.work_state(), WorkState::IncompletePrePay);
        assert_eq!(
            SealState::Anchored.work_state(),
            WorkState::IncompletePrePay
        );
        assert_eq!(SealState::Paid.work_state(), WorkState::IncompletePostPay);
        assert_eq!(
            SealState::Finalizing.work_state(),
            WorkState::IncompletePostPay
        );
        assert_eq!(SealState::Complete.work_state(), WorkState::Complete);
        assert_eq!(SealState::Abandoned.work_state(), WorkState::Abandoned);
        // The D36 pre-pay/post-pay boundary is the consent boundary.
        assert!(!SealState::Staged.is_post_pay());
        assert!(!SealState::Anchored.is_post_pay());
        assert!(SealState::Paid.is_post_pay());
        assert!(SealState::Finalizing.is_post_pay());
    }

    #[test]
    fn entry_keys_round_trip_and_reserve_the_non_blob_slots() {
        assert_eq!(BlobSlot::from_entry_key(STATE_ENTRY), None);
        assert_eq!(BlobSlot::from_entry_key(PLAN_ENTRY), None);
        assert_eq!(
            BlobSlot::from_entry_key(MANIFEST_BLOB_ENTRY),
            Some(BlobSlot::EncryptedManifest)
        );
        for unit_id in [0_u64, 1, 7, 65_535] {
            let slot = BlobSlot::Unit { unit_id };
            let key = slot.entry_key().expect("small id");
            assert_eq!(BlobSlot::from_entry_key(key), Some(slot));
        }
        assert_eq!(BlobSlot::Unit { unit_id: u64::MAX }.entry_key(), None);
    }

    fn sample(slot: BlobSlot, ciphertext: Vec<u8>) -> StagedBlob {
        let address = compute_storage_address(&ciphertext).expect("small blob");
        StagedBlob {
            slot,
            nonce: [7; NONCE_LEN],
            address,
            ciphertext,
        }
    }

    #[test]
    fn staged_blob_round_trips_byte_identically() {
        for slot in [BlobSlot::EncryptedManifest, BlobSlot::Unit { unit_id: 3 }] {
            let blob = sample(slot, vec![0xAB; 300]);
            let encoded = blob.encode().expect("encodes");
            let decoded = StagedBlob::decode(&encoded).expect("decodes");
            assert_eq!(decoded, blob);
            assert_eq!(decoded.ciphertext, blob.ciphertext);
        }
    }

    #[test]
    fn integrity_check_detects_a_single_flipped_bit() {
        let mut blob = sample(BlobSlot::Unit { unit_id: 0 }, vec![1, 2, 3, 4]);
        check_staged_integrity(&blob).expect("pristine bytes verify");
        blob.ciphertext[2] ^= 0x01;
        assert_eq!(
            check_staged_integrity(&blob),
            Err(StagedBytesUnavailable::AddressMismatch)
        );
    }

    #[test]
    fn a_future_schema_version_is_rejected_without_parsing_its_body() {
        let body = encode_item(|e| e.map(|m| m.entry(0, |e| e.u64(1)))).expect("encodes");
        let future = encode_item(|e| {
            e.array(|a| {
                a.item(|e| e.u64(u64::from(SEAL_JOURNAL_VERSION) + 1))?;
                a.item(|e| e.bytes(&body))
            })
        })
        .expect("encodes");
        match StagedBlob::decode(&future) {
            Err(JournalError::NewerRecord { found }) => {
                assert_eq!(found, u64::from(SEAL_JOURNAL_VERSION) + 1);
            }
            other => panic!("expected NewerRecord, got {other:?}"),
        }
    }

    #[test]
    fn malformed_records_error_rather_than_panic() {
        for bytes in [
            &b""[..],
            &b"\x00"[..],
            &[0x9f, 0xff][..],             // indefinite-length array
            &[0x82, 0x00, 0x40][..],       // version 0
            &[0x82, 0x01, 0x40][..],       // empty body
            &[0x83, 0x01, 0x40, 0x00][..], // 3-element envelope
        ] {
            assert!(StagedBlob::decode(bytes).is_err());
            assert!(decode_state(bytes).is_err());
            assert!(decode_plan(bytes).is_err());
        }
    }

    #[test]
    fn state_and_plan_records_round_trip() {
        for state in SealState::ALL {
            let bytes = encode_state(state).expect("encodes");
            assert_eq!(decode_state(&bytes).expect("decodes"), state);
        }
        let seal_id = SealId::from_bytes([9; 16]);
        for plan in [
            SealPlan {
                unit_count: 3,
                manifest_bytes: None,
            },
            SealPlan {
                unit_count: 3,
                manifest_bytes: Some(vec![0xCA, 0xFE, 0xBA, 0xBE]),
            },
        ] {
            let bytes = encode_plan(&seal_id, &plan).expect("encodes");
            let (back_id, back_plan) = decode_plan(&bytes).expect("decodes");
            assert_eq!(back_id, seal_id);
            assert_eq!(back_plan, plan);
        }
    }

    /// The expected blob set is the plan's, in canonical order — units
    /// ascending, encrypted manifest last and only once the manifest
    /// exists.
    #[test]
    fn expected_slots_are_the_canonical_blob_set() {
        let staging_only = SealPlan {
            unit_count: 3,
            manifest_bytes: None,
        };
        assert_eq!(
            staging_only.expected_slots().expect("small plan"),
            vec![
                BlobSlot::Unit { unit_id: 0 },
                BlobSlot::Unit { unit_id: 1 },
                BlobSlot::Unit { unit_id: 2 },
            ]
        );
        let complete = SealPlan {
            unit_count: 2,
            manifest_bytes: Some(vec![1, 2, 3]),
        };
        assert_eq!(
            complete.expected_slots().expect("small plan"),
            vec![
                BlobSlot::Unit { unit_id: 0 },
                BlobSlot::Unit { unit_id: 1 },
                BlobSlot::EncryptedManifest,
            ]
        );
    }
}
