//! What the anchor stage leaves behind (U22): the U9 slot records that
//! persist the artifacts, and the summary the seal report renders.
//!
//! # Two consumers, one source
//!
//! A20's [`AnchorSubmission`] is a rich in-memory value that exists for the
//! length of one invocation. Two things must outlive it:
//!
//! - **the artifacts** — the merged pending `.ots` and every verified
//!   `TimeStampResp`, which `status`/`reveal` read back and F embeds in a
//!   bundle. They go into U9's `anchors/<slot>` area
//!   ([`AnchorArtifact::encode`]), which is opaque bytes to the store.
//! - **the outcome** — per-endpoint, so the seal summary can *name* each
//!   anchor's result rather than printing a count. That is
//!   [`AnchorSummary`], which is derived and never persisted.
//!
//! Both are built here, from the submission, so there is one reading of what
//! the stage produced rather than one per consumer.
//!
//! # The slot names are the schema
//!
//! U9's grammar is `[a-z0-9][a-z0-9._-]{0,63}`, and the names below are
//! chosen so a slot listing names the **family** each artifact belongs to
//! without decrypting anything: `ots-pending` for the merged artifact,
//! `tsa-<n>` for the n-th **verified** capture in endpoint order. Only
//! verified captures are stored: an unverifiable token is evidence of
//! nothing, and keeping it would put bytes in the vault that no consumer may
//! ever act on.
//!
//! **`ots-pending` names the family, not the state** (D97 R7). An upgraded
//! artifact stays in that slot, and the upgrade group rides keys 4/5/6 of the
//! record — deliberately *inside* the AEAD. Slot names are filenames and sit
//! outside it (D42 put "everything else inside"), so a second `ots-upgrade`
//! slot would have published a new anchor-*state* bit to anyone with
//! filesystem read access. The ruling adds no such bit: the listing before
//! and after an upgrade is byte-identical.
//!
//! # One write site, in two spellings
//!
//! An anchor slot is written from exactly two places in this crate (D97 R3):
//! the seal/resume anchor loop, which writes what [`artifacts_of`] produced
//! through `SealJournal::put_anchor`, and [`apply_upgrade`], which is the
//! *only* path that may record an upgrade and which calls
//! `WorkStore::put_anchor` directly. U23 and U24 both go through
//! [`apply_upgrade`], and neither writes an anchor slot by any other route —
//! that single-write-site rule is the whole of the atomicity argument,
//! because `put_anchor` replaces the whole record in one atomic rename.
//!
//! The two spellings are D99 R10's amendment to D97 R3, and they are forced:
//! U24's hook runs after dispatch with no journal in hand and no way to build
//! one (`VaultJournal::new` is scan-restricted to `seal_session.rs`). A
//! call-site count that greps one spelling would therefore report half the
//! rule (U56).
//!
//! # What is deliberately not counted here
//!
//! No independence or identity number. D92 §5.6 permits "N mutually
//! independent parties" only from the verify-side identity count, and A72
//! records that the seal-side [`AnchorSubmission::distinct_tsas`] and the
//! verify-side notion **disagree** for a TSA that rotated its signing key
//! (seal-side reads 2, verify-side 1 — the seal side over-counts). This
//! module therefore reports two things and names them as what they are:
//! *verified tokens* (endpoint-level, and the number A20's gate compares
//! against 1) and *distinct calendar routes* (D54 §3's liveness metric for
//! upgrade redundancy). Neither is an independence claim, so Q89's
//! "2 calendars, 1 party" confusion is not created by this layer.

use antseal_anchor::gate::{AnchorStage, AnchorSubmissionOutcome};
use antseal_anchor::ots::AppliedUpgrade;
use antseal_anchor::submit::AnchorSubmission;
use antseal_core::bundle::schema::OtsUpgrade;
use antseal_core::codec::{CanonicalDecoder, encode_item};
use antseal_core::crypto::secrets::SealId;
use rand_core::TryCryptoRng;

use super::journal::{JournalError, codec, corrupt, envelope, open_envelope};
use crate::vault::store::WorkStore;

/// Length of the Bitcoin block header D79's upgrade group carries — the
/// same fixed 80 the bundle decoder enforces, named here so the vault rule
/// and the bundle rule cannot drift apart by a literal.
const BLOCK_HEADER_LEN: usize = antseal_core::bundle::registry::BLOCK_HEADER_LEN as usize;

/// The `.ots` slot: one merged artifact per work, whatever the calendar
/// count (the merge is A13's, and its branch order is deterministic).
pub const OTS_SLOT: &str = "ots-pending";

/// Slot name for the `index`-th verified TSA capture.
///
/// Kept as a function rather than a format string at the call site so the
/// grammar U9 enforces is satisfied in one place.
#[must_use]
pub fn tsa_slot(index: usize) -> String {
    format!("tsa-{index}")
}

/// Which family a stored artifact belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactKind {
    /// A merged pending `.ots` (A13).
    OtsPending,
    /// One RFC 3161 `TimeStampResp`, verified (A10).
    TsaToken,
}

impl ArtifactKind {
    const fn as_wire(self) -> u64 {
        match self {
            Self::OtsPending => 0,
            Self::TsaToken => 1,
        }
    }

    const fn from_wire(wire: u64) -> Option<Self> {
        match wire {
            0 => Some(Self::OtsPending),
            1 => Some(Self::TsaToken),
            _ => None,
        }
    }

    /// Stable identifier for reports and `--json`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::OtsPending => "ots-pending",
            Self::TsaToken => "tsa-token",
        }
    }
}

/// One anchor artifact as it sits in a U9 slot.
///
/// The artifact bytes alone would not be enough: a `TimeStampResp` does not
/// carry the endpoint it came from, and neither family carries the
/// **fetch date** — the moment this machine received the bytes, which A32
/// defines as provenance that gates no outcome and which U22's Accept row
/// requires to land beside the token. So the slot holds a versioned
/// canonical-CBOR record (the same `[version, body]` envelope every other
/// journal record uses) rather than raw bytes.
///
/// # Two fetch dates, and they are different facts (D97 R4/R5)
///
/// [`Self::fetch_date`] (key 2) is when *this* artifact's bytes arrived —
/// for an upgraded `.ots` that is still the **original submission's**
/// moment, because the upgrade replaces the bytes without re-submitting the
/// commitment. The upgrade group's own [`OtsUpgrade::fetch_date`] (key 6) is
/// when the block header was fetched from esplora. Both are A32 provenance:
/// recorded, never compared. Neither is ever read from a clock at the write
/// site — key 6 is pinned from the engine's parameter (R5), and key 2 is
/// carried across unchanged by the read-modify-write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorArtifact {
    /// Which family.
    pub kind: ArtifactKind,
    /// The endpoint this came from, verbatim as configured. For the merged
    /// `.ots` this is empty: the artifact merges several calendars and names
    /// them internally in its own attestations.
    pub endpoint: String,
    /// POSIX seconds at which this machine received the bytes (A32:
    /// recorded, never compared).
    pub fetch_date: u64,
    /// The artifact itself — `.ots` container bytes, or DER `TimeStampResp`.
    pub bytes: Vec<u8>,
    /// D79's upgrade group — block height, the 80-byte block header, and the
    /// header's own fetch date — present iff this `.ots` has been upgraded to
    /// a Bitcoin attestation (D97 §3).
    ///
    /// Legal only on [`ArtifactKind::OtsPending`]; a `TsaToken` carrying it is
    /// refused by both [`Self::encode`] and [`Self::decode`] (R2). The type is
    /// `antseal_core`'s, deliberately reused rather than mirrored: it is what
    /// the upgrade engine produces and what the bundle consumes, so a second
    /// struct here would be a third home for one fact.
    pub upgrade: Option<OtsUpgrade>,
}

impl AnchorArtifact {
    /// Encode to the versioned canonical-CBOR record bytes.
    ///
    /// The upgrade group is written as keys 4/5/6 or not at all — never
    /// partially, which is unrepresentable because all three live in one
    /// [`OtsUpgrade`].
    ///
    /// # Errors
    ///
    /// [`JournalError::IllegalAnchorWrite`] when an upgrade group is attached
    /// to a non-OTS record (R2, refused on the write side too so this codec
    /// can never emit bytes its own [`decode`](Self::decode) would reject);
    /// [`JournalError::Encode`] — unreachable for well-formed records, but
    /// returned rather than panicked (library discipline).
    pub fn encode(&self) -> Result<Vec<u8>, JournalError> {
        if self.upgrade.is_some() && self.kind != ArtifactKind::OtsPending {
            return Err(JournalError::IllegalAnchorWrite {
                detail: "an upgrade group may only be recorded on an OTS artifact",
            });
        }
        let body = encode_item(|e| {
            e.map(|m| {
                m.entry(0, |e| e.u64(self.kind.as_wire()))?;
                m.entry(1, |e| e.str(&self.endpoint))?;
                m.entry(2, |e| e.u64(self.fetch_date))?;
                m.entry(3, |e| e.bytes(&self.bytes))?;
                match &self.upgrade {
                    Some(upgrade) => {
                        m.entry(4, |e| e.u64(upgrade.block_height()))?;
                        m.entry(5, |e| e.bytes(upgrade.block_header()))?;
                        m.entry(6, |e| e.u64(upgrade.fetch_date()))
                    }
                    None => Ok(()),
                }
            })
        })
        .map_err(|_| JournalError::Encode)?;
        envelope(&body)
    }

    /// Parse an anchor-artifact record defensively.
    ///
    /// # v1 bytes under the v2 parser
    ///
    /// [`open_envelope`] discards the version, so a record written at
    /// `SEAL_JOURNAL_VERSION == 1` (keys 0..3 only) arrives here with nothing
    /// to branch on. That is safe **because keys 4/5/6 are optional and
    /// absent-means-`None`**, which is precisely the correct v1 reading of a
    /// never-upgraded artifact — not because the parser noticed. The next
    /// journal schema change is safe on this path only if it is additive and
    /// optional in the same way (U54).
    ///
    /// # Errors
    ///
    /// [`JournalError::NewerRecord`] for a future schema version;
    /// [`JournalError::Corrupt`] for every malformed shape — an unregistered
    /// kind tag, an unknown key, a partial D79 upgrade group (named by its
    /// lowest-numbered absent key), a block header that is not exactly 80
    /// bytes, or an upgrade group on a non-OTS record (R2). None is
    /// defaulted, and none panics.
    pub fn decode(bytes: &[u8]) -> Result<Self, JournalError> {
        let body = open_envelope(bytes)?;
        let mut d = CanonicalDecoder::new(body);
        let mut map = d.map().map_err(codec)?;

        let mut kind: Option<u64> = None;
        let mut endpoint: Option<String> = None;
        let mut fetch_date: Option<u64> = None;
        let mut artifact: Option<Vec<u8>> = None;
        let mut block_height: Option<u64> = None;
        let mut block_header: Option<[u8; BLOCK_HEADER_LEN]> = None;
        let mut header_fetch_date: Option<u64> = None;

        while let Some(key) = map.next_key(&mut d).map_err(codec)? {
            match key {
                0 => kind = Some(d.u64().map_err(codec)?),
                1 => endpoint = Some(d.str().map_err(codec)?.to_owned()),
                2 => fetch_date = Some(d.u64().map_err(codec)?),
                3 => artifact = Some(d.bytes().map_err(codec)?.to_vec()),
                4 => block_height = Some(d.u64().map_err(codec)?),
                5 => {
                    let raw = d.bytes().map_err(codec)?;
                    block_header =
                        Some(raw.try_into().map_err(|_| {
                            corrupt("artifact block header must be exactly 80 bytes")
                        })?);
                }
                6 => header_fetch_date = Some(d.u64().map_err(codec)?),
                _ => return Err(corrupt("unknown anchor-artifact key (strict schema)")),
            }
        }
        d.finish().map_err(codec)?;

        // D79, copied rather than reinvented (R1): all-three-or-none, decided
        // without ever reading a sealer-written status field, and reporting
        // the **lowest-numbered** absent key so the diagnosis is deterministic
        // when two are missing. The bundle decoder
        // (`antseal_core::bundle::schema::OtsAnchor::decode`) runs the same
        // rule over the same three facts, so the vault and the bundle cannot
        // disagree about a partial group.
        let upgrade = match (block_height, block_header, header_fetch_date) {
            (None, None, None) => None,
            (Some(height), Some(header), Some(date)) => Some(OtsUpgrade::new(height, header, date)),
            (height, header, _) => {
                return Err(corrupt(if height.is_none() {
                    "artifact upgrade group is missing its block height"
                } else if header.is_none() {
                    "artifact upgrade group is missing its block header"
                } else {
                    "artifact upgrade group is missing its header fetch date"
                }));
            }
        };

        let kind = ArtifactKind::from_wire(kind.ok_or_else(|| corrupt("artifact kind missing"))?)
            .ok_or_else(|| corrupt("unregistered anchor-artifact kind"))?;

        // R2: the kind and the group ride one record, so the cross-family
        // check costs a line — and it closes a confusion the two-slot shape
        // could not even have expressed. Checked *after* the group's own
        // shape rule, so a partial group on a TSA record is still reported as
        // partial: the D79 verdict is about the group and does not depend on
        // where it was found.
        if upgrade.is_some() && kind != ArtifactKind::OtsPending {
            return Err(corrupt("an upgrade group is only legal on an OTS artifact"));
        }

        Ok(Self {
            kind,
            endpoint: endpoint.ok_or_else(|| corrupt("artifact endpoint missing"))?,
            fetch_date: fetch_date.ok_or_else(|| corrupt("artifact fetch date missing"))?,
            bytes: artifact.ok_or_else(|| corrupt("artifact bytes missing"))?,
            upgrade,
        })
    }
}

/// Every artifact one submission produced, paired with the slot it belongs
/// in — in stage order (OTS first, then TSA), which is the order the stage
/// ran in.
///
/// Verified captures only, on both counts: `ots.artifact` is `Some` exactly
/// when the merge re-validated, and the TSA half iterates
/// [`antseal_anchor::tsa::TsaCaptureStage::verified`].
#[must_use]
pub fn artifacts_of(
    submission: &AnchorSubmission,
    fetch_date: u64,
) -> Vec<(String, AnchorArtifact)> {
    let mut out = Vec::new();
    if let Some(bytes) = &submission.ots.artifact {
        out.push((
            OTS_SLOT.to_owned(),
            AnchorArtifact {
                kind: ArtifactKind::OtsPending,
                endpoint: String::new(),
                fetch_date,
                bytes: bytes.clone(),
                // A fresh submission is pending by construction: the calendar
                // has not buried the commitment yet, so there is no block to
                // record. The group arrives later, through
                // [`apply_upgrade`] and only through it.
                upgrade: None,
            },
        ));
    }
    for (index, capture) in submission.tsa.verified().enumerate() {
        out.push((
            tsa_slot(index),
            AnchorArtifact {
                kind: ArtifactKind::TsaToken,
                endpoint: capture.endpoint.clone(),
                // The capture's own record, not the caller's parameter: this
                // is the instant *that* exchange completed, and A2 already
                // recorded it.
                fetch_date: capture.record.fetch_date,
                bytes: capture.token.clone(),
                // R2: never on a TSA record.
                upgrade: None,
            },
        ));
    }
    out
}

/// Record one applied OTS upgrade — **the only path in this crate that may
/// write an upgrade group** (D97 R3, D99 R10).
///
/// # Why one function, and why exactly one `put_anchor`
///
/// `AppliedUpgrade`'s own doc says the artifact and its group are *"recorded
/// together … or not at all"*. That is a property of
/// [`WorkStore::put_anchor`](crate::vault::store::WorkStore::put_anchor)
/// being a temp-write + fsync + rename, and it only survives if the pair
/// never crosses two writes. One record, one call: a kill anywhere leaves the
/// slot wholly old or wholly new, and the torn state
/// (`OtsAnchorState::AttestedHeaderMissing`) is unreachable from this path by
/// construction rather than by ordering discipline (D97 §2 K3/K4).
///
/// # Why the store and not the journal (D99 R10 amends D97 R3)
///
/// This takes a [`WorkStore`] and an RNG, not a `&dyn SealJournal`, and the
/// reason is mechanical rather than stylistic: U24's hook runs from
/// `main_entry` after dispatch has completed, takes the vault lock itself,
/// and has no journal — nor any way to build one, since `VaultJournal::new`
/// is scan-restricted to `seal_session.rs` (a session would also mint a D37
/// receipt sink nobody arms, on a path that never pays). `put_anchor` is a
/// store method; this function uses no state machine, no plan, no receipt and
/// no sink, so the store is exactly what it needs and nothing more.
///
/// # It is a read-modify-write, not a blind write (D97 R4)
///
/// `prior` is the record [`StoredAnchors`] decoded out of `slot`. Key 2 — the
/// **original submission's** fetch date — is carried across verbatim; the
/// upgrade's own fetch date is a different fact and lands in key 6, pinned
/// from `applied.upgrade.fetch_date()` (R5). No clock is read here, or
/// anywhere below here.
///
/// # `prior` is load-bearing: compare-and-set (D99 R3)
///
/// The engine polls **unlocked**, so the record this transition was computed
/// from may have been rewritten before the lock was taken — most ordinarily
/// by a resume, which rewrites `ots-pending` from a *fresh* submission. The
/// slot is therefore re-read here and compared against `prior` in full;
/// anything but an exact match discards the transition. Comparing the whole
/// record rather than only the bytes is what makes R4 honest: a changed key 2
/// means the fetch date this write would carry forward belongs to a
/// submission that no longer exists.
///
/// # Errors
///
/// [`JournalError::IllegalAnchorWrite`] when the transition would violate D97
/// R6 (an upgraded artifact with no group is strictly worse than the pending
/// one it replaces, and unrescuable — so it is refused, never written) or R2
/// (a group on a non-OTS record). [`JournalError::AnchorSlotMoved`] when the
/// compare-and-set fails — a benign outcome the caller is expected to handle,
/// not a fault. Otherwise encoding and store-level failures.
pub fn apply_upgrade<R: TryCryptoRng + ?Sized>(
    store: &WorkStore<'_>,
    seal_id: &SealId,
    slot: &str,
    prior: &AnchorArtifact,
    applied: &AppliedUpgrade,
    rng: &mut R,
) -> Result<(), JournalError> {
    // R6. The engine's control flow makes `None` unreachable in a *returned*
    // report (`changed ⟹ upgrade.is_some()`), but that is a property of
    // `ots/engine.rs:451-484` rather than of the type, so the write site
    // refuses rather than trusts. If the engine ever gains a path that pushes
    // without a confirmed header, this is what stops it silently downgrading
    // an anchor to `internally-consistent-only`.
    let Some(upgrade) = applied.upgrade.as_ref() else {
        return Err(JournalError::IllegalAnchorWrite {
            detail: "an OTS upgrade arrived without its block-header group",
        });
    };
    if prior.kind != ArtifactKind::OtsPending {
        return Err(JournalError::IllegalAnchorWrite {
            detail: "an upgrade group may only be recorded on an OTS artifact",
        });
    }

    // D99 R3's compare-and-set. Read through the same decoder the transition
    // was computed with, so "unchanged" means the same record and not merely
    // the same ciphertext (each write draws a fresh nonce, so the bytes on
    // disk differ even for an identical record).
    let current = store
        .get_anchor(seal_id, slot)?
        .ok_or(JournalError::AnchorSlotMoved)?;
    if AnchorArtifact::decode(current.as_bytes())? != *prior {
        return Err(JournalError::AnchorSlotMoved);
    }

    let record = AnchorArtifact {
        kind: prior.kind,
        endpoint: prior.endpoint.clone(),
        // R4: the submission's date, untouched.
        fetch_date: prior.fetch_date,
        bytes: applied.artifact.clone(),
        // R5: the engine's parameter, carried verbatim inside the group.
        upgrade: Some(upgrade.clone()),
    };
    store.put_anchor(seal_id, slot, &record.encode()?, rng)?;
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────
// The reader (U47)
// ─────────────────────────────────────────────────────────────────────────

/// Which family a slot name belongs to, and where it sorts inside it.
///
/// Parsed rather than pattern-matched loosely, because the *name* is the only
/// thing that survives outside the AEAD and a reader that guessed would let a
/// mis-named slot become a mis-ordered anchor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum SlotFamily {
    /// The one merged `.ots` slot. Sorts before every TSA slot, which is
    /// the order [`antseal_anchor::ots::PendingWork`] indexes them in.
    Ots,
    /// The `n`-th verified TSA capture.
    Tsa(usize),
}

impl SlotFamily {
    /// Read a slot name, or `None` for a name outside the two families.
    ///
    /// The `tsa-<n>` arm requires the name to be **exactly** what
    /// [`tsa_slot`] would have produced, so `tsa-01` is refused rather than
    /// silently aliased onto `tsa-1` — two slots decoding to one index is a
    /// lost artifact, and U9's grammar admits both names.
    fn parse(slot: &str) -> Option<Self> {
        if slot == OTS_SLOT {
            return Some(Self::Ots);
        }
        let index: usize = slot.strip_prefix("tsa-")?.parse().ok()?;
        (tsa_slot(index) == slot).then_some(Self::Tsa(index))
    }

    /// The artifact kind a slot of this family must hold.
    const fn kind(self) -> ArtifactKind {
        match self {
            Self::Ots => ArtifactKind::OtsPending,
            Self::Tsa(_) => ArtifactKind::TsaToken,
        }
    }
}

/// Why one anchor slot could not be interpreted (**D100 R1**).
///
/// Three, not one, because they demand three different actions and only one
/// of them is anybody's fault. Collapsing them is the defect one level down:
/// [`Self::NewerRecord`] means *upgrade antseal*, [`Self::Undecodable`] means
/// *your vault is damaged*, and [`Self::SlotMoved`] means *another antseal is
/// running* — which is not damage at all, because `list` takes no lock by
/// design and a concurrent `seal` makes it expected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DamageReason {
    /// The record's bytes will not parse into an [`AnchorArtifact`] — a
    /// malformed CBOR shape, an unregistered kind, an unknown key, a partial
    /// D79 upgrade group, a slot name outside both families, or a record
    /// whose kind disagrees with its slot's family.
    ///
    /// `detail` is the decoder's own `&'static str`, verbatim. Publishing it
    /// is safe **by construction, not by review**:
    /// [`JournalError::Corrupt`]'s own field doc is *"Failure-class summary —
    /// never record bytes"*, so no record content and no secret can reach it
    /// (project rule 6, satisfied by the type).
    Undecodable {
        /// The failure class, as the decoder spelled it.
        detail: &'static str,
    },
    /// The record's envelope names a journal version this build does not
    /// implement.
    NewerRecord {
        /// The version found on disk.
        found: u64,
    },
    /// The slot vanished between the listing and the read.
    SlotMoved,
}

impl DamageReason {
    /// The stable kebab identifier for `--json` (D100 R3), wildcard-free so a
    /// fourth reason has to name itself here.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Undecodable { .. } => "undecodable",
            Self::NewerRecord { .. } => "newer-record",
            Self::SlotMoved => "slot-moved",
        }
    }

    /// The failure class summary a renderer shows beside the slot.
    #[must_use]
    pub const fn detail(&self) -> &'static str {
        match self {
            Self::Undecodable { detail } => detail,
            Self::NewerRecord { .. } => "this record was written by a newer antseal",
            Self::SlotMoved => "this anchor slot changed while it was being read",
        }
    }

    /// The record format version, for [`Self::NewerRecord`] only.
    #[must_use]
    pub const fn format_version(&self) -> Option<u64> {
        match self {
            Self::NewerRecord { found } => Some(*found),
            Self::Undecodable { .. } | Self::SlotMoved => None,
        }
    }

    /// The error this damage **used** to be, byte-for-byte.
    ///
    /// [`StoredAnchors::require_intact`] is the whole-fail door, and the
    /// thing that makes it a door rather than a new policy is that it raises
    /// exactly what `read` raised before D100. Every message and every
    /// [`ErrorClass`](crate::error::ErrorClass) is preserved here, which is
    /// why R11 step 2's refactor could be checked by *"no assertion text
    /// moves"*.
    fn into_error(self) -> JournalError {
        match self {
            Self::Undecodable { detail } => JournalError::Corrupt { detail },
            Self::NewerRecord { found } => JournalError::NewerRecord { found },
            Self::SlotMoved => corrupt("an anchor slot vanished between listing and reading"),
        }
    }
}

/// One anchor slot whose record could not be interpreted, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DamagedSlot {
    /// The slot name, verbatim. Outside the AEAD already (D42 is untouched
    /// by publishing it), and the only handle a user has on the damage.
    pub slot: String,
    /// Which of R1's three this is.
    pub reason: DamageReason,
}

/// One damaged slot as `--json` spells it (**D100 R3**).
///
/// Four keys, all **always present**: `slot`, `reason` ∈
/// `{undecodable, newer-record, slot-moved}`, `detail`, and `format_version`
/// — non-null only for `newer-record`.
///
/// It lives here rather than in either renderer because `list` and `status`
/// both emit it, and one fact spelled two ways in one machine document is
/// A103's defect at the document level (D100 §9(v)).
#[must_use]
pub fn damaged_slot_json(damaged: &DamagedSlot) -> serde_json::Value {
    serde_json::json!({
        "slot": damaged.slot,
        "reason": damaged.reason.name(),
        "detail": damaged.reason.detail(),
        "format_version": damaged.reason.format_version(),
    })
}

impl DamagedSlot {
    /// The kind the slot **name** implies, or `None` when the name itself is
    /// outside both families.
    ///
    /// Deliberately weaker than a verdict, and D100 §1.4 is why: the
    /// artifact's `kind` lives at key 0 **inside** the record, so a damaged
    /// slot's kind is unknowable. The name gives a family and nothing more —
    /// and `assemble` proves the name can be outside both families too. Its
    /// one use is negative: a caller must not claim a kind is *absent* while
    /// holding a damaged slot that could have been one.
    #[must_use]
    pub fn slot_kind(&self) -> Option<ArtifactKind> {
        SlotFamily::parse(&self.slot).map(SlotFamily::kind)
    }
}

/// The artifacts of one work that **did** decode — the evidence half of
/// [`StoredAnchors`], reachable only through one of its two named doors.
///
/// # The order is not the directory order
///
/// [`WorkStore::list_anchors`](crate::vault::store::WorkStore::list_anchors)
/// sorts **lexically**, so `tsa-10` comes back before `tsa-2`. The engine
/// indexes anchors positionally ([`AppliedUpgrade::anchor_index`] is an index
/// into `PendingWork::ots`), so a lexical list would silently pair an applied
/// upgrade with a different capture the first time a work has eleven TSAs.
/// This type therefore re-sorts numerically — OTS first, then TSA by parsed
/// index — and that ordering is what [`Self::ots_slot`] resolves against, in
/// the same pass, never by re-listing the directory (R10).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IntactAnchors {
    /// Ordered OTS-then-TSA; the OTS entries are the first `ots_len`.
    slots: Vec<(String, AnchorArtifact)>,
    ots_len: usize,
}

impl IntactAnchors {
    /// Every artifact with its slot name, OTS first then TSA by index.
    #[must_use]
    pub fn all(&self) -> &[(String, AnchorArtifact)] {
        &self.slots
    }

    /// The OTS artifacts, in the order `PendingWork::ots` must be built in.
    #[must_use]
    pub fn ots(&self) -> &[(String, AnchorArtifact)] {
        &self.slots[..self.ots_len]
    }

    /// The TSA captures, ascending by slot index.
    #[must_use]
    pub fn tsa(&self) -> &[(String, AnchorArtifact)] {
        &self.slots[self.ots_len..]
    }

    /// The slot an [`AppliedUpgrade::anchor_index`] names (R10).
    ///
    /// The index is into the `Vec` **this reader built**, never a slot name
    /// and never a fresh directory listing: re-listing between the read and
    /// the write would resolve the index against a set that may have moved.
    /// `None` means the report named an anchor this work does not have —
    /// a caller bug, surfaced rather than indexed past.
    #[must_use]
    pub fn ots_slot(&self, anchor_index: usize) -> Option<&str> {
        self.ots().get(anchor_index).map(|(slot, _)| slot.as_str())
    }

    /// The artifact an [`AppliedUpgrade::anchor_index`] names, paired with its
    /// slot — what [`apply_upgrade`]'s read-modify-write needs, in one call.
    #[must_use]
    pub fn ots_entry(&self, anchor_index: usize) -> Option<(&str, &AnchorArtifact)> {
        self.ots()
            .get(anchor_index)
            .map(|(slot, artifact)| (slot.as_str(), artifact))
    }

    /// Whether this work holds no *readable* anchor artifacts.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }

    /// How many readable artifacts, across both families.
    #[must_use]
    pub fn len(&self) -> usize {
        self.slots.len()
    }
}

/// Every anchor slot one work holds: the artifacts that decoded, and the
/// slots that did not (**U47**, restructured by **D100 R2**).
///
/// # One reader, because two decoders of one versioned record drift
///
/// `status`, the U24 hook and `reveal` all need these bytes back. This is the
/// only path that decodes them, and [`apply_upgrade`] is the only path that
/// writes them — so the read and the write of a versioned record are each in
/// exactly one place. D100 adds a second **policy**, not a second codec:
/// there is still exactly one call to [`AnchorArtifact::decode`] in the
/// workspace.
///
/// # A decode failure is a value, and the whole-fail rule has a door
///
/// The hazard the old rule named is real — *a caller handed nine of ten
/// artifacts would render a verdict about evidence it does not have* — and it
/// is honoured **more strongly** than before, because it used to be a comment
/// and is now a type. The artifacts live on [`IntactAnchors`], and there are
/// exactly two ways to reach one:
///
/// - [`Self::require_intact`] — the **evidence** door. Refuses if anything is
///   damaged, with precisely the error the whole read used to raise. This is
///   what `apply_upgrade`'s callers and (at M3) `reveal` take: a bundle built
///   from a partial anchor set would be a claim about evidence its builder
///   never saw.
/// - [`Self::intact_and_damaged`] — the **reporting** door. Hands back the
///   survivors *and* the damage together, so a renderer receives the damage
///   whether it asked for it or not. `list`, `status` and the U24 hook take
///   this one, and no fourth production file may (the S36-shaped scan in this
///   module's tests is what enforces it).
///
/// # Where the line is, and why it is the AEAD
///
/// [`Self::read`]'s signature is unchanged and it still fails — on
/// **enumeration** and on **authentication**, never on a per-record schema
/// refusal (R5):
///
/// - everything `list_anchors` raises (I/O, `AlienEntry`, `InvalidSlotName`)
///   is an enumeration failure: if the listing is untrustworthy you do not
///   know what you are missing, and a partial picture is dishonest by
///   construction. Same rule as `list_works`;
/// - everything `get_anchor` raises from the **cipher** layer
///   (`CipherError::AuthFailure`, `BlobTooShort`) stays one code. **That is
///   the line that keeps U6 whole.** Below the AEAD, one sentence; above it,
///   where no unauthenticated caller can observe the distinction, the truth.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct StoredAnchors {
    intact: IntactAnchors,
    /// In the order the two passes found them: decode refusals in
    /// `list_anchors`' lexical order, then family refusals in the same order
    /// (see [`Self::require_intact`]).
    damaged: Vec<DamagedSlot>,
}

impl StoredAnchors {
    /// Read and decode every anchor slot of one work.
    ///
    /// A work with no `anchors/` directory yields an empty set — a state,
    /// not a failure: `--no-anchor` seals and works killed before the anchor
    /// gate both have one. A slot whose record will not decode is **not** a
    /// failure either: it is collected into [`Self::damaged`].
    ///
    /// # Errors
    ///
    /// Enumeration failures from `list_anchors` and cipher-layer failures
    /// from `get_anchor` — the two classes on the far side of the line in
    /// this type's docs. [`JournalError::Encode`] and the transition
    /// variants cannot be produced by a decode and are propagated rather
    /// than reclassified, so a bug in this module never becomes a damaged
    /// slot.
    pub fn read(store: &WorkStore<'_>, seal_id: &SealId) -> Result<Self, JournalError> {
        let mut records = Vec::new();
        let mut damaged = Vec::new();
        for slot in store.list_anchors(seal_id)? {
            let Some(bytes) = store.get_anchor(seal_id, &slot)? else {
                damaged.push(DamagedSlot {
                    slot,
                    reason: DamageReason::SlotMoved,
                });
                continue;
            };
            match AnchorArtifact::decode(bytes.as_bytes()) {
                Ok(artifact) => records.push((slot, artifact)),
                Err(JournalError::Corrupt { detail }) => damaged.push(DamagedSlot {
                    slot,
                    reason: DamageReason::Undecodable { detail },
                }),
                Err(JournalError::NewerRecord { found }) => damaged.push(DamagedSlot {
                    slot,
                    reason: DamageReason::NewerRecord { found },
                }),
                // Not a schema refusal, so not this work's damage: an
                // encode or a transition error arriving here is a bug in
                // this module and is surfaced as one.
                Err(other) => return Err(other),
            }
        }
        Ok(Self::assemble(records, damaged))
    }

    /// Order and cross-check already-decoded records.
    ///
    /// Split out from [`Self::read`] so the ordering and family rules are
    /// testable without an Argon2id vault per case; it is private, so `read`
    /// remains the only way in and U47's "one reader" holds.
    ///
    /// `damaged` is the decode pass's own findings, and family refusals are
    /// **appended** to it rather than interleaved — which is what preserves
    /// the diagnosis [`Self::require_intact`] gives on a vault damaged in
    /// both ways at once (D100 §8's named drift risk).
    fn assemble(records: Vec<(String, AnchorArtifact)>, mut damaged: Vec<DamagedSlot>) -> Self {
        let mut keyed = Vec::with_capacity(records.len());
        for (slot, artifact) in records {
            let Some(family) = SlotFamily::parse(&slot) else {
                damaged.push(DamagedSlot {
                    slot,
                    reason: DamageReason::Undecodable {
                        detail: "anchor slot name belongs to no known artifact family",
                    },
                });
                continue;
            };
            // The slot name lives outside the AEAD and the kind lives inside
            // it; U9's identity AAD stops a record being replayed into a
            // different slot, but nothing stops a *writer* putting the wrong
            // family in. Cheap to check, and it is the difference between a
            // TSA token counted as an OTS anchor and a refusal.
            if artifact.kind != family.kind() {
                damaged.push(DamagedSlot {
                    slot,
                    reason: DamageReason::Undecodable {
                        detail: "anchor slot family disagrees with the record kind",
                    },
                });
                continue;
            }
            keyed.push((family, slot, artifact));
        }
        keyed.sort_by_key(|(family, _, _)| *family);
        let ots_len = keyed
            .iter()
            .filter(|(family, _, _)| matches!(family, SlotFamily::Ots))
            .count();
        Self {
            intact: IntactAnchors {
                slots: keyed
                    .into_iter()
                    .map(|(_, slot, artifact)| (slot, artifact))
                    .collect(),
                ots_len,
            },
            damaged,
        }
    }

    /// Every slot this read could not interpret, in the order it found them.
    #[must_use]
    pub fn damaged(&self) -> &[DamagedSlot] {
        &self.damaged
    }

    /// **The evidence door**: the artifacts, or a refusal naming the first
    /// slot that is not one.
    ///
    /// # Errors
    ///
    /// The first damaged slot's own error, which is byte-for-byte what
    /// [`Self::read`] raised before D100: [`JournalError::NewerRecord`]
    /// propagated **distinctly** from [`JournalError::Corrupt`], because
    /// "upgrade antseal" and "your vault is damaged" are different sentences
    /// and only one of them is the user's fault.
    pub fn require_intact(&self) -> Result<&IntactAnchors, JournalError> {
        match self.damaged.first() {
            Some(first) => Err(first.reason.clone().into_error()),
            None => Ok(&self.intact),
        }
    }

    /// **The reporting door**: the survivors and the damage, together.
    ///
    /// A caller can still drop the second element with an explicit `_`. That
    /// is greppable and reviewable, unlike an absent call, and it is what the
    /// S36-shaped scan in this module's tests checks: only `listing.rs`,
    /// `status.rs` and `upgrade_hook.rs` may name this.
    #[must_use]
    pub fn intact_and_damaged(&self) -> (&IntactAnchors, &[DamagedSlot]) {
        (&self.intact, &self.damaged)
    }

    /// How many anchor slots this work holds in total, damaged included.
    ///
    /// The count `list` renders *"N of M slots unreadable"* from, and the
    /// reason per-record isolation beats a per-work badge: a badge produced
    /// by catching an error at the work boundary can say *damaged* and cannot
    /// say *1 of 4* (D100 §2(b)).
    #[must_use]
    pub fn total_slots(&self) -> usize {
        self.intact.len() + self.damaged.len()
    }

    /// Whether this work holds no anchor slots at all — damaged included.
    ///
    /// A `--no-anchor` seal and a work whose every slot is damaged are
    /// different facts, and this is the one that means *nothing is there*.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.total_slots() == 0
    }
}

/// What one endpoint of the anchor stage did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorEndpointOutcome {
    /// Which half of the stage. The **enum**, not its label, so a renderer
    /// matches exhaustively and a third family cannot acquire a wrong
    /// description by falling into a `_` arm.
    pub stage: AnchorStage,
    /// The endpoint URL, verbatim as configured.
    pub endpoint: String,
    /// `None` on success; the failure class otherwise (`http`,
    /// `not-granted`, `unverifiable`, `untrusted-chain`, …), taken from the
    /// typed error's own `class()` so a new variant cannot acquire a wrong
    /// label in a second table.
    pub failure_class: Option<&'static str>,
    /// The typed error's message, when it failed.
    pub detail: Option<String>,
}

impl AnchorEndpointOutcome {
    /// Whether this endpoint contributed evidence.
    #[must_use]
    pub const fn succeeded(&self) -> bool {
        self.failure_class.is_none()
    }
}

/// The anchor stage's outcome as the seal report needs it.
///
/// Derived from A20's submission and carried out of the pipeline on
/// [`SealOutcome`](super::resume::SealOutcome). Never persisted — the
/// durable record is the artifacts plus the work record's `degraded` flag.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AnchorSummary {
    /// One row per endpoint contacted, in stage order.
    pub endpoints: Vec<AnchorEndpointOutcome>,
    /// TSA endpoints that produced a token passing **full core
    /// verification** — the number A20's gate compares against
    /// `MIN_VERIFIED_TSA_TOKENS`, and never a mixed anchor count
    /// (D54 §3 / D92 §5.5: OTS contributes exactly zero to that gate).
    pub verified_tsa_tokens: usize,
    /// Distinct normalized pending-attestation URIs — D54 §3's **liveness**
    /// metric for how many independent upgrade routes exist. Not an
    /// independence count (module docs).
    pub distinct_calendar_routes: usize,
    /// Whether anything in the stage must be said out loud.
    pub degraded: bool,
    /// A20's degradation report, verbatim — every failed endpoint named.
    pub degradation: Vec<String>,
}

impl AnchorSummary {
    /// Read one submission outcome.
    ///
    /// [`AnchorSubmissionOutcome::Empty`] — the `--no-anchor` path — yields
    /// `None`: an empty summary and "no stage ran" are different facts, and
    /// the report renders them differently.
    #[must_use]
    pub fn of(outcome: &AnchorSubmissionOutcome) -> Option<Self> {
        outcome.submission().map(Self::from_submission)
    }

    /// Read one submission.
    #[must_use]
    pub fn from_submission(submission: &AnchorSubmission) -> Self {
        let ots = submission.ots.attempts.iter().map(|attempt| {
            let failure = attempt.outcome.as_ref().err();
            AnchorEndpointOutcome {
                stage: AnchorStage::Ots,
                endpoint: attempt.calendar.clone(),
                failure_class: failure.map(|f| f.class()),
                detail: failure.map(ToString::to_string),
            }
        });
        let tsa = submission.tsa.attempts.iter().map(|attempt| {
            let failure = attempt.outcome.as_ref().err();
            AnchorEndpointOutcome {
                stage: AnchorStage::Tsa,
                endpoint: attempt.endpoint.clone(),
                failure_class: failure.map(|f| f.class()),
                detail: failure.map(ToString::to_string),
            }
        });
        Self {
            endpoints: ots.chain(tsa).collect(),
            // D92 §5.5's foot-gun, closed at the one place this crate counts:
            // the TSA-scoped accessor, never a mixed anchor total.
            verified_tsa_tokens: submission.verified_tsa_count(),
            distinct_calendar_routes: submission.ots.distinct_calendars(),
            degraded: submission.is_degraded(),
            degradation: submission.degradation_report(),
        }
    }
}

#[cfg(test)]
#[path = "anchors/tests.rs"]
mod tests;
