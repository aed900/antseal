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

/// Every anchor artifact one work holds, decoded once, in the order the
/// upgrade engine indexes them (**U47**).
///
/// # One reader, because two decoders of one versioned record drift
///
/// `status`, the U24 hook and `reveal` all need these bytes back. This is the
/// only path that decodes them, and [`apply_upgrade`] is the only path that
/// writes them — so the read and the write of a versioned record are each in
/// exactly one place.
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
///
/// # A decode failure fails the whole read
///
/// Never a partial picture: one unreadable slot means the work's anchor set
/// is unknown, and a caller handed nine of ten artifacts would render a
/// verdict about evidence it does not have. Same discipline as
/// `list_works`/`list_anchors`/`WorkListing::gather`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct StoredAnchors {
    /// Ordered OTS-then-TSA; the OTS entries are the first `ots_len`.
    slots: Vec<(String, AnchorArtifact)>,
    ots_len: usize,
}

impl StoredAnchors {
    /// Read and decode every anchor slot of one work.
    ///
    /// A work with no `anchors/` directory yields an empty set — a state,
    /// not a failure: `--no-anchor` seals and works killed before the anchor
    /// gate both have one.
    ///
    /// # Errors
    ///
    /// [`JournalError::NewerRecord`] — propagated **distinctly** from
    /// [`JournalError::Corrupt`], because "upgrade antseal" and "your vault
    /// is damaged" are different sentences and only one of them is the user's
    /// fault. [`JournalError::Corrupt`] for a malformed record, a slot name
    /// outside the two families, a record whose kind disagrees with its
    /// slot's family, or a slot that vanished between the listing and the
    /// read. Store-level failures otherwise.
    pub fn read(store: &WorkStore<'_>, seal_id: &SealId) -> Result<Self, JournalError> {
        let mut records = Vec::new();
        for slot in store.list_anchors(seal_id)? {
            let bytes = store
                .get_anchor(seal_id, &slot)?
                .ok_or_else(|| corrupt("an anchor slot vanished between listing and reading"))?;
            let artifact = AnchorArtifact::decode(bytes.as_bytes())?;
            records.push((slot, artifact));
        }
        Self::assemble(records)
    }

    /// Order and cross-check already-decoded records.
    ///
    /// Split out from [`Self::read`] so the ordering and family rules are
    /// testable without an Argon2id vault per case; it is private, so `read`
    /// remains the only way in and U47's "one reader" holds.
    fn assemble(records: Vec<(String, AnchorArtifact)>) -> Result<Self, JournalError> {
        let mut keyed = Vec::with_capacity(records.len());
        for (slot, artifact) in records {
            let family = SlotFamily::parse(&slot)
                .ok_or_else(|| corrupt("anchor slot name belongs to no known artifact family"))?;
            // The slot name lives outside the AEAD and the kind lives inside
            // it; U9's identity AAD stops a record being replayed into a
            // different slot, but nothing stops a *writer* putting the wrong
            // family in. Cheap to check, and it is the difference between a
            // TSA token counted as an OTS anchor and a refusal.
            if artifact.kind != family.kind() {
                return Err(corrupt("anchor slot family disagrees with the record kind"));
            }
            keyed.push((family, slot, artifact));
        }
        keyed.sort_by_key(|(family, _, _)| *family);
        let ots_len = keyed
            .iter()
            .filter(|(family, _, _)| matches!(family, SlotFamily::Ots))
            .count();
        Ok(Self {
            slots: keyed
                .into_iter()
                .map(|(_, slot, artifact)| (slot, artifact))
                .collect(),
            ots_len,
        })
    }

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

    /// Whether this work holds no anchor artifacts at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }

    /// How many artifacts, across both families.
    #[must_use]
    pub fn len(&self) -> usize {
        self.slots.len()
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
