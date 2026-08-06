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
//! chosen so a slot listing is self-describing without decrypting anything:
//! `ots-pending` for the merged artifact, `tsa-<n>` for the n-th **verified**
//! capture in endpoint order. Only verified captures are stored: an
//! unverifiable token is evidence of nothing, and keeping it would put bytes
//! in the vault that no consumer may ever act on.
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
use antseal_anchor::submit::AnchorSubmission;
use antseal_core::codec::{CanonicalDecoder, encode_item};

use super::journal::{JournalError, codec, corrupt, envelope, open_envelope};

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
}

impl AnchorArtifact {
    /// Encode to the versioned canonical-CBOR record bytes.
    ///
    /// # Errors
    ///
    /// [`JournalError::Encode`] — unreachable for well-formed records, but
    /// returned rather than panicked (library discipline).
    pub fn encode(&self) -> Result<Vec<u8>, JournalError> {
        let body = encode_item(|e| {
            e.map(|m| {
                m.entry(0, |e| e.u64(self.kind.as_wire()))?;
                m.entry(1, |e| e.str(&self.endpoint))?;
                m.entry(2, |e| e.u64(self.fetch_date))?;
                m.entry(3, |e| e.bytes(&self.bytes))
            })
        })
        .map_err(|_| JournalError::Encode)?;
        envelope(&body)
    }

    /// Parse an anchor-artifact record defensively.
    ///
    /// # Errors
    ///
    /// [`JournalError::NewerRecord`] for a future schema version;
    /// [`JournalError::Corrupt`] for every malformed shape — including an
    /// unregistered kind tag, which is refused rather than defaulted.
    pub fn decode(bytes: &[u8]) -> Result<Self, JournalError> {
        let body = open_envelope(bytes)?;
        let mut d = CanonicalDecoder::new(body);
        let mut map = d.map().map_err(codec)?;

        let mut kind: Option<u64> = None;
        let mut endpoint: Option<String> = None;
        let mut fetch_date: Option<u64> = None;
        let mut artifact: Option<Vec<u8>> = None;

        while let Some(key) = map.next_key(&mut d).map_err(codec)? {
            match key {
                0 => kind = Some(d.u64().map_err(codec)?),
                1 => endpoint = Some(d.str().map_err(codec)?.to_owned()),
                2 => fetch_date = Some(d.u64().map_err(codec)?),
                3 => artifact = Some(d.bytes().map_err(codec)?.to_vec()),
                _ => return Err(corrupt("unknown anchor-artifact key (strict v1 schema)")),
            }
        }
        d.finish().map_err(codec)?;

        Ok(Self {
            kind: ArtifactKind::from_wire(kind.ok_or_else(|| corrupt("artifact kind missing"))?)
                .ok_or_else(|| corrupt("unregistered anchor-artifact kind"))?,
            endpoint: endpoint.ok_or_else(|| corrupt("artifact endpoint missing"))?,
            fetch_date: fetch_date.ok_or_else(|| corrupt("artifact fetch date missing"))?,
            bytes: artifact.ok_or_else(|| corrupt("artifact bytes missing"))?,
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
            },
        ));
    }
    out
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
