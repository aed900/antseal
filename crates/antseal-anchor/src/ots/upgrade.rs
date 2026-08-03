//! OTS upgrade polling, attestation merge and the upgrade-time header embed
//! (task **A14**; decisions D54, D56, D58 §7.4, D79, D90).
//!
//! # The discriminator is three-way and separated by BODY, not status code
//!
//! Falsified against live calendars rather than assumed (D58 §7.4, and
//! re-measured by this lane 2026-08-03):
//!
//! | response | meaning | action |
//! | --- | --- | --- |
//! | `200` + body | upgraded | merge the returned ops/attestations |
//! | `404` + `Pending confirmation in Bitcoin blockchain` (42 B) | known, not yet buried | re-poll later; **not** an error |
//! | `404` + `Not found` (9 B) | the calendar does not know this commitment | **hard** error; re-polling forever will not fix it |
//!
//! A client that maps 404 to failure reports every honest pending anchor as
//! broken; a client that maps 404 to "not ready" retries a lost submission
//! until the user gives up. The two cases are distinguishable **only** by the
//! body, which is why D90's substrate carries a non-2xx body instead of
//! collapsing it to a status.
//!
//! Two refinements this lane's own measurement forced:
//!
//! - the match is on **trimmed content**, never on length and never on a
//!   byte-exact literal. D90 measured the same body at 9 and 10 bytes from
//!   different calendars — one has a trailing newline — so a length test would
//!   classify one honest calendar as the other case;
//! - a fourth outcome exists and it is not a 404 at all. Polling
//!   `btc.calendar.catallaxy.com` with a corrupted commitment returned
//!   **nothing** (`http=000`, connection failed) where alice and bob returned
//!   the 9-byte body. A transport failure must stay [`UpgradePoll::Failed`] —
//!   advisory and re-pollable — and must never be promoted to the hard error,
//!   or one flaky endpoint permanently condemns an honest anchor. This is
//!   A16's lesson in a second place: a 404 is only meaningful when its body
//!   says so, and an absence of any answer says nothing at all.
//!
//! # Merging is a byte insertion, never a re-encode
//!
//! The upgrade response is a timestamp body rooted at the pending
//! attestation's commitment. Merging it means giving that attestation a
//! sibling — see [`super::container`] for why that is an insertion of
//! `0xff ‖ body` *before* the attestation and not a "fork" wrapped around it.
//! Every other byte of the stored artifact survives untouched, and the result
//! goes back through `parse_ots` before anything is recorded.
//!
//! Other calendars' pending attestations are retained: the insertion adds a
//! sibling and removes nothing, so a partially upgraded artifact carries a
//! Bitcoin attestation beside the pending attestations that have not caught up
//! — which is exactly the state A14's Accept row calls "representable and
//! re-pollable".
//!
//! # The header is fetched at upgrade time, through the must-agree pair
//!
//! Spec mandates the must-agree esplora pair only for `--online` verification.
//! Reusing it here is a deliberate hardening choice, recorded as A14's Notes
//! require: the alternative is trusting one endpoint for the 80 bytes that get
//! **embedded in every bundle for ever**, where a wrong header is not a failed
//! check but a permanently recorded falsehood.
//!
//! The recording is atomic. A merged artifact and its upgrade group are stored
//! together or not at all, so there is never a stored `.ots` carrying a
//! Bitcoin attestation whose header could not be confirmed. D79 makes the
//! group free-standing at the *parse* layer, which is a rule about what
//! decodes; it does not oblige this stage to produce half a transition.

use antseal_core::anchor::ots::{OtsArtifact, OtsAttestation, OtsError, header_commits, parse_ots};
use antseal_core::bundle::schema::OtsUpgrade;
use antseal_core::codec::caps::MAX_OTS_BYTES;

use super::calendars::{OTS_ACCEPT_HEADER, OTS_UPGRADE_PATH_PREFIX, join};
use super::container::{ContainerError, locate_pending, splice_sibling_before};
use super::upgrade_uri::{UpgradeUriRefusal, classify_upgrade_uri};
use crate::agree::{Agreement, EndpointPair};
use crate::esplora::{BlockHeader, fetch_agreed_header};
use crate::http::{
    AnchorHttpError, Endpoint, HttpClient, HttpMethod, HttpRequest, Idempotency, TlsPolicy,
};
use crate::ots::MAX_OTS_CALENDAR_RESPONSE_BYTES;

/// The `404` body that means "known, not yet buried". Compared as trimmed,
/// case-insensitive content.
pub const UPGRADE_PENDING_BODY: &str = "Pending confirmation in Bitcoin blockchain";

/// The `404` body that means "this calendar has never heard of this
/// commitment". Compared the same way.
pub const UPGRADE_NOT_FOUND_BODY: &str = "Not found";

/// A calendar base URI that has passed A42's allowlist.
///
/// Construction is the only way to obtain one, so an upgrade poll cannot be
/// issued against a URI read out of a stored artifact without the allowlist
/// having run. The artifact is attacker-writable under the vault-tamper threat
/// and the opportunistic hook fires on **every** CLI invocation, so an
/// unconstrained fetch here is a server-side request-forgery and
/// deanonymisation surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpgradeTarget {
    base: String,
}

impl UpgradeTarget {
    /// Admit a pending attestation's URI, or say which rule it broke.
    ///
    /// `configured` is the user's calendar list; each entry widens the
    /// allowlist to that host and its subdomains only.
    ///
    /// # Errors
    ///
    /// [`UpgradeUriRefusal`].
    pub fn from_pending_uri(uri: &str, configured: &[String]) -> Result<Self, UpgradeUriRefusal> {
        classify_upgrade_uri(uri, configured)?;
        Ok(Self {
            base: uri.trim().to_owned(),
        })
    }

    /// The admitted base URI.
    #[must_use]
    pub fn base(&self) -> &str {
        &self.base
    }

    /// A target pointing at a loopback stub, for this crate's own tests only.
    ///
    /// `#[cfg(test)]`, not a feature: A42's allowlist requires `https`, a bare
    /// host and no port, so a `http://127.0.0.1:<port>` stub can never be
    /// admitted through the real constructor — and it must not become
    /// admissible, since that carve-out would be reachable from a stored
    /// artifact. Keeping the escape hatch inside `cfg(test)` means it does not
    /// exist in any build that ships, and the refusal path is itself tested
    /// through the real constructor.
    #[cfg(test)]
    pub(crate) fn loopback_for_tests(base: &str) -> Self {
        Self {
            base: base.to_owned(),
        }
    }
}

/// What one upgrade poll produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpgradePoll {
    /// `200` — the body is a timestamp rooted at the polled commitment.
    Upgraded(Vec<u8>),
    /// `404` + the pending body. Not an error; poll again later.
    NotYetConfirmed,
    /// `404` + the not-found body. The submission was lost or the commitment
    /// was derived wrongly; further polling cannot help.
    NotFound,
    /// Anything else: transport failure, timeout, a 404 with an unrecognised
    /// body, a 5xx, an over-cap reply. Advisory and re-pollable — never
    /// promoted to [`Self::NotFound`].
    Failed(AnchorHttpError),
    /// A `200` with an empty body. Not a transport failure and not an
    /// upgrade: merging it would splice zero bytes and re-validate happily,
    /// recording a transition that did not happen.
    Empty,
}

impl UpgradePoll {
    /// Whether this outcome leaves the anchor worth polling again.
    #[must_use]
    pub const fn is_repollable(&self) -> bool {
        matches!(self, Self::NotYetConfirmed | Self::Failed(_) | Self::Empty)
    }
}

/// Poll one calendar for one commitment.
///
/// `GET <base>/timestamp/<lowercase-hex commitment>` — D54 §6.1's path, and
/// the exchange D58 §7.4 measured.
#[must_use]
pub fn poll_upgrade(client: &HttpClient, target: &UpgradeTarget, commitment: &[u8]) -> UpgradePoll {
    let url = join(
        target.base(),
        &format!("{OTS_UPGRADE_PATH_PREFIX}{}", hex_lower(commitment)),
    );
    // Re-validated as a URL in its own right rather than assumed to be one,
    // and under the loopback-carve-out policy so the stubs work while a
    // plain-HTTP public calendar cannot be reached: the reply is unsigned, so
    // transport is its only integrity control.
    let endpoint = match Endpoint::parse(&url, TlsPolicy::RequiredExceptLoopback) {
        Ok(endpoint) => endpoint,
        Err(error) => return UpgradePoll::Failed(error.into()),
    };

    let request = HttpRequest {
        endpoint: &endpoint,
        method: HttpMethod::Get,
        content_type: None,
        accept: Some(OTS_ACCEPT_HEADER),
        body: &[],
        receive_cap_bytes: MAX_OTS_CALENDAR_RESPONSE_BYTES,
        // A read: repeating it has no server-side effect, so both pre-send and
        // ambiguous failures may be retried.
        idempotency: Idempotency::SafeToRepeat,
    };

    match client.send(&request) {
        Ok(response) if response.body.is_empty() => UpgradePoll::Empty,
        Ok(response) => UpgradePoll::Upgraded(response.body),
        Err(AnchorHttpError::Status { status, body, .. }) if status == 404 => {
            match classify_404(&body) {
                Some(poll) => poll,
                // A 404 that says neither thing is neither thing. The status
                // and the body are both carried forward, so a calendar that
                // grows a third message is diagnosable rather than silently
                // sorted into one of the two known arms.
                None => UpgradePoll::Failed(AnchorHttpError::Status {
                    endpoint: endpoint.url().to_owned(),
                    status,
                    body,
                }),
            }
        }
        Err(error) => UpgradePoll::Failed(error),
    }
}

/// Which of the two known 404 bodies this is, if either.
///
/// Trimmed and case-insensitive, never by length. `None` means "a 404 that
/// says neither thing", which is an endpoint failure and refutes nothing.
fn classify_404(body: &[u8]) -> Option<UpgradePoll> {
    let text = core::str::from_utf8(body).ok()?.trim();
    if text.eq_ignore_ascii_case(UPGRADE_PENDING_BODY) {
        return Some(UpgradePoll::NotYetConfirmed);
    }
    if text.eq_ignore_ascii_case(UPGRADE_NOT_FOUND_BODY) {
        return Some(UpgradePoll::NotFound);
    }
    None
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('0'));
        out.push(char::from_digit(u32::from(byte & 0x0f), 16).unwrap_or('0'));
    }
    out
}

/// One pending attestation of a stored artifact, addressed well enough to
/// splice beside it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingRef {
    /// The URI the attestation names.
    pub uri: String,
    /// The ops-derived commitment to poll with.
    pub commitment: Vec<u8>,
    /// Which attestation naming this URI, in document order. Non-zero only
    /// when one calendar appears in the artifact more than once — which D54's
    /// aggregator aliases make reachable.
    pub occurrence: usize,
    /// How many pending attestations name this URI, for the count agreement
    /// [`locate_pending`] requires.
    pub siblings: usize,
}

/// Every upgradeable pending attestation in a stored artifact.
///
/// An attestation whose commitment is indeterminate is skipped: there is no
/// value to put in an upgrade URL, so it can never be polled.
///
/// # Errors
///
/// [`OtsError`] if the stored artifact does not parse against `anchor_digest`.
pub fn pending_refs(stored: &[u8], anchor_digest: &[u8; 32]) -> Result<Vec<PendingRef>, OtsError> {
    let artifact = parse_ots(stored, anchor_digest)?;
    let mut refs: Vec<PendingRef> = Vec::new();
    for attestation in &artifact.attestations {
        let OtsAttestation::Pending { uri, commitment } = attestation else {
            continue;
        };
        // Counted over ALL pending attestations naming this URI, including
        // indeterminate ones: the byte search finds their encodings too, so
        // the count agreement has to be over the same population.
        let siblings = artifact
            .attestations
            .iter()
            .filter(|other| matches!(other, OtsAttestation::Pending { uri: u, .. } if u == uri))
            .count();
        let occurrence = refs.iter().filter(|other| other.uri == *uri).count();
        if let Some(commitment) = commitment {
            refs.push(PendingRef {
                uri: uri.clone(),
                commitment: commitment.clone(),
                occurrence,
                siblings,
            });
        }
    }
    Ok(refs)
}

/// Why a merge was refused. Every arm leaves the stored artifact untouched.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum MergeError {
    /// The stored artifact does not parse. Nothing can be spliced into a file
    /// this codec does not accept.
    #[error("the stored artifact does not parse: {0}")]
    StoredUnparseable(OtsError),
    /// The pending attestation could not be placed in the byte stream.
    #[error(transparent)]
    Container(#[from] ContainerError),
    /// The spliced result does not parse.
    #[error("the merged artifact does not parse: {0}")]
    MergedUnparseable(OtsError),
    /// An attestation that was in the stored artifact is not in the merged
    /// one. A pure insertion cannot do this, so it means the splice landed
    /// somewhere it should not have.
    #[error("the merge lost an attestation that the stored artifact carried")]
    LostAttestation,
    /// The upgrade added no Bitcoin attestation with a determinate merkle
    /// root — so it is not an upgrade, whatever the calendar called it.
    #[error("the upgrade response added no usable Bitcoin attestation")]
    NoBitcoinAttestation,
}

/// A merged artifact, and what the upgrade added.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MergedUpgrade {
    /// The new artifact bytes.
    pub artifact: Vec<u8>,
    /// Bitcoin attestations the merge introduced, in document order.
    pub added: Vec<OtsAttestation>,
}

/// Splice `body` in beside the pending attestation `target` names, and
/// re-validate the result.
///
/// # Errors
///
/// [`MergeError`]. On any of them the caller's stored bytes are unchanged —
/// this function never edits in place.
pub fn merge_upgrade(
    stored: &[u8],
    anchor_digest: &[u8; 32],
    target: &PendingRef,
    body: &[u8],
) -> Result<MergedUpgrade, MergeError> {
    let before = parse_ots(stored, anchor_digest).map_err(MergeError::StoredUnparseable)?;

    let offset = locate_pending(stored, &target.uri, target.occurrence, target.siblings)?;
    let merged = splice_sibling_before(stored, offset, body, MAX_OTS_BYTES)?;

    // A11 is the authority on the result, and it runs over the whole file:
    // every limit, the digest commitment, and trailing-byte strictness all
    // apply to the calendar's bytes now that they are part of our artifact.
    let after = parse_ots(&merged, anchor_digest).map_err(MergeError::MergedUnparseable)?;

    // Nothing may be lost. A pure insertion cannot drop an attestation, so a
    // failure here means the splice landed in the wrong place and the file
    // re-parsed into something else that happens to be well-formed.
    if !retains_all(&before, &after) {
        return Err(MergeError::LostAttestation);
    }

    let added = added_bitcoin(&before, &after);
    if added.is_empty() {
        return Err(MergeError::NoBitcoinAttestation);
    }
    Ok(MergedUpgrade {
        artifact: merged,
        added,
    })
}

/// Is every attestation of `before` still present in `after`, with
/// multiplicity?
///
/// `OtsAttestation` is `PartialEq` but not `Ord`/`Hash`, and the counts are
/// bounded by `MAX_OTS_ATTESTATIONS`, so a quadratic containment check is the
/// honest one rather than a sort that would need an ordering this type has no
/// business defining.
fn retains_all(before: &OtsArtifact, after: &OtsArtifact) -> bool {
    let mut remaining: Vec<&OtsAttestation> = after.attestations.iter().collect();
    for attestation in &before.attestations {
        match remaining.iter().position(|other| *other == attestation) {
            Some(index) => {
                remaining.swap_remove(index);
            }
            None => return false,
        }
    }
    true
}

/// Bitcoin attestations in `after` beyond those already in `before`, keeping
/// only the ones whose merkle root the ops actually derived.
fn added_bitcoin(before: &OtsArtifact, after: &OtsArtifact) -> Vec<OtsAttestation> {
    let mut old: Vec<&OtsAttestation> = before.attestations.iter().collect();
    let mut added = Vec::new();
    for attestation in &after.attestations {
        if let Some(index) = old.iter().position(|other| *other == attestation) {
            old.swap_remove(index);
            continue;
        }
        if matches!(
            attestation,
            OtsAttestation::Bitcoin {
                merkle_root: Some(_),
                ..
            }
        ) {
            added.push(attestation.clone());
        }
    }
    added
}

/// Why an upgrade could not be recorded even though the merge succeeded.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum HeaderError {
    /// The two esplora endpoints disagreed, or one of them could not be
    /// reached. Advisory: try again later.
    #[error("the block header for height {height} could not be agreed by two endpoints")]
    NotAgreed {
        /// The height that was asked about.
        height: u64,
    },
    /// Both endpoints agree the height holds no block. The attestation claims
    /// a block that is not there.
    #[error("both endpoints report no block at height {height}")]
    NoSuchBlock {
        /// The height that was asked about.
        height: u64,
    },
    /// The agreed header's merkle root is not the one the ops derive.
    ///
    /// **This is the check that stops a wrong header being written.** The
    /// merged artifact is discarded with it: an 80-byte header is embedded in
    /// every bundle for ever, so a mismatch here is not a failed check but a
    /// falsehood that was about to become permanent.
    #[error("the agreed header for height {height} does not commit the attestation")]
    HeaderDoesNotCommit {
        /// The height that was asked about.
        height: u64,
    },
}

/// Fetch and check the header for an added Bitcoin attestation.
///
/// `fetch_date` is supplied by the caller (POSIX seconds UTC) rather than read
/// from the clock here, so the whole path is testable without one.
///
/// # Errors
///
/// [`HeaderError`]. The caller must discard the merged artifact on every one
/// of them — the transition is atomic.
pub fn confirm_header(
    client: &HttpClient,
    pair: &EndpointPair,
    attestation: &OtsAttestation,
    fetch_date: u64,
) -> Result<OtsUpgrade, HeaderError> {
    let OtsAttestation::Bitcoin { height, .. } = attestation else {
        // Only a Bitcoin attestation has a height; `merge_upgrade` only ever
        // yields those. Treated as "not agreed" rather than panicking, because
        // this crate returns errors on adversarial input and never unwraps.
        return Err(HeaderError::NotAgreed { height: 0 });
    };
    let height = *height;

    let header: BlockHeader = match fetch_agreed_header(client, pair, height) {
        Agreement::Agreed(Some(header)) => header,
        Agreement::Agreed(None) => return Err(HeaderError::NoSuchBlock { height }),
        Agreement::Disagreed { .. } | Agreement::Unavailable { .. } => {
            return Err(HeaderError::NotAgreed { height });
        }
    };

    let upgrade = OtsUpgrade::new(height, header, fetch_date);
    // A12's own predicate, over A11's own attestation type — the same function
    // the verifier will run offline against the embedded bytes. Checking with
    // a different comparison here is how a bundle comes to fail its own
    // verifier.
    if !header_commits(attestation, &upgrade) {
        return Err(HeaderError::HeaderDoesNotCommit { height });
    }
    Ok(upgrade)
}

#[cfg(test)]
mod tests;
