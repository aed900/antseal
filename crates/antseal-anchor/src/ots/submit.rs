//! The OpenTimestamps calendar submission client (task **A13**; decisions
//! D54, D58 §7.3, D90).
//!
//! # Success is counted in distinct calendars, not in HTTP 200s
//!
//! D54's defaults are four **aggregator aliases**, and an aggregator is a thin
//! front for one calendar. Two aliases can therefore front the same calendar,
//! and two `200`s can be one piece of evidence. The count that decides
//! [`OtsSubmitOutcome`] is over distinct normalised **pending-attestation
//! URIs** — what the calendars said about themselves — never over the URLs
//! this code posted to.
//!
//! # No OTS outcome ever fails a seal, and none is silent
//!
//! A20's gate is TSA-only (D54 §3). At seal time an OTS anchor is `pending`,
//! and `pending` is not headline-eligible, so gating a paid irreversible seal
//! on it would trade a permanent cost for zero evidentiary gain. What OTS
//! failure *does* produce is a degradation report naming every failed endpoint
//! verbatim, with its failure class and its elapsed time
//! ([`OtsSubmission::degradation_report`]) — spec line 189's "loudly, never
//! silently".
//!
//! # Per-calendar validation, for per-calendar attribution
//!
//! Each response is validated **on its own**, by wrapping it in a container
//! header and running it through `parse_ots` against `anchor_digest`. A
//! one-branch container is a legal `.ots`, so this is the real parser and not
//! an approximation of it — and a calendar that returns something that is not
//! a timestamp over our digest is recorded as *that calendar's* failure
//! instead of poisoning the merge and losing which endpoint was at fault.

use std::time::{Duration, Instant};

use antseal_core::anchor::ots::{OtsAttestation, OtsError, parse_ots};
use antseal_core::codec::caps::MAX_OTS_BYTES;

use super::calendars::{
    OTS_ACCEPT_HEADER, OTS_MIN_DISTINCT_CALENDARS, OTS_SUBMIT_CONTENT_TYPE, OTS_SUBMIT_PATH, join,
};
use super::container::assemble;
use crate::http::{
    AnchorHttpError, Endpoint, HttpClient, HttpMethod, HttpRequest, Idempotency, TlsPolicy,
};
use crate::ots::MAX_OTS_CALENDAR_RESPONSE_BYTES;

/// Why one calendar contributed nothing.
///
/// Four classes, because they call for four different responses from a human:
/// a transport failure is retryable, an unparseable body is that calendar
/// misbehaving, and the last two mean the calendar answered about something
/// other than what was asked.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CalendarFailure {
    /// Transport, timeout, non-2xx, over-cap. Carries the endpoint URL.
    #[error(transparent)]
    Http(#[from] AnchorHttpError),
    /// A 2xx body that is not a timestamp over this `anchor_digest`.
    ///
    /// Includes the case that matters most: a calendar whose response commits
    /// a *different* digest fails here, because the digest-commitment check
    /// lives inside `parse_ots` and takes `anchor_digest` as a parameter.
    #[error("{calendar}: the response is not a timestamp over this digest ({source})")]
    Artifact {
        /// The calendar's submit URL.
        calendar: String,
        /// What the codec said.
        source: OtsError,
    },
    /// A timestamp with no pending attestation at all — nothing to poll later.
    #[error("{calendar}: the response carries no pending attestation")]
    NoPending {
        /// The calendar's submit URL.
        calendar: String,
    },
    /// A pending attestation whose commitment is indeterminate, because the
    /// path to it crossed an op this verifier does not implement. There is no
    /// value to put in an upgrade URL, so the attestation can never be
    /// upgraded and recording it would be recording a dead end.
    #[error("{calendar}: the pending attestation's commitment is indeterminate")]
    IndeterminateCommitment {
        /// The calendar's submit URL.
        calendar: String,
    },
}

impl CalendarFailure {
    /// A one-word class name for the degradation report.
    #[must_use]
    pub const fn class(&self) -> &'static str {
        match self {
            Self::Http(_) => "http",
            Self::Artifact { .. } => "unparseable",
            Self::NoPending { .. } => "no-pending-attestation",
            Self::IndeterminateCommitment { .. } => "indeterminate-commitment",
        }
    }
}

/// One calendar's pending attestation, as accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingRecord {
    /// The submit URL this project posted to.
    pub calendar: String,
    /// The URI the **attestation** names — the host A14 polls, and the key
    /// distinct-success counting dedupes on.
    pub uri: String,
    /// The ops-derived commitment, hex-encoded into the upgrade URL by A14.
    /// Measured 44 bytes for all six A25 captures.
    pub commitment: Vec<u8>,
    /// The response bytes, verbatim, as merged into the artifact.
    pub body: Vec<u8>,
}

/// One calendar attempt, successful or not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CalendarAttempt {
    /// The submit URL.
    pub calendar: String,
    /// How long this endpoint took, independently of the others.
    pub elapsed: Duration,
    /// What it produced.
    pub outcome: Result<PendingRecord, CalendarFailure>,
}

/// D54 §3's three-row outcome table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OtsSubmitOutcome {
    /// ≥ [`OTS_MIN_DISTINCT_CALENDARS`] distinct calendars. Normal.
    Complete,
    /// Exactly one distinct calendar. Proceed, with a degradation note.
    Thin,
    /// No usable pending attestation. Proceed; the anchor set carries no OTS
    /// artifact.
    Absent,
}

/// Everything the submission stage produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OtsSubmission {
    /// The digest every attestation commits.
    pub anchor_digest: [u8; 32],
    /// Per-calendar attempts, in the order the calendars were given.
    pub attempts: Vec<CalendarAttempt>,
    /// The merged `.ots`, when at least one calendar succeeded and the merge
    /// re-validated. This is the artifact the vault stores and F embeds.
    pub artifact: Option<Vec<u8>>,
    /// Set when calendars succeeded but their merge did **not** re-validate.
    ///
    /// A separate field rather than a silent `artifact: None`, because the two
    /// mean different things: no calendar answered, against calendars answered
    /// and this code built something the codec rejects. The second is a bug
    /// here and must be visible as one.
    pub merge_rejected: Option<OtsError>,
}

impl OtsSubmission {
    /// The accepted pending attestations.
    pub fn pending(&self) -> impl Iterator<Item = &PendingRecord> {
        self.attempts
            .iter()
            .filter_map(|attempt| attempt.outcome.as_ref().ok())
    }

    /// Distinct normalised pending-attestation URIs — D54's counting rule.
    #[must_use]
    pub fn distinct_calendars(&self) -> usize {
        let mut seen: Vec<String> = Vec::new();
        for record in self.pending() {
            let key = normalise_uri(&record.uri);
            if !seen.contains(&key) {
                seen.push(key);
            }
        }
        seen.len()
    }

    /// D54 §3's outcome.
    #[must_use]
    pub fn outcome(&self) -> OtsSubmitOutcome {
        if self.artifact.is_none() {
            return OtsSubmitOutcome::Absent;
        }
        match self.distinct_calendars() {
            0 => OtsSubmitOutcome::Absent,
            n if n >= OTS_MIN_DISTINCT_CALENDARS => OtsSubmitOutcome::Complete,
            _ => OtsSubmitOutcome::Thin,
        }
    }

    /// One line per failed endpoint: **the URL verbatim**, its failure class,
    /// the underlying message, and its elapsed time.
    ///
    /// Verbatim is the requirement, not a preference (D54 §8): a summarising
    /// "1 calendar failed" is what this exists to make impossible, because the
    /// operator's next action is to look at *that URL*.
    #[must_use]
    pub fn degradation_report(&self) -> Vec<String> {
        self.attempts
            .iter()
            .filter_map(|attempt| {
                attempt.outcome.as_ref().err().map(|failure| {
                    format!(
                        "{} [{}] {} ({} ms)",
                        attempt.calendar,
                        failure.class(),
                        failure,
                        attempt.elapsed.as_millis()
                    )
                })
            })
            .collect()
    }
}

/// Submit `anchor_digest` to every calendar in `calendars`, concurrently, and
/// merge the pending attestations into one stored `.ots`.
///
/// # Concurrency
///
/// `std::thread::scope`, so one calendar's timeout delays only itself — D54's
/// "submit to all four concurrently" and A13's "per-calendar failures are
/// independent". This mirrors [`crate::agree::fetch_and_agree`]'s shape
/// deliberately: **A51** will hoist one shared fan-out for A10/A13/A16/A17,
/// and when it lands only this block changes.
///
/// # Wall clock
///
/// D54 §3 bounds the stage at [`OTS_SUBMIT_DEADLINE_SECS`] = 30 s. On D90's
/// substrate the achievable bound is the **per-endpoint** one, since endpoints
/// run concurrently: 3 attempts × 10 s + 0.8 s backoff = **30.8 s**. The two
/// figures differ by 0.8 s and neither is expressible in terms of the other —
/// the substrate offers no per-call deadline, and a check between retries
/// would have to live inside `HttpClient::send`. Recorded rather than papered
/// over; see the lane's discovered work.
///
/// [`OTS_SUBMIT_DEADLINE_SECS`]: super::calendars::OTS_SUBMIT_DEADLINE_SECS
#[must_use]
pub fn submit_to_calendars(
    client: &HttpClient,
    anchor_digest: &[u8; 32],
    calendars: &[String],
) -> OtsSubmission {
    let attempts: Vec<CalendarAttempt> = std::thread::scope(|scope| {
        let handles: Vec<_> = calendars
            .iter()
            .map(|calendar| scope.spawn(move || submit_one(client, anchor_digest, calendar)))
            .collect();
        handles
            .into_iter()
            .map(|handle| match handle.join() {
                Ok(attempt) => attempt,
                // A panic here is a bug in this crate, never an endpoint
                // failure: laundering it into a `CalendarFailure` would make a
                // broken parser look like a dead calendar.
                Err(panic) => std::panic::resume_unwind(panic),
            })
            .collect()
    });

    let mut submission = OtsSubmission {
        anchor_digest: *anchor_digest,
        attempts,
        artifact: None,
        merge_rejected: None,
    };

    // Deterministic branch order (D58 §7.3's first rider): sort by the
    // response bytes, so two seals of one digest at one calendar set produce
    // one file. Sorting by the URL we posted to would not do — an aggregator
    // alias can change which calendar answers.
    let mut branches: Vec<Vec<u8>> = submission
        .pending()
        .map(|record| record.body.clone())
        .collect();
    if branches.is_empty() {
        return submission;
    }
    branches.sort_unstable();

    let merged = assemble(anchor_digest, &branches);
    // A28's constraint, checked here rather than at bundle build: a stored
    // artifact that cannot be embedded is a seal that anchored and then could
    // not be revealed.
    if merged.len() as u64 > MAX_OTS_BYTES {
        submission.merge_rejected = None;
        return submission;
    }
    match parse_ots(&merged, anchor_digest) {
        Ok(_) => submission.artifact = Some(merged),
        Err(error) => submission.merge_rejected = Some(error),
    }
    submission
}

/// One calendar: POST the 32 raw digest bytes, then validate the reply alone.
fn submit_one(
    client: &HttpClient,
    anchor_digest: &[u8; 32],
    calendar: &str,
) -> CalendarAttempt {
    let started = Instant::now();
    let outcome = submit_and_validate(client, anchor_digest, calendar);
    CalendarAttempt {
        calendar: calendar.to_owned(),
        elapsed: started.elapsed(),
        outcome,
    }
}

fn submit_and_validate(
    client: &HttpClient,
    anchor_digest: &[u8; 32],
    calendar: &str,
) -> Result<PendingRecord, CalendarFailure> {
    let url = join(calendar, OTS_SUBMIT_PATH);
    // `TlsPolicy::Optional`, matching D90's `HttpPolicy::seal()` profile for
    // this family. All four D54 defaults are https; the carve-out exists for
    // the loopback stubs and for a user's private calendar. Note the
    // deliberate asymmetry with A42, which requires https on the *upgrade*
    // URI: that URI comes out of an attacker-writable artifact, this one comes
    // out of config.
    let endpoint = Endpoint::parse(&url, TlsPolicy::Optional)
        .map_err(|error| CalendarFailure::Http(error.into()))?;

    let request = HttpRequest {
        endpoint: &endpoint,
        method: HttpMethod::Post,
        content_type: Some(OTS_SUBMIT_CONTENT_TYPE),
        accept: Some(OTS_ACCEPT_HEADER),
        body: anchor_digest.as_slice(),
        receive_cap_bytes: MAX_OTS_CALENDAR_RESPONSE_BYTES,
        // The one request in this module that may create a server-side effect
        // twice. A pre-send failure is retried; anything that might have been
        // delivered is not — which is why D90's phase placement had to be
        // derived from ureq's predecessor graph rather than from phase names.
        idempotency: Idempotency::AtMostOnceAfterSend,
    };
    let body = client.send(&request).map_err(CalendarFailure::Http)?.body;

    // Validated as a one-branch container: a real `.ots`, through the real
    // parser, against the real digest.
    let single = assemble(anchor_digest, std::slice::from_ref(&body));
    let artifact =
        parse_ots(&single, anchor_digest).map_err(|source| CalendarFailure::Artifact {
            calendar: calendar.to_owned(),
            source,
        })?;

    let mut indeterminate = false;
    for attestation in &artifact.attestations {
        if let OtsAttestation::Pending { uri, commitment } = attestation {
            match commitment {
                Some(commitment) => {
                    return Ok(PendingRecord {
                        calendar: calendar.to_owned(),
                        uri: uri.clone(),
                        commitment: commitment.clone(),
                        body,
                    });
                }
                None => indeterminate = true,
            }
        }
    }
    if indeterminate {
        return Err(CalendarFailure::IndeterminateCommitment {
            calendar: calendar.to_owned(),
        });
    }
    Err(CalendarFailure::NoPending {
        calendar: calendar.to_owned(),
    })
}

/// Normalise a pending URI for distinct-success counting.
///
/// Scheme and host are case-insensitive; anything after the authority is not.
/// A whole-string `to_lowercase` would be wrong on a path, and real calendars
/// emit a bare host — but the counting rule must not depend on that.
#[must_use]
pub fn normalise_uri(uri: &str) -> String {
    let trimmed = uri.trim().trim_end_matches('/');
    let Some((scheme, rest)) = trimmed.split_once("://") else {
        return trimmed.to_ascii_lowercase();
    };
    let (authority, path) = match rest.find('/') {
        Some(index) => rest.split_at(index),
        None => (rest, ""),
    };
    format!(
        "{}://{}{path}",
        scheme.to_ascii_lowercase(),
        authority.to_ascii_lowercase()
    )
}

#[cfg(test)]
mod tests;
