//! The consent hook (D34 Decision 2: defined here beside the pipeline;
//! U14's interactive gate and the test doubles implement it).
//!
//! # Consent is a single-use spend authorization (D36 rule 2)
//!
//! There is **no `pay()` without an affirmative consent obtained in the
//! same process invocation, rendered against the fresh quote that same
//! invocation just fetched.** No consent crosses a process boundary for
//! the purpose of authorizing payment. That is one rule, and every case is
//! a corollary of it rather than a special case:
//!
//! - initial seal: quote → consent → anchor gate → pay;
//! - pre-pay resume: re-quote → re-consent → pay (the former "re-consent
//!   only if the cost changed" conditional is overturned — a journaled
//!   quote is never paid, so there is nothing to compare against that
//!   could authorize a spend);
//! - post-receipt resume: no `pay()` happens, so no prompt happens — the
//!   vacuous case, not an exemption;
//! - D37's proofs-expired state: completing the seal needs a *new*
//!   payment, therefore a fresh in-invocation consent.
//!
//! # "Changed" is display-level only
//!
//! Nothing gates on comparing the fresh quote to a prior one. The render
//! shows [`ConsentRequest::prior`] — the last journaled
//! [`ConsentRecord`] — so a user can see that the price moved, in either
//! direction. Absent prior record ⇒ render without that line; it is never
//! a reason to refuse.

use antseal_core::crypto::secrets::SealId;
use antseal_net::CostQuote;

use crate::error::{CliError, ConsentOutcome};
use crate::vault::store::{ConsentChannel, ConsentRecord};

/// What the user is being asked to authorize.
#[derive(Debug)]
pub struct ConsentRequest<'a> {
    /// The work being sealed.
    pub seal_id: SealId,
    /// The **fresh** quote this invocation just fetched — the exact object
    /// that will be handed to `pay()` if consent is granted (D36's
    /// pay-argument identity rule).
    pub quote: &'a CostQuote,
    /// How many blobs the quote covers (units + the encrypted manifest).
    pub blob_count: usize,
    /// The last journaled consent, for the prior-totals display (D36 rule
    /// 4). Display only — nothing gates on it.
    pub prior: Option<ConsentRecord>,
    /// Whether this is a resumed invocation rather than a fresh seal.
    pub resume: bool,
    /// Whether this consent is being asked because the journaled payment
    /// proofs expired (D37): the previous payment is stranded and *not*
    /// recoverable, and granting authorizes a second, additional spend.
    /// The render must say so.
    pub proofs_expired: bool,
}

/// The gate's answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsentDecision {
    /// Affirmative. The pipeline journals a [`ConsentRecord`] built from
    /// these fields and the quote, then pays.
    Granted {
        /// Which channel affirmed (interactive prompt or `--yes`).
        channel: ConsentChannel,
        /// When, in Unix seconds. Injected rather than read from a clock,
        /// so the pipeline stays deterministic under test.
        at_unix_secs: u64,
    },
    /// Not affirmative. **Never abandonment** (D36 rule 3): the work stays
    /// exactly where it was, resumable at whatever the market later
    /// quotes, and no state transition is written.
    Declined(ConsentOutcome),
}

/// The injected consent gate.
pub trait ConsentHook {
    /// Render the request and obtain an answer.
    ///
    /// # Errors
    ///
    /// [`CliError`] when the *channel itself* fails (no TTY and no
    /// `--yes`, a terminal read error). A refusal is not an error — it is
    /// [`ConsentDecision::Declined`], because "the user said no" and "the
    /// prompt broke" are different facts that lead to different messages.
    fn confirm(&self, request: &ConsentRequest<'_>) -> Result<ConsentDecision, CliError>;
}

/// Build the journaled [`ConsentRecord`] from an affirmative decision and
/// the quote it was rendered against (D36's field set).
#[must_use]
pub fn consent_record(
    quote: &CostQuote,
    channel: ConsentChannel,
    at_unix_secs: u64,
) -> ConsentRecord {
    ConsentRecord {
        total_ant_atto: quote.total_ant_atto,
        gas_estimate_wei: quote.gas_estimate_wei,
        consent_time_unix_secs: at_unix_secs,
        channel,
    }
}
