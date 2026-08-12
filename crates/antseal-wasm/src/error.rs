//! What the boundary can refuse, and how it says so.
//!
//! # No code is minted here
//!
//! `docs/testing/error-code-contract.md` §3 makes the stable code universe
//! **append-only and frozen** (Q52), and every code in it belongs to a
//! rejection class `antseal-core` defines. This crate is a boundary, not a
//! verifier: it therefore **reuses** [`VerifyError::code`] verbatim for every
//! bundle rejection and mints nothing of its own. The binding's own failures
//! — a malformed online-evidence document, a report that is not UTF-8 — are
//! prose, deliberately code-shaped nowhere, so a reader cannot mistake one for
//! a member of the frozen universe.
//!
//! # What JS receives
//!
//! [`BindingError::message`] is what the boundary throws as a JS `Error`. For
//! a bundle rejection it is `"<code>: <display>"` — the same
//! code-in-the-message shape the CLI uses (D69 §7 row 8), so page JS and CLI
//! output name the same rejection with the same token.

use antseal_core::verify::VerifyError;
use antseal_core::verify::orchestration::{SiblingEncodeError, VerifyRunError};
use antseal_core::verify::overlay::OverlayEncodeError;

/// Everything the boundary can refuse to do.
///
/// Every variant is reachable from adversary-supplied input except
/// [`Self::Encode`] and [`Self::NotUtf8`], which are structurally unreachable
/// and typed anyway — library code returns errors, it does not unwrap.
#[derive(Debug, thiserror::Error)]
pub enum BindingError {
    /// The bundle did not pass verification. Carries `antseal-core`'s own
    /// error, so its frozen code survives the boundary unchanged.
    #[error(transparent)]
    Run(#[from] VerifyRunError),

    /// The online-evidence document page JS supplied could not be read.
    ///
    /// A page bug rather than a bundle verdict: the document is constructed by
    /// R24's fetch code, never by the user, so this never becomes a statement
    /// about the seal.
    #[error("the online-evidence document could not be read: {detail}")]
    OnlineEvidence {
        /// What was wrong with it. Never echoes the document.
        detail: String,
    },

    /// A canonical-JSON encoding failed. No input can reach this: the report,
    /// the overlay and the verdict datum have no map, no non-string key and no
    /// float.
    #[error("a verification document could not be encoded as canonical JSON")]
    Encode {
        /// Which document.
        document: &'static str,
    },

    /// Canonical JSON was not valid UTF-8. Structurally unreachable —
    /// `serde_json` emits UTF-8 — and typed rather than unwrapped.
    #[error("the {document} bytes are not valid UTF-8")]
    NotUtf8 {
        /// Which document.
        document: &'static str,
    },

    /// `--online` was requested and no overlay came back. Structurally
    /// unreachable: `VerifyOutcome::overlay` is `Some` exactly when the run
    /// asked for the layer, and this crate is the only caller that asks.
    #[error("the online run produced no overlay")]
    MissingOverlay,
}

impl BindingError {
    /// The message JS sees, with `antseal-core`'s frozen code in front of it
    /// whenever the failure is a bundle rejection.
    #[must_use]
    pub fn message(&self) -> String {
        match self.code() {
            Some(code) => format!("{code}: {self}"),
            None => self.to_string(),
        }
    }

    /// The frozen rejection code, when this failure is one.
    ///
    /// `None` is the honest answer for the binding's own failures: they are
    /// not members of the frozen universe and must never be spelled as if
    /// they were.
    #[must_use]
    pub fn code(&self) -> Option<&'static str> {
        match self {
            Self::Run(run) => run.verify_error().map(VerifyError::code),
            _ => None,
        }
    }
}

impl From<OverlayEncodeError> for BindingError {
    fn from(_: OverlayEncodeError) -> Self {
        Self::Encode {
            document: "the online overlay",
        }
    }
}

impl From<SiblingEncodeError> for BindingError {
    fn from(_: SiblingEncodeError) -> Self {
        Self::Encode {
            document: "the verdict datum",
        }
    }
}
