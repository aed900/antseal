//! Canonicalization (MVP-SPEC.md "Canonicalization (v1)", lines 81–85).
//!
//! Text files get a canonical rendition — UTF-8, NFC-normalized, LF line
//! endings, no BOM — and every hash over text content is computed over those
//! canonical bytes. NFC output depends on the Unicode data version, so that
//! version is frozen per seal into the per-file canonicalization descriptor,
//! and a verifier recomputing canonicalization applies the
//! *descriptor-recorded* version, never "latest" (spec line 83).
//!
//! Module layout:
//!
//! - [`unicode`] (G1, decision D25): the pinned Unicode/NFC data-version
//!   registry and the registry-routed NFC entry point. This is the version
//!   substrate everything else dispatches through.
//! - The pipeline (G2, decisions D20 + D21), re-exported here:
//!   [`canonicalize_v`] / [`canonicalize`] run the frozen five-stage
//!   transform — decode (strict for detected text, lossy U+FFFD for forced
//!   text), strip of **all** leading U+FEFF scalars, one-pass CRLF /
//!   lone-CR → LF, version-dispatched NFC, UTF-8 encode with no BOM —
//!   yielding an invariant-carrying [`CanonicalBytes`]; [`is_text`] is the
//!   strict-UTF-8 detection predicate and [`TextMode`] selects the
//!   detected/forced decode. This is the exact function the verifier's
//!   raw-mirror binding check recomputes (spec line 121).

pub mod unicode;

mod pipeline;

pub use pipeline::{
    CanonicalBytes, CanonicalizeError, TextMode, canonicalize, canonicalize_v, is_text,
};
pub use unicode::{UNICODE_17_0_0, UnicodeVersion, UnicodeVersionError};
