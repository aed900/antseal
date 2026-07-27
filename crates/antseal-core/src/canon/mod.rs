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
//! - The canonicalization pipeline `canonicalize_v` — text detection, single
//!   leading-BOM strip, CRLF / lone-CR → LF, version-dispatched NFC, UTF-8
//!   encode — lands here with G2 and builds on [`unicode`].

pub mod unicode;

pub use unicode::{UnicodeVersion, UnicodeVersionError};
