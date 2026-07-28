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
//!
//! # Error codes
//!
//! Both failure classes carry `content-`-prefixed stable codes
//! ([`CanonicalizeError::code`], [`UnicodeVersionError::code`]) so they can
//! be pinned by tamper rows and surfaced unchanged through R's
//! `VerifyError::Canon` wrapper arm (decision D30,
//! `docs/testing/error-code-contract.md` §2). `canon_code_exemplars` below
//! is the family's exemplar list; the meta-test asserts distinctness within
//! the family *and* against every `content::ContentError` code, because both
//! families share the `content-` prefix.

pub mod unicode;

mod pipeline;

pub use pipeline::{
    CanonicalBytes, CanonicalizeError, TextMode, canonicalize, canonicalize_forced, canonicalize_v,
    canonicalize_v_forced, is_text,
};
pub use unicode::{UNICODE_17_0_0, UnicodeVersion, UnicodeVersionError};

/// One exemplar per distinct [`CanonicalizeError::code`] — every variant of
/// the canonicalization family exactly once (the `content::error` and
/// `crypto::error` exemplar-list precedent).
#[cfg(test)]
pub(crate) fn canon_code_exemplars() -> Vec<CanonicalizeError> {
    vec![
        CanonicalizeError::UnknownVersion(UnicodeVersionError::UnknownUnicodeVersion {
            requested: "unicode-99.0.0".to_owned(),
        }),
        CanonicalizeError::InvalidUtf8 {
            valid_up_to: 5,
            error_len: Some(1),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    /// Distinctness meta-test for the canonicalization slice of the
    /// `content-` domain (mirrors `content::error`'s): every variant has an
    /// exemplar, codes are pairwise distinct, `content-` prefixed and
    /// kebab-cased — and distinct from every `ContentError` code, since the
    /// two families share one prefix and one global namespace (D30 §4).
    #[test]
    fn canon_codes_are_distinct_prefixed_and_do_not_collide_with_content() {
        let exemplars = canon_code_exemplars();
        assert_eq!(
            exemplars.len(),
            2,
            "one exemplar per variant — keep exhaustive when adding variants"
        );

        let codes: BTreeSet<&'static str> = exemplars.iter().map(CanonicalizeError::code).collect();
        assert_eq!(codes.len(), exemplars.len(), "codes pairwise distinct");

        for code in &codes {
            assert!(
                code.starts_with("content-"),
                "code {code:?} must carry the domain prefix"
            );
            assert!(
                !code.is_empty()
                    && code
                        .chars()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'),
                "code {code:?} is not lowercase kebab-case"
            );
        }

        // The registry error's own code is surfaced unchanged by the
        // wrapping pipeline error (contract §2: a wrapped failure keeps its
        // owning type's identity).
        let unknown = UnicodeVersionError::UnknownUnicodeVersion {
            requested: "unicode-99.0.0".to_owned(),
        };
        assert_eq!(unknown.code(), "content-unknown-unicode-version");
        assert_eq!(
            CanonicalizeError::UnknownVersion(unknown.clone()).code(),
            unknown.code()
        );

        // No collision with the sibling `content-` family.
        let content_codes: BTreeSet<&'static str> = crate::content::error::all_code_exemplars()
            .iter()
            .map(crate::content::ContentError::code)
            .collect();
        assert!(
            content_codes.is_disjoint(&codes),
            "canonicalization codes collide with ContentError codes: {:?}",
            content_codes.intersection(&codes).collect::<Vec<_>>()
        );
    }
}
