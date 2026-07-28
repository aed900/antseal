//! **F's version-discriminant registry slice** (task F18): the two tamper
//! rows over F10's `version -> decoder` dispatch, built as a **one-byte**
//! mutation of the F12/F13 golden vectors' own bytes.
//!
//! The harness (distinctness, no-panic and exact-outcome assertions, and the
//! add-a-row procedure) is [`super::tamper`]; the code contract these rows
//! bind to is `docs/testing/error-code-contract.md`.
//!
//! # Why these two rows and not F18's four
//!
//! F18 was written at F10 and named four unrowed codes:
//! `manifest-unsupported-format-version`, `bundle-unsupported-format-version`,
//! `manifest-reserved-key` and `bundle-reserved-key`. **F15 has since landed
//! rows for the two reserved-key codes** (`manifest-reserved-key` and
//! `bundle-reserved-key` in [`super::tamper_rows_format`], both recorded in
//! `testdata/tamper/MATRIX.json`'s `project_added`), so a third and fourth
//! row here would claim outcomes another row already owns and
//! [`super::tamper::check_registry`] would refuse the pair — correctly, since
//! a reserved key in the body and a reserved key in a *unit entry* are one
//! observable (registry §7.15: a named slot is documentation, not a separate
//! code). The reserved-slot **surface** is not thereby untested: F10 sweeps
//! every reserved key of every map of both families exhaustively
//! (`tests/format_version_dispatch.rs`), and F34 owns the finding that the
//! three body sub-maps are still one observable.
//!
//! What was genuinely unrowed is the pair this module lands.
//!
//! # The mutation is one byte, and that is the point
//!
//! Both artifacts declare their version as the value of key 0 of their
//! top-level map (registry §7.2 for the manifest body, §7.6 for the bundle),
//! and a CBOR `uint` below 24 encodes as a single byte. So "this file is from
//! a newer antseal" is **one byte** away from "this file verifies" — which is
//! exactly why the two must not be reported the same way, and why the rows
//! start from real committed bytes rather than from a hand-built map: the
//! claim being pinned is that a genuine v1 artifact plus one byte is
//! *unsupported*, never *corrupt*.
//!
//! The manifest half re-wraps the mutated body in the base envelope. That is
//! length-preserving here (one byte replaced by one byte), so the envelope's
//! `bstr` length head is unchanged and the whole artifact differs from the
//! golden vector in exactly one position — asserted below, because a second
//! difference would mean the row was pinning two mutations at once.
//!
//! # Provenance
//!
//! Both bases are [`super::tamper_rows_format`]'s, hence R6's deterministic
//! constructor, hence byte-identical to the committed golden vectors — the
//! equality F15's fixture-table consumer already asserts against
//! `testdata/vectors/v1/`.

use crate::bundle::{SealProof, SealProofError};
use crate::codec::decode::CanonicalDecoder;
use crate::format::VERSION_KEY;
use crate::manifest::{Manifest, ManifestError, encode_envelope};

use super::tamper::{ActualOutcome, ExpectedOutcome, TamperRow};
use super::tamper_rows_format::{base_body, base_bundle, base_manifest};

/// The version a mutated artifact declares.
///
/// Any value outside [`SUPPORTED_VERSIONS`] behaves identically (F10's
/// `every_unrowed_version_is_the_same_rejection_class` sweeps `0`, `2`, `3`,
/// `23`, `24` and `u64::MAX`); `2` is chosen because it is the version that
/// will actually exist one day, so the row reads as the scenario it stands
/// for.
pub const MUTATED_VERSION: u64 = 2;

/// Byte offset of a versioned top-level map's `format_version` **value**,
/// given the version it must currently declare.
///
/// Located through the F3 decoder's own public surface rather than by
/// re-implementing head parsing, so this can never disagree with the decoder
/// about where the first entry's value begins (the F15 rule). Returns `None`
/// — never panics — when the base is not the artifact this module expects,
/// so a drifted base surfaces as a wrong outcome naming the row.
fn version_value_offset(map: &[u8], current: u64) -> Option<usize> {
    let mut d = CanonicalDecoder::new(map);
    let mut reader = d.map().ok()?;
    if reader.next_key(&mut d).ok()?? != VERSION_KEY {
        return None;
    }
    let at = d.position();
    // A `uint` below 24 is its own head byte, which is what makes the
    // mutation a single-byte splice. Refuse anything else rather than
    // silently writing over a multi-byte head.
    let current = u8::try_from(current).ok()?;
    if current >= 24 || map.get(at) != Some(&current) {
        return None;
    }
    Some(at)
}

/// Rewrite a versioned map's declared version to `version`, canonically.
///
/// The replacement is the crate's own encoding of the value (so a version at
/// or above 24 gets its genuine multi-byte head rather than a hand-made one),
/// which keeps the mutated artifact *canonical CBOR whose only fault is the
/// version* — the shape F18's property needs, since a non-canonical version
/// head is a different rejection class entirely (F10's
/// `a_non_canonical_version_head_is_rejected_as_non_canonical`).
///
/// Length-preserving only for `version < 24`; the manifest half re-encodes
/// its envelope around the result, so a longer body is still a well-formed
/// artifact.
#[must_use]
pub fn with_declared_version(map: &[u8], current: u64, version: u64) -> Option<Vec<u8>> {
    let at = version_value_offset(map, current)?;
    let encoded = crate::codec::encode_item(|e| e.u64(version)).ok()?;
    let mut out = Vec::with_capacity(map.len() + encoded.len());
    out.extend_from_slice(map.get(..at)?);
    out.extend_from_slice(&encoded);
    out.extend_from_slice(map.get(at.checked_add(1)?..)?);
    Some(out)
}

/// Replace a versioned map's declared version with [`MUTATED_VERSION`],
/// changing exactly one byte.
fn bump_version(map: &[u8], current: u64) -> Option<Vec<u8>> {
    if MUTATED_VERSION >= 24 {
        return None;
    }
    with_declared_version(map, current, MUTATED_VERSION)
}

/// The golden manifest **body**, declaring `version` instead of 1.
#[must_use]
pub fn body_at_version(version: u64) -> Option<Vec<u8>> {
    with_declared_version(
        &base_body()?,
        crate::manifest::registry::FORMAT_VERSION_V1,
        version,
    )
}

/// The golden manifest **envelope** carrying [`body_at_version`], re-encoded
/// around it with the base's signatures untouched.
#[must_use]
pub fn manifest_at_version(version: u64) -> Option<Vec<u8>> {
    let base = base_manifest();
    let manifest = Manifest::decode(&base).ok()?;
    encode_envelope(&body_at_version(version)?, manifest.signatures()).ok()
}

/// The golden `.sealproof`, declaring `version` instead of 1.
#[must_use]
pub fn bundle_at_version(version: u64) -> Option<Vec<u8>> {
    with_declared_version(
        &base_bundle(),
        crate::bundle::registry::FORMAT_VERSION_V1,
        version,
    )
}

/// The golden manifest **body** with its `format_version` bumped to
/// [`MUTATED_VERSION`].
#[must_use]
pub fn future_version_body() -> Option<Vec<u8>> {
    bump_version(&base_body()?, crate::manifest::registry::FORMAT_VERSION_V1)
}

/// The golden manifest **envelope** carrying that body, re-encoded around it
/// with the base's signatures untouched.
#[must_use]
pub fn future_version_manifest() -> Option<Vec<u8>> {
    let base = base_manifest();
    let manifest = Manifest::decode(&base).ok()?;
    encode_envelope(&future_version_body()?, manifest.signatures()).ok()
}

/// The golden `.sealproof` with its own `format_version` bumped to
/// [`MUTATED_VERSION`].
#[must_use]
pub fn future_version_bundle() -> Option<Vec<u8>> {
    bump_version(&base_bundle(), crate::bundle::registry::FORMAT_VERSION_V1)
}

/// Report a construction failure as a distinctive outcome rather than a
/// panic, so a drifted base fails as a wrong outcome naming its row (the F15
/// / G19 convention).
fn built(id: &str, bytes: Option<Vec<u8>>) -> Result<Vec<u8>, ActualOutcome> {
    bytes.ok_or_else(|| ActualOutcome::ErrorCode(format!("f18-fixture-construction-failed:{id}")))
}

fn row_manifest_unsupported_version() -> ActualOutcome {
    match built("version-manifest-unsupported", future_version_manifest()) {
        Err(outcome) => outcome,
        Ok(bytes) => ActualOutcome::from_result(Manifest::decode(&bytes), ManifestError::code),
    }
}

fn row_bundle_unsupported_version() -> ActualOutcome {
    match built("version-bundle-unsupported", future_version_bundle()) {
        Err(outcome) => outcome,
        Ok(bytes) => ActualOutcome::from_result(SealProof::decode(&bytes), SealProofError::code),
    }
}

/// F18's rows. Row ids are permanent handles; see [`super::tamper`] for the
/// add-a-row procedure and `docs/testing/error-code-contract.md` for why an
/// expected code may never be edited to make a failing run pass.
pub const ROWS: &[TamperRow] = &[
    TamperRow {
        id: "version-manifest-unsupported",
        base: "golden-manifest-ed25519-only",
        mutation: "bump the manifest body's `format_version` byte from 1 to 2",
        expected: ExpectedOutcome::ErrorCode("manifest-unsupported-format-version"),
        exercise: row_manifest_unsupported_version,
    },
    TamperRow {
        id: "version-bundle-unsupported",
        base: "golden-bundle-unanchored",
        mutation: "bump the bundle's `format_version` byte from 1 to 2",
        expected: ExpectedOutcome::ErrorCode("bundle-unsupported-format-version"),
        exercise: row_bundle_unsupported_version,
    },
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::{SUPPORTED_VERSIONS, peek_format_version};

    /// Count the positions at which two equal-length byte strings differ.
    fn differences(a: &[u8], b: &[u8]) -> usize {
        assert_eq!(a.len(), b.len(), "the mutation must be length-preserving");
        a.iter().zip(b).filter(|(x, y)| x != y).count()
    }

    /// **The single-mutation claim, mechanically.** Each row's artifact
    /// differs from its base in exactly one byte — including the manifest,
    /// whose body is re-wrapped (a stale or re-sized `bstr` head would show
    /// up here as a second difference).
    #[test]
    fn each_row_changes_exactly_one_byte_of_its_base() {
        let manifest = future_version_manifest().expect("manifest fixture builds");
        assert_eq!(differences(&base_manifest(), &manifest), 1);

        let bundle = future_version_bundle().expect("bundle fixture builds");
        assert_eq!(differences(&base_bundle(), &bundle), 1);
    }

    /// The mutated byte really is the discriminant: the F10 peek — the same
    /// function dispatch consults — reads [`MUTATED_VERSION`] out of both.
    #[test]
    fn the_peek_reads_the_mutated_version_from_both_artifacts() {
        let body = future_version_body().expect("body fixture builds");
        assert_eq!(peek_format_version(&body), Some(MUTATED_VERSION));

        let bundle = future_version_bundle().expect("bundle fixture builds");
        assert_eq!(peek_format_version(&bundle), Some(MUTATED_VERSION));

        // …and the version it declares is one this build cannot decode,
        // which is what makes the rows' expected codes the right ones.
        assert!(!SUPPORTED_VERSIONS.contains(&MUTATED_VERSION));
    }

    /// Both rows produce their declared code **and** the layer the surface
    /// attributes it to (D86: a layered decoder always reports a layer).
    ///
    /// The manifest's version error is attributed to the **body**, not the
    /// envelope, because the envelope is shape-frozen across versions and
    /// carries no discriminant of its own — the fact F10's
    /// `peek_reads_both_discriminants_without_decoding` pins from the other
    /// side.
    #[test]
    fn both_rows_report_their_code_and_layer() {
        let manifest = future_version_manifest().expect("manifest fixture builds");
        let err = Manifest::decode(&manifest).expect_err("a v2 manifest must not decode");
        assert_eq!(err.code(), "manifest-unsupported-format-version");
        assert_eq!(err.layer().to_string(), "manifest body");

        let bundle = future_version_bundle().expect("bundle fixture builds");
        let err = SealProof::decode(&bundle).expect_err("a v2 bundle must not decode");
        assert_eq!(err.code(), "bundle-unsupported-format-version");
        assert_eq!(err.layer().to_string(), "bundle");
    }

    /// A row's base must itself be valid, or the row could "pass" by pinning
    /// a defect the mutation had nothing to do with (the R7 rule).
    #[test]
    fn both_bases_decode_before_they_are_mutated() {
        assert!(Manifest::decode(&base_manifest()).is_ok());
        assert!(SealProof::decode(&base_bundle()).is_ok());
    }

    /// The offset finder is total and refuses a base that is not the
    /// artifact it expects — it never panics and never writes over the wrong
    /// byte.
    #[test]
    fn the_offset_finder_declines_rather_than_guessing() {
        // Not a map.
        assert_eq!(version_value_offset(&[0x01], 1), None);
        // Empty input.
        assert_eq!(version_value_offset(&[], 1), None);
        // A map whose first key is not the version key.
        assert_eq!(version_value_offset(&[0xA1, 0x01, 0x01], 1), None);
        // Key 0 present, but declaring a version other than the expected one.
        assert_eq!(version_value_offset(&[0xA1, 0x00, 0x02], 1), None);
        // …and the same map read with the version it actually declares.
        assert_eq!(version_value_offset(&[0xA1, 0x00, 0x02], 2), Some(2));
    }

    /// The slice's own outcomes are pairwise distinct (contract §4 layer 1);
    /// the cross-domain sweep is `tests/tamper_matrix.rs`'s.
    #[test]
    fn the_slice_is_internally_distinct() {
        let mut seen: Vec<String> = Vec::new();
        for row in ROWS {
            let key = row.expected.key();
            assert!(!seen.contains(&key), "row `{}` re-claims `{key}`", row.id);
            seen.push(key);
        }
    }

    /// F18 mints nothing: both codes already existed in F5's and F8's
    /// shipped taxonomies (contract §3).
    #[test]
    fn every_expected_code_already_existed() {
        let manifest_codes: Vec<&'static str> = crate::manifest::error::all_code_exemplars()
            .iter()
            .map(ManifestError::code)
            .collect();
        let bundle_codes: Vec<&'static str> = crate::bundle::error::all_code_exemplars()
            .iter()
            .map(crate::bundle::BundleError::code)
            .collect();
        assert!(manifest_codes.contains(&"manifest-unsupported-format-version"));
        assert!(bundle_codes.contains(&"bundle-unsupported-format-version"));
    }

    /// **The reserved-key half of F18, recorded rather than rowed.** Both
    /// reserved-key codes are already claimed by F15 rows, so this slice must
    /// never grow one — `check_registry` would refuse the pair (module docs).
    #[test]
    fn the_reserved_key_codes_stay_f15s() {
        for code in ["manifest-reserved-key", "bundle-reserved-key"] {
            assert!(
                super::super::tamper_rows_format::ROWS
                    .iter()
                    .any(|row| row.expected == ExpectedOutcome::ErrorCode(code)),
                "`{code}` must still be claimed by an F15 row — if it stops being, F18's \
                 reserved-slot rows become landable and this test is where that is noticed"
            );
            assert!(
                !ROWS
                    .iter()
                    .any(|row| row.expected == ExpectedOutcome::ErrorCode(code)),
                "`{code}` is F15's row; a second row here would collide"
            );
        }
    }
}
