//! **F's `cbor-`-family slice** (task F24): the `DecodeError` codes that
//! were reachable from every schema surface and rowed by none, and the
//! reverse-coverage check that makes an unrowed one impossible to add
//! silently.
//!
//! # The gap this closes, and why neither existing check could see it
//!
//! F3's [`DecodeError`](crate::codec::decode::DecodeError) has **fifteen**
//! codes. Nine carried a row before this task: Q7's seven seed rows plus
//! F15's `cbor-non-shortest-length` and `cbor-nesting-too-deep`. The other
//! six — `cbor-malformed`, `cbor-simple-value`, `cbor-tag`,
//! `cbor-invalid-utf8`, `cbor-unexpected-type`, `cbor-int-out-of-range` —
//! had no row, no fixture and no named owner. They are exercised thoroughly
//! by `codec/decode.rs`'s own unit tests, which is a *unit-level* proof and
//! invisible to Q8's cross-domain distinctness sweep.
//!
//! The structural point is that neither guard could have caught them:
//!
//! - **Q8's registry** maps the *spec's* enumeration onto rows, so it cannot
//!   see a code nobody wrote a spec case for.
//! - **F23's sweep** maps `BundleError`'s and `ManifestError`'s exemplar
//!   lists onto rows — and the `cbor-` family is a **third namespace both of
//!   them merely delegate to** (`Self::Cbor { source } => source.code()`).
//!   A `cbor-` code is reachable through every schema surface while
//!   belonging to neither sweep.
//!
//! So this module adds the sweep for the third namespace, over
//! [`all_code_exemplars`](crate::codec::decode::all_code_exemplars), with the
//! same three-way accounting R7 established: **a row here, a Q7 seed row, or
//! a named owner** — never silence.
//!
//! # Five rows, one named non-row
//!
//! | code | fixture | why it is a row |
//! | --- | --- | --- |
//! | `cbor-tag` | `bundle-tagged-file-id` | security-bearing: a tagged re-spelling of a value aliasing an untagged one under one `work_id` is precisely why F3 bans tags |
//! | `cbor-simple-value` | `body-simple-value-size` | same argument: `true`/`null` are not `1`, and the profile admits neither |
//! | `cbor-invalid-utf8` | `bundle-invalid-utf8-path` | reachable from any `tstr`, and the disclosed path is the one a user *reads* |
//! | `cbor-unexpected-type` | `body-unexpected-type-range` | load-bearing for D10 §6: this is the code an over-deep bundle actually produces, which is the whole argument for the depth row being a direct call |
//! | `cbor-malformed` | `bundle-malformed-file-id` | the commonest hostile head after truncation, and the fixture is one byte |
//!
//! **`cbor-int-out-of-range` is a named non-row**, and the reason is a
//! finding rather than a cost argument: it is produced only by
//! [`CanonicalDecoder::i64`](crate::codec::decode::CanonicalDecoder::i64),
//! and **no v1 schema slot is decoded through `i64()`**. Every integer field
//! in the manifest and bundle registries is a `uint` read through `u64()`,
//! and the generic walker consumes negative integers through minicbor's
//! `int()` rather than the typed reader. The only callers in the whole
//! workspace are the diagnostic renderer
//! ([`super::vectors_cbor_diag`]) and `codec/decode.rs`'s own tests. So no
//! input to `check_canonical`, `Manifest::decode` or `SealProof::decode` can
//! produce it, and a row would assert something no artifact can exhibit.
//! The code stays — the decoder's typed API is general and F1's contingency
//! trigger could make `i64()` a schema read tomorrow — but its row would be
//! a fiction today. Recorded in [`DELIBERATE_NON_ROWS`] and asserted by
//! [`tests::the_int_out_of_range_argument_still_holds`], which re-derives the
//! claim rather than trusting this paragraph.
//!
//! # Every fixture mutates a *nested* item
//!
//! That is the point of sequencing F25 first. Each mutation is expressed as
//! `(path-to-item, replacement)` through [`super::cbor_span`], never as a
//! pinned offset. The five paths land at five different depths and shapes:
//! inside the manifest body, a `uint` three levels down and an **array** five
//! levels down; inside the bundle, two `uint`s and a `tstr` spread across two
//! different array elements. Three of the five are at layer 1 by design —
//! see [`TOUCHED_FILE_ID`] for the reason a fault buried in an embedded
//! `bstr` can be invisible to an independent checker.
//!
//! # Relationship to F23
//!
//! F24's entry says to extend F23's check. F23 was authored in a concurrent
//! lane, so this is its **sibling** rather than an extension: a separate
//! function over a separate namespace, with its own accounting lists. The
//! two are natural to merge into one lane afterwards, and nothing here
//! prevents it.

use crate::bundle::registry::key as bundle_key;
use crate::codec::decode::DecodeError;
use crate::manifest::registry::key as manifest_key;

use super::cbor_span::{Step, span_at_path, splice_item_at_path};
use super::tamper::{ActualOutcome, ExpectedOutcome, TamperRow};
use super::tamper_rows_format::{
    FormatFixture, Surface, base_body, base_bundle, envelope_around, exercise_by_id,
};

// ---------------------------------------------------------------------------
// the five paths
// ---------------------------------------------------------------------------

/// Body → file 0 → unit 0 → `range` (key 2). An **array**, so the typed read
/// that meets it asks for `ExpectedKind::Array`.
const UNIT_RANGE: [Step; 5] = [
    Step::Value(manifest_key::body::FILES),
    Step::Index(0),
    Step::Value(manifest_key::file::UNITS),
    Step::Index(0),
    Step::Value(manifest_key::unit::RANGE),
];

/// Body → file 0 → `size` (key 3). Three levels down; a two-byte `uint`.
const FILE_SIZE: [Step; 3] = [
    Step::Value(manifest_key::body::FILES),
    Step::Index(0),
    Step::Value(manifest_key::file::SIZE),
];

/// Bundle → `full_reveals[0]` → `file_id` (key 0). A one-byte `uint` two
/// levels down, at **layer 1**.
const FULL_REVEAL_FILE_ID: [Step; 3] = [
    Step::Value(bundle_key::bundle::FULL_REVEALS),
    Step::Index(0),
    Step::Value(bundle_key::full_reveal::FILE_ID),
];

/// Bundle → `touched_files[0]` → `file_id` (key 0). A one-byte `uint` two
/// levels down, at **layer 1**.
///
/// The malformed fixture lives here rather than in the manifest body for a
/// reason F14's cross-check made visible: its descent into embedded layers is
/// deliberately unguided, and it uses `cbor2.loads` succeeding as the test for
/// "is this blob a CBOR layer at all". A body containing a reserved head byte
/// does not load, so it is indistinguishable from a salt or a signature and
/// the sweep would find no fault to confirm. At layer 1 the fault is in the
/// outermost document, where the checker looks first.
const TOUCHED_FILE_ID: [Step; 3] = [
    Step::Value(bundle_key::bundle::TOUCHED_FILES),
    Step::Index(0),
    Step::Value(bundle_key::touched_file::FILE_ID),
];

/// Bundle → `touched_files[0]` → `path` (key 1). The one `tstr` in the base
/// bundle, and the field a user actually reads.
const TOUCHED_PATH: [Step; 3] = [
    Step::Value(bundle_key::bundle::TOUCHED_FILES),
    Step::Index(0),
    Step::Value(bundle_key::touched_file::PATH),
];

// ---------------------------------------------------------------------------
// the five fixtures
// ---------------------------------------------------------------------------

/// Apply a replacement item at `path` in the base body and re-wrap it in the
/// base envelope (F15's discipline: a stale `bstr` length head would be a
/// second mutation).
fn body_at(path: &[Step], replacement: &[u8]) -> Option<Vec<u8>> {
    let body = base_body()?;
    envelope_around(&splice_item_at_path(&body, path, replacement)?)
}

/// `cbor-tag`: wrap `full_reveals[0].file_id` in tag **55799**, "self-described
/// CBOR" (RFC 8949 §3.4.6).
///
/// The value it decorates is the *same* `uint` the untagged document carries,
/// which is exactly the aliasing F3 bans tags to prevent: two byte strings,
/// one meaning, one `work_id`. 55799 rather than a made-up number because it
/// is the one tag a real encoder plausibly prepends on its own — the realistic
/// version of the attack is an honest library, not an adversary.
///
/// At layer 1 rather than in the body, for [`TOUCHED_FILE_ID`]'s reason: the
/// cross-check's descent into embedded layers runs only where `cbor2` can load
/// the blob, and `cbor2` applies *semantics* to known tags, so whether a tagged
/// body is reachable at all depends on which tag number was chosen. At layer 1
/// the fault is in the outermost document, where the checker looks first and
/// where no library's tag semantics can hide it.
fn bundle_tagged_file_id() -> Option<Vec<u8>> {
    let bundle = base_bundle();
    // 0xD9 0xD9 0xF7 = tag(55799); 0x00 = the unchanged value.
    splice_item_at_path(&bundle, &FULL_REVEAL_FILE_ID, &[0xD9, 0xD9, 0xF7, 0x00])
}

/// `cbor-simple-value`: replace the file's `size` with `true`.
fn body_simple_value_size() -> Option<Vec<u8>> {
    body_at(&FILE_SIZE, &[0xF5])
}

/// `cbor-unexpected-type`: replace the unit's `range` **array** with a `bstr`
/// of the same width, so the item is perfectly canonical and only the
/// schema's expectation is violated.
///
/// This is the code D10 §6 says an over-deep bundle actually produces, which
/// is why F15's depth row has to be a direct call on `check_canonical`: the
/// schema layer's typed read always wins at level 1.
fn body_unexpected_type_range() -> Option<Vec<u8>> {
    // The range is `82 00 18 40` (array(2), 0, 64) — four bytes. `43 00 00 00`
    // is a three-byte bstr, also four bytes on the wire.
    body_at(&UNIT_RANGE, &[0x43, 0x00, 0x00, 0x00])
}

/// `cbor-malformed`: replace `touched_files[0].file_id` with a head byte no
/// canonical item can start with (major type 0, reserved additional info 28).
///
/// One byte, length-preserving, at layer 1 (see [`TOUCHED_FILE_ID`]).
fn bundle_malformed_file_id() -> Option<Vec<u8>> {
    let bundle = base_bundle();
    let span = span_at_path(&bundle, &TOUCHED_FILE_ID)?;
    if span.byte_len() != 1 {
        return None;
    }
    let mut out = bundle;
    *out.get_mut(span.start)? = 0x1C;
    Some(out)
}

/// `cbor-invalid-utf8`: flip the first byte of the disclosed path to a lone
/// UTF-8 continuation byte.
///
/// Length-preserving and confined to a `tstr` payload, so every length head
/// in the bundle — including the embedded manifest's — stays exact and the
/// only fault is the one the fixture names.
fn bundle_invalid_utf8_path() -> Option<Vec<u8>> {
    let bundle = base_bundle();
    let span = span_at_path(&bundle, &TOUCHED_PATH)?;
    let mut out = bundle;
    // 0x80 is a continuation byte with no lead byte before it: invalid in
    // any position, so this does not depend on what the path spells.
    *out.get_mut(span.head_end)? = 0x80;
    Some(out)
}

/// F24's fixtures, in emit order.
pub const FIXTURES: &[FormatFixture] = &[
    FormatFixture {
        id: "bundle-tagged-file-id",
        base: "bundle",
        mutation: "wrap `full_reveals[0].file_id` in tag 55799 (self-described CBOR), leaving \
                   the value itself unchanged",
        surface: Surface::SealProofDecode,
        code: "cbor-tag",
        layer: Some("bundle"),
        committed: true,
        row: Some("cbor-tag"),
        build: bundle_tagged_file_id,
    },
    FormatFixture {
        id: "body-simple-value-size",
        base: "manifest",
        mutation: "replace the file's `size` value with the simple value `true`",
        surface: Surface::ManifestDecode,
        code: "cbor-simple-value",
        layer: Some("manifest body"),
        committed: true,
        row: Some("cbor-simple-value"),
        build: body_simple_value_size,
    },
    FormatFixture {
        id: "body-unexpected-type-range",
        base: "manifest",
        mutation: "replace the nested unit's `range` array with a byte string of the same width",
        surface: Surface::ManifestDecode,
        code: "cbor-unexpected-type",
        layer: Some("manifest body"),
        committed: true,
        row: Some("cbor-unexpected-type"),
        build: body_unexpected_type_range,
    },
    FormatFixture {
        id: "bundle-malformed-file-id",
        base: "bundle",
        mutation: "replace `touched_files[0].file_id` with a reserved (additional info 28) head \
                   byte",
        surface: Surface::SealProofDecode,
        code: "cbor-malformed",
        layer: Some("bundle"),
        committed: true,
        row: Some("cbor-malformed"),
        build: bundle_malformed_file_id,
    },
    FormatFixture {
        id: "bundle-invalid-utf8-path",
        base: "bundle",
        mutation: "flip the first byte of `touched_files[0].path` to a lone UTF-8 continuation \
                   byte",
        surface: Surface::SealProofDecode,
        code: "cbor-invalid-utf8",
        layer: Some("bundle"),
        committed: true,
        row: Some("cbor-invalid-utf8"),
        build: bundle_invalid_utf8_path,
    },
];

// ---------------------------------------------------------------------------
// the accounting lists
// ---------------------------------------------------------------------------

/// `cbor-` codes claimed by the **Q7 seed rows** in `tests/tamper_matrix.rs`.
///
/// Named here rather than read from there because that registry is an
/// integration test and this check is a lib test. The list is not allowed to
/// go stale in either direction: [`tests::the_accounting_lists_are_not_stale`]
/// checks each entry is a real code and is not *also* claimed here, and
/// `tests/tamper_matrix.rs`'s
/// `the_seed_row_coverage_list_names_live_rows` checks each is genuinely
/// claimed by a live row.
pub const COVERED_BY_SEED_ROWS: &[&str] = &[
    "cbor-non-shortest-int",
    "cbor-indefinite-length",
    "cbor-duplicate-map-key",
    "cbor-unsorted-map-keys",
    "cbor-truncated",
    "cbor-trailing-bytes",
    "cbor-float",
];

/// `cbor-` codes deliberately left unrowed, with the reason.
///
/// One entry, and it is an unreachability argument rather than a cost one
/// (module docs).
pub const DELIBERATE_NON_ROWS: &[(&str, &str)] = &[(
    "cbor-int-out-of-range",
    "Produced only by `CanonicalDecoder::i64`, and no v1 schema slot is decoded through it: every \
     integer field in the manifest and bundle registries is a `uint` read through `u64()`, and \
     the generic walker consumes negative integers through the pinned crate's `int()` rather than \
     the typed reader. No input to `check_canonical`, `Manifest::decode` or `SealProof::decode` \
     can therefore produce this code, so a row would pin an outcome no artifact can exhibit. The \
     code is kept (the typed API is general, and F1's contingency trigger could make `i64()` a \
     schema read) and is covered by `codec/decode.rs`'s unit tests. Re-derived every run by \
     `the_int_out_of_range_argument_still_holds`.",
)];

// ---------------------------------------------------------------------------
// the reverse-coverage check
// ---------------------------------------------------------------------------

/// Codes in `universe` claimed by neither a row, a Q7 seed row, nor a named
/// non-row.
///
/// Taking the universe as an argument is what makes the check testable: the
/// "mint a throwaway sixteenth code" test-of-the-test passes a universe with
/// one extra member rather than editing the enum, so the guard is proven red
/// on every run instead of once by hand.
#[must_use]
pub fn unaccounted_cbor_codes(universe: &[&'static str]) -> Vec<&'static str> {
    let claimed = |code: &'static str| {
        ROWS.iter()
            .chain(super::tamper_rows_format::ROWS)
            .chain(super::tamper_rows_caps::ROWS)
            .any(|row| row.expected == ExpectedOutcome::ErrorCode(code))
    };
    universe
        .iter()
        .copied()
        .filter(|code| {
            !claimed(code)
                && !COVERED_BY_SEED_ROWS.contains(code)
                && !DELIBERATE_NON_ROWS.iter().any(|(named, _)| named == code)
        })
        .collect()
}

/// The whole `cbor-` code universe, read off `DecodeError`'s exemplar list.
#[must_use]
pub fn cbor_code_universe() -> Vec<&'static str> {
    crate::codec::decode::all_code_exemplars()
        .iter()
        .map(DecodeError::code)
        .collect()
}

// ---------------------------------------------------------------------------
// the registry slice
// ---------------------------------------------------------------------------

fn row_tag() -> ActualOutcome {
    exercise_by_id(FIXTURES, "bundle-tagged-file-id")
}
fn row_simple_value() -> ActualOutcome {
    exercise_by_id(FIXTURES, "body-simple-value-size")
}
fn row_unexpected_type() -> ActualOutcome {
    exercise_by_id(FIXTURES, "body-unexpected-type-range")
}
fn row_malformed() -> ActualOutcome {
    exercise_by_id(FIXTURES, "bundle-malformed-file-id")
}
fn row_invalid_utf8() -> ActualOutcome {
    exercise_by_id(FIXTURES, "bundle-invalid-utf8-path")
}

/// F24's M0 tamper rows. Row ids are permanent handles; see the harness docs
/// ([`super::tamper`]) for the add-a-row procedure and
/// `docs/testing/error-code-contract.md` for why an expected code may never
/// be edited to make a failing run pass.
pub const ROWS: &[TamperRow] = &[
    TamperRow {
        id: "cbor-tag",
        base: "golden-bundle-unanchored",
        mutation: "wrap `full_reveals[0].file_id` in tag 55799 (self-described CBOR)",
        expected: ExpectedOutcome::ErrorCode("cbor-tag"),
        exercise: row_tag,
    },
    TamperRow {
        id: "cbor-simple-value",
        base: "golden-manifest-ed25519-only",
        mutation: "replace the file's `size` with the simple value `true`",
        expected: ExpectedOutcome::ErrorCode("cbor-simple-value"),
        exercise: row_simple_value,
    },
    TamperRow {
        id: "cbor-unexpected-type",
        base: "golden-manifest-ed25519-only",
        mutation: "replace the nested unit's `range` array with a byte string",
        expected: ExpectedOutcome::ErrorCode("cbor-unexpected-type"),
        exercise: row_unexpected_type,
    },
    TamperRow {
        id: "cbor-malformed",
        base: "golden-bundle-unanchored",
        mutation: "replace `touched_files[0].file_id` with a reserved head byte (info 28)",
        expected: ExpectedOutcome::ErrorCode("cbor-malformed"),
        exercise: row_malformed,
    },
    TamperRow {
        id: "cbor-invalid-utf8",
        base: "golden-bundle-unanchored",
        mutation: "flip the first byte of the disclosed path to a lone UTF-8 continuation byte",
        expected: ExpectedOutcome::ErrorCode("cbor-invalid-utf8"),
        exercise: row_invalid_utf8,
    },
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::decode::{CanonicalDecoder, check_canonical};
    use std::collections::BTreeSet;

    /// **F24's headline accept.** Every one of `DecodeError`'s codes is
    /// claimed by a row here, by a Q7 seed row, or by a named non-row. There
    /// is no fourth state: a `cbor-` code is reachable through every schema
    /// surface while belonging to neither of the two existing sweeps, so
    /// silence here is silence everywhere.
    #[test]
    fn every_cbor_code_has_a_row_or_a_named_owner() {
        let universe = cbor_code_universe();
        let unaccounted = unaccounted_cbor_codes(&universe);
        assert!(
            unaccounted.is_empty(),
            "these `cbor-` codes have no tamper row and no named owner: {unaccounted:?}\n\
             Add a row here, a Q7 seed row, or an entry in DELIBERATE_NON_ROWS naming why the \
             code can never have one — the point of this check is that the third option is a \
             deliberate, reviewed statement rather than an omission."
        );
        assert_eq!(universe.len(), 15, "F3's code universe is fifteen");
    }

    /// **Test-of-the-test.** A sixteenth code with nothing claiming it turns
    /// the check red — proven on every run by passing an extended universe,
    /// rather than once by hand-editing the enum.
    #[test]
    fn the_check_goes_red_on_an_unaccounted_code() {
        let mut universe = cbor_code_universe();
        universe.push("cbor-throwaway-sixteenth");
        assert_eq!(
            unaccounted_cbor_codes(&universe),
            vec!["cbor-throwaway-sixteenth"]
        );
    }

    /// The accounting lists must not go stale in the other direction either:
    /// a code recorded as seeded or as a non-row must still be a real code,
    /// and must not *also* be claimed by a row.
    #[test]
    fn the_accounting_lists_are_not_stale() {
        let universe: BTreeSet<&str> = cbor_code_universe().into_iter().collect();
        for code in COVERED_BY_SEED_ROWS
            .iter()
            .chain(DELIBERATE_NON_ROWS.iter().map(|(code, _)| code))
        {
            assert!(
                universe.contains(code),
                "`{code}` is recorded in a coverage list but no DecodeError variant emits it"
            );
            assert!(
                !ROWS
                    .iter()
                    .chain(super::super::tamper_rows_format::ROWS)
                    .chain(super::super::tamper_rows_caps::ROWS)
                    .any(|row| row.expected == ExpectedOutcome::ErrorCode(code)),
                "`{code}` is recorded as covered elsewhere AND claimed by a row — check_registry \
                 would refuse the pair"
            );
        }
    }

    /// The `cbor-int-out-of-range` non-row rests on a claim about the *code*,
    /// not on prose: no strict surface can produce it. Re-derived here from
    /// the two ends that could change — the decoder still reports it, and
    /// none of the three surfaces ever does.
    ///
    /// The positive half uses `i64()` directly, which is the only caller
    /// shape that exists; the negative half feeds each surface the same
    /// out-of-range integer in the position a schema read would meet it, and
    /// requires a *different* code to come back.
    #[test]
    fn the_int_out_of_range_argument_still_holds() {
        // 2^64 - 1, canonical, out of range for `i64`.
        let huge: [u8; 9] = [0x1B, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        let mut d = CanonicalDecoder::new(&huge);
        assert_eq!(
            d.i64().map_err(|e| e.code()),
            Err("cbor-int-out-of-range"),
            "the typed read must still produce the code the non-row is about"
        );

        // The generic walker accepts it: canonicality has nothing to say
        // about which Rust type a value fits.
        assert_eq!(check_canonical(&huge), Ok(()));

        // And no schema surface reports it. `{0: 2^64-1}` reaches the
        // format-version read of each layer, which is a `u64()`.
        let mut document = vec![0xA1, 0x00];
        document.extend_from_slice(&huge);
        for observed in [
            super::super::tamper_rows_format::run_surface(Surface::Canonical, &document),
            super::super::tamper_rows_format::run_surface(Surface::ManifestDecode, &document),
            super::super::tamper_rows_format::run_surface(Surface::SealProofDecode, &document),
        ] {
            assert_ne!(
                observed.code.as_deref(),
                Some("cbor-int-out-of-range"),
                "a strict surface produced the code the non-row says is unreachable — the \
                 argument has expired and `cbor-int-out-of-range` now needs a row"
            );
        }
    }

    /// Every fixture produces exactly its declared `(code, layer)` pair.
    #[test]
    fn every_fixture_produces_its_declared_code_and_layer() {
        for fixture in FIXTURES {
            let bytes = (fixture.build)()
                .unwrap_or_else(|| panic!("fixture `{}` failed to build", fixture.id));
            let observed = super::super::tamper_rows_format::run_surface(fixture.surface, &bytes);
            assert_eq!(
                observed.code.as_deref(),
                Some(fixture.code),
                "fixture `{}` reported the wrong code",
                fixture.id
            );
            assert_eq!(
                observed.layer.as_deref(),
                fixture.layer,
                "fixture `{}` reported the wrong layer",
                fixture.id
            );
        }
    }

    /// Every row is backed by a fixture that expects the same code, ids are
    /// unique, and the five codes are five.
    #[test]
    fn rows_and_fixtures_agree() {
        let ids: BTreeSet<&str> = FIXTURES.iter().map(|f| f.id).collect();
        assert_eq!(ids.len(), FIXTURES.len(), "duplicate fixture id");
        let row_ids: BTreeSet<&str> = ROWS.iter().map(|r| r.id).collect();
        assert_eq!(row_ids.len(), ROWS.len(), "duplicate row id");
        let codes: BTreeSet<&str> = FIXTURES.iter().map(|f| f.code).collect();
        assert_eq!(codes.len(), 5, "the five fixtures pin five distinct codes");
        for row in ROWS {
            let backing = FIXTURES
                .iter()
                .find(|f| f.row == Some(row.id))
                .unwrap_or_else(|| panic!("row `{}` has no backing fixture", row.id));
            assert_eq!(row.expected, ExpectedOutcome::ErrorCode(backing.code));
        }
    }

    /// Every fixture mutates a **nested** item — the reason F25 was
    /// sequenced first. "Nested" is checked as "the mutated span is not the
    /// document's outermost item", by locating the path rather than by
    /// asserting a byte offset.
    #[test]
    fn every_fixture_mutates_a_nested_item() {
        let body = base_body().expect("base body");
        let bundle = base_bundle();
        let cases: [(&str, &[u8], &[Step]); 5] = [
            ("bundle-tagged-file-id", &bundle, &FULL_REVEAL_FILE_ID),
            ("body-simple-value-size", &body, &FILE_SIZE),
            ("body-unexpected-type-range", &body, &UNIT_RANGE),
            ("bundle-malformed-file-id", &bundle, &TOUCHED_FILE_ID),
            ("bundle-invalid-utf8-path", &bundle, &TOUCHED_PATH),
        ];
        for (id, document, path) in cases {
            let span = span_at_path(document, path)
                .unwrap_or_else(|| panic!("`{id}`: its path does not resolve"));
            assert!(span.start > 0, "`{id}` mutates the outermost item");
            assert!(
                span.end < document.len(),
                "`{id}` mutates the outermost item"
            );
            assert!(!path.is_empty());
        }
    }

    /// The `tstr` fixture is length-preserving and differs from its base in
    /// exactly one byte — so the embedded manifest's `bstr` length head, and
    /// every other head in the bundle, is untouched.
    #[test]
    fn the_utf8_fixture_is_one_byte_and_length_preserving() {
        let base = base_bundle();
        let mutated = bundle_invalid_utf8_path().expect("the utf8 fixture");
        assert_eq!(mutated.len(), base.len());
        assert_eq!(
            mutated.iter().zip(&base).filter(|(a, b)| a != b).count(),
            1,
            "exactly one byte differs"
        );
    }
}
