//! The M0 tamper-matrix registry (task Q7) — seed rows over the surfaces
//! that exist today.
//!
//! Every row mutates one valid artifact in exactly one way and pins the
//! distinct outcome the verifier must produce (MVP-SPEC.md line 168). The
//! harness itself — the distinctness, no-panic, and exact-outcome
//! assertions, plus the row-addition procedure — lives in
//! [`antseal_core::test_util::tamper`]; the error-code contract these rows
//! bind to is `docs/testing/error-code-contract.md`.
//!
//! **The rows below are Q7's seed set, not the whole matrix.** The full M0
//! row list is assembled by [`all_rows`] from the domain slices that own the
//! fixtures — F15 (format), C17 (crypto), G19 (fine tree), R7/R8
//! (structural and pipeline) — and the 1:1 completeness check against the
//! spec's row list is Q8's. What the seed rows prove is that the harness
//! works, that the codes it binds to are genuinely distinct across domains,
//! and that the row-addition procedure has been exercised end to end.
//!
//! The seven `cbor-*` seed rows below run on a synthetic three-byte map,
//! which is what let Q7 land before any codec fixture existed. F15 has since
//! given four of them — the mutations MVP-SPEC.md line 168 names by hand —
//! a **real manifest-body fixture** under `testdata/tamper/format/`, checked
//! by `tests/format_tamper_fixtures.rs`. Those fixtures deliberately did
//! *not* become second rows: they produce the same four codes, and Q7's
//! distinctness assertion would correctly refuse the pairs
//! (`the_format_fixture_table_agrees_with_the_live_registry`, below, is
//! where the two sides are tied together).

/// Q8's completeness registry check (`testdata/tamper/MATRIX.json`). It
/// lives here rather than in its own test target because the assembled
/// registry it checks against — [`all_rows`] — is this file's.
mod tamper_completeness;

use antseal_core::codec::decode::check_canonical;
use antseal_core::crypto::commit::path_commit;
use antseal_core::crypto::error::CryptoError;
use antseal_core::crypto::material::Salt16;
use antseal_core::crypto::padding::{apply_padding, strip_padding};
use antseal_core::test_util::tamper::{
    ActualOutcome, ExpectedOutcome, TamperRow, check_registry, render_failures,
};
use antseal_core::verify::{
    BundleView, DisclosedField, FileEntry, LengthField, ManifestView, TouchedFile, UnitEntry,
    UnitKind, VerifyError, check_structural,
};

/// Fixed, public, NON-SECRET fixture salt (project rule 6).
const FIXTURE_SALT: [u8; 16] = [7u8; 16];

// ── F: canonical-CBOR rows (base: a canonical map fixture) ──

/// `{0: 1}` in canonical CBOR: map(1), key 0, value 1.
const CANONICAL_MAP: [u8; 3] = [0xA1, 0x00, 0x01];

fn cbor_outcome(bytes: &[u8]) -> ActualOutcome {
    ActualOutcome::from_result(check_canonical(bytes), |err| err.code())
}

fn cbor_non_shortest_int() -> ActualOutcome {
    // Re-encode the value 1 in a two-byte head (0x18 0x01) — same value,
    // non-shortest form.
    cbor_outcome(&[0xA1, 0x00, 0x18, 0x01])
}

fn cbor_indefinite_length() -> ActualOutcome {
    // Indefinite-length map (0xBF … 0xFF) carrying the same entry.
    cbor_outcome(&[0xBF, 0x00, 0x01, 0xFF])
}

fn cbor_duplicate_map_key() -> ActualOutcome {
    cbor_outcome(&[0xA2, 0x00, 0x01, 0x00, 0x02])
}

fn cbor_unsorted_map_keys() -> ActualOutcome {
    cbor_outcome(&[0xA2, 0x01, 0x01, 0x00, 0x02])
}

fn cbor_truncated() -> ActualOutcome {
    cbor_outcome(&CANONICAL_MAP[..2])
}

fn cbor_trailing_bytes() -> ActualOutcome {
    let mut bytes = CANONICAL_MAP.to_vec();
    bytes.push(0x00);
    cbor_outcome(&bytes)
}

fn cbor_float() -> ActualOutcome {
    // Half-precision float 1.0 as the map value — forbidden outright.
    cbor_outcome(&[0xA1, 0x00, 0xF9, 0x3C, 0x00])
}

// ── C: padding rows (base: a correctly padded 10-byte unit) ──

fn padded_unit() -> Vec<u8> {
    apply_padding(&[0xAB; 10])
}

fn crypto_over_padded_unit() -> ActualOutcome {
    // One extra 256-byte bucket beyond the formula.
    let mut plaintext = padded_unit();
    plaintext.extend(std::iter::repeat_n(0u8, 256));
    ActualOutcome::from_result(strip_padding(&plaintext, 10), CryptoError::code)
}

fn crypto_non_zero_padding() -> ActualOutcome {
    let mut plaintext = padded_unit();
    let last = plaintext.len() - 1;
    plaintext[last] = 0x01;
    ActualOutcome::from_result(strip_padding(&plaintext, 10), CryptoError::code)
}

fn crypto_path_salt_length() -> ActualOutcome {
    ActualOutcome::from_result(
        Salt16::try_from_slice(antseal_core::crypto::error::SaltKind::Path, &[7u8; 15]),
        CryptoError::code,
    )
}

// ── R: structural rows (base: a two-unit file that tiles exactly) ──

fn structural_outcome(manifest: &ManifestView<'_>, bundle: &BundleView<'_>) -> ActualOutcome {
    ActualOutcome::from_result(check_structural(manifest, bundle), VerifyError::code)
}

fn base_files() -> [FileEntry; 1] {
    [FileEntry {
        file_id: 1,
        size: 10,
        path_commit: path_commit(&Salt16::from_bytes(FIXTURE_SALT), "a.txt"),
    }]
}

fn normal(unit_id: u64, start: u64, end: u64) -> UnitEntry {
    UnitEntry {
        unit_id,
        file_id: 1,
        kind: UnitKind::Normal,
        range_start: start,
        range_end: end,
    }
}

fn empty_bundle<'a>() -> BundleView<'a> {
    BundleView {
        revealed_unit_ids: &[],
        touched_files: &[],
        proof_unit_refs: &[],
        disclosed_lengths: &[],
    }
}

fn verify_tiling_gap() -> ActualOutcome {
    // Drop the second unit's coverage: [0,4) leaves [4,10) uncovered.
    let files = base_files();
    let units = [normal(0, 0, 4)];
    structural_outcome(
        &ManifestView {
            files: &files,
            units: &units,
        },
        &empty_bundle(),
    )
}

fn verify_tiling_overlap() -> ActualOutcome {
    let files = base_files();
    let units = [normal(0, 0, 6), normal(1, 4, 10)];
    structural_outcome(
        &ManifestView {
            files: &files,
            units: &units,
        },
        &empty_bundle(),
    )
}

fn verify_raw_mirror_in_tiling_set() -> ActualOutcome {
    // The file's only unit is its raw mirror: raw bytes standing in for
    // canonical coverage.
    let files = base_files();
    let units = [UnitEntry {
        unit_id: 9,
        file_id: 1,
        kind: UnitKind::RawMirror,
        range_start: 0,
        range_end: 10,
    }];
    structural_outcome(
        &ManifestView {
            files: &files,
            units: &units,
        },
        &empty_bundle(),
    )
}

fn verify_unknown_unit_ref() -> ActualOutcome {
    let files = base_files();
    let units = [normal(0, 0, 10)];
    let bundle = BundleView {
        revealed_unit_ids: &[42],
        ..empty_bundle()
    };
    structural_outcome(
        &ManifestView {
            files: &files,
            units: &units,
        },
        &bundle,
    )
}

fn verify_duplicate_unit_reveal() -> ActualOutcome {
    let files = base_files();
    let units = [normal(0, 0, 10)];
    let bundle = BundleView {
        revealed_unit_ids: &[0, 0],
        ..empty_bundle()
    };
    structural_outcome(
        &ManifestView {
            files: &files,
            units: &units,
        },
        &bundle,
    )
}

fn verify_path_commit_mismatch() -> ActualOutcome {
    let files = base_files();
    let units = [normal(0, 0, 10)];
    let touched = [TouchedFile {
        file_id: 1,
        path: "substituted.txt",
        path_salt: &FIXTURE_SALT,
    }];
    let bundle = BundleView {
        touched_files: &touched,
        ..empty_bundle()
    };
    structural_outcome(
        &ManifestView {
            files: &files,
            units: &units,
        },
        &bundle,
    )
}

fn verify_wrong_length_s_root() -> ActualOutcome {
    let files = base_files();
    let units = [normal(0, 0, 10)];
    let lengths = [DisclosedField {
        field: LengthField::SRoot,
        len: 31,
    }];
    let bundle = BundleView {
        disclosed_lengths: &lengths,
        ..empty_bundle()
    };
    structural_outcome(
        &ManifestView {
            files: &files,
            units: &units,
        },
        &bundle,
    )
}

/// The seeded M0 registry. Row ids are permanent; see the harness docs for
/// the add-a-row procedure.
const ROWS: &[TamperRow] = &[
    // ── F (F3 strict decode; base: the canonical map `{0: 1}`) ──
    TamperRow {
        id: "cbor-non-shortest-int",
        base: "canonical-map",
        mutation: "re-encode the value 1 in a two-byte head",
        expected: ExpectedOutcome::ErrorCode("cbor-non-shortest-int"),
        exercise: cbor_non_shortest_int,
    },
    TamperRow {
        id: "cbor-indefinite-length",
        base: "canonical-map",
        mutation: "re-encode the map with an indefinite-length head",
        expected: ExpectedOutcome::ErrorCode("cbor-indefinite-length"),
        exercise: cbor_indefinite_length,
    },
    TamperRow {
        id: "cbor-duplicate-map-key",
        base: "canonical-map",
        mutation: "repeat key 0 with a second value",
        expected: ExpectedOutcome::ErrorCode("cbor-duplicate-map-key"),
        exercise: cbor_duplicate_map_key,
    },
    TamperRow {
        id: "cbor-unsorted-map-keys",
        base: "canonical-map",
        mutation: "emit keys 1 then 0 (descending)",
        expected: ExpectedOutcome::ErrorCode("cbor-unsorted-map-keys"),
        exercise: cbor_unsorted_map_keys,
    },
    TamperRow {
        id: "cbor-truncated",
        base: "canonical-map",
        mutation: "cut the final byte",
        expected: ExpectedOutcome::ErrorCode("cbor-truncated"),
        exercise: cbor_truncated,
    },
    TamperRow {
        id: "cbor-trailing-bytes",
        base: "canonical-map",
        mutation: "append a byte after the complete item",
        expected: ExpectedOutcome::ErrorCode("cbor-trailing-bytes"),
        exercise: cbor_trailing_bytes,
    },
    TamperRow {
        id: "cbor-float",
        base: "canonical-map",
        mutation: "replace the value with a half-precision float",
        expected: ExpectedOutcome::ErrorCode("cbor-float"),
        exercise: cbor_float,
    },
    // ── C (C8 padding, C6 salt length; base: a padded 10-byte unit) ──
    TamperRow {
        id: "crypto-padding-length-mismatch",
        base: "padded-unit-10",
        mutation: "append one extra 256-byte pad bucket",
        expected: ExpectedOutcome::ErrorCode("crypto-padding-length-mismatch"),
        exercise: crypto_over_padded_unit,
    },
    TamperRow {
        id: "crypto-non-zero-padding",
        base: "padded-unit-10",
        mutation: "flip the final pad byte to 0x01",
        expected: ExpectedOutcome::ErrorCode("crypto-non-zero-padding"),
        exercise: crypto_non_zero_padding,
    },
    TamperRow {
        id: "crypto-path-salt-length",
        base: "path-salt-16",
        mutation: "truncate the disclosed path_salt to 15 bytes",
        expected: ExpectedOutcome::ErrorCode("crypto-path-salt-length"),
        exercise: crypto_path_salt_length,
    },
    // ── R (R3 structural; base: a 10-byte file tiled by two units) ──
    TamperRow {
        id: "verify-tiling-gap",
        base: "two-unit-file",
        mutation: "delete the second unit, leaving [4,10) uncovered",
        expected: ExpectedOutcome::ErrorCode("tiling-gap"),
        exercise: verify_tiling_gap,
    },
    TamperRow {
        id: "verify-tiling-overlap",
        base: "two-unit-file",
        mutation: "extend the first unit's range into the second's",
        expected: ExpectedOutcome::ErrorCode("tiling-overlap"),
        exercise: verify_tiling_overlap,
    },
    TamperRow {
        id: "verify-raw-mirror-in-tiling-set",
        base: "two-unit-file",
        mutation: "replace both units with the file's raw mirror",
        expected: ExpectedOutcome::ErrorCode("raw-mirror-in-tiling-set"),
        exercise: verify_raw_mirror_in_tiling_set,
    },
    TamperRow {
        id: "verify-unknown-unit-ref",
        base: "two-unit-file",
        mutation: "reveal a unit_id absent from the manifest",
        expected: ExpectedOutcome::ErrorCode("unknown-unit-ref"),
        exercise: verify_unknown_unit_ref,
    },
    TamperRow {
        id: "verify-duplicate-unit-reveal",
        base: "two-unit-file",
        mutation: "reveal the same unit_id twice",
        expected: ExpectedOutcome::ErrorCode("duplicate-unit-reveal"),
        exercise: verify_duplicate_unit_reveal,
    },
    TamperRow {
        id: "verify-path-commit-mismatch",
        base: "two-unit-file",
        mutation: "substitute the disclosed path, keeping the salt",
        expected: ExpectedOutcome::ErrorCode("path-commit-mismatch"),
        exercise: verify_path_commit_mismatch,
    },
    TamperRow {
        id: "verify-wrong-length-s-root",
        base: "two-unit-file",
        mutation: "shorten the disclosed s_root to 31 bytes",
        expected: ExpectedOutcome::ErrorCode("wrong-length-s-root"),
        exercise: verify_wrong_length_s_root,
    },
];

/// The **whole** M0 registry: the seed rows above plus every domain-owned
/// slice registered so far. Assembling them here is what makes the
/// cross-domain distinctness sweep real (error-code contract §4, layer 2) —
/// a collision between, say, a C row and an R row can only surface once
/// both sit in one registry.
///
/// Domains append their slice here as they land: C17 (crypto), G19 (fine
/// tree), R7 (structural), R8 (pipeline integration), F15 (format) and F22
/// (caps + D77's mirror-only shape) are present; A21's M2 anchor rows follow.
fn all_rows() -> Vec<TamperRow> {
    let mut rows = ROWS.to_vec();
    rows.extend_from_slice(antseal_core::test_util::tamper_rows_caps::ROWS);
    rows.extend_from_slice(antseal_core::test_util::tamper_rows_crypto::ROWS);
    rows.extend_from_slice(antseal_core::test_util::tamper_rows_fine_tree::ROWS);
    rows.extend_from_slice(antseal_core::test_util::tamper_rows_format::ROWS);
    rows.extend_from_slice(antseal_core::test_util::tamper_rows_structural::ROWS);
    rows.extend_from_slice(antseal_core::test_util::tamper_rows_pipeline::ROWS);
    rows
}

/// Every registered row produces exactly its distinct expected outcome, and
/// no row panics.
#[test]
fn tamper_registry_is_green() {
    let rows = all_rows();
    match check_registry(&rows) {
        Ok(count) => assert_eq!(count, rows.len()),
        Err(failures) => panic!("{}", render_failures(&failures)),
    }
}

/// The seeded rows span three domains, and their codes carry three
/// different domain prefixes — the cross-domain distinctness the contract
/// requires is actually being exercised, not just asserted within one
/// domain's meta-test.
#[test]
fn seeded_rows_span_multiple_domains() {
    let rows = all_rows();
    let prefixes = ["cbor-", "crypto-"];
    for prefix in prefixes {
        assert!(
            rows.iter().any(|row| matches!(
                row.expected,
                ExpectedOutcome::ErrorCode(code) if code.starts_with(prefix)
            )),
            "no seeded row binds a `{prefix}` code"
        );
    }
    // R's verify-side codes are unprefixed by construction (R1's scheme);
    // require the structural ones explicitly.
    for code in [
        "tiling-gap",
        "path-commit-mismatch",
        "raw-mirror-in-tiling-set",
    ] {
        assert!(
            rows.iter()
                .any(|row| row.expected == ExpectedOutcome::ErrorCode(code)),
            "no seeded row binds `{code}`"
        );
    }
    // The unprefixed R code `path-commit-mismatch` and C's own
    // `crypto-path-commit-mismatch` are genuinely different outcomes (R's
    // pipeline check vs C's commitment primitive) and must stay separable —
    // exactly the cross-domain case the prefix scheme exists for.
    assert!(
        rows.iter()
            .any(|row| row.expected == ExpectedOutcome::ErrorCode("crypto-path-commit-mismatch")),
        "no row binds `crypto-path-commit-mismatch`"
    );
}

/// **F15's fixture table, tied to the live registry.** Every format fixture
/// that names a row must name one that exists *and* expects the fixture's
/// code.
///
/// This is the check that keeps the fixture/row split honest in both
/// directions. A fixture pointing at a row that never existed would be a
/// coverage claim with nothing behind it; a fixture pointing at a row that
/// expects a *different* code would mean the committed bytes are evidence
/// for something other than what the row asserts. It has to live here rather
/// than beside the fixtures, because [`all_rows`] — which includes Q7's own
/// seed rows, and those are what the four spec-named body fixtures point
/// at — is this target's.
#[test]
fn the_format_fixture_table_agrees_with_the_live_registry() {
    use antseal_core::test_util::tamper_rows_format::all_fixtures;

    let rows = all_rows();
    let mut claimed = 0usize;
    for fixture in all_fixtures() {
        let Some(row_id) = fixture.row else {
            continue;
        };
        let row = rows.iter().find(|r| r.id == row_id).unwrap_or_else(|| {
            panic!(
                "fixture `{}` names row `{row_id}`, which is in no domain slice",
                fixture.id
            )
        });
        assert_eq!(
            row.expected,
            ExpectedOutcome::ErrorCode(fixture.code),
            "fixture `{}` is committed as evidence for row `{row_id}`, but they disagree about \
             the code",
            fixture.id
        );
        claimed += 1;
    }
    assert!(
        claimed
            >= antseal_core::test_util::tamper_rows_format::ROWS.len()
                + antseal_core::test_util::tamper_rows_caps::ROWS.len(),
        "every format-level row must be backed by at least one fixture"
    );
}

// ---------------------------------------------------------------------------
// Q8 — completeness against the spec's M0 row list
// (module docs: tests/tamper_completeness/mod.rs; registry:
// testdata/tamper/MATRIX.json)
// ---------------------------------------------------------------------------

/// Every family and case of MVP-SPEC.md line 168 maps onto implemented rows
/// or an explicitly owed one, every implemented row is accounted for
/// (spec case or declared project addition), and the pinned family counts
/// hold.
#[test]
fn tamper_matrix_is_mapped_1_to_1_onto_the_spec_row_list() {
    tamper_completeness::assert_registry_is_consistent(&all_rows());
}

/// The still-owed rows are exactly the enumerated ones, each naming its
/// owning task — the gap is visible rather than silent.
#[test]
fn tamper_matrix_pending_rows_are_the_enumerated_ones() {
    tamper_completeness::assert_pending_set_is_the_pinned_one(&all_rows());
}

/// Mutations that deliberately will NOT become rows are recorded with
/// their reasons (D28's full-reveal unit strip; the C-level GGM-seed
/// length), so nobody "completes" the matrix by adding one.
#[test]
fn tamper_matrix_records_its_deliberate_non_rows() {
    tamper_completeness::assert_non_rows_are_recorded(&all_rows());
}

/// Spec cases discharged **without a row** are exactly the pinned ones
/// (decision D81). This is the state that can make Q14's gate green by
/// argument rather than by a row, so the set is pinned outside the registry
/// and every addition is a reviewed event.
#[test]
fn tamper_matrix_non_row_discharges_are_the_pinned_ones() {
    tamper_completeness::assert_non_row_cases_are_the_pinned_ones(&all_rows());
}

/// Prints Q14's gate condition and the outstanding work every run.
#[test]
fn tamper_matrix_reports_the_q14_gate() {
    tamper_completeness::report_q14_gate(&all_rows());
}
