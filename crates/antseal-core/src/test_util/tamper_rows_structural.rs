//! **R's registry slice for the tamper matrix** (task R7): the M0
//! *structural* rows — every invariant a verifier decides from the shape of
//! a bundle and its signed manifest, each mutated in exactly one way from an
//! [R6 fixture](super::bundle_fixtures) and pinned to the distinct error it
//! must produce (MVP-SPEC.md lines 121, 168).
//!
//! The harness — distinctness, no-panic and exact-outcome assertions, and
//! the add-a-row procedure — is [`super::tamper`]; the code contract these
//! rows bind to is `docs/testing/error-code-contract.md`. Rows live here in
//! the library behind `test-util`, following
//! [`super::tamper_rows_crypto`]'s pattern, so the whole registry can be
//! assembled in one place for the cross-domain distinctness sweep.
//!
//! **Every row below binds an error code that already exists.** R7 mints
//! nothing: the codes came from R1–R5's shipped taxonomy, and a row that
//! could not find a distinct one would be a finding about the taxonomy, not
//! a licence to add one (contract §3).
//!
//! # Mutation is typed, never byte-patching
//!
//! A row sets exactly one [`Tweak`] field and rebuilds the fixture. That is
//! deliberate: a mutation expressed as "flip byte 412 of the encoded bundle"
//! silently becomes a different mutation the moment a map key moves, whereas
//! "record `true_length = width + 1` for unit 3" means the same thing
//! forever. It also keeps every fixture *decodable*, which is what makes
//! these rows structural rather than accidental re-runs of F's CBOR rows.
//!
//! # Which rows are direct-call rows, and why
//!
//! Seventeen of the twenty-three rows drive [`verify_bundle`], which is where
//! R7's Accept wants them. Six cannot, all for the *same* reason, and it is
//! a layering fact worth stating plainly:
//!
//! > **F8's bundle schema decodes every disclosed salt, seed, key and node
//! > hash into a fixed-size type, and makes `file_salt` mandatory inside a
//! > `full_reveals` entry.** Anything the schema can make unrepresentable is
//! > rejected at stage 1 with a `bundle-` code and never reaches R's stage.
//!
//! | row(s) | why not pipeline rows | how they are exercised |
//! | --- | --- | --- |
//! | the five `verify-wrong-length-*` rows | a wrong-length disclosed value is a `bundle-wrong-length-*` code at decode | direct [`check_structural`], exactly as the seeded `verify-wrong-length-s-root` row does |
//! | `verify-partial-reveal-salt-leak-s-root` | [`FullReveal`](crate::bundle::FullReveal) always carries a `file_salt`, so D28 row 1 fires first and row 2 is unreachable | direct [`classify_file_reveal`] |
//!
//! The length family was predicted by R5's rider (error-code contract §7).
//! **The `s_root` case is new at R7** and is the same layering effect in a
//! different field: it is recorded here rather than resolved by weakening a
//! code, because the R-level rule *is* right — R4 adjudicates the presence
//! of the two materials independently, and must keep doing so for the day
//! the bundle schema gains an `s_root`-only shape or R4 is driven by another
//! caller. The pipeline-level companion is asserted as a plain test
//! (`the_pipeline_route_to_an_s_root_leak_is_the_file_salt_row`) so the
//! unreachability is pinned rather than assumed.
//!
//! # Rows deliberately NOT here
//!
//! - **`fine-root-over-broad-cover`** and **`fine-root-binding-failed`** are
//!   **G19's**. R's wrapper arms surface the inner code unchanged (contract
//!   §2), so a G-level row and an R-level row would claim the same outcome
//!   and `check_registry` would correctly refuse the pair — the hazard Q8's
//!   registry recorded ahead of implementation. One row, one owner; R7's
//!   task text lists the over-broad cover, and R7 yields to G19 for it.
//! - **The unit-strip downgrade** (drop one revealed unit from a full reveal
//!   and leave `file_salt` attached). It surfaces as
//!   `partial-reveal-salt-leak-file-salt`, the same outcome as
//!   [`file_salt_leak`], because the two mutations are one observable
//!   failure. Recorded as a `non_rows` entry in
//!   `testdata/tamper/MATRIX.json` since D28, and asserted as a property in
//!   `verify::file_stages`.
//!
//! # The positive fixture
//!
//! `a_leaf_exact_sub_cover_on_a_partial_reveal_is_permitted` is the
//! counterweight R7's Notes require: a partial reveal that ships a genuine
//! multi-node GGM sub-cover **must verify**. Without it, an isolation check
//! that rejected *every* cover on *every* partial reveal would pass all the
//! negative rows above — the rows prove the rule fires, and only the
//! positive fixture proves it is not over-broad.
//!
//! [`Tweak`]: super::bundle_fixtures::Tweak
//! [`verify_bundle`]: crate::verify::verify_bundle
//! [`check_structural`]: crate::verify::check_structural
//! [`classify_file_reveal`]: crate::verify::classify_file_reveal

use crate::crypto::commit::path_commit;
use crate::crypto::material::Salt16;
use crate::verify::{
    BundleView, DisclosedField, FileCanonMode, FileEntry as StructuralFileEntry, FileFineTree,
    FileStageBundleView, FileUnitEntry, FileView, FullRevealMaterialEntry, LengthField,
    ManifestView, UnitEntry as StructuralUnitEntry, UnitKind as StructuralUnitKind, VerifyError,
    VerifyOptions, check_structural, classify_file_reveal, verify_bundle,
};

use super::bundle_fixtures::{
    BuiltFixture, FileSelection, FileSpec, Selection, Tweak, WorkSpec, build_tweaked, shapes,
};
use super::tamper::{ActualOutcome, ExpectedOutcome, TamperRow};

// ---------------------------------------------------------------------------
// the shared base fixtures
// ---------------------------------------------------------------------------

/// The base most rows mutate: R6's three-file work under the mixed
/// selection — file 0 fully revealed (text + raw mirror + fine tree), file 1
/// partially revealed (binary, `--split` into three units, middle unit
/// shown), file 2 untouched (`--no-fine-tree`).
///
/// One work carrying a full reveal, a partial reveal and an untouched file
/// at once is what lets most rows mutate the *same* artifact, which is what
/// the tamper matrix's "one mutation" claim actually means.
fn mixed(tweak: &Tweak) -> BuiltFixture {
    build_tweaked(
        &shapes::multi_file(),
        &shapes::multi_file_mixed_selection(),
        tweak,
    )
}

/// The full-reveal base: R6's three-file work with **everything** shown, so
/// the rows about full-reveal material and whole-file commitments have files
/// that are genuinely fully revealed.
fn all_revealed(tweak: &Tweak) -> BuiltFixture {
    build_tweaked(&shapes::multi_file(), &Selection::all(3), tweak)
}

/// Run a built fixture through the pipeline and report its first error.
fn pipeline(built: &BuiltFixture) -> ActualOutcome {
    ActualOutcome::from_result(
        verify_bundle(&built.bytes, &VerifyOptions::new()),
        VerifyError::code,
    )
}

/// Fixed, public, NON-SECRET salt for the direct-call rows' hand-built views.
const DIRECT_SALT: [u8; 16] = [0x77; 16];

// ---------------------------------------------------------------------------
// (1) tiling — the non-mirror range invariants (spec line 121)
// ---------------------------------------------------------------------------

fn tiling_out_of_bounds() -> ActualOutcome {
    // Widen file 1's LAST unit past the file's `size`: [20, 31) over a
    // 30-byte file. The unit is unrevealed, so nothing per-unit can fire
    // first and the verdict is purely the tiling group's.
    pipeline(&mixed(&Tweak {
        range_out_of_bounds: Some(4),
        ..Tweak::default()
    }))
}

fn tiling_unsorted() -> ActualOutcome {
    // Swap the manifest ranges of file 1's first two (equal-width) units, so
    // the unit table is no longer ascending by `range_start`. The ranges
    // still tile [0, 30) as a set — only their order changed, which is what
    // makes this distinct from the gap and overlap rows.
    pipeline(&mixed(&Tweak {
        unsorted_ranges: Some(1),
        ..Tweak::default()
    }))
}

// ---------------------------------------------------------------------------
// (2) per-unit extent — `true_length` vs the byte-range width
// ---------------------------------------------------------------------------

fn true_length_range_mismatch() -> ActualOutcome {
    // Unit 3 is revealed and 10 bytes wide. Recording `true_length = 11`
    // keeps it inside the same 256-byte padding bucket, so stage 2 (padding)
    // passes and stage 3 is what fires — which is the point: this row must
    // pin the extent rule, not the padding rule C already owns.
    pipeline(&mixed(&Tweak {
        true_length_excess: Some(3),
        ..Tweak::default()
    }))
}

// ---------------------------------------------------------------------------
// (2b) padding, END TO END through the pipeline
// ---------------------------------------------------------------------------
//
// Q7's seed rows already pin C8's `strip_padding` primitive
// (`crypto-padding-length-mismatch`, `crypto-non-zero-padding`). These are the
// R-level codes the *pipeline* raises for the same two defects, and they are
// genuinely distinct outcomes: R's payload is recomputed from the manifest's
// `true_length` in wide arithmetic so the rendered error is identical on
// native and wasm32, which is a claim only a pipeline row can exercise.
//
// The mis-encryption is C9's own (`crypto::unit_aead::mis_encrypt`), so both
// rows prove the ordering that matters: the padding rejections fire strictly
// AFTER the AEAD authenticates, never as a length heuristic before it.

fn padded_length_mismatch() -> ActualOutcome {
    pipeline(&mixed(&Tweak {
        over_pad: Some(3),
        ..Tweak::default()
    }))
}

fn non_zero_padding() -> ActualOutcome {
    pipeline(&mixed(&Tweak {
        non_zero_pad: Some(3),
        ..Tweak::default()
    }))
}

// ---------------------------------------------------------------------------
// (3) referential integrity
// ---------------------------------------------------------------------------

fn unknown_file_ref() -> ActualOutcome {
    // A `touched_files` entry naming a `file_id` the signed file table does
    // not have. Distinct from D82's row below (an *existing* file with no
    // revealed unit), and it fires earlier: R3 group 3 rejects the dangling
    // reference before coherence ever runs.
    pipeline(&mixed(&Tweak {
        unknown_touched_file: Some(9),
        ..Tweak::default()
    }))
}

/// **D82's rule**: `touched_files` must *equal* the set of files with a
/// revealed unit, so an entry for a file the bundle reveals nothing from is
/// rejected at coherence group 1b.
///
/// The mutation splices in a **genuine** `{path, path_salt}` pair for file
/// 2 — the mixed selection's untouched file. That is the whole difficulty:
/// `check_path_commits` runs in stage 2 *before* coherence and iterates the
/// bundle's list, so a junk salt or an invented path would make this row
/// silently pin `path-commit-mismatch` instead. R7 pins the fixture's
/// impeccability separately in
/// `the_d82_fixture_is_impeccable_except_for_the_d82_question`.
///
/// The pair being genuine is also the *reason* for the rule: `path_salt =
/// HKDF(W, "path-salt", file_id)` is a per-work constant, so this is not a
/// forgery a relay has to break a commitment for — it is a copy from any
/// other bundle of the same work.
fn touched_file_without_revealed_unit() -> ActualOutcome {
    pipeline(&mixed(&Tweak {
        touch_without_reveal: Some(2),
        ..Tweak::default()
    }))
}

/// **D80's rule**: a revealed unit's file must appear in `touched_files`.
/// File 1 is partially revealed and carries no full reveal, so its path can
/// be dropped without F8's `full_reveals ⊆ touched_files` rule firing first.
fn revealed_unit_file_not_touched() -> ActualOutcome {
    pipeline(&mixed(&Tweak {
        drop_touched_file: Some(1),
        ..Tweak::default()
    }))
}

// ---------------------------------------------------------------------------
// (3b) reveal-section agreement — a unit in the section its binding forbids
// ---------------------------------------------------------------------------
//
// Named from the BUNDLE's mistake, because that is what a tamper row
// mutates: the manifest binding is signed and is the fact of the matter.

fn covered_unit_revealed_as_non_covered() -> ActualOutcome {
    // Unit 0 is a fine-tree-covered normal unit of file 0.
    pipeline(&mixed(&Tweak {
        misplace_covered_unit: Some(0),
        ..Tweak::default()
    }))
}

fn non_covered_unit_revealed_as_covered() -> ActualOutcome {
    // Unit 1 is file 0's raw mirror — non-covered by kind, whatever its
    // file's fine-tree state (spec line 94).
    pipeline(&mixed(&Tweak {
        misplace_noncovered_unit: Some(1),
        ..Tweak::default()
    }))
}

// ---------------------------------------------------------------------------
// (4) partial-reveal isolation (D28 rows 1–2)
// ---------------------------------------------------------------------------

fn file_salt_leak() -> ActualOutcome {
    // Attach file 1's full-reveal material even though only one of its three
    // units is shown. This is the third-party proof-downgrade shape as well
    // as the sealer-error shape.
    pipeline(&mixed(&Tweak {
        leak_full_material: Some(1),
        ..Tweak::default()
    }))
}

/// Direct-call row: [`FullReveal`](crate::bundle::FullReveal) makes
/// `file_salt` mandatory, so a bundle can never present `s_root` alone and
/// D28 row 2 is unreachable through the pipeline (module docs).
fn s_root_leak() -> ActualOutcome {
    let raw_commit = [0x11u8; 32];
    let fine_root = [0x22u8; 32];
    let file = FileView {
        file_id: 0,
        size: 8,
        canon: FileCanonMode::Binary,
        raw_commit: &raw_commit,
        fine_tree: FileFineTree::Present { root: &fine_root },
    };
    let units = [FileUnitEntry {
        unit_id: 0,
        file_id: 0,
        kind: StructuralUnitKind::Normal,
    }];
    // Nothing revealed ⇒ ¬full(F); material carrying `s_root` and no
    // `file_salt` therefore lands on row 2 rather than row 1.
    let s_root = [0x33u8; 32];
    let material = [FullRevealMaterialEntry {
        file_id: 0,
        file_salt: None,
        s_root: Some(&s_root),
    }];
    ActualOutcome::from_result(
        classify_file_reveal(
            &file,
            &units,
            &FileStageBundleView {
                revealed_unit_ids: &[],
                full_material: &material,
            },
        ),
        VerifyError::code,
    )
}

// ---------------------------------------------------------------------------
// (5) full-reveal material: missing (D28 rows 3–4) and extraneous (D74, row 5)
// ---------------------------------------------------------------------------

fn full_reveal_missing_file_salt() -> ActualOutcome {
    pipeline(&all_revealed(&Tweak {
        drop_full_material: Some(0),
        ..Tweak::default()
    }))
}

fn full_reveal_missing_s_root() -> ActualOutcome {
    pipeline(&all_revealed(&Tweak {
        drop_s_root: Some(0),
        ..Tweak::default()
    }))
}

/// D74's direction: **extra** material. File 2 of the base work has no fine
/// tree, so an `s_root` for it is material the rule does not require.
fn full_reveal_extraneous_s_root() -> ActualOutcome {
    pipeline(&all_revealed(&Tweak {
        extraneous_s_root: Some(2),
        ..Tweak::default()
    }))
}

// ---------------------------------------------------------------------------
// (6) whole-file content commitments (D28 rows 7–10)
// ---------------------------------------------------------------------------

/// A text file's concatenation opens `canon_commit` (row 7).
fn concat_commit_mismatch_canon() -> ActualOutcome {
    pipeline(&all_revealed(&Tweak {
        corrupt_canon_commit: Some(0),
        ..Tweak::default()
    }))
}

/// A **binary** file's concatenation opens `raw_commit` instead — the same
/// check, the other arm, its own code.
fn concat_commit_mismatch_raw() -> ActualOutcome {
    pipeline(&all_revealed(&Tweak {
        corrupt_raw_commit: Some(1),
        ..Tweak::default()
    }))
}

/// On a *text* file the concatenation check opens `canon_commit`, so a
/// corrupt `raw_commit` survives row 7 and is caught by the raw-mirror
/// binding at row 9. Two rows reach two different codes from the same
/// corrupted field — which is why both exist.
fn raw_commit_mismatch() -> ActualOutcome {
    pipeline(&all_revealed(&Tweak {
        corrupt_raw_commit: Some(0),
        ..Tweak::default()
    }))
}

/// D75's second route: the disclosed `s_root` must rebuild `fine_root`. The
/// per-unit cover seeds are left correct, so stage 3 passes and the
/// whole-file rebuild at row 8 is what fires — the two routes to `fine_root`
/// genuinely disagreeing.
fn fine_root_rebuild_mismatch() -> ActualOutcome {
    pipeline(&all_revealed(&Tweak {
        corrupt_disclosed_s_root: Some(0),
        ..Tweak::default()
    }))
}

/// Raw-mirror bytes that do not canonicalize to the file's canonical bytes
/// (row 10). Expressed as a fixture knob rather than a byte patch: the raw
/// bytes — and therefore `raw_commit` and the mirror's `unit_commit` — stay
/// self-consistent, and it is the *canonical domain* that is not what those
/// raw bytes canonicalize to. A patched mirror would fail row 9 first and
/// pin the wrong code.
fn raw_mirror_canonicalization_mismatch() -> ActualOutcome {
    let spec = WorkSpec::new(
        "raw mirror canonicalization mismatch",
        vec![
            FileSpec::text("notes/intro.md", shapes::CRLF_TEXT)
                .with_canonical_override(b"not what those raw bytes canonicalize to\n".to_vec()),
        ],
    );
    pipeline(&build_tweaked(
        &spec,
        &Selection(vec![FileSelection::Full]),
        &Tweak::default(),
    ))
}

// ---------------------------------------------------------------------------
// (7) exact lengths — the six spec-mandated classes, at the R level
// ---------------------------------------------------------------------------
//
// F8 rejects a wrong-length disclosed value at decode with a `bundle-` code,
// so these are direct-call rows on R3's group 1 — the pattern the seeded
// `verify-wrong-length-s-root` row established. They keep R's length codes
// reachable and pinned for the day a field is relaxed to a variable-length
// byte string, which is exactly why R5 kept the group running as a backstop.

fn length_row(field: LengthField, len: u64) -> ActualOutcome {
    let files = [StructuralFileEntry {
        file_id: 0,
        size: 4,
        path_commit: path_commit(&Salt16::from_bytes(DIRECT_SALT), "a.txt"),
    }];
    let units = [StructuralUnitEntry {
        unit_id: 0,
        file_id: 0,
        kind: StructuralUnitKind::Normal,
        range_start: 0,
        range_end: 4,
    }];
    let lengths = [DisclosedField { field, len }];
    ActualOutcome::from_result(
        check_structural(
            &ManifestView {
                files: &files,
                units: &units,
            },
            &BundleView {
                revealed_unit_ids: &[],
                touched_files: &[],
                proof_unit_refs: &[],
                disclosed_lengths: &lengths,
            },
        ),
        VerifyError::code,
    )
}

fn wrong_length_unit_salt() -> ActualOutcome {
    length_row(LengthField::UnitSalt, 15)
}

fn wrong_length_path_salt() -> ActualOutcome {
    length_row(LengthField::PathSalt, 15)
}

fn wrong_length_file_salt() -> ActualOutcome {
    length_row(LengthField::FileSalt, 17)
}

fn wrong_length_ggm_covering_seed() -> ActualOutcome {
    length_row(LengthField::GgmCoveringSeed, 31)
}

fn wrong_length_boundary_node_hash() -> ActualOutcome {
    length_row(LengthField::BoundaryNodeHash, 33)
}

// ---------------------------------------------------------------------------
// the registry slice
// ---------------------------------------------------------------------------

/// R's M0 structural rows. Ids are permanent; see [`super::tamper`]'s module
/// docs for the add-a-row procedure and `docs/testing/error-code-contract.md`
/// for what a code is and why none of these may be edited.
pub const ROWS: &[TamperRow] = &[
    // ── tiling ──
    TamperRow {
        id: "verify-tiling-out-of-bounds",
        base: "r6-multi-file-mixed",
        mutation: "widen the last unit's range past the file's size",
        expected: ExpectedOutcome::ErrorCode("tiling-out-of-bounds"),
        exercise: tiling_out_of_bounds,
    },
    TamperRow {
        id: "verify-tiling-unsorted",
        base: "r6-multi-file-mixed",
        mutation: "swap two equal-width units' ranges, breaking ascending order",
        expected: ExpectedOutcome::ErrorCode("tiling-unsorted"),
        exercise: tiling_unsorted,
    },
    // ── per-unit extent ──
    TamperRow {
        id: "verify-true-length-range-mismatch",
        base: "r6-multi-file-mixed",
        mutation: "record true_length = range width + 1 for a revealed unit",
        expected: ExpectedOutcome::ErrorCode("true-length-range-mismatch"),
        exercise: true_length_range_mismatch,
    },
    TamperRow {
        id: "verify-padded-length-mismatch",
        base: "r6-multi-file-mixed",
        mutation: "encrypt a revealed unit one 256-byte pad bucket too long",
        expected: ExpectedOutcome::ErrorCode("padded-length-mismatch"),
        exercise: padded_length_mismatch,
    },
    TamperRow {
        id: "verify-non-zero-padding",
        base: "r6-multi-file-mixed",
        mutation: "encrypt a revealed unit with a non-zero final pad byte",
        expected: ExpectedOutcome::ErrorCode("non-zero-padding"),
        exercise: non_zero_padding,
    },
    // ── referential integrity ──
    TamperRow {
        id: "verify-unknown-file-ref",
        base: "r6-multi-file-mixed",
        mutation: "disclose a touched file whose file_id the manifest has no row for",
        expected: ExpectedOutcome::ErrorCode("unknown-file-ref"),
        exercise: unknown_file_ref,
    },
    TamperRow {
        id: "verify-revealed-unit-file-not-touched",
        base: "r6-multi-file-mixed",
        mutation: "omit the touched_files entry of a file whose unit is revealed",
        expected: ExpectedOutcome::ErrorCode("revealed-unit-file-not-touched"),
        exercise: revealed_unit_file_not_touched,
    },
    TamperRow {
        id: "verify-touched-file-without-revealed-unit",
        base: "r6-multi-file-mixed",
        mutation: "splice a genuine {path, path_salt} entry for a file the bundle reveals \
                   nothing from",
        expected: ExpectedOutcome::ErrorCode("touched-file-without-revealed-unit"),
        exercise: touched_file_without_revealed_unit,
    },
    // ── reveal-section agreement ──
    TamperRow {
        id: "verify-covered-unit-revealed-as-non-covered",
        base: "r6-multi-file-mixed",
        mutation: "ship a fine-tree-covered unit in the non-covered reveal section",
        expected: ExpectedOutcome::ErrorCode("covered-unit-revealed-as-non-covered"),
        exercise: covered_unit_revealed_as_non_covered,
    },
    TamperRow {
        id: "verify-non-covered-unit-revealed-as-covered",
        base: "r6-multi-file-mixed",
        mutation: "ship a raw mirror in the covered reveal section",
        expected: ExpectedOutcome::ErrorCode("non-covered-unit-revealed-as-covered"),
        exercise: non_covered_unit_revealed_as_covered,
    },
    // ── partial-reveal isolation (D28 rows 1–2) ──
    TamperRow {
        id: "verify-partial-reveal-salt-leak-file-salt",
        base: "r6-multi-file-mixed",
        mutation: "attach a partially revealed file's file_salt",
        expected: ExpectedOutcome::ErrorCode("partial-reveal-salt-leak-file-salt"),
        exercise: file_salt_leak,
    },
    TamperRow {
        id: "verify-partial-reveal-salt-leak-s-root",
        base: "hand-built-file-view",
        mutation: "present s_root without file_salt for a file that is not fully revealed",
        expected: ExpectedOutcome::ErrorCode("partial-reveal-salt-leak-s-root"),
        exercise: s_root_leak,
    },
    // ── full-reveal material (D28 rows 3–5) ──
    TamperRow {
        id: "verify-full-reveal-missing-file-salt",
        base: "r6-multi-file-all",
        mutation: "strip a fully revealed file's full-reveal entry",
        expected: ExpectedOutcome::ErrorCode("full-reveal-material-missing-file-salt"),
        exercise: full_reveal_missing_file_salt,
    },
    TamperRow {
        id: "verify-full-reveal-missing-s-root",
        base: "r6-multi-file-all",
        mutation: "strip the s_root from a fine-tree file's full-reveal entry",
        expected: ExpectedOutcome::ErrorCode("full-reveal-material-missing-s-root"),
        exercise: full_reveal_missing_s_root,
    },
    TamperRow {
        id: "verify-full-reveal-s-root-without-fine-tree",
        base: "r6-multi-file-all",
        mutation: "attach an s_root to a --no-fine-tree file's full-reveal entry",
        expected: ExpectedOutcome::ErrorCode("full-reveal-s-root-without-fine-tree"),
        exercise: full_reveal_extraneous_s_root,
    },
    // ── whole-file content commitments (D28 rows 7–10) ──
    TamperRow {
        id: "verify-concat-commit-mismatch-canon",
        base: "r6-multi-file-all",
        mutation: "flip a bit of a fully revealed text file's canon_commit",
        expected: ExpectedOutcome::ErrorCode("concat-commit-mismatch-canon"),
        exercise: concat_commit_mismatch_canon,
    },
    TamperRow {
        id: "verify-concat-commit-mismatch-raw",
        base: "r6-multi-file-all",
        mutation: "flip a bit of a fully revealed binary file's raw_commit",
        expected: ExpectedOutcome::ErrorCode("concat-commit-mismatch-raw"),
        exercise: concat_commit_mismatch_raw,
    },
    TamperRow {
        id: "verify-raw-commit-mismatch",
        base: "r6-multi-file-all",
        mutation: "flip a bit of a fully revealed TEXT file's raw_commit (its mirror opens it)",
        expected: ExpectedOutcome::ErrorCode("raw-commit-mismatch"),
        exercise: raw_commit_mismatch,
    },
    TamperRow {
        id: "verify-fine-root-rebuild-mismatch",
        base: "r6-multi-file-all",
        mutation: "flip a bit of the disclosed s_root, leaving the cover seeds correct",
        expected: ExpectedOutcome::ErrorCode("fine-root-rebuild-mismatch"),
        exercise: fine_root_rebuild_mismatch,
    },
    TamperRow {
        id: "verify-raw-mirror-canonicalization-mismatch",
        base: "r6-text-with-canonical-override",
        mutation: "canonical bytes that are not what the raw-mirror bytes canonicalize to",
        expected: ExpectedOutcome::ErrorCode("raw-mirror-canonicalization-mismatch"),
        exercise: raw_mirror_canonicalization_mismatch,
    },
    // ── exact lengths (R3 group 1, direct-call — module docs) ──
    TamperRow {
        id: "verify-wrong-length-unit-salt",
        base: "one-unit-file-view",
        mutation: "disclose a 15-byte unit_salt",
        expected: ExpectedOutcome::ErrorCode("wrong-length-unit-salt"),
        exercise: wrong_length_unit_salt,
    },
    TamperRow {
        id: "verify-wrong-length-path-salt",
        base: "one-unit-file-view",
        mutation: "disclose a 15-byte path_salt",
        expected: ExpectedOutcome::ErrorCode("wrong-length-path-salt"),
        exercise: wrong_length_path_salt,
    },
    TamperRow {
        id: "verify-wrong-length-file-salt",
        base: "one-unit-file-view",
        mutation: "disclose a 17-byte file_salt",
        expected: ExpectedOutcome::ErrorCode("wrong-length-file-salt"),
        exercise: wrong_length_file_salt,
    },
    TamperRow {
        id: "verify-wrong-length-ggm-covering-seed",
        base: "one-unit-file-view",
        mutation: "disclose a 31-byte GGM covering seed",
        expected: ExpectedOutcome::ErrorCode("wrong-length-ggm-covering-seed"),
        exercise: wrong_length_ggm_covering_seed,
    },
    TamperRow {
        id: "verify-wrong-length-boundary-node-hash",
        base: "one-unit-file-view",
        mutation: "disclose a 33-byte boundary Merkle node hash",
        expected: ExpectedOutcome::ErrorCode("wrong-length-boundary-node-hash"),
        exercise: wrong_length_boundary_node_hash,
    },
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::SealProof;

    // -----------------------------------------------------------------
    // the POSITIVE fixture — R7's Notes
    // -----------------------------------------------------------------

    /// **The counterweight to every row above.** A partial reveal that ships
    /// a genuine, multi-node, leaf-exact GGM sub-cover **must verify**.
    ///
    /// Without this, an isolation check that rejected *every* cover on
    /// *every* partial reveal would satisfy all of the negative rows. The
    /// rows prove the rule fires; only this proves it is not over-broad.
    #[test]
    fn a_leaf_exact_sub_cover_on_a_partial_reveal_is_permitted() {
        // The `--split` text shape with only its middle unit shown. Its
        // canonical form is 34 bytes split 12/12/10, so the revealed range
        // is [12, 24) on a depth-6 grid — deliberately NOT a single dyadic
        // node, so the cover is genuinely multi-entry and the isolation
        // check has something real to be over-broad about.
        let built = build_tweaked(
            &shapes::split_multi_unit(),
            &Selection(vec![FileSelection::Units(vec![1])]),
            &Tweak::default(),
        );
        let report = verify_bundle(&built.bytes, &VerifyOptions::new())
            .expect("a leaf-exact sub-cover on a partial reveal must VERIFY");
        assert!(report.evidence.passed);

        let proof = SealProof::decode(&built.bytes).expect("decodes");
        let covers: usize = proof
            .bundle()
            .covered_reveals()
            .iter()
            .map(|reveal| reveal.cover().len())
            .sum();
        assert!(
            covers >= 2,
            "the positive fixture must carry a genuinely multi-node cover, got {covers}"
        );
        // …and it is still a partial reveal, so no material was disclosed.
        assert!(proof.bundle().full_reveals().is_empty());
    }

    /// The other half of the positive matrix: two of three units opened
    /// while the third stays dark — the shape whose cover must span exactly
    /// the two revealed spans and nothing between them.
    #[test]
    fn a_partial_reveal_of_two_of_three_units_verifies() {
        let built = build_tweaked(
            &shapes::split_multi_unit(),
            &Selection(vec![FileSelection::Units(vec![0, 2])]),
            &Tweak::default(),
        );
        assert!(
            verify_bundle(&built.bytes, &VerifyOptions::new())
                .expect("two-of-three must verify")
                .evidence
                .passed
        );
    }

    /// …and the same at the **unbalanced n = 6** leaf count, where the
    /// dyadic grid is padded with phantom leaves. A cover node there may
    /// legitimately extend past the last real leaf, which is precisely the
    /// case an over-eager isolation check would reject.
    #[test]
    fn a_partial_reveal_at_unbalanced_n6_is_permitted() {
        let built = build_tweaked(
            &shapes::unbalanced_n6(),
            &Selection(vec![FileSelection::Units(vec![2])]),
            &Tweak::default(),
        );
        assert!(
            verify_bundle(&built.bytes, &VerifyOptions::new())
                .expect("the unbalanced partial reveal must verify")
                .evidence
                .passed
        );
    }

    // -----------------------------------------------------------------
    // the unreachability pin (module docs)
    // -----------------------------------------------------------------

    /// Pins the layering fact the `s_root`-leak row is a direct-call row
    /// *because of*: through the pipeline, a bundle presenting `s_root` on a
    /// partial reveal necessarily presents `file_salt` too, so D28 row 1
    /// claims the verdict. If F8 ever gains an `s_root`-only shape, this
    /// test goes red and the row becomes a pipeline row.
    #[test]
    fn the_pipeline_route_to_an_s_root_leak_is_the_file_salt_row() {
        let built = mixed(&Tweak {
            leak_full_material: Some(1),
            ..Tweak::default()
        });
        let err = verify_bundle(&built.bytes, &VerifyOptions::new()).expect_err("must not verify");
        assert_eq!(err.code(), "partial-reveal-salt-leak-file-salt");
    }

    /// **D82's fixture, handed to stage 2.** The decision resolved to
    /// *reject* a `touched_files` entry for a file with no revealed unit,
    /// minting `touched-file-without-revealed-unit` at R5's coherence group.
    /// R7 owed a fixture impeccable in **every respect except** the D82
    /// question itself; the rule has since landed, and
    /// [`touched_file_without_revealed_unit`] is now the row built on it.
    ///
    /// This test was written to survive that landing and is deliberately
    /// unchanged by it: the spliced entry's `path_salt` genuinely opens the
    /// manifest's `path_commit`, so the row can never silently pin
    /// `path-commit-mismatch` instead. Before the rule landed the fixture
    /// verified; now it fails with D82's code — and in neither case may it
    /// fail on the path. Keeping the tolerant `if let Err` shape is the
    /// point: it makes the assertion about *which* rejection is legitimate,
    /// not about whether one happens.
    #[test]
    fn the_d82_fixture_is_impeccable_except_for_the_d82_question() {
        // File 2 of the base work is untouched by the mixed selection, so it
        // is the file that can carry a reveal-free touched entry.
        let built = mixed(&Tweak {
            touch_without_reveal: Some(2),
            ..Tweak::default()
        });
        if let Err(err) = verify_bundle(&built.bytes, &VerifyOptions::new()) {
            assert_ne!(
                err.code(),
                "path-commit-mismatch",
                "the D82 fixture's path_salt must open path_commit — otherwise D82's row would \
                 pin the wrong failure"
            );
            assert_eq!(
                err.code(),
                "touched-file-without-revealed-unit",
                "the only legitimate rejection of this fixture is D82's own"
            );
        }
    }

    /// Every row's base fixture must itself be **valid** — otherwise a row
    /// could "pass" by pinning a defect the mutation had nothing to do with.
    #[test]
    fn every_base_fixture_verifies_before_it_is_mutated() {
        for built in [mixed(&Tweak::default()), all_revealed(&Tweak::default())] {
            assert!(
                verify_bundle(&built.bytes, &VerifyOptions::new())
                    .expect("a row's base must verify")
                    .evidence
                    .passed
            );
        }
    }

    // -----------------------------------------------------------------
    // R7 Accept bullet 2 — the reverse coverage check
    // -----------------------------------------------------------------

    /// Codes covered by the **Q7 seed rows** in `tests/tamper_matrix.rs`.
    ///
    /// Named here rather than read from there because the seed registry is
    /// an integration test and this check is a lib test — and naming them is
    /// the point: a seed row deleted without moving its code into this list
    /// turns the sweep in `tests/tamper_matrix.rs` red instead.
    const COVERED_BY_SEED_ROWS: &[&str] = &[
        "tiling-gap",
        "tiling-overlap",
        "raw-mirror-in-tiling-set",
        "unknown-unit-ref",
        "duplicate-unit-reveal",
        "path-commit-mismatch",
        "wrong-length-s-root",
    ];

    /// Codes another task still owes a row for, each named with its owner.
    /// Q8's `MATRIX.json` holds the same gap against the *spec's* case list;
    /// this holds it against the *error enum*, which is the direction that
    /// catches an invariant nobody wrote a spec case for.
    const OWED_BY_ANOTHER_TASK: &[(&str, &str)] = &[
        ("unit-decrypt-failed", "R8 — flipped ciphertext byte"),
        (
            "unit-commit-mismatch",
            "R8 — altered manifest field, non-covered unit",
        ),
    ];

    /// **R7 Accept bullet 2.** Every code R's own (unprefixed) namespace can
    /// emit is accounted for: claimed by a row here, by a Q7 seed row, or
    /// explicitly owed by a named task.
    ///
    /// This is the direction Q8's registry cannot check. Q8 maps the *spec's*
    /// enumeration onto rows; this maps the *implementation's* error enum
    /// onto rows, so adding a new structural invariant — a new `VerifyError`
    /// variant or a new kind discriminator — without a row, a seed row, or a
    /// recorded owner fails CI. Wrapper-arm codes are excluded by prefix:
    /// they belong to the domain that minted them (contract §2), and F/C/G
    /// own their rows.
    #[test]
    fn every_unprefixed_verify_code_has_a_row_or_a_named_owner() {
        let owned_prefixes = [
            "cbor-",
            "manifest-",
            "bundle-",
            "crypto-",
            "content-",
            "fine-root-",
        ];
        let mut unaccounted: Vec<&'static str> = Vec::new();

        for exemplar in crate::verify::error::all_error_exemplars() {
            let code = exemplar.code();
            if owned_prefixes.iter().any(|prefix| code.starts_with(prefix)) {
                continue;
            }
            let claimed_here = ROWS
                .iter()
                .any(|row| row.expected == ExpectedOutcome::ErrorCode(code));
            let seeded = COVERED_BY_SEED_ROWS.contains(&code);
            let owed = OWED_BY_ANOTHER_TASK.iter().any(|(owed, _)| *owed == code);
            if !claimed_here && !seeded && !owed {
                unaccounted.push(code);
            }
        }

        assert!(
            unaccounted.is_empty(),
            "these R-level codes have no tamper row and no named owner: {unaccounted:?}\n\
             A new structural invariant needs a row here, a seed row, or an entry in \
             OWED_BY_ANOTHER_TASK naming the task that owes it — the whole point of this check \
             is that the third option is a deliberate, reviewed statement rather than silence."
        );
    }

    /// The accounting lists must not go stale in the other direction either:
    /// a code recorded as owed, or as seeded, must still be a real code, and
    /// must not *also* be claimed by a row here.
    #[test]
    fn the_coverage_accounting_lists_are_not_stale() {
        let universe: Vec<&'static str> = crate::verify::error::all_error_exemplars()
            .iter()
            .map(VerifyError::code)
            .collect();
        for code in COVERED_BY_SEED_ROWS
            .iter()
            .chain(OWED_BY_ANOTHER_TASK.iter().map(|(code, _)| code))
        {
            assert!(
                universe.contains(code),
                "`{code}` is recorded in a coverage list but no VerifyError variant emits it"
            );
            assert!(
                !ROWS
                    .iter()
                    .any(|row| row.expected == ExpectedOutcome::ErrorCode(code)),
                "`{code}` is recorded as covered elsewhere AND claimed by a row here — \
                 check_registry would refuse the pair"
            );
        }
    }

    /// Every code this slice binds already existed in R's shipped taxonomy —
    /// R7 mints nothing (module docs; contract §3).
    #[test]
    fn every_expected_code_is_a_real_verify_error_code() {
        let universe: Vec<&'static str> = crate::verify::error::all_error_exemplars()
            .iter()
            .map(VerifyError::code)
            .collect();
        for row in ROWS {
            let ExpectedOutcome::ErrorCode(code) = row.expected else {
                panic!("row `{}` is not an error-code row", row.id);
            };
            assert!(
                universe.contains(&code),
                "row `{}` binds `{code}`, which no VerifyError variant emits",
                row.id
            );
        }
    }

    /// The slice's own codes are pairwise distinct (contract §4 layer 1);
    /// the cross-domain sweep is `tests/tamper_matrix.rs`'s.
    #[test]
    fn the_slice_is_internally_distinct() {
        let mut seen: Vec<String> = Vec::new();
        for row in ROWS {
            let key = row.expected.key();
            assert!(
                !seen.contains(&key),
                "row `{}` re-claims outcome `{key}`",
                row.id
            );
            seen.push(key);
        }
    }

    /// The rows G19 owns must stay absent from R's slice, or `check_registry`
    /// would refuse the pair when both land (Q8's recorded hazard).
    #[test]
    fn the_fine_tree_rows_stay_g19s() {
        for code in ["fine-root-binding-failed", "fine-root-over-broad-cover"] {
            assert!(
                !ROWS
                    .iter()
                    .any(|row| row.expected == ExpectedOutcome::ErrorCode(code)),
                "`{code}` is G19's row — R's wrapper surfaces the inner code unchanged, so a \
                 second row here would collide"
            );
        }
    }
}
