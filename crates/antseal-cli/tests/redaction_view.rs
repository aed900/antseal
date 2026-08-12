//! **R19 — the redaction view and its CLI renderer**, over real bundles.
//!
//! MVP-SPEC.md line 121:
//!
//! > *"Every reveal displays position + total size (anti-out-of-context
//! > guardrail); unrevealed units render as sized blackout blocks;
//! > unrevealed files render as committed placeholders (size only, path
//! > withheld)."*
//!
//! Every fixture here is a real `.sealproof` built by R6's constructor and
//! put through `verify_bundle`, so the views under test are derived from
//! reports the pipeline actually produced — the tiling invariant, the
//! full-reveal classification and the R53 mirror rule included. A hand-built
//! `RevealSet` would let a shape into the snapshot that no sealer can make;
//! the model's own unit tests
//! (`crates/antseal-core/src/verify/redaction.rs`) cover the hostile shapes
//! a `pub`-fielded report *can* be handed.
//!
//! To regenerate the committed rendering after a **deliberate** change:
//!
//! ```text
//! ANTSEAL_BLESS=1 cargo test -p antseal-cli --test redaction_view
//! ```

use antseal_cli::redaction_out::render_report;
use antseal_core::test_util::bundle_fixtures::{
    FileSelection, FileSpec, Selection, WorkSpec, build, shapes,
};
use antseal_core::verify::redaction::RedactionView;
use antseal_core::verify::report::VerificationReport;
use antseal_core::verify::{VerifyOptions, verify_bundle};

/// The committed rendering.
const SNAPSHOT_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/snapshots/redaction-view.txt"
);

// ─────────────────────────────────────────────────────────────────────
// the five Accept shapes, as real verified bundles
// ─────────────────────────────────────────────────────────────────────

/// One case: a name for the document, the work, and the reveal selection.
struct Case {
    name: &'static str,
    spec: WorkSpec,
    selection: Selection,
}

/// The five shapes R19's Accept row names, in document order.
fn cases() -> Vec<Case> {
    vec![
        Case {
            // Three units, the middle one revealed: a blackout block on
            // either side of it, which is the interleave the report does
            // not carry and this view exists to produce.
            name: "partial reveal — one unit of three",
            spec: shapes::split_multi_unit(),
            selection: Selection(vec![FileSelection::Units(vec![1])]),
        },
        Case {
            // One unit, revealed, plus the raw mirror that rides along
            // with a full reveal (D70).
            name: "full reveal — whole file, mirror rides along",
            spec: shapes::single_text_with_mirror(),
            selection: Selection::all(1),
        },
        Case {
            // File 0 full (with mirror), file 1 partial, file 2 revealed
            // by nothing — the committed-placeholder shape.
            name: "multi-file — full, partial, and a withheld file",
            spec: shapes::multi_file(),
            selection: shapes::multi_file_mixed_selection(),
        },
        Case {
            // `--no-fine-tree`: one whole-file unit bound by `unit_commit`,
            // so the file is a single block spanning itself.
            name: "--no-fine-tree — one whole-file unit",
            spec: shapes::no_fine_tree(),
            selection: Selection::all(1),
        },
        Case {
            // size = 0, one empty unit: the zero-width block, and the
            // denominator that a naive percentage would divide by.
            name: "empty file — a zero-width block at offset 0",
            spec: shapes::empty_file(),
            selection: Selection::all(1),
        },
    ]
}

/// Build the case's bundle and verify it, returning the report.
fn report_for(case: &Case) -> VerificationReport {
    let bytes = build(&case.spec, &case.selection).bytes;
    verify_bundle(&bytes, &VerifyOptions::new())
        .unwrap_or_else(|e| panic!("fixture `{}` must verify: {e}", case.name))
}

/// The whole document: every case, rendered under its heading.
fn render_document() -> String {
    let mut out = String::new();
    out.push_str("antseal — the redaction view (R19), rendered by the CLI\n");
    out.push_str(
        "Every revealed and blacked-out row states size, offset and the file's declared total\n\
         (MVP-SPEC.md line 121). Sizes are the sealer's declared figures throughout.\n",
    );
    for case in cases() {
        out.push_str(&format!("\n════ {} ════\n", case.name));
        out.push_str(&render_report(&report_for(&case)).join("\n"));
        out.push('\n');
    }
    out
}

// ─────────────────────────────────────────────────────────────────────
// R19 Accept row 1 — the snapshot
// ─────────────────────────────────────────────────────────────────────

#[test]
fn the_redaction_view_matches_the_committed_snapshot() {
    let rendered = render_document();
    let path = std::path::Path::new(SNAPSHOT_PATH);
    if std::env::var_os("ANTSEAL_BLESS").is_some() {
        std::fs::create_dir_all(path.parent().expect("snapshot path has a parent"))
            .expect("create snapshot directory");
        std::fs::write(path, &rendered).expect("bless");
        return;
    }
    let committed = std::fs::read_to_string(path).unwrap_or_else(|e| {
        panic!(
            "missing committed redaction snapshot at {}: {e} (generate with ANTSEAL_BLESS=1)",
            path.display()
        )
    });
    assert!(
        committed == rendered,
        "the redaction view drifted from {} — this rendering is MVP-SPEC.md line 121's \
         anti-out-of-context guardrail, so regenerate with ANTSEAL_BLESS=1 only for a \
         deliberate change and justify the diff\n--- rendered ---\n{rendered}",
        path.display()
    );
}

/// Each of the five Accept shapes must actually be **in** the committed
/// document — renderable is not the same as rendered.
#[test]
fn the_snapshot_contains_every_shape_the_accept_row_names() {
    let committed = std::fs::read_to_string(SNAPSHOT_PATH).expect("committed redaction snapshot");
    for case in cases() {
        assert!(
            committed.contains(&format!("════ {} ════", case.name)),
            "the snapshot has no section for `{}` — add it and re-bless",
            case.name
        );
    }
    assert_eq!(cases().len(), 5, "R19's Accept row names five shapes");
}

// ─────────────────────────────────────────────────────────────────────
// R19 Accept row 3 — position + total size, in every rendering
// ─────────────────────────────────────────────────────────────────────

/// A rendered line that describes one unit: the rows the guardrail binds.
///
/// The riding raw-mirror row (`raw mirror: …`) is deliberately **outside**
/// this set, and the reason is that it is not a partial view of anything: a
/// mirror is the whole file's original bytes, byte-for-byte, which the R18
/// row it renders through says outright. There is no position to quote it out
/// of. Every row that shows *part* of a file starts with `unit `.
fn is_unit_row(line: &str) -> bool {
    line.trim_start().starts_with("unit ")
}

/// Does this unit row state size, offset **and** the declared total?
///
/// Written as an independent expectation rather than by calling the wording
/// table back: a test that re-derived the sentence from the same function it
/// is checking could not notice the function dropping a figure.
fn states_position_and_total(line: &str) -> bool {
    line.contains(" byte(s) at offset ") && line.contains(" of ") && line.contains(" declared")
}

/// **Accept row 3.** Every unit row of every fixture shape — revealed and
/// blacked out alike — carries position and the file's declared total size.
/// No flag, no shape and no size gates it.
#[test]
fn every_unit_row_of_every_shape_states_position_and_total_size() {
    let mut checked = 0usize;
    for case in cases() {
        let report = report_for(&case);
        for line in render_report(&report) {
            if !is_unit_row(&line) {
                continue;
            }
            checked += 1;
            assert!(
                states_position_and_total(&line),
                "`{}`: this row drops a figure the guardrail requires: {line}",
                case.name
            );
        }
    }
    assert!(
        checked >= 9,
        "the sweep only saw {checked} unit rows — the fixture walk is broken, not the \
         rendering clean"
    );
}

/// The sweep must be able to fail. The predicate is run against rows built
/// to drop each figure in turn, so a nonzero result on the real tree is not
/// what this rests on.
#[test]
fn the_position_sweep_catches_a_row_that_drops_a_figure() {
    let honest = "      unit 1 revealed: 384 byte(s) at offset 256 of 1024 declared";
    assert!(is_unit_row(honest) && states_position_and_total(honest));

    for planted in [
        // size only — the out-of-context quote this guardrail exists to
        // prevent.
        "      unit 1 revealed: 384 byte(s)",
        // position, no denominator.
        "      unit 1 revealed: 384 byte(s) at offset 256",
        // a percentage instead of the two figures.
        "      unit 1 revealed: 37% of the file",
    ] {
        assert!(
            is_unit_row(planted),
            "the row is still a unit row: {planted}"
        );
        assert!(
            !states_position_and_total(planted),
            "the sweep must reject this row: {planted}"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────
// R19 Accept row 2 — placeholders leak nothing
// ─────────────────────────────────────────────────────────────────────

/// **Accept row 2, as a differential.** Rename the withheld file and replace
/// its bytes with different bytes of the same length: the rendering must be
/// **byte-identical**.
///
/// Asserting that the path does not appear would only prove that *this*
/// path does not appear. This proves the stronger thing — the placeholder's
/// rendering is a function of the ordinal and the declared size, and of
/// nothing else about the file — which is exactly what
/// `UnrevealedFilePlaceholder`'s doc forbids it ever gaining a field for.
/// The declared size is deliberately held constant: structure metadata
/// (file count, sizes, unit boundaries) is visible to bundle recipients by
/// design (MVP-SPEC.md line 95).
#[test]
fn a_withheld_files_rendering_depends_on_nothing_but_its_ordinal_and_size() {
    let secret_bytes = shapes::CANONICAL_TEXT;
    // Same length, still canonical (ASCII, LF-terminated, NFC-stable), so
    // the file's declared size is unchanged and it grows no raw mirror.
    let mut decoy_bytes = vec![b'x'; secret_bytes.len()];
    *decoy_bytes.last_mut().expect("non-empty") = b'\n';
    assert_eq!(decoy_bytes.len(), secret_bytes.len());
    assert_ne!(decoy_bytes.as_slice(), secret_bytes);

    let work = |path: &str, content: &[u8]| {
        WorkSpec::new(
            "multi file",
            vec![
                FileSpec::text("notes/intro.md", shapes::CRLF_TEXT),
                FileSpec::binary("data/blob.bin", (0u8..30).collect::<Vec<u8>>())
                    .split(vec![10, 10, 10]),
                FileSpec::text(path, content.to_vec()).without_fine_tree(),
            ],
        )
    };
    let render_of = |spec: &WorkSpec| {
        let bytes = build(spec, &shapes::multi_file_mixed_selection()).bytes;
        let report = verify_bundle(&bytes, &VerifyOptions::new()).expect("fixture verifies");
        render_report(&report).join("\n")
    };

    let secret = render_of(&work("archive/old.txt", secret_bytes));
    let decoy = render_of(&work("sensitive/merger-with-acme-corp.txt", &decoy_bytes));
    assert_eq!(
        secret, decoy,
        "renaming and rewriting a withheld file moved the redaction view — something in the \
         placeholder's rendering depends on data the bundle must not disclose"
    );

    // And the concrete leak, checked head-on: neither name reaches the
    // rendering, and neither does the file's content.
    for needle in [
        "archive",
        "old.txt",
        "sensitive",
        "merger",
        "acme",
        "already canonical",
    ] {
        assert!(
            !secret.contains(needle) && !decoy.contains(needle),
            "the withheld file's `{needle}` reached the rendering"
        );
    }
    assert!(
        secret.contains(&format!(
            "file #2 — {} declared byte(s), path withheld",
            secret_bytes.len()
        )),
        "the placeholder itself must still render, ordinal and size:\n{secret}"
    );
}

/// The differential must be able to fail: if the rendering did depend on the
/// withheld file's name, the two documents would differ. Two *touched*
/// files' names differing is the positive control for the comparison itself.
#[test]
fn the_differential_reddens_when_a_rendered_name_does_change() {
    let render_of = |path: &str| {
        let spec = WorkSpec::new(
            "control",
            vec![FileSpec::text(path, shapes::CANONICAL_TEXT)],
        );
        let bytes = build(&spec, &Selection::all(1)).bytes;
        let report = verify_bundle(&bytes, &VerifyOptions::new()).expect("fixture verifies");
        render_report(&report).join("\n")
    };
    assert_ne!(
        render_of("a/one.txt"),
        render_of("b/two.txt"),
        "a REVEALED file's path is disclosed and must move the rendering — otherwise the \
         comparison above proves nothing"
    );
}

// ─────────────────────────────────────────────────────────────────────
// sealer-authored paths are adversary-authored (MVP-SPEC.md line 121)
// ─────────────────────────────────────────────────────────────────────

/// A bundle's path is verified against `path_commit`, which proves the
/// sealer committed to it — never that it is safe to print. D67 §3 R3's
/// closed escape set is what stops it repainting the view, and escaping LF
/// is what stops it **forging a row**.
#[test]
fn a_hostile_path_cannot_forge_a_row_or_repaint_the_view() {
    let forged_row = "unit 9 revealed: 999 byte(s) at offset 0 of 999 declared";
    let hostile = format!("notes/\u{202e}gpj.evil\n      {forged_row}\n      ");
    let spec = WorkSpec::new(
        "hostile path",
        vec![FileSpec::text(&hostile, shapes::CANONICAL_TEXT)],
    );
    let bytes = build(&spec, &Selection::all(1)).bytes;
    let report = verify_bundle(&bytes, &VerifyOptions::new())
        .expect("a hostile path is a valid bundle — it is the rendering that must hold");
    assert_eq!(report.reveal.files[0].path, hostile, "the path arrives raw");

    let lines = render_report(&report);
    for line in &lines {
        assert!(
            !line.contains('\n') && !line.contains('\r'),
            "a rendered line must be one line: {line:?}"
        );
        assert!(
            !line.contains('\u{202e}'),
            "the bidi override reached the terminal unescaped: {line:?}"
        );
    }
    assert!(
        !lines.iter().any(|line| line.trim() == forged_row),
        "the path forged a unit row:\n{}",
        lines.join("\n")
    );

    // The one row that carries the path shows it escaped, in full — the
    // reader is told what the name is, not shown what it wants to look like.
    let file_row = lines
        .iter()
        .find(|line| line.contains("file #0"))
        .expect("the file row renders");
    assert!(file_row.contains("\\u{202e}"), "{file_row}");
    assert!(file_row.contains("\\n"), "{file_row}");
    assert!(file_row.contains("notes/"), "{file_row}");

    // The control: an ordinary path is not mangled by the same set.
    let plain = WorkSpec::new(
        "plain path",
        vec![FileSpec::text(
            "notes/café — draft.md",
            shapes::CANONICAL_TEXT,
        )],
    );
    let bytes = build(&plain, &Selection::all(1)).bytes;
    let report = verify_bundle(&bytes, &VerifyOptions::new()).expect("fixture verifies");
    assert!(
        render_report(&report)
            .iter()
            .any(|line| line.contains("\"notes/café — draft.md\"")),
        "ordinary prose in a path must render as prose"
    );
}

/// Nothing this renderer emits is ever more than one line — the invariant
/// the escape set buys, swept over every shape rather than only the hostile
/// one.
#[test]
fn no_rendered_line_of_any_shape_contains_a_line_break() {
    for case in cases() {
        for line in render_report(&report_for(&case)) {
            assert!(
                !line.contains('\n') && !line.contains('\r'),
                "`{}` emitted a multi-line row: {line:?}",
                case.name
            );
        }
    }
}

// ─────────────────────────────────────────────────────────────────────
// R19 Accept row 4 — the model rides in the report's own bytes
// ─────────────────────────────────────────────────────────────────────

/// **Accept row 4.** Every datum the view exposes is already in the report's
/// canonical bytes, so R23's page can rebuild this exact view from the
/// bundle's report alone — with no second document, and with no report field
/// added to buy it (D105 §2.4: a field here would have been a FORMAT EVENT).
#[test]
fn every_datum_the_view_exposes_is_present_in_the_canonical_report_bytes() {
    for case in cases() {
        let report = report_for(&case);
        let json = String::from_utf8(report.to_canonical_json().expect("the report serializes"))
            .expect("canonical report bytes are UTF-8");
        let view = RedactionView::from_report(&report);

        for file in &view.files {
            for needle in [
                format!("\"file_id\":{}", file.file_id),
                format!("\"total_size\":{}", file.total_size),
                format!("\"fully_revealed\":{}", file.fully_revealed),
                format!(
                    "\"path\":{}",
                    serde_json::to_string(file.path).expect("path")
                ),
            ] {
                assert!(
                    json.contains(&needle),
                    "`{}`: {needle} not in {json}",
                    case.name
                );
            }
            for block in &file.blocks {
                let span = format!(
                    "{{\"unit_id\":{},\"start\":{},\"end\":{}}}",
                    block.unit_id, block.start, block.end
                );
                assert!(
                    json.contains(&span),
                    "`{}`: {span} not in {json}",
                    case.name
                );
            }
            if let Some(mirror) = file.raw_mirror {
                assert!(json.contains(&format!(
                    "{{\"unit_id\":{},\"raw_size\":{}}}",
                    mirror.unit_id, mirror.raw_size
                )));
            }
        }
        for placeholder in &view.withheld_files {
            assert!(json.contains(&format!(
                "{{\"file_id\":{},\"size\":{}}}",
                placeholder.file_id, placeholder.size
            )));
        }
    }
}

/// The tiling invariant, seen through the totals: for a report the pipeline
/// produced, revealed + blacked out + wholly withheld accounts for every
/// declared byte exactly once. A view that double-counted the riding raw
/// mirror — the obvious way to get this wrong — fails here.
#[test]
fn the_work_totals_account_for_every_declared_byte_exactly_once() {
    let mut saw_a_mirror = false;
    for case in cases() {
        let report = report_for(&case);
        let view = RedactionView::from_report(&report);
        let totals = &view.totals;
        assert_eq!(
            totals.revealed_bytes + totals.blacked_out_bytes + totals.withheld_file_bytes,
            totals.declared_bytes,
            "`{}`: the totals do not partition the declared bytes",
            case.name
        );
        for file in &view.files {
            assert_eq!(
                file.covered_bytes(),
                u128::from(file.total_size),
                "`{}`: file #{} blocks do not tile it",
                case.name,
                file.file_id
            );
        }
        saw_a_mirror |= totals.raw_mirrors > 0;
    }
    assert!(
        saw_a_mirror,
        "no fixture shipped a riding mirror, so the double-count this test rules out was \
         never reachable"
    );
}
