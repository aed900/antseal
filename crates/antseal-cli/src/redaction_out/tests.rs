//! R19's in-crate rows: the three renderings that need no bundle and
//! therefore no fixture build to run.
//!
//! The five Accept shapes, the committed snapshot, the placeholder-leak
//! differential and the hostile-path rendering live in
//! `tests/redaction_view.rs`, where every view comes from a real
//! `.sealproof` put through `verify_bundle`.
//!
//! Out of line rather than inline (the `status.rs` / `status/tests.rs`
//! pattern) because `tests/verdict_wording.rs`'s source scan walks
//! `crates/antseal-cli/src/**` and excludes files named `tests.rs`: a test
//! naming a frozen sentence is a pin, not a second source of truth, and it
//! has to be somewhere the scan does not read it as a copy.

use antseal_core::verify::report::{
    FileReveal, RawMirrorReveal, RevealSet, UnitSpan, UnrevealedFilePlaceholder,
};
// The module under test names `wording` nowhere after D130 §3 R6 — it folds
// over the assembly instead — so the pins below import the table directly. A
// test naming a frozen sentence is a pin, not a second source of truth, which
// is why this file is out of line and outside `verdict_wording.rs`'s scan.
use antseal_core::verify::wording;

use super::*;

fn partial() -> FileReveal {
    FileReveal {
        file_id: 0,
        path: "pitch/chapter-1.md".to_owned(),
        total_size: 1024,
        fully_revealed: false,
        revealed_spans: vec![UnitSpan {
            unit_id: 1,
            start: 256,
            end: 640,
        }],
        unrevealed_spans: vec![
            UnitSpan {
                unit_id: 0,
                start: 0,
                end: 256,
            },
            UnitSpan {
                unit_id: 2,
                start: 640,
                end: 1024,
            },
        ],
        raw_mirror: None,
    }
}

#[test]
fn a_blackout_row_states_position_and_the_declared_total() {
    let reveal = RevealSet {
        files: vec![partial()],
        unrevealed_files: Vec::new(),
    };
    let view = RedactionView::from_reveal_set(&reveal);
    let lines = render(&view);
    assert!(
        lines
            .iter()
            .any(|l| l.contains("unit 0 blacked out: 256 byte(s) at offset 0 of 1024 declared")),
        "{lines:#?}"
    );
    assert!(
        lines
            .iter()
            .any(|l| l.contains("unit 1 revealed: 384 byte(s) at offset 256 of 1024 declared")),
        "{lines:#?}"
    );
}

#[test]
fn a_riding_mirror_renders_only_under_a_full_reveal() {
    let reveal = RevealSet {
        files: vec![FileReveal {
            file_id: 0,
            path: "notes.txt".to_owned(),
            total_size: 300,
            fully_revealed: true,
            revealed_spans: vec![UnitSpan {
                unit_id: 3,
                start: 0,
                end: 300,
            }],
            unrevealed_spans: Vec::new(),
            raw_mirror: Some(RawMirrorReveal {
                unit_id: 4,
                raw_size: 305,
            }),
        }],
        unrevealed_files: Vec::new(),
    };
    let view = RedactionView::from_reveal_set(&reveal);
    let rendered = render(&view).join("\n");
    assert!(rendered.contains(wording::MIRROR_ORIGINAL_FILE_PHRASE));

    // The same file, partially revealed: the producer would never emit
    // a mirror here, and the renderer has no arm that could invent one.
    let reveal = RevealSet {
        files: vec![partial()],
        unrevealed_files: Vec::new(),
    };
    let view = RedactionView::from_reveal_set(&reveal);
    let rendered = render(&view).join("\n");
    assert!(!rendered.contains(wording::MIRROR_ORIGINAL_FILE_PHRASE));
}

#[test]
fn a_placeholder_row_carries_the_ordinal_and_the_size_and_nothing_else() {
    let reveal = RevealSet {
        files: Vec::new(),
        unrevealed_files: vec![UnrevealedFilePlaceholder {
            file_id: 3,
            size: 49_152,
        }],
    };
    let view = RedactionView::from_reveal_set(&reveal);
    let lines = render(&view);
    let row = lines
        .iter()
        .find(|l| l.contains("file #3"))
        .expect("the placeholder renders");
    assert!(row.contains("49152 declared byte(s)"));
    assert!(row.contains("path withheld"));
}
