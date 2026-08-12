//! The **redaction view** (task R19): the shared, renderer-agnostic shape of
//! MVP-SPEC.md line 121's anti-out-of-context guardrail —
//!
//! > *"Every reveal displays position + total size (anti-out-of-context
//! > guardrail); unrevealed units render as sized blackout blocks;
//! > unrevealed files render as committed placeholders (size only, path
//! > withheld)."*
//!
//! # This module derives; it does not extend the report
//!
//! R5 already put the *data* in the report: [`RevealSet`] carries per-file
//! revealed and unrevealed spans, the full-reveal flag, the riding mirror,
//! and the committed placeholders. What it does **not** carry is the one
//! shape a reader needs — the two span lists **interleaved in file order**,
//! so a revealed range is seen with the blackout blocks on either side of it
//! — nor the work-level totals.
//!
//! Both are pure functions of fields report v1 already serializes, so this
//! module computes them and adds **no report field**. That is the ruling as
//! much as the convenience: under D105 §2.4 a new field on
//! [`VerificationReport`], [`RevealSet`], [`FileReveal`], [`UnitSpan`] or
//! [`UnrevealedFilePlaceholder`] is a FORMAT EVENT costing a `REPORT_VERSION`
//! bump, and a view that can be derived is never worth one. The consequence
//! for R23 is the useful half: the page can rebuild this exact view from the
//! report **bytes** alone, with no second document to fetch or trust.
//!
//! # What the numbers are, and are not
//!
//! [`FileRedaction::total_size`] and [`UnrevealedFilePlaceholder::size`] are
//! the **sealer's declared** figures (their own field docs say so: *"Render
//! it as declared, never as measured"*). `check_tiling` constrains them
//! against the manifest's own unit table and every revealed span opened
//! against its commitment — but nothing in the bundle contradicts a
//! self-consistent overstatement of the *unrevealed* remainder. So this
//! module carries them through unaltered, names them `declared` in every
//! rendering, and never computes a figure that would read as a measurement.
//!
//! # Total by construction
//!
//! [`RedactionView::from_report`] cannot fail and cannot panic. Its inputs
//! are `pub` report fields, so a caller may hand it a [`RevealSet`] no
//! pipeline would produce — overlapping spans, a `start` past its `end`, a
//! span past `total_size`. Widths are [`u64::saturating_sub`] and the byte
//! totals accumulate in `u128` (the house's `PreviewTotals::bytes` idiom), so
//! a hostile shape produces a truthful-about-itself view rather than a wrong
//! number or an abort. [`FileRedaction::covered_bytes`] is the honest place
//! to notice: for anything `verify_bundle` produced it equals `total_size`,
//! because R3's tiling invariant makes the spans exactly tile
//! `[0, total_size)`.
//!
//! # WASM-safe
//!
//! Pure data, borrowed from the report: no clock, no I/O, no allocation
//! beyond the block vectors, and no ordering that depends on anything but the
//! report's own values.

use super::report::{
    FileReveal, RawMirrorReveal, RevealSet, UnitSpan, UnrevealedFilePlaceholder, VerificationReport,
};

/// One block of a file's tiling domain: a whole unit, revealed or blacked
/// out, at its position in `[0, total_size)`.
///
/// The half-open `[start, end)` convention is [`UnitSpan`]'s own; `size` is
/// derived rather than stored so the two can never disagree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RedactionBlock {
    /// Work-global unit id (MVP-SPEC.md line 76) — the id `reveal --units`
    /// takes, so a reader can ask the sealer for a specific blacked-out
    /// block by name.
    pub unit_id: u64,
    /// Inclusive start byte offset: the block's **position**, which line 121
    /// requires every rendering to state.
    pub start: u64,
    /// Exclusive end byte offset.
    pub end: u64,
    /// `true` iff this bundle revealed the unit's bytes.
    pub revealed: bool,
}

impl RedactionBlock {
    /// Width in bytes, saturating — a malformed `end < start` is 0 bytes
    /// wide, never a wrapped width.
    #[must_use]
    pub const fn size(self) -> u64 {
        self.end.saturating_sub(self.start)
    }

    /// The block as it comes from one report span.
    const fn from_span(span: UnitSpan, revealed: bool) -> Self {
        Self {
            unit_id: span.unit_id,
            start: span.start,
            end: span.end,
            revealed,
        }
    }

    /// The total order the interleave sorts on. Distinct real units have
    /// distinct `(start, end)`, so this only ever decides between blocks a
    /// tiling bundle cannot contain — deterministically, which is what the
    /// view owes its snapshots.
    const fn order_key(self) -> (u64, u64, u64, bool) {
        (self.start, self.end, self.unit_id, self.revealed)
    }
}

/// One touched file's redaction view: its blocks in file order, with the
/// denominator every one of them is stated against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileRedaction<'a> {
    /// `file_id` — LE64 index into the manifest file table.
    pub file_id: u64,
    /// The disclosed path, verified against `path_commit`
    /// ([`FileReveal::path`]). **Sealer-authored text**: it is borrowed raw
    /// here and escaped by the renderer for its own surface, the D67 §3 R6
    /// value-vs-rendering split.
    pub path: &'a str,
    /// The file's **declared** total size in its commitment domain — the
    /// anti-out-of-context denominator ([`FileReveal::total_size`]).
    pub total_size: u64,
    /// Whether every non-mirror unit of the file is revealed.
    pub fully_revealed: bool,
    /// Every non-mirror unit of the file, revealed and blacked out
    /// interleaved, sorted by position. This is the interleave the report
    /// does not carry.
    pub blocks: Vec<RedactionBlock>,
    /// The file's revealed raw-mirror unit, when one rode along with a full
    /// reveal ([`FileReveal::raw_mirror`]). It lives in the **raw** byte
    /// domain, outside the tiling `blocks` above, so it is deliberately not
    /// a block and never enters a byte total (that would count one file's
    /// content twice, in two domains).
    pub raw_mirror: Option<RawMirrorReveal>,
    /// Bytes this bundle reveals of this file (Σ revealed block widths).
    pub revealed_bytes: u128,
    /// Bytes blacked out inside this file (Σ unrevealed block widths).
    pub blacked_out_bytes: u128,
}

impl FileRedaction<'_> {
    /// `revealed_bytes + blacked_out_bytes` — the span of the file the
    /// blocks actually account for.
    ///
    /// Equals [`FileRedaction::total_size`] for every report `verify_bundle`
    /// produced, because R3's tiling check
    /// (`crates/antseal-core/src/verify/structural.rs`) requires the
    /// non-mirror units to be sorted, non-overlapping and to exactly tile
    /// `[0, total_size)`. It is exposed so that a caller handed a
    /// hand-built [`RevealSet`] can see the disagreement instead of
    /// inheriting it silently.
    #[must_use]
    pub const fn covered_bytes(&self) -> u128 {
        self.revealed_bytes.saturating_add(self.blacked_out_bytes)
    }

    /// Build one file's view from its report entry.
    fn from_file_reveal(file: &FileReveal) -> FileRedaction<'_> {
        let mut blocks: Vec<RedactionBlock> = file
            .revealed_spans
            .iter()
            .map(|span| RedactionBlock::from_span(*span, true))
            .chain(
                file.unrevealed_spans
                    .iter()
                    .map(|span| RedactionBlock::from_span(*span, false)),
            )
            .collect();
        blocks.sort_unstable_by_key(|block| block.order_key());

        let mut revealed_bytes: u128 = 0;
        let mut blacked_out_bytes: u128 = 0;
        for block in &blocks {
            if block.revealed {
                revealed_bytes = revealed_bytes.saturating_add(u128::from(block.size()));
            } else {
                blacked_out_bytes = blacked_out_bytes.saturating_add(u128::from(block.size()));
            }
        }

        FileRedaction {
            file_id: file.file_id,
            path: &file.path,
            total_size: file.total_size,
            fully_revealed: file.fully_revealed,
            blocks,
            raw_mirror: file.raw_mirror,
            revealed_bytes,
            blacked_out_bytes,
        }
    }
}

/// The work-level totals: the two halves of the disclosure stated together,
/// so neither can be read on its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RedactionTotals {
    /// Files in the work — touched plus wholly unrevealed. Structure
    /// metadata is visible to bundle recipients by design (MVP-SPEC.md
    /// line 95), so the denominator is stateable.
    pub files: u64,
    /// Files with at least one revealed unit.
    pub files_touched: u64,
    /// Touched files whose every non-mirror unit is revealed.
    pub files_fully_revealed: u64,
    /// Files revealed by nothing, carried as committed placeholders.
    pub files_withheld: u64,
    /// Σ every file's declared total size, touched and withheld alike.
    pub declared_bytes: u128,
    /// Σ revealed block widths across every touched file.
    pub revealed_bytes: u128,
    /// Σ blacked-out block widths inside touched files.
    pub blacked_out_bytes: u128,
    /// Σ the declared sizes of the wholly unrevealed files.
    pub withheld_file_bytes: u128,
    /// Raw mirrors riding along with a full reveal. Counted, never added to
    /// a byte total: a mirror is the same content in the raw domain.
    pub raw_mirrors: u64,
}

/// The redaction view of one verified bundle.
///
/// Borrows the report it was derived from: the view is a lens over report
/// data, never a second copy of it that could drift.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactionView<'a> {
    /// Touched files in manifest file order (the order [`RevealSet::files`]
    /// is already in).
    pub files: Vec<FileRedaction<'a>>,
    /// The wholly unrevealed files, as their committed placeholders.
    ///
    /// Deliberately [`UnrevealedFilePlaceholder`] itself rather than a view
    /// type of its own: the report's placeholder has exactly two fields — an
    /// ordinal and a declared size — and its doc forbids it ever gaining a
    /// path, a snippet or any content-derived field. Reusing it makes "a
    /// placeholder leaks nothing" a property of the **type** the view holds,
    /// not a promise its renderer keeps.
    pub withheld_files: Vec<UnrevealedFilePlaceholder>,
    /// The work-level totals.
    pub totals: RedactionTotals,
}

impl<'a> RedactionView<'a> {
    /// Derive the view from a verified report.
    #[must_use]
    pub fn from_report(report: &'a VerificationReport) -> Self {
        Self::from_reveal_set(&report.reveal)
    }

    /// Derive the view from a report's reveal set — the whole of this
    /// module's input, and the reason R23 needs nothing but the report
    /// bytes.
    #[must_use]
    pub fn from_reveal_set(reveal: &'a RevealSet) -> Self {
        let files: Vec<FileRedaction<'a>> = reveal
            .files
            .iter()
            .map(FileRedaction::from_file_reveal)
            .collect();

        let mut totals = RedactionTotals {
            files: count(reveal.files.len()) + count(reveal.unrevealed_files.len()),
            files_touched: count(reveal.files.len()),
            files_withheld: count(reveal.unrevealed_files.len()),
            ..RedactionTotals::default()
        };
        for file in &files {
            if file.fully_revealed {
                totals.files_fully_revealed += 1;
            }
            if file.raw_mirror.is_some() {
                totals.raw_mirrors += 1;
            }
            totals.declared_bytes = totals
                .declared_bytes
                .saturating_add(u128::from(file.total_size));
            totals.revealed_bytes = totals.revealed_bytes.saturating_add(file.revealed_bytes);
            totals.blacked_out_bytes = totals
                .blacked_out_bytes
                .saturating_add(file.blacked_out_bytes);
        }
        for placeholder in &reveal.unrevealed_files {
            let size = u128::from(placeholder.size);
            totals.declared_bytes = totals.declared_bytes.saturating_add(size);
            totals.withheld_file_bytes = totals.withheld_file_bytes.saturating_add(size);
        }

        Self {
            files,
            withheld_files: reveal.unrevealed_files.clone(),
            totals,
        }
    }
}

/// A `usize` count as a `u64`. A widening conversion on every target this
/// workspace builds for (`usize` is 32- or 64-bit, wasm32 included), so it is
/// lossless and has no failure arm to design.
const fn count(n: usize) -> u64 {
    n as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A partially revealed file: unit 1 open between two blackout blocks.
    fn partial_file() -> FileReveal {
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

    /// A fully revealed file with a riding mirror.
    fn full_file() -> FileReveal {
        FileReveal {
            file_id: 1,
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
        }
    }

    fn reveal_set() -> RevealSet {
        RevealSet {
            files: vec![partial_file(), full_file()],
            unrevealed_files: vec![UnrevealedFilePlaceholder {
                file_id: 2,
                size: 49_152,
            }],
        }
    }

    #[test]
    fn the_two_span_lists_interleave_into_one_ordered_run() {
        let reveal = reveal_set();
        let view = RedactionView::from_reveal_set(&reveal);
        let file = &view.files[0];
        assert_eq!(
            file.blocks
                .iter()
                .map(|b| (b.unit_id, b.start, b.end, b.revealed))
                .collect::<Vec<_>>(),
            vec![
                (0, 0, 256, false),
                (1, 256, 640, true),
                (2, 640, 1024, false)
            ],
            "the revealed span must sit between its neighbours, not after them"
        );
        assert!(
            file.blocks.windows(2).all(|w| w[0].start <= w[1].start),
            "blocks are in file order"
        );
    }

    #[test]
    fn every_block_carries_position_and_the_files_declared_total() {
        let reveal = reveal_set();
        let view = RedactionView::from_reveal_set(&reveal);
        for file in &view.files {
            assert!(file.total_size > 0);
            for block in &file.blocks {
                assert!(block.start <= file.total_size);
                assert_eq!(block.size(), block.end - block.start);
            }
        }
    }

    #[test]
    fn a_tiling_files_blocks_account_for_exactly_its_declared_size() {
        let reveal = reveal_set();
        let view = RedactionView::from_reveal_set(&reveal);
        for file in &view.files {
            assert_eq!(
                file.covered_bytes(),
                u128::from(file.total_size),
                "R3's tiling invariant, seen through the view"
            );
        }
        assert_eq!(view.files[0].revealed_bytes, 384);
        assert_eq!(view.files[0].blacked_out_bytes, 256 + 384);
        assert_eq!(view.files[1].revealed_bytes, 300);
        assert_eq!(view.files[1].blacked_out_bytes, 0);
    }

    #[test]
    fn work_totals_split_the_declared_bytes_three_ways() {
        let reveal = reveal_set();
        let view = RedactionView::from_reveal_set(&reveal);
        assert_eq!(
            view.totals,
            RedactionTotals {
                files: 3,
                files_touched: 2,
                files_fully_revealed: 1,
                files_withheld: 1,
                declared_bytes: 1024 + 300 + 49_152,
                revealed_bytes: 384 + 300,
                blacked_out_bytes: 640,
                withheld_file_bytes: 49_152,
                raw_mirrors: 1,
            }
        );
        // The identity the two halves have to satisfy for a tiling report:
        // nothing is double-counted and nothing is unaccounted for.
        assert_eq!(
            view.totals.revealed_bytes
                + view.totals.blacked_out_bytes
                + view.totals.withheld_file_bytes,
            view.totals.declared_bytes
        );
    }

    #[test]
    fn a_riding_mirror_is_counted_but_never_added_to_a_byte_total() {
        // The mirror is 305 raw bytes of a 300-byte canonical file: adding
        // it would report 305 bytes of content that do not exist beside the
        // 300 already counted.
        let reveal = reveal_set();
        let view = RedactionView::from_reveal_set(&reveal);
        assert_eq!(view.totals.raw_mirrors, 1);
        assert_eq!(view.files[1].raw_mirror.map(|m| m.raw_size), Some(305));
        assert_eq!(view.totals.revealed_bytes, 684, "300, not 605");
    }

    #[test]
    fn a_withheld_file_reaches_the_view_as_the_reports_own_placeholder_type() {
        let reveal = reveal_set();
        let view = RedactionView::from_reveal_set(&reveal);
        assert_eq!(
            view.withheld_files,
            vec![UnrevealedFilePlaceholder {
                file_id: 2,
                size: 49_152,
            }]
        );
        // The placeholder's whole surface: an ordinal and a declared size.
        // There is no field a path could travel in.
        let placeholder = view.withheld_files[0];
        assert_eq!(placeholder.file_id, 2);
        assert_eq!(placeholder.size, 49_152);
    }

    #[test]
    fn an_empty_file_is_one_zero_width_block_at_offset_zero() {
        // total_size = 0 with one zero-length unit: the whole file is
        // revealed, and the view must not divide, subtract past zero, or
        // drop the block.
        let reveal = RevealSet {
            files: vec![FileReveal {
                file_id: 0,
                path: "empty.txt".to_owned(),
                total_size: 0,
                fully_revealed: true,
                revealed_spans: vec![UnitSpan {
                    unit_id: 0,
                    start: 0,
                    end: 0,
                }],
                unrevealed_spans: Vec::new(),
                raw_mirror: None,
            }],
            unrevealed_files: Vec::new(),
        };
        let view = RedactionView::from_reveal_set(&reveal);
        assert_eq!(view.files[0].blocks.len(), 1);
        assert_eq!(view.files[0].blocks[0].size(), 0);
        assert_eq!(view.files[0].covered_bytes(), 0);
        assert_eq!(view.totals.declared_bytes, 0);
        assert_eq!(view.totals.revealed_bytes, 0);
    }

    #[test]
    fn a_whole_file_unit_is_a_single_block_spanning_the_file() {
        // The `--no-fine-tree` shape: one non-covered unit per file.
        let reveal = RevealSet {
            files: vec![FileReveal {
                file_id: 0,
                path: "scan.png".to_owned(),
                total_size: 4096,
                fully_revealed: true,
                revealed_spans: vec![UnitSpan {
                    unit_id: 0,
                    start: 0,
                    end: 4096,
                }],
                unrevealed_spans: Vec::new(),
                raw_mirror: None,
            }],
            unrevealed_files: Vec::new(),
        };
        let view = RedactionView::from_reveal_set(&reveal);
        assert_eq!(view.files[0].blocks.len(), 1);
        assert_eq!(view.files[0].blocks[0].size(), 4096);
        assert!(view.files[0].blocks[0].revealed);
    }

    #[test]
    fn an_empty_reveal_set_is_an_empty_view_not_a_panic() {
        let reveal = RevealSet {
            files: Vec::new(),
            unrevealed_files: Vec::new(),
        };
        let view = RedactionView::from_reveal_set(&reveal);
        assert!(view.files.is_empty());
        assert!(view.withheld_files.is_empty());
        assert_eq!(view.totals, RedactionTotals::default());
    }

    /// The report's fields are `pub`, so the view's input is not always a
    /// pipeline's output. A width that would wrap must saturate, and the
    /// disagreement must stay visible rather than being absorbed.
    #[test]
    fn a_malformed_span_saturates_instead_of_wrapping_or_panicking() {
        let reveal = RevealSet {
            files: vec![FileReveal {
                file_id: 0,
                path: "hand-built".to_owned(),
                total_size: 10,
                fully_revealed: false,
                revealed_spans: vec![UnitSpan {
                    unit_id: 0,
                    // end < start: no pipeline emits this.
                    start: 8,
                    end: 2,
                }],
                unrevealed_spans: vec![UnitSpan {
                    unit_id: 1,
                    start: u64::MAX - 1,
                    end: u64::MAX,
                }],
                raw_mirror: None,
            }],
            unrevealed_files: Vec::new(),
        };
        let view = RedactionView::from_reveal_set(&reveal);
        // Sorted by `start`, so the inverted span (start 8) comes first.
        assert_eq!(view.files[0].blocks[0].size(), 0, "8..2 is zero bytes wide");
        assert!(view.files[0].blocks[0].revealed);
        assert_eq!(view.files[0].revealed_bytes, 0);
        assert_eq!(view.files[0].blacked_out_bytes, 1);
        assert_ne!(
            view.files[0].covered_bytes(),
            u128::from(view.files[0].total_size),
            "the disagreement stays visible through covered_bytes"
        );
    }

    /// Sum of two `u64::MAX`-scale widths: the `u128` accumulator is what
    /// keeps a hostile shape from wrapping the work total to a small number.
    #[test]
    fn byte_totals_accumulate_wider_than_the_values_they_sum() {
        let big = |unit_id: u64| UnitSpan {
            unit_id,
            start: 0,
            end: u64::MAX,
        };
        let reveal = RevealSet {
            files: vec![
                FileReveal {
                    file_id: 0,
                    path: "a".to_owned(),
                    total_size: u64::MAX,
                    fully_revealed: true,
                    revealed_spans: vec![big(0)],
                    unrevealed_spans: Vec::new(),
                    raw_mirror: None,
                },
                FileReveal {
                    file_id: 1,
                    path: "b".to_owned(),
                    total_size: u64::MAX,
                    fully_revealed: true,
                    revealed_spans: vec![big(1)],
                    unrevealed_spans: Vec::new(),
                    raw_mirror: None,
                },
            ],
            unrevealed_files: Vec::new(),
        };
        let view = RedactionView::from_reveal_set(&reveal);
        assert_eq!(
            view.totals.revealed_bytes,
            u128::from(u64::MAX) * 2,
            "the sum exceeds u64 and must not wrap"
        );
    }

    #[test]
    fn the_block_order_is_total_even_for_shapes_a_bundle_cannot_have() {
        // Two units sharing a start: impossible under the tiling invariant,
        // so the only thing that matters is that the order is decided by
        // the values and not by iteration accident.
        let overlapping = |file_id: u64| RevealSet {
            files: vec![FileReveal {
                file_id,
                path: "x".to_owned(),
                total_size: 8,
                fully_revealed: false,
                revealed_spans: vec![UnitSpan {
                    unit_id: 7,
                    start: 0,
                    end: 8,
                }],
                unrevealed_spans: vec![UnitSpan {
                    unit_id: 3,
                    start: 0,
                    end: 8,
                }],
                raw_mirror: None,
            }],
            unrevealed_files: Vec::new(),
        };
        let a = overlapping(0);
        let b = overlapping(0);
        let first = RedactionView::from_reveal_set(&a);
        let second = RedactionView::from_reveal_set(&b);
        assert_eq!(first.files[0].blocks, second.files[0].blocks);
        assert_eq!(
            first.files[0]
                .blocks
                .iter()
                .map(|b| b.unit_id)
                .collect::<Vec<_>>(),
            vec![3, 7],
            "ties break on the report's own values"
        );
    }
}
