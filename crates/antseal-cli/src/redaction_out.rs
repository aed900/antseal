//! The **CLI text renderer** for the redaction view (task R19).
//!
//! [`antseal_core::verify::redaction`] derives the view — per file, the
//! revealed and blacked-out unit blocks interleaved in position order, the
//! committed placeholders for wholly unrevealed files, and the work-level
//! totals. This module turns that view into the lines `antseal verify`
//! prints, and does **layout only**: every sentence comes from
//! [`antseal_core::verify::wording`], which R18 froze and which R23's page
//! draws from too, so the CLI and the page cannot spell MVP-SPEC.md line
//! 121's guardrail two ways.
//!
//! # The guardrail is the whole point
//!
//! Line 121: *"Every reveal displays position + total size
//! (anti-out-of-context guardrail)."* The rule is unconditional, so this
//! renderer has **no flag, no width heuristic and no summarising arm** that
//! could drop a position. Every revealed block prints size, offset and the
//! file's declared total; every unrevealed block prints the same three; and
//! [`render`] is a fold over the view rather than a set of cases, so there is
//! no shape whose rendering forgot.
//!
//! # Paths are adversary-authored, and are escaped as such
//!
//! `FileReveal::path` is verified against `path_commit` — which proves the
//! sealer committed to it, not that it is safe to print. Line 121 names the
//! sealer an adversary in the same breath as the guardrail, so the path goes
//! through D67 §3 R3's closed escape set
//! ([`crate::preview::escape_for_terminal`]) before it reaches a line.
//! Escaping LF is the load-bearing half: it makes a path exactly one line,
//! so a path containing `"\n  unit 9 revealed: …"` cannot forge a row in the
//! block list beneath it. The quotes around it are the delimiter, and with
//! `\"` in the escape set nothing inside can close them early.
//!
//! # Declared, never measured
//!
//! Every size printed here is the sealer's own figure
//! ([`FileReveal::total_size`], [`UnrevealedFilePlaceholder::size`] — both
//! documented *"Render it as declared, never as measured"*). The word
//! `declared` sits beside every figure and [`wording::DECLARED_SIZE_NOTE`]
//! states once what it means. This renderer computes no size of its own and
//! prints no rounded unit: bytes are the product's unit of account (D67 §3
//! R1), and a rounded denominator is a worse one.
//!
//! [`FileReveal::path`]: antseal_core::verify::report::FileReveal::path
//! [`FileReveal::total_size`]:
//!     antseal_core::verify::report::FileReveal::total_size
//! [`UnrevealedFilePlaceholder::size`]:
//!     antseal_core::verify::report::UnrevealedFilePlaceholder::size

use antseal_core::verify::redaction::{FileRedaction, RedactionBlock, RedactionView};
use antseal_core::verify::report::VerificationReport;
use antseal_core::verify::wording;

use crate::preview::escape_for_terminal;

/// Indent of a file row inside the block (the house's two spaces, as in
/// `status::WorkStatus::render`).
const FILE_INDENT: &str = "  ";

/// Indent of a per-unit row beneath its file.
const UNIT_INDENT: &str = "      ";

/// Render a verified report's redaction view as lines.
///
/// The caller routes them to stdout (or, under `--json`, to stderr — D51).
#[must_use]
pub fn render_report(report: &VerificationReport) -> Vec<String> {
    render(&RedactionView::from_report(report))
}

/// Render an already-derived view as lines.
///
/// Order is the view's own — manifest file order for touched files, then the
/// placeholders, then the totals — so the rendering carries no ordering
/// decision the model did not already make.
#[must_use]
pub fn render(view: &RedactionView<'_>) -> Vec<String> {
    let mut out = vec![
        format!("{FILE_INDENT}{}", wording::REDACTION_VIEW_LABEL),
        format!("{UNIT_INDENT}{}", wording::DECLARED_SIZE_NOTE),
    ];

    for file in &view.files {
        out.extend(file_lines(file));
    }

    // Placeholders last, and as a run: a reader who has just seen two named
    // files should see the withheld ones as a group rather than interleaved
    // among them, because the ordinal is all that distinguishes them.
    for placeholder in &view.withheld_files {
        out.push(format!(
            "{FILE_INDENT}{}",
            wording::withheld_file_line(placeholder.file_id, placeholder.size)
        ));
    }

    let totals = &view.totals;
    out.push(format!(
        "{FILE_INDENT}{}",
        wording::redaction_totals_line(
            totals.revealed_bytes,
            totals.declared_bytes,
            totals.files_touched,
            totals.files,
        )
    ));
    out.push(format!(
        "{FILE_INDENT}{}",
        wording::withheld_totals_line(
            totals.blacked_out_bytes,
            totals.withheld_file_bytes,
            totals.files_withheld,
        )
    ));
    out
}

/// One touched file: its header, then every block in position order, then
/// the riding mirror when it has one.
fn file_lines(file: &FileRedaction<'_>) -> Vec<String> {
    let mut out = vec![format!(
        "{FILE_INDENT}{}",
        wording::redacted_file_line(
            file.file_id,
            &escape_for_terminal(file.path),
            file.total_size,
            file.fully_revealed,
        )
    )];
    for block in &file.blocks {
        out.push(format!(
            "{UNIT_INDENT}{}",
            block_line(*block, file.total_size)
        ));
    }
    if let Some(mirror) = file.raw_mirror {
        // `raw_mirror` is `Some` only for a full reveal (R53, enforced by
        // the report's producer), which is the one state in which the
        // table's "the original file" phrasing is earned.
        out.push(format!(
            "{UNIT_INDENT}{}",
            wording::mirror_full_reveal_line(mirror.raw_size)
        ));
    }
    out
}

/// One block's row. The revealed and blacked-out arms take the **same three
/// figures** — size, offset, declared total — so no rendering path exists
/// on which a position could be dropped.
fn block_line(block: RedactionBlock, total_size: u64) -> String {
    if block.revealed {
        wording::revealed_span_line(block.unit_id, block.start, block.size(), total_size)
    } else {
        wording::blackout_span_line(block.unit_id, block.start, block.size(), total_size)
    }
}

#[cfg(test)]
#[path = "redaction_out/tests.rs"]
mod tests;
