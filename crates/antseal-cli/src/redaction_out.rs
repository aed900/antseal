//! The **CLI text renderer** for the redaction view (task R19).
//!
//! [`antseal_core::verify::redaction`] derives the view — per file, the
//! revealed and blacked-out unit blocks interleaved in position order, the
//! committed placeholders for wholly unrevealed files, and the work-level
//! totals — and assembles it into [`RenderedRedaction`], the block's final
//! display strings. This module adds **indentation and nothing else**: after
//! D130 §3 R6 it names [`antseal_core::verify::wording`] nowhere, and R23's
//! page draws from the **same assembly** rather than from the same
//! vocabulary, so the CLI and the page cannot spell MVP-SPEC.md line 121's
//! guardrail two ways — not because both were careful, but because there is
//! only one composition and both call it.
//!
//! # The guardrail is the whole point
//!
//! Line 121: *"Every reveal displays position + total size
//! (anti-out-of-context guardrail)."* The rule is unconditional, so this
//! renderer has **no flag, no width heuristic and no summarising arm** that
//! could drop a position. The three figures are stated by the assembly's own
//! `block_lines`, whose revealed and blacked-out arms take the same three;
//! [`render`] is a fold over them rather than a set of cases, so there is no
//! shape whose rendering forgot.
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
//! The set stays **here**, above core, and is handed to the assembly as a
//! function (D130 §3 R5): the page's DOM policy neutralises a different byte
//! set, and D67 §3 R8 keeps `antseal-core`'s WASM safety untouched by keeping
//! neither set inside it.
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

use antseal_core::verify::redaction::{RedactionView, RenderedRedaction, RenderedRedactionFile};
use antseal_core::verify::report::VerificationReport;

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

/// Render an already-derived view as lines, under this surface's escape.
///
/// Order is the view's own — manifest file order for touched files, then the
/// placeholders, then the totals — so the rendering carries no ordering
/// decision the model did not already make.
#[must_use]
pub fn render(view: &RedactionView<'_>) -> Vec<String> {
    render_block(&RenderedRedaction::new(view, &escape_for_terminal))
}

/// Indent an already-assembled block into the lines `antseal verify` prints.
///
/// The whole of this module's remaining job. Declaration order in
/// [`RenderedRedaction`] **is** render order, so this is a fold and not a
/// set of cases: there is no branch here that could drop a row, and the page
/// folds the identical document the same way.
#[must_use]
pub fn render_block(block: &RenderedRedaction) -> Vec<String> {
    let mut out = vec![
        format!("{FILE_INDENT}{}", block.view_label),
        format!("{UNIT_INDENT}{}", block.declared_size_note),
    ];

    for file in &block.files {
        out.extend(file_lines(file));
    }

    // Placeholders last, and as a run: a reader who has just seen two named
    // files should see the withheld ones as a group rather than interleaved
    // among them, because the ordinal is all that distinguishes them.
    for placeholder in &block.withheld_files {
        out.push(format!("{FILE_INDENT}{}", placeholder.line));
    }

    out.push(format!("{FILE_INDENT}{}", block.totals_line));
    out.push(format!("{FILE_INDENT}{}", block.withheld_totals_line));
    out
}

/// One touched file: its header, then every block in position order, then
/// the riding mirror when it has one.
fn file_lines(file: &RenderedRedactionFile) -> Vec<String> {
    let mut out = vec![format!("{FILE_INDENT}{}", file.header_line)];
    for line in &file.block_lines {
        out.push(format!("{UNIT_INDENT}{line}"));
    }
    if let Some(mirror_line) = &file.mirror_line {
        out.push(format!("{UNIT_INDENT}{mirror_line}"));
    }
    out
}

#[cfg(test)]
#[path = "redaction_out/tests.rs"]
mod tests;
