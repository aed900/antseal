//! `--split blank-lines` paragraph splitting (tasks/G.md G6) — the frozen
//! blank-line boundary semantics of decision D22.
//!
//! # Where it operates
//!
//! On the **canonical rendition** ([`CanonicalBytes`], G2), never on raw
//! bytes. That is what makes the result platform-stable: canonical text is
//! LF-only (D21 normalizes CRLF and lone CR away), so a CRLF file and its LF
//! twin split identically. The returned offsets index those canonical bytes —
//! the same domain as a text file's `size` field, its unit byte-ranges, and
//! its fine-tree leaves (MVP-SPEC.md lines 83, 84, 98).
//!
//! # The boundary definition (decision D22 — frozen, normative)
//!
//! Over canonical bytes:
//!
//! - a **line** is a maximal LF-terminated segment; the final segment may be
//!   unterminated. A file ending in LF therefore has **no** extra empty last
//!   line: `"a\n"` is one line, `"a\n\n"` is two (the second blank).
//! - a line is **blank** iff its content, *excluding* the terminating LF,
//!   consists solely of ASCII space (`0x20`) and horizontal tab (`0x09`) — the
//!   empty line included. No other bytes or scalars qualify: U+00A0, U+3000,
//!   U+000B and U+000C all make a line **non**-blank ([`is_blank_line`]).
//! - a **paragraph boundary** is a maximal run of >= 1 blank lines between
//!   non-blank content.
//!
//! Attachment:
//!
//! - a separating blank run attaches to the **preceding** unit (the trailing
//!   separator is part of the earlier unit);
//! - a leading blank run attaches to the **first** unit;
//! - a trailing blank run at EOF attaches to the **last** unit;
//! - no blank lines -> one unit; all-blank file -> one unit; empty file -> one
//!   empty unit (MVP-SPEC.md line 78).
//!
//! Equivalently — and this is how [`split_blank_lines`] is implemented — cut
//! the file immediately after the terminating LF of the **last** line of every
//! maximal blank run that has non-blank content on *both* sides; leading and
//! trailing runs yield no cut. Every unit therefore contains at least one
//! non-blank line, and every cut offset sits one byte past an LF.
//!
//! Byte-level blankness is exactly scalar-level blankness here: every
//! non-ASCII scalar encodes to bytes >= `0x80` in UTF-8, so no multi-byte
//! sequence can contain `0x20` or `0x09`, and scanning raw canonical bytes
//! cannot be fooled by a continuation byte.
//!
//! # What is frozen, and by whom
//!
//! D22's scope note: the verifier checks only the **tiling invariant** —
//! sorted, non-overlapping, exactly tiling `[0, size)` (MVP-SPEC.md line 121)
//! — *not* that boundaries fall on blank lines. This definition is therefore
//! seal-time CLI semantics frozen by policy for reproducibility, not
//! verification law; what is format-permanent is each seal's resulting unit
//! ranges. A future app version may change the rule without a format bump.
//!
//! # Only fine-tree-covered text files split (decision D24)
//!
//! [`split_blank_lines`] takes a [`SplitEligibleText`] witness, obtainable
//! only from a descriptor that is text **and** fine-tree-covered. Binary files
//! are always single-unit (MVP-SPEC.md line 84) and `--no-fine-tree` files are
//! permanently whole-file-reveal-only (line 85), so neither can reach this
//! code — the contradiction is unrepresentable rather than rejected. The
//! matching loud CLI error at `--no-fine-tree` x `--split` is U's, per D24.

use crate::canon::CanonicalBytes;

use super::unit::{ByteRange, FileUnitPlan, SplitEligibleText};

/// ASCII horizontal tab — half the blank-line alphabet (D22).
const TAB: u8 = 0x09;
/// ASCII space — the other half (D22).
const SPACE: u8 = 0x20;
/// The line terminator of a canonical rendition; the only one, since D21's
/// pipeline maps CRLF and lone CR to LF.
const LF: u8 = b'\n';

/// D22's blank-line predicate: `content` — a line **excluding** its
/// terminating LF — is blank iff it consists solely of ASCII space (`0x20`)
/// and horizontal tab (`0x09`), the empty line included.
///
/// Nothing else counts. A line holding only U+00A0 (no-break space), U+3000
/// (ideographic space), U+000B (vertical tab) or U+000C (form feed) is
/// **non**-blank: those scalars are meaningful content in real documents and
/// survive NFC, and admitting them would require freezing a Unicode
/// whitespace class for no practical gain (D22 rationale 3).
///
/// The tiny frozen alphabet is what keeps the rule byte-decidable and matches
/// CommonMark's blank line — the well-tested precedent for "what users
/// perceive as a paragraph break".
#[must_use]
pub fn is_blank_line(content: &[u8]) -> bool {
    content.iter().all(|&b| b == SPACE || b == TAB)
}

/// Split a text file's canonical rendition into paragraph units on blank-line
/// boundaries — `--split blank-lines` (MVP-SPEC.md lines 84, 149).
///
/// The boundary rule is decision D22, reproduced in full in the module docs
/// (verbatim enough to reimplement from the documentation alone).
///
/// # Output contract
///
/// The returned ranges are **sorted, non-overlapping, and exactly tile**
/// `[0, canonical.len())` — the verifier's structural invariant for non-mirror
/// units (MVP-SPEC.md line 121), established here by construction rather than
/// hoped for. They are plain byte offsets, hence leaf-aligned for the file's
/// fine tree (leaf `i` commits canonical byte `i`, line 96), so a per-unit
/// reveal is just the leaf-range opening `[start, start + length)`.
///
/// Never empty: an empty canonical rendition yields the single empty unit of
/// MVP-SPEC.md line 78. For non-empty input every returned range is non-empty
/// and contains at least one non-blank line.
///
/// Deterministic and allocation-bounded: one left-to-right pass, no
/// randomness, no locale, no I/O.
///
/// # Eligibility
///
/// `_eligible` is a [`SplitEligibleText`] witness (D24 — module docs). It is
/// consumed for its type alone; the split depends only on the bytes.
///
/// # Examples
///
/// ```
/// use antseal_core::canon::{TextMode, UnicodeVersion, canonicalize};
/// use antseal_core::content::{
///     CanonDescriptor, ContentKind, FineTreeOptOut, SplitEligibleText, split_blank_lines,
/// };
///
/// // A CRLF file: canonicalization makes the split platform-stable.
/// let raw = b"alpha\r\n\r\nbeta\r\n";
/// let canonical = canonicalize(UnicodeVersion::CURRENT, TextMode::Detected, raw)?;
/// assert_eq!(canonical.as_str(), "alpha\n\nbeta\n");
///
/// let descriptor = CanonDescriptor::describe_file(
///     ContentKind::Text(UnicodeVersion::CURRENT),
///     canonical.len() as u64,
///     FineTreeOptOut::NotRequested,
/// );
/// let eligible = SplitEligibleText::of(&descriptor).expect("covered text file");
///
/// let units = split_blank_lines(eligible, &canonical);
/// // The blank separator attaches to the preceding unit (D22).
/// assert_eq!(units.len(), 2);
/// assert_eq!((units[0].start(), units[0].length()), (0, 7)); // "alpha\n\n"
/// assert_eq!((units[1].start(), units[1].length()), (7, 5)); // "beta\n"
/// # Ok::<(), antseal_core::canon::CanonicalizeError>(())
/// ```
#[must_use]
pub fn split_blank_lines(
    _eligible: SplitEligibleText,
    canonical: &CanonicalBytes,
) -> Vec<ByteRange> {
    let bytes = canonical.as_bytes();
    if bytes.is_empty() {
        // Empty file -> one empty unit (D22; MVP-SPEC.md line 78).
        return vec![ByteRange::empty()];
    }

    // Exclusive end offsets of every unit but the last, strictly ascending.
    let mut cuts: Vec<usize> = Vec::new();
    // Has any non-blank line been seen? Distinguishes a *leading* blank run
    // (attaches to the first unit, never cuts) from a separating one.
    let mut seen_content = false;
    // End offset of the maximal blank run currently open, once that run is
    // known to be preceded by content. Dropped at EOF: a trailing run attaches
    // to the last unit.
    let mut open_run_end: Option<usize> = None;

    let mut line_start = 0usize;
    while line_start < bytes.len() {
        // A line is a maximal LF-terminated segment; the final one may be
        // unterminated, in which case `content_end == line_end == len`.
        let content_end = line_start
            + bytes[line_start..]
                .iter()
                .position(|&b| b == LF)
                .unwrap_or(bytes.len() - line_start);
        let line_end = if content_end < bytes.len() {
            content_end + 1
        } else {
            bytes.len()
        };

        if is_blank_line(&bytes[line_start..content_end]) {
            if seen_content {
                // Extend (or open) the run; only its *last* line's end matters.
                open_run_end = Some(line_end);
            }
        } else {
            if let Some(run_end) = open_run_end.take() {
                // The run had content on both sides: it separates, and the
                // separator belongs to the preceding unit (D22).
                cuts.push(run_end);
            }
            seen_content = true;
        }

        line_start = line_end;
    }
    // `open_run_end` surviving the loop is a trailing run at EOF — attached to
    // the last unit, so deliberately discarded without cutting.

    let mut ranges = Vec::with_capacity(cuts.len() + 1);
    let mut start = 0usize;
    for cut in cuts {
        ranges.push(span(start, cut));
        start = cut;
    }
    ranges.push(span(start, bytes.len()));
    ranges
}

/// The G5 unit plan for a `--split blank-lines` text file: [`split_blank_lines`]
/// fed straight into [`FileUnitPlan::split`], the only constructor that accepts
/// sub-file ranges (D24).
///
/// This is the seam G14's assembly uses; the mirror, if the file needs one, is
/// attached afterwards by G7 and becomes the file's last unit (D23).
#[must_use]
pub fn plan_blank_line_split(
    eligible: SplitEligibleText,
    canonical: &CanonicalBytes,
) -> FileUnitPlan {
    FileUnitPlan::split(eligible, split_blank_lines(eligible, canonical))
}

/// `[start, end)` as a [`ByteRange`].
///
/// `usize -> u64` is lossless on every supported target (32-bit wasm32 and
/// 64-bit natives), and `end >= start` holds by construction — the cut offsets
/// are strictly ascending and bounded by the input length — so the saturating
/// subtraction can never actually saturate; it is there so a future editing
/// mistake degrades to a zero-width range instead of a release-mode wrap.
fn span(start: usize, end: usize) -> ByteRange {
    debug_assert!(end >= start, "cut offsets must ascend");
    ByteRange::new(start as u64, (end.saturating_sub(start)) as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canon::{TextMode, UnicodeVersion, canonicalize};
    use crate::content::descriptor::{CanonDescriptor, ContentKind, FineTreeOptOut};
    use crate::content::ggm::SaltTree;
    use crate::content::unit::assign_unit_ids;
    use crate::crypto::hkdf::{FileId, derive_fine_seed};
    use crate::crypto::material::MasterSecretRef;
    use crate::test_util::TEST_MASTER_SECRET_W;
    // Property tests need the proptest-bearing `test-util` tier, which the
    // wasm32 `--lib` test build deliberately does not enable (P14,
    // docs/wasm-toolchain.md). Everything else in this module runs on both.
    #[cfg(feature = "test-util")]
    use crate::test_util::strategies::proptest_config;
    #[cfg(feature = "test-util")]
    use proptest::prelude::*;
    #[cfg(feature = "test-util")]
    use proptest::test_runner::TestCaseError;

    /// A split witness. The witness carries no size or content — it only
    /// attests "text + fine-tree-covered" (D24) — so one built from a nominal
    /// covered descriptor is the right witness for every case here, including
    /// the empty-file case, which the real pipeline never splits (an empty file
    /// has no fine tree, hence no witness, hence `whole_file(0)`).
    fn witness() -> SplitEligibleText {
        let descriptor = CanonDescriptor::describe_file(
            ContentKind::Text(UnicodeVersion::CURRENT),
            1,
            FineTreeOptOut::NotRequested,
        );
        SplitEligibleText::of(&descriptor).expect("covered text file is split-eligible")
    }

    /// Canonicalize a KAT literal, asserting it is **already** canonical so the
    /// byte offsets asserted below refer to the literal as written.
    fn canonical(text: &str) -> CanonicalBytes {
        let out = canonicalize(UnicodeVersion::CURRENT, TextMode::Detected, text.as_bytes())
            .expect("KAT inputs are valid UTF-8");
        assert_eq!(
            out.as_bytes(),
            text.as_bytes(),
            "KAT input must already be canonical"
        );
        out
    }

    /// Split a KAT literal into `(start, length)` pairs.
    fn split(text: &str) -> Vec<(u64, u64)> {
        spans(&split_blank_lines(witness(), &canonical(text)))
    }

    fn spans(ranges: &[ByteRange]) -> Vec<(u64, u64)> {
        ranges.iter().map(|r| (r.start(), r.length())).collect()
    }

    // ── D22 blank-line alphabet ─────────────────────────────────────────

    /// The frozen alphabet, at the predicate level: space and tab only.
    #[test]
    fn blank_line_alphabet_is_space_and_tab_only() {
        // Blank: empty, spaces, tabs, mixed.
        for content in ["", " ", "\t", "   ", "\t\t", " \t \t "] {
            assert!(is_blank_line(content.as_bytes()), "{content:?} is blank");
        }
        // Non-blank: any other scalar, whitespace or not.
        for content in [
            "x",
            " x ",
            "\u{00A0}",
            " \u{00A0} ",
            "\u{3000}",
            "\u{000B}",
            "\u{000C}",
            "\u{200B}",
        ] {
            assert!(
                !is_blank_line(content.as_bytes()),
                "{content:?} is not blank"
            );
        }
    }

    /// D22 KAT (required by the decision's consequences): a U+00A0-only line is
    /// **not** a paragraph boundary, so the file stays one unit — while a
    /// whitespace-only line (space, tab, or mixed) **is**, and splits it.
    #[test]
    fn d22_kat_exotic_whitespace_is_not_blank_ascii_whitespace_is() {
        // U+00A0 is two UTF-8 bytes (C2 A0): "a\n" + 2 + "\n" + "b\n" = 7.
        assert_eq!(
            split("a\n\u{00A0}\nb\n"),
            [(0, 7)],
            "U+00A0 line is content"
        );
        // Same for the other near-miss whitespace scalars.
        assert_eq!(
            split("a\n\u{3000}\nb\n"),
            [(0, 8)],
            "U+3000 line is content"
        );
        assert_eq!(
            split("a\n\u{000B}\nb\n"),
            [(0, 6)],
            "U+000B line is content"
        );
        assert_eq!(
            split("a\n\u{000C}\nb\n"),
            [(0, 6)],
            "U+000C line is content"
        );

        // ASCII space / tab / mixed: blank, hence a boundary, and the separator
        // attaches to the preceding unit.
        assert_eq!(split("a\n \nb\n"), [(0, 4), (4, 2)], "space-only line");
        assert_eq!(split("a\n\t\nb\n"), [(0, 4), (4, 2)], "tab-only line");
        assert_eq!(split("a\n \t \nb\n"), [(0, 6), (6, 2)], "mixed line");
        // The degenerate blank line: empty.
        assert_eq!(split("a\n\nb\n"), [(0, 3), (3, 2)], "empty line");
    }

    // ── Attachment KATs (G6 accept) ─────────────────────────────────────

    /// A separating run attaches to the **preceding** unit: the boundary sits
    /// immediately after the run's final LF.
    #[test]
    fn separating_run_attaches_to_the_preceding_unit() {
        //                0123 4 5678
        assert_eq!(split("abc\n\ndef\n"), [(0, 5), (5, 4)]);

        // Spelled out in bytes: the blank line is in the *earlier* unit.
        let bytes = canonical("abc\n\ndef\n");
        let ranges = split_blank_lines(witness(), &bytes);
        let first = &bytes.as_bytes()[..ranges[0].length() as usize];
        assert_eq!(first, b"abc\n\n", "the separator is in the earlier unit");
    }

    /// A leading blank run attaches to the **first** unit — it never opens a
    /// unit of its own.
    #[test]
    fn leading_blank_run_attaches_to_the_first_unit() {
        // "\n\nalpha\n\nbeta\n": leading run (0..2) rides with paragraph 1.
        assert_eq!(split("\n\nalpha\n\nbeta\n"), [(0, 9), (9, 5)]);
        // Whitespace-only leading lines behave identically.
        assert_eq!(split("  \n\t\nalpha\n"), [(0, 11)]);
    }

    /// A trailing blank run at EOF attaches to the **last** unit — it never
    /// forms a unit of its own, however long it is.
    #[test]
    fn trailing_blank_run_attaches_to_the_last_unit() {
        assert_eq!(split("alpha\n\nbeta\n\n\n"), [(0, 7), (7, 7)]);
        // Trailing run only (no separator anywhere): still one unit.
        assert_eq!(split("alpha\n\n"), [(0, 7)]);
        assert_eq!(split("alpha\n \t\n\n"), [(0, 10)]);
    }

    /// A maximal run of several blank lines is one boundary, and the whole run
    /// attaches to the preceding unit.
    #[test]
    fn consecutive_blank_lines_form_one_boundary() {
        //                01 2 3 4 56
        assert_eq!(split("a\n\n\n\nb\n"), [(0, 5), (5, 2)]);
        // Mixed-whitespace run (" ", "\t", ""), still one boundary at its end.
        assert_eq!(split("a\n \n\t\n\n b\n"), [(0, 7), (7, 3)]);
        // Three paragraphs, runs of different widths.
        assert_eq!(split("a\n\nb\n\n\nc\n"), [(0, 3), (3, 4), (7, 2)]);
    }

    /// No blank lines -> exactly one unit, whether or not the file ends in LF.
    #[test]
    fn single_paragraph_is_one_unit() {
        assert_eq!(split("one line\nsecond line\n"), [(0, 21)]);
        assert_eq!(split("no trailing newline"), [(0, 19)]);
        assert_eq!(split("x"), [(0, 1)]);
    }

    /// An all-blank file is one unit: its single run is both leading and
    /// trailing, so it never cuts.
    #[test]
    fn all_blank_file_is_one_unit() {
        assert_eq!(split("\n"), [(0, 1)]);
        assert_eq!(split("\n\n\n"), [(0, 3)]);
        assert_eq!(split(" \n\t\n   \n"), [(0, 8)]);
        assert_eq!(split("   "), [(0, 3)], "unterminated blank line");
    }

    /// An empty file is one **empty** unit (MVP-SPEC.md line 78).
    #[test]
    fn empty_file_is_one_empty_unit() {
        let ranges = split_blank_lines(witness(), &canonical(""));
        assert_eq!(spans(&ranges), [(0, 0)]);
        assert!(ranges[0].is_empty());
    }

    /// The final segment may be unterminated, and a file ending in LF has no
    /// extra empty last line.
    #[test]
    fn final_line_may_be_unterminated() {
        assert_eq!(split("a\n\nb"), [(0, 3), (3, 1)]);
        assert_eq!(split("a\n\n b"), [(0, 3), (3, 2)]);
        // "a\n" is ONE line: no phantom blank line after the terminator, so no
        // trailing run and no boundary.
        assert_eq!(split("a\n"), [(0, 2)]);
    }

    /// Platform stability: a CRLF file, its lone-CR twin, and its LF twin all
    /// canonicalize to the same bytes and therefore split identically (D21).
    #[test]
    fn line_ending_flavours_split_identically() {
        let expected = [(0, 7), (7, 5)];
        for raw in [
            &b"alpha\n\nbeta\n"[..],
            &b"alpha\r\n\r\nbeta\r\n"[..],
            &b"alpha\r\rbeta\r"[..],
        ] {
            let canonical = canonicalize(UnicodeVersion::CURRENT, TextMode::Detected, raw)
                .expect("valid UTF-8");
            assert_eq!(canonical.as_str(), "alpha\n\nbeta\n");
            assert_eq!(
                spans(&split_blank_lines(witness(), &canonical)),
                expected,
                "{raw:?}"
            );
        }
    }

    /// Determinism: identical input -> identical ranges, every time.
    #[test]
    fn splitting_is_deterministic() {
        for text in [
            "",
            "a",
            "a\n\nb\n",
            "\n\nlead\n\n\nmid\n\n\n",
            " \t\n\nx\u{00A0}y\n\n",
        ] {
            let canonical = canonical(text);
            let first = split_blank_lines(witness(), &canonical);
            for _ in 0..4 {
                assert_eq!(split_blank_lines(witness(), &canonical), first, "{text:?}");
            }
        }
    }

    // ── Composition with G5 and the fine tree (G6 accept) ───────────────

    /// G6 accept: the boundaries are byte offsets usable **directly** as
    /// fine-tree leaf ranges — leaf-aligned by construction, because leaf `i`
    /// commits canonical byte `i` (MVP-SPEC.md line 96). Every unit's leaves
    /// resolve inside the file's salt tree, each leaf belongs to exactly one
    /// unit, and the units together cover `0..n` with no leaf left over.
    #[test]
    fn unit_boundaries_are_fine_tree_leaf_ranges() {
        let canonical = canonical("alpha\n\nbeta\n\ngamma\n");
        let n = canonical.len() as u64;
        let ranges = split_blank_lines(witness(), &canonical);
        assert_eq!(spans(&ranges), [(0, 7), (7, 6), (13, 6)]);

        let w = MasterSecretRef::from_bytes(&TEST_MASTER_SECRET_W);
        let s_root = derive_fine_seed(w, FileId(0));
        let tree = SaltTree::new(&s_root, n).expect("non-empty file has a tree");
        assert_eq!(tree.leaf_count(), n, "leaf count is the canonical length");

        let mut covered: Vec<u64> = Vec::new();
        for range in &ranges {
            let end = range.end().expect("no overflow");
            assert!(
                end <= tree.leaf_count(),
                "range stays inside the leaf space"
            );
            for leaf in range.start()..end {
                assert!(
                    tree.salt(leaf).is_some(),
                    "leaf {leaf} is a real slot, so its salt derives"
                );
                assert!(tree.leaf_address(leaf).is_ok());
                covered.push(leaf);
            }
        }
        let all: Vec<u64> = (0..n).collect();
        assert_eq!(covered, all, "the units partition the leaf space exactly");
    }

    /// The split feeds G5's plan seam, and the resulting work-global ids follow
    /// range order (D23).
    #[test]
    fn plan_blank_line_split_feeds_the_unit_model() {
        let canonical = canonical("alpha\n\nbeta\n");
        let plan = plan_blank_line_split(witness(), &canonical);
        assert_eq!(plan.unit_count(), 2);
        assert_eq!(plan.mirror_raw_size(), None);
        assert_eq!(
            spans(plan.normal_ranges()),
            [(0, 7), (7, 5)],
            "plan carries G6's ranges unchanged"
        );

        let units = assign_unit_ids(&[plan]);
        let ids: Vec<u64> = units.iter().map(|u| u.unit_id()).collect();
        assert_eq!(ids, [0, 1]);
        assert_eq!(units[0].true_length(), 7);
        assert_eq!(units[1].true_length(), 5);
        // The tiling the verifier will re-check (MVP-SPEC.md line 121).
        assert_eq!(
            units[0].byte_range().end(),
            Some(units[1].byte_range().start())
        );
        assert_eq!(units[1].byte_range().end(), Some(canonical.len() as u64));
    }

    // ── Property tests ──────────────────────────────────────────────────

    /// The output contract: sorted, non-overlapping, exactly tiling
    /// `[0, len)`, never empty, and (for non-empty input) with no empty unit
    /// and every interior boundary one byte past an LF.
    #[cfg(feature = "test-util")]
    fn check_contract(ranges: &[ByteRange], len: u64) -> Result<(), TestCaseError> {
        prop_assert!(!ranges.is_empty(), "a file always has at least one unit");
        prop_assert_eq!(ranges[0].start(), 0, "tiling starts at 0");

        let mut previous_end = 0u64;
        for range in ranges {
            prop_assert_eq!(range.start(), previous_end, "sorted, no gap, no overlap");
            previous_end = range.end().expect("no overflow on real lengths");
            if len > 0 {
                prop_assert!(range.length() > 0, "no empty unit in a non-empty file");
            }
        }
        prop_assert_eq!(previous_end, len, "exact tiling of [0, len)");
        Ok(())
    }

    /// Text that exercises the rule: LF-heavy, with both halves of the blank
    /// alphabet, the near-miss whitespace scalars D22 excludes, CR (which
    /// canonicalization removes), and ordinary content.
    #[cfg(feature = "test-util")]
    fn splitty_text() -> impl Strategy<Value = String> {
        proptest::collection::vec(
            prop_oneof![
                30 => Just('\n'),
                8 => Just(' '),
                8 => Just('\t'),
                4 => Just('\r'),
                24 => proptest::char::range('a', 'z'),
                4 => Just('\u{00A0}'),
                4 => Just('\u{3000}'),
                4 => Just('\u{000B}'),
                4 => Just('\u{000C}'),
                4 => Just('\u{FEFF}'),
            ],
            0..48,
        )
        .prop_map(|chars| chars.into_iter().collect())
    }

    #[cfg(feature = "test-util")]
    proptest! {
        #![proptest_config(proptest_config(0x0064_0006))]

        /// G6 accept: over arbitrary text, the ranges are sorted,
        /// non-overlapping, and exactly tile `[0, len)`; concatenating them
        /// reproduces the canonical bytes; and the split is deterministic.
        #[test]
        fn ranges_tile_the_canonical_rendition(text in splitty_text()) {
            let canonical = canonicalize(UnicodeVersion::CURRENT, TextMode::Detected, text.as_bytes())
                .expect("generated text is valid UTF-8");
            let len = canonical.len() as u64;
            let ranges = split_blank_lines(witness(), &canonical);
            check_contract(&ranges, len)?;

            // Exact tiling, restated as reconstruction.
            let mut rebuilt: Vec<u8> = Vec::with_capacity(canonical.len());
            for range in &ranges {
                let start = range.start() as usize;
                let end = range.end().expect("no overflow") as usize;
                rebuilt.extend_from_slice(&canonical.as_bytes()[start..end]);
            }
            prop_assert_eq!(rebuilt.as_slice(), canonical.as_bytes());

            prop_assert_eq!(split_blank_lines(witness(), &canonical), ranges);
        }

        /// The same contract over **arbitrary bytes** routed through forced-text
        /// canonicalization (total by D20) — the split can never see CR, so no
        /// platform-dependent boundary exists.
        #[test]
        fn ranges_tile_forced_text_from_arbitrary_bytes(raw in proptest::collection::vec(any::<u8>(), 0..64)) {
            let canonical = canonicalize(UnicodeVersion::CURRENT, TextMode::Forced, &raw)
                .expect("forced text is total");
            prop_assert!(!canonical.as_bytes().contains(&b'\r'), "canonical text is LF-only");
            let ranges = split_blank_lines(witness(), &canonical);
            check_contract(&ranges, canonical.len() as u64)?;
        }

        /// Structural consequences of D22's attachment rule: every interior
        /// boundary lands one byte past an LF (a separating run always ends in
        /// one), and every unit holds at least one non-blank line.
        #[test]
        fn boundaries_land_after_a_blank_line(text in splitty_text()) {
            let canonical = canonicalize(UnicodeVersion::CURRENT, TextMode::Detected, text.as_bytes())
                .expect("generated text is valid UTF-8");
            let bytes = canonical.as_bytes();
            let ranges = split_blank_lines(witness(), &canonical);

            for range in ranges.iter().skip(1) {
                let cut = range.start() as usize;
                prop_assert_eq!(bytes[cut - 1], b'\n', "cut sits just after an LF");
            }
            // An all-blank file is the one shape whose single unit has no
            // non-blank line (D22: leading and trailing runs never cut).
            let file_has_content = bytes.split(|&b| b == b'\n').any(|line| !is_blank_line(line));
            if file_has_content {
                for range in &ranges {
                    let start = range.start() as usize;
                    let end = range.end().expect("no overflow") as usize;
                    let has_content = bytes[start..end]
                        .split(|&b| b == b'\n')
                        .any(|line| !is_blank_line(line));
                    prop_assert!(has_content, "every unit holds a non-blank line");
                }
            } else {
                prop_assert_eq!(ranges.len(), 1, "all-blank (or empty) file is one unit");
            }
        }
    }
}
