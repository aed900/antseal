//! U29's unit rows: the rendering's arms, and D51's matrix at the gate.
//!
//! The screens here are built from **constructed** previews rather than
//! from a sealed work, because that is the only way to reach every arm at
//! once — the absent snippet, the empty unit and a path a real seal would
//! have to be attacked to produce. The end-to-end rows (a real seal, a real
//! `run_reveal`, the committed snapshot) are
//! `crates/antseal-cli/tests/reveal_consent.rs`.
//!
//! NON-SECRET: every byte string below is fixture text.

use antseal_core::manifest::{ByteRange, UnitKind};

use super::{
    DISCLOSURE_HEADLINE, DisclosureConsent, DisclosureReport, RECEIPT_EXPOSURE_WARNING, UNIT_INDENT,
};
use crate::error::{CliError, ConsentOutcome, ErrorClass};
use crate::preview::{
    DisclosurePreview, FilePreview, PreviewRow, PreviewTotals, Snippet, SnippetProvenance,
    SnippetWindow,
};
use crate::seal_consent::ConsentPrompt;

// ─────────────────────────────────────────────────────────────────────
// Doubles and builders
// ─────────────────────────────────────────────────────────────────────

/// A prompt that must never be reached (D51: machine mode and `--yes` both
/// answer without asking).
struct NeverAsked;
impl ConsentPrompt for NeverAsked {
    fn ask(&mut self) -> Result<bool, CliError> {
        panic!("the disclosure gate prompted in a mode that must never prompt (D51)");
    }
}

/// A prompt with a scripted answer, counting how often it was asked.
struct Scripted {
    answer: bool,
    asks: usize,
}
impl ConsentPrompt for Scripted {
    fn ask(&mut self) -> Result<bool, CliError> {
        self.asks += 1;
        Ok(self.answer)
    }
}

fn text_snippet(text: &str, truncated: bool) -> Option<Snippet> {
    Some(Snippet {
        window: SnippetWindow::Text(text.to_owned()),
        truncated,
        provenance: SnippetProvenance::SealedBytes,
    })
}

fn hex_snippet(bytes: &[u8], truncated: bool) -> Option<Snippet> {
    Some(Snippet {
        window: SnippetWindow::Hex(bytes.to_vec()),
        truncated,
        provenance: SnippetProvenance::SealedBytes,
    })
}

/// One row, with the fields the screen prints.
fn row(
    unit_id: u64,
    file_id: u64,
    path: &str,
    kind: UnitKind,
    start: u64,
    size: u64,
    snippet: Option<Snippet>,
) -> PreviewRow {
    PreviewRow {
        unit_id,
        file_id,
        path: path.to_owned(),
        kind,
        range: ByteRange::new(start, size),
        size,
        file_fully_revealed: false,
        snippet,
    }
}

/// A preview over the given rows and files, with totals derived from them
/// so no test states a figure twice.
fn preview(rows: Vec<PreviewRow>, files: Vec<FilePreview>) -> DisclosurePreview {
    let totals = PreviewTotals {
        units: rows.len() as u64,
        bytes: rows.iter().map(|r| u128::from(r.size)).sum(),
        files_touched: files.len() as u64,
        files_fully_revealed: files.iter().filter(|f| f.fully_revealed).count() as u64,
        mirror_rides_along: files.iter().any(|f| f.mirror_rides_along),
    };
    DisclosurePreview {
        rows,
        files,
        totals,
    }
}

fn file(file_id: u64, path: &str, fully_revealed: bool, mirror_rides_along: bool) -> FilePreview {
    FilePreview {
        file_id,
        path: path.to_owned(),
        fully_revealed,
        mirror_rides_along,
    }
}

/// The ordinary two-file shape: one file revealed whole with its mirror
/// riding along, one revealed in part.
fn mixed() -> DisclosurePreview {
    preview(
        vec![
            row(
                0,
                0,
                "notes.txt",
                UnitKind::Normal,
                0,
                25,
                text_snippet("café notes\n\nsecond para\n", false),
            ),
            row(
                1,
                0,
                "notes.txt",
                UnitKind::RawMirror,
                0,
                32,
                hex_snippet(&[0xEF, 0xBB, 0xBF, 0x63, 0x61], true),
            ),
            row(
                4,
                2,
                "split.txt",
                UnitKind::Normal,
                11,
                10,
                text_snippet("beta two\n\n", false),
            ),
        ],
        vec![
            file(0, "notes.txt", true, true),
            file(2, "split.txt", false, false),
        ],
    )
}

fn report(preview: &DisclosurePreview, receipt_included: bool) -> DisclosureReport<'_> {
    DisclosureReport {
        preview,
        receipt_included,
    }
}

// ─────────────────────────────────────────────────────────────────────
// The screen
// ─────────────────────────────────────────────────────────────────────

/// **U29 accept**: the headline carries MVP-SPEC.md line 36's own phrase,
/// and every row carries the four fields that line names — file (in the
/// header), byte-range, size, snippet.
#[test]
fn the_screen_says_irreversibly_disclosed_and_carries_the_specs_four_fields() {
    let preview = mixed();
    let lines = report(&preview, false).render();

    assert_eq!(lines[0], DISCLOSURE_HEADLINE);
    assert!(
        lines[0].contains("irreversibly disclosed"),
        "the spec's own words: {}",
        lines[0]
    );

    let joined = lines.join("\n");
    // file
    assert!(joined.contains("file #0 \"notes.txt\""), "{joined}");
    // byte-range + size, on the row that is not at offset 0
    assert!(
        joined.contains("unit 4   normal   10 byte(s) at offset 11"),
        "{joined}"
    );
    // snippet, through D67's renderer
    assert!(joined.contains("\"beta two\\n\\n\""), "{joined}");
}

/// **U29 accept**: the receipt warning renders when the receipt rides, and
/// is **absent otherwise** — asserted as an absence, because a warning that
/// is always there warns about nothing.
#[test]
fn the_receipt_warning_renders_only_when_the_receipt_rides() {
    let preview = mixed();

    let without = report(&preview, false).render().join("\n");
    assert!(!without.contains(RECEIPT_EXPOSURE_WARNING), "{without}");
    assert!(
        !without.to_lowercase().contains("wallet"),
        "no wallet is named when no receipt rides:\n{without}"
    );
    assert!(
        !without.to_lowercase().contains("receipt"),
        "and the receipt is not mentioned at all:\n{without}"
    );

    let with = report(&preview, true).render().join("\n");
    assert!(with.contains(RECEIPT_EXPOSURE_WARNING), "{with}");
    // Spec line 110 + Risks line 185, both halves of the exposure.
    assert!(with.contains("wallet that paid"), "{with}");
    assert!(
        with.contains("every other seal that wallet ever paid for"),
        "{with}"
    );
}

/// The two consequences a `--units` list cannot show on its own: D28's
/// promotion (whole-file commitments open) and D70's ride-along (the exact
/// original bytes). Both stated where they happen, and **only** there.
#[test]
fn the_promotion_and_the_ride_along_are_stated_on_the_file_they_happen_to() {
    let preview = mixed();
    let lines = report(&preview, false).render();

    let notes = lines
        .iter()
        .position(|l| l.contains("file #0 \"notes.txt\""))
        .expect("the whole-revealed file");
    let split = lines
        .iter()
        .position(|l| l.contains("file #2 \"split.txt\""))
        .expect("the partly-revealed file");
    assert!(notes < split, "manifest order");

    assert!(lines[notes].contains("revealed whole"), "{}", lines[notes]);
    assert!(lines[split].contains("partly revealed"), "{}", lines[split]);

    // The notes ride under the whole-revealed file, and stop before the
    // next file's header.
    let between = lines[notes + 1..split].join("\n");
    assert!(between.contains("whole-file commitments"), "{between}");
    assert!(between.contains("raw mirror is included"), "{between}");

    // The partly-revealed file gets neither.
    let after = lines[split..].join("\n");
    assert!(!after.contains("whole-file commitments"), "{after}");
    assert!(!after.contains("raw mirror is included"), "{after}");
}

/// Every D67 §3 arm reaches a line through the one renderer: text, text
/// truncated, hex, hex truncated, the empty unit, and the absent arm.
#[test]
fn every_d67_snippet_arm_renders_through_the_one_renderer() {
    let preview = preview(
        vec![
            row(
                0,
                0,
                "f",
                UnitKind::Normal,
                0,
                5,
                text_snippet("alpha", false),
            ),
            row(
                1,
                0,
                "f",
                UnitKind::Normal,
                5,
                90,
                text_snippet("beta", true),
            ),
            row(
                2,
                0,
                "f",
                UnitKind::Normal,
                95,
                4,
                hex_snippet(&[0xDE, 0xAD], false),
            ),
            row(
                3,
                0,
                "f",
                UnitKind::Normal,
                99,
                40,
                hex_snippet(&[0x89, 0x50], true),
            ),
            row(4, 0, "f", UnitKind::Normal, 139, 0, text_snippet("", false)),
            row(5, 0, "f", UnitKind::Normal, 139, 7, None),
        ],
        vec![file(0, "f", true, false)],
    );
    let lines = report(&preview, false).render();
    let joined = lines.join("\n");

    assert!(joined.contains("   \"alpha\"\n"), "{joined}");
    assert!(joined.contains("   \"beta\"\u{2026}\n"), "{joined}");
    assert!(joined.contains("   hex:dead\n"), "{joined}");
    assert!(joined.contains("   hex:8950\u{2026}\n"), "{joined}");
    assert!(joined.contains("   \"\"\n"), "the empty unit: {joined}");
    assert!(joined.contains("   (snippet unavailable)"), "{joined}");
}

/// The screen this gate paints cannot be repainted by what it is
/// previewing: D67 §3 R3's closed escape set runs over the path **and** the
/// snippet, so neither can carry a newline, a cursor-moving control or a
/// bidi override into the line count.
#[test]
fn neither_a_crafted_path_nor_a_crafted_snippet_can_forge_a_row() {
    let hostile_path = "ok.txt\n      unit 99   normal   1 byte(s) at offset 0   \"safe\"";
    let hostile_text = "hi\u{202E}\u{0007}\n      unit 98   normal   1 byte(s) at offset 0";
    let preview = preview(
        vec![row(
            0,
            0,
            hostile_path,
            UnitKind::Normal,
            0,
            9,
            text_snippet(hostile_text, false),
        )],
        vec![file(0, hostile_path, false, false)],
    );
    let lines = report(&preview, false).render();

    // Headline, one file header, one unit row, totals, finality note.
    assert_eq!(lines.len(), 5, "{lines:#?}");
    for line in &lines {
        assert!(!line.contains('\n'), "every line is one line: {line:?}");
    }
    // The property is **structural**, not lexical: the strings "unit 99"
    // and "unit 98" are still present — they are the sealer's own bytes and
    // the screen shows the bytes — but neither can *be* a row, because a row
    // is a line at the unit indent and the escape set is what stops either
    // from starting one. Asserting their absence instead would have been
    // asserting the wrong thing (and would fail against a correct renderer).
    let rows: Vec<&String> = lines
        .iter()
        .filter(|line| line.starts_with(&format!("{UNIT_INDENT}unit ")))
        .collect();
    assert_eq!(rows.len(), 1, "exactly one unit row: {lines:#?}");
    assert!(
        rows[0].starts_with(&format!("{UNIT_INDENT}unit 0   ")),
        "{rows:?}"
    );

    let joined = lines.join("\n");
    assert!(joined.contains("\\n"), "the LF is escaped: {joined}");
    assert!(joined.contains("\\u{202e}"), "the bidi override: {joined}");
    assert!(joined.contains("\\u{7}"), "the C0 control: {joined}");
}

/// The screen is total over the **rows**, not merely over the files: a row
/// whose file the preview did not name still gets a line, because a consent
/// screen that can silently drop a unit it is about to disclose has failed
/// at its one job. (Unreachable for a preview R15 computed — R15 lists
/// every touched file — which is exactly why it is asserted rather than
/// assumed.)
#[test]
fn a_row_whose_file_the_preview_did_not_name_is_still_shown() {
    let preview = preview(
        vec![
            row(
                0,
                0,
                "named.txt",
                UnitKind::Normal,
                0,
                3,
                text_snippet("abc", false),
            ),
            row(
                9,
                7,
                "gone.txt",
                UnitKind::Normal,
                0,
                4,
                text_snippet("dead", false),
            ),
        ],
        vec![file(0, "named.txt", false, false)],
    );
    let lines = report(&preview, false).render();
    let joined = lines.join("\n");
    assert!(
        joined.contains("also disclosed, from a file this preview could not name:"),
        "{joined}"
    );
    assert!(
        joined.contains("unit 9   normal   4 byte(s) at offset 0"),
        "{joined}"
    );

    // And the arm stays silent when every row has a file.
    let ordinary = mixed();
    assert!(
        !report(&ordinary, false)
            .render()
            .join("\n")
            .contains("could not name"),
        "the arm is unreachable for an ordinary preview"
    );
}

/// U31's positioning discipline on this command's copy, and R18's
/// boundary: a consent screen states what will be disclosed, never what has
/// been proven.
#[test]
fn the_copy_makes_no_notary_or_priority_claim_and_borrows_no_verdict() {
    let preview = mixed();
    let all = report(&preview, true).render().join("\n").to_lowercase();
    for forbidden in ["notar", "priority", "certif", "legal", "attest"] {
        assert!(!all.contains(forbidden), "`{forbidden}` in:\n{all}");
    }
    // Not a verdict sentence: R18's wording is antseal-core's and is not
    // borrowed, paraphrased, or imitated here.
    for verdict in ["existed no later than", "possessed this content by"] {
        assert!(!all.contains(verdict), "`{verdict}` in:\n{all}");
    }
}

// ─────────────────────────────────────────────────────────────────────
// D51's matrix, inherited unchanged
// ─────────────────────────────────────────────────────────────────────

/// The screen renders on **every** row of the matrix — `--yes` skips the
/// question, never the audit trail (D51 invariant 1).
#[test]
fn the_screen_renders_on_every_row_of_the_matrix() {
    let preview = mixed();
    let report = report(&preview, false);

    for (yes, machine) in [(true, true), (true, false), (false, true)] {
        let mut prompt = NeverAsked;
        let gate = DisclosureConsent::new(yes, machine, true, &mut prompt);
        let _ = gate.decide(&report);
        assert_eq!(gate.rendered().len(), 1, "yes={yes} machine={machine}");
        assert_eq!(gate.rendered()[0][0], DISCLOSURE_HEADLINE);
    }

    let mut prompt = Scripted {
        answer: false,
        asks: 0,
    };
    let gate = DisclosureConsent::new(false, false, false, &mut prompt);
    let _ = gate.decide(&report);
    assert_eq!(gate.rendered().len(), 1);
}

/// `--yes` consents in advance and nothing is asked, in either mode.
#[test]
fn yes_consents_in_advance_and_never_prompts() {
    let preview = mixed();
    let report = report(&preview, false);
    for machine in [false, true] {
        let mut prompt = NeverAsked;
        let gate = DisclosureConsent::new(true, machine, false, &mut prompt);
        gate.decide(&report).expect("--yes consents");
    }
}

/// Machine mode without `--yes` aborts — it never prompts and never hangs —
/// and declined ≡ unobtainable: one class, two messages (D51 invariant 3).
#[test]
fn machine_mode_without_yes_aborts_in_the_same_class_a_decline_takes() {
    let preview = mixed();
    let report = report(&preview, false);

    let mut never = NeverAsked;
    let machine = DisclosureConsent::new(false, true, true, &mut never)
        .decide(&report)
        .expect_err("machine mode without --yes cannot consent");
    assert_eq!(machine.class(), ErrorClass::ConsentNotObtained);
    assert!(matches!(
        machine,
        CliError::ConsentNotObtained {
            reason: ConsentOutcome::MachineModeWithoutYes
        }
    ));

    let mut says_no = Scripted {
        answer: false,
        asks: 0,
    };
    let declined = {
        let gate = DisclosureConsent::new(false, false, false, &mut says_no);
        gate.decide(&report).expect_err("a human said no")
    };
    assert_eq!(says_no.asks, 1, "the human was asked exactly once");
    assert_eq!(
        declined.class(),
        machine.class(),
        "one class for both — scripts branch on `did not consent`, not on why"
    );
    assert_ne!(
        declined.to_string(),
        machine.to_string(),
        "and two messages, so a person can tell them apart"
    );
}

/// An interactive yes consents, exactly once.
#[test]
fn an_interactive_yes_consents() {
    let preview = mixed();
    let report = report(&preview, false);
    let mut prompt = Scripted {
        answer: true,
        asks: 0,
    };
    {
        let gate = DisclosureConsent::new(false, false, false, &mut prompt);
        gate.decide(&report).expect("a human said yes");
    }
    assert_eq!(prompt.asks, 1);
}

/// D51 invariant 1/2's routing, as the value the gate holds: `--json`
/// selects stderr so stdout can carry exactly one envelope.
#[test]
fn the_copy_goes_to_stderr_under_json_and_to_stdout_otherwise() {
    let mut prompt = NeverAsked;
    assert!(DisclosureConsent::new(true, true, true, &mut prompt).to_stderr());
    let mut prompt = NeverAsked;
    assert!(!DisclosureConsent::new(true, true, false, &mut prompt).to_stderr());
}
