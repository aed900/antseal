//! U27 unit tests: the pieces of `show` that need no vault — the domain
//! rule, the rendering shapes, the machine snippet form, and the mirror
//! mark's identity with the refusal it quotes.
//!
//! The end-to-end rows (a real seal, the D43 ladder, the `--json` fixture)
//! are `tests/show_command.rs`.
//!
//! NON-SECRET: every byte string here is a documented fixture.

use antseal_core::manifest::fixtures as mf;

use super::*;

fn text_canon() -> CanonMode {
    CanonMode::Text {
        canon_commit: mf::commit32(0x03),
        unicode_version: mf::UNICODE_VERSION.to_owned(),
    }
}

fn file_row(kind: DescriptorKind, fine_tree: bool) -> FileRow {
    let (offset_domain, unicode_version) = match kind {
        DescriptorKind::Text => (
            FineTreeDomain::Canonical,
            Some(mf::UNICODE_VERSION.to_owned()),
        ),
        DescriptorKind::Binary => (FineTreeDomain::Raw, None),
    };
    FileRow {
        file_id: 0,
        path: "notes.txt".to_owned(),
        kind,
        offset_domain,
        fine_tree,
        size: 25,
        unicode_version,
        raw_mirror_unit_id: None,
    }
}

fn row(kind: UnitKind, snippet: Option<Snippet>) -> PreviewRow {
    PreviewRow {
        unit_id: 7,
        file_id: 0,
        path: "notes.txt".to_owned(),
        kind,
        range: antseal_core::manifest::ByteRange::new(4, 11),
        size: 11,
        file_fully_revealed: true,
        snippet,
    }
}

fn text_snippet(provenance: SnippetProvenance) -> Snippet {
    Snippet {
        window: SnippetWindow::Text("hello world".to_owned()),
        truncated: false,
        provenance,
    }
}

// ── the domain rule (spec line 83 / line 92) ──────────────────────────

#[test]
fn the_offset_domain_follows_the_committed_kind_and_the_mirror_is_always_raw() {
    assert_eq!(
        offset_domain(&text_canon(), UnitKind::Normal),
        FineTreeDomain::Canonical,
        "a text file's normal units index into the canonical rendition"
    );
    assert_eq!(
        offset_domain(&CanonMode::Binary, UnitKind::Normal),
        FineTreeDomain::Raw
    );
    // Spec line 92: the mirror lives in the raw byte domain whatever its
    // file's kind — that is the whole point of it.
    assert_eq!(
        offset_domain(&text_canon(), UnitKind::RawMirror),
        FineTreeDomain::Raw
    );
    assert_eq!(
        offset_domain(&CanonMode::Binary, UnitKind::RawMirror),
        FineTreeDomain::Raw
    );
}

// ── the mirror mark is the refusal's own sentence ─────────────────────

#[test]
fn the_mirror_mark_is_the_reveal_refusals_own_display() {
    let note = mirror_note(7);
    assert_eq!(
        note,
        RevealError::RawMirrorNotUnitSelectable { unit_id: 7 }.to_string(),
        "the preview must quote the refusal, never restate it"
    );
    assert!(note.contains("cannot be selected by id"), "{note}");
    assert!(note.contains("unit 7"), "the id is named: {note}");
}

// ── rendering ─────────────────────────────────────────────────────────

#[test]
fn a_unit_row_carries_size_offset_and_the_domain_total_on_every_arm() {
    // Normal: the total is the file's tiling-domain size.
    let normal = unit_line(
        &row(
            UnitKind::Normal,
            Some(text_snippet(SnippetProvenance::SealedBytes)),
        ),
        &file_row(DescriptorKind::Text, true),
    );
    assert_eq!(
        normal,
        "unit 7   normal   11 byte(s) at offset 4 of 25   \"hello world\"   [sealed bytes]"
    );

    // Mirror: the total is its own raw size, because that is the domain
    // its offsets live in.
    let mirror = unit_line(
        &row(
            UnitKind::RawMirror,
            Some(Snippet {
                window: SnippetWindow::Hex(vec![0xEF, 0xBB, 0xBF]),
                truncated: true,
                provenance: SnippetProvenance::SealedBytes,
            }),
        ),
        &file_row(DescriptorKind::Text, true),
    );
    assert_eq!(
        mirror,
        "unit 7   raw-mirror   11 byte(s) at offset 4 of 11   hex:efbbbf…   [sealed bytes]"
    );
}

#[test]
fn the_current_file_arm_carries_its_whole_warning_and_the_absent_arm_carries_no_tag() {
    let current = unit_line(
        &row(
            UnitKind::Normal,
            Some(text_snippet(SnippetProvenance::CurrentFile)),
        ),
        &file_row(DescriptorKind::Text, true),
    );
    assert!(
        current.ends_with("[current file — may differ if modified since sealing]"),
        "{current}"
    );

    // D67 §3 R5: the absent arm renders the literal, and the row keeps its
    // position and size. No provenance tag exists to print.
    let absent = unit_line(
        &row(UnitKind::Normal, None),
        &file_row(DescriptorKind::Text, true),
    );
    assert_eq!(
        absent,
        "unit 7   normal   11 byte(s) at offset 4 of 25   (snippet unavailable)"
    );
    assert!(!absent.contains('['), "no empty tag bracket: {absent}");
}

#[test]
fn a_no_fine_tree_file_says_it_is_whole_file_reveal_only() {
    // Spec lines 18/85: `--no-fine-tree` files are "permanently
    // whole-file-reveal only", and D24 makes them single-unit, so the
    // header is where a `--units` chooser must read it.
    let opted_out = file_line(&file_row(DescriptorKind::Binary, false));
    assert_eq!(
        opted_out,
        "file #0 \"notes.txt\" — binary, 25 byte(s); unit offsets are raw bytes; \
         no fine tree — whole-file reveal only"
    );
    let covered = file_line(&file_row(DescriptorKind::Text, true));
    assert_eq!(
        covered,
        "file #0 \"notes.txt\" — text, 25 byte(s); unit offsets are canonical bytes; \
         fine tree present"
    );
}

#[test]
fn a_path_is_escaped_through_the_closed_set_so_it_cannot_forge_a_row() {
    // The path is the sealer's own argument here rather than an
    // adversary's bundle (D67 §9 (ii)'s distinction), but it goes through
    // the same closed, frozen set R19's redaction view uses — not
    // `escape_debug`, whose output tracks Unicode data across toolchains
    // and would rot this rendering's snapshot under a pin bump (D67 §3 R3).
    let mut file = file_row(DescriptorKind::Text, true);
    file.path = "a\nunit 99   normal\u{202e}".to_owned();
    let line = file_line(&file);
    assert!(!line.contains('\n'), "exactly one line: {line}");
    assert!(line.contains("\"a\\nunit 99   normal\\u{202e}\""), "{line}");

    // A quote inside the path cannot close the delimiter early.
    file.path = "q\"uote".to_owned();
    assert!(
        file_line(&file).contains("\"q\\\"uote\""),
        "{}",
        file_line(&file)
    );

    // Ordinary prose passes through: the closed set escapes controls and
    // bidi, not the user's own alphabet.
    file.path = "notes/café.md".to_owned();
    assert!(file_line(&file).contains("\"notes/café.md\""));
}

// ── the machine snippet value (D67 §3 R6) ─────────────────────────────

#[test]
fn the_machine_snippet_carries_the_raw_window_never_the_rendering() {
    // Text: the raw window as a JSON string. serde escapes the control
    // character its own way; D67 §3 R3's `\u{7}` spelling is terminal-only
    // and must not appear.
    let value = snippet_json(&Snippet {
        window: SnippetWindow::Text("a\u{7}b…".to_owned()),
        truncated: true,
        provenance: SnippetProvenance::SealedBytes,
    });
    assert_eq!(value["form"], serde_json::json!("text"));
    assert_eq!(value["value"], serde_json::json!("a\u{7}b…"));
    assert_eq!(value["truncated"], serde_json::json!(true));
    assert_eq!(value["provenance"], serde_json::json!("sealed-bytes"));
    let text = serde_json::to_string(&value).expect("serializes");
    assert!(text.contains("\\u0007"), "serde's escaping: {text}");
    assert!(!text.contains("u{7}"), "not R3's spelling: {text}");

    // Hex: bare lowercase pairs, no `hex:` label, no marker.
    let value = snippet_json(&Snippet {
        window: SnippetWindow::Hex(vec![0xEF, 0xBB, 0xBF]),
        truncated: true,
        provenance: SnippetProvenance::CurrentFile,
    });
    assert_eq!(value["form"], serde_json::json!("hex"));
    assert_eq!(value["value"], serde_json::json!("efbbbf"));
    assert_eq!(value["provenance"], serde_json::json!("current-file"));
    let text = serde_json::to_string(&value).expect("serializes");
    assert!(!text.contains("hex:"), "no label in the value: {text}");
    assert!(!text.contains('…'), "no marker in the value: {text}");
}

#[test]
fn the_read_cap_is_pinned() {
    // A change here changes which works show a current-file snippet, so it
    // is a reviewed number rather than a constant nobody re-reads.
    assert_eq!(CURRENT_FILE_READ_CAP_BYTES, 64 * 1024 * 1024);
}
