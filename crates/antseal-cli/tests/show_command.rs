//! U27 acceptance suite: `show <work-id>`'s unit table over a real seal.
//!
//! Every row seals the fixture work through the S12 pipeline into a real
//! vault and then gathers through [`antseal_cli::show::WorkUnits::gather`] —
//! the command's own path — so what is asserted is a genuine
//! seal → show round trip. The fixture covers the Accept's whole matrix in
//! one work: a text file carrying a **raw mirror** (BOM + CRLF + NFD), a
//! **binary** file, a **`--split blank-lines`** text file tiled into three
//! units, and a **`--no-fine-tree`** text file.
//!
//! The D43 ladder is exercised by removing rungs from underneath a sealed
//! work — cache present, cache gone with the files still on disk, cache gone
//! and the files gone — because that is the only way to see the fallback and
//! the absent arm at all.
//!
//! **No backend is constructed anywhere below the seal.** `show` holds none
//! (D67 §1 j), and a `MockBackend` appears only because sealing needs one.
//!
//! NON-SECRET: every fixture byte string is documented here.

mod common;

use std::path::{Path, PathBuf};

use antseal_cli::pipeline::journal::{BlobSlot, StagedBlob, UNIT_ENTRY_BASE};
use antseal_cli::pipeline::{
    NoBarriers, Pipeline, RevealEngine, RevealError, RevealRequest, SealFile, SealRequest,
    SealResult, UnitSelection, VaultJournal, hex32,
};
use antseal_cli::preview::{SNIPPET_UNAVAILABLE, SnippetProvenance, SnippetWindow};
use antseal_cli::show::WorkUnits;
use antseal_cli::vault::session::UnlockedVault;
use antseal_cli::vault::store::{SealShapingFlags, WorkState, WorkStore};
use antseal_core::content::{FileFlags, SplitMode};
use antseal_core::crypto::secrets::SealId;
use antseal_core::crypto::sig_policy::SigPolicy;
use antseal_core::manifest::UnitKind;
use antseal_net::NetworkId;
use antseal_net::test_util::{MockBackend, block_on};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

use common::{IsolatedVault, RecordingGate, ScriptedConsent};

// ─────────────────────────────────────────────────────────────────────
// Fixture content — one work, every shape class the Accept names
// ─────────────────────────────────────────────────────────────────────

/// Text whose raw bytes differ from canonical three ways at once (BOM,
/// CRLF, NFD `e`+U+0301), so it carries a **raw mirror**. Canonical:
/// `"café notes\n\nsecond para\n"` (25 bytes); raw: 32 bytes.
const CRLF_BOM_NFD: &[u8] = "\u{FEFF}caf\u{65}\u{301} notes\r\n\r\nsecond para\r\n".as_bytes();

/// Binary: no canonical rendition, raw-domain offsets, no mirror.
const BINARY: &[u8] = &[0x00, 0x01, 0x02, 0xFF, 0xFE, 0x7F, 0x80, 0x00, 0x42];

/// Canonical-already text tiled into three units by `--split blank-lines`.
const SPLIT_TEXT: &[u8] = b"alpha one\n\nbeta two\n\ngamma three\n";

/// Canonical-already text sealed with `--no-fine-tree` **and** a split
/// request: D24 makes it single-unit anyway, which is what "whole-file
/// reveal only" means in the unit table.
const OPTED_OUT: &[u8] = b"first para\n\nsecond para\n";

/// A scratch directory that removes itself, holding the real files whose
/// absolute paths the seal records (the current-file rung reads them).
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "antseal-u27-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        std::fs::create_dir_all(path.join("data")).expect("mk scratch");
        Self(path)
    }

    fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The four fixture files, as given and as they sit on disk.
const NAMES: [&str; 4] = ["notes.txt", "data/blob.bin", "split.txt", "plain.md"];
const CONTENT: [&[u8]; 4] = [CRLF_BOM_NFD, BINARY, SPLIT_TEXT, OPTED_OUT];

/// Write the fixture files into `scratch` and seal them, returning the
/// printed work id. The **absolute** paths are the real ones, because the
/// current-file rung of the D43 ladder reads exactly those.
fn seal_fixture(mock: &MockBackend, vault: &UnlockedVault, scratch: &Scratch) -> String {
    let absolutes: Vec<PathBuf> = NAMES.iter().map(|n| scratch.join(n)).collect();
    for (path, bytes) in absolutes.iter().zip(CONTENT) {
        std::fs::write(path, bytes).expect("plant the fixture file");
    }
    let absolute_strings: Vec<String> = absolutes
        .iter()
        .map(|p| p.to_str().expect("utf-8 path").to_owned())
        .collect();
    let flags = [
        FileFlags::new(),
        FileFlags::new(),
        FileFlags::new().with_split(SplitMode::BlankLines),
        // D24: the split request cannot apply to an opted-out file.
        FileFlags::new()
            .with_no_fine_tree()
            .with_split(SplitMode::BlankLines),
    ];
    let files: Vec<SealFile<'_>> = (0..NAMES.len())
        .map(|i| SealFile {
            path_as_given: NAMES[i],
            path_absolute: &absolute_strings[i],
            bytes: CONTENT[i],
            flags: flags[i],
        })
        .collect();

    let mut journal_rng = ChaCha20Rng::from_seed([0x27; 32]);
    let journal = VaultJournal::new(WorkStore::new(vault), &mut journal_rng);
    let gate = RecordingGate::new();
    let consent = ScriptedConsent::always_yes();
    let pipeline = Pipeline::new(mock, &gate, &journal, &consent, &NoBarriers);
    let request = SealRequest {
        files: &files,
        title: "u27 fixture".to_owned(),
        claimed_time_unix_secs: 1_800_000_000,
        app_version: "antseal-test/1".to_owned(),
        network: NetworkId::Devnet,
        no_anchor: false,
        degraded: false,
        dry_run: false,
        sig_policy: SigPolicy::hybrid(),
        // The production path fills `SealRequest.title` **from**
        // `plan.shaping.title` (`seal_run.rs:465`) and stores the shaping on
        // the record, so the fixture sets both from one value — as `seal`
        // does — and `show` reads the title where `list` and `status` read
        // it.
        shaping: SealShapingFlags {
            title: Some("u27 fixture".to_owned()),
            ..SealShapingFlags::default()
        },
    };
    match block_on(pipeline.seal(&request, &mut ChaCha20Rng::from_seed([0x28; 32])))
        .expect("the fixture seals")
    {
        SealResult::Sealed(outcome) => hex32(&outcome.work_id),
        SealResult::DryRun(_) => unreachable!("not a dry run"),
    }
}

/// The only work in a fixture vault.
fn only_work(store: &WorkStore<'_>) -> SealId {
    let works = store.list_works().expect("list");
    assert_eq!(works.len(), 1, "the fixture vault holds one work");
    works[0]
}

/// Gather `show`'s document for the fixture vault's single work.
fn show(vault: &UnlockedVault) -> WorkUnits {
    let store = WorkStore::new(vault);
    let seal_id = only_work(&store);
    WorkUnits::gather(&store, &seal_id).expect("show gathers")
}

/// Delete every cached unit ciphertext, leaving the plan record (and so the
/// manifest) intact — the state a `vault import`ed work is in, since D43 §3
/// excludes the cache from an export.
fn wipe_unit_cache(vault: &UnlockedVault) {
    let store = WorkStore::new(vault);
    let seal_id = only_work(&store);
    for entry in store.list_journal_entries(&seal_id).expect("entries") {
        if entry >= UNIT_ENTRY_BASE {
            store.delete_journal_entry(&seal_id, entry).expect("delete");
        }
    }
}

// ─────────────────────────────────────────────────────────────────────
// State: `show` reads, and reading is not restoring
// ─────────────────────────────────────────────────────────────────────

/// An **incomplete** work still shows its units, with its state named.
///
/// Deliberately unlike `restore`, which refuses anything but `Complete`
/// (`RestoreError::NotRestorable`): the manifest is built before the
/// payment (spec line 34's normative order), so a seal interrupted after
/// staging has a real unit table — and the command a user reaches for to
/// see what is in a half-finished seal must not be the command that
/// refuses. Nothing here is disclosed or written; `show` is a read.
#[test]
fn an_incomplete_work_still_shows_its_units_and_says_it_is_incomplete() {
    let scratch = Scratch::new("incomplete");
    let vault = IsolatedVault::create("u27-incomplete");
    let unlocked = vault.unlock();
    seal_fixture(&MockBackend::new(), &unlocked, &scratch);
    {
        let store = WorkStore::new(&unlocked);
        let seal_id = only_work(&store);
        store
            .set_state(
                &seal_id,
                WorkState::IncompletePostPay,
                &mut ChaCha20Rng::from_seed([0x2A; 32]),
            )
            .expect("re-tag the work");
    }

    let units = show(&unlocked);
    assert_eq!(units.state, WorkState::IncompletePostPay);
    assert_eq!(units.rows().len(), 7, "the whole unit table is still there");
    assert_eq!(units.json()["state"], serde_json::json!("incomplete"));
    assert!(
        units.render()[0].ends_with("  incomplete"),
        "{:?}",
        units.render()[0]
    );
}

// ─────────────────────────────────────────────────────────────────────
// The table is total over the manifest, and every field is present
// ─────────────────────────────────────────────────────────────────────

/// Accept row 1: the fixture work renders **all** fields for every unit of
/// every file, across the four shape classes.
#[test]
fn every_unit_of_every_file_is_a_row_with_all_its_fields() {
    let scratch = Scratch::new("all-fields");
    let vault = IsolatedVault::create("u27-all");
    let unlocked = vault.unlock();
    let _work_id = seal_fixture(&MockBackend::new(), &unlocked, &scratch);
    let units = show(&unlocked);

    // Four files, in manifest order, each with the committed domain its
    // kind implies (spec line 83) and the fine-tree state it was sealed
    // with.
    let files: Vec<(u64, &str, &str, &str, bool)> = units
        .files
        .iter()
        .map(|f| {
            (
                f.file_id,
                f.path.as_str(),
                f.kind.registry_value_name(),
                f.offset_domain.registry_value_name(),
                f.fine_tree,
            )
        })
        .collect();
    assert_eq!(
        files,
        vec![
            (0, "notes.txt", "text", "canonical", true),
            (1, "data/blob.bin", "binary", "raw", true),
            (2, "split.txt", "text", "canonical", true),
            // D24 / spec lines 18 + 85: opted out, so no fine tree.
            (3, "plain.md", "text", "canonical", false),
        ]
    );
    assert_eq!(
        units.files[0].unicode_version.as_deref(),
        Some("unicode-17.0.0"),
        "spec line 83: the descriptor records the exact NFC version"
    );
    assert!(units.files[1].unicode_version.is_none(), "binary has none");
    assert_eq!(units.files[0].raw_mirror_unit_id, Some(1));
    assert!(units.files[2].raw_mirror_unit_id.is_none());

    // Seven units: notes 0 + its mirror 1, blob 2, split 3/4/5, opted-out 6.
    let rows: Vec<(u64, u64, &str, u64, u64, u64)> = units
        .rows()
        .iter()
        .map(|r| {
            (
                r.unit_id,
                r.file_id,
                r.kind.registry_value_name(),
                r.range.start(),
                r.range.length(),
                r.size,
            )
        })
        .collect();
    assert_eq!(
        rows,
        vec![
            (0, 0, "normal", 0, 25, 25),
            (1, 0, "raw-mirror", 0, 32, 32),
            (2, 1, "normal", 0, 9, 9),
            (3, 2, "normal", 0, 11, 11),
            (4, 2, "normal", 11, 10, 10),
            (5, 2, "normal", 21, 12, 12),
            // Opted out: one unit spanning the whole file, whatever
            // `--split` asked for (D24).
            (6, 3, "normal", 0, 24, 24),
        ]
    );
    assert_eq!(units.preview.totals.units, 7);
    assert_eq!(units.preview.totals.bytes, 25 + 32 + 9 + 11 + 10 + 12 + 24);
    assert_eq!(units.files.len(), 4);
    for row in units.rows() {
        assert!(!row.path.is_empty(), "every row names its file");
    }
}

// ─────────────────────────────────────────────────────────────────────
// Accept row 2: provenance, and graceful degradation
// ─────────────────────────────────────────────────────────────────────

/// Rung 1: with the D43 cache intact every snippet is the **exact sealed
/// bytes**, cut in the unit's committed domain.
#[test]
fn the_cache_rung_yields_sealed_bytes_in_the_committed_domain() {
    let scratch = Scratch::new("cache-rung");
    let vault = IsolatedVault::create("u27-cache");
    let unlocked = vault.unlock();
    seal_fixture(&MockBackend::new(), &unlocked, &scratch);
    let units = show(&unlocked);

    for row in units.rows() {
        let snippet = row
            .snippet
            .as_ref()
            .unwrap_or_else(|| panic!("unit {} has a cached snippet", row.unit_id));
        assert_eq!(snippet.provenance, SnippetProvenance::SealedBytes);
    }

    // The text unit shows the CANONICAL rendition — BOM stripped, CRLF
    // folded, NFD composed — because that is the domain its offsets and its
    // commitment live in.
    assert_eq!(
        units.rows()[0].snippet.as_ref().expect("snippet").window,
        SnippetWindow::Text("café notes\n\nsecond para\n".to_owned())
    );
    // Its mirror shows the RAW bytes as hex: the BOM and the CRLFs are
    // visible rather than invisible (D67 §1 g).
    assert_eq!(
        units.rows()[1].snippet.as_ref().expect("snippet").render(),
        "hex:efbbbf63616665cc81206e6f7465730d…"
    );
    // The binary unit is hex even though its bytes are short.
    assert_eq!(
        units.rows()[2].snippet.as_ref().expect("snippet").render(),
        "hex:000102fffe7f800042"
    );
    // The split file's second unit starts at its own offset.
    assert_eq!(
        units.rows()[4].snippet.as_ref().expect("snippet").window,
        SnippetWindow::Text("beta two\n\n".to_owned())
    );
}

/// Rung 2: with the cache gone and the files still on disk, the snippet is
/// sliced from the **current file** in the unit's commitment domain — a
/// text unit from the re-canonicalized bytes, a mirror from the raw ones —
/// and is labeled as such.
#[test]
fn the_current_file_rung_slices_in_the_commitment_domain_and_says_so() {
    let scratch = Scratch::new("current-rung");
    let vault = IsolatedVault::create("u27-current");
    let unlocked = vault.unlock();
    seal_fixture(&MockBackend::new(), &unlocked, &scratch);
    let sealed = show(&unlocked);
    wipe_unit_cache(&unlocked);
    let current = show(&unlocked);

    for row in current.rows() {
        let snippet = row
            .snippet
            .as_ref()
            .unwrap_or_else(|| panic!("unit {} falls back to the current file", row.unit_id));
        assert_eq!(
            snippet.provenance,
            SnippetProvenance::CurrentFile,
            "unit {}",
            row.unit_id
        );
    }

    // The load-bearing assertion: for an UNMODIFIED file the fallback
    // reproduces the sealed window exactly, which is only true if it
    // re-canonicalized before slicing. A raw-offset slice of `notes.txt`
    // would start at the BOM.
    for (was, now) in sealed.rows().iter().zip(current.rows()) {
        assert_eq!(
            was.snippet.as_ref().map(|s| &s.window),
            now.snippet.as_ref().map(|s| &s.window),
            "unit {}: the current-file window must equal the sealed one",
            was.unit_id
        );
    }
    assert_eq!(
        current.rows()[0].snippet.as_ref().expect("snippet").window,
        SnippetWindow::Text("café notes\n\nsecond para\n".to_owned()),
        "canonical domain, not raw"
    );

    // The rendering carries the warning, on every fallback row.
    let rendered = current.render().join("\n");
    assert!(
        rendered.contains("[current file — may differ if modified since sealing]"),
        "{rendered}"
    );
    assert!(!rendered.contains("[sealed bytes]"), "{rendered}");
}

/// The rungs are per unit, not per work: a cache copy that fails its S4
/// integrity recheck falls through to the current file for **that unit
/// alone**, and every other unit keeps its sealed bytes.
///
/// `show` holds no backend, so where `reveal` would silently refetch (R16)
/// this is the fall-through D43's "cache loss is never an error" allows —
/// the same rule, one rung shorter (D67 §1 j).
#[test]
fn a_corrupt_cache_copy_falls_through_for_that_unit_alone() {
    let scratch = Scratch::new("corrupt");
    let vault = IsolatedVault::create("u27-corrupt");
    let unlocked = vault.unlock();
    seal_fixture(&MockBackend::new(), &unlocked, &scratch);

    // Bit-flip unit 4's cached ciphertext inside an otherwise valid record:
    // the address recompute must reject it.
    {
        let store = WorkStore::new(&unlocked);
        let seal_id = only_work(&store);
        let entry = BlobSlot::Unit { unit_id: 4 }.entry_key().expect("key");
        let record = store
            .get_journal_entry(&seal_id, entry)
            .expect("reads")
            .expect("exists");
        let mut blob = StagedBlob::decode(record.as_bytes()).expect("decodes");
        blob.ciphertext[0] ^= 0x01;
        store
            .put_journal_entry(
                &seal_id,
                entry,
                &blob.encode().expect("encodes"),
                &mut ChaCha20Rng::from_seed([0x29; 32]),
            )
            .expect("writes");
    }

    let units = show(&unlocked);
    for row in units.rows() {
        let snippet = row.snippet.as_ref().expect("every row still has a snippet");
        let want = if row.unit_id == 4 {
            SnippetProvenance::CurrentFile
        } else {
            SnippetProvenance::SealedBytes
        };
        assert_eq!(snippet.provenance, want, "unit {}", row.unit_id);
    }
    // And the fallen-through unit's window is still the right bytes,
    // because the current file is unmodified.
    assert_eq!(
        units.rows()[4].snippet.as_ref().expect("snippet").window,
        SnippetWindow::Text("beta two\n\n".to_owned())
    );
}

/// The warning is not decorative: a file edited since sealing shows its
/// **current** bytes under the current-file label, and the row's sealed
/// size and range are unchanged.
#[test]
fn a_modified_file_shows_its_current_bytes_under_the_warning() {
    let scratch = Scratch::new("modified");
    let vault = IsolatedVault::create("u27-modified");
    let unlocked = vault.unlock();
    seal_fixture(&MockBackend::new(), &unlocked, &scratch);
    wipe_unit_cache(&unlocked);

    // Same canonical length, different content: `alpha` → `ALPHA`.
    std::fs::write(
        scratch.join("split.txt"),
        b"ALPHA one\n\nbeta two\n\ngamma three\n",
    )
    .expect("modify");
    let units = show(&unlocked);

    let row = &units.rows()[3];
    assert_eq!(row.unit_id, 3);
    assert_eq!(row.size, 11, "the row still states the SEALED size");
    assert_eq!(row.range.start(), 0);
    let snippet = row.snippet.as_ref().expect("snippet");
    assert_eq!(
        snippet.window,
        SnippetWindow::Text("ALPHA one\n\n".to_owned()),
        "what is shown is what is on disk now"
    );
    assert_eq!(snippet.provenance, SnippetProvenance::CurrentFile);
}

/// Rung 3: with neither the cache nor the files, every row takes the absent
/// arm — **no error** (D43: cache loss is never one) — and keeps position
/// and size, the pair spec line 121 treats as always present.
#[test]
fn losing_both_local_sources_degrades_to_the_absent_arm_and_never_errors() {
    let scratch = Scratch::new("absent");
    let vault = IsolatedVault::create("u27-absent");
    let unlocked = vault.unlock();
    seal_fixture(&MockBackend::new(), &unlocked, &scratch);
    wipe_unit_cache(&unlocked);
    for name in NAMES {
        std::fs::remove_file(scratch.join(name)).expect("remove the local copy");
    }

    let units = show(&unlocked);
    assert_eq!(units.rows().len(), 7, "every row still renders");
    for row in units.rows() {
        assert!(row.snippet.is_none(), "unit {}", row.unit_id);
        assert!(row.size > 0 || row.range.length() == 0);
    }
    let rendered = units.render().join("\n");
    assert_eq!(
        rendered.matches(SNIPPET_UNAVAILABLE).count(),
        7,
        "{rendered}"
    );
    // Position and size survive the loss.
    assert!(
        rendered.contains("unit 4   normal   10 byte(s) at offset 11 of 33"),
        "{rendered}"
    );
}

/// A sealed path that is no longer a regular file is a fall-through, not a
/// read: `show` must not block on a fifo or try to read a directory.
#[test]
fn a_sealed_path_that_is_no_longer_a_regular_file_degrades() {
    let scratch = Scratch::new("not-a-file");
    let vault = IsolatedVault::create("u27-notfile");
    let unlocked = vault.unlock();
    seal_fixture(&MockBackend::new(), &unlocked, &scratch);
    wipe_unit_cache(&unlocked);

    std::fs::remove_file(scratch.join("plain.md")).expect("remove");
    std::fs::create_dir(scratch.join("plain.md")).expect("a directory where the file was");

    let units = show(&unlocked);
    assert!(
        units.rows()[6].snippet.is_none(),
        "the opted-out file's unit degrades"
    );
    assert!(
        units.rows()[0].snippet.is_some(),
        "the other files are unaffected"
    );
}

// ─────────────────────────────────────────────────────────────────────
// Accept row 1's other half: the raw-mirror mark
// ─────────────────────────────────────────────────────────────────────

/// The mirror's mark in `show` is **the sentence `reveal` will print** if
/// the id is typed — asserted by producing that refusal from R16 and
/// comparing the two strings, not by re-reading the constant.
#[test]
fn the_mirror_mark_is_the_refusal_reveal_actually_gives() {
    let scratch = Scratch::new("mirror-mark");
    let vault = IsolatedVault::create("u27-mirror");
    let unlocked = vault.unlock();
    seal_fixture(&MockBackend::new(), &unlocked, &scratch);
    let units = show(&unlocked);

    let mirror = units
        .rows()
        .iter()
        .find(|r| r.kind == UnitKind::RawMirror)
        .expect("the fixture carries a mirror");
    assert_eq!(mirror.unit_id, 1);

    // What `reveal --units 1` is told, from R16 itself.
    let store = WorkStore::new(&unlocked);
    let seal_id = only_work(&store);
    let mock = MockBackend::new();
    let engine = RevealEngine::new(&mock, &store);
    let refusal = block_on(engine.prepare(
        &seal_id,
        &RevealRequest {
            selection: UnitSelection::Ids(vec![mirror.unit_id]),
            include_receipt: false,
        },
    ))
    .expect_err("a bare mirror id is refused");
    assert!(
        matches!(refusal, RevealError::RawMirrorNotUnitSelectable { unit_id } if unit_id == 1),
        "{refusal:?}"
    );

    // `show`'s marking is that refusal, verbatim.
    let rendered = units.render().join("\n");
    assert!(
        rendered.contains(&refusal.to_string()),
        "the mark and the refusal must be the same sentence\n--- show ---\n{rendered}\n--- \
         reveal ---\n{refusal}"
    );

    // And the machine form of the same fact.
    let doc = units.json();
    let rows = doc["units"].as_array().expect("units array");
    for row in rows {
        let selectable = row["selectable"].as_bool().expect("bool");
        assert_eq!(
            selectable,
            row["kind"] != serde_json::json!("raw-mirror"),
            "{row}"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────
// Accept row 3: the `--json` fixture
// ─────────────────────────────────────────────────────────────────────

/// The registered `--json` shape, with the **per-document key assertion**
/// D65 §8.2 owes for every command (the `list_command.rs` /
/// `restore_output.rs` pattern): silent on additions, red on a removal or a
/// rename.
#[test]
fn the_json_document_carries_the_full_unit_table() {
    let scratch = Scratch::new("json");
    let vault = IsolatedVault::create("u27-json");
    let unlocked = vault.unlock();
    let work_id = seal_fixture(&MockBackend::new(), &unlocked, &scratch);
    let doc = show(&unlocked).json();

    for key in [
        "work_id",
        "seal_id",
        "title",
        "network",
        "state",
        "manifest_source",
        "counts",
        "files",
        "units",
    ] {
        assert!(doc.get(key).is_some(), "document is missing {key}: {doc}");
    }
    assert_eq!(doc["work_id"], serde_json::json!(work_id));
    assert_eq!(doc["state"], serde_json::json!("complete"));
    assert_eq!(doc["network"], serde_json::json!("devnet"));
    assert_eq!(doc["title"], serde_json::json!("u27 fixture"));
    // Never `network`: `show` holds no backend (D67 §1 j).
    assert_eq!(doc["manifest_source"], serde_json::json!("vault-copy"));

    for key in ["units", "files", "bytes"] {
        assert!(
            doc["counts"].get(key).is_some(),
            "counts is missing {key}: {doc}"
        );
    }
    assert_eq!(doc["counts"]["units"], serde_json::json!(7));
    assert_eq!(doc["counts"]["files"], serde_json::json!(4));
    assert_eq!(
        doc["counts"]["bytes"],
        serde_json::json!("123"),
        "a u128 sum of sealer-authored lengths rides as a decimal string (D65 §7)"
    );

    let files = doc["files"].as_array().expect("files array");
    assert_eq!(files.len(), 4);
    for row in files {
        for key in [
            "file_id",
            "path",
            "kind",
            "offset_domain",
            "fine_tree",
            "whole_file_reveal_only",
            "size",
            "unicode_version",
            "raw_mirror_unit_id",
        ] {
            assert!(row.get(key).is_some(), "file row missing {key}: {row}");
        }
    }
    // D65 §7's null rule, on the two nullable file keys: present, and
    // `null` rather than absent.
    assert!(
        files[1]["unicode_version"].is_null(),
        "binary: {}",
        files[1]
    );
    assert!(files[1]["raw_mirror_unit_id"].is_null());
    assert_eq!(files[0]["raw_mirror_unit_id"], serde_json::json!(1));
    assert_eq!(files[3]["whole_file_reveal_only"], serde_json::json!(true));
    assert_eq!(files[0]["whole_file_reveal_only"], serde_json::json!(false));

    let rows = doc["units"].as_array().expect("units array");
    assert_eq!(rows.len(), 7);
    for row in rows {
        for key in [
            "unit_id",
            "file_id",
            "path",
            "kind",
            "selectable",
            "offset_domain",
            "byte_range",
            "size",
            "snippet",
        ] {
            assert!(row.get(key).is_some(), "unit row missing {key}: {row}");
        }
        for key in ["start", "length"] {
            assert!(
                row["byte_range"].get(key).is_some(),
                "byte_range missing {key}: {row}"
            );
        }
        for key in ["form", "value", "truncated", "provenance"] {
            assert!(
                row["snippet"].get(key).is_some(),
                "snippet missing {key}: {row}"
            );
        }
    }

    // D67 §3 R6: machine values are the raw window — no quotes, no `hex:`,
    // no `…` marker anywhere in the document.
    assert_eq!(
        rows[0]["snippet"],
        serde_json::json!({
            "form": "text",
            "value": "café notes\n\nsecond para\n",
            "truncated": false,
            "provenance": "sealed-bytes",
        })
    );
    assert_eq!(
        rows[1]["snippet"]["value"],
        serde_json::json!("efbbbf63616665cc81206e6f7465730d"),
        "bare pairs, no label"
    );
    assert_eq!(rows[1]["snippet"]["truncated"], serde_json::json!(true));
    let text = serde_json::to_string(&doc).expect("serializes");
    assert!(
        !text.contains("hex:"),
        "no rendering leaked into the values"
    );
    assert!(!text.contains('…'), "no marker leaked into the values");
}

/// The absent arm's machine form: `snippet` is **present and `null`**, never
/// a missing key (D65 §6 rider 1 / §7).
#[test]
fn an_absent_snippet_is_present_and_null() {
    let scratch = Scratch::new("json-null");
    let vault = IsolatedVault::create("u27-jsonnull");
    let unlocked = vault.unlock();
    seal_fixture(&MockBackend::new(), &unlocked, &scratch);
    wipe_unit_cache(&unlocked);
    for name in NAMES {
        std::fs::remove_file(scratch.join(name)).expect("remove");
    }

    let doc = show(&unlocked).json();
    for row in doc["units"].as_array().expect("units array") {
        assert!(row.get("snippet").is_some(), "the key is there: {row}");
        assert!(row["snippet"].is_null(), "and it is null: {row}");
    }
}

// ─────────────────────────────────────────────────────────────────────
// The rendering, frozen
// ─────────────────────────────────────────────────────────────────────

/// The committed snapshot of the three ladder states over one work.
///
/// Deterministic because the fixture seals under seeded RNGs, at a literal
/// claimed time, with literal content — so the work id, the seal id and
/// every offset are functions of this file alone.
#[test]
fn the_rendering_matches_the_committed_snapshot() {
    let scratch = Scratch::new("snapshot");
    let vault = IsolatedVault::create("u27-snapshot");
    let unlocked = vault.unlock();
    seal_fixture(&MockBackend::new(), &unlocked, &scratch);

    let mut rendered = String::from(
        "antseal — `show <work-id>` (U27), the unit table `reveal --units` is chosen from\n\n",
    );
    rendered.push_str("════ the D43 cache intact — exact sealed bytes ════\n");
    rendered.push_str(&show(&unlocked).render().join("\n"));

    wipe_unit_cache(&unlocked);
    rendered
        .push_str("\n\n════ cache gone, the files still on disk — current-file fallback ════\n");
    rendered.push_str(&show(&unlocked).render().join("\n"));

    for name in NAMES {
        std::fs::remove_file(scratch.join(name)).expect("remove");
    }
    rendered.push_str("\n\n════ neither — the absent arm, and never an error ════\n");
    rendered.push_str(&show(&unlocked).render().join("\n"));
    rendered.push('\n');

    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/snapshots/show-units.txt");
    if std::env::var_os("ANTSEAL_BLESS").is_some() {
        std::fs::write(&path, &rendered).expect("bless");
        return;
    }
    let committed = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "missing committed show snapshot at {}: {e} (generate with ANTSEAL_BLESS=1)",
            path.display()
        )
    });
    assert!(
        committed == rendered,
        "the `show` rendering drifted from {} — regenerate with ANTSEAL_BLESS=1 and justify \
         the diff\n--- rendered ---\n{rendered}",
        path.display()
    );
}

/// U31's positioning discipline, on this command's copy: possession
/// language, never "notary", never unqualified "priority".
#[test]
fn the_copy_makes_no_notary_or_priority_claim() {
    let scratch = Scratch::new("copy");
    let vault = IsolatedVault::create("u27-copy");
    let unlocked = vault.unlock();
    seal_fixture(&MockBackend::new(), &unlocked, &scratch);
    let rendered = show(&unlocked).render().join("\n").to_lowercase();
    assert!(!rendered.contains("notar"), "{rendered}");
    assert!(!rendered.contains("priority"), "{rendered}");
    // Nor a verdict-shaped sentence: `show` states contents, not proof.
    assert!(!rendered.contains("existed no later than"), "{rendered}");
}
