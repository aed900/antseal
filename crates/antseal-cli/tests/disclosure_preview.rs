//! R15 acceptance over a **real sealed work**: the disclosure preview
//! sourced from the D43 journal→cache through [`VaultSnippetSource`].
//!
//! The in-module suite (`src/preview.rs`) pins every D67 window/escape/
//! rendering rule over synthetic bodies; this file proves the other half
//! of R15's Accept — that the computation composes with the vault the S12
//! pipeline actually writes: paths come from the work record, ciphertexts
//! decrypt from the cache under the recorded `W`, cache loss or corruption
//! degrades to the absent arm (never an error, D43), and no vault secret
//! reaches the preview output.
//!
//! **No network is reachable from the preview by construction**: sealing
//! uses `MockBackend`, but [`VaultSnippetSource`] takes no backend at all
//! — `show`'s sourcing cannot fetch (D67 §1 j), type-level.
//!
//! NON-SECRET: every fixture byte string is documented; `W` is read back
//! through the public store API only to prove it does NOT appear in
//! output.
//!
//! [`VaultSnippetSource`]: antseal_cli::preview::VaultSnippetSource

mod common;

use std::collections::BTreeSet;

use antseal_cli::pipeline::journal::{BlobSlot, StagedBlob, recorded_plan};
use antseal_cli::pipeline::{NoBarriers, Pipeline, SealFile, SealRequest, SealResult};
use antseal_cli::preview::{
    DisclosurePreview, SNIPPET_UNAVAILABLE, SnippetProvenance, SnippetWindow, VaultSnippetSource,
    all_normal_units, disclosure_preview, render_snippet,
};
use antseal_cli::vault::session::UnlockedVault;
use antseal_cli::vault::store::{SealShapingFlags, WorkStore};
use antseal_core::content::{FileFlags, SplitMode};
use antseal_core::crypto::hkdf::{FileId, UnitId, derive_file_salt, derive_unit_key};
use antseal_core::crypto::secrets::SealId;
use antseal_core::crypto::sig_policy::SigPolicy;
use antseal_core::manifest::{Manifest, ManifestBodyV1, UnitKind};
use antseal_net::NetworkId;
use antseal_net::test_util::{MockBackend, block_on};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

use common::{RecordingGate, ScriptedConsent, shared_vault};

// ─────────────────────────────────────────────────────────────────────
// Fixture content (the restore-engine fixture shapes: every unit-shape
// class the preview must handle in one work)
// ─────────────────────────────────────────────────────────────────────

/// Text whose raw bytes differ from canonical three ways at once (BOM,
/// CRLF, NFD `e`+U+0301) — so it carries a raw mirror. Canonical:
/// `"café notes\n\nsecond para\n"` (25 bytes); raw: 32 bytes.
const CRLF_BOM_NFD: &[u8] = "\u{FEFF}caf\u{65}\u{301} notes\r\n\r\nsecond para\r\n".as_bytes();

/// Binary: raw-domain offsets, hex snippet arm.
const BINARY: &[u8] = &[0x00, 0x01, 0x02, 0xFF, 0xFE, 0x7F, 0x80, 0x00, 0x42];

/// Canonical-already text tiled into three units by `--split
/// blank-lines`; canonical bytes == raw bytes, so unit windows can be
/// asserted against slices of this constant.
const SPLIT_TEXT: &[u8] = b"alpha one\n\nbeta two\n\ngamma three\n";

fn files() -> Vec<SealFile<'static>> {
    vec![
        SealFile {
            path_as_given: "notes.txt",
            path_absolute: "/w/notes.txt",
            bytes: CRLF_BOM_NFD,
            flags: FileFlags::new(),
        },
        SealFile {
            path_as_given: "data/blob.bin",
            path_absolute: "/w/data/blob.bin",
            bytes: BINARY,
            flags: FileFlags::new(),
        },
        SealFile {
            path_as_given: "split.txt",
            path_absolute: "/w/split.txt",
            bytes: SPLIT_TEXT,
            flags: FileFlags::new().with_split(SplitMode::BlankLines),
        },
    ]
}

fn seal_fixture(mock: &MockBackend, vault: &UnlockedVault, seed: u8) -> SealId {
    let files = files();
    let request = SealRequest {
        files: &files,
        title: "preview fixture".to_owned(),
        claimed_time_unix_secs: 1_800_000_000,
        app_version: "antseal-test/1".to_owned(),
        network: NetworkId::Devnet,
        no_anchor: false,
        degraded: false,
        dry_run: false,
        sig_policy: SigPolicy::hybrid(),
        shaping: SealShapingFlags::default(),
    };
    let mut journal_rng = ChaCha20Rng::from_seed([seed ^ 0xA5; 32]);
    let journal = antseal_cli::pipeline::VaultJournal::new(WorkStore::new(vault), &mut journal_rng);
    let gate = RecordingGate::new();
    let consent = ScriptedConsent::always_yes();
    let pipeline = Pipeline::new(mock, &gate, &journal, &consent, &NoBarriers);
    let result = block_on(pipeline.seal(&request, &mut ChaCha20Rng::from_seed([seed; 32])))
        .expect("the fixture seals");
    match result {
        SealResult::Sealed(outcome) => outcome.seal_id,
        SealResult::DryRun(_) => unreachable!("not a dry run"),
    }
}

/// Decode the sealed work's manifest body from the journaled plan (the
/// vault copy — the same source `restore` prefers).
fn manifest_body(store: &WorkStore<'_>, seal_id: &SealId) -> ManifestBodyV1 {
    let plan = recorded_plan(store, seal_id)
        .expect("plan reads")
        .expect("plan exists");
    let bytes = plan.manifest_bytes.expect("manifest journaled");
    Manifest::decode(&bytes)
        .expect("manifest decodes")
        .body()
        .clone()
}

/// The full-work preview (`--all` / `show` shape) over the vault cache.
fn preview_all(vault: &UnlockedVault, seal_id: &SealId) -> DisclosurePreview {
    let store = WorkStore::new(vault);
    let record = store.load_meta(seal_id).expect("meta loads");
    let body = manifest_body(&store, seal_id);
    let selection = all_normal_units(&body);
    let mut source = VaultSnippetSource::new(&store, *seal_id, record.w.secret_ref());
    disclosure_preview(&body, &record.input_paths_as_given, &selection, &mut source)
        .expect("preview computes")
}

// ─────────────────────────────────────────────────────────────────────
// R15 Accept: snippets from decrypted cache bytes, totals, annotations
// ─────────────────────────────────────────────────────────────────────

/// **R15 accept**: for a sealed work, every disclosed unit row carries
/// the vault path, the committed byte-range, the size, and a snippet
/// decrypted from the D43 cache — text quoted-and-escaped, binary and
/// the raw mirror as `hex:`, exactly per D67 — and the totals agree with
/// the manifest the seal wrote.
#[test]
fn a_sealed_works_preview_decrypts_its_own_bytes_from_the_cache() {
    let mock = MockBackend::new();
    let vault = shared_vault().unlock();
    let seal_id = seal_fixture(&mock, &vault, 0x51);

    let preview = preview_all(&vault, &seal_id);

    // Manifest order: notes.txt {0 normal, 1 mirror-last (D23)},
    // blob.bin {2}, split.txt {3, 4, 5}.
    assert_eq!(
        preview.rows.iter().map(|r| r.unit_id).collect::<Vec<_>>(),
        vec![0, 1, 2, 3, 4, 5]
    );
    assert!(
        preview.rows.iter().all(|row| row
            .snippet
            .as_ref()
            .is_some_and(|snippet| snippet.provenance == SnippetProvenance::SealedBytes)),
        "every snippet decrypted from the cache, provenance carried"
    );

    // Paths are the vault-recorded spellings, per file.
    let paths: Vec<&str> = preview.rows.iter().map(|r| r.path.as_str()).collect();
    assert_eq!(
        paths,
        vec![
            "notes.txt",
            "notes.txt",
            "data/blob.bin",
            "split.txt",
            "split.txt",
            "split.txt"
        ]
    );

    // notes.txt normal unit: canonical text, LF escaped to one line.
    let notes = &preview.rows[0];
    assert_eq!(notes.size, 25);
    assert_eq!(
        render_snippet(notes.snippet.as_ref()),
        "\"café notes\\n\\nsecond para\\n\""
    );

    // notes.txt raw mirror: ALWAYS hex (D67 §1 g) — the BOM, the NFD
    // sequence and the CR are visible as bytes; range is raw-domain
    // [0, 32).
    let mirror = &preview.rows[1];
    assert_eq!(mirror.kind, UnitKind::RawMirror);
    assert_eq!((mirror.range.start(), mirror.range.length()), (0, 32));
    assert_eq!(mirror.size, 32);
    assert_eq!(
        render_snippet(mirror.snippet.as_ref()),
        "hex:efbbbf63616665cc81206e6f7465730d…"
    );

    // Binary: hex, 9 bytes ≤ the 16-byte cap, no marker.
    let blob = &preview.rows[2];
    assert_eq!(
        render_snippet(blob.snippet.as_ref()),
        "hex:000102fffe7f800042"
    );

    // Split units: each window is exactly the canonical slice its
    // committed byte-range names (canonical == raw for this fixture).
    for row in &preview.rows[3..] {
        let start = usize::try_from(row.range.start()).expect("fits");
        let len = usize::try_from(row.range.length()).expect("fits");
        let expected = core::str::from_utf8(&SPLIT_TEXT[start..start + len]).expect("utf8");
        let snippet = row.snippet.as_ref().expect("snippet present");
        assert_eq!(snippet.window, SnippetWindow::Text(expected.to_owned()));
        assert!(!snippet.truncated, "every split unit is under the cap");
    }

    // Totals agree with the sealed manifest: 6 units, all three files
    // fully revealed, the mirror riding, 25+32+9+33 bytes.
    assert_eq!(preview.totals.units, 6);
    assert_eq!(preview.totals.bytes, 25 + 32 + 9 + 33);
    assert_eq!(preview.totals.files_touched, 3);
    assert_eq!(preview.totals.files_fully_revealed, 3);
    assert!(preview.totals.mirror_rides_along);
    assert!(preview.rows.iter().all(|r| r.file_fully_revealed));
    assert_eq!(preview.files.len(), 3);
    assert!(preview.files[0].mirror_rides_along);
    assert!(!preview.files[1].mirror_rides_along, "binary has no mirror");
}

/// D28/D70 over real data, both arms. A strict `--units` subset of
/// split.txt neither promotes nor ships anything extra; selecting
/// notes.txt's **only** normal unit IS the promotion — the file becomes
/// fully revealed and its raw mirror rides along, and the preview must
/// say so before it is irreversible.
#[test]
fn partial_stays_partial_and_a_files_last_unit_promotes_with_its_mirror() {
    let mock = MockBackend::new();
    let vault = shared_vault().unlock();
    let seal_id = seal_fixture(&mock, &vault, 0x52);

    let store = WorkStore::new(&vault);
    let record = store.load_meta(&seal_id).expect("meta loads");
    let body = manifest_body(&store, &seal_id);
    let mut source = VaultSnippetSource::new(&store, seal_id, record.w.secret_ref());

    // One of split.txt's three units: genuinely partial.
    let partial: BTreeSet<u64> = [3u64].into_iter().collect();
    let preview = disclosure_preview(&body, &record.input_paths_as_given, &partial, &mut source)
        .expect("preview computes");
    assert_eq!(preview.rows.len(), 1);
    assert_eq!(preview.rows[0].unit_id, 3);
    assert!(!preview.rows[0].file_fully_revealed);
    assert!(!preview.totals.mirror_rides_along);
    assert_eq!(preview.totals.files_touched, 1);
    assert_eq!(preview.totals.files_fully_revealed, 0);

    // notes.txt's single normal unit: R(F) = N(F), so this "one unit"
    // selection is a full reveal and the mirror rides (D28 promotion).
    let promoting: BTreeSet<u64> = [0u64].into_iter().collect();
    let preview = disclosure_preview(&body, &record.input_paths_as_given, &promoting, &mut source)
        .expect("preview computes");
    assert_eq!(
        preview.rows.iter().map(|r| r.unit_id).collect::<Vec<_>>(),
        vec![0, 1],
        "the mirror row rides along without being selected"
    );
    assert_eq!(preview.rows[1].kind, UnitKind::RawMirror);
    assert!(preview.rows.iter().all(|r| r.file_fully_revealed));
    assert!(preview.totals.mirror_rides_along);
    assert_eq!(preview.totals.files_fully_revealed, 1);
    assert_eq!(preview.totals.bytes, 25 + 32);
}

// ─────────────────────────────────────────────────────────────────────
// D43: cache loss/corruption degrades the snippet, never the row
// ─────────────────────────────────────────────────────────────────────

/// **R15 accept (snippet-unavailable case)**: a deleted cache entry, an
/// unreadable cache record, and a cache copy failing its S4 integrity
/// recheck all yield `(snippet unavailable)` rows with file/range/size
/// intact — and every other row still gets its snippet.
#[test]
fn cache_loss_and_corruption_degrade_the_snippet_never_the_row() {
    let mock = MockBackend::new();
    let vault = shared_vault().unlock();
    let seal_id = seal_fixture(&mock, &vault, 0x53);
    let store = WorkStore::new(&vault);
    let mut rng = ChaCha20Rng::from_seed([0x53; 32]);

    // Unit 0: bit-flip the cached ciphertext inside an otherwise valid
    // record — the S4 address recompute must reject it.
    let entry0 = BlobSlot::Unit { unit_id: 0 }.entry_key().expect("key");
    let record0 = store
        .get_journal_entry(&seal_id, entry0)
        .expect("reads")
        .expect("exists");
    let mut blob = StagedBlob::decode(record0.as_bytes()).expect("decodes");
    blob.ciphertext[0] ^= 0x01;
    store
        .put_journal_entry(&seal_id, entry0, &blob.encode().expect("encodes"), &mut rng)
        .expect("writes");

    // Unit 2: replace the record with bytes that are not a staged
    // record at all.
    let entry2 = BlobSlot::Unit { unit_id: 2 }.entry_key().expect("key");
    store
        .put_journal_entry(&seal_id, entry2, b"not a staged record", &mut rng)
        .expect("writes");

    // Unit 3: the cache copy is gone entirely.
    let entry3 = BlobSlot::Unit { unit_id: 3 }.entry_key().expect("key");
    assert!(
        store
            .delete_journal_entry(&seal_id, entry3)
            .expect("deletes")
    );

    let preview = preview_all(&vault, &seal_id);

    // Every row is still present with its coordinates.
    assert_eq!(preview.rows.len(), 6);
    for (unit_id, absent) in [(0, true), (1, false), (2, true), (3, true), (4, false)] {
        let row = preview
            .rows
            .iter()
            .find(|r| r.unit_id == unit_id)
            .expect("row exists");
        assert_eq!(
            row.snippet.is_none(),
            absent,
            "unit {unit_id}: absent = {absent}"
        );
        assert!(row.range.length() > 0 && row.size > 0);
        if absent {
            assert_eq!(render_snippet(row.snippet.as_ref()), SNIPPET_UNAVAILABLE);
        }
    }
    // The totals never depended on snippet availability.
    assert_eq!(preview.totals.units, 6);
    assert_eq!(preview.totals.bytes, 25 + 32 + 9 + 33);
}

// ─────────────────────────────────────────────────────────────────────
// Project rule 6: no vault secret in preview output or Debug
// ─────────────────────────────────────────────────────────────────────

/// The preview's entire output — `Debug` of the full structure plus every
/// terminal rendering — contains no spelling of `W`, of any unit key, or
/// of any file salt (the secrets the sourcing path touches or could
/// touch). The disclosed plaintext itself is present, which is the
/// positive control: the sweep is looking at real content, and the
/// carve-out ("the plaintext being deliberately disclosed") is exactly
/// what remains.
#[test]
fn no_vault_secret_reaches_preview_output_or_debug() {
    let mock = MockBackend::new();
    let vault = shared_vault().unlock();
    let seal_id = seal_fixture(&mock, &vault, 0x54);

    let preview = preview_all(&vault, &seal_id);
    let mut haystack = format!("{preview:?}");
    for row in &preview.rows {
        haystack.push_str(&render_snippet(row.snippet.as_ref()));
    }

    // Positive control: the deliberately-disclosed windows are in there.
    assert!(haystack.contains("café notes"));
    assert!(haystack.contains("efbbbf"));

    let store = WorkStore::new(&vault);
    let record = store.load_meta(&seal_id).expect("meta loads");
    let w = record.w.secret_ref();
    let mut secrets: Vec<(String, Vec<u8>)> = vec![("W".to_owned(), w.as_bytes().to_vec())];
    for unit_id in 0..6u64 {
        secrets.push((
            format!("unit key {unit_id}"),
            derive_unit_key(w, UnitId(unit_id)).into_bytes().to_vec(),
        ));
    }
    for file_id in 0..3u64 {
        secrets.push((
            format!("file salt {file_id}"),
            derive_file_salt(w, FileId(file_id))
                .expose_bytes_for_test_vectors()
                .to_vec(),
        ));
    }

    for (what, bytes) in &secrets {
        for spelling in spellings(bytes) {
            assert!(
                !haystack.contains(&spelling),
                "{what} leaked into preview output as {spelling}"
            );
        }
    }
}

/// Lowercase hex, uppercase hex, and the decimal byte-array form derived
/// `Debug` impls print — the spellings a secret realistically escapes
/// into text as (the U21 sweep, plus the Debug-array form).
fn spellings(bytes: &[u8]) -> Vec<String> {
    let lower: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    let upper = lower.to_uppercase();
    let array = format!("{bytes:?}");
    vec![lower, upper, array]
}
