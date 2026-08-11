//! R16 acceptance suite: the reveal engine over `MockBackend`.
//!
//! Every row seals a real work through the S12 pipeline and reveals it
//! through the R16 engine, so what is asserted is the genuine flow —
//! selection resolution, D43 cache-first gathering with the S4 integrity
//! recheck, unit decryption, the R15 preview, and R13's builder with its
//! mandatory self-check — with **no CLI involvement** (R16 Accept): no
//! prompt, no print, no file write happens anywhere below.
//!
//! Two invariants are asserted on every built bundle:
//!
//! - it passes `antseal_core::verify_bundle` (the offline recipient's
//!   check, run here again *outside* the builder — proving the returned
//!   bytes, not trusting the self-check's word);
//! - its decoded content set equals the preview's annotation set
//!   ([`assert_preview_matches_bundle`]) — units, full-reveal files,
//!   mirror and receipt annotations (R16 Accept; D70 §7.6's
//!   preview-parity-by-construction, observed rather than assumed).
//!
//! NON-SECRET: every fixture byte string is documented; `W` is read back
//! through the public store API only to prove it does NOT appear in
//! errors or summaries.

mod common;

use std::collections::BTreeSet;

use antseal_cli::pipeline::journal::{
    BlobSlot, MANIFEST_BLOB_ENTRY, PLAN_ENTRY, StagedBlob, UNIT_ENTRY_BASE,
};
use antseal_cli::pipeline::receipt_sink::recorded_receipt;
use antseal_cli::pipeline::{
    AnchorArtifact, ArtifactKind, NoBarriers, OTS_SLOT, Pipeline, PreparedReveal, RevealEngine,
    RevealError, RevealRequest, SealFile, SealRequest, SealResult, UnitSelection, tsa_slot,
};
use antseal_cli::preview::DisclosurePreview;
use antseal_cli::vault::session::UnlockedVault;
use antseal_cli::vault::store::{SealShapingFlags, WorkState, WorkStore};
use antseal_core::bundle::schema::OtsUpgrade;
use antseal_core::bundle::{AnchorStatus, BundleV1};
use antseal_core::content::{FileFlags, SplitMode};
use antseal_core::crypto::secrets::SealId;
use antseal_core::crypto::sig_policy::SigPolicy;
use antseal_core::crypto::unit_aead::Nonce24 as AeadNonce;
use antseal_core::manifest::{
    ContentAddress, FileEntry, Manifest, ManifestBodyV1, Nonce24, UnitEntry, UnitKind, encode_body,
    encode_envelope, work_id as manifest_work_id,
};
use antseal_core::verify::{VerifyOptions, verify_bundle};
use antseal_net::test_util::{Method, MockBackend, block_on};
use antseal_net::{
    Address, JournalReceipt, NetworkId, PaymentReceipt, StorageBackend, StorageError,
};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

use common::{RecordingGate, ScriptedConsent, shared_vault};

// ─────────────────────────────────────────────────────────────────────
// Fixture content (the restore-engine shapes: every unit-shape class in
// one work — unit ids 0 = notes normal, 1 = notes raw mirror, 2 = binary,
// 3..=5 = the split text file)
// ─────────────────────────────────────────────────────────────────────

/// Text whose raw bytes differ from canonical three ways at once (BOM,
/// CRLF, NFD `e`+U+0301) — so it carries a raw mirror. Canonical:
/// `"café notes\n\nsecond para\n"` (25 bytes); raw: 32 bytes.
const CRLF_BOM_NFD: &[u8] = "\u{FEFF}caf\u{65}\u{301} notes\r\n\r\nsecond para\r\n".as_bytes();

/// Binary: no canonical rendition, raw-domain offsets, no mirror.
const BINARY: &[u8] = &[0x00, 0x01, 0x02, 0xFF, 0xFE, 0x7F, 0x80, 0x00, 0x42];

/// Canonical-already text tiled into three units by `--split blank-lines`
/// — the multi-unit file whose partial reveals need boundary Merkle paths.
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

/// Seal the three-file fixture into `mock` and return the work's seal id.
/// `seed` keeps each test's `seal_id`, `W` and nonces its own.
fn seal_fixture(mock: &MockBackend, vault: &UnlockedVault, seed: u8) -> SealId {
    let files = files();
    let request = SealRequest {
        files: &files,
        title: "reveal fixture".to_owned(),
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

fn all() -> RevealRequest {
    RevealRequest {
        selection: UnitSelection::All,
        include_receipt: false,
    }
}

fn units(ids: &[u64]) -> RevealRequest {
    RevealRequest {
        selection: UnitSelection::Ids(ids.to_vec()),
        include_receipt: false,
    }
}

/// Prepare one reveal over a freshly-borrowed store.
fn prepare<B: StorageBackend>(
    backend: &B,
    vault: &UnlockedVault,
    seal_id: &SealId,
    request: &RevealRequest,
) -> Result<PreparedReveal, RevealError> {
    let store = WorkStore::new(vault);
    let engine = RevealEngine::new(backend, &store);
    block_on(engine.prepare(seal_id, request))
}

/// Prepare + build, asserting the returned bundle passes the recipient's
/// own `verify_bundle` and that the preview annotations equal the decoded
/// bundle's content set. Returns (bundle bytes, preview, summary).
fn reveal_verified<B: StorageBackend>(
    backend: &B,
    vault: &UnlockedVault,
    seal_id: &SealId,
    request: &RevealRequest,
) -> (
    Vec<u8>,
    DisclosurePreview,
    antseal_cli::pipeline::RevealSummary,
) {
    let prepared = prepare(backend, vault, seal_id, request).expect("prepare succeeds");
    let preview = prepared.preview().clone();
    let output = prepared.build().expect("build succeeds");
    verify_bundle(&output.sealproof, &VerifyOptions::new())
        .expect("the returned bundle verifies offline");
    assert_preview_matches_bundle(&preview, &output.summary, &output.sealproof);
    (output.sealproof, preview, output.summary)
}

/// R16 Accept: the preview's annotation set equals the built bundle's
/// actual content set — revealed unit ids, fully-revealed file ids, the
/// mirror-rides-along annotation, and the receipt flag.
fn assert_preview_matches_bundle(
    preview: &DisclosurePreview,
    summary: &antseal_cli::pipeline::RevealSummary,
    sealproof: &[u8],
) {
    let bundle = BundleV1::decode(sealproof).expect("the bundle decodes");

    // Units: preview rows == bundle reveal entries == summary, id for id.
    // The bundle lists its covered section before its non-covered one
    // (each strictly ascending — F9), so the comparison is over the
    // content SET; the preview and summary are in manifest order.
    let preview_ids: Vec<u64> = preview.rows.iter().map(|row| row.unit_id).collect();
    let mut bundle_ids = bundle.revealed_unit_ids();
    bundle_ids.sort_unstable();
    assert_eq!(
        bundle_ids, preview_ids,
        "the bundle reveals exactly the units the preview showed"
    );
    assert_eq!(summary.revealed_unit_ids, preview_ids);
    assert_eq!(preview.totals.units, preview_ids.len() as u64);

    // Fully-revealed files: preview annotations == §7.14 entries.
    let preview_full: Vec<u64> = preview
        .files
        .iter()
        .filter(|file| file.fully_revealed)
        .map(|file| file.file_id)
        .collect();
    let bundle_full: Vec<u64> = bundle
        .full_reveals()
        .iter()
        .map(|entry| entry.file_id())
        .collect();
    assert_eq!(
        bundle_full, preview_full,
        "whole-file commitments open exactly where the preview said they would"
    );
    assert_eq!(summary.files_fully_revealed, preview_full);

    // Touched files: preview file entries == §7.13 entries, path for path.
    let preview_touched: Vec<(u64, &str)> = preview
        .files
        .iter()
        .map(|file| (file.file_id, file.path.as_str()))
        .collect();
    let bundle_touched: Vec<(u64, &str)> = bundle
        .touched_files()
        .iter()
        .map(|entry| (entry.file_id(), entry.path()))
        .collect();
    assert_eq!(bundle_touched, preview_touched);

    // The mirror annotation: a mirror rides iff its row is in the preview
    // iff its §7.12 entry is in the bundle (mirror rows are the preview's
    // RawMirror-kind rows; mirrors are always non-covered, D23/G7).
    let preview_mirrors: BTreeSet<u64> = preview
        .rows
        .iter()
        .filter(|row| row.kind == UnitKind::RawMirror)
        .map(|row| row.unit_id)
        .collect();
    let manifest = Manifest::decode(bundle.manifest_bytes()).expect("embedded manifest decodes");
    let mirror_ids: BTreeSet<u64> = manifest
        .body()
        .files()
        .iter()
        .filter_map(|file| file.raw_mirror().map(UnitEntry::unit_id))
        .collect();
    let bundle_mirrors: BTreeSet<u64> = bundle
        .noncovered_reveals()
        .iter()
        .map(|entry| entry.unit_id())
        .filter(|id| mirror_ids.contains(id))
        .collect();
    assert_eq!(
        bundle_mirrors, preview_mirrors,
        "raw mirrors ride exactly where the preview annotated them"
    );
    assert_eq!(
        preview.totals.mirror_rides_along,
        !preview_mirrors.is_empty()
    );

    // The receipt annotation.
    assert_eq!(
        bundle.receipt().is_some(),
        summary.receipt_included,
        "receipt presence is exactly the summary's flag"
    );
}

/// The staged (D43 cache) record at one journal entry key.
fn staged_blob(store: &WorkStore<'_>, seal_id: &SealId, entry: u64) -> Option<StagedBlob> {
    let bytes = store.get_journal_entry(seal_id, entry).expect("read")?;
    Some(StagedBlob::decode(bytes.as_bytes()).expect("decode"))
}

// ─────────────────────────────────────────────────────────────────────
// R16 Accept: --all
// ─────────────────────────────────────────────────────────────────────

/// **R16 accept (`--all`)**: the bundle verifies offline, reveals every
/// unit including both files' whole-file commitments and the riding
/// mirror, and matches its preview annotation for annotation.
#[test]
fn reveal_all_builds_a_verifying_bundle_matching_its_preview() {
    let mock = MockBackend::new();
    let vault = shared_vault().unlock();
    let seal_id = seal_fixture(&mock, &vault, 0x61);

    let (sealproof, preview, summary) = reveal_verified(&mock, &vault, &seal_id, &all());

    assert_eq!(summary.revealed_unit_ids, vec![0, 1, 2, 3, 4, 5]);
    assert_eq!(
        summary.files_fully_revealed,
        vec![0, 1, 2],
        "--all fully reveals every file"
    );
    assert!(!summary.receipt_included, "omitted by default");
    assert!(preview.totals.mirror_rides_along);

    // The mirror is an ordinary §7.12 entry (no flag, no link — D70) and
    // the s_root annotation agrees with the manifest's fine-tree facts.
    let bundle = BundleV1::decode(&sealproof).expect("decodes");
    let manifest = Manifest::decode(bundle.manifest_bytes()).expect("manifest");
    for entry in bundle.full_reveals() {
        let file = &manifest.body().files()[usize::try_from(entry.file_id()).expect("fits")];
        assert_eq!(
            entry.disclosed_s_root().is_some(),
            file.fine_tree().is_present(),
            "s_root rides exactly with a present fine tree (D28/D74)"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────
// R16 Accept: unit subset (partial), and subset completing a file
// ─────────────────────────────────────────────────────────────────────

/// **R16 accept (unit subset)**: a strict subset of split.txt reveals one
/// covered unit with its boundary Merkle paths, touches one file, opens
/// no whole-file commitment and ships no mirror — and duplicate ids in
/// the request collapse rather than erroring.
#[test]
fn a_unit_subset_stays_partial_and_opens_no_whole_file_commitment() {
    let mock = MockBackend::new();
    let vault = shared_vault().unlock();
    let seal_id = seal_fixture(&mock, &vault, 0x62);

    let (sealproof, preview, summary) =
        reveal_verified(&mock, &vault, &seal_id, &units(&[4, 4, 4]));

    assert_eq!(summary.revealed_unit_ids, vec![4], "duplicates collapsed");
    assert!(summary.files_fully_revealed.is_empty());
    assert!(!preview.totals.mirror_rides_along);
    assert_eq!(preview.totals.files_touched, 1);

    let bundle = BundleV1::decode(&sealproof).expect("decodes");
    assert!(bundle.full_reveals().is_empty(), "no file_salt, no s_root");
    assert_eq!(
        bundle.covered_reveals().len(),
        1,
        "split.txt's units are fine-tree covered: the reveal carries the \
         GGM sub-cover and boundary paths the whole-file gather exists for"
    );
    assert!(bundle.noncovered_reveals().is_empty(), "no mirror rode");
    assert_eq!(bundle.touched_files().len(), 1);
    assert_eq!(bundle.touched_files()[0].path(), "split.txt");
}

/// **R16 accept (subset completing a file — the D70 promotion)**: naming
/// notes.txt's only normal unit by id IS a full reveal — `file_salt`,
/// `s_root` (where a fine tree exists) and the raw mirror all ride, and
/// the preview said so before the user consented.
#[test]
fn a_subset_completing_a_file_promotes_and_its_mirror_rides() {
    let mock = MockBackend::new();
    let vault = shared_vault().unlock();
    let seal_id = seal_fixture(&mock, &vault, 0x63);

    let (sealproof, preview, summary) = reveal_verified(&mock, &vault, &seal_id, &units(&[0]));

    assert_eq!(
        summary.revealed_unit_ids,
        vec![0, 1],
        "the mirror (unit 1) rides without being selected"
    );
    assert_eq!(summary.files_fully_revealed, vec![0]);
    assert!(preview.totals.mirror_rides_along);
    assert!(
        preview.files[0].mirror_rides_along,
        "the consent gate's annotation carried the mirror"
    );

    let bundle = BundleV1::decode(&sealproof).expect("decodes");
    assert_eq!(bundle.full_reveals().len(), 1);
    assert_eq!(bundle.full_reveals()[0].file_id(), 0);
    assert!(
        bundle
            .noncovered_reveals()
            .iter()
            .any(|entry| entry.unit_id() == 1),
        "the mirror is an ordinary non-covered reveal entry (registry §7.12)"
    );
    // Untouched files derive nothing — no path, no salt, no entry.
    assert_eq!(bundle.touched_files().len(), 1);
    assert_eq!(bundle.touched_files()[0].path(), "notes.txt");
}

// ─────────────────────────────────────────────────────────────────────
// R16 Accept: selection rejections, before anything is fetched
// ─────────────────────────────────────────────────────────────────────

/// **R16 accept (bare mirror id)**: `--units <mirror-id>` is the typed
/// G7 rejection pointing at whole-file reveal/`--all` — and it fires
/// before a single byte is gathered, proven by handing the engine an
/// empty backend and a cache-less vault it would otherwise have to hit.
#[test]
fn a_bare_mirror_id_is_rejected_before_anything_is_fetched() {
    let mock = MockBackend::new();
    let vault = shared_vault().unlock();
    let seal_id = seal_fixture(&mock, &vault, 0x64);
    let store = WorkStore::new(&vault);
    for entry in store.list_journal_entries(&seal_id).expect("entries") {
        if entry >= UNIT_ENTRY_BASE {
            store.delete_journal_entry(&seal_id, entry).expect("delete");
        }
    }

    let empty = MockBackend::new();
    let err = prepare(&empty, &vault, &seal_id, &units(&[1])).expect_err("rejected");
    assert!(
        matches!(err, RevealError::RawMirrorNotUnitSelectable { unit_id: 1 }),
        "{err:?}"
    );
    let message = err.to_string();
    assert!(
        message.contains("whole file") && message.contains("--all"),
        "the rejection points at the legal inclusion routes: {message}"
    );
    assert_eq!(
        empty.calls(Method::GetData),
        0,
        "selection validation precedes gathering: nothing was fetched"
    );
}

/// **R16 accept (unknown id)** plus the empty selection: both typed, both
/// pre-fetch.
#[test]
fn unknown_and_empty_selections_are_typed_errors() {
    let mock = MockBackend::new();
    let vault = shared_vault().unlock();
    let seal_id = seal_fixture(&mock, &vault, 0x65);

    let err = prepare(&mock, &vault, &seal_id, &units(&[9])).expect_err("unknown id");
    assert!(
        matches!(err, RevealError::UnknownUnitId { unit_id: 9 }),
        "{err:?}"
    );

    let err = prepare(&mock, &vault, &seal_id, &units(&[])).expect_err("empty selection");
    assert!(matches!(err, RevealError::EmptySelection), "{err:?}");
}

// ─────────────────────────────────────────────────────────────────────
// R16 Accept: sourcing — staged bytes, network fetch, and the D43 arms
// ─────────────────────────────────────────────────────────────────────

/// **R16 accept (staged-bytes path)**: with every cache copy present and
/// passing its recheck, the reveal never touches the network at all —
/// proven by an empty backend that would fail any fetch, and by its call
/// log staying empty.
#[test]
fn staged_bytes_serve_the_whole_reveal_without_touching_the_network() {
    let mock = MockBackend::new();
    let vault = shared_vault().unlock();
    let seal_id = seal_fixture(&mock, &vault, 0x66);

    // The seal went into `mock`; the reveal runs against a fresh, EMPTY
    // backend. Cache-first means the emptiness is never noticed.
    let empty = MockBackend::new();
    let (_, _, summary) = reveal_verified(&empty, &vault, &seal_id, &all());
    assert_eq!(summary.units_from_cache, 6, "every unit came off the cache");
    assert_eq!(summary.units_from_network, 0);
    assert_eq!(
        empty.calls(Method::GetData),
        0,
        "no fetch was even attempted"
    );
}

/// **R16 accept (fetch-from-network path)**: with no local copy of any
/// unit (the vault-import shape, D43 §3), every ciphertext is fetched by
/// its manifest address and the bundle still builds and verifies.
#[test]
fn with_no_local_copies_every_ciphertext_comes_from_the_network() {
    let mock = MockBackend::new();
    let vault = shared_vault().unlock();
    let seal_id = seal_fixture(&mock, &vault, 0x67);
    let store = WorkStore::new(&vault);
    for entry in store.list_journal_entries(&seal_id).expect("entries") {
        if entry >= UNIT_ENTRY_BASE {
            store.delete_journal_entry(&seal_id, entry).expect("delete");
        }
    }

    let (_, _, summary) = reveal_verified(&mock, &vault, &seal_id, &all());
    assert_eq!(summary.units_from_network, 6);
    assert_eq!(summary.units_from_cache, 0);
    assert!(mock.calls(Method::GetData) >= 6);
}

/// **D43 arm (corrupted cache)**: a cache copy failing its S4 integrity
/// recheck is silently refetched — never an error — and the built bundle
/// embeds the true bytes (it verifies, which a corrupt embed could not).
#[test]
fn a_corrupted_cache_copy_is_silently_refetched_never_an_error() {
    let mock = MockBackend::new();
    let vault = shared_vault().unlock();
    let seal_id = seal_fixture(&mock, &vault, 0x68);
    let store = WorkStore::new(&vault);
    let mut rng = ChaCha20Rng::from_seed([0x68; 32]);

    // Bit-flip unit 2's cached ciphertext inside an otherwise valid
    // record: the address recompute must reject it and the network copy
    // must serve instead.
    let entry = BlobSlot::Unit { unit_id: 2 }.entry_key().expect("key");
    let mut blob = staged_blob(&store, &seal_id, entry).expect("cached");
    blob.ciphertext[0] ^= 0x01;
    store
        .put_journal_entry(&seal_id, entry, &blob.encode().expect("encodes"), &mut rng)
        .expect("writes");

    let (_, _, summary) = reveal_verified(&mock, &vault, &seal_id, &all());
    assert_eq!(summary.units_from_network, 1, "exactly the corrupt one");
    assert_eq!(summary.units_from_cache, 5);
}

/// **D43 arm (cache miss)**: a deleted cache entry is fetched — never an
/// error — and the other five stay local.
#[test]
fn a_missing_cache_entry_is_fetched_never_an_error() {
    let mock = MockBackend::new();
    let vault = shared_vault().unlock();
    let seal_id = seal_fixture(&mock, &vault, 0x69);
    let store = WorkStore::new(&vault);

    let entry = BlobSlot::Unit { unit_id: 3 }.entry_key().expect("key");
    assert!(
        store
            .delete_journal_entry(&seal_id, entry)
            .expect("deletes")
    );

    let (_, _, summary) = reveal_verified(&mock, &vault, &seal_id, &all());
    assert_eq!(summary.units_from_network, 1);
    assert_eq!(summary.units_from_cache, 5);
}

/// The gather checker proven able to fail: bytes served for a unit that
/// do not hash to its manifest address — with no cache to heal through —
/// are a typed refusal, not an embed that would fail the recipient.
#[test]
fn substituted_network_bytes_without_a_cache_are_a_typed_address_mismatch() {
    let mock = MockBackend::new();
    let vault = shared_vault().unlock();
    let seal_id = seal_fixture(&mock, &vault, 0x6A);
    let store = WorkStore::new(&vault);

    let entry = BlobSlot::Unit { unit_id: 0 }.entry_key().expect("key");
    let staged = staged_blob(&store, &seal_id, entry).expect("cached");
    store
        .delete_journal_entry(&seal_id, entry)
        .expect("drop the cache copy");

    let substituting = Substituting {
        inner: &mock,
        address: Address::from(staged.address),
        bytes: b"not the sealed ciphertext".to_vec(),
    };
    let err = prepare(&substituting, &vault, &seal_id, &all()).expect_err("refused");
    assert!(
        matches!(err, RevealError::AddressMismatch { unit_id: 0 }),
        "{err:?}"
    );

    // And with nothing served at all: the distinct fetch-failure class.
    let empty = MockBackend::new();
    let err = prepare(&empty, &vault, &seal_id, &all()).expect_err("unfetchable");
    assert!(
        matches!(err, RevealError::Unfetchable { unit_id: 0, .. }),
        "{err:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────
// R16 Accept: --include-receipt
// ─────────────────────────────────────────────────────────────────────

/// **R16 accept (`--include-receipt`)**: the flag embeds the recorded
/// receipt — transaction hashes in capture order, the minimum recorded
/// block number (registry §7.10) — and its omission omits it; both
/// bundles verify.
#[test]
fn include_receipt_embeds_the_recorded_receipt_and_default_omits_it() {
    let mock = MockBackend::new();
    let vault = shared_vault().unlock();
    let seal_id = seal_fixture(&mock, &vault, 0x6B);
    let store = WorkStore::new(&vault);

    // Default: no receipt section at all.
    let (sealproof, _, summary) = reveal_verified(&mock, &vault, &seal_id, &all());
    assert!(!summary.receipt_included);
    assert!(
        BundleV1::decode(&sealproof)
            .expect("decodes")
            .receipt()
            .is_none()
    );

    // Opted in: the §7.10 record mirrors the journaled capture.
    let request = RevealRequest {
        selection: UnitSelection::All,
        include_receipt: true,
    };
    let (sealproof, _, summary) = reveal_verified(&mock, &vault, &seal_id, &request);
    assert!(summary.receipt_included);
    let bundle = BundleV1::decode(&sealproof).expect("decodes");
    let embedded = bundle.receipt().expect("receipt embedded");

    let recorded = recorded_receipt(&store, &seal_id)
        .expect("reads")
        .expect("recorded");
    let expected_hashes: Vec<[u8; 32]> = recorded
        .txs
        .iter()
        .map(|tx| *tx.tx_hash.as_bytes())
        .collect();
    let expected_min = recorded
        .txs
        .iter()
        .filter_map(|tx| tx.block_number)
        .min()
        .expect("the mock records block numbers");
    assert_eq!(embedded.tx_hashes(), expected_hashes.as_slice());
    assert_eq!(embedded.block_number(), expected_min);
    assert!(!embedded.payload().is_empty());
}

/// The receipt checkers proven able to fail — and proven to bind only the
/// opt-in: with the recorded receipt made unusable, a default reveal is
/// untouched (the record is never even read), while `--include-receipt`
/// surfaces each edge as its own typed error.
#[test]
fn receipt_edge_states_are_typed_errors_that_bind_only_the_opt_in() {
    let mock = MockBackend::new();
    let vault = shared_vault().unlock();
    let seal_id = seal_fixture(&mock, &vault, 0x6C);
    let store = WorkStore::new(&vault);
    let mut rng = ChaCha20Rng::from_seed([0x6C; 32]);
    let with_receipt = RevealRequest {
        selection: UnitSelection::All,
        include_receipt: true,
    };

    let recorded = recorded_receipt(&store, &seal_id)
        .expect("reads")
        .expect("recorded");

    // (a) Every transaction stripped of its block number: registry §7.10
    // key 1 is undefinable, and fabricating one is refused.
    let mut unenriched = recorded.clone();
    for tx in &mut unenriched.txs {
        tx.block_number = None;
    }
    put_receipt(&store, &seal_id, &unenriched, &mut rng);
    let err = prepare(&mock, &vault, &seal_id, &with_receipt).expect_err("no block number");
    assert!(
        matches!(err, RevealError::ReceiptBlockNumberUnknown),
        "{err:?}"
    );

    // (b) A receipt with no transactions: nothing embeddable.
    let mut empty_txs = recorded.clone();
    empty_txs.txs.clear();
    put_receipt(&store, &seal_id, &empty_txs, &mut rng);
    let err = prepare(&mock, &vault, &seal_id, &with_receipt).expect_err("nothing to embed");
    assert!(
        matches!(err, RevealError::ReceiptUnavailable { .. }),
        "{err:?}"
    );

    // (c) A record that is not a receipt at all.
    store
        .put_receipt(&seal_id, b"not a receipt record", &mut rng)
        .expect("writes");
    let err = prepare(&mock, &vault, &seal_id, &with_receipt).expect_err("unusable");
    assert!(
        matches!(err, RevealError::ReceiptUnusable { .. }),
        "{err:?}"
    );

    // The default path never reads the record: the same vault state
    // reveals cleanly without the flag (the negative control that the
    // opt-in is the only receipt consumer).
    let (_, _, summary) = reveal_verified(&mock, &vault, &seal_id, &all());
    assert!(!summary.receipt_included);
}

// ─────────────────────────────────────────────────────────────────────
// Anchors: capture-time statuses in, damaged slots refuse
// ─────────────────────────────────────────────────────────────────────

/// Stored anchor artifacts ride into the bundle with the sealer's honest
/// capture-time statuses (registry §6.1): pending `.ots` → `pending`,
/// upgraded → `attested` with its D79 group, TSA capture → `proven` with
/// its fetch date — and the bundle still verifies (anchor verdicts are
/// slot-local and never fail a bundle, D84).
#[test]
fn anchor_artifacts_embed_with_their_capture_time_statuses() {
    let mock = MockBackend::new();
    let vault = shared_vault().unlock();
    let seal_id = seal_fixture(&mock, &vault, 0x6D);
    let store = WorkStore::new(&vault);
    let mut rng = ChaCha20Rng::from_seed([0x6D; 32]);

    let ots = AnchorArtifact {
        kind: ArtifactKind::OtsPending,
        endpoint: String::new(),
        fetch_date: 1_800_000_100,
        bytes: b"pending-ots-container".to_vec(),
        upgrade: None,
    };
    store
        .put_anchor(
            &seal_id,
            OTS_SLOT,
            &ots.encode().expect("encodes"),
            &mut rng,
        )
        .expect("writes");
    for (index, token) in [b"der-token-0".as_slice(), b"der-token-1"]
        .iter()
        .enumerate()
    {
        let tsa = AnchorArtifact {
            kind: ArtifactKind::TsaToken,
            endpoint: format!("https://tsa{index}.example/"),
            fetch_date: 1_800_000_200 + index as u64,
            bytes: token.to_vec(),
            upgrade: None,
        };
        store
            .put_anchor(
                &seal_id,
                &tsa_slot(index),
                &tsa.encode().expect("encodes"),
                &mut rng,
            )
            .expect("writes");
    }

    let (sealproof, _, _) = reveal_verified(&mock, &vault, &seal_id, &all());
    let bundle = BundleV1::decode(&sealproof).expect("decodes");
    assert_eq!(bundle.ots_anchors().len(), 1);
    assert_eq!(bundle.ots_anchors()[0].status(), AnchorStatus::Pending);
    assert_eq!(
        bundle.ots_anchors()[0].ots().as_slice(),
        b"pending-ots-container"
    );
    assert!(bundle.ots_anchors()[0].upgrade().is_none());
    assert_eq!(bundle.tsa_anchors().len(), 2);
    for (index, anchor) in bundle.tsa_anchors().iter().enumerate() {
        assert_eq!(anchor.status(), AnchorStatus::Proven);
        assert_eq!(anchor.fetch_date(), 1_800_000_200 + index as u64);
        assert!(anchor.intermediates().is_empty());
    }

    // The upgraded arm: the D79 group rides and the status says attested
    // — never proven, which needs `verify --online`.
    let upgraded = AnchorArtifact {
        upgrade: Some(OtsUpgrade::new(850_000, [0x11; 80], 1_800_000_300)),
        ..ots
    };
    store
        .put_anchor(
            &seal_id,
            OTS_SLOT,
            &upgraded.encode().expect("encodes"),
            &mut rng,
        )
        .expect("overwrites");
    let (sealproof, _, _) = reveal_verified(&mock, &vault, &seal_id, &all());
    let bundle = BundleV1::decode(&sealproof).expect("decodes");
    assert_eq!(bundle.ots_anchors()[0].status(), AnchorStatus::Attested);
    let group = bundle.ots_anchors()[0].upgrade().expect("group rides");
    assert_eq!(group.block_height(), 850_000);
    assert_eq!(group.fetch_date(), 1_800_000_300);
}

/// The evidence door proven able to fail: a damaged anchor slot refuses
/// the reveal — a bundle silently missing recorded evidence would be
/// dishonest — rather than shipping the readable subset (D100 R2).
#[test]
fn a_damaged_anchor_slot_refuses_the_reveal_rather_than_dropping_evidence() {
    let mock = MockBackend::new();
    let vault = shared_vault().unlock();
    let seal_id = seal_fixture(&mock, &vault, 0x6E);
    let store = WorkStore::new(&vault);
    let mut rng = ChaCha20Rng::from_seed([0x6E; 32]);

    store
        .put_anchor(&seal_id, &tsa_slot(0), b"not an artifact record", &mut rng)
        .expect("writes");

    let err = prepare(&mock, &vault, &seal_id, &all()).expect_err("refused");
    assert!(
        matches!(err, RevealError::AnchorsUnreadable { .. }),
        "{err:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────
// Refusals that precede any work
// ─────────────────────────────────────────────────────────────────────

/// An incomplete work's content is not fully on the network; an unknown
/// id names nothing — both are typed refusals before any gathering.
#[test]
fn incomplete_and_unknown_works_are_refused_with_the_state_named() {
    let mock = MockBackend::new();
    let vault = shared_vault().unlock();
    let seal_id = seal_fixture(&mock, &vault, 0x6F);
    let store = WorkStore::new(&vault);

    let mut record = store.load_meta(&seal_id).expect("meta");
    record.state = WorkState::IncompletePostPay;
    store
        .store_meta(&record, &mut ChaCha20Rng::from_seed([0x6F; 32]))
        .expect("re-store");
    let err = prepare(&mock, &vault, &seal_id, &all()).expect_err("not revealable");
    match &err {
        RevealError::NotRevealable { state } => assert!(state.contains("incomplete"), "{state}"),
        other => panic!("{other:?}"),
    }

    let absent = SealId::from_bytes([0xEE; 16]);
    let err = prepare(&mock, &vault, &absent, &all()).expect_err("unknown work");
    assert!(matches!(err, RevealError::WorkNotFound), "{err:?}");
}

// ─────────────────────────────────────────────────────────────────────
// Manifest resolution: both sources, both absences, identity binding
// ─────────────────────────────────────────────────────────────────────

/// The manifest reaches the reveal from either S14 source — the plaintext
/// vault copy, the D43 cache of the encrypted blob, or the network fetch
/// — and each absence has its own typed refusal.
#[test]
fn manifest_resolution_covers_both_sources_and_names_both_absences() {
    let mock = MockBackend::new();
    let vault = shared_vault().unlock();
    let seal_id = seal_fixture(&mock, &vault, 0x71);
    let store = WorkStore::new(&vault);
    let mut rng = ChaCha20Rng::from_seed([0x71; 32]);

    // Source 2a: plaintext copy gone → the cached encrypted blob serves.
    store
        .delete_journal_entry(&seal_id, PLAN_ENTRY)
        .expect("drop the vault copy");
    let (_, _, summary) = reveal_verified(&mock, &vault, &seal_id, &all());
    assert_eq!(summary.revealed_unit_ids, vec![0, 1, 2, 3, 4, 5]);

    // Source 2b: the cached blob corrupted → refetched from the network,
    // silently (D43), and the reveal still verifies.
    let mut blob = staged_blob(&store, &seal_id, MANIFEST_BLOB_ENTRY).expect("cached");
    blob.ciphertext[0] ^= 0x01;
    store
        .put_journal_entry(
            &seal_id,
            MANIFEST_BLOB_ENTRY,
            &blob.encode().expect("encodes"),
            &mut rng,
        )
        .expect("writes");
    reveal_verified(&mock, &vault, &seal_id, &all());

    // Absence 1 (on a fresh work, its plan copy intact, to isolate the
    // locator's role): no locator → the §7.7 storage record cannot be
    // built, even though the manifest bytes themselves could be.
    let second = seal_fixture(&mock, &vault, 0x72);
    store
        .delete_journal_entry(&second, MANIFEST_BLOB_ENTRY)
        .expect("drop locator");
    let err = prepare(&mock, &vault, &second, &all()).expect_err("no storage record");
    assert!(
        matches!(err, RevealError::StorageRecordUnavailable),
        "{err:?}"
    );

    // Absence 2: neither the plaintext copy nor the locator → no manifest
    // at all.
    store
        .delete_journal_entry(&second, PLAN_ENTRY)
        .expect("drop plan");
    let err = prepare(&mock, &vault, &second, &all()).expect_err("no manifest");
    assert!(matches!(err, RevealError::ManifestUnavailable), "{err:?}");
}

/// The identity binding proven able to fail: a manifest that decodes but
/// does not match the vault's recorded `work_id` is refused — one work
/// can never disclose another seal's content.
#[test]
fn a_manifest_that_is_not_this_works_is_refused() {
    let mock = MockBackend::new();
    let vault = shared_vault().unlock();
    let seal_id = seal_fixture(&mock, &vault, 0x73);
    let store = WorkStore::new(&vault);

    // Patch the title (any body change moves work_id) and do NOT update
    // the vault's recorded work_id.
    repoint_manifest(&store, &mock, &seal_id, false, |body| body.files().to_vec());

    let err = prepare(&mock, &vault, &seal_id, &all()).expect_err("identity mismatch");
    assert!(
        matches!(
            err,
            RevealError::ManifestIdentityMismatch { detail: "work_id" }
        ),
        "{err:?}"
    );
}

/// The decrypt checker proven able to fail: a manifest whose unit nonce
/// was tampered decrypts nothing under the vault's keys — the AEAD/AAD
/// binding surfaces as the typed per-unit class, before any bundle
/// exists.
#[test]
fn a_manifest_nonce_tamper_surfaces_as_a_typed_unit_decrypt_failure() {
    let mock = MockBackend::new();
    let vault = shared_vault().unlock();
    let seal_id = seal_fixture(&mock, &vault, 0x74);
    let store = WorkStore::new(&vault);

    repoint_manifest(&store, &mock, &seal_id, true, |body| {
        body.files()
            .iter()
            .map(|file| {
                let units = file
                    .units()
                    .iter()
                    .map(|unit| {
                        if unit.unit_id() == 0 {
                            let mut nonce = *unit.nonce().as_bytes();
                            nonce[0] ^= 0x01;
                            UnitEntry::new(
                                unit.unit_id(),
                                unit.kind(),
                                unit.range(),
                                unit.true_length(),
                                *unit.binding(),
                                Nonce24::from_bytes(nonce),
                                *unit.address(),
                            )
                        } else {
                            unit.clone()
                        }
                    })
                    .collect();
                FileEntry::new(
                    *file.path_commit(),
                    *file.raw_commit(),
                    file.canon().clone(),
                    file.size(),
                    file.fine_tree(),
                    units,
                )
                .expect("rebuilt file entry")
            })
            .collect()
    });

    let err = prepare(&mock, &vault, &seal_id, &all()).expect_err("decrypt fails");
    assert!(
        matches!(err, RevealError::UnitDecrypt { unit_id: 0, .. }),
        "{err:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────
// Secret hygiene (project rule 6)
// ─────────────────────────────────────────────────────────────────────

/// Neither summaries nor errors mention `W` or file plaintext — across
/// the success path and every refusal exercised above.
#[test]
fn summaries_and_errors_carry_no_key_material() {
    let mock = MockBackend::new();
    let vault = shared_vault().unlock();
    let seal_id = seal_fixture(&mock, &vault, 0x75);
    let store = WorkStore::new(&vault);

    let w_hex = {
        let record = store.load_meta(&seal_id).expect("meta");
        antseal_cli::pipeline::hex32(record.w.secret_ref().as_bytes())
    };

    let prepared = prepare(&mock, &vault, &seal_id, &all()).expect("prepares");
    let debug = format!("{prepared:?}");
    assert!(!debug.contains(&w_hex), "no W in PreparedReveal's Debug");
    assert!(
        !debug.contains("café") && !debug.contains("alpha one"),
        "no gathered plaintext in PreparedReveal's Debug"
    );
    let output = prepared.build().expect("builds");
    let rendered = format!("{output:?} {:?}", output.summary);
    assert!(!rendered.contains(&w_hex));

    // Error paths: exhaust both sources for one unit and inspect the
    // failure text.
    for entry in store.list_journal_entries(&seal_id).expect("entries") {
        if entry >= UNIT_ENTRY_BASE {
            store.delete_journal_entry(&seal_id, entry).expect("delete");
        }
    }
    let empty = MockBackend::new();
    let err = prepare(&empty, &vault, &seal_id, &all()).expect_err("unfetchable");
    let text = format!("{err} {err:?}");
    assert!(!text.contains(&w_hex), "no key material in errors");
    assert!(!text.contains("caf"), "no plaintext content in errors");
}

// ─────────────────────────────────────────────────────────────────────
// Harness
// ─────────────────────────────────────────────────────────────────────

/// A backend that serves substituted bytes for exactly one address and
/// delegates everything else — the "the network answered, with the wrong
/// thing" instrument (the mock's own store is content-addressed and
/// cannot produce it).
struct Substituting<'m> {
    inner: &'m MockBackend,
    address: Address,
    bytes: Vec<u8>,
}

impl StorageBackend for Substituting<'_> {
    async fn quote_batch(
        &self,
        blobs: &[antseal_net::Blob],
    ) -> Result<antseal_net::CostQuote, StorageError> {
        self.inner.quote_batch(blobs).await
    }

    async fn pay(&self, quote: &antseal_net::CostQuote) -> Result<PaymentReceipt, StorageError> {
        self.inner.pay(quote).await
    }

    async fn finalize_batch(
        &self,
        receipt: &PaymentReceipt,
        blobs: &[antseal_net::Blob],
    ) -> Result<Vec<Address>, StorageError> {
        self.inner.finalize_batch(receipt, blobs).await
    }

    async fn get_data(&self, address: Address) -> Result<Vec<u8>, StorageError> {
        if address == self.address {
            return Ok(self.bytes.clone());
        }
        self.inner.get_data(address).await
    }

    async fn balances(&self) -> Result<antseal_net::BalanceReport, StorageError> {
        self.inner.balances().await
    }
}

/// Store a receipt through the same versioned envelope the pipeline
/// writes (the encoder pair lives in `receipt_sink`; tests reproduce it
/// through the public `JournalReceipt` seam).
fn put_receipt(
    store: &WorkStore<'_>,
    seal_id: &SealId,
    receipt: &PaymentReceipt,
    rng: &mut ChaCha20Rng,
) {
    let envelope = JournalReceipt::seal(receipt.clone());
    let bytes = serde_json::to_vec(&envelope).expect("encodes");
    store.put_receipt(seal_id, &bytes, rng).expect("writes");
}

/// Rewrite a work's manifest with `edit`ed file entries (and a marker
/// title change so the body always moves), re-encrypt it under `k_m`,
/// publish it to the network, repoint the vault's locator at it, and drop
/// the plaintext copy so the reveal reads the new one. With
/// `update_work_id` the vault record follows the body (the honest-vault
/// shape); without it the recorded identity is left stale — the
/// identity-mismatch instrument.
///
/// The rebuilt envelope keeps the ORIGINAL signatures. For the tamper
/// arms exercised here that is invisible: the reveal fails before any
/// bundle is built, so no signature is ever checked.
fn repoint_manifest<F>(
    store: &WorkStore<'_>,
    mock: &MockBackend,
    seal_id: &SealId,
    update_work_id: bool,
    edit: F,
) where
    F: FnOnce(&ManifestBodyV1) -> Vec<FileEntry>,
{
    let record = store.load_meta(seal_id).expect("meta");
    let w = record.w.secret_ref();

    let staged = staged_blob(store, seal_id, MANIFEST_BLOB_ENTRY).expect("manifest blob");
    let blob = block_on(mock.get_data(Address::from(staged.address))).expect("fetch manifest");
    let nonce = AeadNonce::from_bytes(staged.nonce);
    let plaintext =
        antseal_core::crypto::manifest_aead::decrypt_manifest(w, &nonce, &blob).expect("open");
    let manifest = Manifest::decode(&plaintext).expect("decode manifest");
    let body = manifest.body();

    let patched = ManifestBodyV1::new(
        body.app_version().to_owned(),
        *body.seal_id(),
        format!("{} (patched)", body.title()),
        body.claimed_time(),
        body.pubkeys().clone(),
        body.sig_policy().to_vec(),
        edit(body),
    )
    .expect("patched body");
    let body_bytes = encode_body(patched).expect("encode body");
    let envelope = encode_envelope(&body_bytes, manifest.signatures()).expect("encode envelope");

    let mut rng = ChaCha20Rng::from_seed([0xCC; 32]);
    let (new_blob, storage) =
        antseal_core::crypto::manifest_aead::encrypt_manifest(w, &envelope, &mut rng)
            .expect("re-encrypt");
    let address = mock.preload_third_party(&new_blob);

    let rewritten = StagedBlob {
        slot: staged.slot,
        nonce: *storage.nonce().as_bytes(),
        address: ContentAddress::from_bytes(*address.as_bytes()),
        ciphertext: new_blob,
    };
    store
        .put_journal_entry(
            seal_id,
            MANIFEST_BLOB_ENTRY,
            &rewritten.encode().expect("encode staged"),
            &mut ChaCha20Rng::from_seed([0xCD; 32]),
        )
        .expect("repoint the locator");
    store
        .delete_journal_entry(seal_id, PLAN_ENTRY)
        .expect("drop the plaintext copy");

    if update_work_id {
        let mut record = store.load_meta(seal_id).expect("meta");
        record.work_id = Some(manifest_work_id(&body_bytes).into_bytes());
        store
            .store_meta(&record, &mut ChaCha20Rng::from_seed([0xCE; 32]))
            .expect("re-store meta");
    }
}
