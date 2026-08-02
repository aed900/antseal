//! S14 acceptance suite: the restore engine over `MockBackend`.
//!
//! Every row here seals a real work through the S12 pipeline and then
//! restores it through the S14 engine, so what is asserted is a genuine
//! round trip — canonicalization, tiling, raw mirrors, AEAD, padding,
//! addresses and commitments all in the loop, with no fixture shortcuts
//! standing in for the parts under test.
//!
//! The devnet round trip is S17's; everything provable without a network
//! is provable here (S14 Accept rows 2, 3 and 5, and the D43 §5 fallback).
//!
//! NON-SECRET: every fixture byte string is documented; `W` never leaves
//! the vault records the harness reads through the public store API.

mod common;

use antseal_cli::error::{CliError, ErrorClass};
use antseal_cli::pipeline::journal::{
    MANIFEST_BLOB_ENTRY, PLAN_ENTRY, STATE_ENTRY, StagedBlob, UNIT_ENTRY_BASE,
};
use antseal_cli::pipeline::{
    ByteSource, FailureKind, FileError, FileOutcome, ManifestSource, NoBarriers, Pipeline,
    RestoreEngine, RestoreError, SealFile, SealRequest, SealResult, VerifiedFile,
};
use antseal_cli::vault::export::{export_vault, import_vault};
use antseal_cli::vault::session::UnlockedVault;
use antseal_cli::vault::store::{SealShapingFlags, WorkState, WorkStore};
use antseal_core::content::{FileFlags, SplitMode};
use antseal_core::crypto::manifest_aead::{decrypt_manifest, encrypt_manifest};
use antseal_core::crypto::secrets::SealId;
use antseal_core::crypto::sig_policy::SigPolicy;
use antseal_core::crypto::unit_aead::Nonce24 as AeadNonce;
use antseal_core::manifest::{
    CanonMode, ContentAddress, FileEntry, Manifest, ManifestBodyV1, encode_body, encode_envelope,
};
use antseal_net::test_util::{Fault, Method, MockBackend, block_on};
use antseal_net::{Address, NetworkId, StorageBackend, StorageError};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

use common::{IsolatedVault, RecordingGate, ScriptedConsent, passphrase, rng, shared_vault};

// ─────────────────────────────────────────────────────────────────────
// Fixture content
// ─────────────────────────────────────────────────────────────────────

/// A text file whose raw bytes differ from its canonical rendition in
/// three independent ways at once: a leading UTF-8 BOM, CRLF line endings,
/// and an NFD sequence (`e` + U+0301) that NFC folds to `é`. It therefore
/// carries a raw mirror, and restoring it byte-identically is the whole
/// point of the mirror (spec line 92).
const CRLF_BOM_NFD: &[u8] = "\u{FEFF}caf\u{65}\u{301} notes\r\n\r\nsecond para\r\n".as_bytes();

/// Binary: no canonical rendition, so its units already *are* raw bytes.
const BINARY: &[u8] = &[0x00, 0x01, 0x02, 0xFF, 0xFE, 0x7F, 0x80, 0x00, 0x42];

/// LF-only, BOM-free, NFC text with blank lines: `--split blank-lines`
/// tiles it into several units and it needs **no** mirror, which is the
/// path where the canonical bytes are also the original bytes.
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

fn request<'a>(files: &'a [SealFile<'a>]) -> SealRequest<'a> {
    SealRequest {
        files,
        title: "restore fixture".to_owned(),
        claimed_time_unix_secs: 1_800_000_000,
        app_version: "antseal-test/1".to_owned(),
        network: NetworkId::Devnet,
        no_anchor: false,
        degraded: false,
        dry_run: false,
        sig_policy: SigPolicy::hybrid(),
        shaping: SealShapingFlags::default(),
    }
}

/// Seal the three-file fixture into `mock` and return the work's seal id.
/// `seed` keeps each test's `seal_id`, `W` and nonces its own.
fn seal_fixture(mock: &MockBackend, vault: &UnlockedVault, seed: u8) -> SealId {
    let files = files();
    let mut journal_rng = ChaCha20Rng::from_seed([seed ^ 0xA5; 32]);
    let journal = antseal_cli::pipeline::VaultJournal::new(WorkStore::new(vault), &mut journal_rng);
    let gate = RecordingGate::new();
    let consent = ScriptedConsent::always_yes();
    let pipeline = Pipeline::new(mock, &gate, &journal, &consent, &NoBarriers);
    let result = block_on(pipeline.seal(&request(&files), &mut ChaCha20Rng::from_seed([seed; 32])))
        .expect("the fixture seals");
    match result {
        SealResult::Sealed(outcome) => outcome.seal_id,
        SealResult::DryRun(_) => unreachable!("not a dry run"),
    }
}

/// Restore `seal_id` from `mock` over a freshly-unlocked vault.
fn restore<B: StorageBackend>(
    mock: &B,
    vault: &UnlockedVault,
    seal_id: &SealId,
) -> Result<antseal_cli::pipeline::RestoreReport, RestoreError> {
    let store = WorkStore::new(vault);
    let engine = RestoreEngine::new(mock, &store);
    block_on(engine.restore(seal_id))
}

fn verified<'r>(report: &'r antseal_cli::pipeline::RestoreReport, path: &str) -> &'r VerifiedFile {
    report
        .verified()
        .find(|f| f.recorded_path == path)
        .unwrap_or_else(|| panic!("{path} verified"))
}

// ─────────────────────────────────────────────────────────────────────
// S14 Accept row 1 (the mock half of it): byte-identical restore
// ─────────────────────────────────────────────────────────────────────

/// **S14 accept**: a CRLF/BOM/NFD text file with a raw mirror, a binary
/// file, and a `--split` multi-unit text file all restore byte-identically
/// to the originals — the mirror-bearing file through its mirror, so the
/// BOM, the CRLF endings and the NFD sequence all survive.
#[test]
fn every_file_shape_restores_byte_identically() {
    let mock = MockBackend::new();
    let vault = shared_vault().unlock();
    let seal_id = seal_fixture(&mock, &vault, 0x11);

    let report = restore(&mock, &vault, &seal_id).expect("restore succeeds");
    assert_eq!(report.files.len(), 3);
    assert!(report.failed().next().is_none(), "no file failed");
    assert_eq!(report.manifest_source, ManifestSource::VaultCopy);

    let notes = verified(&report, "notes.txt");
    assert_eq!(notes.bytes, CRLF_BOM_NFD, "exact original bytes");
    assert_eq!(notes.source, ByteSource::RawMirror);
    assert!(
        notes.bytes.starts_with(&[0xEF, 0xBB, 0xBF])
            && notes.bytes.windows(2).any(|w| w == b"\r\n"),
        "the BOM and the CRLF endings are intact"
    );

    let blob = verified(&report, "data/blob.bin");
    assert_eq!(blob.bytes, BINARY);
    assert_eq!(blob.source, ByteSource::Raw);

    let split = verified(&report, "split.txt");
    assert_eq!(split.bytes, SPLIT_TEXT);
    assert_eq!(
        split.source,
        ByteSource::Canonical,
        "an LF/NFC/BOM-free file needs no mirror, and its canonical bytes ARE the original"
    );
    assert!(
        split.from_network >= 3,
        "blank-line split produced several units"
    );

    // Everything came off the network: the normative path (D43 §5).
    assert_eq!(report.cache_served_units(), 0);
    assert!(mock.calls(Method::GetData) >= 5);
}

/// The report is keyed to the work the vault recorded — a restore can
/// never hand back another seal's content under this work's name.
#[test]
fn the_report_carries_the_recorded_work_identity() {
    let mock = MockBackend::new();
    let vault = shared_vault().unlock();
    let seal_id = seal_fixture(&mock, &vault, 0x12);
    let store = WorkStore::new(&vault);

    let report = restore(&mock, &vault, &seal_id).expect("restore succeeds");
    let recorded = store.load_meta(&seal_id).expect("meta").work_id;
    assert_eq!(recorded, Some(report.work_id));
    assert_eq!(report.network, "devnet");
    assert!(!report.unanchored);

    // And the printed form resolves back to the work.
    let engine = RestoreEngine::new(&mock, &store);
    let printed = antseal_cli::pipeline::hex32(&report.work_id);
    assert_eq!(engine.resolve_work_id(&printed).expect("resolves"), seal_id);
    assert_eq!(
        engine
            .resolve_work_id(&printed.to_uppercase())
            .expect("case-insensitive"),
        seal_id
    );
}

// ─────────────────────────────────────────────────────────────────────
// S14 Accept row 3: D43 §5's verified-cache fallback
// ─────────────────────────────────────────────────────────────────────

/// **S14 accept**: with a unit's network copy unavailable and a valid
/// cache copy present, restore succeeds through the cache — with the same
/// commitment verification, so the fallback costs no trust.
#[test]
fn a_failed_fetch_falls_back_to_the_verified_cache() {
    let mock = MockBackend::new();
    let vault = shared_vault().unlock();
    let seal_id = seal_fixture(&mock, &vault, 0x13);

    // One-shot: the first `get_data` of the run fails.
    mock.arm_fault(Fault::DuringGetData);
    let report = restore(&mock, &vault, &seal_id).expect("restore still succeeds");

    assert!(
        report.failed().next().is_none(),
        "the fallback rescued the run"
    );
    assert_eq!(
        report.cache_served_units(),
        1,
        "exactly one unit came from cache"
    );
    assert_eq!(verified(&report, "notes.txt").bytes, CRLF_BOM_NFD);
    assert_eq!(verified(&report, "split.txt").bytes, SPLIT_TEXT);
}

/// **S14 accept**: with both the network copy and the cache copy gone, the
/// not-found error surfaces — as a per-file row in the fetch class, never
/// as a silent empty file.
#[test]
fn with_neither_network_nor_cache_the_fetch_failure_surfaces() {
    let mock = MockBackend::new();
    let vault = shared_vault().unlock();
    let seal_id = seal_fixture(&mock, &vault, 0x14);
    let store = WorkStore::new(&vault);

    // Drop every cached unit blob, then restore against an empty network.
    for entry in store.list_journal_entries(&seal_id).expect("entries") {
        if entry >= MANIFEST_BLOB_ENTRY {
            store.delete_journal_entry(&seal_id, entry).expect("delete");
        }
    }
    let empty = MockBackend::new();
    let report = restore(&empty, &vault, &seal_id).expect("the run completes");

    assert_eq!(
        report.failed().count(),
        3,
        "every file failed, none half-written"
    );
    for failed in report.failed() {
        assert!(
            matches!(failed.error, FileError::Unfetchable { .. }),
            "{}: {:?}",
            failed.recorded_path,
            failed.error
        );
        assert_eq!(failed.error.kind(), FailureKind::Fetch);
        assert!(
            failed
                .error
                .to_string()
                .contains("no verified local copy exists"),
            "the message names both exhausted sources"
        );
    }
    assert!(report.verified().next().is_none(), "no bytes were produced");
}

// ─────────────────────────────────────────────────────────────────────
// S14 Accept row 2: verification failures are distinct and write nothing
// ─────────────────────────────────────────────────────────────────────

/// **S14 accept**: a commitment mismatch on a file yields a distinct error
/// and that file produces no verified bytes — while the *other* files of
/// the same work still restore, because per-file failures are rows, not
/// early returns.
#[test]
fn a_commitment_mismatch_is_distinct_and_yields_no_bytes_for_that_file() {
    let mock = MockBackend::new();
    let vault = shared_vault().unlock();
    let seal_id = seal_fixture(&mock, &vault, 0x15);
    let store = WorkStore::new(&vault);

    // Corrupt file 0's `canon_commit` inside the manifest itself: the unit
    // ciphertexts stay exactly as sealed, so the fetch, the address
    // recompute, the AEAD and the padding strip all succeed and the
    // commitment check is the only thing left to fail.
    repoint_manifest(&store, &mock, &seal_id, |body| {
        let mut files = Vec::new();
        for (index, file) in body.files().iter().enumerate() {
            let canon = match file.canon() {
                CanonMode::Binary => CanonMode::Binary,
                CanonMode::Text {
                    canon_commit,
                    unicode_version,
                } => {
                    let mut digest = *canon_commit;
                    if index == 0 {
                        digest[0] ^= 0x01;
                    }
                    CanonMode::Text {
                        canon_commit: digest,
                        unicode_version: unicode_version.clone(),
                    }
                }
            };
            files.push(
                FileEntry::new(
                    *file.path_commit(),
                    *file.raw_commit(),
                    canon,
                    file.size(),
                    file.fine_tree(),
                    file.units().to_vec(),
                )
                .expect("rebuilt file entry"),
            );
        }
        files
    });

    let report = restore(&mock, &vault, &seal_id).expect("the run completes");
    let failed: Vec<_> = report.failed().collect();
    assert_eq!(failed.len(), 1, "only the tampered file failed");
    assert_eq!(failed[0].recorded_path, "notes.txt");
    assert!(
        matches!(
            failed[0].error,
            FileError::CommitmentMismatch {
                subject: "the canonical bytes"
            }
        ),
        "{:?}",
        failed[0].error
    );
    assert_eq!(failed[0].error.kind(), FailureKind::Verification);
    assert_eq!(FailureKind::Verification.status(), "verification-failed");

    // The other two files are untouched by their neighbour's failure.
    assert_eq!(verified(&report, "data/blob.bin").bytes, BINARY);
    assert_eq!(verified(&report, "split.txt").bytes, SPLIT_TEXT);
    // And there is no way to write the failed file: the outcome holds no
    // bytes at all (S14's "not written as verified output", by type).
    assert!(report.files.iter().all(|f| match f {
        FileOutcome::Failed(_) => true,
        FileOutcome::Verified(v) => v.recorded_path != "notes.txt",
    }));
}

/// Substituted network bytes are caught by S4's address recompute before
/// the AEAD ever sees them — a distinct verification class from a fetch
/// failure, and distinct from a commitment mismatch.
#[test]
fn substituted_network_bytes_are_caught_by_the_address_recompute() {
    let mock = MockBackend::new();
    let vault = shared_vault().unlock();
    let seal_id = seal_fixture(&mock, &vault, 0x16);
    let store = WorkStore::new(&vault);

    // Find unit 0's address, and drop its cache copy so the fallback
    // cannot (correctly) rescue the substitution.
    let staged = staged_blob(&store, &seal_id, 3).expect("unit 0 is cached");
    store
        .delete_journal_entry(&seal_id, 3)
        .expect("drop the cache copy");

    let substituting = Substituting {
        inner: &mock,
        address: Address::from(staged.address),
        bytes: b"not the sealed ciphertext".to_vec(),
    };
    let report = restore(&substituting, &vault, &seal_id).expect("the run completes");

    let failed: Vec<_> = report.failed().collect();
    assert_eq!(failed.len(), 1);
    assert!(
        matches!(failed[0].error, FileError::AddressMismatch { unit_id: 0 }),
        "{:?}",
        failed[0].error
    );
    assert_eq!(failed[0].error.kind(), FailureKind::Verification);
}

/// The same substitution **with** the cache present is not an error at
/// all: D43's fallback notices the served bytes are not the ones the
/// address names and serves the verified local copy instead.
#[test]
fn a_substitution_heals_through_the_cache_when_one_exists() {
    let mock = MockBackend::new();
    let vault = shared_vault().unlock();
    let seal_id = seal_fixture(&mock, &vault, 0x17);
    let store = WorkStore::new(&vault);
    let staged = staged_blob(&store, &seal_id, 3).expect("unit 0 is cached");

    let substituting = Substituting {
        inner: &mock,
        address: Address::from(staged.address),
        bytes: b"not the sealed ciphertext".to_vec(),
    };
    let report = restore(&substituting, &vault, &seal_id).expect("restore succeeds");
    assert!(report.failed().next().is_none());
    assert_eq!(report.cache_served_units(), 1);
    assert_eq!(verified(&report, "notes.txt").bytes, CRLF_BOM_NFD);
}

// ─────────────────────────────────────────────────────────────────────
// Manifest resolution (S14's two sources)
// ─────────────────────────────────────────────────────────────────────

/// With the vault's plaintext copy gone, restore fetches the encrypted
/// manifest by its journaled address and opens it with `k_m` — S14's
/// second source, and the one a network-first restore leans on.
#[test]
fn the_manifest_is_fetched_and_decrypted_when_the_vault_copy_is_gone() {
    let mock = MockBackend::new();
    let vault = shared_vault().unlock();
    let seal_id = seal_fixture(&mock, &vault, 0x18);
    let store = WorkStore::new(&vault);
    store
        .delete_journal_entry(&seal_id, PLAN_ENTRY)
        .expect("drop the vault copy");

    let report = restore(&mock, &vault, &seal_id).expect("restore succeeds");
    assert_eq!(report.manifest_source, ManifestSource::Network);
    assert_eq!(verified(&report, "notes.txt").bytes, CRLF_BOM_NFD);
    assert_eq!(verified(&report, "data/blob.bin").bytes, BINARY);
}

/// With neither a plaintext copy nor a locator, restore says exactly that
/// rather than guessing: an encrypted manifest cannot be found on a
/// content-addressed network without its address.
///
/// Both sources have to be removed by hand to reach this state. That was
/// once the shape a `vault import`ed **complete** work arrived in, because
/// U12's export applied D43 §3's cache exclusion to the whole journal
/// area; **S29** scoped the exclusion to the staged *unit* blobs, so the
/// import path no longer produces it (the round trip is proven directly
/// by `an_imported_complete_work_restores_from_the_network` below). The
/// engine's refusal is still exactly right when it genuinely happens, and
/// is still asserted here.
#[test]
fn without_a_locator_the_manifest_is_reported_unavailable() {
    let mock = MockBackend::new();
    let vault = shared_vault().unlock();
    let seal_id = seal_fixture(&mock, &vault, 0x19);
    let store = WorkStore::new(&vault);
    store
        .delete_journal_entry(&seal_id, PLAN_ENTRY)
        .expect("drop plan");
    store
        .delete_journal_entry(&seal_id, MANIFEST_BLOB_ENTRY)
        .expect("drop locator");

    let err = restore(&mock, &vault, &seal_id).expect_err("no manifest, no restore");
    assert!(matches!(err, RestoreError::ManifestUnavailable), "{err:?}");
    assert_eq!(
        CliError::from(err).class(),
        ErrorClass::MalformedRestoreRecord,
        "D48's malformed-restore-record class"
    );
}

// ─────────────────────────────────────────────────────────────────────
// S29: the backup round trip
// ─────────────────────────────────────────────────────────────────────

/// **S29** — a `vault export` → wipe → `vault import` of a **complete**
/// work restores, and still carries none of the D43 cache.
///
/// The two halves are asserted together on purpose, because they are the
/// two opposite ways to get this rule wrong. Excluding the *whole*
/// journal area (the defect S29 records) drops entry 2 and with it the
/// encrypted manifest's `{address, nonce}` — and an encrypted manifest
/// cannot be found on a content-addressed network without its address, so
/// the work becomes permanently unrestorable from a backup. Excluding
/// nothing puts content-scale ciphertext into a file users are nagged to
/// keep (U18). The corrected rule — exclude the staged *unit* blobs
/// (`>= UNIT_ENTRY_BASE`), keep the record-scale head — is what both
/// assertions together pin.
///
/// After the import not one unit ciphertext exists locally, so every
/// restored byte below came off the wire: this is D43 §3's "pure network
/// path with zero test contrivance" and S19's clean-tree drill in
/// miniature, with `MockBackend` standing in for Autonomi.
#[test]
fn an_imported_complete_work_restores_from_the_network() {
    let mock = MockBackend::new();
    let vault = IsolatedVault::create("s29-backup");
    let seal_id = {
        let unlocked = vault.unlock();
        let seal_id = seal_fixture(&mock, &unlocked, 0x29);
        assert_eq!(
            WorkStore::new(&unlocked)
                .load_meta(&seal_id)
                .expect("meta")
                .state,
            WorkState::Complete,
            "the export rule under test is the complete-work one"
        );
        seal_id
    };

    // Export, then destroy the vault outright — the clean-machine shape.
    let backup = vault.root.join("backup.sealvault");
    {
        let unlocked = vault.unlock();
        export_vault(&unlocked, &passphrase(), &backup, &mut rng()).expect("export");
    }
    std::fs::remove_dir_all(vault.layout.root()).expect("wipe vault");
    import_vault(&backup, &vault.layout, || Ok(passphrase()), &mut rng()).expect("import");

    let unlocked = vault.unlock();
    let store = WorkStore::new(&unlocked);

    // The D43 cache is still excluded: the record-scale head survived,
    // every staged unit blob did not.
    let entries = store.list_journal_entries(&seal_id).expect("entries");
    assert_eq!(
        entries,
        vec![STATE_ENTRY, PLAN_ENTRY, MANIFEST_BLOB_ENTRY],
        "a complete work exports its record-scale head and nothing else"
    );
    assert!(
        staged_blob(&store, &seal_id, UNIT_ENTRY_BASE).is_none(),
        "no unit ciphertext may survive the round trip (D43 §3)"
    );

    // Restorable, and byte-identical — the S19 gate clause.
    let report = restore(&mock, &unlocked, &seal_id).expect("the imported work restores");
    assert_eq!(report.manifest_source, ManifestSource::VaultCopy);
    assert_eq!(verified(&report, "notes.txt").bytes, CRLF_BOM_NFD);
    assert_eq!(verified(&report, "data/blob.bin").bytes, BINARY);
    assert_eq!(verified(&report, "split.txt").bytes, SPLIT_TEXT);
    for file in report.verified() {
        assert_eq!(
            file.from_cache, 0,
            "{} used a cached unit, so the export was not lean",
            file.recorded_path
        );
        assert!(
            file.from_network > 0,
            "{} produced no unit from the network",
            file.recorded_path
        );
    }

    // And the locator itself round-tripped: drop the plaintext copy and
    // the manifest is still found — by the `{address, nonce}` in entry 2,
    // which is the record whose loss made S29 a gate blocker.
    store
        .delete_journal_entry(&seal_id, PLAN_ENTRY)
        .expect("drop the vault copy");
    let report = restore(&mock, &unlocked, &seal_id).expect("the locator survived too");
    assert_eq!(report.manifest_source, ManifestSource::Network);
    assert_eq!(verified(&report, "notes.txt").bytes, CRLF_BOM_NFD);
}

// ─────────────────────────────────────────────────────────────────────
// Refusals that precede any work
// ─────────────────────────────────────────────────────────────────────

#[test]
fn unknown_and_malformed_work_ids_fail_cleanly() {
    let mock = MockBackend::new();
    let vault = shared_vault().unlock();
    let seal_id = seal_fixture(&mock, &vault, 0x1A);
    let store = WorkStore::new(&vault);
    let engine = RestoreEngine::new(&mock, &store);

    let absent = engine.resolve_work_id(&"ab".repeat(32));
    assert!(matches!(absent, Err(RestoreError::WorkNotFound)));
    for bad in ["", "abc", "zz", &"0".repeat(63), &"g".repeat(64)] {
        assert!(
            matches!(
                engine.resolve_work_id(bad),
                Err(RestoreError::NotAWorkId { .. })
            ),
            "{bad:?} is not a work id"
        );
    }
    // A real one still resolves (the negative cases are not vacuous).
    let record = store.load_meta(&seal_id).expect("meta");
    let printed = antseal_cli::pipeline::hex32(&record.work_id.expect("work_id"));
    assert_eq!(engine.resolve_work_id(&printed).expect("resolves"), seal_id);
}

/// An incomplete work's content was never fully uploaded, so restore
/// refuses with a clean, actionable error rather than fetching addresses
/// that cannot exist.
#[test]
fn an_incomplete_work_is_refused_with_its_state_named() {
    let mock = MockBackend::new();
    let vault = shared_vault().unlock();
    let seal_id = seal_fixture(&mock, &vault, 0x1B);
    let store = WorkStore::new(&vault);

    let mut record = store.load_meta(&seal_id).expect("meta");
    record.state = antseal_cli::vault::store::WorkState::IncompletePostPay;
    store
        .store_meta(&record, &mut ChaCha20Rng::from_seed([0x5B; 32]))
        .expect("re-store");

    let err = restore(&mock, &vault, &seal_id).expect_err("not restorable");
    match &err {
        RestoreError::NotRestorable { state } => {
            assert!(state.contains("incomplete"), "{state}");
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(CliError::from(err).class(), ErrorClass::Usage);
}

// ─────────────────────────────────────────────────────────────────────
// Secret hygiene (project rule 6)
// ─────────────────────────────────────────────────────────────────────

/// Neither the report nor any error mentions `W`, a unit key, or the
/// plaintext of a file the run failed on.
#[test]
fn reports_and_errors_carry_no_key_material() {
    let mock = MockBackend::new();
    let vault = shared_vault().unlock();
    let seal_id = seal_fixture(&mock, &vault, 0x1C);
    let store = WorkStore::new(&vault);

    let w_hex = {
        let record = store.load_meta(&seal_id).expect("meta");
        antseal_cli::pipeline::hex32(record.w.secret_ref().as_bytes())
    };

    let report = restore(&mock, &vault, &seal_id).expect("restore succeeds");
    // The report legitimately holds file bytes (that is its product), so
    // the assertion is about the *rendered* form the CLI would ever print.
    let rendered = format!(
        "{:?}",
        report
            .files
            .iter()
            .map(|f| (f.file_id(), f.recorded_path().to_owned()))
            .collect::<Vec<_>>()
    );
    assert!(!rendered.contains(&w_hex));

    let empty = MockBackend::new();
    for entry in store.list_journal_entries(&seal_id).expect("entries") {
        if entry >= MANIFEST_BLOB_ENTRY {
            store.delete_journal_entry(&seal_id, entry).expect("delete");
        }
    }
    let failed = restore(&empty, &vault, &seal_id).expect("the run completes");
    for row in failed.failed() {
        let text = format!("{} {:?}", row.error, row.error);
        assert!(!text.contains(&w_hex), "no key material in errors");
        assert!(!text.contains("caf"), "no plaintext content in errors");
    }
}

// ─────────────────────────────────────────────────────────────────────
// Harness
// ─────────────────────────────────────────────────────────────────────

/// A backend that serves substituted bytes for exactly one address and
/// delegates everything else — the "the network answered, with the wrong
/// thing" instrument the mock's fault set deliberately does not provide
/// (it cannot: its store is content-addressed).
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

    async fn pay(
        &self,
        quote: &antseal_net::CostQuote,
    ) -> Result<antseal_net::PaymentReceipt, StorageError> {
        self.inner.pay(quote).await
    }

    async fn finalize_batch(
        &self,
        receipt: &antseal_net::PaymentReceipt,
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
}

/// The staged (D43 cache) record at one journal entry key.
fn staged_blob(store: &WorkStore<'_>, seal_id: &SealId, entry: u64) -> Option<StagedBlob> {
    let bytes = store.get_journal_entry(seal_id, entry).expect("read")?;
    Some(StagedBlob::decode(bytes.as_bytes()).expect("decode"))
}

/// Rewrite a work's manifest with `edit`ed file entries, re-encrypt it
/// under `k_m`, publish it to the network, and repoint the vault at it —
/// then drop the plaintext vault copy so restore reads the new one.
///
/// The rebuilt envelope keeps the **original** signatures, which no longer
/// cover the patched body. That is deliberate and load-bearing for what
/// this harness tests: restore does not verify manifest signatures (its
/// two sources are already AEAD-authenticated under this vault's keys), so
/// a test that re-signed would be proving something restore never reads.
fn repoint_manifest<F>(store: &WorkStore<'_>, mock: &MockBackend, seal_id: &SealId, edit: F)
where
    F: FnOnce(&ManifestBodyV1) -> Vec<FileEntry>,
{
    let record = store.load_meta(seal_id).expect("meta");
    let w = record.w.secret_ref();

    let staged = staged_blob(store, seal_id, MANIFEST_BLOB_ENTRY).expect("manifest blob");
    let blob = block_on(mock.get_data(Address::from(staged.address))).expect("fetch manifest");
    let nonce = AeadNonce::from_bytes(staged.nonce);
    let plaintext = decrypt_manifest(w, &nonce, &blob).expect("open manifest");
    let manifest = Manifest::decode(&plaintext).expect("decode manifest");
    let body = manifest.body();

    let patched = ManifestBodyV1::new(
        body.app_version().to_owned(),
        *body.seal_id(),
        body.title().to_owned(),
        body.claimed_time(),
        body.pubkeys().clone(),
        body.sig_policy().to_vec(),
        edit(body),
    )
    .expect("patched body");
    let body_bytes = encode_body(patched).expect("encode body");
    let envelope = encode_envelope(&body_bytes, manifest.signatures()).expect("encode envelope");

    let mut rng = ChaCha20Rng::from_seed([0xCC; 32]);
    let (new_blob, storage) = encrypt_manifest(w, &envelope, &mut rng).expect("re-encrypt");
    let address = mock.preload_third_party(&new_blob);

    // The cache copy is rewritten alongside the network copy, or D43's
    // recheck would (correctly) refuse the stale one and the fallback
    // would hide the tamper this harness is planting.
    let rewritten = StagedBlob {
        slot: staged.slot,
        nonce: *storage.nonce().as_bytes(),
        address: ContentAddress::from_bytes(*address.as_bytes()),
        ciphertext: new_blob,
    };
    let encoded = rewritten.encode().expect("encode staged");
    store
        .put_journal_entry(
            seal_id,
            MANIFEST_BLOB_ENTRY,
            &encoded,
            &mut ChaCha20Rng::from_seed([0xCD; 32]),
        )
        .expect("repoint the locator");
    store
        .delete_journal_entry(seal_id, PLAN_ENTRY)
        .expect("drop the plaintext copy");

    // The work_id moved with the body; keep the vault's record honest so
    // the identity binding is not what fails.
    let mut record = store.load_meta(seal_id).expect("meta");
    record.work_id = Some(antseal_core::manifest::work_id(&body_bytes).into_bytes());
    store
        .store_meta(&record, &mut ChaCha20Rng::from_seed([0xCE; 32]))
        .expect("re-store meta");
}
