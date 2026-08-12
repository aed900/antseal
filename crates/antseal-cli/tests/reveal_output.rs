//! U28 acceptance suite: `reveal`'s command core — the D68 output policy,
//! the D68 §3 R8 ordering, and the bundle a real run actually writes.
//!
//! Every row drives the real command path —
//! [`antseal_cli::reveal_out::run_reveal`] over a `MockBackend` and a real
//! vault — so what is asserted is a genuine seal → reveal → **verify from
//! disk** round trip, not a simulation of one. The bundles are read back
//! **off the filesystem** and handed to `antseal_core::verify_bundle`, the
//! offline recipient's own check: what is proven is the file, not the buffer
//! that produced it.
//!
//! # What this suite does NOT own
//!
//! The consent gate. U28 supplies the seam (`run_reveal`'s `consent`
//! argument) and U29 supplies the gate — the preview rendering, the
//! receipt-exposure warning, `--yes` and D51's machine-mode matrix. The
//! closures here are test doubles that **count** and **decline**, which is
//! exactly what the ordering rows need: D68 §3 R11 pin 2 requires a refused
//! output path to be observed *before* the gate fires, and that is only
//! assertable if something records whether it was asked.
//!
//! NON-SECRET: every fixture byte string is documented in `common`.

mod common;

use std::cell::Cell;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, OnceLock};

use antseal_cli::brand::VERIFIER_URL;
use antseal_cli::cli::RevealArgs;
use antseal_cli::error::{CliError, ErrorClass};
use antseal_cli::pipeline::journal::UNIT_ENTRY_BASE;
use antseal_cli::pipeline::{
    NoBarriers, Pipeline, PreparedReveal, SealFile, SealRequest, SealResult, VaultJournal, hex32,
};
use antseal_cli::reveal_out::{RevealReport, default_bundle_path, run_reveal};
use antseal_cli::vault::session::UnlockedVault;
use antseal_cli::vault::store::{SealShapingFlags, WorkStore};
use antseal_core::bundle::BundleV1;
use antseal_core::content::{FileFlags, SplitMode};
use antseal_core::crypto::secrets::SealId;
use antseal_core::crypto::sig_policy::SigPolicy;
use antseal_core::verify::{VerifyOptions, verify_bundle};
use antseal_net::NetworkId;
use antseal_net::test_util::{Method, MockBackend, block_on};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

use common::{IsolatedVault, RecordingGate, ScriptedConsent};

/// BOM + CRLF + NFD: raw bytes differ from canonical three ways, so this
/// file carries a raw mirror — the unit `--units <mirror-id>` must refuse.
const CRLF_BOM_NFD: &[u8] = "\u{FEFF}caf\u{65}\u{301} notes\r\n\r\nsecond para\r\n".as_bytes();
const BINARY: &[u8] = &[0x00, 0x01, 0x02, 0xFF, 0xFE, 0x7F, 0x80, 0x00, 0x42];
const SPLIT_TEXT: &[u8] = b"alpha one\n\nbeta two\n\ngamma three\n";

/// The fixture's unit ids: 0 = notes normal, **1 = notes raw mirror**,
/// 2 = binary, 3/4/5 = the split text file's three units.
const MIRROR_UNIT: u64 = 1;
const UNKNOWN_UNIT: u64 = 99;

// ─────────────────────────────────────────────────────────────────────
// Harness
// ─────────────────────────────────────────────────────────────────────

/// A scratch directory that removes itself.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "antseal-u28-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        std::fs::create_dir_all(&path).expect("mk scratch");
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

/// Seal the fixture work into `mock` and return its printed work id — the
/// exact string a user copies out of `list` and passes to `reveal`.
fn seal_fixture(mock: &MockBackend, vault: &UnlockedVault, seed: u8) -> String {
    let files = files();
    let mut journal_rng = ChaCha20Rng::from_seed([seed ^ 0xA5; 32]);
    let journal = VaultJournal::new(WorkStore::new(vault), &mut journal_rng);
    let gate = RecordingGate::new();
    let consent = ScriptedConsent::always_yes();
    let pipeline = Pipeline::new(mock, &gate, &journal, &consent, &NoBarriers);
    let request = SealRequest {
        files: &files,
        title: "u28 fixture".to_owned(),
        claimed_time_unix_secs: 1_800_000_000,
        app_version: "antseal-test/1".to_owned(),
        network: NetworkId::Devnet,
        no_anchor: false,
        degraded: false,
        dry_run: false,
        sig_policy: SigPolicy::hybrid(),
        shaping: SealShapingFlags::default(),
    };
    let result = block_on(pipeline.seal(&request, &mut ChaCha20Rng::from_seed([seed; 32])))
        .expect("the fixture seals");
    match result {
        SealResult::Sealed(outcome) => hex32(&outcome.work_id),
        SealResult::DryRun(_) => unreachable!("not a dry run"),
    }
}

/// `antseal reveal <work-id> --all [-o …]`, as parsed argv would arrive.
fn all_args(work_id: &str, output: Option<&Path>) -> RevealArgs {
    RevealArgs {
        work_id: work_id.to_owned(),
        all: true,
        units: Vec::new(),
        output: output.map(Path::to_path_buf),
        include_receipt: false,
        // U29's channel. U28 transports it and reads nothing from it.
        yes: false,
    }
}

/// `antseal reveal <work-id> --units <ids> [-o …]`.
fn unit_args(work_id: &str, units: &[u64], output: Option<&Path>) -> RevealArgs {
    RevealArgs {
        units: units.to_vec(),
        all: false,
        ..all_args(work_id, output)
    }
}

/// A consent seam that records how many times it was asked, and answers
/// however the test needs.
struct Gate {
    asks: Cell<usize>,
    answer: Result<(), ErrorClass>,
}

impl Gate {
    fn granting() -> Self {
        Self {
            asks: Cell::new(0),
            answer: Ok(()),
        }
    }

    fn declining() -> Self {
        Self {
            asks: Cell::new(0),
            answer: Err(ErrorClass::ConsentNotObtained),
        }
    }

    fn consent(&self) -> impl FnOnce(&PreparedReveal) -> Result<(), CliError> + '_ {
        move |prepared| {
            self.asks.set(self.asks.get() + 1);
            // The gate sees the preview and nothing bundle-shaped — R16's
            // two-phase split, observed rather than assumed.
            assert!(
                !prepared.preview().rows.is_empty(),
                "the gate is handed the disclosure preview"
            );
            match self.answer {
                Ok(()) => Ok(()),
                Err(_) => Err(CliError::ConsentNotObtained {
                    reason: antseal_cli::error::ConsentOutcome::Declined,
                }),
            }
        }
    }

    fn asked(&self) -> usize {
        self.asks.get()
    }
}

/// Run one reveal with a granting gate, asserting the gate was asked
/// exactly once.
fn reveal_ok(mock: &MockBackend, vault: &UnlockedVault, args: &RevealArgs) -> RevealReport {
    let store = WorkStore::new(vault);
    let gate = Gate::granting();
    let report =
        block_on(run_reveal(mock, &store, args, gate.consent())).expect("the reveal completes");
    assert_eq!(gate.asked(), 1, "consent is asked exactly once");
    report
}

/// Read the written bundle back **off disk** and put it through the
/// recipient's own offline check. Returns the bytes, because a decoded
/// [`BundleV1`] borrows them.
fn verified_bytes(report: &RevealReport) -> Vec<u8> {
    let bytes = std::fs::read(&report.bundle_path).expect("the bundle is on disk");
    assert_eq!(bytes.len() as u64, report.bytes, "the report's byte count");
    verify_bundle(&bytes, &VerifyOptions::new()).expect("the written bundle verifies offline");
    BundleV1::decode(&bytes).expect("the written bundle decodes");
    bytes
}

/// The only work in a fixture vault.
fn only_work(store: &WorkStore<'_>) -> SealId {
    let works = store.list_works().expect("list");
    assert_eq!(works.len(), 1, "the fixture vault holds one work");
    works[0]
}

/// Drop every cached unit ciphertext — the vault-import shape (D43 §3),
/// where the only source left is the network.
fn wipe_unit_cache(vault: &UnlockedVault) {
    let store = WorkStore::new(vault);
    let seal_id = only_work(&store);
    for entry in store.list_journal_entries(&seal_id).expect("entries") {
        if entry >= UNIT_ENTRY_BASE {
            store.delete_journal_entry(&seal_id, entry).expect("delete");
        }
    }
}

/// Serializes the two tests that need a **real** invocation cwd, because
/// `set_current_dir` is process-global and the harness runs tests in
/// parallel threads of one process. Every other test here uses absolute
/// paths and is unaffected.
fn cwd_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Run `body` with the process cwd set to `dir`, restoring it afterwards.
fn in_cwd<T>(dir: &Path, body: impl FnOnce() -> T) -> T {
    let _guard = cwd_lock();
    let original = std::env::current_dir().expect("cwd");
    std::env::set_current_dir(dir).expect("chdir into the scratch");
    let out = body();
    std::env::set_current_dir(&original).expect("chdir back");
    out
}

// ─────────────────────────────────────────────────────────────────────
// Accept row 1: --all and --units produce R-verified bundles
// ─────────────────────────────────────────────────────────────────────

/// **U28 accept (`--all`)**: the written file verifies offline, discloses
/// every unit including the riding mirror, and the report says so.
#[test]
fn reveal_all_writes_a_bundle_that_verifies_from_disk() {
    let scratch = Scratch::new("all");
    let mock = MockBackend::new();
    let vault = IsolatedVault::create("u28-all");
    let unlocked = vault.unlock();
    let work_id = seal_fixture(&mock, &unlocked, 0x81);

    let target = scratch.join("whole.sealproof");
    let report = reveal_ok(&mock, &unlocked, &all_args(&work_id, Some(&target)));

    assert_eq!(report.bundle_path, target);
    assert_eq!(hex32(&report.work_id), work_id);
    assert_eq!(report.summary.revealed_unit_ids, vec![0, 1, 2, 3, 4, 5]);
    assert_eq!(report.summary.files_fully_revealed, vec![0, 1, 2]);
    assert_eq!(report.files_touched, 3);
    assert!(!report.summary.receipt_included, "omitted by default");

    let bytes = verified_bytes(&report);
    let bundle = BundleV1::decode(&bytes).expect("decodes");
    let mut ids = bundle.revealed_unit_ids();
    ids.sort_unstable();
    assert_eq!(ids, report.summary.revealed_unit_ids);
    assert_eq!(bundle.full_reveals().len(), 3);
}

/// **U28 accept (`--units`)**: a strict subset writes a bundle that also
/// verifies from disk, opens no whole-file commitment, and touches exactly
/// the one file it named.
#[test]
fn reveal_units_writes_a_partial_bundle_that_verifies_from_disk() {
    let scratch = Scratch::new("units");
    let mock = MockBackend::new();
    let vault = IsolatedVault::create("u28-units");
    let unlocked = vault.unlock();
    let work_id = seal_fixture(&mock, &unlocked, 0x82);

    let target = scratch.join("one-paragraph.sealproof");
    let report = reveal_ok(&mock, &unlocked, &unit_args(&work_id, &[4], Some(&target)));

    assert_eq!(report.summary.revealed_unit_ids, vec![4]);
    assert!(report.summary.files_fully_revealed.is_empty());
    assert_eq!(report.files_touched, 1);

    let bytes = verified_bytes(&report);
    let bundle = BundleV1::decode(&bytes).expect("decodes");
    assert_eq!(bundle.revealed_unit_ids(), vec![4]);
    assert!(
        bundle.full_reveals().is_empty(),
        "a partial reveal opens no file_salt and no s_root"
    );
    assert_eq!(bundle.touched_files().len(), 1);
    assert_eq!(bundle.touched_files()[0].path(), "split.txt");
}

// ─────────────────────────────────────────────────────────────────────
// Accept row 2: unknown unit ids and mirror ids are distinct errors
// ─────────────────────────────────────────────────────────────────────

/// **U28 accept**: an unknown id and a bare raw-mirror id are two different
/// refusals with two different sentences — and neither writes anything.
///
/// Both land in `usage` (D69 §5 group 1: *fix the command*), which is the
/// ruling; what must differ, and is asserted here, is what the user is
/// **told**. A code-only assertion would pass with one message for both.
#[test]
fn an_unknown_unit_id_and_a_bare_mirror_id_are_distinct_refusals() {
    let scratch = Scratch::new("refusals");
    let mock = MockBackend::new();
    let vault = IsolatedVault::create("u28-refusals");
    let unlocked = vault.unlock();
    let work_id = seal_fixture(&mock, &unlocked, 0x83);
    let store = WorkStore::new(&unlocked);

    let unknown_target = scratch.join("unknown.sealproof");
    let gate = Gate::granting();
    let unknown = block_on(run_reveal(
        &mock,
        &store,
        &unit_args(&work_id, &[UNKNOWN_UNIT], Some(&unknown_target)),
        gate.consent(),
    ))
    .expect_err("unit 99 does not exist");

    let mirror_target = scratch.join("mirror.sealproof");
    let mirror_gate = Gate::granting();
    let mirror = block_on(run_reveal(
        &mock,
        &store,
        &unit_args(&work_id, &[MIRROR_UNIT], Some(&mirror_target)),
        mirror_gate.consent(),
    ))
    .expect_err("a raw mirror is not selectable by id");

    let (unknown_text, mirror_text) = (unknown.to_string(), mirror.to_string());
    assert_ne!(unknown_text, mirror_text, "two refusals, two sentences");
    assert!(
        unknown_text.contains(&UNKNOWN_UNIT.to_string()) && unknown_text.contains("does not exist"),
        "{unknown_text}"
    );
    assert!(
        mirror_text.contains("raw mirror")
            && mirror_text.contains("whole file")
            && mirror_text.contains("--all"),
        "the mirror refusal names the two legal inclusion routes: {mirror_text}"
    );
    assert_eq!(unknown.class(), ErrorClass::Usage, "{unknown_text}");
    assert_eq!(mirror.class(), ErrorClass::Usage, "{mirror_text}");

    // Selection validation precedes everything: no file, and the gate was
    // never asked to disclose anything.
    assert!(!unknown_target.exists() && !mirror_target.exists());
    assert_eq!(gate.asked(), 0);
    assert_eq!(mirror_gate.asked(), 0);
}

// ─────────────────────────────────────────────────────────────────────
// Accept row 3: the local-copy-absent path exercises S's fetch
// ─────────────────────────────────────────────────────────────────────

/// **U28 accept**: with no cached ciphertext left, the run fetches every
/// unit from the backend — asserted on the mock's own `get_data` call log —
/// and the bundle it writes still verifies from disk.
#[test]
fn with_no_local_copy_the_run_fetches_every_ciphertext_through_the_backend() {
    let scratch = Scratch::new("fetch");
    let mock = MockBackend::new();
    let vault = IsolatedVault::create("u28-fetch");
    let unlocked = vault.unlock();
    let work_id = seal_fixture(&mock, &unlocked, 0x84);

    wipe_unit_cache(&unlocked);
    let before = mock.calls(Method::GetData);

    let target = scratch.join("fetched.sealproof");
    let report = reveal_ok(&mock, &unlocked, &all_args(&work_id, Some(&target)));

    assert_eq!(report.summary.units_from_network, 6, "every unit fetched");
    assert_eq!(report.summary.units_from_cache, 0);
    assert!(
        mock.calls(Method::GetData) >= before + 6,
        "the backend really served them: {} → {}",
        before,
        mock.calls(Method::GetData)
    );
    verified_bytes(&report);
}

// ─────────────────────────────────────────────────────────────────────
// Accept row 4: --include-receipt toggles receipt embedding
// ─────────────────────────────────────────────────────────────────────

/// **U28 accept**: the flag is the opt-in and nothing else — the same work,
/// revealed twice, differs exactly by the §7.10 receipt record, and both
/// bundles verify.
#[test]
fn include_receipt_toggles_the_embedded_receipt() {
    let scratch = Scratch::new("receipt");
    let mock = MockBackend::new();
    let vault = IsolatedVault::create("u28-receipt");
    let unlocked = vault.unlock();
    let work_id = seal_fixture(&mock, &unlocked, 0x85);

    let without = reveal_ok(
        &mock,
        &unlocked,
        &all_args(&work_id, Some(&scratch.join("plain.sealproof"))),
    );
    assert!(!without.summary.receipt_included);
    let plain = verified_bytes(&without);
    assert!(
        BundleV1::decode(&plain)
            .expect("decodes")
            .receipt()
            .is_none()
    );
    assert_eq!(
        without.json()["receipt_included"],
        serde_json::json!(false),
        "the machine form of the same fact"
    );

    let mut args = all_args(&work_id, Some(&scratch.join("with-receipt.sealproof")));
    args.include_receipt = true;
    let with = reveal_ok(&mock, &unlocked, &args);
    assert!(with.summary.receipt_included);
    let embedded = verified_bytes(&with);
    let bundle = BundleV1::decode(&embedded).expect("decodes");
    let receipt = bundle.receipt().expect("the receipt rides");
    assert!(!receipt.tx_hashes().is_empty());
    assert_eq!(with.json()["receipt_included"], serde_json::json!(true));

    // The exposure is stated in the human copy only when it is real
    // (spec lines 36/110/185).
    assert!(with.render().join("\n").contains("wallet that paid"));
    assert!(!without.render().join("\n").contains("wallet"));
}

// ─────────────────────────────────────────────────────────────────────
// Accept row 5: the default path, and the collision that is refused
// before consent (D68 §3 R5/R7/R8, R11 pins 1–2)
// ─────────────────────────────────────────────────────────────────────

/// **U28 accept / D68 §3 R5**: with no `-o`, the bundle lands at
/// `./antseal-reveal-<work-id>.sealproof` in the invocation cwd — the real
/// default, exercised through a real cwd rather than inferred from the
/// path-building function.
#[test]
fn without_o_the_bundle_lands_at_the_default_path_in_the_cwd() {
    let scratch = Scratch::new("default");
    let mock = MockBackend::new();
    let vault = IsolatedVault::create("u28-default");
    let unlocked = vault.unlock();
    let work_id = seal_fixture(&mock, &unlocked, 0x86);

    let report = in_cwd(&scratch.0, || {
        reveal_ok(&mock, &unlocked, &all_args(&work_id, None))
    });

    assert_eq!(report.bundle_path, default_bundle_path(&report.work_id));
    assert_eq!(
        report.bundle_path.to_string_lossy(),
        format!("antseal-reveal-{work_id}.sealproof"),
        "cwd-relative, work-scoped, one extension"
    );
    let landed = scratch.join(&format!("antseal-reveal-{work_id}.sealproof"));
    assert!(landed.is_file(), "the file is in the invocation cwd");
    verify_bundle(
        &std::fs::read(&landed).expect("read"),
        &VerifyOptions::new(),
    )
    .expect("the default-named bundle verifies offline");
}

/// **U28 accept / D68 §3 R7–R8, R11 pin 2**: an occupied default path is
/// **refused with nothing written**, the existing file's bytes and mtime are
/// unchanged, and the refusal fires **before the consent gate** and before
/// any ciphertext is fetched.
///
/// All four are asserted, because each is a different failure: an
/// overwrite, a truncation, a user asked to approve a disclosure that could
/// not land, and money/bandwidth spent on a run that could never finish.
#[test]
fn an_occupied_default_path_is_refused_before_consent_and_before_any_fetch() {
    let scratch = Scratch::new("collision");
    let mock = MockBackend::new();
    let vault = IsolatedVault::create("u28-collision");
    let unlocked = vault.unlock();
    let work_id = seal_fixture(&mock, &unlocked, 0x87);
    let store = WorkStore::new(&unlocked);

    // Nothing local is left, so any gathering at all MUST hit the backend —
    // which is what makes "zero fetches" a real observation rather than a
    // cache artefact.
    wipe_unit_cache(&unlocked);

    let occupied = scratch.join(&format!("antseal-reveal-{work_id}.sealproof"));
    std::fs::write(&occupied, b"an earlier bundle, already sent").expect("occupy");
    let before_bytes = std::fs::read(&occupied).expect("read");
    let before_mtime = std::fs::metadata(&occupied)
        .expect("stat")
        .modified()
        .expect("mtime");
    let before_fetches = mock.calls(Method::GetData);

    let gate = Gate::granting();
    let err = in_cwd(&scratch.0, || {
        block_on(run_reveal(
            &mock,
            &store,
            &all_args(&work_id, None),
            gate.consent(),
        ))
    })
    .expect_err("the default path is occupied");

    assert_eq!(err.class(), ErrorClass::RefusedOverwrite, "{err}");
    assert_eq!(
        err.exit_code(),
        30,
        "D48 §6's rung, U2's number (D68 §3 R7)"
    );
    let text = err.to_string();
    assert!(
        text.contains(&format!("antseal-reveal-{work_id}.sealproof")) && text.contains("-o"),
        "the refusal names the path and the way out: {text}"
    );

    assert_eq!(
        std::fs::read(&occupied).expect("read"),
        before_bytes,
        "the existing file's bytes are untouched"
    );
    assert_eq!(
        std::fs::metadata(&occupied)
            .expect("stat")
            .modified()
            .expect("mtime"),
        before_mtime,
        "the existing file was not even opened for writing"
    );
    assert_eq!(
        gate.asked(),
        0,
        "nobody is asked to consent to a disclosure that cannot be written (D68 §3 R8)"
    );
    assert_eq!(
        mock.calls(Method::GetData),
        before_fetches,
        "a refused output path costs zero fetches"
    );
}

/// The same refusal on an explicit `-o`, and the property `create_new`
/// buys over the pre-flight check: a directory in the way is refused too,
/// and a second reveal of the same work to the same path never replaces the
/// first bundle.
#[test]
fn an_explicit_output_path_is_never_overwritten_and_a_directory_is_refused() {
    let scratch = Scratch::new("explicit");
    let mock = MockBackend::new();
    let vault = IsolatedVault::create("u28-explicit");
    let unlocked = vault.unlock();
    let work_id = seal_fixture(&mock, &unlocked, 0x88);
    let store = WorkStore::new(&unlocked);

    let target = scratch.join("pitch.sealproof");
    let first = reveal_ok(&mock, &unlocked, &all_args(&work_id, Some(&target)));
    let first_bytes = std::fs::read(&target).expect("read");
    assert_eq!(first_bytes.len() as u64, first.bytes);

    // A second reveal — of a DIFFERENT selection, the ordinary case D68
    // §1 (j) names — must not land on top of it.
    let gate = Gate::granting();
    let err = block_on(run_reveal(
        &mock,
        &store,
        &unit_args(&work_id, &[4], Some(&target)),
        gate.consent(),
    ))
    .expect_err("the path is taken");
    assert_eq!(err.class(), ErrorClass::RefusedOverwrite, "{err}");
    assert_eq!(gate.asked(), 0);
    assert_eq!(std::fs::read(&target).expect("read"), first_bytes);

    // A directory occupies the path just as a file does.
    let dir = scratch.join("a-directory.sealproof");
    std::fs::create_dir(&dir).expect("mkdir");
    let dir_gate = Gate::granting();
    let err = block_on(run_reveal(
        &mock,
        &store,
        &all_args(&work_id, Some(&dir)),
        dir_gate.consent(),
    ))
    .expect_err("a directory is in the way");
    assert_eq!(err.class(), ErrorClass::RefusedOverwrite, "{err}");
    assert!(dir.is_dir(), "the directory was not touched");
}

// ─────────────────────────────────────────────────────────────────────
// The consent seam (U28 supplies it; U29 supplies the gate)
// ─────────────────────────────────────────────────────────────────────

/// A gate that declines writes **no bundle file** — the property R16's
/// two-phase split exists for, observed at the command layer.
///
/// U29 owns what makes a gate decline (a "no" at the prompt, machine mode
/// without `--yes`); this row owns only that a declining seam leaves the
/// filesystem exactly as it found it.
#[test]
fn a_declining_consent_seam_writes_no_bundle() {
    let scratch = Scratch::new("declined");
    let mock = MockBackend::new();
    let vault = IsolatedVault::create("u28-declined");
    let unlocked = vault.unlock();
    let work_id = seal_fixture(&mock, &unlocked, 0x89);
    let store = WorkStore::new(&unlocked);

    let target = scratch.join("never-written.sealproof");
    let gate = Gate::declining();
    let err = block_on(run_reveal(
        &mock,
        &store,
        &all_args(&work_id, Some(&target)),
        gate.consent(),
    ))
    .expect_err("consent declined");

    assert_eq!(gate.asked(), 1, "the gate WAS reached this time");
    assert_eq!(err.class(), ErrorClass::ConsentNotObtained, "{err}");
    assert!(!target.exists(), "nothing bundle-shaped reached the disk");
    assert!(
        std::fs::read_dir(&scratch.0)
            .expect("read scratch")
            .next()
            .is_none(),
        "not even a partial file"
    );
}

// ─────────────────────────────────────────────────────────────────────
// Accept row 6: the closing lines and the `--json` document
// ─────────────────────────────────────────────────────────────────────

/// **U28 accept**: the output carries the canonical verifier URL — from
/// [`VERIFIER_URL`], the one Rust definition D62 §3 R8 permits — and the
/// bundle path beside it.
#[test]
fn the_output_carries_the_bundle_path_and_the_canonical_verifier_url() {
    let scratch = Scratch::new("closing");
    let mock = MockBackend::new();
    let vault = IsolatedVault::create("u28-closing");
    let unlocked = vault.unlock();
    let work_id = seal_fixture(&mock, &unlocked, 0x8A);

    let target = scratch.join("closing.sealproof");
    let report = reveal_ok(&mock, &unlocked, &all_args(&work_id, Some(&target)));
    let rendered = report.render().join("\n");

    assert!(rendered.contains(VERIFIER_URL), "{rendered}");
    assert_eq!(
        rendered.matches(VERIFIER_URL).count(),
        1,
        "printed once, not repeated"
    );
    assert!(
        rendered.contains(&target.display().to_string()),
        "{rendered}"
    );
    assert_eq!(
        report.json()["verifier_url"],
        serde_json::json!(VERIFIER_URL),
        "the machine document carries the same one value"
    );
}

/// **U28 accept**: the registered `--json` shape, with the
/// **per-document key assertion** D65 §8.2 owes every command (the
/// `list_command.rs` / `restore_output.rs` / `show_command.rs` pattern):
/// silent on additions, red on a removal or a rename.
#[test]
fn the_json_document_carries_the_bundle_path_units_and_receipt_flag() {
    let scratch = Scratch::new("json");
    let mock = MockBackend::new();
    let vault = IsolatedVault::create("u28-json");
    let unlocked = vault.unlock();
    let work_id = seal_fixture(&mock, &unlocked, 0x8B);

    let target = scratch.join("doc.sealproof");
    let report = reveal_ok(&mock, &unlocked, &unit_args(&work_id, &[0], Some(&target)));
    let doc = report.json();

    for key in [
        "work_id",
        "bundle_path",
        "bytes",
        "revealed_unit_ids",
        "files_fully_revealed",
        "files_touched",
        "receipt_included",
        "units",
        "verifier_url",
    ] {
        assert!(doc.get(key).is_some(), "document is missing {key}: {doc}");
    }
    for key in ["from_cache", "from_network"] {
        assert!(
            doc["units"].get(key).is_some(),
            "units is missing {key}: {doc}"
        );
    }

    assert_eq!(doc["work_id"], serde_json::json!(work_id));
    assert_eq!(
        doc["bundle_path"],
        serde_json::json!(target.display().to_string())
    );
    assert_eq!(doc["bytes"], serde_json::json!(report.bytes));
    // Naming notes.txt's only normal unit IS a full reveal, and the mirror
    // rides with it (D70's promotion) — the machine document says both.
    assert_eq!(doc["revealed_unit_ids"], serde_json::json!([0, 1]));
    assert_eq!(doc["files_fully_revealed"], serde_json::json!([0]));
    assert_eq!(doc["files_touched"], serde_json::json!(1));
    assert_eq!(doc["receipt_included"], serde_json::json!(false));
}
