//! `seal`'s command layer end to end (U13 + U14), driven over
//! `MockBackend` through the library API — D34's rule that the M1 E2E
//! goes through `antseal_cli`, never a spawned binary.
//!
//! What the sibling suites already cover and this one deliberately does
//! not repeat: `seal_pipeline.rs` owns the normative order and the
//! ciphertext-only egress, `seal_matrix.rs` the invariant matrix,
//! `seal_resume.rs` the journal state machine. This suite owns the layer
//! *around* them — plan validation reaching the pipeline, D45 detection
//! choosing between `seal` and `resume`, and the U14 gate deciding whether
//! money may move at all.
//!
//! NON-SECRET: every passphrase, `W` and byte string here is a documented
//! fixture (project rule 6).

mod common;
#[path = "common/spawn.rs"]
mod spawn;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use antseal_cli::backend::{BackendArm, no_backend_message};
use antseal_cli::cli::{Cli, Command};
use antseal_cli::error::ErrorClass;
use antseal_cli::listing::WorkListing;
use antseal_cli::pipeline::{DryRunReport, SealJournal, VaultJournal};
use antseal_cli::seal_consent::{ConsentPrompt, PERMANENCE_WARNING, SealConsent};
use antseal_cli::seal_plan::{SealPlan, build_plan};
use antseal_cli::seal_resume::{
    AbandonConfirm, ResumeDecision, abandon_pre_pay, detect, resolve_abandon_id, run_abandon,
};
use antseal_cli::seal_run::{SealCommandResult, SealContext, dry_run_outcome, run_seal};
use antseal_cli::seal_session::SealSession;
use antseal_cli::seal_warnings::FINE_TREE_ESTIMATE_THRESHOLD_BYTES;
use antseal_cli::vault::bookkeeping::{self, LOSS_WARNING, THEFT_WARNING};
use antseal_cli::vault::store::{WorkState, WorkStore};
use antseal_core::crypto::secrets::SealId;
use antseal_net::test_util::{Method, MockBackend, block_on};
use antseal_net::{BalanceReport, CostQuote, network::EvmAddress20};
use common::IsolatedVault;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

/// A NON-SECRET, structurally complete fixture receipt (one sub-batch
/// tx): the money-moved evidence the abandon guard reads. Every value is
/// an obviously synthetic byte pattern.
fn fixture_receipt() -> antseal_net::PaymentReceipt {
    use antseal_net::{GasSummary, PaymentReceipt, QuoteHash, TxHash, TxRecord, TxStatus};

    let quote = QuoteHash::from_bytes([0xB1; 32]);
    let tx = TxHash::from_bytes([0xB2; 32]);
    PaymentReceipt {
        blobs: Vec::new(),
        tx_map: [(quote, tx)].into_iter().collect(),
        txs: vec![TxRecord {
            tx_hash: tx,
            block_number: Some(42),
            status: TxStatus::Confirmed,
            quote_hashes: vec![quote],
        }],
        storage_cost_atto: 4_200,
        gas: GasSummary {
            gas_cost_wei: 21_000,
        },
    }
}

/// NON-SECRET fixture wallet address: a repeated byte pattern.
const FIXTURE_WALLET: [u8; 20] = [0x5A; 20];

fn funded() -> BalanceReport {
    BalanceReport {
        wallet: EvmAddress20::from_bytes(FIXTURE_WALLET),
        ant_atto: u128::from(u64::MAX),
        gas_wei: u128::from(u64::MAX),
    }
}

fn ctx(machine_mode: bool) -> SealContext {
    SealContext {
        machine_mode,
        to_stderr: true,
        now_unix_secs: 1_800_000_000,
        app_version: "antseal-test/1".to_owned(),
        // Every case in this suite is `--no-anchor`, so the stage is skipped
        // by the pipeline and these endpoints are never read. They are empty
        // rather than defaulted so that a future case which drops the flag
        // aborts offline instead of contacting a live TSA (common's docs).
        anchors: common::offline_anchor_stage(),
    }
}

/// A prompt that must never be reached (every case here is `--yes` or
/// machine mode; an interactive prompt in a test binary would hang).
struct NeverAsked;
impl ConsentPrompt for NeverAsked {
    fn ask(&mut self) -> Result<bool, antseal_cli::error::CliError> {
        panic!("the gate prompted where it must not");
    }
}

/// Says no once, then never again.
struct SaysNo;
impl ConsentPrompt for SaysNo {
    fn ask(&mut self) -> Result<bool, antseal_cli::error::CliError> {
        Ok(false)
    }
}

struct Work {
    dir: PathBuf,
}

impl Work {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "antseal-sealcmd-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("mk work dir");
        Self { dir }
    }

    fn file(&self, name: &str, bytes: &[u8]) -> &Self {
        std::fs::write(self.dir.join(name), bytes).expect("write fixture file");
        self
    }

    /// Build a plan the way the real handler does — through the real
    /// parser, so the flags this suite exercises are the flags the frozen
    /// surface accepts, not a hand-built struct that could drift from it.
    fn plan(&self, extra: &[&str]) -> Result<SealPlan, antseal_cli::error::CliError> {
        let mut argv = vec!["antseal", "seal"];
        argv.extend_from_slice(extra);
        let cli = Cli::parse_checked(argv.iter().copied()).expect("argv parses");
        let Command::Seal(args) = &cli.command else {
            panic!("built a non-seal argv");
        };
        build_plan(args, antseal_net::NetworkId::Devnet, &self.dir)
    }
}

impl Drop for Work {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

// ─────────────────────────────────────────────────────────────────────
// The happy path (U13 accept: work-id + cost, cost persisted)
// ─────────────────────────────────────────────────────────────────────

#[test]
fn a_scripted_seal_completes_prints_work_id_and_cost_and_persists_the_record() {
    let work = Work::new("happy");
    work.file("notes.txt", b"hello world\n\nsecond paragraph\n")
        .file("blob.bin", &[0x7Fu8; 64]);
    let plan = work
        .plan(&["notes.txt", "blob.bin", "--no-anchor", "--yes"])
        .expect("plan validates");

    let backend = MockBackend::new().with_balances(funded());
    let vault = IsolatedVault::create("seal-happy");
    let unlocked = SealSession::open(Arc::new(vault.unlock()));

    let result = block_on(run_seal(
        &backend,
        &unlocked,
        &plan,
        &mut NeverAsked,
        &ctx(true),
        &mut ChaCha20Rng::from_seed([0x11; 32]),
        &mut ChaCha20Rng::from_seed([0x22; 32]),
    ))
    .expect("the seal completes");

    let SealCommandResult::Sealed(report) = result else {
        panic!("a non-dry-run seal returns Sealed");
    };
    assert!(report.paid_here);
    assert!(report.cost_atto > 0, "the mock quotes a nonzero cost");
    assert!(!report.resumed);
    assert!(report.unanchored, "--no-anchor is recorded on the report");
    assert!(report.blob_count >= 3, "two files plus the manifest");

    // The spec's closing line for this flow: "print work-id + cost".
    let rendered = report.render().join("\n");
    assert!(rendered.contains("Sealed. work-id "), "{rendered}");
    assert!(
        rendered.contains(&report.cost_atto.to_string()),
        "{rendered}"
    );
    assert!(rendered.contains("UNANCHORED"), "{rendered}");

    // U13 accept: the cost is persisted to the work record (U9).
    let store = WorkStore::new(unlocked.vault());
    let meta = store.load_meta(&report.seal_id).expect("record exists");
    assert_eq!(meta.state, WorkState::Complete);
    assert_eq!(meta.cost_atto, Some(report.cost_atto));
    assert_eq!(meta.work_id, Some(report.work_id));
    // D45's invocation identity, recorded for the next re-run.
    assert_eq!(meta.input_paths_as_given, vec!["notes.txt", "blob.bin"]);
    assert_eq!(meta.input_paths_absolute, plan.absolute_paths());
    assert!(meta.shaping.no_anchor);
    // The D36 consent record was journaled with the channel that granted.
    let consent = meta.consent.expect("consent journaled");
    assert_eq!(
        consent.channel,
        antseal_cli::vault::store::ConsentChannel::YesFlag
    );
    assert_eq!(consent.consent_time_unix_secs, 1_800_000_000);

    let json = report.json();
    assert_eq!(json["cost_atto"], report.cost_atto.to_string());
    assert_eq!(json["unanchored"], true);
    assert_eq!(json["network"], "devnet");
}

// ─────────────────────────────────────────────────────────────────────
// U14: the gate decides whether money may move
// ─────────────────────────────────────────────────────────────────────

#[test]
fn declining_aborts_before_any_payment_and_leaves_the_work_resumable() {
    let work = Work::new("declined");
    work.file("a.txt", b"content");
    let plan = work
        .plan(&["a.txt", "--no-anchor"])
        .expect("plan validates");

    let backend = MockBackend::new().with_balances(funded());
    let vault = IsolatedVault::create("seal-declined");
    let unlocked = SealSession::open(Arc::new(vault.unlock()));

    let err = block_on(run_seal(
        &backend,
        &unlocked,
        &plan,
        &mut SaysNo,
        // Interactive: machine_mode false, no --yes, so the prompt runs
        // and answers no.
        &ctx(false),
        &mut ChaCha20Rng::from_seed([0x31; 32]),
        &mut ChaCha20Rng::from_seed([0x32; 32]),
    ))
    .expect_err("declined");
    assert_eq!(err.class(), ErrorClass::ConsentNotObtained);
    assert_eq!(err.exit_code(), 10);

    // Asserted from the backend's own call log, not from our belief:
    // nothing was paid and nothing was uploaded.
    assert_eq!(backend.calls(Method::Pay), 0, "no payment after a decline");
    assert_eq!(
        backend.calls(Method::FinalizeBatch),
        0,
        "no upload after a decline"
    );

    // D36 rule 3: declining is never abandonment — the work stays
    // incomplete and resumable.
    let store = WorkStore::new(unlocked.vault());
    let works = store.list_works().expect("list");
    assert_eq!(works.len(), 1);
    assert_eq!(
        store.load_meta(&works[0]).expect("meta").state,
        WorkState::IncompletePrePay
    );
}

#[test]
fn machine_mode_without_yes_aborts_with_the_consent_class_and_never_prompts() {
    let work = Work::new("machine");
    work.file("a.txt", b"content");
    let plan = work
        .plan(&["a.txt", "--no-anchor"])
        .expect("plan validates");

    let backend = MockBackend::new().with_balances(funded());
    let vault = IsolatedVault::create("seal-machine");
    let unlocked = SealSession::open(Arc::new(vault.unlock()));

    let err = block_on(run_seal(
        &backend,
        &unlocked,
        &plan,
        // A prompt here would be a D51 violation, and this double turns
        // it into a failure rather than a hang.
        &mut NeverAsked,
        &ctx(true),
        &mut ChaCha20Rng::from_seed([0x41; 32]),
        &mut ChaCha20Rng::from_seed([0x42; 32]),
    ))
    .expect_err("machine mode without --yes");
    assert_eq!(err.class(), ErrorClass::ConsentNotObtained);
    assert!(err.to_string().contains("--yes"), "{err}");
    assert_eq!(backend.calls(Method::Pay), 0);
}

#[test]
fn the_two_shortfalls_are_distinct_and_nothing_is_paid() {
    for (balances, class, code) in [
        (
            BalanceReport {
                wallet: EvmAddress20::from_bytes(FIXTURE_WALLET),
                ant_atto: 0,
                gas_wei: u128::from(u64::MAX),
            },
            ErrorClass::InsufficientAntToken,
            20,
        ),
        (
            BalanceReport {
                wallet: EvmAddress20::from_bytes(FIXTURE_WALLET),
                ant_atto: u128::from(u64::MAX),
                gas_wei: 0,
            },
            ErrorClass::InsufficientEthGas,
            21,
        ),
    ] {
        let work = Work::new("short");
        work.file("a.txt", b"content");
        let plan = work
            .plan(&["a.txt", "--no-anchor", "--yes"])
            .expect("plan validates");

        let backend = MockBackend::new().with_balances(balances);
        let vault = IsolatedVault::create("seal-short");
        let unlocked = SealSession::open(Arc::new(vault.unlock()));

        let err = block_on(run_seal(
            &backend,
            &unlocked,
            &plan,
            &mut NeverAsked,
            &ctx(true),
            &mut ChaCha20Rng::from_seed([0x51; 32]),
            &mut ChaCha20Rng::from_seed([0x52; 32]),
        ))
        .expect_err("shortfall");
        assert_eq!(err.class(), class);
        assert_eq!(err.exit_code(), code);
        // Both messages name required and available, and they are not the
        // same message — the user remedies them differently.
        assert!(err.to_string().contains("wallet holds"), "{err}");
        assert_eq!(backend.calls(Method::Pay), 0, "a shortfall never pays");
    }
}

// ─────────────────────────────────────────────────────────────────────
// D45: resume detection at the command layer
// ─────────────────────────────────────────────────────────────────────

/// Seal once, killing the run at the consent gate, then re-run the same
/// command: the second invocation must *resume* rather than start a
/// second work.
#[test]
fn re_running_the_same_command_resumes_rather_than_starting_a_second_work() {
    let work = Work::new("resume");
    work.file("a.txt", b"paragraph one\n\nparagraph two\n");
    let plan = work
        .plan(&["a.txt", "--no-anchor"])
        .expect("plan validates");

    let backend = MockBackend::new().with_balances(funded());
    let vault = IsolatedVault::create("seal-resume");
    let unlocked = SealSession::open(Arc::new(vault.unlock()));

    // Run 1: declined at the gate. The work is staged and resumable.
    block_on(run_seal(
        &backend,
        &unlocked,
        &plan,
        &mut SaysNo,
        &ctx(false),
        &mut ChaCha20Rng::from_seed([0x61; 32]),
        &mut ChaCha20Rng::from_seed([0x62; 32]),
    ))
    .expect_err("declined");
    let store = WorkStore::new(unlocked.vault());
    let first = store.list_works().expect("list");
    assert_eq!(first.len(), 1);

    // Run 2: the identical invocation, this time consenting.
    let plan2 = work
        .plan(&["a.txt", "--no-anchor", "--yes"])
        .expect("plan validates");
    let result = block_on(run_seal(
        &backend,
        &unlocked,
        &plan2,
        &mut NeverAsked,
        &ctx(true),
        &mut ChaCha20Rng::from_seed([0x63; 32]),
        &mut ChaCha20Rng::from_seed([0x64; 32]),
    ))
    .expect("the resume completes");
    let SealCommandResult::Sealed(report) = result else {
        panic!("expected Sealed");
    };

    assert!(report.resumed, "the second run resumed the first");
    assert_eq!(
        report.seal_id, first[0],
        "resume finishes the SAME work — a new seal_id would mean fresh \
         nonces and a second payment"
    );
    // Exactly one work in the vault, complete.
    let works = store.list_works().expect("list");
    assert_eq!(works.len(), 1, "resume never duplicates the work");
    assert_eq!(
        store.load_meta(&works[0]).expect("meta").state,
        WorkState::Complete
    );
    // `--yes` is a session flag, NOT part of the identity (D45 §1): run 2
    // added it and still matched.
}

/// D45's **one merged render**, at the case a user actually meets.
///
/// A work killed before the anchor gate still has anchoring to do, so
/// the pipeline's `ConsentRequest::resume` flag reads `false` for it —
/// which is why the gate keys the resume plan on D45's own detection
/// instead. Gating on the flag would have shown no plan at all on the
/// commonest resume there is.
#[test]
fn a_pre_pay_resume_renders_the_plan_and_the_consent_screen_in_one_pass() {
    let work = Work::new("mergedrender");
    work.file("a.txt", b"paragraph one\n\nparagraph two\n");

    let backend = MockBackend::new().with_balances(funded());
    let vault = IsolatedVault::create("seal-mergedrender");
    let unlocked = SealSession::open(Arc::new(vault.unlock()));

    // Run 1: declined at the gate, so the work is staged and pre-pay —
    // and its next resume still has the anchor step ahead of it.
    let plan = work
        .plan(&["a.txt", "--no-anchor"])
        .expect("plan validates");
    block_on(run_seal(
        &backend,
        &unlocked,
        &plan,
        &mut SaysNo,
        &ctx(false),
        &mut ChaCha20Rng::from_seed([0xD1; 32]),
        &mut ChaCha20Rng::from_seed([0xD2; 32]),
    ))
    .expect_err("declined");

    // Run 2: the same invocation, declining again — so the gate is
    // reached and its report can be inspected without paying.
    let resumed = work
        .plan(&["a.txt", "--no-anchor"])
        .expect("plan validates");
    let mut prompt = Recording::default();
    block_on(run_seal(
        &backend,
        &unlocked,
        &resumed,
        &mut prompt,
        &ctx(false),
        &mut ChaCha20Rng::from_seed([0xD3; 32]),
        &mut ChaCha20Rng::from_seed([0xD4; 32]),
    ))
    .expect_err("declined again");

    assert_eq!(
        prompt.asked, 1,
        "one gate pass, not two prompts — the resume plan and the consent \
         screen are the same render (D45)"
    );
    // The prior consent was journaled by run 1... no: run 1 declined, so
    // there is none. What must be there is the resume plan itself.
    assert_eq!(backend.calls(Method::Pay), 0);
}

/// A prompt that says no and counts how often it was asked.
#[derive(Default)]
struct Recording {
    asked: usize,
}
impl ConsentPrompt for Recording {
    fn ask(&mut self) -> Result<bool, antseal_cli::error::CliError> {
        self.asked += 1;
        Ok(false)
    }
}

#[test]
fn a_near_miss_refuses_with_its_own_class_before_anything_is_staged() {
    let work = Work::new("nearmiss");
    work.file("a.txt", b"one").file("b.txt", b"two");
    let plan = work
        .plan(&["a.txt", "b.txt", "--no-anchor"])
        .expect("plan validates");

    let backend = MockBackend::new().with_balances(funded());
    let vault = IsolatedVault::create("seal-nearmiss");
    let unlocked = SealSession::open(Arc::new(vault.unlock()));

    // Leave an incomplete work behind.
    block_on(run_seal(
        &backend,
        &unlocked,
        &plan,
        &mut SaysNo,
        &ctx(false),
        &mut ChaCha20Rng::from_seed([0x71; 32]),
        &mut ChaCha20Rng::from_seed([0x72; 32]),
    ))
    .expect_err("declined");
    let store = WorkStore::new(unlocked.vault());
    let before = store.list_works().expect("list").len();

    // Overlap, not exact: a subset of the recorded list.
    let subset = work
        .plan(&["a.txt", "--no-anchor", "--yes"])
        .expect("plan validates");
    let err = block_on(run_seal(
        &backend,
        &unlocked,
        &subset,
        &mut NeverAsked,
        &ctx(true),
        &mut ChaCha20Rng::from_seed([0x73; 32]),
        &mut ChaCha20Rng::from_seed([0x74; 32]),
    ))
    .expect_err("overlap is not a resume");
    assert_eq!(err.class(), ErrorClass::ResumeOverlapNotExact);
    assert_eq!(err.exit_code(), 25);

    // Same inputs, different shaping flags.
    let reflagged = work
        .plan(&["a.txt", "b.txt", "--no-anchor", "--force-text", "--yes"])
        .expect("plan validates");
    let err = block_on(run_seal(
        &backend,
        &unlocked,
        &reflagged,
        &mut NeverAsked,
        &ctx(true),
        &mut ChaCha20Rng::from_seed([0x75; 32]),
        &mut ChaCha20Rng::from_seed([0x76; 32]),
    ))
    .expect_err("different shaping is not a resume");
    assert_eq!(err.class(), ErrorClass::ResumeFlagMismatch);
    assert_eq!(err.exit_code(), 26);

    // Neither refusal staged anything, and neither paid.
    assert_eq!(store.list_works().expect("list").len(), before);
    assert_eq!(backend.calls(Method::Pay), 0);
}

// ─────────────────────────────────────────────────────────────────────
// The M1 gate clause: --no-anchor × arbitrum-one, at BOTH layers
// ─────────────────────────────────────────────────────────────────────

#[test]
fn no_anchor_on_arbitrum_one_is_refused_at_the_cli_layer_and_at_the_library_layer() {
    let work = Work::new("mainnet");
    work.file("a.txt", b"content");

    // Layer 1 — the CLI: plan validation refuses, whether the network
    // arrives by flag or as the built-in default.
    let cli = Cli::parse_checked(
        [
            "antseal",
            "seal",
            "a.txt",
            "--no-anchor",
            "--network",
            "arbitrum-one",
        ]
        .iter()
        .copied(),
    )
    .expect("argv parses");
    let Command::Seal(args) = &cli.command else {
        panic!("not a seal");
    };
    // The network arrives here already resolved (flag > config > default),
    // so `arbitrum-one` covers the flag spelling above AND the built-in
    // default with no flag at all — the spawned-binary test below runs
    // the flagless form against the real resolution.
    let err = build_plan(args, antseal_net::NetworkId::ArbitrumOne, &work.dir)
        .expect_err("refused at the CLI layer");
    assert_eq!(err.class(), ErrorClass::InvalidSealArgument);
    assert!(
        err.to_string()
            .contains("--no-anchor cannot be used on arbitrum-one"),
        "{err}"
    );

    // Layer 2 — the library: a caller driving the pipeline past the CLI
    // check is refused by S13's own guard, with the same words. Proven by
    // handing `run_seal` a plan whose network says mainnet — which no
    // parse can produce, precisely because layer 1 exists.
    let mut smuggled = work
        .plan(&["a.txt", "--no-anchor", "--yes"])
        .expect("a devnet plan validates");
    smuggled.network = antseal_net::NetworkId::ArbitrumOne;

    let backend = MockBackend::new().with_balances(funded());
    let vault = IsolatedVault::create("seal-mainnet");
    let unlocked = SealSession::open(Arc::new(vault.unlock()));
    let err = block_on(run_seal(
        &backend,
        &unlocked,
        &smuggled,
        &mut NeverAsked,
        &ctx(true),
        &mut ChaCha20Rng::from_seed([0x81; 32]),
        &mut ChaCha20Rng::from_seed([0x82; 32]),
    ))
    .expect_err("refused beneath the CLI too");
    assert_eq!(err.class(), ErrorClass::InvalidSealArgument);
    assert!(
        err.to_string()
            .contains("--no-anchor cannot be used on arbitrum-one"),
        "{err}"
    );
    assert_eq!(
        backend.calls(Method::QuoteBatch),
        0,
        "the mainnet guard fires before anything is even quoted"
    );
}

// ─────────────────────────────────────────────────────────────────────
// D46, through the parser, and identically under --dry-run
// ─────────────────────────────────────────────────────────────────────

#[test]
fn the_d46_matrix_refuses_identically_with_and_without_dry_run() {
    let work = Work::new("d46");
    work.file("a.txt", b"content");
    std::fs::create_dir_all(work.dir.join("sub")).expect("mk sub");

    for case in [
        vec!["sub", "--no-anchor"],
        vec!["a.txt", "a.txt", "--no-anchor"],
        vec!["a.txt", "./a.txt", "--no-anchor"],
    ] {
        let plain = work.plan(&case).expect_err("refused");
        let mut dry = case.clone();
        dry.push("--dry-run");
        let rehearsed = work.plan(&dry).expect_err("refused under --dry-run too");

        assert_eq!(plain.class(), ErrorClass::InvalidSealArgument, "{case:?}");
        assert_eq!(
            plain.to_string(),
            rehearsed.to_string(),
            "D46 must refuse identically under --dry-run (D49): {case:?}"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────
// D49: --dry-run is the pipeline truncated, with zero vault mutation
// ─────────────────────────────────────────────────────────────────────

#[test]
fn a_dry_run_quotes_reports_and_mutates_nothing() {
    let work = Work::new("dryrun");
    work.file("a.txt", b"paragraph one\n\nparagraph two\n");
    let plan = work
        .plan(&["a.txt", "--no-anchor", "--dry-run"])
        .expect("plan validates");

    let backend = MockBackend::new().with_balances(funded());
    let vault = IsolatedVault::create("seal-dryrun");
    let before = vault.fingerprint();
    let unlocked = SealSession::open(Arc::new(vault.unlock()));

    let result = block_on(run_seal(
        &backend,
        &unlocked,
        &plan,
        &mut NeverAsked,
        &ctx(true),
        &mut ChaCha20Rng::from_seed([0x91; 32]),
        &mut ChaCha20Rng::from_seed([0x92; 32]),
    ))
    .expect("the dry run completes");

    let SealCommandResult::DryRun(report) = &result else {
        panic!("--dry-run returns DryRun");
    };
    // A REAL quote over the real blob set — the whole point of D49.
    assert!(report.quote.total_ant_atto > 0);
    assert!(report.blob_count >= 2, "one file plus the manifest");
    assert!(report.dry_run, "the figure is labelled indicative");

    let rendered = result.render().join("\n");
    assert!(rendered.contains("a.txt"), "{rendered}");
    assert!(rendered.contains(PERMANENCE_WARNING), "{rendered}");
    assert!(rendered.contains("indicative"), "{rendered}");
    assert!(rendered.contains("Dry run: nothing was"), "{rendered}");
    assert_eq!(result.json()["dry_run"], true);

    // The mock saw a quote and a balance read, and nothing else.
    assert_eq!(backend.calls(Method::QuoteBatch), 1);
    assert_eq!(backend.calls(Method::Pay), 0);
    assert_eq!(backend.calls(Method::FinalizeBatch), 0);

    // Zero vault mutation, byte for byte.
    drop(unlocked);
    assert_eq!(
        before,
        vault.fingerprint(),
        "a dry run must leave the vault byte-identical (D49)"
    );
}

/// **D45 §5, and the nastiest failure this command could have.**
/// `Pipeline::resume` pays and uploads and has no dry-run parameter, so a
/// `--dry-run` that exact-matches a resumable work must never reach it.
/// This is the regression test for exactly that: found by review, and it
/// would have cost real money on a real network.
#[test]
fn a_dry_run_over_a_resumable_work_shows_the_plan_and_spends_nothing() {
    let work = Work::new("dryresume");
    work.file("a.txt", b"paragraph one\n\nparagraph two\n");

    let backend = MockBackend::new().with_balances(funded());
    let vault = IsolatedVault::create("seal-dryresume");
    let unlocked = SealSession::open(Arc::new(vault.unlock()));

    // Leave a resumable work behind (declined at the gate).
    let plan = work
        .plan(&["a.txt", "--no-anchor"])
        .expect("plan validates");
    block_on(run_seal(
        &backend,
        &unlocked,
        &plan,
        &mut SaysNo,
        &ctx(false),
        &mut ChaCha20Rng::from_seed([0xC1; 32]),
        &mut ChaCha20Rng::from_seed([0xC2; 32]),
    ))
    .expect_err("declined");
    let (staged, state_before) = {
        let store = WorkStore::new(unlocked.vault());
        let staged = store.list_works().expect("list");
        assert_eq!(staged.len(), 1);
        let state = store.load_meta(&staged[0]).expect("meta").state;
        (staged, state)
    };
    drop(unlocked);
    let fingerprint_before = vault.fingerprint();

    // Now the identical invocation with --dry-run. It exact-matches.
    let unlocked = SealSession::open(Arc::new(vault.unlock()));
    let rehearsal = work
        .plan(&["a.txt", "--no-anchor", "--dry-run", "--yes"])
        .expect("plan validates");
    let calls_before = (
        backend.calls(Method::QuoteBatch),
        backend.calls(Method::Balances),
    );
    let result = block_on(run_seal(
        &backend,
        &unlocked,
        &rehearsal,
        &mut NeverAsked,
        &ctx(true),
        &mut ChaCha20Rng::from_seed([0xC3; 32]),
        &mut ChaCha20Rng::from_seed([0xC4; 32]),
    ))
    .expect("the rehearsal succeeds");

    let SealCommandResult::ResumePlan(lines) = &result else {
        panic!("a dry run over a resumable work returns the plan, got {result:?}");
    };
    assert!(
        lines.join("\n").contains("Resuming interrupted seal"),
        "{lines:?}"
    );
    assert!(result.render().join("\n").contains("Nothing was quoted"));
    assert_eq!(result.json()["quoted"], false);

    // Zero of everything: no payment, no upload, no quote — not even a
    // balance read — and the work is exactly where it was.
    assert_eq!(backend.calls(Method::Pay), 0);
    assert_eq!(backend.calls(Method::FinalizeBatch), 0);
    assert_eq!(backend.calls(Method::QuoteBatch), calls_before.0);
    assert_eq!(backend.calls(Method::Balances), calls_before.1);
    {
        let store = WorkStore::new(unlocked.vault());
        assert_eq!(store.list_works().expect("list").len(), 1);
        assert_eq!(
            store.load_meta(&staged[0]).expect("meta").state,
            state_before
        );
    }
    drop(unlocked);
    assert_eq!(
        fingerprint_before,
        vault.fingerprint(),
        "a dry run must leave a resumable work byte-identical (D45 §5)"
    );
}

/// D49's scriptable-funding-gate row, **both** shortfalls: a dry run exits
/// with the same distinct code the real seal would use, so `--dry-run`
/// works as a preflight in a script that branches on which asset is short
/// (acquire ANT vs bridge ETH are different remedies).
#[test]
fn a_dry_run_with_a_drained_wallet_exits_with_the_real_shortfall_code() {
    let work = Work::new("dryshort");
    work.file("a.txt", b"content");
    let plan = work
        .plan(&["a.txt", "--no-anchor", "--dry-run"])
        .expect("plan validates");
    let vault = IsolatedVault::create("seal-dryshort");

    for (ant, gas, class, code) in [
        (
            0u128,
            u128::from(u64::MAX),
            ErrorClass::InsufficientAntToken,
            20,
        ),
        (
            u128::from(u64::MAX),
            0u128,
            ErrorClass::InsufficientEthGas,
            21,
        ),
    ] {
        let backend = MockBackend::new().with_balances(BalanceReport {
            wallet: EvmAddress20::from_bytes(FIXTURE_WALLET),
            ant_atto: ant,
            gas_wei: gas,
        });
        let unlocked = SealSession::open(Arc::new(vault.unlock()));
        let err = block_on(run_seal(
            &backend,
            &unlocked,
            &plan,
            &mut NeverAsked,
            &ctx(true),
            &mut ChaCha20Rng::from_seed([0xA1; 32]),
            &mut ChaCha20Rng::from_seed([0xA2; 32]),
        ))
        .expect_err("a dry run is a scriptable funding gate (D49)");
        assert_eq!(err.class(), class);
        assert_eq!(err.exit_code(), code);
        // The screen that D146 R1 now shows *before* this error is asserted
        // in `a_dry_run_shortfall_shows_the_whole_screen_before_the_typed_error`,
        // not here: `run_seal` builds its `SealConsent` as a local, so the
        // `rendered` recorder is unreachable from this call site, and no test
        // in this workspace can read the process's own streams (D146 §1.6).

        // The gate refused, and it refused *before* anything could move.
        assert_eq!(backend.calls(Method::Pay), 0);
        assert_eq!(backend.calls(Method::FinalizeBatch), 0);
    }
}

/// One quote for the two `dry_run_outcome` cases below, with the two
/// figures far apart so each shortfall amount is a distinct integer and a
/// marker cannot be mistaken for the other asset's.
fn shortfall_quote() -> CostQuote {
    CostQuote {
        blobs: Vec::new(),
        total_ant_atto: 4_200,
        gas_estimate_wei: 21_000,
    }
}

/// The `DryRunReport` `Pipeline::seal` hands the `DryRun` arm. Only
/// `quote` and `blob_count` reach the report; the other two are carried
/// because the struct has them.
fn dry_report(quote: CostQuote) -> DryRunReport {
    DryRunReport {
        quote,
        blob_count: 2,
        ciphertext_bytes: 7,
        units_per_file: vec![1],
    }
}

/// **D49 §3 / D146 R1**: a dry run that finds a shortfall shows the whole
/// rehearsal screen and *then* refuses — the order `ConsentHook::confirm`
/// uses on the real path, which the `DryRun` arm inverted from 2026-08-01
/// until D146.
///
/// Driven through `dry_run_outcome` rather than `run_seal`, because the
/// `SealConsent` `run_seal` builds is a local and unreachable from a test.
/// The instrument is `SealConsent::rendered` — the same one the real gate is
/// asserted on. **What it does not prove**: that any byte reached a file
/// descriptor. `seal` is unwired in the default build and the crate cannot
/// read its own process streams without a new dependency (U29), so the emit
/// is guaranteed by `SealConsent::show`'s body — one method both paths call,
/// which cannot record without emitting — and by nothing observable here
/// (D146 §1.6, §6).
#[test]
fn a_dry_run_shortfall_shows_the_whole_screen_before_the_typed_error() {
    let work = Work::new("dryshortscreen");
    work.file("a.txt", b"content");
    let plan = work
        .plan(&["a.txt", "--no-anchor", "--dry-run"])
        .expect("plan validates");
    let quote = shortfall_quote();
    let required_ant = quote.total_ant_atto;
    let required_gas = quote.gas_estimate_wei;
    let dry = dry_report(quote);
    let context = ctx(true);

    for (label, ant, gas, class, code) in [
        (
            "ANT short",
            1_000u128,
            u128::from(u64::MAX),
            ErrorClass::InsufficientAntToken,
            20,
        ),
        (
            "gas short",
            u128::from(u64::MAX),
            5u128,
            ErrorClass::InsufficientEthGas,
            21,
        ),
        // Both short: the error can only ever name ANT (S8's fixed order,
        // `antseal_net::preflight`), which is precisely why the screen has
        // to render.
        (
            "both short",
            1_000u128,
            5u128,
            ErrorClass::InsufficientAntToken,
            20,
        ),
    ] {
        let mut prompt = NeverAsked;
        let consent = SealConsent::new(
            &plan,
            BalanceReport {
                wallet: EvmAddress20::from_bytes(FIXTURE_WALLET),
                ant_atto: ant,
                gas_wei: gas,
            },
            Vec::new(),
            plan.yes,
            context.machine_mode,
            context.to_stderr,
            context.now_unix_secs,
            &mut prompt,
        );

        let err = dry_run_outcome(&consent, &dry, &context)
            .expect_err("a dry run is a scriptable funding gate (D49 §3)");
        assert_eq!(err.class(), class, "{label}");
        assert_eq!(err.exit_code(), code, "{label}");

        assert_eq!(
            consent.rendered.borrow().len(),
            1,
            "the dry-run shortfall screen never rendered: D49 §3 requires the complete \
             report before the typed error, and D146 §1.1 measured this path at 0 emitted \
             bytes ({label})"
        );

        // The emitted document is `SealCommandResult::DryRun`'s, not the
        // gate's: the shortfall screen must be the funded screen with
        // different numbers, trailer included (D146 §2 R1).
        let recorded = consent.rendered.borrow()[0].clone();
        let screen = SealCommandResult::DryRun(Box::new(recorded))
            .render()
            .join("\n");
        assert!(screen.contains("    a.txt  (7 bytes)"), "{label}: {screen}");
        assert!(screen.contains("Cost (indicative):"), "{label}: {screen}");
        assert!(screen.contains(PERMANENCE_WARNING), "{label}: {screen}");
        assert!(screen.contains("Dry run: nothing was"), "{label}: {screen}");

        let expected_markers = usize::from(ant < required_ant) + usize::from(gas < required_gas);
        assert_eq!(
            screen.matches("** SHORT by ").count(),
            expected_markers,
            "{label}: the screen marks every short asset independently, and that is its \
             whole advantage over the typed error, which names only the first (ANT before \
             gas). Screen:\n{screen}"
        );
        if ant < required_ant {
            assert!(
                screen.contains(&format!("** SHORT by {} **", required_ant - ant)),
                "{label}: the ANT marker is absent or carries the wrong figure:\n{screen}"
            );
        }
        if gas < required_gas {
            assert!(
                screen.contains(&format!("** SHORT by {} **", required_gas - gas)),
                "{label}: the gas marker is absent or carries the wrong figure:\n{screen}"
            );
        }
    }
}

/// **D146 R1's other half**: on the success path this arm emits nothing,
/// because the command handler renders every `Ok`. An unconditional emit —
/// the literal reading of U79's original `Do` line, which D146 overturned —
/// prints the whole rehearsal screen twice for every funded dry run.
#[test]
fn a_funded_dry_run_leaves_the_screen_to_its_caller() {
    let work = Work::new("dryfundedscreen");
    work.file("a.txt", b"content");
    let plan = work
        .plan(&["a.txt", "--no-anchor", "--dry-run"])
        .expect("plan validates");
    let dry = dry_report(shortfall_quote());
    let context = ctx(true);

    let mut prompt = NeverAsked;
    let consent = SealConsent::new(
        &plan,
        funded(),
        Vec::new(),
        plan.yes,
        context.machine_mode,
        context.to_stderr,
        context.now_unix_secs,
        &mut prompt,
    );

    let result = dry_run_outcome(&consent, &dry, &context).expect("a funded dry run succeeds");
    let SealCommandResult::DryRun(report) = &result else {
        panic!("--dry-run returns DryRun, got {result:?}");
    };
    assert!(report.dry_run, "the figure is labelled indicative (D49)");
    assert!(
        result.render().join("\n").contains("Dry run: nothing was"),
        "the caller renders this screen, trailer and all"
    );
    assert!(
        consent.rendered.borrow().is_empty(),
        "the rehearsal screen was emitted here AND by the caller: commands.rs:423-425 \
         renders every Ok, so a funded dry run would print it twice"
    );
}

/// U16 Accept row 4's first half: `--dry-run` combined with the flags that
/// would otherwise change what happens — `--yes` (which consents in
/// advance) and `--force-degraded` (which relaxes the anchor policy) —
/// still performs **no** side effects.
///
/// `--yes` is the one that matters. It is the flag that makes a real seal
/// pay without asking, so a dry run that honoured it would be a rehearsal
/// that buys the thing it was rehearsing. The prompt here is `NeverAsked`
/// and the mock's pay counter is the proof: neither the consent gate nor
/// the payment path is reached at all.
#[test]
fn a_dry_run_with_yes_and_force_degraded_still_does_nothing() {
    let work = Work::new("drycombo");
    work.file("a.txt", b"paragraph one\n\nparagraph two\n");
    let plan = work
        .plan(&[
            "a.txt",
            "--no-anchor",
            "--dry-run",
            "--yes",
            "--force-degraded",
        ])
        .expect("plan validates");
    assert!(plan.yes, "--yes parsed");
    assert!(plan.shaping.force_degraded, "--force-degraded parsed");

    let backend = MockBackend::new().with_balances(funded());
    let vault = IsolatedVault::create("seal-drycombo");
    let before = vault.fingerprint();
    let unlocked = SealSession::open(Arc::new(vault.unlock()));

    let result = block_on(run_seal(
        &backend,
        &unlocked,
        &plan,
        // A dry run must not reach the gate even with `--yes`: `--yes`
        // answers a question that is never asked here.
        &mut NeverAsked,
        &ctx(false),
        &mut ChaCha20Rng::from_seed([0xD1; 32]),
        &mut ChaCha20Rng::from_seed([0xD2; 32]),
    ))
    .expect("the dry run completes");

    let SealCommandResult::DryRun(report) = &result else {
        panic!("--dry-run returns DryRun even with --yes, got {result:?}");
    };
    // Accept row 3's contents, on the flag combination as well: files,
    // byte totals, and the cost carrying D49's indicative label.
    let rendered = result.render().join("\n");
    assert!(
        rendered.contains("Sealing 1 file(s), 29 byte(s)"),
        "{rendered}"
    );
    assert!(rendered.contains("a.txt  (29 bytes)"), "{rendered}");
    assert!(rendered.contains("Cost (indicative):"), "{rendered}");
    assert!(report.dry_run);

    assert_eq!(backend.calls(Method::QuoteBatch), 1);
    assert_eq!(backend.calls(Method::Pay), 0);
    assert_eq!(backend.calls(Method::FinalizeBatch), 0);

    // No work record was created — `--yes` did not turn the rehearsal into
    // a seal, and the vault is byte-identical.
    assert_eq!(
        WorkStore::new(unlocked.vault())
            .list_works()
            .expect("list")
            .len(),
        0
    );
    drop(unlocked);
    assert_eq!(
        before,
        vault.fingerprint(),
        "--dry-run --yes --force-degraded must still leave the vault untouched (D49)"
    );
}

// ─────────────────────────────────────────────────────────────────────
// U18: the first-seal export nag, and the double nag it carries
// ─────────────────────────────────────────────────────────────────────

/// U18 Accept row 1: a first seal in a vault with no recorded export
/// nags; after `vault export` records one, later seals do not.
///
/// The nag is read from the U34 bookkeeping record rather than inferred,
/// which is what makes the second half true at all — before that slot
/// existed the only honest options were "nag forever" or "never nag".
#[test]
fn the_first_seal_nags_about_the_missing_backup_and_a_recorded_export_stops_it() {
    let work = Work::new("nag");
    work.file("a.txt", b"content").file("b.txt", b"more");
    let backend = MockBackend::new().with_balances(funded());
    let vault = IsolatedVault::create("seal-nag");
    let unlocked = SealSession::open(Arc::new(vault.unlock()));

    let first = work
        .plan(&["a.txt", "--no-anchor", "--yes"])
        .expect("plan validates");
    let result = block_on(run_seal(
        &backend,
        &unlocked,
        &first,
        &mut NeverAsked,
        &ctx(true),
        &mut ChaCha20Rng::from_seed([0x71; 32]),
        &mut ChaCha20Rng::from_seed([0x72; 32]),
    ))
    .expect("the seal completes");
    let SealCommandResult::Sealed(report) = result else {
        panic!("expected a completed seal");
    };
    assert!(report.export_nag, "no export recorded yet");

    // Both failure modes, in the words `init` already used (one author).
    let rendered = report.render().join("\n");
    assert!(rendered.contains("NO BACKUP YET"), "{rendered}");
    assert!(rendered.contains("antseal vault export"), "{rendered}");
    assert!(rendered.contains(LOSS_WARNING), "{rendered}");
    assert!(rendered.contains(THEFT_WARNING), "{rendered}");
    assert!(rendered.contains("LOSS"), "{rendered}");
    assert!(rendered.contains("THEFT"), "{rendered}");
    assert!(
        rendered.contains("retroactively and permanently"),
        "{rendered}"
    );
    // U31 positioning: a backup warning makes no legal claim.
    let lower = rendered.to_lowercase();
    assert!(!lower.contains("notary"), "{rendered}");
    assert!(!lower.contains("priority"), "{rendered}");
    // Machine consumers see it too (a scripted seal never reads stderr).
    assert_eq!(report.json()["export_nag"], true);

    // The nag is the same copy `init` closes with — asserted against the
    // real producer, not a hand-copied string.
    let init_copy = antseal_cli::init::standing_warnings(false).join("\n");
    assert!(init_copy.contains(LOSS_WARNING));
    assert!(init_copy.contains(THEFT_WARNING));

    // Record an export, then seal again: silence.
    bookkeeping::record_export(
        unlocked.vault(),
        1_800_000_000,
        &mut ChaCha20Rng::from_seed([0x73; 32]),
    )
    .expect("record the export");
    let second = work
        .plan(&["b.txt", "--no-anchor", "--yes"])
        .expect("plan validates");
    let result = block_on(run_seal(
        &backend,
        &unlocked,
        &second,
        &mut NeverAsked,
        &ctx(true),
        &mut ChaCha20Rng::from_seed([0x74; 32]),
        &mut ChaCha20Rng::from_seed([0x75; 32]),
    ))
    .expect("the seal completes");
    let SealCommandResult::Sealed(report) = result else {
        panic!("expected a completed seal");
    };
    assert!(!report.export_nag, "the backup is recorded; stop nagging");
    let rendered = report.render().join("\n");
    assert!(!rendered.contains("NO BACKUP YET"), "{rendered}");
    assert!(!rendered.contains("LOSS"), "{rendered}");
    assert_eq!(report.json()["export_nag"], false);
}

// ─────────────────────────────────────────────────────────────────────
// U17: user-initiated abandonment, and the loud safety aborts
// ─────────────────────────────────────────────────────────────────────

/// Leave one declined (pre-pay, staged) work behind and hand back its
/// vault. The decline is D36 rule 3's "incomplete, never abandoned"
/// outcome — the exact state a user-initiated abandon has to act on.
fn vault_with_a_declined_work(tag: &str) -> (IsolatedVault, Work, SealId) {
    let work = Work::new(tag);
    work.file("a.txt", b"paragraph one\n\nparagraph two\n");
    let plan = work
        .plan(&["a.txt", "--no-anchor"])
        .expect("plan validates");
    let backend = MockBackend::new().with_balances(funded());
    let vault = IsolatedVault::create(tag);
    let unlocked = SealSession::open(Arc::new(vault.unlock()));
    block_on(run_seal(
        &backend,
        &unlocked,
        &plan,
        &mut SaysNo,
        &ctx(false),
        &mut ChaCha20Rng::from_seed([0x61; 32]),
        &mut ChaCha20Rng::from_seed([0x62; 32]),
    ))
    .expect_err("declined");
    let seal_id = WorkStore::new(unlocked.vault()).list_works().expect("list")[0];
    drop(unlocked);
    (vault, work, seal_id)
}

/// U17 Accept row 3's second half: declining leaves the work resumable
/// (asserted above), while the **explicit** abandonment marks it
/// abandoned — two different outcomes from two different acts, which is
/// exactly why abandonment may never be a side effect of a decline.
#[test]
fn the_explicit_abandonment_marks_the_work_and_it_stops_being_a_resume_candidate() {
    let (vault, work, seal_id) = vault_with_a_declined_work("abandon");
    let unlocked = vault.unlock();
    let store = WorkStore::new(&unlocked);

    // Before: D45 matches it, so the re-run with different flags is the
    // trap this action exists to open.
    let trapped = work
        .plan(&["a.txt", "--no-anchor", "--split", "blank-lines"])
        .expect("plan validates");
    let err = detect(
        &store,
        antseal_net::NetworkId::Devnet,
        &trapped.absolute_paths(),
        &trapped.shaping,
    )
    .expect_err("D45 refuses an inexact re-run");
    assert_eq!(err.class(), ErrorClass::ResumeFlagMismatch);

    let report = {
        let mut rng = ChaCha20Rng::from_seed([0x63; 32]);
        let journal = VaultJournal::new(WorkStore::new(&unlocked), &mut rng);
        abandon_pre_pay(&store, &journal, &seal_id).expect("a pre-pay work is abandonable")
    };
    assert!(!report.already);
    assert_eq!(report.seal_id, seal_id);
    let rendered = report.render().join("\n");
    assert!(
        rendered.contains("Abandoned the interrupted seal"),
        "{rendered}"
    );
    // The copy states what a fresh seal will and will not reuse.
    assert!(rendered.contains("new seal_id"), "{rendered}");
    assert!(rendered.contains("freshly drawn nonces"), "{rendered}");

    // U17 Accept row 5: marked in the record store…
    assert_eq!(
        store.load_meta(&seal_id).expect("meta").state,
        WorkState::Abandoned
    );
    // …and shown by `list` as abandoned.
    let listing = WorkListing::gather(&store).expect("listing");
    let text = listing.render().join("\n");
    assert!(text.contains("abandoned"), "{text}");
    assert_eq!(listing.json()["counts"]["abandoned"], 1);

    // After: the trap is open — the same invocation now runs fresh,
    // because an abandoned work is never a resume candidate (D45 §2).
    let decision = detect(
        &store,
        antseal_net::NetworkId::Devnet,
        &trapped.absolute_paths(),
        &trapped.shaping,
    )
    .expect("the abandoned work no longer matches anything");
    assert!(matches!(decision, ResumeDecision::Fresh { .. }));

    // Idempotent: a script that re-runs the abandon must not fail.
    let again = {
        let mut rng = ChaCha20Rng::from_seed([0x64; 32]);
        let journal = VaultJournal::new(WorkStore::new(&unlocked), &mut rng);
        abandon_pre_pay(&store, &journal, &seal_id).expect("already abandoned is an outcome")
    };
    assert!(again.already);
    assert!(again.render().join("\n").contains("already abandoned"));
}

/// The rule that matters most: **a paid work is never abandoned on
/// request**, and the authority is the journaled receipt rather than the
/// state tag (S16 found a real double-payment defect that came from
/// trusting the tag).
#[test]
fn a_paid_work_is_refused_and_the_receipt_is_the_authority_not_the_tag() {
    let (vault, _work, seal_id) = vault_with_a_declined_work("abandon-paid");
    let unlocked = vault.unlock();
    let store = WorkStore::new(&unlocked);

    // Journal a receipt while the COARSE tag still reads pre-pay — the
    // exact D37 window S16 exposed. The tag says "safe to discard"; the
    // receipt says money moved. The receipt must win.
    assert_eq!(
        store.load_meta(&seal_id).expect("meta").state,
        WorkState::IncompletePrePay
    );
    {
        let mut rng = ChaCha20Rng::from_seed([0x65; 32]);
        let journal = VaultJournal::new(WorkStore::new(&unlocked), &mut rng);
        journal
            .put_receipt(&seal_id, &fixture_receipt())
            .expect("journal a receipt");
    }

    let mut rng = ChaCha20Rng::from_seed([0x66; 32]);
    let journal = VaultJournal::new(WorkStore::new(&unlocked), &mut rng);
    let err = abandon_pre_pay(&store, &journal, &seal_id)
        .expect_err("a paid work is never abandoned on request");
    assert_eq!(err.class(), ErrorClass::Usage);
    let rendered = err.to_string();
    assert!(
        rendered.starts_with("usage error: a payment is recorded for work "),
        "{rendered}"
    );
    assert!(
        rendered.contains("would give that payment up for good"),
        "{rendered}"
    );
    // It offers the real way forward: finish it, buying only what the
    // receipt does not cover — true of a partly paid work too (D203 M6c,
    // D210 R3).
    assert!(
        rendered.contains("pays only for what the receipt does not cover"),
        "{rendered}"
    );
    assert!(rendered.contains("antseal seal a.txt"), "{rendered}");

    // Nothing was written: the work is still exactly where it was.
    assert_eq!(
        store.load_meta(&seal_id).expect("meta").state,
        WorkState::IncompletePrePay
    );
}

/// A finished work has nothing to abandon: its ciphertexts are permanent,
/// and discarding the record would destroy only the keys that read them.
#[test]
fn a_complete_work_is_refused_because_abandoning_it_would_only_lose_the_keys() {
    let work = Work::new("abandon-complete");
    work.file("a.txt", b"content");
    let plan = work
        .plan(&["a.txt", "--no-anchor", "--yes"])
        .expect("plan validates");
    let backend = MockBackend::new().with_balances(funded());
    let vault = IsolatedVault::create("abandon-complete");
    let unlocked = SealSession::open(Arc::new(vault.unlock()));
    let result = block_on(run_seal(
        &backend,
        &unlocked,
        &plan,
        &mut NeverAsked,
        &ctx(true),
        &mut ChaCha20Rng::from_seed([0x67; 32]),
        &mut ChaCha20Rng::from_seed([0x68; 32]),
    ))
    .expect("the seal completes");
    let SealCommandResult::Sealed(report) = result else {
        panic!("expected a completed seal");
    };

    let store = WorkStore::new(unlocked.vault());
    let mut rng = ChaCha20Rng::from_seed([0x69; 32]);
    let journal = VaultJournal::new(WorkStore::new(unlocked.vault()), &mut rng);
    let err = abandon_pre_pay(&store, &journal, &report.seal_id).expect_err("complete is terminal");
    assert_eq!(err.class(), ErrorClass::Usage);
    assert!(err.to_string().contains("is complete"), "{err}");
    assert_eq!(
        store.load_meta(&report.seal_id).expect("meta").state,
        WorkState::Complete
    );
}

// ─────────────────────────────────────────────────────────────────────
// U41 (D185): `antseal abandon`, the surface over U17's engine
// ─────────────────────────────────────────────────────────────────────

/// The 32-hex seal-id every resume message prints — the form
/// `antseal abandon` takes.
fn seal_hex(seal_id: &SealId) -> String {
    seal_id
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// `--yes` as a script passes it: machine mode, confirmed in advance.
const SCRIPTED: AbandonConfirm = AbandonConfirm {
    yes: true,
    machine_mode: true,
};

/// An abandon confirmation that must never be asked.
fn never_asked(question: &str) -> Result<bool, antseal_cli::error::CliError> {
    panic!("the abandon confirmation was asked where it must not be: {question}");
}

/// **U41 Accept 1, end to end (D185 §3 test 1).** The flag-mismatch trap
/// names the command that exits it, and running that command lets the
/// refused invocation proceed: `run_seal` refuses with 26 naming
/// `antseal abandon <seal-id>`; the abandon command's library half runs with
/// `--yes`; the refused invocation then runs `Fresh` and seals.
#[test]
fn the_flag_mismatch_trap_names_abandon_and_the_refused_invocation_then_seals() {
    let (vault, work, seal_id) = vault_with_a_declined_work("u41-trap");
    let session = SealSession::open(Arc::new(vault.unlock()));
    let store = WorkStore::new(session.vault());
    let backend = MockBackend::new().with_balances(funded());
    let refused = work
        .plan(&["a.txt", "--no-anchor", "--split", "blank-lines", "--yes"])
        .expect("plan validates");

    // T1, through the real command path.
    let err = block_on(run_seal(
        &backend,
        &session,
        &refused,
        &mut NeverAsked,
        &ctx(true),
        &mut ChaCha20Rng::from_seed([0x41; 32]),
        &mut ChaCha20Rng::from_seed([0x42; 32]),
    ))
    .expect_err("D45 refuses the same paths with different flags");
    assert_eq!(err.class(), ErrorClass::ResumeFlagMismatch);
    assert_eq!(err.exit_code(), 26);
    let command = format!("antseal abandon {}", seal_hex(&seal_id));
    let text = err.to_string();
    assert!(
        text.contains(&command),
        "the trap must name `{command}`:\n{text}"
    );
    assert_eq!(backend.calls(Method::Pay), 0, "the trap pays nothing");

    // The command it names, as `antseal abandon <seal-id> --yes` runs it.
    let mut shown = Vec::new();
    let report = {
        let mut rng = ChaCha20Rng::from_seed([0x43; 32]);
        let journal = VaultJournal::new(WorkStore::new(session.vault()), &mut rng);
        run_abandon(
            &store,
            &journal,
            &seal_hex(&seal_id),
            SCRIPTED,
            |line| shown.push(line.to_owned()),
            never_asked,
        )
        .expect("an unpaid work is abandoned")
    };
    assert!(!report.already);
    assert_eq!(report.seal_id, seal_id);
    // D51 invariant 1: what will be discarded printed although nothing was
    // asked.
    assert_eq!(shown.len(), 6, "{shown:?}");
    assert_eq!(shown[0], format!("Interrupted seal {}", seal_hex(&seal_id)));
    assert_eq!(shown[4], "  progress: staged; not paid", "{shown:?}");
    assert_eq!(shown[5], "  anchors:  none recorded", "{shown:?}");
    assert_eq!(
        store.load_meta(&seal_id).expect("meta").state,
        WorkState::Abandoned
    );
    assert_eq!(report.json()["seal_id"], seal_hex(&seal_id));
    assert_eq!(report.json()["already"], false);
    assert_eq!(report.json()["previous_state"], "staged");

    // The refused invocation again: nothing matches it now, so it runs
    // fresh and seals — a new seal_id, not a resume.
    let decision = detect(
        &store,
        antseal_net::NetworkId::Devnet,
        &refused.absolute_paths(),
        &refused.shaping,
    )
    .expect("no D45 refusal any more");
    assert_eq!(
        decision,
        ResumeDecision::Fresh {
            incomplete_works: 0
        }
    );
    let result = block_on(run_seal(
        &backend,
        &session,
        &refused,
        &mut NeverAsked,
        &ctx(true),
        &mut ChaCha20Rng::from_seed([0x44; 32]),
        &mut ChaCha20Rng::from_seed([0x45; 32]),
    ))
    .expect("the once-refused invocation seals");
    let SealCommandResult::Sealed(sealed) = result else {
        panic!("expected a completed seal");
    };
    assert!(!sealed.resumed, "a fresh seal, not a resume");
    assert!(sealed.paid_here);
    assert_ne!(sealed.seal_id, seal_id);
    assert_eq!(
        store.load_meta(&sealed.seal_id).expect("meta").state,
        WorkState::Complete
    );

    // Re-running the same abandon is an outcome rather than a failure, and
    // it asks nothing — even in machine mode without `--yes` — because
    // nothing is discarded.
    let mut rng = ChaCha20Rng::from_seed([0x46; 32]);
    let journal = VaultJournal::new(WorkStore::new(session.vault()), &mut rng);
    let again = run_abandon(
        &store,
        &journal,
        &seal_hex(&seal_id),
        AbandonConfirm {
            yes: false,
            machine_mode: true,
        },
        |line| panic!("an abandoned work has nothing to preview: {line}"),
        never_asked,
    )
    .expect("already abandoned is an outcome");
    assert!(again.already);
}

/// **S45 (D197 R2, R3), window 2 — watched red first** (the red baseline was
/// D185 R6's usage text, exit 2, which D197 R7 retires). A seal killed
/// between `begin` and the plan write: its exact re-run used to end on every
/// run in a usage error naming `antseal abandon`, three commands to undo a
/// Ctrl-C. It now abandons the interrupted work itself and seals the same
/// files afresh, under one invocation.
///
/// One unit blob is staged before the "kill", the reachable shape:
/// `pipeline/seal.rs` journals each unit as it is encrypted, before the plan
/// is written. Window 1 — the kill inside `begin` itself — is
/// `a_seal_killed_inside_begin_is_abandoned_and_sealed_afresh`, at the end of
/// this file with the rest of S45's rows and the shared planting helper.
#[test]
fn a_seal_interrupted_before_its_staging_finished_is_abandoned_and_sealed_afresh() {
    let work = Work::new("s45-window2");
    work.file("a.txt", b"paragraph one\n\nparagraph two\n");
    let plan = work
        .plan(&["a.txt", "--no-anchor", "--yes"])
        .expect("plan validates");
    let vault = IsolatedVault::create("s45-window2");
    let session = SealSession::open(Arc::new(vault.unlock()));
    let stale = plant_interrupted_seal(&session, &plan, 0xD3, StagingWindow::MidStaging);
    assert_the_exact_rerun_seals_afresh(&session, &plan, stale);
}

/// **U41 Accept 2 (D185 §3 test 3).** A paid work is refused **through the
/// surface**, not only through the engine: `usage` (2), the engine's own
/// sentence, nothing previewed or asked, and the vault byte-identical.
#[test]
fn a_paid_work_is_refused_through_the_abandon_surface_and_nothing_changes() {
    let (vault, _work, seal_id) = vault_with_a_declined_work("u41-paid");
    {
        let unlocked = vault.unlock();
        let mut rng = ChaCha20Rng::from_seed([0x4D; 32]);
        let journal = VaultJournal::new(WorkStore::new(&unlocked), &mut rng);
        journal
            .put_receipt(&seal_id, &fixture_receipt())
            .expect("journal a receipt");
    }
    let before = vault.fingerprint();
    assert!(before.len() > 3, "the fingerprint sees the vault's files");
    {
        let unlocked = vault.unlock();
        let store = WorkStore::new(&unlocked);
        let mut rng = ChaCha20Rng::from_seed([0x4E; 32]);
        let journal = VaultJournal::new(WorkStore::new(&unlocked), &mut rng);
        let err = run_abandon(
            &store,
            &journal,
            &seal_hex(&seal_id),
            SCRIPTED,
            |line| panic!("a paid work has nothing to preview: {line}"),
            never_asked,
        )
        .expect_err("a paid work is never abandoned on request");
        assert_eq!(err.class(), ErrorClass::Usage);
        assert_eq!(err.exit_code(), 2);
        let text = err.to_string();
        assert!(text.contains("a payment is recorded for work"), "{text}");
        assert!(
            text.contains("antseal seal a.txt"),
            "the refusal names the command that finishes it: {text}"
        );
        assert_eq!(
            store.load_meta(&seal_id).expect("meta").state,
            WorkState::IncompletePrePay
        );
    }
    assert_eq!(vault.fingerprint(), before, "nothing was written");
}

/// **D185 R4 (§3 test 4).** Without `--yes`, machine mode never prompts: the
/// D51 consent class (10), the preview still printed, and the vault
/// byte-identical. An interactive "no" is the same class with its own
/// message, after R4's question, verbatim.
#[test]
fn abandon_without_yes_in_machine_mode_is_consent_not_obtained_and_writes_nothing() {
    let (vault, _work, seal_id) = vault_with_a_declined_work("u41-noyes");
    let before = vault.fingerprint();
    assert!(before.len() > 3, "the fingerprint sees the vault's files");
    {
        let unlocked = vault.unlock();
        let store = WorkStore::new(&unlocked);
        let mut rng = ChaCha20Rng::from_seed([0x4F; 32]);
        let journal = VaultJournal::new(WorkStore::new(&unlocked), &mut rng);

        let mut shown = Vec::new();
        let err = run_abandon(
            &store,
            &journal,
            &seal_hex(&seal_id),
            AbandonConfirm {
                yes: false,
                machine_mode: true,
            },
            |line| shown.push(line.to_owned()),
            never_asked,
        )
        .expect_err("machine mode never prompts");
        assert_eq!(err.class(), ErrorClass::ConsentNotObtained);
        assert_eq!(err.exit_code(), 10);
        assert_eq!(
            err.to_string(),
            "abandoning requires confirmation: machine mode (--json, non-TTY stdin, or \
             --passphrase-fd 0) never prompts — pass --yes to confirm in advance; nothing was \
             changed"
        );
        assert_eq!(shown.len(), 6, "the preview printed: {shown:?}");

        let mut asked = Vec::new();
        let err = run_abandon(
            &store,
            &journal,
            &seal_hex(&seal_id),
            AbandonConfirm {
                yes: false,
                machine_mode: false,
            },
            |_| {},
            |question: &str| {
                asked.push(question.to_owned());
                Ok(false)
            },
        )
        .expect_err("declined");
        assert_eq!(err.class(), ErrorClass::ConsentNotObtained);
        assert_eq!(
            err.to_string(),
            "abandon declined: nothing was changed, and the interrupted seal is still in the vault"
        );
        assert_eq!(
            asked,
            vec![format!(
                "Abandon interrupted seal {}? No payment is recorded for it; the staged work \
                 can no longer be used. [y/N] ",
                seal_hex(&seal_id)
            )]
        );
        assert_eq!(
            store.load_meta(&seal_id).expect("meta").state,
            WorkState::IncompletePrePay
        );
    }
    assert_eq!(vault.fingerprint(), before, "nothing was written");
}

/// **D185 R4's anchors clause, measured from the slots (§3 test 4b).** The
/// question names the anchors only when the vault holds some: the pipeline
/// writes the `Anchored` tag after the anchor step even when `--no-anchor`
/// skipped it, so an `Anchored` work with no slots gets no anchors clause,
/// and one with a recorded slot does.
#[test]
fn the_anchors_clause_follows_the_recorded_anchors_not_the_tag() {
    use antseal_cli::pipeline::SealState;
    use antseal_cli::seal_resume::AbandonPreview;

    let (vault, _work, seal_id) = vault_with_a_declined_work("u41-anchors");
    let unlocked = vault.unlock();
    let store = WorkStore::new(&unlocked);
    let mut rng = ChaCha20Rng::from_seed([0x50; 32]);
    let journal = VaultJournal::new(WorkStore::new(&unlocked), &mut rng);
    journal
        .set_state(&seal_id, SealState::Anchored)
        .expect("Staged → Anchored");

    // `--no-anchor`'s shape: the tag says Anchored, no slot exists.
    let preview = AbandonPreview::read(&store, &journal, &seal_id)
        .expect("read")
        .expect("an unpaid work has a preview");
    assert!(!preview.anchored());
    assert_eq!(
        preview.question(),
        format!(
            "Abandon interrupted seal {}? No payment is recorded for it; the staged work can \
             no longer be used. [y/N] ",
            seal_hex(&seal_id)
        )
    );
    let lines = preview.render();
    assert_eq!(
        lines[4],
        "  progress: staged and past its anchor step; not paid"
    );
    assert_eq!(lines[5], "  anchors:  none recorded");

    // One recorded anchor: now the clause, and the count.
    let mut slot_rng = ChaCha20Rng::from_seed([0x51; 32]);
    store
        .put_anchor(&seal_id, "tsa-0", b"opaque fixture token", &mut slot_rng)
        .expect("record one anchor slot");
    let preview = AbandonPreview::read(&store, &journal, &seal_id)
        .expect("read")
        .expect("an unpaid work has a preview");
    assert!(preview.anchored());
    assert_eq!(
        preview.question(),
        format!(
            "Abandon interrupted seal {}? No payment is recorded for it; the staged work, and \
             the anchors already obtained for it, can no longer be used. [y/N] ",
            seal_hex(&seal_id)
        )
    );
    assert_eq!(
        preview.render()[5],
        "  anchors:  1 recorded, and they cannot be carried over to a new seal"
    );
}

/// **D185 R2 (§3 test 5).** Both id forms resolve to the same work — the
/// seal-id (32 hex, upper case accepted) and the work-id (64 hex) — and
/// anything else is `usage` (2) naming the two forms: a 40-hex string, a
/// prefix, and a well-formed id no work carries. A complete work resolves,
/// and is then refused in the engine's own words, through the surface.
#[test]
fn both_id_forms_resolve_and_anything_else_is_usage_naming_both() {
    let work = Work::new("u41-ids");
    work.file("a.txt", b"content");
    let plan = work
        .plan(&["a.txt", "--no-anchor", "--yes"])
        .expect("plan validates");
    let backend = MockBackend::new().with_balances(funded());
    let vault = IsolatedVault::create("u41-ids");
    let session = SealSession::open(Arc::new(vault.unlock()));
    let result = block_on(run_seal(
        &backend,
        &session,
        &plan,
        &mut NeverAsked,
        &ctx(true),
        &mut ChaCha20Rng::from_seed([0x52; 32]),
        &mut ChaCha20Rng::from_seed([0x53; 32]),
    ))
    .expect("the seal completes");
    let SealCommandResult::Sealed(report) = result else {
        panic!("expected a completed seal");
    };
    let store = WorkStore::new(session.vault());
    let seal = seal_hex(&report.seal_id);
    let work_hex: String = report.work_id.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!((seal.len(), work_hex.len()), (32, 64));

    for given in [seal.clone(), seal.to_uppercase(), work_hex.clone()] {
        assert_eq!(
            resolve_abandon_id(&store, &given).expect("resolves"),
            report.seal_id,
            "{given}"
        );
    }

    let unknown_seal = "0".repeat(32);
    for (given, needle) in [
        ("ab".repeat(20), "is neither a seal id nor a work id"),
        (seal[..31].to_owned(), "is neither a seal id nor a work id"),
        (
            work_hex[..63].to_owned(),
            "is neither a seal id nor a work id",
        ),
        (unknown_seal, "no work in this vault has the seal id"),
        ("w1".to_owned(), "is neither a seal id nor a work id"),
    ] {
        let err = resolve_abandon_id(&store, &given).expect_err("refused");
        assert_eq!(err.class(), ErrorClass::Usage, "{given}");
        let text = err.to_string();
        assert!(text.contains(needle), "{given}: {text}");
        assert!(
            text.contains("(32 hexadecimal characters)")
                && text.contains("(64 hexadecimal characters)"),
            "{given}: the refusal names both forms: {text}"
        );
    }

    // A complete work: resolved, then refused by the engine, nothing asked.
    let mut rng = ChaCha20Rng::from_seed([0x54; 32]);
    let journal = VaultJournal::new(WorkStore::new(session.vault()), &mut rng);
    let err = run_abandon(
        &store,
        &journal,
        &work_hex,
        SCRIPTED,
        |line| panic!("a complete work has nothing to preview: {line}"),
        never_asked,
    )
    .expect_err("complete is terminal");
    assert_eq!(err.class(), ErrorClass::Usage);
    assert!(err.to_string().contains("is complete"), "{err}");
    assert_eq!(
        store.load_meta(&report.seal_id).expect("meta").state,
        WorkState::Complete
    );
}

/// U17's loud safety abort: one exit code, and a message stating the rule
/// it is enforcing.
///
/// There is one reason, not two: U42 (D187 R3) removed `SourceChanged`. A
/// changed source is not an abort — resume never opens a source file, so it
/// resumes from the staged bytes (S18 case (3), D45 §4) — and the removed
/// reason's frozen text said the opposite. The reason enum stays an enum,
/// so a future reason is additive.
#[test]
fn the_resume_safety_abort_says_what_it_protects() {
    use antseal_cli::error::{CliError, ResumeSafetyReason};

    let missing = CliError::ResumeSafetyAbort {
        reason: ResumeSafetyReason::StagedBytesMissing,
    };

    // One class, one exit code (U2's table).
    assert_eq!(missing.class(), ErrorClass::ResumeSafetyAbort);
    assert_eq!(missing.exit_code(), 24);

    // Missing staged bytes: names the forbidden operation, states the
    // forfeiture as a deliberate choice, and names the fresh seal's new
    // seal_id + fresh nonces (U17's copy).
    let text = missing.to_string();
    assert!(text.contains("never re-encrypts"), "{text}");
    assert!(text.contains("abandoned"), "{text}");
    assert!(text.contains("forfeited"), "{text}");
    assert!(text.contains("safety-over-cost"), "{text}");
    assert!(text.contains("NEW seal_id"), "{text}");
    assert!(text.contains("freshly generated nonces"), "{text}");
    assert!(text.contains("(k_u, nonce)"), "{text}");
}

// ─────────────────────────────────────────────────────────────────────
// U15: the three warning moments, in the pre-consent flow
// ─────────────────────────────────────────────────────────────────────

/// U15 + U16 Accept row 3's warnings clause, over the real command.
///
/// The mock-ordering claim is the point: the warnings appear on the screen
/// the gate renders **before** it asks, and here the gate is never asked
/// at all (dry run) and nothing is paid — so a user reading them has not
/// yet spent anything and can still change the flags.
#[test]
fn the_seal_warnings_reach_the_pre_consent_screen_and_the_json_document() {
    let work = Work::new("warnings");
    // Exactly `FINE_TREE_ESTIMATE_THRESHOLD_BYTES` — the estimate line's
    // trigger, and (deliberately) a quarter of the 4 MiB per-blob cap, so
    // this is a real sealable single-unit binary file rather than a size
    // the pipeline would refuse.
    let big = vec![0u8; usize::try_from(FINE_TREE_ESTIMATE_THRESHOLD_BYTES).expect("fits")];
    work.file("notes.txt", b"hello world\n")
        .file("scan.tiff", &big)
        // The opted-out file is small: what is being asserted about it is
        // that it gets NO cost line, which its size cannot influence.
        .file("blob.bin", &[0x7Fu8; 64]);

    let plan = work
        .plan(&[
            "notes.txt",
            "scan.tiff",
            "blob.bin",
            "--title",
            "Q3 layoffs",
            "--no-fine-tree",
            "*.bin",
            "--no-anchor",
            "--dry-run",
        ])
        .expect("plan validates");

    let backend = MockBackend::new().with_balances(funded());
    let vault = IsolatedVault::create("seal-warnings");
    let unlocked = SealSession::open(Arc::new(vault.unlock()));
    let result = block_on(run_seal(
        &backend,
        &unlocked,
        &plan,
        &mut NeverAsked,
        &ctx(true),
        &mut ChaCha20Rng::from_seed([0x51; 32]),
        &mut ChaCha20Rng::from_seed([0x52; 32]),
    ))
    .expect("the rehearsal completes");

    let rendered = result.render().join("\n");
    // 1. Title visibility — the title is in the plaintext manifest every
    //    bundle carries (MVP-SPEC.md line 34).
    assert!(rendered.contains("PLAINTEXT"), "{rendered}");
    assert!(rendered.contains("\"Q3 layoffs\""), "{rendered}");
    // 2. `--no-fine-tree` permanence, naming the matched file.
    assert!(
        rendered.contains("--no-fine-tree matched 1 file(s)"),
        "{rendered}"
    );
    assert!(rendered.contains("blob.bin"), "{rendered}");
    assert!(rendered.contains("PERMANENTLY"), "{rendered}");
    // 3. The fine-tree cost estimate — for the large file that HAS a fine
    //    tree, and not for the one the pattern opted out of.
    assert!(
        rendered.contains("Note: building the byte-range (fine) tree for scan.tiff"),
        "{rendered}"
    );
    assert!(
        !rendered.contains("fine) tree for blob.bin"),
        "an opted-out file has no fine tree, so it has no fine-tree cost: {rendered}"
    );
    assert!(rendered.contains("SHA-256 compressions"), "{rendered}");
    // …and small files stay quiet.
    assert!(!rendered.contains("fine) tree for notes.txt"), "{rendered}");

    // Ordering: all three land above the price (the pre-consent flow).
    let cost_at = rendered.find("Cost (indicative):").expect("cost line");
    for needle in ["PLAINTEXT", "--no-fine-tree matched", "Note: building"] {
        assert!(
            rendered.find(needle).expect(needle) < cost_at,
            "{needle} must precede the quote"
        );
    }

    // The machine document carries them as data, so a script can gate on
    // "did this seal disclose a title / lose reveal granularity?".
    let warnings = result.json()["warnings"]
        .as_array()
        .expect("the dry-run document carries a warnings array")
        .clone();
    assert_eq!(warnings.len(), 3, "{warnings:#?}");

    // Nothing moved: the warnings are advice given before the decision.
    assert_eq!(backend.calls(Method::Pay), 0);
    assert_eq!(backend.calls(Method::FinalizeBatch), 0);
}

// ─────────────────────────────────────────────────────────────────────
// The spawned binary: the surface a user actually meets
// ─────────────────────────────────────────────────────────────────────

fn antseal_bin() -> std::process::Command {
    let mut cmd = spawn::antseal();
    cmd.env_remove("RUST_LOG");
    cmd
}

/// U73: what a `seal` plan that *passes* validation meets next, into a
/// vault-less `HOME` — this build's exit code, and a substring its stderr
/// must carry.
///
/// The id is written **bare** on purpose, here and on `commands::seal`.
/// U73 is above domain U's ceiling in TODO.md's register (72) at the time
/// this landed, and `check-traceability.py --task-citations` fails a
/// *marked* citation of an unallocated id. Bare is its documented tier-2
/// blind spot and it is not a way of hiding: the moment the registrar
/// allocates the row, the ceiling advances and every one of these drops
/// into tier 1, where bare citations are checked like any other. Mark them
/// if you like once the row exists.
///
/// # The disagreement this settles
///
/// The two spawned-binary assertions below hard-coded the default build's
/// answer (exit 23, the word `ant-backend`). Under `--features ant-backend`
/// both failed with exit 2, because `commands::seal_over_backend`'s
/// feature-ON arm opens the vault first and this `HOME` has none. Test and
/// code disagreed; U73 settled it for the **code** and its reasoning lives
/// on `commands::seal`. The short form: U72 had just ruled the same
/// ordering for `reveal` and paid its cost out loud; `seal`'s own recorded
/// rule is *"the cheapest thing that can say no goes first"* and
/// `open_layout` is one `stat`; and `BackendArm::Compiled`'s sentence was
/// false for a `seal` U13 already wired, so there was no true seam refusal
/// for this build to give. U95 retired that sentence (D180), and the build
/// with a backend now compiles no seam refusal at all — so the property
/// this function once asserted of it (that it named no feature flag) has no
/// subject left; the third witness is the compiler's now.
///
/// # Why a `match`, not a `#[cfg]`
///
/// R82's arm (b), carried across to behaviour: both expectations are
/// compiled into **both** builds, so the default build — the only one any
/// CI job runs, since Q153 keeps `heavy-features` local — still
/// type-checks and carries the feature build's answer instead of
/// `#[cfg]`-ing it out of existence. Only the *selection* is per-build.
fn next_stage_for_a_valid_seal_plan() -> (i32, String) {
    match BackendArm::THIS_BUILD {
        // No adapter exists, so the seam refuses. The needle is the whole
        // real message rather than one word of it: U3's rule, and it is
        // what makes this stronger than the `contains("ant-backend")` it
        // replaces.
        BackendArm::NotCompiled => (23, no_backend_message("seal")),
        // The adapter exists and `seal` constructs one, so the honest next
        // answer is the vault this HOME does not have (`open_layout`).
        BackendArm::Compiled => (2, "no vault exists".to_owned()),
    }
}

/// Plan validation runs before the backend seam, the vault and any
/// passphrase — so these refusals are reachable from a bare binary with
/// no vault at all, which is exactly the claim.
#[test]
fn the_binary_refuses_bad_plans_without_a_vault_a_network_or_a_passphrase() {
    let work = Work::new("bin");
    work.file("a.txt", b"content");
    std::fs::create_dir_all(work.dir.join("sub")).expect("mk sub");
    // A vault-less HOME: reaching the vault at all would fail loudly here.
    let home = work.dir.join("home");
    std::fs::create_dir_all(&home).expect("mk home");

    let run = |args: &[&str]| {
        antseal_bin()
            .current_dir(&work.dir)
            .env("HOME", &home)
            .args(args)
            .output()
            .expect("spawn antseal")
    };

    // D46: a directory argument, exit 27.
    let out = run(&["seal", "sub", "--no-anchor", "--network", "devnet"]);
    assert_eq!(out.status.code(), Some(27));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("is a directory"), "{stderr}");
    assert!(out.stdout.is_empty(), "stdout stays clean on errors");

    // D46: a lexical duplicate, exit 27, under --dry-run too.
    let out = run(&[
        "seal",
        "a.txt",
        "./a.txt",
        "--no-anchor",
        "--network",
        "devnet",
        "--dry-run",
    ]);
    assert_eq!(out.status.code(), Some(27));
    assert!(String::from_utf8_lossy(&out.stderr).contains("same file after lexical normalization"));

    // The M1 gate clause: --no-anchor on the DEFAULT network (no
    // --network flag at all — arbitrum-one is the built-in default).
    let out = run(&["seal", "a.txt", "--no-anchor"]);
    assert_eq!(out.status.code(), Some(27));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("--no-anchor cannot be used on arbitrum-one")
    );

    // **U22, from the binary.** A plain anchored seal no longer meets a
    // milestone refusal at all: plan validation passes it through. What it
    // meets *next* is this build's own next gate, which is U73's ruling and
    // is argued on `next_stage_for_a_valid_seal_plan`. Everything U22 is
    // actually about holds in **both** arms and is asserted outside the
    // per-arm expectation: the M1 sentence is gone, nothing has replaced it
    // with a differently-worded claim that anchoring is unavailable, and
    // whatever did refuse was not plan validation.
    let out = run(&["seal", "a.txt", "--network", "devnet"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("anchoring arrives in M2"),
        "the M1 anchor-stage refusal survived U22: {stderr}"
    );
    assert!(
        !stderr.contains("`antseal seal` is not implemented"),
        "seal IS implemented: {stderr}"
    );
    // The sharper, arm-invariant half of U22: this argv got *past* the plan
    // gate (27) and met no milestone stub (3), whichever build ran it.
    assert!(
        !matches!(out.status.code(), Some(27) | Some(3)),
        "plan validation must pass a plain anchored seal through: {stderr}"
    );
    let (expected_code, needle) = next_stage_for_a_valid_seal_plan();
    assert_eq!(
        out.status.code(),
        Some(expected_code),
        "a valid plan must reach the {} arm's next gate: {stderr}",
        BackendArm::THIS_BUILD.name()
    );
    assert!(
        stderr.contains(&needle),
        "the {} arm must say {needle:?}: {stderr}",
        BackendArm::THIS_BUILD.name()
    );

    // `--json`: exactly one envelope on stdout, same exit code.
    let out = run(&[
        "seal",
        "sub",
        "--no-anchor",
        "--network",
        "devnet",
        "--json",
    ]);
    assert_eq!(out.status.code(), Some(27));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let doc: serde_json::Value = serde_json::from_str(stdout.trim()).expect("one JSON document");
    assert_eq!(doc["ok"], false);
    assert_eq!(doc["command"], "seal");
    assert_eq!(doc["error"]["class"], "invalid-seal-argument");
    assert_eq!(doc["error"]["exit_code"], 27);
}

/// The `--no-fine-tree` decision, at the surface: a pattern that matches
/// nothing is refused rather than silently producing a fine tree the user
/// asked not to have (which would be permanent and paid for).
#[test]
fn a_no_fine_tree_pattern_matching_nothing_is_refused_at_the_surface() {
    let work = Work::new("nft");
    work.file("a.txt", b"content");
    let home = work.dir.join("home");
    std::fs::create_dir_all(&home).expect("mk home");

    let out = antseal_bin()
        .current_dir(&work.dir)
        .env("HOME", &home)
        .args([
            "seal",
            "a.txt",
            "--no-fine-tree",
            "*.bin",
            "--no-anchor",
            "--network",
            "devnet",
        ])
        .output()
        .expect("spawn antseal");
    assert_eq!(out.status.code(), Some(2), "usage error");
    assert!(String::from_utf8_lossy(&out.stderr).contains("matched none"));

    // The matching pattern is accepted and reaches the next stage, which
    // is this build's own (U73, on `next_stage_for_a_valid_seal_plan`).
    //
    // This assertion shared the feature-ON red with the U22 block above but
    // **not** its defect. It read `assert_ne!(code, Some(2))` — "accepted"
    // proxied by "not a usage error" — and that proxy was weak in the
    // default build too: it passes for *any* non-usage outcome, a panic
    // (101) included. What broke it under `--features ant-backend` is that
    // the next stage's own honest refusal is `usage` as well ("no vault
    // exists"), so a correct run looked like a rejected pattern. Assert the
    // property directly — the `matched none` sentence is absent — and pin
    // the arm's exact code beside it, which is stronger in both builds.
    let out = antseal_bin()
        .current_dir(&work.dir)
        .env("HOME", &home)
        .args([
            "seal",
            "a.txt",
            "--no-fine-tree",
            "*.txt",
            "--no-anchor",
            "--network",
            "devnet",
        ])
        .output()
        .expect("spawn antseal");
    let stderr = String::from_utf8_lossy(&out.stderr);
    // Measured, not assumed (U73). Switch the pattern above back to a
    // non-matching `*.bin` — the regression this test exists to catch —
    // and in the **feature** build the exit code is 2 either way, so
    // `assert_eq!(code, Some(expected_code))` stays green. It was measured
    // green with both stderr assertions removed. This one and the needle
    // below are each independently sufficient to redden it; this one names
    // the cause, which is why it goes first.
    assert!(
        !stderr.contains("matched none"),
        "a pattern that matches is not a --no-fine-tree refusal: {stderr}"
    );
    let (expected_code, needle) = next_stage_for_a_valid_seal_plan();
    assert_eq!(
        out.status.code(),
        Some(expected_code),
        "an accepted pattern must reach the {} arm's next gate: {stderr}",
        BackendArm::THIS_BUILD.name()
    );
    assert!(
        stderr.contains(&needle),
        "the {} arm must say {needle:?}: {stderr}",
        BackendArm::THIS_BUILD.name()
    );
}

/// `--no-fine-tree` is recorded per file in the plan the pipeline
/// receives (U13 accept: "matches recorded per-file in the descriptor").
#[test]
fn no_fine_tree_matches_are_recorded_per_file() {
    let work = Work::new("nft-record");
    work.file("keep.txt", b"text\n\nmore text\n")
        .file("opaque.bin", &[3u8; 32]);
    let plan = work
        .plan(&[
            "keep.txt",
            "opaque.bin",
            "--no-fine-tree",
            "*.bin",
            "--no-anchor",
            "--yes",
        ])
        .expect("plan validates");
    assert_eq!(plan.no_fine_tree_matches(), vec!["opaque.bin"]);
    assert!(!plan.files[0].flags.no_fine_tree_matched());
    assert!(plan.files[1].flags.no_fine_tree_matched());

    // And it survives into the vault's D45 identity record, so a resume
    // matches on it (a re-run without the flag is a flag mismatch).
    let backend = MockBackend::new().with_balances(funded());
    let vault = IsolatedVault::create("seal-nft");
    let unlocked = SealSession::open(Arc::new(vault.unlock()));
    let result = block_on(run_seal(
        &backend,
        &unlocked,
        &plan,
        &mut NeverAsked,
        &ctx(true),
        &mut ChaCha20Rng::from_seed([0xB1; 32]),
        &mut ChaCha20Rng::from_seed([0xB2; 32]),
    ))
    .expect("seals");
    let SealCommandResult::Sealed(report) = result else {
        panic!("expected Sealed");
    };
    let meta = WorkStore::new(unlocked.vault())
        .load_meta(&report.seal_id)
        .expect("meta");
    assert_eq!(meta.shaping.no_fine_tree, vec!["*.bin".to_owned()]);
}

/// The help snapshot must stay green **without** re-blessing: U13 adds no
/// surface. Asserted here as well as in `cli_surface.rs` because a lane
/// that lands a command is exactly the lane most likely to widen the
/// frozen surface by accident.
#[test]
fn u13_adds_no_command_surface() {
    let committed = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/snapshots/cli-surface.help.txt"),
    )
    .expect("the committed help snapshot exists");
    assert!(
        committed.contains("--no-fine-tree <GLOB>"),
        "the flag U13 implements is the one already frozen in the surface"
    );
    assert!(
        !committed.contains("--resume"),
        "D45 adds no --resume flag: re-running the same command IS the resume"
    );
}

// ─────────────────────────────────────────────────────────────────────
// S45 (D197): a seal interrupted before its staging finished is discarded
// by its exact re-run, which seals the same files afresh
// ─────────────────────────────────────────────────────────────────────

/// Where a planted interrupted seal was "killed": D197's two windows, both
/// before anything was quoted, consented to, anchored or paid.
#[derive(Debug, Clone, Copy)]
enum StagingWindow {
    /// Window 1, inside `VaultJournal::begin`: the work record landed and the
    /// `Staged` tag did not (`begin` is two atomic writes to two files). The
    /// kill is reconstructed on disk rather than raced for — deleting the tag
    /// leaves exactly the bytes it leaves (D106 R4's reconstruction).
    MidBegin,
    /// Window 2, between `begin` and the plan write, with one unit blob
    /// staged: units are journaled one by one as they are encrypted, before
    /// the plan, which is staging's last write.
    MidStaging,
}

/// Plant a seal of `plan`'s invocation interrupted in `window`, under the
/// fixture seal id `[tag; 16]`, and check the planted shape before any test
/// reads it: an incomplete pre-pay work with no plan, whose fine tag is
/// absent (window 1) or `Staged` (window 2).
fn plant_interrupted_seal(
    session: &SealSession,
    plan: &SealPlan,
    tag: u8,
    window: StagingWindow,
) -> SealId {
    use antseal_cli::pipeline::journal::{recorded_plan, recorded_state};
    use antseal_cli::pipeline::{
        BlobSlot, STATE_ENTRY, SealState, StagedBlob, UNIT_ENTRY_BASE, WorkIdentity,
    };
    use antseal_core::crypto::secrets::MasterSecret;

    let store = WorkStore::new(session.vault());
    let seal_id = SealId::from_bytes([tag; 16]);
    {
        let mut rng = ChaCha20Rng::from_seed([tag; 32]);
        let journal = VaultJournal::new(WorkStore::new(session.vault()), &mut rng);
        // NON-SECRET fixture master secret (project rule 6).
        let w = MasterSecret::from_bytes([tag; 32]);
        journal
            .begin(&WorkIdentity {
                w: w.secret_ref(),
                seal_id,
                network: plan.network.as_str().to_owned(),
                unanchored: plan.shaping.no_anchor,
                degraded: false,
                input_paths_as_given: plan.as_given_paths(),
                input_paths_absolute: plan.absolute_paths(),
                shaping: plan.shaping.clone(),
            })
            .expect("begin");
        match window {
            StagingWindow::MidBegin => assert!(
                store
                    .delete_journal_entry(&seal_id, STATE_ENTRY)
                    .expect("delete the tag"),
                "the fine tag was there to delete"
            ),
            StagingWindow::MidStaging => {
                let ciphertext = vec![0x5A_u8; 48];
                journal
                    .put_staged(
                        &seal_id,
                        &StagedBlob {
                            slot: BlobSlot::Unit { unit_id: 0 },
                            nonce: [0x5B; 24],
                            address: antseal_core::storage::compute_storage_address(&ciphertext)
                                .expect("under the chunk cap"),
                            ciphertext,
                        },
                    )
                    .expect("stage one unit");
            }
        }
    }
    // Positive controls on the planted shape.
    let (fine_tag, blob_staged) = match window {
        StagingWindow::MidBegin => (None, false),
        StagingWindow::MidStaging => (Some(SealState::Staged), true),
    };
    assert_eq!(
        recorded_state(&store, &seal_id).expect("tag read"),
        fine_tag,
        "{window:?}: the fine tag"
    );
    assert_eq!(
        store
            .get_journal_entry(&seal_id, UNIT_ENTRY_BASE)
            .expect("read")
            .is_some(),
        blob_staged,
        "{window:?}: the staged unit blob"
    );
    assert!(
        recorded_plan(&store, &seal_id)
            .expect("plan read")
            .is_none(),
        "{window:?}: no plan — staging never finished"
    );
    assert_eq!(
        store.load_meta(&seal_id).expect("meta").state,
        WorkState::IncompletePrePay,
        "{window:?}: the coarse mirror `begin` wrote"
    );
    seal_id
}

/// D197 R2/R3's outcome for an exact re-run over a work whose staging never
/// finished, read back from the vault and from the backend's own call log:
/// the interrupted work is abandoned — fine tag and coarse mirror both — and
/// the same command sealed afresh, under a new seal id, paid once.
fn assert_the_exact_rerun_seals_afresh(session: &SealSession, plan: &SealPlan, stale: SealId) {
    use antseal_cli::pipeline::SealState;
    use antseal_cli::pipeline::journal::recorded_state;

    let store = WorkStore::new(session.vault());
    // The decision `run_seal` acts on, read before the run changes the vault
    // and asserted after it, so that a red names the run's own outcome first.
    let decision = detect(&store, plan.network, &plan.absolute_paths(), &plan.shaping);
    let backend = MockBackend::new().with_balances(funded());
    let result = block_on(run_seal(
        &backend,
        session,
        plan,
        &mut NeverAsked,
        &ctx(true),
        &mut ChaCha20Rng::from_seed([0x48; 32]),
        &mut ChaCha20Rng::from_seed([0x49; 32]),
    ))
    .unwrap_or_else(|err| {
        panic!(
            "the exact re-run must abandon the interrupted seal and seal afresh (D197); got \
             exit {} ({:?}): {err}",
            err.exit_code(),
            err.class()
        )
    });
    let SealCommandResult::Sealed(sealed) = result else {
        panic!("expected a completed seal, got {result:?}");
    };
    assert!(!sealed.resumed, "a fresh seal, not a resume");
    assert!(sealed.paid_here, "the fresh seal paid");
    assert_ne!(sealed.seal_id, stale, "a new seal id (MVP-SPEC line 145)");
    assert_eq!(
        backend.calls(Method::Pay),
        1,
        "one payment: the fresh seal's"
    );
    assert_eq!(
        store.load_meta(&sealed.seal_id).expect("meta").state,
        WorkState::Complete
    );

    // The interrupted work: abandoned through the state machine (fine tag
    // first, coarse mirror second), so it is never a candidate again.
    assert_eq!(
        recorded_state(&store, &stale).expect("tag read"),
        Some(SealState::Abandoned)
    );
    assert_eq!(
        store.load_meta(&stale).expect("meta").state,
        WorkState::Abandoned
    );
    let mut works = store.list_works().expect("list");
    works.sort_unstable_by_key(|id| *id.as_bytes());
    let mut expected = vec![stale, sealed.seal_id];
    expected.sort_unstable_by_key(|id| *id.as_bytes());
    assert_eq!(
        works, expected,
        "the abandoned work and the fresh one, and nothing else"
    );
    // The same command once more finds nothing to resume.
    assert_eq!(
        detect(&store, plan.network, &plan.absolute_paths(), &plan.shaping).expect("detect"),
        ResumeDecision::Fresh {
            incomplete_works: 0
        }
    );

    // The decision the run acted on, and the notice `run_seal` printed for
    // it — at the abandon, and only for a `Restart`. No test can read the
    // process's own streams (D146 §1.6), so the text is asserted at its
    // producer.
    match decision {
        Ok(ResumeDecision::Restart(candidate)) => assert_eq!(candidate.seal_id, stale),
        other => panic!("an exact match that never finished staging restarts; got {other:?}"),
    }
    let notice = antseal_cli::seal_resume::restart_notice(&stale, false);
    assert!(
        notice.contains(&format!(
            "seal {} was interrupted before its staging finished",
            seal_hex(&stale)
        )),
        "{notice}"
    );
}

/// **S45 (D197 R2, R4), window 1 — watched red first** (the red baseline was
/// exit 12, `VaultAuthFailure`: the wrong-passphrase-or-tampering sentence
/// for a Ctrl-C, on every re-run). A kill inside `begin` leaves the work
/// record without its fine tag, and the resume path's `state()` read refused
/// that as corrupt. Its exact re-run now has window 2's outcome: the work is
/// abandoned through `set_state`'s one absent-tag transition (R4), and the
/// same files are sealed afresh.
#[test]
fn a_seal_killed_inside_begin_is_abandoned_and_sealed_afresh() {
    let work = Work::new("s45-window1");
    work.file("a.txt", b"paragraph one\n\nparagraph two\n");
    let plan = work
        .plan(&["a.txt", "--no-anchor", "--yes"])
        .expect("plan validates");
    let vault = IsolatedVault::create("s45-window1");
    let session = SealSession::open(Arc::new(vault.unlock()));
    let stale = plant_interrupted_seal(&session, &plan, 0xD4, StagingWindow::MidBegin);
    assert_the_exact_rerun_seals_afresh(&session, &plan, stale);
}

/// **S45 (D197 R4): `antseal abandon` in window 1 — watched red first** (the
/// red baseline was exit 12 after the confirmation). `set_state` refused
/// every transition from an absent fine tag, so the command D185 built to
/// exit this trap failed on the shape that needed it, after the user had
/// confirmed. `previous_state` is `null` — the value its rustdoc documents
/// for a journal that carried no tag — and the preview says what happened.
#[test]
fn abandon_exits_a_seal_killed_inside_begin() {
    use antseal_cli::pipeline::SealState;
    use antseal_cli::pipeline::journal::recorded_state;

    let work = Work::new("s45-abandon");
    work.file("a.txt", b"paragraph one\n\nparagraph two\n");
    let plan = work
        .plan(&["a.txt", "--no-anchor", "--yes"])
        .expect("plan validates");
    let vault = IsolatedVault::create("s45-abandon");
    let session = SealSession::open(Arc::new(vault.unlock()));
    let stale = plant_interrupted_seal(&session, &plan, 0xD5, StagingWindow::MidBegin);
    let store = WorkStore::new(session.vault());

    let mut shown = Vec::new();
    let report = {
        let mut rng = ChaCha20Rng::from_seed([0x4A; 32]);
        let journal = VaultJournal::new(WorkStore::new(session.vault()), &mut rng);
        run_abandon(
            &store,
            &journal,
            &seal_hex(&stale),
            SCRIPTED,
            |line| shown.push(line.to_owned()),
            never_asked,
        )
        .unwrap_or_else(|err| {
            panic!(
                "`antseal abandon` must exit window 1; got exit {} ({:?}): {err}",
                err.exit_code(),
                err.class()
            )
        })
    };
    assert!(!report.already);
    assert_eq!(report.seal_id, stale);
    assert_eq!(report.previous_state, None, "window 1 carried no fine tag");
    assert!(
        report.json()["previous_state"].is_null(),
        "{}",
        report.json()
    );
    assert_eq!(shown.len(), 6, "{shown:?}");
    assert_eq!(
        shown[4], "  progress: staging was interrupted before it finished; not paid",
        "{shown:?}"
    );
    assert_eq!(
        recorded_state(&store, &stale).expect("tag read"),
        Some(SealState::Abandoned)
    );
    assert_eq!(
        store.load_meta(&stale).expect("meta").state,
        WorkState::Abandoned
    );
}

/// **S45 (D197 R5).** `--dry-run` writes nothing (D49), so over a work whose
/// staging never finished it rehearses the FRESH seal — a real quote over
/// the real blob set — and leaves the interrupted work exactly as it is.
/// Before D197 it returned the resume plan, whose "encrypted units and
/// manifest are staged in the vault" was false for a work with no plan, and
/// the real run then failed.
#[test]
fn a_dry_run_over_an_unfinished_staging_rehearses_a_fresh_seal_and_writes_nothing() {
    use antseal_cli::pipeline::SealState;
    use antseal_cli::pipeline::journal::recorded_state;

    let work = Work::new("s45-dryrun");
    work.file("a.txt", b"paragraph one\n\nparagraph two\n");
    let plan = work
        .plan(&["a.txt", "--no-anchor", "--yes"])
        .expect("plan validates");
    let vault = IsolatedVault::create("s45-dryrun");
    let stale = {
        let session = SealSession::open(Arc::new(vault.unlock()));
        plant_interrupted_seal(&session, &plan, 0xD6, StagingWindow::MidStaging)
    };
    let before = vault.fingerprint();
    assert!(before.len() > 3, "the fingerprint sees the vault's files");

    let session = SealSession::open(Arc::new(vault.unlock()));
    let rehearsal = work
        .plan(&["a.txt", "--no-anchor", "--dry-run"])
        .expect("plan validates");
    let backend = MockBackend::new().with_balances(funded());
    let result = block_on(run_seal(
        &backend,
        &session,
        &rehearsal,
        &mut NeverAsked,
        &ctx(true),
        &mut ChaCha20Rng::from_seed([0x4D; 32]),
        &mut ChaCha20Rng::from_seed([0x4E; 32]),
    ))
    .unwrap_or_else(|err| {
        panic!(
            "the rehearsal succeeds; got exit {} ({:?}): {err}",
            err.exit_code(),
            err.class()
        )
    });
    let SealCommandResult::DryRun(report) = &result else {
        panic!(
            "a dry run over a work whose staging never finished rehearses the fresh seal \
             (D197 R5), got {result:?}"
        );
    };
    assert!(
        report.quote.total_ant_atto > 0,
        "a real quote over the real blob set"
    );
    assert_eq!(backend.calls(Method::QuoteBatch), 1);
    assert_eq!(backend.calls(Method::Pay), 0);
    assert_eq!(backend.calls(Method::FinalizeBatch), 0);
    let json = result.json();
    assert_eq!(json["dry_run"], true);
    assert!(json.get("resume_plan").is_none(), "{json}");
    {
        let store = WorkStore::new(session.vault());
        assert_eq!(
            store.list_works().expect("list"),
            vec![stale],
            "nothing was begun"
        );
        assert_eq!(
            store.load_meta(&stale).expect("meta").state,
            WorkState::IncompletePrePay
        );
        assert_eq!(
            recorded_state(&store, &stale).expect("tag read"),
            Some(SealState::Staged)
        );
    }
    drop(session);
    assert_eq!(
        before,
        vault.fingerprint(),
        "a dry run writes nothing (D49) — not even the abandon a real run makes"
    );
}

/// **S45 (D197 R3): the order of the two writes.** The abandon precedes the
/// fresh seal's `begin`, so a fresh seal that then stops at consent (machine
/// mode without `--yes`, class 10) leaves the interrupted work abandoned and
/// the fresh, staged work as the ONE exact candidate the next re-run
/// resumes. The other order could leave two exact candidates, which D45
/// reports as the internal class on every later run.
#[test]
fn a_restart_stopped_at_consent_leaves_one_resumable_work_not_two() {
    let work = Work::new("s45-consent");
    work.file("a.txt", b"paragraph one\n\nparagraph two\n");
    let plan = work
        .plan(&["a.txt", "--no-anchor", "--yes"])
        .expect("plan validates");
    let vault = IsolatedVault::create("s45-consent");
    let session = SealSession::open(Arc::new(vault.unlock()));
    let stale = plant_interrupted_seal(&session, &plan, 0xD7, StagingWindow::MidStaging);
    let store = WorkStore::new(session.vault());

    let unconsented = work
        .plan(&["a.txt", "--no-anchor"])
        .expect("plan validates");
    let backend = MockBackend::new().with_balances(funded());
    let err = block_on(run_seal(
        &backend,
        &session,
        &unconsented,
        &mut NeverAsked,
        &ctx(true),
        &mut ChaCha20Rng::from_seed([0x4F; 32]),
        &mut ChaCha20Rng::from_seed([0x50; 32]),
    ))
    .expect_err("machine mode without --yes stops at the consent gate");
    assert_eq!(err.class(), ErrorClass::ConsentNotObtained, "{err}");
    assert_eq!(err.exit_code(), 10);
    assert_eq!(backend.calls(Method::Pay), 0);
    assert_eq!(
        store.load_meta(&stale).expect("meta").state,
        WorkState::Abandoned,
        "the abandon came before the fresh seal's first write"
    );

    let works = store.list_works().expect("list");
    assert_eq!(works.len(), 2, "{works:?}");
    let fresh = works
        .into_iter()
        .find(|id| *id != stale)
        .expect("the fresh work");
    match detect(
        &store,
        unconsented.network,
        &unconsented.absolute_paths(),
        &unconsented.shaping,
    ) {
        Ok(ResumeDecision::Resume(candidate)) => assert_eq!(candidate.seal_id, fresh),
        other => panic!(
            "the next re-run resumes the fresh work — one exact candidate, not two; got \
             {other:?}"
        ),
    }
}

/// **S45 (D197 R1): the money guard.** A work with a journaled receipt is
/// never restarted, plan or no plan: the receipt says money moved, and only
/// the receipt answers that (U17 rule 2). The pipeline cannot write this
/// shape (the receipt comes after the plan), so it is planted, giving the
/// predicate's receipt clause a witness of its own beside the engine's
/// re-check in `abandon_pre_pay`.
///
/// `Pay == 0` alone would not be that witness: a restart under a dropped
/// receipt clause is refused by `abandon_pre_pay`'s own re-check, and pays
/// nothing either (D197 §3). So the run's own outcome is asserted too — the
/// decision, since `run_seal` prints the restart notice for a `Restart` and
/// for nothing else (no test can read the process's own streams, D146
/// §1.6), and the exact error the run returned.
#[test]
fn an_unplanned_work_with_a_receipt_is_never_restarted_and_never_paid_again() {
    let work = Work::new("s45-receipt");
    work.file("a.txt", b"paragraph one\n\nparagraph two\n");
    let plan = work
        .plan(&["a.txt", "--no-anchor", "--yes"])
        .expect("plan validates");
    let vault = IsolatedVault::create("s45-receipt");
    let stale = {
        let session = SealSession::open(Arc::new(vault.unlock()));
        let stale = plant_interrupted_seal(&session, &plan, 0xD8, StagingWindow::MidStaging);
        let mut rng = ChaCha20Rng::from_seed([0x51; 32]);
        let journal = VaultJournal::new(WorkStore::new(session.vault()), &mut rng);
        journal
            .put_receipt(&stale, &fixture_receipt())
            .expect("journal a receipt");
        stale
    };
    let before = vault.fingerprint();

    let session = SealSession::open(Arc::new(vault.unlock()));
    // The decision, read before the run and asserted after it, so that a red
    // names the run's own outcome first.
    let decision = {
        let store = WorkStore::new(session.vault());
        assert!(
            store.get_receipt(&stale).expect("read").is_some(),
            "positive control: the receipt is journaled"
        );
        detect(&store, plan.network, &plan.absolute_paths(), &plan.shaping)
    };

    let backend = MockBackend::new().with_balances(funded());
    let err = block_on(run_seal(
        &backend,
        &session,
        &plan,
        &mut NeverAsked,
        &ctx(true),
        &mut ChaCha20Rng::from_seed([0x52; 32]),
        &mut ChaCha20Rng::from_seed([0x53; 32]),
    ))
    .expect_err("there is no plan to resume from");
    assert_eq!(backend.calls(Method::Pay), 0, "nothing is paid again");
    // The resume's own refusal — not abandon's rule 2 ("a payment is recorded"),
    // which only a (wrongly) restarted run would reach.
    assert_eq!(
        err.to_string(),
        "usage error: this work has no journaled seal plan; nothing was staged to resume from"
    );
    assert_eq!(err.class(), ErrorClass::Usage, "{err}");
    assert_eq!(err.exit_code(), 2);
    match decision {
        Ok(ResumeDecision::Resume(candidate)) => assert_eq!(candidate.seal_id, stale),
        other => panic!(
            "a work with a journaled receipt is never restarted (money moved); got {other:?}"
        ),
    }
    drop(session);
    assert_eq!(
        vault.fingerprint(),
        before,
        "the paid work is left exactly as it was"
    );
}

/// **S45 (D197 R1): "pre-staging" is measured, and each clause alone rules it
/// out.** Each row plants one interrupted seal and changes ONE fact about
/// it; only the two untouched windows measure as pre-staging. The receipt,
/// consent, anchor and tag clauses cannot fail on a vault the pipeline wrote
/// (each of those records is written after the plan), so each has its
/// witness here, planted, rather than nowhere.
#[test]
fn pre_staging_is_measured_and_each_clause_alone_rules_it_out() {
    use antseal_cli::pipeline::{OTS_SLOT, SealPlan as JournaledPlan, SealState};
    use antseal_cli::seal_resume::staging_never_finished;
    use antseal_cli::vault::store::{ConsentChannel, ConsentRecord};

    #[derive(Debug, Clone, Copy)]
    enum Change {
        Nothing,
        Plan,
        Receipt,
        Consent,
        AnchorSlot,
        AnchoredTag,
        PostPayMirror,
    }

    let work = Work::new("s45-clauses");
    work.file("a.txt", b"paragraph one\n\nparagraph two\n");
    let plan = work
        .plan(&["a.txt", "--no-anchor", "--yes"])
        .expect("plan validates");
    let vault = IsolatedVault::create("s45-clauses");
    let session = SealSession::open(Arc::new(vault.unlock()));
    let store = WorkStore::new(session.vault());

    let rows = [
        (StagingWindow::MidStaging, Change::Nothing, true),
        (StagingWindow::MidBegin, Change::Nothing, true),
        (StagingWindow::MidStaging, Change::Plan, false),
        (StagingWindow::MidStaging, Change::Receipt, false),
        (StagingWindow::MidBegin, Change::Receipt, false),
        (StagingWindow::MidStaging, Change::Consent, false),
        (StagingWindow::MidStaging, Change::AnchorSlot, false),
        (StagingWindow::MidStaging, Change::AnchoredTag, false),
        (StagingWindow::MidStaging, Change::PostPayMirror, false),
    ];
    assert_eq!(
        rows.len(),
        9,
        "both windows, one row per clause, and window 1 with a receipt"
    );
    let mut wrong = Vec::new();
    for (index, (window, change, expected)) in rows.into_iter().enumerate() {
        let tag = 0xE0 + u8::try_from(index).expect("a handful of rows");
        let seal_id = plant_interrupted_seal(&session, &plan, tag, window);
        // Seeds distinct from the plant's, so no record nonce repeats.
        let mut rng = ChaCha20Rng::from_seed([tag ^ 0x80; 32]);
        let mut store_rng = ChaCha20Rng::from_seed([tag ^ 0xFF; 32]);
        let journal = VaultJournal::new(WorkStore::new(session.vault()), &mut rng);
        match change {
            Change::Nothing => {}
            Change::Plan => journal
                .put_plan(
                    &seal_id,
                    &JournaledPlan {
                        unit_count: 1,
                        manifest_bytes: None,
                    },
                )
                .expect("plan"),
            Change::Receipt => journal
                .put_receipt(&seal_id, &fixture_receipt())
                .expect("receipt"),
            Change::Consent => journal
                .put_consent(
                    &seal_id,
                    ConsentRecord {
                        total_ant_atto: 1,
                        gas_estimate_wei: 1,
                        consent_time_unix_secs: 1_800_000_000,
                        channel: ConsentChannel::YesFlag,
                    },
                )
                .expect("consent"),
            Change::AnchorSlot => store
                .put_anchor(
                    &seal_id,
                    OTS_SLOT,
                    b"NON-SECRET fixture anchor bytes",
                    &mut store_rng,
                )
                .expect("anchor slot"),
            Change::AnchoredTag => journal
                .set_state(&seal_id, SealState::Anchored)
                .expect("Staged -> Anchored"),
            Change::PostPayMirror => {
                let mut record = store.load_meta(&seal_id).expect("meta");
                record.state = WorkState::IncompletePostPay;
                store
                    .store_meta(&record, &mut store_rng)
                    .expect("rewrite the mirror");
            }
        }
        let measured = staging_never_finished(&store, &seal_id);
        if measured != expected {
            wrong.push(format!(
                "{window:?} + {change:?}: measured {measured}, expected {expected}"
            ));
        }
    }
    assert!(
        wrong.is_empty(),
        "pre-staging mis-measured:\n{}",
        wrong.join("\n")
    );
}

// ─────────────────────────────────────────────────────────────────────
// D203 (wave 40): S48's two-write windows, S52's resume-completed cost,
// and U109's money claims in `list`
// ─────────────────────────────────────────────────────────────────────

/// **D203**: a reader takes each fact from its authority — a work's STATE
/// from its fine tag (R1–R2, S48), its MONEY from its receipt (M1–M3,
/// U109) — and `complete()` writes its outcome before the `Complete` tag
/// (R7, S48 + S52).
///
/// Every window here is planted with the suites' own seam: a real
/// transition through the state machine, then the coarse mirror rewritten
/// to the value it held before ([`roll_mirror`]). That is byte for byte
/// what a kill between `VaultJournal::write_state`'s two writes leaves —
/// the tag first, the mirror second, each atomic and fsync'd — so the
/// mirror can only ever TRAIL the tag.
mod d203 {
    use super::*;

    use antseal_anchor::ots::{PendingWork, UpgradeBudget, UpgradeReport};
    use antseal_cli::error::CliError;
    use antseal_cli::listing::{ResumeClock, WorkRow};
    use antseal_cli::pipeline::journal::{
        JournalError, RecordedIdentity, SealPlan as JournalPlan, WorkIdentity,
        effective_work_state, payment_recorded, recorded_state,
    };
    use antseal_cli::pipeline::receipt_sink::{ReceiptSinkFault, recorded_receipt};
    use antseal_cli::pipeline::{
        BlobSlot, NoBarriers, Pipeline, RestoreEngine, RestoreError, RevealEngine, RevealError,
        RevealRequest, SealError, SealState, StagedBlob, UnitSelection,
    };
    use antseal_cli::seal_resume::{AbandonPreview, AbandonReport, gather_candidates};
    use antseal_cli::show::WorkUnits;
    use antseal_cli::status::{StatusContext, WorkStatus};
    use antseal_cli::upgrade_hook::{HookContext, run_with};
    use antseal_cli::vault::session::UnlockedVault;
    use antseal_cli::vault::store::{ConsentChannel, ConsentRecord, StoreError};
    use antseal_core::crypto::secrets::MasterSecret;
    use antseal_net::test_util::{Fault, Method};
    use antseal_net::{
        GasSummary, NetworkId, PaymentReceipt, QuoteHash, TxHash, TxRecord, TxStatus,
    };

    /// D203 M2's two clock notes, verbatim: no payment recorded, and a
    /// payment recorded.
    const RE_QUOTE_NOTE: &str = "no payment is recorded for it; the recorded quote is stale by \
                                 design — resuming re-quotes at current prices and asks for \
                                 consent again";
    const TIME_BOXED_NOTE: &str = "RESUME PROMPTLY: a payment for this seal is recorded, and its \
                                   payment proofs stay usable for uploading only about a day — \
                                   after that, finishing it costs a second payment";
    /// D203 M3's cost line where the vault records neither a cost nor a
    /// payment.
    const NO_COST_LINE: &str = "  cost: none (no payment recorded)";

    fn rng(seed: u8) -> ChaCha20Rng {
        ChaCha20Rng::from_seed([seed; 32])
    }

    fn hex(id: &SealId) -> String {
        id.as_bytes().iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Run `body` against a fresh [`VaultJournal`] over `vault`.
    fn journal_do(vault: &UnlockedVault, body: impl FnOnce(&VaultJournal<'_, ChaCha20Rng>)) {
        let mut r = rng(0x67);
        let journal = VaultJournal::new(WorkStore::new(vault), &mut r);
        body(&journal);
    }

    /// The window: rewrite ONLY the coarse mirror (and, for window B′, the
    /// cost HEAD's order wrote after the tag) — the bytes a kill between
    /// `write_state`'s two writes leaves behind.
    fn roll_mirror(store: &WorkStore<'_>, seal_id: &SealId, mirror: WorkState, drop_cost: bool) {
        let mut record = store.load_meta(seal_id).expect("meta");
        record.state = mirror;
        if drop_cost {
            record.cost_atto = None;
        }
        store
            .store_meta(&record, &mut rng(0xEE))
            .expect("rewrite the mirror");
    }

    /// The positive control every window row starts from: the planted shape,
    /// read back from where it landed.
    fn assert_window(store: &WorkStore<'_>, seal_id: &SealId, tag: SealState, mirror: WorkState) {
        assert_eq!(
            recorded_state(store, seal_id).expect("tag read"),
            Some(tag),
            "the planted fine tag"
        );
        assert_eq!(
            store.load_meta(seal_id).expect("meta").state,
            mirror,
            "the planted stale mirror"
        );
    }

    fn decide(store: &WorkStore<'_>, plan: &SealPlan) -> Result<ResumeDecision, CliError> {
        detect(
            store,
            NetworkId::Devnet,
            &plan.absolute_paths(),
            &plan.shaping,
        )
    }

    fn abandon(vault: &UnlockedVault, seal_id: &SealId) -> Result<AbandonReport, CliError> {
        let store = WorkStore::new(vault);
        let mut r = rng(0x66);
        let journal = VaultJournal::new(WorkStore::new(vault), &mut r);
        abandon_pre_pay(&store, &journal, seal_id)
    }

    fn preview(vault: &UnlockedVault, seal_id: &SealId) -> Option<AbandonPreview> {
        let store = WorkStore::new(vault);
        let mut r = rng(0x68);
        let journal = VaultJournal::new(WorkStore::new(vault), &mut r);
        AbandonPreview::read(&store, &journal, seal_id).expect("the preview reads")
    }

    /// The only row of a one-work vault.
    fn only_row(listing: &WorkListing) -> &WorkRow {
        assert_eq!(listing.works.len(), 1, "one work in this vault");
        &listing.works[0]
    }

    fn sealed(outcome: Result<SealCommandResult, CliError>, what: &str) -> SealReportFields {
        match outcome {
            Ok(SealCommandResult::Sealed(report)) => SealReportFields {
                seal_id: report.seal_id,
                work_id: report.work_id,
                resumed: report.resumed,
                paid_here: report.paid_here,
            },
            Ok(_) => panic!("{what}: a non-dry-run seal returns Sealed"),
            Err(err) => panic!("{what}: {err}"),
        }
    }

    /// The fields of a `Sealed` report these rows read.
    struct SealReportFields {
        seal_id: SealId,
        work_id: [u8; 32],
        resumed: bool,
        paid_here: bool,
    }

    // ── State group (S48): one lag, four windows ─────────────────────

    /// **S48's Accept — window A, exactly**: an abandon killed between its
    /// two writes (fine tag `Abandoned`, mirror still `incomplete-pre-pay`)
    /// is abandoned to every reader. The exact, overlapping and other-flags
    /// invocations are fresh, `list` offers no resume, the abandon preview is
    /// not shown, `antseal abandon` says nothing needed doing and writes
    /// nothing, `restore`/`reveal` name the tag's state, and the exact re-run
    /// seals afresh under a new seal id.
    ///
    /// Red at 6e1cab3 (P1's probe, re-run before the fix): `detect` →
    /// `Resume`, the re-run exits 2 "this work is abandoned and cannot be
    /// resumed", `list` offers the resume, and `abandon` reports
    /// `already: false` beside `previous_state: "abandoned"`.
    #[test]
    fn s48_window_a_an_abandoned_tag_over_a_pre_pay_mirror_is_abandoned_to_every_reader() {
        let (vault, work, seal_id) = vault_with_a_declined_work("d203-wa");
        work.file("b.txt", b"another file\n");
        let session = SealSession::open(Arc::new(vault.unlock()));
        let store = WorkStore::new(session.vault());
        journal_do(session.vault(), |j| {
            j.set_state(&seal_id, SealState::Abandoned)
                .expect("abandon");
        });
        roll_mirror(&store, &seal_id, WorkState::IncompletePrePay, false);
        assert_window(
            &store,
            &seal_id,
            SealState::Abandoned,
            WorkState::IncompletePrePay,
        );

        // D45: no invocation resurrects the work.
        let invocations = [
            work.plan(&["a.txt", "--no-anchor"]).expect("exact"),
            work.plan(&["a.txt", "b.txt", "--no-anchor"])
                .expect("overlap"),
            work.plan(&["a.txt", "--no-anchor", "--split", "blank-lines"])
                .expect("other flags"),
        ];
        assert_eq!(invocations.len(), 3);
        for plan in &invocations {
            let decision = decide(&store, plan);
            assert!(
                matches!(
                    decision,
                    Ok(ResumeDecision::Fresh {
                        incomplete_works: 0
                    })
                ),
                "expected Fresh {{ incomplete_works: 0 }}, got {decision:?}"
            );
        }

        // `list`: abandoned, nothing to resume.
        let listing = WorkListing::gather(&store).expect("list");
        let row = only_row(&listing);
        assert_eq!(
            row.state,
            WorkState::Abandoned,
            "list classifies by the tag"
        );
        assert!(row.resume.is_none(), "{:?}", row.resume);
        assert!(row.resume_refusal.is_none());
        let counts = listing.counts();
        assert_eq!((counts.abandoned, counts.incomplete), (1, 0));

        // D185's preview is not shown: the engine reports the work as done.
        assert_eq!(preview(session.vault(), &seal_id), None);

        // `antseal abandon`: nothing needed doing, and nothing is written.
        let before = vault.fingerprint();
        let report = abandon(session.vault(), &seal_id).expect("already abandoned is an outcome");
        assert!(report.already, "{report:?}");
        assert_eq!(report.previous_state, Some(SealState::Abandoned));
        assert_eq!(report.json()["already"], true);
        assert_eq!(report.json()["previous_state"], "abandoned");
        assert_eq!(
            report.render(),
            vec![format!(
                "Work {} was already abandoned; nothing changed.",
                hex(&seal_id)
            )]
        );
        assert_eq!(vault.fingerprint(), before, "the abandon wrote nothing");

        // The engines that need a complete work name the state the tag holds.
        let backend = MockBackend::new().with_balances(funded());
        match block_on(RestoreEngine::new(&backend, &store).restore(&seal_id)) {
            Err(RestoreError::NotRestorable { state }) => assert_eq!(state, "abandoned"),
            Err(other) => panic!("expected NotRestorable, got: {other}"),
            Ok(_) => panic!("an abandoned work is never restorable"),
        }
        match block_on(RevealEngine::new(&backend, &store).prepare(
            &seal_id,
            &RevealRequest {
                selection: UnitSelection::All,
                include_receipt: false,
            },
        )) {
            Err(RevealError::NotRevealable { state }) => assert_eq!(state, "abandoned"),
            Err(other) => panic!("expected NotRevealable, got: {other}"),
            Ok(_) => panic!("an abandoned work is never revealable"),
        }

        // The exact re-run seals afresh, under a NEW seal id.
        let rerun = work
            .plan(&["a.txt", "--no-anchor", "--yes"])
            .expect("plan validates");
        let fresh = sealed(
            block_on(run_seal(
                &backend,
                &session,
                &rerun,
                &mut NeverAsked,
                &ctx(true),
                &mut rng(0xD2),
                &mut rng(0xD3),
            )),
            "the exact re-run must seal afresh",
        );
        assert!(!fresh.resumed);
        assert_ne!(fresh.seal_id, seal_id, "a fresh seal draws a new seal id");
        assert_eq!(store.list_works().expect("list").len(), 2);
    }

    /// **Window B′ (`Finalizing → Complete`), the commonest producer** —
    /// every successful seal passes through it. Killed there (tag
    /// `Complete`, mirror `incomplete-post-pay`, and under HEAD's order no
    /// cost), the work is complete to every reader: no resume candidate,
    /// `list` "complete", `status`/`show` complete, `restore`/`reveal` pass
    /// their state gate, the upgrade hook visits it, and `abandon` gives the
    /// complete refusal. The exact re-run is a fresh seal — D45 §2's rule for
    /// every complete work (D203's stated residual).
    ///
    /// Red at 6e1cab3: a complete work listed incomplete with "RESUME
    /// PROMPTLY", refused by `restore`/`reveal`, and abandon and the exact
    /// re-run both exit 2 — a permanent dead end (P1 §2 S48 (a2)).
    #[test]
    fn s48_window_b_prime_a_complete_tag_over_a_post_pay_mirror_is_complete_to_every_reader() {
        let work = Work::new("d203-wb");
        work.file("a.txt", b"paragraph one\n\nparagraph two\n");
        let plan = work
            .plan(&["a.txt", "--no-anchor", "--yes"])
            .expect("plan validates");
        let backend = MockBackend::new().with_balances(funded());
        let vault = IsolatedVault::create("d203-wb");
        let session = SealSession::open(Arc::new(vault.unlock()));
        let first = sealed(
            block_on(run_seal(
                &backend,
                &session,
                &plan,
                &mut NeverAsked,
                &ctx(true),
                &mut rng(0x71),
                &mut rng(0x72),
            )),
            "the first seal completes",
        );
        let seal_id = first.seal_id;
        let store = WorkStore::new(session.vault());
        roll_mirror(&store, &seal_id, WorkState::IncompletePostPay, true);
        assert_window(
            &store,
            &seal_id,
            SealState::Complete,
            WorkState::IncompletePostPay,
        );
        assert_eq!(
            store.load_meta(&seal_id).expect("meta").work_id,
            Some(first.work_id),
            "staging recorded the work id (pipeline/seal.rs's record_outcome after put_plan)"
        );

        // D45: not a candidate, and the exact re-run is fresh.
        assert!(
            gather_candidates(&store, NetworkId::Devnet)
                .expect("gather")
                .is_empty()
        );
        let exact = work
            .plan(&["a.txt", "--no-anchor"])
            .expect("plan validates");
        let decision = decide(&store, &exact);
        assert!(
            matches!(
                decision,
                Ok(ResumeDecision::Fresh {
                    incomplete_works: 0
                })
            ),
            "{decision:?}"
        );

        // `list`: complete, nothing to resume.
        let listing = WorkListing::gather(&store).expect("list");
        let row = only_row(&listing);
        assert_eq!(row.state, WorkState::Complete);
        assert!(row.resume.is_none(), "{:?}", row.resume);
        let counts = listing.counts();
        assert_eq!((counts.complete, counts.incomplete), (1, 0));

        // `status` and `show` say complete.
        let status = WorkStatus::gather(&store, &seal_id, StatusContext::new(1_800_000_000))
            .expect("status");
        assert_eq!(status.state, WorkState::Complete);
        let units = WorkUnits::gather(&store, &seal_id).expect("show");
        assert_eq!(units.state, WorkState::Complete);

        // `restore` and `reveal` (the only `.sealproof` producer) pass their
        // state gate.
        if let Err(err) = block_on(RestoreEngine::new(&backend, &store).restore(&seal_id)) {
            panic!("a complete work restores: {err}");
        }
        if let Err(err) = block_on(RevealEngine::new(&backend, &store).prepare(
            &seal_id,
            &RevealRequest {
                selection: UnitSelection::All,
                include_receipt: false,
            },
        )) {
            panic!("a complete work reveals: {err}");
        }

        // The upgrade hook visits it: complete works are its candidates.
        let pass = run_with(&HookContext::with_poll(
            session.vault(),
            UpgradeBudget::opportunistic(),
            1_800_000_000,
            Box::new(|_: &[PendingWork], _: UpgradeBudget| UpgradeReport::default()),
        ));
        assert_eq!(pass.excluded, 0, "{pass:?}");
        assert_eq!(pass.order, vec![seal_id], "{pass:?}");

        // `abandon` gives the complete refusal, not the paid one.
        let err =
            abandon(session.vault(), &seal_id).expect_err("a complete work is never abandoned");
        assert_eq!(err.exit_code(), 2);
        assert!(
            err.to_string()
                .contains("is complete: its ciphertexts are on the network permanently"),
            "{err}"
        );
    }

    /// **Window C (`Anchored → Paid`)**: tag `Paid`, mirror still pre-pay.
    /// The candidate is classified post-pay (consent does not re-fire, D45
    /// §4), `list` puts it on the time-boxed clock, and the abandon refusal —
    /// the receipt first — was already right.
    ///
    /// Red at 6e1cab3: `list` says "re-quote … nothing was paid" for a paid
    /// work, and the candidate carries the stale pre-pay class.
    #[test]
    fn s48_window_c_a_paid_tag_over_a_pre_pay_mirror_is_post_pay_to_every_reader() {
        let (vault, _work, seal_id) = vault_with_a_declined_work("d203-wc");
        let unlocked = vault.unlock();
        let store = WorkStore::new(&unlocked);
        journal_do(&unlocked, |j| {
            j.set_state(&seal_id, SealState::Anchored)
                .expect("anchored");
            j.put_receipt(&seal_id, &fixture_receipt())
                .expect("receipt");
            j.set_state(&seal_id, SealState::Paid).expect("paid");
        });
        roll_mirror(&store, &seal_id, WorkState::IncompletePrePay, false);
        assert_window(
            &store,
            &seal_id,
            SealState::Paid,
            WorkState::IncompletePrePay,
        );

        let candidates = gather_candidates(&store, NetworkId::Devnet).expect("gather");
        assert_eq!(candidates.len(), 1);
        assert_eq!(
            candidates[0].state,
            WorkState::IncompletePostPay,
            "the candidate's class is the tag's"
        );
        assert_eq!(candidates[0].journal_state, Some(SealState::Paid));

        let listing = WorkListing::gather(&store).expect("list");
        let row = only_row(&listing);
        assert_eq!(row.state, WorkState::IncompletePostPay);
        assert_eq!(
            row.resume.as_ref().map(|hint| hint.clock),
            Some(ResumeClock::TimeBoxed)
        );

        let err = abandon(&unlocked, &seal_id).expect_err("a paid work is never abandoned");
        assert!(
            err.to_string().contains("a payment is recorded for work"),
            "{err}"
        );
    }

    /// **Window D (S11's post-pay abandon)**: tag `Abandoned` over a paid
    /// work, mirror still post-pay. Excluded from D45, listed abandoned, and
    /// `abandon` reports it already done.
    ///
    /// Red at 6e1cab3: "RESUME PROMPTLY" for an abandoned work; abandon exit
    /// 2 "already been paid for … Finish it instead by re-running …", whose
    /// re-run exits 2 "abandoned and cannot be resumed" — a dead end.
    #[test]
    fn s48_window_d_an_abandoned_tag_over_a_post_pay_mirror_is_abandoned_to_every_reader() {
        let (vault, work, seal_id) = vault_with_a_declined_work("d203-wd");
        let unlocked = vault.unlock();
        let store = WorkStore::new(&unlocked);
        journal_do(&unlocked, |j| {
            j.set_state(&seal_id, SealState::Anchored)
                .expect("anchored");
            j.put_receipt(&seal_id, &fixture_receipt())
                .expect("receipt");
            j.set_state(&seal_id, SealState::Paid).expect("paid");
            j.set_state(&seal_id, SealState::Abandoned)
                .expect("S11's abandon");
        });
        roll_mirror(&store, &seal_id, WorkState::IncompletePostPay, false);
        assert_window(
            &store,
            &seal_id,
            SealState::Abandoned,
            WorkState::IncompletePostPay,
        );

        assert!(
            gather_candidates(&store, NetworkId::Devnet)
                .expect("gather")
                .is_empty()
        );
        let exact = work
            .plan(&["a.txt", "--no-anchor"])
            .expect("plan validates");
        let decision = decide(&store, &exact);
        assert!(
            matches!(
                decision,
                Ok(ResumeDecision::Fresh {
                    incomplete_works: 0
                })
            ),
            "{decision:?}"
        );

        let listing = WorkListing::gather(&store).expect("list");
        let row = only_row(&listing);
        assert_eq!(row.state, WorkState::Abandoned);
        assert!(row.resume.is_none(), "{:?}", row.resume);

        let before = vault.fingerprint();
        let report = abandon(&unlocked, &seal_id).expect("already abandoned is an outcome");
        assert!(report.already, "{report:?}");
        assert_eq!(report.previous_state, Some(SealState::Abandoned));
        assert_eq!(vault.fingerprint(), before, "the abandon wrote nothing");
    }

    /// **Window E (D197's restart abandon, killed between its writes)**: a
    /// work whose staging never finished (no plan), abandoned by the
    /// restart, mirror still pre-pay. The exact re-run is `Fresh` — not
    /// `Restart`, not exit 2 — and seals the files afresh.
    ///
    /// Red at 6e1cab3: `detect` → `Resume` (`staging_never_finished` clause
    /// 3 needs the tag absent or `Staged`), then exit 2 on every run —
    /// D197's promise defeated by its own abandon's window.
    #[test]
    fn s48_window_e_a_restart_abandon_killed_between_its_writes_seals_afresh() {
        let work = Work::new("d203-we");
        work.file("a.txt", b"paragraph one\n\nparagraph two\n");
        let exact = work
            .plan(&["a.txt", "--no-anchor"])
            .expect("plan validates");
        let vault = IsolatedVault::create("d203-we");
        let session = SealSession::open(Arc::new(vault.unlock()));
        let store = WorkStore::new(session.vault());
        let seal_id = SealId::from_bytes([0x5E; 16]);
        journal_do(session.vault(), |j| {
            let w = MasterSecret::from_bytes([0x5E; 32]);
            j.begin(&WorkIdentity {
                w: w.secret_ref(),
                seal_id,
                network: exact.network.as_str().to_owned(),
                unanchored: exact.shaping.no_anchor,
                degraded: false,
                input_paths_as_given: exact.as_given_paths(),
                input_paths_absolute: exact.absolute_paths(),
                shaping: exact.shaping.clone(),
            })
            .expect("begin");
            let ciphertext = vec![0x5A_u8; 48];
            j.put_staged(
                &seal_id,
                &StagedBlob {
                    slot: BlobSlot::Unit { unit_id: 0 },
                    nonce: [0x5B; 24],
                    address: antseal_core::storage::compute_storage_address(&ciphertext)
                        .expect("under the chunk cap"),
                    ciphertext,
                },
            )
            .expect("stage one unit");
            j.set_state(&seal_id, SealState::Abandoned)
                .expect("the restart's abandon");
        });
        roll_mirror(&store, &seal_id, WorkState::IncompletePrePay, false);
        assert_window(
            &store,
            &seal_id,
            SealState::Abandoned,
            WorkState::IncompletePrePay,
        );

        let decision = decide(&store, &exact);
        assert!(
            matches!(
                decision,
                Ok(ResumeDecision::Fresh {
                    incomplete_works: 0
                })
            ),
            "{decision:?}"
        );

        let rerun = work
            .plan(&["a.txt", "--no-anchor", "--yes"])
            .expect("plan validates");
        let backend = MockBackend::new().with_balances(funded());
        let fresh = sealed(
            block_on(run_seal(
                &backend,
                &session,
                &rerun,
                &mut NeverAsked,
                &ctx(true),
                &mut rng(0x77),
                &mut rng(0x78),
            )),
            "the exact re-run must seal afresh",
        );
        assert!(!fresh.resumed);
        assert_ne!(fresh.seal_id, seal_id);
        assert_eq!(store.list_works().expect("list").len(), 2);
    }

    // ── R7 (S48 + S52): `complete()` writes its outcome first ────────

    /// A journal whose `Complete` transition fails, as a full disk would
    /// make it fail. Every other call reaches the real journal underneath.
    struct FailsTheCompleteTransition<'j, J> {
        inner: &'j J,
    }

    impl<J: SealJournal> SealJournal for FailsTheCompleteTransition<'_, J> {
        fn begin(&self, identity: &WorkIdentity<'_>) -> Result<(), JournalError> {
            self.inner.begin(identity)
        }
        fn put_staged(&self, seal_id: &SealId, blob: &StagedBlob) -> Result<(), JournalError> {
            self.inner.put_staged(seal_id, blob)
        }
        fn staged(&self, seal_id: &SealId, slot: BlobSlot) -> Result<StagedBlob, JournalError> {
            self.inner.staged(seal_id, slot)
        }
        fn staged_slots(&self, seal_id: &SealId) -> Result<Vec<BlobSlot>, JournalError> {
            self.inner.staged_slots(seal_id)
        }
        fn put_plan(&self, seal_id: &SealId, plan: &JournalPlan) -> Result<(), JournalError> {
            self.inner.put_plan(seal_id, plan)
        }
        fn plan(&self, seal_id: &SealId) -> Result<Option<JournalPlan>, JournalError> {
            self.inner.plan(seal_id)
        }
        fn set_state(&self, seal_id: &SealId, state: SealState) -> Result<(), JournalError> {
            if state == SealState::Complete {
                return Err(JournalError::Store(Box::new(StoreError::Io {
                    path: std::path::PathBuf::from("/test/vault/store/works/w/state"),
                    source: std::io::Error::new(std::io::ErrorKind::StorageFull, "test: disk full"),
                })));
            }
            self.inner.set_state(seal_id, state)
        }
        fn state(&self, seal_id: &SealId) -> Result<SealState, JournalError> {
            self.inner.state(seal_id)
        }
        fn put_receipt(
            &self,
            seal_id: &SealId,
            receipt: &PaymentReceipt,
        ) -> Result<(), JournalError> {
            self.inner.put_receipt(seal_id, receipt)
        }
        fn receipt(&self, seal_id: &SealId) -> Result<Option<PaymentReceipt>, JournalError> {
            self.inner.receipt(seal_id)
        }
        fn arm_receipts(&self, seal_id: &SealId, prior: Option<&PaymentReceipt>) {
            self.inner.arm_receipts(seal_id, prior);
        }
        fn receipts_unrecorded(&self) -> Option<ReceiptSinkFault> {
            self.inner.receipts_unrecorded()
        }
        fn put_consent(
            &self,
            seal_id: &SealId,
            consent: ConsentRecord,
        ) -> Result<(), JournalError> {
            self.inner.put_consent(seal_id, consent)
        }
        fn consent(&self, seal_id: &SealId) -> Result<Option<ConsentRecord>, JournalError> {
            self.inner.consent(seal_id)
        }
        fn recorded_identity(&self, seal_id: &SealId) -> Result<RecordedIdentity, JournalError> {
            self.inner.recorded_identity(seal_id)
        }
        /// Refuses rather than forwards: these rows seal with `--no-anchor`,
        /// so the gate is never run and no anchor slot is ever written.
        fn put_anchor(
            &self,
            _seal_id: &SealId,
            _slot: &str,
            _bytes: &[u8],
        ) -> Result<(), JournalError> {
            Err(JournalError::IllegalAnchorWrite {
                detail: "these rows never anchor, so this double refuses anchor writes",
            })
        }
        fn mark_degraded(&self, seal_id: &SealId) -> Result<(), JournalError> {
            self.inner.mark_degraded(seal_id)
        }
        fn record_outcome(
            &self,
            seal_id: &SealId,
            work_id: Option<[u8; 32]>,
            cost_atto: Option<u128>,
        ) -> Result<(), JournalError> {
            self.inner.record_outcome(seal_id, work_id, cost_atto)
        }
        fn incomplete_works(&self) -> Result<Vec<(SealId, Option<SealState>)>, JournalError> {
            self.inner.incomplete_works()
        }
    }

    /// **R7 (G-R7a)**: `complete()` writes its outcome — the work id AND the
    /// cost — before the `Complete` transition, so a failure (or a kill) at
    /// that transition leaves a `Finalizing` work whose meta already carries
    /// both, which the next resume finishes.
    ///
    /// Red at 6e1cab3: the tag was written first, so a failed transition
    /// left `cost_atto: None` (P1 §7.3's B2′ shape, one write earlier).
    #[test]
    fn s52_complete_records_its_outcome_before_the_complete_transition() {
        let (vault, _work, seal_id) = vault_with_a_declined_work("d203-r7a");
        let unlocked = vault.unlock();
        let store = WorkStore::new(&unlocked);
        assert_eq!(
            store.load_meta(&seal_id).expect("meta").cost_atto,
            None,
            "control: no cost is recorded before the payment"
        );

        let mock = MockBackend::new().with_balances(funded());
        let gate = crate::common::RecordingGate::new();
        let consent = crate::common::ScriptedConsent::always_yes();
        let mut r = rng(0xD7);
        let inner = VaultJournal::new(WorkStore::new(&unlocked), &mut r);
        let journal = FailsTheCompleteTransition { inner: &inner };
        let pipeline = Pipeline::new(&mock, &gate, &journal, &consent, &NoBarriers);
        let err = match block_on(pipeline.resume(&seal_id)) {
            Err(err) => err,
            Ok(_) => panic!("the Complete transition must fail"),
        };
        assert!(
            matches!(err, SealError::Journal(JournalError::Store(_))),
            "{err:?}"
        );
        // Control: everything up to the transition ran — paid and finalized.
        assert_eq!(
            recorded_state(&store, &seal_id).expect("tag"),
            Some(SealState::Finalizing)
        );
        let receipt = recorded_receipt(&store, &seal_id)
            .expect("receipt read")
            .expect("the payment is journaled");
        assert!(
            receipt.storage_cost_atto > 0,
            "the mock quotes a nonzero cost"
        );

        let meta = store.load_meta(&seal_id).expect("meta");
        assert!(
            meta.work_id.is_some(),
            "work id None after a failed Complete transition"
        );
        assert_eq!(
            meta.cost_atto,
            Some(receipt.storage_cost_atto),
            "cost None after a failed Complete transition: complete() must write its outcome \
             BEFORE the Complete tag (D203 R7)"
        );
    }

    /// One ordinary failure after the payment — run 1 pays, then the upload
    /// aborts after one stored blob (exit 23) — leaving a paid, incomplete
    /// work: P1 §7.4's CC sequence, run 1.
    fn paid_then_upload_failed(
        tag: &str,
        work: &Work,
    ) -> (
        IsolatedVault,
        SealSession,
        MockBackend,
        SealId,
        PaymentReceipt,
    ) {
        let plan = work
            .plan(&["a.txt", "--no-anchor", "--yes"])
            .expect("plan validates");
        let backend = MockBackend::new().with_balances(funded());
        backend.arm_fault(Fault::AfterStoringK(1));
        let vault = IsolatedVault::create(tag);
        let session = SealSession::open(Arc::new(vault.unlock()));
        match block_on(run_seal(
            &backend,
            &session,
            &plan,
            &mut NeverAsked,
            &ctx(true),
            &mut rng(0xC1),
            &mut rng(0xC2),
        )) {
            Err(err) => assert_eq!(err.exit_code(), 23, "an ordinary upload failure: {err}"),
            Ok(_) => panic!("run 1 must fail mid-upload"),
        }
        let (seal_id, receipt) = {
            let store = WorkStore::new(session.vault());
            let seal_id = store.list_works().expect("list")[0];
            let receipt = recorded_receipt(&store, &seal_id)
                .expect("receipt read")
                .expect("run 1's payment is journaled");
            assert!(
                receipt.storage_cost_atto > 0,
                "the mock quotes a nonzero cost"
            );
            assert!(
                !receipt.tx_map.is_empty(),
                "the receipt maps the quotes it paid"
            );
            assert_eq!(
                store.load_meta(&seal_id).expect("meta").cost_atto,
                None,
                "control: run 1 never completed, so nothing recorded a cost"
            );
            (seal_id, receipt)
        };
        (vault, session, backend, seal_id, receipt)
    }

    /// **S52 (G-R7b)**: the CC sequence finished by a resume that pays
    /// nothing records its cost from the journaled receipt, and `list`
    /// prints it as the work's cost.
    ///
    /// Red at 6e1cab3: `complete()` recorded a cost only `if paid_here`, so
    /// the work stayed "cost: not recorded (nothing paid)" for good
    /// (`[CC-after-run2] cost=None`).
    #[test]
    fn s52_a_work_paid_in_one_run_and_finished_by_a_resume_records_its_cost() {
        let work = Work::new("d203-r7b");
        work.file("a.txt", b"paragraph one\n\nparagraph two\n");
        let (_vault, session, backend, seal_id, receipt) =
            paid_then_upload_failed("d203-r7b", &work);
        let plan = work
            .plan(&["a.txt", "--no-anchor", "--yes"])
            .expect("plan validates");
        let finished = sealed(
            block_on(run_seal(
                &backend,
                &session,
                &plan,
                &mut NeverAsked,
                &ctx(true),
                &mut rng(0xC3),
                &mut rng(0xC4),
            )),
            "run 2 resumes and finishes",
        );
        assert!(finished.resumed);
        assert!(!finished.paid_here, "the resume paid nothing");
        assert_eq!(finished.seal_id, seal_id);

        let store = WorkStore::new(session.vault());
        assert_eq!(
            recorded_state(&store, &seal_id).expect("tag"),
            Some(SealState::Complete)
        );
        let after = recorded_receipt(&store, &seal_id)
            .expect("receipt read")
            .expect("present");
        assert_eq!(
            after.storage_cost_atto, receipt.storage_cost_atto,
            "control: the resume bought nothing"
        );
        assert_eq!(
            store.load_meta(&seal_id).expect("meta").cost_atto,
            Some(receipt.storage_cost_atto),
            "cost=None: a work paid in one run and finished by a resume must record its cost \
             (D203 R7)"
        );
        let text = WorkListing::gather(&store)
            .expect("list")
            .render()
            .join("\n");
        assert!(
            text.contains(&format!("  cost: {} atto-ANT\n", receipt.storage_cost_atto)),
            "{text}"
        );
    }

    // ── Money group (U109): `list` takes money from the receipt ──────

    /// **U109, D203 M3 (GM2)**: after run 1 of the CC sequence the meta
    /// records no cost, and `list` takes it from the money authority — the
    /// journaled receipt — "so far". `--json`'s `cost_atto` keeps the meta's
    /// value this wave (no JSON semantics move before U32).
    ///
    /// Red at 6e1cab3: "cost: not recorded (nothing paid)" two lines above
    /// "RESUME PROMPTLY: this seal is paid for" (`[CC-after-run1]`).
    #[test]
    fn u109_list_reads_the_cost_of_a_paid_incomplete_work_from_its_receipt() {
        let work = Work::new("d203-gm2");
        work.file("a.txt", b"paragraph one\n\nparagraph two\n");
        let (_vault, session, _backend, seal_id, receipt) =
            paid_then_upload_failed("d203-gm2", &work);
        let store = WorkStore::new(session.vault());
        let listing = WorkListing::gather(&store).expect("list");
        let row = only_row(&listing);
        assert_eq!(row.seal_id, seal_id);
        assert_eq!(
            row.resume.as_ref().map(|hint| hint.clock),
            Some(ResumeClock::TimeBoxed)
        );
        let text = listing.render().join("\n");
        let cost_line = format!(
            "  cost: {} atto-ANT so far (from the payment receipt)",
            receipt.storage_cost_atto
        );
        assert_eq!(text.matches(&cost_line).count(), 1, "{text}");
        assert!(!text.contains("nothing paid"), "{text}");
        assert!(!text.contains("nothing was paid"), "{text}");
        assert!(
            listing.json()["works"][0]["cost_atto"].is_null(),
            "--json keeps the meta's value: {}",
            listing.json()
        );
    }

    /// A pre-S50 first-sub-batch revert's capture: a receipt that maps no
    /// quote and moved no ANT (P1's window F). NON-SECRET synthetic bytes.
    fn revert_only_receipt() -> PaymentReceipt {
        PaymentReceipt {
            blobs: Vec::new(),
            tx_map: std::collections::BTreeMap::new(),
            txs: vec![TxRecord {
                tx_hash: TxHash::from_bytes([0xB3; 32]),
                block_number: Some(43),
                status: TxStatus::Reverted,
                quote_hashes: vec![QuoteHash::from_bytes([0xB1; 32])],
            }],
            storage_cost_atto: 0,
            gas: GasSummary {
                gas_cost_wei: 21_000,
            },
        }
    }

    /// What `list` must say about one shape of D203 M1's money table.
    struct MoneyCase {
        label: &'static str,
        listing: WorkListing,
        clock: ResumeClock,
        note: &'static str,
        cost_line: String,
    }

    /// **U109, D203 M1–M3 (GM1)**: `list` takes its money claims from the
    /// receipt — `time-boxed` iff the vault holds a receipt mapping at least
    /// one quote to a transaction — and says "no payment is recorded", never
    /// "nothing was paid", where it holds none. The five shapes are P1
    /// §7.7's (a)–(e).
    ///
    /// Red at 6e1cab3: (a) — the vault after an exit 37 with no durable
    /// capture — says "nothing was paid", which the vault cannot know; (c) —
    /// a stranded payment — is on the re-quote clock, "nothing was paid".
    #[test]
    fn u109_list_states_money_from_the_receipt_in_every_case() {
        let mut cases = Vec::new();

        // (a) consent recorded, tag `Anchored`, no receipt: exit 37 with no
        // durable capture — and equally a pre-landing `Payment` failure.
        {
            let (vault, _work, seal_id) = vault_with_a_declined_work("d203-ma");
            let unlocked = vault.unlock();
            journal_do(&unlocked, |j| {
                j.put_consent(
                    &seal_id,
                    ConsentRecord {
                        total_ant_atto: 18_498,
                        gas_estimate_wei: 23_000,
                        consent_time_unix_secs: 1_800_000_000,
                        channel: ConsentChannel::YesFlag,
                    },
                )
                .expect("consent");
                j.set_state(&seal_id, SealState::Anchored)
                    .expect("anchored");
            });
            cases.push(MoneyCase {
                label: "(a) consent, anchored, no receipt",
                listing: WorkListing::gather(&WorkStore::new(&unlocked)).expect("list"),
                clock: ResumeClock::ReQuote,
                note: RE_QUOTE_NOTE,
                cost_line: NO_COST_LINE.to_owned(),
            });
        }
        // (b) a pre-S50 revert-only receipt (maps no quote) on `Anchored`.
        {
            let (vault, _work, seal_id) = vault_with_a_declined_work("d203-mb");
            let unlocked = vault.unlock();
            journal_do(&unlocked, |j| {
                j.set_state(&seal_id, SealState::Anchored)
                    .expect("anchored");
                j.put_receipt(&seal_id, &revert_only_receipt())
                    .expect("revert capture");
            });
            cases.push(MoneyCase {
                label: "(b) revert-only receipt",
                listing: WorkListing::gather(&WorkStore::new(&unlocked)).expect("list"),
                clock: ResumeClock::ReQuote,
                note: RE_QUOTE_NOTE,
                cost_line: NO_COST_LINE.to_owned(),
            });
        }
        // (c) stranded: `Anchored` + a receipt mapping a quote (exit 28).
        {
            let (vault, _work, seal_id) = vault_with_a_declined_work("d203-mc");
            let unlocked = vault.unlock();
            journal_do(&unlocked, |j| {
                j.set_state(&seal_id, SealState::Anchored)
                    .expect("anchored");
                j.put_receipt(&seal_id, &fixture_receipt())
                    .expect("capture");
            });
            cases.push(MoneyCase {
                label: "(c) stranded",
                listing: WorkListing::gather(&WorkStore::new(&unlocked)).expect("list"),
                clock: ResumeClock::TimeBoxed,
                note: TIME_BOXED_NOTE,
                cost_line: "  cost: 4200 atto-ANT so far (from the payment receipt)".to_owned(),
            });
        }
        // (d) a normal `Paid` work: receipt, then the `Paid` tag.
        {
            let (vault, _work, seal_id) = vault_with_a_declined_work("d203-md");
            let unlocked = vault.unlock();
            journal_do(&unlocked, |j| {
                j.set_state(&seal_id, SealState::Anchored)
                    .expect("anchored");
                j.put_receipt(&seal_id, &fixture_receipt())
                    .expect("receipt");
                j.set_state(&seal_id, SealState::Paid).expect("paid");
            });
            cases.push(MoneyCase {
                label: "(d) paid",
                listing: WorkListing::gather(&WorkStore::new(&unlocked)).expect("list"),
                clock: ResumeClock::TimeBoxed,
                note: TIME_BOXED_NOTE,
                cost_line: "  cost: 4200 atto-ANT so far (from the payment receipt)".to_owned(),
            });
        }
        // (e) D197's pre-staging work: `begin` only, no plan.
        {
            let work = Work::new("d203-me");
            work.file("a.txt", b"paragraph one\n\nparagraph two\n");
            let plan = work
                .plan(&["a.txt", "--no-anchor"])
                .expect("plan validates");
            let vault = IsolatedVault::create("d203-me");
            let unlocked = vault.unlock();
            journal_do(&unlocked, |j| {
                let w = MasterSecret::from_bytes([0x6E; 32]);
                j.begin(&WorkIdentity {
                    w: w.secret_ref(),
                    seal_id: SealId::from_bytes([0x6E; 16]),
                    network: plan.network.as_str().to_owned(),
                    unanchored: plan.shaping.no_anchor,
                    degraded: false,
                    input_paths_as_given: plan.as_given_paths(),
                    input_paths_absolute: plan.absolute_paths(),
                    shaping: plan.shaping.clone(),
                })
                .expect("begin");
            });
            cases.push(MoneyCase {
                label: "(e) pre-staging",
                listing: WorkListing::gather(&WorkStore::new(&unlocked)).expect("list"),
                clock: ResumeClock::ReQuote,
                note: RE_QUOTE_NOTE,
                cost_line: NO_COST_LINE.to_owned(),
            });
        }

        assert_eq!(cases.len(), 5, "P1 §7.7's five shapes");
        let mut wrong = Vec::new();
        for case in &cases {
            let row = only_row(&case.listing);
            let clock = row.resume.as_ref().map(|hint| hint.clock);
            if clock != Some(case.clock) {
                wrong.push(format!(
                    "{}: clock {clock:?}, expected {:?}",
                    case.label, case.clock
                ));
            }
            let text = case.listing.render().join("\n");
            let note_line = format!("  {}\n", case.note);
            if !text.contains(&note_line) {
                wrong.push(format!("{}: note missing, rendered:\n{text}", case.label));
            }
            if text.lines().filter(|line| *line == case.cost_line).count() != 1 {
                wrong.push(format!(
                    "{}: cost line {:?} missing, rendered:\n{text}",
                    case.label, case.cost_line
                ));
            }
            if text.contains("nothing was paid") || text.contains("nothing paid") {
                wrong.push(format!(
                    "{}: claims nothing was paid, rendered:\n{text}",
                    case.label
                ));
            }
        }
        assert!(wrong.is_empty(), "money claims:\n{}", wrong.join("\n"));
    }

    // ── The two predicates, as truth tables ──────────────────────────

    /// **D203 R1**: the fine tag decides wherever one exists, whatever the
    /// mirror says; the mirror answers only for an absent tag.
    #[test]
    fn d203_r1_the_effective_state_is_the_tags_and_the_mirrors_only_without_one() {
        let mirrors = [
            WorkState::IncompletePrePay,
            WorkState::IncompletePostPay,
            WorkState::Complete,
            WorkState::Abandoned,
        ];
        let mut rows = 0;
        for mirror in mirrors {
            for tag in SealState::ALL {
                assert_eq!(
                    effective_work_state(Some(tag), mirror),
                    tag.work_state(),
                    "{tag:?} over a {mirror:?} mirror"
                );
                rows += 1;
            }
            assert_eq!(effective_work_state(None, mirror), mirror);
            rows += 1;
        }
        assert_eq!(rows, 4 * 6 + 4, "every tag over every mirror, and no tag");
    }

    /// **D203 M1**: a payment is recorded exactly when a journaled receipt
    /// maps at least one quote to a transaction — a `Submitted` mapping
    /// included (money may have moved), a revert-only receipt excluded.
    #[test]
    fn d203_m1_a_payment_is_recorded_iff_a_receipt_maps_a_quote() {
        let mut submitted = fixture_receipt();
        submitted.txs[0].status = TxStatus::Submitted;
        submitted.txs[0].block_number = None;
        let cases = [
            ("no receipt", None, false),
            ("a revert-only receipt", Some(revert_only_receipt()), false),
            ("a confirmed mapping", Some(fixture_receipt()), true),
            ("a submitted mapping", Some(submitted), true),
        ];
        assert_eq!(cases.len(), 4);
        for (label, receipt, expected) in &cases {
            assert_eq!(payment_recorded(receipt.as_ref()), *expected, "{label}");
        }
    }

    /// **D203 M1's edge (the orchestrator's question): a zero-payment seal.**
    /// Sealing identical ciphertexts twice (same seeds, same files) makes
    /// the second seal's quote price nothing — every chunk is already stored.
    /// Its `pay` moves no ANT and journals a receipt that maps no quote, so
    /// `payment_recorded` is false and `list` says "no payment is recorded"
    /// — literally true. Its upload refused (exit 23), the work is tagged
    /// post-pay (`Finalizing`) yet on the re-quote clock, by the receipt;
    /// finished by a resume that buys nothing, its recorded cost is the
    /// receipt's: 0.
    #[test]
    fn u109_a_zero_payment_seal_records_no_payment_and_says_so() {
        let work = Work::new("d203-zero");
        work.file("a.txt", b"paragraph one\n\nparagraph two\n");
        let plan = work
            .plan(&["a.txt", "--no-anchor", "--yes"])
            .expect("plan validates");
        let backend = MockBackend::new().with_balances(funded());

        // Seal once into vault A: the backend now holds every chunk.
        let first_vault = IsolatedVault::create("d203-zero-a");
        let first = SealSession::open(Arc::new(first_vault.unlock()));
        let sealed_once = sealed(
            block_on(run_seal(
                &backend,
                &first,
                &plan,
                &mut NeverAsked,
                &ctx(true),
                &mut rng(0xE1),
                &mut rng(0xE2),
            )),
            "the first seal completes",
        );
        assert!(sealed_once.paid_here);

        // The same seal into vault B, its upload refused once (exit 23).
        let vault = IsolatedVault::create("d203-zero-b");
        let session = SealSession::open(Arc::new(vault.unlock()));
        backend.arm_fault(Fault::NetworkOn(Method::FinalizeBatch));
        match block_on(run_seal(
            &backend,
            &session,
            &plan,
            &mut NeverAsked,
            &ctx(true),
            &mut rng(0xE1),
            &mut rng(0xE2),
        )) {
            Err(err) => assert_eq!(err.exit_code(), 23, "{err}"),
            Ok(_) => panic!("the upload must fail once"),
        }
        let store = WorkStore::new(session.vault());
        let seal_id = store.list_works().expect("list")[0];
        let receipt = recorded_receipt(&store, &seal_id)
            .expect("receipt read")
            .expect("pay journals a receipt even when it buys nothing");
        // What a zero-payment `pay` journals: no transaction, no mapping.
        assert!(receipt.txs.is_empty(), "{:?}", receipt.txs);
        assert!(receipt.tx_map.is_empty());
        assert_eq!(receipt.storage_cost_atto, 0);
        assert!(!payment_recorded(Some(&receipt)));
        // `finalize` writes `Finalizing` before it calls `finalize_batch`.
        assert_eq!(
            recorded_state(&store, &seal_id).expect("tag"),
            Some(SealState::Finalizing)
        );

        let listing = WorkListing::gather(&store).expect("list");
        let row = only_row(&listing);
        assert_eq!(
            row.resume.as_ref().map(|hint| hint.clock),
            Some(ResumeClock::ReQuote),
            "the clock is the receipt's, not the post-pay tag's"
        );
        let text = listing.render().join("\n");
        assert!(text.contains(&format!("  {RE_QUOTE_NOTE}\n")), "{text}");
        assert_eq!(
            text.lines().filter(|line| *line == NO_COST_LINE).count(),
            1,
            "{text}"
        );

        // The resume buys nothing and records the receipt's cost: 0.
        let finished = sealed(
            block_on(run_seal(
                &backend,
                &session,
                &plan,
                &mut NeverAsked,
                &ctx(true),
                &mut rng(0xE3),
                &mut rng(0xE4),
            )),
            "the resume finishes",
        );
        assert!(finished.resumed);
        assert!(!finished.paid_here);
        assert_eq!(store.load_meta(&seal_id).expect("meta").cost_atto, Some(0));
        let text = WorkListing::gather(&store)
            .expect("list")
            .render()
            .join("\n");
        assert!(text.contains("  cost: 0 atto-ANT\n"), "{text}");
    }
}

// ─────────────────────────────────────────────────────────────────────
// D203's money group, second half (wave 40, U110): the resume plan, the
// `Paid` tag and the abandon screens take money from the receipt
// ─────────────────────────────────────────────────────────────────────

/// **U110** (D203 M4–M6, M6a–M6c): the resume plan's money lines, the
/// `Paid` tag and the abandon screens follow the money authority — a
/// journaled receipt that maps at least one quote to a transaction
/// (`payment_recorded`, D203 M1) — never the state tag or a receipt's mere
/// existence. Every row starts from a real declined seal
/// ([`vault_with_a_declined_work`]) and plants its shape with the journal's
/// own writers. NON-SECRET values only.
mod u110 {
    use super::*;

    use antseal_cli::error::CliError;
    use antseal_cli::pipeline::journal::{WorkIdentity, recorded_state};
    use antseal_cli::pipeline::receipt_sink::recorded_receipt;
    use antseal_cli::pipeline::{NoBarriers, Pipeline, SealState};
    use antseal_cli::seal_resume::AbandonPreview;
    use antseal_cli::vault::session::UnlockedVault;
    use antseal_cli::vault::store::{ConsentChannel, ConsentRecord};
    use antseal_core::crypto::secrets::MasterSecret;
    use antseal_net::{GasSummary, PaymentReceipt, QuoteHash, TxHash, TxRecord, TxStatus};

    /// D203 M4's two lines for an `Anchored` work whose vault records a
    /// payment: true of a receipt that covers every blob (a kill between
    /// the receipt and the `Paid` tag) and of one that covers some — then
    /// `list`'s proof clock, which every plan over a recorded payment closes
    /// on (D210 R2).
    const PLAN_PAYMENT_RECORDED: [&str; 3] = [
        "    staged:    staged and past its anchor step; a payment is recorded",
        "    remaining: pay the rest, if any, then upload",
        "    RESUME PROMPTLY: a payment for this seal is recorded, and its payment proofs stay \
         usable for uploading only about a day — after that, finishing it costs a second payment",
    ];
    /// D203 M4's two lines for an `Anchored` work whose vault records none.
    const PLAN_NO_PAYMENT: [&str; 2] = [
        "    staged:    staged and past its anchor step; no payment recorded",
        "    remaining: pay, upload",
    ];
    /// Money claims the vault cannot back where it records no payment
    /// (D203 M1's wording rule).
    const UNBACKED: [&str; 4] = [
        "not paid",
        "nothing paid",
        "Nothing was paid",
        "nothing was paid",
    ];

    fn rng(seed: u8) -> ChaCha20Rng {
        ChaCha20Rng::from_seed([seed; 32])
    }

    /// Run `body` against a fresh [`VaultJournal`] over `vault`.
    fn journal_do(vault: &UnlockedVault, body: impl FnOnce(&VaultJournal<'_, ChaCha20Rng>)) {
        let mut r = rng(0x77);
        let journal = VaultJournal::new(WorkStore::new(vault), &mut r);
        body(&journal);
    }

    /// The record a granted consent writes (`consent_anchor_pay`): every
    /// work the pipeline anchored or paid for carries one.
    fn consent_record() -> ConsentRecord {
        ConsentRecord {
            total_ant_atto: 18_498,
            gas_estimate_wei: 23_000,
            consent_time_unix_secs: 1_800_000_000,
            channel: ConsentChannel::YesFlag,
        }
    }

    /// A first-sub-batch revert's capture as builds before S50 journaled it:
    /// a receipt that maps no quote and moved no ANT (P1's window F).
    fn revert_only_receipt() -> PaymentReceipt {
        PaymentReceipt {
            blobs: Vec::new(),
            tx_map: std::collections::BTreeMap::new(),
            txs: vec![TxRecord {
                tx_hash: TxHash::from_bytes([0xB3; 32]),
                block_number: Some(43),
                status: TxStatus::Reverted,
                quote_hashes: vec![QuoteHash::from_bytes([0xB1; 32])],
            }],
            storage_cost_atto: 0,
            gas: GasSummary {
                gas_cost_wei: 21_000,
            },
        }
    }

    /// A declined seal planted into shape (c): consent recorded, the tag
    /// `Anchored`, and `receipt` journaled as a stranded payment leaves it.
    fn anchored_with(tag: &str, receipt: Option<&PaymentReceipt>) -> (IsolatedVault, Work, SealId) {
        let (vault, work, seal_id) = vault_with_a_declined_work(tag);
        let unlocked = vault.unlock();
        journal_do(&unlocked, |j| {
            j.put_consent(&seal_id, consent_record()).expect("consent");
            j.set_state(&seal_id, SealState::Anchored)
                .expect("Staged → Anchored");
            if let Some(receipt) = receipt {
                j.put_receipt(&seal_id, receipt).expect("the capture");
            }
        });
        drop(unlocked);
        (vault, work, seal_id)
    }

    fn tag(session: &SealSession, seal_id: &SealId) -> Option<SealState> {
        recorded_state(&WorkStore::new(session.vault()), seal_id).expect("tag read")
    }

    /// The resume plan `seal --dry-run` prints for an exact match (D45 §5):
    /// the production renderer, through its one caller.
    fn dry_run_plan(session: &SealSession, work: &Work) -> Result<Vec<String>, CliError> {
        let plan = work
            .plan(&["a.txt", "--no-anchor", "--dry-run"])
            .expect("plan validates");
        let backend = MockBackend::new().with_balances(funded());
        let outcome = block_on(run_seal(
            &backend,
            session,
            &plan,
            &mut NeverAsked,
            &ctx(true),
            &mut rng(0x91),
            &mut rng(0x92),
        ));
        for method in [Method::Balances, Method::QuoteBatch, Method::Pay] {
            assert_eq!(
                backend.calls(method),
                0,
                "a resume rehearsal calls {method:?}"
            );
        }
        match outcome {
            Ok(SealCommandResult::ResumePlan(lines)) => Ok(lines),
            Ok(_) => panic!("an exact match rehearses the resume plan"),
            Err(err) => Err(err),
        }
    }

    /// The exact re-run, interactive with no `--yes`: `prompt` answers the
    /// consent question if one is asked. `Ok` only for `Sealed`.
    fn rerun_asking<P: ConsentPrompt>(
        session: &SealSession,
        work: &Work,
        backend: &MockBackend,
        prompt: &mut P,
        seed: u8,
    ) -> Result<antseal_cli::seal_run::SealReport, CliError> {
        let plan = work
            .plan(&["a.txt", "--no-anchor"])
            .expect("plan validates");
        sealed_report(block_on(run_seal(
            backend,
            session,
            &plan,
            prompt,
            &ctx(false),
            &mut rng(seed),
            &mut rng(seed.wrapping_add(1)),
        )))
    }

    /// The exact re-run as a script runs it: `--yes`, machine mode.
    fn rerun_yes(
        session: &SealSession,
        work: &Work,
        backend: &MockBackend,
        seed: u8,
    ) -> Result<antseal_cli::seal_run::SealReport, CliError> {
        let plan = work
            .plan(&["a.txt", "--no-anchor", "--yes"])
            .expect("plan validates");
        sealed_report(block_on(run_seal(
            backend,
            session,
            &plan,
            &mut NeverAsked,
            &ctx(true),
            &mut rng(seed),
            &mut rng(seed.wrapping_add(1)),
        )))
    }

    fn sealed_report(
        outcome: Result<SealCommandResult, CliError>,
    ) -> Result<antseal_cli::seal_run::SealReport, CliError> {
        match outcome {
            Ok(SealCommandResult::Sealed(report)) => Ok(report),
            Ok(_) => panic!("a non-dry-run seal returns Sealed"),
            Err(err) => Err(err),
        }
    }

    /// **U110, D203 M4 + M5 (GM3)** — cases (c) and (c2). A stranded
    /// payment (tag `Anchored`, a receipt mapping one quote and recording
    /// no blob, so every staged blob is still owed) says so in its plan;
    /// DECLINING the remainder's consent leaves the tag `Anchored`, so the
    /// next plan says the same thing again rather than "PAID … upload only
    /// (no further payment)"; and the consenting re-run pays the rest once
    /// and finishes — M5's proof that `finalize` still runs on the path
    /// that pays a remainder.
    ///
    /// Red at L-RESUME2's tree: the plan said "staged and anchored; nothing
    /// paid" / "pay, upload", and the early repair tagged the work `Paid`
    /// before the remainder's consent (P1's `[c2-after] fine=Some(Paid)`).
    #[test]
    fn u110_a_declined_remainder_leaves_the_tag_pre_pay_and_the_plan_says_the_rest_is_owed() {
        let (vault, work, seal_id) = anchored_with("u110-gm3", Some(&fixture_receipt()));
        let session = SealSession::open(Arc::new(vault.unlock()));
        let partial = recorded_receipt(&WorkStore::new(session.vault()), &seal_id)
            .expect("receipt read")
            .expect("the stranded capture is journaled");
        assert!(
            !partial.tx_map.is_empty() && partial.blobs.is_empty(),
            "control: a payment is recorded and it covers no blob"
        );
        assert_eq!(tag(&session, &seal_id), Some(SealState::Anchored));

        let plan_c = dry_run_plan(&session, &work).expect("(c) rehearses");
        assert_eq!(plan_c.len(), 4, "(c): {plan_c:?}");
        assert_eq!(&plan_c[1..], &PLAN_PAYMENT_RECORDED[..], "(c)");

        // (c2): the exact re-run, DECLINED at the remainder's consent.
        let backend = MockBackend::new().with_balances(funded());
        let declined = rerun_asking(&session, &work, &backend, &mut SaysNo, 0xD1)
            .expect_err("the remainder's consent is declined");
        assert_eq!(
            declined.class(),
            ErrorClass::ConsentNotObtained,
            "{declined}"
        );
        assert_eq!(
            backend.calls(Method::QuoteBatch),
            1,
            "control: the remainder was quoted, and priced, before the question"
        );
        assert_eq!(
            backend.calls(Method::Pay),
            0,
            "a declined remainder pays nothing"
        );
        assert_eq!(
            tag(&session, &seal_id),
            Some(SealState::Anchored),
            "fine=Some(Paid) after a declined remainder: the early repair ran before the \
             remainder's consent, so the tag claims a payment the user just declined (D203 M5)"
        );
        let plan_c2 = dry_run_plan(&session, &work).expect("(c2) rehearses");
        assert_eq!(
            plan_c2, plan_c,
            "(c2): the plan still says the rest is owed"
        );

        // The consenting re-run pays the rest exactly once and finishes.
        let backend = MockBackend::new().with_balances(funded());
        let report = match rerun_yes(&session, &work, &backend, 0xD3) {
            Ok(report) => report,
            Err(err) => panic!("the consenting re-run finishes: {err}"),
        };
        assert!(report.resumed);
        assert!(report.paid_here, "the remainder was paid by this run");
        assert_eq!(report.seal_id, seal_id);
        assert_eq!(backend.calls(Method::Pay), 1);
        assert_eq!(tag(&session, &seal_id), Some(SealState::Complete));
        let merged = recorded_receipt(&WorkStore::new(session.vault()), &seal_id)
            .expect("receipt read")
            .expect("present");
        assert!(
            merged
                .tx_map
                .contains_key(&QuoteHash::from_bytes([0xB1; 32])),
            "the merge kept the stranded mapping"
        );
    }

    /// **D203 M5, the nothing-to-buy path.** A recorded payment on a
    /// pre-pay tag whose remainder quote prices nothing — every uncovered
    /// blob is already on the network — is repaired to `Paid` with no
    /// question asked, and `finalize` runs. (A full receipt, the other
    /// repair path, is `seal_matrix.rs`'s
    /// `barrier_post_pay_is_atomic_only_because_of_the_capture_hook`.)
    #[test]
    fn u110_a_remainder_that_prices_nothing_is_repaired_to_paid_and_finalized() {
        let (vault, work, seal_id) = anchored_with("u110-m5-nothing", Some(&fixture_receipt()));
        let session = SealSession::open(Arc::new(vault.unlock()));
        let backend = MockBackend::new().with_balances(funded());
        let mut preloaded = 0;
        journal_do(session.vault(), |j| {
            for slot in j.staged_slots(&seal_id).expect("staged slots") {
                let blob = j.staged(&seal_id, slot).expect("staged blob");
                backend.preload_third_party(&blob.ciphertext);
                preloaded += 1;
            }
        });
        assert!(
            preloaded >= 2,
            "control: units and the manifest are staged ({preloaded})"
        );

        // Interactive with no `--yes`, and a prompt that panics if asked:
        // nothing remains to buy, so nothing may be asked.
        let report = match rerun_asking(&session, &work, &backend, &mut NeverAsked, 0xD5) {
            Ok(report) => report,
            Err(err) => panic!("a remainder that prices nothing finishes: {err}"),
        };
        assert!(report.resumed);
        assert!(!report.paid_here, "nothing was bought");
        assert_eq!(
            backend.calls(Method::QuoteBatch),
            1,
            "the remainder was quoted"
        );
        assert_eq!(backend.calls(Method::Pay), 0);
        assert_eq!(tag(&session, &seal_id), Some(SealState::Complete));
        assert_eq!(
            WorkStore::new(session.vault())
                .load_meta(&seal_id)
                .expect("meta")
                .cost_atto,
            Some(fixture_receipt().storage_cost_atto),
            "the cost is the journaled receipt's (D203 R7)"
        );
    }

    /// **U110, D203 M4 + M6 + M6a (GM4)** — case (a): the vault after an
    /// exit 37 with no durable capture, or a `Payment` failure before any
    /// landing (consent recorded, tag `Anchored`, no receipt). Nothing in
    /// it says whether money moved, so the plan, the preview, the question
    /// and the report each say no payment is recorded — never that nothing
    /// was paid.
    ///
    /// Red at L-RESUME2's tree: "staged and anchored; nothing paid",
    /// "staged and past its anchor step; not paid", "Nothing was paid for
    /// it" (question and report).
    #[test]
    fn u110_with_no_payment_recorded_the_plan_and_the_abandon_screens_say_so() {
        let (vault, work, seal_id) = anchored_with("u110-gm4", None);
        let session = SealSession::open(Arc::new(vault.unlock()));
        let store = WorkStore::new(session.vault());
        assert!(
            recorded_receipt(&store, &seal_id).expect("read").is_none(),
            "control: no receipt"
        );
        assert!(
            store.load_meta(&seal_id).expect("meta").consent.is_some(),
            "control: the consent record exists"
        );

        let plan = dry_run_plan(&session, &work).expect("rehearses");
        assert_eq!(plan.len(), 3, "{plan:?}");
        assert_eq!(&plan[1..], &PLAN_NO_PAYMENT[..]);

        let mut r = rng(0x68);
        let journal = VaultJournal::new(WorkStore::new(session.vault()), &mut r);
        let preview = AbandonPreview::read(&store, &journal, &seal_id)
            .expect("the preview reads")
            .expect("no payment recorded: the preview is shown");
        let lines = preview.render();
        assert_eq!(lines.len(), 6, "{lines:?}");
        assert_eq!(
            lines[4],
            "  progress: staged and past its anchor step; no payment recorded"
        );
        let question = preview.question();
        assert_eq!(
            question,
            format!(
                "Abandon interrupted seal {}? No payment is recorded for it; the staged work can \
                 no longer be used. [y/N] ",
                seal_hex(&seal_id)
            )
        );
        let report = abandon_pre_pay(&store, &journal, &seal_id).expect("abandoned");
        assert!(!report.already);
        let rendered = report.render();
        assert_eq!(rendered.len(), 3, "{rendered:?}");
        assert!(
            rendered[1].starts_with("  No payment is recorded for it and nothing was uploaded. "),
            "{rendered:?}"
        );

        let screens = [
            plan.join("\n"),
            lines.join("\n"),
            question,
            rendered.join("\n"),
        ];
        assert_eq!(screens.len(), 4);
        for screen in &screens {
            for claim in UNBACKED {
                assert!(
                    !screen.contains(claim),
                    "a claim the vault cannot back ({claim:?}):\n{screen}"
                );
            }
        }
    }

    /// One work in each progress arm of the preview that carries a money
    /// word: 0 — `begin` only (no plan, the tag `Staged`: D197's shape);
    /// 1 — a declined seal (plan journaled, the tag `Staged`); 2 — the same,
    /// past its anchor step (the tag `Anchored`).
    fn preview_arm(index: usize, label: &str) -> (IsolatedVault, SealId) {
        if index == 0 {
            let vault = IsolatedVault::create(label);
            let work = Work::new(label);
            work.file("a.txt", b"paragraph one\n\nparagraph two\n");
            let plan = work
                .plan(&["a.txt", "--no-anchor"])
                .expect("plan validates");
            let seal_id = SealId::from_bytes([0x6B; 16]);
            let unlocked = vault.unlock();
            journal_do(&unlocked, |j| {
                let w = MasterSecret::from_bytes([0x6B; 32]);
                j.begin(&WorkIdentity {
                    w: w.secret_ref(),
                    seal_id,
                    network: plan.network.as_str().to_owned(),
                    unanchored: plan.shaping.no_anchor,
                    degraded: false,
                    input_paths_as_given: plan.as_given_paths(),
                    input_paths_absolute: plan.absolute_paths(),
                    shaping: plan.shaping.clone(),
                })
                .expect("begin");
            });
            drop(unlocked);
            return (vault, seal_id);
        }
        let (vault, _work, seal_id) = vault_with_a_declined_work(label);
        if index == 2 {
            let unlocked = vault.unlock();
            journal_do(&unlocked, |j| {
                j.set_state(&seal_id, SealState::Anchored)
                    .expect("Staged → Anchored");
            });
        }
        (vault, seal_id)
    }

    /// **D203 M6b**: the preview says "not paid" only where the vault itself
    /// proves no payment could have started — it holds no consent record,
    /// and the pipeline's one `pay` call comes after that record's write —
    /// and "no payment recorded" wherever a consent exists. The rule holds in
    /// each of the three progress arms that carry a money word.
    #[test]
    fn u110_the_previews_money_word_is_the_consent_records() {
        let arms = [
            "staging was interrupted before it finished",
            "staged",
            "staged and past its anchor step",
        ];
        let mut rows = 0;
        for consented in [false, true] {
            for (index, progress) in arms.iter().enumerate() {
                let label = format!("u110-m6b-{index}-{consented}");
                let (vault, seal_id) = preview_arm(index, &label);
                let unlocked = vault.unlock();
                if consented {
                    journal_do(&unlocked, |j| {
                        j.put_consent(&seal_id, consent_record()).expect("consent");
                    });
                }
                let money = if consented {
                    "no payment recorded"
                } else {
                    "not paid"
                };
                assert_eq!(
                    preview_progress(&unlocked, &seal_id),
                    format!("  progress: {progress}; {money}"),
                    "{label}"
                );
                rows += 1;
            }
        }
        assert_eq!(rows, 6, "three arms, with and without a consent record");
    }

    /// The preview's progress line for `seal_id`.
    fn preview_progress(vault: &UnlockedVault, seal_id: &SealId) -> String {
        let store = WorkStore::new(vault);
        let mut r = rng(0x6A);
        let journal = VaultJournal::new(WorkStore::new(vault), &mut r);
        let preview = AbandonPreview::read(&store, &journal, seal_id)
            .expect("the preview reads")
            .expect("no payment recorded: the preview is shown");
        let lines = preview.render();
        assert_eq!(lines.len(), 6, "{lines:?}");
        lines[4].clone()
    }

    /// **U110, D203 M6 (GM5)** — case (b): a revert-only receipt written
    /// before S50 records no payment, so it blocks neither `antseal
    /// abandon` (the preview is shown and the engine abandons) nor the
    /// pre-pay resume — which re-quotes, re-consents and pays once, and
    /// whose receipt REPLACES the legacy capture (the pre-pay path carries
    /// no prior; the receipt branch would have merged the reverted tx in).
    ///
    /// Red at L-RESUME2's tree: the preview was suppressed and abandon
    /// refused "already been paid for", both keyed on `receipt.is_some()`.
    #[test]
    fn u110_a_revert_only_receipt_blocks_neither_abandon_nor_the_pre_pay_resume() {
        // Abandon.
        {
            let (vault, _work, seal_id) =
                anchored_with("u110-gm5-abandon", Some(&revert_only_receipt()));
            let unlocked = vault.unlock();
            let store = WorkStore::new(&unlocked);
            let mut r = rng(0x69);
            let journal = VaultJournal::new(WorkStore::new(&unlocked), &mut r);
            let preview =
                AbandonPreview::read(&store, &journal, &seal_id).expect("the preview reads");
            let Some(preview) = preview else {
                panic!("the preview was suppressed for a work whose only receipt maps no quote");
            };
            assert_eq!(
                preview.render()[4],
                "  progress: staged and past its anchor step; no payment recorded"
            );
            let report = match abandon_pre_pay(&store, &journal, &seal_id) {
                Ok(report) => report,
                Err(err) => {
                    panic!("abandon refused a work whose only receipt maps no quote: {err}")
                }
            };
            assert!(!report.already);
            assert_eq!(
                recorded_state(&store, &seal_id).expect("tag"),
                Some(SealState::Abandoned)
            );
        }
        // The pre-pay resume.
        {
            let (vault, work, seal_id) =
                anchored_with("u110-gm5-resume", Some(&revert_only_receipt()));
            let session = SealSession::open(Arc::new(vault.unlock()));
            let plan = dry_run_plan(&session, &work).expect("rehearses");
            assert_eq!(&plan[1..], &PLAN_NO_PAYMENT[..]);
            let backend = MockBackend::new().with_balances(funded());
            let report = match rerun_yes(&session, &work, &backend, 0xB5) {
                Ok(report) => report,
                Err(err) => panic!("the consenting re-run finishes: {err}"),
            };
            assert!(report.resumed);
            assert!(report.paid_here);
            assert_eq!(backend.calls(Method::Pay), 1);
            assert_eq!(tag(&session, &seal_id), Some(SealState::Complete));
            let receipt = recorded_receipt(&WorkStore::new(session.vault()), &seal_id)
                .expect("receipt read")
                .expect("present");
            assert!(
                !receipt.tx_map.is_empty(),
                "control: the new payment is recorded"
            );
            let legacy = TxHash::from_bytes([0xB3; 32]);
            assert!(
                receipt.txs.iter().all(|tx| tx.tx_hash != legacy),
                "the legacy revert-only capture survived into the final receipt: the resume took \
                 the receipt branch, not the pre-pay path (D203 M6)"
            );
        }
    }

    /// **D203 M6c**: abandon's rule-2 refusal offers a way forward that is
    /// true of a PARTLY paid work — whose re-run is asked to pay the rest —
    /// as well as of a fully paid one. It used to promise "no further
    /// payment is needed".
    #[test]
    fn u110_the_paid_refusal_offers_a_way_forward_true_of_a_partly_paid_work() {
        let (vault, work, seal_id) = anchored_with("u110-m6c", Some(&fixture_receipt()));
        let session = SealSession::open(Arc::new(vault.unlock()));
        // Control: partly paid — the exact re-run's consent is asked over a
        // priced remainder (declined here, so nothing moves).
        let backend = MockBackend::new().with_balances(funded());
        let declined = rerun_asking(&session, &work, &backend, &mut SaysNo, 0x6C)
            .expect_err("the remainder's consent is declined");
        assert_eq!(
            declined.class(),
            ErrorClass::ConsentNotObtained,
            "{declined}"
        );
        assert_eq!(backend.calls(Method::QuoteBatch), 1);
        assert_eq!(backend.calls(Method::Pay), 0);

        let store = WorkStore::new(session.vault());
        let mut r = rng(0x6D);
        let journal = VaultJournal::new(WorkStore::new(session.vault()), &mut r);
        let err = abandon_pre_pay(&store, &journal, &seal_id)
            .expect_err("a paid work is never abandoned on request");
        assert_eq!(err.class(), ErrorClass::Usage);
        let text = err.to_string();
        assert!(
            !text.contains("no further payment is needed"),
            "the refusal tells a partly paid work's owner that finishing it needs no further \
             payment, while the rest is owed (D203 M6c):\n{text}"
        );
        assert!(text.contains("a payment is recorded for work"), "{text}");
        assert!(
            text.contains("Finish it instead by re-running `antseal seal a.txt"),
            "{text}"
        );
        assert!(
            text.contains("pays only for what the receipt does not cover"),
            "{text}"
        );
    }

    /// The resume plan reads the matched work's receipt (D203 M4), so
    /// `seal --dry-run` over a receipt that will not decode fails — in the
    /// class, exit code and words a real resume reports at its own receipt
    /// read (`Pipeline::resume`, `resume.rs:185`) — rather than printing a
    /// plan that guesses the money. The rehearsal still calls no backend
    /// method.
    #[test]
    fn u110_a_dry_run_over_an_undecodable_receipt_fails_in_the_resumes_own_class() {
        let (vault, work, seal_id) = anchored_with("u110-dry-undecodable", None);
        let session = SealSession::open(Arc::new(vault.unlock()));
        // The store's own writer: a genuine AEAD over plaintext the receipt
        // decoder refuses.
        WorkStore::new(session.vault())
            .put_receipt(&seal_id, b"not a journaled receipt", &mut rng(0x5D))
            .expect("plant an undecodable receipt");

        let dry = dry_run_plan(&session, &work)
            .expect_err("the rehearsal printed a resume plan over a receipt it cannot read");

        let mock = MockBackend::new().with_balances(funded());
        let gate = crate::common::RecordingGate::new();
        let consent = crate::common::ScriptedConsent::always_yes();
        let mut r = rng(0x5E);
        let journal = VaultJournal::new(WorkStore::new(session.vault()), &mut r);
        let pipeline = Pipeline::new(&mock, &gate, &journal, &consent, &NoBarriers);
        let real = match block_on(pipeline.resume(&seal_id)) {
            Ok(_) => panic!("a resume over an undecodable receipt must fail"),
            Err(err) => CliError::from(err),
        };
        assert_eq!(
            mock.calls(Method::QuoteBatch),
            0,
            "the resume failed at its receipt read"
        );
        assert_eq!(dry.class(), ErrorClass::VaultAuthFailure, "{dry}");
        assert_eq!(
            (dry.class(), dry.exit_code(), dry.to_string()),
            (real.class(), real.exit_code(), real.to_string())
        );
    }
}
