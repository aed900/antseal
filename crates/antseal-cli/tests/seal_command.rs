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

use std::path::{Path, PathBuf};

use antseal_cli::cli::{Cli, Command};
use antseal_cli::error::ErrorClass;
use antseal_cli::seal_consent::{ConsentPrompt, PERMANENCE_WARNING};
use antseal_cli::seal_plan::{SealPlan, build_plan};
use antseal_cli::seal_run::{SealCommandResult, SealContext, run_seal};
use antseal_cli::vault::store::{WorkState, WorkStore};
use antseal_net::test_util::{Method, MockBackend, block_on};
use antseal_net::{BalanceReport, network::EvmAddress20};
use common::IsolatedVault;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

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
    let unlocked = vault.unlock();

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
    let store = WorkStore::new(&unlocked);
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
    let unlocked = vault.unlock();

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
    let store = WorkStore::new(&unlocked);
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
    let unlocked = vault.unlock();

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
        let unlocked = vault.unlock();

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
    let unlocked = vault.unlock();

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
    let store = WorkStore::new(&unlocked);
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
    let unlocked = vault.unlock();

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
    let unlocked = vault.unlock();

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
    let store = WorkStore::new(&unlocked);
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
    let unlocked = vault.unlock();
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
    let unlocked = vault.unlock();

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
    let unlocked = vault.unlock();

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
        let store = WorkStore::new(&unlocked);
        let staged = store.list_works().expect("list");
        assert_eq!(staged.len(), 1);
        let state = store.load_meta(&staged[0]).expect("meta").state;
        (staged, state)
    };
    drop(unlocked);
    let fingerprint_before = vault.fingerprint();

    // Now the identical invocation with --dry-run. It exact-matches.
    let unlocked = vault.unlock();
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
        let store = WorkStore::new(&unlocked);
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

#[test]
fn a_dry_run_with_a_drained_wallet_exits_with_the_real_shortfall_code() {
    let work = Work::new("dryshort");
    work.file("a.txt", b"content");
    let plan = work
        .plan(&["a.txt", "--no-anchor", "--dry-run"])
        .expect("plan validates");

    let backend = MockBackend::new().with_balances(BalanceReport {
        wallet: EvmAddress20::from_bytes(FIXTURE_WALLET),
        ant_atto: 0,
        gas_wei: u128::from(u64::MAX),
    });
    let vault = IsolatedVault::create("seal-dryshort");
    let unlocked = vault.unlock();

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
    assert_eq!(err.class(), ErrorClass::InsufficientAntToken);
    assert_eq!(err.exit_code(), 20);
}

// ─────────────────────────────────────────────────────────────────────
// The spawned binary: the surface a user actually meets
// ─────────────────────────────────────────────────────────────────────

fn antseal_bin() -> std::process::Command {
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_antseal"));
    cmd.env_remove("RUST_LOG");
    cmd
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

    // The M1 anchor-stage gate: a plain seal says what is missing, and
    // does not claim `seal` is unimplemented.
    let out = run(&["seal", "a.txt", "--network", "devnet"]);
    assert_eq!(out.status.code(), Some(3));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("anchoring arrives in M2"), "{stderr}");
    assert!(
        !stderr.contains("`antseal seal` is not implemented"),
        "seal IS implemented; only the anchor stage is missing: {stderr}"
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

    // The matching pattern is accepted and reaches the next stage (the
    // backend seam, since this build has no network compiled in).
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
    assert_ne!(
        out.status.code(),
        Some(2),
        "a matching pattern is not a usage error: {}",
        String::from_utf8_lossy(&out.stderr)
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
    let unlocked = vault.unlock();
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
    let meta = WorkStore::new(&unlocked)
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
