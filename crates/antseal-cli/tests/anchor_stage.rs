//! **U22: the anchor stage, through the command a user runs.**
//!
//! A20 already proved that its gate aborts before payment
//! (`anchor_gate_prepay.rs`) — driving `Pipeline` directly with a
//! hand-assembled `SubmitAnchorGate`. That test could not see the thing U22
//! is about: whether the **product** injects that gate at all. Until U22 it
//! did not. `seal_run.rs` built its pipeline with `&NoAnchorGate` while
//! `seal_plan.rs` refused every anchored seal outright, so the gate was
//! built, tested, and reachable by nothing anyone could type.
//!
//! Every case here therefore starts at `run_seal` over a plan produced by
//! the **real** argv parser, with no `--no-anchor`, and asserts on the
//! backend's pay-call counter and on the vault.
//!
//! # No test here can reach a real endpoint (Q16)
//!
//! Every endpoint is a `127.0.0.1:0` stub, and the stub's own request
//! counter is asserted so "the stub answered" is evidence rather than
//! assumption. [`no_test_source_names_a_live_anchor_endpoint`] scans this
//! whole directory for any source that names one, so the next suite cannot
//! quietly acquire the habit.
//!
//! NON-SECRET: every passphrase, key and byte string is a documented fixture
//! (project rule 6).

mod common;

use std::path::PathBuf;

use antseal_anchor::submit::AnchorEndpoints;
use antseal_anchor::testing::replay::{
    CalendarBehaviour, calendar, fixtures as anchor_fixtures, signing_tsa,
};
use antseal_anchor::testing::stub::{StubReply, StubScript, StubServer};
use antseal_cli::cli::{Cli, Command};
use antseal_cli::error::ErrorClass;
use antseal_cli::listing::WorkListing;
use antseal_cli::pipeline::{AnchorArtifact, ArtifactKind, OTS_SLOT};
use antseal_cli::seal_consent::ConsentPrompt;
use antseal_cli::seal_plan::{SealPlan, build_plan};
use antseal_cli::seal_run::{AnchorStageConfig, SealCommandResult, SealContext, run_seal};
use antseal_cli::seal_session::SealSession;
use antseal_cli::vault::store::{WorkState, WorkStore};
use antseal_core::anchor::testing::MockTsa;
use antseal_net::test_util::{Method, MockBackend, block_on};
use antseal_net::{BalanceReport, network::EvmAddress20};
use common::{IsolatedVault, RecordingBackend};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

/// NON-SECRET fixture wallet address: a repeated byte pattern.
const FIXTURE_WALLET: [u8; 20] = [0x5A; 20];
/// A fixed provenance timestamp (A32: recorded, never compared).
const FETCH_DATE: u64 = 1_800_000_000;

fn funded() -> BalanceReport {
    BalanceReport {
        wallet: EvmAddress20::from_bytes(FIXTURE_WALLET),
        ant_atto: u128::from(u64::MAX),
        gas_wei: u128::from(u64::MAX),
    }
}

fn ctx(anchors: AnchorStageConfig) -> SealContext {
    SealContext {
        machine_mode: true,
        to_stderr: true,
        now_unix_secs: FETCH_DATE,
        app_version: "antseal-u22-test/1".to_owned(),
        anchors,
    }
}

fn stage(
    tsa: &[String],
    ots: &[String],
    roots: antseal_core::anchor::roots::TsaRootStore,
) -> AnchorStageConfig {
    AnchorStageConfig {
        endpoints: AnchorEndpoints {
            tsa_urls: tsa.to_vec(),
            ots_calendars: ots.to_vec(),
        },
        roots,
        fetch_date: Some(FETCH_DATE),
    }
}

/// A prompt that must never be reached (every case is `--yes`).
struct NeverAsked;
impl ConsentPrompt for NeverAsked {
    fn ask(&mut self) -> Result<bool, antseal_cli::error::CliError> {
        panic!("the consent gate prompted where --yes must have answered");
    }
}

struct Work {
    dir: PathBuf,
}

impl Work {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "antseal-u22-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("mk work dir");
        std::fs::write(dir.join("notes.txt"), b"alpha beta\n\ngamma delta\n").expect("fixture");
        Self { dir }
    }

    /// Build the plan the way the real handler does — through the real argv
    /// parser, so what is sealed here is what the frozen surface accepts.
    /// **No `--no-anchor`**: that is the whole point of this suite.
    fn plan(&self, extra: &[&str]) -> SealPlan {
        let mut argv = vec!["antseal", "seal", "notes.txt", "--yes"];
        argv.extend_from_slice(extra);
        let cli = Cli::parse_checked(argv.iter().copied()).expect("argv parses");
        let Command::Seal(args) = &cli.command else {
            panic!("built a non-seal argv");
        };
        assert!(!args.no_anchor, "this suite must never pass --no-anchor");
        build_plan(args, antseal_net::NetworkId::Devnet, &self.dir).expect("plan validates")
    }
}

impl Drop for Work {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// A TSA that answers, correctly, with something that is not a token.
///
/// `503` rather than a dead socket: a refused connection is the easy case,
/// and this is the one where an implementation counting HTTP round trips
/// instead of verified tokens would proceed.
fn unhelpful_tsa() -> StubServer {
    StubServer::spawn(StubScript::new().always(StubReply::body(
        503,
        b"timestamping is offline for maintenance".to_vec(),
    )))
}

// ─────────────────────────────────────────────────────────────────────
// U22 Accept row 1: all TSAs fail ⇒ abort BEFORE payment
// ─────────────────────────────────────────────────────────────────────

/// **The load-bearing row.** A plain `antseal seal` whose TSAs all fail
/// aborts with the dedicated exit code and **zero payment**.
///
/// What is counted, precisely:
///
/// - `backend.pay_calls() == 0` — the pipeline never called `pay`;
/// - `mock.payment_tx_count() == 0` — no EVM transaction was issued *by any
///   route*, including one that bypassed the wrapper;
/// - `mock.stored_count() == 0` — nothing was uploaded;
/// - the exact backend call log is `[Balances, QuoteBatch]` — an equality,
///   not a containment, so a payment call appearing anywhere in the sequence
///   reddens this rather than hiding behind a `>= 0`;
/// - the vault holds **no receipt** for the work and it is still `Staged`.
///
/// "It aborted" would be satisfied by an abort *after* payment; every
/// assertion above is about the other side of that line.
#[test]
fn a_plain_seal_whose_tsas_all_fail_aborts_before_any_payment() {
    let work = Work::new("abort");
    let plan = work.plan(&[]);
    let mock = MockBackend::new().with_balances(funded());
    let backend = RecordingBackend::new(&mock);
    let vault = IsolatedVault::create("u22-abort");
    let session = SealSession::open(vault.unlock());

    let tsa = unhelpful_tsa();
    let err = block_on(run_seal(
        &backend,
        &session,
        &plan,
        &mut NeverAsked,
        &ctx(stage(
            &[tsa.base_url()],
            &[],
            *antseal_core::anchor::roots::TsaRootStore::pinned(),
        )),
        &mut ChaCha20Rng::from_seed([0x11; 32]),
        &mut ChaCha20Rng::from_seed([0x12; 32]),
    ))
    .expect_err("the gate refuses");

    // The dedicated class and its code — U2's `anchor-gate-abort`, 22.
    assert_eq!(err.class(), ErrorClass::AnchorGateAbort);
    assert_eq!(err.exit_code(), 22);

    // ── The property this file exists for ──
    assert_eq!(backend.pay_calls(), 0, "pay was reached");
    assert_eq!(mock.payment_tx_count(), 0, "an EVM transaction landed");
    assert_eq!(mock.stored_count(), 0, "bytes were uploaded");
    let methods: Vec<Method> = mock.call_log().iter().map(|c| c.method).collect();
    assert_eq!(
        methods,
        vec![Method::Balances, Method::QuoteBatch],
        "the only backend calls before the gate are the balance read and the quote"
    );

    // ── And the gate that refused is the real one, contacted over the wire ──
    assert!(
        !tsa.requests().is_empty(),
        "the TSA stub was never contacted, so this proves nothing about the real gate"
    );

    // ── The work is left pre-pay and resumable, not half-sealed ──
    let store = WorkStore::new(session.vault());
    let listing = WorkListing::gather(&store).expect("gather");
    assert_eq!(listing.works.len(), 1);
    assert_eq!(listing.works[0].state, WorkState::IncompletePrePay);
    assert_eq!(listing.works[0].cost_atto, None, "a cost was recorded");
}

// ─────────────────────────────────────────────────────────────────────
// U22 Accept row 2: one TSA succeeds ⇒ proceeds (the non-vacuity control)
// ─────────────────────────────────────────────────────────────────────

/// **The non-vacuity control**, and the artifact + summary rows in one run.
///
/// Without it, the row above would be equally true of a product that can
/// never pay at all — "the abort precedes payment" would be a statement
/// about a pipeline with no payment in it.
///
/// The proceed is **earned, not flagged**: no `--force-degraded`. A59's
/// signing mock answers the nonce this process drew a moment ago, core
/// verifies the token and chains it to the injected root, and the gate
/// passes because it holds one verified capture. A recorded token could not
/// have done it — it answers only the nonce it was recorded with.
#[test]
fn one_verified_tsa_lets_the_seal_proceed_and_journals_its_artifacts() {
    let work = Work::new("proceed");
    let plan = work.plan(&[]);
    let mock = MockBackend::new().with_balances(funded());
    let backend = RecordingBackend::new(&mock);
    let vault = IsolatedVault::create("u22-proceed");
    let session = SealSession::open(vault.unlock());

    let signer = MockTsa::granted().expect("the mock CA mints");
    let roots = signer.root_store();
    let responder = signer.clone();
    let tsa = StubServer::spawn(signing_tsa(move |request| responder.respond(request).ok()));
    let calendar_one = StubServer::spawn(calendar(&CalendarBehaviour::PendingSubmit(
        anchor_fixtures::CALENDAR_ALICE_A.to_vec(),
    )));
    let dead_calendar = StubServer::spawn(calendar(&CalendarBehaviour::ServerError));

    let result = block_on(run_seal(
        &backend,
        &session,
        &plan,
        &mut NeverAsked,
        &ctx(stage(
            &[tsa.base_url()],
            &[calendar_one.base_url(), dead_calendar.base_url()],
            roots,
        )),
        &mut ChaCha20Rng::from_seed([0x21; 32]),
        &mut ChaCha20Rng::from_seed([0x22; 32]),
    ))
    .expect("the seal lands");

    let SealCommandResult::Sealed(report) = result else {
        panic!("a non-dry-run seal returns Sealed");
    };

    // Money moved exactly once, through the same wiring the abort row used.
    assert_eq!(backend.pay_calls(), 1, "pay is reachable through this gate");
    assert_eq!(mock.calls(Method::Pay), 1);
    assert!(mock.stored_count() > 0);
    assert_eq!(tsa.requests().len(), 1, "the same gate ran");

    // ── Accept: the summary NAMES each anchor's outcome ──
    let anchors = report.anchors.as_ref().expect("a stage ran");
    assert_eq!(anchors.verified_tsa_tokens, 1);
    let named: Vec<(&str, &str, bool)> = anchors
        .endpoints
        .iter()
        .map(|e| {
            (
                e.stage.label(),
                e.endpoint.as_str(),
                e.failure_class.is_none(),
            )
        })
        .collect();
    assert_eq!(
        named,
        vec![
            ("ots", calendar_one.base_url().as_str(), true),
            ("ots", dead_calendar.base_url().as_str(), false),
            ("tsa", tsa.base_url().as_str(), true),
        ],
        "every endpoint contacted must appear by name, in stage order"
    );
    let rendered = report.render().join("\n");
    for endpoint in [
        tsa.base_url(),
        calendar_one.base_url(),
        dead_calendar.base_url(),
    ] {
        assert!(
            rendered.contains(&endpoint),
            "the human summary does not name {endpoint}:\n{rendered}"
        );
    }
    assert!(rendered.contains("verified timestamp token"), "{rendered}");
    assert!(rendered.contains("FAILED [http]"), "{rendered}");
    // A failed calendar is a degradation, and it is stated out loud.
    assert!(rendered.contains("DEGRADED ANCHOR SET"), "{rendered}");
    assert!(report.degraded, "the record must carry it too");

    // ── Accept: journaled artifacts land in U9 slots ──
    let store = WorkStore::new(session.vault());
    let slots = store.list_anchors(&report.seal_id).expect("list slots");
    assert_eq!(slots, vec![OTS_SLOT.to_owned(), "tsa-0".to_owned()]);

    let token = AnchorArtifact::decode(
        store
            .get_anchor(&report.seal_id, "tsa-0")
            .expect("read slot")
            .expect("slot filled")
            .as_bytes(),
    )
    .expect("decodes");
    assert_eq!(token.kind, ArtifactKind::TsaToken);
    assert_eq!(token.endpoint, tsa.base_url());
    assert_eq!(token.fetch_date, FETCH_DATE, "the fetch date is journaled");
    assert!(
        token.bytes.starts_with(&[0x30]),
        "the stored token is the DER TimeStampResp"
    );

    let ots = AnchorArtifact::decode(
        store
            .get_anchor(&report.seal_id, OTS_SLOT)
            .expect("read slot")
            .expect("slot filled")
            .as_bytes(),
    )
    .expect("decodes");
    assert_eq!(ots.kind, ArtifactKind::OtsPending);
    assert!(!ots.bytes.is_empty(), "the pending .ots is journaled");

    // ── Accept: degraded seals are labelled as such in `list` ──
    let listing = WorkListing::gather(&store).expect("gather");
    let row = listing.works.first().expect("one work");
    assert!(row.degraded, "the record does not carry the degraded flag");
    assert!(
        row.badge().contains("(degraded anchors)"),
        "list must label it: {}",
        row.badge()
    );
    assert!(!row.unanchored, "a degraded seal is not an UNANCHORED one");
}

// ─────────────────────────────────────────────────────────────────────
// U22 Accept row 3: --force-degraded with zero tokens
// ─────────────────────────────────────────────────────────────────────

/// `--force-degraded` converts the abort into a loud proceed. The warning
/// is snapshot-tested (`tests/snapshots/seal-degraded-report.txt`) because
/// it is the only thing standing between a user and the belief that a time
/// was attested.
#[test]
fn force_degraded_with_zero_tokens_proceeds_with_the_snapshotted_warning() {
    let work = Work::new("forced");
    let plan = work.plan(&["--force-degraded"]);
    let mock = MockBackend::new().with_balances(funded());
    let backend = RecordingBackend::new(&mock);
    let vault = IsolatedVault::create("u22-forced");
    let session = SealSession::open(vault.unlock());

    let tsa = unhelpful_tsa();
    let result = block_on(run_seal(
        &backend,
        &session,
        &plan,
        &mut NeverAsked,
        &ctx(stage(
            &[tsa.base_url()],
            &[],
            *antseal_core::anchor::roots::TsaRootStore::pinned(),
        )),
        &mut ChaCha20Rng::from_seed([0x31; 32]),
        &mut ChaCha20Rng::from_seed([0x32; 32]),
    ))
    .expect("--force-degraded proceeds");

    let SealCommandResult::Sealed(report) = result else {
        panic!("a non-dry-run seal returns Sealed");
    };
    assert_eq!(backend.pay_calls(), 1, "the flag must let the seal pay");
    let anchors = report.anchors.as_ref().expect("a stage ran");
    assert_eq!(anchors.verified_tsa_tokens, 0, "nothing was verified");
    assert!(report.degraded);

    // The stage's own lines, and only those: the ephemeral port and the
    // measured elapsed time are normalized (neither is copy), and U18's
    // export nag — a different task's words — is cut off at its first line.
    let rendered = report
        .render()
        .join("\n")
        .replace(&tsa.base_url(), "http://127.0.0.1:<port>");
    let anchor_block: String = rendered
        .lines()
        .skip_while(|line| !line.trim_start().starts_with("Anchors:"))
        .take_while(|line| !line.contains("NO BACKUP YET"))
        .map(normalize_elapsed)
        .collect::<Vec<_>>()
        .join("\n");
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/snapshots/seal-degraded-report.txt");
    if std::env::var_os("ANTSEAL_BLESS").is_some() {
        std::fs::write(&path, format!("{anchor_block}\n")).expect("bless");
        return;
    }
    let committed = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "missing committed degraded-seal snapshot at {}: {e} (generate with ANTSEAL_BLESS=1)",
            path.display()
        )
    });
    assert_eq!(
        committed.trim_end(),
        anchor_block.trim_end(),
        "the degraded-seal warning drifted from {} — this copy is what stands between a user \
         and believing a time was attested; regenerate with ANTSEAL_BLESS=1 and justify the diff",
        path.display()
    );
}

/// `(<digits> ms)` → `(<elapsed> ms)`: A20's degradation report carries a
/// measured duration per endpoint, which is provenance rather than copy.
/// Snapshotting the digits would make this row a stopwatch.
fn normalize_elapsed(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut rest = line;
    while let Some(at) = rest.find(" ms)") {
        let head = &rest[..at];
        let digits = head.len() - head.trim_end_matches(|c: char| c.is_ascii_digit()).len();
        out.push_str(&head[..head.len() - digits]);
        out.push_str("<elapsed> ms)");
        rest = &rest[at + " ms)".len()..];
    }
    out.push_str(rest);
    out
}

// ─────────────────────────────────────────────────────────────────────
// The `--no-anchor` skip, from the command layer
// ─────────────────────────────────────────────────────────────────────

/// **The product-level `--no-anchor` guarantee, after U22 changed what the
/// command injects.** An unanchored seal contacts no endpoint and journals
/// no artifact, driven through `run_seal` with the real gate pointed at
/// stubs that would answer if anyone asked.
///
/// # What this row does *not* prove, stated plainly
///
/// It does not isolate the **pipeline-level** skip. Measured: deleting the
/// `if unanchored { return }` from `Pipeline::run_anchor_gate` leaves this
/// test green, because `SubmitAnchorGate::run` checks the same flag and
/// submits nothing either. Two layers hold the property, and this row sees
/// their conjunction.
///
/// The row that isolates the pipeline's layer is
/// `seal_pipeline.rs::no_anchor_is_allowed_on_the_development_networks`,
/// which drives a **refusing** gate double: with the pipeline skip deleted
/// it fails with `AnchorGate(PolicyNotMet { detail: "0 TSA tokens
/// verified" })` (measured against that planted fault). Keep both — this one
/// is about what leaves the machine, that one about who decided.
#[test]
fn no_anchor_reaches_the_real_gate_and_still_submits_nothing() {
    let work = Work::new("skip");
    let mut argv = vec!["antseal", "seal", "notes.txt", "--yes", "--no-anchor"];
    argv.push("--network");
    argv.push("devnet");
    let cli = Cli::parse_checked(argv.iter().copied()).expect("argv parses");
    let Command::Seal(args) = &cli.command else {
        panic!("non-seal argv");
    };
    let plan = build_plan(args, antseal_net::NetworkId::Devnet, &work.dir).expect("plan validates");

    let mock = MockBackend::new().with_balances(funded());
    let backend = RecordingBackend::new(&mock);
    let vault = IsolatedVault::create("u22-skip");
    let session = SealSession::open(vault.unlock());

    // A TSA and a calendar that would both answer, if anyone asked.
    let signer = MockTsa::granted().expect("the mock CA mints");
    let responder = signer.clone();
    let tsa = StubServer::spawn(signing_tsa(move |request| responder.respond(request).ok()));
    let cal = StubServer::spawn(calendar(&CalendarBehaviour::PendingSubmit(
        anchor_fixtures::CALENDAR_ALICE_A.to_vec(),
    )));

    let result = block_on(run_seal(
        &backend,
        &session,
        &plan,
        &mut NeverAsked,
        &ctx(stage(
            &[tsa.base_url()],
            &[cal.base_url()],
            signer.root_store(),
        )),
        &mut ChaCha20Rng::from_seed([0x41; 32]),
        &mut ChaCha20Rng::from_seed([0x42; 32]),
    ))
    .expect("an unanchored devnet seal lands");

    let SealCommandResult::Sealed(report) = result else {
        panic!("a non-dry-run seal returns Sealed");
    };
    assert!(report.unanchored);
    assert!(
        report.anchors.is_none(),
        "no stage ran, so there is no summary"
    );
    assert_eq!(
        tsa.requests().len(),
        0,
        "an UNANCHORED seal contacted a TSA — the pipeline-level skip was bypassed"
    );
    assert_eq!(
        cal.requests().len(),
        0,
        "an UNANCHORED seal contacted a calendar — the pipeline-level skip was bypassed"
    );
    assert_eq!(cal.connections(), 0, "not even a connection was opened");

    // And nothing was journaled into the anchor slots.
    let store = WorkStore::new(session.vault());
    assert!(
        store
            .list_anchors(&report.seal_id)
            .expect("list slots")
            .is_empty(),
        "an UNANCHORED work has anchor artifacts"
    );
    assert_eq!(backend.pay_calls(), 1, "the seal itself still completed");
}

// ─────────────────────────────────────────────────────────────────────
// U26: the config's TSA list, all the way to the wire
// ─────────────────────────────────────────────────────────────────────

/// **U26 Accept row 1.** A config naming two TSAs makes the stage contact
/// **exactly those two** — asserted on the stubs' own request counters, not
/// on the config value, because the claim is about what left the process.
///
/// `--force-degraded` carries the seal past the gate (both stubs answer 503),
/// so the run reaches the end and the summary can be read; the point here is
/// which endpoints were contacted, not whether a token verified.
///
/// This test is in this file, and not in `config_file.rs`, because it names
/// `AnchorStageConfig::from_config` — which the scan below forbids everywhere
/// else. That is the discipline working, not a workaround: the production
/// constructor is exercised in exactly one place, under the eye of the rule.
#[test]
fn a_configured_tsa_list_is_what_the_stage_contacts() {
    let work = Work::new("u26-custom");
    let plan = work.plan(&["--force-degraded"]);
    let mock = MockBackend::new().with_balances(funded());
    let backend = RecordingBackend::new(&mock);
    let vault = IsolatedVault::create("u26-custom");
    let session = SealSession::open(vault.unlock());

    let first = unhelpful_tsa();
    let second = unhelpful_tsa();
    let config = antseal_cli::config::Config {
        tsa_urls: Some(vec![first.base_url(), second.base_url()]),
        ..antseal_cli::config::Config::default()
    };
    // The production path: config → effective list → the stage. Only the
    // calendars are blanked, so this run makes no OTS submission at all.
    let mut anchors = AnchorStageConfig::from_config(&config);
    anchors.endpoints.ots_calendars = Vec::new();
    anchors.fetch_date = Some(FETCH_DATE);

    // **Checked before the seal runs, on purpose.** If the config→stage
    // wiring ever breaks, the resolved list falls back to the *built-in
    // defaults* — and a test that discovered that by running the seal would
    // discover it by POSTing to a live TSA. Failing here means a broken
    // product cannot turn this suite into a network client (Q16). Measured:
    // with the override dropped in `from_config`, this is the line that
    // reddens, and no request is made.
    assert_eq!(
        anchors.endpoints.tsa_urls,
        vec![first.base_url(), second.base_url()],
        "the configured list did not reach the stage — refusing to run a seal that would \
         fall back to the built-in endpoints"
    );

    let result = block_on(run_seal(
        &backend,
        &session,
        &plan,
        &mut NeverAsked,
        &ctx(anchors),
        &mut ChaCha20Rng::from_seed([0x51; 32]),
        &mut ChaCha20Rng::from_seed([0x52; 32]),
    ))
    .expect("--force-degraded proceeds");

    let SealCommandResult::Sealed(report) = result else {
        panic!("a non-dry-run seal returns Sealed");
    };
    assert!(
        !first.requests().is_empty(),
        "the first configured TSA was never contacted"
    );
    assert!(
        !second.requests().is_empty(),
        "the second configured TSA was never contacted"
    );

    // "Exactly those": the stage's own endpoint list, in configured order,
    // with nothing else in it. A containment assertion would pass for a
    // stage that also contacted a default.
    let contacted: Vec<String> = report
        .anchors
        .as_ref()
        .expect("a stage ran")
        .endpoints
        .iter()
        .map(|e| {
            assert_eq!(
                e.stage,
                antseal_anchor::gate::AnchorStage::Tsa,
                "no calendar was configured"
            );
            e.endpoint.clone()
        })
        .collect();
    assert_eq!(contacted, vec![first.base_url(), second.base_url()]);
}

/// **U26 Accept row 2.** No config ⇒ the built-in defaults, and an empty
/// list means the same thing as an absent one.
///
/// A value assertion, deliberately: the *point* of this row is the endpoint
/// set a defaulted config yields, and a test that contacted them to find out
/// would be the Q16 violation this suite exists to prevent.
#[test]
fn an_absent_or_empty_config_yields_the_built_in_defaults() {
    use antseal_anchor::tsa::DEFAULT_TSA_URLS;

    let defaults = AnchorStageConfig::from_config(&antseal_cli::config::Config::default());
    assert_eq!(defaults.endpoints.tsa_urls, DEFAULT_TSA_URLS.to_vec());

    let empty = AnchorStageConfig::from_config(&antseal_cli::config::Config {
        tsa_urls: Some(Vec::new()),
        ..antseal_cli::config::Config::default()
    });
    assert_eq!(
        empty.endpoints.tsa_urls,
        DEFAULT_TSA_URLS.to_vec(),
        "an empty override must fall back, not disable anchoring silently"
    );

    // And an override really does replace them wholesale — no union.
    let custom = AnchorStageConfig::from_config(&antseal_cli::config::Config {
        tsa_urls: Some(vec!["http://127.0.0.1:1/tsr".to_owned()]),
        ..antseal_cli::config::Config::default()
    });
    assert_eq!(custom.endpoints.tsa_urls, vec!["http://127.0.0.1:1/tsr"]);
    assert!(!defaults.endpoints.ots_calendars.is_empty());
}

/// **U26 Accept row 3 / A50.** A malformed TSA URL is a clean config error
/// **before any pipeline work** — proven from the binary, because "before"
/// is a statement about ordering that only the whole command can settle.
///
/// The two negative assertions carry it: the seal argument is a *directory*,
/// which plan validation refuses with its own distinct code, and there is no
/// vault in this HOME at all. Seeing the config error instead of either means
/// the config was read and refused first.
#[test]
fn a_malformed_configured_tsa_url_refuses_before_any_pipeline_work() {
    let work = Work::new("u26-bad");
    std::fs::create_dir_all(work.dir.join("sub")).expect("mk sub");
    let home = work.dir.join("home");
    std::fs::create_dir_all(home.join(".antseal")).expect("mk vault dir");
    // A50: `gopher://` passes nothing, but the sharper case is a URL the old
    // `starts_with` shape check accepted — `http://` with no host at all.
    std::fs::write(
        home.join(".antseal/config.toml"),
        b"[anchors]\ntsa_urls = [\"http:///tsr\"]\n",
    )
    .expect("write config");

    let out = std::process::Command::new(env!("CARGO_BIN_EXE_antseal"))
        .env_remove("RUST_LOG")
        .env_remove("ANTSEAL_DIR")
        .current_dir(&work.dir)
        .env("HOME", &home)
        .args(["seal", "sub", "--network", "devnet"])
        .output()
        .expect("spawn antseal");

    assert_eq!(
        out.status.code(),
        Some(17),
        "a malformed config must exit with the malformed-config code"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("tsa_urls"), "{stderr}");
    assert!(stderr.contains("config.toml"), "{stderr}");
    // A50, measured: `http:///tsr` clears the old `starts_with("http://")`
    // shape check (11 bytes, right prefix) and is refused only by the
    // substrate's own parser — whose wording is what this asserts, so the
    // test would redden if the check were quietly moved back.
    assert!(stderr.contains("not a usable endpoint URL"), "{stderr}");
    assert!(
        !stderr.contains("is a directory"),
        "plan validation ran before the config was refused: {stderr}"
    );
    assert!(
        !stderr.contains("passphrase"),
        "the vault was reached before the config was refused: {stderr}"
    );
    assert!(out.stdout.is_empty(), "stdout stays clean on errors");
}

/// **A50, as a narrowing.** Three entries the old `starts_with("http://")`
/// shape check accepted and the substrate's parser refuses — and the two
/// that must keep working, including the plain-HTTP DigiCert shape, because
/// `timestamp.digicert.com` refuses connections on 443 (measured, D90 §6.6)
/// and RFC 3161 over TLS is therefore not an option.
///
/// The accept half is what stops this from being a one-way ratchet: a rule
/// that only ever refuses would pass just as well if it refused everything.
#[test]
fn the_tsa_list_is_narrowed_without_losing_plain_http() {
    let parse_one = |url: &str| {
        antseal_cli::config::parse(&format!("[anchors]\ntsa_urls = [\"{url}\"]\n"))
            .map(|c| c.tsa_urls)
    };

    for refused in [
        // No host — 11 bytes, right prefix, accepted by the old check.
        "http:///tsr",
        // Credentials in a pinned endpoint, in cleartext on this profile.
        "http://user:pw@tsa.invalid/tsr",
        // A scheme the substrate cannot speak.
        "https://",
    ] {
        assert!(
            parse_one(refused).is_err(),
            "`{refused}` must be refused at config load"
        );
    }

    for accepted in [
        // The DigiCert shape: plain HTTP, and it must stay legal.
        "http://timestamp.example.invalid",
        "https://tsa.example.invalid/tsr",
        "http://127.0.0.1:8080/tsr",
    ] {
        assert_eq!(
            parse_one(accepted).expect("accepted"),
            Some(vec![accepted.to_owned()]),
            "`{accepted}` must stay configurable"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────
// Q16: the no-live-endpoints rule, enforced rather than remembered
// ─────────────────────────────────────────────────────────────────────

/// The routes by which a test could obtain the built-in endpoint list.
/// Forbidden in any suite, because there is no legitimate reason for a test
/// to hold the production list at all.
const DEFAULT_LIST_ROUTES: [&str; 4] = [
    "DEFAULT_TSA_URLS",
    "AnchorEndpoints::defaults",
    "AnchorStageConfig::from_config",
    "effective_tsa_urls",
];

/// Live hosts. Forbidden **in a suite that builds an anchor stage** — the
/// gate below. `config_file.rs` legitimately names one inside a `config.toml`
/// fixture it only ever *parses*, and refusing that would be refusing U26's
/// own Accept row; a file that both names a live host and constructs the
/// endpoints the stage will contact is the shape that reaches the wire.
const LIVE_HOSTS: [&str; 3] = ["freetsa.org", "digicert.com", "opentimestamps.org"];

/// Every test source in this crate is scanned for a route to a live anchor
/// endpoint.
///
/// `AnchorStageConfig` deliberately has no `Default`, so a suite cannot
/// acquire the production list by omission; this closes the explicit routes.
#[test]
fn no_test_source_names_a_live_anchor_endpoint() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");

    let (offenders, visited) = sources_naming(&dir, &DEFAULT_LIST_ROUTES, &[]);
    assert!(
        visited > 20,
        "the scan visited only {visited} sources — it is not looking where it thinks"
    );
    assert!(
        offenders.is_empty(),
        "these test sources reach for the production endpoint list (Q16 forbids it — build \
         an `AnchorStageConfig` over a `127.0.0.1:0` stub): {offenders:?}"
    );

    let (offenders, _) =
        sources_naming(&dir, &LIVE_HOSTS, &["AnchorEndpoints", "AnchorStageConfig"]);
    assert!(
        offenders.is_empty(),
        "these test sources build an anchor stage AND name a live host (Q16): {offenders:?}"
    );
}

/// **The scan proven red, in both arms.** The row above is worth its verdict
/// only if the scan can fail, so run it against planted violations in a
/// directory of its own — with clean neighbours beside them, so it is not
/// merely always-red.
#[test]
fn the_endpoint_scan_reports_planted_violations() {
    let dir = std::env::temp_dir().join(format!(
        "antseal-u22-scan-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    ));
    std::fs::create_dir_all(dir.join("nested")).expect("mk dir");
    // Arm 1: reaches for the production list.
    std::fs::write(
        dir.join("nested/planted_route.rs"),
        b"fn urls() -> Vec<String> { AnchorEndpoints::defaults().tsa_urls }\n",
    )
    .expect("write");
    // Arm 2: builds a stage AND names a live host.
    std::fs::write(
        dir.join("planted_host.rs"),
        b"let e = AnchorEndpoints { tsa_urls: vec![\"https://freetsa.org/tsr\".into()] };\n",
    )
    .expect("write");
    // Clean: names a live host but builds no stage (the `config_file.rs`
    // shape), so arm 2 must leave it alone.
    std::fs::write(
        dir.join("clean_config.rs"),
        b"let toml = \"[anchors]\\ntsa_urls = [\\\"https://freetsa.org/tsr\\\"]\";\n",
    )
    .expect("write");
    // Clean: builds a stage over a stub.
    std::fs::write(
        dir.join("clean_stub.rs"),
        b"let e = AnchorEndpoints { tsa_urls: vec![stub.base_url()] };\n",
    )
    .expect("write");
    // A comment naming a live host, in a stage-building file: prose, not a
    // call. The scan must not fire on it — a rule that punished explaining
    // itself would be switched off the first time it did.
    std::fs::write(
        dir.join("clean_comment.rs"),
        b"// never point AnchorEndpoints at freetsa.org from a test\nlet e = AnchorEndpoints { tsa_urls: vec![] };\n",
    )
    .expect("write");
    // Not Rust: must not be read at all.
    std::fs::write(dir.join("notes.txt"), b"freetsa.org\n").expect("write");

    let (routes, visited) = sources_naming(&dir, &DEFAULT_LIST_ROUTES, &[]);
    assert_eq!(visited, 5, "the scan read a non-Rust file");
    assert_eq!(routes, vec!["nested/planted_route.rs".to_owned()]);

    let (hosts, _) = sources_naming(&dir, &LIVE_HOSTS, &["AnchorEndpoints", "AnchorStageConfig"]);
    assert_eq!(hosts, vec!["planted_host.rs".to_owned()]);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Rust sources under `dir` (recursively) naming any needle **outside a
/// comment**, optionally restricted to files that also name one of `gate`.
///
/// Returned paths are relative and sorted, so a failure names the offending
/// file rather than a count. A line whose trimmed start is `//` is prose and
/// is skipped — a scan that fired on the comment explaining it would be
/// deleted rather than obeyed (`seal_session`'s scan makes the same
/// carve-out for its own test modules).
///
/// This file is skipped by name: it necessarily contains every needle, in
/// the two arrays above.
fn sources_naming(dir: &std::path::Path, needles: &[&str], gate: &[&str]) -> (Vec<String>, usize) {
    let mut named = Vec::new();
    let mut visited = 0usize;
    let mut stack = vec![dir.to_path_buf()];
    while let Some(next) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&next) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if path.extension().is_none_or(|ext| ext != "rs") {
                continue;
            }
            if path.file_name().is_some_and(|n| n == "anchor_stage.rs") {
                continue;
            }
            visited += 1;
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            let code: Vec<&str> = text
                .lines()
                .filter(|line| !line.trim_start().starts_with("//"))
                .collect();
            if !gate.is_empty() && !gate.iter().any(|g| code.iter().any(|l| l.contains(g))) {
                continue;
            }
            if needles
                .iter()
                .any(|needle| code.iter().any(|line| line.contains(needle)))
            {
                named.push(
                    path.strip_prefix(dir)
                        .unwrap_or(&path)
                        .to_string_lossy()
                        .into_owned(),
                );
            }
        }
    }
    named.sort();
    (named, visited)
}
