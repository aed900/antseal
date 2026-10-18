//! **D194 (`A97` + `U97`): the anchor-gate abort says what failed, and every
//! resume rule it states is true — asserted end to end through `run_seal`.**
//!
//! `anchor_gate_prepay.rs` drives `Pipeline::seal` directly, which is right
//! for A20's "the abort precedes payment" but cannot see D45: resume
//! detection lives in `run_seal`. Every case here starts at `run_seal` over a
//! plan the real argv parser produced (the harness `anchor_stage.rs` uses),
//! and each sentence of the abort is checked against what actually happens
//! next — `A97`'s Accept: *"asserted against D45's actual resume path, not
//! just spell-checked"*.
//!
//! # The order is part of the test
//!
//! The three parts run in ONE test, in the order (i) → (iii) → (ii). Once
//! (ii) completes the work, D45 no longer counts it as a candidate, so an
//! added `--force-degraded` would start a fresh seal instead of being
//! refused.
//!
//! # No test here can reach a real endpoint (Q16)
//!
//! Every TSA is a `127.0.0.1:0` stub, and each stub's request counter is
//! asserted, so "the stub answered" is evidence rather than assumption.
//!
//! NON-SECRET: every passphrase, key and byte string is a documented fixture
//! (project rule 6).

mod common;

use std::path::PathBuf;
use std::sync::Arc;

use antseal_anchor::submit::AnchorEndpoints;
use antseal_anchor::testing::replay::signing_tsa;
use antseal_anchor::testing::stub::{StubReply, StubScript, StubServer};
use antseal_cli::cli::{Cli, Command};
use antseal_cli::error::ErrorClass;
use antseal_cli::pipeline::SealState;
use antseal_cli::pipeline::journal::recorded_state;
use antseal_cli::seal_consent::ConsentPrompt;
use antseal_cli::seal_plan::{SealPlan, build_plan};
use antseal_cli::seal_run::{AnchorStageConfig, SealCommandResult, SealContext, run_seal};
use antseal_cli::seal_session::SealSession;
use antseal_cli::vault::store::WorkStore;
use antseal_core::anchor::roots::TsaRootStore;
use antseal_core::anchor::testing::MockTsa;
use antseal_core::crypto::secrets::SealId;
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

fn ctx(tsa: &[String], roots: TsaRootStore) -> SealContext {
    SealContext {
        machine_mode: true,
        to_stderr: true,
        now_unix_secs: FETCH_DATE,
        app_version: "antseal-d194-test/1".to_owned(),
        anchors: AnchorStageConfig {
            endpoints: AnchorEndpoints {
                tsa_urls: tsa.to_vec(),
                // No calendars: the gate counts TSA tokens only (D54 §3).
                ots_calendars: Vec::new(),
            },
            roots,
            fetch_date: Some(FETCH_DATE),
        },
    }
}

fn rng(seed: u8) -> ChaCha20Rng {
    ChaCha20Rng::from_seed([seed; 32])
}

fn hex(seal_id: &SealId) -> String {
    seal_id
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// A prompt that must never be reached (every plan carries `--yes`).
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
            "antseal-d194-{tag}-{}-{}",
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

    /// The plan the real handler builds, through the real argv parser. Never
    /// `--no-anchor`: the gate is the subject.
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
fn unhelpful_tsa() -> StubServer {
    StubServer::spawn(StubScript::new().always(StubReply::body(
        503,
        b"timestamping is offline for maintenance".to_vec(),
    )))
}

/// **D194 §3, the load-bearing half.** (i) every TSA fails: exit 22, and the
/// message's claims hold at the moment it makes them; (iii) the same paths
/// with `--force-degraded` added: exit 26, and nothing changed; (ii) the
/// identical command against a TSA whose token counts: the same work
/// resumes and pays exactly once.
///
/// (ii) cannot pass on success alone — a fresh seal would also pay once — so
/// it asserts `resumed`, the seal-id, and that no second work exists.
#[test]
fn an_aborted_seal_resumes_on_the_identical_command_and_refuses_an_added_force_degraded() {
    let work = Work::new("resume");
    let plan = work.plan(&[]);
    let mock = MockBackend::new().with_balances(funded());
    let backend = RecordingBackend::new(&mock);
    let vault = IsolatedVault::create("d194-resume");
    let session = SealSession::open(Arc::new(vault.unlock()));
    let store = WorkStore::new(session.vault());
    let only_work = || {
        let works = store.list_works().expect("enumerate");
        assert_eq!(works.len(), 1, "one work across every run: {works:?}");
        works[0]
    };
    let fine_state = |seal_id: &SealId| {
        recorded_state(&store, seal_id)
            .expect("read the state record")
            .expect("the work has a state record")
    };

    // ── (i) every TSA fails ─────────────────────────────────────────────
    let down = unhelpful_tsa();
    let err = block_on(run_seal(
        &backend,
        &session,
        &plan,
        &mut NeverAsked,
        &ctx(&[down.base_url()], *TsaRootStore::pinned()),
        &mut rng(0x31),
        &mut rng(0x32),
    ))
    .expect_err("the gate refuses");
    assert_eq!(err.class(), ErrorClass::AnchorGateAbort);
    assert_eq!(err.exit_code(), 22);
    assert!(
        !down.requests().is_empty(),
        "the TSA stub was never contacted, so this proves nothing about the real gate"
    );
    let seal_id = only_work();
    let id = hex(&seal_id);
    let message = err.to_string();

    // Each claim, then the fact it claims.
    assert!(
        message.contains("the seal stopped before anything was paid or uploaded"),
        "{message}"
    );
    assert_eq!(backend.pay_calls(), 0, "pay was reached");
    assert_eq!(mock.stored_count(), 0, "bytes were uploaded");
    assert!(message.contains("The work is left staged"), "{message}");
    assert_eq!(
        fine_state(&seal_id),
        SealState::Staged,
        "the message says the work is left staged; the journal must agree"
    );
    assert!(
        message.contains("running this exact command again resumes it"),
        "{message}"
    );
    assert!(
        message.contains("--force-degraded cannot be added to that re-run"),
        "{message}"
    );
    assert!(
        message.contains(&format!("`antseal abandon {id}`")),
        "the way forward must name THIS work's seal-id: {message}"
    );
    assert!(
        message.contains(&format!("tsa {} [http]", down.base_url())),
        "the failed endpoint is named with its class: {message}"
    );

    // ── (iii) BEFORE (ii): `--force-degraded` added to the same paths ───
    let degraded = work.plan(&["--force-degraded"]);
    let err = block_on(run_seal(
        &backend,
        &session,
        &degraded,
        &mut NeverAsked,
        &ctx(&[down.base_url()], *TsaRootStore::pinned()),
        &mut rng(0x33),
        &mut rng(0x34),
    ))
    .expect_err("the added flag is refused, exactly as the abort said");
    assert_eq!(err.class(), ErrorClass::ResumeFlagMismatch);
    assert_eq!(err.exit_code(), 26);
    assert!(
        err.to_string().contains(&format!("`antseal abandon {id}`")),
        "both messages must name the same work: {err}"
    );
    assert_eq!(only_work(), seal_id, "the refusal started no second work");
    assert_eq!(
        fine_state(&seal_id),
        SealState::Staged,
        "the refusal changed nothing"
    );
    assert_eq!(backend.pay_calls(), 0);

    // ── (ii) the identical command, once a TSA returns a token that counts
    let signer = MockTsa::granted().expect("the mock CA mints");
    let roots = signer.root_store();
    let responder = signer.clone();
    let tsa = StubServer::spawn(signing_tsa(move |request| responder.respond(request).ok()));
    let result = block_on(run_seal(
        &backend,
        &session,
        &plan,
        &mut NeverAsked,
        &ctx(&[tsa.base_url()], roots),
        &mut rng(0x35),
        &mut rng(0x36),
    ))
    .expect("the identical command finishes the staged work");
    let SealCommandResult::Sealed(report) = result else {
        panic!("a non-dry-run seal returns Sealed");
    };
    assert!(
        report.resumed,
        "the identical command must RESUME the staged work, not start a second seal"
    );
    assert_eq!(report.seal_id, seal_id, "the same work, not a fresh one");
    assert_eq!(only_work(), seal_id);
    assert_eq!(backend.pay_calls(), 1, "one payment across all three runs");
    assert_eq!(
        mock.calls(Method::QuoteBatch),
        2,
        "it quoted again: once in (i), once on the resume, never in (iii)"
    );
    assert_eq!(tsa.requests().len(), 1, "the resume re-ran the gate");
    assert_eq!(fine_state(&seal_id), SealState::Complete);
}

/// **`U97` (D194 R1).** Every endpoint answered, and the seal still cannot
/// pass. The stub serves a real, freshly signed token — A59's signing mock
/// answers the nonce this run draws, so the token verifies — but the gate
/// checks it against the PINNED store, which does not hold the mock's root.
/// (A recorded third-party token cannot play this part through the real
/// gate: it answers only the nonce and digest it was recorded with, so it
/// fails as `unverifiable` before the chain is ever checked.)
///
/// The abort must name that endpoint with its class, print the trust state
/// by its frozen name rather than a Rust `Debug` name, and say that such a
/// token never counts. The lines ride in `--json`'s `message`, with no key
/// added (D194 R3).
#[test]
fn an_unpinned_authority_is_named_with_its_class_its_frozen_state_and_that_it_never_counts() {
    let work = Work::new("unpinned");
    let plan = work.plan(&[]);
    let mock = MockBackend::new().with_balances(funded());
    let backend = RecordingBackend::new(&mock);
    let vault = IsolatedVault::create("d194-unpinned");
    let session = SealSession::open(Arc::new(vault.unlock()));

    let signer = MockTsa::granted().expect("the mock CA mints");
    let responder = signer.clone();
    let tsa = StubServer::spawn(signing_tsa(move |request| responder.respond(request).ok()));
    let err = block_on(run_seal(
        &backend,
        &session,
        &plan,
        &mut NeverAsked,
        &ctx(&[tsa.base_url()], *TsaRootStore::pinned()),
        &mut rng(0x41),
        &mut rng(0x42),
    ))
    .expect_err("a token that reaches no pinned root cannot pass the gate");

    assert_eq!(err.class(), ErrorClass::AnchorGateAbort);
    assert_eq!(
        tsa.requests().len(),
        1,
        "the authority answered — it was reachable all along"
    );
    assert_eq!(backend.pay_calls(), 0);

    let message = err.to_string();
    let url = tsa.base_url();
    let entry = format!(
        "tsa {url} [untrusted-chain] {url}: the token verifies but does not chain to a pinned \
         root (internally-consistent-only)"
    );
    assert!(message.contains(&entry), "{message}");
    assert!(
        !message.contains("InternallyConsistentOnly"),
        "a Rust Debug name leaked into the message: {message}"
    );
    assert!(
        message.contains("never counts toward the gate (docs/user/timestamp-authorities.md §1)"),
        "{message}"
    );

    let object = err.error_object();
    assert_eq!(object["message"], message.as_str());
    let keys: Vec<&str> = object
        .as_object()
        .expect("an object")
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(keys, ["class", "exit_code", "message"], "no key was added");
}
