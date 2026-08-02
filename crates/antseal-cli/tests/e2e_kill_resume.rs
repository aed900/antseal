//! **S18 — the M1 devnet kill/resume matrix.**
//!
//! S16 already proves the resume state machine over `MockBackend`, where
//! kills are clean early returns and payments are counters. This file asks
//! the same questions of a **live 14-node devnet and a real Anvil chain**,
//! where a kill can be a `SIGKILL` mid-write and a payment is an EVM
//! transaction that either happened or did not.
//!
//! Run by `scripts/e2e-devnet.sh` (registry row S18). Locally:
//!
//! ```text
//! scripts/devnet/local-up --nodes 14
//! ANTSEAL_DEVNET_ENV=$PWD/.devnet/env \
//!     cargo test -p antseal-cli --features ant-backend --test e2e_kill_resume -- --nocapture
//! scripts/devnet/local-down
//! ```
//!
//! # The two kill mechanisms, and why both are here
//!
//! * **Named fault barriers** (`pipeline::Barrier`) are deterministic: the
//!   kill lands at a known statement, every run. That is what makes the
//!   payment assertions exact rather than probabilistic.
//! * **A real `SIGKILL`** of a real child process is the only thing that
//!   tests *crash consistency of the journal write itself*. A barrier
//!   returns `Err` from a function that has already returned from `pay` and
//!   already flushed its journal write; a `SIGKILL` does not care what was
//!   half-written. S18's accept row is explicit that both must exist.
//!
//! The child is **this test binary re-executed** (`current_exe`) with a
//! scenario in the environment — never the CLI (D34, and S17's scan
//! enforces it). `fork` would need `unsafe`, which is denied workspace-wide.
//! The parent kills it with `Child::kill`, which is `SIGKILL` on Linux.
//! The vault's U5 lock is `flock`-backed and released by the kernel on
//! process death, so the parent can always take the vault afterwards —
//! that property is exactly what makes this design possible, and
//! `case2` re-acquiring the vault after a `SIGKILL` is a live test of it.
//!
//! # Money is counted on the chain, never in the process under test
//!
//! A receipt is the artifact a double-payment bug would *also* write. So
//! every payment claim here is settled by the wallet's on-chain ANT balance
//! delta and by transaction receipts read from Anvil.
//!
//! NON-SECRET: every fixture byte string is documented and run-tagged; `W`
//! never leaves the vault.

#![cfg(feature = "ant-backend")]

mod common;

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use antseal_cli::backend::{SealBackend, runtime};
use antseal_cli::pipeline::{
    Barrier, BarrierHook, BlobSlot, NoBarriers, Pipeline, RestoreEngine, SealError, SealFile,
    SealJournal, SealRequest, SealResult, SealState, StagedBytesUnavailable, UNIT_ENTRY_BASE,
    VaultJournal, hex32,
};
use antseal_cli::vault::kdf::KdfSelection;
use antseal_cli::vault::layout::VaultLayout;
use antseal_cli::vault::session::{UnlockedVault, create_vault, unlock_vault};
use antseal_cli::vault::store::{SealShapingFlags, WorkStore};
use antseal_core::content::{FileFlags, SplitMode};
use antseal_core::crypto::secrets::SealId;
use antseal_core::crypto::sig_policy::SigPolicy;
use antseal_net::{BlobCost, NetworkId, StorageBackend};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

use common::devnet::{
    CapturedReceipts, RUN_TAG_ENV, ant_balance, gate, hex32_0x, run_seed, run_tag, serial,
    tx_succeeded,
};
use common::{KillAt, RecordingGate, ScriptedConsent, TraceBarriers, passphrase, rng};

// ─────────────────────────────────────────────────────────────────────
// Child-process protocol
// ─────────────────────────────────────────────────────────────────────

/// Scenario selector handed to the re-executed child.
const CHILD_ENV: &str = "ANTSEAL_S18_CHILD";
/// Where the child's vault lives (the parent creates it).
const VAULT_ENV: &str = "ANTSEAL_S18_VAULT";
/// The file the child touches when it has reached its kill point.
const MARKER_ENV: &str = "ANTSEAL_S18_MARKER";

/// Kill after the receipt is durable and before `finalize_batch` — case (1).
const SCENARIO_STALL_PRE_FINALIZE: &str = "stall-pre-finalize";
/// Signal at the same point but keep going, so the parent's kill lands
/// *inside* `finalize_batch` — case (2).
const SCENARIO_KILL_MID_UPLOAD: &str = "kill-mid-upload";

// ─────────────────────────────────────────────────────────────────────
// Fixtures
// ─────────────────────────────────────────────────────────────────────

/// The original sources. Deterministic in the run tag, so the parent and
/// its child build byte-identical works.
fn original_text() -> Vec<u8> {
    format!(
        "original alpha {tag}\n\noriginal beta\n\noriginal gamma\n",
        tag = run_tag()
    )
    .into_bytes()
}

fn original_binary() -> Vec<u8> {
    let mut bytes = vec![0x00, 0xFF, 0x10, 0x20];
    bytes.extend_from_slice(&run_seed("s18-binary")[..12]);
    bytes
}

/// Sources that differ from [`original_text`] in every unit — case (3)'s
/// "the user edited the files after the kill".
fn changed_text() -> Vec<u8> {
    format!(
        "CHANGED alpha {tag}\n\nCHANGED beta\n\nCHANGED gamma\n",
        tag = run_tag()
    )
    .into_bytes()
}

struct Sources {
    text: Vec<u8>,
    binary: Vec<u8>,
}

impl Sources {
    fn original() -> Self {
        Self {
            text: original_text(),
            binary: original_binary(),
        }
    }

    fn changed() -> Self {
        Self {
            text: changed_text(),
            binary: original_binary(),
        }
    }

    fn files(&self) -> Vec<SealFile<'_>> {
        vec![
            SealFile {
                path_as_given: "work.txt",
                path_absolute: "/w/work.txt",
                bytes: &self.text,
                flags: FileFlags::new().with_split(SplitMode::BlankLines),
            },
            SealFile {
                path_as_given: "work.bin",
                path_absolute: "/w/work.bin",
                bytes: &self.binary,
                flags: FileFlags::new(),
            },
        ]
    }
}

fn request<'a>(files: &'a [SealFile<'a>]) -> SealRequest<'a> {
    SealRequest {
        files,
        title: format!("S18 {}", run_tag()),
        claimed_time_unix_secs: 1_800_000_000,
        app_version: "antseal-m1-gate/1".to_owned(),
        network: NetworkId::Devnet,
        no_anchor: true,
        degraded: false,
        dry_run: false,
        sig_policy: SigPolicy::hybrid(),
        shaping: SealShapingFlags::default(),
    }
}

// ─────────────────────────────────────────────────────────────────────
// Vault helpers
// ─────────────────────────────────────────────────────────────────────
//
// `common::IsolatedVault` cannot be used across a process boundary (it
// owns a temp root and unlocks in-process), so S18 keeps the layout
// explicit: the parent creates the vault at a known path and hands the
// path to the child.

fn vault_root(tag: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!("antseal-s18-{tag}-{}", run_tag()));
    std::fs::create_dir_all(&root).expect("mk vault root");
    root
}

fn create_at(root: &Path) -> VaultLayout {
    let layout = VaultLayout::at(root.join("vault"));
    create_vault(&layout, &passphrase(), KdfSelection::Argon2id, &mut rng()).expect("create vault");
    layout
}

fn unlock_at(root: &Path) -> UnlockedVault {
    let layout = VaultLayout::at(root.join("vault"));
    unlock_vault(&layout, &passphrase()).expect("unlock vault")
}

/// The single work the child sealed (there is exactly one per vault here).
fn only_work(store: &WorkStore<'_>) -> SealId {
    let works = store.list_works().expect("enumerate works");
    assert_eq!(
        works.len(),
        1,
        "expected exactly one work in the child's vault, found {}",
        works.len()
    );
    works[0]
}

// ─────────────────────────────────────────────────────────────────────
// Barrier hooks specific to S18
// ─────────────────────────────────────────────────────────────────────

/// Touches a marker file at `barrier`, then blocks forever so the parent
/// can `SIGKILL` a process that is standing exactly where it says it is.
#[derive(Debug)]
struct StallAt {
    barrier: Barrier,
    marker: PathBuf,
}

impl BarrierHook for StallAt {
    fn at(&self, barrier: Barrier) -> Result<(), SealError> {
        if barrier == self.barrier {
            std::fs::write(&self.marker, barrier.name()).expect("write the kill marker");
            // The parent is now racing to kill us. Nothing here may
            // complete: if this returned, the seal would finish and the
            // scenario would be silently untested.
            loop {
                std::thread::sleep(Duration::from_millis(50));
            }
        }
        Ok(())
    }
}

/// Touches a marker at `barrier` and **keeps going**, so the parent's kill
/// lands somewhere inside the work that follows it (case 2: mid-upload).
#[derive(Debug)]
struct MarkAt {
    barrier: Barrier,
    marker: PathBuf,
}

impl BarrierHook for MarkAt {
    fn at(&self, barrier: Barrier) -> Result<(), SealError> {
        if barrier == self.barrier {
            std::fs::write(&self.marker, barrier.name()).expect("write the kill marker");
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────
// Child driver
// ─────────────────────────────────────────────────────────────────────

/// Spawn this test binary again, running `child_seals_until_its_kill_point`
/// under `scenario`, and wait until it reports it has reached the point.
/// Returns the live child, still running, for the caller to `SIGKILL`.
fn spawn_child(scenario: &str, root: &Path, marker: &Path) -> std::process::Child {
    let exe = std::env::current_exe().expect("the test binary's own path");
    let mut command = std::process::Command::new(exe);
    command
        .args([
            "--exact",
            "child_seals_until_its_kill_point",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD_ENV, scenario)
        .env(VAULT_ENV, root)
        .env(MARKER_ENV, marker)
        // The child must derive the same W, nonces and fixture bytes as
        // the parent, so it inherits the run tag rather than minting one.
        .env(RUN_TAG_ENV, run_tag());
    command.spawn().expect("re-execute this test binary")
}

/// Block until the marker appears or the child dies. Panics on either
/// timeout or premature exit — both mean the scenario never happened.
fn await_marker(child: &mut std::process::Child, marker: &Path, what: &str) {
    let deadline = Instant::now() + Duration::from_secs(300);
    while Instant::now() < deadline {
        if marker.exists() {
            return;
        }
        if let Some(status) = child.try_wait().expect("poll the child") {
            panic!("the child exited ({status}) before reaching {what} — the scenario never ran");
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    let _ = child.kill();
    panic!("the child never reached {what} within 300s");
}

/// `Child::kill` is `SIGKILL` on Linux — no handler, no unwinding, no
/// destructor, no flush. That is the whole point.
fn sigkill(child: &mut std::process::Child) -> Duration {
    let started = Instant::now();
    child.kill().expect("SIGKILL the child");
    let status = child.wait().expect("reap the child");
    assert!(
        !status.success(),
        "the child exited successfully — it was not killed, so no crash was tested"
    );
    started.elapsed()
}

/// The child body. A no-op unless this process was spawned as a child, so
/// it is harmless when the suite runs normally.
#[test]
fn child_seals_until_its_kill_point() {
    let Some(scenario) = std::env::var_os(CHILD_ENV) else {
        return;
    };
    let scenario = scenario.to_string_lossy().into_owned();
    let root = PathBuf::from(std::env::var_os(VAULT_ENV).expect("the parent passes a vault root"));
    let marker = PathBuf::from(std::env::var_os(MARKER_ENV).expect("the parent passes a marker"));
    let Some((config, _env, key)) = gate() else {
        panic!("a child was spawned without a live devnet");
    };

    let sources = Sources::original();
    let files = sources.files();
    let unlocked = unlock_at(&root);
    let mut journal_rng = ChaCha20Rng::from_seed(run_seed("s18-child-journal"));
    let journal = VaultJournal::new(WorkStore::new(&unlocked), &mut journal_rng);
    let sink = CapturedReceipts::new();
    let gate_double = RecordingGate::new();
    let consent = ScriptedConsent::always_yes();

    let rt = runtime().expect("runtime");
    let result = rt.block_on(async {
        let backend = SealBackend::connect(&config, &key, sink.clone())
            .await
            .expect("child connects");
        match scenario.as_str() {
            SCENARIO_STALL_PRE_FINALIZE => {
                let barriers = StallAt {
                    barrier: Barrier::PostReceiptJournalPreFinalize,
                    marker: marker.clone(),
                };
                let pipeline = Pipeline::new(&backend, &gate_double, &journal, &consent, &barriers);
                pipeline
                    .seal(
                        &request(&files),
                        &mut ChaCha20Rng::from_seed(run_seed("s18-child-seal")),
                    )
                    .await
            }
            SCENARIO_KILL_MID_UPLOAD => {
                let barriers = MarkAt {
                    barrier: Barrier::PostReceiptJournalPreFinalize,
                    marker: marker.clone(),
                };
                let pipeline = Pipeline::new(&backend, &gate_double, &journal, &consent, &barriers);
                pipeline
                    .seal(
                        &request(&files),
                        &mut ChaCha20Rng::from_seed(run_seed("s18-child-seal")),
                    )
                    .await
            }
            other => panic!("unknown child scenario {other}"),
        }
    });
    // Reaching here at all means the parent's kill was too slow. Say so
    // loudly rather than exiting 0, which `await_marker`/`sigkill` would
    // report as "the child exited before its kill point".
    panic!("the child completed its seal ({result:?}) — the parent never killed it");
}

// ─────────────────────────────────────────────────────────────────────
// Case (1) — kill between pay and finalize, deterministic barrier
// ─────────────────────────────────────────────────────────────────────

/// **S18 accept row 1**: a kill between `pay` and `finalize_batch`, then a
/// resume, costs **exactly one** payment. Settled on Anvil: the wallet's
/// ANT balance falls by the quote once across the whole kill+resume, and
/// the resume submits no payment transaction of its own.
#[test]
fn case1_a_kill_between_pay_and_finalize_never_pays_twice() {
    let _guard = serial();
    let Some((config, env, key)) = gate() else {
        return;
    };

    let sources = Sources::original();
    let files = sources.files();
    let root = vault_root("case1");
    create_at(&root);
    let unlocked = unlock_at(&root);
    let mut journal_rng = ChaCha20Rng::from_seed(run_seed("s18-case1-journal"));
    let journal = VaultJournal::new(WorkStore::new(&unlocked), &mut journal_rng);

    let sink = CapturedReceipts::new();
    let gate_double = RecordingGate::new();
    let consent = ScriptedConsent::always_yes();
    let kill = KillAt::new(Barrier::PostReceiptJournalPreFinalize);

    let wallet = key.address().to_string();
    let token = env.payment_token().to_string();
    let before = ant_balance(env.rpc_url(), &token, &wallet).expect("balance before");

    let rt = runtime().expect("runtime");
    let started = Instant::now();
    let (killed, outcome, seal_id) = rt.block_on(async {
        let backend = SealBackend::connect(&config, &key, sink.clone())
            .await
            .expect("connect");

        let pipeline = Pipeline::new(&backend, &gate_double, &journal, &consent, &kill);
        let killed = pipeline
            .seal(
                &request(&files),
                &mut ChaCha20Rng::from_seed(run_seed("s18-case1-seal")),
            )
            .await
            .expect_err("the barrier kills this invocation");

        let seal_id = only_work(&WorkStore::new(&unlocked));
        // The resume runs over a *fresh* pipeline, as a second invocation
        // would — same journal, same backend session.
        let pipeline = Pipeline::new(&backend, &gate_double, &journal, &consent, &NoBarriers);
        let outcome = pipeline
            .resume(&seal_id)
            .await
            .expect("the interrupted work resumes");
        (killed, outcome, seal_id)
    });
    let elapsed = started.elapsed();

    assert!(
        matches!(
            killed,
            SealError::KilledAtBarrier(Barrier::PostReceiptJournalPreFinalize)
        ),
        "expected the named barrier kill, got {killed:?}"
    );

    // The resume finalized and did not pay.
    assert!(
        !outcome.paid_here,
        "the resume moved money — this is the double payment S18 exists to catch"
    );
    assert_eq!(outcome.paid_atto, 0, "a finalize-only resume pays nothing");
    let receipt = journal
        .receipt(&seal_id)
        .expect("journal read")
        .expect("a post-pay work has a journaled receipt");
    let quoted = consent.last().expect("consent was reached").quote;
    assert!(quoted.total_ant_atto > 0, "a zero quote proves nothing");
    assert_eq!(
        consent.calls(),
        1,
        "the resume re-consented, which means it re-quoted to pay again"
    );

    // The chain's account of it.
    let after = ant_balance(env.rpc_url(), &token, &wallet).expect("balance after");
    let spent = before.checked_sub(after).expect("balance did not decrease");
    assert_eq!(
        spent, quoted.total_ant_atto,
        "the on-chain ANT delta across kill+resume must equal the quote EXACTLY ONCE"
    );
    assert_eq!(
        receipt.storage_cost_atto, quoted.total_ant_atto,
        "the journaled receipt and the quote disagree"
    );
    for tx in &receipt.txs {
        assert!(
            tx_succeeded(env.rpc_url(), &hex32_0x(tx.tx_hash.as_bytes())).expect("receipt lookup"),
            "a receipted payment tx is not on the chain"
        );
    }
    assert_eq!(journal.state(&seal_id).expect("state"), SealState::Complete);
    eprintln!(
        "S18 case1 OK: killed at post-receipt-journal-pre-finalize, resumed, {} atto-ANT spent \
         once across {} payment tx(s), {:.1}s",
        spent,
        receipt.txs.len(),
        elapsed.as_secs_f64()
    );
}

/// **S18 accept row 5 — the real-`SIGKILL` variant of case (1).**
///
/// The barrier test above kills by returning `Err` from a function that has
/// already returned from `pay` and already completed its journal write.
/// This one kills the *process*, with no unwinding and no flush, so what is
/// actually under test is crash consistency of the receipt journal write:
/// if it were not atomic, the resume would find no receipt, re-quote, and
/// pay a second time — and the on-chain delta below would be twice the
/// quote.
#[test]
fn case1_a_real_sigkill_between_pay_and_finalize_never_pays_twice() {
    let _guard = serial();
    let Some((_config, env, key)) = gate() else {
        return;
    };

    let root = vault_root("case1-sigkill");
    create_at(&root);
    let marker = root.join("reached.kill-point");

    let wallet = key.address().to_string();
    let token = env.payment_token().to_string();
    let before = ant_balance(env.rpc_url(), &token, &wallet).expect("balance before");

    let started = Instant::now();
    let mut child = spawn_child(SCENARIO_STALL_PRE_FINALIZE, &root, &marker);
    await_marker(&mut child, &marker, "the pre-finalize kill point");
    let killed_after = sigkill(&mut child);
    let child_pid = child.id();

    // The vault must be takeable: the U5 lock is flock-backed and the
    // kernel released it when the process died.
    let unlocked = unlock_at(&root);
    let store = WorkStore::new(&unlocked);
    let seal_id = only_work(&store);
    let mut journal_rng = ChaCha20Rng::from_seed(run_seed("s18-sigkill-journal"));
    let journal = VaultJournal::new(WorkStore::new(&unlocked), &mut journal_rng);

    let state_at_crash = journal.state(&seal_id).expect("state survived the crash");
    let receipt_at_crash = journal
        .receipt(&seal_id)
        .expect("journal read")
        .expect("the receipt write completed before the crash — otherwise nothing records the pay");

    // Resume in this process, from the journal the dead process left.
    let Some((config, _env2, key2)) = gate() else {
        return;
    };
    let sink = CapturedReceipts::new();
    let gate_double = RecordingGate::new();
    let consent = ScriptedConsent::always_yes();
    let rt = runtime().expect("runtime");
    let outcome = rt.block_on(async {
        let backend = SealBackend::connect(&config, &key2, sink.clone())
            .await
            .expect("connect");
        let pipeline = Pipeline::new(&backend, &gate_double, &journal, &consent, &NoBarriers);
        pipeline
            .resume(&seal_id)
            .await
            .expect("the crashed work resumes")
    });

    assert!(
        !outcome.paid_here,
        "the resume after a SIGKILL paid again — the receipt journal write is not crash-consistent"
    );
    assert_eq!(
        consent.calls(),
        0,
        "a finalize-only resume never re-consents"
    );
    assert_eq!(sink.fired(), 0, "the resume submitted no payment at all");

    let after = ant_balance(env.rpc_url(), &token, &wallet).expect("balance after");
    let spent = before.checked_sub(after).expect("balance did not decrease");
    assert_eq!(
        spent, receipt_at_crash.storage_cost_atto,
        "the on-chain ANT delta across SIGKILL+resume must equal the receipt exactly once"
    );
    assert_eq!(journal.state(&seal_id).expect("state"), SealState::Complete);
    eprintln!(
        "S18 case1-SIGKILL OK: child pid {child_pid} SIGKILLed at {} (state {:?}), reaped in \
         {:.0}ms, resumed without paying; {} atto-ANT spent once, {:.1}s total",
        Barrier::PostReceiptJournalPreFinalize.name(),
        state_at_crash,
        killed_after.as_secs_f64() * 1000.0,
        spent,
        started.elapsed().as_secs_f64()
    );
}

// ─────────────────────────────────────────────────────────────────────
// Case (1b) — D37's multi-sub-batch payment
// ─────────────────────────────────────────────────────────────────────

/// **S18 accept row 2 (the reachable half)**: a payment split across
/// **several sub-batch transactions** submits exactly one tx per sub-batch,
/// captures one receipt per sub-batch through D37's hook, ends with a
/// complete quote→tx map, and moves the quote's worth of ANT exactly once.
///
/// The forced cap (S7's seam, forwarded by
/// `SealBackend::with_max_transfers_per_tx`) is what makes this reachable:
/// `MAX_TRANSFERS_PER_TRANSACTION` is 256, so the natural shape would need
/// a 257-blob work.
///
/// **The kill half of this row is NOT here, and cannot be — see S31.** A
/// kill *between* sub-batch txs is only observable from inside `pay`, and
/// the only in-`pay` seam is D37's capture hook. For the resume to then
/// avoid re-paying, that hook's sink must have written the receipt-so-far
/// **durably** — and no journal-backed `ReceiptSink` exists anywhere in the
/// tree today (`ReadOnly` and test doubles are the only implementations;
/// the pipeline journals the receipt itself, after `pay` returns). So a
/// kill between sub-batches currently loses every receipt so far and the
/// resume re-pays — which is precisely the hazard S16 measured and S27
/// recorded, still open on the production side.
#[test]
fn case1b_a_multi_sub_batch_payment_is_one_tx_per_sub_batch() {
    let _guard = serial();
    let Some((config, env, key)) = gate() else {
        return;
    };

    let sources = Sources::original();
    let files = sources.files();
    let root = vault_root("case1b");
    create_at(&root);
    let unlocked = unlock_at(&root);
    let mut journal_rng = ChaCha20Rng::from_seed(run_seed("s18-case1b-journal"));
    let journal = VaultJournal::new(WorkStore::new(&unlocked), &mut journal_rng);

    let sink = CapturedReceipts::new();
    let gate_double = RecordingGate::new();
    let consent = ScriptedConsent::always_yes();

    let wallet = key.address().to_string();
    let token = env.payment_token().to_string();
    let before = ant_balance(env.rpc_url(), &token, &wallet).expect("balance before");

    // One transfer per sub-batch: every priced blob becomes its own tx, so
    // the work's blob count is the sub-batch count.
    const FORCED_CAP: usize = 1;

    let rt = runtime().expect("runtime");
    let started = Instant::now();
    let outcome = rt.block_on(async {
        let backend = SealBackend::connect(&config, &key, sink.clone())
            .await
            .expect("connect")
            .with_max_transfers_per_tx(FORCED_CAP);
        let pipeline = Pipeline::new(&backend, &gate_double, &journal, &consent, &NoBarriers);
        let SealResult::Sealed(outcome) = pipeline
            .seal(
                &request(&files),
                &mut ChaCha20Rng::from_seed(run_seed("s18-case1b-seal")),
            )
            .await
            .expect("the multi-sub-batch work seals")
        else {
            panic!("expected Sealed");
        };
        outcome
    });
    let elapsed = started.elapsed();

    let quoted = consent.last().expect("consent").quote;
    let receipt = journal
        .receipt(&outcome.seal_id)
        .expect("journal read")
        .expect("journaled receipt");
    // The sub-batch unit is the **non-zero transfer**, not the blob:
    // upstream pays the price-sorted median 3x and zeroes the rest, which
    // is normally one transfer per priced blob but is not guaranteed to be.
    // Counting blobs here would make the expected tx count wrong the first
    // time a blob carried two paying quotes.
    let transfers: usize = quoted
        .blobs
        .iter()
        .map(|line| match &line.cost {
            BlobCost::AlreadyStored => 0,
            BlobCost::Priced { payments, .. } => {
                payments.iter().filter(|p| p.amount_atto > 0).count()
            }
        })
        .sum();
    let expected_txs = transfers.div_ceil(FORCED_CAP);

    assert!(
        expected_txs >= 2,
        "the forced cap did not produce a multi-tx payment ({transfers} non-zero transfers, cap \
         {FORCED_CAP}) — this row would be testing the single-tx path"
    );
    assert_eq!(
        receipt.txs.len(),
        expected_txs,
        "one tx per sub-batch, no more and no fewer"
    );
    assert_eq!(
        sink.fired(),
        expected_txs,
        "D37's hook must fire once per sub-batch, not once per payment"
    );

    // The quote→tx map covers every priced quote, and every tx landed.
    assert_eq!(
        receipt.tx_map.len(),
        transfers,
        "the quote→tx map must cover every paying quote"
    );
    let mut seen = std::collections::BTreeSet::new();
    for tx in &receipt.txs {
        assert!(
            seen.insert(tx.tx_hash),
            "a sub-batch tx hash repeats — a sub-batch was paid twice"
        );
        assert!(
            tx_succeeded(env.rpc_url(), &hex32_0x(tx.tx_hash.as_bytes())).expect("receipt lookup"),
            "a sub-batch tx is not on the chain"
        );
    }

    let after = ant_balance(env.rpc_url(), &token, &wallet).expect("balance after");
    let spent = before.checked_sub(after).expect("balance did not decrease");
    assert_eq!(
        spent, quoted.total_ant_atto,
        "the ANT delta across a multi-tx payment must still equal the quote exactly once"
    );
    eprintln!(
        "S18 case1b OK: {transfers} non-zero transfers at cap {FORCED_CAP} -> {} sub-batch \
         txs, {} hook captures, tx_map {} entries, {spent} atto-ANT once, {:.1}s",
        receipt.txs.len(),
        sink.fired(),
        receipt.tx_map.len(),
        elapsed.as_secs_f64()
    );
}

// ─────────────────────────────────────────────────────────────────────
// Case (2) — SIGKILL mid-upload, byte-identical resume
// ─────────────────────────────────────────────────────────────────────

/// **S18 accept row 3**: a `SIGKILL` landing *inside* `finalize_batch`,
/// then a resume, leaves every network copy byte-identical to the staged
/// ciphertext — fetched address by address and compared.
///
/// Dying after `k` of `n` blobs were stored inside one `finalize_batch`
/// call is deliberately not something the pipeline can subdivide (the
/// `Barrier` docs say so); on the devnet side it is exactly this. The
/// child signals when it is about to enter finalize and the parent kills it
/// shortly after, so the kill lands at an arbitrary point in the upload —
/// which is the realistic shape, and the assertions hold wherever it lands.
#[test]
fn case2_a_sigkill_mid_upload_resumes_byte_identically() {
    let _guard = serial();
    let Some((config, _env, key)) = gate() else {
        return;
    };

    let root = vault_root("case2");
    create_at(&root);
    let marker = root.join("entering.finalize");

    let started = Instant::now();
    let mut child = spawn_child(SCENARIO_KILL_MID_UPLOAD, &root, &marker);
    await_marker(&mut child, &marker, "the finalize entry point");
    // Let the upload get under way before pulling the plug.
    std::thread::sleep(Duration::from_millis(700));
    let child_pid = child.id();
    sigkill(&mut child);

    let unlocked = unlock_at(&root);
    let store = WorkStore::new(&unlocked);
    let seal_id = only_work(&store);
    let mut journal_rng = ChaCha20Rng::from_seed(run_seed("s18-case2-journal"));
    let journal = VaultJournal::new(WorkStore::new(&unlocked), &mut journal_rng);
    let state_at_crash = journal.state(&seal_id).expect("state survived");
    assert_ne!(
        state_at_crash,
        SealState::Complete,
        "the child finished before the kill — nothing was interrupted"
    );

    // Every staged blob, as the dead process left it.
    let plan = journal
        .plan(&seal_id)
        .expect("journal read")
        .expect("a staged work has a plan");
    let mut staged = Vec::new();
    for unit_id in 0..plan.unit_count {
        staged.push(
            journal
                .staged(&seal_id, BlobSlot::Unit { unit_id })
                .expect("staged unit"),
        );
    }
    staged.push(
        journal
            .staged(&seal_id, BlobSlot::EncryptedManifest)
            .expect("staged manifest"),
    );
    let nonces_before: Vec<_> = staged.iter().map(|blob| blob.nonce).collect();

    let sink = CapturedReceipts::new();
    let gate_double = RecordingGate::new();
    let consent = ScriptedConsent::always_yes();
    let barriers = TraceBarriers::new();
    let rt = runtime().expect("runtime");
    let fetched = rt.block_on(async {
        let backend = SealBackend::connect(&config, &key, sink.clone())
            .await
            .expect("connect");
        let pipeline = Pipeline::new(&backend, &gate_double, &journal, &consent, &barriers);
        pipeline
            .resume(&seal_id)
            .await
            .expect("the mid-upload crash resumes");

        // The accept row, literally: fetch every address and compare.
        let mut fetched = Vec::with_capacity(staged.len());
        for blob in &staged {
            let bytes = backend
                .get_data(blob.address.into())
                .await
                .unwrap_or_else(|e| panic!("fetch {} failed: {e}", hex32(blob.address.as_bytes())));
            fetched.push(bytes);
        }
        fetched
    });

    for (blob, bytes) in staged.iter().zip(&fetched) {
        assert_eq!(
            &blob.ciphertext,
            bytes,
            "the network copy at {} is not the staged ciphertext",
            hex32(blob.address.as_bytes())
        );
    }

    // No re-encryption: resume holds no `W` (structural), and the staged
    // nonces are exactly the ones the dead process journaled.
    let nonces_after: Vec<_> = (0..plan.unit_count)
        .map(|unit_id| {
            journal
                .staged(&seal_id, BlobSlot::Unit { unit_id })
                .expect("staged unit")
                .nonce
        })
        .chain(std::iter::once(
            journal
                .staged(&seal_id, BlobSlot::EncryptedManifest)
                .expect("staged manifest")
                .nonce,
        ))
        .collect();
    assert_eq!(
        nonces_before, nonces_after,
        "a staged nonce changed across the resume — something re-encrypted"
    );
    assert!(
        !barriers.crossed().contains(&Barrier::PostStagingJournal),
        "the resume re-ran staging, which means it re-encrypted: {:?}",
        barriers.crossed()
    );
    assert_eq!(journal.state(&seal_id).expect("state"), SealState::Complete);

    eprintln!(
        "S18 case2 OK: child pid {child_pid} SIGKILLed mid-finalize (state at crash {:?}), \
         resumed; {} blobs fetched and byte-equal to their staged ciphertext, {:.1}s",
        state_at_crash,
        fetched.len(),
        started.elapsed().as_secs_f64()
    );
}

// ─────────────────────────────────────────────────────────────────────
// Case (3) — the (k_u, nonce)-reuse guard
// ─────────────────────────────────────────────────────────────────────

/// **S18 accept row 4**: sources changed *and* staged bytes gone ⇒ the
/// resume abandons with the distinct error rather than re-encrypting.
///
/// This is the guard that exists so a journaled nonce is never handed back
/// to the encryptor: re-encrypting the edited sources would produce
/// different plaintext under the same `(k_u, nonce)`, which is the AEAD
/// misuse that breaks confidentiality outright. The instrumentation is
/// threefold — the work is `Abandoned`, no payment left the wallet, and a
/// fresh seal of the changed sources draws a **new** `seal_id` and nonces
/// that differ from every journaled one.
#[test]
fn case3_changed_sources_with_staged_bytes_gone_abandons() {
    let _guard = serial();
    let Some((config, env, key)) = gate() else {
        return;
    };

    let original = Sources::original();
    let root = vault_root("case3-abandon");
    create_at(&root);
    let unlocked = unlock_at(&root);
    let store = WorkStore::new(&unlocked);
    let mut journal_rng = ChaCha20Rng::from_seed(run_seed("s18-case3-journal"));
    let journal = VaultJournal::new(WorkStore::new(&unlocked), &mut journal_rng);

    let sink = CapturedReceipts::new();
    let gate_double = RecordingGate::new();
    let consent = ScriptedConsent::always_yes();
    let kill = KillAt::new(Barrier::PostStagingJournal);

    let wallet = key.address().to_string();
    let token = env.payment_token().to_string();

    let rt = runtime().expect("runtime");
    let seal_id = {
        let files = original.files();
        rt.block_on(async {
            let backend = SealBackend::connect(&config, &key, sink.clone())
                .await
                .expect("connect");
            let pipeline = Pipeline::new(&backend, &gate_double, &journal, &consent, &kill);
            pipeline
                .seal(
                    &request(&files),
                    &mut ChaCha20Rng::from_seed(run_seed("s18-case3-seal")),
                )
                .await
                .expect_err("killed right after staging");
            only_work(&WorkStore::new(&unlocked))
        })
    };

    // The journaled nonces, before anything is destroyed.
    let plan = journal
        .plan(&seal_id)
        .expect("journal read")
        .expect("staged plan");
    let journaled_nonces: Vec<_> = (0..plan.unit_count)
        .map(|unit_id| {
            journal
                .staged(&seal_id, BlobSlot::Unit { unit_id })
                .expect("staged unit")
                .nonce
        })
        .collect();
    assert!(!journaled_nonces.is_empty());

    // "Make staged bytes unavailable": drop unit 0's record. The sources
    // are separately changed — which is what makes re-encryption tempting
    // and wrong.
    assert!(
        store
            .delete_journal_entry(&seal_id, UNIT_ENTRY_BASE)
            .expect("delete a staged unit"),
        "the staged unit record was there to delete"
    );

    let balance_before = ant_balance(env.rpc_url(), &token, &wallet).expect("balance before");
    let resumed = rt.block_on(async {
        let backend = SealBackend::connect(&config, &key, sink.clone())
            .await
            .expect("connect");
        let pipeline = Pipeline::new(&backend, &gate_double, &journal, &consent, &NoBarriers);
        pipeline.resume(&seal_id).await
    });

    match resumed {
        Err(SealError::StagedBytes(StagedBytesUnavailable::Missing)) => {}
        other => panic!("expected the distinct staged-bytes abandon, got {other:?}"),
    }
    assert_eq!(
        journal.state(&seal_id).expect("state"),
        SealState::Abandoned,
        "the work must be marked abandoned, not left resumable"
    );
    let balance_after = ant_balance(env.rpc_url(), &token, &wallet).expect("balance after");
    assert_eq!(
        balance_before, balance_after,
        "the abandoning resume moved ANT — it must never reach a payment"
    );
    assert_eq!(sink.fired(), 0, "no payment was made at any point");

    // The fresh-seal path: a new work, new seal_id, and nonces that are
    // not any of the journaled ones.
    let changed = Sources::changed();
    let files = changed.files();
    let fresh = rt.block_on(async {
        let backend = SealBackend::connect(&config, &key, sink.clone())
            .await
            .expect("connect");
        let pipeline = Pipeline::new(&backend, &gate_double, &journal, &consent, &NoBarriers);
        let SealResult::Sealed(outcome) = pipeline
            .seal(
                &request(&files),
                &mut ChaCha20Rng::from_seed(run_seed("s18-case3-fresh")),
            )
            .await
            .expect("the changed sources seal as a new work")
        else {
            panic!("expected Sealed");
        };
        outcome
    });

    assert_ne!(fresh.seal_id, seal_id, "a fresh seal draws a new seal_id");
    let fresh_plan = journal
        .plan(&fresh.seal_id)
        .expect("journal read")
        .expect("plan");
    for unit_id in 0..fresh_plan.unit_count {
        let nonce = journal
            .staged(&fresh.seal_id, BlobSlot::Unit { unit_id })
            .expect("staged unit")
            .nonce;
        assert!(
            !journaled_nonces.contains(&nonce),
            "the fresh seal reused a nonce journaled by the abandoned work — this is the \
             (k_u, nonce) reuse the guard exists to prevent"
        );
    }
    eprintln!(
        "S18 case3-abandon OK: distinct StagedBytes(Missing) error, state Abandoned, zero ANT \
         moved, fresh seal drew a new seal_id and {} nonces disjoint from the {} journaled ones",
        fresh_plan.unit_count,
        journaled_nonces.len()
    );
}

/// **S18 accept row 4, second half**: changed sources but staged bytes
/// **intact** resume successfully — from the staged bytes alone.
///
/// The proof that the staged bytes (not the edited sources) were used is
/// the restored content: it is the ORIGINAL text, even though the file on
/// disk now says something else. A resume that re-read the sources would
/// return the changed bytes; a resume that re-encrypted would also have
/// reused a journaled nonce.
#[test]
fn case3_changed_sources_with_staged_bytes_intact_resume_from_staged_bytes() {
    let _guard = serial();
    let Some((config, _env, key)) = gate() else {
        return;
    };

    let original = Sources::original();
    let root = vault_root("case3-intact");
    create_at(&root);
    let unlocked = unlock_at(&root);
    let store = WorkStore::new(&unlocked);
    let mut journal_rng = ChaCha20Rng::from_seed(run_seed("s18-case3b-journal"));
    let journal = VaultJournal::new(WorkStore::new(&unlocked), &mut journal_rng);

    let sink = CapturedReceipts::new();
    let gate_double = RecordingGate::new();
    let consent = ScriptedConsent::always_yes();
    let kill = KillAt::new(Barrier::PostReceiptJournalPreFinalize);

    let rt = runtime().expect("runtime");
    let (seal_id, report) = rt.block_on(async {
        let backend = SealBackend::connect(&config, &key, sink.clone())
            .await
            .expect("connect");
        let files = original.files();
        let pipeline = Pipeline::new(&backend, &gate_double, &journal, &consent, &kill);
        pipeline
            .seal(
                &request(&files),
                &mut ChaCha20Rng::from_seed(run_seed("s18-case3b-seal")),
            )
            .await
            .expect_err("killed before finalize");
        let seal_id = only_work(&WorkStore::new(&unlocked));

        // The sources "change" here — the pipeline is never shown them
        // again, which is the point: resume must not want them.
        let pipeline = Pipeline::new(&backend, &gate_double, &journal, &consent, &NoBarriers);
        pipeline
            .resume(&seal_id)
            .await
            .expect("staged bytes are intact, so the resume completes");

        let engine = RestoreEngine::new(&backend, &store);
        let report = engine.restore(&seal_id).await.expect("restore");
        (seal_id, report)
    });

    let restored = report
        .verified()
        .find(|f| f.recorded_path == "work.txt")
        .expect("work.txt verified");
    assert_eq!(
        restored.bytes,
        original_text(),
        "the resumed work restored the CHANGED source — resume re-read the files instead of \
         using the staged bytes"
    );
    assert_ne!(
        restored.bytes,
        changed_text(),
        "the restored bytes match the edited sources, which staged bytes could not have produced"
    );
    assert_eq!(journal.state(&seal_id).expect("state"), SealState::Complete);
    eprintln!(
        "S18 case3-intact OK: resumed from staged bytes alone; restored content is the original, \
         not the edited sources"
    );
}
