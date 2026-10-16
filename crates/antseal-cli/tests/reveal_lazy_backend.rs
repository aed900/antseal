//! D175 acceptance suite (`U91`): in the `ant-backend` build `reveal` fetches
//! uncached ciphertext through the D170 reader, **connected at most once and
//! only from a needed fetch**, and nothing about the network may fail a reveal
//! that needs no fetch; the default build keeps `U72` byte for byte.
//!
//! The rows are the three witnesses D175 §2 R8 restates `U91`'s "zero backend
//! calls" `Accept` into, plus the refusal classes of §2 R3 and the transient
//! class of §2 R4:
//!
//! - **(b), feature build, library**: the **production** lazy backend from the
//!   gated constructor, handed a definition that could only dial a dead
//!   network, reports zero connection attempts and zero calls after
//!   `RevealEngine::prepare` on a fully cached fixture, beside the engine's
//!   own `units_from_cache > 0` — and the production driver, driven the same
//!   way, reads the same zeros from inside its closure;
//! - **(c), both builds, spawned**: exit 0, `units.from_network == 0`,
//!   `units.from_cache > 0` and **no** *"connecting the read-only reader"*
//!   trace, under no export **and** under a dead export. No export catches an
//!   eager definition (it would exit 2); a dead export catches an eager
//!   connect (which on the pinned stack succeeds and would exit 0 — after the
//!   trace);
//! - the partial-cache rows, per build: the build with no backend refuses at
//!   the seam in its own words (U72, unchanged); the build with one reaches
//!   its first fetch and meets, in this order and each in its own class, an
//!   unparseable record (36), a disagreeing `--network` (2), a missing
//!   definition (2) — all before the consent gate, with nothing written and
//!   no connection — or, with a usable definition, an unreachable network in
//!   the network class (23), in the engine's `Unfetchable` sentence, never the
//!   no-backend sentence and never absence.
//!
//! None of this calls `run_reveal`: `U71`'s closed list of its callers is
//! not edited for a test (D175 §2 R6). The library rows drive
//! `RevealEngine::prepare` — where the gathering, and so the refusal, happens
//! — and the process rows read the binary.
//!
//! The accept row that needs a live devnet (a clean home after `vault import`
//! revealing a strict subset from the network) is suite S19's,
//! `tests/e2e_restore.rs`.
//!
//! NON-SECRET: every fixture byte string is documented here; the dead export
//! is walletless and names Anvil's well-known deterministic contracts.

mod common;

#[path = "common/spawn.rs"]
mod spawn;

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::Stdio;

use antseal_cli::backend::BackendArm;
use antseal_cli::pipeline::journal::UNIT_ENTRY_BASE;
use antseal_cli::pipeline::{
    NoBarriers, Pipeline, SealFile, SealRequest, SealResult, VaultJournal, hex32,
};
use antseal_cli::upgrade_hook::HOOK_ARMED;
use antseal_cli::vault::session::UnlockedVault;
use antseal_cli::vault::store::{SealShapingFlags, WorkStore};
use antseal_core::content::{FileFlags, SplitMode};
use antseal_core::crypto::secrets::SealId;
use antseal_core::crypto::sig_policy::SigPolicy;
use antseal_core::verify::{VerifyOptions, verify_bundle};
use antseal_net::NetworkId;
use antseal_net::test_util::{MockBackend, block_on};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

use common::{IsolatedVault, RecordingGate, ScriptedConsent};

/// BOM + CRLF + NFD: raw bytes differ from canonical three ways, so this
/// file carries a raw mirror.
const CRLF_BOM_NFD: &[u8] = "\u{FEFF}caf\u{65}\u{301} notes\r\n\r\nsecond para\r\n".as_bytes();
const BINARY: &[u8] = &[0x00, 0x01, 0x02, 0xFF, 0xFE, 0x7F, 0x80, 0x00, 0x42];
const SPLIT_TEXT: &[u8] = b"alpha one\n\nbeta two\n\ngamma three\n";

/// The two traces the process rows read: D42's hook says the invocation
/// unlocked a vault — the process-level witness of *after the passphrase* —
/// and the read-only construction says whether a connection was attempted.
const HANDLER_LOG: &str = "antseal_cli::upgrade_hook=debug,antseal_cli::backend=debug";

/// `connect_read_only`'s one trace, emitted inside its future — so only when
/// a connection is actually attempted.
const READER_CONNECT_TRACE: &str = "connecting the read-only reader";

/// What a build with a backend compiled in may never print for a fetch (D170
/// §2 R2; D175 §2 R4): the no-backend sentence's own claim. Since U95 that is
/// the only seam sentence left, and it is compiled into the feature build too
/// (`no_backend_message`, D180 U95 R3), so a fault that routes it into that
/// build's `reveal` is one these checks can see — the `Compiled` arm's
/// sentence they used to forbid existed in no build's output after D175, and
/// a check forbidding text nothing can print cannot fail (D180 U95 R5).
const NO_BACKEND_FRAGMENT: &str = "no storage backend compiled in";

/// The engine's rendering of `NotFound` — what an unreachable network must
/// never be reported as (D170 §2 R12; D175 §2 R4).
const ABSENCE_SENTENCE: &str = "has no data at this address";

/// The engine's own fetch-failure sentence (`RevealError::Unfetchable`).
const UNFETCHABLE_SENTENCE: &str = "could not be fetched from the network";

// ─────────────────────────────────────────────────────────────────────
// Harness
// ─────────────────────────────────────────────────────────────────────

/// A scratch directory that removes itself.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "antseal-d175-{tag}-{}-{}",
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

/// Seal the three-file fixture work on `devnet` into `vault` through the real
/// pipeline over a `MockBackend`, every D43 cache copy retained, and return
/// the printed work id. The only place a network appears in this suite's
/// fixtures is here, in the seal that put the bytes in the cache.
fn seal_fixture(vault: &UnlockedVault, seed: u8) -> String {
    let files = vec![
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
    ];
    let mock = MockBackend::new();
    let mut journal_rng = ChaCha20Rng::from_seed([seed ^ 0xA5; 32]);
    let journal = VaultJournal::new(WorkStore::new(vault), &mut journal_rng);
    let gate = RecordingGate::new();
    let consent = ScriptedConsent::always_yes();
    let pipeline = Pipeline::new(&mock, &gate, &journal, &consent, &NoBarriers);
    let request = SealRequest {
        files: &files,
        title: "d175 fixture".to_owned(),
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

/// The only work in a fixture vault.
fn only_work(store: &WorkStore<'_>) -> SealId {
    let works = store.list_works().expect("list");
    assert_eq!(works.len(), 1, "the fixture vault holds one work");
    works[0]
}

/// How many per-unit D43 cache copies the vault holds.
fn unit_cache_entries(store: &WorkStore<'_>) -> usize {
    let seal_id = only_work(store);
    store
        .list_journal_entries(&seal_id)
        .expect("entries")
        .into_iter()
        .filter(|entry| *entry >= UNIT_ENTRY_BASE)
        .count()
}

/// A vault holding the fixture work with every cache copy retained — the
/// shape every "fully cached" row starts from, asserted rather than assumed.
fn fully_cached_fixture(tag: &str, seed: u8) -> (IsolatedVault, String) {
    let vault = IsolatedVault::create(tag);
    let work_id = {
        let unlocked = vault.unlock();
        let work_id = seal_fixture(&unlocked, seed);
        let cached = unit_cache_entries(&WorkStore::new(&unlocked));
        assert!(
            cached >= 3,
            "the fixture must be fully cached, or the zero-call question does not arise: {cached}"
        );
        work_id
    };
    (vault, work_id)
}

/// Drop **one** cached unit ciphertext: the partial-cache shape. Returns the
/// evicted unit's id and how many cache entries remain, so a row cannot
/// silently be measuring an empty cache.
fn evict_one_unit(vault: &IsolatedVault) -> (u64, usize) {
    let unlocked = vault.unlock();
    let store = WorkStore::new(&unlocked);
    let seal_id = only_work(&store);
    let mut units: Vec<u64> = store
        .list_journal_entries(&seal_id)
        .expect("entries")
        .into_iter()
        .filter(|entry| *entry >= UNIT_ENTRY_BASE)
        .collect();
    units.sort_unstable();
    assert!(
        units.len() > 1,
        "the fixture must cache more than one unit, or 'partial' is 'empty'"
    );
    store
        .delete_journal_entry(&seal_id, units[0])
        .expect("evict one unit");
    (units[0] - UNIT_ENTRY_BASE, units.len() - 1)
}

/// Rewrite the fixture work's recorded network to `network` — a string this
/// build cannot resolve, for the unparseable-record rows. Through the store's
/// own meta writer, so the record is otherwise exactly what the seal wrote.
fn forge_recorded_network(vault: &IsolatedVault, network: &str) {
    let unlocked = vault.unlock();
    let store = WorkStore::new(&unlocked);
    let seal_id = only_work(&store);
    let mut record = store.load_meta(&seal_id).expect("load the record");
    record.network = network.to_owned();
    store
        .store_meta(&record, &mut ChaCha20Rng::from_seed([0x5E; 32]))
        .expect("rewrite the record");
    assert_eq!(
        store.load_meta(&seal_id).expect("reload").network,
        network,
        "the forged network was written and read back"
    );
}

/// A devnet definition that reaches **nothing**: its one bootstrap peer is a
/// loopback UDP port bound and released a moment ago, and its payment RPC a
/// loopback TCP port likewise — D170 §2 R7's negative-control shape, with no
/// devnet anywhere.
///
/// NON-SECRET: no key line at all (a walletless export), and the two contract
/// addresses are Anvil's well-known deterministic deployments.
fn dead_devnet_export_text(dir: &Path) -> String {
    let udp = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind a loopback probe socket");
    let bootstrap = udp.local_addr().expect("the probe's address");
    drop(udp);
    let tcp = std::net::TcpListener::bind("127.0.0.1:0").expect("bind a loopback probe listener");
    let rpc_port = tcp.local_addr().expect("the probe's address").port();
    drop(tcp);
    format!(
        "# antseal devnet environment: a dead one, for a negative control\n\
         ANTSEAL_DEVNET_RPC_URL='http://127.0.0.1:{rpc_port}/'\n\
         ANTSEAL_DEVNET_CHAIN_ID='31337'\n\
         ANTSEAL_DEVNET_TOKEN_ADDRESS='0x5FbDB2315678afecb367f032d93F642f64180aa3'\n\
         ANTSEAL_DEVNET_PAYMENT_VAULT_ADDRESS='0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512'\n\
         ANTSEAL_DEVNET_BOOTSTRAP='{bootstrap}'\n\
         ANTSEAL_DEVNET_NODE_COUNT='1'\n\
         ANTSEAL_DEVNET_BASE_PORT='{port}'\n\
         ANTSEAL_DEVNET_DATA_DIR='{data}'\n\
         ANTSEAL_DEVNET_PID='{pid}'\n",
        port = bootstrap.port(),
        data = dir.display(),
        pid = std::process::id(),
    )
}

/// [`dead_devnet_export_text`] written where a spawned binary can be pointed
/// at it.
fn dead_devnet_export(dir: &Path) -> PathBuf {
    let path = dir.join("dead-devnet.env");
    std::fs::write(&path, dead_devnet_export_text(dir)).expect("write the dead devnet export");
    path
}

/// What a spawned `antseal` answered.
struct Spawned {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

impl Spawned {
    /// The one `--json` document on stdout.
    fn document(&self) -> serde_json::Value {
        serde_json::from_str(self.stdout.trim_end_matches('\n')).unwrap_or_else(|error| {
            panic!(
                "stdout is not one JSON document ({error}).\nstdout:\n{}\nstderr:\n{}",
                self.stdout, self.stderr
            )
        })
    }

    /// The error envelope's message.
    fn message(&self) -> String {
        self.document()["error"]["message"]
            .as_str()
            .unwrap_or_else(|| panic!("an error message: {}", self.document()))
            .to_owned()
    }

    /// How many times a connection was attempted, by the reader's one trace.
    fn connect_traces(&self) -> usize {
        self.stderr.matches(READER_CONNECT_TRACE).count()
    }
}

/// Spawn `antseal --json [<before>…] --passphrase-fd 0 reveal <work> --all
/// --yes -o <bundle>` over the vault at `vault_root`, with the fixture
/// passphrase on stdin and `devnet_env` as the only devnet definition it can
/// see (`None` strips any the developer's shell exported).
fn spawn_reveal(
    vault_root: &Path,
    before: &[&str],
    work_id: &str,
    bundle: &Path,
    devnet_env: Option<&Path>,
) -> Spawned {
    let bundle_arg = bundle.to_str().expect("a utf-8 scratch path").to_owned();
    let mut args = vec!["--json"];
    args.extend_from_slice(before);
    args.extend([
        "--passphrase-fd",
        "0",
        "reveal",
        work_id,
        "--all",
        "--yes",
        "-o",
        &bundle_arg,
    ]);
    let mut command = spawn::antseal();
    command
        .args(&args)
        .env("ANTSEAL_DIR", vault_root)
        .env("RUST_LOG", HANDLER_LOG)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    match devnet_env {
        Some(path) => {
            command.env("ANTSEAL_DEVNET_ENV", path);
        }
        None => {
            command.env_remove("ANTSEAL_DEVNET_ENV");
        }
    }
    let mut child = command.spawn().expect("spawn antseal");
    // Ignored on purpose: a command that refuses before reading the
    // passphrase closes the pipe first, and that is the command doing its
    // job rather than the harness failing.
    let _ = child
        .stdin
        .as_mut()
        .expect("stdin is piped")
        .write_all(common::FIXTURE_PASSPHRASE);
    drop(child.stdin.take());
    let out = child.wait_with_output().expect("wait for antseal");
    Spawned {
        code: out.status.code(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

/// What a fully cached reveal must look like in **either** build: exit 0,
/// every unit from the cache, nothing fetched, no connection attempted, the
/// vault unlocked, the bundle on disk and verifying offline.
fn assert_cached_reveal(label: &str, run: &Spawned, bundle: &Path) {
    assert_eq!(
        run.code,
        Some(0),
        "{label}: a fully cached reveal completes in this build (D175 §2 R2). stderr:\n{}",
        run.stderr
    );
    let document = run.document();
    assert_eq!(
        document["ok"],
        serde_json::json!(true),
        "{label}: {document}"
    );
    assert_eq!(
        document["result"]["units"]["from_network"],
        serde_json::json!(0),
        "{label}: nothing was fetched: {document}"
    );
    assert!(
        document["result"]["units"]["from_cache"]
            .as_u64()
            .is_some_and(|n| n > 0),
        "{label}: every unit came from the D43 cache: {document}"
    );
    assert_eq!(
        run.connect_traces(),
        0,
        "{label}: a fully cached reveal attempts no connection — the read-only reader's trace \
         must be absent (D175 §2 R8 (c)). stderr:\n{}",
        run.stderr
    );
    assert!(
        run.stderr.contains(HOOK_ARMED),
        "{label}: the vault was unlocked. stderr:\n{}",
        run.stderr
    );
    let bytes = std::fs::read(bundle)
        .unwrap_or_else(|error| panic!("{label}: the bundle is on disk: {error}"));
    verify_bundle(&bytes, &VerifyOptions::new())
        .unwrap_or_else(|error| panic!("{label}: the written bundle verifies offline: {error:?}"));
}

/// What a build with **no** backend answers for any reveal that needs a
/// fetch — U72, unchanged by D175 §2 R1: the seam refusal in the build's own
/// words, in the network class, after the passphrase, with no connection and
/// nothing written.
fn assert_vault_local_refusal(label: &str, run: &Spawned, bundle: &Path) {
    assert_eq!(
        run.code,
        Some(23),
        "{label}: the default build refuses a required fetch at the seam (U72). stderr:\n{}",
        run.stderr
    );
    let document = run.document();
    assert_eq!(
        document["error"]["class"],
        serde_json::json!("network-failure"),
        "{label}: {document}"
    );
    let message = run.message();
    assert!(
        message.contains(NO_BACKEND_FRAGMENT) && message.contains("unit "),
        "{label}: the refusal names the build's own reason and the unit it could not obtain: \
         {message}"
    );
    assert_eq!(
        run.connect_traces(),
        0,
        "{label}: a build with no backend attempts no connection. stderr:\n{}",
        run.stderr
    );
    assert!(
        run.stderr.contains(HOOK_ARMED),
        "{label}: refused after the passphrase. stderr:\n{}",
        run.stderr
    );
    assert!(
        !bundle.exists(),
        "{label}: a refused reveal writes no bundle"
    );
}

/// What the `ant-backend` build answers when the first needed fetch meets a
/// **refusal** rather than a network: the refusal's own class and words,
/// after the passphrase, before any connection, with nothing written (D175
/// §2 R3).
fn assert_lazy_refusal(
    label: &str,
    run: &Spawned,
    bundle: &Path,
    code: i32,
    class: &str,
    must_name: &[&str],
    must_not_name: &[&str],
) {
    assert_eq!(
        run.code,
        Some(code),
        "{label}: the refusal keeps its own class, {class} ({code}), rather than the network \
         failure it would otherwise be reported as (D175 §2 R3). stderr:\n{}",
        run.stderr
    );
    let document = run.document();
    assert_eq!(
        document["error"]["class"],
        serde_json::json!(class),
        "{label}: {document}"
    );
    let message = run.message();
    for fragment in must_name {
        assert!(
            message.contains(fragment),
            "{label}: the refusal names `{fragment}`: {message}"
        );
    }
    for fragment in must_not_name {
        assert!(
            !message.contains(fragment),
            "{label}: the refusal must not carry `{fragment}`: {message}"
        );
    }
    assert!(
        !message.contains(NO_BACKEND_FRAGMENT),
        "{label}: a build with a backend compiled in never prints the no-backend sentence: \
         {message}"
    );
    assert_eq!(
        run.connect_traces(),
        0,
        "{label}: refused BEFORE any connection. stderr:\n{}",
        run.stderr
    );
    assert!(
        run.stderr.contains(HOOK_ARMED),
        "{label}: refused AFTER the passphrase — the vault had been unlocked. stderr:\n{}",
        run.stderr
    );
    assert!(
        !bundle.exists(),
        "{label}: a refused reveal writes no bundle"
    );
}

// ─────────────────────────────────────────────────────────────────────
// D175 §2 R2 / R8 (c): a fully cached reveal, through the binary, per build
// ─────────────────────────────────────────────────────────────────────

/// **D175 §2 R8 (c), both builds**: a fully cached reveal exits 0 with every
/// unit from the cache and **no** connection attempted — under no export
/// *and* under a dead export.
///
/// The two settings catch two different eager mistakes. With no export, an
/// eagerly resolved definition refuses a `devnet` work with usage 2 before
/// anything is gathered (D175 §1, defect 2 — the regression of U72 in the
/// release build). With a dead export the definition resolves, so an eager
/// *connect* would still exit 0 — after dialling a dead bootstrap for
/// seconds — and only the reader's trace tells that run from this one.
#[test]
fn a_fully_cached_reveal_attempts_no_connection_under_no_export_and_a_dead_export() {
    let scratch = Scratch::new("cached-per-build");
    let (vault, work_id) = fully_cached_fixture("d175-cached", 0x11);
    let dead = dead_devnet_export(&scratch.0);

    for (label, export) in [("no export", None), ("a dead export", Some(dead.as_path()))] {
        let bundle = scratch.join(&format!("{}.sealproof", label.replace(' ', "-")));
        let run = spawn_reveal(vault.layout.root(), &[], &work_id, &bundle, export);
        assert_cached_reveal(label, &run, &bundle);
        assert_eq!(
            run.document()["result"]["network"],
            serde_json::json!("devnet"),
            "{label}: the work's recorded network, verbatim (D174 §2 R12)"
        );
    }
}

/// **D175 §2 R2/R3, the flag half**: a `--network` that disagrees with the
/// record does not refuse a reveal that fetches nothing — in either build.
/// The comparison lives inside the deferred fetch, so it is never made.
#[test]
fn a_fully_cached_reveal_ignores_a_disagreeing_network_flag_because_it_fetches_nothing() {
    let scratch = Scratch::new("cached-flag");
    let (vault, work_id) = fully_cached_fixture("d175-cached-flag", 0x12);
    let bundle = scratch.join("flagged.sealproof");

    let run = spawn_reveal(
        vault.layout.root(),
        &["--network", "arbitrum-one"],
        &work_id,
        &bundle,
        None,
    );
    assert_cached_reveal(
        "--network arbitrum-one over a cached devnet work",
        &run,
        &bundle,
    );
    let document = run.document();
    assert_eq!(
        document["network"],
        serde_json::json!("arbitrum-one"),
        "the invocation's network is what the flag said (D174 §2 R11): {document}"
    );
    assert_eq!(
        document["result"]["network"],
        serde_json::json!("devnet"),
        "and the result's is the record's (D174 §2 R12): {document}"
    );
}

/// **D175 §2 R2, the record half**: even an **unparseable** recorded network
/// does not fail a reveal that fetches nothing — the parse lives inside the
/// deferred fetch too. The partial-cache row below is where it surfaces, as
/// reveal's own class (36).
#[test]
fn a_fully_cached_reveal_with_an_unparseable_recorded_network_still_completes() {
    let scratch = Scratch::new("cached-unparseable");
    let (vault, work_id) = fully_cached_fixture("d175-cached-unparseable", 0x13);
    forge_recorded_network(&vault, "mainnet");
    let bundle = scratch.join("unparseable.sealproof");

    let run = spawn_reveal(vault.layout.root(), &[], &work_id, &bundle, None);
    assert_cached_reveal(
        "an unparseable recorded network, fully cached",
        &run,
        &bundle,
    );
    assert_eq!(
        run.document()["result"]["network"],
        serde_json::json!("mainnet"),
        "the record's string rides verbatim, parsed by nothing (D174 §2 R12)"
    );
}

// ─────────────────────────────────────────────────────────────────────
// D175 §2 R3 / R4: a partial cache, through the binary, per build
// ─────────────────────────────────────────────────────────────────────

/// **D175 §2 R3, no definition**: one evicted unit, no devnet export. The
/// build with a backend reaches its first fetch and refuses with the
/// resolver's own text — **usage (2)**, naming `ANTSEAL_DEVNET_ENV` — after
/// the passphrase, before any connection, nothing written. The build with
/// none refuses at the seam in its own words (U72).
#[test]
fn a_partial_cache_with_no_definition_is_refused_at_the_first_fetch_per_build() {
    let scratch = Scratch::new("partial-no-definition");
    let (vault, work_id) = fully_cached_fixture("d175-partial-no-definition", 0x21);
    let (_evicted, remaining) = evict_one_unit(&vault);
    assert!(remaining > 0, "the cache is partial, not empty");
    let bundle = scratch.join("partial.sealproof");

    let run = spawn_reveal(vault.layout.root(), &[], &work_id, &bundle, None);
    match BackendArm::THIS_BUILD {
        BackendArm::NotCompiled => assert_vault_local_refusal("no definition", &run, &bundle),
        BackendArm::Compiled => assert_lazy_refusal(
            "no definition",
            &run,
            &bundle,
            2,
            "usage",
            &["ANTSEAL_DEVNET_ENV", "devnet"],
            // D174 §2 R7: the no-definition refusal offers no other network
            // as an export-free alternative.
            &["arbitrum-sepolia", ABSENCE_SENTENCE],
        ),
    }
}

/// **D175 §2 R3, the flag, lazily**: one evicted unit, `--network
/// arbitrum-one`, and a dead export **present** — so the definition would
/// resolve, and the usage error can only be the flag's. The build with a
/// backend names both networks; the build with none never reads the flag.
#[test]
fn a_disagreeing_network_flag_is_a_usage_error_only_at_the_first_fetch() {
    let scratch = Scratch::new("partial-flag");
    let (vault, work_id) = fully_cached_fixture("d175-partial-flag", 0x22);
    let (_evicted, remaining) = evict_one_unit(&vault);
    assert!(remaining > 0, "the cache is partial, not empty");
    let dead = dead_devnet_export(&scratch.0);
    let bundle = scratch.join("flagged.sealproof");

    let run = spawn_reveal(
        vault.layout.root(),
        &["--network", "arbitrum-one"],
        &work_id,
        &bundle,
        Some(&dead),
    );
    match BackendArm::THIS_BUILD {
        BackendArm::NotCompiled => assert_vault_local_refusal("disagreeing flag", &run, &bundle),
        BackendArm::Compiled => assert_lazy_refusal(
            "disagreeing flag",
            &run,
            &bundle,
            2,
            "usage",
            &["sealed on `devnet`", "--network arbitrum-one"],
            &["ANTSEAL_DEVNET_ENV"],
        ),
    }
}

/// **D175 §2 R3, the record**: one evicted unit and a recorded network this
/// build cannot resolve. The build with a backend reports it in reveal's own
/// class — **reveal-inputs-unusable (36)**, not `restore`'s and not 23 —
/// naming the string; the build with none refuses at the seam, never having
/// parsed it.
#[test]
fn an_unparseable_recorded_network_is_reveal_inputs_unusable_at_the_first_fetch() {
    let scratch = Scratch::new("partial-unparseable");
    let (vault, work_id) = fully_cached_fixture("d175-partial-unparseable", 0x23);
    let (_evicted, remaining) = evict_one_unit(&vault);
    assert!(remaining > 0, "the cache is partial, not empty");
    forge_recorded_network(&vault, "mainnet");
    let bundle = scratch.join("unparseable.sealproof");

    let run = spawn_reveal(vault.layout.root(), &[], &work_id, &bundle, None);
    match BackendArm::THIS_BUILD {
        BackendArm::NotCompiled => assert_vault_local_refusal("unparseable record", &run, &bundle),
        BackendArm::Compiled => assert_lazy_refusal(
            "unparseable record",
            &run,
            &bundle,
            36,
            "reveal-inputs-unusable",
            &["`mainnet`", "cannot resolve"],
            &["ANTSEAL_DEVNET_ENV", "network failure"],
        ),
    }
}

/// **D175 §2 R4**: one evicted unit over a definition whose only peer is a
/// dead loopback port. The build with a backend connects — once, from the
/// first fetch — and the fetch fails: the whole reveal ends at that unit in
/// the **network class (23)**, in the engine's `Unfetchable` sentence,
/// never the no-backend sentence and never absence; nothing is written.
/// The build with none refuses at the seam without dialling.
///
/// Costs the feature build a dead-bootstrap connect (about six seconds on
/// the pinned stack, which connects `Ok` to nothing and fails per fetch).
#[test]
fn a_partial_cache_over_an_unreachable_network_fails_in_the_network_class_per_build() {
    let scratch = Scratch::new("partial-unreachable");
    let (vault, work_id) = fully_cached_fixture("d175-partial-unreachable", 0x24);
    let (evicted, remaining) = evict_one_unit(&vault);
    assert!(remaining > 0, "the cache is partial, not empty");
    let dead = dead_devnet_export(&scratch.0);
    let bundle = scratch.join("unreachable.sealproof");

    let run = spawn_reveal(vault.layout.root(), &[], &work_id, &bundle, Some(&dead));
    match BackendArm::THIS_BUILD {
        BackendArm::NotCompiled => assert_vault_local_refusal("unreachable", &run, &bundle),
        BackendArm::Compiled => {
            assert_eq!(
                run.code,
                Some(23),
                "an unreachable network ends the reveal in the network class (D175 §2 R4). \
                 stderr:\n{}",
                run.stderr
            );
            let document = run.document();
            assert_eq!(
                document["error"]["class"],
                serde_json::json!("network-failure"),
                "{document}"
            );
            let message = run.message();
            assert!(
                message.contains(UNFETCHABLE_SENTENCE)
                    && message.contains(&format!("unit {evicted} ")),
                "the engine's own sentence, naming the unit it could not obtain: {message}"
            );
            for forbidden in [NO_BACKEND_FRAGMENT, ABSENCE_SENTENCE, "compiled in"] {
                assert!(
                    !message.contains(forbidden),
                    "an unreachable network is reported in the network class — never as a \
                     missing backend and never as absence (`{forbidden}`): {message}"
                );
            }
            assert_eq!(
                run.connect_traces(),
                1,
                "the network was asked exactly once, from the first fetch. stderr:\n{}",
                run.stderr
            );
            assert!(
                run.stderr.contains(HOOK_ARMED),
                "after the passphrase. stderr:\n{}",
                run.stderr
            );
            assert!(!bundle.exists(), "a failed reveal writes no bundle");
        }
    }
}

// ─────────────────────────────────────────────────────────────────────
// D175 §2 R8 (b): the library counter, over the production lazy backend
// ─────────────────────────────────────────────────────────────────────

#[cfg(feature = "ant-backend")]
mod feature_build {
    use antseal_cli::backend::{drive_reveal, lazy_read_only, runtime};
    use antseal_cli::error::{CliError, ErrorClass};
    use antseal_cli::pipeline::{RevealEngine, RevealRequest, RevealSummary, UnitSelection};
    use antseal_cli::vault::store::WorkStore;
    use antseal_net::{DevnetEnv, NetworkConfig};

    use super::{
        ABSENCE_SENTENCE, NO_BACKEND_FRAGMENT, Scratch, UNFETCHABLE_SENTENCE,
        dead_devnet_export_text, evict_one_unit, fully_cached_fixture, only_work,
    };

    /// A definition that could only dial a dead loopback port — what the
    /// production constructor is handed, so a connection attempt, if one
    /// were made, would show in `attempts()` and cost seconds, never money.
    fn dead_definition(scratch: &Scratch) -> NetworkConfig {
        let env = DevnetEnv::from_env_file_optional_wallet(&dead_devnet_export_text(&scratch.0))
            .expect("the dead export parses");
        NetworkConfig::devnet(&env)
    }

    fn all_units() -> RevealRequest {
        RevealRequest {
            selection: UnitSelection::All,
            include_receipt: false,
        }
    }

    /// **D175 §2 R8 (b)**: the production lazy backend from the gated
    /// constructor, with a definition that could only dial a dead network,
    /// reports **zero connection attempts and zero calls** after
    /// `RevealEngine::prepare` on a fully cached fixture — beside the
    /// engine's own split, so neither number stands alone.
    #[test]
    fn the_production_lazy_backend_makes_zero_attempts_and_zero_calls_on_a_fully_cached_work() {
        let scratch = Scratch::new("library-cached");
        let (vault, _work_id) = fully_cached_fixture("d175-library-cached", 0x31);
        let unlocked = vault.unlock();
        let store = WorkStore::new(&unlocked);
        let seal_id = only_work(&store);
        let definition = dead_definition(&scratch);

        let rt = runtime().expect("runtime builds");
        let (attempts, calls, summary): (usize, usize, RevealSummary) = rt.block_on(async {
            let backend = lazy_read_only("reveal", move || Ok(definition));
            let prepared = RevealEngine::new(&backend, &store)
                .prepare(&seal_id, &all_units())
                .await
                .expect("a fully cached work prepares with no network at all");
            (
                backend.attempts(),
                backend.calls(),
                prepared.summary().clone(),
            )
        });

        assert_eq!(
            attempts, 0,
            "a fully cached reveal must not attempt a connection: the deferred reader is \
             awaited only from a fetch the cache cannot answer (D175 §2 R1/R8 (b))"
        );
        assert_eq!(
            calls, 0,
            "a fully cached reveal must not reach the storage seam even once — measured where it \
             happens rather than inferred from the reveal having succeeded"
        );
        assert_eq!(
            summary.units_from_network, 0,
            "no unit came from the network"
        );
        assert!(
            summary.units_from_cache > 0,
            "every unit came from the D43 cache; got {}",
            summary.units_from_cache
        );
    }

    /// The same zeros read from **inside the production driver's closure**
    /// — the shape `commands::reveal` runs — so an eager await or an eager
    /// definition in the driver itself cannot hide behind the constructor's
    /// laziness. The record read is handed over as a closure the driver must
    /// never call for a cached work; here it would panic if it were.
    #[test]
    fn the_production_driver_is_lazy_too() {
        let (vault, _work_id) = fully_cached_fixture("d175-library-driver", 0x32);
        let unlocked = vault.unlock();
        let store = WorkStore::new(&unlocked);
        let seal_id = only_work(&store);

        let (attempts, calls, summary) = drive_reveal(
            None,
            || panic!("the driver read the work's network for a reveal that fetched nothing"),
            async |backend| {
                let prepared = RevealEngine::new(backend, &store)
                    .prepare(&seal_id, &all_units())
                    .await?;
                Ok::<_, CliError>((
                    backend.attempts(),
                    backend.calls(),
                    prepared.summary().clone(),
                ))
            },
        )
        .expect("a fully cached work prepares through the production driver");

        assert_eq!(
            attempts, 0,
            "the driver awaited the deferred reader eagerly"
        );
        assert_eq!(calls, 0, "the driver reached the seam for a cached work");
        assert_eq!(summary.units_from_network, 0);
        assert!(summary.units_from_cache > 0);
    }

    /// **D175 §2 R3 at the library route**: a definition that **refuses** is
    /// awaited exactly once, from the first fetch, fails that fetch in the
    /// network class (the engine's only vocabulary), and `settle` hands the
    /// command back the refusal in its own class — a usage error here.
    /// Nothing is dialled: the refusal precedes the connect.
    #[test]
    fn a_refusing_definition_is_awaited_once_and_settled_into_its_own_class() {
        let (vault, _work_id) = fully_cached_fixture("d175-library-refusal", 0x33);
        let (evicted, remaining) = evict_one_unit(&vault);
        assert!(remaining > 0, "the cache is partial, not empty");
        let unlocked = vault.unlock();
        let store = WorkStore::new(&unlocked);
        let seal_id = only_work(&store);

        let rt = runtime().expect("runtime builds");
        let (attempts, calls, failure, settled) = rt.block_on(async {
            let backend = lazy_read_only("reveal", || {
                Err(CliError::Usage {
                    message: "fixture: the definition refused".to_owned(),
                })
            });
            let failure = RevealEngine::new(&backend, &store)
                .prepare(&seal_id, &all_units())
                .await
                .map(|_| ())
                .expect_err("one evicted unit requires a fetch, and the definition refuses");
            // Mapped the way `run_reveal`'s `?` maps it, then settled the way
            // the driver settles it.
            let mapped = CliError::from(failure);
            let failure = mapped.to_string();
            // Read before `settle` consumes the backend (D175 §2 R5: it is
            // dropped inside the runtime).
            let (attempts, calls) = (backend.attempts(), backend.calls());
            let settled = backend.settle::<()>(Err(mapped));
            (attempts, calls, failure, settled)
        });

        assert_eq!(
            attempts, 1,
            "the deferred definition was awaited exactly once"
        );
        assert!(calls >= 1, "the fetch reached the seam");
        assert!(
            failure.contains(UNFETCHABLE_SENTENCE)
                && failure.contains(&format!("unit {evicted} "))
                && failure.contains("fixture: the definition refused"),
            "the engine reports the refusal as the fetch failure it caused: {failure}"
        );
        let settled = settled.expect_err("the refusal is reported, not swallowed");
        assert_eq!(
            settled.class(),
            ErrorClass::Usage,
            "settle restores the refusal's own class (D175 §2 R3): {settled}"
        );
        assert_eq!(settled.exit_code(), 2);
        assert_eq!(
            settled.to_string(),
            "usage error: fixture: the definition refused",
            "and its own words, not the engine's wrapping"
        );
    }

    /// **D175 §2 R1/R4 at the library route**: with a usable definition that
    /// reaches nothing, the reader is connected exactly once, from the first
    /// fetch, and the whole reveal ends at that unit in the network class —
    /// in the engine's sentence, never the no-backend sentence, never absence —
    /// and `settle` leaves a genuine network failure exactly as it is.
    ///
    /// Costs one dead-bootstrap connect, like the spawned row.
    #[test]
    fn an_unreachable_definition_is_connected_once_and_fails_the_reveal_in_the_network_class() {
        let scratch = Scratch::new("library-unreachable");
        let (vault, _work_id) = fully_cached_fixture("d175-library-unreachable", 0x34);
        let (evicted, remaining) = evict_one_unit(&vault);
        assert!(remaining > 0, "the cache is partial, not empty");
        let unlocked = vault.unlock();
        let store = WorkStore::new(&unlocked);
        let seal_id = only_work(&store);
        let definition = dead_definition(&scratch);

        let rt = runtime().expect("runtime builds");
        let (attempts, calls, settled) = rt.block_on(async {
            let backend = lazy_read_only("reveal", move || Ok(definition));
            let failure = RevealEngine::new(&backend, &store)
                .prepare(&seal_id, &all_units())
                .await
                .map(|_| ())
                .expect_err("one evicted unit requires a fetch, and nothing answers");
            let (attempts, calls) = (backend.attempts(), backend.calls());
            let settled = backend.settle::<()>(Err(CliError::from(failure)));
            (attempts, calls, settled)
        });

        assert_eq!(attempts, 1, "connected exactly once, from the first fetch");
        assert!(calls >= 1, "the fetch reached the seam");
        let error = settled.expect_err("the fetch failure is reported");
        assert_eq!(
            error.class(),
            ErrorClass::NetworkFailure,
            "a genuine network failure keeps its class through settle (D175 §2 R4): {error}"
        );
        assert_eq!(error.exit_code(), 23);
        let text = error.to_string();
        assert!(
            text.contains(UNFETCHABLE_SENTENCE) && text.contains(&format!("unit {evicted} ")),
            "the engine's own sentence, naming the unit: {text}"
        );
        for forbidden in [NO_BACKEND_FRAGMENT, ABSENCE_SENTENCE, "compiled in"] {
            assert!(
                !text.contains(forbidden),
                "never `{forbidden}` for an unreachable network: {text}"
            );
        }
    }
}
