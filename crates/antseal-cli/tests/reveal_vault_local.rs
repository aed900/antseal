//! U72 acceptance suite: what a build with **no storage backend** promises
//! for `reveal`.
//!
//! `commands::reveal` used to return `backend::unavailable("reveal")`
//! unconditionally, at entry, before a work was resolved and before a
//! selection was read. But R16's gathering is cache-first by D43's ruling —
//! every retained cache copy is integrity-rechecked and used, and only a
//! missing or corrupt copy is refetched — so a work whose cache is intact is
//! disclosable with **zero** network access, and the entry refusal made the
//! default build refuse on bytes already on the user's own disk, for the
//! command MVP-SPEC.md line 36 puts at the centre of the product.
//!
//! U72's ruling, argued in full on
//! [`antseal_cli::backend::VaultLocalBackend`], has four parts. This suite
//! is the measurement of each:
//!
//! - **(i)** a fully-cached reveal completes in a build with no backend at
//!   all — [`a_fully_cached_reveal_completes_with_zero_backend_calls`];
//! - **(ii)** a partial cache refuses the **whole** reveal at the first
//!   genuinely-required fetch and never discloses the cached subset —
//!   [`a_partial_cache_refuses_the_whole_reveal_at_the_first_fetch`];
//! - **(iii)** that refusal lands *after* the output path is resolved and a
//!   collision refused, and *before* the consent gate — the second and third
//!   rows both, since D68 §3 R8's order is the thing being re-asserted around
//!   the moved refusal;
//! - **(iv)** the class stays `network-failure` (23) and the message is the
//!   build-arm sentence, named here so a reader can see what a user reads.
//!
//! The backend under test is the **production** one, not a mock: what a
//! default-feature `antseal reveal` holds is exactly
//! `VaultLocalBackend::new("reveal")`. Its
//! [`refusals`](antseal_cli::backend::VaultLocalBackend::refusals) counter is
//! the seam instrument U72's Accept demands — a run that completed *because*
//! nothing was fetched and a run that completed *although* something was
//! fetched are indistinguishable from the outside, so the zero-call claim is
//! measured at the seam rather than inferred from a green result. The
//! engine's own `units_from_cache` / `units_from_network` split is read
//! beside it, as the row requires, so neither number stands alone.
//!
//! NON-SECRET: every fixture byte string is documented here.

mod common;

use std::cell::Cell;
use std::path::{Path, PathBuf};

use antseal_cli::backend::{VaultLocalBackend, block_on_vault_local};
use antseal_cli::cli::RevealArgs;
use antseal_cli::error::{CliError, ErrorClass};
use antseal_cli::pipeline::journal::UNIT_ENTRY_BASE;
use antseal_cli::pipeline::{
    NoBarriers, Pipeline, PreparedReveal, SealFile, SealRequest, SealResult, VaultJournal, hex32,
};
use antseal_cli::reveal_out::run_reveal;
use antseal_cli::vault::session::UnlockedVault;
use antseal_cli::vault::store::{SealShapingFlags, WorkStore};
use antseal_core::content::{FileFlags, SplitMode};
use antseal_core::crypto::secrets::SealId;
use antseal_core::crypto::sig_policy::SigPolicy;
use antseal_core::verify::{VerifyOptions, verify_bundle};
use antseal_net::NetworkId;
use antseal_net::test_util::MockBackend;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

use common::{IsolatedVault, RecordingGate, ScriptedConsent};

/// BOM + CRLF + NFD: raw bytes differ from canonical three ways, so this
/// file carries a raw mirror.
const CRLF_BOM_NFD: &[u8] = "\u{FEFF}caf\u{65}\u{301} notes\r\n\r\nsecond para\r\n".as_bytes();
const BINARY: &[u8] = &[0x00, 0x01, 0x02, 0xFF, 0xFE, 0x7F, 0x80, 0x00, 0x42];
const SPLIT_TEXT: &[u8] = b"alpha one\n\nbeta two\n\ngamma three\n";

// ─────────────────────────────────────────────────────────────────────
// Harness
// ─────────────────────────────────────────────────────────────────────

/// A scratch directory that removes itself.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "antseal-u72-{tag}-{}-{}",
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

/// Seal the fixture work, which is what fills the D43 cache: the ONLY
/// place a network appears in this suite is here, in the seal that put the
/// bytes there in the first place. Every reveal below runs over the
/// production backend that can fetch nothing.
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
        title: "u72 fixture".to_owned(),
        claimed_time_unix_secs: 1_800_000_000,
        app_version: "antseal-test/1".to_owned(),
        network: NetworkId::Devnet,
        no_anchor: false,
        degraded: false,
        dry_run: false,
        sig_policy: SigPolicy::hybrid(),
        shaping: SealShapingFlags::default(),
    };
    let result = antseal_net::test_util::block_on(
        pipeline.seal(&request, &mut ChaCha20Rng::from_seed([seed; 32])),
    )
    .expect("the fixture seals");
    match result {
        SealResult::Sealed(outcome) => hex32(&outcome.work_id),
        SealResult::DryRun(_) => unreachable!("not a dry run"),
    }
}

fn all_args(work_id: &str, output: &Path) -> RevealArgs {
    RevealArgs {
        work_id: work_id.to_owned(),
        all: true,
        units: Vec::new(),
        output: Some(output.to_path_buf()),
        include_receipt: false,
        yes: false,
    }
}

/// A consent seam that records whether it was asked — the only way to tell
/// "the gate granted" from "the gate was never reached", which is the whole
/// of U72's sub-question (iii).
struct Gate {
    asks: Cell<usize>,
}

impl Gate {
    fn new() -> Self {
        Self { asks: Cell::new(0) }
    }

    fn consent(&self) -> impl FnOnce(&PreparedReveal) -> Result<(), CliError> + '_ {
        move |_| {
            self.asks.set(self.asks.get() + 1);
            Ok(())
        }
    }

    fn asked(&self) -> usize {
        self.asks.get()
    }
}

/// The only work in a fixture vault.
fn only_work(store: &WorkStore<'_>) -> SealId {
    let works = store.list_works().expect("list");
    assert_eq!(works.len(), 1, "the fixture vault holds one work");
    works[0]
}

/// Drop **one** cached unit ciphertext: the partial-cache shape. Returns how
/// many cache entries remain, so a test cannot silently be measuring an
/// empty cache.
fn evict_one_unit(vault: &UnlockedVault) -> usize {
    let store = WorkStore::new(vault);
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
    units.len() - 1
}

// ─────────────────────────────────────────────────────────────────────
// (i) The ruling's headline: a cached work reveals with no backend at all
// ─────────────────────────────────────────────────────────────────────

/// **U72 accept row 1**: a work whose cache is complete is revealed end to
/// end in a build without the backend feature, with **zero** backend calls
/// — measured at the seam.
///
/// The backend here can serve nothing at all: every one of its five methods
/// returns a `StorageError`. So the reveal completing is already strong
/// evidence, and it is deliberately not the evidence relied on — U72 asks
/// for the zero-call claim to be *measured*, not inferred from a green
/// result, because "it completed" and "it never asked" are different
/// statements and only the second is the ruling. Both instruments are read:
/// the seam's own call counter, and the split the engine reports.
#[test]
fn a_fully_cached_reveal_completes_with_zero_backend_calls() {
    let scratch = Scratch::new("cached");
    let vault = IsolatedVault::create("u72-cached");
    let unlocked = vault.unlock();
    let work_id = seal_fixture(&unlocked, 0x11);
    let store = WorkStore::new(&unlocked);

    let target = scratch.join("cached.sealproof");
    let backend = VaultLocalBackend::new("reveal");
    let gate = Gate::new();
    let report = block_on_vault_local(run_reveal(
        &backend,
        &store,
        &all_args(&work_id, &target),
        gate.consent(),
    ))
    .expect("the vault-local path completes on its first poll — it performs no I/O")
    .expect("a fully-cached work reveals in a build with no backend at all");

    // The seam instrument: not one call reached the backend.
    assert_eq!(
        backend.refusals(),
        0,
        "a fully-cached reveal must not reach the storage seam even once — this is the ruling, \
         measured where it happens rather than inferred from the reveal having succeeded"
    );
    // The engine's own split, which U72 names as the evidence to use.
    assert_eq!(
        report.summary.units_from_network, 0,
        "no unit came from the network"
    );
    assert!(
        report.summary.units_from_cache > 0,
        "every unit came from the D43 cache; got {}",
        report.summary.units_from_cache
    );
    assert_eq!(gate.asked(), 1, "the gate is asked exactly once");

    // End to end means end to end: the bundle is on disk and passes the
    // offline recipient's own check.
    let bytes = std::fs::read(&report.bundle_path).expect("the bundle is on disk");
    assert_eq!(bytes.len() as u64, report.bytes);
    verify_bundle(&bytes, &VerifyOptions::new()).expect("the written bundle verifies offline");
}

// ─────────────────────────────────────────────────────────────────────
// (ii)+(iii)+(iv) A partial cache refuses the WHOLE reveal, at the seam,
// before the gate
// ─────────────────────────────────────────────────────────────────────

/// **U72 accept row 2**: one evicted unit refuses the whole reveal at the
/// first genuinely-required fetch — and the gate is never asked.
///
/// The cached subset is **not** disclosed. The selection is the user's
/// statement of what to disclose, and narrowing it to whatever happens to be
/// cached would make the contents of a permanent, irrevocable artifact a
/// function of cache state rather than of intent; under D70's promotion rule
/// dropping one unit can flip a file from a full reveal to a partial one,
/// changing what the bundle *means*.
///
/// The gate count is the D68 §3 R8 half: R16 gathers inside `prepare` and
/// `run_reveal` gates on `prepare`'s result, so a required fetch fails while
/// the bundle is still un-previewed. Nobody consents to a disclosure that
/// cannot be gathered — D68's own clause about one that cannot be written,
/// one step earlier.
#[test]
fn a_partial_cache_refuses_the_whole_reveal_at_the_first_fetch() {
    let scratch = Scratch::new("partial");
    let vault = IsolatedVault::create("u72-partial");
    let unlocked = vault.unlock();
    let work_id = seal_fixture(&unlocked, 0x22);
    let remaining = evict_one_unit(&unlocked);
    assert!(remaining > 0, "the cache is partial, not empty");
    let store = WorkStore::new(&unlocked);

    let target = scratch.join("partial.sealproof");
    let backend = VaultLocalBackend::new("reveal");
    let gate = Gate::new();
    let error = block_on_vault_local(run_reveal(
        &backend,
        &store,
        &all_args(&work_id, &target),
        gate.consent(),
    ))
    .expect("no I/O, so the driver completes")
    .expect_err("one missing unit refuses the whole reveal");

    // (iv) the class and the message, stated.
    assert_eq!(
        error.class(),
        ErrorClass::NetworkFailure,
        "the lazy refusal keeps D69 §5 group 2's class — from the caller's side this IS bytes \
         that cannot be obtained, and a second code would split one situation in two: {error}"
    );
    assert_eq!(error.exit_code(), 23, "U2's number for that class");
    let text = error.to_string();
    assert!(
        text.contains("no storage backend compiled in") || text.contains("compiled in"),
        "the refusal names the build's own reason, not a phantom outage: {text}"
    );
    assert!(
        text.contains("unit "),
        "the refusal names the unit it could not obtain: {text}"
    );

    // (iii) the seam WAS reached — this is the boundary the refusal lands
    // at — and the gate was NOT.
    assert!(
        backend.refusals() >= 1,
        "a genuinely-required fetch must reach the seam; that is where the refusal belongs"
    );
    assert_eq!(
        gate.asked(),
        0,
        "nobody consents to a disclosure that cannot be gathered (D68 §3 R8's analogue)"
    );

    // (ii) nothing partial was written.
    assert!(
        !target.exists(),
        "a refused reveal writes no bundle at all, least of all a partial one"
    );
}

/// **U72 accept row 2, the other half**: the step order around the moved
/// refusal is unchanged — an occupied output path is refused **before**
/// anything is gathered.
///
/// This is the row that would fail if the refusal had been moved by
/// resolving and gathering first: the collision check would then cost a
/// pointless fetch attempt, and on a partial cache it would report a network
/// class for a problem the user could fix with `-o`. `backend.refusals()` is
/// zero here for the same reason `Gate::asked()` is: neither the seam nor
/// the gate is reached when the answer is already known.
#[test]
fn an_occupied_output_path_is_refused_before_anything_is_gathered() {
    let scratch = Scratch::new("collision");
    let vault = IsolatedVault::create("u72-collision");
    let unlocked = vault.unlock();
    let work_id = seal_fixture(&unlocked, 0x33);
    // Evict a unit too, so a gather that DID happen would fail with the
    // network class — making the assertion below discriminate the order
    // rather than merely observing a refusal.
    evict_one_unit(&unlocked);
    let store = WorkStore::new(&unlocked);

    let target = scratch.join("occupied.sealproof");
    std::fs::write(&target, b"an earlier bundle, already sent").expect("occupy");
    let before = std::fs::read(&target).expect("read");

    let backend = VaultLocalBackend::new("reveal");
    let gate = Gate::new();
    let error = block_on_vault_local(run_reveal(
        &backend,
        &store,
        &all_args(&work_id, &target),
        gate.consent(),
    ))
    .expect("no I/O")
    .expect_err("the output path is occupied");

    assert_eq!(
        error.class(),
        ErrorClass::RefusedOverwrite,
        "D68 §3 R7's rung, not the gather's: {error}"
    );
    assert_eq!(error.exit_code(), 30);
    assert_eq!(
        backend.refusals(),
        0,
        "the output path is resolved and the collision refused BEFORE anything is gathered \
         (D68 §3 R8) — a refused path costs zero seam calls"
    );
    assert_eq!(gate.asked(), 0, "and zero consent screens");
    assert_eq!(
        std::fs::read(&target).expect("read"),
        before,
        "the existing bundle is untouched"
    );
}

// ─────────────────────────────────────────────────────────────────────
// The driver
// ─────────────────────────────────────────────────────────────────────

/// The vault-local path is driven without a runtime, and the driver is
/// honest about the one case it cannot handle.
///
/// tokio is `optional = true` and activated only by `ant-backend`, so a
/// default build has no runtime at all. `block_on_vault_local` polls once,
/// which is total for a future that performs no I/O — and reports a parked
/// future as an internal error rather than spinning on it, because a
/// no-op-waker loop on a future that genuinely parked is a hang wearing the
/// costume of a driver.
#[test]
fn the_vault_local_driver_reports_a_parked_future_instead_of_spinning() {
    // Ready on the first poll: the ordinary case.
    assert_eq!(
        block_on_vault_local(async { 7u8 }).expect("a ready future completes"),
        7
    );

    // A future that parks. `std::future::pending` never resolves, so a
    // spinning driver would hang this test rather than fail it.
    let error = block_on_vault_local(std::future::pending::<u8>())
        .expect_err("a parked future is an internal error, not a spin");
    assert_eq!(error.class(), ErrorClass::Internal);
    assert!(
        error.to_string().contains("first poll"),
        "the message says what the contract was: {error}"
    );
}
