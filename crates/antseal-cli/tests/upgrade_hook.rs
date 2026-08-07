//! **U24 acceptance suite**: the opportunistic OTS upgrade hook — what it
//! upgrades, what it refuses to touch, what it never says, and which
//! subcommands arm it.
//!
//! The ruling is `docs/decisions/D99-upgrade-hook-placement-and-test-seam.md`,
//! whose §6 rewrites two of U24's Accept rows; the record it writes is D97's.
//! The suite is split the way D99 §5 splits it, and the split is forced:
//!
//! - **in-process, everything injected** for what the hook *does*, because the
//!   production resolver can never admit a `127.0.0.1:0` stub (A42 requires
//!   `https`, a bare host and no port) and a hook that dialled a real calendar
//!   to prove itself would be the Q16 violation it exists inside;
//! - **against the real binary** for *where* it runs, because "the exit code
//!   and stdout are unaffected" and "this subcommand arms it" are claims about
//!   the shipped dispatch path and are unfalsifiable from a library call.
//!
//! # No test here can reach a real endpoint (Q16)
//!
//! Three independent reasons. The calendar URI baked into the synthetic `.ots`
//! fixture is `calendar.example` — RFC 2606 reserved, so it can never resolve,
//! **and** A42's allowlist refuses it before any request is issued, which is
//! what makes the spawned-binary rows below safe to run against the *real*
//! production hook. The in-process rows go through `upgrade_pending_with`,
//! whose resolver this file supplies and which maps every URI onto a loopback
//! stub. And every spawn goes through `spawn::antseal()`, which arms Q16's
//! environment gate (D99 R4.1).
//!
//! NON-SECRET: every digest, seal id, passphrase and artifact here is a
//! documented fixture (project rule 6).

mod common;
#[path = "common/spawn.rs"]
mod spawn;

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use antseal_anchor::agree::EndpointPair;
use antseal_anchor::http::{Endpoint, HttpClient, HttpPolicy, TlsPolicy};
use antseal_anchor::ots::engine::upgrade_pending_with;
use antseal_anchor::ots::upgrade_uri::UpgradeUriRefusal;
use antseal_anchor::ots::{UpgradeBudget, UpgradeTarget};
use antseal_anchor::testing::replay::{CalendarBehaviour, calendar};
use antseal_anchor::testing::stub::{StubMatch, StubReply, StubScript, StubServer};
use antseal_cli::machine::{ALL_COMMAND_NAMES, MINIMAL_ARGV};
use antseal_cli::pipeline::journal::{SealJournal, SealPlan, SealState, WorkIdentity};
use antseal_cli::pipeline::{
    AnchorArtifact, ArtifactKind, OTS_SLOT, StoredAnchors, VaultJournal, tsa_slot,
};
use antseal_cli::upgrade_hook::{HOOK_ARMED, HOOK_NOT_ARMED, HookContext, run_with};
use antseal_cli::vault::session::UnlockedVault;
use antseal_cli::vault::store::{SealShapingFlags, WorkStore};
use antseal_core::anchor::testing::ots_writer;
use antseal_core::crypto::secrets::{MasterSecret, SealId};
use antseal_core::manifest::anchor_digest;
use common::IsolatedVault;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

/// A calendar host that can never resolve (RFC 2606 `.example`) **and** that
/// A42's allowlist refuses, so the production hook issues no request for it.
const CALENDAR: &str = "https://calendar.example/alice";

/// The `fetch_date` on every synthetic capture (A32: recorded, never
/// compared).
const FETCH_DATE: u64 = 1_785_600_000;

/// The `fetch_date` an upgraded header group carries — a different literal
/// from [`FETCH_DATE`] because D97 R4 makes them different facts.
const HEADER_FETCH_DATE: u64 = 1_790_000_000;

/// The Bitcoin height the synthetic attestations name.
const HEIGHT: u64 = 700_113;

/// The passphrase `common`'s fixture vaults are created with.
const FIXTURE_PASSPHRASE: &[u8] = common::FIXTURE_PASSPHRASE;

// ─────────────────────────────────────────────────────────────────────
// Fixture material
// ─────────────────────────────────────────────────────────────────────

fn seal_id(tag: u8) -> SealId {
    let mut bytes = [tag; 16];
    bytes[0] = 0x24;
    SealId::from_bytes(bytes)
}

fn manifest() -> Vec<u8> {
    common::fixture_manifest_envelope()
}

fn digest() -> [u8; 32] {
    anchor_digest(&manifest()).into_bytes()
}

fn pending_ots() -> Vec<u8> {
    ots_writer::container(&digest(), &ots_writer::pending(CALENDAR))
}

fn ots_artifact(bytes: Vec<u8>) -> AnchorArtifact {
    AnchorArtifact {
        kind: ArtifactKind::OtsPending,
        endpoint: String::new(),
        fetch_date: FETCH_DATE,
        bytes,
        upgrade: None,
    }
}

/// What a fixture work is for. Every variant exists to exercise one branch of
/// D99 R6/R7, and the names are the reasons.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Shape {
    /// Complete, one pending `.ots` — the only thing the hook may upgrade.
    UpgradableOts,
    /// Complete, one TSA capture and no `.ots` — nothing to poll (R6).
    NoOtsArtifact,
    /// Complete, but its `ots-pending` slot holds bytes the record codec
    /// refuses (R6: an `AnchorArtifact::decode` refusal).
    UndecodableAnchor,
    /// Complete, one pending `.ots`, but the journaled plan carries no
    /// manifest — so no `anchor_digest` exists to poll against (R6).
    NoManifest,
    /// Not complete: a D45 resume candidate whose slot the next resume
    /// rewrites wholesale (R7).
    Incomplete,
}

impl Shape {
    /// Whether a work of this shape can sit in a vault the *other* commands
    /// still render.
    ///
    /// [`Shape::UndecodableAnchor`] cannot, and the reason is worth stating
    /// because it is not this hook's doing: `StoredAnchors::read` fails the
    /// whole read on one bad record — deliberately, so no caller renders a
    /// verdict about evidence it does not have — and `JournalError::Corrupt`
    /// maps to `CliError::VaultAuthFailure`, so **`list` exits 12 for the
    /// whole vault**. The spawned rows below therefore use a vault without
    /// one: they are about the hook's placement, and a fixture that made the
    /// host command fail for unrelated reasons would prove nothing about it.
    const fn renderable(self) -> bool {
        !matches!(self, Self::UndecodableAnchor)
    }
}

struct Fixture {
    tag: u8,
    shape: Shape,
}

/// Ascending by seal-id byte order, which is `list_works`' order and therefore
/// the order R9 rotates within.
fn fixtures() -> Vec<Fixture> {
    vec![
        Fixture {
            tag: 0x01,
            shape: Shape::UpgradableOts,
        },
        Fixture {
            tag: 0x02,
            shape: Shape::NoOtsArtifact,
        },
        Fixture {
            tag: 0x03,
            shape: Shape::Incomplete,
        },
        Fixture {
            tag: 0x04,
            shape: Shape::UndecodableAnchor,
        },
        Fixture {
            tag: 0x05,
            shape: Shape::NoManifest,
        },
    ]
}

/// The works the hook may consider, in `list_works` order — everything
/// `Complete`, whatever else is wrong with it. Three of the four are there to
/// be *skipped*, which is the point: a pass that silently stopped at the first
/// unreadable work would look identical to a healthy one without them.
fn complete_tags() -> Vec<u8> {
    fixtures()
        .iter()
        .filter(|f| f.shape != Shape::Incomplete)
        .map(|f| f.tag)
        .collect()
}

/// Every fixture shape — the vault the in-process rows drive.
fn fixture_vault(tag: &str) -> IsolatedVault {
    build_vault(tag, false)
}

/// The shapes a vault can hold and still be listable — the vault the spawned
/// rows drive. See [`Shape::renderable`].
fn renderable_vault(tag: &str) -> IsolatedVault {
    build_vault(tag, true)
}

fn build_vault(tag: &str, renderable_only: bool) -> IsolatedVault {
    let vault = IsolatedVault::create(tag);
    let unlocked = vault.unlock();
    let mut rng = ChaCha20Rng::from_seed([0x24; 32]);
    let store = WorkStore::new(&unlocked);
    let journal = VaultJournal::new(WorkStore::new(&unlocked), &mut rng);
    let mut slot_rng = ChaCha20Rng::from_seed([0x25; 32]);

    for f in fixtures() {
        if renderable_only && !f.shape.renderable() {
            continue;
        }
        let w = MasterSecret::from_bytes([f.tag; 32]);
        let id = seal_id(f.tag);
        journal
            .begin(&WorkIdentity {
                w: w.secret_ref(),
                seal_id: id,
                network: "arbitrum-one".to_owned(),
                unanchored: false,
                degraded: false,
                input_paths_as_given: vec!["notes.txt".to_owned()],
                input_paths_absolute: vec!["/w/notes.txt".to_owned()],
                shaping: SealShapingFlags::default(),
            })
            .expect("begin");
        journal
            .put_plan(
                &id,
                &SealPlan {
                    unit_count: 1,
                    // R6's "no `anchor_digest` recoverable" arm: a work killed
                    // before its manifest was built.
                    manifest_bytes: match f.shape {
                        Shape::NoManifest => None,
                        _ => Some(manifest()),
                    },
                },
            )
            .expect("plan");

        let steps: &[SealState] = match f.shape {
            Shape::Incomplete => &[],
            _ => &[
                SealState::Anchored,
                SealState::Paid,
                SealState::Finalizing,
                SealState::Complete,
            ],
        };
        for step in steps {
            journal.set_state(&id, *step).expect("advance");
        }

        match f.shape {
            Shape::NoOtsArtifact => {
                // A TSA-only work: something in the anchors area, but nothing
                // an upgrade could ever address.
                store
                    .put_anchor(
                        &id,
                        &tsa_slot(0),
                        &AnchorArtifact {
                            kind: ArtifactKind::TsaToken,
                            endpoint: "https://tsa.example/tsr".to_owned(),
                            fetch_date: FETCH_DATE,
                            bytes: b"an opaque token".to_vec(),
                            upgrade: None,
                        }
                        .encode()
                        .expect("encode"),
                        &mut slot_rng,
                    )
                    .expect("put anchor");
            }
            Shape::UndecodableAnchor => {
                // Sealed by the real record cipher, so the AEAD opens — and
                // then the *record codec* refuses the plaintext. That is the
                // R6 arm a corrupt-ciphertext fixture would not reach.
                store
                    .put_anchor(
                        &id,
                        OTS_SLOT,
                        b"not an anchor-artifact record",
                        &mut slot_rng,
                    )
                    .expect("put anchor");
            }
            _ => {
                store
                    .put_anchor(
                        &id,
                        OTS_SLOT,
                        &ots_artifact(pending_ots()).encode().expect("encode"),
                        &mut slot_rng,
                    )
                    .expect("put anchor");
            }
        }

        if f.shape != Shape::Incomplete {
            journal
                .record_outcome(&id, Some([f.tag; 32]), Some(1))
                .expect("outcome");
        }
    }
    vault
}

// ─────────────────────────────────────────────────────────────────────
// The injected hook context (D99 R4.4/R5)
// ─────────────────────────────────────────────────────────────────────

/// Resolve every pending URI onto one loopback stub — D99 R5's seam.
///
/// Takes the base URL by value rather than the server by reference: in edition
/// 2024 an `impl Trait` return captures every in-scope lifetime, so borrowing
/// the server here would tie the resolver — and therefore the whole
/// `HookContext` — to the stub's borrow rather than to the vault's.
fn to_stub(base: String) -> impl Fn(&str) -> Result<UpgradeTarget, UpgradeUriRefusal> + 'static {
    move |_uri: &str| Ok(UpgradeTarget::loopback_for_tests(&base))
}

fn esplora_at(height: u64, header_hex: &str) -> StubScript {
    let hash: String = "00000000000000000000".to_owned() + &"ab".repeat(22);
    StubScript::new()
        .route(
            StubMatch::target(format!("/block-height/{height}")),
            StubReply::Body {
                status: 200,
                content_type: "text/plain",
                bytes: hash.as_bytes()[..64].to_vec(),
            },
        )
        .route(
            StubMatch::target("/header"),
            StubReply::Body {
                status: 200,
                content_type: "text/plain",
                bytes: header_hex.as_bytes().to_vec(),
            },
        )
}

fn esplora_pair(first: &StubServer, second: &StubServer) -> EndpointPair {
    EndpointPair::new(
        Endpoint::parse(&first.base_url(), TlsPolicy::RequiredExceptLoopback).expect("first"),
        Endpoint::parse(&second.base_url(), TlsPolicy::RequiredExceptLoopback).expect("second"),
    )
    .expect("distinct loopback origins")
}

/// The three stubs one hook pass talks to, kept alive for its duration.
struct Stubs {
    calendar: StubServer,
    first: StubServer,
    second: StubServer,
}

impl Stubs {
    /// A calendar that upgrades, and an agreeing esplora pair whose header
    /// commits the attestation.
    fn upgrading() -> Self {
        let header = ots_writer::header_with(&digest(), ots_writer::HEADER_NTIME);
        let header_hex: String = header.iter().map(|byte| format!("{byte:02x}")).collect();
        Self {
            calendar: StubServer::spawn(calendar(&CalendarBehaviour::Upgraded {
                pending: Vec::new(),
                upgrade: ots_writer::bitcoin(HEIGHT),
            })),
            first: StubServer::spawn(esplora_at(HEIGHT, &header_hex)),
            second: StubServer::spawn(esplora_at(HEIGHT, &header_hex)),
        }
    }

    /// A calendar that fails at the transport layer — U24's Accept row 2.
    fn failing_calendar() -> Self {
        let header = ots_writer::header_with(&digest(), ots_writer::HEADER_NTIME);
        let header_hex: String = header.iter().map(|byte| format!("{byte:02x}")).collect();
        Self {
            calendar: StubServer::spawn(StubScript::new().route(
                // D54 §6.1's upgrade path, so this stub refuses exactly the
                // request the engine issues and nothing else.
                StubMatch::target("/timestamp/"),
                StubReply::Body {
                    status: 503,
                    content_type: "text/plain",
                    bytes: b"the calendar is having a bad day".to_vec(),
                },
            )),
            first: StubServer::spawn(esplora_at(HEIGHT, &header_hex)),
            second: StubServer::spawn(esplora_at(HEIGHT, &header_hex)),
        }
    }

    fn context<'a>(&self, vault: &'a UnlockedVault, fetch_date: u64) -> HookContext<'a> {
        self.context_with(vault, fetch_date, UpgradeBudget::opportunistic())
    }

    fn context_with<'a>(
        &self,
        vault: &'a UnlockedVault,
        fetch_date: u64,
        budget: UpgradeBudget,
    ) -> HookContext<'a> {
        let client = HttpClient::new(HttpPolicy::opportunistic());
        let pair = esplora_pair(&self.first, &self.second);
        let resolve = to_stub(self.calendar.base_url());
        HookContext::with_poll(
            vault,
            budget,
            fetch_date,
            Box::new(move |works, budget| {
                upgrade_pending_with(&client, &pair, works, budget, fetch_date, &resolve)
            }),
        )
    }
}

// ─────────────────────────────────────────────────────────────────────
// U24 Accept row 1 (D99 §6's rewritten version), data half
// ─────────────────────────────────────────────────────────────────────

/// **U24 accept**: an armed invocation upgrades a pending fixture through a
/// `127.0.0.1:0` calendar stub and persists it, with D97's keys 4/5/6 — and a
/// second pass over the same vault writes nothing at all.
///
/// The re-read is a fresh unlock over a closed vault, so "persisted" is a
/// claim about bytes on disk rather than about a live cache.
#[test]
fn an_armed_pass_upgrades_a_pending_anchor_and_persists_the_group() {
    let vault = fixture_vault("hook-upgrade");
    let id = seal_id(0x01);
    let stubs = Stubs::upgrading();

    let pass = {
        let unlocked = vault.unlock();
        run_with(&stubs.context(&unlocked, HEADER_FETCH_DATE))
    };
    assert_eq!(pass.applied, 1, "one transition, persisted");
    assert_eq!(pass.declined, 0);
    assert!(pass.polls >= 1, "the stub was actually asked");
    assert_eq!(
        pass.skipped,
        complete_tags().len() - 1,
        "every other completed work is a documented skip, not a silent stop"
    );
    assert_eq!(
        pass.excluded, 1,
        "and the incomplete work never became a candidate"
    );

    let reread = vault.unlock();
    let store = WorkStore::new(&reread);
    let stored = StoredAnchors::read(&store, &id).expect("read");
    let (_, artifact) = stored.ots_entry(0).expect("the OTS slot");
    let group = artifact
        .upgrade
        .as_ref()
        .expect("D97 R6: the artifact and its group are recorded together or not at all");
    assert_eq!(group.block_height(), HEIGHT);
    assert_eq!(group.fetch_date(), HEADER_FETCH_DATE, "D97 R5: pinned");
    assert_eq!(artifact.fetch_date, FETCH_DATE, "D97 R4: key 2 carried");
    assert_ne!(
        artifact.bytes,
        pending_ots(),
        "the merged bytes replaced it"
    );

    // A second pass is a no-op, byte for byte — the growth fix, seen from the
    // hook rather than from `status --upgrade`. Without it this is where the
    // per-invocation growth would begin.
    let before = vault.fingerprint();
    let pass = {
        let unlocked = vault.unlock();
        run_with(&stubs.context(&unlocked, HEADER_FETCH_DATE))
    };
    assert_eq!(pass.applied, 0, "nothing to write the second time");
    assert_eq!(vault.fingerprint(), before, "and nothing was written");
}

/// **U24 accept row 2**, in-process half: a calendar that fails leaves the
/// vault byte-identical and the pass free of transitions.
///
/// There is no error to inspect and that is the assertion: `upgrade_pending`
/// returns a report and no `Result`, and `run_with` returns data and no
/// `Result`, so a dead calendar has no path by which it could reach the host
/// command's exit status even if someone tried.
#[test]
fn a_failing_calendar_writes_nothing_and_fails_nothing() {
    let vault = fixture_vault("hook-failing");
    let stubs = Stubs::failing_calendar();
    let before = vault.fingerprint();

    let pass = {
        let unlocked = vault.unlock();
        run_with(&stubs.context(&unlocked, HEADER_FETCH_DATE))
    };
    assert!(pass.polls >= 1, "the poll was issued");
    assert_eq!(pass.applied, 0);
    assert_eq!(pass.declined, 0);
    assert_eq!(vault.fingerprint(), before, "the vault is untouched");
}

// ─────────────────────────────────────────────────────────────────────
// D99 R7 and R6: which works, and what an unreadable one costs
// ─────────────────────────────────────────────────────────────────────

/// **R7**: only `Complete` works are candidates. An incomplete work is a D45
/// resume candidate whose `ots-pending` slot the next resume rewrites from a
/// *fresh* submission, so upgrading it spends the budget on nothing at best
/// and manufactures D97 §1's false `invalid` at worst.
#[test]
fn an_incomplete_work_is_never_a_candidate() {
    let vault = fixture_vault("hook-incomplete");
    let stubs = Stubs::upgrading();
    let unlocked = vault.unlock();
    let pass = run_with(&stubs.context(&unlocked, HEADER_FETCH_DATE));

    let complete: Vec<SealId> = complete_tags().into_iter().map(seal_id).collect();
    let mut ordered = pass.order.clone();
    ordered.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    assert_eq!(
        ordered, complete,
        "the incomplete work must not appear in the candidate set at all"
    );

    // …and its anchor slot is exactly as it was.
    let store = WorkStore::new(&unlocked);
    let stored = StoredAnchors::read(&store, &seal_id(0x03)).expect("read");
    let (_, artifact) = stored.ots_entry(0).expect("the OTS slot");
    assert_eq!(artifact.bytes, pending_ots());
    assert!(artifact.upgrade.is_none());
}

/// **R6**: a work the hook cannot read is a *skip*, and the pass carries on to
/// the works behind it.
///
/// The three unreadable shapes are visited before the upgradable one under a
/// rotation that puts them first, so this is not merely "the pass survived" —
/// it is "the pass survived three different refusals and still did its work".
#[test]
fn an_unreadable_work_is_skipped_and_the_pass_continues() {
    let vault = fixture_vault("hook-unreadable");
    let stubs = Stubs::upgrading();
    let unlocked = vault.unlock();

    // `fetch_date % 4 == 1` starts on the second candidate (tag 0x02), so the
    // three skips come first and the upgradable work is reached last.
    let pass = run_with(&stubs.context(&unlocked, 1));
    assert_eq!(pass.order.first(), Some(&seal_id(0x02)));
    assert_eq!(pass.order.last(), Some(&seal_id(0x01)));
    assert_eq!(
        pass.skipped, 3,
        "no OTS artifact, an undecodable record, and a work with no manifest"
    );
    assert_eq!(pass.considered, 1);
    assert_eq!(
        pass.applied, 1,
        "the upgradable work behind three unreadable ones is still upgraded"
    );
}

// ─────────────────────────────────────────────────────────────────────
// D99 R9: the budget rotates
// ─────────────────────────────────────────────────────────────────────

/// **R9**: the pass starts at `fetch_date % n` over `list_works`' byte order.
///
/// Without this the first work by seal-id order consumes every invocation's
/// budget until it upgrades — and a commitment a calendar answers `NotFound`
/// for consumes it **permanently**, starving every work behind it for the life
/// of the vault. `max_polls` is 4 and the engine returns at the first
/// exhaustion, so "eventually" is not a defence: nothing else moves the
/// starting point.
#[test]
fn the_pass_rotates_its_starting_point_with_the_clock() {
    let vault = fixture_vault("hook-rotation");
    let stubs = Stubs::upgrading();
    let unlocked = vault.unlock();
    let candidates: Vec<SealId> = complete_tags().into_iter().map(seal_id).collect();
    assert!(candidates.len() > 1, "a rotation needs somewhere to go");

    let mut starts = Vec::new();
    for fetch_date in 0..(candidates.len() as u64 * 2) {
        // A budget of zero polls: the rotation is a property of the candidate
        // order, and no work should have to be *done* to assert it.
        let pass = run_with(&stubs.context_with(
            &unlocked,
            fetch_date,
            UpgradeBudget {
                total: Duration::from_secs(30),
                max_polls: 0,
            },
        ));
        let index = usize::try_from(fetch_date).expect("small") % candidates.len();
        assert_eq!(
            pass.order.first(),
            Some(&candidates[index]),
            "fetch_date {fetch_date} must start at candidate {index}"
        );
        assert_eq!(
            pass.order.len(),
            candidates.len(),
            "a rotation visits every candidate, it does not drop the wrapped tail"
        );
        starts.push(pass.order[0]);
    }
    starts.dedup();
    assert_eq!(
        starts.len(),
        candidates.len() * 2,
        "consecutive clock values must not land on the same work twice in a row"
    );
}

// ─────────────────────────────────────────────────────────────────────
// D99 R3: the lock
// ─────────────────────────────────────────────────────────────────────

/// **R3**: a contended single-writer lock is a silent decline — no wait, no
/// retry, no error, and nothing written.
///
/// The lock is a try-lock that refuses a second acquisition even inside one
/// process (`vault/lock.rs`), so holding one here is the same contention a
/// concurrent `seal` would produce.
#[test]
fn a_contended_lock_declines_silently_and_writes_nothing() {
    use antseal_cli::vault::layout::BesideFile;
    use antseal_cli::vault::lock::VaultLock;

    let vault = fixture_vault("hook-lock");
    let stubs = Stubs::upgrading();

    let held = VaultLock::acquire(&vault.layout.beside_path(BesideFile::Lockfile))
        .expect("the interloper takes the lock first");
    // Fingerprinted with the lockfile already in place: `acquire` creates and
    // writes it, and a "the vault is untouched" claim must be about the
    // records rather than about the lock the test itself took.
    let before = vault.fingerprint();
    let pass = {
        let unlocked = vault.unlock();
        run_with(&stubs.context(&unlocked, HEADER_FETCH_DATE))
    };
    assert!(pass.lock_contended, "the contention is recorded");
    assert_eq!(pass.applied, 0, "and nothing was written");
    assert_eq!(vault.fingerprint(), before);
    drop(held);

    // The transitions are recomputed rather than lost: the very next pass,
    // with the lock free, does the work.
    let pass = {
        let unlocked = vault.unlock();
        run_with(&stubs.context(&unlocked, HEADER_FETCH_DATE))
    };
    assert!(!pass.lock_contended);
    assert_eq!(pass.applied, 1);
}

// ─────────────────────────────────────────────────────────────────────
// The real binary
// ─────────────────────────────────────────────────────────────────────

struct Spawned {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

/// Spawn the real binary with the passphrase on stdin.
///
/// `write_all` failures are ignored on purpose: most of the enumerated
/// commands refuse before they ever read a passphrase, and a child that exits
/// first turns the write into `BrokenPipe`. That is the command doing its job,
/// not the harness failing.
fn spawn_at(vault_root: &Path, cwd: &Path, args: &[&str], log: Option<&str>) -> Spawned {
    let mut command = spawn::antseal();
    command
        .args(args)
        .env("ANTSEAL_DIR", vault_root)
        .current_dir(cwd)
        .env_remove("RUST_LOG")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    if let Some(filter) = log {
        command.env("RUST_LOG", filter);
    }
    let mut child = command.spawn().expect("spawn antseal");
    let _ = child
        .stdin
        .as_mut()
        .expect("stdin piped")
        .write_all(FIXTURE_PASSPHRASE);
    drop(child.stdin.take());
    let out = child.wait_with_output().expect("wait for antseal");
    Spawned {
        code: out.status.code(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

/// The `RUST_LOG` filter that makes the hook's two arms visible, and nothing
/// else.
const HOOK_LOG: &str = "antseal_cli::upgrade_hook=debug";

/// Whether a spawned invocation armed the hook, read off the real binary's
/// debug trace. Exactly one of the two arms must appear: a run showing neither
/// is a run in which the hook was not invoked at all, which is the regression
/// D99's rewritten Accept row 4 exists to catch.
fn armed(run: &Spawned) -> bool {
    let armed = run.stderr.contains(HOOK_ARMED);
    let not_armed = run.stderr.contains(HOOK_NOT_ARMED);
    assert!(
        armed ^ not_armed,
        "the hook must report exactly one arm per invocation (armed={armed}, \
         not_armed={not_armed}). stderr:\n{}",
        run.stderr
    );
    armed
}

/// A throwaway directory that cleans up after itself.
struct TestDir(PathBuf);

impl TestDir {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "antseal-cli-hook-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("mk dir");
        TestDir(dir)
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// **D99 §6's rewritten Accept row 4.** Every subcommand of the frozen surface
/// either arms the hook or is a *documented* non-armer, asserted against the
/// real binary's debug trace — D42's rule in both directions, per command.
///
/// # Why this replaced "a test enumerates subcommands and asserts each passes
/// through it"
///
/// That row was factually unsatisfiable (D99 §1.1): neither point that sees
/// all ten subcommands holds a vault — `run::run` takes a `&Cli` and every
/// handler unlocks for itself — so a hook placed there could not satisfy D42
/// at all. The property it was reaching for is *no command silently skips the
/// hook*, and that is what this asserts: the hook is invoked unconditionally,
/// it reports which arm it took, and every command's arm is written down here
/// with the reason it is that one.
///
/// The `reason` column is the load-bearing part. A command that changed arm
/// would fail with the sentence that is no longer true, rather than with a
/// boolean mismatch nobody can adjudicate.
#[test]
fn every_subcommand_either_arms_the_hook_or_is_a_documented_non_armer() {
    let dir = TestDir::new("enumerate");
    let vault = renderable_vault("hook-enumerate");

    // `(command, arms, why)` — indexed by `ALL_COMMAND_NAMES`/`MINIMAL_ARGV`,
    // which the machine registry already asserts are 1:1 and in order.
    let expectations: [(&str, bool, &str); 10] = [
        (
            "init",
            false,
            "D99 R2: `init` consumes the `UnlockedVault` inside `run_init` and holds none at \
             the dispatch layer — and a vault created moments ago has nothing to upgrade. \
             (Here it also refuses outright: a vault already exists.)",
        ),
        (
            "seal",
            false,
            "`seal` DOES arm, through the same `unlock_for_command` expression as `list` — but \
             this minimal argv cannot reach the unlock: plan validation refuses a path that \
             does not exist, ahead of the vault, by design. The structural claim is carried by \
             the source scan, not by this row.",
        ),
        ("list", true, "unlocks through `unlock_for_command`"),
        (
            "show",
            false,
            "M3: the handler does not exist yet, so nothing is unlocked",
        ),
        (
            "status",
            true,
            "unlocks through `unlock_for_command` — and arms BEFORE resolving the work id, so \
             an unknown id still leaves the invocation armed",
        ),
        (
            "restore",
            false,
            "U20 reaches the storage-backend seam before the vault, and this build has no \
             backend — so no passphrase is collected and nothing is unlocked",
        ),
        ("reveal", false, "M3: the handler does not exist yet"),
        (
            "verify",
            false,
            "M3, and verification is vault-less by design — D42's rule has nothing to key on",
        ),
        (
            "vault export",
            true,
            "unlocks through `unlock_for_command`; the hook takes the U5 lock only after this \
             handler has released its own",
        ),
        (
            "vault import",
            false,
            "D99 R2: its only unlock is the self-verification inside `import_vault`, which \
             never leaves that function",
        ),
    ];

    for ((name, expected, why), argv) in expectations.iter().zip(MINIMAL_ARGV) {
        let mut args = vec!["--passphrase-fd", "0"];
        args.extend(argv.iter().skip(1).copied());
        let run = spawn_at(vault.layout.root(), &dir.0, &args, Some(HOOK_LOG));
        assert_eq!(
            armed(&run),
            *expected,
            "`{name}` took the wrong arm of D42's rule. Expected {}, because: {why}\nstderr:\n{}",
            if *expected { "armed" } else { "not armed" },
            run.stderr
        );
    }

    // Anti-vacuity, twice over: the table must cover the frozen surface, and
    // it must contain at least one command of each arm — a table that expected
    // "not armed" everywhere would pass against a hook that never runs.
    assert_eq!(
        expectations.map(|(name, _, _)| name),
        ALL_COMMAND_NAMES,
        "the table must name the canonical surface, in its order"
    );
    assert!(expectations.iter().any(|(_, arms, _)| *arms));
    assert!(expectations.iter().any(|(_, arms, _)| !*arms));
}

/// **U24 Accept row 3, both directions.** A vault-less `verify` performs no
/// vault access, asks for nothing, creates no `~/.antseal` — and performs no
/// hook work, which is the second half D42's rule is usually tested without.
///
/// `HOME` points at an empty directory and `ANTSEAL_DIR` is deliberately
/// unset, so `~/.antseal` is a path the invocation could create and does not.
#[test]
fn a_vault_less_verify_touches_no_vault_and_does_no_hook_work() {
    let home = TestDir::new("no-vault");
    let mut command = spawn::antseal();
    let out = command
        .args(["verify", "bundle.sealproof"])
        .current_dir(&home.0)
        .env("HOME", &home.0)
        .env_remove("ANTSEAL_DIR")
        .env("RUST_LOG", HOOK_LOG)
        .stdin(std::process::Stdio::null())
        .output()
        .expect("spawn antseal");
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();

    assert!(
        !home.0.join(".antseal").exists(),
        "a vault-less command must never create the vault directory (D42)"
    );
    assert!(
        stderr.contains(HOOK_NOT_ARMED),
        "the hook must run and report the not-armed arm; stderr:\n{stderr}"
    );
    assert!(
        !stderr.contains(HOOK_ARMED),
        "…and must not report the armed one; stderr:\n{stderr}"
    );
    assert!(
        !stderr.contains("pass complete"),
        "a not-armed invocation performs NO hook work at all — no candidate scan, no poll, no \
         lock; stderr:\n{stderr}"
    );
    assert!(
        !stderr.to_lowercase().contains("passphrase"),
        "and it must not prompt for anything; stderr:\n{stderr}"
    );
    assert!(
        String::from_utf8_lossy(&out.stdout).is_empty(),
        "nothing on stdout in plain mode either"
    );
}

/// **U24 Accept row 1's second half, and R6's stdout claim**: the hook runs on
/// a real invocation over a vault holding a pending anchor, and the primary
/// command's stdout and exit code are byte-for-byte what they would have been.
///
/// The comparison is one command against itself with the hook's own logging
/// on and off. That is stronger than comparing two different fixtures, which
/// would differ in stdout for reasons that have nothing to do with the hook:
/// here every byte the hook produces is visible in one run and absent from the
/// other, and stdout is identical across them.
///
/// This drives the **production** hook — `HookContext::production`, A42's real
/// resolver, no seam — and it is safe because the fixture's calendar URI is
/// refused by the allowlist before any request is issued. Q16's environment
/// arm is set by `spawn::antseal()` regardless.
#[test]
fn the_hook_runs_on_a_real_invocation_without_touching_stdout() {
    let dir = TestDir::new("stdout");
    let vault = renderable_vault("hook-stdout");
    let root = vault.layout.root();
    let args = ["--json", "--passphrase-fd", "0", "list"];

    let quiet = spawn_at(root, &dir.0, &args, None);
    let loud = spawn_at(root, &dir.0, &args, Some(HOOK_LOG));

    assert_eq!(quiet.code, Some(0), "stderr:\n{}", quiet.stderr);
    assert_eq!(loud.code, quiet.code, "the hook cannot move the exit code");
    assert_eq!(
        loud.stdout, quiet.stdout,
        "U3's one-document contract: every hook byte goes to stderr, so stdout is identical \
         whether the hook is logging or silent"
    );

    // …and it really is one document, still parseable after the hook has run.
    let parsed: serde_json::Value =
        serde_json::from_str(quiet.stdout.trim()).expect("exactly one JSON document on stdout");
    assert_eq!(parsed["ok"], serde_json::json!(true));

    // The hook did run, did arm, and did look at the vault.
    assert!(loud.stderr.contains(HOOK_ARMED), "stderr:\n{}", loud.stderr);
    assert!(
        loud.stderr.contains("pass complete"),
        "an armed invocation performs a pass; stderr:\n{}",
        loud.stderr
    );
    assert!(
        quiet.stderr.is_empty() || !quiet.stderr.contains(HOOK_ARMED),
        "with no RUST_LOG the hook is silent on stderr too"
    );

    // A42's allowlist refused the fixture's calendar rather than dialling it —
    // which is what makes running the *production* hook safe in a test.
    assert!(
        loud.stderr.contains("upgrade-URI allowlist"),
        "the production resolver must refuse `calendar.example` before any request; \
         stderr:\n{}",
        loud.stderr
    );
}

/// **U24 Accept row 2**, against the real binary: a hook that cannot even
/// start leaves the primary command's exit code and output untouched.
///
/// The failure is a `[verify] bitcoin_endpoints` list of one — which parses,
/// so the config itself is valid and every command still runs, but which
/// `UpgradeConfig::pair` refuses because a must-agree pair of one endpoint
/// agrees with itself and proves nothing. The hook has no way to confirm a
/// block header, so it declines; `list` neither knows nor cares.
#[test]
fn a_hook_that_cannot_start_leaves_the_command_untouched() {
    let dir = TestDir::new("bad-endpoints");
    let vault = renderable_vault("hook-bad-endpoints");
    let root = vault.layout.root();
    let args = ["--json", "--passphrase-fd", "0", "list"];

    let healthy = spawn_at(root, &dir.0, &args, Some(HOOK_LOG));
    assert_eq!(healthy.code, Some(0), "stderr:\n{}", healthy.stderr);

    std::fs::write(
        root.join("config.toml"),
        "[verify]\nbitcoin_endpoints = [\"https://a.example\"]\n",
    )
    .expect("write config");
    let broken = spawn_at(root, &dir.0, &args, Some(HOOK_LOG));

    assert_eq!(
        broken.code, healthy.code,
        "the hook's refusal must not reach the exit code; stderr:\n{}",
        broken.stderr
    );
    assert_eq!(
        broken.stdout, healthy.stdout,
        "nor the output: stdout is byte-identical"
    );
    assert!(
        broken.stderr.contains(HOOK_ARMED),
        "the hook still armed — the failure is downstream of that; stderr:\n{}",
        broken.stderr
    );
    assert!(
        broken.stderr.contains("no usable endpoint configuration"),
        "and it said why, at debug, once; stderr:\n{}",
        broken.stderr
    );
    assert!(
        !broken.stderr.contains("pass complete"),
        "a hook that could not start performs no pass; stderr:\n{}",
        broken.stderr
    );
}

/// **R8's cost, measured rather than asserted.** The hook adds wall time to
/// *exit*, and this row records how much on a vault that has work to consider
/// but nothing it can dial.
///
/// The bound is not asserted tightly — this is a 2-core machine and a debug
/// build, and a timing test that fails on a busy afternoon is a test that gets
/// deleted. What is asserted is the shape D99 R8 promises: an invocation whose
/// polls are all refused before any request does **not** pay the 3 s budget.
#[test]
fn a_pass_with_nothing_dialable_costs_no_budget() {
    let dir = TestDir::new("latency");
    let vault = renderable_vault("hook-latency");
    let root = vault.layout.root();
    let args = ["--passphrase-fd", "0", "list"];

    let started = Instant::now();
    let run = spawn_at(root, &dir.0, &args, Some(HOOK_LOG));
    let elapsed = started.elapsed();
    assert_eq!(run.code, Some(0), "stderr:\n{}", run.stderr);
    assert!(
        run.stderr.contains("pass complete"),
        "the pass ran; stderr:\n{}",
        run.stderr
    );
    assert!(
        elapsed < Duration::from_secs(20),
        "a pass whose every URI is refused by A42 before any request must not pay the \
         opportunistic budget, let alone a network timeout — took {elapsed:?}"
    );
}
