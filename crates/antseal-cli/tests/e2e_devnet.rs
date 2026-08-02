//! **S17 — the M1 devnet E2E happy path.**
//!
//! The milestone's first gate suite: a multi-file `--split` seal driven
//! through lane ι's `Pipeline` over U36's `SealBackend` against a **live
//! 14-node devnet**, fetched back, restored, library-verified, and
//! re-checked with the `--live` primitive.
//!
//! Run by `scripts/e2e-devnet.sh` (registry row S17). Locally:
//!
//! ```text
//! scripts/devnet/local-up --nodes 14
//! ANTSEAL_DEVNET_ENV=$PWD/.devnet/env \
//!     cargo test -p antseal-cli --features ant-backend --test e2e_devnet -- --nocapture
//! scripts/devnet/local-down
//! ```
//!
//! # What makes this different from the mock suites
//!
//! `seal_pipeline.rs` and `restore_engine.rs` already prove the pipeline's
//! *shape* over `MockBackend`. Exactly three claims cannot be made there,
//! and they are why this file exists:
//!
//! 1. **S4's precomputation matches what the network actually assigns.**
//!    The mock returns the addresses it was handed, so mock agreement is a
//!    tautology. Here `finalize_batch` returns ant-core's own assignment
//!    and the four-way equality below is a real cross-check of D32's
//!    BLAKE3-256 rule against upstream.
//! 2. **The money is real.** `total ANT spent == the consented quote` is
//!    asserted against the receipt *and* against the wallet's on-chain ANT
//!    balance delta on Anvil.
//! 3. **D37's capture hook fires on the real `pay`.** `backend.rs` proves
//!    by construction that a `SealBackend` *has* a hook; only a live
//!    payment proves the installed hook reaches its sink through ant-core.
//!    S16 measured what the without-hook direction costs — a second
//!    payment — so this is the direction worth instrumenting (S27).
//!
//! # M3 exclusion (Accept row 2)
//!
//! The `verify` CLI, the bundle builder and the verifier page are M3. This
//! suite drives library APIs only, and
//! [`the_gate_suites_invoke_no_m3_cli_or_bundle_builder`] is the mechanical
//! proof rather than a promise in a comment.
//!
//! At M1 "library-verify" therefore means what the library can actually
//! conclude without a bundle: restore's per-file authenticated
//! reconstruction (every unit AEAD-opened and every digest checked, or the
//! file is `Failed` and carries no bytes), plus R5's anchor aggregation
//! yielding **UNANCHORED** for a zero-anchor work. Anchors themselves are
//! M2 (S17 Notes: the anchor step is stubbed via A's interface in M1).
//!
//! NON-SECRET: every fixture byte string here is documented and
//! run-tagged; `W` never leaves the vault.

#![cfg(feature = "ant-backend")]

mod common;

use std::collections::BTreeMap;

use antseal_cli::backend::{SealBackend, runtime};
use antseal_cli::pipeline::{
    BlobSlot, NoBarriers, Pipeline, RestoreEngine, SealFile, SealJournal, SealRequest, SealResult,
    VaultJournal,
};
use antseal_cli::vault::store::{SealShapingFlags, WorkStore};
use antseal_core::content::{FileFlags, SplitMode};
use antseal_core::crypto::sig_policy::SigPolicy;
use antseal_core::manifest::{Manifest, ManifestBodyV1};
use antseal_core::verify::aggregate_anchors;
use antseal_net::{
    Address, LiveVerdict, NetworkId, StorageRecord, live_check, records_from_manifest,
};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

use common::devnet::{
    CapturedReceipts, ant_balance, gate, run_seed, run_tag, serial, tx_count, tx_succeeded,
};
use common::{IsolatedVault, RecordingGate, ScriptedConsent};

// ─────────────────────────────────────────────────────────────────────
// Fixture content
// ─────────────────────────────────────────────────────────────────────

/// A text file whose raw bytes differ from its canonical rendition in two
/// independent ways — a leading UTF-8 BOM and CRLF endings — so it carries
/// a **raw mirror**, and restoring it byte-identically has to go through
/// that mirror.
fn mirrored_text() -> Vec<u8> {
    let mut bytes = vec![0xEF, 0xBB, 0xBF];
    bytes.extend_from_slice(format!("gate run {}\r\nsecond line\r\n", run_tag()).as_bytes());
    bytes
}

/// LF/NFC/BOM-free text with blank-line paragraphs — sealed under
/// `--split blank-lines` it becomes **several units**, which is what makes
/// the work multi-unit rather than one blob per file.
fn split_text() -> Vec<u8> {
    format!(
        "alpha paragraph for run {tag}\n\nbeta paragraph\n\ngamma paragraph\n",
        tag = run_tag()
    )
    .into_bytes()
}

/// Arbitrary non-UTF-8 bytes — the binary path (no canonicalization, no
/// mirror, one unit).
fn binary() -> Vec<u8> {
    let mut bytes = vec![0x00, 0x01, 0x02, 0xFF, 0xFE, 0x7F, 0x80];
    bytes.extend_from_slice(&run_seed("binary-tail")[..16]);
    bytes
}

struct Fixture {
    mirrored: Vec<u8>,
    split: Vec<u8>,
    binary: Vec<u8>,
}

impl Fixture {
    fn new() -> Self {
        Self {
            mirrored: mirrored_text(),
            split: split_text(),
            binary: binary(),
        }
    }

    /// The three-file work: raw-mirror text, `--split` multi-unit text,
    /// binary — the exact shape S17 names.
    fn files(&self) -> Vec<SealFile<'_>> {
        vec![
            SealFile {
                path_as_given: "notes.txt",
                path_absolute: "/w/notes.txt",
                bytes: &self.mirrored,
                flags: FileFlags::new(),
            },
            SealFile {
                path_as_given: "split.txt",
                path_absolute: "/w/split.txt",
                bytes: &self.split,
                flags: FileFlags::new().with_split(SplitMode::BlankLines),
            },
            SealFile {
                path_as_given: "data/blob.bin",
                path_absolute: "/w/data/blob.bin",
                bytes: &self.binary,
                flags: FileFlags::new(),
            },
        ]
    }
}

fn request<'a>(files: &'a [SealFile<'a>], no_anchor: bool) -> SealRequest<'a> {
    SealRequest {
        files,
        title: format!("M1 gate {}", run_tag()),
        claimed_time_unix_secs: 1_800_000_000,
        app_version: "antseal-m1-gate/1".to_owned(),
        network: NetworkId::Devnet,
        no_anchor,
        degraded: false,
        dry_run: false,
        sig_policy: SigPolicy::hybrid(),
        shaping: SealShapingFlags::default(),
    }
}

// ─────────────────────────────────────────────────────────────────────
// S17 row 1 — the multi-file happy path
// ─────────────────────────────────────────────────────────────────────

/// **S17 accept rows 1, 3 (addresses), 4 (`--live`)**: a three-file
/// `--split` work seals against a live devnet; the manifest's addresses,
/// the journal's S4 precomputation, an independent recomputation from the
/// staged ciphertext and the addresses `finalize_batch` returned all agree;
/// the ANT spent equals the quote the consent gate was shown, both in the
/// receipt and on-chain; every file restores byte-identically **off the
/// network**; and the `--live` primitive confirms every blob.
#[test]
fn the_multi_file_split_seal_round_trips_against_a_live_devnet() {
    let _guard = serial();
    let Some((config, env, key)) = gate() else {
        return;
    };
    eprintln!(
        "S17 happy path: run tag {}, {} nodes, chain {}",
        run_tag(),
        env.node_count(),
        env.chain_id()
    );

    let fixture = Fixture::new();
    let files = fixture.files();
    let vault = IsolatedVault::create("s17-happy");
    let unlocked = vault.unlock();
    let store = WorkStore::new(&unlocked);
    let mut journal_rng = ChaCha20Rng::from_seed(run_seed("s17-happy-journal"));
    let journal = VaultJournal::new(WorkStore::new(&unlocked), &mut journal_rng);

    let sink = CapturedReceipts::new();
    let gate_double = RecordingGate::new();
    let consent = ScriptedConsent::always_yes();

    // The impartial witnesses, read before anything moves.
    let wallet = key.address().to_string();
    let token = env.payment_token().to_string();
    let balance_before =
        ant_balance(env.rpc_url(), &token, &wallet).expect("ANT balance before the seal");
    let txs_before = tx_count(env.rpc_url(), &wallet).expect("tx count before the seal");

    let rt = runtime().expect("the backend runtime builds");
    let started = std::time::Instant::now();
    let (outcome, live_report, restore_report, negative_live) = rt.block_on(async {
        let backend = SealBackend::connect(&config, &key, sink.clone())
            .await
            .expect("SealBackend::connect reaches the devnet");

        let pipeline = Pipeline::new(&backend, &gate_double, &journal, &consent, &NoBarriers);
        let result = pipeline
            .seal(
                &request(&files, false),
                &mut ChaCha20Rng::from_seed(run_seed("s17-happy-seal")),
            )
            .await
            .expect("the three-file work seals on the devnet");
        let SealResult::Sealed(outcome) = result else {
            panic!("a non-dry-run seal returns Sealed");
        };

        // ── The `--live` re-fetch check (S15's check_persistence through
        // R11's manifest-aware wrapper), against the work just sealed.
        let manifest_bytes = journal
            .manifest(&outcome.seal_id)
            .expect("journal read")
            .expect("a complete work journaled its manifest");
        let envelope = Manifest::decode(&manifest_bytes).expect("manifest envelope decodes");
        let body = ManifestBodyV1::decode(envelope.body_bytes()).expect("manifest body decodes");

        let plan = journal
            .plan(&outcome.seal_id)
            .expect("journal read")
            .expect("a complete work journaled its plan");
        let mut unit_ciphertexts: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
        for unit_id in 0..plan.unit_count {
            let staged = journal
                .staged(&outcome.seal_id, BlobSlot::Unit { unit_id })
                .expect("every planned unit is staged");
            unit_ciphertexts.insert(unit_id, staged.ciphertext);
        }
        let staged_manifest = journal
            .staged(&outcome.seal_id, BlobSlot::EncryptedManifest)
            .expect("the encrypted manifest is staged");
        let records = records_from_manifest(
            &body,
            &unit_ciphertexts,
            Some((
                Address::from(staged_manifest.address),
                staged_manifest.ciphertext.as_slice(),
            )),
        )
        .expect("the unit table and the staged ciphertexts cover each other exactly");
        let live_report = live_check(&backend, &records)
            .await
            .expect("the live check runs");

        // Not vacuous: a record pointing at an address nothing was ever
        // stored at must NOT come back AllPersisted.
        let never = StorageRecord::new(
            records[0].subject(),
            Address::from(run_seed("never-stored")),
            b"never-stored".as_slice(),
        );
        let negative_live = live_check(&backend, &[never])
            .await
            .expect("the negative control runs");

        // ── Fetch back and restore, over the same live backend.
        let engine = RestoreEngine::new(&backend, &store);
        let restore_report = engine
            .restore(&outcome.seal_id)
            .await
            .expect("the sealed work restores from the devnet");

        (outcome, live_report, restore_report, negative_live)
    });
    let elapsed = started.elapsed();

    // ── D37's hook fired on the real payment path (S27's obligation).
    assert!(
        sink.fired() >= 1,
        "SealBackend::connect installed a capture hook that never fired on a real pay() — \
         D37's post-pay window is unprotected and a crash there costs a second payment (S27)"
    );
    let captured = sink.last().expect("a captured receipt");
    assert_eq!(
        captured.storage_cost_atto, outcome.paid_atto,
        "the captured receipt-so-far must equal what the seal reports paying"
    );

    // ── Addresses: four independent derivations, one answer.
    let manifest_bytes = journal
        .manifest(&outcome.seal_id)
        .expect("journal read")
        .expect("journaled manifest");
    let envelope = Manifest::decode(&manifest_bytes).expect("envelope decodes");
    let body = ManifestBodyV1::decode(envelope.body_bytes()).expect("body decodes");

    let recorded: Vec<[u8; 32]> = body
        .files()
        .iter()
        .flat_map(|file| file.units().iter())
        .map(|unit| *unit.address().as_bytes())
        .collect();
    assert!(
        recorded.len() >= 5,
        "the fixture must be genuinely multi-unit (mirror + split paragraphs + binary), got {}",
        recorded.len()
    );

    let mut journaled = Vec::with_capacity(recorded.len());
    let mut recomputed = Vec::with_capacity(recorded.len());
    for unit_id in 0..recorded.len() as u64 {
        let staged = journal
            .staged(&outcome.seal_id, BlobSlot::Unit { unit_id })
            .expect("every unit is staged");
        journaled.push(*staged.address.as_bytes());
        // The S4 rule applied afresh to the bytes that were actually
        // uploaded — independent of whatever the journal recorded.
        recomputed.push(
            *antseal_core::storage::compute_storage_address(&staged.ciphertext)
                .expect("a staged blob is within the chunk cap")
                .as_bytes(),
        );
    }
    let returned: Vec<[u8; 32]> = outcome.addresses.iter().map(|a| a.to_bytes()).collect();

    assert_eq!(
        recomputed, journaled,
        "S4 recomputation over the staged ciphertext disagrees with the address the journal \
         recorded for it"
    );
    assert_eq!(
        recorded, recomputed,
        "the manifest's recorded unit addresses are not the S4 precomputation of the uploaded \
         ciphertext"
    );
    assert_eq!(
        recorded,
        returned[..recorded.len()],
        "the addresses ant-core assigned on the live devnet differ from the manifest's — D32's \
         BLAKE3-256 rule and upstream's assignment have diverged"
    );
    assert_eq!(
        recorded.len() + 1,
        returned.len(),
        "the encrypted manifest is the last blob in canonical order"
    );

    // ── Money: the receipt, the seal outcome and the chain all agree with
    // the quote the user actually consented to.
    let seen = consent.last().expect("the consent gate was reached");
    assert_eq!(consent.calls(), 1, "one consent prompt for one seal");
    assert!(
        seen.quote.total_ant_atto > 0,
        "the quote was zero — the fixture bytes were already stored on this devnet, so the \
         payment assertions below would be vacuous (run tag {})",
        run_tag()
    );
    assert_eq!(
        outcome.paid_atto, seen.quote.total_ant_atto,
        "total ANT spent must equal the consented quote"
    );
    assert!(outcome.paid_here, "this invocation is the one that paid");
    assert_eq!(
        seen.blob_count,
        returned.len(),
        "consent was rendered over the full blob set"
    );

    let balance_after =
        ant_balance(env.rpc_url(), &token, &wallet).expect("ANT balance after the seal");
    let spent = balance_before
        .checked_sub(balance_after)
        .expect("the ANT balance did not decrease");
    assert_eq!(
        spent, seen.quote.total_ant_atto,
        "the on-chain ANT delta must equal the consented quote exactly — not the receipt's own \
         claim about itself"
    );
    let txs_after = tx_count(env.rpc_url(), &wallet).expect("tx count after the seal");
    for tx in &captured.txs {
        assert!(
            tx_succeeded(
                env.rpc_url(),
                &common::devnet::hex32_0x(tx.tx_hash.as_bytes())
            )
            .expect("receipt lookup"),
            "a receipted payment tx did not land successfully on Anvil"
        );
    }

    // ── Restore: byte-identical, and genuinely off the wire.
    assert_eq!(restore_report.files.len(), 3);
    assert!(
        restore_report.failed().next().is_none(),
        "a file failed to restore: {:?}",
        restore_report.failed().collect::<Vec<_>>()
    );
    let by_path = |path: &str| {
        restore_report
            .verified()
            .find(|f| f.recorded_path == path)
            .unwrap_or_else(|| panic!("{path} verified"))
    };
    assert_eq!(
        by_path("notes.txt").bytes,
        fixture.mirrored,
        "the BOM and CRLF endings must survive through the raw mirror"
    );
    assert_eq!(by_path("split.txt").bytes, fixture.split);
    assert_eq!(by_path("data/blob.bin").bytes, fixture.binary);
    assert_eq!(
        restore_report.cache_served_units(),
        0,
        "restore served units from the D43 cache — this run never proved the bytes are on the \
         devnet at all"
    );
    for file in restore_report.verified() {
        assert!(
            file.from_network > 0,
            "{} produced no unit from the network",
            file.recorded_path
        );
    }

    // ── The `--live` verdict over every blob of the work.
    assert_eq!(
        live_report.verdict,
        LiveVerdict::AllPersisted,
        "unconfirmed subjects: {:?}",
        live_report.unconfirmed()
    );
    assert_eq!(
        live_report.rows.len(),
        returned.len(),
        "the live check must cover every unit and the encrypted manifest"
    );
    assert_eq!(live_report.fetches, returned.len() as u64);
    assert_ne!(
        negative_live.verdict,
        LiveVerdict::AllPersisted,
        "an address nothing was stored at reported AllPersisted — the live check is vacuous"
    );

    eprintln!(
        "S17 happy path OK: {} blobs, {} units, {} atto-ANT, {} payment tx(s) (nonce {}→{}), \
         {:.1}s",
        returned.len(),
        recorded.len(),
        seen.quote.total_ant_atto,
        captured.txs.len(),
        txs_before,
        txs_after,
        elapsed.as_secs_f64()
    );
}

// ─────────────────────────────────────────────────────────────────────
// S17 row 3 — the zero-anchor seal verifies as UNANCHORED
// ─────────────────────────────────────────────────────────────────────

/// **S17 accept row 3**: a `--no-anchor` seal completes on the devnet, the
/// anchor gate is never called, and the work library-verifies as
/// **UNANCHORED** — R5's aggregation over a zero-anchor set yields no
/// headline time, and restore reports the work in the UNANCHORED class.
///
/// The anchored path is deliberately not exercised: real anchors are M2
/// (S17 Notes).
#[test]
fn a_zero_anchor_seal_library_verifies_as_unanchored() {
    let _guard = serial();
    let Some((config, _env, key)) = gate() else {
        return;
    };

    let fixture = Fixture::new();
    let files = fixture.files();
    let vault = IsolatedVault::create("s17-unanchored");
    let unlocked = vault.unlock();
    let store = WorkStore::new(&unlocked);
    let mut journal_rng = ChaCha20Rng::from_seed(run_seed("s17-unanchored-journal"));
    let journal = VaultJournal::new(WorkStore::new(&unlocked), &mut journal_rng);

    let sink = CapturedReceipts::new();
    let gate_double = RecordingGate::new();
    let consent = ScriptedConsent::always_yes();

    let rt = runtime().expect("runtime");
    let (outcome, report) = rt.block_on(async {
        let backend = SealBackend::connect(&config, &key, sink.clone())
            .await
            .expect("connect");
        let pipeline = Pipeline::new(&backend, &gate_double, &journal, &consent, &NoBarriers);
        let SealResult::Sealed(outcome) = pipeline
            .seal(
                &request(&files, true),
                &mut ChaCha20Rng::from_seed(run_seed("s17-unanchored-seal")),
            )
            .await
            .expect("the --no-anchor work seals")
        else {
            panic!("expected Sealed");
        };
        let engine = RestoreEngine::new(&backend, &store);
        let report = engine
            .restore(&outcome.seal_id)
            .await
            .expect("the unanchored work restores");
        (outcome, report)
    });

    assert_eq!(
        gate_double.calls(),
        0,
        "--no-anchor must make no anchor submission at all (S13)"
    );
    assert!(
        report.unanchored,
        "a --no-anchor seal must be recorded in the UNANCHORED work class"
    );
    assert_eq!(report.network, "devnet");
    assert!(report.failed().next().is_none());

    // R5's aggregation, on the anchor set this work actually has: none.
    let aggregate = aggregate_anchors(&[]);
    assert!(
        aggregate.is_unanchored(),
        "a zero-anchor work must aggregate to UNANCHORED"
    );
    assert_eq!(aggregate.total_anchors(), 0);
    assert_eq!(aggregate.headline_eligible_count(), 0);
    assert!(
        aggregate.headline_time_unix().is_none(),
        "an UNANCHORED work must carry no headline time"
    );

    eprintln!(
        "S17 UNANCHORED OK: work {} sealed with zero anchors, {} atto-ANT",
        antseal_cli::pipeline::hex32(&outcome.work_id),
        outcome.paid_atto
    );
}

// ─────────────────────────────────────────────────────────────────────
// S17 accept row 2 — the M3 exclusion, mechanically
// ─────────────────────────────────────────────────────────────────────

/// **S17 accept row 2**: "grep proves no M3 CLI/bundle-builder invocation".
///
/// Written as a test rather than left to a reviewer's grep, and scoped to
/// every `e2e_*.rs` gate suite so S18 and S19 inherit it on landing rather
/// than each re-arguing the point.
///
/// Needs no devnet: this is a source scan, and it is the one row of S17
/// that must hold even when the gate is skipped.
///
/// The needles are assembled from fragments at runtime so that this
/// function's own source — which necessarily contains them — is not itself
/// a hit. The alternative (excluding this file from its own scan) would
/// leave the scan unable to see the file most likely to acquire a
/// shortcut.
#[test]
fn the_gate_suites_invoke_no_m3_cli_or_bundle_builder() {
    let split = |head: &str, tail: &str| format!("{head}{tail}");
    let forbidden: Vec<(String, &str)> = vec![
        (
            split("main_", "entry"),
            "spawning the CLI's argv entry point — D34 requires the E2E to drive library APIs",
        ),
        (
            split("verify_", "bundle"),
            "the bundle verification pipeline is M3",
        ),
        (
            split("CARGO_BIN", "_EXE"),
            "resolving the built binary's path — that is a spawned-CLI shape, and it is the only \
             sanctioned way a cargo test can find the CLI at all",
        ),
        (
            split("assert_", "cmd"),
            "the CLI-spawning test-harness crate",
        ),
        (split("Bundle", "Builder"), "the M3 bundle builder"),
    ];

    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
    let mut scanned = Vec::new();
    let mut violations = Vec::new();
    for entry in std::fs::read_dir(&dir).expect("read tests dir").flatten() {
        let path = entry.path();
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        if !name.starts_with("e2e_") || !name.ends_with(".rs") {
            continue;
        }
        let text = std::fs::read_to_string(&path).expect("read a gate suite");
        scanned.push(name.clone());
        for (needle, why) in &forbidden {
            if text.contains(needle.as_str()) {
                violations.push(format!("{name} names `{needle}` — {why}"));
            }
        }
        // Process spawning is not forbidden outright — S18's accept row
        // *requires* a real SIGKILL, which requires a process to kill, and
        // the only way to get one without `unsafe` fork is to re-execute
        // this very test binary. What must stay forbidden is spawning
        // anything *else*, above all the CLI. So the rule is conditional
        // rather than blanket: a gate suite that spawns must resolve its
        // program from `current_exe`, and the `CARGO_BIN_EXE` needle above
        // independently blocks the one way a cargo test can name the CLI.
        let spawns = text.contains(&split("Command::", "new"));
        if spawns && !text.contains(&split("current_", "exe")) {
            violations.push(format!(
                "{name} spawns a process without resolving it from `current_exe` — an M1 gate \
                 suite may re-execute itself (S18's SIGKILL row) and nothing else"
            ));
        }
    }

    assert!(
        scanned.contains(&"e2e_devnet.rs".to_owned()),
        "the scan did not find this very file — it is not looking where it thinks (found {scanned:?})"
    );
    assert!(
        violations.is_empty(),
        "an M1 gate suite reached for an M3 surface:\n  {}",
        violations.join("\n  ")
    );

    // The scan is not vacuous: a planted invocation really is matched, and
    // a planted spawn of something other than `current_exe` really is
    // caught by the conditional rule.
    let planted = format!("let _ = {}(std::env::args());", split("main_", "entry"));
    assert!(
        forbidden
            .iter()
            .any(|(needle, _)| planted.contains(needle.as_str())),
        "the needle set no longer matches a literal CLI invocation"
    );
    let planted_spawn = format!(
        "{}(\"/usr/bin/antseal\").spawn()",
        split("Command::", "new")
    );
    assert!(
        planted_spawn.contains(&split("Command::", "new"))
            && !planted_spawn.contains(&split("current_", "exe")),
        "the conditional spawn rule no longer recognises a foreign-program spawn"
    );
}
