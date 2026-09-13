//! **U30 — `antseal verify`**, over real `.sealproof` bundles.
//!
//! Every bundle here is built by R6's constructor and put through the same
//! `run_verify` the binary calls, so the exit codes, the rendering and the
//! `--json` document under test are the ones a user gets. The binary itself
//! is spawned for the rows that are *about* the process — the vault-less
//! claim, the never-prompts claim, the one-document contract, and the
//! equality D69 §3 R7 makes assertable (`$? == result.verdict.exit_code`).
//!
//! The rulings under test:
//!
//! - **D69** — the severity fold over the whole anchor set, its four classes
//!   (40/41/42/43), the third arm that lets a nonzero verdict still emit its
//!   result, and the two exclusions (`--live` never moves the code; probe
//!   weather cannot).
//! - **D65** — `result.report` carried **byte-verbatim**, the four members
//!   always present, `ok` meaning *a result document is present*, and `v`
//!   read from `ENVELOPE_VERSION` while the report's version is read from
//!   `REPORT_VERSION`, neither derived from the other.
//! - **D128** — no `--no-storage-linkage` flag exists, and the offline
//!   linkage row renders on **every** run, `--live` or not.

#[path = "common/spawn.rs"]
mod spawn;

use std::path::{Path, PathBuf};
use std::process::Stdio;

use antseal_anchor::arbitrum::endpoints::expected_chain_id;
use antseal_anchor::testing::stub::{StubMatch, StubReply, StubScript, StubServer};
use antseal_cli::backend::degrade;
use antseal_cli::error::ErrorClass;
use antseal_cli::machine::ENVELOPE_VERSION;
use antseal_cli::verify_host::{CollectedInputs, run_verify_live};
use antseal_cli::verify_out::{VerifyRun, run_verify};
use antseal_core::anchor::model::{OnlineBlockResult, OnlineEvidence, ReceiptConfirmation};
use antseal_core::anchor::testing::ots_writer::{FETCH_DATE, bitcoin, container, header_with};
use antseal_core::bundle::schema::{OpaqueBytes, OtsAnchor, OtsUpgrade};
use antseal_core::bundle::{AnchorStatus, BundleV1, SealProof, encode_bundle};
use antseal_core::crypto::unit_aead::Nonce24 as AeadNonce;
use antseal_core::manifest::anchor_digest;
use antseal_core::test_util::bundle_fixtures::{
    Selection, StorageAddresses, Tweak, build, build_tweaked, shapes,
};
use antseal_core::verify::REPORT_VERSION;
use antseal_core::verify::orchestration::{
    FetchFailureClass, LiveBlobOutcome, LiveBlobRow, LiveInputs, LiveLayerVerdict, OnlineInputs,
    VerifyModes,
};
use antseal_core::verify::overlay::{BlockProbe, ProbeEndpoints, ProbeLog, ReceiptProbe};
use antseal_core::verify::storage_linkage::{
    ManifestLinkageSubject, recompute_manifest_storage_blob,
};
use antseal_core::verify::{VerifyOptions, wording};
use antseal_net::test_util::{Fault, Method, MockBackend, block_on};
use antseal_net::{
    Address, BalanceReport, Blob, CostQuote, NetworkId, PaymentReceipt, StorageBackend,
    StorageError,
};

// ─────────────────────────────────────────────────────────────────────
// fixtures — real bundles, built the way R21's own suite builds them
// ─────────────────────────────────────────────────────────────────────

/// A height no other fixture in the tree uses.
const HEIGHT: u64 = 700_411;
/// A second height, far enough from the first that promoted anchors at both
/// span more than the 48 h divergence threshold.
const HEIGHT_LATE: u64 = 700_412;
/// The embedded header's `nTime` for [`HEIGHT`].
const NTIME: u32 = 1_483_398_000;
/// 49 h later — strictly more than the 48 h threshold R17 flags.
const NTIME_LATE: u32 = NTIME + 49 * 3_600;

/// R6's three-file work with **no anchors at all** — the UNANCHORED bundle
/// (MVP-SPEC.md line 137's population, and D69 rung 3).
fn unanchored_bundle() -> Vec<u8> {
    build(&shapes::multi_file(), &Selection::all(3)).bytes
}

/// A tampered bundle: one file's `canon_commit` bit-flipped in the manifest,
/// which is a tamper-matrix row and therefore the `Err` arm of
/// `verify_bundle`.
fn tampered_bundle() -> Vec<u8> {
    build_tweaked(&shapes::multi_file(), &Selection::all(3), &{
        let mut tweak = Tweak::none();
        tweak.corrupt_canon_commit = Some(0);
        tweak
    })
    .bytes
}

/// The unanchored work, carrying `n` genuinely `attested` `.ots` artifacts:
/// zero-op containers stamping this bundle's own `anchor_digest`, each
/// committed at its own height with the D79 upgrade group whose embedded
/// header commits the same digest at its own `nTime`.
///
/// Returns the bytes and, per anchor, `(height, header)` — what agreed online
/// evidence must match for that anchor to promote.
fn attested_bundle(stamps: &[(u64, u32)]) -> (Vec<u8>, Vec<(u64, [u8; 80])>) {
    let built = build(&shapes::multi_file(), &Selection::all(3));
    let proof = SealProof::decode(&built.bytes).expect("the R6 fixture decodes");
    let digest = *anchor_digest(proof.anchor_digest_preimage()).as_bytes();

    let mut anchors = Vec::new();
    let mut evidence = Vec::new();
    for (height, ntime) in stamps {
        let header = header_with(&digest, *ntime);
        anchors.push(
            OtsAnchor::new(
                AnchorStatus::Attested,
                OpaqueBytes::from_vec(container(&digest, &bitcoin(*height))),
                Some(OtsUpgrade::new(*height, header, FETCH_DATE)),
            )
            .expect("a synthetic committed artifact is under the D10 caps"),
        );
        evidence.push((*height, header));
    }

    let mut parts = BundleV1::decode(&built.bytes)
        .expect("the R6 fixture decodes to the model")
        .into_parts();
    parts.ots_anchors = anchors;
    let bytes = encode_bundle(&BundleV1::new(parts).expect("a well-formed bundle"))
        .expect("the rebuilt bundle re-encodes");
    (bytes, evidence)
}

fn options() -> VerifyOptions {
    VerifyOptions::new()
}

/// Endpoint identities for a probe log — fixtures, never contacted.
fn endpoints() -> ProbeEndpoints {
    ProbeEndpoints::new(
        vec![
            "https://blockstream.example/api".to_owned(),
            "https://mempool.example/api".to_owned(),
        ],
        false,
    )
}

/// An offline run.
fn verify_offline_run(bundle: &[u8]) -> VerifyRun {
    run_verify(
        bundle,
        &options(),
        VerifyModes::OFFLINE,
        &CollectedInputs::none(),
    )
    .expect("the fixture bundle verifies")
}

/// An `--online` run over host-supplied agreed evidence.
fn verify_online_run(bundle: &[u8], agreed: &[(u64, [u8; 80])]) -> VerifyRun {
    let mut evidence = OnlineEvidence::new();
    let mut probes = ProbeLog::new(endpoints());
    for (height, header) in agreed {
        evidence = evidence.with_block(*height, OnlineBlockResult::Header(*header));
        probes = probes.with_block(*height, BlockProbe::Agreed);
    }
    let host = CollectedInputs::none().with_online(OnlineInputs::new(evidence, probes));
    run_verify(bundle, &options(), VerifyModes::new().with_online(), &host)
        .expect("the fixture bundle verifies")
}

/// An `--online` run whose probes all **failed** — the weather case.
fn verify_online_weather(bundle: &[u8], heights: &[u64]) -> VerifyRun {
    let mut probes = ProbeLog::new(endpoints());
    for height in heights {
        probes = probes.with_block(*height, BlockProbe::Failed(Vec::new()));
    }
    let host =
        CollectedInputs::none().with_online(OnlineInputs::new(OnlineEvidence::new(), probes));
    run_verify(bundle, &options(), VerifyModes::new().with_online(), &host)
        .expect("the fixture bundle verifies")
}

/// A `--live` run over host-supplied rows.
fn verify_live_run(bundle: &[u8], rows: Vec<LiveBlobRow>) -> VerifyRun {
    let host = CollectedInputs::none().with_live(LiveInputs::from_rows(rows));
    run_verify(bundle, &options(), VerifyModes::new().with_live(), &host)
        .expect("the fixture bundle verifies")
}

// ─────────────────────────────────────────────────────────────────────
// Accept row 1 — golden bundles, correct rendering, MAPPED exit codes
// ─────────────────────────────────────────────────────────────────────

/// The UNANCHORED bundle: every commitment opens, no anchor is
/// headline-eligible, so the run **succeeds** with a report and exits **43**.
///
/// The whole of D69 §4 is in this one row: exit 0 would make the product's
/// loudest string silent to every consumer that is not a human at a terminal.
#[test]
fn an_unanchored_bundle_verifies_and_exits_forty_three() {
    let run = verify_offline_run(&unanchored_bundle());

    assert_eq!(run.exit_class(), Some(ErrorClass::VerifyUnanchored));
    assert_eq!(run.exit_code(), 43);
    assert_eq!(
        run.exit_class().expect("a rung").name(),
        "verify-unanchored"
    );

    // The rendering is R18's, not this crate's: the banner is asserted
    // against the frozen table rather than against a copy.
    let rendered = run.render();
    assert!(
        rendered.contains(&wording::UNANCHORED_BANNER.to_owned()),
        "the loud banner must be the headline: {rendered:#?}"
    );
    assert!(run.outcome().rendered().unanchored);
}

/// A tampered bundle is the `Err` arm: **no report exists** (D27 §4), so it
/// is a `CliError` at **40**, and its distinct rejection code rides in the
/// message — the wave rule *verify a failure by its message*, as a test.
#[test]
fn a_tampered_bundle_is_rejected_at_forty_with_its_code_in_the_message() {
    let error = match run_verify(
        &tampered_bundle(),
        &options(),
        VerifyModes::OFFLINE,
        &CollectedInputs::none(),
    ) {
        Ok(_) => panic!("a tampered bundle must not verify"),
        Err(error) => error,
    };

    assert_eq!(error.class(), ErrorClass::VerifyBundleRejected);
    assert_eq!(error.exit_code(), 40);
    assert_ne!(error.exit_code(), 0, "tampered → nonzero");

    let message = error.to_string();
    // The code namespace and the exit-class namespace are disjoint
    // (`error-code-contract.md` §2): the rejection code is in the message,
    // never in the integer.
    let bundle = tampered_bundle();
    let expected = antseal_core::verify::verify_bundle(&bundle, &options())
        .expect_err("the same rejection")
        .code();
    assert!(
        message.contains(expected),
        "the message must carry `{expected}`: {message}"
    );
}

/// The storage-linkage layer renders on an ordinary offline run — D128 §3
/// R1/R5: `verify_bundle`'s default **runs** the layer, `verify` has no
/// suppression flag, and the section is not `--live`'s to constitute.
#[test]
fn the_storage_layer_renders_without_live_being_requested() {
    let run = verify_offline_run(&unanchored_bundle());
    let rendered = run.render();

    assert!(
        rendered.contains(&wording::STORAGE_LINKAGE_LAYER_LABEL.to_owned()),
        "the storage layer's label is unconditional: {rendered:#?}"
    );
    // The layer evaluated: `NotEvaluated` would be the literal truth about a
    // run that suppressed it, and this run cannot suppress it.
    assert!(
        !matches!(
            run.outcome().report().storage_linkage,
            antseal_core::verify::report::StorageLinkageResult::NotEvaluated
        ),
        "D128 §3 R1: the default runs the layer"
    );
    assert!(run.outcome().live().is_none(), "--live was not requested");
}

// ─────────────────────────────────────────────────────────────────────
// D69 §3 R3 — the fold, over the transitions it names
// ─────────────────────────────────────────────────────────────────────

/// Promotion, 43 → 0: an `attested` OTS whose header both endpoints agree on
/// becomes `proven` and **supplies the headline** (MVP-SPEC.md line 137), so
/// the run that was UNANCHORED now exits 0.
#[test]
fn agreement_promotes_the_rung_from_unanchored_to_clean() {
    let (bundle, agreed) = attested_bundle(&[(HEIGHT, NTIME)]);

    assert_eq!(verify_offline_run(&bundle).exit_code(), 43, "offline");
    let online = verify_online_run(&bundle, &agreed);
    assert_eq!(online.exit_code(), 0, "--online supplies the headline");
    assert_eq!(online.exit_class(), None);

    // And D64 §2 is untouched by that: the **offline block** is built from
    // the offline aggregate under every mode, so it still says UNANCHORED
    // and its bytes have not moved. The exit code is a coarsening of the
    // strongest computation the run performed; the block is a rendering of
    // the offline one. Both are true at once, deliberately.
    assert!(
        online.outcome().rendered().unanchored,
        "the offline block may not be rewritten by the overlay"
    );
    assert_eq!(
        online.outcome().rendered(),
        verify_offline_run(&bundle).outcome().rendered(),
        "D64 §2: the offline block is byte-identical under --online"
    );
}

/// Agreed refutation, → 41: the endpoints agree on a header that does **not**
/// commit this bundle's digest, so the anchor is `invalid` and rung 1 wins.
#[test]
fn an_agreed_header_mismatch_climbs_to_anchor_refuted() {
    let (bundle, agreed) = attested_bundle(&[(HEIGHT, NTIME)]);
    let wrong = header_with(&[0x5A; 32], NTIME);
    let refuting: Vec<(u64, [u8; 80])> = agreed.iter().map(|(h, _)| (*h, wrong)).collect();

    let run = verify_online_run(&bundle, &refuting);
    assert_eq!(run.exit_class(), Some(ErrorClass::VerifyAnchorRefuted));
    assert_eq!(run.exit_code(), 41);
    assert!(
        run.outcome().verdict_class().anchors_refuted >= 1,
        "the datum counts what the rung folded"
    );
}

/// Newly-flagged divergence, → 42: two anchors promote to times 49 h apart,
/// which is strictly more than the threshold, so the eligible set disagrees
/// with itself.
///
/// This is also the row that proves rungs 2 and 3 are mutually exclusive by
/// construction: a divergence needs two eligible anchors, so the set is not
/// unanchored.
#[test]
fn a_newly_flagged_divergence_climbs_to_forty_two() {
    let (bundle, agreed) = attested_bundle(&[(HEIGHT, NTIME), (HEIGHT_LATE, NTIME_LATE)]);

    let run = verify_online_run(&bundle, &agreed);
    let class = run.outcome().verdict_class();
    assert!(class.headline_divergence, "the set spans > 48 h: {class:?}");
    assert!(!class.unanchored, "two eligible anchors");
    assert_eq!(run.exit_class(), Some(ErrorClass::VerifyHeadlineDivergence));
    assert_eq!(run.exit_code(), 42);
}

/// Rung 1 outranks rung 3 without a special case: one `invalid` anchor and
/// no eligible one satisfies **both** predicates, and the fold picks the
/// worst established fact.
#[test]
fn refutation_outranks_unanchored_by_the_fold_not_by_a_list() {
    let (bundle, agreed) = attested_bundle(&[(HEIGHT, NTIME)]);
    let wrong = header_with(&[0x5A; 32], NTIME);
    let run = verify_online_run(&bundle, &[(agreed[0].0, wrong)]);

    let class = run.outcome().verdict_class();
    assert!(class.unanchored, "nothing promoted, so nothing is eligible");
    assert!(class.anchors_refuted >= 1, "and something was refuted");
    assert_eq!(run.exit_code(), 41, "the worst established fact wins");
}

/// **Probe weather cannot move the exit code** (D69 §3 R5) — and it is a
/// theorem, not a check: with no agreement, the online-augmented verdicts
/// *equal* the offline ones.
///
/// Asserted beside D64's report-byte equality so the two travel together.
#[test]
fn probe_failure_moves_neither_the_exit_code_nor_the_report_bytes() {
    let (bundle, agreed) = attested_bundle(&[(HEIGHT, NTIME)]);
    let heights: Vec<u64> = agreed.iter().map(|(h, _)| *h).collect();

    let offline = verify_offline_run(&bundle);
    let weather = verify_online_weather(&bundle, &heights);

    assert_eq!(
        weather.exit_code(),
        offline.exit_code(),
        "a network outage cannot change this command's exit code"
    );
    assert_eq!(
        weather.outcome().report_bytes(),
        offline.outcome().report_bytes(),
        "D64 §6: the report bytes are byte-identical either way"
    );
    assert!(
        weather.outcome().overlay().is_some(),
        "the overlay still renders the failure as that anchor's outcome"
    );
}

// ─────────────────────────────────────────────────────────────────────
// D69 §3 R6 — `--live` never moves the exit code, and reads distinctly
// ─────────────────────────────────────────────────────────────────────

/// One bundle, three live outcomes, **one** exit code (D69 §7 row 7).
///
/// The rung classifier takes no live parameter, so this is a property of the
/// types; the test is what keeps a future edit from adding one.
#[test]
fn live_outcomes_never_move_the_exit_code() {
    let bundle = unanchored_bundle();
    let baseline = verify_offline_run(&bundle).exit_code();

    let cases = [
        ("match", LiveBlobOutcome::Identical),
        ("mismatch", LiveBlobOutcome::Different),
        (
            "fetch-failed",
            LiveBlobOutcome::FetchFailed {
                class: FetchFailureClass::Transport,
            },
        ),
    ];
    for (label, outcome) in cases {
        let run = verify_live_run(
            &bundle,
            vec![LiveBlobRow {
                subject: "unit 0".to_owned(),
                outcome,
            }],
        );
        assert_eq!(run.exit_code(), baseline, "{label} moved the exit code");
        assert_eq!(
            run.outcome().report_bytes(),
            verify_offline_run(&bundle).outcome().report_bytes(),
            "{label} moved the evidence layer"
        );
    }
}

/// A `--live` mismatch fails the **storage-linkage layer** distinctly from
/// the evidence layer: a distinct rendered line, a distinct machine field,
/// and an evidence verdict that did not move (D69 §3 R6's reading of Accept
/// row 2).
#[test]
fn a_live_mismatch_reads_distinctly_from_the_evidence_layer() {
    let bundle = unanchored_bundle();
    let run = verify_live_run(
        &bundle,
        vec![LiveBlobRow {
            subject: "unit 0".to_owned(),
            outcome: LiveBlobOutcome::Different,
        }],
    );

    let live = run.outcome().live().expect("--live produces a section");
    assert_eq!(
        live.verdict,
        antseal_core::verify::orchestration::LiveLayerVerdict::Divergent
    );
    let rendered = run.render();
    let divergent = wording::live_divergent_line(1);
    assert!(
        rendered.iter().any(|line| line.contains(&divergent)),
        "the storage layer states its own verdict: {rendered:#?}"
    );
    // And it did not become the evidence layer's problem.
    assert_eq!(run.exit_code(), verify_offline_run(&bundle).exit_code());
}

/// `--live` over a **MockBackend**: the real collector, driven end to end,
/// over the bundle's own embedded ciphertexts.
///
/// A fault on every `get_data` is the "no network" case D69 §3 R6 reads *by
/// the message*: the full offline verdict still renders, the live section
/// reports R11's `Inconclusive` (*"the check could not be completed"*), and
/// the exit code is the evidence verdict's.
#[test]
fn a_live_check_with_no_reachable_network_is_inconclusive_and_moves_nothing() {
    let bytes = unanchored_bundle();
    let bundle = BundleV1::decode(&bytes).expect("the fixture decodes");
    let backend = MockBackend::new();
    backend.arm_fault(Fault::DuringGetData);

    let live = block_on(antseal_cli::verify_host::collect_live(&bundle, &backend))
        .expect("the collector composes rows from a verified bundle");
    assert!(!live.rows().is_empty(), "the bundle embeds ciphertexts");

    let host = CollectedInputs::none().with_live(live);
    let run = run_verify(&bytes, &options(), VerifyModes::new().with_live(), &host)
        .expect("the offline verdict is unaffected");

    let section = run.outcome().live().expect("a section");
    // The mock's armed fault is one-shot and its store is empty, so the run
    // sees one fetch failure and then negative answers — measured, not
    // assumed. What the row is about is that BOTH kinds of bad news reach
    // the storage layer and neither reaches the evidence one.
    assert!(
        section.counts.fetch_failed >= 1,
        "the fetch failure reached the collector's mapping: {:?}",
        section.counts
    );
    assert!(
        !matches!(
            section.verdict,
            antseal_core::verify::orchestration::LiveLayerVerdict::AllPersisted
                | antseal_core::verify::orchestration::LiveLayerVerdict::NothingChecked
        ),
        "a check that failed is never a pass and never a vacuum: {:?}",
        section.verdict
    );
    assert_eq!(
        run.exit_code(),
        verify_offline_run(&bytes).exit_code(),
        "the offline verdict is unaffected"
    );
    assert_eq!(
        run.outcome().report_bytes(),
        verify_offline_run(&bytes).outcome().report_bytes(),
        "and neither are its bytes"
    );
}

// ─────────────────────────────────────────────────────────────────────
// D170 §2 R6 — `--live` verifies before it collects
// ─────────────────────────────────────────────────────────────────────

/// R6's three-file work with **real** S4 addresses throughout, so a network
/// seeded with the bundle's own blobs holds every subject `--live` asks about.
fn linked_bundle() -> Vec<u8> {
    build(
        &shapes::multi_file().with_storage_addresses(StorageAddresses::Real),
        &Selection::all(3),
    )
    .bytes
}

/// Seed `mock` with every blob `collect_live` will ask for — each embedded
/// unit ciphertext and the encrypted-manifest blob — and return how many.
///
/// The manifest blob is recomputed through R81's public door and asserted to
/// land at the address the signed storage record claims, so the seeding is
/// read back rather than trusted.
fn seed_every_blob(mock: &MockBackend, bundle: &BundleV1<'_>) -> u64 {
    let mut seeded = 0u64;
    for ciphertext in bundle
        .covered_reveals()
        .iter()
        .map(|reveal| reveal.ciphertext().as_slice())
        .chain(
            bundle
                .noncovered_reveals()
                .iter()
                .map(|reveal| reveal.ciphertext().as_slice()),
        )
    {
        let address = mock.preload_third_party(ciphertext);
        assert_eq!(
            mock.stored(address).as_deref(),
            Some(ciphertext),
            "the seeded unit is served back"
        );
        seeded += 1;
    }
    let record = bundle.storage_record();
    let nonce = AeadNonce::from_bytes(*record.nonce().as_bytes());
    let blob = recompute_manifest_storage_blob(&ManifestLinkageSubject {
        manifest_bytes: bundle.manifest_bytes(),
        nonce: &nonce,
        k_m: record.k_m(),
        recorded_address: record.address(),
    })
    .expect("a fixture manifest is far below the AEAD's P_MAX");
    assert_eq!(
        mock.preload_third_party(&blob),
        Address::from(*record.address()),
        "the manifest blob lands at the address the storage record claims"
    );
    seeded + 1
}

/// `MockBackend` behind an `Arc`, so a row can read its call log after the
/// backend it wraps has been handed to `run_verify_live` and dropped there.
struct SharedMock(std::sync::Arc<MockBackend>);

impl StorageBackend for SharedMock {
    async fn quote_batch(&self, blobs: &[Blob]) -> Result<CostQuote, StorageError> {
        self.0.quote_batch(blobs).await
    }

    async fn pay(&self, quote: &CostQuote) -> Result<PaymentReceipt, StorageError> {
        self.0.pay(quote).await
    }

    async fn finalize_batch(
        &self,
        receipt: &PaymentReceipt,
        blobs: &[Blob],
    ) -> Result<Vec<Address>, StorageError> {
        self.0.finalize_batch(receipt, blobs).await
    }

    async fn get_data(&self, address: Address) -> Result<Vec<u8>, StorageError> {
        self.0.get_data(address).await
    }

    async fn balances(&self) -> Result<BalanceReport, StorageError> {
        self.0.balances().await
    }
}

/// **D170 §2 R6 — the order.** `--live` over a bundle that fails offline
/// verification exits with that failure's own class (40) and message, and the
/// network is **never connected to**, let alone fetched from.
///
/// The zero is made to mean something twice over: the tampered bundle still
/// decodes and still embeds ciphertexts, so a composition that connected and
/// collected first would have reached the network; and the same composition
/// over its untampered twin is watched connecting and fetching.
#[test]
fn live_over_a_tampered_bundle_is_rejected_at_forty_with_zero_fetches() {
    use std::sync::atomic::{AtomicBool, Ordering};

    let bytes = tampered_bundle();
    let decoded = BundleV1::decode(&bytes).expect("the tampered bundle still decodes");
    assert!(
        !decoded.covered_reveals().is_empty(),
        "and still embeds ciphertexts, so a composition that collected first would reach the \
         network"
    );

    let network = std::sync::Arc::new(MockBackend::new());
    let connected = AtomicBool::new(false);
    let error = match block_on(run_verify_live(
        &bytes,
        &options(),
        VerifyModes::OFFLINE,
        CollectedInputs::none(),
        async {
            connected.store(true, Ordering::SeqCst);
            SharedMock(std::sync::Arc::clone(&network))
        },
    )) {
        Ok(_) => panic!("a tampered bundle must not verify under --live"),
        Err(error) => error,
    };
    assert_eq!(error.class(), ErrorClass::VerifyBundleRejected);
    assert_eq!(error.exit_code(), 40);
    let offline = match run_verify(
        &bytes,
        &options(),
        VerifyModes::OFFLINE,
        &CollectedInputs::none(),
    ) {
        Ok(_) => panic!("the tampered bundle must not verify offline either"),
        Err(error) => error,
    };
    assert_eq!(
        error.to_string(),
        offline.to_string(),
        "--live rejects with exactly the offline rejection"
    );
    assert_eq!(
        network.calls(Method::GetData),
        0,
        "`--live` fetched {} blob(s) for a bundle that failed verification — collection must \
         run after offline verification passes, never before (D170 §2 R6)",
        network.calls(Method::GetData)
    );
    assert!(
        !connected.load(Ordering::SeqCst),
        "`--live` connected to the network for a bundle that failed verification — the \
         connection must be made only after offline verification passes (D170 §2 R6)"
    );
    assert!(
        network.call_log().is_empty(),
        "no seam call of any kind: {:?}",
        network.call_log()
    );

    // POSITIVE CONTROL: the composition connects and fetches when the bundle
    // verifies.
    let control = std::sync::Arc::new(MockBackend::new());
    let control_connected = AtomicBool::new(false);
    let _run = block_on(run_verify_live(
        &unanchored_bundle(),
        &options(),
        VerifyModes::OFFLINE,
        CollectedInputs::none(),
        async {
            control_connected.store(true, Ordering::SeqCst);
            SharedMock(std::sync::Arc::clone(&control))
        },
    ))
    .expect("the untampered twin verifies under --live");
    assert!(
        control_connected.load(Ordering::SeqCst) && control.calls(Method::GetData) > 0,
        "CONTROL: the same composition over a verifying bundle must connect and fetch, or the \
         zeros above are a composition that never reaches the network rather than an order"
    );
}

/// **D170 §2 R6 — the composition.** Over a network that holds every blob,
/// the live section is attached and reports every subject persisted, while
/// the exit code and the report bytes are exactly the offline run's.
#[test]
fn live_over_a_network_holding_every_blob_reports_persisted_and_moves_nothing() {
    let bytes = linked_bundle();
    let bundle = BundleV1::decode(&bytes).expect("the fixture decodes");
    let network = std::sync::Arc::new(MockBackend::new());
    let seeded = seed_every_blob(&network, &bundle);
    assert!(
        seeded >= 3,
        "several subjects, or all-persisted says little: {seeded}"
    );

    let run = block_on(run_verify_live(
        &bytes,
        &options(),
        VerifyModes::OFFLINE,
        CollectedInputs::none(),
        async { SharedMock(std::sync::Arc::clone(&network)) },
    ))
    .expect("the linked fixture verifies under --live");

    let section = run
        .outcome()
        .live()
        .expect("--live attaches a live section");
    assert_eq!(
        section.verdict,
        LiveLayerVerdict::AllPersisted,
        "the collected rows reached the run: {:?}",
        section.counts
    );
    assert_eq!(section.counts.checked, seeded, "{:?}", section.counts);
    assert_eq!(section.counts.identical, seeded, "{:?}", section.counts);
    assert!(
        run.render()
            .iter()
            .any(|line| line.contains(&wording::live_all_persisted_line(seeded))),
        "the rendered storage layer says so: {:#?}",
        run.render()
    );

    let offline = verify_offline_run(&bytes);
    assert_eq!(
        run.exit_code(),
        offline.exit_code(),
        "the live layer moved the exit code"
    );
    assert_eq!(
        run.outcome().report_bytes(),
        offline.outcome().report_bytes(),
        "the live layer moved the evidence layer's bytes"
    );
    assert_eq!(
        network.calls(Method::GetData) as u64,
        seeded,
        "one fetch per subject"
    );
}

/// **D170 §2 R2 with R6 — an unreachable network.** In both shapes it takes
/// at the seam, `verify --live` renders its offline verdict in full, reports
/// the live section *Inconclusive* with every row a fetch failure, and exits
/// with the evidence verdict's code — 43 for this unanchored work, never the
/// network class's 23:
///
/// - **connect-failed** — the connection attempt fails and `degrade` hands
///   over the unreachable backend, so the (reachable) network below is never
///   asked;
/// - **every-fetch-fails** — the connection succeeds and every fetch fails in
///   the network class, which is what ant-core 0.5.0 does for a dead or empty
///   bootstrap (measured on a live devnet 2026-09-13; the adapter reports it
///   in the network class rather than as absence). That arm runs over a
///   network that **holds** every blob, armed with one fault per subject, so a
///   fetch that escaped its fault would be served and would move the verdict.
#[test]
fn live_over_an_unreachable_network_is_inconclusive_and_exits_with_the_evidence_verdict() {
    let bytes = linked_bundle();
    let bundle = BundleV1::decode(&bytes).expect("the fixture decodes");
    let offline = verify_offline_run(&bytes);
    let network = std::sync::Arc::new(MockBackend::new());
    let subjects = seed_every_blob(&network, &bundle);

    for shape in ["connect-failed", "every-fetch-fails"] {
        let before = network.calls(Method::GetData);
        let outcome = if shape == "connect-failed" {
            block_on(run_verify_live(
                &bytes,
                &options(),
                VerifyModes::OFFLINE,
                CollectedInputs::none(),
                async {
                    degrade(
                        "verify",
                        Err::<SharedMock, _>(StorageError::Network {
                            reason: "fixture: no bootstrap peer answered".to_owned(),
                        }),
                    )
                },
            ))
        } else {
            for _ in 0..subjects {
                network.arm_fault(Fault::NetworkOn(Method::GetData));
            }
            block_on(run_verify_live(
                &bytes,
                &options(),
                VerifyModes::OFFLINE,
                CollectedInputs::none(),
                async { degrade("verify", Ok(SharedMock(std::sync::Arc::clone(&network)))) },
            ))
        };
        let run = match outcome {
            Ok(run) => run,
            Err(error) => panic!(
                "{shape}: an unreachable network must not end `verify --live` (D170 §2 R2): it \
                 returned `{}` (exit {}): {error}",
                error.class().name(),
                error.exit_code()
            ),
        };

        assert_eq!(
            run.exit_code(),
            43,
            "{shape}: the unanchored work's evidence verdict"
        );
        assert_ne!(run.exit_code(), 23, "{shape}: never the network class");
        assert_eq!(run.exit_code(), offline.exit_code(), "{shape}");
        assert_eq!(
            run.outcome().report_bytes(),
            offline.outcome().report_bytes(),
            "{shape}: the offline report bytes, unchanged"
        );

        let section = run
            .outcome()
            .live()
            .expect("--live attaches a live section");
        assert_eq!(
            section.verdict,
            LiveLayerVerdict::Inconclusive,
            "{shape}: {:?}",
            section.counts
        );
        assert_eq!(
            section.counts.checked, subjects,
            "{shape}: {:?}",
            section.counts
        );
        assert_eq!(
            section.counts.fetch_failed, section.counts.checked,
            "{shape}: every row is a fetch failure, and none is a negative answer: {:?}",
            section.counts
        );
        let reached_network = network.calls(Method::GetData) - before;
        if shape == "connect-failed" {
            assert_eq!(
                reached_network, 0,
                "{shape}: the degraded backend fails every fetch itself; nothing reaches a network"
            );
        } else {
            assert_eq!(
                network.armed_faults(),
                0,
                "{shape}: every armed fault fired"
            );
            assert_eq!(
                reached_network as u64, subjects,
                "{shape}: every subject was asked of the network exactly once"
            );
        }
        assert!(
            run.render()
                .iter()
                .any(|line| line.contains(&wording::live_inconclusive_line(subjects))),
            "{shape}: the rendered storage layer says inconclusive: {:#?}",
            run.render()
        );
    }
}

// ─────────────────────────────────────────────────────────────────────
// D65 — the `--json` document
// ─────────────────────────────────────────────────────────────────────

/// **Tier A, and the row that cannot be discharged structurally**: the
/// emitted document contains `to_canonical_json()`'s bytes as a *contiguous
/// substring*.
///
/// The negative control is the point. `serde_json::Map` is a `BTreeMap` in
/// this build, so a `Value` round trip **alphabetizes** the report's keys —
/// and the assertion below proves that is not a hypothetical: the round trip
/// really does reorder these exact bytes, and the emitted document really
/// does carry the original order.
#[test]
fn the_json_document_carries_the_report_bytes_verbatim() {
    let bundle = unanchored_bundle();
    let run = verify_offline_run(&bundle);
    let document = run.json().expect("the result document renders");
    let canonical = run.outcome().report_bytes();

    assert!(
        document
            .as_bytes()
            .windows(canonical.len())
            .any(|w| w == canonical),
        "the report member must be the canonical bytes, contiguous and unmodified"
    );

    // The trap, demonstrated rather than described: routing the same report
    // through `serde_json::Value` produces DIFFERENT bytes, and the
    // difference is alphabetization — `report_version` (D29 rule 1's first
    // declared key) is no longer first.
    let round_tripped = serde_json::to_string(
        &serde_json::from_slice::<serde_json::Value>(canonical).expect("the report parses"),
    )
    .expect("the value re-serializes");
    assert_ne!(
        round_tripped.as_bytes(),
        canonical,
        "if these ever agree the negative control is dead and this row proves nothing"
    );
    let first_key = |text: &str| {
        text.trim_start_matches('{')
            .split('"')
            .nth(1)
            .expect("a first key")
            .to_owned()
    };
    let canonical_text = core::str::from_utf8(canonical).expect("utf-8");
    assert_eq!(
        first_key(canonical_text),
        "report_version",
        "D29 rule 1: declaration order is the wire order"
    );
    assert_ne!(
        first_key(&round_tripped),
        "report_version",
        "the round trip alphabetizes — that is the bug this row exists to catch"
    );
    assert!(
        !document.contains(&round_tripped),
        "the emitted document must not carry the alphabetized form"
    );
}

/// A presence-only key assertion over `result`, in **all four** mode
/// combinations: every key present in every combination, `null` where the
/// mode was off (D65 §5.1 — conditional presence is forbidden).
#[test]
fn the_result_document_carries_all_four_members_in_every_mode() {
    let (bundle, agreed) = attested_bundle(&[(HEIGHT, NTIME)]);
    let rows = vec![LiveBlobRow {
        subject: "unit 0".to_owned(),
        outcome: LiveBlobOutcome::Identical,
    }];

    let mut evidence = OnlineEvidence::new();
    let mut probes = ProbeLog::new(endpoints());
    for (height, header) in &agreed {
        evidence = evidence.with_block(*height, OnlineBlockResult::Header(*header));
        probes = probes.with_block(*height, BlockProbe::Agreed);
    }

    for (online, live) in [(false, false), (true, false), (false, true), (true, true)] {
        let mut modes = VerifyModes::OFFLINE;
        let mut host = CollectedInputs::none();
        if online {
            modes = modes.with_online();
            host = host.with_online(OnlineInputs::new(evidence.clone(), probes.clone()));
        }
        if live {
            modes = modes.with_live();
            host = host.with_live(LiveInputs::from_rows(rows.clone()));
        }
        let run = run_verify(&bundle, &options(), modes, &host).expect("verifies");
        let document: serde_json::Value =
            serde_json::from_str(&run.json().expect("renders")).expect("one JSON object");

        for key in ["report", "overlay", "live", "verdict"] {
            assert!(
                document.get(key).is_some(),
                "`{key}` is missing at online={online} live={live}"
            );
        }
        assert_eq!(
            document["overlay"].is_null(),
            !online,
            "overlay is null exactly when --online was off"
        );
        assert_eq!(
            document["live"].is_null(),
            !live,
            "live is null exactly when --live was off"
        );
        assert!(!document["report"].is_null(), "a report always exists here");
        assert!(
            !document["verdict"].is_null(),
            "the verdict datum is a value"
        );
    }
}

/// The verdict member carries the rung's **name** and its **code**, and the
/// code is the one the process would exit with (D69 §3 R7's assertable
/// equality, at the library level; the binary-level half is below).
#[test]
fn the_verdict_member_carries_the_rung_name_and_its_code() {
    let run = verify_offline_run(&unanchored_bundle());
    let document: serde_json::Value =
        serde_json::from_str(&run.json().expect("renders")).expect("one JSON object");

    assert_eq!(document["verdict"]["rung"], "verify-unanchored");
    assert_eq!(document["verdict"]["exit_code"], 43);
    assert_eq!(
        document["verdict"]["exit_code"],
        serde_json::json!(run.exit_code()),
        "one classifier, one code"
    );
    assert_eq!(document["verdict"]["unanchored"], true);

    // The clean verdict is a `null` rung and code 0 — a value, never a
    // missing key.
    let (bundle, agreed) = attested_bundle(&[(HEIGHT, NTIME)]);
    let clean = verify_online_run(&bundle, &agreed);
    let document: serde_json::Value =
        serde_json::from_str(&clean.json().expect("renders")).expect("one JSON object");
    assert!(document["verdict"]["rung"].is_null());
    assert_eq!(document["verdict"]["exit_code"], 0);
}

// ─────────────────────────────────────────────────────────────────────
// the binary — the process claims, and the third arm
// ─────────────────────────────────────────────────────────────────────

struct TestDir(PathBuf);

impl TestDir {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "antseal-cli-verify-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("create test dir");
        TestDir(dir)
    }
    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Run the binary in a directory with **no vault**, with stdin closed — so a
/// prompt would be a hang, not a question.
fn run_binary(dir: &TestDir, args: &[&str]) -> std::process::Output {
    spawn::antseal()
        .args(args)
        .env("ANTSEAL_DIR", dir.path().join("no-vault-here"))
        .env_remove("RUST_LOG")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn antseal")
}

fn write_bundle(dir: &TestDir, name: &str, bytes: &[u8]) -> PathBuf {
    let path = dir.path().join(name);
    std::fs::write(&path, bytes).expect("write bundle");
    path
}

/// **The third arm, end to end**: a nonzero verdict still emits its `--json`
/// result. This is the row D69 §3 R1 exists for, and the shape nothing in the
/// tree exercised before U30.
#[test]
fn a_nonzero_verdict_still_emits_its_json_result() {
    let dir = TestDir::new("third-arm");
    let path = write_bundle(&dir, "unanchored.sealproof", &unanchored_bundle());
    let out = run_binary(&dir, &["--json", "verify", path.to_str().expect("utf-8")]);

    assert_eq!(out.status.code(), Some(43), "the UNANCHORED rung");

    let stdout = String::from_utf8(out.stdout).expect("utf-8 stdout");
    let document: serde_json::Value =
        serde_json::from_str(stdout.trim_end_matches('\n')).expect("exactly one JSON document");

    assert_eq!(
        document["ok"], true,
        "`ok` means a result document is present, not that the code is 0"
    );
    assert_eq!(document["v"], serde_json::json!(ENVELOPE_VERSION));
    assert_eq!(document["command"], "verify");
    assert!(
        document.get("error").is_none(),
        "this is a success envelope"
    );
    assert!(
        !document["result"]["report"].is_null(),
        "the report is there"
    );

    // D69 §3 R7's equality, over the process's own status.
    assert_eq!(
        document["result"]["verdict"]["exit_code"],
        serde_json::json!(43)
    );
    assert_eq!(document["result"]["verdict"]["rung"], "verify-unanchored");

    // D51 invariant 1: every human byte went to stderr.
    let stderr = String::from_utf8(out.stderr).expect("utf-8 stderr");
    assert!(
        stderr.contains(wording::UNANCHORED_BANNER),
        "the human report belongs on stderr under --json: {stderr}"
    );
}

/// The tier-A carriage claim, asserted over the **binary's own stdout**: the
/// bytes a consumer receives contain `to_canonical_json()`'s bytes
/// contiguously.
#[test]
fn the_binarys_stdout_contains_the_canonical_report_bytes() {
    let dir = TestDir::new("verbatim");
    let bytes = unanchored_bundle();
    let path = write_bundle(&dir, "b.sealproof", &bytes);
    let out = run_binary(&dir, &["--json", "verify", path.to_str().expect("utf-8")]);

    let canonical = verify_offline_run(&bytes).outcome().report_bytes().to_vec();
    assert!(
        out.stdout.windows(canonical.len()).any(|w| w == canonical),
        "the report member must reach stdout byte-for-byte"
    );

    // D65 §4: the two versions are independent axes, and neither is derived
    // from the other. Both are read from their own constant.
    let document: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("one JSON document");
    assert_eq!(document["v"], serde_json::json!(ENVELOPE_VERSION));
    assert_eq!(
        document["result"]["report"]["report_version"],
        serde_json::json!(REPORT_VERSION)
    );
}

/// `verify` needs no vault and never prompts — on a machine that has none,
/// with stdin closed, in plain mode.
///
/// # What this check cannot see, and why it is kept anyway (U77)
///
/// **Kept, not replaced.** It catches a real and different failure: the
/// vault vocabulary leaking into a run that has no vault. But it does not
/// establish the never-prompts claim, and it fails to twice over:
///
/// 1. **Three English words are the whole guard.** A prompt reading
///    *"Enter word 1 of 24"*, *"Key?"* or *"Type the 24 words from your
///    card"* contains none of `passphrase`, `Passphrase` or
///    `no vault exists`, and passes here. Nothing can slip past it *today*
///    only because no key-entry vocabulary exists in the product — D134
///    rules that a paper-key `reveal` lock mode and an unlock surface are
///    coming, which is why the structural guard below was written before
///    that vocabulary exists rather than after.
/// 2. **Prompting is invisible here as a behaviour.** [`run_binary`] closes
///    stdin and collects output *after* the process exits, so a binary that
///    blocked on a read would present as a **hang** — the harness's timeout
///    — and never as a failed assertion. Neither this test nor the
///    structural one closes that gap; the structural one removes the
///    *source* of such a read instead of detecting the block.
///
/// The structural half is
/// [`verifys_handler_reaches_no_prompt_capable_call_site_over_a_closed_scan`].
#[test]
fn verify_runs_on_a_vault_less_machine_without_prompting() {
    let dir = TestDir::new("vault-less");
    let path = write_bundle(&dir, "b.sealproof", &unanchored_bundle());
    let out = run_binary(&dir, &["verify", path.to_str().expect("utf-8")]);

    assert_eq!(out.status.code(), Some(43));
    let stdout = String::from_utf8(out.stdout).expect("utf-8");
    assert!(
        stdout.contains(wording::UNANCHORED_BANNER),
        "plain mode renders on stdout: {stdout}"
    );
    let stderr = String::from_utf8(out.stderr).expect("utf-8");
    for forbidden in ["passphrase", "Passphrase", "no vault exists"] {
        assert!(
            !stdout.contains(forbidden) && !stderr.contains(forbidden),
            "`verify` must not mention the vault: {forbidden}"
        );
    }
}

/// **U77 — the structural half of *"`verify` never prompts"*: a closed scan
/// over the tree's own source text.**
///
/// The output check above is a substring search over three English words.
/// This one is a source-shape assertion in the idiom
/// `crates/antseal-cli/tests/reveal_consent.rs:651`
/// (`the_reveal_consent_gate_has_exactly_one_production_caller`) established
/// for `reveal`'s consent gate: a closed, exhaustively enumerated table
/// scanned over production source, with the searched-for tokens assembled by
/// `concat!` so the scanner cannot match itself.
///
/// # Why now, before the vocabulary exists
///
/// D134 rules that a paper-key `reveal` lock mode and an unlock surface are
/// coming. **No key-entry vocabulary exists in the product today**, so
/// nothing can slip past the output check yet — and that is precisely why
/// this lands now. After the vocabulary exists, strengthening the guard is a
/// change made against a live counterexample; before it exists, it is a rule
/// made in advance (U77's Accept, fourth row).
///
/// # What is asserted, and why each part is closed
///
/// 1. **The device inventory.** The five primitives below are the only ways
///    a Rust program in this workspace can put a question to a human: the
///    no-echo terminal crate, the process's own stdin, std's tty detection,
///    the controlling terminal by path, and a blocking line read. They occur
///    in production source **exactly** as [`DEVICE_SITES`] enumerates —
///    nine rows over six files, exact counts, no "at most" and no
///    "contains". A new prompt-capable call anywhere under any crate's
///    `src/` reddens as a stray or as a moved count.
/// 2. **`verify`'s own handler body is zero.** Counted over the body
///    extracted from `commands.rs` by brace-matching, for every device
///    primitive **and** every in-crate seam. This has to be body-level and
///    not file-level: `commands.rs` names the passphrase collector nine
///    times: eight handler bodies plus the definition (`restore`'s
///    `ant-backend` arm became the eighth with D170). The file `verify`
///    lives in is one of the most prompt-dense in the crate.
/// 3. **The handlers that do collect a secret are an enumerated set of
///    eight, and `verify` is not among them** — with an *accounting*
///    identity (`file total == sum over spans + definition lines`) that
///    reddens if the span extractor ever stops seeing a function, rather
///    than silently reporting zero for a body it failed to find.
/// 4. **`verify`'s one-hop reach is a closed set**: four `crate::` modules
///    and one local helper. A fifth module named in the body reddens until
///    it is listed and classified. Each of the four is then pinned at
///    **zero** primitives and **zero** seams, and its file asserted
///    non-trivial in size — so the zero is a measured zero and not an
///    unread file.
/// 5. **The dependency surface is closed**: `antseal-cli`'s
///    `[dependencies]` is exactly nineteen crates, of which `rpassword` is
///    the only terminal-input edge. A brand-new prompting crate cannot
///    arrive without appearing here, which is what stops the vocabulary
///    list above from being open-ended.
/// 6. **The red direction is committed, not merely claimed.** Both scanners
///    are run a second time over a *planted* tree carrying an interactive
///    read inside a `fn verify` body, and each must return a message naming
///    the planted site. A guard that has never been watched fail is this
///    project's dominant defect class; this one fails on every run, in a
///    controlled place.
///
/// # What this test cannot see
///
/// - **It is one hop, not transitive, and deliberately so.** Measured
///   2026-08-18: the transitive `crate::…` module closure from `verify`'s
///   four reach files covers **28** of `antseal-cli`'s modules — including
///   `passphrase`, `init` and `seal_consent` — because error types and
///   doc-links cross-reference the whole crate. A transitive assertion would
///   therefore be unpassable rather than strict, and the honest guard is the
///   tree-wide inventory (1) plus the one-hop closure (4), not a reachability
///   proof.
/// - **It is text, not types.** A prompt reached through a trait object
///   whose implementation lives in a listed file is still counted at the
///   listed file — the count moves — but a prompt built entirely out of
///   tokens not in the vocabulary, from a dependency already on the list,
///   would not be seen.
/// - **It cannot see a hang.** Neither can
///   [`verify_runs_on_a_vault_less_machine_without_prompting`]: `run_binary`
///   closes stdin and collects output *after* exit, so a binary blocking on
///   a read presents as a timeout, never as a failed assertion. This test
///   removes the *source* of such a read rather than detecting the block,
///   and nothing in this file closes the behavioural gap.
#[test]
fn verifys_handler_reaches_no_prompt_capable_call_site_over_a_closed_scan() {
    use std::collections::{BTreeMap, BTreeSet};

    // ── the vocabulary ──────────────────────────────────────────────
    //
    // Every token is assembled with `concat!` so this file does not
    // contain the strings it hunts for. The scan below only walks a
    // crate's `src/`, and this file is not under one — but a scanner that
    // would match itself if the filter were ever widened is a scanner
    // nobody trusts on sight, and self-exemption by construction is what
    // U77 asks for over an exclusion the next refactor breaks
    // (`reveal_consent.rs:679`'s own precaution, adopted).

    /// `(token, what it is)` — the closed vocabulary of *device*-level
    /// prompting: the irreducible ways to ask a human a question.
    const DEVICE: [(&str, &str); 5] = [
        (
            concat!("rpassword", "::"),
            "the pinned no-echo terminal reader (U7/D41)",
        ),
        (
            concat!("std::io::", "stdin"),
            "the process's own standard input",
        ),
        (concat!("Is", "Terminal"), "std's tty detection"),
        (
            concat!("/dev/", "tty"),
            "the controlling terminal, by path (D51's read/write device)",
        ),
        (
            concat!("read_line", "("),
            "a blocking line read from any reader",
        ),
    ];

    /// `(token, what it is)` — the closed vocabulary of this crate's own
    /// prompting *seams*: the named entry points that end in a question.
    /// A handler reaches a prompt through one of these or through a device
    /// primitive; there is no third way in this crate today.
    const SEAM: [(&str, &str); 4] = [
        (
            concat!("collect_passphrase", "("),
            "`commands.rs`'s passphrase collector (U7)",
        ),
        (
            concat!("ask_on_tty", "("),
            "the one device-level consent prompt, shared by U14 and U29",
        ),
        (
            concat!("collect_from_prompt", "("),
            "the double-entry prompt loop behind the collector",
        ),
        (concat!("prompt_password", "("), "the no-echo read itself"),
    ];

    /// `(primitive index into `DEVICE`, file, exact count, warrant)` — the
    /// **closed** inventory of every device-level prompting token in
    /// production source, tree-wide.
    ///
    /// Counts are over the whole file with line comments removed, including
    /// any `#[cfg(test)]` module living in it: over-counting is the safe
    /// direction for a guard, and every occurrence has to earn a row here.
    const DEVICE_SITES: [(usize, &str, usize, &str); 9] = [
        (
            0,
            "crates/antseal-cli/src/init.rs",
            1,
            "U11's guided setup: the one no-echo read at vault creation",
        ),
        (
            0,
            "crates/antseal-cli/src/passphrase.rs",
            1,
            "U7's production prompt seam (`TtyPrompt::read_secret_line`)",
        ),
        (
            1,
            "crates/antseal-cli/src/init.rs",
            2,
            "U11's two confirm-line reads",
        ),
        (
            1,
            "crates/antseal-cli/src/passphrase.rs",
            2,
            "D51's isatty detection, and `--passphrase-fd 0`'s slurp",
        ),
        (
            1,
            "crates/antseal-cli/src/pipeline/reveal.rs",
            1,
            "NOT a call: R16's in-file scanner plants this token as a string \
             literal to prove its own red direction",
        ),
        (
            2,
            "crates/antseal-cli/src/passphrase.rs",
            1,
            "the `IsTerminal` import behind D51's detection rule",
        ),
        (
            3,
            "crates/antseal-cli/src/seal_consent.rs",
            2,
            "`ask_on_tty`: the device open, and the same path in its error \
             context string",
        ),
        (
            4,
            "crates/antseal-cli/src/init.rs",
            2,
            "U11's two confirm-line reads (the read half of row three)",
        ),
        (
            4,
            "crates/antseal-cli/src/seal_consent.rs",
            1,
            "`ask_on_tty`'s single answer read",
        ),
    ];

    /// The `crate::…` modules `verify`'s body names — the closed one-hop
    /// reach. Each is pinned at zero primitives and zero seams below.
    ///
    /// **D170 wired `--live` without widening this set.** The feature build's
    /// network resolution, runtime and wallet-less reader are all reached
    /// through `backend`, deliberately: `seal`'s network resolver lives in
    /// `devnet_env`, and naming that here would have put a module on the reach
    /// list that nothing had ever pinned at zero.
    const REACH_MODULES: [(&str, &str); 4] = [
        (
            "backend",
            "U36's storage-backend seam: `--live` refuses here in a build with no backend, and \
             in a build with one resolves its network and connects the wallet-less reader here \
             (D170)",
        ),
        ("config", "the config file, for `--online` endpoints only"),
        (
            "verify_host",
            "R21's pure accessor over collected probe data",
        ),
        (
            "verify_out",
            "the run, its rendering and its `--json` document",
        ),
    ];

    /// The `commands.rs`-local helpers `verify`'s body calls.
    const REACH_LOCALS: [(&str, &str); 1] =
        [("now_unix_secs", "the clock, read once for the whole run")];

    /// The handlers in `commands.rs` that **do** reach a prompt. `verify` is
    /// not one, and this is the list that says so by exhaustion rather than
    /// by absence of three English words.
    const PROMPTING_HANDLERS: [(&str, &str); 8] = [
        ("list", "opens the vault to resolve work ids"),
        (
            "restore",
            "the `ant-backend` arm (D170): opens the vault for the work's key, paths and \
             recorded network; the arm with no backend refuses before it and prompts for nothing",
        ),
        (
            "reveal",
            "opens the vault, then asks U29's consent question",
        ),
        (
            "seal_over_backend",
            "the `ant-backend` arm: lock, then passphrase, then network",
        ),
        ("show", "opens the vault"),
        ("status", "opens the vault"),
        ("vault_export", "D47's passphrase proof before the backup"),
        ("vault_import", "the destructive-overwrite confirm"),
    ];

    /// `antseal-cli`'s production dependency surface, closed. `rpassword` is
    /// the only terminal-input edge; a new prompting crate cannot arrive
    /// without failing here first, which is what keeps `DEVICE` from being
    /// an open-ended guess at tomorrow's vocabulary.
    const CLI_DEPENDENCIES: [&str; 19] = [
        "antseal-anchor",
        "antseal-core",
        "antseal-net",
        "argon2",
        "blake2",
        "chacha20poly1305",
        "clap",
        "getrandom",
        "hkdf",
        "rand_core",
        "rpassword",
        "scrypt",
        "serde_json",
        "sha2",
        "thiserror",
        "tokio",
        "tracing",
        "tracing-subscriber",
        "zeroize",
    ];

    const COMMANDS: &str = "crates/antseal-cli/src/commands.rs";
    const HANDLER: &str = "verify";
    const CONTROL_HANDLER: &str = "vault_export";

    // ── the scanner ─────────────────────────────────────────────────

    /// Line comments removed, so a doc reword cannot redden a structural
    /// guard. `://` is left alone: a URL inside a string literal must not
    /// truncate the code after it, because truncation is the *unsafe*
    /// direction — it would hide a token rather than invent one.
    fn code_only(text: &str) -> String {
        let mut out = String::with_capacity(text.len());
        for line in text.lines() {
            let bytes = line.as_bytes();
            let mut cut = line.len();
            let mut index = 0usize;
            while index + 1 < bytes.len() {
                if bytes[index] == b'/'
                    && bytes[index + 1] == b'/'
                    && (index == 0 || bytes[index - 1] != b':')
                {
                    cut = index;
                    break;
                }
                index += 1;
            }
            out.push_str(&line[..cut]);
            out.push('\n');
        }
        out
    }

    fn collect(dir: &Path, out: &mut Vec<PathBuf>) {
        let entries =
            std::fs::read_dir(dir).unwrap_or_else(|e| panic!("cannot list {}: {e}", dir.display()));
        for entry in entries {
            let path = entry
                .unwrap_or_else(|e| panic!("cannot read an entry under {}: {e}", dir.display()))
                .path();
            let skip = path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n == "target" || n == ".git");
            if skip {
                continue;
            }
            if path.is_dir() {
                collect(&path, out);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                out.push(path);
            }
        }
    }

    /// Production source is everything under a crate's `src/`. There is no
    /// exclusion list, on purpose: an exclusion is what the next refactor
    /// breaks, and U77's Accept asks for self-exemption by construction
    /// instead.
    fn is_production_source(relative: &str) -> bool {
        relative.contains("/src/")
    }

    /// `((primitive index, relative path) -> count)`, plus the number of
    /// `.rs` files walked so a broken walker cannot pass as a clean tree.
    fn scan(root: &Path) -> (BTreeMap<(usize, String), usize>, usize) {
        let mut files = Vec::new();
        collect(root, &mut files);
        let mut found: BTreeMap<(usize, String), usize> = BTreeMap::new();
        for file in &files {
            let relative = file
                .strip_prefix(root)
                .expect("every scanned file is under the root")
                .to_string_lossy()
                .replace('\\', "/");
            if !is_production_source(&relative) {
                continue;
            }
            let text = code_only(
                &std::fs::read_to_string(file)
                    .unwrap_or_else(|e| panic!("cannot read {}: {e}", file.display())),
            );
            for (index, &(token, _)) in DEVICE.iter().enumerate() {
                let count = text.matches(token).count();
                if count > 0 {
                    found.insert((index, relative.clone()), count);
                }
            }
        }
        (found, files.len())
    }

    /// The inventory verdict as a **message**, so the red direction can be
    /// asserted on what it says rather than on the fact that something
    /// panicked.
    fn check_inventory(found: &BTreeMap<(usize, String), usize>) -> Result<(), String> {
        let mut listed: BTreeMap<(usize, String), (usize, &str)> = BTreeMap::new();
        for (primitive, file, count, why) in DEVICE_SITES {
            listed.insert((primitive, file.to_owned()), (count, why));
        }
        for ((index, file), count) in found {
            let (token, what) = DEVICE[*index];
            match listed.get(&(*index, file.clone())) {
                None => {
                    return Err(format!(
                        "`{file}` names the prompt-capable primitive `{token}` ({what}) \
                         {count} time(s) and is not on U77's closed list. `verify` is the \
                         key-free third-party command (MVP-SPEC.md line 38) and its \
                         never-prompts claim is structural, not a matter of which English \
                         words reach stdout. Add the site here with its warrant — and if it \
                         is reachable from `commands::verify`, do not add the site (U77)."
                    ));
                }
                Some((expected, why)) if expected != count => {
                    return Err(format!(
                        "`{file}` names `{token}` ({what}) {count} time(s), not {expected}. \
                         It is on U77's closed list as: {why}. A count that moved is a \
                         prompting site nobody ruled, or a listed site that stopped \
                         prompting."
                    ));
                }
                Some(_) => {}
            }
        }
        for ((index, file), (expected, why)) in &listed {
            let seen = found.get(&(*index, file.clone())).copied().unwrap_or(0);
            if seen != *expected {
                let (token, _) = DEVICE[*index];
                return Err(format!(
                    "`{file}` names `{token}` {seen} time(s), not the {expected} U77 \
                     enumerated as: {why}. Either the site moved, or the file did."
                ));
            }
        }
        Ok(())
    }

    /// Every top-level `fn` in `code`, as `(name, body-with-braces span)`.
    ///
    /// Top-level means column zero. A `fn` inside an `impl` block or nested
    /// in another body is indented and gets no span of its own — which is
    /// safe rather than lax, because the accounting identity below refuses
    /// any occurrence that lands in no span and on no definition line.
    fn top_level_fns(code: &str) -> Vec<(String, usize, usize)> {
        let mut out = Vec::new();
        let mut offset = 0usize;
        for line in code.split_inclusive('\n') {
            let start = offset;
            offset += line.len();
            if line.starts_with(char::is_whitespace) {
                continue;
            }
            let mut rest = line;
            for prefix in ["pub(crate) ", "pub(super) ", "pub "] {
                if let Some(stripped) = rest.strip_prefix(prefix) {
                    rest = stripped;
                    break;
                }
            }
            if let Some(stripped) = rest.strip_prefix("async ") {
                rest = stripped;
            }
            let Some(after) = rest.strip_prefix("fn ") else {
                continue;
            };
            let name: String = after
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            if name.is_empty() {
                continue;
            }
            let Some(relative_open) = code[start..].find('{') else {
                continue;
            };
            let open = start + relative_open;
            let mut depth = 0usize;
            let mut close = None;
            for (index, character) in code[open..].char_indices() {
                match character {
                    '{' => depth += 1,
                    '}' => {
                        depth -= 1;
                        if depth == 0 {
                            close = Some(open + index + 1);
                            break;
                        }
                    }
                    _ => {}
                }
            }
            if let Some(close) = close {
                out.push((name, open, close));
            }
        }
        out
    }

    /// The spans of every top-level `fn` called `wanted`. Two is normal:
    /// `seal_over_backend` has one definition per `#[cfg]` arm.
    fn spans_named<'a>(
        spans: &'a [(String, usize, usize)],
        wanted: &str,
    ) -> Vec<&'a (String, usize, usize)> {
        spans.iter().filter(|(name, _, _)| name == wanted).collect()
    }

    /// The verdict on one handler body, as a **message**.
    fn check_handler_body(handler: &str, body: &str) -> Result<(), String> {
        for &(token, what) in DEVICE.iter().chain(SEAM.iter()) {
            let count = body.matches(token).count();
            if count != 0 {
                return Err(format!(
                    "`commands::{handler}`'s own body names `{token}` ({what}) {count} \
                     time(s). It must name it zero times: `{handler}` is the key-free \
                     third-party entry point (MVP-SPEC.md line 38, D99 R2 — it opens no \
                     vault and arms no upgrade hook), and a third party has nothing to \
                     type. This is U77's guard, and it is deliberately structural: the \
                     output check in this file would pass a prompt reading \
                     \"Enter word 1 of 24\"."
                ));
            }
        }
        Ok(())
    }

    /// The `crate::<module>` first segments named in `body`.
    fn crate_modules(body: &str) -> BTreeSet<String> {
        let prefix = concat!("crate", "::");
        let mut out = BTreeSet::new();
        for (offset, _) in body.match_indices(prefix) {
            let name: String = body[offset + prefix.len()..]
                .chars()
                .take_while(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == '_')
                .collect();
            if !name.is_empty() {
                out.insert(name);
            }
        }
        out
    }

    // ── the comment stripper, proven in both directions ─────────────
    //
    // A stripper that returned "" would make every count below zero and
    // every assertion vacuous. That is this project's dominant defect
    // class, so it is checked here rather than trusted.
    let stripped = code_only("let a = 1; // a note about a\n");
    assert!(
        stripped.contains("let a = 1;"),
        "code survives: {stripped:?}"
    );
    assert!(
        !stripped.contains("note"),
        "the comment does not: {stripped:?}"
    );
    let url = code_only("let u = \"https://example.invalid/x\"; let b = 2;\n");
    assert!(
        url.contains("let b = 2;"),
        "`://` must not truncate the code after it: {url:?}"
    );

    // ── 1. the device inventory, tree-wide and closed ───────────────

    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("the crate sits two levels under the workspace root")
        .to_path_buf();
    let (found, walked) = scan(&root);
    assert!(
        walked > 300,
        "the walker found only {walked} `.rs` files — it is not reaching the tree, and \
         every count below would be a vacuous zero"
    );
    assert!(
        found.len() >= DEVICE_SITES.len(),
        "the scan found {} sites for {} enumerated rows — a scanner that finds nothing \
         proves nothing",
        found.len(),
        DEVICE_SITES.len()
    );
    if let Err(message) = check_inventory(&found) {
        panic!("{message}");
    }

    // ── 2/3. `commands.rs`: spans, accounting, and the two verdicts ──

    let commands_path = root.join(COMMANDS);
    let commands = code_only(
        &std::fs::read_to_string(&commands_path)
            .unwrap_or_else(|e| panic!("cannot read {}: {e}", commands_path.display())),
    );
    let spans = top_level_fns(&commands);

    // The extractor's own controls. Without these, a brace-matcher that
    // returned empty bodies would make every "names it zero times" below
    // true for the wrong reason.
    let verify_spans = spans_named(&spans, HANDLER);
    assert_eq!(
        verify_spans.len(),
        1,
        "exactly one top-level `fn {HANDLER}` must be found in {COMMANDS}; the extractor \
         found {} — it is not seeing the handler it is about to clear",
        verify_spans.len()
    );
    assert_eq!(
        spans_named(&spans, "seal_over_backend").len(),
        2,
        "both `#[cfg]` arms of `seal_over_backend` must be seen, or the extractor is \
         skipping definitions"
    );
    // D170: `restore` is the second handler split per build, and the one whose
    // arms disagree about prompting — so an extractor that saw only one of
    // them would classify it by whichever it happened to find.
    assert_eq!(
        spans_named(&spans, "restore").len(),
        2,
        "both `#[cfg]` arms of `restore` must be seen: one prompts and one does not"
    );
    let control = spans_named(&spans, CONTROL_HANDLER);
    assert_eq!(control.len(), 1, "one `fn {CONTROL_HANDLER}`");
    let (_, control_open, control_close) = control[0];
    assert!(
        check_handler_body(CONTROL_HANDLER, &commands[*control_open..*control_close]).is_err(),
        "POSITIVE CONTROL: `{CONTROL_HANDLER}` collects a passphrase (D47's proof before \
         the backup), so the body check must reject it. If this passes, the extractor is \
         handing out empty bodies and every clearance below is worthless."
    );

    // The accounting identity: every occurrence in the file lands either
    // inside exactly one span or on the token's own `fn` definition line.
    for &(token, what) in DEVICE.iter().chain(SEAM.iter()) {
        let total = commands.matches(token).count();
        let inside: usize = spans
            .iter()
            .map(|(_, open, close)| commands[*open..*close].matches(token).count())
            .sum();
        let definitions = commands
            .matches(&format!("fn {}", token.trim_end_matches('(')))
            .count();
        assert_eq!(
            total,
            inside + definitions,
            "{COMMANDS} names `{token}` ({what}) {total} time(s), but {inside} fall inside \
             a top-level `fn` span and {definitions} on a definition line. An unaccounted \
             occurrence means the span extractor missed a function — and a missed function \
             is a prompt this test cannot see."
        );
    }

    let (_, verify_open, verify_close) = verify_spans[0];
    let verify_body = &commands[*verify_open..*verify_close];
    assert!(
        verify_body.len() > 400,
        "`{HANDLER}`'s extracted body is {} bytes — too small to be the handler, so its \
         zero counts would be vacuous",
        verify_body.len()
    );
    if let Err(message) = check_handler_body(HANDLER, verify_body) {
        panic!("{message}");
    }

    // The set of handlers that DO reach a prompt, by exhaustion.
    let mut prompting: BTreeSet<&str> = BTreeSet::new();
    for (name, open, close) in &spans {
        if check_handler_body(name, &commands[*open..*close]).is_err() {
            prompting.insert(name.as_str());
        }
    }
    let expected_prompting: BTreeSet<&str> =
        PROMPTING_HANDLERS.iter().map(|(name, _)| *name).collect();
    assert_eq!(
        prompting, expected_prompting,
        "the handlers in {COMMANDS} that reach a prompt are a closed set (U77). A name \
         that appeared must be classified here; a name that vanished means a handler \
         stopped asking. `{HANDLER}` must never be among them."
    );
    assert!(
        !prompting.contains(HANDLER),
        "`{HANDLER}` collects a secret — the whole of U30's third-party claim is that it \
         does not"
    );

    // ── 4. the one-hop reach, closed and pinned at zero ─────────────

    let reached = crate_modules(verify_body);
    let expected_reach: BTreeSet<String> = REACH_MODULES
        .iter()
        .map(|(name, _)| (*name).to_owned())
        .collect();
    assert_eq!(
        reached, expected_reach,
        "`{HANDLER}`'s body names a different set of `crate::` modules than U77 \
         enumerated. Every module it reaches is pinned at zero prompt-capable tokens \
         below; a module that is not on the list has never been checked. Classify it \
         here, or do not reach it."
    );
    let locals: BTreeSet<&str> = spans
        .iter()
        .map(|(name, _, _)| name.as_str())
        .filter(|name| *name != HANDLER && verify_body.contains(&format!("{name}(")))
        .collect();
    let expected_locals: BTreeSet<&str> = REACH_LOCALS.iter().map(|(name, _)| *name).collect();
    assert_eq!(
        locals, expected_locals,
        "`{HANDLER}`'s body calls a different set of {COMMANDS}-local helpers than U77 \
         enumerated. `collect_passphrase` is one of those helpers, which is exactly why \
         this list is closed rather than open."
    );

    for (module, why) in REACH_MODULES {
        let direct = root.join(format!("crates/antseal-cli/src/{module}.rs"));
        let nested = root.join(format!("crates/antseal-cli/src/{module}/mod.rs"));
        let path = if direct.is_file() { direct } else { nested };
        let text = code_only(
            &std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display())),
        );
        assert!(
            text.len() > 500,
            "`{module}` ({why}) read as {} bytes — a zero over an unread file is not a \
             measured zero",
            text.len()
        );
        for &(token, what) in DEVICE.iter().chain(SEAM.iter()) {
            assert_eq!(
                text.matches(token).count(),
                0,
                "`{module}.rs` ({why}) names `{token}` ({what}). It is on `{HANDLER}`'s \
                 one-hop reach list, and U77 pins every file on that list at zero."
            );
        }
    }

    // ── 5. the dependency surface, closed ───────────────────────────

    let manifest_path = root.join("crates/antseal-cli/Cargo.toml");
    let manifest = std::fs::read_to_string(&manifest_path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", manifest_path.display()));
    let section = manifest
        .split("\n[dependencies]\n")
        .nth(1)
        .expect("`crates/antseal-cli/Cargo.toml` has a `[dependencies]` table")
        .split("\n[")
        .next()
        .expect("a section ends at the next table header");
    let declared: BTreeSet<&str> = section
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| {
            line.split([' ', '.', '='])
                .next()
                .expect("a dependency line starts with its name")
        })
        .collect();
    assert!(
        declared.len() > 10,
        "the manifest parser found only {} dependencies — it is not reading the table, so \
         the closure below would be vacuous: {declared:?}",
        declared.len()
    );
    assert!(
        declared.contains("rpassword"),
        "POSITIVE CONTROL: the one terminal-input dependency must be found by the parser"
    );
    let expected_dependencies: BTreeSet<&str> = CLI_DEPENDENCIES.iter().copied().collect();
    assert_eq!(
        declared, expected_dependencies,
        "`antseal-cli`'s production dependency surface changed. U77 closes it because the \
         `DEVICE` vocabulary above can only enumerate prompting APIs that exist: a new \
         crate capable of reading a terminal would be invisible to every token in this \
         test. Classify the new edge — prompt-capable or not — and add it here."
    );

    // ── 6. the red direction, planted and asserted BY MESSAGE ───────
    //
    // U77's whole point. A prompt-capable read is wired into a `fn verify`
    // body in a planted tree, and each scanner must NAME the planted site.
    // This runs on every invocation, so the guard is never merely believed
    // to be able to fail.

    let planted_root = TestDir::new("u77-planted-prompt");
    let planted_src = planted_root.path().join("crates/antseal-cli/src");
    std::fs::create_dir_all(&planted_src).expect("create the planted src tree");
    let planted_source = format!(
        "pub(crate) fn {HANDLER}(bundle: &Path) -> Result<(), CliError> {{\n    \
         let mut line = String::new();\n    \
         let _ = {stdin}().lock().{read}&mut line);\n    \
         let _ = bundle;\n    Ok(())\n}}\n",
        stdin = DEVICE[1].0,
        read = DEVICE[4].0,
    );
    std::fs::write(planted_src.join("commands.rs"), &planted_source).expect("plant");

    let (planted_found, planted_walked) = scan(planted_root.path());
    assert_eq!(
        planted_walked, 1,
        "the planted tree holds exactly one `.rs` file"
    );
    // The scanner must SEE the plant, not merely error about the real rows
    // it cannot find in a synthetic tree. Measured 2026-08-18: without this
    // line a plant carrying no prompt token at all still produced an `Err`
    // (about `init.rs`), so `expect_err` on its own was a control that could
    // not fail. It is the message assertions below, and this key, that carry
    // the proof.
    assert_eq!(
        planted_found
            .get(&(1, "crates/antseal-cli/src/commands.rs".to_owned()))
            .copied(),
        Some(1),
        "the scanner must see the planted `{}` at the planted site: {planted_found:?}",
        DEVICE[1].0
    );
    let inventory_message = check_inventory(&planted_found)
        .expect_err("the inventory scan must reject a planted prompt-capable call");
    assert!(
        inventory_message.contains("src/commands.rs"),
        "the inventory's rejection must NAME the planted site: {inventory_message}"
    );
    assert!(
        inventory_message.contains(DEVICE[1].0),
        "and the primitive it saw: {inventory_message}"
    );

    let planted_spans = top_level_fns(&planted_source);
    let planted_verify = spans_named(&planted_spans, HANDLER);
    assert_eq!(
        planted_verify.len(),
        1,
        "the plant defines one `fn {HANDLER}`"
    );
    let (_, planted_open, planted_close) = planted_verify[0];
    let body_message = check_handler_body(HANDLER, &planted_source[*planted_open..*planted_close])
        .expect_err("the body check must reject an interactive read wired into `verify`");
    assert!(
        body_message.contains(HANDLER),
        "the body check's rejection must NAME the handler: {body_message}"
    );
    assert!(
        body_message.contains(DEVICE[1].0),
        "and the primitive it saw: {body_message}"
    );
}

/// A tampered bundle through the binary: nonzero, the error envelope, and the
/// rejection code in the message.
#[test]
fn a_tampered_bundle_through_the_binary_is_forty_with_an_error_envelope() {
    let dir = TestDir::new("tampered");
    let path = write_bundle(&dir, "t.sealproof", &tampered_bundle());
    let out = run_binary(&dir, &["--json", "verify", path.to_str().expect("utf-8")]);

    assert_eq!(out.status.code(), Some(40));
    let document: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("one JSON document");
    assert_eq!(document["ok"], false, "no report exists for a rejection");
    assert!(document.get("result").is_none());
    assert_eq!(document["error"]["class"], "verify-bundle-rejected");
    assert_eq!(document["error"]["exit_code"], 40);
}

/// A missing bundle file is `io-error` (4) — a *process* outcome, not a
/// verdict: nothing was verified.
#[test]
fn a_missing_bundle_file_is_the_io_class() {
    let dir = TestDir::new("missing");
    let out = run_binary(&dir, &["--json", "verify", "definitely-not-here.sealproof"]);

    assert_eq!(out.status.code(), Some(4));
    let document: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("one JSON document");
    assert_eq!(document["error"]["class"], "io-error");
}

/// `--online` and `--live` are **off by default**: a plain run computes
/// neither sibling.
#[test]
fn the_two_advisory_modes_are_off_by_default() {
    let run = verify_offline_run(&unanchored_bundle());
    assert!(run.outcome().overlay().is_none());
    assert!(run.outcome().live().is_none());

    let document: serde_json::Value =
        serde_json::from_str(&run.json().expect("renders")).expect("one JSON object");
    assert!(document["overlay"].is_null());
    assert!(document["live"].is_null());
}

/// `--live` in a build with no storage backend refuses at the U36 seam, in
/// the transient network class (23), **before** verification — D69 §3 R6's
/// one carve-out, and a process outcome rather than a verdict.
///
/// Its twins for a build **with** a backend are the two
/// `live_in_a_build_with_a_backend_…` rows below: that build never produces
/// this refusal (D170 §2 R2).
#[cfg(not(feature = "ant-backend"))]
#[test]
fn live_without_a_compiled_backend_refuses_at_the_seam() {
    let dir = TestDir::new("live-seam");
    let path = write_bundle(&dir, "b.sealproof", &unanchored_bundle());
    let out = run_binary(
        &dir,
        &["--json", "verify", path.to_str().expect("utf-8"), "--live"],
    );

    assert_eq!(
        out.status.code(),
        Some(23),
        "network-failure, not a verdict"
    );
    let document: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("one JSON document");
    assert_eq!(document["error"]["class"], "network-failure");
    let message = document["error"]["message"]
        .as_str()
        .expect("a message")
        .to_owned();
    assert!(
        message.contains("verify"),
        "the refusal names the command: {message}"
    );
}

/// `connect_read_only`'s one trace, emitted inside its future — so only when
/// a connection is actually attempted, which is what lets a process-level row
/// tell *never connected* from *connected and failed*.
#[cfg(feature = "ant-backend")]
const READER_CONNECT_TRACE: &str = "connecting the read-only reader";

/// A devnet definition that reaches **nothing**: its one bootstrap peer is a
/// loopback UDP port bound and released a moment ago, its payment RPC a
/// loopback TCP port likewise — D170 §2 R7's negative-control shape with no
/// devnet anywhere. `restore_output.rs` carries the same helper for the same
/// reason; `common` is not this lane's to widen.
///
/// NON-SECRET: no key line (a walletless export), and Anvil's well-known
/// deterministic contract addresses.
#[cfg(feature = "ant-backend")]
fn dead_devnet_export(dir: &TestDir) -> PathBuf {
    let udp = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind a loopback probe socket");
    let bootstrap = udp.local_addr().expect("the probe's address");
    drop(udp);
    let tcp = std::net::TcpListener::bind("127.0.0.1:0").expect("bind a loopback probe listener");
    let rpc_port = tcp.local_addr().expect("the probe's address").port();
    drop(tcp);
    let text = format!(
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
        data = dir.path().display(),
        pid = std::process::id(),
    );
    let path = dir.path().join("dead-devnet.env");
    std::fs::write(&path, text).expect("write the dead devnet export");
    path
}

/// [`run_binary`], with the devnet definition this invocation may see
/// (`None` strips any the developer's shell exported) and the backend's
/// debug trace switched on.
#[cfg(feature = "ant-backend")]
fn run_live_binary(
    dir: &TestDir,
    args: &[&str],
    devnet_env: Option<&Path>,
) -> std::process::Output {
    let mut command = spawn::antseal();
    command
        .args(args)
        .env("ANTSEAL_DIR", dir.path().join("no-vault-here"))
        .env("RUST_LOG", "antseal_cli::backend=debug")
        .stdin(Stdio::null())
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
    command.output().expect("spawn antseal")
}

/// **D170 §2 R2/R6 through the binary, in a build with a backend.** Over a
/// network nothing answers on:
///
/// - a **tampered** bundle exits with its own rejection (40) and the network
///   is **never connected to** — the reader's connect trace is absent, because
///   the connection is a lazy future awaited only after offline verification
///   passes;
/// - an **unanchored** bundle — the positive control, same network, same argv
///   shape — connects, renders its offline verdict in full with an
///   *Inconclusive* live section whose every row is a fetch failure, and exits
///   with the **evidence** verdict's code, 43, never the network class's 23;
///   and the canonical report bytes reach stdout exactly as an offline run
///   produces them.
///
/// The connect trace is what makes the tampered run's absence mean something:
/// the control shows the same process emitting it once a bundle verifies.
#[cfg(feature = "ant-backend")]
#[test]
fn live_in_a_build_with_a_backend_verifies_first_and_never_moves_the_exit_code() {
    let dir = TestDir::new("live-backend-dead-peer");
    let dead = dead_devnet_export(&dir);

    // ── a tampered bundle: 40, and no connection ────────────────────────
    let tampered = write_bundle(&dir, "t.sealproof", &tampered_bundle());
    let out = run_live_binary(
        &dir,
        &[
            "--json",
            "--network",
            "devnet",
            "verify",
            tampered.to_str().expect("utf-8"),
            "--live",
        ],
        Some(&dead),
    );
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert_eq!(out.status.code(), Some(40), "stderr:\n{stderr}");
    let document: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("one JSON document");
    assert_eq!(document["error"]["class"], "verify-bundle-rejected");
    assert!(
        !stderr.contains(READER_CONNECT_TRACE),
        "`--live` connected for a bundle that failed offline verification — the connection \
         must be awaited only after verification passes (D170 §2 R6). stderr:\n{stderr}"
    );

    // ── the control: an unanchored bundle connects and moves nothing ─────
    let bytes = unanchored_bundle();
    let offline = verify_offline_run(&bytes);
    let path = write_bundle(&dir, "b.sealproof", &bytes);
    let out = run_live_binary(
        &dir,
        &[
            "--json",
            "--network",
            "devnet",
            "verify",
            path.to_str().expect("utf-8"),
            "--live",
        ],
        Some(&dead),
    );
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert_eq!(
        out.status.code(),
        Some(i32::from(offline.exit_code())),
        "the evidence verdict's code, never the network class's. stderr:\n{stderr}"
    );
    assert_eq!(out.status.code(), Some(43), "the UNANCHORED rung");
    assert!(
        stderr.contains(READER_CONNECT_TRACE),
        "CONTROL: a bundle that verifies must connect, or the absence above proves nothing. \
         stderr:\n{stderr}"
    );
    let document: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("one JSON document");
    assert_eq!(
        document["ok"], true,
        "a result document, never a refusal: {document}"
    );
    assert!(document.get("error").is_none(), "{document}");
    assert_eq!(document["result"]["verdict"]["exit_code"], 43);
    let live = &document["result"]["live"];
    assert_eq!(
        live["verdict"], "inconclusive",
        "a network nothing answers on is Inconclusive: {live}"
    );
    let checked = live["counts"]["checked"].as_u64().expect("a count");
    assert!(
        checked >= 2,
        "the units and the manifest were all asked about: {live}"
    );
    assert_eq!(
        live["counts"]["fetch_failed"], checked,
        "every row is a fetch failure — none is a negative answer about the network: {live}"
    );
    let canonical = offline.outcome().report_bytes().to_vec();
    assert!(
        out.stdout.windows(canonical.len()).any(|w| w == canonical),
        "the offline report bytes reach stdout unchanged"
    );
}

/// **D170 §2 R6's first clause through the binary**: in a build with a
/// backend, `--live --network devnet` with no devnet definition in sight is a
/// **usage error (2) before verification** — `--online`'s precedent. The
/// bundle is a tampered one, so a handler that verified first would have
/// answered 40; the control without `--live` shows that it does.
#[cfg(feature = "ant-backend")]
#[test]
fn live_in_a_build_with_a_backend_and_no_devnet_definition_is_a_usage_error_first() {
    let dir = TestDir::new("live-backend-no-devnet");
    let tampered = write_bundle(&dir, "t.sealproof", &tampered_bundle());
    let path = tampered.to_str().expect("utf-8");

    let out = run_live_binary(
        &dir,
        &["--json", "--network", "devnet", "verify", path, "--live"],
        None,
    );
    assert_eq!(
        out.status.code(),
        Some(2),
        "stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let document: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("one JSON document");
    assert_eq!(document["error"]["class"], "usage");
    let message = document["error"]["message"].as_str().expect("a message");
    assert!(
        message.contains("ANTSEAL_DEVNET_ENV"),
        "the refusal says what is missing: {message}"
    );
    assert!(
        !String::from_utf8_lossy(&out.stderr).contains(READER_CONNECT_TRACE),
        "and nothing was connected"
    );

    // CONTROL: the same bundle without `--live` is its own rejection, so the
    // 2 above came first rather than instead.
    let control = run_live_binary(
        &dir,
        &["--json", "--network", "devnet", "verify", path],
        None,
    );
    assert_eq!(control.status.code(), Some(40));
}

// ─────────────────────────────────────────────────────────────────────
// the real `--online` collector, against stub endpoints
// ─────────────────────────────────────────────────────────────────────

/// Two endpoints that answer the same height with different blocks: the
/// must-agree pair **disagrees**, so nothing crosses into the evidence path
/// and the overlay says so.
///
/// This drives `probe_online` — the production collector — rather than a
/// fixture host, so the mapping from A16's `Agreement` onto D64's probe
/// classes is measured and not assumed. The servers bind `127.0.0.1:0`;
/// Q16's no-real-endpoints policy is satisfied by construction.
#[test]
fn disagreeing_endpoints_render_the_advisory_and_move_nothing() {
    let (bundle_bytes, agreed) = attested_bundle(&[(HEIGHT, NTIME)]);
    let height = agreed[0].0;

    let hash_a = "a".repeat(64);
    let hash_b = "b".repeat(64);
    let header_a = "11".repeat(80);
    let header_b = "22".repeat(80);

    let first = StubServer::spawn(
        StubScript::new()
            .route(
                StubMatch::target(format!("block-height/{height}")),
                StubReply::body(200, hash_a.clone().into_bytes()),
            )
            .route(
                StubMatch::target(format!("block/{hash_a}/header")),
                StubReply::body(200, header_a.into_bytes()),
            )
            .unmatched(StubReply::body(404, b"Block not found".to_vec())),
    );
    let second = StubServer::spawn(
        StubScript::new()
            .route(
                StubMatch::target(format!("block-height/{height}")),
                StubReply::body(200, hash_b.clone().into_bytes()),
            )
            .route(
                StubMatch::target(format!("block/{hash_b}/header")),
                StubReply::body(200, header_b.into_bytes()),
            )
            .unmatched(StubReply::body(404, b"Block not found".to_vec())),
    );

    let pair = antseal_anchor::agree::EndpointPair::new(
        antseal_anchor::http::Endpoint::parse(
            &first.base_url(),
            antseal_anchor::TlsPolicy::RequiredExceptLoopback,
        )
        .expect("loopback endpoint"),
        antseal_anchor::http::Endpoint::parse(
            &second.base_url(),
            antseal_anchor::TlsPolicy::RequiredExceptLoopback,
        )
        .expect("loopback endpoint"),
    )
    .expect("two distinct origins");

    let client = antseal_anchor::http::HttpClient::new(antseal_anchor::http::HttpPolicy::verify());
    let bundle = BundleV1::decode(&bundle_bytes).expect("the fixture decodes");
    let endpoints = antseal_cli::verify_host::OnlineEndpoints::new(pair, None, true);
    let inputs = antseal_cli::verify_host::probe_online(
        &client,
        &bundle,
        &endpoints,
        antseal_net::NetworkId::ArbitrumOne,
    );

    // Disagreement is the ABSENCE of evidence (D56 §3), and it is recorded
    // in the probe log where a human learns it.
    assert!(
        inputs.evidence().blocks().block(height).is_none(),
        "a disagreeing pair may not promote anything"
    );
    assert_eq!(
        inputs.probes().block(height),
        Some(&BlockProbe::Disagreed),
        "and the reason is recorded for the overlay"
    );

    let host = CollectedInputs::none().with_online(inputs);
    let run = run_verify(
        &bundle_bytes,
        &options(),
        VerifyModes::new().with_online(),
        &host,
    )
    .expect("the fixture bundle verifies");

    assert_eq!(
        run.exit_code(),
        verify_offline_run(&bundle_bytes).exit_code(),
        "endpoint disagreement cannot move the exit code"
    );
    let overlay = run.outcome().overlay().expect("an overlay");
    assert!(
        overlay.endpoints.overridden,
        "the disclosure states the run departed from the pinned defaults"
    );
    assert!(
        overlay
            .anchor_outcomes
            .iter()
            .any(|outcome| outcome.line.contains("disagree")),
        "the advisory names the disagreement distinctly: {:#?}",
        overlay.anchor_outcomes
    );
}

// ─────────────────────────────────────────────────────────────────────
// the receipt echo, and the cross-surface single-source pin (D137)
// ─────────────────────────────────────────────────────────────────────

/// **D137 §1 (f)/(g) — the CLI prints the module's receipt sentence verbatim,
/// and authors none of it.**
///
/// Both surfaces render `overlay.receipt.line` and neither writes it: one
/// edit to `antseal_core::verify::wording` is supposed to move the CLI and
/// the verifier page together. That claim had **no** assertion on the CLI
/// side. `no_renderer_source_spells_a_frozen_verdict_string` is the negative
/// half — it forbids either renderer spelling the clause as a code literal,
/// and D137 §3 R10 is what put these two sentences on its table — but a
/// negative scan cannot see a renderer that stops printing the module's
/// string, or prints it with something appended. This row is the positive
/// half: byte equality against the table, and the same bytes surviving into
/// the printed output.
///
/// The `--json` half is pinned in the same act, because a sentence and a
/// token are two claims and D65 exists to let a scripter gate on the second.
#[test]
fn the_cli_prints_the_modules_receipt_sentence_and_carries_its_token() {
    // A receipt-bearing bundle (F13's shape): without one, D64 §3's presence
    // rule suppresses the echo and every assertion below would be vacuous.
    let bundle = build(&shapes::multi_file_every_anchor_kind(), &Selection::all(3)).bytes;

    // The chain id is read out of A17's own table rather than restated, so
    // this row asserts what `probe_online` would actually have handed core on
    // the default network (D137 §3 R7) instead of a number that happens to
    // match today.
    let chain_id =
        expected_chain_id(NetworkId::ArbitrumOne).expect("a live network has an expected chain id");
    let probes = ProbeLog::new(endpoints()).with_receipt(
        ReceiptProbe::Agreed(ReceiptConfirmation::NotOnChain),
        chain_id,
    );
    let host =
        CollectedInputs::none().with_online(OnlineInputs::new(OnlineEvidence::new(), probes));
    let run = run_verify(&bundle, &options(), VerifyModes::new().with_online(), &host)
        .expect("the receipt-bearing fixture verifies");

    let echo = run
        .outcome()
        .overlay()
        .expect("--online renders an overlay")
        .receipt
        .clone()
        .expect("a receipt present in the bundle and probed renders an echo");

    // Byte-identical, never `contains`: the CLI does layout over R18's final
    // strings and may not paraphrase, truncate, re-case or extend them.
    assert_eq!(
        echo.line,
        wording::receipt_not_on_chain_line(chain_id),
        "the overlay's receipt line is not the module's — one of the two surfaces has started \
         authoring its own copy (R18; D137 §3 R10)"
    );

    // …and the same bytes reach the printed output. `overlay_lines` indents
    // the row, so the leading whitespace is stripped and the REMAINDER is
    // compared for equality: `contains` would pass on a line that appended a
    // qualifier the page does not print.
    let rendered = run.render();
    let carriers: Vec<&String> = rendered
        .iter()
        .filter(|line| line.contains(&wording::receipt_not_on_chain_line(chain_id)))
        .collect();
    assert_eq!(
        carriers.len(),
        1,
        "the receipt sentence must be printed exactly once: {rendered:#?}"
    );
    assert_eq!(
        carriers[0].trim_start(),
        wording::receipt_not_on_chain_line(chain_id),
        "the printed row is the module's sentence plus indentation and NOTHING else"
    );

    // The machine-readable half (D65), **moved by D137 §3 R3**. The bare token
    // `"not-on-chain"` asserted, to every `jq` consumer, the same unqualified
    // claim the prose did — that the transaction is on no chain at all — and
    // correcting only the prose corrects only the half a human reads. It is now
    // a struct variant, `{"not-on-chain":{"chain_id":N}}`, matching the shape
    // `Confirmed` always had.
    //
    // This edit was made only after the previous assertion was seen to go RED
    // on the new shape (`left: Object {"not-on-chain": Object {"chain_id":
    // Number(42161)}}`, `right: String("not-on-chain")`). A pin that is
    // rewritten to match without first being observed to refuse the change is
    // not a pin.
    //
    // A `result.overlay` shape change is a D65 **scope** event, never a
    // `REPORT_VERSION` event: the overlay is a sibling document and its bytes
    // never enter the report. `the_json_document_carries_the_report_bytes_
    // verbatim` is the row that would say otherwise.
    let document: serde_json::Value =
        serde_json::from_str(&run.json().expect("the envelope renders")).expect("one JSON object");
    assert_eq!(
        document["overlay"]["receipt"]["line"],
        serde_json::Value::String(wording::receipt_not_on_chain_line(chain_id)),
        "the envelope carries the module's sentence too, not a second spelling"
    );
    assert_eq!(
        document["overlay"]["receipt"]["outcome"],
        serde_json::json!({ "not-on-chain": { "chain_id": chain_id } }),
        "the receipt echo's token must carry the chain id the guard enforced (D137 §3 R3). \
         Changing this shape is a deliberate D65 scope event, never a tidy-up."
    );
    // …and the number in the token is the same one in the sentence. Two
    // renderings of one datum that could disagree would be worse than the
    // defect this record fixes: a scripter and a reader would be told
    // different things by one document.
    assert!(
        document["overlay"]["receipt"]["line"]
            .as_str()
            .is_some_and(|line| line.contains(&chain_id.to_string())),
        "the sentence does not name the chain id the token carries: {}",
        document["overlay"]["receipt"]["line"]
    );
}
