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

use antseal_anchor::testing::stub::{StubMatch, StubReply, StubScript, StubServer};
use antseal_cli::error::ErrorClass;
use antseal_cli::machine::ENVELOPE_VERSION;
use antseal_cli::verify_host::CollectedInputs;
use antseal_cli::verify_out::{VerifyRun, run_verify};
use antseal_core::anchor::model::{OnlineBlockResult, OnlineEvidence};
use antseal_core::anchor::testing::ots_writer::{FETCH_DATE, bitcoin, container, header_with};
use antseal_core::bundle::schema::{OpaqueBytes, OtsAnchor, OtsUpgrade};
use antseal_core::bundle::{AnchorStatus, BundleV1, SealProof, encode_bundle};
use antseal_core::manifest::anchor_digest;
use antseal_core::test_util::bundle_fixtures::{Selection, Tweak, build, build_tweaked, shapes};
use antseal_core::verify::REPORT_VERSION;
use antseal_core::verify::orchestration::{
    LiveBlobOutcome, LiveBlobRow, LiveInputs, OnlineInputs, VerifyModes,
};
use antseal_core::verify::overlay::{BlockProbe, ProbeEndpoints, ProbeLog};
use antseal_core::verify::{VerifyOptions, wording};
use antseal_net::test_util::{Fault, MockBackend, block_on};

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
                reason: "transport failure".to_owned(),
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
