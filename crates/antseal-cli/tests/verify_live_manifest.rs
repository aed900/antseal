//! **R81 Accept row 1, at the CLI route** — the encrypted-manifest row that
//! `verify --live` could not ask about, driven through `collect_live` and
//! rendered by the same two producers a `verify` run uses.
//!
//! R80's `crates/antseal-net/tests/live_section_bridge.rs` already proves the
//! manifest row at the **net** route: it hand-builds the `StorageRecord`s and
//! drives `live_check` → `live_inputs` → `verify_with_host`. Its own module
//! doc names what it cannot close — *"A test asserting that `collect_live`
//! itself emits the manifest row belongs in `crates/antseal-cli/tests/`"* —
//! because `antseal-net` has no bundle vocabulary and must not grow one. This
//! file is that test. What it adds over the net route is the hop that was
//! missing: the record list is built **by production code, from the bundle**,
//! so the pairing of the reveal section's ciphertexts with the signed
//! manifest's addresses, and the recomputation of the encrypted-manifest blob
//! through R81's public door, are measured rather than restated.
//!
//! # The venue, stated exactly, because it is not the process
//!
//! The deepest reachable route today is
//! `collect_live` → `CollectedInputs::with_live` → `run_verify`, which is what
//! `crates/antseal-cli/tests/verify_command.rs`'s
//! `a_live_check_with_no_reachable_network_is_inconclusive_and_moves_nothing`
//! already drives. It is **not** the spawned binary, and the reason is a
//! measured property of the tree rather than a convenience: `commands.rs:677`
//! returns `backend::unavailable("verify")` for `--live` **unconditionally**,
//! before verification and in both feature arms, so `collect_live` has no
//! caller in `commands.rs` at all and no process invocation can reach it.
//! `verify_command.rs`'s `live_without_a_compiled_backend_refuses_at_the_seam`
//! pins that refusal. Everything downstream of the collector here *is* the
//! production path: `run_verify` is the handler's own call, `VerifyRun::render`
//! is the handler's own rendering, and `VerifyRun::json` is the handler's own
//! `--json` document.
//!
//! # Why the divergent case needs a dishonest responder
//!
//! Against an honest content-addressed `MockBackend`,
//! `PersistenceOutcome::Different` for the manifest is **unreachable** — bytes
//! that are not the blob cannot sit at the blob's address, which is what that
//! outcome's own doc calls the reason R11 ranks it worst. So the *replaced on
//! the network* case R81's Accept row 1 names is reached with a responder
//! whose address rule disagrees with the network's, exactly as the net route's
//! `a_replaced_manifest_blob_renders_the_manifest_row_as_divergent` does. The
//! device here is narrower than that one's *"everything lands at one
//! address"*: it keeps the real S4 rule for every unit ciphertext, so the unit
//! rows stay honest and the manifest row is the only one the device touches —
//! which is what makes *distinct from the unit rows* an assertion rather than
//! a description.
//!
//! Two outcomes are reachable without any device at all, and both are here as
//! controls: an honest network renders the manifest row `Identical`
//! (so `Different` is not a constant of the row), and R20's
//! `StorageAddresses::RealExceptManifest` handle — a storage record whose
//! recorded address is one bit from the true one — renders it `NotFound`
//! beside passing unit rows.

use antseal_cli::verify_host::{CollectedInputs, collect_live};
use antseal_cli::verify_out::{VerifyRun, run_verify};
use antseal_core::bundle::BundleV1;
use antseal_core::crypto::unit_aead::Nonce24 as AeadNonce;
use antseal_core::storage::compute_storage_address;
use antseal_core::test_util::bundle_fixtures::{Selection, StorageAddresses, build, shapes};
use antseal_core::verify::orchestration::{
    LiveBlobOutcome, LiveLayerVerdict, LiveSection, RenderedLiveRow, VerifyModes,
};
use antseal_core::verify::storage_linkage::{
    ManifestLinkageSubject, recompute_manifest_storage_blob,
};
use antseal_core::verify::{VerifyOptions, wording};
use antseal_net::test_util::{MockBackend, block_on};
use antseal_net::{Address, LiveSubject, subject_label};

// ─────────────────────────────────────────────────────────────────────
// the harness — verify_command.rs's, narrowed to what a live run needs
// ─────────────────────────────────────────────────────────────────────

/// The subject label the closed grammar produces for the manifest row.
///
/// Spelled once, and checked against `antseal_net::subject_label` in
/// [`the_manifest_subject_label_comes_from_the_closed_grammar`] — so this constant is
/// a pin on the grammar rather than a second source of it.
const MANIFEST_SUBJECT: &str = "encrypted manifest";

/// A payload of the form `IMPOSTOR_TAG || <32 address bytes>` asks the
/// dishonest responder below to serve it at exactly that address.
///
/// A tag rather than a hard-coded address because the fixture's addresses are
/// derived, not constant: the impostor names its destination in its own bytes,
/// so nothing in this file has to know what BLAKE3 said.
const IMPOSTOR_TAG: &[u8] = b"antseal-test/impostor-at:";

/// A responder that does **not** honour content addressing, but only for
/// payloads that ask for it.
///
/// Everything else keeps the real S4/D32 rule, which is what leaves the unit
/// rows honest while the manifest's recorded slot is occupied by bytes that
/// are not the blob. `MockBackend::with_address_fn` takes a plain `fn`, so the
/// rule cannot close over a runtime address — hence the self-describing
/// payload.
fn impostor_aware_address(bytes: &[u8]) -> Address {
    match bytes.strip_prefix(IMPOSTOR_TAG) {
        Some(target) if target.len() == Address::LEN => {
            let mut destination = [0u8; Address::LEN];
            destination.copy_from_slice(target);
            Address::from_bytes(destination)
        }
        _ => honest_address(bytes),
    }
}

/// S4's real rule, at this crate's boundary type — `MockBackend::new()`'s own
/// default, restated so a test can assert where honest bytes land.
fn honest_address(bytes: &[u8]) -> Address {
    Address::from(compute_storage_address(bytes).expect("fixture blobs are under the chunk cap"))
}

/// R6's three-file work whose manifest **and** storage record carry real S4
/// addresses, under `mode`.
fn linked_bundle(mode: StorageAddresses) -> Vec<u8> {
    build(
        &shapes::multi_file().with_storage_addresses(mode),
        &Selection::all(3),
    )
    .bytes
}

/// Every ciphertext the bundle embeds, in the two passes `collect_live` makes.
///
/// Deliberately *not* paired with the manifest's recorded addresses here: the
/// pairing is the production behaviour under test, and a test that repeated it
/// would be asserting its own arithmetic. What proves the pairing is the
/// section's `identical` count.
fn embedded_ciphertexts(bundle: &BundleV1<'_>) -> Vec<Vec<u8>> {
    bundle
        .covered_reveals()
        .iter()
        .map(|reveal| reveal.ciphertext().as_slice().to_vec())
        .chain(
            bundle
                .noncovered_reveals()
                .iter()
                .map(|reveal| reveal.ciphertext().as_slice().to_vec()),
        )
        .collect()
}

/// The encrypted-manifest blob the sealer uploaded, through R81's public door
/// — the same function `collect_live` and `check_storage_linkage` both call.
///
/// Used only to *seed* a network with an honest copy. The comparison itself is
/// always production's.
fn manifest_blob(bundle: &BundleV1<'_>) -> Vec<u8> {
    let record = bundle.storage_record();
    let nonce = AeadNonce::from_bytes(*record.nonce().as_bytes());
    recompute_manifest_storage_blob(&ManifestLinkageSubject {
        manifest_bytes: bundle.manifest_bytes(),
        nonce: &nonce,
        k_m: record.k_m(),
        recorded_address: record.address(),
    })
    .expect("a fixture manifest is far below the AEAD's P_MAX")
}

/// Seed `mock` with every embedded unit ciphertext, and return how many.
///
/// Asserts no ciphertext accidentally wears [`IMPOSTOR_TAG`]: if one did, the
/// dishonest responder would misfile it and a unit row would silently stop
/// being a unit row.
fn preload_units(mock: &MockBackend, bundle: &BundleV1<'_>) -> u64 {
    let ciphertexts = embedded_ciphertexts(bundle);
    assert!(
        ciphertexts.len() >= 2,
        "the fixture embeds several units, or 'distinct from the unit rows' says nothing"
    );
    for ciphertext in &ciphertexts {
        assert!(
            !ciphertext.starts_with(IMPOSTOR_TAG),
            "a unit ciphertext wears the impostor tag; the responder would misfile it"
        );
        assert_eq!(
            mock.preload_third_party(ciphertext),
            honest_address(ciphertext),
            "unit ciphertexts land under the real S4 rule"
        );
    }
    ciphertexts.len() as u64
}

/// Drive the production collector over `mock`, then the production run.
fn live_run(bundle_bytes: &[u8], bundle: &BundleV1<'_>, mock: &MockBackend) -> VerifyRun {
    let live = block_on(collect_live(bundle, mock))
        .expect("the collector composes rows from a verified bundle");
    let host = CollectedInputs::none().with_live(live);
    run_verify(
        bundle_bytes,
        &VerifyOptions::new(),
        VerifyModes::new().with_live(),
        &host,
    )
    .expect("the R6 fixture verifies")
}

/// An offline run of the same bytes — the baseline every live run is compared
/// against (D69 §3 R6: the live layer moves neither the code nor the report).
fn offline_run(bundle_bytes: &[u8]) -> VerifyRun {
    run_verify(
        bundle_bytes,
        &VerifyOptions::new(),
        VerifyModes::OFFLINE,
        &CollectedInputs::none(),
    )
    .expect("the R6 fixture verifies")
}

/// The one row whose subject is the manifest's — and the proof there is
/// exactly one, which is the *distinct from the unit rows* half.
fn the_manifest_row(section: &LiveSection) -> RenderedLiveRow {
    let matches: Vec<&RenderedLiveRow> = section
        .rows
        .iter()
        .filter(|row| row.subject == MANIFEST_SUBJECT)
        .collect();
    assert_eq!(
        matches.len(),
        1,
        "exactly one manifest row, distinct from every unit row: {:#?}",
        section.rows
    );
    assert_eq!(
        section.rows.last().map(|row| row.subject.as_str()),
        Some(MANIFEST_SUBJECT),
        "the manifest record is appended after the units (collect_live's order)"
    );
    matches[0].clone()
}

/// Every row except the manifest's, which must all be units.
fn unit_rows(section: &LiveSection) -> Vec<RenderedLiveRow> {
    section
        .rows
        .iter()
        .filter(|row| row.subject != MANIFEST_SUBJECT)
        .cloned()
        .collect()
}

/// Assert the run's exit code and report bytes are the offline ones — D69 §3
/// R6, restated on each case so a new live outcome cannot quietly acquire an
/// exit code (`verify_command.rs`'s `live_outcomes_never_move_the_exit_code`
/// is the type-level half; this is the end-to-end half).
fn assert_evidence_layer_untouched(run: &VerifyRun, bundle_bytes: &[u8]) {
    let offline = offline_run(bundle_bytes);
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
}

// ─────────────────────────────────────────────────────────────────────
// the closed grammar this file pins its assertions to
// ─────────────────────────────────────────────────────────────────────

/// [`MANIFEST_SUBJECT`] is `antseal_net::subject_label`'s output for the
/// manifest subject, and is not any unit's.
///
/// Without this the rest of the file could match a label the production
/// grammar stopped producing, and every "exactly one manifest row" assertion
/// would go quietly vacuous.
#[test]
fn the_manifest_subject_label_comes_from_the_closed_grammar() {
    assert_eq!(
        subject_label(LiveSubject::EncryptedManifest),
        MANIFEST_SUBJECT
    );
    assert_ne!(
        subject_label(LiveSubject::Unit {
            unit_id: 0,
            kind: antseal_net::UnitKindTag::Normal,
        }),
        MANIFEST_SUBJECT
    );
}

// ─────────────────────────────────────────────────────────────────────
// R81 Accept row 1 — the manifest blob replaced on the network
// ─────────────────────────────────────────────────────────────────────

/// **R81's Accept row 1.** `verify --live` over a work whose manifest blob was
/// **replaced on the network**: the live section carries an `encrypted
/// manifest` row, distinct from the unit rows, reporting divergence — in the
/// rendered output *and* in the `--json` document — while every unit row
/// passes and the evidence layer does not move.
///
/// The replacement is the only thing the dishonest responder does: unit
/// ciphertexts keep the real S4 rule, so their rows are answered by an honest
/// network and the manifest row is the only subject the device touches.
#[test]
fn a_manifest_blob_replaced_on_the_network_renders_a_divergent_manifest_row() {
    let bytes = linked_bundle(StorageAddresses::Real);
    let bundle = BundleV1::decode(&bytes).expect("the fixture decodes");

    let mock = MockBackend::new().with_address_fn(impostor_aware_address);
    let units = preload_units(&mock, &bundle);

    // The replacement: bytes that are not the blob, sitting at the address the
    // signed storage record claims.
    let recorded = Address::from(*bundle.storage_record().address());
    let mut impostor = IMPOSTOR_TAG.to_vec();
    impostor.extend_from_slice(recorded.as_bytes());
    assert!(
        impostor.len() < bundle.manifest_bytes().len(),
        "the impostor is strictly shorter than the manifest envelope, so it cannot be the \
         blob (which is that envelope plus an AEAD tag) — the row below would otherwise be \
         Identical for a reason that is not the replacement"
    );
    assert_eq!(
        mock.preload_third_party(&impostor),
        recorded,
        "the impostor really did occupy the recorded manifest address"
    );
    // Read it back from where it landed, rather than trusting the seeding.
    assert_eq!(
        mock.stored(recorded).as_deref(),
        Some(impostor.as_slice()),
        "the network serves the impostor at the recorded manifest address"
    );

    let run = live_run(&bytes, &bundle, &mock);
    let section = run
        .outcome()
        .live()
        .expect("--live renders a section")
        .clone();

    // ── the counts: every unit passes, the manifest is the one divergence ──
    assert_eq!(section.counts.checked, units + 1, "{:?}", section.counts);
    assert_eq!(
        section.counts.identical, units,
        "every unit row passes: {:?}",
        section.counts
    );
    assert_eq!(section.counts.different, 1, "{:?}", section.counts);
    assert_eq!(section.counts.not_found, 0, "{:?}", section.counts);
    assert_eq!(section.counts.fetch_failed, 0, "{:?}", section.counts);
    assert_eq!(section.verdict, LiveLayerVerdict::Divergent);

    // ── the row: its own subject, its own outcome, its own frozen line ─────
    let manifest_row = the_manifest_row(&section);
    assert_eq!(manifest_row.subject, MANIFEST_SUBJECT);
    assert_eq!(manifest_row.outcome, LiveBlobOutcome::Different);
    assert_eq!(
        manifest_row.line,
        wording::live_blob_different_line(MANIFEST_SUBJECT),
        "the sentence is R18's table's, not this file's"
    );
    let units_seen = unit_rows(&section);
    assert_eq!(units_seen.len() as u64, units);
    for row in &units_seen {
        assert!(
            row.subject.starts_with("unit "),
            "a non-unit row escaped the manifest filter: {row:#?}"
        );
        assert_eq!(row.outcome, LiveBlobOutcome::Identical, "{row:#?}");
    }

    // ── the rendered output ────────────────────────────────────────────────
    // `verify_out::live_lines` indents a row by DETAIL_INDENT (six spaces).
    let rendered = run.render();
    let expected_line = format!(
        "      {}",
        wording::live_blob_different_line(MANIFEST_SUBJECT)
    );
    assert_eq!(
        rendered
            .iter()
            .filter(|line| **line == expected_line)
            .count(),
        1,
        "exactly one manifest row in the rendered output: {rendered:#?}"
    );
    assert_eq!(
        rendered
            .iter()
            .filter(|line| line.contains(&wording::live_divergent_line(1)))
            .count(),
        1,
        "the storage layer states its own divergence verdict: {rendered:#?}"
    );

    // ── the `--json` document ──────────────────────────────────────────────
    let document = run.json().expect("the result document renders");

    // (a) the row's exact bytes, contiguous — built from the production types
    //     rather than spelled, so a moved field order or a renamed variant
    //     reddens here instead of silently passing a substring match.
    let expected_fragment = serde_json::to_string(&RenderedLiveRow {
        subject: subject_label(LiveSubject::EncryptedManifest),
        outcome: LiveBlobOutcome::Different,
        line: wording::live_blob_different_line(MANIFEST_SUBJECT),
    })
    .expect("a rendered row serializes");
    assert_eq!(
        document.matches(expected_fragment.as_str()).count(),
        1,
        "the manifest row appears once, verbatim, in the --json document.\n  \
         expected: {expected_fragment}\n  document: {document}"
    );

    // (b) and structurally, so the row is a member of `live.rows` and not a
    //     coincidence somewhere else in the document.
    let value: serde_json::Value =
        serde_json::from_str(&document).expect("the document is one JSON object");
    let rows = value["live"]["rows"]
        .as_array()
        .expect("the live member carries rows");
    assert_eq!(rows.len() as u64, units + 1);
    let manifest_json: Vec<&serde_json::Value> = rows
        .iter()
        .filter(|row| row["subject"] == MANIFEST_SUBJECT)
        .collect();
    assert_eq!(
        manifest_json.len(),
        1,
        "exactly one manifest row in --json: {value}"
    );
    assert_eq!(manifest_json[0]["outcome"], "different");
    for row in rows.iter().filter(|row| row["subject"] != MANIFEST_SUBJECT) {
        assert_eq!(row["outcome"], "identical", "{row}");
    }
    assert_eq!(value["live"]["verdict"], "divergent");
    assert_eq!(value["live"]["counts"]["different"], 1);
    assert_eq!(value["live"]["counts"]["identical"], units);

    // (c) R81's actual subject: **both halves of the storage section now
    //     speak about the manifest**, and they say different, compatible
    //     things. The offline half recomputed the blob from the bundle's own
    //     bytes and found it addresses to the recorded address; the live half
    //     found the network serving something else at that address. Before
    //     this row the second sentence could not be said at all.
    assert_eq!(
        value["report"]["storage_linkage"]["evaluated"]["manifest_matched"],
        serde_json::Value::Bool(true),
        "the offline linkage half still passes the manifest: {value}"
    );

    // ── and none of it reached the evidence layer ──────────────────────────
    assert_evidence_layer_untouched(&run, &bytes);
}

// ─────────────────────────────────────────────────────────────────────
// the two controls, both on an honest content-addressed backend
// ─────────────────────────────────────────────────────────────────────

/// The negative control for the row above: the **same fixture** and the same
/// production path, with the true blob on the network, renders the manifest
/// row `Identical`.
///
/// Without it, `Different` above could be a constant of the manifest row
/// rather than a consequence of the replacement. It also measures the thing
/// R81 exists for in the affirmative direction — the live section now reports
/// the fourth subject on an ordinary run, so `AllPersisted` covers the
/// manifest instead of stopping at the units.
#[test]
fn an_honest_network_renders_the_manifest_row_identical_beside_the_unit_rows() {
    let bytes = linked_bundle(StorageAddresses::Real);
    let bundle = BundleV1::decode(&bytes).expect("the fixture decodes");

    let mock = MockBackend::new();
    let units = preload_units(&mock, &bundle);

    // The blob lands at the address the *signed* storage record claims — which
    // is the independent check that R81's door reproduced the right bytes: a
    // wrong recomputation would land somewhere else.
    let blob = manifest_blob(&bundle);
    assert_eq!(
        mock.preload_third_party(&blob),
        Address::from(*bundle.storage_record().address()),
        "the recomputed blob addresses to the recorded address (StorageAddresses::Real)"
    );

    let run = live_run(&bytes, &bundle, &mock);
    let section = run
        .outcome()
        .live()
        .expect("--live renders a section")
        .clone();

    assert_eq!(section.counts.checked, units + 1, "{:?}", section.counts);
    assert_eq!(section.counts.identical, units + 1, "{:?}", section.counts);
    assert_eq!(section.verdict, LiveLayerVerdict::AllPersisted);

    let manifest_row = the_manifest_row(&section);
    assert_eq!(manifest_row.outcome, LiveBlobOutcome::Identical);
    assert_eq!(
        manifest_row.line,
        wording::live_blob_identical_line(MANIFEST_SUBJECT)
    );

    let document = run.json().expect("the result document renders");
    let value: serde_json::Value =
        serde_json::from_str(&document).expect("the document is one JSON object");
    assert_eq!(value["live"]["verdict"], "all-persisted");
    assert_eq!(value["live"]["counts"]["checked"], units + 1);
    let manifest_json: Vec<&serde_json::Value> = value["live"]["rows"]
        .as_array()
        .expect("rows")
        .iter()
        .filter(|row| row["subject"] == MANIFEST_SUBJECT)
        .collect();
    assert_eq!(manifest_json.len(), 1, "{value}");
    assert_eq!(manifest_json[0]["outcome"], "identical");

    assert_evidence_layer_untouched(&run, &bytes);
}

/// R20's own fixture handle at the CLI route: `StorageAddresses::RealExceptManifest`
/// bends **only** the storage record's recorded address, so an honest,
/// content-addressed network holding every real blob still has nothing at the
/// address the bundle claims.
///
/// This is R81's `Do` clause — *"the offline layer's
/// `StorageAddresses::RealExceptManifest` … driven through `MockBackend`
/// rather than through hand-built inputs"* — and it is the one shape that
/// isolates the manifest row with no dishonest responder anywhere.
#[test]
fn a_bent_recorded_manifest_address_isolates_the_manifest_row_from_passing_units() {
    let bytes = linked_bundle(StorageAddresses::RealExceptManifest);
    let bundle = BundleV1::decode(&bytes).expect("the fixture decodes");

    let mock = MockBackend::new();
    let units = preload_units(&mock, &bundle);

    // The true blob is on the network — at its true address, which under this
    // mode is not the one the storage record records.
    let blob = manifest_blob(&bundle);
    let true_at = mock.preload_third_party(&blob);
    let recorded = Address::from(*bundle.storage_record().address());
    assert_ne!(
        true_at, recorded,
        "RealExceptManifest really did bend the recorded address"
    );
    assert!(
        !mock.contains(recorded),
        "nothing is stored at the bent address"
    );

    let run = live_run(&bytes, &bundle, &mock);
    let section = run
        .outcome()
        .live()
        .expect("--live renders a section")
        .clone();

    assert_eq!(section.counts.checked, units + 1, "{:?}", section.counts);
    assert_eq!(section.counts.identical, units, "{:?}", section.counts);
    assert_eq!(section.counts.not_found, 1, "{:?}", section.counts);
    assert_eq!(section.counts.different, 0, "{:?}", section.counts);
    assert_eq!(section.verdict, LiveLayerVerdict::SomeMissing);

    let manifest_row = the_manifest_row(&section);
    assert_eq!(manifest_row.outcome, LiveBlobOutcome::NotFound);
    assert_eq!(
        manifest_row.line,
        wording::live_blob_not_found_line(MANIFEST_SUBJECT)
    );
    for row in &unit_rows(&section) {
        assert_eq!(row.outcome, LiveBlobOutcome::Identical, "{row:#?}");
    }

    let rendered = run.render();
    let expected_line = format!(
        "      {}",
        wording::live_blob_not_found_line(MANIFEST_SUBJECT)
    );
    assert_eq!(
        rendered
            .iter()
            .filter(|line| **line == expected_line)
            .count(),
        1,
        "exactly one manifest row in the rendered output: {rendered:#?}"
    );

    let document = run.json().expect("the result document renders");
    let value: serde_json::Value =
        serde_json::from_str(&document).expect("the document is one JSON object");
    assert_eq!(value["live"]["verdict"], "some-missing");
    let manifest_json: Vec<&serde_json::Value> = value["live"]["rows"]
        .as_array()
        .expect("rows")
        .iter()
        .filter(|row| row["subject"] == MANIFEST_SUBJECT)
        .collect();
    assert_eq!(manifest_json.len(), 1, "{value}");
    assert_eq!(manifest_json[0]["outcome"], "not-found");

    assert_evidence_layer_untouched(&run, &bytes);
}
