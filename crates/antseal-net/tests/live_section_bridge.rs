//! **R80 — the bridge R21's Accept row 3 was missing**, and **R81 — the
//! encrypted-manifest row `--live` could not ask about.**
//!
//! R21 proved the *rendering* of the four live outcomes in `antseal-core`,
//! against hand-built inputs. R11 proved the *fetching* against
//! `MockBackend` in `antseal-net`. Nothing built R21's `LiveInputs` from an
//! actual `live_check(&MockBackend, …)`, and the reason was structural:
//! `antseal-net` depends on `antseal-core`, so core cannot dev-depend on net
//! without a cycle. This file is the composition, on the one seam that can
//! hold it.
//!
//! # Why the test lives here (R80's placement ruling)
//!
//! The choice of home *is* the choice of home for the
//! `LiveCheckReport → LiveInputs` conversion, and that conversion is now
//! [`antseal_net::live_inputs`] — a **production** function, not a
//! `#[cfg(test)]` helper — because both of its source types are this crate's.
//! `antseal-cli`'s `collect_live` delegates to it, so U30's wiring and this
//! test exercise **one** projection rather than two that can disagree. The
//! full argument is on that function; the consequence for this file is that
//! it can drive the real bridge without `antseal-core` gaining any
//! dev-dependency edge at all.
//!
//! # What this file does not close
//!
//! It drives `live_check` → `live_inputs` → `verify_with_host`, which is
//! every hop except the bundle-shaped record building that only
//! `antseal-cli`'s `collect_live` does (this crate has no bundle vocabulary
//! and must not grow one). A test asserting that `collect_live` itself emits
//! the manifest row belongs in `crates/antseal-cli/tests/`.

use antseal_core::anchor::model::OnlineEvidence;
use antseal_core::bundle::BundleV1;
use antseal_core::crypto::unit_aead::Nonce24 as AeadNonce;
use antseal_core::storage::compute_storage_address;
use antseal_core::test_util::bundle_fixtures::{Selection, StorageAddresses, build, shapes};
use antseal_core::verify::orchestration::{
    LiveBlobOutcome, LiveCounts, LiveInputs, LiveLayerVerdict, LiveSection, OnlineInputs,
    VerifyHost, VerifyModes, verify_with_host,
};
use antseal_core::verify::overlay::{ProbeEndpoints, ProbeLog};
use antseal_core::verify::storage_linkage::{
    ManifestLinkageSubject, recompute_manifest_storage_blob,
};
use antseal_core::verify::{VerifyOptions, wording};
use antseal_net::test_util::{Fault, MockBackend, block_on};
use antseal_net::{
    Address, LiveSubject, StorageRecord, UnitKindTag, live_check, live_inputs, subject_label,
};

// ─────────────────────────────────────────────────────────────────────
// the harness
// ─────────────────────────────────────────────────────────────────────

/// A host that reports exactly the live rows it was given, and nothing
/// online.
struct LiveOnlyHost(LiveInputs);

impl VerifyHost for LiveOnlyHost {
    fn online_inputs(&self) -> OnlineInputs {
        OnlineInputs::new(
            OnlineEvidence::new(),
            ProbeLog::new(ProbeEndpoints::new(Vec::new(), false)),
        )
    }

    fn live_inputs(&self) -> LiveInputs {
        self.0.clone()
    }
}

/// Render `inputs` through R21's real composition and return the section.
///
/// The bundle is a plain R6 fixture: `LiveSection` is built from the host's
/// rows alone, so which bundle verifies is irrelevant to the rows — but the
/// run must be a *real* one, because `LiveSection::new` is private and
/// `verify_with_host` is the only door to it. That is deliberate on R21's
/// part and it is why this test cannot shortcut the renderer.
fn render(bundle: &[u8], inputs: LiveInputs) -> LiveSection {
    let host = LiveOnlyHost(inputs);
    let outcome = verify_with_host(
        bundle,
        &VerifyOptions::new(),
        VerifyModes::new().with_live(),
        &host,
        &|value: &str| value.to_owned(),
    )
    .expect("the R6 fixture verifies");
    outcome
        .live()
        .expect("--live was requested, so a section renders")
        .clone()
}

fn plain_bundle() -> Vec<u8> {
    build(&shapes::multi_file(), &Selection::all(3)).bytes
}

/// A fixture whose manifest and storage record carry **real** S4 addresses,
/// optionally with the storage record's address bent by one bit.
fn linked_bundle(mode: StorageAddresses) -> Vec<u8> {
    build(
        &shapes::multi_file().with_storage_addresses(mode),
        &Selection::all(3),
    )
    .bytes
}

/// Every ciphertext the bundle embeds, with the address its **signed
/// manifest** records for that unit — the two opposite sides `collect_live`
/// pairs.
fn embedded_units(bundle: &BundleV1<'_>) -> Vec<(LiveSubject, Address, Vec<u8>)> {
    let manifest = antseal_core::manifest::Manifest::decode(bundle.manifest_bytes())
        .expect("a verified bundle's manifest decodes");
    let recorded: std::collections::BTreeMap<u64, (Address, UnitKindTag)> = manifest
        .body()
        .files()
        .iter()
        .flat_map(|file| file.units().iter())
        .map(|unit| {
            (
                unit.unit_id(),
                (Address::from(*unit.address()), unit.kind().into()),
            )
        })
        .collect();

    // The two reveal sections are distinct types, so they are walked
    // separately rather than chained — the same two passes `collect_live`
    // makes, in the same order.
    let embedded: Vec<(u64, Vec<u8>)> = bundle
        .covered_reveals()
        .iter()
        .map(|reveal| (reveal.unit_id(), reveal.ciphertext().as_slice().to_vec()))
        .chain(
            bundle
                .noncovered_reveals()
                .iter()
                .map(|reveal| (reveal.unit_id(), reveal.ciphertext().as_slice().to_vec())),
        )
        .collect();

    embedded
        .into_iter()
        .filter_map(|(unit_id, ciphertext)| {
            recorded.get(&unit_id).map(|(address, kind)| {
                (
                    LiveSubject::Unit {
                        unit_id,
                        kind: *kind,
                    },
                    *address,
                    ciphertext,
                )
            })
        })
        .collect()
}

/// The manifest blob and the address the bundle's storage record claims —
/// R81's public route, driven exactly as `collect_live` drives it.
fn manifest_subject(bundle: &BundleV1<'_>) -> (Address, Vec<u8>) {
    let record = bundle.storage_record();
    let nonce = AeadNonce::from_bytes(*record.nonce().as_bytes());
    let blob = recompute_manifest_storage_blob(&ManifestLinkageSubject {
        manifest_bytes: bundle.manifest_bytes(),
        nonce: &nonce,
        k_m: record.k_m(),
        recorded_address: record.address(),
    })
    .expect("a fixture manifest is far below P_MAX");
    (Address::from(*record.address()), blob)
}

// ─────────────────────────────────────────────────────────────────────
// R80 — the four outcomes, from a real backend to a rendered row
// ─────────────────────────────────────────────────────────────────────

/// **R80's Accept row 1.** One `MockBackend`, seeded so one blob is
/// identical, one differs, one is absent and one fails to fetch; the report
/// converted by the production bridge; the rendered `LiveSection` asserted
/// row by row against R21's own wording.
#[test]
fn all_four_outcomes_reach_their_rendered_rows_from_one_mock_backend() {
    let mock = MockBackend::new();
    let alpha = vec![0xA1u8; 300];
    let bravo = vec![0xB2u8; 301];
    let charlie = vec![0xC3u8; 302];
    let alpha_at = mock.preload_third_party(&alpha);
    let bravo_at = mock.preload_third_party(&bravo);
    let charlie_at = mock.preload_third_party(&charlie);
    let absent = Address::from_bytes([0x5A; 32]);
    assert!(
        !mock.contains(absent),
        "the absent address really is absent"
    );

    // The expectation for `charlie` is one byte short of what is stored, so
    // the comparison is unequal without any dishonesty from the mock.
    let mut charlie_expected = charlie.clone();
    charlie_expected.pop();

    // Row 0 trips the one-shot fault (it fires on the FIRST `get_data`), so
    // the four outcomes arrive in this order.
    mock.arm_fault(Fault::DuringGetData);
    let records = [
        StorageRecord::new(
            LiveSubject::Unit {
                unit_id: 0,
                kind: UnitKindTag::Normal,
            },
            alpha_at,
            &alpha,
        ),
        StorageRecord::new(
            LiveSubject::Unit {
                unit_id: 1,
                kind: UnitKindTag::RawMirror,
            },
            bravo_at,
            &bravo,
        ),
        StorageRecord::new(
            LiveSubject::Unit {
                unit_id: 2,
                kind: UnitKindTag::Normal,
            },
            charlie_at,
            &charlie_expected,
        ),
        StorageRecord::new(LiveSubject::EncryptedManifest, absent, &alpha),
    ];

    let report = block_on(live_check(&mock, &records)).expect("four records");
    let section = render(&plain_bundle(), live_inputs(&report));

    // The four counts partition the rows, and each is 1 — so no assertion
    // below is about a row that happens to share an outcome with another.
    assert_eq!(
        section.counts,
        LiveCounts {
            identical: 1,
            different: 1,
            not_found: 1,
            fetch_failed: 1,
            checked: 4,
        },
        "the four outcomes each occur exactly once"
    );

    let expected: [(&str, LiveBlobOutcome, String); 4] = [
        (
            "unit 0",
            LiveBlobOutcome::FetchFailed {
                reason: antseal_net::FetchFailureClass::Transport.label().to_owned(),
            },
            wording::live_blob_fetch_error_line(
                "unit 0",
                antseal_net::FetchFailureClass::Transport.label(),
            ),
        ),
        (
            "unit 1 (raw mirror)",
            LiveBlobOutcome::Identical,
            wording::live_blob_identical_line("unit 1 (raw mirror)"),
        ),
        (
            "unit 2",
            LiveBlobOutcome::Different,
            wording::live_blob_different_line("unit 2"),
        ),
        (
            "encrypted manifest",
            LiveBlobOutcome::NotFound,
            wording::live_blob_not_found_line("encrypted manifest"),
        ),
    ];

    assert_eq!(section.rows.len(), expected.len());
    for (row, (subject, outcome, line)) in section.rows.iter().zip(expected) {
        assert_eq!(row.subject, subject, "rows keep record order");
        assert_eq!(row.outcome, outcome, "{subject}");
        assert_eq!(row.line, line, "{subject}");
    }

    // The aggregate: `Divergent` outranks the missing blob and the failed
    // fetch, which is R11's precedence seen through R21's renderer.
    assert_eq!(section.verdict, LiveLayerVerdict::Divergent);
    assert_eq!(section.verdict_line, Some(wording::live_divergent_line(1)));
    assert_eq!(section.label, wording::LIVE_LAYER_LABEL);
}

/// **R80's Accept row 1, second half: the whole ladder**, each rung reached
/// from a real `live_check` rather than from hand-built rows.
#[test]
fn the_aggregate_precedence_ladder_is_climbed_from_real_fetches() {
    let bundle = plain_bundle();
    let good = vec![0x11u8; 288];
    let other = vec![0x22u8; 289];

    let unit = |id: u64| LiveSubject::Unit {
        unit_id: id,
        kind: UnitKindTag::Normal,
    };
    let absent = Address::from_bytes([0x77; 32]);

    // AllPersisted — everything served, byte-identical.
    let mock = MockBackend::new();
    let good_at = mock.preload_third_party(&good);
    let report = block_on(live_check(
        &mock,
        &[StorageRecord::new(unit(0), good_at, &good)],
    ))
    .expect("one record");
    let section = render(&bundle, live_inputs(&report));
    assert_eq!(section.verdict, LiveLayerVerdict::AllPersisted);
    assert_eq!(
        section.verdict_line,
        Some(wording::live_all_persisted_line(1))
    );

    // Inconclusive — nothing negative established, one fetch failed.
    let mock = MockBackend::new();
    let good_at = mock.preload_third_party(&good);
    mock.arm_fault(Fault::DuringGetData);
    let report = block_on(live_check(
        &mock,
        &[StorageRecord::new(unit(0), good_at, &good)],
    ))
    .expect("one record");
    let section = render(&bundle, live_inputs(&report));
    assert_eq!(section.verdict, LiveLayerVerdict::Inconclusive);
    assert_eq!(
        section.verdict_line,
        Some(wording::live_inconclusive_line(1))
    );

    // SomeMissing — an established absence outranks an unresolved fetch.
    let mock = MockBackend::new();
    let good_at = mock.preload_third_party(&good);
    mock.arm_fault(Fault::DuringGetData);
    let report = block_on(live_check(
        &mock,
        &[
            StorageRecord::new(unit(0), good_at, &good),
            StorageRecord::new(unit(1), absent, &other),
        ],
    ))
    .expect("two records");
    let section = render(&bundle, live_inputs(&report));
    assert_eq!(section.counts.fetch_failed, 1, "the gap really is present");
    assert_eq!(section.verdict, LiveLayerVerdict::SomeMissing);
    assert_eq!(
        section.verdict_line,
        Some(wording::live_some_missing_line(1))
    );

    // Divergent — served-but-different outranks both.
    let mock = MockBackend::new();
    let good_at = mock.preload_third_party(&good);
    mock.arm_fault(Fault::DuringGetData);
    let other_at = mock.preload_third_party(&other);
    let mut bent = other.clone();
    bent.pop();
    let report = block_on(live_check(
        &mock,
        &[
            StorageRecord::new(unit(0), good_at, &good),
            StorageRecord::new(unit(1), absent, &other),
            StorageRecord::new(unit(2), other_at, &bent),
        ],
    ))
    .expect("three records");
    let section = render(&bundle, live_inputs(&report));
    assert_eq!(section.counts.fetch_failed, 1);
    assert_eq!(section.counts.not_found, 1);
    assert_eq!(section.counts.different, 1);
    assert_eq!(section.verdict, LiveLayerVerdict::Divergent);
}

/// The bridge labels every subject the vocabulary has, and the labels are the
/// ones the rendered rows are spoken about.
#[test]
fn every_live_subject_has_a_distinct_label_and_no_subject_renders_unnamed() {
    let subjects = [
        LiveSubject::Unit {
            unit_id: 0,
            kind: UnitKindTag::Normal,
        },
        LiveSubject::Unit {
            unit_id: 0,
            kind: UnitKindTag::RawMirror,
        },
        LiveSubject::EncryptedManifest,
    ];
    let mut labels: Vec<String> = subjects.iter().copied().map(subject_label).collect();
    assert!(labels.iter().all(|label| !label.trim().is_empty()));
    labels.sort();
    labels.dedup();
    assert_eq!(
        labels.len(),
        subjects.len(),
        "two subjects render under one label, so a row cannot be attributed"
    );
}

/// **R79's second half.** Its register entry names `LiveBlobRow::subject`
/// beside the fetch-failure reason — both reach a display line, and core's
/// type for the subject is a bare `String`. This asserts the *values* are a
/// closed grammar even though the type is open: every label is
/// `unit <digits>`, `unit <digits> (raw mirror)` or `encrypted manifest`, so
/// nothing a bundle, a backend or a network chose can occupy it and the
/// renderer's missing escape neutralises nothing.
///
/// `u64::MAX` is swept because the digits are the one variable part: if a
/// label ever grew a caller-supplied fragment, the largest ordinary input is
/// where a formatting change would show first.
#[test]
fn every_live_subject_label_is_drawn_from_the_closed_grammar() {
    let ids = [0u64, 7, 42, u64::MAX];
    let mut seen = 0usize;
    for unit_id in ids {
        for kind in [UnitKindTag::Normal, UnitKindTag::RawMirror] {
            let label = subject_label(LiveSubject::Unit { unit_id, kind });
            let digits = unit_id.to_string();
            let expected = match kind {
                UnitKindTag::Normal => format!("unit {digits}"),
                UnitKindTag::RawMirror => format!("unit {digits} (raw mirror)"),
            };
            assert_eq!(label, expected, "{unit_id} / {kind:?}");
            assert!(
                label.chars().all(|c| c.is_ascii_graphic() || c == ' '),
                "the label is printable ASCII with no control byte: {label:?}"
            );
            seen += 1;
        }
    }
    assert_eq!(seen, ids.len() * 2, "the sweep visited every combination");
    assert_eq!(
        subject_label(LiveSubject::EncryptedManifest),
        "encrypted manifest"
    );
}

// ─────────────────────────────────────────────────────────────────────
// R81 — the encrypted-manifest row
// ─────────────────────────────────────────────────────────────────────

/// **The two halves of the storage section compute the same blob.**
///
/// This is the load-bearing check behind R81's ruling: the offline layer
/// hashes `recompute_manifest_storage_blob`'s output into an address, and
/// `--live` byte-compares that same output against the network. If they
/// diverged, one half would be silently checking a different subject.
#[test]
fn the_public_route_reproduces_exactly_the_blob_the_offline_layer_hashes() {
    let bytes = linked_bundle(StorageAddresses::Real);
    let bundle = BundleV1::decode(&bytes).expect("the fixture decodes");
    let (address, blob) = manifest_subject(&bundle);

    let recomputed =
        compute_storage_address(&blob).expect("a fixture manifest blob is under the cap");
    assert_eq!(
        Address::from(recomputed),
        address,
        "the blob the live path compares against is the one the recorded address names"
    );
    assert!(
        !blob.is_empty() && blob != bundle.manifest_bytes(),
        "the blob is the ciphertext, not the plaintext envelope (spec line 98)"
    );
}

/// **R81's Accept row 1, `RealExceptManifest` shape.** A work whose storage
/// record names an address the manifest blob is not at: every unit row passes
/// and the **manifest** row does not, distinctly, in the rendered output and
/// in the `--json` bytes.
#[test]
fn a_bent_manifest_address_renders_its_own_row_beside_passing_unit_rows() {
    let bytes = linked_bundle(StorageAddresses::RealExceptManifest);
    let bundle = BundleV1::decode(&bytes).expect("the fixture decodes");

    let units = embedded_units(&bundle);
    assert!(units.len() >= 2, "the fixture embeds several units");
    let (manifest_at, manifest_blob) = manifest_subject(&bundle);

    // The network holds every unit ciphertext and the *true* manifest blob.
    // Only the recorded address is bent, so the manifest is the one subject
    // the network cannot answer for.
    let mock = MockBackend::new();
    for (_, address, ciphertext) in &units {
        assert_eq!(
            mock.preload_third_party(ciphertext),
            *address,
            "the fixture's recorded unit addresses are the real S4 ones"
        );
    }
    let true_manifest_at = mock.preload_third_party(&manifest_blob);
    assert_ne!(
        true_manifest_at, manifest_at,
        "RealExceptManifest really did bend the recorded address"
    );

    let mut records: Vec<StorageRecord<'_>> = units
        .iter()
        .map(|(subject, address, ciphertext)| StorageRecord::new(*subject, *address, ciphertext))
        .collect();
    records.push(StorageRecord::new(
        LiveSubject::EncryptedManifest,
        manifest_at,
        &manifest_blob,
    ));

    let report = block_on(live_check(&mock, &records)).expect("records are not empty");
    let section = render(&bytes, live_inputs(&report));

    assert_eq!(section.counts.checked as usize, units.len() + 1);
    assert_eq!(
        section.counts.identical as usize,
        units.len(),
        "every unit row passes: {:?}",
        section.counts
    );
    assert_eq!(section.counts.not_found, 1);

    let manifest_row = section
        .rows
        .last()
        .expect("the manifest row is appended last");
    assert_eq!(manifest_row.subject, "encrypted manifest");
    assert_eq!(manifest_row.outcome, LiveBlobOutcome::NotFound);
    assert_eq!(
        manifest_row.line,
        wording::live_blob_not_found_line("encrypted manifest")
    );
    assert!(
        section.rows[..section.rows.len() - 1]
            .iter()
            .all(|row| row.subject != "encrypted manifest"),
        "the manifest row is distinct from the unit rows"
    );
    assert_eq!(section.verdict, LiveLayerVerdict::SomeMissing);

    // …and it is visible to a machine reader, not only to a human one.
    let json = String::from_utf8(section.to_canonical_json().expect("the section serializes"))
        .expect("canonical JSON is UTF-8");
    assert!(json.contains("encrypted manifest"), "{json}");
    assert!(json.contains("not-found"), "{json}");
}

/// A responder that does not honour content addressing serves *different*
/// bytes at the manifest's recorded address — `Different`, which R11 ranks
/// worst precisely because an honest network cannot produce it.
///
/// The divergent address rule is the only way to reach this: against a
/// content-addressed mock, bytes that are not the blob cannot be at the
/// blob's address.
#[test]
fn a_replaced_manifest_blob_renders_the_manifest_row_as_divergent() {
    /// A backend whose address rule disagrees with the network's: everything
    /// lands at one address, so an impostor payload can occupy the
    /// manifest's recorded slot.
    fn one_address(_bytes: &[u8]) -> Address {
        Address::from_bytes([0x00; 32])
    }

    let bytes = linked_bundle(StorageAddresses::Real);
    let bundle = BundleV1::decode(&bytes).expect("the fixture decodes");
    let (_, manifest_blob) = manifest_subject(&bundle);

    let mock = MockBackend::new().with_address_fn(one_address);
    let impostor = b"NOT-THE-MANIFEST-BLOB".to_vec();
    let served_at = mock.preload_third_party(&impostor);
    assert_ne!(
        impostor, manifest_blob,
        "the impostor is not the blob, or the row below would be Identical"
    );

    let report = block_on(live_check(
        &mock,
        &[StorageRecord::new(
            LiveSubject::EncryptedManifest,
            served_at,
            &manifest_blob,
        )],
    ))
    .expect("one record");
    let section = render(&bytes, live_inputs(&report));

    assert_eq!(section.rows.len(), 1);
    assert_eq!(section.rows[0].subject, "encrypted manifest");
    assert_eq!(section.rows[0].outcome, LiveBlobOutcome::Different);
    assert_eq!(
        section.rows[0].line,
        wording::live_blob_different_line("encrypted manifest")
    );
    assert_eq!(section.verdict, LiveLayerVerdict::Divergent);
    assert_eq!(section.verdict_line, Some(wording::live_divergent_line(1)));

    let json = String::from_utf8(section.to_canonical_json().expect("serializes"))
        .expect("canonical JSON is UTF-8");
    assert!(
        json.contains("encrypted manifest") && json.contains("different"),
        "{json}"
    );
}
