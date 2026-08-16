//! R78 — the builder consumes the storage-linkage finding its mandatory
//! self-check now computes (tasks/R.md R78; D128 §10 (iv); D70 §7.3).
//!
//! After D128 §3 R7 the builder's `verify_bundle(&bytes, &VerifyOptions::new())`
//! evaluates the storage-linkage layer. R78 ruled the finding a **hard build
//! error** rather than a warning; the ruling and its three grounds live at
//! `assert_beyond_self_check` in `src/builder/mod.rs`, and this file is the
//! reachability proof the row's Accept row 1 asks for.
//!
//! | case | what is bent | expected |
//! | --- | --- | --- |
//! | [`a_real_addressed_build_is_accepted_and_its_linkage_is_wholly_matched`] | nothing | builds; every unit and the manifest match |
//! | [`a_bent_unit_address_is_refused_inside_build_bundle`] | one **manifest unit entry**'s address | refused, `units_mismatched: 1`, manifest still matched |
//! | [`a_bent_manifest_address_is_refused_inside_build_bundle`] | the **storage record**'s address | refused, no unit mismatched, manifest unmatched |
//! | [`placeholder_addressed_fixtures_are_refused_and_that_is_the_disposition`] | every address (R6's default fill patterns) | refused, total mismatch |
//!
//! **The two bent cases are separate on purpose.** R6's
//! `StorageAddresses::RealExceptUnit` moves the *manifest unit table*, and
//! `RealExceptManifest` moves the *storage record*, leaving the unit table
//! untouched — so the two halves of `StorageLinkageResult::Evaluated` are
//! asserted independently and a check that only looked at one of them stays
//! red on the other.
//!
//! **The `Placeholder` disposition (Accept row 3).** R6's default addresses
//! are per-unit fill patterns and are BLAKE3 of nothing, so every
//! `Placeholder` work is a *total* mismatch and the hard arm refuses it.
//! Nothing frozen depends on that: R6's committed catalogue and every
//! `testdata/` vector are produced by `bundle_fixtures::build`, which does
//! not call `build_bundle`. The two suites that do — `src/builder/tests.rs`
//! and `tests/builder_properties.rs` — therefore build their donors under
//! `StorageAddresses::Real`, which is the shape a seal-pipeline bundle
//! actually has (S12 computes `compute_storage_address` over each ciphertext
//! and over the manifest blob). The refusal is asserted below rather than
//! merely avoided, so the disposition is a committed fact and not a habit.
//!
//! # WASM
//!
//! Same gating as the other suites in `tests/`: the `wasm32-core-tests` lane
//! runs `--lib` only (`scripts/wasm-tests.sh`), so this file is native-only
//! by construction and the wasm32 lanes are untouched. Nothing here needs a
//! clock, a network or randomness — the whole file would run under wasm32 if
//! that lane ever grew integration tests.

use std::collections::BTreeMap;

use antseal_core::builder::{BuildError, BuildInputs, FilePlan, RevealPlan, build_bundle};
use antseal_core::bundle::BundleV1;
use antseal_core::crypto::hkdf::UnitId;
use antseal_core::crypto::material::MasterSecretRef;
use antseal_core::crypto::unit_aead::{Nonce24 as AeadNonce, decrypt_unit};
use antseal_core::manifest::Manifest;
use antseal_core::manifest::registry::UnitKind;
use antseal_core::test_util::TEST_MASTER_SECRET_W;
use antseal_core::test_util::bundle_fixtures::{
    Selection as FixtureSelection, StorageAddresses, WorkSpec, build as fixture_build, shapes,
};
use antseal_core::verify::{StorageLinkageResult, VerifyOptions, verify_bundle};

/// How many unit ciphertexts a full reveal of `shapes::multi_file()` embeds.
///
/// Pinned rather than derived: the rendered messages below spell this number,
/// and a fixture change that shrank the embedded set would otherwise quietly
/// shrink what the bent cases are asserted over.
const MULTI_FILE_EMBEDDED_UNITS: u64 = 6;

fn w() -> MasterSecretRef<'static> {
    MasterSecretRef::from_bytes(&TEST_MASTER_SECRET_W)
}

// ---------------------------------------------------------------------------
// harness: R13 inputs reconstructed from an R6 donor build
// ---------------------------------------------------------------------------
//
// The same reconstruction `src/builder/tests.rs` and `tests/builder_properties.rs`
// use — an `--all` donor build yields the manifest, the storage record and
// every unit's ciphertext, all selection-independent (R6 seam point 1). The
// only thing this file varies is the donor spec's `StorageAddresses` mode.

struct Harness {
    manifest: Vec<u8>,
    donor: Vec<u8>,
    ciphertexts: BTreeMap<u64, Vec<u8>>,
    contents: BTreeMap<u64, Vec<u8>>,
}

impl Harness {
    fn new(spec: &WorkSpec) -> Self {
        let donor = fixture_build(spec, &FixtureSelection::all(spec.files.len()));
        let ciphertexts = ciphertexts_from(&donor.bytes);
        let contents = contents_from(&donor.manifest, &ciphertexts);
        Self {
            manifest: donor.manifest,
            donor: donor.bytes,
            ciphertexts,
            contents,
        }
    }

    fn inputs<'a>(&'a self, plan: &'a RevealPlan) -> BuildInputs<'a> {
        let parts = BundleV1::decode(&self.donor)
            .expect("donor decodes")
            .into_parts();
        BuildInputs {
            manifest: &self.manifest,
            storage_record: parts.storage_record,
            plan,
            unit_ciphertexts: &self.ciphertexts,
            file_contents: &self.contents,
            w: w(),
            ots_anchors: parts.ots_anchors,
            tsa_anchors: parts.tsa_anchors,
            receipt: parts.receipt,
        }
    }
}

fn ciphertexts_from(donor: &[u8]) -> BTreeMap<u64, Vec<u8>> {
    let bundle = BundleV1::decode(donor).expect("donor decodes");
    let mut map = BTreeMap::new();
    for reveal in bundle.covered_reveals() {
        map.insert(reveal.unit_id(), reveal.ciphertext().as_slice().to_vec());
    }
    for reveal in bundle.noncovered_reveals() {
        map.insert(reveal.unit_id(), reveal.ciphertext().as_slice().to_vec());
    }
    map
}

fn contents_from(manifest: &[u8], ciphertexts: &BTreeMap<u64, Vec<u8>>) -> BTreeMap<u64, Vec<u8>> {
    let decoded = Manifest::decode(manifest).expect("manifest decodes");
    let body = decoded.body();
    let mut map = BTreeMap::new();
    for (index, entry) in body.files().iter().enumerate() {
        let mut content = vec![0u8; usize::try_from(entry.size()).expect("small")];
        for unit in entry.units() {
            if unit.kind() != UnitKind::Normal {
                continue;
            }
            let plaintext = decrypt_unit(
                w(),
                body.seal_id(),
                UnitId(unit.unit_id()),
                &AeadNonce::from_bytes(*unit.nonce().as_bytes()),
                &ciphertexts[&unit.unit_id()],
                usize::try_from(unit.true_length()).expect("small"),
            )
            .expect("donor ciphertext decrypts");
            let start = usize::try_from(unit.range().start()).expect("small");
            content[start..start + plaintext.len()].copy_from_slice(&plaintext);
        }
        map.insert(index as u64, content);
    }
    map
}

/// `shapes::multi_file()` under `mode`, fully revealed, through the real
/// [`build_bundle`].
fn build_multi_file(mode: StorageAddresses) -> Result<Vec<u8>, BuildError> {
    let spec = shapes::multi_file().with_storage_addresses(mode);
    let harness = Harness::new(&spec);
    let plan = RevealPlan::new(
        spec.files
            .iter()
            .map(|file| FilePlan::full(file.path()))
            .collect(),
    );
    build_bundle(harness.inputs(&plan))
}

/// The build must have been refused, and by R78's arm — never by some other
/// guard that happens to fire on the same fixture.
fn refusal(mode: StorageAddresses) -> BuildError {
    match build_multi_file(mode) {
        Ok(bytes) => panic!(
            "{mode:?}: build_bundle accepted {} bytes whose embedded content does not address to \
             what the signed manifest records — R78's assertion did not fire",
            bytes.len()
        ),
        Err(error) => error,
    }
}

// ---------------------------------------------------------------------------
// the positive control
// ---------------------------------------------------------------------------

/// Real addresses build, and the layer had something to find: every embedded
/// unit and the manifest blob match.
///
/// This is what makes the three refusals below evidence about the *bend*
/// rather than about a check that refuses everything, and it pins
/// [`MULTI_FILE_EMBEDDED_UNITS`] against the fixture that spells it.
#[test]
fn a_real_addressed_build_is_accepted_and_its_linkage_is_wholly_matched() {
    let bytes = build_multi_file(StorageAddresses::Real).expect("a real-addressed work builds");
    let report = verify_bundle(&bytes, &VerifyOptions::new()).expect("the built bundle verifies");
    assert_eq!(
        report.storage_linkage,
        StorageLinkageResult::Evaluated {
            units_matched: MULTI_FILE_EMBEDDED_UNITS,
            units_mismatched: 0,
            manifest_matched: true,
        },
        "a real-addressed build must be wholly matched, over exactly \
         {MULTI_FILE_EMBEDDED_UNITS} embedded units"
    );
}

// ---------------------------------------------------------------------------
// Accept row 1 — two bent-address cases, each detected inside build_bundle
// ---------------------------------------------------------------------------

/// A bent **unit** address: the manifest unit entry records an address one
/// bit from the right one, so the embedded ciphertext no longer addresses to
/// what the sealer signed. The arm that fires is the **error** arm.
#[test]
fn a_bent_unit_address_is_refused_inside_build_bundle() {
    let error = refusal(StorageAddresses::RealExceptUnit(0));

    assert!(
        matches!(
            error,
            BuildError::StorageLinkageMismatch {
                units_mismatched: 1,
                units_checked: MULTI_FILE_EMBEDDED_UNITS,
                manifest_matched: true,
            }
        ),
        "a bent unit address must refuse the build with exactly one mismatched unit and an \
         untouched manifest half, got: {error:?}"
    );
    assert_eq!(
        error.to_string(),
        "internal assertion: the built bundle does not address to what its signed manifest \
         records — 1 of 6 embedded unit ciphertext(s) mismatched, manifest blob matched: true",
    );
}

/// A bent **manifest** address: the storage record claims an address one bit
/// from the right one and the manifest unit table is untouched, so the unit
/// half stays clean and only the manifest half fires. Same arm, distinct
/// rendering — R18's frozen wording row collapses these two on the verify
/// side (D128 §10 (v)); the builder's own error does not.
#[test]
fn a_bent_manifest_address_is_refused_inside_build_bundle() {
    let error = refusal(StorageAddresses::RealExceptManifest);

    assert!(
        matches!(
            error,
            BuildError::StorageLinkageMismatch {
                units_mismatched: 0,
                units_checked: MULTI_FILE_EMBEDDED_UNITS,
                manifest_matched: false,
            }
        ),
        "a bent manifest address must refuse the build with no unit mismatched and the manifest \
         half unmatched, got: {error:?}"
    );
    assert_eq!(
        error.to_string(),
        "internal assertion: the built bundle does not address to what its signed manifest \
         records — 0 of 6 embedded unit ciphertext(s) mismatched, manifest blob matched: false",
    );
}

// ---------------------------------------------------------------------------
// Accept row 3 — the Placeholder disposition, asserted
// ---------------------------------------------------------------------------

/// R6's default addresses are fill patterns, not BLAKE3 of anything, so a
/// `Placeholder` work is a total mismatch and the hard arm refuses it.
///
/// Recorded as an assertion rather than left implicit: this is the case that
/// decides whether the committed fixture catalogue can be fed to
/// `build_bundle`, and the answer is *not under `Placeholder`* (module docs).
#[test]
fn placeholder_addressed_fixtures_are_refused_and_that_is_the_disposition() {
    let error = refusal(StorageAddresses::Placeholder);

    assert!(
        matches!(
            error,
            BuildError::StorageLinkageMismatch {
                units_mismatched: MULTI_FILE_EMBEDDED_UNITS,
                units_checked: MULTI_FILE_EMBEDDED_UNITS,
                manifest_matched: false,
            }
        ),
        "a placeholder-addressed work is a TOTAL mismatch — every unit and the manifest — and the \
         message must say so, got: {error:?}"
    );
    assert_eq!(
        error.to_string(),
        "internal assertion: the built bundle does not address to what its signed manifest \
         records — 6 of 6 embedded unit ciphertext(s) mismatched, manifest blob matched: false",
    );
}
