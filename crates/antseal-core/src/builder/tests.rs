//! R13's suite: every reveal shape through the real [`build_bundle`], the
//! R6 parity contract (byte equality on shared inputs), and one negative
//! control per internal assertion via the [`forcing`] seam.
//!
//! Deterministic throughout — the only randomness anywhere in a fixture is
//! R6's seeded [`FixtureRng`](crate::test_util::fixture_rng::FixtureRng),
//! and this suite consumes its outputs. Everything here runs on wasm32 as
//! well as natively: the `test-vectors` tier (R6, the forcing seam, this
//! module's imports) is exactly what the `wasm32-core-tests` lane enables,
//! and nothing below touches `test-util`-only surface (no proptest — the
//! property suite is R14's).

use std::collections::BTreeMap;

use super::forcing::{Force, Smuggle, build_bundle_forced};
use super::*;
use crate::bundle::SealProof;
use crate::crypto::hkdf::{derive_file_salt, derive_path_salt};
use crate::crypto::unit_aead::{Nonce24 as AeadNonce, decrypt_unit};
use crate::test_util::TEST_MASTER_SECRET_W;
use crate::test_util::bundle_fixtures::{
    BuiltFixture, FileSelection as FixtureFileSelection, FileSpec, Selection as FixtureSelection,
    StorageAddresses, WorkSpec, build as fixture_build, shapes,
};

fn w() -> MasterSecretRef<'static> {
    MasterSecretRef::from_bytes(&TEST_MASTER_SECRET_W)
}

/// Every donor this suite feeds [`build_bundle`] records **real** addresses
/// (R78).
///
/// R6's default [`StorageAddresses::Placeholder`] fill patterns are BLAKE3 of
/// nothing, so a placeholder-addressed work is a *total* storage-linkage
/// mismatch and R78's assertion refuses it. `Real` is what a seal-pipeline
/// bundle actually looks like (S12 addresses every ciphertext and the
/// manifest blob), so this is the production shape rather than a workaround —
/// and the placeholder refusal is asserted, not merely avoided, in
/// `tests/builder_storage_linkage.rs`. Applied here rather than at twenty
/// call sites so a new test cannot forget it; nothing in this suite reads an
/// address, so no other assertion moves.
fn real_addressed(spec: &WorkSpec) -> WorkSpec {
    spec.clone().with_storage_addresses(StorageAddresses::Real)
}

// ---------------------------------------------------------------------------
// harness: R13 inputs reconstructed from an R6 donor build
// ---------------------------------------------------------------------------

/// Everything [`BuildInputs`] borrows, owned in one place.
///
/// R6's planning phase — file resolution, unit numbering, encryption — runs
/// **before** its selection is consulted, off a spec-seeded RNG, so the
/// manifest and every ciphertext are selection-independent: an `--all`
/// donor build yields byte-identical material to any other selection over
/// the same spec, with every unit's ciphertext embedded. That is what lets
/// this harness feed R13 *the same inputs* R6 consumed (R6 seam point 1).
struct Harness {
    manifest: Vec<u8>,
    donor: Vec<u8>,
    ciphertexts: BTreeMap<u64, Vec<u8>>,
    contents: BTreeMap<u64, Vec<u8>>,
}

impl Harness {
    fn new(spec: &WorkSpec) -> Self {
        let spec = &real_addressed(spec);
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

    /// Fresh inputs for one build: anchors, storage record and receipt are
    /// re-extracted from the donor per call (they are owned by value).
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

/// Every unit's ciphertext, keyed by work-global `unit_id`, out of an
/// `--all` donor bundle (which embeds them all).
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

/// Per-file tiling-domain plaintext, reconstructed by decrypting each
/// file's normal units and placing them by manifest range — the same bytes
/// R16 would hand the builder after its gather step.
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

/// Map a fixture selection onto the builder's plan. `None` — the shape is
/// **inexpressible**: the exhaustive match (no wildcard) is the structural
/// half of D70 §7.1's parity obligation, so a new fixture-only variant
/// fails compilation here rather than slipping past the parity test.
fn plan_from_fixture(spec: &WorkSpec, selection: &FixtureSelection) -> Option<RevealPlan> {
    let mut files = Vec::with_capacity(spec.files.len());
    for (index, file) in spec.files.iter().enumerate() {
        let choice = selection
            .0
            .get(index)
            .unwrap_or(&FixtureFileSelection::Untouched);
        files.push(match choice {
            FixtureFileSelection::Untouched => FilePlan::Untouched,
            FixtureFileSelection::Units(indices) => {
                FilePlan::units(file.path(), indices.iter().copied())
            }
            FixtureFileSelection::Full => FilePlan::full(file.path()),
            FixtureFileSelection::FullNoMirror | FixtureFileSelection::UnitsWithMirror(_) => {
                return None;
            }
        });
    }
    Some(RevealPlan::new(files))
}

fn decode<'a>(bytes: &'a [u8]) -> SealProof<'a> {
    SealProof::decode(bytes).expect("built bundle decodes")
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

// ---------------------------------------------------------------------------
// parity with R6 (R13 Accept; R6 seam points 1–5; D70 §7.1)
// ---------------------------------------------------------------------------

/// R13 output is **byte-identical** to R6's construction for the same
/// inputs, across the whole named catalogue — byte equality is assembly
/// parity in its strongest form, and byte-equal bundles verify identically
/// by construction (which is R13's Accept wording).
///
/// Two normalizations, each pinned exactly so it cannot widen silently:
///
/// - **Inexpressible shapes.** `FullNoMirror` and `UnitsWithMirror` have no
///   [`FilePlan`] counterpart (D70 §7.1's type-level clause), so their
///   catalogue cases are skipped — and the skipped set is asserted to be
///   exactly those two cases.
/// - **The enumerated-full promotion (D70 ruling 1).** R6's
///   `Units([all indices])` reveals every normal unit but **not** the
///   mirror — its output is the fixture-only mirror-less full shape.
///   Under D70 a `--units` set completing a file pulls the mirror in, so
///   for such a case the reference is R6 built with `Full` for that file;
///   the set of cases normalized this way is asserted to be exactly
///   `split-multi-unit/full-via-enumerated-units`.
#[test]
fn parity_r13_matches_r6_for_every_expressible_catalogue_case() {
    let mut inexpressible: Vec<&'static str> = Vec::new();
    let mut promoted: Vec<&'static str> = Vec::new();

    for case in shapes::catalogue() {
        let Some(plan) = plan_from_fixture(&case.spec, &case.selection) else {
            inexpressible.push(case.name);
            continue;
        };

        // The D70-normalized R6 reference selection: Units covering every
        // normal unit ⇒ Full (mirror rides), everything else verbatim.
        let harness = Harness::new(&case.spec);
        let body_holder = Manifest::decode(&harness.manifest).expect("manifest decodes");
        let mut reference = Vec::with_capacity(case.spec.files.len());
        let mut case_promoted = false;
        for (index, choice) in case.selection.0.iter().enumerate() {
            let normal_units = body_holder.body().files()[index]
                .units()
                .iter()
                .filter(|unit| unit.kind() == UnitKind::Normal)
                .count();
            reference.push(match choice {
                FixtureFileSelection::Units(indices) if covers_all(indices, normal_units) => {
                    case_promoted = true;
                    FixtureFileSelection::Full
                }
                other => other.clone(),
            });
        }
        if case_promoted {
            promoted.push(case.name);
        }
        // The R6 side takes the same `real_addressed` donor the harness took
        // (R78) — parity is byte equality, so both sides must record the same
        // addresses or the comparison measures the mode, not the builder.
        let expected: BuiltFixture =
            fixture_build(&real_addressed(&case.spec), &FixtureSelection(reference));

        let built = build_bundle(harness.inputs(&plan))
            .unwrap_or_else(|error| panic!("case `{}` must build: {error}", case.name));
        assert_eq!(
            built, expected.bytes,
            "case `{}`: R13 bytes diverge from R6's construction",
            case.name
        );
    }

    // The structural inability, asserted (D70 §7.1): exactly the two
    // fixture-only shapes are inexpressible, and exactly one catalogue
    // case needed the D70 promotion normalization.
    assert_eq!(
        inexpressible,
        [
            "single-text-with-mirror/full-no-mirror",
            "split-multi-unit/partial-with-mirror",
        ],
        "the set of fixture-only shapes R13's API cannot express has changed"
    );
    assert_eq!(
        promoted,
        ["split-multi-unit/full-via-enumerated-units"],
        "the set of catalogue cases divergent under D70's enumerated-full promotion has changed"
    );
}

fn covers_all(indices: &[usize], normal_units: usize) -> bool {
    let mut sorted: Vec<usize> = indices.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    sorted.len() == normal_units && sorted.iter().copied().eq(0..normal_units)
}

// ---------------------------------------------------------------------------
// reveal shapes through the public API
// ---------------------------------------------------------------------------

/// The multi-file mixed shape: one full text file with a mirror, one
/// partially revealed split binary file, one untouched `--no-fine-tree`
/// file — every emission rule visible in a single bundle.
#[test]
fn a_mixed_multi_file_reveal_emits_the_spec_content_sets() {
    let spec = shapes::multi_file();
    let harness = Harness::new(&spec);
    let plan = RevealPlan::new(vec![
        FilePlan::full("notes/intro.md"),
        FilePlan::units("data/blob.bin", [1]),
        FilePlan::Untouched,
    ]);
    let bytes = build_bundle(harness.inputs(&plan)).expect("mixed reveal builds");
    let proof = decode(&bytes);
    let bundle = proof.bundle();
    let body = proof.manifest().body();

    // File 0 (text, mirror, 1 normal unit): full — its normal unit is
    // covered, its mirror is an ordinary §7.12 entry, full material rides.
    let mirror_id = body.files()[0]
        .raw_mirror()
        .expect("file 0 has a mirror")
        .unit_id();
    assert!(
        bundle
            .noncovered_reveals()
            .iter()
            .any(|reveal| reveal.unit_id() == mirror_id),
        "the full file's mirror must be an ordinary non-covered entry"
    );
    let full_entry = bundle
        .full_reveals()
        .iter()
        .find(|full| full.file_id() == 0)
        .expect("file 0 carries full-reveal material");
    assert!(
        full_entry.disclosed_s_root().is_some(),
        "fine tree ⇒ s_root"
    );

    // File 1 (split binary): partial — one covered entry, no full material.
    assert!(bundle.full_reveals().iter().all(|full| full.file_id() != 1));
    let file1_revealed: Vec<u64> = bundle
        .covered_reveals()
        .iter()
        .map(CoveredReveal::unit_id)
        .filter(|id| {
            body.files()[1]
                .units()
                .iter()
                .any(|unit| unit.unit_id() == *id)
        })
        .collect();
    assert_eq!(file1_revealed.len(), 1, "exactly the selected unit");

    // File 2: untouched — no touched entry, no full entry, no reveals.
    assert!(
        bundle
            .touched_files()
            .iter()
            .all(|file| file.file_id() != 2)
    );
    assert!(bundle.full_reveals().iter().all(|full| full.file_id() != 2));

    // Touched entries exist for exactly the touched files, paths attached.
    let touched: Vec<u64> = bundle
        .touched_files()
        .iter()
        .map(|file| file.file_id())
        .collect();
    assert_eq!(touched, [0, 1]);
}

/// D70 §§1c, 5, 6.4: the mirror rides exactly on full reveals — including
/// the enumerated-units promotion — and a mirror-less file's full reveal is
/// a silent no-op.
#[test]
fn the_mirror_rides_exactly_on_full_reveals() {
    let spec = shapes::split_multi_unit(); // 3 normal units + mirror
    let harness = Harness::new(&spec);
    let body_holder = Manifest::decode(&harness.manifest).expect("decodes");
    let mirror_id = body_holder.body().files()[0]
        .raw_mirror()
        .expect("mirror-bearing")
        .unit_id();

    let revealed_ids = |bytes: &[u8]| decode(bytes).bundle().revealed_unit_ids();

    // Partial: no mirror, no full material.
    let partial = RevealPlan::new(vec![FilePlan::units("notes/split.md", [1])]);
    let bytes = build_bundle(harness.inputs(&partial)).expect("partial builds");
    assert!(!revealed_ids(&bytes).contains(&mirror_id));
    assert!(decode(&bytes).bundle().full_reveals().is_empty());

    // Full: mirror rides.
    let full = RevealPlan::new(vec![FilePlan::full("notes/split.md")]);
    let bytes = build_bundle(harness.inputs(&full)).expect("full builds");
    assert!(revealed_ids(&bytes).contains(&mirror_id));

    // Units naming every normal unit: classifies full — file_salt, s_root
    // AND the mirror ride (the D70 §7.6 promotion; derived, never declared).
    let promoted = RevealPlan::new(vec![FilePlan::units("notes/split.md", [0, 1, 2])]);
    let bytes = build_bundle(harness.inputs(&promoted)).expect("promoted builds");
    assert!(revealed_ids(&bytes).contains(&mirror_id));
    assert_eq!(decode(&bytes).bundle().full_reveals().len(), 1);

    // A mirror-less file's full reveal: no entry, no error (D70 §5 no-op).
    let mirrorless = WorkSpec::new(
        "canonical text",
        vec![FileSpec::text("plain.txt", shapes::CANONICAL_TEXT)],
    );
    let harness = Harness::new(&mirrorless);
    let plan = RevealPlan::new(vec![FilePlan::full("plain.txt")]);
    let bytes = build_bundle(harness.inputs(&plan)).expect("mirror-less full builds");
    let proof = decode(&bytes);
    assert!(proof.manifest().body().files()[0].raw_mirror().is_none());
    assert_eq!(proof.bundle().full_reveals().len(), 1);
}

/// D70 §5: a `--no-fine-tree` mirror-bearing file's full reveal emits TWO
/// non-covered entries (whole-file unit + mirror), no covered entries, and
/// full material without `s_root`.
#[test]
fn a_no_fine_tree_mirror_bearing_full_reveal_emits_two_noncovered_entries_and_no_s_root() {
    let spec = WorkSpec::new(
        "no fine tree with mirror",
        vec![FileSpec::text("crlf.txt", shapes::CRLF_TEXT).without_fine_tree()],
    );
    let harness = Harness::new(&spec);
    let plan = RevealPlan::new(vec![FilePlan::full("crlf.txt")]);
    let bytes = build_bundle(harness.inputs(&plan)).expect("builds");
    let proof = decode(&bytes);
    assert_eq!(proof.bundle().covered_reveals().len(), 0);
    assert_eq!(proof.bundle().noncovered_reveals().len(), 2);
    let full = &proof.bundle().full_reveals()[0];
    assert!(
        full.disclosed_s_root().is_none(),
        "no fine tree ⇒ no s_root"
    );
}

/// Content-model edges: the empty file (one empty non-covered unit, no
/// fine tree) and the one-byte file (n = 1 — the D83 `salt_0 ‖ 0x00·16`
/// disclosed-root form) both build and verify.
#[test]
fn empty_and_one_byte_files_build_and_verify() {
    let harness = Harness::new(&shapes::empty_file());
    let plan = RevealPlan::new(vec![FilePlan::full("data/empty.bin")]);
    let bytes = build_bundle(harness.inputs(&plan)).expect("empty file builds");
    let proof = decode(&bytes);
    assert_eq!(proof.bundle().noncovered_reveals().len(), 1);
    assert!(
        proof.bundle().full_reveals()[0]
            .disclosed_s_root()
            .is_none()
    );

    let harness = Harness::new(&shapes::one_byte_file());
    let plan = RevealPlan::new(vec![FilePlan::full("data/one.bin")]);
    let bytes = build_bundle(harness.inputs(&plan)).expect("one-byte file builds");
    let proof = decode(&bytes);
    let s_root = proof.bundle().full_reveals()[0]
        .disclosed_s_root()
        .expect("n = 1 still has a fine tree");
    assert_eq!(
        &s_root.as_bytes()[16..],
        &[0u8; 16],
        "at n = 1 the disclosed root is the leaf payload: salt_0 ‖ 0x00·16 (D83)"
    );
}

/// The receipt is embedded iff the caller opted it in (the input carries
/// the opt-in as `Some`), across the two every-anchor-kind twins.
#[test]
fn the_receipt_is_embedded_iff_opted() {
    let with = Harness::new(&shapes::multi_file_every_anchor_kind());
    let plan = RevealPlan::new(vec![
        FilePlan::full("notes/intro.md"),
        FilePlan::units("data/blob.bin", [1]),
        FilePlan::Untouched,
    ]);
    let bytes = build_bundle(with.inputs(&plan)).expect("receipt-in builds");
    assert!(decode(&bytes).bundle().receipt().is_some());

    let without = Harness::new(&shapes::multi_file_every_anchor_kind_no_receipt());
    let bytes = build_bundle(without.inputs(&plan)).expect("receipt-out builds");
    assert!(decode(&bytes).bundle().receipt().is_none());
}

/// Untouched files leave no trace: no entry, and none of their derived
/// material — path salt, file salt, fine seed — appears anywhere in the
/// bytes. Partially revealed files' file salts and fine seeds are equally
/// absent (generation-side isolation; the builder re-asserts this
/// internally on every build, this test pins it end-to-end).
#[test]
fn untouched_and_partial_files_leak_no_derived_material() {
    let spec = shapes::multi_file();
    let harness = Harness::new(&spec);
    let plan = RevealPlan::new(vec![
        FilePlan::full("notes/intro.md"),
        FilePlan::units("data/blob.bin", [1]),
        FilePlan::Untouched,
    ]);
    let bytes = build_bundle(harness.inputs(&plan)).expect("builds");

    // Untouched file 2: nothing of it.
    assert!(!contains(
        &bytes,
        derive_path_salt(w(), FileId(2)).as_bytes()
    ));
    assert!(!contains(
        &bytes,
        derive_file_salt(w(), FileId(2)).expose_bytes_for_test_vectors()
    ));

    // Partial file 1: path disclosed (touched), content salts withheld.
    assert!(!contains(
        &bytes,
        derive_file_salt(w(), FileId(1)).expose_bytes_for_test_vectors()
    ));
    assert!(!contains(
        &bytes,
        derive_fine_seed(w(), FileId(1)).as_bytes()
    ));

    // The master secret never reaches any bundle.
    assert!(!contains(&bytes, &TEST_MASTER_SECRET_W));
}

/// Same inputs, same bytes: the builder is deterministic (no clock, no
/// randomness anywhere in it).
#[test]
fn building_is_deterministic() {
    let spec = shapes::multi_file_anchored();
    let harness = Harness::new(&spec);
    let plan = RevealPlan::new(vec![
        FilePlan::full("notes/intro.md"),
        FilePlan::units("data/blob.bin", [0, 2]),
        FilePlan::full("archive/old.txt"),
    ]);
    let first = build_bundle(harness.inputs(&plan)).expect("builds");
    let second = build_bundle(harness.inputs(&plan)).expect("builds");
    assert_eq!(first, second);
}

// ---------------------------------------------------------------------------
// typed input-validation errors
// ---------------------------------------------------------------------------

#[test]
fn input_validation_failures_are_typed_and_distinct() {
    let spec = shapes::split_multi_unit();
    let harness = Harness::new(&spec);

    // Plan length ≠ manifest file count.
    let plan = RevealPlan::new(vec![]);
    assert!(matches!(
        build_bundle(harness.inputs(&plan)),
        Err(BuildError::PlanFileCountMismatch {
            expected: 1,
            got: 0
        })
    ));

    // Empty unit selection: touched-but-nothing-revealed is refused here,
    // by name, instead of surfacing as the verifier's D82 rejection later.
    let plan = RevealPlan::new(vec![FilePlan::units("notes/split.md", [])]);
    assert!(matches!(
        build_bundle(harness.inputs(&plan)),
        Err(BuildError::NoUnitsSelected { file_id: 0 })
    ));

    // Out-of-range normal-unit index.
    let plan = RevealPlan::new(vec![FilePlan::units("notes/split.md", [7])]);
    assert!(matches!(
        build_bundle(harness.inputs(&plan)),
        Err(BuildError::UnitIndexOutOfRange {
            file_id: 0,
            index: 7,
            normal_units: 3,
        })
    ));

    // A revealed unit's ciphertext missing.
    let plan = RevealPlan::new(vec![FilePlan::units("notes/split.md", [1])]);
    let mut inputs = harness.inputs(&plan);
    let starved: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
    inputs.unit_ciphertexts = &starved;
    assert!(matches!(
        build_bundle(inputs),
        Err(BuildError::MissingCiphertext { unit_id: 1 })
    ));

    // A touched fine-tree file's plaintext missing.
    let mut inputs = harness.inputs(&plan);
    let starved: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
    inputs.file_contents = &starved;
    assert!(matches!(
        build_bundle(inputs),
        Err(BuildError::MissingFileContent { file_id: 0 })
    ));

    // Undecodable manifest bytes.
    let plan = RevealPlan::new(vec![FilePlan::full("notes/split.md")]);
    let mut inputs = harness.inputs(&plan);
    inputs.manifest = b"not a manifest";
    assert!(matches!(
        build_bundle(inputs),
        Err(BuildError::Manifest { .. })
    ));
}

/// Wrong *bytes* — content that does not rebuild the manifest's tree, a
/// ciphertext swapped between units — abort at the mandatory self-check
/// (or, for the tree, at G's proof layer): nothing inconsistent with the
/// signed manifest can leave the builder.
#[test]
fn inconsistent_material_aborts_the_build() {
    let spec = shapes::split_multi_unit();
    let harness = Harness::new(&spec);
    let plan = RevealPlan::new(vec![FilePlan::full("notes/split.md")]);

    // Corrupt one content byte: the rebuilt tree no longer matches the
    // manifest's fine_root, so the self-check rejects the bundle.
    let mut wrong_content = harness.contents.clone();
    wrong_content.get_mut(&0).expect("file 0")[0] ^= 0x01;
    let mut inputs = harness.inputs(&plan);
    inputs.file_contents = &wrong_content;
    assert!(matches!(
        build_bundle(inputs),
        Err(BuildError::SelfCheck { .. })
    ));

    // Swap two units' ciphertexts: the AAD's unit_id binding fails inside
    // the self-check's per-unit stage.
    let mut swapped = harness.ciphertexts.clone();
    let a = swapped[&0].clone();
    let b = swapped[&1].clone();
    swapped.insert(0, b);
    swapped.insert(1, a);
    let mut inputs = harness.inputs(&plan);
    inputs.unit_ciphertexts = &swapped;
    assert!(matches!(
        build_bundle(inputs),
        Err(BuildError::SelfCheck { .. })
    ));

    // Corrupt the MIRROR's ciphertext: the mirror is present on a full
    // reveal (D70), so its bytes are checked — a wrong mirror aborts.
    let body_holder = Manifest::decode(&harness.manifest).expect("decodes");
    let mirror_id = body_holder.body().files()[0]
        .raw_mirror()
        .expect("mirror-bearing")
        .unit_id();
    let mut corrupted = harness.ciphertexts.clone();
    corrupted.get_mut(&mirror_id).expect("mirror ciphertext")[0] ^= 0x01;
    let mut inputs = harness.inputs(&plan);
    inputs.unit_ciphertexts = &corrupted;
    assert!(matches!(
        build_bundle(inputs),
        Err(BuildError::SelfCheck { .. })
    ));
}

// ---------------------------------------------------------------------------
// negative controls — one per guard, through the forcing seam (D70 §7.7)
// ---------------------------------------------------------------------------

/// R14's named control: forcing a forbidden item the *verifier* rejects —
/// full-reveal material for a partially revealed file — makes the
/// mandatory self-check fail, with R4's frozen partial-isolation code.
#[test]
fn forcing_full_material_onto_a_partial_file_fails_the_self_check() {
    let spec = shapes::split_multi_unit();
    let harness = Harness::new(&spec);
    let plan = RevealPlan::new(vec![FilePlan::units("notes/split.md", [1])]);
    let force = Force {
        leak_full_material: Some(0),
        ..Force::none()
    };
    match build_bundle_forced(harness.inputs(&plan), &force) {
        Err(BuildError::SelfCheck { source }) => {
            assert_eq!(source.code(), "partial-reveal-salt-leak-file-salt");
        }
        other => panic!("expected the self-check to fire, got {other:?}"),
    }
}

/// Converse mirror assertion (D70 §7.3b): omitting a full file's mirror is
/// a shape the verifier ACCEPTS (frozen `full-no-mirror` vector), so the
/// refusal must come from the internal assertion — the error variant, not
/// `SelfCheck`, is the proof the right guard fired.
#[test]
fn forcing_mirror_omission_is_caught_by_the_converse_assertion() {
    let spec = shapes::single_text_with_mirror();
    let harness = Harness::new(&spec);
    let plan = RevealPlan::new(vec![FilePlan::full("notes/intro.md")]);
    let force = Force {
        omit_mirror: Some(0),
        ..Force::none()
    };
    assert!(matches!(
        build_bundle_forced(harness.inputs(&plan), &force),
        Err(BuildError::MirrorMissingFromFullReveal {
            file_id: 0,
            unit_id: 1,
        })
    ));
}

/// Forward mirror assertion (D70 §7.3a): a partial reveal shipping the
/// mirror is the R53 shape the verifier ACCEPTS — again the internal
/// assertion, not the self-check, must refuse it.
#[test]
fn forcing_a_mirror_alongside_a_partial_reveal_is_caught_by_the_forward_assertion() {
    let spec = shapes::split_multi_unit();
    let harness = Harness::new(&spec);
    let plan = RevealPlan::new(vec![FilePlan::units("notes/split.md", [1])]);
    let body_holder = Manifest::decode(&harness.manifest).expect("decodes");
    let mirror_id = body_holder.body().files()[0]
        .raw_mirror()
        .expect("mirror-bearing")
        .unit_id();
    let force = Force {
        emit_mirror_for: Some(0),
        ..Force::none()
    };
    match build_bundle_forced(harness.inputs(&plan), &force) {
        Err(BuildError::MirrorEmittedWithoutFullReveal { file_id, unit_id }) => {
            assert_eq!((file_id, unit_id), (0, mirror_id));
        }
        other => panic!("expected the forward mirror assertion, got {other:?}"),
    }
}

/// Receipt assertion: presence is legal either way on the wire, so only
/// the internal opted-flag comparison can catch a desync — both
/// directions.
#[test]
fn forcing_receipt_desync_is_caught_in_both_directions() {
    let plan = RevealPlan::new(vec![
        FilePlan::full("notes/intro.md"),
        FilePlan::units("data/blob.bin", [1]),
        FilePlan::Untouched,
    ]);

    // Opted in, forced out.
    let with = Harness::new(&shapes::multi_file_every_anchor_kind());
    let force = Force {
        drop_receipt: true,
        ..Force::none()
    };
    assert!(matches!(
        build_bundle_forced(with.inputs(&plan), &force),
        Err(BuildError::ReceiptPresenceMismatch { opted: true })
    ));

    // Not opted, forced in.
    let without = Harness::new(&shapes::multi_file_every_anchor_kind_no_receipt());
    let force = Force {
        inject_receipt: true,
        ..Force::none()
    };
    assert!(matches!(
        build_bundle_forced(without.inputs(&plan), &force),
        Err(BuildError::ReceiptPresenceMismatch { opted: false })
    ));
}

/// Byte-scan assertions: vault material smuggled where the verifier
/// tolerates arbitrary bytes — an anchor artifact, which never fails a
/// bundle (D84 rule F2) — is caught only by the builder's own scan. One
/// control per scanned material class.
#[test]
fn smuggled_vault_material_is_caught_by_the_byte_scans() {
    let spec = shapes::split_multi_unit();
    let harness = Harness::new(&spec);
    let plan = RevealPlan::new(vec![FilePlan::units("notes/split.md", [1])]);

    let build_with = |smuggle| {
        let force = Force {
            smuggle: Some(smuggle),
            ..Force::none()
        };
        build_bundle_forced(harness.inputs(&plan), &force)
    };

    // File 0 is partially revealed: its file_salt must not appear.
    assert!(matches!(
        build_with(Smuggle::FileSalt(0)),
        Err(BuildError::ForbiddenBytesInEncoding {
            material: ForbiddenMaterial::FileSalt { file_id: 0 },
        })
    ));
    // …nor its fine seed.
    assert!(matches!(
        build_with(Smuggle::FineSeed(0)),
        Err(BuildError::ForbiddenBytesInEncoding {
            material: ForbiddenMaterial::FineSeed { file_id: 0 },
        })
    ));
    // Unit 1 is revealed: its manifest nonce must not appear outside the
    // embedded manifest (nonces are manifest-only, spec line 91).
    assert!(matches!(
        build_with(Smuggle::UnitNonce(1)),
        Err(BuildError::ForbiddenBytesInEncoding {
            material: ForbiddenMaterial::UnitNonce { unit_id: 1 },
        })
    ));
}

/// The seam is inert when unused: the default `Force` produces bytes
/// identical to the production entry point, so every negative control
/// above mutated exactly what it claimed to and nothing else.
#[test]
fn the_default_force_is_byte_identical_to_the_production_path() {
    let spec = shapes::multi_file();
    let harness = Harness::new(&spec);
    let plan = RevealPlan::new(vec![
        FilePlan::full("notes/intro.md"),
        FilePlan::units("data/blob.bin", [1]),
        FilePlan::Untouched,
    ]);
    let unforced = build_bundle(harness.inputs(&plan)).expect("builds");
    let forced = build_bundle_forced(harness.inputs(&plan), &Force::none()).expect("builds");
    assert_eq!(unforced, forced);
}
