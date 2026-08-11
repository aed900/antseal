//! R14 — property tests for the **production builder's** generation-side
//! guarantees (tasks/R.md R14; MVP-SPEC.md lines 114, 121; decision D70 §7.7),
//! over randomized synthetic works × randomized valid selections, all through
//! the real [`build_bundle`].
//!
//! | property | test |
//! | --- | --- |
//! | (a) every built bundle passes `verify_bundle` | [`every_built_bundle_passes_verify_bundle`] |
//! | (b) partial reveals: no `file_salt`, no `s_root`, no ancestor-of-unrevealed-leaf seed | [`partial_reveals_withhold_full_material_and_every_ancestor_seed`] |
//! | (c) mirrors ride exactly with full-file reveals (forward **and** D70 converse) | [`mirrors_ride_exactly_with_full_file_reveals`] |
//! | (d) paths and path salts only for touched files | [`paths_and_path_salts_are_disclosed_only_for_touched_files`] |
//! | negative control: each forced forbidden emission refused with its exact error | [`forcing_each_forbidden_emission_is_refused_with_its_exact_error`] |
//! | the checkers themselves can fail | [`the_independent_checkers_flag_planted_violations`] |
//! | every checker antecedent is deterministically reached | [`every_expressible_catalogue_case_passes_the_independent_checkers`] |
//!
//! R13's own suite (`src/builder/tests.rs`) pins each reveal shape and each
//! forcing-seam variant **once, on fixed shapes**; this file adds the
//! *property* form — randomized works × selections — and never restates those
//! example cases.
//!
//! # Independence of the checkers (R14 Accept, bullet 2)
//!
//! Every verdict here is re-derived from the decoded bundle plus the decoded
//! manifest's **unit table**, never from the builder's plan variables and
//! never through G's cover arithmetic. Concretely:
//!
//! - `full(F)`, mirror presence, unit coverage and byte ranges come from a
//!   fresh walk over `ManifestBodyV1::files()`/`units()` filtering on
//!   [`UnitKind`] directly (not `FileEntry::raw_mirror`, not `RevealPlan`);
//! - GGM ancestry is recomputed from each cover entry's raw `(level, index)`
//!   address by this file's own [`independent_depth`] / [`real_leaf_span`] —
//!   the depth is a from-scratch `smallest d with 2^d >= n` loop and the span
//!   is `[index·2^(d−level), (index+1)·2^(d−level)) ∩ [0, n)`, written from
//!   the D9 addressing definition. Nothing calls `depth_for_leaf_count`,
//!   `NodeAddress::first_slot`/`covers_slot`, `minimal_cover` or any other
//!   G function, so a shared bug in G11/G12's cover code cannot hide.
//!
//! [`the_independent_checkers_flag_planted_violations`] proves each checker
//! **can** fail: violations are planted through the only seams able to emit
//! violating *bytes* — R6's `Tweak`/fixture-only selections, which exist for
//! exactly this (the production seam's forces never yield bytes, because
//! `finish` refuses them; that refusal is the negative-control test's job).
//!
//! # Conventions (Q3, `docs/testing/proptest-conventions.md`)
//!
//! Fixed per-block seeds (0x5EED_1440..=0x5EED_1445, unique workspace-wide);
//! `strategies::integration_test_config` because a suite in `tests/` has no
//! `lib.rs` ancestor and the default persistence would silently store
//! nothing; found counterexamples land in the committed
//! `crates/antseal-core/proptest-regressions/builder_properties.txt`.
//! `PROPTEST_CASES` **overrides** the hardcoded `cases` values below (C18's
//! finding) — they are local-run cost tuning, not floors: every case builds
//! (and self-verifies) real bundles, so the blocks default to 64 (32 for the
//! ten-build negative-control block) the way R6's own builder-cost property
//! block does. The generator signs with the Ed25519-only policy throughout:
//! the manifest reaches [`build_bundle`] pre-signed as opaque input, so
//! signature-policy variety exercises nothing in the builder while ML-DSA
//! keygen+sign would dominate every case (R6's measured ~100 ms); hybrid
//! coverage lives in F16/R6's own corpora and in the catalogue sweep here,
//! whose fixture specs keep the default hybrid policy.
//!
//! # WASM
//!
//! Same gating as F16 (`tests/codec_properties.rs`): this suite lives in
//! `tests/`, and the `wasm32-core-tests` lane runs `--lib` only
//! (`scripts/wasm-tests.sh`) — proptest is not WASM-safe (P14,
//! `Cargo.toml`), so property suites are native-only by construction and the
//! wasm32 lanes are untouched.

use std::collections::{BTreeMap, BTreeSet};

use antseal_core::builder::forcing::{Force, Smuggle, build_bundle_forced};
use antseal_core::builder::{
    BuildError, BuildInputs, FilePlan, ForbiddenMaterial, RevealPlan, build_bundle,
};
use antseal_core::bundle::{BundleV1, SealProof};
use antseal_core::canon::{TextMode, UNICODE_17_0_0, canonicalize_v};
use antseal_core::crypto::hkdf::{
    FileId, UnitId, derive_file_salt, derive_fine_seed, derive_path_salt,
};
use antseal_core::crypto::material::MasterSecretRef;
use antseal_core::crypto::unit_aead::{Nonce24 as AeadNonce, decrypt_unit};
use antseal_core::manifest::Manifest;
use antseal_core::manifest::body::ManifestBodyV1;
use antseal_core::manifest::registry::UnitKind;
use antseal_core::test_util::TEST_MASTER_SECRET_W;
use antseal_core::test_util::bundle_fixtures::{
    AnchorSet, FileSelection as FixtureFileSelection, FileSpec, Selection as FixtureSelection,
    Tweak, WorkSpec, build as fixture_build, build_tweaked, shapes,
};
use antseal_core::test_util::proptest::prelude::*;
use antseal_core::test_util::strategies;
use antseal_core::verify::{VerifyOptions, verify_bundle};

/// Committed regressions file (Q3 §5). Every block in this file points here.
const REGRESSIONS: &str = "proptest-regressions/builder_properties.txt";

fn w() -> MasterSecretRef<'static> {
    MasterSecretRef::from_bytes(&TEST_MASTER_SECRET_W)
}

/// Q3's integration config with a lowered local case count (see module docs;
/// `PROPTEST_CASES` overrides `cases`, so the CI lane still explores more).
fn scenario_config(rng_seed: u64, cases: u32) -> ProptestConfig {
    ProptestConfig {
        cases,
        ..strategies::integration_test_config(rng_seed, REGRESSIONS)
    }
}

/// The wave-4 finding, asserted rather than trusted (Q3 §5): this file's
/// config carries an explicit `Direct` persistence path, so a counterexample
/// found in CI lands in a committed file instead of being silently dropped.
#[test]
fn regressions_are_persisted_to_the_committed_path() {
    let config = strategies::integration_test_config(0x5EED_1440, REGRESSIONS);
    let rendered = format!("{:?}", config.failure_persistence);
    assert!(
        rendered.contains("builder_properties.txt"),
        "failure persistence must name this file's committed regressions path, got {rendered}"
    );
    assert!(
        rendered.contains("Direct"),
        "persistence must be Direct, not the SourceParallel default that cannot resolve from \
         tests/: {rendered}"
    );
}

// ---------------------------------------------------------------------------
// harness: R13 inputs reconstructed from an R6 donor build
// ---------------------------------------------------------------------------
//
// R6's planning phase — file resolution, unit numbering, encryption — runs
// before its selection is consulted, off a spec-seeded RNG, so an `--all`
// donor build yields the manifest and every unit's ciphertext independent of
// any later selection. That is what lets this harness feed the production
// builder the same already-computed material R16's gather step would
// (R6 seam point 1; the same reconstruction R13's own suite uses).

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
/// `--all` donor bundle (which embeds them all — mirrors included).
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

/// Per-file tiling-domain plaintext, reconstructed by decrypting each file's
/// normal units and placing them by manifest range — the bytes R16 would
/// hand the builder after its gather step.
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

// ---------------------------------------------------------------------------
// the independent checkers (R14 Accept, bullet 2 — see module docs)
// ---------------------------------------------------------------------------

/// One file's facts, read by this suite's **own** walk over the decoded
/// manifest's unit table — `UnitKind` filtering only, never
/// `FileEntry::raw_mirror` and never the builder's `RevealPlan`.
struct FileFact {
    file_id: u64,
    size: u64,
    fine_tree: bool,
    /// `(unit_id, range_start, range_length)` per **normal** unit, in
    /// manifest order.
    normal: Vec<(u64, u64, u64)>,
    /// `unit_id`s of raw-mirror units (the manifest schema admits at most
    /// one, but the checker does not assume it).
    mirrors: Vec<u64>,
}

impl FileFact {
    fn unit_ids(&self) -> impl Iterator<Item = u64> + '_ {
        self.normal
            .iter()
            .map(|(id, ..)| *id)
            .chain(self.mirrors.iter().copied())
    }
}

fn facts_of(body: &ManifestBodyV1) -> Vec<FileFact> {
    body.files()
        .iter()
        .enumerate()
        .map(|(index, entry)| {
            let mut normal = Vec::new();
            let mut mirrors = Vec::new();
            for unit in entry.units() {
                match unit.kind() {
                    UnitKind::Normal => {
                        normal.push((unit.unit_id(), unit.range().start(), unit.range().length()));
                    }
                    UnitKind::RawMirror => mirrors.push(unit.unit_id()),
                }
            }
            FileFact {
                file_id: index as u64,
                size: entry.size(),
                fine_tree: entry.fine_tree().is_present(),
                normal,
                mirrors,
            }
        })
        .collect()
}

/// The bundle's revealed unit-id set, collected directly from the two reveal
/// sections rather than through `BundleV1::revealed_unit_ids`.
fn revealed_ids(bundle: &BundleV1<'_>) -> BTreeSet<u64> {
    bundle
        .covered_reveals()
        .iter()
        .map(|reveal| reveal.unit_id())
        .chain(bundle.noncovered_reveals().iter().map(|r| r.unit_id()))
        .collect()
}

/// `full(F) ⟺ N(F) ≠ ∅ ∧ N(F) ⊆ revealed`, re-derived the verifier's way
/// over this suite's own unit-table facts (D28 rider 1).
fn derived_full_files(facts: &[FileFact], revealed: &BTreeSet<u64>) -> BTreeSet<u64> {
    facts
        .iter()
        .filter(|fact| {
            !fact.normal.is_empty() && fact.normal.iter().all(|(id, ..)| revealed.contains(id))
        })
        .map(|fact| fact.file_id)
        .collect()
}

/// Property (b), structural half (plus the D28 exactness that makes the
/// check two-sided): the set of files carrying `full_reveals` material is
/// **exactly** the derived full set, and `s_root` presence inside each entry
/// matches fine-tree presence (D74).
fn check_full_material_exactness(
    facts: &[FileFact],
    bundle: &BundleV1<'_>,
    revealed: &BTreeSet<u64>,
) -> Result<(), String> {
    let full = derived_full_files(facts, revealed);
    let with_material: BTreeSet<u64> = bundle
        .full_reveals()
        .iter()
        .map(|entry| entry.file_id())
        .collect();
    if let Some(file_id) = with_material.difference(&full).next() {
        return Err(format!(
            "file {file_id} carries file_salt/s_root material without being fully revealed"
        ));
    }
    if let Some(file_id) = full.difference(&with_material).next() {
        return Err(format!(
            "file {file_id} is fully revealed but carries no full-reveal material"
        ));
    }
    for entry in bundle.full_reveals() {
        let fact = facts
            .iter()
            .find(|fact| fact.file_id == entry.file_id())
            .ok_or_else(|| format!("full-reveal entry names unknown file {}", entry.file_id()))?;
        if entry.disclosed_s_root().is_some() != fact.fine_tree {
            return Err(format!(
                "file {}: s_root presence ({}) disagrees with fine-tree presence ({})",
                fact.file_id,
                entry.disclosed_s_root().is_some(),
                fact.fine_tree
            ));
        }
    }
    Ok(())
}

/// Property (b), byte half: a not-fully-revealed file's derived `file_salt`
/// and fine seed appear **nowhere** in the encoded bundle — re-derived from
/// `W` here and window-scanned over the final bytes, independent of the
/// builder's own internal scan.
fn check_withheld_bytes(
    facts: &[FileFact],
    revealed: &BTreeSet<u64>,
    bytes: &[u8],
) -> Result<(), String> {
    let full = derived_full_files(facts, revealed);
    for fact in facts {
        if full.contains(&fact.file_id) {
            continue; // a full reveal discloses both legitimately
        }
        let file_id = FileId(fact.file_id);
        if contains(
            bytes,
            derive_file_salt(w(), file_id).expose_bytes_for_test_vectors(),
        ) {
            return Err(format!(
                "file {}: withheld file_salt bytes found in the encoded bundle",
                fact.file_id
            ));
        }
        if contains(bytes, derive_fine_seed(w(), file_id).as_bytes()) {
            return Err(format!(
                "file {}: withheld fine-seed (s_root) bytes found in the encoded bundle",
                fact.file_id
            ));
        }
    }
    Ok(())
}

/// Smallest `d <= 64` with `2^d >= n`, for `n >= 1` — written from the
/// spec's depth definition as a plain doubling loop, deliberately **not**
/// G's `leading_zeros` formula and never calling `depth_for_leaf_count`.
fn independent_depth(n: u64) -> u8 {
    let mut depth: u8 = 0;
    while (1u128 << depth) < u128::from(n) {
        depth += 1;
    }
    depth
}

/// The real-leaf span `[start, end)` of grid node `(level, index)` in a
/// depth-`depth` tree over `n` real leaves — `index · 2^(depth−level)` up to
/// the grid width, clipped to `n` (phantom slots commit nothing). `None`
/// when the node addresses no slot of this tree or spans no real leaf.
///
/// This suite's own arithmetic, from the D9 addressing definition ("the
/// bits of `index`, MSB-first, are the root-to-node path"); it never calls
/// `NodeAddress::first_slot`/`slot_width`/`covers_slot`.
fn real_leaf_span(level: u8, index: u64, depth: u8, n: u64) -> Option<(u64, u64)> {
    if level > depth {
        return None;
    }
    let width = 1u128 << (depth - level);
    let start = u128::from(index) * width;
    let end = (start + width).min(u128::from(n));
    if start >= end {
        return None;
    }
    // Both bounded by n: u64 by construction.
    Some((
        u64::try_from(start).expect("start < n <= u64::MAX"),
        u64::try_from(end).expect("end <= n <= u64::MAX"),
    ))
}

/// Merge `(start, length)` ranges into a sorted, coalesced `(start, end)`
/// union (revealed unit ranges are disjoint but may be adjacent).
fn merged_ranges(ranges: impl Iterator<Item = (u64, u64)>) -> Vec<(u64, u64)> {
    let mut spans: Vec<(u64, u64)> = ranges
        .filter(|(_, length)| *length > 0)
        .map(|(start, length)| (start, start + length))
        .collect();
    spans.sort_unstable();
    let mut merged: Vec<(u64, u64)> = Vec::with_capacity(spans.len());
    for (start, end) in spans {
        match merged.last_mut() {
            Some((_, last_end)) if start <= *last_end => *last_end = (*last_end).max(end),
            _ => merged.push((start, end)),
        }
    }
    merged
}

/// Is `[start, end)` fully inside the merged union?
fn span_within(union: &[(u64, u64)], start: u64, end: u64) -> bool {
    union
        .iter()
        .any(|(u_start, u_end)| start >= *u_start && end <= *u_end)
}

/// Property (b), ancestor half: **no emitted cover seed is an ancestor of
/// any unrevealed leaf** (MVP-SPEC.md line 96). Walks every covered
/// reveal's cover entries, maps each to its owning file through the unit
/// table, and requires the node's independently recomputed real-leaf span
/// to lie inside the union of the file's revealed normal-unit ranges.
fn check_cover_ancestry(
    facts: &[FileFact],
    bundle: &BundleV1<'_>,
    revealed: &BTreeSet<u64>,
) -> Result<(), String> {
    for reveal in bundle.covered_reveals() {
        let unit_id = reveal.unit_id();
        let fact = facts
            .iter()
            .find(|fact| fact.unit_ids().any(|id| id == unit_id))
            .ok_or_else(|| format!("covered reveal for unit {unit_id} names no manifest unit"))?;
        if !fact.fine_tree || fact.size == 0 {
            return Err(format!(
                "file {}: covered reveal for unit {unit_id}, but the file has no fine tree",
                fact.file_id
            ));
        }
        let depth = independent_depth(fact.size);
        let union = merged_ranges(
            fact.normal
                .iter()
                .filter(|(id, ..)| revealed.contains(id))
                .map(|(_, start, length)| (*start, *length)),
        );
        for entry in reveal.cover() {
            let (level, index) = (entry.address().level(), entry.address().index());
            let Some((start, end)) = real_leaf_span(level, index, depth, fact.size) else {
                return Err(format!(
                    "file {}: cover node ({level}, {index}) of unit {unit_id} addresses no real \
                     leaf of a depth-{depth}, n = {} tree",
                    fact.file_id, fact.size
                ));
            };
            if !span_within(&union, start, end) {
                return Err(format!(
                    "file {}: cover node ({level}, {index}) of unit {unit_id} spans real leaves \
                     [{start}, {end}), which are NOT all revealed — that seed opens an \
                     unrevealed leaf",
                    fact.file_id
                ));
            }
        }
    }
    Ok(())
}

/// Property (c), both directions (D70 §§4, 7.7): a revealed mirror implies
/// its file is fully revealed **and** every fully revealed mirror-bearing
/// file's mirror is emitted — mirror-presence re-derived from the unit
/// table's `UnitKind::RawMirror` rows, never from the builder's predicate.
/// A mirror must also only ever be a **non-covered** entry (registry §7.12).
fn check_mirror_rides(
    facts: &[FileFact],
    bundle: &BundleV1<'_>,
    revealed: &BTreeSet<u64>,
) -> Result<(), String> {
    let full = derived_full_files(facts, revealed);
    let covered: BTreeSet<u64> = bundle
        .covered_reveals()
        .iter()
        .map(|reveal| reveal.unit_id())
        .collect();
    for fact in facts {
        for &mirror_id in &fact.mirrors {
            if covered.contains(&mirror_id) {
                return Err(format!(
                    "file {}: mirror unit {mirror_id} emitted as a covered reveal",
                    fact.file_id
                ));
            }
            let emitted = revealed.contains(&mirror_id);
            let is_full = full.contains(&fact.file_id);
            if emitted && !is_full {
                return Err(format!(
                    "file {}: mirror unit {mirror_id} emitted without a full reveal",
                    fact.file_id
                ));
            }
            if is_full && !emitted {
                return Err(format!(
                    "file {}: fully revealed with manifest mirror unit {mirror_id}, but the \
                     mirror was not emitted",
                    fact.file_id
                ));
            }
        }
    }
    Ok(())
}

/// Property (d), structural half: the `touched_files` section names
/// **exactly** the files with at least one revealed unit.
fn check_touched_exactness(
    facts: &[FileFact],
    bundle: &BundleV1<'_>,
    revealed: &BTreeSet<u64>,
) -> Result<(), String> {
    let touched_entries = bundle.touched_files();
    let touched: BTreeSet<u64> = touched_entries.iter().map(|file| file.file_id()).collect();
    if touched.len() != touched_entries.len() {
        return Err("duplicate touched_files entries".to_owned());
    }
    let should: BTreeSet<u64> = facts
        .iter()
        .filter(|fact| fact.unit_ids().any(|id| revealed.contains(&id)))
        .map(|fact| fact.file_id)
        .collect();
    if let Some(file_id) = touched.difference(&should).next() {
        return Err(format!(
            "file {file_id}: path disclosed (touched_files entry) although no unit of it is \
             revealed"
        ));
    }
    if let Some(file_id) = should.difference(&touched).next() {
        return Err(format!(
            "file {file_id}: units revealed but no touched_files entry"
        ));
    }
    Ok(())
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

// ---------------------------------------------------------------------------
// generators: randomized works × randomized valid selections
// ---------------------------------------------------------------------------
//
// Local to this file per Q3 §2's promotion criterion (no second consumer
// yet); modeled on R6's own spec generator and F16's `arb_bundle_bytes`, and
// built ON R6's `WorkSpec`/`FileSpec` rather than on a second constructor.

/// One file, as independent draws: `(text?, content source, no fine tree?,
/// split-pieces intent, plan mode, subset mask)`.
type FileGen = (bool, Vec<u8>, bool, u8, u8, u64);

fn arb_file_gen() -> impl Strategy<Value = FileGen> {
    (
        any::<bool>(),
        proptest::collection::vec(any::<u8>(), 0..=24),
        any::<bool>(),
        0u8..=4,
        0u8..=7,
        any::<u64>(),
    )
}

/// Map arbitrary bytes onto R6's four-symbol text alphabet — always valid
/// UTF-8, and rich in CR/LF so raw-mirror-bearing files are generated
/// often (the same mapping R6's own property generator uses).
fn text_bytes(source: &[u8]) -> Vec<u8> {
    source
        .iter()
        .map(|byte| match byte % 4 {
            0 => b'\r',
            1 => b'\n',
            2 => b'a',
            _ => b' ',
        })
        .collect()
}

/// The tiling-domain length a spec will resolve to: canonical bytes for
/// text (the same `canonicalize_v` call `bundle_fixtures::plan_file` makes,
/// so a drift panics loudly inside `build` rather than mis-tiling), raw for
/// binary.
fn tiling_len_of(text: bool, raw: &[u8]) -> u64 {
    if text {
        canonicalize_v(UNICODE_17_0_0, TextMode::Forced, raw)
            .expect("generator text canonicalizes under forced mode")
            .into_bytes()
            .len() as u64
    } else {
        raw.len() as u64
    }
}

/// Near-equal `--split` widths: `pieces` positive widths summing to
/// `tiling`, or `None` when the intent does not fit.
fn split_widths(tiling: u64, pieces: u8) -> Option<Vec<u64>> {
    let pieces = u64::from(pieces);
    if pieces < 2 || tiling < pieces {
        return None;
    }
    let base = tiling / pieces;
    let extra = tiling % pieces;
    Some((0..pieces).map(|i| base + u64::from(i < extra)).collect())
}

/// Resolve one file's plan intent against its known normal-unit count.
///
/// Modes: untouched / full / units-naming-every-normal-unit (the D70 §7.6
/// promotion — an `--all` equivalent spelled as `--units`) / random
/// non-empty subset (which may itself name every unit, promoting too).
fn plan_for(mode: u8, mask: u64, normal_count: usize, path: &str) -> FilePlan {
    match mode {
        0 | 1 => FilePlan::Untouched,
        2 | 3 => FilePlan::full(path),
        4 => FilePlan::units(path, 0..normal_count),
        _ => {
            let mut picks: BTreeSet<usize> = (0..normal_count)
                .filter(|index| (mask >> (index % 64)) & 1 == 1)
                .collect();
            if picks.is_empty() {
                let fallback = mask % u64::try_from(normal_count).expect("small");
                picks.insert(usize::try_from(fallback).expect("small"));
            }
            FilePlan::units(path, picks)
        }
    }
}

/// Materialize drawn `FileGen`s into specs + plans, with paths
/// `<prefix><index>.<txt|bin>` (unique, fixed-length, so property (d)'s
/// withheld-path byte scan cannot alias across files).
fn materialize_files(gens: &[FileGen], prefix: &str) -> (Vec<FileSpec>, Vec<FilePlan>) {
    let mut specs = Vec::with_capacity(gens.len());
    let mut plans = Vec::with_capacity(gens.len());
    for (index, (text, source, no_tree, pieces, mode, mask)) in gens.iter().enumerate() {
        let path = if *text {
            format!("{prefix}{index}.txt")
        } else {
            format!("{prefix}{index}.bin")
        };
        let raw = if *text {
            text_bytes(source)
        } else {
            source.clone()
        };
        let tiling = tiling_len_of(*text, &raw);
        let mut spec = if *text {
            FileSpec::text(&path, raw)
        } else {
            FileSpec::binary(&path, raw)
        };
        if *no_tree {
            spec = spec.without_fine_tree();
        }
        let mut normal_count = 1usize;
        if let Some(widths) = split_widths(tiling, *pieces) {
            normal_count = widths.len();
            spec = spec.split(widths);
        }
        specs.push(spec);
        plans.push(plan_for(*mode, *mask, normal_count, &path));
    }
    (specs, plans)
}

/// A randomized synthetic work × a randomized **valid** selection: 1–3
/// files across text/binary, mirror-bearing and already-canonical text,
/// fine-tree opt-outs, multi-unit splits, empty and one-byte contents;
/// per-file plans across untouched / subsets / enumerated-full / full; all
/// four anchor-set shapes (receipt in and out); randomized fixture seed.
fn arb_scenario() -> impl Strategy<Value = (WorkSpec, RevealPlan)> {
    (
        proptest::collection::vec(arb_file_gen(), 1..=3),
        any::<u64>(),
        0u8..=3,
    )
        .prop_map(|(gens, seed, anchors)| {
            let (specs, plans) = materialize_files(&gens, "gen/f");
            let anchors = match anchors {
                0 => AnchorSet::Empty,
                1 => AnchorSet::OneOtsTwoTsa,
                2 => AnchorSet::EveryKind { receipt: true },
                _ => AnchorSet::EveryKind { receipt: false },
            };
            let spec = WorkSpec::new("R14 property work", specs)
                .with_seed(seed)
                .with_anchors(anchors)
                .with_ed25519_only_policy();
            (spec, RevealPlan::new(plans))
        })
}

// ---------------------------------------------------------------------------
// property (a): every built bundle passes verify_bundle
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(scenario_config(0x5EED_1441, 64))]

    /// **R14 (a).** The builder already self-checks; this asserts the
    /// RESULT from outside — the returned bytes pass `verify_bundle` under
    /// default options and the evidence layer reports `passed` — so the
    /// property stands on its own rather than trusting the internal gate.
    #[test]
    fn every_built_bundle_passes_verify_bundle(
        (spec, plan) in arb_scenario()
    ) {
        let harness = Harness::new(&spec);
        let bytes = match build_bundle(harness.inputs(&plan)) {
            Ok(bytes) => bytes,
            Err(error) => {
                prop_assert!(false, "an honest scenario must build: {error}");
                return Ok(());
            }
        };
        match verify_bundle(&bytes, &VerifyOptions::new()) {
            Ok(report) => prop_assert!(report.evidence.passed),
            Err(error) => prop_assert!(
                false,
                "built bundle failed verification with `{}`: {error}",
                error.code()
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// property (b): partial-reveal isolation, including the ancestor-seed rule
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(scenario_config(0x5EED_1442, 64))]

    /// **R14 (b).** For every file short of a full reveal: no `file_salt`,
    /// no `s_root` (structurally, via the two-sided material-exactness
    /// check, and byte-wise, via a from-`W` window scan of the encoded
    /// output), and no emitted GGM cover seed whose independently
    /// recomputed leaf span reaches an unrevealed leaf.
    #[test]
    fn partial_reveals_withhold_full_material_and_every_ancestor_seed(
        (spec, plan) in arb_scenario()
    ) {
        let harness = Harness::new(&spec);
        let bytes = match build_bundle(harness.inputs(&plan)) {
            Ok(bytes) => bytes,
            Err(error) => {
                prop_assert!(false, "an honest scenario must build: {error}");
                return Ok(());
            }
        };
        let proof = SealProof::decode(&bytes).expect("built bundle decodes");
        let facts = facts_of(proof.manifest().body());
        let revealed = revealed_ids(proof.bundle());

        if let Err(why) = check_full_material_exactness(&facts, proof.bundle(), &revealed) {
            prop_assert!(false, "{}", why);
        }
        if let Err(why) = check_withheld_bytes(&facts, &revealed, &bytes) {
            prop_assert!(false, "{}", why);
        }
        if let Err(why) = check_cover_ancestry(&facts, proof.bundle(), &revealed) {
            prop_assert!(false, "{}", why);
        }
    }
}

// ---------------------------------------------------------------------------
// property (c): mirrors ride exactly with full-file reveals (D70, both arms)
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(scenario_config(0x5EED_1443, 64))]

    /// **R14 (c), forward + the D70 §7.7 converse.** Every emitted mirror
    /// belongs to a derived-full file, every derived-full file whose unit
    /// table records a `RawMirror` unit has that unit emitted, and a mirror
    /// only ever appears as a non-covered entry — with mirror presence and
    /// `full(F)` both re-derived from the decoded manifest, never from the
    /// builder's own resolution or the `RevealPlan`.
    #[test]
    fn mirrors_ride_exactly_with_full_file_reveals(
        (spec, plan) in arb_scenario()
    ) {
        let harness = Harness::new(&spec);
        let bytes = match build_bundle(harness.inputs(&plan)) {
            Ok(bytes) => bytes,
            Err(error) => {
                prop_assert!(false, "an honest scenario must build: {error}");
                return Ok(());
            }
        };
        let proof = SealProof::decode(&bytes).expect("built bundle decodes");
        let facts = facts_of(proof.manifest().body());
        let revealed = revealed_ids(proof.bundle());
        if let Err(why) = check_mirror_rides(&facts, proof.bundle(), &revealed) {
            prop_assert!(false, "{}", why);
        }
    }
}

// ---------------------------------------------------------------------------
// property (d): paths (and path salts) only for touched files
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(scenario_config(0x5EED_1444, 64))]

    /// **R14 (d).** `touched_files` names exactly the files with a revealed
    /// unit; each disclosed path is the plan's own; and an untouched file
    /// leaves no trace — neither its vault path string (which the builder
    /// was never even handed: `FilePlan::Untouched` has no path slot) nor
    /// its derived `path_salt` appears anywhere in the encoded bundle.
    #[test]
    fn paths_and_path_salts_are_disclosed_only_for_touched_files(
        (spec, plan) in arb_scenario()
    ) {
        let harness = Harness::new(&spec);
        let bytes = match build_bundle(harness.inputs(&plan)) {
            Ok(bytes) => bytes,
            Err(error) => {
                prop_assert!(false, "an honest scenario must build: {error}");
                return Ok(());
            }
        };
        let proof = SealProof::decode(&bytes).expect("built bundle decodes");
        let facts = facts_of(proof.manifest().body());
        let revealed = revealed_ids(proof.bundle());

        if let Err(why) = check_touched_exactness(&facts, proof.bundle(), &revealed) {
            prop_assert!(false, "{}", why);
        }

        for (index, choice) in plan.files().iter().enumerate() {
            let file_id = index as u64;
            let spec_path = spec.files[index].path();
            match choice {
                FilePlan::Untouched => {
                    prop_assert!(
                        !contains(&bytes, spec_path.as_bytes()),
                        "file {}: untouched, but its vault path appears in the bundle",
                        file_id
                    );
                    prop_assert!(
                        !contains(&bytes, derive_path_salt(w(), FileId(file_id)).as_bytes()),
                        "file {}: untouched, but its path_salt appears in the bundle",
                        file_id
                    );
                }
                FilePlan::Units { path, .. } | FilePlan::Full { path } => {
                    let entry = proof
                        .bundle()
                        .touched_files()
                        .iter()
                        .find(|file| file.file_id() == file_id)
                        .expect("touched exactness above guarantees the entry");
                    prop_assert_eq!(
                        entry.path(),
                        path.as_str(),
                        "file {}: disclosed path is not the plan's",
                        file_id
                    );
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// negative control (R14 Accept, bullet 3): every forcing-seam variant, on
// randomized works, refused with its exact error
// ---------------------------------------------------------------------------

/// A work in which **every** force variant has an eligible target, so no
/// case ever skips a row of the seam's force→guard→error table: file 0 is a
/// mirror-bearing two-unit fine-tree text file revealed partially, file 1 a
/// mirror-bearing text file revealed fully, the donor carries an opted-in
/// receipt, plus 0–2 random extra files for shape noise. Returns the plan
/// and file 0's revealed normal-unit index.
fn arb_negative_scenario() -> impl Strategy<Value = (WorkSpec, RevealPlan, usize)> {
    (
        proptest::collection::vec(any::<u8>(), 0..=12),
        proptest::collection::vec(any::<u8>(), 0..=12),
        proptest::collection::vec(arb_file_gen(), 0..=2),
        any::<u64>(),
        any::<u8>(),
    )
        .prop_map(|(a_tail, b_tail, extra_gens, seed, pick)| {
            // "a\r\n" forces a raw mirror (CR never survives
            // canonicalization) and a canonical length of at least 2, so
            // the [1, rest] split below always tiles into exactly 2 units.
            let a_raw = [b"a\r\n".as_slice(), &text_bytes(&a_tail)].concat();
            let b_raw = [b"b\r\n".as_slice(), &text_bytes(&b_tail)].concat();
            let a_tiling = tiling_len_of(true, &a_raw);
            let a_spec = FileSpec::text("neg/a.txt", a_raw).split(vec![1, a_tiling - 1]);
            let b_spec = FileSpec::text("neg/b.txt", b_raw);

            let revealed_index = usize::from(pick) % 2;
            let (extra_specs, extra_plans) = materialize_files(&extra_gens, "neg/x");

            let mut specs = vec![a_spec, b_spec];
            specs.extend(extra_specs);
            let mut plans = vec![
                FilePlan::units("neg/a.txt", [revealed_index]),
                FilePlan::full("neg/b.txt"),
            ];
            plans.extend(extra_plans);

            let spec = WorkSpec::new("R14 negative-control work", specs)
                .with_seed(seed)
                .with_anchors(AnchorSet::EveryKind { receipt: true })
                .with_ed25519_only_policy();
            (spec, RevealPlan::new(plans), revealed_index)
        })
}

proptest! {
    #![proptest_config(scenario_config(0x5EED_1445, 32))]

    /// **R14's negative control, as a property.** For randomized works, each
    /// of the forcing seam's variants (its module-docs force→guard→error
    /// table) is applied one at a time and must be refused with **exactly**
    /// the error that table names — variant and ids, so an assertion cannot
    /// pass for the wrong reason. The unforced build is asserted to succeed
    /// first: the refusals below are then attributable to the force alone.
    #[test]
    fn forcing_each_forbidden_emission_is_refused_with_its_exact_error(
        (spec, plan, revealed_index) in arb_negative_scenario()
    ) {
        let harness = Harness::new(&spec);

        // Baseline: the case itself is honest and buildable.
        match build_bundle(harness.inputs(&plan)) {
            Ok(_) => {}
            Err(error) => {
                prop_assert!(false, "the unforced scenario must build: {error}");
                return Ok(());
            }
        }

        // Target ids, from this suite's own unit-table walk.
        let decoded = Manifest::decode(&harness.manifest).expect("manifest decodes");
        let facts = facts_of(decoded.body());
        let a_mirror = *facts[0].mirrors.first().expect("file 0 carries a mirror");
        let b_mirror = *facts[1].mirrors.first().expect("file 1 carries a mirror");
        let a_revealed_unit = facts[0].normal[revealed_index].0;

        // `Force::leak_full_material` → the mandatory self-check, with R4's
        // frozen partial-isolation code (file_salt precedes s_root when both
        // leak — the file-stage row order, pinned by R4's own tests).
        let mut force = Force::none();
        force.leak_full_material = Some(0);
        match build_bundle_forced(harness.inputs(&plan), &force) {
            Err(BuildError::SelfCheck { source }) => {
                prop_assert_eq!(source.code(), "partial-reveal-salt-leak-file-salt");
            }
            Ok(_) => prop_assert!(false, "leak_full_material must not build"),
            Err(other) => prop_assert!(false, "leak_full_material: wrong refusal: {}", other),
        }

        // `Force::omit_mirror` → the converse internal assertion (the
        // verifier ACCEPTS the mirror-less full reveal, so `SelfCheck` here
        // would mean the wrong guard fired).
        let mut force = Force::none();
        force.omit_mirror = Some(1);
        match build_bundle_forced(harness.inputs(&plan), &force) {
            Err(BuildError::MirrorMissingFromFullReveal { file_id, unit_id }) => {
                prop_assert_eq!((file_id, unit_id), (1, b_mirror));
            }
            Ok(_) => prop_assert!(false, "omit_mirror must not build"),
            Err(other) => prop_assert!(false, "omit_mirror: wrong refusal: {}", other),
        }

        // `Force::emit_mirror_for` → the forward internal assertion (the
        // verifier ACCEPTS the R53 partial-with-mirror shape).
        let mut force = Force::none();
        force.emit_mirror_for = Some(0);
        match build_bundle_forced(harness.inputs(&plan), &force) {
            Err(BuildError::MirrorEmittedWithoutFullReveal { file_id, unit_id }) => {
                prop_assert_eq!((file_id, unit_id), (0, a_mirror));
            }
            Ok(_) => prop_assert!(false, "emit_mirror_for must not build"),
            Err(other) => prop_assert!(false, "emit_mirror_for: wrong refusal: {}", other),
        }

        // `Force::drop_receipt` → receipt ⟺ opted, the opted-in direction.
        let mut force = Force::none();
        force.drop_receipt = true;
        match build_bundle_forced(harness.inputs(&plan), &force) {
            Err(BuildError::ReceiptPresenceMismatch { opted }) => prop_assert!(opted),
            Ok(_) => prop_assert!(false, "drop_receipt must not build"),
            Err(other) => prop_assert!(false, "drop_receipt: wrong refusal: {}", other),
        }

        // `Force::inject_receipt` → the not-opted direction, against the
        // same donor with the caller's opt-in cleared.
        let mut force = Force::none();
        force.inject_receipt = true;
        let mut inputs = harness.inputs(&plan);
        inputs.receipt = None;
        match build_bundle_forced(inputs, &force) {
            Err(BuildError::ReceiptPresenceMismatch { opted }) => prop_assert!(!opted),
            Ok(_) => prop_assert!(false, "inject_receipt must not build"),
            Err(other) => prop_assert!(false, "inject_receipt: wrong refusal: {}", other),
        }

        // `Force::smuggle`, one per scanned material class — the carrier is
        // an anchor artifact, whose bytes never fail verification (D84 rule
        // F2), so only the builder's own byte scan can refuse.
        for (smuggle, expected) in [
            (
                Smuggle::FileSalt(0),
                ForbiddenMaterial::FileSalt { file_id: 0 },
            ),
            (
                Smuggle::FineSeed(0),
                ForbiddenMaterial::FineSeed { file_id: 0 },
            ),
            (
                Smuggle::UnitNonce(a_revealed_unit),
                ForbiddenMaterial::UnitNonce {
                    unit_id: a_revealed_unit,
                },
            ),
        ] {
            let mut force = Force::none();
            force.smuggle = Some(smuggle);
            match build_bundle_forced(harness.inputs(&plan), &force) {
                Err(BuildError::ForbiddenBytesInEncoding { material }) => {
                    prop_assert_eq!(material, expected);
                }
                Ok(_) => prop_assert!(false, "smuggle {:?} must not build", smuggle),
                Err(other) => {
                    prop_assert!(false, "smuggle {:?}: wrong refusal: {}", smuggle, other);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// the checkers can fail (guards the guards' guard)
// ---------------------------------------------------------------------------

/// Plant one violation per checker and prove the **independent checker**
/// flags it — a checker that cannot fail is not a check. The plants come
/// from the only seams able to produce violating *bytes*: R6's fixture-only
/// selections and `Tweak`s (the production forcing seam refuses before
/// returning bytes — that refusal is the negative-control property above).
#[test]
fn the_independent_checkers_flag_planted_violations() {
    let split = shapes::split_multi_unit(); // 3 normal units + raw mirror
    let partial = FixtureSelection(vec![FixtureFileSelection::Units(vec![1])]);

    // Plant 1 — full material on a partially revealed file: both the
    // structural exactness check and the from-`W` byte scan must fire.
    let mut tweak = Tweak::none();
    tweak.leak_full_material = Some(0);
    let planted = build_tweaked(&split, &partial, &tweak);
    let proof = SealProof::decode(&planted.bytes).expect("plant 1 decodes");
    let facts = facts_of(proof.manifest().body());
    let revealed = revealed_ids(proof.bundle());
    let refused = check_full_material_exactness(&facts, proof.bundle(), &revealed)
        .expect_err("plant 1: leaked full material must be flagged");
    assert!(
        refused.contains("file 0"),
        "plant 1 names the file: {refused}"
    );
    assert!(
        check_withheld_bytes(&facts, &revealed, &planted.bytes).is_err(),
        "plant 1: the leaked file_salt bytes must be found by the scan"
    );

    // Plant 2 — the R53 partial-with-mirror shape (fixture-only selection;
    // the verifier ACCEPTS it): the forward mirror arm must fire.
    let planted = fixture_build(
        &split,
        &FixtureSelection(vec![FixtureFileSelection::UnitsWithMirror(vec![1])]),
    );
    let proof = SealProof::decode(&planted.bytes).expect("plant 2 decodes");
    let facts = facts_of(proof.manifest().body());
    let revealed = revealed_ids(proof.bundle());
    let refused = check_mirror_rides(&facts, proof.bundle(), &revealed)
        .expect_err("plant 2: a partial reveal's mirror must be flagged");
    assert!(
        refused.contains("without a full reveal"),
        "plant 2 names the forward arm: {refused}"
    );

    // Plant 3 — the mirror-less full reveal (fixture-only selection; a
    // frozen ACCEPTED verifier vector): the converse arm must fire.
    let planted = fixture_build(
        &shapes::single_text_with_mirror(),
        &FixtureSelection(vec![FixtureFileSelection::FullNoMirror]),
    );
    let proof = SealProof::decode(&planted.bytes).expect("plant 3 decodes");
    let facts = facts_of(proof.manifest().body());
    let revealed = revealed_ids(proof.bundle());
    let refused = check_mirror_rides(&facts, proof.bundle(), &revealed)
        .expect_err("plant 3: a withheld mirror on a full reveal must be flagged");
    assert!(
        refused.contains("was not emitted"),
        "plant 3 names the converse arm: {refused}"
    );

    // Plant 4 — an over-wide cover in real bytes: the mirror misplaced into
    // `covered_reveals` carries unit 0's genuine cover while only unit 1 is
    // revealed, so its seeds are ancestors of unrevealed leaves.
    let donor = fixture_build(&split, &FixtureSelection::all(1));
    let mirror_id = donor.files[0]
        .mirror_unit_id
        .expect("split_multi_unit carries a mirror");
    let mut tweak = Tweak::none();
    tweak.misplace_noncovered_unit = Some(mirror_id);
    let planted = build_tweaked(
        &split,
        &FixtureSelection(vec![FixtureFileSelection::UnitsWithMirror(vec![1])]),
        &tweak,
    );
    let proof = SealProof::decode(&planted.bytes).expect("plant 4 decodes");
    let facts = facts_of(proof.manifest().body());
    let revealed = revealed_ids(proof.bundle());
    let refused = check_cover_ancestry(&facts, proof.bundle(), &revealed)
        .expect_err("plant 4: a cover seed over unrevealed leaves must be flagged");
    assert!(
        refused.contains("unrevealed leaf"),
        "plant 4 names the ancestor rule: {refused}"
    );

    // Plant 5 — the D82 shape: an impeccable touched_files entry for a file
    // the selection reveals nothing of. The touched-exactness arm must fire.
    let multi = shapes::multi_file();
    let mut tweak = Tweak::none();
    tweak.touch_without_reveal = Some(2);
    let planted = build_tweaked(
        &multi,
        &FixtureSelection(vec![
            FixtureFileSelection::Full,
            FixtureFileSelection::Untouched,
            FixtureFileSelection::Untouched,
        ]),
        &tweak,
    );
    let proof = SealProof::decode(&planted.bytes).expect("plant 5 decodes");
    let facts = facts_of(proof.manifest().body());
    let revealed = revealed_ids(proof.bundle());
    let refused = check_touched_exactness(&facts, proof.bundle(), &revealed)
        .expect_err("plant 5: a touched entry without a reveal must be flagged");
    assert!(
        refused.contains("file 2"),
        "plant 5 names the file: {refused}"
    );

    // Plant 6 — the ancestor arithmetic core in isolation: the root node of
    // a depth-2, n = 3 tree spans [0, 3); with only leaf 0 revealed it must
    // be refused, and under a full reveal it must be accepted (so the core
    // can both fire and not fire).
    assert_eq!(real_leaf_span(0, 0, 2, 3), Some((0, 3)));
    let partial_union = merged_ranges([(0u64, 1u64)].into_iter());
    assert!(
        !span_within(&partial_union, 0, 3),
        "the root span must not fit inside a partial reveal"
    );
    let full_union = merged_ranges([(0u64, 1u64), (1, 1), (2, 1)].into_iter());
    assert!(
        span_within(&full_union, 0, 3),
        "the root span must fit inside a full reveal"
    );
    // Phantom-slot clipping: at depth 2 over n = 3, node (1, 1) spans the
    // real leaf 2 alone; node (2, 3) is the phantom slot and spans nothing.
    assert_eq!(real_leaf_span(1, 1, 2, 3), Some((2, 3)));
    assert_eq!(real_leaf_span(2, 3, 2, 3), None);
    // The n = 1 degenerate grid: the root IS the only leaf.
    assert_eq!(real_leaf_span(0, 0, 0, 1), Some((0, 1)));
    // An address below the tree's depth names no slot of it.
    assert_eq!(real_leaf_span(3, 0, 2, 3), None);
}

// ---------------------------------------------------------------------------
// deterministic antecedent coverage: the checkers over the shapes catalogue
// ---------------------------------------------------------------------------

/// Map a fixture selection onto a builder plan; `None` marks the two
/// fixture-only shapes the production API is structurally unable to express
/// (D70 §7.1). Exhaustive match on purpose: a new fixture-only variant
/// fails compilation here instead of silently thinning this sweep.
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

/// Run every independent checker over every expressible catalogue case,
/// built through the real `build_bundle` — a deterministic guarantee that
/// the property blocks' antecedents (partial covered reveals, full
/// mirror-bearing reveals, `--no-fine-tree` reveals, untouched files, the
/// empty file) are genuinely reached, so no property above can go green by
/// never meeting its precondition (the F16 coverage-assertion lesson).
#[test]
fn every_expressible_catalogue_case_passes_the_independent_checkers() {
    let mut skipped: Vec<&'static str> = Vec::new();
    let mut saw_partial_covered = false;
    let mut saw_full_with_mirror = false;
    let mut saw_no_fine_tree_reveal = false;
    let mut saw_untouched = false;
    let mut saw_empty_touched = false;

    for case in shapes::catalogue() {
        let Some(plan) = plan_from_fixture(&case.spec, &case.selection) else {
            skipped.push(case.name);
            continue;
        };
        let harness = Harness::new(&case.spec);
        let bytes = build_bundle(harness.inputs(&plan))
            .unwrap_or_else(|error| panic!("case `{}` must build: {error}", case.name));
        let proof = SealProof::decode(&bytes).expect("built bundle decodes");
        let facts = facts_of(proof.manifest().body());
        let revealed = revealed_ids(proof.bundle());

        for (checker_name, verdict) in [
            (
                "full-material exactness",
                check_full_material_exactness(&facts, proof.bundle(), &revealed),
            ),
            (
                "withheld bytes",
                check_withheld_bytes(&facts, &revealed, &bytes),
            ),
            (
                "cover ancestry",
                check_cover_ancestry(&facts, proof.bundle(), &revealed),
            ),
            (
                "mirror rides",
                check_mirror_rides(&facts, proof.bundle(), &revealed),
            ),
            (
                "touched exactness",
                check_touched_exactness(&facts, proof.bundle(), &revealed),
            ),
        ] {
            if let Err(why) = verdict {
                panic!(
                    "case `{}` fails the {checker_name} checker: {why}",
                    case.name
                );
            }
        }

        let full = derived_full_files(&facts, &revealed);
        let covered_files: BTreeSet<u64> = proof
            .bundle()
            .covered_reveals()
            .iter()
            .filter_map(|reveal| {
                facts
                    .iter()
                    .find(|fact| fact.unit_ids().any(|id| id == reveal.unit_id()))
                    .map(|fact| fact.file_id)
            })
            .collect();
        for fact in &facts {
            let touched = fact.unit_ids().any(|id| revealed.contains(&id));
            let is_full = full.contains(&fact.file_id);
            saw_partial_covered |= touched && !is_full && covered_files.contains(&fact.file_id);
            saw_full_with_mirror |= is_full && !fact.mirrors.is_empty();
            saw_no_fine_tree_reveal |= touched && !fact.fine_tree && fact.size > 0;
            saw_untouched |= !touched;
            saw_empty_touched |= touched && fact.size == 0;
        }
    }

    // The sweep's own completeness: exactly the two D70 §7.1 inexpressible
    // shapes are skipped (this is the sweep's validity condition — asserted
    // here for the sweep, independently of R13's parity test asserting the
    // same fact for parity).
    assert_eq!(
        skipped,
        [
            "single-text-with-mirror/full-no-mirror",
            "split-multi-unit/partial-with-mirror",
        ],
        "the set of fixture-only shapes this sweep must skip has changed"
    );
    assert!(saw_partial_covered, "no partial covered reveal reached");
    assert!(
        saw_full_with_mirror,
        "no full mirror-bearing reveal reached"
    );
    assert!(saw_no_fine_tree_reveal, "no --no-fine-tree reveal reached");
    assert!(saw_untouched, "no untouched file reached");
    assert!(saw_empty_touched, "no empty-file reveal reached");
}
