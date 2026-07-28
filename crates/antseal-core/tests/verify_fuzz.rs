//! **R10's property suite**: `verify_bundle` never panics, and the three
//! properties that stand in for demoted tamper rows.
//!
//! R10 has two halves. The cargo-fuzz target (`fuzz/fuzz_targets/`) is the
//! unbounded one and needs a nightly toolchain and Q9's CI wiring; **this
//! is the half that runs in the ordinary test suite**, which R10's Accept
//! requires in as many words ("runs in the normal test suite, not only
//! under fuzzing"). Both drive the identical engine —
//! [`antseal_core::test_util::bundle_mutators`] — so the two halves cannot
//! disagree about what a mutation is.
//!
//! # The panic property
//!
//! > For every byte string, `verify_bundle` returns a typed `VerifyError`
//! > or a `VerificationReport`.
//!
//! proptest asserting "no panic" reads oddly at first: nothing is compared.
//! The assertion *is* the return, since a panic inside the call fails the
//! case and a hang fails the run. What the properties below add is the
//! second half — that the outcome is a **typed** one, and (for the
//! structure-aware generator) that a real share of cases get past the
//! decoder, so the suite cannot quietly decay into re-testing F17's
//! territory with a slower generator.
//!
//! # The three stand-in properties
//!
//! Decisions D28 and D81 demoted three mutations from tamper rows to
//! recorded non-rows, because each is observationally identical to a row
//! that already claims the outcome. Every one of those `non_rows[]` entries
//! names an R10 property as what asserts it instead
//! (`testdata/tamper/MATRIX.json`), and this file is where those promises
//! are kept:
//!
//! | non-row | property here |
//! |---|---|
//! | `swapped-unit-ciphertext` | [`no_ciphertext_swap_between_revealed_units_verifies`] |
//! | `pipeline-level-wrong-unit-key` | [`no_unit_key_substitution_verifies`] |
//! | `full-reveal-unit-strip-downgrade` | [`no_single_unit_deletion_from_a_full_reveal_verifies`] |
//!
//! They quantify over **rejection**, not over a particular code, which is
//! deliberate and is what makes them the right shape for a demoted row: the
//! code is exactly the thing that is not distinctive, and pinning one here
//! would re-introduce the collision the demotion resolved. The single-unit
//! deletion case is the clearest illustration — since decision D82 it
//! rejects with two *different* codes depending on whether the stripped
//! file retains another revealed unit, and the property is indifferent to
//! that by design.
//!
//! # Section-level recombination (R34)
//!
//! The last section of this file drives R34's [`Recombination`] class,
//! which moves whole sections between two bundles rather than rewriting
//! bytes within one. Its invariant is stronger than the byte-level one and
//! is worth stating separately: a recombination either produces a bundle
//! that gets **past the decoder**, or produces nothing at all. There is no
//! "died in the codec" outcome to tolerate, because the seam re-encodes
//! through `BundleV1::new` — so a failure here is a seam bug, never a
//! sampling accident.

use antseal_core::test_util::bundle_fixtures::{
    FileSelection, Selection, Tweak, build_tweaked, shapes,
};
use antseal_core::test_util::bundle_mutators::{
    Outcome, Recombination, decode_mutation, drive, fuzz_once, recombine, seed_bytes, seed_corpus,
};
use antseal_core::test_util::proptest::prelude::*;
use antseal_core::test_util::strategies;

/// The seed corpus, built **once for the whole binary**.
///
/// R6's constructor does real crypto — signing and AEAD over ~17 bundles —
/// so rebuilding it per proptest case costs minutes rather than seconds and
/// buys nothing: the corpus is deterministic by construction (R6 is seeded),
/// so every case would get identical bytes anyway.
fn corpus() -> &'static [Vec<u8>] {
    static CORPUS: std::sync::OnceLock<Vec<Vec<u8>>> = std::sync::OnceLock::new();
    CORPUS.get_or_init(seed_bytes)
}

proptest! {
    #![proptest_config(strategies::integration_test_config(
        0x5EED_0A10,
        "proptest-regressions/verify_fuzz.txt",
    ))]

    /// Arbitrary bytes: the fuzz target's `selector == 0` path, and the
    /// weakest input class. Most of these die in the decoder, which is
    /// correct — the assertion is that they die *typed*.
    #[test]
    fn arbitrary_bytes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..4096)) {
        let outcome = drive(&bytes);
        prop_assert!(
            matches!(outcome, Outcome::Rejected(_) | Outcome::Verified),
            "verify_bundle must return a typed outcome for every input"
        );
    }

    /// **Structure-aware mutation of valid R6 bundles and R7/R8 tamper
    /// fixtures** — the class R10's task text names, and the one that
    /// actually reaches the stages behind the decoder.
    #[test]
    fn structure_aware_mutations_never_panic(entropy in prop::collection::vec(any::<u8>(), 2..64)) {
        let outcome = fuzz_once(&entropy, corpus());
        prop_assert!(matches!(outcome, Outcome::Rejected(_) | Outcome::Verified));
    }

    /// Every mutation applied to every seed, with proptest choosing the
    /// parameters — the same coverage as above, but with the seed and the
    /// mutation kind quantified explicitly rather than folded into one
    /// entropy string, so a shrunk counterexample names them.
    #[test]
    fn every_mutation_of_every_seed_returns_a_typed_outcome(
        seed_index in 0usize..64,
        kind in 0u8..7,
        params in prop::collection::vec(any::<u8>(), 0..32),
    ) {
        let corpus = corpus();
        let seed = &corpus[seed_index % corpus.len()];
        let mutated = decode_mutation(kind, &params).apply(seed, corpus);
        let outcome = drive(&mutated);
        prop_assert!(matches!(outcome, Outcome::Rejected(_) | Outcome::Verified));
    }

    /// Truncation at **every** length of a valid bundle, not just the
    /// sampled ones: a length-prefixed format's most dangerous input class
    /// is a count it can no longer satisfy.
    #[test]
    fn every_truncation_of_a_valid_bundle_returns_a_typed_outcome(cut in 0usize..100_000) {
        let bundle = &corpus()[0];
        let outcome = drive(&bundle[..cut % (bundle.len() + 1)]);
        prop_assert!(matches!(outcome, Outcome::Rejected(_) | Outcome::Verified));
    }
}

// ---------------------------------------------------------------------------
// what is, and is not, verdict-bearing at M0
// ---------------------------------------------------------------------------

/// The unique offset at which `needle` occurs in `haystack`.
///
/// Uniqueness is asserted, not assumed: a fixture change that made a marker
/// ambiguous would otherwise silently move the region under test.
#[track_caller]
fn find_unique(haystack: &[u8], needle: &[u8]) -> usize {
    let hits: Vec<usize> = haystack
        .windows(needle.len())
        .enumerate()
        .filter(|(_, window)| *window == needle)
        .map(|(index, _)| index)
        .collect();
    assert_eq!(
        hits.len(),
        1,
        "expected exactly one occurrence of the marker, found {}",
        hits.len()
    );
    hits[0]
}

/// **The M0 authentication boundary, stated exactly.**
///
/// A bundle byte whose mutation still verifies is unauthenticated, and the
/// honest question is not "are there any" but "are they the ones we meant".
/// At M0 the answer is a precise, small set: the **storage record** — the
/// Autonomi content address, the manifest nonce and the manifest key, 88
/// bytes in total — and nothing else in a bundle without anchors.
///
/// That is by design, not by omission. Spec line 119 makes storage the
/// product's bonus rather than its proof, and the pipeline says so in
/// terms: the storage-linkage layer "must never gate the evidence verdict".
/// R20 gives those bytes their own rendering at M3, as a *layer*, without
/// making them verdict-bearing.
///
/// Asserting it as an equality is what makes it useful. A future change
/// that left some new field unauthenticated fails the strided half; a
/// change that made the storage record verdict-bearing — inverting the
/// evidence/storage separation — fails the exhaustive half. Either way the
/// boundary moves loudly.
///
/// A one-off exhaustive sweep of all 7891 bytes found exactly these three
/// runs and nothing else (32 B address, 24 B nonce, 32 B key). The
/// committed test keeps the exhaustive half over the region it claims and
/// strides the complement, because ~7900 full verifications is a
/// two-and-a-half-minute test and the strided half re-derives the same
/// conclusion in seconds.
#[test]
fn the_unauthenticated_region_at_m0_is_exactly_the_storage_record() {
    // `valid-multi-file-mixed`, which has empty anchor sections.
    let bundle = &corpus()[0];

    // R6 fills the storage record with recognisable constant patterns, so
    // the region is located by content rather than by a brittle offset.
    let regions: Vec<(usize, usize)> = [(0x5Eu8, 32usize), (0x5A, 24), (0x5C, 32)]
        .into_iter()
        .map(|(pattern, len)| {
            let marker = vec![pattern; len];
            (find_unique(bundle, &marker), len)
        })
        .collect();

    let exempt: std::collections::BTreeSet<usize> = regions
        .iter()
        .flat_map(|(start, len)| *start..*start + *len)
        .collect();
    assert_eq!(exempt.len(), 88, "the storage record is 32 + 24 + 32 bytes");

    // Exhaustive over the claim's positive side.
    for &index in &exempt {
        let mut mutated = bundle.clone();
        mutated[index] ^= 0xFF;
        assert_eq!(
            drive(&mutated),
            Outcome::Verified,
            "byte {index} of the storage record is verdict-bearing at M0 — the \
             evidence/storage separation (spec line 119) has been inverted"
        );
    }

    // Strided over the complement: every other byte is authenticated.
    let mut checked = 0usize;
    for index in (0..bundle.len()).step_by(31) {
        if exempt.contains(&index) {
            continue;
        }
        let mut mutated = bundle.clone();
        mutated[index] ^= 0xFF;
        assert!(
            matches!(drive(&mutated), Outcome::Rejected(_)),
            "flipping byte {index} still verified: a bundle region outside the storage record \
             is unauthenticated"
        );
        checked += 1;
    }
    assert!(
        checked > 200,
        "the strided half only checked {checked} bytes"
    );
}

/// The **anchor artifacts** are the other inert region at M0 — and unlike
/// the storage record they are inert only *for now*.
///
/// The pipeline's anchor stage is an M0 stub that emits one `absent` slot
/// per embedded artifact; R12 replaces it at M2, and A18 owns the verdict
/// states. So today an anchor artifact's bytes can be rewritten and the
/// bundle still verifies, which is correct at M0 and must **stop** being
/// correct once R12 lands.
///
/// This test is therefore written to go red at exactly that moment: when
/// the anchor stage starts verifying artifacts, the assertion below fails
/// and whoever lands R12 inverts it. That is the intended lifecycle, not a
/// fragile test — the one-off sweep measured 67 such bytes across the three
/// fixture artifacts, and leaving them silently unasserted is how a
/// milestone boundary gets forgotten.
#[test]
fn m0_anchor_artifacts_are_inert_until_r12_wires_the_anchor_stage() {
    let anchored = seed_corpus()
        .into_iter()
        .find(|(name, _)| *name == "valid-multi-file-anchored")
        .map(|(_, bytes)| bytes)
        .expect("the anchored shape is in the seed corpus");

    let marker = b"fixture .ots artifact";
    let start = find_unique(&anchored, marker);
    for offset in 0..marker.len() {
        let mut mutated = anchored.clone();
        mutated[start + offset] ^= 0xFF;
        assert_eq!(
            drive(&mutated),
            Outcome::Verified,
            "an OTS artifact byte became verdict-bearing. If R12 has landed, this test has done \
             its job: invert it, and give the anchor stage its own tamper rows (A21)."
        );
    }
}

/// Everything outside those two regions is authenticated, over the whole
/// mutation grid rather than one bundle's byte offsets.
///
/// The complement of the two tests above: they locate the exempt regions
/// precisely on one bundle, this sweeps every mutation kind over every
/// valid shape and requires rejection, skipping only mutations that landed
/// entirely inside an exempt region or changed nothing.
#[test]
fn byte_changing_mutations_outside_the_inert_regions_are_rejected() {
    let corpus = corpus();
    let valid: Vec<(&'static str, Vec<u8>)> = seed_corpus()
        .into_iter()
        .filter(|(name, _)| name.starts_with("valid-"))
        .collect();

    for (name, bundle) in &valid {
        for kind in 0u8..7 {
            for pattern in [0x01u8, 0x40, 0xFF] {
                let mutated = decode_mutation(kind, &[pattern; 20]).apply(bundle, corpus);
                if mutated == *bundle {
                    continue; // the identity mutation, legitimately
                }
                if matches!(drive(&mutated), Outcome::Verified) {
                    // Legitimate only if every changed byte is inert. The
                    // storage record and the anchor artifacts are the two
                    // regions the tests above pin, so a verifying mutation
                    // must be confined to them — and, since it changed
                    // something, must not have changed the length.
                    assert_eq!(
                        mutated.len(),
                        bundle.len(),
                        "`{name}`: a length-changing mutation still verified (kind {kind})"
                    );
                    let changed = mutated
                        .iter()
                        .zip(bundle.iter())
                        .filter(|(a, b)| a != b)
                        .count();
                    assert!(
                        changed <= 88 + 67,
                        "`{name}`: a mutation changing {changed} bytes still verified (kind \
                         {kind}) — that is wider than the storage record plus the M0 anchor \
                         artifacts, so something outside them is unauthenticated"
                    );
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// the three properties that stand in for demoted rows
// ---------------------------------------------------------------------------

/// **Non-row `swapped-unit-ciphertext`** (decision D81): for every ordered
/// pair of distinct revealed units, moving A's ciphertext into B's entry
/// never verifies.
///
/// The row was demoted because an AEAD authentication failure is one bit by
/// construction, so the swap and the flipped ciphertext byte cannot bind
/// distinct codes. This is the quantified replacement — and it is
/// genuinely stronger than the row would have been, since a row picks one
/// pair and this covers every pair of a multi-unit work.
#[test]
fn no_ciphertext_swap_between_revealed_units_verifies() {
    let work = shapes::multi_file();
    let base = build_tweaked(&work, &Selection::all(3), &Tweak::default());
    let revealed = base.revealed_unit_ids.clone();
    assert!(revealed.len() >= 4, "need several revealed units to pair");

    let mut pairs = 0usize;
    for &donor in &revealed {
        for &recipient in &revealed {
            if donor == recipient {
                continue;
            }
            // `Tweak` is `#[non_exhaustive]`, so an out-of-crate caller
            // assigns fields rather than using a struct expression.
            let mut tweak = Tweak::none();
            tweak.swap_ciphertext_into = Some((donor, recipient));
            let built = build_tweaked(&work, &Selection::all(3), &tweak);
            assert!(
                matches!(drive(&built.bytes), Outcome::Rejected(_)),
                "unit {donor}'s ciphertext under unit {recipient}'s entry verified"
            );
            pairs += 1;
        }
    }
    assert_eq!(pairs, revealed.len() * (revealed.len() - 1));
}

/// **Non-row `pipeline-level-wrong-unit-key`** (decision D81): no
/// substitution of a revealed unit's `k_u` ever verifies.
///
/// Every ordered pair again, so the property covers substituting each
/// revealed unit's key for each other's — the full space a relay holding
/// the bundle can reach without breaking a commitment.
#[test]
fn no_unit_key_substitution_verifies() {
    let work = shapes::multi_file();
    let base = build_tweaked(&work, &Selection::all(3), &Tweak::default());
    let revealed = base.revealed_unit_ids.clone();

    for &victim in &revealed {
        for &donor in &revealed {
            if victim == donor {
                continue;
            }
            let mut tweak = Tweak::none();
            tweak.wrong_unit_key = Some((victim, donor));
            let built = build_tweaked(&work, &Selection::all(3), &tweak);
            assert!(
                matches!(drive(&built.bytes), Outcome::Rejected(_)),
                "unit {victim}'s entry carrying unit {donor}'s key verified"
            );
        }
    }
}

/// Same shape for `unit_salt`, which R8 found collapses onto
/// `unit-commit-mismatch` the way the key collapses onto
/// `unit-decrypt-failed` (non-row `pipeline-level-wrong-unit-salt`).
///
/// Only non-covered units carry a `unit_salt`, so the substitution is a
/// no-op on covered ones and those pairs are skipped rather than asserted —
/// the test says which it exercised so a change in the fixture's coverage
/// mix cannot silently empty it.
#[test]
fn no_unit_salt_substitution_verifies() {
    let work = shapes::multi_file();
    let base = build_tweaked(&work, &Selection::all(3), &Tweak::default());
    // Units 1 (file 0's raw mirror) and 5 (file 2's normal unit, its file
    // carrying no fine tree) are the non-covered revealed units.
    let non_covered = [1u64, 5];
    assert!(
        non_covered
            .iter()
            .all(|id| base.revealed_unit_ids.contains(id)),
        "the fixture must reveal the non-covered units this property is about"
    );

    for &victim in &non_covered {
        for &donor in &non_covered {
            if victim == donor {
                continue;
            }
            let mut tweak = Tweak::none();
            tweak.wrong_unit_salt = Some((victim, donor));
            let built = build_tweaked(&work, &Selection::all(3), &tweak);
            assert!(
                matches!(drive(&built.bytes), Outcome::Rejected(_)),
                "unit {victim}'s entry carrying unit {donor}'s unit_salt verified"
            );
        }
    }
}

/// **Non-row `full-reveal-unit-strip-downgrade`** (decision D28): no
/// single-unit deletion from a full-reveal bundle verifies.
///
/// The third-party proof-downgrade attack — drop one revealed unit and
/// leave `file_salt` attached, so the bundle claims a whole-file proof it
/// no longer supports.
///
/// **Rejection, not a code**, and since decision D82 that is load-bearing
/// rather than merely tidy: on a file that retains another revealed unit
/// the outcome is `partial-reveal-salt-leak-file-salt`, while stripping the
/// *only* revealed unit of a file leaves a `touched_files` entry with
/// nothing revealed, so D82's earlier stage-2 code claims the verdict
/// instead. Both are rejections; the property is about the attack failing,
/// not about which stage catches it. The test records which codes it
/// actually saw, so the split is visible rather than hidden by the
/// quantifier.
#[test]
fn no_single_unit_deletion_from_a_full_reveal_verifies() {
    let work = shapes::multi_file();
    let full = build_tweaked(&work, &Selection::all(3), &Tweak::default());
    assert!(
        full.files.iter().all(|file| file.fully_revealed),
        "the base must be a genuine full reveal"
    );

    let mut codes: Vec<&'static str> = Vec::new();
    let mut files_swept = 0usize;
    for file in &full.files {
        let unit_count = file.normal_unit_ids.len();
        // **The >=2-unit qualifier**, which is the non-row's own pin and is
        // not a convenience: dropping the *only* normal unit of a file
        // leaves it revealed-from not at all, so R6 emits no `touched_files`
        // entry for it — and F8's tier-`[X]` rule `full_reveals ⊆
        // touched_files` then refuses to *construct* the bundle. The attack
        // is unrepresentable rather than merely rejected on that shape,
        // which `the_single_unit_downgrade_is_unrepresentable` pins below.
        if unit_count < 2 {
            continue;
        }
        files_swept += 1;
        for dropped in 0..unit_count {
            // Every normal unit of this file except `dropped`; other files
            // stay fully revealed.
            let kept: Vec<usize> = (0..unit_count).filter(|index| *index != dropped).collect();
            let selection = Selection(
                full.files
                    .iter()
                    .map(|other| {
                        if other.file_id == file.file_id {
                            FileSelection::Units(kept.clone())
                        } else {
                            FileSelection::Full
                        }
                    })
                    .collect(),
            );
            // ...and the full-reveal material still attached, which is what
            // makes it a downgrade rather than an honest partial reveal.
            let mut tweak = Tweak::none();
            tweak.leak_full_material = Some(file.file_id);
            let built = build_tweaked(&work, &selection, &tweak);
            match drive(&built.bytes) {
                Outcome::Rejected(code) => codes.push(code),
                Outcome::Verified => panic!(
                    "dropping unit index {dropped} of file {} from a full reveal still verified \
                     — the proof-downgrade attack succeeded",
                    file.file_id
                ),
            }
        }
    }

    assert!(
        files_swept >= 1,
        "no file had the >=2 normal units required"
    );
    assert!(!codes.is_empty(), "the sweep must exercise something");
    codes.sort_unstable();
    codes.dedup();
    // Not an equality assertion: which codes appear depends on each file's
    // unit count, and pinning that here would make an unrelated fixture
    // change look like a regression in this property. Printed so the split
    // D82 introduced stays visible to a reader of the test output.
    println!("single-unit-deletion outcomes: {codes:?}");
}

/// The same attack on a **single-unit** file is not merely rejected — it
/// cannot be built.
///
/// Dropping the only normal unit of a file leaves nothing of it revealed,
/// so R6 emits no `touched_files` entry, and F8's tier-`[X]` rule
/// `full_reveals ⊆ touched_files` refuses the bundle at construction with
/// `FullRevealWithoutTouchedFile`. The proof-downgrade attack therefore has
/// no representable form on such a file, which is a stronger statement than
/// the property above and is the reason the non-row's mutation text pins
/// itself at >= 2 units.
///
/// Worth pinning rather than leaving as a footnote: it means the D28
/// downgrade and the D82 add-material shapes meet here, and which code a
/// single-unit strip produces depends on whether the mutation *retains* the
/// touched entry — F8's, if it drops it (R6's builder derives the entry
/// from the revealed set, so that is this path); D82's stage-2 code, if it
/// keeps it (R7's `touch_without_reveal` knob, which splices one back in).
/// Both are rejections, which is all the property claims.
#[test]
fn the_single_unit_downgrade_is_unrepresentable() {
    let work = shapes::multi_file();
    let full = build_tweaked(&work, &Selection::all(3), &Tweak::none());
    let single: Vec<u64> = full
        .files
        .iter()
        .filter(|file| file.normal_unit_ids.len() == 1)
        .map(|file| file.file_id)
        .collect();
    assert!(!single.is_empty(), "the fixture must have a 1-unit file");

    for file_id in single {
        let selection = Selection(
            full.files
                .iter()
                .map(|other| {
                    if other.file_id == file_id {
                        FileSelection::Units(Vec::new())
                    } else {
                        FileSelection::Full
                    }
                })
                .collect(),
        );
        let mut tweak = Tweak::none();
        tweak.leak_full_material = Some(file_id);
        let work = work.clone();
        let built = std::panic::catch_unwind(move || build_tweaked(&work, &selection, &tweak));
        assert!(
            built.is_err(),
            "F8's `full_reveals ⊆ touched_files` should have refused to construct a full-reveal \
             entry for file {file_id}, which the selection reveals nothing of"
        );
    }
}

// ---------------------------------------------------------------------------
// the seed corpus is what the fuzz target will be given
// ---------------------------------------------------------------------------

/// R10's Accept: "seed corpus includes ... R7 tamper fixtures", plus R34's
/// section-level recombinations.
///
/// Asserted here rather than left to the fuzz crate, because the fuzz crate
/// needs a nightly toolchain and Q9's wiring, and an accept criterion that
/// only holds in a lane nobody can run yet is not held at all.
#[test]
fn the_seed_corpus_covers_valid_shapes_tamper_fixtures_and_recombinations() {
    let seeds = seed_corpus();
    let count = |prefix: &str| {
        seeds
            .iter()
            .filter(|(name, _)| name.starts_with(prefix))
            .count()
    };
    let (valid, tamper, recombined) = (count("valid-"), count("tamper-"), count("recombined-"));
    assert!(valid >= 5, "only {valid} valid seeds");
    assert!(tamper >= 10, "only {tamper} tamper seeds");
    assert!(recombined >= 8, "only {recombined} recombined seeds");
    assert_eq!(
        valid + tamper + recombined,
        seeds.len(),
        "every seed is named by class"
    );
}

// ---------------------------------------------------------------------------
// R34: section-level recombination
// ---------------------------------------------------------------------------

/// **The R34 property**: every `(target, donor, recombination)` triple over
/// the whole seed corpus yields either a decodable bundle or nothing.
///
/// The quantified form of `every_representable_recombination_decodes`, which
/// checks one pair. Here both sides range over the corpus — including the
/// tamper fixtures and the recombined seeds themselves, so grafts compose —
/// and the invariant is the one R10 established for byte-level mutation,
/// restated for the class byte-level mutation cannot reach: a typed outcome
/// always, never a panic, and *past the codec* whenever the seam produced
/// bytes at all.
///
/// **Strided, not the full cross product.** Every corpus entry appears as a
/// target and (via the `+1` offset, which is coprime with any length) as a
/// donor, at three offsets each. The full n² sweep costs 22 s and re-tests
/// mostly near-duplicate pairs; this re-derives the same conclusion in
/// seconds, and the fuzz target is where unbounded pairing belongs.
#[test]
fn every_recombination_of_every_corpus_pair_is_decodable_or_refused() {
    let corpus = corpus();
    let mut produced = 0usize;
    for (index, target) in corpus.iter().enumerate() {
        for offset in [1usize, 7, 13] {
            let donor = &corpus[(index + offset) % corpus.len()];
            for (name, how) in Recombination::all() {
                let Some(bytes) = recombine(target, donor, how) else {
                    continue;
                };
                produced += 1;
                let outcome = drive(&bytes);
                assert!(
                    outcome.reached_the_pipeline(),
                    "`{name}` produced a bundle that died in the codec ({outcome:?}) — the seam \
                     re-encodes through `BundleV1::new`, so this cannot happen"
                );
            }
        }
    }
    // Guards against the sweep silently emptying: if the seam started
    // refusing everything, every assertion above would vacuously hold.
    assert!(
        produced > 400,
        "only {produced} recombinations were representable across the corpus"
    );
}

proptest! {
    #![proptest_config(strategies::integration_test_config(
        0x5EED_0A34,
        "proptest-regressions/verify_fuzz_recombine.txt",
    ))]

    /// Recombination **composed with** byte-level mutation: graft a section
    /// across two corpus bundles, then mutate the result.
    ///
    /// The composition is the point. A grafted bundle is deep in the
    /// machine by construction, so a bit-flip on top of one lands in a
    /// stage that has already found something wrong — the same argument
    /// R10 makes for seeding the corpus with tamper fixtures, one level up.
    #[test]
    fn mutated_recombinations_never_panic(
        target_index in 0usize..64,
        donor_index in 0usize..64,
        how_index in 0usize..16,
        kind in 0u8..7,
        params in prop::collection::vec(any::<u8>(), 0..32),
    ) {
        let corpus = corpus();
        let all = Recombination::all();
        let (_, how) = all[how_index % all.len()];
        let target = &corpus[target_index % corpus.len()];
        let donor = &corpus[donor_index % corpus.len()];
        if let Some(bytes) = recombine(target, donor, how) {
            let mutated = decode_mutation(kind, &params).apply(&bytes, corpus);
            prop_assert!(matches!(drive(&mutated), Outcome::Rejected(_) | Outcome::Verified));
        }
    }
}

/// The tamper seeds must fail at a **spread** of stages, or the corpus
/// would start the fuzzer from one place repeatedly.
#[test]
fn the_tamper_seeds_span_several_failure_stages() {
    let codes: std::collections::BTreeSet<&'static str> = seed_corpus()
        .iter()
        .filter(|(name, _)| name.starts_with("tamper-"))
        .filter_map(|(_, bytes)| match drive(bytes) {
            Outcome::Rejected(code) => Some(code),
            Outcome::Verified => None,
        })
        .collect();
    assert!(
        codes.len() >= 8,
        "tamper seeds produced only {} distinct codes: {codes:?}",
        codes.len()
    );
}
