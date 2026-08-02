//! G20 — the consolidated content-model property suite (tasks/G.md G20;
//! MVP-SPEC.md lines 153, 167–170).
//!
//! One seeded suite for the whole domain's invariants, exercised through the
//! **public** `antseal-core` surface — the surface R's verifier, S's sealer
//! and third-party implementations actually see:
//!
//! | property | test |
//! | --- | --- |
//! | canonicalization idempotence over arbitrary bytes | [`canonicalization_is_idempotent_over_arbitrary_bytes`] |
//! | split tiling | [`split_ranges_tile_the_canonical_rendition`] |
//! | GGM cover bound / completeness / soundness | [`ggm_cover_is_bounded_complete_and_sound`] |
//! | prove → verify round-trip, `n <= 2^12`, arbitrary ranges | [`prove_then_verify_round_trips_over_arbitrary_ranges`] |
//! | streaming vs reference `fine_root` | [`streaming_fine_root_equals_an_independent_reference`] |
//! | no-panic harness mutating proof structs into G13 | [`mutated_proofs_never_panic_and_never_verify`] |
//!
//! # Relationship to the in-module property tests
//!
//! G2/G6/G8–G13 each carry properties next to their crate-private internals.
//! This file deliberately does not restate them; it adds what those cannot
//! reach:
//!
//! - **Breadth.** The in-module round-trip and cover blocks cap at `n <= 200`
//!   and `n <= 300`. G20's mandate is `n <= 2^12`, which is where a `u8`
//!   level, a `1 << level` shift or a frontier index would first misbehave.
//! - **Composition.** [`canonicalize_split_and_seal_compose`] runs the real
//!   seal-side sequence — canonicalize → split → tile → fine-tree → open one
//!   unit → verify — which no single module's tests can see.
//! - **Independence.** The streaming reference here is rebuilt from raw
//!   SHA-256 and the published domain tags rather than from the crate's own
//!   `leaf_hash`/`node_hash`, so it is a second implementation of the tree,
//!   not the same code called twice.
//!
//! # Conventions (Q3, `docs/testing/proptest-conventions.md`)
//!
//! proptest arrives through the `antseal_core::test_util::proptest`
//! re-export; every block sets its own fixed RNG seed, committed here, so a
//! CI failure reproduces byte-for-byte locally; `PROPTEST_CASES` (1024 in
//! the CI `test` lane) scales case counts. No test name uses the reserved
//! `corpus_`/`vector_` markers — these are properties, not byte-stability
//! suites.
//!
//! ## Two wave-4 findings this file must not re-introduce
//!
//! 1. **`PROPTEST_CASES` overrides a hardcoded `cases`, not the other way
//!    round** (found at C18). The `proptest!` macro re-applies
//!    `contextualize_config` to whatever config it is handed, so a `cases`
//!    literal — or a computed `max(...)`, which is contextualized *after*
//!    the literal is built — is a *local-run* value only. Nothing in this
//!    file has a spec-mandated case floor, so no block tries to enforce one;
//!    the `cases` values below are local-run cost tuning and the lever for
//!    CI cost is that lane's environment variable. A future G-domain floor
//!    must bypass the macro entirely and drive `TestRunner::new(config)`
//!    directly, as C3's injectivity test does.
//! 2. **Integration tests need [`strategies::integration_test_config`]**
//!    (found at C18/Q3 §5). proptest's default `SourceParallel` persistence
//!    walks up from the test source looking for `lib.rs`/`main.rs`; a test
//!    in `tests/` has no such ancestor, so the lookup fails and **nothing is
//!    persisted** — a CI-only failure would be unreproducible. Every block
//!    below therefore passes the explicit path, and found counterexamples
//!    land in `crates/antseal-core/proptest-regressions/content_properties.txt`,
//!    which is committed and never deleted.
//!
//! ## Cost (measured 2026-07-28, debug build, x86_64 linux)
//!
//! **~42 s at the default 256 cases; ~2.8 min at the CI lane's 1024.** The
//! fine-tree blocks dominate — a case at `n = 4096` is ~25 000 SHA-256
//! compressions — and the two levers used here are:
//!
//! - **weighted sizes**: [`leaf_count`] reaches `2^12` on roughly one case in
//!   ten rather than uniformly, so the mandated ceiling is still hit many
//!   times per run without paying for it every case;
//! - **an `O(n)` reference**: [`reference_salts`] derives all `n` salts in one
//!   DFS instead of re-walking the `d`-step path per leaf, which is a ~12×
//!   saving at the ceiling and cut this file from ~77 s to ~42 s.
//!
//! Per block at 256 cases: `the_reference_agrees_at_the_awkward_sizes` ~9 s,
//! `prove_then_verify_round_trips_over_arbitrary_ranges` ~9 s, the two
//! mutation blocks ~5 s each,
//! `streaming_fine_root_equals_an_independent_reference` ~2 s, everything
//! else under 1 s.
//!
//! As at C18: the `cases` field cannot cap CI (see finding 1 below), so the
//! lever for CI cost is that lane's `PROPTEST_CASES`, not anything here.

use std::collections::BTreeSet;

use antseal_core::canon::{CanonicalBytes, TextMode, UnicodeVersion, canonicalize};
use antseal_core::content::{
    ByteRange, CanonDescriptor, ChildBit, ContentKind, FineTreeError, FineTreeOptOut, NodeAddress,
    RangeProofView, SaltTree, SplitEligibleText, WireNode, assign_unit_ids, child_seed,
    cover_seeds, minimal_cover, plan_blank_line_split, prove_range, rebuild_fine_root,
    verify_range,
};
use antseal_core::crypto::domain::{TAG_FINE_TREE_LEAF, TAG_FINE_TREE_NODE, TAG_GGM_SALT_CHILD};
use antseal_core::crypto::material::{Salt16, Seed32};
use antseal_core::test_util::proptest::prelude::*;
use antseal_core::test_util::strategies;
use sha2::{Digest, Sha256};

/// Committed regressions file (Q3 §5). Every block in this file points here,
/// so a counterexample found in any of them is persisted and replayed.
const REGRESSIONS: &str = "proptest-regressions/content_properties.txt";

/// G20's mandated ceiling: `n <= 2^12`.
const MAX_LEAF_COUNT: u64 = 1 << 12;

/// U+FEFF, as a named constant: `prop_assert!` stringifies its expression
/// into a `format_args!` template, and a `\u{…}` escape there is read as a
/// capture name.
const BOM: char = '\u{feff}';

/// The wave-4 finding, asserted rather than trusted: this file's config
/// really does carry an explicit persistence path, so a counterexample found
/// in CI is written to a committed file instead of being silently dropped
/// (`docs/testing/proptest-conventions.md` §5). Without this, the
/// `SourceParallel` default would fail its `lib.rs` lookup from `tests/` and
/// persist nothing — and no test would notice.
#[test]
fn regressions_are_persisted_to_the_committed_path() {
    let config = strategies::integration_test_config(0x5EED_6200, REGRESSIONS);
    let rendered = format!("{:?}", config.failure_persistence);
    assert!(
        rendered.contains("content_properties.txt"),
        "failure persistence must name this file's committed regressions path, got {rendered}"
    );
    assert!(
        rendered.contains("Direct"),
        "persistence must be Direct, not the SourceParallel default that cannot \
         resolve from tests/: {rendered}"
    );
}

// ---------------------------------------------------------------------------
// strategies (local: none of these is yet used by a second crate, which is
// Q3 §2's criterion for promoting one into `test_util::strategies`)
// ---------------------------------------------------------------------------

/// Arbitrary bytes, including the empty input.
fn arbitrary_bytes(max: usize) -> impl Strategy<Value = Vec<u8>> {
    proptest::collection::vec(any::<u8>(), 0..=max)
}

/// Leaf counts up to G20's mandated `2^12`, weighted towards the cheap end
/// so the ceiling is reached often without the suite costing minutes (module
/// docs, "Cost").
fn leaf_count() -> impl Strategy<Value = u64> {
    prop_oneof![
        6 => 1u64..=64,
        3 => 65u64..=512,
        1 => 513u64..=MAX_LEAF_COUNT,
    ]
}

/// Text with a real chance of blank-line structure: paragraphs separated by
/// runs of newlines, plus whitespace-only lines and CRLF, so the split's
/// frozen D22 semantics are actually exercised rather than merely called.
fn splitty_text() -> impl Strategy<Value = String> {
    let chunk = prop_oneof![
        6 => "[a-z]{1,8}",
        2 => Just("\n".to_owned()),
        2 => Just("\n\n".to_owned()),
        1 => Just("\r\n\r\n".to_owned()),
        1 => Just("   \n".to_owned()),
        1 => Just("\u{fffd}".to_owned()),
    ];
    proptest::collection::vec(chunk, 0..24).prop_map(|parts| parts.concat())
}

/// A non-empty range inside `[0, n)`, derived from raw draws so shrinking
/// stays meaningful (proptest shrinks the raw values, not a filtered pair).
fn range_within(n: u64, raw_start: u64, raw_length: u64) -> ByteRange {
    let start = raw_start % n;
    let length = (raw_length % (n - start)) + 1;
    ByteRange::new(start, length)
}

/// Deterministic content of `n` bytes from a seed byte — cheap to generate at
/// `n = 4096` and still content-dependent, so a tree built over it is not
/// accidentally uniform.
fn content_of(n: u64, seed: u8) -> Vec<u8> {
    (0..n)
        .map(|i| {
            (i as u8)
                .wrapping_mul(31)
                .wrapping_add(seed)
                .wrapping_add((i >> 8) as u8)
        })
        .collect()
}

// ---------------------------------------------------------------------------
// an independent reference tree (raw SHA-256 + the published domain tags)
// ---------------------------------------------------------------------------

/// One GGM child step, `s_{v‖b} = SHA-256(0x06 ‖ s_v ‖ b)`, written against
/// MVP-SPEC.md line 96 with raw SHA-256 rather than through the crate's
/// `child_seed`.
fn reference_child(seed: &[u8; 32], bit: u8) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([TAG_GGM_SALT_CHILD]);
    hasher.update(seed);
    hasher.update([bit]);
    hasher.finalize().into()
}

/// `salt_0 … salt_{n−1}`, derived by one DFS over the depth-`d` grid.
///
/// The path is taken **MSB-first** — bit `d − 1` chooses the first child —
/// which is the rule this reference exists to hold the crate to. Deriving
/// them all in one descent rather than re-walking per leaf keeps the
/// reference `O(n)` instead of `O(n·d)`, which is what makes the `n = 2^12`
/// cases affordable.
fn reference_salts(s_root: &[u8; 32], n: u64) -> Vec<[u8; 16]> {
    let depth = reference_depth(n);
    let mut salts = Vec::with_capacity(n as usize);
    // Explicit stack of (seed, level, index); push the RIGHT child first so
    // leaves come out in ascending index order.
    let mut stack = vec![(*s_root, 0u8, 0u64)];
    while let Some((seed, level, index)) = stack.pop() {
        if (index << (depth - level)) >= n {
            continue; // wholly unused slots commit nothing
        }
        if level == depth {
            let mut salt = [0u8; 16];
            salt.copy_from_slice(&seed[..16]);
            salts.push(salt);
            continue;
        }
        stack.push((reference_child(&seed, 1), level + 1, index * 2 + 1));
        stack.push((reference_child(&seed, 0), level + 1, index * 2));
    }
    salts
}

/// `ceil(log2 n)`, the reference's own depth rule (`n = 1` → 0).
fn reference_depth(n: u64) -> u8 {
    let mut depth = 0u8;
    while (1u64 << depth) < n {
        depth += 1;
    }
    depth
}

/// The RFC 6962 root of `content` under `s_root`, built recursively: the left
/// subtree of a node spanning `w > 1` leaves is the largest **perfect** one.
fn reference_root(s_root: &[u8; 32], content: &[u8]) -> Option<[u8; 32]> {
    if content.is_empty() {
        return None; // an empty file has no fine tree (MVP-SPEC.md line 78)
    }
    let salts = reference_salts(s_root, content.len() as u64);
    Some(reference_subtree(&salts, content, 0, content.len()))
}

fn reference_subtree(salts: &[[u8; 16]], content: &[u8], first: usize, end: usize) -> [u8; 32] {
    if end - first == 1 {
        let mut hasher = Sha256::new();
        hasher.update([TAG_FINE_TREE_LEAF]);
        hasher.update(salts[first]);
        hasher.update((first as u64).to_le_bytes());
        hasher.update([content[first]]);
        return hasher.finalize().into();
    }
    let mut split = 1usize;
    while split * 2 < end - first {
        split *= 2;
    }
    let left = reference_subtree(salts, content, first, first + split);
    let right = reference_subtree(salts, content, first + split, end);
    let mut hasher = Sha256::new();
    hasher.update([TAG_FINE_TREE_NODE]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

// ---------------------------------------------------------------------------
// 1. canonicalization idempotence over arbitrary bytes (G2)
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(strategies::integration_test_config(0x5EED_6201, REGRESSIONS))]

    /// G2's normative property (MVP-SPEC.md line 83): forced-text
    /// canonicalization is **total** over arbitrary bytes and **idempotent**,
    /// which is what lets R's raw-mirror check recompute
    /// `canonicalize(raw) == canonical` unconditionally.
    #[test]
    fn canonicalization_is_idempotent_over_arbitrary_bytes(raw in arbitrary_bytes(192)) {
        let once = canonicalize(UnicodeVersion::CURRENT, TextMode::Forced, &raw)
            .expect("forced mode is total (D20)");
        let twice = canonicalize(UnicodeVersion::CURRENT, TextMode::Forced, once.as_bytes())
            .expect("forced mode is total (D20)");
        prop_assert_eq!(once.as_bytes(), twice.as_bytes());
        // The output is always valid UTF-8 with no CR and no leading BOM —
        // the three post-conditions the pipeline's stages establish (D21).
        prop_assert!(!once.as_bytes().contains(&b'\r'), "no CR survives (D21)");
        prop_assert!(
            !once.as_str().starts_with(BOM),
            "the leading BOM run is stripped (D21)"
        );
    }

    /// Detected mode agrees with forced mode on every input detected as text,
    /// so a file's canonical bytes never depend on *how* it was classified —
    /// only on whether it was.
    #[test]
    fn detected_and_forced_modes_agree_on_valid_utf8(text in ".{0,120}") {
        let detected = canonicalize(UnicodeVersion::CURRENT, TextMode::Detected, text.as_bytes())
            .expect("valid UTF-8 is detected as text");
        let forced = canonicalize(UnicodeVersion::CURRENT, TextMode::Forced, text.as_bytes())
            .expect("forced mode is total");
        prop_assert_eq!(detected.as_bytes(), forced.as_bytes());
    }
}

// ---------------------------------------------------------------------------
// 2. split tiling (G6)
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(strategies::integration_test_config(0x5EED_6202, REGRESSIONS))]

    /// G6/D22: `--split blank-lines` ranges are sorted, non-overlapping and
    /// **exactly tile** `[0, size)` over the canonical rendition, and their
    /// concatenation reproduces it byte for byte — the structural invariant
    /// R re-checks on every bundle (MVP-SPEC.md line 121).
    #[test]
    fn split_ranges_tile_the_canonical_rendition(text in splitty_text()) {
        let canonical = canonicalize(UnicodeVersion::CURRENT, TextMode::Forced, text.as_bytes())
            .expect("forced mode is total");
        let size = canonical.len() as u64;
        let descriptor = CanonDescriptor::describe_file(
            ContentKind::Text(UnicodeVersion::CURRENT),
            size,
            FineTreeOptOut::NotRequested,
        );
        let Some(eligible) = SplitEligibleText::of(&descriptor) else {
            // Empty files opt out of the fine tree, hence out of splitting.
            prop_assert_eq!(size, 0);
            return Ok(());
        };
        let units = assign_unit_ids(&[plan_blank_line_split(eligible, &canonical)]);
        prop_assert!(!units.is_empty(), "a split always yields at least one unit");

        let mut next = 0u64;
        let mut rebuilt: Vec<u8> = Vec::new();
        for (ordinal, unit) in units.iter().enumerate() {
            prop_assert_eq!(unit.unit_id(), ordinal as u64, "ids are manifest ordinals");
            let range = unit.byte_range();
            prop_assert_eq!(range.start(), next, "sorted, no gap, no overlap");
            let end = range.end().expect("no overflow");
            rebuilt.extend_from_slice(&canonical.as_bytes()[next as usize..end as usize]);
            next = end;
        }
        prop_assert_eq!(next, size, "the tiling covers [0, size) exactly");
        prop_assert_eq!(rebuilt.as_slice(), canonical.as_bytes());
    }
}

// ---------------------------------------------------------------------------
// 3. GGM cover: bound, completeness, soundness (G11)
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(strategies::integration_test_config(0x5EED_6203, REGRESSIONS))]

    /// G11's four properties over `(n <= 2^12, arbitrary range)`
    /// (MVP-SPEC.md line 96):
    ///
    /// 1. **bound** — `|cover| <= max(1, 2·ceil(log2 n))`;
    /// 2. **completeness** — the nodes' real spans partition the revealed
    ///    range exactly, in ascending order, so every revealed salt is
    ///    derivable and the verifier can walk cover and bytes in lockstep;
    /// 3. **soundness** — no node's real span reaches a leaf outside the
    ///    range (the leaf-exactness rule);
    /// 4. **`s_root` iff the range is `[0, n)`**.
    #[test]
    fn ggm_cover_is_bounded_complete_and_sound(
        n in leaf_count(),
        raw_start in any::<u64>(),
        raw_length in any::<u64>(),
    ) {
        let range = range_within(n, raw_start, raw_length);
        let end = range.end().expect("in bounds");
        let cover = minimal_cover(range, n).expect("range is inside [0, n)");
        let depth = cover.depth();

        // 1. bound
        let log2_ceil = u64::from(depth);
        prop_assert!(
            cover.nodes().len() as u64 <= (2 * log2_ceil).max(1),
            "|cover| = {} exceeds 2·ceil(log2 {n}) = {}",
            cover.nodes().len(),
            2 * log2_ceil
        );

        // 2 + 3. exact partition of the revealed range, ascending
        let mut next = range.start();
        for node in cover.nodes() {
            prop_assert_eq!(node.first_leaf(), next, "ascending, contiguous, no gap");
            prop_assert!(node.leaf_len() > 0);
            next = node.first_leaf() + node.leaf_len();
            prop_assert!(next <= end, "a node reaches past the revealed range");
            // The address really is on this tree's grid and its real span is
            // the node's claimed span.
            let address = node.address();
            prop_assert!(address.level() <= depth);
            prop_assert_eq!(address.first_slot(depth).expect("on the grid"), node.first_leaf());
        }
        prop_assert_eq!(next, end, "the cover does not span the whole range");

        // 4. s_root iff full range
        prop_assert_eq!(cover.releases_s_root(), range.start() == 0 && end == n);
    }

    /// Soundness again, but by **real derivation** rather than by span
    /// arithmetic: expand every shipped seed down to its leaves and require
    /// the resulting salt set to contain no unrevealed real leaf. Capped at a
    /// small `n` because the closure is `O(n)` hashes — the exhaustive
    /// version of this argument at `n = 6` is G16.
    #[test]
    fn the_derivable_salt_closure_never_reaches_an_unrevealed_leaf(
        n in 1u64..=64,
        raw_start in any::<u64>(),
        raw_length in any::<u64>(),
        root_bytes in any::<[u8; 32]>(),
    ) {
        let range = range_within(n, raw_start, raw_length);
        let end = range.end().expect("in bounds");
        let s_root = Seed32::from_bytes(root_bytes);
        let cover = minimal_cover(range, n).expect("in bounds");
        let depth = cover.depth();
        let tree = SaltTree::new(&s_root, n).expect("n >= 1");

        // Derived once: `cover_seeds` is the disclosure path, and calling it
        // per leaf would make this property quadratic in `n`.
        let disclosed = cover_seeds(&s_root, &cover);
        let mut derivable: BTreeSet<u64> = BTreeSet::new();
        for entry in &disclosed {
            descend_into(entry.seed(), entry.node().address(), depth, &mut derivable);
        }
        for leaf in 0..n {
            let inside = leaf >= range.start() && leaf < end;
            prop_assert_eq!(
                derivable.contains(&leaf),
                inside,
                "leaf {} is {}revealed but {}derivable",
                leaf,
                if inside { "" } else { "not " },
                if derivable.contains(&leaf) { "" } else { "not " }
            );
        }
        // And the derived salts are the tree's own — completeness is about
        // the right bytes, not merely the right slots.
        for leaf in range.start()..end {
            prop_assert_eq!(
                derived_salt(&disclosed, depth, leaf),
                Some(*tree.salt(leaf).expect("real leaf").as_bytes())
            );
        }
    }
}

/// Record every leaf slot reachable below `address`, descending the real GGM
/// tree from `seed`.
fn descend_into(seed: &Seed32, address: NodeAddress, depth: u8, out: &mut BTreeSet<u64>) {
    if address.level() == depth {
        out.insert(address.index());
        return;
    }
    for bit in ChildBit::ALL {
        let child = address.child(bit).expect("below the maximum level");
        descend_into(&child_seed(seed, bit), child, depth, out);
    }
}

/// The salt a cover recipient derives for `leaf`, or `None` if no shipped
/// seed reaches it.
fn derived_salt(
    disclosed: &[antseal_core::content::CoverEntry],
    depth: u8,
    leaf: u64,
) -> Option<[u8; 16]> {
    for entry in disclosed {
        let address = entry.node().address();
        let first = address.first_slot(depth).ok()?;
        let width = u64::try_from(address.slot_width(depth).ok()?).unwrap_or(u64::MAX);
        if leaf < first || leaf >= first.saturating_add(width) {
            continue;
        }
        let mut seed = Seed32::from_bytes(*entry.seed().as_bytes());
        for bit in (0..(depth - address.level())).rev() {
            seed = child_seed(&seed, ChildBit::from_bit((leaf >> bit) & 1 == 1));
        }
        let mut salt = [0u8; Salt16::LEN];
        salt.copy_from_slice(&seed.as_bytes()[..Salt16::LEN]);
        return Some(salt);
    }
    None
}

// ---------------------------------------------------------------------------
// 4. prove -> verify round-trip, n <= 2^12 (G12 + G13)
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(strategies::integration_test_config(0x5EED_6204, REGRESSIONS))]

    /// The end-to-end opening property over G20's mandated `n <= 2^12` and
    /// arbitrary ranges: every proof a prover can generate verifies against
    /// `fine_root` through the **same** entry point a decoded bundle takes
    /// (MVP-SPEC.md lines 96, 114, 121).
    #[test]
    fn prove_then_verify_round_trips_over_arbitrary_ranges(
        n in leaf_count(),
        raw_start in any::<u64>(),
        raw_length in any::<u64>(),
        content_seed in any::<u8>(),
        root_bytes in any::<[u8; 32]>(),
    ) {
        let content = content_of(n, content_seed);
        let range = range_within(n, raw_start, raw_length);
        let end = range.end().expect("in bounds");
        let s_root = Seed32::from_bytes(root_bytes);
        let fine_root = rebuild_fine_root(&s_root, &content).expect("n >= 1");

        let proof = prove_range(&s_root, &content, range, n).expect("in bounds");
        prop_assert_eq!(proof.range(), range);
        prop_assert_eq!(proof.leaf_count(), n);
        let revealed = &content[range.start() as usize..end as usize];
        prop_assert_eq!(proof.verify(revealed, &fine_root), Ok(()));

        // Proof size stays logarithmic at the ceiling — the property that
        // makes a 4096-byte file's opening the same shape as a 6-byte one.
        let log2_ceil = usize::from(proof.depth());
        prop_assert!(proof.cover().len() <= (2 * log2_ceil).max(1));
        prop_assert!(proof.boundary().len() <= (2 * log2_ceil).max(1));
    }

    /// The whole seal-side sequence, composed: canonicalize -> split -> tile
    /// -> build the fine tree over the canonical bytes -> open ONE unit ->
    /// verify. Cross-layer drift (a split range in the wrong domain, a
    /// `size` field taken from the raw bytes) is invisible to any single
    /// module's tests and shows up here.
    #[test]
    fn canonicalize_split_and_seal_compose(
        text in splitty_text(),
        which in any::<usize>(),
        root_bytes in any::<[u8; 32]>(),
    ) {
        let canonical: CanonicalBytes =
            canonicalize(UnicodeVersion::CURRENT, TextMode::Forced, text.as_bytes())
                .expect("forced mode is total");
        let size = canonical.len() as u64;
        prop_assume!(size > 0);

        let descriptor = CanonDescriptor::describe_file(
            ContentKind::Text(UnicodeVersion::CURRENT),
            size,
            FineTreeOptOut::NotRequested,
        );
        let eligible = SplitEligibleText::of(&descriptor).expect("non-empty covered text");
        let units = assign_unit_ids(&[plan_blank_line_split(eligible, &canonical)]);

        let s_root = Seed32::from_bytes(root_bytes);
        let fine_root = rebuild_fine_root(&s_root, canonical.as_bytes()).expect("size > 0");

        // Open one unit — a per-unit reveal IS a leaf-aligned range opening.
        let unit = units[which % units.len()];
        let range = unit.byte_range();
        prop_assume!(range.length() > 0);
        let end = range.end().expect("no overflow");
        let proof = prove_range(&s_root, canonical.as_bytes(), range, size)
            .expect("unit ranges are inside [0, size)");
        let revealed = &canonical.as_bytes()[range.start() as usize..end as usize];
        prop_assert_eq!(proof.verify(revealed, &fine_root), Ok(()));
    }
}

// ---------------------------------------------------------------------------
// 5. streaming vs an independent reference (G9)
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(strategies::integration_test_config(0x5EED_6205, REGRESSIONS))]

    /// `rebuild_fine_root` equals a reference tree built from **raw SHA-256
    /// and the published domain tags** — a second implementation of
    /// MVP-SPEC.md lines 78/96, not the same code called twice. Includes
    /// `n = 0` (no tree at all).
    #[test]
    fn streaming_fine_root_equals_an_independent_reference(
        content in arbitrary_bytes(300),
        root_bytes in any::<[u8; 32]>(),
    ) {
        let s_root = Seed32::from_bytes(root_bytes);
        let streamed = rebuild_fine_root(&s_root, &content);
        let reference = reference_root(&root_bytes, &content);
        prop_assert_eq!(
            streamed.as_ref().map(|root| *root.as_bytes()),
            reference,
            "the streaming builder and the independent reference disagree"
        );
    }

    /// The `n = 1` and just-past-a-power-of-two shapes at the ceiling: the
    /// reference agrees there too, and `n = 0` yields no tree.
    #[test]
    fn the_reference_agrees_at_the_awkward_sizes(
        offset in 0u64..=2,
        // Weighted like `leaf_count`: the 2^12 shapes must be reached, but
        // not on most cases (module docs, "Cost").
        exponent in prop_oneof![3 => 0u32..=6, 2 => 7u32..=10, 1 => 11u32..=12],
        root_bytes in any::<[u8; 32]>(),
    ) {
        let n = (1u64 << exponent).saturating_add(offset).min(MAX_LEAF_COUNT);
        let content = content_of(n, 0x5a);
        let s_root = Seed32::from_bytes(root_bytes);
        prop_assert_eq!(
            rebuild_fine_root(&s_root, &content).map(|root| *root.as_bytes()),
            reference_root(&root_bytes, &content)
        );
        prop_assert_eq!(rebuild_fine_root(&s_root, &[]), None, "n = 0 has no tree");
    }
}

// ---------------------------------------------------------------------------
// 6. the no-panic mutation harness into G13
// ---------------------------------------------------------------------------

/// One mutation of a wire proof. Drawn as data so proptest can shrink it.
#[derive(Debug, Clone, Copy)]
enum Mutation {
    /// Change a node's level.
    Level { at: usize, to: u8 },
    /// Change a node's index.
    Index { at: usize, to: u64 },
    /// Flip a byte of a node's payload.
    FlipByte { at: usize, byte: usize, mask: u8 },
    /// Truncate a node's payload (the wrong-length class).
    Truncate { at: usize, to: usize },
    /// Append a byte to a node's payload.
    Extend { at: usize },
    /// Drop a node.
    Drop { at: usize },
    /// Duplicate a node.
    Duplicate { at: usize },
    /// Swap two nodes (order matters — the verifier recomputes the order).
    Swap { a: usize, b: usize },
}

fn mutation() -> impl Strategy<Value = Mutation> {
    prop_oneof![
        (any::<usize>(), any::<u8>()).prop_map(|(at, to)| Mutation::Level { at, to }),
        (any::<usize>(), any::<u64>()).prop_map(|(at, to)| Mutation::Index { at, to }),
        (any::<usize>(), any::<usize>(), 1u8..=255)
            .prop_map(|(at, byte, mask)| Mutation::FlipByte { at, byte, mask }),
        (any::<usize>(), 0usize..40).prop_map(|(at, to)| Mutation::Truncate { at, to }),
        any::<usize>().prop_map(|at| Mutation::Extend { at }),
        any::<usize>().prop_map(|at| Mutation::Drop { at }),
        any::<usize>().prop_map(|at| Mutation::Duplicate { at }),
        (any::<usize>(), any::<usize>()).prop_map(|(a, b)| Mutation::Swap { a, b }),
    ]
}

/// Owned wire node, so mutations can change lengths.
type Owned = (u8, u64, Vec<u8>);

fn apply(nodes: &mut Vec<Owned>, mutation: Mutation) {
    if nodes.is_empty() {
        return;
    }
    let len = nodes.len();
    match mutation {
        Mutation::Level { at, to } => nodes[at % len].0 = to,
        Mutation::Index { at, to } => nodes[at % len].1 = to,
        Mutation::FlipByte { at, byte, mask } => {
            let node = &mut nodes[at % len];
            if !node.2.is_empty() {
                let index = byte % node.2.len();
                node.2[index] ^= mask;
            }
        }
        Mutation::Truncate { at, to } => {
            let node = &mut nodes[at % len];
            let keep = to.min(node.2.len());
            node.2.truncate(keep);
        }
        Mutation::Extend { at } => nodes[at % len].2.push(0xAA),
        Mutation::Drop { at } => {
            nodes.remove(at % len);
        }
        Mutation::Duplicate { at } => {
            let node = nodes[at % len].clone();
            nodes.push(node);
        }
        Mutation::Swap { a, b } => nodes.swap(a % len, b % len),
    }
}

fn as_wire(nodes: &[Owned]) -> Vec<WireNode<'_>> {
    nodes
        .iter()
        .map(|(level, index, bytes)| WireNode {
            level: *level,
            index: *index,
            bytes,
        })
        .collect()
}

/// The **semantically significant** projection of a wire node — since D83
/// RESOLVED, the **identity** projection.
///
/// Before D83 this function existed to carve out an exception. A cover node
/// at `level == d` covers exactly one leaf, so the verifier descends
/// `d − level == 0` levels and takes `salt_i = seed[..16]` directly, leaving
/// bytes 16..32 unread — so "every wire change is rejected" was false, and
/// the projection is what made the property exact instead of approximately
/// true. That is how the malleability was found (see the committed
/// counterexample below).
///
/// **D83 resolved as option B**, the canonical zero tail: a `level == d`
/// payload is `salt_i ‖ 0x00·16`, and a non-zero upper half is a rejection
/// (`fine-root-leaf-seed-tail-not-zero`). Every byte of every wire node is
/// therefore now either hashed or checked, and the carve-out is gone. The
/// function is kept — collapsed to the identity, with the parameters it no
/// longer needs — precisely so the *shape* of the property is unchanged and
/// the diff that closed the hole is legible: what moved is the projection,
/// not the assertion.
fn significant(nodes: &[Owned]) -> Vec<(u8, u64, usize, Vec<u8>)> {
    nodes
        .iter()
        // The length is carried separately: a wrong-length payload is
        // rejected by G13 before any byte is looked at (spec line 121).
        .map(|(level, index, bytes)| (*level, *index, bytes.len(), bytes.clone()))
        .collect()
}

proptest! {
    #![proptest_config(strategies::integration_test_config(0x5EED_6206, REGRESSIONS))]

    /// The G20 no-panic harness. Take an honest proof, mutate its wire form
    /// arbitrarily, and drive G13's `verify_range` with the result:
    ///
    /// - it must **never panic** — a bundle is adversarial input, and
    ///   library code returns errors (working principle "parse defensively");
    /// - any mutation that changes the wire form's **significant** bytes must
    ///   be **rejected**, since the verifier recomputes the canonical cover
    ///   and boundary from `(range, n)` alone;
    /// - a mutation that changes nothing must still verify.
    ///
    /// "Significant" is [`significant`], which since **D83 RESOLVED** is the
    /// identity: the property is now the unqualified "any change to the wire
    /// form is rejected" it was originally written to assert. It did not
    /// start that way — this very property, at `PROPTEST_CASES=1024`, found
    /// that a `level == d` cover node's upper 16 bytes were never examined
    /// (the counterexample is committed, and restated as a named case below),
    /// and D83 closed the hole by fixing them at zero and checking them.
    #[test]
    fn mutated_proofs_never_panic_and_never_verify(
        n in 2u64..=256,
        raw_start in any::<u64>(),
        raw_length in any::<u64>(),
        content_seed in any::<u8>(),
        root_bytes in any::<[u8; 32]>(),
        mutations in proptest::collection::vec(mutation(), 1..4),
        mutate_boundary in any::<bool>(),
    ) {
        let content = content_of(n, content_seed);
        let range = range_within(n, raw_start, raw_length);
        let end = range.end().expect("in bounds");
        let s_root = Seed32::from_bytes(root_bytes);
        let fine_root = rebuild_fine_root(&s_root, &content).expect("n >= 1");
        let proof = prove_range(&s_root, &content, range, n).expect("in bounds");
        let revealed = &content[range.start() as usize..end as usize];

        let own = |nodes: Vec<WireNode<'_>>| -> Vec<Owned> {
            nodes.into_iter().map(|w| (w.level, w.index, w.bytes.to_vec())).collect()
        };
        let honest_cover = own(proof.wire_cover());
        let honest_boundary = own(proof.wire_boundary());

        let mut cover = honest_cover.clone();
        let mut boundary = honest_boundary.clone();
        for mutation in &mutations {
            if mutate_boundary {
                apply(&mut boundary, *mutation);
            } else {
                apply(&mut cover, *mutation);
            }
        }

        // No panic — this call is the whole point of the harness.
        let wire_cover = as_wire(&cover);
        let wire_boundary = as_wire(&boundary);
        let outcome = verify_range(
            &RangeProofView { range, cover: &wire_cover, boundary: &wire_boundary },
            revealed,
            n,
            &fine_root,
        );

        let changed = significant(&cover) != significant(&honest_cover)
            || significant(&boundary) != significant(&honest_boundary);
        if changed {
            prop_assert!(
                outcome.is_err(),
                "a mutated proof verified: cover {:?} boundary {:?}",
                cover.iter().map(|n| (n.0, n.1, n.2.len())).collect::<Vec<_>>(),
                boundary.iter().map(|n| (n.0, n.1, n.2.len())).collect::<Vec<_>>()
            );
        } else {
            prop_assert_eq!(
                outcome,
                Ok(()),
                "an unchanged proof must still verify"
            );
        }
    }

    /// Nothing above is vacuous: a bit flipped in a cover node's **first** 16
    /// bytes, or anywhere in a boundary hash, really is rejected. Stated as
    /// its own property so D83's carve-out cannot quietly grow into "byte
    /// changes are fine".
    #[test]
    fn a_flip_in_the_significant_bytes_is_always_rejected(
        n in 2u64..=256,
        raw_start in any::<u64>(),
        raw_length in any::<u64>(),
        content_seed in any::<u8>(),
        root_bytes in any::<[u8; 32]>(),
        which in any::<usize>(),
        byte in 0usize..16,
        mask in 1u8..=255,
        hit_boundary in any::<bool>(),
    ) {
        let content = content_of(n, content_seed);
        let range = range_within(n, raw_start, raw_length);
        let end = range.end().expect("in bounds");
        let s_root = Seed32::from_bytes(root_bytes);
        let fine_root = rebuild_fine_root(&s_root, &content).expect("n >= 1");
        let proof = prove_range(&s_root, &content, range, n).expect("in bounds");
        let revealed = &content[range.start() as usize..end as usize];

        let own = |nodes: Vec<WireNode<'_>>| -> Vec<Owned> {
            nodes.into_iter().map(|w| (w.level, w.index, w.bytes.to_vec())).collect()
        };
        let mut cover = own(proof.wire_cover());
        let mut boundary = own(proof.wire_boundary());
        let target = if hit_boundary && !boundary.is_empty() {
            &mut boundary
        } else {
            &mut cover
        };
        let at = which % target.len();
        target[at].2[byte] ^= mask;

        let wire_cover = as_wire(&cover);
        let wire_boundary = as_wire(&boundary);
        prop_assert!(
            verify_range(
                &RangeProofView { range, cover: &wire_cover, boundary: &wire_boundary },
                revealed,
                n,
                &fine_root,
            ).is_err(),
            "a flip in the first 16 bytes must always be caught"
        );
    }

    /// Wholly arbitrary wire proofs — not derived from any real tree — must
    /// also return an error rather than panic. This is the shape a hostile
    /// `.sealproof` presents after F's decoder has done its structural work.
    #[test]
    fn arbitrary_wire_proofs_never_panic(
        n in 0u64..=64,
        raw_start in any::<u64>(),
        raw_length in any::<u64>(),
        cover in proptest::collection::vec(
            (any::<u8>(), any::<u64>(), arbitrary_bytes(36)), 0..4),
        boundary in proptest::collection::vec(
            (any::<u8>(), any::<u64>(), arbitrary_bytes(36)), 0..4),
        root_bytes in any::<[u8; 32]>(),
        revealed in arbitrary_bytes(64),
    ) {
        let s_root = Seed32::from_bytes(root_bytes);
        let content = content_of(n.max(1), 7);
        let fine_root = rebuild_fine_root(&s_root, &content).expect("n >= 1");
        let range = ByteRange::new(raw_start, raw_length);
        let wire_cover = as_wire(&cover);
        let wire_boundary = as_wire(&boundary);
        // Total, by contract: any outcome is acceptable except a panic.
        let _ = verify_range(
            &RangeProofView { range, cover: &wire_cover, boundary: &wire_boundary },
            &revealed,
            n,
            &fine_root,
        );
    }
}

// ---------------------------------------------------------------------------
// committed regression cases (Q3 §5)
// ---------------------------------------------------------------------------

/// **The D83 counterexample, as a named deterministic case — now inverted.**
///
/// `crates/antseal-core/proptest-regressions/content_properties.txt` carries
/// the shrunken seed proptest found, and replays it automatically. **Keep
/// it**: deleting the seed would discard the evidence that produced the
/// decision. A seed line is opaque, though, so the case is restated here in
/// full: this is the input that turned "any wire change is rejected" from a
/// plausible property into a recorded format question.
///
/// `n = 101` (`d = 7`), a one-leaf reveal, so the cover is the single
/// deepest node `(7, 73)`. When this case was written, flipping any bit of
/// that node's bytes 16..32 left verification **succeeding**, because the
/// verifier's descent from a `level == d` cover node is zero levels long and
/// takes `seed[..16]`.
///
/// **D83 resolved as option B**, so the same case now proves the opposite:
/// the honest wire form carries `salt_73 ‖ 0x00·16`, and every one of those
/// sixteen bytes is checked. The assertions below are the same assertions
/// with `Ok(())` replaced by the exact rejection — which is the whole point
/// of keeping the case rather than replacing it.
#[test]
fn d83_leaf_level_cover_seed_tail_committed_counterexample() {
    let n: u64 = 101;
    let content = content_of(n, 0);
    let s_root = Seed32::from_bytes([0u8; 32]);
    let fine_root = rebuild_fine_root(&s_root, &content).expect("n >= 1");
    let range = ByteRange::new(73, 1);
    let proof = prove_range(&s_root, &content, range, n).expect("in bounds");
    let revealed = &content[73..74];

    // The shape the counterexample depends on: one cover node, at the leaf
    // level of a d = 7 tree.
    assert_eq!(proof.depth(), 7);
    assert_eq!(proof.cover().len(), 1);
    assert_eq!(proof.cover()[0].node().address().level(), 7);
    assert_eq!(proof.cover()[0].node().address().index(), 73);

    let boundary: Vec<(u8, u64, Vec<u8>)> = proof
        .wire_boundary()
        .into_iter()
        .map(|w| (w.level, w.index, w.bytes.to_vec()))
        .collect();
    // Since D83 the disclosed payload is NOT the derived seed at this level:
    // it is `salt_73 ‖ 0x00·16`. Both facts are asserted, because the whole
    // case turns on the difference between them.
    let mut payload = proof.cover()[0].payload().as_bytes().to_vec();
    let derived = proof.cover()[0].seed().as_bytes().to_vec();
    assert_eq!(payload[..Salt16::LEN], derived[..Salt16::LEN]);
    assert_eq!(payload[Salt16::LEN..], [0u8; 16]);
    assert_ne!(payload, derived, "the derived seed has a non-zero tail");

    let verify_with = |payload: &[u8]| {
        let cover = vec![WireNode {
            level: 7,
            index: 73,
            bytes: payload,
        }];
        let wire_boundary = as_wire(&boundary);
        verify_range(
            &RangeProofView {
                range,
                cover: &cover,
                boundary: &wire_boundary,
            },
            revealed,
            n,
            &fine_root,
        )
    };

    assert_eq!(verify_with(&payload), Ok(()), "the honest proof verifies");

    // **INVERTED BY D83.** Every byte of the tail is now checked, with its
    // own code — the mutation class that previously had no observable effect
    // at all, which is what made a tamper row for it unlandable as written.
    for index in Salt16::LEN..Seed32::LEN {
        payload[index] ^= 0x01;
        assert_eq!(
            verify_with(&payload),
            Err(FineTreeError::LeafSeedTailNotZero {
                level: 7,
                index: 73
            }),
            "byte {index} of a leaf-level cover payload must be checked (D83)"
        );
        payload[index] ^= 0x01;
    }

    // Unchanged: every byte of the significant half fails, as the salt.
    for index in 0..Salt16::LEN {
        payload[index] ^= 0x01;
        assert!(
            verify_with(&payload).is_err(),
            "byte {index} of a leaf-level cover payload IS the salt and must be checked"
        );
        payload[index] ^= 0x01;
    }

    // And the *derived* seed, offered whole — the exact artifact the old
    // behaviour accepted — is now rejected. This is D83 stated as one line.
    assert_eq!(
        verify_with(&derived),
        Err(FineTreeError::LeafSeedTailNotZero {
            level: 7,
            index: 73
        })
    );
}
