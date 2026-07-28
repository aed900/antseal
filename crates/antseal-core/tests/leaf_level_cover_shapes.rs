//! **R37** — the leaf-level (`level == d`) GGM cover class, asserted at the
//! catalogue level.
//!
//! Until R37 no committed fixture produced a cover node at the grid's leaf
//! level, so roughly three quarters of all real reveal shapes (D83 §1 Fact 3)
//! and the whole of D83's wire rule were unexercised end to end. This file is
//! the statement that the gap is closed and stays closed.
//!
//! # What "asserted directly" means here
//!
//! Every claim below is read off a **decoded bundle's cover addresses**
//! compared against `d = ⌈log₂ n⌉`, never inferred from a file length. That
//! distinction is the whole point of the task: the plausible-sounding rule
//! "a leaf-level node appears iff `n` is odd" is **false**, and believing it
//! is what let the gap survive five waves. The true rule is D83 §1 Fact 2,
//!
//! ```text
//! a cover of leaves [a, b) of an n-leaf file contains a level == d node
//!     iff   d == 0  ∨  a odd  ∨  (b odd ∧ b < n)
//! ```
//!
//! which is a statement about **unit boundaries**, not about file parity: by
//! D83 §1 Fact 1 the whole-file cover `[0, n)` is the single root node for
//! *every* `n`, so an unsplit odd-length file discloses no leaf-level node at
//! all — except at `n == 1`, where `d == 0` makes the root a leaf.
//! [`the_incidence_rule_holds_over_the_grid`] re-derives that rule from the
//! implementation rather than from this comment.
//!
//! # The shapes
//!
//! | shape | why |
//! |---|---|
//! | `odd-split-multi-unit/all` | odd-length file, odd unit boundaries: a **full** reveal shipping leaf-level nodes under D75-BOTH |
//! | `odd-split-multi-unit/partial` | the same nodes in a **partial** reveal, so the class is not full-reveal-only |
//! | `unbalanced-n6-odd-split/unit-1` | G11's normative KAT `(3, 2)`, at bundle level |
//! | `one-byte-file/full` | `n == 1`, `d == 0`: the degenerate case where the cover payload and `s_root` are the same 32 bytes |

use std::collections::BTreeMap;

use antseal_core::bundle::SealProof;
use antseal_core::content::ggm::depth_for_leaf_count;
use antseal_core::content::{ByteRange, minimal_cover};
use antseal_core::test_util::bundle_fixtures::{BuiltFixture, build, shapes};

/// Lower-case hex, local so the test carries no dependency on a test-util
/// helper's visibility.
fn rendered_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

/// Every `(shape, unit_id, level, index)` whose disclosed cover node sits at
/// its file's leaf level, over one built fixture.
fn leaf_level_nodes(name: &'static str, built: &BuiltFixture) -> Vec<(&'static str, u64, u8, u64)> {
    let proof = SealProof::decode(&built.bytes).expect("fixture decodes");
    let body = proof.manifest().body();
    let mut found = Vec::new();

    for reveal in proof.bundle().covered_reveals() {
        let file_index = body
            .files()
            .iter()
            .position(|file| {
                file.units()
                    .iter()
                    .any(|unit| unit.unit_id() == reveal.unit_id())
            })
            .expect("every covered reveal names a manifest unit");
        let size = built.files[file_index].size;
        let Some(depth) = depth_for_leaf_count(size) else {
            continue; // an empty file has no grid
        };
        for entry in reveal.cover() {
            if entry.address().level() == depth {
                found.push((
                    name,
                    reveal.unit_id(),
                    entry.address().level(),
                    entry.address().index(),
                ));
            }
        }
    }
    found
}

/// The catalogue's leaf-level nodes, keyed by shape.
fn catalogue_leaf_level_nodes() -> BTreeMap<&'static str, Vec<(u64, u8, u64)>> {
    let mut out = BTreeMap::new();
    for case in shapes::catalogue() {
        let built = build(&case.spec, &case.selection);
        let nodes: Vec<(u64, u8, u64)> = leaf_level_nodes(case.name, &built)
            .into_iter()
            .map(|(_, unit, level, index)| (unit, level, index))
            .collect();
        if !nodes.is_empty() {
            out.insert(case.name, nodes);
        }
    }
    out
}

/// **R37's first Accept bullet.** The catalogue contains covered reveals with
/// a `level == d` cover node, and the census is pinned exactly.
///
/// Pinned as an equality rather than a `>= 1`: a bare existence check would
/// still pass if a refactor silently dropped three of the four shapes, and
/// the *distribution* is the interesting part — one shape supplies it through
/// a full reveal, one through a partial reveal, one through the `n == 1`
/// degeneracy, and one is G11's KAT.
#[test]
fn the_catalogue_produces_leaf_level_cover_nodes() {
    let census = catalogue_leaf_level_nodes();

    let expected: BTreeMap<&'static str, Vec<(u64, u8, u64)>> = [
        // n = 35 split 11/11/13, full reveal: units [0,11) and [11,22) each
        // contribute one; [22,35) ends at the file end, so its ragged right
        // edge is absorbed (D83 Fact 2's `b < n` clause).
        ("odd-split-multi-unit/all", vec![(0, 6, 10), (1, 6, 11)]),
        // The same file, unit 1 alone: a = 11 is odd, so the node survives
        // into a partial reveal.
        ("odd-split-multi-unit/partial", vec![(1, 6, 11)]),
        // n = 1: d = 0, the root IS the leaf.
        ("one-byte-file/full", vec![(0, 0, 0)]),
        // n = 6 split 2/1/3, full reveal: unit 1 = [2,3) -> (3,2),
        // unit 2 = [3,6) -> (3,3).
        ("unbalanced-n6-odd-split/all", vec![(1, 3, 2), (2, 3, 3)]),
        // G11's normative KAT, standing alone.
        ("unbalanced-n6-odd-split/unit-1", vec![(1, 3, 2)]),
    ]
    .into_iter()
    .collect();

    assert_eq!(
        census, expected,
        "the leaf-level census moved. Adding a shape that produces one is fine — add its row. \
         LOSING one is not: it would mean D83's wire rule is unexercised at bundle level again."
    );
}

/// The class is reachable **without** a whole-file disclosure.
///
/// Split out from the census because it is the specific gap R37's third
/// clause names: if every leaf-level node arrived only through a full reveal,
/// the partial-reveal path through `verify_range` — which is where a real
/// selective disclosure lives — would still be untested.
#[test]
fn a_partial_reveal_carries_a_leaf_level_cover_node() {
    for name in [
        "odd-split-multi-unit/partial",
        "unbalanced-n6-odd-split/unit-1",
    ] {
        let case = shapes::by_name(name).expect("catalogue case");
        let built = build(&case.spec, &case.selection);
        assert!(
            built.files.iter().all(|file| !file.fully_revealed),
            "`{name}` must be a PARTIAL reveal, or it proves the wrong thing"
        );
        assert!(
            !leaf_level_nodes(name, &built).is_empty(),
            "`{name}` carries no level == d cover node"
        );
    }
}

/// **R37's second Accept bullet.** At `n == 1` the disclosed cover payload
/// and `full_reveal.s_root` are the *same* 32 bytes, pinned as one value.
///
/// D83 §2 is the reason this needs saying: `d == 0` makes the grid root the
/// single leaf, so one bundle carries the same material at registry §7.11
/// key 3 and §7.14 key 2. Under D83 option B both are `salt_0 ‖ 0x00·16`, so
/// D75's outstanding "agreement rider" discharges as a plain byte equality —
/// and pinning the shared value here makes any future divergence a diff
/// rather than a silent re-derivation.
#[test]
fn the_one_byte_full_reveal_pins_one_value_at_both_sites() {
    let case = shapes::by_name("one-byte-file/full").expect("catalogue case");
    let built = build(&case.spec, &case.selection);
    let proof = SealProof::decode(&built.bytes).expect("fixture decodes");

    let reveals = proof.bundle().covered_reveals();
    assert_eq!(reveals.len(), 1, "the one-byte file has one covered unit");
    let cover = reveals[0].cover();
    assert_eq!(cover.len(), 1, "its cover is the single node (0, 0)");
    assert_eq!(cover[0].address().level(), 0);
    assert_eq!(cover[0].address().index(), 0);

    let fulls = proof.bundle().full_reveals();
    assert_eq!(fulls.len(), 1, "one fully revealed file");
    let s_root = fulls[0]
        .disclosed_s_root()
        .expect("a fully revealed fine-tree file discloses s_root");

    assert_eq!(
        cover[0].seed().as_bytes(),
        s_root.as_bytes(),
        "at n == 1 the cover payload and s_root are the same disclosure; D75's agreement rider \
         is a byte equality once D83 fixes the tail"
    );

    // The shared value, pinned. It is `salt_0 ‖ 0x00·16` by D83 option B —
    // NOT the raw GGM seed, whose upper half is real but unread material.
    //
    // Deliberately NOT the fine-tree vector's `n1-root-is-leaf` value
    // (`b723077e…`): that case derives its `s_root` directly, while this one
    // is `HKDF(W, "fine-seed", file_id)` for R6's `data/one.bin`. Two
    // independent derivations of the same *rule*, which is worth more than
    // one number reused twice — the shared zero tail is what both pin.
    const PINNED: &str = "27367827ba525c57ebe82b2cd824983c00000000000000000000000000000000";
    assert_eq!(
        rendered_hex(s_root.as_bytes()),
        PINNED,
        "the n == 1 leaf-level payload moved. It is disclosed at two registry sites in one \
         bundle and pinned in the bundle vector, so a change here is a format event."
    );
    assert!(
        s_root.as_bytes()[16..].iter().all(|byte| *byte == 0),
        "D83's canonical tail"
    );
}

/// D83 §1 Fact 2, re-derived from `minimal_cover` rather than trusted.
///
/// D83 §9.6 asks for this: the rule was verified exhaustively only to
/// `n ≤ 24` when it was written, and every sizing argument in §3 — and every
/// "this fixture cannot produce one" claim in §6's must-not-change table —
/// rests on it. Exhaustive to `n = 128` here (~0.4 M covers, well inside a
/// default-lane budget); verified to `n = 512` offline while landing R37,
/// zero mismatches, recorded in D83's R37 amendment.
#[test]
fn the_incidence_rule_holds_over_the_grid() {
    for n in 1u64..=128 {
        let depth = depth_for_leaf_count(n).expect("n > 0");
        for a in 0..n {
            for b in (a + 1)..=n {
                let cover =
                    minimal_cover(ByteRange::new(a, b - a), n).expect("a sub-range is in bounds");
                let observed = cover
                    .nodes()
                    .iter()
                    .any(|node| node.address().level() == depth);
                let predicted = depth == 0 || a % 2 == 1 || (b % 2 == 1 && b < n);
                assert_eq!(
                    observed, predicted,
                    "D83 Fact 2 is wrong at n = {n}, [a, b) = [{a}, {b}) — record the \
                     counterexample in D83 before changing anything else"
                );
            }
        }
    }
}

/// The bundles agree with the rule too — the same statement one layer up,
/// over real reveals rather than synthetic ranges.
///
/// This is what keeps the census in
/// [`the_catalogue_produces_leaf_level_cover_nodes`] honest: it says *which*
/// shapes have the nodes, and this says the answer is a consequence of their
/// unit boundaries and nothing else.
#[test]
fn every_catalogue_reveal_matches_the_incidence_rule() {
    for case in shapes::catalogue() {
        let built = build(&case.spec, &case.selection);
        let proof = SealProof::decode(&built.bytes).expect("fixture decodes");
        let body = proof.manifest().body();
        let observed = leaf_level_nodes(case.name, &built);

        for reveal in proof.bundle().covered_reveals() {
            let (file_index, unit) = body
                .files()
                .iter()
                .enumerate()
                .find_map(|(index, file)| {
                    file.units()
                        .iter()
                        .find(|unit| unit.unit_id() == reveal.unit_id())
                        .map(|unit| (index, unit))
                })
                .expect("every covered reveal names a manifest unit");
            let size = built.files[file_index].size;
            let Some(depth) = depth_for_leaf_count(size) else {
                continue;
            };
            let (a, b) = (
                unit.range().start(),
                unit.range().end_exclusive().expect("in range"),
            );
            let predicted = depth == 0 || a % 2 == 1 || (b % 2 == 1 && b < size);
            let observed_here = observed
                .iter()
                .any(|(_, unit_id, _, _)| *unit_id == reveal.unit_id());
            assert_eq!(
                observed_here,
                predicted,
                "shape `{}` unit {}: leaves [{a}, {b}) of n = {size}",
                case.name,
                reveal.unit_id()
            );
        }
    }
}
