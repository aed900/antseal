//! G16 — the leaf-exact-cover **disclosure** test: the spec-mandated
//! puncturing-soundness regression guard.
//!
//! # The rule this file exists to guard
//!
//! > **Normative: the cover MUST be leaf-exact** … a merely-valid dyadic
//! > cover whose node spans an unrevealed real leaf `j < n` would disclose
//! > `salt_j` and reopen the per-byte confirmation attack; **no seed that is
//! > an ancestor of any unrevealed leaf ever leaves the vault**
//! > (MVP-SPEC.md line 96; M0 milestone, line 153)
//!
//! # Why this is not a duplicate of G11's KATs
//!
//! G11 already pins both spec KATs — `n = 6` reveal `{2}` → `(3,2)` and
//! `n = 6` reveal `[4,6)` → `(1,1)` — and `cover_seeds` is the crate's only
//! seed-disclosure path. Those say *which nodes* ship. This file asks the
//! question one level up, which is the question the attacker asks:
//!
//! > given the seeds that actually ship, what is the **full closure** of
//! > salts an adversary can derive from them?
//!
//! GGM derivation is one-way downward, so a disclosed seed at `(l, i)` hands
//! its holder every descendant leaf seed — the whole subtree, not just the
//! nodes anyone intended. The closure is therefore computed here by really
//! walking `child_seed` down from each disclosed seed, never by re-deriving
//! from `s_root`: what is asserted is what a bundle recipient can compute.
//!
//! # The acceptance clause, proved rather than asserted
//!
//! tasks/G.md G16 requires that regressing the cover algorithm to *any*
//! merely-valid (non-leaf-exact) dyadic cover **fails** this test. That is
//! established twice:
//!
//! 1. [`coarsening_the_cover_upward_is_caught`] runs a concrete, plausible
//!    regression — "coalesce each node into its parent to ship fewer, bigger
//!    seeds" — through the same battery and shows exactly what leaks.
//! 2. [`every_merely_valid_non_leaf_exact_cover_fails_the_battery`] proves
//!    the general claim by **exhaustion** over all 2^12 subsets of the used
//!    grid nodes at `n = 6`: for every candidate cover of the revealed range,
//!    the battery accepts it **iff** it is leaf-exact. Not a sample — every
//!    dyadic cover there is.

use std::collections::{BTreeMap, BTreeSet};

use antseal_core::content::{
    ByteRange, ChildBit, NodeAddress, SaltTree, child_seed, cover_seeds, minimal_cover,
};
use antseal_core::crypto::material::{Salt16, Seed32};
use antseal_core::test_util::alternate_test_secret;
use antseal_core::test_util::vectors_fine_tree::S_ROOT_LABEL;

/// The fixture file: `n = 6`, the unbalanced case the spec names, `d = 3`,
/// slots 6 and 7 unused.
const N: u64 = 6;
const DEPTH: u8 = 3;

/// The same synthetic `s_root` the committed G15 vector pins, so a reader can
/// line the two up byte for byte. NON-SECRET by the documented convention:
/// `s_root = SHA-256(label ‖ TEST_MASTER_SECRET_W)`.
fn s_root() -> Seed32 {
    Seed32::from_bytes(alternate_test_secret(S_ROOT_LABEL.as_bytes()))
}

fn tree(s_root: &Seed32) -> SaltTree<'_> {
    SaltTree::new(s_root, N).expect("n = 6 has a salt tree")
}

fn address(level: u8, index: u64) -> NodeAddress {
    NodeAddress::try_new(level, index).expect("address is on the grid")
}

// ---------------------------------------------------------------------------
// the closure: what a holder of these seeds can actually derive
// ---------------------------------------------------------------------------

/// Every leaf slot reachable from `address`, paired with the salt derived by
/// walking down from `seed` — the real GGM descent, so this is what a bundle
/// recipient computes, not what we believe they compute.
///
/// Unused slots (`>= n`) are included deliberately: they are part of the
/// closure, and the whole point of the `[4,6)` companion case is that
/// deriving them harms nothing because they commit no byte.
fn closure_from(seed: &Seed32, address: NodeAddress, out: &mut BTreeMap<u64, [u8; 16]>) {
    if address.level() == DEPTH {
        let mut salt = [0u8; Salt16::LEN];
        salt.copy_from_slice(&seed.as_bytes()[..Salt16::LEN]);
        out.insert(address.index(), salt);
        return;
    }
    for bit in ChildBit::ALL {
        let child = address.child(bit).expect("not at the maximum level");
        closure_from(&child_seed(seed, bit), child, out);
    }
}

/// The closure of a whole cover, given as `(address, seed)` pairs.
fn closure_of(disclosed: &[(NodeAddress, Seed32)]) -> BTreeMap<u64, [u8; 16]> {
    let mut out = BTreeMap::new();
    for (address, seed) in disclosed {
        closure_from(seed, *address, &mut out);
    }
    out
}

/// Derive the seeds a cover would ship, by descending from `s_root`.
///
/// Used only for the *hypothetical* covers the regression proof exercises;
/// the real covers go through the crate's `cover_seeds`, which is the only
/// seed-disclosure path that exists in production code.
fn hypothetical_seeds(s_root: &Seed32, cover: &[NodeAddress]) -> Vec<(NodeAddress, Seed32)> {
    let tree = tree(s_root);
    cover
        .iter()
        .map(|address| {
            let seed = tree
                .seed_at(*address)
                .expect("candidate covers only use nodes that cover a real leaf");
            (*address, seed)
        })
        .collect()
}

// ---------------------------------------------------------------------------
// the battery
// ---------------------------------------------------------------------------

/// The three disclosure properties, as a **predicate** so the regression
/// proof can exercise it rather than only assert it:
///
/// 1. **Completeness** — the closure yields the correct `salt_j` for every
///    revealed leaf, so the reveal actually opens.
/// 2. **Soundness (puncturing)** — the closure contains **no** `salt_j` for
///    any real (`j < n`) unrevealed leaf. This is the line-96 rule.
/// 3. **`s_root` absent on a partial reveal** — neither shipped directly nor
///    named. The root is released **iff** the range is the whole file
///    (MVP-SPEC.md line 96), so this rule is conditioned on the reveal being
///    partial rather than stated absolutely; the `iff` in the other direction
///    is [`the_full_reveal_is_the_only_case_that_releases_s_root`].
///
/// Returns the reason on failure, so the exhaustive proof can show *why*
/// each rejected cover is rejected.
fn disclosure_battery(
    s_root: &Seed32,
    disclosed: &[(NodeAddress, Seed32)],
    revealed: &BTreeSet<u64>,
) -> Result<BTreeMap<u64, [u8; 16]>, String> {
    let tree = tree(s_root);
    let derived = closure_of(disclosed);
    let full_reveal = (0..N).all(|leaf| revealed.contains(&leaf));

    // 3. s_root: not as an address, not as bytes — unless the reveal is the
    //    whole file, which is precisely the case that releases it.
    if !full_reveal {
        for (address, seed) in disclosed {
            if *address == NodeAddress::root() {
                return Err("the cover contains the root — that IS s_root".to_owned());
            }
            if seed.as_bytes() == s_root.as_bytes() {
                return Err("a disclosed seed is s_root itself".to_owned());
            }
        }
    }

    // 1. Completeness.
    for &leaf in revealed {
        let expected = tree.salt(leaf).expect("revealed leaves are real");
        match derived.get(&leaf) {
            None => return Err(format!("salt_{leaf} is revealed but not derivable")),
            Some(salt) if salt != expected.as_bytes() => {
                return Err(format!("the derived salt_{leaf} is not the tree's"));
            }
            Some(_) => {}
        }
    }

    // 2. Soundness — the security-bearing half.
    for leaf in 0..N {
        if revealed.contains(&leaf) {
            continue;
        }
        if derived.contains_key(&leaf) {
            return Err(format!(
                "salt_{leaf} is derivable but leaf {leaf} is NOT revealed — \
                 the cover spans an unrevealed real leaf (MVP-SPEC.md line 96)"
            ));
        }
    }
    Ok(derived)
}

/// The addresses the crate would really ship for `range`, through the one
/// disclosure path that exists.
fn shipped(s_root: &Seed32, range: ByteRange) -> Vec<(NodeAddress, Seed32)> {
    let cover = minimal_cover(range, N).expect("range is in bounds");
    cover_seeds(s_root, &cover)
        .into_iter()
        .map(|entry| {
            (
                entry.node().address(),
                Seed32::from_bytes(*entry.seed().as_bytes()),
            )
        })
        .collect()
}

// ---------------------------------------------------------------------------
// the spec-mandated case: n = 6, reveal {2}
// ---------------------------------------------------------------------------

/// **The G16 test** (MVP-SPEC.md line 153's "leaf-exact-cover disclosure
/// test"). At `n = 6`, build the shipped cover for reveal `{2}`, enumerate
/// every seed in it, compute the full closure of derivable salts, and require
/// that the closure is exactly `{salt_2}` among the real leaves — with
/// `s_root` nowhere in sight.
///
/// This is the **puncturing-soundness regression guard**: the GGM tree is a
/// puncturable PRF, and the guarantee being defended is that puncturing at
/// `{2}` hands out a key that opens leaf 2 and *provably nothing else real*.
/// A cover that merely happens to be a valid dyadic decomposition would
/// reopen the per-byte confirmation attack on every leaf it over-spans.
#[test]
fn leaf_exact_cover_at_n6_reveal_2_discloses_exactly_salt_2() {
    let s_root = s_root();
    let tree = tree(&s_root);
    let disclosed = shipped(&s_root, ByteRange::new(2, 1));

    // Every seed the cover contains — the enumeration the task asks for.
    assert_eq!(disclosed.len(), 1, "reveal {{2}} ships exactly one seed");
    assert_eq!(
        disclosed[0].0,
        address(3, 2),
        "the deepest single-leaf node for slot 2 (G11's KAT)"
    );

    let revealed: BTreeSet<u64> = [2].into_iter().collect();
    let derived = disclosure_battery(&s_root, &disclosed, &revealed)
        .unwrap_or_else(|why| panic!("the shipped cover must satisfy the battery: {why}"));

    // Stated again explicitly, in the spec's own terms, so the test reads as
    // the claim it is making rather than as a call to a helper.
    assert_eq!(
        derived.get(&2).copied(),
        Some(*tree.salt(2).expect("leaf 2 is real").as_bytes()),
        "salt_2 IS derivable — the reveal opens"
    );
    for j in [0u64, 1, 3, 4, 5] {
        assert!(
            !derived.contains_key(&j),
            "salt_{j} must NOT be derivable: leaf {j} is a real unrevealed leaf"
        );
    }
    assert_ne!(
        disclosed[0].1.as_bytes(),
        s_root.as_bytes(),
        "s_root is absent — it is released iff the range is [0, n)"
    );
    // The closure is a single slot: nothing at all beyond leaf 2, real or not.
    assert_eq!(derived.keys().copied().collect::<Vec<_>>(), vec![2]);
}

/// The companion **positive** case (G16): at `n = 6`, reveal `[4,6)` ships the
/// node spanning slots `[4,8)` — real leaves 4 and 5 *plus the unused slots 6
/// and 7*. Deriving those two extra slot values discloses no real unrevealed
/// salt, because slots `>= n` commit no byte; that allowance is what keeps
/// the cover size at `O(log n)` on a ragged right edge.
#[test]
fn the_node_spanning_unused_slots_discloses_no_real_unrevealed_salt() {
    let s_root = s_root();
    let disclosed = shipped(&s_root, ByteRange::new(4, 2));

    assert_eq!(disclosed.len(), 1);
    assert_eq!(
        disclosed[0].0,
        address(1, 1),
        "one node over slots [4,8) (G11's second KAT)"
    );

    let revealed: BTreeSet<u64> = [4, 5].into_iter().collect();
    let derived = disclosure_battery(&s_root, &disclosed, &revealed)
        .unwrap_or_else(|why| panic!("the unused-slot allowance must be sound: {why}"));

    // The closure really does reach the unused slots — the allowance is being
    // exercised, not sidestepped — and they are the ONLY extra members.
    assert_eq!(
        derived.keys().copied().collect::<Vec<_>>(),
        vec![4, 5, 6, 7],
        "slots 6 and 7 are derivable and are not real leaves"
    );
    for j in [0u64, 1, 2, 3] {
        assert!(
            !derived.contains_key(&j),
            "salt_{j} must NOT be derivable from the [4,6) cover"
        );
    }
}

/// The full reveal is the one case where `s_root` legitimately leaves the
/// vault — stated here so the `s_root`-absent assertions above are read as
/// "iff the range is `[0, n)`", not as "never".
#[test]
fn the_full_reveal_is_the_only_case_that_releases_s_root() {
    let s_root = s_root();
    let cover = minimal_cover(ByteRange::new(0, N), N).expect("full range");
    assert!(cover.releases_s_root());
    let entries = cover_seeds(&s_root, &cover);
    assert_eq!(entries.len(), 1);
    assert_eq!(
        entries[0].seed().as_bytes(),
        s_root.as_bytes(),
        "the full-range cover IS s_root"
    );
    for start in 0..N {
        for length in 1..=(N - start) {
            if start == 0 && length == N {
                continue;
            }
            let partial = minimal_cover(ByteRange::new(start, length), N).expect("in bounds");
            assert!(
                !partial.releases_s_root(),
                "[{start},{}) is partial and must not release s_root",
                start + length
            );
        }
    }
}

// ---------------------------------------------------------------------------
// the acceptance clause: the battery really does catch a regression
// ---------------------------------------------------------------------------

/// Every grid node at `n = 6` that covers at least one real leaf — the only
/// nodes any implementation could plausibly emit (the crate refuses to derive
/// the others at all).
fn used_nodes() -> Vec<NodeAddress> {
    let mut nodes = Vec::new();
    for level in 0..=DEPTH {
        for index in 0..(1u64 << level) {
            if (index << (DEPTH - level)) < N {
                nodes.push(address(level, index));
            }
        }
    }
    nodes
}

/// The real leaves a node covers.
fn real_span(node: NodeAddress) -> BTreeSet<u64> {
    let first = node.first_slot(DEPTH).expect("on the grid");
    let width = u64::try_from(node.slot_width(DEPTH).expect("on the grid")).unwrap_or(u64::MAX);
    (first..first.saturating_add(width).min(N)).collect()
}

/// A concrete, plausible regression: **coarsen the cover upward** — replace
/// each node by its parent so the bundle ships fewer, bigger seeds. The
/// result is still a perfectly valid dyadic cover of the revealed range. It
/// is not leaf-exact, and the battery says so, naming the leak.
#[test]
fn coarsening_the_cover_upward_is_caught() {
    let s_root = s_root();

    // reveal {2}: (3,2) coarsens to (2,1), whose real span is {2, 3}.
    let coarse = vec![address(2, 1)];
    assert_eq!(real_span(coarse[0]), [2u64, 3].into_iter().collect());
    let why = disclosure_battery(
        &s_root,
        &hypothetical_seeds(&s_root, &coarse),
        &[2u64].into_iter().collect(),
    )
    .expect_err("a cover spanning leaf 3 must be rejected");
    assert!(
        why.contains("salt_3") && why.contains("NOT revealed"),
        "the battery must name the leaked salt; got: {why}"
    );

    // reveal [4,6): (1,1) coarsens to the root, i.e. straight to s_root.
    let why = disclosure_battery(
        &s_root,
        &hypothetical_seeds(&s_root, &[address(0, 0)]),
        &[4u64, 5].into_iter().collect(),
    )
    .expect_err("a cover containing the root must be rejected on a partial reveal");
    assert!(why.contains("s_root"), "got: {why}");

    // And the shipped covers are *not* the coarsened ones — the crate is not
    // accidentally passing because it emits something else entirely.
    assert_eq!(shipped(&s_root, ByteRange::new(2, 1))[0].0, address(3, 2));
    assert_eq!(shipped(&s_root, ByteRange::new(4, 2))[0].0, address(1, 1));
}

/// **The general claim, by exhaustion.** Over all `2^12` subsets of the used
/// grid nodes at `n = 6`, for each revealed range: a candidate that covers
/// the range passes [`disclosure_battery`] **iff** it is leaf-exact. So no
/// merely-valid dyadic cover can pass — there is no such cover left to try.
///
/// This is what makes G16 a regression guard rather than a KAT: whatever a
/// future `minimal_cover` returns, if it is not leaf-exact it is in the
/// rejected set.
#[test]
fn every_merely_valid_non_leaf_exact_cover_fails_the_battery() {
    let s_root = s_root();
    let nodes = used_nodes();
    assert_eq!(nodes.len(), 12, "n = 6, d = 3: twelve used grid nodes");

    // Precompute so the sweep is cheap; the battery still does the real GGM
    // descent per candidate.
    let spans: Vec<BTreeSet<u64>> = nodes.iter().copied().map(real_span).collect();

    let mut checked = 0usize;
    let mut accepted = 0usize;
    for (start, length) in [(2u64, 1u64), (4, 2), (1, 2), (0, 6)] {
        let revealed: BTreeSet<u64> = (start..start + length).collect();
        let ship = shipped(&s_root, ByteRange::new(start, length));
        let shipped_set: BTreeSet<NodeAddress> = ship.iter().map(|(a, _)| *a).collect();
        let mut shipped_was_accepted = false;

        for mask in 0u32..(1 << 12) {
            let candidate: Vec<NodeAddress> = (0..12)
                .filter(|bit| mask & (1 << bit) != 0)
                .map(|bit| nodes[bit])
                .collect();
            if candidate.is_empty() {
                continue;
            }
            // "Covers the revealed range" — the minimum any cover must do.
            let union: BTreeSet<u64> = (0..12)
                .filter(|bit| mask & (1 << bit) != 0)
                .flat_map(|bit| spans[bit].iter().copied())
                .collect();
            if !revealed.is_subset(&union) {
                continue;
            }
            checked += 1;

            // Leaf-exact: every emitted node's REAL span lies inside the
            // revealed range (MVP-SPEC.md line 96).
            let leaf_exact = (0..12)
                .filter(|bit| mask & (1 << bit) != 0)
                .all(|bit| spans[bit].is_subset(&revealed));

            let verdict =
                disclosure_battery(&s_root, &hypothetical_seeds(&s_root, &candidate), &revealed);
            assert_eq!(
                verdict.is_ok(),
                leaf_exact,
                "reveal [{start},{}): candidate {candidate:?} is {}leaf-exact but the \
                 battery {}; a merely-valid dyadic cover must never pass",
                start + length,
                if leaf_exact { "" } else { "not " },
                if verdict.is_ok() {
                    "accepted it"
                } else {
                    "rejected it"
                }
            );
            if verdict.is_ok() {
                accepted += 1;
                // The shipped cover is minimal among the acceptable ones.
                assert!(
                    ship.len() <= candidate.len(),
                    "reveal [{start},{}): the shipped cover ({} node(s)) must be no larger \
                     than any other leaf-exact cover ({} node(s))",
                    start + length,
                    ship.len(),
                    candidate.len()
                );
                if candidate.iter().copied().collect::<BTreeSet<_>>() == shipped_set {
                    shipped_was_accepted = true;
                }
            }
        }
        assert!(
            shipped_was_accepted,
            "reveal [{start},{}): the crate's own cover must be among the accepted ones",
            start + length
        );
    }
    // The sweep is not vacuous in either direction.
    assert!(checked > 1_000, "only {checked} candidate covers examined");
    assert!(
        accepted > 0 && accepted < checked,
        "accepted {accepted} of {checked}"
    );
    println!("G16 exhaustive sweep: {accepted} of {checked} candidate covers are leaf-exact");
}
