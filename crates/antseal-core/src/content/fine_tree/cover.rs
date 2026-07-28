//! The leaf-exact minimal GGM sub-cover (tasks/G.md G11; MVP-SPEC.md
//! lines 96, 114).
//!
//! # What a cover is, and the rule it must obey
//!
//! Revealing leaves `[a, b)` of a fine-tree file means handing the verifier
//! enough GGM material to derive `salt_a … salt_{b−1}` and **nothing else**.
//! MSB-first leaf indexing makes any contiguous range a dyadic decomposition,
//! so instead of `b − a` salts the reveal ships the seeds of the few maximal
//! subtrees whose leaves are exactly the revealed ones — at most
//! `2·ceil(log2 n)` seeds, ~1.7 KB even at `n = 10^8` (line 96).
//!
//! The normative constraint is not "a valid dyadic cover" but the strictly
//! stronger:
//!
//! > **Normative: the cover MUST be leaf-exact** (deepest single-leaf nodes at
//! > the range boundaries) — a merely-valid dyadic cover whose node spans an
//! > unrevealed real leaf `j < n` would disclose `salt_j` and reopen the
//! > per-byte confirmation attack; **no seed that is an ancestor of any
//! > unrevealed leaf ever leaves the vault** (MVP-SPEC.md line 96)
//!
//! ## Unused slots are not leaves
//!
//! The GGM grid has `2^d >= n` slots; slots `i >= n` commit nothing and no
//! byte is ever opened under them. A node may therefore span unused slots
//! freely — what it may not span is an unrevealed **real** leaf. This is not
//! a loophole but the thing that keeps the `2·ceil(log2 n)` bound honest at a
//! ragged right edge: at `n = 6` a reveal of `[4, 6)` emits the single node
//! over slots `[4, 8)`, whose real leaves are exactly 4 and 5.
//!
//! # Made unconstructible, not merely rejected
//!
//! [`LeafExactCover`] has no public constructor. The only way to obtain one
//! is [`minimal_cover`], whose recursion emits a node **only** when the
//! node's real-leaf span lies wholly inside the revealed range; and
//! [`cover_seeds`] — the only function in the crate that turns cover nodes
//! into disclosable seeds — takes a `&LeafExactCover` and nothing else. So
//! "ask the vault for an ancestor seed" is not a call anybody can write. It
//! is the same discipline as
//! [`SplitEligibleText`](crate::content::SplitEligibleText) and
//! [`FullFileRevealContext`](crate::crypto::disclosure::FullFileRevealContext),
//! applied to disclosure.
//!
//! `s_root` follows for free: the tree root's real span is all of `[0, n)`,
//! so the root is emitted **iff** the revealed range is `[0, n)` — which is
//! exactly the spec's "the fine-seed `s_root` itself is conveyed only on a
//! full-file reveal". No separate rule, no separate check.
//!
//! # Cost
//!
//! `minimal_cover` visits `O(d)` nodes with an explicit stack of at most
//! `d + 1` entries — no recursion, so no stack-depth class exists even for a
//! hostile `n`. [`cover_seeds`] costs `level` SHA-256 compressions per node,
//! `O(d^2)` in the worst case and `< 2d` in practice, with no heap traffic
//! beyond the output.

use zeroize::Zeroize as _;

use crate::content::ggm::{NodeAddress, child_seed, depth_for_leaf_count};
use crate::content::unit::ByteRange;
use crate::crypto::material::{Salt16, Seed32};

use super::error::FineTreeError;

/// One node of a leaf-exact cover: its grid address plus the **real** leaves
/// it covers (slots `>= n` excluded).
///
/// Constructible only by [`minimal_cover`] — the leaf-exactness guarantee
/// lives in this type, so a value of it always satisfies
/// `[first_leaf, first_leaf + leaf_len) ⊆ revealed range` and
/// `first_leaf + leaf_len <= n`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CoverNode {
    first_leaf: u64,
    leaf_len: u64,
    address: NodeAddress,
}

impl CoverNode {
    /// The node's `(level, index)` address on the depth-`d` dyadic grid
    /// (decision D9).
    #[must_use]
    pub const fn address(self) -> NodeAddress {
        self.address
    }

    /// First **real** leaf this node covers.
    #[must_use]
    pub const fn first_leaf(self) -> u64 {
        self.first_leaf
    }

    /// Number of **real** leaves this node covers — its slot span truncated
    /// at `n`, hence never zero.
    #[must_use]
    pub const fn leaf_len(self) -> u64 {
        self.leaf_len
    }
}

/// The minimal leaf-exact GGM sub-cover of one revealed leaf range.
///
/// Ordered by ascending first leaf; the nodes' real spans **partition** the
/// revealed range exactly (asserted by this module's property tests), which
/// is what lets a verifier walk cover and revealed bytes in lockstep.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeafExactCover {
    range: ByteRange,
    leaf_count: u64,
    depth: u8,
    nodes: Vec<CoverNode>,
}

impl LeafExactCover {
    /// The revealed leaf range `[start, start + length)`.
    #[must_use]
    pub const fn range(&self) -> ByteRange {
        self.range
    }

    /// The file's leaf count `n`.
    #[must_use]
    pub const fn leaf_count(&self) -> u64 {
        self.leaf_count
    }

    /// The GGM tree depth `d = ceil(log2 n)`.
    #[must_use]
    pub const fn depth(&self) -> u8 {
        self.depth
    }

    /// The cover's nodes, ascending by first leaf.
    #[must_use]
    pub fn nodes(&self) -> &[CoverNode] {
        &self.nodes
    }

    /// Whether this cover conveys `s_root` itself.
    ///
    /// True **iff** the revealed range is the whole file — a consequence of
    /// the construction, not a separate check (module docs; MVP-SPEC.md
    /// lines 96, 114). Exposed so R's partial-reveal-isolation stage can
    /// state the rule it enforces in the same words the spec uses.
    #[must_use]
    pub fn releases_s_root(&self) -> bool {
        matches!(self.nodes.as_slice(), [only] if only.address == NodeAddress::root())
    }
}

/// The minimal leaf-exact GGM sub-cover of `range` in a file of `leaf_count`
/// leaves (MVP-SPEC.md line 96).
///
/// The tree depth is **derived** from `leaf_count` rather than accepted as a
/// parameter: `d = ceil(log2 n)` is a function of `n`
/// ([`depth_for_leaf_count`]), and taking both would make the inconsistent
/// pair `(n, d)` representable at every call site.
///
/// # Errors
///
/// [`FineTreeError::RangeOutOfBounds`] when the range is empty, overflows, or
/// is not contained in `[0, leaf_count)` — including every range against an
/// empty file, which has no fine tree at all (MVP-SPEC.md line 78).
///
/// ```
/// use antseal_core::content::{ByteRange, minimal_cover};
///
/// // n = 6, reveal {2}: the deepest single-leaf node for slot 2.
/// let cover = minimal_cover(ByteRange::new(2, 1), 6).expect("in bounds");
/// assert_eq!(cover.nodes().len(), 1);
/// assert_eq!(cover.nodes()[0].address().level(), 3);
/// assert_eq!(cover.nodes()[0].address().index(), 2);
/// assert!(!cover.releases_s_root());
///
/// // n = 6, reveal [4, 6): one node spanning slots [4, 8) — real leaves
/// // 4 and 5 plus the unused slots 6 and 7.
/// let edge = minimal_cover(ByteRange::new(4, 2), 6).expect("in bounds");
/// assert_eq!(edge.nodes().len(), 1);
/// assert_eq!(edge.nodes()[0].address().level(), 1);
/// assert_eq!(edge.nodes()[0].leaf_len(), 2);
///
/// // The full range is exactly the root, i.e. s_root itself.
/// let full = minimal_cover(ByteRange::new(0, 6), 6).expect("in bounds");
/// assert!(full.releases_s_root());
/// ```
pub fn minimal_cover(range: ByteRange, leaf_count: u64) -> Result<LeafExactCover, FineTreeError> {
    let out_of_bounds = || FineTreeError::RangeOutOfBounds {
        start: range.start(),
        length: range.length(),
        leaf_count,
    };

    let depth = depth_for_leaf_count(leaf_count).ok_or_else(out_of_bounds)?;
    if range.is_empty() {
        return Err(out_of_bounds());
    }
    let end = range.end().ok_or_else(out_of_bounds)?;
    if end > leaf_count {
        return Err(out_of_bounds());
    }
    let (start, end) = (u128::from(range.start()), u128::from(end));
    let real_leaves = u128::from(leaf_count);

    // Pre-order DFS with an explicit stack: at most `d + 1` pending nodes, no
    // recursion, so no stack-depth failure class exists for any `n`. Pushing
    // the right child first makes the left subtree pop first, so nodes are
    // emitted in ascending-first-leaf order.
    let mut nodes: Vec<CoverNode> = Vec::new();
    let mut pending: Vec<NodeAddress> = Vec::with_capacity(usize::from(depth) + 1);
    pending.push(NodeAddress::root());

    while let Some(address) = pending.pop() {
        // Both are infallible for an address this loop produced (it descends
        // from the root and never past `depth`); mapping rather than
        // unwrapping keeps the function total.
        let first_slot = u128::from(address.first_slot(depth).map_err(|_| out_of_bounds())?);
        let slot_width = address.slot_width(depth).map_err(|_| out_of_bounds())?;

        // Slots at or past `n` are unused: they commit no byte, so a node
        // over only unused slots is dropped rather than emitted.
        if first_slot >= real_leaves {
            continue;
        }
        let real_end = (first_slot + slot_width).min(real_leaves);

        // Disjoint from the revealed range: nothing to cover here.
        if real_end <= start || first_slot >= end {
            continue;
        }

        // Leaf-exact: emit only when every REAL leaf under this node is
        // revealed. Unused slots beyond `real_end` are irrelevant — that is
        // what keeps the 2·ceil(log2 n) bound at a ragged right edge.
        if first_slot >= start && real_end <= end {
            nodes.push(CoverNode {
                first_leaf: u64::try_from(first_slot).unwrap_or(u64::MAX),
                leaf_len: u64::try_from(real_end - first_slot).unwrap_or(u64::MAX),
                address,
            });
            continue;
        }

        // Otherwise the node straddles the boundary and must be split. It
        // cannot be a leaf: a leaf's real span is a single slot, which is
        // either inside the range (emitted above) or disjoint (skipped
        // above). The guard is defensive only.
        if address.level() >= depth {
            continue;
        }
        for bit in [
            crate::content::ggm::ChildBit::Right,
            crate::content::ggm::ChildBit::Left,
        ] {
            pending.push(address.child(bit).map_err(|_| out_of_bounds())?);
        }
    }

    Ok(LeafExactCover {
        range,
        leaf_count,
        depth,
        nodes,
    })
}

/// One disclosable cover entry: a node, the GGM seed derived for it, and the
/// bytes a bundle actually ships for it.
///
/// Constructible only by [`cover_seeds`], so a `CoverEntry` always carries a
/// seed the leaf-exactness rule permits leaving the vault.
///
/// # Why two values and not one (D83)
///
/// The two coincide everywhere except at the grid's leaf level. A node at
/// `level == d` covers exactly one leaf slot, so a verifier reads
/// `salt_i = payload[..16]` with no descent and bytes `16..32` are never
/// hashed; v1 fixes them at zero, so [`Self::payload`] is `salt_i ‖ 0x00·16`
/// there while [`Self::seed`] stays the true derived seed. Keeping both is
/// deliberate: `seed()` must go on meaning *the GGM seed*, or
/// `cover_seeds_agree_with_the_salt_tree` would become a statement about the
/// wire form instead of about the GGM tree and would stop proving what it
/// claims.
///
/// Both fields are [`Seed32`] rather than `[u8; 32]` so that the redacted
/// `Debug` and the zeroize-on-drop travel with them — a bare array inside a
/// `Debug`-deriving [`RangeProof`](super::RangeProof) would print salt bytes
/// in a panic message (project rule 6).
#[derive(Debug)]
pub struct CoverEntry {
    node: CoverNode,
    seed: Seed32,
    payload: Seed32,
}

impl CoverEntry {
    /// The covered node.
    #[must_use]
    pub const fn node(&self) -> CoverNode {
        self.node
    }

    /// The node's GGM seed, exactly as
    /// [`SaltTree::seed_at`](crate::content::SaltTree) derives it
    /// (MVP-SPEC.md lines 114, 121).
    ///
    /// This is the *tree* value. What a bundle discloses is
    /// [`Self::payload`], which differs at `level == d` (D83).
    #[must_use]
    pub const fn seed(&self) -> &Seed32 {
        &self.seed
    }

    /// The bytes a bundle discloses for this node — 32 either way: the seed
    /// itself for `level < d`, and the canonical leaf-level payload
    /// `salt_i ‖ 0x00·16` for `level == d` (D83;
    /// `docs/format/registry-v1.md` §2, §5).
    #[must_use]
    pub const fn payload(&self) -> &Seed32 {
        &self.payload
    }
}

/// Derive the disclosable seed of every node of a leaf-exact cover
/// (MVP-SPEC.md line 114).
///
/// **The only seed-disclosure path in the crate.** It accepts a
/// [`LeafExactCover`] and nothing else, which is what makes "no seed that is
/// an ancestor of any unrevealed leaf ever leaves the vault" (line 96) a
/// property of the type system rather than of a runtime check.
///
/// Infallible: every node of a `LeafExactCover` sits at `level <= d` and
/// covers at least one real leaf, so the descent
/// (`s_{v‖b} = SHA-256(0x06 ‖ s_v ‖ b)` along the address's MSB-first path
/// bits) is always defined. `cover_seeds_agree_with_the_salt_tree` asserts
/// the descent equals G8's [`SaltTree::seed_at`](crate::content::SaltTree)
/// for every emitted node.
///
/// Each entry carries **both** the derived seed and the bytes a bundle
/// discloses for it; they differ only at `level == d`, where D83 fixes the
/// disclosed form at `salt_i ‖ 0x00·16` (see [`CoverEntry`]). The tail of a
/// leaf-level node's true seed therefore never leaves this function.
#[must_use]
pub fn cover_seeds(s_root: &Seed32, cover: &LeafExactCover) -> Vec<CoverEntry> {
    let depth = cover.depth();
    cover
        .nodes()
        .iter()
        .map(|node| {
            let seed = descend(s_root, node.address);
            let payload = disclosed_payload(&seed, node.address, depth);
            CoverEntry {
                node: *node,
                seed,
                payload,
            }
        })
        .collect()
}

/// The bytes a bundle discloses for one cover node (D83).
///
/// The seed itself below the leaf level; `salt_i ‖ 0x00·16` at `level == d`,
/// where the verifier reads `salt_i = payload[..16]` with no descent and the
/// tail is never hashed (MVP-SPEC.md line 96). The scratch buffer wipes
/// before returning, so the discarded tail exists in exactly one place.
fn disclosed_payload(seed: &Seed32, address: NodeAddress, depth: u8) -> Seed32 {
    if address.level() != depth {
        return Seed32::from_bytes(*seed.as_bytes());
    }
    let mut bytes = [0u8; Seed32::LEN];
    bytes[..Salt16::LEN].copy_from_slice(&seed.as_bytes()[..Salt16::LEN]);
    let payload = Seed32::from_bytes(bytes);
    bytes.zeroize();
    payload
}

/// Walk `s_root` down to `address` along the MSB-first bits of its index
/// (MVP-SPEC.md line 96). O(1) auxiliary state; each intermediate seed wipes
/// when the next replaces it.
pub(crate) fn descend(s_root: &Seed32, address: NodeAddress) -> Seed32 {
    let mut seed = Seed32::from_bytes(*s_root.as_bytes());
    for bit in address.path_bits() {
        seed = child_seed(&seed, bit);
    }
    seed
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::content::ggm::SaltTree;
    use crate::test_util::TEST_MASTER_SECRET_W;
    #[cfg(feature = "test-util")]
    use crate::test_util::strategies::proptest_config;
    #[cfg(feature = "test-util")]
    use proptest::prelude::*;
    use std::collections::BTreeSet;

    fn root_seed() -> Seed32 {
        Seed32::from_bytes(TEST_MASTER_SECRET_W)
    }

    fn addresses(cover: &LeafExactCover) -> Vec<(u8, u64)> {
        cover
            .nodes()
            .iter()
            .map(|n| (n.address().level(), n.address().index()))
            .collect()
    }

    /// Every salt a holder of `cover`'s seeds can derive, restricted to the
    /// **real** leaves `0..n` — the puncturing-soundness closure.
    fn derivable_real_leaves(cover: &LeafExactCover) -> BTreeSet<u64> {
        let mut reachable = BTreeSet::new();
        for node in cover.nodes() {
            let first = node
                .address()
                .first_slot(cover.depth())
                .expect("cover nodes are on the grid");
            let width = node
                .address()
                .slot_width(cover.depth())
                .expect("cover nodes are on the grid");
            // The holder can derive every leaf under the node, unused slots
            // included; only the real ones are salts of actual bytes.
            let last = (u128::from(first) + width).min(u128::from(cover.leaf_count()));
            for leaf in first..u64::try_from(last).unwrap_or(u64::MAX) {
                reachable.insert(leaf);
            }
        }
        reachable
    }

    // ── The two spec-named cases (G11 accept) ───────────────────────────

    /// G11 accept: `n = 6`, reveal `{2}` → exactly the deepest single-leaf
    /// node for slot 2, and `s_root` absent.
    #[test]
    fn n6_reveal_leaf_2_is_a_single_deepest_node() {
        let cover = minimal_cover(ByteRange::new(2, 1), 6).expect("in bounds");
        assert_eq!(cover.depth(), 3);
        assert_eq!(addresses(&cover), vec![(3, 2)]);
        assert_eq!(cover.nodes()[0].first_leaf(), 2);
        assert_eq!(cover.nodes()[0].leaf_len(), 1);
        assert!(!cover.releases_s_root());
        assert_eq!(derivable_real_leaves(&cover), BTreeSet::from([2]));
    }

    /// G11 accept, the unused-slot allowance as a **positive** case:
    /// `n = 6`, reveal `[4, 6)` → the node over slots `[4, 8)`, whose real
    /// leaves are exactly 4 and 5.
    #[test]
    fn n6_reveal_ragged_right_edge_uses_the_unused_slot_allowance() {
        let cover = minimal_cover(ByteRange::new(4, 2), 6).expect("in bounds");
        assert_eq!(addresses(&cover), vec![(1, 1)], "the node spanning [4, 8)");
        assert_eq!(cover.nodes()[0].first_leaf(), 4);
        assert_eq!(
            cover.nodes()[0].leaf_len(),
            2,
            "slots 6 and 7 are not leaves"
        );
        assert!(!cover.releases_s_root());
        assert_eq!(derivable_real_leaves(&cover), BTreeSet::from([4, 5]));

        // The naive "slot span must fit the range" rule would have emitted
        // two deeper nodes instead — this is the regression guard for the
        // allowance actually being taken.
        assert_ne!(addresses(&cover), vec![(2, 2), (3, 5)]);
    }

    /// G11 accept: the full range is exactly `[root]`, i.e. `s_root`.
    #[test]
    fn full_range_is_exactly_the_root() {
        for n in [1u64, 2, 3, 5, 6, 8, 9, 100] {
            let cover = minimal_cover(ByteRange::new(0, n), n).expect("in bounds");
            assert_eq!(addresses(&cover), vec![(0, 0)], "n = {n}");
            assert!(cover.releases_s_root(), "n = {n}");
            assert_eq!(cover.nodes()[0].leaf_len(), n, "n = {n}");
        }
    }

    /// The `n = 1` corner: the root *is* the only leaf, so the sole cover is
    /// the root and it is a full reveal.
    #[test]
    fn single_leaf_file_covers_with_the_root() {
        let cover = minimal_cover(ByteRange::new(0, 1), 1).expect("in bounds");
        assert_eq!(cover.depth(), 0);
        assert_eq!(addresses(&cover), vec![(0, 0)]);
        assert!(cover.releases_s_root());
    }

    /// Hand-checked decomposition at `n = 8`, reveal `[1, 7)` — both
    /// boundaries decompose to deepest single-leaf nodes, the interior to
    /// maximal subtrees, in ascending order.
    #[test]
    fn interior_range_decomposes_to_maximal_subtrees() {
        let cover = minimal_cover(ByteRange::new(1, 6), 8).expect("in bounds");
        assert_eq!(addresses(&cover), vec![(3, 1), (2, 1), (2, 2), (3, 6)]);
        assert_eq!(
            derivable_real_leaves(&cover),
            BTreeSet::from([1, 2, 3, 4, 5, 6])
        );
    }

    // ── Rejections ──────────────────────────────────────────────────────

    /// Empty, overflowing and out-of-range requests are all the same
    /// distinct class — there is nothing to cover in any of them.
    #[test]
    fn degenerate_ranges_are_rejected() {
        for (range, n) in [
            (ByteRange::new(0, 0), 6),
            (ByteRange::new(3, 0), 6),
            (ByteRange::new(0, 7), 6),
            (ByteRange::new(6, 1), 6),
            (ByteRange::new(u64::MAX, 2), 6),
            (ByteRange::new(0, 1), 0),
            (ByteRange::new(0, 0), 0),
        ] {
            assert_eq!(
                minimal_cover(range, n).err(),
                Some(FineTreeError::RangeOutOfBounds {
                    start: range.start(),
                    length: range.length(),
                    leaf_count: n,
                }),
                "{range:?} against n = {n}"
            );
        }
    }

    // ── Seeds (G11 accept) ──────────────────────────────────────────────

    /// [`cover_seeds`] is the same derivation as G8's per-node
    /// [`SaltTree::seed_at`] — the descent here is the definition restated,
    /// not a second implementation.
    #[test]
    fn cover_seeds_agree_with_the_salt_tree() {
        let s_root = root_seed();
        for n in [1u64, 2, 5, 6, 7, 8, 9, 16, 33] {
            let tree = SaltTree::new(&s_root, n).expect("n >= 1");
            for start in 0..n {
                for length in 1..=(n - start) {
                    let cover = minimal_cover(ByteRange::new(start, length), n).expect("in bounds");
                    for entry in cover_seeds(&s_root, &cover) {
                        let expected = tree
                            .seed_at(entry.node().address())
                            .expect("cover nodes cover real leaves");
                        assert_eq!(
                            entry.seed().as_bytes(),
                            expected.as_bytes(),
                            "n = {n}, [{start}, {start}+{length})"
                        );
                    }
                }
            }
        }
    }

    /// The full-range cover's single seed **is** `s_root`, byte for byte —
    /// the spec's "the full `[0, n)` cover" (line 114).
    #[test]
    fn full_range_cover_seed_is_s_root_itself() {
        let s_root = root_seed();
        let cover = minimal_cover(ByteRange::new(0, 6), 6).expect("in bounds");
        let entries = cover_seeds(&s_root, &cover);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].seed().as_bytes(), s_root.as_bytes());
    }

    /// Project rule 6: a `CoverEntry`'s `Debug` never shows its seed — nor,
    /// since D83 added it, its payload. Checked on a leaf-level cover as well
    /// as an interior one, because that is where the two values differ and a
    /// `[u8; 32]` payload field would have printed the salt.
    #[test]
    fn cover_entry_debug_redacts_the_seed() {
        let s_root = root_seed();
        for range in [ByteRange::new(0, 6), ByteRange::new(2, 1)] {
            let cover = minimal_cover(range, 6).expect("in bounds");
            let rendered = format!("{:?}", cover_seeds(&s_root, &cover));
            assert_eq!(
                rendered.matches("<redacted>").count(),
                2 * cover.nodes().len(),
                "seed AND payload must both be redacted: {rendered}"
            );
            assert!(!rendered.contains("1f"), "{rendered}");
            for entry in cover_seeds(&s_root, &cover) {
                let salt = hex_of(&entry.payload().as_bytes()[..Salt16::LEN]);
                assert!(!rendered.contains(&salt), "{rendered}");
            }
        }
    }

    /// D83's prover half: a cover node's disclosed payload is the seed at
    /// `level < d` and `salt_i ‖ 0x00·16` at `level == d`, over every range
    /// of every small `n` — and the salt it carries is always the one G8's
    /// [`SaltTree`] derives, so the canonical form loses no information a
    /// verifier needs.
    #[test]
    fn disclosed_payloads_are_canonical_at_the_leaf_level() {
        let s_root = root_seed();
        let mut leaf_level_seen = 0usize;
        for n in [1u64, 2, 5, 6, 7, 8, 9, 16, 33] {
            let tree = SaltTree::new(&s_root, n).expect("n >= 1");
            for start in 0..n {
                for length in 1..=(n - start) {
                    let cover = minimal_cover(ByteRange::new(start, length), n).expect("in bounds");
                    let depth = cover.depth();
                    for entry in cover_seeds(&s_root, &cover) {
                        let address = entry.node().address();
                        let payload = entry.payload().as_bytes();
                        if address.level() == depth {
                            leaf_level_seen += 1;
                            let salt = tree
                                .salt(address.index())
                                .expect("a cover node covers a real leaf");
                            assert_eq!(&payload[..Salt16::LEN], salt.as_bytes());
                            assert_eq!(&payload[Salt16::LEN..], &[0u8; 16]);
                        } else {
                            assert_eq!(payload, entry.seed().as_bytes());
                        }
                        // `seed()` never changes meaning: it is the GGM value.
                        assert_eq!(
                            entry.seed().as_bytes(),
                            tree.seed_at(address).expect("on the grid").as_bytes()
                        );
                    }
                }
            }
        }
        assert!(
            leaf_level_seen > 0,
            "the sweep must actually reach the leaf level"
        );
    }

    fn hex_of(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    // ── Property tests (G11 accept) ─────────────────────────────────────

    #[cfg(feature = "test-util")]

    proptest! {
        #![proptest_config(proptest_config(0x0064_0011))]

        /// G11 accept, all four properties over arbitrary `(n, range)`:
        ///
        /// 1. **bound** — `|cover| <= max(1, 2·ceil(log2 n))` (the `max`
        ///    covers `n = 1`, where `d = 0` and the sole node is the root);
        /// 2. **completeness** — every in-range salt is derivable;
        /// 3. **soundness** — the derivable closure contains **no** `salt_j`
        ///    for an unrevealed real leaf `j < n`;
        /// 4. **`s_root` iff full range**.
        #[test]
        fn cover_is_bounded_complete_sound_and_root_iff_full(
            n in 1u64..=200,
            start in 0u64..200,
            length in 1u64..200,
        ) {
            let start = start % n;
            let length = length.min(n - start);
            let range = ByteRange::new(start, length);
            let cover = minimal_cover(range, n).expect("constructed in bounds");
            let depth = u64::from(cover.depth());

            // 1. bound
            let bound = usize::try_from((2 * depth).max(1)).unwrap_or(usize::MAX);
            prop_assert!(
                cover.nodes().len() <= bound,
                "|cover| {} > {bound} at n = {n}",
                cover.nodes().len()
            );

            // 2 + 3. the derivable real-leaf closure is EXACTLY the range
            let closure = derivable_real_leaves(&cover);
            let expected: BTreeSet<u64> = (start..start + length).collect();
            prop_assert_eq!(&closure, &expected);

            // 4. s_root iff full range
            prop_assert_eq!(cover.releases_s_root(), start == 0 && length == n);
        }

        /// The nodes' real spans **partition** the range in ascending order —
        /// no gap, no overlap, no duplicate address. This is what lets a
        /// verifier walk cover entries and revealed bytes in lockstep.
        #[test]
        fn real_spans_partition_the_range_in_order(
            n in 1u64..=200,
            start in 0u64..200,
            length in 1u64..200,
        ) {
            let start = start % n;
            let length = length.min(n - start);
            let cover = minimal_cover(ByteRange::new(start, length), n)
                .expect("constructed in bounds");

            let mut cursor = start;
            let mut seen = BTreeSet::new();
            for node in cover.nodes() {
                prop_assert_eq!(node.first_leaf(), cursor, "gap or overlap");
                prop_assert!(node.leaf_len() > 0);
                prop_assert!(seen.insert(node.address()), "duplicate address");
                cursor += node.leaf_len();
            }
            prop_assert_eq!(cursor, start + length, "cover stops short of the range");
        }

        /// Determinism: the same request always yields the same cover, and
        /// the same seeds.
        #[test]
        fn cover_derivation_is_deterministic(
            n in 1u64..=64,
            start in 0u64..64,
            length in 1u64..64,
            root_bytes in any::<[u8; 32]>(),
        ) {
            let start = start % n;
            let length = length.min(n - start);
            let range = ByteRange::new(start, length);
            let a = minimal_cover(range, n).expect("in bounds");
            let b = minimal_cover(range, n).expect("in bounds");
            prop_assert_eq!(&a, &b);

            let seed = Seed32::from_bytes(root_bytes);
            let seeds_a: Vec<[u8; 32]> = cover_seeds(&seed, &a)
                .iter()
                .map(|e| *e.seed().as_bytes())
                .collect();
            let seeds_b: Vec<[u8; 32]> = cover_seeds(&seed, &b)
                .iter()
                .map(|e| *e.seed().as_bytes())
                .collect();
            prop_assert_eq!(seeds_a, seeds_b);
        }
    }
}
