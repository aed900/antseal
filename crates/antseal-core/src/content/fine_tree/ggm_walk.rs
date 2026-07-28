//! Sequential GGM leaf-seed walker (tasks/G.md G9) — the amortized-O(1),
//! O(log n)-memory primitive every fine-tree traversal shares.
//!
//! # What it does
//!
//! [`super::super::SaltTree::salt`] derives one leaf salt in `d` SHA-256
//! compressions with O(1) state. Deriving *every* leaf that way costs `n·d`
//! compressions — `O(n log n)`, and at `d = 27` (a 128 MiB file) that is
//! ~27 compressions per byte against the spec's ~5–7 budget (MVP-SPEC.md
//! line 85).
//!
//! A depth-first co-traversal fixes it. The walker keeps the seeds of the
//! current leaf's ancestors in a stack of `d + 1` entries; advancing from
//! leaf `i − 1` to leaf `i` re-derives only the levels the two paths do not
//! share:
//!
//! ```text
//! differing low bits  h = bit_width((i−1) XOR i)      (h >= 1)
//! shared prefix       common = d − h                  levels 0 ..= common survive
//! work                h child derivations
//! ```
//!
//! Summed over a full sweep this is the classic binary-counter total: `≈ 2n`
//! derivations for `n` leaves (exactly `sum_{l=0..d} ceil(n / 2^(d−l)) − 1`
//! for a prefix sweep `0..n`), i.e. **amortized ~2 SHA-256 compressions per
//! leaf** with a stack of at most `d + 1 <= 65` seeds. That is the "O(d) seed
//! stack, amortized O(1) hashes" the task entry specifies, and the reason
//! the whole construction lands at ~5 compressions per byte.
//!
//! # Sub-tree rooting
//!
//! The walker is rooted at an arbitrary seed with an arbitrary *local* depth,
//! not necessarily at `s_root`/`d`. That is what lets G13 derive the salts of
//! a revealed range from the range's GGM sub-cover using the identical code:
//! a cover node at `(level, index)` is a walker rooted at that node's seed
//! with local depth `d − level`, and its local leaves `0..2^(d−level)` are
//! the file's leaves `index·2^(d−level) ..`.
//!
//! # Secret-material discipline (project rule 6)
//!
//! The stack holds live GGM seeds. [`Seed32`] redacts its `Debug` and wipes
//! on drop, `truncate` therefore wipes the abandoned suffix, and no accessor
//! here yields anything but the current leaf's 16-byte salt.

use crate::content::ggm::{ChildBit, child_seed};
use crate::crypto::material::{Salt16, Seed32};

/// A depth-first cursor over the leaf seeds of one GGM (sub)tree.
///
/// Constructed at a root seed and a local depth; [`Self::next_salt`] yields
/// local leaves `0, 1, 2, …` in order, each in amortized O(1) SHA-256
/// compressions. Seeking backwards or randomly is deliberately impossible —
/// the sequential contract is what makes the amortization sound.
#[derive(Debug)]
pub(crate) struct GgmWalker {
    /// `stack[l]` is the seed of the level-`l` ancestor of the leaf the
    /// cursor currently sits on. Always non-empty (`stack[0]` is the root);
    /// length is `depth + 1` once primed.
    stack: Vec<Seed32>,
    /// Local depth: derivation steps from this walker's root to its leaves.
    depth: u8,
    /// Local index of the leaf the stack currently describes; `None` before
    /// the first [`Self::next_salt`].
    cursor: Option<u64>,
    /// Instrumentation: child derivations performed (one SHA-256 compression
    /// each — the preimage `0x06 ‖ seed ‖ b` is 34 B, a single block).
    derivations: u64,
    /// Instrumentation: the high-water mark of `stack.len()`.
    peak_stack_len: u32,
}

impl GgmWalker {
    /// A walker over the `2^depth` leaves below `root`.
    ///
    /// `depth` is the *local* depth; the caller supplies `d` for a whole-file
    /// walk and `d − level` for a walk under a cover node. Values above
    /// [`NodeAddress::MAX_LEVEL`](crate::content::NodeAddress::MAX_LEVEL) are
    /// unreachable — `d = ceil(log2 n) <= 64` for any `u64` leaf count.
    pub(crate) fn new(root: &Seed32, depth: u8) -> Self {
        let mut stack = Vec::with_capacity(usize::from(depth) + 1);
        stack.push(Seed32::from_bytes(*root.as_bytes()));
        Self {
            stack,
            depth,
            cursor: None,
            derivations: 0,
            peak_stack_len: 1,
        }
    }

    /// Advance to the next local leaf and return its 16-byte salt
    /// (`salt_i` = the leaf seed truncated to 16 B; MVP-SPEC.md line 96).
    ///
    /// At `depth = 0` the root *is* the only leaf, so the first call returns
    /// `root[..16]` with no derivation at all — the spec's `n = 1` case.
    ///
    /// Callers never advance past the tree's real leaves: the fine-tree
    /// builder stops at `n`, and G13's salt source stops at each cover node's
    /// real span. The cursor arithmetic is nonetheless total (wrapping is
    /// impossible below `2^depth <= 2^64`), so a mis-driving caller gets
    /// wrong salts, never a panic.
    pub(crate) fn next_salt(&mut self) -> Salt16 {
        let next = match self.cursor {
            None => 0,
            Some(current) => current.wrapping_add(1),
        };
        self.reseat(next);
        self.cursor = Some(next);

        // `reseat` guarantees `stack.len() == depth + 1`, so the leaf seed is
        // the last entry; the `unwrap_or` arm is unreachable (the stack is
        // never empty) and exists only to keep this path panic-free.
        let leaf_seed = self.stack.last().map_or([0u8; Seed32::LEN], |seed| {
            let mut bytes = [0u8; Seed32::LEN];
            bytes.copy_from_slice(seed.as_bytes());
            bytes
        });
        let mut salt = [0u8; Salt16::LEN];
        salt.copy_from_slice(&leaf_seed[..Salt16::LEN]);
        Salt16::from_bytes(salt)
    }

    /// Re-derive exactly the levels the paths to `self.cursor` and `next` do
    /// not share, leaving `stack` describing `next`.
    fn reseat(&mut self, next: u64) {
        let common = match self.cursor {
            // Initial descent: nothing is shared below the root.
            None => 0,
            Some(current) => {
                // The low bits in which the two indices differ; `bit_width`
                // of the XOR. Always >= 1 for `current != next`, and at most
                // `depth`, since `next < 2^depth` (trailing-zero argument).
                let differing = u8::try_from(u64::BITS - (current ^ next).leading_zeros())
                    .unwrap_or(u8::MAX)
                    .min(self.depth);
                self.depth - differing
            }
        };

        // Wipes every abandoned seed (Seed32 zeroizes on drop).
        self.stack.truncate(usize::from(common) + 1);

        for level in (common + 1)..=self.depth {
            // Path bit for `level` is bit `depth − level` of the index,
            // MSB-first (MVP-SPEC.md line 96). `depth − level <= 63`, so the
            // shift is always in range.
            let bit = ChildBit::from_bit((next >> (self.depth - level)) & 1 == 1);
            let child = match self.stack.last() {
                Some(parent) => child_seed(parent, bit),
                // Unreachable: the stack always holds at least the root.
                None => Seed32::from_bytes([0u8; Seed32::LEN]),
            };
            self.stack.push(child);
            self.derivations += 1;
        }

        self.peak_stack_len = self
            .peak_stack_len
            .max(u32::try_from(self.stack.len()).unwrap_or(u32::MAX));
    }

    /// Child derivations performed so far — one SHA-256 compression each
    /// (instrumentation for G10/G18).
    pub(crate) const fn derivations(&self) -> u64 {
        self.derivations
    }

    /// High-water mark of the seed stack — the structural half of G9's
    /// `O(log n)` memory claim (`<= depth + 1`).
    pub(crate) const fn peak_stack_len(&self) -> u32 {
        self.peak_stack_len
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::content::ggm::{SaltTree, depth_for_leaf_count};
    use crate::test_util::TEST_MASTER_SECRET_W;
    use crate::test_util::strategies::proptest_config;
    use proptest::prelude::*;

    fn root() -> Seed32 {
        Seed32::from_bytes(TEST_MASTER_SECRET_W)
    }

    /// The walker agrees with G8's independent per-leaf derivation for every
    /// leaf of every small tree — the equivalence that lets the fine tree
    /// use the fast path without a second salt definition.
    #[test]
    fn walker_matches_salt_tree_leaf_by_leaf() {
        let seed = root();
        for n in 1u64..=40 {
            let depth = depth_for_leaf_count(n).expect("n >= 1");
            let tree = SaltTree::new(&seed, n).expect("n >= 1");
            let mut walker = GgmWalker::new(&seed, depth);
            for i in 0..n {
                let expected = tree.salt(i).expect("in range");
                let got = walker.next_salt();
                assert_eq!(got.as_bytes(), expected.as_bytes(), "n = {n}, leaf = {i}");
            }
        }
    }

    /// `depth = 0` (`n = 1`): the root is the leaf, `salt_0 = s_root[..16]`,
    /// and not a single derivation happens (MVP-SPEC.md line 96).
    #[test]
    fn depth_zero_costs_nothing() {
        let seed = root();
        let mut walker = GgmWalker::new(&seed, 0);
        let salt = walker.next_salt();
        assert_eq!(salt.as_bytes(), &seed.as_bytes()[..16]);
        assert_eq!(walker.derivations(), 0);
        assert_eq!(walker.peak_stack_len(), 1);
    }

    /// The amortization is real: a full sweep of `n` leaves costs exactly
    /// `sum_{l=0..=d} ceil(n / 2^(d−l)) − 1` derivations — the number of
    /// edges in the union of the root-to-leaf paths — which is `< 2n + d`.
    /// A naive per-leaf implementation would cost `n·d`.
    #[test]
    fn sweep_cost_is_the_path_union_and_amortizes_to_two_per_leaf() {
        let seed = root();
        for n in [1u64, 2, 3, 5, 6, 8, 9, 16, 17, 100, 257] {
            let depth = depth_for_leaf_count(n).expect("n >= 1");
            let mut walker = GgmWalker::new(&seed, depth);
            for _ in 0..n {
                let _ = walker.next_salt();
            }

            let expected_nodes: u64 = (0..=depth)
                .map(|level| n.div_ceil(1u64 << (depth - level)))
                .sum();
            assert_eq!(
                walker.derivations(),
                expected_nodes - 1,
                "n = {n}: sweep must derive exactly the path-union edges"
            );
            assert!(
                walker.derivations() < 2 * n + u64::from(depth),
                "n = {n}: amortized cost must stay near 2 per leaf"
            );
            assert_eq!(
                walker.peak_stack_len(),
                u32::from(depth) + 1,
                "n = {n}: the stack is exactly d + 1 deep, never n-proportional"
            );
        }
    }

    proptest! {
        #![proptest_config(proptest_config(0x0064_0009))]

        /// Sequential walking equals independent per-leaf derivation for
        /// arbitrary trees and roots (the core equivalence, generalized).
        #[test]
        fn walker_equals_independent_derivation(
            n in 1u64..=200,
            root_bytes in any::<[u8; 32]>(),
        ) {
            let seed = Seed32::from_bytes(root_bytes);
            let depth = depth_for_leaf_count(n).expect("n >= 1");
            let tree = SaltTree::new(&seed, n).expect("n >= 1");
            let mut walker = GgmWalker::new(&seed, depth);
            for i in 0..n {
                let expected = tree.salt(i).expect("in range");
                let got = walker.next_salt();
                prop_assert_eq!(got.as_bytes(), expected.as_bytes());
            }
            // O(log n) memory, structurally.
            prop_assert!(u64::from(walker.peak_stack_len()) <= u64::from(depth) + 1);
        }

        /// A walker rooted at an interior node reproduces the file-level
        /// salts of that node's slot span — the property G13's cover-driven
        /// salt source depends on.
        #[test]
        fn subtree_rooted_walker_matches_absolute_leaves(
            level in 0u8..=4,
            root_bytes in any::<[u8; 32]>(),
        ) {
            let n = 64u64;
            let depth = depth_for_leaf_count(n).expect("n >= 1");
            let level = level.min(depth);
            let seed = Seed32::from_bytes(root_bytes);
            let tree = SaltTree::new(&seed, n).expect("n >= 1");

            let width = 1u64 << (depth - level);
            for index in 0..(1u64 << level) {
                let address = crate::content::NodeAddress::try_new(level, index)
                    .expect("level <= depth, index < 2^level");
                let node_seed = tree.seed_at(address).expect("covers real leaves");
                let mut walker = GgmWalker::new(&node_seed, depth - level);
                for local in 0..width {
                    let absolute = index * width + local;
                    let expected = tree.salt(absolute).expect("in range");
                    let got = walker.next_salt();
                    prop_assert_eq!(got.as_bytes(), expected.as_bytes());
                }
            }
        }
    }
}
