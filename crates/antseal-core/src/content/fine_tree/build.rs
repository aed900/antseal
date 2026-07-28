//! Streaming fine-tree construction and the verifier-side rebuild primitive
//! (tasks/G.md G9; MVP-SPEC.md lines 78, 85, 96, 121).
//!
//! # The tree
//!
//! For a file whose byte-domain length is `n` (canonical bytes for text, raw
//! bytes for binary — G4's descriptor decides which), the fine tree commits
//! **one leaf per byte**:
//!
//! ```text
//! leaf_i = SHA-256(0x00 ‖ salt_i ‖ LE64(i) ‖ byte_i)          (line 96)
//! node   = SHA-256(0x01 ‖ left ‖ right)                        (lines 78, 96)
//! ```
//!
//! with `salt_i` the GGM salt of leaf `i` ([`SaltTree`], G8) and the interior
//! shape given by **RFC 6962-style unbalanced promotion** (line 78): the tree
//! over leaves `[s, e)` splits at the largest power of two `k < e − s`, so
//! the left child is always a perfect subtree and the right child carries the
//! remainder. `n = 0` has no tree at all; `n = 1` has root = leaf.
//!
//! Only `fine_root` enters the manifest, and for a fine-tree file it is the
//! **sole** content commitment (line 94) — which is why the construction has
//! to be exactly reproducible by a third-party verifier from the bundle
//! alone.
//!
//! # Why streaming, and what "O(log n) memory" means here
//!
//! Line 85 requires construction to "stream with O(log n) memory" — a seal of
//! a 4 GiB dataset must not need 4 GiB of leaf hashes. Two structures carry
//! the whole state:
//!
//! - the **GGM seed stack** ([`GgmWalker`]) — `d + 1 <= 65` seeds;
//! - the **Merkle frontier** — the roots of the completed perfect subtrees to
//!   the left of the cursor, whose widths are strictly decreasing powers of
//!   two, hence at most `d + 1 <= 65` entries.
//!
//! Both bounds are *structural*: [`FineTreeStats`] records their high-water
//! marks, so the property test asserts the shape of the memory rather than
//! sampling an allocator. G18 turns the same instrumentation into a budget at
//! CI scale (its constants are open decision D26 and are deliberately **not**
//! frozen here).
//!
//! # Cost
//!
//! The instrumentation counts SHA-256 *compressions*, not calls, because the
//! three preimages differ in block count:
//!
//! | preimage | bytes | + 9 B padding | blocks |
//! | --- | --- | --- | --- |
//! | leaf `0x00 ‖ salt(16) ‖ LE64(8) ‖ byte(1)` | 26 | 35 | 1 |
//! | node `0x01 ‖ left(32) ‖ right(32)` | 65 | 74 | 2 |
//! | GGM child `0x06 ‖ seed(32) ‖ b(1)` | 34 | 43 | 1 |
//!
//! With `n` leaves, `n − 1` interior nodes and `≈ 2n` GGM derivations that is
//! `1 + 2 + 2 ≈ **5 compressions per byte**`, the bottom of the spec's
//! "~5–7" figure (line 85) — measured by
//! [`FineTreeStats::sha256_compressions`], never estimated by eye.

use crate::content::ggm::depth_for_leaf_count;
use crate::crypto::domain::{TAG_FINE_TREE_LEAF, TAG_FINE_TREE_NODE, tagged_sha256};
use crate::crypto::material::{Salt16, Seed32};

use super::error::FineTreeError;
use super::ggm_walk::GgmWalker;

/// A file's `fine_root` — the root of its fine tree, and for a fine-tree
/// file its **sole** content commitment (MVP-SPEC.md lines 94, 96, 98).
///
/// A public manifest value: plain value semantics, hex `Debug`, no
/// redaction, no zeroization. Deliberately its own newtype rather than a
/// bare `[u8; 32]` or a reused node-hash type, so a boundary Merkle node
/// hash can never be passed where the root is expected.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct FineRoot([u8; 32]);

impl FineRoot {
    /// Length in bytes.
    pub const LEN: usize = 32;

    /// Construct from exactly-sized bytes (F's decoder, after its own
    /// length check).
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrow the raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl core::fmt::Debug for FineRoot {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("FineRoot(")?;
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        f.write_str(")")
    }
}

/// `leaf_i = SHA-256(0x00 ‖ salt_i ‖ LE64(i) ‖ byte_i)` (MVP-SPEC.md
/// line 96).
///
/// The single leaf-preimage site in the codebase: the index is **LE64**, the
/// salt precedes it, and the byte is last. Routed through
/// [`tagged_sha256`] so `0x00` is structurally the first preimage byte.
#[must_use]
pub(crate) fn leaf_hash(salt: &Salt16, index: u64, byte: u8) -> [u8; 32] {
    tagged_sha256(
        TAG_FINE_TREE_LEAF,
        &[salt.as_bytes(), &index.to_le_bytes(), &[byte]],
    )
}

/// `node = SHA-256(0x01 ‖ left ‖ right)` (MVP-SPEC.md lines 78, 79, 96).
///
/// The single interior-node preimage site in the codebase.
#[must_use]
pub(crate) fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    tagged_sha256(TAG_FINE_TREE_NODE, &[left, right])
}

/// Instrumented cost and memory shape of one fine-tree construction
/// (tasks/G.md G9; consumed by G10's estimator and G18's budgets).
///
/// Counters are always collected — three integer increments per byte are
/// noise next to five SHA-256 compressions, and G18 must be able to read
/// them from an ordinary release build. Nothing here is ever encoded,
/// hashed, or signed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FineTreeStats {
    /// Leaf preimages hashed — equal to the file's leaf count once the
    /// construction completes.
    pub leaf_hashes: u64,
    /// Interior-node preimages hashed — `n − 1` once complete.
    pub node_hashes: u64,
    /// GGM child derivations performed (`0x06 ‖ seed ‖ b`).
    pub ggm_derivations: u64,
    /// High-water mark of the Merkle frontier, in subtree roots.
    pub peak_frontier_len: u32,
    /// High-water mark of the GGM seed stack, in seeds.
    pub peak_seed_stack_len: u32,
}

impl FineTreeStats {
    /// SHA-256 blocks per leaf preimage (26 B + 9 B padding → 1).
    pub const LEAF_BLOCKS: u64 = 1;
    /// SHA-256 blocks per interior-node preimage (65 B + 9 B padding → 2).
    pub const NODE_BLOCKS: u64 = 2;
    /// SHA-256 blocks per GGM child preimage (34 B + 9 B padding → 1).
    pub const GGM_BLOCKS: u64 = 1;

    /// Total SHA-256 compression-function invocations
    /// (module docs, cost table). Saturating: a hostile leaf count can make
    /// the product large, never wrap.
    #[must_use]
    pub const fn sha256_compressions(&self) -> u64 {
        self.leaf_hashes
            .saturating_mul(Self::LEAF_BLOCKS)
            .saturating_add(self.node_hashes.saturating_mul(Self::NODE_BLOCKS))
            .saturating_add(self.ggm_derivations.saturating_mul(Self::GGM_BLOCKS))
    }

    /// Compressions per input byte in **thousandths** — `5_000` is the
    /// spec's lower "~5 per byte" figure (MVP-SPEC.md line 85).
    ///
    /// Integer milli-units rather than a float: `antseal-core` carries no
    /// floating point anywhere (the CBOR profile bans it outright), and a
    /// ratio that must be compared against thresholds in CI is better off
    /// exact. Zero when nothing has been hashed.
    #[must_use]
    pub const fn compressions_per_byte_milli(&self) -> u64 {
        if self.leaf_hashes == 0 {
            return 0;
        }
        self.sha256_compressions().saturating_mul(1_000) / self.leaf_hashes
    }
}

/// The Merkle frontier: roots of the completed perfect subtrees to the left
/// of the cursor, widest first.
///
/// Widths are strictly decreasing powers of two — a binary counter over the
/// leaves consumed so far — so the frontier holds at most `d + 1` entries and
/// a new leaf triggers exactly as many merges as the counter has trailing
/// ones. Widths are `u128` purely so the `2 · width` step is provably free of
/// overflow at the `n = u64::MAX` corner.
#[derive(Debug, Default)]
struct MerkleFrontier {
    stack: Vec<(u128, [u8; 32])>,
    node_hashes: u64,
    peak_len: u32,
}

impl MerkleFrontier {
    fn with_capacity(depth: u8) -> Self {
        Self {
            stack: Vec::with_capacity(usize::from(depth) + 1),
            node_hashes: 0,
            peak_len: 0,
        }
    }

    /// Absorb one leaf hash, merging equal-width neighbours.
    fn push_leaf(&mut self, hash: [u8; 32]) {
        self.stack.push((1, hash));
        self.peak_len = self
            .peak_len
            .max(u32::try_from(self.stack.len()).unwrap_or(u32::MAX));

        while self.stack.len() >= 2 {
            let (right_width, right) = match self.stack.last() {
                Some(entry) => *entry,
                None => break,
            };
            let (left_width, left) = match self.stack.get(self.stack.len() - 2) {
                Some(entry) => *entry,
                None => break,
            };
            if left_width != right_width {
                break;
            }
            self.stack.truncate(self.stack.len() - 2);
            self.stack
                .push((left_width + right_width, node_hash(&left, &right)));
            self.node_hashes += 1;
        }
    }

    /// Fold the remaining subtrees right-to-left — RFC 6962's unbalanced
    /// promotion, which always attaches the smaller (rightmost) remainder as
    /// the right child of the next wider subtree.
    ///
    /// `None` iff no leaf was ever absorbed (`n = 0`, no tree).
    fn finish(mut self) -> Option<([u8; 32], u64)> {
        let (_, mut accumulator) = self.stack.pop()?;
        while let Some((_, left)) = self.stack.pop() {
            accumulator = node_hash(&left, &accumulator);
            self.node_hashes += 1;
        }
        Some((accumulator, self.node_hashes))
    }
}

/// Single-pass, chunk-fed fine-tree construction with O(log n) auxiliary
/// memory (tasks/G.md G9; MVP-SPEC.md line 85).
///
/// The leaf count is fixed at construction because the GGM tree's depth
/// `d = ceil(log2 n)` — and therefore every `salt_i` — depends on it
/// (line 96). Feeding a different number of bytes than declared is an error,
/// not a silently different tree.
///
/// ```
/// use antseal_core::content::{FineTreeBuilder, rebuild_fine_root};
/// use antseal_core::crypto::material::Seed32;
///
/// let s_root = Seed32::from_bytes([7u8; 32]);
/// let content = b"hello fine tree";
///
/// // Streamed in arbitrary slices …
/// let mut builder = FineTreeBuilder::new(&s_root, content.len() as u64)
///     .expect("non-empty file has a tree");
/// builder.feed(&content[..4]).expect("within the declared leaf count");
/// builder.feed(&content[4..]).expect("within the declared leaf count");
/// let (streamed, stats) = builder.finish().expect("fed exactly n bytes");
///
/// // … equals the one-shot rebuild a verifier performs.
/// assert_eq!(Some(streamed), rebuild_fine_root(&s_root, content));
/// assert_eq!(stats.leaf_hashes, content.len() as u64);
/// ```
#[derive(Debug)]
pub struct FineTreeBuilder {
    walker: GgmWalker,
    frontier: MerkleFrontier,
    leaf_count: u64,
    depth: u8,
    fed: u64,
}

impl FineTreeBuilder {
    /// A builder for a file of `leaf_count` bytes rooted at `s_root`.
    ///
    /// `None` for `leaf_count == 0`: an empty file has **no fine tree** and
    /// one empty unit (MVP-SPEC.md line 78) — the absence is the answer, not
    /// an error.
    #[must_use]
    pub fn new(s_root: &Seed32, leaf_count: u64) -> Option<Self> {
        let depth = depth_for_leaf_count(leaf_count)?;
        Some(Self {
            walker: GgmWalker::new(s_root, depth),
            frontier: MerkleFrontier::with_capacity(depth),
            leaf_count,
            depth,
            fed: 0,
        })
    }

    /// Absorb the next `chunk` of content bytes.
    ///
    /// Chunking is invisible to the result: leaves are indexed by absolute
    /// position, so any slicing of the same input produces the same
    /// `fine_root` (asserted by `chunk_boundaries_do_not_matter`).
    ///
    /// # Errors
    ///
    /// [`FineTreeError::ByteLenMismatch`] if the chunk would push the total
    /// past the declared leaf count. Detected *before* any hashing, so an
    /// over-long stream costs nothing and allocates nothing.
    pub fn feed(&mut self, chunk: &[u8]) -> Result<(), FineTreeError> {
        let chunk_len = u64::try_from(chunk.len()).unwrap_or(u64::MAX);
        let total = self.fed.saturating_add(chunk_len);
        if total > self.leaf_count {
            return Err(FineTreeError::ByteLenMismatch {
                expected: self.leaf_count,
                got: total,
            });
        }

        for byte in chunk {
            let salt = self.walker.next_salt();
            let hash = leaf_hash(&salt, self.fed, *byte);
            self.frontier.push_leaf(hash);
            self.fed += 1;
        }
        Ok(())
    }

    /// Fold the frontier and yield `fine_root` together with the measured
    /// cost and memory shape.
    ///
    /// # Errors
    ///
    /// [`FineTreeError::ByteLenMismatch`] if fewer than `leaf_count` bytes
    /// were fed — a short stream must never silently commit a shorter file.
    pub fn finish(self) -> Result<(FineRoot, FineTreeStats), FineTreeError> {
        if self.fed != self.leaf_count {
            return Err(FineTreeError::ByteLenMismatch {
                expected: self.leaf_count,
                got: self.fed,
            });
        }
        let leaf_hashes = self.fed;
        let ggm_derivations = self.walker.derivations();
        let peak_seed_stack_len = self.walker.peak_stack_len();
        let peak_frontier_len = self.frontier.peak_len;

        // `finish` returns `None` only for an empty frontier, i.e. n = 0 —
        // unreachable here, since `new` refuses that case.
        let (root, node_hashes) = self
            .frontier
            .finish()
            .unwrap_or(([0u8; 32], self.leaf_count.saturating_sub(1)));

        Ok((
            FineRoot::from_bytes(root),
            FineTreeStats {
                leaf_hashes,
                node_hashes,
                ggm_derivations,
                peak_frontier_len,
                peak_seed_stack_len,
            },
        ))
    }

    /// Cost and memory shape so far — readable mid-stream, which is how G18
    /// asserts the peak bound at a size too large to buffer.
    #[must_use]
    pub fn stats(&self) -> FineTreeStats {
        FineTreeStats {
            leaf_hashes: self.fed,
            node_hashes: self.frontier.node_hashes,
            ggm_derivations: self.walker.derivations(),
            peak_frontier_len: self.frontier.peak_len,
            peak_seed_stack_len: self.walker.peak_stack_len(),
        }
    }

    /// The GGM tree depth `d = ceil(log2 n)` this builder derives against.
    #[must_use]
    pub const fn depth(&self) -> u8 {
        self.depth
    }

    /// The declared leaf count `n`.
    #[must_use]
    pub const fn leaf_count(&self) -> u64 {
        self.leaf_count
    }

    /// Bytes absorbed so far.
    #[must_use]
    pub const fn fed(&self) -> u64 {
        self.fed
    }
}

/// Rebuild a file's `fine_root` from a bundle-supplied `s_root` and the
/// file's full content bytes — **the primitive R's verifier executes on a
/// full-file reveal** (MVP-SPEC.md line 121: "using the bundled `s_root`, the
/// verifier MUST rebuild the whole fine tree from those bytes and match
/// `fine_root`").
///
/// It is the *identical* construction the sealer ran, driven through the same
/// [`FineTreeBuilder`] — there is deliberately no second implementation that
/// could drift.
///
/// `None` iff `bytes` is empty: an empty file has no fine tree (line 78), so
/// there is nothing to match and the manifest carries no `fine_root` either.
#[must_use]
pub fn rebuild_fine_root(s_root: &Seed32, bytes: &[u8]) -> Option<FineRoot> {
    // `usize -> u64` is lossless on every supported target (64-bit native,
    // 32-bit wasm32), so the fallback is unreachable; it keeps the function
    // total rather than casting.
    let leaf_count = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    let mut builder = FineTreeBuilder::new(s_root, leaf_count)?;
    builder.feed(bytes).ok()?;
    builder.finish().ok().map(|(root, _stats)| root)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::content::ggm::SaltTree;
    use crate::test_util::TEST_MASTER_SECRET_W;
    use crate::test_util::strategies::proptest_config;
    use proptest::prelude::*;

    fn root_seed() -> Seed32 {
        Seed32::from_bytes(TEST_MASTER_SECRET_W)
    }

    /// **Independent** reference: the recursive RFC 6962 definition over a
    /// materialized leaf-hash vector, with every salt taken from G8's
    /// per-leaf [`SaltTree::salt`]. Shares no traversal code with the
    /// streaming builder — it is deliberately the naive `O(n log n)`,
    /// `O(n)`-memory implementation the streaming one replaces.
    fn reference_root(s_root: &Seed32, bytes: &[u8]) -> Option<[u8; 32]> {
        let n = u64::try_from(bytes.len()).ok()?;
        let tree = SaltTree::new(s_root, n)?;
        let leaves: Vec<[u8; 32]> = bytes
            .iter()
            .enumerate()
            .map(|(i, byte)| {
                let index = u64::try_from(i).expect("index fits u64");
                let salt = tree.salt(index).expect("index < n");
                leaf_hash(&salt, index, *byte)
            })
            .collect();
        Some(reference_mth(&leaves))
    }

    /// RFC 6962 `MTH`, written straight from the definition.
    fn reference_mth(leaves: &[[u8; 32]]) -> [u8; 32] {
        assert!(!leaves.is_empty(), "MTH is undefined for zero leaves");
        if leaves.len() == 1 {
            return leaves[0];
        }
        let mut k = 1usize;
        while k * 2 < leaves.len() {
            k *= 2;
        }
        let left = reference_mth(&leaves[..k]);
        let right = reference_mth(&leaves[k..]);
        node_hash(&left, &right)
    }

    fn build(s_root: &Seed32, bytes: &[u8]) -> Option<(FineRoot, FineTreeStats)> {
        let n = u64::try_from(bytes.len()).expect("fits u64");
        let mut builder = FineTreeBuilder::new(s_root, n)?;
        builder.feed(bytes).expect("exactly n bytes");
        Some(builder.finish().expect("exactly n bytes"))
    }

    // ── Edge cases (G9 accept) ──────────────────────────────────────────

    /// `n = 0` → no tree; `n = 1` → root == leaf (MVP-SPEC.md line 78).
    #[test]
    fn empty_file_has_no_tree_and_one_byte_file_root_is_its_leaf() {
        let seed = root_seed();
        assert!(FineTreeBuilder::new(&seed, 0).is_none(), "n = 0 → no tree");
        assert_eq!(rebuild_fine_root(&seed, b""), None);

        let (root, stats) = build(&seed, b"Z").expect("n = 1 has a tree");
        let tree = SaltTree::new(&seed, 1).expect("n = 1");
        let salt = tree.salt(0).expect("leaf 0");
        assert_eq!(
            root.as_bytes(),
            &leaf_hash(&salt, 0, b'Z'),
            "n = 1 → root == leaf_0"
        );
        assert_eq!(stats.node_hashes, 0, "a single leaf has no interior node");
        assert_eq!(stats.ggm_derivations, 0, "d = 0 → salt_0 = s_root[..16]");
    }

    /// Pinned code-level vector: the exact `fine_root` of the n = 6
    /// unbalanced witness (MVP-SPEC.md line 169 mandates an unbalanced-n
    /// golden vector; the committed *file* form lands in G15). Any change to
    /// the leaf preimage, the node preimage, the promotion rule, or the salt
    /// derivation breaks this.
    #[test]
    fn pinned_fine_root_vectors() {
        let seed = root_seed();
        let (n6, _) = build(&seed, b"abcdef").expect("n = 6");
        assert_eq!(n6.as_bytes(), &PINNED_N6_ROOT);

        let (n1, _) = build(&seed, b"a").expect("n = 1");
        assert_eq!(n1.as_bytes(), &PINNED_N1_ROOT);

        let (n5, _) = build(&seed, b"abcde").expect("n = 5");
        assert_eq!(n5.as_bytes(), &PINNED_N5_ROOT);
    }

    /// `fine_root` for `s_root` = the documented fixture pattern, content
    /// `b"a"` (n = 1, d = 0 — root is the leaf).
    const PINNED_N1_ROOT: [u8; 32] = [
        0xD6, 0x54, 0x62, 0x3D, 0xAD, 0xE7, 0xE6, 0x70, 0x9D, 0xDE, 0x44, 0xBE, 0x5C, 0x15, 0xBF,
        0x25, 0x77, 0xF7, 0xDF, 0x5A, 0x24, 0x83, 0x0F, 0xA0, 0xA9, 0x64, 0x3D, 0x1A, 0xE9, 0xCE,
        0x69, 0xB1,
    ];
    /// `fine_root` for content `b"abcde"` (n = 5, d = 3 — unused GGM slots
    /// 5..8 and a 4 + 1 unbalanced promotion).
    const PINNED_N5_ROOT: [u8; 32] = [
        0x5F, 0x45, 0xB2, 0xE1, 0x47, 0x8F, 0x67, 0x92, 0xA8, 0x79, 0x3E, 0xB4, 0x25, 0xC7, 0xC4,
        0x69, 0x1F, 0xBB, 0x66, 0xAB, 0xC2, 0xC1, 0xB9, 0xA3, 0x47, 0x11, 0x1E, 0x41, 0xF5, 0x3F,
        0xEB, 0x53,
    ];
    /// `fine_root` for content `b"abcdef"` (n = 6, d = 3 — the MSB-first
    /// witness tree with a 4 + 2 unbalanced promotion).
    const PINNED_N6_ROOT: [u8; 32] = [
        0x34, 0x13, 0xB4, 0x8C, 0x10, 0xB9, 0x0B, 0x23, 0x40, 0xF0, 0x8A, 0xAE, 0xFA, 0xB4, 0xFF,
        0x04, 0xB4, 0xF9, 0xCC, 0xFB, 0x89, 0x21, 0x07, 0x93, 0x2E, 0x57, 0x77, 0xA3, 0x13, 0xDB,
        0xD2, 0xE1,
    ];

    /// The RFC 6962 promotion shape, spelled out at n = 6 against hand-built
    /// intermediates: root = H(H(H(l0,l1),H(l2,l3)), H(l4,l5)).
    #[test]
    fn unbalanced_promotion_matches_rfc6962_by_hand() {
        let seed = root_seed();
        let content = b"abcdef";
        let tree = SaltTree::new(&seed, 6).expect("n = 6");
        let leaf = |i: u64| {
            leaf_hash(
                &tree.salt(i).expect("in range"),
                i,
                content[usize::try_from(i).expect("small")],
            )
        };
        let l01 = node_hash(&leaf(0), &leaf(1));
        let l23 = node_hash(&leaf(2), &leaf(3));
        let l45 = node_hash(&leaf(4), &leaf(5));
        let expected = node_hash(&node_hash(&l01, &l23), &l45);

        let (root, _) = build(&seed, content).expect("n = 6");
        assert_eq!(root.as_bytes(), &expected);
    }

    // ── Streaming behaviour (G9 accept) ─────────────────────────────────

    /// G9 accept: identical `fine_root` regardless of how the input is
    /// sliced across `feed` calls.
    #[test]
    fn chunk_boundaries_do_not_matter() {
        let seed = root_seed();
        let content: Vec<u8> = (0..=250u8).cycle().take(777).collect();
        let one_shot = rebuild_fine_root(&seed, &content).expect("non-empty");

        for chunk_size in [1usize, 2, 3, 7, 64, 256, 776, 777, 1024] {
            let mut builder = FineTreeBuilder::new(&seed, 777).expect("n > 0");
            for chunk in content.chunks(chunk_size) {
                builder.feed(chunk).expect("within n");
            }
            let (root, _) = builder.finish().expect("exactly n");
            assert_eq!(root, one_shot, "chunk size {chunk_size}");
        }

        // Zero-length feeds are inert.
        let mut builder = FineTreeBuilder::new(&seed, 777).expect("n > 0");
        builder.feed(b"").expect("inert");
        builder.feed(&content).expect("within n");
        builder.feed(b"").expect("inert");
        assert_eq!(builder.finish().expect("exactly n").0, one_shot);
    }

    /// Over- and under-feeding are errors with the same distinct class, and
    /// the over-feed is rejected **before** any hashing happens.
    #[test]
    fn feeding_the_wrong_byte_count_is_rejected() {
        let seed = root_seed();

        let mut over = FineTreeBuilder::new(&seed, 4).expect("n > 0");
        assert_eq!(
            over.feed(b"abcde"),
            Err(FineTreeError::ByteLenMismatch {
                expected: 4,
                got: 5
            })
        );
        assert_eq!(over.fed(), 0, "nothing was hashed before the rejection");
        assert_eq!(over.stats().leaf_hashes, 0);

        let mut split = FineTreeBuilder::new(&seed, 4).expect("n > 0");
        split.feed(b"abc").expect("within n");
        assert_eq!(
            split.feed(b"de"),
            Err(FineTreeError::ByteLenMismatch {
                expected: 4,
                got: 5
            })
        );

        let mut under = FineTreeBuilder::new(&seed, 4).expect("n > 0");
        under.feed(b"abc").expect("within n");
        assert_eq!(
            under.finish().err(),
            Some(FineTreeError::ByteLenMismatch {
                expected: 4,
                got: 3
            })
        );
    }

    /// Different roots, different bytes, and different lengths all give
    /// different trees — the construction binds all three.
    #[test]
    fn the_root_binds_seed_content_and_length() {
        let seed = root_seed();
        let other = Seed32::from_bytes([0xEE; 32]);
        let base = build(&seed, b"abcdef").expect("n = 6").0;

        assert_ne!(base, build(&other, b"abcdef").expect("n = 6").0);
        assert_ne!(base, build(&seed, b"abcdeF").expect("n = 6").0);
        assert_ne!(base, build(&seed, b"abcde").expect("n = 5").0);
        assert_ne!(base, build(&seed, b"abcdefg").expect("n = 7").0);
        // Transposition: the LE64 index in the leaf preimage defeats it.
        assert_ne!(base, build(&seed, b"bacdef").expect("n = 6").0);
    }

    // ── Instrumentation (G9 accept) ─────────────────────────────────────

    /// The measured compression count matches the closed-form model
    /// **exactly** — a far stronger statement than an envelope, and the
    /// identity G10's estimator is built on:
    ///
    /// ```text
    /// compressions(n) = n·1              leaves
    ///                 + (n − 1)·2        interior nodes
    ///                 + G(n)·1           GGM child derivations
    /// G(n) = (sum_{l=0..=d} ceil(n / 2^(d−l))) − 1     (path-union edges)
    /// ```
    #[test]
    fn measured_cost_matches_the_closed_form_model() {
        let seed = root_seed();
        for n in [1usize, 2, 3, 5, 6, 8, 9, 16, 17, 31, 32, 33, 100, 129, 512] {
            let content: Vec<u8> = (0..n).map(|i| u8::try_from(i % 251).unwrap_or(0)).collect();
            let (_, stats) = build(&seed, &content).expect("n > 0");
            let n64 = u64::try_from(n).expect("small");
            let depth = depth_for_leaf_count(n64).expect("n > 0");

            let ggm_model: u64 = (0..=depth)
                .map(|level| n64.div_ceil(1u64 << (depth - level)))
                .sum::<u64>()
                - 1;
            assert_eq!(stats.leaf_hashes, n64, "n = {n}");
            assert_eq!(stats.node_hashes, n64 - 1, "n = {n}: interior nodes");
            assert_eq!(stats.ggm_derivations, ggm_model, "n = {n}: GGM edges");
            assert_eq!(
                stats.sha256_compressions(),
                n64 + 2 * (n64 - 1) + ggm_model,
                "n = {n}: total compressions"
            );
        }
    }

    /// G9 accept: the instrumented compressions/byte figure, including at
    /// `n` just above a power of two (worst GGM padding).
    ///
    /// The construction's asymptote is **exactly 5** per byte
    /// (1 leaf + 2 node + 2 GGM) and it approaches from just below, since
    /// there are `n − 1` interior nodes rather than `n`. The assertion is
    /// therefore "at the bottom of the spec's ~5–7 envelope, never above
    /// it" — the concrete budget constants are G18's, gated on the still
    /// open decision D26, and are deliberately not frozen here.
    #[test]
    fn compressions_per_byte_sit_at_the_bottom_of_the_spec_envelope() {
        let seed = root_seed();
        for n in [4_096usize, 4_097, 8_192, 8_193, 12_289] {
            let content: Vec<u8> = (0..n).map(|i| u8::try_from(i % 251).unwrap_or(0)).collect();
            let (_, stats) = build(&seed, &content).expect("n > 0");
            let milli = stats.compressions_per_byte_milli();
            assert!(
                (4_900..=7_000).contains(&milli),
                "n = {n}: {milli} milli-compressions/byte outside the spec envelope"
            );
            // And the exact statement the envelope approximates.
            assert!(
                milli >= 4_990,
                "n = {n}: {milli} is further below the 5.0 asymptote than n can explain"
            );
        }
    }

    /// G9 accept: the memory bound is **structural** — both instrumented
    /// stacks stay within `d + 1`, independent of `n`, so the claim does not
    /// rest on an allocator measurement.
    #[test]
    fn auxiliary_memory_is_logarithmic() {
        let seed = root_seed();
        for n in [1usize, 2, 7, 8, 9, 1_000, 4_096, 10_000] {
            let content: Vec<u8> = (0..n).map(|i| u8::try_from(i % 251).unwrap_or(0)).collect();
            let (_, stats) = build(&seed, &content).expect("n > 0");
            let depth =
                u32::from(depth_for_leaf_count(u64::try_from(n).expect("small")).expect("n > 0"));
            assert!(
                stats.peak_seed_stack_len <= depth + 1,
                "n = {n}: GGM stack {} > d + 1 = {}",
                stats.peak_seed_stack_len,
                depth + 1
            );
            assert!(
                stats.peak_frontier_len <= depth + 1,
                "n = {n}: frontier {} > d + 1 = {}",
                stats.peak_frontier_len,
                depth + 1
            );
        }
    }

    /// `FineRoot` renders as hex and is not confusable with a node hash type
    /// in `Debug` output.
    #[test]
    fn fine_root_debug_is_hex() {
        let root = FineRoot::from_bytes([0xAB; 32]);
        let rendered = format!("{root:?}");
        assert!(rendered.starts_with("FineRoot(abab"), "{rendered}");
        assert_eq!(FineRoot::LEN, 32);
    }

    // ── Property tests (G9 accept) ──────────────────────────────────────

    proptest! {
        #![proptest_config(proptest_config(0x0064_0009))]

        /// G9 accept: the streaming result equals the naive in-memory
        /// reference for every `n` in `0..~300` with random bytes.
        #[test]
        fn streaming_equals_the_naive_reference(
            content in proptest::collection::vec(any::<u8>(), 0..300),
            root_bytes in any::<[u8; 32]>(),
        ) {
            let seed = Seed32::from_bytes(root_bytes);
            let streamed = rebuild_fine_root(&seed, &content);
            let reference = reference_root(&seed, &content).map(FineRoot::from_bytes);
            prop_assert_eq!(streamed, reference);
        }

        /// G9 accept: chunk-boundary independence over arbitrary content and
        /// arbitrary slicings.
        #[test]
        fn chunking_never_changes_the_root(
            content in proptest::collection::vec(any::<u8>(), 1..200),
            chunk in 1usize..64,
            root_bytes in any::<[u8; 32]>(),
        ) {
            let seed = Seed32::from_bytes(root_bytes);
            let n = u64::try_from(content.len()).expect("small");
            let mut builder = FineTreeBuilder::new(&seed, n).expect("n > 0");
            for slice in content.chunks(chunk) {
                builder.feed(slice).expect("within n");
            }
            let (root, _) = builder.finish().expect("exactly n");
            prop_assert_eq!(Some(root), rebuild_fine_root(&seed, &content));
        }

        /// G9 accept: the O(log n) memory bound holds for every shape, and
        /// the frontier's width invariant (strictly decreasing powers of two)
        /// is what makes it hold.
        #[test]
        fn memory_stays_logarithmic(
            content in proptest::collection::vec(any::<u8>(), 1..400),
            root_bytes in any::<[u8; 32]>(),
        ) {
            let seed = Seed32::from_bytes(root_bytes);
            let n = u64::try_from(content.len()).expect("small");
            let depth = u32::from(depth_for_leaf_count(n).expect("n > 0"));
            let mut builder = FineTreeBuilder::new(&seed, n).expect("n > 0");
            for slice in content.chunks(13) {
                builder.feed(slice).expect("within n");
                let stats = builder.stats();
                prop_assert!(stats.peak_frontier_len <= depth + 1);
                prop_assert!(stats.peak_seed_stack_len <= depth + 1);
            }
        }

        /// Distinct content of the same length gives distinct roots (binding,
        /// modulo the SHA-256 collision assumption the spec names in line 100).
        #[test]
        fn distinct_content_gives_distinct_roots(
            a in proptest::collection::vec(any::<u8>(), 1..60),
            b in proptest::collection::vec(any::<u8>(), 1..60),
            root_bytes in any::<[u8; 32]>(),
        ) {
            prop_assume!(a != b);
            let seed = Seed32::from_bytes(root_bytes);
            prop_assert_ne!(
                rebuild_fine_root(&seed, &a),
                rebuild_fine_root(&seed, &b)
            );
        }
    }
}
