//! GGM salt tree (tasks/G.md G8) — the puncturable-PRF salt source behind the
//! fine tree's per-byte commitments (MVP-SPEC.md line 96).
//!
//! # What it is
//!
//! Each fine-tree leaf `i` commits one byte under its own 16-byte salt:
//! `leaf_i = SHA-256(0x00 ‖ salt_i ‖ LE64(i) ‖ byte_i)`. Storing a flat salt
//! per byte would cost 16 B of disclosure **per revealed byte**, and a single
//! shared salt would turn `fine_root` into an unsalted whole-file commitment
//! the moment it leaked. Instead the salts are the leaves of a GGM tree grown
//! from one 32-byte seed:
//!
//! - `s_root = HKDF(W, "fine-seed", file_id)` (32 B) — **injected** by the
//!   caller (C's derivation); this module never touches `W`.
//! - depth `d = ceil(log2 n)` over the file's leaf count `n`; `n = 1` gives
//!   `d = 0`. The tree is a **complete** binary tree of `2^d` leaf slots,
//!   deliberately independent of the content Merkle tree's (unbalanced,
//!   RFC-6962-promoted) shape — the two only share the leaf index space.
//! - children: `s_{v‖b} = SHA-256(0x06 ‖ s_v ‖ b)` for `b ∈ {0x00, 0x01}`
//!   ([`child_seed`], routed through the single domain-tag registry).
//! - leaf `i` is reached from `s_root` by the bits of `i` **MSB-first** (bit
//!   `d−1` first) — [`NodeAddress::path_bits`].
//! - slots `i >= n` are **unused**: no public output path in this module
//!   derives them ([`SaltTree::salt`] returns `None`, [`SaltTree::seed_at`]
//!   returns [`ContentError::UnusedGgmSlot`]).
//! - `salt_i` = the leaf seed truncated to 16 B; with `d = 0`, `n = 1` that is
//!   `s_root[..16]`, exactly as the spec states.
//!
//! MSB-first indexing is what makes every contiguous byte range a **dyadic**
//! decomposition, so a range reveal ships a minimal sub-cover of at most
//! `2·ceil(log2 n)` seeds (~1.7 KB even at `n = 10^8`) instead of one salt per
//! byte, while out-of-range salts stay pseudorandom.
//!
//! # Node addressing (open decision D9, co-frozen with F)
//!
//! [`NodeAddress`] is `(level, index)`: `level` = child-derivation steps below
//! `s_root` (root = 0, leaf slots at `level = d`), `index` = position within
//! the level, `index < 2^level`. **The bits of `index`, MSB-first, are exactly
//! the root-to-node path** — so this is the spec's own leaf-addressing rule
//! (line 96) generalized to interior nodes, not a second convention.
//!
//! The **semantic** form is G's and is adopted here; the **CBOR encoding** is
//! F's (`docs/format/registry-v1.md` §5 Candidate A — `cover_entry =
//! [level, index, seed]`, `path_node = [level, index, hash]`), whose draft
//! recommends exactly this shape pending G8's adoption. Formal freeze happens
//! with the registry at Q14. Nothing in this module encodes anything.
//!
//! # Cost and safety properties
//!
//! Derivation is pure, deterministic, and **allocation-bounded**: reaching any
//! node costs `level` SHA-256 compressions with O(1) auxiliary state and no
//! heap traffic — `O(log n)`, never `O(n)`. G9 amortizes the same primitive
//! down to O(1) hashes per leaf with an O(d) seed stack. All of it is WASM-safe
//! (no I/O, no clocks, no randomness).
//!
//! Seeds are secret material: [`Seed32`] redacts its `Debug` and wipes on drop,
//! and no error in this module carries seed or salt bytes (project rule 6).
//! **No seed that is an ancestor of an unrevealed leaf may ever leave the
//! vault** (MVP-SPEC.md line 96) — that is a disclosure-policy rule enforced by
//! G11's leaf-exact cover construction, not by this derivation layer, which
//! answers exactly what it is asked.

use zeroize::Zeroize;

use crate::crypto::domain::{TAG_GGM_SALT_CHILD, tagged_sha256};
use crate::crypto::material::{Salt16, Seed32};

use super::error::ContentError;

/// GGM tree depth for a file of `n` leaves: `d = ceil(log2 n)`
/// (MVP-SPEC.md line 96).
///
/// - `n = 0` → `None`: an empty file has no fine tree at all (line 78).
/// - `n = 1` → `Some(0)`: the root *is* the only leaf, and `salt_0 =
///   s_root[..16]`.
/// - otherwise the smallest `d` with `2^d >= n`.
///
/// Saturates naturally at [`NodeAddress::MAX_LEVEL`]: `n = u64::MAX` gives
/// `d = 64`.
#[must_use]
pub const fn depth_for_leaf_count(n: u64) -> Option<u8> {
    if n == 0 {
        return None;
    }
    if n == 1 {
        return Some(0);
    }
    // ceil(log2 n) = 64 − leading_zeros(n − 1) for n >= 2, which lies in
    // 1..=64 and therefore always fits a u8.
    Some((64 - (n - 1).leading_zeros()) as u8)
}

/// Which child of a GGM node: the byte `b` appended to the parent seed in
/// `s_{v‖b} = SHA-256(0x06 ‖ s_v ‖ b)` (MVP-SPEC.md line 96).
///
/// `b` is preimage **data**, not a domain tag — only the leading `0x06` carries
/// domain meaning (see [`crate::crypto::domain`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChildBit {
    /// Path bit 0 — the lower half of the parent's slot interval.
    Left,
    /// Path bit 1 — the upper half.
    Right,
}

impl ChildBit {
    /// Both children, in path-bit order.
    pub const ALL: [Self; 2] = [Self::Left, Self::Right];

    /// The preimage byte: 0 for [`Self::Left`], 1 for [`Self::Right`].
    #[must_use]
    pub const fn as_byte(self) -> u8 {
        match self {
            Self::Left => 0,
            Self::Right => 1,
        }
    }

    /// The child selected by a path bit (`false` → left, `true` → right).
    #[must_use]
    pub const fn from_bit(bit: bool) -> Self {
        if bit { Self::Right } else { Self::Left }
    }
}

/// A node slot on the depth-`d` dyadic grid, as `(level, index)`
/// (open decision D9; module docs).
///
/// Constructible only through the checked constructors, so a value of this type
/// always satisfies `level <= 64` and `index < 2^level`. Validity *relative to a
/// particular tree* (`level <= d`, and the slot covering at least one real leaf)
/// is checked where the tree is known — [`SaltTree::seed_at`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NodeAddress {
    level: u8,
    index: u64,
}

impl NodeAddress {
    /// Deepest representable level. A file's leaf count is a `u64`, so
    /// `d = ceil(log2 n) <= 64`.
    pub const MAX_LEVEL: u8 = 64;

    /// The tree root, `(0, 0)` — the slot holding `s_root` itself.
    #[must_use]
    pub const fn root() -> Self {
        Self { level: 0, index: 0 }
    }

    /// A checked `(level, index)` slot.
    ///
    /// # Errors
    ///
    /// - [`ContentError::NodeAddressLevelTooDeep`] when `level > 64`.
    /// - [`ContentError::NodeAddressIndexOutOfRange`] when `index >= 2^level`
    ///   (the index's `level` bits *are* the path, so a wider index would name
    ///   no path at all).
    pub const fn try_new(level: u8, index: u64) -> Result<Self, ContentError> {
        if level > Self::MAX_LEVEL {
            return Err(ContentError::NodeAddressLevelTooDeep {
                level,
                max: Self::MAX_LEVEL,
            });
        }
        // At level 64 every u64 index is in range; below that, check 2^level.
        if level < 64 && index >= (1u64 << level) {
            return Err(ContentError::NodeAddressIndexOutOfRange { level, index });
        }
        Ok(Self { level, index })
    }

    /// The leaf slot `index` in a tree of depth `depth`.
    ///
    /// # Errors
    ///
    /// As [`Self::try_new`].
    pub const fn leaf(depth: u8, index: u64) -> Result<Self, ContentError> {
        Self::try_new(depth, index)
    }

    /// Child-derivation steps below `s_root` (root = 0).
    #[must_use]
    pub const fn level(self) -> u8 {
        self.level
    }

    /// Position within the level; its `level` bits, MSB-first, are the
    /// root-to-node path.
    #[must_use]
    pub const fn index(self) -> u64 {
        self.index
    }

    /// The root-to-node path as [`ChildBit`]s, **MSB-first** (bit `level−1`
    /// first) — the spec's leaf rule, generalized (MVP-SPEC.md line 96).
    ///
    /// Yields exactly `level` items and allocates nothing.
    #[must_use]
    pub const fn path_bits(self) -> PathBits {
        PathBits {
            index: self.index,
            remaining: self.level,
        }
    }

    /// The child slot reached by taking `bit` from here.
    ///
    /// # Errors
    ///
    /// [`ContentError::NodeAddressLevelTooDeep`] at the maximum level.
    pub const fn child(self, bit: ChildBit) -> Result<Self, ContentError> {
        if self.level >= Self::MAX_LEVEL {
            return Err(ContentError::NodeAddressLevelTooDeep {
                level: Self::MAX_LEVEL + 1,
                max: Self::MAX_LEVEL,
            });
        }
        // index < 2^level and level < 64, so 2·index + 1 < 2^(level+1) <= 2^64.
        Self::try_new(self.level + 1, self.index * 2 + bit.as_byte() as u64)
    }

    /// Check this address against a tree of depth `depth`.
    ///
    /// # Errors
    ///
    /// [`ContentError::NodeAddressLevelExceedsDepth`] when `level > depth` —
    /// representable, but not a slot of *this* tree.
    pub const fn validate_in_tree(self, depth: u8) -> Result<(), ContentError> {
        if self.level > depth {
            return Err(ContentError::NodeAddressLevelExceedsDepth {
                level: self.level,
                depth,
            });
        }
        Ok(())
    }

    /// First leaf slot this node covers in a depth-`depth` tree:
    /// `index · 2^(depth − level)`.
    ///
    /// Always a `u64`: the product is `< 2^depth <= 2^64`.
    ///
    /// # Errors
    ///
    /// As [`Self::validate_in_tree`].
    pub const fn first_slot(self, depth: u8) -> Result<u64, ContentError> {
        if let Err(error) = self.validate_in_tree(depth) {
            return Err(error);
        }
        let shift = depth - self.level;
        // `shift == 64` occurs only at depth 64, level 0 — where the address is
        // necessarily the root (`index == 0`) and the true first slot is 0, so
        // the fallback is exact rather than a fudge.
        Ok(match self.index.checked_shl(shift as u32) {
            Some(slot) => slot,
            None => 0,
        })
    }

    /// Number of leaf slots this node covers: `2^(depth − level)`.
    ///
    /// `u128` because the degenerate depth-64 root covers `2^64` slots, which
    /// does not fit a `u64` — keeping the arithmetic panic-free on
    /// adversarially large `size` fields.
    ///
    /// # Errors
    ///
    /// As [`Self::validate_in_tree`].
    pub const fn slot_width(self, depth: u8) -> Result<u128, ContentError> {
        if let Err(error) = self.validate_in_tree(depth) {
            return Err(error);
        }
        Ok(1u128 << (depth - self.level))
    }

    /// Whether this node covers leaf slot `slot` in a depth-`depth` tree.
    ///
    /// # Errors
    ///
    /// As [`Self::validate_in_tree`].
    pub const fn covers_slot(self, depth: u8, slot: u64) -> Result<bool, ContentError> {
        let first = match self.first_slot(depth) {
            Ok(first) => first,
            Err(error) => return Err(error),
        };
        let width = match self.slot_width(depth) {
            Ok(width) => width,
            Err(error) => return Err(error),
        };
        Ok(slot >= first && (slot as u128) < (first as u128) + width)
    }
}

/// MSB-first path-bit iterator returned by [`NodeAddress::path_bits`].
#[derive(Debug, Clone)]
pub struct PathBits {
    index: u64,
    remaining: u8,
}

impl Iterator for PathBits {
    type Item = ChildBit;

    fn next(&mut self) -> Option<ChildBit> {
        if self.remaining == 0 {
            return None;
        }
        self.remaining -= 1;
        // `remaining` is now <= 63, so the shift is always in range.
        Some(ChildBit::from_bit((self.index >> self.remaining) & 1 == 1))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let len = usize::from(self.remaining);
        (len, Some(len))
    }
}

impl ExactSizeIterator for PathBits {}

/// One GGM child derivation: `s_{v‖b} = SHA-256(0x06 ‖ s_v ‖ b)`
/// (MVP-SPEC.md lines 79, 96).
///
/// The single hash primitive of this module; G9's amortized DFS calls exactly
/// this. Routed through [`tagged_sha256`] so `0x06` is structurally the first
/// preimage byte.
#[must_use]
pub fn child_seed(parent: &Seed32, bit: ChildBit) -> Seed32 {
    Seed32::from_bytes(tagged_sha256(
        TAG_GGM_SALT_CHILD,
        &[parent.as_bytes(), &[bit.as_byte()]],
    ))
}

/// The GGM salt tree of one file (MVP-SPEC.md line 96).
///
/// Borrows `s_root` rather than owning it: the seed is secret material with
/// wiping drop semantics ([`Seed32`]), and borrowing keeps exactly one copy
/// alive, owned by the caller.
///
/// `Debug` is safe to print — the borrowed seed redacts itself — and exposes
/// only the public structural quantities.
#[derive(Debug)]
pub struct SaltTree<'a> {
    s_root: &'a Seed32,
    leaf_count: u64,
    depth: u8,
}

impl<'a> SaltTree<'a> {
    /// The salt tree over `leaf_count` leaves rooted at `s_root`.
    ///
    /// `None` for `leaf_count == 0`: an empty file has no fine tree and no
    /// salts (MVP-SPEC.md line 78). `leaf_count` is the file-table `size`
    /// field — canonical bytes for text, raw bytes for binary (line 98).
    #[must_use]
    pub const fn new(s_root: &'a Seed32, leaf_count: u64) -> Option<Self> {
        match depth_for_leaf_count(leaf_count) {
            None => None,
            Some(depth) => Some(Self {
                s_root,
                leaf_count,
                depth,
            }),
        }
    }

    /// Tree depth `d = ceil(log2 n)`.
    #[must_use]
    pub const fn depth(&self) -> u8 {
        self.depth
    }

    /// The file's leaf count `n` — the number of *used* slots.
    #[must_use]
    pub const fn leaf_count(&self) -> u64 {
        self.leaf_count
    }

    /// Total leaf slots on the grid, `2^d` (`u128`: the depth-64 grid has
    /// `2^64`). Slots `n..2^d` are unused.
    #[must_use]
    pub const fn slot_count(&self) -> u128 {
        1u128 << self.depth
    }

    /// The root slot, `(0, 0)`.
    #[must_use]
    pub const fn root_address(&self) -> NodeAddress {
        NodeAddress::root()
    }

    /// The address of leaf `index` in this tree: `(d, index)`.
    ///
    /// # Errors
    ///
    /// [`ContentError::NodeAddressIndexOutOfRange`] when `index >= 2^d`.
    /// Note this permits unused slots `n..2^d` — the *derivation* refuses them
    /// ([`Self::seed_at`]); addressing them is how a verifier names what it is
    /// rejecting.
    pub const fn leaf_address(&self, index: u64) -> Result<NodeAddress, ContentError> {
        NodeAddress::leaf(self.depth, index)
    }

    /// Derive the seed at `address`.
    ///
    /// Costs `address.level()` SHA-256 compressions and allocates nothing.
    ///
    /// # Errors
    ///
    /// - [`ContentError::NodeAddressLevelExceedsDepth`] — not a slot of this
    ///   tree.
    /// - [`ContentError::UnusedGgmSlot`] — the slot covers only unused leaf
    ///   slots (`first_slot >= n`). Such a node commits nothing, so no public
    ///   path derives it (MVP-SPEC.md line 96: "slots `i >= n` are unused").
    ///   Nodes that *straddle* the boundary are derivable: they cover real
    ///   leaves, and a range cover legitimately needs them.
    pub fn seed_at(&self, address: NodeAddress) -> Result<Seed32, ContentError> {
        let first_slot = address.first_slot(self.depth)?;
        if first_slot >= self.leaf_count {
            return Err(ContentError::UnusedGgmSlot {
                first_slot,
                leaf_count: self.leaf_count,
            });
        }
        Ok(self.derive_along(address.path_bits()))
    }

    /// The 16-byte salt of leaf `index`: the leaf seed truncated to 16 B
    /// (MVP-SPEC.md line 96).
    ///
    /// `None` iff `index >= n` — an unused slot, whose seed is **not derived**
    /// (the check precedes every hash).
    ///
    /// With `d = 0` (`n = 1`) the leaf *is* the root, so `salt_0 = s_root[..16]`
    /// with zero derivation steps, exactly as the spec states.
    #[must_use]
    pub fn salt(&self, index: u64) -> Option<Salt16> {
        if index >= self.leaf_count {
            return None;
        }
        // `index < n <= 2^d`, so the leaf address is always in range and the
        // walk below is the whole derivation.
        let seed = self.derive_along(PathBits {
            index,
            remaining: self.depth,
        });
        // C23: the truncation buffer is a copy of secret salt bytes that we
        // own and `[u8; N]` has no `Drop`, so it is wiped explicitly once the
        // value is inside the zeroizing newtype.
        let mut salt = [0u8; Salt16::LEN];
        salt.copy_from_slice(&seed.as_bytes()[..Salt16::LEN]);
        let wrapped = Salt16::from_bytes(salt);
        salt.zeroize();
        Some(wrapped)
    }

    /// Walk from `s_root` along a path. O(1) auxiliary state, no allocation;
    /// each intermediate [`Seed32`] wipes when the next replaces it.
    fn derive_along(&self, path: PathBits) -> Seed32 {
        let mut seed = Seed32::from_bytes(*self.s_root.as_bytes());
        for bit in path {
            seed = child_seed(&seed, bit);
        }
        seed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::TEST_MASTER_SECRET_W;
    // Property tests need the proptest-bearing `test-util` tier, which the
    // wasm32 `--lib` test build deliberately does not enable (P14,
    // docs/wasm-toolchain.md). Everything else in this module runs on both.
    #[cfg(feature = "test-util")]
    use crate::test_util::strategies::proptest_config;
    #[cfg(feature = "test-util")]
    use proptest::prelude::*;
    use sha2::{Digest, Sha256};

    /// Stand-in `s_root` for code-level vectors: the documented **non-secret**
    /// fixture byte pattern `0x00 0x01 … 0x1f` (`testdata/README.md`;
    /// project rule 6 — no real vault material in fixtures). The composed
    /// `HKDF(W, "fine-seed", file_id)` → salt vectors land as golden files in
    /// G15.
    fn kat_root() -> Seed32 {
        Seed32::from_bytes(TEST_MASTER_SECRET_W)
    }

    /// A second, unrelated root, so the KATs prove seed-dependence rather than
    /// just self-consistency.
    fn other_root() -> Seed32 {
        let mut bytes = [0u8; 32];
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = 0xF0 ^ u8::try_from(i).unwrap_or(0);
        }
        Seed32::from_bytes(bytes)
    }

    /// **Independent** reference implementation: raw SHA-256 over a manually
    /// concatenated `0x06 ‖ seed ‖ b` preimage, walking the bits of `index`
    /// MSB-first. Shares no code with the implementation under test.
    fn reference_leaf_seed(s_root: &[u8; 32], depth: u8, index: u64) -> [u8; 32] {
        let mut seed = *s_root;
        for step in (0..depth).rev() {
            let bit = u8::try_from((index >> step) & 1).unwrap_or(0);
            let mut preimage = Vec::with_capacity(34);
            preimage.push(0x06);
            preimage.extend_from_slice(&seed);
            preimage.push(bit);
            seed = Sha256::digest(&preimage).into();
        }
        seed
    }

    fn reference_salt(s_root: &[u8; 32], depth: u8, index: u64) -> [u8; 16] {
        let seed = reference_leaf_seed(s_root, depth, index);
        let mut salt = [0u8; 16];
        salt.copy_from_slice(&seed[..16]);
        salt
    }

    fn salt_bytes(tree: &SaltTree<'_>, index: u64) -> [u8; 16] {
        *tree.salt(index).expect("leaf must be in range").as_bytes()
    }

    // ── Depth ───────────────────────────────────────────────────────────

    /// `d = ceil(log2 n)`, with the spec's two edge cases pinned
    /// (MVP-SPEC.md lines 78, 96).
    #[test]
    fn depth_matches_ceil_log2() {
        assert_eq!(depth_for_leaf_count(0), None, "empty file has no tree");
        assert_eq!(depth_for_leaf_count(1), Some(0), "n = 1 → d = 0");
        for (n, d) in [
            (2u64, 1u8),
            (3, 2),
            (4, 2),
            (5, 3),
            (6, 3),
            (7, 3),
            (8, 3),
            (9, 4),
            (1_000_000, 20),
            (1 << 40, 40),
            ((1 << 40) + 1, 41),
        ] {
            assert_eq!(depth_for_leaf_count(n), Some(d), "n = {n}");
        }
        // The saturating corner: a hostile `size` field still yields d <= 64.
        assert_eq!(depth_for_leaf_count(1u64 << 63), Some(63));
        assert_eq!(depth_for_leaf_count((1u64 << 63) + 1), Some(64));
        assert_eq!(depth_for_leaf_count(u64::MAX), Some(64));
    }

    // ── MSB-first indexing (G8 accept) ──────────────────────────────────

    /// G8 accept, MSB-first pinned: at `n = 6` (`d = 3`) leaf 2's path is
    /// bits **(0, 1, 0)** — asserted explicitly, both as path bits and as the
    /// derivation actually performed. LSB-first would give (0, 1, 0) reversed,
    /// i.e. leaf 2 and leaf 4 would swap salts; this test is the guard.
    #[test]
    fn leaf_path_is_msb_first() {
        let depth = depth_for_leaf_count(6).expect("n = 6 has a tree");
        assert_eq!(depth, 3);

        let leaf2 = NodeAddress::leaf(depth, 2).expect("leaf 2 is addressable");
        let bits: Vec<ChildBit> = leaf2.path_bits().collect();
        assert_eq!(
            bits,
            vec![ChildBit::Left, ChildBit::Right, ChildBit::Left],
            "leaf 2 at d = 3 must be reached by bits (0, 1, 0), MSB-first"
        );
        assert_eq!(
            bits.iter().map(|b| b.as_byte()).collect::<Vec<u8>>(),
            vec![0, 1, 0]
        );

        // The derivation follows exactly that path: root → 0 → 1 → 0.
        let root = kat_root();
        let step1 = child_seed(&root, ChildBit::Left);
        let step2 = child_seed(&step1, ChildBit::Right);
        let step3 = child_seed(&step2, ChildBit::Left);
        let mut expected = [0u8; 16];
        expected.copy_from_slice(&step3.as_bytes()[..16]);

        let tree = SaltTree::new(&root, 6).expect("n = 6 has a tree");
        assert_eq!(salt_bytes(&tree, 2), expected);

        // And leaf 4 — bits (1, 0, 0) — is a *different* salt, which is what
        // an LSB-first implementation would get wrong.
        let leaf4 = NodeAddress::leaf(depth, 4).expect("leaf 4 is addressable");
        assert_eq!(
            leaf4.path_bits().map(|b| b.as_byte()).collect::<Vec<u8>>(),
            vec![1, 0, 0]
        );
        assert_ne!(salt_bytes(&tree, 4), expected);
    }

    /// The index's bits *are* the path: descending from the root by an
    /// address's path bits reconstructs that address (the D9 key property).
    #[test]
    fn path_bits_reconstruct_the_address() {
        for (level, index) in [(0u8, 0u64), (1, 1), (3, 5), (7, 100), (10, 1023)] {
            let address = NodeAddress::try_new(level, index).expect("in range");
            let mut walked = NodeAddress::root();
            for bit in address.path_bits() {
                walked = walked.child(bit).expect("stays within MAX_LEVEL");
            }
            assert_eq!(walked, address, "level {level}, index {index}");
        }
    }

    // ── Known-answer vectors (G8 accept) ────────────────────────────────

    /// G8 accept: KATs against the independent reference, including the
    /// `n = 1` case where `salt_0 = s_root[..16]` with no derivation at all.
    #[test]
    fn salt_kats_match_the_independent_reference() {
        let root = kat_root();
        let root_bytes = *root.as_bytes();

        // n = 1, d = 0: the leaf is the root.
        let tree1 = SaltTree::new(&root, 1).expect("n = 1 has a tree");
        assert_eq!(tree1.depth(), 0);
        assert_eq!(tree1.slot_count(), 1);
        let mut expected_first16 = [0u8; 16];
        expected_first16.copy_from_slice(&root_bytes[..16]);
        assert_eq!(
            salt_bytes(&tree1, 0),
            expected_first16,
            "n = 1 → salt_0 = s_root[..16] (MVP-SPEC.md line 96)"
        );
        assert_eq!(salt_bytes(&tree1, 0), reference_salt(&root_bytes, 0, 0));

        // Several shapes, every used leaf, both roots.
        for n in [1u64, 2, 3, 4, 5, 6, 7, 8, 9, 16, 17] {
            let depth = depth_for_leaf_count(n).expect("n >= 1");
            for seed in [kat_root(), other_root()] {
                let seed_bytes = *seed.as_bytes();
                let tree = SaltTree::new(&seed, n).expect("n >= 1");
                assert_eq!(tree.depth(), depth);
                for i in 0..n {
                    assert_eq!(
                        salt_bytes(&tree, i),
                        reference_salt(&seed_bytes, depth, i),
                        "n = {n}, leaf = {i}"
                    );
                }
            }
        }
    }

    /// G8 accept: pinned code-level vectors — the exact salt bytes this
    /// construction must produce forever, from the documented fixture root.
    /// A change to the domain tag, the truncation, the bit order, or the
    /// preimage layout breaks these.
    #[test]
    fn pinned_salt_vectors() {
        let root = kat_root();

        // n = 1 (d = 0): salt_0 = s_root[..16] = 0x00..0x0f.
        let tree1 = SaltTree::new(&root, 1).expect("n = 1");
        assert_eq!(
            salt_bytes(&tree1, 0),
            [
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
                0x0E, 0x0F,
            ]
        );

        // n = 2 (d = 1): one derivation step each.
        let tree2 = SaltTree::new(&root, 2).expect("n = 2");
        assert_eq!(salt_bytes(&tree2, 0), PINNED_N2_LEAF0);
        assert_eq!(salt_bytes(&tree2, 1), PINNED_N2_LEAF1);

        // n = 6 (d = 3): the MSB-first witness tree.
        let tree6 = SaltTree::new(&root, 6).expect("n = 6");
        assert_eq!(salt_bytes(&tree6, 0), PINNED_N6_LEAF0);
        assert_eq!(salt_bytes(&tree6, 2), PINNED_N6_LEAF2);
        assert_eq!(salt_bytes(&tree6, 5), PINNED_N6_LEAF5);

        // The single child derivation, pinned on its own.
        assert_eq!(
            child_seed(&root, ChildBit::Left).as_bytes(),
            &PINNED_CHILD_LEFT
        );
        assert_eq!(
            child_seed(&root, ChildBit::Right).as_bytes(),
            &PINNED_CHILD_RIGHT
        );
    }

    /// `child(s_root, 0)` — one left step from the fixture root.
    const PINNED_CHILD_LEFT: [u8; 32] = [
        0xBF, 0x8A, 0xFD, 0x0F, 0x27, 0x6A, 0xCE, 0x32, 0x0D, 0x56, 0xD9, 0x20, 0x83, 0x1A, 0xB4,
        0xE0, 0x6A, 0xB9, 0xDA, 0x67, 0x6A, 0x43, 0x6C, 0xF5, 0xB2, 0xA8, 0x04, 0x7F, 0x0F, 0xF0,
        0xBD, 0x80,
    ];
    /// `child(s_root, 1)` — one right step from the fixture root.
    const PINNED_CHILD_RIGHT: [u8; 32] = [
        0xFE, 0x41, 0x6D, 0x68, 0xCF, 0x8C, 0x6C, 0xF5, 0xD1, 0xFF, 0x75, 0xB5, 0x17, 0x29, 0x7F,
        0x0B, 0xFB, 0x52, 0x1A, 0x8A, 0x9F, 0x4D, 0x05, 0x2C, 0xD1, 0x02, 0xE8, 0x89, 0x35, 0x72,
        0x6F, 0x8B,
    ];
    /// `n = 2`, leaf 0 — path (0).
    const PINNED_N2_LEAF0: [u8; 16] = [
        0xBF, 0x8A, 0xFD, 0x0F, 0x27, 0x6A, 0xCE, 0x32, 0x0D, 0x56, 0xD9, 0x20, 0x83, 0x1A, 0xB4,
        0xE0,
    ];
    /// `n = 2`, leaf 1 — path (1).
    const PINNED_N2_LEAF1: [u8; 16] = [
        0xFE, 0x41, 0x6D, 0x68, 0xCF, 0x8C, 0x6C, 0xF5, 0xD1, 0xFF, 0x75, 0xB5, 0x17, 0x29, 0x7F,
        0x0B,
    ];
    /// `n = 6` (`d = 3`), leaf 0 — path (0, 0, 0).
    const PINNED_N6_LEAF0: [u8; 16] = [
        0x1F, 0xBF, 0xBB, 0xE4, 0x66, 0x10, 0x09, 0xAD, 0xF2, 0x5C, 0x72, 0x1B, 0xCA, 0x7C, 0x25,
        0x66,
    ];
    /// `n = 6` (`d = 3`), leaf 2 — path (0, 1, 0), the MSB-first witness.
    const PINNED_N6_LEAF2: [u8; 16] = [
        0x1C, 0x50, 0x0C, 0x69, 0xD4, 0xC9, 0xAC, 0x7C, 0x3C, 0x39, 0xE2, 0xB8, 0x20, 0x93, 0x5A,
        0x89,
    ];
    /// `n = 6` (`d = 3`), leaf 5 — path (1, 0, 1).
    const PINNED_N6_LEAF5: [u8; 16] = [
        0xBC, 0xEB, 0x28, 0x57, 0x2F, 0x7E, 0xAC, 0xD7, 0x5A, 0x3E, 0xFB, 0x8F, 0x13, 0x1E, 0x2C,
        0x7F,
    ];

    // ── Unused slots are never derived (G8 accept) ──────────────────────

    /// Slots `i >= n` are unused: `salt` refuses them and `seed_at` refuses any
    /// node covering only unused slots (MVP-SPEC.md line 96).
    #[test]
    fn unused_slots_are_not_derivable() {
        let root = kat_root();
        let tree = SaltTree::new(&root, 6).expect("n = 6"); // d = 3, slots 6, 7 unused

        assert!(tree.salt(5).is_some());
        assert!(tree.salt(6).is_none(), "slot 6 >= n is unused");
        assert!(tree.salt(7).is_none());
        assert!(tree.salt(u64::MAX).is_none());

        // Leaf slots 6 and 7 are addressable (a verifier must be able to name
        // them) but not derivable.
        let unused_leaf = tree.leaf_address(6).expect("addressable");
        // `Seed32` has no `PartialEq` by design (uncontrolled comparison of
        // secret material), so error assertions go through `.err()`.
        assert_eq!(
            tree.seed_at(unused_leaf).err(),
            Some(ContentError::UnusedGgmSlot {
                first_slot: 6,
                leaf_count: 6
            })
        );
        // The interior node over slots [6, 8) is wholly unused too.
        let unused_interior = NodeAddress::try_new(2, 3).expect("in range");
        assert_eq!(unused_interior.first_slot(3), Ok(6));
        assert!(matches!(
            tree.seed_at(unused_interior),
            Err(ContentError::UnusedGgmSlot { .. })
        ));
        // A node straddling the boundary covers real leaves and IS derivable
        // (a range cover legitimately needs it).
        let straddling = NodeAddress::try_new(2, 2).expect("in range");
        assert_eq!(straddling.first_slot(3), Ok(4));
        assert!(tree.seed_at(straddling).is_ok());
    }

    /// `seed_at` rejects a level below this tree's depth with its own distinct
    /// error.
    #[test]
    fn addresses_below_the_tree_depth_are_rejected() {
        let root = kat_root();
        let tree = SaltTree::new(&root, 4).expect("n = 4"); // d = 2
        let too_deep = NodeAddress::try_new(3, 0).expect("representable");
        assert_eq!(
            tree.seed_at(too_deep).err(),
            Some(ContentError::NodeAddressLevelExceedsDepth { level: 3, depth: 2 })
        );
        assert_eq!(
            too_deep.first_slot(2),
            Err(ContentError::NodeAddressLevelExceedsDepth { level: 3, depth: 2 })
        );
        assert_eq!(
            too_deep.slot_width(2),
            Err(ContentError::NodeAddressLevelExceedsDepth { level: 3, depth: 2 })
        );
    }

    /// Address construction rejects out-of-range values with distinct errors,
    /// and never panics on hostile inputs (project principle 2).
    #[test]
    fn node_address_construction_is_checked() {
        assert_eq!(
            NodeAddress::try_new(65, 0),
            Err(ContentError::NodeAddressLevelTooDeep { level: 65, max: 64 })
        );
        assert_eq!(
            NodeAddress::try_new(u8::MAX, 0),
            Err(ContentError::NodeAddressLevelTooDeep {
                level: u8::MAX,
                max: 64
            })
        );
        assert_eq!(
            NodeAddress::try_new(3, 8),
            Err(ContentError::NodeAddressIndexOutOfRange { level: 3, index: 8 })
        );
        assert_eq!(
            NodeAddress::try_new(0, 1),
            Err(ContentError::NodeAddressIndexOutOfRange { level: 0, index: 1 })
        );
        // In range, including both extremes of the level-64 row.
        assert!(NodeAddress::try_new(3, 7).is_ok());
        assert!(NodeAddress::try_new(64, u64::MAX).is_ok());
        assert!(NodeAddress::try_new(63, (1u64 << 63) - 1).is_ok());
        assert_eq!(
            NodeAddress::try_new(63, 1u64 << 63),
            Err(ContentError::NodeAddressIndexOutOfRange {
                level: 63,
                index: 1u64 << 63
            })
        );
        // `child` cannot walk past the maximum level.
        let deepest = NodeAddress::try_new(64, 0).expect("in range");
        assert_eq!(
            deepest.child(ChildBit::Left),
            Err(ContentError::NodeAddressLevelTooDeep { level: 65, max: 64 })
        );
    }

    /// Slot geometry, including the depth-64 corner where the width does not
    /// fit a `u64` (panic-freedom on hostile `size` values).
    #[test]
    fn slot_geometry_is_panic_free_at_the_extremes() {
        let root = NodeAddress::root();
        assert_eq!(root.first_slot(64), Ok(0));
        assert_eq!(root.slot_width(64), Ok(1u128 << 64));
        assert_eq!(root.covers_slot(64, u64::MAX), Ok(true));
        assert_eq!(root.slot_width(0), Ok(1));

        let node = NodeAddress::try_new(2, 3).expect("in range");
        assert_eq!(node.first_slot(4), Ok(12));
        assert_eq!(node.slot_width(4), Ok(4));
        assert_eq!(node.covers_slot(4, 11), Ok(false));
        assert_eq!(node.covers_slot(4, 12), Ok(true));
        assert_eq!(node.covers_slot(4, 15), Ok(true));
        assert_eq!(node.covers_slot(4, 16), Ok(false));

        // A huge tree derives in O(d) — no allocation proportional to n.
        let seed = kat_root();
        let huge = SaltTree::new(&seed, u64::MAX).expect("n > 0");
        assert_eq!(huge.depth(), 64);
        assert_eq!(huge.slot_count(), 1u128 << 64);
        assert!(huge.salt(u64::MAX - 1).is_some());
        assert!(huge.salt(0).is_some());
    }

    /// Project rule 6: nothing in `SaltTree`'s `Debug` reveals seed bytes.
    #[test]
    fn debug_never_reveals_seed_bytes() {
        let root = kat_root();
        let tree = SaltTree::new(&root, 6).expect("n = 6");
        let rendered = format!("{tree:?}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
        assert!(rendered.contains("leaf_count: 6"), "{rendered}");
        // No byte of the root leaks (0x1f is its most distinctive tail byte).
        assert!(!rendered.contains("31"), "{rendered}");
        assert!(!rendered.contains("1f"), "{rendered}");
    }

    // ── Property tests (G8 accept) ──────────────────────────────────────

    #[cfg(feature = "test-util")]
    proptest! {
        #![proptest_config(proptest_config(0x0064_0008))]

        /// Leaf salts are pairwise distinct within a tree (small `n`), so no
        /// two bytes ever share a salt.
        #[test]
        fn leaf_salts_are_pairwise_distinct(n in 1u64..=48, root_byte in any::<u8>()) {
            let root = Seed32::from_bytes([root_byte; 32]);
            let tree = SaltTree::new(&root, n).expect("n >= 1");
            let salts: std::collections::BTreeSet<[u8; 16]> =
                (0..n).map(|i| salt_bytes(&tree, i)).collect();
            prop_assert_eq!(salts.len(), usize::try_from(n).unwrap_or(usize::MAX));
        }

        /// Sibling children of any seed differ (the `b` byte actually
        /// separates the two derivations).
        #[test]
        fn sibling_children_differ(seed_bytes in any::<[u8; 32]>()) {
            let seed = Seed32::from_bytes(seed_bytes);
            let left = child_seed(&seed, ChildBit::Left);
            let right = child_seed(&seed, ChildBit::Right);
            prop_assert_ne!(left.as_bytes(), right.as_bytes());
            // And neither equals the parent.
            prop_assert_ne!(left.as_bytes(), &seed_bytes);
            prop_assert_ne!(right.as_bytes(), &seed_bytes);
        }

        /// Re-derivation is deterministic: the same tree and index always give
        /// the same salt, and a fresh tree over the same root agrees.
        #[test]
        fn derivation_is_deterministic(
            n in 1u64..=64,
            index in 0u64..64,
            root_bytes in any::<[u8; 32]>(),
        ) {
            let index = index % n;
            let root = Seed32::from_bytes(root_bytes);
            let tree = SaltTree::new(&root, n).expect("n >= 1");
            let once = salt_bytes(&tree, index);
            prop_assert_eq!(salt_bytes(&tree, index), once);

            let root_again = Seed32::from_bytes(root_bytes);
            let tree_again = SaltTree::new(&root_again, n).expect("n >= 1");
            prop_assert_eq!(salt_bytes(&tree_again, index), once);
        }

        /// Equivalence with the independent reference over arbitrary shapes.
        #[test]
        fn matches_reference_implementation(
            n in 1u64..=100,
            index in 0u64..100,
            root_bytes in any::<[u8; 32]>(),
        ) {
            let index = index % n;
            let depth = depth_for_leaf_count(n).expect("n >= 1");
            let root = Seed32::from_bytes(root_bytes);
            let tree = SaltTree::new(&root, n).expect("n >= 1");
            prop_assert_eq!(
                salt_bytes(&tree, index),
                reference_salt(&root_bytes, depth, index)
            );
        }

        /// Different roots give different salts (the tree is seed-dependent
        /// everywhere, not just at the root).
        #[test]
        fn distinct_roots_give_distinct_salts(
            a in any::<[u8; 32]>(),
            b in any::<[u8; 32]>(),
            n in 1u64..=32,
        ) {
            prop_assume!(a != b);
            let root_a = Seed32::from_bytes(a);
            let root_b = Seed32::from_bytes(b);
            let tree_a = SaltTree::new(&root_a, n).expect("n >= 1");
            let tree_b = SaltTree::new(&root_b, n).expect("n >= 1");
            for i in 0..n {
                prop_assert_ne!(salt_bytes(&tree_a, i), salt_bytes(&tree_b, i));
            }
        }

        /// Address arithmetic never panics and stays self-consistent for any
        /// (level, index, depth) triple a hostile bundle could name.
        #[test]
        fn address_arithmetic_is_total(
            level in 0u8..=70,
            index in any::<u64>(),
            depth in 0u8..=64,
        ) {
            match NodeAddress::try_new(level, index) {
                Err(_) => {
                    // Rejected inputs simply have no geometry — nothing panics.
                }
                Ok(address) => {
                    prop_assert_eq!(address.level(), level);
                    prop_assert_eq!(address.path_bits().count(), usize::from(level));
                    match address.first_slot(depth) {
                        Err(_) => prop_assert!(level > depth),
                        Ok(first) => {
                            let width = address.slot_width(depth).expect("same precondition");
                            prop_assert!(u128::from(first) + width <= (1u128 << depth));
                            prop_assert_eq!(address.covers_slot(depth, first), Ok(true));
                        }
                    }
                }
            }
        }
    }
}
