//! Range-proof generation (tasks/G.md G12; MVP-SPEC.md lines 96, 114).
//!
//! # What a range proof carries
//!
//! Opening leaves `[a, b)` of a fine-tree file against `fine_root` needs two
//! things beyond the revealed bytes themselves (line 114):
//!
//! 1. the **leaf-exact GGM sub-cover** of `[a, b)` — the seeds from which the
//!    verifier derives `salt_a … salt_{b−1}` and nothing else (G11);
//! 2. the **boundary Merkle paths** — the hashes of the maximal subtrees that
//!    lie entirely outside `[a, b)`, which the verifier folds together with
//!    the leaves it rebuilt to reach `fine_root`.
//!
//! [`RangeProof`] is exactly those two lists plus the claimed range. The
//! revealed bytes travel alongside it, per F/R's bundle layout; nothing here
//! encodes anything (F owns the CBOR spelling —
//! `docs/format/registry-v1.md` §5/§7.11).
//!
//! # One machinery, two entry points
//!
//! A per-unit reveal **is** a leaf-aligned range opening: unit boundaries are
//! byte offsets and fine-tree leaves are bytes, so [`prove_unit`] maps the
//! unit's byte-range to a leaf range and calls [`prove_range`]. There is no
//! second code path and no special casing — which is what makes it impossible
//! for a per-unit reveal and a byte-range reveal of the same span to disagree
//! (line 96's single-authoritative-commitment rule).
//!
//! # How the boundary path is computed
//!
//! One post-order walk of the content tree, from `[0, n)` down:
//!
//! ```text
//! walk(s, e):
//!   if [s, e) is disjoint from [a, b):   hash the subtree, RECORD it, return
//!   if e − s == 1:                       return the leaf (its byte is revealed)
//!   k = rfc6962_split(e − s)
//!   return node(walk(s, s+k), walk(s+k, e))
//! ```
//!
//! Recording happens at the *first* disjoint node encountered, so the
//! recorded set is the **maximal** disjoint decomposition — `O(log n)`
//! hashes, ascending by first leaf, exactly the set a verifier recomputes
//! from `(range, n)` alone. Because a node whose interval meets `[a, b)` has
//! at most one disjoint child, at most one hash is recorded per level of each
//! fringe.
//!
//! Leaves are consumed in strictly increasing index order by both the
//! recording walk and the plain subtree hashing it delegates to, so a single
//! [`GgmWalker`](super::ggm_walk) supplies every salt in amortized O(1) —
//! auxiliary memory stays `O(log n)` even though the prover necessarily
//! touches all `n` bytes.
//!
//! # Node addressing on the content tree
//!
//! Cover nodes live on the GGM dyadic grid and address naturally (D9). A
//! *content*-tree node can span a truncated interval — at `n = 7` the node
//! over leaves `[4, 7)` is not a dyadic block — so its canonical address is
//! the **deepest grid slot whose real span equals the node's leaf interval**
//! (`docs/format/registry-v1.md` §5, "Canonical slot for content-tree
//! (boundary-path) nodes"): `[4, 7)` at `n = 7` is `(1, 1)`, whose slot span
//! `[4, 8)` truncates to `[4, 7)`. [`canonical_slot`] is that rule.

use crate::content::descriptor::CanonDescriptor;
use crate::content::ggm::NodeAddress;
use crate::content::unit::{ByteRange, Unit, is_fine_tree_covered};
use crate::crypto::material::{NodeHash32, Seed32};

use super::build::{leaf_hash, node_hash, rfc6962_split};
use super::cover::{CoverEntry, cover_seeds, minimal_cover};
use super::error::FineTreeError;
use super::ggm_walk::GgmWalker;

/// One boundary Merkle sibling: a content-tree node lying entirely outside
/// the revealed range, with the hash a verifier folds in instead of
/// recomputing it (MVP-SPEC.md lines 114, 121).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BoundaryNode {
    address: NodeAddress,
    hash: NodeHash32,
}

impl BoundaryNode {
    /// The node's canonical grid address (module docs; registry §5).
    #[must_use]
    pub const fn address(self) -> NodeAddress {
        self.address
    }

    /// The 32-byte subtree hash (MVP-SPEC.md line 121 length rule).
    #[must_use]
    pub const fn hash(&self) -> &NodeHash32 {
        &self.hash
    }
}

/// A wire-shaped proof node: an address plus a byte string of **unchecked**
/// length — the shape F's strict CBOR decoder yields for both `cover_entry`
/// and `path_node` (`docs/format/registry-v1.md` §5).
///
/// The length check is G13's
/// ([`FineTreeError::BadSeedLength`]/[`BadNodeHashLength`]), which is why
/// this type deliberately does *not* hold a `Seed32`/`NodeHash32`: a decoded
/// bundle has no such guarantee yet, and pretending otherwise would move the
/// spec's length rule (line 121) out of the verifier.
///
/// [`BadNodeHashLength`]: FineTreeError::BadNodeHashLength
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WireNode<'a> {
    /// Grid level (root = 0).
    pub level: u8,
    /// Position within the level; its `level` bits MSB-first are the path.
    pub index: u64,
    /// The seed or node hash — 32 bytes when honest, anything when not.
    pub bytes: &'a [u8],
}

/// A leaf-range opening against `fine_root` (MVP-SPEC.md line 114).
///
/// Produced by [`prove_range`]/[`prove_unit`]; carries exactly what a bundle
/// ships for one covered reveal, in the canonical order a verifier
/// recomputes. The revealed bytes are **not** part of it — they travel
/// separately per F/R's bundle layout — so the struct stays the same shape
/// for a 1-byte and a 1-GiB reveal.
#[derive(Debug)]
pub struct RangeProof {
    range: ByteRange,
    leaf_count: u64,
    depth: u8,
    cover: Vec<CoverEntry>,
    boundary: Vec<BoundaryNode>,
}

impl RangeProof {
    /// The claimed leaf range `[start, start + length)`.
    #[must_use]
    pub const fn range(&self) -> ByteRange {
        self.range
    }

    /// The file's leaf count `n` this proof was built against.
    #[must_use]
    pub const fn leaf_count(&self) -> u64 {
        self.leaf_count
    }

    /// The GGM tree depth `d = ceil(log2 n)`.
    #[must_use]
    pub const fn depth(&self) -> u8 {
        self.depth
    }

    /// The leaf-exact GGM sub-cover, ascending by first leaf.
    #[must_use]
    pub fn cover(&self) -> &[CoverEntry] {
        &self.cover
    }

    /// The boundary Merkle siblings, ascending by first leaf.
    #[must_use]
    pub fn boundary(&self) -> &[BoundaryNode] {
        &self.boundary
    }

    /// The cover as wire nodes — the shape [`verify_range`] consumes, so a
    /// freshly generated proof and a decoded bundle travel the *identical*
    /// verification path.
    ///
    /// [`verify_range`]: super::verify::verify_range
    #[must_use]
    pub fn wire_cover(&self) -> Vec<WireNode<'_>> {
        self.cover
            .iter()
            .map(|entry| WireNode {
                level: entry.node().address().level(),
                index: entry.node().address().index(),
                bytes: entry.seed().as_bytes(),
            })
            .collect()
    }

    /// The boundary path as wire nodes (see [`Self::wire_cover`]).
    #[must_use]
    pub fn wire_boundary(&self) -> Vec<WireNode<'_>> {
        self.boundary
            .iter()
            .map(|node| WireNode {
                level: node.address().level(),
                index: node.address().index(),
                bytes: node.hash().as_bytes(),
            })
            .collect()
    }
}

/// A unit whose content is bound **solely** by `fine_root` — the only kind of
/// unit [`prove_unit`] will open (MVP-SPEC.md line 94).
///
/// Obtainable only through [`Self::of`], which consults G5's
/// [`is_fine_tree_covered`] predicate, so "produce a range proof for a
/// `--no-fine-tree` whole-file unit or a raw-mirror unit" — neither of which
/// the canonical fine tree covers — is not a call that can be written. Those
/// units open against their own `unit_commit` instead; the two modes are
/// mutually exclusive by the same spec rule. Same shape as G5's
/// [`SplitEligibleText`](crate::content::SplitEligibleText).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoveredUnit(ByteRange);

impl CoveredUnit {
    /// The unit's leaf range, or `None` when the unit is not fine-tree
    /// covered.
    #[must_use]
    pub fn of(unit: &Unit, descriptor: &CanonDescriptor) -> Option<Self> {
        is_fine_tree_covered(unit, descriptor).then(|| Self(unit.byte_range()))
    }

    /// The unit's byte range — leaf-aligned by construction, since unit
    /// boundaries are byte offsets and fine-tree leaves are bytes
    /// (MVP-SPEC.md line 96).
    #[must_use]
    pub const fn leaf_range(self) -> ByteRange {
        self.0
    }
}

/// Build a range proof for `range` over `content` (MVP-SPEC.md lines 96, 114).
///
/// `content` is the file's whole byte-domain content — canonical bytes for
/// text, raw bytes for binary (G4's descriptor decides) — because the
/// boundary path commits the bytes *outside* the revealed range as much as
/// the cover commits the ones inside.
///
/// Auxiliary memory is `O(log n)`; the walk is `O(n)` hashes, which is
/// inherent (a prover must know the whole tree).
///
/// # Errors
///
/// - [`FineTreeError::ByteLenMismatch`] when `content.len() != leaf_count` —
///   the tree's shape and every salt depend on `n`, so a mismatched pair
///   would silently prove the wrong tree.
/// - [`FineTreeError::RangeOutOfBounds`] when the range is empty, overflows,
///   or leaves `[0, leaf_count)` (from [`minimal_cover`]).
/// - [`FineTreeError::WrongCoverShape`] is structurally unreachable here (it
///   would mean the walk produced a node with no canonical grid slot); it
///   exists so the function stays total rather than unwrapping.
pub fn prove_range(
    s_root: &Seed32,
    content: &[u8],
    range: ByteRange,
    leaf_count: u64,
) -> Result<RangeProof, FineTreeError> {
    let content_len = u64::try_from(content.len()).unwrap_or(u64::MAX);
    if content_len != leaf_count {
        return Err(FineTreeError::ByteLenMismatch {
            expected: leaf_count,
            got: content_len,
        });
    }

    // Validates the range and yields the leaf-exact cover in one step: the
    // proof cannot exist for a range the cover would refuse.
    let cover = minimal_cover(range, leaf_count)?;
    let depth = cover.depth();
    let range_end = range.end().ok_or(FineTreeError::RangeOutOfBounds {
        start: range.start(),
        length: range.length(),
        leaf_count,
    })?;

    let mut walk = ProofWalk {
        walker: GgmWalker::new(s_root, depth),
        content,
        leaf_count,
        depth,
        range_start: range.start(),
        range_end,
        boundary: Vec::new(),
    };
    walk.record(0, leaf_count)?;

    Ok(RangeProof {
        range,
        leaf_count,
        depth,
        cover: cover_seeds(s_root, &cover),
        boundary: walk.boundary,
    })
}

/// Build a range proof for one fine-tree-covered unit — **the same call**,
/// with the unit's byte range as the leaf range (MVP-SPEC.md line 96: "an
/// MVP per-unit reveal is just the special case where the range is a whole
/// unit").
///
/// # Errors
///
/// As [`prove_range`].
pub fn prove_unit(
    s_root: &Seed32,
    content: &[u8],
    unit: CoveredUnit,
    leaf_count: u64,
) -> Result<RangeProof, FineTreeError> {
    prove_range(s_root, content, unit.leaf_range(), leaf_count)
}

/// The canonical grid address of a content-tree node covering leaves
/// `[first, end)` (module docs; `docs/format/registry-v1.md` §5).
///
/// The **deepest** slot whose real span — its slot interval truncated at `n` —
/// equals `[first, end)`. Deepest matters: at `n = 7` the node over `[6, 7)`
/// is both `(3, 6)` and (by truncation) `(2, 3)`; only one of them may be on
/// the wire, so the canonical choice is the deeper.
///
/// `None` for an interval that is no content-tree node's span — structurally
/// unreachable from the walk, since every RFC 6962 subtree's leaf interval is
/// a dyadic block truncated at `n`.
#[must_use]
pub(crate) fn canonical_slot(
    first: u64,
    end: u64,
    leaf_count: u64,
    depth: u8,
) -> Option<NodeAddress> {
    let (first, end, leaf_count) = (u128::from(first), u128::from(end), u128::from(leaf_count));
    for level in (0..=depth).rev() {
        // `depth - level <= 64`, so the shift is in range for u128.
        let width = 1u128 << (depth - level);
        if first % width != 0 {
            continue;
        }
        if (first + width).min(leaf_count) != end {
            continue;
        }
        let index = u64::try_from(first / width).ok()?;
        return NodeAddress::try_new(level, index).ok();
    }
    None
}

/// Post-order walk of the content tree collecting the maximal subtrees
/// disjoint from the revealed range (module docs).
struct ProofWalk<'a> {
    walker: GgmWalker,
    content: &'a [u8],
    leaf_count: u64,
    depth: u8,
    range_start: u64,
    range_end: u64,
    boundary: Vec<BoundaryNode>,
}

impl ProofWalk<'_> {
    /// Hash leaf `index`, consuming the next salt from the shared walker.
    ///
    /// The walker and the walk agree because both proceed in strictly
    /// increasing leaf order; `index` is always `< leaf_count == content.len()`,
    /// so the `unwrap_or` is unreachable and exists only to stay panic-free.
    fn leaf(&mut self, index: u64) -> [u8; 32] {
        let salt = self.walker.next_salt();
        let byte = usize::try_from(index)
            .ok()
            .and_then(|i| self.content.get(i))
            .copied()
            .unwrap_or(0);
        leaf_hash(&salt, index, byte)
    }

    /// Plain RFC 6962 hash of the subtree over leaves `[first, end)`, with no
    /// recording. Recursion depth is bounded by `d + 1 <= 65`.
    fn subtree(&mut self, first: u64, end: u64) -> [u8; 32] {
        if end.saturating_sub(first) <= 1 {
            return self.leaf(first);
        }
        let split = rfc6962_split(end - first);
        let left = self.subtree(first, first + split);
        let right = self.subtree(first + split, end);
        node_hash(&left, &right)
    }

    /// As [`Self::subtree`], but recording the first node on each path that
    /// is wholly outside the revealed range.
    fn record(&mut self, first: u64, end: u64) -> Result<[u8; 32], FineTreeError> {
        if end <= self.range_start || first >= self.range_end {
            let hash = self.subtree(first, end);
            let address = canonical_slot(first, end, self.leaf_count, self.depth)
                .ok_or(FineTreeError::WrongCoverShape)?;
            self.boundary.push(BoundaryNode {
                address,
                hash: NodeHash32::from_bytes(hash),
            });
            return Ok(hash);
        }
        if end.saturating_sub(first) <= 1 {
            return Ok(self.leaf(first));
        }
        let split = rfc6962_split(end - first);
        let left = self.record(first, first + split)?;
        let right = self.record(first + split, end)?;
        Ok(node_hash(&left, &right))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canon::UnicodeVersion;
    use crate::content::descriptor::{ContentKind, FineTreeOptOut};
    use crate::content::ggm::depth_for_leaf_count;
    use crate::content::unit::{UnitKind, assign_unit_ids};
    use crate::content::{FileUnitPlan, rebuild_fine_root};
    use crate::test_util::TEST_MASTER_SECRET_W;
    use crate::test_util::strategies::proptest_config;
    use proptest::prelude::*;

    fn root_seed() -> Seed32 {
        Seed32::from_bytes(TEST_MASTER_SECRET_W)
    }

    /// Owned wire form of one node list: `(level, index, bytes)` per node.
    type OwnedNodes = Vec<(u8, u64, Vec<u8>)>;

    fn wire(proof: &RangeProof) -> (OwnedNodes, OwnedNodes) {
        let owned = |nodes: Vec<WireNode<'_>>| {
            nodes
                .into_iter()
                .map(|n| (n.level, n.index, n.bytes.to_vec()))
                .collect::<Vec<_>>()
        };
        (owned(proof.wire_cover()), owned(proof.wire_boundary()))
    }

    fn content_of(n: usize) -> Vec<u8> {
        (0..n).map(|i| u8::try_from(i % 251).unwrap_or(0)).collect()
    }

    // ── The walk reproduces the tree (G12 correctness anchor) ───────────

    /// The proof walk's own root equals G9's streaming construction — the
    /// two traversals (frontier vs recursive split) must agree or every
    /// boundary hash is meaningless.
    #[test]
    fn the_proof_walk_reproduces_the_streaming_root() {
        let seed = root_seed();
        for n in [1usize, 2, 3, 5, 6, 7, 8, 9, 17, 64, 100] {
            let content = content_of(n);
            let expected = rebuild_fine_root(&seed, &content).expect("n > 0");
            let leaf_count = u64::try_from(n).expect("small");
            let depth = depth_for_leaf_count(leaf_count).expect("n > 0");
            let mut walk = ProofWalk {
                walker: GgmWalker::new(&seed, depth),
                content: &content,
                leaf_count,
                depth,
                range_start: 0,
                range_end: leaf_count,
                boundary: Vec::new(),
            };
            let root = walk.record(0, leaf_count).expect("in bounds");
            assert_eq!(&root, expected.as_bytes(), "n = {n}");
            assert!(walk.boundary.is_empty(), "a full range has no siblings");
        }
    }

    // ── Canonical content-tree addressing (registry §5) ─────────────────

    /// The deepest-slot rule (`docs/format/registry-v1.md` §5), with both
    /// ambiguous cases pinned: at `n = 7` the node over `[6, 7)` is `(3, 6)`,
    /// not the equally-truncating `(2, 3)`; at `n = 6` the node over `[4, 6)`
    /// is `(2, 2)`, not `(1, 1)` — the registry's own worked example.
    ///
    /// Note the deliberate asymmetry with G11's **cover** rule, which emits
    /// `(1, 1)` for the same real span (see
    /// `boundary_addressing_deliberately_differs_from_cover_addressing`).
    #[test]
    fn content_tree_nodes_take_the_deepest_grid_slot() {
        // n = 7, d = 3.
        assert_eq!(canonical_slot(0, 4, 7, 3), NodeAddress::try_new(1, 0).ok());
        assert_eq!(canonical_slot(4, 7, 7, 3), NodeAddress::try_new(1, 1).ok());
        assert_eq!(canonical_slot(4, 6, 7, 3), NodeAddress::try_new(2, 2).ok());
        assert_eq!(canonical_slot(6, 7, 7, 3), NodeAddress::try_new(3, 6).ok());
        assert_ne!(canonical_slot(6, 7, 7, 3), NodeAddress::try_new(2, 3).ok());
        // n = 6, d = 3: the whole tree, and the ragged right subtree — the
        // registry's worked example, verbatim.
        assert_eq!(canonical_slot(0, 6, 6, 3), NodeAddress::try_new(0, 0).ok());
        assert_eq!(canonical_slot(4, 6, 6, 3), NodeAddress::try_new(2, 2).ok());
        // Not a node span at all.
        assert_eq!(canonical_slot(1, 3, 8, 3), None);
    }

    /// **The deliberate rule split, pinned so nobody "fixes" it by accident.**
    ///
    /// The real span `[4, 6)` at `n = 6` has two grid addresses — `(1, 1)`,
    /// whose slot interval `[4, 8)` truncates to it, and `(2, 2)`, whose slot
    /// interval *is* it. The two proof lists resolve the tie differently, on
    /// purpose:
    ///
    /// - a **cover** address names a GGM *seed*, and G11's minimal
    ///   decomposition emits the shallowest node whose real span fits the
    ///   revealed range — `(1, 1)`, exactly as tasks/G.md G11's accept bullet
    ///   requires ("the node spanning slots [4,8) … is emitted");
    /// - a **boundary** address names a content-subtree *hash*, whose
    ///   identity is its leaf interval alone, and
    ///   `docs/format/registry-v1.md` §5 fixes the deepest slot as that
    ///   interval's normal form — `(2, 2)`, the registry's own example.
    ///
    /// Nothing can be confused by this: cover nodes lie inside the revealed
    /// range and boundary nodes outside it, so no node ever appears in both
    /// lists, and each list is recomputed by the verifier under its own rule.
    /// It is nonetheless a **format-visible** asymmetry and is flagged for
    /// ratification with the registry at Q14.
    #[test]
    fn boundary_addressing_deliberately_differs_from_cover_addressing() {
        let cover = minimal_cover(ByteRange::new(4, 2), 6).expect("in bounds");
        assert_eq!(cover.nodes().len(), 1);
        assert_eq!(
            (
                cover.nodes()[0].address().level(),
                cover.nodes()[0].address().index()
            ),
            (1, 1),
            "G11 emits the shallow node — its seed is what gets disclosed"
        );

        let boundary = canonical_slot(4, 6, 6, 3).expect("a real content-node span");
        assert_eq!(
            (boundary.level(), boundary.index()),
            (2, 2),
            "registry §5 names the same span by its deepest slot"
        );
        assert_ne!(cover.nodes()[0].address(), boundary);
    }

    // ── Hand-checked proofs (G12 accept, and G15's future vectors) ──────

    /// `n = 6`, reveal `{2}`: cover = the deepest node for slot 2; boundary
    /// = leaf 3, the subtree over `[0, 2)`, and the subtree over `[4, 6)` —
    /// exactly the siblings on the path from leaf 2 to the root.
    #[test]
    fn n6_single_leaf_proof_has_the_expected_shape() {
        let seed = root_seed();
        let content = b"abcdef";
        let proof = prove_range(&seed, content, ByteRange::new(2, 1), 6).expect("in bounds");

        assert_eq!(
            proof
                .cover()
                .iter()
                .map(|e| (e.node().address().level(), e.node().address().index()))
                .collect::<Vec<_>>(),
            vec![(3, 2)]
        );
        assert_eq!(
            proof
                .boundary()
                .iter()
                .map(|b| (b.address().level(), b.address().index()))
                .collect::<Vec<_>>(),
            vec![(2, 0), (3, 3), (2, 2)],
            "siblings in post-order: [0,2), leaf 3, then [4,6) — the last \
             addressed by its deepest slot (2, 2) per registry §5"
        );
    }

    /// `n = 6`, full range: the cover is `s_root` alone and there are **no**
    /// boundary siblings — every leaf is revealed (MVP-SPEC.md line 114).
    #[test]
    fn full_range_proof_is_s_root_and_no_boundary() {
        let seed = root_seed();
        let proof = prove_range(&seed, b"abcdef", ByteRange::new(0, 6), 6).expect("in bounds");
        assert_eq!(proof.cover().len(), 1);
        assert_eq!(proof.cover()[0].node().address(), NodeAddress::root());
        assert_eq!(proof.cover()[0].seed().as_bytes(), seed.as_bytes());
        assert!(proof.boundary().is_empty());
    }

    /// `n = 6`, reveal `[4, 6)` — the ragged right edge: one cover node over
    /// slots `[4, 8)` and one boundary sibling, the perfect subtree `[0, 4)`.
    #[test]
    fn ragged_right_edge_proof_is_minimal() {
        let seed = root_seed();
        let proof = prove_range(&seed, b"abcdef", ByteRange::new(4, 2), 6).expect("in bounds");
        assert_eq!(proof.cover().len(), 1);
        assert_eq!(proof.cover()[0].node().address().level(), 1);
        assert_eq!(
            proof
                .boundary()
                .iter()
                .map(|b| (b.address().level(), b.address().index()))
                .collect::<Vec<_>>(),
            vec![(1, 0)]
        );
    }

    // ── prove_unit is prove_range (G12 accept) ──────────────────────────

    /// G12 accept: `prove_unit`'s output is byte-identical to `prove_range`
    /// over the same span — literally the same call, asserted on the wire
    /// form so nothing structural can differ either.
    #[test]
    fn prove_unit_is_byte_identical_to_prove_range() {
        let seed = root_seed();
        let content = content_of(40);
        let descriptor = CanonDescriptor::describe_file(
            ContentKind::Text(UnicodeVersion::CURRENT),
            40,
            FineTreeOptOut::NotRequested,
        );
        let units = assign_unit_ids(&[FileUnitPlan::split(
            crate::content::SplitEligibleText::of(&descriptor).expect("covered text file"),
            vec![
                ByteRange::new(0, 12),
                ByteRange::new(12, 9),
                ByteRange::new(21, 19),
            ],
        )]);

        for unit in &units {
            let covered = CoveredUnit::of(unit, &descriptor).expect("covered");
            let by_unit = prove_unit(&seed, &content, covered, 40).expect("in bounds");
            let by_range = prove_range(&seed, &content, unit.byte_range(), 40).expect("in bounds");
            assert_eq!(by_unit.range(), by_range.range());
            assert_eq!(wire(&by_unit), wire(&by_range), "unit {}", unit.unit_id());
        }
    }

    /// A unit the canonical fine tree does not cover cannot even be handed
    /// to `prove_unit`: the witness refuses to exist (spec lines 92, 94).
    #[test]
    fn non_covered_units_have_no_covered_unit_witness() {
        // Raw mirror: raw byte domain, never covered by the canonical tree.
        let text = CanonDescriptor::describe_file(
            ContentKind::Text(UnicodeVersion::CURRENT),
            40,
            FineTreeOptOut::NotRequested,
        );
        let units = assign_unit_ids(&[FileUnitPlan::whole_file(40).with_raw_mirror(46)]);
        let mirror = units
            .iter()
            .find(|u| u.kind() == UnitKind::RawMirror)
            .expect("mirror present");
        assert_eq!(CoveredUnit::of(mirror, &text), None);

        // --no-fine-tree whole-file unit: bound by unit_commit instead.
        let opted_out = CanonDescriptor::describe_file(
            ContentKind::Text(UnicodeVersion::CURRENT),
            40,
            FineTreeOptOut::Requested,
        );
        let whole = assign_unit_ids(&[FileUnitPlan::whole_file(40)]);
        assert_eq!(CoveredUnit::of(&whole[0], &opted_out), None);

        // The covered case is the one that does produce a witness.
        assert!(CoveredUnit::of(&whole[0], &text).is_some());
    }

    // ── Rejections ──────────────────────────────────────────────────────

    /// Content length and the declared leaf count must agree; degenerate
    /// ranges are refused by the cover before any hashing.
    #[test]
    fn mismatched_length_and_degenerate_ranges_are_rejected() {
        let seed = root_seed();
        assert_eq!(
            prove_range(&seed, b"abcdef", ByteRange::new(0, 6), 5).err(),
            Some(FineTreeError::ByteLenMismatch {
                expected: 5,
                got: 6
            })
        );
        for range in [
            ByteRange::new(0, 0),
            ByteRange::new(6, 1),
            ByteRange::new(0, 7),
            ByteRange::new(u64::MAX, 1),
        ] {
            assert!(matches!(
                prove_range(&seed, b"abcdef", range, 6),
                Err(FineTreeError::RangeOutOfBounds { .. })
            ));
        }
        // An empty file has no tree, so it has no openings either.
        assert!(matches!(
            prove_range(&seed, b"", ByteRange::new(0, 1), 0),
            Err(FineTreeError::RangeOutOfBounds { .. })
        ));
    }

    // ── Property tests (G12 accept) ─────────────────────────────────────

    proptest! {
        #![proptest_config(proptest_config(0x0064_0012))]

        /// G12 accept, proof-size bound: `<= max(1, 2d)` cover seeds and
        /// `O(log n)` boundary hashes, for every shape including the
        /// unbalanced right edge.
        #[test]
        fn proof_size_is_logarithmic(
            n in 1u64..=300,
            start in 0u64..300,
            length in 1u64..300,
        ) {
            let start = start % n;
            let length = length.min(n - start);
            let seed = Seed32::from_bytes([0x5A; 32]);
            let content: Vec<u8> = (0..n).map(|i| u8::try_from(i % 251).unwrap_or(0)).collect();
            let proof = prove_range(&seed, &content, ByteRange::new(start, length), n)
                .expect("constructed in bounds");

            let depth = u64::from(proof.depth());
            let cover_bound = usize::try_from((2 * depth).max(1)).unwrap_or(usize::MAX);
            let boundary_bound = usize::try_from(2 * (depth + 1)).unwrap_or(usize::MAX);
            prop_assert!(proof.cover().len() <= cover_bound);
            prop_assert!(proof.boundary().len() <= boundary_bound);
            // Every disclosed value has its exact spec length (line 121).
            for node in proof.wire_cover().iter().chain(proof.wire_boundary().iter()) {
                prop_assert_eq!(node.bytes.len(), 32);
            }
        }

        /// G12 accept: generated covers still satisfy G11's soundness
        /// property — the derivable real-leaf closure is exactly the
        /// revealed range, so no ancestor of an unrevealed leaf ships.
        #[test]
        fn generated_covers_stay_sound(
            n in 1u64..=200,
            start in 0u64..200,
            length in 1u64..200,
        ) {
            let start = start % n;
            let length = length.min(n - start);
            let seed = Seed32::from_bytes([0xC3; 32]);
            let content: Vec<u8> = (0..n).map(|i| u8::try_from(i % 251).unwrap_or(0)).collect();
            let proof = prove_range(&seed, &content, ByteRange::new(start, length), n)
                .expect("constructed in bounds");

            let mut cursor = start;
            for entry in proof.cover() {
                let node = entry.node();
                prop_assert_eq!(node.first_leaf(), cursor);
                cursor += node.leaf_len();
                // The node's REAL span must lie inside the revealed range.
                prop_assert!(node.first_leaf() >= start);
                prop_assert!(node.first_leaf() + node.leaf_len() <= start + length);
            }
            prop_assert_eq!(cursor, start + length);

            // s_root ships iff the whole file is revealed.
            let ships_root = proof
                .cover()
                .iter()
                .any(|e| e.node().address() == NodeAddress::root());
            prop_assert_eq!(ships_root, start == 0 && length == n);
        }

        /// Boundary nodes are disjoint from the revealed range, ascending,
        /// and each addressable — the shape a verifier recomputes.
        #[test]
        fn boundary_nodes_are_disjoint_ascending_and_addressable(
            n in 1u64..=200,
            start in 0u64..200,
            length in 1u64..200,
        ) {
            let start = start % n;
            let length = length.min(n - start);
            let end = start + length;
            let seed = Seed32::from_bytes([0x11; 32]);
            let content: Vec<u8> = (0..n).map(|i| u8::try_from(i % 251).unwrap_or(0)).collect();
            let proof = prove_range(&seed, &content, ByteRange::new(start, length), n)
                .expect("constructed in bounds");

            let depth = proof.depth();
            let mut previous: Option<u64> = None;
            for node in proof.boundary() {
                let first = node.address().first_slot(depth).expect("on the grid");
                let width = node.address().slot_width(depth).expect("on the grid");
                let real_end = u64::try_from(
                    (u128::from(first) + width).min(u128::from(n))
                ).unwrap_or(u64::MAX);
                prop_assert!(real_end <= start || first >= end, "boundary node overlaps the range");
                if let Some(previous) = previous {
                    prop_assert!(first > previous, "boundary nodes must ascend");
                }
                previous = Some(first);
            }

            // A full reveal has no boundary at all.
            prop_assert_eq!(
                proof.boundary().is_empty(),
                start == 0 && length == n
            );
        }

        /// Determinism: the same inputs always give a byte-identical proof.
        #[test]
        fn generation_is_deterministic(
            n in 1u64..=64,
            start in 0u64..64,
            length in 1u64..64,
            root_bytes in any::<[u8; 32]>(),
        ) {
            let start = start % n;
            let length = length.min(n - start);
            let seed = Seed32::from_bytes(root_bytes);
            let content: Vec<u8> = (0..n).map(|i| u8::try_from(i % 251).unwrap_or(0)).collect();
            let range = ByteRange::new(start, length);
            let a = prove_range(&seed, &content, range, n).expect("in bounds");
            let b = prove_range(&seed, &content, range, n).expect("in bounds");
            prop_assert_eq!(wire(&a), wire(&b));
        }
    }
}
