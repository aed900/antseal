//! Range-proof verification against `fine_root` (tasks/G.md G13;
//! MVP-SPEC.md lines 96, 118, 121).
//!
//! # The check
//!
//! [`verify_range`] answers one question — *do these bytes sit at these
//! positions of the file this `fine_root` commits?* — from a proof whose
//! every field is adversary-authored. The sealer is an adversary too
//! (line 121), and a bundle recipient may be handed a proof built to
//! disclose more than it should, so the function never trusts a value it can
//! recompute:
//!
//! 1. **the range** must be a non-empty sub-range of `[0, n)`;
//! 2. **the revealed byte count** must equal the range's width — a proof may
//!    not claim more span than it shows (line 121);
//! 3. **every disclosed seed and node hash** must be exactly 32 bytes
//!    (lines 96, 121);
//! 4. **no offered cover node may span an unrevealed real leaf** — the
//!    leaf-exact rule (line 96), including `s_root` offered for a partial
//!    range;
//! 5. **the offered cover and boundary path must equal the ones recomputed
//!    from `(range, n)`** — not merely be *a* valid decomposition;
//! 6. **every `level == d` disclosure must carry the canonical zero tail**
//!    `salt_i ‖ 0x00·16` (decision D83) — the one field whose upper half no
//!    hash reads, so a value rule is the only thing that keeps one proof to
//!    one encoding;
//! 7. only then are leaves rebuilt and folded, and the result compared to
//!    `fine_root`.
//!
//! The order is **frozen** and asserted
//! (`error_precedence_is_deterministic`): a proof with several faults always
//! reports the same one, so a tamper row can pin an exact code (line 168).
//!
//! # Why recompute the cover instead of validating it
//!
//! A merely-valid dyadic cover that happens to span an unrevealed real leaf
//! `j < n` hands the recipient `salt_j` and reopens the per-byte confirmation
//! attack the whole design exists to prevent (line 96). Checking "is this
//! cover valid?" would accept it. Recomputing the leaf-exact cover from
//! `(range, n)` — the same [`minimal_cover`] the prover ran — and requiring
//! equality makes the *canonical* proof the only acceptable one, and gives
//! the over-broad case its own permanent code
//! ([`FineTreeError::OverBroadCover`]) rather than folding it into a generic
//! mismatch.
//!
//! # Full reveals delegate to G9
//!
//! When the range is the whole file the cover is `s_root` itself and there is
//! no boundary path, so verification *is* the rebuild R performs on a full
//! file reveal: [`verify_range`] calls
//! [`rebuild_fine_root`](super::rebuild_fine_root) directly rather than
//! reimplementing it (line 121: "using the bundled `s_root`, the verifier
//! MUST rebuild the whole fine tree from those bytes and match `fine_root`").
//!
//! # Bounded work on hostile input
//!
//! `n` is a wire value and may claim `u64::MAX`. Nothing here is proportional
//! to it: the tree depth is `d = ceil(log2 n) <= 64`, the recursion descends
//! only into nodes that meet the revealed range — `O(d + revealed_len)` calls
//! at a stack depth of at most `d + 1` — and every disjoint subtree is
//! answered from the (length-bounded) boundary list instead of being walked.
//! Salt derivation is amortized O(1) per revealed byte with an `O(d)` seed
//! stack. So the cost of verifying a proof is bounded by the *proof*, never
//! by the file it claims to describe.

use crate::content::ggm::NodeAddress;
use crate::content::unit::ByteRange;
use crate::crypto::material::{Salt16, Seed32};

use super::build::{FineRoot, leaf_hash, node_hash, rebuild_fine_root, rfc6962_split};
use super::cover::{CoverNode, LeafExactCover, minimal_cover};
use super::error::FineTreeError;
use super::ggm_walk::GgmWalker;
use super::proof::{RangeProof, WireNode, canonical_slot};

/// Required length of every disclosed GGM seed and boundary node hash
/// (MVP-SPEC.md line 121).
const DISCLOSED_LEN: usize = 32;

/// Significant bytes of a disclosed GGM payload at `level == d` (decision
/// D83): a leaf-level node's payload is read as `salt_i = payload[..16]` with
/// no descent, so only its low 16 bytes are ever an input to a hash.
///
/// The remaining `32 − 16` bytes are the *canonical tail*
/// [`check_leaf_level_payload`] enforces. The length itself is unchanged and
/// still [`DISCLOSED_LEN`].
pub const LEAF_PAYLOAD_SIGNIFICANT_LEN: usize = Salt16::LEN;

/// Enforce D83's canonical tail on one disclosed, length-checked GGM payload.
///
/// A `level == d` cover node covers exactly one leaf slot, so the verifier
/// descends `d − level = 0` levels and takes `salt_i = payload[..16]`
/// directly (MVP-SPEC.md line 96). Bytes `16..32` are therefore never hashed,
/// and v1 fixes them at zero so that one proof has exactly one encoding:
///
/// ```text
/// payload = salt_i ‖ 0x00·16        (level == d only)
/// ```
///
/// A **no-op for `address.level() != depth`**: only a node at the grid's leaf
/// level has a tail the verifier never reads. At `depth == 0` (`n == 1`) the
/// grid root *is* the leaf, which is why the same predicate also governs
/// `full_reveal.s_root` (`docs/format/registry-v1.md` §7.14 key 2).
///
/// The comparison is a plain `!=` and deliberately **not** constant-time: the
/// payload is disclosed public material a bundle already publishes in the
/// clear, so there is no secret for a timing channel to leak.
///
/// # Errors
///
/// [`FineTreeError::LeafSeedTailNotZero`] when the node sits at `level == d`
/// and any of bytes `16..32` is non-zero.
///
/// ```
/// use antseal_core::content::fine_tree::verify::check_leaf_level_payload;
/// use antseal_core::content::NodeAddress;
///
/// // n = 1 (d = 0): the grid root is the single leaf, so its tail is fixed.
/// let mut payload = [0u8; 32];
/// payload[..16].copy_from_slice(&[0xA5; 16]);
/// assert!(check_leaf_level_payload(&payload, NodeAddress::root(), 0).is_ok());
///
/// payload[16] = 1;
/// assert!(check_leaf_level_payload(&payload, NodeAddress::root(), 0).is_err());
///
/// // …and at any shallower level the tail is the real seed, so it is free.
/// assert!(check_leaf_level_payload(&payload, NodeAddress::root(), 3).is_ok());
/// ```
pub fn check_leaf_level_payload(
    payload: &[u8; DISCLOSED_LEN],
    address: NodeAddress,
    depth: u8,
) -> Result<(), FineTreeError> {
    if address.level() != depth {
        return Ok(());
    }
    if payload[LEAF_PAYLOAD_SIGNIFICANT_LEN..]
        != [0u8; DISCLOSED_LEN - LEAF_PAYLOAD_SIGNIFICANT_LEN]
    {
        return Err(FineTreeError::LeafSeedTailNotZero {
            level: address.level(),
            index: address.index(),
        });
    }
    Ok(())
}

/// A decoded range proof exactly as it arrives from F's strict CBOR layer:
/// a claimed range plus two lists of `(level, index, bytes)` whose byte
/// lengths are **not** yet checked.
///
/// Deliberately a borrowed view rather than an owned struct — it is the
/// shape a decoder can hand over without copying, and the shape a tamper
/// test can mutate field by field.
#[derive(Debug, Clone, Copy)]
pub struct RangeProofView<'a> {
    /// The claimed leaf range `[start, start + length)`.
    pub range: ByteRange,
    /// The offered GGM sub-cover.
    pub cover: &'a [WireNode<'a>],
    /// The offered boundary Merkle path.
    pub boundary: &'a [WireNode<'a>],
}

impl RangeProof {
    /// Verify this proof against `fine_root` through the **same** entry point
    /// a decoded bundle takes ([`verify_range`]) — there is no prover-side
    /// shortcut that could pass where a bundle would fail.
    ///
    /// # Errors
    ///
    /// As [`verify_range`].
    pub fn verify(&self, revealed_bytes: &[u8], fine_root: &FineRoot) -> Result<(), FineTreeError> {
        let cover = self.wire_cover();
        let boundary = self.wire_boundary();
        verify_range(
            &RangeProofView {
                range: self.range(),
                cover: &cover,
                boundary: &boundary,
            },
            revealed_bytes,
            self.leaf_count(),
            fine_root,
        )
    }
}

/// Verify a leaf-range opening against `fine_root` (module docs;
/// MVP-SPEC.md lines 96, 118, 121).
///
/// `revealed_bytes` are the bytes of `proof.range` in the file's byte domain
/// — canonical bytes for text, raw bytes for binary (line 85) — as produced
/// by R's decrypt/padding-strip stages. `leaf_count` is the file table's
/// `size` field.
///
/// # Errors
///
/// In this frozen precedence — the first fault found is the one reported:
///
/// 1. [`FineTreeError::RangeOutOfBounds`] — empty/overflowing range, a range
///    outside `[0, leaf_count)`, or any range against a file with no fine
///    tree (`leaf_count == 0`).
/// 2. [`FineTreeError::ByteLenMismatch`] — `revealed_bytes.len()` is not the
///    range's width.
/// 3. [`FineTreeError::BadSeedLength`] — a cover seed is not 32 bytes.
/// 4. [`FineTreeError::BadNodeHashLength`] — a boundary hash is not 32 bytes.
/// 5. [`FineTreeError::OverBroadCover`] — an offered cover node spans a real
///    leaf outside the revealed range (`s_root` on a partial range included).
/// 6. [`FineTreeError::WrongCoverShape`] — the offered cover or boundary path
///    is not the recomputed canonical one (count, order, addressing, an
///    address off this tree's grid, or a node over only unused slots).
/// 7. [`FineTreeError::LeafSeedTailNotZero`] — a `level == d` cover payload's
///    upper 16 bytes are not zero (D83; see [`check_leaf_level_payload`]).
/// 8. [`FineTreeError::RootMismatch`] — everything is well formed but the
///    rebuilt root is not `fine_root`.
pub fn verify_range(
    proof: &RangeProofView<'_>,
    revealed_bytes: &[u8],
    leaf_count: u64,
    fine_root: &FineRoot,
) -> Result<(), FineTreeError> {
    // 1. Range validity — and, in the same step, the canonical cover the
    //    offered one must equal. `minimal_cover` owns both rules.
    let expected = minimal_cover(proof.range, leaf_count)?;
    let depth = expected.depth();
    let range_start = proof.range.start();
    let range_end = proof.range.end().ok_or(FineTreeError::RangeOutOfBounds {
        start: proof.range.start(),
        length: proof.range.length(),
        leaf_count,
    })?;

    // 2. The reveal must show exactly the span it claims (line 121).
    let revealed_len = u64::try_from(revealed_bytes.len()).unwrap_or(u64::MAX);
    if revealed_len != proof.range.length() {
        return Err(FineTreeError::ByteLenMismatch {
            expected: proof.range.length(),
            got: revealed_len,
        });
    }

    // 3 + 4. Exact lengths of every disclosed value (lines 96, 121).
    check_lengths(proof.cover, FineTreeError::seed_len)?;
    check_lengths(proof.boundary, FineTreeError::node_len)?;

    // 5 + 6. The cover must be the canonical leaf-exact one; anything that
    //        would disclose an unrevealed real leaf's salt is classified
    //        first, so the security-bearing code always wins.
    check_cover(
        proof.cover,
        &expected,
        leaf_count,
        depth,
        range_start,
        range_end,
    )?;

    // 7. D83's canonical leaf-level payload. Its position is load-bearing at
    //    both ends:
    //
    //    - **after `check_cover`**, because the security-bearing
    //      `OverBroadCover` and the structural `WrongCoverShape` must never
    //      be masked by a cheaper check — a level-`d` node can be over-broad
    //      (at d = 3 the node (3, 5) offered for a reveal of leaf 2) — and
    //      because only a passed `check_cover` makes the offered addresses
    //      known equal to the recomputed ones, which is what lets the zip
    //      below trust `node.address()`;
    //    - **before the `releases_s_root()` branch**, so it also governs the
    //      `n == 1` full reveal, whose single cover node sits at
    //      `level 0 == d`.
    for (node, wire) in expected.nodes().iter().zip(proof.cover) {
        check_leaf_level_payload(seed_of(wire)?.as_bytes(), node.address(), depth)?;
    }

    // The full-reveal case IS G9's rebuild: the cover is s_root, there is no
    // boundary path, and the verifier recomputes the whole tree from the
    // revealed bytes (line 121).
    if expected.releases_s_root() {
        if !proof.boundary.is_empty() {
            return Err(FineTreeError::WrongCoverShape);
        }
        let s_root = seed_of(proof.cover.first().ok_or(FineTreeError::WrongCoverShape)?)?;
        return match rebuild_fine_root(&s_root, revealed_bytes) {
            Some(rebuilt) if rebuilt == *fine_root => Ok(()),
            _ => Err(FineTreeError::RootMismatch),
        };
    }

    // 6 + 7. Rebuild the revealed leaves from the cover's seeds and fold them
    //        with the boundary path, checking each sibling's address against
    //        the one recomputed from (range, n) as it is consumed.
    let mut fold = Fold {
        salts: CoverSalts::new(proof.cover, expected.nodes(), depth)?,
        boundary: proof.boundary,
        boundary_cursor: 0,
        revealed: revealed_bytes,
        leaf_count,
        depth,
        range_start,
        range_end,
    };
    let root = fold.fold(0, leaf_count)?;
    if fold.boundary_cursor != proof.boundary.len() {
        // Extra siblings the canonical path has no place for.
        return Err(FineTreeError::WrongCoverShape);
    }
    if root == *fine_root.as_bytes() {
        Ok(())
    } else {
        Err(FineTreeError::RootMismatch)
    }
}

/// Every wire value must be exactly 32 bytes, reported with the caller's
/// class so a bad seed and a bad node hash are separate tamper rows.
fn check_lengths(
    nodes: &[WireNode<'_>],
    class: fn(usize, usize) -> FineTreeError,
) -> Result<(), FineTreeError> {
    for node in nodes {
        if node.bytes.len() != DISCLOSED_LEN {
            return Err(class(DISCLOSED_LEN, node.bytes.len()));
        }
    }
    Ok(())
}

impl FineTreeError {
    /// `BadSeedLength` as a plain `fn(expected, got)`, for [`check_lengths`].
    const fn seed_len(expected: usize, got: usize) -> Self {
        Self::BadSeedLength { expected, got }
    }

    /// `BadNodeHashLength` as a plain `fn(expected, got)`.
    const fn node_len(expected: usize, got: usize) -> Self {
        Self::BadNodeHashLength { expected, got }
    }
}

/// The offered seed of a length-checked wire node.
fn seed_of(node: &WireNode<'_>) -> Result<Seed32, FineTreeError> {
    let bytes = <[u8; 32]>::try_from(node.bytes).map_err(|_| FineTreeError::BadSeedLength {
        expected: DISCLOSED_LEN,
        got: node.bytes.len(),
    })?;
    Ok(Seed32::from_bytes(bytes))
}

/// Classify the offered cover: over-broad first (the security-bearing
/// outcome), then structural equality with the recomputed canonical cover.
fn check_cover(
    offered: &[WireNode<'_>],
    expected: &LeafExactCover,
    leaf_count: u64,
    depth: u8,
    range_start: u64,
    range_end: u64,
) -> Result<(), FineTreeError> {
    // Parse every address first, remembering (rather than immediately
    // returning) structural faults, so a proof carrying both a malformed
    // address and an over-broad node is still classified as over-broad —
    // the outcome with the disclosure meaning.
    let mut structural_fault = offered.len() != expected.nodes().len();
    let mut parsed: Vec<Option<NodeAddress>> = Vec::with_capacity(offered.len());
    for node in offered {
        match NodeAddress::try_new(node.level, node.index) {
            Ok(address) if address.validate_in_tree(depth).is_ok() => parsed.push(Some(address)),
            _ => {
                structural_fault = true;
                parsed.push(None);
            }
        }
    }

    for address in parsed.iter().flatten() {
        let first_slot = address
            .first_slot(depth)
            .map_err(|_| FineTreeError::WrongCoverShape)?;
        let slot_width = address
            .slot_width(depth)
            .map_err(|_| FineTreeError::WrongCoverShape)?;
        if first_slot >= leaf_count {
            // Covers only unused slots: it commits nothing, so it cannot be
            // part of any cover — a shape fault, not a disclosure one.
            structural_fault = true;
            continue;
        }
        let real_end = (u128::from(first_slot) + slot_width).min(u128::from(leaf_count));
        if first_slot < range_start || real_end > u128::from(range_end) {
            // MVP-SPEC.md line 96: this node's seed would derive the salt of
            // a real leaf the reveal does not show.
            return Err(FineTreeError::OverBroadCover);
        }
    }

    if structural_fault {
        return Err(FineTreeError::WrongCoverShape);
    }
    // Same nodes, same order — the canonical proof is the only one accepted.
    for (address, node) in parsed.iter().flatten().zip(expected.nodes()) {
        if *address != node.address() {
            return Err(FineTreeError::WrongCoverShape);
        }
    }
    Ok(())
}

/// Salts of the revealed leaves, derived from the cover's seeds in ascending
/// leaf order.
///
/// One [`GgmWalker`] per cover node, rooted at that node's seed with local
/// depth `d − level`: the walker's local leaf `j` is the file's leaf
/// `first_leaf + j`, so the whole revealed range is covered in amortized O(1)
/// hashes per byte with an `O(d)` seed stack.
struct CoverSalts {
    /// Per cover node, ascending: its seed, its sub-tree depth `d − level`,
    /// and how many real leaves it still owes.
    entries: Vec<CoverSaltSource>,
    entry: usize,
    remaining_in_entry: u64,
    walker: Option<GgmWalker>,
}

/// One cover node's salt source.
struct CoverSaltSource {
    seed: Seed32,
    sub_depth: u8,
    leaf_len: u64,
}

impl CoverSalts {
    /// Pair the offered (length-checked) seeds with the recomputed geometry.
    /// The two lists are already known equal in length and addressing.
    fn new(
        offered: &[WireNode<'_>],
        expected: &[CoverNode],
        depth: u8,
    ) -> Result<Self, FineTreeError> {
        let mut entries = Vec::with_capacity(expected.len());
        for (node, wire) in expected.iter().zip(offered) {
            entries.push(CoverSaltSource {
                seed: seed_of(wire)?,
                sub_depth: depth.saturating_sub(node.address().level()),
                leaf_len: node.leaf_len(),
            });
        }
        Ok(Self {
            entries,
            entry: 0,
            remaining_in_entry: 0,
            walker: None,
        })
    }

    /// The next revealed leaf's salt, in ascending leaf order.
    fn next_salt(&mut self) -> Option<Salt16> {
        while self.remaining_in_entry == 0 {
            let source = self.entries.get(self.entry)?;
            self.walker = Some(GgmWalker::new(&source.seed, source.sub_depth));
            self.remaining_in_entry = source.leaf_len;
            self.entry += 1;
        }
        self.remaining_in_entry -= 1;
        self.walker.as_mut().map(GgmWalker::next_salt)
    }
}

/// The verification fold: rebuild revealed leaves, take disjoint subtrees
/// from the boundary path, and combine under RFC 6962 promotion.
struct Fold<'a> {
    salts: CoverSalts,
    boundary: &'a [WireNode<'a>],
    boundary_cursor: usize,
    revealed: &'a [u8],
    leaf_count: u64,
    depth: u8,
    range_start: u64,
    range_end: u64,
}

impl Fold<'_> {
    /// Hash of the content-tree node over leaves `[first, end)`.
    ///
    /// Recursion depth is bounded by `d + 1 <= 65`, and the number of calls
    /// by `O(d + revealed_len)` — a disjoint subtree is answered from the
    /// boundary list without descending into it (module docs).
    fn fold(&mut self, first: u64, end: u64) -> Result<[u8; 32], FineTreeError> {
        if end <= self.range_start || first >= self.range_end {
            return self.take_boundary(first, end);
        }
        if end.saturating_sub(first) <= 1 {
            return self.rebuild_leaf(first);
        }
        let split = rfc6962_split(end - first);
        let left = self.fold(first, first + split)?;
        let right = self.fold(first + split, end)?;
        Ok(node_hash(&left, &right))
    }

    /// Consume the next boundary sibling, checking it is the one the
    /// canonical path has at this position — count, order and address in a
    /// single comparison.
    fn take_boundary(&mut self, first: u64, end: u64) -> Result<[u8; 32], FineTreeError> {
        let node = self
            .boundary
            .get(self.boundary_cursor)
            .ok_or(FineTreeError::WrongCoverShape)?;
        self.boundary_cursor += 1;

        let address = canonical_slot(first, end, self.leaf_count, self.depth)
            .ok_or(FineTreeError::WrongCoverShape)?;
        if node.level != address.level() || node.index != address.index() {
            return Err(FineTreeError::WrongCoverShape);
        }
        <[u8; 32]>::try_from(node.bytes).map_err(|_| FineTreeError::BadNodeHashLength {
            expected: DISCLOSED_LEN,
            got: node.bytes.len(),
        })
    }

    /// `leaf_i = SHA-256(0x00 ‖ salt_i ‖ LE64(i) ‖ byte_i)` from the
    /// cover-derived salt and the revealed byte at that position.
    fn rebuild_leaf(&mut self, index: u64) -> Result<[u8; 32], FineTreeError> {
        let salt = self
            .salts
            .next_salt()
            .ok_or(FineTreeError::WrongCoverShape)?;
        let byte = index
            .checked_sub(self.range_start)
            .and_then(|offset| usize::try_from(offset).ok())
            .and_then(|offset| self.revealed.get(offset))
            .copied()
            .ok_or(FineTreeError::ByteLenMismatch {
                expected: self.range_end - self.range_start,
                got: u64::try_from(self.revealed.len()).unwrap_or(u64::MAX),
            })?;
        Ok(leaf_hash(&salt, index, byte))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // `cover_seeds` is only reached from the proptest-bearing tier, which the
    // wasm32 `--lib` build deliberately does not enable (P14).
    #[cfg(feature = "test-util")]
    use crate::content::fine_tree::cover::cover_seeds;
    use crate::content::fine_tree::cover::descend;
    use crate::content::fine_tree::proof::prove_range;
    use crate::test_util::TEST_MASTER_SECRET_W;
    #[cfg(feature = "test-util")]
    use crate::test_util::strategies::proptest_config;
    #[cfg(feature = "test-util")]
    use proptest::prelude::*;
    use std::collections::BTreeSet;

    fn root_seed() -> Seed32 {
        Seed32::from_bytes(TEST_MASTER_SECRET_W)
    }

    fn content_of(n: usize) -> Vec<u8> {
        (0..n).map(|i| u8::try_from(i % 251).unwrap_or(0)).collect()
    }

    /// A mutable owned mirror of a proof's wire form, so adversarial tests
    /// can change one field at a time.
    #[derive(Debug, Clone)]
    struct OwnedProof {
        range: ByteRange,
        cover: Vec<(u8, u64, Vec<u8>)>,
        boundary: Vec<(u8, u64, Vec<u8>)>,
    }

    impl OwnedProof {
        fn of(proof: &RangeProof) -> Self {
            let own = |nodes: Vec<WireNode<'_>>| {
                nodes
                    .into_iter()
                    .map(|n| (n.level, n.index, n.bytes.to_vec()))
                    .collect::<Vec<_>>()
            };
            Self {
                range: proof.range(),
                cover: own(proof.wire_cover()),
                boundary: own(proof.wire_boundary()),
            }
        }

        fn check(
            &self,
            revealed: &[u8],
            leaf_count: u64,
            fine_root: &FineRoot,
        ) -> Result<(), FineTreeError> {
            fn view(rows: &[(u8, u64, Vec<u8>)]) -> Vec<WireNode<'_>> {
                rows.iter()
                    .map(|(level, index, bytes)| WireNode {
                        level: *level,
                        index: *index,
                        bytes,
                    })
                    .collect()
            }
            let cover = view(&self.cover);
            let boundary = view(&self.boundary);
            verify_range(
                &RangeProofView {
                    range: self.range,
                    cover: &cover,
                    boundary: &boundary,
                },
                revealed,
                leaf_count,
                fine_root,
            )
        }
    }

    /// A known-good n = 6 opening of leaf 2 — the fixture the adversarial
    /// tests below mutate, and the shape G19's tamper rows will reuse.
    struct Fixture {
        seed: Seed32,
        fine_root: FineRoot,
        proof: RangeProof,
        revealed: Vec<u8>,
    }

    /// A D83-canonical leaf-level payload: 16 chosen salt bytes, zero tail.
    fn canonical_payload(salt: [u8; Salt16::LEN]) -> [u8; DISCLOSED_LEN] {
        let mut payload = [0u8; DISCLOSED_LEN];
        payload[..Salt16::LEN].copy_from_slice(&salt);
        payload
    }

    fn n6_leaf2() -> Fixture {
        let seed = root_seed();
        let content = b"abcdef".to_vec();
        let fine_root =
            crate::content::rebuild_fine_root(&seed, &content).expect("n = 6 has a tree");
        let proof = prove_range(&seed, &content, ByteRange::new(2, 1), 6).expect("in bounds");
        let revealed = content[2..3].to_vec();
        Fixture {
            seed,
            fine_root,
            proof,
            revealed,
        }
    }

    // ── Happy path (G13 accept) ─────────────────────────────────────────

    /// G13 accept: every G12-generated proof verifies — over every range of
    /// every small `n`, including the unbalanced shapes and the ragged right
    /// edge.
    #[test]
    fn every_generated_proof_verifies() {
        let seed = root_seed();
        for n in 1usize..=33 {
            let content = content_of(n);
            let fine_root = crate::content::rebuild_fine_root(&seed, &content).expect("n > 0");
            let n64 = u64::try_from(n).expect("small");
            for start in 0..n64 {
                for length in 1..=(n64 - start) {
                    let range = ByteRange::new(start, length);
                    let proof = prove_range(&seed, &content, range, n64).expect("in bounds");
                    let lo = usize::try_from(start).expect("small");
                    let hi = usize::try_from(start + length).expect("small");
                    assert_eq!(
                        proof.verify(&content[lo..hi], &fine_root),
                        Ok(()),
                        "n = {n}, [{start}, {start}+{length})"
                    );
                }
            }
        }
    }

    /// The full-range case delegates to G9's `rebuild_fine_root` — the same
    /// function R runs on a full file reveal (MVP-SPEC.md line 121).
    #[test]
    fn full_range_verification_is_the_g9_rebuild() {
        let seed = root_seed();
        let content = b"abcdef";
        let fine_root = crate::content::rebuild_fine_root(&seed, content).expect("n = 6");
        let proof = prove_range(&seed, content, ByteRange::new(0, 6), 6).expect("in bounds");
        assert_eq!(proof.verify(content, &fine_root), Ok(()));

        // The cover really is s_root, and the rebuild really is the same
        // computation.
        assert_eq!(proof.cover()[0].seed().as_bytes(), seed.as_bytes());
        assert_eq!(
            crate::content::rebuild_fine_root(proof.cover()[0].seed(), content),
            Some(fine_root)
        );

        // …and a full-range proof carrying a stray boundary node is refused.
        let mut tampered = OwnedProof::of(&proof);
        tampered.boundary.push((3, 0, vec![0u8; 32]));
        assert_eq!(
            tampered.check(content, 6, &fine_root),
            Err(FineTreeError::WrongCoverShape)
        );
    }

    // ── One adversarial test per error class (G13 accept) ───────────────

    /// 1. `RangeOutOfBounds` — empty, reversed-by-overflow, past `n`, and
    ///    every range against a file with no fine tree.
    #[test]
    fn adversarial_range_out_of_bounds() {
        let Fixture {
            fine_root,
            proof,
            revealed,
            ..
        } = n6_leaf2();
        for range in [
            ByteRange::new(2, 0),
            ByteRange::new(6, 1),
            ByteRange::new(0, 7),
            ByteRange::new(u64::MAX, 1),
        ] {
            let mut tampered = OwnedProof::of(&proof);
            tampered.range = range;
            assert!(
                matches!(
                    tampered.check(&revealed, 6, &fine_root),
                    Err(FineTreeError::RangeOutOfBounds { .. })
                ),
                "{range:?}"
            );
        }
        // A hostile leaf_count of 0 means "no fine tree at all".
        assert!(matches!(
            OwnedProof::of(&proof).check(&revealed, 0, &fine_root),
            Err(FineTreeError::RangeOutOfBounds { .. })
        ));
    }

    /// 2. `ByteLenMismatch` — a proof claiming more span than it reveals
    ///    (MVP-SPEC.md line 121), in both directions.
    #[test]
    fn adversarial_byte_len_mismatch() {
        let Fixture {
            fine_root,
            proof,
            revealed,
            ..
        } = n6_leaf2();
        let owned = OwnedProof::of(&proof);
        assert_eq!(
            owned.check(b"", 6, &fine_root),
            Err(FineTreeError::ByteLenMismatch {
                expected: 1,
                got: 0
            })
        );
        assert_eq!(
            owned.check(b"cd", 6, &fine_root),
            Err(FineTreeError::ByteLenMismatch {
                expected: 1,
                got: 2
            })
        );
        // And the claim-more-than-you-show shape: widen the range without
        // widening the reveal.
        let mut widened = owned.clone();
        widened.range = ByteRange::new(2, 3);
        assert_eq!(
            widened.check(&revealed, 6, &fine_root),
            Err(FineTreeError::ByteLenMismatch {
                expected: 3,
                got: 1
            })
        );
    }

    /// 3. `BadSeedLength` — a cover seed of any length but 32
    ///    (MVP-SPEC.md lines 96, 121).
    #[test]
    fn adversarial_bad_seed_length() {
        let Fixture {
            fine_root,
            proof,
            revealed,
            ..
        } = n6_leaf2();
        for len in [0usize, 16, 31, 33, 64] {
            let mut tampered = OwnedProof::of(&proof);
            tampered.cover[0].2 = vec![0xAA; len];
            assert_eq!(
                tampered.check(&revealed, 6, &fine_root),
                Err(FineTreeError::BadSeedLength {
                    expected: 32,
                    got: len
                }),
                "seed length {len}"
            );
        }
    }

    /// 4. `BadNodeHashLength` — a boundary hash of any length but 32.
    #[test]
    fn adversarial_bad_node_hash_length() {
        let Fixture {
            fine_root,
            proof,
            revealed,
            ..
        } = n6_leaf2();
        for len in [0usize, 16, 31, 33, 64] {
            let mut tampered = OwnedProof::of(&proof);
            tampered.boundary[0].2 = vec![0xBB; len];
            assert_eq!(
                tampered.check(&revealed, 6, &fine_root),
                Err(FineTreeError::BadNodeHashLength {
                    expected: 32,
                    got: len
                }),
                "hash length {len}"
            );
        }
    }

    /// 5. `OverBroadCover` — **the security row** (G19). A dyadically valid
    ///    but over-broad cover whose node spans an unrevealed real leaf, and
    ///    the headline case of `s_root` offered for a partial range.
    #[test]
    fn adversarial_over_broad_cover() {
        let Fixture {
            seed,
            fine_root,
            proof,
            revealed,
            ..
        } = n6_leaf2();

        // Substitute node (2, 1): slots [2, 4), i.e. real leaves 2 AND 3 —
        // a perfectly valid dyadic node whose seed would disclose salt_3.
        let over_broad = NodeAddress::try_new(2, 1).expect("on the grid");
        let mut tampered = OwnedProof::of(&proof);
        tampered.cover = vec![(
            over_broad.level(),
            over_broad.index(),
            descend(&seed, over_broad).as_bytes().to_vec(),
        )];
        assert_eq!(
            tampered.check(&revealed, 6, &fine_root),
            Err(FineTreeError::OverBroadCover)
        );

        // s_root on a partial range — the rule's headline case (line 96).
        let mut root_offered = OwnedProof::of(&proof);
        root_offered.cover = vec![(0, 0, seed.as_bytes().to_vec())];
        assert_eq!(
            root_offered.check(&revealed, 6, &fine_root),
            Err(FineTreeError::OverBroadCover)
        );

        // A node inside [0, n) but disjoint from the range is over-broad too:
        // it discloses the salt of a leaf the reveal does not show.
        let elsewhere = NodeAddress::try_new(3, 5).expect("on the grid");
        let mut other_leaf = OwnedProof::of(&proof);
        other_leaf.cover = vec![(
            elsewhere.level(),
            elsewhere.index(),
            descend(&seed, elsewhere).as_bytes().to_vec(),
        )];
        assert_eq!(
            other_leaf.check(&revealed, 6, &fine_root),
            Err(FineTreeError::OverBroadCover)
        );
    }

    /// 6. `WrongCoverShape` — everything structural: wrong count, wrong
    ///    order, an address off the grid, a node over only unused slots, a
    ///    duplicated cover node, a wrong-position boundary node, and a
    ///    boundary list that is too short or too long.
    #[test]
    fn adversarial_wrong_cover_shape() {
        let Fixture {
            fine_root,
            proof,
            revealed,
            ..
        } = n6_leaf2();
        let good = OwnedProof::of(&proof);

        // Empty cover.
        let mut empty = good.clone();
        empty.cover.clear();
        assert_eq!(
            empty.check(&revealed, 6, &fine_root),
            Err(FineTreeError::WrongCoverShape)
        );

        // Duplicated cover node (right count would be 1, so this is 2).
        let mut duplicated = good.clone();
        duplicated.cover.push(good.cover[0].clone());
        assert_eq!(
            duplicated.check(&revealed, 6, &fine_root),
            Err(FineTreeError::WrongCoverShape)
        );

        // Address below this tree's depth (d = 3, so level 4 is off-grid).
        let mut off_grid = good.clone();
        off_grid.cover[0].0 = 4;
        assert_eq!(
            off_grid.check(&revealed, 6, &fine_root),
            Err(FineTreeError::WrongCoverShape)
        );

        // Index outside its level (level 3 admits indices < 8).
        let mut bad_index = good.clone();
        bad_index.cover[0].1 = 8;
        assert_eq!(
            bad_index.check(&revealed, 6, &fine_root),
            Err(FineTreeError::WrongCoverShape)
        );

        // A node over only unused slots (slot 6 >= n = 6) commits nothing.
        let mut unused = good.clone();
        unused.cover[0] = (3, 6, vec![0u8; 32]);
        assert_eq!(
            unused.check(&revealed, 6, &fine_root),
            Err(FineTreeError::WrongCoverShape)
        );

        // Reordered boundary path — same hashes, wrong positions.
        let mut reordered = good.clone();
        reordered.boundary.swap(0, 2);
        assert_eq!(
            reordered.check(&revealed, 6, &fine_root),
            Err(FineTreeError::WrongCoverShape)
        );

        // Truncated and padded boundary paths.
        let mut short = good.clone();
        short.boundary.pop();
        assert_eq!(
            short.check(&revealed, 6, &fine_root),
            Err(FineTreeError::WrongCoverShape)
        );
        let mut long = good.clone();
        long.boundary.push((3, 0, vec![0u8; 32]));
        assert_eq!(
            long.check(&revealed, 6, &fine_root),
            Err(FineTreeError::WrongCoverShape)
        );

        // A boundary node re-addressed to a valid-but-wrong slot.
        let mut misaddressed = good.clone();
        misaddressed.boundary[0].0 = 3;
        misaddressed.boundary[0].1 = 0;
        assert_eq!(
            misaddressed.check(&revealed, 6, &fine_root),
            Err(FineTreeError::WrongCoverShape)
        );
    }

    /// **The regression guard for "canonical, not merely valid".**
    ///
    /// At `n = 8` a reveal of `[0, 4)` has the single cover node `(1, 0)`.
    /// Its two children `(2, 0)` and `(2, 1)` form a cover that is dyadically
    /// valid, *leaf-exact* (neither spans an unrevealed real leaf) and
    /// discloses strictly **less** than the canonical one — yet it is not the
    /// proof `minimal_cover` produces, so `verify_range` refuses it.
    ///
    /// If someone later "relaxes" the exact-cover comparison to a validity
    /// check — which looks harmless, since this substitution leaks nothing —
    /// this test fails. The relaxation must not happen: recomputing and
    /// comparing is what makes the over-broad case a *distinct* rejection
    /// (MVP-SPEC.md line 96) instead of one branch of a general validity
    /// predicate that a future edit could weaken.
    #[test]
    fn a_valid_but_non_canonical_cover_is_still_refused() {
        let seed = root_seed();
        let content = content_of(8);
        let fine_root = crate::content::rebuild_fine_root(&seed, &content).expect("n = 8");
        let proof = prove_range(&seed, &content, ByteRange::new(0, 4), 8).expect("in bounds");
        let revealed = &content[0..4];
        assert_eq!(proof.verify(revealed, &fine_root), Ok(()));

        let canonical = OwnedProof::of(&proof);
        assert_eq!(canonical.cover.len(), 1);
        assert_eq!((canonical.cover[0].0, canonical.cover[0].1), (1, 0));

        let mut split_cover = canonical.clone();
        split_cover.cover = [(2u8, 0u64), (2, 1)]
            .into_iter()
            .map(|(level, index)| {
                let address = NodeAddress::try_new(level, index).expect("on the grid");
                (level, index, descend(&seed, address).as_bytes().to_vec())
            })
            .collect();

        // Leaf-exact and strictly less disclosing — and still refused.
        assert_eq!(
            split_cover.check(revealed, 8, &fine_root),
            Err(FineTreeError::WrongCoverShape)
        );
    }

    /// 7. `RootMismatch` — **the other security row** (G19): well-formed
    ///    proof, flipped content byte. Also a flipped boundary hash and a
    ///    wrong `fine_root`.
    #[test]
    fn adversarial_root_mismatch() {
        let Fixture {
            fine_root,
            proof,
            revealed,
            ..
        } = n6_leaf2();

        // G19 row 1: flip a byte of the revealed content.
        let mut flipped = revealed.clone();
        flipped[0] ^= 0x01;
        assert_eq!(
            proof.verify(&flipped, &fine_root),
            Err(FineTreeError::RootMismatch)
        );

        // A flipped boundary hash — correct shape, wrong value.
        let mut tampered = OwnedProof::of(&proof);
        tampered.boundary[0].2[0] ^= 0xFF;
        assert_eq!(
            tampered.check(&revealed, 6, &fine_root),
            Err(FineTreeError::RootMismatch)
        );

        // A cover payload of the right length and the right *shape* but the
        // wrong value. The fixture's node (3, 2) is at level d = 3, so the
        // payload must keep D83's zero tail or the earlier class fires
        // instead — which `precedence` below asserts explicitly.
        let mut wrong_seed = OwnedProof::of(&proof);
        wrong_seed.cover[0].2 = canonical_payload([0x99; 16]).to_vec();
        assert_eq!(
            wrong_seed.check(&revealed, 6, &fine_root),
            Err(FineTreeError::RootMismatch)
        );

        // A different fine_root.
        assert_eq!(
            proof.verify(&revealed, &FineRoot::from_bytes([0u8; 32])),
            Err(FineTreeError::RootMismatch)
        );
    }

    /// The eight classes really are eight distinct outcomes, reachable from
    /// this one fixture — the tamper-matrix requirement (MVP-SPEC.md
    /// line 168) demonstrated end to end rather than asserted on exemplars.
    ///
    /// The eighth is D83's `LeafSeedTailNotZero`, which this fixture reaches
    /// for free: `n = 6` reveal `{2}` has the single cover node `(3, 2)`, and
    /// `3` is the depth of the grid.
    #[test]
    fn all_eight_classes_are_reachable_and_distinct() {
        let Fixture {
            seed,
            fine_root,
            proof,
            revealed,
            ..
        } = n6_leaf2();
        let good = OwnedProof::of(&proof);

        let mut out_of_bounds = good.clone();
        out_of_bounds.range = ByteRange::new(6, 1);
        let mut bad_seed = good.clone();
        bad_seed.cover[0].2 = vec![0u8; 31];
        let mut bad_hash = good.clone();
        bad_hash.boundary[0].2 = vec![0u8; 31];
        let mut over_broad = good.clone();
        over_broad.cover = vec![(0, 0, seed.as_bytes().to_vec())];
        let mut wrong_shape = good.clone();
        wrong_shape.boundary.pop();
        let mut dirty_tail = good.clone();
        dirty_tail.cover[0].2[Salt16::LEN] ^= 0x01;
        let mut wrong_root = good.clone();
        wrong_root.cover[0].2 = canonical_payload([0x99; 16]).to_vec();

        let outcomes = [
            out_of_bounds.check(&revealed, 6, &fine_root),
            good.check(b"", 6, &fine_root),
            bad_seed.check(&revealed, 6, &fine_root),
            bad_hash.check(&revealed, 6, &fine_root),
            over_broad.check(&revealed, 6, &fine_root),
            wrong_shape.check(&revealed, 6, &fine_root),
            dirty_tail.check(&revealed, 6, &fine_root),
            wrong_root.check(&revealed, 6, &fine_root),
        ];

        let codes: BTreeSet<&'static str> = outcomes
            .iter()
            .map(|outcome| outcome.expect_err("each mutation must fail").code())
            .collect();
        assert_eq!(
            codes.len(),
            8,
            "each mutation must fail distinctly: {codes:?}"
        );
        assert_eq!(good.check(&revealed, 6, &fine_root), Ok(()));
    }

    /// 8. `LeafSeedTailNotZero` — **D83's row**. The honest opening of leaf 2
    ///    at `n = 6` ships the canonical `salt_2 ‖ 0¹⁶` for node `(3, 2)`;
    ///    setting any tail byte is a rejection naming that exact address.
    #[test]
    fn adversarial_leaf_seed_tail_not_zero() {
        let Fixture {
            fine_root,
            proof,
            revealed,
            ..
        } = n6_leaf2();
        let good = OwnedProof::of(&proof);

        // The honest wire form really does carry the canonical tail — this is
        // the prover half of D83, and without it the mutations below would
        // prove nothing.
        assert_eq!((good.cover[0].0, good.cover[0].1), (3, 2));
        assert_eq!(&good.cover[0].2[Salt16::LEN..], &[0u8; 16]);
        assert_eq!(
            &good.cover[0].2[..Salt16::LEN],
            &proof.cover()[0].seed().as_bytes()[..Salt16::LEN],
            "the disclosed salt is still the derived one"
        );

        for index in Salt16::LEN..DISCLOSED_LEN {
            for mask in [0x01u8, 0x80, 0xFF] {
                let mut tampered = good.clone();
                tampered.cover[0].2[index] ^= mask;
                assert_eq!(
                    tampered.check(&revealed, 6, &fine_root),
                    Err(FineTreeError::LeafSeedTailNotZero { level: 3, index: 2 }),
                    "tail byte {index}, mask {mask:#04x}"
                );
            }
        }
        assert_eq!(good.check(&revealed, 6, &fine_root), Ok(()));
    }

    /// D83 §4.3's `n == 1` case, which the original record missed: at
    /// `d = 0` the grid root **is** the single leaf, so the whole-file cover
    /// node `(0, 0)` is a `level == d` disclosure and takes the canonical
    /// tail — on the branch that delegates to G9's rebuild.
    #[test]
    fn a_one_leaf_full_reveal_takes_the_canonical_tail() {
        let seed = root_seed();
        let content = b"Z";
        let fine_root = crate::content::rebuild_fine_root(&seed, content).expect("n = 1");
        let proof = prove_range(&seed, content, ByteRange::new(0, 1), 1).expect("in bounds");
        let good = OwnedProof::of(&proof);

        // One cover node, the root, at level 0 == d, carrying salt_0 ‖ 0¹⁶ —
        // and the true s_root's tail never leaves the vault.
        assert_eq!(proof.depth(), 0);
        assert_eq!((good.cover[0].0, good.cover[0].1), (0, 0));
        assert_eq!(&good.cover[0].2[..Salt16::LEN], &seed.as_bytes()[..16]);
        assert_eq!(&good.cover[0].2[Salt16::LEN..], &[0u8; 16]);
        assert_ne!(good.cover[0].2.as_slice(), seed.as_bytes().as_slice());

        // It still verifies — `rebuild_fine_root` derives salt_0 =
        // payload[..16], which is the correct salt.
        assert_eq!(good.check(content, 1, &fine_root), Ok(()));
        assert_eq!(proof.verify(content, &fine_root), Ok(()));

        // …and a non-zero tail is rejected on that same branch, before the
        // rebuild can turn it into a generic root mismatch.
        for index in Salt16::LEN..DISCLOSED_LEN {
            let mut tampered = good.clone();
            tampered.cover[0].2[index] ^= 0x01;
            assert_eq!(
                tampered.check(content, 1, &fine_root),
                Err(FineTreeError::LeafSeedTailNotZero { level: 0, index: 0 }),
                "tail byte {index}"
            );
        }

        // The true s_root, offered whole, is now inadmissible — the concrete
        // statement that D83 changed the wire form at n = 1.
        let mut raw_root = good.clone();
        raw_root.cover[0].2 = seed.as_bytes().to_vec();
        assert_eq!(
            raw_root.check(content, 1, &fine_root),
            Err(FineTreeError::LeafSeedTailNotZero { level: 0, index: 0 })
        );
    }

    /// The **frozen** precedence of module docs: a proof carrying several
    /// faults always reports the earlier class, so a tamper row can pin an
    /// exact code.
    #[test]
    fn error_precedence_is_deterministic() {
        let Fixture {
            seed,
            fine_root,
            proof,
            revealed,
            ..
        } = n6_leaf2();
        let good = OwnedProof::of(&proof);

        // Range fault + byte-length fault + bad seed → range wins.
        let mut all_three = good.clone();
        all_three.range = ByteRange::new(9, 1);
        all_three.cover[0].2 = vec![0u8; 4];
        assert!(matches!(
            all_three.check(b"", 6, &fine_root),
            Err(FineTreeError::RangeOutOfBounds { .. })
        ));

        // Byte-length fault + bad seed → byte length wins.
        let mut len_and_seed = good.clone();
        len_and_seed.cover[0].2 = vec![0u8; 4];
        assert!(matches!(
            len_and_seed.check(b"xy", 6, &fine_root),
            Err(FineTreeError::ByteLenMismatch { .. })
        ));

        // Bad seed + bad node hash → seed wins.
        let mut both_lengths = good.clone();
        both_lengths.cover[0].2 = vec![0u8; 4];
        both_lengths.boundary[0].2 = vec![0u8; 4];
        assert!(matches!(
            both_lengths.check(&revealed, 6, &fine_root),
            Err(FineTreeError::BadSeedLength { .. })
        ));

        // Over-broad cover + malformed extra address → over-broad wins, so
        // the disclosure-bearing classification can never be masked.
        let mut masked = good.clone();
        masked.cover = vec![(0, 0, seed.as_bytes().to_vec()), (99, 0, vec![0u8; 32])];
        assert_eq!(
            masked.check(&revealed, 6, &fine_root),
            Err(FineTreeError::OverBroadCover)
        );

        // Shape fault + wrong root → shape wins. The cover payload keeps
        // D83's canonical zero tail, so the second fault really is "wrong
        // root" and not the step-7 value rule.
        let mut shape_and_root = good.clone();
        shape_and_root.boundary.pop();
        shape_and_root.cover[0].2 = canonical_payload([0x99; 16]).to_vec();
        assert_eq!(
            shape_and_root.check(&revealed, 6, &fine_root),
            Err(FineTreeError::WrongCoverShape)
        );

        // ── D83's step 7, pinned from both sides ──
        //
        // Over-broad cover + dirty tail → over-broad wins. The substituted
        // node (3, 5) is itself at level d, so this is exactly the case that
        // forces step 7 to sit *after* `check_cover`: the disclosure-bearing
        // classification must never be masked by the cheaper value rule.
        let elsewhere = NodeAddress::try_new(3, 5).expect("on the grid");
        let mut over_broad_and_tail = good.clone();
        over_broad_and_tail.cover = vec![(
            elsewhere.level(),
            elsewhere.index(),
            descend(&seed, elsewhere).as_bytes().to_vec(),
        )];
        assert_ne!(
            &over_broad_and_tail.cover[0].2[Salt16::LEN..],
            &[0u8; 16],
            "the substituted node must really carry a dirty tail"
        );
        assert_eq!(
            over_broad_and_tail.check(&revealed, 6, &fine_root),
            Err(FineTreeError::OverBroadCover)
        );

        // **`WrongCoverShape` has two sites, and step 7 sits between them.**
        //
        // The *cover* half is `check_cover`'s (count, order, addressing,
        // unused slots) and precedes the tail check:
        let mut cover_shape_and_tail = good.clone();
        cover_shape_and_tail
            .cover
            .push(cover_shape_and_tail.cover[0].clone());
        cover_shape_and_tail.cover[0].2[Salt16::LEN] ^= 0x01;
        assert_eq!(
            cover_shape_and_tail.check(&revealed, 6, &fine_root),
            Err(FineTreeError::WrongCoverShape)
        );

        // …whereas the *boundary* half is diagnosed during the fold, when a
        // sibling is missing or misplaced — which is strictly **after** step
        // 7. So a proof carrying both a short boundary path and a dirty leaf
        // tail reports the tail. That is the correct trade: `check_cover`'s
        // security-bearing classifications still win, and what is reordered
        // is only the residual structural mismatch that "discloses nothing"
        // (see `FineTreeError::WrongCoverShape`). Recorded because the
        // numbered precedence reads as though the class had one position.
        let mut boundary_shape_and_tail = good.clone();
        boundary_shape_and_tail.boundary.pop();
        boundary_shape_and_tail.cover[0].2[Salt16::LEN] ^= 0x01;
        assert_eq!(
            boundary_shape_and_tail.check(&revealed, 6, &fine_root),
            Err(FineTreeError::LeafSeedTailNotZero { level: 3, index: 2 })
        );

        // Dirty tail + wrong salt (hence wrong root) → the tail wins, so the
        // D83 row can pin an exact code rather than inheriting the generic
        // binding failure.
        let mut tail_and_root = good.clone();
        tail_and_root.cover[0].2 = vec![0x99; 32];
        assert_eq!(
            tail_and_root.check(&revealed, 6, &fine_root),
            Err(FineTreeError::LeafSeedTailNotZero { level: 3, index: 2 })
        );
    }

    /// A hostile `leaf_count` costs the verifier nothing: the proof for a
    /// one-byte reveal of a claimed `u64::MAX`-leaf file is rejected on its
    /// merits, in bounded time, with no allocation proportional to `n`.
    #[test]
    fn a_hostile_leaf_count_does_not_blow_up_the_verifier() {
        let Fixture {
            seed,
            fine_root,
            proof,
            revealed,
            ..
        } = n6_leaf2();
        for leaf_count in [u64::MAX, 1u64 << 63, 1_000_000_000_000] {
            let mut huge = OwnedProof::of(&proof);
            huge.range = ByteRange::new(0, 1);
            huge.cover = vec![(
                64,
                0,
                descend(&seed, NodeAddress::try_new(64, 0).expect("on the grid"))
                    .as_bytes()
                    .to_vec(),
            )];
            // Whatever it decides, it must decide it — and never succeed.
            assert!(
                huge.check(&revealed, leaf_count, &fine_root).is_err(),
                "leaf_count = {leaf_count}"
            );
        }
    }

    // ── The canonical leaf-level payload predicate (D83) ────────────────

    /// [`check_leaf_level_payload`] in isolation: it fires **only** at
    /// `level == depth`, it accepts exactly the zero tail, and it names the
    /// offending address and nothing else.
    #[test]
    fn the_leaf_level_payload_predicate_binds_only_the_leaf_level() {
        assert_eq!(LEAF_PAYLOAD_SIGNIFICANT_LEN, Salt16::LEN);

        let canonical = {
            let mut bytes = [0u8; DISCLOSED_LEN];
            bytes[..LEAF_PAYLOAD_SIGNIFICANT_LEN].copy_from_slice(&[0xA5; Salt16::LEN]);
            bytes
        };
        let leaf = NodeAddress::try_new(3, 2).expect("on the grid");

        // Canonical at the leaf level, and at every other level too.
        assert_eq!(check_leaf_level_payload(&canonical, leaf, 3), Ok(()));
        assert_eq!(
            check_leaf_level_payload(&canonical, NodeAddress::root(), 0),
            Ok(())
        );

        // Every single byte of the tail is checked, one at a time.
        for index in LEAF_PAYLOAD_SIGNIFICANT_LEN..DISCLOSED_LEN {
            let mut dirty = canonical;
            dirty[index] = 0x01;
            assert_eq!(
                check_leaf_level_payload(&dirty, leaf, 3),
                Err(FineTreeError::LeafSeedTailNotZero { level: 3, index: 2 }),
                "byte {index} of the tail must be checked"
            );
            // …and the very same bytes are free at every shallower level,
            // where they are the real seed.
            for depth in [4u8, 5, 64] {
                assert_eq!(
                    check_leaf_level_payload(&dirty, leaf, depth),
                    Ok(()),
                    "level 3 is not the leaf level of a depth-{depth} grid"
                );
            }
        }

        // The significant half is never the predicate's business: a payload
        // with an arbitrary salt and a zero tail is canonical.
        let mut arbitrary_salt = [0xFFu8; DISCLOSED_LEN];
        arbitrary_salt[LEAF_PAYLOAD_SIGNIFICANT_LEN..].fill(0);
        assert_eq!(check_leaf_level_payload(&arbitrary_salt, leaf, 3), Ok(()));
    }

    // ── Property tests (G13 accept) ─────────────────────────────────────

    #[cfg(feature = "test-util")]

    proptest! {
        #![proptest_config(proptest_config(0x0064_0013))]

        /// G13 accept: generate → verify round-trips over random `n` and
        /// ranges, including `[0, n)`, single-leaf ranges, and ranges at the
        /// unbalanced right edge.
        #[test]
        fn generated_proofs_round_trip(
            n in 1u64..=200,
            start in 0u64..200,
            length in 1u64..200,
            root_bytes in any::<[u8; 32]>(),
        ) {
            let start = start % n;
            let length = length.min(n - start);
            let seed = Seed32::from_bytes(root_bytes);
            let content: Vec<u8> = (0..n).map(|i| u8::try_from(i % 251).unwrap_or(0)).collect();
            let fine_root = crate::content::rebuild_fine_root(&seed, &content).expect("n > 0");
            let proof = prove_range(&seed, &content, ByteRange::new(start, length), n)
                .expect("in bounds");
            let lo = usize::try_from(start).expect("small");
            let hi = usize::try_from(start + length).expect("small");
            prop_assert_eq!(proof.verify(&content[lo..hi], &fine_root), Ok(()));
        }

        /// Any single mutation of the revealed bytes is caught.
        #[test]
        fn mutated_content_never_verifies(
            n in 2u64..=64,
            start in 0u64..64,
            length in 1u64..64,
            flip_at in 0usize..64,
            mask in 1u8..=255,
        ) {
            let start = start % n;
            let length = length.min(n - start);
            let seed = Seed32::from_bytes([0x2B; 32]);
            let content: Vec<u8> = (0..n).map(|i| u8::try_from(i % 251).unwrap_or(0)).collect();
            let fine_root = crate::content::rebuild_fine_root(&seed, &content).expect("n > 0");
            let proof = prove_range(&seed, &content, ByteRange::new(start, length), n)
                .expect("in bounds");

            let lo = usize::try_from(start).expect("small");
            let hi = usize::try_from(start + length).expect("small");
            let mut revealed = content[lo..hi].to_vec();
            let at = flip_at % revealed.len();
            revealed[at] ^= mask;
            prop_assert_eq!(
                proof.verify(&revealed, &fine_root),
                Err(FineTreeError::RootMismatch)
            );
        }

        /// G13 accept: **no panic** on arbitrary/mutated proof fields. Every
        /// wire value — levels, indices, byte lengths, the range, `n`, the
        /// root — is adversary-chosen; the function must always return.
        #[test]
        fn arbitrary_proofs_never_panic(
            range_start in any::<u64>(),
            range_length in any::<u64>(),
            leaf_count in any::<u64>(),
            cover in proptest::collection::vec(
                (any::<u8>(), any::<u64>(), proptest::collection::vec(any::<u8>(), 0..40)),
                0..6,
            ),
            boundary in proptest::collection::vec(
                (any::<u8>(), any::<u64>(), proptest::collection::vec(any::<u8>(), 0..40)),
                0..6,
            ),
            revealed in proptest::collection::vec(any::<u8>(), 0..40),
            root_bytes in any::<[u8; 32]>(),
        ) {
            let owned = OwnedProof {
                range: ByteRange::new(range_start, range_length),
                cover,
                boundary,
            };
            // The assertion is that this returns at all; a success would be
            // an astronomically unlikely forgery, so it must not happen.
            let outcome = owned.check(&revealed, leaf_count, &FineRoot::from_bytes(root_bytes));
            prop_assert!(outcome.is_err());
        }

        /// Mutating a *valid* proof one field at a time never panics and
        /// never verifies — the structured half of the fuzz property.
        #[test]
        fn single_field_mutations_are_rejected(
            n in 1u64..=48,
            start in 0u64..48,
            length in 1u64..48,
            which in 0usize..6,
            index_noise in any::<u64>(),
            level_noise in any::<u8>(),
        ) {
            let start = start % n;
            let length = length.min(n - start);
            let seed = Seed32::from_bytes([0x77; 32]);
            let content: Vec<u8> = (0..n).map(|i| u8::try_from(i % 251).unwrap_or(0)).collect();
            let fine_root = crate::content::rebuild_fine_root(&seed, &content).expect("n > 0");
            let proof = prove_range(&seed, &content, ByteRange::new(start, length), n)
                .expect("in bounds");
            let lo = usize::try_from(start).expect("small");
            let hi = usize::try_from(start + length).expect("small");
            let revealed = content[lo..hi].to_vec();

            let original = OwnedProof::of(&proof);
            // The known-good proof must verify, or the mutation below proves
            // nothing.
            prop_assert_eq!(original.check(&revealed, n, &fine_root), Ok(()));

            let mut tampered = original.clone();
            match which {
                0 => tampered.range = ByteRange::new(start.wrapping_add(1), length),
                1 => tampered.range = ByteRange::new(start, length.wrapping_add(1)),
                2 => {
                    if let Some(node) = tampered.cover.first_mut() {
                        node.0 = level_noise;
                    }
                }
                3 => {
                    if let Some(node) = tampered.cover.first_mut() {
                        node.1 = index_noise;
                    }
                }
                4 => {
                    if let Some(node) = tampered.boundary.first_mut() {
                        node.1 = index_noise;
                    }
                }
                _ => {
                    if let Some(node) = tampered.cover.first_mut() {
                        node.2[0] ^= 0xFF;
                    }
                }
            }

            // Only assert when the mutation actually changed something —
            // random noise can land on the original value.
            prop_assume!(
                tampered.range != original.range
                    || tampered.cover != original.cover
                    || tampered.boundary != original.boundary
            );
            prop_assert!(
                tampered.check(&revealed, n, &fine_root).is_err(),
                "a mutated proof verified"
            );
        }

        /// G13 accept: an `s_root`-bearing cover is rejected for **every**
        /// partial range, at every shape — the puncturing-soundness guard.
        #[test]
        fn s_root_never_opens_a_partial_range(
            n in 2u64..=120,
            start in 0u64..120,
            length in 1u64..120,
            root_bytes in any::<[u8; 32]>(),
        ) {
            let start = start % n;
            let length = length.min(n - start);
            prop_assume!(!(start == 0 && length == n));

            let seed = Seed32::from_bytes(root_bytes);
            let content: Vec<u8> = (0..n).map(|i| u8::try_from(i % 251).unwrap_or(0)).collect();
            let fine_root = crate::content::rebuild_fine_root(&seed, &content).expect("n > 0");
            let proof = prove_range(&seed, &content, ByteRange::new(start, length), n)
                .expect("in bounds");
            let lo = usize::try_from(start).expect("small");
            let hi = usize::try_from(start + length).expect("small");

            let mut tampered = OwnedProof::of(&proof);
            tampered.cover = vec![(0, 0, seed.as_bytes().to_vec())];
            prop_assert_eq!(
                tampered.check(&content[lo..hi], n, &fine_root),
                Err(FineTreeError::OverBroadCover)
            );
        }

        /// Every over-broad substitution — any strict ancestor of a correct
        /// cover node — is rejected as `OverBroadCover`, never accepted and
        /// never mistaken for a shape fault.
        #[test]
        fn ancestors_of_cover_nodes_are_always_over_broad(
            n in 2u64..=120,
            start in 0u64..120,
            length in 1u64..120,
            root_bytes in any::<[u8; 32]>(),
        ) {
            let start = start % n;
            let length = length.min(n - start);
            prop_assume!(!(start == 0 && length == n));

            let seed = Seed32::from_bytes(root_bytes);
            let content: Vec<u8> = (0..n).map(|i| u8::try_from(i % 251).unwrap_or(0)).collect();
            let fine_root = crate::content::rebuild_fine_root(&seed, &content).expect("n > 0");
            let range = ByteRange::new(start, length);
            let proof = prove_range(&seed, &content, range, n).expect("in bounds");
            let lo = usize::try_from(start).expect("small");
            let hi = usize::try_from(start + length).expect("small");
            let expected = minimal_cover(range, n).expect("in bounds");

            for node in expected.nodes() {
                let address = node.address();
                if address.level() == 0 {
                    continue;
                }
                // The node's parent: drop the last path bit.
                let parent = NodeAddress::try_new(address.level() - 1, address.index() / 2)
                    .expect("a parent is always on the grid");
                let mut tampered = OwnedProof::of(&proof);
                tampered.cover = cover_seeds(&seed, &expected)
                    .iter()
                    .map(|entry| {
                        let this = entry.node().address();
                        if this == address {
                            (
                                parent.level(),
                                parent.index(),
                                descend(&seed, parent).as_bytes().to_vec(),
                            )
                        } else {
                            // The wire form is the payload, not the seed
                            // (D83) — an honest entry must stay honest, or
                            // the substitution would not be the only fault.
                            (
                                this.level(),
                                this.index(),
                                entry.payload().as_bytes().to_vec(),
                            )
                        }
                    })
                    .collect();
                let outcome = tampered.check(&content[lo..hi], n, &fine_root);
                prop_assert!(
                    matches!(
                        outcome,
                        Err(FineTreeError::OverBroadCover | FineTreeError::WrongCoverShape)
                    ),
                    "an ancestor seed was accepted at {address:?}"
                );
            }
        }
    }
}
