//! Fine-tree cost estimation (tasks/G.md G10; MVP-SPEC.md line 85).
//!
//! > `seal` prints an estimated fine-tree cost for large files (~5–7 SHA-256
//! > compressions per byte; construction must stream with O(log n) memory)
//! > — MVP-SPEC.md line 85
//!
//! This module is that estimate, computed from the file's byte count alone —
//! no hashing, no I/O, `O(log n)` arithmetic — so the CLI can print it
//! *before* committing to a seal (U15 wires it at M1).
//!
//! # The formula
//!
//! Three preimage classes, each with a fixed SHA-256 block count (the cost
//! table in [`super::build`]):
//!
//! ```text
//! compressions(n) =      n · 1     leaf   0x00 ‖ salt(16) ‖ LE64(8) ‖ byte(1)   26 B → 1 block
//!                 + (n − 1) · 2     node   0x01 ‖ left(32) ‖ right(32)           65 B → 2 blocks
//!                 +   G(n) · 1     GGM    0x06 ‖ seed(32) ‖ b(1)                34 B → 1 block
//!
//! G(n) = ( Σ_{l=0..d} ⌈n / 2^(d−l)⌉ ) − 1,   d = ⌈log₂ n⌉
//! ```
//!
//! `G(n)` is the number of *edges* in the union of the root-to-leaf paths of
//! leaves `0..n` — exactly what the DFS co-traversal walks, hence `≈ 2n` and
//! bounded by `2·2^d`. Summing: `1 + 2 + 2 ≈ **5 compressions per byte**`,
//! the bottom of the spec's "~5–7" figure.
//!
//! # This estimate is exact, and that is deliberate
//!
//! The construction's cost depends only on `n`, so the "estimate" is the
//! *identity* G9's instrumentation measures — asserted equal, not merely
//! bracketed, in both modules' tests. Keeping it exact means a user's printed
//! number and CI's measured number can never disagree, and it gives G18 a
//! reference to hold its budgets against. The "~" in the spec belongs to the
//! per-byte ratio (which drifts with `n` because there are `n − 1` interior
//! nodes, not `n`), not to the count.
//!
//! Wall-clock and memory *budgets* are **not** here: those are G18's, gated
//! on the still-open decision D26.

use crate::content::ggm::depth_for_leaf_count;

use super::build::FineTreeStats;

/// The predicted cost of building one file's fine tree (module docs).
///
/// Shaped for the seal-time print: the three counts a reader can sanity-check
/// individually, the total, and the per-byte ratio the spec quotes. `Display`
/// renders the one-line form U prints.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CostEstimate {
    /// The file's leaf count `n` (its byte-domain length).
    pub leaf_count: u64,
    /// Leaf preimages: exactly `n`.
    pub leaf_hashes: u64,
    /// Interior-node preimages: exactly `n − 1` (0 for `n <= 1`).
    pub node_hashes: u64,
    /// GGM child derivations: the path-union edge count `G(n)`.
    pub ggm_derivations: u64,
}

impl CostEstimate {
    /// Total SHA-256 compression-function invocations, weighted by each
    /// preimage's block count — the same weighting
    /// [`FineTreeStats::sha256_compressions`] applies to measured counts.
    #[must_use]
    pub const fn sha256_compressions(&self) -> u64 {
        self.leaf_hashes
            .saturating_mul(FineTreeStats::LEAF_BLOCKS)
            .saturating_add(self.node_hashes.saturating_mul(FineTreeStats::NODE_BLOCKS))
            .saturating_add(
                self.ggm_derivations
                    .saturating_mul(FineTreeStats::GGM_BLOCKS),
            )
    }

    /// Compressions per input byte in **thousandths** — `5_000` is the spec's
    /// "~5 per byte" (MVP-SPEC.md line 85). Integer milli-units, matching
    /// [`FineTreeStats::compressions_per_byte_milli`]; `antseal-core` carries
    /// no floating point.
    #[must_use]
    pub const fn compressions_per_byte_milli(&self) -> u64 {
        if self.leaf_count == 0 {
            return 0;
        }
        self.sha256_compressions().saturating_mul(1_000) / self.leaf_count
    }

    /// Whether an actual construction's instrumentation matches this
    /// prediction exactly (module docs: the estimate is the identity).
    ///
    /// The tie between G10 and G9/G18: a change to either accounting breaks
    /// this, which is the point.
    #[must_use]
    pub const fn matches_measured(&self, measured: &FineTreeStats) -> bool {
        self.leaf_hashes == measured.leaf_hashes
            && self.node_hashes == measured.node_hashes
            && self.ggm_derivations == measured.ggm_derivations
    }
}

impl core::fmt::Display for CostEstimate {
    /// The seal-time one-liner, e.g.
    /// `~5242875 SHA-256 compressions (~4.999 per byte) for 1048576 bytes`.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let milli = self.compressions_per_byte_milli();
        write!(
            f,
            "~{} SHA-256 compressions (~{}.{:03} per byte) for {} bytes",
            self.sha256_compressions(),
            milli / 1_000,
            milli % 1_000,
            self.leaf_count
        )
    }
}

/// Predict the cost of building the fine tree of an `n`-byte file
/// (MVP-SPEC.md line 85; module docs for the formula).
///
/// Pure arithmetic in `O(log n)` — nothing is hashed and no buffer is
/// allocated, so it is safe to call on a multi-gigabyte file before deciding
/// to seal it.
///
/// `n = 0` yields an all-zero estimate: an empty file has no fine tree at all
/// (MVP-SPEC.md line 78).
///
/// ```
/// use antseal_core::content::estimate_fine_tree_cost;
///
/// let estimate = estimate_fine_tree_cost(1 << 20);
/// assert_eq!(estimate.leaf_hashes, 1 << 20);
/// // ~5 compressions per byte — the bottom of the spec's ~5-7 figure.
/// assert!((4_900..=7_000).contains(&estimate.compressions_per_byte_milli()));
/// assert_eq!(estimate_fine_tree_cost(0), Default::default());
/// ```
#[must_use]
pub fn estimate_fine_tree_cost(leaf_count: u64) -> CostEstimate {
    let Some(depth) = depth_for_leaf_count(leaf_count) else {
        return CostEstimate::default();
    };
    CostEstimate {
        leaf_count,
        leaf_hashes: leaf_count,
        node_hashes: leaf_count - 1,
        ggm_derivations: ggm_path_union_edges(leaf_count, depth),
    }
}

/// `G(n) = ( Σ_{l=0..d} ⌈n / 2^(d−l)⌉ ) − 1` — the edges in the union of the
/// root-to-leaf paths of leaves `0..n` on the depth-`d` grid (module docs).
///
/// `u128` throughout: at `d = 64` the divisor is `2^64`, and the sum can
/// reach `≈ 2n`, neither of which fits a `u64` at the extremes.
fn ggm_path_union_edges(leaf_count: u64, depth: u8) -> u64 {
    let n = u128::from(leaf_count);
    let mut nodes: u128 = 0;
    for level in 0..=depth {
        // `depth - level <= 64`, in range for a u128 shift.
        nodes += n.div_ceil(1u128 << (depth - level));
    }
    // The root always contributes one node, so the subtraction cannot wrap.
    u64::try_from(nodes.saturating_sub(1)).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::content::fine_tree::build::FineTreeBuilder;
    use crate::crypto::material::Seed32;
    use crate::test_util::TEST_MASTER_SECRET_W;
    use crate::test_util::strategies::proptest_config;
    use proptest::prelude::*;

    fn measured(leaf_count: u64) -> FineTreeStats {
        let seed = Seed32::from_bytes(TEST_MASTER_SECRET_W);
        let content: Vec<u8> = (0..leaf_count)
            .map(|i| u8::try_from(i % 251).unwrap_or(0))
            .collect();
        let mut builder = FineTreeBuilder::new(&seed, leaf_count).expect("n > 0");
        builder.feed(&content).expect("exactly n");
        builder.finish().expect("exactly n").1
    }

    /// G10 accept: the estimate brackets — in fact **equals** — G9's measured
    /// counts, including at `n` just above a power of two (worst GGM
    /// padding) and at the `n = 1` / `n = 2` corners.
    #[test]
    fn estimate_matches_measured_counts() {
        for n in [
            1u64, 2, 3, 4, 5, 6, 7, 8, 9, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 1_000,
            1_024, 1_025,
        ] {
            let estimate = estimate_fine_tree_cost(n);
            let stats = measured(n);
            assert!(
                estimate.matches_measured(&stats),
                "n = {n}: estimate {estimate:?} != measured {stats:?}"
            );
            assert_eq!(
                estimate.sha256_compressions(),
                stats.sha256_compressions(),
                "n = {n}"
            );
            assert_eq!(
                estimate.compressions_per_byte_milli(),
                stats.compressions_per_byte_milli(),
                "n = {n}"
            );
        }
    }

    /// The empty file has no tree and therefore no cost (MVP-SPEC.md
    /// line 78).
    #[test]
    fn the_empty_file_costs_nothing() {
        let estimate = estimate_fine_tree_cost(0);
        assert_eq!(estimate, CostEstimate::default());
        assert_eq!(estimate.sha256_compressions(), 0);
        assert_eq!(estimate.compressions_per_byte_milli(), 0);
    }

    /// The spec's per-byte figure, checked where it is meant to apply — large
    /// files. The asymptote is exactly 5 and is approached from below (there
    /// are `n − 1` interior nodes, not `n`), so the useful statement is "at
    /// the bottom of ~5–7, never above it". The concrete budget belongs to
    /// G18 / decision D26.
    #[test]
    fn large_files_sit_at_the_bottom_of_the_spec_envelope() {
        for n in [
            1u64 << 12,
            (1 << 12) + 1,
            1 << 20,
            (1 << 20) + 1,
            1 << 30,
            100_000_000,
        ] {
            let milli = estimate_fine_tree_cost(n).compressions_per_byte_milli();
            assert!(
                (4_990..=7_000).contains(&milli),
                "n = {n}: {milli} milli-compressions/byte outside the spec envelope"
            );
        }
    }

    /// The GGM term is bounded by `2·2^d` as the task entry states, and is
    /// `≈ 2n` in practice.
    #[test]
    fn the_ggm_term_stays_within_its_stated_bound() {
        for n in [1u64, 2, 5, 6, 9, 17, 1_000, 65_537] {
            let estimate = estimate_fine_tree_cost(n);
            let depth = depth_for_leaf_count(n).expect("n > 0");
            let bound = 2u128 * (1u128 << depth);
            assert!(
                u128::from(estimate.ggm_derivations) <= bound,
                "n = {n}: {} > 2·2^{depth}",
                estimate.ggm_derivations
            );
            assert!(
                u128::from(estimate.ggm_derivations) <= 2 * u128::from(n) + u128::from(depth),
                "n = {n}: the GGM term should amortize to ~2 per leaf"
            );
        }
    }

    /// The seal-time rendering U prints.
    #[test]
    fn display_renders_the_seal_time_line() {
        let estimate = estimate_fine_tree_cost(6);
        assert_eq!(
            estimate.to_string(),
            "~27 SHA-256 compressions (~4.500 per byte) for 6 bytes"
        );
        assert_eq!(estimate.leaf_hashes, 6);
        assert_eq!(estimate.node_hashes, 5);
        assert_eq!(estimate.ggm_derivations, 11);
    }

    /// A hostile `size` field must not overflow or panic the estimator —
    /// `seal` prints it before anything is validated.
    #[test]
    fn extreme_leaf_counts_are_panic_free() {
        for n in [u64::MAX, (1u64 << 63) + 1, 1u64 << 63] {
            let estimate = estimate_fine_tree_cost(n);
            assert_eq!(estimate.leaf_hashes, n);
            assert!(estimate.sha256_compressions() > 0);
            assert!(!estimate.to_string().is_empty());
        }
    }

    proptest! {
        #![proptest_config(proptest_config(0x0064_0010))]

        /// Estimate and measurement agree for every shape (the G10↔G9 tie).
        #[test]
        fn estimate_equals_measurement(n in 1u64..=400) {
            prop_assert!(estimate_fine_tree_cost(n).matches_measured(&measured(n)));
        }

        /// Monotone in `n` and never panicking, at any magnitude.
        #[test]
        fn estimate_is_monotone_and_total(n in 1u64..=u64::MAX / 4) {
            let here = estimate_fine_tree_cost(n);
            let next = estimate_fine_tree_cost(n + 1);
            prop_assert!(next.sha256_compressions() >= here.sha256_compressions());
            prop_assert_eq!(here.leaf_hashes, n);
            prop_assert_eq!(here.node_hashes, n - 1);
        }
    }
}
