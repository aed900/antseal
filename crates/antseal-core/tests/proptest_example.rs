//! Q3 — the worked example of the property-testing conventions
//! (`docs/testing/proptest-conventions.md`).
//!
//! Demonstrates the full consumption pattern every component domain
//! (F/C/G/S/A/R) follows:
//!
//! - proptest arrives through the `antseal_core::test_util::proptest`
//!   re-export (never a per-crate proptest declaration — one frozen
//!   version workspace-wide);
//! - shared strategies come from `antseal_core::test_util::strategies`;
//! - the config is the deterministic project builder
//!   [`strategies::proptest_config`] with a per-block fixed seed, so CI
//!   failures reproduce exactly while `PROPTEST_CASES` (set in the CI
//!   `test` lane) scales case counts per environment;
//! - on failure, proptest persists the seed under
//!   `crates/<crate>/proptest-regressions/` — those files are committed
//!   and never deleted (conventions doc §regressions).

use antseal_core::crypto::hkdf::{UnitId, derive_unit_key};
use antseal_core::crypto::material::MasterSecretRef;
use antseal_core::test_util::proptest::prelude::*;
use antseal_core::test_util::{TEST_MASTER_SECRET_W, strategies};

proptest! {
    #![proptest_config(strategies::proptest_config(0x5EED_0002))]

    /// Example property: for ANY work-shaped unit tiling, (a) the shared
    /// strategy upholds its documented contract — sorted, non-overlapping,
    /// contiguous ranges exactly tiling `[0, total_size)` (the MVP-SPEC.md
    /// line 121 structural invariant downstream domains rely on the
    /// generator for), and (b) consuming it against real crate code, the
    /// per-unit derived keys are pairwise distinct across the work's
    /// `unit_id` ordinals (spec line 77: distinct infos ⇒ independent PRF
    /// outputs).
    #[test]
    fn example_unit_tilings_are_exact_and_derive_distinct_unit_keys(
        tiling in strategies::unit_tiling(8, 64),
    ) {
        // (a) Strategy contract.
        prop_assert!(!tiling.ranges.is_empty());
        let mut expected_start = 0u64;
        for range in &tiling.ranges {
            prop_assert_eq!(range.start, expected_start, "contiguous, in order");
            prop_assert!(range.end >= range.start);
            expected_start = range.end;
        }
        prop_assert_eq!(expected_start, tiling.total_size, "exact tiling of [0, size)");
        if tiling.total_size == 0 {
            // Empty work: exactly one empty unit (spec line 78).
            prop_assert_eq!(tiling.ranges.len(), 1);
        } else {
            for range in &tiling.ranges {
                prop_assert!(range.end > range.start, "non-empty units only");
            }
        }

        // (b) Real consumption: unit_id = manifest-order ordinal; derived
        // unit keys must be pairwise distinct.
        let w = MasterSecretRef::from_bytes(&TEST_MASTER_SECRET_W);
        let keys: Vec<[u8; 32]> = (0..tiling.ranges.len() as u64)
            .map(|unit_id| derive_unit_key(w, UnitId(unit_id)).into_bytes())
            .collect();
        for i in 0..keys.len() {
            for j in (i + 1)..keys.len() {
                prop_assert_ne!(keys[i], keys[j], "unit {} vs {}", i, j);
            }
        }
    }
}
