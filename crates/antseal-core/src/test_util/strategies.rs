//! Shared proptest strategies + the deterministic config builder (Q3).
//!
//! Conventions these implement: `docs/testing/proptest-conventions.md`.
//! Domains (F/C/G/S/A/R) import from here instead of redefining
//! work-shaped generators, so structural invariants (e.g. "unit ranges
//! exactly tile `[0, size)`", MVP-SPEC.md line 121) are generated the same
//! way everywhere.
//!
//! Values produced by these strategies exist only in test memory — the
//! committed-fixture secret-material convention (`testdata/README.md`)
//! does not restrict them; anything *committed* must derive from
//! [`super::TEST_MASTER_SECRET_W`].

use core::ops::Range;

use proptest::prelude::*;
use proptest::test_runner::RngSeed;

/// The project-standard proptest configuration (Q3):
///
/// - **deterministic**: the RNG seed is fixed per `proptest!` block —
///   every test picks its own stable literal, so CI failures reproduce
///   exactly and case exploration never depends on the runner;
/// - **environment-tunable case counts**: everything else starts from
///   [`ProptestConfig::default()`], which honours proptest's own
///   environment overrides — CI raises `PROPTEST_CASES` (set in the `test`
///   lane), local runs use the default, and tests with spec-mandated
///   floors (e.g. C3's ≥10 000) hardcode `cases` on top of this builder.
///
/// ```rust
/// use antseal_core::test_util::proptest::prelude::*;
/// use antseal_core::test_util::strategies;
///
/// proptest! {
///     #![proptest_config(strategies::proptest_config(0x5EED_0001))]
///     #[test]
///     fn doubling_is_even(n in 0u32..1000) {
///         prop_assert_eq!((n * 2) % 2, 0);
///     }
/// }
/// ```
#[must_use]
pub fn proptest_config(rng_seed: u64) -> ProptestConfig {
    ProptestConfig {
        rng_seed: RngSeed::Fixed(rng_seed),
        ..ProptestConfig::default()
    }
}

/// A work-shaped unit tiling: `ranges` are sorted, non-overlapping,
/// contiguous byte ranges exactly tiling `[0, total_size)` — the verifier
/// structural invariant for non-mirror units (MVP-SPEC.md line 121). The
/// empty-work case is one empty unit (`0..0`, spec line 78).
///
/// `unit_id`s are the range indices in order (work-global manifest-order
/// ordinals, spec line 76).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnitTiling {
    /// Total tiled size in bytes (0 for the empty work).
    pub total_size: u64,
    /// The tiling ranges, in order; never empty.
    pub ranges: Vec<Range<u64>>,
}

/// Strategy for [`UnitTiling`]: 1..=`max_units` units of 1..=`max_unit_len`
/// bytes each (plus the occasional empty-work case). Both bounds must be
/// ≥ 1 and small enough that the total cannot overflow `u64` (test-util
/// contract; violations abort the strategy loudly rather than generating
/// nonsense).
pub fn unit_tiling(max_units: usize, max_unit_len: u64) -> impl Strategy<Value = UnitTiling> {
    assert!(max_units >= 1, "unit_tiling: max_units must be >= 1");
    assert!(max_unit_len >= 1, "unit_tiling: max_unit_len must be >= 1");
    let tiled = proptest::collection::vec(1..=max_unit_len, 1..=max_units).prop_map(|lens| {
        let mut ranges = Vec::with_capacity(lens.len());
        let mut offset: u64 = 0;
        for len in lens {
            let end = offset
                .checked_add(len)
                .expect("unit_tiling bounds must not overflow u64");
            ranges.push(offset..end);
            offset = end;
        }
        UnitTiling {
            total_size: offset,
            ranges,
        }
    });
    // (`once(..).collect()` rather than `vec![0..0]`: the literal one-empty-
    // range Vec is exactly what the empty work means — one empty unit.)
    let empty_work = UnitTiling {
        total_size: 0,
        ranges: core::iter::once(0..0).collect(),
    };
    prop_oneof![
        // Empty work: one empty unit (MVP-SPEC.md line 78).
        1 => Just(empty_work),
        9 => tiled,
    ]
}
