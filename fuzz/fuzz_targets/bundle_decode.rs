//! **F17's bundle-decoder fuzz target**: `SealProof::decode` over arbitrary
//! bytes — all **three** strict layers of registry §7.6.3 in one call.
//!
//! The input is the candidate `.sealproof`, byte for byte (rationale:
//! `antseal_core::test_util::codec_fuzz`). What this target adds over
//! `manifest_decode` is the *nesting*: layer 1 decides the bundle's own
//! schema without ever opening the embedded manifest (D78), then layers 2
//! and 3 run over a **sub-slice** of the same buffer. A nested decoder is
//! where a hostile length head is most likely to be believed — the inner
//! pass is handed a slice whose bounds the outer pass computed — which is
//! exactly why the allocation budget is asserted here rather than assumed.
//!
//! Invariants per input:
//!
//! - **no panic**, at any of the three layers;
//! - **no allocation beyond the F11 budget** — peak single allocation stays
//!   within the input's own length plus a fixed constant, the observable
//!   form of decision D10 §4's clamp rule.
//!
//! Seed corpus: `testdata/fuzz-seeds/bundle_decode/` — every R6 catalogue
//! shape (including the UNANCHORED bundle and the every-anchor-kind ones)
//! plus F15's bundle-family tamper fixtures.

#![no_main]

use libfuzzer_sys::fuzz_target;

use antseal_core::test_util::codec_fuzz::drive_bundle;
use antseal_fuzz::{Counting, assert_within_budget, measure, selftest_tripwire};

#[global_allocator]
static ALLOC: Counting = Counting;

fuzz_target!(|data: &[u8]| {
    selftest_tripwire("bundle_decode");

    let (_outcome, budget) = measure(|| drive_bundle(data));
    assert_within_budget("SealProof::decode", data.len(), budget);
});
