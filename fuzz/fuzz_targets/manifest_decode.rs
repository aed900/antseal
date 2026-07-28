//! **F17's manifest-decoder fuzz target**: `Manifest::decode` over arbitrary
//! bytes.
//!
//! The input **is** the candidate manifest envelope, byte for byte — there
//! is no entropy layout to decode and no per-process fixture build, so every
//! iteration is one decode and libFuzzer's mutators operate directly on the
//! wire format. (R10's `verify_bundle` target reads its input as entropy
//! instead, and the reason the two differ is written down in
//! `antseal_core::test_util::codec_fuzz`.)
//!
//! One call covers **layers 2 and 3** of registry §7.6.3: `Manifest::decode`
//! runs the envelope pass and then strict-decodes the embedded body from the
//! bytes it borrowed. Both invariants are asserted per input:
//!
//! - **no panic** — the assertion is the return; there is deliberately no
//!   `catch_unwind`, because swallowing the panic would defeat the property;
//! - **no allocation beyond the F11 budget** — measured, not assumed. This
//!   generalizes `crates/antseal-core/tests/parser_caps_alloc.rs`'s two
//!   hand-picked hostile inputs to every input libFuzzer can invent.
//!
//! Seed corpus: `testdata/fuzz-seeds/manifest_decode/` — every distinct
//! manifest R6 builds plus F15's manifest-family tamper fixtures. Run it
//! with `scripts/fuzz.sh`, which wires the corpus paths.

#![no_main]

use libfuzzer_sys::fuzz_target;

use antseal_core::test_util::codec_fuzz::drive_manifest;
use antseal_fuzz::{Counting, assert_within_budget, measure, selftest_tripwire};

#[global_allocator]
static ALLOC: Counting = Counting;

fuzz_target!(|data: &[u8]| {
    selftest_tripwire("manifest_decode");

    let (_outcome, budget) = measure(|| drive_manifest(data));
    assert_within_budget("Manifest::decode", data.len(), budget);
});
