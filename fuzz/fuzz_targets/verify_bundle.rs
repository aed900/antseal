//! **R10's fuzz target**: `verify_bundle` never panics.
//!
//! The invariant, stated once and shared with the in-suite property tests
//! (`crates/antseal-core/tests/verify_fuzz.rs`):
//!
//! > For every byte string, `verify_bundle` returns a typed `VerifyError`
//! > or a `VerificationReport`. It never panics and never aborts.
//!
//! # Why this file is nearly empty
//!
//! Everything interesting — the mutation set, the seed corpus, the driver —
//! is in `antseal_core::test_util::bundle_mutators`, behind `test-util`,
//! and is exercised by the ordinary test suite on every CI build. That is
//! deliberate. A fuzz target carrying its own mutators is only ever
//! exercised when someone runs the fuzzer, so it rots between runs and a
//! crash it finds may not reproduce under the test suite. Here the two
//! share one code path, so a libFuzzer crash reproduces as a plain unit
//! test over the same entropy bytes.
//!
//! It also means this crate needs no `arbitrary` impl: the driver
//! interprets raw entropy itself, under a layout documented on
//! `mutate_from_entropy` so a crashing input can be decoded by hand.
//!
//! # Relationship to F17
//!
//! F17 fuzzes the **CBOR decoders** and expects most inputs to die at the
//! first byte. This target's job is the opposite: get *past* the decoder
//! and stress the stages behind it. `Corpus::Reject` is returned for inputs
//! that never made it out of the codec, so libFuzzer stops accumulating
//! corpus entries that only duplicate F17's coverage, and the corpus stays
//! concentrated where this target is actually useful.

#![no_main]

use libfuzzer_sys::{Corpus, fuzz_target};

use antseal_core::test_util::bundle_mutators::{Outcome, mutate_from_entropy, seed_bytes};
use antseal_fuzz::selftest_tripwire;

/// The seed corpus, built once per process.
///
/// R6's constructor signs and encrypts, so building it per iteration would
/// dominate the run and starve the thing under test. It is deterministic,
/// so one build is exactly as good as many.
fn corpus() -> &'static [Vec<u8>] {
    static CORPUS: std::sync::OnceLock<Vec<Vec<u8>>> = std::sync::OnceLock::new();
    CORPUS.get_or_init(seed_bytes)
}

fuzz_target!(|data: &[u8]| -> Corpus {
    // Q9's crash-artifact demonstration, armed per target by
    // `scripts/fuzz.sh selftest` and inert otherwise (fuzz/src/lib.rs).
    selftest_tripwire("verify_bundle");

    let bundle = mutate_from_entropy(data, corpus());

    // The assertion is the return: a panic anywhere inside `verify_bundle`
    // aborts the process and libFuzzer records the crash. There is
    // deliberately no `catch_unwind` — swallowing the panic would defeat
    // the entire property.
    match antseal_core::test_util::bundle_mutators::drive(&bundle) {
        // Reached the evidence stages: worth keeping in the corpus.
        outcome if outcome.reached_the_pipeline() => Corpus::Keep,
        // Died in the codec — F17's territory, not this target's. Rejecting
        // it keeps the corpus concentrated on inputs that exercise the
        // stages behind the decoder.
        Outcome::Rejected(_) | Outcome::Verified => Corpus::Reject,
    }
});
