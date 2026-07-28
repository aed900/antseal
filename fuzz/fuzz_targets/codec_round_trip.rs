//! **F17's round-trip fuzz target**: decode-success implies canonical-byte
//! identity.
//!
//! The law, stated once in
//! [`antseal_core::test_util::codec_fuzz::round_trip`] and shared with the
//! in-suite half:
//!
//! > For every byte string: whatever strict-decodes re-encodes to the
//! > **same bytes** and re-decodes to the **same value**, with `work_id`
//! > and `anchor_digest` unchanged.
//!
//! # Why this is a fuzz target and not only a property test
//!
//! F16 (`crates/antseal-core/tests/codec_properties.rs`) already states the
//! round-trip laws — over **generated schema-valid values**. A generator can
//! only build documents it knows how to build, and the interesting inputs
//! are precisely the ones it does not: a manifest whose `signatures` map
//! carries an algorithm the strategy never emits, a bundle whose section
//! ordering sits exactly on a boundary, a body whose string fields hold
//! bytes no generator would choose. This target starts from *arbitrary
//! bytes* and keeps only what the strict decoder accepts, so the law is
//! tested on the decoder's real acceptance set rather than on the
//! generator's image of it.
//!
//! That matters because the law is load-bearing rather than cosmetic:
//! `work_id = SHA-256(manifest body)` and `anchor_digest = SHA-256(manifest
//! envelope)` are digests of *received* bytes (MVP-SPEC.md lines 74–75). A
//! document that decoded and then re-encoded differently would mean "the
//! bytes I received" and "the bytes I would produce" are distinguishable —
//! which is the precondition for a signature that verifies over one and a
//! digest that was anchored over the other.
//!
//! # Corpus
//!
//! This target has **no corpus directory of its own**: its input space is
//! the union of `manifest_decode`'s and `bundle_decode`'s, so
//! `scripts/fuzz.sh` passes both seed directories rather than committing the
//! same bytes a second time.

#![no_main]

use libfuzzer_sys::{Corpus, fuzz_target};

use antseal_core::test_util::codec_fuzz::{RoundTripped, round_trip};
use antseal_fuzz::{Counting, assert_within_budget, measure, selftest_tripwire};

#[global_allocator]
static ALLOC: Counting = Counting;

fuzz_target!(|data: &[u8]| -> Corpus {
    selftest_tripwire("codec_round_trip");

    let (verdict, budget) = measure(|| round_trip(data));

    // A violated law is a crash, carrying its own diagnosis: the message is
    // the `RoundTripViolation`'s `Display`, which names the broken law, the
    // artifact and the first differing offset. No backtrace needed.
    let arm = match verdict {
        Ok(arm) => arm,
        Err(violation) => panic!("round-trip law violated: {violation}"),
    };

    // The round trip re-encodes, so it legitimately allocates more than a
    // bare decode; the budget's `TOTAL_FACTOR` covers that and the
    // peak-single clamp still holds.
    assert_within_budget("round_trip", data.len(), budget);

    match arm {
        // Something decoded: worth keeping, since inputs that reach the law
        // at all are the scarce resource here.
        RoundTripped::Manifest | RoundTripped::Bundle => Corpus::Keep,
        // Nothing decoded, so the law held vacuously. Rejecting keeps the
        // corpus concentrated on inputs that actually exercise it — the
        // decoders' own rejection paths are `manifest_decode`'s and
        // `bundle_decode`'s territory, not this target's.
        RoundTripped::Neither => Corpus::Reject,
    }
});
