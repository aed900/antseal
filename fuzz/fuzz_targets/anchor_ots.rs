//! **A23's `.ots` target**: the in-house OpenTimestamps codec over arbitrary
//! bytes — decode, op execution, and every one of D58's limits.
//!
//! This target exists because of a measurement, not a policy. The crate
//! antseal rejected (D58 §3) failed on inputs a fuzzer finds in seconds:
//!
//! - **80 bytes** → uncatchable `SIGABRT`, from `vec![0; attacker_varint]`;
//! - **102 bytes** → a second `SIGABRT`, through an uncapped running value;
//! - **87 bytes** → **panicked in debug and parsed to a different answer in
//!   release** — the worst of the three, because a release build returns a
//!   verdict rather than a crash.
//!
//! All four D58 inputs are committed regression tests
//! (`anchor::ots::tests`). They are the calibration for this target: a
//! fuzzer that cannot rediscover *that class* is not doing its job, so the
//! invariants below are written against that class specifically rather than
//! against "no panic" alone.
//!
//! Invariants per input:
//!
//! - **no panic and no abort.** The abort half is the one only a fuzzer can
//!   check: a `SIGABRT` from an oversized allocation is not catchable by
//!   `catch_unwind`, and on `wasm32` — which is where this codec ships, in
//!   the verifier page — it traps.
//! - **every failure is a typed `anchor-ots-` code.** Not merely
//!   `anchor-`: the `.ots` codec has its own namespace under D91 §6.1, and
//!   an escape into a neighbouring one would mean a rejection is being
//!   reported as the wrong *kind* of failure.
//! - **no allocation beyond the F11 budget, as D58 §10.3 rule 6 scopes it.**
//!   This is the assertion that would have caught D58 §3.1 directly —
//!   `vec![0; n]` for an attacker's `n` is a peak single allocation unrelated
//!   to the input length, which is exactly what `assert_within_budget_*`
//!   bounds. **Amended by D102 (task A100).** The default budget is D10 §4's
//!   clamp rule, which is a rule about **length headers**; this parser's peak
//!   is `walk.rest`, an iterative work stack **count-bounded** by
//!   `MAX_OTS_DEPTH` with no length header to clamp against. That is a third
//!   class, it had never been written down, and applying the clamp constant to
//!   it was `assert_within_budget`'s default argument reaching a call site
//!   nobody checked when this target was added. The exemption below is
//!   `ots_structural_alloc_bytes`, derived in `antseal-core` from the limit
//!   constants and `size_of` — never restated here, per rule 6 clause (a) —
//!   and it is a **function of the input**, so an artifact that never goes
//!   deep gets almost none of it. Both D58 crashers stay fully visible; see
//!   `assert_within_budget_structural`'s docs for the measured argument.
//! - **the release/debug divergence of §3.3 cannot hide**, because the fuzz
//!   profile sets `debug-assertions = true` and `overflow-checks = true` on
//!   an optimised build (`fuzz/Cargo.toml`): a masked shift or a wrapping
//!   add is a finding here rather than a different answer.
//!
//! The driver is `antseal_core::anchor::fuzz_entry::drive_ots`, in the crate
//! rather than here, so the ordinary suite compiles and runs it and it
//! cannot rot between fuzz sessions. It reads the anchor digest from the
//! artifact's own start-digest field — see that function's docs for why a
//! head-split would make every well-formed input die at step 5 of 7, before
//! the walk where all four crashers live.
//!
//! Seed corpus: `testdata/anchors/A25-bootstrap/`, wired in
//! `scripts/fuzz.sh`'s `corpus_dirs()`. Real `.ots` artifacts are valid
//! inputs byte for byte, which is a property of the driver above and the
//! reason this target needs no derived corpus.

#![no_main]

use libfuzzer_sys::fuzz_target;

use antseal_core::anchor::fuzz_entry::drive_ots;
use antseal_core::anchor::ots::ots_structural_alloc_bytes;
use antseal_fuzz::{Counting, assert_within_budget_structural, measure, selftest_tripwire};

#[global_allocator]
static ALLOC: Counting = Counting;

fuzz_target!(|data: &[u8]| {
    selftest_tripwire("anchor_ots");

    let (outcome, budget) = measure(|| drive_ots(data));

    if let Err(e) = outcome {
        assert!(
            e.code().starts_with("anchor-ots-"),
            "an .ots failure escaped its namespace: {}",
            e.code()
        );
    }

    assert_within_budget_structural(
        "anchor::ots::parse_ots",
        data.len(),
        budget,
        ots_structural_alloc_bytes(data.len()),
    );
});
