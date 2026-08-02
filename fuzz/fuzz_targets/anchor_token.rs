//! **A5's anchor-stage fuzz target**: the whole RFC 3161 / CMS / X.509 path
//! over arbitrary bytes.
//!
//! This is the layer that eats attacker-controlled DER. A `.sealproof` is
//! unsigned (D8), so its anchor artifacts are chosen by whoever hands you the
//! bundle, and nothing upstream of this stage has parsed a single byte of
//! them — verify stage 1's job over an anchor field is complete when the
//! `bstr` decodes canonically and passes D10's byte cap (F1).
//!
//! Invariants per input:
//!
//! - **no panic and no abort**. The abort half is why this target exists
//!   rather than a proptest: a stack overflow is not a panic, is not
//!   catchable, and traps on `wasm32`. D60 §2.4 reached one with a recursive
//!   DER walker at depth 20 000 in 83 407 bytes, which is why
//!   `antseal-core` contains no such walker and depth is `der`'s guard. What
//!   this target searches for is a path that *escapes* that guard — every
//!   re-parse of an inner field starts a fresh depth budget, and this stage
//!   has four (`TSTInfo` out of `eContent`, a certificate out of the bag, an
//!   ESS attribute value, an extension's `extnValue`).
//! - **every failure is a typed `anchor-` error**, never a generic one and
//!   never a borrowed prefix (D91 §6.1).
//! - **no allocation beyond the F11 budget** — a 1 MiB token must not induce
//!   a gigabyte, which is the shape a believed length head takes.
//!
//! Both the bundle path (`expected_nonce = None`) and the capture path
//! (`Some`, attacker-chosen) are driven, alternating on the input's first
//! bit: the `None` arm is the one a hostile bundle reaches, and the `Some`
//! arm is the only place the nonce comparison exists at all.
//!
//! Seed corpus: `testdata/anchors/A25-bootstrap/` — nine live TSA responses,
//! five derived BER/reordering variants, and the FreeTSA D59 pair. Real
//! tokens are the seeds that matter: a mutation of a valid CMS structure
//! reaches far deeper than any random buffer.

#![no_main]

use libfuzzer_sys::fuzz_target;

use antseal_core::anchor::fuzz_entry::{drive_anchor_token, drive_anchor_token_with_nonce};
use antseal_fuzz::{Counting, assert_within_budget, measure, selftest_tripwire};

#[global_allocator]
static ALLOC: Counting = Counting;

fuzz_target!(|data: &[u8]| {
    selftest_tripwire("anchor_token");

    // Alternate the two paths on one input bit rather than running both on
    // every input: running both would halve the throughput and, worse, would
    // make the coverage feedback for one path indistinguishable from the
    // other's.
    let capture_path = data.first().is_some_and(|b| b & 1 == 1);

    let (outcome, budget) = measure(|| {
        if capture_path {
            drive_anchor_token_with_nonce(data)
        } else {
            drive_anchor_token(data)
        }
    });

    if let Err(e) = outcome {
        assert!(
            e.code().starts_with("anchor-"),
            "an anchor-stage failure escaped its namespace: {}",
            e.code()
        );
    }

    assert_within_budget("anchor::tsa::verify_token", data.len(), budget);
});
