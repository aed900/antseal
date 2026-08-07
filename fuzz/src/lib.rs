//! Shared harness for antseal's cargo-fuzz targets (F17/Q9).
//!
//! Two things live here because every target needs them and neither belongs
//! in `antseal-core`:
//!
//! 1. **[`Counting`]** — a global allocator that measures what a decode
//!    actually allocated, so F11's budget can be asserted on *every* fuzz
//!    input rather than on the two hand-picked ones in
//!    `crates/antseal-core/tests/parser_caps_alloc.rs`.
//! 2. **[`selftest_tripwire`]** — the permanent, env-gated crash injector
//!    that proves the whole pipeline can go red: target → libFuzzer crash →
//!    artifact written → CI lane fails → artifact uploaded.
//!
//! # Why the tripwire is permanent rather than a temporary edit
//!
//! F17's accept says "a temporarily injected panic is caught by the target,
//! then removed", and Q9's says the crash-artifact path is "demonstrated
//! with a synthetic crash". A demonstration that is deleted afterwards
//! proves the pipeline worked *once*, on someone's laptop, at a commit that
//! no longer exists. This repository already prefers the other shape — the
//! `secret-guard` lane plants fakes and re-proves its detector on every run,
//! `wasm-bitmatch` injects a divergence before it trusts a match — and this
//! is the same move: `ANTSEAL_FUZZ_SELFTEST=<target>` makes exactly that
//! target abort on its first input, and `scripts/fuzz.sh selftest` runs it
//! before the smoke lane's verdict is believed.
//!
//! The tripwire lives in the fuzz crate only. Nothing in `antseal-core`
//! reads an environment variable, and nothing that ships can panic on
//! demand.

// A `#[global_allocator]` requires `unsafe impl GlobalAlloc`, whose four
// methods are `unsafe fn` by definition; there is no safe API that observes
// allocation. The workspace denies `unsafe_code` and its sanctioned opt-out
// is exactly this: an `#![allow]` at the crate root with a written
// justification. `antseal-core` itself remains entirely `unsafe`-free — this
// crate is detached from the workspace and ships nothing.
//
// Invariants upheld by the `unsafe` in [`Counting`] (same three as
// `crates/antseal-core/tests/parser_caps_alloc.rs`, which is the precedent):
//
// 1. Every method forwards unchanged to `System`, with identical arguments
//    and no reinterpretation of `ptr` or `Layout`, so `dealloc` always
//    receives a pointer from the same allocator with the same layout.
// 2. The added code is allocation-free and lock-free — three `Relaxed`
//    atomics — so it can neither re-enter the allocator nor deadlock inside
//    one.
// 3. The counters are observation-only: no control-flow decision inside the
//    allocator depends on them, so an arbitrary counter value cannot change
//    which pointer is returned.
#![allow(unsafe_code)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

// ---------------------------------------------------------------------------
// the F11 allocation budget
// ---------------------------------------------------------------------------

static ARMED: AtomicBool = AtomicBool::new(false);
static PEAK_SINGLE: AtomicUsize = AtomicUsize::new(0);
static TOTAL: AtomicUsize = AtomicUsize::new(0);

/// A counting global allocator, armed only around the call under test.
pub struct Counting;

// SAFETY: see the crate-root justification.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if ARMED.load(Ordering::Relaxed) {
            PEAK_SINGLE.fetch_max(layout.size(), Ordering::Relaxed);
            TOTAL.fetch_add(layout.size(), Ordering::Relaxed);
        }
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if ARMED.load(Ordering::Relaxed) {
            PEAK_SINGLE.fetch_max(new_size, Ordering::Relaxed);
            TOTAL.fetch_add(new_size, Ordering::Relaxed);
        }
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

/// Fixed overhead a parser is allowed regardless of input size: error
/// values, decoder state, the odd `String`.
///
/// Identical to the constant `parser_caps_alloc.rs` uses, and for the same
/// reason: any slack big enough to hide a length-driven allocation would
/// defeat the assertion.
pub const SLACK: usize = 4 * 1024;

/// Bytes of `Vec` capacity one clamped **element** costs.
///
/// # The finding this constant recorded, and its fix
///
/// `crates/antseal-core/tests/parser_caps_alloc.rs` stated decision D10 §4's
/// consequence as
///
/// > an attacker can never make the parser allocate more than the
/// > attacker's own bytes — modulo a small constant … which is what `SLACK`
/// > covers
///
/// and until task **F30** that was **not true in general**. The clamp was
/// `Vec::with_capacity(min(claimed, remaining_input))` where the left side
/// counts *elements* and the right side counts *bytes*, so the true bound was
/// `remaining_input × size_of::<Element>()`. That test passed only because
/// both of its inputs were under 32 bytes, so the multiplier disappeared
/// inside a 4 KiB `SLACK`.
///
/// The first fuzz run over the committed corpus surfaced it immediately: a
/// **152-byte** input whose `signatures` map head claims 59 638 entries drove
/// a **4 704-byte** single allocation — 147 elements of `(SigAlg, Vec<u8>)`,
/// 32 B each. The amplification factor was `size_of::<Element>()`: a property
/// of the type, not of the input. Measured element sizes at the time
/// (x86-64), across every clamped-allocation site: `FileEntry` 192,
/// `OtsAnchor` 136, `UnitEntry` 128, `CoveredReveal` 112, `TsaAnchor` 88,
/// `NonCoveredReveal` 80, `FullReveal` 64, `TouchedFile` 48,
/// `(SigAlg, Vec<u8>)` 32 — so this constant was **256**, the largest of them
/// rounded up.
///
/// **F30 removed the multiplier**: `clamped_capacity` is now generic in the
/// element type and divides the remaining bytes by its width, so the
/// reservation is bounded in *bytes* by the remaining input:
/// `capacity × size_of::<T>() ≤ remaining ≤ input.len()`. The same two heads
/// now reserve 65 536 B for a 65 549 B input and 19 968 B for a 20 005 B one
/// (`crates/antseal-core/tests/parser_caps_alloc.rs`,
/// `the_reservation_never_exceeds_the_input_that_drove_it`). One input byte
/// buys at most one reserved byte, which is why this is **1** and why the
/// strong claim can be stated literally again.
pub const MAX_CLAMPED_ELEMENT_BYTES: usize = 1;

/// How many times its own input a decode may allocate **in total**.
///
/// The sharp claim is about [`peak_single`](Budget::peak_single) — that is
/// where a hostile length head shows up. `total` is necessarily larger on a
/// decode that succeeds: reveal sections own their ciphertexts, nested
/// layers each decode their own slice, and the round-trip target re-encodes
/// on top. What `total` still forbids is the thing that actually hurts —
/// **super-linear** blowup — so the factor is deliberately generous (a
/// handful of clamped containers plus their payload copies) and the
/// assertion is about the *shape* of the growth rather than its constant.
///
/// **Independent of [`MAX_CLAMPED_ELEMENT_BYTES`]** (F30). It used to be
/// derived from it (`4 ×`), which was a coincidence of magnitude rather than
/// a relationship: the peak bound is about the *clamp*, the total bound is
/// about payload copies and re-encoding, and F30 moved the first without
/// having any evidence about the second. Tightening this is its own task
/// with its own measurement.
pub const TOTAL_FACTOR: usize = 1_024;

/// Peak-single factor for a target that **re-encodes**, not just decodes.
///
/// A decode's peak allocation is a clamped reservation, so it is bounded by
/// the input (see [`MAX_CLAMPED_ELEMENT_BYTES`]). A *round trip* also builds
/// an output buffer, and `Vec` grows that by doubling — so its peak is
/// bounded by the output size rounded up to a power of two, which for an
/// output the size of the input is up to 2× the input and has nothing to do
/// with the clamp.
///
/// **Measured, not guessed** (F30): tightening the shared factor to 1 turned
/// `codec_round_trip` red at iteration 20 000 on an 11 280 B peak for a
/// 5 751 B input — **1.96×**, exactly one doubling past the output. Both
/// decode targets stayed green over 20 000 iterations each, which is what
/// establishes that the failure is the encoder's regrowth and not the clamp.
/// **4** is that worst case with one further doubling of headroom, and it
/// still refuses everything the bound exists for: `claimed` is a `u64`, so a
/// length-driven allocation misses this by many orders of magnitude.
pub const ROUND_TRIP_PEAK_FACTOR: usize = 4;

/// What one measured call allocated.
#[derive(Debug, Clone, Copy)]
pub struct Budget {
    /// Largest single allocation.
    pub peak_single: usize,
    /// Sum of every allocation request (never decremented on free, so a
    /// decoder that allocated and dropped in a loop is still caught).
    pub total: usize,
}

/// Run `f` with the counter armed.
///
/// Not re-entrant and not thread-safe by design: libFuzzer drives one input
/// at a time on one thread, which is what makes the measurement exact.
pub fn measure<T>(f: impl FnOnce() -> T) -> (T, Budget) {
    PEAK_SINGLE.store(0, Ordering::Relaxed);
    TOTAL.store(0, Ordering::Relaxed);
    ARMED.store(true, Ordering::Relaxed);
    let value = f();
    ARMED.store(false, Ordering::Relaxed);
    (
        value,
        Budget {
            peak_single: PEAK_SINGLE.load(Ordering::Relaxed),
            total: TOTAL.load(Ordering::Relaxed),
        },
    )
}

/// Assert F11's allocation budget for an `input.len()`-byte input.
///
/// The invariant, from decision D10 §4's clamp rule (*every pre-allocation
/// is clamped to `min(claimed_length, remaining_input)`*), stated in the
/// form that is actually true — which since F30 is the strong form (see
/// [`MAX_CLAMPED_ELEMENT_BYTES`]):
///
/// > An attacker can never make the parser allocate more than the
/// > attacker's own bytes, plus a fixed constant.
///
/// What that catches is everything that matters: an allocation sized by a
/// **claimed** count rather than by the input. `claimed` is a `u64` and can
/// be `u64::MAX`; the gap between `len` and `u64::MAX` is the whole point,
/// and no unclamped allocation fits under this bound.
///
/// # Panics
///
/// On a violation — which is the point: libFuzzer records it as a crash and
/// the offending input is written to `fuzz/artifacts/`.
pub fn assert_within_budget(what: &str, input_len: usize, budget: Budget) {
    assert_within_budget_scaled(what, input_len, budget, MAX_CLAMPED_ELEMENT_BYTES);
}

/// [`assert_within_budget`] with an explicit peak factor.
///
/// The one caller that needs it is `codec_round_trip`, whose peak is the
/// **encoder's** output buffer rather than a clamped reservation; see
/// [`ROUND_TRIP_PEAK_FACTOR`]. Keeping it a separate entry point rather than
/// loosening the shared constant is the point: the decode targets keep the
/// sharp 1× bound that is the actual statement of D10 §4's clamp rule.
///
/// # Panics
///
/// On a violation, as [`assert_within_budget`].
pub fn assert_within_budget_scaled(
    what: &str,
    input_len: usize,
    budget: Budget,
    peak_factor: usize,
) {
    assert_within_budget_full(what, input_len, budget, peak_factor, 0);
}

/// [`assert_within_budget`] with a **rule 6 structural exemption** (D102 §3.3).
///
/// # What this is not
///
/// It is not a widening of the clamp rule, and it is not an exception granted
/// to the party the guard caught. [`MAX_CLAMPED_ELEMENT_BYTES`] is untouched,
/// F30's finding is untouched, and every site the clamp rule was ever about
/// keeps the sharp 1× bound. What changes is that the rule stops being applied
/// to a site it was never about.
///
/// D10 §4's clamp — *"every pre-allocation is clamped to `min(claimed_length,
/// remaining_input)`"*, justified by *"every element of a definite-length
/// array costs at least one wire byte"* — is a rule about **length headers**.
/// A container bounded instead by a **count limit** has no claimed length to
/// clamp against: the `.ots` parser's work stack is bounded by
/// `MAX_OTS_DEPTH`, its attestation list by `MAX_OTS_ATTESTATIONS`, and the
/// RFC 3161 path's certificate bag by `MAX_CHAIN_CERTS`. For those, one input
/// byte buys `size_of::<Element>()` reserved bytes by arithmetic, on legal
/// input, and **no parser change alters that** (D102 §4.3 measured the one
/// candidate change and it does not save the rule). They are governed by D58
/// §10.3 **rule 6** instead, which requires their cost to be derived from the
/// limit constants and `size_of` — which is what `exemption` must be, computed
/// by `antseal_core` and passed in here rather than restated.
///
/// # Why an inequality, when the unit test asserts equality
///
/// `Vec` growth from capacity 4 by doubling is a `RawVec` implementation
/// detail, not a language guarantee. An equality here would flake the day the
/// growth policy changed — and **a flaky guard gets switched off**, which is
/// worse than no guard and is the failure mode D102 exists to prevent. The
/// equality lives in `crates/antseal-core/tests/anchor_ots_alloc.rs`, on the
/// exactly-pinned stable toolchain, where a growth-policy change arrives as a
/// reviewed toolchain bump with a red test attached.
///
/// # What is still caught
///
/// `exemption` is a **function of the input**, never a constant: at an 80-byte
/// input the `.ots` exemption is 11 264 B and at 1 145 B it is 53 248 B, so an
/// input that never goes deep gets almost none of it. Both D58 crashers stay
/// fully visible — a regression reintroducing `vec![0; attacker_varint]` at
/// the 80-byte §3.1 input, or the unbounded hexlify chain at the 102-byte
/// §3.2 one, is red; so is a regression capped at `MAX_OTS_VALUE_BYTES`
/// (32 768 B) at either length. The honest cost, stated rather than buried: at
/// an 80-byte input the window a hostile allocation can hide in widens from
/// 4 176 B to 11 264 B. Closing that further needs **per-site attribution**,
/// which a `#[global_allocator]` cannot give.
///
/// # Panics
///
/// On a violation, as [`assert_within_budget`].
pub fn assert_within_budget_structural(
    what: &str,
    input_len: usize,
    budget: Budget,
    exemption: usize,
) {
    assert_within_budget_full(
        what,
        input_len,
        budget,
        MAX_CLAMPED_ELEMENT_BYTES,
        exemption,
    );
}

/// The one body all three entry points share.
///
/// # Panics
///
/// On a violation, as [`assert_within_budget`].
fn assert_within_budget_full(
    what: &str,
    input_len: usize,
    budget: Budget,
    peak_factor: usize,
    exemption: usize,
) {
    let clamp_cap = input_len.saturating_mul(peak_factor).saturating_add(SLACK);
    let single_cap = clamp_cap.max(exemption);
    assert!(
        budget.peak_single <= single_cap,
        "{what}: peak single allocation {} B for a {input_len} B input (cap {single_cap} B = \
         max(len x {peak_factor} + {SLACK}, structural {exemption})) — D10 §4's clamp rule says \
         a hostile length head can never drive an allocation larger than the input that claimed \
         it, and D58 §10.3 rule 6 says a count-bounded container may cost no more than the \
         derivation from its own limit constant",
        budget.peak_single
    );
    let total_cap = input_len.saturating_mul(TOTAL_FACTOR).saturating_add(SLACK);
    assert!(
        budget.total <= total_cap,
        "{what}: total allocation {} B for a {input_len} B input (cap {total_cap} B) — \
         allocation must stay linear in the input",
        budget.total
    );
}

// ---------------------------------------------------------------------------
// the self-test tripwire
// ---------------------------------------------------------------------------

/// Environment variable naming the target that must crash on its next input.
pub const SELFTEST_VAR: &str = "ANTSEAL_FUZZ_SELFTEST";

/// Abort if this process was asked to demonstrate a crash.
///
/// Call it first in every target. When `ANTSEAL_FUZZ_SELFTEST` equals the
/// target's name, the target panics on its first input; libFuzzer records
/// the crash and writes the reproducer to `fuzz/artifacts/<target>/`. That
/// is the executed proof — re-run on demand, never a deleted commit — that
/// a real finding would surface the same way.
///
/// The variable is read on **every** call rather than cached: a cached read
/// would make the tripwire a property of process start-up, and the thing
/// being demonstrated is that a panic *inside an iteration* becomes an
/// artifact.
///
/// # Panics
///
/// Deliberately, when armed for this target.
pub fn selftest_tripwire(target: &str) {
    if std::env::var(SELFTEST_VAR).as_deref() == Ok(target) {
        panic!(
            "{SELFTEST_VAR}={target}: synthetic crash (fuzz/src/lib.rs). \
             This is the crash-artifact demonstration, not a finding."
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_budget_admits_a_clamped_decode_and_refuses_a_length_driven_one() {
        // Post-F30, the 152-byte `signatures` input that produced the
        // original finding reserves floor(147 / 32) = 4 entries of 32 B.
        // Clamped in bytes, therefore admitted.
        assert_within_budget(
            "sigmap clamp",
            152,
            Budget {
                peak_single: 128,
                total: 8_192,
            },
        );
        // The pre-F30 reservation for that same input — 147 elements of
        // 32 B — is NOT admitted any more: 4 704 > 152 x 1 + 4096. This is
        // the regression the tightened constant now catches.
        let regressed = std::panic::catch_unwind(|| {
            assert_within_budget(
                "pre-F30 sigmap clamp",
                152,
                Budget {
                    peak_single: 4_704,
                    total: 8_192,
                },
            );
        });
        assert!(
            regressed.is_err(),
            "the element-size multiplier must no longer fit inside the budget"
        );
        // A 4 MiB single allocation from the same input is not clamped at
        // all: 4 MiB > 152 x 1 + 4096.
        let violated = std::panic::catch_unwind(|| {
            assert_within_budget(
                "hostile",
                152,
                Budget {
                    peak_single: 4 << 20,
                    total: 4 << 20,
                },
            );
        });
        assert!(
            violated.is_err(),
            "the budget assertion must be able to fail"
        );
    }

    /// Super-linear growth is refused even when every individual allocation
    /// is small — the case `peak_single` alone cannot see.
    #[test]
    fn the_budget_refuses_super_linear_total_growth() {
        let violated = std::panic::catch_unwind(|| {
            assert_within_budget(
                "quadratic",
                4_096,
                Budget {
                    peak_single: 64,
                    total: 4_096 * 4_096,
                },
            );
        });
        assert!(violated.is_err());
    }

    /// **D102 §3.3 property 3, executed.** The rule 6 exemption is a scoping
    /// of the guard, not a widening of it: the class this target was built to
    /// catch stays fully visible at the exact input lengths D58 measured.
    ///
    /// What makes it fail: an exemption that stops being a function of the
    /// input, or one large enough to swallow a `MAX_OTS_VALUE_BYTES`-capped
    /// regression — the shape option (B) would have produced, and the reason
    /// D102 §4.2 calls it the worst option on the table.
    #[test]
    fn the_structural_exemption_still_refuses_both_d58_crashers() {
        use antseal_core::anchor::ots::ots_structural_alloc_bytes;

        // D58 §3.1's 80-byte `.ots` and §3.2's 102-byte one. The exemption
        // each is granted is a property of its length alone.
        for (len, exemption) in [(80_usize, 11_264_usize), (102, 11_264)] {
            assert_eq!(
                ots_structural_alloc_bytes(len),
                exemption,
                "the exemption at {len} B moved"
            );

            // §3.1's actual allocation: 549 755 813 887 B from four bytes.
            let crasher = std::panic::catch_unwind(|| {
                assert_within_budget_structural(
                    "D58 §3.1",
                    len,
                    Budget {
                        peak_single: 549_755_813_887,
                        total: 549_755_813_887,
                    },
                    exemption,
                );
            });
            assert!(crasher.is_err(), "the D58 crasher class is no longer red");

            // A regression merely capped at `MAX_OTS_VALUE_BYTES` — the
            // budget A100's `Do` leaned toward — is red too, at both lengths.
            let capped = std::panic::catch_unwind(|| {
                assert_within_budget_structural(
                    "MAX_OTS_VALUE_BYTES-capped regression",
                    len,
                    Budget {
                        peak_single: 32_768,
                        total: 32_768,
                    },
                    exemption,
                );
            });
            assert!(
                capped.is_err(),
                "a 32 768 B allocation from {len} B of input must not fit \
                 inside the exemption, or rule 6 has become the flat constant \
                 D102 §4.2 refutes"
            );
        }

        // …and the 142-byte structural witness, which is red under the
        // unscoped rule and green under this one. Both directions, because a
        // guard that cannot fail and a guard that cannot pass are the same
        // defect wearing different signs.
        let witness_peak = Budget {
            peak_single: 5_120,
            total: 12_417,
        };
        let unscoped = std::panic::catch_unwind(|| {
            assert_within_budget("A100's 142 B witness, unscoped", 142, witness_peak);
        });
        assert!(
            unscoped.is_err(),
            "the witness must violate the pre-D102 guard, or it witnesses nothing"
        );
        assert_within_budget_structural(
            "A100's 142 B witness, rule 6",
            142,
            witness_peak,
            ots_structural_alloc_bytes(142),
        );
    }

    /// The DER path's exemption, which is scoped **before** its target has
    /// ever gone red (D102 §6).
    ///
    /// What makes it fail: `MAX_CHAIN_CERTS` or `size_of::<Certificate>()`
    /// moving without the derivation moving with it.
    #[test]
    fn the_der_exemption_is_derived_and_input_shaped() {
        use antseal_core::anchor::caps::{TSA_STRUCTURAL_ALLOC_BYTES, tsa_structural_alloc_bytes};

        // A one-byte token can reserve at most one of each container.
        assert!(tsa_structural_alloc_bytes(1) < TSA_STRUCTURAL_ALLOC_BYTES / 8);
        // Past the largest count limit the exemption is flat, by construction.
        assert_eq!(
            tsa_structural_alloc_bytes(64),
            TSA_STRUCTURAL_ALLOC_BYTES,
            "the exemption must saturate at exactly the derived constant"
        );
        // And a gigabyte from a kilobyte is still red.
        let hostile = std::panic::catch_unwind(|| {
            assert_within_budget_structural(
                "a believed length head",
                1_024,
                Budget {
                    peak_single: 1 << 30,
                    total: 1 << 30,
                },
                tsa_structural_alloc_bytes(1_024),
            );
        });
        assert!(hostile.is_err());
    }

    #[test]
    fn the_tripwire_is_inert_unless_it_names_this_target() {
        // Not armed for anything in a plain `cargo test` run.
        selftest_tripwire("manifest_decode");
        selftest_tripwire("bundle_decode");
        selftest_tripwire("codec_round_trip");
        selftest_tripwire("verify_bundle");
    }
}
