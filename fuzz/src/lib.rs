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
/// # The correction this constant encodes (found by this fuzzer)
///
/// `crates/antseal-core/tests/parser_caps_alloc.rs` states decision D10 §4's
/// consequence as
///
/// > an attacker can never make the parser allocate more than the
/// > attacker's own bytes — modulo a small constant … which is what `SLACK`
/// > covers
///
/// and that is **not true in general**. The clamp is
/// `Vec::with_capacity(min(claimed, remaining_input))` where the unit is
/// *elements*, not bytes, so the true bound is
/// `remaining_input × size_of::<Element>()`. That test passes because both
/// of its inputs are under 32 bytes, so the multiplier disappears inside a
/// 4 KiB `SLACK`.
///
/// The first fuzz run over the committed corpus surfaced it immediately: a
/// **152-byte** input whose `signatures` map head claims 59 638 entries
/// drives a **4 704-byte** single allocation — 147 elements of
/// `(SigAlg, Vec<u8>)`, 32 B each. The amplification factor is
/// `size_of::<Element>()`, and it is a property of the type, not of the
/// input.
///
/// Measured element sizes at this commit (x86-64), all clamped-allocation
/// sites: `FileEntry` 192, `OtsAnchor` 136, `UnitEntry` 128,
/// `CoveredReveal` 112, `TsaAnchor` 88, `NonCoveredReveal` 80,
/// `FullReveal` 64, `TouchedFile` 48, `(SigAlg, Vec<u8>)` 32. **256** is the
/// largest of those rounded up, leaving room for layout drift without
/// admitting a whole new element class unnoticed.
///
/// Task **F30** proposes making the clamp element-aware where a bound is
/// already known (the `sig_alg` universe is 16, so `signatures`,
/// `pubkeys` and `sig_policy` need never reserve more than 16 slots), which
/// would let this constant shrink towards 1 and restore the strong claim
/// literally. Until then the assertion states what is *true*, not what
/// would be nicer.
pub const MAX_CLAMPED_ELEMENT_BYTES: usize = 256;

/// How many times its own input a decode may allocate **in total**.
///
/// The sharp claim is about [`peak_single`](Budget::peak_single) — that is
/// where a hostile length head shows up. `total` is necessarily larger on a
/// decode that succeeds: reveal sections own their ciphertexts, nested
/// layers each decode their own slice, and the round-trip target re-encodes
/// on top. What `total` still forbids is the thing that actually hurts —
/// **super-linear** blowup — so the factor is deliberately generous
/// (4 × [`MAX_CLAMPED_ELEMENT_BYTES`], i.e. a handful of clamped containers
/// plus their payload copies) and the assertion is about the *shape* of the
/// growth rather than its constant.
pub const TOTAL_FACTOR: usize = 4 * MAX_CLAMPED_ELEMENT_BYTES;

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
/// form that is actually true (see [`MAX_CLAMPED_ELEMENT_BYTES`]):
///
/// > An attacker can never make the parser allocate more than the
/// > attacker's own bytes times one element, plus a fixed constant.
///
/// What that still catches is everything that matters: an allocation sized
/// by a **claimed** count rather than by the input. `claimed` is a `u64` and
/// can be `u64::MAX`; the gap between `len × 256` and `u64::MAX × 256` is
/// the whole point, and no realistic unclamped allocation fits under this
/// bound.
///
/// # Panics
///
/// On a violation — which is the point: libFuzzer records it as a crash and
/// the offending input is written to `fuzz/artifacts/`.
pub fn assert_within_budget(what: &str, input_len: usize, budget: Budget) {
    let single_cap = input_len
        .saturating_mul(MAX_CLAMPED_ELEMENT_BYTES)
        .saturating_add(SLACK);
    assert!(
        budget.peak_single <= single_cap,
        "{what}: peak single allocation {} B for a {input_len} B input (cap {single_cap} B = \
         len x {MAX_CLAMPED_ELEMENT_BYTES} + {SLACK}) — D10 §4's clamp rule says a hostile \
         length head can never drive an allocation larger than the input that claimed it, \
         scaled by one element",
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
        // The finding that set MAX_CLAMPED_ELEMENT_BYTES: a 152-byte input
        // whose `signatures` head claims 59 638 entries reserves 147
        // elements of 32 B. Clamped, therefore admitted.
        assert_within_budget(
            "sigmap clamp",
            152,
            Budget {
                peak_single: 4_704,
                total: 8_192,
            },
        );
        // The same input driving a 4 MiB single allocation is NOT clamped:
        // 4 MiB > 152 x 256 + 4096.
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

    #[test]
    fn the_tripwire_is_inert_unless_it_names_this_target() {
        // Not armed for anything in a plain `cargo test` run.
        selftest_tripwire("manifest_decode");
        selftest_tripwire("bundle_decode");
        selftest_tripwire("codec_round_trip");
        selftest_tripwire("verify_bundle");
    }
}
