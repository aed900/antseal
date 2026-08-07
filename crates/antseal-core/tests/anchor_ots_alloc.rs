//! **A100 / D102**: what the `.ots` parser's count-bounded containers cost, in
//! bytes, asserted at equality.
//!
//! `fuzz-smoke` was red for four consecutive CI runs on four different inputs
//! — 248, 744, 988 and 638 bytes — every one of them below 1 024 B and every
//! one peaking at **exactly 5 120 B** while the guard's relative cap moved
//! four times. Neither of the two rules A100 named governs that allocation
//! (D102 §1): it is `walk.rest`, the iterative parser's work stack, which is
//! **count-bounded** by `MAX_OTS_DEPTH` and has no length header to clamp
//! against. D10 §4's clamp is a rule about length headers, so it never applied
//! here; D58 §10.3 **rule 6** now does, and this file is its clause (b).
//!
//! > **6. A container bounded by a *count limit* is not governed by the clamp
//! > rule, and its cost must be derived, bounded and asserted** — (a) derived
//! > from the limit constants and `size_of`, never a literal; (b) **asserted
//! > at equality against the measured peak**; (c) `≤ MAX_OTS_BYTES`.
//!
//! Clause (a) is [`antseal_core::anchor::ots::OTS_STRUCTURAL_ALLOC_BYTES`] and
//! its neighbours; clause (c) is a `const` assertion in
//! `crates/antseal-core/src/anchor/ots/limits.rs`, so a raise that breaks it
//! fails `cargo build` rather than reddening a lane someone can rerun. This
//! file is clause (b), on the stable toolchain, with no nightly, no
//! sanitizer, no cargo-fuzz and no network.
//!
//! # Why equality and not `≤`
//!
//! D26 §2 is the precedent and its argument transfers verbatim: G18 asked for
//! a bound of the form `C₁·⌈log₂ n⌉` and D26 overturned the *shape*, replacing
//! the fudge constant with exact closed forms asserted at equality, because
//! *"that number — not a `C₁` — is what 'O(log n) memory' means in this
//! codebase."* An inequality goes green forever after a raise; an equality
//! goes red the moment the structure changes, in either direction, including a
//! change nobody intended.
//!
//! **The one place equality must not go is the fuzz lane**, and that is
//! deliberate (D102 §8). `Vec` growth from capacity 4 by doubling is a
//! `RawVec` implementation detail, not a language guarantee, so an equality in
//! a nightly-toolchain lane would flake on a growth-policy change — and **a
//! flaky guard gets switched off**, which is the failure mode this whole
//! record exists to prevent. `fuzz/fuzz_targets/anchor_ots.rs` keeps an
//! inequality. This binary may assert equality because the workspace pins
//! stable `=1.92.0` exactly (D4), so a growth-policy change arrives as a
//! reviewed toolchain bump with a red test attached — which is the correct
//! venue for it.
//!
//! # Why this is its own test binary, with one test in it
//!
//! A `#[global_allocator]` is process-wide and `cargo test` runs a binary's
//! tests on parallel threads, so a counting allocator shared with unrelated
//! tests would see their allocations too and every peak assertion would be
//! flaky. `parser_caps_alloc.rs` learned this first and is the precedent;
//! **one test per binary** is what makes the measurement exact. The four rows
//! below are sequential steps of a single test for that reason, not four
//! `#[test]`s.
//!
//! # The reproducer is generated, not transcribed
//!
//! A100 carried a base64 blob in its task entry. Measured at D102 §7, it is
//! **245 bytes** with sha1 `08df86ba…` against a record claiming **248** and
//! `b5aec24c…` — four base64 characters lost in transcription, and nothing in
//! the tree can regenerate the bytes the record names. It still trips the
//! budget, but at `anchor-ots-unknown-op` rather than the recorded site, so
//! the row was **unverifiable, not dead**. `docs/testing/fuzzing.md` §4 step 4
//! already prefers a generated witness over a hand-transcribed one; the
//! standing rule D102 §7 adds is that **reproducer bytes are never carried in
//! prose**. Every input below is built here, by the writer the suite already
//! owns, and states its own cause in its construction.
//!
//! Row 1's **142-byte** witness is the smallest input that violates the
//! unscoped guard — smaller than all four CI inputs, which libFuzzer minimised
//! for crash preservation rather than for size.
//!
//! # Not on wasm32
//!
//! `anchor::testing` is gated `cfg(any(test, feature = "test-util"))` and the
//! wasm32 dev-dependency edge enables `test-vectors` only; the
//! `wasm32-core-tests` lane runs `--lib`, so integration targets are not built
//! there at all. The attribute makes that a fact about this file rather than a
//! property of the lane's argv, exactly as `anchor_ots_writer.rs` does. Clause
//! (c) is a `const` assertion and therefore *does* ride the wasm32 build, and
//! it is derived from `size_of`, so the narrower 32-bit `Frame` costs it
//! nothing.
//!
//! Secret-material convention (project rule 6): every input here is `.ots`
//! wire structure and a published filler digest; no key, salt, or plaintext
//! material.
//!
//! # The `unsafe_code` exception — sanctioned, scoped, and justified
//!
//! `unsafe_code = "deny"` is a workspace lint (root `Cargo.toml`), whose
//! sanctioned opt-out is "a crate that genuinely needs `unsafe` adds
//! `#![allow(unsafe_code)]` at its crate root together with a written
//! justification … and the exception is called out explicitly in review".
//! **This test binary is such a crate root, and `antseal-core`'s library is
//! untouched: it remains entirely `unsafe`-free.** `std::alloc::GlobalAlloc`
//! is an `unsafe trait` whose four methods are `unsafe fn` by definition, and
//! there is no safe API that observes allocation peaks.
//!
//! Invariants upheld by the `unsafe` below — the same four
//! `parser_caps_alloc.rs` carries:
//!
//! 1. **Every method forwards unchanged to `System`**, with identical
//!    arguments and no reinterpretation of `ptr` or `Layout`, so `dealloc`
//!    always receives a pointer from the same allocator with the same layout.
//! 2. **The added code is allocation-free and lock-free** — three `Relaxed`
//!    atomics — so it can neither re-enter the allocator nor deadlock inside
//!    one.
//! 3. **The counters are observation-only**: no control-flow decision inside
//!    the allocator depends on them, so an arbitrary counter value cannot
//!    change which pointer is returned.
//! 4. **The counter is armed only around the call under test**, and this
//!    binary runs one test, so nothing else is executing while it is armed.
#![allow(unsafe_code)]
#![cfg(not(target_arch = "wasm32"))]

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use antseal_core::anchor::ots::{
    MAX_OTS_ATTESTATIONS, MAX_OTS_DEPTH, OTS_ATTESTATION_BYTES, OTS_FRAME_BYTES,
    OTS_STRUCTURAL_ALLOC_BYTES, OTS_STRUCTURAL_ATTESTATION_BYTES, OTS_STRUCTURAL_WORK_STACK_BYTES,
    ots_structural_alloc_bytes, parse_ots_measured,
};
use antseal_core::anchor::testing::ots_writer::{
    DIGEST_UPGRADED_LARGE_TEST, UPGRADED_LARGE_TEST, container, pending, synthetic_digest,
};
use antseal_core::codec::caps::MAX_OTS_BYTES;

// ─────────────────────────────────────────────────────────────────────
// A counting global allocator, armed only around the call under test.
// ─────────────────────────────────────────────────────────────────────

static ARMED: AtomicBool = AtomicBool::new(false);
/// The largest single allocation observed while armed — the quantity rule 6
/// is about, and the one the fuzz guard reports.
static PEAK_SINGLE: AtomicUsize = AtomicUsize::new(0);
/// Total bytes requested while armed, never decremented on free.
static TOTAL: AtomicUsize = AtomicUsize::new(0);

struct Counting;

// SAFETY: every method forwards unchanged to `System`, so the pointers handed
// out and the pointers freed are always the same allocator's with the same
// layout. The only added behaviour is three `Relaxed` atomics, which allocate
// nothing (no re-entrancy) and block on nothing (no deadlock) and feed no
// control-flow decision. Full justification in the module docs.
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

#[global_allocator]
static ALLOC: Counting = Counting;

/// What one parse allocated.
#[derive(Debug, Clone, Copy)]
struct Measured {
    peak_single: usize,
    total: usize,
    depth: u32,
    attestations: u32,
}

/// The fixed overhead the fuzz guard allows regardless of input size.
///
/// Restated here rather than imported: `fuzz/` is a **detached** crate (its
/// `Cargo.toml` carries the empty `[workspace]` table that keeps
/// `libfuzzer-sys` out of the audited graph), so this crate cannot see
/// `antseal_fuzz::SLACK`. `parser_caps_alloc.rs` restates the same constant
/// for the same reason. [`the_guard_shape_this_file_asserts_is_the_targets`]
/// is the assertion that keeps the two from drifting silently.
const SLACK: usize = 4 * 1024;

/// The guard `fuzz/fuzz_targets/anchor_ots.rs` applies, as D102 §3.3 scopes
/// it.
///
/// `peak_single ≤ max(len × 1 + SLACK, structural(len))`. The exemption is a
/// **function of the input**, not a constant: every frame and every
/// attestation costs at least one wire byte, so an input that never goes deep
/// gets almost none of it.
fn scoped_budget(input_len: usize) -> usize {
    (input_len + SLACK).max(ots_structural_alloc_bytes(input_len))
}

/// The guard as it stood before D102 — D10 §4's clamp rule, applied to a site
/// it was never about.
const fn unscoped_budget(input_len: usize) -> usize {
    input_len + SLACK
}

/// Parse `bytes` with the counter armed, and report what it cost.
fn measure(bytes: &[u8], digest: &[u8; 32]) -> Measured {
    PEAK_SINGLE.store(0, Ordering::Relaxed);
    TOTAL.store(0, Ordering::Relaxed);
    ARMED.store(true, Ordering::Relaxed);
    let parsed = parse_ots_measured(bytes, digest);
    ARMED.store(false, Ordering::Relaxed);

    let (artifact, shape) = parsed.expect("every fixture in this file is a legal artifact");
    Measured {
        peak_single: PEAK_SINGLE.load(Ordering::Relaxed),
        total: TOTAL.load(Ordering::Relaxed),
        depth: shape.max_depth,
        attestations: u32::try_from(artifact.attestations.len()).expect("bounded by 256"),
    }
}

// ─────────────────────────────────────────────────────────────────────
// Generated witnesses. Every one states its own cause in its shape.
// ─────────────────────────────────────────────────────────────────────

/// A one-character calendar URI.
///
/// The URI's length is not the subject and a real one adds 44 bytes to every
/// fixture that uses it, which would put row 1's witness over the 1 024-byte
/// line the CI verdict turned on — the very confound being measured.
const SHORT_URI: &str = "x";

/// The calendar URI `super::parser_is_iterative_at_max_depth` writes, so that
/// row 2's input is that green test's input **byte for byte**.
///
/// Restated rather than imported for the reason `anchor::ots::tests` restates
/// the magic: the two suites are opposite instruments, and a row that moves
/// when the other file moves is not a witness.
const CALENDAR_URI: &str = "https://alice.btc.calendar.opentimestamps.org";

/// A chain of `ops` sequential SHA-256 steps terminated by one pending
/// attestation: depth `ops`, one attestation, no forks.
///
/// This is `parser_is_iterative_at_max_depth`'s shape, parameterised in the
/// two dimensions the rows need — how deep, and how many bytes the terminating
/// attestation spends on its URI.
fn chain(ops: u32, uri: &str) -> ([u8; 32], Vec<u8>) {
    let digest = synthetic_digest(0x42);
    let mut body = vec![0x08_u8; ops as usize];
    body.extend_from_slice(&pending(uri));
    (digest, container(&digest, &body))
}

/// An **open-fork spine** of `n` levels: `(0xff 0x08)ⁿ` followed by `n + 1`
/// attestations.
///
/// Every `0xff` says *"another child follows"*, so every ancestor is left
/// genuinely open and none of them can be popped until its second child
/// arrives. This is the shape that refutes the tail-call elimination
/// (D102 §4.3) — a last child's parent is never resumed, but here every parent
/// is — and it is the only shape in which the **attestation** list, not the
/// work stack, is the peak.
fn open_fork_spine(n: u32) -> ([u8; 32], Vec<u8>) {
    let digest = synthetic_digest(0x43);
    let mut body = Vec::new();
    for _ in 0..n {
        body.push(0xff);
        body.push(0x08);
    }
    // One attestation closes the deepest node; one more closes each open
    // ancestor, the root included.
    for _ in 0..=n {
        body.extend_from_slice(&pending(SHORT_URI));
    }
    (digest, container(&digest, &body))
}

/// `Vec`'s reservation for `n` pushed elements: it grows by doubling, so the
/// largest single allocation is the first power of two at or above `n`.
///
/// Deliberately **not** clamped to `Vec`'s minimum capacity of 4. Every row
/// below pushes far more than four elements, and adding a floor would make the
/// helper agree with the allocator for a reason the rows do not test.
const fn reserved(n: u32) -> usize {
    (n as usize).next_power_of_two()
}

// ─────────────────────────────────────────────────────────────────────

/// **The whole of D102 §8 — and the only `#[test]` in this binary.**
///
/// One test, because the allocator is process-wide and `cargo test` runs a
/// binary's tests on parallel threads: a second `#[test]` allocating anywhere
/// — a `format!`, the harness's own bookkeeping — while [`measure`] is armed
/// would raise `PEAK_SINGLE` from another thread and every equality below
/// would flake. The three sections are functions rather than tests for exactly
/// that reason; see the module docs.
#[test]
fn rule_six_holds_for_the_dot_ots_parser() {
    count_bounded_containers_cost_exactly_what_rule_six_derives();
    clause_c_holds_with_the_headroom_a_future_raiser_needs();
    the_guard_shape_this_file_asserts_is_the_targets();
}

/// **D102 §8, rows 1–4, plus the guard rows either side of them.**
///
/// What makes it fail, in each direction:
///
/// - a new count-bounded container in the parser, or a `Frame`/
///   `OtsAttestation` field added or removed — the equalities move;
/// - a raise of `MAX_OTS_DEPTH` or `MAX_OTS_ATTESTATIONS` — row 2 and the
///   totals move (and clause (c) may stop the build first);
/// - `walk.rest` ceasing to hold exactly the root-to-current path, which is
///   D102 kill criterion 2 and the assumption the whole derivation rests on —
///   `depth` is asserted against the fixture's own construction for that
///   reason;
/// - the 142-byte witness ceasing to violate the unscoped bound, which would
///   mean the regression case had gone vacuous.
fn count_bounded_containers_cost_exactly_what_rule_six_derives() {
    // ── row 1: the boundary, and the minimal witness ─────────────────
    //
    // Capacity 64 holds 64 frames; the 65th push doubles to 128. Two inputs
    // that differ by one wire byte therefore differ by 2 560 B of allocation,
    // and only the second one is over the unscoped guard's cap. That is the
    // boundary A100's four CI inputs were all far above.
    let (digest, at_64) = chain(64, SHORT_URI);
    let m64 = measure(&at_64, &digest);
    assert_eq!(m64.depth, 64, "the fixture must reach depth 64");
    assert_eq!(
        m64.peak_single,
        reserved(64) * OTS_FRAME_BYTES,
        "64 frames must reserve exactly one power of two's worth: {m64:?}"
    );

    let (digest, witness) = chain(65, SHORT_URI);
    assert_eq!(
        witness.len(),
        142,
        "the minimal structural witness is 142 B — smaller than all four CI \
         inputs, which libFuzzer minimised for crash preservation, not size"
    );
    let m65 = measure(&witness, &digest);
    assert_eq!(m65.depth, 65, "the fixture must reach depth 65");
    assert_eq!(
        m65.peak_single,
        reserved(65) * OTS_FRAME_BYTES,
        "the 65th push must cross 64 -> 128: {m65:?}"
    );
    assert_eq!(
        m65.peak_single,
        m64.peak_single * 2,
        "one wire byte, one doubling — {} B at depth 64, {} B at depth 65",
        m64.peak_single,
        m65.peak_single
    );

    // **The regression case, in both directions.** Red under the guard as it
    // stood — this is the reproduction, and it is what makes the row non-
    // vacuous — and green under the guard D102 §3.3 scopes.
    assert!(
        m65.peak_single > unscoped_budget(witness.len()),
        "the 142 B witness no longer reproduces A100: peak {} B is inside the \
         unscoped cap {} B, so this regression case has gone vacuous",
        m65.peak_single,
        unscoped_budget(witness.len())
    );
    assert!(
        m65.peak_single <= scoped_budget(witness.len()),
        "peak {} B exceeds rule 6's scoped budget {} B for a {} B input",
        m65.peak_single,
        scoped_budget(witness.len()),
        witness.len()
    );

    // ── row 2: the work stack at its own limit ───────────────────────
    //
    // `parser_is_iterative_at_max_depth` builds this input and asserts it
    // parses. It is green today and silent about what it costs; this is the
    // assertion it did not carry. 1 145 B of legal, tree-required input.
    let (digest, at_cap) = chain(MAX_OTS_DEPTH, CALENDAR_URI);
    assert_eq!(at_cap.len(), 1_145, "D102 §1.2's row, byte for byte");
    let m_cap = measure(&at_cap, &digest);
    assert_eq!(m_cap.depth, MAX_OTS_DEPTH);
    assert_eq!(
        m_cap.peak_single, OTS_STRUCTURAL_WORK_STACK_BYTES,
        "a legal artifact at MAX_OTS_DEPTH must cost exactly the derived \
         work-stack bound: {m_cap:?}"
    );

    // ── row 3: the attestation list is the peak, and it is reachable ──
    //
    // 129 attestations from 1 869 B. The work stack reaches only depth 128
    // here, so this is the one row where the *other* container wins — which is
    // what stops the next fuzz red re-opening all of this under a different
    // constant (D102 §1.3).
    let (digest, spine) = open_fork_spine(128);
    assert_eq!(spine.len(), 1_869, "D102 §1.2's row, byte for byte");
    let m_spine = measure(&spine, &digest);
    assert_eq!(m_spine.depth, 128);
    assert_eq!(m_spine.attestations, 129);
    assert_eq!(
        m_spine.peak_single,
        reserved(129) * OTS_ATTESTATION_BYTES,
        "the attestation list, not the work stack, must be the peak here \
         (the work stack reserves {} B at depth 128): {m_spine:?}",
        reserved(128) * OTS_FRAME_BYTES
    );
    assert!(
        m_spine.peak_single > reserved(m_spine.depth) * OTS_FRAME_BYTES,
        "row 3 is testing the work stack again — it must be the attestation list"
    );

    // ── row 4: the real mainnet artifact, at the identical cost ──────
    //
    // A100's Accept row 3, strengthened per D102 §7: the honest artifact must
    // not merely parse, it must cost **exactly** what four hostile CI inputs
    // cost. It passed the unscoped guard for one reason only — 1 768 > 1 024 —
    // so the guard's verdict on identical allocator behaviour was settled by
    // input length and nothing else.
    let m_real = measure(UPGRADED_LARGE_TEST, &DIGEST_UPGRADED_LARGE_TEST);
    assert_eq!(UPGRADED_LARGE_TEST.len(), 1_768);
    assert_eq!(m_real.depth, 67, "D58 §9.5's corrected depth measurement");
    assert_eq!(
        m_real.peak_single,
        reserved(m_real.depth) * OTS_FRAME_BYTES,
        "the real artifact's real cost: {m_real:?}"
    );
    assert_eq!(
        m_real.peak_single, m65.peak_single,
        "the mainnet artifact and the 142 B hostile witness must allocate the \
         identical {} B — that identity is why the guard's verdict could never \
         have been about the input's length",
        m65.peak_single
    );
    assert!(
        m_real.peak_single <= unscoped_budget(UPGRADED_LARGE_TEST.len()),
        "the honest artifact passed the unscoped guard, and did so only \
         because 1 768 > 1 024 — if this ever fails, the whole record's \
         framing is wrong"
    );

    // ── the sum, and D102 kill criterion 1 ───────────────────────────
    //
    // Every peak observed above is a member of {40 x 2^k} u {48 x 2^k}. A peak
    // that is not is the falsification the record names.
    for m in [m64, m65, m_cap, m_spine, m_real] {
        let frames = m.peak_single.is_multiple_of(OTS_FRAME_BYTES)
            && (m.peak_single / OTS_FRAME_BYTES).is_power_of_two();
        let atts = m.peak_single.is_multiple_of(OTS_ATTESTATION_BYTES)
            && (m.peak_single / OTS_ATTESTATION_BYTES).is_power_of_two();
        assert!(
            frames || atts,
            "peak {} B is neither a work-stack nor an attestation reservation \
             — D102 kill criterion 1: the record is wrong and must be reopened",
            m.peak_single
        );
        assert!(
            m.total <= m.peak_single * 8,
            "total allocation must stay a small multiple of the peak: {m:?}"
        );
    }

    assert_eq!(
        OTS_STRUCTURAL_ALLOC_BYTES,
        OTS_STRUCTURAL_WORK_STACK_BYTES + OTS_STRUCTURAL_ATTESTATION_BYTES
    );
    assert_eq!(
        OTS_STRUCTURAL_ATTESTATION_BYTES,
        reserved(MAX_OTS_ATTESTATIONS) * OTS_ATTESTATION_BYTES
    );
}

/// **Rule 6 clause (c), witnessed rather than merely compiled.**
///
/// The binding form is the `const` assertion in `limits.rs` — it fails
/// `cargo build`, which is unignorable in a way no test is. This row exists
/// because a `const` assertion that holds leaves no trace a reader can find,
/// and because the *headroom* is the number a future raiser actually needs.
///
/// What makes it fail: nothing that clause (c) does not already stop the build
/// for. It is a statement of the margin, not a second gate.
fn clause_c_holds_with_the_headroom_a_future_raiser_needs() {
    let cost = u64::try_from(OTS_STRUCTURAL_ALLOC_BYTES).expect("far under u64");
    assert!(cost <= MAX_OTS_BYTES, "clause (c)");

    // D102 §3.2's table, recomputed rather than transcribed: how far
    // MAX_OTS_DEPTH could be raised before clause (c) refuses it.
    let per_frame = u64::try_from(OTS_FRAME_BYTES).expect("small");
    let attestations = u64::try_from(OTS_STRUCTURAL_ATTESTATION_BYTES).expect("small");
    let mut depth = u64::from(MAX_OTS_DEPTH);
    let mut last_green = depth;
    while depth.next_power_of_two() * per_frame + attestations <= MAX_OTS_BYTES {
        last_green = depth;
        depth *= 2;
    }
    assert!(
        last_green >= u64::from(MAX_OTS_DEPTH) * 4,
        "clause (c) leaves less than 4x of headroom on MAX_OTS_DEPTH \
         (largest admissible power of two: {last_green}) — a raise that is \
         independently necessary would now be blocked, which is D102 kill \
         criterion 4 and must be re-argued on memory rather than relaxed"
    );
    assert!(
        depth.next_power_of_two() * per_frame + attestations > MAX_OTS_BYTES,
        "the loop must terminate on a refusal, or clause (c) refuses nothing"
    );
}

/// The guard shape this file restates is the one the fuzz target applies.
///
/// `fuzz/` is a detached crate, so [`SLACK`] and the `max(…)` above are a
/// **copy** of `fuzz/fuzz_targets/anchor_ots.rs`'s budget rather than an
/// import — the same situation `parser_caps_alloc.rs` is in. A copy that
/// drifts is a regression case asserting a rule nothing enforces, so the two
/// numbers that can drift are pinned against the target's own source text.
///
/// What makes it fail: changing `SLACK`, the peak factor, or the exemption in
/// `fuzz/` without changing it here.
fn the_guard_shape_this_file_asserts_is_the_targets() {
    const TARGET: &str = include_str!("../../../fuzz/fuzz_targets/anchor_ots.rs");
    const HARNESS: &str = include_str!("../../../fuzz/src/lib.rs");

    assert!(
        HARNESS.contains(&format!(
            "pub const SLACK: usize = {} * 1024;",
            SLACK / 1024
        )),
        "fuzz/src/lib.rs's SLACK is no longer {SLACK} — this file's copy has drifted"
    );
    assert!(
        HARNESS.contains("pub const MAX_CLAMPED_ELEMENT_BYTES: usize = 1;"),
        "the 1x clamp factor moved; D102 §3.3 property 2 says rule 6 leaves it \
         untouched everywhere it was ever true"
    );
    assert!(
        TARGET.contains("ots_structural_alloc_bytes"),
        "the .ots target no longer consumes rule 6's derivation by name — a \
         second copy of it is exactly what clause (a) forbids"
    );
}
