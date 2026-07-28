//! F11 accept: **the adversarial allocation test.**
//!
//! > "A small input claiming a huge bstr/array length is rejected without a
//! > large allocation (counting/limiting test allocator asserts peak)."
//!
//! This is the observable form of D10 §4's clamp rule — *every pre-allocation
//! is clamped to `min(claimed_length, remaining_input)`* — and the invariant
//! F17's fuzz target restates ("no allocation beyond the F11 budget").
//!
//! # What F17 disproved, and what this file now claims (task F30)
//!
//! Until F30 this file stated the consequence as *"an attacker can never make
//! the parser allocate more than the attacker's own bytes"* while asserting
//! something strictly weaker, and F17's first fuzz run falsified the stated
//! form in seconds. Two independent reasons the two tests below could not
//! have caught it, both structural rather than unlucky:
//!
//! 1. **Both fixtures put their container head last**, so `d.remaining()` —
//!    the clamp's right-hand operand — is 0 or single digits at the
//!    allocation. A clamp whose operands are in *different units* is
//!    indistinguishable from a correct one when one of them is zero.
//! 2. **`SLACK` is 4 KiB and the fixtures are under 128 B**, so even the
//!    32× multiplier F17 measured fits inside the slack.
//!
//! The claim is now true as written — F30 made [`clamped_capacity`] divide
//! the remaining bytes by the element width — and
//! [`the_reservation_never_exceeds_the_input_that_drove_it`] is where it is
//! actually proven, on kilobyte inputs whose heads are followed by a tail.
//! That test was run red against the pre-F30 clamp (2 097 152 B reserved for
//! a 65 549 B input; 3 145 728 B for a 20 005 B one) before it was run green.
//!
//! [`clamped_capacity`]: antseal_core::codec::clamped_capacity
//!
//! # Why this is its own test binary
//!
//! A `#[global_allocator]` is process-wide and `cargo test` runs a binary's
//! tests on parallel threads, so a counting allocator shared with unrelated
//! tests would see their allocations too and the peak assertion would be
//! flaky. One test per binary makes the measurement exact: between arming and
//! disarming the counter, the only code running is the decoder under test.
//!
//! Secret-material convention (project rule 6): the inputs are length heads
//! and a published filler byte; no key, salt, or plaintext material.
//!
//! # The `unsafe_code` exception — sanctioned, scoped, and justified
//!
//! `unsafe_code = "deny"` is a workspace lint (root `Cargo.toml`), whose
//! sanctioned opt-out is "a crate that genuinely needs `unsafe` adds
//! `#![allow(unsafe_code)]` at its crate root together with a written
//! justification … and the exception is called out explicitly in review".
//! **This test binary is such a crate root, and `antseal-core`'s library is
//! untouched: it remains entirely `unsafe`-free.**
//!
//! The need is unavoidable: `std::alloc::GlobalAlloc` is an `unsafe trait`
//! whose four methods are `unsafe fn` by definition, and F11's accept
//! criterion names a counting allocator as the measurement instrument. There
//! is no safe API that observes allocation peaks.
//!
//! Invariants upheld by the `unsafe` below:
//!
//! 1. **Every method forwards unchanged to `System`**, with identical
//!    arguments and no reinterpretation of `ptr` or `Layout`. The pointers
//!    this allocator hands out are exactly `System`'s, and the pointers it
//!    frees are exactly the ones `System` produced — so the safety contract
//!    (`dealloc` receives a pointer from the *same* allocator with the *same*
//!    layout) is discharged by delegation.
//! 2. **The added code is allocation-free and lock-free**: three atomics with
//!    `Relaxed` ordering. Nothing in it can allocate, so it cannot re-enter
//!    the allocator; nothing in it can block, so it cannot deadlock inside a
//!    global allocator.
//! 3. **The counters are observation-only**: no control-flow decision inside
//!    the allocator depends on them, so an arbitrary counter value cannot
//!    change which pointer is returned.
#![allow(unsafe_code)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use antseal_core::bundle::BundleV1;
use antseal_core::codec::caps;
use antseal_core::manifest::{Manifest, ManifestBodyV1};

// ─────────────────────────────────────────────────────────────────────
// A counting global allocator, armed only around the call under test.
// ─────────────────────────────────────────────────────────────────────

static ARMED: AtomicBool = AtomicBool::new(false);
/// The largest single allocation observed while armed.
static PEAK_SINGLE: AtomicUsize = AtomicUsize::new(0);
/// Total bytes requested while armed (allocations are never freed back out of
/// this counter — a decoder that allocated and dropped in a loop would still
/// be caught).
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

/// Run `f` with the counter armed; return `(peak_single, total)` bytes.
fn measure(f: impl FnOnce()) -> (usize, usize) {
    PEAK_SINGLE.store(0, Ordering::Relaxed);
    TOTAL.store(0, Ordering::Relaxed);
    ARMED.store(true, Ordering::Relaxed);
    f();
    ARMED.store(false, Ordering::Relaxed);
    (
        PEAK_SINGLE.load(Ordering::Relaxed),
        TOTAL.load(Ordering::Relaxed),
    )
}

// ─────────────────────────────────────────────────────────────────────
// Fixtures: a handful of bytes claiming astronomically many elements.
// ─────────────────────────────────────────────────────────────────────

/// An 8-byte-argument head. Shortest-form **only** for arguments above
/// `u32::MAX`; see [`canon_head`] for the general case.
fn head(major: u8, arg: u64) -> Vec<u8> {
    let mut v = vec![(major << 5) | 27];
    v.extend_from_slice(&arg.to_be_bytes());
    v
}

/// A **canonical** (shortest-form) head — the only kind that survives
/// `d.array()`/`d.map()`.
///
/// [`head`] always writes the 8-byte argument, which is non-canonical for
/// anything under 2^32 and is rejected as `cbor-non-shortest-length` at step
/// 1 of D10 §4's frozen order — *before* the cap check and before the
/// clamped allocation. A fixture that wants to reach the allocation must
/// therefore encode its length canonically.
fn canon_head(major: u8, arg: u64) -> Vec<u8> {
    let m = major << 5;
    match arg {
        0..=23 => vec![m | (arg as u8)],
        24..=0xFF => vec![m | 24, arg as u8],
        0x100..=0xFFFF => {
            let mut v = vec![m | 25];
            v.extend_from_slice(&(arg as u16).to_be_bytes());
            v
        }
        0x1_0000..=0xFFFF_FFFF => {
            let mut v = vec![m | 26];
            v.extend_from_slice(&(arg as u32).to_be_bytes());
            v
        }
        _ => head(major, arg),
    }
}

/// `{0: 1, 1: h'', 2: <storage record>, 3: array(u64::MAX)}` and nothing else —
/// 84 bytes claiming 18 446 744 073 709 551 615 OTS anchors.
fn bundle_claiming(count: u64) -> Vec<u8> {
    let mut v = vec![
        0xa4, // map(4)
        0x00, 0x01, // 0: 1
        0x01, 0x40, // 1: h''
        0x02, 0xa3, // 2: map(3)
        0x00, 0x58, 0x20,
    ];
    v.extend_from_slice(&[0xC7; 32]); // address
    v.extend_from_slice(&[0x01, 0x58, 0x18]);
    v.extend_from_slice(&[0xC7; 24]); // nonce
    v.extend_from_slice(&[0x02, 0x58, 0x20]);
    v.extend_from_slice(&[0xC7; 32]); // k_m
    v.push(0x03); // key 3: ots_anchors
    // `canon_head`, not `head` (F30): at `count = u64::MAX` the two agree,
    // but at `count = MAX_OTS_ANCHOR_COUNT` the always-8-byte form is
    // `cbor-non-shortest-length` and dies before the cap and the clamp.
    v.extend_from_slice(&canon_head(4, count));
    v
}

/// A manifest envelope whose `signatures` map head claims `count` entries.
/// `signatures` is a **recorded non-cap** (D10 §3) — bounded by the 16-value
/// `sig_alg` universe rather than by a cap — which is exactly why it is the
/// interesting case: only the clamp stands between a hostile head and an
/// allocation here.
fn manifest_claiming(count: u64) -> Vec<u8> {
    let mut v = vec![
        0xa2, // map(2)
        0x00, 0x40, // 0: h'' (body — never reached)
        0x01, // 1: signatures
    ];
    v.extend_from_slice(&head(5, count));
    v
}

/// The same envelope with `filler` junk bytes **after** the map head, so the
/// decoder's `remaining()` — the clamp's right-hand operand — is large.
///
/// This is the shape F17's fuzzer found and the two fixtures above cannot
/// produce: both of them put the container head *last*, so `remaining()` is
/// 0 or single digits and the clamp collapses to zero regardless of whether
/// its units agree. See [`the_reservation_never_exceeds_the_input_that_drove_it`].
fn manifest_claiming_with_tail(count: u64, filler: usize) -> Vec<u8> {
    let mut v = vec![
        0xa2, // map(2)
        0x00, 0x40, // 0: h'' (body — never reached)
        0x01, // 1: signatures
    ];
    v.extend_from_slice(&canon_head(5, count));
    v.extend(std::iter::repeat_n(0xC7, filler));
    v
}

/// A manifest **body** `{7: array(count)}` followed by `filler` junk bytes.
///
/// `files` carries the largest clamped element in the format
/// (`FileEntry`), so it is the worst-case amplification site, where
/// `signatures` (32 B entries) is merely the one the fuzzer reached first.
fn body_claiming_files_with_tail(count: u64, filler: usize) -> Vec<u8> {
    let mut v = vec![0xa1, 0x07]; // map(1) { 7: files
    v.extend_from_slice(&canon_head(4, count));
    v.extend(std::iter::repeat_n(0xC7, filler));
    v
}

// ─────────────────────────────────────────────────────────────────────

/// A tiny input claiming `u64::MAX` elements must allocate nothing large,
/// whether the list is capped (the cap fires first) or uncapped (only the
/// clamp stands in the way).
///
/// The bound asserted is the input length itself: *an attacker can never make
/// the parser allocate more than the attacker's own bytes* — modulo a small
/// constant for the parser's own bookkeeping, which is what `SLACK` covers.
///
/// **This test does not on its own establish that claim** (F30). Both
/// fixtures end at their container head, so `d.remaining()` is 0 there and
/// the clamp returns 0 whatever unit its operands are in; and both inputs are
/// under 128 B, so a multiplier of 32 would still fit inside `SLACK`. The
/// claim is proven by
/// [`the_reservation_never_exceeds_the_input_that_drove_it`]; what *this*
/// test still pins is the precedence — that a `u64::MAX` claim is refused by
/// the cap, with the cap's own code, before any element is read.
#[test]
fn a_huge_claimed_length_never_drives_a_large_allocation() {
    /// The parser's own fixed overhead (error values, decoder state). Kept
    /// tight: the point of the assertion is the absence of a length-driven
    /// allocation, so any slack big enough to hide one would defeat it.
    const SLACK: usize = 4 * 1024;

    // 1. A **capped** list: the cap fires at the array head, before the
    //    clamped allocation is even reached.
    let capped = bundle_claiming(u64::MAX);
    assert!(
        capped.len() < 128,
        "the hostile input is tiny by construction"
    );
    let mut code = "";
    let (peak, total) = measure(|| {
        code = BundleV1::decode(&capped)
            .map(|_| ())
            .expect_err("must reject")
            .code();
    });
    assert_eq!(code, "bundle-too-many-ots-anchors");
    assert!(
        peak <= capped.len() + SLACK,
        "peak single allocation {peak} B for a {} B input claiming u64::MAX entries",
        capped.len()
    );
    assert!(total <= capped.len() + SLACK, "total {total} B");

    // 2. An **uncapped** map: `signatures` has no cap by decision (D10 §3),
    //    so the clamp alone must bound it.
    let uncapped = manifest_claiming(u64::MAX);
    assert!(uncapped.len() < 32);
    let (peak, total) = measure(|| {
        let _ = Manifest::decode(&uncapped).map(|_| ());
    });
    assert!(
        peak <= uncapped.len() + SLACK,
        "peak single allocation {peak} B for a {} B uncapped-list input",
        uncapped.len()
    );
    assert!(total <= uncapped.len() + SLACK, "total {total} B");
}

/// The same assertion at the boundary that matters most: a claim of exactly
/// the cap, from an input far too small to hold it. The cap admits it, so
/// only the clamp stands between the head and
/// `MAX_OTS_ANCHOR_COUNT * size_of::<OtsAnchor>()` = 34 816 B for a ~115-byte
/// input.
///
/// **Two corrections here (F30).** The docstring named `covered_reveals` and
/// `CoveredReveal` while the fixture builds `ots_anchors`; and the fixture
/// used the always-8-byte length head, which is `cbor-non-shortest-length`
/// for 256 — so the decode died at step 1 of D10 §4's order and never reached
/// the cap it claims to be testing. The two `assert_ne!`s below are what keep
/// it from going vacuous again, and
/// [`the_amplification_fixtures_are_not_vacuous`] does the same for the F30
/// fixtures.
#[test]
fn an_at_cap_claim_from_a_tiny_input_allocates_only_what_the_input_could_hold() {
    const SLACK: usize = 4 * 1024;
    let input = bundle_claiming(caps::MAX_OTS_ANCHOR_COUNT);
    let code = BundleV1::decode(&input)
        .map(|_| ())
        .expect_err("truncated at the array head")
        .code();
    assert_ne!(
        code, "cbor-non-shortest-length",
        "the length head must be canonical, or the cap and the clamp are never reached"
    );
    assert_ne!(
        code, "bundle-too-many-ots-anchors",
        "an at-cap claim must pass the cap, or only the cap is being tested"
    );
    let (peak, total) = measure(|| {
        let _ = BundleV1::decode(&input).map(|_| ());
    });
    assert!(
        peak <= input.len() + SLACK,
        "peak {peak} B for a {} B input claiming {} entries",
        input.len(),
        caps::MAX_OTS_ANCHOR_COUNT
    );
    assert!(total <= input.len() + SLACK, "total {total} B");
}

/// **F30 / F17's finding.** The reservation must never exceed the bytes that
/// drove it — in *bytes*, which is the unit the two fixtures above cannot
/// distinguish.
///
/// `clamped_capacity` takes `min(claimed_elements, remaining_bytes)` and hands
/// the result to `Vec::with_capacity`, which multiplies it by
/// `size_of::<T>()`. Before F30 the reservation was therefore
/// `min(claimed, remaining) x size_of::<T>()` bytes — up to `size_of::<T>()`
/// times the attacker's own input, 192x at the `files` array. It went
/// unnoticed for two reasons, both structural:
///
/// 1. every fixture above puts its container head **last**, so `remaining()`
///    is 0 and the clamp collapses to zero whatever its units; and
/// 2. `SLACK` is 4 KiB while the fixtures are under 128 B, so even a 32x
///    multiplier fits inside the slack.
///
/// This test removes both: the inputs are kilobytes, the heads are followed
/// by a tail, and the asserted bound is the input length itself.
#[test]
fn the_reservation_never_exceeds_the_input_that_drove_it() {
    const SLACK: usize = 4 * 1024;

    // 1. `signatures` — the uncapped map F17's fuzzer reached first.
    //    Entries are `(SigAlg, Vec<u8>)`: 32 B each on x86-64.
    let sig_input = manifest_claiming_with_tail(u64::MAX, 64 * 1024);
    let (sig_peak, sig_total) = measure(|| {
        let _ = Manifest::decode(&sig_input).map(|_| ());
    });

    // 2. `files` — the largest clamped element in the format (`FileEntry`),
    //    and a **capped** list, so this also shows that passing the cap is
    //    not the same as being bounded by the input.
    let files_input = body_claiming_files_with_tail(caps::MAX_FILE_COUNT, 20_000);
    let (files_peak, files_total) = measure(|| {
        let _ = ManifestBodyV1::decode(&files_input).map(|_| ());
    });

    // Both measurements are taken before either is asserted, so one failure
    // still reports the other site's number — the amplification factor is a
    // property of the element type, so the two numbers are the evidence.
    let report = format!(
        "signatures: peak {sig_peak} B / total {sig_total} B for a {} B input; \
         files: peak {files_peak} B / total {files_total} B for a {} B input",
        sig_input.len(),
        files_input.len()
    );
    assert!(
        sig_peak <= sig_input.len() + SLACK && sig_total <= sig_input.len() + SLACK,
        "the reservation is scaled by size_of::<(SigAlg, Vec<u8>)>() instead of being \
         bounded by the remaining bytes — {report}"
    );
    assert!(
        files_peak <= files_input.len() + SLACK && files_total <= files_input.len() + SLACK,
        "at-cap is not the same as bounded by the input ({} claimed entries) — {report}",
        caps::MAX_FILE_COUNT
    );
}

/// The fixtures reach the clamped allocation rather than dying at head
/// canonicality first.
///
/// Without this, `the_reservation_never_exceeds_the_input_that_drove_it` could
/// pass vacuously — which is exactly how the at-cap test below stood for a
/// wave: it built its length head with the always-8-byte [`head`], which is
/// `cbor-non-shortest-length` for 256 and is refused at step 1 of D10 §4's
/// order, before any allocation.
#[test]
fn the_amplification_fixtures_are_not_vacuous() {
    let input = manifest_claiming_with_tail(u64::MAX, 64);
    let code = Manifest::decode(&input)
        .map(|_| ())
        .expect_err("junk tail cannot decode as a sig_alg key")
        .code();
    assert_ne!(
        code, "cbor-non-shortest-length",
        "the signatures head must be canonical, or the clamp is never reached"
    );

    let input = body_claiming_files_with_tail(caps::MAX_FILE_COUNT, 64);
    let code = ManifestBodyV1::decode(&input)
        .map(|_| ())
        .expect_err("junk tail cannot decode as a file entry")
        .code();
    assert_ne!(
        code, "cbor-non-shortest-length",
        "the files head must be canonical, or the cap and the clamp are never reached"
    );
    assert_ne!(
        code, "manifest-too-many-files",
        "an at-cap claim must pass the cap, so that only the clamp bounds the allocation"
    );
}
