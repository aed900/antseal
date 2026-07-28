//! C22/D88 — the residue regression test for the `sha2` `zeroize` feature.
//!
//! `docs/dependency-policy.md` §1 records the property this file guards:
//! **`sha2`'s non-default `zeroize` feature is load-bearing and has no
//! compile-time detector.** The compile-time `ZeroizeOnDrop` assertions in
//! `crypto.rs::zeroization_sweep` cannot see it, because the wipe is ordinary
//! **drop glue on fields** — `Sha256VarCore::drop` and `BlockBuffer::drop`,
//! both `#[cfg(feature = "zeroize")]` — and not a trait bound. `digest`'s
//! `buffer_fixed!` `ZeroizeOnDrop` arm emits a marker impl with **no `Drop`**,
//! so no assertion over `Hmac<Sha256>` or `Sha256` can distinguish a build
//! with the feature from one without it. These tests are the only guard.
//!
//! Drop the feature from the workspace pin and this file goes red with the
//! recoverable bytes named in the failure message. That is the whole point:
//! a zeroization test that passes either way is worthless.
//!
//! # The probe, and why it needs `unsafe`
//!
//! Residue is a claim about *memory after a value is gone*, which safe Rust
//! deliberately cannot express — once a value drops, its storage is
//! unreachable. So the probe owns the storage instead of the value:
//!
//! 1. allocate raw bytes with the value's exact `Layout`;
//! 2. poison every byte with [`POISON`] (`0xAA`), so "untouched" is
//!    distinguishable from "wiped" — an all-zero result cannot be an artefact
//!    of a fresh zeroed allocation;
//! 3. move the constructed value into the allocation with `ptr::write`;
//! 4. run its destructor with `ptr::drop_in_place`, which does **not** free;
//! 5. read the bytes back and dealloc.
//!
//! `probe_reads_real_bytes_of_a_type_that_does_not_wipe` is the control: it
//! runs the same probe over a plain `[u8; 32]`, which has no `Drop`, and
//! asserts the fixture comes back **verbatim**. Without that control, "all
//! bytes are zero" would be an unfalsifiable claim about the probe rather
//! than a measurement of the crates under test.
//!
//! ## Invariants upheld (the workspace `unsafe_code = "deny"` opt-out)
//!
//! - The allocation is non-zero-sized (asserted) and correctly aligned for
//!   `T`, because the layout is `Layout::new::<T>()`.
//! - `ptr::write` initialises the slot without dropping the uninitialised
//!   previous contents; the value is dropped exactly once, by
//!   `drop_in_place`, and never read as a `T` afterwards.
//! - `dealloc` receives the same pointer and the same layout `alloc` returned.
//! - **Deliberate caveat:** reading the post-`drop_in_place` bytes as `u8` is
//!   exactly the thing the abstract machine considers logically deinitialised,
//!   and a `T` with padding may leave padding bytes the compiler never copied.
//!   That is inherent to measuring residue at all, it is why this is a
//!   test-only probe rather than a library helper, and it is why the file
//!   carries `#![allow(unsafe_code)]` with this justification instead of the
//!   technique living anywhere near production code.
//!
//! Native only. R5 of `docs/zeroization-audit.md` already records that a
//! zeroization claim is meaningless under `wasm32` — the engine may have
//! copied the bytes before they reached linear memory and `memory.grow` may
//! relocate the whole heap — so measuring residue there would assert
//! something the platform does not promise.
//!
//! Both cases use the documented **NON-SECRET** fixture
//! `TEST_MASTER_SECRET_W` = `0x00 0x01 … 0x1f` (project rule 6: no real vault
//! material in fixtures, including in a test whose failure message prints the
//! bytes it found).

#![cfg(not(target_arch = "wasm32"))]
#![allow(unsafe_code)]

use std::alloc::{Layout, alloc, dealloc};
use std::ptr;

use antseal_core::crypto::domain::TAG_GGM_SALT_CHILD;
use antseal_core::test_util::TEST_MASTER_SECRET_W;
use hkdf::{Hkdf, HkdfExtract};
use sha2::{Digest, Sha256};

/// Fill byte for the probe's allocation. Distinct from `0x00` so a wiped
/// result is provably a wipe, and distinct from every fixture byte so an
/// untouched region is recognisable on sight.
const POISON: u8 = 0xAA;

/// Construct `T` inside an allocation this function owns, drop it, and return
/// what the destructor left behind. See the module docs for the invariants.
fn residue_after_drop<T>(construct: impl FnOnce() -> T) -> Vec<u8> {
    let size = size_of::<T>();
    assert!(size > 0, "the probe needs a non-zero-sized value");
    let layout = Layout::new::<T>();

    // SAFETY: `layout` has non-zero size, asserted above.
    let raw = unsafe { alloc(layout) };
    assert!(!raw.is_null(), "probe allocation failed for {size} bytes");

    // SAFETY: `raw` is a live allocation of exactly `size` writable bytes.
    unsafe { ptr::write_bytes(raw, POISON, size) };

    let slot = raw.cast::<T>();
    // SAFETY: `slot` is aligned for `T` (the layout is `T`'s own) and points
    // at `size_of::<T>()` writable bytes. `write` initialises the slot and
    // does not drop the previous, uninitialised contents.
    unsafe { ptr::write(slot, construct()) };

    // SAFETY: `slot` holds the live `T` written immediately above; this is
    // its single drop, and it is never read as a `T` again. `drop_in_place`
    // runs the destructor without freeing the allocation.
    unsafe { ptr::drop_in_place(slot) };

    // SAFETY: the allocation is still live — `drop_in_place` does not free —
    // and every one of its `size` bytes was written by the poison fill.
    let residue = unsafe { std::slice::from_raw_parts(raw.cast_const(), size) }.to_vec();

    // SAFETY: `raw` came from `alloc` with this exact `layout` and has not
    // been freed.
    unsafe { dealloc(raw, layout) };

    residue
}

/// Bytes that are neither zero nor still poison — i.e. what the destructor
/// left of the value.
fn non_zero_count(residue: &[u8]) -> usize {
    residue.iter().filter(|byte| **byte != 0x00).count()
}

/// Whether `needle` survives anywhere in `haystack` as a contiguous run.
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    needle.len() <= haystack.len() && haystack.windows(needle.len()).any(|w| w == needle)
}

/// Control: the probe reports real bytes for a type that does **not** wipe.
///
/// A plain `[u8; 32]` has no `Drop`, so `drop_in_place` is a no-op and the
/// fixture must come back verbatim. If this ever passed while the two residue
/// tests below also passed for the wrong reason — a probe that read the wrong
/// memory, or an allocator that handed back zeroed pages — the wrongness
/// would show up here first.
#[test]
fn probe_reads_real_bytes_of_a_type_that_does_not_wipe() {
    let residue = residue_after_drop(|| TEST_MASTER_SECRET_W);
    assert_eq!(
        residue,
        TEST_MASTER_SECRET_W.to_vec(),
        "the probe must read back what a Drop-less type leaves; \
         if this fails the two residue assertions below prove nothing"
    );
    assert!(
        contains(&residue, &TEST_MASTER_SECRET_W),
        "the recoverability search must find a value that is verbatim present"
    );
}

/// D88 §2, second column: a dropped **extract context** keeps no verbatim `W`.
///
/// `Hkdf::new` is `extract(salt, ikm).1`, and `HkdfExtract<Sha256>` is the
/// context it builds and drops on the way: an `Hmac<Sha256>` keyed with the
/// (empty) salt, fed `W` as IKM. `W` is 32 bytes and SHA-256's block is 64, so
/// until `finalize` compresses it `W` sits **verbatim** in the `BlockBuffer`.
/// `docs/zeroization-audit.md` R1 described the exposure as "`W`-equivalent";
/// it is `W` itself, in the clear.
///
/// This case exists because the `Hkdf<Sha256>` test below **cannot** witness
/// that claim: the extract context is consumed inside `Hkdf::new`, and the
/// value handed back holds only the PRK-keyed HMAC. Probing the returned
/// `Hkdf` alone would leave D88's strongest finding unguarded — its
/// "recoverable verbatim `W`" assertion would pass vacuously.
#[test]
fn dropped_hkdf_extract_context_retains_no_verbatim_master_secret() {
    let residue = residue_after_drop(|| {
        let mut extract = HkdfExtract::<Sha256>::new(Some(&[]));
        extract.input_ikm(&TEST_MASTER_SECRET_W);
        extract
    });

    assert!(
        !contains(&residue, &TEST_MASTER_SECRET_W),
        "the master secret W survives VERBATIM in the dropped HKDF extract \
         context ({} of {} bytes non-zero): it is buffered uncompressed until \
         finalize (D88 §1). Check that Cargo.toml still has \
         `sha2 = {{ ..., features = [\"zeroize\"] }}`.",
        non_zero_count(&residue),
        residue.len()
    );
    assert_eq!(
        non_zero_count(&residue),
        0,
        "the dropped HKDF extract context left {} of {} bytes non-zero",
        non_zero_count(&residue),
        residue.len()
    );
}

/// D88 §2, first column: a dropped `Hkdf<Sha256>` keeps nothing of the PRK.
///
/// The value holds an `Hmac<Sha256>` keyed with the HKDF **PRK**, which is
/// `W`-equivalent *for that work*: anyone holding it can produce every unit
/// key, every salt, the fine seed and both signing seeds (MVP-SPEC.md lines
/// 91, 94–98). `expand_multi_info` additionally **clones** it once per 32-byte
/// output block, so each derivation drops several copies.
///
/// Wiped by `sha2/zeroize` (D88 option (d)), through drop glue on
/// `Sha256VarCore` and `BlockBuffer` — not through `ZeroizeOnDrop`, which
/// `Hmac<D>` does not implement under any feature.
#[test]
fn dropped_hkdf_state_retains_no_master_secret_bytes() {
    let residue = residue_after_drop(|| Hkdf::<Sha256>::new(Some(&[]), &TEST_MASTER_SECRET_W));

    assert!(
        !contains(&residue, &TEST_MASTER_SECRET_W),
        "the master secret W survives verbatim in a dropped Hkdf<Sha256> \
         ({} of {} bytes non-zero): enable the `zeroize` feature on the sha2 \
         pin (D88)",
        non_zero_count(&residue),
        residue.len()
    );
    assert_eq!(
        non_zero_count(&residue),
        0,
        "a dropped Hkdf<Sha256> left {} of {} bytes non-zero — the PRK-keyed \
         HMAC state is W-equivalent for this work (docs/zeroization-audit.md \
         R1). Check that Cargo.toml still has \
         `sha2 = {{ ..., features = [\"zeroize\"] }}` (D88).",
        non_zero_count(&residue),
        residue.len()
    );
}

/// D88 §2b: a dropped `Sha256` keeps nothing of the GGM parent seed.
///
/// `content::ggm::child_seed` derives `s_{v‖b} = SHA-256(0x06 ‖ s_v ‖ b)`
/// (MVP-SPEC.md lines 79, 96) through `crypto::domain::tagged_sha256`. The
/// preimage is 34 bytes — under SHA-256's 64-byte block — so the **parent
/// seed** is still uncompressed in the hasher's `BlockBuffer` when the hasher
/// drops. GGM covering seeds are secret puncturable-PRF material: a leaked
/// ancestor seed opens leaves the reveal deliberately withheld
/// (`docs/security-assumptions.md` §3, class 3), and *every* `child_seed`
/// call strands one.
///
/// This gap is not in C21's audit at all; D88 found it while probing R1.
#[test]
fn dropped_sha256_retains_no_ggm_seed() {
    // The parent seed, standing in for `s_v`. Fixture, not vault material.
    let parent_seed = TEST_MASTER_SECRET_W;
    let residue = residue_after_drop(|| {
        let mut hasher = Sha256::new();
        hasher.update([TAG_GGM_SALT_CHILD]);
        hasher.update(parent_seed);
        hasher.update([0x00u8]); // ChildBit::Left
        hasher
    });

    assert!(
        !contains(&residue, &parent_seed),
        "the GGM parent seed survives verbatim in a dropped Sha256 \
         ({} of {} bytes non-zero): every child_seed call would strand one, \
         opening leaves the reveal withheld (D88 §2b)",
        non_zero_count(&residue),
        residue.len()
    );
    assert_eq!(
        non_zero_count(&residue),
        0,
        "a dropped Sha256 left {} of {} bytes non-zero after hashing a GGM \
         child preimage. Check that Cargo.toml still has \
         `sha2 = {{ ..., features = [\"zeroize\"] }}` (D88).",
        non_zero_count(&residue),
        residue.len()
    );
}
