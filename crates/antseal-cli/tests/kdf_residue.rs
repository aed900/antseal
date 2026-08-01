//! U6/D40 — the residue regression test for the blake2 stack inside
//! argon2 (the D88 §2 methodology, replicated for the vault KDF's hash
//! core as D40's pin-time obligation requires).
//!
//! # What is guarded, and why no trait assertion can do it
//!
//! Argon2id's initial hash H0 feeds the **passphrase verbatim** into a
//! `Blake2b512` (argon2-0.6.0-rc.8/src/lib.rs `initial_hash`). blake2's
//! wiping `Drop` on the BLAKE2b core state (`self.h.zeroize();
//! self.t.zeroize()`, blake2-0.11.0-rc.6/src/macros.rs:250-255) and on
//! its block buffer (macros.rs:452-460) is gated on **blake2's own**
//! `zeroize` feature — and argon2's `zeroize` feature does NOT forward it
//! (crates.io index metadata, 2026-08-01: `argon2/zeroize =
//! ["dep:zeroize"]`, blake2 dep listed with no features). The workspace
//! therefore declares blake2 directly, solely to force that feature
//! (workspace Cargo.toml, the D88/hmac-declaration precedent). This file
//! is the behavioral guard on that line: the wipe is ordinary drop glue,
//! not a trait bound, so no `ZeroizeOnDrop` assertion can see it — the
//! `buffer_fixed!` `ZeroizeOnDrop` arm is a marker impl with no `Drop`
//! (D88 §1), and blake2's macro has the same shape.
//!
//! # Red-first evidence (D40: "prove the probe CAN fail")
//!
//! Executed on this exact tree before the pin was believed, 2026-08-01:
//! with the workspace blake2 declaration's `features = ["zeroize"]`
//! removed, `dropped_blake2b512_retains_no_passphrase_bytes` goes RED with
//! **65 bytes of passphrase-derived chaining state** (`h`, residue
//! positions 0–64) surviving the drop — while the block buffer stays
//! wiped, because `digest/zeroize` rides in independently via the sha2
//! pin. That measured split is exactly D88's "half a detector" finding
//! transposed to blake2: the buffer wipe and the core-state wipe are
//! gated by DIFFERENT features, and only the blake2 declaration below
//! turns on the second. With the feature restored the suite is green:
//! every field byte — chaining state, length counter, block buffer — is
//! wiped, and only trailing struct padding (unreachable by any `Drop`;
//! see the in-test comment) survives. The committed control test keeps
//! the probe falsifiable on every run: a probe that cannot read real
//! residue proves nothing.
//!
//! # The probe, and why it needs `unsafe`
//!
//! Identical technique and invariants as
//! `crates/antseal-core/tests/zeroization_residue.rs` (C22/D88): own the
//! allocation, poison it, `ptr::write` the value in, `drop_in_place`,
//! read back. Native only, and the fixture passphrase is a documented
//! NON-SECRET byte pattern (project rule 6).
//!
//! ## Invariants upheld (the workspace `unsafe_code = "deny"` opt-out)
//!
//! - The allocation is non-zero-sized (asserted) and aligned for `T`
//!   (`Layout::new::<T>()`).
//! - `ptr::write` initialises without dropping uninitialised contents;
//!   the value is dropped exactly once, by `drop_in_place`, and never
//!   read as a `T` afterwards.
//! - `dealloc` receives the same pointer and layout `alloc` returned.
//! - Reading post-drop bytes as `u8` is inherent to measuring residue at
//!   all; this technique lives only in test probes, never near
//!   production code.

#![cfg(not(target_arch = "wasm32"))]
#![allow(unsafe_code)]

use std::alloc::{Layout, alloc, dealloc};
use std::ptr;

use blake2::{Blake2b512, Digest};

/// Fill byte for the probe's allocation: distinct from `0x00` so a wiped
/// result is provably a wipe, and absent from the fixture bytes so an
/// untouched region is recognisable.
const POISON: u8 = 0xAA;

/// Documented NON-SECRET fixture "passphrase": 160 bytes cycling
/// `0x30..=0x7F` — longer than BLAKE2b's 128-byte block, so at least one
/// compression has run when the hasher drops and the chaining state `h`
/// is fixture-derived (exercising the core-state wipe, not only the
/// buffer wipe).
fn fixture_passphrase() -> Vec<u8> {
    (0u8..160).map(|i| 0x30 + (i % 0x50)).collect()
}

/// Construct `T` inside an allocation this function owns, drop it, and
/// return what the destructor left behind (module docs: invariants).
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
    // SAFETY: `slot` is aligned for `T` (the layout is `T`'s own) and
    // points at `size_of::<T>()` writable bytes; `write` does not drop
    // the uninitialised previous contents.
    unsafe { ptr::write(slot, construct()) };

    // SAFETY: `slot` holds the live `T` written above; this is its single
    // drop, and it is never read as a `T` again.
    unsafe { ptr::drop_in_place(slot) };

    // SAFETY: still live — `drop_in_place` does not free — and every byte
    // was written by the poison fill.
    let residue = unsafe { std::slice::from_raw_parts(raw.cast_const(), size) }.to_vec();

    // SAFETY: `raw` came from `alloc` with this exact `layout` and has
    // not been freed.
    unsafe { dealloc(raw, layout) };

    residue
}

/// Whether `needle` survives anywhere in `haystack` as a contiguous run.
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    needle.len() <= haystack.len() && haystack.windows(needle.len()).any(|w| w == needle)
}

/// Control: the probe reports real bytes for a type that does **not**
/// wipe. Without this, "all bytes are zero" would be an unfalsifiable
/// claim about the probe rather than a measurement of the crates.
#[test]
fn probe_reads_real_bytes_of_a_type_that_does_not_wipe() {
    let fixture: [u8; 32] = fixture_passphrase()[..32].try_into().expect("sized");
    let residue = residue_after_drop(|| fixture);
    assert_eq!(
        residue,
        fixture.to_vec(),
        "the probe must read back what a Drop-less type leaves; if this \
         fails, the residue assertion below proves nothing"
    );
}

/// The pin gate: a dropped `Blake2b512` that was fed the passphrase — the
/// exact shape argon2's `initial_hash` builds and drops — retains
/// nothing: not the passphrase in its block buffer, not the derived
/// chaining state in its core. Full wipe, the D88 "0 — fully wiped" bar.
#[test]
fn dropped_blake2b512_retains_no_passphrase_bytes() {
    let passphrase = fixture_passphrase();
    let residue = residue_after_drop(|| {
        let mut hasher = Blake2b512::new();
        // argon2's initial_hash shape: little-endian parameter words,
        // then length-prefixed passphrase and salt.
        hasher.update(1u32.to_le_bytes());
        hasher.update((passphrase.len() as u32).to_le_bytes());
        hasher.update(&passphrase);
        hasher.update(16u32.to_le_bytes());
        hasher.update([0x02u8; 16]);
        hasher
    });

    assert!(
        !contains(&residue, &passphrase[..64]),
        "the fixture passphrase survives VERBATIM in the dropped Blake2b512 \
         block buffer: check that the workspace Cargo.toml blake2 line \
         still carries features = [\"zeroize\"] (and that digest/zeroize is \
         still forwarded by the sha2 pin)"
    );
    // Full-wipe claim, minus the one thing no `Drop` can reach: trailing
    // repr(Rust) padding, whose bytes are copied verbatim from the
    // constructing stack frame by the move into the probe's slot (the
    // D88 probe caveat). Measured on the pinned toolchain: 5 bytes of
    // tail padding survive; every *field* byte — chaining state, length
    // counter, block buffer — is zero. The assertion pins that shape
    // structurally: any surviving byte must sit in the final 8-byte tail
    // (the maximum padding of an 8-aligned struct), so an un-wiped field
    // — 64 bytes of `h`, 128 of buffer — can never hide under it.
    let surviving: Vec<(usize, u8)> = residue
        .iter()
        .enumerate()
        .filter(|(_, b)| **b != 0)
        .map(|(i, b)| (i, *b))
        .collect();
    let tail_start = residue.len() - 8;
    assert!(
        surviving.iter().all(|(i, _)| *i >= tail_start),
        "a dropped Blake2b512 left non-padding bytes non-zero at {surviving:?} \
         (struct size {}): blake2's core-state/buffer Drop (macros.rs:250-255, \
         via digest's wrapper) is not active — the workspace blake2 `zeroize` \
         feature has been lost (argon2's own zeroize feature does NOT \
         forward it)",
        residue.len()
    );
}

/// Declaration guard (the C24 middle layer): the workspace manifest still
/// says what the residue test above proves behaviorally. Catches the
/// feature being dropped in a way that leaves some other zeroize source
/// accidentally keeping the residue test green (e.g. a future blake2
/// default-feature change).
#[test]
fn workspace_manifest_still_forces_the_kdf_zeroize_features() {
    let manifest = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../Cargo.toml"),
    )
    .expect("read workspace Cargo.toml");
    let line_with = |name: &str| {
        manifest
            .lines()
            .find(|l| l.trim_start().starts_with(&format!("{name} = ")))
            .unwrap_or_else(|| panic!("workspace manifest lost its {name} declaration"))
    };
    let blake2 = line_with("blake2");
    assert!(
        blake2.contains("\"zeroize\""),
        "the blake2 declaration lost its load-bearing zeroize feature: {blake2}"
    );
    let argon2 = line_with("argon2");
    assert!(
        argon2.contains("\"zeroize\""),
        "the argon2 declaration lost its zeroize feature: {argon2}"
    );
    assert!(
        argon2.contains("=0.6.0-rc.8"),
        "the argon2 rc pin moved without a D40 §4 review: {argon2}"
    );
}
