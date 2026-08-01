//! Deterministic Autonomi storage-address recomputation (task S4;
//! decisions D32/D35).
//!
//! One rule, stated once: an antseal blob — a unit ciphertext, a raw-mirror
//! ciphertext, or the encrypted manifest blob — is exactly **one** Autonomi
//! chunk (D32), and its network address is **BLAKE3-256 of the ciphertext
//! bytes**. That is upstream's own chunk-address function, recomputed here
//! with the exact-pinned `blake3` crate alone:
//!
//! - `compute_address(content) = *blake3::hash(content).as_bytes()`
//!   (`ant-protocol-2.3.0/src/data_types.rs:10-12`);
//! - `pub type XorName = [u8; 32]` (`ant-protocol-2.3.0/src/chunk.rs:43`).
//!
//! [`compute_storage_address`] is called at seal time to compute every
//! ciphertext address *before* `quote_batch` (S12; MVP-SPEC.md line 34),
//! and it is the primitive the M3 offline storage-linkage layer (R20;
//! MVP-SPEC.md line 119) uses to check that a bundle's embedded ciphertext
//! derives the manifest's recorded [`ContentAddress`] — fully offline, in
//! the WASM verifier page, with no network and no upstream code.
//!
//! # The cap is part of the rule
//!
//! v1 has **no data-map path** (D32): content over [`MAX_CHUNK_SIZE`] has
//! no address at all, so an over-cap input is a typed rejection
//! ([`ExceedsChunkCap`]), never a hash. The caller-facing rejection lives
//! upstream at S12 plan validation (before consent, anchors, or quote —
//! upstream's client would quote and *pay* for an unstorable chunk without
//! complaint, D32 evidence row 4); this function's check is defense in
//! depth beneath it, and the reason a `> MAX_CHUNK_SIZE` golden vector is a
//! committed *rejection* case rather than a committed address.
//!
//! # Spec-deviation flag (D32, recorded — not silent divergence)
//!
//! MVP-SPEC.md lines 34/51/110/119 name the mechanism "via
//! `self_encryption`". Under D32/D35 the mechanism is BLAKE3-256 — the
//! chunk-address function of ant-core's own storage model — and no antseal
//! crate depends on `self_encryption` at all (CI-enforced, `scripts/
//! ci-lanes.sh dep-graph`). The spec's *requirements* behind those lines —
//! pre-quote address computation; deterministic, offline, WASM-safe
//! recomputation in `antseal-core` — are satisfied by this module.
//!
//! # Determinism and the golden vectors
//!
//! BLAKE3 is a fixed function; the committed `storage-address` golden
//! vectors (`testdata/vectors/v1/storage/`), not the crate version, are the
//! determinism authority (D35 decision 3). The Q5 native↔wasm32 bit-match
//! lane executes them on both targets and byte-compares every recomputed
//! address.

use crate::manifest::ContentAddress;

/// The Autonomi chunk-size cap, in bytes: content larger than this has no
/// v1 storage address and cannot be stored (D32 hard invariant).
///
/// Pinned to the upstream constant `ant_protocol::MAX_CHUNK_SIZE`
/// (`4 * 1024 * 1024`, `ant-protocol-2.3.0/src/chunk.rs:19`; D32 evidence
/// row 3). Note this is a **different** constant from `self_encryption`'s
/// compile-time-overridable `4_190_208`, which is irrelevant to antseal
/// under D32/D35.
///
/// `antseal-net` re-exports this value as its own `MAX_CHUNK_SIZE` (this
/// crate must not depend on `antseal-net`, so the constant lives here and
/// net aliases it; a cross-crate equality test in net keeps the two from
/// ever re-diverging). S9 freezes the value against the pinned upstream
/// source; a change is a deliberate bump event (S20), never a drive-by.
pub const MAX_CHUNK_SIZE: usize = 4_194_304;

/// The input handed to [`compute_storage_address`] exceeds
/// [`MAX_CHUNK_SIZE`], so **no v1 address exists for it** (D32: one blob =
/// one chunk; the data-map path does not exist in v1).
///
/// A typed error, never a panic: over-cap content must fail cheap and loud
/// before any money can move (the authoritative, user-facing rejection —
/// with the `--split` suggestion for eligible text — is S12's plan
/// validation; this is the primitive-level backstop).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error(
    "input of {len} bytes exceeds the Autonomi chunk cap of {MAX_CHUNK_SIZE} bytes — one blob is \
     exactly one chunk (D32) and no v1 storage address exists for over-cap content"
)]
pub struct ExceedsChunkCap {
    /// Length of the rejected input, in bytes.
    pub len: usize,
}

/// Compute the Autonomi storage address of one blob: **BLAKE3-256 of the
/// ciphertext bytes** (D32; `compute_address`,
/// `ant-protocol-2.3.0/src/data_types.rs:10-12`).
///
/// Deterministic, offline, WASM-safe: same bytes ⇒ same address on every
/// target, forever — the property the manifest's recorded addresses, the
/// seal pipeline's pre-quote computation (S12), and the M3 storage-linkage
/// layer (R20) all rest on. Address equality against real
/// ant-core-assigned addresses is asserted on a live devnet by S9/S17.
///
/// # Errors
///
/// [`ExceedsChunkCap`] if `blob_bytes.len() > MAX_CHUNK_SIZE`: over-cap
/// content has no v1 address (module docs; D32 decision 5).
pub fn compute_storage_address(blob_bytes: &[u8]) -> Result<ContentAddress, ExceedsChunkCap> {
    if blob_bytes.len() > MAX_CHUNK_SIZE {
        return Err(ExceedsChunkCap {
            len: blob_bytes.len(),
        });
    }
    Ok(ContentAddress::from_bytes(
        *blake3::hash(blob_bytes).as_bytes(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// BLAKE3-256 of the empty string — the first entry of the official
    /// BLAKE3 test vectors (BLAKE3-team `test_vectors.json`, input length
    /// 0), spelled here as an independent literal so the wasm32 `--lib`
    /// lane carries at least one known-answer check without file I/O.
    const BLAKE3_EMPTY: [u8; 32] = [
        0xaf, 0x13, 0x49, 0xb9, 0xf5, 0xf9, 0xa1, 0xa6, 0xa0, 0x40, 0x4d, 0xea, 0x36, 0xdc, 0xc9,
        0x49, 0x9b, 0xcb, 0x25, 0xc9, 0xad, 0xc1, 0x12, 0xb7, 0xcc, 0x9a, 0x93, 0xca, 0xe4, 0x1f,
        0x32, 0x62,
    ];

    /// The official BLAKE3 test-vector input pattern: `byte[i] = i % 251`.
    /// The committed `storage-address` golden vectors generate their inputs
    /// with the same formula (testdata/vectors/v1/storage/README.md).
    fn pattern_bytes(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8).collect()
    }

    #[test]
    fn cap_is_the_pinned_upstream_value() {
        // ant-protocol-2.3.0/src/chunk.rs:19 — `4 * 1024 * 1024`. S9 pins
        // this against the real crate on a devnet; this local assertion
        // makes a typo here loud on its own, and antseal-net's
        // cross-crate test pins its alias to this constant.
        assert_eq!(MAX_CHUNK_SIZE, 4 * 1024 * 1024);
        assert_eq!(MAX_CHUNK_SIZE, 4_194_304);
    }

    #[test]
    fn empty_input_has_the_known_blake3_address() {
        let address = compute_storage_address(&[]).expect("empty input is under the cap");
        assert_eq!(address.as_bytes(), &BLAKE3_EMPTY);
    }

    #[test]
    fn cap_edge_is_accepted_and_cap_plus_one_is_a_typed_rejection() {
        // Exactly MAX_CHUNK_SIZE: storable, has an address.
        let edge = vec![0xAB; MAX_CHUNK_SIZE];
        let address = compute_storage_address(&edge).expect("cap-edge input is addressable");
        assert_eq!(address.as_bytes().len(), 32);

        // cap + 1: no address exists in v1 (D32) — typed error, no panic.
        let over = vec![0xAB; MAX_CHUNK_SIZE + 1];
        let err = compute_storage_address(&over).expect_err("cap + 1 must be rejected");
        assert_eq!(
            err,
            ExceedsChunkCap {
                len: MAX_CHUNK_SIZE + 1
            }
        );
        let msg = err.to_string();
        assert!(msg.contains("4194304"), "cap named in the message: {msg}");
        assert!(
            msg.contains("4194305"),
            "length named in the message: {msg}"
        );
    }

    #[test]
    fn same_bytes_same_address_across_calls() {
        let bytes = pattern_bytes(272);
        let first = compute_storage_address(&bytes).expect("under cap");
        let second = compute_storage_address(&bytes).expect("under cap");
        assert_eq!(first, second);
        // A different input (one byte flipped) must not map to the same
        // address — the sanity direction of content addressing.
        let mut flipped = bytes;
        flipped[0] ^= 0x01;
        let third = compute_storage_address(&flipped).expect("under cap");
        assert_ne!(first, third);
    }

    #[test]
    fn one_shot_equals_incremental_hashing() {
        // The function hashes in one shot; the crate's incremental hasher
        // must agree — the two API paths cannot be allowed to diverge,
        // because S12 (whole blobs in memory) and any future streaming
        // caller must compute the identical address.
        let bytes = pattern_bytes(3 * 1024 + 17);
        let one_shot = compute_storage_address(&bytes).expect("under cap");
        let mut hasher = blake3::Hasher::new();
        hasher.update(&bytes[..1000]);
        hasher.update(&bytes[1000..1024]);
        hasher.update(&bytes[1024..]);
        assert_eq!(one_shot.as_bytes(), hasher.finalize().as_bytes());
    }

    // ── property tests (native-only; the wasm32 lane runs the
    //    deterministic unit tests above) ─────────────────────────────────
    #[cfg(feature = "test-util")]
    mod properties {
        use super::*;
        use crate::test_util::proptest::prelude::*;
        use crate::test_util::strategies::proptest_config;

        proptest! {
            #![proptest_config(proptest_config(0x5EED_0054))]

            /// Determinism: same bytes ⇒ same address, and the address is
            /// exactly the crate's one-shot hash (no hidden state).
            #[test]
            fn address_is_deterministic(bytes in proptest::collection::vec(any::<u8>(), 0..4096)) {
                let a = compute_storage_address(&bytes).expect("under cap");
                let b = compute_storage_address(&bytes).expect("under cap");
                prop_assert_eq!(a, b);
            }

            /// Incremental hashing at an arbitrary split point agrees with
            /// the one-shot address.
            #[test]
            fn split_point_never_changes_the_address(
                bytes in proptest::collection::vec(any::<u8>(), 1..4096),
                split_seed in any::<usize>(),
            ) {
                let split = split_seed % (bytes.len() + 1);
                let one_shot = compute_storage_address(&bytes).expect("under cap");
                let mut hasher = blake3::Hasher::new();
                hasher.update(&bytes[..split]);
                hasher.update(&bytes[split..]);
                let incremental = hasher.finalize();
                prop_assert_eq!(one_shot.as_bytes(), incremental.as_bytes());
            }

            /// Appending a byte always moves the address (extension must
            /// never be address-neutral).
            #[test]
            fn appending_a_byte_moves_the_address(
                bytes in proptest::collection::vec(any::<u8>(), 0..2048),
                extra in any::<u8>(),
            ) {
                let base = compute_storage_address(&bytes).expect("under cap");
                let mut extended = bytes;
                extended.push(extra);
                let moved = compute_storage_address(&extended).expect("under cap");
                prop_assert_ne!(base, moved);
            }
        }
    }
}
