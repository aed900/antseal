//! S9 — the storage constants and behaviours, frozen against the pinned
//! upstream.
//!
//! This is the M1-mandated upstream-verification suite: every number here
//! is either **linked** (compared against the constant upstream actually
//! compiles, so a bump breaks the build or the test) or **derived** (the
//! formula is asserted, not the answer). A deliberate `ant-core` /
//! `ant-protocol` bump under S20's procedure is the only way these change.
//!
//! # Layout
//!
//! - The **derivation** half runs in the DEFAULT feature set: the cap, the
//!   padding/AEAD arithmetic, the size ladder, and the two over-cap
//!   refusals. No upstream graph needed.
//! - The **linkage** half is `#[cfg(feature = "ant-backend")]`: equality
//!   with `ant_protocol`'s own constants. That is the assertion with teeth
//!   — the default half would happily agree with itself after an upstream
//!   change.
//! - The devnet half (network-assigned addresses across the ladder,
//!   `get_data` byte-identity) is `tests/devnet_backend.rs`, env-gated.
//!
//! # The proof-age finding (S9's investigation, 2026-08-02)
//!
//! S9 was asked to pin `QUOTE_MAX_AGE_SECS` (~24 h) as "node-side proof
//! validity". **That constant does not exist in the pinned ant-node
//! 0.15.0, and neither does the enforcement D37 attributed to it.**
//! Evidence, all from the pinned sources:
//!
//! | claim | pinned reality |
//! |---|---|
//! | `QUOTE_MAX_AGE_SECS` in `ant-node/src/payment/verifier.rs` (cited by `ant-core-0.5.0/src/data/client/batch.rs:1051-1058` and `.../cached_single.rs:48-58`) | **0 occurrences** anywhere in `ant-node-0.15.0` |
//! | `QUOTE_FUTURE_SKEW_TOLERANCE_SECS = 300` in the same file (cited by `batch.rs:1060-1069`) | **0 occurrences** |
//! | a storer-side `validate_quote_timestamps` call (cited by `batch.rs:1042-1049`) | **0 occurrences** |
//!
//! The single-node payment path antseal uses (D37 excludes merkle mode)
//! is `verify_payment_inner` → `ProofType::SingleNode` →
//! `verify_evm_payment` (`ant-node-0.15.0/src/payment/verifier.rs:801`,
//! `:835`, `:945`). Its steps — documented at `verifier.rs:938-944` and
//! confirmed against the body — are: `validate_quote_structure`,
//! `validate_quote_arithmetic`, median-candidate selection, per-candidate
//! content/peer binding + ML-DSA-65 signature + K-closeness + on-chain
//! 3× settlement, price floor, ADR-0004 cross-check. **No timestamp gate
//! at any step**, and the one staleness gate the file mentions was
//! deliberately retired (`verifier.rs:966-971`: the price-binding check
//! "RETIRES the percentage-based own-quote price-staleness gate").
//!
//! The only proof-age enforcement that exists in the pinned stack is
//! [`MERKLE_PAYMENT_EXPIRATION`] — 7 days, on the **merkle** path, which
//! D37 excludes from antseal's paid path. It is pinned below anyway, as
//! the tripwire: it is where age enforcement lives today, so a bump that
//! moves it (or moves age enforcement onto the single-node path) surfaces
//! here at the S20 review.
//!
//! Consequences, all recorded at source: the ~24 h window is a
//! **client-side, self-imposed** figure (`CACHED_PROOF_MAX_AGE_SECS`
//! governs *ant-core's own* on-disk proof cache — which antseal does not
//! even use, since it journals its own `proof_bytes` and calls
//! `chunk_put_with_proof`), not a network rule. `StorageError::ProofsExpired`
//! stays as a defensive classifier and the "resume promptly" guidance
//! stays conservative — being early costs one re-pay of a cheap chunk,
//! and the mechanism could return upstream at any release. What changed
//! is the **attribution**: see the dated correction in
//! `docs/decisions/D37-multi-tx-payment.md`.
//!
//! [`MERKLE_PAYMENT_EXPIRATION`]: https://docs.rs/evmlib

use antseal_core::bundle::registry::{AEAD_TAG_LEN, MIN_CIPHERTEXT_LEN, PADDING_BLOCK};
use antseal_core::crypto::padding::{PAD_BLOCK, padded_length};
use antseal_core::storage::{MAX_CHUNK_SIZE, compute_storage_address};
use antseal_net::{Blob, MAX_CHUNK_SIZE as NET_MAX_CHUNK_SIZE};

// ===========================================================================
// The size ladder — one definition, shared by this file and the devnet suite
// ===========================================================================

/// Smallest well-shaped unit ciphertext: one padding block plus the tag.
const RUNG_MIN: usize = 272;
/// A mid rung: 256 padding blocks plus the tag.
const RUNG_MID: usize = 65_552;
/// The largest ciphertext a real unit *plaintext* can produce.
const RUNG_MAX_FROM_PLAINTEXT: usize = 4_194_064;
/// The exact chunk cap — storable, but not reachable from a padded unit.
const RUNG_CAP_EDGE: usize = 4_194_304;
/// One byte over the cap: refused before any backend exists.
const RUNG_OVER_CAP: usize = 4_194_305;

/// The largest unit *plaintext* (as opposed to ciphertext) that fits.
const MAX_UNIT_PLAINTEXT: usize = 4_194_047;

// ===========================================================================
// Derivation — default feature set
// ===========================================================================

/// The cap itself, and the fact that both crates name the same value.
#[test]
fn the_chunk_cap_is_four_mebibytes_and_both_crates_agree() {
    assert_eq!(MAX_CHUNK_SIZE, 4_194_304);
    assert_eq!(MAX_CHUNK_SIZE, 4 * 1024 * 1024, "= upstream's own spelling");
    assert_eq!(
        NET_MAX_CHUNK_SIZE, MAX_CHUNK_SIZE,
        "antseal-net's alias must stay an alias, never a re-literalized copy"
    );
}

/// The padding/AEAD constants the ladder is built from.
#[test]
fn the_padding_and_tag_constants_are_frozen_and_self_consistent() {
    assert_eq!(PAD_BLOCK, 256, "v1 padding bucket (spec line 91)");
    assert_eq!(
        PADDING_BLOCK, PAD_BLOCK as u64,
        "the bundle registry and the crypto codec must name one block size"
    );
    assert_eq!(AEAD_TAG_LEN, 16, "XChaCha20-Poly1305 tag");
    assert_eq!(MIN_CIPHERTEXT_LEN, PADDING_BLOCK + AEAD_TAG_LEN);
    assert_eq!(MIN_CIPHERTEXT_LEN, RUNG_MIN as u64);
}

/// The smallest rung, derived: an empty plaintext still pads to a full
/// block, so 272 B is the floor for *any* unit ciphertext.
#[test]
fn the_smallest_unit_ciphertext_is_derived_not_assumed() {
    assert_eq!(padded_length(0), PAD_BLOCK, "padding always adds ≥ 1 byte");
    assert_eq!(padded_length(0) + AEAD_TAG_LEN as usize, RUNG_MIN);
    // The next plaintext byte does not grow it: the floor holds across the
    // whole first block.
    assert_eq!(
        padded_length(PAD_BLOCK - 1) + AEAD_TAG_LEN as usize,
        RUNG_MIN
    );
    // ...and the byte after that does.
    assert_eq!(
        padded_length(PAD_BLOCK) + AEAD_TAG_LEN as usize,
        RUNG_MIN + PAD_BLOCK
    );
}

/// **The derivation S9 asks for, asserted as a derivation.**
///
/// The max unit plaintext is not a magic number: it falls out of the cap,
/// the block size and the tag, through `padded_length` itself.
#[test]
fn the_max_unit_plaintext_is_derived_from_the_cap_the_block_and_the_tag() {
    let tag = AEAD_TAG_LEN as usize;

    // The largest padded buffer that still leaves room for the tag.
    let max_padded = (MAX_CHUNK_SIZE - tag) / PAD_BLOCK * PAD_BLOCK;
    assert_eq!(max_padded, 4_194_048);

    // `padded_length` is STRICTLY greater than its input, so the largest
    // plaintext landing on `max_padded` is one byte short of it.
    let max_plaintext = max_padded - 1;
    assert_eq!(padded_length(max_plaintext), max_padded);
    assert_eq!(
        max_plaintext, MAX_UNIT_PLAINTEXT,
        "the derived value must equal the recorded 4_194_047"
    );

    // Its ciphertext is the largest a real unit can produce, and it fits.
    let max_ciphertext = padded_length(max_plaintext) + tag;
    assert_eq!(max_ciphertext, RUNG_MAX_FROM_PLAINTEXT);
    assert!(max_ciphertext <= MAX_CHUNK_SIZE);

    // One more plaintext byte crosses a block boundary and overflows the
    // cap by the tag — this is *why* the max is 4_194_047 and not more.
    let over = padded_length(max_plaintext + 1) + tag;
    assert_eq!(over, MAX_CHUNK_SIZE + tag);
    assert!(
        over > MAX_CHUNK_SIZE,
        "plaintext {} pads to {} and cannot carry its tag under the cap",
        max_plaintext + 1,
        padded_length(max_plaintext + 1)
    );

    // The cap edge is storable but unreachable from a padded unit: no
    // plaintext produces exactly 4_194_304 bytes of ciphertext. Compared
    // against the DERIVED maximum, not the recorded rung — comparing two
    // constants would assert nothing.
    assert!(
        RUNG_CAP_EDGE > max_ciphertext,
        "the cap edge must sit above every plaintext-derived ciphertext"
    );
    assert_ne!(
        (RUNG_CAP_EDGE - tag) % PAD_BLOCK,
        0,
        "cap − tag is not a whole number of padding blocks"
    );
}

/// Every rung is constructible, and the over-cap rung is refused twice —
/// at S4's address rule and at the `Blob` constructor — before any
/// backend exists (D32's three-deep enforcement, two of whose layers are
/// reachable offline).
#[test]
fn the_ladder_is_constructible_and_cap_plus_one_is_refused_offline() {
    for size in [RUNG_MIN, RUNG_MID, RUNG_MAX_FROM_PLAINTEXT, RUNG_CAP_EDGE] {
        let bytes = vec![0xA5u8; size];
        let blob = Blob::new(bytes.clone())
            .unwrap_or_else(|error| panic!("rung {size} must be constructible: {error}"));
        assert_eq!(blob.len(), size);
        compute_storage_address(&bytes)
            .unwrap_or_else(|error| panic!("rung {size} must be addressable: {error}"));
    }

    // Layer 1 (S4, WASM-safe): the address rule refuses it.
    let over = vec![0u8; RUNG_OVER_CAP];
    let error = compute_storage_address(&over).expect_err("cap + 1 has no address");
    assert_eq!(error.len, RUNG_OVER_CAP);

    // Layer 2 (the storage boundary): no `StorageBackend` impl can ever
    // receive it, because the value cannot be built.
    let error = Blob::new(over).expect_err("cap + 1 is not a blob");
    assert_eq!(error.len, RUNG_OVER_CAP);
    assert!(
        error.to_string().contains(&MAX_CHUNK_SIZE.to_string()),
        "the refusal names the cap: {error}"
    );
}

/// The chunk address rule is BLAKE3-256 of the content and nothing else
/// (D32/D11) — pinned against the official BLAKE3 empty-input vector, so
/// a hash-function change cannot pass silently.
#[test]
fn the_chunk_address_rule_is_plain_blake3_256_of_the_content() {
    let empty = compute_storage_address(&[]).expect("empty is under cap");
    assert_eq!(
        hex_lower(empty.as_bytes()),
        "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
        "BLAKE3 official empty-input test vector"
    );

    // Content addressing: equal bytes ⇒ equal address, one flipped bit ⇒
    // a different one.
    let a = compute_storage_address(&[1, 2, 3]).expect("under cap");
    let b = compute_storage_address(&[1, 2, 3]).expect("under cap");
    let c = compute_storage_address(&[1, 2, 4]).expect("under cap");
    assert_eq!(a, b);
    assert_ne!(a, c);
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut acc, byte| {
        use std::fmt::Write as _;
        let _ = write!(acc, "{byte:02x}");
        acc
    })
}

// ===========================================================================
// Linkage — the assertions with teeth (requires the upstream graph)
// ===========================================================================

/// The cap is not a number we chose: it is `ant_protocol`'s, compared
/// against the constant upstream actually compiles.
#[cfg(feature = "ant-backend")]
#[test]
fn the_cap_is_linked_to_ant_protocols_own_constant() {
    assert_eq!(
        MAX_CHUNK_SIZE,
        ant_protocol::chunk::MAX_CHUNK_SIZE,
        "antseal's MAX_CHUNK_SIZE must equal the pinned ant-protocol constant \
         (ant-protocol-2.3.0/src/chunk.rs:19); a divergence here is an upstream bump that S20's \
         procedure must review, never a drive-by"
    );
}

/// The proof-age tripwire (S9's investigation, above).
///
/// `MERKLE_PAYMENT_EXPIRATION` is the **only** proof-age enforcement in
/// the pinned stack (`evmlib-0.9.0/src/merkle_payments/merkle_tree.rs:24`,
/// enforced at `:464`), and it governs the **merkle** path, which D37
/// excludes from antseal's paid path. Pinned as the watchpoint: if
/// upstream changes this window, or moves age enforcement onto the
/// single-node path antseal does use, the S20 bump review sees it here.
///
/// There is deliberately no assertion about `QUOTE_MAX_AGE_SECS`: a
/// constant that does not exist cannot be referenced. Its absence is
/// recorded in this file's module docs and in the D37 correction note.
#[cfg(feature = "ant-backend")]
#[test]
fn the_only_pinned_proof_age_window_is_merkles_seven_days() {
    assert_eq!(
        ant_protocol::evm::MERKLE_PAYMENT_EXPIRATION,
        7 * 24 * 60 * 60,
        "merkle payment expiration = 7 days"
    );
    assert_eq!(ant_protocol::evm::MERKLE_PAYMENT_EXPIRATION, 604_800);
    // Not 24 h — the figure D37 recorded as node-side policy. Stated as an
    // assertion so the two can never be conflated again by inspection.
    assert_ne!(
        ant_protocol::evm::MERKLE_PAYMENT_EXPIRATION,
        24 * 60 * 60,
        "the pinned window is 7 days on the merkle path, NOT the ~24 h D37 attributed to a \
         node-side QUOTE_MAX_AGE_SECS that does not exist"
    );
}

/// Upstream's payment sub-batch cap, linked (D37's ⌈blobs/256⌉ rule and
/// `MockBackend::DEFAULT_MAX_TRANSFERS_PER_TX` both rest on it).
#[cfg(feature = "ant-backend")]
#[test]
fn the_payment_sub_batch_cap_is_linked_to_upstream() {
    assert_eq!(
        antseal_net::test_util::DEFAULT_MAX_TRANSFERS_PER_TX,
        evmlib_max_transfers(),
        "the mock's sub-batch cap must equal upstream's MAX_TRANSFERS_PER_TRANSACTION"
    );
}

/// Upstream exposes the cap through the payment-vault module; read it
/// through the one declared edge (`ant-protocol`, never evmlib direct —
/// the S5 dependency-edge decision).
#[cfg(feature = "ant-backend")]
fn evmlib_max_transfers() -> usize {
    ant_protocol::evm::contract::payment_vault::MAX_TRANSFERS_PER_TRANSACTION
}
