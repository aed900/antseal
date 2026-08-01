//! [`Blob`] — one AEAD-ciphertext byte string that becomes exactly one
//! Autonomi chunk (decision D32).
//!
//! Under D32 there is no data-map path in v1: every antseal blob (unit
//! ciphertext, raw-mirror ciphertext, encrypted manifest) is stored as one
//! chunk, addressed by BLAKE3-256 of its bytes, capped at
//! [`MAX_CHUNK_SIZE`]. The cap is enforced three-deep (D32 Decision 2);
//! this type is the middle layer: **no [`StorageBackend`] impl can ever
//! receive an over-cap blob**, because the constructor refuses to build
//! one.
//!
//! [`StorageBackend`]: crate::StorageBackend

/// The Autonomi chunk-size cap, in bytes: a blob larger than this cannot be
/// stored (D32 hard invariant).
///
/// An **alias of [`antseal_core::storage::MAX_CHUNK_SIZE`]** (S4): the
/// constant lives in `antseal-core` — the WASM-safe crate the M3 linkage
/// layer runs from, which cannot depend on this one — and this crate
/// re-exports it over its existing `antseal-core` dependency edge, so the
/// two crates structurally cannot disagree (a test below pins the alias in
/// case someone ever re-literalizes it). Value pinned to the upstream
/// constant `ant_protocol::MAX_CHUNK_SIZE` (`4 * 1024 * 1024`,
/// `ant-protocol-2.3.0/src/chunk.rs:19`; D32 evidence row 3). Note this is
/// a **different** constant from `self_encryption`'s env-overridable
/// `4_190_208`, which is irrelevant to antseal under D32/D35. S9 freezes
/// the value against the pinned upstream source; a change is a deliberate
/// bump event (S20), never a drive-by.
///
/// Why the client side must enforce it: upstream's
/// `prepare_chunk_payment` computes the address and quote plan with **no
/// size check** (`ant-core-0.5.0/src/data/client/batch.rs:354-415`, D32
/// evidence row 4) — an oversized blob would be quoted and **paid**
/// without complaint, burning ANT on a chunk the nodes then reject
/// (`ProtocolError::ChunkTooLarge`). The authoritative rejection is S12's
/// plan validation, before consent/anchor/quote; this constructor is
/// defense in depth beneath it.
pub const MAX_CHUNK_SIZE: usize = antseal_core::storage::MAX_CHUNK_SIZE;

/// Constructing a [`Blob`] over [`MAX_CHUNK_SIZE`] bytes was refused.
///
/// A dedicated error type (not a [`StorageError`] variant): the failure
/// happens at seal *plan* time, before any backend exists or any network
/// operation is conceivable, and D32 Decision 5 requires it to be its own
/// distinct class. The caller-facing rejection — with the `--split`
/// suggestion for eligible text — lives upstream at S12 plan validation;
/// this is the type-level backstop.
///
/// [`StorageError`]: crate::StorageError
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error(
    "blob of {len} bytes exceeds the Autonomi chunk cap of {MAX_CHUNK_SIZE} bytes: a blob is \
     exactly one chunk (D32) and an over-cap blob would be quoted and paid but never stored"
)]
pub struct BlobExceedsChunkCap {
    /// Length of the refused byte string.
    pub len: usize,
}

/// One ciphertext byte string to upload — exactly one Autonomi chunk (D32).
///
/// Invariant, constructor-enforced: `len() <= MAX_CHUNK_SIZE`. The bytes
/// are always AEAD ciphertext (unit ciphertext, raw-mirror ciphertext, or
/// the encrypted manifest blob) — the seal pipeline's ciphertext-only
/// egress rule (S12) means no plaintext ever reaches this type, and
/// therefore never reaches a backend.
///
/// Equality/cloning are byte-wise; `Debug` prints only the length (a blob
/// is opaque ciphertext, and multi-MiB dumps help nobody).
#[derive(Clone, PartialEq, Eq)]
pub struct Blob {
    bytes: Vec<u8>,
}

impl Blob {
    /// Wrap ciphertext bytes as a storable blob.
    ///
    /// # Errors
    ///
    /// [`BlobExceedsChunkCap`] if `bytes.len() > MAX_CHUNK_SIZE` — a typed
    /// error, never a panic: the check exists precisely so over-cap content
    /// fails cheap and loud before any money can move (D32).
    pub fn new(bytes: Vec<u8>) -> Result<Self, BlobExceedsChunkCap> {
        if bytes.len() > MAX_CHUNK_SIZE {
            return Err(BlobExceedsChunkCap { len: bytes.len() });
        }
        Ok(Self { bytes })
    }

    /// The ciphertext bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Length in bytes (always `<= MAX_CHUNK_SIZE`).
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Whether the blob is empty. (antseal never produces one — the
    /// smallest unit ciphertext is 272 B — but emptiness is not this
    /// type's invariant to enforce.)
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Consume the blob, returning the ciphertext bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

impl core::fmt::Debug for Blob {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Blob")
            .field("len", &self.bytes.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cap_constant_is_the_pinned_upstream_value() {
        // ant-protocol-2.3.0/src/chunk.rs:19 — `4 * 1024 * 1024`. S9 pins
        // this against the real crate; this local assertion makes a typo
        // here loud on its own.
        assert_eq!(MAX_CHUNK_SIZE, 4 * 1024 * 1024);
        assert_eq!(MAX_CHUNK_SIZE, 4_194_304);
    }

    #[test]
    fn cap_constant_is_shared_with_core_not_duplicated() {
        // S4's cross-crate rule: core owns the constant (it cannot depend
        // on net), net aliases it. This test is what keeps a future edit
        // from re-literalizing the alias and letting the two drift.
        assert_eq!(MAX_CHUNK_SIZE, antseal_core::storage::MAX_CHUNK_SIZE);
        // And the cap relates to S4's address rule exactly as documented:
        // cap-edge input has an address, cap+1 has none.
        assert!(antseal_core::storage::compute_storage_address(&vec![0u8; MAX_CHUNK_SIZE]).is_ok());
        assert!(
            antseal_core::storage::compute_storage_address(&vec![0u8; MAX_CHUNK_SIZE + 1]).is_err()
        );
    }

    #[test]
    fn cap_edge_is_accepted() {
        let blob = Blob::new(vec![0xAB; MAX_CHUNK_SIZE]).expect("cap-edge blob is storable");
        assert_eq!(blob.len(), MAX_CHUNK_SIZE);
        assert!(!blob.is_empty());
    }

    #[test]
    fn over_cap_is_a_typed_error_not_a_panic() {
        let err = Blob::new(vec![0xAB; MAX_CHUNK_SIZE + 1]).expect_err("cap + 1 must be refused");
        assert_eq!(
            err,
            BlobExceedsChunkCap {
                len: MAX_CHUNK_SIZE + 1
            }
        );
        let msg = err.to_string();
        assert!(msg.contains("4194304"), "cap named in the message: {msg}");
    }

    #[test]
    fn bytes_round_trip() {
        let bytes = vec![1u8, 2, 3, 4];
        let blob = Blob::new(bytes.clone()).expect("small blob");
        assert_eq!(blob.as_bytes(), bytes.as_slice());
        assert_eq!(blob.clone().into_bytes(), bytes);
    }

    #[test]
    fn debug_prints_length_not_content() {
        let blob = Blob::new(vec![0xEE; 16]).expect("small blob");
        let dbg = format!("{blob:?}");
        assert_eq!(dbg, "Blob { len: 16 }");
        assert!(
            !dbg.contains("EE") && !dbg.contains("238"),
            "no content bytes in Debug: {dbg}"
        );
    }
}
