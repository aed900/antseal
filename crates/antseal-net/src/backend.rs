//! [`StorageBackend`] — the batch-first storage trait (S2), shaped to
//! MVP-SPEC.md lines 63–66.

use crate::{Address, Blob, CostQuote, PaymentReceipt, StorageError};

/// The batch-first Autonomi storage boundary (MVP-SPEC.md lines 60–69).
///
/// # The churn-isolation boundary
///
/// **All Autonomi storage network use goes through this trait.** The
/// ant-core implementation lives in exactly one adapter impl file (S6),
/// so upstream churn — `ant-core` is pinned `=0.5.0` and releases
/// weekly-to-biweekly — stays contained there: the trait, the mock, and
/// every consumer are unaffected by a bump (S20's procedure enforces
/// this). Tests run on `MockBackend` (S3) with no live network.
///
/// **Anchor network I/O is explicitly out of scope for this crate**: the
/// OTS calendar, TSA HTTP, esplora, and two-endpoint Arbitrum
/// *confirmation* clients — anchor-**evidence** I/O — live in
/// `antseal-anchor` (spec line 60; D33's scope note on the S2 accept).
/// The **payment RPC is in scope**: submitting, confirming, and
/// backfilling the payment transactions over the S5-configured endpoint
/// is part of driving the payment itself — `pay()` captures each tx's
/// block number from the very receipt it awaits, and owns the
/// `eth_getTransactionReceipt` backfill (D33). The churn boundary keeps
/// anchor evidence out of net; it was never a rule that net may not speak
/// JSON-RPC to the chain it pays on.
///
/// # The pay/finalize split — the crash-safety contract
///
/// The write path is **split at the payment boundary** so a crash between
/// [`pay`] and [`finalize_batch`] never re-pays: the journal records the
/// [`PaymentReceipt`] the instant each EVM tx lands — per sub-batch,
/// strictly before the next sub-batch is submitted and strictly before
/// any finalize call (D37/S7/S10) — and a resumed seal calls
/// `finalize_batch` with the recorded receipt to store any not-yet-stored
/// chunks. `finalize_batch` is **idempotent over already-stored
/// addresses, resumable, and issues no new payment** — calling it twice
/// with the same receipt stores nothing twice and returns the same
/// address vector. Post-pay resume is time-boxed by antseal's own
/// conservative ~24 h proof-age window ([`StorageError::ProofsExpired`])
/// — a **client-side** policy, not a pinned-node rule (S9's correction,
/// 2026-08-02; see that variant's docs).
///
/// Ordering across the four operations is the pipeline's normative order
/// (S12): `quote_batch` over the **full** blob set → consent → anchor
/// gate → `pay` → journal → `finalize_batch`. A quote is a single-use
/// spend authorization input: a journaled quote is never paid; resume
/// re-quotes and re-consents unconditionally (D36).
///
/// # Object safety / `async fn` (deliberate, argued)
///
/// The four operations are native `async fn`s (Rust 1.92; no `Box<dyn
/// Future>` indirection, no runtime dependency in this crate), which
/// makes the trait **not dyn-compatible**. That is acceptable by design:
/// the one consumer is the seal/restore orchestration in
/// `antseal_cli`'s library (D34), which is *generic* over an injected
/// `B: StorageBackend` — monomorphic over `AntCoreBackend` in production
/// and `MockBackend` in tests — and never needs `dyn StorageBackend`.
/// The returned futures carry **no `Send` bound**: the pipeline awaits
/// them on its own task and never `tokio::spawn`s them. If either
/// constraint ever binds, widening it (return-type-notation bounds or a
/// boxed wrapper) is a deliberate S-domain event, not a drive-by.
#[allow(async_fn_in_trait)] // dyn-compatibility deliberately traded away; rationale above.
pub trait StorageBackend {
    /// Quote the cost of storing every blob in `blobs`, in order.
    ///
    /// The returned [`CostQuote`] is complete (covers every blob — S8's
    /// consent guarantee) and carries the full quote preimages the
    /// receipt journals. Already-stored chunks quote as zero-cost
    /// [`BlobCost::AlreadyStored`] lines (upstream `Ok(None)`, D32
    /// evidence row 11). Read-only: no payment, no store, no journal.
    ///
    /// # Errors
    ///
    /// [`StorageError::Quote`] / [`StorageError::Network`].
    ///
    /// [`BlobCost::AlreadyStored`]: crate::BlobCost::AlreadyStored
    async fn quote_batch(&self, blobs: &[Blob]) -> Result<CostQuote, StorageError>;

    /// Execute the quoted payment: one EVM tx per ≤256-blob sub-batch,
    /// submitted **sequentially**, each journaled as it lands — a single
    /// tx in the common case (D37; the spec's "one Merkle-batch EVM tx"
    /// is a recorded deviation: merkle mode is excluded because its
    /// proofs carry no tx hashes).
    ///
    /// Money moves here and nowhere else. The returned receipt is
    /// store-ready: [`finalize_batch`] needs nothing but it and the
    /// blobs.
    ///
    /// # Errors
    ///
    /// [`StorageError::Payment`] (nothing landed),
    /// [`StorageError::InsufficientAnt`] /
    /// [`StorageError::InsufficientGas`] (distinct preflight shortfalls),
    /// [`StorageError::StrandedPayment`] (landed partially — the partial
    /// map is journaled before this surfaces), or
    /// [`StorageError::Network`].
    ///
    /// [`finalize_batch`]: StorageBackend::finalize_batch
    async fn pay(&self, quote: &CostQuote) -> Result<PaymentReceipt, StorageError>;

    /// Upload every not-yet-stored blob under the recorded receipt and
    /// return each blob's address, in `blobs` order.
    ///
    /// **Idempotent; issues no new payment** (the contract the pay/
    /// finalize split exists for): already-stored addresses are skipped;
    /// a partial store resumes by calling this again with the same
    /// receipt. Every non-zero quote must be covered by the receipt's
    /// quote→tx map, else the gap is a typed error.
    ///
    /// # Errors
    ///
    /// [`StorageError::Finalize`] (including map gaps),
    /// [`StorageError::ProofsExpired`] (the ~24 h window passed),
    /// [`StorageError::Network`].
    async fn finalize_batch(
        &self,
        receipt: &PaymentReceipt,
        blobs: &[Blob],
    ) -> Result<Vec<Address>, StorageError>;

    /// Fetch the chunk at `address` — maps to ant-core's
    /// `chunk_get(&XorName)` (D32: a blob is one chunk; no `DataMap`, no
    /// reassembly, and `data_download` is not involved).
    ///
    /// # Errors
    ///
    /// [`StorageError::NotFound`] (the network answered: no such chunk)
    /// distinctly from [`StorageError::Network`] (no answer).
    async fn get_data(&self, address: Address) -> Result<Vec<u8>, StorageError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::block_on;
    use crate::{BlobCost, BlobQuote, GasSummary};
    use std::collections::BTreeMap;

    /// A canned backend proving the trait is implementable exactly as
    /// spec lines 63–66 shape it (the real impls land in S3/S6).
    struct NullBackend;

    impl StorageBackend for NullBackend {
        async fn quote_batch(&self, blobs: &[Blob]) -> Result<CostQuote, StorageError> {
            Ok(CostQuote {
                blobs: blobs
                    .iter()
                    .map(|blob| BlobQuote {
                        address: Address::from_bytes([blob.len() as u8; 32]),
                        cost: BlobCost::AlreadyStored,
                    })
                    .collect(),
                total_ant_atto: 0,
                gas_estimate_wei: 0,
            })
        }

        async fn pay(&self, _quote: &CostQuote) -> Result<PaymentReceipt, StorageError> {
            Ok(PaymentReceipt {
                blobs: Vec::new(),
                tx_map: BTreeMap::new(),
                txs: Vec::new(),
                storage_cost_atto: 0,
                gas: GasSummary { gas_cost_wei: 0 },
            })
        }

        async fn finalize_batch(
            &self,
            _receipt: &PaymentReceipt,
            blobs: &[Blob],
        ) -> Result<Vec<Address>, StorageError> {
            Ok(blobs
                .iter()
                .map(|blob| Address::from_bytes([blob.len() as u8; 32]))
                .collect())
        }

        async fn get_data(&self, address: Address) -> Result<Vec<u8>, StorageError> {
            Err(StorageError::NotFound { address })
        }
    }

    /// A generic consumer compiles — the D34 consumption shape (the
    /// pipeline is generic over `B: StorageBackend`, never `dyn`).
    async fn drive<B: StorageBackend>(backend: &B, blobs: &[Blob]) -> Result<usize, StorageError> {
        let quote = backend.quote_batch(blobs).await?;
        let receipt = backend.pay(&quote).await?;
        let addresses = backend.finalize_batch(&receipt, blobs).await?;
        Ok(addresses.len())
    }

    #[test]
    fn trait_signatures_drive_end_to_end_generically() {
        let blobs = vec![
            Blob::new(vec![1; 4]).expect("small blob"),
            Blob::new(vec![2; 7]).expect("small blob"),
        ];
        let stored = block_on(drive(&NullBackend, &blobs)).expect("null backend never fails");
        assert_eq!(stored, 2);

        let missing = Address::from_bytes([5; 32]);
        let err = block_on(NullBackend.get_data(missing)).expect_err("null backend holds nothing");
        assert_eq!(err, StorageError::NotFound { address: missing });
    }
}
