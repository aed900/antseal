//! [`StorageBackend`] — the batch-first storage trait (S2), shaped to
//! MVP-SPEC.md lines 63–66 — plus the balance/preflight surface U14's
//! consent gate renders.
//!
//! # Why the balance types live here (D89, 2026-08-02)
//!
//! [`BalanceReport`] and [`PreflightReport`] used to sit inside the
//! `ant-backend`-gated adapter file. Neither names one upstream type —
//! they are an [`EvmAddress20`](crate::network::EvmAddress20) and six
//! `u128`s — so they were gated **only because of where they were
//! written**, and moving them costs exactly zero packages.
//!
//! The real blocker D89 found is the one fixed here: `balances()` and
//! `preflight()` were **inherent methods on the concrete
//! `AntCoreBackend`**, so a consent gate written against them would hold a
//! concrete backend — violating project rule 1 ("all network access goes
//! through `StorageBackend`") and D34's injected-interface design, and
//! leaving U14's "both balances" row untestable against `MockBackend`
//! *even with the feature on*. [`StorageBackend::balances`] is therefore
//! part of the seam, and the shortfall rule is the pure function
//! [`preflight`] that every implementation shares.

use crate::network::EvmAddress20;
use crate::{Address, Blob, CostQuote, PaymentReceipt, StorageError};

/// The session wallet's balances (task S8) — structured data for U14's
/// consent render and `--json` (serde-serializable; no secret material:
/// the wallet address is public chain data).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BalanceReport {
    /// The paying wallet's EVM address.
    pub wallet: EvmAddress20,
    /// ANT (payment-token ERC-20) balance, atto-ANT (saturating at
    /// `u128::MAX`).
    pub ant_atto: u128,
    /// ETH (gas) balance, wei (saturating at `u128::MAX`).
    pub gas_wei: u128,
}

/// A passed preflight's numbers (task S8) — what the consent screen
/// renders beside the quote. Failure is never a report: it is the
/// distinct [`StorageError::InsufficientAnt`] /
/// [`StorageError::InsufficientGas`] error instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PreflightReport {
    /// The complete quote's storage cost (every blob in the handed-in
    /// set — S8's completeness guarantee), atto-ANT.
    pub required_ant_atto: u128,
    /// The wallet's ANT balance, atto-ANT.
    pub available_ant_atto: u128,
    /// The quote's gas estimate for the batch payment tx(s), wei.
    pub required_gas_wei: u128,
    /// The wallet's ETH balance, wei.
    pub available_gas_wei: u128,
}

/// Payment preflight (task S8): compare the **complete** quote — storage
/// ANT for every blob in the handed-in set plus the estimated gas for the
/// batch payment tx(s) — against both balances.
///
/// Checked in a fixed, documented order: **ANT first** (the primary
/// cost), then gas — so a doubly-underfunded wallet reports the ANT
/// shortfall deterministically. `pay()` re-runs this internally before
/// moving any money, so a preflight-passed seal can only fail on a
/// balance that changed after consent (and then fails BEFORE any
/// transaction).
///
/// **Arithmetic, not I/O** — which is exactly why it is a free function
/// and deliberately *not* a trait method (D89 Decision 3): putting it on
/// the seam would let an implementation disagree about which shortfall
/// fires, and S8's guarantee is that `pay()`'s internal re-check and the
/// consent gate consult **one** implementation.
///
/// # Errors
///
/// [`StorageError::InsufficientAnt`] / [`StorageError::InsufficientGas`]
/// — distinct by type (the user remedies them differently: acquire ANT vs
/// bridge ETH).
pub fn preflight(
    balances: &BalanceReport,
    quote: &CostQuote,
) -> Result<PreflightReport, StorageError> {
    let report = PreflightReport {
        required_ant_atto: quote.total_ant_atto,
        available_ant_atto: balances.ant_atto,
        required_gas_wei: quote.gas_estimate_wei,
        available_gas_wei: balances.gas_wei,
    };
    if report.available_ant_atto < report.required_ant_atto {
        return Err(StorageError::InsufficientAnt {
            required_atto: report.required_ant_atto,
            available_atto: report.available_ant_atto,
        });
    }
    if report.available_gas_wei < report.required_gas_wei {
        return Err(StorageError::InsufficientGas {
            required_wei: report.required_gas_wei,
            available_wei: report.available_gas_wei,
        });
    }
    Ok(report)
}

/// The ERC-20 allowance rule for the Autonomi payment vault (Q240; the
/// ruling and its price are in `docs/threat-model.md` §2.3).
///
/// Returns `Some(amount_atto)` — the amount a fresh `approve` must carry
/// — or `None` when the standing allowance already covers `total_atto`
/// and no `approve` is emitted at all.
///
/// **The amount is the exact quoted total, never `U256::MAX`.** Upstream
/// approves unlimited spending at every call site it has; antseal does not,
/// so the payment vault is never standing-authorised to move more ANT than
/// the payment it was raised for. The cost of that choice is an anonymity
/// cost and it is stated in the threat model rather than hidden here: an
/// exact allowance is consumed by its own payment, so a fresh, non-round
/// `Approval` is emitted on the public chain before essentially every seal.
/// That is a deliberate trade, not an accident, and this function is the
/// one place the amount is decided — which is what makes it pinnable.
///
/// **Arithmetic, not I/O**, and a free function for the same reason
/// [`preflight`] is one (D89 Decision 3): the rule must have exactly one
/// implementation, and a rule that lives on the seam can be disagreed with
/// by an implementation. It lives in the DEFAULT feature set so the pin
/// costs no upstream graph — `crates/antseal-net/tests/allowance_policy.rs`
/// is the test, on `MockBackend`'s feature set, with no live network and no
/// spend of any kind.
///
/// Units are atto-ANT throughout, which is the adapter's own domain: the
/// total is summed from the quote's per-transfer `amount_atto`
/// (`u128`) before it is widened for the on-chain call.
#[must_use]
pub fn allowance_to_approve(current_atto: u128, total_atto: u128) -> Option<u128> {
    // The short-circuit. It reads like an optimisation and is not one: see
    // `AntCoreBackend::ensure_allowance`, where the reason it almost never
    // fires is written beside the call.
    if current_atto >= total_atto {
        return None;
    }
    Some(total_atto)
}

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
    /// [`StorageError::NotFound`] **only** when the network answered, with
    /// authority, that no such chunk is stored; [`StorageError::Network`]
    /// whenever that could not be established — no answer, a lookup that
    /// found no peers, or a sample too small or too divided to count.
    ///
    /// *Could not find* is never *not found*. Consumers render `NotFound` as a
    /// negative fact about the network (`crate::fetch_failure_class` makes it
    /// an answer rather than a failure, and the live check reports the blob
    /// missing), so an implementation that reports an unreachable network as
    /// `NotFound` publishes a false statement about stored evidence. The
    /// ant-core adapter holds this with a confirming close-group sweep and
    /// ant-core's own absence rule (`ant_backend.rs`, `fetch_chunk`).
    async fn get_data(&self, address: Address) -> Result<Vec<u8>, StorageError>;

    /// The paying wallet's ANT and ETH balances (task S8) — read-only,
    /// no payment, no store, no journal.
    ///
    /// On the seam because it is **network I/O** (project rule 1), and
    /// because U14's consent gate must render both balances beside the
    /// quote in the default lane, against `MockBackend`, with no live
    /// network (D89 Decision 3). Combine with [`preflight`] — the shared
    /// pure shortfall rule — rather than reimplementing the comparison.
    ///
    /// # Errors
    ///
    /// [`StorageError::Network`] when either balance cannot be read.
    async fn balances(&self) -> Result<BalanceReport, StorageError>;
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

        async fn balances(&self) -> Result<BalanceReport, StorageError> {
            Ok(BalanceReport {
                wallet: EvmAddress20::from_bytes([0u8; EvmAddress20::LEN]),
                ant_atto: 0,
                gas_wei: 0,
            })
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

    fn quote_costing(ant_atto: u128, gas_wei: u128) -> CostQuote {
        CostQuote {
            blobs: Vec::new(),
            total_ant_atto: ant_atto,
            gas_estimate_wei: gas_wei,
        }
    }

    fn wallet_with(ant_atto: u128, gas_wei: u128) -> BalanceReport {
        BalanceReport {
            wallet: EvmAddress20::from_bytes([7u8; EvmAddress20::LEN]),
            ant_atto,
            gas_wei,
        }
    }

    /// The shortfall rule, in the DEFAULT lane and as a pure function
    /// (D89 Decision 3) — U14 Accept row 4's insufficient-token vs
    /// insufficient-gas split, with the S8 ANT-first order pinned.
    #[test]
    fn preflight_splits_the_two_shortfalls_ant_first() {
        // Comfortably funded.
        let report = preflight(&wallet_with(500, 500), &quote_costing(100, 100))
            .expect("funded wallet passes");
        assert_eq!(
            report,
            PreflightReport {
                required_ant_atto: 100,
                available_ant_atto: 500,
                required_gas_wei: 100,
                available_gas_wei: 500,
            }
        );

        // Exactly-funded is funded: the comparison is `<`, not `<=`.
        preflight(&wallet_with(100, 100), &quote_costing(100, 100)).expect("exact balance passes");

        // ANT short only.
        assert_eq!(
            preflight(&wallet_with(99, 500), &quote_costing(100, 100)).expect_err("ANT short"),
            StorageError::InsufficientAnt {
                required_atto: 100,
                available_atto: 99,
            }
        );

        // Gas short only — a DIFFERENT error, because the remedy differs.
        assert_eq!(
            preflight(&wallet_with(500, 99), &quote_costing(100, 100)).expect_err("gas short"),
            StorageError::InsufficientGas {
                required_wei: 100,
                available_wei: 99,
            }
        );

        // Doubly short reports ANT — the documented deterministic order.
        assert_eq!(
            preflight(&wallet_with(0, 0), &quote_costing(100, 100)).expect_err("both short"),
            StorageError::InsufficientAnt {
                required_atto: 100,
                available_atto: 0,
            }
        );

        // A zero-cost quote (everything already stored) passes on an
        // empty wallet: no payment is owed.
        preflight(&wallet_with(0, 0), &quote_costing(0, 0)).expect("nothing to pay for");
    }

    /// Saturated balances still compare correctly (the adapter saturates
    /// U256 into u128 — a saturated balance covers any representable
    /// requirement).
    #[test]
    fn preflight_is_total_at_the_u128_boundary() {
        preflight(
            &wallet_with(u128::MAX, u128::MAX),
            &quote_costing(u128::MAX, u128::MAX),
        )
        .expect("saturated balance covers a saturated requirement");
        assert_eq!(
            preflight(
                &wallet_with(u128::MAX - 1, u128::MAX),
                &quote_costing(u128::MAX, 0)
            )
            .expect_err("one atto short"),
            StorageError::InsufficientAnt {
                required_atto: u128::MAX,
                available_atto: u128::MAX - 1,
            }
        );
    }
}
