//! [`AntCoreBackend`] — the ONE ant-core adapter impl file (task S6;
//! feature **`ant-backend`**, never in the default graph).
//!
//! # Churn containment (normative)
//!
//! Every `ant_core`/`ant_protocol`/`alloy` **product** use in this
//! workspace lives in this file or in [`crate::evm`] (S5's wallet/network
//! half) — the containment the `StorageBackend` boundary exists for
//! (backend.rs module docs; enforced by the `dep-graph` CI lane's
//! adapter-containment check). An `ant-core` bump (S20) re-verifies this
//! file and `evm.rs` and nothing else.
//!
//! # The API charter this adapter drives (D32/D33/D37; S1 survey)
//!
//! | op | upstream surface | citation |
//! |---|---|---|
//! | `quote_batch` | `Client::prepare_chunk_payment` per blob; `Ok(None)` = already stored | `ant-core-0.5.0/src/data/client/batch.rs:354-415` |
//! | `pay` | **external-signer flow**: per-sub-batch `payForQuotes` calldata (`PaymentVaultHandler::pay_for_quotes_calldata`), signed and submitted over our own provider, each tx's receipt awaited; proofs built via the pure `finalize_batch_payment` | `evmlib-0.9.0/src/contract/payment_vault/handler.rs:112-127`; `ant-core-0.5.0/src/data/client/batch.rs:337-343` |
//! | `finalize_batch` | `chunk_exists` skip probe + `chunk_put_with_proof` to `CLOSE_GROUP_MAJORITY` targets | `ant-core-0.5.0/src/data/client/chunk.rs:534-541,1011-1013`; `ant-protocol-2.3.0/src/chunk.rs:40` |
//! | `get_data` | `chunk_get` (D32: blob = one chunk; no `DataMap`) | `ant-core-0.5.0/src/data/client/chunk.rs:632-636` |
//!
//! **Explicitly never driven** (their results carry no payment data, or
//! their error paths destroy capture): `data_upload*`, `chunk_put`,
//! `Client::batch_pay` (D37 ruling: its error path discards the partial
//! paid map — if the native flow is ever used, drive
//! `Wallet::pay_for_quotes` directly), and every merkle payment surface
//! (no tx hashes in proofs/results, D37 ruling 1). The CI containment
//! check greps for the forbidden call sites.
//!
//! Structurally the client is built with `with_evm_network` (the
//! external-signer driver, `ant-core-0.5.0/src/data/client/mod.rs:451-455`)
//! and **never** `with_wallet`, so upstream's wallet-gated payment paths
//! (`require_wallet`) cannot even be reached from this adapter.
//!
//! # Payment mechanics (D37 Decision 2, D33 Decision 1)
//!
//! `pay()` submits ⌈non-zero-transfers/256⌉ **sequential** EVM txs
//! (`MAX_TRANSFERS_PER_TRANSACTION = 256`,
//! `evmlib-0.9.0/src/contract/payment_vault/mod.rs:11`; one non-zero
//! transfer per blob under the median-×3 rule ⇒ 256 blobs/tx). Each tx's
//! receipt is awaited in-band — `block_number`/`status` come from the very
//! awaited receipt object, no separate RPC read (D33's primary flow) —
//! and the **capture hook** fires with the cumulative receipt **before
//! the next sub-batch is submitted** (the journal-write timing S10/S12
//! build on; the write itself is the pipeline's job). A mid-sequence
//! failure surfaces as [`StorageError::StrandedPayment`] only after the
//! hook has delivered every landed sub-batch's record.
//!
//! The ERC-20 allowance for the payment vault is approved with the
//! **exact quoted total** (never upstream's `U256::MAX`,
//! `evmlib-0.9.0/src/wallet.rs:416-427` — S1 §7's wallet-hygiene note).
//!
//! # Provider notes (D33 Decision 4)
//!
//! One signing provider is built at [`AntCoreBackend::connect`] from the
//! re-exported [`Wallet`] (`Wallet::to_provider()`,
//! `evmlib-0.9.0/src/wallet.rs:213-215`) and type-erased to
//! [`DynProvider`]; submission, receipt awaits, the chain-id guard, and
//! the `eth_getTransactionReceipt` backfill all ride it — the same
//! S5-configured payment RPC endpoint D33 names (D33's letter mentions
//! the `http_provider` re-export for the backfill; this provider targets
//! the identical endpoint and already exists, so no second provider is
//! constructed). Its nonce filler re-reads the pending count per tx
//! (`SimpleNonceManager`, alloy-provider-1.8.3/src/fillers/nonce.rs:37-45),
//! which composes safely with the fully-awaited, sequential submissions
//! here and with the approve tx `Wallet` submits internally.
//!
//! # Hygiene
//!
//! No receipt field (tx hash, quote hash, preimage) and no key material
//! ever enters an error message or log from this module. Upstream
//! **payment-class** error strings can embed quote-hash hex
//! (`batch.rs:300-305`), so those are redacted to their class name;
//! network/storage-class messages pass through (they name chunk
//! addresses at most, which are public content identifiers — error.rs
//! header).

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use alloy::network::TransactionBuilder;
use alloy::providers::{DynProvider, Provider};
use alloy::rpc::types::TransactionRequest;
use ant_core::data::{
    Client, ClientConfig, Error as AntError, PaidChunk, PreparedChunk, finalize_batch_payment,
};
use ant_protocol::CLOSE_GROUP_MAJORITY;
use ant_protocol::evm::contract::payment_vault::MAX_TRANSFERS_PER_TRANSACTION;
use ant_protocol::evm::contract::payment_vault::handler::PaymentVaultHandler;
use ant_protocol::evm::{Amount, U256};
use bytes::Bytes;

use crate::backend::{BalanceReport, PreflightReport};
use crate::evm::to_evm_network;
use crate::network::{NetworkConfig, NetworkId};
use crate::quote::{
    BlobCost, BlobQuote, CostQuote, EncodedPeerId, PeerQuote, QuoteHash, QuotePaymentEntry,
    QuotePreimage, RewardsAddress, TxHash,
};
use crate::receipt::{BlobPaymentRecord, GasSummary, PaymentReceipt, TxRecord, TxStatus};
use crate::wallet::WalletKey;
use crate::{Address, Blob, MAX_CHUNK_SIZE, StorageBackend, StorageError};

/// Upstream wallet type, via the sanctioned re-export chain.
use ant_protocol::evm::Wallet;

// ---------------------------------------------------------------------------
// Gas model constants (quote-time estimate; S8 preflight input)
// ---------------------------------------------------------------------------
//
// `eth_estimateGas` on the `payForQuotes` calldata REVERTS before the
// allowance is approved (ERC-20 `transferFrom` without allowance), and the
// quote happens strictly before consent and therefore before any approve —
// so the quote-time gas figure is a static model, not an RPC estimate
// (task S8 note: "gas estimation source verified against pinned upstream at
// execution time" — this is the recorded outcome). The constants are
// deliberately conservative multiples of costs measured on the live local
// devnet (Anvil, 2026-08-01, this file's own txs): approve 46_394 gas;
// payForQuotes 73_212 gas at 1 transfer, 152_566 at 3 ⇒ ≈39.7k marginal
// per transfer over a ≈33.5k base. ~3–9× headroom keeps the S8 "actual
// paid gas ≤ estimate" acceptance true under basefee movement; S9/S18
// watch the constants across upstream bumps.
/// Gas allowance for the one exact-amount ERC-20 `approve` tx.
const APPROVE_GAS: u64 = 140_000;
/// Per-sub-batch fixed overhead (intrinsic + calldata + loop setup).
const PER_TX_BASE_GAS: u64 = 300_000;
/// Per non-zero transfer marginal gas (vault record + token transfer).
const PER_TRANSFER_GAS: u64 = 220_000;

/// antseal's own conservative proof-age window (~24 h, D37 Decision 6).
/// Used ONLY to classify a storer's payment-class PUT rejection as
/// [`StorageError::ProofsExpired`] vs a generic finalize failure; never to
/// gate anything pre-emptively — which is exactly why the S9 correction
/// below costs nothing.
///
/// Value mirrors ant-core's client-side cache policy
/// (`CACHED_PROOF_MAX_AGE_SECS = 24 * 60 * 60`,
/// `ant-core-0.5.0/src/data/client/batch.rs:1051-1058`).
///
/// **[S9, 2026-08-02]** That upstream constant's doc claims to mirror
/// `QUOTE_MAX_AGE_SECS` "in `ant-node/src/payment/verifier.rs`". No such
/// constant exists in the pinned ant-node 0.15.0, and the single-node
/// payment path applies no timestamp gate — so this is a **self-imposed**
/// client policy, not a mirror of anything the network enforces. It stays:
/// classification-only use makes a wrong guess cost one re-pay, and the
/// mechanism could return upstream at any release. Evidence:
/// `crates/antseal-net/tests/storage_constants.rs` module docs.
const PROOF_VALIDITY_WINDOW_SECS: u64 = 24 * 60 * 60;

/// Per-sub-batch journal capture hook (D37 Decision 2 / S7 timing
/// contract): invoked with the **cumulative** receipt-so-far after each
/// sub-batch tx lands — strictly before the next sub-batch is submitted —
/// and once more with the final receipt (which is identical to the last
/// in-flight payload; the S7 capture-consistency test asserts it). The
/// journal WRITE the hook performs is the pipeline's (S10/S12); this type
/// is only the timing seam.
pub type CaptureHook = Arc<dyn Fn(&PaymentReceipt) + Send + Sync>;

/// What `pay()` stages for `finalize_batch`'s same-process fast path:
/// the ordered PUT targets and the store-ready proof for one paid blob.
/// A resumed process (journaled receipt, no staged state) re-derives
/// targets via an unpaid quote round instead (D37 Decision 5).
struct StagedPaid {
    targets: Vec<(
        ant_protocol::transport::PeerId,
        Vec<ant_protocol::transport::MultiAddr>,
    )>,
    proof_bytes: Vec<u8>,
}

/// Mutable adapter state. A std `Mutex` guarded for strictly non-await
/// critical sections (lock, mutate, drop — never held across an await).
#[derive(Default)]
struct Staged {
    /// PreparedChunks from the most recent `quote_batch` round, by
    /// address. Replaced wholesale each round: only the latest quote is
    /// payable (D36 — a journaled/stale quote is never paid).
    prepared: HashMap<Address, PreparedChunk>,
    /// Per-blob store material from this process's `pay`, by address.
    paid: HashMap<Address, StagedPaid>,
}

/// The real [`StorageBackend`] over the pinned ant-core 0.5.0 stack.
///
/// Construction: [`AntCoreBackend::connect`]. One value per payment
/// session; it holds the upstream [`Wallet`] (which keeps the signing key
/// in alloy's non-zeroizing structures for its lifetime — inherent to the
/// payment path, documented in [`crate::evm`]; keep the backend's
/// lifetime to the session).
pub struct AntCoreBackend {
    client: Client,
    wallet: Wallet,
    provider: DynProvider,
    config: NetworkConfig,
    /// Sub-batch cap. Defaults to the upstream protocol cap; the test
    /// seam can only lower it (mirrors `MockBackend`'s seam so the
    /// multi-tx protocol is exercisable without 257 real blobs — S7's
    /// "forced sub-batch size").
    max_transfers_per_tx: usize,
    capture_hook: Option<CaptureHook>,
    staged: Mutex<Staged>,
}

impl AntCoreBackend {
    /// Connect to the configured network and prepare the payment session.
    ///
    /// - Autonomi side: `Client::connect` over `config.bootstrap`
    ///   (loopback allowed only for [`NetworkId::Devnet`] — the transport
    ///   handshake variant is devnet-only,
    ///   `ant-core-0.5.0/src/data/client/mod.rs:238-247`), then
    ///   `with_evm_network` (the external-signer driver — deliberately
    ///   never `with_wallet`, see module docs).
    /// - EVM side: the payment [`Wallet`] built from the vault-held key
    ///   handle (custody is U10/U13's; this takes the handle), plus the
    ///   one signing provider (module docs).
    /// - Guard: the RPC's `eth_chainId` must equal
    ///   `config.evm_chain_id` — the wrong-network/wrong-Sepolia guard
    ///   the `NetworkConfig` field documents.
    ///
    /// # Errors
    ///
    /// [`StorageError::Network`] for connect/transport/chain-id failures;
    /// [`StorageError::Quote`] never (no quoting here).
    pub async fn connect(
        config: &NetworkConfig,
        wallet_key: &WalletKey,
    ) -> Result<Self, StorageError> {
        let evm_network = to_evm_network(config).map_err(|e| StorageError::Network {
            reason: format!("network configuration rejected: {e}"),
        })?;
        let wallet = wallet_key
            .evm_wallet(config)
            .map_err(|e| StorageError::Network {
                reason: format!("payment wallet construction failed: {e}"),
            })?;
        let provider = wallet.to_provider().erased();

        // Wrong-network guard before anything can pay: eth_chainId must
        // match the pinned/exported id (42161 / 421614 / devnet's 31337).
        let chain_id = provider
            .get_chain_id()
            .await
            .map_err(|e| StorageError::Network {
                reason: format!("payment RPC unreachable (eth_chainId): {e}"),
            })?;
        if chain_id != config.evm_chain_id {
            return Err(StorageError::Network {
                reason: format!(
                    "chain-id mismatch: the {network} config pins {expected} but the RPC reports \
                     {chain_id} — wrong network or wrong RPC endpoint",
                    network = config.id,
                    expected = config.evm_chain_id,
                ),
            });
        }

        let client_config = ClientConfig {
            // Loopback handshakes are a devnet-only transport variant;
            // production peers reject them (ClientConfig docs).
            allow_loopback: config.id == NetworkId::Devnet,
            ..ClientConfig::default()
        };
        let client = Client::connect(&config.bootstrap, client_config)
            .await
            .map_err(|e| map_ant_error(ErrContext::Connect, &e))?
            .with_evm_network(evm_network);

        Ok(Self {
            client,
            wallet,
            provider,
            config: config.clone(),
            max_transfers_per_tx: MAX_TRANSFERS_PER_TRANSACTION,
            capture_hook: None,
            staged: Mutex::new(Staged::default()),
        })
    }

    /// Install the per-sub-batch capture hook (see [`CaptureHook`]).
    #[must_use]
    pub fn with_capture_hook(mut self, hook: CaptureHook) -> Self {
        self.capture_hook = Some(hook);
        self
    }

    /// **Test seam** (mirrors `MockBackend::with_max_transfers_per_tx`):
    /// force a smaller sub-batch cap so the sequential multi-tx protocol
    /// — real txs, real receipts, real per-sub-batch capture — is
    /// exercisable on a devnet without 257 blobs (S7's "forced sub-batch
    /// size"). Clamped into `1..=` the upstream protocol cap: this seam
    /// can never RAISE the cap above
    /// `MAX_TRANSFERS_PER_TRANSACTION = 256`.
    #[must_use]
    pub fn with_max_transfers_per_tx(mut self, cap: usize) -> Self {
        self.max_transfers_per_tx = cap.clamp(1, MAX_TRANSFERS_PER_TRANSACTION);
        self
    }

    /// The network this backend session is bound to.
    #[must_use]
    pub fn network_config(&self) -> &NetworkConfig {
        &self.config
    }

    /// Idempotent block-number backfill (D33 Decision 2): for every
    /// [`TxRecord`] whose `block_number` slot is empty, read
    /// `eth_getTransactionReceipt(tx_hash)` over the payment RPC and fill
    /// `block_number`/`status`. Returns how many records were enriched.
    ///
    /// **No payment-path side effects** — read-only RPC; safe to call any
    /// number of times; enrichment never gates finalize. A hash whose
    /// receipt is not yet visible is left untouched (retry later).
    ///
    /// # Errors
    ///
    /// [`StorageError::Network`] only when the RPC itself is unreachable;
    /// an individual not-yet-visible receipt is not an error.
    pub async fn backfill_block_numbers(
        &self,
        receipt: &mut PaymentReceipt,
    ) -> Result<usize, StorageError> {
        let mut filled = 0usize;
        for tx in &mut receipt.txs {
            if tx.block_number.is_some() {
                continue;
            }
            let hash = alloy::primitives::B256::from(*tx.tx_hash.as_bytes());
            let fetched = self
                .provider
                .get_transaction_receipt(hash)
                .await
                .map_err(|e| StorageError::Network {
                    reason: format!("eth_getTransactionReceipt failed: {e}"),
                })?;
            if let Some(evm_receipt) = fetched {
                tx.block_number = evm_receipt.block_number;
                tx.status = if evm_receipt.status() {
                    TxStatus::Confirmed
                } else {
                    TxStatus::Reverted
                };
                if evm_receipt.block_number.is_some() {
                    filled += 1;
                }
            }
        }
        Ok(filled)
    }

    /// Payment preflight (task S8) over this session's live balances.
    ///
    /// The **rule** itself — the ANT-first order and the two distinct
    /// shortfalls — is the pure [`crate::backend::preflight`] in the
    /// default graph (D89 Decision 3); this method is the I/O half that
    /// feeds it. Keeping one implementation is what makes `pay()`'s
    /// internal re-check (S8's guarantee) and U14's consent render agree
    /// by construction rather than by review.
    ///
    /// # Errors
    ///
    /// [`StorageError::InsufficientAnt`] /
    /// [`StorageError::InsufficientGas`] — distinct by type (the user
    /// remedies them differently: acquire ANT vs bridge ETH);
    /// [`StorageError::Network`] when balances cannot be read.
    pub async fn preflight(&self, quote: &CostQuote) -> Result<PreflightReport, StorageError> {
        crate::backend::preflight(&self.balances().await?, quote)
    }

    // -- internal ----------------------------------------------------------

    /// Defense-in-depth cap assert at the adapter boundary (D32 Decision
    /// 2, third layer): [`Blob`]'s constructor makes an over-cap blob
    /// unrepresentable, so this is unreachable through the public types —
    /// but the invariant is re-checked here so no future refactor can
    /// route unchecked bytes to a quote/payment (upstream would quote and
    /// PAY for an unstorable chunk without complaint, `batch.rs:354-415`).
    fn check_blob_len(len: usize) -> Result<(), StorageError> {
        if len > MAX_CHUNK_SIZE {
            // Typed error, deliberately NOT a debug_assert: this is the
            // no-panic defense-in-depth path itself (tested directly).
            return Err(StorageError::Quote {
                reason: format!(
                    "blob of {len} bytes exceeds the {MAX_CHUNK_SIZE}-byte chunk cap at the \
                     adapter boundary (D32 defense in depth)"
                ),
            });
        }
        Ok(())
    }

    /// Quote-time gas model (constants above): approve + per-tx base +
    /// per-transfer marginal, priced at the current gas price.
    async fn estimate_gas_wei(&self, priced_blobs: usize) -> Result<u128, StorageError> {
        if priced_blobs == 0 {
            return Ok(0);
        }
        let sub_batches = priced_blobs.div_ceil(self.max_transfers_per_tx) as u64;
        let units =
            APPROVE_GAS + PER_TX_BASE_GAS * sub_batches + PER_TRANSFER_GAS * (priced_blobs as u64);
        let gas_price = self
            .provider
            .get_gas_price()
            .await
            .map_err(|e| StorageError::Network {
                reason: format!("eth_gasPrice failed: {e}"),
            })?;
        Ok(u128::from(units).saturating_mul(gas_price))
    }

    /// ANT (ERC-20) and ETH balances of the session wallet, in
    /// (atto-ANT, wei). Values above `u128::MAX` saturate (comparisons
    /// stay correct: a saturated balance still covers any representable
    /// requirement).
    async fn raw_balances(&self) -> Result<(u128, u128), StorageError> {
        let ant = self
            .wallet
            .balance_of_tokens()
            .await
            .map_err(|e| StorageError::Network {
                reason: format!("ANT balance query failed: {e}"),
            })?;
        let gas = self
            .wallet
            .balance_of_gas_tokens()
            .await
            .map_err(|e| StorageError::Network {
                reason: format!("ETH balance query failed: {e}"),
            })?;
        Ok((saturate_u256(ant), saturate_u256(gas)))
    }

    /// Exact-allowance approve (module docs): if the vault's current
    /// allowance is below `total`, approve exactly `total` — never
    /// `U256::MAX`. Returns the approve tx's gas cost in wei (0 when no
    /// approve was needed).
    async fn ensure_allowance(&self, total: Amount) -> Result<u128, StorageError> {
        let vault = vault_address(&self.wallet);
        let current =
            self.wallet
                .token_allowance(vault)
                .await
                .map_err(|e| StorageError::Network {
                    reason: format!("allowance query failed: {e}"),
                })?;
        if current >= total {
            return Ok(0);
        }
        let tx_hash = self
            .wallet
            .approve_to_spend_tokens(vault, total)
            .await
            .map_err(|e| StorageError::Payment {
                reason: format!("token approve failed: {}", redact_evm_error(&e.to_string())),
            })?;
        // The approve's own gas, for the receipt's gas summary — read from
        // its receipt (the approve is fully awaited by upstream).
        let receipt = self
            .provider
            .get_transaction_receipt(tx_hash)
            .await
            .ok()
            .flatten();
        Ok(receipt.map_or(0, |r| {
            u128::from(r.gas_used).saturating_mul(r.effective_gas_price)
        }))
    }

    /// Store one blob's bytes+proof to its ordered PUT targets until
    /// `CLOSE_GROUP_MAJORITY` peers accepted (the public-surface
    /// replication of upstream's `pub(crate)` close-group PUT —
    /// sequential with early exit; simple and deterministic).
    async fn put_to_majority(
        &self,
        address: Address,
        content: Bytes,
        proof_bytes: &[u8],
        targets: &[(
            ant_protocol::transport::PeerId,
            Vec<ant_protocol::transport::MultiAddr>,
        )],
        oldest_quote_unix_secs: u64,
    ) -> Result<(), StorageError> {
        if targets.is_empty() {
            return Err(StorageError::Finalize {
                reason: format!("no PUT targets available for blob at address {address}"),
            });
        }
        let mut successes = 0usize;
        let mut last_error: Option<StorageError> = None;
        for (peer, addrs) in targets {
            match self
                .client
                .chunk_put_with_proof(content.clone(), proof_bytes.to_vec(), peer, addrs)
                .await
            {
                Ok(stored_at) => {
                    // Upstream computes the address from the content it
                    // stored; equality is the D32 rule holding.
                    if stored_at != *address.as_bytes() {
                        return Err(StorageError::Finalize {
                            reason: format!(
                                "network stored blob under a different address than the S4 \
                                 recomputation for {address} — address-rule divergence"
                            ),
                        });
                    }
                    successes += 1;
                    if successes >= CLOSE_GROUP_MAJORITY {
                        return Ok(());
                    }
                }
                Err(e) => {
                    last_error = Some(classify_put_error(&e, address, oldest_quote_unix_secs));
                    // ProofsExpired is terminal for the whole finalize —
                    // every remaining PUT would be rejected the same way.
                    if matches!(last_error, Some(StorageError::ProofsExpired)) {
                        return Err(StorageError::ProofsExpired);
                    }
                }
            }
        }
        Err(last_error.unwrap_or_else(|| StorageError::Finalize {
            reason: format!(
                "stored to {successes} of the required {CLOSE_GROUP_MAJORITY} peers for blob at \
                 address {address}"
            ),
        }))
    }
}

impl StorageBackend for AntCoreBackend {
    async fn quote_batch(&self, blobs: &[Blob]) -> Result<CostQuote, StorageError> {
        for blob in blobs {
            Self::check_blob_len(blob.len())?;
        }

        let mut lines = Vec::with_capacity(blobs.len());
        let mut fresh_prepared: HashMap<Address, PreparedChunk> = HashMap::new();
        let mut total_ant_atto: u128 = 0;
        let mut priced_blobs = 0usize;

        for blob in blobs {
            // The address authority is S4 (D32); upstream re-derives the
            // same BLAKE3-256 internally and the two are asserted equal
            // below (divergence = the D32 model broke ⇒ typed error, not
            // silent trust).
            let address = s4_address(blob)?;
            let content = Bytes::copy_from_slice(blob.as_bytes());
            let prepared = self
                .client
                .prepare_chunk_payment(content)
                .await
                .map_err(|e| map_ant_error(ErrContext::Quote, &e))?;

            let cost = match prepared {
                // `Ok(None)`: already stored — the zero-cost line
                // (`batch.rs:361-368`; D32 evidence row 11).
                None => BlobCost::AlreadyStored,
                Some(chunk) => {
                    if chunk.address != *address.as_bytes() {
                        return Err(StorageError::Quote {
                            reason: format!(
                                "upstream derived a different chunk address than the S4 \
                                 recomputation for the blob at {address} — address-rule divergence"
                            ),
                        });
                    }
                    priced_blobs += 1;
                    let payments = convert_payment_lines(&chunk)?;
                    for line in &payments {
                        total_ant_atto = total_ant_atto.saturating_add(line.amount_atto);
                    }
                    let peer_quotes = convert_peer_quotes(&chunk)?;
                    let commitment_sidecars = chunk.commitment_sidecars.clone();
                    fresh_prepared.insert(address, chunk);
                    BlobCost::Priced {
                        payments,
                        peer_quotes,
                        commitment_sidecars,
                    }
                }
            };
            lines.push(BlobQuote { address, cost });
        }

        let gas_estimate_wei = self.estimate_gas_wei(priced_blobs).await?;

        // Stage the prepared set — replaced wholesale: only THIS round's
        // quote is payable (D36; `pay` verifies line-for-line).
        {
            let mut staged = lock_staged(&self.staged);
            staged.prepared = fresh_prepared;
        }

        Ok(CostQuote {
            blobs: lines,
            total_ant_atto,
            gas_estimate_wei,
        })
    }

    async fn pay(&self, quote: &CostQuote) -> Result<PaymentReceipt, StorageError> {
        // 1. Pull the staged prepared chunks and verify the quote is THIS
        //    round's (D36: a stale/journaled/foreign quote is never paid).
        //    Priced blobs keep their quote order; `slot` is each priced
        //    blob's position in the receipt's per-blob record vector.
        let mut priced: Vec<PricedBlobSlot> = Vec::new();
        {
            let mut staged = lock_staged(&self.staged);
            for line in &quote.blobs {
                let BlobCost::Priced {
                    payments,
                    peer_quotes,
                    commitment_sidecars,
                } = &line.cost
                else {
                    continue;
                };
                let Some(prepared) = staged.prepared.remove(&line.address) else {
                    return Err(StorageError::Payment {
                        reason: format!(
                            "the quote is not this backend's latest quote round (no staged \
                             quotes for the blob at {address}); re-quote and re-consent (D36)",
                            address = line.address
                        ),
                    });
                };
                if !payment_lines_match(payments, &prepared) {
                    return Err(StorageError::Payment {
                        reason: format!(
                            "the quote's payment lines do not match the staged quote round for \
                             the blob at {address}; re-quote and re-consent (D36)",
                            address = line.address
                        ),
                    });
                }
                priced.push(PricedBlobSlot {
                    slot: priced.len(),
                    address: line.address,
                    prepared,
                    entries: payments.clone(),
                    peer_quotes: peer_quotes.clone(),
                    commitment_sidecars: commitment_sidecars.clone(),
                });
            }
            // Whatever remains staged is from the same round but not in
            // this quote object — clear it: one pay per quote round.
            staged.prepared.clear();
        }

        // 2. Distinct-shortfall preflight before any money moves — the
        //    same check the public S8 `preflight` exposes, re-run here so
        //    pay is safe even when the pipeline skipped it.
        self.preflight(quote).await?;

        // 3. The transfer list: every non-zero entry, in blob order —
        //    upstream pays the price-sorted median 3× and zeros the rest
        //    (`batch.rs:59-95`), so this is one transfer per blob in the
        //    normal case, and the sub-batch cap is a blobs-per-tx cap.
        let mut transfers: Vec<(usize, QuoteHash, RewardsAddress, u128)> = Vec::new();
        for blob in &priced {
            for entry in &blob.entries {
                if entry.amount_atto > 0 {
                    transfers.push((
                        blob.slot,
                        entry.quote_hash,
                        entry.rewards_address,
                        entry.amount_atto,
                    ));
                }
            }
        }
        let total: u128 = transfers.iter().map(|(_, _, _, amount)| *amount).sum();

        // 4. Exact-allowance approve (no-op when nothing to transfer).
        let mut gas_cost_wei: u128 = 0;
        if total > 0 {
            gas_cost_wei = self.ensure_allowance(U256::from(total)).await?;
        }

        // 5. Sequential ≤cap sub-batches (D37 Decision 2). Each blob's
        //    proof is buildable once the LAST of its (normally one)
        //    non-zero transfers has a tx hash; `ready_after[slot]` is that
        //    sub-batch index (usize::MAX ⇒ no transfers ⇒ ready at once).
        let sub_batches: Vec<&[(usize, QuoteHash, RewardsAddress, u128)]> =
            transfers.chunks(self.max_transfers_per_tx).collect();
        let mut ready_after: Vec<usize> = vec![usize::MAX; priced.len()];
        for (batch_index, batch) in sub_batches.iter().enumerate() {
            for (slot, ..) in *batch {
                ready_after[*slot] = batch_index;
            }
        }

        let vault = vault_address(&self.wallet);
        let handler = PaymentVaultHandler::new(vault, self.provider.clone());
        let from = self.wallet.address();

        let mut records: Vec<Option<BlobPaymentRecord>> = (0..priced.len()).map(|_| None).collect();
        let mut remaining: Vec<Option<PricedBlobSlot>> = priced.into_iter().map(Some).collect();
        let mut tx_map: BTreeMap<QuoteHash, TxHash> = BTreeMap::new();
        let mut txs: Vec<TxRecord> = Vec::new();

        // Blobs with no non-zero transfer (theoretical zero-price quote)
        // are proof-ready immediately, with no tx hashes.
        finalize_ready_blobs(
            &mut remaining,
            &ready_after,
            usize::MAX,
            &tx_map,
            &mut records,
            &mut lock_staged(&self.staged).paid,
        )?;

        for (batch_index, batch) in sub_batches.iter().enumerate() {
            // Build this sub-batch's payForQuotes calldata (offline ABI
            // encode; `handler.rs:112-127`).
            let entries: Vec<(
                ant_protocol::evm::QuoteHash,
                ant_protocol::evm::Address,
                Amount,
            )> = batch
                .iter()
                .map(|(_, quote_hash, rewards, amount)| {
                    (
                        ant_protocol::evm::QuoteHash::from(*quote_hash.as_bytes()),
                        ant_protocol::evm::Address::from(*rewards.as_bytes()),
                        U256::from(*amount),
                    )
                })
                .collect();
            let (calldata, to) = handler.pay_for_quotes_calldata(entries).map_err(|e| {
                stranded_or_payment(
                    txs.len(),
                    format!(
                        "calldata build failed: {}",
                        redact_evm_error(&e.to_string())
                    ),
                )
            })?;

            // Submit and await the landing — the receipt object below IS
            // the D33 primary-flow capture source (block number in-band).
            let request = TransactionRequest::default()
                .with_from(from)
                .with_to(to)
                .with_input(calldata);
            let pending = self.provider.send_transaction(request).await.map_err(|e| {
                stranded_or_payment(
                    txs.len(),
                    format!(
                        "sub-batch tx submission failed: {}",
                        redact_evm_error(&e.to_string())
                    ),
                )
            })?;
            let submitted_hash = TxHash::from_bytes(pending.tx_hash().0);
            let evm_receipt = match pending.get_receipt().await {
                Ok(receipt) => receipt,
                Err(e) => {
                    // The tx was accepted by the RPC but its landing was
                    // not observed: journal the hash with `Submitted`
                    // status (backfill fills the rest) and surface the
                    // stranded state — money MAY have moved.
                    txs.push(TxRecord {
                        tx_hash: submitted_hash,
                        block_number: None,
                        status: TxStatus::Submitted,
                        quote_hashes: batch.iter().map(|(_, qh, ..)| *qh).collect(),
                    });
                    for (_, quote_hash, ..) in *batch {
                        tx_map.insert(*quote_hash, submitted_hash);
                    }
                    emit_capture(
                        self.capture_hook.as_ref(),
                        &records,
                        &tx_map,
                        &txs,
                        gas_cost_wei,
                    );
                    return Err(StorageError::StrandedPayment {
                        landed_tx_count: txs
                            .iter()
                            .filter(|t| t.status == TxStatus::Confirmed)
                            .count(),
                        reason: format!(
                            "sub-batch tx landing not observed: {}",
                            redact_evm_error(&e.to_string())
                        ),
                    });
                }
            };

            let landed_hash = TxHash::from_bytes(evm_receipt.transaction_hash.0);
            let confirmed = evm_receipt.status();
            gas_cost_wei = gas_cost_wei.saturating_add(
                u128::from(evm_receipt.gas_used).saturating_mul(evm_receipt.effective_gas_price),
            );
            txs.push(TxRecord {
                tx_hash: landed_hash,
                block_number: evm_receipt.block_number,
                status: if confirmed {
                    TxStatus::Confirmed
                } else {
                    TxStatus::Reverted
                },
                quote_hashes: batch.iter().map(|(_, qh, ..)| *qh).collect(),
            });

            if !confirmed {
                // A reverted payForQuotes moved no ANT: its quotes are NOT
                // mapped (they are unpaid), the record is journaled as
                // evidence of the gas spend, and the stranded state names
                // only the confirmed landings.
                emit_capture(
                    self.capture_hook.as_ref(),
                    &records,
                    &tx_map,
                    &txs,
                    gas_cost_wei,
                );
                return Err(StorageError::StrandedPayment {
                    landed_tx_count: txs
                        .iter()
                        .filter(|t| t.status == TxStatus::Confirmed)
                        .count(),
                    reason: "a payment sub-batch transaction reverted on-chain".into(),
                });
            }

            for (_, quote_hash, ..) in *batch {
                tx_map.insert(*quote_hash, landed_hash);
            }

            // Build the proofs that became complete with this landing
            // (per-blob `finalize_batch_payment` — pure, `batch.rs:337-343`)
            // and journal via the hook BEFORE the next submission.
            finalize_ready_blobs(
                &mut remaining,
                &ready_after,
                batch_index,
                &tx_map,
                &mut records,
                &mut lock_staged(&self.staged).paid,
            )?;
            emit_capture(
                self.capture_hook.as_ref(),
                &records,
                &tx_map,
                &txs,
                gas_cost_wei,
            );
        }

        let blobs: Vec<BlobPaymentRecord> = records.into_iter().flatten().collect();
        let receipt = PaymentReceipt {
            blobs,
            tx_map,
            txs,
            storage_cost_atto: total,
            gas: GasSummary { gas_cost_wei },
        };
        debug_assert!(receipt.covers_all_paid_quotes());
        Ok(receipt)
    }

    async fn finalize_batch(
        &self,
        receipt: &PaymentReceipt,
        blobs: &[Blob],
    ) -> Result<Vec<Address>, StorageError> {
        for blob in blobs {
            Self::check_blob_len(blob.len())?;
        }
        // The upstream gap rule, checked receipt-wide BEFORE any network
        // work (`batch.rs:300-305` — upstream would error the same way,
        // but with quote-hash hex in the message; this check keeps that
        // string unreachable and the failure typed).
        if !receipt.covers_all_paid_quotes() {
            return Err(StorageError::Finalize {
                reason: "quote→tx map gap: a non-zero quote in the receipt has no tx hash — \
                         the journaled receipt is truncated or corrupt"
                    .into(),
            });
        }

        let mut addresses = Vec::with_capacity(blobs.len());
        for blob in blobs {
            let address = s4_address(blob)?;
            addresses.push(address);

            // Idempotency: already-stored addresses are skipped — whether
            // stored by an earlier finalize, a partial store, or a third
            // party (`chunk_exists`, chunk.rs:1011-1013).
            let exists = self
                .client
                .chunk_exists(address.as_bytes())
                .await
                .map_err(|e| map_ant_error(ErrContext::Finalize, &e))?;
            if exists {
                continue;
            }

            // Not stored ⇒ the receipt must hold this blob's record; its
            // journaled `proof_bytes` are THE store artifact (D37 row 13).
            let record = receipt
                .blobs
                .iter()
                .find(|r| r.address == address)
                .ok_or_else(|| StorageError::Finalize {
                    reason: format!("no payment record for unstored blob at address {address}"),
                })?;
            let oldest_quote = record
                .peer_quotes
                .iter()
                .map(|pq| pq.quote.timestamp_unix_secs)
                .min()
                .unwrap_or(0);

            // PUT targets: the same-process fast path uses the targets
            // staged by `pay`; a resumed process re-resolves them via an
            // unpaid quote round (D37 Decision 5 — the fresh plan's
            // payment half is dropped unpaid).
            let staged_targets = {
                let staged = lock_staged(&self.staged);
                staged.paid.get(&address).map(|paid| {
                    debug_assert_eq!(
                        paid.proof_bytes, record.proof_bytes,
                        "staged proof and journaled proof must be the same bytes"
                    );
                    paid.targets.clone()
                })
            };
            let targets = match staged_targets {
                Some(targets) => targets,
                None => {
                    match self
                        .client
                        .prepare_chunk_payment(Bytes::copy_from_slice(blob.as_bytes()))
                        .await
                        .map_err(|e| map_ant_error(ErrContext::Finalize, &e))?
                    {
                        // Already stored after all (race with the probe
                        // above): skip.
                        None => continue,
                        Some(fresh) => fresh.quoted_peers,
                    }
                }
            };

            self.put_to_majority(
                address,
                Bytes::copy_from_slice(blob.as_bytes()),
                &record.proof_bytes,
                &targets,
                oldest_quote,
            )
            .await?;
        }
        Ok(addresses)
    }

    async fn get_data(&self, address: Address) -> Result<Vec<u8>, StorageError> {
        let chunk = self
            .client
            .chunk_get(address.as_bytes())
            .await
            .map_err(|e| map_ant_error(ErrContext::Get, &e))?;
        let Some(chunk) = chunk else {
            return Err(StorageError::NotFound { address });
        };
        // Integrity re-check at our boundary (upstream checks too;
        // defense in depth): the D32 address rule must hold over the
        // returned bytes.
        let derived = antseal_core::storage::compute_storage_address(&chunk.content)
            .map(Address::from)
            .map_err(|_| StorageError::Network {
                reason: format!("network returned an over-cap chunk for address {address}"),
            })?;
        if derived != address {
            return Err(StorageError::Network {
                reason: format!(
                    "network returned bytes whose BLAKE3-256 address does not match the \
                     requested {address} — integrity failure"
                ),
            });
        }
        Ok(chunk.content.to_vec())
    }

    /// ANT (ERC-20 `balanceOf`) and ETH (`eth_getBalance`) balances of
    /// the configured session wallet (task S8) — read-only, over the
    /// re-exported [`Wallet`]'s balance surface
    /// (`evmlib-0.9.0/src/wallet.rs:88-95`).
    ///
    /// On the trait since D89: U14's consent gate takes a
    /// [`StorageBackend`], never this concrete type.
    async fn balances(&self) -> Result<BalanceReport, StorageError> {
        let (ant_atto, gas_wei) = self.raw_balances().await?;
        Ok(BalanceReport {
            wallet: crate::network::EvmAddress20::from_bytes(self.wallet.address().0.0),
            ant_atto,
            gas_wei,
        })
    }
}

// ---------------------------------------------------------------------------
// Conversion + helper functions
// ---------------------------------------------------------------------------

/// S4 address of a blob — the single address authority (D32).
fn s4_address(blob: &Blob) -> Result<Address, StorageError> {
    antseal_core::storage::compute_storage_address(blob.as_bytes())
        .map(Address::from)
        .map_err(|e| StorageError::Quote {
            reason: format!("address computation refused the blob: {e}"),
        })
}

/// Upstream payment plan lines → our mirror (checked u128 conversion —
/// an over-`u128::MAX` amount is a quote-class error, never a truncation).
fn convert_payment_lines(chunk: &PreparedChunk) -> Result<Vec<QuotePaymentEntry>, StorageError> {
    chunk
        .payment
        .quotes
        .iter()
        .map(|info| {
            Ok(QuotePaymentEntry {
                quote_hash: QuoteHash::from_bytes(info.quote_hash.0),
                rewards_address: RewardsAddress::from_bytes(info.rewards_address.0.0),
                amount_atto: checked_u128(info.amount)?,
                price_atto: checked_u128(info.price)?,
            })
        })
        .collect()
}

/// Upstream signed quote preimages → our mirror (field-for-field per the
/// S1 §3 table; the v1.1 chain re-derives
/// `QuoteHash = Keccak-256(bytes_for_sig ‖ pub_key ‖ signature)` from
/// exactly these fields).
fn convert_peer_quotes(chunk: &PreparedChunk) -> Result<Vec<PeerQuote>, StorageError> {
    chunk
        .peer_quotes
        .iter()
        .map(|(peer_id, quote)| {
            Ok(PeerQuote {
                peer_id: EncodedPeerId::from_bytes(*peer_id.as_bytes()),
                quote: QuotePreimage {
                    content: Address::from_bytes(quote.content.0),
                    timestamp_unix_secs: unix_secs(quote.timestamp),
                    price_atto: checked_u128(quote.price)?,
                    rewards_address: RewardsAddress::from_bytes(quote.rewards_address.0.0),
                    node_pub_key: quote.pub_key.clone(),
                    node_signature: quote.signature.clone(),
                    committed_key_count: quote.committed_key_count,
                    commitment_pin: quote.commitment_pin,
                },
            })
        })
        .collect()
}

/// Do the quote's payment lines equal the staged prepared chunk's,
/// line for line? (The D36 staleness check `pay` runs.)
fn payment_lines_match(lines: &[QuotePaymentEntry], prepared: &PreparedChunk) -> bool {
    let staged = &prepared.payment.quotes;
    if lines.len() != staged.len() {
        return false;
    }
    lines.iter().zip(staged).all(|(line, info)| {
        line.quote_hash.as_bytes() == &info.quote_hash.0
            && line.rewards_address.as_bytes() == &info.rewards_address.0.0
            && checked_u128(info.amount).is_ok_and(|amount| amount == line.amount_atto)
            && checked_u128(info.price).is_ok_and(|price| price == line.price_atto)
    })
}

/// Build proof records for every blob whose last needed tx hash exists
/// after `landed_index` sub-batches (`usize::MAX` = the zero-transfer
/// pre-pass). Consumes each blob's `PreparedChunk` exactly once via the
/// pure `finalize_batch_payment` (`batch.rs:337-343`), stages the PUT
/// targets + proof for `finalize_batch`'s fast path, and fills the
/// blob's record slot.
fn finalize_ready_blobs(
    remaining: &mut [Option<PricedBlobSlot>],
    ready_after: &[usize],
    landed_index: usize,
    tx_map: &BTreeMap<QuoteHash, TxHash>,
    records: &mut [Option<BlobPaymentRecord>],
    staged_paid: &mut HashMap<Address, StagedPaid>,
) -> Result<(), StorageError> {
    let upstream_map: HashMap<ant_protocol::evm::QuoteHash, ant_protocol::evm::TxHash> = tx_map
        .iter()
        .map(|(qh, th)| {
            (
                ant_protocol::evm::QuoteHash::from(*qh.as_bytes()),
                ant_protocol::evm::TxHash::from(*th.as_bytes()),
            )
        })
        .collect();
    for slot_entry in remaining.iter_mut() {
        let ready = slot_entry
            .as_ref()
            .is_some_and(|blob| ready_after[blob.slot] == landed_index);
        if !ready {
            continue;
        }
        let Some(blob) = slot_entry.take() else {
            continue;
        };
        let mut paid = finalize_batch_payment(vec![blob.prepared], &upstream_map).map_err(|e| {
            StorageError::Payment {
                reason: format!(
                    "proof construction failed: {}",
                    redact_evm_error(&e.to_string())
                ),
            }
        })?;
        let Some(paid_chunk) = paid.pop() else {
            return Err(StorageError::Payment {
                reason: "upstream returned no paid chunk for one prepared chunk (invariant \
                         breach)"
                    .into(),
            });
        };
        let PaidChunk {
            address: _,
            quoted_peers,
            proof_bytes,
            ..
        } = paid_chunk;
        staged_paid.insert(
            blob.address,
            StagedPaid {
                targets: quoted_peers,
                proof_bytes: proof_bytes.clone(),
            },
        );
        records[blob.slot] = Some(BlobPaymentRecord {
            address: blob.address,
            payments: blob.entries,
            peer_quotes: blob.peer_quotes,
            commitment_sidecars: blob.commitment_sidecars,
            proof_bytes,
        });
    }
    Ok(())
}

/// The priced-blob unit `pay()` threads through payment and proof
/// building (named at module level so `finalize_ready_blobs` can take
/// it; `pay` constructs it from the staged `PreparedChunk` + the quote's
/// converted lines).
struct PricedBlobSlot {
    slot: usize,
    address: Address,
    prepared: PreparedChunk,
    entries: Vec<QuotePaymentEntry>,
    peer_quotes: Vec<PeerQuote>,
    commitment_sidecars: Vec<Vec<u8>>,
}

/// Deliver the cumulative receipt-so-far to the capture hook (no-op
/// without a hook). Order of fields mirrors the final receipt exactly.
fn emit_capture(
    hook: Option<&CaptureHook>,
    records: &[Option<BlobPaymentRecord>],
    tx_map: &BTreeMap<QuoteHash, TxHash>,
    txs: &[TxRecord],
    gas_cost_wei: u128,
) {
    let Some(hook) = hook else { return };
    let blobs: Vec<BlobPaymentRecord> = records.iter().flatten().cloned().collect();
    let storage_cost_atto = blobs
        .iter()
        .flat_map(|record| record.payments.iter())
        .filter(|line| tx_map.contains_key(&line.quote_hash))
        .map(|line| line.amount_atto)
        .sum();
    let receipt = PaymentReceipt {
        blobs,
        tx_map: tx_map.clone(),
        txs: txs.to_vec(),
        storage_cost_atto,
        gas: GasSummary { gas_cost_wei },
    };
    hook(&receipt);
}

/// `Payment` before any landing, `StrandedPayment` after (the split the
/// error taxonomy exists for).
fn stranded_or_payment(landed_tx_count: usize, reason: String) -> StorageError {
    if landed_tx_count == 0 {
        StorageError::Payment { reason }
    } else {
        StorageError::StrandedPayment {
            landed_tx_count,
            reason,
        }
    }
}

/// The payment vault contract address for the wallet's network.
fn vault_address(wallet: &Wallet) -> ant_protocol::evm::Address {
    *wallet.network().payment_vault_address()
}

/// Redact hash-shaped material from an upstream/alloy error rendering
/// before it enters a `reason` string (hygiene, module docs): any run of
/// 16+ hex digits — tx hashes, quote hashes, calldata, addresses — is
/// replaced wholesale. Short numbers (gas figures, nonces, chain ids)
/// survive; anything wallet-linkable does not.
fn redact_evm_error(message: &str) -> String {
    let mut out = String::with_capacity(message.len());
    let mut hex_run = String::new();
    let flush = |run: &mut String, out: &mut String| {
        if run.len() >= 16 {
            out.push_str("<hex redacted>");
        } else {
            out.push_str(run);
        }
        run.clear();
    };
    for c in message.chars() {
        if c.is_ascii_hexdigit() {
            hex_run.push(c);
        } else {
            flush(&mut hex_run, &mut out);
            out.push(c);
        }
    }
    flush(&mut hex_run, &mut out);
    out
}

/// Checked `U256 → u128` (quote-class failure above `u128::MAX` — never a
/// truncation; quote.rs module docs).
fn checked_u128(amount: Amount) -> Result<u128, StorageError> {
    u128::try_from(amount).map_err(|_| StorageError::Quote {
        reason: "a quoted amount exceeds u128::MAX atto-ANT — refusing to truncate".into(),
    })
}

/// `U256 → u128`, saturating — for balances only (comparisons stay
/// correct at saturation; costs use [`checked_u128`]).
fn saturate_u256(value: U256) -> u128 {
    u128::try_from(value).unwrap_or(u128::MAX)
}

/// Unix seconds of a `SystemTime` (pre-epoch clamps to 0 — defensive,
/// never a panic; the signed quote bytes use whole seconds upstream,
/// `data_payments.rs:146-171`).
fn unix_secs(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Lock the staged state; a poisoned mutex is unrecoverable state
/// corruption in a test-panic scenario — recover the guard (state is
/// still consistent: every critical section is a plain insert/remove).
fn lock_staged(staged: &Mutex<Staged>) -> std::sync::MutexGuard<'_, Staged> {
    match staged.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// Which operation an upstream error surfaced from (selects the
/// `StorageError` class).
#[derive(Clone, Copy)]
enum ErrContext {
    Connect,
    Quote,
    Finalize,
    Get,
}

/// Map `ant_core::data::Error` into the S2 taxonomy (S1 §13). Payment-
/// class messages are redacted (module docs: upstream embeds quote-hash
/// hex in some payment errors); transport/storage-class messages pass
/// through (chunk addresses are public identifiers).
fn map_ant_error(context: ErrContext, error: &AntError) -> StorageError {
    let class = match context {
        ErrContext::Connect | ErrContext::Get => None,
        ErrContext::Quote => Some(false),
        ErrContext::Finalize => Some(true),
    };
    match error {
        // `chunk_get` signals absence via `Ok(None)` (mapped by the
        // caller); an `Error::NotFound` from any operation is therefore a
        // network-shaped surprise, not the typed NotFound.
        AntError::NotFound(detail) => StorageError::Network {
            reason: format!("not found: {detail}"),
        },
        AntError::Payment(_) => match class {
            Some(true) => StorageError::Finalize {
                reason: "upstream payment-class error during finalize (detail redacted: \
                         upstream payment errors can embed receipt material)"
                    .into(),
            },
            _ => StorageError::Quote {
                reason: "upstream payment-class error during quoting (detail redacted: \
                         upstream payment errors can embed receipt material)"
                    .into(),
            },
        },
        AntError::AlreadyStored => match class {
            Some(true) => StorageError::Finalize {
                reason: "upstream reported already-stored where a fresh store was expected".into(),
            },
            _ => StorageError::Quote {
                reason: "upstream reported already-stored outside the quote path".into(),
            },
        },
        other => StorageError::Network {
            reason: format!("{other}"),
        },
    }
}

/// Classify a PUT failure during finalize: a **payment-class remote
/// rejection** of a proof whose oldest quote has outlived the node-side
/// validity window is the distinct proofs-expired stranded state (D37
/// Decision 6); every other failure is a retryable finalize/network
/// error.
fn classify_put_error(
    error: &AntError,
    address: Address,
    oldest_quote_unix_secs: u64,
) -> StorageError {
    let payment_class_rejection = matches!(
        error,
        AntError::RemotePut {
            source: ant_protocol::ProtocolError::PaymentFailed(_),
            ..
        }
    ) || matches!(error, AntError::Payment(_));
    if payment_class_rejection && quote_age_exceeds_window(oldest_quote_unix_secs, now_unix_secs())
    {
        return StorageError::ProofsExpired;
    }
    if payment_class_rejection {
        return StorageError::Finalize {
            reason: format!(
                "a storer rejected the payment proof for the blob at {address} (detail \
                 redacted: upstream payment errors can embed receipt material)"
            ),
        };
    }
    map_ant_error(ErrContext::Finalize, error)
}

/// The pure age rule behind the [`StorageError::ProofsExpired`]
/// classification (unit-tested directly — a devnet cannot practically
/// age quotes 24 h).
fn quote_age_exceeds_window(quote_unix_secs: u64, now_unix_secs: u64) -> bool {
    now_unix_secs.saturating_sub(quote_unix_secs) > PROOF_VALIDITY_WINDOW_SECS
}

fn now_unix_secs() -> u64 {
    unix_secs(SystemTime::now())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cap_check_is_a_typed_error_never_a_panic_in_release_shape() {
        // The defense-in-depth seam (D32 Decision 2, adapter layer): the
        // check itself must return the typed error for over-cap lengths —
        // `Blob` makes the input unrepresentable, so the seam is tested
        // directly.
        assert!(AntCoreBackend::check_blob_len(0).is_ok());
        assert!(AntCoreBackend::check_blob_len(MAX_CHUNK_SIZE).is_ok());
        let err = AntCoreBackend::check_blob_len(MAX_CHUNK_SIZE + 1);
        match err {
            Err(StorageError::Quote { reason }) => {
                assert!(reason.contains("4194304"), "{reason}");
            }
            other => panic!("expected the typed Quote error, got {other:?}"),
        }
    }

    #[test]
    fn proof_expiry_classifier_uses_the_24h_window() {
        let now = 2_000_000_000;
        // Fresh quote: not expired.
        assert!(!quote_age_exceeds_window(now - 60, now));
        // Exactly at the window edge: not expired (strictly-greater rule).
        assert!(!quote_age_exceeds_window(
            now - PROOF_VALIDITY_WINDOW_SECS,
            now
        ));
        // One second past: expired.
        assert!(quote_age_exceeds_window(
            now - PROOF_VALIDITY_WINDOW_SECS - 1,
            now
        ));
        // Future-dated quote (clock skew): never "expired".
        assert!(!quote_age_exceeds_window(now + 3_600, now));
    }

    #[test]
    fn stranded_split_matches_the_taxonomy() {
        assert!(matches!(
            stranded_or_payment(0, "x".into()),
            StorageError::Payment { .. }
        ));
        assert!(matches!(
            stranded_or_payment(2, "x".into()),
            StorageError::StrandedPayment {
                landed_tx_count: 2,
                ..
            }
        ));
    }

    #[test]
    fn amount_conversions_are_checked_not_truncating() {
        assert_eq!(checked_u128(U256::from(42u64)).ok(), Some(42));
        let over = U256::from(u128::MAX).saturating_add(U256::from(1u64));
        assert!(matches!(
            checked_u128(over),
            Err(StorageError::Quote { .. })
        ));
        assert_eq!(saturate_u256(over), u128::MAX);
    }

    #[test]
    fn balance_and_preflight_reports_serialize_for_json_consumers() {
        // S8 accept: structured data consumable by U's consent UX and
        // `--json`. serde_json is the pinned evidence codec (dev-dep).
        let balances = BalanceReport {
            wallet: crate::network::EvmAddress20::from_bytes([0xAB; 20]),
            ant_atto: 1_000_000,
            gas_wei: 42,
        };
        let json = serde_json::to_value(balances).expect("serializes");
        assert_eq!(json["ant_atto"], 1_000_000);
        assert_eq!(json["gas_wei"], 42);

        let report = PreflightReport {
            required_ant_atto: 900,
            available_ant_atto: 1_000_000,
            required_gas_wei: 40,
            available_gas_wei: 42,
        };
        let json = serde_json::to_value(report).expect("serializes");
        assert_eq!(json["required_ant_atto"], 900);
        assert_eq!(json["available_gas_wei"], 42);
        let back: PreflightReport = serde_json::from_value(json).expect("round-trips");
        assert_eq!(back, report);
    }

    #[test]
    fn payment_class_upstream_errors_are_redacted() {
        // Upstream payment errors can embed quote-hash hex
        // (batch.rs:300-305); the mapped message must not carry it.
        let leaky = AntError::Payment("Missing tx hash for quote deadbeefcafebabe".into());
        let mapped = map_ant_error(ErrContext::Quote, &leaky);
        let rendered = mapped.to_string();
        assert!(
            !rendered.contains("deadbeef"),
            "payment detail leaked: {rendered}"
        );
        // Transport-class detail passes through (public addresses only).
        let transport = AntError::Network("dial failed to peer".into());
        assert!(
            map_ant_error(ErrContext::Get, &transport)
                .to_string()
                .contains("dial failed"),
        );
    }
}
