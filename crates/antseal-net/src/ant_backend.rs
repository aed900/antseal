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
//! | `get_data` | `chunk_get` (D32: blob = one chunk; no `DataMap`); on `Ok(None)`, `chunk_get_from_close_group` so that only an authoritative sweep reports absence | `ant-core-0.5.0/src/data/client/chunk.rs:632-636,851-857,168-170` |
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
//! # The second client: [`AntCoreReader`] (D170 §2 R1)
//!
//! Read-only commands get a client built with **neither** `with_wallet` nor
//! `with_evm_network`, which drives `chunk_get` and nothing else. It lives in
//! this file for the same reason the payer does — an ant-core bump re-verifies
//! one file — and it shares the payer's connect configuration and its
//! `get_data` address re-check rather than copying them.
//!
//! # The third type: [`AntCoreReceiptReader`] (D173 §2 R14)
//!
//! A receipt read — `status`'s block-number backfill — needs neither a storage
//! session nor a key. This type builds a key-less provider over the payment RPC,
//! runs the payer's chain-id guard, and backfills; it holds no `Client`, so it
//! dials no storage peer and consults no storage gate.
//!
//! # The storage gate and the transport mode (D173 §2 R8–R10)
//!
//! Both storage constructors — the payer's and the reader's — consult
//! [`crate::network::storage_gate`] as their first fallible step, then
//! [`crate::network::upstream_state`] (S42: an environment in which upstream
//! would panic or write its state file under the current directory is refused),
//! then derive the transport mode from the peers (`client_config`), and only
//! then open a socket. A shape scan in `tests/storage_gate.rs` holds that order
//! in the default feature set, where this file is not even compiled.
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
//! the payer's `eth_getTransactionReceipt` backfill all ride it — the same
//! S5-configured payment RPC endpoint D33 names.
//!
//! **[D173 §2 R14, 2026-09-15]** This paragraph used to say that no second
//! provider is constructed, because the backfill could ride this one. That
//! made a receipt read cost a payment session: a signing key and a storage
//! `Client`. [`AntCoreReceiptReader`] now builds the key-less provider D33's
//! letter names (`ant_protocol::evm::utils::http_provider`) over the same
//! endpoint, and the payer's backfill runs the same function over this
//! provider. Its nonce filler re-reads the pending count per tx
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
use ant_protocol::evm::utils::http_provider;
use ant_protocol::evm::{Amount, U256};
use bytes::Bytes;

use crate::backend::{BalanceReport, PreflightReport, allowance_to_approve};
use crate::evm::to_evm_network;
use crate::network::{NetworkConfig, PeerLocality, storage_gate, upstream_state};
use crate::put_policy::{self, PayingTx, PutReply, PutTally, PutVerdict};
use crate::quote::{
    BlobCost, BlobQuote, CostQuote, EncodedPeerId, PeerQuote, QuoteHash, QuotePaymentEntry,
    QuotePreimage, RewardsAddress, TxHash,
};
use crate::receipt::{BlobPaymentRecord, GasSummary, PaymentReceipt, TxRecord, TxStatus};
use crate::wallet::WalletKey;
use crate::{Address, Blob, CaptureOutcome, MAX_CHUNK_SIZE, StorageBackend, StorageError};

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

// antseal's proof-age window (~24 h, D37 Decision 6) and the rule that reads
// it moved to `crate::put_policy` with S43 (D179 R4): the verdict is pure and
// lives in the default graph; this file only feeds it.

/// Per-sub-batch journal capture hook (D37 Decision 2 / S7 timing
/// contract): invoked with the **cumulative** receipt-so-far after each
/// sub-batch tx lands — strictly before the next sub-batch is submitted —
/// so when `pay` returns a receipt, the last payload equals it (the S7
/// capture-consistency test asserts it). The journal WRITE is the pipeline's
/// (S10/S12); the hook answers whether it became durable ([`CaptureOutcome`]),
/// and after a not-durable answer `pay` submits no further sub-batch (S46).
pub type CaptureHook = Arc<dyn Fn(&PaymentReceipt) -> CaptureOutcome + Send + Sync>;

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
    /// The steps, in the order they run — the first three are pure, so **no
    /// socket is opened until all have passed** (D173 §2 R10):
    ///
    /// 1. The **storage gate** ([`crate::network::storage_gate`]): when armed,
    ///    a bootstrap set holding any non-loopback peer is refused here. It
    ///    must precede the `eth_chainId` call below, because for a public
    ///    network id that call reaches evmlib's compiled-in public RPC
    ///    whatever `config.rpc_url` says (`crate::evm::to_evm_network`).
    /// 2. **Upstream's state directory** ([`crate::network::upstream_state`],
    ///    S42, D178 R1): an environment in which the client would panic — after
    ///    dialing — or write its `client_adaptive.json` under the current
    ///    directory is refused here.
    /// 3. The **transport mode** (`client_config`, D173 §2 R8): loopback comes
    ///    from the resolved peers, and a set no mode can dial — empty, mixed,
    ///    unspecified, port 0, repeated, or loopback under `arbitrum-one` — is
    ///    refused here, still before any socket.
    /// 4. EVM side: the payment [`Wallet`] built from the vault-held key
    ///    handle (custody is U10/U13's; this takes the handle), plus the one
    ///    signing provider (module docs).
    /// 5. Guard: the RPC's `eth_chainId` must equal `config.evm_chain_id` —
    ///    the wrong-network/wrong-Sepolia guard the `NetworkConfig` field
    ///    documents, shared with [`AntCoreReceiptReader::connect`].
    /// 6. Autonomi side: `Client::connect` over `config.bootstrap`, then
    ///    `with_evm_network` (the external-signer driver — deliberately never
    ///    `with_wallet`, see module docs).
    ///
    /// # Errors
    ///
    /// [`StorageError::Network`] for the storage gate's refusal, the
    /// upstream-state refusal, a peer set no transport mode can dial, and
    /// connect/transport/chain-id failures; [`StorageError::Quote`] never (no
    /// quoting here).
    pub async fn connect(
        config: &NetworkConfig,
        wallet_key: &WalletKey,
    ) -> Result<Self, StorageError> {
        consult_storage_gate(config)?;
        consult_upstream_state()?;
        let client_config = client_config(config)?;
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
        chain_id_guard(&provider, config).await?;

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

    /// Idempotent block-number backfill (D33 Decision 2) over this payment
    /// session's own provider: for every [`TxRecord`] whose `block_number`
    /// slot is empty, read `eth_getTransactionReceipt(tx_hash)` and fill
    /// `block_number`/`status`. Returns how many records were enriched.
    ///
    /// **[D173 §2 R14, 2026-09-15] A delegation, kept for a caller that already
    /// holds a payment session.** The body belongs to
    /// [`AntCoreReceiptReader::backfill_block_numbers`], which reads the same
    /// receipts with no Autonomi `Client` and no wallet key — the type a
    /// receipt read that holds no payment session (`status`) should build.
    /// Both run one function, so they cannot drift.
    ///
    /// # Errors
    ///
    /// As [`AntCoreReceiptReader::backfill_block_numbers`].
    pub async fn backfill_block_numbers(
        &self,
        receipt: &mut PaymentReceipt,
    ) -> Result<usize, StorageError> {
        fill_block_numbers(&self.provider, receipt).await
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
    /// allowance is below `total_atto`, approve exactly `total_atto` —
    /// never unlimited. Returns the approve tx's gas cost in wei (0 when
    /// no approve was needed).
    ///
    /// # The amount is decided elsewhere, deliberately
    ///
    /// The rule is [`allowance_to_approve`] in the DEFAULT feature set,
    /// not a literal here, so that it can be pinned by a test that needs
    /// no upstream graph, no network and no spend
    /// (`tests/allowance_policy.rs`). **Do not inline it.** The choice it
    /// encodes is a ruled wallet-hygiene/anonymity trade — Q240,
    /// `docs/threat-model.md` §2.3 — and the obvious "simplification"
    /// toward upstream's shape is precisely the refactor the pin exists to
    /// catch. Upstream carries the *identical* guard
    /// (`evmlib-0.9.0/src/wallet.rs:185-190`, `:415-426`); the clients
    /// differ only in the amount.
    ///
    /// # The short-circuit is not an optimisation that works
    ///
    /// `allowance_to_approve` returning `None` — the standing allowance
    /// already covers the total — **almost never happens on this path**,
    /// and a reader should not mistake it for a saving. An exact allowance
    /// is consumed by the very payment it was raised for: `payForQuotes`
    /// moves exactly `total_atto` by `transferFrom`, which decrements the
    /// allowance to zero, so the next seal starts from zero again. It
    /// fires only when a previous seal approved and then failed to spend
    /// (a [`StorageError::StrandedPayment`] shape) and the next seal's
    /// total is no larger than what was left. The observable consequence
    /// is a fresh, public, permanent `Approval` before essentially every
    /// seal, which is the fingerprint §2.3 prices.
    ///
    /// The `U256 → u128` lift of the current allowance is verdict-
    /// preserving (see [`saturate_u256`]): a standing allowance above
    /// `u128::MAX` saturates to `u128::MAX`, which still compares
    /// greater-or-equal to every representable total, so an unlimited
    /// standing allowance short-circuits exactly as it does at full width.
    async fn ensure_allowance(&self, total_atto: u128) -> Result<u128, StorageError> {
        let vault = vault_address(&self.wallet);
        let current =
            self.wallet
                .token_allowance(vault)
                .await
                .map_err(|e| StorageError::Network {
                    reason: format!("allowance query failed: {e}"),
                })?;
        let Some(amount_atto) = allowance_to_approve(saturate_u256(current), total_atto) else {
            return Ok(0);
        };
        let tx_hash = self
            .wallet
            .approve_to_spend_tokens(vault, U256::from(amount_atto))
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
            gas_cost_wei = self.ensure_allowance(total).await?;
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
        // are proof-ready immediately, with no tx hashes. This runs before
        // any sub-batch is submitted, so a proof failure here moved no ANT.
        finalize_ready_blobs(
            &mut remaining,
            &ready_after,
            usize::MAX,
            &tx_map,
            &mut records,
            &mut lock_staged(&self.staged).paid,
        )
        .map_err(pre_pass_proof_failure)?;

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

            // A reverted payForQuotes moved no ANT: its quotes are NOT mapped
            // (they are unpaid). A confirmed one maps its quotes and builds
            // the proofs that became complete with this landing (per-blob
            // `finalize_batch_payment` — pure, `batch.rs:337-343`); a proof
            // failure is data here, because after a landing it is not a
            // payment that moved nothing (S49).
            let outcome = if confirmed {
                for (_, quote_hash, ..) in *batch {
                    tx_map.insert(*quote_hash, landed_hash);
                }
                let finalized = finalize_ready_blobs(
                    &mut remaining,
                    &ready_after,
                    batch_index,
                    &tx_map,
                    &mut records,
                    &mut lock_staged(&self.staged).paid,
                );
                SubBatchOutcome::Confirmed { finalized }
            } else {
                SubBatchOutcome::Reverted
            };
            // Journal via the hook BEFORE the next submission, and decide
            // whether the payment goes on (S46, S49, S50 — D204).
            settle_sub_batch(
                outcome,
                self.capture_hook.as_ref(),
                &records,
                &tx_map,
                &txs,
                gas_cost_wei,
                batch_index,
                sub_batches.len(),
            )?;
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

            let content = Bytes::copy_from_slice(blob.as_bytes());
            let provider = &self.provider;
            put_to_majority(
                address,
                receipt,
                record,
                &targets,
                |(peer, addrs)| {
                    self.client.chunk_put_with_proof(
                        content.clone(),
                        record.proof_bytes.clone(),
                        peer,
                        addrs,
                    )
                },
                |paying| paying_block_time(provider, paying),
                now_unix_secs,
            )
            .await?;
        }
        Ok(addresses)
    }

    async fn get_data(&self, address: Address) -> Result<Vec<u8>, StorageError> {
        fetch_chunk(&self.client, address).await
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
// The wallet-less download-only reader (D170 §2 R1)
// ---------------------------------------------------------------------------

/// Why every non-fetching method of [`AntCoreReader`] refuses.
///
/// One sentence for all four, carried inside the variant each method's own
/// trait contract names for that operation failing with nothing at risk
/// (`quote_batch` → [`StorageError::Quote`], `pay` → [`StorageError::Payment`],
/// `finalize_batch` → [`StorageError::Finalize`], `balances` →
/// [`StorageError::Network`]). No new variant: `fetch_failure_class` stays
/// total over the same closed set, so the class vocabulary a `--live` row can
/// carry does not grow. Names no key, no receipt field, no address.
const READER_REFUSAL: &str = "this is the download-only reader: it was connected with no wallet \
     and no EVM network, so it cannot quote, pay, store or read balances — a command that pays \
     must use the payment backend, which carries the D37 capture hook";

/// A connected Autonomi client that can **fetch and nothing else** — no
/// wallet, no EVM network, no payment RPC (D170 §2 R1).
///
/// # Why a second type, not an optional wallet on [`AntCoreBackend`]
///
/// `restore` and `verify --live` only ever call `get_data`, and upstream
/// needs no wallet for it: `Client::connect(peers, ClientConfig)` builds a
/// client with `wallet: None, evm_network: None`
/// (`ant-core-0.5.0/src/data/client/mod.rs:410-433`) and `chunk_get` reads
/// neither (`chunk.rs:632-636`). [`AntCoreBackend::connect`] instead demands
/// a signing wallet and an `eth_chainId` answer before it will dial a single
/// peer — `verify` holds no vault and so no key (D99 R2), and a vault made by
/// `create_vault` holds no wallet record. D170 refused the two cheaper
/// shapes: a throwaway wallet would mint key material to read public
/// ciphertext, and an `Option` wallet on the payer would put a runtime `None`
/// check between D37's capture guarantee and every payment.
///
/// # It cannot pay, structurally
///
/// The client is built **without** `with_evm_network` and without
/// `with_wallet`, so even upstream's own payment paths would fail their
/// `require_evm_network` guard; and this type's `quote_batch`, `pay`,
/// `finalize_batch` and `balances` never touch the client at all — they
/// return `READER_REFUSAL` in the variant their trait contract names. The
/// CLI additionally holds it behind a read-only wrapper, so a command that
/// needs to pay cannot be handed one by accident.
///
/// # Shared, not copied
///
/// The storage gate, `client_config` (the transport mode derived from the
/// peers, D173 §2 R8) and `fetch_chunk` (the `chunk_get` call, its absence
/// confirmation and its D32 address re-check) are the same functions
/// [`AntCoreBackend`] uses, so the payer and the reader cannot drift on which
/// peers may be dialed, in which mode, or on what bytes count as the chunk
/// asked for.
pub struct AntCoreReader {
    client: Client,
    config: NetworkConfig,
}

impl AntCoreReader {
    /// Connect to `config.bootstrap` with no wallet and no EVM network.
    ///
    /// Nothing about the payment side of `config` is read: no RPC is dialed
    /// and no chain id is checked, because nothing this type does can reach
    /// a chain. Before `Client::connect`, and before any socket, the storage
    /// gate is consulted first (D173 §2 R10), then upstream's state directory
    /// (S42), and then the transport mode is derived from the peers — exactly
    /// as for the payer (`client_config`).
    ///
    /// # A connection that succeeded is not a network that answers
    ///
    /// Upstream does not gate client start-up on reaching a peer: saorsa-core
    /// 0.26.2's `connect_bootstrap_peers` returns `Ok` when it has nothing to
    /// dial (`src/network.rs:2099`) and, after every dial has failed, *"Starting
    /// a node should not be gated on immediate bootstrap connectivity"*
    /// (`:2166`). Measured on a live devnet (2026-09-13): a dead loopback
    /// bootstrap connected `Ok` in 6.3 s and an empty one in 45 ms. So an
    /// unreachable network surfaces at the first `get_data`, not here — and
    /// `fetch_chunk` is what keeps that fetch from calling the chunk absent.
    /// **[D173 §2 R8, 2026-09-15]** An empty set no longer reaches upstream at
    /// all: `client_config` refuses it in the network class. A dead set still
    /// connects `Ok`. `tests/devnet_backend.rs`'s
    /// `devnet_d170_an_unreachable_network_is_never_reported_as_absence` holds
    /// both halves.
    ///
    /// # Errors
    ///
    /// [`StorageError::Network`] for the storage gate's refusal, the
    /// upstream-state refusal, a peer set no transport mode can dial, and when
    /// upstream cannot create or start the client node.
    pub async fn connect(config: &NetworkConfig) -> Result<Self, StorageError> {
        consult_storage_gate(config)?;
        consult_upstream_state()?;
        let client_config = client_config(config)?;
        let client = Client::connect(&config.bootstrap, client_config)
            .await
            .map_err(|e| map_ant_error(ErrContext::Connect, &e))?;
        Ok(Self {
            client,
            config: config.clone(),
        })
    }

    /// The network this reader is bound to.
    #[must_use]
    pub fn network_config(&self) -> &NetworkConfig {
        &self.config
    }
}

impl StorageBackend for AntCoreReader {
    async fn quote_batch(&self, _blobs: &[Blob]) -> Result<CostQuote, StorageError> {
        Err(StorageError::Quote {
            reason: READER_REFUSAL.to_owned(),
        })
    }

    async fn pay(&self, _quote: &CostQuote) -> Result<PaymentReceipt, StorageError> {
        Err(StorageError::Payment {
            reason: READER_REFUSAL.to_owned(),
        })
    }

    async fn finalize_batch(
        &self,
        _receipt: &PaymentReceipt,
        _blobs: &[Blob],
    ) -> Result<Vec<Address>, StorageError> {
        Err(StorageError::Finalize {
            reason: READER_REFUSAL.to_owned(),
        })
    }

    async fn get_data(&self, address: Address) -> Result<Vec<u8>, StorageError> {
        fetch_chunk(&self.client, address).await
    }

    async fn balances(&self) -> Result<BalanceReport, StorageError> {
        Err(StorageError::Network {
            reason: READER_REFUSAL.to_owned(),
        })
    }
}

// ---------------------------------------------------------------------------
// The receipt reader (D173 §2 R14): a chain read with no storage session
// ---------------------------------------------------------------------------

/// Reads EVM payment receipts over a network's payment RPC — **no Autonomi
/// `Client`, no wallet, no EVM network object** (D173 §2 R14).
///
/// # Why a third type
///
/// `status`'s block-number backfill (D33 Decision 2) reads public receipts. It
/// rode the payer: a full [`AntCoreBackend::connect`], which needs the vault's
/// signing key and runs `Client::connect` over the bootstrap set, and whose
/// client the backfill never used. With `arbitrum-one`'s vendored peers that
/// would have made `status` dial the storage network to read a chain. This type
/// is D33 Decision 1's letter instead: a key-less provider from
/// `ant_protocol::evm::utils::http_provider` over the definition's RPC URL.
///
/// # What it does not consult
///
/// The storage gate ([`crate::network::storage_gate`]) and the bootstrap set:
/// it opens no storage session, so there is no storage peer to refuse, and
/// `config.bootstrap` is never read. The payment RPC stays outside both
/// network gates (D173 §2 R13).
pub struct AntCoreReceiptReader {
    provider: DynProvider,
    config: NetworkConfig,
}

impl AntCoreReceiptReader {
    /// Build the key-less provider over `config.rpc_url` and run the payer's
    /// chain-id guard.
    ///
    /// For `arbitrum-one` and `arbitrum-sepolia` the URL is the pinned public
    /// endpoint, which `crate::evm`'s agreement test holds equal to the
    /// built-in one the payer's wallet provider uses; for `devnet` it is the
    /// export's.
    ///
    /// # Errors
    ///
    /// [`StorageError::Network`] when the RPC URL does not parse (the URL is not
    /// echoed: a private endpoint can carry a credential in its path), when
    /// `eth_chainId` fails, or when the RPC reports a chain other than
    /// `config.evm_chain_id` — the payer's guard, in the payer's words.
    pub async fn connect(config: &NetworkConfig) -> Result<Self, StorageError> {
        let rpc_url: url::Url = config.rpc_url.parse().map_err(|_| StorageError::Network {
            reason: format!("the {} payment RPC URL is not a valid URL", config.id),
        })?;
        let provider = http_provider(rpc_url).erased();
        chain_id_guard(&provider, config).await?;
        Ok(Self {
            provider,
            config: config.clone(),
        })
    }

    /// The network this reader is bound to.
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
    /// number of times; enrichment never gates finalize. A hash whose receipt
    /// is not yet visible is left untouched (retry later).
    ///
    /// # Errors
    ///
    /// [`StorageError::Network`] only when the RPC itself is unreachable; an
    /// individual not-yet-visible receipt is not an error.
    pub async fn backfill_block_numbers(
        &self,
        receipt: &mut PaymentReceipt,
    ) -> Result<usize, StorageError> {
        fill_block_numbers(&self.provider, receipt).await
    }
}

// ---------------------------------------------------------------------------
// Conversion + helper functions
// ---------------------------------------------------------------------------

/// The storage gate (D173 §2 R9) as both storage constructors consult it —
/// **first**, before any other fallible step and any socket (§2 R10).
///
/// Refuses in the network class, so no new [`StorageError`] variant exists for
/// it (D173 §2 R9), with a reason that begins with
/// [`storage_gate::REFUSAL`].
fn consult_storage_gate(config: &NetworkConfig) -> Result<(), StorageError> {
    storage_gate::check(&config.bootstrap).map_err(|refusal| StorageError::Network {
        reason: refusal.to_string(),
    })
}

/// Upstream's state directory (S42, D178 R1) as both storage constructors
/// consult it — **second**, right after the storage gate, and still before any
/// socket.
///
/// `Client::connect` reads and, on drop, writes `client_adaptive.json` in a
/// directory it finds through the environment; where that lookup would panic —
/// after the client node has started and dialed — or would resolve a
/// directory that is not absolute, this refuses instead, in the network
/// class, so no new [`StorageError`] variant exists for it either. The reason
/// begins with [`upstream_state::REFUSAL`].
fn consult_upstream_state() -> Result<(), StorageError> {
    upstream_state::check().map_err(|refusal| StorageError::Network {
        reason: refusal.to_string(),
    })
}

/// The upstream client configuration **both** storage adapters connect with —
/// or the refusal of a peer set no transport mode can dial (D173 §2 R8).
///
/// `allow_loopback` comes from the peers, never from the network id:
/// [`NetworkConfig::peer_locality`] classifies `config.bootstrap` after
/// IPv4-mapped canonicalization, and only an all-loopback set binds loopback.
/// Upstream threads the flag to saorsa-core's `local` mode, which binds
/// loopback only and admits loopback candidates
/// (`ant-core-0.5.0/src/data/network.rs:48-54`; `saorsa-core-0.26.2/src/
/// network.rs:178-185,551-552`), while production peers reject the handshake
/// variant it produces (`ant-core-0.5.0/src/data/client/mod.rs:238-247`) — so a
/// mixed set has no mode that serves it.
///
/// A refusal is the network class, before `Client::connect`, in the payer and
/// the reader alike: the variant D170's absence tests accept, so an empty set's
/// refusal reads as an unreachable network and never as absence.
///
/// **Recorded behaviour change (D173 §2 R8):** this used to key loopback on the
/// `devnet` id, so a devnet export with non-loopback peers bound loopback only
/// (it now binds all interfaces), and an `arbitrum-sepolia` configuration
/// holding a Sepolia devnet's loopback peers could not dial them (it now binds
/// loopback, D174 §2 R5).
fn client_config(config: &NetworkConfig) -> Result<ClientConfig, StorageError> {
    let locality = config
        .peer_locality()
        .map_err(|refusal| StorageError::Network {
            reason: format!(
                "refusing to connect over the {} bootstrap set: {refusal}",
                config.id
            ),
        })?;
    Ok(ClientConfig {
        allow_loopback: locality == PeerLocality::Loopback,
        ..ClientConfig::default()
    })
}

/// The wrong-network guard both payment-RPC constructors run — the payer's and
/// the receipt reader's: `eth_chainId` must equal `config.evm_chain_id` (42161 /
/// 421614 / a devnet's run-scoped id). One function, so the check and its words
/// cannot drift between them.
async fn chain_id_guard(
    provider: &DynProvider,
    config: &NetworkConfig,
) -> Result<(), StorageError> {
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
    Ok(())
}

/// D33 Decision 2's backfill body, run by
/// [`AntCoreReceiptReader::backfill_block_numbers`] and, as a delegation, by
/// [`AntCoreBackend::backfill_block_numbers`] (D173 §2 R14).
async fn fill_block_numbers(
    provider: &DynProvider,
    receipt: &mut PaymentReceipt,
) -> Result<usize, StorageError> {
    let mut filled = 0usize;
    for tx in &mut receipt.txs {
        if tx.block_number.is_some() {
            continue;
        }
        let hash = alloy::primitives::B256::from(*tx.tx_hash.as_bytes());
        let fetched =
            provider
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

/// `get_data` for **both** adapters: `chunk_get` (D32: blob = one chunk, no
/// `DataMap`); when that finds nothing, a confirming close-group sweep that
/// alone may call the chunk absent; then the address re-check at our own
/// boundary.
///
/// # `chunk_get`'s `Ok(None)` is not an answer
///
/// ant-core 0.5.0 returns `Ok(None)` from `chunk_get` for authoritative
/// absence **and** for three things that are not absence at all: a first
/// close-group lookup that failed (swallowed, `chunk.rs:678-690`), a retry
/// lookup that failed too (`:747`), and a sweep that timed out or erred
/// without a unanimous answer (`:771`). Mapping every `None` to
/// [`StorageError::NotFound`] — which this adapter used to do — made an
/// unreachable network report *"no such chunk"*: measured on a live devnet
/// before this change (2026-09-13), a reader whose bootstrap was a dead
/// loopback port, or empty, connected `Ok` and answered `NotFound` in 1.0 s
/// for a chunk the devnet held. The live
/// check renders `NotFound` as a negative fact (*"no longer on the
/// network"*), so that was a false statement about stored evidence.
/// `devnet_d170_an_unreachable_network_is_never_reported_as_absence` is the
/// negative control that now holds the line.
///
/// So a `None` is re-asked through `chunk_get_from_close_group`
/// (`chunk.rs:851`), which reports every close-group peer's own answer, and
/// [`classify_sweep`] applies upstream's absence rule to it. Only a verdict
/// of absence becomes `NotFound`; anything less is the network class, and a
/// peer that serves the chunk during the sweep serves it.
///
/// # Errors
///
/// [`StorageError::NotFound`] only when a close-group sweep established
/// absence authoritatively; [`StorageError::Network`] for a transport
/// failure, a lookup or sweep that established nothing, an over-cap chunk, or
/// bytes that do not hash to `address` (R79's recorded cost: a mismatch is
/// reported in the network class, so `Different` cannot arise from this
/// adapter).
async fn fetch_chunk(client: &Client, address: Address) -> Result<Vec<u8>, StorageError> {
    let fetched = client
        .chunk_get(address.as_bytes())
        .await
        .map_err(|e| map_ant_error(ErrContext::Get, &e))?;
    let content = match fetched {
        Some(chunk) => chunk.content,
        None => confirm_absence(client, address).await?,
    };
    // Integrity re-check at our boundary (upstream checks too; defense in
    // depth): the D32 address rule must hold over the returned bytes.
    let derived = antseal_core::storage::compute_storage_address(&content)
        .map(Address::from)
        .map_err(|_| StorageError::Network {
            reason: format!("network returned an over-cap chunk for address {address}"),
        })?;
    if derived != address {
        return Err(StorageError::Network {
            reason: format!(
                "network returned bytes whose BLAKE3-256 address does not match the requested \
                 {address} — integrity failure"
            ),
        });
    }
    Ok(content.to_vec())
}

/// Re-ask the close group about a chunk `chunk_get` did not find.
///
/// Returns the chunk if a peer serves it; otherwise an error that is
/// [`StorageError::NotFound`] only when the sweep's answers are authoritative
/// ([`classify_sweep`]), and [`StorageError::Network`] — naming the counts,
/// never a peer or a byte — when they are not. A lookup that fails outright
/// (no peers to ask) is the network class too, through [`map_ant_error`].
async fn confirm_absence(client: &Client, address: Address) -> Result<Bytes, StorageError> {
    let answers = client
        .chunk_get_from_close_group(address.as_bytes())
        .await
        .map_err(|e| map_ant_error(ErrContext::Get, &e))?
        .into_iter()
        .map(|peer| match peer.chunk_result {
            Ok(Some(chunk)) => PeerAnswer::Served(chunk.content),
            Ok(None) => PeerAnswer::NotFound,
            Err(_) => PeerAnswer::Failed,
        });
    match classify_sweep(answers) {
        SweepVerdict::Served(content) => Ok(content),
        SweepVerdict::Absent => Err(StorageError::NotFound { address }),
        SweepVerdict::Unestablished { queried, not_found } => Err(StorageError::Network {
            reason: format!(
                "the network did not establish whether {address} is stored: {not_found} of \
                 {queried} close-group peer(s) answered not-found, and absence needs a unanimous \
                 answer from at least {CLOSE_GROUP_MAJORITY}"
            ),
        }),
    }
}

/// One close-group peer's answer to a chunk GET, reduced to what
/// [`classify_sweep`] needs.
enum PeerAnswer {
    /// The peer served the chunk (upstream verified address and hash).
    Served(Bytes),
    /// The peer answered that it holds no such chunk.
    NotFound,
    /// No usable answer: timeout, transport or protocol error, bad bytes.
    Failed,
}

/// What a close-group sweep established about one address.
#[derive(Debug, PartialEq, Eq)]
enum SweepVerdict {
    /// A peer served the chunk.
    Served(Bytes),
    /// Absence, established by upstream's own rule.
    Absent,
    /// Neither: too few peers answered, or not unanimously.
    Unestablished {
        /// Peers the sweep asked.
        queried: usize,
        /// Of those, peers that answered not-found.
        not_found: usize,
    },
}

/// Classify a sweep's answers: the first served chunk wins; otherwise absence
/// only by [`is_authoritative_absence`]; otherwise nothing was established.
fn classify_sweep(answers: impl IntoIterator<Item = PeerAnswer>) -> SweepVerdict {
    let mut queried = 0usize;
    let mut not_found = 0usize;
    for answer in answers {
        queried += 1;
        match answer {
            PeerAnswer::Served(content) => return SweepVerdict::Served(content),
            PeerAnswer::NotFound => not_found += 1,
            PeerAnswer::Failed => {}
        }
    }
    if is_authoritative_absence(not_found, queried) {
        SweepVerdict::Absent
    } else {
        SweepVerdict::Unestablished { queried, not_found }
    }
}

/// ant-core 0.5.0's own absence rule, mirrored: a **majority-sized** sample
/// (`CLOSE_GROUP_MAJORITY`, the replica count, `ant-protocol-2.3.0/src/
/// chunk.rs:40`) that answered not-found **unanimously**.
///
/// Upstream's `is_authoritative_not_found` (`ant-core-0.5.0/src/data/client/
/// chunk.rs:168`) is private, so the two lines are restated here — which makes
/// this function an S20 bump-checklist item: an upstream change to that rule
/// must be carried here by hand, and `absence_needs_a_unanimous_majority_
/// sized_sample` pins today's table. The reasoning is upstream's and is worth
/// keeping: replicas sit on 4 of 7 peers, so a non-unanimous answer can be
/// storers that did not reply, and a thin lookup of 1–3 peers can miss the
/// replica set entirely.
const fn is_authoritative_absence(not_found: usize, queried: usize) -> bool {
    queried >= CLOSE_GROUP_MAJORITY && not_found == queried
}

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
///
/// It stops at the first blob whose proof cannot be built — the blobs
/// before it keep their records — and returns that failure's redacted
/// detail as DATA, not as a [`StorageError`]: the class depends on when it
/// happened (S49, D204). The pre-pass maps it to [`StorageError::Payment`]
/// ([`pre_pass_proof_failure`]); after a landing, [`settle_sub_batch`]
/// captures what exists and strands.
fn finalize_ready_blobs(
    remaining: &mut [Option<PricedBlobSlot>],
    ready_after: &[usize],
    landed_index: usize,
    tx_map: &BTreeMap<QuoteHash, TxHash>,
    records: &mut [Option<BlobPaymentRecord>],
    staged_paid: &mut HashMap<Address, StagedPaid>,
) -> Result<(), String> {
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
        let mut paid = finalize_batch_payment(vec![blob.prepared], &upstream_map)
            .map_err(|e| redact_evm_error(&e.to_string()))?;
        let Some(paid_chunk) = paid.pop() else {
            return Err(
                "upstream returned no paid chunk for one prepared chunk (invariant breach)".into(),
            );
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

/// Deliver the cumulative receipt-so-far to the capture hook and return its
/// verdict — `None` without a hook, which is no verdict (S46). Order of
/// fields mirrors the final receipt exactly.
fn emit_capture(
    hook: Option<&CaptureHook>,
    records: &[Option<BlobPaymentRecord>],
    tx_map: &BTreeMap<QuoteHash, TxHash>,
    txs: &[TxRecord],
    gas_cost_wei: u128,
) -> Option<CaptureOutcome> {
    let hook = hook?;
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
    Some(hook(&receipt))
}

/// What one awaited sub-batch receipt reported, as [`settle_sub_batch`]
/// takes it (D204).
#[derive(Debug)]
enum SubBatchOutcome {
    /// Mined but reverted: no ANT moved, and the sub-batch's quotes are not
    /// mapped (they are unpaid).
    Reverted,
    /// Mined successfully: the sub-batch's quotes are mapped, and
    /// `finalized` is what building the proofs that became complete with
    /// it returned — [`finalize_ready_blobs`]'s failure as data, so the
    /// class of a failure after this landing is chosen here (S49).
    Confirmed {
        /// `Err` carries the redacted detail of the first proof that
        /// could not be built.
        finalized: Result<(), String>,
    },
}

/// Decide what `pay`'s loop does after one awaited sub-batch receipt — the one
/// place S46, S49 and S50 are ruled (D204). Pure: everything it reads is passed
/// in, and its only effect is the capture it may deliver. The count it reports
/// is THIS call's confirmed landings (`txs` is this call's).
///
/// - **Confirmed, proofs built:** capture the receipt-so-far and go on —
///   unless the capture was not durable and sub-batches remain: then stop with
///   [`StorageError::StrandedPayment`], so at most this one sub-batch is paid
///   without a durable record (S46, D198 R2). After the last sub-batch a
///   not-durable capture stops nothing: the caller's post-`pay` write is the
///   second chance (D186 R3). No hook is no verdict.
/// - **Confirmed, a proof failed (S49):** money moved, so capture what exists
///   — the landed quote→tx map, the tx, the gas, and the records of the blobs
///   finalized before the failing one — and THEN strand with the confirmed
///   count, whatever the capture's verdict (the pipeline reads that verdict
///   for its 28/37 split). Capturing before EVERY finalize instead would
///   journal a landing's map without its records, and a resume would re-buy
///   that sub-batch. The failing blob, and every ready blob after it, get no
///   record, so a resume re-buys them (D37 Decision 5's caveat; D204 R2).
/// - **Reverted after a confirmed landing:** capture — the reverted tx is gas
///   evidence beside the landed ones — then strand with the confirmed count.
/// - **Reverted with no confirmed landing in this call (S50):** no ANT moved,
///   so [`StorageError::Payment`] and NO capture: a receipt that maps no quote
///   would read as a payment to every money reader downstream. In a remainder
///   round, the prior round's journaled receipt is left as it was.
#[allow(clippy::too_many_arguments)] // R1's inputs: the outcome, the hook, the receipt-so-far
// `emit_capture` takes, and the loop position; bundling them would move the
// same fields behind a name that explains nothing.
fn settle_sub_batch(
    outcome: SubBatchOutcome,
    hook: Option<&CaptureHook>,
    records: &[Option<BlobPaymentRecord>],
    tx_map: &BTreeMap<QuoteHash, TxHash>,
    txs: &[TxRecord],
    gas_cost_wei: u128,
    batch_index: usize,
    sub_batch_count: usize,
) -> Result<(), StorageError> {
    let landed = txs
        .iter()
        .filter(|t| t.status == TxStatus::Confirmed)
        .count();
    let finalized = match outcome {
        SubBatchOutcome::Reverted if landed == 0 => {
            return Err(StorageError::Payment {
                reason: "the first payment sub-batch transaction reverted on-chain: it moved no \
                         ANT, and the gas it used is spent"
                    .into(),
            });
        }
        SubBatchOutcome::Reverted => {
            emit_capture(hook, records, tx_map, txs, gas_cost_wei);
            return Err(StorageError::StrandedPayment {
                landed_tx_count: landed,
                reason: "a payment sub-batch transaction reverted on-chain".into(),
            });
        }
        SubBatchOutcome::Confirmed { finalized } => finalized,
    };
    let captured = emit_capture(hook, records, tx_map, txs, gas_cost_wei);
    if let Err(detail) = finalized {
        return Err(stranded_or_payment(
            landed,
            format!(
                "proof construction failed after sub-batch {} of {} landed: {detail}",
                batch_index + 1,
                sub_batch_count
            ),
        ));
    }
    if captured == Some(CaptureOutcome::NotDurable) && batch_index + 1 < sub_batch_count {
        return Err(StorageError::StrandedPayment {
            landed_tx_count: landed,
            reason: format!(
                "the receipt-so-far could not be journaled after sub-batch {} of {} landed, so \
                 no further sub-batch was submitted (D37 Decision 2)",
                batch_index + 1,
                sub_batch_count
            ),
        });
    }
    Ok(())
}

/// The zero-transfer pre-pass's proof failure: the pre-pass runs before any
/// sub-batch is submitted, so no ANT moved — [`StorageError::Payment`], the
/// class it had before S49 (D204 R2).
fn pre_pass_proof_failure(detail: String) -> StorageError {
    StorageError::Payment {
        reason: format!("proof construction failed: {detail}"),
    }
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

/// `U256 → u128`, saturating — for balances and for the allowance
/// comparison (comparisons stay correct at saturation: a value above
/// `u128::MAX` becomes `u128::MAX`, which is still greater-or-equal to
/// every representable operand; costs use [`checked_u128`]).
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
///
/// A connect or a fetch is [`StorageError::Network`] whatever upstream
/// reported (S47): `AntCoreReader::connect`'s and `fetch_chunk`'s contracts
/// name no quote or finalize class. The per-context matches have no `_` arm,
/// so a fifth context must decide its own class.
fn map_ant_error(context: ErrContext, error: &AntError) -> StorageError {
    match error {
        // `chunk_get` signals absence via `Ok(None)` (mapped by the
        // caller); an `Error::NotFound` from any operation is therefore a
        // network-shaped surprise, not the typed NotFound.
        AntError::NotFound(detail) => StorageError::Network {
            reason: format!("not found: {detail}"),
        },
        AntError::Payment(_) => match context {
            ErrContext::Connect => StorageError::Network {
                reason: "upstream reported a payment-class error while connecting (detail \
                         redacted: upstream payment errors can embed receipt material)"
                    .into(),
            },
            ErrContext::Get => StorageError::Network {
                reason: "upstream reported a payment-class error while fetching (detail \
                         redacted: upstream payment errors can embed receipt material)"
                    .into(),
            },
            ErrContext::Quote => StorageError::Quote {
                reason: "upstream payment-class error during quoting (detail redacted: \
                         upstream payment errors can embed receipt material)"
                    .into(),
            },
            ErrContext::Finalize => StorageError::Finalize {
                reason: "upstream payment-class error during finalize (detail redacted: \
                         upstream payment errors can embed receipt material)"
                    .into(),
            },
        },
        AntError::AlreadyStored => match context {
            ErrContext::Connect => StorageError::Network {
                reason: "upstream reported already-stored while connecting".into(),
            },
            ErrContext::Get => StorageError::Network {
                reason: "upstream reported already-stored while fetching".into(),
            },
            ErrContext::Quote => StorageError::Quote {
                reason: "upstream reported already-stored outside the quote path".into(),
            },
            ErrContext::Finalize => StorageError::Finalize {
                reason: "upstream reported already-stored where a fresh store was expected".into(),
            },
        },
        other => StorageError::Network {
            reason: format!("{other}"),
        },
    }
}

/// Store one blob's bytes and proof to its ordered PUT targets until
/// `CLOSE_GROUP_MAJORITY` stored — the public-surface replication of
/// upstream's `pub(crate)` close-group PUT, sequential with early exit.
///
/// # A decline is one target's answer (S43, D179)
///
/// Each failed PUT becomes a [`PutReply`] ([`put_reply`]) and the round goes
/// on to the next target — a payment-class decline included — stopping only at
/// a majority of stores or when the targets run out, as upstream's own
/// close-group PUT does (`ant-core-0.5.0/src/data/client/chunk.rs:36-79`). A
/// round that falls short is judged by [`put_policy::verdict`]: the payment's
/// block time is read through `block_time` only when the declines alone made
/// the majority unreachable, and only that, with a payment more than 24 hours
/// old, is [`StorageError::ProofsExpired`]. Every other shortfall is a
/// [`StorageError::Finalize`], which resume answers by finalizing again and
/// paying nothing.
///
/// This used to classify each payment-class reply on its own, by the age of
/// the blob's **oldest quote** — a timestamp the quoting peer writes — and end
/// the round at the first one classified as expired, so one hostile target
/// first in line could abandon six that would have stored (S43's defect).
///
/// # The seam
///
/// `put` is one target's `chunk_put_with_proof`, `block_time` the payment RPC
/// ([`paying_block_time`]) and `now` the clock, so the unit tests drive this
/// loop with the replies the pinned client really produces.
async fn put_to_majority<'t, T, P, PF, B, BF>(
    address: Address,
    receipt: &PaymentReceipt,
    record: &BlobPaymentRecord,
    targets: &'t [T],
    mut put: P,
    mut block_time: B,
    now: impl FnOnce() -> u64,
) -> Result<(), StorageError>
where
    P: FnMut(&'t T) -> PF,
    PF: Future<Output = Result<[u8; 32], AntError>>,
    B: FnMut(PayingTx) -> BF,
    BF: Future<Output = Option<u64>>,
{
    if targets.is_empty() {
        return Err(StorageError::Finalize {
            reason: format!("no PUT targets available for blob at address {address}"),
        });
    }
    let mut tally = PutTally::new(CLOSE_GROUP_MAJORITY);
    let mut last_failure: Option<String> = None;
    for target in targets {
        match put(target).await {
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
                tally.record(PutReply::Stored);
                if tally.majority_stored() {
                    return Ok(());
                }
            }
            Err(error) => {
                let reply = put_reply(&error);
                tally.record(reply);
                // A decline's own text is never kept: upstream payment
                // errors can embed receipt material (module docs).
                if reply == PutReply::Failed {
                    last_failure = Some(failure_detail(&error));
                }
            }
        }
    }

    // The payment's age is read only on the one path where it can matter.
    let paid_at = if tally.declines_are_decisive() {
        let mut block_times = Vec::new();
        for paying in put_policy::paying_txs(receipt, record) {
            block_times.push(block_time(paying).await);
        }
        put_policy::payment_time(&block_times)
    } else {
        None
    };
    match put_policy::verdict(&tally, paid_at, now()) {
        PutVerdict::Stored => Ok(()),
        PutVerdict::ProofsExpired => Err(StorageError::ProofsExpired),
        PutVerdict::Retry => Err(StorageError::Finalize {
            reason: retry_reason(address, &tally, paid_at.is_some(), last_failure.as_deref()),
        }),
    }
}

/// The adapter's half of the PUT verdict (D179 R4): one failed PUT, as the
/// policy reads it. Payment-class — a structured `PaymentFailed`, or
/// `PaymentRequired`, which upstream surfaces as `Error::Payment`
/// (`ant-core-0.5.0/src/data/client/chunk.rs:580-581`) — is a decline; every
/// other failure is a failure. These are the two arms upstream's own
/// `classify_put_failure` calls a price-floor decline (`chunk.rs:64-84`).
fn put_reply(error: &AntError) -> PutReply {
    match error {
        AntError::RemotePut {
            source: ant_protocol::ProtocolError::PaymentFailed(_),
            ..
        }
        | AntError::Payment(_) => PutReply::Declined,
        _ => PutReply::Failed,
    }
}

/// A non-payment PUT failure's text, through [`map_ant_error`]'s hygiene (the
/// one place upstream error text is let through or redacted), without the
/// class prefix the finalize error adds again.
fn failure_detail(error: &AntError) -> String {
    match map_ant_error(ErrContext::Finalize, error) {
        StorageError::Network { reason }
        | StorageError::Finalize { reason }
        | StorageError::Quote { reason } => reason,
        other => other.to_string(),
    }
}

/// The finalize error of a round that fell short without an expired payment —
/// counts and the chunk address only, never a receipt field.
fn retry_reason(
    address: Address,
    tally: &PutTally,
    paid_at_known: bool,
    last_failure: Option<&str>,
) -> String {
    let tried = tally
        .stored()
        .saturating_add(tally.declined())
        .saturating_add(tally.failed());
    if tally.declines_are_decisive() {
        let age = if paid_at_known {
            "the payment is not more than 24 hours old by its block time"
        } else {
            "the payment's block time could not be read"
        };
        format!(
            "{declined} of {tried} storing peers refused the payment proof for the blob at \
             address {address}, but {age}, so it is not treated as expired: finalize again — \
             no new payment is needed",
            declined = tally.declined(),
        )
    } else {
        let last =
            last_failure.map_or_else(String::new, |detail| format!("; last failure: {detail}"));
        format!(
            "stored to {stored} of the required {majority} peers for blob at address {address} \
             ({declined} declined the payment proof, {failed} failed{last}); finalize again — \
             no new payment is needed",
            stored = tally.stored(),
            majority = tally.majority(),
            declined = tally.declined(),
            failed = tally.failed(),
        )
    }
}

/// The block timestamp of one transaction that paid for a blob, read over the
/// payment RPC this session already holds (D179 R3): the journaled block
/// number when the receipt has one, else the chain's transaction receipt;
/// then that block's header.
///
/// `None` on any failure — an RPC error, a receipt or block the RPC does not
/// show, a block it cannot parse. The policy reads `None` as **not** expired,
/// so a failed read costs a retry and never a payment.
async fn paying_block_time(provider: &DynProvider, paying: PayingTx) -> Option<u64> {
    let block_number = match paying.block_number {
        Some(number) => number,
        None => {
            let hash = alloy::primitives::B256::from(*paying.tx_hash.as_bytes());
            provider
                .get_transaction_receipt(hash)
                .await
                .ok()??
                .block_number?
        }
    };
    let block = provider
        .get_block_by_number(alloy::rpc::types::BlockNumberOrTag::Number(block_number))
        .await
        .ok()??;
    Some(block.header.timestamp)
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

    /// Upstream's absence rule, restated as a table (`is_authoritative_
    /// absence` mirrors a private ant-core function, so this is the pin an
    /// S20 bump re-reads it against).
    #[test]
    fn absence_needs_a_unanimous_majority_sized_sample() {
        assert_eq!(
            CLOSE_GROUP_MAJORITY, 4,
            "the replica count this table was written against"
        );
        for (not_found, queried, absent) in [
            (0, 0, false), // nobody could be asked: an unreachable network
            (1, 1, false), // a thin lookup
            (3, 3, false), // unanimous, but below the replica count
            (4, 4, true),
            (7, 7, true),
            (4, 5, false), // one peer gave no usable answer — it may hold a replica
            (6, 7, false),
            (0, 7, false),
        ] {
            assert_eq!(
                is_authoritative_absence(not_found, queried),
                absent,
                "{not_found} not-found of {queried} queried"
            );
        }
    }

    /// The sweep classifier: a served chunk wins wherever it sits, absence
    /// only by the rule above, and every other shape — including a sweep with
    /// no peers at all — establishes nothing.
    #[test]
    fn a_sweep_that_established_nothing_is_never_absence() {
        use PeerAnswer::{Failed, NotFound, Served};

        assert_eq!(
            classify_sweep(Vec::new()),
            SweepVerdict::Unestablished {
                queried: 0,
                not_found: 0
            }
        );
        assert_eq!(
            classify_sweep((0..7).map(|_| Failed)),
            SweepVerdict::Unestablished {
                queried: 7,
                not_found: 0
            }
        );
        assert_eq!(
            classify_sweep((0..6).map(|_| NotFound).chain([Failed])),
            SweepVerdict::Unestablished {
                queried: 7,
                not_found: 6
            }
        );
        assert_eq!(
            classify_sweep((0..3).map(|_| NotFound)),
            SweepVerdict::Unestablished {
                queried: 3,
                not_found: 3
            }
        );
        assert_eq!(
            classify_sweep((0..7).map(|_| NotFound)),
            SweepVerdict::Absent
        );
        let chunk = Bytes::from_static(b"served during the sweep");
        assert_eq!(
            classify_sweep([NotFound, Failed, Served(chunk.clone()), NotFound]),
            SweepVerdict::Served(chunk)
        );
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

    // ── D173 §2 R8–R10: the gate and the transport mode ───────────────────

    fn with_peers(base: NetworkConfig, peers: &[&str]) -> NetworkConfig {
        NetworkConfig {
            bootstrap: peers
                .iter()
                .map(|text| {
                    text.parse()
                        .unwrap_or_else(|_| panic!("fixture {text:?} is not a socket address"))
                })
                .collect(),
            ..base
        }
    }

    /// A `devnet` configuration whose chain half is inert data: nothing here
    /// dials, so none of it has to answer.
    fn devnet_base() -> NetworkConfig {
        NetworkConfig {
            id: crate::network::NetworkId::Devnet,
            evm_chain_id: 31_337,
            rpc_url: "http://127.0.0.1:1/".to_owned(),
            ..NetworkConfig::arbitrum_sepolia()
        }
    }

    /// `allow_loopback` comes from the peers, never the network id (D173 §2
    /// R8) — including the two cases the id rule got wrong: a Sepolia devnet's
    /// loopback peers under `arbitrum-sepolia` (D174 §2 R5), and a LAN devnet
    /// (the recorded behaviour change).
    #[test]
    fn client_config_derives_loopback_from_the_peers_never_the_network_id() {
        let admitted = [
            (
                "a Sepolia devnet's loopback peers",
                with_peers(
                    NetworkConfig::arbitrum_sepolia(),
                    &["127.0.0.1:20001", "127.0.0.1:20002"],
                ),
                true,
            ),
            (
                "a local devnet's loopback peers",
                with_peers(devnet_base(), &["127.0.0.1:20001", "[::1]:20002"]),
                true,
            ),
            (
                "a LAN devnet's non-loopback peers",
                with_peers(devnet_base(), &["192.168.1.20:20001"]),
                false,
            ),
            (
                "arbitrum-one's non-loopback peers",
                with_peers(NetworkConfig::arbitrum_one(), &["192.0.2.1:10000"]),
                false,
            ),
        ];
        for (label, config, expected) in admitted {
            let built = client_config(&config).unwrap_or_else(|refusal| {
                panic!("{label} must get a transport mode, got a refusal: {refusal}")
            });
            assert_eq!(
                built.allow_loopback, expected,
                "{label} are dialable only with allow_loopback = {expected}"
            );
        }

        let refused = [
            ("an empty set", with_peers(devnet_base(), &[])),
            (
                "a mixed set",
                with_peers(devnet_base(), &["127.0.0.1:20001", "192.0.2.1:10000"]),
            ),
            (
                "a repeated peer",
                with_peers(devnet_base(), &["127.0.0.1:20001", "127.0.0.1:20001"]),
            ),
            (
                "loopback peers under arbitrum-one",
                with_peers(NetworkConfig::arbitrum_one(), &["127.0.0.1:20001"]),
            ),
        ];
        for (label, config) in refused {
            match client_config(&config) {
                Err(StorageError::Network { reason }) => assert!(
                    reason.starts_with("refusing to connect over the"),
                    "{label}: {reason}"
                ),
                Err(other) => panic!("{label} was refused in the wrong class: {other:?}"),
                Ok(built) => panic!(
                    "{label} must be refused before Client::connect; it got allow_loopback = {}",
                    built.allow_loopback
                ),
            }
        }
    }

    /// The adapter reports the storage gate in the network class, with the
    /// refusal sentence first — armed here by the compiler (`cfg(test)`).
    #[test]
    fn the_storage_gate_is_reported_in_the_network_class() {
        match consult_storage_gate(&with_peers(devnet_base(), &["192.0.2.1:9"])) {
            Err(StorageError::Network { reason }) => assert!(
                reason.starts_with(storage_gate::REFUSAL),
                "the reason must begin with the refusal sentence: {reason}"
            ),
            other => {
                panic!(
                    "a public peer must be refused by the armed gate in the network class: {other:?}"
                )
            }
        }
        assert_eq!(
            consult_storage_gate(&with_peers(devnet_base(), &["127.0.0.1:9"])),
            Ok(())
        );
        assert_eq!(
            consult_storage_gate(&with_peers(devnet_base(), &[])),
            Ok(())
        );
    }

    /// **S43 (D179), the adapter seam.** [`put_to_majority`] driven with the
    /// replies the pinned client really produces — `AntError` values built
    /// from upstream's public enum, in the shapes `chunk_put_with_proof`
    /// returns them (`ant-core-0.5.0/src/data/client/chunk.rs:580-597`) — and
    /// the payment RPC and the clock injected.
    ///
    /// Every blob here has quotes stamped **72 hours** ago: the quoting
    /// peers' own field, which S43's defect read as the payment's age. The
    /// block time the injected RPC reports is what the rows vary.
    mod s43_seam {
        use std::collections::BTreeMap;

        use super::super::*;
        use crate::put_policy::PayingTx;
        use crate::test_util::block_on;

        const NOW: u64 = 1_900_000_000;
        const HOUR: u64 = 60 * 60;
        const ADDRESS: [u8; 32] = [0x5A; 32];
        const PAYING_TX: [u8; 32] = [0x7E; 32];
        const PAYING_BLOCK: u64 = 4_242;

        /// One target's answer, as a test spells it.
        #[derive(Debug, Clone, Copy)]
        enum Reply {
            /// `ChunkPutResponse::Success`.
            Store,
            /// `ChunkPutResponse::PaymentRequired`, which upstream surfaces as
            /// `Error::Payment` (`chunk.rs:580-581`).
            PaymentRequired,
            /// A structured `PaymentFailed` rejection (`chunk.rs:582-592`).
            PaymentFailed,
            /// The peer could not be reached at all.
            Dial,
        }

        /// The upstream value a target's reply is, built afresh per call
        /// (`AntError` is not `Clone`).
        fn upstream(reply: Reply) -> Result<[u8; 32], AntError> {
            match reply {
                Reply::Store => Ok(ADDRESS),
                Reply::PaymentRequired => Err(AntError::Payment(
                    "Payment required: the paid quote's issuer is unknown here".into(),
                )),
                Reply::PaymentFailed => Err(AntError::RemotePut {
                    address: "5a".repeat(32),
                    source: ant_protocol::ProtocolError::PaymentFailed(
                        "the proof's issuers are not close enough".into(),
                    ),
                }),
                Reply::Dial => Err(AntError::Network(
                    "Failed to send PUT to peer: no route".into(),
                )),
            }
        }

        /// A journaled receipt for one blob: one non-zero line, paid by one
        /// transaction at [`PAYING_BLOCK`], and seven quotes stamped 72 h ago.
        fn paid_blob() -> (PaymentReceipt, BlobPaymentRecord) {
            let quote_hash = QuoteHash::from_bytes([0xA1; 32]);
            let quote = |byte: u8| PeerQuote {
                peer_id: EncodedPeerId::from_bytes([byte; 32]),
                quote: QuotePreimage {
                    content: Address::from_bytes(ADDRESS),
                    timestamp_unix_secs: NOW - 72 * HOUR,
                    price_atto: 100,
                    rewards_address: RewardsAddress::from_bytes([byte; 20]),
                    node_pub_key: vec![byte; 4],
                    node_signature: vec![byte; 4],
                    committed_key_count: 0,
                    commitment_pin: None,
                },
            };
            let record = BlobPaymentRecord {
                address: Address::from_bytes(ADDRESS),
                payments: vec![
                    QuotePaymentEntry {
                        quote_hash,
                        rewards_address: RewardsAddress::from_bytes([0x01; 20]),
                        amount_atto: 300,
                        price_atto: 100,
                    },
                    QuotePaymentEntry {
                        quote_hash: QuoteHash::from_bytes([0xA2; 32]),
                        rewards_address: RewardsAddress::from_bytes([0x02; 20]),
                        amount_atto: 0,
                        price_atto: 100,
                    },
                ],
                peer_quotes: (1..=7).map(quote).collect(),
                commitment_sidecars: Vec::new(),
                proof_bytes: vec![0x01, 0x02],
            };
            let receipt = PaymentReceipt {
                blobs: vec![record.clone()],
                tx_map: BTreeMap::from([(quote_hash, TxHash::from_bytes(PAYING_TX))]),
                txs: vec![TxRecord {
                    tx_hash: TxHash::from_bytes(PAYING_TX),
                    block_number: Some(PAYING_BLOCK),
                    status: TxStatus::Confirmed,
                    quote_hashes: vec![quote_hash],
                }],
                storage_cost_atto: 300,
                gas: GasSummary { gas_cost_wei: 0 },
            };
            (receipt, record)
        }

        /// What one round did: its result, how many targets were sent the
        /// chunk, and which paying transactions the RPC was asked about.
        struct Round {
            outcome: Result<(), StorageError>,
            puts: usize,
            asked: Vec<PayingTx>,
        }

        /// Run [`put_to_majority`] over `targets`, with the RPC answering
        /// `block_time` for the paying block.
        fn round(targets: &[Reply], block_time: Option<u64>) -> Round {
            let (receipt, record) = paid_blob();
            let mut puts = 0usize;
            let mut asked = Vec::new();
            let outcome = block_on(put_to_majority(
                Address::from_bytes(ADDRESS),
                &receipt,
                &record,
                targets,
                |reply: &Reply| {
                    puts += 1;
                    let answer = upstream(*reply);
                    async move { answer }
                },
                |paying: PayingTx| {
                    asked.push(paying);
                    async move { block_time }
                },
                || NOW,
            ));
            Round {
                outcome,
                puts,
                asked,
            }
        }

        fn the_paying_tx() -> PayingTx {
            PayingTx {
                tx_hash: TxHash::from_bytes(PAYING_TX),
                block_number: Some(PAYING_BLOCK),
            }
        }

        /// **S43 Accept 1 (B1).** One peer with an old timestamp declines on
        /// payment grounds, first in line; the six behind it would store. The
        /// round must store at the fourth store — five PUTs — never yield
        /// `ProofsExpired`, and never even ask the chain how old the payment
        /// is. Both decline shapes upstream produces.
        #[test]
        fn s43_b1_one_hostile_decline_is_one_targets_answer_not_an_expired_payment() {
            for decline in [Reply::PaymentRequired, Reply::PaymentFailed] {
                let mut targets = vec![decline];
                targets.extend([Reply::Store; 6]);
                let run = round(&targets, Some(NOW - HOUR));
                if let Err(error) = &run.outcome {
                    panic!(
                        "one hostile decline ({decline:?}) aborted the PUT as {error:?} after {} \
                         of 7 targets (S43)",
                        run.puts
                    );
                }
                assert_eq!(
                    run.puts, 5,
                    "one decline, then the four stores a majority needs ({decline:?})"
                );
                assert!(
                    run.asked.is_empty(),
                    "a round that stored never asks the payment's age: {:?}",
                    run.asked
                );
            }
        }

        /// **S43 B2.** Every target declines, but the payment is an hour old
        /// by its block time: a retryable finalize, never `ProofsExpired` —
        /// the quotes' 72-hour-old stamps are not an input.
        #[test]
        fn s43_b2_a_declining_majority_over_a_young_payment_is_a_retry() {
            let targets = [
                Reply::PaymentRequired,
                Reply::PaymentFailed,
                Reply::PaymentRequired,
                Reply::PaymentFailed,
                Reply::PaymentRequired,
                Reply::PaymentFailed,
                Reply::PaymentRequired,
            ];
            let run = round(&targets, Some(NOW - HOUR));
            match &run.outcome {
                Err(StorageError::Finalize { reason }) => assert!(
                    reason.contains("7 of 7")
                        && reason.contains("not more than 24 hours old")
                        && !reason.contains("issuer"),
                    "the retry names the declines and the payment's age, and no decline's own \
                     text (it can embed receipt material): {reason}"
                ),
                other => panic!("a hostile majority expired a payment at 1 h chain age: {other:?}"),
            }
            assert_eq!(run.puts, 7, "every target is tried");
            assert_eq!(
                run.asked,
                [the_paying_tx()],
                "the chain is asked once, about the blob's paying transaction"
            );
        }

        /// **S43 B3.** Two declines and five unreachable peers, payment a day
        /// and an hour old: the declines did not make the majority
        /// unreachable, so this is a retry — and the payment's age is never
        /// read.
        #[test]
        fn s43_b3_declines_that_are_not_decisive_are_a_retry() {
            // The last reply is a decline, so a loop that kept "the last error"
            // would carry a decline's text where the dial failure's belongs.
            let targets = [
                Reply::Dial,
                Reply::PaymentRequired,
                Reply::Dial,
                Reply::Dial,
                Reply::Dial,
                Reply::Dial,
                Reply::PaymentFailed,
            ];
            let run = round(&targets, Some(NOW - 25 * HOUR));
            match &run.outcome {
                Err(StorageError::Finalize { reason }) => assert!(
                    reason.contains("stored to 0 of the required 4")
                        && reason.contains("2 declined")
                        && reason.contains("5 failed")
                        && reason.contains("Failed to send PUT to peer")
                        && !reason.contains("issuer"),
                    "the retry names the tally and the last non-payment failure, never a \
                     decline's own text: {reason}"
                ),
                other => panic!("declines not decisive, yet {other:?}"),
            }
            assert_eq!(run.puts, 7);
            assert!(
                run.asked.is_empty(),
                "the age is read only when the declines are decisive: {:?}",
                run.asked
            );
        }

        /// **S43 B4, the positive row.** Four declines and three stores, the
        /// payment a day and an hour old by its block time: `ProofsExpired`.
        #[test]
        fn s43_b4_a_declining_majority_over_an_old_payment_is_proofs_expired() {
            let targets = [
                Reply::Store,
                Reply::PaymentRequired,
                Reply::Store,
                Reply::PaymentFailed,
                Reply::PaymentRequired,
                Reply::Store,
                Reply::PaymentFailed,
            ];
            let run = round(&targets, Some(NOW - 25 * HOUR));
            assert_eq!(run.outcome, Err(StorageError::ProofsExpired));
            assert_eq!(run.puts, 7);
            assert_eq!(run.asked, [the_paying_tx()]);
        }

        /// **S43 B5.** Every target declines and the RPC cannot say when the
        /// payment was made: a retry, never a payment.
        #[test]
        fn s43_b5_an_unreadable_block_time_is_a_retry() {
            let run = round(&[Reply::PaymentRequired; 7], None);
            match &run.outcome {
                Err(StorageError::Finalize { reason }) => assert!(
                    reason.contains("could not be read"),
                    "the retry says the payment's age is unknown: {reason}"
                ),
                other => panic!("unreadable block time re-pays: {other:?}"),
            }
            assert_eq!(run.asked, [the_paying_tx()]);
        }

        /// The address re-check still holds inside the round (D32): a target
        /// naming another address ends it, whatever came before.
        #[test]
        fn s43_a_store_under_another_address_is_still_a_divergence() {
            let (receipt, record) = paid_blob();
            let outcome = block_on(put_to_majority(
                Address::from_bytes(ADDRESS),
                &receipt,
                &record,
                &[0u8],
                |_| async { Ok::<[u8; 32], AntError>([0x00; 32]) },
                |_| async { Some(NOW) },
                || NOW,
            ));
            match outcome {
                Err(StorageError::Finalize { reason }) => {
                    assert!(reason.contains("address-rule divergence"), "{reason}");
                }
                other => panic!("a divergent address must end the round: {other:?}"),
            }
        }
    }

    /// **S43 (D179 R3), the block-time read.** [`paying_block_time`] over the
    /// same key-less provider type the payer's RPC rides, against a loopback
    /// JSON-RPC stub that serves an Arbitrum-shaped block (its extra
    /// `l1BlockNumber`, `sendCount` and `sendRoot` fields included) and an
    /// Arbitrum-shaped transaction receipt. Nothing here leaves loopback.
    mod s43_block_time {
        use std::io::{Read, Write};
        use std::net::{SocketAddr, TcpListener, TcpStream};
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::{Arc, Mutex};
        use std::thread::JoinHandle;
        use std::time::Duration;

        use super::super::*;
        use crate::put_policy::PayingTx;

        const BLOCK: u64 = 0x1092;
        const BLOCK_TIMESTAMP: u64 = 0x6553_f100;
        const TX: [u8; 32] = [0x7E; 32];

        fn hex32(byte: u8) -> String {
            format!("0x{}", format!("{byte:02x}").repeat(32))
        }

        /// A block as Arbitrum One's RPC shapes it; the values are synthetic.
        fn arbitrum_block() -> serde_json::Value {
            serde_json::json!({
                "baseFeePerGas": "0x989680",
                "difficulty": "0x1",
                "extraData": hex32(0x11),
                "gasLimit": "0x4000000000000",
                "gasUsed": "0x1a8f4",
                "hash": hex32(0x22),
                "l1BlockNumber": "0x1438b2c",
                "logsBloom": format!("0x{}", "00".repeat(256)),
                "miner": "0xa4b000000000000000000073657175656e636572",
                "mixHash": hex32(0x33),
                "nonce": "0x00000000001d4d4a",
                "number": format!("{BLOCK:#x}"),
                "parentHash": hex32(0x44),
                "receiptsRoot": hex32(0x55),
                "sendCount": "0x1d4d4a",
                "sendRoot": hex32(0x66),
                "sha3Uncles": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
                "size": "0x30f",
                "stateRoot": hex32(0x77),
                "timestamp": format!("{BLOCK_TIMESTAMP:#x}"),
                "totalDifficulty": "0x1092",
                "transactions": [hex32(0x7e)],
                "transactionsRoot": hex32(0x88),
                "uncles": []
            })
        }

        /// A transaction receipt as Arbitrum One's RPC shapes it.
        fn arbitrum_receipt() -> serde_json::Value {
            serde_json::json!({
                "blockHash": hex32(0x22),
                "blockNumber": format!("{BLOCK:#x}"),
                "contractAddress": null,
                "cumulativeGasUsed": "0x1a8f4",
                "effectiveGasPrice": "0x989680",
                "from": "0x1111111111111111111111111111111111111111",
                "gasUsed": "0x1a8f4",
                "gasUsedForL1": "0x2f1",
                "l1BlockNumber": "0x1438b2c",
                "logs": [],
                "logsBloom": format!("0x{}", "00".repeat(256)),
                "status": "0x1",
                "to": "0x9a3ecac693b699fc0b2b6a50b5549e50c2320a26",
                "transactionHash": hex32(0x7e),
                "transactionIndex": "0x1",
                "type": "0x2"
            })
        }

        /// What the stub answers.
        #[derive(Clone, Copy)]
        enum Serve {
            /// The block and the receipt above.
            Arbitrum,
            /// `null` for everything: the RPC does not show them.
            Nothing,
        }

        /// A loopback JSON-RPC stub that records each method it is asked.
        struct Stub {
            address: SocketAddr,
            methods: Arc<Mutex<Vec<(String, serde_json::Value)>>>,
            stop: Arc<AtomicBool>,
            thread: Option<JoinHandle<()>>,
        }

        impl Stub {
            fn start(serve: Serve) -> Self {
                let listener = TcpListener::bind("127.0.0.1:0").expect("bind a loopback listener");
                let address = listener.local_addr().expect("the listener's address");
                let methods = Arc::new(Mutex::new(Vec::new()));
                let stop = Arc::new(AtomicBool::new(false));
                let thread = {
                    let methods = Arc::clone(&methods);
                    let stop = Arc::clone(&stop);
                    std::thread::spawn(move || {
                        for stream in listener.incoming() {
                            if stop.load(Ordering::SeqCst) {
                                break;
                            }
                            if let Ok(mut stream) = stream {
                                drop(answer(&mut stream, serve, &methods));
                            }
                        }
                    })
                };
                Self {
                    address,
                    methods,
                    stop,
                    thread: Some(thread),
                }
            }

            fn provider(&self) -> DynProvider {
                let url: url::Url = format!("http://{}/", self.address)
                    .parse()
                    .expect("a loopback URL parses");
                http_provider(url).erased()
            }

            fn methods(&self) -> Vec<(String, serde_json::Value)> {
                match self.methods.lock() {
                    Ok(methods) => methods.clone(),
                    Err(poisoned) => poisoned.into_inner().clone(),
                }
            }
        }

        impl Drop for Stub {
            fn drop(&mut self) {
                self.stop.store(true, Ordering::SeqCst);
                drop(TcpStream::connect(self.address));
                if let Some(thread) = self.thread.take() {
                    drop(thread.join());
                }
            }
        }

        fn answer(
            stream: &mut TcpStream,
            serve: Serve,
            methods: &Mutex<Vec<(String, serde_json::Value)>>,
        ) -> std::io::Result<()> {
            stream.set_read_timeout(Some(Duration::from_secs(5)))?;
            let mut buffer = Vec::new();
            let mut chunk = [0u8; 4096];
            let header_end = loop {
                let read = stream.read(&mut chunk)?;
                if read == 0 {
                    return Ok(());
                }
                buffer.extend_from_slice(&chunk[..read]);
                if let Some(at) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
                    break at + 4;
                }
            };
            let head = String::from_utf8_lossy(&buffer[..header_end]).to_ascii_lowercase();
            let length = head
                .lines()
                .find_map(|line| line.strip_prefix("content-length:"))
                .and_then(|value| value.trim().parse::<usize>().ok())
                .unwrap_or(0);
            while buffer.len() < header_end + length {
                let read = stream.read(&mut chunk)?;
                if read == 0 {
                    break;
                }
                buffer.extend_from_slice(&chunk[..read]);
            }
            let body_end = (header_end + length).min(buffer.len());
            let request: serde_json::Value =
                serde_json::from_slice(&buffer[header_end..body_end]).unwrap_or_default();
            let method = request["method"].as_str().unwrap_or_default().to_owned();
            let result = match (serve, method.as_str()) {
                (Serve::Arbitrum, "eth_getBlockByNumber") => arbitrum_block(),
                (Serve::Arbitrum, "eth_getTransactionReceipt") => arbitrum_receipt(),
                _ => serde_json::Value::Null,
            };
            match methods.lock() {
                Ok(mut seen) => seen.push((method, request["params"].clone())),
                Err(poisoned) => poisoned
                    .into_inner()
                    .push((method, request["params"].clone())),
            }
            let reply = serde_json::json!({
                "jsonrpc": "2.0",
                "id": request["id"].clone(),
                "result": result,
            })
            .to_string();
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
                 Connection: close\r\n\r\n{reply}",
                reply.len()
            )?;
            stream.flush()
        }

        /// The journaled block number is used as it is: one call, the block.
        #[tokio::test(flavor = "multi_thread")]
        async fn s43_the_paying_block_time_is_the_blocks_own_timestamp() {
            let stub = Stub::start(Serve::Arbitrum);
            let time = paying_block_time(
                &stub.provider(),
                PayingTx {
                    tx_hash: TxHash::from_bytes(TX),
                    block_number: Some(BLOCK),
                },
            )
            .await;
            assert_eq!(time, Some(BLOCK_TIMESTAMP));
            let methods = stub.methods();
            assert_eq!(methods.len(), 1, "{methods:?}");
            assert_eq!(methods[0].0, "eth_getBlockByNumber");
            assert_eq!(methods[0].1[0], serde_json::json!(format!("{BLOCK:#x}")));
        }

        /// A journal-first record with no block number: the chain's receipt
        /// supplies it, then the block its time.
        #[tokio::test(flavor = "multi_thread")]
        async fn s43_an_unknown_block_number_is_read_from_the_chains_receipt() {
            let stub = Stub::start(Serve::Arbitrum);
            let time = paying_block_time(
                &stub.provider(),
                PayingTx {
                    tx_hash: TxHash::from_bytes(TX),
                    block_number: None,
                },
            )
            .await;
            assert_eq!(time, Some(BLOCK_TIMESTAMP));
            let asked: Vec<String> = stub
                .methods()
                .into_iter()
                .map(|(method, _)| method)
                .collect();
            assert_eq!(asked, ["eth_getTransactionReceipt", "eth_getBlockByNumber"]);
        }

        /// An RPC that shows neither the receipt nor the block, and one that
        /// is not there at all: no time — which the policy reads as not
        /// expired.
        #[tokio::test(flavor = "multi_thread")]
        async fn s43_a_time_the_rpc_cannot_give_is_none() {
            let stub = Stub::start(Serve::Nothing);
            for block_number in [Some(BLOCK), None] {
                let paying = PayingTx {
                    tx_hash: TxHash::from_bytes(TX),
                    block_number,
                };
                assert_eq!(paying_block_time(&stub.provider(), paying).await, None);
            }
            let dead = {
                let listener =
                    TcpListener::bind("127.0.0.1:0").expect("bind a loopback probe listener");
                listener.local_addr().expect("the probe's address")
            };
            let url: url::Url = format!("http://{dead}/")
                .parse()
                .expect("a loopback URL parses");
            let provider = http_provider(url).erased();
            let paying = PayingTx {
                tx_hash: TxHash::from_bytes(TX),
                block_number: Some(BLOCK),
            };
            assert_eq!(paying_block_time(&provider, paying).await, None);
        }
    }

    // ── S47: a connect or a fetch is the network class ─────────────────────

    /// The payment-class error S47's tests feed `map_ant_error`: upstream
    /// embeds quote-hash hex in some payment errors (`batch.rs:300-305`), so
    /// its detail must never reach the mapped text.
    fn s47_leaky_payment_error() -> AntError {
        AntError::Payment("Missing tx hash for quote deadbeefcafebabe".into())
    }

    /// **S47: a connect or a fetch is [`StorageError::Network`] whatever
    /// upstream reported.** `AntCoreReader::connect`'s and `fetch_chunk`'s
    /// contracts name only the network class (and, for a fetch, the typed
    /// absence), so a payment-class or already-stored error from either is a
    /// network failure — never a quote failure, which `degrade` would render
    /// after *"no connection to the Autonomi network was made"* and
    /// `verify --live` would file as a backend refusal. The payment detail
    /// stays redacted. All four combinations are mapped before the verdict,
    /// so a red names every one that is wrong.
    #[test]
    fn s47_a_connect_or_fetch_time_payment_or_already_stored_error_is_a_network_failure() {
        let cases = [
            (
                "Connect + Payment",
                map_ant_error(ErrContext::Connect, &s47_leaky_payment_error()),
                "upstream reported a payment-class error while connecting (detail redacted: \
                 upstream payment errors can embed receipt material)",
            ),
            (
                "Connect + AlreadyStored",
                map_ant_error(ErrContext::Connect, &AntError::AlreadyStored),
                "upstream reported already-stored while connecting",
            ),
            (
                "Get + Payment",
                map_ant_error(ErrContext::Get, &s47_leaky_payment_error()),
                "upstream reported a payment-class error while fetching (detail redacted: \
                 upstream payment errors can embed receipt material)",
            ),
            (
                "Get + AlreadyStored",
                map_ant_error(ErrContext::Get, &AntError::AlreadyStored),
                "upstream reported already-stored while fetching",
            ),
        ];
        assert_eq!(cases.len(), 4, "two contexts, two upstream variants");
        let mut wrong = Vec::new();
        for (case, mapped, reason) in &cases {
            let rendered = mapped.to_string();
            assert!(
                !rendered.contains("deadbeef"),
                "{case}: payment detail leaked: {rendered}"
            );
            match mapped {
                StorageError::Network { reason: got } if got == reason => {}
                StorageError::Network { reason: got } => {
                    wrong.push(format!("{case}: Network, but the reason is {got:?}"));
                }
                other => wrong.push(format!("{case}: expected Network, got {other:?}")),
            }
        }
        assert!(
            wrong.is_empty(),
            "{} of {} connect/fetch-time errors are not the network class with S47's words:\n{}",
            wrong.len(),
            cases.len(),
            wrong.join("\n")
        );
    }

    /// **S47's unchanged half:** a quote and a finalize keep their own
    /// classes for a payment-class or already-stored error, and their texts
    /// byte for byte.
    #[test]
    fn s47_a_quote_or_finalize_time_payment_or_already_stored_error_keeps_its_class() {
        let cases = [
            (
                "Quote + Payment",
                map_ant_error(ErrContext::Quote, &s47_leaky_payment_error()),
                StorageError::Quote {
                    reason: "upstream payment-class error during quoting (detail redacted: \
                             upstream payment errors can embed receipt material)"
                        .into(),
                },
            ),
            (
                "Quote + AlreadyStored",
                map_ant_error(ErrContext::Quote, &AntError::AlreadyStored),
                StorageError::Quote {
                    reason: "upstream reported already-stored outside the quote path".into(),
                },
            ),
            (
                "Finalize + Payment",
                map_ant_error(ErrContext::Finalize, &s47_leaky_payment_error()),
                StorageError::Finalize {
                    reason: "upstream payment-class error during finalize (detail redacted: \
                             upstream payment errors can embed receipt material)"
                        .into(),
                },
            ),
            (
                "Finalize + AlreadyStored",
                map_ant_error(ErrContext::Finalize, &AntError::AlreadyStored),
                StorageError::Finalize {
                    reason: "upstream reported already-stored where a fresh store was expected"
                        .into(),
                },
            ),
        ];
        assert_eq!(cases.len(), 4, "two contexts, two upstream variants");
        for (case, mapped, expected) in cases {
            assert!(
                !mapped.to_string().contains("deadbeef"),
                "{case}: payment detail leaked: {mapped}"
            );
            assert_eq!(mapped, expected, "{case}: byte-unchanged by S47");
        }
    }

    // ── S49 + S50 (D204): what the loop does after each awaited receipt ────

    /// **D204's seam, driven directly.** No in-crate test can reach `pay()`'s
    /// loop — an [`AntCoreBackend`] needs a live `Client` — so the decision
    /// taken after each awaited sub-batch receipt is the pure
    /// [`settle_sub_batch`], and these rows drive it. The S49 rows also drive
    /// the real [`finalize_ready_blobs`] over upstream's own
    /// `finalize_batch_payment`. The devnet S46 rows
    /// (`tests/devnet_backend.rs`) are the witness that the loop calls it.
    mod s49_s50_settle {
        use std::collections::{BTreeMap, HashMap};
        use std::sync::{Arc, Mutex};

        use super::super::*;

        /// The gas the receipt-so-far carries (any non-zero figure).
        const GAS_WEI: u128 = 21_000_000;
        /// Each fixture blob's one non-zero line: the median quote's price,
        /// paid 3× (upstream's single-node rule).
        const AMOUNT_ATTO: u128 = 300;
        const PRICE_ATTO: u128 = 100;

        type Seen = Arc<Mutex<Vec<PaymentReceipt>>>;

        /// A capture hook that keeps every receipt it is handed and answers
        /// `verdict`.
        fn recording_hook(verdict: CaptureOutcome) -> (CaptureHook, Seen) {
            let seen: Seen = Arc::new(Mutex::new(Vec::new()));
            let sink = Arc::clone(&seen);
            let hook: CaptureHook = Arc::new(move |receipt: &PaymentReceipt| {
                sink.lock()
                    .expect("capture sink lock")
                    .push(receipt.clone());
                verdict
            });
            (hook, seen)
        }

        fn captures(seen: &Seen) -> Vec<PaymentReceipt> {
            seen.lock().expect("capture sink lock").clone()
        }

        fn quote(byte: u8) -> QuoteHash {
            QuoteHash::from_bytes([byte; 32])
        }

        /// One sub-batch tx record, paying quote `paid`.
        fn tx(byte: u8, paid: u8, status: TxStatus) -> TxRecord {
            TxRecord {
                tx_hash: TxHash::from_bytes([byte; 32]),
                block_number: Some(u64::from(byte)),
                status,
                quote_hashes: vec![quote(paid)],
            }
        }

        /// A priced blob whose one non-zero line pays quote `byte`, staged the
        /// way `pay` holds it: our line beside upstream's `PreparedChunk`, in
        /// the shape upstream's own `batch.rs` tests build (no peers).
        fn priced(slot: usize, byte: u8) -> PricedBlobSlot {
            let entry = QuotePaymentEntry {
                quote_hash: quote(byte),
                rewards_address: RewardsAddress::from_bytes([byte; 20]),
                amount_atto: AMOUNT_ATTO,
                price_atto: PRICE_ATTO,
            };
            let prepared = PreparedChunk {
                content: Bytes::from(vec![byte; 32]),
                address: [byte; 32],
                quoted_peers: Vec::new(),
                payment: ant_core::data::client::batch::SingleNodeQuotePayment {
                    quotes: vec![ant_protocol::payment::QuotePaymentInfo {
                        quote_hash: ant_protocol::evm::QuoteHash::from(
                            *entry.quote_hash.as_bytes(),
                        ),
                        rewards_address: ant_protocol::evm::RewardsAddress::from(
                            *entry.rewards_address.as_bytes(),
                        ),
                        amount: Amount::from(AMOUNT_ATTO),
                        price: Amount::from(PRICE_ATTO),
                    }],
                },
                peer_quotes: Vec::new(),
                commitment_sidecars: Vec::new(),
            };
            assert!(
                payment_lines_match(std::slice::from_ref(&entry), &prepared),
                "fixture: the line is its staged quote's (D36)"
            );
            PricedBlobSlot {
                slot,
                address: Address::from_bytes([byte; 32]),
                prepared,
                entries: vec![entry],
                peer_quotes: Vec::new(),
                commitment_sidecars: Vec::new(),
            }
        }

        /// What `pay` holds when it calls the seam.
        struct SoFar {
            records: Vec<Option<BlobPaymentRecord>>,
            tx_map: BTreeMap<QuoteHash, TxHash>,
            txs: Vec<TxRecord>,
        }

        /// `pay`'s state after the first `landed` of `blobs` one-blob
        /// sub-batches landed (blob i: quote `0xA0 + i`, paid by tx
        /// `0x70 + i`), each proof built by the real [`finalize_ready_blobs`].
        fn after_landings(blobs: usize, landed: usize) -> SoFar {
            let byte = |i: usize| u8::try_from(i).expect("a handful of fixture blobs");
            let mut remaining: Vec<Option<PricedBlobSlot>> = (0..blobs)
                .map(|i| Some(priced(i, 0xA0 + byte(i))))
                .collect();
            let ready_after: Vec<usize> = (0..blobs).collect();
            let mut records: Vec<Option<BlobPaymentRecord>> = vec![None; blobs];
            let mut tx_map = BTreeMap::new();
            let mut txs = Vec::new();
            let mut staged = HashMap::new();
            for i in 0..landed {
                txs.push(tx(0x70 + byte(i), 0xA0 + byte(i), TxStatus::Confirmed));
                tx_map.insert(
                    quote(0xA0 + byte(i)),
                    TxHash::from_bytes([0x70 + byte(i); 32]),
                );
                finalize_ready_blobs(
                    &mut remaining,
                    &ready_after,
                    i,
                    &tx_map,
                    &mut records,
                    &mut staged,
                )
                .expect("fixture: a landed blob's proof builds");
            }
            assert_eq!(
                records.iter().flatten().count(),
                landed,
                "fixture: one record per landed blob"
            );
            SoFar {
                records,
                tx_map,
                txs,
            }
        }

        /// Sub-batch 1 of 2 landed, paying blob A (quote 0xA0) — and blob B,
        /// ready after the same landing, holds a staged quote (0xB0) the
        /// landing did not map: the gap upstream's `build_paid_chunks` refuses
        /// ("Missing tx hash for quote …"). At the pinned ant-core the gap
        /// cannot occur right after a landing; it is the injected fault S49
        /// guards an ant-core bump against. The real [`finalize_ready_blobs`]
        /// builds A's proof, fails on B, and returns the failure as data.
        fn first_landing_then_a_proof_gap() -> (SoFar, Result<(), String>) {
            let mut remaining = vec![Some(priced(0, 0xA0)), Some(priced(1, 0xB0))];
            let tx_map = BTreeMap::from([(quote(0xA0), TxHash::from_bytes([0x70; 32]))]);
            let txs = vec![tx(0x70, 0xA0, TxStatus::Confirmed)];
            let mut records = vec![None, None];
            let mut staged = HashMap::new();
            let finalized = finalize_ready_blobs(
                &mut remaining,
                &[0, 0],
                0,
                &tx_map,
                &mut records,
                &mut staged,
            );
            (
                SoFar {
                    records,
                    tx_map,
                    txs,
                },
                finalized,
            )
        }

        /// **S49 (G49-1, D204 R2).** A proof that cannot be built after a
        /// confirmed landing: the capture of what exists is delivered — the
        /// landed quote→tx map, the tx, the gas, and the record of the blob
        /// finalized before the failing one — and THEN the payment strands
        /// with the confirmed count, so the class and the journal agree that
        /// money moved. The blob whose proof failed has no record, so a resume
        /// re-buys that one blob (D37 Decision 5's granularity caveat).
        #[test]
        fn s49_a_proof_failure_after_a_landing_delivers_the_capture_and_strands() {
            let (so_far, finalized) = first_landing_then_a_proof_gap();
            let detail = finalized
                .clone()
                .expect_err("fixture: blob B's proof cannot be built");
            assert!(
                detail.contains("Missing tx hash for quote <hex redacted>"),
                "fixture: upstream's own gap error, redacted: {detail}"
            );
            assert!(
                so_far.records[0].is_some() && so_far.records[1].is_none(),
                "fixture: blob A finalized before blob B failed"
            );

            let (hook, seen) = recording_hook(CaptureOutcome::Durable);
            let result = settle_sub_batch(
                SubBatchOutcome::Confirmed { finalized },
                Some(&hook),
                &so_far.records,
                &so_far.tx_map,
                &so_far.txs,
                GAS_WEI,
                0,
                2,
            );
            let captured = captures(&seen);
            let Err(StorageError::StrandedPayment {
                landed_tx_count: 1,
                reason,
            }) = &result
            else {
                panic!(
                    "S49: a proof failure after a landing must strand with the landed count — \
                     expected StrandedPayment {{ landed_tx_count: 1 }}, got {result:?}; \
                     captures: {}",
                    captured.len()
                );
            };
            assert_eq!(
                reason,
                &format!("proof construction failed after sub-batch 1 of 2 landed: {detail}")
            );
            assert!(
                !reason.contains(&"b0".repeat(8)),
                "the unmapped quote's hash stays out of the reason: {reason}"
            );
            assert_eq!(
                captured.len(),
                1,
                "exactly one capture, delivered before the class"
            );
            let receipt = &captured[0];
            assert_eq!(
                receipt.tx_map, so_far.tx_map,
                "the capture maps the landed quote"
            );
            assert!(receipt.tx_map.contains_key(&quote(0xA0)));
            assert_eq!(receipt.txs, so_far.txs, "the capture carries the landed tx");
            assert_eq!(receipt.txs.len(), 1);
            assert_eq!(receipt.gas.gas_cost_wei, GAS_WEI);
            assert_eq!(
                receipt.blobs.len(),
                1,
                "the blob finalized before the failing one keeps its record"
            );
            assert_eq!(receipt.blobs[0].address, Address::from_bytes([0xA0; 32]));
            assert_eq!(receipt.storage_cost_atto, AMOUNT_ATTO);
        }

        /// **S49's unchanged half (G49-2).** The zero-transfer pre-pass runs
        /// before any sub-batch, so its proof failure moved no ANT: it stays
        /// [`StorageError::Payment`] with the words it had before S49, and
        /// nothing is recorded or staged for the blob. Nothing can be captured
        /// there: neither [`finalize_ready_blobs`] nor
        /// [`pre_pass_proof_failure`] is handed the hook.
        #[test]
        fn s49_the_pre_pass_failure_stays_payment() {
            // A blob the pre-pass holds as ready at once (`usize::MAX`) whose
            // staged quote nothing paid: the pre-pass's own failure.
            let mut remaining = vec![Some(priced(0, 0xC0))];
            let mut records = vec![None];
            let mut staged = HashMap::new();
            let detail = finalize_ready_blobs(
                &mut remaining,
                &[usize::MAX],
                usize::MAX,
                &BTreeMap::new(),
                &mut records,
                &mut staged,
            )
            .expect_err("fixture: an unpaid staged quote has no proof");
            assert!(
                detail.contains("Missing tx hash for quote <hex redacted>"),
                "fixture: upstream's own gap error, redacted: {detail}"
            );

            assert_eq!(
                pre_pass_proof_failure(detail.clone()),
                StorageError::Payment {
                    reason: format!("proof construction failed: {detail}"),
                },
                "the pre-pass keeps its class and its words"
            );
            assert!(
                records.iter().all(Option::is_none) && staged.is_empty(),
                "nothing is recorded or staged for a blob whose proof failed"
            );
        }

        /// **S46 in the seam (G46-u, D198 R2).** A not-durable capture
        /// mid-sequence stops the payment with D198's words, after that one
        /// capture; the same verdict after the LAST sub-batch stops nothing —
        /// the caller's post-`pay` write is the second chance (D186 R3).
        /// Controls: a durable capture, and no hook at all (no verdict), go
        /// on.
        #[test]
        fn s46_a_not_durable_capture_stops_mid_sequence_but_not_after_the_last() {
            let stop = StorageError::StrandedPayment {
                landed_tx_count: 1,
                reason: "the receipt-so-far could not be journaled after sub-batch 1 of 2 landed, \
                         so no further sub-batch was submitted (D37 Decision 2)"
                    .into(),
            };
            let rows = [
                (
                    "not durable, sub-batch 1 of 2",
                    Some(CaptureOutcome::NotDurable),
                    1,
                    Err(stop),
                ),
                (
                    "not durable, sub-batch 2 of 2",
                    Some(CaptureOutcome::NotDurable),
                    2,
                    Ok(()),
                ),
                (
                    "durable, sub-batch 1 of 2",
                    Some(CaptureOutcome::Durable),
                    1,
                    Ok(()),
                ),
                ("no hook, sub-batch 1 of 2", None, 1, Ok(())),
            ];
            assert_eq!(rows.len(), 4, "two verdicts at two positions, plus no hook");
            for (case, verdict, landed, expected) in rows {
                let so_far = after_landings(2, landed);
                let hooked = verdict.map(recording_hook);
                let result = settle_sub_batch(
                    SubBatchOutcome::Confirmed { finalized: Ok(()) },
                    hooked.as_ref().map(|(hook, _)| hook),
                    &so_far.records,
                    &so_far.tx_map,
                    &so_far.txs,
                    GAS_WEI,
                    landed - 1,
                    2,
                );
                assert_eq!(result, expected, "{case}");
                if let Some((_, seen)) = &hooked {
                    let captured = captures(seen);
                    assert_eq!(captured.len(), 1, "{case}: the landing's one capture");
                    assert_eq!(captured[0].txs.len(), landed, "{case}");
                    assert_eq!(
                        captured[0].blobs.len(),
                        landed,
                        "{case}: the capture carries every landed record"
                    );
                }
            }
        }

        /// **S50 (G50-1, D204 R3-R4).** The FIRST sub-batch of this call
        /// reverts: no ANT moved and no quote is paid, so the class is
        /// [`StorageError::Payment`] — "before any ANT moved" — and NOTHING is
        /// journaled. A receipt that maps no quote reads as a payment to every
        /// money reader in the CLI: `abandon` refused the work as "already
        /// been paid for", and a declined resume tagged it `Paid`.
        #[test]
        fn s50_a_first_sub_batch_revert_is_a_payment_failure_and_journals_nothing() {
            let records: Vec<Option<BlobPaymentRecord>> = vec![None, None];
            let txs = vec![tx(0x70, 0xA0, TxStatus::Reverted)];
            let (hook, seen) = recording_hook(CaptureOutcome::Durable);
            let result = settle_sub_batch(
                SubBatchOutcome::Reverted,
                Some(&hook),
                &records,
                &BTreeMap::new(),
                &txs,
                GAS_WEI,
                0,
                2,
            );
            let captured = captures(&seen).len();
            let Err(error @ StorageError::Payment { .. }) = &result else {
                panic!(
                    "S50: a first-sub-batch revert moved no ANT — expected Payment, got \
                     {result:?}; captures: {captured}"
                );
            };
            assert_eq!(
                error.to_string(),
                "payment failed before any ANT moved: the first payment sub-batch transaction \
                 reverted on-chain: it moved no ANT, and the gas it used is spent"
            );
            assert_eq!(
                captured, 0,
                "a zero-ANT revert journals nothing: {captured} capture(s)"
            );
        }

        /// **S50's unchanged half (G50-2).** A revert AFTER a confirmed
        /// landing keeps the stranded class, its unchanged reason, and its
        /// capture: the landed sub-batch's map and record, plus the reverted
        /// tx as evidence of the gas.
        #[test]
        fn s50_a_later_revert_keeps_the_stranded_class_and_its_capture() {
            let mut so_far = after_landings(2, 1);
            so_far.txs.push(tx(0x71, 0xA1, TxStatus::Reverted));
            let (hook, seen) = recording_hook(CaptureOutcome::Durable);
            let result = settle_sub_batch(
                SubBatchOutcome::Reverted,
                Some(&hook),
                &so_far.records,
                &so_far.tx_map,
                &so_far.txs,
                GAS_WEI,
                1,
                2,
            );
            let captured = captures(&seen);
            assert_eq!(
                result,
                Err(StorageError::StrandedPayment {
                    landed_tx_count: 1,
                    reason: "a payment sub-batch transaction reverted on-chain".into(),
                }),
                "captures: {}",
                captured.len()
            );
            assert_eq!(captured.len(), 1, "a revert after a landing is captured");
            let receipt = &captured[0];
            assert_eq!(receipt.txs.len(), 2, "the landed tx and the reverted one");
            assert_eq!(receipt.txs[1].status, TxStatus::Reverted);
            assert_eq!(
                receipt.tx_map, so_far.tx_map,
                "only the landed quote is mapped"
            );
            assert_eq!(receipt.tx_map.len(), 1);
            assert!(
                !receipt.tx_map.contains_key(&quote(0xA1)),
                "the reverted sub-batch's quote is unpaid"
            );
            assert_eq!(receipt.blobs.len(), 1, "the landed blob's record");
        }
    }
}
